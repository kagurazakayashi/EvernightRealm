// registrationstatus.go 是「申請人查本人待審批申請狀態」的傳輸層落點：
// POST /auth/registration-status 一條路徑做一件事（驗證憑據、回報他自己那份申請的結局）。
//
// 這一條通路的形態是由用戶批准的四件事拼出來的，逐條對應到這裡：
//  1. 它驗證憑據，但不簽發會話：成功回應不寫 Set-Cookie、不回任何會話材料、
//     不在 sessions 表留下一行，也沒有一枚需要壽命與撤銷邊界的「狀態證明令牌」。
//     每一次查詢都是一次全新的憑據證明，關掉頁面就什麼都不剩下。
//     這條通路因此不能讀到任何普通業務：待審批的人手上沒有任何可複用的憑據，
//     而「我申請了」與「我能進去了」是兩次獨立證明的兩件事。
//  2. 它只認登入名＋口令，沒有「申請編號」這一格：一個可猜測的編號就等於
//     一條不用出示憑據也能讀別人申請的通路。協議層因此沒有那種格子可填
//     （未知欄位規則把它們當場拒殺，1004）。
//  3. 失敗一律同形：查無此名、訪客帳戶、口令形狀不合格、口令不符都收斂成 2001，
//     與 /auth/login 同一句話、同一個狀態碼，而且用例內部做過等時佔位派生。
//     這條通路對「誰的名字存在」不新增信號。
//  4. 回應只講申請人自己的三個事實：結局（pending／approved／rejected）、
//     提交時刻、決定時刻。沒有審核人是誰、沒有拒絕理由、沒有別人的申請、
//     也沒有任何「排到第幾位」這種伺服器內部狀態。
//
// 前置鏈與 /auth/login、/auth/register 逐字同族（noStore → allowRequestOrigin → decodeJSON）：
// 這是一條匿名可達、且每次都要交口令的寫入型讀取，瀏覽器跨站請求必須先被來源擋下；
// 來源位址只交 remoteHost（實際連線），轉發標頭一概不進用例——本專案沒有已批准的可信代理約定，
// 把標頭值當來源等於把限流鍵交給請求方隨意填寫。
//
// 頻率封頂不在這裡判：用例用的是裝配層給登入的那一份守衛（同一份記憶體、同一組閾值），
// 所以「先刷登入再刷查狀態」共用同一份口令猜測預算。被擋的嘗試到不了查庫與 Argon2 派生，
// 回應是 2006＋Retry-After，與登入限流同一句話。
//
// 也刻意不問帳戶建立策略：用戶批准的語意是「模式只管新提交，歷史申請原地保留」。
// Root 之後把 approval 改成 closed 或 open，都不該替已經交上來的申請做決定，
// 所以這裡不能因為「現在不是 approval 模式」就把人擋在查詢之外。
//
// 回應本體絕不含口令明文、Argon2id 雜湊、會話材料、帳戶標識之外的內部鍵（正規化鍵不出去），
// 也不含 roles 之類的欄位：這條通路回答的是申請結局，不是權限。
package httpapi

import (
	"errors"
	"math"
	"net/http"
	"strconv"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/selfregister"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// registrationStatusRequest 是查本人申請狀態的請求本體。只有這兩個欄位可用：
// 「帳戶標識」「申請編號」「審核備註」之類的宣稱會被未知欄位規則當場拒殺（1004）——
// 這條通路的對象由「他交出的憑據」唯一決定，協定層沒有一個格子能指到別人身上。
type registrationStatusRequest struct {
	LoginName string `json:"login_name"`
	Password  string `json:"password"`
}

// applicationStatusResponse 是查詢成功的回應本體。
//
// reviewed_at 只在「已經有決定」時出現（omitempty 的缺席是事實的缺席，不是零值的謊話：
// 一個還在等的人不該看到一個 1970 年的決定時刻）。submitted_at 取帳戶的建立時刻，
// 那是「申請送進來的那一刻」在同一張表裡的唯一寫法。
// 沒有 account_id：申請人從來沒被告知過自己的標識，把它放進回應只多出一個可被轉述的編號，
// 對「我的申請怎麼樣了」這句話沒有幫助。
type applicationStatusResponse struct {
	Outcome     string `json:"outcome"`
	SubmittedAt string `json:"submitted_at"`
	ReviewedAt  string `json:"reviewed_at,omitempty"`
	RequestID   string `json:"request_id"`
}

// registrationStatusEndpoints 回傳受限狀態查詢端點的登記清單；未注入用例時為空。
//
// 與 /auth/register 共用同一個 Deps 欄位（同一條准入通路的兩側），因此「裝配了什麼就服務什麼」
// 這句話對兩條路徑同時成立：沒注入用例的執行檔，註冊與查狀態一條都不掛。
// 只有 POST 一個方法：這條通路每次都要交口令，而交口令的請求不該進 URL、進查詢字串、
// 進訪問日誌的 request line 或瀏覽器的歷史記錄（用戶批准的「不把秘密放入 URL」）。
// 因此它也不做 GET——GET 能被預取、被快取、被複製位址欄貼出來，三者都是把憑據往外送。
func (s *Server) registrationStatusEndpoints() []apiRoute {
	if s.selfRegister == nil {
		return nil
	}
	return []apiRoute{
		{"/auth/registration-status", s.allowMethods(s.handleApplicationStatus, http.MethodPost)},
	}
}

// handleApplicationStatus 處理 POST /auth/registration-status：申請人查本人申請狀態。
//
// 回應恆為 no-store（沿用同族端點的前置鏈）：這是一份會過期的本人狀態，
// 讓它留在瀏覽器或中介快取裡，等於把「他還在等」這件事變成一份能被人翻出來的副本。
// 成功不寫 Set-Cookie——這條通路的成功不是登入成功（見檔案頭注第 1 點）。
func (s *Server) handleApplicationStatus(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	if !s.allowRequestOrigin(r) {
		writeError(w, r, CodeOriginForbidden, http.StatusForbidden)
		return
	}
	var in registrationStatusRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	status, err := s.selfRegister.ApplicationStatus(r.Context(), selfregister.ApplicationStatusInput{
		LoginName: in.LoginName,
		Password:  in.Password,
	}, requestIDFromRequest(r), remoteHost(r))
	if err != nil {
		s.writeApplicationStatusFailure(w, r, err)
		return
	}
	payload := applicationStatusResponse{
		Outcome:     status.Outcome.String(),
		SubmittedAt: timeutil.FormatUTC(status.SubmittedAt),
		RequestID:   requestIDFromRequest(r),
	}
	if !status.ReviewedAt.IsZero() {
		payload.ReviewedAt = timeutil.FormatUTC(status.ReviewedAt)
	}
	writeJSON(w, http.StatusOK, payload)
}

// writeApplicationStatusFailure 把查狀態用例的錯誤對映為對外回應。
//
// 逐條對應不同的處置，而且「同形」這一組刻意合併到一枚碼上：
//   - 2001／401：查無此名、訪客帳戶、口令形狀不合格、口令不符。四者共用一句話，
//     因為把它們分開就是給探測者一份免費的名單；處置也確實是同一句「請核對你的登入名與口令」；
//   - 2006＋Retry-After（429）：這個來源對這個名字嘗試過多、正冷卻。信封恰好三鍵，
//     不透露它擋的是哪個名字（與登入限流同形）；
//   - 2020／403：憑據成立但這一筆不經審批通路。它只在身分已證明後才可能出現，
//     所以不會成為探測信號；處置是「改用登入入口」，與 2017 那句「等 Root 打開」不同；
//   - 1004／400：登入名不合領域規則（點名 login_name 欄位）。這是本次寫法的問題，
//     與帳戶存在與否無關，可以安全地分開；
//   - 500：其餘（讀帳戶失敗這類非拒絕故障），細節只進日誌。
func (s *Server) writeApplicationStatusFailure(w http.ResponseWriter, r *http.Request, err error) {
	var throttled *selfregister.ThrottledError
	if errors.As(err, &throttled) {
		seconds := int64(math.Ceil(throttled.RetryAfter.Seconds()))
		if seconds < 1 {
			// 冷卻只剩不足一秒：報 0 秒會被讀成「立刻再試」，寧可多等一粒鐘。
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeError(w, r, CodeLoginThrottled, http.StatusTooManyRequests)
		return
	}
	switch {
	case errors.Is(err, selfregister.ErrInvalidCredentials):
		writeError(w, r, CodeInvalidCredentials, http.StatusUnauthorized)
	case errors.Is(err, selfregister.ErrNotAnApplication):
		writeError(w, r, CodeNotAnApplication, http.StatusForbidden)
	case errors.Is(err, account.ErrInvalidLogin):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "login_name"})
	default:
		s.logger.Error("查申請狀態失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// 以下三個函式不存在，是刻意的：
//   - 沒有一個「按 account_id 查申請狀態」的讀法——那是一條不需要憑據的旁路；
//   - 沒有一個回傳 pending 名單的讀法——那屬 internal/acctreview 的 /admin/registrations，
//     它的授權邊界是伺服器級管理權，不屬於這條匿名通路（匿名這側一旦能翻名冊，
//     「只回答他自己那一份結局」這句話就廢了）；
//   - 沒有任何寫入（批准／拒絕）掛在這條路徑上：決定屬 internal/acctreview 那組端點，
//     由已認證的主體經另一道授權做出。兩側各掛各的依賴（Deps.SelfRegister 與
//     Deps.RegistrationReview），少注入誰就少一組端點，不會出現半條能用的通路。
