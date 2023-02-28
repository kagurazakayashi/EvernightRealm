// guest.go 是「匿名訪客以臨時受限身分進入」的傳輸層落點：
// POST /auth/guest 一條路徑做一件事（換得一個訪客帳戶與一枚會話）。
//
// 這個檔案刻意只做協定層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定——逐字複用 allowRequestOrigin 那條共用鏈（這是一條有副作用的
//     匿名寫入），與登入、自註冊端點同一條防線；
//  2. 請求本體的形態——白名單只有 nickname 一個欄位，未知欄位（role／account_type／
//     status／subject_kind／login_name／account_id 之類的宣稱）由 decodeJSON 的
//     DisallowUnknownFields 當場拒殺（1004）：「建的是哪一類主體」由「打的哪個端點」
//     決定，而「他叫什麼」只影響展示，不影響他是誰；
//  3. 來源位址的取得——只交 remoteHost（實際連線），轉發標頭一概不進用例：
//     訪客入口的計量主軸就是「來源位址 × 這條通路」，把標頭值當來源等於讓請求方
//     自己決定限流要記在誰帳上；
//  4. 結論對映——把用例回傳的可判別錯誤一一映射到機器碼，其餘一律 500 且細節只進日誌。
//     這組端點用到的碼：1004（點名 nickname 欄位）、2006（來源被限流、附 Retry-After）、
//     2017（帳戶建立策略此刻不開放訪客）。刻意不新增機器碼：2017 那句話本來就是為
//     「這條帳戶建立通路此刻被伺服器策略關閉」寫的，為訪客另開一枚碼只會讓同一個處置
//     有兩種寫法。
//
// 與 /auth/login 的分工，以及「為什麼訪客這裡會簽發會話而自註冊不會」：
//   - 自註冊建的是「一個可以反覆證明自己是誰的人」，他隨後要用自己剛選的口令走登入，
//     於是一條既有限流、會話、首次改密門閂只有一套（見 selfregister.go 頭注）；
//   - 訪客帳戶按定義沒有口令，也就沒有任何「隨後用口令登入」的路可走。如果不在此刻簽發
//     會話，他手上就什麼都不剩下，這扇門等於沒開。因此這一條路徑簽發會話——
//     但走的是全服務唯一的簽發點（internal/session）與唯一的一套 Cookie 分發通路
//     （setSessionCookie），寿命、絕對期限、閒置、撤銷、輪換、裝置名額全部與普通帳戶
//     逐字同規格。這裡沒有一枚「不受撤銷與到期約束的特殊 Cookie」可以給。
//
// 會話秘密的分發與登入完全一致（見 auth.go 頭注第 4 點）：回應 JSON 本體永不含秘密，
// Web 由瀏覽器代管 HttpOnly Cookie，原生客戶端從 Set-Cookie 讀取後改用 Bearer 回傳。
//
// 回應本體絕不含口令（訪客根本沒有）、會話材料、內部登入名或任何正規化鍵；
// display_name 是本端自己產生或本人剛交的那一串，回顯它不增加任何洩漏，
// 而界面要講「您是誰」需要的就是它。account_type 固定為 guest：它是界面後續
// 如實標出「臨時身分」的唯一依據（見 loginResponse 同名欄位）。
// 同理沒有 activity／資產／訊息任何一欄：那些模組尚未實作，
// 這趟進入對應的真相就是「尚未屬於任何活動」。
package httpapi

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"

	"github.com/kagurazakayashi/EvernightRealm/internal/guestacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// GuestUseCase 是「訪客進入」用例在傳輸層的入口形態（由 internal/app 注入 *guestacct.Service）。
//
// 以介面接收而不是直接收 *guestacct.Service：傳輸層組合的是「能做這件事的能力」，
// 未注入時一個訪客端點都不掛（與 Deps.Auth、Deps.SelfRegister 同一取向）。
//
// sourceIP 只能是傳輸層從實際連線取出的位址（remoteHost）：這條通路的寫入放大器封頂
// 完全以它為鍵，讓請求方自報來源等於讓它自己決定要讓誰消耗預算。
type GuestUseCase interface {
	// Enter 讓一個匿名的人自願換得一個訪客臨時身分與一枚會話。准入判定（策略現讀）
	// 在用例的交易內發生，傳輸層不先問一次「現在能不能放」（多一張會過期的答案
	// 改不了寫入那一刻的事實）；頻率計量也在用例內，先於任何寫入。
	Enter(ctx context.Context, in guestacct.EnterInput, requestID, sourceIP string) (guestacct.Outcome, error)
}

// guestEnterRequest 是訪客進入請求的本體。只有這一個欄位可用：
// 「角色」「帳戶類型」「登入名」「活動標識」之類的宣稱會被未知欄位規則當場拒殺（1004）。
// nickname 可留空，留空時由伺服器產生一個語言中立的臨時編號；它只是展示資訊，
// 不是憑據、不参与任何判定，因此也不需要是秘密——本端不會拿它認人（見 internal/guestacct 頭注）。
type guestEnterRequest struct {
	Nickname string `json:"nickname"`
}

// guestEnterResponse 是訪客進入成功的回應本體。
//
// 它是 loginResponse 的同族：秘密不在這裡（只在 Set-Cookie），會話內部標識也不在這裡，
// device_id 才是可展示的那一枚。多出來的兩欄（account_type 與 display_name）各有其必要：
// account_type 讓界面知道「這不是普通帳戶」，而 display_name 是本人之後看得見的那個名字——
// 他沒有口令可以再次證明自己，這一趟能認出他的就是這一行資料與手上那枚會話。
// must_change_password 不在這裡出現：訪客按定義無憑據，「下次登入必須改密」對他是一句空話
// （遷移 0003 的 CHECK 把 must_change_password 凍結為 0），沒有需要告知的現值。
type guestEnterResponse struct {
	SubjectKind string `json:"subject_kind"`
	AccountID   string `json:"account_id"`
	AccountType string `json:"account_type"`
	DisplayName string `json:"display_name"`
	DeviceID    string `json:"device_id"`
	ExpiresAt   string `json:"expires_at"`
	RequestID   string `json:"request_id"`
}

// guestEndpoints 回傳訪客進入端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深連結回退用的 API 首段清單（/auth）因此自動同步
// ——/auth 首段本就因登入端點而屬 API，這裡不新增首段，只多掛一條路徑。
// 只有 POST 一個方法（allowMethods 已登記，其餘方法回 1002 帶 Allow）：
// 這是一條有副作用的匿名寫入，GET 會被預取、被快取、被機器人掃，三者都不是
// 「本人主動要走這扇門」的那個動作。
func (s *Server) guestEndpoints() []apiRoute {
	if s.guest == nil {
		return nil
	}
	return []apiRoute{
		{"/auth/guest", s.allowMethods(s.handleGuestEnter, http.MethodPost)},
	}
}

// handleGuestEnter 處理 POST /auth/guest：訪客自願進入為臨時受限身分。
//
// 前置鏈與 /auth/login 逐字同族（noStore → allowRequestOrigin → decodeJSON），
// 結尾也與登入同族：成功即 setSessionCookie，之後的每一個請求經同一條
// resolveCredentials 解析，沒有任何端點能因為「這是訪客簽的會話」而多放行一件事。
//
// 准入（策略現讀）、頻率計量、登入名產生、主體構造與審計都由用例判，
// 傳輸層不先判一次——兩處各判一套的結局是其中一套被繞過。
func (s *Server) handleGuestEnter(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	if !s.allowRequestOrigin(r) {
		writeError(w, r, CodeOriginForbidden, http.StatusForbidden)
		return
	}
	var in guestEnterRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	outcome, err := s.guest.Enter(r.Context(), guestacct.EnterInput{
		Nickname: in.Nickname,
	}, requestIDFromRequest(r), remoteHost(r))
	if err != nil {
		s.writeGuestEnterFailure(w, r, err)
		return
	}
	s.setSessionCookie(w, r, outcome.Session, outcome.Secret)
	writeJSON(w, http.StatusOK, guestEnterResponse{
		SubjectKind: subjectKindOf(outcome.Principal),
		AccountID:   outcome.AccountID.String(),
		AccountType: outcome.Type.String(),
		DisplayName: outcome.DisplayName,
		DeviceID:    outcome.Session.DeviceID.String(),
		ExpiresAt:   timeutil.FormatUTC(outcome.Session.ExpiresAt),
		RequestID:   requestIDFromRequest(r),
	})
}

// writeGuestEnterFailure 把訪客進入用例的錯誤對映為對外回應。
//
// 逐條對應不同的處置，不互相冒充：
//   - 2006（附 Retry-After）：這個來源在訪客入口上的嘗試預算用盡、正冷卻。處置是
//     「等一會兒」，與 1004（改暱稱寫法）、2017（等 Root 打開關）都不是同一件事；
//     被擋的嘗試本就沒到查庫與寫入，回應不透露任何帳戶資訊（與登入限流同形）；
//   - 1004＋invalid_field=nickname：暱稱不合顯示名規則（超長、含控制或格式字元）。
//     這是本次寫法的問題，與策略、與他是誰都無關，可以安全點名欄位；
//   - 2017：帳戶建立策略此刻不開放訪客。請求本體沒有任何可改的欄位，換暱稱、
//     重新整理都不是處置——要等的是 Root 把訪客開關打開；
//   - 500：其餘（策略行缺失、標識產生失敗、資料庫故障這類非拒絕錯誤），細節只進日誌。
func (s *Server) writeGuestEnterFailure(w http.ResponseWriter, r *http.Request, err error) {
	var throttled *guestacct.ThrottledError
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
	case errors.Is(err, guestacct.ErrGuestDisabled):
		writeError(w, r, CodeAccountCreationDisabled, http.StatusForbidden)
	case errors.Is(err, guestacct.ErrInvalidNickname):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "nickname"})
	default:
		s.logger.Error("訪客進入處理失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}
