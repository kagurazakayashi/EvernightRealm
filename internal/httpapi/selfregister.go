// selfregister.go 是「匿名用戶自註冊為普通帳戶」的傳輸層落點：
// POST /auth/register 一條路徑做一件事（建立一個可立即登入的普通帳戶）。
//
// 這個檔案刻意只做協定層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定——逐字複用 allowRequestOrigin 那條共用鏈（這是一條有副作用的
//     匿名寫入，瀏覽器跨站請求必須先被來源擋下），與登入端點同一條防線；
//  2. 請求本體的形態——白名單只有 login_name／display_name／password 三個欄位，
//     未知欄位（role／account_type／status／subject_kind／must_change_password／
//     activity_id 這類「自報身分或企圖覆蓋隱藏欄位」的嘗試）由 decodeJSON 的
//     DisallowUnknownFields 當場拒殺（1004）：「建的是哪一類主體」由「打的哪個端點」
//     決定，不是由請求內容決定，協定層因此沒有一個格子能把自註冊昇格成管理員；
//  3. 來源位址的取得——只交 remoteHost（實際連線），轉發標頭一概不傳進用例：
//     本專案沒有已批准的可信代理約定，把標頭值當來源等於把限流鍵交給請求方隨意填寫；
//  4. 結論對映——把用例回傳的可判別錯誤一一映射到機器碼，其餘一律 500 且細節只進日誌。
//     這組端點用到的碼：1004（改寫法，點名是哪個欄位）、2006（來源被限流、附 Retry-After）、
//     2016（該自註冊模式對應的准入流程尚未上線）、2017（策略此刻不開放自註冊）、
//     2019（那個名字是別人的）。
//
// 與 /auth/login 的分工：兩者都是匿名、都先過來源判定、都不預讀策略，但落地完全不同——
// 登入是「拿已有憑據換一枚會話」，自註冊是「在策略放開時新建一筆普通帳戶」。
// 與 /admin/accounts 的 POST 建號的分工：那個經 NeedServerAdmin 判定、建出來的帳戶帶
// 首次改密義務（口令由管理員代選）；這個是匿名通路、不經任何主體判定、口令由本人自選，
// 因此 must_change_password 恆為 false（「選完就能直接登入」是既定語意）。
//
// 註冊成功刻意不簽發會話、不下發 Cookie：這與「返回標準登入流程」的既定決定一致——
// 自註冊只負責把人送進帳戶目錄，之後由本人用剛選的口令走 /auth/login，
// 既有認證邊界（限流、會話、首次改密門閂）因此只有一套，不在註冊路上複製第二套。
//
// 回應本體絕不含口令明文、Argon2id 雜湊、會話材料或任何內部正規化鍵；也沒有 roles 欄位
// ——自註冊建的按定義是「不帶任何伺服器級授予」的普通帳戶，回應不描述一件不存在的事。
// 同理沒有 activity／資產／訊息任何一欄：那些模組尚未實作，這裡不拿空值冒充查得到的真相。
package httpapi

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/selfregister"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// SelfRegisterUseCase 是「匿名自註冊」用例在傳輸層的入口形態（由 internal/app 注入 *selfregister.Service）。
//
// 與 Deps.Auth、Deps.StandardAccounts 分開一個介面、分開一個 Deps 欄位，理由同前幾步：
// 「裝配了什麼就服務什麼」——沒注入本用例的執行檔一個 /auth/register 端點都不掛。
//
// sourceIP 只能是傳輸層從實際連線取出的位址（remoteHost）：頻率封頂與橫掃偵測都以它為鍵，
// 讓請求方自報來源等於讓它自己決定限流要記在誰帳上。
type SelfRegisterUseCase interface {
	// RegisterAccount 讓一個匿名申請人自註冊為普通帳戶：准入判定（策略現讀與模式校驗）
	// 在的用例的交易內發生，傳輸層不先問一次「現在能不能建」（見檔案頭注：多一張會過期的答案
	// 改不了寫入那一刻的事實）。被拒的結論全部可判別，見 internal/selfregister。
	RegisterAccount(ctx context.Context, in selfregister.RegisterInput,
		requestID, sourceIP string) (selfregister.RegisteredAccount, error)
}

// registerRequest 是自註冊請求的本體。只有這三個欄位可用：
// 「角色」「帳戶類型」「審批狀態」「首次改密」「活動標識」之類的宣稱會被未知欄位規則當場拒殺
// （回 1004），因此「把自己註冊成管理員」在協定層就沒有一個可以填的格子。
type registerRequest struct {
	LoginName   string `json:"login_name"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

// registeredAccountResponse 是自註冊成功的回應本體。
//
// 全部為可展示事實；刻意缺席的：初始口令（連同它的任何前綴或長度）、Argon2id 雜湊、
// 會話材料（本路徑不簽發會話）、roles 欄位（見檔案頭注）。must_change_password 恆為 false，
// 讓界面能把「這個口令是你自己選的、現在就能登入」講給用戶聽。account_id 是穩定標識，
// 而「已建立」不等於「已加入活動」——回應裡沒有任何活動欄位可被誤讀。
type registeredAccountResponse struct {
	AccountID          string `json:"account_id"`
	LoginName          string `json:"login_name"`
	DisplayName        string `json:"display_name"`
	Status             string `json:"status"`
	MustChangePassword bool   `json:"must_change_password"`
	CreatedAt          string `json:"created_at"`
	RequestID          string `json:"request_id"`
}

// selfRegisterEndpoints 回傳自註冊端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深連結回退用的 API 首段清單（/auth）因此自動同步
// ——/auth 首段本就因登入端點而屬 API，這裡不新增首段，只多掛一條路徑。
// 只有 POST 一個方法（allowMethods 已登記，其餘方法回 1002 帶 Allow）：
// 「建一筆帳戶」在協定層只有一個入口，讀能力現值走 /auth/capabilities，
// 讀帳戶資料需要登入後的路徑，都不在這一條上開第二份讀法。
func (s *Server) selfRegisterEndpoints() []apiRoute {
	if s.selfRegister == nil {
		return nil
	}
	return []apiRoute{
		{"/auth/register", s.allowMethods(s.handleRegister, http.MethodPost)},
	}
}

// handleRegister 處理 POST /auth/register：匿名自註冊為普通帳戶。
//
// 前置鏈與 /auth/login 逐字同族（noStore → allowRequestOrigin → decodeJSON），
// 差別只在結尾：登入成功簽發會話並下發 Cookie，註冊成功只回一筆新建帳戶的現值、
// 不碰任何憑據分發（見檔案頭注「不簽發會話」）。
//
// 准入（策略現讀＋模式校驗）、頻率封頂、口令形狀、登入名正規化與唯一性都由用例判，
// 傳輸層不先判一次——兩處各判一套的結局是其中一套被繞過。口令本身的強度規則也不在這裡
// 抄寫（那是 credential 模組那道閘，經用例映射為 1004＋點名 password 欄位）。
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	if !s.allowRequestOrigin(r) {
		writeError(w, r, CodeOriginForbidden, http.StatusForbidden)
		return
	}
	var in registerRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	created, err := s.selfRegister.RegisterAccount(r.Context(), selfregister.RegisterInput{
		LoginName:   in.LoginName,
		DisplayName: in.DisplayName,
		Password:    in.Password,
	}, requestIDFromRequest(r), remoteHost(r))
	if err != nil {
		s.writeRegisterFailure(w, r, err)
		return
	}
	// 成功不寫 Set-Cookie：只把人送進目錄，登入由本人隨後用剛選的口令走 /auth/login。
	writeJSON(w, http.StatusCreated, registeredAccountResponse{
		AccountID:          created.AccountID.String(),
		LoginName:          created.LoginName,
		DisplayName:        created.DisplayName,
		Status:             created.Status.String(),
		MustChangePassword: created.MustChangePassword,
		CreatedAt:          timeutil.FormatUTC(created.CreatedAt),
		RequestID:          requestIDFromRequest(r),
	})
}

// writeRegisterFailure 把自註冊用例的錯誤對映為對外回應。
//
// 失敗映射逐條對應不同的處置，不互相冒充：
//   - 2006（附 Retry-After）：這個來源對這個名字的嘗試過多、正冷卻。處置是「等一會兒」，
//     與 1004（改寫法）、2019（換名字）都不是同一件事；被擋的嘗試本就沒到查庫與派生，
//     回應不透露它擋的是哪個名字（與登入限流同形）；
//   - 1004：本體欄位不合規（登入名含空白／顯示名為空／口令形狀不合格）。details 只點出
//     是哪一個欄位，不復述伺服器的域規則原文，也不含任何輸入內容；
//   - 2019：登入名已被佔用。這是業務衝突，帳戶一個也沒多出來；正常用戶據此知道要換名字
//     （與需要已認證主體的 2012 分開：那枚碼的合同寫明只在 Root 建號入口出現）；
//   - 2017：策略此刻不開放自註冊。它不是權限問題、也不是寫法問題——要等的是 Root 把模式
//     打開，換名字、重新整理都不是處置；
//   - 2016：策略開著、但生效模式是 approval／invite 這種准入流程尚未上線的類型。
//     與 2017 分開是因為處置不同：一個是「沒開這條路」，另一個是「開著但功能還沒上線」；
//   - 500：其餘（策略行缺失、派生故障這類非拒絕錯誤），細節只進日誌。
func (s *Server) writeRegisterFailure(w http.ResponseWriter, r *http.Request, err error) {
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
	case errors.Is(err, selfregister.ErrDuplicateLogin):
		writeError(w, r, CodeSelfRegisterNameTaken, http.StatusConflict)
	case errors.Is(err, selfregister.ErrRegisterDisabled):
		writeError(w, r, CodeAccountCreationDisabled, http.StatusForbidden)
	case errors.Is(err, selfregister.ErrRegisterModeUnsupported):
		writeError(w, r, CodeAccountPolicyModeUnavailable, http.StatusBadRequest)
	case errors.Is(err, selfregister.ErrInvalidPassword):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "password"})
	case errors.Is(err, account.ErrInvalidLogin):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "login_name"})
	case errors.Is(err, account.ErrInvalidDisplayName):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "display_name"})
	case errors.Is(err, acctpolicy.ErrNoPolicyRow):
		// 結構缺陷：單例策略行被外部工具動過。對外只有一句通用失敗，細節只進日誌。
		s.logger.Error("自註冊時讀不到帳戶建立策略", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	default:
		s.logger.Error("自註冊處理失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}
