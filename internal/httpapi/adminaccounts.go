// adminaccounts.go 是「伺服器級管理員建立普通帳戶」的傳輸層落點：
// /admin/accounts 一條路徑一件事（POST 建立），其餘方法回 1002 帶 Allow。
//
// 這個檔案刻意只做協定層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 consolePrincipal 那條共用鏈，
//     不在這裡重寫一份「先看 Cookie 再看標頭」的順序；
//  2. 首次改密門閂——同一條鏈上的 requirePasswordChangeDone，與其餘受保護端點同一把閘；
//  3. 請求本體與方法形態——本體只有 login_name／display_name／password，
//     未知欄位（含 role、account_type、status、subject_kind、must_change_password
//     這類「自報身分或企圖覆蓋隱藏欄位」的嘗試）由 decodeJSON 的 DisallowUnknownFields
//     當場拒殺：「建的是哪一類主體」由「打的哪個端點」決定，不是由請求內容決定；
//     「哪個活動」更是連格子都沒有——建號不屬於任何活動，也塞不進任何活動；
//  4. 結論對映——把用例回傳的可判別錯誤一一映射到機器碼，其餘一律 500 且細節只進日誌。
//
// 與 /root/admins 的分工是一條邊界而不是一個目錄慣例：那個端點建的是「持有伺服器級
// 角色的主體」，經 NeedRoot 判定、不受三個建立開關約束；這個端點建的是「普通帳戶」，
// 經 NeedServerAdmin 判定、受 admin_create_standard 約束且對所有主體一視同仁
// （Root 走這條路同樣被關擋）。兩條路各自把「誰能建哪一類人」答完整，合成一份也沒有。
//
// 開關不預讀：這裡沒有「先問一次能不能建」的端點，策略現值只有 Root 讀得到；
// 管理員表單照常提交，開著就建、關著就收 2017 那一句。判定只發生在用例的交易內
// 現讀那一刻，界面預讀與否都改不了這個事實，多一個讀端點只是多一張會過期的答案。
//
// 回應本體絕不含口令明文、憑據雜湊、會話材料或任何內部正規化鍵；也刻意不帶 roles
// 欄位——本用例建出的帳戶恆無任何伺服器級授予，回應不描述一件不存在的事，
// 免得界面把「沒有這一行」讀成「查不到」。
package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/stdacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// StdAccountUseCase 是「管理員建立普通帳戶」用例在傳輸層的入口形態
// （由 internal/app 注入 *stdacct.Service）。
//
// 與 Deps.Admins、Deps.AccountPolicy 分開一個介面、分開一個 Deps 欄位，理由同前兩步：
// 「裝配了什麼就服務什麼」——沒注入本用例的執行檔一個 /admin/accounts 端點都不掛。
//
// principal 一律是「本次請求的憑據剛換出的受信主體」；授權（NeedServerAdmin）、
// 策略現讀與放行合成都在用例裡判，不在傳輸層先判一次——兩處各判一套的結局
// 是其中一套被繞過。
type StdAccountUseCase interface {
	// CreateStandardAccount 以持有伺服器級管理權的受信主體建立一個普通帳戶。
	// 策略開關在建立交易的同一快照上現讀復核，關閉時整筆不發生並回
	// stdacct.ErrCreateDisabled。
	CreateStandardAccount(ctx context.Context, principal identity.Principal,
		in stdacct.CreateInput, requestID string) (stdacct.CreatedAccount, error)
}

// createStandardAccountRequest 是建立請求的本體。只有這三個欄位可用：
// 「角色」「帳戶類型」「審批狀態」「活動標識」之類的宣稱會被未知欄位規則當場拒殺
// （回 1004），因此「普通帳戶把自己建成管理員」在協定層就沒有一個可以填的格子。
type createStandardAccountRequest struct {
	LoginName   string `json:"login_name"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

// createdStandardAccountResponse 是建立成功的回應本體。
//
// 全部為可展示事實；刻意缺席的：初始口令（連同它的任何前綴或長度）、Argon2id 雜湊、
// 新帳戶的會話材料、roles 欄位（見檔案頭注）。must_change_password 恆為 true，
// 讓界面能把「這個口令只用一次」講給操作者聽；account_id 是穩定標識，
// 而「已建立」不等於「已加入活動」——回應裡沒有任何活動欄位可被誤讀。
type createdStandardAccountResponse struct {
	AccountID          string `json:"account_id"`
	LoginName          string `json:"login_name"`
	DisplayName        string `json:"display_name"`
	Status             string `json:"status"`
	MustChangePassword bool   `json:"must_change_password"`
	CreatedAt          string `json:"created_at"`
	RequestID          string `json:"request_id"`
}

// standardAccountEndpoints 回傳普通帳戶建立端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深連結回退用的 API 首段清單（/admin）因此自動同步。
func (s *Server) standardAccountEndpoints() []apiRoute {
	if s.stdAccounts == nil {
		return nil
	}
	return []apiRoute{
		{"/admin/accounts", s.allowMethods(s.handleCreateStandardAccount, http.MethodPost)},
	}
}

// handleCreateStandardAccount 處理 POST /admin/accounts。
func (s *Server) handleCreateStandardAccount(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	var in createStandardAccountRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	created, err := s.stdAccounts.CreateStandardAccount(r.Context(), principal, stdacct.CreateInput{
		LoginName:       in.LoginName,
		DisplayName:     in.DisplayName,
		InitialPassword: in.Password,
	}, requestIDFromRequest(r))
	if err != nil {
		s.writeCreateStandardFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, createdStandardAccountResponse{
		AccountID:          created.AccountID.String(),
		LoginName:          created.LoginName,
		DisplayName:        created.DisplayName,
		Status:             created.Status.String(),
		MustChangePassword: created.MustChangePassword,
		CreatedAt:          timeutil.FormatUTC(created.CreatedAt),
		RequestID:          requestIDFromRequest(r),
	})
}

// writeCreateStandardFailure 把建立用例的錯誤對映為對外回應。
//
// 失敗映射逐條對應不同的處置，不互相冒充：
//   - 1004：本體欄位不合規（登入名含空白／顯示名為空／口令形狀不合格）。details 只點出
//     是哪一個欄位，不復述伺服器的域規則原文，也不含任何輸入內容；
//   - 2012：登入名已被佔用。這是業務衝突，帳戶一個也沒多出來；
//   - 2017：策略此刻不開放這條通路。它不是權限問題（2011），也不是寫法問題（1004）——
//     要等的是 Root 打開開關，換名字、換身分、重登都不是處置；
//   - 2011：這個主體沒有伺服器級管理權（普通帳戶與系統主體都在這裡被拒）；
//   - 500：其餘（策略行缺失、資料庫故障這類非拒絕錯誤），細節只進日誌。
func (s *Server) writeCreateStandardFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, stdacct.ErrDuplicateLogin):
		writeError(w, r, CodeLoginNameTaken, http.StatusConflict)
	case errors.Is(err, stdacct.ErrInvalidInitialPassword):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "password"})
	case errors.Is(err, account.ErrInvalidLogin):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "login_name"})
	case errors.Is(err, account.ErrInvalidDisplayName):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "display_name"})
	case errors.Is(err, stdacct.ErrCreateDisabled):
		writeError(w, r, CodeAccountCreationDisabled, http.StatusForbidden)
	case errors.Is(err, identity.ErrPermissionDenied):
		// 403：憑據有效，缺的是權限。不發刪除指令——那枚 Cookie 此刻仍換得出同一個主體。
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	case errors.Is(err, acctpolicy.ErrNoPolicyRow):
		// 結構缺陷：單例策略行被外部工具動過。對外只有一句通用失敗，細節只進日誌。
		s.logger.Error("建立普通帳戶時讀不到帳戶建立策略", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	case errors.Is(err, identity.ErrNotAuthenticated), errors.Is(err, identity.ErrInvalidPrincipal):
		// 到這裡只剩「帶著有效會話卻換不出可信主體」一種可能，那是服務端缺陷而不是拒絕：
		// 照 500 報，讓它被當成缺陷查，而不是報成 2011 讓操作者以為自己沒登入。
		s.logger.Error("建立普通帳戶的主體不合法", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	default:
		s.logger.Error("建立普通帳戶處理失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}
