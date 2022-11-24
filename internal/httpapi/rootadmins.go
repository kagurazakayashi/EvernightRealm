// rootadmins.go 是「Root 開設伺服器級管理員帳戶」的傳輸層落點：
// POST／GET 共用 /root/admins 這一路徑，端點本身決定做哪一件事。
//
// 這個檔案刻意只做協定層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 allowRequestOrigin＋resolveCredentials，
//     不在這裡重寫一份「先看 Cookie 再看標頭」的順序（兩套判定的結果必然是其中一套被繞過）；
//  2. 首次改密門閂——複用 requirePasswordChangeDone，與其餘受保護端點同一把閘；
//  3. 請求本體的形態——只有 login_name／display_name／password 三個欄位，
//     未知欄位（含 role、type、account_id、subject_kind 這類「自報身分」的嘗試）
//     由 decodeJSON 的 DisallowUnknownFields 當場拒殺：「建的是管理員」由
//     「打的哪個端點」決定，不是由請求內容決定；
//  4. 結論對映——把用例回傳的可判別錯誤一一映射到既有機器碼，其餘一律 500 且細節只進日誌。
//
// 回應本體絕不含口令明文、憑據雜湊或任何會話材料：开设成功後能公開的只有帳戶的可展示事實。
// 初始口令由 Root 自己帶進來（用戶批准的一次性交付形態），伺服端不生成、不回顯、
// 也不在衝突回應裡把舊帳戶的任何資料递回去。
//
// 「最小列表」只是一個確認入口：沒有分頁、沒有搜尋條件、沒有按登入名的查詢參數，
// 完整的帳戶目錄與維護台屬後續步驟，本檔不預先假裝有。
package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/adminacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// RootAdminUseCase 是開設用例在傳輸層的入口形態（由 internal/app 注入 *adminacct.Service）。
//
// 與 AuthUseCase 分開一個介面、分開一個 Deps 欄位，理由是「裝配了什麼就服務什麼」：
// 沒注入開設用例的執行檔一個 /root/admins 端點都不掛，協定層行為與本步之前逐字相同
// （與 Deps.Auth、Deps.Web 同一取向）。
//
// principal 一律是「本次請求的憑據剛換出的受信主體」：傳輸層先走 resolveCredentials
// 才拿得到它，因此這裡沒有任何一條路把請求裡的某个字串當成身分。
type RootAdminUseCase interface {
	// CreateAdmin 以當前受信主體開設一個持有伺服器級管理員角色的新帳戶。
	// 授權由用例內的 identity.Authorize(principal, NeedRoot) 給出，不在傳輸層先判一次——
	// 兩處各判一套的結局是其中一套被繞過。
	CreateAdmin(ctx context.Context, principal identity.Principal,
		in adminacct.CreateInput, requestID string) (adminacct.CreatedAdmin, error)
	// ListAdmins 列舉持有伺服器級管理員角色的帳戶（確認用的最小清單）。
	// 範圍由主體決定，請求裡沒有任何欄位可以改寫「列誰的清單」。
	ListAdmins(ctx context.Context, principal identity.Principal) ([]adminacct.Summary, error)
}

// createAdminRequest 是開設請求的本體。只有這三個欄位可用：
// 「角色」「帳戶類型」「主體類別」之類的宣稱會被未知欄位規則當場拒殺（回 1004），
// 因此「普通管理員把自己建成 Root」在協定層就沒有一個可以填的格子。
type createAdminRequest struct {
	LoginName   string `json:"login_name"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

// createdAdminResponse 是開設成功的回應本體。
//
// 全部為可展示事實；刻意缺席的：初始口令（連同它的任何前綴或長度）、Argon2id 雜湊、
// 新帳戶的會話材料。must_change_password 恆為 true，讓界面能把「這個口令只用一次」
// 這句話如實講給 Root 聽，而不是讓 Root 以為那是對方的長期口令。
type createdAdminResponse struct {
	AccountID          string   `json:"account_id"`
	LoginName          string   `json:"login_name"`
	DisplayName        string   `json:"display_name"`
	Status             string   `json:"status"`
	MustChangePassword bool     `json:"must_change_password"`
	Roles              []string `json:"roles"`
	CreatedAt          string   `json:"created_at"`
	RequestID          string   `json:"request_id"`
}

// adminItem 是確認清單裡的一行（同一筆資料在列表與單筆回應裡的形狀必須同源）。
type adminItem struct {
	AccountID          string `json:"account_id"`
	LoginName          string `json:"login_name"`
	DisplayName        string `json:"display_name"`
	Status             string `json:"status"`
	MustChangePassword bool   `json:"must_change_password"`
	CreatedAt          string `json:"created_at"`
	// LastLoginAt 為最近一次登入時刻；從未登入時欄位缺席（不拿建立時刻冒充）。
	LastLoginAt string `json:"last_login_at,omitempty"`
}

// adminListResponse 是 GET /root/admins 的回應本體。
type adminListResponse struct {
	Admins    []adminItem `json:"admins"`
	RequestID string      `json:"request_id"`
}

// rootAdminEndpoints 回傳開設端點登記清單；未注入用例時為空。
//
// 與 auth 端點同一個來源、同一個有無判定：登記與否只這一處，
// 「/root 首段屬於 API」因此自動成立（深連結回退不會把端點路徑當頁面回 HTML）。
func (s *Server) rootAdminEndpoints() []apiRoute {
	if s.admins == nil {
		return nil
	}
	// 同一路徑上 GET／HEAD 是「確認清單」、POST 是「開設」：方法由 allowMethods 放行，
	// 做哪件事由 handleRootAdmins 依 r.Method 分流。分成兩條路徑樣式反而會多出
	// 一個「兩個端點共用一份授權語意」的維護點。
	return []apiRoute{
		{"/root/admins", s.allowMethods(s.handleRootAdmins,
			http.MethodGet, http.MethodHead, http.MethodPost)},
	}
}

// handleRootAdmins 依方法分流：POST 開設、GET／HEAD 列舉。
//
// 兩條路共用同一套前置（來源判定 → 憑據解析 → 首次改密門閂），差異只在
// 有沒有請求本體與怎麼映射失敗：
//   - POST 是有副作用的方法，先過 allowRequestOrigin；GET 不該被來源規則誤傷
//     （allowRequestOrigin 對安全方法本來就放行，放在前面只是讓兩條路同形）；
//   - 解析出主體後，授權仍由用例判定：這裡不先判「是不是 Root」再放行，
//     否則判定的真相就分成了兩份（其中一份必然會被日後新增的呼叫點漏掉）。
func (s *Server) handleRootAdmins(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	if !s.allowRequestOrigin(r) {
		writeError(w, r, CodeOriginForbidden, http.StatusForbidden)
		return
	}
	res := s.resolveCredentials(r)
	switch res.status {
	case credOK:
		// Root 憑據不在 accounts 表，這把閘對 Root 恆放行（見 auth.MustChangePassword）；
		// 呼叫它是為了「新增受保護端點時不必再想一次要不要擋」，而不是假裝 Root 會欠改密。
		if !s.requirePasswordChangeDone(w, r, res.resolved.Principal) {
			return
		}
		if r.Method == http.MethodPost {
			s.createRootAdmin(w, r, res.resolved.Principal)
			return
		}
		s.listRootAdmins(w, r, res.resolved.Principal)
	case credAbsent:
		writeError(w, r, CodeNotAuthenticated, http.StatusUnauthorized)
	case credInvalid:
		if res.viaCookie {
			http.SetCookie(w, s.clearedSessionCookie(r))
		}
		writeError(w, r, CodeSessionInvalid, http.StatusUnauthorized)
	case credStale:
		writeError(w, r, CodeSessionStale, http.StatusUnauthorized)
	case credNotReady:
		writeError(w, r, CodeNotReady, http.StatusServiceUnavailable)
	case credConflict:
		writeError(w, r, CodeAuthMethodConflict, http.StatusBadRequest)
	case credUnavailable:
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// createRootAdmin 處理 POST /root/admins。
//
// 失敗映射逐條對應不同的處置，不互相冒充：
//   - 1004：本體欄位不合規（登入名含空白／顯示名為空／口令形狀不合格）。details 只點出
//     是哪一個欄位，不復述伺服器的域規則原文，也不含任何輸入內容；
//   - 2012：登入名已被佔用。這是業務衝突，账户一個也没多出來；
//   - 2011：這個主體不是 Root（普通帳戶與普通管理員都在這裡被拒）。它不是憑據問題，
//     因此不發刪除指令，也不把人推回登入頁；
//   - 500：其餘（資料庫故障这类非拒絕錯誤），細節只進日誌。
func (s *Server) createRootAdmin(w http.ResponseWriter, r *http.Request, principal identity.Principal) {
	var in createAdminRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	created, err := s.admins.CreateAdmin(r.Context(), principal, adminacct.CreateInput{
		LoginName:       in.LoginName,
		DisplayName:     in.DisplayName,
		InitialPassword: in.Password,
	}, requestIDFromRequest(r))
	if err != nil {
		s.writeCreateAdminFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, createdAdminResponse{
		AccountID:          created.AccountID.String(),
		LoginName:          created.LoginName,
		DisplayName:        created.DisplayName,
		Status:             created.Status.String(),
		MustChangePassword: created.MustChangePassword,
		Roles:              roleNames(created.Roles),
		CreatedAt:          timeutil.FormatUTC(created.CreatedAt),
		RequestID:          requestIDFromRequest(r),
	})
}

// writeCreateAdminFailure 把開設用例的錯誤對映為對外回應。
func (s *Server) writeCreateAdminFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminacct.ErrDuplicateLogin):
		writeError(w, r, CodeLoginNameTaken, http.StatusConflict)
	case errors.Is(err, adminacct.ErrInvalidInitialPassword):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "password"})
	case errors.Is(err, account.ErrInvalidLogin):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "login_name"})
	case errors.Is(err, account.ErrInvalidDisplayName):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "display_name"})
	case errors.Is(err, identity.ErrPermissionDenied):
		// 403：憑據有效，缺的是權限。不發刪除指令——那枚 Cookie 此刻仍換得出同一個主體。
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	case errors.Is(err, identity.ErrNotAuthenticated), errors.Is(err, identity.ErrInvalidPrincipal):
		// 到這裡只剩「帶著有效會話卻換不出可信主體」一種可能，那是服務端缺陷而不是拒絕：
		// 照 500 報，讓它被当成缺陷查，而不是報成 2011 讓 Root 以為自己沒登入。
		s.logger.Error("開設管理員的主體不合法", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	default:
		s.logger.Error("開設管理員處理失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// listRootAdmins 處理 GET／HEAD /root/admins。
func (s *Server) listRootAdmins(w http.ResponseWriter, r *http.Request, principal identity.Principal) {
	list, err := s.admins.ListAdmins(r.Context(), principal)
	if err != nil {
		if errors.Is(err, identity.ErrPermissionDenied) {
			writeError(w, r, CodePermissionDenied, http.StatusForbidden)
			return
		}
		s.logger.Error("列舉管理員失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		return
	}
	items := make([]adminItem, 0, len(list))
	for _, entry := range list {
		item := adminItem{
			AccountID:          entry.AccountID.String(),
			LoginName:          entry.LoginName,
			DisplayName:        entry.DisplayName,
			Status:             entry.Status.String(),
			MustChangePassword: entry.MustChangePassword,
			CreatedAt:          timeutil.FormatUTC(entry.CreatedAt),
		}
		if !entry.LastLoginAt.IsZero() {
			item.LastLoginAt = timeutil.FormatUTC(entry.LastLoginAt)
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, adminListResponse{
		Admins:    items,
		RequestID: requestIDFromRequest(r),
	})
}
