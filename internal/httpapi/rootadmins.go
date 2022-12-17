// rootadmins.go 是「Root 對伺服器級管理員的目錄性操作」的傳輸層落點：
// /root/admins 一個路徑做兩件事（GET／HEAD 分頁目錄、POST 開設），
// /root/admins/{account_id} 一個路徑做兩件事（GET／HEAD 單筆詳情、PUT 編輯非安全資料），
// /root/admins/{account_id}/status 一條路徑做一件事（PUT 停用或恢復登入，唯一白名單欄位是狀態）。
//
// 這個檔案刻意只做協定層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 allowRequestOrigin＋resolveCredentials，
//     不在這裡重寫一份「先看 Cookie 再看標頭」的順序（兩套判定的結果必然是其中一套被繞過）；
//  2. 首次改密門閂——複用 requirePasswordChangeDone，與其餘受保護端點同一把閘；
//  3. 請求本體與查詢參數的形態——開設只有 login_name／display_name／password，
//     編輯只有 display_name 與它所依據的 expected_display_name；
//     未知欄位（含 role、type、status、account_id、must_change_password 這類「自報身分
//     或企圖覆蓋隱藏欄位」的嘗試）由 decodeJSON 的 DisallowUnknownFields 當場拒殺：
//     「動的是哪一類資料」由「打的哪個端點、用的哪個方法」決定，不是由請求內容決定；
//  4. 結論對映——把用例回傳的可判別錯誤一一映射到既有機器碼，其餘一律 500 且細節只進日誌。
//
// 回應本體絕不含口令明文、憑據雜湊、會話材料或任何內部正規化鍵：能公開的只有帳戶的
// 可展示事實。目錄與詳情的欄位是白名單投影（見 internal/adminacct/directory.go 的邊界約定的
// 單筆對應），新增欄位必須先回答「這個用途真的需要它嗎」。
//
// 路徑裡的 {account_id} 是本倉庫第一條帶路徑參數的端點：解析失敗（不是一枚 UUID）
// 與查無此人都回同一個 1001——對外的句子不區分「格式不對」與「沒有這個人」，
// 免得端點變成一台標識格式探測器。
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/adminacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// RootAdminUseCase 是管理員目錄用例在傳輸層的入口形態（由 internal/app 注入 *adminacct.Service）。
//
// 與 AuthUseCase 分開一個介面、分開一個 Deps 欄位，理由是「裝配了什麼就服務什麼」：
// 沒注入這些用例的執行檔一個 /root/admins 端點都不掛，協定層行為與本步之前逐字相同
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
	// Directory 以當前受信主體分頁列舉管理員目錄（含狀態篩選與總數）。
	Directory(ctx context.Context, principal identity.Principal,
		q adminacct.DirectoryQuery) (adminacct.DirectoryPage, error)
	// AdminProfile 讀回單筆管理員詳情（經帳戶實體校驗的當前資料）。
	AdminProfile(ctx context.Context, principal identity.Principal,
		accountID idgen.ID) (adminacct.Profile, error)
	// UpdateAdminProfile 以白名單編輯管理員的顯示名；expectedDisplayName 是呼叫端
	// 提交所依據的現值，兩者不符時整個編輯不發生並回衝突結論。
	UpdateAdminProfile(ctx context.Context, principal identity.Principal,
		accountID idgen.ID, displayName, expectedDisplayName, requestID string) (adminacct.Profile, error)
	// UpdateAdminStatus 停用或恢復一名目錄內管理員的登入狀態；expectedStatus 是呼叫端
	// 提交所依據的現狀，不符時狀態、會話撤銷、審計一件都不發生並回衝突結論。
	UpdateAdminStatus(ctx context.Context, principal identity.Principal,
		accountID idgen.ID, in adminacct.StatusChangeInput, requestID string) (adminacct.StatusChange, error)
}

// createAdminRequest 是開設請求的本體。只有這三個欄位可用：
// 「角色」「帳戶類型」「主體類別」之類的宣稱會被未知欄位規則當場拒殺（回 1004），
// 因此「普通管理員把自己建成 Root」在協定層就沒有一個可以填的格子。
type createAdminRequest struct {
	LoginName   string `json:"login_name"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

// updateAdminProfileRequest 是編輯請求的本體。白名單只有顯示名一欄，外加它所依據的現值：
// status／must_change_password／account_type／password／login_name 等隱藏或身分欄位
// 在本體裡沒有格子可填（未知欄位 1004），「保存普通資料順手把旗標清了」在協定層就沒發生點。
type updateAdminProfileRequest struct {
	DisplayName         string `json:"display_name"`
	ExpectedDisplayName string `json:"expected_display_name"`
}

// updateAdminStatusRequest 是停用／恢復請求的本體。白名單只有狀態一欄，外加它所依據的現狀：
// 這裡沒有顯示名、憑據、旗標或原因文本的格子（未知欄位 1004）——「停用在協定層不順手改資料、
// 恢復在協定層不清首次改密義務」成立在同一條理由上：動哪一欄由端點與白名單決定。
type updateAdminStatusRequest struct {
	Status         string `json:"status"`
	ExpectedStatus string `json:"expected_status"`
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

// adminItem 是目錄行／詳情／編輯結果共用的單筆形状（同一筆資料在不同回應裡的形狀必須同源）。
type adminItem struct {
	AccountID          string `json:"account_id"`
	LoginName          string `json:"login_name"`
	DisplayName        string `json:"display_name"`
	Status             string `json:"status"`
	MustChangePassword bool   `json:"must_change_password"`
	CreatedAt          string `json:"created_at"`
	// LastLoginAt 為最近一次登入時刻；從未登入時欄位缺席（不拿建立時刻冒充）。
	LastLoginAt string `json:"last_login_at,omitempty"`
	// GrantedAt 為 server_admin 授予寫下的時刻；目錄行與詳情都恆有（成員資格本身就是授予）。
	GrantedAt string `json:"granted_at"`
	// DisabledAt 為進入禁用狀態的時刻；active 時欄位缺席（不拿零值冒充「停過又沒停」）。
	DisabledAt string `json:"disabled_at,omitempty"`
	// Roles 為該帳戶經服務端核實持有的角色；僅單筆回應帶出——
	// 目錄的每一行本來就是按授予查出來的，逐行重複一份同一個字串不回答任何新問題。
	Roles []string `json:"roles,omitempty"`
}

// adminListResponse 是 GET /root/admins 的回應本體。
//
// 分頁三元組回顯「你問的是哪一頁、一頁多大、總共幾筆」：客戶端據此算頁數與
// 標空狀態，不需要（也不准）自己拿行數猜。admins 恆為數組，空頁是 []。
type adminListResponse struct {
	Admins    []adminItem `json:"admins"`
	Page      int64       `json:"page"`
	PageSize  int64       `json:"page_size"`
	Total     int64       `json:"total"`
	RequestID string      `json:"request_id"`
}

// adminProfileResponse 是 GET／PUT /root/admins/{account_id} 的回應本體。
//
// PUT 成功回的是「保存之後的資料庫現值」而不是請求本體的迴音：
// 界面顯示的當前資料必須來自服務端保存結果，這條從回應的來源就成立。
type adminProfileResponse struct {
	Admin     adminItem `json:"admin"`
	RequestID string    `json:"request_id"`
}

// adminStatusResponse 是 PUT /root/admins/{account_id}/status 的回應本體。
//
// admin 同則是「變更之後的資料庫現值」；revoked_sessions 是這次落庫的撤銷數量，
// 存在的理由只有一件：界面要能如實說出「這次讓 N 臺裝置重新登入」，
// 而不是讓 Root 對著一句「已停用」猜影響範圍。恢復時這個數恆為 0——
// 「不復活停用前會話」不需要一句安慰話，它需要一個永遠不增撤的計數。
type adminStatusResponse struct {
	Admin           adminItem `json:"admin"`
	RevokedSessions int       `json:"revoked_sessions"`
	RequestID       string    `json:"request_id"`
}

// rootAdminEndpoints 回傳管理員目錄端點登記清單；未注入用例時為空。
//
// 與 auth 端點同一個來源、同一個有無判定：登記與否只這一處，
// 「/root 首段屬於 API」因此自動成立（深連結回退不會把端點路徑當頁面回 HTML）。
func (s *Server) rootAdminEndpoints() []apiRoute {
	if s.admins == nil {
		return nil
	}
	// 同一路徑上方法決定做哪件事：分流都發生在各自 handle 的第一層，
	// 拆成多條路徑樣式反而會多出「幾個端點共用一份授權語意」的維護點。
	// {account_id} 匹配恰好一個路徑段；多出的段落到 catch-all，回 JSON 的 1001。
	// /status 是單欄（status）的子資源：狀態這種安全欄位與顯示名那種普通資料
	// 各有自己的白名單與確認語意，不共寫同一次 PUT。
	return []apiRoute{
		{"/root/admins", s.allowMethods(s.handleRootAdmins,
			http.MethodGet, http.MethodHead, http.MethodPost)},
		{"/root/admins/{account_id}", s.allowMethods(s.handleRootAdmin,
			http.MethodGet, http.MethodHead, http.MethodPut)},
		{"/root/admins/{account_id}/status", s.allowMethods(s.handleRootAdminStatus,
			http.MethodPut)},
	}
}

// rootAdminPrincipal 走三個入口共用的前置鏈：來源判定 → 憑據解析 → 首次改密門閂。
//
// 回 false 時回應已經寫好，呼叫端直接返回即可；授權不在這裡判（由用例判），
// 否則同一件事有兩套真相。
func (s *Server) rootAdminPrincipal(w http.ResponseWriter, r *http.Request) (identity.Principal, bool) {
	s.noStore(w)
	if !s.allowRequestOrigin(r) {
		writeError(w, r, CodeOriginForbidden, http.StatusForbidden)
		return identity.Principal{}, false
	}
	res := s.resolveCredentials(r)
	switch res.status {
	case credOK:
		// Root 憑據不在 accounts 表，這把閘對 Root 恆放行（見 auth.MustChangePassword）；
		// 呼叫它是為了「新增受保護端點時不必再想一次要不要擋」，而不是假裝 Root 會欠改密。
		if !s.requirePasswordChangeDone(w, r, res.resolved.Principal) {
			return identity.Principal{}, false
		}
		return res.resolved.Principal, true
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
	return identity.Principal{}, false
}

// handleRootAdmins 依方法分流：POST 開設、GET／HEAD 分頁目錄。
func (s *Server) handleRootAdmins(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.rootAdminPrincipal(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		s.createRootAdmin(w, r, principal)
		return
	}
	s.directoryRootAdmins(w, r, principal)
}

// handleRootAdmin 處理 /root/admins/{account_id}：GET／HEAD 詳情、PUT 編輯。
func (s *Server) handleRootAdmin(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.rootAdminPrincipal(w, r)
	if !ok {
		return
	}
	// 標識解析失敗與「查無此人是同一句話」：不告訴敲門的人他猜的格式对不对。
	id, err := idgen.Parse(r.PathValue("account_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if r.Method == http.MethodPut {
		s.updateRootAdmin(w, r, principal, id)
		return
	}
	profile, err := s.admins.AdminProfile(r.Context(), principal, id)
	if err != nil {
		s.writeRootAdminReadFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, adminProfileResponse{
		Admin:     profileItem(profile),
		RequestID: requestIDFromRequest(r),
	})
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

// directoryRootAdmins 處理 GET／HEAD /root/admins：解析查詢參數後交目錄用例。
//
// 「參數沒帶」與「參數帶了但不合形」分開處置：前者用本倉庫的默認常數（值只有一份），
// 後者當場回 1004 點出是哪個查詢參數——把 0 或負數默默當成「沒帶」會讓分頁錯誤
// 變成空頁，而空頁是合法回應，錯誤因此永遠查不出來。
func (s *Server) directoryRootAdmins(w http.ResponseWriter, r *http.Request, principal identity.Principal) {
	q := r.URL.Query()
	query := adminacct.DirectoryQuery{Page: 1, PageSize: adminacct.DirectoryDefaultPageSize}
	if raw := q.Get("page"); raw != "" {
		page, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
				map[string]any{"invalid_field": "page"})
			return
		}
		query.Page = page
	}
	if raw := q.Get("page_size"); raw != "" {
		size, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
				map[string]any{"invalid_field": "page_size"})
			return
		}
		query.PageSize = size
	}
	query.StatusFilter = q.Get("status")

	page, err := s.admins.Directory(r.Context(), principal, query)
	if err != nil {
		switch {
		case errors.Is(err, adminacct.ErrInvalidPage):
			writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
				map[string]any{"invalid_field": "page"})
		case errors.Is(err, adminacct.ErrInvalidPageSize):
			writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
				map[string]any{"invalid_field": "page_size"})
		case errors.Is(err, adminacct.ErrInvalidStatusFilter):
			writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
				map[string]any{"invalid_field": "status"})
		case errors.Is(err, identity.ErrPermissionDenied):
			writeError(w, r, CodePermissionDenied, http.StatusForbidden)
		default:
			s.logger.Error("列舉管理員目錄失敗", "request_id", requestIDFromRequest(r), "err", err)
			writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		}
		return
	}
	items := make([]adminItem, 0, len(page.Rows))
	for _, row := range page.Rows {
		items = append(items, directoryItem(row))
	}
	writeJSON(w, http.StatusOK, adminListResponse{
		Admins:    items,
		Page:      page.Page,
		PageSize:  page.PageSize,
		Total:     page.Total,
		RequestID: requestIDFromRequest(r),
	})
}

// updateRootAdmin 處理 PUT /root/admins/{account_id}。
func (s *Server) updateRootAdmin(w http.ResponseWriter, r *http.Request,
	principal identity.Principal, accountID idgen.ID) {
	var in updateAdminProfileRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	// 空依據值不進用例：顯示名在域規則裡恆非空，拿空字串當「我看見的現值」
	// 永遠比不中，那是一次必然落敗的請求，直接點出欄位比回衝突誠實。
	if in.ExpectedDisplayName == "" {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "expected_display_name"})
		return
	}
	updated, err := s.admins.UpdateAdminProfile(r.Context(), principal, accountID,
		in.DisplayName, in.ExpectedDisplayName, requestIDFromRequest(r))
	if err != nil {
		s.writeUpdateAdminFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, adminProfileResponse{
		Admin:     profileItem(updated),
		RequestID: requestIDFromRequest(r),
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

// writeRootAdminReadFailure 把詳情讀取的錯誤對映為對外回應。
func (s *Server) writeRootAdminReadFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminacct.ErrAdminNotFound):
		// 「不存在」與「不在目錄裡」同形（見 adminacct.ErrAdminNotFound 的說明）。
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	default:
		s.logger.Error("讀取管理員詳情失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// writeUpdateAdminFailure 把編輯用例的錯誤對映為對外回應。
//
// 每一句的處置都不同，所以各是各的碼：1004 要人改輸入、2013 要人重讀現值、
// 1001 是目標根本不在目錄、2011 是主體不對——把它們混成一句，
// 客戶端就只剩「再試一次」這把錘子，而再試一次對这四種情況都不是答案。
func (s *Server) writeUpdateAdminFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, account.ErrInvalidDisplayName):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "display_name"})
	case errors.Is(err, adminacct.ErrProfileConflict):
		writeError(w, r, CodeProfileConflict, http.StatusConflict)
	case errors.Is(err, adminacct.ErrAdminNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	default:
		s.logger.Error("編輯管理員資料失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// handleRootAdminStatus 處理 PUT /root/admins/{account_id}/status：停用或恢復登入。
//
// 這條子路徑只有 PUT 一個方法（allowMethods 已登記，其餘方法回 1002 帶 Allow）：
// 「動狀態」在協定層就只有一個入口，GET 詳情本來就在父路徑上，不在這裡開第二份讀法。
func (s *Server) handleRootAdminStatus(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.rootAdminPrincipal(w, r)
	if !ok {
		return
	}
	id, err := idgen.Parse(r.PathValue("account_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in updateAdminStatusRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	// 兩個欄位都必須落在封閉集合內：值取自 internal/account 的常數（字面值只有一份）。
	// 非法值当场 1004 點名欄位，不帶進用例——那是拼寫問題，不是併發問題。
	newStatus, expectedStatus, badField := parseAdminStatusPair(in)
	if badField != "" {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": badField})
		return
	}
	// 新舊同值是一次必然寫不出新事實的請求（見 account.Store.SetStatus 的域不变量），
	// 在這裡點名比回 2014 誠實：資料庫根本還不需要被問到。
	if newStatus == expectedStatus {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "status"})
		return
	}
	changed, err := s.admins.UpdateAdminStatus(r.Context(), principal, id,
		adminacct.StatusChangeInput{NewStatus: newStatus, ExpectedStatus: expectedStatus},
		requestIDFromRequest(r))
	if err != nil {
		s.writeUpdateAdminStatusFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, adminStatusResponse{
		Admin:           profileItem(changed.Profile),
		RevokedSessions: changed.RevokedSessions,
		RequestID:       requestIDFromRequest(r),
	})
}

// parseAdminStatusPair 把請求的字串欄位換成帳戶狀態枚舉；任何一侧不合格時
// 回傳要點名的欄位名（「status」或「expected_status」），兩侧都缺就點新目標那一側。
func parseAdminStatusPair(in updateAdminStatusRequest) (newStatus, expectedStatus account.Status, badField string) {
	newStatus = account.Status(in.Status)
	expectedStatus = account.Status(in.ExpectedStatus)
	switch {
	case in.ExpectedStatus == "":
		return "", "", "expected_status"
	case !isKnownAccountStatus(newStatus):
		return "", "", "status"
	case !isKnownAccountStatus(expectedStatus):
		return "", "", "expected_status"
	}
	return newStatus, expectedStatus, ""
}

// isKnownAccountStatus 回報狀態值是否落在帳戶域的封閉集合內。
// 比較对象取自 internal/account 的常數而不是就地抄字面值：枚舉的真相只有一份。
func isKnownAccountStatus(s account.Status) bool {
	return s == account.StatusActive || s == account.StatusDisabled
}

// writeUpdateAdminStatusFailure 把停用／恢復用例的錯誤對映為對外回應。
//
// 每一句的處置都不同，所以各是各的碼：1004 要人改寫法、2014 要人重讀目標現狀
// 再重新確認、1001 是目標根本不在目錄、2011 是主體不對——混成一句，
// 客戶端就只剩「再點一次按鈕」這把錘子，而對 2014 來說再點一次恰恰是最壞的處置。
func (s *Server) writeUpdateAdminStatusFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminacct.ErrInvalidStatusChange):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "status"})
	case errors.Is(err, adminacct.ErrStatusConflict):
		writeError(w, r, CodeAdminStatusConflict, http.StatusConflict)
	case errors.Is(err, adminacct.ErrAdminNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	default:
		s.logger.Error("變更管理員狀態失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// directoryItem 把目錄的一行投影成回應本體（欄位白名單見 internal/adminacct/directory.go）。
func directoryItem(row adminacct.DirectoryRow) adminItem {
	item := adminItem{
		AccountID:          row.AccountID,
		LoginName:          row.LoginName,
		DisplayName:        row.DisplayName,
		Status:             row.Status,
		MustChangePassword: row.MustChangePassword,
		CreatedAt:          timeutil.FormatUTC(row.CreatedAt),
		GrantedAt:          timeutil.FormatUTC(row.GrantedAt),
	}
	if !row.LastLoginAt.IsZero() {
		item.LastLoginAt = timeutil.FormatUTC(row.LastLoginAt)
	}
	return item
}

// profileItem 把單筆經實體校驗的資料成回應本體；與目錄行同形，外加角色核實結果。
func profileItem(p adminacct.Profile) adminItem {
	item := adminItem{
		AccountID:          p.AccountID.String(),
		LoginName:          p.LoginName,
		DisplayName:        p.DisplayName,
		Status:             p.Status.String(),
		MustChangePassword: p.MustChangePassword,
		CreatedAt:          timeutil.FormatUTC(p.CreatedAt),
		GrantedAt:          timeutil.FormatUTC(p.GrantedAt),
		Roles:              roleNames(p.Roles),
	}
	if !p.LastLoginAt.IsZero() {
		item.LastLoginAt = timeutil.FormatUTC(p.LastLoginAt)
	}
	if !p.DisabledAt.IsZero() {
		item.DisabledAt = timeutil.FormatUTC(p.DisabledAt)
	}
	return item
}
