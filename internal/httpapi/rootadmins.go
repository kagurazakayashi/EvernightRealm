// rootadmins.go 是「Root 對伺服器級管理員的目錄性操作」的傳輸層落點：
// /root/admins 一個路徑做兩件事（GET／HEAD 分頁目錄、POST 開設），
// /root/admins/{account_id} 一個路徑做三件事（GET／HEAD 單筆詳情、PUT 編輯非安全資料、
// DELETE 軟刪除），
// /root/admins/{account_id}/status 一條路徑做一件事（PUT 停用或恢復登入，唯一白名單欄位是狀態），
// /root/admins/{account_id}/password 一條路徑做一件事（PUT 重置登入憑據，唯一白名單欄位是新口令）。
//
// 詳情與刪除共用父路徑、狀態與憑據各有各的子路徑，這個分工不是排版偏好：
// 後兩者是「某一個安全欄位的白名單」，所以各自需要一條只能動那一欄的 PUT；
// 而刪除動的是整個帳戶的去向，它既不是一個欄位，也不是一種可設定狀態，
// 因此它是父資源上的一個方法——把它塞進 /status 會讓「恢復登入」這條路
// 間接成為刪除與被刪復活的入口，而那正是停用與刪除必須分開的理由。
//
// 這個檔案刻意只做協定層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 allowRequestOrigin＋resolveCredentials，
//     不在這裡重寫一份「先看 Cookie 再看標頭」的順序（兩套判定的結果必然是其中一套被繞過）；
//  2. 首次改密門閂——複用 requirePasswordChangeDone，與其餘受保護端點同一把閘；
//  3. 請求本體與查詢參數的形態——開設只有 login_name／display_name／password，
//     編輯只有 display_name 與它所依據的 expected_display_name，
//     停用／恢復只有 status 與 expected_status，重置憑據只有 password 一欄，
//     刪除什麼都不帶（它不選欄位，也沒有可交的依據值）；
//     未知欄位（含 role、type、status、account_id、must_change_password 這類「自報身分
//     或企圖覆蓋隱藏欄位」的嘗試）由 decodeJSON 的 DisallowUnknownFields 當場拒殺：
//     「動的是哪一類資料」由「打的哪個端點、用的哪個方法」決定，不是由請求內容決定；
//  4. 結論對映——把用例回傳的可判別錯誤一一映射到機器碼，其餘一律 500 且細節只進日誌。
//     「目標已被刪除」有自己的碼 2015，且四個寫入口徑（編輯／停用恢復／重置／刪除）
//     都走同一句話：判定點在用例裡只有一個（requireNotDeleted），傳輸層不另判一次。
//
// 回應本體絕不含口令明文、憑據雜湊、會話材料或任何內部正規化鍵：能公開的只有帳戶的
// 可展示事實。目錄與詳情的欄位是白名單投影（見 internal/adminacct/directory.go 的邊界約定的
// 單筆對應），新增欄位必須先回答「這個用途真的需要它嗎」。
//
// 路徑裡的 {account_id} 是本倉庫第一條帶路徑參數的端點：解析失敗（不是一枚 UUID）
// 與查無此人都回同一個 1001——對外的句子不區分「格式不對」與「沒有這個人」，
// 免得端點變成一台標識格式探測器。「在目錄裡但已被刪除」不是這同一句話（2015），
// 因為 Root 對著一份列著他的目錄能做的事只有「別再寫他」，而不是「換個標識」。
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
	// ResetAdminPassword 以 Root 主體重置一名目錄內管理員的登入憑據：舊口令與
	// 既有會話即刻失效、首次改密義務重設、停用狀態不動。本用例刻意沒有依據值——
	// 重置的發起人拿不出「現行口令」那類錨點（見 internal/adminacct/resetpassword.go）。
	ResetAdminPassword(ctx context.Context, principal identity.Principal,
		accountID idgen.ID, newPassword, requestID string) (adminacct.PasswordReset, error)
	// DeleteAdmin 以 Root 主體軟刪除一名目錄內管理員：停止新登入、撤銷其有效會話、
	// 顯示名匿名化，而行與登入名鍵保留以承載歷史身份。本用例與重置憑據同一取向，
	// 刻意沒有依據值——正當性錨在「他還沒被刪」這條狀態機守衛上，第二次刪除寫不中
	// 任何一行並回 ErrAdminDeleted（見 internal/adminacct/deleted.go）。
	DeleteAdmin(ctx context.Context, principal identity.Principal,
		accountID idgen.ID, requestID string) (adminacct.Deletion, error)
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

// resetAdminPasswordRequest 是重置憑據請求的本體。白名單只有新口令一欄：
// 沒有 expected_*、沒有 status、沒有 must_change_password——前兩者是別的白名單通路
// 的欄位（未知欄位 1004），第三者是本次重置要「強制寫成 1」的義務旗標，
// 絕無可能被請求反向清掉（「重置不順手免義務」成立在本體連格子都沒有的形狀上）。
type resetAdminPasswordRequest struct {
	Password string `json:"password"`
}

// deleteAdminRequest 是刪除請求的本體：一個欄位都沒有。
//
// 它存在只為了讓 decodeJSON 那道閘照常規生效——不帶本體的 DELETE 是最常見的形態，
// 而帶本體的 DELETE 必須是一個不含任何欄位的 JSON 物件。少了這個型別，
// 「順手塞 expected_status／purge／display_name」的請求會被默默當做沒看見，
// 而「看不見」在協定層就等於承認那些欄位本來可以有意義。
type deleteAdminRequest struct{}

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
	// 被刪除前本是停用者時，它在刪除之後仍帶出——那仍是「何時停的」的歷史事實。
	DisabledAt string `json:"disabled_at,omitempty"`
	// DeletedAt 為進入刪除終態的時刻；未被刪除時欄位缺席（不拿零值冒充「刪過」）。
	// status 為 deleted 時它恆存在（遷移 0007 的成對 CHECK 保證兩件事實不會各說各話）。
	DeletedAt string `json:"deleted_at,omitempty"`
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

// adminPasswordResetResponse 是 PUT /root/admins/{account_id}/password 的回應本體。
//
// admin 是「重置之後的資料庫現值」：must_change_password 恆為 true（這正是界面要把
// 「這個口令只用一次」講給 Root 聽的依據），status 與 disabled_at 保持原樣。
// revoked_sessions 與停用-response 同一理由：界面要能如實說出「這次讓 N 臺裝置重新登入」。
// 回應裡絕對不會有的東西：新口令的任何回顯（連同前綴或長度）、任一側的雜湊、
// 會話材料——口令只在請求本體裡出現一次，回應與交付都不碰它；線下的交付管道在協議之外。
type adminPasswordResetResponse struct {
	Admin           adminItem `json:"admin"`
	RevokedSessions int       `json:"revoked_sessions"`
	RequestID       string    `json:"request_id"`
}

// adminDeleteResponse 是 DELETE /root/admins/{account_id} 的回應本體。
//
// admin 是「刪除之後的資料庫現值」：status 恆為 deleted、display_name 已是佔位值、
// deleted_at 恆有——界面要把「他已被刪除、刪於何時、現在顯示什麼」講成服務端的事實，
// 而不是把 Root 剛才按下鈕這回事回顯一遍。
// revoked_sessions 與停用／重置同一理由：界面要能如實說出「這次讓 N 臺裝置失去登入狀態」。
// 對一個本就停用的目標這個數通常是 0（其會話早在停用時已撤）——0 是事實，不是失敗。
// 回應裡絕對不會有的東西：憑據雜湊、會話材料，也不會有「如何恢復」的暗示——
// 刪除是終態，本協議沒有一條把它改回來的路。
type adminDeleteResponse struct {
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
	// /password 是單欄（password）的子資源：憑據與狀態同屬安全欄位，但兩條白名單、
	// 兩套確認語意、兩個審計動作各是各的——「重置不是解除停用」在路由形狀上就分開。
	// 刪除則掛在父路徑的 DELETE 方法上：它不是一個欄位的白名單，也不是一種可設定狀態，
	// 而是整個帳戶的去向，所以既不該混進 /status 那條「active|disabled」的通路，
	// 也不需要一個自己的子路徑去宣稱「這裡動的是刪除欄」。
	return []apiRoute{
		{"/root/admins", s.allowMethods(s.handleRootAdmins,
			http.MethodGet, http.MethodHead, http.MethodPost)},
		{"/root/admins/{account_id}", s.allowMethods(s.handleRootAdminProfile,
			http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete)},
		{"/root/admins/{account_id}/status", s.allowMethods(s.handleRootAdminStatus,
			http.MethodPut)},
		{"/root/admins/{account_id}/password", s.allowMethods(s.handleRootAdminPassword,
			http.MethodPut)},
	}
}

// rootAdminPrincipal 走四個入口共用的前置鏈：來源判定 → 憑據解析 → 首次改密門閂。
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

// handleRootAdminProfile 處理 /root/admins/{account_id}：GET／HEAD 詳情、PUT 編輯、DELETE 軟刪除。
//
// 刪除沒有請求本體：它不選欄位、也不交依據值，交任何本體都會多出一個
// 「這個端點似乎可以設定點什麼」的誤讀（decodeJSON 的未知欄位規則因此無事可做）。
func (s *Server) handleRootAdminProfile(w http.ResponseWriter, r *http.Request) {
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
	switch r.Method {
	case http.MethodPut:
		s.updateRootAdmin(w, r, principal, id)
		return
	case http.MethodDelete:
		s.deleteRootAdmin(w, r, principal, id)
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

// deleteRootAdmin 處理 DELETE /root/admins/{account_id}：軟刪除一名目錄內管理員。
//
// 與其餘寫入入口同一條前置鏈（來源判定 → 憑據解析 → 首次改密門閂 → 用例內的 NeedRoot），
// 這裡不再判一次權限，否則同一件事有兩套真相。
//
// 失敗映射逐條對應不同的處置：
//   - 1001：標識不合法、目標不在目錄（含幽靈標識、未授予帳戶、Root 保留標識、
//     以及本步之前就存在的物理刪除目標）——四種企圖同一句話，端點不是標識探測器；
//   - 2015：目標已是刪除態。重試不會讓它變成成功，所以要與 1001 分開一句話；
//   - 2011：這個主體不是 Root；
//   - 500：其餘，細節只進日誌。
//
// 成功回 200 而不是 204：回應本體帶著「刪除之後的現值」與這次撤銷的會話數量，
// 界面要拿服務端的事實去改掉那份詳情，而不是拿一個空回應猜結果。
func (s *Server) deleteRootAdmin(w http.ResponseWriter, r *http.Request,
	principal identity.Principal, accountID idgen.ID) {
	// 本體不許帶任何欄位：不帶本體就是「我要刪他」，帶了就必須是個空物件。
	// 這條判定不是講究——默默忽略一份帶著 expected_status 或 purge 的本體，
	// 等於承認那些欄位本來可以有意義。
	var in deleteAdminRequest
	if r.ContentLength != 0 && !decodeJSON(w, r, &in) {
		return
	}
	deletion, err := s.admins.DeleteAdmin(r.Context(), principal, accountID, requestIDFromRequest(r))
	if err != nil {
		s.writeDeleteAdminFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, adminDeleteResponse{
		Admin:           profileItem(deletion.Profile),
		RevokedSessions: deletion.RevokedSessions,
		RequestID:       requestIDFromRequest(r),
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
	case errors.Is(err, adminacct.ErrAdminDeleted):
		// 對已刪除的目標改名：處置不是「重讀現值再改」，而是「這個目標不再接受任何寫入」。
		writeError(w, r, CodeAdminDeleted, http.StatusConflict)
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
	case errors.Is(err, adminacct.ErrAdminDeleted):
		// 已刪除的目標不是「一個還能被恢復的停用」：這句話必須有自己的碼，
		// 否則介面會把 2014 的出口（重讀再確認一次）遞給一個永遠確認不成的目標。
		writeError(w, r, CodeAdminDeleted, http.StatusConflict)
	case errors.Is(err, adminacct.ErrAdminNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	default:
		s.logger.Error("變更管理員狀態失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// handleRootAdminPassword 處理 PUT /root/admins/{account_id}/password：重置登入憑據。
//
// 這條子路徑只有 PUT 一個方法（allowMethods 已登記，其餘方法回 1002 帶 Allow）：
// 「動憑據」在協定層就只有一個入口。標識解析失敗與查無同一句話（1001），
// 口令本身的形狀不合格不在此處判（那是 credential 模組那一道閘，經用例映射為
// 1004＋點名 password 欄位）——傳輸層不抄寫第二份口令規則。
func (s *Server) handleRootAdminPassword(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.rootAdminPrincipal(w, r)
	if !ok {
		return
	}
	id, err := idgen.Parse(r.PathValue("account_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in resetAdminPasswordRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	reset, err := s.admins.ResetAdminPassword(r.Context(), principal, id,
		in.Password, requestIDFromRequest(r))
	if err != nil {
		s.writeResetAdminPasswordFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, adminPasswordResetResponse{
		Admin:           profileItem(reset.Profile),
		RevokedSessions: reset.RevokedSessions,
		RequestID:       requestIDFromRequest(r),
	})
}

// writeResetAdminPasswordFailure 把重置用例的錯誤對映為對外回應。
//
// 刻意沒有「衝突」這一句：本用例不設依據值（Root 拿不出「現行口令」那類誠實的
// 錨點），所以不存在 2013/2014 那樣的併發結論——重複提交是又做了一次完整重置，
// 每次都留一筆審計。處置各歸各：1004 要人改口令、1001 是目標不在目錄、
// 2011 是主體不對，其餘細節只進日誌。
func (s *Server) writeResetAdminPasswordFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminacct.ErrInvalidResetPassword):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "password"})
	case errors.Is(err, adminacct.ErrAdminDeleted):
		// 對已刪除的目標重置憑據：口令交出去也沒有接受者，這句話與「改改口令寫法」
		// （1004）和「這個人不在目錄裡」（1001）都不是同一處置。
		writeError(w, r, CodeAdminDeleted, http.StatusConflict)
	case errors.Is(err, adminacct.ErrAdminNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	default:
		s.logger.Error("重置管理員憑據失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// writeDeleteAdminFailure 把刪除用例的錯誤對映為對外回應。
//
// 1001 與 2015 分開只為處置不同：一個是「這個人不在這本目錄裡」，
// 另一個是「目錄裡那個你正看著的人已經被刪掉了」。把後者報成 1001，
// Root 會對著一份明明列著他的目錄反覆懷疑標識抄錯；把後者報成成功，
// 則是在審計與真相之間造出一件沒發生過的事（重複刪除在資料庫裡一個字都沒寫）。
// 本用例刻意沒有衝突那一句：它不設依據值，所以不存在 2013/2014 式的落敗。
func (s *Server) writeDeleteAdminFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, adminacct.ErrAdminDeleted):
		writeError(w, r, CodeAdminDeleted, http.StatusConflict)
	case errors.Is(err, adminacct.ErrAdminNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	default:
		s.logger.Error("刪除管理員失敗", "request_id", requestIDFromRequest(r), "err", err)
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
	if !row.DeletedAt.IsZero() {
		item.DeletedAt = timeutil.FormatUTC(row.DeletedAt)
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
	if !p.DeletedAt.IsZero() {
		item.DeletedAt = timeutil.FormatUTC(p.DeletedAt)
	}
	return item
}
