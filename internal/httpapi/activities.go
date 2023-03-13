// activities.go 是「活動生命週期管理」在傳輸層的落點：
// /admin/activities 一條路徑做兩件事（GET／HEAD 分頁目錄、POST 建立），
// /admin/activities/{activity_id} 一條路徑做兩件事（GET／HEAD 詳情、PUT 編輯資料），
// /admin/activities/{activity_id}/status 一條路徑做一件事（PUT 轉換狀態），
// /admin/activities/{activity_id}/managers 一條路徑做一件事（GET／HEAD 讀名冊），
// /root/activities/{activity_id}/managers 一條路徑做一件事（POST 指派），
// /root/activities/{activity_id}/managers/{account_id} 一條路徑做一件事（DELETE 撤銷）。
//
// 本檔案刻意只做協議層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 consolePrincipal 那條共用鏈，不在這裡重寫一份
//     「先看 Cookie 再看標頭」的順序；
//  2. 首次改密門閂——同一條鏈上的 requirePasswordChangeDone，與其餘受保護端點同一把閘；
//  3. 請求本體與查詢引數的形態——建立只認 name／description 兩個欄位，
//     編輯只認那兩欄加上它們各自依據的現值，狀態轉換只認 status 一欄，
//     指派只認 account_id 一欄，撤銷什麼都不帶；未知欄位由 decodeJSON 的
//     DisallowUnknownFields 當場拒殺（1004），於是「順手把 id、created_by、archived_at、
//     還有一條自報的角色一起送進來」在本體裡沒有一個可以填的格子——
//     「動的是哪個活動」由路徑決定，「誰在做」由那枚憑據決定，都不由請求內容決定；
//  4. 結論對映——把用例回傳的可判別錯誤一一對映到機器碼，其餘一律 500 且細節只進日誌。
//     這組端點用到的碼：1001（活動不在可見範圍，含標識寫壞與「不是他管的活動」兩種情況）、
//     1004（改寫法）、2011（換個身分辨不成這件事）、2013（資料現值已過期）、
//     2015（指派目標已是被軟刪除的管理員）、
//     以及本步新發布的 2029（已歸檔，終態拒寫）、2030（狀態現值衝突）、
//     2031（那條路不存在）、2032（他已經是這個活動的管理人）。
//
// 為什麼管理的入口在 /admin 而增減管理人在 /root（用戶批准於本步）：
// 「管某個活動的資料與狀態」屬於管理員這個身份面，而且還要再過活動作用域那道閘——
// 伺服器級管理員不等於所有活動的管理員；「把一個帳戶變成能管某個活動」則是一次權限授予，
// 與 Root 開設管理員、Root 簽發准入憑證同側，因此走 NeedRoot。兩組端點各有各的依賴欄位，
// 少注入誰就少那一組通路，不會留下一條半能用的路。
//
// 回應本體絕不含任何憑據材料、會話材料或帳戶內部欄位：活動帶的是名稱、描述、狀態、
// 建立者標識、管理人數與三個時刻；名冊帶的是管理人的顯示名與他此刻的帳戶狀態。
// Root 建立的活動在 created_by_account_id 那一格缺席（omitempty）：Root 不在 accounts 表裡，
// 介面據「這一格有沒有出現」顯示「由 Root 建立」，而不是拿一個讀不回任何人的標識冒充。
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/kagurazakayashi/EvernightRealm/internal/activity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// ActivityUseCase 是「活動生命週期管理」用例在傳輸層的入口形態（由 internal/app 注入 *activity.Service）。
//
// 獨立一個依賴欄位：本執行檔沒注入它時一個活動端點都不掛，協定層行為與尚未有活動模組的版次
// 逐字相同（與邀請碼、審批那兩組同一取向）。principal 一律是「本次請求的憑據此刻換出的受信主體」，
// 授權（NeedServerAdmin／NeedRoot）、活動作用域判定、現值核實與那一跳落庫都在用例裡判。
type ActivityUseCase interface {
	// Create 建立一個活動（一律是草稿），並在同一筆交易裡把建立者指派為第一位管理人。
	// 帳戶主體以外（Root）沒有可指派的帳戶標識，那一格在回應裡缺席。
	Create(ctx context.Context, principal identity.Principal,
		name, description, requestID string) (activity.Activity, error)
	// Directory 以當前受信主體讀一頁活動目錄：Root 看全部，帳戶只看自己獲指派的活動。
	Directory(ctx context.Context, principal identity.Principal,
		query activity.DirectoryQuery) (activity.DirectoryPage, error)
	// ActivityDetail 讀回單筆活動；不在可見範圍與查無此活動收斂成同一句話。
	ActivityDetail(ctx context.Context, principal identity.Principal,
		activityID idgen.ID) (activity.Activity, error)
	// UpdateActivityProfile 以白名單編輯活動的名稱與描述；兩個 expected_* 是呼叫端
	// 提交所依據的現值，現值已變時整個編輯不發生並回可判別的衝突結論。
	// 狀態、建立者與識別欄位不在這條通路的白名單裡（見 internal/activity/profile.go）。
	UpdateActivityProfile(ctx context.Context, principal identity.Principal,
		activityID idgen.ID, name, description, expectedName, expectedDescription,
		requestID string) (activity.Activity, error)
	// Transition 把活動推到目標狀態；只有已批准的四條路徑走得通，
	// 歸檔之後一律拒寫（見 internal/activity/status.go）。
	Transition(ctx context.Context, principal identity.Principal,
		activityID idgen.ID, target activity.Status, requestID string) (activity.Activity, error)
	// AssignManager 由 Root 把一位既有管理員指派為該活動的管理人。
	AssignManager(ctx context.Context, principal identity.Principal,
		activityID, accountID idgen.ID, requestID string) (activity.Activity, error)
	// RevokeManager 由 Root 撤銷一筆指派；本來就沒有這個指派回報查無此人而不是謊報成功。
	RevokeManager(ctx context.Context, principal identity.Principal,
		activityID, accountID idgen.ID, requestID string) (activity.Activity, error)
	// ManagerRoster 讀回該活動當前的管理人名冊（讀的權限與活動作用域同閘，寫不在這條通路上）。
	ManagerRoster(ctx context.Context, principal identity.Principal,
		activityID idgen.ID) ([]activity.Manager, error)
}

// createActivityRequest 是建立請求的本體。白名單只有兩個欄位：
// status 由「新建一律草稿」這條領域規則決定，created_by 由憑據決定，
// id 由 idgen 決定——三者在本體裡都沒有格子，因此「我建一個已開放的活動、
// 建立者填我自己以外的誰」在協定層就沒有發生點。
type createActivityRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// updateActivityProfileRequest 是資料編輯請求的本體。白名單是兩欄資料加它們各自的現值依據：
// id／activity_id／status／created_by／archived_at 這些身分與狀態列位都沒有格子（未知欄位 1004），
// 「儲存資料順手把活動改成已開放」或「順手把它挪成另一個活動」因此不是被拒，而是無處可填。
type updateActivityProfileRequest struct {
	Name                string `json:"name"`
	Description         string `json:"description"`
	ExpectedName        string `json:"expected_name"`
	ExpectedDescription string `json:"expected_description"`
}

// updateActivityStatusRequest 是狀態轉換請求的本體。白名單只有目標狀態一欄：
// 刻意不帶 expected_status——操作者對「現在的狀態」拿不出比現值更誠實的錨點，
// 正當性錨在帶 WHERE 的單向 UPDATE 上（見 internal/activity/store.go 的 UpdateStatus），
// 現值已變與同態重複都收斂成 2030。名稱與描述也不在本體之內（那是父路徑的白名單）。
type updateActivityStatusRequest struct {
	Status string `json:"status"`
}

// assignActivityManagerRequest 是指派請求的本體。白名單只有目標帳戶標識一欄：
// 「誰在指派」由那枚 Root 憑據決定，本體沒有任何格子能填操作者；
// role／account_type／granted_at 這些欄位也不存在——被指派者必須已經持有伺服器級管理員資格，
// 那一句由服務層現讀 internal/grant，不由請求宣告。
type assignActivityManagerRequest struct {
	AccountID string `json:"account_id"`
}

// revokeActivityManagerRequest 是撤銷請求的本體：一個空格都沒有（同 R2-005 的刪除約定——
// 空物件或無本體，任何未知欄位由 decodeJSON 當場拒殺為 1004）。
type revokeActivityManagerRequest struct{}

// activityItem 是目錄行、建立回顯、詳情與各條寫入結果共用的形狀
// （同一筆資料在不同回應裡的形狀必須同源）。
//
// created_by_account_id 與 archived_at 走 omitempty：缺席是事實的缺席
// （由 Root 建立而 Root 沒有帳戶標識／還沒歸檔），不拿一個讀不回任何人的標識或 1970 年冒充。
type activityItem struct {
	ActivityID   string `json:"activity_id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Status       string `json:"status"`
	CreatedBy    string `json:"created_by_account_id,omitempty"`
	ManagerCount int64  `json:"manager_count"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	ArchivedAt   string `json:"archived_at,omitempty"`
}

// activityDirectoryResponse 是 GET／HEAD /admin/activities 的回應本體。
type activityDirectoryResponse struct {
	Activities []activityItem `json:"activities"`
	Page       int64          `json:"page"`
	PageSize   int64          `json:"page_size"`
	Total      int64          `json:"total"`
	RequestID  string         `json:"request_id"`
}

// activityDetailResponse 是 GET／HEAD /admin/activities/{activity_id} 的回應本體。
type activityDetailResponse struct {
	Activity  activityItem `json:"activity"`
	RequestID string       `json:"request_id"`
}

// createActivityResponse 是 POST /admin/activities 的回應本體（201）。
type createActivityResponse struct {
	Activity  activityItem `json:"activity"`
	RequestID string       `json:"request_id"`
}

// activityManagerItem 是名冊行：管理人的顯示名與他此刻的帳戶狀態。
//
// account_status 如實帶出 deleted 這類終態——名冊不藏這種行（仍列、可讀），
// 介面據這一格把那張卡轉成只讀，而不是假裝查無此人。
// display_name 為空表示該帳戶行已被物理清理（軟參照讀不回顯示名）：
// 空值就是空值，介面不編造一個名字。
type activityManagerItem struct {
	AccountID     string `json:"account_id"`
	DisplayName   string `json:"display_name"`
	AccountStatus string `json:"account_status"`
	GrantedAt     string `json:"granted_at"`
}

// activityManagerRosterResponse 是名冊讀法的回應本體。
//
// 刻意不帶 activity 這一格：詳情本来就是單筆讀法，名冊多帶一份「順带的現值」只會造出
// 同一筆活動有兩個答案來源，而且這條路徑上的讀取根本不寫東西，無現值可回。
// 指派與撤銷的回應帶著活動現值（見 activityWriteResponse），兩處不同形是刻意的。
type activityManagerRosterResponse struct {
	Managers  []activityManagerItem `json:"managers"`
	RequestID string                `json:"request_id"`
}

// activityWriteResponse 是 PUT 編輯、PUT 轉換與 POST 指派、DELETE 撤銷共用的寫入回應本體。
type activityWriteResponse struct {
	Activity  activityItem `json:"activity"`
	RequestID string       `json:"request_id"`
}

// activityEndpoints 回傳活動管理端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深連結回退用的 API 首段清單（/admin 與 /root）因此自動同步。
// 名冊的讀法掛在 /admin 而寫法掛在 /root：同一張表、兩套准入邊界
// （NeedServerAdmin 加活動作用域判定，對 NeedRoot），共用一個字首就會出現
// 「讀的人順手也能寫」的誤讀形態。
func (s *Server) activityEndpoints() []apiRoute {
	if s.activities == nil {
		return nil
	}
	return []apiRoute{
		{"/admin/activities", s.allowMethods(s.handleActivities,
			http.MethodGet, http.MethodHead, http.MethodPost)},
		{"/admin/activities/{activity_id}", s.allowMethods(s.handleActivityProfile,
			http.MethodGet, http.MethodHead, http.MethodPut)},
		{"/admin/activities/{activity_id}/status", s.allowMethods(s.handleActivityStatus,
			http.MethodPut)},
		{"/admin/activities/{activity_id}/managers", s.allowMethods(s.handleActivityManagers,
			http.MethodGet, http.MethodHead)},
		{"/root/activities/{activity_id}/managers", s.allowMethods(s.handleActivityManagerAssign,
			http.MethodPost)},
		{"/root/activities/{activity_id}/managers/{account_id}", s.allowMethods(s.handleActivityManagerRevoke,
			http.MethodDelete)},
	}
}

// handleActivities 依方法分流：GET／HEAD 分頁目錄、POST 建立一個活動。
func (s *Server) handleActivities(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		s.createActivity(w, r, principal)
		return
	}
	s.directoryActivities(w, r, principal)
}

// directoryActivities 處理 GET／HEAD /admin/activities：解析查詢引數後交目錄用例。
//
// 「引數沒帶」與「帶了但不合形」分開處置：前者用本倉庫的預設常數（值只有一份），
// 後者當場回 1004 點名是哪個查詢引數。q（關鍵字）不做任何解析：它是一段原字串比對，
// 長短與取值集合由用例判，空字串與「沒帶」在用例裡收斂成同一句話。
func (s *Server) directoryActivities(w http.ResponseWriter, r *http.Request, principal identity.Principal) {
	query := r.URL.Query()
	directory := activity.DirectoryQuery{Page: 1, PageSize: activity.DirectoryDefaultPageSize}
	if raw := query.Get("page"); raw != "" {
		page, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
				map[string]any{"invalid_field": "page"})
			return
		}
		directory.Page = page
	}
	if raw := query.Get("page_size"); raw != "" {
		size, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
				map[string]any{"invalid_field": "page_size"})
			return
		}
		directory.PageSize = size
	}
	directory.StatusFilter = query.Get("status")
	directory.Keyword = query.Get("q")

	page, err := s.activities.Directory(r.Context(), principal, directory)
	if err != nil {
		s.writeActivityDirectoryFailure(w, r, err)
		return
	}
	items := make([]activityItem, 0, len(page.Rows))
	for _, row := range page.Rows {
		items = append(items, activityRow(row))
	}
	writeJSON(w, http.StatusOK, activityDirectoryResponse{
		Activities: items,
		Page:       page.Page,
		PageSize:   page.PageSize,
		Total:      page.Total,
		RequestID:  requestIDFromRequest(r),
	})
}

// createActivity 處理 POST /admin/activities：建立一個草稿活動。
func (s *Server) createActivity(w http.ResponseWriter, r *http.Request, principal identity.Principal) {
	var in createActivityRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	created, err := s.activities.Create(r.Context(), principal, in.Name, in.Description,
		requestIDFromRequest(r))
	if err != nil {
		s.writeActivityCreateFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, createActivityResponse{
		Activity:  activityRow(created),
		RequestID: requestIDFromRequest(r),
	})
}

// handleActivityProfile 處理 /admin/activities/{activity_id}：GET／HEAD 詳情、PUT 編輯資料。
//
// 標識解析失敗與「這個活動不在他的可見範圍」是同一句話（1001）：不告訴敲門的人
// 他猜的格式對不對，也不承認「那確實是一個活動、只是輪不到你」。
// 已歸檔的活動在這裡換到的是 2029——那是一行他看得見、卻動不了的記錄，
// 報成 1001 會讓他對著目錄裡明明列著的活動反覆懷疑標識抄錯了。
func (s *Server) handleActivityProfile(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	id, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if r.Method == http.MethodPut {
		s.updateActivityProfile(w, r, principal, id)
		return
	}
	detail, err := s.activities.ActivityDetail(r.Context(), principal, id)
	if err != nil {
		s.writeActivityDetailFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, activityDetailResponse{
		Activity:  activityRow(detail),
		RequestID: requestIDFromRequest(r),
	})
}

// updateActivityProfile 處理 PUT /admin/activities/{activity_id}：白名單編輯名稱與描述。
func (s *Server) updateActivityProfile(w http.ResponseWriter, r *http.Request,
	principal identity.Principal, id idgen.ID) {
	var in updateActivityProfileRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	updated, err := s.activities.UpdateActivityProfile(r.Context(), principal, id,
		in.Name, in.Description, in.ExpectedName, in.ExpectedDescription, requestIDFromRequest(r))
	if err != nil {
		s.writeActivityProfileFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, activityWriteResponse{
		Activity:  activityRow(updated),
		RequestID: requestIDFromRequest(r),
	})
}

// handleActivityStatus 處理 PUT /admin/activities/{activity_id}/status：狀態轉換。
//
// 這條子路徑只有 PUT 一個方法：「改狀態」在協議層只有一個入口，讀現值本來就在父路徑上。
// 本體只認 status 一欄，也不交依據值（理由見 updateActivityStatusRequest 頭注）。
func (s *Server) handleActivityStatus(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	id, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in updateActivityStatusRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	// 「這個名字不存在」與「這個名字存在但不是四態之一」在這裡是同一句話（1004 點名 status）：
	// 集合外的取值沒有可判別的處置差異，改寫法才有答案。
	target, err := activity.ParseStatus(strings.TrimSpace(in.Status))
	if err != nil {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "status"})
		return
	}
	updated, err := s.activities.Transition(r.Context(), principal, id, target, requestIDFromRequest(r))
	if err != nil {
		s.writeActivityStatusFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, activityWriteResponse{
		Activity:  activityRow(updated),
		RequestID: requestIDFromRequest(r),
	})
}

// handleActivityManagers 處理 GET／HEAD /admin/activities/{activity_id}/managers：讀名冊。
//
// 讀的權限與活動本身同一道閘（Root 或該活動的管理人）：管理人看得見「還有誰在管這個活動」，
// 但他不能據此加人或刪人——寫法在 /root 那一組上。
func (s *Server) handleActivityManagers(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	id, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	roster, err := s.activities.ManagerRoster(r.Context(), principal, id)
	if err != nil {
		s.writeActivityRosterFailure(w, r, err)
		return
	}
	// 名冊是一張可以長也可以為空的表，這條讀法只回答「他管不著這個活動」那一種失敗，
	// 因此回應不帶活動那一格（要現值請讀詳情，別讓同一筆資料有兩個答案來源）。
	items := make([]activityManagerItem, 0, len(roster))
	for _, row := range roster {
		items = append(items, activityManagerRow(row))
	}
	writeJSON(w, http.StatusOK, activityManagerRosterResponse{
		Managers:  items,
		RequestID: requestIDFromRequest(r),
	})
}

// handleActivityManagerAssign 處理 POST /root/activities/{activity_id}/managers：指派一位管理人。
func (s *Server) handleActivityManagerAssign(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in assignActivityManagerRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	accountID, err := idgen.Parse(strings.TrimSpace(in.AccountID))
	if err != nil {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "account_id"})
		return
	}
	updated, err := s.activities.AssignManager(r.Context(), principal, activityID, accountID,
		requestIDFromRequest(r))
	if err != nil {
		s.writeActivityAssignFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, activityWriteResponse{
		Activity:  activityRow(updated),
		RequestID: requestIDFromRequest(r),
	})
}

// handleActivityManagerRevoke 處理 DELETE /root/activities/{activity_id}/managers/{account_id}：撤銷指派。
//
// 兩個標識任一個非法都是 1001（同 R2 各條目標路徑）：這句話不區分「格式不對」與「沒有這一行」，
// 免得端點變成一臺標識格式探測器。本體什麼都不許帶：不選欄位、也不交依據值。
func (s *Server) handleActivityManagerRevoke(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	accountID, err := idgen.Parse(r.PathValue("account_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in revokeActivityManagerRequest
	if r.ContentLength != 0 && !decodeJSON(w, r, &in) {
		return
	}
	updated, err := s.activities.RevokeManager(r.Context(), principal, activityID, accountID,
		requestIDFromRequest(r))
	if err != nil {
		s.writeActivityAssignFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, activityWriteResponse{
		Activity:  activityRow(updated),
		RequestID: requestIDFromRequest(r),
	})
}

// activityRow 把一筆活動換成回應本體（欄位白名單見 internal/activity/store.go 的讀法）。
func activityRow(a activity.Activity) activityItem {
	item := activityItem{
		ActivityID:   a.ID.String(),
		Name:         a.Name,
		Description:  a.Description,
		Status:       a.Status.String(),
		ManagerCount: a.ManagerCount,
		CreatedAt:    timeutil.FormatUTC(a.CreatedAt),
		UpdatedAt:    timeutil.FormatUTC(a.UpdatedAt),
	}
	if !a.CreatedByAccountID.IsNil() {
		item.CreatedBy = a.CreatedByAccountID.String()
	}
	if !a.ArchivedAt.IsZero() {
		item.ArchivedAt = timeutil.FormatUTC(a.ArchivedAt)
	}
	return item
}

// activityManagerRow 把一行指派換成名冊項；三個「缺席」各有其意義（見型別頭注）。
func activityManagerRow(m activity.Manager) activityManagerItem {
	return activityManagerItem{
		AccountID:     m.AccountID.String(),
		DisplayName:   m.DisplayName,
		AccountStatus: string(m.AccountStatus),
		GrantedAt:     timeutil.FormatUTC(m.GrantedAt),
	}
}

// writeActivityCommonFailures 是六條通路共用的那一段對映：主體與可見範圍。
//
// 回傳 true 表示已寫出回應。身分類失敗（沒帶憑據、憑據換不出身分）由 consolePrincipal
// 那一條鏈攔掉，走到這裡只剩兩種結論：2011（這個身分做不了這件事）與
// 1001（這個活動不在他的可見範圍）。主體不合法（帶著有效會話卻換不出可信主體）照 500 報，
// 讓它被當成缺陷查，而不是報成 2011 讓操作者以為自己沒登入。
func (s *Server) writeActivityCommonFailures(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case errors.Is(err, activity.ErrActivityNotFound), errors.Is(err, activity.ErrNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	case errors.Is(err, identity.ErrNotAuthenticated), errors.Is(err, identity.ErrInvalidPrincipal),
		errors.Is(err, identity.ErrInvalidRequirement):
		s.logger.Error("活動端點的主體不合法", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	default:
		return false
	}
	return true
}

// writeActivityDirectoryFailure 把目錄用例的錯誤對映為對外回應（每個結論引數各自點名）。
//
// 每一個分支寫完回應就 return：少了那一句，一段已被答覆的錯誤會繼續往下掉進
// 「未知故障」那條 500，於是一個人收到兩份信封，而第二份才是難看的那一份。
func (s *Server) writeActivityDirectoryFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, activity.ErrInvalidPage):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "page"})
		return
	case errors.Is(err, activity.ErrInvalidPageSize):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "page_size"})
		return
	case errors.Is(err, activity.ErrInvalidStatusFilter):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "status"})
		return
	case errors.Is(err, activity.ErrInvalidKeyword):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "q"})
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("讀取活動目錄失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}

// writeActivityCreateFailure 把建立用例的錯誤對映為對外回應。
func (s *Server) writeActivityCreateFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, activity.ErrInvalidName):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "name"})
		return
	case errors.Is(err, activity.ErrInvalidDescription):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "description"})
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("建立活動失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}

// writeActivityDetailFailure 把詳情與名冊兩條讀法的錯誤對映為對外回應。
func (s *Server) writeActivityDetailFailure(w http.ResponseWriter, r *http.Request, err error) {
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("讀取活動詳情失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}

// writeActivityRosterFailure 保留給名冊那條讀法日後需要的差異化結論。
//
// 目前它與詳情完全同形（可見範圍、身分、故障三類），因此直接委派——
// 分成兩個函式只為了讓「日後名冊要多加一句什麼」時有個明確的落點，而不是改到詳情去。
func (s *Server) writeActivityRosterFailure(w http.ResponseWriter, r *http.Request, err error) {
	s.writeActivityDetailFailure(w, r, err)
}

// writeActivityProfileFailure 把資料編輯用例的錯誤對映為對外回應。
//
// 2013 沿用帳戶資料編輯那一枚（同一句話、同一處置：重讀現值再決定），不另發新碼；
// 2029 是本步新發布的那一枚終態拒寫。被拒的編輯不回顯任何一方現值。
func (s *Server) writeActivityProfileFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, activity.ErrInvalidName):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "name"})
		return
	case errors.Is(err, activity.ErrInvalidDescription):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "description"})
		return
	case errors.Is(err, activity.ErrProfileConflict):
		writeError(w, r, CodeProfileConflict, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrArchived):
		writeError(w, r, CodeActivityArchived, http.StatusConflict)
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("編輯活動資料失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}

// writeActivityStatusFailure 把狀態轉換用例的錯誤對映為對外回應。
//
// 三句拒絕各有各的碼，因為處置完全不同：2029「這件事已經結束」、2030「重讀現值再決定」、
// 2031「這條路不存在，重讀也沒有用」。
func (s *Server) writeActivityStatusFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, activity.ErrArchived):
		writeError(w, r, CodeActivityArchived, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrStatusConflict):
		writeError(w, r, CodeActivityStatusConflict, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrInvalidTransition):
		writeError(w, r, CodeActivityTransitionInvalid, http.StatusConflict)
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("轉換活動狀態失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}

// writeActivityAssignFailure 把指派與撤銷兩條通路的錯誤對映為對外回應。
//
// 查無此人是 1001：它罩住「那個活動不存在或輪不到你」（在 /root 上就是從沒這個活動）、
// 「那個帳戶不在能被指派的範圍裡」與「本來就沒有這個指派」——三者對操作者都是同一個處置：
// 換一個目標。已刪除終態是 2015（沿用帳戶側那一枚：同一句話、同一處置「別再對他下寫入令」）；
// 已是管理人與已歸檔各有各的新碼。
func (s *Server) writeActivityAssignFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, activity.ErrManagerDuplicate):
		writeError(w, r, CodeActivityManagerTaken, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrManagerDeleted):
		writeError(w, r, CodeAdminDeleted, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrManagerNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	case errors.Is(err, activity.ErrArchived):
		writeError(w, r, CodeActivityArchived, http.StatusConflict)
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("變動活動管理人失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}
