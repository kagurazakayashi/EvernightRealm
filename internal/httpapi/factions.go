// factions.go 是「活動陣營管理」在傳輸層的落點：
// /admin/activities/{activity_id}/factions 一條路徑做兩件事（GET／HEAD 列表、POST 建立），
// /admin/activities/{activity_id}/factions/{faction_id} 一條路徑做一件事（PUT 編輯）。
//
// 本檔案刻意只做協議層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 consolePrincipal 那條共用鏈；
//  2. 首次改密門閂——同一條鏈上的 requirePasswordChangeDone；
//  3. 請求本體的形態——建立只認 name／description／icon／color 四個欄位與可選的
//     sort_order，編輯只認那六欄（含可用開關）加上它們各自依據的現值；
//     未知欄位由 decodeJSON 的 DisallowUnknownFields 當場拒殺（1004），於是
//     「順手把 faction_id、activity_id、created_at、還有一格自報的 available 意圖
//     寫進不該有的地方」在本體裡沒有可以填的格子——「動哪個陣營」由路徑決定，
//     「哪個活動下的陣營」由路徑決定，「誰在做」由那枚憑據決定；
//  4. 結論對映——把用例回傳的可判別錯誤一一對映到機器碼，其餘一律 500 且細節只進日誌。
//     這組端點用到的碼：1001（陣營或活動不在可見範圍，含標識寫壞、不屬於該活動
//     與「不是他管的活動」）、1004（點名欄位）、2011（不屬於管理員這個身份面）、
//     2013（資料現值已過期，沿 R2-008／R3-001 復用口徑）、2029（歸檔終態）、
//     以及本步新發布的 2033（活動停止，業務寫入待重開）與 2034（同活動內陣營重名）。
//
// 為什麼陣營端點掛在 /admin 而不另發一組 /root（用戶批准於本步的邊界沿用 R3-001）：
// 打理活動內的陣營屬「管某個活動本身的資料」，准入是 NeedServerAdmin 加上這個活動的
// 一行指派——與活動資料編輯同一道閘，因此同一個前綴；普通成員敲不進任何一條。
// 本步沒有「把陣營挪去另一個活動」或「物理刪除陣營」的通路（見遷移 0013 檔頭），
// 因此這一族路徑上不存在 DELETE，也沒有任何方法能改變歸屬。
//
// 回應本體不含任何憑據材料、會話材料或帳戶內部欄位：一行陣營帶的就是它的六欄白名單
// 資料、標識、歸屬活動與兩個時刻。可用性是旗標：停用不藏行，列表照樣列（仍列、可讀）。
package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/kagurazakayashi/EvernightRealm/internal/activity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// FactionUseCase 是「活動陣營管理」用例在傳輸層的入口形態（由 internal/app 注入同一個
// *activity.Service 的陣營通路）。
//
// 獨立一個依賴欄位（口徑同 Activities 與 GuestBindings 的分離理由）：本執行檔沒注入它時
// 一個陣營端點都不掛，協定層行為與尚未有陣營模組的版次逐字相同。
// principal 一律是「本次請求的憑據此刻換出的受信主體」，授權、活動作用域判定、
// 業務寫入門禁、重名核實與那一跳落庫都在用例裡判。
type FactionUseCase interface {
	// CreateFaction 在一個活動裡建立陣營：新建一律可用，未指定排序值時由服務層
	// 在交易內排到最後一格；停止與歸檔的活動一律拒寫（各自一句話，見 internal/activity/status.go）。
	CreateFaction(ctx context.Context, principal identity.Principal,
		activityID idgen.ID, draft activity.FactionDraft, requestID string) (activity.Faction, error)
	// Factions 以當前受信主體讀一個活動的陣營列表（仍列、可讀：停止與歸檔照樣能讀）。
	Factions(ctx context.Context, principal identity.Principal,
		activityID idgen.ID) ([]activity.Faction, error)
	// UpdateFaction 以白名單編輯六欄資料（含可用性開關）；六個 expected_* 是提交所依據的
	// 現值，現值已變時整個編輯不落並回可判別的衝突。標識與歸屬不在這條通路上。
	UpdateFaction(ctx context.Context, principal identity.Principal,
		activityID, factionID idgen.ID, edit activity.FactionEdit, requestID string) (activity.Faction, error)
}

// createFactionRequest 是建立陣營請求的本體。白名單是四個必填欄位加一格可選的排序值：
// available 沒有格子——出生形態由「新建一律可用」這條領域規則決定；
// id／activity_id／created_at 也沒有格子——身份與歸屬由路徑和倉儲決定（見 internal/activity/factions.go）。
// sort_order 缺席（未帶該欄）時由服務層現算排尾值；帶了就必须是界內整數。
type createFactionRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Color       string `json:"color"`
	SortOrder   *int64 `json:"sort_order"`
}

// updateFactionRequest 是編輯陣營請求的本體：六欄白名單新值加六欄依據值。
// id／activity_id／created_at 連一個格子都沒有（未知欄位 1004），
// 「儲存陣營資料順手把它挪進另一個活動」或「順手改它的身份」因此不是被拒，而是無處可填。
// 依據值逐欄對應：正確性錨在「庫裡此刻的六欄等於你依據的那六欄」這條可觀測事實上。
type updateFactionRequest struct {
	Name                string `json:"name"`
	Description         string `json:"description"`
	Icon                string `json:"icon"`
	Color               string `json:"color"`
	SortOrder           int64  `json:"sort_order"`
	Available           bool   `json:"available"`
	ExpectedName        string `json:"expected_name"`
	ExpectedDescription string `json:"expected_description"`
	ExpectedIcon        string `json:"expected_icon"`
	ExpectedColor       string `json:"expected_color"`
	ExpectedSortOrder   int64  `json:"expected_sort_order"`
	ExpectedAvailable   bool   `json:"expected_available"`
}

// factionItem 是列表行、建立回顯與編輯結果共用的形狀（同一筆資料在不同回應裡的形狀必須同源）。
type factionItem struct {
	FactionID   string `json:"faction_id"`
	ActivityID  string `json:"activity_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Color       string `json:"color"`
	SortOrder   int64  `json:"sort_order"`
	Available   bool   `json:"available"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// factionListResponse 是 GET／HEAD 列表的回應本體。
//
// 不帶活動那一格：列表本来就是「這個活動的陣營們」，活動現值屬父路徑的詳情讀法，
// 塞在這裡會讓同一筆活動有兩個答案來源（口徑同管理人名冊）。
// 陣營表按本步形態是小表（一場活動的幾組陣營），與名冊同樣不分頁。
type factionListResponse struct {
	Factions  []factionItem `json:"factions"`
	RequestID string        `json:"request_id"`
}

// factionWriteResponse 是 POST 建立與 PUT 編輯共用的寫入回應本體。
type factionWriteResponse struct {
	Faction   factionItem `json:"faction"`
	RequestID string      `json:"request_id"`
}

// factionEndpoints 回傳陣營管理端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深連結回退用的 API 首段清單（/admin）因此自動同步。
// 建立與讀取掛在集合路徑上、編輯掛在單筆路徑上；這一族沒有 DELETE——
// 本步批准的是「只有可用／停用，沒有刪除通路」（見遷移 0013 檔頭）。
func (s *Server) factionEndpoints() []apiRoute {
	if s.factions == nil {
		return nil
	}
	return []apiRoute{
		{"/admin/activities/{activity_id}/factions", s.allowMethods(s.handleFactions,
			http.MethodGet, http.MethodHead, http.MethodPost)},
		{"/admin/activities/{activity_id}/factions/{faction_id}", s.allowMethods(s.handleFactionProfile,
			http.MethodPut)},
	}
}

// handleFactions 依方法分流：GET／HEAD 陣營列表、POST 建立一個陣營。
func (s *Server) handleFactions(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if r.Method == http.MethodPost {
		s.createFaction(w, r, principal, activityID)
		return
	}
	s.listFactions(w, r, principal, activityID)
}

// listFactions 處理 GET／HEAD 列表：可見範圍的拒絕與「從沒這個活動」同形（1001），
// 已歸檔與已停止的活動照樣列出行（仍列、可讀）。
func (s *Server) listFactions(w http.ResponseWriter, r *http.Request,
	principal identity.Principal, activityID idgen.ID) {
	rows, err := s.factions.Factions(r.Context(), principal, activityID)
	if err != nil {
		if s.writeActivityCommonFailures(w, r, err) {
			return
		}
		s.logger.Error("讀取陣營列表失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		return
	}
	items := make([]factionItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, factionRow(row))
	}
	writeJSON(w, http.StatusOK, factionListResponse{
		Factions:  items,
		RequestID: requestIDFromRequest(r),
	})
}

// createFaction 處理 POST 建立：本體白名單交用例，其餘結論都在對映裡。
func (s *Server) createFaction(w http.ResponseWriter, r *http.Request,
	principal identity.Principal, activityID idgen.ID) {
	var in createFactionRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	created, err := s.factions.CreateFaction(r.Context(), principal, activityID,
		activity.FactionDraft{
			Name:        in.Name,
			Description: in.Description,
			Icon:        in.Icon,
			Color:       in.Color,
			SortOrder:   in.SortOrder,
		}, requestIDFromRequest(r))
	if err != nil {
		s.writeFactionWriteFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, factionWriteResponse{
		Faction:   factionRow(created),
		RequestID: requestIDFromRequest(r),
	})
}

// handleFactionProfile 處理 /admin/activities/{activity_id}/factions/{faction_id}：PUT 編輯。
//
// 這條子路徑只有 PUT 一個方法：讀現值在列表那條路上，這一族刻意不另發單筆讀法
// （列表就是全量，單筆詳情會造出第二個答案來源）。兩個標識任一個非法都是 1001
// （同 R2 各條目標路徑：不讓端點變成標識格式探測器）。
func (s *Server) handleFactionProfile(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	factionID, err := idgen.Parse(r.PathValue("faction_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in updateFactionRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	updated, err := s.factions.UpdateFaction(r.Context(), principal, activityID, factionID,
		activity.FactionEdit{
			Name:                in.Name,
			Description:         in.Description,
			Icon:                in.Icon,
			Color:               in.Color,
			SortOrder:           in.SortOrder,
			Available:           in.Available,
			ExpectedName:        in.ExpectedName,
			ExpectedDescription: in.ExpectedDescription,
			ExpectedIcon:        in.ExpectedIcon,
			ExpectedColor:       in.ExpectedColor,
			ExpectedSortOrder:   in.ExpectedSortOrder,
			ExpectedAvailable:   in.ExpectedAvailable,
		}, requestIDFromRequest(r))
	if err != nil {
		s.writeFactionWriteFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, factionWriteResponse{
		Faction:   factionRow(updated),
		RequestID: requestIDFromRequest(r),
	})
}

// factionRow 把一筆陣營換成回應本體（欄位白名單見 internal/activity/factionstore.go 的讀法）。
func factionRow(f activity.Faction) factionItem {
	return factionItem{
		FactionID:   f.ID.String(),
		ActivityID:  f.ActivityID.String(),
		Name:        f.Name,
		Description: f.Description,
		Icon:        f.Icon,
		Color:       f.Color,
		SortOrder:   f.SortOrder,
		Available:   f.Available,
		CreatedAt:   timeutil.FormatUTC(f.CreatedAt),
		UpdatedAt:   timeutil.FormatUTC(f.UpdatedAt),
	}
}

// writeFactionWriteFailure 把建立與編輯兩條寫入通路的錯誤對映為對外回應。
//
// 每一格拒絕各有各的碼與處置，因為操作者要做的事完全不同：
// 1004 改寫法（點名是哪一欄）、2034 換個名字、2013 重讀現值再決定、
// 2033 等活动重開、2029 這件事已經結束。2013 沿用帳戶與活動資料編輯那一枚
// （同一句話、同一處置），不另發新碼；2033／2034 是本步順發的兩枚。
// 被拒的寫入不回顯任何一方現值。
func (s *Server) writeFactionWriteFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, activity.ErrInvalidName):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "name"})
		return
	case errors.Is(err, activity.ErrInvalidDescription):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "description"})
		return
	case errors.Is(err, activity.ErrInvalidIcon):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "icon"})
		return
	case errors.Is(err, activity.ErrInvalidColor):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "color"})
		return
	case errors.Is(err, activity.ErrInvalidSortOrder):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "sort_order"})
		return
	case errors.Is(err, activity.ErrFactionProfileConflict):
		writeError(w, r, CodeProfileConflict, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrFactionNameTaken):
		writeError(w, r, CodeFactionNameTaken, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrActivityClosedWrites):
		writeError(w, r, CodeActivityClosedWrites, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrArchived):
		writeError(w, r, CodeActivityArchived, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrFactionNotFound):
		// 「查無此陣營」與「它不屬於這個活動」是同一句話（不可分辨；見 factions.go 的用例）。
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("寫入陣營失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}
