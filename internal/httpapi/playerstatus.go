// playerstatus.go 是「玩家業務狀態與顯示名稱」在傳輸層的落點：
// /admin/activities/{activity_id}/player-statuses 一條路徑做兩件事（GET／HEAD 狀態目錄、
// POST 建立自訂狀態），/admin/activities/{activity_id}/player-statuses/{status_id} 編輯自訂狀態，
// /admin/activities/{activity_id}/player-status-labels/{status_key} 編輯內建狀態的顯示名稱，
// 以及 /admin/activities/{activity_id}/members/{member_id}/business-status 變更成員目前狀態。
//
// 本檔案只做協議層該做的四件事：
//  1. 來源（CSRF）判定與憑據解析——逐字復用 consolePrincipal 那條共用鏈；
//  2. 首次改密門閂——同一條鏈上的 requirePasswordChangeDone；
//  3. 請求形態——建立自訂狀態只認 name；編輯自訂狀態只認 name／available 加上兩個依據值；
//     顯示名稱只認 display_name 加上 expected_display_name；成員狀態只認兩欄新值加上
//     兩欄依據值。未知欄位由 decodeJSON 的 DisallowUnknownFields 當場拒殺（1004），
//     因此「順手把活動標識、成員標識、內部值或角色寫進不該有的地方」在本體裡沒有格子。
//  4. 結論對映——可判別錯誤一一對映到機器碼，其餘一律 500 且細節只進日誌。
//
// 本步新發布兩枚碼：2041（自訂狀態已停用，不再接收新的選用）與 2042（同活動自訂狀態重名）；
// 其餘復用 1001／1004／2011／2013／2029／2033。被拒的寫入不回顯任何一方現值。
//
// 這一族沒有任何「自動翻轉」：GET／HEAD 只讀，PUT 只在被明確呼叫時改一欄；
// offline 是管理員維護的業務狀態，不會因為請求抵達、頁面開啟或時間流逝而改變。
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

// PlayerStatusUseCase 是玩家業務狀態用例在傳輸層的入口形態
// （由 internal/app 注入同一個 *activity.Service 的狀態通路）。
//
// 獨立一個依賴欄位（口徑同 Members／MemberDirectory／Tags 的分離理由）：
// 本執行檔沒注入它時一個狀態端點都不掛，協定層行為與尚未有這件事的版次逐字相同。
type PlayerStatusUseCase interface {
	// PlayerStatusCatalog 讀一個活動的內建狀態顯示名稱與自訂狀態定義。
	PlayerStatusCatalog(ctx context.Context, principal identity.Principal,
		activityID idgen.ID) (activity.PlayerStatusCatalog, error)
	// CreateCustomStatus 建立一個自訂狀態定義。
	CreateCustomStatus(ctx context.Context, principal identity.Principal,
		activityID idgen.ID, name, requestID string) (activity.CustomStatus, error)
	// UpdateCustomStatus 編輯自訂狀態的名稱與可用性。
	UpdateCustomStatus(ctx context.Context, principal identity.Principal,
		activityID, statusID idgen.ID, edit activity.CustomStatusEdit,
		requestID string) (activity.CustomStatus, error)
	// UpdateStatusLabel 編輯內建狀態在該活動的顯示名稱覆蓋（空字串＝恢復預設）。
	UpdateStatusLabel(ctx context.Context, principal identity.Principal,
		activityID idgen.ID, key activity.BusinessStatus, displayName, expectedDisplayName,
		requestID string) (activity.BuiltinStatusView, error)
	// UpdateMemberBusinessStatus 變更一個成員目前的業務狀態。
	UpdateMemberBusinessStatus(ctx context.Context, principal identity.Principal,
		activityID, memberID idgen.ID, status activity.BusinessStatus, customStatusID idgen.ID,
		expectedStatus activity.BusinessStatus, expectedCustomStatusID idgen.ID,
		requestID string) (activity.Member, error)
}

// builtinStatusItem 是一個內建狀態的展示現值。
//
// display_name 為空字串代表沒有活動層級覆蓋，介面應使用四語言預設文案；
// uses_default_display_name 把同一件事寫成一個明確的布林，客戶端不必猜空字串的兩種可能。
// 內建狀態永遠可用，因此沒有 available 這一格。
type builtinStatusItem struct {
	StatusKey              string `json:"status_key"`
	DisplayName            string `json:"display_name"`
	UsesDefaultDisplayName bool   `json:"uses_default_display_name"`
}

// customStatusItem 是一個自訂狀態定義的對外投影。
// 它不帶「誰正在使用」的名單或計數：今日沒有那條讀法，也不拿 0 冒充。
type customStatusItem struct {
	CustomStatusID string `json:"custom_status_id"`
	Name           string `json:"name"`
	Available      bool   `json:"available"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

// playerStatusCatalogResponse 是狀態目錄的回應本體。
type playerStatusCatalogResponse struct {
	BuiltinStatuses []builtinStatusItem `json:"builtin_statuses"`
	CustomStatuses  []customStatusItem  `json:"custom_statuses"`
	RequestID       string              `json:"request_id"`
}

// createCustomStatusRequest 是建立自訂狀態的本體：只有名稱。
// 可用性、標識、活動歸屬與時刻都不在請求裡。
type createCustomStatusRequest struct {
	Name string `json:"name"`
}

// updateCustomStatusRequest 是編輯自訂狀態的本體：兩欄新值加兩欄依據值。
type updateCustomStatusRequest struct {
	Name              string `json:"name"`
	Available         bool   `json:"available"`
	ExpectedName      string `json:"expected_name"`
	ExpectedAvailable bool   `json:"expected_available"`
}

// updateStatusLabelRequest 是編輯內建狀態顯示名稱的本體。
// display_name 為空字串是「恢復四語言預設」，不是刪除狀態。
type updateStatusLabelRequest struct {
	DisplayName         string `json:"display_name"`
	ExpectedDisplayName string `json:"expected_display_name"`
}

// updateMemberBusinessStatusRequest 是變更成員目前狀態的本體。
//
// 兩欄新值加上兩欄依據值；custom_status_id 與 expected_custom_status_id 在非 custom 狀態時
// 必須是空字串（或省略），在 custom 狀態時必須是正規標識。請求裡沒有「哪個玩家」「哪場活動」
// 或「誰在做」的格子：那些由路徑與憑據決定。
type updateMemberBusinessStatusRequest struct {
	BusinessStatus         string `json:"business_status"`
	CustomStatusID         string `json:"custom_status_id"`
	ExpectedBusinessStatus string `json:"expected_business_status"`
	ExpectedCustomStatusID string `json:"expected_custom_status_id"`
}

// customStatusWriteResponse 是建立與編輯自訂狀態共用的回應本體。
type customStatusWriteResponse struct {
	CustomStatus customStatusItem `json:"custom_status"`
	RequestID    string           `json:"request_id"`
}

// builtinStatusWriteResponse 是編輯顯示名稱的回應本體。
type builtinStatusWriteResponse struct {
	BuiltinStatus builtinStatusItem `json:"builtin_status"`
	RequestID     string            `json:"request_id"`
}

// playerStatusEndpoints 回傳狀態端點的登記清單；未注入用例時為空。
func (s *Server) playerStatusEndpoints() []apiRoute {
	if s.playerStatus == nil {
		return nil
	}
	return []apiRoute{
		{"/admin/activities/{activity_id}/player-statuses",
			s.allowMethods(s.handlePlayerStatuses, http.MethodGet, http.MethodHead, http.MethodPost)},
		{"/admin/activities/{activity_id}/player-statuses/{status_id}",
			s.allowMethods(s.handleCustomStatusUpdate, http.MethodPut)},
		{"/admin/activities/{activity_id}/player-status-labels/{status_key}",
			s.allowMethods(s.handleStatusLabelUpdate, http.MethodPut)},
		{"/admin/activities/{activity_id}/members/{member_id}/business-status",
			s.allowMethods(s.handleMemberBusinessStatus, http.MethodPut)},
	}
}

// handlePlayerStatuses 依方法分流：GET／HEAD 狀態目錄、POST 建立自訂狀態。
func (s *Server) handlePlayerStatuses(w http.ResponseWriter, r *http.Request) {
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
		var in createCustomStatusRequest
		if !decodeJSON(w, r, &in) {
			return
		}
		created, err := s.playerStatus.CreateCustomStatus(r.Context(), principal, activityID,
			in.Name, requestIDFromRequest(r))
		if err != nil {
			s.writePlayerStatusFailure(w, r, err, "name")
			return
		}
		writeJSON(w, http.StatusCreated, customStatusWriteResponse{
			CustomStatus: customStatusRow(created), RequestID: requestIDFromRequest(r),
		})
		return
	}
	catalog, err := s.playerStatus.PlayerStatusCatalog(r.Context(), principal, activityID)
	if err != nil {
		s.writePlayerStatusFailure(w, r, err, "name")
		return
	}
	builtins := make([]builtinStatusItem, 0, len(catalog.Builtins))
	for _, item := range catalog.Builtins {
		builtins = append(builtins, builtinStatusRow(item))
	}
	custom := make([]customStatusItem, 0, len(catalog.Custom))
	for _, item := range catalog.Custom {
		custom = append(custom, customStatusRow(item))
	}
	writeJSON(w, http.StatusOK, playerStatusCatalogResponse{
		BuiltinStatuses: builtins, CustomStatuses: custom, RequestID: requestIDFromRequest(r),
	})
}

// handleCustomStatusUpdate 處理 PUT /admin/activities/{activity_id}/player-statuses/{status_id}。
func (s *Server) handleCustomStatusUpdate(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	statusID, err := idgen.Parse(r.PathValue("status_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in updateCustomStatusRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	updated, err := s.playerStatus.UpdateCustomStatus(r.Context(), principal, activityID, statusID,
		activity.CustomStatusEdit{
			New: activity.CustomStatusFields{Name: in.Name, Available: in.Available},
			Expected: activity.CustomStatusFields{
				Name: in.ExpectedName, Available: in.ExpectedAvailable,
			},
		}, requestIDFromRequest(r))
	if err != nil {
		s.writePlayerStatusFailure(w, r, err, "name")
		return
	}
	writeJSON(w, http.StatusOK, customStatusWriteResponse{
		CustomStatus: customStatusRow(updated), RequestID: requestIDFromRequest(r),
	})
}

// handleStatusLabelUpdate 處理 PUT /admin/activities/{activity_id}/player-status-labels/{status_key}。
func (s *Server) handleStatusLabelUpdate(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	key := activity.BusinessStatus(r.PathValue("status_key"))
	var in updateStatusLabelRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	updated, err := s.playerStatus.UpdateStatusLabel(r.Context(), principal, activityID, key,
		in.DisplayName, in.ExpectedDisplayName, requestIDFromRequest(r))
	if err != nil {
		s.writePlayerStatusFailure(w, r, err, "display_name")
		return
	}
	writeJSON(w, http.StatusOK, builtinStatusWriteResponse{
		BuiltinStatus: builtinStatusRow(updated), RequestID: requestIDFromRequest(r),
	})
}

// handleMemberBusinessStatus 處理
// PUT /admin/activities/{activity_id}/members/{member_id}/business-status。
func (s *Server) handleMemberBusinessStatus(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	memberID, err := idgen.Parse(r.PathValue("member_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in updateMemberBusinessStatusRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	customStatusID, ok := parseOptionalStatusID(w, r, in.CustomStatusID, "custom_status_id")
	if !ok {
		return
	}
	expectedCustomStatusID, ok := parseOptionalStatusID(w, r, in.ExpectedCustomStatusID,
		"expected_custom_status_id")
	if !ok {
		return
	}
	updated, err := s.playerStatus.UpdateMemberBusinessStatus(r.Context(), principal,
		activityID, memberID, activity.BusinessStatus(in.BusinessStatus), customStatusID,
		activity.BusinessStatus(in.ExpectedBusinessStatus), expectedCustomStatusID,
		requestIDFromRequest(r))
	if err != nil {
		s.writePlayerStatusFailure(w, r, err, "business_status")
		return
	}
	writeJSON(w, http.StatusOK, memberWriteResponse{
		Member: memberRow(updated), RequestID: requestIDFromRequest(r),
	})
}

// parseOptionalStatusID 解析可空的自訂狀態標識：空字串是合法的「沒有」，
// 非空但解析不出正規標識是請求寫法錯誤（1004 點名欄位），不是 1001。
func parseOptionalStatusID(w http.ResponseWriter, r *http.Request,
	raw, field string) (idgen.ID, bool) {
	if raw == "" {
		return idgen.ID{}, true
	}
	id, err := idgen.Parse(raw)
	if err != nil {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": field})
		return idgen.ID{}, false
	}
	return id, true
}

// builtinStatusRow 把內建狀態的展示現值換成回應本體。
func builtinStatusRow(item activity.BuiltinStatusView) builtinStatusItem {
	return builtinStatusItem{
		StatusKey:              item.Key.String(),
		DisplayName:            item.DisplayName,
		UsesDefaultDisplayName: item.DisplayName == "",
	}
}

// customStatusRow 把自訂狀態定義換成回應本體。
func customStatusRow(status activity.CustomStatus) customStatusItem {
	return customStatusItem{
		CustomStatusID: status.ID.String(),
		Name:           status.Name,
		Available:      status.Available,
		CreatedAt:      timeutil.FormatUTC(status.CreatedAt),
		UpdatedAt:      timeutil.FormatUTC(status.UpdatedAt),
	}
}

// statusIDOrEmpty 把零值標識換成空字串（口徑同 factionIDOrEmpty）。
func statusIDOrEmpty(id idgen.ID) string {
	if id.IsNil() {
		return ""
	}
	return id.String()
}

// writePlayerStatusFailure 把狀態一族共用的錯誤對映為對外回應。
//
// nameField 指出「名稱類錯誤」該點名哪一欄（自訂狀態是 name，顯示名稱是 display_name）。
// 其餘每一格拒絕各有各的處置：1004 改寫法、2013 重讀現值、2041 換一個仍可用的狀態、
// 2042 換個名字、2033 等活動重開、2029 這件事已經結束、1001 換個目標。
// 被拒的寫入不回顯任何一方現值。
func (s *Server) writePlayerStatusFailure(w http.ResponseWriter, r *http.Request,
	err error, nameField string) {
	switch {
	case errors.Is(err, activity.ErrInvalidBusinessStatus):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "business_status"})
		return
	case errors.Is(err, activity.ErrInvalidStatusName):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": nameField})
		return
	case errors.Is(err, activity.ErrCustomStatusUnavailable):
		writeError(w, r, CodePlayerStatusUnavailable, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrCustomStatusNameTaken):
		writeError(w, r, CodePlayerStatusNameTaken, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrCustomStatusConflict),
		errors.Is(err, activity.ErrStatusLabelConflict),
		errors.Is(err, activity.ErrMemberProfileConflict),
		errors.Is(err, activity.ErrProfileConflict):
		writeError(w, r, CodeProfileConflict, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrActivityClosedWrites):
		writeError(w, r, CodeActivityClosedWrites, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrArchived):
		writeError(w, r, CodeActivityArchived, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrCustomStatusNotFound),
		errors.Is(err, activity.ErrMemberNotFound),
		errors.Is(err, activity.ErrActivityNotFound):
		// 「查無」「屬於另一場活動」「這個活動不歸你管」與「狀態定義讀不到」
		// 收斂成同一句話（不可分辨）。
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("處理玩家狀態請求失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}
