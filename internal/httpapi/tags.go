// tags.go 是「活動標籤定義與公開範圍」在傳輸層的落點：
// /admin/activities/{activity_id}/tags 一條路徑做兩件事（GET／HEAD 列表、POST 建立），
// /admin/activities/{activity_id}/tags/{tag_id} 一條路徑做一件事（PUT 編輯），
// /player/activities/{activity_id}/tags 一條路徑做一件事（GET／HEAD 讀公開定義清單），
// /player/activities/{activity_id}/tags/{tag_id} 一條路徑做一件事（GET／HEAD 直查單枚公開定義）。
//
// 這一組端點存在的理由是「準入邊界與輸出白名單都不同」，不是「同一件事換個字首」：
//   - 管理那一族問的是活動管理面那道閘（NeedServerAdmin 加上這個活動的一行指派），
//     與活動資料編輯、陣營管理、成員名冊同一道閘，因此仍掛在 /admin 之下，
//     讀到的是含內部定義的完整七欄加兩個派生值；
//   - 玩家那一族只問「這次請求的憑據此刻換出的是哪一個帳戶、他在這場活動有沒有成員行」，
//     讀到的是只有定義本身與展示四值的投影——沒有內部可用性、沒有公開旗標本身、
//     沒有時刻、沒有計數。普通玩家敲管理那一族拿到的是 2011，敲玩家這一族裡一枚內部定義
//     拿到的是與幽靈逐字同文的 1001。
//
// 本檔案刻意只做協議層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 consolePrincipal 那條共用鏈；
//  2. 首次改密門閂——同一條鏈上的 requirePasswordChangeDone；
//  3. 請求本體的形態——建立只認 name／description／icon／color 四個欄位與可選的 sort_order，
//     編輯只認那七欄（含可用與公開兩個開關）加上它們各自依據的現值；
//     未知欄位由 decodeJSON 的 DisallowUnknownFields 當場拒殺（1004），於是
//     「順手把 tag_id、activity_id、created_at、一格自報的『我是管理人』、甚至一格
//     自報的 accepts_new_assignments 寫進不該有的地方」在本體裡沒有可以填的格子——
//     「動哪一枚標籤」由路徑決定，「哪個活動下的標籤」由路徑決定，「誰在做」由那枚憑據決定；
//     玩家那一族只有 GET／HEAD，本體無處可填（PUT 在這一族根本不掛，Allow 也不虛報）。
//  4. 結論對映——把用例回傳的可判別錯誤一一對映到機器碼，其餘一律 500 且細節只進日誌。
//     這組端點用到的碼：1001（標籤或活動不在可見範圍，含標識寫壞、不屬於該活動、
//     對玩家未公開、以及「不是他管的活動」）、1004（點名欄位）、2011（不屬於管理員這個身份面）、
//     2013（資料現值已過期，沿用陣營與成員資料編輯那枚）、2029（歸檔終態）、2033（活動停止），
//     以及本步新發布的 2040（同活動內標籤重名）。
//
// 回應本體不含任何憑據材料、會話材料或帳戶內部欄位。公開旗標是「這份定義讀不讀得到」，
// 它不是角色也不是權限；把一欄 public 翻成真，不會讓任何一個本来不在目錄裡的人变得可被查出
// （那一件事由 internal/activity 的目錄判定負責）。停用與恢復、公開與收回都走 PUT 那一條
// 七欄白名單通路（用戶批准：不另設狀態子資源），這一族因此不存在 DELETE——
// 本步批准的是「只有可用／停用，沒有刪除通路，也不級聯清空歷史」（見遷移 0017 檔頭）。
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

// TagUseCase 是「活動標籤定義與公開範圍」用例在傳輸層的入口形態（由 internal/app 注入
// 同一個 *activity.Service 的標籤通路）。
//
// 獨立一個依賴欄位（口径同 Activities、Factions、Members 與 MemberDirectory 的分離理由）：
// 本執行檔沒注入它時一個標籤端點都不掛，協定層行為與尚未有標籤模組的版次逐字相同。
// principal 一律是「本次請求的憑據此刻換出的受信主體」，授權、活動作用域判定、
// 業務寫入門禁、重名核實、公開篩選與那一跳落庫都在用例裡判。
type TagUseCase interface {
	// CreateTag 在一個活動裡建立標籤定義：新建即可用、且不公開；未指定排序值時由服務層
	// 在交易內排到最後一格；停止與歸檔的活動一律拒寫（各自一句話，見 internal/activity/status.go）。
	CreateTag(ctx context.Context, principal identity.Principal,
		activityID idgen.ID, draft activity.TagDraft, requestID string) (activity.Tag, error)
	// Tags 以當前受信主體讀一個活動的標籤定義列表（含內部定義；仍列、可讀）。
	Tags(ctx context.Context, principal identity.Principal,
		activityID idgen.ID) ([]activity.Tag, error)
	// UpdateTag 以白名單編輯七欄資料（含可用與公開兩個開關）；七個 expected_* 是提交所依據的
	// 現值，現值已變時整個編輯不落並回可判別的衝突。標識與歸屬不在這條通路上。
	UpdateTag(ctx context.Context, principal identity.Principal,
		activityID, tagID idgen.ID, edit activity.TagEdit, requestID string) (activity.Tag, error)
	// PublicTagCatalog 以本次會話的帳戶讀一場活動裡被設成公開的標籤定義清單。
	PublicTagCatalog(ctx context.Context, principal identity.Principal,
		activityID idgen.ID) ([]activity.PublicTagItem, error)
	// PublicTagDetail 以同一條可見範圍直查單枚公開標籤定義（內部定義與幽靈同形）。
	PublicTagDetail(ctx context.Context, principal identity.Principal,
		activityID, tagID idgen.ID) (activity.PublicTagItem, error)
}

// createTagRequest 是建立標籤請求的本體。白名單是四個必填欄位加一格可選的排序值：
// available 與 public 都沒有格子——出生形態由「新建即可用、新建一律內部」這兩條領域規則決定
// （見 internal/activity/tags.go 頭注）；id／activity_id／created_at 也沒有格子——
// 身份與歸屬由路徑和倉儲決定。sort_order 缺席時由服務層現算排尾值；帶了就必須是界內整數。
type createTagRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Color       string `json:"color"`
	SortOrder   *int64 `json:"sort_order"`
}

// updateTagRequest 是編輯標籤請求的本體：七欄白名單新值加七欄依據值。
// id／activity_id／created_at 連一個格子都沒有（未知欄位 1004），
// 「儲存標籤資料順手把它挪進另一個活動」或「順手改它的身份」因此不是被拒，而是無處可填。
// 依據值逐欄對應：正確性錨在「庫裡此刻的七欄等於你依據的那七欄」這條可觀測事實上。
type updateTagRequest struct {
	Name                string `json:"name"`
	Description         string `json:"description"`
	Icon                string `json:"icon"`
	Color               string `json:"color"`
	SortOrder           int64  `json:"sort_order"`
	Available           bool   `json:"available"`
	Public              bool   `json:"public"`
	ExpectedName        string `json:"expected_name"`
	ExpectedDescription string `json:"expected_description"`
	ExpectedIcon        string `json:"expected_icon"`
	ExpectedColor       string `json:"expected_color"`
	ExpectedSortOrder   int64  `json:"expected_sort_order"`
	ExpectedAvailable   bool   `json:"expected_available"`
	ExpectedPublic      bool   `json:"expected_public"`
}

// tagItem 是管理側列表行、建立回顯與編輯結果共用的形狀（同一筆資料在不同回應裡的形狀必須同源）。
//
// accepts_new_assignments 是服務端派生的只讀欄（只增不刪的兼容演進）：available 且所屬活動
// 此刻接受業務寫入時才為真。它不是第八格可寫資料——PUT 的本體白名單裡沒有這一格，
// 帶著它來的請求在協定層就被 1004 殺掉，於是「介面以為改了这一格就改了可用性」無處可犯；
// 介面顯示的「此刻貼不貼得出去」與日後貼標通路的判定同源，不用自己拼兩個欄位。
type tagItem struct {
	TagID       string `json:"tag_id"`
	ActivityID  string `json:"activity_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Color       string `json:"color"`
	SortOrder   int64  `json:"sort_order"`
	Available   bool   `json:"available"`
	Public      bool   `json:"public"`
	// AcceptsNewAssignments 是派生現值，寫入通路不接受它（見上方說明）。
	AcceptsNewAssignments bool   `json:"accepts_new_assignments"`
	CreatedAt             string `json:"created_at"`
	UpdatedAt             string `json:"updated_at"`
}

// tagListResponse 是管理側 GET／HEAD 列表的回應本體。
//
// 不帶活動那一格：列表本来就是「這個活動的標籤們」，活動現值屬父路徑的詳情讀法。
// 標籤表按本步形態是小表（一場活動的幾枚標記），與陣營與名冊同樣不分頁。
// 這一族不帶任何「被貼標人數」：今日沒有貼標关系，拿 0 冒充計數就是把沒做的事寫成做過。
type tagListResponse struct {
	Tags      []tagItem `json:"tags"`
	RequestID string    `json:"request_id"`
}

// tagWriteResponse 是 POST 建立與 PUT 編輯共用的寫入回應本體。
type tagWriteResponse struct {
	Tag       tagItem `json:"tag"`
	RequestID string  `json:"request_id"`
}

// publicTagItem 是玩家側的一行標籤定義投影（白名單見 internal/activity/tagcatalog.go）。
//
// 這四個展示值與 tagItem 裡同名的那幾格同源於同一張表，差別只在少了內部那一側：
// available、public、accepts_new_assignments、activity_id、created_at、updated_at
// 都不在這兒，也不是空字串佔位——這一族讀法從來不把它們湊齊，因此無從遞出去。
type publicTagItem struct {
	TagID       string `json:"tag_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Color       string `json:"color"`
	SortOrder   int64  `json:"sort_order"`
}

// publicTagListResponse 是玩家側公開標籤目錄的回應本體。
type publicTagListResponse struct {
	Tags      []publicTagItem `json:"tags"`
	RequestID string          `json:"request_id"`
}

// publicTagResponse 是玩家側單笔直查的回應本體。
//
// 不複用管理側那個形狀：那一份帶的是內部欄位，把同一個結構喂給兩道不同的閘，
// 遲早有一處忘了填某欄而让玩家讀到一個假的 false。
type publicTagResponse struct {
	Tag       publicTagItem `json:"tag"`
	RequestID string        `json:"request_id"`
}

// tagEndpoints 回傳標籤定義端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深連結回退用的 API 首段清單（/admin 與 /player）因此自動同步。
// 管理那一族沒有 DELETE——本步批准的是「只有可用／停用，沒有刪除通路」（見遷移 0017 檔頭）；
// 玩家那一族只有讀法（PUT 與 POST 都不掛），本步也沒有「玩家自己给自己貼標」這條通路。
func (s *Server) tagEndpoints() []apiRoute {
	if s.tags == nil {
		return nil
	}
	return []apiRoute{
		{"/admin/activities/{activity_id}/tags", s.allowMethods(s.handleTags,
			http.MethodGet, http.MethodHead, http.MethodPost)},
		{"/admin/activities/{activity_id}/tags/{tag_id}", s.allowMethods(s.handleTagProfile,
			http.MethodPut)},
		{"/player/activities/{activity_id}/tags", s.allowMethods(s.handlePublicTags,
			http.MethodGet, http.MethodHead)},
		{"/player/activities/{activity_id}/tags/{tag_id}", s.allowMethods(s.handlePublicTag,
			http.MethodGet, http.MethodHead)},
	}
}

// handleTags 依方法分流：GET／HEAD 標籤列表、POST 建立一枚標籤。
func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
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
		s.createTag(w, r, principal, activityID)
		return
	}
	s.listTags(w, r, principal, activityID)
}

// listTags 處理管理側 GET／HEAD 列表：可見範圍的拒絕與「從沒這個活動」同形（1001），
// 已歸檔與已停止的活動照樣列出行（仍列、可讀），內部定義照樣列（這一族的閘是管理面那道）。
func (s *Server) listTags(w http.ResponseWriter, r *http.Request,
	principal identity.Principal, activityID idgen.ID) {
	rows, err := s.tags.Tags(r.Context(), principal, activityID)
	if err != nil {
		if s.writeActivityCommonFailures(w, r, err) {
			return
		}
		s.logger.Error("讀取標籤列表失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		return
	}
	items := make([]tagItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, tagRow(row))
	}
	writeJSON(w, http.StatusOK, tagListResponse{
		Tags:      items,
		RequestID: requestIDFromRequest(r),
	})
}

// createTag 處理 POST 建立：本體白名單交用例，其餘結論都在對映裡。
func (s *Server) createTag(w http.ResponseWriter, r *http.Request,
	principal identity.Principal, activityID idgen.ID) {
	var in createTagRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	created, err := s.tags.CreateTag(r.Context(), principal, activityID,
		activity.TagDraft{
			Name:        in.Name,
			Description: in.Description,
			Icon:        in.Icon,
			Color:       in.Color,
			SortOrder:   in.SortOrder,
		}, requestIDFromRequest(r))
	if err != nil {
		s.writeTagWriteFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, tagWriteResponse{
		Tag:       tagRow(created),
		RequestID: requestIDFromRequest(r),
	})
}

// handleTagProfile 處理 /admin/activities/{activity_id}/tags/{tag_id}：PUT 編輯。
//
// 這條子路徑只有 PUT 一個方法：讀現值在列表那條路上，這一族刻意不另發單筆讀法
// （列表就是全量，單筆詳情會造出第二個答案來源）。兩個標識任一個非法都是 1001
// （同 R2 各條目標路徑：不讓端點變成標識格式探測器）。
func (s *Server) handleTagProfile(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	tagID, err := idgen.Parse(r.PathValue("tag_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in updateTagRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	updated, err := s.tags.UpdateTag(r.Context(), principal, activityID, tagID,
		activity.TagEdit{
			New: activity.TagFields{
				Name:        in.Name,
				Description: in.Description,
				Icon:        in.Icon,
				Color:       in.Color,
				SortOrder:   in.SortOrder,
				Available:   in.Available,
				Public:      in.Public,
			},
			Expected: activity.TagFields{
				Name:        in.ExpectedName,
				Description: in.ExpectedDescription,
				Icon:        in.ExpectedIcon,
				Color:       in.ExpectedColor,
				SortOrder:   in.ExpectedSortOrder,
				Available:   in.ExpectedAvailable,
				Public:      in.ExpectedPublic,
			},
		}, requestIDFromRequest(r))
	if err != nil {
		s.writeTagWriteFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, tagWriteResponse{
		Tag:       tagRow(updated),
		RequestID: requestIDFromRequest(r),
	})
}

// handlePublicTags 處理玩家側 GET／HEAD /player/activities/{activity_id}/tags：
// 只列被設成公開的定義；非成員與 Root 和「從沒這場活動」同形（1001），匿名 2002。
func (s *Server) handlePublicTags(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	rows, err := s.tags.PublicTagCatalog(r.Context(), principal, activityID)
	if err != nil {
		s.writeTagCatalogFailure(w, r, err)
		return
	}
	items := make([]publicTagItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, publicTagRow(row))
	}
	writeJSON(w, http.StatusOK, publicTagListResponse{
		Tags:      items,
		RequestID: requestIDFromRequest(r),
	})
}

// handlePublicTag 處理玩家側 GET／HEAD .../tags/{tag_id}：單枚直查。
//
// 標識寫壞是 1001（這一族不當標識格式探測器）。直查一枚未公開的定義與直查一枚從未存在的
// 標識逐字同文——這條路徑不承認「有這枚標籤，只是不給你讀」。
func (s *Server) handlePublicTag(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	tagID, err := idgen.Parse(r.PathValue("tag_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	row, err := s.tags.PublicTagDetail(r.Context(), principal, activityID, tagID)
	if err != nil {
		s.writeTagCatalogFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, publicTagResponse{
		Tag:       publicTagRow(row),
		RequestID: requestIDFromRequest(r),
	})
}

// tagRow 把一筆標籤定義換成管理側回應本體（欄位白名單見 internal/activity/tagstore.go 的讀法；
// accepts_new_assignments 是用例蓋上的派生值，這一層不再自己算一遍，免得兩處各講一套）。
func tagRow(t activity.Tag) tagItem {
	return tagItem{
		TagID:                 t.ID.String(),
		ActivityID:            t.ActivityID.String(),
		Name:                  t.Name,
		Description:           t.Description,
		Icon:                  t.Icon,
		Color:                 t.Color,
		SortOrder:             t.SortOrder,
		Available:             t.Available,
		Public:                t.Public,
		AcceptsNewAssignments: t.AcceptsNewAssignments,
		CreatedAt:             timeutil.FormatUTC(t.CreatedAt),
		UpdatedAt:             timeutil.FormatUTC(t.UpdatedAt),
	}
}

// publicTagRow 把一筆標籤定義換成玩家側回應本體（白名單見 internal/activity/tagcatalog.go）。
func publicTagRow(t activity.PublicTagItem) publicTagItem {
	return publicTagItem{
		TagID:       t.TagID.String(),
		Name:        t.Name,
		Description: t.Description,
		Icon:        t.Icon,
		Color:       t.Color,
		SortOrder:   t.SortOrder,
	}
}

// writeTagWriteFailure 把建立與編輯兩條管理側寫入通路的錯誤對映為對外回應。
//
// 每一格拒絕各有各的碼與處置，因為操作者要做的事完全不同：
// 1004 改寫法（點名是哪一欄）、2040 換個名字、2013 重讀現值再決定、
// 2033 等活動重開、2029 這件事已經結束。2013 沿用帳戶、活動與陣營資料編輯那一枚
// （同一句話、同一處置），不另發新碼；2040 是本步順發的唯一一枚。
// 被拒的寫入不回顯任何一方現值。
func (s *Server) writeTagWriteFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, activity.ErrInvalidName):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "name"})
		return
	case errors.Is(err, activity.ErrInvalidDescription):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "description"})
		return
	case errors.Is(err, activity.ErrInvalidTagIcon):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "icon"})
		return
	case errors.Is(err, activity.ErrInvalidTagColor):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "color"})
		return
	case errors.Is(err, activity.ErrInvalidTagSortOrder):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "sort_order"})
		return
	case errors.Is(err, activity.ErrTagProfileConflict):
		writeError(w, r, CodeProfileConflict, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrTagNameTaken):
		writeError(w, r, CodeTagNameTaken, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrActivityClosedWrites):
		writeError(w, r, CodeActivityClosedWrites, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrArchived):
		writeError(w, r, CodeActivityArchived, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrTagNotFound):
		// 「查無此標籤」與「它不屬於這個活動」是同一句話（不可分辨；見 tags.go 的用例）。
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("寫入標籤失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}

// writeTagCatalogFailure 把玩家那一族的兩條讀法對映為對外回應。
//
// 三個「查無」收斂成同一句話（1001）：查無這個活動、他不是這場活動的成員、
// 那枚標籤不屬於這個活動或此刻沒被設成公開。被拒的人多知道哪一個都不該是信號，
// 而這裡也沒有任何一格能讓他宣稱「我是管理人所以給我看內部定義」——那是另一族端點、
// 另一道閘（敲過去拿 2011）。
func (s *Server) writeTagCatalogFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, activity.ErrTagNotFound),
		errors.Is(err, activity.ErrMemberNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("處理公開標籤目錄請求失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}
