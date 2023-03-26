// memberdirectory.go 是「玩家目錄可見性」在傳輸層的落點：
// /admin/activities/{activity_id}/member-directory 一條路徑做一件事（PUT 編輯那一欄配置），
// /admin/activities/{activity_id}/members/{member_id}/directory-visibility 一條路徑做一件事
// （PUT 編輯那一行的覆蓋），玩家那一族三條路徑各做一讀：
// /player/activities/{activity_id}/members（GET／HEAD 目錄）、
// /player/activities/{activity_id}/members/{member_id}（GET／HEAD 單筆直查）、
// /player/activities/{activity_id}/profile（GET／HEAD 本人資料投影）。
//
// 這一組端點存在的理由是「準入邊界不同」，不是「同一件事換個字首」：
//   - 配置與覆蓋那兩條走活動管理面那道閘（NeedServerAdmin 加上這個活動的一行指派），
//     與活動資料編輯、陣營管理、成員名冊、自選配置同一道閘，因此仍掛在 /admin 之下；
//   - 玩家那三條只問「這次請求的憑據此刻換出的是哪一個帳戶」，主體由會話決定，
//     路徑裡沒有一格能填「哪個玩家」，查詢串與本體裡也沒有——特別是沒有一格能宣稱
//     「用管理視角給我全部人」：IsManager 只由服務端現讀的指派決定，帶了這類欄位
//     就在 decodeJSON 的 DisallowUnknownFields 那一步撞 1004。
//
// 本檔案刻意只做協議層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 consolePrincipal 那條共用鏈；
//  2. 首次改密門閂——同一條鏈上的 requirePasswordChangeDone；
//  3. 請求形態——配置只認 mode 加上它所依據的現值 expected_mode，覆蓋只認 visibility
//     加上 expected_visibility；目錄一讀只認 page／page_size／q／faction 四個查詢引數，
//     「引數沒帶」用常數預設、「帶了但不合形」當場 1004 點名（口徑同活動目錄）；
//  4. 結論對映——把用例回傳的可判別錯誤對映到機器碼，其餘一律 500 且細節只進日誌。
//     這組端點用到的碼全是既有的：1001（活動、成員或那一行此刻不在可見範圍，含標識寫壞、
//     跨活動，以及「他確實存在但此刻你看不見他」）、1004（點名欄位或查詢引數）、
//     2011（不屬於管理員這個身份面）、2013（現值已過期）、2029（歸檔終態）、
//     2033（活動停止，業務寫入待重開）。本步不發新碼：
//     「目錄這一態不列任何人」的答案是一份空清單而不是一個錯誤，
//     「你看不見他那一行」與「從沒這個人」必須同形，兩句都不該有新的可列舉信號。
//
// 回應本體不含任何憑據材料、會話材料或帳戶內部欄位：一行目錄項只有他在這場活動內的標識、
// 活動內暱稱、陣營的展示三值與加入時刻。登入名、口令形態、帳戶狀態、內部標籤與
// 「他為什麼不可見」那種後台原因一律不出去（管理面要那些走 /admin 名冊，那道閘不同）。
// 派生值（活動的 member_directory_mode、名冊的 admin_identity 與 directory_visibility）
// 恆在回應、絕在請求，帶了就 1004（口徑同 faction_select_mode 與 accepts_new_members）。
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/kagurazakayashi/EvernightRealm/internal/activity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// MemberDirectoryUseCase 是「玩家目錄可見性」用例在傳輸層的入口形態
// （由 internal/app 注入同一個 *activity.Service 的目錄通路）。
//
// 獨立一個依賴欄位（口徑同 Activities、Factions、Members 與 FactionSelect 的分離理由）：
// 本執行檔沒注入它時一個目錄端點都不掛，協定層行為與尚未有這件事的版次逐字相同。
// principal 一律是「本次請求的憑據此刻換出的受信主體」，可見範圍、管理視角、
// 業務寫入門禁、覆蓋編輯與那一跳留痕都在用例裡判。
type MemberDirectoryUseCase interface {
	// MemberDirectory 以當前受信主體讀一頁玩家目錄（先授權篩選，再分頁與計數）。
	MemberDirectory(ctx context.Context, principal identity.Principal,
		activityID idgen.ID, query activity.DirectoryMemberQuery) (activity.DirectoryMemberPage, error)
	// DirectoryMemberDetail 以同一個判定讀回單筆目錄項。
	DirectoryMemberDetail(ctx context.Context, principal identity.Principal,
		activityID, memberID idgen.ID) (activity.DirectoryMember, error)
	// OwnMemberProfile 讀回本次會話帳戶在那場活動裡的資料投影（不经目錄可見性判定）。
	OwnMemberProfile(ctx context.Context, principal identity.Principal,
		activityID idgen.ID) (activity.OwnMemberProfileView, error)
	// UpdateMemberDirectoryMode 由活動管理人編輯那一欄配置；兩個 mode 值都屬封閉集合，
	// expected_mode 是提交所依據的現值，現值已變時整個編輯不落並回可判別的衝突。
	UpdateMemberDirectoryMode(ctx context.Context, principal identity.Principal,
		activityID idgen.ID, mode, expectedMode activity.DirectoryMode,
		requestID string) (activity.Activity, error)
	// UpdateMemberDirectoryVisibility 由活動管理人編輯單一行成員的目錄覆蓋（只可收緊）。
	UpdateMemberDirectoryVisibility(ctx context.Context, principal identity.Principal,
		activityID, memberID idgen.ID, visibility, expectedVisibility activity.DirectoryVisibility,
		requestID string) (activity.Member, error)
}

// updateMemberDirectoryModeRequest 是配置編輯請求的本體：新模式加上它所依據的現值。
// 沒有「哪個玩家」、沒有覆蓋、也沒有任何一格能宣稱管理視角——那一欄配置動的就是它自己一欄。
type updateMemberDirectoryModeRequest struct {
	Mode         string `json:"mode"`
	ExpectedMode string `json:"expected_mode"`
}

// updateDirectoryVisibilityRequest 是覆蓋編輯請求的本體：新覆蓋加上它所依據的現值。
// 取值集合只有 inherit|hidden：能做到的最寬結果就是完全服從活動規則，
// 「把這個玩家單獨開放給所有人」在本體裡沒有一個格子能表達。
type updateDirectoryVisibilityRequest struct {
	Visibility         string `json:"visibility"`
	ExpectedVisibility string `json:"expected_visibility"`
}

// directoryMemberItem 是一行目錄資料的對外投影（白名單見 internal/activity 的 directoryItemOf）。
//
// faction_id 恆在：空字串是「尚未分組」這個合法現值（口徑同成員名冊），不靠欄位缺席表達。
// faction_available 也恆在：它是那個陣營自己的停用旗標現值（不折進活動狀態），介面據它講出
// 「該玩家所屬陣營已停用」那一句；無歸屬與讀不到展示值時同為假，而那兩種形態由
// faction_id 與 faction_name 各自表達。
// 沒有 account_id、沒有 display_name、沒有 account_status，也沒有 admin_identity：
// 後四格是管理面的事實，放進玩家目錄等於讓普通玩家多得到「他是誰的哪一個帳戶」
// 與「谁是后台的人」兩枚可列舉信號。
type directoryMemberItem struct {
	MemberID         string `json:"member_id"`
	Nickname         string `json:"nickname"`
	FactionID        string `json:"faction_id"`
	FactionName      string `json:"faction_name"`
	FactionIcon      string `json:"faction_icon"`
	FactionColor     string `json:"faction_color"`
	FactionAvailable bool   `json:"faction_available"`
	JoinedAt         string `json:"joined_at"`
}

// directoryFacetItem 是篩選候選的一項（計數與列表同源，見 internal/activity 的 directoryFacets）。
type directoryFacetItem struct {
	FactionID string `json:"faction_id"`
	Name      string `json:"name"`
	Icon      string `json:"icon"`
	Color     string `json:"color"`
	Count     int64  `json:"count"`
}

// memberDirectoryResponse 是目錄一讀的回應本體。
//
// member_directory_mode 是服務端現讀的派生值：界面據它如實說出「這一態本来就不列任何人」，
// 而不是把一份空清單唸成「這場活動還沒有人加入」——那兩句在同一份回應裡分不開，
// 而把它們混為一談正是防枚举要防的形態。
type memberDirectoryResponse struct {
	Members             []directoryMemberItem `json:"members"`
	Facets              []directoryFacetItem  `json:"facets"`
	MemberDirectoryMode string                `json:"member_directory_mode"`
	SelfMemberID        string                `json:"self_member_id"`
	Page                int64                 `json:"page"`
	PageSize            int64                 `json:"page_size"`
	Total               int64                 `json:"total"`
	RequestID           string                `json:"request_id"`
}

// directoryMemberResponse 是單筆直查的回應本體。
type directoryMemberResponse struct {
	Member    directoryMemberItem `json:"member"`
	RequestID string              `json:"request_id"`
}

// ownMemberProfileResponse 是本人資料投影的回應本體。
//
// 它帶 directory_visibility（他自己那一行的覆蓋現值）與 member_directory_mode（這一讀生效的
// 活動規則）：兩格都是「本人看得見自己、也看得見這場活動把目錄開到多大」的事實，
// 而不構成分身——别人的可見性與任何帳戶欄位都不在這一份回應裡。
// faction_available 與目錄那一欄同形同語意，讓「我歸屬的陣營已停用」那一句在目錄收起時
// 仍然說得出來（本人通路本來就不經目錄判定）。
type ownMemberProfileResponse struct {
	ActivityID          string `json:"activity_id"`
	Name                string `json:"name"`
	Status              string `json:"status"`
	MemberDirectoryMode string `json:"member_directory_mode"`
	MemberID            string `json:"member_id"`
	Nickname            string `json:"nickname"`
	FactionID           string `json:"faction_id"`
	FactionName         string `json:"faction_name"`
	FactionIcon         string `json:"faction_icon"`
	FactionColor        string `json:"faction_color"`
	FactionAvailable    bool   `json:"faction_available"`
	DirectoryVisibility string `json:"directory_visibility"`
	JoinedAt            string `json:"joined_at"`
	RequestID           string `json:"request_id"`
}

// memberDirectoryEndpoints 回傳目錄端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深連結回退用的 API 首段清單（/admin 與 /player）因此自動同步：
// /player 那一族若只有本步這三條掛上，它也確實屬於 API（未注入時玩家深連結照舊回退應用外殼）。
func (s *Server) memberDirectoryEndpoints() []apiRoute {
	if s.memberDirectory == nil {
		return nil
	}
	return []apiRoute{
		{"/admin/activities/{activity_id}/member-directory",
			s.allowMethods(s.handleMemberDirectoryConfig, http.MethodPut)},
		{"/admin/activities/{activity_id}/members/{member_id}/directory-visibility",
			s.allowMethods(s.handleDirectoryVisibility, http.MethodPut)},
		{"/player/activities/{activity_id}/members",
			s.allowMethods(s.handleMemberDirectory, http.MethodGet, http.MethodHead)},
		{"/player/activities/{activity_id}/members/{member_id}",
			s.allowMethods(s.handleDirectoryMember, http.MethodGet, http.MethodHead)},
		{"/player/activities/{activity_id}/profile",
			s.allowMethods(s.handleOwnMemberProfile, http.MethodGet, http.MethodHead)},
	}
}

// handleMemberDirectoryConfig 處理 PUT /admin/activities/{activity_id}/member-directory。
func (s *Server) handleMemberDirectoryConfig(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in updateMemberDirectoryModeRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	updated, err := s.memberDirectory.UpdateMemberDirectoryMode(r.Context(), principal, activityID,
		activity.DirectoryMode(in.Mode), activity.DirectoryMode(in.ExpectedMode),
		requestIDFromRequest(r))
	if err != nil {
		s.writeMemberDirectoryFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, activityWriteResponse{
		Activity:  activityRow(updated),
		RequestID: requestIDFromRequest(r),
	})
}

// handleDirectoryVisibility 處理 PUT .../members/{member_id}/directory-visibility。
//
// 兩個標識任一個寫壞都是 1001：這一族路徑不當標識格式探測器（口徑同成員那族路徑）。
func (s *Server) handleDirectoryVisibility(w http.ResponseWriter, r *http.Request) {
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
	var in updateDirectoryVisibilityRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	updated, err := s.memberDirectory.UpdateMemberDirectoryVisibility(r.Context(), principal,
		activityID, memberID,
		activity.DirectoryVisibility(in.Visibility), activity.DirectoryVisibility(in.ExpectedVisibility),
		requestIDFromRequest(r))
	if err != nil {
		s.writeMemberDirectoryFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, memberWriteResponse{
		Member:    memberRow(updated),
		RequestID: requestIDFromRequest(r),
	})
}

// handleMemberDirectory 處理 GET／HEAD /player/activities/{activity_id}/members。
//
// 「引數沒帶」與「帶了但不合形」分開處置：前者用本倉庫的預設常數（值只有一份），
// 後者當場回 1004 點名是哪個查詢引數。q 不做任何解析：它是一段原字串比對，
// 長短由用例判，空字串與「沒帶」在用例裡收斂成同一句話。
// faction 要解析得出正規標識才收：寫壞了是 1004（引數寫法），而不是 1001（那會把
// 一枚格式探測器掛在玩家路徑上）。解析得動但屬於別的活動或不存在的陣標識則按
// 「這一篩選下沒有可见的人」回答——空清單對兩種說法是同一份回應，不多出存在性信號。
func (s *Server) handleMemberDirectory(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	query := r.URL.Query()
	directory := activity.DirectoryMemberQuery{
		Page: 1, PageSize: activity.DirectoryDefaultPageSize,
	}
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
	directory.Keyword = query.Get("q")
	if raw := query.Get("faction"); raw != "" {
		factionID, err := idgen.Parse(raw)
		if err != nil {
			writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
				map[string]any{"invalid_field": "faction"})
			return
		}
		directory.FactionID = factionID
	}

	page, err := s.memberDirectory.MemberDirectory(r.Context(), principal, activityID, directory)
	if err != nil {
		s.writeMemberDirectoryFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, memberDirectoryPayload(page, requestIDFromRequest(r)))
}

// handleDirectoryMember 處理 GET／HEAD /player/activities/{activity_id}/members/{member_id}。
func (s *Server) handleDirectoryMember(w http.ResponseWriter, r *http.Request) {
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
	item, err := s.memberDirectory.DirectoryMemberDetail(r.Context(), principal, activityID, memberID)
	if err != nil {
		s.writeMemberDirectoryFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, directoryMemberResponse{
		Member:    directoryMemberRow(item),
		RequestID: requestIDFromRequest(r),
	})
}

// handleOwnMemberProfile 處理 GET／HEAD /player/activities/{activity_id}/profile。
func (s *Server) handleOwnMemberProfile(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	view, err := s.memberDirectory.OwnMemberProfile(r.Context(), principal, activityID)
	if err != nil {
		s.writeMemberDirectoryFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, ownMemberProfileResponse{
		ActivityID:          view.Activity.ID.String(),
		Name:                view.Activity.Name,
		Status:              view.Activity.Status.String(),
		MemberDirectoryMode: view.Activity.MemberDirectoryMode.String(),
		MemberID:            view.Member.ID.String(),
		Nickname:            view.Member.Nickname,
		FactionID:           factionIDOrEmpty(view.Member.FactionID),
		FactionName:         view.Item.FactionName,
		FactionIcon:         view.Item.FactionIcon,
		FactionColor:        view.Item.FactionColor,
		FactionAvailable:    view.Item.FactionAvailable,
		DirectoryVisibility: view.Member.DirectoryVisibility.String(),
		JoinedAt:            timeutil.FormatUTC(view.Member.JoinedAt),
		RequestID:           requestIDFromRequest(r),
	})
}

// memberDirectoryPayload 把一頁目錄換成回應本體（派生值取服務端算好的那一份，
// 這一層不再自己猜「模式加覆蓋加授予」的組合）。
func memberDirectoryPayload(page activity.DirectoryMemberPage,
	requestID string) memberDirectoryResponse {
	items := make([]directoryMemberItem, 0, len(page.Rows))
	for _, row := range page.Rows {
		items = append(items, directoryMemberRow(row))
	}
	facets := make([]directoryFacetItem, 0, len(page.Facets))
	for _, facet := range page.Facets {
		facets = append(facets, directoryFacetItem{
			FactionID: factionIDOrEmpty(facet.FactionID), Name: facet.Name,
			Icon: facet.Icon, Color: facet.Color, Count: facet.Count,
		})
	}
	return memberDirectoryResponse{
		Members:             items,
		Facets:              facets,
		MemberDirectoryMode: page.Mode.String(),
		SelfMemberID:        selfMemberIDOrEmpty(page.SelfID),
		Page:                page.Page,
		PageSize:            page.PageSize,
		Total:               page.Total,
		RequestID:           requestID,
	}
}

// directoryMemberRow 把一行目錄投影換成回應本體。
func directoryMemberRow(item activity.DirectoryMember) directoryMemberItem {
	return directoryMemberItem{
		MemberID:         item.MemberID.String(),
		Nickname:         item.Nickname,
		FactionID:        factionIDOrEmpty(item.FactionID),
		FactionName:      item.FactionName,
		FactionIcon:      item.FactionIcon,
		FactionColor:     item.FactionColor,
		FactionAvailable: item.FactionAvailable,
		JoinedAt:         timeutil.FormatUTC(item.JoinedAt),
	}
}

// selfMemberIDOrEmpty 把「觀看者自己在這場活動裡的標識」換成回應裡的可讀值：
// 零值（獲准管理該活動、自己卻沒有成員行的那種管理視角）出口為空字串，
// 而不是湊一個解析不回任何人的全零標識（口徑同 factionIDOrEmpty）。
func selfMemberIDOrEmpty(id idgen.ID) string {
	if id.IsNil() {
		return ""
	}
	return id.String()
}

// writeMemberDirectoryFailure 把目錄的三條讀法與兩條管理寫入通路共用的錯誤對映為對外回應。
//
// 每一格拒絕各有各的碼與處置，因為操作者要做的事完全不同：
// 1004 改寫法（點名是哪一欄或哪個查詢引數）、2013 重讀現值再決定（配置與覆蓋共用同一枚：
// 處置同形）、2033 等活動重開、2029 這件事已經結束、1001 換個目標。
// 1001 那一格同時收斂四件事——查無這個活動、他不是這場活動的成員、那一行屬於別的活動、
// 以及那一行此刻按規則不給他看（不可分辨；見 internal/activity/memberdirectory.go）。
// 「目錄這一態不列任何人」不在這裡：那一態的答案是一份空清單而不是錯誤。
// 被拒的寫入不回顯任何一方現值。
func (s *Server) writeMemberDirectoryFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, activity.ErrInvalidDirectoryMode):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "mode"})
		return
	case errors.Is(err, activity.ErrInvalidDirectoryVisibility):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "visibility"})
		return
	case errors.Is(err, activity.ErrInvalidPage):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "page"})
		return
	case errors.Is(err, activity.ErrInvalidPageSize):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "page_size"})
		return
	case errors.Is(err, activity.ErrInvalidKeyword):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "q"})
		return
	case errors.Is(err, activity.ErrMemberProfileConflict),
		errors.Is(err, activity.ErrProfileConflict):
		writeError(w, r, CodeProfileConflict, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrActivityClosedWrites):
		writeError(w, r, CodeActivityClosedWrites, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrArchived):
		writeError(w, r, CodeActivityArchived, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrMemberNotFound), errors.Is(err, activity.ErrActivityNotFound):
		// 「查無這個活動」「他不是這個活動的成員」「那一行不屬於這個活動」
		// 與「那一行此刻對他不可見」是同一句話（不可分辨）。
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("處理玩家目錄請求失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}
