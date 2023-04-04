// factionselect.go 是「玩家自選陣營與活動開關」在傳輸層的落點：
// /admin/activities/{activity_id}/faction-select 一條路徑做一件事（PUT 編輯那一欄配置），
// /player/activities 一條路徑做一件事（GET／HEAD 讀我參加了哪些活動），
// /player/activities/{activity_id}/faction 一條路徑做兩件事（GET／HEAD 讀我的陣營現況、
// PUT 自選一個陣營）。
//
// 這一組端點存在的理由是「準入邊界不同」，不是「同一件事換個字首」：
//   - 配置那一條走的是活動管理面那道閘（NeedServerAdmin 加上這個活動的一行指派），
//     與活動資料編輯、陣營管理、成員名冊同一道閘，因此仍掛在 /admin 之下；
//   - 玩家那三條只問「這次請求的憑據此刻換出的是哪一個帳戶」，主體由會話決定，
//     路徑裡沒有一格能填「哪個玩家」，本體裡也沒有——把管理端那條通用編輯通路開放給
//     玩家不等於授權，它是「任何人都可以改任何人的資料」，因此這裡另起一族只碰自己
//     一欄的路徑。/player 這一個首段屬本步新增，與 /admin、/root、/auth 同規（無版本前綴、
//     只增不刪）；前端的路由名稱是 /player-surface，與它不同形，深連結回退不受影響。
//
// 本檔案刻意只做協議層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 consolePrincipal 那條共用鏈；
//  2. 首次改密門閂——同一條鏈上的 requirePasswordChangeDone；
//  3. 請求本體的形態——配置編輯只認 mode 加上它所依據的現值 expected_mode，
//     自選只認 faction_id 加上它所依據的現值 expected_faction_id；未知欄位由 decodeJSON 的
//     DisallowUnknownFields 當場拒殺（1004），於是「順手把 member_id、account_id、activity_id、
//     nickname、甚至一格自報的『我是管理人』寫進來」在本體裡沒有可以填的格子；
//  4. 結論對映——把用例回傳的可判別錯誤一一對映到機器碼，其餘一律 500 且細節只進日誌。
//     這組端點用到的碼：1001（活動、成員或陣營不在可見範圍，含標識寫壞）、1004（點名欄位）、
//     2013（現值已過期，沿用活動與成員資料編輯那枚）、2029（歸檔終態）、
//     2033（活動停止，業務寫入待重開），以及本步新發布的 2036～2039
//     （陣營停用／活動沒開放自選／活動還在草稿／僅首次模式下已選過）。
//
// 回應本體不含任何憑據材料、會話材料或帳戶內部欄位。派生值（活動的 faction_select_mode、
// 玩家現況裡的 can_select_now、每個候選項的 selectable）恆在回應裡，而請求本體沒有這些格子——
// 帶了就由 1004 點名（口徑同陣營列表的 accepts_new_members）。
// 界面據此把「此刻能不能選」與「這次提交的結果」分兩處顯示：前者是服務端讀出的現值，
// 後者是寫入通路的結論，藏按鈕永遠不代替服務端那道閘。
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

// FactionSelectUseCase 是「玩家自選陣營與活動開關」用例在傳輸層的入口形態
// （由 internal/app 注入同一個 *activity.Service 的自選通路）。
//
// 獨立一個依賴欄位（口徑同 Activities、Factions 與 Members 的分離理由）：本執行檔沒注入它時
// 一個自選端點都不掛，協定層行為與尚未有這件事的版次逐字相同。
// principal 一律是「本次請求的憑據此刻換出的受信主體」，授權、活動作用域判定、
// 本人成員行核實、時機判定、陣營可用性核實與那一跳落庫都在用例裡判。
type FactionSelectUseCase interface {
	// UpdateFactionSelectMode 由活動管理人編輯那一欄配置；兩個 mode 值都屬封閉集合，
	// expected_mode 是提交所依據的現值，現值已變時整個編輯不落並回可判別的衝突。
	// 它不改寫任何人的既有歸屬（見 internal/activity/selfselect.go 的理由）。
	UpdateFactionSelectMode(ctx context.Context, principal identity.Principal,
		activityID idgen.ID, mode, expectedMode activity.FactionSelectMode,
		requestID string) (activity.Activity, error)
	// MyActivityEntries 以本次會話的帳戶讀「我參加了哪些活動」。
	MyActivityEntries(ctx context.Context,
		principal identity.Principal) ([]activity.MemberActivityEntry, error)
	// MyFactionSelection 讀回這個帳戶在那場活動裡的陣營現況與候選清單。
	MyFactionSelection(ctx context.Context, principal identity.Principal,
		activityID idgen.ID) (activity.FactionSelectionView, error)
	// SelectOwnFaction 讓這個帳戶自己把歸屬換成一個此刻可用的陣營；
	// expected_faction_id 是他提交所依據的歸屬現值（空字串＝他以為自己尚未分組）。
	SelectOwnFaction(ctx context.Context, principal identity.Principal,
		activityID, factionID, expectedFactionID idgen.ID,
		requestID string) (activity.Member, error)
}

// updateFactionSelectRequest 是配置編輯請求的本體：新模式加上它所依據的現值。
// 狀態、名稱、描述與任何人的歸屬都沒有格子——那一欄配置動的就是它自己一欄。
type updateFactionSelectRequest struct {
	Mode         string `json:"mode"`
	ExpectedMode string `json:"expected_mode"`
}

// selectOwnFactionRequest 是玩家自選請求的本體：目標陣營加上它所依據的歸屬現值。
// 沒有 member_id、沒有 account_id、也沒有「清空歸屬」那一格（自選只能設定，不能遷出）。
type selectOwnFactionRequest struct {
	FactionID         string `json:"faction_id"`
	ExpectedFactionID string `json:"expected_faction_id"`
}

// myActivityItem 是「我參加了哪些活動」的一行：活動那一側的現值加上我自己的成員行現值。
//
// faction_id 恆在：空字串是「尚未分組」這個合法現值（口徑同成員名冊），不靠欄位缺席表達。
type myActivityItem struct {
	ActivityID        string `json:"activity_id"`
	Name              string `json:"name"`
	Status            string `json:"status"`
	FactionSelectMode string `json:"faction_select_mode"`
	MemberID          string `json:"member_id"`
	Nickname          string `json:"nickname"`
	FactionID         string `json:"faction_id"`
	// AccessRestricted 是本人那一行 restrict_login 的服務端現值投影（遷移 0019）。
	// 清單照舊列這一場活動——他的成員身份是事實，藏起清單項不等於限制，只是讓它難找；
	// 但該活動其餘 /player 讀寫都會撞 2043，界面靠這一格把「訪問已被限制」說在敲壁之前。
	// 它是派生值：恆在回應、絕在請求（口徑同 accepts_new_members 與 selectable）。
	AccessRestricted bool   `json:"access_restricted"`
	JoinedAt         string `json:"joined_at"`
}

// myActivityListResponse 是本人活動清單讀法的回應本體（不分頁：一個人參加的活動是小表，
// 口徑同成員名冊與管理人名冊）。
type myActivityListResponse struct {
	Activities []myActivityItem `json:"activities"`
	RequestID  string           `json:"request_id"`
}

// factionOptionItem 是一個候選陣營與「它此刻能不能被這個玩家選」的派生值。
type factionOptionItem struct {
	FactionID   string `json:"faction_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Color       string `json:"color"`
	SortOrder   int64  `json:"sort_order"`
	Available   bool   `json:"available"`
	Selectable  bool   `json:"selectable"`
}

// factionSelectionResponse 是「我的陣營現況」一讀的回應本體。
//
// can_select_now 是服務端派生值（活動的狀態加那一欄配置的合取），請求本體沒有這一格；
// 它只負責把界面該不該長出那顆按鈕說出來，寫入通路在交易內重新問同樣的幾句話。
type factionSelectionResponse struct {
	ActivityID        string              `json:"activity_id"`
	Name              string              `json:"name"`
	Status            string              `json:"status"`
	FactionSelectMode string              `json:"faction_select_mode"`
	CanSelectNow      bool                `json:"can_select_now"`
	MemberID          string              `json:"member_id"`
	Nickname          string              `json:"nickname"`
	FactionID         string              `json:"faction_id"`
	Factions          []factionOptionItem `json:"factions"`
	RequestID         string              `json:"request_id"`
}

// selfFactionWriteResponse 是自選寫入的回應本體。
//
// 刻意不複用成員名冊那個形狀：名冊行帶的是「帳戶側的投影」（顯示名與帳戶狀態），
// 而這一條通路的回讀只有 activity_members 那一行的事實。把兩格空字串塞進回應，
// 介面上就會讀成「這個人查無此人」——那是把「沒做那次投影」誤報成「軟參照讀不回」。
type selfFactionWriteResponse struct {
	MemberID   string `json:"member_id"`
	ActivityID string `json:"activity_id"`
	Nickname   string `json:"nickname"`
	FactionID  string `json:"faction_id"`
	UpdatedAt  string `json:"updated_at"`
	RequestID  string `json:"request_id"`
}

// factionSelectEndpoints 回傳自選陣營端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深連結回退用的 API 首段清單（/admin 與本步新增的 /player）
// 因此自動同步：不可能出現「/player 這個首段被排除了卻沒掛上任何端點」那種
// 「玩家深連結拿到 JSON 404 而不是應用外殼」的形態。
func (s *Server) factionSelectEndpoints() []apiRoute {
	if s.factionSelect == nil {
		return nil
	}
	return []apiRoute{
		{"/admin/activities/{activity_id}/faction-select",
			s.allowMethods(s.handleFactionSelectConfig, http.MethodPut)},
		{"/player/activities",
			s.allowMethods(s.handleMyActivities, http.MethodGet, http.MethodHead)},
		{"/player/activities/{activity_id}/faction",
			s.allowMethods(s.handleMyFaction, http.MethodGet, http.MethodHead, http.MethodPut)},
	}
}

// handleFactionSelectConfig 處理 PUT /admin/activities/{activity_id}/faction-select。
func (s *Server) handleFactionSelectConfig(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in updateFactionSelectRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	updated, err := s.factionSelect.UpdateFactionSelectMode(r.Context(), principal, activityID,
		activity.FactionSelectMode(in.Mode), activity.FactionSelectMode(in.ExpectedMode),
		requestIDFromRequest(r))
	if err != nil {
		s.writeFactionSelectFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, activityWriteResponse{
		Activity:  activityRow(updated),
		RequestID: requestIDFromRequest(r),
	})
}

// handleMyActivities 處理 GET／HEAD /player/activities：只列本人有成員行的活動。
func (s *Server) handleMyActivities(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	entries, err := s.factionSelect.MyActivityEntries(r.Context(), principal)
	if err != nil {
		s.writeFactionSelectFailure(w, r, err)
		return
	}
	items := make([]myActivityItem, 0, len(entries))
	for _, entry := range entries {
		items = append(items, myActivityRow(entry))
	}
	writeJSON(w, http.StatusOK, myActivityListResponse{
		Activities: items,
		RequestID:  requestIDFromRequest(r),
	})
}

// handleMyFaction 依方法分流：GET／HEAD 讀我的陣營現況、PUT 自選一個陣營。
func (s *Server) handleMyFaction(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if r.Method == http.MethodPut {
		s.selectOwnFaction(w, r, principal, activityID)
		return
	}
	view, err := s.factionSelect.MyFactionSelection(r.Context(), principal, activityID)
	if err != nil {
		s.writeFactionSelectFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, factionSelectionViewResponse(view, requestIDFromRequest(r)))
}

// selectOwnFaction 處理 PUT /player/activities/{activity_id}/faction。
//
// 兩個標識任一個寫壞（解析不出正規標識）都是 1001：這一條路徑不當標識格式探測器，
// 口徑同成員那族路徑與管理人指派。空字串的依據值是合法寫法——它的語意是
// 「我以為自己還沒分組」，由倉儲以 NULL 安全比對去核實。
func (s *Server) selectOwnFaction(w http.ResponseWriter, r *http.Request,
	principal identity.Principal, activityID idgen.ID) {
	var in selectOwnFactionRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	factionID, err := idgen.Parse(in.FactionID)
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var expected idgen.ID
	if in.ExpectedFactionID != "" {
		expected, err = idgen.Parse(in.ExpectedFactionID)
		if err != nil {
			writeError(w, r, CodeNotFound, http.StatusNotFound)
			return
		}
	}
	updated, err := s.factionSelect.SelectOwnFaction(r.Context(), principal, activityID,
		factionID, expected, requestIDFromRequest(r))
	if err != nil {
		s.writeFactionSelectFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, selfFactionWriteResponse{
		MemberID:   updated.ID.String(),
		ActivityID: updated.ActivityID.String(),
		Nickname:   updated.Nickname,
		FactionID:  factionIDOrEmpty(updated.FactionID),
		UpdatedAt:  timeutil.FormatUTC(updated.UpdatedAt),
		RequestID:  requestIDFromRequest(r),
	})
}

// myActivityRow 把「本人的成員行＋那場活動」換成清單項。
func myActivityRow(entry activity.MemberActivityEntry) myActivityItem {
	return myActivityItem{
		ActivityID:        entry.Activity.ID.String(),
		Name:              entry.Activity.Name,
		Status:            entry.Activity.Status.String(),
		FactionSelectMode: entry.Activity.FactionSelectMode.String(),
		MemberID:          entry.Member.ID.String(),
		Nickname:          entry.Member.Nickname,
		FactionID:         factionIDOrEmpty(entry.Member.FactionID),
		AccessRestricted:  entry.Member.RestrictLogin,
		JoinedAt:          timeutil.FormatUTC(entry.Member.JoinedAt),
	}
}

// factionSelectionViewResponse 把現況讀法換成回應本體（派生值取服務端算好的那一份，
// 這一層不再自己猜「活動狀態加配置加旗標」的組合）。
func factionSelectionViewResponse(view activity.FactionSelectionView,
	requestID string) factionSelectionResponse {
	options := make([]factionOptionItem, 0, len(view.Options))
	for _, option := range view.Options {
		options = append(options, factionOptionItem{
			FactionID:   option.Faction.ID.String(),
			Name:        option.Faction.Name,
			Description: option.Faction.Description,
			Icon:        option.Faction.Icon,
			Color:       option.Faction.Color,
			SortOrder:   option.Faction.SortOrder,
			Available:   option.Faction.Available,
			Selectable:  option.Selectable,
		})
	}
	return factionSelectionResponse{
		ActivityID:        view.Activity.ID.String(),
		Name:              view.Activity.Name,
		Status:            view.Activity.Status.String(),
		FactionSelectMode: view.Activity.FactionSelectMode.String(),
		CanSelectNow:      view.CanSelectNow(),
		MemberID:          view.Member.ID.String(),
		Nickname:          view.Member.Nickname,
		FactionID:         factionIDOrEmpty(view.Member.FactionID),
		Factions:          options,
		RequestID:         requestID,
	}
}

// factionIDOrEmpty 把歸屬換成回應裡的可讀值：零值（尚未分組）出口為空字串，
// 而不是湊一個解析不回任何陣營的全零標識（口徑同成員名冊與陣營圖標、顏色的空）。
func factionIDOrEmpty(id idgen.ID) string {
	if id.IsNil() {
		return ""
	}
	return id.String()
}

// writeFactionSelectFailure 把配置編輯與玩家自選兩條寫入通路、以及兩條玩家讀法的錯誤
// 對映為對外回應。
//
// 每一格拒絕各有各的碼與處置，因為操作者要做的事完全不同：
// 1004 改寫法（點名是哪一欄）、2036 換一個還開著的陣營或請管理人重新啟用、
// 2037 等管理人打開那一欄配置、2038 等活動開放、2039 這件事已由他選過一次而自助不再可改、
// 2013 重讀現值再決定（配置與自選共用同一枚：處置同形）、2033 等活動重開、
// 2029 這件事已經結束、1001 換個目標（含「他不是這個活動的成員」與「那個陣營不屬於這場活動」——
// 不可分辨收斂，口徑同成員那族路徑）。被拒的寫入不回顯任何一方現值。
func (s *Server) writeFactionSelectFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, activity.ErrInvalidFactionSelectMode):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "mode"})
		return
	case errors.Is(err, activity.ErrInvalidFactionSelection):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "faction_id"})
		return
	case errors.Is(err, activity.ErrFactionNotAcceptingMembers):
		writeError(w, r, CodeFactionNotAcceptingMembers, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrFactionSelectDisabled):
		writeError(w, r, CodeFactionSelectDisabled, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrFactionSelectNotOpen):
		writeError(w, r, CodeFactionSelectNotOpen, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrFactionSelectLockedIn):
		writeError(w, r, CodeFactionSelectLockedIn, http.StatusConflict)
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
	case errors.Is(err, activity.ErrMemberNotFound), errors.Is(err, activity.ErrFactionNotFound),
		errors.Is(err, activity.ErrActivityNotFound):
		// 「查無這個活動」「他不是這個活動的成員」「那個陣營不屬於這個活動」是同一句話
		// （不可分辨；見 internal/activity/selfselect.go 與 members.go 的判定）。
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("處理自選陣營請求失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}
