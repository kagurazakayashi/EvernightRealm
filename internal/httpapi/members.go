// members.go 是「活動成員與唯一檔案」在傳輸層的落點：
// /admin/activities/{activity_id}/members 一條路徑做兩件事（GET／HEAD 名冊、POST 建立成員），
// /admin/activities/{activity_id}/members/{member_id} 一條路徑做一件事（PUT 編輯暱稱）。
//
// 本檔案刻意只做協議層該做的四件事，一条領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 consolePrincipal 那條共用鏈；
//  2. 首次改密門閂——同一條鏈上的 requirePasswordChangeDone；
//  3. 請求本體的形態——建立只認 account_id 與 nickname 兩個欄位，編輯只認 nickname
//     加上它所依據的現值 expected_nickname；未知欄位由 decodeJSON 的 DisallowUnknownFields
//     當場拒殺（1004），於是「順手把 member_id、activity_id、joined_at、還有一格自報的
//     陣營歸屬或角色寫進不該有的地方」在本體裡沒有可以填的格子——「動哪個成員」由路徑決定，
//     「哪個活動下的成員」由路徑決定、「他是哪一個人」由服務層現讀 accounts 決定，
//     「誰在做」由那枚憑據決定；
//  4. 結論對映——把用例回傳的可判別錯誤一一對映到機器碼，其餘一律 500 且細節只進日誌。
//     這組端點用到的碼：1001（成員或目標帳戶不在可見範圍，含標識寫壞、跨活動、
//     目標帳戶不具參加資格）、1004（點名欄位）、2011（不屬於管理員這個身份面）、
//     2013（現值已過期，沿 R2-008／R3-001／R4-001 復用口徑）、2029（歸檔終態）、
//     2033（活動停止，業務寫入待重開），以及本步新發布的 2035（該帳戶在此活動已有成員身份）。
//
// 為什麼成員端點掛在 /admin 而不另發一組 /root（用戶批准於本步的邊界沿用 R3-001／R4-001）：
// 打理活動內的成員名冊屬「管某個活動本身的事」，准入是 NeedServerAdmin 加上這個活動的
// 一行指派——與活動資料編輯、陣營管理同一道閘，因此同一個前綴；普通帳戶敲不進任何一條。
// 本步沒有「把成員移出活動」或「把成員改成別人」的通路（見遷移 0014 的觸發器），
// 因此這一族路徑上不存在 DELETE，也沒有任何一格能改身份。
//
// 回應本體不含任何憑據材料、會話材料或帳戶內部欄位：一行成員帶的是它的身份三欄、
// 活動內暱稱、陣營歸屬（空字串＝尚未分組，屬合法現值而不是缺席）、帳戶的顯示名與狀態
// 投影，以及兩個時刻。顯示名與狀態為空字串時語意是「軟參照指向的那一行已讀不回」，
// 介面據實顯示通用句，不編造一個名字（口徑同管理人名冊）。
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

// MemberUseCase 是「活動成員與唯一檔案」用例在傳輸層的入口形態（由 internal/app 注入
// 同一個 *activity.Service 的成員通路）。
//
// 獨立一個依賴欄位（口徑同 Activities 與 Factions 的分離理由）：本執行檔沒注入它時
// 一個成員端點都不掛，協定層行為與尚未有成員模組的版次逐字相同。
// principal 一律是「本次請求的憑據此刻換出的受信主體」，授權、活動作用域判定、
// 業務寫入門禁、目標帳戶資格核實與那一跳落庫都在用例裡判。
type MemberUseCase interface {
	// CreateMember 在一個活動裡為一個既有帳戶建立成員身份與唯一檔案：出生即無陣營，
	// 目標帳戶的型別與狀態由服務層現讀（停止與歸檔的活動一律拒寫，見 internal/activity/status.go）。
	CreateMember(ctx context.Context, principal identity.Principal,
		activityID, accountID idgen.ID, nickname, requestID string) (activity.Member, error)
	// Members 以當前受信主體讀一個活動的成員名冊（仍列、可讀：停止與歸檔照樣能讀）。
	Members(ctx context.Context, principal identity.Principal,
		activityID idgen.ID) ([]activity.Member, error)
	// UpdateMemberNickname 以白名單方式編輯暱稱一欄；expected_nickname 是提交所依據的現值，
	// 現值已變時整個編輯不落並回可判別的衝突。身分三欄與陣營歸屬不在這條通路上。
	UpdateMemberNickname(ctx context.Context, principal identity.Principal,
		activityID, memberID idgen.ID, nickname, expectedNickname,
		requestID string) (activity.Member, error)
}

// createMemberRequest 是建立成員請求的本體。白名單只有兩格：目標帳戶與活動內暱稱。
// member_id／activity_id／created_at／faction_id 都沒有格子——身份與歸屬由路徑和倉儲決定，
// 陣營分配屬下一步的通路（見 internal/activity/members.go 的頭注），
// 「建立成員時順手把他分進某個陣營」因此在協定層就無處可填。
type createMemberRequest struct {
	AccountID string `json:"account_id"`
	Nickname  string `json:"nickname"`
}

// updateMemberRequest 是編輯成員請求的本體：暱稱新值加上它所依據的現值。
// 身分三欄與 faction_id 連一個格子都沒有（未知欄位 1004），
// 「儲存名字順手把他挪進另一個陣營」不是被拒，而是無處可填。
type updateMemberRequest struct {
	Nickname         string `json:"nickname"`
	ExpectedNickname string `json:"expected_nickname"`
}

// memberItem 是名冊行、建立回顯與編輯結果共用的形狀（同一筆資料在不同回應裡的形狀必須同源）。
//
// faction_id 恆在回應裡：空字串是「尚未分組」這個合法現值（口徑同陣營的圖標與顏色），
// 不靠欄位缺席表達——否則介面要區分「這個人還沒組」與「這一格我讀不懂」，而兩者不是同一句話。
// display_name 與 account_status 同樣恆在：空字串是軟參照讀不回時的如實陳述。
type memberItem struct {
	MemberID   string `json:"member_id"`
	ActivityID string `json:"activity_id"`
	AccountID  string `json:"account_id"`
	Nickname   string `json:"nickname"`
	FactionID  string `json:"faction_id"`
	// DisplayName 與 AccountStatus 是帳戶的投影，不是 activity_members 的欄位（見
	// internal/activity/memberstore.go 的讀法說明）；兩者同時為空表示那一行已讀不回。
	DisplayName   string `json:"display_name"`
	AccountStatus string `json:"account_status"`
	// DirectoryVisibility 是這一行的目錄覆蓋現值（inherit|hidden，出廠 inherit）。
	// 它屬只增不刪的相容演進欄位：管理名冊把它帶出來，管理人才能看懂自己刚收起來的是哪一行；
	// 玩家側的目錄投影從不帶它（見 internal/httpapi/memberdirectory.go 的白名單理由）。
	DirectoryVisibility string `json:"directory_visibility"`
	// AdminIdentity 是「這個帳戶此刻持有 server_admin 授予」的服務端現讀投影：
	// 判據只有 internal/grant，不是暱稱或任何前端標記。它只在管理面出現，
	// 對 all_players_except_admin 那一態而言，這一格回答的正是「被收起來的是誰」。
	AdminIdentity bool `json:"admin_identity"`
	// BusinessStatus 是成員此刻的業務狀態內部值（七個內建鍵之一；出廠 normal）。
	// 它與連線在線狀態無關：沒有任何請求、頁面開啟或心跳會自動改寫它。
	BusinessStatus string `json:"business_status"`
	// CustomStatusID 是自訂狀態定義的穩定標識；非 custom 狀態時為空字串。
	CustomStatusID string `json:"custom_status_id"`
	// CustomStatusName 是自訂定義此刻的名稱；非 custom 或讀不到定義時為空字串。
	CustomStatusName string `json:"custom_status_name"`
	// StatusDisplayName 是展示用名稱：內建狀態取活動覆蓋（空字串＝用戶端四語言預設），
	// 自訂狀態取定義名稱。它是顯示值，不是內部身份，也不得被前端當成 HTML。
	StatusDisplayName string `json:"status_display_name"`
	// StatusAvailable 表示這個狀態此刻是否仍可被選用（內建恆為真，自訂取定義現值）。
	StatusAvailable bool `json:"status_available"`
	// 六枚分項限制旗標的現值（遷移 0019，出廠恆為假）：只在管理面出現，
	// 玩家目錄與本人資料投影從不帶它們（見 memberrestrictions.go 的白名單理由）。
	// 每欄恆在回應、絕在請求——編輯走自己那條 restricts 通路的逐對白名單。
	RestrictLogin       bool   `json:"restrict_login"`
	RestrictChat        bool   `json:"restrict_chat"`
	RestrictPrivateChat bool   `json:"restrict_private_chat"`
	RestrictTrade       bool   `json:"restrict_trade"`
	RestrictTransfer    bool   `json:"restrict_transfer"`
	RestrictItemUse     bool   `json:"restrict_item_use"`
	JoinedAt            string `json:"joined_at"`
	UpdatedAt           string `json:"updated_at"`
}

// memberListResponse 是 GET／HEAD 名冊的回應本體。
//
// 不帶活動那一格：名冊本來就是「這個活動的成員們」，活動現值屬父路徑的詳情讀法
// （口徑同陣營列表與管理人名冊）。本步的成員是一場活動的參加名單，與那兩張小表同樣不分頁。
type memberListResponse struct {
	Members   []memberItem `json:"members"`
	RequestID string       `json:"request_id"`
}

// memberWriteResponse 是 POST 建立與 PUT 編輯共用的寫入回應本體。
type memberWriteResponse struct {
	Member    memberItem `json:"member"`
	RequestID string     `json:"request_id"`
}

// memberEndpoints 回傳成員管理端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深連結回退用的 API 首段清單（/admin）因此自動同步。
// 建立與讀取掛在集合路徑上、編輯掛在單筆路徑上；這一族沒有 DELETE——
// 本步批准的是「沒有把成員移出活動的通路」（見遷移 0014 檔頭）。
func (s *Server) memberEndpoints() []apiRoute {
	if s.members == nil {
		return nil
	}
	return []apiRoute{
		{"/admin/activities/{activity_id}/members", s.allowMethods(s.handleMembers,
			http.MethodGet, http.MethodHead, http.MethodPost)},
		{"/admin/activities/{activity_id}/members/{member_id}", s.allowMethods(s.handleMemberProfile,
			http.MethodPut)},
	}
}

// handleMembers 依方法分流：GET／HEAD 成員名冊、POST 建立一個成員身份。
func (s *Server) handleMembers(w http.ResponseWriter, r *http.Request) {
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
		s.createMember(w, r, principal, activityID)
		return
	}
	s.listMembers(w, r, principal, activityID)
}

// listMembers 處理 GET／HEAD 名冊：可見範圍的拒絕與「從沒這個活動」同形（1001），
// 已歸檔與已停止的活動照樣列出行（仍列、可讀）。
func (s *Server) listMembers(w http.ResponseWriter, r *http.Request,
	principal identity.Principal, activityID idgen.ID) {
	rows, err := s.members.Members(r.Context(), principal, activityID)
	if err != nil {
		if s.writeActivityCommonFailures(w, r, err) {
			return
		}
		s.logger.Error("讀取成員名冊失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		return
	}
	items := make([]memberItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, memberRow(row))
	}
	writeJSON(w, http.StatusOK, memberListResponse{
		Members:   items,
		RequestID: requestIDFromRequest(r),
	})
}

// createMember 處理 POST 建立：本體白名單交用例，其餘結論都在對映裡。
//
// 目標標識寫壞（解析不出正規標識）與查無此人同一句話（1001）：這一族路徑不當標識格式探測器，
// 口徑同 R2 各條目標路徑與管理人指派。
func (s *Server) createMember(w http.ResponseWriter, r *http.Request,
	principal identity.Principal, activityID idgen.ID) {
	var in createMemberRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	accountID, err := idgen.Parse(in.AccountID)
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	created, err := s.members.CreateMember(r.Context(), principal, activityID, accountID,
		in.Nickname, requestIDFromRequest(r))
	if err != nil {
		s.writeMemberWriteFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, memberWriteResponse{
		Member:    memberRow(created),
		RequestID: requestIDFromRequest(r),
	})
}

// handleMemberProfile 處理 /admin/activities/{activity_id}/members/{member_id}：PUT 編輯暱稱。
//
// 這條子路徑只有 PUT 一個方法：讀現值在名冊那條路上，這一族刻意不另發單筆讀法
// （名冊就是全量，單筆詳情會造出第二個答案來源）。兩個標識任一個非法都是 1001。
func (s *Server) handleMemberProfile(w http.ResponseWriter, r *http.Request) {
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
	var in updateMemberRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	updated, err := s.members.UpdateMemberNickname(r.Context(), principal, activityID, memberID,
		in.Nickname, in.ExpectedNickname, requestIDFromRequest(r))
	if err != nil {
		s.writeMemberWriteFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, memberWriteResponse{
		Member:    memberRow(updated),
		RequestID: requestIDFromRequest(r),
	})
}

// memberRow 把一行成員換成回應本體（欄位白名單見 internal/activity/memberstore.go 的讀法；
// display_name 與 account_status 是用例讀回後蓋上的投影，這一層不再自己查帳戶，
// 免得同一個事實出現兩個答案來源）。
func memberRow(m activity.Member) memberItem {
	// 零值標識的 String 是「全零的 UUID 字串」，它既解析不回任何陣營也不是一句人話：
	// 「尚未分組」因此出口為空字串，而不是湊一個读不回任何人的標識（口徑同陣營圖標與顏色的空）。
	factionID := ""
	if m.HasFaction() {
		factionID = m.FactionID.String()
	}
	return memberItem{
		MemberID:      m.ID.String(),
		ActivityID:    m.ActivityID.String(),
		AccountID:     m.AccountID.String(),
		Nickname:      m.Nickname,
		FactionID:     factionID,
		DisplayName:   m.DisplayName,
		AccountStatus: m.AccountStatus.String(),
		// 兩格都是服務端現讀的投影，請求本體沒有格子能填它們（帶了就在寫入通路撞 1004）。
		DirectoryVisibility: m.DirectoryVisibility.String(),
		AdminIdentity:       m.AdminIdentity,
		BusinessStatus:      m.BusinessStatus.String(),
		CustomStatusID:      statusIDOrEmpty(m.CustomStatusID),
		CustomStatusName:    m.CustomStatusName,
		StatusDisplayName:   m.StatusDisplayName,
		StatusAvailable:     m.StatusAvailable,
		// 六枚限制旗標逐欄原樣出去：現值不是派生推測，管理人也才能拿它們當依據值。
		RestrictLogin:       m.RestrictLogin,
		RestrictChat:        m.RestrictChat,
		RestrictPrivateChat: m.RestrictPrivateChat,
		RestrictTrade:       m.RestrictTrade,
		RestrictTransfer:    m.RestrictTransfer,
		RestrictItemUse:     m.RestrictItemUse,
		JoinedAt:            timeutil.FormatUTC(m.JoinedAt),
		UpdatedAt:           timeutil.FormatUTC(m.UpdatedAt),
	}
}

// writeMemberWriteFailure 把建立與編輯兩條寫入通路的錯誤對映為對外回應。
//
// 每一格拒絕各有各的碼與處置，因為操作者要做的事完全不同：
// 1004 改寫法（點名是哪一欄）、2035 換個人或改那份既有檔案、2013 重讀現值再決定、
// 2033 等活動重開、2029 這件事已經結束、1001 換個目標（含「那個人此刻不具參加資格」——
// 用戶批准的收斂：不為管理人另開一句「他被刪了」）。2013 沿用帳戶、活動與陣營資料編輯
// 那一枚（同一句話、同一處置），不另發新碼；2035 是本步順發的那一枚。
// 被拒的寫入不回顯任何一方現值。
func (s *Server) writeMemberWriteFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, activity.ErrInvalidNickname):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "nickname"})
		return
	case errors.Is(err, activity.ErrMemberAccountTaken):
		writeError(w, r, CodeActivityMemberTaken, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrMemberProfileConflict):
		writeError(w, r, CodeProfileConflict, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrActivityClosedWrites):
		writeError(w, r, CodeActivityClosedWrites, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrArchived):
		writeError(w, r, CodeActivityArchived, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrMemberNotFound):
		// 「查無此成員」「它不屬於這個活動」「目標帳戶不具參加資格」是同一句話
		// （不可分辨；見 internal/activity/members.go 的兩處判定）。
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("寫入活動成員失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}
