// memberrestrictions.go 是「玩家分項限制與活動訪問控制」在傳輸層的落點：
// /admin/activities/{activity_id}/members/{member_id}/restrictions 一條路徑做編輯
// （PUT，逐欄白名單），/player/activities/{activity_id}/restrictions 一條路徑做本人查閱
// （GET／HEAD，六個布林）。
//
// 本檔案只做協議層該做的四件事：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 consolePrincipal 那條共用鏈；
//  2. 首次改密門閂——同一條鏈上的 requirePasswordChangeDone；
//  3. 請求形態——編輯本體只認六對 restrict_*／expected_restrict_*：每一對都要麼同時出現、
//     要麼同時缺席；至少出現一對；「只帶新值不帶依據值」與「只帶依據值」都是 1004 點名，
//     未知欄位由 decodeJSON 的 DisallowUnknownFields 當場拒殺。缺席的那幾欄倉儲的 SET 子句
//     裡連格子都沒有，「取消聊天順手取消私聊」在協定層與 SQL 形狀上同時無處發生。
//  4. 結論對映——可判別錯誤一一對映到機器碼，其餘一律 500 且細節只進日誌。
//
// 本步新發布一枚碼：2043（該玩家在此活動的訪問資格已被限制）。它不只屬於本檔這兩條路徑：
// 玩家族其餘活動通路（自選、目錄、本人資料、標籤）的現讀判定都經
// writeActivityCommonFailures 收敛到同一枚，於是「被擋」對任何通路都是同一句話。
// 其餘復用 1001／1004／2011／2013／2029／2033。
//
// 六枚旗標在兩份回應裡的語意都是「此刻的現值」，不是派生推測：管理名冊那一份帶全六欄
// （含操作所需的依據值語意），玩家本人那一份只帶六個布林與標識——沒有原因、沒有操作者、
// 沒有時間戳（那些屬審計；本倉庫沒有審計查詢的 HTTP 入口，是批准邊界）。
// 聊天、私聊、交易、轉賬與使用物品的業務尚未實現：本檔不發與它們對應的任何碼，
// 介面也不擺「去試聊天功能」這類假可用入口。
package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/kagurazakayashi/EvernightRealm/internal/activity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// MemberRestrictionUseCase 是分項限制用例在傳輸層的入口形態
// （由 internal/app 注入同一個 *activity.Service 的限制通路）。
//
// 獨立一個依賴欄位（口徑同 Members／MemberDirectory／Tags／PlayerStatus 的分離理由）：
// 本執行檔沒注入它時一個限制端點都不掛，協定層行為與尚未有這件事的版次逐字相同。
// 注意：訪問資格的「擋」不在這裡——那六條既有玩家通路的判定在服務層現讀，
// 與本依賴是否裝配無關（旗標讀法與判定同屬 *activity.Service）。
type MemberRestrictionUseCase interface {
	// UpdateMemberRestrictions 由活動管理人逐欄編輯一行成員被選中的那幾枚限制。
	UpdateMemberRestrictions(ctx context.Context, principal identity.Principal,
		activityID, memberID idgen.ID, edit activity.MemberRestrictionEdit,
		requestID string) (activity.Member, error)
	// OwnMemberRestrictions 讀回本次會話帳戶在那場活動裡的六枚限制現值（不受訪問限制遮擋）。
	OwnMemberRestrictions(ctx context.Context, principal identity.Principal,
		activityID idgen.ID) (activity.Member, error)
}

// restrictionFieldPair 是一對欄位在請求形態上的描述：JSON 欄位名與其鍵。
//
// 六對欄位走同一份清單，於是「白名單有哪些欄位」只有一處來源，
// 逐對校驗（新值與依據值同時出現或同時缺席）也逐字共用同一個循環。
type restrictionFieldPair struct {
	key          activity.MemberRestrictionKey
	valueField   string
	expectedName string
	value        *bool
	expected     *bool
}

// updateMemberRestrictionsRequest 是編輯分項限制的本體：六對可選欄位。
//
// 指針區分「沒帶」與「帶了 false」：限制欄的合法值就是布爾，缺席才是「這欄不動」。
// 請求裡沒有「哪個玩家」「哪場活動」「誰在做」或任何派生格：那些由路徑與憑據決定，
// 帶了這類欄位就在 DisallowUnknownFields 一步撞 1004。
type updateMemberRestrictionsRequest struct {
	RestrictLogin               *bool `json:"restrict_login"`
	RestrictChat                *bool `json:"restrict_chat"`
	RestrictPrivateChat         *bool `json:"restrict_private_chat"`
	RestrictTrade               *bool `json:"restrict_trade"`
	RestrictTransfer            *bool `json:"restrict_transfer"`
	RestrictItemUse             *bool `json:"restrict_item_use"`
	ExpectedRestrictLogin       *bool `json:"expected_restrict_login"`
	ExpectedRestrictChat        *bool `json:"expected_restrict_chat"`
	ExpectedRestrictPrivateChat *bool `json:"expected_restrict_private_chat"`
	ExpectedRestrictTrade       *bool `json:"expected_restrict_trade"`
	ExpectedRestrictTransfer    *bool `json:"expected_restrict_transfer"`
	ExpectedRestrictItemUse     *bool `json:"expected_restrict_item_use"`
}

// pairs 把本體展成逐對清單（固定順序：login、chat、private_chat、trade、transfer、item_use）。
func (in updateMemberRestrictionsRequest) pairs() []restrictionFieldPair {
	return []restrictionFieldPair{
		{activity.RestrictionLogin, "restrict_login", "expected_restrict_login",
			in.RestrictLogin, in.ExpectedRestrictLogin},
		{activity.RestrictionChat, "restrict_chat", "expected_restrict_chat",
			in.RestrictChat, in.ExpectedRestrictChat},
		{activity.RestrictionPrivateChat, "restrict_private_chat",
			"expected_restrict_private_chat", in.RestrictPrivateChat, in.ExpectedRestrictPrivateChat},
		{activity.RestrictionTrade, "restrict_trade", "expected_restrict_trade",
			in.RestrictTrade, in.ExpectedRestrictTrade},
		{activity.RestrictionTransfer, "restrict_transfer", "expected_restrict_transfer",
			in.RestrictTransfer, in.ExpectedRestrictTransfer},
		{activity.RestrictionItemUse, "restrict_item_use", "expected_restrict_item_use",
			in.RestrictItemUse, in.ExpectedRestrictItemUse},
	}
}

// toEdit 把本體換成領域編輯，並在校驗不過時回「點名哪一欄」的請求寫法結論。
//
// 三种寫法各有名字，因為處置不同：一欄都沒帶（restrictions）、帶了孤零零的新值
// （具體 expected_* 欄）、或只帶依據值（具體 restrict_* 欄）。
func (in updateMemberRestrictionsRequest) toEdit() (activity.MemberRestrictionEdit, string, bool) {
	pairs := in.pairs()
	changes := make([]activity.MemberRestrictionChange, 0, len(pairs))
	for _, pair := range pairs {
		if pair.value == nil && pair.expected == nil {
			continue
		}
		if pair.value == nil {
			return activity.MemberRestrictionEdit{}, pair.valueField, false
		}
		if pair.expected == nil {
			return activity.MemberRestrictionEdit{}, pair.expectedName, false
		}
		changes = append(changes, activity.MemberRestrictionChange{
			Key: pair.key, Value: *pair.value, Expected: *pair.expected,
		})
	}
	if len(changes) == 0 {
		return activity.MemberRestrictionEdit{}, "restrictions", false
	}
	return activity.MemberRestrictionEdit{Changes: changes}, "", true
}

// memberRestrictionsResponse 是本人查閱六枚限制現值的回應本體。
//
// 只有標識與六個布林：每一欄恆在，缺席不是合法形態（口徑同「空字串是合法現值、
// 不靠欄位缺席表達」）。沒有原因句、沒有操作者、沒有翻動時間——那些屬審計。
// 被禁止登入的人仍讀得動這一條：用戶批准的「本人獲准查看有效結果」在這裡落地。
type memberRestrictionsResponse struct {
	ActivityID string `json:"activity_id"`
	MemberID   string `json:"member_id"`
	// 六欄與管理名冊的 restrict_* 同名同語意：此刻的現值，不是派生推測。
	RestrictLogin       bool   `json:"restrict_login"`
	RestrictChat        bool   `json:"restrict_chat"`
	RestrictPrivateChat bool   `json:"restrict_private_chat"`
	RestrictTrade       bool   `json:"restrict_trade"`
	RestrictTransfer    bool   `json:"restrict_transfer"`
	RestrictItemUse     bool   `json:"restrict_item_use"`
	RequestID           string `json:"request_id"`
}

// memberRestrictionsEndpoints 回傳分項限制端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深連結回退用的 API 首段清單（/admin 與 /player）因此自動同步。
// 編輯走活動管理面那道閘（NeedServerAdmin 加上這個活動的一行指派），
// 本人查閱只認「這次請求的憑據換出的是哪一個帳戶」——兩套准入邊界共用一個依賴欄位，
// 只是讓「裝配與否」有一個來源。
func (s *Server) memberRestrictionsEndpoints() []apiRoute {
	if s.memberRestrictions == nil {
		return nil
	}
	return []apiRoute{
		{"/admin/activities/{activity_id}/members/{member_id}/restrictions",
			s.allowMethods(s.handleMemberRestrictionsUpdate, http.MethodPut)},
		{"/player/activities/{activity_id}/restrictions",
			s.allowMethods(s.handleOwnMemberRestrictions, http.MethodGet, http.MethodHead)},
	}
}

// handleMemberRestrictionsUpdate 處理
// PUT /admin/activities/{activity_id}/members/{member_id}/restrictions。
//
// 兩個標識任一個寫壞都是 1001：這一族路徑不當標識格式探測器（口徑同成員那族路徑）。
func (s *Server) handleMemberRestrictionsUpdate(w http.ResponseWriter, r *http.Request) {
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
	var in updateMemberRestrictionsRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	edit, invalidField, ok := in.toEdit()
	if !ok {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": invalidField})
		return
	}
	updated, err := s.memberRestrictions.UpdateMemberRestrictions(r.Context(), principal,
		activityID, memberID, edit, requestIDFromRequest(r))
	if err != nil {
		s.writeMemberRestrictionFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, memberWriteResponse{
		Member:    memberRow(updated),
		RequestID: requestIDFromRequest(r),
	})
}

// handleOwnMemberRestrictions 處理 GET／HEAD /player/activities/{activity_id}/restrictions。
//
// 這一條是本步唯一「被禁止登入也讀得動」的活動通路：它回答的就是「我被限制的是哪些項」，
// 若同受訪問遮擋，被限制的人就只剩一句無法核實的指控。除此之外它不給出任何別的東西——
// 沒有暱稱、沒有陣營、沒有原因句。
func (s *Server) handleOwnMemberRestrictions(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	member, err := s.memberRestrictions.OwnMemberRestrictions(r.Context(), principal, activityID)
	if err != nil {
		s.writeMemberRestrictionFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, memberRestrictionsResponse{
		ActivityID:          member.ActivityID.String(),
		MemberID:            member.ID.String(),
		RestrictLogin:       member.RestrictLogin,
		RestrictChat:        member.RestrictChat,
		RestrictPrivateChat: member.RestrictPrivateChat,
		RestrictTrade:       member.RestrictTrade,
		RestrictTransfer:    member.RestrictTransfer,
		RestrictItemUse:     member.RestrictItemUse,
		RequestID:           requestIDFromRequest(r),
	})
}

// writeMemberRestrictionFailure 把分項限制兩條通路的錯誤對映為對外回應。
//
// 每一格拒絕各有各的處置：1004 改寫法、2013 重讀現值再決定、2033 等活動重開、
// 2029 這件事已經結束、1001 換個目標（含跨活動與「這個活動不歸你管」的不可分辨收斂）。
// 被拒的寫入不回顯任何一方現值。2043 不在這裡出現——編輯與本人查閱都不是訪問判定點。
func (s *Server) writeMemberRestrictionFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, activity.ErrInvalidRestrictionUpdate):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "restrictions"})
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
	case errors.Is(err, activity.ErrMemberNotFound),
		errors.Is(err, activity.ErrActivityNotFound):
		// 「查無」「屬於另一場活動」與「這個活動不歸你管」收斂成同一句話。
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("處理成員分項限制請求失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}
