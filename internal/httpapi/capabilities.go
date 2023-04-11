// capabilities.go 是「狀態規則與手動限制的組合判定」在傳輸層的落點：
// /admin/activities/{activity_id}/capability-rules 讀寫活動層級的 7×6 狀態能力矩陣，
// /admin/activities/{activity_id}/members/{member_id}/capabilities 讀管理側的來源摘要，
// /player/activities/{activity_id}/capabilities 讀本人此刻的有效能力。
//
// 本檔案只做協議層該做的四件事：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 consolePrincipal 那條共用鏈；
//  2. 首次改密門閂——同一條鏈上的 requirePasswordChangeDone；
//  3. 請求形態——規則替換只認 expected_revision 與七列 rules（每列 status_key 加上
//     denied_capabilities）；其餘兩條是純讀。未知欄位由 decodeJSON 的
//     DisallowUnknownFields 當場拒殺（1004），因此「順手把活動標識、成員標識或
//     別人家的狀態寫進本體」在請求裡沒有格子。
//  4. 結論對映——可判別錯誤一一對映到機器碼，其餘一律 500 且細節只進日誌。
//
// 三份回應的邊界刻意不同：
//   - 規則矩陣是管理面事實：七個內建狀態、六項能力、revision 與「是否配置過」。
//   - 管理側摘要多帶業務狀態、活動狀態、帳戶狀態與逐來源布林，讓操作者能看懂
//     「解除手動後為什麼仍被拒絕」；仍不含審計原因、操作者與時刻。
//   - 玩家側只帶能力鍵、允許／拒絕與來源類別（identity／lifecycle／status／manual）。
//     不帶業務狀態、活動狀態、帳戶狀態或任何逐來源細節；那句話對他的意義是
//     「哪幾項被拒絕、屬於哪一類來源」，不是後台的原因與人員。
//
// 玩家側這一條刻意不經活動訪問門禁：即使 login 被手動限制或狀態規則拒絕，
// 本人仍讀得動自己的有效能力——否則被擋的人只會拿到一句無法核實的拒絕。
// 這與 /player/activities/{id}/restrictions 是同一條批准語意的兩面。
package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/kagurazakayashi/EvernightRealm/internal/activity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// CapabilityUseCase 是能力組合判定在傳輸層的入口形態
// （由 internal/app 注入同一個 *activity.Service 的能力通路）。
//
// 獨立一個依賴欄位（口徑同成員、目錄、標籤、狀態與分項限制的分離理由）：
// 本執行檔沒注入它時一個能力端點都不掛。注意「擋」不依賴這組端點——
// 玩家族其餘通路的訪問判定在服務層現讀，與本依賴是否裝配無關。
type CapabilityUseCase interface {
	// CapabilityRules 讀一個活動的狀態能力矩陣。
	CapabilityRules(ctx context.Context, principal identity.Principal,
		activityID idgen.ID) (activity.CapabilityRuleSet, error)
	// UpdateCapabilityRules 以 revision 比較-and-set 換掉整份矩陣。
	UpdateCapabilityRules(ctx context.Context, principal identity.Principal,
		activityID idgen.ID, edit activity.CapabilityRuleEdit,
		requestID string) (activity.CapabilityRuleSet, error)
	// MemberCapabilities 讀管理側的成員有效能力與來源摘要。
	MemberCapabilities(ctx context.Context, principal identity.Principal,
		activityID, memberID idgen.ID) (activity.CapabilityEvaluation, error)
	// OwnCapabilities 讀本次會話帳戶在本場活動的有效能力（不受訪問門禁遮擋）。
	OwnCapabilities(ctx context.Context, principal identity.Principal,
		activityID idgen.ID) (activity.CapabilityEvaluation, error)
}

// capabilityRuleGroupItem 是一列狀態規則的對外形狀。
//
// denied_capabilities 恆在：空陣列是「這個狀態不拒絕任何能力」的合法現值，
// 不靠欄位缺席表達。能力鍵與狀態鍵都由後端封閉集合校驗，寫壞即 1004。
type capabilityRuleGroupItem struct {
	StatusKey          string   `json:"status_key"`
	DeniedCapabilities []string `json:"denied_capabilities"`
}

// updateCapabilityRulesRequest 是整份矩陣替換的本體。
//
// ExpectedRevision 用指標區分「沒帶」與「帶了 0」：0 是合法的「我認為尚未配置」。
// 請求裡沒有「哪場活動」「誰在做」或任何派生格：那些由路徑與憑據決定。
type updateCapabilityRulesRequest struct {
	ExpectedRevision *int64                    `json:"expected_revision"`
	Rules            []capabilityRuleGroupItem `json:"rules"`
}

// toEdit 把本體換成領域編輯；expected_revision 缺失或為負時點名該欄。
func (in updateCapabilityRulesRequest) toEdit() (activity.CapabilityRuleEdit, string, bool) {
	if in.ExpectedRevision == nil {
		return activity.CapabilityRuleEdit{}, "expected_revision", false
	}
	if *in.ExpectedRevision < 0 {
		return activity.CapabilityRuleEdit{}, "expected_revision", false
	}
	groups := make([]activity.CapabilityRuleGroup, 0, len(in.Rules))
	for _, item := range in.Rules {
		denied := make([]activity.CapabilityKey, 0, len(item.DeniedCapabilities))
		for _, raw := range item.DeniedCapabilities {
			denied = append(denied, activity.CapabilityKey(raw))
		}
		groups = append(groups, activity.CapabilityRuleGroup{
			Status: activity.BusinessStatus(item.StatusKey),
			Denied: denied,
		})
	}
	return activity.CapabilityRuleEdit{ExpectedRevision: *in.ExpectedRevision, Groups: groups},
		"rules", true
}

// capabilityRulesResponse 是矩陣讀寫共用的回應本體。
type capabilityRulesResponse struct {
	ActivityID string `json:"activity_id"`
	// Revision 為 0 表示活動從未配置，rules 是出廠預設。
	Revision int64 `json:"revision"`
	// Configured 把「revision 0＝尚未落地」寫成明確布林，客戶端不必猜 0 的兩種可能。
	Configured bool `json:"configured"`
	// CapabilityKeys 是六項能力鍵的固定順序，供客戶端如實渲染整個矩陣。
	CapabilityKeys []string                  `json:"capability_keys"`
	Rules          []capabilityRuleGroupItem `json:"rules"`
	RequestID      string                    `json:"request_id"`
}

// capabilityDecisionItem 是管理側摘要的一項能力。
type capabilityDecisionItem struct {
	Capability string   `json:"capability"`
	Allowed    bool     `json:"allowed"`
	Sources    []string `json:"sources"`
	// 逐來源布林只出現在管理側；它們讓操作者看懂「解除手動後仍被哪個來源拒絕」。
	ManualDenied    bool `json:"manual_denied"`
	StatusDenied    bool `json:"status_denied"`
	LifecycleDenied bool `json:"lifecycle_denied"`
	IdentityDenied  bool `json:"identity_denied"`
}

// memberCapabilitiesResponse 是管理側成員有效能力與來源摘要。
type memberCapabilitiesResponse struct {
	ActivityID     string                   `json:"activity_id"`
	MemberID       string                   `json:"member_id"`
	BusinessStatus string                   `json:"business_status"`
	ActivityStatus string                   `json:"activity_status"`
	AccountStatus  string                   `json:"account_status"`
	RulesRevision  int64                    `json:"rules_revision"`
	AccessAllowed  bool                     `json:"access_allowed"`
	Capabilities   []capabilityDecisionItem `json:"capabilities"`
	RequestID      string                   `json:"request_id"`
}

// ownCapabilityDecisionItem 是玩家側摘要的一項能力。
//
// 它不帶 manual_denied／status_denied／lifecycle_denied／identity_denied：
// 玩家只需要知道「哪一項被拒絕、屬於哪一類來源」，不需要後台的逐來源細節。
type ownCapabilityDecisionItem struct {
	Capability string   `json:"capability"`
	Allowed    bool     `json:"allowed"`
	Sources    []string `json:"sources"`
}

// ownCapabilitiesResponse 是本人有效能力。
//
// 不帶 business_status、activity_status 或 account_status：那些事實各有自己的
// 讀法，這一條只回答能力與來源類別。access_allowed 是 login 那一項的派生值，
// 讓界面可以直接說「能不能進入」，不必自己在一份清單裡找鍵。
type ownCapabilitiesResponse struct {
	ActivityID    string                      `json:"activity_id"`
	MemberID      string                      `json:"member_id"`
	RulesRevision int64                       `json:"rules_revision"`
	AccessAllowed bool                        `json:"access_allowed"`
	Capabilities  []ownCapabilityDecisionItem `json:"capabilities"`
	RequestID     string                      `json:"request_id"`
}

// capabilityEndpoints 回傳能力端點的登記清單；未注入用例時為空。
func (s *Server) capabilityEndpoints() []apiRoute {
	if s.capabilities == nil {
		return nil
	}
	return []apiRoute{
		{"/admin/activities/{activity_id}/capability-rules",
			s.allowMethods(s.handleCapabilityRules, http.MethodGet, http.MethodHead, http.MethodPut)},
		{"/admin/activities/{activity_id}/members/{member_id}/capabilities",
			s.allowMethods(s.handleMemberCapabilities, http.MethodGet, http.MethodHead)},
		{"/player/activities/{activity_id}/capabilities",
			s.allowMethods(s.handleOwnCapabilities, http.MethodGet, http.MethodHead)},
	}
}

// handleCapabilityRules 依方法分流：GET／HEAD 讀矩陣、PUT 換整份矩陣。
func (s *Server) handleCapabilityRules(w http.ResponseWriter, r *http.Request) {
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
		var in updateCapabilityRulesRequest
		if !decodeJSON(w, r, &in) {
			return
		}
		edit, invalidField, ok := in.toEdit()
		if !ok {
			writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
				map[string]any{"invalid_field": invalidField})
			return
		}
		updated, err := s.capabilities.UpdateCapabilityRules(r.Context(), principal,
			activityID, edit, requestIDFromRequest(r))
		if err != nil {
			s.writeCapabilityFailure(w, r, err, invalidField)
			return
		}
		writeJSON(w, http.StatusOK, capabilityRulesRow(activityID, updated,
			requestIDFromRequest(r)))
		return
	}
	rules, err := s.capabilities.CapabilityRules(r.Context(), principal, activityID)
	if err != nil {
		s.writeCapabilityFailure(w, r, err, "rules")
		return
	}
	writeJSON(w, http.StatusOK, capabilityRulesRow(activityID, rules,
		requestIDFromRequest(r)))
}

// handleMemberCapabilities 處理
// GET／HEAD /admin/activities/{activity_id}/members/{member_id}/capabilities。
func (s *Server) handleMemberCapabilities(w http.ResponseWriter, r *http.Request) {
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
	evaluation, err := s.capabilities.MemberCapabilities(r.Context(), principal,
		activityID, memberID)
	if err != nil {
		s.writeCapabilityFailure(w, r, err, "member")
		return
	}
	items := make([]capabilityDecisionItem, 0, len(evaluation.Decisions))
	for _, decision := range evaluation.Decisions {
		items = append(items, capabilityDecisionItem{
			Capability:      decision.Key.String(),
			Allowed:         decision.Allowed,
			Sources:         capabilitySourceStrings(decision.Sources),
			ManualDenied:    decision.ManualDenied,
			StatusDenied:    decision.StatusDenied,
			LifecycleDenied: decision.LifecycleDenied,
			IdentityDenied:  decision.IdentityDenied,
		})
	}
	writeJSON(w, http.StatusOK, memberCapabilitiesResponse{
		ActivityID:     evaluation.Activity.ID.String(),
		MemberID:       evaluation.Member.ID.String(),
		BusinessStatus: evaluation.Member.BusinessStatus.String(),
		ActivityStatus: evaluation.Activity.Status.String(),
		AccountStatus:  evaluation.AccountStatus.String(),
		RulesRevision:  evaluation.RulesRevision,
		AccessAllowed:  evaluation.AccessAllowed,
		Capabilities:   items,
		RequestID:      requestIDFromRequest(r),
	})
}

// handleOwnCapabilities 處理 GET／HEAD /player/activities/{activity_id}/capabilities。
//
// 這一條是本步「被擋的人也讀得動自己的有效能力」的落點：它不呼叫訪問門禁，
// 也不把業務狀態、活動狀態或帳戶狀態帶出去。查無成員與幽靈活動都是 1001。
func (s *Server) handleOwnCapabilities(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	activityID, err := idgen.Parse(r.PathValue("activity_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	evaluation, err := s.capabilities.OwnCapabilities(r.Context(), principal, activityID)
	if err != nil {
		s.writeCapabilityFailure(w, r, err, "capabilities")
		return
	}
	items := make([]ownCapabilityDecisionItem, 0, len(evaluation.Decisions))
	for _, decision := range evaluation.Decisions {
		items = append(items, ownCapabilityDecisionItem{
			Capability: decision.Key.String(),
			Allowed:    decision.Allowed,
			Sources:    capabilitySourceStrings(decision.Sources),
		})
	}
	writeJSON(w, http.StatusOK, ownCapabilitiesResponse{
		ActivityID:    evaluation.Activity.ID.String(),
		MemberID:      evaluation.Member.ID.String(),
		RulesRevision: evaluation.RulesRevision,
		AccessAllowed: evaluation.AccessAllowed,
		Capabilities:  items,
		RequestID:     requestIDFromRequest(r),
	})
}

// capabilityRulesRow 把領域矩陣換成回應本體。
func capabilityRulesRow(activityID idgen.ID, rules activity.CapabilityRuleSet,
	requestID string) capabilityRulesResponse {
	items := make([]capabilityRuleGroupItem, 0, len(rules.Groups))
	for _, group := range rules.Groups {
		denied := make([]string, 0, len(group.Denied))
		for _, key := range group.Denied {
			denied = append(denied, key.String())
		}
		items = append(items, capabilityRuleGroupItem{
			StatusKey:          group.Status.String(),
			DeniedCapabilities: denied,
		})
	}
	keys := activity.CapabilityKeys()
	capabilityKeys := make([]string, 0, len(keys))
	for _, key := range keys {
		capabilityKeys = append(capabilityKeys, key.String())
	}
	return capabilityRulesResponse{
		ActivityID:     activityID.String(),
		Revision:       rules.Revision,
		Configured:     rules.Revision > 0,
		CapabilityKeys: capabilityKeys,
		Rules:          items,
		RequestID:      requestID,
	}
}

// capabilitySourceStrings 把來源類別換成 JSON 字串切片；空來源回空切片而不是 nil。
func capabilitySourceStrings(sources []activity.CapabilitySource) []string {
	out := make([]string, 0, len(sources))
	for _, source := range sources {
		out = append(out, source.String())
	}
	return out
}

// writeCapabilityFailure 把能力端點的錯誤對映為對外回應。
//
// 1004 改寫法（invalidField 點名是 expected_revision、rules 還是 member）、
// 2013 重讀 revision 再決定、2029 這件事已結束、1001 換個目標；
// 其餘交給活動端點的共用對映（2011、未知故障）。被拒的替換不回顯任何現值。
func (s *Server) writeCapabilityFailure(w http.ResponseWriter, r *http.Request,
	err error, invalidField string) {
	switch {
	case errors.Is(err, activity.ErrInvalidCapabilityRules):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": invalidField})
		return
	case errors.Is(err, activity.ErrCapabilityRulesConflict):
		writeError(w, r, CodeProfileConflict, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrArchived):
		writeError(w, r, CodeActivityArchived, http.StatusConflict)
		return
	case errors.Is(err, activity.ErrMemberNotFound), errors.Is(err, activity.ErrActivityNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if s.writeActivityCommonFailures(w, r, err) {
		return
	}
	s.logger.Error("處理能力組合判定請求失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}
