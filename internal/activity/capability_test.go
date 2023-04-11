// capability_test.go 是「業務狀態規則與手動限制的組合判定」在服務層的證據。
//
// 本檔逐格取證用戶批准的五條組合規則：
//   - 逐能力獨立：login 被拒絕不改寫其餘五項；
//   - 各來源拒絕優先：狀態與手動同時拒絕時兩個來源都列出，解除一項仍受另一項限制；
//   - 切換狀態只改變狀態來源：手動限制逐欄保留；
//   - 規則更新後的下一筆請求按新 revision 回答，跨活動互不相干；
//   - 生命週期拒絕五項業務能力但不拒絕查看，且歸檔不會被規則編輯器覆蓋；
//   - 身份資格是前置拒絕（帳戶停用時所有能力拒絕）。
//
// 刻意不收的東西：
//   - 沒有替身：授權、門禁、CAS 與審計都走真路徑（真資料庫＋注入時鐘）；
//   - 不測協定層（欄位注入 1004、機器碼 2044 對映、玩家回應的欄位白名單）：
//     那是 internal/httpapi 的端點證據；
//   - 不測聊天／交易等業務效果：那些業務尚未實現，本檔只取證判定結果與來源。
package activity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// capabilityGroupsWith 回傳一份「某個狀態拒絕指定能力」的完整七列矩陣。
func capabilityGroupsWith(status BusinessStatus, denied ...CapabilityKey) []CapabilityRuleGroup {
	groups := DefaultCapabilityRuleGroups()
	for i := range groups {
		if groups[i].Status == status {
			groups[i].Denied = append([]CapabilityKey(nil), denied...)
		}
	}
	return groups
}

// mustUpdateCapabilityRules 送一次必須成功的矩陣替換。
func (e *env) mustUpdateCapabilityRules(t *testing.T, principal identity.Principal,
	activityID idgen.ID, expectedRevision int64, groups []CapabilityRuleGroup) CapabilityRuleSet {
	t.Helper()
	updated, err := e.service.UpdateCapabilityRules(context.Background(), principal, activityID,
		CapabilityRuleEdit{ExpectedRevision: expectedRevision, Groups: groups},
		"req-capability-rules")
	if err != nil {
		t.Fatalf("替換狀態能力規則應成功：%v", err)
	}
	return updated
}

// ownCapabilities 讀本人在主場活動的有效能力。
func (s *restrictionScene) ownCapabilities(t *testing.T) CapabilityEvaluation {
	t.Helper()
	evaluation, err := s.e.service.OwnCapabilities(context.Background(), s.player,
		s.activity.ID)
	if err != nil {
		t.Fatalf("讀本人有效能力應成功：%v", err)
	}
	return evaluation
}

// mustCapabilityDecision 取出某一項能力的結論。
func mustCapabilityDecision(t *testing.T, evaluation CapabilityEvaluation,
	key CapabilityKey) CapabilityDecision {
	t.Helper()
	decision, ok := evaluation.Decision(key)
	if !ok {
		t.Fatalf("有效能力結果缺少 %q", key.String())
	}
	return decision
}

// sourceList 把來源換成可比對的字串（固定順序）。
func sourceList(decision CapabilityDecision) string {
	parts := make([]string, 0, len(decision.Sources))
	for _, source := range decision.Sources {
		parts = append(parts, source.String())
	}
	return strings.Join(parts, ",")
}

// mustDeniedBy 斷言某項能力被拒絕且來源逐字等於 expected。
func mustDeniedBy(t *testing.T, evaluation CapabilityEvaluation, key CapabilityKey,
	expected string) {
	t.Helper()
	decision := mustCapabilityDecision(t, evaluation, key)
	if decision.Allowed {
		t.Fatalf("%q 應被拒絕，實際允許（來源 %s）", key.String(), sourceList(decision))
	}
	if got := sourceList(decision); got != expected {
		t.Fatalf("%q 的拒絕來源應是 %q，實際 %q", key.String(), expected, got)
	}
}

// mustAllowed 斷言某項能力允許且沒有來源。
func mustAllowed(t *testing.T, evaluation CapabilityEvaluation, key CapabilityKey) {
	t.Helper()
	decision := mustCapabilityDecision(t, evaluation, key)
	if !decision.Allowed || len(decision.Sources) != 0 {
		t.Fatalf("%q 應允許且無來源，實際 allowed=%v sources=%s",
			key.String(), decision.Allowed, sourceList(decision))
	}
}

// latestCapabilityRuleAudit 讀規則替換最新一筆活動域留痕。
//
// 它按 id 倒序而不是時刻倒序：注入時鐘在同一毫秒內落多筆時，
// 「最新一筆」必須由 UUIDv7 的時間性標識自己排（口徑同 UNIQUE 破平的理由）。
func (e *env) latestCapabilityRuleAudit(t *testing.T, activityID string) memberAuditRow {
	t.Helper()
	var row memberAuditRow
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT actor_kind,
			COALESCE(actor_id, ''), reason, changes_json
		FROM activity_audit WHERE action = 'activity.capability_rules_update'
			AND activity_id = ?
		ORDER BY id DESC LIMIT 1`, activityID).
		Scan(&row.actorKind, &row.actorID, &row.reason, &row.changes)
	if err != nil {
		t.Fatalf("讀取規則替換留痕失敗：%v", err)
	}
	return row
}

// TestCapabilityDefaultMatrixAndManualCombination 驗收：
// 出廠 normal 全允許；手動 restrict_login 只拒絕 login，其餘五項仍是允許；
// dead 的狀態來源只拒絕五項業務能力、不拒絕查看；手動與狀態並列，解除一種不覆蓋另一種；
// 切換狀態只改變狀態來源，手動旗標逐欄保留。
func TestCapabilityDefaultMatrixAndManualCombination(t *testing.T) {
	s := newRestrictionScene(t, "Capability.Combine")
	e := s.e
	ctx := context.Background()

	// 出廠：normal、沒有手動限制、活動是草稿（生命週期不拒絕業務能力）。
	initial := s.ownCapabilities(t)
	if !initial.AccessAllowed || initial.RulesRevision != 0 {
		t.Fatalf("出廠應可進入且規則版本為 0，實際 access=%v revision=%d",
			initial.AccessAllowed, initial.RulesRevision)
	}
	for _, key := range CapabilityKeys() {
		mustAllowed(t, initial, key)
	}

	// Normal + 手動 restrict_login：逐能力獨立——login 拒絕，其餘五項仍是允許。
	s.setLogin(t, true)
	frozen := s.ownCapabilities(t)
	if frozen.AccessAllowed {
		t.Fatalf("手動 restrict_login 之後 access_allowed 應為假")
	}
	mustDeniedBy(t, frozen, RestrictionLogin, "manual")
	for _, key := range []CapabilityKey{
		RestrictionChat, RestrictionPrivateChat, RestrictionTrade,
		RestrictionTransfer, RestrictionItemUse,
	} {
		mustAllowed(t, frozen, key)
	}
	if _, err := e.service.EnsureMemberActivityAccess(ctx, e.db.SQL(),
		s.activity.ID, s.member.AccountID); !errors.Is(err, ErrMemberAccessRestricted) {
		t.Fatalf("手動凍結時訪問判定應回 ErrMemberAccessRestricted，實際 %v", err)
	}

	// 手動只凍結 login，再把狀態改成 dead：login 仍被手動拒絕，
	// 五項業務能力被狀態拒絕；切換狀態沒有清掉手動旗標。
	s.setLogin(t, false)
	if _, err := e.service.EnsureMemberActivityAccess(ctx, e.db.SQL(),
		s.activity.ID, s.member.AccountID); err != nil {
		t.Fatalf("解除手動後訪問判定應放行，實際 %v", err)
	}
	e.mustSetMemberStatus(t, s.admin, s.activity.ID, s.member.ID,
		BusinessStatusDead, idgen.Nil, BusinessStatusNormal, idgen.Nil)
	dead := s.ownCapabilities(t)
	mustAllowed(t, dead, RestrictionLogin)
	for _, key := range []CapabilityKey{
		RestrictionChat, RestrictionPrivateChat, RestrictionTrade,
		RestrictionTransfer, RestrictionItemUse,
	} {
		mustDeniedBy(t, dead, key, "status")
	}

	// Dead + 手動 login：兩個來源並列；login 以手動為對外優先（2043），
	// 但能力摘要仍只列出真正拒絕 login 的 manual（dead 不拒絕 login）。
	s.setLogin(t, true)
	both := s.ownCapabilities(t)
	mustDeniedBy(t, both, RestrictionLogin, "manual")
	if _, err := e.service.EnsureMemberActivityAccess(ctx, e.db.SQL(),
		s.activity.ID, s.member.AccountID); !errors.Is(err, ErrMemberAccessRestricted) {
		t.Fatalf("手動與狀態同時拒絕 login 時應先回手動那一句，實際 %v", err)
	}

	// Dead → Normal：狀態來源清空，手動 login 原樣保留——不會顯示「已解凍」。
	e.mustSetMemberStatus(t, s.admin, s.activity.ID, s.member.ID,
		BusinessStatusNormal, idgen.Nil, BusinessStatusDead, idgen.Nil)
	after := s.ownCapabilities(t)
	if after.AccessAllowed {
		t.Fatalf("狀態改回 normal 後，手動 login 仍應拒絕進入")
	}
	mustDeniedBy(t, after, RestrictionLogin, "manual")
	for _, key := range []CapabilityKey{
		RestrictionChat, RestrictionPrivateChat, RestrictionTrade,
		RestrictionTransfer, RestrictionItemUse,
	} {
		mustAllowed(t, after, key)
	}
}

// TestCapabilityMultiSourceLiftingOneKeepsTheOther 驗收：
// 手動與狀態同時拒絕同一項時兩個來源都列出；解除手動後仍被狀態拒絕，
// 不會顯示成「已解除」；再切回 normal 才放行。
func TestCapabilityMultiSourceLiftingOneKeepsTheOther(t *testing.T) {
	s := newRestrictionScene(t, "Capability.MultiSource")
	e := s.e

	// arrested 出廠拒絕交易、轉賬與使用物品；再手動拒絕交易。
	e.mustSetMemberStatus(t, s.admin, s.activity.ID, s.member.ID,
		BusinessStatusArrested, idgen.Nil, BusinessStatusNormal, idgen.Nil)
	e.mustRestrict(t, s.admin, s.activity.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionTrade, Value: true, Expected: false}))

	both := s.ownCapabilities(t)
	mustDeniedBy(t, both, RestrictionTrade, "status,manual")
	mustDeniedBy(t, both, RestrictionTransfer, "status")
	mustDeniedBy(t, both, RestrictionItemUse, "status")
	mustAllowed(t, both, RestrictionLogin)
	mustAllowed(t, both, RestrictionChat)
	mustAllowed(t, both, RestrictionPrivateChat)

	// 只解除手動交易：交易仍被狀態拒絕——「已解凍」不是事實。
	e.mustRestrict(t, s.admin, s.activity.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionTrade, Value: false, Expected: true}))
	still := s.ownCapabilities(t)
	mustDeniedBy(t, still, RestrictionTrade, "status")

	// 狀態切回 normal 之後才允許；手動旗標已是 false，沒有殘留。
	e.mustSetMemberStatus(t, s.admin, s.activity.ID, s.member.ID,
		BusinessStatusNormal, idgen.Nil, BusinessStatusArrested, idgen.Nil)
	final := s.ownCapabilities(t)
	mustAllowed(t, final, RestrictionTrade)
	mustAllowed(t, final, RestrictionTransfer)
	mustAllowed(t, final, RestrictionItemUse)
}

// TestCapabilityRulesRevisionAndNextRequest 驗收：
// 規則替換以 revision 比較-and-set；更新後的下一筆請求按新值回答；
// 舊 revision 落敗且不覆蓋贏家；冪等重送不推進版本、不追加審計；
// 自訂狀態那一列不得拒絕能力；跨活動規則互不相干。
func TestCapabilityRulesRevisionAndNextRequest(t *testing.T) {
	s := newRestrictionScene(t, "Capability.Rules")
	e := s.e
	ctx := context.Background()

	// 出廠：主場與另一場都是 revision 0、預設矩陣。
	current, err := e.service.CapabilityRules(ctx, s.admin, s.activity.ID)
	if err != nil || current.Revision != 0 {
		t.Fatalf("出廠規則應是 revision 0：%v（%d）", err, current.Revision)
	}
	other, err := e.service.CapabilityRules(ctx, s.admin, s.other.ID)
	if err != nil || other.Revision != 0 {
		t.Fatalf("另一場出廠規則應是 revision 0：%v（%d）", err, other.Revision)
	}

	// normal 拒絕 chat：下一筆請求就是新結論，另一場照舊。
	updated := e.mustUpdateCapabilityRules(t, s.admin, s.activity.ID, 0,
		capabilityGroupsWith(BusinessStatusNormal, RestrictionChat))
	if updated.Revision != 1 {
		t.Fatalf("第一次替換後 revision 應是 1，實際 %d", updated.Revision)
	}
	next := s.ownCapabilities(t)
	if next.RulesRevision != 1 {
		t.Fatalf("下一筆請求應讀到 revision 1，實際 %d", next.RulesRevision)
	}
	mustDeniedBy(t, next, RestrictionChat, "status")
	mustAllowed(t, next, RestrictionPrivateChat)

	otherEval, err := e.service.OwnCapabilities(ctx, s.player, s.other.ID)
	if err != nil {
		t.Fatalf("讀另一場有效能力失敗：%v", err)
	}
	if otherEval.RulesRevision != 0 {
		t.Fatalf("另一場不該讀到主場的規則版本，實際 %d", otherEval.RulesRevision)
	}
	mustAllowed(t, otherEval, RestrictionChat)

	// 第二次替換：normal 同時拒絕 chat 與 private_chat，revision 2。
	updated = e.mustUpdateCapabilityRules(t, s.admin, s.activity.ID, 1,
		capabilityGroupsWith(BusinessStatusNormal, RestrictionChat, RestrictionPrivateChat))
	if updated.Revision != 2 {
		t.Fatalf("第二次替換後 revision 應是 2，實際 %d", updated.Revision)
	}
	next = s.ownCapabilities(t)
	mustDeniedBy(t, next, RestrictionChat, "status")
	mustDeniedBy(t, next, RestrictionPrivateChat, "status")

	// 拿舊 revision 1 再送：落敗，不覆蓋 revision 2 的贏家。
	_, err = e.service.UpdateCapabilityRules(ctx, s.admin, s.activity.ID,
		CapabilityRuleEdit{ExpectedRevision: 1,
			Groups: capabilityGroupsWith(BusinessStatusNormal)},
		"req-capability-stale")
	if !errors.Is(err, ErrCapabilityRulesConflict) {
		t.Fatalf("舊 revision 應回衝突，實際 %v", err)
	}
	afterStale, err := e.service.CapabilityRules(ctx, s.admin, s.activity.ID)
	if err != nil || afterStale.Revision != 2 || !afterStale.Denied(BusinessStatusNormal, RestrictionChat) {
		t.Fatalf("落敗的替換不該改動贏家：%v（%+v）", err, afterStale)
	}

	// 冪等重送：相同矩陣、相同 revision → 不推進版本、不追加審計。
	auditBefore := e.countAuditRows(t, "activity.capability_rules_update", s.activity.ID.String())
	replay := e.mustUpdateCapabilityRules(t, s.admin, s.activity.ID, 2,
		capabilityGroupsWith(BusinessStatusNormal, RestrictionChat, RestrictionPrivateChat))
	if replay.Revision != 2 {
		t.Fatalf("冪等重送不該推進版本，實際 %d", replay.Revision)
	}
	if got := e.countAuditRows(t, "activity.capability_rules_update",
		s.activity.ID.String()); got != auditBefore {
		t.Fatalf("冪等重送不該追加審計，實際 %d 筆（原 %d）", got, auditBefore)
	}

	// 非冪等替換留痕帶操作者與實際翻動的格。
	_ = e.mustUpdateCapabilityRules(t, s.admin, s.activity.ID, 2,
		capabilityGroupsWith(BusinessStatusNormal))
	row := e.latestCapabilityRuleAudit(t, s.activity.ID.String())
	if row.actorKind == "" || row.actorID == "" {
		t.Errorf("規則替換審計必須帶操作者，實際 %+v", row)
	}
	if !strings.Contains(row.changes, "capability_rules.normal.chat") ||
		!strings.Contains(row.changes, "capability_rules.normal.private_chat") {
		t.Errorf("規則替換審計應逐格帶出翻動欄位，實際 %s", row.changes)
	}
	if strings.Contains(row.changes, "member.restrict") {
		t.Errorf("規則替換審計不該混入手動限制，實際 %s", row.changes)
	}

	// 自訂狀態不參與矩陣：custom 那一列拒絕任何能力都是請求寫法錯誤。
	_, err = e.service.UpdateCapabilityRules(ctx, s.admin, s.activity.ID,
		CapabilityRuleEdit{ExpectedRevision: 3,
			Groups: capabilityGroupsWith(BusinessStatusCustom, RestrictionChat)},
		"req-capability-custom")
	if !errors.Is(err, ErrInvalidCapabilityRules) {
		t.Fatalf("custom 列拒絕能力應被拒，實際 %v", err)
	}

	// 自訂定義的成員狀態不因名稱得到任何封鎖：custom 列全允許。
	definition := e.mustCreateCustomStatus(t, s.admin, s.activity.ID, "負傷")
	e.mustSetMemberStatus(t, s.admin, s.activity.ID, s.member.ID,
		BusinessStatusCustom, definition.ID, BusinessStatusNormal, idgen.Nil)
	customEval := s.ownCapabilities(t)
	for _, key := range CapabilityKeys() {
		mustAllowed(t, customEval, key)
	}
}

// TestCapabilityLifecycleAndIdentity 驗收：
// 停止與歸檔只拒絕五項業務能力、不拒絕查看；歸檔拒寫規則；
// 帳戶停用是前置身份來源，拒絕所有能力。
func TestCapabilityLifecycleAndIdentity(t *testing.T) {
	s := newRestrictionScene(t, "Capability.Lifecycle")
	e := s.e
	ctx := context.Background()

	// 草稿→開放：全部允許；開放→停止：login 仍允許，五項業務被生命週期拒絕。
	if _, err := e.service.Transition(ctx, s.admin, s.activity.ID, StatusActive,
		"req-active"); err != nil {
		t.Fatalf("開放活動失敗：%v", err)
	}
	activeEval := s.ownCapabilities(t)
	for _, key := range CapabilityKeys() {
		mustAllowed(t, activeEval, key)
	}
	if _, err := e.service.Transition(ctx, s.admin, s.activity.ID, StatusClosed,
		"req-closed"); err != nil {
		t.Fatalf("停止活動失敗：%v", err)
	}
	closed := s.ownCapabilities(t)
	mustAllowed(t, closed, RestrictionLogin)
	for _, key := range []CapabilityKey{
		RestrictionChat, RestrictionPrivateChat, RestrictionTrade,
		RestrictionTransfer, RestrictionItemUse,
	} {
		mustDeniedBy(t, closed, key, "lifecycle")
	}
	if _, err := e.service.EnsureMemberCapability(ctx, e.db.SQL(), s.activity.ID,
		s.member.AccountID, RestrictionChat); !errors.Is(err, ErrMemberCapabilityRestricted) {
		t.Fatalf("停止態的聊天能力應被生命週期拒絕，實際 %v", err)
	} else {
		var typed *MemberCapabilityRestrictedError
		if !errors.As(err, &typed) || len(typed.Sources) != 1 ||
			typed.Sources[0] != CapabilitySourceLifecycle {
			t.Fatalf("型別錯誤應帶生命週期來源，實際 %+v", typed)
		}
	}
	// 停止態仍可準備規則；歸檔後拒寫，但讀法與本人摘要照舊。
	_ = e.mustUpdateCapabilityRules(t, s.admin, s.activity.ID, 0,
		capabilityGroupsWith(BusinessStatusArrested, RestrictionChat))
	if _, err := e.service.Transition(ctx, s.admin, s.activity.ID, StatusArchived,
		"req-archived"); err != nil {
		t.Fatalf("歸檔活動失敗：%v", err)
	}
	archived := s.ownCapabilities(t)
	mustAllowed(t, archived, RestrictionLogin)
	mustDeniedBy(t, archived, RestrictionChat, "lifecycle")
	if _, err := e.service.UpdateCapabilityRules(ctx, s.admin, s.activity.ID,
		CapabilityRuleEdit{ExpectedRevision: 1,
			Groups: capabilityGroupsWith(BusinessStatusNormal)}, "req-archived-rules"); !errors.Is(err, ErrArchived) {
		t.Fatalf("歸檔後替換規則應回 ErrArchived，實際 %v", err)
	}
	if rules, err := e.service.CapabilityRules(ctx, s.admin, s.activity.ID); err != nil ||
		rules.Revision != 1 {
		t.Fatalf("歸檔後仍應讀得到規則現值：%v（%+v）", err, rules)
	}

	// 身份資格：把成員的帳戶停用，管理側摘要應把 identity 列為所有能力的來源。
	if changed, err := e.accounts.SetStatus(ctx, e.db.SQL(), s.member.AccountID,
		account.StatusDisabled, account.StatusActive); err != nil || !changed {
		t.Fatalf("停用成員帳戶失敗：%v（%t）", err, changed)
	}
	evaluation, err := e.service.MemberCapabilities(ctx, s.admin, s.activity.ID, s.member.ID)
	if err != nil {
		t.Fatalf("讀管理側來源摘要失敗：%v", err)
	}
	if evaluation.AccountStatus != account.StatusDisabled {
		t.Fatalf("摘要應帶帳戶現值 disabled，實際 %q", evaluation.AccountStatus.String())
	}
	for _, key := range CapabilityKeys() {
		decision := mustCapabilityDecision(t, evaluation, key)
		if decision.Allowed || !decision.IdentityDenied {
			t.Fatalf("%q 在帳戶停用時應被 identity 拒絕，實際 %+v", key.String(), decision)
		}
		if !strings.Contains(sourceList(decision), string(CapabilitySourceIdentity)) {
			t.Fatalf("%q 的來源應包含 identity，實際 %s", key.String(), sourceList(decision))
		}
	}
	if _, err := e.service.EnsureMemberCapability(ctx, e.db.SQL(), s.activity.ID,
		s.member.AccountID, RestrictionLogin); !errors.Is(err, ErrMemberIdentityInvalid) {
		t.Fatalf("帳戶停用時能力判定應回身份失效，實際 %v", err)
	}
}
