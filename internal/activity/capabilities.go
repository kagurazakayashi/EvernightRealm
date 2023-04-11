// capabilities.go 是「業務狀態規則與手動限制的組合判定」的用例層：
// 活動層級矩陣的讀寫、管理側的成員來源摘要、玩家本人的有效能力，以及把四個來源
// 合成同一個結果的單一判定入口。
//
// 這一層把用戶批准的組合規則凝成同一條通路：
//   - 逐能力獨立：login 被拒絕不會改寫其餘五項；每一項只回答自己的來源。
//   - 各來源拒絕優先：identity、lifecycle、status、manual 並列，任何一個拒絕即拒絕；
//     解除一個不覆蓋另一個。
//   - 身份資格是前置來源：帳戶失效或成員行讀不到時所有能力拒絕；玩家側通路在
//     讀不到成員行時仍先收斂成 ErrMemberNotFound，不讓限制變成存在性探測器。
//   - 生命週期只拒絕五項業務能力，不拒絕 login：停止與歸檔仍可查看；
//     它永遠不由狀態規則編輯器改寫。
//   - 狀態只增加禁止項：矩陣只回答「這個狀態拒絕哪幾項」，不回答「允許哪幾項」，
//     也不放寬手動限制、生命週期或身份資格；沒有管理員豁免。
//   - 每次判定都現讀活動、成員、規則與帳戶，沒有任何進程內快取；回應帶規則
//     revision，編輯以 expected_revision 做比較-and-set。倉庫沒有實時層，
//     「下一筆請求按現值回答」就是全部的失效形態。
//
// 自訂業務狀態不參與矩陣：它的名稱由管理員自由填寫，讓名稱參與能力判定等於
// 從名字推測行為。`custom` 那一列在出廠與本步的所有編輯裡都不拒絕任何能力，
// 服務層也不接受自訂定義成為規則鍵。
package activity

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// CapabilityRules 以當前受信主體讀一個活動的狀態能力矩陣。
//
// 它是管理面讀法：停止與歸檔的活動照樣可讀，因為「這場活動當時的規則」是歷史事實。
// 讀不到版本行時回出廠預設與 revision 0；任何不完整的持久事實都如實報錯，
// 不降級成「缺席即允許」。
func (s *Service) CapabilityRules(ctx context.Context, principal identity.Principal,
	activityID idgen.ID) (CapabilityRuleSet, error) {
	q := s.db.SQL()
	if err := s.requireActivityScope(ctx, q, principal, activityID,
		"capability_rules_read"); err != nil {
		return CapabilityRuleSet{}, err
	}
	if _, err := s.readActivity(ctx, q, activityID); err != nil {
		return CapabilityRuleSet{}, err
	}
	rules, err := s.store.CapabilityRuleSet(ctx, q, activityID)
	if err != nil {
		s.log.Error("讀取狀態能力規則失敗", "activity", activityID.String(), "err", err)
		return CapabilityRuleSet{}, fmt.Errorf("activity: 讀取狀態能力規則失敗: %w", err)
	}
	return rules, nil
}

// UpdateCapabilityRules 以比較-and-set 換掉一個活動的整份狀態能力矩陣。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 域校驗（在寫之前）：恰好七列、狀態鍵在內建集合內且不重複、能力鍵合法且不重複；
//  2. 交易內判定活動作用域（NeedServerAdmin 加上這個活動的一行指派）；
//  3. 交易內讀活動現值並核實它還沒歸檔（停止態仍可準備規則）；
//  4. 交易內現讀現值並核實 expected_revision 相符（不符即整個替換不落）；
//  5. 新矩陣與現值逐格相同時視為冪等成功：不寫入、不追加審計；
//  6. 帶版本條件的替換：42 格一起換，落敗的那一次連一格都不動；
//  7. 同一交易內追加活動域審計，changes 只帶實際翻動的格。
//
// 這條通路只改狀態來源；手動限制仍在成員行、生命週期仍在活動、身份資格仍來自帳戶，
// 三者都不會被這份矩陣覆蓋。被拒的替換不追加審計。
func (s *Service) UpdateCapabilityRules(ctx context.Context, principal identity.Principal,
	activityID idgen.ID, edit CapabilityRuleEdit, requestID string) (CapabilityRuleSet, error) {
	groups, err := ValidateCapabilityRuleEdit(edit)
	if err != nil {
		return CapabilityRuleSet{}, err
	}

	var updated CapabilityRuleSet
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID,
			"capability_rules_update"); err != nil {
			return err
		}
		beforeActivity, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		if err := requireNotArchived(beforeActivity); err != nil {
			return err
		}
		current, err := s.store.CapabilityRuleSet(tctx, tx, activityID)
		if err != nil {
			return err
		}
		if current.Revision != edit.ExpectedRevision {
			return ErrCapabilityRulesConflict
		}
		if sameCapabilityRuleGroups(current.Groups, groups) {
			// 冪等重送：不寫入、不追加審計。revision 不推進——沒有發生任何改動。
			updated = current
			return nil
		}
		nextRevision, changed, err := s.store.ReplaceCapabilityRuleSet(tctx, tx,
			activityID, edit.ExpectedRevision, groups)
		if err != nil {
			return err
		}
		if !changed {
			return ErrCapabilityRulesConflict
		}
		updated = CapabilityRuleSet{Revision: nextRevision, Groups: cloneCapabilityRuleGroups(groups)}
		changes := capabilityRuleChanges(current.Groups, groups)
		rec, err := s.activityRecord(principal, activityID, "activity.capability_rules_update",
			"activity", activityID.String(), capabilityRuleEditReason(), requestID, changes...)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidCapabilityRules), errors.Is(err, ErrCapabilityRulesConflict),
			errors.Is(err, ErrActivityNotFound), errors.Is(err, ErrArchived),
			errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return CapabilityRuleSet{}, err
		}
		s.log.Error("變更狀態能力規則失敗", "request_id", requestID, "err", err)
		return CapabilityRuleSet{}, fmt.Errorf("activity: 變更狀態能力規則失敗: %w", err)
	}
	s.log.Info("已變更狀態能力規則",
		"activity", activityID.String(), "revision", updated.Revision, "request_id", requestID)
	return updated, nil
}

// MemberCapabilities 以管理面的成員標識讀回一行的有效能力與來源摘要。
//
// 它是派生讀法：成員行、業務狀態規則、活動生命週期與帳戶狀態各自現讀一次，
// 再按同一套組合規則合成。停止與歸檔的活動照樣可讀（來源摘要仍是歷史事實）。
// 查無成員、跨活動與活動不在可見範圍一律收斂成 ErrMemberNotFound 或
// ErrActivityNotFound，不新增可列舉的差異。
func (s *Service) MemberCapabilities(ctx context.Context, principal identity.Principal,
	activityID, memberID idgen.ID) (CapabilityEvaluation, error) {
	q := s.db.SQL()
	if err := s.requireActivityScope(ctx, q, principal, activityID,
		"member_capability_summary"); err != nil {
		return CapabilityEvaluation{}, err
	}
	a, err := s.readActivity(ctx, q, activityID)
	if err != nil {
		return CapabilityEvaluation{}, err
	}
	member, err := s.store.MemberByID(ctx, q, memberID)
	if err != nil {
		return CapabilityEvaluation{}, err
	}
	if member.ActivityID != activityID {
		// 跨活動與從未存在收斂成同一句話（口徑同成員編輯）。
		return CapabilityEvaluation{}, ErrMemberNotFound
	}
	return s.evaluateCapabilitySet(ctx, q, a, member)
}

// OwnCapabilities 讀回「本次會話帳戶在那場活動裡的有效能力」。
//
// 它是批准語意裡「本人獲准查看有效結果」的延伸：即使 login 被手動限制或
// 業務狀態規則拒絕，這一條仍讀得動——否則被擋的人只會拿到一句無法核實的拒絕。
// 主體由會話決定，路徑與本體都沒有「哪個玩家」的格子；查無成員與幽靈活動
// 同收斂成 ErrMemberNotFound（1001），不先回答被限制（那會變成存在性探測器）。
func (s *Service) OwnCapabilities(ctx context.Context, principal identity.Principal,
	activityID idgen.ID) (CapabilityEvaluation, error) {
	accountID, err := s.requireSelfPrincipal(principal, "own_capabilities")
	if err != nil {
		return CapabilityEvaluation{}, err
	}
	q := s.db.SQL()
	member, err := s.store.MemberByAccount(ctx, q, activityID, accountID)
	if err != nil {
		return CapabilityEvaluation{}, err
	}
	a, err := s.readActivity(ctx, q, member.ActivityID)
	if err != nil {
		return CapabilityEvaluation{}, err
	}
	return s.evaluateCapabilitySet(ctx, q, a, member)
}

// evaluateCapabilitySet 是四個來源合成同一個結果的唯一實作。
//
// q 由呼叫端給（autocommit 連線或交易）：管理側摘要用 autocommit；
// 將來的業務通路必須在自己的寫入交易內呼叫 EnsureMemberCapability，
// 兩者讀到的都是同一份現值。判定順序不是優先級——四個來源並列記錄，
// 只有「手動限制先於狀態限制對外發碼」那一點是已批准的對外顺序（2043 先於 2044）。
func (s *Service) evaluateCapabilitySet(ctx context.Context, q database.Querier,
	a Activity, member Member) (CapabilityEvaluation, error) {
	if !member.BusinessStatus.valid() {
		return CapabilityEvaluation{}, fmt.Errorf(
			"capability: 成員 %s 的業務狀態 %q 不在內建集合內",
			member.ID.String(), member.BusinessStatus.String())
	}
	rules, err := s.store.CapabilityRuleSet(ctx, q, a.ID)
	if err != nil {
		s.log.Error("讀取狀態能力規則失敗", "activity", a.ID.String(), "err", err)
		return CapabilityEvaluation{}, fmt.Errorf("activity: 讀取狀態能力規則失敗: %w", err)
	}

	identityDenied := false
	accountStatus := account.Status("")
	acct, err := s.accounts.ByID(ctx, q, member.AccountID)
	if err != nil {
		if !errors.Is(err, account.ErrNotFound) {
			return CapabilityEvaluation{}, err
		}
		// 軟參照指向的帳戶行被物理清理：身份資格失效，如實記為來源而不是猜一個狀態。
		identityDenied = true
	} else {
		accountStatus = acct.Status
		switch acct.Type {
		case account.TypeStandard, account.TypeGuest:
		default:
			identityDenied = true
		}
		if acct.Status != account.StatusActive {
			identityDenied = true
		}
	}

	decisions := make([]CapabilityDecision, 0, len(memberRestrictionKeys))
	for _, key := range memberRestrictionKeys {
		manualDenied, ok := member.RestrictionValue(key)
		if !ok {
			return CapabilityEvaluation{}, fmt.Errorf(
				"capability: 能力鍵 %q 在成員行上讀不到對應欄位", key.String())
		}
		statusDenied := rules.Denied(member.BusinessStatus, key)
		// 生命週期只拒絕五項業務能力：停止與歸檔仍可查看，login 不在它的作用範圍。
		lifecycleDenied := key != RestrictionLogin && !a.Status.AllowsBusinessWrites()
		sources := make([]CapabilitySource, 0, len(capabilitySourceOrder))
		if identityDenied {
			sources = append(sources, CapabilitySourceIdentity)
		}
		if lifecycleDenied {
			sources = append(sources, CapabilitySourceLifecycle)
		}
		if statusDenied {
			sources = append(sources, CapabilitySourceStatus)
		}
		if manualDenied {
			sources = append(sources, CapabilitySourceManual)
		}
		decisions = append(decisions, CapabilityDecision{
			Key:             key,
			Allowed:         len(sources) == 0,
			Sources:         sources,
			ManualDenied:    manualDenied,
			StatusDenied:    statusDenied,
			LifecycleDenied: lifecycleDenied,
			IdentityDenied:  identityDenied,
		})
	}
	evaluation := CapabilityEvaluation{
		Activity:      a,
		Member:        member,
		AccountStatus: accountStatus,
		RulesRevision: rules.Revision,
		Decisions:     decisions,
	}
	for _, decision := range decisions {
		if decision.Key == RestrictionLogin {
			evaluation.AccessAllowed = decision.Allowed
			break
		}
	}
	return evaluation, nil
}

// capabilityRuleChanges 列出兩份矩陣之間實際翻動的格（供審計 changes）。
//
// 只列翻動的格：一份 42 格全都重寫成相同值的提交在服務層已被判成冪等，
// 不會走到這裡；走到這裡的每一格都是真的變了。欄位名由兩個封閉集合派生，
// 請求字串到不了這裡。
func capabilityRuleChanges(before, after []CapabilityRuleGroup) []audit.Change {
	beforeSet := CapabilityRuleSet{Groups: before}
	afterSet := CapabilityRuleSet{Groups: after}
	changes := make([]audit.Change, 0, capabilityRuleCellCount)
	for _, status := range builtinBusinessStatuses {
		for _, key := range memberRestrictionKeys {
			was := beforeSet.Denied(status, key)
			now := afterSet.Denied(status, key)
			if was == now {
				continue
			}
			changes = append(changes, auditChange(
				"capability_rules."+status.String()+"."+key.String(),
				fmt.Sprint(was), fmt.Sprint(now)))
		}
	}
	return changes
}

// capabilityRuleEditReason 是狀態能力規則替換的固定原因句。
func capabilityRuleEditReason() string {
	return "管理員經已認證會話變更狀態能力規則：僅變更業務狀態來源的封鎖矩陣，" +
		"不覆蓋成員手動限制、活動生命週期與身份資格；自訂狀態不參與本矩陣；" +
		"每一次判定都按服務端現值重新計算，沒有快取"
}
