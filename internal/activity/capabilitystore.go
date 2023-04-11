// capabilitystore.go 是狀態能力規則的持久倉儲：一份活動層級的 7×6 矩陣與它的版本。
//
// 兩條讀寫都接受 database.Querier、自己不開交易（口徑同本套件其余倉儲）：
// 「換掉整份矩陣」與「追加那一筆審計」必須落在同一個交易裡，否則會出現
// 「規則已換、審計說沒換」或反過來的一對事實。
//
// 形狀上的三條規定：
//   - 沒有版本行＝活動從未配置，讀出廠預設（revision 0），不落任何行；
//     第一次寫入才建立版本行，revision 從 1 開始。
//   - 版本行存在時，42 格必須全部存在；讀到少於 42 格、重複格、集合外取值，
//     一律回報資料缺陷，不降級成「缺席即允許」。
//   - 比較-and-set 的依據是版本行的 revision：首次寫入用 INSERT OR IGNORE
//     看是否真的建立了那一行，後續用帶 WHERE revision 的 UPDATE 看是否命中；
//     落敗的那一次不刪、不插、不改任何一格。
package activity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// CapabilityRuleSet 讀回一個活動的狀態能力矩陣。
//
// 沒有版本行是合法的「從未配置」：回出廠預設與 revision 0，不寫任何行。
// 有版本行時逐格核實完整性，任何缺口都如實報錯。
func (s *Store) CapabilityRuleSet(ctx context.Context, q database.Querier,
	activityID idgen.ID) (CapabilityRuleSet, error) {
	if q == nil {
		return CapabilityRuleSet{}, errors.New("capability: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() {
		return CapabilityRuleSet{}, ErrActivityNotFound
	}
	var revision int64
	err := q.QueryRowContext(ctx,
		`SELECT revision FROM activity_capability_rule_sets WHERE activity_id = ?`,
		activityID.String()).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultCapabilityRuleSet(), nil
	}
	if err != nil {
		return CapabilityRuleSet{}, fmt.Errorf("capability: 讀取狀態能力規則版本失敗: %w", err)
	}
	if revision < 1 {
		return CapabilityRuleSet{}, fmt.Errorf("capability: 狀態能力規則版本 %d 不合法", revision)
	}

	rows, err := q.QueryContext(ctx, `SELECT status_key, capability_key, denied
		FROM activity_capability_rules WHERE activity_id = ?`, activityID.String())
	if err != nil {
		return CapabilityRuleSet{}, fmt.Errorf("capability: 讀取狀態能力規則失敗: %w", err)
	}
	defer rows.Close()

	type cellKey struct {
		status BusinessStatus
		key    CapabilityKey
	}
	cells := make(map[cellKey]bool, capabilityRuleCellCount)
	for rows.Next() {
		var statusText, keyText string
		var denied int64
		if err := rows.Scan(&statusText, &keyText, &denied); err != nil {
			return CapabilityRuleSet{}, fmt.Errorf("capability: 解析狀態能力規則失敗: %w", err)
		}
		status := BusinessStatus(statusText)
		if !status.valid() {
			return CapabilityRuleSet{}, fmt.Errorf("capability: 規則列的狀態鍵 %q 不在內建集合內",
				statusText)
		}
		key := MemberRestrictionKey(keyText)
		if !key.valid() {
			return CapabilityRuleSet{}, fmt.Errorf("capability: 規則列的能力鍵 %q 不在封閉集合內",
				keyText)
		}
		if denied != 0 && denied != 1 {
			return CapabilityRuleSet{}, fmt.Errorf("capability: 規則列 %s/%s 的 denied=%d 不是 0 或 1",
				statusText, keyText, denied)
		}
		cell := cellKey{status: status, key: key}
		if _, dup := cells[cell]; dup {
			return CapabilityRuleSet{}, fmt.Errorf("capability: 規則列 %s/%s 出現兩次",
				statusText, keyText)
		}
		cells[cell] = denied == 1
	}
	if err := rows.Err(); err != nil {
		return CapabilityRuleSet{}, fmt.Errorf("capability: 讀取狀態能力規則失敗: %w", err)
	}
	if len(cells) != capabilityRuleCellCount {
		return CapabilityRuleSet{}, fmt.Errorf("capability: 狀態能力規則不完整（%d/%d 格）",
			len(cells), capabilityRuleCellCount)
	}
	// 自訂狀態不得拒絕任何能力：這是資料缺陷而不是請求寫法問題，
	// 因此回一般錯誤（對外 500），不讓 GET 把它誤讀成 1004。
	for _, key := range memberRestrictionKeys {
		if cells[cellKey{status: BusinessStatusCustom, key: key}] {
			return CapabilityRuleSet{}, fmt.Errorf(
				"capability: custom 列不得拒絕能力（資料缺陷：%s）", key.String())
		}
	}

	groups := make([]CapabilityRuleGroup, 0, len(builtinBusinessStatuses))
	for _, status := range builtinBusinessStatuses {
		denied := make([]CapabilityKey, 0, len(memberRestrictionKeys))
		for _, key := range memberRestrictionKeys {
			if cells[cellKey{status: status, key: key}] {
				denied = append(denied, key)
			}
		}
		groups = append(groups, CapabilityRuleGroup{Status: status, Denied: denied})
	}
	return CapabilityRuleSet{Revision: revision, Groups: groups}, nil
}

// ReplaceCapabilityRuleSet 以比較-and-set 換掉一個活動的整份矩陣。
//
// expectedRevision 為 0 表示「我認為這個活動還沒配置過」；大於 0 表示
// 「我認為現在是這一版」。命中時寫入 42 格並把版本推進一號（首次為 1）。
// 回傳 (新版本, 是否命中, 錯誤)；未命中時不留下任何改動。
func (s *Store) ReplaceCapabilityRuleSet(ctx context.Context, q database.Querier,
	activityID idgen.ID, expectedRevision int64,
	groups []CapabilityRuleGroup) (int64, bool, error) {
	if q == nil {
		return 0, false, errors.New("capability: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() {
		return 0, false, ErrActivityNotFound
	}
	normalized, err := normalizeCapabilityRuleGroups(groups)
	if err != nil {
		return 0, false, err
	}
	if expectedRevision < 0 {
		return 0, false, fmt.Errorf("%w：expected_revision 不可為負數",
			ErrInvalidCapabilityRules)
	}
	now := timeutil.ToMillis(s.clock.Now())

	var nextRevision int64
	if expectedRevision == 0 {
		// 首次寫入：INSERT OR IGNORE 以主鍵分辨贏家與落敗者，
		// 不靠「先查再插」那個可被插隊的視窗。
		res, err := q.ExecContext(ctx, `INSERT OR IGNORE INTO activity_capability_rule_sets
			(activity_id, revision, updated_at) VALUES (?, 1, ?)`,
			activityID.String(), now)
		if err != nil {
			return 0, false, fmt.Errorf("capability: 建立狀態能力規則版本失敗: %w", err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return 0, false, fmt.Errorf("capability: 確認狀態能力規則版本寫入失敗: %w", err)
		}
		if affected != 1 {
			return 0, false, nil
		}
		nextRevision = 1
	} else {
		res, err := q.ExecContext(ctx, `UPDATE activity_capability_rule_sets
			SET revision = revision + 1, updated_at = ?
			WHERE activity_id = ? AND revision = ?`,
			now, activityID.String(), expectedRevision)
		if err != nil {
			return 0, false, fmt.Errorf("capability: 推進狀態能力規則版本失敗: %w", err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return 0, false, fmt.Errorf("capability: 確認狀態能力規則版本寫入失敗: %w", err)
		}
		if affected != 1 {
			return 0, false, nil
		}
		nextRevision = expectedRevision + 1
		// 整份替換：舊格全部清掉，再由下面同一個交易寫入新的 42 格。
		if _, err := q.ExecContext(ctx,
			`DELETE FROM activity_capability_rules WHERE activity_id = ?`,
			activityID.String()); err != nil {
			return 0, false, fmt.Errorf("capability: 清除舊狀態能力規則失敗: %w", err)
		}
	}

	for _, group := range normalized {
		for _, key := range memberRestrictionKeys {
			denied := int64(0)
			for _, item := range group.Denied {
				if item == key {
					denied = 1
					break
				}
			}
			if _, err := q.ExecContext(ctx, `INSERT INTO activity_capability_rules
				(activity_id, status_key, capability_key, denied) VALUES (?, ?, ?, ?)`,
				activityID.String(), group.Status.String(), key.String(), denied); err != nil {
				return 0, false, fmt.Errorf("capability: 寫入狀態能力規則失敗: %w", err)
			}
		}
	}
	return nextRevision, true, nil
}
