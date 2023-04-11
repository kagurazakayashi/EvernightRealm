// capability_rules_test.go 驗收遷移 0020：狀態能力規則的持久形態。
//
// 三個驗收面：
//  1. 增量遷移不傷既有事實——兩個新表是空的，既有活動、成員、陣營、標籤與狀態
//     一個字都沒動；「沒有版本行＝從未配置」因此有可比對的舊值。
//  2. 封閉形態：狀態鍵只收七個內建值、能力鍵只收六項、denied 只收 0/1、
//     custom 那一列不得為 1（自訂狀態不參與矩陣）、revision 必須 >= 1。
//  3. 參照完整性：規則列必須指向一個已存在的版本行；版本行必須指向一個活動。
package migrate

import (
	"context"
	"database/sql"
	"testing"
)

// dbAt0020WithFacts 建出一座「既有 0019 事實、已套上 0020」的資料庫。
func dbAt0020WithFacts(t *testing.T) *sql.DB {
	t.Helper()
	pool := dbAt0019WithFacts(t)
	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	if _, err := applySet(context.Background(), pool, known, Options{}); err != nil {
		t.Fatalf("套用 0020 失敗：%v", err)
	}
	return pool
}

// capabilityRuleRowCount 讀新兩張表的筆數。
func capabilityRuleRowCount(t *testing.T, pool *sql.DB, table string) int {
	t.Helper()
	var got int
	if err := pool.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM "+table).Scan(&got); err != nil {
		t.Fatalf("統計 %s 失敗：%v", table, err)
	}
	return got
}

// TestCapabilityRulesMigrationKeepsEveryOldFact 驗收：0020 只新增兩張表，
// 既有事實逐字不動，且新表出廠為空（每個活動都讀成「從未配置」）。
func TestCapabilityRulesMigrationKeepsEveryOldFact(t *testing.T) {
	ctx := context.Background()
	pool := dbAt0019WithFacts(t)
	defer pool.Close()

	accountsBefore := factsSnapshot(t, pool)
	activitiesBefore := snapshotRows(t, pool, "activities")
	membersBefore := snapshotRows(t, pool, "activity_members")
	factionsBefore := snapshotRows(t, pool, "activity_factions")
	tagsBefore := snapshotRows(t, pool, "activity_tags")
	statusesBefore := snapshotRows(t, pool, "activity_player_statuses")
	labelsBefore := snapshotRows(t, pool, "activity_player_status_labels")

	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	if _, err := applySet(ctx, pool, known, Options{}); err != nil {
		t.Fatalf("套用 0020 失敗：%v", err)
	}

	if after := factsSnapshot(t, pool); after != accountsBefore {
		t.Errorf("0020 改寫了帳戶側既有事實：\n舊 %s\n新 %s", accountsBefore, after)
	}
	for _, table := range []struct {
		name string
		want string
	}{
		{"activities", activitiesBefore},
		{"activity_members", membersBefore},
		{"activity_factions", factionsBefore},
		{"activity_tags", tagsBefore},
		{"activity_player_statuses", statusesBefore},
		{"activity_player_status_labels", labelsBefore},
	} {
		if after := snapshotRows(t, pool, table.name); after != table.want {
			t.Errorf("0020 改寫了 %s 既有事實：\n舊 %s\n新 %s", table.name, table.want, after)
		}
	}
	if got := capabilityRuleRowCount(t, pool, "activity_capability_rule_sets"); got != 0 {
		t.Errorf("新版本表出廠必須為空，實際 %d 行", got)
	}
	if got := capabilityRuleRowCount(t, pool, "activity_capability_rules"); got != 0 {
		t.Errorf("新規則表出廠必須為空，實際 %d 行", got)
	}
}

// TestCapabilityRulesMigrationShape 驗收：封閉集合、custom 不可拒絕能力、
// 版本 >= 1 與兩層參照完整性。
func TestCapabilityRulesMigrationShape(t *testing.T) {
	ctx := context.Background()
	pool := dbAt0020WithFacts(t)
	defer pool.Close()

	// 沒有版本行時，規則列不得先於版本行存在。
	if _, err := pool.ExecContext(ctx, `INSERT INTO activity_capability_rules
			(activity_id, status_key, capability_key, denied)
		VALUES (?, 'normal', 'chat', 0)`, memActID1); err == nil {
		t.Fatalf("沒有版本行時寫入規則列應被外鍵拒絕")
	}

	// 版本行必須指向既有活動，revision 必須 >= 1。
	for _, stmt := range []string{
		`INSERT INTO activity_capability_rule_sets (activity_id, revision, updated_at)
			VALUES ('0192f0c4-1c9a-7000-8000-00000000dead', 1, 9000)`,
		`INSERT INTO activity_capability_rule_sets (activity_id, revision, updated_at)
			VALUES ('` + memActID1 + `', 0, 9000)`,
	} {
		if _, err := pool.ExecContext(ctx, stmt); err == nil {
			t.Fatalf("不合法的版本行應被拒絕：%s", stmt)
		}
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO activity_capability_rule_sets
			(activity_id, revision, updated_at) VALUES (?, 1, 9000)`, memActID1); err != nil {
		t.Fatalf("合法的版本行應寫得進去：%v", err)
	}

	// 合法的 42 格：先寫一格允許，再逐格驗證封閉集合。
	if _, err := pool.ExecContext(ctx, `INSERT INTO activity_capability_rules
			(activity_id, status_key, capability_key, denied)
		VALUES (?, 'normal', 'chat', 0)`, memActID1); err != nil {
		t.Fatalf("合法的規則列應寫得進去：%v", err)
	}
	for name, stmt := range map[string]string{
		"denied 非 0/1": `INSERT INTO activity_capability_rules
			(activity_id, status_key, capability_key, denied)
			VALUES ('` + memActID1 + `', 'normal', 'trade', 2)`,
		"狀態鍵集合外": `INSERT INTO activity_capability_rules
			(activity_id, status_key, capability_key, denied)
			VALUES ('` + memActID1 + `', 'haunted', 'trade', 1)`,
		"能力鍵集合外": `INSERT INTO activity_capability_rules
			(activity_id, status_key, capability_key, denied)
			VALUES ('` + memActID1 + `', 'normal', 'fly', 1)`,
		"custom 不得拒絕能力": `INSERT INTO activity_capability_rules
			(activity_id, status_key, capability_key, denied)
			VALUES ('` + memActID1 + `', 'custom', 'chat', 1)`,
	} {
		if _, err := pool.ExecContext(ctx, stmt); err == nil {
			t.Errorf("%s 應被 CHECK 拒絕", name)
		}
	}

	// 同一格不可重複；不同格可以逐格翻動。
	if _, err := pool.ExecContext(ctx, `INSERT INTO activity_capability_rules
			(activity_id, status_key, capability_key, denied)
		VALUES (?, 'normal', 'chat', 1)`, memActID1); err == nil {
		t.Fatalf("同一格重複寫入應撞主鍵")
	}
	if _, err := pool.ExecContext(ctx, `UPDATE activity_capability_rules
		SET denied = 1 WHERE activity_id = ? AND status_key = 'normal' AND capability_key = 'chat'`,
		memActID1); err != nil {
		t.Fatalf("合法翻動應成功：%v", err)
	}
	var denied int
	if err := pool.QueryRowContext(ctx, `SELECT denied FROM activity_capability_rules
		WHERE activity_id = ? AND status_key = 'normal' AND capability_key = 'chat'`,
		memActID1).Scan(&denied); err != nil || denied != 1 {
		t.Fatalf("翻動後應讀到 1，實際 %d（%v）", denied, err)
	}
}
