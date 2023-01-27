// soft_delete_test.go 是遷移 0007 的升級證據：一支帶著真實既有資料的 v6 資料庫，
// 套上 0007 之後要同時滿足兩件事——每一行舊資料與每一條舊規則都還在原處，
// 而新增的刪除終態形態真的可用。
//
// 這裡取的證不是「遷移跑完了」，而是「搬表的過程沒有把任何一條約束搬丟」：
// 0007 為了放寬 status 的 CHECK 必須重建 accounts，並連帶重建兩張參照它的子表，
// 這種規模的遷移最容易留下的缺陷恰恰是「某個觸發器忘記重建」——它不會讓遷移失敗，
// 只會讓之後某一次的寫入悄悄少一道閘。
package migrate

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// splitMigrations 依版本切出「到 v6 為止」與「v7 本身」兩段。
//
// 注意呼叫 applySet 時要交的是兩段合起來的完整集合：遷移器會逐條核對版本表裡每一筆
// 已套用記錄是否在已知集合裡認得（認不得就是 ErrOutOfOrder），只交 v7 會被當成
// 「版本表帶著執行檔不認識的 1..6」。正式流程永遠交完整集合，這裡拆開只是為了
// 先把資料庫停在 v6、再單獨觀察 0007 的效果。
func splitMigrations(t *testing.T) (through6, only7 []Migration) {
	t.Helper()
	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	for _, m := range known {
		switch {
		case m.Version < 7:
			through6 = append(through6, m)
		case m.Version == 7:
			only7 = append(only7, m)
		}
	}
	if len(only7) != 1 {
		t.Fatalf("必須恰好有一支版本 7 的遷移可供單獨套用，實際 %d 支", len(only7))
	}
	return through6, only7
}

// seedV6Facts 在 v6 結構上留下後續要逐字比對的既有事實：
// 一個 active、一個 disabled，外加一份會話、兩筆授予與兩筆審計。
func seedV6Facts(t *testing.T, db *sql.DB) (activeID, disabledID string) {
	t.Helper()
	ctx := context.Background()
	activeID, disabledID = "0192f0c4-1c9a-7000-8000-0000000000a1", "0192f0c4-1c9a-7000-8000-0000000000b2"

	mustExec := func(statement string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, statement, args...); err != nil {
			t.Fatalf("佈下 v6 既有事實失敗：%v（%s）", err, statement)
		}
	}
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at, last_login_at, disabled_at)
		VALUES (?, 'still.here', 'still.here', '留著的甲', ?, 'standard', 'active', 0, 1000, 1500, NULL)`,
		activeID, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$fakehashfortestonly")
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at, last_login_at, disabled_at)
		VALUES (?, 'was.stopped', 'was.stopped', '停過的乙', ?, 'standard', 'disabled', 1, 1000, NULL, 1600)`,
		disabledID, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$fakehashfortestonly")
	mustExec(`INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
			created_at, last_active_at, expires_at, revoked_at, rotation_seq, previous_token_hash)
		VALUES (?, ?, ?, 'account', ?, 1100, 1200, 99999, NULL, 1, ?)`,
		"0192f0c4-1c9a-7000-8000-0000000000s1", "0192f0c4-1c9a-7000-8000-0000000000d1",
		strings.Repeat("a", 64), activeID, strings.Repeat("b", 64))
	mustExec(`INSERT INTO account_server_roles (account_id, role, granted_at) VALUES (?, 'server_admin', 1000)`, activeID)
	mustExec(`INSERT INTO account_server_roles (account_id, role, granted_at) VALUES (?, 'server_admin', 1100)`, disabledID)
	mustExec(`INSERT INTO root_audit (id, created_at, actor_kind, actor_id, action, target_kind, target_id, changes_json)
		VALUES (?, 1200, 'root', ?, 'admin.create', 'account', ?, '[{"field":"login_name"}]')`,
		"0192f0c4-1c9a-7000-8000-0000000000e1", "0192f0c4-1c9a-7000-8000-0000000000ff", activeID)

	return activeID, disabledID
}

// TestSoftDeleteMigrationKeepsEveryRowAndRule 帶資料升級：行逐字保留、
// 規則一條不少，而刪除終態真的可用。
func TestSoftDeleteMigrationKeepsEveryRowAndRule(t *testing.T) {
	ctx := context.Background()
	through6, only7 := splitMigrations(t)

	path := filepath.Join(retryTempDir(t), "evernight.db")
	db := mustOpen(t, path)
	t.Cleanup(func() { _ = db.Close() })

	if _, err := applySet(ctx, db.SQL(), through6, Options{}); err != nil {
		t.Fatalf("套用 v1..v6 失敗：%v", err)
	}
	activeID, disabledID := seedV6Facts(t, db.SQL())

	if _, err := applySet(ctx, db.SQL(), append(through6, only7...), Options{}); err != nil {
		t.Fatalf("套用 0007 失敗：%v", err)
	}

	// 1) 每一行舊資料逐字還在，deleted_at 對他們都是 NULL（他們都還沒被刪除過）。
	for _, want := range []struct {
		id, login, status string
		disabledAt        int64
		mustChange        int64
	}{
		{activeID, "still.here", "active", 0, 0},
		{disabledID, "was.stopped", "disabled", 1600, 1},
	} {
		var (
			login, status       string
			disabledAt, deleted sql.NullInt64
			mustChange, created int64
			lastLogin           sql.NullInt64
			hash                sql.NullString
		)
		if err := db.SQL().QueryRowContext(ctx, `SELECT login_name, status, disabled_at, deleted_at,
				must_change_password, created_at, last_login_at, password_hash FROM accounts WHERE id = ?`,
			want.id).Scan(&login, &status, &disabledAt, &deleted, &mustChange, &created, &lastLogin, &hash); err != nil {
			t.Fatalf("讀回帳戶 %s 失敗：%v", want.id, err)
		}
		if login != want.login || status != want.status {
			t.Errorf("帳戶 %s 的登入名/狀態被搬移改寫：%q/%q（希望 %q/%q）",
				want.id, login, status, want.login, want.status)
		}
		if disabledAt.Int64 != want.disabledAt || disabledAt.Valid != (want.disabledAt != 0) {
			t.Errorf("帳戶 %s 的停用時刻被搬移改寫：%+v", want.id, disabledAt)
		}
		if deleted.Valid {
			t.Errorf("帳戶 %s 在升級後憑空帶著刪除時刻：%+v", want.id, deleted)
		}
		if mustChange != want.mustChange || created != 1000 || hash.String == "" {
			t.Errorf("帳戶 %s 的旗標/建立時刻/憑據被搬移改寫：%d/%d/%q", want.id, mustChange, created, hash.String)
		}
	}
	// 會話、授予、審計三張表的行數與內容都不該因為搬 accounts 而變化。
	for table, want := range map[string]int{
		"sessions": 1, "account_server_roles": 2, "root_audit": 1,
	} {
		var got int
		if err := db.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&got); err != nil {
			t.Fatalf("計數 %s 失敗：%v", table, err)
		}
		if got != want {
			t.Errorf("%s 的行數應是 %d，實際 %d（級聯或搬漏都會在這裡現形）", table, want, got)
		}
	}

	// 2) 外鍵關係真的回到了 accounts：孤立子行進不去，帶著子行的父行也不能被物理移除。
	if _, err := db.SQL().ExecContext(ctx,
		`INSERT INTO account_server_roles (account_id, role, granted_at) VALUES (?, 'server_admin', 1)`,
		"0192f0c4-1c9a-7000-8000-0000000000zz"); err == nil {
		t.Error("升級後外鍵竟不再擋孤立授予行（REFERENCES 子句沒跟著正名）")
	}
	if _, err := db.SQL().ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, activeID); err == nil {
		t.Error("帶著會話與授予的帳戶行竟能被物理刪除（外鍵沒保住既有參照）")
	}

	// 3) 各表的觸發器與索引一條都沒丟：這些失敗都該是「擋住了」而不是「沒建起來」。
	if _, err := db.SQL().ExecContext(ctx, `UPDATE accounts SET id = ? WHERE id = ?`,
		"0192f0c4-1c9a-7000-8000-0000000000a9", activeID); err == nil {
		t.Error("accounts 主鍵不可變的觸發器不見了")
	}
	if _, err := db.SQL().ExecContext(ctx, `UPDATE sessions SET token_hash = ? WHERE id = ?`,
		strings.Repeat("c", 64), "0192f0c4-1c9a-7000-8000-0000000000s1"); err == nil {
		t.Error("sessions 的憑據輪換觸發器不見了（就地換秘密不經世代號）")
	}
	if _, err := db.SQL().ExecContext(ctx, `UPDATE account_server_roles SET role = 'server_admin' WHERE account_id = ?`,
		activeID); err == nil {
		t.Error("授予行不可就地改寫的觸發器不見了")
	}
	if _, err := db.SQL().ExecContext(ctx, `INSERT INTO accounts (id, login_name, login_name_key, display_name,
			password_hash, account_type, status, must_change_password, created_at)
		VALUES (?, 'dup.key', 'dup.key', 'x', ?, 'guest', 'active', 0, 1000)`,
		"0192f0c4-1c9a-7000-8000-0000000000c3", "$argon2id$x"); err == nil {
		t.Error("訪客帳戶帶憑據的 CHECK 不見了")
	}
	if _, err := db.SQL().ExecContext(ctx, `INSERT INTO account_server_roles (account_id, role, granted_at)
			VALUES ((SELECT id FROM accounts WHERE login_name_key = 'dup.key'), 'server_admin', 1)`); err == nil {
		t.Error("「訪客不可持有角色」的觸發器在升級後失效（它引用父表名，是本次搬移最容易漏掉的一條）")
	}

	// 4) 新增的刪除終態真的可用：成對 CHECK、終態守衛、登入名佔用一次驗齊。
	if _, err := db.SQL().ExecContext(ctx,
		`UPDATE accounts SET status = 'deleted' WHERE id = ?`, activeID); err == nil {
		t.Error("deleted 沒帶刪除時刻竟然寫得進去（成對 CHECK 沒生效）")
	}
	if _, err := db.SQL().ExecContext(ctx,
		`UPDATE accounts SET status = 'deleted', deleted_at = 2000 WHERE id = ?`, activeID); err != nil {
		t.Fatalf("合法的刪除形態應寫得進去：%v", err)
	}
	if _, err := db.SQL().ExecContext(ctx,
		`UPDATE accounts SET display_name = '我還在' WHERE id = ?`, activeID); err == nil {
		t.Error("已刪除行竟還能被改寫（終態守衛沒生效）")
	}
	if _, err := db.SQL().ExecContext(ctx, `UPDATE accounts SET status = 'active', deleted_at = NULL WHERE id = ?`,
		activeID); err == nil {
		t.Error("已刪除行竟能被改回可用（終態守衛沒擋住復活這條路）")
	}
	if _, err := db.SQL().ExecContext(ctx, `INSERT INTO accounts (id, login_name, login_name_key, display_name,
			password_hash, account_type, status, must_change_password, created_at)
		VALUES (?, 'still.HERE', 'still.here', '同名再來', ?, 'standard', 'active', 1, 1000)`,
		"0192f0c4-1c9a-7000-8000-0000000000c4", "$argon2id$fake"); err == nil {
		t.Error("已刪除帳戶的登入名竟可被復用（唯一索引或行保留出了問題）")
	}

	// 5) 搬移不留中間產物：暫名表與守衛表都該消失，版本記到 7。
	var leftovers int
	if err := db.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%presoftdelete%' OR name LIKE '%migration_guard%'`).
		Scan(&leftovers); err != nil {
		t.Fatalf("查詢殘留物件失敗：%v", err)
	}
	if leftovers != 0 {
		t.Errorf("升級後還留著搬移過程的中間產物：%d 個", leftovers)
	}
	var header int
	if err := db.SQL().QueryRowContext(ctx, "PRAGMA user_version").Scan(&header); err != nil {
		t.Fatalf("讀檔頭版本失敗：%v", err)
	}
	if header != 7 {
		t.Errorf("檔頭 schema 版本應推進到 7，實際 %d", header)
	}
	var recorded int
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM schema_migrations WHERE version = 7").Scan(&recorded); err != nil {
		t.Fatalf("讀版本表失敗：%v", err)
	}
	if recorded != 1 {
		t.Errorf("版本表應恰好有一筆 7 的記錄，實際 %d", recorded)
	}
	if ok := integrityVerdict(t, db.SQL()); ok != "ok" {
		t.Errorf("升級後 integrity_check 報出問題：%s", ok)
	}
	if bad := fkViolations(t, db.SQL()); bad != 0 {
		t.Errorf("升級後仍有 %d 條外鍵對不上", bad)
	}
}

// TestSoftDeleteMigrationRollsBackOnBrokenSchema 失敗要整支回滾：
// 以「同內容但末尾多寫一條非法行」的遷移取代 0007，資料庫必須停在 v6 原樣。
//
// 這條證據的意義只在於確認遷移器的原子性對本支遷移同樣成立：0007 動了三張表，
// 如果半途失敗只留下一張搬好的表，那個現場比任何一次拒絕都難恢復。
func TestSoftDeleteMigrationRollsBackOnBrokenSchema(t *testing.T) {
	ctx := context.Background()
	through6, only7 := splitMigrations(t)

	path := filepath.Join(retryTempDir(t), "evernight.db")
	db := mustOpen(t, path)
	t.Cleanup(func() { _ = db.Close() })

	if _, err := applySet(ctx, db.SQL(), through6, Options{}); err != nil {
		t.Fatalf("套用 v1..v6 失敗：%v", err)
	}
	activeID, _ := seedV6Facts(t, db.SQL())

	broken := testMigration(7, only7[0].Name, only7[0].SQL+`
INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
	account_type, status, must_change_password, created_at)
	VALUES ('0192f0c4-1c9a-7000-8000-0000000000ff', 'bad', 'bad', '壞', NULL, 'standard', 'active', 0, 1);
`)
	if _, err := applySet(ctx, db.SQL(), append(through6, broken), Options{}); err == nil {
		t.Fatal("帶著非法末尾行的遷移應失敗")
	}

	// 回滾之後：仍是 v6 的形態（沒有 deleted_at 欄），既有行一筆不缺。
	if _, err := db.SQL().ExecContext(ctx, `UPDATE accounts SET status = 'deleted', deleted_at = 1 WHERE id = ?`,
		activeID); err == nil {
		t.Error("失敗的遷移竟把新形態留了下來（未整體回滾）")
	}
	if got := mustInt(t, db.SQL(), "SELECT COUNT(*) FROM accounts"); got != 2 {
		t.Errorf("回滾後帳戶行數應仍是 2，實際 %d", got)
	}
	var header int
	if err := db.SQL().QueryRowContext(ctx, "PRAGMA user_version").Scan(&header); err != nil {
		t.Fatalf("讀檔頭版本失敗：%v", err)
	}
	if header != 6 {
		t.Errorf("失敗的遷移不得推進檔頭版本，實際 %d", header)
	}
	if got := mustInt(t, db.SQL(), "SELECT COUNT(*) FROM schema_migrations WHERE version = 7"); got != 0 {
		t.Errorf("失敗的遷移不得寫入版本記錄，實際 %d 筆", got)
	}
}

// integrityVerdict 讀 PRAGMA integrity_check 的第一行結論（正常是 "ok"）。
func integrityVerdict(t *testing.T, db *sql.DB) string {
	t.Helper()
	var verdict string
	if err := db.QueryRowContext(context.Background(), "PRAGMA integrity_check").Scan(&verdict); err != nil {
		t.Fatalf("讀 integrity_check 失敗：%v", err)
	}
	return verdict
}

// fkViolations 數出 PRAGMA foreign_key_check 的違流行數（0 代表每一條外鍵都對得上）。
//
// 刻意用經典的 PRAGMA 而不是 pragma_foreign_key_check() 表值函式：遷移檔本身也不依賴
// 表值函式（見 0007 的守衛為什麼寫成反查），證據與被驗證的東西該走同一條支援面。
func fkViolations(t *testing.T, db *sql.DB) int {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), "PRAGMA foreign_key_check")
	if err != nil {
		t.Fatalf("讀 foreign_key_check 失敗：%v", err)
	}
	defer func() { _ = rows.Close() }()
	count := 0
	for rows.Next() {
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍歷 foreign_key_check 失敗：%v", err)
	}
	return count
}

// mustInt 讀回一個整數查詢結果（失敗即終止測試）。
func mustInt(t *testing.T, db *sql.DB, query string) int {
	t.Helper()
	var got int
	if err := db.QueryRowContext(context.Background(), query).Scan(&got); err != nil {
		t.Fatalf("查詢 %q 失敗：%v", query, err)
	}
	return got
}
