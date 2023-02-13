// pending_approval_test.go 是遷移 0009 的升級證據：一支帶著真實既有資料的 v8 資料庫，
// 套上 0009 之後要同時滿足三件事——每一行舊資料與每一條舊規則都還在原處、
// 新增的兩個狀態真的可用、而新增的「決定時刻」欄位對既有每一行都是 NULL（從來沒這回事）。
//
// 與 0007 的測試同一取向：取的證不是「遷移跑完了」，而是「搬表的過程沒有把任何一條約束搬丟」。
// 0009 為了放寬 status 的 CHECK 必須重建 accounts 並連帶重建兩張參照它的子表，
// 這種規模的遷移最容易留下的缺陷恰恰是「某個觸發器或索引忘記重建」——它不會讓遷移失敗，
// 只會讓之後某一次寫入悄悄少一道閘。所以本檔把那些閘逐條再踩一次。
package migrate

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
)

// splitApprovalMigrations 依版本切出「到 v8 為止」與「v9 本身」兩段（與 splitMigrations 同法）。
//
// 呼叫 applySet 時交的仍須是完整集合：遷移器會逐條核對版本表裡每一筆已套用記錄
// 是否在已知集合裡認得，只交 v9 會被當成「版本表帶著執行檔不認識的 1..8」。
func splitApprovalMigrations(t *testing.T) (through8, only9 []Migration) {
	t.Helper()
	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	for _, m := range known {
		switch {
		case m.Version < 9:
			through8 = append(through8, m)
		case m.Version == 9:
			only9 = append(only9, m)
		}
	}
	if len(only9) != 1 {
		t.Fatalf("必須恰好有一支版本 9 的遷移可供單獨套用，實際 %d 支", len(only9))
	}
	return through8, only9
}

// v8 時期就存在的帳戶標識與測試憑據（fake 雜湊，只服務本檔的 CHECK 取證）。
const (
	v8ActiveID   = "0192f0c4-1c9a-7000-8000-0000000000a1"
	v8StoppedID  = "0192f0c4-1c9a-7000-8000-0000000000b2"
	v8DeletedID  = "0192f0c4-1c9a-7000-8000-0000000000c3"
	v8GuestID    = "0192f0c4-1c9a-7000-8000-0000000000d4"
	v8ArgonHash  = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$fakehashfortestonly"
	v9PendingID  = "0192f0c4-1c9a-7000-8000-0000000000e5"
	v9Pending2ID = "0192f0c4-1c9a-7000-8000-0000000000f6"
	v9FakeHash   = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$secondfakehashfortest"
)

// seedV8Facts 在 v8 結構上留下後續要逐字比對的既有事實：
// 可用／停用／已刪除三個狀態的帳戶各一、一個無憑據的訪客，外加一份會話、一筆授予與一筆審計。
func seedV8Facts(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	mustExec := func(statement string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, statement, args...); err != nil {
			t.Fatalf("佈下 v8 既有事實失敗：%v（%s）", err, statement)
		}
	}
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at, last_login_at, disabled_at, deleted_at)
		VALUES (?, 'still.here', 'still.here', '留著的甲', ?, 'standard', 'active', 0, 1000, 1500, NULL, NULL)`,
		v8ActiveID, v8ArgonHash)
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at, last_login_at, disabled_at, deleted_at)
		VALUES (?, 'was.stopped', 'was.stopped', '停過的乙', ?, 'standard', 'disabled', 1, 1000, NULL, 1600, NULL)`,
		v8StoppedID, v8ArgonHash)
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at, last_login_at, disabled_at)
		VALUES (?, 'was.deleted', 'was.deleted', 'DEL_20260101_刪過的丙', ?, 'standard', 'active', 0, 1000, NULL, NULL)`,
		v8DeletedID, v8ArgonHash)
	// 刪除只能發生在已存在的帳戶上（accounts_insert_not_deleted 就是這句話），
	// 因此這裡先用合法形態種下，再走那一跳 UPDATE——與生產路徑同一個順序。
	mustExec("UPDATE accounts SET status = 'deleted', deleted_at = 1700 WHERE id = ?", v8DeletedID)
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name,
			account_type, status, must_change_password, created_at)
		VALUES (?, 'guest.here', 'guest.here', '訪客丁', 'guest', 'active', 0, 1000)`, v8GuestID)
	mustExec(`INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
			created_at, last_active_at, expires_at, revoked_at, rotation_seq, previous_token_hash)
		VALUES (?, ?, ?, 'account', ?, 1100, 1200, 99999, NULL, 1, ?)`,
		"0192f0c4-1c9a-7000-8000-0000000000s1", "0192f0c4-1c9a-7000-8000-0000000000t2",
		strings.Repeat("a", 64), v8ActiveID, strings.Repeat("b", 64))
	mustExec(`INSERT INTO account_server_roles (account_id, role, granted_at) VALUES (?, 'server_admin', 1000)`,
		v8ActiveID)
	mustExec(`INSERT INTO root_audit (id, created_at, actor_kind, actor_id, action, target_kind, target_id, changes_json)
		VALUES (?, 1200, 'root', ?, 'admin.create', 'account', ?, '{}')`,
		"0192f0c4-1c9a-7000-8000-0000000000u3", v8ActiveID, v8StoppedID)
}

// openUpTo 把資料庫建到給定版本並回傳連線（呼叫端自己收尾）。
func openUpTo(t *testing.T, through []Migration) *database.DB {
	t.Helper()
	db := mustOpen(t, filepath.Join(retryTempDir(t), "evernight.db"))
	t.Cleanup(func() { _ = db.Close() })
	if _, err := applySet(context.Background(), db.SQL(), through, Options{}); err != nil {
		t.Fatalf("套用 v1..v%d 失敗：%v", through[len(through)-1].Version, err)
	}
	return db
}

// applyOnly9 在既有集合後追加 0009 並套用，失敗即終止測試。
func applyOnly9(t *testing.T, db *database.DB, through8, only9 []Migration) {
	t.Helper()
	if _, err := applySet(context.Background(), db.SQL(), append(through8, only9...), Options{}); err != nil {
		t.Fatalf("套用 0009 失敗：%v", err)
	}
}

// TestApprovalMigrationKeepsEveryOldFact 驗收：0009 搬表之後舊的行、舊的規則與外鍵關係
// 都在原處，而 reviewed_at 對既有每一行都是 NULL。
func TestApprovalMigrationKeepsEveryOldFact(t *testing.T) {
	ctx := context.Background()
	through8, only9 := splitApprovalMigrations(t)
	db := openUpTo(t, through8)
	seedV8Facts(t, db.SQL())
	applyOnly9(t, db, through8, only9)
	pool := db.SQL()

	// 1) 狀態與三個時刻逐字比對（「搬移不是重新解釋」只有逐字比對才證得了）。
	for _, want := range []struct {
		id, login, status, displayName string
		disabledAt, deletedAt          int64
		mustChange                     int64
	}{
		{v8ActiveID, "still.here", "active", "留著的甲", 0, 0, 0},
		{v8StoppedID, "was.stopped", "disabled", "停過的乙", 1600, 0, 1},
		{v8DeletedID, "was.deleted", "deleted", "DEL_20260101_刪過的丙", 0, 1700, 0},
		{v8GuestID, "guest.here", "active", "訪客丁", 0, 0, 0},
	} {
		var (
			login, status, name string
			disabled, deleted   sql.NullInt64
			reviewed            sql.NullInt64
			mustChange, created int64
			hash                sql.NullString
		)
		if err := pool.QueryRowContext(ctx, `SELECT login_name, display_name, status, disabled_at,
				deleted_at, reviewed_at, must_change_password, created_at, password_hash
			FROM accounts WHERE id = ?`, want.id).
			Scan(&login, &name, &status, &disabled, &deleted, &reviewed, &mustChange, &created, &hash); err != nil {
			t.Fatalf("讀回帳戶 %s 失敗：%v", want.id, err)
		}
		if login != want.login || status != want.status || name != want.displayName {
			t.Errorf("帳戶 %s 被搬移改寫：%q/%q/%q（希望 %q/%q/%q）",
				want.id, login, status, name, want.login, want.status, want.displayName)
		}
		if disabled.Int64 != want.disabledAt || disabled.Valid != (want.disabledAt != 0) {
			t.Errorf("帳戶 %s 的停用時刻被搬移改寫：%+v", want.id, disabled)
		}
		if deleted.Int64 != want.deletedAt || deleted.Valid != (want.deletedAt != 0) {
			t.Errorf("帳戶 %s 的刪除時刻被搬移改寫：%+v", want.id, deleted)
		}
		// 這一條是本支遷移的「回填守門」：沒有人審核過這些人，就不該有一個審核時刻憑空出現。
		if reviewed.Valid {
			t.Errorf("帳戶 %s 在升級後憑空帶著審核決定時刻：%+v", want.id, reviewed)
		}
		if mustChange != want.mustChange || created != 1000 {
			t.Errorf("帳戶 %s 的旗標或建立時刻被搬移改寫：%d/%d", want.id, mustChange, created)
		}
		if want.id == v8GuestID && hash.Valid {
			t.Error("訪客的「無憑據」形態被搬移破壞")
		}
	}

	// 2) 外鍵與索引仍在原處。
	if got := mustInt(t, pool, "SELECT COUNT(*) FROM sessions s JOIN accounts a ON a.id = s.account_id"); got != 1 {
		t.Errorf("搬移後會話與帳戶的外鍵關係應仍在，實際 join 到 %d 行", got)
	}
	if got := mustInt(t, pool, `SELECT COUNT(*) FROM account_server_roles r
		JOIN accounts a ON a.id = r.account_id`); got != 1 {
		t.Errorf("搬移後授予與帳戶的外鍵關係應仍在，實際 join 到 %d 行", got)
	}
	if got := fkViolations(t, pool); got != 0 {
		t.Errorf("foreign_key_check 應為零違例，實際 %d", got)
	}
	if got := mustInt(t, pool, "SELECT COUNT(*) FROM root_audit"); got != 1 {
		t.Errorf("審計表不該被這一支遷移動到，實際 %d 筆", got)
	}
	// 登入名唯一索引仍生效：同鍵的第二筆必須被擋。
	if _, err := pool.ExecContext(ctx, `INSERT INTO accounts (id, login_name, login_name_key, display_name,
		password_hash, account_type, status, must_change_password, created_at)
		VALUES (?, 'Still.Here', 'still.here', '撞名的', ?, 'standard', 'active', 0, 2000)`,
		"0192f0c4-1c9a-7000-8000-0000000000v4", v8ArgonHash); err == nil {
		t.Error("登入名唯一索引在搬表後失靈：同鍵的第二筆被收下了")
	}

	// 3) 三支觸發器都要還在（忘記重建不會讓遷移失敗，只會讓之後少一道閘）。
	expectAbort(t, pool, "主鍵仍不得改寫",
		"UPDATE accounts SET id = ? WHERE id = ?", "0192f0c4-1c9a-7000-8000-0000000000w5", v8ActiveID)
	expectAbort(t, pool, "刪除終態仍被釘住",
		"UPDATE accounts SET status = 'active' WHERE id = ?", v8DeletedID)
	expectAbort(t, pool, "訪客仍不得持有伺服器級角色",
		"INSERT INTO account_server_roles (account_id, role, granted_at) VALUES (?, 'server_admin', 2000)",
		v8GuestID)
	expectAbort(t, pool, "會話的絕對期限仍不可就地延長",
		"UPDATE sessions SET expires_at = expires_at + 1 WHERE id = ?",
		"0192f0c4-1c9a-7000-8000-0000000000s1")
}

// TestApprovalMigrationOpensTheNewShapes 驗收：新增的兩個狀態與決定時刻真的可用，
// 而每一條新增的規則都在該擋的地方擋住。
func TestApprovalMigrationOpensTheNewShapes(t *testing.T) {
	ctx := context.Background()
	through8, only9 := splitApprovalMigrations(t)
	db := openUpTo(t, through8)
	seedV8Facts(t, db.SQL())
	applyOnly9(t, db, through8, only9)
	pool := db.SQL()

	// 待審批生得下來（不帶決定時刻），而這是唯一能在建立時出現的審批形態。
	if _, err := pool.ExecContext(ctx, `INSERT INTO accounts (id, login_name, login_name_key, display_name,
		password_hash, account_type, status, must_change_password, created_at)
		VALUES (?, 'apply.one', 'apply.one', '申請人一', ?, 'standard', 'pending', 0, 2000)`,
		v9PendingID, v9FakeHash); err != nil {
		t.Fatalf("待審批的申請應落得進去：%v", err)
	}
	// 批准那一跳：status 換成 active 的同時留下決定時刻（下一步審批用例要寫的正是這一行）。
	if _, err := pool.ExecContext(ctx,
		"UPDATE accounts SET status = 'active', reviewed_at = 2500 WHERE id = ?", v9PendingID); err != nil {
		t.Fatalf("批准那一跳應寫得進：%v", err)
	}
	// 拒絕那一跳：pending 落成 rejected 並帶時刻。
	if _, err := pool.ExecContext(ctx, `INSERT INTO accounts (id, login_name, login_name_key, display_name,
		password_hash, account_type, status, must_change_password, created_at)
		VALUES (?, 'apply.two', 'apply.two', '申請人二', ?, 'standard', 'pending', 0, 2000)`,
		v9Pending2ID, v9FakeHash); err != nil {
		t.Fatalf("第二份申請應落得進去：%v", err)
	}
	if _, err := pool.ExecContext(ctx,
		"UPDATE accounts SET status = 'rejected', reviewed_at = 2600 WHERE id = ?", v9Pending2ID); err != nil {
		t.Fatalf("拒絕那一跳應寫得進：%v", err)
	}

	// 新增的規則各踩一次：寫錯形態時整條語句必須失敗，而不是留下一個說不通的行。
	expectAbort(t, pool, "待審批不該帶著決定時刻出生",
		`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at, reviewed_at)
			VALUES (?, 'apply.bad1', 'apply.bad1', '壞形態一', ?, 'standard', 'pending', 0, 2000, 2100)`,
		"0192f0c4-1c9a-7000-8000-0000000000x6", v9FakeHash)
	expectAbort(t, pool, "已拒絕卻沒有決定時刻",
		`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at)
			VALUES (?, 'apply.bad2', 'apply.bad2', '壞形態二', ?, 'standard', 'rejected', 0, 2000)`,
		"0192f0c4-1c9a-7000-8000-0000000000y7", v9FakeHash)
	expectAbort(t, pool, "新行不該憑空帶一個決定時刻",
		`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at, reviewed_at)
			VALUES (?, 'apply.bad3', 'apply.bad3', '壞形態三', ?, 'standard', 'active', 0, 2000, 2100)`,
		"0192f0c4-1c9a-7000-8000-0000000000z8", v9FakeHash)
	expectAbort(t, pool, "訪客不該以待審批形態出生",
		`INSERT INTO accounts (id, login_name, login_name_key, display_name,
			account_type, status, must_change_password, created_at)
			VALUES (?, 'guest.bad', 'guest.bad', '壞訪客', 'guest', 'pending', 0, 2000)`,
		"0192f0c4-1c9a-7000-8000-0000000000a9")
	expectAbort(t, pool, "決定時刻不可能早於帳戶誕生",
		"UPDATE accounts SET reviewed_at = 1000 WHERE id = ?", v9Pending2ID)
	// 被拒絕的那一筆不該帶著「何時被停用」：他沒被停過，他只被拒絕過。
	expectAbort(t, pool, "審核鏈上的狀態不該帶停用時刻",
		"UPDATE accounts SET disabled_at = 2700 WHERE id = ?", v9Pending2ID)

	// 批准留下的時刻不會被後續停用抹掉：那是「他走過審批」的歷史事實。
	if _, err := pool.ExecContext(ctx,
		"UPDATE accounts SET status = 'disabled', disabled_at = 3000 WHERE id = ?", v9PendingID); err != nil {
		t.Fatalf("批准後再停用應寫得進：%v", err)
	}
	var (
		status          string
		reviewed, stopQ sql.NullInt64
	)
	if err := pool.QueryRowContext(ctx,
		"SELECT status, reviewed_at, disabled_at FROM accounts WHERE id = ?", v9PendingID).
		Scan(&status, &reviewed, &stopQ); err != nil {
		t.Fatalf("讀回批准後停用的行失敗：%v", err)
	}
	if status != "disabled" || !reviewed.Valid || reviewed.Int64 != 2500 {
		t.Errorf("批准時刻不該被停用抹掉，實際 %s/%+v", status, reviewed)
	}

	// 遷移成功要如實推進版本：0009 落進版本表，檔頭也跟著走。
	if got := mustInt(t, pool, "SELECT COUNT(*) FROM schema_migrations WHERE version = 9"); got != 1 {
		t.Errorf("成功的遷移應留下一筆版本記錄，實際 %d 筆", got)
	}
	var header int
	if err := pool.QueryRowContext(ctx, "PRAGMA user_version").Scan(&header); err != nil {
		t.Fatalf("讀檔頭版本失敗：%v", err)
	}
	if header != 9 {
		t.Errorf("檔頭版本應推進到 9，實際 %d", header)
	}
}

// TestApprovalMigrationRollsBackOnBrokenSchema 驗收：0009 中途失敗時整支回滾，
// 資料庫停在 v8 的原狀——不留「表已重建而約束缺一角」的半成品。
//
// 手法是在遷移之前先把暫名表佔用掉，讓第一條 CREATE TABLE 就失敗：
// 此刻 accounts 還是舊表，任何一個「半搬完」的形態都不該被留下。
func TestApprovalMigrationRollsBackOnBrokenSchema(t *testing.T) {
	ctx := context.Background()
	through8, only9 := splitApprovalMigrations(t)
	db := openUpTo(t, through8)
	seedV8Facts(t, db.SQL())
	pool := db.SQL()

	if _, err := pool.ExecContext(ctx,
		"CREATE TABLE accounts_pendingapproval (id TEXT PRIMARY KEY)"); err != nil {
		t.Fatalf("佔用暫名表失敗：%v", err)
	}
	if _, err := applySet(ctx, pool, append(through8, only9...), Options{}); err == nil {
		t.Fatal("暫名表已被佔用時 0009 應失敗")
	}

	// 回滾後仍是 v8 的形態：pending 寫不進去，也沒有一欄 reviewed_at。
	if _, err := pool.ExecContext(ctx, `INSERT INTO accounts (id, login_name, login_name_key, display_name,
		password_hash, account_type, status, must_change_password, created_at)
		VALUES (?, 'rollback.probe', 'rollback.probe', '回滾探針', ?, 'standard', 'pending', 0, 2000)`,
		"0192f0c4-1c9a-7000-8000-0000000000b1", v9FakeHash); err == nil {
		t.Error("整支回滾後舊表仍該只認三個狀態，pending 卻被收下了")
	}
	if _, err := pool.ExecContext(ctx, "SELECT reviewed_at FROM accounts LIMIT 0"); err == nil {
		t.Error("回滾後 accounts 不該已有 reviewed_at 欄")
	}
	if got := mustInt(t, pool, "SELECT COUNT(*) FROM accounts"); got != 4 {
		t.Errorf("回滾後帳戶行數應仍是 4，實際 %d", got)
	}
	if got := mustInt(t, pool, "SELECT COUNT(*) FROM schema_migrations WHERE version = 9"); got != 0 {
		t.Errorf("失敗的遷移不得寫入版本記錄，實際 %d 筆", got)
	}
	var header int
	if err := pool.QueryRowContext(ctx, "PRAGMA user_version").Scan(&header); err != nil {
		t.Fatalf("讀檔頭版本失敗：%v", err)
	}
	if header != 8 {
		t.Errorf("失敗的遷移不得推進檔頭版本，實際 %d", header)
	}
}

// expectAbort 斷言一條語句必定失敗：觸發器與 CHECK 的證據就是「它擋住了這一次」，
// 這裡要的是失敗本身，不是某一段錯誤文字（訊息屬實作細節，會隨版本漂移）。
func expectAbort(t *testing.T, pool *sql.DB, what, statement string, args ...any) {
	t.Helper()
	if _, err := pool.ExecContext(context.Background(), statement, args...); err == nil {
		t.Errorf("%s：這條語句應該被資料庫擋下，實際寫成功了：%s", what, statement)
	}
}
