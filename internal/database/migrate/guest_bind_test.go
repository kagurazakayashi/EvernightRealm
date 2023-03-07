// guest_bind_test.go 驗收遷移 0011：訪戶綁定的執行形態。
//
// 三個驗收面各自對應本步的一句話：
//  1. 搬表不傷舊事實（六種狀態的帳戶、會話、授予、審計逐字還在原處，外鍵關係還在）；
//  2. 'retired' 是一條有牙齒的終態（成對 CHECK、只屬於訪戶、只能由既存行進入、
//     進去之後整行釘死）；
//  3. 兩張新表把綁定的規則寫成結構（憑證只准核銷一次且簽發事實不可改寫、
//     留痕只追加且一個訪戶只被綁走一次、同意形態是封閉集合）。
package migrate

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// 本檔使用的標識（全部是 36 字元的小寫 UUID 形狀，只服務本檔的 CHECK 取證）。
const (
	// 搬表前就存在的六行與綁定參與者。
	v10ActiveID   = "0192f0c4-1c9a-7000-8000-0000000001a1" // 持有授予的簽發管理員
	v10StoppedID  = "0192f0c4-1c9a-7000-8000-0000000001b2"
	v10DeletedID  = "0192f0c4-1c9a-7000-8000-0000000001c3"
	v10PendingID  = "0192f0c4-1c9a-7000-8000-0000000001d4"
	v10RejectedID = "0192f0c4-1c9a-7000-8000-0000000001e5"
	v10GuestID    = "0192f0c4-1c9a-7000-8000-0000000001f6" // 綁定的來源訪戶
	v11TargetID   = "0192f0c4-1c9a-7000-8000-0000000002b2" // 綁定的目標普通帳戶
	// 退休形態測試另用的三個訪戶與一枚普通帳戶。
	v11Guest2ID = "0192f0c4-1c9a-7000-8000-0000000002c3"
	v11Guest3ID = "0192f0c4-1c9a-7000-8000-0000000006c9"
	v11Guest4ID = "0192f0c4-1c9a-7000-8000-0000000005b8"
	v11Std2ID   = "0192f0c4-1c9a-7000-8000-0000000007da"
	// 憑證與留痕行的標識。
	v11TicketID  = "0192f0c4-1c9a-7000-8000-0000000002a1"
	v11Ticket2ID = "0192f0c4-1c9a-7000-8000-0000000008e6"
	v11BindingID = "0192f0c4-1c9a-7000-8000-0000000009f1"
	v11GhostID   = "0192f0c4-1c9a-7000-8000-000000000bb3"

	v10FakeHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$fakehashfortestonly"
)

// v11TicketHash 與 v11PlanDigest 是兩個哈希欄的合法形狀（SHA-256 十六進位，64 字元）。
var (
	v11TicketHash = strings.Repeat("c", 64)
	v11PlanDigest = strings.Repeat("d", 64)
)

// splitGuestBindMigrations 依版本切出「到 v10 為止」與「v11 本身」兩段（與
// splitApprovalMigrations 同法）。呼叫 applySet 時交的仍須是完整集合：遷移器會逐條
// 核對版本表裡每一筆已套用記錄是否在已知集合裡認得。
func splitGuestBindMigrations(t *testing.T) (through10, only11 []Migration) {
	t.Helper()
	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	for _, m := range known {
		switch {
		case m.Version < 11:
			through10 = append(through10, m)
		case m.Version == 11:
			only11 = append(only11, m)
		}
	}
	if len(only11) != 1 {
		t.Fatalf("必須恰好有一支版本 11 的遷移可供單獨套用，實際 %d 支", len(only11))
	}
	return through10, only11
}

// seedV10Facts 在 v10 結構上留下搬表後要逐字比對的既有事實：六種狀態的帳戶各一
// （active／disabled／deleted／pending／rejected／訪戶 active）、一枚會話、一筆授予、一筆審計。
// 每一跳都走當時合法的形態順序（刪除與審批都要「先有行再寫終態」），不繞觸發器。
func seedV10Facts(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	mustExec := func(statement string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, statement, args...); err != nil {
			t.Fatalf("佈下 v10 既有事實失敗：%v（%s）", err, statement)
		}
	}
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at, last_login_at, disabled_at, deleted_at)
		VALUES (?, 'still.here', 'still.here', '留著的甲', ?, 'standard', 'active', 0, 1000, 1500, NULL, NULL)`,
		v10ActiveID, v10FakeHash)
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at, last_login_at, disabled_at, deleted_at)
		VALUES (?, 'was.stopped', 'was.stopped', '停過的乙', ?, 'standard', 'disabled', 1, 1000, NULL, 1600, NULL)`,
		v10StoppedID, v10FakeHash)
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at, last_login_at, disabled_at)
		VALUES (?, 'was.deleted', 'was.deleted', 'DEL_20260101_刪過的丙', ?, 'standard', 'active', 0, 1000, NULL, NULL)`,
		v10DeletedID, v10FakeHash)
	mustExec("UPDATE accounts SET status = 'deleted', deleted_at = 1700 WHERE id = ?", v10DeletedID)
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at)
		VALUES (?, 'waiting.one', 'waiting.one', '待審的丁', ?, 'standard', 'pending', 1, 1000)`,
		v10PendingID, v10FakeHash)
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at)
		VALUES (?, 'was.refused', 'was.refused', '被拒的戊', ?, 'standard', 'pending', 1, 1000)`,
		v10RejectedID, v10FakeHash)
	mustExec("UPDATE accounts SET status = 'rejected', reviewed_at = 1800 WHERE id = ?", v10RejectedID)
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name,
			account_type, status, must_change_password, created_at)
		VALUES (?, 'guest.here', 'guest.here', '訪客己', 'guest', 'active', 0, 1000)`, v10GuestID)
	mustExec(`INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
			created_at, last_active_at, expires_at, revoked_at, rotation_seq, previous_token_hash)
		VALUES (?, ?, ?, 'account', ?, 1100, 1200, 99999, NULL, 1, ?)`,
		"0192f0c4-1c9a-7000-8000-0000000003d4", "0192f0c4-1c9a-7000-8000-0000000003e5",
		strings.Repeat("a", 64), v10ActiveID, strings.Repeat("b", 64))
	mustExec(`INSERT INTO account_server_roles (account_id, role, granted_at) VALUES (?, 'server_admin', 1000)`,
		v10ActiveID)
	mustExec(`INSERT INTO root_audit (id, created_at, actor_kind, actor_id, action, target_kind, target_id, changes_json)
		VALUES (?, 1200, 'root', ?, 'admin.create', 'account', ?, '{}')`,
		"0192f0c4-1c9a-7000-8000-0000000003f6", v10ActiveID, v10StoppedID)
}

// seedBindParticipants 佈下綁定通路要參照的三個帳戶：來源訪戶、目標普通帳戶、
// 持有授予的簽發管理員（外鍵要求父行先存在）。
func seedBindParticipants(t *testing.T, pool *sql.DB) {
	t.Helper()
	ctx := context.Background()
	mustExec := func(statement string, args ...any) {
		t.Helper()
		if _, err := pool.ExecContext(ctx, statement, args...); err != nil {
			t.Fatalf("佈下綁定參與者失敗：%v（%s）", err, statement)
		}
	}
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name,
			account_type, status, must_change_password, created_at)
		VALUES (?, 'guest.bind', 'guest.bind', '待綁定的訪戶', 'guest', 'active', 0, 1000)`,
		v10GuestID)
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at)
		VALUES (?, 'target.bind', 'target.bind', '受綁的甲', ?, 'standard', 'active', 0, 1000)`,
		v11TargetID, v10FakeHash)
	mustExec(`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at)
		VALUES (?, 'admin.bind', 'admin.bind', '簽發的管理員', ?, 'standard', 'active', 0, 1000)`,
		v10ActiveID, v10FakeHash)
	mustExec(`INSERT INTO account_server_roles (account_id, role, granted_at) VALUES (?, 'server_admin', 1000)`,
		v10ActiveID)
}

// insertTicket 以合法形態簽發一枚憑證（未核銷），呼叫端再從這一跳出發去踩各條非法改動。
func insertTicket(t *testing.T, pool *sql.DB, id, hash string) {
	t.Helper()
	_, err := pool.ExecContext(context.Background(), `INSERT INTO guest_bind_tickets
			(id, ticket_hash, source_account_id, target_account_id, issued_by_account_id,
			 plan_digest, schema_version, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, 11, 2000, 2900)`,
		id, hash, v10GuestID, v11TargetID, v10ActiveID, v11PlanDigest)
	if err != nil {
		t.Fatalf("種下合法憑證 %s 失敗：%v", id, err)
	}
}

// TestGuestBindMigrationKeepsEveryOldFact 驗收：0011 搬表之後舊的行、舊的規則與外鍵關係
// 都在原處，而 retired_at 對既有每一行都是 NULL（沒有人被綁走過）。
func TestGuestBindMigrationKeepsEveryOldFact(t *testing.T) {
	ctx := context.Background()
	through10, only11 := splitGuestBindMigrations(t)

	db := openUpTo(t, through10)
	pool := db.SQL()
	seedV10Facts(t, pool)

	// 帳戶全部欄位的逐字快照：搬表前抓一份，搬表後再抓一份對比。
	type row struct {
		id                  string
		loginName, loginKey string
		display             string
		hash                sql.NullString
		accountType, status string
		mustChange          int
		created             int64
		lastLogin           sql.NullInt64
		disabledAt          sql.NullInt64
		deletedAt           sql.NullInt64
		reviewedAt          sql.NullInt64
	}
	scanRows := func() []row {
		t.Helper()
		rows, err := pool.QueryContext(ctx, `SELECT id, login_name, login_name_key, display_name,
				password_hash, account_type, status, must_change_password, created_at,
				last_login_at, disabled_at, deleted_at, reviewed_at
			FROM accounts ORDER BY id`)
		if err != nil {
			t.Fatalf("讀取帳戶快照失敗：%v", err)
		}
		defer rows.Close()
		var out []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.loginName, &r.loginKey, &r.display, &r.hash,
				&r.accountType, &r.status, &r.mustChange, &r.created, &r.lastLogin,
				&r.disabledAt, &r.deletedAt, &r.reviewedAt); err != nil {
				t.Fatalf("解析帳戶快照失敗：%v", err)
			}
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("讀取帳戶快照失敗：%v", err)
		}
		return out
	}
	before := scanRows()
	if len(before) != 6 {
		t.Fatalf("佈下的帳戶應為 6 行，實際 %d 行", len(before))
	}

	if _, err := applySet(ctx, pool, append(through10, only11...), Options{}); err != nil {
		t.Fatalf("套用 0011 失敗：%v", err)
	}
	after := scanRows()
	if len(after) != len(before) {
		t.Fatalf("搬表前後行數不同：%d vs %d", len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Errorf("帳戶 %s 在搬表後被改寫：\n舊 %+v\n新 %+v", before[i].id, before[i], after[i])
		}
	}

	// retired_at 對既有每一行都是 NULL：沒有人被綁走過，回填等於偽造歷史。
	if got := mustInt(t, pool, "SELECT COUNT(*) FROM accounts WHERE retired_at IS NOT NULL"); got != 0 {
		t.Errorf("搬表後不得有任何行帶著退休時刻，實際 %d 行", got)
	}

	// 外鍵關係與只追加審計都在原處：子表重建不是把連結弄斷。
	if got := mustInt(t, pool, "SELECT COUNT(*) FROM sessions s WHERE s.account_id IS NOT NULL"+
		" AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = s.account_id)"); got != 0 {
		t.Errorf("搬表後出現孤兒會話 %d 行", got)
	}
	if got := mustInt(t, pool, "SELECT COUNT(*) FROM account_server_roles r WHERE NOT EXISTS"+
		" (SELECT 1 FROM accounts a WHERE a.id = r.account_id)"); got != 0 {
		t.Errorf("搬表後出現孤兒授予 %d 行", got)
	}
	if got := mustInt(t, pool, "SELECT COUNT(*) FROM root_audit"); got != 1 {
		t.Errorf("既有審計應逐字留在一筆，實際 %d 筆", got)
	}

	// 兩張新表存在且是空的：本支遷移不做任何回填。
	if found, err := tableExists(ctx, pool, "guest_bind_tickets", "guest_account_bindings"); err != nil || !found {
		t.Fatalf("0011 應建出兩張綁定表（found=%v err=%v）", found, err)
	}
	if got := mustInt(t, pool, "SELECT COUNT(*) FROM guest_bind_tickets"); got != 0 {
		t.Errorf("憑證表遷移後必須是空的，實際 %d 行", got)
	}
	if got := mustInt(t, pool, "SELECT COUNT(*) FROM guest_account_bindings"); got != 0 {
		t.Errorf("留痕表遷移後必須是空的，實際 %d 行", got)
	}

	// 版本推進的兩句話：版本表留一筆 11，檔頭跟著走。
	if got := mustInt(t, pool, "SELECT COUNT(*) FROM schema_migrations WHERE version = 11"); got != 1 {
		t.Errorf("0011 應留下一筆版本記錄，實際 %d 筆", got)
	}
	var header int
	if err := pool.QueryRowContext(ctx, "PRAGMA user_version").Scan(&header); err != nil {
		t.Fatalf("讀檔頭版本失敗：%v", err)
	}
	if header != 11 {
		t.Errorf("檔頭版本應推進到 11，實際 %d", header)
	}
}

// TestGuestBindMigrationKeepsOldTriggers 驗收：搬表之後舊的規則仍各有牙齒，
// 而且退休欄位的出現不給「已刪除行被事後改寫」開新口子。
func TestGuestBindMigrationKeepsOldTriggers(t *testing.T) {
	ctx := context.Background()
	through10, only11 := splitGuestBindMigrations(t)
	db := openUpTo(t, through10)
	pool := db.SQL()
	seedV10Facts(t, pool)
	if _, err := applySet(ctx, pool, append(through10, only11...), Options{}); err != nil {
		t.Fatalf("套用 0011 失敗：%v", err)
	}

	// 訪戶不可持授予（0006 的觸發器正文必須仍指向正名後的 accounts）。
	expectAbort(t, pool, "訪戶持授予",
		`INSERT INTO account_server_roles (account_id, role, granted_at) VALUES (?, 'server_admin', 2000)`,
		v10GuestID)
	// 已刪除行不得再寫（含不得事後補一筆退休時刻）。
	expectAbort(t, pool, "已刪除行被事後寫上退休時刻",
		`UPDATE accounts SET retired_at = 2100 WHERE id = ?`, v10DeletedID)
	// 主鍵仍是穩定標識。
	expectAbort(t, pool, "改主鍵",
		`UPDATE accounts SET id = ? WHERE id = ?`, v11GhostID, v10GuestID)
}

// TestGuestBindRetirementShapeRules 驗收：'retired' 是有牙齒的終態。
//
// 合法形態只有一條路徑（既存訪戶行 → status='retired' ＋ retired_at 同一跳），
// 其餘每一種「湊得出來但無法解釋」的寫法都必須被擋。
func TestGuestBindRetirementShapeRules(t *testing.T) {
	ctx := context.Background()
	through10, only11 := splitGuestBindMigrations(t)
	db := openUpTo(t, append(through10, only11...))
	pool := db.SQL()
	seedBindParticipants(t, pool)

	// 合法的那一跳：既存的可用訪戶進入退休態。
	if _, err := pool.ExecContext(ctx,
		`UPDATE accounts SET status = 'retired', retired_at = 2000 WHERE id = ?`, v10GuestID); err != nil {
		t.Fatalf("合法退休那一跳應寫得進：%v", err)
	}
	var (
		status     string
		retiredAt  sql.NullInt64
		display    string
		loginName  string
		mustChange int
	)
	if err := pool.QueryRowContext(ctx, `SELECT status, retired_at, display_name, login_name,
		must_change_password FROM accounts WHERE id = ?`, v10GuestID).
		Scan(&status, &retiredAt, &display, &loginName, &mustChange); err != nil {
		t.Fatalf("讀回退休行失敗：%v", err)
	}
	if status != "retired" || !retiredAt.Valid || retiredAt.Int64 != 2000 {
		t.Errorf("退休行的形態應為 retired/2000，實際 %s/%+v", status, retiredAt)
	}
	// 退休不做匿名化：名字是歷史的一部分（與刪除通路的區別就寫在這一欄上）。
	if display != "待綁定的訪戶" || loginName != "guest.bind" {
		t.Errorf("退休行不得被改寫姓名，實際 %q/%q", display, loginName)
	}
	// 訪戶按定義無憑據：退休不給他把口令變出來（must_change_password 仍為 0）。
	if mustChange != 0 {
		t.Errorf("退休訪戶的改密旗標應仍為 0，實際 %d", mustChange)
	}

	// 進去之後整行釘死：五個方向各自擋一件「事後改寫歷史」的寫法。
	expectAbort(t, pool, "退休行翻回可登入狀態",
		`UPDATE accounts SET status = 'active' WHERE id = ?`, v10GuestID)
	expectAbort(t, pool, "退休行被複用登入名",
		`UPDATE accounts SET login_name = 'reused.name', login_name_key = 'reused.name' WHERE id = ?`,
		v10GuestID)
	expectAbort(t, pool, "退休行被改名",
		`UPDATE accounts SET display_name = '改過的歷史' WHERE id = ?`, v10GuestID)
	expectAbort(t, pool, "退休時刻被改寫",
		`UPDATE accounts SET retired_at = 2500 WHERE id = ?`, v10GuestID)
	expectAbort(t, pool, "退休行被順帶刪除",
		`UPDATE accounts SET deleted_at = 2600 WHERE id = ?`, v10GuestID)

	// 成對規則：狀態與時刻必須同生同滅。
	mustInsertGuest(t, pool, v11Guest2ID, "guest.two", "第二個訪戶")
	expectAbort(t, pool, "退休狀態卻沒有退休時刻",
		`UPDATE accounts SET status = 'retired' WHERE id = ?`, v11Guest2ID)
	expectAbort(t, pool, "可用狀態卻帶著退休時刻",
		`UPDATE accounts SET retired_at = 2000 WHERE id = ?`, v11Guest2ID)
	// 一出生就帶著退休時刻：沒有人做過綁定，卻留了一次綁定的時刻。
	expectAbort(t, pool, "出生即退休",
		`INSERT INTO accounts (id, login_name, login_name_key, display_name, account_type,
				status, must_change_password, created_at, retired_at)
			VALUES (?, 'guest.born', 'guest.born', '出生即退休', 'guest', 'retired', 0, 1000, 1000)`,
		v11Guest4ID)

	// 退休只屬於訪戶：一個 retired 的 standard 行沒有通路能解釋它怎麼來的。
	if _, err := pool.ExecContext(ctx, `INSERT INTO accounts (id, login_name, login_name_key,
			display_name, password_hash, account_type, status, must_change_password, created_at)
		VALUES (?, 'std.two', 'std.two', '第二個普通帳戶', ?, 'standard', 'active', 0, 1000)`,
		v11Std2ID, v10FakeHash); err != nil {
		t.Fatalf("種下第二個普通帳戶失敗：%v", err)
	}
	expectAbort(t, pool, "普通帳戶進入退休態",
		`UPDATE accounts SET status = 'retired', retired_at = 2000 WHERE id = ?`, v11Std2ID)

	// 退休只能從「可用」那一跳進入：停用中的訪戶帶著停用時刻，整條被擋
	//（要綁走他，處置是先恢復他的登入能力）。
	mustInsertGuest(t, pool, v11Guest3ID, "guest.three", "第三個訪戶")
	if _, err := pool.ExecContext(ctx,
		`UPDATE accounts SET status = 'disabled', disabled_at = 1500 WHERE id = ?`,
		v11Guest3ID); err != nil {
		t.Fatalf("停用第三個訪戶失敗：%v", err)
	}
	expectAbort(t, pool, "停用中的訪戶被退休（停用時刻還在）",
		`UPDATE accounts SET status = 'retired', retired_at = 2000 WHERE id = ?`, v11Guest3ID)

	// 時刻單調：退休不可能早於誕生。
	expectAbort(t, pool, "退休時刻早於建立時刻",
		`UPDATE accounts SET status = 'retired', retired_at = 500 WHERE id = ?`, v11Guest2ID)
}

// mustInsertGuest 種下一筆可用的訪戶（退休形態測試的起點）。
func mustInsertGuest(t *testing.T, pool *sql.DB, id, login, display string) {
	t.Helper()
	_, err := pool.ExecContext(context.Background(),
		`INSERT INTO accounts (id, login_name, login_name_key, display_name,
				account_type, status, must_change_password, created_at)
			VALUES (?, ?, ?, ?, 'guest', 'active', 0, 1000)`, id, login, login, display)
	if err != nil {
		t.Fatalf("種下訪戶 %s 失敗：%v", id, err)
	}
}

// TestGuestBindTicketTableRules 驗收：憑證表把「限定這一對、短效、只准核銷一次」寫成結構。
func TestGuestBindTicketTableRules(t *testing.T) {
	ctx := context.Background()
	through10, only11 := splitGuestBindMigrations(t)
	db := openUpTo(t, append(through10, only11...))
	pool := db.SQL()
	seedBindParticipants(t, pool)

	insertTicket(t, pool, v11TicketID, v11TicketHash)

	// 出生態：未核銷。
	var consumed sql.NullInt64
	if err := pool.QueryRowContext(ctx,
		"SELECT consumed_at FROM guest_bind_tickets WHERE id = ?", v11TicketID).Scan(&consumed); err != nil {
		t.Fatalf("讀回憑證失敗：%v", err)
	}
	if consumed.Valid {
		t.Errorf("新建憑證不得帶著核銷時刻，實際 %+v", consumed)
	}

	// 簽發時就带核銷時刻：那是一句「憑證一出生就被用掉了」的謊。
	expectAbort(t, pool, "出生即已核銷的憑證",
		`INSERT INTO guest_bind_tickets (id, ticket_hash, source_account_id, target_account_id,
				issued_by_account_id, plan_digest, schema_version, created_at, expires_at, consumed_at)
			VALUES (?, ?, ?, ?, ?, ?, 11, 2000, 2900, 2100)`,
		v11Ticket2ID, strings.Repeat("e", 64), v10GuestID, v11TargetID, v10ActiveID, v11PlanDigest)

	// 核銷那一跳合法，而且只能一次。
	if _, err := pool.ExecContext(ctx,
		"UPDATE guest_bind_tickets SET consumed_at = 2500 WHERE id = ?", v11TicketID); err != nil {
		t.Fatalf("合法核銷應寫得進：%v", err)
	}
	expectAbort(t, pool, "已核銷憑證被還回去",
		"UPDATE guest_bind_tickets SET consumed_at = NULL WHERE id = ?", v11TicketID)
	expectAbort(t, pool, "已核銷憑證被改核銷時刻",
		"UPDATE guest_bind_tickets SET consumed_at = 2600 WHERE id = ?", v11TicketID)

	// 簽發事實不可改寫：換來源、換目標、改有效期、改計劃摘要、改哈希、改簽發人。
	// 每條的參數都取「本身合法、只是不該被改」的值：讓觸發器成為唯一的擋下者，
	// 而不是讓欄位 CHECK 或外鍵先替它答話（那樣這條斷言就在測別的东西）。
	insertTicket(t, pool, v11Ticket2ID, strings.Repeat("e", 64))
	immutable := []struct {
		what      string
		statement string
		args      []any
	}{
		{"換來源", "UPDATE guest_bind_tickets SET source_account_id = ? WHERE id = ?",
			[]any{v10StoppedID, v11Ticket2ID}},
		{"換目標", "UPDATE guest_bind_tickets SET target_account_id = ? WHERE id = ?",
			[]any{v10StoppedID, v11Ticket2ID}},
		{"改簽發人", "UPDATE guest_bind_tickets SET issued_by_account_id = ? WHERE id = ?",
			[]any{v10StoppedID, v11Ticket2ID}},
		{"改計劃摘要", "UPDATE guest_bind_tickets SET plan_digest = ? WHERE id = ?",
			[]any{strings.Repeat("9", 64), v11Ticket2ID}},
		{"改憑證哈希", "UPDATE guest_bind_tickets SET ticket_hash = ? WHERE id = ?",
			[]any{strings.Repeat("8", 64), v11Ticket2ID}},
		{"改資料庫版本", "UPDATE guest_bind_tickets SET schema_version = 12 WHERE id = ?",
			[]any{v11Ticket2ID}},
		{"改有效期", "UPDATE guest_bind_tickets SET expires_at = 99999 WHERE id = ?",
			[]any{v11Ticket2ID}},
		{"改簽發時刻", "UPDATE guest_bind_tickets SET created_at = 1000 WHERE id = ?",
			[]any{v11Ticket2ID}},
	}
	for _, item := range immutable {
		if _, err := pool.ExecContext(ctx, item.statement, item.args...); err == nil {
			t.Errorf("%s：這條改動應被擋下，實際寫成功了：%s", item.what, item.statement)
		}
	}
	// 主鍵不可改。
	expectAbort(t, pool, "改憑證主鍵",
		"UPDATE guest_bind_tickets SET id = ? WHERE id = ?", v11GhostID, v11Ticket2ID)

	// 「把自己綁進自己」在憑證層沒有落點。
	expectAbort(t, pool, "來源與目標同一人",
		`INSERT INTO guest_bind_tickets (id, ticket_hash, source_account_id, target_account_id,
				issued_by_account_id, plan_digest, schema_version, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, 11, 2000, 2900)`,
		"0192f0c4-1c9a-7000-8000-000000000cc4", strings.Repeat("f", 64),
		v11TargetID, v11TargetID, v10ActiveID)
	// 同一枚哈希不能簽發兩次（UNIQUE）。
	expectAbort(t, pool, "重復哈希的憑證",
		`INSERT INTO guest_bind_tickets (id, ticket_hash, source_account_id, target_account_id,
				issued_by_account_id, plan_digest, schema_version, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, 11, 2000, 2900)`,
		"0192f0c4-1c9a-7000-8000-000000000dd5", v11TicketHash,
		v10GuestID, v11TargetID, v10ActiveID)
	// 一枚「出生即已過期」的憑證沒有誠實語意。
	expectAbort(t, pool, "到期時刻不晚於簽發時刻",
		`INSERT INTO guest_bind_tickets (id, ticket_hash, source_account_id, target_account_id,
				issued_by_account_id, plan_digest, schema_version, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, 11, 2000, 2000)`,
		"0192f0c4-1c9a-7000-8000-000000000ee6", strings.Repeat("1", 64),
		v10GuestID, v11TargetID, v10ActiveID)
	// 憑證行不可刪除（未核銷者由到期失效，已核銷者是綁定證據）。
	expectAbort(t, pool, "刪除憑證行",
		"DELETE FROM guest_bind_tickets WHERE id = ?", v11TicketID)
	// 外鍵：指向不存在的來源寫不進。
	expectAbort(t, pool, "憑證指向不存在的來源",
		`INSERT INTO guest_bind_tickets (id, ticket_hash, source_account_id, target_account_id,
				issued_by_account_id, plan_digest, schema_version, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, 11, 2000, 2900)`,
		"0192f0c4-1c9a-7000-8000-000000000ff7", strings.Repeat("2", 64),
		v11GhostID, v11TargetID, v10ActiveID)
}

// TestGuestBindBindingTableRules 驗收：留痕表是只追加的歷史解釋，
// 而且「一個訪戶只能被綁走一次」「留痕只能指向已核銷的憑證」「同意形態是封閉集合」
// 三句話都有資料庫層的牙齒。
func TestGuestBindBindingTableRules(t *testing.T) {
	ctx := context.Background()
	through10, only11 := splitGuestBindMigrations(t)
	db := openUpTo(t, append(through10, only11...))
	pool := db.SQL()
	seedBindParticipants(t, pool)
	insertTicket(t, pool, v11TicketID, v11TicketHash)

	insertBinding := func(id string) error {
		_, err := pool.ExecContext(ctx, `INSERT INTO guest_account_bindings
				(id, source_account_id, target_account_id, ticket_id, bound_at,
				 revoked_sessions, consent_mode)
			VALUES (?, ?, ?, ?, 2500, 1, 'target_self_initiated')`,
			id, v10GuestID, v11TargetID, v11TicketID)
		return err
	}

	// 憑證還沒核銷時留痕寫不進：沒有核銷就沒有一次綁定。
	expectAbort(t, pool, "留痕指向未核銷的憑證", `INSERT INTO guest_account_bindings
			(id, source_account_id, target_account_id, ticket_id, bound_at,
			 revoked_sessions, consent_mode)
		VALUES (?, ?, ?, ?, 2500, 1, 'target_self_initiated')`,
		v11BindingID, v10GuestID, v11TargetID, v11TicketID)
	if _, err := pool.ExecContext(ctx,
		"UPDATE guest_bind_tickets SET consumed_at = 2500 WHERE id = ?", v11TicketID); err != nil {
		t.Fatalf("核銷憑證失敗：%v", err)
	}

	if err := insertBinding("0192f0c4-1c9a-7000-8000-0000000011a2"); err != nil {
		t.Fatalf("合法留痕應寫得進：%v", err)
	}

	// 同一個訪戶不能被綁走第二次（重複核銷不會再遷移一次的結構保證）。
	if err := insertBinding(v11BindingID); err == nil {
		t.Errorf("同一枚來源的重復留痕應被 UNIQUE 擋下，實際寫成功了")
	}
	// 只追加：不改寫、不刪除。
	expectAbort(t, pool, "改寫留痕",
		"UPDATE guest_account_bindings SET revoked_sessions = 9 WHERE id = ?", "0192f0c4-1c9a-7000-8000-0000000011a2")
	expectAbort(t, pool, "刪除留痕",
		"DELETE FROM guest_account_bindings WHERE id = ?", "0192f0c4-1c9a-7000-8000-0000000011a2")
	// 同意形態是封閉集合且只有一格：沒有「管理員代簽」這一格。
	expectAbort(t, pool, "表外的同意形態", `INSERT INTO guest_account_bindings
			(id, source_account_id, target_account_id, ticket_id, bound_at,
			 revoked_sessions, consent_mode)
		VALUES (?, ?, ?, ?, 2500, 0, 'admin_initiated')`,
		v11BindingID, v10StoppedID, v11TargetID, v11TicketID)
	// 來源與目標同一人沒有落點。
	expectAbort(t, pool, "留痕的來源與目標同一人", `INSERT INTO guest_account_bindings
			(id, source_account_id, target_account_id, ticket_id, bound_at,
			 revoked_sessions, consent_mode)
		VALUES (?, ?, ?, ?, 2500, 0, 'target_self_initiated')`,
		"0192f0c4-1c9a-7000-8000-0000000012b3", v11TargetID, v11TargetID, v11TicketID)
	// 留痕不可指向不存在的憑證。
	expectAbort(t, pool, "留痕指向不存在的憑證", `INSERT INTO guest_account_bindings
			(id, source_account_id, target_account_id, ticket_id, bound_at,
			 revoked_sessions, consent_mode)
		VALUES (?, ?, ?, ?, 2500, 0, 'target_self_initiated')`,
		"0192f0c4-1c9a-7000-8000-0000000013c4", v10StoppedID, v11TargetID, v11GhostID)
}

// TestGuestBindRetirementAndBindingCoexist 驗收：一筆訪戶走完「退休＋留痕」之後，
// 兩張表的行互相指得回，而目標那一行一個字都沒被改寫。
func TestGuestBindRetirementAndBindingCoexist(t *testing.T) {
	ctx := context.Background()
	through10, only11 := splitGuestBindMigrations(t)
	db := openUpTo(t, append(through10, only11...))
	pool := db.SQL()
	seedBindParticipants(t, pool)

	// 完整的一跳：簽發 → 核銷 → 訪戶退休 → 留痕（順序與綁定用例同形）。
	insertTicket(t, pool, v11TicketID, v11TicketHash)
	if _, err := pool.ExecContext(ctx,
		"UPDATE guest_bind_tickets SET consumed_at = 2500 WHERE id = ?", v11TicketID); err != nil {
		t.Fatalf("核銷憑證失敗：%v", err)
	}
	if _, err := pool.ExecContext(ctx,
		`UPDATE accounts SET status = 'retired', retired_at = 2500 WHERE id = ?`,
		v10GuestID); err != nil {
		t.Fatalf("訪戶退休失敗：%v", err)
	}
	if _, err := pool.ExecContext(ctx, `INSERT INTO guest_account_bindings
			(id, source_account_id, target_account_id, ticket_id, bound_at,
			 revoked_sessions, consent_mode)
		VALUES (?, ?, ?, ?, 2500, 2, 'target_self_initiated')`,
		v11BindingID, v10GuestID, v11TargetID, v11TicketID); err != nil {
		t.Fatalf("寫下留痕失敗：%v", err)
	}

	// 三張表各自說一句話，而且互相指得回。
	var (
		status      string
		retiredAt   sql.NullInt64
		boundTarget string
		consumed    sql.NullInt64
	)
	if err := pool.QueryRowContext(ctx,
		"SELECT status, retired_at FROM accounts WHERE id = ?", v10GuestID).
		Scan(&status, &retiredAt); err != nil {
		t.Fatalf("讀回退休行失敗：%v", err)
	}
	if status != "retired" || !retiredAt.Valid || retiredAt.Int64 != 2500 {
		t.Errorf("退休形態應為 retired/2500，實際 %s/%+v", status, retiredAt)
	}
	if err := pool.QueryRowContext(ctx, `SELECT b.target_account_id, t.consumed_at
			FROM guest_account_bindings b
			JOIN guest_bind_tickets t ON t.id = b.ticket_id
			WHERE b.id = ?`, v11BindingID).
		Scan(&boundTarget, &consumed); err != nil {
		t.Fatalf("追溯留痕與憑證的連結失敗：%v", err)
	}
	if boundTarget != v11TargetID || !consumed.Valid || consumed.Int64 != 2500 {
		t.Errorf("留痕應指向目標 %s 與已核銷憑證，實際 %+v/%+v", v11TargetID, boundTarget, consumed)
	}

	// 目標那一行不因綁定而改變形態：憑據、狀態與旗標逐字原樣。
	var (
		targetStatus string
		targetHash   sql.NullString
	)
	if err := pool.QueryRowContext(ctx,
		"SELECT status, password_hash FROM accounts WHERE id = ?", v11TargetID).
		Scan(&targetStatus, &targetHash); err != nil {
		t.Fatalf("讀回目標行失敗：%v", err)
	}
	if targetStatus != "active" || !targetHash.Valid || targetHash.String != v10FakeHash {
		t.Errorf("目標行不得被綁定改寫，實際 %s/%+v", targetStatus, targetHash)
	}
}
