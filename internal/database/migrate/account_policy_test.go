// account_policy_test.go 是遷移 0008 的證據：三個建立入口的開關在資料庫層長什麼樣、
// 出廠那一行種下的值是不是「最嚴的一側」，以及單例與封閉集合是不是真的釘在 SQL 上。
//
// 這裡取的證不是「遷移跑完了」，而是四件之後沒有第二道閘可退的事：
//   - 舊資料不動：0008 只新增一張表，v7 的帳戶、會話、授予、審計必須逐行還在原處；
//   - 出廠值不擅自開放：三個欄的默認值是 0／closed／0，updated_at 是 0 而不是一個假時刻；
//   - 非法值寫不進去：模式不是四個名字之一、布林不是 0/1，一律被 CHECK 擋下，
//     所以「繞過應用層直寫資料庫」也造不出一份讀不出來的策略；
//   - 單例行刪不掉、也不會有第二行：沒有行時讀取端必須憑空猜一個答案，
//     有兩行時「當前生效的策略」就有兩個問法。
package migrate

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// splitPolicyMigrations 依版本切出「到 v7 為止」與「0008 本身」兩段。
//
// 呼叫 applySet 時交的仍是合起來的完整集合（見 splitMigrations 的說明）：
// 拆開只是為了先把資料庫停在 v7，再單獨觀察 0008 的效果。
func splitPolicyMigrations(t *testing.T) (through7, only8 []Migration) {
	t.Helper()
	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	for _, m := range known {
		switch {
		case m.Version < 8:
			through7 = append(through7, m)
		case m.Version == 8:
			only8 = append(only8, m)
		}
	}
	if len(only8) != 1 {
		t.Fatalf("必須恰好有一支版本 8 的遷移可供單獨套用，實際 %d 支", len(only8))
	}
	return through7, only8
}

// readPolicyRow 讀回單例行的四個值（測試取證用，不參與任何生產判定）。
func readPolicyRow(t *testing.T, db *sql.DB) (adminCreate int, mode string, guest int, updatedAt int64) {
	t.Helper()
	err := db.QueryRowContext(context.Background(),
		`SELECT admin_create_standard, self_register_mode, guest_enabled, updated_at
		   FROM account_creation_policy WHERE id = 1`).
		Scan(&adminCreate, &mode, &guest, &updatedAt)
	if err != nil {
		t.Fatalf("讀取策略單例行失敗：%v", err)
	}
	return adminCreate, mode, guest, updatedAt
}

// TestAccountPolicyMigrationSeedsStrictDefault 驗證 0008 種下的出廠值就是本步之前的真實行為。
func TestAccountPolicyMigrationSeedsStrictDefault(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(retryTempDir(t), "evernight.db")
	db := mustOpen(t, path)
	defer func() { _ = db.Close() }()

	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	at := timeutil.FromMillis(timeutil.ToMillis(timeutil.System().Now()))
	if _, err := applySet(ctx, db.SQL(), known, Options{Clock: timeutil.NewTest(at)}); err != nil {
		t.Fatalf("套用全部遷移失敗：%v", err)
	}

	adminCreate, mode, guest, updatedAt := readPolicyRow(t, db.SQL())
	if adminCreate != 0 || mode != "closed" || guest != 0 {
		t.Errorf("出廠值應為全關＋closed，實際 %d/%q/%d", adminCreate, mode, guest)
	}
	// updated_at 為 0 是一個有意義的事實：沒人改過。拿套用遷移的時刻冒充會留下
	// 「某一刻有人動過策略」這條查有此事的假紀錄。
	if updatedAt != 0 {
		t.Errorf("出廠行的 updated_at 應為 0（從未被改寫），實際 %d", updatedAt)
	}

	var rows int
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM account_creation_policy").Scan(&rows); err != nil {
		t.Fatalf("計數策略表失敗：%v", err)
	}
	if rows != 1 {
		t.Errorf("策略表應恰好一行，實際 %d 行", rows)
	}
}

// TestAccountPolicyMigrationPreservesV7Facts 驗證 0008 是純新增：v7 的既有事實逐行還在。
func TestAccountPolicyMigrationPreservesV7Facts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(retryTempDir(t), "evernight.db")
	db := mustOpen(t, path)
	defer func() { _ = db.Close() }()

	through7, only8 := splitPolicyMigrations(t)
	if _, err := applySet(ctx, db.SQL(), through7, Options{}); err != nil {
		t.Fatalf("先停在 v7 失敗：%v", err)
	}
	seedV6Facts(t, db.SQL())
	if version, err := Current(ctx, db.SQL()); err != nil || version != 7 {
		t.Fatalf("套用前版本應為 7，實際 %d（%v）", version, err)
	}

	if _, err := applySet(ctx, db.SQL(), append(through7, only8...), Options{}); err != nil {
		t.Fatalf("單獨套用 0008 失敗：%v", err)
	}

	// 舊資料仍可讀：帳戶行與它的狀態、授予、審計都在原處（0008 不碰那幾張表）。
	var loginName, status string
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT login_name, status FROM accounts WHERE login_name = 'still.here'").
		Scan(&loginName, &status); err != nil {
		t.Fatalf("升級後讀不回既有帳戶失敗：%v", err)
	}
	if loginName != "still.here" || status != "active" {
		t.Errorf("既有帳戶應原樣保留，實際 %q/%q", loginName, status)
	}
	// 參照帳戶的三張表也必須還在原處：0008 不碰它們，若哪天被順手動過，
	// 這裡的計數會先於任何業務測試發現（數量取自 seedV6Facts 種下的事實）。
	for table, want := range map[string]int{"sessions": 1, "account_server_roles": 2, "root_audit": 1} {
		var count int
		if err := db.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			t.Fatalf("計數 %s 失敗：%v", table, err)
		}
		if count != want {
			t.Errorf("%s 應保留 %d 行，實際 %d 行", table, want, count)
		}
	}
	if version, err := Current(ctx, db.SQL()); err != nil || version != 8 {
		t.Fatalf("升級後版本應為 8，實際 %d（%v）", version, err)
	}
	// 升級同時種下出廠那一行：舊資料不動、新行可用，兩件事在同一支遷移裡成立。
	adminCreate, mode, guest, updatedAt := readPolicyRow(t, db.SQL())
	if adminCreate != 0 || mode != "closed" || guest != 0 || updatedAt != 0 {
		t.Errorf("升級後的出廠值應為全關＋closed＋未改寫，實際 %d/%q/%d/%d", adminCreate, mode, guest, updatedAt)
	}
}

// TestAccountPolicyConstraintsRejectIllegalValues 驗證非法值在 SQL 層就寫不進去。
//
// 每一條都必須失敗：CHECK 是這一欄唯一的最後一道閘（應用層的復核在它之前），
// 少一條就等於「繞過應用層直寫資料庫」能留下一份讀不出來的策略。
func TestAccountPolicyConstraintsRejectIllegalValues(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(retryTempDir(t), "evernight.db")
	db := mustOpen(t, path)
	defer func() { _ = db.Close() }()

	through7, only8 := splitPolicyMigrations(t)
	if _, err := applySet(ctx, db.SQL(), append(through7, only8...), Options{}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}

	mustFail := func(name, statement string, args ...any) {
		t.Helper()
		if _, err := db.SQL().ExecContext(ctx, statement, args...); err == nil {
			t.Errorf("%s：這條寫法應被資料庫擋下，實際寫入了", name)
		}
	}
	mustFail("模式不在封閉集合", `UPDATE account_creation_policy SET self_register_mode = 'pending' WHERE id = 1`)
	mustFail("模式大小寫不同", `UPDATE account_creation_policy SET self_register_mode = 'Open' WHERE id = 1`)
	mustFail("模式為空字串", `UPDATE account_creation_policy SET self_register_mode = '' WHERE id = 1`)
	mustFail("開關不是 0/1", `UPDATE account_creation_policy SET admin_create_standard = 2 WHERE id = 1`)
	mustFail("訪客開關不是 0/1", `UPDATE account_creation_policy SET guest_enabled = -1 WHERE id = 1`)
	mustFail("時刻為負", `UPDATE account_creation_policy SET updated_at = -1 WHERE id = 1`)
	mustFail("第二行", `INSERT INTO account_creation_policy (id, admin_create_standard, self_register_mode, guest_enabled, updated_at) VALUES (2, 1, 'open', 1, 1000)`)
	mustFail("直接插入 deleted 之外的另一種繞法：id 不為 1", `INSERT INTO account_creation_policy (id) VALUES (7)`)
	mustFail("策略行不可刪除", `DELETE FROM account_creation_policy WHERE id = 1`)
	mustFail("單例不可改 id", `UPDATE account_creation_policy SET id = 2 WHERE id = 1`)

	// 上面全數失敗之後，現值必須仍是出廠那一組：拒絕的寫法一個字都不該留下。
	adminCreate, mode, guest, updatedAt := readPolicyRow(t, db.SQL())
	if adminCreate != 0 || mode != "closed" || guest != 0 || updatedAt != 0 {
		t.Errorf("被拒的寫法不應改動現值，實際 %d/%q/%d/%d", adminCreate, mode, guest, updatedAt)
	}

	// 四個已批准的名字都寫得進去：approval／invite 在形態上是合法值（部署者可能直接用
	// 外部工具寫入），「不可經介面寫入」屬應用層的規則，不是表形態的規則。
	for _, name := range []string{"closed", "open", "approval", "invite"} {
		if _, err := db.SQL().ExecContext(ctx,
			`UPDATE account_creation_policy SET self_register_mode = ?, updated_at = ? WHERE id = 1`,
			name, int64(1234)); err != nil {
			t.Errorf("模式 %q 為已批准名字，應可落庫：%v", name, err)
		}
	}
}

// TestAccountPolicyMigrationRollsBackOnFailure 驗證 0008 失敗時整輪回滾，不留半套結構。
//
// 手法是把目標表先建好（名字相同、內容不同），讓 CREATE TABLE 在第一步就撞名：
// 若遷移不是原子的，資料庫會停在「有表但沒種下行、也沒有觸發器」這種比什麼都沒做更壞的狀態。
func TestAccountPolicyMigrationRollsBackOnFailure(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(retryTempDir(t), "evernight.db")
	db := mustOpen(t, path)
	defer func() { _ = db.Close() }()

	through7, only8 := splitPolicyMigrations(t)
	if _, err := applySet(ctx, db.SQL(), through7, Options{}); err != nil {
		t.Fatalf("先停在 v7 失敗：%v", err)
	}
	if _, err := db.SQL().ExecContext(ctx,
		`CREATE TABLE account_creation_policy (id INTEGER PRIMARY KEY, noise TEXT)`); err != nil {
		t.Fatalf("佈下同名表失敗：%v", err)
	}
	if _, err := db.SQL().ExecContext(ctx,
		`INSERT INTO account_creation_policy (id, noise) VALUES (1, '外部工具留下的半套表')`); err != nil {
		t.Fatalf("佈下既有行失敗：%v", err)
	}

	known := append(through7, only8...)
	if _, err := applySet(ctx, db.SQL(), known, Options{}); err == nil {
		t.Fatal("目標表已被佔用時 0008 應失敗")
	}
	if version, err := Current(ctx, db.SQL()); err != nil || version != 7 {
		t.Fatalf("失敗的遷移不應推進版本，實際 %d（%v）", version, err)
	}
	// 觸發器必須不存在（它們與建表同在一筆交易裡，回滾就一起消失）。
	var triggers int
	if err := db.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND tbl_name='account_creation_policy'`).
		Scan(&triggers); err != nil {
		t.Fatalf("查詢觸發器失敗：%v", err)
	}
	if triggers != 0 {
		t.Errorf("回滾後不應留下任何策略表觸發器，實際 %d 個", triggers)
	}
	// 那張同名表的既有內容也不該被遷移動過（失敗的遷移不該有任何副作用）。
	var noise string
	if err := db.SQL().QueryRowContext(ctx,
		`SELECT noise FROM account_creation_policy WHERE id = 1`).Scan(&noise); err != nil {
		t.Fatalf("讀回同名表的既有行失敗：%v", err)
	}
	if noise == "" {
		t.Error("同名表的既有行不應被遷移清空")
	}
}
