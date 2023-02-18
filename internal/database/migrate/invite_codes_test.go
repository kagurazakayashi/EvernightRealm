// invite_codes_test.go 是遷移 0010 的取證：伺服器級「註冊邀請碼」這一張新表，
// 每一格 CHECK 與每一條觸發器都要在該擋的地方擋住、在該放的地方放得進去。
//
// 這一支遷移不搬任何既有表（它是一張乾淨的新表），因此取的證不是「搬移沒丟約束」，
// 而是「一枚邀請碼的合法形態被完整凍住」：
//   - 驗證材料是定寬雜湊、不可就地換；
//   - 額度與有效期這兩個准入參數建立後不可變（調大 max_uses 是一種未經審計的擴權）；
//   - 用掉幾次只能一次加一、且不能超過上限；
//   - 撤銷是終態——落下時刻後既不能重新生效、也不能再被核銷，已核銷的歷史隨之行一起留住；
//   - 過期用 0 這個取值本身表達「永不過期」，非零時必須晚於簽發時刻。
package migrate

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
)

// 本檔測試用的固定標識與雜湊（皆為佔位值，不是任何真實秘密）。
const (
	inviteCodeID1 = "0192f0c4-1c9a-7000-8000-0000000000c1"
	inviteCodeID2 = "0192f0c4-1c9a-7000-8000-0000000000c2"
	// inviteHashA／inviteHashB 是兩枚定寬 64 的小寫十六進位雜湊，
	// 讓同一測試裡的兩行各自佔不同的 code_hash UNIQUE。
	inviteHashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	inviteHashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// applyThroughInvite 建立一座套到最新版（含 0010）的乾淨資料庫（呼叫端自己收尾）。
func applyThroughInvite(t *testing.T) *database.DB {
	t.Helper()
	db := mustOpen(t, filepath.Join(retryTempDir(t), "evernight.db"))
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Apply(context.Background(), db.SQL(), Options{}); err != nil {
		t.Fatalf("套用全部遷移（含 0010）失敗：%v", err)
	}
	return db
}

// seedInviteCode 以合法形態插入一枚未使用、未撤銷的邀請碼，
// 呼叫端再從這一行出發去踩各條非法改動（與 0009 測試「先種合法形態、再走那一跳」同一手法）。
func seedInviteCode(t *testing.T, pool *sql.DB, id, hash string, maxUses, createdAt, expiresAt int64) {
	t.Helper()
	_, err := pool.ExecContext(context.Background(),
		`INSERT INTO registration_invite_codes (id, code_hash, label, max_uses, used_count, created_at, expires_at)
			VALUES (?, ?, '邀測', ?, 0, ?, ?)`,
		id, hash, maxUses, createdAt, expiresAt)
	if err != nil {
		t.Fatalf("種下合法邀請碼 %s 失敗：%v", id, err)
	}
}

// TestInviteCodesMigrationOpensCleanTable 驗收：0010 建出表、索引與觸發器，
// 合法的一枚碼生得下來，而版本如實推進。
func TestInviteCodesMigrationOpensCleanTable(t *testing.T) {
	ctx := context.Background()
	db := applyThroughInvite(t)
	pool := db.SQL()

	if found, err := tableExists(ctx, pool, "registration_invite_codes"); err != nil || !found {
		t.Fatalf("0010 應建出 registration_invite_codes 表（found=%v err=%v）", found, err)
	}
	seedInviteCode(t, pool, inviteCodeID1, inviteHashA, 1, 1000, 0)

	// 出生態：未使用、未撤銷、永不過期。
	var used, revoked, expires int64
	if err := pool.QueryRowContext(ctx,
		`SELECT used_count, revoked_at, expires_at FROM registration_invite_codes WHERE id = ?`, inviteCodeID1).
		Scan(&used, &revoked, &expires); err != nil {
		t.Fatalf("讀回邀請碼失敗：%v", err)
	}
	if used != 0 || revoked != 0 || expires != 0 {
		t.Errorf("新建邀請碼的出生態應是 0/0/0，實際 %d/%d/%d", used, revoked, expires)
	}

	if got := mustInt(t, pool, "SELECT COUNT(*) FROM schema_migrations WHERE version = 10"); got != 1 {
		t.Errorf("0010 應留下一筆版本記錄，實際 %d 筆", got)
	}
	var header int
	if err := pool.QueryRowContext(ctx, "PRAGMA user_version").Scan(&header); err != nil {
		t.Fatalf("讀檔頭版本失敗：%v", err)
	}
	if header != 10 {
		t.Errorf("檔頭版本應推進到 10，實際 %d", header)
	}
}

// TestInviteCodesColumnRules 驗收：欄位級 CHECK 各自擋住它該擋的形態，
// 而合法形態放得進去——這是「一枚碼長什麼樣」的結構合同。
func TestInviteCodesColumnRules(t *testing.T) {
	ctx := context.Background()
	db := applyThroughInvite(t)
	pool := db.SQL()

	// 合法：帶一個未來到期時刻（expires_at > created_at）。
	if _, err := pool.ExecContext(ctx, `INSERT INTO registration_invite_codes
			(id, code_hash, label, max_uses, created_at, expires_at)
			VALUES (?, ?, '邀測', 5, 1000, 2000)`, inviteCodeID1, inviteHashA); err != nil {
		t.Fatalf("帶未來到期時刻的合法碼應落得進去：%v", err)
	}

	// max_uses 至少為 1（「零次可用的碼」不是單次碼，是一枚根本核銷不掉的垃圾行）。
	expectAbort(t, pool, "max_uses 不得小於 1",
		`INSERT INTO registration_invite_codes (id, code_hash, label, max_uses, created_at)
			VALUES (?, ?, '甲', 0, 1000)`, inviteCodeID2, inviteHashB)

	// 一枚碼的雜湊必須定寬 64（不是任何「看起來像」的字串都能冒充驗證材料）。
	expectAbort(t, pool, "code_hash 長度須恰為 64",
		`INSERT INTO registration_invite_codes (id, code_hash, label, max_uses, created_at)
			VALUES (?, ?, '甲', 1, 1000)`, inviteCodeID2, strings.Repeat("f", 63))

	// 標籤不許為空（列表那一格要有話可說）。
	expectAbort(t, pool, "label 不得為空",
		`INSERT INTO registration_invite_codes (id, code_hash, label, max_uses, created_at)
			VALUES (?, ?, '', 1, 1000)`, inviteCodeID2, inviteHashB)

	// 到期時刻早於簽發時刻：一枚「出生即已過期」的碼沒有誠實說法。
	expectAbort(t, pool, "expires_at 非零時須晚於 created_at",
		`INSERT INTO registration_invite_codes (id, code_hash, label, max_uses, created_at, expires_at)
			VALUES (?, ?, '甲', 1, 1000, 999)`, inviteCodeID2, inviteHashB)

	// used_count 出生就超過 max_uses（與 CHECK used_count BETWEEN 0 AND max_uses 相抵）。
	expectAbort(t, pool, "used_count 不得超過 max_uses",
		`INSERT INTO registration_invite_codes (id, code_hash, label, max_uses, used_count, created_at)
			VALUES (?, ?, '甲', 1, 2, 1000)`, inviteCodeID2, inviteHashB)
}

// TestInviteCodesImmutableFacts 驗收：簽發時定下的事實不可就地改寫，
// 而唯一被允許隨一次核銷移動的是 used_count（加一，且不越過 max_uses）。
func TestInviteCodesImmutableFacts(t *testing.T) {
	ctx := context.Background()
	db := applyThroughInvite(t)
	pool := db.SQL()
	seedInviteCode(t, pool, inviteCodeID1, inviteHashA, 3, 1000, 0)

	// 主鍵、驗證材料、四個簽發事實各自不可變。
	expectAbort(t, pool, "id 不可改寫",
		"UPDATE registration_invite_codes SET id = ? WHERE id = ?", inviteCodeID2, inviteCodeID1)
	expectAbort(t, pool, "code_hash 不可就地換（丟失請重新簽發一枚）",
		"UPDATE registration_invite_codes SET code_hash = ? WHERE id = ?", strings.Repeat("9", 64), inviteCodeID1)
	expectAbort(t, pool, "max_uses 不可調大（那是未經審計的准入擴權）",
		"UPDATE registration_invite_codes SET max_uses = 99 WHERE id = ?", inviteCodeID1)
	expectAbort(t, pool, "expires_at 不可改寫",
		"UPDATE registration_invite_codes SET expires_at = 5000 WHERE id = ?", inviteCodeID1)
	expectAbort(t, pool, "label 不可改寫",
		"UPDATE registration_invite_codes SET label = '換個名' WHERE id = ?", inviteCodeID1)

	// 一次核銷加一放得過；跳號與回減擋住（monotonic 觸發器正是核銷那條 UPDATE 的合同）。
	if _, err := pool.ExecContext(ctx,
		"UPDATE registration_invite_codes SET used_count = used_count + 1 WHERE id = ?", inviteCodeID1); err != nil {
		t.Fatalf("第一次核銷（0→1）應寫得進：%v", err)
	}
	expectAbort(t, pool, "used_count 不得一次跳兩格",
		"UPDATE registration_invite_codes SET used_count = used_count + 2 WHERE id = ?", inviteCodeID1)
	expectAbort(t, pool, "used_count 不得回減（抹掉已核銷的歷史）",
		"UPDATE registration_invite_codes SET used_count = 0 WHERE id = ?", inviteCodeID1)

	// 用到滿（3/3）合法：1→2、2→3 各一次加一。
	if _, err := pool.ExecContext(ctx,
		"UPDATE registration_invite_codes SET used_count = used_count + 1 WHERE id = ?", inviteCodeID1); err != nil {
		t.Fatalf("第二次核銷（1→2）應寫得進：%v", err)
	}
	if _, err := pool.ExecContext(ctx,
		"UPDATE registration_invite_codes SET used_count = used_count + 1 WHERE id = ?", inviteCodeID1); err != nil {
		t.Fatalf("第三次核銷（2→3）應寫得進：%v", err)
	}
	// 已滿（3/3）後第四次「一次加一」雖通過觸發器，仍被 CHECK（used_count<=max_uses）擋下：
	// 這一條把「併發核銷把計數竄過上限」在資料庫層釘死，屬核銷那一步要依賴的併發邊界。
	expectAbort(t, pool, "已滿（3/3）後不得再核銷（4>max_uses）",
		"UPDATE registration_invite_codes SET used_count = used_count + 1 WHERE id = ?", inviteCodeID1)
}

// TestInviteCodesInsertGuards 驗收：新建的一枚碼只能是「一次都沒用過、且沒被撤銷」的出生形態。
func TestInviteCodesInsertGuards(t *testing.T) {
	db := applyThroughInvite(t)
	pool := db.SQL()

	// 出生就帶已核銷次數：那該是核銷那一步寫入的事實，不是建立時能自報的。
	expectAbort(t, pool, "新建不得帶有已核銷次數",
		`INSERT INTO registration_invite_codes (id, code_hash, label, max_uses, used_count, created_at)
			VALUES (?, ?, '甲', 3, 1, 1000)`, inviteCodeID1, inviteHashA)
	// 出生就帶撤銷時刻：撤銷只能發生在已存在的碼上。
	expectAbort(t, pool, "新建不得直接帶有撤銷時刻",
		`INSERT INTO registration_invite_codes (id, code_hash, label, max_uses, created_at, revoked_at)
			VALUES (?, ?, '甲', 3, 1000, 1500)`, inviteCodeID2, inviteHashB)
}

// TestInviteCodesRevocationIsTerminal 驗收：撤銷落下時刻即終態——
// 既不能重新生效、不能再被核銷，已核銷的歷史留住。
func TestInviteCodesRevocationIsTerminal(t *testing.T) {
	ctx := context.Background()
	db := applyThroughInvite(t)
	pool := db.SQL()
	seedInviteCode(t, pool, inviteCodeID1, inviteHashA, 3, 1000, 0)

	// 先用掉一次，留下「已核銷 1 次」的歷史。
	if _, err := pool.ExecContext(ctx,
		"UPDATE registration_invite_codes SET used_count = used_count + 1 WHERE id = ?", inviteCodeID1); err != nil {
		t.Fatalf("撤銷前的一次核銷應寫得進：%v", err)
	}
	// 撤銷那一刻寫得進（revoked_at 0→非零，且這是唯一被允許的寫入）。
	if _, err := pool.ExecContext(ctx,
		"UPDATE registration_invite_codes SET revoked_at = 2000 WHERE id = ?", inviteCodeID1); err != nil {
		t.Fatalf("撤銷應寫得進：%v", err)
	}

	// 撤銷後：改撤銷時刻、清回 0、再核銷，全部被終態觸發器擋下。
	expectAbort(t, pool, "撤銷態不得改判（換個撤銷時刻）",
		"UPDATE registration_invite_codes SET revoked_at = 3000 WHERE id = ?", inviteCodeID1)
	expectAbort(t, pool, "撤銷態不得重新生效（清回 0）",
		"UPDATE registration_invite_codes SET revoked_at = 0 WHERE id = ?", inviteCodeID1)
	expectAbort(t, pool, "已撤銷的碼不得再被核銷",
		"UPDATE registration_invite_codes SET used_count = used_count + 1 WHERE id = ?", inviteCodeID1)

	// 已核銷的歷史留住：撤銷不抹掉 used_count。
	var used, revoked int64
	if err := pool.QueryRowContext(ctx,
		"SELECT used_count, revoked_at FROM registration_invite_codes WHERE id = ?", inviteCodeID1).
		Scan(&used, &revoked); err != nil {
		t.Fatalf("讀回撤銷後的行失敗：%v", err)
	}
	if used != 1 || revoked != 2000 {
		t.Errorf("撤銷後應保留 used_count=1、revoked_at=2000，實際 %d/%d", used, revoked)
	}
}
