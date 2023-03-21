// members_test.go 驗收遷移 0014：activity_members 的持久形態。
//
// 四個驗收面各自對應本步的一句決定：
//  1. 增量遷移不傷既有事實（帳戶、會話、授予、審計、活動、指派、陣營逐字還在原處），
//     新表是空的、不回填任何東西——「從前有過成員」這種話不由遷移來說；
//  2. 本表對 accounts 沒有任何外鍵邊（只有指向 activities 與 activity_factions 的兩條硬邊）——
//     這是「成員表落地之後訪戶綁定仍然走得通」的結構依據（見 internal/stdacct/bindpreflight.go）；
//  3. 關係形態：UNIQUE (activity_id, account_id) 是「一個帳戶在一場活動裡只有一份檔案」，
//     跨活動各自獨立；暱稱長度與標識形态的 CHECK；身份三欄不可就地改寫；
//  4. 陣營歸屬的兩句話：可空（NULL 是「尚未分組」這個事實），而不空時必須屬於同一場活動——
//     後者外鍵看不見，由寫入與更新兩條觸發器補上。
package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
)

// 本檔使用的標識（全部是 36 字元的小寫 UUID 形狀，只服務本檔的 CHECK 取證）。
const (
	memActID1   = "0192f0c4-1c9a-7000-8000-000000000e01" // 合法活動一（既有事實裡那場 active 的活動）
	memActID2   = "0192f0c4-1c9a-7000-8000-000000000e02" // 合法活動二（跨活動各有一份檔案取證）
	memGhostAct = "0192f0c4-1c9a-7000-8000-000000000e09" // 從未存在的活動標識
	memFacID1   = "0192f0c4-1c9a-7000-8000-000000000e11" // 合法陣營一（屬活動一）
	memFacID2   = "0192f0c4-1c9a-7000-8000-000000000e12" // 合法陣營二（屬活動二，跨場拼接取證）
	memID1      = "0192f0c4-1c9a-7000-8000-000000000f01" // 合法成員一
	memID2      = "0192f0c4-1c9a-7000-8000-000000000f02" // 合法成員二
	memID3      = "0192f0c4-1c9a-7000-8000-000000000f03" // 合法成員三
	memGhostID  = "0192f0c4-1c9a-7000-8000-000000000f09" // 從未存在過的成員標識
)

// dbAt0014WithFacts 建出一座「既有 0013 事實、已套上 0014」的資料庫，
// 並在兩場活動下各種一個陣營供歸屬取證。
func dbAt0014WithFacts(t *testing.T) *sql.DB {
	t.Helper()
	pool, through13, only14 := dbAt0013WithFactsSplit(t)
	if _, err := applySet(context.Background(), pool, append(through13, only14...), Options{}); err != nil {
		t.Fatalf("套用 0014 失敗：%v", err)
	}
	// through13 已含到 0013 的全部版本，applySet 只會接著落地 0014 這一支。
	insertActivity(t, pool, memActID1, "第一場", "active", 5000, nil)
	insertActivity(t, pool, memActID2, "第二場", "draft", 5100, nil)
	insertFaction(t, pool, memFacID1, memActID1, "甲場的陣營", 0)
	insertFaction(t, pool, memFacID2, memActID2, "乙場的陣營", 0)
	return pool
}

// dbAt0013WithFactsSplit 復用 factions_test.go 的現場，回傳「到 0012（含既有活動事實）」
// 的池子、已套到 0013 的遷移清單，與 0014 本身兩段。
//
// 拆兩段的理由同 factions_test.go：applySet 對版本嚴格遞增把關，同一支套兩次就是它
// 當場報出的形態缺陷，所以「先套到 0013」與「再套 0014」必須各拿自己那一段。
func dbAt0013WithFactsSplit(t *testing.T) (*sql.DB, []Migration, []Migration) {
	t.Helper()
	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	var through13, only14 []Migration
	for _, m := range known {
		switch {
		case m.Version < 14:
			through13 = append(through13, m)
		case m.Version == 14:
			only14 = append(only14, m)
		}
	}
	if len(only14) != 1 {
		t.Fatalf("必須恰好一支 0014，實際 %d", len(only14))
	}
	// 池子由 activities_test.go 那條現場提供：它已套到 0012 並種好帳戶、授予與指派。
	// 這裡把 0013 接上（沿用 factions_test.go 的拆法：applySet 要拿到「到目標版本為止的
	// 完整清單」，只交一支 0014 會被它當成「版本表裡有它不認識的遷移」而報缺陷）。
	pool, through12, only13 := dbAt0012WithFactsSplit(t)
	if _, err := applySet(context.Background(), pool, append(through12, only13...), Options{}); err != nil {
		t.Fatalf("先套到 0013 失敗：%v", err)
	}
	return pool, through13, only14
}

// insertMember 以合法形態寫入一行成員身份（陣營歸屬留 NULL），呼叫端再從這裡出發去踩各條非法形態。
func insertMember(t *testing.T, pool *sql.DB, id, activityID, accountID, nickname string) {
	t.Helper()
	_, err := pool.ExecContext(context.Background(), `INSERT INTO activity_members
			(id, activity_id, account_id, nickname, created_at, updated_at)
		VALUES (?, ?, ?, ?, 7000, 7000)`, id, activityID, accountID, nickname)
	if err != nil {
		t.Fatalf("種下合法成員 %s 失敗：%v", id, err)
	}
}

// TestMemberMigrationKeepsEveryOldFact 驗收：0014 只加一張新表，舊的行逐字在原處。
func TestMemberMigrationKeepsEveryOldFact(t *testing.T) {
	ctx := context.Background()
	pool, through13, only14 := dbAt0013WithFactsSplit(t)

	// 先種下 0013 的既有事實：一場活動、一位管理人、一個陣營（「既有成員」今天的真實形態
	// 就是這些——本支遷移之前庫裡沒有一行成員可留）。
	insertActivity(t, pool, memActID1, "遷移前的活動", "active", 5000, nil)
	if _, err := pool.ExecContext(ctx, `INSERT INTO activity_manager_grants
			(activity_id, account_id, granted_at) VALUES (?, ?, 5050)`,
		memActID1, actCreatorID); err != nil {
		t.Fatalf("種下遷移前的指派行失敗：%v", err)
	}
	insertFaction(t, pool, memFacID1, memActID1, "遷移前的陣營", 0)

	accountsBefore := factsSnapshot(t, pool)
	if !strings.Contains(accountsBefore, "accounts") {
		t.Fatalf("快照裡必須看得到既有帳戶行，實際為空表示佈資料沒生效")
	}
	factionsBefore := snapshotRows(t, pool, "activity_factions")
	grantsBefore := snapshotRows(t, pool, "activity_manager_grants")

	if _, err := applySet(ctx, pool, append(through13, only14...), Options{}); err != nil {
		t.Fatalf("套用 0014 失敗：%v", err)
	}

	if after := factsSnapshot(t, pool); after != accountsBefore {
		t.Errorf("0014 改寫了帳戶側既有事實：\n舊 %s\n新 %s", after, accountsBefore)
	}
	if after := snapshotRows(t, pool, "activity_factions"); after != factionsBefore {
		t.Errorf("0014 改寫了陣營側既有事實：\n舊 %s\n新 %s", after, factionsBefore)
	}
	if after := snapshotRows(t, pool, "activity_manager_grants"); after != grantsBefore {
		t.Errorf("0014 改寫了指派側既有事實：\n舊 %s\n新 %s", after, grantsBefore)
	}

	// 新表存在且是空的：本支遷移不做任何回填（回填等於偽造「從前有過成員」）。
	if found, err := tableExists(ctx, pool, "activity_members"); err != nil || !found {
		t.Fatalf("0014 應建出 activity_members（found=%v err=%v）", found, err)
	}
	if got := mustCount(t, pool, "SELECT COUNT(*) FROM activity_members"); got != 0 {
		t.Errorf("activity_members 遷移後必須是空的，實際 %d 行", got)
	}
	if got := mustCount(t, pool, "SELECT COUNT(*) FROM schema_migrations WHERE version = 14"); got != 1 {
		t.Errorf("0014 應留下一筆版本記錄，實際 %d 筆", got)
	}
	var header int
	if err := pool.QueryRowContext(ctx, "PRAGMA user_version").Scan(&header); err != nil {
		t.Fatalf("讀檔頭版本失敗：%v", err)
	}
	if header != 14 {
		t.Errorf("檔頭版本應推進到 14，實際 %d", header)
	}
}

// snapshotRows 把一張表的全部行讀成一段可比較文本（逐字對照「遷移有沒有動舊行」）。
func snapshotRows(t *testing.T, pool *sql.DB, table string) string {
	t.Helper()
	rows, err := pool.QueryContext(context.Background(), "SELECT * FROM "+table+" ORDER BY rowid")
	if err != nil {
		t.Fatalf("讀取 %s 的現況失敗：%v", table, err)
	}
	defer rows.Close()
	var out strings.Builder
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("讀取 %s 的欄位失敗：%v", table, err)
	}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("解析 %s 的行失敗：%v", table, err)
		}
		for i, v := range vals {
			out.WriteString(cols[i] + "=" + stringifyCell(v) + "|")
		}
		out.WriteString("\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("讀取 %s 的現況失敗：%v", table, err)
	}
	return out.String()
}

// stringifyCell 把一格值換成穩定文本（[]byte 按字串讀，NULL 讀成明確的記號）。
func stringifyCell(v any) string {
	switch cell := v.(type) {
	case nil:
		return "<null>"
	case []byte:
		return string(cell)
	case string:
		return cell
	default:
		return fmt.Sprintf("%v", cell)
	}
}

// TestMemberAccountEdgesAreSoftReference 驗收：成員表只有兩條硬外鍵邊（activities 與
// activity_factions），對 accounts 沒有任何邊——「成員表落地之後訪戶綁定仍然走得通」
// 這句話的結構依據，也是它不進 bindpreflight 硬引用登記表的理由。
func TestMemberAccountEdgesAreSoftReference(t *testing.T) {
	pool := dbAt0014WithFacts(t)

	rows, err := pool.QueryContext(context.Background(),
		`SELECT "table" FROM pragma_foreign_key_list(?) ORDER BY id`, "activity_members")
	if err != nil {
		t.Fatalf("讀取 activity_members 的外鍵邊失敗：%v", err)
	}
	defer rows.Close()
	var edges []string
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			t.Fatalf("解析外鍵邊失敗：%v", err)
		}
		edges = append(edges, target)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("讀取外鍵邊失敗：%v", err)
	}
	if len(edges) != 2 {
		t.Errorf("成員表應恰有兩條硬外鍵邊（對 accounts 無邊），實際 %v", edges)
	}
	// 順序不是斷言的對象（pragma_foreign_key_list 的回傳序不承擔合同）：要問的是「有哪兩條邊、
	// 以及有沒有一條指向 accounts」——後者才是綁定通路能否走通的那一句話。
	sawActivities, sawFactions, sawAccounts := false, false, false
	for _, edge := range edges {
		switch edge {
		case "activities":
			sawActivities = true
		case "activity_factions":
			sawFactions = true
		case "accounts":
			sawAccounts = true
		}
	}
	if !sawActivities || !sawFactions || sawAccounts {
		t.Errorf("兩條邊必須是 activities 與 activity_factions，且對 accounts 必須無邊，實際 %v", edges)
	}

	// 軟參照的代價與取捨在這裡如實取證：庫外標識在 SQL 層寫得進去（那是軟參照的定義），
	// 攔住它的是服務層的資格核實（見 internal/activity/members.go），不是這一層。
	if _, err := pool.ExecContext(context.Background(), `INSERT INTO activity_members
			(id, activity_id, account_id, nickname, created_at, updated_at)
		VALUES (?, ?, ?, '軟參照的幽靈', 7000, 7000)`,
		memID3, memActID1, memGhostID); err != nil {
		t.Errorf("軟參照欄位按定義不該被外鍵擋下（把關在服務層）：%v", err)
	}
	// 指向不存在活動的成員行寫不進（硬外鍵把關）。
	expectAbort(t, pool, "指向不存在活動的成員行",
		`INSERT INTO activity_members (id, activity_id, account_id, nickname, created_at, updated_at)
		VALUES (?, ?, ?, '幽靈下的成員', 7000, 7000)`, "0192f0c4-1c9a-7000-8000-000000000f04",
		memGhostAct, actCreatorID)
}

// TestMemberRelationshipRules 驗收：一個帳戶在一場活動裡只有一份檔案（同活動重複即拒）、
// 跨活動各自獨立、暱稱的長度與形態界線，以及身份三欄不可就地改寫。
func TestMemberRelationshipRules(t *testing.T) {
	pool := dbAt0014WithFacts(t)
	insertMember(t, pool, memID1, memActID1, actCreatorID, "唯一的檔案")

	// 同活動同帳戶的第二行：UNIQUE (activity_id, account_id) 當場擋下。
	expectAbort(t, pool, "同活動同帳戶的第二份檔案",
		`INSERT INTO activity_members (id, activity_id, account_id, nickname, created_at, updated_at)
		VALUES (?, ?, ?, '第二次提交', 7000, 7000)`, memID2, memActID1, actCreatorID)
	// 同一個人在另一場活動裡：完全合法，兩份檔案互不相干。
	insertMember(t, pool, memID2, memActID2, actCreatorID, "乙場的檔案")
	// 同活動另一個帳戶、同名暱稱：合法（用戶批准：暱稱不施加唯一約束）。
	insertMember(t, pool, memID3, memActID1, v10GuestID, "唯一的檔案")

	illegal := []struct {
		what string
		sql  string
		args []any
	}{
		{"空暱稱", `INSERT INTO activity_members (id, activity_id, account_id, nickname, created_at, updated_at)
			VALUES (?, ?, ?, '', 7000, 7000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f11", memActID1, actCreatorID}},
		{"超長暱稱", `INSERT INTO activity_members (id, activity_id, account_id, nickname, created_at, updated_at)
			VALUES (?, ?, ?, ?, 7000, 7000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f12", memActID1, v10ActiveID, strings.Repeat("長", 65)}},
		{"不合法形狀的成員標識", `INSERT INTO activity_members (id, activity_id, account_id, nickname, created_at, updated_at)
			VALUES ('not-a-uuid', ?, ?, '正常', 7000, 7000)`,
			[]any{memActID1, "0192f0c4-1c9a-7000-8000-000000000f13"}},
		{"缺欄位的成員標識", `INSERT INTO activity_members (id, activity_id, account_id, nickname, created_at, updated_at)
			VALUES ('0192f0c4-1c9a-7000-8000-000000000f1', ?, ?, '正常', 7000, 7000)`,
			[]any{memActID1, "0192f0c4-1c9a-7000-8000-000000000f14"}},
		{"更新時刻早於建立時刻", `INSERT INTO activity_members (id, activity_id, account_id, nickname, created_at, updated_at)
			VALUES (?, ?, ?, '正常', 7000, 6999)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f15", memActID1, "0192f0c4-1c9a-7000-8000-000000000f16"}},
		{"不合法形狀的陣營標識", `INSERT INTO activity_members (id, activity_id, account_id, nickname, faction_id, created_at, updated_at)
			VALUES (?, ?, ?, '正常', 'nope', 7000, 7000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f17", memActID1, "0192f0c4-1c9a-7000-8000-000000000f18"}},
	}
	for _, tc := range illegal {
		if _, err := pool.ExecContext(context.Background(), tc.sql, tc.args...); err == nil {
			t.Errorf("%s：這條寫入應該被資料庫擋下，實際寫成功了", tc.what)
		}
	}

	// 身份三欄不可就地改寫：改任何一欄都等於換了一個主體，而暱稱照樣能改。
	expectAbort(t, pool, "改成員主鍵",
		`UPDATE activity_members SET id = ? WHERE id = ?`, "0192f0c4-1c9a-7000-8000-000000000f21", memID1)
	expectAbort(t, pool, "改成員所屬活動",
		`UPDATE activity_members SET activity_id = ? WHERE id = ?`, memActID2, memID1)
	expectAbort(t, pool, "改成員指向的帳戶",
		`UPDATE activity_members SET account_id = ? WHERE id = ?`, v10ActiveID, memID1)
	if _, err := pool.ExecContext(context.Background(), `UPDATE activity_members
			SET nickname = '改過的名字', updated_at = 7500 WHERE id = ?`, memID1); err != nil {
		t.Errorf("暱稱與時刻應能正常更新：%v", err)
	}

	// 活動歸檔不刪成員行：終態的「仍列、可讀」由行的存在性支撐（本表沒有刪除通路）。
	if _, err := pool.ExecContext(context.Background(), `UPDATE activities
			SET status = 'archived', archived_at = 7600, updated_at = 7600 WHERE id = ?`,
		memActID1); err != nil {
		t.Fatalf("合法活動應能進入歸檔態：%v", err)
	}
	if got := mustCount(t, pool,
		"SELECT COUNT(*) FROM activity_members WHERE activity_id = ?", memActID1); got < 1 {
		t.Errorf("歸檔後成員行仍要在原處（仍列、可讀、拒寫），實際 %d 行", got)
	}
}

// TestMemberFactionBelongsToSameActivity 驗收：陣營歸屬可空（NULL 是「尚未分組」），
// 而不空時必須與本行同屬一場活動——外鍵只看「那個陣營存不存在」，跨活動拼接由兩條觸發器擋下。
func TestMemberFactionBelongsToSameActivity(t *testing.T) {
	pool := dbAt0014WithFacts(t)

	// 合法歸屬：甲場活動的成員指向甲場的陣營。
	if _, err := pool.ExecContext(context.Background(), `INSERT INTO activity_members
			(id, activity_id, account_id, nickname, faction_id, created_at, updated_at)
		VALUES (?, ?, ?, '同場的成員', ?, 7000, 7000)`,
		memID1, memActID1, actCreatorID, memFacID1); err != nil {
		t.Errorf("同活動的陣營歸屬應能寫入：%v", err)
	}
	// 跨活動拼接：乙場的陣營寫進甲場的成員行，觸發器當場擋下（外鍵看不见這一句）。
	expectAbort(t, pool, "把另一場活動的陣營寫進建立語句",
		`INSERT INTO activity_members (id, activity_id, account_id, nickname, faction_id, created_at, updated_at)
		VALUES (?, ?, ?, '跨場的成員', ?, 7000, 7000)`, memID2, memActID1, v10ActiveID, memFacID2)
	// 指向從未存在的陣營：硬外鍵擋下（與跨活動是兩句話，各證各的）。
	expectAbort(t, pool, "指向不存在陣營",
		`INSERT INTO activity_members (id, activity_id, account_id, nickname, faction_id, created_at, updated_at)
		VALUES (?, ?, ?, '幽靈陣營', ?, 7000, 7000)`,
		"0192f0c4-1c9a-7000-8000-000000000f31", memActID1, "0192f0c4-1c9a-7000-8000-000000000f32", memGhostID)

	// 更新那一跳同樣成立：日后的分配通路走 UPDATE faction_id，跨場拼接在這裡就被擋。
	if _, err := pool.ExecContext(context.Background(), `UPDATE activity_members
			SET faction_id = ? WHERE id = ?`, memFacID1, memID1); err != nil {
		t.Errorf("同活動的陣營改派應能寫入：%v", err)
	}
	expectAbort(t, pool, "把另一場活動的陣營改派進來",
		`UPDATE activity_members SET faction_id = ? WHERE id = ?`, memFacID2, memID1)

	// 改回 NULL 是合法的：遷出到「尚未分組」不該被資料庫擋住（用戶批准：允許無陣營）。
	if _, err := pool.ExecContext(context.Background(), `UPDATE activity_members
			SET faction_id = NULL, updated_at = 7600 WHERE id = ?`, memID1); err != nil {
		t.Errorf("把陣營歸屬清空應能寫入：%v", err)
	}
}
