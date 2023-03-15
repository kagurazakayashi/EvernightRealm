// factions_test.go 驗收遷移 0013：activity_factions 的持久形態。
//
// 四個驗收面各自對應本步的一句決定：
//  1. 增量遷移不傷既有事實（帳戶、會話、授予、審計逐字還在原處，已落的活動與指派行
//     也原封不動——「不破壞既有成員」在今天的真實形態就是不破壞既有活動與管理人），
//     新表是空的、不回填任何東西；
//  2. 本表對 accounts 沒有任何外鍵邊（只有對 activities 的一條硬外鍵）——這是
//     「訪戶綁定預檢不會把陣營表當成未登記引用」的結構依據（見 internal/stdacct/bindpreflight.go）；
//  3. 名稱規則（同活動內 UNIQUE、跨活動同名合法）與圖標／顏色／排序／可用性的封閉形态；
//  4. 身份與歸屬不可就地改寫（觸發器），其余欄位可正常 UPDATE，本表沒有刪除通路的結構必要性。
package migrate

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// 本檔使用的標識（全部是 36 字元的小寫 UUID 形狀，只服務本檔的 CHECK 取證）。
const (
	facActID1  = "0192f0c4-1c9a-7000-8000-000000000e01" // 合法活動一（陣營的歸屬）
	facActID2  = "0192f0c4-1c9a-7000-8000-000000000e02" // 合法活動二（跨活動同名取證）
	facGhostID = "0192f0c4-1c9a-7000-8000-000000000e09" // 從未存在的活動標識
	facID1     = "0192f0c4-1c9a-7000-8000-000000000e11" // 合法陣營一
	facID2     = "0192f0c4-1c9a-7000-8000-000000000e12" // 合法陣營二
	facID3     = "0192f0c4-1c9a-7000-8000-000000000e13" // 合法陣營三
)

// dbAt0013WithFacts 建出一座「既有 0012 事實、已套上 0013」的資料庫，
// 並種下兩場活動供陣營行挂靠。
func dbAt0013WithFacts(t *testing.T) *sql.DB {
	t.Helper()
	pool, through12, only13 := dbAt0012WithFactsSplit(t)
	if _, err := applySet(context.Background(), pool, append(through12, only13...), Options{}); err != nil {
		t.Fatalf("套用 0013 失敗：%v", err)
	}
	insertActivity(t, pool, facActID1, "第一場", "active", 5000, nil)
	insertActivity(t, pool, facActID2, "第二場", "draft", 5100, nil)
	return pool
}

// dbAt0012WithFactsSplit 復用 activities_test.go 的現場並拆出「到 0012」與「0013 本身」兩段。
func dbAt0012WithFactsSplit(t *testing.T) (*sql.DB, []Migration, []Migration) {
	t.Helper()
	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	var through12, only13 []Migration
	for _, m := range known {
		switch {
		case m.Version < 13:
			through12 = append(through12, m)
		case m.Version == 13:
			only13 = append(only13, m)
		}
	}
	if len(only13) != 1 {
		t.Fatalf("必須恰好一支 0013，實際 %d", len(only13))
	}
	pool, through11, only12 := dbAt0011WithFacts(t)
	if _, err := applySet(context.Background(), pool, append(through11, only12...), Options{}); err != nil {
		t.Fatalf("先套用 0012 失敗：%v", err)
	}
	// through12 自迴圈已含 0012（Version < 13 的全部），不能再把 only12 接一次——
	// applySet 對版本嚴格遞增把關，重複一支就是它當場報出的形態缺陷。
	return pool, through12, only13
}

// insertFaction 以合法形態寫入一行陣營，呼叫端再從這裡出發去踩各條非法形態。
func insertFaction(t *testing.T, pool *sql.DB, id, activityID, name string, sortOrder int64) {
	t.Helper()
	_, err := pool.ExecContext(context.Background(), `INSERT INTO activity_factions
			(id, activity_id, name, description, icon, color, sort_order, available, created_at, updated_at)
		VALUES (?, ?, ?, '', '', '', ?, 1, 6000, 6000)`, id, activityID, name, sortOrder)
	if err != nil {
		t.Fatalf("種下合法陣營 %s 失敗：%v", id, err)
	}
}

// TestFactionMigrationKeepsEveryOldFact 驗收：0013 只加一張新表，舊的行逐字在原處。
func TestFactionMigrationKeepsEveryOldFact(t *testing.T) {
	ctx := context.Background()
	pool, through12, only13 := dbAt0012WithFactsSplit(t)

	// 先種下 0012 的既有事實：一場活動與它的一位管理人（「既有成員」今天的真實形態）。
	insertActivity(t, pool, facActID1, "遷移前的活動", "active", 5000, nil)
	if _, err := pool.ExecContext(ctx, `INSERT INTO activity_manager_grants
			(activity_id, account_id, granted_at) VALUES (?, ?, 5050)`,
		facActID1, actCreatorID); err != nil {
		t.Fatalf("種下遷移前的指派行失敗：%v", err)
	}

	accountsBefore := factsSnapshot(t, pool)
	if !strings.Contains(accountsBefore, "accounts") {
		t.Fatalf("快照裡必須看得到既有帳戶行，實際為空表示佈資料沒生效")
	}
	var actNameBefore, grantAccountBefore string
	if err := pool.QueryRowContext(ctx, "SELECT name FROM activities WHERE id = ?", facActID1).
		Scan(&actNameBefore); err != nil {
		t.Fatalf("讀遷移前的活動失敗：%v", err)
	}
	if err := pool.QueryRowContext(ctx,
		"SELECT account_id FROM activity_manager_grants WHERE activity_id = ?", facActID1).
		Scan(&grantAccountBefore); err != nil {
		t.Fatalf("讀遷移前的指派失敗：%v", err)
	}

	if _, err := applySet(ctx, pool, append(through12, only13...), Options{}); err != nil {
		t.Fatalf("套用 0013 失敗：%v", err)
	}

	if after := factsSnapshot(t, pool); after != accountsBefore {
		t.Errorf("0013 改寫了帳戶側既有事實：\n舊 %s\n新 %s", after, accountsBefore)
	}
	var actNameAfter, grantAccountAfter string
	if err := pool.QueryRowContext(ctx, "SELECT name FROM activities WHERE id = ?", facActID1).
		Scan(&actNameAfter); err != nil {
		t.Fatalf("套 0013 後讀活動失敗：%v", err)
	}
	if err := pool.QueryRowContext(ctx,
		"SELECT account_id FROM activity_manager_grants WHERE activity_id = ?", facActID1).
		Scan(&grantAccountAfter); err != nil {
		t.Fatalf("套 0013 後讀指派失敗：%v", err)
	}
	if actNameAfter != actNameBefore || grantAccountAfter != grantAccountBefore {
		t.Errorf("0013 改寫了活動側既有事實（%q→%q／%q→%q）",
			actNameBefore, actNameAfter, grantAccountBefore, grantAccountAfter)
	}

	// 新表存在且是空的：本支遷移不做任何回填（回填等於偽造「從前有過陣營」）。
	if found, err := tableExists(ctx, pool, "activity_factions"); err != nil || !found {
		t.Fatalf("0013 應建出 activity_factions（found=%v err=%v）", found, err)
	}
	if got := mustCount(t, pool, "SELECT COUNT(*) FROM activity_factions"); got != 0 {
		t.Errorf("activity_factions 遷移後必須是空的，實際 %d 行", got)
	}
	if got := mustCount(t, pool, "SELECT COUNT(*) FROM schema_migrations WHERE version = 13"); got != 1 {
		t.Errorf("0013 應留下一筆版本記錄，實際 %d 筆", got)
	}
	var header int
	if err := pool.QueryRowContext(ctx, "PRAGMA user_version").Scan(&header); err != nil {
		t.Fatalf("讀檔頭版本失敗：%v", err)
	}
	if header != 13 {
		t.Errorf("檔頭版本應推進到 13，實際 %d", header)
	}
}

// TestFactionAccountEdgesAreAbsent 驗收：陣營表只有一條指向 activities 的硬外鍵邊，
// 對 accounts 沒有任何邊——「陣營落地之後訪戶綁定仍然走得通」這句話的結構依據。
func TestFactionAccountEdgesAreAbsent(t *testing.T) {
	pool := dbAt0013WithFacts(t)

	rows, err := pool.QueryContext(context.Background(),
		`SELECT "table" FROM pragma_foreign_key_list(?) ORDER BY id`, "activity_factions")
	if err != nil {
		t.Fatalf("讀取 activity_factions 的外鍵邊失敗：%v", err)
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
	if len(edges) != 1 || edges[0] != "activities" {
		t.Errorf("陣營表應只有一條指向 activities 的硬外鍵邊（對 accounts 無邊），實際 %v", edges)
	}

	// 指向不存在活動的陣營行寫不進（硬外鍵把關）；合法歸屬寫得進。
	expectAbort(t, pool, "指向不存在活動的陣營行",
		`INSERT INTO activity_factions (id, activity_id, name, created_at, updated_at)
		VALUES (?, ?, '幽靈下的陣營', 6000, 6000)`, facID1, facGhostID)
	insertFaction(t, pool, facID1, facActID1, "合法的陣營", 0)
}

// TestFactionShapeRules 驗收：同活動名稱唯一、跨活動同名合法，
// 以及圖標／顏色／排序／可用性／長度每一種湊得出來但無法解釋的形態都被擋。
func TestFactionShapeRules(t *testing.T) {
	pool := dbAt0013WithFacts(t)
	insertFaction(t, pool, facID1, facActID1, "黎明軍", 0)

	// 同活動內的第二個同名：UNIQUE (activity_id, name) 當場擋下。
	expectAbort(t, pool, "同活動內重名",
		`INSERT INTO activity_factions (id, activity_id, name, created_at, updated_at)
		VALUES (?, ?, '黎明軍', 6000, 6000)`, facID2, facActID1)
	// 另一場活動同名：完全合法，兩場活動互不相干。
	if _, err := pool.ExecContext(context.Background(), `INSERT INTO activity_factions
			(id, activity_id, name, created_at, updated_at) VALUES (?, ?, '黎明軍', 6000, 6000)`,
		facID2, facActID2); err != nil {
		t.Errorf("跨活動同名陣營應能寫入：%v", err)
	}

	illegal := []struct {
		what string
		sql  string
		args []any
	}{
		{"空名稱", `INSERT INTO activity_factions (id, activity_id, name, created_at, updated_at)
			VALUES (?, ?, '', 6000, 6000)`, []any{"0192f0c4-1c9a-7000-8000-000000000e21", facActID1}},
		{"超長名稱", `INSERT INTO activity_factions (id, activity_id, name, created_at, updated_at)
			VALUES (?, ?, ?, 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000e22", facActID1, strings.Repeat("長", 65)}},
		{"超長描述", `INSERT INTO activity_factions (id, activity_id, name, description, created_at, updated_at)
			VALUES (?, ?, '正常', ?, 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000e23", facActID1, strings.Repeat("字", 501)}},
		{"封閉集合外的圖標", `INSERT INTO activity_factions (id, activity_id, name, icon, created_at, updated_at)
			VALUES (?, ?, '正常', 'dragon', 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000e24", facActID1}},
		{"顏色缺井", `INSERT INTO activity_factions (id, activity_id, name, color, created_at, updated_at)
			VALUES (?, ?, '正常', 'ff0000', 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000e25", facActID1}},
		{"顏色位數不對", `INSERT INTO activity_factions (id, activity_id, name, color, created_at, updated_at)
			VALUES (?, ?, '正常', '#ff000', 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000e26", facActID1}},
		{"顏色含非十六進位", `INSERT INTO activity_factions (id, activity_id, name, color, created_at, updated_at)
			VALUES (?, ?, '正常', '#ff000g', 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000e27", facActID1}},
		{"排序值為負", `INSERT INTO activity_factions (id, activity_id, name, sort_order, created_at, updated_at)
			VALUES (?, ?, '正常', -1, 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000e28", facActID1}},
		{"排序值越上界", `INSERT INTO activity_factions (id, activity_id, name, sort_order, created_at, updated_at)
			VALUES (?, ?, '正常', 100000, 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000e29", facActID1}},
		{"可用性不是布林形態", `INSERT INTO activity_factions (id, activity_id, name, available, created_at, updated_at)
			VALUES (?, ?, '正常', 2, 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000e2a", facActID1}},
		{"更新時刻早於建立時刻", `INSERT INTO activity_factions (id, activity_id, name, created_at, updated_at)
			VALUES (?, ?, '正常', 6000, 5999)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000e2b", facActID1}},
		{"不合法形狀的陣營標識", `INSERT INTO activity_factions (id, activity_id, name, created_at, updated_at)
			VALUES ('not-a-uuid', ?, '正常', 6000, 6000)`, []any{facActID1}},
	}
	for _, tc := range illegal {
		if _, err := pool.ExecContext(context.Background(), tc.sql, tc.args...); err == nil {
			t.Errorf("%s：這條寫入應該被資料庫擋下，實際寫成功了", tc.what)
		}
	}

	// 合法形態收個尾：封閉集合內的圖標、大寫十六進位顏色、邊界排序值與停用旗標。
	if _, err := pool.ExecContext(context.Background(), `INSERT INTO activity_factions
			(id, activity_id, name, icon, color, sort_order, available, created_at, updated_at)
		VALUES (?, ?, '邊界合法', 'anchor', '#AABBCC', 99999, 0, 6000, 6000)`,
		facID3, facActID1); err != nil {
		t.Errorf("各欄合法邊界形態應能寫入：%v", err)
	}
}

// TestFactionIdentityAndBelongingImmutable 驗收：標識與歸屬不可就地改寫，
// 白名單資料欄可以正常改，且本表沒有「把陣營連同歷史搬去另一場活動」的表達方式。
func TestFactionIdentityAndBelongingImmutable(t *testing.T) {
	pool := dbAt0013WithFacts(t)
	insertFaction(t, pool, facID1, facActID1, "不動身份的陣營", 0)

	expectAbort(t, pool, "改陣營主鍵",
		`UPDATE activity_factions SET id = ? WHERE id = ?`, facID2, facID1)
	expectAbort(t, pool, "改陣營歸屬活動",
		`UPDATE activity_factions SET activity_id = ? WHERE id = ?`, facActID2, facID1)

	// 其余欄位照常可改：觸發器擋的只有那兩欄，不是整張表凍結。
	if _, err := pool.ExecContext(context.Background(), `UPDATE activity_factions
			SET name = '改過名', available = 0, sort_order = 7, updated_at = 6500 WHERE id = ?`,
		facID1); err != nil {
		t.Errorf("白名單資料欄應能正常更新：%v", err)
	}

	// 活動歸檔不刪陣營行：終態的「仍列、可讀」由行的存在性支撐（本表沒有刪除通路）。
	if _, err := pool.ExecContext(context.Background(), `UPDATE activities
			SET status = 'archived', archived_at = 6600, updated_at = 6600 WHERE id = ?`,
		facActID1); err != nil {
		t.Fatalf("合法活動應能進入歸檔態：%v", err)
	}
	if got := mustCount(t, pool,
		"SELECT COUNT(*) FROM activity_factions WHERE activity_id = ?", facActID1); got != 1 {
		t.Errorf("歸檔後陣營行仍要在原處（仍列、可讀、拒寫），實際 %d 行", got)
	}
}
