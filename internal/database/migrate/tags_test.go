// tags_test.go 驗收遷移 0017：activity_tags 的持久形態。
//
// 四個驗收面各自對應本步的一句決定：
//  1. 增量遷移不傷既有事實（帳戶、活動、指派、陣營、成員逐字還在原處，0016 那兩欄的現值
//     也一個字沒動），新表是空的、不回填任何東西——「從前有過標籤」這種話不由遷移來說；
//  2. 本表對 accounts 沒有任何外鍵邊（只有指向 activities 的一條硬邊）——這是
//     「標籤表落地之後訪戶綁定仍然走得通、也不需要進 bindpreflight 的引用登記表」的結構依據；
//  3. 名稱規則（同活動內 UNIQUE、跨活動同名合法）與圖標／顏色／排序／可用性／公開的封閉形態，
//     以及兩格旗標的出廠值（available=1、public=0）：新建即內部這件事有資料庫那一端的默認值撐著；
//  4. 身份與歸屬不可就地改寫（觸發器），其餘欄位可正常 UPDATE，本表沒有刪除通路的結構必要性。
package migrate

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// 本檔使用的標識（全部是 36 字元的小寫 UUID 形狀，只服務本檔的 CHECK 取證）。
const (
	tagActID1  = "0192f0c4-1c9a-7000-8000-000000000e01" // 合法活動一（標籤的歸屬）
	tagActID2  = "0192f0c4-1c9a-7000-8000-000000000e02" // 合法活動二（跨活動同名取證）
	tagGhostID = "0192f0c4-1c9a-7000-8000-000000000e09" // 從未存在的活動標識
	tagID1     = "0192f0c4-1c9a-7000-8000-000000000f11" // 合法標籤一
	tagID2     = "0192f0c4-1c9a-7000-8000-000000000f12" // 合法標籤二
	tagID3     = "0192f0c4-1c9a-7000-8000-000000000f13" // 合法標籤三
	tagID4     = "0192f0c4-1c9a-7000-8000-000000000f14" // 合法標籤四
)

// knownSplitTo0017 把內嵌遷移拆成「到 0016 為止的全部」與「0017 本身」兩段。
//
// 拆兩段與 0016 那一步同一理由：applySet 對版本嚴格遞增把關，而本檔需要一座
// 「0017 還沒落地」的資料庫才能先取既有事實的快照。比 0017 更新的版本不在此列
// （日后的遷移不該回頭讓本檔變紅）。
func knownSplitTo0017(t *testing.T) (through16, only17 []Migration) {
	t.Helper()
	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	for _, m := range known {
		switch {
		case m.Version < 17:
			through16 = append(through16, m)
		case m.Version == 17:
			only17 = append(only17, m)
		}
	}
	if len(only17) != 1 {
		t.Fatalf("必須恰好一支 0017，實際 %d", len(only17))
	}
	return through16, only17
}

// dbAt0017WithFacts 建出一座「既有 0016 事實、已套上 0017」的資料庫。
//
// 現場複用 0016 那一步的池子（兩場活動、兩個陣營、兩行成員，其中一行已分組），
// 於是「加了標籤表之後，活動／陣營／成員／帳戶那一側一個字都沒動」這一句有可比對的舊值。
func dbAt0017WithFacts(t *testing.T) *sql.DB {
	t.Helper()
	pool := dbAt0015WithDirectoryFacts(t)
	through16, only17 := knownSplitTo0017(t)
	if _, err := applySet(context.Background(), pool, append(through16, only17...), Options{}); err != nil {
		t.Fatalf("套用 0016 與 0017 失敗：%v", err)
	}
	return pool
}

// insertTag 以合法形態寫入一行標籤，呼叫端再從這裡出發去踩各條非法形態。
func insertTag(t *testing.T, pool *sql.DB, id, activityID, name string, sortOrder int64) {
	t.Helper()
	_, err := pool.ExecContext(context.Background(), `INSERT INTO activity_tags
			(id, activity_id, name, description, icon, color, sort_order, created_at, updated_at)
		VALUES (?, ?, ?, '', '', '', ?, 6000, 6000)`, id, activityID, name, sortOrder)
	if err != nil {
		t.Fatalf("種下合法標籤 %s 失敗：%v", id, err)
	}
}

// TestTagMigrationKeepsEveryOldFact 驗收：0017 只加一張新表，舊的行逐字在原處。
func TestTagMigrationKeepsEveryOldFact(t *testing.T) {
	ctx := context.Background()
	pool := dbAt0015WithDirectoryFacts(t)
	through16, only17 := knownSplitTo0017(t)
	// 先把 0016 落地再取快照：本檔要比對的「既有事實」包含 0016 那兩欄的現值，
	// 而那座池子此刻還在 0015（那兩欄還不存在的時候讀它們不是舊值，是查無此欄）。
	if _, err := applySet(ctx, pool, through16, Options{}); err != nil {
		t.Fatalf("先套到 0016 失敗：%v", err)
	}

	accountsBefore := factsSnapshot(t, pool)
	if !strings.Contains(accountsBefore, "accounts") {
		t.Fatalf("快照裡必須看得到既有帳戶行，實際為空表示佈資料沒生效")
	}
	factionsBefore := snapshotRows(t, pool, "activity_factions")
	membersBefore := directoryMemberFacts(t, pool)
	var actNameBefore, dirModeBefore string
	if err := pool.QueryRowContext(ctx, "SELECT name FROM activities WHERE id = ?", tagActID1).
		Scan(&actNameBefore); err != nil {
		t.Fatalf("讀遷移前的活動失敗：%v", err)
	}
	if err := pool.QueryRowContext(ctx,
		"SELECT member_directory_mode FROM activities WHERE id = ?", tagActID1).
		Scan(&dirModeBefore); err != nil {
		t.Fatalf("讀遷移前的目錄模式失敗：%v", err)
	}

	if _, err := applySet(ctx, pool, append(through16, only17...), Options{}); err != nil {
		t.Fatalf("套用 0017 失敗：%v", err)
	}

	if after := factsSnapshot(t, pool); after != accountsBefore {
		t.Errorf("0017 改寫了帳戶側既有事實：\n舊 %s\n新 %s", after, accountsBefore)
	}
	if after := snapshotRows(t, pool, "activity_factions"); after != factionsBefore {
		t.Errorf("0017 改寫了陣營側既有事實：\n舊 %s\n新 %s", after, factionsBefore)
	}
	if after := directoryMemberFacts(t, pool); after != membersBefore {
		t.Errorf("0017 改寫了成員側既有事實：\n舊 %s\n新 %s", after, membersBefore)
	}
	var actNameAfter, dirModeAfter string
	if err := pool.QueryRowContext(ctx, "SELECT name FROM activities WHERE id = ?", tagActID1).
		Scan(&actNameAfter); err != nil {
		t.Fatalf("套 0017 後讀活動失敗：%v", err)
	}
	if err := pool.QueryRowContext(ctx,
		"SELECT member_directory_mode FROM activities WHERE id = ?", tagActID1).
		Scan(&dirModeAfter); err != nil {
		t.Fatalf("套 0017 後讀目錄模式失敗：%v", err)
	}
	if actNameAfter != actNameBefore || dirModeAfter != dirModeBefore {
		t.Errorf("0017 改寫了活動側既有事實（%q→%q／%q→%q）",
			actNameBefore, actNameAfter, dirModeBefore, dirModeAfter)
	}

	// 新表存在且是空的：本支遷移不做任何回填（回填等於偽造「從前有過標籤」）。
	if found, err := tableExists(ctx, pool, "activity_tags"); err != nil || !found {
		t.Fatalf("0017 應建出 activity_tags（found=%v err=%v）", found, err)
	}
	if got := mustCount(t, pool, "SELECT COUNT(*) FROM activity_tags"); got != 0 {
		t.Errorf("activity_tags 遷移後必須是空的，實際 %d 行", got)
	}
	if got := mustCount(t, pool, "SELECT COUNT(*) FROM schema_migrations WHERE version = 17"); got != 1 {
		t.Errorf("0017 應留下一筆版本記錄，實際 %d 筆", got)
	}
	var header int
	if err := pool.QueryRowContext(ctx, "PRAGMA user_version").Scan(&header); err != nil {
		t.Fatalf("讀檔頭版本失敗：%v", err)
	}
	if header != 17 {
		t.Errorf("檔頭版本應推進到 17，實際 %d", header)
	}
}

// TestTagAccountEdgesAreAbsent 驗收：標籤表只有一條指向 activities 的硬外鍵邊，
// 對 accounts 沒有任何邊——「標籤落地之後訪戶綁定仍然走得通」這句話的結構依據。
func TestTagAccountEdgesAreAbsent(t *testing.T) {
	pool := dbAt0017WithFacts(t)

	rows, err := pool.QueryContext(context.Background(),
		`SELECT "table" FROM pragma_foreign_key_list(?) ORDER BY id`, "activity_tags")
	if err != nil {
		t.Fatalf("讀取 activity_tags 的外鍵邊失敗：%v", err)
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
		t.Errorf("標籤表應只有一條指向 activities 的硬外鍵邊（對 accounts 無邊），實際 %v", edges)
	}

	// 指向不存在活動的標籤行寫不進（硬外鍵把關）；合法歸屬寫得進。
	expectAbort(t, pool, "指向不存在活動的標籤行",
		`INSERT INTO activity_tags (id, activity_id, name, created_at, updated_at)
		VALUES (?, ?, '幽靈下的標籤', 6000, 6000)`, tagID1, tagGhostID)
	insertTag(t, pool, tagID1, tagActID1, "合法的標籤", 0)
}

// TestTagDefaultsAreInternal 驗收：只帶必要欄位寫入的一行標籤，出生就是「可用且不公開」。
//
// 這一格是「標籤預設是管理員內部資訊」那句決定的資料庫端依據：不是靠服務層記得填 false，
// 而是那欄根本沒有默認值以外的可能——出廠 1 讓升級後與新建的活動都不未經批准就被開放。
func TestTagDefaultsAreInternal(t *testing.T) {
	pool := dbAt0017WithFacts(t)
	insertTag(t, pool, tagID1, tagActID1, "只帶必要欄位的那一枚", 0)

	var available, public int
	if err := pool.QueryRowContext(context.Background(),
		"SELECT available, public FROM activity_tags WHERE id = ?", tagID1).
		Scan(&available, &public); err != nil {
		t.Fatalf("讀回新建標籤的旗標失敗：%v", err)
	}
	if available != 1 {
		t.Errorf("新建標籤的可用性應為 1（新建即可用），實際 %d", available)
	}
	if public != 0 {
		t.Errorf("新建標籤的公開旗標應為 0（出廠即內部資訊），實際 %d", public)
	}
}

// TestTagShapeRules 驗收：同活動名稱唯一、跨活動同名合法，
// 以及圖標／顏色／排序／可用性／公開／長度每一種湊得出來但無法解釋的形態都被擋。
func TestTagShapeRules(t *testing.T) {
	pool := dbAt0017WithFacts(t)
	insertTag(t, pool, tagID1, tagActID1, "冠軍", 0)

	// 同活動內的第二個同名：UNIQUE (activity_id, name) 當場擋下。
	expectAbort(t, pool, "同活動內重名",
		`INSERT INTO activity_tags (id, activity_id, name, created_at, updated_at)
		VALUES (?, ?, '冠軍', 6000, 6000)`, tagID2, tagActID1)
	// 另一場活動同名：完全合法，兩場活動互不相干。
	if _, err := pool.ExecContext(context.Background(), `INSERT INTO activity_tags
			(id, activity_id, name, created_at, updated_at) VALUES (?, ?, '冠軍', 6000, 6000)`,
		tagID2, tagActID2); err != nil {
		t.Errorf("跨活動同名標籤應能寫入：%v", err)
	}
	// 同活動內允許「同排序值」：破平屬服務端讀法，不是資料庫約束。
	insertTag(t, pool, tagID3, tagActID1, "亞軍", 0)

	illegal := []struct {
		what string
		sql  string
		args []any
	}{
		{"空名稱", `INSERT INTO activity_tags (id, activity_id, name, created_at, updated_at)
			VALUES (?, ?, '', 6000, 6000)`, []any{"0192f0c4-1c9a-7000-8000-000000000f21", tagActID1}},
		{"超長名稱", `INSERT INTO activity_tags (id, activity_id, name, created_at, updated_at)
			VALUES (?, ?, ?, 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f22", tagActID1, strings.Repeat("長", 65)}},
		{"超長描述", `INSERT INTO activity_tags (id, activity_id, name, description, created_at, updated_at)
			VALUES (?, ?, '正常', ?, 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f23", tagActID1, strings.Repeat("字", 501)}},
		{"封閉集合外的圖標", `INSERT INTO activity_tags (id, activity_id, name, icon, created_at, updated_at)
			VALUES (?, ?, '正常', 'dragon', 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f24", tagActID1}},
		{"顏色缺井", `INSERT INTO activity_tags (id, activity_id, name, color, created_at, updated_at)
			VALUES (?, ?, '正常', 'ff0000', 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f25", tagActID1}},
		{"顏色位數不對", `INSERT INTO activity_tags (id, activity_id, name, color, created_at, updated_at)
			VALUES (?, ?, '正常', '#ff000', 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f26", tagActID1}},
		{"顏色含非十六進位", `INSERT INTO activity_tags (id, activity_id, name, color, created_at, updated_at)
			VALUES (?, ?, '正常', '#ff000g', 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f27", tagActID1}},
		{"排序值為負", `INSERT INTO activity_tags (id, activity_id, name, sort_order, created_at, updated_at)
			VALUES (?, ?, '正常', -1, 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f28", tagActID1}},
		{"排序值越上界", `INSERT INTO activity_tags (id, activity_id, name, sort_order, created_at, updated_at)
			VALUES (?, ?, '正常', 100000, 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f29", tagActID1}},
		{"可用性不是布林形態", `INSERT INTO activity_tags (id, activity_id, name, available, created_at, updated_at)
			VALUES (?, ?, '正常', 2, 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f2a", tagActID1}},
		{"公開旗標不是布林形態", `INSERT INTO activity_tags (id, activity_id, name, public, created_at, updated_at)
			VALUES (?, ?, '正常', 2, 6000, 6000)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f2b", tagActID1}},
		{"更新時刻早於建立時刻", `INSERT INTO activity_tags (id, activity_id, name, created_at, updated_at)
			VALUES (?, ?, '正常', 6000, 5999)`,
			[]any{"0192f0c4-1c9a-7000-8000-000000000f2c", tagActID1}},
		{"不合法形狀的標籤標識", `INSERT INTO activity_tags (id, activity_id, name, created_at, updated_at)
			VALUES ('not-a-uuid', ?, '正常', 6000, 6000)`, []any{tagActID1}},
	}
	for _, tc := range illegal {
		if _, err := pool.ExecContext(context.Background(), tc.sql, tc.args...); err == nil {
			t.Errorf("%s：這條寫入應該被資料庫擋下，實際寫成功了", tc.what)
		}
	}

	// 合法形態收個尾：封閉集合內的圖標、大寫十六進位顏色、邊界排序值與兩個旗標的反向取值。
	if _, err := pool.ExecContext(context.Background(), `INSERT INTO activity_tags
			(id, activity_id, name, icon, color, sort_order, available, public, created_at, updated_at)
		VALUES (?, ?, '邊界合法', 'anchor', '#AABBCC', 99999, 0, 1, 6000, 6000)`,
		tagID4, tagActID1); err != nil {
		t.Errorf("各欄合法邊界形態應能寫入：%v", err)
	}
}

// TestTagIdentityAndBelongingImmutable 驗收：標識與歸屬不可就地改寫，
// 白名單資料欄可以正常改，且本表沒有「把標籤連同歷史搬去另一場活動」的表達方式。
func TestTagIdentityAndBelongingImmutable(t *testing.T) {
	pool := dbAt0017WithFacts(t)
	insertTag(t, pool, tagID1, tagActID1, "不動身份的標籤", 0)

	expectAbort(t, pool, "改標籤主鍵",
		`UPDATE activity_tags SET id = ? WHERE id = ?`, tagID2, tagID1)
	expectAbort(t, pool, "改標籤歸屬活動",
		`UPDATE activity_tags SET activity_id = ? WHERE id = ?`, tagActID2, tagID1)

	// 其余欄位照常可改：觸發器擋的只有那兩欄，不是整張表凍結。
	// 公開旗標就在這裡改得動——它是白名單的一欄，而改它不改寫任何人的既有引用。
	if _, err := pool.ExecContext(context.Background(), `UPDATE activity_tags
			SET name = '改過名', available = 0, public = 1, sort_order = 7, updated_at = 6500
			WHERE id = ?`, tagID1); err != nil {
		t.Errorf("白名單資料欄應能正常更新：%v", err)
	}

	// 活動歸檔不刪標籤行：終態的「仍列、可讀」由行的存在性支撐（本表沒有刪除通路）。
	if _, err := pool.ExecContext(context.Background(), `UPDATE activities
			SET status = 'archived', archived_at = 6600, updated_at = 6600 WHERE id = ?`,
		tagActID1); err != nil {
		t.Fatalf("合法活動應能進入歸檔態：%v", err)
	}
	if got := mustCount(t, pool,
		"SELECT COUNT(*) FROM activity_tags WHERE activity_id = ?", tagActID1); got != 1 {
		t.Errorf("歸檔後標籤行仍要在原處（仍列、可讀、拒寫），實際 %d 行", got)
	}
}
