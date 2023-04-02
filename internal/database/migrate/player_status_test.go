// player_status_test.go 驗收遷移 0018：玩家業務狀態的持久形態。
//
// 四個驗收面各自對應本步的一句決定：
//  1. 增量遷移不傷既有事實（帳戶、活動、陣營、成員與標籤逐字還在原處），成員那兩欄由
//     DEFAULT 落在 normal 與 NULL——既有 Profile 不被「重置」，也不需要回填；
//  2. custom 與自訂標識的成對規則、以及「自訂定義必須與成員同屬一場活動」都釘在觸發器上：
//     繞過應用層的直寫也進不來，跨活動拼接在資料庫層就不成立；
//  3. 自訂狀態定義的封閉形態（同活動名稱唯一、跨活動同名合法、availability 出廠為真、
//     標識與歸屬不可就地改寫），以及顯示名稱覆蓋的鍵封閉集合與「空字串＝沒有覆蓋」；
//  4. 兩張新表對 accounts 沒有任何外鍵邊（只有指向 activities 的硬邊），這是綁定預檢
//     不需要新增登記、而既有綁定通路照常走得通的結構依據。
package migrate

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// 本檔使用的標識（全部是 36 字元的小寫 UUID 形狀，只服務本檔的 CHECK 取證）。
const (
	bizCustomID1  = "0192f0c4-1c9a-7000-8000-000000000g21" // 合法自訂狀態一（屬活動一）
	bizCustomID2  = "0192f0c4-1c9a-7000-8000-000000000g22" // 合法自訂狀態二（屬活動一）
	bizCustomID3  = "0192f0c4-1c9a-7000-8000-000000000g23" // 合法自訂狀態三（屬活動二）
	bizGhostActID = "0192f0c4-1c9a-7000-8000-000000000g29" // 從未存在的活動標識
)

// knownSplitTo0018 把內嵌遷移拆成「到 0017 為止的全部」與「0018 本身」兩段。
//
// 拆兩段的理由同前幾支：applySet 對版本嚴格遞增把關，而本檔需要一座「0018 還沒落地」
// 的資料庫才能先取既有事實的快照。比 0018 更新的版本不在此列。
func knownSplitTo0018(t *testing.T) (through17, only18 []Migration) {
	t.Helper()
	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	for _, m := range known {
		switch {
		case m.Version < 18:
			through17 = append(through17, m)
		case m.Version == 18:
			only18 = append(only18, m)
		}
	}
	if len(only18) != 1 {
		t.Fatalf("必須恰好一支 0018，實際 %d", len(only18))
	}
	return through17, only18
}

// dbAt0018WithFacts 建出一座「既有 0017 事實、已套上 0018」的資料庫。
//
// 現場複用標籤那一步的池子（兩場活動、兩個陣營、兩行成員，其中一行已分組），
// 於是「加了狀態之後舊的一行一欄都沒動」這一句有可比對的舊值。
func dbAt0018WithFacts(t *testing.T) *sql.DB {
	t.Helper()
	pool := dbAt0015WithDirectoryFacts(t)
	through17, only18 := knownSplitTo0018(t)
	if _, err := applySet(context.Background(), pool, append(through17, only18...),
		Options{}); err != nil {
		t.Fatalf("套用 0017 與 0018 失敗：%v", err)
	}
	return pool
}

// insertCustomStatus 以合法形態寫入一行自訂狀態定義。
func insertCustomStatus(t *testing.T, pool *sql.DB, id, activityID, name string) {
	t.Helper()
	_, err := pool.ExecContext(context.Background(), `INSERT INTO activity_player_statuses
			(id, activity_id, name, created_at, updated_at)
		VALUES (?, ?, ?, 8000, 8000)`, id, activityID, name)
	if err != nil {
		t.Fatalf("種下自訂狀態 %s 失敗：%v", id, err)
	}
}

// memberStatusOf 讀一行的狀態兩欄（NULL 讀成空字串，方便逐字比較）。
func memberStatusOf(t *testing.T, pool *sql.DB, memberID string) (string, string) {
	t.Helper()
	var status, custom string
	err := pool.QueryRowContext(context.Background(), `SELECT business_status,
			COALESCE(business_status_custom_id, '') FROM activity_members WHERE id = ?`,
		memberID).Scan(&status, &custom)
	if err != nil {
		t.Fatalf("讀取成員 %s 的狀態失敗：%v", memberID, err)
	}
	return status, custom
}

// mustFailWith 斷言一條直寫被資料庫擋下，而且錯誤句子帶著預期字眼。
func mustFailWith(t *testing.T, pool *sql.DB, what, want string, stmt string, args ...any) {
	t.Helper()
	_, err := pool.ExecContext(context.Background(), stmt, args...)
	if err == nil {
		t.Fatalf("%s 必須被資料庫擋下", what)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("%s 的錯誤句子該含 %q，實際 %v", what, want, err)
	}
}

// TestPlayerStatusMigrationKeepsEveryOldFact 驗收：0018 只加兩張新表與兩欄預設值，
// 既有的事實一個字都沒動，而且不需要回填（既有成員自動讀成 normal／NULL）。
func TestPlayerStatusMigrationKeepsEveryOldFact(t *testing.T) {
	ctx := context.Background()
	pool := dbAt0015WithDirectoryFacts(t)
	defer pool.Close()

	through17, only18 := knownSplitTo0018(t)
	if _, err := applySet(ctx, pool, through17, Options{}); err != nil {
		t.Fatalf("先套到 0017 失敗：%v", err)
	}
	accountsBefore := factsSnapshot(t, pool)
	factionsBefore := snapshotRows(t, pool, "activity_factions")
	tagsBefore := snapshotRows(t, pool, "activity_tags")
	membersBefore := directoryMemberFacts(t, pool)

	if _, err := applySet(ctx, pool, append(through17, only18...), Options{}); err != nil {
		t.Fatalf("套用 0018 失敗：%v", err)
	}

	if after := factsSnapshot(t, pool); after != accountsBefore {
		t.Errorf("0018 改寫了帳戶側既有事實：\n舊 %s\n新 %s", accountsBefore, after)
	}
	if after := snapshotRows(t, pool, "activity_factions"); after != factionsBefore {
		t.Errorf("0018 改寫了陣營側既有事實：\n舊 %s\n新 %s", factionsBefore, after)
	}
	if after := snapshotRows(t, pool, "activity_tags"); after != tagsBefore {
		t.Errorf("0018 改寫了標籤側既有事實：\n舊 %s\n新 %s", tagsBefore, after)
	}
	if after := directoryMemberFacts(t, pool); after != membersBefore {
		t.Errorf("0018 改寫了成員側既有事實：\n舊 %s\n新 %s", membersBefore, after)
	}
	if got := snapshotRows(t, pool, "activity_player_statuses"); strings.TrimSpace(got) != "" {
		t.Errorf("新表必須是空的（不回填任何東西），實際 %s", got)
	}
	if got := snapshotRows(t, pool, "activity_player_status_labels"); strings.TrimSpace(got) != "" {
		t.Errorf("顯示名稱覆蓋必須是空的（出廠沒有覆蓋），實際 %s", got)
	}
	// 既有兩行成員由 DEFAULT 直接落在集合內：這就是「遷移不重置既有 Profile」的形態。
	for _, memberID := range []string{dirMemberID1, dirMemberID2} {
		status, custom := memberStatusOf(t, pool, memberID)
		if status != "normal" || custom != "" {
			t.Errorf("成員 %s 遷移後必須讀成 normal／NULL，實際 %q／%q", memberID, status, custom)
		}
	}
	// 遷移之後新建的行也照樣落預設值（insertMember 的欄位清單裡沒有新欄）。
	// 這一行的（活動, 帳戶）組合在池子裡還沒出現過：撞的是「一人一檔」那條唯一索引的
	// 另一側，不是它。
	insertMember(t, pool, memID3, memActID1, v10GuestID, "0018 之後新建的成員")
	if status, custom := memberStatusOf(t, pool, memID3); status != "normal" || custom != "" {
		t.Errorf("新行也該是 normal／NULL，實際 %q／%q", status, custom)
	}
}

// TestPlayerStatusShapeRules 驗收：自訂狀態定義與顯示名稱覆蓋的封閉形態。
func TestPlayerStatusShapeRules(t *testing.T) {
	ctx := context.Background()
	pool := dbAt0018WithFacts(t)
	defer pool.Close()

	insertCustomStatus(t, pool, bizCustomID1, memActID1, "失蹤中")

	// 同活動名稱唯一、跨活動同名互不相干（UNIQUE 分書）。
	mustFailWith(t, pool, "同活動重名", "UNIQUE constraint failed",
		`INSERT INTO activity_player_statuses (id, activity_id, name, created_at, updated_at)
		 VALUES (?, ?, '失蹤中', 8100, 8100)`, bizCustomID2, memActID1)
	insertCustomStatus(t, pool, bizCustomID3, memActID2, "失蹤中")
	// 歸屬必須是真實存在的活動（硬外鍵）。
	mustFailWith(t, pool, "指向從未存在的活動", "FOREIGN KEY constraint failed",
		`INSERT INTO activity_player_statuses (id, activity_id, name, created_at, updated_at)
		 VALUES (?, ?, '幽靈場的定義', 8100, 8100)`, bizGhostActID, bizGhostActID)
	// 名稱上界與非空（CHECK 以字元數計）。
	for name, want := range map[string]string{
		"": "CHECK constraint failed", strings.Repeat("名", 65): "CHECK constraint failed",
	} {
		mustFailWith(t, pool, "名稱形態 "+name, want,
			`INSERT INTO activity_player_statuses (id, activity_id, name, created_at, updated_at)
			 VALUES (?, ?, ?, 8100, 8100)`, bizCustomID2, memActID1, name)
	}
	// availability 是封閉集合（0/1），出廠為真。
	var available int
	if err := pool.QueryRowContext(ctx,
		"SELECT available FROM activity_player_statuses WHERE id = ?", bizCustomID1).
		Scan(&available); err != nil {
		t.Fatalf("讀取自訂狀態可用性失敗：%v", err)
	}
	if available != 1 {
		t.Errorf("新建的自訂狀態必須出生即可用，實際 %d", available)
	}
	mustFailWith(t, pool, "可用性取值集合外", "CHECK constraint failed",
		`UPDATE activity_player_statuses SET available = 2 WHERE id = ?`, bizCustomID1)

	// 顯示名稱覆蓋：鍵集合封閉、活動必須存在、空字串合法（代表沒有覆蓋）。
	if _, err := pool.ExecContext(ctx, `INSERT INTO activity_player_status_labels
			(activity_id, status_key, display_name, updated_at) VALUES (?, 'offline', '', 8200)`,
		memActID1); err != nil {
		t.Fatalf("空字串的覆蓋（＝使用預設）必須寫得進去：%v", err)
	}
	mustFailWith(t, pool, "集合外的內建鍵", "CHECK constraint failed",
		`INSERT INTO activity_player_status_labels (activity_id, status_key, display_name, updated_at)
		 VALUES (?, 'connected', '連線中', 8200)`, memActID1)
	mustFailWith(t, pool, "大寫的內建鍵", "CHECK constraint failed",
		`INSERT INTO activity_player_status_labels (activity_id, status_key, display_name, updated_at)
		 VALUES (?, 'OFFLINE', '離線', 8200)`, memActID1)
	mustFailWith(t, pool, "指向從未存在的活動", "FOREIGN KEY constraint failed",
		`INSERT INTO activity_player_status_labels (activity_id, status_key, display_name, updated_at)
		 VALUES (?, 'offline', '離線', 8200)`, bizGhostActID)
	mustFailWith(t, pool, "覆蓋顯示名超長", "CHECK constraint failed",
		`INSERT INTO activity_player_status_labels (activity_id, status_key, display_name, updated_at)
		 VALUES (?, 'dead', ?, 8200)`, memActID1, strings.Repeat("長", 65))
	// 一個活動的一個鍵只能有一行覆蓋（主鍵）。
	mustFailWith(t, pool, "同鍵重覆覆蓋", "UNIQUE constraint failed",
		`INSERT INTO activity_player_status_labels (activity_id, status_key, display_name, updated_at)
		 VALUES (?, 'offline', '又一個覆蓋', 8300)`, memActID1)
}

// TestPlayerStatusIdentityImmutable 驗收：自訂狀態與覆蓋的身份、歸屬都不可就地改寫。
func TestPlayerStatusIdentityImmutable(t *testing.T) {
	pool := dbAt0018WithFacts(t)
	defer pool.Close()
	insertCustomStatus(t, pool, bizCustomID1, memActID1, "失蹤中")
	if _, err := pool.ExecContext(context.Background(),
		`INSERT INTO activity_player_status_labels
			(activity_id, status_key, display_name, updated_at)
		 VALUES (?, 'offline', '暫離現場', 8200)`, memActID1); err != nil {
		t.Fatalf("種下顯示名稱覆蓋失敗：%v", err)
	}

	// 自訂狀態：標識與歸屬都擋；名稱與可用性照樣可改。
	mustFailWith(t, pool, "改自訂狀態標識", "不可就地改寫",
		`UPDATE activity_player_statuses SET id = ? WHERE id = ?`, bizCustomID2, bizCustomID1)
	mustFailWith(t, pool, "改自訂狀態歸屬", "不可就地改寫",
		`UPDATE activity_player_statuses SET activity_id = ? WHERE id = ?`,
		memActID2, bizCustomID1)
	if _, err := pool.ExecContext(context.Background(),
		`UPDATE activity_player_statuses SET name = ?, available = 0, updated_at = 8300
		 WHERE id = ?`, "改名後的定義", bizCustomID1); err != nil {
		t.Fatalf("改名與停用必須可寫：%v", err)
	}

	// 覆蓋：主鍵兩欄都擋；顯示名稱照樣可改（改回空字串就是恢復預設）。
	mustFailWith(t, pool, "改覆蓋的活動", "不可就地改寫",
		`UPDATE activity_player_status_labels SET activity_id = ?
		 WHERE activity_id = ? AND status_key = 'offline'`, memActID2, memActID1)
	mustFailWith(t, pool, "改覆蓋的鍵", "不可就地改寫",
		`UPDATE activity_player_status_labels SET status_key = 'dead'
		 WHERE activity_id = ? AND status_key = 'offline'`, memActID1)
	if _, err := pool.ExecContext(context.Background(),
		`UPDATE activity_player_status_labels SET display_name = '', updated_at = 8400
		 WHERE activity_id = ? AND status_key = 'offline'`, memActID1); err != nil {
		t.Fatalf("恢復預設（清成空字串）必須可寫：%v", err)
	}
}

// TestPlayerStatusMemberPairRules 驗收：custom 與自訂標識的成對規則、同活動限制，
// 以及狀態鍵的封閉集合都釘在資料庫上（繞過應用層的直寫也進不來）。
func TestPlayerStatusMemberPairRules(t *testing.T) {
	pool := dbAt0018WithFacts(t)
	defer pool.Close()
	insertCustomStatus(t, pool, bizCustomID1, memActID1, "失蹤中")
	insertCustomStatus(t, pool, bizCustomID3, memActID2, "別人的定義")

	// 合法形態：custom ＋ 同活動的自訂標識。
	if _, err := pool.ExecContext(context.Background(),
		`UPDATE activity_members SET business_status = 'custom',
		        business_status_custom_id = ? WHERE id = ?`, bizCustomID1, dirMemberID1); err != nil {
		t.Fatalf("合法的自訂狀態指派必須寫得進去：%v", err)
	}
	if status, custom := memberStatusOf(t, pool, dirMemberID1); status != "custom" ||
		custom != bizCustomID1 {
		t.Errorf("回讀的成對形態不一致：%q／%q", status, custom)
	}

	// custom 缺自訂標識。
	mustFailWith(t, pool, "custom 缺自訂標識", "必須指向一個自訂狀態定義",
		`UPDATE activity_members SET business_status = 'custom',
		        business_status_custom_id = NULL WHERE id = ?`, dirMemberID1)
	// 內建值卻帶自訂標識。
	mustFailWith(t, pool, "內建值帶自訂標識", "不得帶自訂狀態標識",
		`UPDATE activity_members SET business_status = 'offline',
		        business_status_custom_id = ? WHERE id = ?`, bizCustomID1, dirMemberID1)
	// 跨活動拼接：定義屬於另一場活動。
	mustFailWith(t, pool, "跨活動的自訂狀態", "必須與成員同屬一場活動",
		`UPDATE activity_members SET business_status = 'custom',
		        business_status_custom_id = ? WHERE id = ?`, bizCustomID3, dirMemberID1)
	// 指向從未存在的定義：同活動那條觸發器先答（它在 CHECK 與外鍵之前跑），
	// 外鍵邊本身的存在性由另一組取證（pragma_foreign_key_list）釘住。
	mustFailWith(t, pool, "幽靈的自訂狀態", "必須與成員同屬一場活動",
		`UPDATE activity_members SET business_status = 'custom',
		        business_status_custom_id = ? WHERE id = ?`, bizCustomID2, dirMemberID1)
	// 狀態鍵的封閉集合（含大寫與集合外的自造值）。
	for _, bad := range []string{"Normal", "connected", ""} {
		mustFailWith(t, pool, "非法狀態鍵 "+bad, "CHECK constraint failed",
			`UPDATE activity_members SET business_status = ? WHERE id = ?`, bad, dirMemberID2)
	}
	// 插入那一跳也同樣成立（觸發器成對存在）。
	mustFailWith(t, pool, "插入 custom 缺自訂標識", "必須指向一個自訂狀態定義",
		`INSERT INTO activity_members (id, activity_id, account_id, nickname,
		        business_status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 'custom', 8500, 8500)`,
		memID3, memActID1, v10GuestID, "插入的那位")
	// 內建值與 NULL 的合法組合照樣插得進去（出生形態只有一個答案）。
	if _, err := pool.ExecContext(context.Background(), `INSERT INTO activity_members
			(id, activity_id, account_id, nickname, business_status, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'arrested', 8500, 8500)`,
		memID3, memActID1, v10GuestID, "被拘束的新行"); err != nil {
		t.Fatalf("合法的內建狀態插入必須成功：%v", err)
	}
	if status, custom := memberStatusOf(t, pool, memID3); status != "arrested" || custom != "" {
		t.Errorf("新行的成對形態不一致：%q／%q", status, custom)
	}
}

// TestPlayerStatusNewTablesHaveNoAccountEdges 驗收：兩張新表對 accounts 沒有任何外鍵邊，
// 因此不需要進 bindpreflight 的引用登記表；成員那一欄的新邊指向的是自訂狀態定義。
func TestPlayerStatusNewTablesHaveNoAccountEdges(t *testing.T) {
	pool := dbAt0018WithFacts(t)
	defer pool.Close()

	for _, table := range []string{"activity_player_statuses", "activity_player_status_labels"} {
		rows, err := pool.QueryContext(context.Background(),
			`SELECT "table", "from", "to" FROM pragma_foreign_key_list(?)`, table)
		if err != nil {
			t.Fatalf("讀 %s 的外鍵清單失敗：%v", table, err)
		}
		count := 0
		for rows.Next() {
			var refTable, refFrom, refTo string
			if err := rows.Scan(&refTable, &refFrom, &refTo); err != nil {
				rows.Close()
				t.Fatalf("解析 %s 的外鍵清單失敗：%v", table, err)
			}
			count++
			if refTable == "accounts" {
				t.Errorf("%s 不該有指向 accounts 的外鍵邊", table)
			}
			if refTable != "activities" {
				t.Errorf("%s 的外鍵必須只指向 activities，實際 %q", table, refTable)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatalf("遍歷 %s 的外鍵清單失敗：%v", table, err)
		}
		rows.Close()
		if count == 0 {
			t.Errorf("%s 必須有一條指向 activities 的硬邊", table)
		}
	}

	// 成員新增的那條邊指向自訂狀態定義（不是 accounts）。
	var references string
	err := pool.QueryRowContext(context.Background(),
		`SELECT "table" FROM pragma_foreign_key_list('activity_members')
		 WHERE "from" = 'business_status_custom_id'`).Scan(&references)
	if err != nil {
		t.Fatalf("讀成員那一欄的外鍵目標失敗：%v", err)
	}
	if references != "activity_player_statuses" {
		t.Errorf("business_status_custom_id 必須指向自訂狀態定義，實際 %q", references)
	}
}
