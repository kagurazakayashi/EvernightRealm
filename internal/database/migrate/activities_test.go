// activities_test.go 驗收遷移 0012：活動實體與活動管理人指派的持久形態。
//
// 四個驗收面各自對應本步的一句話：
//  1. 增量遷移不傷既有事實（六種形態的帳戶、會話、授予、審計逐字還在原處，
//     兩張新表是空的、不回填任何東西）；
//  2. 指向 accounts 的兩個欄位是刻意的無外鍵軟參照——這句要能被結構證明，因為它同時是
//     「訪戶綁定預檢不會把這兩張表當成未登記引用」的依據（見 internal/stdacct/bindpreflight.go）；
//  3. 狀態是封閉集合（四態、archived 與歸檔時刻成對、主鍵不可就地改寫、名稱不是身份鍵）；
//  4. 指派行有牙齒（指向不存在活動的行寫不進、訪戶不可持有管理權、就地改寫被擋、
//     改指派只能撤銷舊行再插入新行、歸檔不刪行）。
package migrate

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// 本檔使用的標識（全部是 36 字元的小寫 UUID 形狀，只服務本檔的 CHECK 取證）。
const (
	actCreatorID = v10ActiveID                            // 既有事實裡那位持有 server_admin 授予的帳戶（活動建立者與管理人）
	actGuestID   = v10GuestID                             // 既有事實裡的訪戶：不可被指派為活動管理人
	actGhostID   = "0192f0c4-1c9a-7000-8000-000000000d09" // 從未出現過的標識
	actID1       = "0192f0c4-1c9a-7000-8000-000000000d01" // 合法活動一
	actID2       = "0192f0c4-1c9a-7000-8000-000000000d02" // 合法活動二
)

// splitThroughTenWithFacts 切出「到 0010 為止」「0011 本身」「0012 本身」三段，
// 並驗證 11／12 各自恰好一支（少了任何一支，本檔要驗的那道門就不存在）。
func splitThroughTenWithFacts(t *testing.T) (through10, only11, only12 []Migration) {
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
		case m.Version == 12:
			only12 = append(only12, m)
		}
	}
	if len(only11) != 1 || len(only12) != 1 {
		t.Fatalf("必須各有 0011 與 0012 一支，實際 %d／%d", len(only11), len(only12))
	}
	return through10, only11, only12
}

// dbAt0011WithFacts 建出一座套到 0011、佈好既有事實的資料庫（呼叫端自己收尾）。
func dbAt0011WithFacts(t *testing.T) (*sql.DB, []Migration, []Migration) {
	t.Helper()
	through10, only11, only12 := splitThroughTenWithFacts(t)
	db := openUpTo(t, through10)
	pool := db.SQL()
	seedV10Facts(t, pool)
	if _, err := applySet(context.Background(), pool, append(through10, only11...), Options{}); err != nil {
		t.Fatalf("套用 0011 失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return pool, append(through10, only11...), only12
}

// dbAt0012WithFacts 建出一座「既有 0011 事實、且已套上 0012」的資料庫：
// 後三個驗收面問的是新表自己的規則，起點必須在 0012 之後。
func dbAt0012WithFacts(t *testing.T) *sql.DB {
	t.Helper()
	pool, through11, only12 := dbAt0011WithFacts(t)
	if _, err := applySet(context.Background(), pool, append(through11, only12...), Options{}); err != nil {
		t.Fatalf("套用 0012 失敗：%v", err)
	}
	return pool
}

// factsSnapshot 把既有資料表的每一行壓成一條可逐字比對的字串（NULL 一律讀成空段）。
//
// 用的是 SQL 內的串接而不是 Go 側掃描：欄位增减時這條查詢會當場報錯，
// 比「靜默少比一欄」更容易發現——本檔要的證據正是「一個字都沒被改」。
func factsSnapshot(t *testing.T, pool *sql.DB) string {
	t.Helper()
	const query = `SELECT group_concat(line, char(30)) FROM (
		SELECT 'accounts' || char(31) || id || char(31) || login_name || char(31) || login_name_key ||
			char(31) || display_name || char(31) || IFNULL(password_hash, '') || char(31) ||
			account_type || char(31) || status || char(31) || must_change_password || char(31) ||
			created_at || char(31) || IFNULL(last_login_at, '') || char(31) ||
			IFNULL(disabled_at, '') || char(31) || IFNULL(deleted_at, '') || char(31) ||
			IFNULL(reviewed_at, '') || char(31) || IFNULL(retired_at, '') AS line FROM accounts
		UNION ALL
		SELECT 'sessions' || char(31) || id || char(31) || device_id || char(31) ||
			IFNULL(account_id, '') || char(31) || subject_kind || char(31) || token_hash FROM sessions
		UNION ALL
		SELECT 'roles' || char(31) || account_id || char(31) || role || char(31) || granted_at
			FROM account_server_roles
		UNION ALL
		SELECT 'root_audit' || char(31) || id || char(31) || actor_kind || char(31) ||
			IFNULL(actor_id, '') || char(31) || action || char(31) || target_kind || char(31) ||
			IFNULL(target_id, '') || char(31) || created_at FROM root_audit
		ORDER BY line)`
	var got sql.NullString
	if err := pool.QueryRowContext(context.Background(), query).Scan(&got); err != nil {
		t.Fatalf("抓取既有事實快照失敗：%v", err)
	}
	return got.String
}

// mustCount 回傳一條 COUNT(*) 的結果。
func mustCount(t *testing.T, pool *sql.DB, query string, args ...any) int {
	t.Helper()
	var got int
	if err := pool.QueryRowContext(context.Background(), query, args...).Scan(&got); err != nil {
		t.Fatalf("查詢 %q 失敗：%v", query, err)
	}
	return got
}

// insertActivity 以合法形態寫入一行活動，呼叫端再從這裡出發去踩各條非法形態。
func insertActivity(t *testing.T, pool *sql.DB, id, name, status string,
	createdAt int64, archivedAt any) {
	t.Helper()
	_, err := pool.ExecContext(context.Background(), `INSERT INTO activities
			(id, name, description, status, created_by_account_id, created_at, updated_at, archived_at)
		VALUES (?, ?, '描述', ?, ?, ?, ?, ?)`,
		id, name, status, actCreatorID, createdAt, createdAt, archivedAt)
	if err != nil {
		t.Fatalf("種下合法活動 %s 失敗：%v", id, err)
	}
}

// TestActivityMigrationKeepsEveryOldFact 驗收：0012 只加兩張新表，舊的行逐字在原處。
func TestActivityMigrationKeepsEveryOldFact(t *testing.T) {
	ctx := context.Background()
	pool, through11, only12 := dbAt0011WithFacts(t)

	before := factsSnapshot(t, pool)
	if !strings.Contains(before, "accounts") {
		t.Fatalf("快照裡必須看得到既有帳戶行，實際為空表示佈資料沒生效")
	}

	if _, err := applySet(ctx, pool, append(through11, only12...), Options{}); err != nil {
		t.Fatalf("套用 0012 失敗：%v", err)
	}

	if after := factsSnapshot(t, pool); after != before {
		t.Errorf("0012 改寫了既有事實：\n舊 %s\n新 %s", before, after)
	}

	// 兩張新表存在且都是空的：本支遷移不做任何回填（回填等於偽造「從前有過活動」）。
	for _, table := range []string{"activities", "activity_manager_grants"} {
		found, err := tableExists(ctx, pool, table)
		if err != nil || !found {
			t.Fatalf("0012 應建出 %s（found=%v err=%v）", table, found, err)
		}
		if got := mustCount(t, pool, "SELECT COUNT(*) FROM "+table); got != 0 {
			t.Errorf("%s 遷移後必須是空的，實際 %d 行", table, got)
		}
	}
	if got := mustCount(t, pool, "SELECT COUNT(*) FROM schema_migrations WHERE version = 12"); got != 1 {
		t.Errorf("0012 應留下一筆版本記錄，實際 %d 筆", got)
	}
	var header int
	if err := pool.QueryRowContext(ctx, "PRAGMA user_version").Scan(&header); err != nil {
		t.Fatalf("讀檔頭版本失敗：%v", err)
	}
	if header != 12 {
		t.Errorf("檔頭版本應推進到 12，實際 %d", header)
	}
}

// TestActivityAccountEdgesAreSoftReferences 驗收：兩張新表對 accounts 沒有任何外鍵邊，
// 而 activity_manager_grants 對 activities 有一條硬外鍵邊。
//
// 這不是一句作風說明：internal/stdacct 的綁定預檢每次執行都現掃實庫裡「引用 accounts 的外鍵邊」，
// 查得一張未登記的表就整體 fail-closed。本檔把「軟參照」寫成可執行的斷言，
// 「活動落地之後訪戶綁定仍然走得通」這句話才有證據，而不是靠讀 SQL 讀出來的印象。
func TestActivityAccountEdgesAreSoftReferences(t *testing.T) {
	pool := dbAt0012WithFacts(t)

	// 外鍵邊一律經 pragma 的參數化表值函式讀取：表名走引數，不拼進 SQL 文本。
	foreignKeyTargets := func(t *testing.T, table string) []string {
		t.Helper()
		rows, err := pool.QueryContext(context.Background(),
			`SELECT "table" FROM pragma_foreign_key_list(?) ORDER BY id`, table)
		if err != nil {
			t.Fatalf("讀取 %s 的外鍵邊失敗：%v", table, err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var target string
			if err := rows.Scan(&target); err != nil {
				t.Fatalf("解析 %s 的外鍵邊失敗：%v", table, err)
			}
			out = append(out, target)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("讀取 %s 的外鍵邊失敗：%v", table, err)
		}
		return out
	}

	if edges := foreignKeyTargets(t, "activities"); len(edges) != 0 {
		t.Errorf("activities 不該有任何外鍵邊（建立者是軟參照），實際指向 %v", edges)
	}
	grantEdges := foreignKeyTargets(t, "activity_manager_grants")
	if len(grantEdges) != 1 || grantEdges[0] != "activities" {
		t.Errorf("指派表應只有一條指向 activities 的硬外鍵邊，實際 %v", grantEdges)
	}

	// 軟參照的取捨兩側都要在證據裡：指向一個從未存在的帳戶，資料庫不拦（由域層擋）；
	// 指向一個從未存在的活動，資料庫當場拦下。
	if _, err := pool.ExecContext(context.Background(), `INSERT INTO activities
			(id, name, status, created_by_account_id, created_at, updated_at)
		VALUES (?, '軟參照取證', 'draft', ?, 2000, 2000)`, actID1, actGhostID); err != nil {
		t.Errorf("建立者軟參照不該由資料庫拦下（口徑與 0002 審計表一致）：%v", err)
	}
	// Root 建立的活動：建立者那一格是 NULL（Root 不在 accounts 表裡，沒有可填的帳戶標識）。
	// 「填一個讀不回任何人的零值標識」不是同一件事，因此這條形态必須走得通、
	// 而零值形狀（長度不對）必須走不通。
	if _, err := pool.ExecContext(context.Background(), `INSERT INTO activities
			(id, name, status, created_by_account_id, created_at, updated_at)
		VALUES (?, 'Root 建的活動', 'draft', NULL, 2100, 2100)`, actID2); err != nil {
		t.Errorf("建立者可為 NULL（Root 沒有帳戶標識）：%v", err)
	}
	expectAbort(t, pool, "建立者帶一個長度不對的標識",
		`INSERT INTO activities (id, name, status, created_by_account_id, created_at, updated_at)
		VALUES ('0192f0c4-1c9a-7000-8000-000000000d03', '壞形狀', 'draft', 'root', 2200, 2200)`)
	expectAbort(t, pool, "指向不存在活動的指派行",
		`INSERT INTO activity_manager_grants (activity_id, account_id, granted_at) VALUES (?, ?, 2000)`,
		actGhostID, actCreatorID)
}

// TestActivityStatusShapeRules 驗收：狀態是封閉集合，名稱不是身份鍵，主鍵不可就地改寫。
func TestActivityStatusShapeRules(t *testing.T) {
	pool := dbAt0012WithFacts(t)

	// 四態各自是合法形態（只有 archived 帶歸檔時刻）。
	for i, status := range []string{"draft", "active", "closed", "archived"} {
		var archivedAt any
		if status == "archived" {
			archivedAt = int64(2000 + i)
		}
		id := []string{
			"0192f0c4-1c9a-7000-8000-000000000d11",
			"0192f0c4-1c9a-7000-8000-000000000d12",
			"0192f0c4-1c9a-7000-8000-000000000d13",
			"0192f0c4-1c9a-7000-8000-000000000d14",
		}[i]
		if _, err := pool.ExecContext(context.Background(), `INSERT INTO activities
				(id, name, description, status, created_by_account_id, created_at, updated_at, archived_at)
			VALUES (?, ?, '', ?, ?, ?, ?, ?)`,
			id, "合法態 "+status, status, actCreatorID, 2000+i, 2000+i, archivedAt); err != nil {
			t.Errorf("狀態 %s 是已批准的四態之一，應能寫入：%v", status, err)
		}
	}

	// 每一種「湊得出來但無法解釋」的形態都必須被擋。
	illegal := []struct {
		what      string
		id        string
		name      string
		status    string
		createdAt int64
		updatedAt int64
		archived  any
	}{
		{"未定義的狀態取值", "0192f0c4-1c9a-7000-8000-000000000d21", "非法", "paused", 3000, 3000, nil},
		{"archived 卻沒有歸檔時刻", "0192f0c4-1c9a-7000-8000-000000000d22", "非法", "archived", 3100, 3100, nil},
		{"非 archived 卻帶歸檔時刻", "0192f0c4-1c9a-7000-8000-000000000d23", "非法", "active", 3200, 3200, int64(3200)},
		{"空的活動名稱", "0192f0c4-1c9a-7000-8000-000000000d24", "", "draft", 3300, 3300, nil},
		{"超長的活動名稱", "0192f0c4-1c9a-7000-8000-000000000d25", strings.Repeat("長", 65), "draft", 3400, 3400, nil},
		{"超長的活動描述", "0192f0c4-1c9a-7000-8000-000000000d27", "正常", "draft", 3500, 3500, nil},
		{"更新時刻早於建立時刻", "0192f0c4-1c9a-7000-8000-000000000d26", "非法", "draft", 3600, 3599, nil},
		{"不合法形狀的活動標識", "not-a-uuid", "非法", "draft", 3700, 3700, nil},
	}
	for _, tc := range illegal {
		// 「超長的活動描述」這一格走的是描述欄而不是名稱欄：用同一個語句塞 501 字描述。
		if tc.what == "超長的活動描述" {
			_, err := pool.ExecContext(context.Background(), `INSERT INTO activities
					(id, name, description, status, created_by_account_id, created_at, updated_at)
				VALUES (?, '正常', ?, 'draft', ?, 3500, 3500)`,
				tc.id, strings.Repeat("長", 501), actCreatorID)
			if err == nil {
				t.Errorf("%s：這條寫入應該被資料庫擋下，實際寫成功了", tc.what)
			}
			continue
		}
		_, err := pool.ExecContext(context.Background(), `INSERT INTO activities
				(id, name, description, status, created_by_account_id, created_at, updated_at, archived_at)
			VALUES (?, ?, '', ?, ?, ?, ?, ?)`,
			tc.id, tc.name, tc.status, actCreatorID, tc.createdAt, tc.updatedAt, tc.archived)
		if err == nil {
			t.Errorf("%s：這條寫入應該被資料庫擋下，實際寫成功了", tc.what)
		}
	}

	// 名稱可重複：同名活動彼此無關，身份只有 id（跨活動同名不得變成寫不進去）。
	insertActivity(t, pool, actID2, "同名活動", "active", 4000, nil)
	if _, err := pool.ExecContext(context.Background(), `INSERT INTO activities
			(id, name, description, status, created_by_account_id, created_at, updated_at)
		VALUES (?, '同名活動', '', 'draft', ?, 4100, 4100)`,
		"0192f0c4-1c9a-7000-8000-000000000d32", actCreatorID); err != nil {
		t.Errorf("第二份同名活動也應能寫入（名稱不是身份鍵）：%v", err)
	}

	// 主鍵不可就地改寫：改 id 等於換了一個實體，指向它的指派會留在舊值上。
	expectAbort(t, pool, "改活動主鍵",
		`UPDATE activities SET id = ? WHERE id = ?`, actGhostID, actID2)
}

// TestActivityManagerGrantShapeRules 驗收：指派行的形態規則、訪戶禁止與歸檔不刪行。
func TestActivityManagerGrantShapeRules(t *testing.T) {
	pool := dbAt0012WithFacts(t)
	insertActivity(t, pool, actID1, "第一個活動", "draft", 4000, nil)
	insertActivity(t, pool, actID2, "第二個活動", "active", 4100, nil)

	// 合法指派：一個活動同一名管理人一行。
	if _, err := pool.ExecContext(context.Background(), `INSERT INTO activity_manager_grants
			(activity_id, account_id, granted_at) VALUES (?, ?, 4200)`, actID1, actCreatorID); err != nil {
		t.Fatalf("合法指派應能寫入：%v", err)
	}
	expectAbort(t, pool, "同一活動同一名管理人重複指派",
		`INSERT INTO activity_manager_grants (activity_id, account_id, granted_at) VALUES (?, ?, 4300)`,
		actID1, actCreatorID)
	// 訪戶不可持有活動管理權（與 0006 擋「訪戶＋伺服器級角色」同一形態要求）。
	expectAbort(t, pool, "訪戶被指派為活動管理人",
		`INSERT INTO activity_manager_grants (activity_id, account_id, granted_at) VALUES (?, ?, 4400)`,
		actID1, actGuestID)
	// 就地改寫任一主鍵段等於把「誰管哪個活動」原地換掉，事後查不出原本是誰。
	expectAbort(t, pool, "改指派行的活動標識",
		`UPDATE activity_manager_grants SET activity_id = ? WHERE activity_id = ?`, actID2, actID1)
	expectAbort(t, pool, "改指派行的帳戶標識",
		`UPDATE activity_manager_grants SET account_id = ? WHERE account_id = ?`, actGuestID, actCreatorID)
	// 同一帳戶可以管多個活動：主鍵是配對，不是單欄唯一。
	if _, err := pool.ExecContext(context.Background(), `INSERT INTO activity_manager_grants
			(activity_id, account_id, granted_at) VALUES (?, ?, 4500)`, actID2, actCreatorID); err != nil {
		t.Errorf("同一管理人在第二個活動應各有一行指派：%v", err)
	}
	// 撤銷舊行再插入新行是改指派的正確表達：刪除必須走得通（不配 CASCADE 也不擋手動撤銷）。
	if _, err := pool.ExecContext(context.Background(), `DELETE FROM activity_manager_grants
			WHERE activity_id = ? AND account_id = ?`, actID2, actCreatorID); err != nil {
		t.Errorf("撤銷指派行應走得通：%v", err)
	}
	// 歸檔不刪行：終態的活動仍被指派表指著（活動永不物理刪除，指派不會變成孤兒）。
	if _, err := pool.ExecContext(context.Background(), `UPDATE activities
			SET status = 'archived', archived_at = 4600, updated_at = 4600 WHERE id = ?`, actID1); err != nil {
		t.Errorf("合法活動應能進入歸檔態：%v", err)
	}
	if got := mustCount(t, pool,
		"SELECT COUNT(*) FROM activity_manager_grants WHERE activity_id = ?", actID1); got != 1 {
		t.Errorf("歸檔後指派行仍要在原處（仍列、可讀、拒寫），實際 %d 行", got)
	}
	// 歸檔是終態：資料庫層不開放「解除歸檔」這條路（時刻與狀態成對，拆開就寫不進）。
	expectAbort(t, pool, "把歸檔態改回 active 卻留著歸檔時刻",
		`UPDATE activities SET status = 'active' WHERE id = ?`, actID1)
}
