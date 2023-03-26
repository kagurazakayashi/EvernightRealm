// member_directory_test.go 是遷移 0016（activities.member_directory_mode 與
// activity_members.directory_visibility）的證據：這一支只加兩欄、一個字都不回頭改寫，
// 而「既有活動讀成目錄不開放」與「既有成員讀成沒有覆蓋」兩件事都來自 DEFAULT，
// 不是某段程式補寫出來的。
//
// 取證重點與新增一張表那兩支不同：
//   - 本步新增的是「誰能看見誰」這種可見性事實，因此先要釘住「升級不會讓任何人突然变得可見」；
//   - 兩欄的封閉集合都要在 SQL 層成立——繞過域層直寫資料庫的那條路（誤操作、外部工具）
//     同樣寫不進一個解釋不了的模式值或覆蓋值，尤其是「放寬」那一類（visible、public）；
//   - 兩張既有表的觸發器必須還在原處：身份欄不可就地改寫這句話與本支無關，
//     卻最容易被「重建表」那種做法弄丟。
package migrate

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"
)

// dirFacID1 與 dirFacID2 掛在 dbAt0014WithFacts 已經種下的兩場活動下（同一批既有事實）。
const (
	dirMemberID1 = "0192f0c4-1c9a-7000-8000-000000000f31" // 合法成員一（屬活動一）
	dirMemberID2 = "0192f0c4-1c9a-7000-8000-000000000f32" // 合法成員二（屬活動二）
)

// directoryMemberFacts 讀 activity_members 那幾欄「0016 絕對不該動」的既有事實，
// 刻意不把新欄列進去：新欄由 DEFAULT 出現，舊欄逐字不動才是本支要證的那句話。
// （直接用 snapshotRows 會因為多了一欄而必然不同，那個差異不是取證對象。）
func directoryMemberFacts(t *testing.T, pool *sql.DB) string {
	t.Helper()
	rows, err := pool.QueryContext(context.Background(), `SELECT id, activity_id, account_id,
			nickname, COALESCE(faction_id, ''), created_at, updated_at
		FROM activity_members ORDER BY id`)
	if err != nil {
		t.Fatalf("讀取成員既有事實失敗：%v", err)
	}
	defer rows.Close()

	var out strings.Builder
	for rows.Next() {
		var id, activityID, accountID, nickname, factionID string
		var joinedAt, updatedAt int64
		if err := rows.Scan(&id, &activityID, &accountID, &nickname, &factionID,
			&joinedAt, &updatedAt); err != nil {
			t.Fatalf("解析成員既有事實失敗：%v", err)
		}
		out.WriteString(id + "|" + activityID + "|" + accountID + "|" + nickname + "|" +
			factionID + "|" + strconv.FormatInt(joinedAt, 10) + "|" +
			strconv.FormatInt(updatedAt, 10) + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍歷成員既有事實失敗：%v", err)
	}
	return out.String()
}

// knownSplitTo0016 把內嵌遷移拆成「到 0015 為止的全部」與「0016 本身」兩段。
//
// 拆兩段與 0015 那一步同一理由：applySet 對版本嚴格遞增把關，
// 而本檔需要一座「0016 還沒落地」的資料庫才能先取既有事實的快照。
// 比 0016 更新的版本不在此列（日后的遷移不該回头讓本檔變紅）。
func knownSplitTo0016(t *testing.T) (through15, only16 []Migration) {
	t.Helper()
	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	for _, m := range known {
		switch {
		case m.Version < 16:
			through15 = append(through15, m)
		case m.Version == 16:
			only16 = append(only16, m)
		}
	}
	if len(only16) != 1 {
		t.Fatalf("必須恰好一支 0016，實際 %d", len(only16))
	}
	return through15, only16
}

// applyThrough0016 把「到 0016 為止的完整清單」套到一座已在 0015 的池子上。
//
// 刻意不單獨交 only16：applySet 對版本表的連續性把關（版本表裡有 1..15 而清單只有 16
// 會被讀成「執行檔缺少前面的遷移檔」），既有測試全部交完整清單，這裡也照同一條規則走。
func applyThrough0016(t *testing.T, pool *sql.DB) {
	t.Helper()
	through15, only16 := knownSplitTo0016(t)
	if _, err := applySet(context.Background(), pool, append(through15, only16...), Options{}); err != nil {
		t.Fatalf("套用 0016 失敗：%v", err)
	}
}
func dbAt0015WithDirectoryFacts(t *testing.T) *sql.DB {
	t.Helper()
	pool := dbAt0014WithFacts(t)
	through15, only16 := knownSplitTo0016(t)
	if _, err := applySet(context.Background(), pool, through15, Options{}); err != nil {
		t.Fatalf("先套到 0015 失敗：%v", err)
	}
	if len(only16) != 1 {
		t.Fatalf("0016 必須恰好一支")
	}
	// 一行已分組、一行尚未分組：本支不得動任何人的歸屬（0015 收回開關也不清歸屬同一態度）。
	insertMember(t, pool, dirMemberID1, memActID1, actCreatorID, "已分組的那一位")
	if _, err := pool.ExecContext(context.Background(),
		`UPDATE activity_members SET faction_id = ? WHERE id = ?`,
		memFacID1, dirMemberID1); err != nil {
		t.Fatalf("種下陣營歸屬失敗：%v", err)
	}
	insertMember(t, pool, dirMemberID2, memActID2, v10GuestID, "尚未分組的那一位")
	return pool
}

// TestMemberDirectoryMigrationKeepsEveryOldFact 驗收：0016 只加兩欄，
// 舊的活動行、成員行、帳戶行與陣營行一個字都沒動，既有觸發器還在原處。
func TestMemberDirectoryMigrationKeepsEveryOldFact(t *testing.T) {
	ctx := context.Background()
	pool := dbAt0015WithDirectoryFacts(t)
	defer pool.Close()

	activitiesBefore := selectActivityFacts(t, pool)
	membersBefore := directoryMemberFacts(t, pool)
	accountsBefore := snapshotRows(t, pool, "accounts")
	factionsBefore := snapshotRows(t, pool, "activity_factions")

	applyThrough0016(t, pool)

	if after := directoryMemberFacts(t, pool); after != membersBefore {
		t.Errorf("0016 改寫了成員側既有事實：\n舊 %s\n新 %s", membersBefore, after)
	}
	// 活動側逐字不動要另外證一次：這一步同時在 activities 上加欄，
	// 而 selectActivityFacts 的欄位清單裡沒有新欄。
	if after := selectActivityFacts(t, pool); after != activitiesBefore {
		t.Errorf("0016 改寫了活動側既有事實：\n舊 %s\n新 %s", activitiesBefore, after)
	}
	if after := snapshotRows(t, pool, "accounts"); after != accountsBefore {
		t.Errorf("0016 改寫了帳戶側既有事實：\n舊 %s\n新 %s", accountsBefore, after)
	}
	if after := snapshotRows(t, pool, "activity_factions"); after != factionsBefore {
		t.Errorf("0016 改寫了陣營側既有事實：\n舊 %s\n新 %s", factionsBefore, after)
	}
	if got := mustCount(t, pool,
		"SELECT COUNT(*) FROM schema_migrations WHERE version = 16"); got != 1 {
		t.Errorf("0016 應留下一筆版本記錄，實際 %d 筆", got)
	}
	var header int
	if err := pool.QueryRowContext(ctx, "PRAGMA user_version").Scan(&header); err != nil {
		t.Fatalf("讀檔頭版本失敗：%v", err)
	}
	if header != 16 {
		t.Errorf("檔頭版本應推進到 16，實際 %d", header)
	}
	// 本支不建新表：可見性是兩張既有表各自的屬性，不是第三個一等實體。
	for _, name := range []string{"activity_member_directory", "member_directory_settings",
		"member_directory_grants"} {
		if got := mustCount(t, pool,
			"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", name); got != 0 {
			t.Errorf("0016 不得另建 %s，實際 %d 張", name, got)
		}
	}
	// 兩張表的「身份不可就地改寫」觸發器仍在原處：本支只是各多一欄，沒有理由動過它們。
	if _, err := pool.ExecContext(ctx, `UPDATE activities SET id = ? WHERE id = ?`,
		memActID2, memActID1); err == nil ||
		!strings.Contains(err.Error(), "活動主鍵不可就地改寫") {
		t.Errorf("0016 之後活動主鍵觸發器必須仍然擋下就地改寫，實際 %v", err)
	}
	if _, err := pool.ExecContext(ctx, `UPDATE activity_members SET account_id = ? WHERE id = ?`,
		v10GuestID, dirMemberID1); err == nil ||
		!strings.Contains(err.Error(), "不可就地改寫") {
		t.Errorf("0016 之後成員身份觸發器必須仍然擋下就地改寫，實際 %v", err)
	}
}

// TestMemberDirectoryDefaultsComeFromMigration 驗收兩欄的出廠值：
// 不在欄位清單裡的寫法一律走 DEFAULT，於是「既有活動讀成目錄不開放」與
// 「既有與新建的成員行讀成沒有覆蓋」在同一種 SQL 形狀下成立，不需要任何程式補寫。
func TestMemberDirectoryDefaultsComeFromMigration(t *testing.T) {
	pool := dbAt0015WithDirectoryFacts(t)
	defer pool.Close()

	applyThrough0016(t, pool)

	// 既有活動：讀成 hidden（不是 same_faction_only，也不是 any）。
	if got := directoryModeOf(t, pool, memActID1); got != "hidden" {
		t.Errorf("既有活動的目錄模式必須讀成 hidden，實際 %q", got)
	}
	if got := directoryModeOf(t, pool, memActID2); got != "hidden" {
		t.Errorf("既有活動二的目錄模式必須讀成 hidden，實際 %q", got)
	}
	// 既有成員行（含已分組那一行）：讀成 inherit——本支不替任何人決定「要不要被收起來」。
	for _, memberID := range []string{dirMemberID1, dirMemberID2} {
		if got := directoryVisibilityOf(t, pool, memberID); got != "inherit" {
			t.Errorf("成員 %s 的覆蓋必須讀成 inherit，實際 %q", memberID, got)
		}
	}

	// 不列新欄的新行（insertActivity／insertMember 的欄位清單）照樣讀成出廠值。
	// 帳戶刻意選 v10GuestID：actCreatorID 已經在活動一裡有一份檔案（UNIQUE 那句話先在本檔的
	// 佈資料層成立，否則取證還沒開始就撞在自己種的那一行上）。
	insertActivity(t, pool, memID1, "本支之後新建的活動", "draft", 8000, nil)
	if got := directoryModeOf(t, pool, memID1); got != "hidden" {
		t.Errorf("新建活動的目錄模式必須是 hidden，實際 %q", got)
	}
	insertMember(t, pool, memID2, memActID1, v10GuestID, "本支之後新建的成員")
	if got := directoryVisibilityOf(t, pool, memID2); got != "inherit" {
		t.Errorf("新建成員的覆蓋必須是 inherit，實際 %q", got)
	}
}

// TestMemberDirectoryClosedSetsRejectIllegalValues 驗收兩欄的封閉集合在 SQL 層成立：
// 合法取值全部寫得進去，集合外、大小寫變體、空字串與 NULL 一律撞牆。
//
// 「放寬可見範圍」那一類取值（visible、public、everyone）在這裡必須與壞字串同命：
// 本步批准的覆蓋只能收緊，庫層沒有給它留任何一格。
func TestMemberDirectoryClosedSetsRejectIllegalValues(t *testing.T) {
	ctx := context.Background()
	pool := dbAt0015WithDirectoryFacts(t)
	applyThrough0016(t, pool)

	// 四個合法模式逐一寫入並讀回（封閉，但不止一個值）。
	for _, mode := range []string{"hidden", "same_faction_only",
		"all_players_except_admin", "all_members"} {
		if _, err := pool.ExecContext(ctx,
			`UPDATE activities SET member_directory_mode = ? WHERE id = ?`,
			mode, memActID1); err != nil {
			t.Fatalf("模式 %q 屬封閉集合內，應寫得進去：%v", mode, err)
		}
		if got := directoryModeOf(t, pool, memActID1); got != mode {
			t.Errorf("寫入 %q 後必須讀回同一個值，實際 %q", mode, got)
		}
	}
	// 兩個合法覆蓋同理。
	for _, visibility := range []string{"inherit", "hidden"} {
		if _, err := pool.ExecContext(ctx,
			`UPDATE activity_members SET directory_visibility = ? WHERE id = ?`,
			visibility, dirMemberID1); err != nil {
			t.Fatalf("覆蓋 %q 屬封閉集合內，應寫得進去：%v", visibility, err)
		}
		if got := directoryVisibilityOf(t, pool, dirMemberID1); got != visibility {
			t.Errorf("寫入 %q 後必須讀回同一個值，實際 %q", visibility, got)
		}
	}

	for _, statement := range []string{
		// 集合外的模式；大小寫變體（域層與遷移 0015 同樣不放過）；空字串；NULL。
		`UPDATE activities SET member_directory_mode = 'everyone' WHERE id = '` + memActID1 + `'`,
		`UPDATE activities SET member_directory_mode = 'HIDDEN' WHERE id = '` + memActID1 + `'`,
		`UPDATE activities SET member_directory_mode = '' WHERE id = '` + memActID1 + `'`,
		`UPDATE activities SET member_directory_mode = NULL WHERE id = '` + memActID1 + `'`,
		// 集合外的覆蓋，含三個「意圖是放寬」的寫法：庫層一律無處可填。
		`UPDATE activity_members SET directory_visibility = 'visible' WHERE id = '` + dirMemberID1 + `'`,
		`UPDATE activity_members SET directory_visibility = 'public' WHERE id = '` + dirMemberID1 + `'`,
		`UPDATE activity_members SET directory_visibility = 'INHERIT' WHERE id = '` + dirMemberID1 + `'`,
		`UPDATE activity_members SET directory_visibility = '' WHERE id = '` + dirMemberID1 + `'`,
		`UPDATE activity_members SET directory_visibility = NULL WHERE id = '` + dirMemberID1 + `'`,
		// 繞過應用的直寫插入也要撞牆（欄位清單齊全，只有取值不對）。
		`INSERT INTO activities (id, name, description, status, member_directory_mode,
			created_by_account_id, created_at, updated_at)
		VALUES ('` + memGhostAct + `', '壞模式', '', 'draft', 'ALL_MEMBERS', '` +
			actCreatorID + `', 1, 1)`,
		`INSERT INTO activity_members (id, activity_id, account_id, nickname,
			directory_visibility, created_at, updated_at)
		VALUES ('` + memGhostID + `', '` + memActID1 + `', '` + actCreatorID + `', '壞覆蓋',
			'everyone', 1, 1)`,
	} {
		// NULL 那幾句撞的是 NOT NULL（不是 CHECK），兩種都算「在 SQL 層被撞牆」：
		// 這一欄的把關在資料庫，不在任何一段 Go 程式碼裡。
		if _, err := pool.ExecContext(ctx, statement); err == nil ||
			!strings.Contains(err.Error(), "constraint failed") {
			t.Errorf("這句必須撞 CHECK，實際錯誤：%v（%.40s）", err, statement)
		}
	}

	// 兩欄各自獨立：改目錄模式不會動到任何人的覆蓋，反之亦然（白名單寫入的形態）。
	if _, err := pool.ExecContext(ctx,
		`UPDATE activities SET member_directory_mode = 'all_members' WHERE id = ?`,
		memActID1); err != nil {
		t.Fatalf("合法模式應寫得進去：%v", err)
	}
	if got := directoryVisibilityOf(t, pool, dirMemberID1); got != "hidden" {
		t.Errorf("改活動模式不該動到成員覆蓋，實際 %q", got)
	}
	// 也與生命週期無關：狀態成對那條 CHECK 不受本支影響。
	if _, err := pool.ExecContext(ctx,
		`UPDATE activities SET member_directory_mode = 'hidden', status = 'archived' WHERE id = ?`,
		memActID1); err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Errorf("狀態成對規則必須仍在（歸檔要帶 archived_at），實際 %v", err)
	}
}

// directoryModeOf 讀回一欄 member_directory_mode（它帶 NOT NULL，讀不出即為取證失敗）。
func directoryModeOf(t *testing.T, pool *sql.DB, id string) string {
	t.Helper()
	var mode string
	err := pool.QueryRowContext(context.Background(),
		"SELECT member_directory_mode FROM activities WHERE id = ?", id).Scan(&mode)
	if err != nil {
		t.Fatalf("讀取活動 %s 的目錄模式失敗：%v", id, err)
	}
	return mode
}

// directoryVisibilityOf 讀回一欄 directory_visibility。
func directoryVisibilityOf(t *testing.T, pool *sql.DB, id string) string {
	t.Helper()
	var visibility string
	err := pool.QueryRowContext(context.Background(),
		"SELECT directory_visibility FROM activity_members WHERE id = ?", id).Scan(&visibility)
	if err != nil {
		t.Fatalf("讀取成員 %s 的目錄覆蓋失敗：%v", id, err)
	}
	return visibility
}
