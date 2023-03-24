// faction_select_test.go 是遷移 0015（activities.faction_select_mode）的證據：
// 這一欄只加不換——舊的行一個字都沒動、既有觸發器還在原處，而「既有活動讀成沒開放自選」
// 與「新建的活動也讀成沒開放」兩件事都來自 DEFAULT，不是某段程式補寫出來的。
//
// 取證重點因此與新增一張表那兩支不同：本支要釘住的是「新增一欄不回頭改寫任何既有事實」，
// 以及「封閉集合在 SQL 層成立」——繞過域層直寫資料庫的那條路（誤操作、外部工具）
// 同樣必須寫不進一個解釋不了的模式值。
package migrate

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"
)

// selectActivityFacts 讀 activities 那幾欄「0015 絕對不該動」的既有事實，
// 刻意不把新欄列進去：新欄由 DEFAULT 出現，舊欄逐字不動才是本支遷移要證的那句話。
func selectActivityFacts(t *testing.T, pool *sql.DB) string {
	t.Helper()
	rows, err := pool.QueryContext(context.Background(), `SELECT id, name, description, status,
			COALESCE(created_by_account_id, ''), created_at, updated_at,
			COALESCE(archived_at, 0)
		FROM activities ORDER BY id`)
	if err != nil {
		t.Fatalf("讀取活動既有事實失敗：%v", err)
	}
	defer rows.Close()

	var out strings.Builder
	for rows.Next() {
		var id, name, description, status, creator string
		var createdAt, updatedAt, archivedAt int64
		if err := rows.Scan(&id, &name, &description, &status, &creator,
			&createdAt, &updatedAt, &archivedAt); err != nil {
			t.Fatalf("解析活動既有事實失敗：%v", err)
		}
		out.WriteString(id + "|" + name + "|" + description + "|" + status + "|" + creator + "|" +
			strconv.FormatInt(createdAt, 10) + "|" + strconv.FormatInt(updatedAt, 10) + "|" + strconv.FormatInt(archivedAt, 10) + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("讀取活動既有事實中途失敗：%v", err)
	}
	return out.String()
}

// knownSplitTo0015 把內嵌遷移拆成「到 0014 為止的全部」與「0015 本身」兩段
// （拆兩段的理由同 members_test.go：applySet 對版本嚴格遞增把關，同一支套兩次是缺陷）。
func knownSplitTo0015(t *testing.T) (through14, only15 []Migration) {
	t.Helper()
	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	for _, m := range known {
		switch {
		case m.Version < 15:
			through14 = append(through14, m)
		case m.Version == 15:
			only15 = append(only15, m)
		}
	}
	if len(only15) != 1 {
		t.Fatalf("必須恰好一支 0015，實際 %d", len(only15))
	}
	return through14, only15
}

// TestFactionSelectMigrationKeepsEveryOldFact 驗收：0015 只加一欄，舊行逐字在原處，
// 而既有活動與新佈資料的活動都讀成 disabled（相容規則的落點）。
func TestFactionSelectMigrationKeepsEveryOldFact(t *testing.T) {
	ctx := context.Background()
	pool := dbAt0014WithFacts(t)

	// dbAt0014WithFacts 的現場已經有兩場活動（active 與 draft）、每場一個陣營與一行成員：
	// 「既有事實」在今天真有這些東西，本支遷移必須一個字都不動它們。
	activitiesBefore := selectActivityFacts(t, pool)
	if !strings.Contains(activitiesBefore, memActID1) {
		t.Fatalf("快照裡必須看得到既有活動行，實際：%q", activitiesBefore)
	}
	accountsBefore := factsSnapshot(t, pool)
	membersBefore := snapshotRows(t, pool, "activity_members")
	factionsBefore := snapshotRows(t, pool, "activity_factions")

	through14, only15 := knownSplitTo0015(t)
	if _, err := applySet(ctx, pool, append(through14, only15...), Options{}); err != nil {
		t.Fatalf("套用 0015 失敗：%v", err)
	}

	if after := selectActivityFacts(t, pool); after != activitiesBefore {
		t.Errorf("0015 改寫了活動側既有事實：\n舊 %s\n新 %s", after, activitiesBefore)
	}
	if after := factsSnapshot(t, pool); after != accountsBefore {
		t.Errorf("0015 改寫了帳戶側既有事實：\n舊 %s\n新 %s", after, accountsBefore)
	}
	if after := snapshotRows(t, pool, "activity_members"); after != membersBefore {
		t.Errorf("0015 改寫了成員側既有事實：\n舊 %s\n新 %s", after, membersBefore)
	}
	if after := snapshotRows(t, pool, "activity_factions"); after != factionsBefore {
		t.Errorf("0015 改寫了陣營側既有事實：\n舊 %s\n新 %s", after, factionsBefore)
	}
	if got := mustCount(t, pool, "SELECT COUNT(*) FROM schema_migrations WHERE version = 15"); got != 1 {
		t.Errorf("0015 應留下一筆版本記錄，實際 %d 筆", got)
	}
	var header int
	if err := pool.QueryRowContext(ctx, "PRAGMA user_version").Scan(&header); err != nil {
		t.Fatalf("讀檔頭版本失敗：%v", err)
	}
	if header != 15 {
		t.Errorf("檔頭版本應推進到 15，實際 %d", header)
	}
	// 本支不建新表也不建索引：它只是活動那一行多一欄（拿 sqlite_master 數一次，
	// 免得將來說「配置是一張獨立設定表」時查不出這是什麼時候變的）。
	if got := mustCount(t, pool,
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'activity_faction_select'"); got != 0 {
		t.Errorf("0015 不得另建設定表，實際 %d 張", got)
	}
	// 既有觸發器還在原處：主鍵不可就地改寫這條與本支無關，卻最容易被「重建表」那種做法弄丟。
	if _, err := pool.ExecContext(ctx, `UPDATE activities SET id = ? WHERE id = ?`,
		memActID2, memActID1); err == nil ||
		!strings.Contains(err.Error(), "活動主鍵不可就地改寫") {
		t.Errorf("0015 之後主鍵觸發器必須仍然擋下就地改寫，實際 %v", err)
	}
}

// TestFactionSelectModeDefaultAndClosedSet 驗收那一欄的出廠值與封閉集合：
// 不在欄位清單裡的寫法一律走 DEFAULT（包括新建立的活動），集合外取值與 NULL 都撞 CHECK。
func TestFactionSelectModeDefaultAndClosedSet(t *testing.T) {
	ctx := context.Background()
	pool := dbAt0014WithFacts(t)
	through14, only15 := knownSplitTo0015(t)
	if _, err := applySet(ctx, pool, append(through14, only15...), Options{}); err != nil {
		t.Fatalf("套用 0015 失敗：%v", err)
	}

	// insertActivity 的欄位清單裡沒有這一欄：它讀到的就是 DEFAULT，
	// 「新功能不未經批準就向所有活動開放」因此在每一種寫法下都成立。
	if got := modeOf(t, pool, memActID1); got != "disabled" {
		t.Errorf("既有活動必須讀成 disabled，實際 %q", got)
	}

	// 三個合法取值都寫得進去（集合是封閉的，但不是只有一個值）。
	for _, mode := range []string{"disabled", "first_only", "free"} {
		if _, err := pool.ExecContext(ctx,
			`UPDATE activities SET faction_select_mode = ? WHERE id = ?`, mode, memActID1); err != nil {
			t.Fatalf("模式 %q 屬封閉集合內，應寫得進去：%v", mode, err)
		}
		if got := modeOf(t, pool, memActID1); got != mode {
			t.Errorf("寫入 %q 後必須讀回同一個值，實際 %q", mode, got)
		}
	}

	// 集合外、空字串與 NULL 都在 SQL 層被撞牆（繞過域層直寫的那條路同樣擋住）。
	for _, statement := range []string{
		`UPDATE activities SET faction_select_mode = 'unlimited' WHERE id = '` + memActID1 + `'`,
		`UPDATE activities SET faction_select_mode = '' WHERE id = '` + memActID1 + `'`,
		`UPDATE activities SET faction_select_mode = NULL WHERE id = '` + memActID1 + `'`,
		`INSERT INTO activities (id, name, description, status, faction_select_mode,
			created_by_account_id, created_at, updated_at)
		VALUES ('` + memGhostAct + `', '壞取值', '', 'draft', 'FREE', '` + actCreatorID + `', 1, 1)`,
	} {
		// NULL 那一句撞的是 NOT NULL（它不是 CHECK 那條），兩種都算「在 SQL 層被撞牆」：
		// 這一欄的把關在資料庫，不在任何一段 Go 程式碼裡。
		if _, err := pool.ExecContext(ctx, statement); err == nil ||
			!strings.Contains(err.Error(), "constraint failed") {
			t.Errorf("這句必須撞 CHECK，實際錯誤：%v（%s）", err, statement[:40])
		}
	}

	// 帶欄位清單的新行可以顯式選一個合法值（配置寫入通路的形態）。
	if _, err := pool.ExecContext(ctx, `INSERT INTO activities (id, name, description, status,
			faction_select_mode, created_by_account_id, created_at, updated_at)
		VALUES (?, '顯式選 free', '', 'draft', 'free', ?, 6000, 6000)`,
		memID1, actCreatorID); err != nil {
		t.Fatalf("合法取值應寫得進去：%v", err)
	}
	if got := modeOf(t, pool, memID1); got != "free" {
		t.Errorf("顯式寫入必須讀回 free，實際 %q", got)
	}
	// 而這一欄與生命週期無關：狀態那四態的 CHECK 不受本支影響。
	if _, err := pool.ExecContext(ctx,
		`UPDATE activities SET faction_select_mode = 'free', status = 'archived' WHERE id = ?`,
		memActID1); err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Errorf("狀態成對規則必須仍在（歸檔要帶 archived_at），實際 %v", err)
	}
}

// modeOf 讀回一欄 faction_select_mode（NULL 讀不成，因為它帶 NOT NULL）。
func modeOf(t *testing.T, pool *sql.DB, id string) string {
	t.Helper()
	var mode string
	err := pool.QueryRowContext(context.Background(),
		"SELECT faction_select_mode FROM activities WHERE id = ?", id).Scan(&mode)
	if err != nil {
		t.Fatalf("讀取活動 %s 的模式失敗：%v", id, err)
	}
	return mode
}
