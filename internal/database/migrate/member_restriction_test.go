// member_restriction_test.go 驗收遷移 0019：玩家分項限制的持久形態。
//
// 三個驗收面各自對應本步的一句決定：
//  1. 增量遷移不傷既有事實——六欄由 DEFAULT 落在 0（不限制），既有 Profile 不被
//     「重置」、也不需要在升級後突然凍結任何人；遷移之後新建的行照樣落預設值；
//  2. 六欄各自的封閉形態：CHECK 只收 0/1，繞過應用層的直寫（2、-1、文字）進不來；
//     0014 的「身分三欄不可就地改寫」觸發器不因為多六欄而鬆動，
//     而六欄本身可以被 UPDATE 逐欄翻動——「各存各欄、各改各的」在資料庫層成立；
//  3. 六欄都落在 activity_members 上，沒有新增任何指向 accounts 的邊：這是綁定預檢
//     不需要新增登記、既有綁定通路照常走得動的結構依據。
package migrate

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// knownSplitTo0019 把內嵌遷移拆成「到 0018 為止的全部」與「0019 本身」兩段。
//
// 拆兩段的理由同前幾支：本檔需要一座「0019 還沒落地」的資料庫才能先取既有事實的快照。
func knownSplitTo0019(t *testing.T) (through18, only19 []Migration) {
	t.Helper()
	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗：%v", err)
	}
	for _, m := range known {
		switch {
		case m.Version < 19:
			through18 = append(through18, m)
		case m.Version == 19:
			only19 = append(only19, m)
		}
	}
	if len(only19) != 1 {
		t.Fatalf("必須恰好一支 0019，實際 %d", len(only19))
	}
	return through18, only19
}

// dbAt0019WithFacts 建出一座「既有 0018 事實、已套上 0019」的資料庫。
//
// 現場複用狀態那一步的池子（兩場活動、兩行成員、陣營與標籤都在），
// 於是「加了六欄之後舊的一行一欄都沒動」這一句有可比對的舊值。
func dbAt0019WithFacts(t *testing.T) *sql.DB {
	t.Helper()
	pool := dbAt0018WithFacts(t)
	through18, only19 := knownSplitTo0019(t)
	if _, err := applySet(context.Background(), pool, append(through18, only19...),
		Options{}); err != nil {
		t.Fatalf("套用 0019 失敗：%v", err)
	}
	return pool
}

// restrictionFactsOf 讀一行的六欄限制（逐欄原樣讀成整數）。
func restrictionFactsOf(t *testing.T, pool *sql.DB, memberID string) []int64 {
	t.Helper()
	var flags [6]int64
	err := pool.QueryRowContext(context.Background(), `SELECT restrict_login,
			restrict_chat, restrict_private_chat, restrict_trade, restrict_transfer,
			restrict_item_use
		FROM activity_members WHERE id = ?`, memberID).
		Scan(&flags[0], &flags[1], &flags[2], &flags[3], &flags[4], &flags[5])
	if err != nil {
		t.Fatalf("讀取成員 %s 的六欄限制失敗：%v", memberID, err)
	}
	return flags[:]
}

// mustReadAllZero 斷言六欄全 0（出廠與遷移後的相容形態）。
func mustReadAllZero(t *testing.T, pool *sql.DB, memberID, why string) {
	t.Helper()
	for i, value := range restrictionFactsOf(t, pool, memberID) {
		if value != 0 {
			t.Errorf("%s：成員 %s 的第 %d 欄限制必須是 0，實際 %d", why, memberID, i+1, value)
		}
	}
}

// TestMemberRestrictionMigrationKeepsEveryOldFact 驗收：0019 只加六欄預設值，
// 既有事實一個字都沒動，而且不需要回填——既有成員自動讀成「全不限制」。
func TestMemberRestrictionMigrationKeepsEveryOldFact(t *testing.T) {
	ctx := context.Background()
	pool := dbAt0015WithDirectoryFacts(t)
	defer pool.Close()

	through18, only19 := knownSplitTo0019(t)
	if _, err := applySet(ctx, pool, through18, Options{}); err != nil {
		t.Fatalf("先套到 0018 失敗：%v", err)
	}
	accountsBefore := factsSnapshot(t, pool)
	factionsBefore := snapshotRows(t, pool, "activity_factions")
	tagsBefore := snapshotRows(t, pool, "activity_tags")
	statusesBefore := snapshotRows(t, pool, "activity_player_statuses")
	membersBefore := directoryMemberFacts(t, pool)
	statusSideBefore := map[string]string{}
	for _, memberID := range []string{dirMemberID1, dirMemberID2} {
		status, custom := memberStatusOf(t, pool, memberID)
		statusSideBefore[memberID] = status + "|" + custom
	}

	if _, err := applySet(ctx, pool, append(through18, only19...), Options{}); err != nil {
		t.Fatalf("套用 0019 失敗：%v", err)
	}

	if after := factsSnapshot(t, pool); after != accountsBefore {
		t.Errorf("0019 改寫了帳戶側既有事實：\n舊 %s\n新 %s", accountsBefore, after)
	}
	if after := snapshotRows(t, pool, "activity_factions"); after != factionsBefore {
		t.Errorf("0019 改寫了陣營側既有事實：\n舊 %s\n新 %s", factionsBefore, after)
	}
	if after := snapshotRows(t, pool, "activity_tags"); after != tagsBefore {
		t.Errorf("0019 改寫了標籤側既有事實：\n舊 %s\n新 %s", tagsBefore, after)
	}
	if after := snapshotRows(t, pool, "activity_player_statuses"); after != statusesBefore {
		t.Errorf("0019 改寫了自訂狀態既有事實：\n舊 %s\n新 %s", statusesBefore, after)
	}
	if after := directoryMemberFacts(t, pool); after != membersBefore {
		t.Errorf("0019 改寫了成員側既有事實：\n舊 %s\n新 %s", membersBefore, after)
	}
	for _, memberID := range []string{dirMemberID1, dirMemberID2} {
		status, custom := memberStatusOf(t, pool, memberID)
		if got := status + "|" + custom; got != statusSideBefore[memberID] {
			t.Errorf("0019 不該動業務狀態兩欄：成員 %s 舊 %s 新 %s",
				memberID, statusSideBefore[memberID], got)
		}
	}

	// 既有兩行成員由 DEFAULT 直接落在 0：這就是「遷移不重置、也不凍結任何人」的形態。
	for _, memberID := range []string{dirMemberID1, dirMemberID2} {
		mustReadAllZero(t, pool, memberID, "遷移後的既有行")
	}
	// 遷移之後新建的行也照樣落預設值（insertMember 的欄位清單裡沒有新欄）。
	insertMember(t, pool, memID3, memActID1, v10GuestID, "0019 之後新建的成員")
	mustReadAllZero(t, pool, memID3, "遷移後新建的行")
}

// TestMemberRestrictionColumnRules 驗收：六欄各自的封閉形態——CHECK 只收 0/1，
// 被選中的欄可以逐欄翻動，沒被 UPDATE 點名的欄原樣不動。
func TestMemberRestrictionColumnRules(t *testing.T) {
	ctx := context.Background()
	pool := dbAt0019WithFacts(t)
	defer pool.Close()

	// 集合外取值一律被擋（繞過應用層的直寫也進不來）。
	mustFailWith(t, pool, "限制欄寫 2", "CHECK",
		`UPDATE activity_members SET restrict_login = 2 WHERE id = ?`, dirMemberID1)
	mustFailWith(t, pool, "限制欄寫 -1", "CHECK",
		`UPDATE activity_members SET restrict_chat = -1 WHERE id = ?`, dirMemberID1)
	mustFailWith(t, pool, "限制欄寫文字", "CHECK",
		`UPDATE activity_members SET restrict_item_use = 'yes' WHERE id = ?`, dirMemberID1)
	mustFailWith(t, pool, "新建行帶集合外限制", "CHECK",
		`INSERT INTO activity_members (id, activity_id, account_id, nickname,
			restrict_private_chat, created_at, updated_at)
		VALUES (?, ?, ?, ?, 7, 9000, 9000)`,
		"0192f0c4-1c9a-7000-8000-000000000h31", memActID1, memID1, "寫壞限制的_row")

	// 逐欄翻動：只點名 restrict_login 與 restrict_trade，其餘四欄必須原樣。
	if _, err := pool.ExecContext(ctx, `UPDATE activity_members
		SET restrict_login = 1, restrict_trade = 1 WHERE id = ?`, dirMemberID1); err != nil {
		t.Fatalf("翻動兩欄限制應成功：%v", err)
	}
	got := restrictionFactsOf(t, pool, dirMemberID1)
	if got[0] != 1 || got[3] != 1 || got[1] != 0 || got[2] != 0 || got[4] != 0 || got[5] != 0 {
		t.Errorf("只有被點名的兩欄該翻，實際 %v", got)
	}

	// 取消一欄不順手取消另一欄（同形在服務層另有端到端取證）。
	if _, err := pool.ExecContext(ctx, `UPDATE activity_members
		SET restrict_login = 0 WHERE id = ?`, dirMemberID1); err != nil {
		t.Fatalf("單獨取消 login 應成功：%v", err)
	}
	got = restrictionFactsOf(t, pool, dirMemberID1)
	if got[0] != 0 || got[3] != 1 {
		t.Errorf("取消 login 不該牽動 trade，實際 %v", got)
	}
}

// TestMemberRestrictionIdentityTriggerUnmoved 驗收：六欄的加入不鬆動 0014 的
// 「身分三欄不可就地改寫」——限制可以改，身份改不動。
func TestMemberRestrictionIdentityTriggerUnmoved(t *testing.T) {
	ctx := context.Background()
	pool := dbAt0019WithFacts(t)
	defer pool.Close()

	if _, err := pool.ExecContext(ctx, `UPDATE activity_members
		SET restrict_transfer = 1, activity_id = ? WHERE id = ?`, memActID1, dirMemberID1); err == nil {
		t.Fatalf("同一條 UPDATE 想把限制與歸屬一起改寫必須被擋")
	} else if !strings.Contains(err.Error(), "不可就地改寫") {
		t.Errorf("錯誤句子該含觸發器那句，實際 %v", err)
	}
	// 被擋的整條 UPDATE 一個字都不落。
	if got := restrictionFactsOf(t, pool, dirMemberID1); got[4] != 0 {
		t.Errorf("整條 UPDATE 回滾後 transfer 必須原樣，實際 %v", got)
	}
}
