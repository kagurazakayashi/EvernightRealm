// r4_faction_directory_matrix_test.go 是「陣營變更與玩家目錄授權閉環」的整體驗收證據：
// 同一套自建現場把同一個帳戶放了進兩場活動（兩場各有各的陣營與目錄規則），
// 再把同陣營、異陣營、無陣營、停用陣營、持有授予者、未獲指派的管理人、訪戶與外人帳戶
// 全部排進同一台真庫真會話的服務裡，沿完整中介層逐端點問一句：
// 「選擇陣營、停用陣營、自選開關、目錄覆蓋、目錄模式這五類變更落地之後，
// 列表、搜尋、單筆詳情、計數、篩選候選、分頁、名冊與本人投影這八個出口，
// 是否各自都按同一份新規則回答」。
//
// 與逐步上線時各檔端到端測試的分工：那一批釘的是「單條通路当天的批准」，
// 本檔釘的是「五類變更 × 八個出口 × 八類角色今天並排成立」——跨步驟互相污染
// （換隊後某一個出口還留在舊答案上、停用把人的歸屬抹掉、覆蓋漏進計數、
// 撤銷指派後還讀得到全量、帳戶轉正或退休後陣營引用變成悬空）會在這裡現形，
// 而單步看不見。
//
// 刻意不收的東西：
//   - 沒有替身：準入、活動作用域、業務寫入門禁、可見性判定、授予現讀、CAS 與審計
//     都跨層走真路徑（真資料庫＋真會話＋注入時鐘），接錯線就會紅；
//   - 不重複四態矩陣的逐模式可見集合（服務層與目錄端點檔已各自取證），
//     本檔量的是「變更落地後八個出口一起改口」與「跨活動、跨角色的邊界在服務層而不是界面」；
//   - 不測管理側的分配與遷出通路：那條路今日不存在，本檔只反證「沒有格子能填它」；
//   - 不碰真實數據目錄、不佔 5206，全程本次專屬的臨時庫。
package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
)

// 三個合法形狀但從未存在的標識：不可分辨性要有對照組，而且要與「真的存在但輪不到他」並排比對。
const (
	r4GhostActivity  = "0192f0c4-1c9a-7000-8000-000000000f51"
	r4GhostMember    = "0192f0c4-1c9a-7000-8000-000000000f52"
	r4GhostFaction   = "0192f0c4-1c9a-7000-8000-000000000f53"
	r4NilUUIDLiteral = "00000000-0000-0000-0000-000000000000"
)

// r4Scene 是本檔共用的現場。
//
// 兩場活動、四個陣營、八行主場成員與三行外場成員，每一格分工都要能餵給某一句結論：
//   - 甲：同一個帳戶在兩場活動各有一行，歸屬不同（跨活動隔離的主角）；
//   - 乙：與甲同陣營（換隊前後都該看見甲，換走後不該）；
//   - 丙：異陣營（換隊前後都不該看見甲，換進來後該）；
//   - 丁：無陣營（「尚未分組」不構成一個群體，僅同陣營態下只看得見自己）；
//   - 己：訪戶成員（參加不是權限，也進目錄）；
//   - 管理人一：持有授予且是本場管理人（管理視角的對象）；
//   - 管理人二：持有授予、管的是另一場，在本場只是普通成員（不因持有授予而提權）；
//   - 幕後：持有授予但任何一場都不歸他管，在本場是普通成員
//     （all_players_except_admin 該對別人收起來的那一行）。
type r4Scene struct {
	env       *factionEnv
	root      string
	manaA     string // 管理人一的會話標頭（主場獲指派）
	manaB     string // 管理人二的會話標頭（外場獲指派）
	activityA string
	activityB string
	red       string            // 主場紅隊
	blue      string            // 主場藍隊
	purple    string            // 外場紫隊
	member    map[string]string // 暱稱 → 成員標識
	cookie    map[string]string // 暱稱 → 會話標頭
	account   map[string]string // 暱稱 → 帳戶標識
}

// newR4Scene 佈好現場。目錄模式保持出廠的 hidden，由各測試自己決定要不要打開；
// 玩家自選那一欄兩場都打開成 free——今日唯一能把歸屬落下的通路就是它。
func newR4Scene(t *testing.T) *r4Scene {
	t.Helper()
	e := newFactionEnv(t)
	s := &r4Scene{env: e, member: map[string]string{}, cookie: map[string]string{},
		account: map[string]string{}}
	s.root = cookieHeader(e.factionRootCookie(t))

	managerAID, managerACookie := e.dirAdminWithSession(t, "r4.manager.a")
	s.manaA = managerACookie
	s.account["管理人一"] = managerAID
	s.activityA = e.createFactionActivity(t, managerACookie, "閉環主場")

	// 第二位管理人自己建的那場活動：他在主場有成員行、卻沒有主場的指派。
	managerBID, managerBCookie := e.dirAdminWithSession(t, "r4.manager.b")
	s.manaB = managerBCookie
	s.account["管理人二"] = managerBID
	s.activityB = e.createFactionActivity(t, managerBCookie, "輪不到主場的場")

	// 第三位持有授予者：他不建活動，因此不獲任何指派——只是主場的一位普通成員。
	backstageID, backstageCookie := e.dirAdminWithSession(t, "r4.backstage")
	s.account["幕後"] = backstageID
	s.cookie["幕後"] = backstageCookie

	e.selfSetMode(t, managerACookie, s.activityA, "free", "disabled")
	e.selfSetMode(t, managerBCookie, s.activityB, "free", "disabled")
	s.red = selfFactionID(t, e.selfCreateFaction(t, managerACookie, s.activityA, "紅隊"))
	s.blue = selfFactionID(t, e.selfCreateFaction(t, managerACookie, s.activityA, "藍隊"))
	s.purple = selfFactionID(t, e.selfCreateFaction(t, managerBCookie, s.activityB, "紫隊"))

	for _, pair := range []struct{ login, nickname string }{
		{"r4.jia", "甲"}, {"r4.yi", "乙"}, {"r4.bing", "丙"}, {"r4.ding", "丁"},
	} {
		accountID, playerCookie := e.selfSelectPlayer(t, managerACookie, pair.login)
		s.account[pair.nickname] = accountID
		s.cookie[pair.nickname] = playerCookie
		s.member[pair.nickname] = e.selfAddMember(t, managerACookie, s.activityA,
			accountID, pair.nickname)
	}

	// 訪戶成員：先打開訪客進入那一格（出廠是關的），再走真實訪戶通路。
	guestID, guestCookie := e.dirGuest(t, "己")
	s.account["己"] = guestID
	s.cookie["己"] = guestCookie
	s.member["己"] = e.selfAddMember(t, managerACookie, s.activityA, guestID, "己")

	// 兩位持有授予的成員行（管理人一與管理人二都真的在主場有一行身份）。
	s.member["管理人一"] = e.selfAddMember(t, managerACookie, s.activityA, managerAID, "管理人一")
	s.member["管理人二"] = e.selfAddMember(t, managerACookie, s.activityA, managerBID, "管理人二")
	s.member["幕後"] = e.selfAddMember(t, managerACookie, s.activityA, backstageID, "幕後")

	// 外場三行：甲的第二行（同一個帳戶）、管理人二、以及一位只在主場有身份的陌生人。
	s.member["甲在別場"] = e.selfAddMember(t, managerBCookie, s.activityB, s.account["甲"], "甲在別場")
	s.member["管理人二在外場"] = e.selfAddMember(t, managerBCookie, s.activityB, managerBID, "管理人二在外場")
	strangerID, strangerCookie := e.selfSelectPlayer(t, managerACookie, "r4.stranger")
	s.account["路人"] = strangerID
	s.cookie["路人"] = strangerCookie
	s.member["路人"] = e.selfAddMember(t, managerBCookie, s.activityB, strangerID, "路人")

	// 歸屬一律由玩家自己選下去（本倉庫今日唯一能寫這一欄的通路）。
	e.dirSelect(t, s.cookie["甲"], s.activityA, s.red)
	e.dirSelect(t, s.cookie["乙"], s.activityA, s.red)
	e.dirSelect(t, s.cookie["己"], s.activityA, s.red)
	e.dirSelect(t, s.cookie["丙"], s.activityA, s.blue)
	e.dirSelect(t, s.cookie["甲"], s.activityB, s.purple)
	return s
}

// —— 現場操作助手：每一條都走端點，不從倉儲抄近路 ——

// dirMode 讀某一場活動的目錄模式庫中現值（結論只問資料庫，不問用例的回憶）。
func (s *r4Scene) dirMode(t *testing.T, activityID string) string {
	t.Helper()
	return r4ActivityColumn(t, s.env.db, activityID, "member_directory_mode")
}

// setDirMode 由指定的管理人寫那一欄目錄模式，回傳狀態碼（合法管理人一律交 s.manaA）。
func (s *r4Scene) setDirMode(t *testing.T, activityID, mode, who string) int {
	t.Helper()
	resp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+activityID+"/member-directory",
		dirBody(t, map[string]any{"mode": mode, "expected_mode": r4ActivityColumn(t, s.env.db, activityID, "member_directory_mode")}), who)
	return resp.StatusCode
}

// mustSetDirMode 把主場那一欄模式換掉（外場要指定管理人，指派不跨場）。
func (s *r4Scene) mustSetDirMode(t *testing.T, activityID, mode string) {
	t.Helper()
	s.mustSetDirModeFor(t, activityID, mode, s.manaA)
}

// mustSetDirModeFor 由「那一場獲指派的管理人」換掉模式並斷言回顯新值。
//
// 依據值一律取庫中現值而不是硬編：本檔的多筆寫入會前後相接，寫死的依據值會讓落敗者
// 看起來像被拒絕，而那並不是本檔要量的東西。
func (s *r4Scene) mustSetDirModeFor(t *testing.T, activityID, mode, who string) {
	t.Helper()
	resp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+activityID+"/member-directory",
		dirBody(t, map[string]any{"mode": mode, "expected_mode": r4ActivityColumn(t, s.env.db, activityID, "member_directory_mode")}), who)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("設定目錄模式 %q 應成功：%d %s", mode, resp.StatusCode, body)
	}
	if got, _ := mustActivityItem(t, resp)["member_directory_mode"].(string); got != mode {
		t.Fatalf("配置寫入要回顯新模式，實際 %q", got)
	}
}

// list 讀一頁目錄（非 200 當場失敗）。
func (s *r4Scene) list(t *testing.T, who, activityID, query string) map[string]any {
	t.Helper()
	resp := s.listResp(t, who, activityID, query)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("目錄一讀應成功：%d %s", resp.StatusCode, body)
	}
	return decodeJSONBody(t, resp)
}

// listResp 讀一頁目錄並交出原始回應（要被拒的那些出口自己看狀態碼）。
func (s *r4Scene) listResp(t *testing.T, who, activityID, query string) *http.Response {
	t.Helper()
	return s.env.request(t, http.MethodGet,
		"/player/activities/"+activityID+"/members"+query, "", who)
}

// detail 單筆直查。
func (s *r4Scene) detail(t *testing.T, who, activityID, memberID string) *http.Response {
	t.Helper()
	return s.env.request(t, http.MethodGet,
		"/player/activities/"+activityID+"/members/"+memberID, "", who)
}

// profile 讀本人投影。
func (s *r4Scene) profile(t *testing.T, who, activityID string) *http.Response {
	t.Helper()
	return s.env.request(t, http.MethodGet,
		"/player/activities/"+activityID+"/profile", "", who)
}

// mustProfile 讀本人投影並斷言成功。
func (s *r4Scene) mustProfile(t *testing.T, who, activityID string) map[string]any {
	t.Helper()
	resp := s.profile(t, who, activityID)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("本人投影應成功：%d %s", resp.StatusCode, body)
	}
	return decodeJSONBody(t, resp)
}

// roster 讀管理名冊（非 200 當場失敗）。
func (s *r4Scene) roster(t *testing.T, who, activityID string) []map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodGet, "/admin/activities/"+activityID+"/members", "", who)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("名冊一讀應成功：%d %s", resp.StatusCode, body)
	}
	return memberRoster(t, resp)
}

// factionView 讀玩家側那一條現況讀法（含逐陣營的 selectable）。
func (s *r4Scene) factionView(t *testing.T, who, activityID string) *http.Response {
	t.Helper()
	return s.env.request(t, http.MethodGet,
		"/player/activities/"+activityID+"/faction", "", who)
}

// selectFaction 送一次玩家自選；依據值一律由呼叫端從讀法拿，不在這裡硬編。
func (s *r4Scene) selectFaction(t *testing.T, who, activityID, factionID, expected string) *http.Response {
	t.Helper()
	return s.env.request(t, http.MethodPut,
		"/player/activities/"+activityID+"/faction",
		selfSelectBody(factionID, expected), who)
}

// mustSelect 送一次必然成功的自選並回應答本體。
func (s *r4Scene) mustSelect(t *testing.T, who, activityID, factionID string) map[string]any {
	t.Helper()
	expected := s.factionOf(t, who, activityID)
	resp := s.selectFaction(t, who, activityID, factionID, expected)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("自選陣營 %s 應成功：%d %s", factionID, resp.StatusCode, body)
	}
	return decodeJSONBody(t, resp)
}

// factionOf 讀某人在某一場活動的歸屬現值（走他自己的本人讀法，不抄近路）。
func (s *r4Scene) factionOf(t *testing.T, who, activityID string) string {
	t.Helper()
	view := s.mustProfile(t, who, activityID)
	faction, _ := view["faction_id"].(string)
	return faction
}

// memberID 取本檔那張暱稱→標識表的值（讀不到即失敗，避免斷言寫在空字串上）。
func (s *r4Scene) id(t *testing.T, nickname string) string {
	t.Helper()
	id := s.member[nickname]
	if id == "" {
		t.Fatalf("現場沒有 %q 這一行的成員標識", nickname)
	}
	return id
}

// cookieOf 取某個暱稱的會話標頭（沒有行的對象回空字串即匿名）。
func (s *r4Scene) cookieOf(t *testing.T, nickname string) string {
	t.Helper()
	cookie := s.cookie[nickname]
	if nickname != "" && cookie == "" {
		// 管理人一與管理人二的會話存在欄位而不是表裡，其餘玩家才進表。
		if nickname == "管理人一" {
			return s.manaA
		}
		if nickname == "管理人二" {
			return s.manaB
		}
		t.Fatalf("現場沒有 %q 的會話", nickname)
	}
	return cookie
}

// override 送一次目錄覆蓋編輯。
func (s *r4Scene) override(t *testing.T, activityID, memberID, visibility, expected, who string) *http.Response {
	t.Helper()
	return s.env.request(t, http.MethodPut,
		"/admin/activities/"+activityID+"/members/"+memberID+"/directory-visibility",
		dirBody(t, map[string]any{"visibility": visibility,
			"expected_visibility": expected}), who)
}

// mustOverride 收起或放回一行成員的覆蓋，依據值取現讀的那一格。
func (s *r4Scene) mustOverride(t *testing.T, activityID, memberID, visibility string) {
	t.Helper()
	expected := "inherit"
	for _, row := range s.roster(t, s.manaA, activityID) {
		if row["member_id"] == memberID {
			expected, _ = row["directory_visibility"].(string)
		}
	}
	resp := s.override(t, activityID, memberID, visibility, expected, s.manaA)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("設定覆蓋 %q 應成功：%d %s", visibility, resp.StatusCode, body)
	}
}

// setStatus 走真實管理通路換一個帳戶的登入能力（依據值取目錄讀回的現值）。
func (s *r4Scene) setStatus(t *testing.T, accountID, status, expected string) *http.Response {
	t.Helper()
	return s.env.request(t, http.MethodPut, "/admin/accounts/"+accountID+"/status",
		dirBody(t, map[string]any{"status": status, "expected_status": expected}), s.manaA)
}

// —— 庫中現值與留痕的直查助手 ——

// r4ActivityColumn 讀 activities 表的某一欄現值。欄位名取自下方那張白名單，
// 不開放任意字串進 SQL——測試裡的「動態欄位」不該比生產代碼更隨意。
func r4ActivityColumn(t *testing.T, db *database.DB, activityID, column string) string {
	t.Helper()
	switch column {
	case "member_directory_mode", "faction_select_mode", "status", "name":
	default:
		t.Fatalf("不打算直查的欄位：%q", column)
	}
	var got string
	err := db.SQL().QueryRowContext(context.Background(),
		"SELECT "+column+" FROM activities WHERE id = ?", activityID).Scan(&got)
	if err != nil {
		t.Fatalf("讀 activities.%s 失敗：%v", column, err)
	}
	return got
}

// r4MemberFaction 讀一行成員的歸屬庫中現值（無陣營出口成空字串）。
func r4MemberFaction(t *testing.T, db *database.DB, memberID string) string {
	t.Helper()
	var got string
	err := db.SQL().QueryRowContext(context.Background(),
		`SELECT COALESCE(faction_id, '') FROM activity_members WHERE id = ?`, memberID).Scan(&got)
	if err != nil {
		t.Fatalf("讀成員 %s 的歸屬失敗：%v", memberID, err)
	}
	return got
}

// r4MemberActivityAndAccount 讀一行成員的（活動, 帳戶）——跨活動與轉正取證都問這一顆。
func r4MemberActivityAndAccount(t *testing.T, db *database.DB, memberID string) (string, string) {
	t.Helper()
	var activityID, accountID string
	err := db.SQL().QueryRowContext(context.Background(),
		`SELECT activity_id, account_id FROM activity_members WHERE id = ?`, memberID).
		Scan(&activityID, &accountID)
	if err != nil {
		t.Fatalf("讀成員 %s 的身份欄失敗：%v", memberID, err)
	}
	return activityID, accountID
}

// r4MemberCount 數某一場活動的成員行（既有的行不被任何陣營或目錄變更抹掉）。
func r4MemberCount(t *testing.T, db *database.DB, activityID string) int {
	t.Helper()
	var got int
	err := db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM activity_members WHERE activity_id = ?`, activityID).Scan(&got)
	if err != nil {
		t.Fatalf("數成員行失敗：%v", err)
	}
	return got
}

// r4FactionAvailable 讀一個陣營的可用性庫中現值。
func r4FactionAvailable(t *testing.T, db *database.DB, factionID string) bool {
	t.Helper()
	var got bool
	err := db.SQL().QueryRowContext(context.Background(),
		`SELECT available FROM activity_factions WHERE id = ?`, factionID).Scan(&got)
	if err != nil {
		t.Fatalf("讀陣營 %s 的可用性失敗：%v", factionID, err)
	}
	return got
}

// r4AccountFacts 讀一行帳戶的可觀測形態（轉正、停用、刪除、退休四件事都問這一顆）。
func r4AccountFacts(t *testing.T, db *database.DB, accountID string) (accountType, status string) {
	t.Helper()
	err := db.SQL().QueryRowContext(context.Background(),
		`SELECT account_type, status FROM accounts WHERE id = ?`, accountID).
		Scan(&accountType, &status)
	if err != nil {
		t.Fatalf("讀帳戶 %s 失敗：%v", accountID, err)
	}
	return accountType, status
}

// r4AuditRow 是一筆活動域留痕的可觀察形態。
type r4AuditRow struct {
	action    string
	actorKind string
	actorID   string
	targetID  string
	changes   string
}

// r4Audits 按動作讀回全部留痕（時刻取自注入時鐘，同值以標識破平，與列表讀法同一條規則）。
func r4Audits(t *testing.T, db *database.DB, action string) []r4AuditRow {
	t.Helper()
	rows, err := db.SQL().QueryContext(context.Background(), `SELECT actor_kind,
			COALESCE(actor_id, ''), COALESCE(target_id, ''), changes_json
		FROM activity_audit WHERE action = ?
		ORDER BY created_at ASC, id ASC`, action)
	if err != nil {
		t.Fatalf("讀留痕 %s 失敗：%v", action, err)
	}
	defer rows.Close()
	var out []r4AuditRow
	for rows.Next() {
		var row r4AuditRow
		row.action = action
		if err := rows.Scan(&row.actorKind, &row.actorID, &row.targetID, &row.changes); err != nil {
			t.Fatalf("掃描留痕 %s 失敗：%v", action, err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("讀留痕 %s 收尾失敗：%v", action, err)
	}
	return out
}

// r4AuditCount 數某一動作留下的留痕筆數。
func r4AuditCount(t *testing.T, db *database.DB, action string) int {
	t.Helper()
	return len(r4Audits(t, db, action))
}

// r4BlockAudit 佈下一枚「審計寫不進去」的注入觸發器，回傳拆除它的函式。
//
// 這是本檔量「回滾不產生成功事件」唯一的手法：真交易、真約束，不改任何生產代碼。
func r4BlockAudit(t *testing.T, db *database.DB) func() {
	t.Helper()
	const block = `CREATE TRIGGER r4_audit_block BEFORE INSERT ON activity_audit
		BEGIN SELECT RAISE(ABORT, '測試注入：審計寫入失敗'); END`
	const drop = `DROP TRIGGER r4_audit_block`
	if _, err := db.SQL().ExecContext(context.Background(), block); err != nil {
		t.Fatalf("佈下注入觸發器失敗：%v", err)
	}
	return func() {
		if _, err := db.SQL().ExecContext(context.Background(), drop); err != nil {
			t.Fatalf("拆除注入觸發器失敗：%v", err)
		}
	}
}

// —— 斷言助手 ——

// r4Visible 把一頁目錄讀成「有哪些人」，並順手反證白名單兩側。
func r4Visible(t *testing.T, payload map[string]any) []string {
	t.Helper()
	return dirNames(t, payload)
}

// r4FacetCount 讀某個陣營在這一頁裡的篩選候選計數（該陣營不在候選裡即失敗）。
func r4FacetCount(t *testing.T, payload map[string]any, factionID string) int64 {
	t.Helper()
	facet := dirFacetOf(t, payload, factionID)
	count, _ := facet["count"].(float64)
	return int64(count)
}

// r4Total 讀這一頁回顯的總數。
func r4Total(t *testing.T, payload map[string]any) int64 {
	t.Helper()
	total, _ := payload["total"].(float64)
	return int64(total)
}

// r4RowField 讀某一行的那一格（行讀不到即失敗）。
func r4RowField(t *testing.T, payload map[string]any, nickname, field string) any {
	t.Helper()
	row := dirRowOf(t, payload, nickname)
	return row[field]
}

// r4EveryExit 是一份「同一個事實的八個出口」讀到的東西，交給各測試逐個比對。
type r4EveryExit struct {
	inList        bool
	listFactionID string
	searchFound   bool
	detailStatus  int
	detailFaction string
	total         int64
	facetCounts   map[string]int64
	rosterFaction string
}

// r4ReadEveryExit 用同一位觀看者的會話，把八個出口一次讀齊（所有斷言都出自這一份快照之後的
// 逐筆請求；倉庫今日沒有快取，也沒有推送，因此「下一筆請求按新規則回答」是今日唯一可宣稱的形態）。
func (s *r4Scene) r4ReadEveryExit(t *testing.T, who, activityID, targetNickname string,
	pageQuery string) r4EveryExit {
	t.Helper()
	targetID := s.id(t, targetNickname)
	exit := r4EveryExit{facetCounts: map[string]int64{}}

	page := s.list(t, who, activityID, pageQuery)
	for _, name := range r4Visible(t, page) {
		if name == targetNickname {
			exit.inList = true
			row := dirRowOf(t, page, targetNickname)
			exit.listFactionID, _ = row["faction_id"].(string)
		}
	}
	exit.total = r4Total(t, page)
	for _, raw := range page["facets"].([]any) {
		facet, _ := raw.(map[string]any)
		id, _ := facet["faction_id"].(string)
		count, _ := facet["count"].(float64)
		exit.facetCounts[id] = int64(count)
	}

	// 停用旗標與本人歸屬這兩格各由對應那組直接斷言，本結構不代收（收了不問就是死欄位）。
	searched := s.list(t, who, activityID, "?q="+targetNickname)
	for _, name := range r4Visible(t, searched) {
		if name == targetNickname {
			exit.searchFound = true
		}
	}

	detail := s.detail(t, who, activityID, targetID)
	exit.detailStatus = detail.StatusCode
	if detail.StatusCode == http.StatusOK {
		item := mustDirectoryItem(t, detail)
		exit.detailFaction, _ = item["faction_id"].(string)
	}

	return exit
}

// r4RosterFaction 讀管理名冊裡某個成員標識的歸屬現值（沒有這一格時回空字串）。
func (s *r4Scene) r4RosterFaction(t *testing.T, who, activityID, memberID string) string {
	t.Helper()
	for _, row := range s.roster(t, who, activityID) {
		if row["member_id"] == memberID {
			faction, _ := row["faction_id"].(string)
			return faction
		}
	}
	t.Fatalf("名冊讀不到 %s 這一列", memberID)
	return ""
}

// r4PageWalk 按 page_size 把目錄逐頁走完，回全部行（不重不漏由呼叫端斷言）。
func (s *r4Scene) r4PageWalk(t *testing.T, who, activityID string, pageSize int) []string {
	t.Helper()
	var out []string
	seen := map[string]bool{}
	for page := 1; page <= 20; page++ {
		payload := s.list(t, who, activityID,
			"?page="+strconv.Itoa(page)+"&page_size="+strconv.Itoa(pageSize))
		rows, _ := payload["members"].([]any)
		if len(rows) == 0 {
			return out
		}
		for _, raw := range rows {
			item, _ := raw.(map[string]any)
			id, _ := item["member_id"].(string)
			if seen[id] {
				t.Errorf("第 %d 頁把 %s 吐了第二次（分頁重疊）", page, id)
			}
			seen[id] = true
			name, _ := item["nickname"].(string)
			out = append(out, name)
		}
	}
	t.Fatalf("走了二十頁還沒走完，目錄可能不收斂：%v", out)
	return out
}

// TestR4CrossActivitySameAccountClosedLoop 驗收同一個帳戶跨兩場活動時的那道隔離閘：
// 兩行身份各有各的歸屬與各自的讀法；陣營標識在兩場之間不能互換、也不能拿去敲對面那場的任何出口；
// 換掉一場的歸屬不碰另一場的任何事實；而「他存在於對面那場」這件事本身不是一個可探測的差異。
func TestR4CrossActivitySameAccountClosedLoop(t *testing.T) {
	s := newR4Scene(t)
	s.mustSetDirMode(t, s.activityA, "all_members")
	s.mustSetDirModeFor(t, s.activityB, "all_members", s.manaB)

	// 本人那一族的活動清單只列他有成員行的那兩場，而且每行帶著自己那場的歸屬。
	entries := decodeJSONBody(t, s.env.request(t, http.MethodGet, "/player/activities", "",
		s.cookieOf(t, "甲")))
	activities, _ := entries["activities"].([]any)
	if len(activities) != 2 {
		t.Fatalf("甲參加了兩場活動，清單就該是兩行，實際 %v", activities)
	}
	perActivity := map[string]map[string]any{}
	for _, raw := range activities {
		item, _ := raw.(map[string]any)
		id, _ := item["activity_id"].(string)
		perActivity[id] = item
	}
	for activityID, wantFaction := range map[string]string{s.activityA: s.red, s.activityB: s.purple} {
		item, ok := perActivity[activityID]
		if !ok {
			t.Fatalf("清單少了 %s 這一場：%v", activityID, activities)
		}
		if got, _ := item["faction_id"].(string); got != wantFaction {
			t.Errorf("%s 那一行要帶著自己那場的歸屬 %s，實際 %q", activityID, wantFaction, got)
		}
	}

	// 本人讀法：同一個人、兩行身份、兩個歸屬，互不遮蓋。
	viewA := s.mustProfile(t, s.cookieOf(t, "甲"), s.activityA)
	viewB := s.mustProfile(t, s.cookieOf(t, "甲"), s.activityB)
	if viewA["member_id"] != s.member["甲"] || viewA["faction_id"] != s.red ||
		viewA["faction_name"] != "紅隊" {
		t.Errorf("主場本人投影讀錯行：%v", viewA)
	}
	if viewB["member_id"] != s.member["甲在別場"] || viewB["faction_id"] != s.purple ||
		viewB["faction_name"] != "紫隊" {
		t.Errorf("外場本人投影讀錯行：%v", viewB)
	}
	if viewA["member_id"] == viewB["member_id"] {
		t.Errorf("兩場各一行不可能同一個標識：%v／%v", viewA, viewB)
	}

	// 兩場的目錄各自只列自己那場的人：外場看不到主場的乙丙丁己，主場也看不到路人的外場行。
	pageA := s.list(t, s.cookieOf(t, "甲"), s.activityA, "")
	if got := len(r4Visible(t, pageA)); got != 8 {
		t.Errorf("主場目錄該是八行，實際 %v", r4Visible(t, pageA))
	}
	for _, forbidden := range []string{"路人", "甲在別場", "管理人二在外場"} {
		for _, name := range r4Visible(t, pageA) {
			if name == forbidden {
				t.Errorf("外場的行漏進主場目錄：%s → %v", forbidden, name)
			}
		}
	}
	pageB := s.list(t, s.cookieOf(t, "甲"), s.activityB, "")
	if got := dirSorted(r4Visible(t, pageB)); !equalStrings(got,
		[]string{"甲在別場", "管理人二在外場", "路人"}) {
		t.Errorf("外場目錄該是那三行，實際 %v", got)
	}
	// 候選與計數也各自只問自己那場：主場從不列出紫隊，外場從不列出紅隊或藍隊。
	if _, ok := s.facet(t, pageA, s.purple); ok {
		t.Errorf("主場的篩選候選不該出現外場的紫隊：%v", pageA["facets"])
	}
	for _, other := range []string{s.red, s.blue} {
		if _, ok := s.facet(t, pageB, other); ok {
			t.Errorf("外場的篩選候選不該出現主場的陣營 %s：%v", other, pageB["facets"])
		}
	}

	// 拿對面那場的標識來敲這一場：一律與查無同形，不多出一句「那確實是另一場的什麼」。
	crossChecks := []struct {
		who, activity, foreign, label string
	}{
		{s.cookieOf(t, "甲"), s.activityA, s.member["甲在別場"], "外場成員標識敲主場直查"},
		{s.cookieOf(t, "甲"), s.activityB, s.member["乙"], "主場成員標識敲外場直查"},
		{s.cookieOf(t, "甲"), r4GhostActivity, s.member["甲在別場"], "幽靈活動掛真成員標識"},
	}
	for _, tc := range crossChecks {
		if resp := s.detail(t, tc.who, tc.activity, tc.foreign); resp.StatusCode !=
			http.StatusNotFound {
			t.Errorf("%s 該是 1001 那個狀態碼，實際 %d", tc.label, resp.StatusCode)
		}
	}
	// 換隊也不能跨場：外場的紫隊拿到主場去選、主場的紅隊拿到外場去選，都收斂成同一句話。
	beforeA := s.factionOf(t, s.cookieOf(t, "甲"), s.activityA)
	if code := r4ErrorCode(t, s.selectFaction(t, s.cookieOf(t, "甲"), s.activityA, s.purple,
		beforeA)); code != 1001 {
		t.Errorf("拿外場陣營在主場自選該收斂成 1001，實際 %d", code)
	}
	if got := s.factionOf(t, s.cookieOf(t, "甲"), s.activityA); got != beforeA {
		t.Errorf("被拒的跨場自選一個字都不該落：主場歸屬 %q", got)
	}
	if code := r4ErrorCode(t, s.selectFaction(t, s.cookieOf(t, "甲"), s.activityB, s.red,
		s.factionOf(t, s.cookieOf(t, "甲"), s.activityB))); code != 1001 {
		t.Errorf("拿主場陣營在外場自選該收斂成 1001，實際 %d", code)
	}
	// 只在主場有身份的人敲外場任何出口：與幽靈活動逐字同形（不多出存在性訊號）。
	strangerOnB := s.listResp(t, s.cookieOf(t, "路人"), s.activityA, "")
	ghostOnB := s.listResp(t, s.cookieOf(t, "路人"), r4GhostActivity, "")
	if strangerOnB.StatusCode != http.StatusNotFound || ghostOnB.StatusCode != http.StatusNotFound {
		t.Fatalf("非成員與幽靈都該是 404：%d／%d", strangerOnB.StatusCode, ghostOnB.StatusCode)
	}
	if a, b := dirErrorText(t, strangerOnB), dirErrorText(t, ghostOnB); a.code != b.code ||
		a.msg != b.msg {
		t.Errorf("兩種拒絕必須逐字同形：%+v／%+v", a, b)
	}

	// 在主場換一次隊：外場那一行、外場目錄與外場名冊都該像什麼都沒發生。
	beforeSelects := r4AuditCount(t, s.env.db, "member.faction_select")
	s.mustSelect(t, s.cookieOf(t, "甲"), s.activityA, s.blue)
	if got := r4MemberFaction(t, s.env.db, s.member["甲在別場"]); got != s.purple {
		t.Errorf("主場換隊動到外場歸屬：實際 %q", got)
	}
	if got := s.factionOf(t, s.cookieOf(t, "甲"), s.activityB); got != s.purple {
		t.Errorf("外場本人讀法該照舊是紫隊，實際 %q", got)
	}
	if got := s.r4RosterFaction(t, s.manaB, s.activityB, s.member["甲在別場"]); got != s.purple {
		t.Errorf("外場名冊該照舊是紫隊，實際 %q", got)
	}
	if got := r4MemberCount(t, s.env.db, s.activityB); got != 3 {
		t.Errorf("主場的換隊不該動外場的行數，實際 %d 行", got)
	}
	// 主場那一側八個出口都跟著改口（細節由下一檔逐個量），這裡只釘「換隊確實落地」。
	if got := r4MemberFaction(t, s.env.db, s.member["甲"]); got != s.blue {
		t.Errorf("主場歸屬該是藍隊，實際 %q", got)
	}
	// 一次換隊只多一笔留痕，而且掛的是他在主場那一行、以場內玩家身份記下；
	// 外場那一行不該被牽連出第二條記錄。
	afterSelects := r4Audits(t, s.env.db, "member.faction_select")
	if len(afterSelects) != beforeSelects+1 {
		t.Errorf("換隊只該追加一筆留痕：%d → %d", beforeSelects, len(afterSelects))
	}
	newest := afterSelects[len(afterSelects)-1]
	if newest.targetID != s.member["甲"] || newest.actorKind != "player" ||
		!strings.Contains(newest.changes, s.red) || !strings.Contains(newest.changes, s.blue) {
		t.Errorf("自選留痕要帶主場那一行、場內玩家身份與前後歸屬：%+v", newest)
	}
}

// facet 讀某一頁候選裡那個陣營那一項（回 ok=false 表示它不在候選裡）。
func (s *r4Scene) facet(t *testing.T, payload map[string]any, factionID string) (map[string]any, bool) {
	t.Helper()
	rows, _ := payload["facets"].([]any)
	for _, raw := range rows {
		item, _ := raw.(map[string]any)
		if item["faction_id"] == factionID {
			return item, true
		}
	}
	return nil, false
}

// r4ErrorCode 只取機器碼（狀態碼另問）。
func r4ErrorCode(t *testing.T, resp *http.Response) int {
	t.Helper()
	return dirErrorText(t, resp).code
}

// TestR4FactionSwitchLockstepAcrossEightExits 驗收「換一次隊」在八個出口上的同時改口：
// 同陣營的人不再看見他、異陣營的人開始看見他，計數、篩選候選、搜尋、單筆直查、
// 分頁、管理名冊與本人投影都出自同一份現讀；而看不見他的那一句與查無這個人同形。
func TestR4FactionSwitchLockstepAcrossEightExits(t *testing.T) {
	s := newR4Scene(t)
	s.mustSetDirMode(t, s.activityA, "same_faction_only")

	// 換隊前：乙（同隊）看得见甲，丙（異隊）看不見甲。
	before := s.r4ReadEveryExit(t, s.cookieOf(t, "乙"), s.activityA, "甲", "")
	if !before.inList || !before.searchFound || before.detailStatus != http.StatusOK ||
		before.listFactionID != s.red || before.detailFaction != s.red {
		t.Fatalf("換隊前乙該從八個出口都看見紅隊的甲：%+v", before)
	}
	if before.facetCounts[s.red] != 3 || before.total != 3 {
		t.Errorf("紅隊三人那一份計數與候選該同源：%+v", before)
	}
	beforeBing := s.r4ReadEveryExit(t, s.cookieOf(t, "丙"), s.activityA, "甲", "")
	if beforeBing.inList || beforeBing.searchFound ||
		beforeBing.detailStatus != http.StatusNotFound || beforeBing.total != 1 {
		t.Errorf("換隊前丙只該看見自己一行：%+v", beforeBing)
	}

	// 換隊：甲自己把歸屬從紅隊換成藍隊（依據值取讀回的那一格）。
	s.mustSelect(t, s.cookieOf(t, "甲"), s.activityA, s.blue)

	// 換隊後同一位觀看者（乙）：八個出口一起改口，而不是某一個出口還留在舊答案上。
	after := s.r4ReadEveryExit(t, s.cookieOf(t, "乙"), s.activityA, "甲", "")
	if after.inList || after.searchFound {
		t.Errorf("換走之後甲不該出現在乙的目錄或搜尋結果：%+v", after)
	}
	if after.detailStatus != http.StatusNotFound {
		t.Errorf("列不出來就點不進去（同一句判定）：%d", after.detailStatus)
	}
	if got := r4ErrorCode(t, s.detail(t, s.cookieOf(t, "乙"), s.activityA, s.member["甲"])); got != 1001 {
		t.Errorf("失權後直查該是不可分辨的 1001，實際 %d", got)
	}
	if after.listFactionID != "" || after.total != 2 || after.facetCounts[s.red] != 2 ||
		after.facetCounts[s.blue] != 0 {
		t.Errorf("計數與候選要跟著少一行紅隊：%+v", after)
	}

	// 換進來的這一側（丙）：同一筆請求就按新規則回答。
	afterBing := s.r4ReadEveryExit(t, s.cookieOf(t, "丙"), s.activityA, "甲", "")
	if !afterBing.inList || !afterBing.searchFound || afterBing.detailStatus != http.StatusOK ||
		afterBing.listFactionID != s.blue || afterBing.detailFaction != s.blue {
		t.Errorf("換進藍隊後丙該從八個出口都看見甲：%+v", afterBing)
	}
	if afterBing.total != 2 || afterBing.facetCounts[s.blue] != 2 {
		t.Errorf("藍隊兩人那一份計數與候選該同源：%+v", afterBing)
	}
	// 候選只從「已授權篩選」之後的行分組：丙這一份答案裡根本不該出現紅隊那一项，
	// 而不是「列出來但計數為零」——後者是一枚「那邊還有一群人」的存在性訊號。
	if _, ok := s.facet(t, s.list(t, s.cookieOf(t, "丙"), s.activityA, ""), s.red); ok {
		t.Errorf("僅同陣營態下，丙的候選不該出現紅隊：%v",
			s.list(t, s.cookieOf(t, "丙"), s.activityA, "")["facets"])
	}

	// 本人那一行自己照舊讀得到新歸屬；管理名冊讀到同一個值；庫中現值也是同一個值。
	if got := s.factionOf(t, s.cookieOf(t, "甲"), s.activityA); got != s.blue {
		t.Errorf("本人投影該讀到藍隊，實際 %q", got)
	}
	if got := s.r4RosterFaction(t, s.manaA, s.activityA, s.member["甲"]); got != s.blue {
		t.Errorf("管理名冊該讀到藍隊，實際 %q", got)
	}
	if got := r4MemberFaction(t, s.env.db, s.member["甲"]); got != s.blue {
		t.Errorf("庫中現值該是藍隊，實際 %q", got)
	}
	// 管理視角不看模式：同一時刻管理人讀到的是八行，換隊前後都一樣。
	if got := len(r4Visible(t, s.list(t, s.manaA, s.activityA, ""))); got != 8 {
		t.Errorf("管理視角該是八行，實際 %d", got)
	}

	// 分頁：丙那一側的兩行用一頁一行也走得完，且不重不漏；越界頁空而 total 照實。
	walked := s.r4PageWalk(t, s.cookieOf(t, "丙"), s.activityA, 1)
	if got := dirSorted(walked); !equalStrings(got, []string{"丙", "甲"}) {
		t.Errorf("逐頁走完該剛好那兩行，實際 %v", got)
	}
	beyond := s.list(t, s.cookieOf(t, "丙"), s.activityA, "?page=9&page_size=1")
	if rows, _ := beyond["members"].([]any); len(rows) != 0 || r4Total(t, beyond) != 2 {
		t.Errorf("越界頁該是空的一頁而 total 照實：%d／%d", len(rows), r4Total(t, beyond))
	}
}

// factionRow 讀管理面陣營清單裡那個陣營的現值一行（依據值一律取讀回的那一份）。
func (s *r4Scene) factionRow(t *testing.T, activityID, factionID string) map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodGet, "/admin/activities/"+activityID+"/factions", "", s.manaA)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("讀陣營清單應成功：%d %s", resp.StatusCode, body)
	}
	for _, item := range factionList(t, resp) {
		if item["faction_id"] == factionID {
			return item
		}
	}
	t.Fatalf("清單讀不到陣營 %s", factionID)
	return nil
}

// setFactionAvailable 以現讀行為依據值，送一次「只翻可用性」的編輯並回狀態碼。
func (s *r4Scene) setFactionAvailable(t *testing.T, activityID, factionID string,
	available bool) *http.Response {
	t.Helper()
	row := s.factionRow(t, activityID, factionID)
	return s.env.request(t, http.MethodPut,
		"/admin/activities/"+activityID+"/factions/"+factionID,
		factionEditBody(row, map[string]any{"available": available}), s.manaA)
}

// mustSetFactionAvailable 是「必須成功」的那一顆，並把回應那一格交回去。
func (s *r4Scene) mustSetFactionAvailable(t *testing.T, activityID, factionID string,
	available bool) map[string]any {
	t.Helper()
	resp := s.setFactionAvailable(t, activityID, factionID, available)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("翻轉可用性 %v 應成功：%d %s", available, resp.StatusCode, body)
	}
	return mustFactionItem(t, resp)
}

// setSelectMode 由本場管理人換那一欄自選開關（依據值取庫中現值）。
func (s *r4Scene) setSelectMode(t *testing.T, activityID, mode string) *http.Response {
	t.Helper()
	return s.env.request(t, http.MethodPut,
		"/admin/activities/"+activityID+"/faction-select",
		selfModeBody(mode, r4ActivityColumn(t, s.env.db, activityID, "faction_select_mode")),
		s.manaA)
}

// mustSetSelectMode 換開關並斷言成功。
func (s *r4Scene) mustSetSelectMode(t *testing.T, activityID, mode string) {
	t.Helper()
	resp := s.setSelectMode(t, activityID, mode)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("設定自選開關 %q 應成功：%d %s", mode, resp.StatusCode, body)
	}
}

// setStatus 走真實管理通路換一場活動的生命週期（狀態轉換那一條白名單只認 status 一欄）。
func (s *r4Scene) setActivityStatus(t *testing.T, activityID, status string) *http.Response {
	t.Helper()
	return s.env.request(t, http.MethodPut, "/admin/activities/"+activityID+"/status",
		dirBody(t, map[string]any{"status": status}), s.manaA)
}

// mustSee 斷言某個會話在某個模式下的目錄剛好是這幾行，並順手比對計數與候選的總和。
func (s *r4Scene) mustSee(t *testing.T, who string, want ...string) {
	t.Helper()
	page := s.list(t, who, s.activityA, "")
	got := dirSorted(r4Visible(t, page))
	if !equalStrings(got, want) {
		t.Fatalf("目錄該剛好是 %v，實際 %v", want, got)
	}
	if r4Total(t, page) != int64(len(want)) {
		t.Fatalf("計數要與列表同源（total %d 對 %d 行）", r4Total(t, page), len(want))
	}
	var facetSum int64
	for _, raw := range page["facets"].([]any) {
		facet, _ := raw.(map[string]any)
		count, _ := facet["count"].(float64)
		facetSum += int64(count)
	}
	if grouped := s.groupedVisible(t, page); facetSum != grouped {
		t.Fatalf("候選計數的總和要等於有歸屬的那些行：%d／%d", facetSum, grouped)
	}
}

// groupedVisible 數一頁目錄裡「有陣營歸屬」的行（無歸屬那幾行不進候選，所以總和比行數少）。
func (s *r4Scene) groupedVisible(t *testing.T, page map[string]any) int64 {
	t.Helper()
	var grouped int64
	for _, name := range r4Visible(t, page) {
		row := dirRowOf(t, page, name)
		if id, _ := row["faction_id"].(string); id != "" {
			grouped++
		}
	}
	return grouped
}

// factionIDsOf 把「每個人此刻的歸屬」讀成一份快照，供前後比對（任何變更都不該動到別人）。
func (s *r4Scene) factionIDsOf(t *testing.T, nicknames ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range nicknames {
		out[name] = r4MemberFaction(t, s.env.db, s.id(t, name))
	}
	return out
}

// assertFactionsUnmoved 把一份快照逐個比回庫中現值。
func (s *r4Scene) assertFactionsUnmoved(t *testing.T, snapshot map[string]string, label string) {
	t.Helper()
	for name, want := range snapshot {
		if got := r4MemberFaction(t, s.env.db, s.id(t, name)); got != want {
			t.Errorf("%s：%s 的歸屬被動了（%q → %q）", label, name, want, got)
		}
	}
}

// TestR4DisabledFactionTouchesNobodysMembership 驗收停用那一句的完整形態：
// 停用只讓這個陣營不再接收新成員，既有的人一個都不被搬出、一個都不從目錄裡消失，
// 列表／搜尋／單筆／計數／候選／分頁／名冊／本人投影八個出口讀到的是同一個「已停用」現值；
// 重新啟用之後，下一筆請求就能把新成員收進來，而目錄跟著改口——這中間沒有任何一欄被順手改寫。
func TestR4DisabledFactionTouchesNobodysMembership(t *testing.T) {
	s := newR4Scene(t)
	s.mustSetDirMode(t, s.activityA, "all_members")
	before := s.factionIDsOf(t, "甲", "乙", "丙", "丁", "己", "管理人一")

	// 停用紅隊：庫中只翻那一欄。
	s.mustSetFactionAvailable(t, s.activityA, s.red, false)
	if r4FactionAvailable(t, s.env.db, s.red) {
		t.Fatal("停用該落在庫中現值上")
	}
	s.assertFactionsUnmoved(t, before, "停用紅隊")

	// 八個出口：人還在、歸屬還在、名稱還在，只有可用性那一欄改口。
	page := s.list(t, s.cookieOf(t, "甲"), s.activityA, "")
	if got := len(r4Visible(t, page)); got != 8 {
		t.Errorf("停用不該讓任何人從目錄消失，實際 %d 行：%v", got, r4Visible(t, page))
	}
	if r4RowField(t, page, "甲", "faction_available") != false ||
		r4RowField(t, page, "乙", "faction_available") != false ||
		r4RowField(t, page, "己", "faction_available") != false {
		t.Errorf("紅隊那三行要讀到已停用：%v", page["members"])
	}
	if r4RowField(t, page, "丙", "faction_available") != true {
		t.Errorf("藍隊那一行不該被牽連：%v", dirRowOf(t, page, "丙"))
	}
	// 無歸屬那行的「假」與停用的「假」分得開：靠的是 faction_id 與 faction_name 那兩格。
	if row := dirRowOf(t, page, "丁"); row["faction_available"] != false ||
		row["faction_id"] != "" || row["faction_name"] != "" {
		t.Errorf("尚未分組那行該是假旗標加空展示值：%v", row)
	}
	if r4FacetCount(t, page, s.red) != 3 || r4Total(t, page) != 8 {
		t.Errorf("計數與候選不跟著停用改口：%+v", page["facets"])
	}
	if got := s.r4ReadEveryExit(t, s.cookieOf(t, "甲"), s.activityA, "乙", ""); got.detailStatus !=
		http.StatusOK || got.detailFaction != s.red || !got.searchFound {
		t.Errorf("停用的隊裡同袍照樣列得出、點得進、搜得到：%+v", got)
	}
	own := s.mustProfile(t, s.cookieOf(t, "乙"), s.activityA)
	if own["faction_id"] != s.red || own["faction_name"] != "紅隊" ||
		own["faction_available"] != false {
		t.Errorf("本人投影要讀到自己歸屬的停用現值：%v", own)
	}
	if got := s.r4RosterFaction(t, s.manaA, s.activityA, s.member["乙"]); got != s.red {
		t.Errorf("名冊該照舊列著紅隊那一份歸屬，實際 %q", got)
	}

	// 停用態下「能不能選」在玩家側讀法上是可讀的：選項還在，但 selectable 是假。
	view := decodeJSONBody(t, s.factionView(t, s.cookieOf(t, "丁"), s.activityA))
	options, _ := view["factions"].([]any)
	var redOption map[string]any
	for _, raw := range options {
		item, _ := raw.(map[string]any)
		if item["faction_id"] == s.red {
			redOption = item
		}
	}
	if redOption == nil || redOption["available"] != false ||
		redOption["selectable"] != false {
		t.Fatalf("停營的選項要如實說出不可選：%v", options)
	}
	// 丁想把停用中的紅隊選下去：2036、零落地、零留痕。
	auditsBefore := r4AuditCount(t, s.env.db, "member.faction_select")
	if code := r4ErrorCode(t, s.selectFaction(t, s.cookieOf(t, "丁"), s.activityA, s.red, "")); code !=
		2036 {
		t.Errorf("選進停用中的陣營該是 2036，實際 %d", code)
	}
	s.assertFactionsUnmoved(t, before, "被拒的那次選營")
	if got := r4AuditCount(t, s.env.db, "member.faction_select"); got != auditsBefore {
		t.Errorf("被拒的寫入不追加留痕：%d → %d", auditsBefore, got)
	}
	if got := s.detail(t, s.cookieOf(t, "丁"), s.activityA, s.member["丁"]); got.StatusCode !=
		http.StatusOK {
		t.Errorf("被拒之後本人那一行的詳情讀法該照舊：%d", got.StatusCode)
	}

	// 可見性不因停用被撤走：僅同陣營態下紅隊三人還是互相看得到。
	s.mustSetDirMode(t, s.activityA, "same_faction_only")
	s.mustSee(t, s.cookieOf(t, "甲"), "甲", "乙", "己")
	s.mustSee(t, s.cookieOf(t, "丁"), "丁")

	// 重新啟用只翻那一欄：不復原、不改寫停用期間保留下來的任何東西，
	// 而丁的同一個意圖在下一筆請求就能成立。
	s.mustSetFactionAvailable(t, s.activityA, s.red, true)
	s.assertFactionsUnmoved(t, before, "重新啟用紅隊")
	s.mustSelect(t, s.cookieOf(t, "丁"), s.activityA, s.red)
	if got := r4MemberFaction(t, s.env.db, s.member["丁"]); got != s.red {
		t.Fatalf("丁此刻該在紅隊，實際 %q", got)
	}
	s.mustSee(t, s.cookieOf(t, "甲"), "丁", "甲", "乙", "己")
	enabled := s.list(t, s.cookieOf(t, "甲"), s.activityA, "")
	if r4FacetCount(t, enabled, s.red) != 4 || r4Total(t, enabled) != 4 {
		t.Errorf("四人那份計數與候選要一起改口：%+v", enabled["facets"])
	}
	if r4RowField(t, enabled, "丁", "faction_available") != true {
		t.Errorf("重新啟用後該讀到可用：%v", dirRowOf(t, enabled, "丁"))
	}
	if got := r4AuditCount(t, s.env.db, "member.faction_select"); got != auditsBefore+1 {
		t.Errorf("一次成功的自選追加一筆留痕：%d → %d", auditsBefore, got)
	}
	// 逐頁走完仍是那四人，不重不漏。
	if got := dirSorted(s.r4PageWalk(t, s.cookieOf(t, "丁"), s.activityA, 1)); !equalStrings(got,
		[]string{"丁", "甲", "乙", "己"}) {
		t.Errorf("分頁走完該剛好那四人，實際 %v", got)
	}
}

// TestR4SelfSwitchMovesNobodyOnClose 驗收那一欄自選開關的三句：收回開關只擋「往後的切換」，
// 既不抹掉也不搬動任何人已經選定的歸屬；關掉時玩家連一次寫入都發生不了（2037），
// 僅首次模式下已有歸屬的人第二次改主意當場被拒（2039）；而这三句都不改目錄的答案——
// 目錄判定吃的是歸屬現值，不是那一欄開關。
func TestR4SelfSwitchMovesNobodyOnClose(t *testing.T) {
	s := newR4Scene(t)
	s.mustSetDirMode(t, s.activityA, "all_members")

	// 先量一次「開關是開的」這句：乙確實能把歸屬換掉。
	baseline := s.factionIDsOf(t, "甲", "乙", "丙", "丁", "己")
	auditBefore := r4AuditCount(t, s.env.db, "member.faction_select")
	s.mustSelect(t, s.cookieOf(t, "乙"), s.activityA, s.blue)
	if r4AuditCount(t, s.env.db, "member.faction_select") != auditBefore+1 {
		t.Fatal("一次成功的自選該留下一筆留痕")
	}
	afterSwitch := s.factionIDsOf(t, "甲", "乙", "丙", "丁", "己")
	if afterSwitch["乙"] != s.blue || afterSwitch["甲"] != baseline["甲"] {
		t.Fatalf("換隊要只動寫的那一行：%v", afterSwitch)
	}

	// 收回開關：既存事實一個字不動，而下一筆玩家寫入連交易都不進。
	s.mustSetSelectMode(t, s.activityA, "disabled")
	s.assertFactionsUnmoved(t, afterSwitch, "收回自選開關")
	if got := r4ActivityColumn(t, s.env.db, s.activityA, "faction_select_mode"); got != "disabled" {
		t.Fatalf("開關該落在庫中現值上，實際 %q", got)
	}
	view := decodeJSONBody(t, s.factionView(t, s.cookieOf(t, "甲"), s.activityA))
	if view["can_select_now"] != false {
		t.Errorf("關掉的這一格要如實回顯：%v", view)
	}
	if code := r4ErrorCode(t, s.selectFaction(t, s.cookieOf(t, "甲"), s.activityA, s.blue,
		s.red)); code != 2037 {
		t.Errorf("沒開放自選該是 2037，實際 %d", code)
	}
	s.assertFactionsUnmoved(t, afterSwitch, "被拒的那次自選")
	if got := r4AuditCount(t, s.env.db, "member.faction_select"); got != auditBefore+1 {
		t.Errorf("被拒的自選不追加留痕：%d", got)
	}
	// 目錄的答案不受那一欄開關影響：該列的人照樣列得出。
	page := s.list(t, s.cookieOf(t, "甲"), s.activityA, "")
	if len(r4Visible(t, page)) != 8 || r4Total(t, page) != 8 {
		t.Errorf("收回開關不動目錄：%d 行／total %d", len(r4Visible(t, page)), r4Total(t, page))
	}
	if _, ok := s.facet(t, page, s.blue); !ok {
		t.Errorf("乙已經在藍隊，候選就該有藍隊：%v", page["facets"])
	}

	// 僅首次：已有歸屬的人改主意當場被拒（2039），而「尚未分組」的人仍然選得進去。
	s.mustSetSelectMode(t, s.activityA, "first_only")
	if code := r4ErrorCode(t, s.selectFaction(t, s.cookieOf(t, "丙"), s.activityA, s.red,
		s.blue)); code != 2039 {
		t.Errorf("僅首次態下第二次切換該是 2039，實際 %d", code)
	}
	s.assertFactionsUnmoved(t, afterSwitch, "被拒的僅首次切換")

	// 放回 free：丁那一句才真的落地，而別人仍然不動。
	s.mustSetSelectMode(t, s.activityA, "free")
	dingBefore := s.factionIDsOf(t, "甲", "乙", "丙", "己")
	s.mustSelect(t, s.cookieOf(t, "丁"), s.activityA, s.red)
	s.assertFactionsUnmoved(t, dingBefore, "丁那一次切換")
	if got := r4MemberFaction(t, s.env.db, s.member["丁"]); got != s.red {
		t.Fatalf("丁該在紅隊，實際 %q", got)
	}
	moved := s.list(t, s.cookieOf(t, "丙"), s.activityA, "")
	if r4FacetCount(t, moved, s.red) != 3 || r4FacetCount(t, moved, s.blue) != 2 {
		t.Errorf("候選要跟著丁那一次改口：%v", moved["facets"])
	}
	// 再一次收回開關：丁剛選的那一份也不被抹掉（「關掉不等於清空」這句要有對照組）。
	s.mustSetSelectMode(t, s.activityA, "disabled")
	if got := r4MemberFaction(t, s.env.db, s.member["丁"]); got != s.red {
		t.Errorf("收回開關把已選的歸屬清掉了：%q", got)
	}
	if got := len(r4Visible(t, s.list(t, s.cookieOf(t, "甲"), s.activityA, ""))); got != 8 {
		t.Errorf("目錄該照舊八行，實際 %d", got)
	}
}

// TestR4OverrideVersusDirectoryModeAndManagerView 驗收「Profile 覆蓋」與「活動目錄設定」
// 是兩件事，以及本人資料入口與管理目錄的分工：
// 覆蓋收起的那一行對普通玩家從八個出口一起消失（而計數與候選跟著少），
// 對獲指派的管理人一格都不少，對本人自己也一欄都不少；
// 活動那一欄收成 hidden 時目錄對任何人都列不出人，但本人讀法與名冊照舊成立。
func TestR4OverrideVersusDirectoryModeAndManagerView(t *testing.T) {
	s := newR4Scene(t)
	s.mustSetDirMode(t, s.activityA, "all_members")
	auditsBefore := r4AuditCount(t, s.env.db, "member.directory_visibility_update")

	s.mustOverride(t, s.activityA, s.member["乙"], "hidden")

	// 普通玩家這一側：八個出口一起收起那一行。
	page := s.list(t, s.cookieOf(t, "甲"), s.activityA, "")
	names := r4Visible(t, page)
	for _, name := range names {
		if name == "乙" {
			t.Errorf("被收起的一行不該出現在玩家目錄：%v", names)
		}
	}
	if len(names) != 7 || r4Total(t, page) != 7 {
		t.Errorf("計數要跟著少一行：%d 行／total %d", len(names), r4Total(t, page))
	}
	if r4FacetCount(t, page, s.red) != 2 {
		t.Errorf("紅隊候選該跟著少一人：%v", page["facets"])
	}
	if searched := s.list(t, s.cookieOf(t, "甲"), s.activityA, "?q=乙"); len(
		r4Visible(t, searched)) != 0 || r4Total(t, searched) != 0 {
		t.Errorf("搜尋不該把收起的那一行撈回來：%v", searched["members"])
	}
	if got := s.detail(t, s.cookieOf(t, "甲"), s.activityA, s.member["乙"]); got.StatusCode !=
		http.StatusNotFound || r4ErrorCode(t, got) != 1001 {
		t.Errorf("收起之後的直查該是不可分辨的 1001：%d", got.StatusCode)
	}
	if walked := dirSorted(s.r4PageWalk(t, s.cookieOf(t, "丙"), s.activityA, 2)); len(walked) != 7 {
		t.Errorf("逐頁走完該剛好七行，實際 %v", walked)
	}

	// 管理視角不看覆蓋：同一時刻管理人讀到的仍是八行，而名冊如實說出那一行被收起來了。
	managerPage := s.list(t, s.manaA, s.activityA, "")
	if len(r4Visible(t, managerPage)) != 8 {
		t.Errorf("管理視角不該少一行：%v", r4Visible(t, managerPage))
	}
	var overridden map[string]any
	for _, row := range s.roster(t, s.manaA, s.activityA) {
		if row["member_id"] == s.member["乙"] {
			overridden = row
		}
		if row["member_id"] == s.member["甲"] && row["admin_identity"] == true {
			t.Errorf("沒有授予的普通成員不能被讀成管理員身分：%v", row)
		}
	}
	if overridden == nil || overridden["directory_visibility"] != "hidden" {
		t.Fatalf("名冊要如實帶出那一行的覆蓋現值：%v", overridden)
	}
	for _, holder := range []string{"管理人一", "管理人二", "幕後"} {
		for _, row := range s.roster(t, s.manaA, s.activityA) {
			if row["member_id"] == s.member[holder] && row["admin_identity"] != true {
				t.Errorf("%s 持有授予，名冊該如實說出", holder)
			}
		}
	}
	// 被收起來的本人：自己那一行照舊讀得到，而且讀到自己那格覆蓋。
	own := s.mustProfile(t, s.cookieOf(t, "乙"), s.activityA)
	if own["directory_visibility"] != "hidden" || own["faction_id"] != s.red ||
		own["nickname"] != "乙" {
		t.Errorf("覆蓋不該對本人收起他自己：%v", own)
	}

	// 活動那一欄改成 hidden：目錄對任何人列不出人，本人與名冊兩側照舊。
	s.mustSetDirMode(t, s.activityA, "hidden")
	hidden := s.list(t, s.cookieOf(t, "甲"), s.activityA, "")
	if len(r4Visible(t, hidden)) != 0 || r4Total(t, hidden) != 0 {
		t.Errorf("hidden 態該是空的一頁：%v", hidden["members"])
	}
	if hidden["member_directory_mode"] != "hidden" {
		t.Errorf("收起來的那一格要如實回顯：%v", hidden["member_directory_mode"])
	}
	if got := s.profile(t, s.cookieOf(t, "乙"), s.activityA); got.StatusCode != http.StatusOK {
		t.Errorf("目錄收起時本人讀法仍該成功：%d", got.StatusCode)
	}
	if got := len(r4Visible(t, s.list(t, s.manaA, s.activityA, ""))); got != 8 {
		t.Errorf("管理視角先於模式：hidden 態下獲指派者仍讀到八行，實際 %d", got)
	}
	if got := len(s.roster(t, s.manaA, s.activityA)); got != 8 {
		t.Errorf("名冊不受目錄模式約束，實際 %d 列", got)
	}

	// 放回覆蓋與模式：下一筆請求就按新規則回答（倉庫今日沒有快取，也沒有推送可宣稱）。
	s.mustOverride(t, s.activityA, s.member["乙"], "inherit")
	s.mustSetDirMode(t, s.activityA, "same_faction_only")
	s.mustSee(t, s.cookieOf(t, "甲"), "甲", "乙", "己")
	if got := r4AuditCount(t, s.env.db, "member.directory_visibility_update"); got !=
		auditsBefore+2 {
		t.Errorf("兩次覆蓋寫入各留一筆：%d → %d", auditsBefore, got)
	}
}

// r4Write 是一次「某一族寫入通路在某一種活動狀態下」的取样：動作名、送出去的請求，
// 以及批准語意裡它此刻該拿到的機器碼。表格化寫出來，是因為同一個狀態要一次問完七條通路，
// 少問一條就等於承認「這一族的門禁大概是一樣的」。
type r4Write struct {
	label  string
	action string
	code   int
	send   func(t *testing.T, s *r4Scene) *http.Response
}

// TestR4LifecycleGateIsPerFamilyInBothDirections 驗收生命週期那三道閘在陣營與目錄兩族通路上的分工：
// 停止態擋的是業務寫入（換隊、覆蓋、陣營編輯、建立名冊、改暱稱一律 2033），
// 卻不擋「為重開之後做準備」的那兩欄配置，更不擋任何一條讀法；
// 重新開放之後同一批業務寫入照樣走得通；歸檔是終態——連配置也一起收在 2029，
// 而行仍列、仍可讀，目錄與名冊不會因為歸檔就查無此人。
func TestR4LifecycleGateIsPerFamilyInBothDirections(t *testing.T) {
	s := newR4Scene(t)
	s.mustSetDirMode(t, s.activityA, "all_members")
	factions := s.factionIDsOf(t, "甲", "乙", "丙", "丁", "己")
	memberCount := r4MemberCount(t, s.env.db, s.activityA)
	auditNames := []string{"member.faction_select", "member.directory_visibility_update",
		"faction.update", "faction.create", "member.create", "member.update",
		"activity.member_directory_update", "activity.faction_select_update"}
	snapshots := map[string]int{}
	for _, action := range auditNames {
		snapshots[action] = r4AuditCount(t, s.env.db, action)
	}

	// 停止這場活動（狀態轉換那一條白名單只認 status 一欄）。
	if got := s.setActivityStatus(t, s.activityA, "closed"); got.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(got.Body)
		t.Fatalf("停止活動應成功：%d %s", got.StatusCode, body)
	}

	// 業務寫入一族：七條通路各自撞在同一句門禁上，也各自只該聽到那一句。
	newcomerID, _ := s.env.selfSelectPlayer(t, s.manaA, "r4.newcomer")
	business := []r4Write{
		{"玩家換隊", "member.faction_select", 2033, func(t *testing.T, sc *r4Scene) *http.Response {
			return sc.selectFaction(t, sc.cookieOf(t, "甲"), sc.activityA, sc.blue, sc.red)
		}},
		{"名冊覆蓋", "member.directory_visibility_update", 2033,
			func(t *testing.T, sc *r4Scene) *http.Response {
				return sc.override(t, sc.activityA, sc.member["乙"], "hidden", "inherit", sc.manaA)
			}},
		{"陣營編輯", "faction.update", 2033, func(t *testing.T, sc *r4Scene) *http.Response {
			return sc.setFactionAvailable(t, sc.activityA, sc.blue, false)
		}},
		{"陣營建立", "faction.create", 2033, func(t *testing.T, sc *r4Scene) *http.Response {
			return sc.env.request(t, http.MethodPost,
				"/admin/activities/"+sc.activityA+"/factions",
				`{"name":"將被擋下的隊","description":"","icon":"","color":""}`, sc.manaA)
		}},
		{"名冊建立", "member.create", 2033, func(t *testing.T, sc *r4Scene) *http.Response {
			return sc.env.request(t, http.MethodPost,
				"/admin/activities/"+sc.activityA+"/members",
				`{"account_id":"`+newcomerID+`","nickname":"新來的"}`, sc.manaA)
		}},
		{"暱稱編輯", "member.update", 2033, func(t *testing.T, sc *r4Scene) *http.Response {
			return sc.env.request(t, http.MethodPut,
				"/admin/activities/"+sc.activityA+"/members/"+sc.member["丁"],
				dirBody(t, map[string]any{"nickname": "改名了", "expected_nickname": "丁"}), sc.manaA)
		}},
	}
	for _, w := range business {
		resp := w.send(t, s)
		if got := r4ErrorCode(t, resp); got != w.code {
			t.Errorf("%s 在停止態該拿到 %d，實際 %d", w.label, w.code, got)
		}
	}
	// 門禁的代價是「一個字都不落」：歸屬、覆蓋、可用性、可用名冊行數全部原樣。
	s.assertFactionsUnmoved(t, factions, "停止態的七次被拒寫入")
	if got := r4MemberCount(t, s.env.db, s.activityA); got != memberCount {
		t.Errorf("被拒的名冊建立不該多一行：%d → %d", memberCount, got)
	}
	if !r4FactionAvailable(t, s.env.db, s.blue) {
		t.Error("被拒的停用不該翻那一欄：藍隊此刻仍該是可用")
	}
	for _, row := range s.roster(t, s.manaA, s.activityA) {
		if row["member_id"] == s.member["乙"] && row["directory_visibility"] != "inherit" {
			t.Errorf("被拒的覆蓋寫入不該落：%v", row)
		}
		if row["member_id"] == s.member["丁"] && row["nickname"] != "丁" {
			t.Errorf("被拒的改名不該落：%v", row)
		}
	}
	for _, action := range auditNames {
		if got := r4AuditCount(t, s.env.db, action); got != snapshots[action] {
			t.Errorf("%s 在被拒的請求上不該留下成功事件：%d → %d", action, snapshots[action], got)
		}
	}

	// 配置那一側與讀法都不受這一態約束：停止態照樣能為重開之後備好兩欄設定。
	if got := s.setDirMode(t, s.activityA, "same_faction_only", s.manaA); got != http.StatusOK {
		t.Errorf("停止態仍該能寫目錄模式那一欄，實際 %d", got)
	}
	if got := s.setSelectMode(t, s.activityA, "first_only"); got.StatusCode != http.StatusOK {
		t.Errorf("停止態仍該能寫自選開關，實際 %d", got.StatusCode)
	}
	if got := s.listResp(t, s.cookieOf(t, "甲"), s.activityA, ""); got.StatusCode != http.StatusOK {
		t.Errorf("停止態的目錄讀法不受門禁：%d", got.StatusCode)
	}
	if got := s.profile(t, s.cookieOf(t, "乙"), s.activityA); got.StatusCode != http.StatusOK {
		t.Errorf("停止態的本人讀法不受門禁：%d", got.StatusCode)
	}
	if got := s.factionView(t, s.cookieOf(t, "甲"), s.activityA); got.StatusCode != http.StatusOK {
		t.Errorf("停止態的現況讀法不受門禁：%d", got.StatusCode)
	}
	if got := s.detail(t, s.cookieOf(t, "甲"), s.activityA, s.member["乙"]); got.StatusCode !=
		http.StatusOK {
		t.Errorf("停止態的單筆直查不受門禁：%d", got.StatusCode)
	}
	// 停止態下玩家側讀到的 selectable 是假（時機那一句先擋住寫入），而目錄照舊列得出人。
	view := decodeJSONBody(t, s.factionView(t, s.cookieOf(t, "甲"), s.activityA))
	if view["can_select_now"] != false {
		t.Errorf("停止態下現況讀法要如實說出不能選：%v", view)
	}
	if got := len(r4Visible(t, s.list(t, s.cookieOf(t, "甲"), s.activityA, ""))); got != 3 {
		t.Errorf("紅隊三人那份僅同陣營答案不該因停止而消失，實際 %d", got)
	}

	// 重新開放：同一批業務寫入照樣走得通，而配置現值不被「重開」這件事抹掉。
	if got := s.setActivityStatus(t, s.activityA, "active"); got.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(got.Body)
		t.Fatalf("重新開放應成功：%d %s", got.StatusCode, body)
	}
	if got := s.dirMode(t, s.activityA); got != "same_faction_only" {
		t.Errorf("重開不該動那一欄配置，實際 %q", got)
	}
	// 停止態備好的那一欄自選開關也要如實跟隨重開：它是 first_only，先把甲的切換放回 free。
	s.mustSetSelectMode(t, s.activityA, "free")
	s.mustSelect(t, s.cookieOf(t, "甲"), s.activityA, s.blue)
	s.mustOverride(t, s.activityA, s.member["乙"], "hidden")
	s.mustSetFactionAvailable(t, s.activityA, s.blue, false)
	if got := r4MemberFaction(t, s.env.db, s.member["甲"]); got != s.blue {
		t.Errorf("重開後的換隊該落地，實際 %q", got)
	}

	// 歸檔是終態：這一次連配置也一起收起來，而讀法一格都不少。
	if got := s.setActivityStatus(t, s.activityA, "archived"); got.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(got.Body)
		t.Fatalf("歸檔應成功：%d %s", got.StatusCode, body)
	}
	archived := []r4Write{
		{"歸檔後的換隊", "member.faction_select", 2029, func(t *testing.T, sc *r4Scene) *http.Response {
			return sc.selectFaction(t, sc.cookieOf(t, "丙"), sc.activityA, sc.red, sc.blue)
		}},
		{"歸檔後的覆蓋", "member.directory_visibility_update", 2029,
			func(t *testing.T, sc *r4Scene) *http.Response {
				return sc.override(t, sc.activityA, sc.member["丙"], "hidden", "inherit", sc.manaA)
			}},
		{"歸檔後的目錄模式", "activity.member_directory_update", 2029,
			func(t *testing.T, sc *r4Scene) *http.Response {
				return sc.env.request(t, http.MethodPut,
					"/admin/activities/"+sc.activityA+"/member-directory",
					dirBody(t, map[string]any{"mode": "all_members",
						"expected_mode": r4ActivityColumn(t, sc.env.db, sc.activityA,
							"member_directory_mode")}), sc.manaA)
			}},
		{"歸檔後的自選開關", "activity.faction_select_update", 2029,
			func(t *testing.T, sc *r4Scene) *http.Response {
				return sc.env.request(t, http.MethodPut,
					"/admin/activities/"+sc.activityA+"/faction-select",
					selfModeBody("free", r4ActivityColumn(t, sc.env.db, sc.activityA,
						"faction_select_mode")), sc.manaA)
			}},
		{"歸檔後的陣營編輯", "faction.update", 2029, func(t *testing.T, sc *r4Scene) *http.Response {
			return sc.setFactionAvailable(t, sc.activityA, sc.blue, true)
		}},
	}
	for _, w := range archived {
		resp := w.send(t, s)
		if got := r4ErrorCode(t, resp); got != w.code {
			t.Errorf("%s 該拿到 %d，實際 %d", w.label, w.code, got)
		}
	}
	if got := r4MemberFaction(t, s.env.db, s.member["丙"]); got != s.blue {
		t.Errorf("歸檔後的被拒寫入不動現值，實際 %q", got)
	}
	if got := len(r4Visible(t, s.list(t, s.manaA, s.activityA, ""))); got != 8 {
		t.Errorf("歸檔的場次照舊讀得出名冊（行仍列、仍可讀），實際 %d 行", got)
	}
	if got := len(s.roster(t, s.manaA, s.activityA)); got != 8 {
		t.Errorf("歸檔不抹掉任何一行成員，實際 %d 列", got)
	}
	if got := r4ActivityColumn(t, s.env.db, s.activityA, "member_directory_mode"); got !=
		"same_faction_only" {
		t.Errorf("歸檔後的被拒配置寫入不該落，實際 %q", got)
	}
	// 留痕與實際提交一一對上：這一趟裡成功的寫入只有六筆（重開後的自選開關、換隊、覆蓋、
	// 陣營編輯，加上停止態那兩欄配置），而被拒的十一筆一條成功事件都不該留下。
	committed := map[string]int{
		"member.faction_select":              1,
		"member.directory_visibility_update": 1,
		"faction.update":                     1,
		"faction.create":                     0,
		"member.create":                      0,
		"member.update":                      0,
		"activity.member_directory_update":   1,
		"activity.faction_select_update":     2,
	}
	for action, want := range committed {
		got := r4AuditCount(t, s.env.db, action) - snapshots[action]
		if got != want {
			t.Errorf("%s 的留痕增量要等於實際提交數：期望 +%d，實際 +%d", action, want, got)
		}
	}
}

// r4Bad 是一次「本體裡多塞一格」的取样：這份本體該被擋在 400／1004，而且一個字都不落。
type r4Bad struct {
	label  string
	method string
	path   string
	body   map[string]any
}

// TestR4SpoofedIdentitiesAndRevokedScopeStayServerSide 驗收「界面藏起按鈕之外，服務層還有边界」這一句：
// 管理人側的分配通路今日根本沒有格子能填「誰進哪一隊」，把這種意圖硬塞進任何一份本體都撞在 1004；
// 玩家這一族的「是哪個玩家」由憑據決定，路徑與本體都塞不进别人；
// 未獲指派的管理人、Root、匿名在兩族路徑上各有各的收斂；
// 而 Root 撤銷指派之後，下一筆請求就把他的視角降回普通成員——不是界面換了，是服務端換了。
func TestR4SpoofedIdentitiesAndRevokedScopeStayServerSide(t *testing.T) {
	s := newR4Scene(t)
	s.mustSetDirMode(t, s.activityA, "all_members")
	factions := s.factionIDsOf(t, "甲", "乙", "丙", "丁", "己", "管理人一", "管理人二")

	// 一、把「管理人分配陣營」的形態硬塞進三份本體：這一族連格子都沒有。
	newcomerID, _ := s.env.selfSelectPlayer(t, s.manaA, "r4.pusher")
	bad := []r4Bad{
		{"建立名冊時塞陣營", http.MethodPost, "/admin/activities/" + s.activityA + "/members",
			map[string]any{"account_id": newcomerID, "nickname": "硬塞的", "faction_id": s.red}},
		{"建立名冊時塞管理員身分", http.MethodPost, "/admin/activities/" + s.activityA + "/members",
			map[string]any{"account_id": newcomerID, "nickname": "硬塞的", "admin_identity": true}},
		{"建立名冊時塞覆蓋", http.MethodPost, "/admin/activities/" + s.activityA + "/members",
			map[string]any{"account_id": newcomerID, "nickname": "硬塞的",
				"directory_visibility": "hidden"}},
		{"改暱稱時塞陣營", http.MethodPut, "/admin/activities/" + s.activityA + "/members/" + s.member["丁"],
			map[string]any{"nickname": "改名順手換隊", "expected_nickname": "丁",
				"faction_id": s.blue}},
		{"改暱稱時塞別人", http.MethodPut, "/admin/activities/" + s.activityA + "/members/" + s.member["丁"],
			map[string]any{"nickname": "順手指人", "expected_nickname": "丁",
				"account_id": s.account["乙"]}},
		{"覆蓋時塞陣營", http.MethodPut, "/admin/activities/" + s.activityA + "/members/" + s.member["丁"] +
			"/directory-visibility",
			map[string]any{"visibility": "hidden", "expected_visibility": "inherit",
				"faction_id": s.red}},
		{"覆蓋時代別人宣稱", http.MethodPut, "/admin/activities/" + s.activityA + "/members/" + s.member["丁"] +
			"/directory-visibility",
			map[string]any{"visibility": "hidden", "expected_visibility": "inherit",
				"member_id": s.member["乙"]}},
		{"目錄模式時塞活動", http.MethodPut, "/admin/activities/" + s.activityA + "/member-directory",
			map[string]any{"mode": "hidden", "expected_mode": "all_members",
				"activity_id": s.activityB}},
		{"自選時指别人", http.MethodPut, "/player/activities/" + s.activityA + "/faction",
			map[string]any{"faction_id": s.blue, "expected_faction_id": s.red,
				"member_id": s.member["乙"]}},
		{"自選時帶派生值", http.MethodPut, "/player/activities/" + s.activityA + "/faction",
			map[string]any{"faction_id": s.blue, "expected_faction_id": s.red,
				"selectable": true, "can_select_now": true}},
	}
	for _, item := range bad {
		resp := s.env.request(t, item.method, item.path, dirBody(t, item.body),
			s.pickWriter(item.path))
		got := dirErrorText(t, resp)
		if resp.StatusCode != http.StatusBadRequest || got.code != 1004 {
			t.Errorf("%s 該擋在 400／1004，實際 %d %+v", item.label, resp.StatusCode, got)
		}
	}
	// POST 那一族也要吃同一條規則（建立名冊的多塞一格）。
	if resp := s.env.request(t, http.MethodPost, "/admin/activities/"+s.activityA+"/members",
		dirBody(t, bad[0].body), s.manaA); resp.StatusCode != http.StatusBadRequest ||
		r4ErrorCode(t, resp) != 1004 {
		t.Errorf("建立名冊時塞陣營該擋下：%d", resp.StatusCode)
	}
	s.assertFactionsUnmoved(t, factions, "被拒的注入本體")
	if got := r4MemberCount(t, s.env.db, s.activityA); got != 8 {
		t.Errorf("被拒的建立不該多一行，實際 %d", got)
	}
	// 零值與畸形的陣營標識：一律收斂成「查無」那一句，而不是另一枚可枚舉的差異，
	// 也不是「把他改成尚未分組」（自選沒有清空这一步）。
	for _, malformed := range []string{r4NilUUIDLiteral, "not-an-id", ""} {
		resp := s.selectFaction(t, s.cookieOf(t, "甲"), s.activityA, malformed, s.red)
		if resp.StatusCode != http.StatusNotFound || r4ErrorCode(t, resp) != 1001 {
			t.Errorf("畸形陣營標識 %q 該收斂成 404／1001，實際 %d", malformed, resp.StatusCode)
		}
	}
	s.assertFactionsUnmoved(t, factions, "三次畸形標識的自選")

	// 二、查詢引數不是身分依據：玩家那一族的觀看者由憑據換出，多帶的格子改不了答案。
	s.mustSetDirMode(t, s.activityA, "same_faction_only")
	plain := s.list(t, s.cookieOf(t, "丙"), s.activityA, "")
	claimed := s.list(t, s.cookieOf(t, "丙"), s.activityA,
		"?admin_view=1&scope=all&account_id="+s.account["甲"])
	if !equalStrings(dirSorted(r4Visible(t, plain)), dirSorted(r4Visible(t, claimed))) {
		t.Errorf("自報管理視角不該改變可見集合：%v／%v", r4Visible(t, plain),
			r4Visible(t, claimed))
	}
	ownPlain := s.mustProfile(t, s.cookieOf(t, "甲"), s.activityA)
	if got := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activityA+"/profile?member_id="+s.member["乙"], "",
		s.cookieOf(t, "甲")); got.StatusCode != http.StatusOK {
		t.Errorf("本人讀法多帶一格不該變成另一句話：%d", got.StatusCode)
	}
	if view := s.mustProfile(t, s.cookieOf(t, "乙"), s.activityA); view["member_id"] !=
		s.member["乙"] {
		t.Errorf("觀看者永遠是自己：%v／%v", ownPlain["member_id"], view["member_id"])
	}

	// 三、把別人的標識放到路徑上：玩家族與管理族各有各的收斂，而都不是「他存在，所以給你改」。
	if got := s.override(t, s.activityA, s.member["乙"], "hidden", "inherit",
		s.cookieOf(t, "甲")); got.StatusCode != http.StatusForbidden ||
		r4ErrorCode(t, got) != 2011 {
		t.Errorf("玩家碰管理側覆蓋通路該是 403／2011：%d", got.StatusCode)
	}
	if got := s.override(t, s.activityA, s.member["甲"], "hidden", "inherit",
		s.cookieOf(t, "甲")); got.StatusCode != http.StatusForbidden {
		t.Errorf("玩家連收自己都要被拒（這一族只由管理側寫）：%d", got.StatusCode)
	}
	if got := s.detail(t, s.cookieOf(t, "丁"), s.activityA, s.member["甲"]); got.StatusCode !=
		http.StatusNotFound || r4ErrorCode(t, got) != 1001 {
		t.Errorf("僅同陣營態下異隊者的直查該收斂成 1001：%d", got.StatusCode)
	}
	// 未獲指派的管理人在主場的三類寫入：與查無同形，不承認這場活動輪得到他。
	// 三份本體都是合法形狀：這一組要問的是「輪不輪得到他管這場」，不是本體寫法
	// （本體不合法時先撞 1004，那是上一組的結論）。
	for _, path := range []string{
		"/admin/activities/" + s.activityA + "/member-directory",
		"/admin/activities/" + s.activityA + "/faction-select",
		"/admin/activities/" + s.activityA + "/members/" + s.member["丁"] + "/directory-visibility",
	} {
		body := `{"mode":"all_members","expected_mode":"same_faction_only"}`
		if strings.HasSuffix(path, "/faction-select") {
			body = `{"mode":"free","expected_mode":"free"}`
		}
		if strings.HasSuffix(path, "/directory-visibility") {
			body = `{"visibility":"hidden","expected_visibility":"inherit"}`
		}
		resp := s.env.request(t, http.MethodPut, path, body, s.manaB)
		if resp.StatusCode != http.StatusNotFound || r4ErrorCode(t, resp) != 1001 {
			t.Errorf("%s 由未獲指派者送該是 404／1001：%d", path, resp.StatusCode)
		}
	}
	// Root 在玩家這一族沒有可指向的成員行：與查無同形，而不是全量目錄。
	if got := s.listResp(t, s.root, s.activityA, ""); got.StatusCode != http.StatusNotFound ||
		r4ErrorCode(t, got) != 1001 {
		t.Errorf("Root 讀玩家目錄該收斂成 1001：%d", got.StatusCode)
	}
	// 匿名一律先撞身分那一句。
	if got := r4ErrorCode(t, s.listResp(t, "", s.activityA, "")); got != 2002 {
		t.Errorf("匿名讀目錄該是 2002，實際 %d", got)
	}

	// 四、撤銷指派之後的下一筆請求：視角降回普通成員，管理通路一起關門，而他的成員行與歸屬一格不動。
	s.assertFactionsUnmoved(t, factions, "撤銷指派之前")
	if got := s.env.request(t, http.MethodDelete,
		"/root/activities/"+s.activityA+"/managers/"+s.account["管理人一"], `{}`, s.root); got.
		StatusCode != http.StatusOK {
		body, _ := io.ReadAll(got.Body)
		t.Fatalf("Root 撤銷指派應成功：%d %s", got.StatusCode, body)
	}
	if got := len(r4Visible(t, s.list(t, s.manaA, s.activityA, ""))); got != 1 {
		t.Errorf("撤銷指派後該只看得見自己一行，實際 %d 行", got)
	}
	if got := s.env.request(t, http.MethodPut,
		"/admin/activities/"+s.activityA+"/member-directory",
		dirBody(t, map[string]any{"mode": "all_members", "expected_mode": "same_faction_only"}),
		s.manaA); got.StatusCode != http.StatusNotFound {
		t.Errorf("撤銷指派後改配置該是 404：%d", got.StatusCode)
	}
	if got := s.env.request(t, http.MethodGet, "/admin/activities/"+s.activityA+"/members", "",
		s.manaA); got.StatusCode != http.StatusNotFound {
		t.Errorf("撤銷指派後讀名冊該是 404：%d", got.StatusCode)
	}
	// 重新指派：同一筆請求的下一筆就按新規則回答（今日沒有快取，也沒有推送可宣稱）。
	if got := s.env.request(t, http.MethodPost, "/root/activities/"+s.activityA+"/managers",
		dirBody(t, map[string]any{"account_id": s.account["管理人一"]}), s.root); got.
		StatusCode != http.StatusOK {
		body, _ := io.ReadAll(got.Body)
		t.Fatalf("Root 重新指派應成功：%d %s", got.StatusCode, body)
	}
	if got := len(r4Visible(t, s.list(t, s.manaA, s.activityA, ""))); got != 8 {
		t.Errorf("重新指派後該讀回全量八行，實際 %d 行", got)
	}
	s.assertFactionsUnmoved(t, factions, "指派進出前後")

	// 五、遲到的舊請求：三份過期依據值各自 2013，贏家不被覆蓋，也不追加留痕。
	stale := []struct {
		label, action string
		send          func(t *testing.T, sc *r4Scene) *http.Response
	}{
		{"目錄模式帶著舊現值", "activity.member_directory_update",
			func(t *testing.T, sc *r4Scene) *http.Response {
				return sc.env.request(t, http.MethodPut,
					"/admin/activities/"+sc.activityA+"/member-directory",
					dirBody(t, map[string]any{"mode": "all_members",
						"expected_mode": "hidden"}), sc.manaA)
			}},
		{"覆蓋帶著舊現值", "member.directory_visibility_update",
			func(t *testing.T, sc *r4Scene) *http.Response {
				return sc.override(t, sc.activityA, sc.member["乙"], "hidden", "hidden", sc.manaA)
			}},
		{"自選帶著舊歸屬", "member.faction_select",
			func(t *testing.T, sc *r4Scene) *http.Response {
				// 丙此刻在藍隊，依據值填一份他從來沒有的標識：CAS 落敗，
				// 而伺服器不因這個標識查無任何東西就換一句話（不落 1001 也不落 2036）。
				return sc.selectFaction(t, sc.cookieOf(t, "丙"), sc.activityA, sc.red, sc.purple)
			}},
	}
	for _, tc := range stale {
		before := r4AuditCount(t, s.env.db, tc.action)
		resp := tc.send(t, s)
		if resp.StatusCode != http.StatusConflict || r4ErrorCode(t, resp) != 2013 {
			t.Errorf("%s 該是 409／2013，實際 %d", tc.label, resp.StatusCode)
		}
		if got := r4AuditCount(t, s.env.db, tc.action); got != before {
			t.Errorf("%s 落敗時不追加留痕：%d → %d", tc.label, before, got)
		}
	}
	s.assertFactionsUnmoved(t, factions, "三份遲到的舊請求")

	// 六、跨站來源：三族寫入共用同一道閘，被拒之後庫中現值一格不動。
	for _, tc := range []struct{ label, path, body, action string }{
		{"目錄模式", "/admin/activities/" + s.activityA + "/member-directory",
			`{"mode":"hidden","expected_mode":"same_faction_only"}`,
			"activity.member_directory_update"},
		{"覆蓋", "/admin/activities/" + s.activityA + "/members/" + s.member["丁"] +
			"/directory-visibility", `{"visibility":"hidden","expected_visibility":"inherit"}`,
			"member.directory_visibility_update"},
		{"自選", "/player/activities/" + s.activityA + "/faction",
			`{"faction_id":"` + s.red + `","expected_faction_id":""}`, "member.faction_select"},
	} {
		before := r4AuditCount(t, s.env.db, tc.action)
		resp := s.env.dirRequestWithOrigin(t, http.MethodPut, tc.path, tc.body, s.manaA,
			"https://example.invalid")
		if r4ErrorCode(t, resp) != 2005 {
			t.Errorf("%s 的跨站來源該是 2005：%+v", tc.label, dirErrorText(t, resp))
		}
		if got := r4AuditCount(t, s.env.db, tc.action); got != before {
			t.Errorf("%s 被來源閘擋下時不追加留痕：%d → %d", tc.label, before, got)
		}
	}
	s.assertFactionsUnmoved(t, factions, "被來源閘擋下的三次寫入")

	// 七、方法面：這一族沒有移出、沒有清空、沒有部分更新，Allow 也不虛報。
	for _, path := range []string{
		"/player/activities/" + s.activityA + "/members/" + s.member["乙"],
		"/player/activities/" + s.activityA + "/faction",
		"/admin/activities/" + s.activityA + "/members/" + s.member["乙"],
		"/admin/activities/" + s.activityA + "/members/" + s.member["乙"] + "/directory-visibility",
	} {
		resp := s.env.request(t, http.MethodDelete, path, "", s.manaA)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s 不受理 DELETE：%d", path, resp.StatusCode)
		}
		if allow := resp.Header.Get("Allow"); strings.Contains(allow, "DELETE") ||
			strings.Contains(allow, "PATCH") {
			t.Errorf("%s 的 Allow 不該宣稱沒有交付的方法：實際 %q", path, allow)
		}
	}
	if got := r4MemberCount(t, s.env.db, s.activityA); got != 8 {
		t.Errorf("被拒的 DELETE 一列都不該少：實際 %d 行", got)
	}
}

// pickWriter 按路徑的那一族挑一個「有資格把本體送到用例面前」的主體：
// 管理側用本場管理人，玩家側用甲的會話——這一格不是判定對象，
// 而是要讓 1004 那一句真的由本體形態決定，而不是先撞在準入上。
func (s *r4Scene) pickWriter(path string) string {
	if strings.HasPrefix(path, "/player/") {
		return s.cookieOfNoFail("甲")
	}
	return s.manaA
}

// cookieOfNoFail 是 pickWriter 內部用的取會話版本（失敗即終止，不返回空字串瞞過斷言）。
func (s *r4Scene) cookieOfNoFail(nickname string) string {
	if cookie := s.cookie[nickname]; cookie != "" {
		return cookie
	}
	if nickname == "管理人一" {
		return s.manaA
	}
	return s.manaB
}

// r4Send 是給併發那幾組用的裸請求助手：它不在測試執行緒上，所以一律用 Errorf 而不是 Fatalf
// （從別的 goroutine 呼叫 t.Fatalf 是載具不允許的形態）。
func r4Send(t *testing.T, s *r4Scene, method, path, body, cookie string) (int, int) {
	t.Helper()
	req, err := http.NewRequest(method, s.env.ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Errorf("建立 %s %s 請求失敗：%v", method, path, err)
		return 0, 0
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := s.env.ts.Client().Do(req)
	if err != nil {
		t.Errorf("%s %s 失敗：%v", method, path, err)
		return 0, 0
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Errorf("%s %s 的回應不是 JSON：%s", method, path, raw)
		return resp.StatusCode, 0
	}
	code, _ := payload["code"].(float64)
	return resp.StatusCode, int(code)
}

// r4OtherFaction 交出「此刻他所屬之外的那一個主場陣營」（併發那兩組只問換隊這件事，不問方向）。
func (s *r4Scene) r4OtherFaction(t *testing.T, who, activityID string) string {
	t.Helper()
	current := s.factionOf(t, who, activityID)
	if current == s.red {
		return s.blue
	}
	return s.red
}

// TestR4ConcurrentWritesCommitExactlyOnce 驗收三組真實併發的結論都只有「一次提交、一條留痕」：
// 同一個人同時從兩個方向自選、自選與停用同一個陣營撞在一起、兩個管理人同一份依據值改同一欄配置。
// SQLite 的單寫者串行加上「交易內現讀＋帶 WHERE 的單向更新」使這裡只能出現兩種形態：
// 贏家落地並留下一筆，落敗者拿到 2013（或規則那一句）而一個字都不落；
// 而出現的那條留痕必須與庫中現值對得上——留痕不能比提交多，也不能比提交少。
func TestR4ConcurrentWritesCommitExactlyOnce(t *testing.T) {
	s := newR4Scene(t)
	s.mustSetDirMode(t, s.activityA, "all_members")

	// 一、同一個人兩筆同時自選：丁還沒有歸屬，兩個方向都用「尚未分組」當依據值。
	concurrentBase := r4AuditCount(t, s.env.db, "member.faction_select")
	selects := sync.WaitGroup{}
	type outcome struct {
		status int
		code   int
		target string
	}
	results := make([]outcome, 2)
	for i, target := range []string{s.red, s.blue} {
		selects.Add(1)
		go func(i int, target string) {
			defer selects.Done()
			status, code := r4Send(t, s, http.MethodPut,
				"/player/activities/"+s.activityA+"/faction",
				selfSelectBody(target, ""), s.cookieOf(t, "丁"))
			results[i] = outcome{status: status, code: code, target: target}
		}(i, target)
	}
	selects.Wait()
	successes := 0
	for _, got := range results {
		switch {
		case got.status == http.StatusOK:
			successes++
		case got.status == http.StatusConflict && got.code == 2013:
		default:
			t.Errorf("併發自選只能是一次成功加一次 2013，實際 %d／%d", got.status, got.code)
		}
	}
	if successes != 1 {
		t.Fatalf("兩筆自選該恰好落地一筆，實際 %d 筆", successes)
	}
	live := r4MemberFaction(t, s.env.db, s.member["丁"])
	if live != results[0].target && live != results[1].target {
		t.Errorf("庫中現值該是贏家那一個方向，實際 %q", live)
	}
	// 留痕只能比提交多一条都不行：最後一筆要剛好是贏家那一次，前後值裡帶著庫中現值。
	audits := r4Audits(t, s.env.db, "member.faction_select")
	if len(audits) != concurrentBase+1 {
		t.Fatalf("兩筆併發自選只該留下一筆留痕：%d → %d", concurrentBase, len(audits))
	}
	newest := audits[len(audits)-1]
	if newest.targetID != s.member["丁"] || !strings.Contains(newest.changes, live) {
		t.Errorf("最後一筆自選留痕要對得上提交：%+v／現值 %q", newest, live)
	}

	// 二、自選與停用同一個陣營同時送：兩種合法終態之外都不許出现。
	before := r4AuditCount(t, s.env.db, "member.faction_select")
	factionBefore := r4MemberFaction(t, s.env.db, s.member["甲"])
	pair := sync.WaitGroup{}
	var selectStatus, selectCode, disableStatus, disableCode int
	pair.Add(2)
	go func() {
		defer pair.Done()
		selectStatus, selectCode = r4Send(t, s, http.MethodPut,
			"/player/activities/"+s.activityA+"/faction",
			selfSelectBody(otherOf(t, s, factionBefore), factionBefore), s.cookieOf(t, "甲"))
	}()
	go func() {
		defer pair.Done()
		disableStatus, disableCode = r4Send(t, s, http.MethodPut,
			"/admin/activities/"+s.activityA+"/factions/"+factionBefore,
			factionEditBody(s.factionRow(t, s.activityA, factionBefore),
				map[string]any{"available": false}), s.manaA)
	}()
	pair.Wait()
	afterFaction := r4MemberFaction(t, s.env.db, s.member["甲"])
	afterAvailable := r4FactionAvailable(t, s.env.db, factionBefore)
	// 停用動的是 available 一欄、自選動的是 faction_id 一欄：兩筆各自都該成功落地，
	// 誰先在事務裡讀到快照只決定「這一次自選選不選得進已停用的隊」。
	if disableStatus != http.StatusOK {
		t.Errorf("併發中的停用該照常成功（它不與自選搶同一欄）：%d／%d", disableStatus, disableCode)
	}
	if afterAvailable {
		t.Errorf("停用落地了卻還讀到可用：%v", afterAvailable)
	}
	switch {
	case afterFaction == factionBefore:
		// 停用先落地：那次自選必被同一句門禁擋下（2036），歸屬一格不動。
		if selectStatus != http.StatusConflict || selectCode != 2036 {
			t.Errorf("選進已停用的陣營該是 409／2036，實際 %d／%d", selectStatus, selectCode)
		}
		if got := r4AuditCount(t, s.env.db, "member.faction_select"); got != before {
			t.Errorf("被擋下的自選不追加留痕：%d → %d", before, got)
		}
	default:
		// 自選先落地：歸屬進了那一個隊，而隨後那筆停用照樣成功（停用不逐出現有成員）。
		if selectStatus != http.StatusOK {
			t.Errorf("自選排在停用前該成功，實際 %d／%d", selectStatus, selectCode)
		}
		if afterFaction == factionBefore {
			t.Errorf("自選成功了卻沒有現值：%q", afterFaction)
		}
	}
	// 兩個方向的留痕都各自等於實際提交的次數（回滾與被拒的不在此列）。
	if got := r4AuditCount(t, s.env.db, "member.faction_select"); got !=
		before+boolToInt(afterFaction != factionBefore) {
		t.Errorf("自選留痕增量要等於提交次數：%d → %d（現值 %q）", before, got, afterFaction)
	}

	// 三、兩份同一依據值的配置寫入同時送：只有一個落地。
	modeBefore := r4ActivityColumn(t, s.env.db, s.activityA, "member_directory_mode")
	configBase := r4AuditCount(t, s.env.db, "activity.member_directory_update")
	config := sync.WaitGroup{}
	modeResults := make([]int, 2)
	for i, want := range []string{"hidden", "same_faction_only"} {
		config.Add(1)
		go func(i int, want string) {
			defer config.Done()
			status, _ := r4Send(t, s, http.MethodPut,
				"/admin/activities/"+s.activityA+"/member-directory",
				dirBody(t, map[string]any{"mode": want, "expected_mode": modeBefore}), s.manaA)
			modeResults[i] = status
		}(i, want)
	}
	config.Wait()
	won := 0
	for _, status := range modeResults {
		if status == http.StatusOK {
			won++
		}
	}
	if won != 1 {
		t.Errorf("同一份依據值的兩次配置該恰好落地一次，實際 %d 次：%v", won, modeResults)
	}
	if got := r4ActivityColumn(t, s.env.db, s.activityA, "member_directory_mode"); got == modeBefore {
		t.Errorf("配置寫入該把那一欄換掉，仍讀到 %q", got)
	}
	// 兩筆配置寫入只該留下一筆留痕，而且那一筆的前後值就是贏家換成現值的那一個方向。
	afterConfig := r4Audits(t, s.env.db, "activity.member_directory_update")
	if len(afterConfig) != configBase+1 {
		t.Fatalf("兩筆同依據值的配置該剛好留一筆：%d → %d", configBase, len(afterConfig))
	}
	winnerMode := r4ActivityColumn(t, s.env.db, s.activityA, "member_directory_mode")
	if latest := afterConfig[len(afterConfig)-1]; latest.actorKind != "admin" ||
		!strings.Contains(latest.changes, winnerMode) {
		t.Errorf("配置留痕要帶管理員身分與贏家現值：%+v／現值 %q", latest, winnerMode)
	}
	// 下一筆請求按新規則回答：把模式收成為 hidden 之後任何人都列不出人。
	s.mustSetDirMode(t, s.activityA, "hidden")
	if got := len(r4Visible(t, s.list(t, s.cookieOf(t, "丙"), s.activityA, ""))); got != 0 {
		t.Errorf("收成為 hidden 後下一筆請求該列不出人，實際 %d 行", got)
	}
}

// otherOf 交出「不是這一個的另一個主場陣營」。
func otherOf(t *testing.T, s *r4Scene, current string) string {
	t.Helper()
	if current == s.red {
		return s.blue
	}
	return s.red
}

// boolToInt 把「有沒有發生這一次提交」換成留痕增量。
func boolToInt(occurred bool) int {
	if occurred {
		return 1
	}
	return 0
}

// TestR4AuditFailureRollsBackBothFamilies 驗收「寫入失敗不產生成功事件」在兩族通路上的形態：
// 審計寫不進去時，換隊、覆蓋、目錄模式與陣營停用都整體回滾——現值一格不動、
// 一行不多、一條成功留痕也沒有；拆掉注入之後同一條通路照樣走得通，
// 而那筆留痕的前後值與庫中現值逐字對得上。
func TestR4AuditFailureRollsBackBothFamilies(t *testing.T) {
	s := newR4Scene(t)
	s.mustSetDirMode(t, s.activityA, "all_members")

	factions := s.factionIDsOf(t, "甲", "乙", "丙", "己")
	modeBefore := r4ActivityColumn(t, s.env.db, s.activityA, "member_directory_mode")
	visibilities := map[string]string{}
	for _, name := range []string{"乙", "丙"} {
		visibilities[name] = "inherit"
	}
	actions := []string{"member.faction_select", "member.directory_visibility_update",
		"activity.member_directory_update", "faction.update"}
	baselines := map[string]int{}
	for _, action := range actions {
		baselines[action] = r4AuditCount(t, s.env.db, action)
	}

	drop := r4BlockAudit(t, s.env.db)
	// 四族寫入同時被同一個注入擋住：每一筆都該是服務端錯誤，而不是一句「成功但沒留下痕」。
	if resp := s.selectFaction(t, s.cookieOf(t, "乙"), s.activityA,
		s.r4OtherFaction(t, s.cookieOf(t, "乙"), s.activityA),
		factions["乙"]); resp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("審計寫不進時自選該整筆失敗並帶著原因：%d %s", resp.StatusCode, body)
	}
	if resp := s.override(t, s.activityA, s.member["丙"], "hidden", visibilities["丙"], s.manaA); resp.
		StatusCode != http.StatusInternalServerError {
		t.Errorf("審計寫不進時覆蓋該整筆失敗：%d", resp.StatusCode)
	}
	if resp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+s.activityA+"/member-directory",
		dirBody(t, map[string]any{"mode": "hidden", "expected_mode": modeBefore}), s.manaA); resp.
		StatusCode != http.StatusInternalServerError {
		t.Errorf("審計寫不進時配置該整筆失敗：%d", resp.StatusCode)
	}
	if resp := s.setFactionAvailable(t, s.activityA, s.red, false); resp.StatusCode !=
		http.StatusInternalServerError {
		t.Errorf("審計寫不進時停用該整筆失敗：%d", resp.StatusCode)
	}
	// 回滾的邊界：一欄都不動、一行都不動、一條成功留痕都不多。
	s.assertFactionsUnmoved(t, factions, "整筆回滾的自選")
	if got := r4ActivityColumn(t, s.env.db, s.activityA, "member_directory_mode"); got != modeBefore {
		t.Errorf("回滾的配置寫入不動現值：%q → %q", modeBefore, got)
	}
	if !r4FactionAvailable(t, s.env.db, s.red) {
		t.Error("回滾的停用不該翻那一欄")
	}
	for _, row := range s.roster(t, s.manaA, s.activityA) {
		if row["directory_visibility"] != "inherit" {
			t.Errorf("回滾的覆蓋寫入不動任何一行的覆蓋：%v", row)
		}
	}
	if got := r4MemberCount(t, s.env.db, s.activityA); got != 8 {
		t.Errorf("回滾不該動行數，實際 %d", got)
	}
	for _, action := range actions {
		if got := r4AuditCount(t, s.env.db, action); got != baselines[action] {
			t.Errorf("%s 在整筆回滾後不該有成功事件：%d → %d", action, baselines[action], got)
		}
	}
	drop()

	// 拆掉注入之後同一條通路照樣走得通，而留痕與現值逐字對得上。
	s.mustSelect(t, s.cookieOf(t, "乙"), s.activityA, s.r4OtherFaction(t, s.cookieOf(t, "乙"),
		s.activityA))
	s.mustOverride(t, s.activityA, s.member["丙"], "hidden")
	s.mustSetDirMode(t, s.activityA, "same_faction_only")
	s.mustSetFactionAvailable(t, s.activityA, s.red, false)
	for _, action := range actions {
		got := r4AuditCount(t, s.env.db, action)
		if got != baselines[action]+1 {
			t.Errorf("%s 重來一次該剛好留一筆：%d → %d", action, baselines[action], got)
		}
	}
	// 自選那筆留痕的前後值要與庫中現值同一個答案（前後不是兩次不同時刻的猜測）。
	audits := r4Audits(t, s.env.db, "member.faction_select")
	newest := audits[len(audits)-1]
	live := r4MemberFaction(t, s.env.db, s.member["乙"])
	if newest.targetID != s.member["乙"] || newest.actorKind != "player" ||
		!strings.Contains(newest.changes, factions["乙"]) || !strings.Contains(newest.changes, live) {
		t.Errorf("自選留痕要帶著前後歸屬並與現值對得上：%+v／現值 %q", newest, live)
	}
	// 停用那一欄同理：留痕寫的是 available 的前後值，而不是任何別人的東西。
	factionAudit := r4Audits(t, s.env.db, "faction.update")[len(
		r4Audits(t, s.env.db, "faction.update"))-1]
	if factionAudit.actorKind != "admin" || !strings.Contains(factionAudit.changes, "available") {
		t.Errorf("陣營停用的留痕要帶管理員身分與那一欄前後值：%+v", factionAudit)
	}
	// 收尾再問一次「回滾的那四次沒混進任何動作的留痕裡」：
	// 四個動作各自的總筆數此刻恰好等於本檔成功的那四次（基線＋一）。
	for _, action := range actions {
		if got := r4AuditCount(t, s.env.db, action); got != baselines[action]+1 {
			t.Errorf("%s 的留痕總筆數要與成功次數對上：%d → %d", action, baselines[action], got)
		}
	}
}

// TestR4AccountSideChangesKeepFactionReferences 驗收帳戶那一側的三種處置對新增的陣營引用是否安全：
// 訪戶原地轉正（穩定標識存续）、停用（可恢復）與軟刪除（終態）都不搬、不改寫、也不抹掉
// 任何一行活動內身份——成員行仍舊指向同一個帳戶標識，歸屬仍是當時那一個隊，
// 目錄與名冊照舊列得出那一行；而帳戶側的事實（類型、狀態）一律不從玩家目錄那一族洩漏出去。
func TestR4AccountSideChangesKeepFactionReferences(t *testing.T) {
	s := newR4Scene(t)
	s.mustSetDirMode(t, s.activityA, "all_members")
	factions := s.factionIDsOf(t, "甲", "乙", "丙", "丁", "己")

	// 一、訪戶原地轉正：他那一行成員身份與歸屬原樣，舊憑據立刻不算，新憑據讀到同一份事實。
	guestID := s.account["己"]
	guestCookie := s.cookieOf(t, "己")
	if accountType, _ := r4AccountFacts(t, s.env.db, guestID); accountType != "guest" {
		t.Fatalf("現場的己必須仍是訪戶，實際 %q", accountType)
	}
	upgraded := s.env.request(t, http.MethodPut, "/admin/accounts/"+guestID+"/upgrade",
		dirBody(t, map[string]any{"login_name": "r4.guest.upgraded",
			"password": activityTestStandardSeed}), s.manaA)
	if upgraded.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(upgraded.Body)
		t.Fatalf("訪戶轉正應成功：%d %s", upgraded.StatusCode, body)
	}
	if accountType, _ := r4AccountFacts(t, s.env.db, guestID); accountType != "standard" {
		t.Errorf("轉正要動的是同一行的類型，實際 %q", accountType)
	}
	if got := r4MemberFaction(t, s.env.db, s.member["己"]); got != s.red {
		t.Errorf("轉正不改寫陣營歸屬，實際 %q", got)
	}
	if _, account := r4MemberActivityAndAccount(t, s.env.db, s.member["己"]); account != guestID {
		t.Errorf("轉正後那一行仍該指向同一個穩定標識")
	}
	if got := r4MemberCount(t, s.env.db, s.activityA); got != 8 {
		t.Errorf("轉正不該多出不重複的身份行，實際 %d 行", got)
	}
	// 舊的訪戶憑據在轉正那一刻被撤銷：他不能再以任何一條通路讀自己。
	if got := s.profile(t, guestCookie, s.activityA); got.StatusCode == http.StatusOK {
		t.Error("轉正後的舊訪戶會話不該還能讀本人投影")
	}
	if got := s.listResp(t, guestCookie, s.activityA, ""); got.StatusCode == http.StatusOK {
		t.Error("轉正後的舊訪戶會話不該還能讀目錄")
	}
	first := loginCookie(t, s.env.request(t, http.MethodPost, "/auth/login",
		dirBody(t, map[string]any{"login_name": "r4.guest.upgraded",
			"password": activityTestStandardSeed}), ""))
	if got := r4ErrorCode(t, s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activityA+"/profile", "", cookieHeader(first))); got != 2010 {
		t.Errorf("轉正出來的是「首次必須改密」那個形態，實際 %d", got)
	}
	if resp := s.env.request(t, http.MethodPost, "/auth/password/change",
		dirBody(t, map[string]any{"current_password": activityTestStandardSeed,
			"new_password": activityTestStandardNewPwd}), cookieHeader(first)); resp.
		StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("轉正後的本人改密應成功：%s", body)
	}
	fresh := cookieHeader(loginCookie(t, s.env.request(t, http.MethodPost, "/auth/login",
		dirBody(t, map[string]any{"login_name": "r4.guest.upgraded",
			"password": activityTestStandardNewPwd}), "")))
	own := s.mustProfile(t, fresh, s.activityA)
	if own["member_id"] != s.member["己"] || own["nickname"] != "己" ||
		own["faction_id"] != s.red || own["faction_name"] != "紅隊" {
		t.Errorf("轉正前後讀到的活動內事實必須一字不差：%v", own)
	}
	// 轉正也順手反證「本體沒有格子能把訪客升成管理員」。
	if resp := s.env.request(t, http.MethodPut, "/admin/accounts/"+s.account["丁"]+"/upgrade",
		dirBody(t, map[string]any{"login_name": "r4.smuggle", "password": activityTestStandardSeed,
			"account_type": "standard", "roles": []string{"server_admin"}}), s.manaA); resp.
		StatusCode != http.StatusBadRequest || r4ErrorCode(t, resp) != 1004 {
		t.Errorf("升級本體多塞角色該是 400／1004：%d", resp.StatusCode)
	}

	// 二、停用：他会話被撤銷，別人那一側的目錄一格不少，名冊如實說出帳戶狀態而玩家目錄不說。
	disabled := s.setStatus(t, s.account["丙"], "disabled", "active")
	if disabled.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(disabled.Body)
		t.Fatalf("停用應成功：%d %s", disabled.StatusCode, body)
	}
	if _, status := r4AccountFacts(t, s.env.db, s.account["丙"]); status != "disabled" {
		t.Errorf("停用該落在帳戶那一行，實際 %q", status)
	}
	if got := r4MemberFaction(t, s.env.db, s.member["丙"]); got != s.blue {
		t.Errorf("停用不改寫歸屬，實際 %q", got)
	}
	page := s.list(t, s.cookieOf(t, "甲"), s.activityA, "")
	if row := dirRowOf(t, page, "丙"); row["faction_id"] != s.blue ||
		row["faction_available"] != true {
		t.Errorf("停用中的成員在別人目錄裡該照舊列著：%v", row)
	}
	dingRow := dirRowOf(t, page, "丙")
	for _, forbidden := range []string{"account_status", "account_id", "display_name",
		"login_name", "admin_identity", "directory_visibility"} {
		if _, leaked := dingRow[forbidden]; leaked {
			t.Errorf("玩家目錄不該洩漏帳戶側或管理側欄位 %q：%v", forbidden, dingRow)
		}
	}
	var rosterRow map[string]any
	for _, row := range s.roster(t, s.manaA, s.activityA) {
		if row["member_id"] == s.member["丙"] {
			rosterRow = row
		}
	}
	if rosterRow == nil || rosterRow["account_status"] != "disabled" {
		t.Errorf("管理名冊要如實帶出帳戶狀態（只增不刪的那一格）：%v", rosterRow)
	}
	if got := s.profile(t, s.cookieOf(t, "丙"), s.activityA); got.StatusCode == http.StatusOK {
		t.Error("停用後他的會話該被撤銷，讀不到本人投影")
	}
	// 停用中的人仍舊可以被加進別一場活動的名冊（「停用不是刪除」這句在成員通路上的形態）。
	stillOpen := s.env.request(t, http.MethodPost,
		"/admin/activities/"+s.activityB+"/members",
		dirBody(t, map[string]any{"account_id": s.account["丙"], "nickname": "停用中的別場行"}),
		s.manaB)
	if stillOpen.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(stillOpen.Body)
		t.Errorf("停用中的帳戶仍可加入另一場活動：%d %s", stillOpen.StatusCode, body)
	}
	// 恢復之後他重新讀得到自己那一行（同一行、同一個歸屬）。
	if got := s.setStatus(t, s.account["丙"], "active", "disabled"); got.StatusCode !=
		http.StatusOK {
		body, _ := io.ReadAll(got.Body)
		t.Fatalf("恢復應成功：%s", body)
	}
	restored := cookieHeader(loginCookie(t, s.env.request(t, http.MethodPost, "/auth/login",
		dirBody(t, map[string]any{"login_name": "r4.bing",
			"password": activityTestStandardNewPwd}), "")))
	if own := s.mustProfile(t, restored, s.activityA); own["member_id"] != s.member["丙"] ||
		own["faction_id"] != s.blue {
		t.Errorf("恢復前後讀到的該是同一家族的同一行：%v", own)
	}

	// 三、軟刪除（終態）：他那一行仍在、別人仍看得見，而沒有任何通路能把成員行跟著刪掉。
	if got := s.env.request(t, http.MethodDelete, "/admin/accounts/"+s.account["丁"], `{}`,
		s.manaA); got.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(got.Body)
		t.Fatalf("軟刪除應成功：%d %s", got.StatusCode, body)
	}
	if _, status := r4AccountFacts(t, s.env.db, s.account["丁"]); status != "deleted" {
		t.Errorf("刪除該落在帳戶那一行的狀態上，實際 %q", status)
	}
	if got := r4MemberFaction(t, s.env.db, s.member["丁"]); got != factions["丁"] {
		t.Errorf("軟刪除不改寫歸屬：%q → %q", factions["丁"], got)
	}
	after := s.list(t, s.cookieOf(t, "甲"), s.activityA, "")
	if len(r4Visible(t, after)) != 8 {
		t.Errorf("軟刪除不把人從目錄抹掉（歷史不搬不改寫）：%v", r4Visible(t, after))
	}
	if got := r4MemberCount(t, s.env.db, s.activityA); got != 8 {
		t.Errorf("軟刪除不減成員行，實際 %d 行", got)
	}
	// 而這一族沒有「順手把成員行也刪了」的通路：DELETE 一律 405。
	if got := s.env.request(t, http.MethodDelete,
		"/admin/activities/"+s.activityA+"/members/"+s.member["丁"], "", s.manaA); got.
		StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("成員族不受理 DELETE：%d", got.StatusCode)
	}
	// 他本人也再讀不到任何東西（會話隨刪除撤銷）。
	if got := s.profile(t, s.cookieOf(t, "丁"), s.activityA); got.StatusCode == http.StatusOK {
		t.Error("被刪除者的會話不該還能讀本人投影")
	}
	// 被刪過的人不能再被加進名冊：那句與查無同形，不會多出一行指向終態帳戶的身份。
	if got := s.env.request(t, http.MethodPost,
		"/admin/activities/"+s.activityA+"/members",
		dirBody(t, map[string]any{"account_id": s.account["丁"], "nickname": "重複的已刪者"}),
		s.manaA); got.StatusCode != http.StatusNotFound || r4ErrorCode(t, got) != 1001 {
		t.Errorf("把已軟刪除的帳戶再建一行成員該收斂成 1001：%d", got.StatusCode)
	}
	if got := r4MemberCount(t, s.env.db, s.activityA); got != 8 {
		t.Errorf("被拒的建立不該多一行，實際 %d 行", got)
	}
	s.assertFactionsUnmoved(t, factions, "轉正／停用／刪除三處之後")
}

// TestR4GuestBindingLeavesNoOrphanOrMixedIdentity 驗收綁定那一段通路帶著陣營引用時的形態：
// 預檢不把「他在一場活動裡有身份」當成未登記的引用（整體 fail-closed 的開關沒被誤觸），
// 執行之後來源進入退休終態、他的成員行原樣指向原標識，
// 而目標既不會因此多出一份活動內身份、也讀不到那一段歷史——
// 「不能製造悬空或混合身份」在這裡是可問的兩個方向：既有那一行不多不少，新的那一行根本不存在。
func TestR4GuestBindingLeavesNoOrphanOrMixedIdentity(t *testing.T) {
	s := newR4Scene(t)
	s.mustSetDirMode(t, s.activityA, "all_members")
	guestID := s.account["己"]
	sourceCookie := s.cookieOf(t, "己")
	_, targetCookie := s.env.selfSelectPlayer(t, s.manaA, "r4.bind.target")
	targetID := s.accountOf(t, "r4.bind.target")

	// 預檢：一行帶著陣營歸屬的成員身份不構成阻止原因（它是歷史事實，不是待搬遷的歸屬）。
	preflight := s.env.request(t, http.MethodPost,
		"/admin/accounts/"+guestID+"/bind-preflight",
		dirBody(t, map[string]any{"target_account_id": targetID}), s.manaA)
	if preflight.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(preflight.Body)
		t.Fatalf("綁定預檢應成功：%d %s", preflight.StatusCode, body)
	}
	preview := decodeJSONBody(t, preflight)
	if preview["executable"] != true {
		t.Errorf("這一對今天該是可執行，實際 %v", preview)
	}
	if blockers, _ := preview["blockers"].([]any); len(blockers) != 0 {
		t.Errorf("成員行不該成為阻止原因：%v", blockers)
	}

	// 簽發憑證，然後由目標本人核銷——管理員代按的那一格在今日根本不存在（另檔已取證，這裡只問結果）。
	issued := decodeJSONBody(t, s.env.request(t, http.MethodPost,
		"/admin/accounts/"+guestID+"/bind-ticket",
		dirBody(t, map[string]any{"target_account_id": targetID}), s.manaA))
	ticket, _ := issued["ticket"].(string)
	if ticket == "" {
		t.Fatalf("簽發回應要帶著憑證：%v", issued)
	}
	claimed := s.env.request(t, http.MethodPost, "/auth/guest-bindings",
		dirBody(t, map[string]any{"ticket": ticket}), targetCookie)
	if claimed.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(claimed.Body)
		t.Fatalf("目標本人核銷憑證應成功：%d %s", claimed.StatusCode, body)
	}

	// 來源進入退休終態，而他那一行成員身份與歸屬一個字都沒動、行數也沒變。
	if _, status := r4AccountFacts(t, s.env.db, guestID); status != "retired" {
		t.Errorf("綁定要把來源放進退休終態，實際 %q", status)
	}
	if got := r4MemberFaction(t, s.env.db, s.member["己"]); got != s.red {
		t.Errorf("綁定不改寫歸屬，實際 %q", got)
	}
	if _, account := r4MemberActivityAndAccount(t, s.env.db, s.member["己"]); account != guestID {
		t.Error("那一行仍該指向原来的來源標識：綁定不代為搬遷活動內身份")
	}
	if got := r4MemberCount(t, s.env.db, s.activityA); got != 8 {
		t.Errorf("綁定既不搬也不複製，主場仍該是八行，實際 %d", got)
	}
	// 混合身份的反證：目標自己敲本人讀法，拿到的是不可分辨那一句（他沒有那場活動的成員行）。
	if got := s.profile(t, targetCookie, s.activityA); got.StatusCode != http.StatusNotFound ||
		r4ErrorCode(t, got) != 1001 {
		t.Errorf("目標不該借綁定取得活動內身份：%d", got.StatusCode)
	}
	if got := s.listResp(t, targetCookie, s.activityA, ""); got.StatusCode != http.StatusNotFound {
		t.Errorf("目標也不該借綁定讀到那場的目錄：%d", got.StatusCode)
	}
	// 來源的舊憑據在核銷那一刻被撤銷，退休行也讀不到任何東西。
	if got := s.profile(t, sourceCookie, s.activityA); got.StatusCode == http.StatusOK {
		t.Error("綁定後來源的舊會話不該還能讀本人投影")
	}
	// 別人那一側的目錄照舊列得出他（活動內事實不因帳戶側的終態而消失），而且沒有多一個他。
	page := s.list(t, s.cookieOf(t, "甲"), s.activityA, "")
	if len(r4Visible(t, page)) != 8 {
		t.Errorf("綁定不該讓目錄少一行或多一行：%v", r4Visible(t, page))
	}
	if row := dirRowOf(t, page, "己"); row["faction_id"] != s.red {
		t.Errorf("目錄裡那一行仍舊帶著當時的歸屬：%v", row)
	}
	// 同一枚憑證不能核銷第二次（重複綁定既不會重寫歷史，也不會多造一份身份）。
	again := s.env.request(t, http.MethodPost, "/auth/guest-bindings",
		dirBody(t, map[string]any{"ticket": ticket}), targetCookie)
	if again.StatusCode == http.StatusOK {
		t.Fatal("同一枚憑證不該能核銷兩次")
	}
	// 這一組要把「拒絕」量成一句可判定的話，而不是只量「不是 200」：已核銷的憑證屬憑證本身失效。
	if again.StatusCode != http.StatusForbidden || r4ErrorCode(t, again) != 2025 {
		t.Errorf("重複核銷該是 403／2025（憑據有效而那張小票已換不出這次綁定），實際 %d／%d",
			again.StatusCode, r4ErrorCode(t, again))
	}
	if got := r4MemberCount(t, s.env.db, s.activityA); got != 8 {
		t.Errorf("被拒的重複核銷不動行數，實際 %d", got)
	}
	// 已退休的那一行也不是可以再度綁定的來源：這一句是「明確拒絕」而不是查無此人。
	replay := s.env.request(t, http.MethodPost,
		"/admin/accounts/"+guestID+"/bind-preflight",
		dirBody(t, map[string]any{"target_account_id": targetID}), s.manaA)
	if replay.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(replay.Body)
		t.Fatalf("對退休來源重新預檢該回到一句可讀的結論：%d %s", replay.StatusCode, body)
	}
	replayed := decodeJSONBody(t, replay)
	if replayed["executable"] == true {
		t.Errorf("退休來源不該再度可綁：%v", replayed)
	}
	if blockers, _ := replayed["blockers"].([]any); len(blockers) == 0 {
		t.Errorf("必須說出阻止原因而不是默默回不可執行：%v", replayed)
	}
}

// accountOf 由管理側帳戶目錄把登入名換成帳戶標識（綁定那一段需要兩個標識，而現場只記了暱稱）。
func (s *r4Scene) accountOf(t *testing.T, login string) string {
	t.Helper()
	resp := s.env.request(t, http.MethodGet,
		"/admin/accounts?page=1&page_size=100&"+"q="+login, "", s.manaA)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("讀帳戶目錄應成功：%d %s", resp.StatusCode, body)
	}
	accounts, _ := decodeJSONBody(t, resp)["accounts"].([]any)
	for _, raw := range accounts {
		item, _ := raw.(map[string]any)
		if item["login_name"] == login {
			id, _ := item["account_id"].(string)
			return id
		}
	}
	t.Fatalf("帳戶目錄讀不到 %q", login)
	return ""
}

// TestR4AdminIdentityIsReadFromGrantsNotFromNames 驗收第四態那一句的判據與分工：
// 「管理員身分」只由 internal/grant 的現讀決定，因此持有授予的成員對普通玩家收起來、
// 對獲指派的管理人照樣列得出、對他本人照樣列得出；把這樣一個人換進某個陣營之後，
// 同一個陣營的候選計數在兩份答案裡各自成立（普通玩家少他一個），
// 而不是「計數跟着他走」或「跟着暱稱走」。
func TestR4AdminIdentityIsReadFromGrantsNotFromNames(t *testing.T) {
	s := newR4Scene(t)

	s.mustSetDirMode(t, s.activityA, "all_players_except_admin")
	// 普通玩家這一份：三位持有授予者一律收起來（判據是授予，不是他在名冊上的暱稱）。
	page := s.list(t, s.cookieOf(t, "甲"), s.activityA, "")
	if got := dirSorted(r4Visible(t, page)); !equalStrings(got,
		[]string{"丁", "丙", "乙", "己", "甲"}) {
		t.Errorf("排除管理員身分那態該收起來持有授予的三行，實際 %v", got)
	}
	if r4Total(t, page) != 5 {
		t.Errorf("計數要與列表同源（5 行），實際 %d", r4Total(t, page))
	}
	// 其中一位持有授予者本人：-self 那一句排在模式之前，他看得見自己。
	himself := dirSorted(r4Visible(t, s.list(t, s.cookieOf(t, "幕後"), s.activityA, "")))
	if !equalStrings(himself, []string{"丁", "丙", "乙", "己", "幕後", "甲"}) {
		t.Errorf("持有授予的成員該看得見自己與全部非管理員成員，實際 %v", himself)
	}
	// 獲指派的管理人：同一句請求換成管理視角，八行一格不少——包括被別人收起來的三位。
	if got := len(r4Visible(t, s.list(t, s.manaA, s.activityA, ""))); got != 8 {
		t.Errorf("管理視角不受這一態約束，該是八行，實際 %d 行", got)
	}
	// 持有授予但沒被指派的人不是管理視角：他在這一態下與普通玩家同一份答案。
	outsider := dirSorted(r4Visible(t, s.list(t, s.manaB, s.activityA, "")))
	if !equalStrings(outsider, []string{"丁", "丙", "乙", "己", "管理人二", "甲"}) {
		t.Errorf("未獲指派的管理人不該多看見任何人，實際 %v", outsider)
	}

	// 把一位持有授予者換進紅隊：他對普通玩家仍然不可見，而紅隊的候選計數在兩份答案裡各說各的。
	s.mustSelect(t, s.cookieOf(t, "幕後"), s.activityA, s.red)
	after := s.list(t, s.cookieOf(t, "甲"), s.activityA, "")
	if r4FacetCount(t, after, s.red) != 3 {
		t.Errorf("對甲而言紅隊仍該是三人（幕後不在他這一份結果裡）：%v", after["facets"])
	}
	if len(r4Visible(t, after)) != 5 {
		t.Errorf("換隊不該讓被收起來的人浮現：%v", r4Visible(t, after))
	}
	if got := r4FacetCount(t, s.list(t, s.manaA, s.activityA, ""), s.red); got != 4 {
		t.Errorf("管理視角這一份紅隊該是四人，實際 %d", got)
	}
	// 而本人在僅同陣營態下照常看得見同袍（這一態不收管理員，收的是「不是同隊」）。
	s.mustSetDirMode(t, s.activityA, "same_faction_only")
	if got := dirSorted(r4Visible(t, s.list(t, s.cookieOf(t, "幕後"), s.activityA, ""))); !equalStrings(
		got, []string{"乙", "己", "幕後", "甲"}) {
		t.Errorf("僅同陣營態下紅隊四人該互相看得到（判據是歸屬而不是旗標與授予）：%v", got)
	}
	// 收回目錄時，兩類主體的答案是兩句話：獲指派的照樣全量，持有授予但沒被指派的空一頁。
	s.mustSetDirMode(t, s.activityA, "hidden")
	if got := len(r4Visible(t, s.list(t, s.manaB, s.activityA, ""))); got != 0 {
		t.Errorf("未獲指派者在 hidden 態該是空的一頁，實際 %d 行", got)
	}
	if got := len(r4Visible(t, s.list(t, s.manaA, s.activityA, ""))); got != 8 {
		t.Errorf("獲指派者在 hidden 態該照樣讀到八行，實際 %d 行", got)
	}
}
