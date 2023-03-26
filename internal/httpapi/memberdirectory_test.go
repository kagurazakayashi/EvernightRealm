// memberdirectory_test.go 是「玩家目錄可見性」在傳輸層的端到端證據：出廠那份不開放的目錄、
// 管理人把模式開下去、玩家讀目錄與單筆直查與本人投影、各路徑各自的準入矩陣
// （匿名、非成員帳戶、外人管理員、場內管理人、本人、Root、訪戶）、本體與查詢引數的白名單
// （含四種「順手宣稱管理視角」的寫法）、覆蓋落地後列表與名冊各自的說法、兩筆留痕的操作者，
// 以及「拿著舊畫面重發」在 2013 與「下一筆請求按新規則判定」這兩件事上各自的形態。
//
// 刻意不收的東西：
//   - 沒有替身：授權、活動作用域、業務門禁、可見性判定、授予現讀、CAS 與審計都跨層走真路徑
//     （真資料庫＋真會話＋注入時鐘），接錯線就會紅；
//   - 不重複服務層的四態矩陣：逐模式的可見集合已由 internal/activity 取證，
//     本檔釘的是協定層該長的形狀（哪些欄出去、哪些碼各自成句、不可分辨是否逐字同文）；
//   - 不碰真實數據目錄、不佔 5206，全程本次專屬的臨時庫。
package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// dirGhostActivity 與 dirGhostMember 是兩個合法形狀但從未存在的標識（不可分辨性的對照組）。
const (
	dirGhostActivity = "0192f0c4-1c9a-7000-8000-000000000fd1"
	dirGhostMember   = "0192f0c4-1c9a-7000-8000-000000000fd2"
)

// dirBody 湊一份本體（鍵值由呼叫端給，順序不重要：這是給後端讀的 JSON 物件）。
func dirBody(t *testing.T, fields map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("湊本體失敗：%v", err)
	}
	return string(encoded)
}

// dirQuery 湊一組分頁查詢引數（走的是「頁面＋每頁筆數」這一條既有約定，不另造游標格式）。
func dirQuery(page, pageSize int) string {
	return "?page=" + strconv.Itoa(page) + "&page_size=" + strconv.Itoa(pageSize)
}

// dirScene 是本檔共用的現場：一場已開放的活動、兩個陣營、七行成員。
//
// 七行的分工（每一條協定結論都要有對應的對象）：
//   - 甲／乙／己：同一個陣營（己是訪戶——參加不是權限）；
//   - 丙：另一個陣營（異陣營對象）；
//   - 丁：無陣營（「尚未分組」對象）；
//   - 管理人一：持有授予、且是這場活動的管理人（管理視角的對象，也是
//     all_players_except_admin 該對普通玩家收起來的一行）；
//   - 管理人二：持有授予、但不是這場活動的管理人（他管另一場）——「外人不因持有授予而提權」的對象。
type dirScene struct {
	env      *factionEnv
	admin    string // 管理人一的會話標頭
	outsider string // 管理人二的會話標頭
	activity string
	other    string
	fac1     string
	fac2     string
	member   map[string]string // nickname → member_id
	cookies  map[string]string // nickname → Cookie 標頭
}

// newDirScene 佈好現場。目錄那一欄保持出廠的 hidden，由各測試自己決定要不要打開。
func newDirScene(t *testing.T) *dirScene {
	t.Helper()
	e := newFactionEnv(t)
	s := &dirScene{env: e, member: map[string]string{}, cookies: map[string]string{}}

	adminID, adminCookie := e.dirAdminWithSession(t, "dir.admin")
	s.admin = adminCookie
	s.activity = e.createFactionActivity(t, adminCookie, "有目錄的場")

	// 另一位持有授予者：他管理的是「另一場」活動，因此對本場而言他只是普通玩家那一類。
	outsiderID, outsiderCookie := e.dirAdminWithSession(t, "dir.outsider")
	s.outsider = outsiderCookie
	s.other = e.createFactionActivity(t, outsiderCookie, "外人管的場")

	// 玩家自選那一欄先打開成 free：今日能把陣營歸屬落下的通路只有它，而目錄判定吃的就是這個現值。
	e.selfSetMode(t, adminCookie, s.activity, "free", "disabled")
	s.fac1, _ = dirFactionID(t, e.selfCreateFaction(t, adminCookie, s.activity, "紅隊"))
	s.fac2, _ = dirFactionID(t, e.selfCreateFaction(t, adminCookie, s.activity, "藍隊"))

	// 五位普通玩家（含一位訪戶）與兩位持有授予者，全部進名冊。
	for _, pair := range []struct{ login, nickname, faction string }{
		{"dir.jia", "甲", "紅隊"}, {"dir.yi", "乙", "紅隊"},
		{"dir.bing", "丙", "藍隊"}, {"dir.ding", "丁", ""},
	} {
		accountID, cookie := e.selfSelectPlayer(t, adminCookie, pair.login)
		s.member[pair.nickname] = e.selfAddMember(t, adminCookie, s.activity,
			accountID, pair.nickname)
		s.cookies[pair.nickname] = cookie
		if pair.faction != "" {
			factionID := s.fac1
			if pair.faction == "藍隊" {
				factionID = s.fac2
			}
			e.dirSelect(t, cookie, s.activity, factionID)
		}
	}
	guestID, guestCookie := e.dirGuest(t, "己")
	s.member["己"] = e.selfAddMember(t, adminCookie, s.activity, guestID, "己")
	s.cookies["己"] = guestCookie
	e.dirSelect(t, guestCookie, s.activity, s.fac1)

	s.member["管理人一"] = e.selfAddMember(t, adminCookie, s.activity, adminID, "管理人一")
	s.member["管理人二"] = e.selfAddMember(t, adminCookie, s.activity, outsiderID, "管理人二")
	return s
}

// dirSelect 由玩家自己把歸屬選下去（借道上一那一步那條通路，本檔不另寫一份協定）。
func (e *factionEnv) dirSelect(t *testing.T, cookie, activityID, factionID string) {
	t.Helper()
	resp := e.request(t, http.MethodPut, "/player/activities/"+activityID+"/faction",
		selfSelectBody(factionID, ""), cookie)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("自選陣營 %s 應成功：%d %s", factionID, resp.StatusCode, body)
	}
}

// dirGuest 走真實訪戶通路取得一位訪戶的帳戶標識與會話標頭（Guest 也能是成員）。
//
// 先把「允許訪客進入」那一格翻開（出廠是關的），否則連門都敲不到；這一格屬帳戶建立策略，
// 准入是 NeedRoot（見 internal/httpapi/accountpolicy.go），與本步的目錄可見性是兩套東西。
func (e *factionEnv) dirGuest(t *testing.T, nickname string) (string, string) {
	t.Helper()
	if resp := e.request(t, http.MethodPut, "/root/account-policy",
		policyBody(true, "closed", true), cookieHeader(e.factionRootCookie(t))); resp.StatusCode !=
		http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("打開訪客進入應成功：%s", body)
	}
	resp := e.request(t, http.MethodPost, "/auth/guest",
		dirBody(t, map[string]any{"nickname": nickname}), "")
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("建立訪戶應成功：%d %s", resp.StatusCode, body)
	}
	payload := decodeJSONBody(t, resp)
	accountID, _ := payload["account_id"].(string)
	if accountID == "" {
		t.Fatalf("訪戶回應要帶著帳戶標識，實際 %v", payload)
	}
	return accountID, cookieHeader(loginCookie(t, resp))
}

// dirAdminWithSession 開設一位管理員並走完首改，回傳他的帳戶標識與會話標頭。
func (e *factionEnv) dirAdminWithSession(t *testing.T, login string) (string, string) {
	t.Helper()
	resp := e.request(t, http.MethodPost, "/root/admins",
		dirBody(t, map[string]any{"login_name": login, "display_name": "目錄管理員",
			"password": activityTestAdminSeed}),
		cookieHeader(e.factionRootCookie(t)))
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 開設管理員應成功：%d %s", resp.StatusCode, body)
	}
	payload := decodeJSONBody(t, resp)
	accountID, _ := payload["account_id"].(string)
	if accountID == "" {
		t.Fatalf("開設回應要帶著帳戶標識，實際 %v", payload)
	}
	first := loginCookie(t, e.request(t, http.MethodPost, "/auth/login",
		dirBody(t, map[string]any{"login_name": login, "password": activityTestAdminSeed}), ""))
	if changed := e.request(t, http.MethodPost, "/auth/password/change",
		dirBody(t, map[string]any{"current_password": activityTestAdminSeed,
			"new_password": activityTestAdminChanged}),
		cookieHeader(first)); changed.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(changed.Body)
		t.Fatalf("首次改密應成功：%s", body)
	}
	relogin := e.request(t, http.MethodPost, "/auth/login",
		dirBody(t, map[string]any{"login_name": login,
			"password": activityTestAdminChanged}), "")
	return accountID, cookieHeader(loginCookie(t, relogin))
}

// dirFactionID 從陣營建立回應取標識。
func dirFactionID(t *testing.T, item map[string]any) (string, string) {
	t.Helper()
	id, _ := item["faction_id"].(string)
	name, _ := item["name"].(string)
	if id == "" {
		t.Fatalf("陣營回應要帶著標識，實際 %v", item)
	}
	return id, name
}

// dirSetMode 由管理人編輯那一欄模式；expectNonZero 時把狀態碼當成斷言對象。
func (s *dirScene) setMode(t *testing.T, mode, expected, admin string) (map[string]any, int) {
	t.Helper()
	who := s.admin
	if admin != "" {
		who = admin
	}
	resp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+s.activity+"/member-directory",
		dirBody(t, map[string]any{"mode": mode, "expected_mode": expected}), who)
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	return mustActivityItem(t, resp), resp.StatusCode
}

// mustSetMode 是「必須成功」的那一顆，並把模式換進現場（後續請求吃新規則）。
func (s *dirScene) mustSetMode(t *testing.T, mode string) {
	t.Helper()
	item, _ := s.setMode(t, mode, s.currentMode(t), "")
	if got, _ := item["member_directory_mode"].(string); got != mode {
		t.Fatalf("配置寫入要回顯新模式，實際 %q", got)
	}
}

// currentMode 讀活動详情那一格的現值（依據值一律取服務端讀回的那一份，不硬編）。
func (s *dirScene) currentMode(t *testing.T) string {
	t.Helper()
	resp := s.env.request(t, http.MethodGet, "/admin/activities/"+s.activity, "", s.admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("讀活動詳情應成功：%d %s", resp.StatusCode, body)
	}
	item := mustActivityItem(t, resp)
	mode, _ := item["member_directory_mode"].(string)
	if mode == "" {
		t.Fatalf("活動詳情必須帶著 member_directory_mode，實際 %v", item)
	}
	return mode
}

// dirList 讀一頁目錄並回回應本體（非 200 當場失敗）。
func (s *dirScene) list(t *testing.T, cookie, query string) map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/members"+query, "", cookie)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("目錄一讀應成功：%d %s", resp.StatusCode, body)
	}
	payload := decodeJSONBody(t, resp)
	for _, key := range []string{"members", "facets", "member_directory_mode",
		"self_member_id", "page", "page_size", "total", "request_id"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("目錄回應必須帶著 %q 這一格，實際 %v", key, payload)
		}
	}
	return payload
}

// dirNames 取目錄回應裡每一行的暱稱，並逐行反證白名單兩側（該在的都在、不該在的一格都沒有）。
func dirNames(t *testing.T, payload map[string]any) []string {
	t.Helper()
	rows, ok := payload["members"].([]any)
	if !ok {
		t.Fatalf("members 必須是清單，實際 %v", payload["members"])
	}
	out := make([]string, 0, len(rows))
	for _, raw := range rows {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("目錄行必須是物件，實際 %v", raw)
		}
		for _, forbidden := range []string{"account_id", "login_name", "display_name",
			"account_status", "admin_identity", "directory_visibility", "password_hash",
			"device_id", "activity_id", "updated_at", "must_change_password"} {
			if _, ok := item[forbidden]; ok {
				t.Errorf("目錄行不該帶出帳戶側或管理側的欄位 %q：%v", forbidden, item)
			}
		}
		for _, required := range []string{"member_id", "nickname", "faction_id",
			"faction_name", "faction_icon", "faction_color", "faction_available",
			"joined_at"} {
			if _, ok := item[required]; !ok {
				t.Errorf("目錄行必須帶著 %q 這一格（欄位缺席與空值是兩回事）：%v", required, item)
			}
		}
		name, _ := item["nickname"].(string)
		out = append(out, name)
	}
	return out
}

// sortedNames 把清單排序後交給斷言（目錄的順序由加入時刻決定，斷言不依賴它）。
func dirSorted(names []string) []string {
	out := append([]string(nil), names...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// TestMemberDirectoryDefaultHiddenAndConfigRoundTrip 驗收出廠形態與那一欄配置的端到端一趟：
// 不經任何配置就是一個都不列（而詳情照樣讀得到模式現值）；管理人打開之後玩家立刻讀得到人。
func TestMemberDirectoryDefaultHiddenAndConfigRoundTrip(t *testing.T) {
	s := newDirScene(t)

	if got := s.currentMode(t); got != "hidden" {
		t.Fatalf("新建活動的目錄模式必須是 hidden，實際 %q", got)
	}
	page := s.list(t, s.cookies["甲"], "")
	if len(dirNames(t, page)) != 0 || page["total"].(float64) != 0 {
		t.Errorf("出廠形態該一個都不列，實際 %v／%v", dirNames(t, page), page["total"])
	}
	if mode, _ := page["member_directory_mode"].(string); mode != "hidden" {
		t.Errorf("目錄回應要如實帶出模式，實際 %q", mode)
	}
	// 出廠形態下的單筆直查與他人標識：全部不可分辨，而不是「存在但不給看」的第二句話。
	if resp := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/members/"+s.member["乙"], "", s.cookies["甲"]); resp.StatusCode !=
		http.StatusNotFound {
		t.Errorf("hidden 態的直查該是 1001 那個狀態碼：%d", resp.StatusCode)
	}

	s.mustSetMode(t, "all_members")
	full := s.list(t, s.cookies["甲"], "")
	if got := dirSorted(dirNames(t, full)); len(got) != 7 {
		t.Errorf("打開全量後甲該看到七行，實際 %v", got)
	}
	if full["total"].(float64) != 7 {
		t.Errorf("計數要跟著變成 7，實際 %v", full["total"])
	}
	// 留痕：只有一筆成功的配置寫入留下一條，而且操作者是管理員帳戶、前後值都在。
	if got := s.env.countMemberAudits(t, "activity.member_directory_update"); got != 1 {
		t.Errorf("配置寫入留下一筆留痕，實際 %d", got)
	}
	row := s.env.dirAudit(t, "activity.member_directory_update")
	if row.actorKind != "admin" ||
		!strings.Contains(row.changes, "member_directory_mode") ||
		!strings.Contains(row.changes, "hidden") ||
		!strings.Contains(row.changes, "all_members") {
		t.Errorf("留痕要帶管理員身份與前後值：%+v", row)
	}
	// 單筆直查與列表同進退：現在點得進了。
	resp := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/members/"+s.member["乙"], "", s.cookies["甲"])
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("全量態的直查應成功：%d %s", resp.StatusCode, body)
	}
	item := mustDirectoryItem(t, resp)
	if item["nickname"] != "乙" || item["faction_name"] != "紅隊" {
		t.Errorf("直查回應要帶出展示事實：%v", item)
	}
}

// TestMemberDirectoryModeSemanticsAtTransport 驗收另外兩態在協定層各自的答案與篩選候選／分頁。
func TestMemberDirectoryModeSemanticsAtTransport(t *testing.T) {
	s := newDirScene(t)

	s.mustSetMode(t, "same_faction_only")
	page := s.list(t, s.cookies["甲"], "")
	if got := dirSorted(dirNames(t, page)); !equalStrings(got, []string{"乙", "己", "甲"}) {
		t.Errorf("僅同陣營態下甲該看到紅隊三人，實際 %v", got)
	}
	facets, _ := page["facets"].([]any)
	if len(facets) != 1 {
		t.Fatalf("篩選候選必須只剩紅隊一項，實際 %v", facets)
	}
	facet, _ := facets[0].(map[string]any)
	if facet["count"].(float64) != 3 || facet["faction_id"] != s.fac1 {
		t.Errorf("候選項要帶著紅隊與計數 3，實際 %v", facet)
	}
	// 無陣營的丁：只看得到自己（用戶批准於本步：無陣營不是一個群體）。
	alone := s.list(t, s.cookies["丁"], "")
	if got := dirSorted(dirNames(t, alone)); !equalStrings(got, []string{"丁"}) {
		t.Errorf("丁在僅同陣營態下只該看見自己，實際 %v", got)
	}

	s.mustSetMode(t, "all_players_except_admin")
	hidden := s.list(t, s.cookies["甲"], "")
	if got := dirSorted(dirNames(t, hidden)); !equalStrings(got,
		[]string{"丙", "乙", "丁", "己", "甲"}) {
		t.Errorf("排除管理員身分那態該收起來持有授予的兩行，實際 %v", got)
	}
	// 判據是授予而非顯示名：把「管理人二」的暱稱改成像平民，他依然不在列表裡。
	if resp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+s.activity+"/members/"+s.member["管理人二"],
		dirBody(t, map[string]any{"nickname": "路過", "expected_nickname": "管理人二"}),
		s.admin); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("改名應成功：%s", body)
	}
	renamed := s.list(t, s.cookies["甲"], "")
	for _, name := range dirNames(t, renamed) {
		if name == "路過" {
			t.Errorf("改暱稱不該讓持有授予者變得可見：%v", dirSorted(dirNames(t, renamed)))
		}
	}

	s.mustSetMode(t, "all_members")
	// 分頁：一頁兩行逐頁走完，合起來是不重不漏的七行，而 total 恆為可見行數。
	seen := map[string]bool{}
	for page := 1; page <= 4; page++ {
		got := s.list(t, s.cookies["甲"], dirQuery(page, 2))
		rows, _ := got["members"].([]any)
		if len(rows) > 2 {
			t.Errorf("第 %d 頁不得超過兩行，實際 %d", page, len(rows))
		}
		if got["total"].(float64) != 7 {
			t.Errorf("總數不受分頁影響（該是 7），實際 %v", got["total"])
		}
		if got["page"].(float64) != float64(page) {
			t.Errorf("第 %d 頁要回顯自己，實際 %v", page, got["page"])
		}
		for _, raw := range rows {
			item, _ := raw.(map[string]any)
			id, _ := item["member_id"].(string)
			if seen[id] {
				t.Errorf("游標把 %s 吐了兩次（分頁重疊）", id)
			}
			seen[id] = true
		}
	}
	if len(seen) != 7 {
		t.Errorf("四頁合起來必須剛好是那七行（不重不漏），實際 %d 行", len(seen))
	}
	first := s.list(t, s.cookies["甲"], "?page=1&page_size=2")
	if rows, _ := first["members"].([]any); len(rows) != 2 {
		t.Errorf("page_size=2 該只給兩行，實際 %d", len(rows))
	}
	if first["page"].(float64) != 1 || first["page_size"].(float64) != 2 {
		t.Errorf("分頁三元組要回顯生效值，實際 %v／%v", first["page"], first["page_size"])
	}
	third := s.list(t, s.cookies["甲"], "?page=9&page_size=2")
	if rows, _ := third["members"].([]any); len(rows) != 0 || third["total"].(float64) != 7 {
		t.Errorf("越界頁該是空的一頁而 total 照實：%d／%v", len(rows), third["total"])
	}
}

// TestMemberDirectoryAccessMatrix 驗收各路徑的準入：匿名、非成員帳戶、外人管理員、
// Root 與系統、普通成員碰管理面，以及「非成員」與「幽靈活動」逐字同形。
func TestMemberDirectoryAccessMatrix(t *testing.T) {
	s := newDirScene(t)
	s.mustSetMode(t, "all_members")

	// 匿名：先撞在未通過認證那一句（2002），不是空清單。
	anon := s.env.request(t, http.MethodGet, "/player/activities/"+s.activity+"/members", "", "")
	if code := dirErrorCode(t, anon); code != 2002 {
		t.Errorf("匿名讀目錄該是 2002，實際 %d", code)
	}
	// 既非成員也非管理人的普通帳戶，與幽靈活動：同碼同文（不可分辨）。
	outsiderAccount, outsiderCookie := s.env.selfSelectPlayer(t, s.admin, "dir.stranger")
	_ = outsiderAccount
	denied := s.env.request(t, http.MethodGet, "/player/activities/"+s.activity+"/members",
		"", outsiderCookie)
	ghost := s.env.request(t, http.MethodGet, "/player/activities/"+dirGhostActivity+"/members",
		"", s.cookies["甲"])
	if denied.StatusCode != http.StatusNotFound || ghost.StatusCode != http.StatusNotFound {
		t.Errorf("非成員與幽靈都該是 404：%d／%d", denied.StatusCode, ghost.StatusCode)
	}
	deniedBody, ghostBody := dirErrorText(t, denied), dirErrorText(t, ghost)
	if deniedBody.code != ghostBody.code || deniedBody.msg != ghostBody.msg {
		t.Errorf("兩種拒絕必須逐字同形（不多出存在性信號）：%+v／%+v", deniedBody, ghostBody)
	}
	// Root 在玩家這一族沒有可指向的成員行：與查無同形，而不是「全量目錄」。
	root := cookieHeader(s.env.factionRootCookie(t))
	if code := dirErrorCode(t, s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/members", "", root)); code != 1001 {
		t.Errorf("Root 讀玩家目錄該收斂成 1001，實際 %d", code)
	}
	// 持有授予但這個活動不歸他管（他在本場只是普通成員）：他讀到的是模式過濾後的那一份，
	// 而不是全部——這一句就是「不授予其他活動管理權、也不能靠管理視角提權」的協定層形態。
	// 把模式收成僅同陣營時他無歸屬，因此只看得到自己一行；同一時刻獲准管理本場的管理人讀到七行。
	s.mustSetMode(t, "same_faction_only")
	outsiderView := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/members", "", s.outsider)
	if outsiderView.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(outsiderView.Body)
		t.Fatalf("外人管理員作為成員該讀得到目錄：%d %s", outsiderView.StatusCode, body)
	}
	if got := dirNames(t, decodeJSONBody(t, outsiderView)); len(got) != 1 ||
		got[0] != "管理人二" {
		t.Errorf("未獲指派的管理人不該多看見任何人，實際 %v", got)
	}
	managerView := s.list(t, s.admin, "")
	if len(dirNames(t, managerView)) != 7 {
		t.Errorf("獲准管理的管理人在同一態下該看到七行，實際 %v", dirNames(t, managerView))
	}
	if managerView["member_directory_mode"] != "same_faction_only" {
		t.Errorf("管理視角也要如實帶出活動模式：%v", managerView["member_directory_mode"])
	}
	// 他在自己獲准管理的那場活動裡沒有成員行，卻仍讀得到那一場的目錄（空的一頁，
	// 因為那裡本來就沒人）：管理視角來自服務端現讀的指派，不是任何一格請求參數。
	if resp := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.other+"/members", "", s.outsider); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("管理人該讀得到自己那場活動：%d %s", resp.StatusCode, body)
	} else if rows, _ := decodeJSONBody(t, resp)["members"].([]any); len(rows) != 0 {
		t.Errorf("外人那場活動沒有成員行，該是空的一頁，實際 %d 行", len(rows))
	}
	// 管理面兩條路徑：普通成員拿到 2011，不是 1001（他確實是一場活動的成員，
	// 缺的是「屬於管理員這個身份面」那一句，處置也不同）。
	if _, code := s.setMode(t, "hidden", "all_members", s.cookies["甲"]); code != http.StatusForbidden {
		t.Errorf("玩家改配置該拿到 403／2011，實際 %d", code)
	}
	visResp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+s.activity+"/members/"+s.member["甲"]+"/directory-visibility",
		dirBody(t, map[string]any{"visibility": "hidden", "expected_visibility": "inherit"}),
		s.cookies["甲"])
	if visResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(visResp.Body)
		t.Errorf("玩家改覆蓋該拿到 403：%d %s", visResp.StatusCode, body)
	}
	// 未獲指派的管理人：與查無同形（1001），不承認那個活動存在。
	if _, code := s.setMode(t, "hidden", "all_members", s.outsider); code != http.StatusNotFound {
		t.Errorf("外人管理員改配置該是 404，實際 %d", code)
	}
}

// TestMemberDirectoryBodyAndQueryWhitelists 驗收本體與查詢引數的形態：
// 任何「宣稱管理視角」「順手指標識」「帶派生值」的寫法都無處可填，
// 而寫法錯誤一律 1004 點名，不會被降級成「當成沒帶」。
func TestMemberDirectoryBodyAndQueryWhitelists(t *testing.T) {
	s := newDirScene(t)

	for _, body := range []map[string]any{
		{"mode": "all_members", "expected_mode": "hidden", "member_id": s.member["乙"]},
		{"mode": "all_members", "expected_mode": "hidden", "account_id": s.member["乙"]},
		{"mode": "all_members", "expected_mode": "hidden", "is_admin": true},
		{"mode": "all_members", "expected_mode": "hidden", "admin_view": true},
		{"mode": "all_members", "expected_mode": "hidden", "scope": "all"},
		{"mode": "all_members", "expected_mode": "hidden", "viewer": s.member["甲"]},
		{"mode": "all_members", "expected_mode": "hidden", "faction_select_mode": "free"},
		{"mode": "all_members"},
		{"expected_mode": "hidden"},
		{"mode": "everyone", "expected_mode": "hidden"},
		{"mode": "ALL_MEMBERS", "expected_mode": "hidden"},
		{"mode": "all_members", "expected_mode": "nope"},
	} {
		resp := s.env.request(t, http.MethodPut,
			"/admin/activities/"+s.activity+"/member-directory", dirBody(t, body), s.admin)
		if resp.StatusCode != http.StatusBadRequest {
			bodyText, _ := io.ReadAll(resp.Body)
			t.Errorf("這份本體該被擋在 400：%s（%s）", body, bodyText)
			continue
		}
		err := dirErrorText(t, resp)
		if err.code != 1004 {
			t.Errorf("寫法錯誤一律 1004，實際 %+v（本體 %v）", err, body)
		}
	}
	// 配置寫入一律沒有落地：庫中現值仍是出廠的 hidden。
	if got := s.currentMode(t); got != "hidden" {
		t.Errorf("被拒的寫法一個字都不該落，實際 %q", got)
	}

	for _, body := range []map[string]any{
		{"visibility": "hidden", "expected_visibility": "inherit", "member_id": s.member["甲"]},
		{"visibility": "hidden", "expected_visibility": "inherit", "account_id": s.member["甲"]},
		{"visibility": "hidden", "expected_visibility": "inherit", "reason": "低调"},
		{"visibility": "visible", "expected_visibility": "inherit"},
		{"visibility": "hidden", "expected_visibility": "nope"},
		{"visibility": "hidden"},
	} {
		resp := s.env.request(t, http.MethodPut,
			"/admin/activities/"+s.activity+"/members/"+s.member["甲"]+"/directory-visibility",
			dirBody(t, body), s.admin)
		err := dirErrorText(t, resp)
		if resp.StatusCode != http.StatusBadRequest || err.code != 1004 {
			t.Errorf("這份覆蓋本體該被擋在 400／1004：%v → %d %+v", body, resp.StatusCode, err)
		}
	}

	// 查詢引數：寫壞的每一格各自點名（不把 0 或負數默認成「沒帶」）。
	for _, tc := range []struct{ query, field string }{
		{"?page=0", "page"},
		{"?page=-1", "page"},
		{"?page=abc", "page"},
		{"?page_size=0", "page_size"},
		{"?page_size=99999", "page_size"},
		{"?faction=not-an-id", "faction"},
	} {
		resp := s.env.request(t, http.MethodGet,
			"/player/activities/"+s.activity+"/members"+tc.query, "", s.cookies["甲"])
		err := dirErrorText(t, resp)
		if resp.StatusCode != http.StatusBadRequest || err.code != 1004 ||
			err.field != tc.field {
			t.Errorf("%s 該回 400／1004 並點名 %q，實際 %d %+v",
				tc.query, tc.field, resp.StatusCode, err)
		}
	}
	// 超長關鍵字：由用例判長度（上界沿用活動描述那 500 個碼位），點名 q。
	long := "?q="
	for i := 0; i < 90; i++ {
		long += "长长的关键字"
	}
	if err := dirErrorText(t, s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/members"+long, "", s.cookies["甲"])); err.code != 1004 ||
		err.field != "q" {
		t.Errorf("超長關鍵字該點名 q，實際 %+v", err)
	}

	// 方法面：玩家這一族不接受 POST／PUT／DELETE，Allow 也不宣稱 DELETE 之外的把戲；
	// 管理面兩條只認 PUT。
	notAllowed := s.env.request(t, http.MethodPost,
		"/player/activities/"+s.activity+"/members", dirBody(t, map[string]any{}), s.cookies["甲"])
	if notAllowed.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("玩家目錄不受理 POST：%d", notAllowed.StatusCode)
	}
	if allow := notAllowed.Header.Get("Allow"); allow == "" ||
		strings.Contains(allow, "DELETE") {
		t.Errorf("Allow 要列出真正受理的方法而不宣稱 DELETE：實際 %q", allow)
	}
	// 跨站來源一律 2005 且零落地（GET 讀法不受 CSRF 影響，寫入才問）。
	if _, code := s.setMode(t, "all_members", "hidden", s.admin); code != http.StatusOK {
		t.Fatalf("先做一次合法寫入以便反證：%d", code)
	}
	crossSite := s.env.dirRequestWithOrigin(t, http.MethodPut,
		"/admin/activities/"+s.activity+"/member-directory",
		dirBody(t, map[string]any{"mode": "hidden", "expected_mode": "all_members"}),
		s.admin, "https://example.invalid")
	if dirErrorCode(t, crossSite) != 2005 {
		t.Errorf("跨站來源該是 2005，實際 %+v", dirErrorText(t, crossSite))
	}
}

// TestMemberDirectoryOverrideAndSelfProfile 驗收覆蓋在協定層的兩側說法與本人投影：
// 玩家目錄收起來的那一行，在管理名冊裡仍列並帶著 directory_visibility 與 admin_identity；
// 而本人在任何模式下都讀得到自己的那一行。
func TestMemberDirectoryOverrideAndSelfProfile(t *testing.T) {
	s := newDirScene(t)
	s.mustSetMode(t, "all_members")

	yi := s.member["乙"]
	resp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+s.activity+"/members/"+yi+"/directory-visibility",
		dirBody(t, map[string]any{"visibility": "hidden", "expected_visibility": "inherit"}),
		s.admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("收緊覆蓋應成功：%d %s", resp.StatusCode, body)
	}
	item, _ := decodeJSONBody(t, resp)["member"].(map[string]any)
	if item["directory_visibility"] != "hidden" {
		t.Errorf("覆蓋寫入要回顯新值，實際 %v", item)
	}
	// 玩家目錄裡他消失了，計數與篩選候選一起少一行。
	page := s.list(t, s.cookies["甲"], "")
	for _, name := range dirNames(t, page) {
		if name == "乙" {
			t.Errorf("被收起來的一行不該出現在玩家目錄：%v", dirNames(t, page))
		}
	}
	if page["total"].(float64) != 6 {
		t.Errorf("計數要跟著少一行，實際 %v", page["total"])
	}
	for _, raw := range page["facets"].([]any) {
		facet, _ := raw.(map[string]any)
		if facet["faction_id"] == s.fac1 && facet["count"].(float64) != 2 {
			t.Errorf("篩選候選計數要與列表同源（紅隊變成 2），實際 %v", facet)
		}
	}
	// 管理名冊仍列那一行，並帶著覆蓋與「他是不是管理員身分」兩個投影。
	roster := s.env.request(t, http.MethodGet, "/admin/activities/"+s.activity+"/members", "", s.admin)
	if roster.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(roster.Body)
		t.Fatalf("名冊應成功：%d %s", roster.StatusCode, body)
	}
	var foundHidden, foundAdmin bool
	for _, row := range memberRoster(t, roster) {
		if row["member_id"] == yi && row["directory_visibility"] == "hidden" {
			foundHidden = true
		}
		if row["nickname"] == "管理人一" && row["admin_identity"] == true {
			foundAdmin = true
		}
		if row["nickname"] == "甲" && row["admin_identity"] == true {
			t.Errorf("沒有授予的普通成員絕不能被讀成管理員身分：%v", row)
		}
	}
	if !foundHidden {
		t.Errorf("名冊要如實帶出那一行的覆蓋現值（仍列、可讀）：%v", memberRoster(t, roster))
	}
	if !foundAdmin {
		t.Errorf("名冊要帶出「持有授予」的投影，管理人才能看懂被收起來的是誰")
	}
	// 本人那一讀：覆蓋與模式都不擋他看見自己。
	own := s.env.request(t, http.MethodGet, "/player/activities/"+s.activity+"/profile",
		"", s.cookies["乙"])
	if own.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(own.Body)
		t.Fatalf("本人投影應成功：%d %s", own.StatusCode, body)
	}
	view := decodeJSONBody(t, own)
	if view["nickname"] != "乙" || view["directory_visibility"] != "hidden" ||
		view["member_directory_mode"] != "all_members" || view["faction_name"] != "紅隊" {
		t.Errorf("本人投影要含活動內事實：\n%v", view)
	}
	for _, forbidden := range []string{"account_id", "login_name", "display_name",
		"account_status", "admin_identity"} {
		if _, ok := view[forbidden]; ok {
			t.Errorf("本人投影也不該帶出帳戶側欄位 %q：%v", forbidden, view)
		}
	}
	// 換成 hidden 之後，本人投影照樣成功而目錄照樣是空的（兩句不是同一件事）。
	s.mustSetMode(t, "hidden")
	if len(dirNames(t, s.list(t, s.cookies["乙"], ""))) != 0 {
		t.Errorf("hidden 態下本人的目錄該是空的")
	}
	if own := s.env.request(t, http.MethodGet, "/player/activities/"+s.activity+"/profile",
		"", s.cookies["乙"]); own.StatusCode != http.StatusOK {
		t.Errorf("hidden 態下本人投影仍該成功：%d", own.StatusCode)
	}
	// 訪戶成員也走同一條本人通路（參加不是權限）。
	if guest := s.env.request(t, http.MethodGet, "/player/activities/"+s.activity+"/profile",
		"", s.cookies["己"]); guest.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(guest.Body)
		t.Errorf("訪戶的本人投影該成功：%d %s", guest.StatusCode, body)
	}
	// 兩筆管理寫入各留一痕，操作者都是管理員帳戶而不是玩家身份。
	if got := s.env.countMemberAudits(t, "member.directory_visibility_update"); got != 1 {
		t.Errorf("覆蓋寫入留下一筆留痕，實際 %d", got)
	}
	row := s.env.dirAudit(t, "member.directory_visibility_update")
	if row.actorKind != "admin" ||
		!strings.Contains(row.changes, "directory_visibility") ||
		!strings.Contains(row.changes, "inherit") ||
		!strings.Contains(row.changes, "hidden") {
		t.Errorf("覆蓋留痕要帶管理員身份與前後值：%+v", row)
	}
}

// TestMemberDirectoryStaleRequestBehaviour 驗收「拿著舊畫面重發」的兩件事：
// 帶著過期依據值的寫入拿到 2013 而不覆蓋贏家；而純粹的讀取在下一次請求就按新規則回答
// （倉庫裡沒有目錄快取，也沒有推送系統可宣稱——這裡取證的是「下一次請求」這一句）。
func TestMemberDirectoryStaleRequestBehaviour(t *testing.T) {
	s := newDirScene(t)

	// 兩份同依據值的配置寫入：只有先到的那個成功。
	if _, code := s.setMode(t, "same_faction_only", "hidden", s.admin); code != http.StatusOK {
		t.Fatalf("第一次配置應成功：%d", code)
	}
	if _, code := s.setMode(t, "all_members", "hidden", s.admin); code != http.StatusConflict {
		t.Errorf("過期依據值的第二次寫入該撞 2013，實際 %d", code)
	}
	if got := s.currentMode(t); got != "same_faction_only" {
		t.Errorf("落敗的那一筆不得覆蓋贏家，現值 %q", got)
	}
	if got := s.env.countMemberAudits(t, "activity.member_directory_update"); got != 1 {
		t.Errorf("被拒的寫入不追加留痕，實際 %d", got)
	}

	// 讀取侧：同一份請求在規則改變後的下一筆就是新答案。
	firstPage := s.list(t, s.cookies["甲"], "")
	if len(dirNames(t, firstPage)) != 3 {
		t.Fatalf("僅同陣營態下該是紅隊三人，實際 %v", dirNames(t, firstPage))
	}
	// 丙在這一態下看不見甲：直查甲的標識必須不可分辨（舊列表沒有給他這條資訊）。
	if resp := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/members/"+s.member["甲"], "", s.cookies["丙"]); resp.StatusCode !=
		http.StatusNotFound {
		t.Errorf("丙直查甲該是 404：%d", resp.StatusCode)
	}
	s.mustSetMode(t, "all_members")
	secondPage := s.list(t, s.cookies["丙"], "")
	if len(dirNames(t, secondPage)) != 7 {
		t.Errorf("改完模式的下一筆請求該按新規則回答，實際 %v", dirNames(t, secondPage))
	}
	if resp := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/members/"+s.member["甲"], "", s.cookies["丙"]); resp.StatusCode !=
		http.StatusOK {
		t.Errorf("同一個直查在新規則下該點得進：%d", resp.StatusCode)
	}
	// 反向：把某人收起來之後，之前從列表學到的標識立刻查不到（請求級失效，不等推送）。
	if item, code := s.dirSetVisibilityFor(t, s.member["甲"], "hidden", "inherit"); code !=
		http.StatusOK {
		t.Fatalf("收起甲應成功：%d", code)
	} else if item["directory_visibility"] != "hidden" {
		t.Fatalf("回應要回顯新值：%v", item)
	}
	if resp := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/members/"+s.member["甲"], "", s.cookies["丙"]); resp.StatusCode !=
		http.StatusNotFound {
		t.Errorf("被收起來之後同一個直查該不可分辨：%d", resp.StatusCode)
	}
	// 而管理人（持有指派）照樣看得見他：管理視角不看覆蓋。
	if resp := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/members/"+s.member["甲"], "", s.admin); resp.StatusCode !=
		http.StatusOK {
		t.Errorf("管理人該讀得到被收起來的那一行：%d", resp.StatusCode)
	}
}

// dirSetVisibilityFor 送一次覆蓋編輯並回回應的那一行與狀態碼。
func (s *dirScene) dirSetVisibilityFor(t *testing.T, memberID, visibility,
	expected string) (map[string]any, int) {
	t.Helper()
	resp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+s.activity+"/members/"+memberID+"/directory-visibility",
		dirBody(t, map[string]any{"visibility": visibility,
			"expected_visibility": expected}), s.admin)
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	item, _ := decodeJSONBody(t, resp)["member"].(map[string]any)
	return item, resp.StatusCode
}

// dirRequestWithOrigin 送一条帶 Origin 的請求（跨站來源那一格要真的送到服務端才會判）。
func (e *factionEnv) dirRequestWithOrigin(t *testing.T, method, path, body, cookie,
	origin string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("建立請求失敗：%v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	req.Header.Set("Origin", origin)
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s 失敗：%v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// dirAuditRow 是一筆留痕的可觀察形態（操作者類別、標識、目標與 changes 都問資料庫）。
type dirAuditRow struct {
	actorKind string
	actorID   string
	targetID  string
	reason    string
	changes   string
}

// dirAudit 讀回某個動作最新一筆活動域留痕。
func (e *factionEnv) dirAudit(t *testing.T, action string) dirAuditRow {
	t.Helper()
	var row dirAuditRow
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT actor_kind,
			COALESCE(actor_id, ''), COALESCE(target_id, ''), reason, changes_json
		FROM activity_audit WHERE action = ?
		ORDER BY created_at DESC, id DESC LIMIT 1`, action).
		Scan(&row.actorKind, &row.actorID, &row.targetID, &row.reason, &row.changes)
	if err != nil {
		t.Fatalf("讀取留痕 %s 失敗：%v", action, err)
	}
	return row
}

// mustDirectoryItem 讀單筆直查回應裡的 member 那一格。
func mustDirectoryItem(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("直查應成功：%d %s", resp.StatusCode, body)
	}
	item, ok := decodeJSONBody(t, resp)["member"].(map[string]any)
	if !ok {
		t.Fatalf("直查回應必須帶著 member 這一格")
	}
	return item
}

// dirError 是錯誤信封的可斷言形態（碼、訊息與點名的欄位）。
type dirError struct {
	code  int
	msg   string
	field string
}

// dirErrorText 把錯誤回應讀成一份可斷言的結構（非錯誤回應當場失敗，避免斷言寫在 200 上）。
func dirErrorText(t *testing.T, resp *http.Response) dirError {
	t.Helper()
	payload := decodeJSONBody(t, resp)
	value, ok := payload["code"]
	if !ok {
		t.Fatalf("回應要帶著機器碼，實際 %v", payload)
	}
	number, _ := value.(float64)
	message, _ := payload["message"].(string)
	field := ""
	if details, ok := payload["details"].(map[string]any); ok {
		field, _ = details["invalid_field"].(string)
	}
	return dirError{code: int(number), msg: message, field: field}
}

// dirErrorCode 只取機器碼（HTTP 狀態碼另問）。
func dirErrorCode(t *testing.T, resp *http.Response) int {
	t.Helper()
	return dirErrorText(t, resp).code
}

// equalStrings 比較兩個字串集合（先各自排序：目錄的行序由加入時刻決定，
// 而期望清單是用人去寫的，不該要求作者記住 UTF-8 位元組序）。
func equalStrings(got, want []string) bool {
	a, b := dirSorted(got), dirSorted(want)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// dirRowOf 從目錄回應裡取某個暱稱那一行（讀不到當場失敗，不拿零值繼續斷言）。
func dirRowOf(t *testing.T, payload map[string]any, nickname string) map[string]any {
	t.Helper()
	rows, ok := payload["members"].([]any)
	if !ok {
		t.Fatalf("members 必須是清單，實際 %v", payload["members"])
	}
	for _, raw := range rows {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("目錄行必須是物件，實際 %v", raw)
		}
		if item["nickname"] == nickname {
			return item
		}
	}
	t.Fatalf("目錄回應裡讀不到 %q 那一行：%v", nickname, payload)
	return nil
}

// dirFacetOf 從目錄回應裡取某個陣營的篩選候選項（讀不到即失敗）。
func dirFacetOf(t *testing.T, payload map[string]any, factionID string) map[string]any {
	t.Helper()
	facets, _ := payload["facets"].([]any)
	for _, raw := range facets {
		item, _ := raw.(map[string]any)
		if item["faction_id"] == factionID {
			return item
		}
	}
	t.Fatalf("篩選候選讀不到陣營 %s：%v", factionID, payload["facets"])
	return nil
}

// TestMemberDirectoryEndpointFactionAvailability 驗收目錄那一欄派生值在協定層的形態：
// 它恆在（真與假都分得出來，不能與「欄位缺席」同形）、三條讀法同一個答案，
// 而停用不讓任何人從目錄裡消失、也不改任何人的名稱與歸屬——
// 那正是服務層「停用只約束新分配，保留歸屬與歷史」在對外界面上的形狀。
func TestMemberDirectoryEndpointFactionAvailability(t *testing.T) {
	s := newDirScene(t)
	s.mustSetMode(t, "all_members")

	page := s.list(t, s.cookies["甲"], "")
	for _, name := range []string{"甲", "乙", "丙", "己"} {
		if row := dirRowOf(t, page, name); row["faction_available"] != true {
			t.Errorf("%s 的歸屬未停用時該讀到真：%v", name, row)
		}
	}
	// 尚未分組：這一欄是假，而「尚未分組」由空的 faction_id 表達（三種假分得開靠的是另外兩格）。
	if row := dirRowOf(t, page, "丁"); row["faction_available"] != false ||
		row["faction_name"] != "" || row["faction_id"] != "" {
		t.Errorf("無歸屬那行該讀到假且展示值為空：%v", row)
	}

	// 停用紅隊走管理面的陣營編輯白名單：依據值一律取現讀的那一行。
	listResp := s.env.request(t, http.MethodGet,
		"/admin/activities/"+s.activity+"/factions", "", s.admin)
	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("讀陣營清單應成功：%d %s", listResp.StatusCode, body)
	}
	var red map[string]any
	for _, item := range factionList(t, listResp) {
		if item["faction_id"] == s.fac1 {
			red = item
		}
	}
	if red == nil {
		t.Fatalf("清單讀不到紅隊：%v", listResp)
	}
	if _, ok := red["accepts_new_members"]; !ok {
		t.Fatalf("管理面清單該帶著派生的 accepts_new_members：%v", red)
	}
	disableResp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+s.activity+"/factions/"+s.fac1,
		factionEditBody(red, map[string]any{"available": false}), s.admin)
	if disableResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(disableResp.Body)
		t.Fatalf("停用紅隊應成功：%d %s", disableResp.StatusCode, body)
	}

	page = s.list(t, s.cookies["甲"], "")
	for _, name := range []string{"甲", "乙", "己"} {
		row := dirRowOf(t, page, name)
		if row["faction_available"] != false {
			t.Errorf("停用後 %s 該讀到假：%v", name, row)
		}
		if row["faction_name"] != "紅隊" || row["faction_id"] != s.fac1 {
			t.Errorf("停用不改名稱與歸屬（歷史引用保護）：%v", row)
		}
	}
	if row := dirRowOf(t, page, "丙"); row["faction_available"] != true {
		t.Errorf("藍隊那行不該被牽連：%v", row)
	}
	// 計數與候選不跟著改口：紅隊那三個人還在目錄裡。
	if facet := dirFacetOf(t, page, s.fac1); facet["count"].(float64) != 3 {
		t.Errorf("停用不該讓紅隊的候選計數變動：%v", facet)
	}

	detailResp := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/members/"+s.member["乙"], "", s.cookies["甲"])
	if detailResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(detailResp.Body)
		t.Fatalf("停用態的直查仍應成功：%d %s", detailResp.StatusCode, body)
	}
	if item := mustDirectoryItem(t, detailResp); item["faction_available"] != false {
		t.Errorf("單筆詳情要與列表同一個答案：%v", item)
	}
	ownResp := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/profile", "", s.cookies["乙"])
	if ownResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(ownResp.Body)
		t.Fatalf("本人投影應成功：%d %s", ownResp.StatusCode, body)
	}
	if view := decodeJSONBody(t, ownResp); view["faction_available"] != false {
		t.Errorf("本人讀法也要讀到自己歸屬的停用現值：%v", view)
	}

	// 收回目錄：列表照樣是空的一頁，而本人通路仍讀得到那一欄（兩句不是同一件事）。
	s.mustSetMode(t, "hidden")
	hidden := s.list(t, s.cookies["甲"], "")
	if rows, _ := hidden["members"].([]any); len(rows) != 0 {
		t.Errorf("hidden 態該是空的一頁，實際 %v", rows)
	}
	if _, ok := hidden["faction_available"]; ok {
		t.Errorf("這一格只在行上，不在回應頂層：%v", hidden)
	}
	after := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/profile", "", s.cookies["乙"])
	if view := decodeJSONBody(t, after); view["faction_available"] != false ||
		view["member_directory_mode"] != "hidden" {
		t.Errorf("目錄收起時本人仍該讀到停用現值與 hidden 模式：%v", view)
	}
}
