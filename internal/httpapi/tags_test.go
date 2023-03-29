// tags_test.go 是「活動標籤定義與公開範圍」在傳輸層的端到端證據：新建的標籤一出生就是
// 內部資訊、公開是一枚一枚翻開的、管理側列表與寫回的本體白名單（含「順手宣稱 public／
// accepts_new_assignments／activity_id／時刻欄位」）、跨活動讀改的不可分辨、同活動重名
// 與跨活動同名的兩副面孔、停止／歸檔兩道寫入門禁各有各的碼、併發編輯落敗那一句、
// 玩家那一族只讀公開定義（直查內部與幽靈逐字同文）、收回公開後下一筆請求就讀不到、
// 翻公開不改動目錄的可見集合，以及改名不換標識。
//
// 刻意不收的東西：
//   - 沒有替身：授權、活動作用域、業務門禁、重名核實、公開篩選、CAS 與審計都跨層走真路徑；
//   - 不測「把標籤貼在玩家身上」：貼標尚未落地，這一族端點裡沒有一格能填「誰貼哪個標籤」，
//     也不拿空清單冒充「他沒有標籤」；
//   - 不重複 internal/activity 的服務層矩陣：那一側已取證的結論，這裡只問協定形態；
//   - 不碰真實數據目錄、不佔 5206，全程本次專屬的臨時庫與注入時鐘。
package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// 本檔使用的幽靈標識：合法形狀但從未存在（不可分辨性要比對它）。
const (
	tagGhostActivityID = "0192f0c4-1c9a-7000-8000-000000000fe1"
	tagGhostTagID      = "0192f0c4-1c9a-7000-8000-000000000fe2"
)

// tagScene 是本檔共用的輕量現場：一場已開放的活動、一位獲指派的管理人、一位場內玩家，
// 另有一場由「外人管理人」管的活動（跨活動與作用域的反證需要它）。
//
// 它刻意比目錄那檔的現場小很多：標籤的斷言問的是定義與公開旗標，不需要七行成員與兩個陣營，
// 而每多一位需要登入與首次改密的帳戶，現場成本都是實打實的口令派生。唯一需要多位玩家的那一組
// （目錄的可見集合不受公開旗標影響）自己在測試內補人。
type tagScene struct {
	env      *factionEnv
	admin    string // 本場管理人的會話標頭
	outsider string // 另一場的管理人（對本場而言只是普通玩家那一類）
	activity string
	other    string
	player   string // 場內玩家的會話標頭
}

// newTagScene 佈好輕量現場：兩場都已開放的活動、兩位管理人與一位場內玩家。
func newTagScene(t *testing.T) *tagScene {
	t.Helper()
	e := newFactionEnv(t)
	s := &tagScene{env: e}
	_, s.admin = e.dirAdminWithSession(t, "tag.admin")
	_, s.outsider = e.dirAdminWithSession(t, "tag.outsider")
	s.activity = e.createFactionActivity(t, s.admin, "有標籤的場")
	s.other = e.createFactionActivity(t, s.outsider, "外人管的場")
	accountID, cookie := e.selfSelectPlayer(t, s.admin, "tag.jia")
	e.selfAddMember(t, s.admin, s.activity, accountID, "甲")
	s.player = cookie
	return s
}

// tagAdminPath 是管理側那一族的集合路徑（列表與建立）。
func tagAdminPath(activityID string) string {
	return "/admin/activities/" + activityID + "/tags"
}

// tagAdminItemPath 是管理側那一族的單筆路徑（編輯）。
func tagAdminItemPath(activityID, tagID string) string {
	return tagAdminPath(activityID) + "/" + tagID
}

// tagPlayerPath 是玩家那一族的公開清單路徑。
func tagPlayerPath(activityID string) string {
	return "/player/activities/" + activityID + "/tags"
}

// tagPlayerItemPath 是玩家那一族的單筆直查路徑。
func tagPlayerItemPath(activityID, tagID string) string {
	return tagPlayerPath(activityID) + "/" + tagID
}

// mustCreateTag 由本場管理人建立一枚標籤並回讀那一格（非 201 當場失敗）。
func (s *tagScene) mustCreateTag(t *testing.T, name string) map[string]any {
	t.Helper()
	return s.mustCreateTagIn(t, s.activity, s.admin, name)
}

// mustCreateTagIn 在指定活動裡以指定會話建立一枚標籤。
func (s *tagScene) mustCreateTagIn(t *testing.T, activityID, who, name string) map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodPost, tagAdminPath(activityID),
		dirBody(t, map[string]any{"name": name, "description": "", "icon": "", "color": ""}), who)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("建立標籤 %q 應成功：%d %s", name, resp.StatusCode, body)
	}
	item, ok := decodeJSONBody(t, resp)["tag"].(map[string]any)
	if !ok {
		t.Fatalf("建立回應要帶著 tag 這一格")
	}
	return item
}

// tagUpdateBody 以「服務端讀回的那一行」為依據值湊一份編輯本體，overrides 決定要改哪幾欄。
//
// 依據值一律從那一行現值長出來而不是硬編：這一檔每次寫入問的都是真實的 CAS 那句話，
// 而「拿著舊畫面重發」那種形態另有專門的測試去問。
func tagUpdateBody(t *testing.T, item map[string]any, overrides map[string]any) string {
	t.Helper()
	body := map[string]any{
		"name": item["name"], "description": item["description"], "icon": item["icon"],
		"color": item["color"], "sort_order": item["sort_order"],
		"available": item["available"], "public": item["public"],
		"expected_name": item["name"], "expected_description": item["description"],
		"expected_icon": item["icon"], "expected_color": item["color"],
		"expected_sort_order": item["sort_order"], "expected_available": item["available"],
		"expected_public": item["public"],
	}
	for key, value := range overrides {
		body[key] = value
	}
	return dirBody(t, body)
}

// mustUpdateTag 送一次必須成功的編輯並回讀 tag 那一格。
func (s *tagScene) mustUpdateTag(t *testing.T, item map[string]any,
	overrides map[string]any) map[string]any {
	t.Helper()
	return s.mustUpdateTagIn(t, s.activity, s.admin, item, overrides)
}

// mustUpdateTagIn 在指定活動裡以指定會話送一次必須成功的編輯。
func (s *tagScene) mustUpdateTagIn(t *testing.T, activityID, who string,
	item map[string]any, overrides map[string]any) map[string]any {
	t.Helper()
	tagID, _ := item["tag_id"].(string)
	resp := s.env.request(t, http.MethodPut, tagAdminItemPath(activityID, tagID),
		tagUpdateBody(t, item, overrides), who)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("編輯標籤 %s 應成功：%d %s", tagID, resp.StatusCode, body)
	}
	updated, ok := decodeJSONBody(t, resp)["tag"].(map[string]any)
	if !ok {
		t.Fatalf("編輯回應要帶著 tag 這一格")
	}
	return updated
}

// adminTags 讀管理側列表（非 200 當場失敗）。
func (s *tagScene) adminTags(t *testing.T, who, activityID string) []map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodGet, tagAdminPath(activityID), "", who)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("管理側列表應成功：%d %s", resp.StatusCode, body)
	}
	return tagRowsOf(t, decodeJSONBody(t, resp)["tags"])
}

// playerTags 讀玩家那一族的公開清單（非 200 當場失敗）。
func (s *tagScene) playerTags(t *testing.T, who, activityID string) []map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodGet, tagPlayerPath(activityID), "", who)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("玩家側公開清單應成功：%d %s", resp.StatusCode, body)
	}
	return tagRowsOf(t, decodeJSONBody(t, resp)["tags"])
}

// tagRowsOf 把回應裡的 tags 那一格換成逐行可斷言的清單。
func tagRowsOf(t *testing.T, raw any) []map[string]any {
	t.Helper()
	rows, ok := raw.([]any)
	if !ok {
		t.Fatalf("tags 必須是清單，實際 %v", raw)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, entry := range rows {
		item, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("標籤行必須是物件，實際 %v", entry)
		}
		out = append(out, item)
	}
	return out
}

// tagNames 取清單裡每一行的名稱（斷言不依賴行序：次序由後端的排序算式決定）。
func tagNames(rows []map[string]any) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		name, _ := row["name"].(string)
		out = append(out, name)
	}
	return out
}

// mustTagField 讀一格，缺席當場失敗（旗標與派生欄恆在回應是合同的一部分）。
func mustTagField(t *testing.T, item map[string]any, field string) any {
	t.Helper()
	value, ok := item[field]
	if !ok {
		t.Fatalf("%q 這一格必須在回應裡，實際 %v", field, item)
	}
	return value
}

// mustTagBool 讀一格的布林現值。
func mustTagBool(t *testing.T, item map[string]any, field string) bool {
	t.Helper()
	value, ok := mustTagField(t, item, field).(bool)
	if !ok {
		t.Fatalf("%q 該是布林，實際 %T", field, item[field])
	}
	return value
}

// addPlayer 在本場補一位自己登入的玩家並回傳他的會話標頭。
func (s *tagScene) addPlayer(t *testing.T, login, nickname string) string {
	t.Helper()
	accountID, cookie := s.env.selfSelectPlayer(t, s.admin, login)
	s.env.selfAddMember(t, s.admin, s.activity, accountID, nickname)
	return cookie
}

// setDirectoryMode 走真實管理通路換一場活動的目錄模式（依據值取服務端讀回的現值）。
func (s *tagScene) setDirectoryMode(t *testing.T, activityID, mode string) {
	t.Helper()
	detail := s.env.request(t, http.MethodGet, "/admin/activities/"+activityID, "", s.admin)
	if detail.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(detail.Body)
		t.Fatalf("讀活動詳情應成功：%s", body)
	}
	item := mustActivityItem(t, detail)
	current, _ := item["member_directory_mode"].(string)
	if current == "" {
		t.Fatalf("活動詳情必須帶著 member_directory_mode，實際 %v", item)
	}
	resp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+activityID+"/member-directory",
		dirBody(t, map[string]any{"mode": mode, "expected_mode": current}), s.admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("設定目錄模式 %q 應成功：%d %s", mode, resp.StatusCode, body)
	}
}

// directoryPage 讀玩家那一族的目錄一頁（回應本體；非 200 當場失敗）。
func (s *tagScene) directoryPage(t *testing.T, who, activityID string) map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodGet,
		"/player/activities/"+activityID+"/members"+dirQuery(1, 50), "", who)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("目錄一讀應成功：%d %s", resp.StatusCode, body)
	}
	return decodeJSONBody(t, resp)
}

// tagAudit 讀回某個動作最新一筆活動域留痕（操作者、目標、原因與 changes）。
func (e *factionEnv) tagAudit(t *testing.T, action string) dirAuditRow {
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

// tagAuditCount 數某個動作的留痕筆數（被拒的寫入不該留下一筆）。
func (e *factionEnv) tagAuditCount(t *testing.T, action string) int {
	t.Helper()
	var count int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM activity_audit WHERE action = ?", action).Scan(&count); err != nil {
		t.Fatalf("數留痕 %s 失敗：%v", action, err)
	}
	return count
}

// TestTagCreateIsInternalAtTransport 驗收：新建的標籤一出生就是內部資訊、可用，
// 派生那一格也如實說是「此刻貼得出去」；管理側列表讀得到它，玩家那一族讀不到。
func TestTagCreateIsInternalAtTransport(t *testing.T) {
	s := newTagScene(t)
	created := s.mustCreateTag(t, "內部備註")
	if mustTagBool(t, created, "public") {
		t.Error("新建的標籤不該一出生就對外（預設要明確翻那一欄才公開）")
	}
	if !mustTagBool(t, created, "available") {
		t.Error("新建的標籤該一出生即可用")
	}
	if !mustTagBool(t, created, "accepts_new_assignments") {
		t.Error("可用且活動正在開放：派生那一格該是真")
	}
	if got, _ := created["activity_id"].(string); got != s.activity {
		t.Errorf("標識與歸屬由服務端決定，activity_id 該是 %s，實際 %q", s.activity, got)
	}
	// 每一格該在的都在（含兩個時刻與排序值）：這是一行定義的完整事實，不是猜出來的。
	for _, field := range []string{"tag_id", "name", "description", "icon", "color",
		"sort_order", "created_at", "updated_at"} {
		mustTagField(t, created, field)
	}

	rows := s.adminTags(t, s.admin, s.activity)
	if len(rows) != 1 || tagNames(rows)[0] != "內部備註" {
		t.Fatalf("管理側列表該讀到那一枚，實際 %v", tagNames(rows))
	}
	if got := s.playerTags(t, s.player, s.activity); len(got) != 0 {
		t.Errorf("未公開的定義不該出現在玩家那一族的清單裡，實際 %v", tagNames(got))
	}
	detail := s.env.request(t, http.MethodGet,
		tagPlayerItemPath(s.activity, created["tag_id"].(string)), "", s.player)
	ghost := s.env.request(t, http.MethodGet, tagPlayerItemPath(s.activity, tagGhostTagID), "", s.player)
	if detail.StatusCode != http.StatusNotFound || ghost.StatusCode != http.StatusNotFound {
		t.Fatalf("直查內部定義與直查幽靈都該 404，實際 %d／%d", detail.StatusCode, ghost.StatusCode)
	}
	got, want := dirErrorText(t, detail), dirErrorText(t, ghost)
	if got.code != want.code || got.msg != want.msg {
		t.Errorf("兩句必須逐字同形（不能讓玩家路徑變成內部定義的存在性探測器）：\n%+v\n%+v", got, want)
	}
	// 同一枚定義在管理側讀得到、在玩家那一族無處可讀：兩份 DTO、兩道閘。
	if mustTagBool(t, s.adminTags(t, s.admin, s.activity)[0], "public") {
		t.Error("管理側讀到的該如實帶著「這枚沒公開」這件事")
	}
}

// TestTagPublicFlagIsPerTagAtTransport 驗收：翻公開走那條七欄白名單編輯，一次只動一枚；
// 玩家那一族的清單與直查立刻按新狀態投影，而且投影本身不帶任何內部欄位。
func TestTagPublicFlagIsPerTagAtTransport(t *testing.T) {
	s := newTagScene(t)
	one := s.mustCreateTag(t, "對外稱號")
	other := s.mustCreateTag(t, "留內部的")

	published := s.mustUpdateTag(t, one, map[string]any{"public": true})
	if !mustTagBool(t, published, "public") {
		t.Fatal("回應要如實回顯新的公開旗標")
	}
	if published["tag_id"] != one["tag_id"] {
		t.Error("翻公開不該換掉標識")
	}

	rows := s.playerTags(t, s.player, s.activity)
	if len(rows) != 1 || tagNames(rows)[0] != "對外稱號" {
		t.Fatalf("翻公開後下一筆請求就該讀到它，實際 %v", tagNames(rows))
	}
	// 玩家那一族的白名單：內部可用性、公開旗標本身、歸屬活動與兩個時刻都不在這一份投影裡，
	// 也不在回應裡以「假的 false」佔位（那是把沒做的事唸成一句話）。
	for _, forbidden := range []string{"available", "public", "accepts_new_assignments",
		"activity_id", "created_at", "updated_at", "member_count", "account_id", "nickname"} {
		if _, ok := rows[0][forbidden]; ok {
			t.Errorf("玩家投影不該帶出 %q 這一格：%v", forbidden, rows[0])
		}
	}
	for _, required := range []string{"tag_id", "name", "description", "icon", "color",
		"sort_order"} {
		mustTagField(t, rows[0], required)
	}

	// 另一枚仍是內部：公開是一枚一枚決定的，沒有「整場活動一起翻」那種通路。
	for _, row := range s.adminTags(t, s.admin, s.activity) {
		want := row["name"] == "對外稱號"
		if got := mustTagBool(t, row, "public"); got != want {
			t.Errorf("%q 的公開旗標該是 %v，實際 %v", row["name"], want, got)
		}
	}
	if got := s.playerTags(t, s.player, s.activity); len(got) != 1 ||
		got[0]["tag_id"] == other["tag_id"] {
		t.Errorf("未翻開的那一枚不該被順手公開，實際 %v", tagNames(got))
	}

	// 收回公開：下一筆清單與直查都讀不到，且與幽靈逐字同文（今日沒有快取層可失效）。
	s.mustUpdateTag(t, published, map[string]any{"public": false})
	if got := s.playerTags(t, s.player, s.activity); len(got) != 0 {
		t.Errorf("收回公開後下一筆請求該讀不到它，實際 %v", tagNames(got))
	}
	reverted := s.env.request(t, http.MethodGet,
		tagPlayerItemPath(s.activity, one["tag_id"].(string)), "", s.player)
	ghost := s.env.request(t, http.MethodGet, tagPlayerItemPath(s.activity, tagGhostTagID), "", s.player)
	if a, b := dirErrorText(t, reverted), dirErrorText(t, ghost); a.code != b.code || a.msg != b.msg {
		t.Errorf("收回後的直查該與幽靈同文：\n%+v\n%+v", a, b)
	}
	if got := s.adminTags(t, s.admin, s.activity); len(got) != 2 {
		t.Errorf("收回公開不刪行，管理側該照樣讀到兩枚，實際 %d", len(got))
	}
}

// TestTagAccessMatrixAtTransport 驗收這一族四條路徑各自的准入：普通玩家敲不進管理面，
// 未獲指派的管理人與 Root 與「從沒這場活動」同形，匿名一律 2002，而玩家那一族只吃本人成員行。
func TestTagAccessMatrixAtTransport(t *testing.T) {
	s := newTagScene(t)
	created := s.mustCreateTag(t, "准入取證的")
	s.mustUpdateTag(t, created, map[string]any{"public": true})
	root := cookieHeader(s.env.factionRootCookie(t))

	// 普通玩家讀管理側列表與兩條寫入：一律 2011（不屬於管理員這個身份面）。
	for _, tc := range []struct {
		method, path string
		body         string
	}{
		{http.MethodGet, tagAdminPath(s.activity), ""},
		{http.MethodPost, tagAdminPath(s.activity), dirBody(t, map[string]any{"name": "玩家想建的"})},
		{http.MethodPut, tagAdminItemPath(s.activity, created["tag_id"].(string)),
			tagUpdateBody(t, created, map[string]any{"public": false})},
	} {
		resp := s.env.request(t, tc.method, tc.path, tc.body, s.player)
		if got := dirErrorCode(t, resp); got != 2011 {
			t.Errorf("%s %s 該拿 2011，實際 %d", tc.method, tc.path, got)
		}
	}

	// 未獲指派的管理人（他管的是另一場）：持有授予也不該看到別人管的活動，收斂成 1001。
	outsiderList := s.env.request(t, http.MethodGet, tagAdminPath(s.activity), "", s.outsider)
	if got := dirErrorCode(t, outsiderList); got != 1001 {
		t.Errorf("外人管理人讀本場列表該拿 1001，實際 %d", got)
	}
	// 他對自己那場完全走得通：這一格拒絕讲的是作用域，不是他把請求寫壞了。
	if got := len(s.adminTags(t, s.outsider, s.other)); got != 0 {
		t.Errorf("外人那場現在該是空的，實際 %d", got)
	}
	otherTag := s.mustCreateTagIn(t, s.other, s.outsider, "外人那場的標籤")
	if got := len(s.adminTags(t, s.outsider, s.other)); got != 1 {
		t.Errorf("外人讀自己那場該讀到一行，實際 %d", got)
	}

	// Root 在玩家那一族沒有可指向的成員行：與查無這個活動同文（不是「Root 比較大所以看得到」）。
	rootCatalog := s.env.request(t, http.MethodGet, tagPlayerPath(s.activity), "", root)
	ghostCatalog := s.env.request(t, http.MethodGet, tagPlayerPath(tagGhostActivityID), "", s.player)
	if rootCatalog.StatusCode != http.StatusNotFound || ghostCatalog.StatusCode != http.StatusNotFound {
		t.Fatalf("Root 與幽靈活動都該 404，實際 %d／%d",
			rootCatalog.StatusCode, ghostCatalog.StatusCode)
	}
	if a, b := dirErrorText(t, rootCatalog), dirErrorText(t, ghostCatalog); a.msg != b.msg {
		t.Errorf("兩句必須逐字同文：\n%+v\n%+v", a, b)
	}
	// 場內玩家讀這一族是 200：擋下別人的不是「玩家這個身分」，而是「沒有這一行成員」。
	if got := s.playerTags(t, s.player, s.activity); len(got) != 1 {
		t.Errorf("場內玩家該讀到那一枚公開定義，實際 %v", tagNames(got))
	}
	// 場內玩家敲另一場的公開目錄：他在那場沒有成員行，答案與幽靈同文；
	// 另一場那枚定義即使被它的管理人翻開公開，也不因此對甲場的玩家可读（跨活動隔離）。
	otherCatalog := s.env.request(t, http.MethodGet, tagPlayerPath(s.other), "", s.player)
	ghostItem := s.env.request(t, http.MethodGet,
		tagPlayerItemPath(s.activity, tagGhostTagID), "", s.player)
	if a, b := dirErrorText(t, otherCatalog), dirErrorText(t, ghostItem); a.code != 1001 ||
		b.code != 1001 || a.msg != b.msg {
		t.Errorf("非成員與幽靈都該收斂成同文 1001：\n%+v\n%+v", a, b)
	}
	crossItem := s.env.request(t, http.MethodGet,
		tagPlayerItemPath(s.other, otherTag["tag_id"].(string)), "", s.player)
	if got := dirErrorText(t, crossItem); got.code != 1001 {
		t.Errorf("拿別人那場的標識到玩家這一族該拿不可分辨那一句，實際 %d", got.code)
	}

	// 匿名：兩族都是 2002（尚未取得主體，不給任何存在性信號）。
	for _, path := range []string{tagAdminPath(s.activity), tagPlayerPath(s.activity)} {
		resp := s.env.request(t, http.MethodGet, path, "", "")
		if got := dirErrorCode(t, resp); got != 2002 {
			t.Errorf("匿名敲 %s 該拿 2002，實際 %d", path, got)
		}
	}

	// 跨站來源：寫入一律 2005（Cookie 會話的 CSRF 邊界，與其餘寫入通路同一句）。
	crossOrigin := s.env.dirRequestWithOrigin(t, http.MethodPost, tagAdminPath(s.activity),
		dirBody(t, map[string]any{"name": "跨站來的", "description": "", "icon": "", "color": ""}),
		s.admin, "http://console.invalid")
	if got := dirErrorCode(t, crossOrigin); got != 2005 {
		t.Errorf("跨站來源的寫入該拿 2005，實際 %d", got)
	}
}

// TestTagNameAndCrossActivityRules 驗收：同活動內重名拿本步新發的 2040，跨活動同名完全合法，
// 而拿甲場的標識去敲乙場一律收斂成 1001 且與幽靈同文。
func TestTagNameAndCrossActivityRules(t *testing.T) {
	s := newTagScene(t)
	first := s.mustCreateTag(t, "冠軍")

	dup := s.env.request(t, http.MethodPost, tagAdminPath(s.activity),
		dirBody(t, map[string]any{"name": "冠軍", "description": "", "icon": "", "color": ""}),
		s.admin)
	if got := dirErrorCode(t, dup); got != 2040 {
		t.Errorf("同活動重名該拿 2040，實際 %d", got)
	}
	if got := len(s.adminTags(t, s.admin, s.activity)); got != 1 {
		t.Errorf("撞名的那一次該整筆不落地，列表該有 1 枚，實際 %d", got)
	}

	// 跨活動同名：完全合法（另一場由那位外人管理人自己建）。
	otherTag := s.mustCreateTagIn(t, s.other, s.outsider, "冠軍")

	// 拿甲場的標識去敲乙場，與拿一枚從未存在的標識去敲：同一句話。
	onOther := s.env.request(t, http.MethodPut, tagAdminItemPath(s.other, first["tag_id"].(string)),
		tagUpdateBody(t, first, map[string]any{"name": "挪個場試試"}), s.outsider)
	onGhost := s.env.request(t, http.MethodPut, tagAdminItemPath(s.other, tagGhostTagID),
		tagUpdateBody(t, first, map[string]any{"name": "湊不上任何東西"}), s.outsider)
	if a, b := dirErrorText(t, onOther), dirErrorText(t, onGhost); a.code != 1001 ||
		b.code != 1001 || a.msg != b.msg {
		t.Errorf("跨活動與幽靈都該收斂成同文 1001：\n%+v\n%+v", a, b)
	}

	// 乙場那枚翻開公開之後，到甲場這一側直查仍與幽靈同文：標識不跨活動生效。
	publishedOther := s.mustUpdateTagIn(t, s.other, s.outsider, otherTag,
		map[string]any{"public": true})
	crossDetail := s.env.request(t, http.MethodGet,
		tagPlayerItemPath(s.activity, publishedOther["tag_id"].(string)), "", s.player)
	ghostDetail := s.env.request(t, http.MethodGet,
		tagPlayerItemPath(s.activity, tagGhostTagID), "", s.player)
	if a, b := dirErrorText(t, crossDetail), dirErrorText(t, ghostDetail); a.code != 1001 ||
		b.code != 1001 || a.msg != b.msg {
		t.Errorf("跨活動的直查不該成為第二枚信號：\n%+v\n%+v", a, b)
	}
	if got := tagNames(s.playerTags(t, s.player, s.activity)); len(got) != 0 {
		t.Errorf("乙場的定義不該出現在甲場玩家的清單裡，實際 %v", got)
	}
	// 兩場各讀各的：乙場的玩家沒有，外場的管理人讀到自己那一枚且帶著公開現值。
	outsiderRows := s.adminTags(t, s.outsider, s.other)
	if len(outsiderRows) != 1 || !mustTagBool(t, outsiderRows[0], "public") {
		t.Errorf("乙場的管理人該讀到自己那枚且現值是公開，實際 %v", outsiderRows)
	}
}

// TestTagPublicDoesNotChangeDirectoryVisibility 驗收這一步最容易被讀錯的那一句：
// 翻公開只讓「這份定義」讀得到，它不放大目錄的可見集合、不讓任何人多得到一項能力。
func TestTagPublicDoesNotChangeDirectoryVisibility(t *testing.T) {
	s := newTagScene(t)
	// 補三位玩家：目錄的「可見集合」要有東西可比，一個人比不出「少了一行」。
	s.addPlayer(t, "tag.yi", "乙")
	s.addPlayer(t, "tag.bing", "丙")
	s.addPlayer(t, "tag.ding", "丁")
	tag := s.mustCreateTag(t, "對外稱號")

	s.setDirectoryMode(t, s.activity, "all_members")
	before := s.directoryPage(t, s.player, s.activity)
	totalBefore, _ := before["total"].(float64)
	if totalBefore < 4 {
		t.Fatalf("現場該有四位以上玩家，實際 total=%v 表示佈資料沒生效", totalBefore)
	}

	s.mustUpdateTag(t, tag, map[string]any{"public": true})
	after := s.directoryPage(t, s.player, s.activity)
	totalAfter, _ := after["total"].(float64)
	if totalAfter != totalBefore {
		t.Errorf("翻公開一欄不該改變目錄的可見人數（%v→%v）", totalBefore, totalAfter)
	}
	if !equalStrings(dirNames(t, before), dirNames(t, after)) {
		t.Errorf("翻公開前後目錄該是同一群人：%v vs %v", dirNames(t, before), dirNames(t, after))
	}
	// 目錄那一行也不會因為「有標籤可用」就多長出任何格子：今日沒有貼標，也沒有拿空值
	// 冒充的標籤欄（把未落地的事寫成一個假值，界面就會把它念成事實）。
	for _, row := range tagRowsOf(t, after["members"]) {
		for _, forbidden := range []string{"tags", "tag_id", "tag_name", "public"} {
			if _, ok := row[forbidden]; ok {
				t.Errorf("目錄行不該出現尚未落地的標籤欄 %q：%v", forbidden, row)
			}
		}
	}

	// 目錄收成 hidden：一個人都看不見，而一枚公開標籤照樣讀得到——標籤不是可見性開關，
	// 可見性也不是標籤的讀取條件（兩件事各有各的閘，用戶批准於本步）。
	s.setDirectoryMode(t, s.activity, "hidden")
	hidden := s.directoryPage(t, s.player, s.activity)
	if got, _ := hidden["total"].(float64); got != 0 {
		t.Errorf("hidden 態目錄該是空的一頁，實際 total=%v", got)
	}
	if len(dirNames(t, hidden)) != 0 {
		t.Errorf("hidden 態不該列出任何人，實際 %v", dirNames(t, hidden))
	}
	if got := s.playerTags(t, s.player, s.activity); len(got) != 1 {
		t.Errorf("目錄收起來不該讓公開定義一起讀不到（標籤不是目錄的一部分）：%v", tagNames(got))
	}

	// 反方向也要成句：收回公開之後目錄的答案一個字都不動（今日兩側互不影響）。
	revoked := s.adminTags(t, s.admin, s.activity)[0]
	s.mustUpdateTag(t, revoked, map[string]any{"public": false})
	afterRevoke := s.directoryPage(t, s.player, s.activity)
	if total, _ := afterRevoke["total"].(float64); total != 0 {
		t.Errorf("收回公開不該把目錄打開：hidden 態照樣一個都不列，實際 total=%v", total)
	}
}

// TestTagLifecycleAndBodyWhitelists 驗收兩道寫入門禁各有各的碼、本體白名單的每一處注入
// 都在協定層被 1004 點名，而派生那一格不是可寫資料。
func TestTagLifecycleAndBodyWhitelists(t *testing.T) {
	s := newTagScene(t)
	tag := s.mustCreateTag(t, "要過生命週期的")

	// 順手宣稱的每一格都沒有可以填的地方：id／歸屬／時刻／派生值，甚至建立時宣稱公開。
	injections := []struct {
		what string
		body map[string]any
	}{
		{"建立時宣稱公開", map[string]any{"name": "注入一", "description": "", "icon": "",
			"color": "", "public": true}},
		{"建立時代填標識", map[string]any{"name": "注入二", "description": "", "icon": "",
			"color": "", "tag_id": tagGhostTagID}},
		{"建立時代填歸屬", map[string]any{"name": "注入三", "description": "", "icon": "",
			"color": "", "activity_id": s.other}},
		{"建立時順手宣稱派生值", map[string]any{"name": "注入四", "description": "", "icon": "",
			"color": "", "accepts_new_assignments": true}},
	}
	for _, tc := range injections {
		resp := s.env.request(t, http.MethodPost, tagAdminPath(s.activity), dirBody(t, tc.body), s.admin)
		if got := dirErrorCode(t, resp); got != 1004 {
			t.Errorf("%s 該被 1004 擋下，實際 %d", tc.what, got)
		}
	}
	extraEdit := decodeJSONMap(t, tagUpdateBody(t, tag, nil))
	extraEdit["created_at"] = "2020-01-01T00:00:00Z"
	stamped := s.env.request(t, http.MethodPut, tagAdminItemPath(s.activity, tag["tag_id"].(string)),
		dirBody(t, extraEdit), s.admin)
	if got := dirErrorCode(t, stamped); got != 1004 {
		t.Errorf("編輯時順手改建立時刻該被 1004 擋下，實際 %d", got)
	}
	if got := len(s.adminTags(t, s.admin, s.activity)); got != 1 {
		t.Errorf("被擋下的注入一筆都不該落地，列表該有 1 枚，實際 %d", got)
	}

	// 每一欄的非法寫法各有各的點名。
	for _, tc := range []struct {
		what      string
		field     string
		overrides map[string]any
	}{
		{"缺井的顏色", "color", map[string]any{"color": "ff0000"}},
		{"集合外的圖標", "icon", map[string]any{"icon": "dragon"}},
		{"負的排序值", "sort_order", map[string]any{"sort_order": -1}},
		{"超長名稱", "name", map[string]any{"name": strings.Repeat("長", 65)}},
	} {
		resp := s.env.request(t, http.MethodPut, tagAdminItemPath(s.activity, tag["tag_id"].(string)),
			tagUpdateBody(t, tag, tc.overrides), s.admin)
		got := dirErrorText(t, resp)
		if got.code != 1004 || got.field != tc.field {
			t.Errorf("%s 該被 1004 點名 %s，實際 %d／%q", tc.what, tc.field, got.code, got.field)
		}
	}

	// 停止態：業務寫入一律 2033，而兩族的讀法都不受門禁約束。
	if resp := s.env.request(t, http.MethodPut, "/admin/activities/"+s.activity+"/status",
		dirBody(t, map[string]any{"status": "closed"}), s.admin); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("停止活動應成功：%s", body)
	}
	closedCreate := s.env.request(t, http.MethodPost, tagAdminPath(s.activity),
		dirBody(t, map[string]any{"name": "停止後建的", "description": "", "icon": "", "color": ""}),
		s.admin)
	if got := dirErrorCode(t, closedCreate); got != 2033 {
		t.Errorf("停止態的建立該拿 2033，實際 %d", got)
	}
	closedEdit := s.env.request(t, http.MethodPut, tagAdminItemPath(s.activity, tag["tag_id"].(string)),
		tagUpdateBody(t, tag, map[string]any{"public": true}), s.admin)
	if got := dirErrorCode(t, closedEdit); got != 2033 {
		t.Errorf("停止態翻公開該拿 2033，實際 %d", got)
	}
	current := s.adminTags(t, s.admin, s.activity)[0]
	if mustTagBool(t, current, "accepts_new_assignments") {
		t.Error("停止態裡連還開著的標籤也貼不出去：派生那一格該轉假")
	}
	if got := s.playerTags(t, s.player, s.activity); len(got) != 0 {
		t.Errorf("停止態不該把沒公開的定義放進玩家清單，實際 %v", tagNames(got))
	}

	// 歸檔是終態：這一句與 2033 分開，處置也不同（「等重開」對終態不成立）。
	if resp := s.env.request(t, http.MethodPut, "/admin/activities/"+s.activity+"/status",
		dirBody(t, map[string]any{"status": "archived"}), s.admin); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("歸檔活動應成功：%s", body)
	}
	archived := s.env.request(t, http.MethodPut, tagAdminItemPath(s.activity, tag["tag_id"].(string)),
		tagUpdateBody(t, tag, map[string]any{"public": true}), s.admin)
	if got := dirErrorCode(t, archived); got != 2029 {
		t.Errorf("歸檔態的寫入該拿 2029，實際 %d", got)
	}
	// 兩族讀法都不受終態約束：仍列、可讀，拒的是寫。
	if got := len(s.adminTags(t, s.admin, s.activity)); got != 1 {
		t.Errorf("歸檔後管理側照樣讀得到那一行，實際 %d", got)
	}
	if got := s.playerTags(t, s.player, s.activity); len(got) != 0 {
		t.Errorf("歸檔不該順手把定義放進玩家清單，實際 %v", tagNames(got))
	}
}

// TestTagStaleEditAndNoDeletePath 驗收：併發編輯裡落敗那一份撞 2013 且一個字都不落、
// 也不追加留痕；而這一族沒有刪除通路（405 的 Allow 也不虛報 DELETE）。
func TestTagStaleEditAndNoDeletePath(t *testing.T) {
	s := newTagScene(t)
	tag := s.mustCreateTag(t, "被搶先的那枚")
	auditsBefore := s.env.tagAuditCount(t, "tag.update")

	// 兩份都以同一份現值為依據：先落的贏，後到的撞牆。
	winning := map[string]any{"name": "贏家改的", "public": true}
	if got := s.mustUpdateTag(t, tag, winning); got["name"] != "贏家改的" {
		t.Fatalf("贏家那一份該落地，實際 %v", got["name"])
	}
	stale := s.env.request(t, http.MethodPut, tagAdminItemPath(s.activity, tag["tag_id"].(string)),
		tagUpdateBody(t, tag, winning), s.admin)
	got := dirErrorText(t, stale)
	if got.code != 2013 {
		t.Errorf("過期依據值該拿 2013，實際 %d", got.code)
	}
	current := s.adminTags(t, s.admin, s.activity)[0]
	if current["name"] != "贏家改的" || !mustTagBool(t, current, "public") {
		t.Errorf("落敗的那一份不該覆蓋贏家：實際 %v／%v", current["name"], current["public"])
	}
	if after := s.env.tagAuditCount(t, "tag.update"); after != auditsBefore+1 {
		t.Errorf("留痕筆數該等於實際提交數（%d→%d，本該 +1）", auditsBefore, after)
	}

	// 這一族沒有刪除：停用是唯一能表達「不想再被使用」的地方（用戶批准於本步）。
	notAllowed := s.env.request(t, http.MethodGet, tagAdminItemPath(s.activity, tag["tag_id"].(string)),
		"", s.admin)
	if notAllowed.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("管理側單筆路徑不該存在 GET：%d", notAllowed.StatusCode)
	}
	if allow := notAllowed.Header.Get("Allow"); allow != http.MethodPut {
		t.Errorf("405 必須附 Allow=PUT，實際 %q", allow)
	}
	deleted := s.env.request(t, http.MethodDelete, tagAdminItemPath(s.activity, tag["tag_id"].(string)),
		"", s.admin)
	if deleted.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("刪除這條路根本不該存在：%d", deleted.StatusCode)
	}
	if allow := deleted.Header.Get("Allow"); strings.Contains(allow, "DELETE") {
		t.Errorf("Allow 不該虛報 DELETE，實際 %q", allow)
	}
	// 玩家那一族只有讀法：PUT 與 POST 都不掛。
	writeOnPlayer := s.env.request(t, http.MethodPut,
		tagPlayerItemPath(s.activity, tag["tag_id"].(string)),
		dirBody(t, map[string]any{"public": true}), s.player)
	if writeOnPlayer.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("玩家那一族不受理寫入：%d", writeOnPlayer.StatusCode)
	}
	if got := len(s.adminTags(t, s.admin, s.activity)); got != 1 {
		t.Errorf("被擋下的這些敲擊一個都不該動到行數，實際 %d", got)
	}
}

// TestTagRenameKeepsStableIDAtTransport 驗收：改名不換標識、不改建立時刻，
// 玩家那一族按同一枚標識讀到新名稱，而留痕帶著前後值與真實操作者。
func TestTagRenameKeepsStableIDAtTransport(t *testing.T) {
	s := newTagScene(t)
	tag := s.mustCreateTag(t, "舊名字")
	published := s.mustUpdateTag(t, tag, map[string]any{"public": true})

	// 兩筆寫入之間把注入時鐘往前撥一格：比的是「改動時刻前進」，不碰主機時鐘。
	s.env.clock.Advance(time.Second)
	renamed := s.mustUpdateTag(t, published, map[string]any{"name": "新名字"})
	if renamed["tag_id"] != published["tag_id"] {
		t.Fatal("改名換了標識：日後引用標籤的那一步因此不可能穩定")
	}
	if renamed["created_at"] != published["created_at"] {
		t.Error("改名不該動建立時刻")
	}
	if renamed["updated_at"] == published["updated_at"] {
		t.Errorf("兩次寫入之間改動時刻該前進（同一顆注入時鐘下的兩次提交），實際 %q",
			renamed["updated_at"])
	}
	// 同一枚標識讀到的是新名字：穩定 ID 承載身份，名稱只是展示值。
	detail := s.env.request(t, http.MethodGet,
		tagPlayerItemPath(s.activity, published["tag_id"].(string)), "", s.player)
	if detail.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(detail.Body)
		t.Fatalf("按原標識直查該成功：%s", body)
	}
	item, _ := decodeJSONBody(t, detail)["tag"].(map[string]any)
	if item["name"] != "新名字" || item["tag_id"] != published["tag_id"] {
		t.Errorf("直查讀到的該是同一枚、帶著新名稱，實際 %v", item)
	}
	if got := tagNames(s.playerTags(t, s.player, s.activity)); len(got) != 1 || got[0] != "新名字" {
		t.Errorf("清單那一行也要一起改口，實際 %v", got)
	}

	update := s.env.tagAudit(t, "tag.update")
	if !strings.Contains(update.changes, "舊名字") || !strings.Contains(update.changes, "新名字") {
		t.Errorf("留痕要帶得出名稱的前後值，實際 %s", update.changes)
	}
	if update.targetID != published["tag_id"].(string) {
		t.Errorf("留痕的目標該是那枚標籤的標識，實際 %s", update.targetID)
	}
	if update.actorKind == "system" || update.actorID == "" {
		t.Errorf("留痕要帶著真實操作者，實際 %+v", update)
	}
}

// TestTagAuditCarriesPublicChangeAtTransport 驗收涉及公開範圍的變更有真實操作者與變更摘要。
func TestTagAuditCarriesPublicChangeAtTransport(t *testing.T) {
	s := newTagScene(t)
	tag := s.mustCreateTag(t, "留痕取證的")

	create := s.env.tagAudit(t, "tag.create")
	if create.actorKind == "system" || create.actorID == "" {
		t.Errorf("建立的留痕要帶著真實操作者，實際 %+v", create)
	}
	if !strings.Contains(create.changes, "\"public\"") {
		t.Errorf("建立的摘要要如實記下這枚標籤出生不公開，實際 %s", create.changes)
	}
	if create.targetID != tag["tag_id"].(string) {
		t.Errorf("建立留痕的目標該是那枚標籤，實際 %s", create.targetID)
	}

	published := s.mustUpdateTag(t, tag, map[string]any{"public": true})
	update := s.env.tagAudit(t, "tag.update")
	if !strings.Contains(update.changes, "\"public\"") ||
		!strings.Contains(update.changes, "false") || !strings.Contains(update.changes, "true") {
		t.Errorf("翻公開的摘要要帶得出前後值，實際 %s", update.changes)
	}
	if !strings.Contains(update.reason, "公開") {
		t.Errorf("原因句要說出這一次動的是公開範圍，實際 %q", update.reason)
	}
	if update.actorID == "" || update.targetID != published["tag_id"] {
		t.Errorf("留痕要帶著操作者與目標：%+v", update)
	}
	// changes 裡一個秘密都沒有：留痕不帶憑據、會話材料或口令形態。
	for _, forbidden := range []string{"password", "token", "cookie", "secret"} {
		if strings.Contains(strings.ToLower(update.changes+update.reason), forbidden) {
			t.Errorf("留痕不該出現 %q 這種東西", forbidden)
		}
	}

	// 只翻可用性的那一次：原因句該講「停用」而不是「公開」，兩者不混用。
	disabled := s.mustUpdateTag(t, published, map[string]any{"available": false})
	disable := s.env.tagAudit(t, "tag.update")
	if !strings.Contains(disable.reason, "停用") {
		t.Errorf("停用那一次的留痕要說出這是動可用性，實際 %q", disable.reason)
	}
	if strings.Contains(disable.reason, "公開") {
		t.Errorf("只翻可用性的編輯不該被念成動了公開範圍，實際 %q", disable.reason)
	}
	if !mustTagBool(t, disabled, "public") {
		t.Error("停用那一跳不該順手把公開收回去")
	}
	if mustTagBool(t, disabled, "accepts_new_assignments") {
		t.Error("停用之後派生那一格該轉假（貼標通路將讀同一個結論）")
	}
}

// decodeJSONMap 把一份 JSON 字串換成可增減欄位的 map（湊「多塞一格」的本體用）。
func decodeJSONMap(t *testing.T, raw string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("解析湊出來的本體失敗：%v", err)
	}
	return out
}
