// playerstatus_test.go 是「玩家業務狀態與顯示名稱」在傳輸層的端到端證據：
// 內建七值與出廠 normal、顯示名稱覆蓋只改展示值、自訂狀態的建立／改名／停用、
// 同活動重名的 2042、選停用中定義的 2041、非法狀態鍵的 1004 點名、
// 跨活動成員與自訂定義的不可分辨（1001）、業務寫入門禁與配置門禁各有各的碼、
// 併發落敗那句、本體白名單（多塞一格就 1004）、玩家目錄與本人投影帶著狀態而
// 可見集合不受狀態影響，以及「讀取與時間推進都不會翻轉業務狀態」。
//
// 刻意不收的東西：
//   - 不重複 internal/activity 的服務層矩陣：那一側已取證的結論，這裡只問協定形態；
//   - 不碰真實資料目錄、不佔 5206，全程本次專屬的臨時庫與注入時鐘；
//   - 不宣稱任何推送或即時失效：這一切的取證形態都是「下一筆請求按現值回答」。
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// 本檔使用的幽靈標識：合法形狀但從未存在（不可分辨性要比對它）。
const (
	statusGhostMemberID = "0192f0c4-1c9a-7000-8000-000000000fd2"
	statusGhostCustomID = "0192f0c4-1c9a-7000-8000-000000000fd3"
)

// statusScene 是本檔共用的輕量現場：一場已開放的活動、一位獲指派的管理人、
// 一位场内玩家（有會話，能敲玩家那一族）、另一場由外人管的活動（跨活動反證需要它）。
//
// 它刻意保持小：狀態的斷言問的是定義與兩欄狀態值，不需要七行成員與兩個陣營的目錄現場
// （R4-008 記下的耗時教訓：端點探針每多一位需要登入與首改的帳戶，成本都是實打實的口令派生）。
type statusScene struct {
	env      *factionEnv
	admin    string
	outsider string
	activity string
	other    string
	player   string // 場内玩家的會話標頭
	member   string // 場内玩家的成員標識
}

func newStatusScene(t *testing.T) *statusScene {
	t.Helper()
	e := newFactionEnv(t)
	s := &statusScene{env: e}
	_, s.admin = e.dirAdminWithSession(t, "status.admin")
	_, s.outsider = e.dirAdminWithSession(t, "status.outsider")
	s.activity = e.createFactionActivity(t, s.admin, "有狀態的場")
	s.other = e.createFactionActivity(t, s.outsider, "外人管的場")
	accountID, cookie := e.selfSelectPlayer(t, s.admin, "status.jia")
	s.member = e.selfAddMember(t, s.admin, s.activity, accountID, "甲")
	s.player = cookie
	return s
}

// statusCatalogPath 是管理側狀態目錄的集合路徑。
func statusCatalogPath(activityID string) string {
	return "/admin/activities/" + activityID + "/player-statuses"
}

// statusCustomPath 是管理側單筆自訂狀態的路徑。
func statusCustomPath(activityID, statusID string) string {
	return statusCatalogPath(activityID) + "/" + statusID
}

// statusLabelPath 是管理側內建顯示名稱覆蓋的路徑。
func statusLabelPath(activityID, key string) string {
	return "/admin/activities/" + activityID + "/player-status-labels/" + key
}

// statusMemberPath 是管理側成員狀態變更的路徑。
func statusMemberPath(activityID, memberID string) string {
	return "/admin/activities/" + activityID + "/members/" + memberID + "/business-status"
}

// statusJSONBody 湊一份 JSON 本體（沿用目錄那檔的寫法，不另造一份編碼器）。
func statusJSONBody(fields map[string]any) string {
	encoded, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// statusMemberBody 湊一份成員狀態本體：兩欄新值加兩欄依據值。
func statusMemberBody(status, customID, expectedStatus, expectedCustomID string) string {
	return statusJSONBody(map[string]any{
		"business_status": status, "custom_status_id": customID,
		"expected_business_status":  expectedStatus,
		"expected_custom_status_id": expectedCustomID,
	})
}

// mustStatusCatalog 讀管理側目錄並回 builtin_statuses／custom_statuses 兩份清單。
func (s *statusScene) mustStatusCatalog(t *testing.T, who, activityID string) (
	[]map[string]any, []map[string]any) {
	t.Helper()
	resp := s.env.request(t, http.MethodGet, statusCatalogPath(activityID), "", who)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("狀態目錄應成功：%d %s", resp.StatusCode, body)
	}
	payload := decodeJSONBody(t, resp)
	return statusRowsOf(t, payload["builtin_statuses"]),
		statusRowsOf(t, payload["custom_statuses"])
}

// statusRowsOf 把回應裡的一格清單換成逐行可斷言的切片。
func statusRowsOf(t *testing.T, raw any) []map[string]any {
	t.Helper()
	rows, ok := raw.([]any)
	if !ok {
		t.Fatalf("狀態清單必須是清單，實際 %v", raw)
	}
	out := make([]map[string]any, 0, len(rows))
	for _, entry := range rows {
		item, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("狀態行必須是物件，實際 %v", entry)
		}
		out = append(out, item)
	}
	return out
}

// statusBuiltinRow 取目錄裡某個內建鍵的那一行。
func statusBuiltinRow(t *testing.T, rows []map[string]any, key string) map[string]any {
	t.Helper()
	for _, row := range rows {
		if got, _ := row["status_key"].(string); got == key {
			return row
		}
	}
	t.Fatalf("目錄裡必須有 %s 這一格", key)
	return nil
}

// mustCreateCustomStatus 建立自訂狀態並回讀那一行。
func (s *statusScene) mustCreateCustomStatus(t *testing.T, who, activityID, name string) map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodPost, statusCatalogPath(activityID),
		statusJSONBody(map[string]any{"name": name}), who)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("建立自訂狀態 %q 應成功：%d %s", name, resp.StatusCode, body)
	}
	item, ok := decodeJSONBody(t, resp)["custom_status"].(map[string]any)
	if !ok {
		t.Fatalf("建立回應要帶著 custom_status 這一格")
	}
	return item
}

// customStatusIDOf 取自訂狀態行的標識格。
func customStatusIDOf(t *testing.T, item map[string]any) string {
	t.Helper()
	id, _ := item["custom_status_id"].(string)
	if id == "" {
		t.Fatalf("自訂狀態行要帶著 custom_status_id，實際 %v", item)
	}
	return id
}

// mustUpdateCustomStatus 送一次必須成功的自訂狀態編輯。
func (s *statusScene) mustUpdateCustomStatus(t *testing.T, who, activityID string,
	item map[string]any, overrides map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{
		"name": item["name"], "available": item["available"],
		"expected_name": item["name"], "expected_available": item["available"],
	}
	for key, value := range overrides {
		body[key] = value
	}
	resp := s.env.request(t, http.MethodPut,
		statusCustomPath(activityID, customStatusIDOf(t, item)), statusJSONBody(body), who)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("編輯自訂狀態應成功：%d %s", resp.StatusCode, raw)
	}
	updated, ok := decodeJSONBody(t, resp)["custom_status"].(map[string]any)
	if !ok {
		t.Fatalf("編輯回應要帶著 custom_status 這一格")
	}
	return updated
}

// mustSetStatusLabel 送一次必須成功的顯示名稱編輯並回讀那一格。
func (s *statusScene) mustSetStatusLabel(t *testing.T, who, activityID, key,
	display, expected string) map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodPut, statusLabelPath(activityID, key),
		statusJSONBody(map[string]any{"display_name": display, "expected_display_name": expected}), who)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("編輯顯示名稱 %s 應成功：%d %s", key, resp.StatusCode, body)
	}
	item, ok := decodeJSONBody(t, resp)["builtin_status"].(map[string]any)
	if !ok {
		t.Fatalf("顯示名稱回應要帶著 builtin_status 這一格")
	}
	return item
}

// mustSetMemberStatus 送一次必須成功的成員狀態變更並回讀 member 那一格。
func (s *statusScene) mustSetMemberStatus(t *testing.T, who, activityID, memberID,
	status, customID, expectedStatus, expectedCustomID string) map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodPut, statusMemberPath(activityID, memberID),
		statusMemberBody(status, customID, expectedStatus, expectedCustomID), who)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("變更成員狀態應成功：%d %s", resp.StatusCode, body)
	}
	return mustMemberItem(t, resp)
}

// statusErrorCode 讀錯誤信封的 code（不依賴訊息文字）。
func statusErrorCode(t *testing.T, resp *http.Response) int {
	t.Helper()
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var envelope struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("錯誤回應必須是統一信封：%v（%s）", err, raw)
	}
	return envelope.Code
}

// memberRosterRow 從名冊裡按成員標識取那一行。
func memberRosterRow(t *testing.T, rows []map[string]any, memberID string) map[string]any {
	t.Helper()
	for _, row := range rows {
		if got, _ := row["member_id"].(string); got == memberID {
			return row
		}
	}
	t.Fatalf("名冊裡必須有 %s 這一行人", memberID)
	return nil
}

// statusTransitionTo 把活動推到目標狀態（真通路，不直接改庫）。
//
// closed→archived 與 active→archived 都是合法路徑，因此一步就到位；
// 刻意不寫「沿路徑逐跳推」的版本：同一場活動被推兩次同一格時拿回的是 2030，
// 而那一句在這裡講的是「沒有可發生的物件」，不是本步要取證的門禁。
func (s *statusScene) statusTransitionTo(t *testing.T, want string) {
	t.Helper()
	resp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+s.activity+"/status", statusJSONBody(map[string]any{"status": want}),
		s.admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("把活動推到 %s 應成功：%d %s", want, resp.StatusCode, body)
	}
}

// TestStatusEndpointBirthIsNormal 驗收：名冊與玩家投影都帶著狀態，新成員出生為 normal，
// 而目錄的七個內建鍵逐字齐全、出廠都沒有覆蓋。
func TestStatusEndpointBirthIsNormal(t *testing.T) {
	s := newStatusScene(t)

	roster := memberRoster(t, s.env.request(t, http.MethodGet,
		"/admin/activities/"+s.activity+"/members", "", s.admin))
	row := memberRosterRow(t, roster, s.member)
	for _, field := range []string{"business_status", "custom_status_id", "custom_status_name",
		"status_display_name", "status_available"} {
		if _, ok := row[field]; !ok {
			t.Errorf("名冊行必須帶著 %s 這一格（只增不刪的相容演進欄位）", field)
		}
	}
	if row["business_status"] != "normal" || row["custom_status_id"] != "" ||
		row["status_display_name"] != "" || row["status_available"] != true {
		t.Errorf("出生形態必須是 normal、無自訂參考、無覆蓋且可用，實際 %v", row)
	}

	builtins, custom := s.mustStatusCatalog(t, s.admin, s.activity)
	if len(builtins) != 7 {
		t.Fatalf("目錄必須逐字列出七個內建鍵，實際 %d 格", len(builtins))
	}
	want := []string{"normal", "suspended", "eliminated", "dead", "arrested", "offline", "custom"}
	for i, key := range want {
		if got, _ := builtins[i]["status_key"].(string); got != key {
			t.Errorf("第 %d 格該是 %s，實際 %q", i, key, got)
		}
		if builtins[i]["display_name"] != "" || builtins[i]["uses_default_display_name"] != true {
			t.Errorf("出廠沒有任何覆蓋：%v", builtins[i])
		}
	}
	if len(custom) != 0 {
		t.Errorf("沒有自訂定義時該是空清單，實際 %v", custom)
	}

	// 玩家目錄（全量態）與本人投影都讀得到同一份出生形態。
	s.mustSetDirectoryAll(t)
	page := s.list(t, s.player)
	item := dirRowOf(t, page, "甲")
	if item["business_status"] != "normal" || item["status_available"] != true {
		t.Errorf("玩家目錄要帶著狀態投影：%v", item)
	}
	own := decodeJSONBody(t, s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/profile", "", s.player))
	if own["business_status"] != "normal" {
		t.Errorf("本人投影要帶著狀態：%v", own)
	}
	for _, forbidden := range []string{"custom_status_id", "custom_status_name"} {
		if _, ok := item[forbidden]; !ok {
			t.Errorf("目錄投影也該帶著 %s 這一格", forbidden)
		}
	}
}

// TestStatusEndpointLabelRenameKeepsInternalValue 驗收：改顯示名稱只改展示值，
// 成员的內部值一格不動；恢復預設是清空覆蓋而不是刪除狀態；依據值過期回 2013。
func TestStatusEndpointLabelRenameKeepsInternalValue(t *testing.T) {
	s := newStatusScene(t)
	s.mustSetStatusLabel(t, s.admin, s.activity, "offline", "暫離現場", "")

	// 把這位玩家切到離線：回應帶著覆蓋後的顯示名稱。
	updated := s.mustSetMemberStatus(t, s.admin, s.activity, s.member,
		"offline", "", "normal", "")
	if updated["business_status"] != "offline" || updated["status_display_name"] != "暫離現場" {
		t.Fatalf("狀態與覆蓋必須同源，實際 %v", updated)
	}
	roster := memberRoster(t, s.env.request(t, http.MethodGet,
		"/admin/activities/"+s.activity+"/members", "", s.admin))
	if row := memberRosterRow(t, roster, s.member); row["business_status"] != "offline" {
		t.Errorf("改名與切狀態都不該動其他欄，實際 %v", row)
	}

	// 恢復預設：空字串是「沒有覆蓋」，內部值照舊。
	reset := s.mustSetStatusLabel(t, s.admin, s.activity, "offline", "", "暫離現場")
	if reset["display_name"] != "" || reset["uses_default_display_name"] != true {
		t.Fatalf("恢復預設要回空覆蓋，實際 %v", reset)
	}
	roster = memberRoster(t, s.env.request(t, http.MethodGet,
		"/admin/activities/"+s.activity+"/members", "", s.admin))
	if row := memberRosterRow(t, roster, s.member); row["business_status"] != "offline" ||
		row["status_display_name"] != "" {
		t.Errorf("恢復預設不該動成员的內部值，實際 %v", row)
	}

	// 依據值過期：2013，且一個字都不覆蓋。
	stale := s.env.request(t, http.MethodPut, statusLabelPath(s.activity, "offline"),
		statusJSONBody(map[string]any{"display_name": "又一個名字", "expected_display_name": "暫離現場"}),
		s.admin)
	if stale.StatusCode != http.StatusConflict || statusErrorCode(t, stale) != int(CodeProfileConflict) {
		t.Fatalf("過期依據值該回 409／2013")
	}
	builtins, _ := s.mustStatusCatalog(t, s.admin, s.activity)
	if row := statusBuiltinRow(t, builtins, "offline"); row["display_name"] != "" {
		t.Errorf("落敗的那一筆不該留下痕跡，實際 %v", row)
	}

	audit := s.env.dirAudit(t, "player_status.label_update")
	if audit.actorKind != "admin" || audit.actorID == "" {
		t.Errorf("顯示名稱留痕要帶真實操作者，實際 %+v", audit)
	}
}

// TestStatusEndpointCustomLifecycle 驗收：自訂狀態出生即可用、同活動重名 2042、
// 跨活動同名合法、選中後玩家讀到定義名稱、停用後新的選用拿 2041 而既有成員不動、
// 重新啟用後同一個意圖就能成立。
func TestStatusEndpointCustomLifecycle(t *testing.T) {
	s := newStatusScene(t)
	created := s.mustCreateCustomStatus(t, s.admin, s.activity, "失蹤中")
	if created["available"] != true {
		t.Fatalf("新建自訂狀態必須出生即可用：%v", created)
	}
	statusID := customStatusIDOf(t, created)

	// 同活動重名（含剔空白後相等）：2042。
	dup := s.env.request(t, http.MethodPost, statusCatalogPath(s.activity),
		statusJSONBody(map[string]any{"name": " 失蹤中 "}), s.admin)
	if dup.StatusCode != http.StatusConflict ||
		statusErrorCode(t, dup) != int(CodePlayerStatusNameTaken) {
		t.Fatalf("同活動重名該回 409／2042")
	}
	// 跨活動同名合法。
	foreign := s.mustCreateCustomStatus(t, s.outsider, s.other, "失蹤中")

	s.mustSetMemberStatus(t, s.admin, s.activity, s.member, "custom", statusID, "normal", "")
	_, custom := s.mustStatusCatalog(t, s.admin, s.activity)
	if len(custom) != 1 {
		t.Fatalf("本場該有一行自訂定義，實際 %v", custom)
	}
	s.mustSetDirectoryAll(t)
	item := dirRowOf(t, s.list(t, s.player), "甲")
	if item["business_status"] != "custom" || item["custom_status_id"] != statusID ||
		item["custom_status_name"] != "失蹤中" || item["status_available"] != true {
		t.Fatalf("玩家讀到的自訂狀態該是定義本身：%v", item)
	}

	// 停用：既有成員保留原狀態與標識，只擋新的選用。
	disabled := s.mustUpdateCustomStatus(t, s.admin, s.activity, created,
		map[string]any{"available": false})
	if disabled["available"] != false {
		t.Fatalf("停用該如實回顯：%v", disabled)
	}
	otherAccountID := s.env.memberTargetAccount(t, s.admin, "status.yi")
	otherMember := s.env.selfAddMember(t, s.admin, s.activity, otherAccountID, "乙")
	late := s.env.request(t, http.MethodPut, statusMemberPath(s.activity, otherMember),
		statusMemberBody("custom", statusID, "normal", ""), s.admin)
	if late.StatusCode != http.StatusConflict ||
		statusErrorCode(t, late) != int(CodePlayerStatusUnavailable) {
		t.Fatalf("選停用中的定義該回 409／2041")
	}
	item = dirRowOf(t, s.list(t, s.player), "甲")
	if item["custom_status_id"] != statusID || item["status_available"] != false ||
		item["custom_status_name"] != "失蹤中" {
		t.Errorf("停用不該搬動既有成員，只該把可用性改口：%v", item)
	}

	// 改名不換標識、不改内部值。
	renamed := s.mustUpdateCustomStatus(t, s.admin, s.activity, disabled,
		map[string]any{"name": "改名後的定義"})
	if renamed["custom_status_id"] != statusID {
		t.Fatalf("改名不該換標識：%v", renamed)
	}
	item = dirRowOf(t, s.list(t, s.player), "甲")
	if item["custom_status_name"] != "改名後的定義" || item["custom_status_id"] != statusID {
		t.Errorf("自訂名稱現讀、標識不變：%v", item)
	}

	// 重新啟用後，另一個人就能選同一個定義。
	s.mustUpdateCustomStatus(t, s.admin, s.activity, renamed, map[string]any{"available": true})
	s.mustSetMemberStatus(t, s.admin, s.activity, otherMember, "custom", statusID, "normal", "")

	// 别人的定義（跨活動）與幽靈標識收斂成同一句 1001。
	for _, id := range []string{customStatusIDOf(t, foreign), statusGhostCustomID} {
		resp := s.env.request(t, http.MethodPut, statusMemberPath(s.activity, s.member),
			statusMemberBody("custom", id, "custom", statusID), s.admin)
		if resp.StatusCode != http.StatusNotFound || statusErrorCode(t, resp) != int(CodeNotFound) {
			t.Fatalf("跨活動與幽靈的自訂定義該逐字同文（1001），實際 %d", resp.StatusCode)
		}
	}
}

// TestStatusEndpointInvalidWrites 驗收：非法狀態鍵、成對關係不成立、多塞一格的本體、
// 寫壞的標識，各自有各自的一句話，而且一個字都不落。
func TestStatusEndpointInvalidWrites(t *testing.T) {
	s := newStatusScene(t)
	cases := []struct {
		what   string
		body   string
		status int
		code   int
	}{
		{"集合外的狀態鍵", statusMemberBody("Normal", "", "normal", ""),
			http.StatusBadRequest, int(CodeInvalidBody)},
		{"空的狀態鍵", statusMemberBody("", "", "normal", ""),
			http.StatusBadRequest, int(CodeInvalidBody)},
		{"custom 缺自訂標識", statusMemberBody("custom", "", "normal", ""),
			http.StatusBadRequest, int(CodeInvalidBody)},
		{"內建值卻帶自訂標識", statusMemberBody("normal", statusGhostCustomID, "normal", ""),
			http.StatusBadRequest, int(CodeInvalidBody)},
		{"本體多塞活動標識", statusJSONBody(map[string]any{"business_status": "offline",
			"custom_status_id": "", "expected_business_status": "normal",
			"expected_custom_status_id": "", "activity_id": s.activity}),
			http.StatusBadRequest, int(CodeInvalidBody)},
		{"本體多塞自報的操作者", statusJSONBody(map[string]any{"business_status": "offline",
			"custom_status_id": "", "expected_business_status": "normal",
			"expected_custom_status_id": "", "actor_kind": "player"}),
			http.StatusBadRequest, int(CodeInvalidBody)},
		{"寫壞的自訂標識", statusMemberBody("custom", "not-a-uuid", "normal", ""),
			http.StatusBadRequest, int(CodeInvalidBody)},
	}
	for _, tc := range cases {
		resp := s.env.request(t, http.MethodPut, statusMemberPath(s.activity, s.member),
			tc.body, s.admin)
		if resp.StatusCode != tc.status || statusErrorCode(t, resp) != tc.code {
			t.Errorf("%s 該回 %d／%d，實際不符", tc.what, tc.status, tc.code)
		}
		roster := memberRoster(t, s.env.request(t, http.MethodGet,
			"/admin/activities/"+s.activity+"/members", "", s.admin))
		if row := memberRosterRow(t, roster, s.member); row["business_status"] != "normal" {
			t.Errorf("%s 之後內部值一個字都不該動，實際 %v", tc.what, row)
		}
	}
	if n := s.env.countMemberAudits(t, "member.business_status_update"); n != 0 {
		t.Errorf("被拒的寫入一條痕都不加，實際 %d", n)
	}

	// 跨活動的成員標識與幽靈同文（1001）。
	ghost := s.env.request(t, http.MethodPut, statusMemberPath(s.activity, statusGhostMemberID),
		statusMemberBody("offline", "", "normal", ""), s.admin)
	foreignRow := s.env.request(t, http.MethodPut, statusMemberPath(s.activity, s.member),
		statusMemberBody("offline", "", "normal", ""), s.outsider)
	if ghost.StatusCode != http.StatusNotFound ||
		statusErrorCode(t, ghost) != int(CodeNotFound) ||
		foreignRow.StatusCode != http.StatusNotFound {
		t.Fatalf("幽靈與「這活動不歸你管」都該收斂成 1001")
	}
	// 另一場活動的成員標識拼在本場路徑上：也是 1001，不動那一行。
	outsiderAccount := s.env.memberTargetAccount(t, s.outsider, "status.wai")
	outsiderMember := s.env.selfAddMember(t, s.outsider, s.other, outsiderAccount, "外場的人")
	splice := s.env.request(t, http.MethodPut, statusMemberPath(s.activity, outsiderMember),
		statusMemberBody("offline", "", "normal", ""), s.admin)
	if splice.StatusCode != http.StatusNotFound || statusErrorCode(t, splice) != int(CodeNotFound) {
		t.Fatalf("跨活動拼接該與幽靈同文")
	}
}

// TestStatusEndpointLifecycleGates 驗收：成員狀態變更吃業務寫入門禁（停止 2033、歸檔 2029），
// 配置兩族在停止態仍可寫、歸檔一律 2029，而讀法在任何狀態都照舊可讀。
func TestStatusEndpointLifecycleGates(t *testing.T) {
	s := newStatusScene(t)
	created := s.mustCreateCustomStatus(t, s.admin, s.activity, "停止前建的")

	s.statusTransitionTo(t, "closed")
	closed := s.env.request(t, http.MethodPut, statusMemberPath(s.activity, s.member),
		statusMemberBody("offline", "", "normal", ""), s.admin)
	if closed.StatusCode != http.StatusConflict ||
		statusErrorCode(t, closed) != int(CodeActivityClosedWrites) {
		t.Fatalf("停止態的成員狀態變更該回 409／2033")
	}
	// 配置側在停止態仍可寫。
	s.mustSetStatusLabel(t, s.admin, s.activity, "offline", "停止時設的", "")
	s.mustUpdateCustomStatus(t, s.admin, s.activity, created, map[string]any{"available": false})
	s.mustStatusCatalog(t, s.admin, s.activity)
	if roster := memberRoster(t, s.env.request(t, http.MethodGet,
		"/admin/activities/"+s.activity+"/members", "", s.admin)); len(roster) != 1 {
		t.Fatalf("停止態名冊照舊可讀：%v", roster)
	}

	s.statusTransitionTo(t, "archived")
	archivedWrite := s.env.request(t, http.MethodPut, statusMemberPath(s.activity, s.member),
		statusMemberBody("offline", "", "normal", ""), s.admin)
	if archivedWrite.StatusCode != http.StatusConflict ||
		statusErrorCode(t, archivedWrite) != int(CodeActivityArchived) {
		t.Fatalf("歸檔態的成員狀態變更該回 409／2029")
	}
	archivedLabel := s.env.request(t, http.MethodPut, statusLabelPath(s.activity, "offline"),
		statusJSONBody(map[string]any{"display_name": "歸檔後想改", "expected_display_name": "停止時設的"}),
		s.admin)
	if archivedLabel.StatusCode != http.StatusConflict ||
		statusErrorCode(t, archivedLabel) != int(CodeActivityArchived) {
		t.Fatalf("歸檔態的配置寫入也一律 2029")
	}
	archivedCreate := s.env.request(t, http.MethodPost, statusCatalogPath(s.activity),
		statusJSONBody(map[string]any{"name": "歸檔後想建"}), s.admin)
	if archivedCreate.StatusCode != http.StatusConflict ||
		statusErrorCode(t, archivedCreate) != int(CodeActivityArchived) {
		t.Fatalf("歸檔態不發新建定義")
	}
	// 仍列可讀：目錄與名冊帶著歸檔前的現值，一個字都沒被歸檔改寫。
	builtins, custom := s.mustStatusCatalog(t, s.admin, s.activity)
	if len(custom) != 1 || custom[0]["available"] != false {
		t.Errorf("歸檔不動既有定義：%v", custom)
	}
	if row := statusBuiltinRow(t, builtins, "offline"); row["display_name"] != "停止時設的" {
		t.Errorf("歸檔不動覆蓋現值：%v", row)
	}
	roster := memberRoster(t, s.env.request(t, http.MethodGet,
		"/admin/activities/"+s.activity+"/members", "", s.admin))
	if row := memberRosterRow(t, roster, s.member); row["business_status"] != "normal" {
		t.Errorf("歸檔後成員狀態一格沒動：%v", row)
	}
}

// TestStatusEndpointConcurrentWrites 驗收：兩筆同依據值的狀態變更只有贏家落地，
// 落敗那句是 2013、不寫第二次，留痕筆數等於實際提交數。
func TestStatusEndpointConcurrentWrites(t *testing.T) {
	s := newStatusScene(t)
	s.mustSetMemberStatus(t, s.admin, s.activity, s.member, "arrested", "", "normal", "")
	loser := s.env.request(t, http.MethodPut, statusMemberPath(s.activity, s.member),
		statusMemberBody("dead", "", "normal", ""), s.admin)
	if loser.StatusCode != http.StatusConflict ||
		statusErrorCode(t, loser) != int(CodeProfileConflict) {
		t.Fatalf("帶過期依據值的第二筆該回 409／2013")
	}
	roster := memberRoster(t, s.env.request(t, http.MethodGet,
		"/admin/activities/"+s.activity+"/members", "", s.admin))
	if row := memberRosterRow(t, roster, s.member); row["business_status"] != "arrested" {
		t.Errorf("贏家現值不被覆蓋：%v", row)
	}
	if n := s.env.countMemberAudits(t, "member.business_status_update"); n != 1 {
		t.Errorf("留痕筆數該等於實際提交數，實際 %d", n)
	}

	// 冪等重送：同一份「沒有翻轉」的提交不製造第二條留痕，也不報錯。
	s.mustSetMemberStatus(t, s.admin, s.activity, s.member, "arrested", "", "arrested", "")
	if n := s.env.countMemberAudits(t, "member.business_status_update"); n != 1 {
		t.Errorf("冪等重送後留痕仍該只有一筆，實際 %d", n)
	}

	// 自訂狀態編輯同形：兩份同依據值，只有一份落地。
	created := s.mustCreateCustomStatus(t, s.admin, s.activity, "相撞的定義")
	s.mustUpdateCustomStatus(t, s.admin, s.activity, created, map[string]any{"name": "贏家寫法"})
	lose := s.env.request(t, http.MethodPut, statusCustomPath(s.activity, customStatusIDOf(t, created)),
		statusJSONBody(map[string]any{"name": "落敗寫法", "available": true,
			"expected_name": "相撞的定義", "expected_available": true}), s.admin)
	if lose.StatusCode != http.StatusConflict ||
		statusErrorCode(t, lose) != int(CodeProfileConflict) {
		t.Fatalf("過期依據值的定義編輯該回 409／2013")
	}
	_, custom := s.mustStatusCatalog(t, s.admin, s.activity)
	if custom[0]["name"] != "贏家寫法" {
		t.Errorf("定義現值該是贏家那份：%v", custom)
	}
}

// TestStatusEndpointOfflineIsNotConnectivity 驗收：讀取與時間推進都不翻轉業務狀態。
//
// 這一組是「業務 Offline 不隨網路或頁面狀態變化」那句在協定層的取證：
// 倉庫今日沒有任何連線狀態欄位，讀取通路也不寫狀態，時鐘推進更不碰那一欄。
func TestStatusEndpointOfflineIsNotConnectivity(t *testing.T) {
	s := newStatusScene(t)
	s.mustSetMemberStatus(t, s.admin, s.activity, s.member, "offline", "", "normal", "")
	s.mustSetDirectoryAll(t)

	for i := 0; i < 3; i++ {
		if resp := s.env.request(t, http.MethodGet,
			"/player/activities/"+s.activity+"/profile", "", s.player); resp.StatusCode !=
			http.StatusOK {
			t.Fatalf("第 %d 次本人投影應成功：%d", i, resp.StatusCode)
		} else {
			payload := decodeJSONBody(t, resp)
			if payload["business_status"] != "offline" {
				t.Fatalf("讀取不該翻轉業務狀態：%v", payload)
			}
		}
		item := dirRowOf(t, s.list(t, s.player), "甲")
		if item["business_status"] != "offline" {
			t.Fatalf("目錄讀取不該翻轉業務狀態：%v", item)
		}
		// 連管理面的讀法也敲幾次：它們同樣只讀不寫。
		s.mustStatusCatalog(t, s.admin, s.activity)
		s.env.clock.Advance(90 * time.Second)
	}

	roster := memberRoster(t, s.env.request(t, http.MethodGet,
		"/admin/activities/"+s.activity+"/members", "", s.admin))
	row := memberRosterRow(t, roster, s.member)
	if row["business_status"] != "offline" {
		t.Errorf("三次讀取與時鐘推進之後狀態一格沒動，實際 %v", row)
	}
	if n := s.env.countMemberAudits(t, "member.business_status_update"); n != 1 {
		t.Errorf("讀取不該留下第二次留痕，實際 %d", n)
	}
}

// TestStatusEndpointAdmissionMatrix 驗收：普通帳戶與匿名敲管理那一族各有各的句子，
// 而玩家那一族的讀法不因為狀態而多得到任何東西。
func TestStatusEndpointAdmissionMatrix(t *testing.T) {
	s := newStatusScene(t)
	plainAccount, plainCookie := s.env.selfSelectPlayer(t, s.admin, "status.plain")
	_ = plainAccount
	paths := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, statusCatalogPath(s.activity), ""},
		{http.MethodPost, statusCatalogPath(s.activity), statusJSONBody(map[string]any{"name": "平民建的"})},
		{http.MethodPut, statusLabelPath(s.activity, "offline"),
			statusJSONBody(map[string]any{"display_name": "平民改的", "expected_display_name": ""})},
		{http.MethodPut, statusMemberPath(s.activity, s.member),
			statusMemberBody("offline", "", "normal", "")},
	}
	for _, tc := range paths {
		resp := s.env.request(t, tc.method, tc.path, tc.body, plainCookie)
		if resp.StatusCode != http.StatusForbidden ||
			statusErrorCode(t, resp) != int(CodePermissionDenied) {
			t.Errorf("普通帳戶敲 %s %s 該回 403／2011", tc.method, tc.path)
		}
		respAnon := s.env.request(t, tc.method, tc.path, tc.body, "")
		if respAnon.StatusCode != http.StatusUnauthorized ||
			statusErrorCode(t, respAnon) != int(CodeNotAuthenticated) {
			t.Errorf("匿名敲 %s %s 該回 401／2002", tc.method, tc.path)
		}
	}
	// 玩家那一族沒有狀態的寫入通路：狀態不是玩家能自報的欄位。
	selfWrite := s.env.request(t, http.MethodPut,
		"/player/activities/"+s.activity+"/profile", statusJSONBody(map[string]any{"business_status": "dead"}),
		s.player)
	if selfWrite.StatusCode != http.StatusNotFound &&
		selfWrite.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("本人通路不受理狀態寫入，實際 %d", selfWrite.StatusCode)
	}
	// 本檔這一族不受理 DELETE（自訂狀態只停用、不刪除）。
	deleteCustom := s.env.request(t, http.MethodDelete,
		statusCatalogPath(s.activity), "", s.admin)
	if deleteCustom.StatusCode == http.StatusOK {
		t.Fatalf("狀態定義沒有刪除通路")
	}
	allow := deleteCustom.Header.Get("Allow")
	if strings.Contains(allow, "DELETE") {
		t.Errorf("Allow 標頭不得虛報刪除方法：%q", allow)
	}
}

// TestStatusEndpointAuditCarriesActorAndChanges 驗收：被接受的狀態變更留下帶真實操作者與
// 前後值的留痕；被拒的寫入一條痕都不加。
func TestStatusEndpointAuditCarriesActorAndChanges(t *testing.T) {
	s := newStatusScene(t)
	created := s.mustCreateCustomStatus(t, s.admin, s.activity, "被引用的定義")
	statusID := customStatusIDOf(t, created)

	s.mustSetMemberStatus(t, s.admin, s.activity, s.member, "custom", statusID, "normal", "")
	row := s.env.dirAudit(t, "member.business_status_update")
	if row.actorKind != "admin" || row.actorID == "" {
		t.Fatalf("留痕要帶真實操作者，實際 %+v", row)
	}
	for _, want := range []string{"normal", "custom", statusID, "被引用的定義"} {
		if !strings.Contains(row.changes, want) {
			t.Errorf("changes 該帶 %q，實際 %s", want, row.changes)
		}
	}
	if !strings.Contains(row.reason, "業務狀態") {
		t.Errorf("原因句要說出這是狀態變更，實際 %q", row.reason)
	}
	for _, forbidden := range []string{"password", "token", "cookie", "session"} {
		if strings.Contains(strings.ToLower(row.changes+row.reason), forbidden) {
			t.Errorf("留痕不得帶任何憑據字樣：%q", forbidden)
		}
	}

	before := s.env.countMemberAudits(t, "member.business_status_update")
	stale := s.env.request(t, http.MethodPut, statusMemberPath(s.activity, s.member),
		statusMemberBody("dead", "", "normal", ""), s.admin)
	if stale.StatusCode != http.StatusConflict {
		t.Fatalf("過期依據值該回衝突")
	}
	if got := s.env.countMemberAudits(t, "member.business_status_update"); got != before {
		t.Errorf("被拒的寫入不留痕：%d→%d", before, got)
	}
}

// mustSetDirectoryAll 把這場活動的目錄打開成 all_members（玩家投影取證的先導）。
func (s *statusScene) mustSetDirectoryAll(t *testing.T) {
	t.Helper()
	resp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+s.activity+"/member-directory",
		statusJSONBody(map[string]any{"mode": "all_members", "expected_mode": "hidden"}), s.admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("打開目錄應成功：%d %s", resp.StatusCode, body)
	}
}

// list 讀玩家目錄一頁（非 200 當場失敗）。
func (s *statusScene) list(t *testing.T, cookie string) map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/members"+dirQuery(1, 20), "", cookie)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("玩家目錄應成功：%d %s", resp.StatusCode, body)
	}
	return decodeJSONBody(t, resp)
}
