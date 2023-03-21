// members_test.go 是「活動成員與唯一檔案」在傳輸層的端到端證據：一位管理人走完
// 建立成員→讀名冊→改暱稱→活動歸檔後的讀寫兩副面孔，四條路徑各自的權限矩陣
// （匿名、普通帳戶、外人管理員、Root）、本體欄位白名單（含「順手宣稱 faction_id／
// member_id／activity_id／角色」）、跨活動與幽靈標識的同碼同文、重複建立的 2035 與
// 不合格目標的 1001、停止態的 2033 與重開後的翻案、併發編輯的 2013，
// 以及這一族沒有 DELETE 與跨站來源一律 2005。
//
// 刻意不收的東西：
//   - 沒有替身：授權、活動作用域判定、業務門禁、帳戶資格核實、CAS 與審計都跨層走真路徑；
//   - 不測玩家在陣營間的分配：本步沒有分配端點，斷言只到「回應裡的 faction_id 是空字串」
//     這一句，不偽造任何「他被分進哪一組」的形態；
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

// memberGhostActivityID 是一個合法形狀但從未存在的活動標識（不可分辨性的對照組）。
const memberGhostActivityID = "0192f0c4-1c9a-7000-8000-000000000fe1"

// memberGhostAccountID 是一個合法形狀但從未存在的帳戶標識（目標資格那一句的對照組）。
const memberGhostAccountID = "0192f0c4-1c9a-7000-8000-000000000fe2"

// memberCreateBody 湊一份建立成員的请求本體（只有白名單兩格）。
func memberCreateBody(accountID, nickname string) string {
	encoded, err := json.Marshal(map[string]any{"account_id": accountID, "nickname": nickname})
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// memberEditBody 湊一份編輯暱稱的請求本體：新值加上它所依據的現值。
func memberEditBody(nickname, expectedNickname string) string {
	encoded, err := json.Marshal(map[string]any{
		"nickname": nickname, "expected_nickname": expectedNickname,
	})
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// mustMemberItem 讀寫入回應裡的 member 那一格。
func mustMemberItem(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	payload := decodeJSONBody(t, resp)
	item, ok := payload["member"].(map[string]any)
	if !ok {
		t.Fatalf("回應必須帶著 member 這一格，實際 %v", payload)
	}
	return item
}

// memberRoster 讀名冊回應的 members 陣列。
func memberRoster(t *testing.T, resp *http.Response) []map[string]any {
	t.Helper()
	payload := decodeJSONBody(t, resp)
	raw, ok := payload["members"].([]any)
	if !ok {
		t.Fatalf("名冊回應必須帶著 members 陣列，實際 %v", payload)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, row := range raw {
		item, ok := row.(map[string]any)
		if !ok {
			t.Fatalf("名冊每項都該是物件，實際 %T", row)
		}
		out = append(out, item)
	}
	return out
}

// memberOpenPolicy 把「管理員建立普通帳戶」的開關打開（目標帳戶的先導通路）。
func (e *factionEnv) memberOpenPolicy(t *testing.T) {
	t.Helper()
	resp := e.request(t, http.MethodPut, "/root/account-policy", policyBody(true, "closed", false),
		cookieHeader(e.factionRootCookie(t)))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("打開管理員建立開關應成功：%s", body)
	}
}

// memberTargetAccount 由管理員開一位普通帳戶並回傳他的帳戶標識（名冊的目標來源）。
func (e *factionEnv) memberTargetAccount(t *testing.T, admin, login string) string {
	t.Helper()
	e.memberOpenPolicy(t)
	resp := e.request(t, http.MethodPost, "/admin/accounts",
		`{"login_name":"`+login+`","display_name":"名冊裡的玩家","password":"`+activityTestStandardSeed+`"}`,
		admin)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("管理員開設普通帳戶應成功：%d %s", resp.StatusCode, body)
	}
	id, ok := decodeJSONBody(t, resp)["account_id"].(string)
	if !ok || id == "" {
		t.Fatalf("開設回應要帶著帳戶標識：%v", decodeJSONBody(t, resp))
	}
	return id
}

// TestMemberEndpointLifecycle 驗收：草稿期就能備名冊、建立回顯帶著服務端決定的身份與時刻、
// 出生即無陣營（faction_id 是空字串而不是缺席或零值標識）、名冊按加入時刻穩定呈現、
// 改暱稱帶著資料庫現值；而歸檔之後寫入一律 2029、名冊照樣讀得到（仍列、可讀）。
func TestMemberEndpointLifecycle(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "Member.Lifecycle"))
	playerID := e.memberTargetAccount(t, admin, "member.lifecycle.1")
	secondID := e.memberTargetAccount(t, admin, "member.lifecycle.2")

	draftResp := e.request(t, http.MethodPost, "/admin/activities",
		`{"name":"草稿備名冊","description":""}`, admin)
	activityID, _ := mustActivityItem(t, draftResp)["activity_id"].(string)

	// 空名冊是空的但不是錯誤：「還沒有人加入」是可表達的事實。
	empty := memberRoster(t, e.request(t, http.MethodGet,
		"/admin/activities/"+activityID+"/members", "", admin))
	if len(empty) != 0 {
		t.Fatalf("空名冊該是零行，實際 %d 行", len(empty))
	}

	created := e.request(t, http.MethodPost, "/admin/activities/"+activityID+"/members",
		memberCreateBody(playerID, "夜行者"), admin)
	if created.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(created.Body)
		t.Fatalf("草稿期建立成員應回 201：%s", body)
	}
	first := mustMemberItem(t, created)
	if first["activity_id"] != activityID || first["account_id"] != playerID {
		t.Errorf("歸屬與目標由路徑／服務端決定：%v", first)
	}
	if id, _ := first["member_id"].(string); id == "" {
		t.Error("成員標識由服務端產生，該有值")
	}
	// 空字串是「尚未分組」這個合法現值：這一格恆在回應裡，不靠缺席表達。
	value, present := first["faction_id"]
	if !present || value != "" {
		t.Errorf("出生時 faction_id 該是空字串（不是缺席、不是零值標識），實際 %v（present=%v）", value, present)
	}
	if first["display_name"] != "名冊裡的玩家" || first["account_status"] != "active" {
		t.Errorf("名冊行要蓋上帳戶投影，實際 %v／%v", first["display_name"], first["account_status"])
	}
	// 時刻由服務端給（UTC ISO 字串）：介面不需要自己拼「何時算加入」。
	if at, _ := first["joined_at"].(string); !strings.HasSuffix(at, "Z") || !strings.Contains(at, "T") {
		t.Errorf("joined_at 該是 UTC ISO 字串，實際 %q", at)
	}
	if at, _ := first["updated_at"].(string); at == "" {
		t.Errorf("updated_at 該帶著服務端現值，實際 %q", at)
	}

	e.clock.Advance(time.Minute)
	second := mustMemberItem(t, e.request(t, http.MethodPost, "/admin/activities/"+activityID+"/members",
		memberCreateBody(secondID, "另一位玩家"), admin))
	rows := memberRoster(t, e.request(t, http.MethodGet,
		"/admin/activities/"+activityID+"/members", "", admin))
	if len(rows) != 2 || rows[0]["member_id"] != first["member_id"] ||
		rows[1]["member_id"] != second["member_id"] {
		t.Fatalf("名冊應按加入時刻穩定給出兩行，實際 %+v", rows)
	}

	// 改暱稱：帶著列表讀回的現值作依據，回應回讀資料庫現值。
	edited := e.request(t, http.MethodPut,
		"/admin/activities/"+activityID+"/members/"+first["member_id"].(string),
		memberEditBody("改名後的玩家", "夜行者"), admin)
	if edited.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(edited.Body)
		t.Fatalf("改暱稱應成功：%s", body)
	}
	editedItem := mustMemberItem(t, edited)
	if editedItem["nickname"] != "改名後的玩家" {
		t.Errorf("編輯回應要回讀現值，實際 %v", editedItem["nickname"])
	}
	if editedItem["member_id"] != first["member_id"] || editedItem["account_id"] != playerID ||
		editedItem["activity_id"] != activityID {
		t.Errorf("編輯不得動身份三欄：%v", editedItem)
	}
	if editedItem["faction_id"] != "" {
		t.Errorf("改暱稱不得順手寫入陣營歸屬，實際 %v", editedItem["faction_id"])
	}

	// 歸檔是終態：寫入一律 2029，讀取照常、行仍列。
	if resp := e.request(t, http.MethodPut, "/admin/activities/"+activityID+"/status",
		`{"status":"archived"}`, admin); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("歸檔活動應成功：%s", body)
	}
	blocked := e.request(t, http.MethodPut,
		"/admin/activities/"+activityID+"/members/"+first["member_id"].(string),
		memberEditBody("歸檔後想改的", "改名後的玩家"), admin)
	if code, _, _ := memberEnvelope(t, blocked); code != int(CodeActivityArchived) {
		t.Errorf("歸檔態的編輯應拿 2029，實際 %d", code)
	}
	afterRows := memberRoster(t, e.request(t, http.MethodGet,
		"/admin/activities/"+activityID+"/members", "", admin))
	if len(afterRows) != 2 || afterRows[0]["nickname"] != "改名後的玩家" {
		t.Errorf("歸檔態仍列、可讀：名冊應讀到兩行且現值未動，實際 %+v", afterRows)
	}
}

// TestMemberEndpointAdmissionMatrix 驗收：匿名回 2002、普通帳戶回 2011、
// 外人管理員與幽靈活動同碼同文（1001），Root 不受指派限制讀得到任何活動的名冊；
// 而被拒的每一次都沒在庫裡留下一行成員。
func TestMemberEndpointAdmissionMatrix(t *testing.T) {
	e := newFactionEnv(t)
	adminCookie := e.factionAdminCookie(t, "Member.Matrix")
	admin := cookieHeader(adminCookie)
	playerID := e.memberTargetAccount(t, admin, "member.matrix.1")
	activityID := e.createFactionActivity(t, admin, "准入取證的場")
	memberID := mustMemberItem(t, e.request(t, http.MethodPost,
		"/admin/activities/"+activityID+"/members", memberCreateBody(playerID, "管理人加的"),
		admin))["member_id"].(string)
	rowsBefore := e.countMemberRows(t)

	// 匿名：GET 與 POST 都先撞在「沒帶憑據」上。
	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/admin/activities/" + activityID + "/members", ""},
		{http.MethodPost, "/admin/activities/" + activityID + "/members", memberCreateBody(playerID, "匿名加的")},
		{http.MethodPut, "/admin/activities/" + activityID + "/members/" + memberID, memberEditBody("匿名改的", "管理人加的")},
	} {
		resp := e.request(t, tc.method, tc.path, tc.body, "")
		if code, _, _ := memberEnvelope(t, resp); code != int(CodeNotAuthenticated) {
			t.Errorf("%s %s 匿名應回 2002，實際 %d", tc.method, tc.path, code)
		}
	}

	// 普通帳戶（有效會話、零授予）：身分可信，权限不足。
	plain := cookieHeader(e.factionStandardCookie(t, adminCookie, "Member.Plain"))
	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/admin/activities/" + activityID + "/members", ""},
		{http.MethodPost, "/admin/activities/" + activityID + "/members", memberCreateBody(playerID, "平民加的")},
	} {
		resp := e.request(t, tc.method, tc.path, tc.body, plain)
		if code, _, _ := memberEnvelope(t, resp); code != int(CodePermissionDenied) {
			t.Errorf("%s %s 普通帳戶應回 2011，實際 %d", tc.method, tc.path, code)
		}
	}

	// 另一位管理員（持有 server_admin 但沒被指派這個活動）：與幽靈活動逐字同形。
	outsider := cookieHeader(e.factionAdminCookie(t, "Member.Outsider"))
	onReal := e.request(t, http.MethodGet, "/admin/activities/"+activityID+"/members", "", outsider)
	onGhost := e.request(t, http.MethodGet, "/admin/activities/"+memberGhostActivityID+"/members", "", outsider)
	codeReal, msgReal, _ := memberEnvelope(t, onReal)
	codeGhost, msgGhost, _ := memberEnvelope(t, onGhost)
	if codeReal != int(CodeNotFound) || codeGhost != int(CodeNotFound) {
		t.Errorf("外人身管理員與幽靈都該回 1001，實際 %d／%d", codeReal, codeGhost)
	}
	if msgReal != msgGhost || onReal.StatusCode != onGhost.StatusCode {
		t.Errorf("兩句必須同碼同文同狀態，否則就是可枚舉信號：%q vs %q", msgReal, msgGhost)
	}

	// Root 讀得到任何活動的名冊（它不受指派約束）。
	if rows := memberRoster(t, e.request(t, http.MethodGet,
		"/admin/activities/"+activityID+"/members", "", cookieHeader(e.factionRootCookie(t)))); len(rows) != 1 {
		t.Errorf("Root 應讀到那一行，實際 %d 行", len(rows))
	}
	if got := e.countMemberRows(t); got != rowsBefore {
		t.Errorf("被拒的三路都不該落庫，前 %d 行／實際 %d 行", rowsBefore, got)
	}
}

// TestMemberEndpointBodyWhitelist 驗收：本體沒有格子能宣稱身分、歸屬、陣營或角色——
// 帶著它們來的請求在協定層就被 1004 點名，一個字都不落庫；暱稱不合法同样点名這一欄。
func TestMemberEndpointBodyWhitelist(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "Member.Body"))
	playerID := e.memberTargetAccount(t, admin, "member.body.1")
	activityID := e.createFactionActivity(t, admin, "本體白名單的場")
	rowsBefore := e.countMemberRows(t)
	auditsBefore := e.countMemberAudits(t, "member.create")

	injected := []struct {
		what string
		body map[string]any
	}{
		{"宣稱陣營歸屬", map[string]any{"account_id": playerID, "nickname": "想自報陣營", "faction_id": memberGhostActivityID}},
		{"宣稱成員標識", map[string]any{"account_id": playerID, "nickname": "想自報id", "member_id": memberGhostActivityID}},
		{"宣稱歸屬活動", map[string]any{"account_id": playerID, "nickname": "想換活動", "activity_id": activityID}},
		{"宣稱角色", map[string]any{"account_id": playerID, "nickname": "想加權", "role": "manager"}},
		{"宣稱操作者", map[string]any{"account_id": playerID, "nickname": "想頂名", "actor_id": playerID}},
		{"宣稱時刻", map[string]any{"account_id": playerID, "nickname": "想填時間", "created_at": "2020-01-01T00:00:00Z"}},
	}
	for _, tc := range injected {
		encoded, err := json.Marshal(tc.body)
		if err != nil {
			t.Fatalf("序列化測試本體失敗：%v", err)
		}
		resp := e.request(t, http.MethodPost, "/admin/activities/"+activityID+"/members",
			string(encoded), admin)
		code, _, _ := memberEnvelope(t, resp)
		if code != int(CodeInvalidBody) || resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s：該被 1004 殺掉，實際 %d／%d", tc.what, code, resp.StatusCode)
		}
	}

	// 每一格非法寫法都點名是哪一欄（介面據此標紅，而不是對著整份表單猜）。
	nickNames := []struct {
		what  string
		input string
	}{
		{"空暱稱", ""},
		{"全空白", "   "},
		{"超長暱稱", strings.Repeat("長", 65)},
	}
	for _, tc := range nickNames {
		resp := e.request(t, http.MethodPost, "/admin/activities/"+activityID+"/members",
			memberCreateBody(playerID, tc.input), admin)
		code, _, details := memberEnvelope(t, resp)
		if code != int(CodeInvalidBody) {
			t.Errorf("%s：該回 1004，實際 %d", tc.what, code)
		}
		if field, _ := details["invalid_field"].(string); field != "nickname" {
			t.Errorf("%s：要點名 nickname，實際 %v", tc.what, details)
		}
	}

	// 目標標識寫壞與查無此人同形（不讓端點變成標識格式探測器）。
	bad := e.request(t, http.MethodPost, "/admin/activities/"+activityID+"/members",
		memberCreateBody("not-a-uuid", "壞標識"), admin)
	ghost := e.request(t, http.MethodPost, "/admin/activities/"+activityID+"/members",
		memberCreateBody(memberGhostAccountID, "幽靈標識"), admin)
	codeBad, _, _ := memberEnvelope(t, bad)
	codeGhost, _, _ := memberEnvelope(t, ghost)
	if codeBad != int(CodeNotFound) || codeGhost != int(CodeNotFound) || bad.StatusCode != ghost.StatusCode {
		t.Errorf("壞標識與幽靈都該是 1001／同狀態，實際 %d／%d", codeBad, codeGhost)
	}

	// 編輯那一條同樣沒有陣營那一格：帶著 faction_id 來的 PUT 在協定層就被殺。
	created := mustMemberItem(t, e.request(t, http.MethodPost,
		"/admin/activities/"+activityID+"/members", memberCreateBody(playerID, "要改名的"), admin))
	bodyWithFaction, err := json.Marshal(map[string]any{
		"nickname": "改名", "expected_nickname": "要改名的", "faction_id": memberGhostActivityID,
	})
	if err != nil {
		t.Fatalf("序列化測試本體失敗：%v", err)
	}
	resp := e.request(t, http.MethodPut,
		"/admin/activities/"+activityID+"/members/"+created["member_id"].(string),
		string(bodyWithFaction), admin)
	if code, _, _ := memberEnvelope(t, resp); code != int(CodeInvalidBody) {
		t.Errorf("PUT 帶 faction_id 該被 1004 殺掉，實際 %d", code)
	}
	if got := e.countMemberRows(t); got != rowsBefore+1 {
		t.Errorf("白名單之外的請求只該留下那一次合法建立，前 %d 行／實際 %d 行", rowsBefore, got)
	}
	if got := e.countMemberAudits(t, "member.create"); got != auditsBefore+1 {
		t.Errorf("被協定層殺掉的寫入不該留審計，前 %d 筆／實際 %d 筆", auditsBefore, got)
	}
}

// TestMemberEndpointDuplicateAndIneligibleTarget 驗收：重複建立拿到 2035（既不覆也不謊報），
// 不合格目標（終態帳戶）拿到與幽靈同形的 1001，兩者都零落地、零留痕。
func TestMemberEndpointDuplicateAndIneligibleTarget(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "Member.Dup"))
	playerID := e.memberTargetAccount(t, admin, "member.dup.1")
	activityID := e.createFactionActivity(t, admin, "重複取證的場")

	once := e.request(t, http.MethodPost, "/admin/activities/"+activityID+"/members",
		memberCreateBody(playerID, "唯一的檔案"), admin)
	if once.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(once.Body)
		t.Fatalf("第一次建立應成功：%s", body)
	}
	rowsBefore := e.countMemberRows(t)
	auditsBefore := e.countMemberAudits(t, "member.create")

	dup := e.request(t, http.MethodPost, "/admin/activities/"+activityID+"/members",
		memberCreateBody(playerID, "第二次提交想覆蓋"), admin)
	code, _, _ := memberEnvelope(t, dup)
	if code != int(CodeActivityMemberTaken) || dup.StatusCode != http.StatusConflict {
		t.Errorf("重複建立應回 2035／409，實際 %d／%d", code, dup.StatusCode)
	}
	// 既有檔案不被第二次提交覆蓋（正確性來自 UNIQUE，不來自先查）。
	rows := memberRoster(t, e.request(t, http.MethodGet,
		"/admin/activities/"+activityID+"/members", "", admin))
	if len(rows) != 1 || rows[0]["nickname"] != "唯一的檔案" {
		t.Errorf("被拒的重複動了名冊：實際 %+v", rows)
	}

	// 已被軟刪除的帳戶：與幽靈標識同碼同文（不為管理人另開一句「他被刪了」）。
	victimID := e.memberTargetAccount(t, admin, "member.dup.deleted")
	if resp := e.request(t, http.MethodDelete, "/admin/accounts/"+victimID, "", admin); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 軟刪除測試帳戶應成功：%d %s", resp.StatusCode, body)
	}
	deletedResp := e.request(t, http.MethodPost, "/admin/activities/"+activityID+"/members",
		memberCreateBody(victimID, "被刪的人想加入"), admin)
	ghostResp := e.request(t, http.MethodPost, "/admin/activities/"+activityID+"/members",
		memberCreateBody(memberGhostAccountID, "幽靈想加入"), admin)
	codeDeleted, msgDeleted, _ := memberEnvelope(t, deletedResp)
	codeGhost, msgGhost, _ := memberEnvelope(t, ghostResp)
	if codeDeleted != int(CodeNotFound) || codeGhost != int(CodeNotFound) {
		t.Errorf("終態目標與幽靈都該收斂成 1001，實際 %d／%d", codeDeleted, codeGhost)
	}
	if msgDeleted != msgGhost || deletedResp.StatusCode != ghostResp.StatusCode {
		t.Errorf("兩句必須同碼同文同狀態，否則多了一枚列舉信號：%q vs %q", msgDeleted, msgGhost)
	}
	if got := e.countMemberRows(t); got != rowsBefore {
		t.Errorf("2035 與兩次不合格都不該落庫，前 %d 行／實際 %d 行", rowsBefore, got)
	}
	if got := e.countMemberAudits(t, "member.create"); got != auditsBefore {
		t.Errorf("被拒的寫入不該留審計，前 %d 筆／實際 %d 筆", auditsBefore, got)
	}
}

// TestMemberEndpointClosedWritesThenReopen 驗收：停止態的名冊寫入拿 2033（處置是等重開）、
// 重新開放之後同一句話翻案；併發下後到的改名拿 2013 且贏家不被覆蓋。
func TestMemberEndpointClosedWritesThenReopen(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "Member.Closed"))
	playerID := e.memberTargetAccount(t, admin, "member.closed.1")
	activityID := e.createFactionActivity(t, admin, "停止取證的場")
	created := mustMemberItem(t, e.request(t, http.MethodPost,
		"/admin/activities/"+activityID+"/members", memberCreateBody(playerID, "停止前的名字"), admin))
	memberID, _ := created["member_id"].(string)

	if resp := e.request(t, http.MethodPut, "/admin/activities/"+activityID+"/status",
		`{"status":"closed"}`, admin); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("停止活動應成功：%s", body)
	}
	closedCreate := e.request(t, http.MethodPost, "/admin/activities/"+activityID+"/members",
		memberCreateBody(e.memberTargetAccount(t, admin, "member.closed.2"), "停止期想加的"), admin)
	if code, _, _ := memberEnvelope(t, closedCreate); code != int(CodeActivityClosedWrites) {
		t.Errorf("停止態的建立應拿 2033，實際 %d", code)
	}
	closedEdit := e.request(t, http.MethodPut,
		"/admin/activities/"+activityID+"/members/"+memberID,
		memberEditBody("停止期想改的", "停止前的名字"), admin)
	if code, _, _ := memberEnvelope(t, closedEdit); code != int(CodeActivityClosedWrites) {
		t.Errorf("停止態的編輯應拿 2033，實際 %d", code)
	}
	// 停止態仍列、可讀。
	if rows := memberRoster(t, e.request(t, http.MethodGet,
		"/admin/activities/"+activityID+"/members", "", admin)); len(rows) != 1 ||
		rows[0]["nickname"] != "停止前的名字" {
		t.Errorf("停止態名冊該照讀且現值未動，實際 %+v", rows)
	}

	// 重新開放：同一句話翻案（停止不是終態）。
	if resp := e.request(t, http.MethodPut, "/admin/activities/"+activityID+"/status",
		`{"status":"active"}`, admin); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("重新開放應成功：%s", body)
	}
	reopened := e.request(t, http.MethodPut,
		"/admin/activities/"+activityID+"/members/"+memberID,
		memberEditBody("重開後改的名", "停止前的名字"), admin)
	if reopened.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(reopened.Body)
		t.Fatalf("重開後的同一句應成功：%s", body)
	}

	// 併發：兩人對著同一份畫面改名，後到的拿 2013，贏家的值不動。
	stale := e.request(t, http.MethodPut,
		"/admin/activities/"+activityID+"/members/"+memberID,
		memberEditBody("輸家的名字", "停止前的名字"), admin)
	if code, _, _ := memberEnvelope(t, stale); code != int(CodeProfileConflict) {
		t.Errorf("過期依據值的改名應拿 2013，實際 %d", code)
	}
	rows := memberRoster(t, e.request(t, http.MethodGet,
		"/admin/activities/"+activityID+"/members", "", admin))
	if rows[0]["nickname"] != "重開後改的名" {
		t.Errorf("落敗的改名覆蓋了贏家：實際 %v", rows[0]["nickname"])
	}
}

// TestMemberEndpointMethodsAndForeignOrigin 驗收：這一族沒有 DELETE（405 且 Allow 如實說出
// 支援的方法），跨站來源的寫入一律 2005，而讀取不受影響。
func TestMemberEndpointMethodsAndForeignOrigin(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "Member.Methods"))
	playerID := e.memberTargetAccount(t, admin, "member.methods.1")
	activityID := e.createFactionActivity(t, admin, "方法與來源取證的場")
	memberID := mustMemberItem(t, e.request(t, http.MethodPost,
		"/admin/activities/"+activityID+"/members", memberCreateBody(playerID, "會被試著刪除的人"),
		admin))["member_id"].(string)

	notFound := e.request(t, http.MethodDelete,
		"/admin/activities/"+activityID+"/members/"+memberID, "", admin)
	code, _, _ := memberEnvelope(t, notFound)
	if code != int(CodeMethodNotAllowed) || notFound.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("名冊這一族不該有 DELETE，實際 %d／%d", code, notFound.StatusCode)
	}
	if allow := notFound.Header.Get("Allow"); strings.Contains(allow, http.MethodDelete) {
		t.Errorf("Allow 標頭不得宣稱支援 DELETE：實際 %q", allow)
	}

	// 跨站來源：寫入一律先撞 CSRF 閘（2005），讀取不受影響。
	req, err := http.NewRequest(http.MethodPost,
		e.ts.URL+"/admin/activities/"+activityID+"/members",
		strings.NewReader(memberCreateBody(e.memberTargetAccount(t, admin, "member.methods.2"), "跨站想加的")))
	if err != nil {
		t.Fatalf("建立請求失敗：%v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", admin)
	req.Header.Set("Origin", "http://not-this-host.example")
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("跨站請求失敗：%v", err)
	}
	defer resp.Body.Close()
	if code, _, _ := memberEnvelope(t, resp); code != int(CodeOriginForbidden) {
		t.Errorf("跨站來源的寫入應拿 2005，實際 %d", code)
	}
	if rows := memberRoster(t, e.request(t, http.MethodGet,
		"/admin/activities/"+activityID+"/members", "", admin)); len(rows) != 1 {
		t.Errorf("被 CSRF 擋下的寫入不該多出一行，實際 %d 行", len(rows))
	}
}

// memberEnvelope 讀出錯誤信封的碼、訊息與細節（envelope 那個共用 helper 只回前兩項，
// 而這一組端點要斷言 1004 點名的是哪一欄，因此多取 Details 一格）。
func memberEnvelope(t *testing.T, resp *http.Response) (int, string, map[string]any) {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	var got struct {
		Code      int            `json:"code"`
		Message   string         `json:"message"`
		Details   map[string]any `json:"details"`
		RequestID string         `json:"request_id"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("錯誤回應應為 JSON 信封，實際 %q", body)
	}
	return got.Code, got.Message, got.Details
}

// countMemberRows 數名冊行（每一次被拒的寫入都以「庫裡沒多東西」取證）。
func (e *factionEnv) countMemberRows(t *testing.T) int {
	t.Helper()
	var got int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM activity_members").Scan(&got); err != nil {
		t.Fatalf("統計成員行失敗：%v", err)
	}
	return got
}

// countMemberAudits 數活動域審計裡某個動作有幾筆。
func (e *factionEnv) countMemberAudits(t *testing.T, action string) int {
	t.Helper()
	var got int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM activity_audit WHERE action = ?", action).Scan(&got); err != nil {
		t.Fatalf("統計審計 %s 失敗：%v", action, err)
	}
	return got
}
