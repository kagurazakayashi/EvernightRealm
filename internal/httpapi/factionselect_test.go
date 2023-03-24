// factionselect_test.go 是「玩家自選陣營與活動開關」在傳輸層的端到端證據：
// 一位管理人打開開關、玩家讀自己的現況並把歸屬選下去，各路徑各自的準入矩陣
// （匿名、非成員帳戶、外人管理員、Root、本人）、開關與生命週期四句各自對映到哪一枚碼、
// 本體欄位白名單（含「順手宣稱 member_id／account_id／activity_id／角色／派生值」）、
// 跨活動與幽靈標識的同碼同文、寫入者只能動到自己、併發與結果不明下的 2013，
// 以及這一族不宣稱 DELETE 與跨站來源一律 2005。
//
// 刻意不收的東西：
//   - 沒有替身：授權、活動作用域判定、業務門禁、本人成員行核實、陣營可用性判定、
//     CAS 與審計都跨層走真路徑（真資料庫＋真會話＋注入時鐘），接錯線就會紅；
//   - 不測管理側的分配與遷出：那條通路尚未落地，本檔斷言只到「玩家自己選下去之後
//     名冊那一側讀得到同一個現值」，不偽造任何「管理人把他搬進哪一組」的形態；
//   - 不碰真實數據目錄、不佔 5206，全程本次專屬的臨時庫。
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// selfGhostActivityID 是一個合法形狀但從未存在的活動標識（不可分辨性的對照組）。
const selfGhostActivityID = "0192f0c4-1c9a-7000-8000-000000000f31"

// selfGhostFactionID 是一個合法形狀但從未存在的陣營標識（同一句對照組）。
const selfGhostFactionID = "0192f0c4-1c9a-7000-8000-000000000f32"

// selfSelectBody 湊一份自選請求的本體：目標陣營加上它所依據的歸屬現值（兩格，不多不少）。
func selfSelectBody(factionID, expectedFactionID string) string {
	encoded, err := json.Marshal(map[string]any{
		"faction_id": factionID, "expected_faction_id": expectedFactionID,
	})
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// selfModeBody 湊一份配置編輯的本體：新模式加上它所依據的現值。
func selfModeBody(mode, expectedMode string) string {
	encoded, err := json.Marshal(map[string]any{"mode": mode, "expected_mode": expectedMode})
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// selfSelectPlayer 由管理員開一位普通帳戶、替他走完首次改密，回傳「他的帳戶標識」
// 與「他完成首改之後的會話標頭」。
//
// 兩樣都要：帳戶標識是管理人把他加入名冊的輸入，會話則是玩家自己敲 /player 那一族的憑據。
// 這一條鏈逐字沿用 activityEnv 那批交付通路（開設→登陸→改密→再登陸），
// 因此「未改密就碰業務」早已被門閂擋住，本檔不另證一次。
func (e *factionEnv) selfSelectPlayer(t *testing.T, admin, login string) (string, string) {
	t.Helper()
	accountID := e.memberTargetAccount(t, admin, login)
	first := loginCookie(t, e.request(t, http.MethodPost, "/auth/login",
		`{"login_name":"`+login+`","password":"`+activityTestStandardSeed+`"}`, ""))
	if resp := e.request(t, http.MethodPost, "/auth/password/change",
		`{"current_password":"`+activityTestStandardSeed+`","new_password":"`+
			activityTestStandardNewPwd+`"}`, cookieHeader(first)); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("玩家首次改密應成功：%s", body)
	}
	return accountID, cookieHeader(loginCookie(t, e.request(t, http.MethodPost, "/auth/login",
		`{"login_name":"`+login+`","password":"`+activityTestStandardNewPwd+`"}`, "")))
}

// selfSetMode 由管理人把某一場活動的自選模式換掉，失敗即終止並回新的一份活動現值。
func (e *factionEnv) selfSetMode(t *testing.T, admin, activityID, mode, expected string) map[string]any {
	t.Helper()
	resp := e.request(t, http.MethodPut, "/admin/activities/"+activityID+"/faction-select",
		selfModeBody(mode, expected), admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("設定模式 %q 應成功：%d %s", mode, resp.StatusCode, body)
	}
	return mustActivityItem(t, resp)
}

// selfCreateFaction 由管理人建立一個陣營，回傳回應裡的那一份現值
// （排序值是服務端在交易內現算的，後續要拿它當依據值，不能硬編 0）。
func (e *factionEnv) selfCreateFaction(t *testing.T, admin, activityID, name string) map[string]any {
	t.Helper()
	resp := e.request(t, http.MethodPost, "/admin/activities/"+activityID+"/factions",
		`{"name":"`+name+`","description":"","icon":"","color":""}`, admin)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("建立陣營 %q 應成功：%d %s", name, resp.StatusCode, body)
	}
	return mustFactionItem(t, resp)
}

// selfFactionID 從一份陣營現值取標識。
func selfFactionID(t *testing.T, item map[string]any) string {
	t.Helper()
	id, _ := item["faction_id"].(string)
	if id == "" {
		t.Fatalf("陣營回應要帶著標識，實際 %v", item)
	}
	return id
}

// selfDisableFaction 以建立回應讀到的每一格現值為依據值，送一次「只翻可用性」的編輯。
func (e *factionEnv) selfDisableFaction(t *testing.T, admin, activityID string, item map[string]any) {
	t.Helper()
	factionID := selfFactionID(t, item)
	resp := e.request(t, http.MethodPut, "/admin/activities/"+activityID+"/factions/"+factionID,
		factionEditBody(item, map[string]any{"available": false}), admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("停用陣營 %q 應成功：%s", factionID, body)
	}
}

// selfAddMember 由管理人把一位既有帳戶加入名冊並回傳他的成員標識。
func (e *factionEnv) selfAddMember(t *testing.T, admin, activityID, accountID, nickname string) string {
	t.Helper()
	resp := e.request(t, http.MethodPost, "/admin/activities/"+activityID+"/members",
		`{"account_id":"`+accountID+`","nickname":"`+nickname+`"}`, admin)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("建立成員 %q 應成功：%d %s", nickname, resp.StatusCode, body)
	}
	id, _ := mustMemberItem(t, resp)["member_id"].(string)
	return id
}

// selfViewPayload 把玩家現況回應讀成一份本體。
//
// 一次讀完整份、之後都問這一塊：*http.Response 的 Body 只能讀一次，
// 每個斷言各自再 ReadAll 一遍會在第二次拿到空本體，於測試裡長出一種「回應是空的」假象。
func selfViewPayload(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("本人讀現況應成功：%d %s", resp.StatusCode, body)
	}
	payload := decodeJSONBody(t, resp)
	for _, key := range []string{"can_select_now", "faction_select_mode", "faction_id", "factions"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("現況回應必須帶著 %q 這一格，實際 %v", key, payload)
		}
	}
	return payload
}

// selfRosterFaction 經管理端名冊讀回某一行的 faction_id
// （「寫入者動到的到底是哪一行」靠這一讀做證據，它與玩家側同源）。
func (e *factionEnv) selfRosterFaction(t *testing.T, admin, activityID, memberID string) string {
	t.Helper()
	resp := e.request(t, http.MethodGet, "/admin/activities/"+activityID+"/members", "", admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("讀名冊應成功：%s", body)
	}
	for _, row := range memberRoster(t, resp) {
		if row["member_id"] == memberID {
			value, ok := row["faction_id"].(string)
			if !ok {
				t.Fatalf("名冊每行都該帶 faction_id，實際 %v", row)
			}
			return value
		}
	}
	t.Fatalf("名冊裡必須找得到成員 %s", memberID)
	return ""
}

// TestFactionSelectEndpointLifecycle 驗收端到端的一趟路：新活動出廠就是 disabled（回應裡
// 那一格讀得到）、管理人打開僅首次、玩家讀自己的現況、把陣營選下去、再讀一次現值已更新，
// 而第二次自助被擋；管理端名冊讀到的是同一個現值（沒有第二個答案來源）。
func TestFactionSelectEndpointLifecycle(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "SelfSel.Lifecycle"))
	activityID := e.createFactionActivity(t, admin, "自選一趟路")
	factionID := selfFactionID(t, e.selfCreateFaction(t, admin, activityID, "黎明軍"))

	// 出廠現值：連剛建立的活動都讀成 disabled（只增不刪地多出來的一格）。
	detail := e.request(t, http.MethodGet, "/admin/activities/"+activityID, "", admin)
	if got := mustActivityItem(t, detail)["faction_select_mode"]; got != "disabled" {
		t.Fatalf("活動回應要帶出自選模式現值 disabled，實際 %v", got)
	}

	playerID, player := e.selfSelectPlayer(t, admin, "selfsel.lifecycle.1")
	memberID := e.selfAddMember(t, admin, activityID, playerID, "深夜行者")

	// 還沒開：玩家讀得到自己的現況，而「此刻不能選」是服務端派生出來的現值。
	closed := selfViewPayload(t, e.request(t, http.MethodGet,
		"/player/activities/"+activityID+"/faction", "", player))
	if closed["can_select_now"] != false {
		t.Error("未開放時 can_select_now 必須是假")
	}
	if closed["faction_select_mode"] != "disabled" {
		t.Errorf("現況要帶出模式現值，實際 %v", closed["faction_select_mode"])
	}
	if closed["faction_id"] != "" {
		t.Errorf("出生即無陣營讀成空字串，實際 %v", closed["faction_id"])
	}

	blocked := e.request(t, http.MethodPut, "/player/activities/"+activityID+"/faction",
		selfSelectBody(factionID, ""), player)
	if code, _, _ := memberEnvelope(t, blocked); code != int(CodeFactionSelectDisabled) {
		t.Fatalf("未開放自選應回 2037，實際 %d", code)
	}

	// 管理人打開「僅首次」：回應帶著新的活動現值，界面據此才長出那顆按鈕。
	updated := e.selfSetMode(t, admin, activityID, "first_only", "disabled")
	if updated["faction_select_mode"] != "first_only" {
		t.Fatalf("配置寫入要回讀新值，實際 %v", updated["faction_select_mode"])
	}
	opened := selfViewPayload(t, e.request(t, http.MethodGet,
		"/player/activities/"+activityID+"/faction", "", player))
	if opened["can_select_now"] != true {
		t.Error("打開後 can_select_now 必須是真")
	}
	options, ok := opened["factions"].([]any)
	if !ok || len(options) != 1 {
		t.Fatalf("候選清單要帶出一個陣營，實際 %v", opened["factions"])
	}
	option := options[0].(map[string]any)
	if option["faction_id"] != factionID || option["selectable"] != true {
		t.Errorf("開著的陣營要標成可選，實際 %v", option)
	}
	if _, exists := option["accepts_new_members"]; exists {
		t.Error("玩家側不該出現管理側那個派生值（兩側算式不同：這一讀還要多問活動是不是開放中）")
	}

	written := e.request(t, http.MethodPut, "/player/activities/"+activityID+"/faction",
		selfSelectBody(factionID, ""), player)
	if written.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(written.Body)
		t.Fatalf("首次自選應成功：%s", body)
	}
	created := decodeJSONBody(t, written)
	if created["faction_id"] != factionID {
		t.Errorf("自選回應要帶著落庫後的歸屬，實際 %v", created["faction_id"])
	}
	if created["member_id"] != memberID {
		t.Errorf("自選回應要帶著本人的成員標識，實際 %v", created["member_id"])
	}
	if _, exists := created["display_name"]; exists {
		t.Error("自選回應不帶帳戶投影：那一格空值的語意是「軟參照讀不回」，會把誤導讀成事實")
	}

	// 重讀：現況與管理端名冊讀到同一個現值（單一權威關係在兩側都同一份）。
	reread := selfViewPayload(t, e.request(t, http.MethodGet,
		"/player/activities/"+activityID+"/faction", "", player))
	if reread["faction_id"] != factionID {
		t.Errorf("重讀現況要帶著新歸屬，實際 %v", reread["faction_id"])
	}
	if got := e.selfRosterFaction(t, admin, activityID, memberID); got != factionID {
		t.Errorf("名冊那一側要讀到同一個現值，實際 %q", got)
	}

	second := e.request(t, http.MethodPut, "/player/activities/"+activityID+"/faction",
		selfSelectBody(factionID, ""), player)
	if code, _, _ := memberEnvelope(t, second); code != int(CodeFactionSelectLockedIn) {
		t.Errorf("僅首次模式下的第二次應回 2039，實際 %d", code)
	}
	if got := e.countMemberAudits(t, "member.faction_select"); got != 1 {
		t.Errorf("被拒的第二次不多記留痕，實際 %d 筆", got)
	}

	// 本人的活動清單：一行，同時帶出那場活動的現值與他自己的歸屬。
	list := decodeJSONBody(t, e.request(t, http.MethodGet, "/player/activities", "", player))
	rows, ok := list["activities"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("本人清單應恰好一行，實際 %v", list["activities"])
	}
	row := rows[0].(map[string]any)
	if row["activity_id"] != activityID || row["member_id"] != memberID ||
		row["faction_id"] != factionID || row["faction_select_mode"] != "first_only" {
		t.Errorf("清單每行要同時帶出活動與本人的現值，實際 %v", row)
	}
	if _, exists := row["status"]; !exists {
		t.Error("清單每行要帶出活動狀態（界面據實顯示「還沒開放」那一句）")
	}
}

// TestFactionSelectEndpointReasons 驗收四句拒絕各有各的碼與處置：沒開放自選（2037）、
// 活動還在草稿（2038）、活動已停止（2033）、目標陣營已停用（2036），歸檔走 2029；
// 而且每一次被拒之後現值逐字不動、留痕不多記一筆。
func TestFactionSelectEndpointReasons(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "SelfSel.Reasons"))

	// 草稿那場：配置可以打開，玩家時機未到。
	draftResp := e.request(t, http.MethodPost, "/admin/activities",
		`{"name":"草稿裡的自選","description":""}`, admin)
	draftID, _ := mustActivityItem(t, draftResp)["activity_id"].(string)
	draftFaction := selfFactionID(t, e.selfCreateFaction(t, admin, draftID, "草稿軍"))
	draftPlayerID, draftPlayer := e.selfSelectPlayer(t, admin, "selfsel.reasons.draft")
	e.selfAddMember(t, admin, draftID, draftPlayerID, "草稿的我")
	e.selfSetMode(t, admin, draftID, "free", "disabled")
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodPut,
		"/player/activities/"+draftID+"/faction", selfSelectBody(draftFaction, ""),
		draftPlayer)); code != int(CodeFactionSelectNotOpen) {
		t.Errorf("草稿應回 2038，實際 %d", code)
	}

	// 開放那一場：先落地一份歸屬，再讓三種拒絕各自問到自己那一句。
	openID := e.createFactionActivity(t, admin, "開放中的自選")
	keptItem := e.selfCreateFaction(t, admin, openID, "留著的軍")
	kept := selfFactionID(t, keptItem)
	stoppedItem := e.selfCreateFaction(t, admin, openID, "停用的軍")
	stopped := selfFactionID(t, stoppedItem)
	openPlayerID, openPlayer := e.selfSelectPlayer(t, admin, "selfsel.reasons.open")
	memberID := e.selfAddMember(t, admin, openID, openPlayerID, "開放的我")
	e.selfSetMode(t, admin, openID, "free", "disabled")
	if resp := e.request(t, http.MethodPut, "/player/activities/"+openID+"/faction",
		selfSelectBody(kept, ""), openPlayer); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("先把歸屬落在留著的軍應成功：%s", body)
	}

	e.selfDisableFaction(t, admin, openID, stoppedItem)
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodPut,
		"/player/activities/"+openID+"/faction", selfSelectBody(stopped, kept),
		openPlayer)); code != int(CodeFactionNotAcceptingMembers) {
		t.Errorf("換進停用陣營應回 2036，實際 %d", code)
	}
	if got := e.selfRosterFaction(t, admin, openID, memberID); got != kept {
		t.Errorf("被拒的自選不能動歸屬，實際 %q", got)
	}
	// 停用的陣營在候選清單裡標成不可選，而本人既有歸屬照樣讀得回來（保留歸屬那句的顯示面）。
	view := selfViewPayload(t, e.request(t, http.MethodGet,
		"/player/activities/"+openID+"/faction", "", openPlayer))
	for _, raw := range view["factions"].([]any) {
		option := raw.(map[string]any)
		switch option["faction_id"] {
		case stopped:
			if option["selectable"] != false {
				t.Error("停用的陣營必須標成不可選")
			}
		case kept:
			if option["selectable"] != true {
				t.Error("還開著的陣營必須標成可選")
			}
		}
	}

	// 停止：等活動重開那一句（與草稿那一句分得開）。
	if resp := e.request(t, http.MethodPut, "/admin/activities/"+openID+"/status",
		`{"status":"closed"}`, admin); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("停止活動應成功：%s", body)
	}
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodPut,
		"/player/activities/"+openID+"/faction", selfSelectBody(kept, ""),
		openPlayer)); code != int(CodeActivityClosedWrites) {
		t.Errorf("停止態應回 2033，實際 %d", code)
	}
	// 停止態下配置仍可編輯（它屬活動自己的資料，與名稱描述同側）。
	e.selfSetMode(t, admin, openID, "free", "free")

	// 歸檔：終態那一句；本人的讀法仍然列、仍然讀得到，配置一律拒寫。
	if resp := e.request(t, http.MethodPut, "/admin/activities/"+openID+"/status",
		`{"status":"archived"}`, admin); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("歸檔活動應成功：%s", body)
	}
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodPut,
		"/player/activities/"+openID+"/faction", selfSelectBody(kept, ""),
		openPlayer)); code != int(CodeActivityArchived) {
		t.Errorf("歸檔態應回 2029，實際 %d", code)
	}
	archived := selfViewPayload(t, e.request(t, http.MethodGet,
		"/player/activities/"+openID+"/faction", "", openPlayer))
	if archived["can_select_now"] != false {
		t.Error("歸檔後 can_select_now 必須是假")
	}
	if archived["faction_id"] != kept {
		t.Errorf("歸檔不改寫任何人已經選過的歸屬，實際 %v", archived["faction_id"])
	}
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodPut,
		"/admin/activities/"+openID+"/faction-select", selfModeBody("disabled", "free"),
		admin)); code != int(CodeActivityArchived) {
		t.Errorf("歸檔後的配置寫入應回 2029，實際 %d", code)
	}
}

// TestFactionSelectEndpointPrincipalMatrix 驗收準入：匿名一律 2002、普通帳戶但非成員一律
// 1001（與幽靈活動逐字同形）、Root 不是任何人的代理因此也拿 1001，
// 而管理端那一條配置通路外人管理員與場內成員都過不去。
func TestFactionSelectEndpointPrincipalMatrix(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "SelfSel.Matrix"))
	outsider := cookieHeader(e.factionAdminCookie(t, "SelfSel.Outsider"))
	openID := e.createFactionActivity(t, admin, "準入矩陣的場")
	factionID := selfFactionID(t, e.selfCreateFaction(t, admin, openID, "矩陣軍"))
	outsiderActivity := e.createFactionActivity(t, outsider, "別人的場")

	playerAccountID, player := e.selfSelectPlayer(t, admin, "selfsel.matrix.1")
	e.selfAddMember(t, admin, openID, playerAccountID, "矩陣裡的玩家")
	_, nonMember := e.selfSelectPlayer(t, admin, "selfsel.matrix.2")
	root := cookieHeader(e.factionRootCookie(t))

	for _, path := range []string{
		"/player/activities",
		"/player/activities/" + openID + "/faction",
	} {
		if code, _, _ := memberEnvelope(t, e.request(t, http.MethodGet, path, "", "")); code !=
			int(CodeNotAuthenticated) {
			t.Errorf("GET %s 匿名應回 2002，實際 %d", path, code)
		}
	}
	ghostPath := "/player/activities/" + selfGhostActivityID + "/faction"
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodGet, ghostPath, "", player)); code !=
		int(CodeNotFound) {
		t.Errorf("幽靈活動的本人讀法應回 1001，實際 %d", code)
	}

	// 非成員的普通帳戶讀「別人的場」與讀幽靈活動逐字同形：多知道哪一個都不該是信號。
	codeReal, msgReal, _ := memberEnvelope(t, e.request(t, http.MethodGet,
		"/player/activities/"+outsiderActivity+"/faction", "", nonMember))
	codeGhost, msgGhost, _ := memberEnvelope(t, e.request(t, http.MethodGet, ghostPath, "", nonMember))
	if codeReal != int(CodeNotFound) || codeGhost != int(CodeNotFound) ||
		msgReal == "" || msgReal != msgGhost {
		t.Errorf("非成員讀別人的活動必須與幽靈同碼同文，實際 %d／%d 與 %q／%q",
			codeReal, codeGhost, msgReal, msgGhost)
	}

	// 非成員在「草稿」與「未開放自選」的活動上動手，拿到的也是 1001，而不是那兩句時機原因：
	// 後端把本人成員行的核實排在時機判定之前，否則這條路徑就成了一枚「那個標識是不是一場活動」的探針。
	draftID := mustActivityItem(t, e.request(t, http.MethodPost, "/admin/activities",
		`{"name":"非成員敲不到的草稿","description":""}`, admin))["activity_id"].(string)
	draftFactionID := selfFactionID(t, e.selfCreateFaction(t, admin, draftID, "草稿軍"))
	codeDraft, msgDraft, _ := memberEnvelope(t, e.request(t, http.MethodPut,
		"/player/activities/"+draftID+"/faction", selfSelectBody(draftFactionID, ""), nonMember))
	if codeDraft != int(CodeNotFound) || msgDraft != msgGhost {
		t.Errorf("非成員在草稿活動上自選都必須與幽靈同碼同文，實際 %d／%q 對比 %d／%q",
			codeDraft, msgDraft, codeGhost, msgGhost)
	}

	// Root 不在 accounts 表裡：他沒有任何一場活動裡的成員身份，因此本人通路一律 1001，
	// 而不是順手取得「全部玩家的現況」，也不能代人自選。
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodGet,
		"/player/activities", "", root)); code != int(CodeNotFound) {
		t.Errorf("Root 的本人清單應回 1001（他沒有成員行），實際 %d", code)
	}
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodPut,
		"/player/activities/"+openID+"/faction", selfSelectBody(factionID, ""),
		root)); code != int(CodeNotFound) {
		t.Errorf("Root 代人自選應回 1001，實際 %d", code)
	}

	// 配置那一條：外人管理員拿到與幽靈同形的 1001，場內成員拿到 2011（他不屬於管理員這個身份面）。
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodPut,
		"/admin/activities/"+openID+"/faction-select", selfModeBody("free", "disabled"),
		outsider)); code != int(CodeNotFound) {
		t.Errorf("外人管理員改別人活動的配置應回 1001，實際 %d", code)
	}
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodPut,
		"/admin/activities/"+selfGhostActivityID+"/faction-select",
		selfModeBody("free", "disabled"), outsider)); code != int(CodeNotFound) {
		t.Errorf("幽靈活動的配置寫入必須與外人同形，實際 %d", code)
	}
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodPut,
		"/admin/activities/"+openID+"/faction-select", selfModeBody("free", "disabled"),
		player)); code != int(CodePermissionDenied) {
		t.Errorf("場內成員改活動配置應回 2011，實際 %d", code)
	}
	if got := mustActivityItem(t, e.request(t, http.MethodGet,
		"/admin/activities/"+openID, "", admin))["faction_select_mode"]; got != "disabled" {
		t.Errorf("上面那幾次被拒的配置寫入不得動現值，實際 %v", got)
	}

	// 「我還沒參加任何活動」是一句事實：空清單，而不是錯誤或別人的清單。
	emptyList := decodeJSONBody(t, e.request(t, http.MethodGet, "/player/activities", "", nonMember))
	if rows, ok := emptyList["activities"].([]any); !ok || len(rows) != 0 {
		t.Errorf("非成員的本人清單必須是空陣列，實際 %v", emptyList["activities"])
	}
}

// TestFactionSelectEndpointBodyWhitelist 驗收本體形態：配置編輯只認 mode 與 expected_mode、
// 自選只認 faction_id 與 expected_faction_id，任何一格宣稱「我是誰／動的是誰／派生值」
// 都在協定層被點名；而標識寫壞與查無此人同形。
func TestFactionSelectEndpointBodyWhitelist(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "SelfSel.Body"))
	openID := e.createFactionActivity(t, admin, "白名單的場")
	factionID := selfFactionID(t, e.selfCreateFaction(t, admin, openID, "白名單軍"))
	playerAccountID, player := e.selfSelectPlayer(t, admin, "selfsel.body.1")
	e.selfAddMember(t, admin, openID, playerAccountID, "白名單的我")
	e.selfSetMode(t, admin, openID, "free", "disabled")

	selfPath := "/player/activities/" + openID + "/faction"
	modePath := "/admin/activities/" + openID + "/faction-select"
	cases := []struct {
		name   string
		path   string
		body   string
		who    string
		code   int
		reason string
		field  string
	}{
		{"宣稱成員標識", selfPath,
			`{"faction_id":"` + factionID + `","expected_faction_id":"","member_id":"m"}`,
			player, int(CodeInvalidBody), "unknown field", "member_id"},
		{"宣稱帳戶標識", selfPath,
			`{"faction_id":"` + factionID + `","expected_faction_id":"","account_id":"` +
				playerAccountID + `"}`, player, int(CodeInvalidBody), "unknown field", "account_id"},
		{"宣稱歸屬活動", selfPath,
			`{"faction_id":"` + factionID + `","expected_faction_id":"","activity_id":"` +
				openID + `"}`, player, int(CodeInvalidBody), "unknown field", "activity_id"},
		{"宣稱角色", selfPath,
			`{"faction_id":"` + factionID + `","expected_faction_id":"","role":"server_admin"}`,
			player, int(CodeInvalidBody), "unknown field", "role"},
		{"宣稱派生值", selfPath,
			`{"faction_id":"` + factionID + `","expected_faction_id":"","can_select_now":true}`,
			player, int(CodeInvalidBody), "unknown field", "can_select_now"},
		{"宣稱活動狀態", modePath,
			`{"mode":"free","expected_mode":"free","status":"active"}`,
			admin, int(CodeInvalidBody), "unknown field", "status"},
		{"缺目標格", selfPath, `{"expected_faction_id":""}`,
			player, int(CodeNotFound), "", ""},
		{"目標寫壞", selfPath, `{"faction_id":"not-a-uuid","expected_faction_id":""}`,
			player, int(CodeNotFound), "", ""},
		{"目標是幽靈陣營", selfPath,
			`{"faction_id":"` + selfGhostFactionID + `","expected_faction_id":""}`,
			player, int(CodeNotFound), "", ""},
		{"清空歸屬的寫法", selfPath, selfSelectBody("", factionID),
			player, int(CodeNotFound), "", ""},
		{"目標與依據同一格", selfPath, selfSelectBody(factionID, factionID),
			player, int(CodeInvalidBody), "", "faction_id"},
		{"模式取值在集合外", modePath, selfModeBody("unlimited", "free"),
			admin, int(CodeInvalidBody), "", "mode"},
	}
	for _, caseOf := range cases {
		resp := e.request(t, http.MethodPut, caseOf.path, caseOf.body, caseOf.who)
		code, _, details := memberEnvelope(t, resp)
		if code != caseOf.code {
			t.Errorf("%s 應回 %d，實際 %d", caseOf.name, caseOf.code, code)
			continue
		}
		if caseOf.reason != "" && details["reason"] != caseOf.reason {
			t.Errorf("%s 的拒絕要如實說明 %q，實際 details %v", caseOf.name, caseOf.reason, details)
		}
		if caseOf.field != "" && details["field"] != caseOf.field &&
			details["invalid_field"] != caseOf.field {
			t.Errorf("%s 的拒絕要點名 %q，實際 details %v", caseOf.name, caseOf.field, details)
		}
	}
	// 被點名的這幾次都沒落地：留痕一筆都沒多，本人現值仍是尚未分組。
	if got := e.countMemberAudits(t, "member.faction_select"); got != 0 {
		t.Errorf("本體白名單的每一次拒絕都不記留痕，實際 %d 筆", got)
	}
	view := selfViewPayload(t, e.request(t, http.MethodGet, selfPath, "", player))
	if view["faction_id"] != "" {
		t.Errorf("白名單取證之後本人現值必須仍是尚未分組，實際 %v", view["faction_id"])
	}
}

// TestFactionSelectEndpointSelfOnly 驗收「寫入者只能動到自己」在端點上的形態：
// 兩個玩家各自的會話選下去，名冊裡兩行各自更新，誰也碰不到誰。
func TestFactionSelectEndpointSelfOnly(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "SelfSel.Only"))
	openID := e.createFactionActivity(t, admin, "只動自己")
	left := selfFactionID(t, e.selfCreateFaction(t, admin, openID, "左軍"))
	right := selfFactionID(t, e.selfCreateFaction(t, admin, openID, "右軍"))
	e.selfSetMode(t, admin, openID, "free", "disabled")

	firstID, first := e.selfSelectPlayer(t, admin, "selfsel.only.1")
	secondID, second := e.selfSelectPlayer(t, admin, "selfsel.only.2")
	firstMember := e.selfAddMember(t, admin, openID, firstID, "甲行")
	secondMember := e.selfAddMember(t, admin, openID, secondID, "乙行")

	if resp := e.request(t, http.MethodPut, "/player/activities/"+openID+"/faction",
		selfSelectBody(left, ""), first); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("甲的自選應成功：%s", body)
	}
	if got := e.selfRosterFaction(t, admin, openID, secondMember); got != "" {
		t.Errorf("甲的自選不能動到乙那一行，實際 %q", got)
	}
	if resp := e.request(t, http.MethodPut, "/player/activities/"+openID+"/faction",
		selfSelectBody(right, ""), second); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("乙的自選應成功：%s", body)
	}
	if got := e.selfRosterFaction(t, admin, openID, firstMember); got != left {
		t.Errorf("乙的自選不能覆蓋甲那一行，實際 %q", got)
	}
	if got := e.selfRosterFaction(t, admin, openID, secondMember); got != right {
		t.Errorf("乙那一行要落在右軍，實際 %q", got)
	}

	// 兩筆留痕的操作者各是本人的成員標識（不是帳戶標識，也不是管理人）。
	var actors []string
	rows, err := e.db.SQL().Query(`SELECT actor_kind, COALESCE(actor_id, ''), target_id
		FROM activity_audit WHERE action = 'member.faction_select'
		ORDER BY created_at ASC, id ASC`)
	if err != nil {
		t.Fatalf("讀取自選留痕失敗：%v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind, actor, target string
		if err := rows.Scan(&kind, &actor, &target); err != nil {
			t.Fatalf("解析自選留痕失敗：%v", err)
		}
		if kind != "player" || actor == "" || actor != target {
			t.Errorf("留痕的操作者必須是玩家身份且等於目標成員行，實際 %s／%s／%s", kind, actor, target)
		}
		actors = append(actors, actor)
	}
	if len(actors) != 2 || actors[0] != firstMember || actors[1] != secondMember {
		t.Errorf("兩次自選各記一筆、按序是甲與乙的成員標識，實際 %v", actors)
	}
}

// TestFactionSelectEndpointStaleAndRetry 驗收併發與結果不明：拿過期的歸屬現值提交回 2013
// 且不覆蓋贏家；同一份請求原樣重發時第二次仍是 2013（而不是「又切換一次」），
// 於是客戶重讀之後不會重複產生切換與審計。配置那一側同形。
func TestFactionSelectEndpointStaleAndRetry(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "SelfSel.Stale"))
	openID := e.createFactionActivity(t, admin, "過期現值")
	left := selfFactionID(t, e.selfCreateFaction(t, admin, openID, "左軍"))
	right := selfFactionID(t, e.selfCreateFaction(t, admin, openID, "右軍"))
	third := selfFactionID(t, e.selfCreateFaction(t, admin, openID, "第三軍"))
	e.selfSetMode(t, admin, openID, "free", "disabled")

	playerID, player := e.selfSelectPlayer(t, admin, "selfsel.stale.1")
	memberID := e.selfAddMember(t, admin, openID, playerID, "戊")

	if resp := e.request(t, http.MethodPut, "/player/activities/"+openID+"/faction",
		selfSelectBody(left, ""), player); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("首次自選應成功：%s", body)
	}
	// 第二個裝置仍拿著「他還沒分組」這份舊現值：目標合法、依據過期，回 2013。
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodPut,
		"/player/activities/"+openID+"/faction", selfSelectBody(right, ""),
		player)); code != int(CodeProfileConflict) {
		t.Errorf("依據值已過期應回 2013，實際 %d", code)
	}
	if got := e.selfRosterFaction(t, admin, openID, memberID); got != left {
		t.Errorf("落敗者不得覆蓋贏家，實際 %q", got)
	}
	// 結果不明後的補發同形：同一份過期依據值不會再切換一次。
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodPut,
		"/player/activities/"+openID+"/faction", selfSelectBody(third, ""),
		player)); code != int(CodeProfileConflict) {
		t.Errorf("補發同一份過期請求應再拿 2013，實際 %d", code)
	}
	if got := e.countMemberAudits(t, "member.faction_select"); got != 1 {
		t.Errorf("只有那一次成功的切換留下留痕，實際 %d 筆", got)
	}
	// 帶著正確現值的那一次仍然走得通：2013 的出口是重讀，不是這件事永遠做不了。
	if resp := e.request(t, http.MethodPut, "/player/activities/"+openID+"/faction",
		selfSelectBody(third, left), player); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("帶著正確依據值的自選應成功：%s", body)
	}
	// 配置那一側同形：過期的 expected_mode 回 2013，現值不動。
	if code, _, _ := memberEnvelope(t, e.request(t, http.MethodPut,
		"/admin/activities/"+openID+"/faction-select", selfModeBody("disabled", "first_only"),
		admin)); code != int(CodeProfileConflict) {
		t.Errorf("配置依據值過期應回 2013，實際 %d", code)
	}
	detail := mustActivityItem(t, e.request(t, http.MethodGet,
		"/admin/activities/"+openID, "", admin))
	if detail["faction_select_mode"] != "free" {
		t.Errorf("落敗的配置保存不得改寫現值，實際 %v", detail["faction_select_mode"])
	}
}

// TestFactionSelectEndpointShapeAndCrossSite 驗收這一路徑族不宣稱 DELETE（本步沒有清空歸屬的
// 通路），配置那一條只長 PUT，以及跨站來源一律 2005 且一個字都沒落。
func TestFactionSelectEndpointShapeAndCrossSite(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "SelfSel.Shape"))
	openID := e.createFactionActivity(t, admin, "形狀取證")
	factionID := selfFactionID(t, e.selfCreateFaction(t, admin, openID, "形狀軍"))
	e.selfSetMode(t, admin, openID, "free", "disabled")
	playerID, player := e.selfSelectPlayer(t, admin, "selfsel.shape.1")
	memberID := e.selfAddMember(t, admin, openID, playerID, "己")

	deleteResp := e.request(t, http.MethodDelete, "/player/activities/"+openID+"/faction", "", player)
	if deleteResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("這一族不該有 DELETE，實際 %d", deleteResp.StatusCode)
	}
	if allow := deleteResp.Header.Get("Allow"); strings.Contains(strings.ToLower(allow), "delete") {
		t.Errorf("405 的 Allow 不可宣稱 DELETE，實際 %q", allow)
	}
	if resp := e.request(t, http.MethodPost, "/admin/activities/"+openID+"/faction-select",
		selfModeBody("free", "free"), admin); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("配置通路不該有 POST，實際 %d", resp.StatusCode)
	}

	crossSite, err := http.NewRequest(http.MethodPut,
		e.ts.URL+"/player/activities/"+openID+"/faction",
		strings.NewReader(selfSelectBody(factionID, "")))
	if err != nil {
		t.Fatalf("構造跨站請求失敗：%v", err)
	}
	crossSite.Header.Set("Content-Type", "application/json")
	crossSite.Header.Set("Cookie", player)
	crossSite.Header.Set("Origin", "http://evil.example")
	resp, err := e.ts.Client().Do(crossSite)
	if err != nil {
		t.Fatalf("跨站請求失敗：%v", err)
	}
	defer resp.Body.Close()
	if code, _, _ := memberEnvelope(t, resp); code != int(CodeOriginForbidden) {
		t.Errorf("跨站來源應回 2005，實際 %d", code)
	}
	if got := e.selfRosterFaction(t, admin, openID, memberID); got != "" {
		t.Errorf("被擋的跨站寫入不能動歸屬，實際 %q", got)
	}
}
