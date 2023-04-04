// memberrestrictions_test.go 是「玩家分項限制與活動訪問控制」在傳輸層的端到端證據：
// 名冊與玩家讀法帶著六欄現值（出廠全假）、逐欄白名單（一欄都没帶與孤零的依據值都是
// 1004 點名）、多欄一次翻、取消一欄不動另一欄、併發落敗回 2013、冪等重送零留痕、
// 被禁止登入後玩家族全部通路回 403／2043 而本人查閱與清單照舊、解除後的下一筆請求
// 即恢復、跨活動與幽灵同收 1001、普通帳戶 2011、匿名 2002、業務寫入門禁 2033／2029，
// 以及留痕帶真實操作者與逐欄前後值。
//
// 刻意不收的東西：
//   - 不重複 internal/activity 的服務層矩陣：那一側已取證的結論，這裡只問協定形態；
//   - 不碰真實資料目錄、不佔 5206，全程本次專屬的臨時庫與注入時鐘；
//   - 不宣稱任何推送或即時失效：這一切的取證形態都是「下一筆請求按現值回答」；
//   - 聊天／私聊／交易／轉賬／使用物品今日沒有業務端點，本檔不發、也不測任何
//     與它們對應的機器碼——只測旗標的保存、顯示與 login 那一条訪問判定。
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// 本檔使用的幽靈標識：合法形狀但從未存在（不可分辨性要比對它）。
const (
	restrictionGhostMember = "0192f0c4-1c9a-7000-8000-000000000fe1"
)

// restrictionField 是六欄在回應裡的欄位名（名冊、本人查閱與編輯回顯共用同一份清單）。
var restrictionFields = []string{
	"restrict_login", "restrict_chat", "restrict_private_chat",
	"restrict_trade", "restrict_transfer", "restrict_item_use",
}

// restrictionPair 湊一對「新值＋依據值」進本體。
func restrictionPair(body map[string]any, field string, value, expected bool) {
	body[field] = value
	body["expected_"+field] = expected
}

// restrictionTransScene 是本檔共用的輕量現場：一場已開放的活動、一位獲指派的管理人、
// 兩位場内玩家（都有會話，其中甲是要被限制的目標）、另一場由同一管理人管的活動。
type restrictionTransScene struct {
	env             *factionEnv
	admin           string
	activity        string
	other           string
	player          string // 目標玩家的會話標頭
	member          string // 目標玩家的成員標識
	bystander       string // 另一位玩家的會話標頭
	bystanderMember string
}

func newRestrictionTransScene(t *testing.T) *restrictionTransScene {
	t.Helper()
	e := newFactionEnv(t)
	s := &restrictionTransScene{env: e}
	_, s.admin = e.dirAdminWithSession(t, "restriction.admin")
	s.activity = e.createFactionActivity(t, s.admin, "有限制的場")
	s.other = e.createFactionActivity(t, s.admin, "另一場")
	accountID, cookie := e.selfSelectPlayer(t, s.admin, "restriction.jia")
	s.member = e.selfAddMember(t, s.admin, s.activity, accountID, "甲")
	s.player = cookie
	bystanderID, bystander := e.selfSelectPlayer(t, s.admin, "restriction.yi")
	s.bystanderMember = e.selfAddMember(t, s.admin, s.activity, bystanderID, "乙")
	s.bystander = bystander
	// 甲在另一場也有一份身份：跨活動隔離要在協定層有可比對的兩行。
	e.selfAddMember(t, s.admin, s.other, accountID, "甲（另一場）")
	// 打開目錄與自選：解除後的玩家族讀法要拿得到 200 作為恢復的證據。
	e.request(t, http.MethodPut, "/admin/activities/"+s.activity+"/member-directory",
		statusJSONBody(map[string]any{"mode": "all_members", "expected_mode": "hidden"}),
		s.admin)
	e.selfSetMode(t, s.admin, s.activity, "free", "disabled")
	return s
}

// restrictionsAdminPath 是管理側逐欄編輯的路徑。
func restrictionsAdminPath(activityID, memberID string) string {
	return "/admin/activities/" + activityID + "/members/" + memberID + "/restrictions"
}

// restrictionsOwnPath 是玩家側本人查閱的路徑。
func restrictionsOwnPath(activityID string) string {
	return "/player/activities/" + activityID + "/restrictions"
}

// mustRestrict 送一次必須成功的編輯並回讀 member 那一格。
func (s *restrictionTransScene) mustRestrict(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodPut, restrictionsAdminPath(s.activity, s.member),
		statusJSONBody(body), s.admin)
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("分項限制編輯應成功：%d %s", resp.StatusCode, payload)
	}
	item, ok := decodeJSONBody(t, resp)["member"].(map[string]any)
	if !ok {
		t.Fatalf("編輯回應要帶著 member 這一格")
	}
	return item
}

// restrictionBody 讀本人查閱回應並逐欄斷言（期望值是欄位名→布爾的清單）。
func (s *restrictionTransScene) mustReadOwn(t *testing.T, who, activityID string,
	want map[string]bool) {
	t.Helper()
	resp := s.env.request(t, http.MethodGet, restrictionsOwnPath(activityID), "", who)
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("本人查閱限制應成功：%d %s", resp.StatusCode, payload)
	}
	payload := decodeJSONBody(t, resp)
	for _, field := range restrictionFields {
		got, ok := payload[field].(bool)
		if !ok {
			t.Fatalf("本人查閱必須帶著 %s 這一格布林，實際 %v", field, payload[field])
		}
		if expected, listed := want[field]; listed && got != expected {
			t.Errorf("%s 該是 %v，實際 %v", field, expected, got)
		}
	}
}

// rosterRow 讀管理名冊裡指定成員的那一行。
func (s *restrictionTransScene) rosterRow(t *testing.T, memberID string) map[string]any {
	t.Helper()
	rows := memberRoster(t, s.env.request(t, http.MethodGet,
		"/admin/activities/"+s.activity+"/members", "", s.admin))
	return memberRosterRow(t, rows, memberID)
}

// statusEnvelopeOf 讀一次錯誤回應，回「機器碼與原始本體」兩格。
//
// 它存在的理由只有一個：Body 讀一次就沒了——先 statusErrorCode 再 readAllBody 的寫法
// 會在第二讀拿到空字串，於是「細節點名了哪一欄」這種斷言會在測試裡長出假失敗。
func statusEnvelopeOf(t *testing.T, resp *http.Response) (int, string) {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取錯誤回應失敗：%v", err)
	}
	var envelope struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("錯誤回應必須是統一信封：%v（%s）", err, raw)
	}
	return envelope.Code, string(raw)
}

// transitionTo 把這場活動沿合法路徑推到目標狀態（口徑同 statusScene 那條共用鏈）。
func (s *restrictionTransScene) transitionTo(t *testing.T, want string) {
	t.Helper()
	resp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+s.activity+"/status", statusJSONBody(map[string]any{"status": want}),
		s.admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("把活動推到 %s 應成功：%d %s", want, resp.StatusCode, body)
	}
}

// TestRestrictionEndpointBirthIsUnrestricted 驗收：新成員六欄在名冊、本人查閱與
// 本人活動清單裡都讀得出「全不限制」，派生格 access_restricted 為假。
func TestRestrictionEndpointBirthIsUnrestricted(t *testing.T) {
	s := newRestrictionTransScene(t)

	row := s.rosterRow(t, s.member)
	for _, field := range restrictionFields {
		if value, ok := row[field].(bool); !ok || value {
			t.Errorf("名冊行必須帶著 %s 且出廠為假，實際 %v", field, row[field])
		}
	}
	s.mustReadOwn(t, s.player, s.activity, map[string]bool{})

	entries := decodeJSONBody(t, s.env.request(t, http.MethodGet, "/player/activities",
		"", s.player))["activities"].([]any)
	if len(entries) != 2 {
		t.Fatalf("本人清單該有兩場，實際 %v", entries)
	}
	for _, raw := range entries {
		entry := raw.(map[string]any)
		if value, ok := entry["access_restricted"].(bool); !ok || value {
			t.Errorf("清單項必須帶著 access_restricted 且出廠為假，實際 %v",
				entry["access_restricted"])
		}
	}
}

// TestRestrictionEndpointWhitelistAndIndependence 驗收：白名單逐對把關——
// 空本體、孤零的新值或依據值、未知欄位都 1004 點名；一次可翻多欄；
// 取消一欄時其餘原樣留下（回應層與庫層同形）。
func TestRestrictionEndpointWhitelistAndIndependence(t *testing.T) {
	s := newRestrictionTransScene(t)

	// 一欄都没帶：1004 點名 restrictions。
	empty := s.env.request(t, http.MethodPut, restrictionsAdminPath(s.activity, s.member),
		statusJSONBody(map[string]any{}), s.admin)
	emptyCode, emptyRaw := statusEnvelopeOf(t, empty)
	if empty.StatusCode != http.StatusBadRequest || emptyCode != int(CodeInvalidBody) {
		t.Fatalf("空本體該回 400／1004，實際 %d／%d", empty.StatusCode, emptyCode)
	}
	if !strings.Contains(emptyRaw, "restrictions") {
		t.Errorf("空本體的細節該點名 restrictions，實際 %s", emptyRaw)
	}

	// 只帶新值、沒帶依據值：1004 點名缺的那一欄依據值。
	missingExpected := s.env.request(t, http.MethodPut,
		restrictionsAdminPath(s.activity, s.member),
		statusJSONBody(map[string]any{"restrict_chat": true}), s.admin)
	missingCode, missingRaw := statusEnvelopeOf(t, missingExpected)
	if missingExpected.StatusCode != http.StatusBadRequest ||
		missingCode != int(CodeInvalidBody) ||
		!strings.Contains(missingRaw, "expected_restrict_chat") {
		t.Fatalf("孤零的新值該被點名 expected_restrict_chat，實際 %d／%s",
			missingExpected.StatusCode, missingRaw)
	}

	// 未知欄位（想把派生值寫進請求）：1004（DisallowUnknownFields 當場拒殺）。
	unknown := s.env.request(t, http.MethodPut, restrictionsAdminPath(s.activity, s.member),
		statusJSONBody(map[string]any{
			"restrict_login": true, "expected_restrict_login": false,
			"access_restricted": true,
		}), s.admin)
	if unknown.StatusCode != http.StatusBadRequest {
		t.Fatalf("多塞一格該整筆拒絕，實際 %d", unknown.StatusCode)
	}

	// 一次翻三欄。
	item := s.mustRestrict(t, func() map[string]any {
		body := map[string]any{}
		restrictionPair(body, "restrict_login", true, false)
		restrictionPair(body, "restrict_chat", true, false)
		restrictionPair(body, "restrict_private_chat", true, false)
		return body
	}())
	for _, field := range []string{"restrict_login", "restrict_chat", "restrict_private_chat"} {
		if item[field] != true {
			t.Errorf("%s 該如實回顯為真，實際 %v", field, item[field])
		}
	}

	// 只取消聊天：登入與私聊必須原樣留在回應與名冊裡。
	item = s.mustRestrict(t, func() map[string]any {
		body := map[string]any{}
		restrictionPair(body, "restrict_chat", false, true)
		return body
	}())
	if item["restrict_chat"] != false || item["restrict_login"] != true ||
		item["restrict_private_chat"] != true {
		t.Errorf("取消聊天不該順手取消別欄，實際 %v", item)
	}
	row := s.rosterRow(t, s.member)
	if row["restrict_login"] != true || row["restrict_private_chat"] != true ||
		row["restrict_chat"] != false {
		t.Errorf("名冊必須讀回同一份逐欄現值，實際 %v", row)
	}
	s.mustReadOwn(t, s.player, s.activity, map[string]bool{
		"restrict_login": true, "restrict_chat": false, "restrict_private_chat": true,
		"restrict_trade": false, "restrict_transfer": false, "restrict_item_use": false,
	})
}

// TestRestrictionEndpointConflictAndIdempotent 驗收：併發落敗回 2013 且一個字不落；
// 冪等重送是成功但不製造第二條留痕。
func TestRestrictionEndpointConflictAndIdempotent(t *testing.T) {
	s := newRestrictionTransScene(t)
	s.mustRestrict(t, func() map[string]any {
		body := map[string]any{}
		restrictionPair(body, "restrict_trade", true, false)
		return body
	}())
	audits := s.env.countMemberAudits(t, "member.restrictions_update")

	// 同一份「以為還未限制」的依據值重送：衝突、零落地、零留痕。
	stale := s.env.request(t, http.MethodPut, restrictionsAdminPath(s.activity, s.member),
		statusJSONBody(func() map[string]any {
			body := map[string]any{}
			restrictionPair(body, "restrict_trade", false, false)
			return body
		}()), s.admin)
	if stale.StatusCode != http.StatusConflict ||
		statusErrorCode(t, stale) != int(CodeProfileConflict) {
		t.Fatalf("過期依據值該回 409／2013")
	}
	if got := s.env.countMemberAudits(t, "member.restrictions_update"); got != audits {
		t.Errorf("被拒的編輯不留痕：%d→%d", audits, got)
	}

	// 冪等重送（新值＝現值且依據相符）：成功、不追加留痕。
	again := s.env.request(t, http.MethodPut, restrictionsAdminPath(s.activity, s.member),
		statusJSONBody(func() map[string]any {
			body := map[string]any{}
			restrictionPair(body, "restrict_trade", true, true)
			return body
		}()), s.admin)
	if again.StatusCode != http.StatusOK {
		t.Fatalf("冪等重送該是成功：%d", again.StatusCode)
	}
	if got := s.env.countMemberAudits(t, "member.restrictions_update"); got != audits {
		t.Errorf("冪等重送不製造第二條留痕：%d→%d", audits, got)
	}
}

// TestRestrictionEndpointAccessGate 驗收：禁止登入後，玩家族的每一條活動通路
// 都回 403／2043（含既有 Session 的下一筆請求，不是只在新登錄時查）；
// 本人查閱與活動清單照舊 200；同場另一位玩家與另一場活動不受牽連；
// 解除後的下一筆請求即恢復。
func TestRestrictionEndpointAccessGate(t *testing.T) {
	s := newRestrictionTransScene(t)
	faction := s.env.selfCreateFaction(t, s.admin, s.activity, "被擋的那個組")
	factionID, _ := faction["faction_id"].(string)

	// 出廠反證：通路本來都讀得動。
	if got := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/faction", "", s.player); got.StatusCode != http.StatusOK {
		t.Fatalf("未限制時陣營現況應可讀：%d", got.StatusCode)
	}

	s.mustRestrict(t, func() map[string]any {
		body := map[string]any{}
		restrictionPair(body, "restrict_login", true, false)
		return body
	}())

	gated := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"陣營現況", http.MethodGet, "/player/activities/" + s.activity + "/faction", ""},
		{"陣營自選", http.MethodPut, "/player/activities/" + s.activity + "/faction",
			statusJSONBody(map[string]any{"faction_id": factionID, "expected_faction_id": ""})},
		{"玩家目錄", http.MethodGet, "/player/activities/" + s.activity + "/members", ""},
		{"目錄單筆", http.MethodGet,
			"/player/activities/" + s.activity + "/members/" + s.member, ""},
		{"本人資料", http.MethodGet, "/player/activities/" + s.activity + "/profile", ""},
		{"標籤清單", http.MethodGet, "/player/activities/" + s.activity + "/tags", ""},
	}
	for _, entry := range gated {
		resp := s.env.request(t, entry.method, entry.path, entry.body, s.player)
		if resp.StatusCode != http.StatusForbidden ||
			statusErrorCode(t, resp) != int(CodeMemberAccessRestricted) {
			t.Errorf("%s：被限制後該回 403／2043，實際 %d／%d", entry.name,
				resp.StatusCode, statusErrorCode(t, resp))
		}
	}

	// 本人查閱與清單是批准留給被限制者的兩扇門：照舊 200。
	s.mustReadOwn(t, s.player, s.activity, map[string]bool{"restrict_login": true})
	entries := decodeJSONBody(t, s.env.request(t, http.MethodGet, "/player/activities",
		"", s.player))["activities"].([]any)
	blocked := 0
	for _, raw := range entries {
		entry := raw.(map[string]any)
		if entry["activity_id"] == s.activity && entry["access_restricted"] == true {
			blocked++
		}
		if entry["activity_id"] == s.other && entry["access_restricted"] != false {
			t.Errorf("另一場不該被標成受限：%v", entry)
		}
	}
	if blocked != 1 {
		t.Fatalf("清單該照舊列出兩場並如實標記受限，實際 %v", entries)
	}
	// 另一場的一切通路照舊可讀（跨活動隔離在協定層的形態）。
	if got := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.other+"/faction", "", s.player); got.StatusCode != http.StatusOK {
		t.Errorf("另一場的陣營現況該照舊可讀：%d", got.StatusCode)
	}
	// 同場另一位玩家不受牽連。
	if got := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/profile", "", s.bystander); got.StatusCode != http.StatusOK {
		t.Errorf("未受限玩家的本人資料該照舊可讀：%d", got.StatusCode)
	}
	// 管理通路不受玩家側旗標影響（凍結目標不会把管理名冊一起凍掉）。
	if rows := memberRoster(t, s.env.request(t, http.MethodGet,
		"/admin/activities/"+s.activity+"/members", "", s.admin)); len(rows) != 2 {
		t.Fatalf("名冊必須照舊讀出兩行，實際 %d 行", len(rows))
	}

	// 解除：下一筆請求就按新值回答（請求級失效；倉庫今日沒有實時層）。
	s.mustRestrict(t, func() map[string]any {
		body := map[string]any{}
		restrictionPair(body, "restrict_login", false, true)
		return body
	}())
	if got := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/faction", "", s.player); got.StatusCode != http.StatusOK {
		t.Errorf("解除後的下一筆請求該恢復 200：%d", got.StatusCode)
	}
	// 自選寫入也要真的走得動（PUT 不再被訪問判定擋下）。
	if got := s.env.request(t, http.MethodPut,
		"/player/activities/"+s.activity+"/faction", statusJSONBody(map[string]any{
			"faction_id": factionID, "expected_faction_id": ""}), s.player); got.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(got.Body)
		t.Fatalf("解除後的自選該成功：%d %s", got.StatusCode, body)
	}
}

// TestRestrictionEndpointAdmissionAndIsolation 驗收：普通帳戶敲管理族 2011、
// 匿名 2002、幽靈成員與跨活動拼接同收 1001、被限制的人敲本人查閱以外的路徑不改變准入。
func TestRestrictionEndpointAdmissionAndIsolation(t *testing.T) {
	s := newRestrictionTransScene(t)

	// 普通帳戶（玩家的會話）敲管理編輯：2011。
	plain := s.env.request(t, http.MethodPut, restrictionsAdminPath(s.activity, s.member),
		statusJSONBody(func() map[string]any {
			body := map[string]any{}
			restrictionPair(body, "restrict_login", true, false)
			return body
		}()), s.player)
	if plain.StatusCode != http.StatusForbidden ||
		statusErrorCode(t, plain) != int(CodePermissionDenied) {
		t.Fatalf("普通帳戶敲管理族該回 403／2011，實際 %d／%d",
			plain.StatusCode, statusErrorCode(t, plain))
	}

	// 匿名：2002。
	anonymous := s.env.request(t, http.MethodGet, restrictionsOwnPath(s.activity), "", "")
	if statusErrorCode(t, anonymous) != int(CodeNotAuthenticated) {
		t.Fatalf("匿名敲本人查閱該回 2002，實際 %d", statusErrorCode(t, anonymous))
	}

	// 幽靈成員標識與跨活動拼接（甲在另一場有行，拿這一場的標識拼進那一場）同收 1001。
	for _, testCase := range []struct {
		name       string
		activityID string
		memberID   string
	}{
		{"幽靈成員", s.activity, restrictionGhostMember},
		{"跨活動拼接", s.other, s.member},
	} {
		resp := s.env.request(t, http.MethodPut,
			restrictionsAdminPath(testCase.activityID, testCase.memberID),
			statusJSONBody(func() map[string]any {
				body := map[string]any{}
				restrictionPair(body, "restrict_trade", true, false)
				return body
			}()), s.admin)
		if resp.StatusCode != http.StatusNotFound ||
			statusErrorCode(t, resp) != int(CodeNotFound) {
			t.Errorf("%s：該收斂為不可分辨的 1001，實際 %d／%d", testCase.name,
				resp.StatusCode, statusErrorCode(t, resp))
		}
	}

	// 標識寫壞同樣 1001（這一族路徑不當標識格式探測器）。
	broken := s.env.request(t, http.MethodPut,
		restrictionsAdminPath(s.activity, "not-a-uuid"),
		statusJSONBody(func() map[string]any {
			body := map[string]any{}
			restrictionPair(body, "restrict_trade", true, false)
			return body
		}()), s.admin)
	if broken.StatusCode != http.StatusNotFound {
		t.Errorf("寫壞的成員標識該回 1001，實際 %d", broken.StatusCode)
	}
}

// TestRestrictionEndpointLifecycleGates 驗收：編輯屬業務寫入（停止 2033、歸檔 2029），
// 而本人查閱在任何生命週期都照舊可讀、訪問判定照舊按現值擋。
func TestRestrictionEndpointLifecycleGates(t *testing.T) {
	s := newRestrictionTransScene(t)
	s.mustRestrict(t, func() map[string]any {
		body := map[string]any{}
		restrictionPair(body, "restrict_login", true, false)
		return body
	}())

	s.transitionTo(t, "closed")
	closed := s.env.request(t, http.MethodPut, restrictionsAdminPath(s.activity, s.member),
		statusJSONBody(func() map[string]any {
			body := map[string]any{}
			restrictionPair(body, "restrict_chat", true, false)
			return body
		}()), s.admin)
	if closed.StatusCode != http.StatusConflict ||
		statusErrorCode(t, closed) != int(CodeActivityClosedWrites) {
		t.Fatalf("停止態的編輯該回 409／2033")
	}
	s.mustReadOwn(t, s.player, s.activity, map[string]bool{"restrict_login": true})
	gated := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/profile", "", s.player)
	if statusErrorCode(t, gated) != int(CodeMemberAccessRestricted) {
		t.Errorf("停止態的訪問判定仍該按現值回 2043，實際 %d", statusErrorCode(t, gated))
	}

	s.transitionTo(t, "archived")
	archived := s.env.request(t, http.MethodPut, restrictionsAdminPath(s.activity, s.member),
		statusJSONBody(func() map[string]any {
			body := map[string]any{}
			restrictionPair(body, "restrict_chat", true, false)
			return body
		}()), s.admin)
	if archived.StatusCode != http.StatusConflict ||
		statusErrorCode(t, archived) != int(CodeActivityArchived) {
		t.Fatalf("歸檔態的編輯該回 409／2029")
	}
	s.mustReadOwn(t, s.player, s.activity, map[string]bool{"restrict_login": true})
}

// TestRestrictionEndpointAuditCarriesActorAndChanges 驗收：被接受的編輯留下帶
// 真實操作者與逐欄前後值的留痕；被拒的（上面已斷言零留痕）不重複。
func TestRestrictionEndpointAuditCarriesActorAndChanges(t *testing.T) {
	s := newRestrictionTransScene(t)
	s.mustRestrict(t, func() map[string]any {
		body := map[string]any{}
		restrictionPair(body, "restrict_login", true, false)
		restrictionPair(body, "restrict_transfer", true, false)
		return body
	}())
	row := s.env.dirAudit(t, "member.restrictions_update")
	if row.actorKind != "admin" || row.actorID == "" {
		t.Fatalf("留痕要帶真實操作者，實際 %+v", row)
	}
	for _, want := range []string{"restrict_login", "restrict_transfer", "false", "true"} {
		if !strings.Contains(row.changes, want) {
			t.Errorf("changes 該帶 %q，實際 %s", want, row.changes)
		}
	}
	if strings.Contains(row.changes, "restrict_chat") {
		t.Errorf("未翻動的限制不進 changes：實際 %s", row.changes)
	}
	for _, forbidden := range []string{"password", "token", "cookie", "session"} {
		if strings.Contains(strings.ToLower(row.changes+row.reason), forbidden) {
			t.Errorf("留痕不得帶任何憑據字樣：%q", forbidden)
		}
	}
}
