// capabilities_test.go 是「狀態規則與手動限制的組合判定」在傳輸層的端到端證據：
// 管理側 7×6 規則矩陣的讀寫與 revision 比較-and-set、成員來源摘要、本人有效能力，
// 以及新的 2044（狀態規則拒絕訪問資格）與既有 2043（手動限制）的对外分工。
//
// 取證重點：
//   - 玩家側回應只有能力鍵、允許／拒絕與來源類別，沒有業務狀態、活動狀態、帳戶狀態、
//     逐來源細節、原因、操作者或時刻；
//   - 本人摘要即使被手動限制或狀態規則擋下仍讀得動；其他玩家族通路照常 2043／2044；
//   - 解除手動後若狀態仍拒絕，下一筆請求回 2044；兩者同時存在時回 2043，摘要並列來源；
//   - 規則更新後的下一筆請求按新 revision 回答，跨活動互不相干；
//   - 停止態仍可準備規則，歸檔後拒寫但讀法與本人摘要照舊；
//   - 帳戶停用後既有會話 2003 失效，管理側摘要仍如實列出 identity 來源。
//
// 刻意不收的東西：
//   - 不重複 internal/activity 的完整真值矩陣：那一側已逐格取證；
//   - 不碰真實資料目錄、不佔 5206，全程本次專屬的臨時庫與注入時鐘；
//   - 不宣稱推送或即時失效：取證形態一律是「下一筆請求按現值回答」。
package httpapi

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// capabilityTransScene 複用分項限制的輕量現場：一場已開放活動、一位獲指派的管理人、
// 兩位場內玩家（都有會話），以及同一管理人管的另一場活動。
type capabilityTransScene struct {
	*restrictionTransScene
}

func newCapabilityTransScene(t *testing.T) *capabilityTransScene {
	t.Helper()
	return &capabilityTransScene{newRestrictionTransScene(t)}
}

func capabilityRulesPath(activityID string) string {
	return "/admin/activities/" + activityID + "/capability-rules"
}

func capabilityMemberPath(activityID, memberID string) string {
	return "/admin/activities/" + activityID + "/members/" + memberID + "/capabilities"
}

func capabilityOwnPath(activityID string) string {
	return "/player/activities/" + activityID + "/capabilities"
}

// defaultCapabilityDenied 是出廠分組保守矩陣的拒絕清單（與領域預設同值）。
func defaultCapabilityDenied() map[string][]string {
	return map[string][]string{
		"normal":     {},
		"suspended":  {"login", "chat", "private_chat", "trade", "transfer", "item_use"},
		"eliminated": {"chat", "private_chat", "trade", "transfer", "item_use"},
		"dead":       {"chat", "private_chat", "trade", "transfer", "item_use"},
		"arrested":   {"trade", "transfer", "item_use"},
		"offline":    {},
		"custom":     {},
	}
}

// capabilityRulesBody 把拒絕清單換成 PUT 本體（七列齊全，固定順序）。
func capabilityRulesBody(expectedRevision int64, denied map[string][]string) string {
	order := []string{"normal", "suspended", "eliminated", "dead", "arrested", "offline", "custom"}
	rules := make([]map[string]any, 0, len(order))
	for _, status := range order {
		values := denied[status]
		if values == nil {
			values = []string{}
		}
		rules = append(rules, map[string]any{
			"status_key":          status,
			"denied_capabilities": values,
		})
	}
	return statusJSONBody(map[string]any{
		"expected_revision": expectedRevision,
		"rules":             rules,
	})
}

// deniedOf 從 GET／PUT 的規則回應裡取出某個狀態的拒絕清單。
func deniedOf(t *testing.T, payload map[string]any, status string) []string {
	t.Helper()
	raw, ok := payload["rules"].([]any)
	if !ok {
		t.Fatalf("規則回應缺少 rules：%v", payload)
	}
	for _, item := range raw {
		group, _ := item.(map[string]any)
		if group["status_key"] != status {
			continue
		}
		values, _ := group["denied_capabilities"].([]any)
		out := make([]string, 0, len(values))
		for _, value := range values {
			out = append(out, value.(string))
		}
		return out
	}
	t.Fatalf("規則回應缺少狀態 %s", status)
	return nil
}

// capabilityItemOf 從有效能力回應裡取出某一項。
func capabilityItemOf(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()
	raw, ok := payload["capabilities"].([]any)
	if !ok {
		t.Fatalf("有效能力回應缺少 capabilities：%v", payload)
	}
	for _, item := range raw {
		entry, _ := item.(map[string]any)
		if entry["capability"] == key {
			return entry
		}
	}
	t.Fatalf("有效能力回應缺少 %s", key)
	return nil
}

// sourcesOf 把 sources 陣列讀成逗號字串。
func sourcesOf(t *testing.T, item map[string]any) string {
	t.Helper()
	raw, ok := item["sources"].([]any)
	if !ok {
		t.Fatalf("能力項缺少 sources 陣列：%v", item)
	}
	parts := make([]string, 0, len(raw))
	for _, value := range raw {
		parts = append(parts, value.(string))
	}
	return strings.Join(parts, ",")
}

// mustCapabilityItem 斷言某項能力被拒絕且來源逐字相符。
func mustCapabilityItem(t *testing.T, payload map[string]any, key string,
	allowed bool, sources string) {
	t.Helper()
	item := capabilityItemOf(t, payload, key)
	if got := item["allowed"]; got != allowed {
		t.Fatalf("%s 的 allowed 應是 %v，實際 %v", key, allowed, got)
	}
	if got := sourcesOf(t, item); got != sources {
		t.Fatalf("%s 的來源應是 %q，實際 %q", key, sources, got)
	}
}

// setLoginRestriction 以明確依據值翻動 restrict_login。
func (s *capabilityTransScene) setLoginRestriction(t *testing.T, value, expected bool) {
	t.Helper()
	s.mustRestrict(t, map[string]any{
		"restrict_login": value, "expected_restrict_login": expected,
	})
}

// setTradeRestriction 以明確依據值翻動 restrict_trade。
func (s *capabilityTransScene) setTradeRestriction(t *testing.T, value, expected bool) {
	t.Helper()
	s.mustRestrict(t, map[string]any{
		"restrict_trade": value, "expected_restrict_trade": expected,
	})
}

// setMemberBusinessStatus 以明確依據值變更成員業務狀態。
func (s *capabilityTransScene) setMemberBusinessStatus(t *testing.T, status, expected string) {
	t.Helper()
	resp := s.env.request(t, http.MethodPut,
		"/admin/activities/"+s.activity+"/members/"+s.member+"/business-status",
		statusJSONBody(map[string]any{
			"business_status":           status,
			"custom_status_id":          "",
			"expected_business_status":  expected,
			"expected_custom_status_id": "",
		}), s.admin)
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("變更成員狀態為 %s 應成功：%d %s", status, resp.StatusCode, payload)
	}
}

// readOwnCapabilities 讀本人有效能力。
func (s *capabilityTransScene) readOwnCapabilities(t *testing.T) map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodGet, capabilityOwnPath(s.activity), "", s.player)
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("本人有效能力應讀得到：%d %s", resp.StatusCode, payload)
	}
	return decodeJSONBody(t, resp)
}

// readMemberCapabilities 讀管理側來源摘要。
func (s *capabilityTransScene) readMemberCapabilities(t *testing.T, memberID string) map[string]any {
	t.Helper()
	resp := s.env.request(t, http.MethodGet, capabilityMemberPath(s.activity, memberID),
		"", s.admin)
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("管理側能力摘要應讀得到：%d %s", resp.StatusCode, payload)
	}
	return decodeJSONBody(t, resp)
}

// familyRead 是玩家族的一條普通讀法（目錄）：它受訪問門禁約束，
// 用來對照「本人能力摘要仍在門外」。
func (s *capabilityTransScene) familyRead(t *testing.T) (int, int) {
	t.Helper()
	resp := s.env.request(t, http.MethodGet,
		"/player/activities/"+s.activity+"/members", "", s.player)
	if resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		return resp.StatusCode, 0
	}
	code, _ := statusEnvelopeOf(t, resp)
	return resp.StatusCode, code
}

// TestCapabilityEndpointRules 驗收規則矩陣的協定形態：
// 出廠 revision 0、七列完整、六項能力鍵；缺 expected_revision／未知欄位／
// 狀態或能力寫壞都 1004；合法替換回新 revision；舊 revision 2013；冪等重送回同版；
// 跨活動互不相干；普通帳戶 2011、匿名 2002；歸檔後拒寫但讀法照舊。
func TestCapabilityEndpointRules(t *testing.T) {
	s := newCapabilityTransScene(t)

	// 出廠：revision 0、configured false、七列、六項能力鍵。
	resp := s.env.request(t, http.MethodGet, capabilityRulesPath(s.activity), "", s.admin)
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("讀取規則應成功：%d %s", resp.StatusCode, payload)
	}
	initial := decodeJSONBody(t, resp)
	if initial["revision"].(float64) != 0 || initial["configured"].(bool) {
		t.Fatalf("出廠規則應是 revision 0／未配置，實際 %v", initial)
	}
	if keys, _ := initial["capability_keys"].([]any); len(keys) != 6 {
		t.Fatalf("規則回應應帶六項能力鍵，實際 %v", initial["capability_keys"])
	}
	if rules, _ := initial["rules"].([]any); len(rules) != 7 {
		t.Fatalf("規則回應應帶七列，實際 %d", len(rules))
	}
	if got := strings.Join(deniedOf(t, initial, "suspended"), ","); got !=
		"login,chat,private_chat,trade,transfer,item_use" {
		t.Fatalf("出廠 suspended 的拒絕清單不符：%s", got)
	}
	if got := strings.Join(deniedOf(t, initial, "custom"), ","); got != "" {
		t.Fatalf("出廠 custom 不得拒絕任何能力，實際 %s", got)
	}

	// 缺 expected_revision：1004 點名該欄。
	missing := s.env.request(t, http.MethodPut, capabilityRulesPath(s.activity),
		statusJSONBody(map[string]any{"rules": []any{}}), s.admin)
	missingCode, missingRaw := statusEnvelopeOf(t, missing)
	if missing.StatusCode != http.StatusBadRequest || missingCode != int(CodeInvalidBody) ||
		!strings.Contains(missingRaw, "expected_revision") {
		t.Fatalf("缺 expected_revision 應回 400／1004，實際 %d／%s",
			missing.StatusCode, missingRaw)
	}

	// 未知欄位：1004。
	unknown := s.env.request(t, http.MethodPut, capabilityRulesPath(s.activity),
		`{"expected_revision":0,"rules":[],"note":"x"}`, s.admin)
	if code, _ := statusEnvelopeOf(t, unknown); unknown.StatusCode != http.StatusBadRequest ||
		code != int(CodeInvalidBody) {
		t.Fatalf("未知欄位應回 400／1004，實際 %d／%d", unknown.StatusCode, code)
	}

	// 合法替換：normal 拒絕 chat，revision 1。
	denied := defaultCapabilityDenied()
	denied["normal"] = []string{"chat"}
	resp = s.env.request(t, http.MethodPut, capabilityRulesPath(s.activity),
		capabilityRulesBody(0, denied), s.admin)
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("替換規則應成功：%d %s", resp.StatusCode, payload)
	}
	updated := decodeJSONBody(t, resp)
	if updated["revision"].(float64) != 1 || !updated["configured"].(bool) {
		t.Fatalf("第一次替換後應是 revision 1／已配置，實際 %v", updated)
	}
	if got := strings.Join(deniedOf(t, updated, "normal"), ","); got != "chat" {
		t.Fatalf("normal 的拒絕清單應是 chat，實際 %s", got)
	}

	// 舊 revision 再送：409／2013，不覆蓋贏家。
	staleDenied := defaultCapabilityDenied()
	resp = s.env.request(t, http.MethodPut, capabilityRulesPath(s.activity),
		capabilityRulesBody(0, staleDenied), s.admin)
	if resp.StatusCode != http.StatusConflict ||
		mustEnvelopeCode(t, resp) != int(CodeProfileConflict) {
		t.Fatalf("舊 revision 應回 409／2013")
	}
	afterStale := decodeJSONBody(t, s.env.request(t, http.MethodGet,
		capabilityRulesPath(s.activity), "", s.admin))
	if afterStale["revision"].(float64) != 1 ||
		strings.Join(deniedOf(t, afterStale, "normal"), ",") != "chat" {
		t.Fatalf("落敗的替換不該改動贏家，實際 %v", afterStale)
	}

	// 冪等重送：相同矩陣、相同 revision → 同版。
	resp = s.env.request(t, http.MethodPut, capabilityRulesPath(s.activity),
		capabilityRulesBody(1, denied), s.admin)
	if resp.StatusCode != http.StatusOK ||
		decodeJSONBody(t, resp)["revision"].(float64) != 1 {
		t.Fatalf("冪等重送應回同一版 revision 1")
	}

	// custom 拒絕能力、集合外狀態與集合外能力都是 1004。
	for name, body := range map[string]string{
		"custom 拒絕能力": capabilityRulesBody(1, map[string][]string{
			"normal": {}, "suspended": {}, "eliminated": {}, "dead": {},
			"arrested": {}, "offline": {}, "custom": {"chat"},
		}),
		"狀態鍵集合外": `{"expected_revision":1,"rules":[
			{"status_key":"haunted","denied_capabilities":[]},
			{"status_key":"normal","denied_capabilities":[]},
			{"status_key":"suspended","denied_capabilities":[]},
			{"status_key":"eliminated","denied_capabilities":[]},
			{"status_key":"dead","denied_capabilities":[]},
			{"status_key":"arrested","denied_capabilities":[]},
			{"status_key":"offline","denied_capabilities":[]},
			{"status_key":"custom","denied_capabilities":[]}]}`,
		"能力鍵集合外": `{"expected_revision":1,"rules":[
			{"status_key":"normal","denied_capabilities":["fly"]},
			{"status_key":"suspended","denied_capabilities":[]},
			{"status_key":"eliminated","denied_capabilities":[]},
			{"status_key":"dead","denied_capabilities":[]},
			{"status_key":"arrested","denied_capabilities":[]},
			{"status_key":"offline","denied_capabilities":[]},
			{"status_key":"custom","denied_capabilities":[]}]}`,
	} {
		resp := s.env.request(t, http.MethodPut, capabilityRulesPath(s.activity), body, s.admin)
		if resp.StatusCode != http.StatusBadRequest ||
			mustEnvelopeCode(t, resp) != int(CodeInvalidBody) {
			t.Errorf("%s 應回 400／1004", name)
		}
	}

	// 跨活動隔離：另一場仍是 revision 0。
	other := decodeJSONBody(t, s.env.request(t, http.MethodGet,
		capabilityRulesPath(s.other), "", s.admin))
	if other["revision"].(float64) != 0 {
		t.Fatalf("另一場不該讀到主場的規則版本，實際 %v", other)
	}

	// 准入：普通帳戶 2011、匿名 2002。
	if code := mustEnvelopeCode(t, s.env.request(t, http.MethodGet,
		capabilityRulesPath(s.activity), "", s.bystander)); code != int(CodePermissionDenied) {
		t.Fatalf("普通帳戶讀規則應回 2011，實際 %d", code)
	}
	if resp := s.env.request(t, http.MethodGet, capabilityRulesPath(s.activity), "", ""); resp.StatusCode != http.StatusUnauthorized ||
		mustEnvelopeCode(t, resp) != int(CodeNotAuthenticated) {
		t.Fatalf("匿名讀規則應回 401／2002")
	}

	// 停止態仍可準備規則；歸檔後拒寫，讀法照舊。
	s.transitionTo(t, "closed")
	if resp := s.env.request(t, http.MethodPut, capabilityRulesPath(s.activity),
		capabilityRulesBody(1, defaultCapabilityDenied()), s.admin); resp.StatusCode != http.StatusOK {
		t.Fatalf("停止態仍應可寫規則，實際 %d", resp.StatusCode)
	}
	s.transitionTo(t, "archived")
	resp = s.env.request(t, http.MethodPut, capabilityRulesPath(s.activity),
		capabilityRulesBody(2, defaultCapabilityDenied()), s.admin)
	if resp.StatusCode != http.StatusConflict ||
		mustEnvelopeCode(t, resp) != int(CodeActivityArchived) {
		t.Fatalf("歸檔後寫規則應回 409／2029")
	}
	if resp := s.env.request(t, http.MethodGet, capabilityRulesPath(s.activity), "", s.admin); resp.StatusCode != http.StatusOK {
		t.Fatalf("歸檔後仍應讀得到規則，實際 %d", resp.StatusCode)
	}
}

// mustEnvelopeCode 讀錯誤碼並關閉本體。
func mustEnvelopeCode(t *testing.T, resp *http.Response) int {
	t.Helper()
	code, _ := statusEnvelopeOf(t, resp)
	return code
}

// TestCapabilityEndpointOwnAndAdminSummary 驗收：
// 玩家摘要只帶能力鍵、允許／拒絕與來源類別；手動限制只拒絕 login，其餘五項仍允許；
// 狀態 suspended 拒絕全部六項並使玩家族回 2044；兩者同時時回 2043 且摘要並列來源；
// 解除手動後狀態仍拒絕；狀態改回 normal 後下一筆請求恢復；管理側摘要帶逐來源布林。
func TestCapabilityEndpointOwnAndAdminSummary(t *testing.T) {
	s := newCapabilityTransScene(t)

	// 出廠：本人摘要可讀、全部允許、沒有任何管理側細節欄位。
	own := s.readOwnCapabilities(t)
	if own["access_allowed"] != true {
		t.Fatalf("出廠應可進入，實際 %v", own["access_allowed"])
	}
	for _, forbidden := range []string{
		"business_status", "activity_status", "account_status",
		"manual_denied", "status_denied", "lifecycle_denied", "identity_denied",
		"reason", "actor", "created_at", "updated_at",
	} {
		if _, exists := own[forbidden]; exists {
			t.Errorf("玩家摘要不得帶 %s，實際 %v", forbidden, own[forbidden])
		}
	}
	for _, key := range []string{"login", "chat", "private_chat", "trade", "transfer", "item_use"} {
		mustCapabilityItem(t, own, key, true, "")
	}

	// 手動 restrict_login：本人摘要仍可讀；login 拒絕、其餘五項仍是允許。
	s.setLoginRestriction(t, true, false)
	own = s.readOwnCapabilities(t)
	if own["access_allowed"] != false {
		t.Fatalf("手動限制後 access_allowed 應為假")
	}
	mustCapabilityItem(t, own, "login", false, "manual")
	for _, key := range []string{"chat", "private_chat", "trade", "transfer", "item_use"} {
		mustCapabilityItem(t, own, key, true, "")
	}
	if status, code := s.familyRead(t); status != http.StatusForbidden || code != int(CodeMemberAccessRestricted) {
		t.Fatalf("手動限制後玩家族普通讀法應回 403／2043，實際 %d／%d", status, code)
	}

	// 管理側摘要：帶業務狀態、活動狀態、帳戶狀態與逐來源布林。
	adminView := s.readMemberCapabilities(t, s.member)
	if adminView["business_status"] != "normal" || adminView["activity_status"] != "active" ||
		adminView["account_status"] != "active" {
		t.Fatalf("管理側摘要的三格現值不符：%v", adminView)
	}
	loginItem := capabilityItemOf(t, adminView, "login")
	if loginItem["manual_denied"] != true || loginItem["status_denied"] != false ||
		loginItem["lifecycle_denied"] != false || loginItem["identity_denied"] != false {
		t.Fatalf("管理側 login 的逐來源布林不符：%v", loginItem)
	}

	// 解除手動；狀態改成 suspended：玩家族回 2044，本人摘要仍可讀。
	s.setLoginRestriction(t, false, true)
	s.setMemberBusinessStatus(t, "suspended", "normal")
	own = s.readOwnCapabilities(t)
	if own["access_allowed"] != false {
		t.Fatalf("suspended 應拒絕 login")
	}
	mustCapabilityItem(t, own, "login", false, "status")
	mustCapabilityItem(t, own, "chat", false, "status")
	if status, code := s.familyRead(t); status != http.StatusForbidden ||
		code != int(CodeMemberStatusRestricted) {
		t.Fatalf("狀態規則拒絕訪問時玩家族應回 403／2044，實際 %d／%d", status, code)
	}

	// 再加手動 login：玩家族先回 2043；摘要並列 status 與 manual。
	s.setLoginRestriction(t, true, false)
	own = s.readOwnCapabilities(t)
	mustCapabilityItem(t, own, "login", false, "status,manual")
	if status, code := s.familyRead(t); status != http.StatusForbidden ||
		code != int(CodeMemberAccessRestricted) {
		t.Fatalf("兩者同時存在時應先回 403／2043，實際 %d／%d", status, code)
	}

	// 只解除手動：仍被狀態拒絕，下一筆回 2044——不會顯示成「已解凍」。
	s.setLoginRestriction(t, false, true)
	own = s.readOwnCapabilities(t)
	mustCapabilityItem(t, own, "login", false, "status")
	if status, code := s.familyRead(t); status != http.StatusForbidden ||
		code != int(CodeMemberStatusRestricted) {
		t.Fatalf("解除手動但狀態仍拒絕時應回 403／2044，實際 %d／%d", status, code)
	}

	// 狀態改回 normal：下一筆請求恢復。
	s.setMemberBusinessStatus(t, "normal", "suspended")
	if status, code := s.familyRead(t); status != http.StatusOK {
		t.Fatalf("狀態改回 normal 後玩家族應恢復，實際 %d／%d", status, code)
	}
	own = s.readOwnCapabilities(t)
	if own["access_allowed"] != true {
		t.Fatalf("狀態改回 normal 後 access_allowed 應為真")
	}

	// dead 不拒絕 login、但拒絕五項業務能力：這就是「Dead 改回 Normal」前的形態。
	s.setMemberBusinessStatus(t, "dead", "normal")
	own = s.readOwnCapabilities(t)
	if own["access_allowed"] != true {
		t.Fatalf("dead 依批准映射不拒絕 login")
	}
	mustCapabilityItem(t, own, "login", true, "")
	mustCapabilityItem(t, own, "chat", false, "status")
	if status, _ := s.familyRead(t); status != http.StatusOK {
		t.Fatalf("dead 仍可查看活動，玩家族應回 200，實際 %d", status)
	}
	adminView = s.readMemberCapabilities(t, s.member)
	chatItem := capabilityItemOf(t, adminView, "chat")
	if chatItem["status_denied"] != true || chatItem["manual_denied"] != false {
		t.Fatalf("dead 的 chat 應只被狀態拒絕：%v", chatItem)
	}

	// 普通帳戶讀管理摘要 2011；幽靈成員與幽靈活動 1001。
	if code := mustEnvelopeCode(t, s.env.request(t, http.MethodGet,
		capabilityMemberPath(s.activity, s.member), "", s.bystander)); code != int(CodePermissionDenied) {
		t.Fatalf("普通帳戶讀管理摘要應回 2011，實際 %d", code)
	}
	if code := mustEnvelopeCode(t, s.env.request(t, http.MethodGet,
		capabilityMemberPath(s.activity, restrictionGhostMember), "", s.admin)); code != int(CodeNotFound) {
		t.Fatalf("幽靈成員應回 1001，實際 %d", code)
	}
	if code := mustEnvelopeCode(t, s.env.request(t, http.MethodGet,
		capabilityOwnPath(restrictionGhostMember), "", s.player)); code != int(CodeNotFound) {
		t.Fatalf("幽靈活動的本人摘要應回 1001，實際 %d", code)
	}
	if code := mustEnvelopeCode(t, s.env.request(t, http.MethodGet,
		capabilityOwnPath(s.activity), "", "")); code != int(CodeNotAuthenticated) {
		t.Fatalf("匿名讀本人摘要應回 2002，實際 %d", code)
	}
}

// TestCapabilityEndpointMultiSourceAndIsolation 驗收：
// 多來源並列、解除一項仍受另一項限制、跨活動規則隔離，以及玩家回應不含內部細節。
func TestCapabilityEndpointMultiSourceAndIsolation(t *testing.T) {
	s := newCapabilityTransScene(t)

	// arrested 出廠拒絕交易／轉賬／使用物品；再手動拒絕交易。
	s.setMemberBusinessStatus(t, "arrested", "normal")
	s.setTradeRestriction(t, true, false)
	adminView := s.readMemberCapabilities(t, s.member)
	mustCapabilityItem(t, adminView, "trade", false, "status,manual")
	mustCapabilityItem(t, adminView, "transfer", false, "status")
	mustCapabilityItem(t, adminView, "item_use", false, "status")
	mustCapabilityItem(t, adminView, "login", true, "")
	tradeItem := capabilityItemOf(t, adminView, "trade")
	if tradeItem["status_denied"] != true || tradeItem["manual_denied"] != true {
		t.Fatalf("trade 應同時標出兩個來源：%v", tradeItem)
	}

	// 只解除手動交易：仍被狀態拒絕。
	s.setTradeRestriction(t, false, true)
	adminView = s.readMemberCapabilities(t, s.member)
	mustCapabilityItem(t, adminView, "trade", false, "status")
	tradeItem = capabilityItemOf(t, adminView, "trade")
	if tradeItem["manual_denied"] != false || tradeItem["status_denied"] != true {
		t.Fatalf("解除手動後 trade 應只剩狀態來源：%v", tradeItem)
	}

	// 主場 normal 拒絕 chat；另一場照舊，玩家在另一場的摘要不受影響。
	s.setMemberBusinessStatus(t, "normal", "arrested")
	denied := defaultCapabilityDenied()
	denied["normal"] = []string{"chat"}
	if resp := s.env.request(t, http.MethodPut, capabilityRulesPath(s.activity),
		capabilityRulesBody(0, denied), s.admin); resp.StatusCode != http.StatusOK {
		t.Fatalf("主場規則替換失敗：%d", resp.StatusCode)
	}
	otherResp := s.env.request(t, http.MethodGet, capabilityOwnPath(s.other), "", s.player)
	if otherResp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(otherResp.Body)
		t.Fatalf("另一場本人摘要應成功：%d %s", otherResp.StatusCode, payload)
	}
	other := decodeJSONBody(t, otherResp)
	if other["rules_revision"].(float64) != 0 {
		t.Fatalf("另一場不該讀到主場規則版本，實際 %v", other["rules_revision"])
	}
	mustCapabilityItem(t, other, "chat", true, "")
	mustCapabilityItem(t, s.readOwnCapabilities(t), "chat", false, "status")

	// 玩家回應的原文不得出現內部細節或審計欄位。
	raw := statusJSONBody(s.readOwnCapabilities(t))
	for _, forbidden := range []string{
		`"business_status"`, `"activity_status"`, `"account_status"`,
		`"manual_denied"`, `"status_denied"`, `"lifecycle_denied"`, `"identity_denied"`,
		`"reason"`, `"actor"`, `"created_at"`, `"updated_at"`,
	} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("玩家摘要原文不得包含 %s：%s", forbidden, raw)
		}
	}
}

// TestCapabilityEndpointLifecycleAndIdentity 驗收：
// 停止只拒絕五項業務能力、不拒絕查看；歸檔後本人摘要與管理摘要仍可讀；
// 帳戶停用使既有會話失效，但管理側摘要仍如實列出 identity 來源。
func TestCapabilityEndpointLifecycleAndIdentity(t *testing.T) {
	s := newCapabilityTransScene(t)

	s.transitionTo(t, "closed")
	own := s.readOwnCapabilities(t)
	if own["access_allowed"] != true {
		t.Fatalf("停止態仍應可查看")
	}
	mustCapabilityItem(t, own, "login", true, "")
	mustCapabilityItem(t, own, "chat", false, "lifecycle")
	if status, _ := s.familyRead(t); status != http.StatusOK {
		t.Fatalf("停止態仍可查看活動內容，玩家族應回 200，實際 %d", status)
	}
	adminView := s.readMemberCapabilities(t, s.member)
	if adminView["activity_status"] != "closed" {
		t.Fatalf("管理摘要應帶 closed，實際 %v", adminView["activity_status"])
	}
	chatItem := capabilityItemOf(t, adminView, "chat")
	if chatItem["lifecycle_denied"] != true {
		t.Fatalf("停止態 chat 應標出生命週期來源：%v", chatItem)
	}

	// 歸檔：本人與管理摘要照舊可讀。
	s.transitionTo(t, "archived")
	if own := s.readOwnCapabilities(t); own["access_allowed"] != true {
		t.Fatalf("歸檔後仍應可查看")
	}
	if adminView := s.readMemberCapabilities(t, s.member); adminView["activity_status"] != "archived" {
		t.Fatalf("歸檔後管理摘要應帶 archived，實際 %v", adminView["activity_status"])
	}

	// 帳戶停用：既有會話失效（2003），管理側摘要仍如實列出 identity 來源。
	var accountID string
	if err := s.env.db.SQL().QueryRowContext(t.Context(), `SELECT account_id
		FROM activity_members WHERE id = ?`, s.member).Scan(&accountID); err != nil {
		t.Fatalf("讀取成員的帳戶標識失敗：%v", err)
	}
	accounts := account.NewStore(s.env.clock)
	parsedAccountID, err := idgen.Parse(accountID)
	if err != nil {
		t.Fatalf("帳戶標識 %q 無法解析：%v", accountID, err)
	}
	if changed, err := accounts.SetStatus(t.Context(), s.env.db.SQL(), parsedAccountID,
		account.StatusDisabled, account.StatusActive); err != nil || !changed {
		t.Fatalf("停用成員帳戶失敗：%v（%t）", err, changed)
	}
	if code := mustEnvelopeCode(t, s.env.request(t, http.MethodGet,
		capabilityOwnPath(s.activity), "", s.player)); code != int(CodeSessionInvalid) {
		t.Fatalf("帳戶停用後既有會話應失效（2003），實際 %d", code)
	}
	adminView = s.readMemberCapabilities(t, s.member)
	if adminView["account_status"] != "disabled" {
		t.Fatalf("管理摘要應帶 disabled，實際 %v", adminView["account_status"])
	}
	for _, key := range []string{"login", "chat", "private_chat", "trade", "transfer", "item_use"} {
		item := capabilityItemOf(t, adminView, key)
		if item["identity_denied"] != true {
			t.Errorf("%s 應標出 identity 來源：%v", key, item)
		}
	}
}
