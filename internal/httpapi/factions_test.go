// factions_test.go 是「活動陣營管理」在傳輸層的端到端證據：
// 一位管理員走完建立→列表→改名與停用，兩條路徑各自的權限矩陣、本體欄位白名單
// （含「順手宣稱 available／activity_id／身分欄位」）、跨活動讀改的不可分辨、
// 同活動重名與跨活動同名的兩副面孔、停止／歸檔兩道寫入門禁各有各的碼、
// 非法顏色／圖標／排序逐欄點名，併發編輯的落敗那一句，以及停用與恢復那條通路上的
// 派生值（accepts_new_members）與「停用只翻一欄、行仍列可讀、重複請求各有各的形状」。
//
// 刻意不收的東西：
//   - 沒有替身：授權、活動作用域判定、業務門禁、重名核實與審計都跨層走真路徑；
//   - 不測陣營分配給玩家：成員尚未落地，這一族端點裡沒有一格能填「誰進哪個陣營」；
//   - 不碰真實數據目錄、不佔 5206，全程本次專屬的臨時庫與注入時鐘。
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/activity"
	"github.com/kagurazakayashi/EvernightRealm/internal/adminacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/guestbind"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/stdacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// factionGhostActivityID 是一個合法形狀但從未存在的活動標識（不可分辨性要比對它）。
const factionGhostActivityID = "0192f0c4-1c9a-7000-8000-000000000fef"

// factionEnv 是本次測試專屬的現場：與 activityEnv 同一批真組件，並把陣營與成員用例
// 一起注入（三個依賴欄位都餵同一個 *activity.Service，與 internal/app 的裝配同形）。
type factionEnv struct {
	ts    *httptest.Server
	db    *database.DB
	clock *timeutil.Test
}

func newFactionEnv(t *testing.T) *factionEnv {
	t.Helper()
	clock := timeutil.NewTest(testBaseTime())
	dir := t.TempDir()
	db, err := database.Open(context.Background(), database.Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試數據庫失敗：%v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			t.Errorf("暫存目錄清理失敗（殘留：%s）：%v", dir, err)
		}
	})
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: clock}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	accountsStore := account.NewStore(clock)
	grantsStore := grant.NewStore(clock)
	auditStore := audit.NewStore(clock)
	sessions, err := session.NewStoreWithPolicy(clock, time.Hour, session.Policy{})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	rootHash, err := credential.Hash(activityTestRootPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試 Root 憑據失敗：%v", err)
	}
	authService, err := auth.New(auth.Deps{
		DB: db, Sessions: sessions, Accounts: accountsStore, Grants: grantsStore,
		Audits: auditStore, RootPasswordHash: rootHash, Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立登錄用例失敗：%v", err)
	}
	adminService, err := adminacct.New(adminacct.Deps{
		DB: db, Accounts: accountsStore, Grants: grantsStore,
		Audits: auditStore, Sessions: sessions, Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立開設用例失敗：%v", err)
	}
	policyStore := acctpolicy.NewStore(clock)
	policyService, err := acctpolicy.New(acctpolicy.Deps{DB: db, Store: policyStore, Audits: auditStore})
	if err != nil {
		t.Fatalf("建立策略用例失敗：%v", err)
	}
	standardService, err := stdacct.New(stdacct.Deps{
		DB: db, Accounts: accountsStore, Grants: grantsStore, Policy: policyStore,
		Sessions: sessions, Audits: auditStore, BindTickets: guestbind.NewStore(clock),
		Clock: clock, Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立普通帳戶用例失敗：%v", err)
	}
	activityService, err := activity.New(activity.Deps{
		DB: db, Accounts: accountsStore, Grants: grantsStore, Audits: auditStore, Clock: clock,
	})
	if err != nil {
		t.Fatalf("建立活動用例失敗：%v", err)
	}
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{
		Auth: authService, Admins: adminService, StandardAccounts: standardService,
		AccountPolicy: policyService, Activities: activityService, Factions: activityService,
		// 成員用例與陣營用例共用同一個 *activity.Service（口徑同 internal/app 的裝配）：
		// 這一組現場因此能同時跑陣營與名冊兩族端點。
		Members: activityService,
		// 自選陣營一族同樣注入這一個實例（factionselect_test.go 的現場依賴這一欄：
		// 沒注入時 /player 那三條路徑根本不掛，斷言會變成在測 404 而不是在測準入）。
		FactionSelect: activityService,
		Clock:         clock,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &factionEnv{ts: ts, db: db, clock: clock}
}

// factionGhostFactionID 是一個合法形狀但從未存在的陣營標識（不可分辨性的對照組）。
const factionGhostFactionID = "0192f0c4-1c9a-7000-8000-000000000ffa"

// request 送一條可帶 Cookie 的請求（GET 與帶本體的寫入都走這一顆）。
func (e *factionEnv) request(t *testing.T, method, path, body, cookie string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, e.ts.URL+path, reader)
	if err != nil {
		t.Fatalf("建立請求失敗：%v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s 失敗：%v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// factionAdminCookie 借用 activityEnv 的交付鏈做出「已完成首改的管理員會話」——
// 該鏈只依賴 ts 上的端點，這裡把同一套请求器包一層交給它。
func (e *factionEnv) factionAdminCookie(t *testing.T, login string) *http.Cookie {
	t.Helper()
	resp := e.request(t, http.MethodPost, "/root/admins",
		`{"login_name":"`+login+`","display_name":"陣營管理員","password":"`+activityTestAdminSeed+`"}`,
		cookieHeader(e.factionRootCookie(t)))
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 開設管理員應成功：%d %s", resp.StatusCode, body)
	}
	first := loginCookie(t, e.request(t, http.MethodPost, "/auth/login",
		`{"login_name":"`+login+`","password":"`+activityTestAdminSeed+`"}`, ""))
	if resp := e.request(t, http.MethodPost, "/auth/password/change",
		`{"current_password":"`+activityTestAdminSeed+`","new_password":"`+activityTestAdminChanged+`"}`,
		cookieHeader(first)); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("首次改密應成功：%s", body)
	}
	return loginCookie(t, e.request(t, http.MethodPost, "/auth/login",
		`{"login_name":"`+login+`","password":"`+activityTestAdminChanged+`"}`, ""))
}

// factionRootCookie 走真實登陸通路取得 Root 會話。
func (e *factionEnv) factionRootCookie(t *testing.T) *http.Cookie {
	t.Helper()
	resp := e.request(t, http.MethodPost, "/auth/root/login",
		`{"password":"`+activityTestRootPassword+`"}`, "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 登陸應成功：%d %s", resp.StatusCode, body)
	}
	return loginCookie(t, resp)
}

// factionStandardCookie 由管理員開一位普通帳戶並取得他的會話（無任何伺服器級權限）。
func (e *factionEnv) factionStandardCookie(t *testing.T, admin *http.Cookie, login string) *http.Cookie {
	t.Helper()
	root := cookieHeader(e.factionRootCookie(t))
	if resp := e.request(t, http.MethodPut, "/root/account-policy", policyBody(true, "closed", false),
		root); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("打開管理員建立開關應成功：%s", body)
	}
	if resp := e.request(t, http.MethodPost, "/admin/accounts",
		`{"login_name":"`+login+`","display_name":"陣營平民","password":"`+activityTestStandardSeed+`"}`,
		cookieHeader(admin)); resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("管理員開設普通帳戶應成功：%d %s", resp.StatusCode, body)
	}
	first := loginCookie(t, e.request(t, http.MethodPost, "/auth/login",
		`{"login_name":"`+login+`","password":"`+activityTestStandardSeed+`"}`, ""))
	e.request(t, http.MethodPost, "/auth/password/change",
		`{"current_password":"`+activityTestStandardSeed+`","new_password":"`+activityTestStandardNewPwd+`"}`,
		cookieHeader(first))
	return loginCookie(t, e.request(t, http.MethodPost, "/auth/login",
		`{"login_name":"`+login+`","password":"`+activityTestStandardNewPwd+`"}`, ""))
}

// createFactionActivity 建立一個活動並直接開放（陣營的常态工作面），回傳活動標識。
func (e *factionEnv) createFactionActivity(t *testing.T, admin, name string) string {
	t.Helper()
	resp := e.request(t, http.MethodPost, "/admin/activities",
		`{"name":"`+name+`","description":"陣營取證的場"}`, admin)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("建立活動 %q 應成功：%d %s", name, resp.StatusCode, body)
	}
	id, _ := mustActivityItem(t, resp)["activity_id"].(string)
	if status := e.request(t, http.MethodPut, "/admin/activities/"+id+"/status",
		`{"status":"active"}`, admin); status.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(status.Body)
		t.Fatalf("開放活動應成功：%s", body)
	}
	return id
}

// mustFactionItem 讀寫入回應裡的 faction 那一格。
func mustFactionItem(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	payload := decodeJSONBody(t, resp)
	item, ok := payload["faction"].(map[string]any)
	if !ok {
		t.Fatalf("回應必須帶著 faction 這一格，實際 %v", payload)
	}
	return item
}

// factionList 讀列表回應的 factions 陣列。
func factionList(t *testing.T, resp *http.Response) []map[string]any {
	t.Helper()
	payload := decodeJSONBody(t, resp)
	raw, ok := payload["factions"].([]any)
	if !ok {
		t.Fatalf("列表回應必須帶著 factions 陣列，實際 %v", payload)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, row := range raw {
		item, ok := row.(map[string]any)
		if !ok {
			t.Fatalf("列表每項都該是物件，實際 %T", row)
		}
		out = append(out, item)
	}
	return out
}

// factionEditBody 以一行列表項的現值為依據，湊一份編輯請求本體（可只改其中幾欄）。
func factionEditBody(item map[string]any, overrides map[string]any) string {
	base := map[string]any{
		"name": item["name"], "description": item["description"],
		"icon": item["icon"], "color": item["color"],
		"sort_order": item["sort_order"], "available": item["available"],
		"expected_name": item["name"], "expected_description": item["description"],
		"expected_icon": item["icon"], "expected_color": item["color"],
		"expected_sort_order": item["sort_order"], "expected_available": item["available"],
	}
	for key, value := range overrides {
		base[key] = value
	}
	encoded, err := json.Marshal(base)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// TestFactionEndpointLifecycle 驗收：草稿期就能備陣營（業務門禁放行 draft／active）、
// 新建一律可用且未帶排序值排尾、列表按排序穩定呈現、編輯帶回服務端現值；
// 而歸檔之後連同「把可用改回來」在內的所有寫入都是 2029，讀取照常。
func TestFactionEndpointLifecycle(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "Faction.Lifecycle"))
	draftResp := e.request(t, http.MethodPost, "/admin/activities",
		`{"name":"草稿備陣營","description":""}`, admin)
	id, _ := mustActivityItem(t, draftResp)["activity_id"].(string)

	// 草稿態允許準備業務資料（用戶批准於 R3-001 的四態語意）。
	created := e.request(t, http.MethodPost, "/admin/activities/"+id+"/factions",
		`{"name":"黎明軍","description":"開場描述","icon":"sun","color":"#F0A020"}`, admin)
	if created.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(created.Body)
		t.Fatalf("草稿期建立陣營應回 201：%s", body)
	}
	first := mustFactionItem(t, created)
	if first["available"] != true {
		t.Errorf("新建的陣營一律可用（請求沒有那一格）：%v", first["available"])
	}
	if first["sort_order"].(float64) != 0 {
		t.Errorf("空表首格排序值應為 0，實際 %v", first["sort_order"])
	}
	if first["color"] != "#f0a020" {
		t.Errorf("顏色必須正規化成小寫單一寫法，實際 %v", first["color"])
	}
	if first["activity_id"] != id || first["faction_id"] == "" || first["faction_id"] == nil {
		t.Errorf("歸屬與標識由服務端決定：%v", first)
	}
	if _, present := first["created_by"]; present {
		t.Error("陣營回應不該有任何「自報身分」欄位")
	}
	factionID, _ := first["faction_id"].(string)

	second := mustFactionItem(t, e.request(t, http.MethodPost, "/admin/activities/"+id+"/factions",
		`{"name":"長夜軍","description":"","icon":"moon","color":"#102040","sort_order":5}`, admin))
	third := mustFactionItem(t, e.request(t, http.MethodPost, "/admin/activities/"+id+"/factions",
		`{"name":"尾軍","description":"","icon":"","color":""}`, admin))
	if third["sort_order"].(float64) != 6 {
		t.Errorf("未帶排序值應排到當前最大值之後（5+1），實際 %v", third["sort_order"])
	}

	rows := factionList(t, e.request(t, http.MethodGet, "/admin/activities/"+id+"/factions", "", admin))
	if len(rows) != 3 || rows[0]["faction_id"] != factionID ||
		rows[1]["faction_id"] != second["faction_id"] || rows[2]["faction_id"] != third["faction_id"] {
		t.Fatalf("列表應按排序值穩定給出三行，實際 %+v", rows)
	}

	// 編輯：改名、停用一步完成；回應帶著資料庫現值而不是請求意圖的回音。
	edited := e.request(t, http.MethodPut, "/admin/activities/"+id+"/factions/"+factionID,
		factionEditBody(rows[0], map[string]any{"name": "改名後的黎明軍", "available": false}), admin)
	if edited.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(edited.Body)
		t.Fatalf("編輯陣營應成功：%s", body)
	}
	item := mustFactionItem(t, edited)
	if item["name"] != "改名後的黎明軍" || item["available"] != false {
		t.Errorf("編輯回應應回顯服务端現值：%v", item)
	}
	if item["created_at"] != rows[0]["created_at"] || item["id"] != nil {
		t.Errorf("編輯不得改動建立時刻，也不該長出「id」這種欄位：%v", item)
	}

	// 歸檔：讀照常、所有寫都是 2029。
	if status := e.request(t, http.MethodPut, "/admin/activities/"+id+"/status",
		`{"status":"archived"}`, admin); status.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(status.Body)
		t.Fatalf("歸檔活動應成功：%s", body)
	}
	if resp := e.request(t, http.MethodGet, "/admin/activities/"+id+"/factions", "", admin); resp.StatusCode != http.StatusOK {
		t.Errorf("歸檔態的列表仍列、可讀：%d", resp.StatusCode)
	} else if len(factionList(t, resp)) != 3 {
		t.Error("歸檔不刪陣營行")
	}
	if resp := e.request(t, http.MethodPost, "/admin/activities/"+id+"/factions",
		`{"name":"歸檔後想建的","description":"","icon":"","color":""}`, admin); resp.StatusCode != http.StatusConflict {
		t.Fatalf("歸檔後的建立應回 409：%d", resp.StatusCode)
	} else if code, _ := envelope(t, resp); code != int(CodeActivityArchived) {
		t.Errorf("歸檔後的建立應回 2029，實際 %d", code)
	}
	rows = factionList(t, e.request(t, http.MethodGet, "/admin/activities/"+id+"/factions", "", admin))
	if resp := e.request(t, http.MethodPut, "/admin/activities/"+id+"/factions/"+factionID,
		factionEditBody(rows[0], map[string]any{"name": "歸檔後想改的"}), admin); resp.StatusCode != http.StatusConflict {
		t.Fatalf("歸檔後的編輯應回 409：%d", resp.StatusCode)
	} else if code, _ := envelope(t, resp); code != int(CodeActivityArchived) {
		t.Errorf("歸檔後的編輯應回 2029，實際 %d", code)
	}
}

// TestFactionEndpointPermissionMatrix 驗收：匿名、普通帳戶（今天的「普通成員」形態）、
// 外人管理員與被指派之後的管理員，在這一族端點上各位於自己的那一格。
func TestFactionEndpointPermissionMatrix(t *testing.T) {
	e := newFactionEnv(t)
	adminCookie := e.factionAdminCookie(t, "Faction.MatrixAdmin")
	plainCookie := e.factionStandardCookie(t, adminCookie, "faction.plain")
	id := e.createFactionActivity(t, cookieHeader(adminCookie), "矩陣取證場")

	anonymous := []struct{ method, path, body string }{
		{http.MethodGet, "/admin/activities/" + id + "/factions", ""},
		{http.MethodPost, "/admin/activities/" + id + "/factions", `{"name":"匿名建的","description":"","icon":"","color":""}`},
		{http.MethodPut, "/admin/activities/" + id + "/factions/" + id, `{"name":"匿名改的","description":"","icon":"","color":"","sort_order":0,"available":true}`},
	}
	for _, tc := range anonymous {
		resp := e.request(t, tc.method, tc.path, tc.body, "")
		if code, _ := envelope(t, resp); code != int(CodeNotAuthenticated) || resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s 匿名應回 2002／401，實際 %d %d", tc.method, tc.path, code, resp.StatusCode)
		}
	}

	// 普通帳戶：憑據有效、缺的是那個身份面（2011）；被拒的請求一行都不多。
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/admin/activities/" + id + "/factions", ""},
		{http.MethodPost, "/admin/activities/" + id + "/factions", `{"name":"平民建的","description":"","icon":"","color":""}`},
		{http.MethodPut, "/admin/activities/" + id + "/factions/" + id, `{"name":"平民改的","description":"","icon":"","color":"","sort_order":0,"available":true}`},
	} {
		resp := e.request(t, tc.method, tc.path, tc.body, cookieHeader(plainCookie))
		if code, _ := envelope(t, resp); code != int(CodePermissionDenied) {
			t.Errorf("%s %s 普通帳戶應回 2011，實際 %d", tc.method, tc.path, code)
		}
	}

	// 外人管理員讀列表：與「從沒這個活動」同形（1001，不承認活動存在）。
	stranger := cookieHeader(e.factionAdminCookie(t, "Faction.MatrixStranger"))
	ghostCode, ghostMessage := envelope(t, e.request(t, http.MethodGet,
		"/admin/activities/"+factionGhostActivityID+"/factions", "", stranger))
	outsiderCode, outsiderMessage := envelope(t, e.request(t, http.MethodGet,
		"/admin/activities/"+id+"/factions", "", stranger))
	if outsiderCode != int(CodeNotFound) || ghostCode != int(CodeNotFound) ||
		outsiderMessage != ghostMessage {
		t.Errorf("外人讀與幽靈讀必須同碼同文：%d/%q vs %d/%q",
			outsiderCode, outsiderMessage, ghostCode, ghostMessage)
	}
	if got := countActivityRows(t, e.db, "activity_factions"); got != 0 {
		t.Errorf("被拒的寫入不該多出行，實際 %d 行", got)
	}

	// Root 不受指派限制：它能列、能建（活動管理權口徑同 R3-001）。
	root := cookieHeader(e.factionRootCookie(t))
	if resp := e.request(t, http.MethodPost, "/admin/activities/"+id+"/factions",
		`{"name":"Root 備的一組","description":"","icon":"","color":""}`, root); resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 建立陣營應成功：%s", body)
	}
}

// TestFactionEndpointRejectsInjectedFields 驗收：本體連一格能填「身分、歸屬、建立時刻」
// 或「绕过白名單的宣稱」的地方都沒有，注入意圖在協定層就被 1004 點名欄位擋下。
func TestFactionEndpointRejectsInjectedFields(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "Faction.Inject"))
	id := e.createFactionActivity(t, admin, "注入取證場")
	factionID, _ := mustFactionItem(t, e.request(t, http.MethodPost, "/admin/activities/"+id+"/factions",
		`{"name":"被注入的","description":"","icon":"","color":""}`, admin))["faction_id"].(string)

	cases := []struct {
		what, method, path, body, field string
	}{
		{"建立宣稱 available", http.MethodPost, "/admin/activities/" + id + "/factions",
			`{"name":"宣稱停用","description":"","icon":"","color":"","available":false}`, "available"},
		{"建立宣稱身分欄位", http.MethodPost, "/admin/activities/" + id + "/factions",
			`{"name":"宣稱身分","description":"","icon":"","color":"","faction_id":"` + factionID + `","created_at":1}`, "faction_id"},
		{"建立宣稱歸屬", http.MethodPost, "/admin/activities/" + id + "/factions",
			`{"name":"宣稱歸屬","description":"","icon":"","color":"","activity_id":"` + id + `"}`, "activity_id"},
		{"編輯順手改標識", http.MethodPut, "/admin/activities/" + id + "/factions/" + factionID,
			factionEditBody(map[string]any{"name": "被注入的", "description": "", "icon": "", "color": "",
				"sort_order": float64(0), "available": true},
				map[string]any{"id": factionID}), "id"},
		{"編輯順手改歸屬", http.MethodPut, "/admin/activities/" + id + "/factions/" + factionID,
			factionEditBody(map[string]any{"name": "被注入的", "description": "", "icon": "", "color": "",
				"sort_order": float64(0), "available": true},
				map[string]any{"activity_id": id}), "activity_id"},
		{"編輯順手塞狀態欄", http.MethodPut, "/admin/activities/" + id + "/factions/" + factionID,
			factionEditBody(map[string]any{"name": "被注入的", "description": "", "icon": "", "color": "",
				"sort_order": float64(0), "available": true},
				map[string]any{"status": "deleted"}), "status"},
	}
	for _, tc := range cases {
		t.Run(tc.what, func(t *testing.T) {
			resp := e.request(t, tc.method, tc.path, tc.body, admin)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("注入應回 400：%d", resp.StatusCode)
			}
			var got struct {
				Code    int            `json:"code"`
				Details map[string]any `json:"details"`
			}
			body, _ := io.ReadAll(resp.Body)
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("解析回應失敗：%v（%s）", err, body)
			}
			if got.Code != int(CodeInvalidBody) {
				t.Errorf("注入應回 1004，實際 %d", got.Code)
			}
			if got.Details["reason"] != "unknown field" || got.Details["field"] != tc.field {
				t.Errorf("錯誤細節必須點名是哪個欄位，實際 %v", got.Details)
			}
		})
	}

	// 被擋下的請求一個欄位都不動。
	rows := factionList(t, e.request(t, http.MethodGet, "/admin/activities/"+id+"/factions", "", admin))
	if len(rows) != 1 || rows[0]["name"] != "被注入的" || rows[0]["available"] != true {
		t.Errorf("被拒的注入動了列表現值：%+v", rows)
	}
}

// TestFactionEndpointFieldValidation 驗收：非法顏色、圖標與排序值各自點名欄位（1004），
// 改寫法就有答案——不是業務衝突也不是權限句。
func TestFactionEndpointFieldValidation(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "Faction.Validate"))
	id := e.createFactionActivity(t, admin, "取值取證場")

	for _, tc := range []struct {
		what, body, field string
	}{
		{"空名稱", `{"name":"  ","description":"","icon":"","color":""}`, "name"},
		{"非法顏色", `{"name":"甲","description":"","icon":"","color":"ff0000"}`, "color"},
		{"顏色位數不足", `{"name":"甲","description":"","icon":"","color":"#ff00"}`, "color"},
		{"集合外圖標", `{"name":"甲","description":"","icon":"dragon","color":""}`, "icon"},
		{"排序越上界", `{"name":"甲","description":"","icon":"","color":"","sort_order":100000}`, "sort_order"},
		{"排序為負", `{"name":"甲","description":"","icon":"","color":"","sort_order":-1}`, "sort_order"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			resp := e.request(t, http.MethodPost, "/admin/activities/"+id+"/factions", tc.body, admin)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("非法取值應回 400：%d", resp.StatusCode)
			}
			var got struct {
				Code    int            `json:"code"`
				Details map[string]any `json:"details"`
			}
			body, _ := io.ReadAll(resp.Body)
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("解析回應失敗：%v（%s）", err, body)
			}
			if got.Code != int(CodeInvalidBody) || got.Details["invalid_field"] != tc.field {
				t.Errorf("應回 1004 並點名 %s，實際 %d／%v", tc.field, got.Code, got.Details)
			}
		})
	}
	if got := countActivityRows(t, e.db, "activity_factions"); got != 0 {
		t.Errorf("六條非法取值不該落庫，實際 %d 行", got)
	}
}

// TestFactionEndpointNameRulesEndToEnd 驗收：同活動重名拿 2034、跨活動同名各建各的，
// 編輯改名撞上同活動他人同樣 2034，現值不動。
func TestFactionEndpointNameRulesEndToEnd(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "Faction.Names"))
	actA := e.createFactionActivity(t, admin, "同名取證甲")
	actB := e.createFactionActivity(t, admin, "同名取證乙")

	if resp := e.request(t, http.MethodPost, "/admin/activities/"+actA+"/factions",
		`{"name":"黎明軍","description":"","icon":"","color":""}`, admin); resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("甲活動首建應成功：%s", body)
	}
	if resp := e.request(t, http.MethodPost, "/admin/activities/"+actA+"/factions",
		`{"name":"黎明軍","description":"","icon":"","color":""}`, admin); resp.StatusCode != http.StatusConflict {
		t.Fatalf("同活動重名應回 409：%d", resp.StatusCode)
	} else if code, _ := envelope(t, resp); code != int(CodeFactionNameTaken) {
		t.Errorf("同活動重名應回 2034，實際 %d", code)
	}
	if resp := e.request(t, http.MethodPost, "/admin/activities/"+actB+"/factions",
		`{"name":"黎明軍","description":"","icon":"","color":""}`, admin); resp.StatusCode != http.StatusCreated {
		t.Errorf("跨活動同名是合法部署形態：%d", resp.StatusCode)
	}

	// 撞名的改名：2034，現值不動。
	rows := factionList(t, e.request(t, http.MethodGet, "/admin/activities/"+actA+"/factions", "", admin))
	other := mustFactionItem(t, e.request(t, http.MethodPost, "/admin/activities/"+actA+"/factions",
		`{"name":"黃昏軍","description":"","icon":"","color":""}`, admin))
	_ = rows
	if resp := e.request(t, http.MethodPut, "/admin/activities/"+actA+"/factions/"+other["faction_id"].(string),
		factionEditBody(other, map[string]any{"name": "黎明軍"}), admin); resp.StatusCode != http.StatusConflict {
		t.Fatalf("改名撞名應回 409：%d", resp.StatusCode)
	} else if code, _ := envelope(t, resp); code != int(CodeFactionNameTaken) {
		t.Errorf("改名撞名應回 2034，實際 %d", code)
	}
	after := factionList(t, e.request(t, http.MethodGet, "/admin/activities/"+actA+"/factions", "", admin))
	for _, row := range after {
		if row["name"] == "黎明軍" && row["faction_id"] == other["faction_id"] {
			t.Error("撞名的改名把現值改掉了")
		}
	}
}

// TestFactionEndpointClosedWritesRejected 驗收：停止態的建與改都拿到 2033 那一句
// （處置＝等重開，與 2029 終態分得開），列表照讀；重開後同一路徑立刻能寫。
func TestFactionEndpointClosedWritesRejected(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "Faction.Closed"))
	id := e.createFactionActivity(t, admin, "要停止的場")
	created := mustFactionItem(t, e.request(t, http.MethodPost, "/admin/activities/"+id+"/factions",
		`{"name":"停止前建的","description":"","icon":"","color":""}`, admin))

	if status := e.request(t, http.MethodPut, "/admin/activities/"+id+"/status",
		`{"status":"closed"}`, admin); status.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(status.Body)
		t.Fatalf("停止活動應成功：%s", body)
	}
	for _, tc := range []struct {
		what, method, path, body string
	}{
		{"停止期建立", http.MethodPost, "/admin/activities/" + id + "/factions",
			`{"name":"停止期想建的","description":"","icon":"","color":""}`},
		{"停止期編輯", http.MethodPut, "/admin/activities/" + id + "/factions/" + created["faction_id"].(string),
			factionEditBody(created, map[string]any{"name": "停止期想改的"})},
	} {
		resp := e.request(t, tc.method, tc.path, tc.body, admin)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("%s 應回 409：%d", tc.what, resp.StatusCode)
		}
		if code, _ := envelope(t, resp); code != int(CodeActivityClosedWrites) {
			t.Errorf("%s 應回 2033（活動停止、等重開），實際 %d", tc.what, code)
		}
	}
	if resp := e.request(t, http.MethodGet, "/admin/activities/"+id+"/factions", "", admin); resp.StatusCode != http.StatusOK {
		t.Errorf("停止態仍列、可讀：%d", resp.StatusCode)
	}

	// 重開之後同一句話立刻翻案：門禁讀的是現值而不是歷史快照。
	if status := e.request(t, http.MethodPut, "/admin/activities/"+id+"/status",
		`{"status":"active"}`, admin); status.StatusCode != http.StatusOK {
		statusBody, _ := io.ReadAll(status.Body)
		t.Fatalf("重開活動應成功：%s", statusBody)
	}
	if resp := e.request(t, http.MethodPost, "/admin/activities/"+id+"/factions",
		`{"name":"重開後建的","description":"","icon":"","color":""}`, admin); resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Errorf("重開後建立應成功：%s", bodyBytes)
	}
}

// TestFactionEndpointCrossActivityIndistinguishable 驗收：把甲活動的陣營標識掛在乙活動
// 名下編輯，信封與「幽靈陣營標識」逐字同形；而這個請求本身就說明協議層沒有格子能改歸屬。
func TestFactionEndpointCrossActivityIndistinguishable(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "Faction.Cross"))
	actA := e.createFactionActivity(t, admin, "跨活動甲")
	actB := e.createFactionActivity(t, admin, "跨活動乙")
	factionID := mustFactionItem(t, e.request(t, http.MethodPost, "/admin/activities/"+actA+"/factions",
		`{"name":"只屬甲","description":"","icon":"","color":""}`, admin))["faction_id"].(string)

	rows := factionList(t, e.request(t, http.MethodGet, "/admin/activities/"+actA+"/factions", "", admin))
	ghostItem := map[string]any{"name": "借來的名字", "description": "", "icon": "", "color": "",
		"sort_order": float64(0), "available": true}

	onA := e.request(t, http.MethodPut, "/admin/activities/"+actB+"/factions/"+factionID,
		factionEditBody(rows[0], map[string]any{"name": "挪進乙的企圖"}), admin)
	onGhost := e.request(t, http.MethodPut, "/admin/activities/"+actB+"/factions/"+factionGhostFactionID,
		factionEditBody(ghostItem, nil), admin)
	if onA.StatusCode != http.StatusNotFound || onGhost.StatusCode != http.StatusNotFound {
		t.Fatalf("跨活動與幽靈都應回 404：%d／%d", onA.StatusCode, onGhost.StatusCode)
	}
	codeA, messageA := envelope(t, onA)
	codeGhost, messageGhost := envelope(t, onGhost)
	if codeA != int(CodeNotFound) || codeA != codeGhost || messageA != messageGhost {
		t.Errorf("兩句必須同碼同文，否則就是探測信號：%d/%q vs %d/%q", codeA, messageA, codeGhost, messageGhost)
	}
	// 甲的現值與歸屬一個字都沒動。
	still := factionList(t, e.request(t, http.MethodGet, "/admin/activities/"+actA+"/factions", "", admin))
	if len(still) != 1 || still[0]["name"] != "只屬甲" || still[0]["activity_id"] != actA {
		t.Errorf("被拒的跨活動編輯動了現值或歸屬：%+v", still)
	}
}

// TestFactionEndpointConcurrentEdit 驗收：同一份畫面上的第二次提交拿到 2013，
// 贏家現值不被覆蓋，落敗者不留審計（沿用帳戶與活動資料編輯那一枚，不另發新碼）。
func TestFactionEndpointConcurrentEdit(t *testing.T) {
	e := newFactionEnv(t)
	admin := cookieHeader(e.factionAdminCookie(t, "Faction.Cas"))
	id := e.createFactionActivity(t, admin, "併發取證場")
	row := mustFactionItem(t, e.request(t, http.MethodPost, "/admin/activities/"+id+"/factions",
		`{"name":"原名","description":"","icon":"","color":""}`, admin))

	first := e.request(t, http.MethodPut, "/admin/activities/"+id+"/factions/"+row["faction_id"].(string),
		factionEditBody(row, map[string]any{"name": "贏家名", "sort_order": float64(9)}), admin)
	if first.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(first.Body)
		t.Fatalf("第一次編輯應成功：%s", body)
	}
	second := e.request(t, http.MethodPut, "/admin/activities/"+id+"/factions/"+row["faction_id"].(string),
		factionEditBody(row, map[string]any{"name": "輸家名"}), admin)
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("落敗的編輯應回 409：%d", second.StatusCode)
	}
	if code, _ := envelope(t, second); code != int(CodeProfileConflict) {
		t.Errorf("落敗的編輯應沿用 2013，實際 %d", code)
	}
	rows := factionList(t, e.request(t, http.MethodGet, "/admin/activities/"+id+"/factions", "", admin))
	if rows[0]["name"] != "贏家名" || rows[0]["sort_order"].(float64) != 9 {
		t.Errorf("落敗的編輯覆蓋了現值：%+v", rows[0])
	}
	if got := countAuditAction(t, e.db, "faction.update", id); got != 1 {
		t.Errorf("落敗的編輯不該留審計（建立不記 update），實際 %d 筆", got)
	}

	// 方法約定：單筆路徑只認 PUT，其餘回 405 並附 Allow。
	notAllowed := e.request(t, http.MethodGet, "/admin/activities/"+id+"/factions/"+row["faction_id"].(string), "", admin)
	if notAllowed.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET 那條單筆路徑不該存在：%d", notAllowed.StatusCode)
	}
	if allow := notAllowed.Header.Get("Allow"); allow != http.MethodPut {
		t.Errorf("405 必須附 Allow=PUT，實際 %q", allow)
	}
	deleteResp := e.request(t, http.MethodDelete, "/admin/activities/"+id+"/factions/"+row["faction_id"].(string), "", admin)
	if deleteResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("這一族沒有刪除通路：%d", deleteResp.StatusCode)
	}
}

// TestFactionEndpointForeignOriginIsRefused 驗收：陣營寫入走全服務同一把 CSRF 閘，
// 外站來源帶著有效 Cookie 也進不來，且這一句發生在落庫之前。
func TestFactionEndpointForeignOriginIsRefused(t *testing.T) {
	e := newFactionEnv(t)
	admin := e.factionAdminCookie(t, "Faction.Origin")
	id := e.createFactionActivity(t, cookieHeader(admin), "跨站取證場")
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+"/admin/activities/"+id+"/factions",
		bytes.NewReader([]byte(`{"name":"跨站送進來的","description":"","icon":"","color":""}`)))
	if err != nil {
		t.Fatalf("建立請求失敗：%v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookieHeader(admin))
	req.Header.Set("Origin", "http://not-this-host.example")
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("請求失敗：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("跨站來源應被拒：%d", resp.StatusCode)
	}
	if code, _ := envelope(t, resp); code != int(CodeOriginForbidden) {
		t.Errorf("跨站來源應回 2005，實際 %d", code)
	}
	if got := countActivityRows(t, e.db, "activity_factions"); got != 0 {
		t.Errorf("被來源閘擋下的請求不該落庫，實際 %d 行", got)
	}
}

// TestFactionEndpointDisableAndRestore 驗收：停用與恢復走同一條 PUT 白名單通路，
// 回應與列表都如實帶著「此刻還收不收新成員」這句服務端派生值；停用不藏行、不改標識、
// 不動其他欄位；重複停用冪等、過期依據值落敗在 2013；派生那一格不可寫（1004 點名）；
// 未授权（2011／1001）與跨活動（1001 同形）都動不了它；活動停止時連可用行的派生值
// 也照實說「收不到新成員」，重開後同一句話翻案。
func TestFactionEndpointDisableAndRestore(t *testing.T) {
	e := newFactionEnv(t)
	adminCookie := e.factionAdminCookie(t, "Faction.Disable")
	admin := cookieHeader(adminCookie)
	plain := cookieHeader(e.factionStandardCookie(t, adminCookie, "faction.disable_plain"))
	stranger := cookieHeader(e.factionAdminCookie(t, "Faction.DisableStranger"))
	id := e.createFactionActivity(t, admin, "停用取證場")
	created := mustFactionItem(t, e.request(t, http.MethodPost, "/admin/activities/"+id+"/factions",
		`{"name":"黎明軍","description":"開場描述","icon":"sun","color":"#F0A020"}`, admin))
	factionID, _ := created["faction_id"].(string)
	if created["available"] != true || created["accepts_new_members"] != true {
		t.Fatalf("新建且活動可寫時兩者都該是真：%v／%v", created["available"], created["accepts_new_members"])
	}
	path := "/admin/activities/" + id + "/factions/" + factionID

	disable := e.request(t, http.MethodPut, path, factionEditBody(created, map[string]any{"available": false}), admin)
	if disable.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(disable.Body)
		t.Fatalf("停用應回 200：%s", body)
	}
	disabled := mustFactionItem(t, disable)
	if disabled["available"] != false {
		t.Errorf("回應該帶著資料庫現值（已停用）：%v", disabled["available"])
	}
	if disabled["accepts_new_members"] != false {
		t.Errorf("停用後的派生值必須是收不到新成員：%v", disabled["accepts_new_members"])
	}
	// 除了那一格，其餘現值逐字還在原處：停用不是刪除，也不是重置。
	for _, key := range []string{"name", "description", "icon", "color", "sort_order", "created_at", "activity_id"} {
		if disabled[key] != created[key] {
			t.Errorf("停用動了 %s 這一格：%v → %v", key, created[key], disabled[key])
		}
	}
	if disabled["faction_id"] != factionID {
		t.Errorf("停用動了標識（引用會失效）：%v → %v", factionID, disabled["faction_id"])
	}

	// 仍列、可讀。
	rows := factionList(t, e.request(t, http.MethodGet, "/admin/activities/"+id+"/factions", "", admin))
	if len(rows) != 1 || rows[0]["available"] != false || rows[0]["accepts_new_members"] != false {
		t.Fatalf("停用後列表仍要列出行：%+v", rows)
	}

	// 重複停用（依據值取剛讀到的現值）：整份編輯冪等成功，值一個字不動。
	again := e.request(t, http.MethodPut, path, factionEditBody(rows[0], nil), admin)
	if again.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(again.Body)
		t.Fatalf("重複停用該冪等成功：%s", body)
	}
	if mustFactionItem(t, again)["available"] != false {
		t.Error("重複停用後的現值仍該是停用")
	}
	if got := countAuditAction(t, e.db, "faction.update", id); got != 2 {
		t.Errorf("停用與那次如實的重存各留一筆，實際 %d 筆", got)
	}

	// 拿著「當時還可用」的舊畫面再送一次：現值已不是他所見，2013 且零落地、零留痕。
	stale := e.request(t, http.MethodPut, path, factionEditBody(created, map[string]any{"available": false}), admin)
	if stale.StatusCode != http.StatusConflict {
		t.Fatalf("過期依據值的重複停用應回 409：%d", stale.StatusCode)
	}
	if code, _ := envelope(t, stale); code != int(CodeProfileConflict) {
		t.Errorf("過期的重複停用該沿用 2013，實際 %d", code)
	}
	if got := countAuditAction(t, e.db, "faction.update", id); got != 2 {
		t.Errorf("落敗的重複請求不該留審計，實際 %d 筆", got)
	}

	// 派生那一格不是可寫欄位：想靠它宣稱「還收新成員」在協定層就撞 1004 點名。
	injected := e.request(t, http.MethodPut, path,
		factionEditBody(rows[0], map[string]any{"accepts_new_members": true}), admin)
	if injected.StatusCode != http.StatusBadRequest {
		t.Fatalf("寫派生值應回 400：%d", injected.StatusCode)
	}
	var envelopeBody struct {
		Code    int            `json:"code"`
		Details map[string]any `json:"details"`
	}
	body, _ := io.ReadAll(injected.Body)
	if err := json.Unmarshal(body, &envelopeBody); err != nil {
		t.Fatalf("解析回應失敗：%v（%s）", err, body)
	}
	if envelopeBody.Code != int(CodeInvalidBody) || envelopeBody.Details["field"] != "accepts_new_members" {
		t.Errorf("該點名是這一格寫不進去：%v", envelopeBody.Details)
	}

	// 未授權與跨活動都動不了它：普通帳戶 2011，外人管理員與幽靈標識同碼同文。
	if code, _ := envelope(t, e.request(t, http.MethodPut, path,
		factionEditBody(rows[0], map[string]any{"available": true}), plain)); code != int(CodePermissionDenied) {
		t.Errorf("普通帳戶的停用請求應回 2011，實際 %d", code)
	}
	outsider := e.request(t, http.MethodPut, "/admin/activities/"+id+"/factions/"+factionID,
		factionEditBody(rows[0], map[string]any{"available": true}), stranger)
	ghost := e.request(t, http.MethodPut, "/admin/activities/"+id+"/factions/"+factionGhostFactionID,
		factionEditBody(rows[0], map[string]any{"available": true}), admin)
	outsiderCode, outsiderMessage := envelope(t, outsider)
	ghostCode, ghostMessage := envelope(t, ghost)
	if outsiderCode != int(CodeNotFound) || ghostCode != int(CodeNotFound) || outsiderMessage != ghostMessage {
		t.Errorf("外人停用與幽靈停用都該收斂成同一句：%d/%q vs %d/%q",
			outsiderCode, outsiderMessage, ghostCode, ghostMessage)
	}
	stillRejected := factionList(t, e.request(t, http.MethodGet, "/admin/activities/"+id+"/factions", "", admin))
	if len(stillRejected) != 1 || stillRejected[0]["available"] != false {
		t.Errorf("被拒的恢復請求動了現值：%+v", stillRejected)
	}

	// 活動停止時：連還開著的陣營也收不到新成員，這一句由服務端派生值說出來。
	restored := mustFactionItem(t, e.request(t, http.MethodPut, path,
		factionEditBody(rows[0], map[string]any{"available": true}), admin))
	if restored["available"] != true || restored["accepts_new_members"] != true {
		t.Fatalf("重新啟用後兩者都該是真：%v／%v", restored["available"], restored["accepts_new_members"])
	}
	if status := e.request(t, http.MethodPut, "/admin/activities/"+id+"/status",
		`{"status":"closed"}`, admin); status.StatusCode != http.StatusOK {
		statusBody, _ := io.ReadAll(status.Body)
		t.Fatalf("停止活動應成功：%s", statusBody)
	}
	closedRows := factionList(t, e.request(t, http.MethodGet, "/admin/activities/"+id+"/factions", "", admin))
	if len(closedRows) != 1 || closedRows[0]["available"] != true || closedRows[0]["accepts_new_members"] != false {
		t.Errorf("停止活動裡的可用陣營該派生成收不到新成員：%+v", closedRows)
	}
	if code, _ := envelope(t, e.request(t, http.MethodPut, path,
		factionEditBody(restored, map[string]any{"available": false}), admin)); code != int(CodeActivityClosedWrites) {
		t.Errorf("停止態的停用請求該拿到 2033（等重開）那一句，實際 %d", code)
	}
	if status := e.request(t, http.MethodPut, "/admin/activities/"+id+"/status",
		`{"status":"active"}`, admin); status.StatusCode != http.StatusOK {
		t.Fatalf("重開活動應成功：%d", status.StatusCode)
	}
	reopened := factionList(t, e.request(t, http.MethodGet, "/admin/activities/"+id+"/factions", "", admin))
	if reopened[0]["available"] != true || reopened[0]["accepts_new_members"] != true {
		t.Errorf("重開後同一句派生值必須翻案回來：%+v", reopened[0])
	}
}

// countAuditAction 統計活動域審計裡某動作某活動的筆數。
func countAuditAction(t *testing.T, db *database.DB, action, activityID string) int {
	t.Helper()
	var got int
	if err := db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM activity_audit WHERE action = ? AND activity_id = ?`,
		action, activityID).Scan(&got); err != nil {
		t.Fatalf("統計審計 %s／%s 失敗：%v", action, activityID, err)
	}
	return got
}
