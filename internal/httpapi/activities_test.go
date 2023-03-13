// activities_test.go 是「活動生命週期管理」在傳輸層的端到端證據：
// Root 與管理員走完建立→開放→停止→歸檔這條路、六條端點各自的權限矩陣、
// 本體欄位白名單（含「順手改活動 ID／順手把狀態寫進資料編輯」）、
// 跨活動的不可分辨、併發編輯的落敗那一句，以及四枚新碼各自出现的場景。
//
// 刻意不收的東西：
//   - 沒有替身：授權、活動作用域判定、首次改密門閂、來源判定、落庫與審計都跨層走真路徑，
//     接錯線就會紅（同一手法見 invitecodes_test.go 的頭注）；
//   - 不測活動內業務（成員、陣營、資產）：那些模組尚未落地，這裡沒有任何入口能造出它們，
//     「活动已建好但裡面是空的」是本步的真相，不是半成品；
//   - 不碰任何真實數據目錄、不佔 5206，全程用本次專屬的臨時庫與注入時鐘。
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

const (
	activityTestRootPassword   = "activities-test-root-口令"
	activityTestAdminSeed      = "activities-test-管理員初始口令"
	activityTestAdminChanged   = "activities-test-管理員改後口令"
	activityTestStandardSeed   = "activities-test-普通帳戶初始口令"
	activityTestStandardNewPwd = "activities-test-普通帳戶改後口令"
)

// activityGhostAccountID 是一個合法形狀但從未存在的帳戶標識（用於注入與拒絕路徑）。
const activityGhostAccountID = "0192f0c4-1c9a-7000-8000-000000000fee"

// activityEnv 是本次測試專屬的現場：真資料庫、真登入／開設／普通帳戶／活動用例，
// 加一臺掛了活動端點的測試服務。
type activityEnv struct {
	ts    *httptest.Server
	db    *database.DB
	clock *timeutil.Test
}

// newActivityEnv 建立現場並啟動測試服務。注入時鐘讓「何時建立、何時歸檔」這兩格可斷言。
func newActivityEnv(t *testing.T) *activityEnv {
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
	// 普通帳戶用例：本檔要用它做出一位「有會話但沒有伺服器級權限」的普通帳戶，
	// 才能把「普通成員敲管理接口」這一格走真路徑验一遍。
	policyStore := acctpolicy.NewStore(clock)
	policyService, err := acctpolicy.New(acctpolicy.Deps{
		DB: db, Store: policyStore, Audits: auditStore,
	})
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
		AccountPolicy: policyService, Activities: activityService, Clock: clock,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &activityEnv{ts: ts, db: db, clock: clock}
}

// rootCookie 走真實登陸通路取得 Root 會話。
func (e *activityEnv) rootCookie(t *testing.T) *http.Cookie {
	t.Helper()
	resp := postJSON(t, e.ts, "/auth/root/login",
		`{"password":"`+activityTestRootPassword+`"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 登陸應成功：%d %s", resp.StatusCode, body)
	}
	return loginCookie(t, resp)
}

// liveAdminCookie 走完整交付鏈取得一位「已完成首次改密」的管理員會話。
func (e *activityEnv) liveAdminCookie(t *testing.T, login string) *http.Cookie {
	t.Helper()
	root := e.rootCookie(t)
	resp := postJSON(t, e.ts, "/root/admins",
		`{"login_name":"`+login+`","display_name":"活動管理員","password":"`+activityTestAdminSeed+`"}`,
		"", map[string]string{"Cookie": cookieHeader(root)})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 開設管理員應成功：%d %s", resp.StatusCode, body)
	}
	first := loginCookie(t, postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+activityTestAdminSeed+`"}`, "", nil))
	changed := postJSON(t, e.ts, "/auth/password/change",
		`{"current_password":"`+activityTestAdminSeed+`","new_password":"`+activityTestAdminChanged+`"}`,
		"", map[string]string{"Cookie": cookieHeader(first)})
	if changed.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(changed.Body)
		t.Fatalf("首次改密應成功：%d %s", changed.StatusCode, body)
	}
	return loginCookie(t, postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+activityTestAdminChanged+`"}`, "", nil))
}

// liveStandardCookie 由管理員開設一位普通帳戶並取得他的會話（他沒有任何伺服器級權限）。
func (e *activityEnv) liveStandardCookie(t *testing.T, admin *http.Cookie, login string) *http.Cookie {
	t.Helper()
	// 先由 Root 打開「管理員建立普通帳戶」那顆開關：出廠默認是關的（R2-006 的嚴格默認），
	// 這條測試要的不是繞過它，而是沿真實通路做出一位「有會話但沒有伺服器級權限」的普通帳戶。
	policy := putJSON(t, e.ts, "/root/account-policy", policyBody(true, "closed", false), "",
		map[string]string{"Cookie": cookieHeader(e.rootCookie(t))})
	if policy.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(policy.Body)
		t.Fatalf("打開管理員建立開關應成功：%d %s", policy.StatusCode, body)
	}
	resp := postJSON(t, e.ts, "/admin/accounts",
		`{"login_name":"`+login+`","display_name":"活動平民","password":"`+activityTestStandardSeed+`"}`,
		"", map[string]string{"Cookie": cookieHeader(admin)})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("管理員開設普通帳戶應成功：%d %s", resp.StatusCode, body)
	}
	first := loginCookie(t, postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+activityTestStandardSeed+`"}`, "", nil))
	postJSON(t, e.ts, "/auth/password/change",
		`{"current_password":"`+activityTestStandardSeed+`","new_password":"`+activityTestStandardNewPwd+`"}`,
		"", map[string]string{"Cookie": cookieHeader(first)})
	return loginCookie(t, postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+activityTestStandardNewPwd+`"}`, "", nil))
}

// activityRequest 送一條可帶 Cookie 的請求（GET 與帶本體的寫入都走這一顆）。
func (e *activityEnv) activityRequest(t *testing.T, method, path, body, cookie string) *http.Response {
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

// envelope 讀出錯誤信封的碼與訊息（跨活動那句「不可分辨」要比對雨者逐字同形）。
func envelope(t *testing.T, resp *http.Response) (int, string) {
	t.Helper()
	var got struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("錯誤回應應為 JSON 信封，實際 %q", body)
	}
	return got.Code, got.Message
}

// mustActivityItem 讀回應裡的 activity 那一格。
func mustActivityItem(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	payload := decodeJSONBody(t, resp)
	item, ok := payload["activity"].(map[string]any)
	if !ok {
		t.Fatalf("回應必須帶著 activity 這一格，實際 %v", payload)
	}
	return item
}

// createActivity 建立一個活動並回它的標識（失敗即終止）。
func (e *activityEnv) createActivity(t *testing.T, cookie, name string) string {
	t.Helper()
	resp := e.activityRequest(t, http.MethodPost, "/admin/activities",
		`{"name":"`+name+`","description":"測試用的場"}`, cookie)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("建立活動 %q 應成功：%d %s", name, resp.StatusCode, body)
	}
	id, _ := mustActivityItem(t, resp)["activity_id"].(string)
	if id == "" {
		t.Fatal("建立回應必須帶著活動標識")
	}
	return id
}

// TestActivityEndpointLifecycleEndToEnd 驗收：一位管理員從建立走到歸檔，
// 每一跳都帶著伺服器的現值回來，而歸檔之後連同「把狀態改回去」在內的所有寫入都拿到 2029。
func TestActivityEndpointLifecycleEndToEnd(t *testing.T) {
	e := newActivityEnv(t)
	admin := cookieHeader(e.liveAdminCookie(t, "Activity.Lifecycle"))

	created := e.activityRequest(t, http.MethodPost, "/admin/activities",
		`{"name":"長夜第一場","description":"開場描述"}`, admin)
	if created.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(created.Body)
		t.Fatalf("建立活動應回 201：%s", body)
	}
	item := mustActivityItem(t, created)
	id, _ := item["activity_id"].(string)
	if item["status"] != "draft" || item["manager_count"].(float64) != 1 {
		t.Errorf("新建活動應是草稿且已指派建立者，實際 %v", item)
	}
	if _, present := item["archived_at"]; present {
		t.Error("還沒歸檔的活動不該帶著歸檔時刻（缺席是事實的缺席）")
	}
	if item["created_by_account_id"] == nil || item["created_by_account_id"] == "" {
		t.Error("帳戶建立的活动必須讀得回建立者標識")
	}

	// 目錄：總數與這一頁都該看見它。
	directory := e.activityRequest(t, http.MethodGet, "/admin/activities?page=1&page_size=20", "", admin)
	if directory.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(directory.Body)
		t.Fatalf("讀目錄應成功：%s", body)
	}
	var page activityDirectoryResponse
	if err := json.NewDecoder(directory.Body).Decode(&page); err != nil {
		t.Fatalf("解析目錄回應失敗：%v", err)
	}
	if page.Total != 1 || len(page.Activities) != 1 || page.Activities[0].ActivityID != id {
		t.Errorf("目錄應只列這位管理員管得著的那一行，實際 %+v", page)
	}

	// 開放 → 停止 → 重新開放 → 歸檔（用戶批准的四條路徑）。
	for step, target := range []string{"active", "closed", "active", "archived"} {
		resp := e.activityRequest(t, http.MethodPut, "/admin/activities/"+id+"/status",
			`{"status":"`+target+`"}`, admin)
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("第 %d 跳轉換到 %s 應成功：%s", step+1, target, body)
		}
		if got := mustActivityItem(t, resp)["status"]; got != target {
			t.Errorf("第 %d 跳應回顯轉換後的現值 %s，實際 %v", step+1, target, got)
		}
	}
	archived := mustActivityItem(t, e.activityRequest(t, http.MethodGet,
		"/admin/activities/"+id, "", admin))
	if archived["archived_at"] == nil || archived["archived_at"] == "" {
		t.Error("歸檔後必須讀得到歸檔時刻")
	}

	// 終態拒寫：資料編輯與再一次轉換都是 2029，而且一個欄位都不動。
	if resp := e.activityRequest(t, http.MethodPut, "/admin/activities/"+id,
		`{"name":"歸檔後改名","description":"","expected_name":"長夜第一場","expected_description":"開場描述"}`, admin); resp.StatusCode != http.StatusConflict {
		t.Fatalf("歸檔後的編輯應回 409：%d", resp.StatusCode)
	} else if code, _ := envelope(t, resp); code != int(CodeActivityArchived) {
		t.Errorf("歸檔後的編輯應回 2029，實際 %d", code)
	}
	if resp := e.activityRequest(t, http.MethodPut, "/admin/activities/"+id+"/status",
		`{"status":"active"}`, admin); resp.StatusCode != http.StatusConflict {
		t.Fatalf("歸檔後的轉換應回 409：%d", resp.StatusCode)
	} else if code, _ := envelope(t, resp); code != int(CodeActivityArchived) {
		t.Errorf("終態應回 2029 而不是 2030／2031，實際 %d", code)
	}

	// 方法約定：這些子路徑各自只認一個方法，其餘回 1002 並附 Allow。
	notAllowed := e.activityRequest(t, http.MethodPost, "/admin/activities/"+id+"/status",
		`{"status":"active"}`, admin)
	if notAllowed.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST 那條狀態路徑不該存在：%d", notAllowed.StatusCode)
	}
	if allow := notAllowed.Header.Get("Allow"); allow != http.MethodPut {
		t.Errorf("405 必須附 Allow=PUT，實際 %q", allow)
	}
}

// TestActivityEndpointPermissionMatrix 驗收：沒帶憑據、帶的是普通帳戶的憑據、
// 與帶的是管理員的憑據，在這六條端點上各位於自己的那一格。
//
// 「普通成員不能調用管理接口」在這裡不是靠界面藏按鈕：他帶著有效會話直接打，
// 拿到的是 2011，而且庫裡一行都不多。
func TestActivityEndpointPermissionMatrix(t *testing.T) {
	e := newActivityEnv(t)
	adminCookie := e.liveAdminCookie(t, "Activity.MatrixAdmin")
	plainCookie := e.liveStandardCookie(t, adminCookie, "activity.plain")
	id := e.createActivity(t, cookieHeader(adminCookie), "矩陣取證的場")

	anonymous := []struct {
		method, path, body string
	}{
		{http.MethodGet, "/admin/activities", ""},
		{http.MethodPost, "/admin/activities", `{"name":"匿名建的","description":""}`},
		{http.MethodGet, "/admin/activities/" + id, ""},
		{http.MethodPut, "/admin/activities/" + id + "/status", `{"status":"active"}`},
		{http.MethodGet, "/admin/activities/" + id + "/managers", ""},
	}
	for _, tc := range anonymous {
		resp := e.activityRequest(t, tc.method, tc.path, tc.body, "")
		if code, _ := envelope(t, resp); code != int(CodeNotAuthenticated) || resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s 匿名應回 2002／401，實際 %d %d", tc.method, tc.path, code, resp.StatusCode)
		}
	}

	// 普通帳戶：憑據有效、身分可信，缺的就是那個身份面（403，処置不是重新登入）。
	for _, tc := range []struct {
		method, path, body string
		want               ErrorCode
	}{
		{http.MethodGet, "/admin/activities", "", CodePermissionDenied},
		{http.MethodPost, "/admin/activities", `{"name":"平民建的場","description":""}`, CodePermissionDenied},
		// 單筆讀寫也先撞身份那道閘：他連「管理員這個身份面」都不屬於，
		// 還輪不到活動作用域去答「這個活動管不著你」（那一側收斂成 1001，由跨活動那條用例固定）。
		{http.MethodGet, "/admin/activities/" + id, "", CodePermissionDenied},
		{http.MethodPut, "/admin/activities/" + id + "/status", `{"status":"active"}`, CodePermissionDenied},
		{http.MethodGet, "/admin/activities/" + id + "/managers", "", CodePermissionDenied},
		{http.MethodPost, "/root/activities/" + id + "/managers", `{"account_id":"00000000-0000-7000-8000-000000000000"}`, CodePermissionDenied},
		{http.MethodDelete, "/root/activities/" + id + "/managers/00000000-0000-7000-8000-000000000000", "", CodePermissionDenied},
	} {
		resp := e.activityRequest(t, tc.method, tc.path, tc.body, cookieHeader(plainCookie))
		if code, _ := envelope(t, resp); code != int(tc.want) {
			t.Errorf("%s %s 普通帳戶應回 %d，實際 %d", tc.method, tc.path, tc.want, code)
		}
	}

	// 被拒的這些請求沒有多出任何活動行，也沒有多記任何審計。
	if got := countActivityRows(t, e.db, "activities"); got != 1 {
		t.Errorf("被拒的建立不該多出行，實際 %d 行", got)
	}
	if got := countActivityRows(t, e.db, "activity_audit"); got != 1 {
		t.Errorf("六條被拒的請求不該記審計（只有成功的建立那一筆），實際 %d 筆", got)
	}
}

// TestActivityEndpointRejectsEveryInjectedField 驗收：本體連一個能填「身分、狀態、
// 建立者、活動標識」的格子都沒有，注入的意圖在協定層就被 1004 擋下，而不是被「忽略」混過去。
func TestActivityEndpointRejectsEveryInjectedField(t *testing.T) {
	e := newActivityEnv(t)
	admin := cookieHeader(e.liveAdminCookie(t, "Activity.Inject"))
	id := e.createActivity(t, admin, "注入取證的場")

	cases := []struct {
		what             string
		method, path     string
		body             string
		wantField, field string
	}{
		{
			what: "建立時宣稱狀態與建立者", method: http.MethodPost, path: "/admin/activities",
			body: `{"name":" injection","description":"","status":"active","created_by_account_id":"` +
				id + `","id":"` + id + `"}`,
			wantField: "unknown field", field: "status",
		},
		{
			what: "資料編輯順手改狀態", method: http.MethodPut, path: "/admin/activities/" + id,
			body:      `{"name":"改名","description":"","expected_name":"注入取證的場","expected_description":"","status":"archived"}`,
			wantField: "unknown field", field: "status",
		},
		{
			what: "資料編輯順手改活動標識", method: http.MethodPut, path: "/admin/activities/" + id,
			body: `{"name":"改名","description":"","expected_name":"注入取證的場","expected_description":"","activity_id":"` +
				id + `"}`,
			wantField: "unknown field", field: "activity_id",
		},
		{
			what: "狀態轉換順手改名稱", method: http.MethodPut, path: "/admin/activities/" + id + "/status",
			body:      `{"status":"active","name":"順手改名"}`,
			wantField: "unknown field", field: "name",
		},
		{
			what: "指派順手宣稱角色", method: http.MethodPost, path: "/root/activities/" + id + "/managers",
			body:      `{"account_id":"` + id + `","role":"server_admin","granted_at":1}`,
			wantField: "unknown field", field: "role",
		},
		{
			what: "撤銷帶上任何本體", method: http.MethodDelete,
			path: "/root/activities/" + id + "/managers/" + id,
			body: `{"reason":"我想撤"}`, wantField: "unknown field", field: "reason",
		},
	}
	for _, tc := range cases {
		t.Run(tc.what, func(t *testing.T) {
			resp := e.activityRequest(t, tc.method, tc.path, tc.body, admin)
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
			if got.Details["reason"] != tc.wantField || got.Details["field"] != tc.field {
				t.Errorf("錯誤細節必須點名是哪個欄位，實際 %v", got.Details)
			}
		})
	}

	// 被擋下的編輯一個欄位都不動：狀態仍是草稿，名稱仍是原名。
	detail := mustActivityItem(t, e.activityRequest(t, http.MethodGet, "/admin/activities/"+id, "", admin))
	if detail["status"] != "draft" || detail["name"] != "注入取證的場" {
		t.Errorf("被拒的請求動了現值：%v", detail)
	}
}

// TestActivityEndpointCrossActivityIsIndistinguishable 驗收：乙管理員讀、改甲活動得到的信封
// 與「這個標識從來不是一個活動」逐字同形，因此這條通路不是一臺活動存在性探測器。
func TestActivityEndpointCrossActivityIsIndistinguishable(t *testing.T) {
	e := newActivityEnv(t)
	alpha := cookieHeader(e.liveAdminCookie(t, "Activity.Alpha"))
	beta := cookieHeader(e.liveAdminCookie(t, "Activity.Beta"))
	id := e.createActivity(t, alpha, "甲活動")

	ghost := "/admin/activities/0192f0c4-1c9a-7000-8000-000000000fee"
	// 格式正確的幽靈標識（不是亂寫的那種），才比得出「兩句本來就該同形」。
	for _, path := range []string{"/admin/activities/" + id, ghost} {
		resp := e.activityRequest(t, http.MethodGet, path, "", beta)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("乙讀他人活動與讀幽靈標識都應回 404：%d", resp.StatusCode)
		}
	}
	firstCode, firstMessage := envelope(t, e.activityRequest(t, http.MethodGet, "/admin/activities/"+id, "", beta))
	secondCode, secondMessage := envelope(t, e.activityRequest(t, http.MethodGet, ghost, "", beta))
	if firstCode != int(CodeNotFound) || firstCode != secondCode || firstMessage != secondMessage {
		t.Errorf("兩句必須同碼同文，否則就是枚舉信號：%d/%q vs %d/%q",
			firstCode, firstMessage, secondCode, secondMessage)
	}

	// 乙也改不動甲的活動，而且同一句話；甲的現值一個字都沒變。
	if code, _ := envelope(t, e.activityRequest(t, http.MethodPut, "/admin/activities/"+id,
		`{"name":"被乙改","description":"","expected_name":"甲活動","expected_description":"測試用的場"}`, beta)); code != int(CodeNotFound) {
		t.Errorf("乙改甲活動應回 1001，實際 %d", code)
	}
	alphaDetail := mustActivityItem(t, e.activityRequest(t, http.MethodGet, "/admin/activities/"+id, "", alpha))
	if alphaDetail["name"] != "甲活動" {
		t.Errorf("被拒的編輯動了甲的活動名稱：%v", alphaDetail["name"])
	}

	// 乙的目錄是空的，而不是「全部活動」：漏帶授權資料不會默默放寬可見範圍。
	var page activityDirectoryResponse
	body, _ := io.ReadAll(e.activityRequest(t, http.MethodGet, "/admin/activities", "", beta).Body)
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("解析乙的目錄失敗：%v（%s）", err, body)
	}
	if page.Total != 0 || len(page.Activities) != 0 {
		t.Errorf("乙看不見任何活動，實際 Total=%d Rows=%d", page.Total, len(page.Activities))
	}
}

// TestActivityEndpointStatusValidationAndConflict 驗收：非法取值點名欄位、
// 不存在的路徑另有其碼、重複轉換拿到的是「重讀現值」那一句而不是成功。
func TestActivityEndpointStatusValidationAndConflict(t *testing.T) {
	e := newActivityEnv(t)
	admin := cookieHeader(e.liveAdminCookie(t, "Activity.Status"))
	id := e.createActivity(t, admin, "狀態取值取證")

	// 集合外的取值：1004 點名 status（改寫法就有答案）。
	if resp := e.activityRequest(t, http.MethodPut, "/admin/activities/"+id+"/status",
		`{"status":"paused"}`, admin); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("非法狀態取值應回 400：%d", resp.StatusCode)
	} else if code, _ := envelope(t, resp); code != int(CodeInvalidBody) {
		t.Errorf("非法狀態取值應回 1004，實際 %d", code)
	}

	// 路徑不存在：草稿沒有「停止」這條出口，重讀現值也沒有用——2031。
	if resp := e.activityRequest(t, http.MethodPut, "/admin/activities/"+id+"/status",
		`{"status":"closed"}`, admin); resp.StatusCode != http.StatusConflict {
		t.Fatalf("非法路徑應回 409：%d", resp.StatusCode)
	} else if code, _ := envelope(t, resp); code != int(CodeActivityTransitionInvalid) {
		t.Errorf("非法路徑應回 2031，實際 %d", code)
	}

	// 合法開放，然後同態重複：2030（現值已經就是你要的那個）。
	e.activityRequest(t, http.MethodPut, "/admin/activities/"+id+"/status", `{"status":"active"}`, admin)
	if resp := e.activityRequest(t, http.MethodPut, "/admin/activities/"+id+"/status",
		`{"status":"active"}`, admin); resp.StatusCode != http.StatusConflict {
		t.Fatalf("同態重複應回 409：%d", resp.StatusCode)
	} else if code, _ := envelope(t, resp); code != int(CodeActivityStatusConflict) {
		t.Errorf("同態重複應回 2030，實際 %d", code)
	}

	// 標識寫壞與查無此活動是同一句話（不讓端點變成標識格式探測器）。
	if resp := e.activityRequest(t, http.MethodPut, "/admin/activities/not-a-uuid/status",
		`{"status":"active"}`, admin); resp.StatusCode != http.StatusNotFound {
		t.Errorf("非法標識應回 404：%d", resp.StatusCode)
	}
}

// TestActivityEndpointConcurrentProfileEdit 驗收：同一份畫面上的第二次提交拿到 2013，
// 而且一個字都不覆蓋（與帳戶資料編輯同一取向：正確性來自資料庫條件，不來自先查後寫）。
func TestActivityEndpointConcurrentProfileEdit(t *testing.T) {
	e := newActivityEnv(t)
	admin := cookieHeader(e.liveAdminCookie(t, "Activity.Cas"))
	id := e.createActivity(t, admin, "併發編輯取證")

	first := e.activityRequest(t, http.MethodPut, "/admin/activities/"+id,
		`{"name":"贏家的名字","description":"贏家的描述","expected_name":"併發編輯取證","expected_description":"測試用的場"}`, admin)
	if first.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(first.Body)
		t.Fatalf("第一次編輯應成功：%s", body)
	}
	second := e.activityRequest(t, http.MethodPut, "/admin/activities/"+id,
		`{"name":"輸家的名字","description":"輸家的描述","expected_name":"併發編輯取證","expected_description":"測試用的場"}`, admin)
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("落敗的編輯應回 409：%d", second.StatusCode)
	}
	if code, _ := envelope(t, second); code != int(CodeProfileConflict) {
		t.Errorf("落敗的編輯應沿用 2013（同一句話、同一處置），實際 %d", code)
	}
	detail := mustActivityItem(t, e.activityRequest(t, http.MethodGet, "/admin/activities/"+id, "", admin))
	if detail["name"] != "贏家的名字" || detail["description"] != "贏家的描述" {
		t.Errorf("落敗的編輯覆蓋了現值：%v", detail)
	}
	if got := countActivityRows(t, e.db, "activity_audit"); got != 2 {
		t.Errorf("落敗的編輯不該留審計（建立與成功編輯各一筆），實際 %d 筆", got)
	}
}

// TestActivityEndpointManagerAssignmentNeedsRoot 驗收：指派的寫法只在 Root 那一側，
// 四種失敗各有各的碼，而指派生效之後那位新管理人立刻讀得到這個活動。
func TestActivityEndpointManagerAssignmentNeedsRoot(t *testing.T) {
	e := newActivityEnv(t)
	root := e.rootCookie(t)
	owner := e.liveAdminCookie(t, "Activity.AssignOwner")
	late := e.liveAdminCookie(t, "Activity.AssignLate")
	e.liveAdminCookie(t, "Activity.AssignDoomed")
	id := e.createActivity(t, cookieHeader(owner), "要人來管的場")

	// 管理員自己加人：權限不足（2011），不是「找不到人」。
	if resp := e.activityRequest(t, http.MethodPost, "/root/activities/"+id+"/managers",
		`{"account_id":"`+activityGhostAccountID+`"}`, cookieHeader(owner)); resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("管理人自行加人應被拒：%s", body)
	} else if code, _ := envelope(t, resp); code != int(CodePermissionDenied) {
		t.Errorf("管理人自行加人應回 2011，實際 %d", code)
	}

	// 找出那位新管理人的帳戶標識（Root 的管理員目錄讀得到）。
	lateID := adminAccountIDByName(t, e, root, "Activity.AssignLate")
	assigned := e.activityRequest(t, http.MethodPost, "/root/activities/"+id+"/managers",
		`{"account_id":"`+lateID+`"}`, cookieHeader(root))
	if assigned.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(assigned.Body)
		t.Fatalf("Root 指派應成功：%s", body)
	}
	if count := mustActivityItem(t, assigned)["manager_count"].(float64); count != 2 {
		t.Errorf("指派後應有兩位管理人，實際 %v", count)
	}

	// 指派生效之後他立刻讀得到（活動作用域現讀，不是登入時凍結的快照）。
	if resp := e.activityRequest(t, http.MethodGet, "/admin/activities/"+id, "", cookieHeader(late)); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("被指派之後應讀得到該活動：%s", body)
	}

	// 重複指派是 2032（不是謊報成功）；查無此人是 1001；已刪除的管理員是 2015。
	if resp := e.activityRequest(t, http.MethodPost, "/root/activities/"+id+"/managers",
		`{"account_id":"`+lateID+`"}`, cookieHeader(root)); resp.StatusCode != http.StatusConflict {
		t.Fatalf("重複指派應回 409：%d", resp.StatusCode)
	} else if code, _ := envelope(t, resp); code != int(CodeActivityManagerTaken) {
		t.Errorf("重複指派應回 2032，實際 %d", code)
	}
	if resp := e.activityRequest(t, http.MethodPost, "/root/activities/"+id+"/managers",
		`{"account_id":"`+"0192f0c4-1c9a-7000-8000-000000000fee"+`"}`, cookieHeader(root)); resp.StatusCode != http.StatusNotFound {
		t.Errorf("指派給從未存在的帳戶應回 404：%d", resp.StatusCode)
	}
	// 先把那位帳戶送進刪除終態，再試指派。
	doomedID := adminAccountIDByName(t, e, root, "Activity.AssignDoomed")
	if resp := e.activityRequest(t, http.MethodDelete, "/root/admins/"+doomedID,
		"", cookieHeader(root)); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 軟刪除管理員應成功：%s", body)
	}
	if resp := e.activityRequest(t, http.MethodPost, "/root/activities/"+id+"/managers",
		`{"account_id":"`+doomedID+`"}`, cookieHeader(root)); resp.StatusCode != http.StatusConflict {
		t.Fatalf("指派終態帳戶應回 409：%d", resp.StatusCode)
	} else if code, _ := envelope(t, resp); code != int(CodeAdminDeleted) {
		t.Errorf("指派終態帳戶應沿用 2015，實際 %d", code)
	}
	// 名冊讀法：管理人在內、外人讀不到；撤銷之後那行立刻消失，再撤一次是查無。
	roster := e.activityRequest(t, http.MethodGet, "/admin/activities/"+id+"/managers", "", cookieHeader(owner))
	if roster.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(roster.Body)
		t.Fatalf("管理人讀自己的名冊應成功：%s", body)
	}
	var got activityManagerRosterResponse
	if err := json.NewDecoder(roster.Body).Decode(&got); err != nil {
		t.Fatalf("解析名冊失敗：%v", err)
	}
	if len(got.Managers) != 2 {
		t.Errorf("名冊應有兩行（建立者與新指派的），實際 %d 行", len(got.Managers))
	}
	for _, row := range got.Managers {
		if row.AccountID == "" || row.DisplayName == "" || row.AccountStatus != "active" || row.GrantedAt == "" {
			t.Errorf("名冊每行都要帶得出顯示名與現狀，實際 %+v", row)
		}
	}
	if resp := e.activityRequest(t, http.MethodGet, "/admin/activities/"+id+"/managers", "",
		cookieHeader(e.liveAdminCookie(t, "Activity.RosterStranger"))); resp.StatusCode != http.StatusNotFound {
		t.Errorf("外人讀不到這個活動的名冊：%d", resp.StatusCode)
	}
	if resp := e.activityRequest(t, http.MethodDelete, "/root/activities/"+id+"/managers/"+lateID,
		"", cookieHeader(root)); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 撤銷指派應成功：%s", body)
	} else if count := mustActivityItem(t, resp)["manager_count"].(float64); count != 1 {
		t.Errorf("撤銷後應剩一位管理人，實際 %v", count)
	}
	if resp := e.activityRequest(t, http.MethodDelete, "/root/activities/"+id+"/managers/"+lateID,
		"", cookieHeader(root)); resp.StatusCode != http.StatusNotFound {
		t.Errorf("重複撤銷不可謊報成功，應回 404：%d", resp.StatusCode)
	}
	// 撤銷之後他立刻讀不到那個活動（同一道閘，反向也成立）。
	if resp := e.activityRequest(t, http.MethodGet, "/admin/activities/"+id, "", cookieHeader(late)); resp.StatusCode != http.StatusNotFound {
		t.Errorf("撤銷之後應立刻失去可見範圍：%d", resp.StatusCode)
	}
}

// TestActivityEndpointForeignOriginIsRefused 驗收：這條寫入鏈走的是全服務同一把 CSRF 閘——
// 外站來源帶著有效 Cookie 也進不來，而且這一句發生在授權判定之前。
func TestActivityEndpointForeignOriginIsRefused(t *testing.T) {
	e := newActivityEnv(t)
	admin := e.liveAdminCookie(t, "Activity.Origin")
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+"/admin/activities",
		bytes.NewReader([]byte(`{"name":"跨站送進來的","description":""}`)))
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
	if got := countActivityRows(t, e.db, "activities"); got != 0 {
		t.Errorf("被來源閘擋下的請求不該落庫，實際 %d 行", got)
	}
}

// countActivityRows 統計一張表的筆數。
func countActivityRows(t *testing.T, db *database.DB, table string) int {
	t.Helper()
	var got int
	if err := db.SQL().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&got); err != nil {
		t.Fatalf("統計 %s 失敗：%v", table, err)
	}
	return got
}

// adminAccountIDByName 從 Root 的管理員目錄裡按登入名找出那位帳戶的標識。
func adminAccountIDByName(t *testing.T, e *activityEnv, root *http.Cookie, login string) string {
	t.Helper()
	resp := e.activityRequest(t, http.MethodGet, "/root/admins?page=1&page_size=100", "", cookieHeader(root))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("讀管理員目錄應成功：%s", body)
	}
	var page struct {
		Admins []struct {
			AccountID string `json:"account_id"`
			LoginName string `json:"login_name"`
		} `json:"admins"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("解析管理員目錄失敗：%v", err)
	}
	for _, row := range page.Admins {
		if row.LoginName == login {
			return row.AccountID
		}
	}
	t.Fatalf("管理員目錄裡找不到 %s（實際 %+v）", login, page.Admins)
	return ""
}
