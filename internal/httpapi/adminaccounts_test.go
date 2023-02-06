// adminaccounts_test.go 是「管理員建立普通帳戶」的傳輸層端到端證據：
// 真資料庫＋真用例＋完整中介層鏈，從 Root 開設管理員、管理員真實登入與首改，
// 一路走到 POST /admin/accounts、策略開關的兩側、偽造欄位、重複提交與審計歸屬。
//
// 刻意不收的東西：
//   - 沒有替身：授權、首次改密門閂、策略現讀、審計都跨層走真路徑，接錯線就會紅；
//   - 不碰任何真實資料目錄、不佔 5206，全程用本次專屬的暫存庫與系統時鐘。
package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/adminacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/stdacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 測試口令：只活在測試進程的記憶體，不是任何環境的憑據。
const (
	stdTestRootPassword  = "adminaccounts-test-root-口令"
	stdTestAdminPassword = "adminaccounts-test-管理員口令"
	stdTestInitial       = "adminaccounts-test-一次性初始口令"
	stdTestChanged       = "adminaccounts-test-改後口令"
)

// stdEnv 是本次測試專屬的現場與測試服務。
type stdEnv struct {
	ts       *httptest.Server
	db       *database.DB
	accounts *account.Store
	policy   *acctpolicy.Store
}

// newStdEnv 建立現場並啟動一臺掛了建立普通帳戶端點的測試服務。
func newStdEnv(t *testing.T) *stdEnv {
	t.Helper()
	clock := timeutil.System()
	dir := t.TempDir()
	db, err := database.Open(context.Background(), database.Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
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
	sessions, err := session.NewStoreWithPolicy(clock, time.Hour, session.Policy{})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	rootHash, err := credential.Hash(stdTestRootPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試 Root 憑據失敗：%v", err)
	}
	auditStore := audit.NewStore(clock)
	policyStore := acctpolicy.NewStore(clock)
	authService, err := auth.New(auth.Deps{
		DB: db, Sessions: sessions, Accounts: accountsStore, Grants: grantsStore,
		Audits: auditStore, RootPasswordHash: rootHash, Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立登入用例失敗：%v", err)
	}
	adminService, err := adminacct.New(adminacct.Deps{
		DB: db, Accounts: accountsStore, Grants: grantsStore,
		Audits: auditStore, Sessions: sessions, Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立管理員用例失敗：%v", err)
	}
	policyService, err := acctpolicy.New(acctpolicy.Deps{
		DB: db, Store: policyStore, Audits: auditStore,
	})
	if err != nil {
		t.Fatalf("建立策略用例失敗：%v", err)
	}
	stdService, err := stdacct.New(stdacct.Deps{
		DB: db, Accounts: accountsStore, Grants: grantsStore, Policy: policyStore,
		Sessions: sessions, Audits: auditStore, Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立普通帳戶用例失敗：%v", err)
	}
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{
		Auth: authService, Admins: adminService, AccountPolicy: policyService,
		StandardAccounts: stdService, Clock: clock,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &stdEnv{ts: ts, db: db, accounts: accountsStore, policy: policyStore}
}

// rootCookie 以測試 Root 口令登入並取得本次專用的會話 Cookie。
func (e *stdEnv) rootCookie(t *testing.T) *http.Cookie {
	t.Helper()
	resp := postJSON(t, e.ts, "/auth/root/login",
		`{"password":"`+stdTestRootPassword+`"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 登入應成功：%d %s", resp.StatusCode, body)
	}
	return loginCookie(t, resp)
}

// setAdminCreate 經策略端點（Root 的真路徑）翻動管理員建號開關，其餘兩欄按出廠形態寫回。
func (e *stdEnv) setAdminCreate(t *testing.T, root *http.Cookie, on bool) {
	t.Helper()
	resp := putJSON(t, e.ts, "/root/account-policy", policyBody(on, "closed", false), "",
		map[string]string{"Cookie": cookieHeader(root)})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("保存策略應成功：%d %s", resp.StatusCode, body)
	}
}

// loginRaw 發一次帳戶登入並原樣回傳回應（成功與否都由斷言處置）。
func (e *stdEnv) loginRaw(t *testing.T, login, password string) *http.Response {
	t.Helper()
	return postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+password+`"}`, "", nil)
}

// loginAs 以登入名與口令取得會話回應，不成功即終止。
func (e *stdEnv) loginAs(t *testing.T, login, password string) *http.Response {
	t.Helper()
	resp := e.loginRaw(t, login, password)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("登入 %s 應成功：%d %s", login, resp.StatusCode, body)
	}
	return resp
}

// liveAdminCookie 走完整交付鏈取得一位「已完成首次改密」的管理員會話：
// Root 經端點開設 → 新管理員以初始口令登入 → 本人改密 → 用新口令重登。
// 用真路徑而不是直寫 SQL：本步的證據鏈要接在 R2-001 與 R1-019 的既有門閂上。
func (e *stdEnv) liveAdminCookie(t *testing.T, login string) *http.Cookie {
	t.Helper()
	root := e.rootCookie(t)
	resp := postJSON(t, e.ts, "/root/admins",
		`{"login_name":"`+login+`","display_name":"現行管理員","password":"`+stdTestAdminPassword+`"}`,
		"", map[string]string{"Cookie": cookieHeader(root)})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 開設管理員應成功：%d %s", resp.StatusCode, body)
	}
	first := e.loginAs(t, login, stdTestAdminPassword)
	cookie := loginCookie(t, first)
	changed := postJSON(t, e.ts, "/auth/password/change",
		`{"current_password":"`+stdTestAdminPassword+`","new_password":"`+stdTestChanged+`"}`,
		"", map[string]string{"Cookie": cookieHeader(cookie)})
	if changed.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(changed.Body)
		t.Fatalf("首次改密應成功：%d %s", changed.StatusCode, body)
	}
	second := e.loginAs(t, login, stdTestChanged)
	return loginCookie(t, second)
}

// createAccount 發一次 POST /admin/accounts，本體與附加標頭原樣交出去。
func (e *stdEnv) createAccount(t *testing.T, body string, cookie *http.Cookie,
	extra map[string]string) *http.Response {
	t.Helper()
	headers := map[string]string{}
	if cookie != nil {
		headers["Cookie"] = cookieHeader(cookie)
	}
	for k, v := range extra {
		headers[k] = v
	}
	return postJSON(t, e.ts, "/admin/accounts", body, "", headers)
}

// stdBody 產生一份完整的建立本體（三個欄位一個都不缺）。
func stdBody(login, display, password string) string {
	payload := map[string]any{
		"login_name":   login,
		"display_name": display,
		"password":     password,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// envelopeCode 讀出錯誤信封的機器碼（斷言分流用；訊息另查）。
func envelopeCode(t *testing.T, resp *http.Response) int {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	var env struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("錯誤信封解析失敗：%s", body)
	}
	return env.Code
}

// countTableRows 數一張表的行數（斷言「被拒的請求不產生寫入」用）。
func countTableRows(t *testing.T, db *database.DB, table string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("計數 %s 失敗：%v", table, err)
	}
	return n
}

// countCreateAudits 數 root_audit 裡的建號審計筆數。
func countCreateAudits(t *testing.T, db *database.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = 'account.create_standard'").
		Scan(&n); err != nil {
		t.Fatalf("計數建號審計失敗：%v", err)
	}
	return n
}

// TestAdminCreateStandardFullLoop 完整閉環：Root 打開關 → 管理員真實登入 →
// POST /admin/accounts 得 201 與恰好七鍵回應 → 新建普通帳戶以初始口令登入、
// 被首改門閂擋在非必要的入口（2010）→ 完成改密後一切如常、舊口令徹底失效。
func TestAdminCreateStandardFullLoop(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "loop.admin")

	resp := e.createAccount(t, stdBody("New.Player", "新玩家", stdTestInitial), admin, nil)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("有權管理員建立應成功：%d %s", resp.StatusCode, body)
	}
	var created map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("解析建立回應失敗：%v", err)
	}
	wantKeys := []string{"account_id", "login_name", "display_name", "status",
		"must_change_password", "created_at", "request_id"}
	if len(created) != len(wantKeys) {
		t.Fatalf("回應鍵集合應恰好是 %v，實際 %v", wantKeys, created)
	}
	for _, key := range wantKeys {
		if _, ok := created[key]; !ok {
			t.Errorf("回應缺少欄位 %s", key)
		}
	}
	if created["status"] != "active" || created["must_change_password"] != true ||
		created["login_name"] != "New.Player" {
		t.Errorf("回應應帶出服務端判定的形態，實際 %v", created)
	}
	// 「已建立」不等於「已加入活動」：回應根本沒有一個活動欄位可被誤讀；
	// 也沒有口令、雜湊、會話材料與 roles（建的帳戶恆無授予）。
	raw, err := json.Marshal(created)
	if err != nil {
		t.Fatalf("重新編碼回應失敗：%v", err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{"activity", "password_hash", "argon2id", "token", "cookie", "roles", strings.ToLower(stdTestInitial)} {
		if strings.Contains(text, forbidden) {
			t.Errorf("建立回應不得含 %q：實際 %s", forbidden, text)
		}
	}

	// 新建的普通帳戶走第一部分的真實通路：初始口令可登入、帶著首改義務、
	// 受保護端點在改密前被 2010 擋住、改密後舊口令徹底失效。
	first := e.loginAs(t, "new.PLAYER", stdTestInitial)
	cookie := loginCookie(t, first)
	blocked := getAuth(t, e.ts, "/auth/devices", cookieHeader(cookie), "", "")
	if blocked.StatusCode != http.StatusForbidden || envelopeCode(t, blocked) != int(CodePasswordChangeRequired) {
		t.Errorf("首改未完成時受保護端點應回 2010/403，實際 %d", blocked.StatusCode)
	}
	changed := postJSON(t, e.ts, "/auth/password/change",
		`{"current_password":"`+stdTestInitial+`","new_password":"`+stdTestChanged+`"}`,
		"", map[string]string{"Cookie": cookieHeader(cookie)})
	if changed.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(changed.Body)
		t.Fatalf("新建帳戶首次改密應成功：%d %s", changed.StatusCode, body)
	}
	e.loginAs(t, "New.Player", stdTestChanged)
	if stale := e.loginRaw(t, "New.Player", stdTestInitial); stale.StatusCode != http.StatusUnauthorized {
		t.Errorf("舊的一次性口令必須徹底失效，實際 %d", stale.StatusCode)
	}
	// 改密後他的會話解析不帶任何角色：普通帳戶就是普通帳戶。
	sess := getAuth(t, e.ts, "/auth/session", cookieHeader(loginCookie(t, e.loginAs(t, "New.Player", stdTestChanged))), "", "")
	var sessionBody struct {
		Roles []string `json:"roles"`
	}
	body, _ := io.ReadAll(sess.Body)
	if err := json.Unmarshal(body, &sessionBody); err != nil {
		t.Fatalf("解析會話回應失敗：%s", body)
	}
	if len(sessionBody.Roles) != 0 {
		t.Errorf("新建普通帳戶的會話不該帶出角色，實際 %v", sessionBody.Roles)
	}
}

// TestPolicyClosedRejectsWithoutWrites 開關關閉時（出廠形態）提交回 2017/403，
// 帳戶與審計一行都不多；四語言訊息齊備；Root 走同一端點也吃同一句（無例外）。
func TestPolicyClosedRejectsWithoutWrites(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	// 出廠全關，不先翻開：這一條量的是默認形態下的拒絕。
	admin := e.liveAdminCookie(t, "gated.admin")

	accountsBefore := countTableRows(t, e.db, "accounts")
	auditsBefore := countTableRows(t, e.db, "root_audit")
	resp := e.createAccount(t, stdBody("gated.player", "會被擋", stdTestInitial), admin, nil)
	if resp.StatusCode != http.StatusForbidden || envelopeCode(t, resp) != int(CodeAccountCreationDisabled) {
		t.Fatalf("開關關閉時應回 2017/403，實際 %d", resp.StatusCode)
	}
	// 四語言齊備：同一類請求換四個 Accept-Language，任何一語拿到空訊息都是缺陷。
	for _, tag := range []string{"zh-CN", "zh-TW", "en-US", "ja-JP"} {
		r := e.createAccount(t, stdBody("gated.player", "會被擋", stdTestInitial), admin,
			map[string]string{"Accept-Language": tag})
		var env struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("%s 信封解析失敗：%s", tag, body)
		}
		if env.Code != int(CodeAccountCreationDisabled) || env.Message == "" {
			t.Errorf("%s 的 2017 訊息必須存在，實際 code=%d message=%q", tag, env.Code, env.Message)
		}
	}
	// Root 無例外：開著才放行（見 TestRootPassesWhenOpen），關著照樣被拒。
	rootResp := e.createAccount(t, stdBody("root.via.admin", "Root 走管理員路", stdTestInitial), root, nil)
	if rootResp.StatusCode != http.StatusForbidden || envelopeCode(t, rootResp) != int(CodeAccountCreationDisabled) {
		t.Errorf("Root 走 /admin/accounts 同受開關約束，實際 %d", rootResp.StatusCode)
	}
	if n := countTableRows(t, e.db, "accounts"); n != accountsBefore {
		t.Errorf("被策略擋下的建立不得多出帳戶（前 %d 後 %d）", accountsBefore, n)
	}
	if n := countTableRows(t, e.db, "root_audit"); n != auditsBefore {
		t.Errorf("被策略擋下的建立不得追加審計（前 %d 後 %d）", auditsBefore, n)
	}
}

// TestRootPassesWhenOpen Root 在開關打開時走這條端點建得成，且審計照實記 actor=root。
func TestRootPassesWhenOpen(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)

	resp := e.createAccount(t, stdBody("root.path.ok", "Root 經此路建立", stdTestInitial), root, nil)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("開著時 Root 走這條端點應放行（不豁免≠禁止），實際 %d %s", resp.StatusCode, body)
	}
	var actorKind string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT actor_kind FROM root_audit WHERE action = 'account.create_standard'").
		Scan(&actorKind); err != nil {
		t.Fatalf("讀回建號審計失敗：%v", err)
	}
	if actorKind != string(audit.ActorRoot) {
		t.Errorf("Root 的動作應照實記 root，實際 %q", actorKind)
	}
}

// TestAuthorizationMatrix 匿名 2002、普通帳戶 2011、跨站來源 2005 且零寫入、
// 未知方法 1002：這一條端點的鑑別面逐格各是各句。
func TestAuthorizationMatrix(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "matrix.admin")

	anon := e.createAccount(t, stdBody("matrix.anon", "匿名", stdTestInitial), nil, nil)
	if anon.StatusCode != http.StatusUnauthorized || envelopeCode(t, anon) != int(CodeNotAuthenticated) {
		t.Errorf("匿名應回 2002/401，實際 %d", anon.StatusCode)
	}
	// 種一個沒有授予、不欠改密的普通帳戶並登入：這一條量的是權限，不摻門閂干擾。
	hash, err := credential.Hash(stdTestInitial, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	if _, err := e.accounts.Create(context.Background(), e.db.SQL(), account.NewInput{
		LoginName: "matrix.plain", DisplayName: "普通帳戶", PasswordHash: hash,
		Type: account.TypeStandard, Status: account.StatusActive,
	}); err != nil {
		t.Fatalf("種入普通帳戶失敗：%v", err)
	}
	plainCookie := loginCookie(t, e.loginAs(t, "matrix.plain", stdTestInitial))
	forbidden := e.createAccount(t, stdBody("matrix.escalate", "企圖建號", stdTestInitial), plainCookie, nil)
	if forbidden.StatusCode != http.StatusForbidden || envelopeCode(t, forbidden) != int(CodePermissionDenied) {
		t.Errorf("普通帳戶應回 2011/403，實際 %d", forbidden.StatusCode)
	}
	crossSite := e.createAccount(t, stdBody("matrix.cross", "跨站", stdTestInitial), admin,
		map[string]string{"Origin": "http://evil.example"})
	if crossSite.StatusCode != http.StatusForbidden || envelopeCode(t, crossSite) != int(CodeOriginForbidden) {
		t.Errorf("跨站來源應回 2005/403，實際 %d", crossSite.StatusCode)
	}
	// GET 已是目錄讀取（本步的變更），405 那一格改由兩個未登記的方法量：
	// 「/admin/accounts 只認 GET／HEAD／POST」與「單筆路徑只認 GET／HEAD／PUT」。
	for _, probe := range []struct{ method, path string }{
		{http.MethodDelete, "/admin/accounts"},
		{http.MethodPatch, "/admin/accounts/00000000-0000-7000-8000-000000000000"},
	} {
		wrongMethod := sendMethod(t, e.ts, probe.method, probe.path, admin)
		if wrongMethod.StatusCode != http.StatusMethodNotAllowed ||
			envelopeCode(t, wrongMethod) != int(CodeMethodNotAllowed) {
			t.Errorf("%s %s 應回 1002/405，實際 %d", probe.method, probe.path, wrongMethod.StatusCode)
		}
	}
	if n := countCreateAudits(t, e.db); n != 0 {
		t.Errorf("被拒矩陣不得產生建號審計，實際 %d 筆", n)
	}
}

// TestForgedClaimsRejectedAtProtocolLayer 本體帶 role／account_type／status／
// subject_kind／must_change_password／activity_id 六種自報欄位全回 1004，
// 零寫入零審計：「建的是哪一類主體」在協定層就沒有一個可以填的格子。
func TestForgedClaimsRejectedAtProtocolLayer(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "forged.admin")
	accountsBefore := countTableRows(t, e.db, "accounts")

	bodies := []string{
		`{"login_name":"f1","display_name":"企圖","password":"` + stdTestInitial + `","role":"server_admin"}`,
		`{"login_name":"f2","display_name":"企圖","password":"` + stdTestInitial + `","account_type":"guest"}`,
		`{"login_name":"f3","display_name":"企圖","password":"` + stdTestInitial + `","status":"disabled"}`,
		`{"login_name":"f4","display_name":"企圖","password":"` + stdTestInitial + `","subject_kind":"root"}`,
		`{"login_name":"f5","display_name":"企圖","password":"` + stdTestInitial + `","must_change_password":false}`,
		`{"login_name":"f6","display_name":"企圖","password":"` + stdTestInitial + `","activity_id":"00000000-0000-7000-8000-000000000000"}`,
	}
	for i, body := range bodies {
		resp := e.createAccount(t, body, admin, nil)
		if resp.StatusCode != http.StatusBadRequest || envelopeCode(t, resp) != int(CodeInvalidBody) {
			t.Errorf("第 %d 份偽造本體應回 1004/400，實際 %d", i+1, resp.StatusCode)
		}
	}
	if n := countTableRows(t, e.db, "accounts"); n != accountsBefore {
		t.Errorf("偽造本體不得多出帳戶（前 %d 後 %d）", accountsBefore, n)
	}
	if n := countCreateAudits(t, e.db); n != 0 {
		t.Errorf("偽造本體不得產生建號審計，實際 %d 筆", n)
	}
}

// TestDuplicateAndResubmitConverge 重複名稱與丟失回應後的重試都收斂到 2012/409，
// 帳戶與建號審計各只多一行一筆：正確性來自資料庫唯一索引，不是先查後插。
func TestDuplicateAndResubmitConverge(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "dup.admin")

	first := e.createAccount(t, stdBody("dup.player", "重複測試", stdTestInitial), admin, nil)
	if first.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(first.Body)
		t.Fatalf("首次建立應成功：%d %s", first.StatusCode, body)
	}
	for _, variant := range []string{"dup.player", "DUP.PLAYER", "ｄｕｐ.ｐｌａｙｅｒ"} {
		resp := e.createAccount(t, stdBody(variant, "重複測試", stdTestInitial), admin, nil)
		if resp.StatusCode != http.StatusConflict || envelopeCode(t, resp) != int(CodeLoginNameTaken) {
			t.Errorf("%q 應回 2012/409，實際 %d", variant, resp.StatusCode)
		}
	}
	// dup.admin 與 loop/admin 系列各異步建號：這裡只斷言建號審計恰好一筆。
	if n := countCreateAudits(t, e.db); n != 1 {
		t.Errorf("三次重複提交後建號審計仍只一筆，實際 %d", n)
	}
}

// TestAuditActorIsRealOperator 審計的真實歸屬：成功建立後 root_audit 裡那一筆的
// actor_id 就是那位管理員本人的帳戶標識——既不是 Root 的保留標識，也不是新建帳戶自己；
// 同時本步沒有新增任何審計查閱入口（/root/audit 不存在）。
func TestAuditActorIsRealOperator(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "actor.admin")

	resp := e.createAccount(t, stdBody("actor.player", "歸屬驗證", stdTestInitial), admin, nil)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("建立應成功：%d %s", resp.StatusCode, body)
	}
	var created struct {
		AccountID string `json:"account_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("解析建立回應失敗：%v", err)
	}
	// 操作者的帳戶標識：從他此刻的會話反查（/auth/session 回的是服務端認定的身分）。
	sess := getAuth(t, e.ts, "/auth/session", cookieHeader(admin), "", "")
	var sessionBody struct {
		AccountID string `json:"account_id"`
	}
	body, _ := io.ReadAll(sess.Body)
	if err := json.Unmarshal(body, &sessionBody); err != nil {
		t.Fatalf("解析會話回應失敗：%s", body)
	}
	var actorKind, actorID string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT actor_kind, actor_id FROM root_audit
		 WHERE action = 'account.create_standard' AND target_id = ?`, created.AccountID).
		Scan(&actorKind, &actorID); err != nil {
		t.Fatalf("讀回建號審計失敗：%v", err)
	}
	if actorKind != string(audit.ActorAdmin) {
		t.Errorf("actor.kind 應為 admin，實際 %q", actorKind)
	}
	if actorID != sessionBody.AccountID {
		t.Errorf("actor.id 應是操作者本人帳戶（%s），實際 %s", sessionBody.AccountID, actorID)
	}
	if actorID == created.AccountID {
		t.Error("actor.id 不得是新建帳戶自己：那是把「誰建的」記成了「建了誰」")
	}
	// 沒有新增任何審計查閱入口：Root 域不因本步多一條 HTTP 路。
	noRead := getAuth(t, e.ts, "/root/audit", cookieHeader(root), "", "")
	if noRead.StatusCode != http.StatusNotFound {
		t.Errorf("不得出現 /root/audit 查閱端點，實際 %d", noRead.StatusCode)
	}
}

// TestEndpointAbsentWithoutWiring 未注入用例時端點一個都不掛：建號、目錄、單筆與狀態
// 四個入口全都回到 1001，與未掛載時逐字相同——「裝配了什麼就服務什麼」沒有分支。
func TestEndpointAbsentWithoutWiring(t *testing.T) {
	clock := timeutil.System()
	dir := t.TempDir()
	db, err := database.Open(context.Background(), database.Options{
		Path: filepath.Join(dir, "evernight.db"), BusyTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
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
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{Clock: clock})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp := postJSON(t, ts, "/admin/accounts", "{}", "", nil)
	if resp.StatusCode != http.StatusNotFound || envelopeCode(t, resp) != int(CodeNotFound) {
		t.Errorf("未注入用例時 POST /admin/accounts 應回 1001，實際 %d", resp.StatusCode)
	}
	// 本組端點的四個入口同一句話：沒裝配就一個都不掛，連「目錄讀得到但改不了狀態」
	// 這種半套形態也不可能出現。
	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, "/admin/accounts"},
		{http.MethodGet, "/admin/accounts/00000000-0000-7000-8000-000000000000"},
		{http.MethodPut, "/admin/accounts/00000000-0000-7000-8000-000000000000"},
		{http.MethodPut, "/admin/accounts/00000000-0000-7000-8000-000000000000/status"},
	} {
		got := sendMethod(t, ts, probe.method, probe.path, nil)
		if got.StatusCode != http.StatusNotFound || envelopeCode(t, got) != int(CodeNotFound) {
			t.Errorf("未注入用例時 %s %s 應回 1001，實際 %d", probe.method, probe.path, got.StatusCode)
		}
	}
}
