// rootadmins_test.go 是「Root 開設管理員帳戶」的傳輸層端到端證據：
// 真資料庫＋真用例＋完整中介層鏈，從 Root 登入拿到 Cookie 一路走到
// 新管理員首次登入、被首次改密門閂擋住、改完放行的整條時間線。
//
// 刻意不收的東西：
//   - 沒有替身：授權、授予讀取、門閂都跨層走真路徑，接錯線就會紅；
//   - 不碰任何真實資料目錄、不佔 5206、不等真實週期（會話期限取一小時，全程注入系統時鐘）。

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
	"github.com/kagurazakayashi/EvernightRealm/internal/adminacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 測試口令：只活在測試進程的記憶體，不是任何環境的憑據。
const (
	adminTestRootPassword  = "rootadmins-test-root-口令"
	adminTestInitialPasswd = "rootadmins-test-一次性初始口令"
	adminTestChangedPasswd = "rootadmins-test-改後口令"
	adminTestPlainPasswd   = "rootadmins-test-普通帳戶口令"
)

// adminEnv 是本次測試專屬的現場：临时庫、真實登入用例與真實開設用例。
type adminEnv struct {
	ts       *httptest.Server
	db       *database.DB
	accounts *account.Store
	admins   *adminacct.Service
}

// newAdminEnv 建立現場；rootPassword 為空時重現「Root 尚未初始化」的部署。
func newAdminEnv(t *testing.T, rootPassword string) *adminEnv {
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
	sessions, err := session.NewStoreWithPolicy(clock, time.Hour, session.Policy{})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	rootHash := ""
	if rootPassword != "" {
		rootHash, err = credential.Hash(rootPassword, credential.TestParams)
		if err != nil {
			t.Fatalf("產生測試 Root 憑據失敗：%v", err)
		}
	}
	accountsStore := account.NewStore(clock)
	grantsStore := grant.NewStore(clock)
	auditStore := audit.NewStore(clock)
	authService, err := auth.New(auth.Deps{
		DB:               db,
		Sessions:         sessions,
		Accounts:         accountsStore,
		Grants:           grantsStore,
		Audits:           auditStore,
		RootPasswordHash: rootHash,
		Hashing:          credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立登入用例失敗：%v", err)
	}
	adminService, err := adminacct.New(adminacct.Deps{
		DB:       db,
		Accounts: accountsStore,
		Grants:   grantsStore,
		Audits:   auditStore,
		Hashing:  credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立開設用例失敗：%v", err)
	}
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{Auth: authService, Admins: adminService, Clock: clock})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &adminEnv{ts: ts, db: db, accounts: accountsStore, admins: adminService}
}

// rootCookie 以測試 Root 口令登入並取得本次專用的會話 Cookie。
func (e *adminEnv) rootCookie(t *testing.T) *http.Cookie {
	t.Helper()
	resp := postJSON(t, e.ts, "/auth/root/login",
		`{"password":"`+adminTestRootPassword+`"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 登入應成功：%d %s", resp.StatusCode, body)
	}
	return loginCookie(t, resp)
}

// cookieHeader 把 Cookie 組成名值對字串。
func cookieHeader(cookie *http.Cookie) string { return sessionCookieName + "=" + cookie.Value }

// loginAs 以登入名與口令取得會話 Cookie（用來取「新開出的管理員」那一臺）。
func (e *adminEnv) loginAs(t *testing.T, login, password string) *http.Response {
	t.Helper()
	return postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+password+`"}`, "", nil)
}

// createAdminRaw 發一次 POST /root/admins，把本體原樣交出去（ malformed 用例要用）。
func createAdminRaw(t *testing.T, ts *httptest.Server, body string, cookie *http.Cookie,
	origin string, extra map[string]string) *http.Response {
	t.Helper()
	headers := map[string]string{"Cookie": cookieHeader(cookie)}
	for k, v := range extra {
		headers[k] = v
	}
	return postJSON(t, ts, "/root/admins", body, origin, headers)
}

// createAdminBody 產生一份合法的開設本體。
func createAdminBody(login, displayName, password string) string {
	payload := map[string]any{
		"login_name":   login,
		"display_name": displayName,
		"password":     password,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// TestRootCreateAdminEndToEnd 走完整條開設時間線：Root 開人 → 清單看得到 →
// 新人以一次性口令登入並帶著角色 → 受首次改密門閂約束 → 改完放行、舊口令失效。
func TestRootCreateAdminEndToEnd(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	cookie := env.rootCookie(t)

	resp := createAdminRaw(t, env.ts,
		createAdminBody("Ops.Primary", "首任管理員", adminTestInitialPasswd),
		cookie, env.ts.URL, nil)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 開設管理員應成功：%d %s", resp.StatusCode, body)
	}
	created := decodeJSONBody(t, resp)
	if created["login_name"] != "Ops.Primary" || created["display_name"] != "首任管理員" {
		t.Errorf("回應應回可展示的身分欄位，實際 %v", created)
	}
	if created["status"] != "active" || created["must_change_password"] != true {
		t.Errorf("新建管理員應為 active 且欠首次改密，實際 %v", created)
	}
	roles, _ := created["roles"].([]any)
	if len(roles) != 1 || roles[0] != identity.RoleServerAdmin.String() {
		t.Errorf("回應應帶出服務端判定的角色，實際 %v", created["roles"])
	}
	accountID, _ := created["account_id"].(string)
	if accountID == "" {
		t.Fatal("回應應帶出新帳戶標識")
	}

	// 最小清單確認：剛開的那個人查得到，且從未登入的帳戶不帶 last_login_at。
	listResp := getAuth(t, env.ts, "/root/admins", cookieHeader(cookie), "", "")
	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("Root 列舉管理員應成功：%d %s", resp.StatusCode, body)
	}
	var list adminListResponse
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("解析清單失敗：%v", err)
	}
	if len(list.Admins) != 1 || list.Admins[0].AccountID != accountID {
		t.Fatalf("清單應恰好一位管理員，實際 %+v", list.Admins)
	}
	if list.Admins[0].LastLoginAt != "" {
		t.Errorf("從未登入不應被填上登入時刻，實際 %q", list.Admins[0].LastLoginAt)
	}

	// 新管理員首次登入（故意換一個大小寫寫法：唯一鍵比對與展示寫法分家）。
	loginResp := env.loginAs(t, "ops.PRIMARY", adminTestInitialPasswd)
	if loginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("新建管理員應能以初始口令登入：%d %s", resp.StatusCode, body)
	}
	facts := decodeJSONBody(t, loginResp)
	if facts["subject_kind"] != "account" || facts["must_change_password"] != true {
		t.Errorf("首次登入應回報帳戶主體且欠改密，實際 %v", facts)
	}
	if loginRoles, _ := facts["roles"].([]any); len(loginRoles) != 1 ||
		loginRoles[0] != identity.RoleServerAdmin.String() {
		t.Errorf("登入回應應帶出真實角色，實際 %v", facts["roles"])
	}
	adminCookie := loginCookie(t, loginResp)

	// 門閂在服務端生效：改密之前，受保護端點一律 2010（不是「藏按鈕」）。
	gated := getAuth(t, env.ts, "/auth/devices", cookieHeader(adminCookie), "", "")
	assertEnvelopeCode(t, gated, CodePasswordChangeRequired)

	// 同一枚會話問當前會話：這是唯一永遠不被本旗標擋的入口（客戶端據此知道還欠改密）。
	stillReadable := getAuth(t, env.ts, "/auth/session", cookieHeader(adminCookie), "", "")
	if stillReadable.StatusCode != http.StatusOK {
		t.Errorf("/auth/session 不應被首次改密門閂擋下：%d", stillReadable.StatusCode)
	}

	changeResp := postJSON(t, env.ts, "/auth/password/change",
		`{"current_password":"`+adminTestInitialPasswd+`","new_password":"`+adminTestChangedPasswd+`"}`,
		"", map[string]string{"Cookie": cookieHeader(adminCookie)})
	if changeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(changeResp.Body)
		t.Fatalf("首次改密應成功：%d %s", resp.StatusCode, body)
	}

	// 改密後：舊口令徹底失效；新口令登入的會話旗標已解除、角色仍在、門閂放行。
	if stale := env.loginAs(t, "ops.primary", adminTestInitialPasswd); stale.StatusCode != http.StatusUnauthorized {
		t.Errorf("一次性初始口令必須徹底失效应得 401，實際 %d", stale.StatusCode)
	}
	after := env.loginAs(t, "ops.primary", adminTestChangedPasswd)
	if after.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(after.Body)
		t.Fatalf("改密後應能以新口令登入：%d %s", after.StatusCode, body)
	}
	afterFacts := decodeJSONBody(t, after)
	if _, ok := afterFacts["must_change_password"]; ok {
		t.Errorf("旗標解除後欄位應缺席，實際 %v", afterFacts["must_change_password"])
	}
	if afterRoles, _ := afterFacts["roles"].([]any); len(afterRoles) != 1 {
		t.Errorf("改密不該動到角色，實際 %v", afterFacts["roles"])
	}
	devices := getAuth(t, env.ts, "/auth/devices", cookieHeader(loginCookie(t, after)), "", "")
	if devices.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(devices.Body)
		t.Fatalf("完成改密後受保護端點應放行：%d %s", devices.StatusCode, body)
	}

	// 審計落地且不含任何憑據材料：開設那一筆的原始行裡查不到初始口令與雜湊。
	var changes, reason string
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT changes_json, reason FROM root_audit WHERE action = 'admin.create'").
		Scan(&changes, &reason); err != nil {
		t.Fatalf("讀回開設審計失敗：%v", err)
	}
	if strings.Contains(changes, adminTestInitialPasswd) || strings.Contains(changes, "$argon2id$") {
		t.Error("審計變更摘要不得含口令明文或憑據雜湊")
	}
	if !strings.Contains(changes, identity.RoleServerAdmin.String()) {
		t.Errorf("審計應記下授予了哪個角色，實際 %s", changes)
	}
	// 清單回應本身也不得被塞進任何憑據材料。
	if strings.Contains(changes+reason, adminTestChangedPasswd) {
		t.Error("審計不得含任何口令")
	}
}

// TestCreateAdminAuthorizationMatrix 只有 Root 能開設與列舉：
// 普通帳戶、持有 server_admin 的普通管理員、匿名來源各自收到哪一句。
//
// 「普通管理員不能创建同级管理员」在这里是一條 HTTP 斷言而不是产品约定：
// 帶著有效管理員會話的請求拿到的是 2011（不是 2002／2003），
// 也就不是任何「重新登入一次試試」能繞過的東西。
func TestCreateAdminAuthorizationMatrix(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)

	// 普通帳戶（無授予）與普通管理員（有授予）都從同一條登入通路進來。
	env.livePlainAccount(t, "plain.user", adminTestPlainPasswd)
	plainCookie := loginCookie(t, env.loginAs(t, "plain.user", adminTestPlainPasswd))

	createdResp := createAdminRaw(t, env.ts,
		createAdminBody("second.admin", "第二任管理員", adminTestInitialPasswd),
		rootCookie, env.ts.URL, nil)
	if createdResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(createdResp.Body)
		t.Fatalf("Root 開設應成功：%d %s", createdResp.StatusCode, body)
	}
	adminCookie := loginCookie(t, env.loginAs(t, "second.admin", adminTestInitialPasswd))
	// 管理員要先完成首次改密才拿得到一般受保護端點；這裡直接問 /root/admins 也要先過那道閘，
	// 因此改用「已改完密」的會話來測授權，避免把 2011 的結論和 2010 混在一起。
	if resp := postJSON(t, env.ts, "/auth/password/change",
		`{"current_password":"`+adminTestInitialPasswd+`","new_password":"`+adminTestChangedPasswd+`"}`,
		"", map[string]string{"Cookie": cookieHeader(adminCookie)}); resp.StatusCode != http.StatusOK {
		t.Fatalf("管理員改密失敗：%d", resp.StatusCode)
	}
	adminCookie = loginCookie(t, env.loginAs(t, "second.admin", adminTestChangedPasswd))

	body := createAdminBody("escalation.attempt", "企圖升格", adminTestInitialPasswd)
	for name, cookie := range map[string]*http.Cookie{
		"普通帳戶":  plainCookie,
		"普通管理員": adminCookie,
	} {
		resp := createAdminRaw(t, env.ts, body, cookie, env.ts.URL, nil)
		assertEnvelopeCode(t, resp, CodePermissionDenied)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s 開設被拒應為 403，實際 %d", name, resp.StatusCode)
		}
		listResp := getAuth(t, env.ts, "/root/admins", cookieHeader(cookie), "", "")
		assertEnvelopeCode(t, listResp, CodePermissionDenied)
	}

	// 沒帶任何憑據：這是「先登入」而不是「你登入得不對」。
	noCred := postJSON(t, env.ts, "/root/admins", body, env.ts.URL, nil)
	assertEnvelopeCode(t, noCred, CodeNotAuthenticated)

	// Cookie＋Bearer 混用：在碰到授權之前就拒掉。
	mixed := postJSON(t, env.ts, "/root/admins", body, env.ts.URL, map[string]string{
		"Cookie":        cookieHeader(rootCookie),
		"Authorization": bearerScheme + rootCookie.Value,
		"Content-Type":  "application/json",
	})
	assertEnvelopeCode(t, mixed, CodeAuthMethodConflict)

	// 跨站來源：CSRF 來源策略先拒，與權限判定無關。
	crossSite := createAdminRaw(t, env.ts, body, rootCookie, "http://evil.invalid", nil)
	assertEnvelopeCode(t, crossSite, CodeOriginForbidden)
	if resp := createAdminRaw(t, env.ts, body, rootCookie, env.ts.URL,
		map[string]string{"Sec-Fetch-Site": crossSiteDirective}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("Sec-Fetch-Site: cross-site 應被來源策略拒掉，實際 %d", resp.StatusCode)
	}

	// 上面所有被拒的嘗試都不該多開出一個人：庫裡只有 Root 開的那一位。
	var admins int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM account_server_roles").Scan(&admins); err != nil {
		t.Fatalf("計數授予失敗：%v", err)
	}
	if admins != 1 {
		t.Errorf("被拒的開設不得留下授予，實際 %d 行", admins)
	}
}

// envelopeOf 讀出並解析錯誤信封（同一個回應本體只准讀一次：
// assertEnvelopeCode 會把 body 吃乾，之後再 decode 只能拿到空字串）。
func envelopeOf(t *testing.T, resp *http.Response) ErrorEnvelope {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取回應失敗：%v", err)
	}
	var env ErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("回應應為錯誤信封，實際 %q", body)
	}
	return env
}

// livePlainAccount 落一個不帶任何授予、也不欠首次改密的標準帳戶
// （區別於 adminacct 開出來的管理員：後者的旗標是這一步的產品語意，不能省）。
func (e *adminEnv) livePlainAccount(t *testing.T, login, password string) {
	t.Helper()
	hash, err := credential.Hash(password, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	if _, err := e.accounts.Create(context.Background(), e.db.SQL(), account.NewInput{
		LoginName: login, DisplayName: "普通帳戶", PasswordHash: hash,
		Type: account.TypeStandard, Status: account.StatusActive,
	}); err != nil {
		t.Fatalf("建立帳戶失敗：%v", err)
	}
}

// TestCreateAdminRejectsSelfReportedFields 請求本體裡的任何身分宣稱都被拒。
//
// role／account_type／status／subject_kind／account_id／must_change_password 這一類欄位
// 在合同裡根本不存在（DisallowUnknownFields），因此「改一個欄位就把自己也建成 Root」
// 沒有一個可以填的格子；被拒時不產生任何寫入。
func TestCreateAdminRejectsSelfReportedFields(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	cookie := env.rootCookie(t)

	bodies := []string{
		`{"login_name":"x.one","display_name":"宣稱角色","password":"` + adminTestInitialPasswd + `","role":"root"}`,
		`{"login_name":"x.two","display_name":"宣稱類型","password":"` + adminTestInitialPasswd + `","account_type":"guest"}`,
		`{"login_name":"x.three","display_name":"宣稱主體","password":"` + adminTestInitialPasswd + `","subject_kind":"root"}`,
		`{"login_name":"x.four","display_name":"免改密","password":"` + adminTestInitialPasswd + `","must_change_password":false}`,
		`{"login_name":"x.five","display_name":"指定標識","password":"` + adminTestInitialPasswd + `","account_id":"00000000-0000-7000-8000-000000000001"}`,
	}
	for _, body := range bodies {
		resp := createAdminRaw(t, env.ts, body, cookie, env.ts.URL, nil)
		if env := envelopeOf(t, resp); env.Code != CodeInvalidBody {
			t.Errorf("%s 應被未知欄位規則拒為 1004，實際 %d", body, env.Code)
		}
	}

	var accounts, grants, audits int
	for query, into := range map[string]*int{
		"SELECT COUNT(*) FROM accounts":                               &accounts,
		"SELECT COUNT(*) FROM account_server_roles":                   &grants,
		"SELECT COUNT(*) FROM root_audit WHERE action='admin.create'": &audits,
	} {
		if err := env.db.SQL().QueryRowContext(context.Background(), query).Scan(into); err != nil {
			t.Fatalf("計數失敗（%s）：%v", query, err)
		}
	}
	if accounts != 0 || grants != 0 || audits != 0 {
		t.Errorf("被拒的身分宣稱不得留下任何寫入（帳戶 %d／授予 %d／審計 %d）", accounts, grants, audits)
	}
}

// TestCreateAdminDuplicateIsConflict 重複提交（含正規化變體）收斂為業務衝突，不產生第二個人。
//
// 這一條同時釘住「丟失回應後的整筆重試」：Root 看見的是「已被佔用」，
// 而不是一份新帳戶，也不會被回顯任何憑據。
func TestCreateAdminDuplicateIsConflict(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	cookie := env.rootCookie(t)

	first := createAdminRaw(t, env.ts,
		createAdminBody("Dup.Admin", "重複提交", adminTestInitialPasswd), cookie, env.ts.URL, nil)
	if first.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(first.Body)
		t.Fatalf("首次開設應成功：%d %s", first.StatusCode, body)
	}
	firstBody, _ := io.ReadAll(first.Body)

	for _, variant := range []string{"dup.admin", "DUP.ADMIN", "Ｄｕｐ.Ａｄｍｉｎ"} {
		resp := createAdminRaw(t, env.ts,
			createAdminBody(variant, "重複提交", adminTestChangedPasswd), cookie, env.ts.URL, nil)
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("%q 應回 409，實際 %d", variant, resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("讀取衝突回應失敗：%v", err)
		}
		if env := envelopeOfBody(t, body); env.Code != CodeLoginNameTaken {
			t.Errorf("%q 應為 2012，實際 %d", variant, env.Code)
		}
		if strings.Contains(string(body), adminTestInitialPasswd) ||
			strings.Contains(string(body), adminTestChangedPasswd) ||
			strings.Contains(string(body), "$argon2id$") {
			t.Errorf("衝突回應不得回顯任何口令或雜湊：%s", body)
		}
	}
	if strings.Contains(string(firstBody), adminTestInitialPasswd) {
		t.Error("成功回應也不得回顯初始口令")
	}

	var accounts, grants int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM accounts").Scan(&accounts); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM account_server_roles").Scan(&grants); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if accounts != 1 || grants != 1 {
		t.Errorf("三次重複提交後仍只應有一位管理員（帳戶 %d／授予 %d）", accounts, grants)
	}
}

// TestCreateAdminInputErrors 不合規的登入名／顯示名／口令各自回 1004 並點出欄位。
//
// details 只給欄位名：伺服器的域規則原文（含具體被拒的字元與码位）不進回應，
// 那属於日誌與開發者診斷，不属於给客戶端的四語言句子。
func TestCreateAdminInputErrors(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	cookie := env.rootCookie(t)

	cases := []struct {
		body string
		want string
	}{
		{createAdminBody("bad name", "含空白", adminTestInitialPasswd), "login_name"},
		{createAdminBody("", "空登入名", adminTestInitialPasswd), "login_name"},
		{createAdminBody("ok.name", "  ", adminTestInitialPasswd), "display_name"},
		{createAdminBody("ok.name2", "空口令", ""), "password"},
	}
	for _, tc := range cases {
		resp := createAdminRaw(t, env.ts, tc.body, cookie, env.ts.URL, nil)
		env := envelopeOf(t, resp)
		if env.Code != CodeInvalidBody {
			t.Errorf("%s 應為 1004，實際 %d", tc.body, env.Code)
		}
		if env.Details["invalid_field"] != tc.want {
			t.Errorf("%s 應點出欄位 %q，實際 %v", tc.body, tc.want, env.Details)
		}
	}
	var accounts int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM accounts").Scan(&accounts); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if accounts != 0 {
		t.Errorf("不合規的輸入不得留下帳戶，實際 %d 行", accounts)
	}
}

// TestRootAdminEndpointsFollowAssembly 端點有無只由裝配決定（未注入用例時一個都不掛）。
func TestRootAdminEndpointsFollowAssembly(t *testing.T) {
	if routes := (&Server{}).rootAdminEndpoints(); len(routes) != 0 {
		t.Errorf("未注入開設用例時不應登記任何端點，實際 %d 條", len(routes))
	}
	env := newLiveEnv(t, adminTestRootPassword)
	resp := getAuth(t, env.ts, "/root/admins", "", "", "")
	assertEnvelopeCode(t, resp, CodeNotFound)
}

// envelopeOfBody 從已讀出的位元組解析信封（供「同一回應要同时看碼與原文」的用例使用）。
func envelopeOfBody(t *testing.T, body []byte) ErrorEnvelope {
	t.Helper()
	var env ErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("回應應為錯誤信封，實際 %q", body)
	}
	return env
}
