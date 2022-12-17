// rootadmins_test.go 是「Root 開設管理員帳戶」的傳輸層端到端證據：
// 真資料庫＋真用例＋完整中介層鏈，從 Root 登入拿到 Cookie 一路走到
// 新管理員首次登入、被首次改密門閂擋住、改完放行的整條時間線。
//
// 刻意不收的東西：
//   - 沒有替身：授權、授予讀取、門閂都跨層走真路徑，接錯線就會紅；
//   - 不碰任何真實資料目錄、不佔 5206、不等真實週期（會話期限取一小時，全程注入系統時鐘）。

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
		Sessions: sessions,
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

// putJSON 送一個 PUT（本體原樣交出，供畸形與攻擊用例使用）。
func putJSON(t *testing.T, ts *httptest.Server, path, body, origin string, extra map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, ts.URL+path, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("建立請求失敗：%v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for name, value := range extra {
		req.Header.Set(name, value)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("PUT %s 失敗：%v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// sendRaw 以任意方法打任意路徑（405 分流用）。
func sendRaw(t *testing.T, ts *httptest.Server, method, path string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("建立請求失敗：%v", err)
	}
	if cookie != nil {
		req.Header.Set("Cookie", cookieHeader(cookie))
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s 失敗：%v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// adminRowSnapshot 直讀一列帳戶的「編輯不該觸碰」欄位拼接（傳輸層攻擊探針的對照組）。
func adminRowSnapshot(t *testing.T, db *database.DB, accountID string) string {
	t.Helper()
	var (
		loginName, loginKey, passwordHash, accountType, status string
		mustChange, createdAt, lastLoginAt, disabledAt         int64
	)
	err := db.SQL().QueryRowContext(context.Background(), `SELECT COALESCE(login_name,''), COALESCE(login_name_key,''),
		COALESCE(password_hash,''), COALESCE(account_type,''), COALESCE(status,''),
		COALESCE(must_change_password,-1), COALESCE(created_at,-1),
		COALESCE(last_login_at,-1), COALESCE(disabled_at,-1) FROM accounts WHERE id = ?`, accountID).
		Scan(&loginName, &loginKey, &passwordHash, &accountType, &status,
			&mustChange, &createdAt, &lastLoginAt, &disabledAt)
	if err != nil {
		t.Fatalf("直讀帳戶行失敗：%v", err)
	}
	return loginName + "\x00" + loginKey + "\x00" + passwordHash + "\x00" + accountType + "\x00" + status +
		"\x00" + strconv.FormatInt(mustChange, 10) + "\x00" + strconv.FormatInt(createdAt, 10) +
		"\x00" + strconv.FormatInt(lastLoginAt, 10) + "\x00" + strconv.FormatInt(disabledAt, 10)
}

// createAdminViaAPI 用 Root 會話開一個管理員並回傳其 account_id（目錄/編輯探針的前置）。
func createAdminViaAPI(t *testing.T, env *adminEnv, cookie *http.Cookie, login string) string {
	t.Helper()
	resp := createAdminRaw(t, env.ts, createAdminBody(login, "目錄測試管理員", adminTestInitialPasswd),
		cookie, env.ts.URL, nil)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("開設 %s 應成功：%d %s", login, resp.StatusCode, body)
	}
	created := decodeJSONBody(t, resp)
	id, _ := created["account_id"].(string)
	if id == "" {
		t.Fatalf("開設回應應帶 account_id，實際 %v", created)
	}
	return id
}

// TestAdminDirectoryOverHTTP 目錄端點的分頁、篩選與回顯：
// 默認值、翻頁、狀態過濾、非法參數各自的結論，以及回應不帶任何憑據材料。
func TestAdminDirectoryOverHTTP(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	cookie := env.rootCookie(t)
	ids := make([]string, 0, 3)
	for _, login := range []string{"dir.one", "dir.two", "dir.three"} {
		ids = append(ids, createAdminViaAPI(t, env, cookie, login))
	}
	// 把最早那位禁用（直寫 SQL；停用能力本身屬後續步驟，這裡只是造一個狀態不同的行）。
	if _, err := env.db.SQL().ExecContext(context.Background(),
		"UPDATE accounts SET status = 'disabled', disabled_at = ? WHERE id = ?",
		time.Now().UnixMilli(), ids[0]); err != nil {
		t.Fatalf("禁用測試帳戶失敗：%v", err)
	}

	resp := getAuth(t, env.ts, "/root/admins", cookieHeader(cookie), "", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("目錄默認查詢應成功：%d %s", resp.StatusCode, body)
	}
	var page adminListResponse
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("解析目錄失敗：%v", err)
	}
	if page.Page != 1 || page.PageSize != adminacct.DirectoryDefaultPageSize || page.Total != 3 {
		t.Errorf("默認分頁回顯應為 1／%d／3，實際 %d／%d／%d",
			adminacct.DirectoryDefaultPageSize, page.Page, page.PageSize, page.Total)
	}
	if len(page.Admins) != 3 {
		t.Fatalf("三筆應在第一頁，實際 %d 筆", len(page.Admins))
	}
	// 授予倒序：最後開的在最前；每行都帶 granted_at，且沒有一行帶任何憑據欄位。
	if page.Admins[0].AccountID != ids[2] {
		t.Errorf("首行應是最新授予，實際 %s", page.Admins[0].AccountID)
	}
	for _, item := range page.Admins {
		if item.GrantedAt == "" {
			t.Errorf("目錄行必須帶授予時刻：%+v", item)
		}
	}

	// 翻頁：page_size=1 的第二頁是次新的一位。
	paged := getAuth(t, env.ts, "/root/admins?page=2&page_size=1", cookieHeader(cookie), "", "")
	var page2 adminListResponse
	if err := json.NewDecoder(paged.Body).Decode(&page2); err != nil {
		t.Fatalf("解析第二頁失敗：%v", err)
	}
	if paged.StatusCode != http.StatusOK || page2.Total != 3 || len(page2.Admins) != 1 ||
		page2.Admins[0].AccountID != ids[1] {
		t.Fatalf("第二頁應恰好是次新授予者，實際 %d／%+v", page2.Total, page2.Admins)
	}

	// 狀態篩選：disabled 命中一筆，且其 total 是篩選後的筆數。
	filtered := getAuth(t, env.ts, "/root/admins?status=disabled", cookieHeader(cookie), "", "")
	var pageD adminListResponse
	if err := json.NewDecoder(filtered.Body).Decode(&pageD); err != nil {
		t.Fatalf("解析篩選頁失敗：%v", err)
	}
	if filtered.StatusCode != http.StatusOK || pageD.Total != 1 ||
		len(pageD.Admins) != 1 || pageD.Admins[0].Status != "disabled" {
		t.Fatalf("disabled 篩選應命中被禁用的那筆，實際 %d／%+v", pageD.Total, pageD.Admins)
	}

	// 超出總數的合法頁碼：空頁而非錯誤。
	beyond := getAuth(t, env.ts, "/root/admins?page=99", cookieHeader(cookie), "", "")
	var pageBeyond adminListResponse
	if err := json.NewDecoder(beyond.Body).Decode(&pageBeyond); err != nil {
		t.Fatalf("解析空頁失敗：%v", err)
	}
	if beyond.StatusCode != http.StatusOK || pageBeyond.Total != 3 || len(pageBeyond.Admins) != 0 {
		t.Errorf("超出總數應回空頁與真實總數，實際 %d／%d", pageBeyond.Total, len(pageBeyond.Admins))
	}

	// 非法參數逐個點名：page 的「壞」分兩種（非數字在協定層、非法值在域層），處置同一句。
	for _, tc := range []struct{ query, want string }{
		{"/root/admins?page=abc", "page"},
		{"/root/admins?page=0", "page"},
		{"/root/admins?page_size=0", "page_size"},
		{"/root/admins?page_size=101", "page_size"},
		{"/root/admins?status=ghost", "status"},
	} {
		resp := getAuth(t, env.ts, tc.query, cookieHeader(cookie), "", "")
		env := envelopeOf(t, resp)
		if env.Code != CodeInvalidBody || env.Details["invalid_field"] != tc.want {
			t.Errorf("%s 應回 1004 並點出 %q，實際 %d／%v", tc.query, tc.want, env.Code, env.Details)
		}
	}

	// 脱敏把關：整份回應原文裡不該出現憑據欄位名、Argon2id 或任何測試口令的值
	// （must_change_password 是合同內的可展示旗標，不在禁列；禁的是雜湊欄與明文）。
	raw := getAuth(t, env.ts, "/root/admins", cookieHeader(cookie), "", "")
	bodyText := readAllText(t, raw)
	for _, forbidden := range []string{"password_hash", "argon2id", "login_name_key",
		"disabled_at", adminTestInitialPasswd, adminTestRootPassword} {
		if strings.Contains(bodyText, forbidden) {
			t.Errorf("目錄回應含不该出現的材料 %q", forbidden)
		}
	}

	// 非 Root 與未登入：與開設同一道閘、同一句處置。
	env.livePlainAccount(t, "dir.plain", adminTestPlainPasswd)
	plainCookie := loginCookie(t, env.loginAs(t, "dir.plain", adminTestPlainPasswd))
	assertEnvelopeCode(t, getAuth(t, env.ts, "/root/admins", cookieHeader(plainCookie), "", ""), CodePermissionDenied)
	assertEnvelopeCode(t, getAuth(t, env.ts, "/root/admins", "", "", ""), CodeNotAuthenticated)
}

// TestAdminProfileDetailOverHTTP 單筆詳情：成員讀得到、格式壞與非成員同形、閘外一律拒。
func TestAdminProfileDetailOverHTTP(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	cookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, cookie, "detail.http")
	env.livePlainAccount(t, "detail.plain", adminTestPlainPasswd)
	var plainID string
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT id FROM accounts WHERE login_name = 'detail.plain'").Scan(&plainID); err != nil {
		t.Fatalf("讀普通帳戶標識失敗：%v", err)
	}

	resp := getAuth(t, env.ts, "/root/admins/"+id, cookieHeader(cookie), "", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("詳情應成功：%d %s", resp.StatusCode, body)
	}
	var detail adminProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("解析詳情失敗：%v", err)
	}
	if detail.Admin.AccountID != id || detail.Admin.LoginName != "detail.http" ||
		detail.Admin.GrantedAt == "" || len(detail.Admin.Roles) != 1 ||
		detail.Admin.Roles[0] != identity.RoleServerAdmin.String() {
		t.Errorf("詳情欄位不正確：%+v", detail.Admin)
	}
	if detail.RequestID == "" {
		t.Error("詳情應帶關聯 ID")
	}

	// 「格式壞」「不存在」「存在但非成員」三種輸入收斂成同一個 1001：探不到差異。
	for name, path := range map[string]string{
		"格式壞": "/root/admins/not-a-uuid",
		"不存在": "/root/admins/00000000-0000-7000-8000-000000000000",
		"非成員": "/root/admins/" + plainID,
	} {
		got := getAuth(t, env.ts, path, cookieHeader(cookie), "", "")
		assertEnvelopeCode(t, got, CodeNotFound)
		if got.StatusCode != http.StatusNotFound {
			t.Errorf("%s 應為 404，實際 %d", name, got.StatusCode)
		}
	}

	// 方法分流：單筆路徑不接受 POST（開設只在集合路徑上）。
	notAllowed := sendRaw(t, env.ts, http.MethodPost, "/root/admins/"+id, cookie)
	if notAllowed.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("單筆路徑上的 POST 應為 405，實際 %d", notAllowed.StatusCode)
	}
	if allow := notAllowed.Header.Get("Allow"); !strings.Contains(allow, http.MethodPut) {
		t.Errorf("405 的 Allow 應列出編輯方法，實際 %q", allow)
	}

	// 非 Root 讀詳情：2011；未登入：2002。
	plainCookie := loginCookie(t, env.loginAs(t, "detail.plain", adminTestPlainPasswd))
	assertEnvelopeCode(t, getAuth(t, env.ts, "/root/admins/"+id, cookieHeader(plainCookie), "", ""), CodePermissionDenied)
	assertEnvelopeCode(t, getAuth(t, env.ts, "/root/admins/"+id, "", "", ""), CodeNotAuthenticated)
}

// TestAdminProfileEditOverHTTP 白名單編輯的傳輸層證據：成功回現值、隱藏欄位攻擊零寫入、
// 併發回 2013、非 Root 與非成員各收各的碼。
func TestAdminProfileEditOverHTTP(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	cookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, cookie, "edit.http")
	snapshot := adminRowSnapshot(t, env.db, id)

	// 成功編輯：回應是保存後的資料庫現值（去空白形態），不是請求本體的迴音。
	resp := putJSON(t, env.ts, "/root/admins/"+id,
		`{"display_name":"  編輯後的顯示名  ","expected_display_name":"目錄測試管理員"}`,
		env.ts.URL, map[string]string{"Cookie": cookieHeader(cookie)})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("合法編輯應成功：%d %s", resp.StatusCode, body)
	}
	var updated adminProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		t.Fatalf("解析編輯回應失敗：%v", err)
	}
	if updated.Admin.DisplayName != "編輯後的顯示名" || updated.Admin.AccountID != id {
		t.Errorf("編輯回應應回保存後的現值，實際 %+v", updated.Admin)
	}
	// 隱藏欄位逐字不動：憑據、狀態、旗標、類型、登入名鍵、時刻全在對照組裡。
	if got := adminRowSnapshot(t, env.db, id); got != snapshot {
		t.Error("編輯顯示名不得觸碰任何隱藏欄位")
	}

	// 陳舊現值：2013 且一個字都不覆蓋；回應不回顯任何一方的值。
	stale := putJSON(t, env.ts, "/root/admins/"+id,
		`{"display_name":"對著舊畫面保存","expected_display_name":"目錄測試管理員"}`,
		env.ts.URL, map[string]string{"Cookie": cookieHeader(cookie)})
	if stale.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(stale.Body)
		t.Fatalf("陳舊現值應為 409，實際 %d %s", stale.StatusCode, body)
	}
	conflictBody, err := io.ReadAll(stale.Body)
	if err != nil {
		t.Fatalf("讀衝突回應失敗：%v", err)
	}
	conflict := envelopeOfBody(t, conflictBody)
	if conflict.Code != CodeProfileConflict {
		t.Errorf("併發衝突應為 2013，實際 %d", conflict.Code)
	}
	if strings.Contains(string(conflictBody), "對著舊畫面保存") ||
		strings.Contains(string(conflictBody), "編輯後的顯示名") {
		t.Errorf("衝突回應不得回顯任何一方的值：%s", conflictBody)
	}
	if got := adminRowSnapshot(t, env.db, id); got != snapshot {
		t.Error("衝突的編輯不得留下欄位位移")
	}

	// 隱藏欄位批量賦值攻擊：本體裡多出任何身分/安全欄位都先被未知欄位規則殺掉。
	attacks := []string{
		`{"display_name":"企圖清旗標","expected_display_name":"編輯後的顯示名","must_change_password":false}`,
		`{"display_name":"企圖停用","expected_display_name":"編輯後的顯示名","status":"disabled"}`,
		`{"display_name":"企圖改類型","expected_display_name":"編輯後的顯示名","account_type":"guest"}`,
		`{"display_name":"企圖改登入名","expected_display_name":"編輯後的顯示名","login_name":"hijacked"}`,
		`{"display_name":"企圖發憑據","expected_display_name":"編輯後的顯示名","password":"P@ssw0rd!"}`,
		`{"display_name":"企圖指定人","account_id":"` + id + `","display_name":"重複鍵"}`,
		`{"display_name":"企圖清憑據","expected_display_name":"編輯後的顯示名","password_hash":"$argon2id$x"}`,
	}
	for _, body := range attacks {
		got := putJSON(t, env.ts, "/root/admins/"+id, body, env.ts.URL,
			map[string]string{"Cookie": cookieHeader(cookie)})
		if env := envelopeOf(t, got); env.Code != CodeInvalidBody {
			t.Errorf("%s 應被未知欄位規則拒為 1004，實際 %d", body, env.Code)
		}
	}
	if got := adminRowSnapshot(t, env.db, id); got != snapshot {
		t.Error("被拒的賦值攻擊不得留下任何寫入")
	}

	// 空依據值：協定層當場點名（顯示名恆非空，空依據永遠比不中，報 1004 比報衝突誠實）。
	emptyBase := putJSON(t, env.ts, "/root/admins/"+id,
		`{"display_name":"任何新名","expected_display_name":""}`,
		env.ts.URL, map[string]string{"Cookie": cookieHeader(cookie)})
	if env := envelopeOf(t, emptyBase); env.Code != CodeInvalidBody ||
		env.Details["invalid_field"] != "expected_display_name" {
		t.Errorf("空依據值應回 1004 並點出欄位，實際 %+v", env)
	}

	// 不合規顯示名：1004 display_name。
	badName := putJSON(t, env.ts, "/root/admins/"+id,
		`{"display_name":"  ","expected_display_name":"編輯後的顯示名"}`,
		env.ts.URL, map[string]string{"Cookie": cookieHeader(cookie)})
	if env := envelopeOf(t, badName); env.Code != CodeInvalidBody ||
		env.Details["invalid_field"] != "display_name" {
		t.Errorf("空顯示名應回 1004 display_name，實際 %+v", env)
	}

	// 跨站來源的 PUT：與 POST 同規矩，來源策略先拒（編輯是有副作用的方法）。
	crossSite := putJSON(t, env.ts, "/root/admins/"+id,
		`{"display_name":"跨站企圖","expected_display_name":"編輯後的顯示名"}`,
		"http://evil.invalid", map[string]string{"Cookie": cookieHeader(cookie)})
	assertEnvelopeCode(t, crossSite, CodeOriginForbidden)

	// 非 Root 編輯：2011；編輯非成員：1001（且與查無同形）。
	env.livePlainAccount(t, "edit.plain", adminTestPlainPasswd)
	plainCookie := loginCookie(t, env.loginAs(t, "edit.plain", adminTestPlainPasswd))
	forbidden := putJSON(t, env.ts, "/root/admins/"+id,
		`{"display_name":"普通人改目錄","expected_display_name":"編輯後的顯示名"}`,
		env.ts.URL, map[string]string{"Cookie": cookieHeader(plainCookie)})
	assertEnvelopeCode(t, forbidden, CodePermissionDenied)
	var plainID string
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT id FROM accounts WHERE login_name = 'edit.plain'").Scan(&plainID); err != nil {
		t.Fatalf("讀普通帳戶標識失敗：%v", err)
	}
	plainSnapshot := adminRowSnapshot(t, env.db, plainID)
	outside := putJSON(t, env.ts, "/root/admins/"+plainID,
		`{"display_name":"改到目錄外","expected_display_name":"普通帳戶"}`,
		env.ts.URL, map[string]string{"Cookie": cookieHeader(cookie)})
	assertEnvelopeCode(t, outside, CodeNotFound)
	if got := adminRowSnapshot(t, env.db, plainID); got != plainSnapshot {
		t.Error("對目錄外帳戶的編輯不得留下寫入")
	}

	// 審計只多贏家們該有的筆數：成功 1 筆 admin.profile_update，其餘全數零追加。
	var updates int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.profile_update'").Scan(&updates); err != nil {
		t.Fatalf("計數編輯審計失敗：%v", err)
	}
	if updates != 1 {
		t.Errorf("只該有成功那筆編輯留下審計，實際 %d 筆", updates)
	}
	var changes string
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT changes_json FROM root_audit WHERE action = 'admin.profile_update'").Scan(&changes); err != nil {
		t.Fatalf("讀編輯審計失敗：%v", err)
	}
	if !strings.Contains(changes, "目錄測試管理員") || !strings.Contains(changes, "編輯後的顯示名") {
		t.Errorf("編輯審計應帶顯示名前後值，實際 %s", changes)
	}
	if strings.Contains(changes, "P@ssw0rd") || strings.Contains(changes, "$argon2id$") ||
		strings.Contains(changes, "must_change_password") {
		t.Errorf("編輯審計不得含憑據材料或隱藏欄位的影子：%s", changes)
	}
}

// TestAdminProfileConcurrentEditOverHTTP 同一份畫面兩路並發：恰好一個 200、另一個 2013。
//
// 這是傳輸層端到端的併發尾巴（域層另有 6 路版本）：證據鏈要覆蓋「從 HTTP 打進去」
// 的那條路，否則 CAS 只在單元裡成立、中介層接錯線就查不出來。
func TestAdminProfileConcurrentEditOverHTTP(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	cookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, cookie, "race.http")

	const attempts = 4
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		okCount  int
		conflict int
		other    []int
	)
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodPut, env.ts.URL+"/root/admins/"+id,
				bytes.NewReader([]byte(`{"display_name":"並發改名-`+strconv.Itoa(i)+
					`","expected_display_name":"目錄測試管理員"}`)))
			if err != nil {
				t.Errorf("建立併發請求失敗：%v", err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Cookie", cookieHeader(cookie))
			req.Header.Set("Origin", env.ts.URL)
			resp, err := env.ts.Client().Do(req)
			if err != nil {
				t.Errorf("併發 PUT 失敗：%v", err)
				return
			}
			defer resp.Body.Close()
			mu.Lock()
			defer mu.Unlock()
			switch resp.StatusCode {
			case http.StatusOK:
				okCount++
			case http.StatusConflict:
				conflict++
			default:
				other = append(other, resp.StatusCode)
			}
		}(i)
	}
	wg.Wait()
	if len(other) > 0 {
		t.Fatalf("併發編輯只該出現 200 或 409，實際 %v", other)
	}
	if okCount != 1 || conflict != attempts-1 {
		t.Errorf("併發編輯應恰好一個生效、其餘衝突，實際 成功 %d／衝突 %d", okCount, conflict)
	}
	var display string
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT display_name FROM accounts WHERE id = ?", id).Scan(&display); err != nil {
		t.Fatalf("讀回顯示名失敗：%v", err)
	}
	if !strings.HasPrefix(display, "並發改名-") {
		t.Errorf("落庫值應是贏家的提交，實際 %q", display)
	}
	var updates int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.profile_update'").Scan(&updates); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if updates != 1 {
		t.Errorf("落敗者不得留下審計，實際 %d 筆", updates)
	}
}

// readAllText 讀盡回應原文（脱敏斷言用；Body 已由 getAuth 的 Cleanup 負責關閉）。
func readAllText(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取回應失敗：%v", err)
	}
	return string(body)
}

// TestRootDisableAndRestoreAdminOverHTTP 停用→失效→恢復的完整時間線，全程走真 HTTP 鏈。
//
// 这一段證據釘四件事，每一件都對應本步對外承諾的一句：
//   - 停用的實際效果不是列表上的一個標籤：舊會話的下一條請求就收到 2003，
//     新登入收到與其他拒絕同形的 2001；
//   - 恢復只恢復新登入能力：停用前簽發的兩份會話永遠打不開（revoked_at 已落庫），
//     而首次改密義務原封不動地等著這個人（2010 門閂仍在）；
//   - 重複操作回的是可判別的 2014，不是第二次「成功」；
//   - 回應原文裡沒有一個格子可能含憑據材料。
func TestRootDisableAndRestoreAdminOverHTTP(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, rootCookie, "stop.e2e")
	cookieA := loginCookie(t, env.loginAs(t, "stop.e2e", adminTestInitialPasswd))
	cookieB := loginCookie(t, env.loginAs(t, "stop.e2e", adminTestInitialPasswd))

	statusPath := "/root/admins/" + id + "/status"
	putStatus := func(body string) *http.Response {
		return putJSON(t, env.ts, statusPath, body, env.ts.URL,
			map[string]string{"Cookie": cookieHeader(rootCookie)})
	}

	resp := putStatus(`{"status":"disabled","expected_status":"active"}`)
	if resp.StatusCode != http.StatusOK {
		text := readAllText(t, resp)
		t.Fatalf("停用應成功：%d %s", resp.StatusCode, text)
	}
	var change adminStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&change); err != nil {
		t.Fatalf("解析停用回應失敗：%v", err)
	}
	if change.Admin.Status != "disabled" || change.Admin.DisabledAt == "" {
		t.Errorf("回應應是變更後的現值（disabled 帶時刻），實際 %+v", change.Admin)
	}
	if change.RevokedSessions != 2 {
		t.Errorf("停用應回報撤銷了兩份會話，實際 %d", change.RevokedSessions)
	}

	// 舊會話立即失效：兩份都換不出身分（解析在門閂與授權之前）。
	for name, cookie := range map[string]*http.Cookie{"會話A": cookieA, "會話B": cookieB} {
		got := getAuth(t, env.ts, "/root/admins", cookieHeader(cookie), "", "")
		assertEnvelopeCode(t, got, CodeSessionInvalid)
		if got.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s 停用後應收到 401，實際 %d", name, got.StatusCode)
		}
	}
	// 新登入被拒，且與其他登入拒絕同形：不指出「這個帳戶被鎖了」。
	denied := env.loginAs(t, "stop.e2e", adminTestInitialPasswd)
	assertEnvelopeCode(t, denied, CodeInvalidCredentials)

	// 重複停用：呼叫端那份「他還活著」的依據已不是現值。
	dup := putStatus(`{"status":"disabled","expected_status":"active"}`)
	assertEnvelopeCode(t, dup, CodeAdminStatusConflict)
	if dup.StatusCode != http.StatusConflict {
		t.Errorf("重複停用應為 409，實際 %d", dup.StatusCode)
	}

	// 恢復：只回復新登入能力。
	reEnabled := putStatus(`{"status":"active","expected_status":"disabled"}`)
	if reEnabled.StatusCode != http.StatusOK {
		text := readAllText(t, reEnabled)
		t.Fatalf("恢復應成功：%d %s", reEnabled.StatusCode, text)
	}
	var restored adminStatusResponse
	if err := json.NewDecoder(reEnabled.Body).Decode(&restored); err != nil {
		t.Fatalf("解析恢復回應失敗：%v", err)
	}
	if restored.Admin.Status != "active" || restored.Admin.DisabledAt != "" {
		t.Errorf("恢復後應是 active 且不帶停用時刻，實際 %+v", restored.Admin)
	}
	if restored.RevokedSessions != 0 {
		t.Errorf("恢復不該撤銷任何會話，實際 %d", restored.RevokedSessions)
	}
	// 停用前的兩份會話不復活。
	for name, cookie := range map[string]*http.Cookie{"會話A": cookieA, "會話B": cookieB} {
		got := getAuth(t, env.ts, "/root/admins", cookieHeader(cookie), "", "")
		assertEnvelopeCode(t, got, CodeSessionInvalid)
		if got.StatusCode != http.StatusUnauthorized {
			t.Errorf("恢復後 %s 仍應是 401（不復活），實際 %d", name, got.StatusCode)
		}
	}
	// 必須重新登入；首次改密義務還在（2010，而不是放行）。
	relogin := env.loginAs(t, "stop.e2e", adminTestInitialPasswd)
	if relogin.StatusCode != http.StatusOK {
		text := readAllText(t, relogin)
		t.Fatalf("恢復後新登入應成功：%d %s", relogin.StatusCode, text)
	}
	gated := getAuth(t, env.ts, "/root/admins", cookieHeader(loginCookie(t, relogin)), "", "")
	assertEnvelopeCode(t, gated, CodePasswordChangeRequired)
	// 恢復後的目錄現值：status=disabled 篩選不再有他，all 有他。
	all := getAuth(t, env.ts, "/root/admins?status=disabled", cookieHeader(rootCookie), "", "")
	if text := readAllText(t, all); strings.Contains(text, id) {
		t.Error("恢復後該帳戶不應仍出現在 disabled 篩選裡")
	}
}

// TestAdminStatusInputAndAttackSurface 狀態子資源的輸入閘與攻擊面。
//
// 每一段擋的是不同來路的壞輸入：同值與表外值是拼寫問題（1004 點名欄位）、
// 未知欄位是本體企圖（1004 且零寫入）、格式不對的標識與目錄外的標識同回 1001
// （端點不是列舉探針）、方法不對回 405。全部路徑都不得動目標帳戶一行。
func TestAdminStatusInputAndAttackSurface(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, rootCookie, "stop.input")
	snapshot := adminRowSnapshot(t, env.db, id)
	statusPath := "/root/admins/" + id + "/status"

	for name, body := range map[string]string{
		"同值停用":  `{"status":"disabled","expected_status":"disabled"}`,
		"同值恢復":  `{"status":"active","expected_status":"active"}`,
		"表外新狀態": `{"status":"ghost","expected_status":"active"}`,
		"表外依據":  `{"status":"disabled","expected_status":"ghost"}`,
		"缺依據":   `{"status":"disabled"}`,
		"空依據":   `{"status":"disabled","expected_status":""}`,
	} {
		resp := putJSON(t, env.ts, statusPath, body, env.ts.URL,
			map[string]string{"Cookie": cookieHeader(rootCookie)})
		env2 := envelopeOf(t, resp)
		if env2.Code != CodeInvalidBody {
			t.Errorf("%s 應回 1004，實際 %d", name, env2.Code)
		}
	}

	// 隱藏欄位批量賦值：狀態請求企圖順手改憑據／改名／清旗標，全部當場拒殺。
	for name, body := range map[string]string{
		"順帶口令":   `{"status":"disabled","expected_status":"active","password":"x"}`,
		"順帶改名":   `{"status":"disabled","expected_status":"active","display_name":"被順手改了"}`,
		"順帶旗標":   `{"status":"disabled","expected_status":"active","must_change_password":false}`,
		"順帶類型":   `{"status":"disabled","expected_status":"active","account_type":"guest"}`,
		"自報原因文本": `{"status":"disabled","expected_status":"active","reason":"隨意的文字"}`,
	} {
		resp := putJSON(t, env.ts, statusPath, body, env.ts.URL,
			map[string]string{"Cookie": cookieHeader(rootCookie)})
		if code := envelopeOf(t, resp).Code; code != CodeInvalidBody {
			t.Errorf("%s：未知欄位企圖應被 1004 拒殺，實際 %d", name, code)
		}
	}
	if got := adminRowSnapshot(t, env.db, id); got != snapshot {
		t.Error("被拒的狀態請求不得動目標帳戶任何一欄")
	}

	// 標識形態與目錄外標識同回 1001：格式錯、幽靈、未授予者，外界分不出差別。
	for name, path := range map[string]string{
		"格式不對": "/root/admins/not-a-uuid/status",
		"幽靈標識": "/root/admins/0192f0c4-1c9a-7c3e-9a1b-2f4d6e8a0b1c/status",
	} {
		resp := putJSON(t, env.ts, path, `{"status":"disabled","expected_status":"active"}`,
			env.ts.URL, map[string]string{"Cookie": cookieHeader(rootCookie)})
		assertEnvelopeCode(t, resp, CodeNotFound)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s 應為 404，實際 %d", name, resp.StatusCode)
		}
	}
	// 存在的普通帳戶（未授予）：同形 1001，狀態通路不回答「這是不是人」。
	env.livePlainAccount(t, "plain.ungranted", adminTestPlainPasswd)
	var plainID string
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT id FROM accounts WHERE login_name = ?", "plain.ungranted").Scan(&plainID); err != nil {
		t.Fatalf("讀普通帳戶標識失敗：%v", err)
	}
	resp := putJSON(t, env.ts, "/root/admins/"+plainID+"/status",
		`{"status":"disabled","expected_status":"active"}`, env.ts.URL,
		map[string]string{"Cookie": cookieHeader(rootCookie)})
	assertEnvelopeCode(t, resp, CodeNotFound)

	// 方法分流：子資源只認 PUT；GET 落 405 且 Allow 如實。
	notAllowed := sendRaw(t, env.ts, http.MethodGet, statusPath, rootCookie)
	assertEnvelopeCode(t, notAllowed, CodeMethodNotAllowed)
	if allow := notAllowed.Header.Get("Allow"); !strings.Contains(allow, http.MethodPut) {
		t.Errorf("405 的 Allow 應列出 PUT，實際 %q", allow)
	}

	// 成功回應原文脱敏：沒有憑據、內部鍵或口令的影子。
	ok := putJSON(t, env.ts, statusPath, `{"status":"disabled","expected_status":"active"}`,
		env.ts.URL, map[string]string{"Cookie": cookieHeader(rootCookie)})
	text := readAllText(t, ok)
	for _, forbidden := range []string{"password_hash", "argon2id", "login_name_key", adminTestInitialPasswd} {
		if strings.Contains(text, forbidden) {
			t.Errorf("狀態回應不得含 %q", forbidden)
		}
	}
}

// TestAdminStatusAuthorizationMatrix 停用/恢復只屬 Root：其他主體各自收到哪一句。
//
// 「管理員停用其他管理員」在本步被明確關在門外——普通管理員帶著完成改密的
// 有效會話拿到的是 2011（處置是「別再試」），而不是可以被重新登入繞過的 2002/2003。
func TestAdminStatusAuthorizationMatrix(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	victimID := createAdminViaAPI(t, env, rootCookie, "stop.victim")
	statusPath := "/root/admins/" + victimID + "/status"

	env.livePlainAccount(t, "plain.matrix", adminTestPlainPasswd)
	plainCookie := loginCookie(t, env.loginAs(t, "plain.matrix", adminTestPlainPasswd))

	peerID := createAdminViaAPI(t, env, rootCookie, "stop.peer")
	peerCookie := loginCookie(t, env.loginAs(t, "stop.peer", adminTestInitialPasswd))
	if resp := postJSON(t, env.ts, "/auth/password/change",
		`{"current_password":"`+adminTestInitialPasswd+`","new_password":"`+adminTestChangedPasswd+`"}`,
		"", map[string]string{"Cookie": cookieHeader(peerCookie)}); resp.StatusCode != http.StatusOK {
		t.Fatalf("同級管理員改密失敗：%d", resp.StatusCode)
	}
	peerCookie = loginCookie(t, env.loginAs(t, "stop.peer", adminTestChangedPasswd))
	// 先確認這位同級確實「是目錄裡的人」：他能讀自己的詳情路徑（非 Root 得到 2011，
	// 說明請求已活著走到授權判定），而不是被憑據問題擋在門外。
	if got := getAuth(t, env.ts, "/root/admins/"+peerID, cookieHeader(peerCookie), "", ""); envelopeOf(t, got).Code != CodePermissionDenied {
		t.Fatal("同級管理員的會話應有效（判定落在權限而不是憑據）")
	}

	for name, cookie := range map[string]*http.Cookie{
		"普通帳戶":  plainCookie,
		"普通管理員": peerCookie,
	} {
		resp := putJSON(t, env.ts, statusPath, `{"status":"disabled","expected_status":"active"}`,
			env.ts.URL, map[string]string{"Cookie": cookieHeader(cookie)})
		assertEnvelopeCode(t, resp, CodePermissionDenied)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s 停用同級應為 403，實際 %d", name, resp.StatusCode)
		}
	}
	// 匿名來源：先問憑據，不是先談權限。
	resp := putJSON(t, env.ts, statusPath, `{"status":"disabled","expected_status":"active"}`, "", nil)
	assertEnvelopeCode(t, resp, CodeNotAuthenticated)

	// 越權嘗試不得留下一行變更或一筆審計。
	var status string
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT status FROM accounts WHERE id = ?", victimID).Scan(&status); err != nil {
		t.Fatalf("讀回狀態失敗：%v", err)
	}
	if status != "active" {
		t.Errorf("被拒的越權停用不得改變狀態，實際 %s", status)
	}
	var audits int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action IN ('admin.disable','admin.enable')").Scan(&audits); err != nil {
		t.Fatalf("計數審計失敗：%v", err)
	}
	if audits != 0 {
		t.Errorf("被拒的狀態變更不得寫入 Root 審計，實際 %d 筆", audits)
	}
}

// TestAdminStatusConcurrentHTTPEditsExactlyOneWin 並發停用的最終裁定在資料庫：
// 四路同依據的 HTTP 併發恰好一次 200，其餘 409，審計只有一筆「admin.disable」。
// 贏家之前已經完成的寫入（例如開設本身）不許倒退——狀態行與審計計數一起作證。
func TestAdminStatusConcurrentHTTPEditsExactlyOneWin(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, rootCookie, "stop.http-race")
	// 停用前先完成一次「明確發生的操作」（本人改密）：停用不得讓它倒退。
	cookie := loginCookie(t, env.loginAs(t, "stop.http-race", adminTestInitialPasswd))
	if resp := postJSON(t, env.ts, "/auth/password/change",
		`{"current_password":"`+adminTestInitialPasswd+`","new_password":"`+adminTestChangedPasswd+`"}`,
		"", map[string]string{"Cookie": cookieHeader(cookie)}); resp.StatusCode != http.StatusOK {
		t.Fatalf("目標改密失敗：%d", resp.StatusCode)
	}

	statusPath := "/root/admins/" + id + "/status"
	const attempts = 4
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		okCount  int
		conflict int
		other    []int
	)
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodPut, env.ts.URL+statusPath,
				bytes.NewReader([]byte(`{"status":"disabled","expected_status":"active"}`)))
			if err != nil {
				t.Errorf("建立併發請求失敗：%v", err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Cookie", cookieHeader(rootCookie))
			req.Header.Set("Origin", env.ts.URL)
			resp, err := env.ts.Client().Do(req)
			if err != nil {
				t.Errorf("併發 PUT 失敗：%v", err)
				return
			}
			defer resp.Body.Close()
			mu.Lock()
			defer mu.Unlock()
			switch resp.StatusCode {
			case http.StatusOK:
				okCount++
			case http.StatusConflict:
				conflict++
			default:
				other = append(other, resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	if okCount != 1 || conflict != attempts-1 {
		t.Errorf("併發停用應恰好一次生效、其餘衝突，實際 成功 %d／衝突 %d／其餘 %v", okCount, conflict, other)
	}
	var audits int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.disable'").Scan(&audits); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if audits != 1 {
		t.Errorf("落敗者不得留下審計，實際 %d 筆", audits)
	}

	// 「已完成的操作不倒退」的正面證據：停用前本人已改密的結果，
	// 在停用發生後仍然有效——恢復之後用新口令能登入、一次性舊口令被拒。
	// 若停用把那次改密「倒退」了，這兩句會立刻反轉。
	if resp := putJSON(t, env.ts, statusPath, `{"status":"active","expected_status":"disabled"}`,
		env.ts.URL, map[string]string{"Cookie": cookieHeader(rootCookie)}); resp.StatusCode != http.StatusOK {
		t.Fatalf("併發後的恢復應成功：%d", resp.StatusCode)
	}
	if resp := env.loginAs(t, "stop.http-race", adminTestChangedPasswd); resp.StatusCode != http.StatusOK {
		t.Errorf("停用不該讓本人先前完成的改密倒退，新口令登入應成功，實際 %d", resp.StatusCode)
	}
	assertEnvelopeCode(t, env.loginAs(t, "stop.http-race", adminTestInitialPasswd), CodeInvalidCredentials)
}
