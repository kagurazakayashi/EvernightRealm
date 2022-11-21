package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// fakeAuth 是傳輸層測試用的 AuthUseCase 替身：只負責回吐預置結果並記錄收到的參數，
// 讓「Cookie 形態、來源校驗、認證方式獨佔、錯誤映射」這些傳輸層規則
// 能脫離資料庫被逐一釘死。業務判定（口令對錯、事務）由 internal/auth 自己的測試負責。
type fakeAuth struct {
	outcome    auth.Outcome
	loginErr   error
	resolveFn  func(secret string) (identity.Principal, session.Session, error)
	lastLogin  func(loginName, password, requestID string)
	lastRoot   func(password, requestID string)
	lastSecret string
	// logoutErr 讓傳輸層測試能釘住登出用例的回傳形態（撤銷失敗映射為 500）。
	logoutErr error
	// lastLogout 記錄登出收到的主體與會話（斷言「只有活會話那條路才調用撤銷」）。
	lastLogout func(identity.Principal, session.Session)
	// rotateFn 覆寫輪換用例的回傳形態；未設定時一律回 rotateErr。
	// 與 resolveFn 同一取向：傳輸層測試要釘的是「分發與對映」，不是會不會話層判定。
	rotateFn func(secret string) (auth.Outcome, error)
	// rotateErr 是未設定 rotateFn 時輪換用例的回傳錯誤（nil 即回一個空結果）。
	rotateErr error
	// lastRotate 記錄輪換收到的秘密：斷言「端點交出去的是本請求帶來的憑據」，
	// 以及「回應本體與 Cookie 之外沒有任何地方出現新秘密」。
	lastRotate string
	// lastIP 記錄收到的來源位址：限流把「傳輸層只交實際連線位址、不交轉發標頭」
	// 的責任放在 handler，這裡釘住「handler 確實交了 remoteHost 而不是標頭值」。
	lastIP string
	// devicesFn 覆寫「列舉裝置」的回傳形態；未設定時回一個空清單。
	devicesFn func(principal identity.Principal) ([]session.Session, error)
	// listErr 是未設定 devicesFn 時列舉裝置的回傳錯誤（nil 即回空清單）。
	listErr error
	// revokeFn 覆寫「撤銷裝置」的回傳形態；未設定時一律回 revokeErr。
	revokeFn func(principal identity.Principal, deviceID idgen.ID) (auth.DeviceRevokeResult, error)
	// revokeErr 是未設定 revokeFn 時撤銷裝置的回傳錯誤。
	revokeErr error
	// lastRevokeDevice 記錄撤銷收到的目標裝置標識：斷言「端點把請求裡的 device_id
	// 原樣交下去，且主體是本請求解析出來的受信主體」。
	lastRevokeDevice idgen.ID
	// changeFn 覆寫「本人改密」用例的回傳形態；未設定時一律回 changeErr。
	changeFn func(principal identity.Principal, currentPassword, newPassword string) (auth.PasswordChangeResult, error)
	// changeErr 是未設定 changeFn 時改密用例的回傳錯誤。
	changeErr error
	// lastChange 記錄改密收到的兩個口令欄：斷言「端點把請求本體原樣交下去」，
	// 以及測試自己知道哪些字串是本次專屬的假口令。
	lastChange struct{ current, newPassword string }
	// mustChangeFn 覆寫「必須改密旗標」的回傳形態；未設定時回 mustChange。
	mustChangeFn func(principal identity.Principal) (bool, error)
	// mustChange 是未設定 mustChangeFn 時旗標的回傳值。
	mustChange bool
}

func (f *fakeAuth) LoginAccount(ctx context.Context, loginName, password, requestID, ip string) (auth.Outcome, error) {
	f.lastIP = ip
	if f.lastLogin != nil {
		f.lastLogin(loginName, password, requestID)
	}
	return f.outcome, f.loginErr
}

func (f *fakeAuth) LoginRoot(ctx context.Context, password, requestID, ip string) (auth.Outcome, error) {
	f.lastIP = ip
	if f.lastRoot != nil {
		f.lastRoot(password, requestID)
	}
	return f.outcome, f.loginErr
}

func (f *fakeAuth) Resolve(ctx context.Context, secret string) (identity.Principal, session.Session, error) {
	f.lastSecret = secret
	if f.resolveFn != nil {
		return f.resolveFn(secret)
	}
	return identity.Principal{}, session.Session{}, auth.ErrInvalidSession
}

func (f *fakeAuth) Logout(ctx context.Context, principal identity.Principal, sess session.Session, requestID string) error {
	if f.lastLogout != nil {
		f.lastLogout(principal, sess)
	}
	return f.logoutErr
}

func (f *fakeAuth) RotateSession(ctx context.Context, secret, requestID string) (auth.Outcome, error) {
	f.lastRotate = secret
	if f.rotateFn != nil {
		return f.rotateFn(secret)
	}
	return auth.Outcome{}, f.rotateErr
}

func (f *fakeAuth) ListDevices(ctx context.Context, principal identity.Principal) ([]session.Session, error) {
	if f.devicesFn != nil {
		return f.devicesFn(principal)
	}
	return nil, f.listErr
}

func (f *fakeAuth) RevokeDevice(ctx context.Context, principal identity.Principal, deviceID idgen.ID, requestID string) (auth.DeviceRevokeResult, error) {
	f.lastRevokeDevice = deviceID
	if f.revokeFn != nil {
		return f.revokeFn(principal, deviceID)
	}
	return auth.DeviceRevokeResult{}, f.revokeErr
}

func (f *fakeAuth) ChangePassword(ctx context.Context, principal identity.Principal,
	currentPassword, newPassword, requestID string) (auth.PasswordChangeResult, error) {
	f.lastChange.current = currentPassword
	f.lastChange.newPassword = newPassword
	if f.changeFn != nil {
		return f.changeFn(principal, currentPassword, newPassword)
	}
	return auth.PasswordChangeResult{}, f.changeErr
}

func (f *fakeAuth) MustChangePassword(ctx context.Context, principal identity.Principal) (bool, error) {
	if f.mustChangeFn != nil {
		return f.mustChangeFn(principal)
	}
	return f.mustChange, nil
}

// testOutcome 構造一個帳戶主體的登入結果（秘密固定，便於斷言它只進 Cookie）。
func testOutcome(t *testing.T) auth.Outcome {
	t.Helper()
	id := mustTestID(t)
	deviceID := mustTestID(t)
	acctID := mustTestID(t)
	principal, err := identity.NewAccountPrincipal(identity.AccountInput{
		Subject: identity.AccountSubject{ID: acctID, Type: account.TypeStandard, Status: account.StatusActive},
		Origin:  identity.OriginHTTPRequest,
	})
	if err != nil {
		t.Fatalf("構造帳戶主體失敗：%v", err)
	}
	now := timeutil.System().Now()
	return auth.Outcome{
		Principal: principal,
		Session:   session.Session{ID: id, DeviceID: deviceID, CreatedAt: now, LastActiveAt: now, ExpiresAt: now.Add(time.Hour)},
		Secret:    "account-secret-should-only-live-in-cookie",
	}
}

// mustTestID 產生正規 UUIDv7 標識（會話與帳戶標識斷言用）。
func mustTestID(t *testing.T) idgen.ID {
	t.Helper()
	id, err := idgen.New()
	if err != nil {
		t.Fatalf("產生測試標識失敗：%v", err)
	}
	return id
}

// authTestServer 建立注入了替身用例的 HTTP 測試服務（走完整中介層鏈）。
func authTestServer(t *testing.T, fake AuthUseCase, mutate func(*config.Config)) *httptest.Server {
	t.Helper()
	cfg := config.Default()
	if mutate != nil {
		mutate(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("測試組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{Auth: fake, Clock: timeutil.System()})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// postJSON 送一個 JSON 本體的請求（可帶 Origin 與額外標頭）。
func postJSON(t *testing.T, ts *httptest.Server, path, body, origin string, extra map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader([]byte(body)))
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
		t.Fatalf("POST %s 失敗：%v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// getAuth 送一個可帶 Cookie／Authorization 的 GET。
func getAuth(t *testing.T, ts *httptest.Server, path, cookie, bearer, origin string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("建立請求失敗：%v", err)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s 失敗：%v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// decodeJSONBody 讀回應本體為 map（合同欄位斷言用）。
func decodeJSONBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("回應應為 JSON，實際 %q", body)
	}
	return got
}

// loginCookie 從成功登入回應中取回會話 Cookie。
func loginCookie(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	cookies := resp.Cookies()
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatalf("登入回應應帶會話 Cookie，實際 %v", cookies)
	return nil
}

// TestLoginSetsHardenedSessionCookie 釘住簽發 Cookie 的全部安全屬性，並確認
// 會話秘密只在 Set-Cookie 裡、回應 JSON 不含它（原生客戶端據此從標頭讀秘密）。
func TestLoginSetsHardenedSessionCookie(t *testing.T) {
	fake := &fakeAuth{outcome: testOutcome(t)}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/login", `{"login_name":"alice","password":"pw"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("登入應成功，實際 %d", resp.StatusCode)
	}
	cookie := loginCookie(t, resp)
	if !cookie.HttpOnly {
		t.Error("會話 Cookie 必須 HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite 應為 Lax，實際 %v", cookie.SameSite)
	}
	if cookie.Secure {
		t.Error("HTTP 連線下不應標 Secure（LAN HTTP 是批准部署形態）")
	}
	if cookie.Path != "/" {
		t.Errorf("Path 應為根路徑，實際 %q", cookie.Path)
	}
	if cookie.MaxAge <= 0 {
		t.Errorf("Max-Age 應為正（與會話壽命同階），實際 %d", cookie.MaxAge)
	}
	if !strings.EqualFold(cookie.Value, fake.outcome.Secret) {
		t.Errorf("Cookie 值應是會話秘密：%q", cookie.Value)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("認證回應必禁快取，實際 %q", resp.Header.Get("Cache-Control"))
	}
	body, _ := io.ReadAll(resp.Body)
	if bytes.Contains(body, []byte(fake.outcome.Secret)) {
		t.Error("回應 JSON 本體不得出現會話秘密")
	}
}

// TestLoginCookieSecureOverTLS 確認 Secure 與實際 TLS 連線綁定：
// 同一處理鏈在 TLS 下要標 Secure，這是 HTTP 與 HTTPS 部署的關鍵差異。
func TestLoginCookieSecureOverTLS(t *testing.T) {
	fake := &fakeAuth{outcome: testOutcome(t)}
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{Auth: fake})
	// 以 StartTLS 的測試伺服器提供真實 TLS 連線，Secure 判定才有依據（不是手搓 r.TLS）。
	ts := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(ts.Close)
	resp := postJSON(t, ts, "/auth/login", `{"login_name":"alice","password":"pw"}`, "", nil)
	cookie := loginCookie(t, resp)
	if !cookie.Secure {
		t.Error("TLS 連線下會話 Cookie 必須標 Secure")
	}
}

// TestLoginResponseShape 確認登入成功回應的契約欄位：主體類別、帳戶標識、
// 設備標識、到期時刻與關聯 ID，且 Root 分支不帶 account_id。
func TestLoginResponseShape(t *testing.T) {
	outcome := testOutcome(t)
	fake := &fakeAuth{outcome: outcome}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/login", `{"login_name":"alice","password":"pw"}`, "", nil)
	got := decodeJSONBody(t, resp)
	if got["subject_kind"] != "account" {
		t.Errorf("subject_kind 應為 account，實際 %v", got["subject_kind"])
	}
	if got["account_id"] != outcome.Principal.AccountID().String() {
		t.Errorf("account_id 不符：%v", got["account_id"])
	}
	if got["device_id"] != outcome.Session.DeviceID.String() {
		t.Errorf("device_id 不符：%v", got["device_id"])
	}
	if _, ok := got["expires_at"]; !ok {
		t.Error("登入回應應帶 expires_at")
	}
	if got["request_id"] == "" || got["request_id"] == nil {
		t.Error("登入回應應帶 request_id")
	}
}

// TestRootLoginOmitsAccountID 確認 Root 分支不帶帳戶標識（Root 不在 accounts 表）。
func TestRootLoginOmitsAccountID(t *testing.T) {
	root, err := identity.Root(identity.ResumeRootProof(), identity.OriginHTTPRequest)
	if err != nil {
		t.Fatalf("構造 Root 主體失敗：%v", err)
	}
	now := timeutil.System().Now()
	fake := &fakeAuth{outcome: auth.Outcome{
		Principal: root,
		Session:   session.Session{ID: mustTestID(t), DeviceID: mustTestID(t), CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
		Secret:    "root-secret",
	}}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/root/login", `{"password":"pw"}`, "", nil)
	got := decodeJSONBody(t, resp)
	if got["subject_kind"] != "root" {
		t.Errorf("subject_kind 應為 root，實際 %v", got["subject_kind"])
	}
	if _, ok := got["account_id"]; ok {
		t.Error("Root 登入回應不可出現 account_id（空值也不給，避免被讀成幽靈帳戶）")
	}
}

// TestLoginRejectsCrossSiteOrigin 是 CSRF 的核心反例：帶異站 Origin 的登入
// 一律被來源策略拒絕（403 / 2005），而且根本不到達用例（不消耗憑據校驗）。
func TestLoginRejectsCrossSiteOrigin(t *testing.T) {
	var called bool
	fake := &fakeAuth{outcome: testOutcome(t), lastLogin: func(_, _, _ string) { called = true }}
	ts := authTestServer(t, fake, allowOrigins("http://good.example"))
	resp := postJSON(t, ts, "/auth/login", `{"login_name":"alice","password":"pw"}`, "http://evil.example", nil)
	assertEnvelopeCode(t, resp, CodeOriginForbidden)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("來源拒絕應回 403，實際 %d", resp.StatusCode)
	}
	if called {
		t.Error("被來源策略擋下時不可呼叫登入用例")
	}
}

// TestLoginAllowsSameOriginAndWhitelisted 是 CSRF 正例：同源（比對請求自身
// scheme://host）與組態白名單來源都放行；不帶 Origin（原生）也放行。
func TestLoginAllowsSameOriginAndWhitelisted(t *testing.T) {
	fake := &fakeAuth{outcome: testOutcome(t)}
	ts := authTestServer(t, fake, allowOrigins("http://dev.example"))
	// 同源：Origin 等於 ts.URL（http://127.0.0.1:port）。
	if resp := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"p"}`, ts.URL, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("同源登入應放行，實際 %d", resp.StatusCode)
	}
	// 白名單來源。
	if resp := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"p"}`, "http://dev.example", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("白名單來源應放行，實際 %d", resp.StatusCode)
	}
	// 無 Origin（原生）。
	if resp := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"p"}`, "", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("原生請求應放行，實際 %d", resp.StatusCode)
	}
}

// TestLoginRejectsSecFetchSiteCrossSite 確認即使不帶 Origin，Sec-Fetch-Site
// 宣告 cross-site 的請求也被拒——這是比 Origin 更難被舊式手法剝奪的自證標頭。
func TestLoginRejectsSecFetchSiteCrossSite(t *testing.T) {
	fake := &fakeAuth{outcome: testOutcome(t)}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"p"}`, "",
		map[string]string{"Sec-Fetch-Site": "cross-site"})
	assertEnvelopeCode(t, resp, CodeOriginForbidden)
}

// TestResolveRejectsMixedAuthMethods 釘住認證方式獨佔：同時帶 Cookie 與 Bearer、
// 或瀏覽器（帶 Origin）企圖用 Bearer，都在解析入口被拒（2004），不到達用例。
func TestResolveRejectsMixedAuthMethods(t *testing.T) {
	fake := &fakeAuth{resolveFn: func(secret string) (identity.Principal, session.Session, error) {
		t.Errorf("混用請求不應到達解析：%q", secret)
		return identity.Principal{}, session.Session{}, auth.ErrInvalidSession
	}}
	ts := authTestServer(t, fake, nil)
	secret := testOutcome(t).Secret

	// Cookie + Bearer 同時出現。
	resp := getAuth(t, ts, "/auth/session", sessionCookieName+"="+secret, secret, "")
	assertEnvelopeCode(t, resp, CodeAuthMethodConflict)

	// 只有 Bearer，但帶 Origin（瀏覽器企圖繞過 Cookie 路徑）。
	resp = getAuth(t, ts, "/auth/session", "", secret, "http://evil.example")
	assertEnvelopeCode(t, resp, CodeAuthMethodConflict)
}

// TestSessionCookieRoundTrip 走通「Cookie → 當前會話」：帶有效秘密的 Cookie
// 換回 200 與主體欄位；秘密原樣送到用例。
func TestSessionCookieRoundTrip(t *testing.T) {
	outcome := testOutcome(t)
	fake := &fakeAuth{resolveFn: func(secret string) (identity.Principal, session.Session, error) {
		if secret != outcome.Secret {
			t.Errorf("解析收到的秘密不符：%q", secret)
		}
		return outcome.Principal, outcome.Session, nil
	}}
	ts := authTestServer(t, fake, nil)
	resp := getAuth(t, ts, "/auth/session", sessionCookieName+"="+outcome.Secret, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("有效 Cookie 應換回當前會話，實際 %d", resp.StatusCode)
	}
	got := decodeJSONBody(t, resp)
	if got["subject_kind"] != "account" || got["device_id"] != outcome.Session.DeviceID.String() {
		t.Errorf("當前會話欄位不符：%v", got)
	}
}

// TestSessionNativeBearerRoundTrip 確認原生客戶端用 Bearer（無 Origin）认证成功。
func TestSessionNativeBearerRoundTrip(t *testing.T) {
	outcome := testOutcome(t)
	fake := &fakeAuth{resolveFn: func(secret string) (identity.Principal, session.Session, error) {
		return outcome.Principal, outcome.Session, nil
	}}
	ts := authTestServer(t, fake, nil)
	resp := getAuth(t, ts, "/auth/session", "", outcome.Secret, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("原生 Bearer 應认证成功，實際 %d", resp.StatusCode)
	}
}

// TestSessionInvalidCookieClearsCookie 確認無效 Cookie 被換成刪除指令：
// 留著一枚已失效的 Cookie 只會讓下次請求再撞同一堵牆。
func TestSessionInvalidCookieClearsCookie(t *testing.T) {
	fake := &fakeAuth{} // resolveFn 為 nil → 恆回 ErrInvalidSession
	ts := authTestServer(t, fake, nil)
	resp := getAuth(t, ts, "/auth/session", sessionCookieName+"=stale-secret", "", "")
	assertEnvelopeCode(t, resp, CodeSessionInvalid)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("無效會話應回 401，實際 %d", resp.StatusCode)
	}
	cleared := false
	for _, raw := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(raw, sessionCookieName+"=") && strings.Contains(raw, "Max-Age=0") {
			cleared = true
			if !strings.Contains(raw, "Path=/") || !strings.Contains(raw, "HttpOnly") || !strings.Contains(raw, "SameSite=Lax") {
				t.Errorf("刪除指令屬性須與簽發一致：%q", raw)
			}
		}
	}
	if !cleared {
		t.Errorf("無效 Cookie 應附刪除指令（Max-Age=0），實際 %v", resp.Header.Values("Set-Cookie"))
	}
}

// TestSessionNoCredentials 區分「沒帶」與「帶了但無效」：完全無憑據回 2002。
func TestSessionNoCredentials(t *testing.T) {
	fake := &fakeAuth{}
	ts := authTestServer(t, fake, nil)
	resp := getAuth(t, ts, "/auth/session", "", "", "")
	assertEnvelopeCode(t, resp, CodeNotAuthenticated)
}

// TestLoginFailureMapsToIndistinguishableCredentialError 確認內部的「查無此人／口令錯」
// 已被用例收斂為 ErrInvalidCredentials；傳輸層不追加任何可區分的第二句（不洩露帳戶）。
func TestLoginFailureMapsToIndistinguishableCredentialError(t *testing.T) {
	fake := &fakeAuth{loginErr: auth.ErrInvalidCredentials}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/login", `{"login_name":"nobody","password":"pw"}`, "", nil)
	assertEnvelopeCode(t, resp, CodeInvalidCredentials)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("憑據無效應回 401，實際 %d", resp.StatusCode)
	}
}

// TestLoginInternalErrorIsRedacted 確認用例回非拒絕類錯誤（資料庫故障）時，
// 傳輸層回 500 與 CodeUnknown，不把內部錯誤鏈帶進回應。
func TestLoginInternalErrorIsRedacted(t *testing.T) {
	fake := &fakeAuth{loginErr: errors.New("internal: sqlite disk /secret/path blew up")}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"p"}`, "", nil)
	assertEnvelopeCode(t, resp, CodeUnknown)
	body, _ := io.ReadAll(resp.Body)
	for _, leak := range []string{"sqlite", "/secret/path", "blew up"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("內部錯誤不得外洩 %q 到回應：%s", leak, body)
		}
	}
}

// TestLoginRejectsUnknownFields 確認請求本體不藏可自報的欄位：多帶 role/subject_kind
// 之類欄位直接被 DisallowUnknownFields 拒殺（1004），絕不落入主體判定。
func TestLoginRejectsUnknownFields(t *testing.T) {
	fake := &fakeAuth{outcome: testOutcome(t)}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"p","role":"root"}`, "", nil)
	assertEnvelopeCode(t, resp, CodeInvalidBody)
}

// TestLoginRejectsOversizedBody 確認請求大小受限（server.max_body_bytes）：
// 超大口令在本體解析階段就被 1003 擋下，不進派生。
func TestLoginRejectsOversizedBody(t *testing.T) {
	fake := &fakeAuth{outcome: testOutcome(t)}
	cfgMutate := func(c *config.Config) { c.Server.MaxBodyBytes = 1 << 10 } // 1 KiB
	ts := authTestServer(t, fake, cfgMutate)
	huge := `{"login_name":"a","password":"` + strings.Repeat("x", 4096) + `"}`
	resp := postJSON(t, ts, "/auth/login", huge, "", nil)
	assertEnvelopeCode(t, resp, CodePayloadTooLarge)
}

// TestAuthEndpointsAbsentWithoutDeps 確認未注入用例時一個 auth 端點都不掛：
// /auth/login 落到回退層，行為與未實作前逐字相同（404 信封）。
func TestAuthEndpointsAbsentWithoutDeps(t *testing.T) {
	ts := testServer(t) // Deps{}：無 Auth。
	resp := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"p"}`, "", nil)
	assertEnvelopeCode(t, resp, CodeNotFound)
}

// TestAuthPreflightThenActualRequest 把「預檢是協定層問答、不是身分授權」釘成端到端：
// 白名單來源的預檢通過（204 帶方法與憑據標頭）之後，實際請求仍要各自通過
// 來源校驗；而同一來源若不在白名單（此處用未放行的evil），預檢與實際請求都到不了端點。
func TestAuthPreflightThenActualRequest(t *testing.T) {
	fake := &fakeAuth{outcome: testOutcome(t)}
	ts := authTestServer(t, fake, func(c *config.Config) {
		c.Security.CORS.AllowedOrigins = []string{"http://127.0.0.1:8765"}
		c.Security.CORS.AllowedMethods = append(c.Security.CORS.AllowedMethods, "POST")
		c.Security.CORS.AllowCredentials = true
	})

	// 預檢：OPTIONS 帶 Access-Control-Request-Method: POST。
	req, err := http.NewRequest(http.MethodOptions, ts.URL+"/auth/login", nil)
	if err != nil {
		t.Fatalf("建立預檢請求失敗：%v", err)
	}
	req.Header.Set("Origin", "http://127.0.0.1:8765")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("預檢失敗：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("放行的預檢應回 204，實際 %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:8765" {
		t.Errorf("預檢應反射精確來源（帶憑據不得用通配），實際 %q", got)
	}
	if resp.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("allow_credentials 組態應體現在預檢回應")
	}

	// 實際請求：同一白名單來源現在被來源校驗放行（預檢成功不等於放行——兩關都要過）。
	if got := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"p"}`, "http://127.0.0.1:8765", nil); got.StatusCode != http.StatusOK {
		t.Errorf("白名單來源的實際請求應放行，實際 %d", got.StatusCode)
	}

	// 但來源換成未放行者：預檢層就不給任何跨域標頭，實際請求層被 2005 拒絕。
	other := doWithOrigin(t, ts, http.MethodOptions, "/auth/login", "http://evil.example",
		map[string]string{"Access-Control-Request-Method": "POST"})
	if other.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("未放行來源不可獲得任何跨域標頭")
	}
	blocked := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"p"}`, "http://evil.example", nil)
	assertEnvelopeCode(t, blocked, CodeOriginForbidden)
}
