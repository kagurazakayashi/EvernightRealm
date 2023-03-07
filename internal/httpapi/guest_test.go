// guest_test.go 釘住「訪客以臨時受限身分進入」在傳輸層的契約：本體白名單（未知欄位當場拒殺）、
// 來源判定、結論對映（2017／2006＋Retry-After／1004 點名 nickname／500）、成功時的下發形態
// （一枚與普通帳戶同規格的會話 Cookie，秘密只進 Set-Cookie），以及未注入用例時這條路徑根本不掛。
//
// 後半部是一條真庫、真用例的閉環：開關關著時入口不亮、按下去被拒；Root 翻開後同一個人
// 換得的會話讀得到自己的 account_type=guest，而同一枚憑據在管理端與 Root 端都被拒為權限不足
// （匿名者則是「根本沒帶憑據」）——這一句是「不因為他已取得會話就放行普通管理」在協定層的證據。
// 准入與計量的業務判定由 internal/guestacct 自己的測試負責。
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/kagurazakayashi/EvernightRealm/internal/guestacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/guestbind"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/stdacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// fakeGuest 是 GuestUseCase 的傳輸層替身：回吐預置結果並記錄收到的輸入。
type fakeGuest struct {
	result  guestacct.Outcome
	err     error
	calls   int
	lastIn  guestacct.EnterInput
	lastReq string
	lastIP  string
}

func (f *fakeGuest) Enter(ctx context.Context, in guestacct.EnterInput,
	requestID, sourceIP string) (guestacct.Outcome, error) {
	f.calls++
	f.lastIn = in
	f.lastReq = requestID
	f.lastIP = sourceIP
	return f.result, f.err
}

// guestTestServer 建立只注入訪客用例的 HTTP 測試服務（走完整中介層鏈）。
// 刻意不注入 Auth：端點掛不掛只取決於有無訪客用例，與登入用例無關。
func guestTestServer(t *testing.T, fake GuestUseCase) *httptest.Server {
	t.Helper()
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("測試組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{Guest: fake, Clock: timeutil.System()})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// guestOutcomeForTest 構造一個「訪客／active／零授予」的成功結果與一枚同規格會話。
func guestOutcomeForTest(t *testing.T) guestacct.Outcome {
	t.Helper()
	a := account.Account{ID: mustTestID(t), LoginName: "guest_018f0000-0000-7000-8000-000000000000",
		DisplayName: "夜訪的旅人", Type: account.TypeGuest, Status: account.StatusActive}
	principal, err := identity.NewAccountPrincipal(identity.AccountInput{
		Subject: identity.SubjectOf(a), Origin: identity.OriginHTTPRequest,
		Grants: identity.NewServerGrants(),
	})
	if err != nil {
		t.Fatalf("構造測試主體失敗：%v", err)
	}
	return guestacct.Outcome{
		Principal:   principal,
		AccountID:   a.ID,
		DisplayName: a.DisplayName,
		Type:        account.TypeGuest,
		Session:     session.Session{DeviceID: mustTestID(t), ExpiresAt: timeutil.System().Now().Add(time.Hour)},
		Secret:      "test-guest-secret-只准進-set-cookie",
	}
}

// TestGuestEnterSuccessIssuesOrdinaryCookie 成功形態：回應只有可展示事實、秘密不進本體，
// 而 Cookie 的屬性組合與登入簽發時逐字一致（HttpOnly＋SameSite=Lax＋Path=/＋ expires）。
func TestGuestEnterSuccessIssuesOrdinaryCookie(t *testing.T) {
	fake := &fakeGuest{result: guestOutcomeForTest(t)}
	ts := guestTestServer(t, fake)

	resp := postJSON(t, ts, "/auth/guest", `{"nickname":"夜訪的旅人"}`, "",
		map[string]string{"X-Forwarded-For": "8.8.8.8"})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("訪客進入應為 200，實際 %d %s", resp.StatusCode, body)
	}

	body := decodeJSONBody(t, resp)
	for _, field := range []string{"subject_kind", "account_id", "account_type", "display_name",
		"device_id", "expires_at", "request_id"} {
		if _, ok := body[field]; !ok {
			t.Fatalf("回應缺少契約欄位 %s：%#v", field, body)
		}
	}
	if body["subject_kind"] != "account" || body["account_type"] != "guest" {
		t.Errorf("主體類別與類型應為 account/guest，實際 %#v/%#v", body["subject_kind"], body["account_type"])
	}
	if body["display_name"] != "夜訪的旅人" {
		t.Errorf("展示名應是本人交來的那一串，實際 %#v", body["display_name"])
	}
	// 沒有口令、沒有憑據材料、沒有 roles、也沒有任何活動欄位：這趟進入對應的真相就是還不屬於任何活動。
	for _, forbidden := range []string{"roles", "role", "password", "password_hash", "activity_id", "secret"} {
		if _, ok := body[forbidden]; ok {
			t.Fatalf("回應不得含 %s 欄：%#v", forbidden, body)
		}
	}
	if strings.Contains(dumpOf(body), fake.result.Secret) {
		t.Fatalf("會話秘密不得出現在回應本體：%#v", body)
	}

	cookie := loginCookie(t, resp)
	if cookie.HttpOnly != true {
		t.Error("訪客會話 Cookie 必須是 HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite 必須是 Lax（與登入同一條 CSRF 防線），實際 %v", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("Path 必須是根路徑（全服務唯一一枚會話 Cookie），實際 %q", cookie.Path)
	}
	if cookie.MaxAge <= 0 {
		t.Errorf("Must 帶 Max-Age 表達會話壽命（受到期約束），實際 %d", cookie.MaxAge)
	}
	if fake.lastIn.Nickname != "夜訪的旅人" {
		t.Errorf("用例收到的暱稱應原樣對應：%#v", fake.lastIn)
	}
	if fake.lastIP != "127.0.0.1" {
		t.Fatalf("來源必須取實際連線位址而非轉發標頭，實際交了 %q", fake.lastIP)
	}
	if got := resp.Header.Get(cacheControlHeader); got != "no-store" {
		t.Fatalf("訪客回應須 no-store，實際 %q", got)
	}
}

// TestGuestEnterRejectsUnknownFields 協定層沒有一格能把訪客昇格：自報角色、類型、狀態、
// 登入名或活動標識一律 1004，而且一個請求都不進用例（更不建號）。
func TestGuestEnterRejectsUnknownFields(t *testing.T) {
	fake := &fakeGuest{result: guestOutcomeForTest(t)}
	ts := guestTestServer(t, fake)

	bodies := []string{
		`{"nickname":"甲","role":"server_admin"}`,
		`{"nickname":"甲","account_type":"standard"}`,
		`{"nickname":"甲","status":"active"}`,
		`{"nickname":"甲","login_name":"我想叫這個"}`,
		`{"nickname":"甲","account_id":"018f0000-0000-7000-8000-000000000000"}`,
		`{"nickname":"甲","activity_id":"018f0000-0000-7000-8000-000000000001"}`,
	}
	for _, raw := range bodies {
		resp := postJSON(t, ts, "/auth/guest", raw, "", nil)
		assertRegisterCode(t, resp, int(CodeInvalidBody), http.StatusBadRequest)
	}
	if fake.calls != 0 {
		t.Fatalf("未知欄位不得進用例，實際進了 %d 次", fake.calls)
	}
}

// TestGuestEnterFailureMapping 結論對映逐條對應不同處置，不互相冒充。
func TestGuestEnterFailureMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantCode   int
		wantStatus int
	}{
		{"策略關著", guestacct.ErrGuestDisabled, int(CodeAccountCreationDisabled), http.StatusForbidden},
		{"暱稱不合規", guestacct.ErrInvalidNickname, int(CodeInvalidBody), http.StatusBadRequest},
		{"被限流", &guestacct.ThrottledError{RetryAfter: 90 * time.Second}, int(CodeLoginThrottled), http.StatusTooManyRequests},
		{"內部故障", errors.New("guestacct: 訪客進入失敗: boom"), int(CodeUnknown), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		fake := &fakeGuest{err: tc.err}
		ts := guestTestServer(t, fake)
		resp := postJSON(t, ts, "/auth/guest", `{"nickname":"乙"}`, "", nil)
		body := assertRegisterCode(t, resp, tc.wantCode, tc.wantStatus)
		if tc.wantCode == int(CodeInvalidBody) {
			details, _ := body["details"].(map[string]any)
			if details["invalid_field"] != "nickname" {
				t.Errorf("%s：1004 應點名 nickname 欄位，實際 %#v", tc.name, body["details"])
			}
		}
		if tc.wantCode == int(CodeLoginThrottled) {
			if got := resp.Header.Get("Retry-After"); got != "90" {
				t.Errorf("%s：限流要附 Retry-After，實際 %q", tc.name, got)
			}
		}
		// 被拒的回應一律不得下發 Cookie：沒有會話可給，也不該讓瀏覽器帶著一枚憑據猜測。
		if len(resp.Header.Values("Set-Cookie")) != 0 {
			t.Errorf("%s：被拒的訪客請求不得下發 Cookie：%v", tc.name, resp.Header.Values("Set-Cookie"))
		}
	}
}

// TestGuestEndpointAbsentWithoutUseCase 未注入用例時這條路徑根本不掛（不留半成品入口）。
func TestGuestEndpointAbsentWithoutUseCase(t *testing.T) {
	cfg := config.Default()
	srv := New(&cfg, testVersion, Deps{Clock: timeutil.System()})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp := postJSON(t, ts, "/auth/guest", `{}`, "", nil)
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("未注入用例時 /auth/guest 應回 404 信封：%d %s", resp.StatusCode, body)
	}
	if body := decodeJSONBody(t, resp); int(body["code"].(float64)) != int(CodeNotFound) {
		t.Errorf("應是 1001 而不是別的：%#v", body)
	}
}

// TestGuestEnterOriginRejected 跨站來源當場被拒（這是一條有副作用的匿名寫入）。
func TestGuestEnterOriginRejected(t *testing.T) {
	fake := &fakeGuest{result: guestOutcomeForTest(t)}
	ts := guestTestServer(t, fake)

	resp := postJSON(t, ts, "/auth/guest", `{"nickname":"跨站"}`, "https://evil.example", nil)
	assertRegisterCode(t, resp, int(CodeOriginForbidden), http.StatusForbidden)
	if fake.calls != 0 {
		t.Errorf("來源被拒時不得進用例，實際進了 %d 次", fake.calls)
	}
}

// guestLiveTestRootPassword 只活在本次測試進程，不是任何環境的憑據。
const guestLiveTestRootPassword = "guest-live-test-root-口令"

// guestLiveEnv 是真庫、真用例的現場：登入、策略、管理員建號與訪客四條通路都掛上，
// 於是要判定的不是替身的回吐，而是「一枚訪客會話在既有授權鏈上真的走得動哪裡、走不動哪裡」。
type guestLiveEnv struct {
	ts     *httptest.Server
	db     *database.DB
	policy *acctpolicy.Store
}

func newGuestLiveEnv(t *testing.T) *guestLiveEnv {
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
	auditStore := audit.NewStore(clock)
	policyStore := acctpolicy.NewStore(clock)
	sessions, err := session.NewStoreWithPolicy(clock, time.Hour, session.Policy{})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	rootHash, err := credential.Hash(guestLiveTestRootPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試 Root 憑據失敗：%v", err)
	}
	authService, err := auth.New(auth.Deps{
		DB: db, Sessions: sessions, Accounts: accountsStore, Grants: grantsStore,
		Audits: auditStore, RootPasswordHash: rootHash, Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立登入用例失敗：%v", err)
	}
	policyService, err := acctpolicy.New(acctpolicy.Deps{DB: db, Store: policyStore, Audits: auditStore})
	if err != nil {
		t.Fatalf("建立策略用例失敗：%v", err)
	}
	// 開設管理員用例只為讓 /root/admins 掛得上：本現場要拿一位「已完成首次改密的普通主體」
	// 對照訪客的 account_type，而這條路不讀帳戶建立策略開關（Root 開管理員是既有授權邊界）。
	adminService, err := adminacct.New(adminacct.Deps{
		DB: db, Accounts: accountsStore, Grants: grantsStore,
		Audits: auditStore, Sessions: sessions, Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立管理員用例失敗：%v", err)
	}
	stdService, err := stdacct.New(stdacct.Deps{
		DB: db, Accounts: accountsStore, Grants: grantsStore, Policy: policyStore,
		Sessions: sessions, Audits: auditStore,
		BindTickets: guestbind.NewStore(clock), Clock: clock,
		Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立普通帳戶用例失敗：%v", err)
	}
	guestGuard, err := auth.NewLoginGuard(auth.GuardConfig{
		FailLimit: 10000, Window: time.Second, Cooldown: time.Second,
		SourceFailLimit: 10000, MaxEntries: 100000,
	}, clock)
	if err != nil {
		t.Fatalf("建立訪客守衛失敗：%v", err)
	}
	guestService, err := guestacct.New(guestacct.Deps{
		DB: db, Accounts: accountsStore, Policy: policyStore, Sessions: sessions,
		Audits: auditStore, Guard: guestGuard,
	})
	if err != nil {
		t.Fatalf("建立訪客用例失敗：%v", err)
	}
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{
		Auth: authService, Admins: adminService, AccountPolicy: policyService,
		StandardAccounts: stdService, Guest: guestService, Clock: clock,
		// 綁定執行側（本人三條通路）與管理端共用同一個服務實例，但它是另一個依賴欄位：
		// 兩側的准入邊界不同，分开注入才測得出「只裝管理端時本人通路根本不掛」。
		GuestBindings: stdService,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &guestLiveEnv{ts: ts, db: db, policy: policyStore}
}

// rootCookie 以測試 Root 口令登入並取得本次專用的會話 Cookie。
func (e *guestLiveEnv) rootCookie(t *testing.T) *http.Cookie {
	t.Helper()
	resp := postJSON(t, e.ts, "/auth/root/login",
		`{"password":"`+guestLiveTestRootPassword+`"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 登入應成功：%d %s", resp.StatusCode, body)
	}
	return loginCookie(t, resp)
}

// setGuest 經策略端點（Root 的真路徑）翻動訪客開關，其餘兩欄按出廠形態寫回。
func (e *guestLiveEnv) setGuest(t *testing.T, root *http.Cookie, on bool) {
	t.Helper()
	resp := putJSON(t, e.ts, "/root/account-policy", policyBody(false, "closed", on), "",
		map[string]string{"Cookie": cookieHeader(root)})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("保存策略應成功：%d %s", resp.StatusCode, body)
	}
}

// enter 發一次訪客進入並原樣回傳回應。
func (e *guestLiveEnv) enter(t *testing.T, nickname string) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"nickname": nickname})
	return postJSON(t, e.ts, "/auth/guest", string(raw), "", nil)
}

// countAccounts 數 accounts 表行數（測試取證用）。
func (e *guestLiveEnv) countAccounts(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM accounts").Scan(&n); err != nil {
		t.Fatalf("計數 accounts 失敗：%v", err)
	}
	return n
}

// TestGuestEntryEndToEnd 一條完整閉環：開關關著時入口不亮、按下去被拒且不建號；
// Root 翻開後同一個人主動按換得一枚會話，讀得到自己的 account_type=guest，
// 而同一枚憑據在管理端與 Root 端都被拒為權限不足（匿名者則是沒帶憑據）。
// 最後登出：那枚 Cookie 立刻換不出身分——訪客沒有任何「不受撤銷約束」的特殊憑據。
func TestGuestEntryEndToEnd(t *testing.T) {
	e := newGuestLiveEnv(t)

	// 出廠：訪客開關關著。匿名入口答案為關，硬按也換不出帳戶。
	caps := decodeJSONBody(t, getAuth(t, e.ts, "/auth/capabilities", "", "", ""))
	if caps["guest_open"] != false {
		t.Fatalf("出廠策略下 guest_open 應為關，實際 %#v", caps)
	}
	before := e.countAccounts(t)
	blocked := e.enter(t, "關著時的敲門")
	assertRegisterCode(t, blocked, int(CodeAccountCreationDisabled), http.StatusForbidden)
	if len(blocked.Header.Values("Set-Cookie")) != 0 {
		t.Error("被策略擋下時不得下發任何 Cookie")
	}
	if e.countAccounts(t) != before {
		t.Error("被策略擋下時一個帳戶都不該多出來")
	}

	// Root 翻開訪客開關。
	root := e.rootCookie(t)
	e.setGuest(t, root, true)
	caps = decodeJSONBody(t, getAuth(t, e.ts, "/auth/capabilities", "", "", ""))
	if caps["guest_open"] != true {
		t.Fatalf("策略翻開後 guest_open 應為真，實際 %#v", caps)
	}

	resp := e.enter(t, "同一個暱稱")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("訪客進入應成功：%d %s", resp.StatusCode, body)
	}
	body := decodeJSONBody(t, resp)
	guest := loginCookie(t, resp)

	// 同一枚憑據問自己的會話：類型如實是 guest，而且沒有任何授予。
	self := decodeJSONBody(t, getAuth(t, e.ts, "/auth/session", cookieHeader(guest), "", ""))
	if self["account_type"] != "guest" {
		t.Errorf("會話摘要應回報訪客類型，實際 %#v", self["account_type"])
	}
	if self["account_id"] != body["account_id"] {
		t.Errorf("會話指向的應就是剛建出的帳戶：%v 對 %v", self["account_id"], body["account_id"])
	}
	if _, ok := self["roles"]; ok {
		t.Errorf("訪客不帶任何授予，roles 欄位應缺席：%#v", self)
	}

	// 授權差異：同一條管理端路徑上，匿名是「沒帶憑據」（2002），訪客是「有身分但不夠」（2011）。
	anonAdmin := decodeJSONBody(t, getAuth(t, e.ts, "/admin/accounts", "", "", ""))
	if int(anonAdmin["code"].(float64)) != int(CodeNotAuthenticated) {
		t.Errorf("匿名讀管理目錄應回 2002，實際 %#v", anonAdmin)
	}
	guestAdmin := decodeJSONBody(t, getAuth(t, e.ts, "/admin/accounts", cookieHeader(guest), "", ""))
	if int(guestAdmin["code"].(float64)) != int(CodePermissionDenied) {
		t.Errorf("訪客讀管理目錄應回 2011（不因取得會話而放行），實際 %#v", guestAdmin)
	}
	// Root 端點同理：他連「讀一份准入配置」的資格都沒有，因此也枚舉不到全站帳戶。
	if got := decodeJSONBody(t, getAuth(t, e.ts, "/root/account-policy", cookieHeader(guest), "", "")); int(got["code"].(float64)) != int(CodePermissionDenied) {
		t.Errorf("訪客讀 Root 策略應回 2011，實際 %#v", got)
	}
	// 寫入方向也一樣：訪客拿同一枚憑據去代人建號，被拒的是權限而不是憑據。
	writeAttempt := postJSON(t, e.ts, "/admin/accounts",
		`{"login_name":"guest.try.create","display_name":"想開人","password":"x"}`, "",
		map[string]string{"Cookie": cookieHeader(guest)})
	if int(decodeJSONBody(t, writeAttempt)["code"].(float64)) != int(CodePermissionDenied) {
		t.Errorf("訪客代人建號應回 2011，實際 %d", writeAttempt.StatusCode)
	}

	// Root 端點也不能因為「他帶著一枚有效會話」就多放行一件事。
	anonRoot := decodeJSONBody(t, getAuth(t, e.ts, "/root/account-policy", "", "", ""))
	if int(anonRoot["code"].(float64)) != int(CodeNotAuthenticated) {
		t.Errorf("匿名讀 Root 策略應回 2002，實際 %#v", anonRoot)
	}

	// 登出：撤銷生效，那枚 Cookie 立即換不出身分（受撤銷約束，與普通帳戶同一條路）。
	logout := postJSON(t, e.ts, "/auth/logout", `{}`, "", map[string]string{"Cookie": cookieHeader(guest)})
	if logout.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(logout.Body)
		t.Fatalf("訪客登出應成功：%d %s", logout.StatusCode, out)
	}
	after := decodeJSONBody(t, getAuth(t, e.ts, "/auth/session", cookieHeader(guest), "", ""))
	if int(after["code"].(float64)) != int(CodeSessionInvalid) {
		t.Errorf("登出後同一枚憑據應換不出身分（2003），實際 %#v", after)
	}

	// 同名再一次進入：是另一個人、另一筆帳戶，沒有任何「憑暱稱認人」的通路。
	countBefore := e.countAccounts(t)
	second := e.enter(t, "同一個暱稱")
	if second.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(second.Body)
		t.Fatalf("第二趟訪客進入應成功：%d %s", second.StatusCode, out)
	}
	secondBody := decodeJSONBody(t, second)
	if secondBody["account_id"] == body["account_id"] {
		t.Error("同暱稱的兩趟必須是兩個不同的穩定標識")
	}
	if secondBody["display_name"] != body["display_name"] {
		t.Error("展示名應逐字相同（顯示名不承擔唯一性）")
	}
	if got := e.countAccounts(t); got != countBefore+1 {
		t.Errorf("第二趟應恰好多出一筆帳戶，實際 %d→%d", countBefore, got)
	}
}

// TestStandardAccountSubjectCarriesStandardType account_type 不是訪客專用的記號：
// 普通帳戶與 Root 在同一組回應裡各自如實描述自己（Root 根本沒有帳戶類型，欄位缺席）。
func TestStandardAccountSubjectCarriesStandardType(t *testing.T) {
	e := newGuestLiveEnv(t)

	root := e.rootCookie(t)
	rootSession := decodeJSONBody(t, getAuth(t, e.ts, "/auth/session", cookieHeader(root), "", ""))
	if rootSession["subject_kind"] != "root" {
		t.Fatalf("Root 的主體類別應為 root，實際 %#v", rootSession)
	}
	if _, ok := rootSession["account_type"]; ok {
		t.Errorf("Root 不在 accounts 表，account_type 欄位應缺席：%#v", rootSession)
	}

	// Root 開一位管理員（帶首次改密義務），他登入後讀到的類型是 standard。
	adminPass := "guest-live-test-管理員口令"
	created := postJSON(t, e.ts, "/root/admins",
		`{"login_name":"std.subject.probe","display_name":"現行管理員","password":"`+adminPass+`"}`,
		"", map[string]string{"Cookie": cookieHeader(root)})
	if created.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(created.Body)
		t.Fatalf("Root 開設管理員應成功：%d %s", created.StatusCode, body)
	}
	first := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"std.subject.probe","password":"`+adminPass+`"}`, "", nil)
	if first.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(first.Body)
		t.Fatalf("管理員首次登入應成功：%d %s", first.StatusCode, body)
	}
	loginBody := decodeJSONBody(t, first)
	if loginBody["account_type"] != "standard" {
		t.Errorf("普通帳戶登入應回報 standard，實際 %#v", loginBody["account_type"])
	}
	// 首次改密義務仍由既有旗標承載，類型欄位不借它的名義攔人。
	if loginBody["must_change_password"] != true {
		t.Errorf("Root 開設的管理員應欠首次改密，實際 %#v", loginBody["must_change_password"])
	}
}

// dumpOf 把回應本體轉成可比對的原始 JSON 文字（測試取證用）。
func dumpOf(body map[string]any) string {
	raw, err := json.Marshal(body)
	if err != nil {
		return ""
	}
	return string(raw)
}

// 以下三項是刻意的缺席，留註以免日後被當成漏項補回來：
//   - 沒有一枚新的機器碼：訪客入口的三個結論各有現成的碼（2017／2006／1004），
//     為同一個處置另開一枚碼只會讓一句話有兩種寫法；
//   - 沒有一個「列出全站訪客」的匿名端點：訪客帳戶在既有管理目錄裡就讀得到，
//     而那本目錄的讀入門只有已認證的伺服器級管理者過得去；
//   - 沒有任何「凭暱稱換回會話」的通路：暱稱可自報、可重複，拿它認人等於造一把口令。
