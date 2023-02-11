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
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/selfregister"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// selfregister_test.go 釘住「匿名自註冊」在傳輸層的契約：本體白名單（未知欄位當場拒殺）、
// 來源判定、結論對映（2019／2017／2016／2006＋Retry-After／1004 點名欄位／500）、
// 以及「成功只回一筆新建帳戶的現值、刻意不簽發會話」。准入與唯一性的業務判定由
// internal/selfregister 自己的測試負責，這裡只驗證「協定層有沒有把對的結論翻譯成對的碼、
// 有沒有在該擋的地方一個帳戶都不多造」。

// fakeSelfRegister 是 SelfRegisterUseCase 的傳輸層替身：回吐預置結果並記錄收到的輸入，
// 讓「未知欄位拒殺、來源取實際連線、錯誤對映、不簽發 Cookie」這些傳輸層規則脫離資料庫被釘死。
type fakeSelfRegister struct {
	result  selfregister.RegisteredAccount
	err     error
	calls   int
	lastIn  selfregister.RegisterInput
	lastReq string
	lastIP  string
}

func (f *fakeSelfRegister) RegisterAccount(ctx context.Context, in selfregister.RegisterInput,
	requestID, sourceIP string) (selfregister.RegisteredAccount, error) {
	f.calls++
	f.lastIn = in
	f.lastReq = requestID
	f.lastIP = sourceIP
	return f.result, f.err
}

// registerTestServer 建立只注入自註冊用例的 HTTP 測試服務（走完整中介層鏈）。
// 刻意不注入 Auth：端點掛不掛只取決於有無自註冊用例，與登入用例無關。
func registerTestServer(t *testing.T, fake SelfRegisterUseCase, mutate func(*config.Config)) *httptest.Server {
	t.Helper()
	cfg := config.Default()
	if mutate != nil {
		mutate(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("測試組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{SelfRegister: fake, Clock: timeutil.System()})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// successResult 構造一個「標準／active／無需改密」的註冊成功結果。
func successResult(t *testing.T) selfregister.RegisteredAccount {
	t.Helper()
	return selfregister.RegisteredAccount{
		AccountID:          mustTestID(t),
		LoginName:          "Std.First.Sign.In",
		DisplayName:        "首个自註冊帳戶",
		Status:             account.StatusActive,
		MustChangePassword: false,
		CreatedAt:          timeutil.System().Now().UTC(),
	}
}

// registerBody 用三個白名單欄位拼一個合法本體（欄位值由測試提供）。
func registerBody(login, display, password string) string {
	b, _ := json.Marshal(map[string]string{
		"login_name":   login,
		"display_name": display,
		"password":     password,
	})
	return string(b)
}

// assertRegisterCode 斷言回應的機器碼、HTTP 狀態與在地化訊息非空，並回傳解碼後的信封。
func assertRegisterCode(t *testing.T, resp *http.Response, wantCode int, wantStatus int) map[string]any {
	t.Helper()
	if resp.StatusCode != wantStatus {
		t.Fatalf("HTTP 狀態應為 %d，實際 %d", wantStatus, resp.StatusCode)
	}
	body := decodeJSONBody(t, resp)
	code, ok := body["code"].(float64)
	if !ok || int(code) != wantCode {
		t.Fatalf("機器碼應為 %d，實際 %#v", wantCode, body["code"])
	}
	if msg, ok := body["message"].(string); !ok || msg == "" {
		t.Fatalf("message 應為非空在地化文案：%#v", body["message"])
	}
	if got := resp.Header.Get(cacheControlHeader); got != "no-store" {
		t.Fatalf("自註冊回應仍須 no-store，實際 %q", got)
	}
	return body
}

// TestRegisterSuccessShapeNoSessionCookie 釘住成功回應的形態與「不簽發會話」：
// 只有那組可展示事實、must_change_password 恆為 false、無任何 Cookie／口令／雜湊外洩，
// 而且來源位址取實際連線（127.0.0.1）而非轉發標頭。
func TestRegisterSuccessShapeNoSessionCookie(t *testing.T) {
	fake := &fakeSelfRegister{result: successResult(t)}
	ts := registerTestServer(t, fake, nil)

	resp := postJSON(t, ts, "/auth/register",
		registerBody("Std.First.Sign.In", "首个自註冊帳戶", "selfregister-自選口令"),
		"", map[string]string{"X-Forwarded-For": "8.8.8.8"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("註冊成功應為 201，實際 %d", resp.StatusCode)
	}

	// 不簽發會話：回應不得帶任何會話 Cookie（也不得帶 Set-Cookie）。
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			t.Fatalf("自註冊成功不得簽發會話 Cookie：%v", c)
		}
	}
	if len(resp.Header.Values("Set-Cookie")) != 0 {
		t.Fatalf("自註冊成功不得下發任何 Cookie：%v", resp.Header.Values("Set-Cookie"))
	}

	body := decodeJSONBody(t, resp)
	for _, field := range []string{"account_id", "login_name", "display_name", "status",
		"must_change_password", "created_at", "request_id"} {
		if _, ok := body[field]; !ok {
			t.Fatalf("回應缺少契约欄位 %s：%#v", field, body)
		}
	}
	if body["status"] != "active" {
		t.Fatalf("status 應為 active，實際 %#v", body["status"])
	}
	if mcp, ok := body["must_change_password"].(bool); !ok || mcp {
		t.Fatalf("must_change_password 應恆為 false，實際 %#v", body["must_change_password"])
	}
	// 沒有 roles／activity 任何一欄：自註冊建的按定義不帶伺服器級授予，回應不描述不存在的事。
	for _, forbidden := range []string{"roles", "role", "account_type", "activity_id", "password", "password_hash"} {
		if _, ok := body[forbidden]; ok {
			t.Fatalf("回應不得含 %s 欄：%#v", forbidden, body)
		}
	}
	// 本體交下去的是原樣三欄，且來源取實際連線而非轉發標頭。
	if fake.lastIn.LoginName != "Std.First.Sign.In" || fake.lastIn.Password != "selfregister-自選口令" {
		t.Fatalf("用例收到的輸入應原樣對應：%#v", fake.lastIn)
	}
	if fake.lastIP != "127.0.0.1" {
		t.Fatalf("來源必須取實際連線位址，實際交了 %q", fake.lastIP)
	}
	if fake.lastReq == "" {
		t.Fatal("應把請求關聯 ID 交進用例")
	}
}

// TestRegisterRejectsSelfClaimedRoleFields 釘住協定層沒有「把自己昇格」的格子：
// 任何自報身分或企圖覆蓋隱藏欄位都由 DisallowUnknownFields 當場拒殺（1004＋點名該欄位），
// 用例一次都不會被Call到——因此這類請求一個帳戶也不會多出來。
func TestRegisterRejectsSelfClaimedRoleFields(t *testing.T) {
	for _, smuggled := range []string{"role", "account_type", "status", "subject_kind",
		"must_change_password", "activity_id", "granted_roles"} {
		t.Run(smuggled, func(t *testing.T) {
			fake := &fakeSelfRegister{result: successResult(t)}
			ts := registerTestServer(t, fake, nil)

			var payload map[string]any
			if err := json.Unmarshal([]byte(registerBody("a.b", "AB", "selfregister-自選口令")), &payload); err != nil {
				t.Fatalf("組裝本體失敗：%v", err)
			}
			// 嘗試把「建的是哪一類主體」寫進請求內容——協定層不給這個欄位落地。
			payload[smuggled] = "server_admin"
			raw, _ := json.Marshal(payload)

			resp := postJSON(t, ts, "/auth/register", string(raw), "", nil)
			body := assertRegisterCode(t, resp, 1004, http.StatusBadRequest)
			details, ok := body["details"].(map[string]any)
			if !ok {
				t.Fatalf("未知欄位回應應帶 details：%#v", body)
			}
			if details["reason"] != "unknown field" || details["field"] != smuggled {
				t.Fatalf("應點名被拒的欄位 %s，實際 %#v", smuggled, details)
			}
			if fake.calls != 0 {
				t.Fatalf("未知欄位請求不得到達用例（應零建立），實際 calls=%d", fake.calls)
			}
		})
	}
}

// TestRegisterErrorMappings 逐條釘住用例結論到機器碼的對映，各自對應不同的處置、不互相冒充。
func TestRegisterErrorMappings(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantCode   int
		wantStatus int
		// wantField 非空時斷言 details.invalid_field（1004 點名欄位那組）。
		wantField string
	}{
		{"duplicate", selfregister.ErrDuplicateLogin, 2019, http.StatusConflict, ""},
		{"disabled", selfregister.ErrRegisterDisabled, 2017, http.StatusForbidden, ""},
		{"mode_unsupported", selfregister.ErrRegisterModeUnsupported, 2016, http.StatusBadRequest, ""},
		{"no_policy_row", acctpolicy.ErrNoPolicyRow, 1000, http.StatusInternalServerError, ""},
		{"invalid_password", selfregister.ErrInvalidPassword, 1004, http.StatusBadRequest, "password"},
		{"invalid_login", account.ErrInvalidLogin, 1004, http.StatusBadRequest, "login_name"},
		{"invalid_display", account.ErrInvalidDisplayName, 1004, http.StatusBadRequest, "display_name"},
		{"unclassified", errors.New("派生故障"), 1000, http.StatusInternalServerError, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSelfRegister{err: tc.err}
			ts := registerTestServer(t, fake, nil)
			resp := postJSON(t, ts, "/auth/register",
				registerBody("a.b", "AB", "selfregister-自選口令"), "", nil)
			body := assertRegisterCode(t, resp, tc.wantCode, tc.wantStatus)
			if tc.wantField != "" {
				details, ok := body["details"].(map[string]any)
				if !ok || details["invalid_field"] != tc.wantField {
					t.Fatalf("1004 應點名 %s 欄，實際 %#v", tc.wantField, body["details"])
				}
			}
			// 失敗不偽造成功：非 201 一律不得帶 account_id。
			if _, ok := body["account_id"]; ok {
				t.Fatalf("失敗回應不得含 account_id：%#v", body)
			}
		})
	}
}

// TestRegisterThrottledMapsTo429WithRetryAfter 釘住限流在傳輸層的對映：2006／429、
// Retry-After 向上取整（不足一秒報 1 秒），且回應不透露它擋的是哪個名字。
func TestRegisterThrottledMapsTo429WithRetryAfter(t *testing.T) {
	fake := &fakeSelfRegister{err: &selfregister.ThrottledError{RetryAfter: 90200 * time.Millisecond}}
	ts := registerTestServer(t, fake, nil)

	resp := postJSON(t, ts, "/auth/register", registerBody("a.b", "AB", "pw12345678"), "", nil)
	body := assertRegisterCode(t, resp, 2006, http.StatusTooManyRequests)
	if got := resp.Header.Get("Retry-After"); got != "91" {
		t.Fatalf("Retry-After 應向上取整為 91 秒，實際 %q", got)
	}
	// 信封只有固定三欄：限流回應不得出現 details 或任何指出「擋的是哪個名字」的欄位。
	for _, field := range []string{"code", "message", "request_id"} {
		if _, ok := body[field]; !ok {
			t.Fatalf("限流回應缺少信封欄位 %s：%#v", field, body)
		}
	}
	if len(body) != 3 {
		t.Fatalf("限流回應不得帶信封之外的欄位：%#v", body)
	}
}

// TestRegisterThrottledRetryAfterMinimumOneSecond 冷卻尾巴不足一秒時報 1 秒：
// 報 0 會被讀成「立刻再試」，與冷卻尚未結束的事實矛盾。
func TestRegisterThrottledRetryAfterMinimumOneSecond(t *testing.T) {
	fake := &fakeSelfRegister{err: &selfregister.ThrottledError{RetryAfter: 120 * time.Millisecond}}
	ts := registerTestServer(t, fake, nil)

	resp := postJSON(t, ts, "/auth/register", registerBody("a.b", "AB", "pw12345678"), "", nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("應為 429，實際 %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After 下限應為 1 秒，實際 %q", got)
	}
}

// TestRegisterThrottledMessageIsLocalized 用真實限流對映走一遍四語言：
// 2006 文案在 zh-CN／zh-TW／en-US／ja-JP 都各有其句，缺語言時回退預設而非空字串。
func TestRegisterThrottledMessageIsLocalized(t *testing.T) {
	fake := &fakeSelfRegister{err: &selfregister.ThrottledError{RetryAfter: time.Minute}}
	ts := registerTestServer(t, fake, nil)

	want := map[string]string{
		"zh-CN": "登录尝试过多，请稍后再试。",
		"zh-TW": "登入嘗試次數過多，請稍後再試。",
		"en-US": "Too many login attempts. Please try again later.",
		"ja-JP": "ログイン試行回数が多すぎます。しばらくしてからもう一度お試しください。",
	}
	seen := map[string]struct{}{}
	for locale, expected := range want {
		resp := postJSON(t, ts, "/auth/register", registerBody("a.b", "AB", "pw12345678"), "",
			map[string]string{"Accept-Language": locale})
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("解碼失敗：%v", err)
		}
		if body["message"] != expected {
			t.Fatalf("%s 文案應為 %q，實際 %#v", locale, expected, body["message"])
		}
		seen[locale] = struct{}{}
	}
	if len(seen) != len(want) {
		t.Fatalf("四語言都應覆蓋到：%v", seen)
	}
}

// TestRegisterNameTakenMessageIsLocalized 409 那句可判別重名同樣須四語言齊備，
// 讓正常用戶在任一門面下都知道「要換名字」而不是以為是故障。
func TestRegisterNameTakenMessageIsLocalized(t *testing.T) {
	fake := &fakeSelfRegister{err: selfregister.ErrDuplicateLogin}
	ts := registerTestServer(t, fake, nil)

	want := map[string]string{
		"zh-CN": "这个登录名已被占用（比对会吸收大小写与全角／半角等差异写法），本次注册没有创建账户。请换一个名字后重新提交。",
		"zh-TW": "這個登入名已被佔用（比對會吸收大小寫與全形／半形等差異寫法），本次註冊沒有建立帳戶。請換一個名字後重新提交。",
		"en-US": "This login name is already taken (matching absorbs case and width variants such as full-width letters), so this sign-up created no account. Choose another name and submit again.",
		"ja-JP": "このログイン名はすでに使用されています（比較では大小文字や全角・半角などの表記の差異が吸収される）ため、今回の登録ではアカウントが作成されませんでした。別の名前を選んで再度送信してください。",
	}
	for locale, expected := range want {
		resp := postJSON(t, ts, "/auth/register", registerBody("a.b", "AB", "pw12345678"), "",
			map[string]string{"Accept-Language": locale})
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("解碼失敗：%v", err)
		}
		if body["message"] != expected {
			t.Fatalf("%s 文案應為 %q，實際 %#v", locale, expected, body["message"])
		}
	}
}

// TestRegisterOriginRejected 釘住「有副作用的匿名寫入必須先過來源判定」：
// 跨站 Origin 與 Sec-Fetch-Site: cross-site 一律 2005，且用例一次都不被Call到。
func TestRegisterOriginRejected(t *testing.T) {
	fake := &fakeSelfRegister{result: successResult(t)}
	ts := registerTestServer(t, fake, nil)

	resp := postJSON(t, ts, "/auth/register", registerBody("a.b", "AB", "pw12345678"),
		"http://evil.invalid", nil)
	assertRegisterCode(t, resp, 2005, http.StatusForbidden)

	respCross := postJSON(t, ts, "/auth/register", registerBody("a.b", "AB", "pw12345678"), "",
		map[string]string{"Sec-Fetch-Site": "cross-site"})
	assertRegisterCode(t, respCross, 2005, http.StatusForbidden)

	if fake.calls != 0 {
		t.Fatalf("來源被拒的請求不得到達用例，實際 calls=%d", fake.calls)
	}
}

// TestRegisterBodyTooLarge 本體超過 server.max_body_bytes 時回 1003／413，
// 不進入解碼白名單之後的任何通路（因此也零建立）。
func TestRegisterBodyTooLarge(t *testing.T) {
	fake := &fakeSelfRegister{result: successResult(t)}
	ts := registerTestServer(t, fake, func(c *config.Config) {
		c.Server.MaxBodyBytes = 1024
	})

	// 用一個超長 password 撐爆本體；關鍵是「大小上限先於業務判定生效」。
	huge := registerBody("a.b", "AB", strings.Repeat("x", 4096))
	resp := postJSON(t, ts, "/auth/register", huge, "", nil)
	assertRegisterCode(t, resp, 1003, http.StatusRequestEntityTooLarge)
	if fake.calls != 0 {
		t.Fatalf("過大本體不得到達用例，實際 calls=%d", fake.calls)
	}
}

// TestRegisterMalformedAndEmptyBody 空本體與畸形 JSON 都是寫法問題（1004），
// 不誤對映成業務結論，更不偽造成功。
func TestRegisterMalformedAndEmptyBody(t *testing.T) {
	fake := &fakeSelfRegister{result: successResult(t)}
	ts := registerTestServer(t, fake, nil)

	resp := postJSON(t, ts, "/auth/register", "", "", nil)
	body := assertRegisterCode(t, resp, 1004, http.StatusBadRequest)
	details, _ := body["details"].(map[string]any)
	if details["reason"] != "empty request body" {
		t.Fatalf("空本體應點出 empty request body，實際 %#v", body["details"])
	}

	resp = postJSON(t, ts, "/auth/register", `{"login_name":`, "", nil)
	assertRegisterCode(t, resp, 1004, http.StatusBadRequest)

	if fake.calls != 0 {
		t.Fatalf("畸形本體不得到達用例，實際 calls=%d", fake.calls)
	}
}

// TestRegisterWrongContentType 非 JSON 內容型別回 1005，不落進本體白名單判定。
func TestRegisterWrongContentType(t *testing.T) {
	fake := &fakeSelfRegister{result: successResult(t)}
	ts := registerTestServer(t, fake, nil)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/auth/register",
		bytes.NewReader([]byte("login_name=a&password=b")))
	if err != nil {
		t.Fatalf("建立請求失敗：%v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /auth/register 失敗：%v", err)
	}
	defer resp.Body.Close()
	assertRegisterCode(t, resp, 1005, http.StatusUnsupportedMediaType)
	if fake.calls != 0 {
		t.Fatalf("錯誤內容型別不得到達用例，實際 calls=%d", fake.calls)
	}
}

// TestRegisterMethodNotAllowedOnlyPost 這條路徑只有一個方法：非 POST 回 1002 帶 Allow，
// 且「讀能力現值」不在這條上開第二份讀法（GET 直接被方法判定擋下）。
func TestRegisterMethodNotAllowedOnlyPost(t *testing.T) {
	fake := &fakeSelfRegister{result: successResult(t)}
	ts := registerTestServer(t, fake, nil)

	resp := getAuth(t, ts, "/auth/register", "", "", "")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("非 POST 應回 405，實際 %d", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); !strings.Contains(allow, http.MethodPost) {
		t.Fatalf("405 應帶 Allow 標明 POST，實際 %q", allow)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("1002")) {
		t.Fatalf("非 POST 應回機器碼 1002，實際 %q", body)
	}
}

// TestRegisterEndpointNotMountedWithoutUseCase 沒注入自註冊用例的執行檔一個 /auth/register
// 都不掛：打這條路徑得 404（或路由層通用未_found），而不是被半裝配的處理函數接住。
func TestRegisterEndpointNotMountedWithoutUseCase(t *testing.T) {
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{Clock: timeutil.System()})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp := postJSON(t, ts, "/auth/register", registerBody("a.b", "AB", "pw12345678"), "", nil)
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("未注入用例時絕不應簽出 201")
	}
}
