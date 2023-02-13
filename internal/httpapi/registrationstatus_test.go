package httpapi

// registrationstatus_test.go 釘住「申請人查本人申請狀態」在傳輸層的契約：
// 白名單只有登入名與口令兩欄（未知欄位當場拒殺）、來源判定、四種憑據失敗收斂成同一句 2001、
// 已證明身分又不是申請時才出現的 2020、2006＋Retry-After，以及最重要的一件事——
// 這條通路驗證憑據卻刻意不簽發會話（不寫 Set-Cookie、回應裡沒有任何會話材料）。
//
// 憑據校驗與結局判定的業務形態由 internal/selfregister 的測試負責；
// 這裡只驗證協定層有沒有把對的結論翻譯成對的碼、有沒有在該擋的地方一個請求都不往下送，
// 以及有沒有把秘密留在本體裡（URL 上一個字都不該有）。

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/selfregister"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// applicationStatusBody 用兩個白名單欄位拼一個合法本體。
func applicationStatusBody(login, password string) string {
	b, _ := json.Marshal(map[string]string{"login_name": login, "password": password})
	return string(b)
}

// pendingStatus 構造一個「還在等」的查詢結果。
func pendingStatus(t *testing.T) selfregister.ApplicationStatus {
	t.Helper()
	return selfregister.ApplicationStatus{
		Outcome:     selfregister.OutcomePending,
		SubmittedAt: timeutil.System().Now().UTC(),
	}
}

// TestApplicationStatusSuccessShapeNoSessionCookie 釘住成功形態與「不簽發會話」：
// 回應只有結局、提交時刻與關聯 ID；pending 時不帶決定時刻；全案無 Cookie、無口令外洩，
// 而用例收到的來源位址是實際連線（轉發標頭一概不採信）。
func TestApplicationStatusSuccessShapeNoSessionCookie(t *testing.T) {
	fake := &fakeSelfRegister{statusResult: pendingStatus(t)}
	ts := registerTestServer(t, fake, nil)

	const password = "申請人自選口令"
	resp := postJSON(t, ts, "/auth/registration-status", applicationStatusBody("Apply.One", password), "",
		map[string]string{"X-Forwarded-For": "8.8.8.8"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("查詢成功應為 200，實際 %d", resp.StatusCode)
	}
	if cookies := resp.Cookies(); len(cookies) != 0 {
		t.Errorf("查狀態不得簽發任何 Cookie：%+v", cookies)
	}
	body := decodeJSONBody(t, resp)
	if body["outcome"] != "pending" {
		t.Errorf("結局應原樣帶出，實際 %#v", body["outcome"])
	}
	if submitted, ok := body["submitted_at"].(string); !ok || submitted == "" {
		t.Errorf("應帶出提交時刻，實際 %#v", body["submitted_at"])
	}
	if _, present := body["reviewed_at"]; present {
		t.Error("還沒決定時回應裡不該有一個決定時刻（哪怕是零值）")
	}
	if id, ok := body["request_id"].(string); !ok || id == "" {
		t.Error("回應必須帶著請求關聯 ID")
	}
	// 回應不替申請人報出「他是誰的帳戶」這種可轉述的編號：只有他自己知道的兩欄資料都不必出去。
	for _, absent := range []string{"account_id", "display_name", "login_name", "roles", "reason"} {
		if _, ok := body[absent]; ok {
			t.Errorf("回應裡不該有 %s 這一欄：%#v", absent, body)
		}
	}
	if fake.statusCalls != 1 {
		t.Errorf("恰好送進用例一次，實際 %d 次", fake.statusCalls)
	}
	if fake.lastStatusIP != "127.0.0.1" {
		t.Errorf("來源位址只能取實際連線，實際 %q", fake.lastStatusIP)
	}
	if fake.lastStatusIn.Password != password || fake.lastStatusIn.LoginName != "Apply.One" {
		t.Errorf("用例收到的應是本體的兩欄，實際 %+v", fake.lastStatusIn)
	}
	dumped, _ := json.Marshal(body)
	if strings.Contains(string(dumped), password) {
		t.Error("回應不得回顯口令明文")
	}
}

// TestApplicationStatusCarriesDecisionTime 已批准與已拒絕都帶得出決定時刻。
func TestApplicationStatusCarriesDecisionTime(t *testing.T) {
	decided := timeutil.System().Now().UTC().Add(time.Hour)
	for _, outcome := range []selfregister.ApplicationOutcome{selfregister.OutcomeApproved, selfregister.OutcomeRejected} {
		fake := &fakeSelfRegister{statusResult: selfregister.ApplicationStatus{
			Outcome:     outcome,
			SubmittedAt: timeutil.System().Now().UTC(),
			ReviewedAt:  decided,
		}}
		ts := registerTestServer(t, fake, nil)
		resp := postJSON(t, ts, "/auth/registration-status", applicationStatusBody("Apply.Two", "口令"), "", nil)
		body := decodeJSONBody(t, resp)
		if body["outcome"] != outcome.String() {
			t.Errorf("%s 的結局應原樣帶出，實際 %#v", outcome, body["outcome"])
		}
		if reviewed, ok := body["reviewed_at"].(string); !ok || reviewed == "" {
			t.Errorf("%s 應帶出決定時刻，實際 %#v", outcome, body["reviewed_at"])
		}
	}
}

// TestApplicationStatusRejectsSelfReportedIdentity 協定層沒有格子能指向別人：
// 任何「帳戶標識」「申請編號」「結局宣稱」之類的欄位都被未知欄位規則當場拒殺，
// 而且一個查詢都不送進用例。
func TestApplicationStatusRejectsSelfReportedIdentity(t *testing.T) {
	cases := []struct{ name, extra string }{
		{"帳戶標識", `"account_id":"0192f0c4-1c9a-7000-8000-000000000000"`},
		{"申請編號", `"application_id":"req-1"`},
		{"結局宣稱", `"outcome":"approved"`},
		{"角色宣稱", `"role":"server_admin"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSelfRegister{}
			ts := registerTestServer(t, fake, nil)
			resp := postJSON(t, ts, "/auth/registration-status",
				`{"login_name":"Apply.Three","password":"口令",`+tc.extra+`}`, "", nil)
			body := assertRegisterCode(t, resp, int(CodeInvalidBody), http.StatusBadRequest)
			details, ok := body["details"].(map[string]any)
			if !ok || details["reason"] != "unknown field" {
				t.Fatalf("未知欄位回應應點明原因，實際 %#v", body["details"])
			}
			if fake.statusCalls != 0 {
				t.Errorf("被協定層拒殺的請求不得送進用例，實際送達 %d 次", fake.statusCalls)
			}
		})
	}
}

// TestApplicationStatusErrorMapping 錯誤對映逐條對應不同的處置，而四種憑據失敗同形。
func TestApplicationStatusErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantCode   int
		wantStatus int
		wantField  string
	}{
		// 查無此名、訪客帳戶、口令形狀不合格、口令不符四者都到這裡收斂成同一句話：
		// 把它們分開就是給探測者一部免費的名單。
		{"憑據無效", selfregister.ErrInvalidCredentials, int(CodeInvalidCredentials), http.StatusUnauthorized, ""},
		{"已證明身分但不是申請", selfregister.ErrNotAnApplication,
			int(CodeNotAnApplication), http.StatusForbidden, ""},
		{"不合規的登入名", account.ErrInvalidLogin, int(CodeInvalidBody), http.StatusBadRequest, "login_name"},
		{"未分類故障", errors.New("資料庫打嗝"), int(CodeUnknown), http.StatusInternalServerError, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSelfRegister{statusErr: tc.err}
			ts := registerTestServer(t, fake, nil)
			resp := postJSON(t, ts, "/auth/registration-status", applicationStatusBody("Apply.Four", "口令"), "", nil)
			body := assertRegisterCode(t, resp, tc.wantCode, tc.wantStatus)
			if tc.wantField != "" {
				details, ok := body["details"].(map[string]any)
				if !ok || details["invalid_field"] != tc.wantField {
					t.Fatalf("1004 應點名 %s 欄，實際 %#v", tc.wantField, body["details"])
				}
			}
			// 失敗不偽造成功：非 200 一律不得帶 outcome。
			if _, ok := body["outcome"]; ok {
				t.Fatalf("失敗回應不得含 outcome：%#v", body)
			}
			dumped, _ := json.Marshal(body)
			if strings.Contains(string(dumped), "口令") {
				t.Error("錯誤回應不得回顯口令明文")
			}
		})
	}
}

// TestApplicationStatusThrottleKeepsRetryAfter 限流沿用同一枚碼與 Retry-After，
// 信封恰好三鍵、不透露被擋的是哪個名字。
func TestApplicationStatusThrottleKeepsRetryAfter(t *testing.T) {
	fake := &fakeSelfRegister{statusErr: &selfregister.ThrottledError{RetryAfter: 90200 * time.Millisecond}}
	ts := registerTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/registration-status", applicationStatusBody("Apply.Five", "口令"), "", nil)
	body := assertRegisterCode(t, resp, int(CodeLoginThrottled), http.StatusTooManyRequests)
	if got := resp.Header.Get("Retry-After"); got != "91" {
		t.Errorf("Retry-After 應向上取整為 91 秒，實際 %q", got)
	}
	for key := range body {
		switch key {
		case "code", "message", "request_id":
		default:
			t.Errorf("被擋的回應信封多了一鍵 %q：%v", key, body[key])
		}
	}
}

// TestApplicationStatusMessageIsDistinctAndLocalized 2020 四語言齊備，
// 而且與「憑據無效」「策略未開放」兩句不同文——同一句話不得同時描述兩種處置。
func TestApplicationStatusMessageIsDistinctAndLocalized(t *testing.T) {
	for _, locale := range []string{LocaleZhCN, LocaleZhTW, LocaleEnUS, LocaleJaJP} {
		text := errorMessages[CodeNotAnApplication][locale]
		if text == "" {
			t.Fatalf("%s 缺 2020 的訊息", locale)
		}
		if text == errorMessages[CodeInvalidCredentials][locale] {
			t.Errorf("%s 的 2020 與「憑據無效」同文，處置會被講成同一件事", locale)
		}
		if text == errorMessages[CodeAccountCreationDisabled][locale] {
			t.Errorf("%s 的 2020 與「策略未開放」同文，等 Root 與去登入是兩句話", locale)
		}
	}

	fake := &fakeSelfRegister{statusErr: selfregister.ErrNotAnApplication}
	ts := registerTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/registration-status", applicationStatusBody("Apply.Six", "口令"), "",
		map[string]string{"Accept-Language": "en-US"})
	body := decodeJSONBody(t, resp)
	if body["message"] != errorMessages[CodeNotAnApplication][LocaleEnUS] {
		t.Errorf("Accept-Language 應被採納，實際 %#v", body["message"])
	}
}

// TestApplicationStatusRejectsForeignOrigin 跨站來源先被擋下，一個查詢都不送進用例。
func TestApplicationStatusRejectsForeignOrigin(t *testing.T) {
	fake := &fakeSelfRegister{statusResult: pendingStatus(t)}
	ts := registerTestServer(t, fake, nil)

	resp := postJSON(t, ts, "/auth/registration-status", applicationStatusBody("Apply.Seven", "口令"),
		"http://evil.invalid", nil)
	assertRegisterCode(t, resp, int(CodeOriginForbidden), http.StatusForbidden)
	respCross := postJSON(t, ts, "/auth/registration-status", applicationStatusBody("Apply.Seven", "口令"), "",
		map[string]string{"Sec-Fetch-Site": "cross-site"})
	assertRegisterCode(t, respCross, int(CodeOriginForbidden), http.StatusForbidden)
	if fake.statusCalls != 0 {
		t.Errorf("被來源判定擋下的請求不得觸達用例，實際 %d 次", fake.statusCalls)
	}
}

// TestApplicationStatusIsPostOnlySecretNeverInURL 這條路徑只認 POST：
// 把口令放進 URL 查詢字串的那種讀法不存在，GET 一律 405 且帶著 Allow 標頭。
//
// 這一條釘的是用戶批准的「不把秘密放入 URL」：GET 能被預取、能被快取、位址欄一貼
// 就是一份憑據副本，所以這條通路在協定層就只留請求本體這一種交法。
func TestApplicationStatusIsPostOnlySecretNeverInURL(t *testing.T) {
	fake := &fakeSelfRegister{}
	ts := registerTestServer(t, fake, nil)
	req, err := http.NewRequest(http.MethodGet,
		ts.URL+"/auth/registration-status?login_name=Apply.Eight&password=口令", nil)
	if err != nil {
		t.Fatalf("構造 GET 失敗：%v", err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("請求失敗：%v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET 應被拒為 405，實際 %d", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); !strings.Contains(allow, http.MethodPost) {
		t.Errorf("405 應告知唯一方法，實際 Allow=%q", allow)
	}
	if fake.statusCalls != 0 {
		t.Errorf("方法都不對的請求不該送進用例，實際 %d 次", fake.statusCalls)
	}
}

// TestApplicationStatusNotMountedWithoutUseCase 沒注入用例的執行檔兩條路徑都不掛：
// 「裝配了什麼就服務什麼」對提交與查狀態同時成立，不留一條能探測的半成品端點。
func TestApplicationStatusNotMountedWithoutUseCase(t *testing.T) {
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{Clock: timeutil.System()})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	for _, path := range []string{"/auth/register", "/auth/registration-status"} {
		resp := postJSON(t, ts, path, applicationStatusBody("Apply.Nine", "口令"), "", nil)
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			t.Errorf("未注入用例時 %s 不該被服務成成功，實際 %d", path, resp.StatusCode)
		}
	}
}
