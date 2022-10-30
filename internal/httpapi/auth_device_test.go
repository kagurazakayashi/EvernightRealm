package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// 這一檔釘住「裝置登入策略」在協定層的兩件事：
//   - 名額已滿是 2008／403，一條可判、且與 2001（憑據無效）、2006（限流冷卻）都不同形；
//   - 端到端（真實 auth.Service＋SQLite＋完整中介層鏈）的四種行為：單裝置替換、
//     上限拒絕時既有 Cookie 一律照舊可用、登出立即釋放名額、輪換不佔也不騰名額。
//
// 傳輸層沒有任何「裝置」概念要實作，這是刻意的：請求本體只有登入名與口令，
// 多帶任何 device_* 欄位都會被 DisallowUnknownFields 拒掉。客戶端自報的裝置資訊
// 因此連到達計數判定的路徑都沒有——名額只由伺服器數。

// readEnvelopeBody 讀出錯誤信封與原始文字（兩者都要斷言：碼要對、文字不得夾帶內部資訊）。
func readEnvelopeBody(t *testing.T, resp *http.Response) (ErrorEnvelope, string) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取回應失敗：%v", err)
	}
	var env ErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("回應應為錯誤信封，實際 %q", body)
	}
	return env, string(body)
}

// TestLoginDeviceLimitMapsToForbidden 是錯誤對映本身：名額已滿不是憑據無效（401），
// 也不是限流（429），而是「你已經證明瞭自己是誰，但這一次策略不放行」（403）。
// 兩個登入端點走同一條對映，不各長一套語意。
func TestLoginDeviceLimitMapsToForbidden(t *testing.T) {
	// 兩個登入端點各有自己的請求本體（Root 端點不認登入名，多帶欄位是 1004 而不是策略結論）。
	for _, tc := range []struct{ path, body string }{
		{"/auth/login", `{"login_name":"a","password":"p"}`},
		{"/auth/root/login", `{"password":"p"}`},
	} {
		fake := &fakeAuth{loginErr: auth.ErrLoginDeviceLimit}
		ts := authTestServer(t, fake, nil)
		resp := postJSON(t, ts, tc.path, tc.body, "", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s：名額已滿應回 403，實際 %d", tc.path, resp.StatusCode)
		}
		assertEnvelopeCode(t, resp, CodeDeviceLimitReached)
	}
}

// TestLoginDeviceLimitEnvelopeCarriesNoInternals 釘住回應的「缺席」：
// 沒有 details、不含名額數字、不含主體或裝置標識。
func TestLoginDeviceLimitEnvelopeCarriesNoInternals(t *testing.T) {
	fake := &fakeAuth{loginErr: auth.ErrLoginDeviceLimit}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/login", `{"login_name":"alice","password":"pw"}`, "", nil)
	env, body := readEnvelopeBody(t, resp)
	if env.Details != nil {
		t.Errorf("名額回應不得附 details（會把內部配置變成可探測欄位）：%v", env.Details)
	}
	for _, leak := range []string{"alice", "max_devices", "device_policy", "上限", "password"} {
		if strings.Contains(body, leak) {
			t.Errorf("回應不得洩露 %q：%s", leak, body)
		}
	}
}

// TestDeviceLimitMessagesCoverAllLocales 四語言齊備：每個支援語言都要有一句
// 非空、且彼此不同的文案（缺漏由本步的測試把關，不靠執行期回退掩蓋）。
func TestDeviceLimitMessagesCoverAllLocales(t *testing.T) {
	messages := errorMessages[CodeDeviceLimitReached]
	for _, locale := range []string{LocaleZhCN, LocaleZhTW, LocaleEnUS, LocaleJaJP} {
		if strings.TrimSpace(messages[locale]) == "" {
			t.Errorf("2008 缺少 %s 文案", locale)
		}
	}
	fake := &fakeAuth{loginErr: auth.ErrLoginDeviceLimit}
	ts := authTestServer(t, fake, nil)
	for _, locale := range []string{LocaleZhCN, LocaleZhTW, LocaleEnUS, LocaleJaJP} {
		resp := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"p"}`, "",
			map[string]string{"Accept-Language": locale})
		env, _ := readEnvelopeBody(t, resp)
		if env.Message != messages[locale] {
			t.Errorf("%s 的訊息應為 %q，實際 %q", locale, messages[locale], env.Message)
		}
	}
}

// TestLiveSingleDeviceReplacesPriorCookie 端到端的單裝置：第二次登入之後，
// 第一枚 Cookie 換不出身份（2003），第二枚照常可用。
// 這一條同時釘住「登入成功一律覆寫 Cookie」不會被策略改寫成「沿用舊的那一枚」。
func TestLiveSingleDeviceReplacesPriorCookie(t *testing.T) {
	env := newLiveEnvWithPolicy(t, "", session.Policy{DeviceMode: session.DeviceModeSingle})
	env.liveAccount(t, "single_e2e", "correct-pass")

	first := postJSON(t, env.ts, "/auth/login", `{"login_name":"single_e2e","password":"correct-pass"}`, "", nil)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("首次登入應成功：%d", first.StatusCode)
	}
	firstCookie := sessionCookieName + "=" + loginCookie(t, first).Value

	second := postJSON(t, env.ts, "/auth/login", `{"login_name":"single_e2e","password":"correct-pass"}`, "", nil)
	if second.StatusCode != http.StatusOK {
		t.Fatalf("第二次登入應成功：%d", second.StatusCode)
	}
	secondCookie := sessionCookieName + "=" + loginCookie(t, second).Value

	if got := getAuth(t, env.ts, "/auth/session", firstCookie, "", ""); got.StatusCode != http.StatusUnauthorized {
		t.Errorf("舊 Cookie 應已被撤銷（401），實際 %d", got.StatusCode)
	} else {
		assertEnvelopeCode(t, got, CodeSessionInvalid)
	}
	if got := getAuth(t, env.ts, "/auth/session", secondCookie, "", ""); got.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(got.Body)
		t.Fatalf("新 Cookie 應可用：%d %s", got.StatusCode, body)
	}
}

// TestLiveDeviceLimitRejectsThirdLogin 端到端的指定上限：第三份登入回 2008／403，
// 而前兩份會話一動未動（拒絕不淘汰任何既存裝置）。
func TestLiveDeviceLimitRejectsThirdLogin(t *testing.T) {
	env := newLiveEnvWithPolicy(t, "",
		session.Policy{DeviceMode: session.DeviceModeLimited, MaxDevices: 2})
	env.liveAccount(t, "limit_e2e", "correct-pass")

	first := postJSON(t, env.ts, "/auth/login", `{"login_name":"limit_e2e","password":"correct-pass"}`, "", nil)
	second := postJSON(t, env.ts, "/auth/login", `{"login_name":"limit_e2e","password":"correct-pass"}`, "", nil)
	if first.StatusCode != http.StatusOK || second.StatusCode != http.StatusOK {
		t.Fatalf("前兩份登入應成功：%d / %d", first.StatusCode, second.StatusCode)
	}
	firstCookie := sessionCookieName + "=" + loginCookie(t, first).Value

	third := postJSON(t, env.ts, "/auth/login", `{"login_name":"limit_e2e","password":"correct-pass"}`, "", nil)
	if third.StatusCode != http.StatusForbidden {
		t.Errorf("第三份登入應被名額擋下（403），實際 %d", third.StatusCode)
	}
	assertEnvelopeCode(t, third, CodeDeviceLimitReached)
	// 被拒的這一次不得留下任何 Cookie：那會讓瀏覽器帶上一枚「查無此會話」的憑據。
	for _, c := range third.Cookies() {
		if c.Name == sessionCookieName {
			t.Errorf("被拒的登入不應簽發 Cookie：%+v", c)
		}
	}
	if got := getAuth(t, env.ts, "/auth/session", firstCookie, "", ""); got.StatusCode != http.StatusOK {
		t.Errorf("名額已滿不得讓既有會話失效：第一份 Cookie 應可用，實際 %d", got.StatusCode)
	}
}

// TestLiveLogoutFreesDeviceSlot 名額釋放走的其實是完整的一條路：
// 登出端點 → 用例撤銷 → 下一次登入計數看到的那一格確實空了。
func TestLiveLogoutFreesDeviceSlot(t *testing.T) {
	env := newLiveEnvWithPolicy(t, "",
		session.Policy{DeviceMode: session.DeviceModeLimited, MaxDevices: 1})
	env.liveAccount(t, "slot_e2e", "correct-pass")

	first := postJSON(t, env.ts, "/auth/login", `{"login_name":"slot_e2e","password":"correct-pass"}`, "", nil)
	firstCookie := sessionCookieName + "=" + loginCookie(t, first).Value
	if got := postJSON(t, env.ts, "/auth/login", `{"login_name":"slot_e2e","password":"correct-pass"}`, "", nil); got.StatusCode != http.StatusForbidden {
		t.Fatalf("名額應已被佔住，實際 %d", got.StatusCode)
	}
	if got := postJSON(t, env.ts, "/auth/logout", `{}`, "", map[string]string{"Cookie": firstCookie}); got.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(got.Body)
		t.Fatalf("登出應成功：%d %s", got.StatusCode, body)
	}
	second := postJSON(t, env.ts, "/auth/login", `{"login_name":"slot_e2e","password":"correct-pass"}`, "", nil)
	if second.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(second.Body)
		t.Errorf("登出後應能立刻重新登入：%d %s", second.StatusCode, body)
	}
}

// TestLiveRotationKeepsSlotOccupied 輪換不佔名額、也不騰出名額：上限 1 的主體
// 輪換過之後再登入，仍是 2008。這一條把「輪換＝換密不是換裝置」釘在協定層。
func TestLiveRotationKeepsSlotOccupied(t *testing.T) {
	env := newLiveEnvWithPolicy(t, "",
		session.Policy{DeviceMode: session.DeviceModeLimited, MaxDevices: 1})
	env.liveAccount(t, "rotate_e2e", "correct-pass")

	login := postJSON(t, env.ts, "/auth/login", `{"login_name":"rotate_e2e","password":"correct-pass"}`, "", nil)
	cookie := sessionCookieName + "=" + loginCookie(t, login).Value
	rotated := postJSON(t, env.ts, rotatePath, `{}`, "", map[string]string{"Cookie": cookie})
	if rotated.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(rotated.Body)
		t.Fatalf("輪換應成功：%d %s", rotated.StatusCode, body)
	}
	next := postJSON(t, env.ts, "/auth/login", `{"login_name":"rotate_e2e","password":"correct-pass"}`, "", nil)
	if next.StatusCode != http.StatusForbidden {
		t.Errorf("輪換不應騰出名額，實際 %d", next.StatusCode)
	}
	assertEnvelopeCode(t, next, CodeDeviceLimitReached)
}

// TestLoginRejectsDeviceFields 是「客戶端自報的裝置資訊連到達判定的路徑都沒有」的證據：
// 多帶 device_name / device_id / max_devices 之類的欄位一律 1004，而不是被讀進去。
func TestLoginRejectsDeviceFields(t *testing.T) {
	fake := &fakeAuth{outcome: auth.Outcome{}}
	ts := authTestServer(t, fake, nil)
	for _, body := range []string{
		`{"login_name":"a","password":"p","device_name":"我的手機"}`,
		`{"login_name":"a","password":"p","device_id":"00000000-0000-0000-0000-000000000000"}`,
		`{"login_name":"a","password":"p","max_devices":1}`,
	} {
		resp := postJSON(t, ts, "/auth/login", body, "", nil)
		assertEnvelopeCode(t, resp, CodeInvalidBody)
	}
}

// TestDeviceLimitIsDistinctFromCredentialAndThrottleErrors 三個 2xxx 結論必須彼此可判：
// 2001／2006／2008 各自對應不同的處置，混在一起就等於把使用者推錯方向。
func TestDeviceLimitIsDistinctFromCredentialAndThrottleErrors(t *testing.T) {
	if CodeDeviceLimitReached == CodeInvalidCredentials || CodeDeviceLimitReached == CodeLoginThrottled {
		t.Error("2008 必須是新的、未用過的機器碼")
	}
	// 數值的發布合同：只增不刪，2008 是 2xxx 段的下一個可用值。
	if int(CodeDeviceLimitReached) != 2008 {
		t.Errorf("機器碼數值一經發布不得變動，實際 %d", CodeDeviceLimitReached)
	}
	// 用例層的三個結論也必須互斥（errors.Is 不會把一個誤判成另一個）。
	for _, pair := range [][2]error{
		{auth.ErrLoginDeviceLimit, auth.ErrInvalidCredentials},
		{auth.ErrLoginDeviceLimit, auth.ErrLoginThrottled},
		{auth.ErrLoginDeviceLimit, auth.ErrInvalidSession},
	} {
		if errors.Is(pair[0], pair[1]) || errors.Is(pair[1], pair[0]) {
			t.Errorf("用例錯誤不得互相命中：%v / %v", pair[0], pair[1])
		}
	}
}
