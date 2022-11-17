package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// 這一檔釘住「我的裝置」兩個端點在協定層的規則：
//   - GET /auth/devices 只讀、走共用解析鏈（未帶 2002、失效 2003、上一代 2007、混用 2004），
//     回應只有可展示事實，絕不含任何憑據材料；
//   - POST /auth/devices/revoke 是有副作用的方法，先過 CSRF 來源策略，再要求 credOK
//     （這正是「敏感操作重檢當前會話有效」），撤銷目標經 idgen 解析，越權／不存在
//     收斂為 2009；撤的若是自己這臺，Web 下發刪除指令、body 標 current=true。
//
// 協定映射用替身釘死（分發與對映才是本檔的職責），端到端行為用真實 auth.Service＋SQLite
// 補上「清單範圍真的由解析出的主體決定、撤銷真的讓舊憑據立即失效」這一層。

const (
	devicesPath      = "/auth/devices"
	deviceRevokePath = "/auth/devices/revoke"
)

// resolveOK 造一個「帶任意憑據即換回指定主體+會話」的解析函式。
func resolveOK(o auth.Outcome) func(string) (identity.Principal, session.Session, error) {
	return func(string) (identity.Principal, session.Session, error) { return o.Principal, o.Session, nil }
}

// resolveErr 造一個「換回指定錯誤」的解析函式（ credInvalid／credStale 路徑用）。
func resolveErr(err error) func(string) (identity.Principal, session.Session, error) {
	return func(string) (identity.Principal, session.Session, error) {
		return identity.Principal{}, session.Session{}, err
	}
}

// readAll 讀盡回應本體（測試專屬；每個回應只讀一次，故要重複用就先存 raw）。
func readAll(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取回應失敗：%v", err)
	}
	return b
}

// decodeEnvelopeFrom 從已讀出的 bytes 解析錯誤信封。
func decodeEnvelopeFrom(t *testing.T, raw []byte) ErrorEnvelope {
	t.Helper()
	var env ErrorEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("回應應為錯誤信封：%s", raw)
	}
	return env
}

// decodeDevices 把清單回應（讀盡本體）解成裝置陣列＋頂層 map＋原始文字。
func decodeDevices(t *testing.T, resp *http.Response) ([]map[string]any, string) {
	t.Helper()
	raw := readAll(t, resp)
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("清單回應應為 JSON：%s", raw)
	}
	arr, _ := top["devices"].([]any)
	items := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		m, _ := e.(map[string]any)
		items = append(items, m)
	}
	return items, string(raw)
}

// hasClearingCookie 回報回應是否帶有對會話 Cookie 的刪除指令（Max-Age<0 或空值）。
func hasClearingCookie(resp *http.Response) bool {
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName && (c.MaxAge < 0 || c.Value == "") {
			return true
		}
	}
	return false
}

// assertCodeStatus 釘住錯誤回應的狀態碼與機器碼兩者皆符。
func assertCodeStatus(t *testing.T, resp *http.Response, wantCode ErrorCode, wantStatus int) {
	t.Helper()
	raw := readAll(t, resp)
	if resp.StatusCode != wantStatus {
		t.Errorf("狀態碼應為 %d，實際 %d（%s）", wantStatus, resp.StatusCode, raw)
	}
	if env := decodeEnvelopeFrom(t, raw); env.Code != wantCode {
		t.Errorf("機器碼應為 %d，實際 %d", wantCode, env.Code)
	}
}

// —— 協定層：用替身釘死解析鏈與錯誤對映。——

// TestDevicesRequiresValidSession 未帶 2002、失效 2003、上一代 2007、混用 2004——
// 與 /auth/session 同一條解析鏈、同一組結論。
func TestDevicesRequiresValidSession(t *testing.T) {
	// 未帶憑據：resolveCredentials 走 credAbsent，不呼叫 Resolve。
	tsNo := authTestServer(t, &fakeAuth{}, nil)
	assertCodeStatus(t, getAuth(t, tsNo, devicesPath, "", "", ""), CodeNotAuthenticated, http.StatusUnauthorized)

	// 失效憑據：401/2003，Web 順帶刪除指令。
	tsInvalid := authTestServer(t, &fakeAuth{resolveFn: resolveErr(auth.ErrInvalidSession)}, nil)
	resp := getAuth(t, tsInvalid, devicesPath, sessionCookieName+"=x", "", "")
	assertCodeStatus(t, resp, CodeSessionInvalid, http.StatusUnauthorized)

	// 上一代：401/2007，不發刪除指令（有效憑據可能已在瀏覽器裡）。
	tsStale := authTestServer(t, &fakeAuth{resolveFn: resolveErr(auth.ErrStaleSession)}, nil)
	staleResp := getAuth(t, tsStale, devicesPath, sessionCookieName+"=x", "", "")
	assertCodeStatus(t, staleResp, CodeSessionStale, http.StatusUnauthorized)

	// 混用 Cookie＋Bearer：400/2004。
	tsConflict := authTestServer(t, &fakeAuth{resolveFn: resolveOK(testOutcome(t))}, nil)
	assertCodeStatus(t, getAuth(t, tsConflict, devicesPath, sessionCookieName+"=x", "bearer-y", ""),
		CodeAuthMethodConflict, http.StatusBadRequest)
}

// TestListDevicesBodyCarriesNoCredential 清單能拿到兩枚裝置、恰好一枚 current，
// 且回應文字不含本請求所帶來的秘密。
func TestListDevicesBodyCarriesNoCredential(t *testing.T) {
	o := testOutcome(t)
	other := mustTestID(t)
	fake := &fakeAuth{resolveFn: resolveOK(o)}
	fake.devicesFn = func(identity.Principal) ([]session.Session, error) {
		return []session.Session{o.Session, {DeviceID: other, CreatedAt: o.Session.CreatedAt}}, nil
	}
	ts := authTestServer(t, fake, nil)
	resp := getAuth(t, ts, devicesPath, sessionCookieName+"=x", "", "")
	if resp.StatusCode != http.StatusOK {
		items, _ := decodeDevices(t, resp)
		t.Fatalf("有效憑據應拿到清單，實際 %d（%d 項）", resp.StatusCode, len(items))
	}
	items, raw := decodeDevices(t, resp)
	if len(items) != 2 {
		t.Fatalf("清單應含兩枚裝置，實際 %d", len(items))
	}
	assertSingleCurrentDevice(t, items, o.Session.DeviceID.String())
	if strings.Contains(raw, o.Secret) {
		t.Error("清單回應不得夾帶會話秘密")
	}
}

// TestDeviceRevokeRejectsCrossOrigin 跨站來源在解析憑據前就被擋，回 403/2005。
func TestDeviceRevokeRejectsCrossOrigin(t *testing.T) {
	ts := authTestServer(t, &fakeAuth{resolveFn: resolveOK(testOutcome(t))}, nil)
	resp := postJSON(t, ts, deviceRevokePath,
		`{"device_id":"019e0000-0000-7000-8000-000000000000"}`, "http://evil.example",
		map[string]string{"Cookie": sessionCookieName + "=x"})
	assertCodeStatus(t, resp, CodeOriginForbidden, http.StatusForbidden)
}

// TestDeviceRevokeRejectsNoSession 沒有有效會話就無從歸屬：未帶憑據 401/2002。
func TestDeviceRevokeRejectsNoSession(t *testing.T) {
	ts := authTestServer(t, &fakeAuth{}, nil)
	resp := postJSON(t, ts, deviceRevokePath,
		`{"device_id":"019e0000-0000-7000-8000-000000000000"}`, "", nil)
	assertCodeStatus(t, resp, CodeNotAuthenticated, http.StatusUnauthorized)
}

// TestDeviceRevokeMalformedAndUnknownFields 本體只有 device_id：形狀不合格 → 1004；
// 多帶 account_id／主體宣稱 → 1004（不给越權留入口）。
func TestDeviceRevokeMalformedAndUnknownFields(t *testing.T) {
	ts := authTestServer(t, &fakeAuth{resolveFn: resolveOK(testOutcome(t))}, nil)
	cookie := map[string]string{"Cookie": sessionCookieName + "=x"}
	assertCodeStatus(t, postJSON(t, ts, deviceRevokePath, `{"device_id":"not-a-uuid"}`, "", cookie),
		CodeInvalidBody, http.StatusBadRequest)
	assertCodeStatus(t, postJSON(t, ts, deviceRevokePath,
		`{"device_id":"019e0000-0000-7000-8000-000000000000","account_id":"deadbeef"}`, "", cookie),
		CodeInvalidBody, http.StatusBadRequest)
}

// TestDeviceRevokeMapsNotFound 越權／不存在的目標收斂為同一個 404/2009。
func TestDeviceRevokeMapsNotFound(t *testing.T) {
	o := testOutcome(t)
	fake := &fakeAuth{resolveFn: resolveOK(o)}
	fake.revokeFn = func(identity.Principal, idgen.ID) (auth.DeviceRevokeResult, error) {
		return auth.DeviceRevokeResult{}, session.ErrNotFound
	}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, deviceRevokePath,
		`{"device_id":"019e0000-0000-7000-8000-000000000000"}`, "",
		map[string]string{"Cookie": sessionCookieName + "=x"})
	assertCodeStatus(t, resp, CodeDeviceNotFound, http.StatusNotFound)
}

// TestDeviceRevokeCurrentClearsCookie 撤自己這臺：200、current=true、Web 下發刪除指令。
func TestDeviceRevokeCurrentClearsCookie(t *testing.T) {
	o := testOutcome(t)
	fake := &fakeAuth{resolveFn: resolveOK(o)}
	fake.revokeFn = func(identity.Principal, idgen.ID) (auth.DeviceRevokeResult, error) {
		return auth.DeviceRevokeResult{Session: o.Session, Revoked: true}, nil
	}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, deviceRevokePath, `{"device_id":"`+o.Session.DeviceID.String()+`"}`, "",
		map[string]string{"Cookie": sessionCookieName + "=x"})
	body := decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("撤銷當前裝置應 200，實際 %d", resp.StatusCode)
	}
	if body["current"] != true || body["revoked"] != true {
		t.Errorf("撤銷當前裝置應 current=true/revoked=true，實際 %v", body)
	}
	if !hasClearingCookie(resp) {
		t.Error("撤銷當前裝置（Web）必須下發 Cookie 刪除指令")
	}
}

// TestDeviceRevokeOtherKeepsCookie 撤別的裝置：current=false、不發刪除指令。
func TestDeviceRevokeOtherKeepsCookie(t *testing.T) {
	o := testOutcome(t)
	other := mustTestID(t)
	fake := &fakeAuth{resolveFn: resolveOK(o)}
	fake.revokeFn = func(identity.Principal, idgen.ID) (auth.DeviceRevokeResult, error) {
		return auth.DeviceRevokeResult{Session: session.Session{DeviceID: other}, Revoked: true}, nil
	}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, deviceRevokePath, `{"device_id":"`+other.String()+`"}`, "",
		map[string]string{"Cookie": sessionCookieName + "=x"})
	body := decodeJSONBody(t, resp)
	if body["current"] != false {
		t.Errorf("撤銷別的裝置應 current=false，實際 %v", body["current"])
	}
	if hasClearingCookie(resp) {
		t.Error("撤銷別的裝置不得清除本請求的有效 Cookie")
	}
}

// TestDeviceNotFoundMessagesCoverAllLocales 四語言齊備 2009，且互不相同。
func TestDeviceNotFoundMessagesCoverAllLocales(t *testing.T) {
	messages := errorMessages[CodeDeviceNotFound]
	seen := map[string]bool{}
	for _, locale := range []string{LocaleZhCN, LocaleZhTW, LocaleEnUS, LocaleJaJP} {
		text := strings.TrimSpace(messages[locale])
		if text == "" {
			t.Errorf("2009 缺少 %s 文案", locale)
		}
		if seen[text] {
			t.Errorf("2009 的多語言文案不得雷同（%s）", locale)
		}
		seen[text] = true
	}
}

// TestCodeDeviceNotFoundIsNewAndStable 機器碼發布合同：2009 是未用過的新值，數值不得漂移。
func TestCodeDeviceNotFoundIsNewAndStable(t *testing.T) {
	if int(CodeDeviceNotFound) != 2009 {
		t.Errorf("2009 一經發布數值不得變動，實際 %d", CodeDeviceNotFound)
	}
	for _, other := range []ErrorCode{CodeSessionStale, CodeDeviceLimitReached, CodeSessionInvalid, CodeNotFound} {
		if other == CodeDeviceNotFound {
			t.Errorf("2009 不得與既有機器碼 %d 重用", other)
		}
	}
}

// —— 端到端：真實 auth.Service＋SQLite，清單範圍與撤銷生效邊界的現場證據。——

// TestLiveDevicesListAndRevokeOtherDevice 多裝置清單、撤銷別臺、舊憑據立即失效、清單刷新、冪等。
func TestLiveDevicesListAndRevokeOtherDevice(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "dev_e2e", "correct-pass")

	first := postJSON(t, env.ts, "/auth/login", `{"login_name":"dev_e2e","password":"correct-pass"}`, "", nil)
	second := postJSON(t, env.ts, "/auth/login", `{"login_name":"dev_e2e","password":"correct-pass"}`, "", nil)
	if first.StatusCode != http.StatusOK || second.StatusCode != http.StatusOK {
		t.Fatalf("兩份登入應成功：%d / %d", first.StatusCode, second.StatusCode)
	}
	firstCookie := sessionCookieName + "=" + loginCookie(t, first).Value
	secondCookie := sessionCookieName + "=" + loginCookie(t, second).Value
	firstDevice := decodeJSONBody(t, first)["device_id"].(string)
	secondDevice := decodeJSONBody(t, second)["device_id"].(string)

	items, _ := decodeDevices(t, getAuth(t, env.ts, devicesPath, secondCookie, "", ""))
	if len(items) != 2 {
		t.Fatalf("多裝置清單應含兩枚，實際 %d", len(items))
	}
	assertSingleCurrentDevice(t, items, secondDevice)

	revoke := postJSON(t, env.ts, deviceRevokePath, `{"device_id":"`+firstDevice+`"}`, "",
		map[string]string{"Cookie": secondCookie})
	if revoke.StatusCode != http.StatusOK {
		t.Fatalf("撤銷別臺應 200，實際 %d", revoke.StatusCode)
	}
	rb := decodeJSONBody(t, revoke)
	if rb["current"] != false || rb["revoked"] != true {
		t.Errorf("撤銷別臺應 current=false/revoked=true，實際 %v", rb)
	}
	if hasClearingCookie(revoke) {
		t.Error("撤銷別臺不應清除當前 Cookie")
	}

	assertCodeStatus(t, getAuth(t, env.ts, "/auth/session", firstCookie, "", ""),
		CodeSessionInvalid, http.StatusUnauthorized)
	if got := getAuth(t, env.ts, "/auth/session", secondCookie, "", ""); got.StatusCode != http.StatusOK {
		t.Error("當前裝置不應受別臺撤銷牽連")
	}

	refresh, _ := decodeDevices(t, getAuth(t, env.ts, devicesPath, secondCookie, "", ""))
	stateByID := map[string]any{}
	for _, m := range refresh {
		stateByID[m["device_id"].(string)] = m["status"]
	}
	if stateByID[firstDevice] != "revoked" {
		t.Errorf("刷新後被撤銷裝置狀態應為 revoked，實際 %v", stateByID[firstDevice])
	}
	if stateByID[secondDevice] != "active" {
		t.Errorf("當前裝置狀態應為 active，實際 %v", stateByID[secondDevice])
	}

	again := postJSON(t, env.ts, deviceRevokePath, `{"device_id":"`+firstDevice+`"}`, "",
		map[string]string{"Cookie": secondCookie})
	if again.StatusCode != http.StatusOK {
		t.Fatalf("重複撤銷應 200，實際 %d", again.StatusCode)
	}
	if decodeJSONBody(t, again)["revoked"] != false {
		t.Error("重複撤銷不得再回報 revoked=true")
	}
}

// TestLiveRevokeCurrentDeviceEndsSession 撤自己這臺：Web 下發刪除指令、舊 Cookie 立即失效。
func TestLiveRevokeCurrentDeviceEndsSession(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "dev_self", "correct-pass")
	login := postJSON(t, env.ts, "/auth/login", `{"login_name":"dev_self","password":"correct-pass"}`, "", nil)
	cookie := sessionCookieName + "=" + loginCookie(t, login).Value
	thisDevice := decodeJSONBody(t, login)["device_id"].(string)

	revoke := postJSON(t, env.ts, deviceRevokePath, `{"device_id":"`+thisDevice+`"}`, "",
		map[string]string{"Cookie": cookie})
	if revoke.StatusCode != http.StatusOK {
		t.Fatalf("撤銷當前裝置應 200，實際 %d", revoke.StatusCode)
	}
	if decodeJSONBody(t, revoke)["current"] != true {
		t.Error("撤銷自己這臺應標 current=true")
	}
	if !hasClearingCookie(revoke) {
		t.Error("撤銷當前裝置（Web）必須下發刪除指令")
	}
	assertCodeStatus(t, getAuth(t, env.ts, "/auth/session", cookie, "", ""),
		CodeSessionInvalid, http.StatusUnauthorized)
}

// TestLiveDevicesIsolatedAcrossAccounts 跨帳戶隔離：甲列不出、也撤不掉乙的裝置（2009）。
func TestLiveDevicesIsolatedAcrossAccounts(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "iso_a", "correct-pass")
	env.liveAccount(t, "iso_b", "correct-pass")
	a := postJSON(t, env.ts, "/auth/login", `{"login_name":"iso_a","password":"correct-pass"}`, "", nil)
	b := postJSON(t, env.ts, "/auth/login", `{"login_name":"iso_b","password":"correct-pass"}`, "", nil)
	aCookie := sessionCookieName + "=" + loginCookie(t, a).Value
	bCookie := sessionCookieName + "=" + loginCookie(t, b).Value
	bDevice := decodeJSONBody(t, b)["device_id"].(string)

	items, _ := decodeDevices(t, getAuth(t, env.ts, devicesPath, aCookie, "", ""))
	if len(items) != 1 {
		t.Fatalf("甲只該看到自己一臺，實際 %d", len(items))
	}
	if items[0]["device_id"] == bDevice {
		t.Error("甲的清單不得出現乙的裝置")
	}
	resp := postJSON(t, env.ts, deviceRevokePath, `{"device_id":"`+bDevice+`"}`, "",
		map[string]string{"Cookie": aCookie})
	assertCodeStatus(t, resp, CodeDeviceNotFound, http.StatusNotFound)
	if got := getAuth(t, env.ts, "/auth/session", bCookie, "", ""); got.StatusCode != http.StatusOK {
		t.Error("越權撤銷嘗試不得動到乙的會話")
	}
}

// TestRootManagesOwnDevicesViaSamePath Root 用同一條受信主體通路管理自己的裝置。
func TestRootManagesOwnDevicesViaSamePath(t *testing.T) {
	env := newLiveEnv(t, "root-口令-e2e")
	r1 := postJSON(t, env.ts, "/auth/root/login", `{"password":"root-口令-e2e"}`, "", nil)
	r2 := postJSON(t, env.ts, "/auth/root/login", `{"password":"root-口令-e2e"}`, "", nil)
	c1 := sessionCookieName + "=" + loginCookie(t, r1).Value
	c2 := sessionCookieName + "=" + loginCookie(t, r2).Value
	d1 := decodeJSONBody(t, r1)["device_id"].(string)

	items, _ := decodeDevices(t, getAuth(t, env.ts, devicesPath, c2, "", ""))
	if len(items) != 2 {
		t.Fatalf("Root 兩臺都該在列，實際 %d", len(items))
	}
	revoke := postJSON(t, env.ts, deviceRevokePath, `{"device_id":"`+d1+`"}`, "",
		map[string]string{"Cookie": c2})
	if revoke.StatusCode != http.StatusOK {
		t.Fatalf("Root 撤銷裝置應 200，實際 %d", revoke.StatusCode)
	}
	assertCodeStatus(t, getAuth(t, env.ts, "/auth/session", c1, "", ""),
		CodeSessionInvalid, http.StatusUnauthorized)
	if got := getAuth(t, env.ts, "/auth/session", c2, "", ""); got.StatusCode != http.StatusOK {
		t.Error("未撤銷的另一臺 Root 會話不應受牽連")
	}
	var auditCount int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action='auth.device_revoke'").Scan(&auditCount); err != nil {
		t.Fatalf("統計審計失敗：%v", err)
	}
	if auditCount != 1 {
		t.Errorf("Root 撤銷裝置應留 1 筆 auth.device_revoke，實際 %d", auditCount)
	}
}

// assertSingleCurrentDevice 釘住清單裡恰好一枚 current，且為指定裝置。
func assertSingleCurrentDevice(t *testing.T, items []map[string]any, wantDevice string) {
	t.Helper()
	var currentIDs []any
	for _, m := range items {
		if m["current"] == true {
			currentIDs = append(currentIDs, m["device_id"])
		}
	}
	if len(currentIDs) != 1 {
		t.Fatalf("清單必須恰好一枚 current，實際 %d 枚", len(currentIDs))
	}
	if currentIDs[0] != wantDevice {
		t.Errorf("current 應指向當前請求的裝置 %s，實際 %v", wantDevice, currentIDs[0])
	}
}
