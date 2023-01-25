// rootadmins_reset_test.go 是「Root 重置管理員登入憑據」的傳輸層端到端證據：
// 真資料庫＋真用例＋完整中介層鏈，從重置落地、舊口令與舊會話死亡、
// 首次改密門閂生效，到越權與壞輸入「一個字都不寫」的形態。

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// adminTestResetPasswd 與第二把重置口令：只活在測試進程的記憶體。
const (
	adminTestResetPasswd  = "rootadmins-test-重置口令甲"
	adminTestResetPasswd2 = "rootadmins-test-重置口令乙"
)

// TestRootResetAdminPasswordEndToEndOverHTTP 走完整條重置時間線：
// Root 開人 → 目標以初始口令登入（兩臺）→ Root 重置 → 兩份舊會話即刻 401、
// 舊口令即刻 401 → 新口令登入且欠首次改密 → 2010 門閂生效 → 本人還清義務、
// 重置口令也死亡。這釘的是「重置複用了本人改密與門閂的既有機制」而不是另造一套。
func TestRootResetAdminPasswordEndToEndOverHTTP(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, rootCookie, "reset.e2e")
	cookieA := loginCookie(t, env.loginAs(t, "reset.e2e", adminTestInitialPasswd))
	cookieB := loginCookie(t, env.loginAs(t, "reset.e2e", adminTestInitialPasswd))

	passwordPath := "/root/admins/" + id + "/password"
	resp := putJSON(t, env.ts, passwordPath,
		`{"password":"`+adminTestResetPasswd+`"}`, env.ts.URL,
		map[string]string{"Cookie": cookieHeader(rootCookie)})
	if resp.StatusCode != http.StatusOK {
		text := readAllText(t, resp)
		t.Fatalf("重置應成功：%d %s", resp.StatusCode, text)
	}
	var reset adminPasswordResetResponse
	if err := json.NewDecoder(resp.Body).Decode(&reset); err != nil {
		t.Fatalf("解析重置回應失敗：%v", err)
	}
	if !reset.Admin.MustChangePassword || reset.Admin.Status != "active" {
		t.Errorf("重置後的現值應是 active 且欠首次改密，實際 %+v", reset.Admin)
	}
	if reset.RevokedSessions != 2 {
		t.Errorf("重置應回報撤銷了兩份會話，實際 %d", reset.RevokedSessions)
	}

	// 舊會話立即失效：兩份都換不出身分。
	for name, cookie := range map[string]*http.Cookie{"會話A": cookieA, "會話B": cookieB} {
		got := getAuth(t, env.ts, "/root/admins", cookieHeader(cookie), "", "")
		assertEnvelopeCode(t, got, CodeSessionInvalid)
		if got.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s 重置後應收到 401，實際 %d", name, got.StatusCode)
		}
	}
	// 舊口令徹底死亡，且與其餘憑據拒絕同形。
	assertEnvelopeCode(t, env.loginAs(t, "reset.e2e", adminTestInitialPasswd), CodeInvalidCredentials)

	// 新口令可登入，但帶回首改義務；門閂與本人改密那一步共用同一把閘。
	relogin := env.loginAs(t, "reset.e2e", adminTestResetPasswd)
	if relogin.StatusCode != http.StatusOK {
		text := readAllText(t, relogin)
		t.Fatalf("重置口令應能登入：%d %s", relogin.StatusCode, text)
	}
	facts := decodeJSONBody(t, relogin)
	if facts["must_change_password"] != true {
		t.Errorf("重置後首登應欠改密，實際 %v", facts)
	}
	adminCookie := loginCookie(t, relogin)
	gated := getAuth(t, env.ts, "/auth/devices", cookieHeader(adminCookie), "", "")
	assertEnvelopeCode(t, gated, CodePasswordChangeRequired)
	if still := getAuth(t, env.ts, "/auth/session", cookieHeader(adminCookie), "", ""); still.StatusCode != http.StatusOK {
		t.Errorf("/auth/session 不應被改密門閂擋下：%d", still.StatusCode)
	}

	// 本人還清義務：以重置口令換最終口令，成功後重置口令也死了。
	change := postJSON(t, env.ts, "/auth/password/change",
		`{"current_password":"`+adminTestResetPasswd+`","new_password":"`+adminTestChangedPasswd+`"}`,
		"", map[string]string{"Cookie": cookieHeader(adminCookie)})
	if change.StatusCode != http.StatusOK {
		text := readAllText(t, change)
		t.Fatalf("以重置口令完成首次改密應成功：%d %s", change.StatusCode, text)
	}
	assertEnvelopeCode(t, env.loginAs(t, "reset.e2e", adminTestResetPasswd), CodeInvalidCredentials)
	final := env.loginAs(t, "reset.e2e", adminTestChangedPasswd)
	if final.StatusCode != http.StatusOK {
		t.Fatalf("最終口令應能登入：%d", final.StatusCode)
	}
	if _, ok := decodeJSONBody(t, final)["must_change_password"]; ok {
		t.Error("義務清償後旗標欄位應缺席")
	}

	// 審計脱敏：任何口令明文與雜湊都不許出現。
	var changes, reason string
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT changes_json, reason FROM root_audit WHERE action = 'admin.password_reset'").
		Scan(&changes, &reason); err != nil {
		t.Fatalf("讀回重置審計失敗：%v", err)
	}
	for _, secret := range []string{adminTestInitialPasswd, adminTestResetPasswd,
		adminTestChangedPasswd, "argon2id", "password_hash", "login_name_key"} {
		if strings.Contains(changes, secret) || strings.Contains(reason, secret) {
			t.Errorf("重置審計不得含 %q 的影子", secret)
		}
	}
}

// TestResetAdminPasswordKeepsDisabledTargetDisabled 重置不是解除停用：
// 停用中的目標重置成功、現值仍 disabled 帶原時刻、新口令在停用期間仍登不進去；
// 之後由 status 通路恢復，新口令才生效、初始口令仍是死的。
func TestResetAdminPasswordKeepsDisabledTargetDisabled(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, rootCookie, "reset.dis")
	statusPath := "/root/admins/" + id + "/status"
	if resp := putJSON(t, env.ts, statusPath,
		`{"status":"disabled","expected_status":"active"}`, env.ts.URL,
		map[string]string{"Cookie": cookieHeader(rootCookie)}); resp.StatusCode != http.StatusOK {
		t.Fatalf("預先停用失敗：%d", resp.StatusCode)
	}
	detailBefore := readAllText(t, getAuth(t, env.ts, "/root/admins/"+id,
		cookieHeader(rootCookie), "", ""))

	resp := putJSON(t, env.ts, "/root/admins/"+id+"/password",
		`{"password":"`+adminTestResetPasswd+`"}`, env.ts.URL,
		map[string]string{"Cookie": cookieHeader(rootCookie)})
	if resp.StatusCode != http.StatusOK {
		text := readAllText(t, resp)
		t.Fatalf("對停用目標重置應成功：%d %s", resp.StatusCode, text)
	}
	var reset adminPasswordResetResponse
	if err := json.NewDecoder(resp.Body).Decode(&reset); err != nil {
		t.Fatalf("解析回應失敗：%v", err)
	}
	if reset.Admin.Status != "disabled" || reset.Admin.DisabledAt == "" {
		t.Errorf("重置回應必須如實回報仍停用且帶停用時刻，實際 %+v", reset.Admin)
	}
	if !strings.Contains(detailBefore, reset.Admin.DisabledAt) {
		t.Errorf("停用時刻不得被重置改寫（詳情 %s／回應 %s）", detailBefore, reset.Admin.DisabledAt)
	}
	if reset.RevokedSessions != 0 {
		t.Errorf("停用者沒有未撤銷的會話，重置應撤 0，實際 %d", reset.RevokedSessions)
	}
	// 停用期間新口令也登不進去（收斂到憑據無效同形，不洩露「口令對了只是人被停」）。
	assertEnvelopeCode(t, env.loginAs(t, "reset.dis", adminTestResetPasswd), CodeInvalidCredentials)

	// 恢復走正經通路；恢復後生效的是重置交付的口令，初始口令仍是死的。
	if resp := putJSON(t, env.ts, statusPath,
		`{"status":"active","expected_status":"disabled"}`, env.ts.URL,
		map[string]string{"Cookie": cookieHeader(rootCookie)}); resp.StatusCode != http.StatusOK {
		t.Fatalf("恢復失敗：%d", resp.StatusCode)
	}
	if resp := env.loginAs(t, "reset.dis", adminTestResetPasswd); resp.StatusCode != http.StatusOK {
		t.Errorf("恢復後重置口令應可登入：%d", resp.StatusCode)
	}
	assertEnvelopeCode(t, env.loginAs(t, "reset.dis", adminTestInitialPasswd), CodeInvalidCredentials)
}

// TestResetAdminPasswordInputAndAttackSurface 憑據子資源的輸入閘與攻擊面。
func TestResetAdminPasswordInputAndAttackSurface(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, rootCookie, "reset.input")
	snapshot := adminRowSnapshot(t, env.db, id)
	passwordPath := "/root/admins/" + id + "/password"

	// 空口令與缺欄位：1004；空口令那一個案例要點名 password。
	for name, body := range map[string]string{"空口令": `{"password":""}`, "缺口令欄位": `{}`} {
		resp := putJSON(t, env.ts, passwordPath, body, env.ts.URL,
			map[string]string{"Cookie": cookieHeader(rootCookie)})
		env2 := envelopeOf(t, resp)
		if env2.Code != CodeInvalidBody {
			t.Errorf("%s 應回 1004，實際 %d", name, env2.Code)
		}
	}
	// 空口令那一個案例還要點名欄位：處置是「改那一欄再打」，不是猜哪個欄位壞了。
	emptyResp := putJSON(t, env.ts, passwordPath, `{"password":""}`, env.ts.URL,
		map[string]string{"Cookie": cookieHeader(rootCookie)})
	if env2 := envelopeOf(t, emptyResp); env2.Details["invalid_field"] != "password" {
		t.Errorf("空口令應點名 password 欄位，實際 details %v", env2.Details)
	}
	// 未知欄位企圖：帶著狀態／依據值／旗標／身分欄位的重置全部拒殺。
	for name, body := range map[string]string{
		"順帶依據值":   `{"password":"x","expected_status":"active"}`,
		"順帶狀態":    `{"password":"x","status":"active"}`,
		"順帶免改密旗標": `{"password":"x","must_change_password":false}`,
		"自報標識":    `{"password":"x","account_id":"` + id + `"}`,
		"順帶改名":    `{"password":"x","display_name":"被順手改了"}`,
	} {
		resp := putJSON(t, env.ts, passwordPath, body, env.ts.URL,
			map[string]string{"Cookie": cookieHeader(rootCookie)})
		if code := envelopeOf(t, resp).Code; code != CodeInvalidBody {
			t.Errorf("%s：未知欄位企圖應被 1004 拒殺，實際 %d", name, code)
		}
	}
	// 跨站來源：先問來源，不問口令。
	resp := putJSON(t, env.ts, passwordPath, `{"password":"x"}`, "http://evil.example",
		map[string]string{"Cookie": cookieHeader(rootCookie)})
	assertEnvelopeCode(t, resp, CodeOriginForbidden)
	if got := adminRowSnapshot(t, env.db, id); got != snapshot {
		t.Error("被拒的重置請求不得動目標帳戶任何一欄")
	}
	var resets int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.password_reset'").Scan(&resets); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if resets != 0 {
		t.Errorf("被拒的重置不得留下審計，實際 %d 筆", resets)
	}

	// 標識形態與目錄外標識同回 1001：端點不是列舉探針。
	for name, path := range map[string]string{
		"格式不對": "/root/admins/not-a-uuid/password",
		"幽靈標識": "/root/admins/0192f0c4-1c9a-7c3e-9a1b-2f4d6e8a0b1c/password",
	} {
		resp := putJSON(t, env.ts, path, `{"password":"`+adminTestResetPasswd+`"}`,
			env.ts.URL, map[string]string{"Cookie": cookieHeader(rootCookie)})
		assertEnvelopeCode(t, resp, CodeNotFound)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s 應為 404，實際 %d", name, resp.StatusCode)
		}
	}
	env.livePlainAccount(t, "plain.ungranted", adminTestPlainPasswd)
	var plainID string
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT id FROM accounts WHERE login_name = ?", "plain.ungranted").Scan(&plainID); err != nil {
		t.Fatalf("讀普通帳戶標識失敗：%v", err)
	}
	resp = putJSON(t, env.ts, "/root/admins/"+plainID+"/password",
		`{"password":"`+adminTestResetPasswd+`"}`, env.ts.URL,
		map[string]string{"Cookie": cookieHeader(rootCookie)})
	assertEnvelopeCode(t, resp, CodeNotFound)

	// 方法分流：子資源只認 PUT；GET 落 405 且 Allow 如實。
	notAllowed := sendRaw(t, env.ts, http.MethodGet, passwordPath, rootCookie)
	assertEnvelopeCode(t, notAllowed, CodeMethodNotAllowed)
	if allow := notAllowed.Header.Get("Allow"); !strings.Contains(allow, http.MethodPut) {
		t.Errorf("405 的 Allow 應列出 PUT，實際 %q", allow)
	}
}

// TestResetAdminPasswordAuthorizationMatrix 重置只屬 Root：其他主體各自收到哪一句。
func TestResetAdminPasswordAuthorizationMatrix(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	victimID := createAdminViaAPI(t, env, rootCookie, "reset.victim")
	passwordPath := "/root/admins/" + victimID + "/password"
	snapshot := adminRowSnapshot(t, env.db, victimID)

	env.livePlainAccount(t, "plain.resetmatrix", adminTestPlainPasswd)
	plainCookie := loginCookie(t, env.loginAs(t, "plain.resetmatrix", adminTestPlainPasswd))

	createAdminViaAPI(t, env, rootCookie, "reset.peer2")
	peerCookie := loginCookie(t, env.loginAs(t, "reset.peer2", adminTestInitialPasswd))
	if resp := postJSON(t, env.ts, "/auth/password/change",
		`{"current_password":"`+adminTestInitialPasswd+`","new_password":"`+adminTestChangedPasswd+`"}`,
		"", map[string]string{"Cookie": cookieHeader(peerCookie)}); resp.StatusCode != http.StatusOK {
		t.Fatalf("同級管理員改密失敗：%d", resp.StatusCode)
	}
	peerCookie = loginCookie(t, env.loginAs(t, "reset.peer2", adminTestChangedPasswd))

	for name, cookie := range map[string]*http.Cookie{
		"普通帳戶":  plainCookie,
		"普通管理員": peerCookie,
	} {
		resp := putJSON(t, env.ts, passwordPath, `{"password":"`+adminTestResetPasswd+`"}`,
			env.ts.URL, map[string]string{"Cookie": cookieHeader(cookie)})
		assertEnvelopeCode(t, resp, CodePermissionDenied)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s 重置他人應為 403，實際 %d", name, resp.StatusCode)
		}
	}
	resp := putJSON(t, env.ts, passwordPath, `{"password":"`+adminTestResetPasswd+`"}`, "", nil)
	assertEnvelopeCode(t, resp, CodeNotAuthenticated)

	if got := adminRowSnapshot(t, env.db, victimID); got != snapshot {
		t.Error("被拒的越權重置不得動目標憑據")
	}
	var resets int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.password_reset'").Scan(&resets); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if resets != 0 {
		t.Errorf("被拒的重置不得寫入 Root 審計，實際 %d 筆", resets)
	}
}

// TestResetAdminPasswordRepeatOverHTTPBothAreWholeOperations 重複請求的批准語意（HTTP 面）：
// 第二次重置不是「陳舊嘗試被拒」，而是又做一次完整重置——它必須把第一次之後
// 新簽發的會話也撤掉，並留下第二筆審計；最終現值只認最後一次交付的口令。
// 界面據此不得在結果不明時自動重發（那會是真的又重置了一次）。
func TestResetAdminPasswordRepeatOverHTTPBothAreWholeOperations(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, rootCookie, "reset.repeat")
	passwordPath := "/root/admins/" + id + "/password"

	first := putJSON(t, env.ts, passwordPath, `{"password":"`+adminTestResetPasswd+`"}`,
		env.ts.URL, map[string]string{"Cookie": cookieHeader(rootCookie)})
	if first.StatusCode != http.StatusOK {
		text := readAllText(t, first)
		t.Fatalf("首次重置失敗：%d %s", first.StatusCode, text)
	}
	var firstReset adminPasswordResetResponse
	if err := json.NewDecoder(first.Body).Decode(&firstReset); err != nil {
		t.Fatalf("解析失敗：%v", err)
	}
	if firstReset.RevokedSessions != 0 {
		t.Errorf("首次重置前沒有任何有效會話，應撤 0，實際 %d", firstReset.RevokedSessions)
	}

	live := loginCookie(t, env.loginAs(t, "reset.repeat", adminTestResetPasswd))
	second := putJSON(t, env.ts, passwordPath, `{"password":"`+adminTestResetPasswd2+`"}`,
		env.ts.URL, map[string]string{"Cookie": cookieHeader(rootCookie)})
	if second.StatusCode != http.StatusOK {
		text := readAllText(t, second)
		t.Fatalf("第二次重置應成功（重複提交是又做一次，不是被拒）：%d %s", second.StatusCode, text)
	}
	var secondReset adminPasswordResetResponse
	if err := json.NewDecoder(second.Body).Decode(&secondReset); err != nil {
		t.Fatalf("解析失敗：%v", err)
	}
	if secondReset.RevokedSessions != 1 {
		t.Errorf("第二次重置應撤掉中間簽發的 1 份會話，實際 %d", secondReset.RevokedSessions)
	}
	assertEnvelopeCode(t, getAuth(t, env.ts, "/root/admins", cookieHeader(live), "", ""), CodeSessionInvalid)
	assertEnvelopeCode(t, env.loginAs(t, "reset.repeat", adminTestResetPasswd), CodeInvalidCredentials)
	if resp := env.loginAs(t, "reset.repeat", adminTestResetPasswd2); resp.StatusCode != http.StatusOK {
		t.Errorf("最後一次交付的口令應是唯一有效者：%d", resp.StatusCode)
	}
	var resets int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.password_reset'").Scan(&resets); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if resets != 2 {
		t.Errorf("兩次完整重置應各留一筆審計，實際 %d 筆", resets)
	}
}

// TestResetResponseNeverEchoesCredential 重置的成功回應原文不得含任何憑據材料：
// 交付只發生在請求那一側，回應把口令回顯一次就等於洩露一次。
func TestResetResponseNeverEchoesCredential(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, rootCookie, "reset.echo")
	text := readAllText(t, putJSON(t, env.ts, "/root/admins/"+id+"/password",
		`{"password":"`+adminTestResetPasswd+`"}`, env.ts.URL,
		map[string]string{"Cookie": cookieHeader(rootCookie)}))
	for _, forbidden := range []string{adminTestResetPasswd, adminTestInitialPasswd,
		"argon2id", "password_hash", "login_name_key"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("重置回應不得含 %q", forbidden)
		}
	}
}
