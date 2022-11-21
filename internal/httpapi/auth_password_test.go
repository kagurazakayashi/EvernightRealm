package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// 這一檔釘住本人改密在傳輸層的形態與「首次登入必須改密」的服務端門禁：
//   * CSRF→憑據解析→用例的關卡順序沿用既有端點同一族，映射各是各的結論；
//   * 現行口令不對 2001 且不發刪除指令（會話還活著）；表單問題 1004；
//     部署形態／存儲故障 500；成功 200＋Web 刪除指令＋revoked_sessions；
//   * 帶旗標的帳戶只準碰 /auth/session、改密與登出，其餘已認證端點一律 2010——
//     這是服務端的門，不是界面的一句提示；
//   * 登入與當前會話回應帶出現行旗標（false 時欄位缺席），客戶端才有單一依據。
//
// 端到端部分走真實 auth.Service＋SQLite：改密後舊 Cookie 立即失效、
// 舊口令登不進去、新口令登入後門禁消失，全部是跨層接線的現場證據。

// pwCookie 產生帶會話 Cookie 的標頭（值本身是測試專屬假字串，不是任何憑據）。
func pwCookie(value string) map[string]string {
	return map[string]string{"Cookie": sessionCookieName + "=" + value}
}

// TestPasswordChangeOriginGuard 跨站來源（Origin 不符或 Sec-Fetch-Site 宣告跨站）
// 在碰到任何用例之前就被擋下——Web 強制改密攻擊的第一道閘。
func TestPasswordChangeOriginGuard(t *testing.T) {
	out := testOutcome(t)
	fake := &fakeAuth{resolveFn: resolveOK(out)}
	ts := authTestServer(t, fake, nil)

	resp := postJSON(t, ts, "/auth/password/change", `{"current_password":"a","new_password":"b"}`, "http://evil.example", nil)
	assertCodeStatus(t, resp, CodeOriginForbidden, http.StatusForbidden)
	resp = postJSON(t, ts, "/auth/password/change", `{"current_password":"a","new_password":"b"}`, "",
		map[string]string{"Sec-Fetch-Site": "cross-site"})
	assertCodeStatus(t, resp, CodeOriginForbidden, http.StatusForbidden)
	if fake.lastChange.current != "" {
		t.Error("被來源閘擋下的請求不該觸碰用例")
	}
}

// TestPasswordChangeCredentialStatuses 憑據解析的各檔結論沿用既有合同，不另造一套。
func TestPasswordChangeCredentialStatuses(t *testing.T) {
	const body = `{"current_password":"a","new_password":"b"}`
	t.Run("未帶憑據 2002", func(t *testing.T) {
		out := testOutcome(t)
		fake := &fakeAuth{resolveFn: resolveOK(out)}
		ts := authTestServer(t, fake, nil)
		resp := postJSON(t, ts, "/auth/password/change", body, "", nil)
		assertCodeStatus(t, resp, CodeNotAuthenticated, http.StatusUnauthorized)
	})
	t.Run("失效憑據 2003 附刪除指令", func(t *testing.T) {
		fake := &fakeAuth{} // resolveFn 未設定：一律 ErrInvalidSession
		ts := authTestServer(t, fake, nil)
		resp := postJSON(t, ts, "/auth/password/change", body, "", pwCookie("dead-secret"))
		assertCodeStatus(t, resp, CodeSessionInvalid, http.StatusUnauthorized)
		if !hasClearingCookie(resp) {
			t.Error("失效 Cookie 應順帶下發刪除指令")
		}
	})
	t.Run("上一代憑據 2007 不發刪除指令", func(t *testing.T) {
		fake := &fakeAuth{resolveFn: resolveErr(auth.ErrStaleSession)}
		ts := authTestServer(t, fake, nil)
		resp := postJSON(t, ts, "/auth/password/change", body, "", pwCookie("stale-secret"))
		assertCodeStatus(t, resp, CodeSessionStale, http.StatusUnauthorized)
		if hasClearingCookie(resp) {
			t.Error("2007 刻意不發刪除指令（見 resolveSession 註解）")
		}
	})
	t.Run("混用認證方式 2004", func(t *testing.T) {
		out := testOutcome(t)
		fake := &fakeAuth{resolveFn: resolveOK(out)}
		ts := authTestServer(t, fake, nil)
		reqHeaders := pwCookie("x")
		reqHeaders["Authorization"] = "Bearer y"
		resp := postJSON(t, ts, "/auth/password/change", body, "", reqHeaders)
		assertCodeStatus(t, resp, CodeAuthMethodConflict, http.StatusBadRequest)
	})
}

// TestPasswordChangeBodyShape 請求本體只準帶現行口令與新口令：未知欄位與畸形 JSON 都喫 1004。
func TestPasswordChangeBodyShape(t *testing.T) {
	out := testOutcome(t)
	fake := &fakeAuth{
		resolveFn: resolveOK(out),
		changeFn: func(identity.Principal, string, string) (auth.PasswordChangeResult, error) {
			t.Error("形狀不合格的請求不該觸碰改密用例")
			return auth.PasswordChangeResult{}, nil
		},
	}
	ts := authTestServer(t, fake, nil)
	for name, body := range map[string]string{
		"帶 account_id": `{"current_password":"a","new_password":"b","account_id":"whatever"}`,
		"空本體":          ``,
		"非物件":          `[1]`,
	} {
		resp := postJSON(t, ts, "/auth/password/change", body, "", pwCookie("pw"))
		raw := readAll(t, resp)
		if env := decodeEnvelopeFrom(t, raw); env.Code != CodeInvalidBody {
			t.Errorf("%s：應 1004，實際 %d（%s）", name, env.Code, raw)
		}
	}
}

// TestPasswordChangeErrorMapping 用例結論到對外回應的對映（含「2001 不發刪除指令」）。
func TestPasswordChangeErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		changeErr  error
		wantCode   ErrorCode
		wantStatus int
		wantReason string
	}{
		{"現行口令不對", auth.ErrInvalidCredentials, CodeInvalidCredentials, http.StatusUnauthorized, ""},
		{"新口令等於現行", auth.ErrSamePassword, CodeInvalidBody, http.StatusBadRequest, "same_as_current"},
		{"新口令形狀不合格", auth.ErrInvalidNewPassword, CodeInvalidBody, http.StatusBadRequest, ""},
		{"部署不接受覆寫", auth.ErrRootCredentialLocked, CodeUnknown, http.StatusInternalServerError, ""},
		{"存儲故障", context.DeadlineExceeded, CodeUnknown, http.StatusInternalServerError, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := testOutcome(t)
			fake := &fakeAuth{
				resolveFn: resolveOK(out),
				changeErr: tc.changeErr,
			}
			ts := authTestServer(t, fake, nil)
			resp := postJSON(t, ts, "/auth/password/change", `{"current_password":"cur","new_password":"new"}`, "", pwCookie("pw"))
			raw := readAll(t, resp)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("狀態碼 %d，期望 %d（%s）", resp.StatusCode, tc.wantStatus, raw)
			}
			env := decodeEnvelopeFrom(t, raw)
			if env.Code != tc.wantCode {
				t.Errorf("機器碼 %d，期望 %d", env.Code, tc.wantCode)
			}
			if hasClearingCookie(resp) {
				t.Error("失敗路徑不該下發刪除指令（會話仍有效或變更未發生）")
			}
			if tc.wantReason != "" {
				if reason, ok := env.Details["reason"].(string); !ok || reason != tc.wantReason {
					t.Errorf("同口令失敗應帶可公開的判定依據，實際 %+v", env.Details)
				}
			}
		})
	}
}

// TestPasswordChangeSuccessShape 成功形態：200＋revoked_sessions＋Web 刪除指令；
// 原生（Bearer）路徑不發 Cookie；本體不含任何口令或憑據回顯。
func TestPasswordChangeSuccessShape(t *testing.T) {
	out := testOutcome(t)
	fake := &fakeAuth{
		resolveFn: resolveOK(out),
		changeFn: func(identity.Principal, string, string) (auth.PasswordChangeResult, error) {
			return auth.PasswordChangeResult{RevokedSessions: 3}, nil
		},
	}
	ts := authTestServer(t, fake, nil)

	resp := postJSON(t, ts, "/auth/password/change", `{"current_password":"cur","new_password":"new"}`, "", pwCookie("pw-cookie"))
	raw := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("應 200，實際 %d %s", resp.StatusCode, raw)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("解析回應失敗：%v", err)
	}
	if got, ok := payload["revoked_sessions"].(float64); !ok || got != 3 {
		t.Errorf("revoked_sessions 不正確：%+v", payload)
	}
	if _, ok := payload["request_id"].(string); !ok {
		t.Error("回應應帶請求關聯 ID")
	}
	if strings.Contains(string(raw), "cur") && strings.Contains(string(raw), "new") {
		// 「cur」「new」是本次專屬假字串；回應本體若同時出現兩者等於回顯了口令欄位。
		t.Errorf("回應不該回顯口令欄位：%s", raw)
	}
	if !hasClearingCookie(resp) {
		t.Error("改密已讓本會話失效，Web 路徑必須下發刪除指令")
	}
	if fake.lastChange.current != "cur" || fake.lastChange.newPassword != "new" {
		t.Error("端點應把請求本體原樣交進用例")
	}

	// 原生路徑：Bearer、無 Origin——秘密由客戶端自管，伺服器不發無意義的 Cookie。
	reqHeaders := map[string]string{"Authorization": "Bearer pw-native-secret"}
	resp = postJSON(t, ts, "/auth/password/change", `{"current_password":"cur","new_password":"new"}`, "", reqHeaders)
	raw = readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("原生路徑應 200，實際 %d %s", resp.StatusCode, raw)
	}
	if len(resp.Cookies()) != 0 {
		t.Errorf("原生路徑不該出現 Set-Cookie：%+v", resp.Cookies())
	}
}

// TestMustChangeGateAllowsOnlyNecessaryEntries 帶旗標的帳戶：改密、登出、當前會話照用；
// 輪換與裝置端點一律 2010。閘查在用例之前——被擋的請求不該觸碰任何寫入。
func TestMustChangeGateAllowsOnlyNecessaryEntries(t *testing.T) {
	var devicesCalled, rotateCalled, revokeCalled bool
	out := testOutcome(t)
	fake := &fakeAuth{
		resolveFn:  resolveOK(out),
		mustChange: true,
		devicesFn: func(identity.Principal) ([]session.Session, error) {
			devicesCalled = true
			return nil, nil
		},
		rotateFn: func(string) (auth.Outcome, error) {
			rotateCalled = true
			return auth.Outcome{}, nil
		},
		revokeFn: func(identity.Principal, idgen.ID) (auth.DeviceRevokeResult, error) {
			revokeCalled = true
			return auth.DeviceRevokeResult{}, nil
		},
		changeFn: func(identity.Principal, string, string) (auth.PasswordChangeResult, error) {
			return auth.PasswordChangeResult{RevokedSessions: 1}, nil
		},
	}
	ts := authTestServer(t, fake, nil)

	assertCodeStatus(t, getAuth(t, ts, devicesPath, sessionCookieName+"=pw", "", ""), CodePasswordChangeRequired, http.StatusForbidden)
	assertCodeStatus(t, postJSON(t, ts, "/auth/session/rotate", `{}`, "", pwCookie("pw")),
		CodePasswordChangeRequired, http.StatusForbidden)
	assertCodeStatus(t, postJSON(t, ts, deviceRevokePath, `{"device_id":"does-not-matter"}`, "", pwCookie("pw")),
		CodePasswordChangeRequired, http.StatusForbidden)
	if devicesCalled || rotateCalled || revokeCalled {
		t.Error("被門禁擋下的請求不該觸碰用例")
	}

	// 必要入口保持可用：/auth/session 帶著旗標回 200，logout 與改密不經閘。
	resp := getAuth(t, ts, "/auth/session", sessionCookieName+"=pw", "", "")
	body := decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/auth/session 必須永遠可讀（旗標的得知入口），實際 %d", resp.StatusCode)
	}
	if body["must_change_password"] != true {
		t.Errorf("當前會話回應應帶出旗標：%+v", body)
	}
	resp = postJSON(t, ts, "/auth/logout", `{}`, "", pwCookie("pw"))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("退出是必要入口，應 200，實際 %d", resp.StatusCode)
	}
	resp = postJSON(t, ts, "/auth/password/change", `{"current_password":"cur","new_password":"new"}`, "", pwCookie("pw"))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("改密本身就是出口，應 200，實際 %d", resp.StatusCode)
	}
}

// TestMustChangeGateReadFailureIs500 「查不出旗標」既不放行也不冒充 2010：內部故障照報。
func TestMustChangeGateReadFailureIs500(t *testing.T) {
	out := testOutcome(t)
	fake := &fakeAuth{
		resolveFn: resolveOK(out),
		mustChangeFn: func(identity.Principal) (bool, error) {
			return false, context.DeadlineExceeded
		},
	}
	ts := authTestServer(t, fake, nil)
	assertCodeStatus(t, getAuth(t, ts, devicesPath, sessionCookieName+"=pw", "", ""), CodeUnknown, http.StatusInternalServerError)
	assertCodeStatus(t, getAuth(t, ts, "/auth/session", sessionCookieName+"=pw", "", ""), CodeUnknown, http.StatusInternalServerError)
}

// TestMustChangeFlagInAuthResponses 合同演進只增不刪：登入回應在旗標為 false
// 時欄位缺席（舊客戶端逐字兼容），為 true 時必然出現。
func TestMustChangeFlagInAuthResponses(t *testing.T) {
	fake := &fakeAuth{}
	out := testOutcome(t)
	out.MustChangePassword = true
	fake.outcome = out
	ts := authTestServer(t, fake, nil)

	resp := postJSON(t, ts, "/auth/login", `{"login_name":"u","password":"p"}`, "", nil)
	raw := readAll(t, resp)
	if !strings.Contains(string(raw), `"must_change_password":true`) {
		t.Errorf("登入回應應帶出旗標：%s", raw)
	}

	fake.outcome.MustChangePassword = false
	resp = postJSON(t, ts, "/auth/login", `{"login_name":"u","password":"p"}`, "", nil)
	raw = readAll(t, resp)
	if strings.Contains(string(raw), "must_change_password") {
		t.Errorf("旗標為 false 時欄位應缺席：%s", raw)
	}
}

// TestPasswordChangeRequiredMessagesCoverAllLocales 四語言齊備 2010，且互不相同。
func TestPasswordChangeRequiredMessagesCoverAllLocales(t *testing.T) {
	messages := errorMessages[CodePasswordChangeRequired]
	seen := map[string]bool{}
	for _, locale := range []string{LocaleZhCN, LocaleZhTW, LocaleEnUS, LocaleJaJP} {
		text := strings.TrimSpace(messages[locale])
		if text == "" {
			t.Errorf("2010 缺少 %s 文案", locale)
		}
		if seen[text] {
			t.Errorf("2010 的多語言文案不得雷同（%s）", locale)
		}
		seen[text] = true
	}
}

// TestCodePasswordChangeRequiredIsNewAndStable 機器碼發布合同：2010 是新值且不得漂移。
func TestCodePasswordChangeRequiredIsNewAndStable(t *testing.T) {
	if int(CodePasswordChangeRequired) != 2010 {
		t.Errorf("2010 一經發布數值不得變動，實際 %d", CodePasswordChangeRequired)
	}
	for _, other := range []ErrorCode{CodeDeviceNotFound, CodeDeviceLimitReached, CodeSessionStale, CodeLoginThrottled} {
		if other == CodePasswordChangeRequired {
			t.Errorf("2010 不得與既有機器碼 %d 重用", other)
		}
	}
}

// —— 端到端：真實用例＋SQLite 上的完整循環與 Root 部署形態的誠實拒絕。——

// TestLivePasswordChangeFirstLoginLoop 首次改密的完整現實路徑：
// 登入（帶旗標）→ 受保護端點被 2010 擋 → 改密（錯口令 2001、同口令 1004、成功 200）
// → 舊 Cookie 立即失效 → 舊口令登不進去 → 新口令登入後旗標與門禁一起消失。
func TestLivePasswordChangeFirstLoginLoop(t *testing.T) {
	env := newLiveEnv(t, "")
	const initialPassword = "e2e-initial-pass"
	const newerPassword = "e2e-newer-pass"
	hash, err := credential.Hash(initialPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	if _, err := env.accounts.Create(context.Background(), env.db.SQL(), account.NewInput{
		LoginName: "e2e_pw", DisplayName: "端到端改密帳戶", PasswordHash: hash,
		Type: account.TypeStandard, Status: account.StatusActive, MustChangePassword: true,
	}); err != nil {
		t.Fatalf("建立帳戶失敗：%v", err)
	}

	resp := postJSON(t, env.ts, "/auth/login", `{"login_name":"e2e_pw","password":"`+initialPassword+`"}`, "", nil)
	raw := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("旗標帳戶應能登入：%d %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), `"must_change_password":true`) {
		t.Fatalf("登入回應應帶出旗標：%s", raw)
	}
	secret := loginCookie(t, resp).Value

	// 受保護端點被擋（403＋2010）；必要入口 /auth/session 仍 200 並帶著旗標。
	assertCodeStatus(t, getAuth(t, env.ts, devicesPath, sessionCookieName+"="+secret, "", ""),
		CodePasswordChangeRequired, http.StatusForbidden)
	reportResp := env.sessionWithCookie(t, secret)
	if reportResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(reportResp.Body)
		t.Fatalf("當前會話不應被旗標擋：%d %s", reportResp.StatusCode, body)
	}

	// 改密的三種失敗與一種成功。
	assertCodeStatus(t, postJSON(t, env.ts, "/auth/password/change",
		`{"current_password":"錯的","new_password":"`+newerPassword+`"}`, "", pwCookie(secret)),
		CodeInvalidCredentials, http.StatusUnauthorized)
	assertCodeStatus(t, postJSON(t, env.ts, "/auth/password/change",
		`{"current_password":"`+initialPassword+`","new_password":"`+initialPassword+`"}`, "", pwCookie(secret)),
		CodeInvalidBody, http.StatusBadRequest)
	changeResp := postJSON(t, env.ts, "/auth/password/change",
		`{"current_password":"`+initialPassword+`","new_password":"`+newerPassword+`"}`, "", pwCookie(secret))
	raw = readAll(t, changeResp)
	if changeResp.StatusCode != http.StatusOK {
		t.Fatalf("改密應成功：%d %s", changeResp.StatusCode, raw)
	}
	if !hasClearingCookie(changeResp) {
		t.Error("Web 路徑成功後應下發刪除指令")
	}

	// 舊憑據立即換不出身份；舊口令登入被拒；新口令登入後旗標與門禁一起消失。
	assertCodeStatus(t, getAuth(t, env.ts, "/auth/session", sessionCookieName+"="+secret, "", ""),
		CodeSessionInvalid, http.StatusUnauthorized)
	assertCodeStatus(t, postJSON(t, env.ts, "/auth/login",
		`{"login_name":"e2e_pw","password":"`+initialPassword+`"}`, "", nil),
		CodeInvalidCredentials, http.StatusUnauthorized)
	reLogin := postJSON(t, env.ts, "/auth/login",
		`{"login_name":"e2e_pw","password":"`+newerPassword+`"}`, "", nil)
	raw = readAll(t, reLogin)
	if reLogin.StatusCode != http.StatusOK {
		t.Fatalf("新口令應可登入：%d %s", reLogin.StatusCode, raw)
	}
	if strings.Contains(string(raw), "must_change_password") {
		t.Errorf("改密後登入回應不應再帶旗標欄位：%s", raw)
	}
	newSecret := loginCookie(t, reLogin).Value
	resp = getAuth(t, env.ts, devicesPath, sessionCookieName+"="+newSecret, "", "")
	raw = readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("還清義務後裝置端點應放行：%d %s", resp.StatusCode, raw)
	}
}

// TestLivePasswordChangeRootLocked 未接配置寫入通路（靜態快照）的部署形態：
// 現行口令校驗照常（錯口令得 2001），正確口令下則是誠實的 500——
// 「發了 Root 會話但無處換口令」不能被說成改密成功。
func TestLivePasswordChangeRootLocked(t *testing.T) {
	const rootPassword = "e2e-root-pass"
	env := newLiveEnv(t, rootPassword)
	resp := postJSON(t, env.ts, "/auth/root/login", `{"password":"`+rootPassword+`"}`, "", nil)
	raw := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Root 登入應成功：%d %s", resp.StatusCode, raw)
	}
	secret := loginCookie(t, resp).Value

	assertCodeStatus(t, postJSON(t, env.ts, "/auth/password/change",
		`{"current_password":"錯的","new_password":"x"}`, "", pwCookie(secret)),
		CodeInvalidCredentials, http.StatusUnauthorized)
	resp = postJSON(t, env.ts, "/auth/password/change",
		`{"current_password":"`+rootPassword+`","new_password":"新的口令"}`, "", pwCookie(secret))
	raw = readAll(t, resp)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("不可覆寫的部署應 500，實際 %d %s", resp.StatusCode, raw)
	}
	// Root 會話不受牽連（失敗發生在任何寫入之前）。
	if reportResp := env.sessionWithCookie(t, secret); reportResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(reportResp.Body)
		t.Errorf("被拒的改密不該動到會話：%d %s", reportResp.StatusCode, body)
	}
}

// TestLivePasswordChangeDoesNotTouchOtherSubjects 改密只動本人：另一帳戶的會話與
// 口令完全不受牽連（主體範圍由解析決定，請求沒有任何欄位能指定「改誰」）。
func TestLivePasswordChangeDoesNotTouchOtherSubjects(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "pw_a", "pass-a")
	env.liveAccount(t, "pw_b", "pass-b")
	secretA := env.login(t, "pw_a", "pass-a")
	secretB := env.login(t, "pw_b", "pass-b")

	resp := postJSON(t, env.ts, "/auth/password/change",
		`{"current_password":"pass-a","new_password":"pass-a2"}`, "", pwCookie(secretA))
	raw := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("A 改密應成功：%d %s", resp.StatusCode, raw)
	}
	// B 的會話照活、B 的口令照登。
	if respB := env.sessionWithCookie(t, secretB); respB.StatusCode != http.StatusOK {
		t.Errorf("B 的會話不該受 A 改密牽連，實際 %d", respB.StatusCode)
	}
	resp = postJSON(t, env.ts, "/auth/login", `{"login_name":"pw_b","password":"pass-b"}`, "", nil)
	readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("B 的口令不該被換掉，實際 %d", resp.StatusCode)
	}
}
