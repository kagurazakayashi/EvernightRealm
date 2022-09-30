package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// 這一檔釘住輪換端點（POST /auth/session/rotate）的傳輸層合同與端到端事實：
//   - 傳輸層（fake 用例）：Cookie／Bearer 的解析複用與 /auth/session 同一入口，
//     來源策略、認證方式獨佔、方法限制與錯誤對映（2002／2003／2004／2005／2007／500）
//     各自可判，且「落後一代」不下發 Cookie 刪除指令；
//   - 端到端（真實 auth.Service＋SQLite＋完整中介層鏈）：換出的新秘密當場可用、
//     舊秘密立刻變成 2007、裝置身分與絕對期限不變、審計不含任何秘密、
//     已登出與已到期的會話輪換不了、用同一枚舊秘密連打兩次只有第一次成功。

// rotatePath 是輪換端點的路徑（本檔所有請求都打這裡）。
const rotatePath = "/auth/session/rotate"

// errRotateBoom 是「非拒絕類故障」的測試錯誤：它必須被對映成 500，
// 而不是被當成一種憑據拒絕（那會把伺服器故障說成「請重新登入」）。
var errRotateBoom = errors.New("rotate-test: 資料庫故障替身")

// rotateOutcome 在登入結果之上造一個「已輪換」的用例回傳：新秘密、世代號加一，
// 其餘欄位（會話標識、裝置標識、絕對期限）逐字不變——那正是輪換的語義。
func rotateOutcome(t *testing.T, base auth.Outcome, seq int64, newSecret string) auth.Outcome {
	t.Helper()
	rotated := base.Session
	rotated.RotationSeq = seq
	return auth.Outcome{Principal: base.Principal, Session: rotated, Secret: newSecret}
}

// readRotateBody 解出輪換回應本體（傳輸層測試用；端到端測試走 rotateResult）。
func readRotateBody(t *testing.T, resp *http.Response) rotateResponse {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取回應失敗：%v", err)
	}
	var out rotateResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("輪換回應不是合同內的 JSON：%v（%s）", err, body)
	}
	return out
}

// --- 傳輸層（fake 用例）：分發、來源策略與錯誤對映 -------------------------

// TestRotateValidCookieIssuesNewCookie：有效 Cookie → 換發新秘密並覆寫同名 Cookie，
// 回應本體只有可展示事實與世代號，秘密一個字都不出現在本體裡。
func TestRotateValidCookieIssuesNewCookie(t *testing.T) {
	base := testOutcome(t)
	const newSecret = "rotated-secret-should-only-live-in-cookie"
	fake := &fakeAuth{
		resolveFn: func(secret string) (identity.Principal, session.Session, error) {
			if secret != base.Secret {
				return identity.Principal{}, session.Session{}, auth.ErrInvalidSession
			}
			return base.Principal, base.Session, nil
		},
		rotateFn: func(secret string) (auth.Outcome, error) {
			return rotateOutcome(t, base, 1, newSecret), nil
		},
	}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, rotatePath, `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + base.Secret,
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("有效 Cookie 輪換應 200，實際 %d %s", resp.StatusCode, body)
	}
	if fake.lastRotate != base.Secret {
		t.Errorf("端點應把本請求帶來的憑據交給用例，實際 %q", fake.lastRotate)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取回應失敗：%v", err)
	}
	var body rotateResponse
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("輪換回應不是合同內的 JSON：%v（%s）", err, raw)
	}
	if body.RotationSeq != 1 {
		t.Errorf("回應應帶新世代號 1，實際 %d", body.RotationSeq)
	}
	if body.DeviceID != base.Session.DeviceID.String() {
		t.Errorf("回應的設備標識應與登入時相同：%s vs %s", body.DeviceID, base.Session.DeviceID)
	}
	if body.ExpiresAt == "" {
		t.Error("回應應帶絕對期限（輪換不改它，但客戶端要能對時）")
	}
	if strings.Contains(string(raw), newSecret) || strings.Contains(string(raw), base.Secret) {
		t.Error("輪換回應本體不得包含任何一枚會話秘密")
	}

	cookie := loginCookie(t, resp)
	if cookie.Value != newSecret {
		t.Error("Set-Cookie 應換成輪換後的新秘密")
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Errorf("輪換後的 Cookie 屬性必須與簽發時一致：%+v", cookie)
	}
	if cookie.MaxAge <= 0 {
		t.Errorf("輪換後的 Cookie 仍應帶正的 Max-Age，實際 %d", cookie.MaxAge)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("認證回應必禁快取，實際 %q", got)
	}
}

// TestRotateNativeBearerIssuesCookieHeader：原生路徑（無 Origin 的 Bearer）同樣從
// Set-Cookie 取回新秘密——這是既有的秘密分發合同，輪換不另開一條通路。
func TestRotateNativeBearerIssuesCookieHeader(t *testing.T) {
	base := testOutcome(t)
	const newSecret = "rotated-native-secret"
	fake := &fakeAuth{
		resolveFn: func(secret string) (identity.Principal, session.Session, error) {
			return base.Principal, base.Session, nil
		},
		rotateFn: func(secret string) (auth.Outcome, error) {
			return rotateOutcome(t, base, 3, newSecret), nil
		},
	}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, rotatePath, `{}`, "", map[string]string{
		"Authorization": "Bearer " + base.Secret,
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("原生 Bearer 輪換應 200，實際 %d %s", resp.StatusCode, body)
	}
	if got := loginCookie(t, resp).Value; got != newSecret {
		t.Error("原生客戶端應能從 Set-Cookie 讀到新秘密")
	}
	if got := readRotateBody(t, resp).RotationSeq; got != 3 {
		t.Errorf("世代號應為 3，實際 %d", got)
	}
}

// TestRotateStaleCredentialReturns2007WithoutDelete：落後一代 → 2007，
// 且刻意不發 Cookie 刪除指令（瀏覽器裡那枚可能已經是更新後的憑據）。
func TestRotateStaleCredentialReturns2007WithoutDelete(t *testing.T) {
	base := testOutcome(t)
	fake := &fakeAuth{
		resolveFn: func(secret string) (identity.Principal, session.Session, error) {
			return identity.Principal{}, session.Session{}, auth.ErrStaleSession
		},
	}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, rotatePath, `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + base.Secret,
	})
	envelope, _ := decodeEnvelope(t, resp)
	if resp.StatusCode != http.StatusUnauthorized || envelope.Code != CodeSessionStale {
		t.Errorf("落後一代應為 401/2007，實際 %d/%d", resp.StatusCode, envelope.Code)
	}
	if len(resp.Cookies()) != 0 {
		t.Errorf("落後一代不得下發任何 Cookie 指令，實際 %d 條", len(resp.Cookies()))
	}
}

// TestRotateInvalidCredentialReturns2003WithDelete：已失效憑據 → 2003＋刪除指令，
// 與 /auth/session 的處置逐字相同（同一個解析入口，不另寫一套）。
func TestRotateInvalidCredentialReturns2003WithDelete(t *testing.T) {
	fake := &fakeAuth{
		resolveFn: func(secret string) (identity.Principal, session.Session, error) {
			return identity.Principal{}, session.Session{}, auth.ErrInvalidSession
		},
	}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, rotatePath, `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=dead-secret",
	})
	envelope, _ := decodeEnvelope(t, resp)
	if resp.StatusCode != http.StatusUnauthorized || envelope.Code != CodeSessionInvalid {
		t.Errorf("失效憑據應為 401/2003，實際 %d/%d", resp.StatusCode, envelope.Code)
	}
	assertCookieCleared(t, resp)
}

// TestRotateUseCaseFailureAfterResolveMaps2003Or2007：解析透過但用例失敗時的兩條對映——
// 併發輸給另一次輪換（2007，不刪 Cookie）與解析後被撤銷（2003，Web 順帶刪除指令）。
func TestRotateUseCaseFailureAfterResolveMaps2003Or2007(t *testing.T) {
	base := testOutcome(t)
	cases := []struct {
		name       string
		err        error
		wantCode   ErrorCode
		wantDelete bool
	}{
		{"併發落後一代", auth.ErrStaleSession, CodeSessionStale, false},
		{"解析後被撤銷", auth.ErrInvalidSession, CodeSessionInvalid, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeAuth{
				resolveFn: func(secret string) (identity.Principal, session.Session, error) {
					return base.Principal, base.Session, nil
				},
				rotateFn: func(secret string) (auth.Outcome, error) {
					return auth.Outcome{}, tc.err
				},
			}
			ts := authTestServer(t, fake, nil)
			resp := postJSON(t, ts, rotatePath, `{}`, "", map[string]string{
				"Cookie": sessionCookieName + "=" + base.Secret,
			})
			envelope, _ := decodeEnvelope(t, resp)
			if resp.StatusCode != http.StatusUnauthorized || envelope.Code != tc.wantCode {
				t.Errorf("應為 401/%d，實際 %d/%d", tc.wantCode, resp.StatusCode, envelope.Code)
			}
			cleared := false
			for _, c := range resp.Cookies() {
				if c.Name == sessionCookieName && c.MaxAge < 0 {
					cleared = true
				}
			}
			if cleared != tc.wantDelete {
				t.Errorf("刪除指令應為 %t，實際 %t", tc.wantDelete, cleared)
			}
		})
	}
}

// TestRotateInternalFailureReturns500：非拒絕類故障（資料庫等）→ 500/1000，細節只進日誌。
func TestRotateInternalFailureReturns500(t *testing.T) {
	base := testOutcome(t)
	fake := &fakeAuth{
		resolveFn: func(secret string) (identity.Principal, session.Session, error) {
			return base.Principal, base.Session, nil
		},
		rotateErr: errRotateBoom,
	}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, rotatePath, `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + base.Secret,
	})
	envelope, _ := decodeEnvelope(t, resp)
	if resp.StatusCode != http.StatusInternalServerError || envelope.Code != CodeUnknown {
		t.Errorf("內部故障應為 500/1000，實際 %d/%d", resp.StatusCode, envelope.Code)
	}
}

// TestRotateGuardsRequestShape：無憑據 2002、混用 2004、瀏覽器帶 Bearer 2004、
// 跨站來源 2005（且用例根本不被呼叫）、方法不符 405。
func TestRotateGuardsRequestShape(t *testing.T) {
	base := testOutcome(t)
	newRotateFake := func(t *testing.T, called *bool) *fakeAuth {
		t.Helper()
		return &fakeAuth{
			resolveFn: func(secret string) (identity.Principal, session.Session, error) {
				return base.Principal, base.Session, nil
			},
			rotateFn: func(secret string) (auth.Outcome, error) {
				*called = true
				return rotateOutcome(t, base, 1, "should-not-be-reached"), nil
			},
		}
	}

	t.Run("無憑據", func(t *testing.T) {
		var called bool
		ts := authTestServer(t, newRotateFake(t, &called), nil)
		resp := postJSON(t, ts, rotatePath, `{}`, "", nil)
		envelope, _ := decodeEnvelope(t, resp)
		if resp.StatusCode != http.StatusUnauthorized || envelope.Code != CodeNotAuthenticated {
			t.Errorf("無憑據應為 401/2002，實際 %d/%d", resp.StatusCode, envelope.Code)
		}
		if called {
			t.Error("無憑據不得觸及輪換用例")
		}
	})

	t.Run("混用兩種認證方式", func(t *testing.T) {
		var called bool
		ts := authTestServer(t, newRotateFake(t, &called), nil)
		resp := postJSON(t, ts, rotatePath, `{}`, "", map[string]string{
			"Cookie":        sessionCookieName + "=" + base.Secret,
			"Authorization": "Bearer " + base.Secret,
		})
		envelope, _ := decodeEnvelope(t, resp)
		if resp.StatusCode != http.StatusBadRequest || envelope.Code != CodeAuthMethodConflict {
			t.Errorf("混用應為 400/2004，實際 %d/%d", resp.StatusCode, envelope.Code)
		}
		if called {
			t.Error("混用不得觸及輪換用例")
		}
	})

	t.Run("瀏覽器請求企圖用 Bearer", func(t *testing.T) {
		var called bool
		ts := authTestServer(t, newRotateFake(t, &called), nil)
		// 來源必須是同源：跨站來源會先被 CSRF 策略擋成 2005，測不到認證方式獨佔這條。
		resp := postJSON(t, ts, rotatePath, `{}`, ts.URL, map[string]string{
			"Authorization": "Bearer " + base.Secret,
		})
		envelope, _ := decodeEnvelope(t, resp)
		if resp.StatusCode != http.StatusBadRequest || envelope.Code != CodeAuthMethodConflict {
			t.Errorf("瀏覽器帶 Bearer 應為 400/2004，實際 %d/%d", resp.StatusCode, envelope.Code)
		}
		if called {
			t.Error("認證方式不符不得觸及輪換用例")
		}
	})

	t.Run("跨站來源", func(t *testing.T) {
		var called bool
		ts := authTestServer(t, newRotateFake(t, &called), nil)
		resp := postJSON(t, ts, rotatePath, `{}`, "http://evil.test", map[string]string{
			"Cookie":         sessionCookieName + "=" + base.Secret,
			"Sec-Fetch-Site": "cross-site",
		})
		envelope, _ := decodeEnvelope(t, resp)
		if resp.StatusCode != http.StatusForbidden || envelope.Code != CodeOriginForbidden {
			t.Errorf("跨站來源應為 403/2005，實際 %d/%d", resp.StatusCode, envelope.Code)
		}
		if called {
			t.Error("來源不合不得觸及輪換用例（CSRF 換密正是這條要擋的）")
		}
	})

	t.Run("方法不符", func(t *testing.T) {
		var called bool
		ts := authTestServer(t, newRotateFake(t, &called), nil)
		resp := getAuth(t, ts, rotatePath, sessionCookieName+"="+base.Secret, "", "")
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET 應為 405，實際 %d", resp.StatusCode)
		}
		if got := resp.Header.Get("Allow"); got != http.MethodPost {
			t.Errorf("405 應帶 Allow: POST，實際 %q", got)
		}
		if called {
			t.Error("方法不符不得觸及輪換用例")
		}
	})
}

// --- 端到端（真實用例＋SQLite＋完整中介層鏈） ------------------------------

// rotateResult 是一次輪換請求的完整結果：狀態、原始本體、解出的合同欄位，
// 以及 Set-Cookie 裡的新秘密。
//
// 做成一個值而不是讓每個用例各自讀 body：讀過一次的 Body 就沒了，
// 「本體不含秘密」與「本體符合合同」這兩條斷言必須看同一份位元組。
type rotateResult struct {
	status  int
	body    []byte
	report  rotateResponse
	secret  string
	cookies []*http.Cookie
}

// login 登一次，並把 Web 端拿到的會話秘密取回來。
func (e *liveEnv) login(t *testing.T, login, password string) string {
	t.Helper()
	resp := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+password+`"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("登入應成功：%d %s", resp.StatusCode, body)
	}
	return loginCookie(t, resp).Value
}

// rotateRaw 帶 Cookie 打一次輪換，不斷言狀態碼（失敗路徑也要看完整結果）。
func (e *liveEnv) rotateRaw(t *testing.T, secret string) rotateResult {
	t.Helper()
	resp := postJSON(t, e.ts, rotatePath, `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + secret,
	})
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取輪換回應失敗：%v", err)
	}
	out := rotateResult{status: resp.StatusCode, body: raw, cookies: resp.Cookies()}
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &out.report); err != nil {
			t.Fatalf("輪換回應不是合同內的 JSON：%v（%s）", err, raw)
		}
		for _, c := range out.cookies {
			if c.Name == sessionCookieName {
				out.secret = c.Value
			}
		}
	}
	return out
}

// rotate 打一次輪換並斷言成功，回傳完整結果。
func (e *liveEnv) rotate(t *testing.T, secret string) rotateResult {
	t.Helper()
	out := e.rotateRaw(t, secret)
	if out.status != http.StatusOK {
		t.Fatalf("輪換應 200，實際 %d %s", out.status, out.body)
	}
	if out.secret == "" {
		t.Fatal("輪換成功必須在 Set-Cookie 裡給出新秘密")
	}
	return out
}

// sessionReport 帶 Cookie 問一次 /auth/session 並解出合同欄位。
func (e *liveEnv) sessionReport(t *testing.T, secret string) sessionResponse {
	t.Helper()
	resp := getAuth(t, e.ts, "/auth/session", sessionCookieName+"="+secret, "", "")
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取會話回應失敗：%v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("會話應有效：%d %s", resp.StatusCode, raw)
	}
	var out sessionResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("會話回應不是合同內的 JSON：%v（%s）", err, raw)
	}
	return out
}

// sessionStatusWithBearer 以原生 Bearer 問一次 /auth/session，只回狀態碼。
func (e *liveEnv) sessionStatusWithBearer(t *testing.T, secret string) int {
	t.Helper()
	resp := getAuth(t, e.ts, "/auth/session", "", secret, "")
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	return resp.StatusCode
}

// sessionCodeWithCookie 以 Cookie 問一次 /auth/session，回狀態碼與完整回應。
func (e *liveEnv) sessionWithCookie(t *testing.T, secret string) *http.Response {
	t.Helper()
	return getAuth(t, e.ts, "/auth/session", sessionCookieName+"="+secret, "", "")
}

// countSessionRows 數會話行數：輪換是就地換代，不是新增一行。
func (e *liveEnv) countSessionRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM sessions").Scan(&n); err != nil {
		t.Fatalf("統計會話行數失敗：%v", err)
	}
	return n
}

// readRotationSeq 讀回庫裡那一行的世代號（前置要求恰好一行）。
func (e *liveEnv) readRotationSeq(t *testing.T) int64 {
	t.Helper()
	var seq int64
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT rotation_seq FROM sessions").Scan(&seq); err != nil {
		t.Fatalf("讀回世代號失敗：%v", err)
	}
	return seq
}

// TestRotateEndToEndCookieChain：登入 → 輪換 → 新秘密當場可用、舊秘密變 2007、
// 裝置身分與絕對期限不變、世代號在 /auth/session 上看得見。
func TestRotateEndToEndCookieChain(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "rotate_e2e", "correct-pass")
	old := env.login(t, "rotate_e2e", "correct-pass")

	before := env.sessionReport(t, old)
	res := env.rotate(t, old)

	if res.secret == old {
		t.Fatal("輪換必須換出一枚不同的新秘密")
	}
	if res.report.DeviceID != before.DeviceID {
		t.Errorf("輪換不得換掉設備身分：%s vs %s", res.report.DeviceID, before.DeviceID)
	}
	if res.report.ExpiresAt != before.ExpiresAt {
		t.Errorf("輪換不得延長絕對期限：%s vs %s", res.report.ExpiresAt, before.ExpiresAt)
	}
	if res.report.RotationSeq != 1 {
		t.Errorf("世代號應為 1，實際 %d", res.report.RotationSeq)
	}
	if strings.Contains(string(res.body), res.secret) || strings.Contains(string(res.body), old) {
		t.Error("輪換回應本體不得包含任何一枚會話秘密")
	}

	// 新秘密當場可用，而且 /auth/session 上看得見世代號與同一套可展示事實。
	after := env.sessionReport(t, res.secret)
	if after.RotationSeq != 1 {
		t.Errorf("/auth/session 應回報世代號 1，實際 %d", after.RotationSeq)
	}
	if after.DeviceID != before.DeviceID || after.ExpiresAt != before.ExpiresAt {
		t.Error("輪換前後的可展示事實（設備、期限）應逐字相同")
	}

	// 舊秘密：401/2007，而且不下發刪除指令（它不是「已失效」，只是「晚了」）。
	stale := env.sessionWithCookie(t, old)
	defer stale.Body.Close()
	envelope, _ := decodeEnvelope(t, stale)
	if stale.StatusCode != http.StatusUnauthorized || envelope.Code != CodeSessionStale {
		t.Errorf("舊秘密應為 401/2007，實際 %d/%d", stale.StatusCode, envelope.Code)
	}
	if len(stale.Cookies()) != 0 {
		t.Errorf("2007 不得下發 Cookie 指令，實際 %d 條", len(stale.Cookies()))
	}
}

// TestRotateEndToEndBearer：原生路徑端到端——從 Set-Cookie 讀新秘密，再以 Bearer 用它。
func TestRotateEndToEndBearer(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "rotate_bearer", "correct-pass")
	old := env.login(t, "rotate_bearer", "correct-pass")

	req, err := http.NewRequest(http.MethodPost, env.ts.URL+rotatePath, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("組裝請求失敗：%v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+old)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("發出請求失敗：%v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取回應失敗：%v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("原生 Bearer 輪換應 200，實際 %d %s", resp.StatusCode, raw)
	}
	var newSecret string
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			newSecret = c.Value
		}
	}
	if newSecret == "" || newSecret == old {
		t.Fatalf("原生客戶端應從 Set-Cookie 讀到新秘密，實際 %q", newSecret)
	}
	if strings.Contains(string(raw), newSecret) {
		t.Error("輪換回應本體不得包含新秘密")
	}
	if got := env.sessionStatusWithBearer(t, newSecret); got != http.StatusOK {
		t.Errorf("新秘密以 Bearer 問當前會話應 200，實際 %d", got)
	}
	if got := env.sessionStatusWithBearer(t, old); got != http.StatusUnauthorized {
		t.Errorf("舊秘密以 Bearer 問當前會話應 401，實際 %d", got)
	}
}

// TestRotateEndToEndSecondAttemptIsStale：用同一枚舊秘密連打兩次輪換——
// 第一次成功，第二次是 2007，庫裡只推進一格，也沒有第二枚新秘密被簽發。
func TestRotateEndToEndSecondAttemptIsStale(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "rotate_twice", "correct-pass")
	old := env.login(t, "rotate_twice", "correct-pass")

	first := env.rotate(t, old)
	second := env.rotateRaw(t, old)
	if second.status != http.StatusUnauthorized {
		t.Fatalf("第二次用舊秘密輪換應 401，實際 %d %s", second.status, second.body)
	}
	var envelope ErrorEnvelope
	if err := json.Unmarshal(second.body, &envelope); err != nil {
		t.Fatalf("錯誤回應不是合同內的 JSON：%v（%s）", err, second.body)
	}
	if envelope.Code != CodeSessionStale {
		t.Errorf("第二次用舊秘密輪換應為 2007，實際 %d", envelope.Code)
	}
	if len(second.cookies) != 0 {
		t.Errorf("被拒的輪換不得下發任何 Cookie，實際 %d 條", len(second.cookies))
	}
	if got := env.readRotationSeq(t); got != 1 {
		t.Errorf("庫內世代號應只推進到 1，實際 %d", got)
	}
	if got := env.countSessionRows(t); got != 1 {
		t.Errorf("輪換不得新增會話行，實際 %d 行", got)
	}
	// 第一次換出的那枚仍然是當代：併發輸家沒有把它弄壞。
	if got := env.sessionStatusWithBearer(t, first.secret); got != http.StatusOK {
		t.Errorf("當代秘密應仍然有效，實際 %d", got)
	}
}

// TestRotateEndToEndAfterLogout：已登出的會話輪換不了（2003＋刪除指令），
// 換密不是「把已撤銷的會話救回來」的通路。
func TestRotateEndToEndAfterLogout(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "rotate_after_logout", "correct-pass")
	secret := env.login(t, "rotate_after_logout", "correct-pass")
	if out := postJSON(t, env.ts, "/auth/logout", `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + secret,
	}); out.StatusCode != http.StatusOK {
		t.Fatalf("登出應 2xx，實際 %d", out.StatusCode)
	}

	res := env.rotateRaw(t, secret)
	if res.status != http.StatusUnauthorized {
		t.Fatalf("已撤銷會話輪換應 401，實際 %d %s", res.status, res.body)
	}
	var envelope ErrorEnvelope
	if err := json.Unmarshal(res.body, &envelope); err != nil {
		t.Fatalf("錯誤回應不是合同內的 JSON：%v（%s）", err, res.body)
	}
	if envelope.Code != CodeSessionInvalid {
		t.Errorf("已撤銷會話輪換應為 2003，實際 %d", envelope.Code)
	}
	cleared := false
	for _, c := range res.cookies {
		if c.Name == sessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("失效憑據應順帶下發 Cookie 刪除指令")
	}
	if got := env.countSessionRows(t); got != 1 {
		t.Errorf("輪換不得新增或刪除會話行，實際 %d 行", got)
	}
	if got := env.readRotationSeq(t); got != 0 {
		t.Errorf("被拒的輪換不得推進世代號，實際 %d", got)
	}
}

// TestRotateEndToEndExpired：已過絕對期限的會話輪換不了——輪換不是續期。
func TestRotateEndToEndExpired(t *testing.T) {
	env := newClockedLiveEnv(t, time.Hour, session.Policy{})
	env.liveAccount(t, "rotate_expired_e2e", "correct-pass")
	secret := env.login(t, "rotate_expired_e2e", "correct-pass")
	env.clock.Advance(time.Hour + time.Minute)

	resp := postJSON(t, env.ts, rotatePath, `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + secret,
	})
	defer resp.Body.Close()
	assertEnvelopeCode(t, resp, CodeSessionInvalid)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("已到期會話輪換應為 401，實際 %d", resp.StatusCode)
	}
	var seq int64
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT rotation_seq FROM sessions").Scan(&seq); err != nil {
		t.Fatalf("讀回世代號失敗：%v", err)
	}
	if seq != 0 {
		t.Errorf("被拒的輪換不得推進世代號，實際 %d", seq)
	}
}

// TestRotateEndToEndRootAuditHasNoSecret：Root 輪換留下恰好一筆 auth.rotate，
// target 指向該會話，且審計任何一欄都不出現新舊秘密。
func TestRotateEndToEndRootAuditHasNoSecret(t *testing.T) {
	env := newLiveEnv(t, "rotate-root-pass")
	resp := postJSON(t, env.ts, "/auth/root/login", `{"password":"rotate-root-pass"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 登入應成功：%d %s", resp.StatusCode, body)
	}
	old := loginCookie(t, resp).Value
	res := env.rotate(t, old)

	ctx := context.Background()
	var n int
	if err := env.db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM root_audit WHERE action = 'auth.rotate'").Scan(&n); err != nil {
		t.Fatalf("統計輪換審計失敗：%v", err)
	}
	if n != 1 {
		t.Errorf("Root 輪換應留下恰好一筆 auth.rotate，實際 %d", n)
	}
	rows, err := env.db.SQL().QueryContext(ctx,
		"SELECT action, target_kind, target_id, reason, request_id FROM root_audit")
	if err != nil {
		t.Fatalf("讀取審計失敗：%v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			action, targetKind, targetID, requestID string
			reason                                  sql.NullString
		)
		if err := rows.Scan(&action, &targetKind, &targetID, &reason, &requestID); err != nil {
			t.Fatalf("掃描審計失敗：%v", err)
		}
		for _, field := range []string{action, targetKind, targetID, reason.String, requestID} {
			if strings.Contains(field, old) || strings.Contains(field, res.secret) {
				t.Errorf("審計欄位洩露了會話秘密：%s=%q", action, field)
			}
		}
		if action == "auth.rotate" && targetID == "" {
			t.Error("輪換審計的 target 應指向該會話")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍歷審計失敗：%v", err)
	}
}

// TestRotateEndToEndAccountWritesNoAudit：普通帳戶的輪換不進任何審計表（既有批准的判定）。
func TestRotateEndToEndAccountWritesNoAudit(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "rotate_no_audit", "correct-pass")
	old := env.login(t, "rotate_no_audit", "correct-pass")
	env.rotate(t, old)

	ctx := context.Background()
	for _, table := range []string{"root_audit", "activity_audit"} {
		var n int
		if err := env.db.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("統計 %s 失敗：%v", table, err)
		}
		if n != 0 {
			t.Errorf("普通帳戶輪換不應寫 %s，實際 %d 筆", table, n)
		}
	}
}
