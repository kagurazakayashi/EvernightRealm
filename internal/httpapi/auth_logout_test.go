package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// 這一檔把「登出必須讓服務端會話失效、而且要幂等」这条要求釘在兩個層面：
//   - 傳輸層（使用 fake 用例）：Cookie／Bearer 的解析复用与 /auth/session 同一入口，
//     有效會話→撤銷＋刪除指令；無憑據／憑據失效→幂等 2xx，不創建會話、
//     不叫使用者重新登入；混用／來源不合→對應錯誤碼且不觸及撤銷通路。
//   - 端到端（真實 auth.Service＋SQLite）：登出後舊秘密真的解析不出主體，
//     重複登出同一枚會話仍是 2xx、Root 域多出一筆 auth.logout 且不洩露秘密、
//     普通帳戶不進審計表。

// --- 傳輸層（fake）：解析、幂等與錯誤映射 ----------------------------------

// TestLogoutValidCookieClearsCookieAndRevokes：有效 Cookie → 撤銷會話＋Web 路徑下發刪除指令。
// 這是登出在瀏覽器形态的主路徑，删除指令屬性必須與簽發一致才能真的清掉同名 Cookie。
func TestLogoutValidCookieClearsCookieAndRevokes(t *testing.T) {
	outcome := testOutcome(t)
	var revokedPrincipal identity.Principal
	var revokedSession session.Session
	fake := &fakeAuth{
		resolveFn: func(secret string) (identity.Principal, session.Session, error) {
			if secret != outcome.Secret {
				return identity.Principal{}, session.Session{}, auth.ErrInvalidSession
			}
			return outcome.Principal, outcome.Session, nil
		},
		lastLogout: func(p identity.Principal, s session.Session) {
			revokedPrincipal, revokedSession = p, s
		},
	}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/logout", `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + outcome.Secret,
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("有效 Cookie 登出應 2xx，實際 %d %s", resp.StatusCode, body)
	}
	if revokedPrincipal.AccountID() != outcome.Principal.AccountID() {
		t.Errorf("撤銷收到的主體不符：%v", revokedPrincipal.AccountID())
	}
	if revokedSession.ID != outcome.Session.ID {
		t.Errorf("撤銷收到的會話不符：%v vs %v", revokedSession.ID, outcome.Session.ID)
	}
	assertCookieCleared(t, resp)
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("認證回應必禁快取，實際 %q", got)
	}
}

// TestLogoutNativeBearerRevokesNoCookie：原生 Bearer（無 Origin）→ 撤銷，但不發無意義的 Cookie。
func TestLogoutNativeBearerRevokesNoCookie(t *testing.T) {
	outcome := testOutcome(t)
	var logoutCalled bool
	fake := &fakeAuth{
		resolveFn: func(secret string) (identity.Principal, session.Session, error) {
			return outcome.Principal, outcome.Session, nil
		},
		lastLogout: func(_ identity.Principal, _ session.Session) { logoutCalled = true },
	}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/logout", `{}`, "", map[string]string{
		"Authorization": "Bearer " + outcome.Secret,
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("原生 Bearer 登出應 2xx，實際 %d %s", resp.StatusCode, body)
	}
	if !logoutCalled {
		t.Error("有效 Bearer 必須觸發撤銷")
	}
	if raw := resp.Header.Values("Set-Cookie"); len(raw) != 0 {
		t.Errorf("原生路徑不應下發 Cookie：%v", raw)
	}
}

// TestLogoutNoCredentialsIsIdempotentNoOp：完全沒帶憑據也是幂等成功——目標狀態
// 「這枚憑據換不出身份」本就成立，且必須根本不到達撤銷通路（不产生任何寫入）。
func TestLogoutNoCredentialsIsIdempotentNoOp(t *testing.T) {
	var logoutCalled bool
	fake := &fakeAuth{lastLogout: func(_ identity.Principal, _ session.Session) { logoutCalled = true }}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/logout", `{}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("無憑據登出應幂等 2xx，實際 %d %s", resp.StatusCode, body)
	}
	if logoutCalled {
		t.Error("無憑據不應呼叫撤銷用例")
	}
	got := decodeJSONBody(t, resp)
	if got["request_id"] == nil || got["request_id"] == "" {
		t.Errorf("登出回應至少要帶 request_id：%v", got)
	}
	// 幂等成功回應不携任何身分欄位（秘密不能進回應，身分也不能）。
	for _, k := range []string{"subject_kind", "account_id", "device_id", "expires_at"} {
		if _, ok := got[k]; ok {
			t.Errorf("登出回應不可帶 %s 欄位：%v", k, got)
		}
	}
}

// TestLogoutInvalidCookieIsIdempotentNoOp：帶了一枚已失效的秘密也是幂等 2xx，
// 但仍要順帶下發刪除指令把瀏覽器裡那枚爛 Cookie 清掉。
func TestLogoutInvalidCookieIsIdempotentNoOp(t *testing.T) {
	var logoutCalled bool
	fake := &fakeAuth{
		resolveFn: func(_ string) (identity.Principal, session.Session, error) {
			return identity.Principal{}, session.Session{}, auth.ErrInvalidSession
		},
		lastLogout: func(_ identity.Principal, _ session.Session) { logoutCalled = true },
	}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/logout", `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=stale-secret",
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("憑據失效登出應幂等 2xx（而不是 2003），實際 %d %s", resp.StatusCode, body)
	}
	if logoutCalled {
		t.Error("憑據失效不應呼叫撤銷用例")
	}
	assertCookieCleared(t, resp)
}

// TestLogoutMixedAuthMethodsRejected：Cookie＋Bearer 混用、或帶 Origin 的 Bearer 請求
// 一律 2004，且不到達撤銷通路——混用繞過來源校驗的那條路徑在登出上也不開。
func TestLogoutMixedAuthMethodsRejected(t *testing.T) {
	var logoutCalled bool
	fake := &fakeAuth{lastLogout: func(_ identity.Principal, _ session.Session) { logoutCalled = true }}
	ts := authTestServer(t, fake, nil)

	// Cookie + Bearer 並存。
	resp := postJSON(t, ts, "/auth/logout", `{}`, "", map[string]string{
		"Cookie":        sessionCookieName + "=abc",
		"Authorization": "Bearer abc",
	})
	assertEnvelopeCode(t, resp, CodeAuthMethodConflict)

	// 瀏覽器（任何 Origin）企圖用 Bearer。
	resp = postJSON(t, ts, "/auth/logout", `{}`, "http://evil.example", map[string]string{
		"Authorization": "Bearer abc",
	})
	assertEnvelopeCode(t, resp, CodeOriginForbidden)

	if logoutCalled {
		t.Error("被拒的登出請求不應觸及撤銷用例")
	}
}

// TestLogoutCrossSiteOriginRejected：異站 Origin 的登出先被來源策略擋下（2005），
// 不執行任何寫入——強制登出本身就是一種 CSRF 攻擊。
func TestLogoutCrossSiteOriginRejected(t *testing.T) {
	var logoutCalled bool
	var resolvedSecret string
	fake := &fakeAuth{
		resolveFn: func(secret string) (identity.Principal, session.Session, error) {
			resolvedSecret = secret
			return identity.Principal{}, session.Session{}, auth.ErrInvalidSession
		},
		lastLogout: func(_ identity.Principal, _ session.Session) { logoutCalled = true },
	}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/logout", `{}`, "http://evil.example", map[string]string{
		"Cookie": sessionCookieName + "=abc",
	})
	assertEnvelopeCode(t, resp, CodeOriginForbidden)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("來源拒絕應回 403，實際 %d", resp.StatusCode)
	}
	if resolvedSecret != "" || logoutCalled {
		t.Error("來源被拒時不可到達解析或撤銷")
	}
}

// TestLogoutSecFetchSiteCrossSiteRejected：Sec-Fetch-Site: cross-site 的登出請求同拒。
func TestLogoutSecFetchSiteCrossSiteRejected(t *testing.T) {
	fake := &fakeAuth{}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/logout", `{}`, "",
		map[string]string{"Sec-Fetch-Site": "cross-site", "Cookie": sessionCookieName + "=abc"})
	assertEnvelopeCode(t, resp, CodeOriginForbidden)
}

// TestLogoutInternalErrorIsRedacted：撤銷用例回非拒絕錯誤（資料庫故障）時一律 500，
// 細節只進伺服器端日誌，不洩到回應裡。
func TestLogoutInternalErrorIsRedacted(t *testing.T) {
	outcome := testOutcome(t)
	fake := &fakeAuth{
		resolveFn: func(_ string) (identity.Principal, session.Session, error) {
			return outcome.Principal, outcome.Session, nil
		},
		logoutErr: errors.New("internal: sqlite disk /var/lib/evernight/x blew up"),
	}
	ts := authTestServer(t, fake, nil)
	resp := postJSON(t, ts, "/auth/logout", `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + outcome.Secret,
	})
	assertEnvelopeCode(t, resp, CodeUnknown)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("撤銷失敗應回 500，實際 %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "sqlite") || strings.Contains(string(body), "evernight") {
		t.Errorf("500 回應不得洩内部錯链：%s", body)
	}
}

// --- 端到端（真實用例＋SQLite） ---------------------------------------------

// TestLogoutEndToEndRevokesSession：登入 → 登出 → 舊 Cookie 换不回身分，且舊 Bearer
// 同規（同一枚秘密在兩種通路下都被撤銷）。Cookie 刪除指令在登出回應中逐字带出。
func TestLogoutEndToEndRevokesSession(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "logout_e2e", "correct-pass")

	resp := postJSON(t, env.ts, "/auth/login", `{"login_name":"logout_e2e","password":"correct-pass"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("登入應成功：%d %s", resp.StatusCode, body)
	}
	cookie := loginCookie(t, resp)

	// 登出：Web 路徑带 Cookie，服务器应返回 2xx 与删除指令。
	out := postJSON(t, env.ts, "/auth/logout", `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + cookie.Value,
	})
	if out.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(out.Body)
		t.Fatalf("登出應 2xx，實際 %d %s", out.StatusCode, body)
	}
	assertCookieCleared(t, out)

	// 舊 Cookie 已換不出主體：/auth/session 401 與 2003。
	after := getAuth(t, env.ts, "/auth/session", sessionCookieName+"="+cookie.Value, "", "")
	assertEnvelopeCode(t, after, CodeSessionInvalid)

	// 舊秘密以 Bearer 也同樣解析失敗（同一枚會話行已被撤銷）。
	native := getAuth(t, env.ts, "/auth/session", "", cookie.Value, "")
	assertEnvelopeCode(t, native, CodeSessionInvalid)
}

// TestLogoutIsIdempotentEndToEnd：登出同一枚已被撤銷的憑據仍是 2xx，不創建任何新會話。
// 這是「重複退出不产生新的会话或不合理报错」在端到端上的直接断言。
func TestLogoutIsIdempotentEndToEnd(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "logout_idem", "correct-pass")

	resp := postJSON(t, env.ts, "/auth/login", `{"login_name":"logout_idem","password":"correct-pass"}`, "", nil)
	cookie := loginCookie(t, resp)
	first := listAllSessionIDs(t, env.db)
	if len(first) != 1 {
		t.Fatalf("前置應恰好一枚會話，實際 %d", len(first))
	}

	// 第一次登出：實際撤銷。
	one := postJSON(t, env.ts, "/auth/logout", `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + cookie.Value,
	})
	if one.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(one.Body)
		t.Fatalf("首次登出應 2xx，實際 %d %s", one.StatusCode, body)
	}

	// 重複登出（拿同一枚已失效的秘密再来一次）：幂等 2xx、不產生新會話。
	two := postJSON(t, env.ts, "/auth/logout", `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + cookie.Value,
	})
	if two.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(two.Body)
		t.Fatalf("重複登出應幂等 2xx（而不是 2003），實際 %d %s", two.StatusCode, body)
	}
	second := listAllSessionIDs(t, env.db)
	if len(second) != len(first) {
		t.Errorf("登出不得產生新會話：%d vs %d", len(first), len(second))
	}
}

// TestRootLogoutAuditsNoSecretLeak：Root 端到端登出落下 auth.logout 一筆審計，
// target_id 指向該會話，且 root_audit 任何一欄都不出現該次登出的會話秘密。
func TestRootLogoutAuditsNoSecretLeak(t *testing.T) {
	env := newLiveEnv(t, "登出-root-口令")
	resp := postJSON(t, env.ts, "/auth/root/login", `{"password":"登出-root-口令"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 登入應成功：%d %s", resp.StatusCode, body)
	}
	cookie := loginCookie(t, resp)
	out := postJSON(t, env.ts, "/auth/logout", `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + cookie.Value,
	})
	if out.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(out.Body)
		t.Fatalf("Root 登出應 2xx，實際 %d %s", out.StatusCode, body)
	}

	ctx := context.Background()
	var logoutCount int
	if err := env.db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM root_audit WHERE action = 'auth.logout'").Scan(&logoutCount); err != nil {
		t.Fatalf("統計登出審計失敗：%v", err)
	}
	if logoutCount != 1 {
		t.Errorf("Root 登出應留下恰好一筆 auth.logout，實際 %d", logoutCount)
	}

	// 審計的任何欄位都不得帶此次登出所使用的會話秘密明文。
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
			if strings.Contains(field, cookie.Value) {
				t.Errorf("審計欄位出會登出秘密：%s=%q", action, field)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍歷審計失敗：%v", err)
	}
}

// TestAccountLogoutWritesNoAudit：普通帳戶端到端登出後，root_audit 與 activity_audit
// 兩表都恒零——沿用 R1-009 已批准的判定。
func TestAccountLogoutWritesNoAudit(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "logout_acc_e2e", "correct-pass")
	resp := postJSON(t, env.ts, "/auth/login", `{"login_name":"logout_acc_e2e","password":"correct-pass"}`, "", nil)
	cookie := loginCookie(t, resp)
	out := postJSON(t, env.ts, "/auth/logout", `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + cookie.Value,
	})
	if out.StatusCode != http.StatusOK {
		t.Fatalf("帳戶登出應 2xx，實際 %d", out.StatusCode)
	}
	ctx := context.Background()
	for _, table := range []string{"root_audit", "activity_audit"} {
		var n int
		if err := env.db.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("統計 %s 失敗：%v", table, err)
		}
		if n != 0 {
			t.Errorf("普通帳戶登出不可寫入 %s（現有 %d 筆）", table, n)
		}
	}
}

// TestLoginAgainAfterLogout：登出後拿同一份口令再登一次，必須拿到一枚「新的」會話，
// 而且新會話可用、舊 Cookie 仍解析失敗——這釘住「退出之後重新登入是一趟乾脆的替換」，
// 不會出現「舊憑據在某个窗口内又能用」或「新登录复用了被撤銷的行」。
func TestLoginAgainAfterLogout(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "logout_relogin", "correct-pass")

	first := postJSON(t, env.ts, "/auth/login", `{"login_name":"logout_relogin","password":"correct-pass"}`, "", nil)
	firstCookie := loginCookie(t, first)
	out := postJSON(t, env.ts, "/auth/logout", `{}`, "", map[string]string{
		"Cookie": sessionCookieName + "=" + firstCookie.Value,
	})
	if out.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(out.Body)
		t.Fatalf("登出應 2xx，實際 %d %s", out.StatusCode, body)
	}

	// 舊 Cookie 仍然换不出身分。
	after := getAuth(t, env.ts, "/auth/session", sessionCookieName+"="+firstCookie.Value, "", "")
	assertEnvelopeCode(t, after, CodeSessionInvalid)

	// 重新登入：2xx + 一枚不同的新秘密 + 新 Cookie 立刻可用。
	second := postJSON(t, env.ts, "/auth/login", `{"login_name":"logout_relogin","password":"correct-pass"}`, "", nil)
	if second.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(second.Body)
		t.Fatalf("重新登入應成功：%d %s", second.StatusCode, body)
	}
	secondCookie := loginCookie(t, second)
	if secondCookie.Value == firstCookie.Value {
		t.Error("重新登入必須簽發新的會話秘密（不复用被撤銷的那一枚）")
	}
	check := getAuth(t, env.ts, "/auth/session", sessionCookieName+"="+secondCookie.Value, "", "")
	if check.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(check.Body)
		t.Fatalf("新 Cookie 應可用：%d %s", check.StatusCode, body)
	}
}

// TestLogoutMethodNotAllowed：登出端點只准 POST；GET 一律被 allowMethods 擋（405＋Allow）。
func TestLogoutMethodNotAllowed(t *testing.T) {
	outcome := testOutcome(t)
	fake := &fakeAuth{resolveFn: func(_ string) (identity.Principal, session.Session, error) {
		return outcome.Principal, outcome.Session, nil
	}}
	ts := authTestServer(t, fake, nil)
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/auth/logout", nil)
	if err != nil {
		t.Fatalf("建立請求失敗：%v", err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET 請求失敗：%v", err)
	}
	defer resp.Body.Close()
	assertEnvelopeCode(t, resp, CodeMethodNotAllowed)
	if resp.Header.Get("Allow") != http.MethodPost {
		t.Errorf("Allow 標頭應只列 POST，實際 %q", resp.Header.Get("Allow"))
	}
}

// --- 共用断言助手 ------------------------------------------------------------

// assertCookieCleared 檢查回應帶一枚同名同屬性的刪除指令（Max-Age<=0）；
// 與 TestSessionInvalidCookieClearsCookie 同判據，抽出來避免兩處各寫一份。
func assertCookieCleared(t *testing.T, resp *http.Response) {
	t.Helper()
	for _, raw := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(raw, sessionCookieName+"=") &&
			(strings.Contains(raw, "Max-Age=0") || strings.Contains(raw, "Max-Age=-1")) {
			if !strings.Contains(raw, "Path=/") || !strings.Contains(raw, "HttpOnly") || !strings.Contains(raw, "SameSite=Lax") {
				t.Errorf("刪除指令屬性須與簽發一致：%q", raw)
			}
			return
		}
	}
	t.Errorf("登出回應應附刪除指令（Max-Age<=0），實際 %v", resp.Header.Values("Set-Cookie"))
}
