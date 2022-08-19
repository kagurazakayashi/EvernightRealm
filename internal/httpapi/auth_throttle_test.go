package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// auth_throttle_test.go 釘住限流在傳輸層的三件事：
// 機器碼 2006 與 HTTP 429 的對映、Retry-After 的取整、
// 以及「來源位址只取實際連線、轉發標頭一概不進用例」。

func TestLoginThrottledMapsTo429WithRetryAfter(t *testing.T) {
	fake := &fakeAuth{loginErr: &auth.ThrottledError{RetryAfter: 90200 * time.Millisecond}}
	ts := authTestServer(t, fake, nil)

	resp := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"b"}`, "", nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("限流回應應為 429，實際 %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "91" {
		t.Fatalf("Retry-After 應向上取整為 91 秒，實際 %q", got)
	}
	body := decodeJSONBody(t, resp)
	if code, ok := body["code"].(float64); !ok || int(code) != 2006 {
		t.Fatalf("機器碼應為 2006，實際 %#v", body["code"])
	}
	// 信封只有固定三欄：限流回應不得出現 details 或任何指出「誰被鎖」的欄位。
	for _, field := range [3]string{"code", "message", "request_id"} {
		if _, ok := body[field]; !ok {
			t.Fatalf("回應缺少信封欄位 %s：%#v", field, body)
		}
	}
	if len(body) != 3 {
		t.Fatalf("限流回應不得帶信封之外的欄位：%#v", body)
	}
	if msg, ok := body["message"].(string); !ok || msg == "" {
		t.Fatalf("message 應為非空在地化文案：%#v", body["message"])
	}
}

func TestLoginThrottledRetryAfterMinimumOneSecond(t *testing.T) {
	// 不足一秒的尾巴報 1 秒：報 0 會被讀成「立刻再試」，與冷卻尚未結束的事實矛盾。
	fake := &fakeAuth{loginErr: &auth.ThrottledError{RetryAfter: 120 * time.Millisecond}}
	ts := authTestServer(t, fake, nil)

	resp := postJSON(t, ts, "/auth/root/login", `{"password":"x"}`, "", nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("應為 429，實際 %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After 下限應為 1 秒，實際 %q", got)
	}
}

func TestLoginThrottledMessageIsLocalized(t *testing.T) {
	fake := &fakeAuth{loginErr: &auth.ThrottledError{RetryAfter: time.Minute}}
	ts := authTestServer(t, fake, nil)

	want := map[string]string{
		"zh-CN": "登录尝试过多，请稍后再试。",
		"zh-TW": "登入嘗試次數過多，請稍後再試。",
		"en-US": "Too many login attempts. Please try again later.",
		"ja-JP": "ログイン試行回数が多すぎます。しばらくしてからもう一度お試しください。",
	}
	for locale, expected := range want {
		resp := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"b"}`, "",
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

func TestLoginSourceIsConnectionAddressNotForwardedHeaders(t *testing.T) {
	// 沒有可信代理約定，就沒有資格替別人宣稱來源：三個常見轉發標頭全部不得進入用例。
	fake := &fakeAuth{outcome: testOutcome(t)}
	ts := authTestServer(t, fake, nil)

	resp := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"b"}`, "", map[string]string{
		"X-Forwarded-For": "8.8.8.8, 9.9.9.9",
		"X-Real-IP":       "7.7.7.7",
		"Forwarded":       "for=6.6.6.6",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("應正常放行，實際 %d", resp.StatusCode)
	}
	// httptest 用戶端與服務端同機：實際連線位址恆為 127.0.0.1，與標頭宣稱無關。
	if fake.lastIP != "127.0.0.1" {
		t.Fatalf("來源必須取實際連線位址，實際交了 %q", fake.lastIP)
	}

	fakeRoot := &fakeAuth{outcome: testOutcome(t)}
	tsRoot := authTestServer(t, fakeRoot, nil)
	if resp := postJSON(t, tsRoot, "/auth/root/login", `{"password":"b"}`, "",
		map[string]string{"X-Forwarded-For": "8.8.8.8"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("Root 端點應正常放行，實際 %d", resp.StatusCode)
	}
	if fakeRoot.lastIP != "127.0.0.1" {
		t.Fatalf("Root 端點來源必須取實際連線位址，實際交了 %q", fakeRoot.lastIP)
	}
}

func TestThrottledLoginDoesNotSetSessionCookie(t *testing.T) {
	fake := &fakeAuth{loginErr: &auth.ThrottledError{RetryAfter: time.Minute}}
	ts := authTestServer(t, fake, nil)

	resp := postJSON(t, ts, "/auth/login", `{"login_name":"a","password":"b"}`, "", nil)
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			t.Fatalf("限流回應不得簽發會話 Cookie：%v", c)
		}
	}
	if got := resp.Header.Get(cacheControlHeader); got != "no-store" {
		t.Fatalf("限流回應仍須 no-store，實際 %q", got)
	}
}

// countLiveSessions 統計會話行數（端到端「被擋零簽發」斷言用）。
func countLiveSessions(t *testing.T, db *database.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sessions").Scan(&n); err != nil {
		t.Fatalf("統計會話失敗：%v", err)
	}
	return n
}

// TestThrottleEndToEndIndistinguishable 走真實用例＋真實庫：
// 「未知帳戶被打滿」與「真帳戶被打滿」的 429 回應逐字同形（除 request_id），
// 而且被擋的嘗試不再觸碰任何簽發通路。這是限流不可枚舉性的端到端證據。
// 守衛用真實系統時鐘：冷卻 15 分鐘在測試生命週期內不會自然到期，
// 「到期恢復」的語意已由 internal/auth 的注入時鐘測試釘住，這裡不重複。
func TestThrottleEndToEndIndistinguishable(t *testing.T) {
	guard, err := auth.NewLoginGuard(auth.GuardConfig{FailLimit: 2, SourceFailLimit: 10}, timeutil.System())
	if err != nil {
		t.Fatalf("建立守衛失敗：%v", err)
	}
	e := newLiveEnvGuarded(t, "", guard)
	e.liveAccount(t, "throttle_live", "throttle-live-口令")

	for _, login := range [2]string{"throttle_no_such_account", "throttle_live"} {
		for i := 0; i < 2; i++ {
			resp := postJSON(t, e.ts, "/auth/login", `{"login_name":"`+login+`","password":"錯口令"}`, "", nil)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s 第 %d 次應為 401/2001，實際 %d", login, i+1, resp.StatusCode)
			}
		}
	}

	// 兩個目標此刻都在冷卻：回應形態必須逐字一致。
	var bodies [2]map[string]any
	for idx, login := range [2]string{"throttle_no_such_account", "throttle_live"} {
		resp := postJSON(t, e.ts, "/auth/login", `{"login_name":"`+login+`","password":"anything"}`, "", nil)
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("%s 應被限流 429，實際 %d", login, resp.StatusCode)
		}
		if resp.Header.Get("Retry-After") == "" {
			t.Fatal("429 必須附 Retry-After")
		}
		bodies[idx] = decodeJSONBody(t, resp)
	}
	delete(bodies[0], "request_id")
	delete(bodies[1], "request_id")
	if !jsonEnvelopeEqual(bodies[0], bodies[1]) {
		t.Fatalf("未知與已知帳戶的限流回應必須逐字同形：%#v vs %#v", bodies[0], bodies[1])
	}

	// 冷卻中的正確口令也拿不到會話：sessions 表不因被擋嘗試而增長。
	before := countLiveSessions(t, e.db)
	resp := postJSON(t, e.ts, "/auth/login", `{"login_name":"throttle_live","password":"throttle-live-口令"}`, "", nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("冷卻中正確口令應被擋，實際 %d", resp.StatusCode)
	}
	if after := countLiveSessions(t, e.db); after != before {
		t.Fatalf("被擋嘗試不得簽發會話（%d → %d）", before, after)
	}
}

// jsonEnvelopeEqual 以重新編碼比較兩個錯誤信封（map 序無關）。
func jsonEnvelopeEqual(a, b map[string]any) bool {
	ja, ea := json.Marshal(a)
	jb, eb := json.Marshal(b)
	if ea != nil || eb != nil {
		return false
	}
	// map 的 json.Marshal 按鍵排序，逐字比較即等值比較。
	return string(ja) == string(jb)
}
