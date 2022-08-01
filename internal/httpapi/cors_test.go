package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
)

// corsTestServer 以指定跨域組態建出完整路由樹（與正式路徑同一中介層鏈）。
func corsTestServer(t *testing.T, mutate func(*config.Config)) *httptest.Server {
	t.Helper()
	cfg := config.Default()
	if mutate != nil {
		mutate(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("測試組態不合法: %v", err)
	}
	srv := New(&cfg, testVersion, Deps{})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// allowOrigins 放行指定來源，其餘方法與標頭沿用預設清單。
func allowOrigins(origins ...string) func(*config.Config) {
	return func(c *config.Config) { c.Security.CORS.AllowedOrigins = origins }
}

// doWithOrigin 送一個可帶 Origin 與額外標頭的請求。
func doWithOrigin(t *testing.T, ts *httptest.Server, method, path, origin string, extra map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("建立請求失敗: %v", err)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for name, value := range extra {
		req.Header.Set(name, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s 失敗: %v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// assertEnvelopeCode 檢查統一錯誤信封的機器碼與關聯 ID。
func assertEnvelopeCode(t *testing.T, resp *http.Response, want ErrorCode) {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	var env ErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("回應應為錯誤信封，實際 %q", body)
	}
	if env.Code != want {
		t.Errorf("機器碼應為 %d，實際 %d（%s）", want, env.Code, body)
	}
	if env.RequestID == "" {
		t.Error("信封應帶 request_id")
	}
}

func TestCORSDisabledByDefault(t *testing.T) {
	// 本步的驗收條件之一：開發設定不會無條件進入正式組態。
	// 預設（未列來源）時，即使請求明顯來自別的頁面，也不得出現任何跨域標頭。
	ts := corsTestServer(t, nil)
	for _, path := range []string{"/health", "/time", "/no-such-path"} {
		resp := doWithOrigin(t, ts, http.MethodGet, path, "http://evil.example", nil)
		for _, name := range []string{
			accessControlAllowOrigin, accessControlAllowCredentials,
			accessControlAllowMethods, accessControlAllowHeaders, accessControlExposeHeaders,
		} {
			if got := resp.Header.Get(name); got != "" {
				t.Errorf("%s 在跨域關閉時不應帶 %s，實際 %q", path, name, got)
			}
		}
		if resp.StatusCode != http.StatusOK && path != "/no-such-path" {
			t.Errorf("%s 應照常回應 200，實際 %d", path, resp.StatusCode)
		}
	}
}

func TestCORSSameOriginRequestGetsNoCORSHeaders(t *testing.T) {
	// 同源請求不帶 Origin；開了白名單也不該因此多出跨域標頭。
	ts := corsTestServer(t, allowOrigins("http://127.0.0.1:8765"))
	resp := doWithOrigin(t, ts, http.MethodGet, "/health", "", nil)
	if got := resp.Header.Get(accessControlAllowOrigin); got != "" {
		t.Errorf("無 Origin 的請求不應帶跨域標頭，實際 %q", got)
	}
	if got := resp.Header.Get(varyHeader); strings.Contains(got, "Origin") {
		t.Errorf("無 Origin 時不需要 Vary: Origin，實際 %q", got)
	}
}

func TestCORSExactOriginIsEchoedOnErrorResponses(t *testing.T) {
	ts := corsTestServer(t, allowOrigins("http://127.0.0.1:8765"))
	cases := []struct {
		name   string
		method string
		path   string
		status int
	}{
		{"存活檢查", http.MethodGet, "/health", http.StatusOK},
		{"未知路徑", http.MethodGet, "/no-such-path", http.StatusNotFound},
		{"方法不允許", http.MethodPost, "/health", http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doWithOrigin(t, ts, tc.method, tc.path, "http://127.0.0.1:8765", nil)
			if resp.StatusCode != tc.status {
				t.Fatalf("狀態碼應為 %d，實際 %d", tc.status, resp.StatusCode)
			}
			if got := resp.Header.Get(accessControlAllowOrigin); got != "http://127.0.0.1:8765" {
				t.Errorf("ACAO 應反射放行來源，實際 %q", got)
			}
			if got := resp.Header.Get(varyHeader); !strings.Contains(got, "Origin") {
				t.Errorf("必須帶 Vary: Origin 以免快取污染，實際 %q", got)
			}
			if tc.method == http.MethodGet {
				// 暴露清單讓客戶端腳本讀得到 X-Request-Id（關聯 ID 是排錯依據）。
				if got := resp.Header.Get(accessControlExposeHeaders); !strings.Contains(got, "X-Request-Id") {
					t.Errorf("應暴露 X-Request-Id，實際 %q", got)
				}
			}
		})
	}
}

func TestCORSUnlistedOriginReceivesNothing(t *testing.T) {
	ts := corsTestServer(t, allowOrigins("http://127.0.0.1:8765"))
	resp := doWithOrigin(t, ts, http.MethodGet, "/health", "http://other.example", nil)
	if got := resp.Header.Get(accessControlAllowOrigin); got != "" {
		t.Errorf("未列來源不得取得 ACAO，實際 %q", got)
	}
	if got := resp.Header.Get(varyHeader); !strings.Contains(got, "Origin") {
		t.Errorf("未放行也要 Vary: Origin，否則快取會把拒絕結果給所有來源共用，實際 %q", got)
	}
	// 拒絕時也不透露「哪些來源被放行」——端點不該變成來源探測器。
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(strings.ToLower(string(body)), "8765") {
		t.Errorf("回應內文不得出現白名單來源：%s", body)
	}
}

func TestCORSWildcardAllowsAnyOrigin(t *testing.T) {
	ts := corsTestServer(t, allowOrigins("*"))
	resp := doWithOrigin(t, ts, http.MethodGet, "/time", "http://any.page.example", nil)
	if got := resp.Header.Get(accessControlAllowOrigin); got != "*" {
		t.Errorf("萬用來源應回 *，實際 %q", got)
	}
	if got := resp.Header.Get(accessControlAllowCredentials); got != "" {
		t.Errorf("萬用來源不得帶 Allow-Credentials，實際 %q", got)
	}
}

func TestCORSCredentialsReflectOrigin(t *testing.T) {
	ts := corsTestServer(t, func(c *config.Config) {
		c.Security.CORS.AllowedOrigins = []string{"http://127.0.0.1:8765"}
		c.Security.CORS.AllowCredentials = true
	})
	resp := doWithOrigin(t, ts, http.MethodGet, "/health", "http://127.0.0.1:8765", nil)
	if got := resp.Header.Get(accessControlAllowOrigin); got != "http://127.0.0.1:8765" {
		t.Errorf("憑據模式必須反射來源而非回 *，實際 %q", got)
	}
	if got := resp.Header.Get(accessControlAllowCredentials); got != "true" {
		t.Errorf("憑據模式應回 Allow-Credentials: true，實際 %q", got)
	}
}

func TestCORSPreflightAllowed(t *testing.T) {
	ts := corsTestServer(t, allowOrigins("http://127.0.0.1:8765"))
	resp := doWithOrigin(t, ts, http.MethodOptions, "/health", "http://127.0.0.1:8765", map[string]string{
		accessControlRequestMethod:      http.MethodGet,
		accessControlRequestHeadersName: "Idempotency-Key, X-Request-Id",
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("預檢應回 204，實際 %d", resp.StatusCode)
	}
	if got := resp.Header.Get(accessControlAllowMethods); !strings.Contains(got, "GET") {
		t.Errorf("預檢應帶 Allow-Methods，實際 %q", got)
	}
	got := resp.Header.Get(accessControlAllowHeaders)
	for _, want := range []string{"Idempotency-Key", "X-Request-Id"} {
		if !strings.Contains(got, want) {
			t.Errorf("預檢應回給客戶端它所請求的標頭 %s，實際 %q", want, got)
		}
	}
	if resp.Header.Get(accessControlMaxAge) == "" {
		t.Error("預檢應帶 Max-Age")
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("預檢不該有回應體，實際 %q", body)
	}
}

func TestCORSPreflightRejectsDisallowedMethodAndHeader(t *testing.T) {
	ts := corsTestServer(t, allowOrigins("http://127.0.0.1:8765"))
	t.Run("方法不放行", func(t *testing.T) {
		resp := doWithOrigin(t, ts, http.MethodOptions, "/health", "http://127.0.0.1:8765", map[string]string{
			accessControlRequestMethod: "DELETE",
		})
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("未放行的方法預檢應回 405，實際 %d", resp.StatusCode)
		}
		assertEnvelopeCode(t, resp, CodeMethodNotAllowed)
	})
	t.Run("標頭不放行", func(t *testing.T) {
		resp := doWithOrigin(t, ts, http.MethodOptions, "/health", "http://127.0.0.1:8765", map[string]string{
			accessControlRequestMethod:      http.MethodGet,
			accessControlRequestHeadersName: "X-Secret-Tool",
		})
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("未放行的標頭預檢應回 405，實際 %d", resp.StatusCode)
		}
		if got := resp.Header.Get(accessControlAllowHeaders); got != "" {
			t.Errorf("拒絕時不應回 Allow-Headers，實際 %q", got)
		}
	})
}

func TestCORSPreflightFromUnlistedOriginHasNoCORSHeaders(t *testing.T) {
	ts := corsTestServer(t, allowOrigins("http://127.0.0.1:8765"))
	resp := doWithOrigin(t, ts, http.MethodOptions, "/health", "http://evil.example", map[string]string{
		accessControlRequestMethod: http.MethodGet,
	})
	if got := resp.Header.Get(accessControlAllowOrigin); got != "" {
		t.Errorf("未放行來源的預檢不得帶 ACAO，實際 %q", got)
	}
	if got := resp.Header.Get(accessControlAllowMethods); got != "" {
		t.Errorf("未放行來源不該知道放行方法清單，實際 %q", got)
	}
}

func TestCORSNonPreflightOptionsKeepsRouterBehavior(t *testing.T) {
	// 只認瀏覽器預檢；一般 OPTIONS 仍由路由回 405（日後要自訂 OPTIONS 行為才改得動）。
	ts := corsTestServer(t, allowOrigins("http://127.0.0.1:8765"))
	resp := doWithOrigin(t, ts, http.MethodOptions, "/health", "http://127.0.0.1:8765", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("無 Access-Control-Request-Method 的 OPTIONS 應由路由處理為 405，實際 %d", resp.StatusCode)
	}
	assertEnvelopeCode(t, resp, CodeMethodNotAllowed)
}

func TestCORSPreflightStillCarriesRequestIDAndSecurityHeaders(t *testing.T) {
	// 跨域中介層在關聯 ID 之後、安全頭之內：預檢也要能在日誌裡對應到一筆請求，
	// 而且放寬跨域不能順帶把安全基線弄丟。
	ts := corsTestServer(t, allowOrigins("http://127.0.0.1:8765"))
	resp := doWithOrigin(t, ts, http.MethodOptions, "/health", "http://127.0.0.1:8765", map[string]string{
		accessControlRequestMethod: http.MethodGet,
	})
	if got := resp.Header.Get(requestIDHeader); got == "" {
		t.Error("預檢回應應帶 X-Request-Id")
	}
	if got := resp.Header.Get(contentSecurityPolicyHeader); got == "" {
		t.Error("預檢回應應帶安全回應頭")
	}
}
