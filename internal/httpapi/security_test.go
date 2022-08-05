package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
)

// assertBaselineSecurityHeaders 檢查回應帶有內建基線安全標頭（非 TLS 連線不應有 HSTS）。
func assertBaselineSecurityHeaders(t *testing.T, resp *http.Response) {
	t.Helper()
	expected := map[string]string{
		contentSecurityPolicyHeader:    defaultCSP,
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              defaultFrameOptions,
		"Referrer-Policy":              defaultReferrerPolicy,
		"Permissions-Policy":           defaultPermissionsPolicy,
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	for name, want := range expected {
		if got := resp.Header.Get(name); got != want {
			t.Errorf("標頭 %s 應為 %q，實際 %q", name, want, got)
		}
	}
	if got := resp.Header.Get(hstsHeader); got != "" {
		t.Errorf("非 TLS 連線不應輸出 %s，實際 %q", hstsHeader, got)
	}
}

func TestSecurityHeadersOnSuccessAndErrorResponses(t *testing.T) {
	// 成功、404、405 皆經正式路由樹。
	ts := testServer(t)
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"存活檢查", http.MethodGet, "/health"},
		{"未知路徑", http.MethodGet, "/no-such-path"},
		{"方法不允許", http.MethodPost, "/health"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, ts.URL+tc.path, nil)
			if err != nil {
				t.Fatalf("建立請求失敗: %v", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("請求失敗: %v", err)
			}
			defer resp.Body.Close()
			assertBaselineSecurityHeaders(t, resp)
		})
	}

	// 輸入錯誤（415、413）與 panic（500）同樣必須帶標頭。
	t.Run("內容型別不受支援", func(t *testing.T) {
		jsonTS := newTestJSONServer(t, nil)
		resp := postBody(t, jsonTS.URL+"/json", "text/plain", `{"name":"a","count":1}`)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Fatalf("狀態碼應為 415，實際 %d", resp.StatusCode)
		}
		assertBaselineSecurityHeaders(t, resp)
	})

	t.Run("請求體超限", func(t *testing.T) {
		jsonTS := newTestJSONServer(t, func(cfg *config.Config) { cfg.Server.MaxBodyBytes = 64 })
		resp := postBody(t, jsonTS.URL+"/json", "application/json", `{"name":"`+strings.Repeat("a", 256)+`","count":1}`)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("狀態碼應為 413，實際 %d", resp.StatusCode)
		}
		assertBaselineSecurityHeaders(t, resp)
	})

	t.Run("panic 回應", func(t *testing.T) {
		cfg := config.Default()
		srv := New(&cfg, testVersion, Deps{})
		srv.logger = testLogger(io.Discard)
		mux := http.NewServeMux()
		mux.HandleFunc("/panic", func(http.ResponseWriter, *http.Request) { panic("boom") })
		panicTS := httptest.NewServer(srv.wrap(mux))
		defer panicTS.Close()

		resp, err := http.Get(panicTS.URL + "/panic")
		if err != nil {
			t.Fatalf("請求失敗: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("狀態碼應為 500，實際 %d", resp.StatusCode)
		}
		assertBaselineSecurityHeaders(t, resp)
	})
}

// parseCSPDirectives 將 CSP 標頭拆為指令 → 來源清單，供逐項斷言。
func parseCSPDirectives(t *testing.T, policy string) map[string][]string {
	t.Helper()
	directives := make(map[string][]string)
	for _, part := range strings.Split(policy, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		directives[fields[0]] = fields[1:]
	}
	return directives
}

func TestDefaultCSPIsNotWideOpen(t *testing.T) {
	if strings.Contains(defaultCSP, "'unsafe-eval'") {
		t.Error("CSP 不得包含 'unsafe-eval'")
	}
	if strings.Contains(defaultCSP, "*") {
		t.Error("CSP 不得包含 * 通配來源")
	}
	for _, scheme := range []string{"http:", "https:", "ws:", "wss:"} {
		if strings.Contains(defaultCSP, scheme) {
			t.Errorf("CSP 不得包含裸方案來源 %q（等同放行任意主機）", scheme)
		}
	}

	directives := parseCSPDirectives(t, defaultCSP)

	// 相容本機 Flutter Web 的必要指令：WASM 編譯、行內樣式、blob Worker、內嵌字型。
	for directive, wantSource := range map[string]string{
		"script-src":  "'wasm-unsafe-eval'",
		"style-src":   "'unsafe-inline'",
		"worker-src":  "blob:",
		"font-src":    "data:",
		"img-src":     "data:",
		"connect-src": "'self'",
	} {
		sources, ok := directives[directive]
		if !ok {
			t.Fatalf("CSP 缺少指令 %s", directive)
		}
		if !containsString(sources, wantSource) {
			t.Errorf("CSP 指令 %s 應含 %s，實際 %v", directive, wantSource, sources)
		}
	}

	// 腳本不得載入非 'self' 來源，也不得放行 data:/blob:（XSS 載體）。
	for _, source := range directives["script-src"] {
		if source != "'self'" && source != "'wasm-unsafe-eval'" {
			t.Errorf("script-src 不應允許來源 %q", source)
		}
	}

	for directive, wantSource := range map[string]string{
		"frame-ancestors": "'none'",
		"object-src":      "'none'",
		"base-uri":        "'self'",
		"form-action":     "'self'",
	} {
		if !containsString(directives[directive], wantSource) {
			t.Errorf("CSP 指令 %s 應為 %s，實際 %v", directive, wantSource, directives[directive])
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestPermissionsPolicyAllowsSameOriginCamera(t *testing.T) {
	// QR 掃碼需要相機；僅允許同源，且不得寫成 camera=() 而誤關功能。
	if !strings.Contains(defaultPermissionsPolicy, "camera=(self)") {
		t.Errorf("權限策略應允許同源相機（QR 掃碼需要），實際 %q", defaultPermissionsPolicy)
	}
	if strings.Contains(defaultPermissionsPolicy, "camera=()") {
		t.Error("權限策略不得關閉相機（會使掃碼功能失效）")
	}
}

func TestSecurityHeadersFromConfig(t *testing.T) {
	const (
		customCSP     = "default-src 'none'; script-src 'self'"
		customFrame   = "SAMEORIGIN"
		customReferer = "same-origin"
		customPerms   = "camera=(self)"
	)
	cfg := config.Default()
	cfg.Security.Headers.ContentSecurityPolicy = customCSP
	cfg.Security.Headers.FrameOptions = customFrame
	cfg.Security.Headers.ReferrerPolicy = customReferer
	cfg.Security.Headers.PermissionsPolicy = customPerms
	srv := New(&cfg, testVersion, Deps{})

	mux := http.NewServeMux()
	srv.registerRoutes(mux)
	ts := httptest.NewServer(srv.wrap(mux))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("請求失敗: %v", err)
	}
	defer resp.Body.Close()

	for name, want := range map[string]string{
		contentSecurityPolicyHeader: customCSP,
		"X-Frame-Options":           customFrame,
		"Referrer-Policy":           customReferer,
		"Permissions-Policy":        customPerms,
	} {
		if got := resp.Header.Get(name); got != want {
			t.Errorf("標頭 %s 應為組態值 %q，實際 %q", name, want, got)
		}
	}
	// 未提供覆寫的標頭仍維持內建基線。
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("未覆寫的標頭應維持內建基線，實際 %q", got)
	}
}

func TestHSTSOnlyOnTLSConnections(t *testing.T) {
	cfg := config.Default()
	srv := New(&cfg, testVersion, Deps{})
	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	tlsTS := httptest.NewTLSServer(srv.wrap(mux))
	defer tlsTS.Close()
	resp, err := tlsTS.Client().Get(tlsTS.URL + "/health")
	if err != nil {
		t.Fatalf("TLS 請求失敗: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get(hstsHeader); got != hstsValue {
		t.Errorf("TLS 連線應輸出 %s=%s，實際 %q", hstsHeader, hstsValue, got)
	}
}
