package httpapi

// 這批測試守的是同一件事：加了網頁介面之後，API 那側的協定不能有第二種答案。
// 最危險的漂移不是頁面壞掉，而是「未知端點回傳 HTML」——用戶端會把外殼當成 JSON 去解析，
// 症狀出現在前端而不是協定層，查起來最花時間。

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/webassets/bundle"
)

const (
	testShellBody     = `<!DOCTYPE html><html><base href="/"><title>EvernightRealm</title></html>`
	testScriptBody    = "console.log('evernight realm bootstrapping');"
	testWasmBody      = "\x00asm\x01\x00\x00\x00"
	testBootstrapBody = `const e={"useLocalCanvasKit":true};`
)

// testBundle 組出一份可通過產物判定的檔案樹；測試不需要真的跑過一次前端建置。
func testBundle() fstest.MapFS {
	fsys := fstest.MapFS{
		"index.html":                    &fstest.MapFile{Data: []byte(testShellBody)},
		"flutter.js":                    &fstest.MapFile{Data: []byte("// flutter loader")},
		"flutter_bootstrap.js":          &fstest.MapFile{Data: []byte(testBootstrapBody)},
		"main.dart.js":                  &fstest.MapFile{Data: []byte(testScriptBody)},
		"manifest.json":                 &fstest.MapFile{Data: []byte("{}")},
		"version.json":                  &fstest.MapFile{Data: []byte(`{"version":"1.0.0"}`)},
		"favicon.png":                   &fstest.MapFile{Data: []byte("\x89PNG")},
		"assets/AssetManifest.bin":      &fstest.MapFile{Data: []byte("bin")},
		"assets/AssetManifest.bin.json": &fstest.MapFile{Data: []byte("{}")},
		"canvaskit/canvaskit.js":        &fstest.MapFile{Data: []byte("// canvaskit")},
		"canvaskit/canvaskit.wasm":      &fstest.MapFile{Data: []byte(testWasmBody)},
		"icons/Icon-192.png":            &fstest.MapFile{Data: []byte("\x89PNG")},
		"subdirectory/only-here.txt":    &fstest.MapFile{Data: []byte("x")},
		bundle.PlaceholderName:          &fstest.MapFile{Data: []byte(bundle.PlaceholderNote)},
		".last_build_id":                &fstest.MapFile{Data: []byte("abcd1234")},
	}
	return fsys
}

// newWebServer 以指定產物建立套用完整中介層鏈的測試伺服器；fsys 為 nil 表示未內嵌。
func newWebServer(t *testing.T, fsys fstest.MapFS) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	var deps Deps
	if fsys != nil {
		deps.Web = fsys
	}
	cfg := config.Default()
	srv := New(&cfg, testVersion, deps)
	var logBuf bytes.Buffer
	srv.logger = testLogger(&logBuf)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, &logBuf
}

func TestWebServesShellAtRoot(t *testing.T) {
	ts, _ := newWebServer(t, testBundle())

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / 失敗: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取回應失敗: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("狀態碼應為 200，實際 %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type 應為 HTML，實際 %q", got)
	}
	if string(body) != testShellBody {
		t.Errorf("外殼內容不符: %q", body)
	}
	if got := resp.Header.Get("Cache-Control"); got != noCacheDirective {
		t.Errorf("外殼應標 no-cache（升級執行檔後不能卡在舊殼），實際 %q", got)
	}
	// 安全回應頭與關聯 ID 由中介層鏈負責，靜態回應也不例外：頁面是最容易被注入的位置。
	if got := resp.Header.Get(contentSecurityPolicyHeader); !strings.Contains(got, "script-src 'self'") {
		t.Errorf("回應應附內建 CSP 基線，實際 %q", got)
	}
	if got := resp.Header.Get(requestIDHeader); got == "" {
		t.Error("回應應帶請求關聯 ID")
	}
}

func TestWebServesStaticAssetsWithContentType(t *testing.T) {
	cases := []struct {
		path     string
		wantType string
		wantBody string
	}{
		{path: "/main.dart.js", wantType: "javascript", wantBody: testScriptBody},
		{path: "/flutter_bootstrap.js", wantType: "javascript", wantBody: testBootstrapBody},
		{path: "/canvaskit/canvaskit.wasm", wantType: "application/wasm", wantBody: testWasmBody},
		{path: "/canvaskit/canvaskit.js", wantType: "javascript", wantBody: "// canvaskit"},
		{path: "/manifest.json", wantType: "application/json", wantBody: "{}"},
		{path: "/version.json", wantType: "application/json", wantBody: `{"version":"1.0.0"}`},
		{path: "/assets/AssetManifest.bin.json", wantType: "application/json", wantBody: "{}"},
		{path: "/favicon.png", wantType: "image/png", wantBody: "\x89PNG"},
		{path: "/index.html", wantType: "text/html", wantBody: testShellBody},
	}
	ts, _ := newWebServer(t, testBundle())

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("GET %s 失敗: %v", tc.path, err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("讀取回應失敗: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("狀態碼應為 200，實際 %d", resp.StatusCode)
			}
			got := resp.Header.Get("Content-Type")
			if !strings.Contains(got, tc.wantType) {
				t.Errorf("Content-Type 應含 %q，實際 %q", tc.wantType, got)
			}
			if string(body) != tc.wantBody {
				t.Errorf("回應內文應為 %q，實際 %q", tc.wantBody, body)
			}
			// 只有外殼宣告 no-cache；其餘資源的快取策略留給升級與發布步驟統一決定。
			if wantCache := strings.HasPrefix(got, "text/html"); wantCache {
				if got := resp.Header.Get("Cache-Control"); got != noCacheDirective {
					t.Errorf("HTML 應標 no-cache，實際 %q", got)
				}
			} else if got := resp.Header.Get("Cache-Control"); got != "" {
				t.Errorf("靜態資源本回合不應有快取標頭，實際 %q", got)
			}
		})
	}
}

func TestWebFallsBackToShellForDeepLinks(t *testing.T) {
	ts, _ := newWebServer(t, testBundle())

	for _, path := range []string{"/room/blue-moon", "/console/root/sessions", "/npc/", "/a/b/c.d/e"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s 失敗: %v", path, err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("深連結應回 200 外殼，實際 %d（%q）", resp.StatusCode, body)
			}
			if string(body) != testShellBody {
				t.Errorf("應交回應用外殼，實際 %q", body)
			}
			if got := resp.Header.Get("Cache-Control"); got != noCacheDirective {
				t.Errorf("回退的外殼也應標 no-cache，實際 %q", got)
			}
		})
	}
}

// TestWebKeepsAPIPathsAsJSONErrors 驗證端點旁邊的未知路徑不回外殼。
//
// /health 本身由路由直接命中；/health/extra 會落到 catch-all，那仍是一條「API 底下的子路徑」，
// 必須回 JSON 的 404。少了這條區分，位址拼錯的症狀會是「JSON 解析失敗」而不是「找不到端點」。
func TestWebKeepsAPIPathsAsJSONErrors(t *testing.T) {
	ts, _ := newWebServer(t, testBundle())

	for _, path := range []string{"/health/extra", "/ready/deep/deeper", "/time/now"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s 失敗: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("未登記的端點子路徑應回 404，實際 %d", resp.StatusCode)
			}
			envelope, body := decodeEnvelope(t, resp)
			if envelope.Code != CodeNotFound {
				t.Errorf("錯誤碼應為 %d，實際 %d（%s）", CodeNotFound, envelope.Code, body)
			}
			if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
				t.Errorf("端點旁的未知路徑應回 JSON，實際 %q", got)
			}
		})
	}
}

func TestWebDoesNotFallbackForFileLikePaths(t *testing.T) {
	ts, _ := newWebServer(t, testBundle())

	// 像檔案的請求一律 404：把 HTML 當成套錯名字的腳本回給瀏覽器，症狀會變成看不懂的執行期錯誤。
	for _, path := range []string{"/missing.js", "/canvaskit/canvaskit.ttf", "/assets/AssetManifest.bin.png", "/room/1.5"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s 失敗: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("不存在的檔案應回 404，實際 %d", resp.StatusCode)
			}
			if got := resp.Header.Get("Content-Type"); strings.Contains(got, "text/html") {
				t.Errorf("不應把外殼當成缺失檔案的回應: %q", got)
			}
			envelope, _ := decodeEnvelope(t, resp)
			if envelope.Code != CodeNotFound {
				t.Errorf("錯誤碼應為 %d，實際 %d", CodeNotFound, envelope.Code)
			}
		})
	}
}

func TestWebRefusesHiddenAndDirectoryPaths(t *testing.T) {
	ts, _ := newWebServer(t, testBundle())

	paths := []string{
		"/" + bundle.PlaceholderName,
		"/.last_build_id",
		"/canvaskit",
		"/canvaskit/",
		"/assets",
		"/subdirectory",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s 失敗: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("隱藏檔案與目錄應回 404，實際 %d", resp.StatusCode)
			}
			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), "佔位檔") || strings.Contains(string(body), "abcd1234") {
				t.Errorf("不應把佔位檔或建置殘留送出去: %q", body)
			}
			// 目錄也不該被當成深連結：/canvaskit 既不是頁面也不是檔案。
			if strings.Contains(string(body), "<base href") {
				t.Errorf("不應以備用外殼回應目錄或隱藏檔案: %q", body)
			}
		})
	}
}

func TestWebRefusesMethodsOtherThanGetHead(t *testing.T) {
	ts, _ := newWebServer(t, testBundle())

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		for _, path := range []string{"/", "/room/blue-moon", "/main.dart.js"} {
			t.Run(method+" "+path, func(t *testing.T) {
				req, err := http.NewRequest(method, ts.URL+path, strings.NewReader("{}"))
				if err != nil {
					t.Fatalf("建立請求失敗: %v", err)
				}
				req.Header.Set("Content-Type", "application/json")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("請求失敗: %v", err)
				}
				defer resp.Body.Close()

				// 回 404 而不是 405：這些路徑目前沒有任何業務端點，405 會騙人說它存在。
				if resp.StatusCode != http.StatusNotFound {
					t.Fatalf("狀態碼應為 404，實際 %d", resp.StatusCode)
				}
				envelope, _ := decodeEnvelope(t, resp)
				if envelope.Code != CodeNotFound {
					t.Errorf("錯誤碼應為 %d，實際 %d", CodeNotFound, envelope.Code)
				}
			})
		}
	}
}

func TestWebEndpointsKeepTheirOwnMethodRules(t *testing.T) {
	ts, _ := newWebServer(t, testBundle())

	resp, err := http.Post(ts.URL+"/health", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /health 失敗: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("已登記端點的未知方法應仍回 405，實際 %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); !strings.Contains(got, "GET") {
		t.Errorf("405 應附 Allow 標頭，實際 %q", got)
	}
}

func TestWebWithoutBundleKeepsNotFoundContract(t *testing.T) {
	// 未內嵌產物（或產物不完整）時，協定層行為必須與還沒有網頁介面的版次逐字相同。
	ts, _ := newWebServer(t, nil)

	for _, path := range []string{"/", "/room/blue-moon", "/main.dart.js"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s 失敗: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("未內嵌產物時應回 404，實際 %d", resp.StatusCode)
			}
			envelope, _ := decodeEnvelope(t, resp)
			if envelope.Code != CodeNotFound {
				t.Errorf("錯誤碼應為 %d，實際 %d", CodeNotFound, envelope.Code)
			}
			if got := resp.Header.Get("Cache-Control"); got != "" {
				t.Errorf("404 不應帶外殼的快取標頭，實際 %q", got)
			}
			if got := resp.Header.Get(contentSecurityPolicyHeader); got == "" {
				t.Error("404 仍應帶安全回應頭")
			}
		})
	}
}

func TestWebFallbackRequiresShellToExist(t *testing.T) {
	// 外殼不見了卻回 200 空白頁是最壞的結果：畫面什麼都沒有，網路層卻全綠。
	fsys := testBundle()
	delete(fsys, "index.html")
	ts, _ := newWebServer(t, fsys)

	for _, path := range []string{"/", "/room/blue-moon"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s 失敗: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("缺少外殼時應回 404 信封，實際 %d", resp.StatusCode)
			}
			envelope, _ := decodeEnvelope(t, resp)
			if envelope.Code != CodeNotFound {
				t.Errorf("錯誤碼應為 %d，實際 %d", CodeNotFound, envelope.Code)
			}
		})
	}
}

func TestWebServesHeadAndRange(t *testing.T) {
	ts, _ := newWebServer(t, testBundle())

	t.Run("HEAD 外殼", func(t *testing.T) {
		resp, err := http.Head(ts.URL + "/")
		if err != nil {
			t.Fatalf("HEAD 失敗: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("HEAD / 應回 200，實際 %d", resp.StatusCode)
		}
		if resp.ContentLength <= 0 {
			t.Errorf("HEAD 應帶長度供前端判斷，實際 %d", resp.ContentLength)
		}
		body, _ := io.ReadAll(resp.Body)
		if len(body) != 0 {
			t.Errorf("HEAD 不應有內文，實際 %q", body)
		}
	})

	t.Run("腳本範圍請求", func(t *testing.T) {
		// 引擎檔以 WebAssembly 串流載入，部分瀏覽器以範圍請求分段取回；回錯狀態碼會變成載入失敗。
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/main.dart.js", nil)
		if err != nil {
			t.Fatalf("建立請求失敗: %v", err)
		}
		req.Header.Set("Range", "bytes=0-3")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("請求失敗: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusPartialContent {
			t.Fatalf("範圍請求應回 206，實際 %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != testScriptBody[:4] {
			t.Errorf("範圍內容應為前 4 位元組，實際 %q", body)
		}
	})
}

// TestWebStaysInsideBundle 驗證醜路徑一律走正規化或 404，拿不到產物目錄之外的東西。
//
// 內嵌檔案樹本身就只能看到 dist，因此這裡要固定的是「回應永遠落在協定內」：
// 重導向後的結果要不是產物裡的檔案，要不是統一 404 信封，不會出現第三種答案。
func TestWebStaysInsideBundle(t *testing.T) {
	ts, _ := newWebServer(t, testBundle())

	cases := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{path: "/../config.yaml", wantStatus: http.StatusNotFound},
		{path: "/../../config.example.yaml", wantStatus: http.StatusNotFound},
		{path: "/main.dart.js/../../config.yaml", wantStatus: http.StatusNotFound},
		{path: "/%2e%2e/main.dart.js", wantStatus: http.StatusNotFound},
		{path: "//main.dart.js", wantStatus: http.StatusOK, wantBody: testScriptBody},
		{path: "/./main.dart.js", wantStatus: http.StatusOK, wantBody: testScriptBody},
		{path: "/subdirectory/../index.html", wantStatus: http.StatusOK, wantBody: testShellBody},
		// 向上跳的寫法被正規化之後如果落在一條「不像檔案」的路徑上，就按深連結回外殼：
		// 這是單頁應用規則的結果，不是讀到了產物之外的檔案（內嵌檔案樹結構上看不到 dist 以外）。
		{path: "/a/../../etc/passwd", wantStatus: http.StatusOK, wantBody: testShellBody},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("GET %s 失敗: %v", tc.path, err)
			}
			defer resp.Body.Close()

			// 404 的內文就是信封本身：交錯讀取會讓 decodeEnvelope 拿到空內文。
			if tc.wantStatus == http.StatusNotFound {
				envelope, body := decodeEnvelope(t, resp)
				if resp.StatusCode != http.StatusNotFound {
					t.Fatalf("狀態碼應為 404，實際 %d（%s）", resp.StatusCode, body)
				}
				if envelope.Code != CodeNotFound {
					t.Errorf("錯誤碼應為 %d，實際 %d", CodeNotFound, envelope.Code)
				}
				if strings.Contains(string(body), "root_password_hash") {
					t.Errorf("回應不得洩漏產物之外的內容: %q", body)
				}
				return
			}

			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("狀態碼應為 %d，實際 %d（%q）", tc.wantStatus, resp.StatusCode, body)
			}
			if tc.wantBody != "" && string(body) != tc.wantBody {
				t.Errorf("回應內文不符: %q", body)
			}
		})
	}
}

// isRedirect 判別 3xx 重導向（net/http 對路徑正規化的重導向用 307，不該把狀態碼寫死成一種）。
func isRedirect(status int) bool {
	return status >= http.StatusMultipleChoices && status < http.StatusBadRequest
}

// TestWebHandlerRefusesInvalidPathsDirectly 不看客戶端跟不跟重導向，直接驗路由樹給的答案：要正軌化、要拒絕，也沒有第三種。
func TestWebHandlerRefusesInvalidPathsDirectly(t *testing.T) {
	cfg := config.Default()
	srv := New(&cfg, testVersion, Deps{Web: testBundle()})
	handler := srv.Handler()

	for _, rawPath := range []string{"/../config.yaml", "/a/../../etc/passwd", "/%2e%2e/main.dart.js"} {
		t.Run(rawPath, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost"+rawPath, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()
			if !isRedirect(resp.StatusCode) && resp.StatusCode != http.StatusNotFound {
				t.Errorf("髒路徑只能被正規化或拒絕，實際 %d", resp.StatusCode)
			}
			if isRedirect(resp.StatusCode) {
				if target := resp.Header.Get("Location"); strings.Contains(target, "..") {
					t.Errorf("重導向目標不得保留向上跳的寫法: %q", target)
				}
			}
			if got := resp.Header.Get(contentSecurityPolicyHeader); got == "" {
				t.Error("任何回應都應帶安全回應頭")
			}
		})
	}
}

func TestAPIFirstSegmentsDeriveFromRouteTable(t *testing.T) {
	// 回退用的排除清單必須由登記清單派生：新增端點只改 apiRoutes 一處就自動納入排除。
	segments := apiFirstSegments([]apiRoute{
		{pattern: "/health"},
		{pattern: "/ready"},
		{pattern: "/orders/{id}"},
		{pattern: "/assets/all/"},
		{pattern: "/"},
	})
	for _, want := range []string{"health", "ready", "orders", "assets"} {
		if _, ok := segments[want]; !ok {
			t.Errorf("首段 %s 應在排除清單裡，實際 %v", want, segments)
		}
	}
	if len(segments) != 4 {
		t.Errorf("根路徑不該產生排除段，實際 %v", segments)
	}

	registered := apiFirstSegments((&Server{}).apiRoutes())
	for _, path := range []string{"/health/extra", "/ready/x", "/time/now"} {
		if _, ok := registered[firstPathSegment(path)]; !ok {
			t.Errorf("目前登記的端點 %s 未被排除清單涵蓋", path)
		}
	}
	if _, ok := registered["orders"]; ok {
		t.Error("未登記的首段不該出現在排除清單")
	}
}

func TestPathHeuristics(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"/health", "health"},
		{"/health/extra", "health"},
		{"/", ""},
		{"/orders/1/items", "orders"},
		{"", ""},
	} {
		if got := firstPathSegment(tc.input); got != tc.want {
			t.Errorf("firstPathSegment(%q) = %q，預期 %q", tc.input, got, tc.want)
		}
	}

	// looksLikeFile 只看最後一段有沒有附帶副檔名。含句號的路徑段會被當成檔案，
	// 因此前端的路由名稱不得含句號——這條取捨寫在註解裡，也在這裡固定住。
	for _, tc := range []struct {
		input string
		want  bool
	}{
		{input: "main.dart.js", want: true},
		{input: "index.html", want: true},
		{input: "canvaskit/canvaskit.wasm", want: true},
		{input: "room/blue-moon", want: false},
		{input: "a.b/c", want: false},
		{input: "index.", want: false},
		{input: "version", want: false},
		{input: "", want: false},
	} {
		if got := looksLikeFile(tc.input); got != tc.want {
			t.Errorf("looksLikeFile(%q) = %v，預期 %v", tc.input, got, tc.want)
		}
	}

	for _, tc := range []struct {
		input string
		want  bool
	}{
		{input: bundle.PlaceholderName, want: true},
		{input: "canvaskit/.hidden", want: true},
		{input: "index.html", want: false},
		{input: "_private/x", want: false},
	} {
		if got := isHiddenName(tc.input); got != tc.want {
			t.Errorf("isHiddenName(%q) = %v，預期 %v", tc.input, got, tc.want)
		}
	}

	for _, tc := range []struct {
		input string
		want  bool
	}{
		{input: "index.html", want: true},
		{input: "sub/page.htm", want: true},
		{input: "main.dart.js", want: false},
		{input: "manifest.json", want: false},
	} {
		if got := isHTMLName(tc.input); got != tc.want {
			t.Errorf("isHTMLName(%q) = %v，預期 %v", tc.input, got, tc.want)
		}
	}
}
