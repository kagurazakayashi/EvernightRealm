package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// decodeEnvelope 讀取回應並解析為統一錯誤信封，同時回傳原始回應內容。
func decodeEnvelope(t *testing.T, resp *http.Response) (ErrorEnvelope, []byte) {
	t.Helper()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("錯誤回應 Content-Type 應為 JSON，實際 %q", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取回應失敗: %v", err)
	}
	var envelope ErrorEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("錯誤回應應為信封 JSON: %v (%s)", err, body)
	}
	if envelope.Message == "" {
		t.Errorf("錯誤信封缺少使用者訊息: %s", body)
	}
	return envelope, body
}

func TestNotFoundEnvelope(t *testing.T) {
	ts := testServer(t)
	resp, err := http.Get(ts.URL + "/no-such-path")
	if err != nil {
		t.Fatalf("GET /no-such-path 失敗: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("未知路徑應得 404，實際 %d", resp.StatusCode)
	}

	envelope, _ := decodeEnvelope(t, resp)
	if envelope.Code != CodeNotFound {
		t.Errorf("錯誤碼應為 %d，實際 %d", CodeNotFound, envelope.Code)
	}
	if envelope.RequestID == "" {
		t.Error("錯誤信封應帶 request_id")
	}
	if headerID := resp.Header.Get(requestIDHeader); headerID != envelope.RequestID {
		t.Errorf("回應標頭 %s 應與信封 request_id 一致，實際 %q 與 %q", requestIDHeader, headerID, envelope.RequestID)
	}
}

func TestMethodNotAllowedEnvelope(t *testing.T) {
	ts := testServer(t)
	resp, err := http.Post(ts.URL+"/health", "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatalf("POST /health 失敗: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("非 GET 應得 405，實際 %d", resp.StatusCode)
	}

	allow := resp.Header.Get("Allow")
	if !strings.Contains(allow, http.MethodGet) || !strings.Contains(allow, http.MethodHead) {
		t.Errorf("405 回應應附 Allow 標頭列出允許方法，實際 %q", allow)
	}
	if envelope, _ := decodeEnvelope(t, resp); envelope.Code != CodeMethodNotAllowed {
		t.Errorf("錯誤碼應為 %d，實際 %d", CodeMethodNotAllowed, envelope.Code)
	}
}

func TestErrorEnvelopeLocaleNegotiation(t *testing.T) {
	cases := []struct {
		name           string
		acceptLanguage string
		wantMessage    string
	}{
		{"繁體中文", "zh-TW,zh;q=0.9,en;q=0.8", errorMessages[CodeNotFound][LocaleZhTW]},
		{"簡體中文", "zh-CN", errorMessages[CodeNotFound][LocaleZhCN]},
		{"日文", "ja-JP", errorMessages[CodeNotFound][LocaleJaJP]},
		{"英文", "en-US", errorMessages[CodeNotFound][LocaleEnUS]},
		{"未支援語言回退", "fr-FR,de;q=0.9", errorMessages[CodeNotFound][LocaleEnUS]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := testServer(t)
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/no-such-path", nil)
			if err != nil {
				t.Fatalf("建立請求失敗: %v", err)
			}
			req.Header.Set("Accept-Language", tc.acceptLanguage)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("請求失敗: %v", err)
			}
			defer resp.Body.Close()

			if envelope, _ := decodeEnvelope(t, resp); envelope.Message != tc.wantMessage {
				t.Errorf("Accept-Language %q 應得訊息 %q，實際 %q", tc.acceptLanguage, tc.wantMessage, envelope.Message)
			}
		})
	}
}

func TestRequestIDPropagation(t *testing.T) {
	const clientID = "client-trace-0001"
	ts := testServer(t)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/no-such-path", nil)
	if err != nil {
		t.Fatalf("建立請求失敗: %v", err)
	}
	req.Header.Set(requestIDHeader, clientID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("請求失敗: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get(requestIDHeader); got != clientID {
		t.Errorf("合法的用戶端 %s 應被透傳，實際 %q", requestIDHeader, got)
	}
	if envelope, _ := decodeEnvelope(t, resp); envelope.RequestID != clientID {
		t.Errorf("信封 request_id 應為 %q，實際 %q", clientID, envelope.RequestID)
	}
}

func TestRequestIDRejectsUnsafeValue(t *testing.T) {
	unsafeIDs := []string{
		"with space",
		"with;semicolon",
		strings.Repeat("a", requestIDMaxLen+1),
	}
	for _, unsafe := range unsafeIDs {
		t.Run(unsafe[:min(len(unsafe), 12)], func(t *testing.T) {
			ts := testServer(t)
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/health", nil)
			if err != nil {
				t.Fatalf("建立請求失敗: %v", err)
			}
			req.Header.Set(requestIDHeader, unsafe)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("請求失敗: %v", err)
			}
			defer resp.Body.Close()

			got := resp.Header.Get(requestIDHeader)
			if got == unsafe {
				t.Fatalf("不安全的 %s 不應被透傳: %q", requestIDHeader, got)
			}
			if _, err := idgen.Parse(got); err != nil {
				t.Fatalf("應改以統一介面產生正規 UUIDv7 關聯 ID，實際 %q: %v", got, err)
			}
		})
	}
}

// TestServerGeneratedRequestIDUsesIDGen 驗證伺服器自行產生的關聯 ID 一律經統一介面：
// 格式為正規 UUIDv7，且依產生順序可排序（排序欄位為前 8 個位元組）。
func TestServerGeneratedRequestIDUsesIDGen(t *testing.T) {
	ts := testServer(t)
	var orderPrefixes []string
	for range 5 {
		resp, err := http.Get(ts.URL + "/health")
		if err != nil {
			t.Fatalf("GET /health 失敗: %v", err)
		}
		defer resp.Body.Close()

		id, err := idgen.Parse(resp.Header.Get(requestIDHeader))
		if err != nil {
			t.Fatalf("關聯 ID %q 應可經統一介面解析: %v", resp.Header.Get(requestIDHeader), err)
		}
		orderPrefixes = append(orderPrefixes, strings.ReplaceAll(id.String(), "-", "")[:16])
	}
	for i := 1; i < len(orderPrefixes); i++ {
		if orderPrefixes[i-1] >= orderPrefixes[i] {
			t.Errorf("後產生的關聯 ID 排序前綴應較大：%s 之後是 %s", orderPrefixes[i-1], orderPrefixes[i])
		}
	}
}

// TestRequestIDGenerationFailureRejectsRequest 驗證亂數來源異常時不降級：
// 無法產生關聯 ID 即以統一信封回 500，不輸出其他格式頂替，原因只寫伺服器端日誌。
func TestRequestIDGenerationFailureRejectsRequest(t *testing.T) {
	const cause = "熵源不可用"
	var logBuf bytes.Buffer
	cfg := config.Default()
	srv := New(&cfg, testVersion, Deps{})
	srv.logger = testLogger(&logBuf)
	srv.newID = func() (idgen.ID, error) { return idgen.Nil, errors.New(cause) }

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("請求失敗: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("無法產生關聯 ID 應回 500，實際 %d", resp.StatusCode)
	}
	if got := resp.Header.Get(requestIDHeader); got != "" {
		t.Errorf("不應以其他格式頂替關聯 ID，實際 %q", got)
	}

	envelope, body := decodeEnvelope(t, resp)
	if envelope.Code != CodeUnknown {
		t.Errorf("錯誤碼應為 %d，實際 %d", CodeUnknown, envelope.Code)
	}
	if envelope.RequestID != "" {
		t.Errorf("信封 request_id 應留空（關聯 ID 無法產生），實際 %q", envelope.RequestID)
	}
	if strings.Contains(string(body), cause) {
		t.Errorf("回應不得洩漏底層錯誤原因: %s", body)
	}
	if logged := logBuf.String(); !strings.Contains(logged, cause) || !strings.Contains(logged, "/health") {
		t.Errorf("伺服器端日誌應保留失敗原因與請求路徑: %s", logged)
	}
	// 本層自行寫出的拒絕回應仍須帶完整安全標頭（安全標頭中介層位於鏈最外層）。
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("拒絕回應缺少安全標頭")
	}
}

func TestHealthIncludesRequestID(t *testing.T) {
	ts := testServer(t)
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health 失敗: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var got map[string]string
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("回應體應為 JSON: %v (%s)", err, body)
	}
	if got["request_id"] == "" {
		t.Errorf("存活檢查回應應帶 request_id: %s", body)
	}
	if got["request_id"] != resp.Header.Get(requestIDHeader) {
		t.Errorf("存活檢查 request_id 應與回應標頭一致，實際 %q 與 %q",
			got["request_id"], resp.Header.Get(requestIDHeader))
	}
}

func TestPanicRecoveryReturnsEnvelopeAndLogsID(t *testing.T) {
	const secret = "panic-detail-should-not-leak"
	var logBuf bytes.Buffer
	cfg := config.Default()
	srv := New(&cfg, testVersion, Deps{})
	srv.logger = testLogger(&logBuf)

	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(secret)
	})
	ts := httptest.NewServer(chain(panicking, srv.withRequestID, srv.withRecovery))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/panic")
	if err != nil {
		t.Fatalf("請求失敗: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("panic 應回 500，實際 %d", resp.StatusCode)
	}

	envelope, body := decodeEnvelope(t, resp)
	if envelope.Code != CodeUnknown {
		t.Errorf("panic 應回錯誤碼 %d，實際 %d", CodeUnknown, envelope.Code)
	}

	if strings.Contains(string(body), secret) || strings.Contains(string(body), "goroutine") {
		t.Errorf("回應不得洩漏 panic 內容或堆疊: %s", body)
	}

	logged := logBuf.String()
	if !strings.Contains(logged, envelope.RequestID) {
		t.Errorf("伺服器端日誌應含請求關聯 ID %q: %s", envelope.RequestID, logged)
	}
	if !strings.Contains(logged, secret) {
		t.Errorf("伺服器端日誌應保留 panic 內容以供診斷: %s", logged)
	}
}

func TestPanicRecoveryRepanicsAbortHandler(t *testing.T) {
	cfg := config.Default()
	srv := New(&cfg, testVersion, Deps{})

	aborting := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	})
	handler := chain(aborting, srv.withRequestID, srv.withRecovery)

	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Fatalf("http.ErrAbortHandler 應交還 net/http 處理，實際 %v", recovered)
		}
	}()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/abort", nil))
}

func TestNegotiateLocale(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"", LocaleEnUS},
		{"   ", LocaleEnUS},
		{"zh-TW", LocaleZhTW},
		{"ZH-tw", LocaleZhTW},
		{"zh-Hant", LocaleZhTW},
		{"zh-Hans-CN", LocaleZhCN},
		{"zh-CN,zh;q=0.9,en;q=0.8", LocaleZhCN},
		{"zh;q=0.5,en;q=0.9", LocaleEnUS},
		{"zh-TW;q=0", LocaleEnUS},
		{"ja-JP", LocaleJaJP},
		{"fr-FR;q=0.9,ja;q=0.8", LocaleJaJP},
		{"fr-FR,de;q=0.9", LocaleEnUS},
		{"*", LocaleEnUS},
		{"ja;q=abc", LocaleEnUS},
		{"en-US;q=1.0, zh-TW;q=0.9", LocaleEnUS},
	}
	for _, tc := range cases {
		if got := negotiateLocale(tc.header); got != tc.want {
			t.Errorf("Accept-Language %q 應得 %q，實際 %q", tc.header, tc.want, got)
		}
	}
}

func TestValidRequestID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"", false},
		{"client-trace_0001.abc", true},
		{"0192f0c4-1c9a-7c3e-9a1b-2f4d6e8a0b1c", true},
		{"with space", false},
		{"with\nnewline", false},
		{"with;semicolon", false},
		{"中文", false},
		{strings.Repeat("a", requestIDMaxLen), true},
		{strings.Repeat("a", requestIDMaxLen+1), false},
	}
	for _, tc := range cases {
		if got := validRequestID(tc.id); got != tc.want {
			t.Errorf("validRequestID(%q) 應為 %v，實際 %v", tc.id, tc.want, got)
		}
	}
}

func TestErrorMessagesCoverAllLocales(t *testing.T) {
	locales := []string{LocaleZhCN, LocaleZhTW, LocaleEnUS, LocaleJaJP}
	for code := range errorMessages {
		for _, locale := range locales {
			if messageFor(code, locale) == "" {
				t.Errorf("錯誤碼 %d 缺少語言 %q 的訊息", code, locale)
			}
		}
	}
	if messageFor(CodeNotFound, "fr-FR") != errorMessages[CodeNotFound][defaultLocale] {
		t.Error("未支援語言應回退預設語言訊息")
	}
}
