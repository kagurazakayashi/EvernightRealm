package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
)

// testJSONPayload 為測試端點的解碼目標：含兩個欄位以驗證型別與未知欄位判定。
type testJSONPayload struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// newTestJSONServer 以指定保護參數建立掛有單一 JSON 端點的測試伺服器，
// 中介層鏈與正式路徑一致（經 Server.wrap）。
func newTestJSONServer(t *testing.T, mutate func(*config.Config)) *httptest.Server {
	t.Helper()
	cfg := config.Default()
	if mutate != nil {
		mutate(&cfg)
	}
	srv := New(&cfg, testVersion, Deps{})
	srv.logger = testLogger(io.Discard)

	mux := http.NewServeMux()
	mux.HandleFunc("/json", srv.allowMethods(func(w http.ResponseWriter, r *http.Request) {
		var payload testJSONPayload
		if !decodeJSON(w, r, &payload) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"name": payload.Name, "count": payload.Count})
	}, http.MethodPost))

	ts := httptest.NewServer(srv.wrap(mux))
	t.Cleanup(ts.Close)
	return ts
}

// postBody 以指定內容型別送出請求體。
func postBody(t *testing.T, url, contentType, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("建立請求失敗: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("請求失敗: %v", err)
	}
	return resp
}

func TestServerTimeoutsAndHeaderLimitApplied(t *testing.T) {
	cfg := config.Default()
	srv := New(&cfg, testVersion, Deps{})

	if srv.httpSrv.ReadHeaderTimeout != time.Duration(cfg.Server.ReadHeaderTimeoutMS)*time.Millisecond {
		t.Errorf("ReadHeaderTimeout 應取自組態，實際 %s", srv.httpSrv.ReadHeaderTimeout)
	}
	if srv.httpSrv.ReadTimeout != time.Duration(cfg.Server.ReadTimeoutMS)*time.Millisecond {
		t.Errorf("ReadTimeout 應取自組態，實際 %s", srv.httpSrv.ReadTimeout)
	}
	if srv.httpSrv.WriteTimeout != time.Duration(cfg.Server.WriteTimeoutMS)*time.Millisecond {
		t.Errorf("WriteTimeout 應取自組態，實際 %s", srv.httpSrv.WriteTimeout)
	}
	if srv.httpSrv.IdleTimeout != time.Duration(cfg.Server.IdleTimeoutMS)*time.Millisecond {
		t.Errorf("IdleTimeout 應取自組態，實際 %s", srv.httpSrv.IdleTimeout)
	}
	if srv.httpSrv.MaxHeaderBytes != maxHeaderBytes {
		t.Errorf("MaxHeaderBytes 應為 %d，實際 %d", maxHeaderBytes, srv.httpSrv.MaxHeaderBytes)
	}
}

func TestDecodeJSONAcceptsValidBody(t *testing.T) {
	ts := newTestJSONServer(t, nil)
	resp := postBody(t, ts.URL+"/json", "application/json", `{"name":"星","count":3}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("合法請求應得 200，實際 %d (%s)", resp.StatusCode, body)
	}
}

func TestDecodeJSONAcceptsJSONSuffixContentType(t *testing.T) {
	ts := newTestJSONServer(t, nil)
	resp := postBody(t, ts.URL+"/json", "application/vnd.evernight+json; charset=utf-8", `{"name":"a","count":1}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("+json 內容型別應被接受，實際 %d (%s)", resp.StatusCode, body)
	}
}

func TestDecodeJSONRejectsOversizedBody(t *testing.T) {
	const limit = 128
	ts := newTestJSONServer(t, func(cfg *config.Config) { cfg.Server.MaxBodyBytes = limit })

	oversized := `{"name":"` + strings.Repeat("a", 512) + `","count":1}`
	resp := postBody(t, ts.URL+"/json", "application/json", oversized)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("超過上限應得 413，實際 %d", resp.StatusCode)
	}
	envelope, _ := decodeEnvelope(t, resp)
	if envelope.Code != CodePayloadTooLarge {
		t.Errorf("錯誤碼應為 %d，實際 %d", CodePayloadTooLarge, envelope.Code)
	}
	if got, ok := envelope.Details["limit_bytes"].(float64); !ok || int64(got) != limit {
		t.Errorf("細節應帶上限 %d，實際 %v", limit, envelope.Details)
	}
}

func TestDecodeJSONRejectsMalformedBody(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantReason string
	}{
		{"截斷的 JSON", `{"name":`, "truncated request body"},
		{"語法錯誤", `{"name" "a"}`, "invalid JSON syntax"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestJSONServer(t, nil)
			resp := postBody(t, ts.URL+"/json", "application/json", tc.body)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("畸形 JSON 應得 400，實際 %d", resp.StatusCode)
			}
			envelope, body := decodeEnvelope(t, resp)
			if envelope.Code != CodeInvalidBody {
				t.Errorf("錯誤碼應為 %d，實際 %d", CodeInvalidBody, envelope.Code)
			}
			if envelope.Details["reason"] != tc.wantReason {
				t.Errorf("細節應為 %q，實際 %v", tc.wantReason, envelope.Details)
			}
			if strings.Contains(string(body), "goroutine") {
				t.Errorf("回應不得洩漏堆疊: %s", body)
			}
		})
	}
}

func TestDecodeJSONRejectsUnknownField(t *testing.T) {
	ts := newTestJSONServer(t, nil)
	resp := postBody(t, ts.URL+"/json", "application/json", `{"name":"a","count":1,"nmae":"typo"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("未知欄位應得 400，實際 %d", resp.StatusCode)
	}
	envelope, _ := decodeEnvelope(t, resp)
	if envelope.Code != CodeInvalidBody {
		t.Errorf("錯誤碼應為 %d，實際 %d", CodeInvalidBody, envelope.Code)
	}
	if envelope.Details["reason"] != "unknown field" || envelope.Details["field"] != "nmae" {
		t.Errorf("細節應指出未知欄位名稱，實際 %v", envelope.Details)
	}
}

// TestDecodeJSONRejectsClientSuppliedTime 驗證客戶端無法把「當前時間」塞進請求體：
// 請求結構不含任何時間欄位，自行加上的時間欄位一律當成未知欄位拒絕——
// 業務時間只能取自伺服器時鐘（規格 §27.2、SYS-006、ADR-007）。
func TestDecodeJSONRejectsClientSuppliedTime(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		field string
	}{
		{"now", `{"name":"a","count":1,"now":"2020-01-01T00:00:00Z"}`, "now"},
		{"server_time（毫秒整數）", `{"name":"a","count":1,"server_time":1577836800000}`, "server_time"},
		{"timestamp（帶偏移寫法）", `{"name":"a","count":1,"timestamp":"2020-01-01T08:00:00+08:00"}`, "timestamp"},
		{"created_at", `{"created_at":"2020-01-01T00:00:00.000Z","name":"a","count":1}`, "created_at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestJSONServer(t, nil)
			resp := postBody(t, ts.URL+"/json", "application/json", tc.body)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("客戶端提交的時間欄位應得 400，實際 %d", resp.StatusCode)
			}
			envelope, _ := decodeEnvelope(t, resp)
			if envelope.Code != CodeInvalidBody {
				t.Errorf("錯誤碼應為 %d，實際 %d", CodeInvalidBody, envelope.Code)
			}
			if envelope.Details["reason"] != "unknown field" || envelope.Details["field"] != tc.field {
				t.Errorf("細節應指出未知欄位 %q，實際 %v", tc.field, envelope.Details)
			}
		})
	}
}

func TestDecodeJSONRejectsTypeMismatch(t *testing.T) {
	ts := newTestJSONServer(t, nil)
	resp := postBody(t, ts.URL+"/json", "application/json", `{"name":"a","count":"三"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("型別不符應得 400，實際 %d", resp.StatusCode)
	}
	envelope, body := decodeEnvelope(t, resp)
	if envelope.Code != CodeInvalidBody || envelope.Details["field"] != "count" {
		t.Errorf("細節應指出欄位 count，實際 %v", envelope.Details)
	}
	// 細節不得帶出伺服器內部型別名稱（如 Go 結構名或套件路徑）。
	if strings.Contains(string(body), "testJSONPayload") || strings.Contains(string(body), "httpapi.") {
		t.Errorf("回應不得洩漏內部型別名稱: %s", body)
	}
}

func TestDecodeJSONRejectsEmptyBody(t *testing.T) {
	ts := newTestJSONServer(t, nil)
	resp := postBody(t, ts.URL+"/json", "application/json", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("空本體應得 400，實際 %d", resp.StatusCode)
	}
	if envelope, _ := decodeEnvelope(t, resp); envelope.Details["reason"] != "empty request body" {
		t.Errorf("細節應指出空本體，實際 %v", envelope.Details)
	}
}

func TestDecodeJSONRejectsTrailingData(t *testing.T) {
	ts := newTestJSONServer(t, nil)
	resp := postBody(t, ts.URL+"/json", "application/json", `{"name":"a","count":1}{"name":"b"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("尾隨資料應得 400，實際 %d", resp.StatusCode)
	}
	if envelope, _ := decodeEnvelope(t, resp); envelope.Details["reason"] != "unexpected trailing data" {
		t.Errorf("細節應指出尾隨資料，實際 %v", envelope.Details)
	}
}

func TestDecodeJSONRejectsNonJSONContentType(t *testing.T) {
	ts := newTestJSONServer(t, nil)
	for _, contentType := range []string{"text/plain", "application/x-www-form-urlencoded", "application/jsonx"} {
		t.Run(contentType, func(t *testing.T) {
			resp := postBody(t, ts.URL+"/json", contentType, `{"name":"a","count":1}`)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnsupportedMediaType {
				t.Fatalf("內容型別 %q 應得 415，實際 %d", contentType, resp.StatusCode)
			}
			envelope, _ := decodeEnvelope(t, resp)
			if envelope.Code != CodeUnsupportedMediaType {
				t.Errorf("錯誤碼應為 %d，實際 %d", CodeUnsupportedMediaType, envelope.Code)
			}
			if envelope.Details["expected_content_type"] != "application/json" {
				t.Errorf("細節應指出預期內容型別，實際 %v", envelope.Details)
			}
		})
	}
}

func TestRequestTimeoutReturnsStableError(t *testing.T) {
	var logBuf bytes.Buffer
	cfg := config.Default()
	cfg.Server.RequestTimeoutMS = 50
	srv := New(&cfg, testVersion, Deps{})
	srv.logger = testLogger(&logBuf)

	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		// 尊重請求 context：期限到期即結束處理，回應交由 withTimeout 統一回覆。
		<-r.Context().Done()
	})
	ts := httptest.NewServer(srv.wrap(mux))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/slow")
	if err != nil {
		t.Fatalf("請求失敗: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("處理逾時應得 503，實際 %d", resp.StatusCode)
	}
	envelope, body := decodeEnvelope(t, resp)
	if envelope.Code != CodeRequestTimeout {
		t.Errorf("錯誤碼應為 %d，實際 %d", CodeRequestTimeout, envelope.Code)
	}
	if strings.Contains(string(body), "goroutine") {
		t.Errorf("回應不得洩漏堆疊: %s", body)
	}
	if !strings.Contains(logBuf.String(), envelope.RequestID) {
		t.Errorf("伺服器端日誌應含請求關聯 ID %q: %s", envelope.RequestID, logBuf.String())
	}
}

func TestRequestTimeoutAllowsFastHandler(t *testing.T) {
	ts := newTestJSONServer(t, func(cfg *config.Config) { cfg.Server.RequestTimeoutMS = 2000 })
	resp := postBody(t, ts.URL+"/json", "application/json", `{"name":"a","count":1}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期限內完成的請求應得 200，實際 %d", resp.StatusCode)
	}
}
