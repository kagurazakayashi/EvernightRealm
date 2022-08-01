package httpapi

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/runlog"
)

// accessMessageOf 回傳日誌文字裡的訪問記錄行（不含其他記錄）。
func accessLinesOf(logText string) []string {
	var out []string
	for _, line := range strings.Split(logText, "\n") {
		if strings.Contains(line, accessMessage) {
			out = append(out, line)
		}
	}
	return out
}

// newAccessLogServer 以注入的日誌寫入器建立測試伺服器（走 Deps.Log，與正式路徑同一條注入線）。
func newAccessLogServer(t *testing.T, cfg *config.Config, deps Deps) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	var logBuf bytes.Buffer
	deps.Log = testLogger(&logBuf)
	srv := New(cfg, testVersion, deps)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("日誌內容：\n%s", logBuf.String())
		}
	})
	return ts, &logBuf
}

func TestAccessLogRecordsEveryRequest(t *testing.T) {
	cfg := config.Default()
	ts, logBuf := newAccessLogServer(t, &cfg, Deps{})

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	logText := logBuf.String()
	lines := accessLinesOf(logText)
	if len(lines) != 1 {
		t.Fatalf("訪問記錄行數 = %d，want 1：%q", len(lines), logText)
	}
	line := lines[0]
	for _, want := range []string{
		accessMessage,
		"method=GET",
		"path=/health",
		"status=200",
		"duration_ms=",
		"request_id=",
		"remote_addr=127.0.0.1",
		"proto=HTTP/1.1",
		"resp_bytes=",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("訪問記錄缺少 %q：%q", want, line)
		}
	}
	if strings.Contains(line, "query=") {
		t.Errorf("沒有查詢字串時不應出現 query 欄位：%q", line)
	}
	// 關聯 ID 必須與回應標頭同值：日誌與客戶端兩邊要能對上同一筆請求。
	idHeader := resp.Header.Get(requestIDHeader)
	if idHeader == "" || !strings.Contains(line, "request_id="+idHeader) {
		t.Errorf("訪問記錄的 request_id 與回應標頭不同（%q）：%q", idHeader, line)
	}
	// 回應標頭與信封裡的 request_id 同源（既有協議），這裡再確認訪問記錄用的是同一個值。
	if again := resp.Header.Get("x-request-id"); again != idHeader {
		t.Errorf("標頭名大小寫不一致：%q 對 %q", again, idHeader)
	}
}

func TestAccessLogLevelFollowsStatus(t *testing.T) {
	cfg := config.Default()
	var logBuf bytes.Buffer
	srv := New(&cfg, testVersion, Deps{Log: testLogger(&logBuf)})

	mux := http.NewServeMux()
	mux.HandleFunc("/ok", srv.allowMethods(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	}, http.MethodGet))
	mux.HandleFunc("/panic", func(http.ResponseWriter, *http.Request) { panic("boom") })
	handler := srv.wrap(mux)

	cases := []struct {
		name      string
		method    string
		target    string
		wantCode  int
		wantLevel string
	}{
		{"成功", http.MethodGet, "/ok", http.StatusOK, "INFO"},
		{"未知路徑", http.MethodGet, "/nope", http.StatusNotFound, "WARN"},
		{"方法不對", http.MethodPost, "/ok", http.StatusMethodNotAllowed, "WARN"},
		{"處理器 panic", http.MethodGet, "/panic", http.StatusInternalServerError, "ERROR"},
	}
	for _, tc := range cases {
		logBuf.Reset()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))

		lines := accessLinesOf(logBuf.String())
		if len(lines) != 1 {
			t.Errorf("%s：訪問記錄行數 = %d，want 1：%q", tc.name, len(lines), logBuf.String())
			continue
		}
		if rec.Code != tc.wantCode {
			t.Errorf("%s：狀態碼 = %d，want %d", tc.name, rec.Code, tc.wantCode)
		}
		if !strings.Contains(lines[0], " "+tc.wantLevel+" "+accessMessage) {
			t.Errorf("%s：狀態 %d 應記為 %s：%q", tc.name, rec.Code, tc.wantLevel, lines[0])
		}
		if !strings.Contains(lines[0], fmt.Sprintf("status=%d", tc.wantCode)) {
			t.Errorf("%s：訪問記錄的狀態碼與實際回應不符：%q", tc.name, lines[0])
		}
	}
}

func TestAccessLogCountsOneLinePerRequestIncludingHead(t *testing.T) {
	cfg := config.Default()
	ts, logBuf := newAccessLogServer(t, &cfg, Deps{})

	for i := 0; i < 5; i++ {
		resp, err := http.Get(ts.URL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	// HEAD 也要計：無回應主體不代表沒發生一趟請求。
	resp, err := http.Head(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := len(accessLinesOf(logBuf.String())); got != 6 {
		t.Errorf("訪問記錄行數 = %d，want 6：%s", got, logBuf.String())
	}
}

// TestAccessLogRecordsPreflight 驗證跨域預檢也留下一行（被拒的來源更要看得見有人試過）。
func TestAccessLogRecordsPreflight(t *testing.T) {
	cfg := config.Default()
	cfg.Security.CORS.AllowedOrigins = []string{"http://127.0.0.1:8765"}
	cfg.Security.CORS.AllowedHeaders = []string{"X-Ping"}
	ts, logBuf := newAccessLogServer(t, &cfg, Deps{})

	req, err := http.NewRequest(http.MethodOptions, ts.URL+"/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "http://127.0.0.1:8765")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "X-Ping")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("預檢狀態碼 = %d，want 204", resp.StatusCode)
	}

	lines := accessLinesOf(logBuf.String())
	if len(lines) != 1 {
		t.Fatalf("預檢的訪問記錄行數 = %d，want 1：%q", len(lines), logBuf.String())
	}
	if !strings.Contains(lines[0], "method=OPTIONS") || !strings.Contains(lines[0], "status=204") {
		t.Errorf("預檢記錄欄位不符：%q", lines[0])
	}
}

// TestAccessLogNeverContainsRequestBody 是本步的收口項目：
// PIN、會話令牌與聊天正文不得進入常規日誌。
func TestAccessLogNeverContainsRequestBody(t *testing.T) {
	const (
		pin       = "48219375"
		tokenVal  = "sess-9f8e7d6c5b4a3210fedcba76543210"
		chatPlain = "今晚八點在舊倉庫見面，口令是 48219375"
	)
	cfg := config.Default()
	var logBuf bytes.Buffer
	srv := New(&cfg, testVersion, Deps{Log: testLogger(&logBuf)})

	mux := http.NewServeMux()
	mux.HandleFunc("/login", srv.allowMethods(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			PIN   string `json:"pin"`
			Token string `json:"session_token"`
			Text  string `json:"text"`
		}
		if !decodeJSON(w, r, &payload) {
			return
		}
		// 刻意把收到的值原樣回傳以證明「回應內容」與「日誌內容」是兩件事：
		// 日誌裡必須找不到這三段文字，回應裡有才算測試到東西。
		writeJSON(w, http.StatusOK, map[string]any{"pin": payload.PIN, "text": payload.Text})
	}, http.MethodPost))
	handler := srv.wrap(mux)

	cases := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
	}{
		{"成功解析含憑據的請求體", "application/json",
			`{"pin":"` + pin + `","session_token":"` + tokenVal + `","text":"` + chatPlain + `"}`, http.StatusOK},
		{"未知欄位", "application/json", `{"unknown":"` + pin + `"}`, http.StatusBadRequest},
		{"非 JSON 內容型別", "text/plain", "pin=" + pin, http.StatusUnsupportedMediaType},
		{"畸形 JSON", "application/json", `{"pin":"` + pin + `",`, http.StatusBadRequest},
		{"空請求體", "application/json", "", http.StatusBadRequest},
	}
	for _, tc := range cases {
		logBuf.Reset()
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", tc.contentType)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != tc.wantStatus {
			t.Errorf("%s：狀態碼 = %d，want %d（回應 %s）", tc.name, rec.Code, tc.wantStatus, rec.Body.String())
		}
		if tc.wantStatus == http.StatusOK && !strings.Contains(rec.Body.String(), pin) {
			t.Errorf("%s：回應本身沒帶回這段文字，測試條件不成立", tc.name)
		}
		logged := logBuf.String()
		for _, secret := range []string{pin, tokenVal, chatPlain, "今晚八點在舊倉庫見面"} {
			if strings.Contains(logged, secret) {
				t.Errorf("%s：請求體內容出現在日誌：%q", tc.name, logged)
			}
		}
		if got := len(accessLinesOf(logged)); got != 1 {
			t.Errorf("%s：訪問記錄行數 = %d，want 1：%q", tc.name, got, logged)
		}
	}
}

// TestAccessLogRejectsForgedLines 驗證客戶端可控的路徑與標頭無法在日誌裡捏造額外行。
//
// 以 httptest.NewRequest 直接構造：Go 的 HTTP 客戶端會拒絕含換行的標頭值（正確的防呆），
// 但「拿真實客戶端送不出來」不等於「服務端不會收到」——反向代理、其他語言的客戶端
// 與之後的 WebSocket 層都可能把這種值送到處理器跟前，日誌這一層要自己站得住。
func TestAccessLogRejectsForgedLines(t *testing.T) {
	cfg := config.Default()
	var logBuf bytes.Buffer
	srv := New(&cfg, testVersion, Deps{Log: testLogger(&logBuf)})

	req := httptest.NewRequest("GET", "/a%0AINJECTED%20ERROR%20fake", nil)
	req.Header.Set("User-Agent", "curl/8.6\nINJECTED 第二行")
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

	logged := logBuf.String()
	if n := strings.Count(logged, "\n"); n != 1 {
		t.Errorf("日誌行數 = %d，want 1（換行未被跳脫就會被當成另筆記錄）：%q", n, logged)
	}
	if strings.Contains(logged, "\nINJECTED") {
		t.Errorf("注入的換行原樣出現在日誌：%q", logged)
	}
	// 跳脫不等於消失：仍要看得見原始意圖，否則「誰送了奇怪的請求」這件事查不出來。
	if !strings.Contains(logged, `\n`) || !strings.Contains(logged, "INJECTED") {
		t.Errorf("注入內容應以跳脫形式留痕：%q", logged)
	}
}

func TestAccessLogMasksTokenShapedQuery(t *testing.T) {
	cfg := config.Default()
	ts, logBuf := newAccessLogServer(t, &cfg, Deps{})

	const secret = "9f8e7d6c5b4a3210fedcba76543210"
	resp, err := http.Get(ts.URL + "/search?qr=" + secret)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	logged := logBuf.String()
	if strings.Contains(logged, secret) {
		t.Errorf("查詢字串裡的憑證形狀未被遮罩：%q", logged)
	}
	if !strings.Contains(logged, "query=") {
		t.Errorf("有查詢字串時應記錄：%q", logged)
	}
}

// TestRequestTimeoutLogsOnce 驗證逾時路徑：一條逾時記錄加一條訪問記錄，訪問記錄不重複。
func TestRequestTimeoutLogsOnce(t *testing.T) {
	cfg := config.Default()
	cfg.Server.RequestTimeoutMS = 30
	var logBuf bytes.Buffer
	srv := New(&cfg, testVersion, Deps{Log: testLogger(&logBuf)})

	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(300 * time.Millisecond):
			fmt.Fprint(w, "too late")
		}
	})
	rec := httptest.NewRecorder()
	srv.wrap(mux).ServeHTTP(rec, httptest.NewRequest("GET", "/slow", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("逾時狀態碼 = %d，want 503", rec.Code)
	}
	logged := logBuf.String()
	if lines := accessLinesOf(logged); len(lines) != 1 {
		t.Errorf("訪問記錄行數 = %d，want 1：%q", len(lines), logged)
	} else if !strings.Contains(lines[0], "status=503") || !strings.Contains(lines[0], "ERROR") {
		t.Errorf("逾時的訪問記錄不符：%q", lines[0])
	}
	if !strings.Contains(logged, "請求處理逾時") {
		t.Errorf("缺少逾時記錄：%q", logged)
	}
	if strings.Contains(logged, "too late") {
		t.Errorf("已逾時的處理內容不該進日誌：%q", logged)
	}
}

// TestDepsLogNilDiscards 驗證未注入記錄出口時不寫標準錯誤、也不崩掉。
func TestDepsLogNilDiscards(t *testing.T) {
	cfg := config.Default()
	srv := New(&cfg, testVersion, Deps{})
	rec := httptest.NewRecorder()
	srv.wrap(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/health", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("狀態碼 = %d，want 404", rec.Code)
	}
}

// TestErrorLogWriterCarriesNetHTTPErrors 驗證 net/http 自己的錯誤訊息進的是注入的寫入器，
// 且標準庫不再外加時間前綴（時間戳由記錄本身攜帶，兩份時間會分不清事件時刻與寫入時刻）。
func TestErrorLogWriterCarriesNetHTTPErrors(t *testing.T) {
	cfg := config.Default()
	var logBuf bytes.Buffer
	var httpErrs bytes.Buffer
	srv := New(&cfg, testVersion, Deps{Log: testLogger(&logBuf), ErrorLog: &httpErrs})

	srv.httpSrv.ErrorLog.Printf("http: URL query contains semicolon")
	if got := httpErrs.String(); got != "http: URL query contains semicolon\n" {
		t.Errorf("ErrorLog 寫入器收到的內容 = %q，應為不含前綴的原始訊息", got)
	}
}

// TestErrorLogAdapterRedacts 用正式組合（runlog 的適配器）驗證 net/http 錯誤也走同一條脫敏管線。
func TestErrorLogAdapterRedacts(t *testing.T) {
	cfg := config.Default()
	lg, err := runlog.Open(runlog.Options{Dir: t.TempDir(), Level: "debug", Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lg.Close() })

	srv := New(&cfg, testVersion, Deps{Log: lg.Logger, ErrorLog: lg.ErrorLogWriter(slog.LevelError)})
	const secret = "abc123def456ghi789jkl012"
	srv.httpSrv.ErrorLog.Printf("malformed HTTP request: token=%s", secret)
	if err := lg.Close(); err != nil {
		t.Fatalf("Close 失敗：%v", err)
	}

	data, err := os.ReadFile(lg.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Errorf("net/http 錯誤訊息裡的憑證未被遮罩：%s", data)
	}
	if !strings.Contains(string(data), "malformed HTTP request") {
		t.Errorf("net/http 的錯誤未成記錄：%s", data)
	}
	if !strings.Contains(string(data), `"level":"ERROR"`) {
		t.Errorf("net/http 的錯誤應記為 ERROR：%s", data)
	}
}

// TestPanicRecordStaysOneLine 驗證 panic 與堆疊進日誌後仍是一筆一行記錄，且堆疊裡的憑證形狀被遮罩。
//
// 這是最容易失控的一條路：堆疊本身多行、內容不可控（引數值會被 Go 印進影格），
// 若原樣落地，「一行一記錄」的閱讀前提就沒了，堆疊裡的憑證也一起留檔。
func TestPanicRecordStaysOneLine(t *testing.T) {
	cfg := config.Default()
	var logBuf bytes.Buffer
	srv := New(&cfg, testVersion, Deps{Log: testLogger(&logBuf)})

	const leak = "abcdef1234567890ABCDEF"
	mux := http.NewServeMux()
	mux.HandleFunc("/boom", func(http.ResponseWriter, *http.Request) {
		panic(fmt.Sprintf("無法定位憑證 Bearer %s", leak))
	})
	srv.wrap(mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/boom", nil))

	logged := logBuf.String()
	if strings.Contains(logged, leak) {
		t.Errorf("panic 內容裡的憑證未被遮罩：%q", logged)
	}
	if !strings.Contains(logged, "已攔截 panic") || !strings.Contains(logged, "goroutine") {
		t.Errorf("panic 記錄應含堆疊線索：%q", logged)
	}
	if n := strings.Count(logged, "\n"); n != 2 {
		t.Errorf("日誌行數 = %d，want 2（panic 一筆加訪問一筆，堆疊不得再分行）：%q", n, logged)
	}
	// 對外回應仍是脫敏信封：堆疊只能在伺服器端日誌裡看到。
	rec := httptest.NewRecorder()
	srv.wrap(mux).ServeHTTP(rec, httptest.NewRequest("GET", "/boom", nil))
	if body := rec.Body.String(); strings.Contains(body, "goroutine") || strings.Contains(body, leak) {
		t.Errorf("回應不得帶出堆疊或憑證：%s", body)
	}
}

// TestTransportDoesNotOwnLogSink 固定「傳輸層不自建日誌出口」：
// httpapi 只能把記錄交給注入的出口，不能自己開一條往終端去的管線。
//
// 理由與 DEC-016 的「傳輸層不 import 儲存層」同一條邊界：日誌的去處、層級與脫敏
// 屬於組合層的事，各層自建出口的最終結果是好幾條互不相干的日誌，出事時拼不出完整經過。
func TestTransportDoesNotOwnLogSink(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"os.Stderr", "os.Stdout", "log.New(os.", "log.Println", "fmt.Print"}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, token := range forbidden {
			if strings.Contains(string(data), token) {
				t.Errorf("%s 直接使用了 %q：記錄一律經注入的出口，不對外印字", name, token)
			}
		}
	}
}
