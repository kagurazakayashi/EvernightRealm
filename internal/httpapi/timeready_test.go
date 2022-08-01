package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// rfc3339UTC 為時間回應的已發布格式：恆含三位毫秒、以 Z 結尾、長度固定 24 字元。
var rfc3339UTC = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

// clockFixed 為注入時間來源的基準時刻（含毫秒，用於驗證格式與精度）。
var clockFixed = time.Date(2026, 9, 25, 12, 34, 56, 789_000_000, time.UTC)

// readyError 為可注入的就緒檢查；err 為 nil 表示依賴正常。
func readyError(err error) func(context.Context) error {
	return func(context.Context) error { return err }
}

// newDepsServer 以指定依賴建立測試伺服器，回傳伺服器與承載伺服器端日誌的緩衝區。
func newDepsServer(t *testing.T, deps Deps) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	cfg := config.Default()
	srv := New(&cfg, testVersion, deps)
	var logBuf bytes.Buffer
	srv.logger = testLogger(&logBuf)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, &logBuf
}

// getTime 請求 /time 並解析回應（欄位型別混合，故不經 map[string]string）。
func getTime(t *testing.T, url string, headers map[string]string) (timeResponse, *http.Response) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("建立請求失敗: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("請求失敗: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取回應失敗: %v", err)
	}
	var got timeResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("時間回應應為 JSON: %v (%s)", err, body)
	}
	return got, resp
}

func TestReadyReportsOKWhenDependencyHealthy(t *testing.T) {
	ts, _ := newDepsServer(t, Deps{Ready: readyError(nil)})
	resp, err := http.Get(ts.URL + "/ready")
	if err != nil {
		t.Fatalf("GET /ready 失敗: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("依賴正常時應得 200，實際 %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var got map[string]string
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("回應應為 JSON: %v (%s)", err, body)
	}
	if got["status"] != "ready" || got["service"] != "evernight-server" {
		t.Errorf("就緒回應異常: %s", body)
	}
	if got["request_id"] == "" || got["request_id"] != resp.Header.Get(requestIDHeader) {
		t.Errorf("就緒回應的 request_id 應與標頭一致且非空，實際 %q", got["request_id"])
	}
}

// TestReadyWithoutDependenciesIsReady 驗證未接外部依賴時的行為：程序存活即業務可用。
func TestReadyWithoutDependenciesIsReady(t *testing.T) {
	ts, _ := newDepsServer(t, Deps{})
	resp, err := http.Get(ts.URL + "/ready")
	if err != nil {
		t.Fatalf("GET /ready 失敗: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("未註冊依賴時應視為就緒，實際 %d", resp.StatusCode)
	}
}

// TestReadyReportsUnavailableAndStaysDesensitised 驗證「資料庫未就緒不會報告業務可用」：
// 503 與穩定錯誤碼 1007，內部原因只進伺服器端日誌，同時 /health 仍回答存活。
func TestReadyReportsUnavailableAndStaysDesensitised(t *testing.T) {
	// 原因內容刻意含路徑與驅動字樣，確保它不會出現在回應裡。
	const cause = `database: 無法連線至 D:\evernight-data\secret\evernight.db（driver: SQLITE_BUSY）`
	ts, logBuf := newDepsServer(t, Deps{Ready: readyError(errors.New(cause))})

	resp, err := http.Get(ts.URL + "/ready")
	if err != nil {
		t.Fatalf("GET /ready 失敗: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("依賴異常時應得 503，實際 %d", resp.StatusCode)
	}
	envelope, body := decodeEnvelope(t, resp)
	if envelope.Code != CodeNotReady {
		t.Errorf("錯誤碼應為 %d，實際 %d", CodeNotReady, envelope.Code)
	}
	if strings.Contains(string(body), cause) || strings.Contains(string(body), "SQLITE") ||
		strings.Contains(string(body), `D:\`) {
		t.Errorf("回應不得洩漏內部原因或路徑: %s", body)
	}
	if envelope.RequestID == "" || envelope.RequestID != resp.Header.Get(requestIDHeader) {
		t.Errorf("未就緒回應仍須帶 request_id，實際 %q", envelope.RequestID)
	}
	// 日誌裡的是「人類可讀那一份」：反斜線會被跳脫成 \\，因此逐字比對要改看關鍵片段，
	// 原字逐字的內容由日誌檔案（JSON 那一份）負責，見 internal/runlog 的對應測試。
	if logged := logBuf.String(); !strings.Contains(logged, "無法連線至") ||
		!strings.Contains(logged, "SQLITE_BUSY") || !strings.Contains(logged, envelope.RequestID) {
		t.Errorf("伺服器端日誌應含失敗原因與可對應的 request_id：%s", logged)
	}
	// 未就緒的回應仍然帶著完整安全標頭（中介層鏈最外層）。
	assertBaselineSecurityHeaders(t, resp)

	// 存活與就緒分離：資料庫不可用不代表進程沒活著。
	healthResp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health 失敗: %v", err)
	}
	defer healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Errorf("依賴異常時 /health 仍應得 200（存活），實際 %d", healthResp.StatusCode)
	}
}

func TestReadyLocaleNegotiation(t *testing.T) {
	ts, _ := newDepsServer(t, Deps{Ready: readyError(errors.New("down"))})
	cases := []struct {
		acceptLanguage string
		want           string
	}{
		{"zh-TW,zh;q=0.9", errorMessages[CodeNotReady][LocaleZhTW]},
		{"zh-CN", errorMessages[CodeNotReady][LocaleZhCN]},
		{"ja-JP", errorMessages[CodeNotReady][LocaleJaJP]},
		{"en-US", errorMessages[CodeNotReady][LocaleEnUS]},
		{"fr-FR", errorMessages[CodeNotReady][LocaleEnUS]},
	}
	for _, tc := range cases {
		t.Run(tc.acceptLanguage, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/ready", nil)
			if err != nil {
				t.Fatalf("建立請求失敗: %v", err)
			}
			req.Header.Set("Accept-Language", tc.acceptLanguage)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("請求失敗: %v", err)
			}
			defer resp.Body.Close()

			envelope, _ := decodeEnvelope(t, resp)
			if envelope.Message != tc.want {
				t.Errorf("語言 %q 應得 %q，實際 %q", tc.acceptLanguage, tc.want, envelope.Message)
			}
		})
	}
}

// TestReadyBoundsDependencyWait 驗證就緒檢查帶期限：依賴卡住時不會拖到連線層逾時。
func TestReadyBoundsDependencyWait(t *testing.T) {
	ts, _ := newDepsServer(t, Deps{Ready: func(ctx context.Context) error {
		<-ctx.Done() // 等待本層期限到來後回報未就緒
		return ctx.Err()
	}})

	start := time.Now()
	resp, err := http.Get(ts.URL + "/ready")
	if err != nil {
		t.Fatalf("GET /ready 失敗: %v", err)
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("依賴卡住時應回 503，實際 %d", resp.StatusCode)
	}
	if elapsed > readyCheckTimeout+2*time.Second {
		t.Errorf("就緒檢查未在期限內返回，耗時 %v（上限 %v）", elapsed, readyCheckTimeout)
	}
}

func TestTimeResponseUsesServerClock(t *testing.T) {
	ts, _ := newDepsServer(t, Deps{Clock: timeutil.NewTest(clockFixed)})
	got, resp := getTime(t, ts.URL+"/time", nil)

	if got.Time != "2026-09-25T12:34:56.789Z" {
		t.Errorf("時間應為注入時鐘的 UTC 正規字串，實際 %q", got.Time)
	}
	if !rfc3339UTC.MatchString(got.Time) {
		t.Errorf("時間格式不符已發布格式： %q", got.Time)
	}
	if got.Timezone != config.Default().Server.DisplayTimezone {
		t.Errorf("時區應為組態的顯示時區 %q，實際 %q", config.Default().Server.DisplayTimezone, got.Timezone)
	}
	if got.UTCOffsetSeconds != 8*3600 {
		t.Errorf("Asia/Shanghai 偏移應為 28800 秒，實際 %d", got.UTCOffsetSeconds)
	}
	if got.RequestID == "" || got.RequestID != resp.Header.Get(requestIDHeader) {
		t.Errorf("時間回應的 request_id 應與標頭一致且非空，實際 %q", got.RequestID)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("回應內容型別應為 JSON，實際 %q", ct)
	}
}

// TestTimeIgnoresClientSuppliedTime 驗證客戶端無法影響時間：
// 查詢參數、標頭與不同的注入時刻都只反映伺服器時鐘。
func TestTimeIgnoresClientSuppliedTime(t *testing.T) {
	ts, _ := newDepsServer(t, Deps{Clock: timeutil.NewTest(clockFixed)})
	got, resp := getTime(t, ts.URL+"/time?now=2020-01-01T00:00:00Z&server_time=1577836800000", map[string]string{
		"Accept-Language": "en-US",
		"X-Client-Time":   "2020-01-01T00:00:00Z",
		"X-Timezone":      "Pacific/Kiritimati",
	})
	if got.Time != "2026-09-25T12:34:56.789Z" {
		t.Errorf("客戶端帶入的時間參數不得影響回應，實際 %q", got.Time)
	}
	if got.Timezone != config.Default().Server.DisplayTimezone || got.UTCOffsetSeconds != 8*3600 {
		t.Errorf("時區由組態決定，實際 %q / %d", got.Timezone, got.UTCOffsetSeconds)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("應得 200，實際 %d", resp.StatusCode)
	}
}

// TestTimeFormatStableAcrossRequests 驗證連續請求的時間格式恆定且不倒退。
func TestTimeFormatStableAcrossRequests(t *testing.T) {
	ts, _ := newDepsServer(t, Deps{})
	var prev string
	for range 5 {
		got, _ := getTime(t, ts.URL+"/time", nil)
		if !rfc3339UTC.MatchString(got.Time) || len(got.Time) != 24 {
			t.Fatalf("時間格式不穩定: %q", got.Time)
		}
		if prev != "" && got.Time < prev {
			t.Errorf("時間倒退：%s 之後是 %s", prev, got.Time)
		}
		prev = got.Time

		// 回應的時刻必須貼近系統 UTC 此刻（本端點使用的是伺服器時鐘）。
		at, err := timeutil.ParseUTC(got.Time)
		if err != nil {
			t.Fatalf("回應時間應可被自身解析: %v", err)
		}
		if drift := time.Until(at); drift > 5*time.Second || drift < -5*time.Second {
			t.Errorf("回應時間偏離此刻過遠: %v（漂移 %v）", at, drift)
		}
	}
}

// TestTimeNotGatedByReadiness 驗證時間查詢不受就緒門控：
// 資料庫不可用時用戶端仍需校時與顯示斷線狀態。
func TestTimeNotGatedByReadiness(t *testing.T) {
	ts, _ := newDepsServer(t, Deps{
		Ready: readyError(errors.New("database down")),
		Clock: timeutil.NewTest(clockFixed),
	})
	got, resp := getTime(t, ts.URL+"/time", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("時間查詢不應受就緒門控，實際 %d", resp.StatusCode)
	}
	if got.Time != "2026-09-25T12:34:56.789Z" {
		t.Errorf("時間應仍由時鐘給出，實際 %q", got.Time)
	}
}

func TestTimeAndReadyRejectOtherMethods(t *testing.T) {
	ts, _ := newDepsServer(t, Deps{Ready: readyError(nil)})
	for _, path := range []string{"/time", "/ready"} {
		resp, err := http.Post(ts.URL+path, "application/json", strings.NewReader(""))
		if err != nil {
			t.Fatalf("POST %s 失敗: %v", path, err)
		}
		envelope, _ := decodeEnvelope(t, resp)
		resp.Body.Close()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s 非 GET 應得 405，實際 %d", path, resp.StatusCode)
		}
		if envelope.Code != CodeMethodNotAllowed {
			t.Errorf("%s 錯誤碼應為 %d，實際 %d", path, CodeMethodNotAllowed, envelope.Code)
		}
		allow := resp.Header.Get("Allow")
		if !strings.Contains(allow, http.MethodGet) || !strings.Contains(allow, http.MethodHead) {
			t.Errorf("%s 的 Allow 應列出 GET 與 HEAD，實際 %q", path, allow)
		}
	}
}
