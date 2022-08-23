package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// initStatusStub 是狀態來源的替身：記下被問了幾次，並回吐預置的結果或錯誤。
//
// 傳輸層測試要釘的是「回應形態、方法放行、快取標頭、錯誤不洩漏」，
// 檔案與環境變數的判定由 internal/app 自己的測試負責，不在這裡重演。
type initStatusStub struct {
	status RootInitStatus
	err    error
	calls  int
}

// get 實作 httpapi.Deps.InitStatus。
func (s *initStatusStub) get() (RootInitStatus, error) {
	s.calls++
	return s.status, s.err
}

// initStatusServer 建立注入（或未注入）狀態來源的測試服務，走完整中介層鏈。
//
// stub 為 nil 時代表「沒有注入來源」；web 為 nil 時代表沒有內嵌產物，
// 兩者都是這個端點對外形態的一部分，因此留成參數而不是各建一個 helper。
func initStatusServer(t *testing.T, stub *initStatusStub, web fs.FS) *httptest.Server {
	t.Helper()
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("測試組態不合法：%v", err)
	}
	deps := Deps{Clock: timeutil.System()}
	if stub != nil {
		deps.InitStatus = stub.get
	}
	if web != nil {
		deps.Web = web
	}
	ts := httptest.NewServer(New(&cfg, testVersion, deps).Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestInitStatusAbsentWhenNotInjected(t *testing.T) {
	ts := initStatusServer(t, nil, nil)
	resp, err := http.Get(ts.URL + "/root/init-status")
	if err != nil {
		t.Fatalf("請求失敗：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("未注入來源時端點應不存在，實際 %d", resp.StatusCode)
	}
	var envelope ErrorEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatalf("解析回應失敗：%v", err)
	}
	if envelope.Code != CodeNotFound {
		t.Errorf("機器碼應為 %d，實際 %d", CodeNotFound, envelope.Code)
	}
}

func TestInitStatusReportsThreeBooleans(t *testing.T) {
	cases := []struct {
		name   string
		status RootInitStatus
	}{
		{"尚無組態檔", RootInitStatus{}},
		{"有檔案但還沒有 Root", RootInitStatus{ConfigExists: true}},
		{"已初始化", RootInitStatus{ConfigExists: true, RootInitialized: true}},
		{"環境變數蓋著", RootInitStatus{ConfigExists: true, EnvOverride: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &initStatusStub{status: tc.status}
			ts := initStatusServer(t, stub, nil)
			resp, err := http.Get(ts.URL + "/root/init-status")
			if err != nil {
				t.Fatalf("請求失敗：%v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("狀態查詢應回 200，實際 %d", resp.StatusCode)
			}
			if got := resp.Header.Get(cacheControlHeader); got != "no-store" {
				t.Errorf("狀態回應必禁快取（重新檢查才有人看得懂），實際 %q", got)
			}
			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("解析回應失敗：%v", err)
			}
			// 欄位集合是這個端點的全部对外合同：多一欄就是多一條內部資訊的出口。
			wantKeys := map[string]bool{
				"config_exists": true, "root_initialized": true,
				"env_override": true, "request_id": true,
			}
			if len(body) != len(wantKeys) {
				t.Errorf("回應欄位應只有 %v，實際 %v", wantKeys, body)
			}
			for key := range wantKeys {
				if _, ok := body[key]; !ok {
					t.Errorf("回應缺少欄位 %s", key)
				}
			}
			for field, want := range map[string]bool{
				"config_exists":    tc.status.ConfigExists,
				"root_initialized": tc.status.RootInitialized,
				"env_override":     tc.status.EnvOverride,
			} {
				if body[field] != want {
					t.Errorf("%s 應為 %v，實際 %v", field, want, body[field])
				}
			}
			if stub.calls != 1 {
				t.Errorf("一次請求應只問一次來源，實際 %d 次", stub.calls)
			}
		})
	}
}

func TestInitStatusReadFailureStaysGeneric(t *testing.T) {
	// 內部原因（路徑、行號）是這一行要驗的重點：它只能進日誌，不能進回應。
	const internalReason = "第 12 行 YAML 語法錯誤 in P:\\secret\\config.yaml"
	stub := &initStatusStub{err: errors.New(internalReason)}
	ts := initStatusServer(t, stub, nil)
	resp, err := http.Get(ts.URL + "/root/init-status")
	if err != nil {
		t.Fatalf("請求失敗：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("查不出來應回 500，實際 %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取回應失敗：%v", err)
	}
	if strings.Contains(string(raw), internalReason) {
		t.Errorf("回應洩漏了內部原因：%s", raw)
	}
	var envelope ErrorEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("解析回應失敗：%v", err)
	}
	if envelope.Code != CodeUnknown {
		t.Errorf("機器碼應為 %d，實際 %d", CodeUnknown, envelope.Code)
	}
	if envelope.Details != nil {
		t.Errorf("錯誤回應不該帶 details，實際 %v", envelope.Details)
	}
}

func TestInitStatusIsReadOnly(t *testing.T) {
	stub := &initStatusStub{status: RootInitStatus{ConfigExists: true, RootInitialized: true}}
	ts := initStatusServer(t, stub, nil)

	resp, err := http.Post(ts.URL+"/root/init-status", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("請求失敗：%v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("寫入方法應被拒，實際 %d", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("Allow 標頭應為 GET, HEAD，實際 %q", allow)
	}
	if stub.calls != 0 {
		t.Errorf("被拒的方法不該去問來源，實際問了 %d 次", stub.calls)
	}

	headReq, err := http.NewRequest(http.MethodHead, ts.URL+"/root/init-status", nil)
	if err != nil {
		t.Fatalf("建立 HEAD 請求失敗：%v", err)
	}
	headResp, err := http.DefaultClient.Do(headReq)
	if err != nil {
		t.Fatalf("HEAD 請求失敗：%v", err)
	}
	headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		t.Errorf("HEAD 應與 GET 同形，實際 %d", headResp.StatusCode)
	}
}

func TestInitStatusSegmentIsNotSwallowedByShell(t *testing.T) {
	// 內嵌產物在場時，端點首段一律不回外殼：這條登記與回退共用同一份清單，
	// 寫錯的症狀是「狀態端點回傳 HTML」，比 404 更難查。
	web := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>shell</html>")},
	}
	stub := &initStatusStub{status: RootInitStatus{ConfigExists: true}}
	ts := initStatusServer(t, stub, web)

	resp, err := http.Get(ts.URL + "/root/init-status")
	if err != nil {
		t.Fatalf("請求失敗：%v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀取回應失敗：%v", err)
	}
	if strings.Contains(string(body), "shell") {
		t.Fatalf("端點被外殼吞掉了：%s", body)
	}
	if ctype := resp.Header.Get("Content-Type"); !strings.HasPrefix(ctype, "application/json") {
		t.Errorf("端點應回 JSON，實際 Content-Type %q", ctype)
	}

	// 同首段的未知子路徑也該回 JSON 404，而不是深連結外殼。
	subResp, err := http.Get(ts.URL + "/root/init-status/extra")
	if err != nil {
		t.Fatalf("請求子路徑失敗：%v", err)
	}
	defer subResp.Body.Close()
	subBody, err := io.ReadAll(subResp.Body)
	if err != nil {
		t.Fatalf("讀取子路徑回應失敗：%v", err)
	}
	if strings.Contains(string(subBody), "shell") {
		t.Errorf("API 首段下的子路徑回退了外殼：%s", subBody)
	}
	if subResp.StatusCode != http.StatusNotFound {
		t.Errorf("子路徑應回 404，實際 %d", subResp.StatusCode)
	}

	// 對照組：不是端點首段的路徑仍回外殼。
	pageResp, err := http.Get(ts.URL + "/some-deep-link")
	if err != nil {
		t.Fatalf("請求深連結失敗：%v", err)
	}
	defer pageResp.Body.Close()
	pageBody, err := io.ReadAll(pageResp.Body)
	if err != nil {
		t.Fatalf("讀取深連結回應失敗：%v", err)
	}
	if !strings.Contains(string(pageBody), "shell") {
		t.Errorf("深連結應回外殼，實際 %s", pageBody)
	}
}
