package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestReadyHonoursInjectedErrorCode 是磁碟寫保護能被區分出來的傳輸層證據：
// 注入方指定 1008 時就回 1008，且內部原因仍只進伺服器端日誌。
func TestReadyHonoursInjectedErrorCode(t *testing.T) {
	const cause = `disk: 可用空間不足，拒絕新的寫入：剩餘 512.0 MiB 低於絕對下限 1.0 GiB`
	ts, logBuf := newDepsServer(t, Deps{
		Ready: readyError(&UnreadyError{Code: CodeNoSpace, Err: errors.New(cause)}),
	})
	resp, body := getReady(t, ts)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("未就緒應得 503，實際 %d", resp.StatusCode)
	}
	var env ErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("回應應為信封 JSON：%v (%s)", err, body)
	}
	if env.Code != CodeNoSpace {
		t.Errorf("錯誤碼 = %d，want %d（空間不足要與一般未就緒分開）", env.Code, CodeNoSpace)
	}
	// 客戶端只拿到本地化的一句話：容量數字與路徑屬伺服器狀態，洩出去就是偵察情報。
	for _, leak := range []string{"MiB", "GiB", cause, "disk:"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("回應洩漏了內部原因片段 %q：%s", leak, body)
		}
	}
	if env.Message == "" || env.RequestID == "" {
		t.Errorf("信封欄位不全：%s", body)
	}
	if !strings.Contains(logBuf.String(), cause) {
		t.Errorf("日誌應留有底層原因以便對照排錯：%s", logBuf.String())
	}
}

// TestReadyFallsBackToNotReadyCode 固定兩條回退：未指定碼的 UnreadyError、
// 以及完全不帶型別的錯誤，都沿用 1007——新增碼必須是明確決定，不是預設。
func TestReadyFallsBackToNotReadyCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"UnreadyError 未指定碼", &UnreadyError{Err: errors.New("ping failed")}},
		{"一般錯誤", errors.New("ping failed")},
		{"包裝過的 UnreadyError", fmt.Errorf("就緒檢查失敗：%w",
			&UnreadyError{Code: CodeNotReady, Err: errors.New("x")})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, _ := newDepsServer(t, Deps{Ready: readyError(tc.err)})
			resp, body := getReady(t, ts)
			defer resp.Body.Close()

			var env ErrorEnvelope
			if err := json.Unmarshal(body, &env); err != nil {
				t.Fatalf("回應應為信封 JSON：%v (%s)", err, body)
			}
			if resp.StatusCode != http.StatusServiceUnavailable || env.Code != CodeNotReady {
				t.Errorf("得 %d / code=%d，want 503 / %d", resp.StatusCode, env.Code, CodeNotReady)
			}
		})
	}
}

// TestNoSpaceMessageExistsInEveryLocale 是四語言合同的把關：
// 少任何一種語言就會變成「某些用戶看到英文句子」，而那個失敗不會讓建置變紅。
func TestNoSpaceMessageExistsInEveryLocale(t *testing.T) {
	seen := map[string]bool{}
	for _, locale := range []string{LocaleZhCN, LocaleZhTW, LocaleEnUS, LocaleJaJP} {
		msg := messageFor(CodeNoSpace, locale)
		if msg == "" {
			t.Fatalf("%s 的 1008 訊息為空", locale)
		}
		if msg == messageFor(CodeNotReady, locale) {
			t.Errorf("%s 的 1008 與 1007 句子相同，用戶端分不出來", locale)
		}
		seen[msg] = true
	}
	if len(seen) != 4 {
		t.Errorf("四語言應各自不同，實際得到 %d 種寫法", len(seen))
	}
}

// TestUnreadyErrorIsNilSafe：這顆錯誤會被 errors.As 取出來再用，
// 取到 nil 指標時若 Error()/Unwrap() panic，失敗點會落在日誌格式化裡，比原始問題更難查。
func TestUnreadyErrorIsNilSafe(t *testing.T) {
	var e *UnreadyError
	if e.Error() == "" {
		t.Error("nil 指標也要給得出可讀的一行")
	}
	if e.Unwrap() != nil {
		t.Error("nil 指標的 Unwrap 應為 nil")
	}
	if got := readyErrorCode(e); got != CodeNotReady {
		t.Errorf("nil 指標應回退 %d，實際 %d", CodeNotReady, got)
	}
}

func TestReadyStillReportsHealthAlive(t *testing.T) {
	// 存活與就緒分開是 DEC-016 定的：空間不足時 /health 仍必須 200，
	// 否則排錯的人會把「服務活著但寫不進去」讀成「進程沒了」。
	ts, _ := newDepsServer(t, Deps{Ready: readyError(&UnreadyError{Code: CodeNoSpace, Err: errors.New("low")})})
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("磁碟不足時 /health 仍應 200，實際 %d", resp.StatusCode)
	}
}

// getReady 取 /ready 並一次讀完回應（供多個斷言重複使用同一份位元組）。
func getReady(t *testing.T, ts *httptest.Server) (*http.Response, []byte) {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL + "/ready")
	if err != nil {
		t.Fatalf("GET /ready 失敗：%v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		t.Fatalf("讀回應失敗：%v", err)
	}
	return resp, body
}
