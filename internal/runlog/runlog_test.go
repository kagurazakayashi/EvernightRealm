package runlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/kagurazakayashi/EvernightRealm/internal/redact"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixedClock 回傳固定時刻，讓逐字比對輸出行成為可能（DEC-015 的可注入測試時鐘）。
func fixedClock() time.Time { return time.Date(2026, 9, 26, 12, 34, 56, 789_000_000, time.UTC) }

// newTestLogger 在暫時目錄建立日誌，標準錯誤輸出改寫入回傳的緩衝區。
func newTestLogger(t *testing.T, level string) (*Logger, *bytes.Buffer) {
	t.Helper()
	var stderr bytes.Buffer
	logger, err := Open(Options{
		Dir:    filepath.Join(t.TempDir(), "logs"),
		Level:  level,
		Stderr: &stderr,
		Now:    fixedClock,
	})
	if err != nil {
		t.Fatalf("Open 失敗：%v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	return logger, &stderr
}

// readLogLines 取回日誌檔案內容並切成行（每筆記錄一行）。
func readLogLines(t *testing.T, logger *Logger) []string {
	t.Helper()
	data, err := os.ReadFile(logger.Path())
	if err != nil {
		t.Fatalf("讀取日誌檔案失敗：%v", err)
	}
	text := strings.TrimRight(string(data), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func TestOpenWritesFileAndStderr(t *testing.T) {
	logger, stderr := newTestLogger(t, "info")
	logger.Info("服務已啟動", "listen", "127.0.0.1:5206")

	if err := logger.Close(); err != nil {
		t.Fatalf("Close 失敗：%v", err)
	}
	lines := readLogLines(t, logger)
	if len(lines) != 1 {
		t.Fatalf("日誌檔案行數 = %d，want 1（%v）", len(lines), lines)
	}

	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("日誌檔案不是合法 JSON：%v", err)
	}
	if record["msg"] != "服務已啟動" || record["listen"] != "127.0.0.1:5206" {
		t.Errorf("JSON 記錄欄位不符：%v", record)
	}
	if record["level"] != "INFO" {
		t.Errorf("level = %v，want INFO", record["level"])
	}
	// 時間戳與協議同格式（24 字元、含毫秒、Z 結尾），才能與 /time 及資料庫欄位直接比對。
	if stamp, _ := record["time"].(string); len(stamp) != 24 || !strings.HasSuffix(stamp, "Z") {
		t.Errorf("time = %q，應為 24 字元且以 Z 結尾", stamp)
	} else if stamp != "2026-09-26T12:34:56.789Z" {
		t.Errorf("time = %q，應取自注入時鐘", stamp)
	}
	if _, ok := record["source"]; !ok {
		t.Error("JSON 記錄應帶呼叫端資訊（source），否則只知道發生了什麼、不知道誰說的")
	}

	human := stderr.String()
	want := "2026-09-26T12:34:56.789Z INFO 服務已啟動 listen=127.0.0.1:5206\n"
	if human != want {
		t.Errorf("人類可讀行不符：\n got %q\nwant %q", human, want)
	}
}

func TestRedactionAppliesToBothSinks(t *testing.T) {
	const leak = "hunter2完整令牌值"
	const jwt = "curl/8.6 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ"
	logger, stderr := newTestLogger(t, "debug")
	logger.Error("登入被拒絕", "password", leak, "session_token", leak, "user_agent", jwt)

	lines := readLogLines(t, logger)
	if len(lines) != 1 {
		t.Fatalf("行數 = %d", len(lines))
	}
	if strings.Contains(lines[0], leak) {
		t.Errorf("JSON 記錄洩漏原值：%s", lines[0])
	}
	if strings.Contains(stderr.String(), leak) {
		t.Errorf("stderr 記錄洩漏原值：%s", stderr.String())
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	if record["password"] != redact.Redacted {
		t.Errorf("password = %v，want %q", record["password"], redact.Redacted)
	}
	if ref, _ := record["session_token"].(string); !strings.HasPrefix(ref, redact.RefPrefix) {
		t.Errorf("session_token = %v，應改記為 %s 短辨識碼", record["session_token"], redact.RefPrefix)
	}
	// user_agent 不是敏感欄位名，但值裡出現 JWT 形狀時仍要被打掉：
	// 鍵名清單只擋得住「大家都知道該叫什麼」的欄位，標頭與錯誤訊息得靠值形狀。
	agent, _ := record["user_agent"].(string)
	if strings.Contains(agent, "eyJhbGciOiJIUzI1NiJ9") {
		t.Errorf("user_agent 裡的 JWT 未被遮罩：%q", agent)
	}
	if !strings.HasPrefix(agent, "curl/8.6 "+redact.RefPrefix) {
		t.Errorf("user_agent 的非憑證部分被一起抹掉了：%q", agent)
	}
}

func TestMessageAndGroupsAreRedacted(t *testing.T) {
	logger, stderr := newTestLogger(t, "debug")
	const leak = "9f8e7d6c5b4a3210fedcba9876543210"
	logger.With(slog.Group("session", slog.String("token", leak))).
		Warn("解析標頭失敗 Authorization: Bearer " + leak)

	human := stderr.String()
	if strings.Contains(human, leak) {
		t.Errorf("群組欄位或訊息洩漏：%q", human)
	}
	lines := readLogLines(t, logger)
	if len(lines) != 1 {
		t.Fatalf("行數 = %d", len(lines))
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	group, ok := record["session"].(map[string]any)
	if !ok {
		t.Fatalf("群組結構未保留（記錄變成 %v）", record)
	}
	if ref, _ := group["token"].(string); !strings.HasPrefix(ref, redact.RefPrefix) {
		t.Errorf("session.token = %v，應改記為短辨識碼", group["token"])
	}
	if _, exists := group["session.token"]; exists {
		t.Error("群組內的鍵名被展平重複了一次")
	}
}

func TestLevelFiltering(t *testing.T) {
	for _, tc := range []struct {
		level   string
		kept    []slog.Level
		dropped []slog.Level
	}{
		{"debug", []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}, nil},
		{"info", []slog.Level{slog.LevelInfo, slog.LevelWarn, slog.LevelError}, []slog.Level{slog.LevelDebug}},
		{"warn", []slog.Level{slog.LevelWarn, slog.LevelError}, []slog.Level{slog.LevelDebug, slog.LevelInfo}},
		{"error", []slog.Level{slog.LevelError}, []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn}},
	} {
		logger, stderr := newTestLogger(t, tc.level)
		for _, level := range append(append([]slog.Level{}, tc.kept...), tc.dropped...) {
			logger.Log(context.Background(), level, "層級測試", "level", level.String())
		}
		if got, want := len(readLogLines(t, logger)), len(tc.kept); got != want {
			t.Errorf("層級 %s：日誌檔案行數 = %d，want %d", tc.level, got, want)
		}
		if got, want := lines(stderr.String()), len(tc.kept); got != want {
			t.Errorf("層級 %s：stderr 行數 = %d，want %d", tc.level, got, want)
		}
	}
}

func TestHumanOutputCannotForgeLines(t *testing.T) {
	logger, stderr := newTestLogger(t, "info")
	// 客戶端可控的文字（路徑、標頭、錯誤訊息）可能帶換行：
	// 原樣送出的話就能在日誌裡捏造出額外行，把排錯引到別處。
	logger.Info("多行\n訊息", "path", "/a\nFAKE ERROR 攻擊", "ua", "x\t\"y\"\\z")

	out := stderr.String()
	if lines := strings.Count(out, "\n"); lines != 1 {
		t.Errorf("stderr 行數 = %d，want 1：%q", lines, out)
	}
	if !strings.Contains(out, `\nFAKE ERROR 攻擊`) || !strings.Contains(out, `\t`) {
		t.Errorf("控制字元未被跳脫，輸出仍會換行：%q", out)
	}
	// 含空白或跳脫字的值必須加引號，否則 key=value 的邊界本身就讀不出來。
	if !strings.Contains(out, `path="/a\nFAKE ERROR 攻擊"`) {
		t.Errorf("含空白的值未加引號：%q", out)
	}

	// JSON 那份由 encoding/json 自己跳脫，取回後應逐字等於原值（含換行）。
	lines := readLogLines(t, logger)
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("日誌檔案不是合法 JSON：%v", err)
	}
	if record["path"] != "/a\nFAKE ERROR 攻擊" {
		t.Errorf("JSON 記錄的 path = %q", record["path"])
	}
}

func TestValueKindsSurvive(t *testing.T) {
	logger, stderr := newTestLogger(t, "debug")
	logger.Info("型別測試",
		slog.Int("status", 503),
		slog.Bool("guard", true),
		slog.Duration("elapsed", 12*time.Millisecond),
		slog.Any("err", errors.New("資料庫無法回應")))

	lines := readLogLines(t, logger)
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	if record["status"] != float64(503) {
		t.Errorf("status = %#v，整數不應被壓成字串", record["status"])
	}
	if record["guard"] != true {
		t.Errorf("guard = %#v", record["guard"])
	}
	// 歷時在 JSON 裡是奈秒數字（12000000）——這是標準庫 JSONHandler 對 KindDuration 的
	// 原有編法，本層不改造它；要可讀的形狀走人類可讀那份（12ms）。
	if record["elapsed"] != float64(12_000_000) {
		t.Errorf("elapsed = %#v，want 12000000（奈秒）", record["elapsed"])
	}
	if !strings.Contains(stderr.String(), "elapsed=12ms") {
		t.Error("人類可讀份的歷時應寫成 12ms")
	}
	if record["err"] != "資料庫無法回應" {
		t.Errorf("err = %#v", record["err"])
	}
}

// TestBoundAttrsAreRedacted 固定一處側門：以 logger.With 綁定的欄位不再經過 Handle，
// 必須在綁定的當下就遮罩好。
func TestBoundAttrsAreRedacted(t *testing.T) {
	const leak = "hunter2-from-with"
	logger, stderr := newTestLogger(t, "debug")

	logger.With("password", leak, "request_id", "0198c2f4-7a3e-7b21-9c8d-1e2f3a4b5c6d").
		Info("綁定欄位的記錄")
	out := stderr.String()
	if strings.Contains(out, leak) {
		t.Errorf("With 綁定的敏感欄位未被遮罩：%q", out)
	}
	// 關聯 ID 不屬於憑據，被一起遮掉的話日誌就失去對應回應的那把鑰匙。
	if !strings.Contains(out, "request_id=0198c2f4-7a3e-7b21-9c8d-1e2f3a4b5c6d") {
		t.Errorf("request_id 不應被遮罩：%q", out)
	}

	// 群組名也會決定敏感度：WithGroup 之後的欄位要按「群組.鍵名」判定。
	const idLeak = "sess-9f8e7d6c5b4a3210fedcba"
	logger.WithGroup("session").Info("群組綁定", "id", idLeak)
	if strings.Contains(stderr.String(), idLeak) {
		t.Errorf("session.id 應按 %s 短辨識碼記錄：%q", redact.RefPrefix, stderr.String())
	}
}

func TestErrorLogWriterFeedsSamePipeline(t *testing.T) {
	logger, stderr := newTestLogger(t, "debug")
	// net/http 的 ErrorLog 只收 *log.Logger：經本適配器進來一樣走脫敏。
	stdlib := log.New(logger.ErrorLogWriter(slog.LevelWarn), "", 0)
	stdlib.Printf("http: URL query contains semicolon: token=abc123def456ghi789")

	human := stderr.String()
	if strings.Contains(human, "abc123def456ghi789") {
		t.Errorf("標準庫出口洩漏憑證：%q", human)
	}
	if !strings.Contains(human, "WARN") || !strings.Contains(human, "http: URL query contains semicolon") {
		t.Errorf("標準庫訊息未成記錄：%q", human)
	}
	if strings.Contains(human, "2026/") || strings.Contains(human, "0001/") {
		t.Errorf("適配器不應外加時間前綴（時間由記錄攜帶）：%q", human)
	}
	lines := readLogLines(t, logger)
	if len(lines) != 1 {
		t.Fatalf("行數 = %d", len(lines))
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	if record["level"] != "WARN" {
		t.Errorf("level = %v，want WARN", record["level"])
	}
}

func TestFanoutWritesOthersWhenOneFails(t *testing.T) {
	var ok bytes.Buffer
	failing := errWriter{}
	multi := &fanoutHandler{handlers: []slog.Handler{
		newHumanHandler(failing, slog.LevelDebug, nil),
		newHumanHandler(&ok, slog.LevelDebug, nil),
	}}
	rec := slog.NewRecord(fixedClock(), slog.LevelError, "兩個下游都該看見", 0)
	if err := multi.Handle(nil, rec); err == nil {
		t.Error("下游失敗時應合併回傳錯誤")
	}
	if !strings.Contains(ok.String(), "兩個下游都該看見") {
		t.Errorf("另一個下游未寫入：%q", ok.String())
	}
}

func TestWithAttrsAndGroupOnRedactingChain(t *testing.T) {
	logger, stderr := newTestLogger(t, "debug")
	scoped := logger.With("component", "httpapi").WithGroup("request")
	scoped.Info("帶上下文", "method", "GET")

	human := stderr.String()
	if !strings.Contains(human, "component=httpapi") || !strings.Contains(human, "method=GET") {
		t.Errorf("附加欄位或群組遺漏：%q", human)
	}
	if !strings.Contains(human, "request.method=GET") {
		t.Errorf("群組名應出現在展平的鍵名前：%q", human)
	}
}

func TestOpenRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		opts    Options
		wantSub string
	}{
		{"層級未知", Options{Dir: dir, Level: "verbose"}, "logs.level"},
		{"層級為空", Options{Dir: dir, Level: ""}, "logs.level"},
		{"目錄為空", Options{Dir: "", Level: "info"}, "logs.dir"},
		{"前綴含路徑分隔符", Options{Dir: dir, Level: "info", FilePrefix: "a" + string(rune(0x5C)) + "b"}, "禁忌字元"},
		{"前綴是相對目錄", Options{Dir: dir, Level: "info", FilePrefix: ".."}, "前綴不可為"},
		{"前綴含 Windows 保留字元", Options{Dir: dir, Level: "info", FilePrefix: "run:1"}, "禁忌字元"},
		{"保留天數為負", Options{Dir: dir, Level: "info", RetentionDays: -1}, "不可為負數"},
		{"目錄不可用", Options{Dir: blocker, Level: "info"}, "not-a-dir"},
	}
	for _, tc := range cases {
		logger, err := Open(tc.opts)
		if err == nil {
			if logger != nil {
				_ = logger.Close()
			}
			t.Errorf("%s：應開啟失敗", tc.name)
			continue
		}
		if logger != nil {
			t.Errorf("%s：失敗時不應回傳記錄器", tc.name)
		}
		if !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s：錯誤訊息未指出 %q：%v", tc.name, tc.wantSub, err)
		}
	}
}

func TestOpenAppendsAcrossReopenAndClosesIdempotently(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	first, err := Open(Options{Dir: dir, Level: "info", Stderr: io.Discard, Now: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	first.Info("第一筆")
	if err := first.Close(); err != nil {
		t.Fatalf("Close 失敗：%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("重複 Close 不應產生新錯誤：%v", err)
	}

	second, err := Open(Options{Dir: dir, Level: "info", Stderr: io.Discard, Now: fixedClock})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.Path() != first.Path() {
		t.Errorf("重開後的檔名不同：%s 對 %s", second.Path(), first.Path())
	}
	if base := filepath.Base(second.Path()); !strings.HasSuffix(base, ".log") || !strings.HasPrefix(base, DefaultFilePrefix+".") {
		t.Errorf("預設檔名形狀不符：%q（應為 <前綴>.<日期>.log）", base)
	}
	second.Info("第二筆")
	lines := readLogLines(t, second)
	if len(lines) != 2 || !strings.Contains(lines[0], "第一筆") || !strings.Contains(lines[1], "第二筆") {
		t.Errorf("重開應接在上一次之後而不是蓋掉：%v", lines)
	}
}

func TestParseLevel(t *testing.T) {
	for name, want := range map[string]slog.Level{
		"debug":  slog.LevelDebug,
		"INFO":   slog.LevelInfo,
		" warn ": slog.LevelWarn,
		"error":  slog.LevelError,
	} {
		got, err := ParseLevel(name)
		if err != nil {
			t.Errorf("ParseLevel(%q) 失敗：%v", name, err)
			continue
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v，want %v", name, got, want)
		}
	}
	for _, name := range []string{"", "verbose", "trace", "fatal", "infos"} {
		if _, err := ParseLevel(name); err == nil {
			t.Errorf("ParseLevel(%q) 應回傳錯誤", name)
		}
	}
}

func TestWriterLoggerRedactsAndKeepsAllLevels(t *testing.T) {
	var out bytes.Buffer
	logger := WriterLogger(&out)
	logger.Debug("除錯也留", "pin", "4821")
	human := out.String()
	if strings.Contains(human, "4821") {
		t.Errorf("pin 未被遮罩：%q", human)
	}
	if !strings.Contains(human, "DEBUG") {
		t.Errorf("WriterLogger 不應過濾層級：%q", human)
	}
}

func TestConcurrentRecordsAreNotInterleaved(t *testing.T) {
	logger, stderr := newTestLogger(t, "debug")
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			logger.Info("併發記錄", "n", n)
		}(i)
	}
	wg.Wait()

	const wantLines = 32
	if got := lines(stderr.String()); got != wantLines {
		t.Errorf("stderr 行數 = %d，want %d（一行一記錄，交錯就會對不上）", got, wantLines)
	}
	if got := len(readLogLines(t, logger)); got != wantLines {
		t.Errorf("日誌檔案行數 = %d，want %d", got, wantLines)
	}
}

// lines 回傳字串中的完整行數（尾端換行算一行結束，不另計空行）。
func lines(text string) int {
	if text == "" {
		return 0
	}
	return strings.Count(text, "\n")
}

// errWriter 是永遠寫失敗的寫入器，用以驗證一個下游故障不拖垮另一個。
type errWriter struct{}

// Write 恆回傳錯誤。
func (errWriter) Write([]byte) (int, error) { return 0, errors.New("磁碟已滿") }
