package runlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// zonePlus8 為固定 +08:00 的顯示時區（不用 IANA 名稱，避免測試依賴系統 tzdata）。
var zonePlus8 = time.FixedZone("UTC+8", 8*3600)

// testClock 為可推進的時鐘：跨日測試要能把「今天」精確推到明天。
type testClock struct {
	mu sync.Mutex
	at time.Time
}

// Now 回傳當前設定時刻。
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

// Set 直接把時刻推到某一個 UTC 瞬間。
func (c *testClock) Set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = at
}

// newRotatingLogger 建立以 clock 為準、按顯示時區分檔的記錄器。
func newRotatingLogger(t *testing.T, dir, prefix string, days int, clock *testClock, stderr io.Writer) *Logger {
	t.Helper()
	lg, err := Open(Options{
		Dir:           dir,
		FilePrefix:    prefix,
		Level:         "debug",
		RetentionDays: days,
		Location:      zonePlus8,
		Stderr:        stderr,
		Now:           clock.Now,
	})
	if err != nil {
		t.Fatalf("Open 失敗：%v", err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	return lg
}

// mustDate 把「顯示時區的某一天」表示成 UTC 瞬間（正午，避開邊界）。
func mustDate(t *testing.T, ymd string) time.Time {
	t.Helper()
	parsed, err := time.ParseInLocation("2006-01-02 15:04:05", ymd+" 12:00:00", zonePlus8)
	if err != nil {
		t.Fatalf("解析日期 %s 失敗：%v", ymd, parsed)
	}
	return parsed.UTC()
}

func TestLogFileNameShape(t *testing.T) {
	at := time.Date(2026, 9, 26, 23, 30, 0, 0, time.UTC)
	if got := LogFileName("evernight-run", at, time.UTC); got != "evernight-run.2026-09-26.log" {
		t.Errorf("UTC 檔名 = %q", got)
	}
	// 同一瞬間在 +08:00 已經是 27 日：分檔跟顯示時區，記錄內容仍是 UTC。
	if got := LogFileName("evernight-run", at, zonePlus8); got != "evernight-run.2026-09-27.log" {
		t.Errorf("+08:00 檔名 = %q", got)
	}
	if got := LogFileName("", at, nil); got != DefaultFilePrefix+".2026-09-26.log" {
		t.Errorf("零值前綴與零值時區的檔名 = %q", got)
	}
}

// TestRolloverOnCalendarDayChange 驗證跨日那條記錄把檔案切過去，而不是等重啟。
func TestRolloverOnCalendarDayChange(t *testing.T) {
	dir := filepath.Join(retryTempDir(t), "logs")
	clock := &testClock{at: time.Date(2026, 9, 26, 15, 0, 0, 0, time.UTC)} // +08:00 → 23:00，仍屬 26 日
	var stderr bytes.Buffer
	lg := newRotatingLogger(t, dir, "run", 0, clock, &stderr)

	lg.Info("今日最後一條")
	first := lg.Path()
	if base := filepath.Base(first); base != "run.2026-09-26.log" {
		t.Fatalf("第一份檔名 = %q", base)
	}

	// 推進到 +08:00 的次日凌晨（UTC 16:30 → 當地 00:30）。
	clock.Set(time.Date(2026, 9, 26, 16, 30, 0, 0, time.UTC))
	lg.Info("次日第一條")
	second := lg.Path()
	if base := filepath.Base(second); base != "run.2026-09-27.log" {
		t.Fatalf("換日後檔名 = %q", base)
	}
	if second == first {
		t.Fatal("換日後仍指向同一個檔案")
	}

	// 內容各自回家：舊檔不再被寫入，新檔從頭開始。
	oldData := readFile(t, first)
	newData := readFile(t, second)
	if strings.Contains(newData, "今日最後一條") || !strings.Contains(oldData, "今日最後一條") {
		t.Errorf("換日前的記錄跑到了新檔：%s / %s", oldData, newData)
	}
	if !strings.Contains(newData, "次日第一條") || strings.Contains(oldData, "次日第一條") {
		t.Errorf("換日後的記錄沒進新檔：%s / %s", oldData, newData)
	}
	// 記錄裡的時刻仍是 UTC（DEC-015），與檔名的當地日期刻意不對齊。
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimRight(newData, "\n")), &rec); err != nil {
		t.Fatalf("新檔不是合法 JSON：%v", err)
	}
	if rec["time"] != "2026-09-26T16:30:00.000Z" {
		t.Errorf("新檔記錄的時刻 = %v，應為 UTC 原值", rec["time"])
	}
	if out := stderr.String(); strings.Contains(out, "換日失敗") {
		t.Errorf("正常換日不應回報失敗：%q", out)
	}
}

// TestRetentionDeletesOnlyOwnDatedFiles 驗證淘汰只認得自己的檔名形狀。
//
// 這條就是「不清理永久審計帳本」的落點：普通日誌可淘汰，
// 同一目錄裡的審計檔、別人的檔、甚至目錄本身，一個位元組都不該被碰。
func TestRetentionDeletesOnlyOwnDatedFiles(t *testing.T) {
	dir := filepath.Join(retryTempDir(t), "logs")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	clock := &testClock{at: mustDate(t, "2026-09-26")}

	// 保留 3 天、今天為 26 日 → 保留線是 24 日；25/24 要留住，20 日與 1999 年要刪掉。
	ownOld := []string{"run.2026-09-25.log", "run.2026-09-24.log", "run.2026-09-20.log", "run.1999-01-01.log"}
	foreign := []string{
		"audit.2026-09-20.log",   // 別的前綴：同為「日期檔」也不歸本套件管
		"evernight-run.log",      // 換日分檔之前的舊檔形狀
		"run.2026-09-20.log.tmp", // 半途中止的寫檔
		"run.2026-13-45.log",     // 日期不合法：解不出來就不算自己的檔
		"run.2026-09-20.log",     // 同前綴但日期在保留線外 → 這個會被刪（列在 ownOld）
		"keepme.txt",             // 完全無關的檔案
		"run.20-09-26.log",       // 日期形狀不對
		"audit-2026-09-01.log",   // 另一種審計命名
		"run.2026-09-26.log",     // 今天的檔：正在寫，永不列入刪除
	}
	for _, name := range append(append([]string{}, ownOld...), foreign...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("舊內容 "+name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// 一個與日誌檔同名的目錄：os.Remove 對非空目錄會失敗，
	// 但本函式根本不該把它當檔案——這是「誤把目錄當舊檔刪」的負向對照。
	if err := os.MkdirAll(filepath.Join(dir, "run.2000-01-01.log"), 0o750); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	lg := newRotatingLogger(t, dir, "run", 3, clock, &stderr)
	lg.Info("今天的記錄")
	_ = lg.Close()

	for _, name := range ownOld {
		if name == "run.2026-09-25.log" || name == "run.2026-09-24.log" {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Errorf("保留線內的 %s 被刪掉了：%v", name, err)
			}
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("過期的 %s 未被刪除（err=%v）", name, err)
		}
	}
	for _, name := range foreign {
		if name == "run.2026-09-20.log" || name == "run.2026-09-26.log" {
			continue // 前者過期應刪，後者是今天的檔
		}
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("不屬於本套件的 %s 被動過了：%v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "run.2000-01-01.log")); err != nil {
		t.Errorf("同名目錄被動過了：%v", err)
	}
	// 今天的內容還在
	data := readFile(t, filepath.Join(dir, "run.2026-09-26.log"))
	if !strings.Contains(data, "今天的記錄") {
		t.Errorf("今天的檔案內容不符：%s", data)
	}
	if !strings.Contains(stderr.String(), "已刪除 2 份過期檔案（保留 3 天）") {
		t.Errorf("清理結果未回報：%q", stderr.String())
	}
}

// TestRetentionUnlimitedDeletesNothing 驗證預設值（0）真的不自動刪任何東西——
// 這是部署者選定的取向，測試要能把「不小心設成 0 就全刪光」這種反轉擋住。
func TestRetentionUnlimitedDeletesNothing(t *testing.T) {
	dir := filepath.Join(retryTempDir(t), "logs")
	old := filepath.Join(dir, "run.2010-01-01.log")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte("十年前的記錄\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	clock := &testClock{at: mustDate(t, "2026-09-26")}
	lg := newRotatingLogger(t, dir, "run", 0, clock, &stderr)
	lg.Info("現在")
	_ = lg.Close()

	if _, err := os.Stat(old); err != nil {
		t.Errorf("retention_days=0 卻刪了舊檔：%v", err)
	}
	if strings.Contains(stderr.String(), "清理") {
		t.Errorf("不限制時不應回報清理：%q", stderr.String())
	}
}

// TestRolloverFailureKeepsWriting 驗證換日開檔失敗時日誌不中斷，而且看得見出錯。
//
// 製造方式：把「明天那份檔案」的位置先佔成一個目錄——OpenFile 必定失敗。
// 這時正確的做法是繼續寫在還開著的檔案裡並回報，而不是讓記錄整條消失。
func TestRolloverFailureKeepsWriting(t *testing.T) {
	dir := filepath.Join(retryTempDir(t), "logs")
	clock := &testClock{at: mustDate(t, "2026-09-26")}
	var stderr bytes.Buffer
	lg := newRotatingLogger(t, dir, "run", 0, clock, &stderr)

	// 明天的檔名位置放一個目錄：在那個位置上建立檔案必定失敗（目錄不是檔案）。
	tomorrow := time.Date(2026, 9, 27, 12, 0, 0, 0, zonePlus8)
	if err := os.MkdirAll(filepath.Join(dir, fmt.Sprintf("run.%s.log", tomorrow.In(zonePlus8).Format("2006-01-02"))), 0o750); err != nil {
		t.Fatal(err)
	}

	clock.Set(time.Date(2026, 9, 27, 4, 0, 0, 0, time.UTC)) // 當地 12:00，已是 27 日
	lg.Warn("跨日後的一條記錄")

	note := stderr.String()
	if !strings.Contains(note, "日誌換日失敗") {
		t.Errorf("換日失敗未回報：%q", note)
	}
	data := readFile(t, lg.Path())
	if !strings.Contains(data, "跨日後的一條記錄") {
		t.Errorf("換日失敗後記錄被丟棄：%s", data)
	}
	if filepath.Base(lg.Path()) != "run.2026-09-26.log" {
		t.Errorf("失敗後路徑被改掉：%q", lg.Path())
	}
}

// TestRotationConcurrentWritesKeepEveryLine 驗證跨日與併發同時發生時每條記錄都落了地。
func TestRotationConcurrentWritesKeepEveryLine(t *testing.T) {
	dir := filepath.Join(retryTempDir(t), "logs")
	clock := &testClock{at: mustDate(t, "2026-09-26")}
	var stderr bytes.Buffer
	lg := newRotatingLogger(t, dir, "run", 0, clock, &stderr)

	var wg sync.WaitGroup
	const perBurst = 40
	for burst := 0; burst < 3; burst++ {
		for i := 0; i < perBurst; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				lg.Info("併發記錄", "n", n)
			}(i)
		}
		// 每輪之後推進半天，讓寫入真的跨越顯示時區的日期邊界。
		clock.Set(clock.Now().Add(12 * time.Hour))
	}
	wg.Wait()

	total := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data := readFile(t, filepath.Join(dir, entry.Name()))
		total += strings.Count(data, "\n")
	}
	if want := 3 * perBurst; total != want {
		t.Errorf("全部日誌檔案的行數 = %d，want %d（交錯或丟棄就會少）", total, want)
	}
}

// TestOpenRejectsUnsafePrefix 驗證前綴直接在 runlog 這層被擋住（不依賴呼叫端先做組態校驗）。
func TestOpenRejectsUnsafePrefix(t *testing.T) {
	dir := retryTempDir(t)
	cases := []struct {
		name   string
		prefix string
	}{
		{"含正斜線", "logs/run"},
		{"含反斜線", `logs\run`},
		{"相對目錄", ".."},
		{"含冒號", "run:1"},
		{"含萬用字元", "run*"},
		{"含引號", `run"x`},
		{"含換行", "run\nlog"},
		{"過長", strings.Repeat("r", 65)},
	}
	for _, tc := range cases {
		lg, err := Open(Options{Dir: dir, FilePrefix: tc.prefix, Level: "info", Stderr: io.Discard})
		if err == nil {
			_ = lg.Close()
			t.Errorf("%s：應拒絕前綴 %q", tc.name, tc.prefix)
			continue
		}
		if lg != nil {
			t.Errorf("%s：拒絕時不應回傳記錄器", tc.name)
		}
	}
	// 含點的前綴是合法的（moe.yashi.run.2026-09-26.log），清理規則也要認得它。
	prefix := "moe.yashi.run"
	clock := &testClock{at: mustDate(t, "2026-09-26")}
	lg := newRotatingLogger(t, filepath.Join(dir, "logs"), prefix, 0, clock, io.Discard)
	if base := filepath.Base(lg.Path()); base != "moe.yashi.run.2026-09-26.log" {
		t.Errorf("帶點前綴的檔名 = %q", base)
	}
	sink := &daySink{prefix: prefix}
	if _, ok := sink.dateOfName("moe.yashi.run.2026-09-25.log"); !ok {
		t.Error("帶點前綴的舊檔沒被認出來（保留淘汰會漏掉它）")
	}
	if _, ok := sink.dateOfName("moe.yashi.other.2026-09-25.log"); ok {
		t.Error("別的前綴被誤認為自己的檔案")
	}
	_ = lg.Close()
}

func TestDaySinkCloseIsIdempotent(t *testing.T) {
	dir := filepath.Join(retryTempDir(t), "logs")
	clock := &testClock{at: mustDate(t, "2026-09-26")}
	lg := newRotatingLogger(t, dir, "run", 0, clock, io.Discard)
	lg.Info("一條")
	if err := lg.Close(); err != nil {
		t.Fatalf("Close 失敗：%v", err)
	}
	if err := lg.Close(); err != nil {
		t.Fatalf("重複 Close 不應產生新錯誤：%v", err)
	}
	// 關閉後再寫不得 panic，也不得留下一半的檔案內容。
	lg.Info("關閉後的記錄")
	if strings.Contains(readFile(t, lg.Path()), "關閉後的記錄") {
		t.Error("關閉後仍寫入了日誌檔案")
	}
}

// readFile 取回檔案內容（測試專用：讀到空檔要直接失敗，不要讓字串比對假通過）。
func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取 %s 失敗：%v", path, err)
	}
	return string(data)
}
