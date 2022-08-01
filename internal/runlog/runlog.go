// Package runlog 提供服務端的結構化運行日誌：統一出口、層級過濾與寫出前的脫敏管線。
//
// 一次記錄同時落到兩個地方：資料目錄 logs/ 下的日誌檔案（JSON 行，供程式判讀）
// 與標準錯誤輸出（一行人類可讀，供本機 Ctrl+C 終端直接看懂）。兩邊寫的是同一份
// 已脫敏的記錄，因此不會出現「畫面說有、檔案說沒有」這類查不清的分歧。
//
// 本套件負責的是「發生了什麼事」，不是業務狀態：
//   - 時刻一律正規化為 UTC（規格 §27.2、DEC-015），與資料庫及協議的時間戳同一格式；
//   - 值在離開本套件前一律過 redact.go 的管線（實作 ER-SEC-001 §7），
//     呼叫端不需要、也不被允許自己決定哪些文字可以進日誌；
//   - 普通日誌與不可變的審計記錄是兩個體系（規格 §32）：本套件的輸出可輪轉、可淘汰，
//     審計記錄的存放與保留由各自的子系統負責，絕不共用這條管線。
package runlog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// Options 為 Open 的輸入；零值欄位採用註解所述預設。
type Options struct {
	// Dir 為日誌目錄（組態已解析為絕對路徑）；空值視為設定錯誤而拒絕開啟。
	Dir string
	// FilePrefix 為日誌檔名前綴；空值採用 DefaultFilePrefix。
	// 實際檔案名為 `<前綴>.<YYYY-MM-DD>.log`，因此不得含路徑分隔符或檔案系統禁忌字元。
	FilePrefix string
	// Level 為最低記錄層級（debug|info|warn|error），空值或不合法即開啟失敗——
	// 靜默退回預設層級會讓部署者以為自己開了 debug，實際沒有。
	Level string
	// RetentionDays 為日誌保留天數（含當日）；0 表示不限制（預設，不自動刪除任何檔案）。
	// 淘汰只認得本套件自己的檔名形狀，目錄裡的別的檔案一律不動（規格 §32：審計不隨日誌清理）。
	RetentionDays int
	// Location 為「自然日」的判定時區；nil 時用 UTC。
	// 正式路徑由組合層給 server.display_timezone，與 /time 報給客戶端的「今天」同一個來源。
	Location *time.Location
	// Stderr 為人類可讀那份的寫入器；nil 時使用 os.Stderr。
	// 傳入 io.Discard 即只留日誌檔案一份；換日與保留清理的維護訊息也走同一個去處。
	Stderr io.Writer
	// Now 為時刻來源；nil 時沿用記錄產生時的時鐘。
	// 測試注入固定時鐘以逐字比對輸出行，也以它驗證跨日切檔。
	Now func() time.Time
}

// Logger 持有運行日誌的記錄器與其所寫入的檔案；零值不可用，請經 Open 取得。
type Logger struct {
	*slog.Logger

	// sink 為日誌檔案的寫入器（關閉由本型別負責）。
	sink io.WriteCloser
	// path 為開啟當時的檔案路徑，供不認識 daySink 的場合兜底（Path() 一律優先問 sink）。
	path string
	// mu 保護 closed/closeErr，使重複 Close 有確定行為。
	mu       sync.Mutex
	closed   bool
	closeErr error
}

// Open 建立日誌目錄（如缺）與當日檔案，回傳已接好兩個寫出器的記錄器。
//
// 目錄或檔案無法建立時回傳點出路徑的錯誤，不降級為「只寫 stderr」：
// 部署者既然設了 logs.dir，日誌落在別處比落在哪裡更難查。
func Open(opts Options) (*Logger, error) {
	level, err := ParseLevel(opts.Level)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(opts.Dir) == "" {
		return nil, errors.New("runlog: logs.dir 不可為空")
	}
	prefix := opts.FilePrefix
	if prefix == "" {
		prefix = DefaultFilePrefix
	}
	if err := validateFilePrefix(prefix); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("runlog: 建立日誌目錄 %s 失敗: %w", opts.Dir, err)
	}

	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	// 檔案那份經 daySink 落地：它負責換日與保留淘汰，寫入器介面對 slog 來說是同一個 io.Writer。
	sink, err := newDaySink(opts.Dir, prefix, opts.Location, opts.Now, opts.RetentionDays, stderr)
	if err != nil {
		return nil, fmt.Errorf("runlog: %w", err)
	}

	fileHandler := slog.NewJSONHandler(sink, &slog.HandlerOptions{
		Level:       level,
		AddSource:   true,
		ReplaceAttr: formatTimeAsUTC,
	})
	human := newHumanHandler(stderr, level, nil)
	handler := newRedacting(&fanoutHandler{handlers: []slog.Handler{fileHandler, human}}, opts.Now)

	return &Logger{Logger: slog.New(handler), sink: sink, path: sink.Path()}, nil
}

// 檔案系統禁忌字元的碼位（路徑分隔符、Windows 保留字元、DEL）。
// 以碼位寫而不用字面量：反斜線在原始碼與腳本之間最容易被吞掉一層跳脫，
// 而這條規則的全部內容就是幾個標點。
var illegalNameChars = map[rune]bool{
	0x2F: true, 0x5C: true, 0x3A: true, 0x2A: true,
	0x3F: true, 0x22: true, 0x3C: true, 0x3E: true,
	0x7C: true, 0x7F: true,
}

// validateFilePrefix 檢查前綴能安全拼進檔案名（<前綴>.YYYY-MM-DD.log）。
//
// config 那邊已有同樣的校驗；這裡再擋一次是因為 runlog 直接面對檔案系統，
// 不能假設每個呼叫者都走過組態校驗（測試、日後的一次性命令都算直接呼叫者）。
func validateFilePrefix(prefix string) error {
	if prefix == "." || prefix == ".." {
		return fmt.Errorf("runlog: 日誌檔名前綴不可為 %q", prefix)
	}
	if len(prefix) > 64 {
		return fmt.Errorf("runlog: 日誌檔名前綴過長（%d 個字元，上限 64）", len(prefix))
	}
	for _, r := range prefix {
		if illegalNameChars[r] {
			return fmt.Errorf("runlog: 日誌檔名前綴含檔案系統禁忌字元（0x%02X）: %q", r, prefix)
		}
		if r < 0x20 {
			return fmt.Errorf("runlog: 日誌檔名前綴含控制字元（0x%02X）: %q", r, prefix)
		}
	}
	return nil
}

// Path 回傳目前正要寫入的日誌檔案路徑（跨日後跟著換日檔案改變）。
func (l *Logger) Path() string {
	if sink, ok := l.sink.(*daySink); ok {
		return sink.Path()
	}
	return l.path
}

// Close 關閉日誌檔案；重複關閉回傳第一次的結果，不產生新的錯誤。
//
// 正常結束碼路徑一定要走到這裡，否則 Windows 上殘留的檔案句柄會讓後續的
// 手動輪替或刪除動作回報「使用中」。
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return l.closeErr
	}
	l.closed = true
	if l.sink != nil {
		l.closeErr = l.sink.Close()
	}
	return l.closeErr
}

// formatTimeAsUTC 把 JSON 記錄的時間戳改成與協議一致的寫法（恆含三位毫秒、以 Z 結尾）。
//
// 預設的 slog 輸出帶奈秒，字元數不固定；統一成 timeutil 的格式後，
// 日誌裡的時間字串才能與 /time 的回應以及資料庫欄位直接比對。
func formatTimeAsUTC(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
		return slog.String(slog.TimeKey, timeutil.FormatUTC(a.Value.Time()))
	}
	return a
}

// ParseLevel 把組態的層級名稱轉成 slog 層級。
//
// 這是一份映射而非第二組校驗：config 那邊仍要拒絕未知值（啟動階段就報出來），
// 本方法負責「合法值怎麼用」，兩邊的一致性由 config 的測試固定
// ——清單各寫一份時，漏更新的那一份不會讓建置失敗，只會讓某個層級悄悄失效。
func ParseLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelError, fmt.Errorf("runlog: logs.level 需為 debug|info|warn|error，實際為 %q", name)
	}
}

// WriterLogger 建立把已脫敏記錄以人類可讀格式寫入 w 的記錄器（不限層級）。
//
// 供測試逐字取回輸出，以及不需要同時落檔的場合（一次性命令的自我記錄）。
func WriterLogger(w io.Writer) *slog.Logger {
	return slog.New(newRedacting(newHumanHandler(w, slog.LevelDebug, nil), nil))
}

// ErrorLogWriter 回傳一個寫入器：任何經標準庫 log.Logger 送進來的整行訊息，
// 都會以 level 記成一筆結構化記錄，從而走同一條脫敏管線。
//
// net/http 的 http.Server.ErrorLog 只收 *log.Logger，而它的訊息內容是任意文字
// （畸形請求行、無法解析的 URL 都會被原帶出來），因此這條出口不能繞過脫敏。
// 呼叫端以 log.New(w, "", 0) 包住即可，前綴留空：時間由記錄本身攜帶，
// 兩份時間戳會讓人分不清事件時刻與寫入時刻。
func (l *Logger) ErrorLogWriter(level slog.Level) io.Writer {
	return &errorLogWriter{logger: l.Logger, level: level}
}

// errorLogWriter 是 log.Logger 到 slog 記錄的適配寫入器。
type errorLogWriter struct {
	logger *slog.Logger
	level  slog.Level
}

// Write 把一整行訊息（尾端換行移除）作為記錄訊息送出；空行不產生記錄。
// 回傳長度恆等於輸入長度，使 log.Logger 不會把寫入器的處理誤判為失敗。
func (w *errorLogWriter) Write(p []byte) (int, error) {
	message := strings.TrimRight(string(p), "\r\n")
	if message != "" {
		w.logger.Log(context.Background(), w.level, message)
	}
	return len(p), nil
}
