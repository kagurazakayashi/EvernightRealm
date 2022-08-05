// Package database 提供 SQLite 連線池、單寫入實例約束與連線生命週期管理。
//
// 服務端所有資料庫連線一律由本套件建立，並固定使用決策記錄 DEC-002 的參數組：
// journal_mode=WAL、foreign_keys=1、busy_timeout（組態可調）。
// 同一資料庫同時只允許一個服務程序寫入（規格 §26.3、ADR-004），
// 由資料庫檔旁的作業系統層級檔案鎖強制執行。
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	// 純 Go 的 SQLite 驅動（ADR-004）：無 cgo，跨平台單一執行檔。
	_ "modernc.org/sqlite"
)

// 連線池與逾時參數。
//
// WAL 允許多個讀者與單一寫者並行，因此保留少量連線供讀取；
// 寫入由 SQLite 自身序列化，等待時間由 busy_timeout 決定。
// 閒置連線會持有 WAL 讀取快照並阻礙檢查點回收，故設定閒置回收時間。
const (
	maxOpenConns       = 4
	maxIdleConns       = 4
	connMaxIdleTime    = 5 * time.Minute
	defaultBusyTimeout = 5 * time.Second
	// verifyTimeout 為開啟時驗證 PRAGMA 的期限；避免鎖競爭時啟動無限等待。
	verifyTimeout = 10 * time.Second
)

// Options 為 Open 的輸入參數。
type Options struct {
	// Path 為資料庫檔案路徑；建議使用 config.Resolve 產生的絕對路徑。
	Path string
	// BusyTimeout 為鎖等待超時；0 表示採用預設 5 秒。
	BusyTimeout time.Duration
	// KnownSchemaVersion 為執行檔已知的最高 schema 版本；0 表示不做版本比較。
	KnownSchemaVersion int
	// Preflight 為開庫前預檢模式；零值為 PreflightHeader。
	Preflight Preflight
	// TxPolicy 為交易邊界的預設行為；
	// 零值為 BeginImmediate + NestedReject + 不重試 + 無期限 + 不在交易邊界複驗 schema。
	TxPolicy TxPolicy
	// WriteGuard 在每個寫入交易 BEGIN 之前呼叫，回傳錯誤即不開始交易。
	//
	// nil（預設）表示沒有門。這裡的 nil 與「安全判定可選」不同類：磁碟保護的開關由
	// 組態的兩個下限決定（全為 0 即不啟用），呼叫方在沒啟用時注入 nil 是如實反映設定，
	// 不是留了一條繞過檢查的路。
	WriteGuard func() error
}

// DB 為服務端的資料庫存取入口，持有連線池與單寫入實例鎖。
type DB struct {
	sql       *sql.DB // 寫入池（autocommit 與寫入交易）
	read      *sql.DB // 唯讀池（只讀交易；物理唯讀 mode=ro）
	lock      *fileLock
	path      string
	journal   string
	header    Header
	preflight string
	policy    TxPolicy
	// knownVersion 為執行檔已知的 schema 版本（0 表示不做版本比較），
	// 供交易邊界的 schema 把關使用（schema_guard=transaction）。
	knownVersion int
	// writeGuard 是寫入交易開始前的前置檢查（nil 表示沒有門）。
	//
	// 由呼叫方（internal/app）注入，本套件因此不需要 import 任何監測實作：
	// 儲存層不認識磁碟，正如傳輸層不認識日誌管線（DEC-016、DEC-025 同一條邊界）。
	writeGuard func() error
}

// Open 取得單寫入實例鎖、執行開庫前預檢、建立連線池，並驗證 PRAGMA 實際生效。
//
// 順序刻意為「先取鎖、再預檢、最後開庫」：
// 鎖先於一切，確保同一資料庫同時只有一個服務程序在動作；
// 預檢以純檔案讀取（必要時加唯讀連線）判定檔案是否為本服務資料庫、版本是否相容，
// 不通過時在尚未接觸資料庫前即拒絕，拒絕本身不會改動原檔（規格附錄 E.5）；
// 兩者皆通過才可寫開啟，避免第二個程序或不相容版本對資料庫造成任何寫入。
// 驗證失敗或逾時時會自動釋放已取得的資源，不留殘留鎖。
func Open(ctx context.Context, opts Options) (*DB, error) {
	path := strings.TrimSpace(opts.Path)
	if path == "" {
		return nil, errors.New("database: 資料庫路徑不可為空")
	}
	busyTimeout := opts.BusyTimeout
	if busyTimeout <= 0 {
		busyTimeout = defaultBusyTimeout
	}
	path = filepath.Clean(path)

	lock, err := acquireLock(path)
	if err != nil {
		return nil, err
	}

	header, note, err := preflight(ctx, path, busyTimeout, opts)
	if err != nil {
		_ = lock.release()
		return nil, err
	}

	pool, err := sql.Open("sqlite", dsn(path, busyTimeout, opts.TxPolicy.BeginMode))
	if err != nil {
		_ = lock.release()
		return nil, fmt.Errorf("database: 建立連線池失敗（%s）: %w", path, err)
	}
	tunePool(pool)

	db := &DB{
		sql:          pool,
		lock:         lock,
		path:         path,
		header:       header,
		preflight:    note,
		policy:       opts.TxPolicy,
		writeGuard:   opts.WriteGuard,
		knownVersion: opts.KnownSchemaVersion,
	}
	journal, err := db.verify(ctx, busyTimeout)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	db.journal = journal

	// 唯讀池：供只讀交易使用（BEGIN deferred，不佔寫入鎖）。
	// 以 sql.Open 建立（不立即連線），因此空資料庫在遷移完成後第一次使用時才真正連線。
	readPool, err := sql.Open("sqlite", dsnReadOnly(path, busyTimeout))
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: 建立唯讀連線池失敗（%s）: %w", path, err)
	}
	tunePool(readPool)
	db.read = readPool
	return db, nil
}

// tunePool 設定連線池上限：SQLite 為單檔寫入，過多連線只會增加鎖競爭。
func tunePool(pool *sql.DB) {
	pool.SetMaxOpenConns(maxOpenConns)
	pool.SetMaxIdleConns(maxIdleConns)
	pool.SetConnMaxIdleTime(connMaxIdleTime)
}

// preflight 執行開庫前預檢：檔頭標記（必要時加唯讀版本讀取）。
//
// 回傳的 note 非空時表示預檢降級（唯讀預檢不可用而退回可寫開啟），供啟動輸出提示。
func preflight(ctx context.Context, path string, busyTimeout time.Duration, opts Options) (Header, string, error) {
	header, err := ReadHeader(path)
	if err != nil {
		return Header{}, "", err
	}
	if opts.Preflight == PreflightOff {
		return header, "", nil
	}
	if err := checkHeader(header, opts.KnownSchemaVersion); err != nil {
		return header, "", err
	}
	if opts.Preflight != PreflightReadOnly || !header.Exists || header.Empty {
		return header, "", nil
	}

	version, err := probeSchemaVersion(ctx, path, busyTimeout)
	if err != nil {
		// 唯讀預檢不可用（如 WAL 需回復）：退回可寫開啟，版本仍由版本表把關。
		return header, fmt.Sprintf("唯讀預檢不可用（%v），已改以可寫開啟檢查版本。", err), nil
	}
	if opts.KnownSchemaVersion > 0 && version > opts.KnownSchemaVersion {
		return header, "", fmt.Errorf(
			"%w：唯讀連線所見 schema 版本 %d 高於執行檔已知版本 %d（檔頭標記為 %d）；請改用較新的執行檔",
			ErrSchemaTooNew, version, opts.KnownSchemaVersion, header.SchemaVersion)
	}
	return header, "", nil
}

// verify 確認連線可用且 PRAGMA 實際生效（連線字串與實際狀態不一致時啟動失敗）。
//
// 使用單一專用連線讀取 PRAGMA：連線池可能在多條實體連線上輪替，
// 只有同一條連線上的讀值才能代表連線建立時的實際設定。
func (d *DB) verify(ctx context.Context, busyTimeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	if err := d.sql.PingContext(ctx); err != nil {
		return "", fmt.Errorf("database: 無法連線資料庫 %s: %w", d.path, err)
	}

	conn, err := d.sql.Conn(ctx)
	if err != nil {
		return "", fmt.Errorf("database: 取得驗證連線失敗（%s）: %w", d.path, err)
	}
	defer func() { _ = conn.Close() }()

	var journal string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		return "", fmt.Errorf("database: 讀取 journal_mode 失敗（%s）: %w", d.path, err)
	}
	if !strings.EqualFold(journal, "wal") {
		return "", fmt.Errorf("database: 無法啟用 WAL（journal_mode=%s，%s）；請確認資料目錄可寫且非網路磁碟", journal, d.path)
	}

	var foreignKeys int
	if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return "", fmt.Errorf("database: 讀取 foreign_keys 失敗（%s）: %w", d.path, err)
	}
	if foreignKeys != 1 {
		return "", fmt.Errorf("database: 外鍵約束未啟用（foreign_keys=%d，%s）", foreignKeys, d.path)
	}

	var busy int
	if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy); err != nil {
		return "", fmt.Errorf("database: 讀取 busy_timeout 失敗（%s）: %w", d.path, err)
	}
	if want := int(busyTimeout.Milliseconds()); busy != want {
		return "", fmt.Errorf("database: busy_timeout 未生效（實際 %d ms，預期 %d ms，%s）", busy, want, d.path)
	}
	return strings.ToLower(journal), nil
}

// dsn 依 DEC-002 產生連線字串：file: + URL 編碼路徑 + PRAGMA 參數組。
//
// 路徑必須逐段 URL 編碼：以 "file:" 開頭的 DSN 會被 SQLite 當成 URI 解析並做 %XX 解碼，
// 未編碼的 '%' 與 '#' 會改變實際開啟的檔案（探針 tools/verify/step038-dsn 實證）。
// 參數值為套件自產的固定字串，故直接拼接而不做查詢編碼，以維持與 DEC-002 一致的可讀形式。
//
// _txlock 由驅動在每次 BeginTx 時採用（實證：BEGIN IMMEDIATE 使忙鎖失敗點固定於
// 交易開始前，而非回呼執行到一半；見 tools/verify/step041-tx）。
func dsn(path string, busyTimeout time.Duration, mode BeginMode) string {
	return "file:" + encodeURIPath(path) +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		fmt.Sprintf("&_pragma=busy_timeout(%d)", busyTimeout.Milliseconds()) +
		"&_txlock=" + mode.dsnValue()
}

// encodeURIPath 逐段以 URL 路徑規則編碼，保留 '/' 分隔；Windows 磁碟機代號的 ':' 不編碼。
func encodeURIPath(path string) string {
	slashed := filepath.ToSlash(path)
	parts := strings.Split(slashed, "/")
	for i, part := range parts {
		// 單段編碼：空格→%20、'%'→%25、非 ASCII→UTF-8 %XX；'/' 為分隔符故逐段處理。
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

// dsnReadOnly 產生唯讀連線字串（供預檢與只讀交易使用）。
//
// 唯讀連線不得包含 journal_mode 等會寫入資料庫的 PRAGMA，
// 另以 query_only 確保即使誤用也無法寫入；_txlock=deferred 讓只讀交易不佔寫入鎖。
func dsnReadOnly(path string, busyTimeout time.Duration) string {
	return "file:" + encodeURIPath(path) +
		"?mode=ro" +
		"&_pragma=query_only(1)" +
		fmt.Sprintf("&_pragma=busy_timeout(%d)", busyTimeout.Milliseconds()) +
		"&_txlock=deferred"
}

// SQL 回傳底層連線池，供遷移、倉儲與就緒檢查使用。
func (d *DB) SQL() *sql.DB {
	if d == nil {
		return nil
	}
	return d.sql
}

// Path 回傳資料庫檔案路徑。
func (d *DB) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// JournalMode 回傳開啟時實測的日誌模式（正常為 wal）。
func (d *DB) JournalMode() string {
	if d == nil {
		return ""
	}
	return d.journal
}

// Header 回傳開庫前預檢所得的檔頭辨識結果。
func (d *DB) Header() Header {
	if d == nil {
		return Header{}
	}
	return d.header
}

// PreflightNote 回傳預檢降級提示；空字串表示預檢正常執行。
func (d *DB) PreflightNote() string {
	if d == nil {
		return ""
	}
	return d.preflight
}

// StampApplicationID 在檔頭寫入本服務識別碼（已標記時不寫入）。
//
// 必須在確認資料庫為本服務所有之後呼叫（遷移成功後）：
// 如此一來，對非本服務的資料庫不會留下標記，後續啟動才能繼續以標記攔截。
func (d *DB) StampApplicationID(ctx context.Context) error {
	if d == nil || d.sql == nil {
		return errors.New("database: 資料庫尚未開啟")
	}
	// 以 SQLite 視角判定（含尚未 checkpoint 的 WAL 變更），避免主檔檔頭落後造成重複寫入。
	var current int64
	if err := d.sql.QueryRowContext(ctx, "PRAGMA application_id").Scan(&current); err != nil {
		return fmt.Errorf("database: 讀取資料庫識別碼失敗（%s）: %w", d.path, err)
	}
	if uint32(current) == ApplicationID {
		d.header.ApplicationID = ApplicationID
		return nil
	}
	if _, err := d.sql.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id = %d", ApplicationID)); err != nil {
		return fmt.Errorf("database: 寫入資料庫識別碼失敗（%s）: %w", d.path, err)
	}
	d.header.ApplicationID = ApplicationID
	return nil
}

// CheckIntegrity 執行完整性自檢：integrity_check 必須回報 ok，外鍵不得有違規。
//
// 供啟動時（組態開啟）與 `migrate --verify` 使用；大庫上可能耗時，
// 故不列入每次啟動的必經流程。
func (d *DB) CheckIntegrity(ctx context.Context) error {
	if d == nil || d.sql == nil {
		return errors.New("database: 資料庫尚未開啟")
	}
	rows, err := d.sql.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return fmt.Errorf("database: 完整性檢查失敗（%s）: %w", d.path, err)
	}
	var messages []string
	for rows.Next() {
		var message string
		if err := rows.Scan(&message); err != nil {
			_ = rows.Close()
			return fmt.Errorf("database: 解析完整性檢查結果失敗: %w", err)
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("database: 完整性檢查失敗（%s）: %w", d.path, err)
	}
	_ = rows.Close()
	if len(messages) != 1 || messages[0] != "ok" {
		return fmt.Errorf("database: 資料庫完整性檢查未通過（%s）：%s", d.path, summarize(messages))
	}

	foreignRows, err := d.sql.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("database: 外鍵檢查失敗（%s）: %w", d.path, err)
	}
	defer func() { _ = foreignRows.Close() }()
	var violations []string
	for foreignRows.Next() {
		var table, parent string
		var rowid, fkid sql.NullInt64
		if err := foreignRows.Scan(&table, &rowid, &parent, &fkid); err != nil {
			return fmt.Errorf("database: 解析外鍵檢查結果失敗: %w", err)
		}
		violations = append(violations, fmt.Sprintf("%s(rowid=%d)→%s", table, rowid.Int64, parent))
	}
	if err := foreignRows.Err(); err != nil {
		return fmt.Errorf("database: 外鍵檢查失敗（%s）: %w", d.path, err)
	}
	if len(violations) > 0 {
		return fmt.Errorf("database: 資料庫外鍵違規 %d 筆（%s）：%s", len(violations), d.path, summarize(violations))
	}
	return nil
}

// summarize 將診斷訊息截短為最多 3 筆，避免錯誤訊息過長。
func summarize(items []string) string {
	if len(items) == 0 {
		return "無訊息"
	}
	const limit = 3
	shown := items
	suffix := ""
	if len(items) > limit {
		shown = items[:limit]
		suffix = fmt.Sprintf("（另有 %d 筆）", len(items)-limit)
	}
	return strings.Join(shown, "；") + suffix
}

// Stats 回傳連線池統計，供診斷與就緒檢查使用。
func (d *DB) Stats() sql.DBStats {
	if d == nil {
		return sql.DBStats{}
	}
	return d.sql.Stats()
}

// Ping 確認資料庫仍可回應，供就緒檢查使用。
func (d *DB) Ping(ctx context.Context) error {
	if d == nil || d.sql == nil {
		return errors.New("database: 資料庫尚未開啟")
	}
	return d.sql.PingContext(ctx)
}

// Close 關閉連線池並釋放單寫入實例鎖；可安全重複呼叫。
//
// 先關連線池再放鎖：確保釋放鎖時已無任何連線在寫入資料庫。
func (d *DB) Close() error {
	if d == nil {
		return nil
	}
	var errs []error
	if d.sql != nil {
		if err := d.sql.Close(); err != nil {
			errs = append(errs, fmt.Errorf("database: 關閉連線池失敗: %w", err))
		}
		d.sql = nil
	}
	if d.read != nil {
		if err := d.read.Close(); err != nil {
			errs = append(errs, fmt.Errorf("database: 關閉唯讀連線池失敗: %w", err))
		}
		d.read = nil
	}
	if d.lock != nil {
		if err := d.lock.release(); err != nil {
			errs = append(errs, err)
		}
		d.lock = nil
	}
	return errors.Join(errs...)
}
