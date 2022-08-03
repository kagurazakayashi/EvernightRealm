// 交易執行邊界（STEP-041）。
//
// 設計要點：
//
//   - 回呼式：InTx 取得交易、執行回呼、依回呼結果提交或整體回滾。
//     回呼回傳錯誤或 panic 一律整體回滾，呼叫方無需（也無法）自行提交，
//     避免忘記回滾而長期持有寫入鎖（規格 NFR-010、TRX-004）。
//   - 顯式注入：倉儲方法一律接受 Querier，*sql.DB 與 *Tx 皆滿足，
//     因此同一組倉儲方法既可用於 autocommit，也可在同一交易內組合多個倉儲。
//   - 寫入交易以 BEGIN IMMEDIATE 開始（可配置）：失敗點固定於交易開始前，
//     不會在回呼執行到一半才發現拿不到寫入鎖（實證見 tools/verify/step041-tx）。
//   - 只讀交易走物理唯讀連線池（mode=ro），不會佔用寫入鎖，也不依賴易洩漏的 PRAGMA。
//   - schema 把關：組態 database.schema_guard=transaction 時，寫入交易在回呼執行前
//     複驗資料庫 schema 版本，不符即拒絕整個交易（規格附錄 E.5）。
//
// 契約（組態見 config.example.yaml `database.transaction`）：
//
//   - begin_mode：immediate（預設；失敗點固定於交易開始前，回呼不會執行到一半才失敗）
//     | deferred（首次寫入才取鎖，較容易在回呼中途失敗，不建議）。
//   - nested：reject（預設）| savepoint（真嵌套，內層可獨立回滾）| reuse（加入外層）。
//   - busy_retry_max / busy_retry_backoff_ms：忙鎖重試次數與線性退避（預設 0 / 50ms；
//     重試會重跑整個回呼，僅在交易冪等時開啟）。
//   - timeout_ms：單一交易執行期限（預設 10000ms；逾時整體回滾並回報 ErrTxTimeout）。
//   - schema_guard：startup（預設，僅啟動時把關）| transaction（另於交易邊界複驗）。
//
// 不提供組態的項目（SQLite 語意決定，刻意不做成可調）：
//
//   - 隔離級別固定為 SQLite 的 serializable（驅動不接受 sql.TxOptions.Isolation，
//     設定也只會被忽略或報錯），因此不開放設定。
//   - 提交與回滾一律由本套件決定，呼叫方拿不到 Commit/Rollback（見 Tx）。
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// Querier 為倉儲可用的最小資料庫介面。
//
// *sql.DB（autocommit）與 *Tx（交易內）皆滿足此介面，
// 使同一組倉儲方法能同時服務兩種情境，並讓「同一交易內多個倉儲」成為型別保證。
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// BeginMode 為寫入交易的 BEGIN 模式。
type BeginMode int

const (
	// BeginImmediate 於交易開始即取得寫入鎖（預設）：
	// 忙鎖時在交易開始前即失敗，回呼尚未執行，重試安全。
	BeginImmediate BeginMode = iota
	// BeginDeferred 延到首次寫入才取得寫入鎖：
	// 忙鎖時失敗點落在回呼執行途中（可能已有副作用），不利重試。
	BeginDeferred
)

// String 回傳組態值形式的名稱。
func (m BeginMode) String() string {
	if m == BeginDeferred {
		return "deferred"
	}
	return "immediate"
}

// dsnValue 回傳驅動 DSN 的 _txlock 參數值。
func (m BeginMode) dsnValue() string { return m.String() }

// ParseBeginMode 解析組態值。
func ParseBeginMode(value string) (BeginMode, error) {
	switch value {
	case "immediate", "":
		return BeginImmediate, nil
	case "deferred":
		return BeginDeferred, nil
	default:
		return BeginImmediate, fmt.Errorf("database: 不認識的交易 BEGIN 模式 %q（可用 immediate|deferred）", value)
	}
}

// NestedPolicy 為同一交易內再開交易（嵌套）的行為。
type NestedPolicy int

const (
	// NestedReject 直接拒絕嵌套（預設）：語意無歧義，強制呼叫方顯式傳遞交易。
	NestedReject NestedPolicy = iota
	// NestedSavepoint 以 SAVEPOINT 實現真嵌套：內層可獨立回滾，外層仍可提交。
	NestedSavepoint
	// NestedReuse 加入外層交易：內層失敗需由外層決定是否整體回滾。
	NestedReuse
)

// String 回傳組態值形式的名稱。
func (p NestedPolicy) String() string {
	switch p {
	case NestedSavepoint:
		return "savepoint"
	case NestedReuse:
		return "reuse"
	default:
		return "reject"
	}
}

// ParseNestedPolicy 解析組態值。
func ParseNestedPolicy(value string) (NestedPolicy, error) {
	switch value {
	case "reject", "":
		return NestedReject, nil
	case "savepoint":
		return NestedSavepoint, nil
	case "reuse":
		return NestedReuse, nil
	default:
		return NestedReject, fmt.Errorf("database: 不認識的嵌套交易策略 %q（可用 reject|savepoint|reuse）", value)
	}
}

// TxPolicy 為交易邊界的預設行為（由組態決定，開啟資料庫時固定）。
type TxPolicy struct {
	// BeginMode 為寫入交易的 BEGIN 模式。
	BeginMode BeginMode
	// Nested 為嵌套交易策略。
	Nested NestedPolicy
	// BusyRetryMax 為忙鎖時重試整個交易的次數；0 表示不重試。
	BusyRetryMax int
	// BusyRetryBackoff 為重試的線性退避基數；0 表示立即重試。
	BusyRetryBackoff time.Duration
	// Timeout 為單一交易的執行期限；0 表示不限制。
	Timeout time.Duration
	// GuardSchema 為 true 時，每個寫入交易在回呼執行前複驗 schema 版本
	// （組態 database.schema_guard=transaction）；預設 false，只在啟動時把關。
	GuardSchema bool
}

// SchemaGuard 回傳組態值形式的寫入把關層級名稱。
func (p TxPolicy) SchemaGuard() string {
	if p.GuardSchema {
		return "transaction"
	}
	return "startup"
}

// String 產生啟動輸出用的單行摘要。
func (p TxPolicy) String() string {
	return fmt.Sprintf("begin_mode=%s nested=%s busy_retry_max=%d busy_retry_backoff_ms=%d timeout_ms=%d schema_guard=%s",
		p.BeginMode, p.Nested, p.BusyRetryMax, p.BusyRetryBackoff.Milliseconds(), p.Timeout.Milliseconds(), p.SchemaGuard())
}

// 交易邊界錯誤；呼叫端以 errors.Is 判定。
var (
	// ErrTxNested 表示在既有交易內再次開啟交易，而策略為 NestedReject。
	ErrTxNested = errors.New("database: 已在交易內，不允許嵌套開啟交易")
	// ErrTxFinished 表示交易已結束（提交或回滾）後仍被使用。
	ErrTxFinished = errors.New("database: 交易已結束")
	// ErrTxTimeout 表示交易逾時（database.transaction.timeout_ms）。
	ErrTxTimeout = errors.New("database: 交易逾時")
)

// SQLite 主結果碼（sqlite3.h）：擴充碼以 &0xff 取主碼。
const (
	sqliteBusy   = 5
	sqliteLocked = 6
)

// IsBusyError 判定錯誤是否為可重試的忙鎖錯誤（SQLITE_BUSY / SQLITE_LOCKED）。
//
// 驅動錯誤為 *sqlite.Error 且帶結果碼，優先以碼判定；無法取得碼時以訊息比對後備。
func IsBusyError(err error) bool {
	if err == nil {
		return false
	}
	var sqliteErr interface{ Code() int }
	if errors.As(err, &sqliteErr) {
		switch sqliteErr.Code() & 0xff {
		case sqliteBusy, sqliteLocked:
			return true
		}
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") ||
		strings.Contains(message, "database table is locked") ||
		strings.Contains(message, "sqlite_busy") ||
		strings.Contains(message, "sqlite_locked")
}

// Tx 為一個進行中的交易，實作 Querier，供倉儲在交易內執行語句。
//
// 提交與回滾由 InTx 統一負責（回呼式），因此 Tx 不提供 Commit/Rollback，
// 呼叫方無法讓交易處於「既不提交也不回滾」的狀態。
type Tx struct {
	tx            *sql.Tx
	readOnly      bool
	depth         int
	savepointName string
	finished      atomic.Bool
}

// ReadOnly 回報本交易是否為唯讀交易。
func (t *Tx) ReadOnly() bool { return t != nil && t.readOnly }

// Depth 回報嵌套深度（頂層為 0）。
func (t *Tx) Depth() int {
	if t == nil {
		return 0
	}
	return t.depth
}

// Savepoint 回傳本交易對應的儲存點名稱（頂層為空字串）。
func (t *Tx) Savepoint() string {
	if t == nil {
		return ""
	}
	return t.savepointName
}

// ExecContext 於交易內執行語句。
func (t *Tx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	return t.tx.ExecContext(ctx, query, args...)
}

// QueryContext 於交易內查詢。
func (t *Tx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	return t.tx.QueryContext(ctx, query, args...)
}

// QueryRowContext 於交易內查詢單列。
//
// 交易已結束（或本 Tx 為零值）時，回傳的 *sql.Row 在 Scan 時回報 ErrTxFinished：
// *sql.Row 無法直接攜帶錯誤，故以「已完成」的 context 讓 database/sql
// 在取得連線前即回報本套件的錯誤（見 errorContext）。
func (t *Tx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	if err := t.check(); err != nil {
		return t.errorRow(err)
	}
	return t.tx.QueryRowContext(ctx, query, args...)
}

// errorRow 產生「Scan 時必定回報 err」的 *sql.Row。
//
// 零值 Tx 沒有任何底層交易可用，故借用 database/sql 的 context 檢查：
// 取連線前會先看 ctx.Done() 並回報 ctx.Err()，因此把錯誤放進 context 即可。
// 此路徑僅在誤用（交易結束後或零值 Tx）時走到，不影響正常查詢。
func (t *Tx) errorRow(err error) *sql.Row {
	failed := errorContext{Context: context.Background(), err: err}
	if t == nil || t.tx == nil {
		// 連底層交易都沒有：以一個從不開啟連線的連線池承載錯誤。
		return errorPool.QueryRowContext(failed, "SELECT 1")
	}
	return t.tx.QueryRowContext(failed, "SELECT 1")
}

// errorPool 為 errorRow 的後備連線池：指向記憶體資料庫且從不開啟連線，
// 因此用它發出的查詢必定失敗，Scan 時回報 errorContext 攜帶的錯誤。
var errorPool, _ = sql.Open("sqlite", "file::memory:?mode=ro")

// errorContext 為 Done 已關閉、Err 固定回報指定錯誤的 context。
type errorContext struct {
	context.Context
	err error
}

// Done 一律回報已關閉，使 database/sql 立即走錯誤路徑。
func (c errorContext) Done() <-chan struct{} { return closedDone }

// Err 固定回報建構時指定的錯誤。
func (c errorContext) Err() error { return c.err }

// Deadline 回報無期限（錯誤判定只依 Err）。
func (c errorContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// closedDone 為已關閉的 channel，供 errorContext 重複使用。
var closedDone = func() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}()

// check 拒絕使用已結束的交易（呼叫方若把交易存起來事後使用即會踩到此保護）。
func (t *Tx) check() error {
	if t == nil || t.tx == nil {
		return ErrTxFinished
	}
	if t.finished.Load() {
		return ErrTxFinished
	}
	return nil
}

// TxFunc 為交易回呼。
//
// 必須使用傳入的 ctx（而非外層 ctx）：ctx 中帶有當前交易資訊，
// 嵌套偵測與逾時取消皆依賴它；改用外層 ctx 會使嵌套策略失效。
type TxFunc func(ctx context.Context, tx *Tx) error

// txContextKey 為 ctx 中交易資訊的鍵（僅供嵌套偵測，不作為隱式查詢通道）。
type txContextKey struct{}

// txFromContext 取出 ctx 中的當前交易。
func txFromContext(ctx context.Context) (*Tx, bool) {
	tx, ok := ctx.Value(txContextKey{}).(*Tx)
	return tx, ok
}

// withTx 產生帶有交易資訊的 ctx。
func withTx(ctx context.Context, tx *Tx) context.Context {
	return context.WithValue(ctx, txContextKey{}, tx)
}

// InTx 在一個寫入交易內執行 fn：fn 回傳錯誤或 panic 時整體回滾。
//
// 行為由 TxPolicy 決定：BEGIN 模式、嵌套策略、忙鎖重試與交易逾時。
// 忙鎖重試會重新執行整個 fn，因此僅適用於冪等交易（policy.BusyRetryMax 預設 0）。
func (db *DB) InTx(ctx context.Context, fn TxFunc) error {
	return db.inTx(ctx, false, fn)
}

// InTxReadOnly 在一個唯讀交易內執行 fn：用於需要一致快照的多個倉儲讀取。
//
// 走物理唯讀連線池（mode=ro），不佔用寫入鎖；交易以 deferred 開始，
// 因此期間其他連線的提交不會改變本交易看到的快照（實證見 tools/verify/step041-tx）。
func (db *DB) InTxReadOnly(ctx context.Context, fn TxFunc) error {
	return db.inTx(ctx, true, fn)
}

// TxPolicy 回傳本資料庫的交易策略（供啟動輸出與診斷）。
func (db *DB) TxPolicy() TxPolicy {
	if db == nil {
		return TxPolicy{}
	}
	return db.policy
}

// inTx 為 InTx / InTxReadOnly 的共用主體。
func (db *DB) inTx(ctx context.Context, readOnly bool, fn TxFunc) error {
	if db == nil || db.sql == nil {
		return errors.New("database: 資料庫未開啟")
	}
	if fn == nil {
		return errors.New("database: 交易回呼不可為空")
	}
	// 嵌套：ctx 中已有進行中的交易時，依策略處理。
	if outer, ok := txFromContext(ctx); ok {
		if outer.finished.Load() {
			return fmt.Errorf("%w：請使用回呼提供的 ctx，不要將交易或該 ctx 帶到交易之外", ErrTxFinished)
		}
		switch db.policy.Nested {
		case NestedReject:
			return fmt.Errorf("%w（當前深度 %d，策略 reject）", ErrTxNested, outer.depth)
		case NestedReuse:
			return fn(ctx, outer)
		case NestedSavepoint:
			return outer.savepoint(ctx, fn)
		}
	}

	pool := db.sql
	if readOnly {
		pool = db.read
	}
	if pool == nil {
		return errors.New("database: 唯讀連線池未建立")
	}

	// 寫入前門：可用空間不足時不開始交易（規格 AT-020「不得在空間不足時留下已確認
	// 但未持久化的交易」）。唯讀交易不經此門——它不落盤，攔它只會讓人連現況都看不到。
	// 位置在 BEGIN 之前而不是之中：交易已開始才拒絕，會白拿一次寫入鎖再回滾。
	if !readOnly && db.writeGuard != nil {
		if err := db.writeGuard(); err != nil {
			return err
		}
	}

	attempts := db.policy.BusyRetryMax + 1
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			backoff := db.policy.BusyRetryBackoff * time.Duration(attempt)
			if backoff > 0 {
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return err
				}
			}
		}
		err = db.runTx(ctx, pool, readOnly, fn)
		if err == nil || !IsBusyError(err) {
			return err
		}
	}
	return err
}

// runTx 執行單次交易嘗試：取得連線、開始交易、執行回呼、提交或整體回滾。
//
// 交易生命週期交由 database/sql 管理（連線異常時自動汰換），
// 本函式只負責「提交或回滾」的決策與逾時包裝。
// 寫入交易在回呼執行前先通過 schema 把關（GuardSchema 開啟時）。
func (db *DB) runTx(ctx context.Context, pool *sql.DB, readOnly bool, fn TxFunc) error {
	txCtx := ctx
	if db.policy.Timeout > 0 {
		var cancel context.CancelFunc
		txCtx, cancel = context.WithTimeout(ctx, db.policy.Timeout)
		defer cancel()
	}

	sqlTx, err := pool.BeginTx(txCtx, &sql.TxOptions{ReadOnly: readOnly})
	if err != nil {
		return beginError(err, readOnly, db.policy.Timeout)
	}
	tx := &Tx{tx: sqlTx, readOnly: readOnly}

	// panic 也要回滾：先回滾再重新拋出，避免交易懸置而長期佔用寫入鎖。
	defer func() {
		if r := recover(); r != nil {
			_ = sqlTx.Rollback()
			tx.finished.Store(true)
			panic(r)
		}
	}()

	// 寫入交易在回呼執行前複驗 schema 版本（組態 database.schema_guard=transaction）。
	// 檢查在同一條連線的同一個交易內，因此「通過檢查」與「實際寫入」看到的是同一個版本；
	// 不通過時回呼尚未執行，故不可能留下部分寫入。
	if !readOnly {
		if err := db.guardSchema(txCtx, tx); err != nil {
			tx.finished.Store(true)
			_ = sqlTx.Rollback()
			return err
		}
	}

	if err := fn(withTx(txCtx, tx), tx); err != nil {
		tx.finished.Store(true)
		rollbackErr := sqlTx.Rollback()
		if errors.Is(rollbackErr, sql.ErrTxDone) {
			rollbackErr = nil
		}
		if timeout := txTimeout(ctx, txCtx, db.policy.Timeout, err); timeout != nil {
			return timeout
		}
		if rollbackErr != nil {
			return fmt.Errorf("%w（回滾亦失敗：%v）", err, rollbackErr)
		}
		return err
	}

	tx.finished.Store(true)
	if err := sqlTx.Commit(); err != nil {
		// 期限已過時 database/sql 會在送出 COMMIT 前就放棄（先檢查 tx 的 context），
		// 此時交易仍開著，必須自行回滾；驅動層的提交失敗則已自行清理連線，
		// 這裡的第二次回滾只會得到 sql.ErrTxDone，屬正常。
		rollbackErr := sqlTx.Rollback()
		if errors.Is(rollbackErr, sql.ErrTxDone) {
			rollbackErr = nil
		}
		if timeout := txTimeout(ctx, txCtx, db.policy.Timeout, err); timeout != nil {
			return timeout
		}
		if rollbackErr != nil {
			return fmt.Errorf("database: 交易提交失敗（回滾亦失敗：%v）：%w", rollbackErr, err)
		}
		return fmt.Errorf("database: 交易提交失敗（已整體回滾）：%w", err)
	}
	return nil
}

// txTimeout 於交易期限（database.transaction.timeout_ms）觸發時，把錯誤標記為 ErrTxTimeout，
// 讓呼叫端能區分「逾時整體回滾」與一般業務錯誤。
//
// 判定條件：本策略設有期限、外層 ctx 仍有效（逾時確實由本策略造成，而非外層取消）、
// 且交易 ctx 已過期。逾時路徑一律已整體回滾（見 runTx）。
func txTimeout(outer, txCtx context.Context, timeout time.Duration, err error) error {
	if err == nil || timeout <= 0 || outer.Err() != nil || !errors.Is(txCtx.Err(), context.DeadlineExceeded) {
		return nil
	}
	return fmt.Errorf("%w（交易期限 %s，已整體回滾）：%w", ErrTxTimeout, timeout, err)
}

// guardSchema 在寫入交易邊界複驗 schema 版本（schema_guard=transaction 時生效）。
//
// 開庫前預檢已在啟動時攔下較新版本；此處另於每次寫入交易內複驗，
// 用於攔截執行期資料庫檔被替換或還原成其他版本的情況
// （單寫入實例鎖只約束本服務程序，管不到外部檔案操作）。
// 版本不符即拒絕該交易，符合「不識別 schema 版本時不寫入」（規格附錄 E.5）。
func (db *DB) guardSchema(ctx context.Context, q Querier) error {
	if !db.policy.GuardSchema || db.knownVersion <= 0 {
		return nil
	}
	var version int
	if err := q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("database: 交易邊界讀取 schema 版本失敗（%s）: %w", db.path, err)
	}
	switch {
	case version > db.knownVersion:
		return fmt.Errorf("%w：交易邊界讀到版本 %d，高於執行檔已知版本 %d；已拒絕此交易（schema_guard=transaction）",
			ErrSchemaTooNew, version, db.knownVersion)
	case version < db.knownVersion:
		return fmt.Errorf("%w：交易邊界讀到版本 %d，低於執行檔已知版本 %d（資料庫可能被還原或替換）；已拒絕此交易（schema_guard=transaction）",
			ErrSchemaBehind, version, db.knownVersion)
	}
	return nil
}

// beginError 包裝交易開始失敗的錯誤，逾時與忙鎖給出可操作的提示。
func beginError(err error, readOnly bool, timeout time.Duration) error {
	kind := "寫入"
	if readOnly {
		kind = "唯讀"
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w（%s交易開始前，期限 %s）：%w", ErrTxTimeout, kind, timeout, err)
	case IsBusyError(err):
		return fmt.Errorf("database: %s交易無法開始（資料庫忙碌，另一寫入者持有鎖）：%w", kind, err)
	default:
		return fmt.Errorf("database: %s交易無法開始：%w", kind, err)
	}
}

// savepointSeq 產生唯一的儲存點名稱序號（同一交易內可能多次嵌套）。
var savepointSeq atomic.Uint64

// savepoint 以 SAVEPOINT 實現嵌套交易：內層失敗只回滾到儲存點，外層仍可提交。
//
// 清理語句（ROLLBACK TO / RELEASE）以 WithoutCancel 執行：
// 內層失敗常因 ctx 逾時或取消，此時仍需完成清理才能讓外層交易保持可用。
func (t *Tx) savepoint(ctx context.Context, fn TxFunc) error {
	if err := t.check(); err != nil {
		return err
	}
	name := fmt.Sprintf("er_sp_%d", savepointSeq.Add(1))
	if _, err := t.tx.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
		return fmt.Errorf("database: 建立儲存點失敗（%s）：%w", name, err)
	}
	inner := &Tx{tx: t.tx, readOnly: t.readOnly, depth: t.depth + 1, savepointName: name}
	cleanup := context.WithoutCancel(ctx)

	if err := fn(withTx(ctx, inner), inner); err != nil {
		inner.finished.Store(true)
		if _, rbErr := t.tx.ExecContext(cleanup, "ROLLBACK TO "+name); rbErr != nil {
			return fmt.Errorf("%w（回滾至儲存點 %s 亦失敗：%v）", err, name, rbErr)
		}
		if _, relErr := t.tx.ExecContext(cleanup, "RELEASE "+name); relErr != nil {
			return fmt.Errorf("%w（釋放儲存點 %s 亦失敗：%v）", err, name, relErr)
		}
		return err
	}
	inner.finished.Store(true)
	if _, err := t.tx.ExecContext(cleanup, "RELEASE "+name); err != nil {
		return fmt.Errorf("database: 釋放儲存點失敗（%s）：%w", name, err)
	}
	return nil
}
