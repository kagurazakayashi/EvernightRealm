// Package migrate 提供版本化前向資料庫遷移與版本檢查。
//
// 依既有決策採自研最小遷移器：版本表 + 每支遷移單一交易，
// 失敗或中斷不留半套用狀態（整支遷移要嘛全成功、要嘛整體回滾）。
// 遷移檔以 go:embed 內嵌於執行檔，隨單一執行檔發布，無執行期路徑依賴。
//
// 新增遷移：在 migrations/ 目錄加入 `NNNN_名稱.sql`（版本四位數，遞增且唯一），
// 內容為可在單一交易內完成的 SQL。已發布的遷移檔不得再改寫：內容以 SHA-256
// 記錄於版本表，改寫會被拒絕（改寫會使既有資料庫與執行檔對不上）。
// 遷移僅前向；回滾一律以備份還原，不得刪除遷移記錄（規格附錄 E.5）。
//
// 本套件只依賴 database/sql 與內部時間工具（internal/timeutil），不依賴 internal/database，
// 以便資料庫引擎與遷移器保持單向關係（由啟動流程負責串接）。
package migrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

//go:embed migrations/*.sql
var embedded embed.FS

const (
	// TableName 為版本表名稱；記錄只增不改，供版本檢查與診斷使用。
	TableName = "schema_migrations"
	// dir 為內嵌遷移檔所在目錄。
	dir = "migrations"
)

// createTableSQL 建立版本表。
//
// 表結構約定（決策記錄 DEC-011）：一般表（非 STRICT）；時間戳為 INTEGER，
// Unix 毫秒 UTC，不使用本地時間字串。
const createTableSQL = `CREATE TABLE IF NOT EXISTS ` + TableName + ` (
	version    INTEGER PRIMARY KEY,
	name       TEXT    NOT NULL,
	checksum   TEXT    NOT NULL,
	applied_at INTEGER NOT NULL
)`

// fileNamePattern 為遷移檔名規則：四位數版本 + 底線 + 小寫名稱。
var fileNamePattern = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// 版本檢查錯誤；呼叫端以 errors.Is 判定類型。
var (
	// ErrFutureVersion 表示資料庫版本高於執行檔已知版本（降級執行）。
	ErrFutureVersion = errors.New("migrate: 資料庫版本高於執行檔")
	// ErrChecksumMismatch 表示已套用遷移的內容與執行檔不符。
	ErrChecksumMismatch = errors.New("migrate: 已套用遷移的內容與執行檔不符")
	// ErrOutOfOrder 表示版本表狀態不連續（缺檔、亂序或未知版本）。
	ErrOutOfOrder = errors.New("migrate: 版本表狀態不連續")
	// ErrUnknownDatabase 表示資料庫非空但缺少版本表（非本服務所有）。
	ErrUnknownDatabase = errors.New("migrate: 資料庫非空但缺少版本表")
)

// Migration 描述一支遷移。
type Migration struct {
	// Version 為版本號（由檔名前綴決定，遞增且唯一）。
	Version int
	// Name 為遷移名稱（檔名中版本之後的部分）。
	Name string
	// Checksum 為 SQL 內容的 SHA-256 十六進位字串。
	Checksum string
	// SQL 為遷移內容。
	SQL string
}

// String 回傳 `NNNN_名稱` 形式，供輸出與錯誤訊息使用。
func (m Migration) String() string {
	return fmt.Sprintf("%04d_%s", m.Version, m.Name)
}

// Applied 為版本表中的一筆已套用記錄。
type Applied struct {
	// Version 為版本號。
	Version int
	// Name 為遷移名稱。
	Name string
	// Checksum 為套用當時的內容雜湊。
	Checksum string
	// AppliedAt 為套用時間（UTC）。
	AppliedAt time.Time
}

// Options 為 Apply 的輸入參數。
type Options struct {
	// DryRun 為 true 時只檢查版本與待套用清單，完全不變更資料庫。
	DryRun bool
	// Clock 為版本記錄時間戳的來源；nil 表示使用伺服器系統時鐘。
	// 注入 timeutil.NewTest 可使套用時間成為可斷言的固定值。
	Clock timeutil.Clock
}

// Result 為一次 Apply 的結果。
type Result struct {
	// DryRun 表示本次是否為檢查模式（未變更資料庫）。
	DryRun bool
	// FromVersion 為套用前的版本（空庫為 0）。
	FromVersion int
	// ToVersion 為套用後的版本（檢查模式等於 FromVersion）。
	ToVersion int
	// Applied 為本次實際套用的遷移（依版本遞增）。
	Applied []Migration
	// Pending 為尚未套用的遷移（依版本遞增）；檢查模式據此輸出待辦清單。
	Pending []Migration
	// Skipped 為已套用而略過的遷移數量。
	Skipped int
}

// Load 讀取內嵌遷移檔並校驗版本遞增、名稱與內容。
func Load() ([]Migration, error) {
	entries, err := fs.ReadDir(embedded, dir)
	if err != nil {
		return nil, fmt.Errorf("migrate: 讀取內嵌遷移目錄失敗: %w", err)
	}
	migrations := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, name, err := parseName(entry.Name())
		if err != nil {
			return nil, err
		}
		data, err := embedded.ReadFile(path.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("migrate: 讀取遷移檔 %s 失敗: %w", entry.Name(), err)
		}
		if strings.TrimSpace(string(data)) == "" {
			return nil, fmt.Errorf("migrate: 遷移檔 %s 內容為空", entry.Name())
		}
		migrations = append(migrations, Migration{
			Version:  version,
			Name:     name,
			Checksum: checksum(data),
			SQL:      string(data),
		})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	for i, m := range migrations {
		if i > 0 && migrations[i-1].Version == m.Version {
			return nil, fmt.Errorf("migrate: 版本號重複（%d：%s 與 %s）", m.Version, migrations[i-1].String(), m.String())
		}
	}
	return migrations, nil
}

// MaxVersion 回傳內嵌遷移中的最高版本；無遷移時回傳 0。
//
// 供啟動流程設定開庫前預檢的已知版本（檔頭標記比較用）。
func MaxVersion() (int, error) {
	known, err := Load()
	if err != nil {
		return 0, err
	}
	if len(known) == 0 {
		return 0, nil
	}
	return known[len(known)-1].Version, nil
}

// Current 回傳資料庫目前版本；資料庫尚未遷移（無版本表）時回傳 0。
func Current(ctx context.Context, db *sql.DB) (int, error) {
	if db == nil {
		return 0, errors.New("migrate: 資料庫連線不可為 nil")
	}
	exists, err := tableExists(ctx, db)
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	var version sql.NullInt64
	if err := db.QueryRowContext(ctx, "SELECT MAX(version) FROM "+TableName).Scan(&version); err != nil {
		return 0, fmt.Errorf("migrate: 讀取目前版本失敗: %w", err)
	}
	if !version.Valid {
		return 0, nil
	}
	return int(version.Int64), nil
}

// Apply 讀取內嵌遷移並套用所有尚未套用的版本。
//
// 流程：讀取版本表 → 版本檢查（較新版本、內容雜湊、狀態連續性）
// → 計算待套用清單 → 逐支以單一交易套用。任何一步失敗即回傳錯誤，
// 已套用者維持已提交狀態，失敗的那一支整體回滾，資料庫不會停在中間狀態。
func Apply(ctx context.Context, db *sql.DB, opts Options) (Result, error) {
	known, err := Load()
	if err != nil {
		return Result{}, err
	}
	return applySet(ctx, db, known, opts)
}

// applySet 為 Apply 的實作主體，可注入自訂遷移集合（供測試故障與版本檢查路徑）。
func applySet(ctx context.Context, db *sql.DB, known []Migration, opts Options) (Result, error) {
	if db == nil {
		return Result{}, errors.New("migrate: 資料庫連線不可為 nil")
	}
	for i, m := range known {
		if m.Version <= 0 {
			return Result{}, fmt.Errorf("migrate: 遷移版本必須為正整數（%s）", m)
		}
		if i > 0 && known[i-1].Version >= m.Version {
			return Result{}, fmt.Errorf("migrate: 遷移集合必須依版本嚴格遞增（%s 之後為 %s）", known[i-1], m)
		}
	}

	// 識別檢查：資料庫非空但缺少版本表，表示這不是本服務建立的資料庫；
	// 繼續下去會在別人的資料庫裡建表，因此一律拒絕（檢查模式同樣拒絕）。
	// 版本表存在但尚無記錄（如首次遷移失敗）不算陌生資料庫。
	tableFound, err := tableExists(ctx, db)
	if err != nil {
		return Result{}, err
	}
	if !tableFound {
		tables, err := userTables(ctx, db)
		if err != nil {
			return Result{}, err
		}
		if len(tables) > 0 {
			return Result{}, fmt.Errorf("%w：已有 %d 個資料表（%s）；為避免破壞非本服務的資料，已拒絕遷移",
				ErrUnknownDatabase, len(tables), summarize(tables))
		}
	}

	applied, err := loadApplied(ctx, db)
	if err != nil {
		return Result{}, err
	}

	res := Result{DryRun: opts.DryRun}
	knownByVersion := make(map[int]Migration, len(known))
	maxKnown := 0
	for _, m := range known {
		knownByVersion[m.Version] = m
		if m.Version > maxKnown {
			maxKnown = m.Version
		}
	}
	appliedByVersion := make(map[int]Applied, len(applied))

	// 版本檢查：資料庫不得比執行檔新，已套用內容不得與執行檔不符。
	for _, a := range applied {
		if a.Version > res.FromVersion {
			res.FromVersion = a.Version
		}
		appliedByVersion[a.Version] = a
		if a.Version > maxKnown {
			return Result{}, fmt.Errorf("%w：資料庫版本 %d（%s）高於執行檔已知版本 %d；請改用較新的執行檔，或以備份還原後再啟動",
				ErrFutureVersion, a.Version, a.Name, maxKnown)
		}
		m, ok := knownByVersion[a.Version]
		if !ok {
			return Result{}, fmt.Errorf("%w：版本表存在未知遷移 %d（%s），執行檔缺少對應遷移檔",
				ErrOutOfOrder, a.Version, a.Name)
		}
		if m.Checksum != a.Checksum {
			return Result{}, fmt.Errorf("%w：%s（執行檔 %s，版本表 %s）；已發布的遷移檔不得改寫",
				ErrChecksumMismatch, m, short(m.Checksum), short(a.Checksum))
		}
		res.Skipped++
	}

	// 待套用清單：已知但未套用者；版本必須高於目前版本，否則版本表狀態不連續。
	for _, m := range known {
		if _, ok := appliedByVersion[m.Version]; ok {
			continue
		}
		if m.Version < res.FromVersion {
			return Result{}, fmt.Errorf("%w：目前版本 %d，卻缺少更早的遷移 %s；請確認資料目錄與執行檔版本一致",
				ErrOutOfOrder, res.FromVersion, m)
		}
		res.Pending = append(res.Pending, m)
	}

	res.ToVersion = res.FromVersion
	if opts.DryRun || len(res.Pending) == 0 {
		return res, nil
	}

	// 有實際待套用遷移時才建立版本表，確保檢查模式不動資料庫。
	if err := ensureTable(ctx, db); err != nil {
		return res, err
	}

	clock := opts.Clock
	if clock == nil {
		clock = timeutil.System()
	}
	for _, m := range res.Pending {
		if err := applyOne(ctx, db, m, clock.Now()); err != nil {
			return res, err
		}
		res.Applied = append(res.Applied, m)
		res.ToVersion = m.Version
	}
	return res, nil
}

// applyOne 以單一交易套用一支遷移並寫入版本記錄。
//
// 交易保證原子性：SQL 失敗或提交失敗時整支回滾，版本表與結構都維持原狀。
func applyOne(ctx context.Context, db *sql.DB, m Migration, at time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrate: 開始交易失敗（%s）: %w", m, err)
	}
	// 提交後再回滾會得到 sql.ErrTxDone，可安全忽略。
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("migrate: 套用 %s 失敗（已整體回滾，資料庫維持原版本）: %w", m, err)
	}
	// 同步檔頭 schema 版本標記（同一交易內，與版本記錄一同生效或一同回滾），
	// 供開庫前預檢在尚未接觸資料庫時判定版本（見 database 套件的預檢說明）。
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.Version)); err != nil {
		return fmt.Errorf("migrate: 寫入 schema 版本標記失敗（%s，已整體回滾）: %w", m, err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO "+TableName+" (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
		m.Version, m.Name, m.Checksum, timeutil.ToMillis(at)); err != nil {
		return fmt.Errorf("migrate: 寫入版本記錄失敗（%s，已整體回滾）: %w", m, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrate: 提交 %s 失敗: %w", m, err)
	}
	return nil
}

// loadApplied 讀取版本表全部記錄（依版本遞增）；版本表不存在時回傳空清單。
func loadApplied(ctx context.Context, db *sql.DB) ([]Applied, error) {
	exists, err := tableExists(ctx, db)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, "SELECT version, name, checksum, applied_at FROM "+TableName+" ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("migrate: 讀取版本表失敗: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var applied []Applied
	for rows.Next() {
		var a Applied
		var appliedAt int64
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum, &appliedAt); err != nil {
			return nil, fmt.Errorf("migrate: 解析版本表失敗: %w", err)
		}
		a.AppliedAt = timeutil.FromMillis(appliedAt)
		applied = append(applied, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("migrate: 讀取版本表失敗: %w", err)
	}
	return applied, nil
}

// ensureTable 建立版本表（已存在時不變更）。
func ensureTable(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, createTableSQL); err != nil {
		return fmt.Errorf("migrate: 建立版本表失敗: %w", err)
	}
	return nil
}

// tableExists 查詢指定資料表是否存在。
func tableExists(ctx context.Context, db *sql.DB, name ...string) (bool, error) {
	table := TableName
	if len(name) > 0 {
		table = name[0]
	}
	var found string
	err := db.QueryRowContext(ctx,
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("migrate: 查詢資料表 %s 失敗: %w", table, err)
	}
	return true, nil
}

// userTables 列出使用者資料表（排除 SQLite 內部表）；供識別檢查使用。
func userTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("migrate: 查詢資料表清單失敗: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("migrate: 解析資料表清單失敗: %w", err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("migrate: 查詢資料表清單失敗: %w", err)
	}
	return tables, nil
}

// summarize 將清單截短為最多 3 筆，避免錯誤訊息過長。
func summarize(items []string) string {
	if len(items) == 0 {
		return "無"
	}
	const limit = 3
	shown := items
	suffix := ""
	if len(items) > limit {
		shown = items[:limit]
		suffix = fmt.Sprintf("…等 %d 項", len(items))
	}
	return strings.Join(shown, "、") + suffix
}

// parseName 解析遷移檔名為版本與名稱。
func parseName(fileName string) (int, string, error) {
	matches := fileNamePattern.FindStringSubmatch(fileName)
	if matches == nil {
		return 0, "", fmt.Errorf("migrate: 遷移檔名 %q 不符規則（應為 NNNN_名稱.sql，版本四位數、名稱限小寫英數字與底線）", fileName)
	}
	version, err := strconv.Atoi(matches[1])
	if err != nil || version <= 0 {
		return 0, "", fmt.Errorf("migrate: 遷移檔名 %q 的版本號無效", fileName)
	}
	return version, matches[2], nil
}

// checksum 計算遷移內容的 SHA-256。
func checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// short 截短雜湊供錯誤訊息使用。
func short(sum string) string {
	if len(sum) <= 12 {
		return sum
	}
	return sum[:12]
}
