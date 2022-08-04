// 一致性快照：把資料庫取成一份可獨立開啟的單檔副本。
//
// 取法是程序級實測選定的（內建 SQLite 3.53.4 支援 VACUUM INTO）：
// VACUUM INTO 讀的是連線當前可見的已提交狀態，包含仍在 -wal 裡、尚未 checkpoint 回主檔的資料，
// 產物是一份自足的單檔資料庫（journal_mode=delete，沒有 -wal/-shm 相依），
// 且過程不寫源庫、不觸發源庫的 checkpoint。
// 代價是兩條硬限制：目標檔必須不存在，且不得在交易內執行——兩者都在下方函式裡變成錯誤而不是猜。
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

// ErrSnapshotTargetExists 表示快照目標位址已有檔案。
//
// 單獨成一個錯誤值是因為呼叫端的處置不同：這通常是「同一個名字重複用」，
// 換個目標名就好；而實測顯示 SQLite 遇到已存在的目標會報 `file is not a database`，
// 那句錯誤既說出錯的檔案又暗示資料庫壞了，照原樣丟給運維只會把人往錯方向帶。
var ErrSnapshotTargetExists = errors.New("database: 快照目標已存在，拒絕覆蓋")

// snapshotDSN 產生快照專用連線字串。
//
// 與寫入池（dsn）和唯讀池（dsnReadOnly）都不同，三處差異都是實測得來的：
//   - 不得帶 journal_mode 等會寫庫的 PRAGMA：唯讀連線寫不動，帶了只會讓開庫失敗；
//   - 不得帶 query_only(1)：VACUUM INTO 雖然只寫新檔，仍被 query_only 視為寫入而拒絕
//     （實測報 attempt to write a readonly database (8)），所以既有唯讀池不能拿來做快照；
//   - mode=ro 本身就夠：它只禁止對源庫的寫入，不禁止在同一連線建立的語句把資料讀進新檔。
func snapshotDSN(path string, busyTimeout time.Duration) string {
	return "file:" + encodeURIPath(path) +
		"?mode=ro" +
		fmt.Sprintf("&_pragma=busy_timeout(%d)", busyTimeout.Milliseconds()) +
		"&_txlock=deferred"
}

// OpenSnapshot 建立一條專供一致性快照的唯讀連線，呼叫端負責 Close。
//
// 這條連線刻意不取單寫入實例鎖：快照不寫源庫，因此不需要排他的寫入地位，
// 「備份不必先停服務」這件事完全依賴這個差異（程序級實測：服務持有鎖並持續寫入期間，
// 另一個行程以本連線仍取出完整快照，且服務端的寫入未被阻擋）。
// 反過來說，這道鎖本來也只約束本服務的程式碼——實測外部 SQLite 工具仍能對活動庫 checkpoint，
// 所以不能把它當成抵外部的手段。
func OpenSnapshot(path string, busyTimeout time.Duration) (*sql.DB, error) {
	cleaned := filepath.Clean(path)
	if cleaned == "" {
		return nil, errors.New("database: 資料庫路徑不可為空")
	}
	if busyTimeout <= 0 {
		busyTimeout = defaultBusyTimeout
	}
	db, err := sql.Open("sqlite", snapshotDSN(cleaned, busyTimeout))
	if err != nil {
		return nil, err
	}
	// 固定為單一行線：VACUUM INTO 一次只寫一份產物，多一行線只是多一個「這句跑在哪條線上」的變數。
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: 開啟快照連線失敗（%s）: %w", cleaned, err)
	}
	return db, nil
}

// Snapshot 用 VACUUM INTO 把來源取成 target 指向的單檔副本。
//
// 路徑一律走參數綁定（實測綁定可用），因此不需要自行加引號，也就不會有「路徑含單引號」這類注入面。
// 目標已存在時先以 ErrSnapshotTargetExists 拒絕，不讓 SQLite 去動那個檔案；
// 呼叫端若要「每次一份」，自帶不重複的名稱（本專案用 UTC 時間戳加上識別碼前綴）。
func Snapshot(ctx context.Context, db *sql.DB, target string) error {
	if db == nil {
		return errors.New("database: 快照連線不可為 nil")
	}
	cleaned := filepath.Clean(target)
	if _, err := os.Stat(cleaned); err == nil {
		return fmt.Errorf("%w：%s", ErrSnapshotTargetExists, cleaned)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("database: 檢查快照目標 %s 失敗: %w", cleaned, err)
	}
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, cleaned); err != nil {
		return fmt.Errorf("database: 取得快照失敗（目標 %s）: %w", cleaned, err)
	}
	return nil
}

// TableRows 是一份快照裡某張資料表的列數。
type TableRows struct {
	// Table 是資料表名（來自 sqlite_master，不假設本專案的表清單）。
	Table string `json:"table"`
	// Rows 是該表的列數。
	Rows int64 `json:"rows"`
}

// SnapshotInfo 是一份快照自身的可核對事實。
//
// 這些值進備份清單，讓「這份備份有沒有壞」在備份當時就有答案，
// 不必等到要還原才發現（NFR-011 要求備份能在新目錄恢復並通過一致性檢查，
// 而一致性檢查的第一次執行不該押在恢復那天）。
type SnapshotInfo struct {
	// SchemaVersion 是版本表裡的最高版本；查不到時為 0（例如尚未遷移的庫）。
	SchemaVersion int
	// JournalMode 是快照檔案的journal 模式（VACUUM INTO 的產物為 delete）。
	JournalMode string
	// Integrity 是 integrity_check 的回值（正常為 ok）。
	Integrity string
	// ApplicationID 與 HeaderSchemaVersion 是副本檔頭的標記與 user_version；
	// 本服務的預檢靠這兩個值辨認「這是我的庫」，因此必須在備份時就記下來。
	ApplicationID       uint32
	HeaderSchemaVersion int
	// Tables 是快照內各資料表的列數，依表名排序（清單要可重複產生）。
	Tables []TableRows
}

// InspectSnapshot 以唯讀連線開啟快照並讀回可核對的事實。
//
// 這裡不做「寫得回去」的檢查（那是 STEP-069 還原驗證的工作），只確認取出來的這一份是好的：
// integrity_check 必須回 ok，任何其他回值都由呼叫端據以拒絕發布這份備份。
func InspectSnapshot(ctx context.Context, path string, busyTimeout time.Duration) (SnapshotInfo, error) {
	db, err := sql.Open("sqlite", snapshotDSN(path, busyTimeout))
	if err != nil {
		return SnapshotInfo{}, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	info := SnapshotInfo{}
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&info.Integrity); err != nil {
		return SnapshotInfo{}, fmt.Errorf("database: 快照完整性檢查無法執行（%s）: %w", path, err)
	}
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&info.JournalMode); err != nil {
		return info, fmt.Errorf("database: 讀取快照 journal 模式失敗: %w", err)
	}
	var appID int64
	if err := db.QueryRowContext(ctx, `PRAGMA application_id`).Scan(&appID); err != nil {
		return info, fmt.Errorf("database: 讀取快照 application_id 失敗: %w", err)
	}
	info.ApplicationID = uint32(appID)
	var userVersion int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&userVersion); err != nil {
		return info, fmt.Errorf("database: 讀取快照 user_version 失敗: %w", err)
	}
	info.HeaderSchemaVersion = userVersion

	// 版本表可能不存在（尚未遷移的庫）：這時最高版本記 0，不讓一份空庫變成快照失敗。
	if version, ok, err := schemaVersion(ctx, db); err != nil {
		return info, err
	} else if ok {
		info.SchemaVersion = version
	}

	names, err := snapshotTableNames(ctx, db)
	if err != nil {
		return info, err
	}
	info.Tables = make([]TableRows, 0, len(names))
	for _, name := range names {
		var rows int64
		// 表名來自 sqlite_master 而非使用者輸入，且仍以引號包住空白與底線字元做防呆。
		if err := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT count(*) FROM %q`, name)).Scan(&rows); err != nil {
			return info, fmt.Errorf("database: 計算快照表 %s 的列數失敗: %w", name, err)
		}
		info.Tables = append(info.Tables, TableRows{Table: name, Rows: rows})
	}
	return info, nil
}

// snapshotTableNames 回傳快照內所有資料表的名稱（排序、不含 sqlite_ 內部表）。
func snapshotTableNames(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("database: 列出快照資料表失敗: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// schemaVersion 讀版本表的最高版本；第二個回值為 false 表示這張表不存在。
func schemaVersion(ctx context.Context, db *sql.DB) (int, bool, error) {
	var exists int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&exists); err != nil {
		return 0, false, err
	}
	if exists == 0 {
		return 0, false, nil
	}
	var version sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil {
		return 0, true, err
	}
	return int(version.Int64), true, nil
}
