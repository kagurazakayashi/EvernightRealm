package database

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// openTestDB 於獨立暫存目錄開啟測試資料庫，測試結束時自動關閉。
func openTestDB(t *testing.T, busyTimeout time.Duration) *DB {
	t.Helper()
	dir := retryTempDir(t)
	db, err := Open(context.Background(), Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: busyTimeout,
	})
	if err != nil {
		t.Fatalf("Open 失敗: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close 失敗: %v", err)
		}
	})
	return db
}

func TestOpenAppliesBaselinePragmas(t *testing.T) {
	// DEC-002 參數組必須在實際連線上生效，而非只是寫在連線字串裡。
	db := openTestDB(t, 3*time.Second)
	if got := db.JournalMode(); got != "wal" {
		t.Fatalf("JournalMode 應為 wal，實際 %q", got)
	}
	if got := db.Path(); !strings.HasSuffix(got, "evernight.db") {
		t.Fatalf("Path 應指向資料庫檔，實際 %q", got)
	}

	ctx := context.Background()
	conn, err := db.SQL().Conn(ctx)
	if err != nil {
		t.Fatalf("取得連線失敗: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var journal string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		t.Fatalf("讀取 journal_mode 失敗: %v", err)
	}
	if journal != "wal" {
		t.Fatalf("journal_mode 應為 wal，實際 %q", journal)
	}

	var foreignKeys int
	if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatalf("讀取 foreign_keys 失敗: %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys 應為 1，實際 %d", foreignKeys)
	}

	var busy int
	if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy); err != nil {
		t.Fatalf("讀取 busy_timeout 失敗: %v", err)
	}
	if want := 3000; busy != want {
		t.Fatalf("busy_timeout 應為 %d ms，實際 %d ms", want, busy)
	}

	// WAL 模式下寫入會產生 -wal 檔（同目錄可見）。
	if _, err := db.SQL().ExecContext(ctx, "CREATE TABLE t (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("建表失敗: %v", err)
	}
	if _, err := db.SQL().ExecContext(ctx, "INSERT INTO t (id) VALUES (1)"); err != nil {
		t.Fatalf("寫入失敗: %v", err)
	}
	if _, err := os.Stat(db.Path() + "-wal"); err != nil {
		t.Fatalf("WAL 模式下應存在 -wal 檔: %v", err)
	}
}

func TestReopenReadsDataAfterRestart(t *testing.T) {
	// 驗收：重啟可讀取資料。寫入 → 關閉（等同程序結束）→ 重新開啟 → 讀回同一筆資料。
	dir := retryTempDir(t)
	path := filepath.Join(dir, "evernight.db")
	ctx := context.Background()

	first, err := Open(ctx, Options{Path: path, BusyTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("首次 Open 失敗: %v", err)
	}
	if _, err := first.SQL().ExecContext(ctx,
		"CREATE TABLE probe (id INTEGER PRIMARY KEY, note TEXT NOT NULL)"); err != nil {
		t.Fatalf("建表失敗: %v", err)
	}
	if _, err := first.SQL().ExecContext(ctx,
		"INSERT INTO probe (id, note) VALUES (1, '長夜')"); err != nil {
		t.Fatalf("寫入失敗: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("關閉失敗: %v", err)
	}

	second, err := Open(ctx, Options{Path: path, BusyTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("重新 Open 失敗（重啟應可讀取資料）: %v", err)
	}
	defer func() { _ = second.Close() }()

	var note string
	if err := second.SQL().QueryRowContext(ctx,
		"SELECT note FROM probe WHERE id = 1").Scan(&note); err != nil {
		t.Fatalf("重啟後讀取失敗: %v", err)
	}
	if note != "長夜" {
		t.Fatalf("重啟後讀到 %q，預期 %q", note, "長夜")
	}
}

func TestForeignKeyEnforced(t *testing.T) {
	// 外鍵預設關閉（探針 tools/verify/step024-sqlite-wal 實證），必須由 DSN 明確開啟並實際生效。
	db := openTestDB(t, time.Second)
	ctx := context.Background()

	stmts := []string{
		"CREATE TABLE parent (id INTEGER PRIMARY KEY)",
		"CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL REFERENCES parent(id))",
	}
	for _, s := range stmts {
		if _, err := db.SQL().ExecContext(ctx, s); err != nil {
			t.Fatalf("建表失敗（%s）: %v", s, err)
		}
	}

	if _, err := db.SQL().ExecContext(ctx,
		"INSERT INTO child (id, parent_id) VALUES (1, 999)"); err == nil {
		t.Fatal("插入不存在的外鍵應被拒絕，實際成功")
	}
}

func TestSecondWriterRejected(t *testing.T) {
	// 驗收：單寫入實例約束有驗證。同一資料庫的第二個服務程序必須啟動失敗。
	dir := retryTempDir(t)
	path := filepath.Join(dir, "evernight.db")
	ctx := context.Background()

	first, err := Open(ctx, Options{Path: path, BusyTimeout: time.Second})
	if err != nil {
		t.Fatalf("首次 Open 失敗: %v", err)
	}

	second, err := Open(ctx, Options{Path: path, BusyTimeout: time.Second})
	if err == nil {
		_ = second.Close()
		_ = first.Close()
		t.Fatal("第二個寫入者應被拒絕，實際開啟成功")
	}
	if !strings.Contains(err.Error(), "單寫入實例約束") {
		t.Fatalf("錯誤訊息應指出單寫入實例約束，實際: %v", err)
	}

	// 第一個程序釋放後，後續程序應能正常開啟（鎖不殘留）。
	if err := first.Close(); err != nil {
		t.Fatalf("關閉第一個資料庫失敗: %v", err)
	}
	third, err := Open(ctx, Options{Path: path, BusyTimeout: time.Second})
	if err != nil {
		t.Fatalf("前一個寫入者結束後應可開啟: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatalf("關閉失敗: %v", err)
	}
}

func TestLockFileHoldsOwnerInfo(t *testing.T) {
	// 鎖檔記錄持有者 pid 供人工診斷；Windows 的位元組範圍鎖對其他控制代碼是強制的，
	// 因此須在釋放鎖後才讀取（也順帶驗證鎖確實已釋放）。
	dir := retryTempDir(t)
	db, err := Open(context.Background(), Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Open 失敗: %v", err)
	}
	lockPath := db.Path() + lockSuffix
	if err := db.Close(); err != nil {
		t.Fatalf("Close 失敗: %v", err)
	}

	data, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("鎖檔應存在: %v", err)
	}
	if !strings.HasPrefix(string(data), "pid=") {
		t.Fatalf("鎖檔應記錄持有者 pid，實際內容 %q", data)
	}
}

func TestSpecialCharactersInPath(t *testing.T) {
	// 資料目錄可能含空格、中文與 '%'、'#'；DSN 的 URI 編碼必須讓實際檔案落在預期路徑。
	dir := filepath.Join(retryTempDir(t), "資料 目錄", "pct%dir", "hash#tag")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("建立測試目錄失敗: %v", err)
	}
	path := filepath.Join(dir, "evernight.db")
	ctx := context.Background()

	db, err := Open(ctx, Options{Path: path, BusyTimeout: time.Second})
	if err != nil {
		t.Fatalf("Open 失敗（含特殊字元路徑）: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.SQL().ExecContext(ctx, "CREATE TABLE t (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("建表失敗: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("資料庫檔應落在預期路徑 %s: %v", path, err)
	}
}

func TestCloseIsIdempotentAndReleasesLock(t *testing.T) {
	dir := retryTempDir(t)
	path := filepath.Join(dir, "evernight.db")
	ctx := context.Background()

	db, err := Open(ctx, Options{Path: path, BusyTimeout: time.Second})
	if err != nil {
		t.Fatalf("Open 失敗: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("第一次 Close 失敗: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("重複 Close 應無錯誤，實際: %v", err)
	}
	if db.SQL() != nil {
		t.Fatal("Close 後 SQL() 應為 nil")
	}
	if err := db.Ping(ctx); err == nil {
		t.Fatal("Close 後 Ping 應失敗")
	}

	// 鎖已釋放：同一路徑可再次開啟。
	again, err := Open(ctx, Options{Path: path, BusyTimeout: time.Second})
	if err != nil {
		t.Fatalf("Close 後應可重新開啟: %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatalf("關閉失敗: %v", err)
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	if _, err := Open(context.Background(), Options{Path: "  "}); err == nil {
		t.Fatal("空路徑應被拒絕")
	}
}

func TestBusyTimeoutDefaultsWhenUnset(t *testing.T) {
	// 未指定 BusyTimeout 時採預設值，且必須在連線上生效。
	db := openTestDB(t, 0)
	var busy int
	if err := db.SQL().QueryRow("PRAGMA busy_timeout").Scan(&busy); err != nil {
		t.Fatalf("讀取 busy_timeout 失敗: %v", err)
	}
	if want := int(defaultBusyTimeout.Milliseconds()); busy != want {
		t.Fatalf("busy_timeout 應為預設 %d ms，實際 %d ms", want, busy)
	}
}

func TestDSNEncodesPathSegments(t *testing.T) {
	dsn := dsn(filepath.Join("dir with space", "資料%目錄", "evernight.db"), 5*time.Second, BeginImmediate)
	for _, want := range []string{
		"file:",
		"dir%20with%20space",
		"%25", // '%' 必須編碼，否則 SQLite 會做 URI 解碼而改變檔名
		"_pragma=journal_mode(WAL)",
		"_pragma=foreign_keys(1)",
		"_txlock=immediate",
		"_pragma=busy_timeout(5000)",
	} {
		if !strings.Contains(dsn, want) {
			t.Fatalf("DSN 應包含 %q，實際 %q", want, dsn)
		}
	}
}
