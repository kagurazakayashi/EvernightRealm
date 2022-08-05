package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
)

// digestOf 回傳檔案 SHA-256；檔案不存在時回傳固定字串。
func digestOf(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "missing"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// writeDatabaseWithMarker 於資料目錄建立帶指定標記的資料庫檔（模擬較新執行檔留下的資料庫）。
func writeDatabaseWithMarker(t *testing.T, dir string, appID uint32, userVersion int) string {
	t.Helper()
	path := filepath.Join(dir, "evernight.db")
	pool, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=busy_timeout(1000)")
	if err != nil {
		t.Fatalf("建立測試資料庫失敗: %v", err)
	}
	ctx := context.Background()
	for _, statement := range []string{
		"CREATE TABLE future_table (id INTEGER PRIMARY KEY)",
		fmt.Sprintf("PRAGMA application_id = %d", appID),
		fmt.Sprintf("PRAGMA user_version = %d", userVersion),
	} {
		if _, err := pool.ExecContext(ctx, statement); err != nil {
			_ = pool.Close()
			t.Fatalf("執行 %q 失敗: %v", statement, err)
		}
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("關閉測試資料庫失敗: %v", err)
	}
	return path
}

func TestRunRefusesFutureSchemaVersionWithoutWriting(t *testing.T) {
	// 驗收：未來版本啟動失敗，原庫保持完整（規格附錄 E.5）。
	dir := retryTempDir(t)
	path := writeDatabaseWithMarker(t, dir, database.ApplicationID, 99)
	before := map[string]string{
		path:          digestOf(path),
		path + "-wal": digestOf(path + "-wal"),
		path + "-shm": digestOf(path + "-shm"),
	}

	out := &syncBuffer{}
	err := run(context.Background(), func() {}, []string{"--data-dir", dir}, out, io.Discard)
	if err == nil {
		t.Fatal("較新版本的資料庫應使啟動失敗")
	}
	if !errors.Is(err, database.ErrSchemaTooNew) {
		t.Fatalf("錯誤應為 ErrSchemaTooNew，實際 %v", err)
	}
	for name, digest := range before {
		if got := digestOf(name); got != digest {
			t.Errorf("%s 在拒絕路徑上被改動", filepath.Base(name))
		}
	}
	// 啟動不得有任何輸出（拒絕發生在監聽與摘要之前），也不得占用連接埠。
	if got := out.String(); got != "" {
		t.Fatalf("拒絕路徑不應有輸出，實際：%s", got)
	}
}

func TestMigrateStampsApplicationIDAndRecordsVersion(t *testing.T) {
	dir := retryTempDir(t)
	out := &syncBuffer{}
	if err := Migrate(context.Background(), []string{"--data-dir", dir}, out); err != nil {
		t.Fatalf("Migrate 失敗: %v", err)
	}

	header, err := database.ReadHeader(filepath.Join(dir, "evernight.db"))
	if err != nil {
		t.Fatalf("讀取檔頭失敗: %v", err)
	}
	if header.ApplicationID != database.ApplicationID {
		t.Fatalf("遷移後檔頭應帶本服務識別碼 0x%08X，實際 0x%08X", database.ApplicationID, header.ApplicationID)
	}
	maxVersion, err := migrate.MaxVersion()
	if err != nil {
		t.Fatalf("MaxVersion 失敗: %v", err)
	}
	if header.SchemaVersion != maxVersion {
		t.Fatalf("檔頭版本應為 %d，實際 %d", maxVersion, header.SchemaVersion)
	}
}

func TestMigrateVerifyReportsIntegrityWithoutMigrating(t *testing.T) {
	// 自檢模式：只做完整性與版本檢查，不套用遷移（資料庫維持未遷移狀態）。
	dir := retryTempDir(t)
	out := &syncBuffer{}
	if err := Migrate(context.Background(), []string{"--verify", "--data-dir", dir}, out); err != nil {
		t.Fatalf("Migrate --verify 失敗: %v", err)
	}
	output := out.String()
	for _, want := range []string{"資料庫自檢：integrity_check=ok", "資料庫版本檢查", "目前 version=0"} {
		if !strings.Contains(output, want) {
			t.Errorf("自檢輸出應含 %q，實際：%s", want, output)
		}
	}

	// 版本表不應被建立（自檢不變更資料）。
	pool, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(dir, "evernight.db"))+"?mode=ro")
	if err != nil {
		t.Fatalf("唯讀開啟失敗: %v", err)
	}
	defer func() { _ = pool.Close() }()
	var count int
	if err := pool.QueryRowContext(context.Background(),
		"SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", migrate.TableName).Scan(&count); err != nil {
		t.Fatalf("查詢版本表失敗: %v", err)
	}
	if count != 0 {
		t.Fatal("自檢模式不應建立版本表")
	}
}

func TestMigrateRejectsForeignDatabase(t *testing.T) {
	// 指向他人的 SQLite 檔時必須拒絕，且不改動該檔內容。
	dir := retryTempDir(t)
	path := writeDatabaseWithMarker(t, dir, 0x12345678, 0)
	before := digestOf(path)

	out := &syncBuffer{}
	err := Migrate(context.Background(), []string{"--data-dir", dir}, out)
	if err == nil {
		t.Fatal("他人的資料庫應被拒絕")
	}
	if !errors.Is(err, database.ErrForeignDatabase) {
		t.Fatalf("錯誤應為 ErrForeignDatabase，實際 %v", err)
	}
	if got := digestOf(path); got != before {
		t.Fatal("拒絕時不得改動他人的資料庫檔")
	}
}

func TestRunWithIntegrityCheckAndSchemaGuardConfigured(t *testing.T) {
	// 組態可開啟啟動時完整性自檢，並可設定寫入把關層級（transaction 於交易邊界複驗）。
	dir := retryTempDir(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("建立資料目錄失敗: %v", err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(
		"database:\n  integrity_check: true\n  schema_guard: \"transaction\"\n  preflight: \"readonly\"\n"), 0o600); err != nil {
		t.Fatalf("寫入組態失敗: %v", err)
	}

	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, cancel, []string{"--data-dir", dir}, out, io.Discard) }()

	addr := waitForListenAddr(t, out, runErr)
	if addr == "" {
		t.Fatal("應取得監聽地址")
	}
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run 失敗: %v（輸出：%s）", err, out.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run 未在期限內結束")
	}

	output := out.String()
	for _, want := range []string{
		"資料庫完整性自檢：integrity_check=ok",
		// 交易策略預設值需在啟動輸出可見。
		"資料庫交易策略：begin_mode=immediate nested=reject busy_retry_max=0 " +
			"busy_retry_backoff_ms=50 timeout_ms=10000 schema_guard=transaction",
		"資料庫寫入把關：schema_guard=transaction",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("啟動輸出應含 %q，實際：%s", want, output)
		}
	}
	// 唯讀預檢模式下仍須正常啟動並完成遷移。
	if !strings.Contains(output, "資料庫遷移：已套用") {
		t.Errorf("應完成首次遷移，實際：%s", output)
	}
}
