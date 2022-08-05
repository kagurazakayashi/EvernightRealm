package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
)

// createForeignDatabase 以驅動層建立「他人的資料庫」：有使用者資料表但沒有版本表。
func createForeignDatabase(t *testing.T, path string, statements ...string) {
	t.Helper()
	pool, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=busy_timeout(1000)")
	if err != nil {
		t.Fatalf("建立測試資料庫失敗: %v", err)
	}
	for _, statement := range statements {
		if _, err := pool.ExecContext(context.Background(), statement); err != nil {
			_ = pool.Close()
			t.Fatalf("執行 %q 失敗: %v", statement, err)
		}
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("關閉測試資料庫失敗: %v", err)
	}
}

// TestApplyRefusesUnknownNonEmptyDatabase 驗收：不認識的資料庫不得被遷移。
//
// 非空但缺少版本表表示這不是本服務建立的資料庫；若照常遷移，
// 會在別人的資料庫裡建立本服務的資料表（實證見 tools/verify/step040-preflight）。
func TestApplyRefusesUnknownNonEmptyDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(retryTempDir(t), "evernight.db")
	createForeignDatabase(t, path,
		"CREATE TABLE someone_elses (id INTEGER PRIMARY KEY, note TEXT)",
		"INSERT INTO someone_elses (id, note) VALUES (1, '別人的資料')")

	db := mustOpen(t, path)
	defer func() { _ = db.Close() }()

	// 檢查模式同樣必須拒絕：版本檢查不能對陌生資料庫給出「待套用」的假象。
	for _, dryRun := range []bool{false, true} {
		_, err := Apply(ctx, db.SQL(), Options{DryRun: dryRun})
		if err == nil {
			t.Fatalf("dryRun=%v：陌生資料庫應被拒絕遷移", dryRun)
		}
		if !errors.Is(err, ErrUnknownDatabase) {
			t.Fatalf("dryRun=%v：錯誤應為 ErrUnknownDatabase，實際 %v", dryRun, err)
		}
		if !strings.Contains(err.Error(), "someone_elses") {
			t.Fatalf("dryRun=%v：錯誤訊息應指出既有資料表，實際 %v", dryRun, err)
		}
	}

	// 原資料必須完好：他人的資料表保留、未建立本服務的版本表與資料表。
	var rows int
	if err := db.SQL().QueryRowContext(ctx, "SELECT count(*) FROM someone_elses").Scan(&rows); err != nil {
		t.Fatalf("讀取原資料失敗: %v", err)
	}
	if rows != 1 {
		t.Fatalf("原資料應保留 1 筆，實際 %d 筆", rows)
	}
	for _, table := range []string{TableName, "server_settings"} {
		var count int
		if err := db.SQL().QueryRowContext(ctx,
			"SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil {
			t.Fatalf("查詢資料表 %s 失敗: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("陌生資料庫不應被建立 %s 資料表", table)
		}
	}
}

// TestApplyRecordsSchemaVersionInHeader 驗證遷移會在檔頭留下 schema 版本標記。
//
// 標記與版本記錄在同一交易內寫入，供開庫前預檢在尚未接觸資料庫時判定版本。
func TestApplyRecordsSchemaVersionInHeader(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(retryTempDir(t), "evernight.db")
	db := mustOpen(t, path)
	defer func() { _ = db.Close() }()

	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗: %v", err)
	}
	maxVersion, err := MaxVersion()
	if err != nil {
		t.Fatalf("MaxVersion 失敗: %v", err)
	}
	if maxVersion != known[len(known)-1].Version {
		t.Fatalf("MaxVersion 應為 %d，實際 %d", known[len(known)-1].Version, maxVersion)
	}

	if _, err := Apply(ctx, db.SQL(), Options{}); err != nil {
		t.Fatalf("遷移失敗: %v", err)
	}

	var headerVersion int
	if err := db.SQL().QueryRowContext(ctx, "PRAGMA user_version").Scan(&headerVersion); err != nil {
		t.Fatalf("讀取檔頭版本失敗: %v", err)
	}
	if headerVersion != maxVersion {
		t.Fatalf("檔頭版本應為 %d，實際 %d", maxVersion, headerVersion)
	}

	// 失敗的遷移必須連檔頭標記一起回滾（與版本記錄同進退）。
	broken := testMigration(maxVersion+1, "broken", "CREATE TABLE will_rollback (id INTEGER PRIMARY KEY);\n"+
		"INSERT INTO no_such_table (id) VALUES (1);")
	if _, err := applySet(ctx, db.SQL(), []Migration{broken}, Options{}); err == nil {
		t.Fatal("損壞的遷移應失敗")
	}
	if err := db.SQL().QueryRowContext(ctx, "PRAGMA user_version").Scan(&headerVersion); err != nil {
		t.Fatalf("讀取檔頭版本失敗: %v", err)
	}
	if headerVersion != maxVersion {
		t.Fatalf("失敗的遷移不得推進檔頭版本：應為 %d，實際 %d", maxVersion, headerVersion)
	}
}

// TestDatabaseOpenAcceptsMarkedDatabaseAfterMigration 驗證遷移後再次開庫（含檔頭預檢）不受影響。
func TestDatabaseOpenAcceptsMarkedDatabaseAfterMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(retryTempDir(t), "evernight.db")
	db := mustOpen(t, path)
	if _, err := Apply(ctx, db.SQL(), Options{}); err != nil {
		t.Fatalf("遷移失敗: %v", err)
	}
	if err := db.StampApplicationID(ctx); err != nil {
		t.Fatalf("寫入識別碼失敗: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("關閉失敗: %v", err)
	}

	maxVersion, err := MaxVersion()
	if err != nil {
		t.Fatalf("MaxVersion 失敗: %v", err)
	}
	reopened, err := database.Open(ctx, database.Options{
		Path:               path,
		BusyTimeout:        time.Second,
		KnownSchemaVersion: maxVersion,
	})
	if err != nil {
		t.Fatalf("標記後的資料庫應可再次開啟: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("關閉失敗: %v", err)
	}

	// 較新的執行檔留下的資料庫（標記版本更高）必須被拒絕開啟。
	newer, err := database.Open(ctx, database.Options{
		Path:               path,
		BusyTimeout:        time.Second,
		KnownSchemaVersion: maxVersion,
		Preflight:          database.PreflightReadOnly,
	})
	if err != nil {
		t.Fatalf("版本相同時唯讀預檢應放行: %v", err)
	}
	if err := newer.Close(); err != nil {
		t.Fatalf("關閉失敗: %v", err)
	}
	if err := bumpHeaderVersion(path, maxVersion+5); err != nil {
		t.Fatalf("寫入較新版本標記失敗: %v", err)
	}
	_, err = database.Open(ctx, database.Options{
		Path:               path,
		BusyTimeout:        time.Second,
		KnownSchemaVersion: maxVersion,
		Preflight:          database.PreflightReadOnly,
	})
	if !errors.Is(err, database.ErrSchemaTooNew) {
		t.Fatalf("較新版本應被拒絕，實際 %v", err)
	}
}

// bumpHeaderVersion 以驅動層把檔頭 schema 版本改為指定值（模擬較新執行檔留下的資料庫）。
func bumpHeaderVersion(path string, version int) error {
	pool, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=busy_timeout(1000)")
	if err != nil {
		return err
	}
	defer func() { _ = pool.Close() }()
	if _, err := pool.ExecContext(context.Background(), fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		return err
	}
	return pool.Close()
}
