package migrate

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// mustOpen 開啟指定路徑的測試資料庫（含單寫入實例鎖）。
func mustOpen(t *testing.T, path string) *database.DB {
	t.Helper()
	db, err := database.Open(context.Background(), database.Options{Path: path, BusyTimeout: time.Second})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗: %v", err)
	}
	return db
}

// openTestDB 於暫存目錄開啟測試資料庫並自動關閉。
func openTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(retryTempDir(t), "evernight.db")
	db := mustOpen(t, path)
	t.Cleanup(func() { _ = db.Close() })
	return db.SQL(), path
}

// testMigration 以內容產生遷移（雜湊由內容計算，與正式流程一致）。
func testMigration(version int, name, sqlText string) Migration {
	return Migration{Version: version, Name: name, Checksum: checksum([]byte(sqlText)), SQL: sqlText}
}

// TestLoadEmbeddedMigrations 驗證內嵌遷移可讀取且命名、版本、內容皆合法。
func TestLoadEmbeddedMigrations(t *testing.T) {
	migrations, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("內嵌遷移不得為空（至少需有首支建表遷移）")
	}
	namePattern := regexp.MustCompile(`^\d{4}_[a-z0-9_]+$`)
	for i, m := range migrations {
		if m.Version <= 0 {
			t.Errorf("遷移版本必須為正整數：%+v", m)
		}
		if i > 0 && migrations[i-1].Version >= m.Version {
			t.Errorf("遷移版本必須嚴格遞增：%s 之後為 %s", migrations[i-1], m)
		}
		if !namePattern.MatchString(m.String()) {
			t.Errorf("遷移名稱格式不符：%q", m.String())
		}
		if len(m.Checksum) != 64 {
			t.Errorf("%s 的雜湊長度應為 64，實際 %d", m, len(m.Checksum))
		}
		if strings.TrimSpace(m.SQL) == "" {
			t.Errorf("%s 內容不得為空", m)
		}
	}
}

// TestParseName 驗證遷移檔名規則。
func TestParseName(t *testing.T) {
	valid := map[string]int{
		"0001_server_settings.sql": 1,
		"0042_add_index.sql":       42,
	}
	for name, wantVersion := range valid {
		version, _, err := parseName(name)
		if err != nil {
			t.Errorf("檔名 %q 應被接受，實際錯誤: %v", name, err)
			continue
		}
		if version != wantVersion {
			t.Errorf("檔名 %q 版本應為 %d，實際 %d", name, wantVersion, version)
		}
	}

	invalid := []string{
		"1_x.sql",        // 版本未補零
		"0001_.sql",      // 名稱缺失
		"0001_x.SQL",     // 副檔名大小寫
		"0001-x.sql",     // 分隔符錯誤
		"0001_X.sql",     // 名稱含大寫
		"0000_x.sql",     // 版本為 0
		"0001_x.sql.bak", // 非 .sql
		"readme.sql",     // 無版本前綴
	}
	for _, name := range invalid {
		if _, _, err := parseName(name); err == nil {
			t.Errorf("檔名 %q 應被拒絕", name)
		}
	}
}

// TestApplyOnEmptyDatabase 驗證空庫建立：建立版本表、依序套用、結構實際生效。
func TestApplyOnEmptyDatabase(t *testing.T) {
	ctx := context.Background()
	pool, _ := openTestDB(t)
	before := time.Now().UTC()

	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗: %v", err)
	}
	res, err := Apply(ctx, pool, Options{})
	if err != nil {
		t.Fatalf("空庫套用遷移失敗: %v", err)
	}
	if res.FromVersion != 0 {
		t.Errorf("空庫套用前版本應為 0，實際 %d", res.FromVersion)
	}
	if len(res.Applied) != len(known) {
		t.Fatalf("應套用全部 %d 支遷移，實際 %d", len(known), len(res.Applied))
	}
	if res.Skipped != 0 {
		t.Errorf("空庫不應有略過的遷移，實際 %d", res.Skipped)
	}
	wantVersion := known[len(known)-1].Version
	if res.ToVersion != wantVersion {
		t.Errorf("套用後版本應為 %d，實際 %d", wantVersion, res.ToVersion)
	}

	applied, err := loadApplied(ctx, pool)
	if err != nil {
		t.Fatalf("讀取版本表失敗: %v", err)
	}
	if len(applied) != len(known) {
		t.Fatalf("版本表應有 %d 筆記錄，實際 %d", len(known), len(applied))
	}
	for _, a := range applied {
		if a.AppliedAt.Before(before.Add(-time.Minute)) || a.AppliedAt.After(time.Now().UTC().Add(time.Minute)) {
			t.Errorf("%d 的套用時間不合理：%s", a.Version, a.AppliedAt)
		}
	}

	// 首支遷移的實際效果與表結構約定（時間戳為 INTEGER）。
	exists, err := tableExists(ctx, pool, "server_settings")
	if err != nil {
		t.Fatalf("查詢 server_settings 失敗: %v", err)
	}
	if !exists {
		t.Fatal("套用後應存在 server_settings 表")
	}
	columns := readColumns(t, pool, "server_settings")
	wantTypes := map[string]string{"key": "TEXT", "value": "TEXT", "updated_at": "INTEGER"}
	for column, wantType := range wantTypes {
		gotType, ok := columns[column]
		if !ok {
			t.Errorf("server_settings 缺少欄位 %s", column)
			continue
		}
		if gotType != wantType {
			t.Errorf("欄位 %s 型別應為 %s，實際 %s", column, wantType, gotType)
		}
	}

	// 版本查詢與套用結果一致。
	current, err := Current(ctx, pool)
	if err != nil {
		t.Fatalf("讀取目前版本失敗: %v", err)
	}
	if current != res.ToVersion {
		t.Errorf("Current 應為 %d，實際 %d", res.ToVersion, current)
	}
}

// TestApplyUsesInjectedClock 驗證版本記錄的時間戳取自注入的時鐘而非系統牆鐘：
// 業務時間必須可注入，後續交易、Pending 與排程的判定才能被確定性地驗證（規格 §27.2）。
func TestApplyUsesInjectedClock(t *testing.T) {
	ctx := context.Background()
	clock := timeutil.NewTest(time.Date(2026, 9, 25, 12, 34, 56, 789_000_000, time.UTC))

	poolFirst, _ := openTestDB(t)
	res, err := Apply(ctx, poolFirst, Options{Clock: clock})
	if err != nil {
		t.Fatalf("注入時鐘套用遷移失敗: %v", err)
	}
	if len(res.Applied) == 0 {
		t.Fatal("本測試需要有待套用的遷移")
	}
	assertAppliedAt(t, ctx, poolFirst, timeutil.ToMillis(clock.Now()))

	// 推進時鐘後套用到另一個空白庫：時間戳隨之改變，證明取值發生在套用當下而非建立時鐘時。
	clock.Advance(time.Minute)
	poolSecond, _ := openTestDB(t)
	if _, err := Apply(ctx, poolSecond, Options{Clock: clock}); err != nil {
		t.Fatalf("推進時鐘後套用遷移失敗: %v", err)
	}
	assertAppliedAt(t, ctx, poolSecond, timeutil.ToMillis(clock.Now()))
}

// assertAppliedAt 確認版本表每一筆的原始欄位（Unix 毫秒整數）與讀回值都等於毫秒值。
func assertAppliedAt(t *testing.T, ctx context.Context, pool *sql.DB, millis int64) {
	t.Helper()

	rows, err := pool.QueryContext(ctx, "SELECT version, applied_at FROM "+TableName+" ORDER BY version")
	if err != nil {
		t.Fatalf("讀取原始版本表失敗: %v", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var version int
		var got int64
		if err := rows.Scan(&version, &got); err != nil {
			t.Fatalf("解析原始版本表失敗: %v", err)
		}
		count++
		if got != millis {
			t.Errorf("版本 %d 的 applied_at 應為注入時鐘的 %d 毫秒，實際 %d", version, millis, got)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("讀取原始版本表失敗: %v", err)
	}
	if count == 0 {
		t.Fatal("版本表不應為空")
	}

	applied, err := loadApplied(ctx, pool)
	if err != nil {
		t.Fatalf("讀取版本表失敗: %v", err)
	}
	for _, a := range applied {
		if a.AppliedAt.UnixMilli() != millis {
			t.Errorf("版本 %d 讀回的時間應為 %d 毫秒，實際 %v", a.Version, millis, a.AppliedAt)
		}
		if _, offset := a.AppliedAt.Zone(); offset != 0 {
			t.Errorf("版本 %d 讀回的時間應為 UTC，實際區偏移 %d 秒", a.Version, offset)
		}
	}
}

// TestApplyAcrossRestartIsIdempotent 驗證重複啟動：重新開啟資料庫後再套用為冪等，
// 且先前寫入的資料仍可讀取。
func TestApplyAcrossRestartIsIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(retryTempDir(t), "evernight.db")

	first := mustOpen(t, path)
	firstRes, err := Apply(ctx, first.SQL(), Options{})
	if err != nil {
		t.Fatalf("首次套用遷移失敗: %v", err)
	}
	if _, err := first.SQL().ExecContext(ctx,
		"INSERT INTO server_settings (key, value, updated_at) VALUES (?, ?, ?)",
		"display_timezone", "Asia/Taipei", time.Now().UTC().UnixMilli()); err != nil {
		t.Fatalf("寫入設定失敗: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("關閉資料庫失敗: %v", err)
	}

	// 模擬重啟：重新開啟同一資料庫並再次套用。
	second := mustOpen(t, path)
	defer func() { _ = second.Close() }()
	secondRes, err := Apply(ctx, second.SQL(), Options{})
	if err != nil {
		t.Fatalf("重啟後套用遷移失敗: %v", err)
	}
	if len(secondRes.Applied) != 0 {
		t.Errorf("重啟後不應重複套用遷移，實際套用 %d 支", len(secondRes.Applied))
	}
	if len(secondRes.Pending) != 0 || len(secondRes.Applied) != 0 || secondRes.Skipped == 0 {
		t.Errorf("重啟後應全部略過（略過 %d 支、待套用 %d 支、已套用 %d 支）",
			secondRes.Skipped, len(secondRes.Pending), len(secondRes.Applied))
	}
	if secondRes.FromVersion != firstRes.ToVersion || secondRes.ToVersion != firstRes.ToVersion {
		t.Errorf("重啟後版本應維持 %d，實際 %d → %d", firstRes.ToVersion, secondRes.FromVersion, secondRes.ToVersion)
	}

	var value string
	if err := second.SQL().QueryRowContext(ctx,
		"SELECT value FROM server_settings WHERE key = ?", "display_timezone").Scan(&value); err != nil {
		t.Fatalf("重啟後讀取先前資料失敗: %v", err)
	}
	if value != "Asia/Taipei" {
		t.Errorf("重啟後讀到的值應為 Asia/Taipei，實際 %q", value)
	}
}

// TestApplyDryRunDoesNotTouchDatabase 驗證檢查模式完全不變更資料庫。
func TestApplyDryRunDoesNotTouchDatabase(t *testing.T) {
	ctx := context.Background()
	pool, path := openTestDB(t)

	known, err := Load()
	if err != nil {
		t.Fatalf("讀取內嵌遷移失敗: %v", err)
	}
	res, err := Apply(ctx, pool, Options{DryRun: true})
	if err != nil {
		t.Fatalf("檢查模式失敗: %v", err)
	}
	if !res.DryRun {
		t.Error("結果應標記為檢查模式")
	}
	if len(res.Pending) != len(known) || len(res.Applied) != 0 {
		t.Errorf("空庫檢查模式應列出全部 %d 支待套用、且不套用任何遷移，實際待套用 %d、已套用 %d",
			len(known), len(res.Pending), len(res.Applied))
	}
	if res.FromVersion != 0 || res.ToVersion != 0 {
		t.Errorf("檢查模式不應改變版本，實際 %d → %d", res.FromVersion, res.ToVersion)
	}
	exists, err := tableExists(ctx, pool)
	if err != nil {
		t.Fatalf("查詢版本表失敗: %v", err)
	}
	if exists {
		t.Error("檢查模式不應建立版本表")
	}
	if settingsExists, err := tableExists(ctx, pool, "server_settings"); err != nil {
		t.Fatalf("查詢 server_settings 失敗: %v", err)
	} else if settingsExists {
		t.Error("檢查模式不應建立業務資料表")
	}

	// 檢查模式後仍可正常套用（狀態未被檢查動作污染）。
	if _, err := Apply(ctx, pool, Options{}); err != nil {
		t.Fatalf("檢查模式後套用遷移失敗: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("資料庫檔應存在: %v", err)
	}
}

// TestFailedMigrationRollsBackAndKeepsVersion 驗證失敗中止：
// 失敗的遷移整支回滾（不留半套用結構），版本表維持在前一版本，
// 修正後可繼續套用。
func TestFailedMigrationRollsBackAndKeepsVersion(t *testing.T) {
	ctx := context.Background()
	pool, _ := openTestDB(t)

	known := []Migration{
		testMigration(1, "create_first", "CREATE TABLE first_table (id INTEGER PRIMARY KEY);"),
		testMigration(2, "create_second", "CREATE TABLE second_table (id INTEGER PRIMARY KEY);"+
			" INSERT INTO no_such_table (id) VALUES (1);"),
	}
	if _, err := applySet(ctx, pool, known, Options{}); err == nil {
		t.Fatal("遷移內容有誤時應回報錯誤")
	}

	applied, err := loadApplied(ctx, pool)
	if err != nil {
		t.Fatalf("讀取版本表失敗: %v", err)
	}
	if len(applied) != 1 || applied[0].Version != 1 {
		t.Fatalf("版本表應只保留已成功的第 1 版，實際 %+v", applied)
	}
	if exists, err := tableExists(ctx, pool, "second_table"); err != nil {
		t.Fatalf("查詢 second_table 失敗: %v", err)
	} else if exists {
		t.Error("失敗的遷移必須整支回滾，不得留下中途建立的表")
	}
	if exists, err := tableExists(ctx, pool, "first_table"); err != nil {
		t.Fatalf("查詢 first_table 失敗: %v", err)
	} else if !exists {
		t.Error("已成功的遷移不得被回滾")
	}

	// 修正該支遷移後可續套用，版本推進到 2。
	fixed := []Migration{
		known[0],
		testMigration(2, "create_second", "CREATE TABLE second_table (id INTEGER PRIMARY KEY);"),
	}
	res, err := applySet(ctx, pool, fixed, Options{})
	if err != nil {
		t.Fatalf("修正後套用失敗: %v", err)
	}
	if res.FromVersion != 1 || res.ToVersion != 2 || len(res.Applied) != 1 {
		t.Errorf("修正後應由版本 1 推進到 2（套用 1 支），實際 %d → %d（套用 %d 支）",
			res.FromVersion, res.ToVersion, len(res.Applied))
	}
	if exists, err := tableExists(ctx, pool, "second_table"); err != nil {
		t.Fatalf("查詢 second_table 失敗: %v", err)
	} else if !exists {
		t.Error("修正後應成功建立 second_table")
	}
}

// TestFutureVersionRejected 驗證資料庫版本較執行檔新時拒絕執行，且原庫保持完整。
func TestFutureVersionRejected(t *testing.T) {
	ctx := context.Background()
	pool, _ := openTestDB(t)

	known := []Migration{testMigration(1, "create_first", "CREATE TABLE first_table (id INTEGER PRIMARY KEY);")}
	if _, err := applySet(ctx, pool, known, Options{}); err != nil {
		t.Fatalf("套用遷移失敗: %v", err)
	}
	// 模擬資料庫曾被較新的執行檔遷移過。
	if _, err := pool.ExecContext(ctx,
		"INSERT INTO "+TableName+" (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
		9999, "from_newer_build", checksum([]byte("future")), time.Now().UTC().UnixMilli()); err != nil {
		t.Fatalf("寫入未來版本記錄失敗: %v", err)
	}

	_, err := applySet(ctx, pool, known, Options{})
	if !errors.Is(err, ErrFutureVersion) {
		t.Fatalf("應回報版本較新（ErrFutureVersion），實際: %v", err)
	}

	// 原庫保持完整：版本記錄未被刪除、結構未被變更。
	applied, err := loadApplied(ctx, pool)
	if err != nil {
		t.Fatalf("讀取版本表失敗: %v", err)
	}
	if len(applied) != 2 {
		t.Errorf("拒絕執行時不得刪除版本記錄，實際剩 %d 筆", len(applied))
	}
	if exists, err := tableExists(ctx, pool, "first_table"); err != nil {
		t.Fatalf("查詢 first_table 失敗: %v", err)
	} else if !exists {
		t.Error("拒絕執行時不得變更既有結構")
	}
}

// TestChecksumMismatchRejected 驗證已發布遷移被改寫時拒絕執行。
func TestChecksumMismatchRejected(t *testing.T) {
	ctx := context.Background()
	pool, _ := openTestDB(t)

	original := []Migration{testMigration(1, "create_first", "CREATE TABLE first_table (id INTEGER PRIMARY KEY);")}
	if _, err := applySet(ctx, pool, original, Options{}); err != nil {
		t.Fatalf("套用遷移失敗: %v", err)
	}
	rewritten := []Migration{testMigration(1, "create_first", "CREATE TABLE first_table (id INTEGER PRIMARY KEY, note TEXT);")}

	_, err := applySet(ctx, pool, rewritten, Options{})
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("應回報內容不符（ErrChecksumMismatch），實際: %v", err)
	}
	if !strings.Contains(err.Error(), "0001_create_first") {
		t.Errorf("錯誤訊息應指出遷移名稱，實際: %v", err)
	}
}

// TestOutOfOrderRejected 驗證版本表狀態不連續時拒絕執行。
func TestOutOfOrderRejected(t *testing.T) {
	ctx := context.Background()
	pool, _ := openTestDB(t)

	second := testMigration(2, "create_second", "CREATE TABLE second_table (id INTEGER PRIMARY KEY);")
	if _, err := applySet(ctx, pool, []Migration{second}, Options{}); err != nil {
		t.Fatalf("套用遷移失敗: %v", err)
	}
	first := testMigration(1, "create_first", "CREATE TABLE first_table (id INTEGER PRIMARY KEY);")

	_, err := applySet(ctx, pool, []Migration{first, second}, Options{})
	if !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("應回報狀態不連續（ErrOutOfOrder），實際: %v", err)
	}

	// 缺少對應遷移檔（未知版本）同樣視為不連續。
	_, err = applySet(ctx, pool, []Migration{testMigration(3, "create_third", "CREATE TABLE third_table (id INTEGER PRIMARY KEY);")}, Options{})
	if !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("執行檔缺少版本表中既有的遷移時應回報不連續，實際: %v", err)
	}
}

// TestApplyRejectsInvalidInput 驗證 nil 連線與非法遷移集合皆被拒絕。
func TestApplyRejectsInvalidInput(t *testing.T) {
	ctx := context.Background()
	if _, err := Apply(ctx, nil, Options{}); err == nil {
		t.Error("nil 連線應被拒絕")
	}
	pool, _ := openTestDB(t)
	if _, err := Current(ctx, nil); err == nil {
		t.Error("Current 的 nil 連線應被拒絕")
	}
	if _, err := applySet(ctx, pool, []Migration{testMigration(0, "zero", "SELECT 1;")}, Options{}); err == nil {
		t.Error("版本 0 應被拒絕")
	}
	duplicated := []Migration{
		testMigration(1, "a", "SELECT 1;"),
		testMigration(1, "b", "SELECT 2;"),
	}
	if _, err := applySet(ctx, pool, duplicated, Options{}); err == nil {
		t.Error("版本重複的遷移集合應被拒絕")
	}
}

// readColumns 讀取指定資料表的欄位名稱與型別。
func readColumns(t *testing.T, pool *sql.DB, table string) map[string]string {
	t.Helper()
	rows, err := pool.Query("SELECT name, type FROM pragma_table_info(?)", table)
	if err != nil {
		t.Fatalf("讀取 %s 欄位失敗: %v", table, err)
	}
	defer func() { _ = rows.Close() }()

	columns := map[string]string{}
	for rows.Next() {
		var name, columnType string
		if err := rows.Scan(&name, &columnType); err != nil {
			t.Fatalf("解析 %s 欄位失敗: %v", table, err)
		}
		columns[name] = strings.ToUpper(columnType)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("讀取 %s 欄位失敗: %v", table, err)
	}
	return columns
}
