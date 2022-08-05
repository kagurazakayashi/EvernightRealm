package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// createDatabaseFile 以驅動層直接建立含指定標記的資料庫檔（不經 Open，故不取單寫入鎖）。
//
// 用於準備各種「開庫前就必須被拒絕」的檔案：較新版本、他人的資料庫、缺標記的舊庫等。
func createDatabaseFile(t *testing.T, path string, appID uint32, userVersion int, statements ...string) {
	t.Helper()
	pool, err := sql.Open("sqlite", dsn(path, time.Second, BeginImmediate))
	if err != nil {
		t.Fatalf("建立測試資料庫失敗: %v", err)
	}
	ctx := context.Background()
	exec := func(query string) {
		t.Helper()
		if _, err := pool.ExecContext(ctx, query); err != nil {
			_ = pool.Close()
			t.Fatalf("執行 %q 失敗: %v", query, err)
		}
	}
	for _, statement := range statements {
		exec(statement)
	}
	if appID != 0 {
		exec(fmt.Sprintf("PRAGMA application_id = %d", appID))
	}
	if userVersion != 0 {
		exec(fmt.Sprintf("PRAGMA user_version = %d", userVersion))
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("關閉測試資料庫失敗: %v", err)
	}
}

// fileDigest 回傳檔案 SHA-256；檔案不存在時回傳固定字串。
func fileDigest(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "missing"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// snapshotFiles 記錄資料庫主檔與 WAL／共享記憶體檔的雜湊。
func snapshotFiles(path string) map[string]string {
	return map[string]string{
		path:          fileDigest(path),
		path + "-wal": fileDigest(path + "-wal"),
		path + "-shm": fileDigest(path + "-shm"),
	}
}

// assertFilesUnchanged 驗證拒絕路徑完全沒有改動資料庫檔（含 WAL 與共享記憶體檔）。
//
// 這是「拒絕時原庫保持完整」的核心斷言：預檢在開庫前完成，故連 -wal/-shm 都不該出現。
func assertFilesUnchanged(t *testing.T, path string, before map[string]string) {
	t.Helper()
	for name, digest := range before {
		if got := fileDigest(name); got != digest {
			t.Errorf("%s 在拒絕路徑上被改動（%s → %s）", filepath.Base(name), shortDigest(digest), shortDigest(got))
		}
	}
}

func shortDigest(digest string) string {
	if digest == "missing" {
		return digest
	}
	return digest[:8]
}

func TestReadHeaderStates(t *testing.T) {
	dir := retryTempDir(t)

	missing := filepath.Join(dir, "missing.db")
	if header, err := ReadHeader(missing); err != nil || header.Exists {
		t.Fatalf("檔案不存在時應回傳 Exists=false 且無錯誤，實際 %+v / %v", header, err)
	}

	empty := filepath.Join(dir, "empty.db")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("建立空檔失敗: %v", err)
	}
	if header, err := ReadHeader(empty); err != nil || !header.Empty || header.SQLite {
		t.Fatalf("空檔應標示 Empty 且非 SQLite，實際 %+v / %v", header, err)
	}

	short := filepath.Join(dir, "short.db")
	if err := os.WriteFile(short, []byte("SQLite format 3\x00"), 0o600); err != nil {
		t.Fatalf("建立短檔失敗: %v", err)
	}
	if header, err := ReadHeader(short); err != nil || header.SQLite {
		t.Fatalf("長度不足 100 位元組不應視為 SQLite，實際 %+v / %v", header, err)
	}

	junk := filepath.Join(dir, "junk.db")
	if err := os.WriteFile(junk, []byte("這不是資料庫檔，只是純文字。"), 0o600); err != nil {
		t.Fatalf("建立純文字檔失敗: %v", err)
	}
	if header, err := ReadHeader(junk); err != nil || header.SQLite {
		t.Fatalf("非 SQLite 檔不應視為 SQLite，實際 %+v / %v", header, err)
	}

	marked := filepath.Join(dir, "marked.db")
	createDatabaseFile(t, marked, ApplicationID, 7, "CREATE TABLE probe (id INTEGER PRIMARY KEY)")
	header, err := ReadHeader(marked)
	if err != nil {
		t.Fatalf("讀取檔頭失敗: %v", err)
	}
	if !header.SQLite {
		t.Fatal("標記過的資料庫應被辨識為 SQLite 檔")
	}
	if header.ApplicationID != ApplicationID {
		t.Fatalf("application_id 應為 0x%08X，實際 0x%08X", ApplicationID, header.ApplicationID)
	}
	if header.SchemaVersion != 7 {
		t.Fatalf("user_version 應為 7，實際 %d", header.SchemaVersion)
	}
}

func TestOpenRefusesIncompatibleDatabaseWithoutWriting(t *testing.T) {
	// 驗收：未來版本或第二寫入者啟動失敗，原庫保持完整（規格附錄 E.5）。
	// 預檢在開庫前完成，因此拒絕時連 -wal/-shm 都不該出現。
	cases := []struct {
		name         string
		knownVersion int
		want         error
		setup        func(t *testing.T, path string)
	}{
		{
			name:         "較新版本",
			knownVersion: 1,
			want:         ErrSchemaTooNew,
			setup: func(t *testing.T, path string) {
				createDatabaseFile(t, path, ApplicationID, 99, "CREATE TABLE probe (id INTEGER PRIMARY KEY)")
			},
		},
		{
			name:         "他人的資料庫",
			knownVersion: 1,
			want:         ErrForeignDatabase,
			setup: func(t *testing.T, path string) {
				createDatabaseFile(t, path, 0x12345678, 1, "CREATE TABLE someone_elses (id INTEGER PRIMARY KEY)")
			},
		},
		{
			name:         "非 SQLite 檔",
			knownVersion: 1,
			want:         ErrNotSQLite,
			setup: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("純文字，不是資料庫"), 0o600); err != nil {
					t.Fatalf("建立測試檔失敗: %v", err)
				}
			},
		},
		{
			name:         "長度不足的檔案",
			knownVersion: 1,
			want:         ErrNotSQLite,
			setup: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("SQLite"), 0o600); err != nil {
					t.Fatalf("建立測試檔失敗: %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := retryTempDir(t)
			path := filepath.Join(dir, "evernight.db")
			tc.setup(t, path)
			before := snapshotFiles(path)

			db, err := Open(context.Background(), Options{
				Path:               path,
				BusyTimeout:        time.Second,
				KnownSchemaVersion: tc.knownVersion,
			})
			if err == nil {
				_ = db.Close()
				t.Fatal("不相容的資料庫應被拒絕開啟")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("錯誤應為 %v，實際 %v", tc.want, err)
			}
			assertFilesUnchanged(t, path, before)

			// 拒絕必須發生在開庫前：不得留下 WAL 或共享記憶體檔。
			if _, err := os.Stat(path + "-wal"); err == nil {
				t.Error("拒絕路徑不應建立 WAL 檔")
			}
			if _, err := os.Stat(path + "-shm"); err == nil {
				t.Error("拒絕路徑不應建立共享記憶體檔")
			}
		})
	}
}

func TestReadOnlyPreflightCatchesVersionInWal(t *testing.T) {
	// 檔頭標記的已知限制：WAL 已提交但未 checkpoint 時主檔檔頭會落後；
	// 唯讀預檢（mode=ro）能看到 WAL 中的最新版本，因此可攔截這種較新版本。
	ctx := context.Background()
	dir := retryTempDir(t)
	path := filepath.Join(dir, "evernight.db")
	createDatabaseFile(t, path, ApplicationID, 1, "CREATE TABLE probe (id INTEGER PRIMARY KEY)")

	holder, err := sql.Open("sqlite", dsn(path, time.Second, BeginImmediate))
	if err != nil {
		t.Fatalf("開啟模擬較新版本連線失敗: %v", err)
	}
	defer func() { _ = holder.Close() }()
	if _, err := holder.ExecContext(ctx, "PRAGMA user_version = 99"); err != nil {
		t.Fatalf("寫入較新版本標記失敗: %v", err)
	}
	header, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("讀取檔頭失敗: %v", err)
	}
	if header.SchemaVersion != 1 {
		t.Fatalf("前提不成立：主檔檔頭應仍為舊版本，實際 %d", header.SchemaVersion)
	}

	// 唯讀預檢必須先於檔頭預檢執行（前者拒絕時不開庫，故不觸發 checkpoint 而改寫檔頭）。
	_, err = Open(ctx, Options{
		Path:               path,
		BusyTimeout:        time.Second,
		KnownSchemaVersion: 1,
		Preflight:          PreflightReadOnly,
	})
	if err == nil {
		t.Fatal("唯讀預檢應攔截僅存在於 WAL 的較新版本")
	}
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("錯誤應為 ErrSchemaTooNew，實際 %v", err)
	}

	// 對照組：檔頭預檢放行（版本藏在 WAL 中，檔頭看不到）——這是選用唯讀模式的理由。
	db, err := Open(ctx, Options{
		Path:               path,
		BusyTimeout:        time.Second,
		KnownSchemaVersion: 1,
		Preflight:          PreflightHeader,
	})
	if err != nil {
		t.Fatalf("檔頭預檢模式應放行（已知限制）: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("關閉失敗: %v", err)
	}
}

func TestPreflightOffSkipsChecks(t *testing.T) {
	// off 模式直接可寫開啟：外來檔在開庫階段不攔截，改由版本表把關（取捨已記錄於組態註解）。
	dir := retryTempDir(t)
	path := filepath.Join(dir, "evernight.db")
	createDatabaseFile(t, path, 0x12345678, 1, "CREATE TABLE someone_elses (id INTEGER PRIMARY KEY)")

	db, err := Open(context.Background(), Options{
		Path:               path,
		BusyTimeout:        time.Second,
		KnownSchemaVersion: 1,
		Preflight:          PreflightOff,
	})
	if err != nil {
		t.Fatalf("off 模式不應在開庫階段拒絕: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("關閉失敗: %v", err)
	}
}

func TestStampApplicationIDAdoptsUnmarkedDatabase(t *testing.T) {
	// 未標記的資料庫（如本步驟之前建立、或他人以預設值建立）在開啟階段不寫入標記；
	// 只有確認資料庫為本服務所有（遷移成功）後才落標記。
	ctx := context.Background()
	dir := retryTempDir(t)
	path := filepath.Join(dir, "evernight.db")
	createDatabaseFile(t, path, 0, 0, "CREATE TABLE legacy (id INTEGER PRIMARY KEY)")

	db, err := Open(ctx, Options{Path: path, BusyTimeout: time.Second, KnownSchemaVersion: 1})
	if err != nil {
		t.Fatalf("未標記的資料庫應可開啟（由版本表與識別檢查把關）: %v", err)
	}
	defer func() { _ = db.Close() }()

	if header, err := ReadHeader(path); err != nil || header.ApplicationID == ApplicationID {
		t.Fatalf("開啟階段不應寫入識別碼，實際 0x%08X / %v", header.ApplicationID, err)
	}
	if err := db.StampApplicationID(ctx); err != nil {
		t.Fatalf("寫入識別碼失敗: %v", err)
	}
	// 以 SQLite 視角確認（含尚未 checkpoint 的 WAL 變更）。
	var stamped int64
	if err := db.SQL().QueryRowContext(ctx, "PRAGMA application_id").Scan(&stamped); err != nil {
		t.Fatalf("讀取識別碼失敗: %v", err)
	}
	if uint32(stamped) != ApplicationID {
		t.Fatalf("識別碼應為 0x%08X，實際 0x%08X", ApplicationID, uint32(stamped))
	}

	// 冪等：已標記時不再寫入。
	if err := db.StampApplicationID(ctx); err != nil {
		t.Fatalf("重複標記應成功: %v", err)
	}

	// 程序正常結束（最後一個連線關閉）時 SQLite 會 checkpoint，標記落入主檔；
	// 標記在 checkpoint 前只存在於 WAL，屬預期行為（預檢僅為快速判斷，
	// 權威來源仍是版本表）。
	if err := db.Close(); err != nil {
		t.Fatalf("關閉失敗: %v", err)
	}
	header, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("讀取檔頭失敗: %v", err)
	}
	if header.ApplicationID != ApplicationID {
		t.Fatalf("關閉後主檔檔頭應帶識別碼 0x%08X，實際 0x%08X", ApplicationID, header.ApplicationID)
	}
}

func TestSecondWriterRejectionReportsHolder(t *testing.T) {
	// 拒絕第二個寫入者時附上持有者資訊（pid/取得時間），讓使用者直接知道是誰占用。
	ctx := context.Background()
	dir := retryTempDir(t)
	path := filepath.Join(dir, "evernight.db")

	first, err := Open(ctx, Options{Path: path, BusyTimeout: time.Second})
	if err != nil {
		t.Fatalf("首次 Open 失敗: %v", err)
	}
	defer func() { _ = first.Close() }()

	before := snapshotFiles(path)
	second, err := Open(ctx, Options{Path: path, BusyTimeout: time.Second})
	if err == nil {
		_ = second.Close()
		t.Fatal("第二個寫入者應被拒絕")
	}
	message := err.Error()
	if !strings.Contains(message, "目前持有者：") {
		t.Fatalf("錯誤訊息應附上持有者資訊，實際: %v", err)
	}
	if !strings.Contains(message, fmt.Sprintf("pid=%d", os.Getpid())) {
		t.Fatalf("持有者資訊應包含 pid，實際: %v", err)
	}
	assertFilesUnchanged(t, path, before)
}

func TestCheckIntegrityDetectsForeignKeyViolation(t *testing.T) {
	ctx := context.Background()
	dir := retryTempDir(t)
	path := filepath.Join(dir, "evernight.db")
	createDatabaseFile(t, path, ApplicationID, 1,
		"CREATE TABLE parent (id INTEGER PRIMARY KEY)",
		"CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))")

	db, err := Open(ctx, Options{Path: path, BusyTimeout: time.Second, KnownSchemaVersion: 1})
	if err != nil {
		t.Fatalf("Open 失敗: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := db.CheckIntegrity(ctx); err != nil {
		t.Fatalf("乾淨的資料庫自檢應通過: %v", err)
	}

	// 以關閉外鍵的連線寫入違規資料（模擬外部寫入或歷史資料）。
	raw, err := sql.Open("sqlite", "file:"+encodeURIPath(path)+"?_pragma=busy_timeout(1000)")
	if err != nil {
		t.Fatalf("開啟模擬連線失敗: %v", err)
	}
	if _, err := raw.ExecContext(ctx, "INSERT INTO child (id, parent_id) VALUES (1, 999)"); err != nil {
		_ = raw.Close()
		t.Fatalf("寫入違規資料失敗: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("關閉模擬連線失敗: %v", err)
	}

	err = db.CheckIntegrity(ctx)
	if err == nil {
		t.Fatal("外鍵違規應被自檢發現")
	}
	if !strings.Contains(err.Error(), "外鍵違規") {
		t.Fatalf("錯誤訊息應指出外鍵違規，實際: %v", err)
	}
}
