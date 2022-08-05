package database

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 本檔測的是「一致性快照」這條路徑的實測性質，逐條對應備份取法選定的理由：
// 快照含 WAL 內已提交未 checkpoint 的資料、不碰源庫、目標已存在即拒、連線唯讀寫不動源庫、
// 服務持鎖期間仍取得出快照、未提交的列不會混進來。

// openAt 在指定路徑開啟測試資料庫（正式開庫流程，含單寫入實例鎖），測試結束自動關閉。
func openAt(t *testing.T, path string, busy time.Duration) *DB {
	t.Helper()
	db, err := Open(context.Background(), Options{Path: path, BusyTimeout: busy})
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

// migrateToHead 用正式遷移器把結構套到內嵌遷移的最高版本，再建一張探針表。
//
// 回傳值是遷移器報出的最高版本，讓斷言不必在測試裡重複寫一次「應該是 2」。
func migrateToHead(t *testing.T, db *DB) int {
	t.Helper()
	res, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: timeutil.System()})
	if err != nil {
		t.Fatalf("套用遷移失敗: %v", err)
	}
	if _, err := db.SQL().ExecContext(context.Background(),
		`CREATE TABLE IF NOT EXISTS probe_rows (n INTEGER PRIMARY KEY, note TEXT NOT NULL)`); err != nil {
		t.Fatalf("建立探針表失敗: %v", err)
	}
	return res.ToVersion
}

func insertProbeRows(t *testing.T, db *DB, count int) {
	t.Helper()
	ctx := context.Background()
	err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
		for n := 1; n <= count; n++ {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO probe_rows (n, note) VALUES (?, ?)`, n, strings.Repeat("長夜幻境", 16)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("植入資料失敗: %v", err)
	}
}

// takeSnapshot 開一條快照連線、取快照、關連線，回傳快照檔位元組數。
func takeSnapshot(t *testing.T, sourcePath, target string, busy time.Duration) int64 {
	t.Helper()
	snap, err := OpenSnapshot(sourcePath, busy)
	if err != nil {
		t.Fatalf("開啟快照連線失敗: %v", err)
	}
	defer func() {
		if err := snap.Close(); err != nil {
			t.Errorf("關閉快照連線失敗: %v", err)
		}
	}()
	if err := Snapshot(context.Background(), snap, target); err != nil {
		t.Fatalf("取快照失敗: %v", err)
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatalf("快照檔不存在: %v", err)
	}
	return st.Size()
}

func countRows(t *testing.T, dbPath, query string) int {
	t.Helper()
	pool, err := sql.Open("sqlite", snapshotDSN(dbPath, time.Second))
	if err != nil {
		t.Fatalf("開啟唯讀連線失敗: %v", err)
	}
	defer pool.Close()
	var n int
	if err := pool.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("執行 %q 失敗: %v", query, err)
	}
	return n
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

// TestSnapshotIncludesUncheckpointedWAL 是本步的核心性質：
// 已提交但仍在 -wal 裡、尚未 checkpoint 回主檔的資料必須出現在快照裡。
// 「複製主檔」這條路線就是在這一步失敗的。
func TestSnapshotIncludesUncheckpointedWAL(t *testing.T) {
	dir := retryTempDir(t)
	path := filepath.Join(dir, "probe.db")
	db := openAt(t, path, 2*time.Second)
	migrateToHead(t, db)
	insertProbeRows(t, db, 500)

	wal := path + "-wal"
	if fileSize(wal) == 0 {
		t.Fatal("前提不成立：此環境沒有產生 -wal，無法驗證「WAL 內資料也在快照裡」")
	}
	if mainSize := fileSize(path); mainSize > fileSize(wal) {
		t.Errorf("主檔（%d B）比 -wal（%d B）大，說明資料已 checkpoint，本條證據要重新設計",
			mainSize, fileSize(wal))
	}

	target := filepath.Join(dir, "snap.db")
	if size := takeSnapshot(t, path, target, 2*time.Second); size == 0 {
		t.Fatal("快照檔為空")
	}
	if got := countRows(t, target, `SELECT count(*) FROM probe_rows`); got != 500 {
		t.Errorf("快照應含 WAL 裡全部 500 列，實際 %d", got)
	}
	// 快照必須是一份自足的檔案：它自己不能再依賴 -wal/-shm，否則「搬走一個檔」變成「搬走三個檔」。
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(target + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("快照不應產生 %s 側檔（stat 回 %v）", suffix, err)
		}
	}
	// 探針表以外的結構（版本表、業務表）也要在，否則備份出來的是一具空殼。
	for _, table := range []string{"schema_migrations", "server_settings", "root_audit", "activity_audit"} {
		if got := countRows(t, target, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='`+table+`'`); got != 1 {
			t.Errorf("快照缺少資料表 %s（stat 回 %d）", table, got)
		}
	}
}

// TestSnapshotLeavesSourceUntouched 要求源庫主檔與 -wal 在快照前後位元組相同：
// 快照不寫源庫，也不順手替源庫做 checkpoint。
func TestSnapshotLeavesSourceUntouched(t *testing.T) {
	dir := retryTempDir(t)
	path := filepath.Join(dir, "probe.db")
	db := openAt(t, path, 2*time.Second)
	migrateToHead(t, db)
	insertProbeRows(t, db, 200)

	// 只比主檔與 -wal。-shm（WAL 索引）刻意不在斷言內：一條唯讀連線開啟時會在裡面登記讀者位置，
	// 那是 SQLite 讓併發讀者安全的機制而不是寫進資料；把 -shm 也要求不變，等於要求「不讀」。
	// 這個差異要老實記著：備份不是純檔案讀，它是一位正經的 SQLite 讀者。
	mainBefore, walBefore := fileDigest(path), fileDigest(path+"-wal")
	takeSnapshot(t, path, filepath.Join(dir, "snap.db"), 2*time.Second)

	if got := fileDigest(path); got != mainBefore {
		t.Errorf("快照改動了源庫主檔（%s → %s）", shortDigest(mainBefore), shortDigest(got))
	}
	if got := fileDigest(path + "-wal"); got != walBefore {
		t.Errorf("快照改動了源庫 -wal（表示被 checkpoint 了）：%s → %s", shortDigest(walBefore), shortDigest(got))
	}
	// 快照結束後源庫仍要讀得回原本的資料：證明這位讀者離開時沒留下半筆狀態。
	if got := countRows(t, path, `SELECT count(*) FROM probe_rows`); got != 200 {
		t.Errorf("快照後源庫列數應仍為 200，實際 %d", got)
	}
}

func TestSnapshotRejectsExistingTarget(t *testing.T) {
	dir := retryTempDir(t)
	path := filepath.Join(dir, "probe.db")
	db := openAt(t, path, 2*time.Second)
	migrateToHead(t, db)
	insertProbeRows(t, db, 10)

	target := filepath.Join(dir, "taken.db")
	sentinel := []byte("SENTINEL")
	if err := os.WriteFile(target, sentinel, 0o644); err != nil {
		t.Fatal(err)
	}

	snap, err := OpenSnapshot(path, 2*time.Second)
	if err != nil {
		t.Fatalf("開啟快照連線失敗: %v", err)
	}
	defer snap.Close()

	err = Snapshot(context.Background(), snap, target)
	if !errors.Is(err, ErrSnapshotTargetExists) {
		t.Fatalf("目標已存在時應回 ErrSnapshotTargetExists，實際 %v", err)
	}
	if !strings.Contains(err.Error(), target) {
		t.Errorf("錯誤需點出是哪個目標檔：%v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != string(sentinel) {
		t.Errorf("拒絕時不得動到既有檔案，實際內容變成 %q", got)
	}
}

func TestSnapshotRejectsMissingParentDirectory(t *testing.T) {
	dir := retryTempDir(t)
	path := filepath.Join(dir, "probe.db")
	db := openAt(t, path, 2*time.Second)
	migrateToHead(t, db)

	snap, err := OpenSnapshot(path, 2*time.Second)
	if err != nil {
		t.Fatalf("開啟快照連線失敗: %v", err)
	}
	defer snap.Close()

	target := filepath.Join(dir, "not-created", "snap.db")
	err = Snapshot(context.Background(), snap, target)
	if err == nil {
		t.Fatal("父目錄不存在時應失敗（呼叫端得先建目錄）")
	}
	if !strings.Contains(err.Error(), target) {
		t.Errorf("錯誤需带上目標路徑：%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "not-created")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("失敗不應順手建出目錄：%v", err)
	}
}

// TestSnapshotConnectionCannotWrite 固定住「快照連線是唯讀」這件事。
//
// mode=ro 只禁止寫源庫，仍允許 VACUUM INTO 寫新檔；少了這條斷言，
// 日後有人「順手」拿這條連線去做寫入不會有任何信號。
func TestSnapshotConnectionCannotWrite(t *testing.T) {
	dir := retryTempDir(t)
	path := filepath.Join(dir, "probe.db")
	db := openAt(t, path, 2*time.Second)
	migrateToHead(t, db)
	insertProbeRows(t, db, 5)

	snap, err := OpenSnapshot(path, 2*time.Second)
	if err != nil {
		t.Fatalf("開啟快照連線失敗: %v", err)
	}
	defer snap.Close()

	if _, err := snap.ExecContext(context.Background(),
		`INSERT INTO probe_rows (n, note) VALUES (9999, '不該寫得進去')`); err == nil {
		t.Error("快照連線竟寫入了源庫，唯讀性質不成立")
	}
	if got := countRows(t, path, `SELECT count(*) FROM probe_rows WHERE n = 9999`); got != 0 {
		t.Errorf("源庫出現了本不該寫的列（%d 筆）", got)
	}
}

// TestSnapshotOpenDoesNotTakeSingleWriterLock 是本步交付形態的根據：
// 本程序正使用這個庫（持有單寫入實例鎖）時，快照連線仍然開得起來、也取得出快照。
func TestSnapshotOpenDoesNotTakeSingleWriterLock(t *testing.T) {
	dir := retryTempDir(t)
	path := filepath.Join(dir, "probe.db")
	db := openAt(t, path, 2*time.Second)
	migrateToHead(t, db)
	insertProbeRows(t, db, 100)

	size := takeSnapshot(t, path, filepath.Join(dir, "snap.db"), 2*time.Second)
	if size == 0 {
		t.Fatal("快照為空檔")
	}
	if got := countRows(t, filepath.Join(dir, "snap.db"), `SELECT count(*) FROM probe_rows`); got != 100 {
		t.Errorf("快照列數應為 100，實際 %d", got)
	}
	// 源庫的鎖仍然在：第二條正式開庫必須被拒，否則「備份不排入寫入序列」就成了空話。
	if _, err := Open(context.Background(), Options{Path: path, BusyTimeout: 200 * time.Millisecond}); err == nil {
		t.Error("正式開庫在已有持有者時竟然成功，單寫入實例約束被備份路徑繞過了")
	}
}

// TestSnapshotExcludesUncommittedRows 證明快照的界線是「已提交」而不是「連線看過什麼」。
func TestSnapshotExcludesUncommittedRows(t *testing.T) {
	dir := retryTempDir(t)
	path := filepath.Join(dir, "probe.db")
	db := openAt(t, path, 2*time.Second)
	migrateToHead(t, db)
	insertProbeRows(t, db, 40)

	holder, err := sql.Open("sqlite", dsn(path, time.Second, BeginImmediate))
	if err != nil {
		t.Fatalf("建立占位連線失敗: %v", err)
	}
	defer holder.Close()
	tx, err := holder.Begin()
	if err != nil {
		t.Fatalf("開始占位交易失敗: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO probe_rows (n, note) VALUES (41, '未提交')`); err != nil {
		_ = tx.Rollback()
		t.Fatalf("占位寫入失敗: %v", err)
	}

	takeSnapshot(t, path, filepath.Join(dir, "snap.db"), 2*time.Second)
	if got := countRows(t, filepath.Join(dir, "snap.db"), `SELECT count(*) FROM probe_rows`); got != 40 {
		t.Errorf("快照不得含未提交的列，應為 40，實際 %d", got)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("提交占位交易失敗: %v", err)
	}
}

func TestSnapshotRejectsEmptyPathAndNilConn(t *testing.T) {
	if _, err := OpenSnapshot("   ", time.Second); err == nil {
		t.Fatal("空路徑應被拒絕")
	}
	if err := Snapshot(context.Background(), nil, "x.db"); err == nil {
		t.Fatal("nil 連線應被拒絕而不是靜默成功")
	}
}

// TestInspectSnapshotReportsFacts 要求清單會用到的每項事實都取自快照本身。
func TestInspectSnapshotReportsFacts(t *testing.T) {
	dir := retryTempDir(t)
	path := filepath.Join(dir, "probe.db")
	db := openAt(t, path, 2*time.Second)
	head := migrateToHead(t, db)
	insertProbeRows(t, db, 7)
	if err := db.StampApplicationID(context.Background()); err != nil {
		t.Fatalf("寫入檔頭標記失敗: %v", err)
	}

	target := filepath.Join(dir, "snap.db")
	takeSnapshot(t, path, target, 2*time.Second)

	info, err := InspectSnapshot(context.Background(), target, 2*time.Second)
	if err != nil {
		t.Fatalf("檢查快照失敗: %v", err)
	}
	if info.Integrity != "ok" {
		t.Errorf("integrity 應為 ok，實際 %q", info.Integrity)
	}
	if info.JournalMode != "delete" {
		t.Errorf("快照應為單檔 delete 模式，實際 %q", info.JournalMode)
	}
	if info.ApplicationID != ApplicationID {
		t.Errorf("快照應繼承源庫的 application_id（0x%08X），實際 0x%08X", ApplicationID, info.ApplicationID)
	}
	if info.SchemaVersion != head {
		t.Errorf("版本表最高版本應為 %d，實際 %d", head, info.SchemaVersion)
	}
	if info.HeaderSchemaVersion != head {
		t.Errorf("檔頭 user_version 應為 %d，實際 %d", head, info.HeaderSchemaVersion)
	}
	if len(info.Tables) == 0 {
		t.Fatal("表列數清單不可為空")
	}
	for i := 1; i < len(info.Tables); i++ {
		if info.Tables[i-1].Table > info.Tables[i].Table {
			t.Fatalf("表清單需按名排序，否則清單無法逐字比較：%v", info.Tables)
		}
	}
	if rows := rowsOf(info.Tables, "probe_rows"); rows != 7 {
		t.Errorf("probe_rows 列數應為 7，實際 %d", rows)
	}
	// sqlite_ 開頭的內部表不進清單：它們不是可恢復的內容，列出來只會讓人誤數。
	for _, row := range info.Tables {
		if strings.HasPrefix(row.Table, "sqlite_") {
			t.Errorf("內部表 %s 不應出現在清單", row.Table)
		}
	}
}

// TestInspectSnapshotOnEmptyDatabase：一張表都沒有時不該失敗，也不該出現 null 清單。
func TestInspectSnapshotOnEmptyDatabase(t *testing.T) {
	dir := retryTempDir(t)
	path := filepath.Join(dir, "probe.db")
	db := openAt(t, path, 2*time.Second)
	if _, err := db.SQL().ExecContext(context.Background(), `CREATE TABLE only_here (x INTEGER)`); err != nil {
		t.Fatalf("建表失敗: %v", err)
	}
	target := filepath.Join(dir, "snap.db")
	takeSnapshot(t, path, target, 2*time.Second)

	info, err := InspectSnapshot(context.Background(), target, 2*time.Second)
	if err != nil {
		t.Fatalf("檢查快照失敗: %v", err)
	}
	if info.SchemaVersion != 0 {
		t.Errorf("尚無版本表時最高版本應為 0，實際 %d", info.SchemaVersion)
	}
	if len(info.Tables) != 1 || info.Tables[0].Table != "only_here" {
		t.Errorf("表清單應只有 only_here，實際 %v", info.Tables)
	}
}

// TestInspectSnapshotRejectsMissingFile 讓「檢查一份不存在的快照」變成錯誤而不是 ok。
func TestInspectSnapshotRejectsMissingFile(t *testing.T) {
	if _, err := InspectSnapshot(context.Background(), filepath.Join(retryTempDir(t), "nope.db"), time.Second); err == nil {
		t.Fatal("快照檔不存在時應回錯誤")
	}
}

func TestSnapshotDSNCarriesNoWritePragmas(t *testing.T) {
	// journal_mode 會在唯讀連線失敗；query_only 會讓 VACUUM INTO 被拒
	// （程序級實測報 attempt to write a readonly database）——兩者都不準出現在快照連線字串裡。
	got := snapshotDSN(`C:\data 目錄\probe.db`, 3*time.Second)
	for _, forbidden := range []string{"journal_mode", "query_only", "_txlock=immediate"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("快照連線字串不應含 %s：%s", forbidden, got)
		}
	}
	if !strings.Contains(got, "mode=ro") || !strings.Contains(got, "busy_timeout(3000)") {
		t.Errorf("快照連線字串缺少必要參數：%s", got)
	}
	// 路徑含空格與中文時必須編碼，否則 URI 解析到的不是同一個檔案（DEC-002 補充）。
	if strings.Contains(got, " ") {
		t.Errorf("路徑未編碼：%s", got)
	}
}

func rowsOf(tables []TableRows, name string) int64 {
	for _, row := range tables {
		if row.Table == name {
			return row.Rows
		}
	}
	return -1
}
