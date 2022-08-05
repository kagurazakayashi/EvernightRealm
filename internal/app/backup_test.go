package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/backup"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 本檔測的是 `evernight-server backup` 這條運維路徑：命令接線、組態來源、
// 以及「備份包能不能被本服務自己讀回來」這個最小閉環。

func digestFileBytes(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "missing"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// seedServerSetting 用正式開庫流程寫一筆業務資料，關庫後資料留在檔裡。
func seedServerSetting(t *testing.T, dir, key, value string) {
	t.Helper()
	ctx := context.Background()
	db, err := database.Open(ctx, database.Options{Path: filepath.Join(dir, "evernight.db"), BusyTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("開啟資料庫失敗: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("關閉資料庫失敗: %v", err)
		}
	}()
	if _, err := migrate.Apply(ctx, db.SQL(), migrate.Options{Clock: timeutil.System()}); err != nil {
		t.Fatalf("套用遷移失敗: %v", err)
	}
	if err := db.StampApplicationID(ctx); err != nil {
		t.Fatalf("寫入檔頭標記失敗: %v", err)
	}
	err = db.InTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO server_settings (key, value, updated_at) VALUES (?, ?, ?)`,
			key, value, timeutil.ToMillis(timeutil.System().Now()))
		return err
	})
	if err != nil {
		t.Fatalf("寫入設定失敗: %v", err)
	}
}

// onlyBundle 回傳備份目錄裡唯一那份備份包的路徑；出現兩項就先讓測試失敗，
// 因為那代表上一次跑留下的殘渣會把這次的斷言變成隨機通過。
func onlyBundle(t *testing.T, backupsDir string) string {
	t.Helper()
	entries, err := os.ReadDir(backupsDir)
	if err != nil {
		t.Fatalf("讀取備份目錄失敗: %v", err)
	}
	var dirs []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("備份目錄留下臨時目錄 %s（失敗路徑沒清乾淨）", e.Name())
			continue
		}
		if e.IsDir() {
			dirs = append(dirs, filepath.Join(backupsDir, e.Name()))
		}
	}
	if len(dirs) != 1 {
		t.Fatalf("應恰好有一份備份包，實際 %d 份：%v", len(dirs), dirs)
	}
	return dirs[0]
}

func readManifest(t *testing.T, bundleDir string) backup.Manifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(bundleDir, backup.ManifestName))
	if err != nil {
		t.Fatalf("讀取清單失敗: %v", err)
	}
	var m backup.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("清單不是合法 JSON: %v", err)
	}
	return m
}

func hasFile(m backup.Manifest, rel string) bool {
	for _, e := range m.Files {
		if e.Path == rel {
			return true
		}
	}
	return false
}

func TestBackupSubcommandProducesRestorableBundle(t *testing.T) {
	dir := retryTempDir(t)
	ctx := context.Background()

	if err := Migrate(ctx, []string{"--data-dir", dir}, &bytes.Buffer{}); err != nil {
		t.Fatalf("先建立資料庫（migrate）失敗: %v", err)
	}
	seedServerSetting(t, dir, "theme", "長夜幻境")

	beforeMain := digestFileBytes(filepath.Join(dir, "evernight.db"))
	out := &bytes.Buffer{}
	if err := Backup(ctx, []string{"--data-dir", dir}, out); err != nil {
		t.Fatalf("backup 子命令失敗: %v\n輸出：%s", err, out)
	}
	report := out.String()
	for _, want := range []string{
		"備份包：", "integrity=ok", "journal=delete", "application_id=0x4556524c",
		"收錄：", "敏感性提示", "evernight-server restore",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("備份報告缺少 %q：\n%s", want, report)
		}
	}

	// 源庫逐位元組不變：這才是「備份不必停服務、也不打斷服務」的根據。
	if got := digestFileBytes(filepath.Join(dir, "evernight.db")); got != beforeMain {
		t.Errorf("備份改動了源庫主檔（%s → %s）", beforeMain[:12], got[:12])
	}

	bundle := onlyBundle(t, filepath.Join(dir, "backups"))
	manifest := readManifest(t, bundle)
	if manifest.FormatVersion != backup.FormatVersion || manifest.Product != backup.Product {
		t.Errorf("清單格式版本或產品識別不對：%+v", manifest)
	}
	if manifest.ServerVersion != Version {
		t.Errorf("清單需記錄伺服器版本，實際 %q", manifest.ServerVersion)
	}
	if !strings.HasSuffix(manifest.CreatedAt, "Z") || len(manifest.CreatedAt) != 24 {
		t.Errorf("created_at 需為含毫秒的 UTC 格式（與 /time、資料庫同形），實際 %q", manifest.CreatedAt)
	}
	if manifest.Database.SchemaVersion == 0 {
		t.Error("清單未記錄快照的結構版本")
	}
	if !hasFile(manifest, backup.DatabaseRel) || !hasFile(manifest, backup.ConfigRel) {
		t.Errorf("清單需同時含快照與組態：%v", manifest.Files)
	}
	if manifest.Totals.Files != len(manifest.Files) {
		t.Errorf("totals 與清單筆數不符：%d vs %d", manifest.Totals.Files, len(manifest.Files))
	}
	for _, e := range manifest.Files {
		actual := digestFileBytes(filepath.Join(bundle, filepath.FromSlash(e.Path)))
		if actual != e.SHA256 {
			t.Errorf("%s 的清單摘要與磁盤不符", e.Path)
		}
	}

	// 最小閉環（NFR-011 的起點）：把快照放進一個全新資料目錄，用正式開庫流程讀回來。
	restoreDir := filepath.Join(retryTempDir(t), "restored")
	if err := os.MkdirAll(restoreDir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(bundle, filepath.FromSlash(backup.DatabaseRel)))
	if err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(restoreDir, "evernight.db")
	if err := os.WriteFile(restored, data, 0o644); err != nil {
		t.Fatal(err)
	}

	known, err := migrate.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(ctx, database.Options{Path: restored, BusyTimeout: 2 * time.Second, KnownSchemaVersion: known})
	if err != nil {
		t.Fatalf("副本應被正式開庫流程接受: %v", err)
	}
	defer db.Close()
	if err := db.CheckIntegrity(ctx); err != nil {
		t.Errorf("副本完整性檢查未過: %v", err)
	}
	version, err := migrate.Current(ctx, db.SQL())
	if err != nil {
		t.Fatalf("讀取副本版本失敗: %v", err)
	}
	if version != manifest.Database.SchemaVersion {
		t.Errorf("副本版本 %d 與清單記錄的 %d 不符", version, manifest.Database.SchemaVersion)
	}
	var value string
	if err := db.SQL().QueryRowContext(ctx,
		`SELECT value FROM server_settings WHERE key = 'theme'`).Scan(&value); err != nil {
		t.Fatalf("副本讀不回業務資料: %v", err)
	}
	if value != "長夜幻境" {
		t.Errorf("副本內容不對：%q", value)
	}
}

// TestBackupRunsWhileServiceHoldsTheWriter 是本步交付形態的根據，也是探針那組程序級證據在單元層的對應物：
// 本程序正以正式開庫流程使用這個庫（持單寫入實例鎖、資料還在 -wal 裡未 checkpoint），
// backup 仍要取出快照，而且快照裡必須有那些只在 -wal 的列。
func TestBackupRunsWhileServiceHoldsTheWriter(t *testing.T) {
	dir := retryTempDir(t)
	ctx := context.Background()
	if err := Migrate(ctx, []string{"--data-dir", dir}, &bytes.Buffer{}); err != nil {
		t.Fatalf("migrate 失敗: %v", err)
	}

	db, err := database.Open(ctx, database.Options{Path: filepath.Join(dir, "evernight.db"), BusyTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("開啟資料庫失敗: %v", err)
	}
	defer db.Close()
	if _, err := migrate.Apply(ctx, db.SQL(), migrate.Options{Clock: timeutil.System()}); err != nil {
		t.Fatalf("套用遷移失敗: %v", err)
	}
	// 寫在同一個程序、且不關閉連線：資料停在 -wal，正是「複製主檔會拿不到」的那一段。
	err = db.InTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO server_settings (key, value, updated_at) VALUES (?, ?, ?)`,
			"in_wal", "只在 WAL 裡", timeutil.ToMillis(timeutil.System().Now()))
		return err
	})
	if err != nil {
		t.Fatalf("寫入失敗: %v", err)
	}
	if wal := filepath.Join(dir, "evernight.db-wal"); !fileExists(wal) {
		t.Fatal("前提不成立：沒有產生 -wal")
	}

	out := &bytes.Buffer{}
	if err := Backup(ctx, []string{"--data-dir", dir}, out); err != nil {
		t.Fatalf("服務持鎖期間備份失敗: %v\n輸出：%s", err, out)
	}

	bundle := onlyBundle(t, filepath.Join(dir, "backups"))
	restored := filepath.Join(retryTempDir(t), "evernight.db")
	data, err := os.ReadFile(filepath.Join(bundle, filepath.FromSlash(backup.DatabaseRel)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(restored, data, 0o644); err != nil {
		t.Fatal(err)
	}
	pool, err := database.Open(ctx, database.Options{Path: restored, BusyTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("開副本失敗: %v", err)
	}
	defer pool.Close()
	var value string
	if err := pool.SQL().QueryRowContext(ctx,
		`SELECT value FROM server_settings WHERE key = 'in_wal'`).Scan(&value); err != nil {
		t.Fatalf("快照讀不回只在 -wal 的已提交資料（這正是備份最該保住的東西）: %v", err)
	}
	if value != "只在 WAL 裡" {
		t.Errorf("值不對：%q", value)
	}
}

func TestBackupRefusesWhenSpaceIsLow(t *testing.T) {
	dir := retryTempDir(t)
	// 先把資料庫建好：空間不足這條路要在「其他前提都成立」的情況下測，
	// 否則失敗原因可能是沒庫、可能是鎖，就不是空間判定。
	if err := Migrate(context.Background(), []string{"--data-dir", dir}, &bytes.Buffer{}); err != nil {
		t.Fatalf("建立資料庫失敗: %v", err)
	}

	// 一個任何真實卷都不可能滿意的下限（與 disk_test.go 同一手法）：
	// 比去把開發機寫滿更可靠，也不影響其他測試。
	t.Setenv("ER_DISK_MIN_FREE_BYTES", "4611686018427387904")

	out := &bytes.Buffer{}
	err := Backup(context.Background(), []string{"--data-dir", dir}, out)
	if !errors.Is(err, backup.ErrSpace) {
		t.Fatalf("空間不足時應回 ErrSpace，實際 %v\n%s", err, out)
	}
	if !strings.Contains(err.Error(), "未開始備份") {
		t.Errorf("錯誤需說明「還沒有動筆」：%v", err)
	}
	// 判定落在動筆之前：既沒有備份包，也沒有臨時目錄，源庫也沒有被打開過。
	entries, dirErr := os.ReadDir(filepath.Join(dir, "backups"))
	if dirErr == nil && len(entries) != 0 {
		t.Errorf("拒絕時備份目錄應保持空，實際 %d 項：%v", len(entries), entries)
	}
	if strings.Contains(out.String(), "備份包：") {
		t.Errorf("拒絕時不應印出成功報告：%s", out)
	}
}

func TestBackupIncludesContentDirs(t *testing.T) {
	dir := retryTempDir(t)
	ctx := context.Background()
	if err := Migrate(ctx, []string{"--data-dir", dir}, &bytes.Buffer{}); err != nil {
		t.Fatalf("migrate 失敗: %v", err)
	}
	// 三個內容目錄各放一檔（含巢狀），並留一個空目錄：清單要含前三者，包裡要含全部四個結構。
	for path, content := range map[string]string{
		filepath.Join(dir, "media", "pic.png"):          "MEDIA",
		filepath.Join(dir, "documents", "a", "doc.txt"): "DOC",
		filepath.Join(dir, "attachments", "up.bin"):     "UP",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// 空目錄要在第一次備份前就存在：同一秒跑兩次備份會撞到同一個包名（已由另一條測試固定）。
	if err := os.MkdirAll(filepath.Join(dir, "documents", "empty-sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Backup(ctx, []string{"--data-dir", dir}, &bytes.Buffer{}); err != nil {
		t.Fatalf("備份失敗: %v", err)
	}
	bundle := onlyBundle(t, filepath.Join(dir, "backups"))
	manifest := readManifest(t, bundle)
	for _, rel := range []string{"media/pic.png", "documents/a/doc.txt", "attachments/up.bin"} {
		if !hasFile(manifest, rel) {
			t.Errorf("清單缺少 %s：%v", rel, manifest.Files)
		}
	}
	// 空目錄也要在包裡，否則恢復出來的目錄結構不完整、服務又得自己建一次（兩份真相）。
	if st, err := os.Stat(filepath.Join(bundle, "documents", "empty-sub")); err != nil || !st.IsDir() {
		t.Errorf("空的來源目錄沒進備份包：%v", err)
	}
}

// TestBackupNeverReachesIntoBackupsDir：備份包寫在 backups/ 裡，
// 而 backups/ 不是被收錄的內容目錄——否則第二份備份會含第一份，一份包裡裝著一包。
func TestBackupNeverReachesIntoBackupsDir(t *testing.T) {
	dir := retryTempDir(t)
	ctx := context.Background()
	if err := Migrate(ctx, []string{"--data-dir", dir}, &bytes.Buffer{}); err != nil {
		t.Fatalf("migrate 失敗: %v", err)
	}
	// 先放一份「別人的備份包」在 backups 裡，模擬已有舊備份。
	old := filepath.Join(dir, "backups", "20200101T000000Z-oldoldold")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, backup.ManifestName), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	if err := Backup(ctx, []string{"--data-dir", dir}, out); err != nil {
		t.Fatalf("備份失敗: %v", err)
	}
	bundle := bundleFromReport(t, out.String())
	if filepath.Base(bundle) == filepath.Base(old) {
		t.Fatal("報告指回的還是舊包")
	}
	for _, e := range readManifest(t, bundle).Files {
		if strings.Contains(e.Path, "backups") {
			t.Errorf("清單收錄了備份目錄本身：%s", e.Path)
		}
	}
	if _, err := os.Stat(filepath.Join(bundle, "backups")); !errors.Is(err, os.ErrNotExist) {
		t.Error("備份包裡出現了 backups 目錄（遞迴收錄）")
	}
}

func TestBackupFailsWhenDatabaseMissing(t *testing.T) {
	dir := retryTempDir(t)
	out := &bytes.Buffer{}
	err := Backup(context.Background(), []string{"--data-dir", dir}, out)
	if err == nil {
		t.Fatal("資料庫不存在時應失敗，而不是做出一份空備份")
	}
	if !strings.Contains(err.Error(), dir) && !strings.Contains(err.Error(), "evernight.db") {
		t.Errorf("錯誤需點出是哪个檔案讀不到：%v", err)
	}
	if strings.Contains(out.String(), "備份包：") {
		t.Error("失敗路徑卻印出了成功報告")
	}
}

func TestBundleNameShapeAndUniqueness(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 34, 56, 789_000_000, time.UTC)
	id, err := idgen.New()
	if err != nil {
		t.Fatal(err)
	}
	got := bundleName(now, id)
	if len(got) != len("20060102T150405Z")+1+8 {
		t.Errorf("包名長度固定才方便排序與比對：%q", got)
	}
	if !strings.HasPrefix(got, "20260927T123456Z-") {
		t.Errorf("包名需以 UTC 緊湊時間開頭（按名字排序就是按產生順序）：%q", got)
	}
	if strings.ContainsAny(got, `/\:`) {
		t.Errorf("包名需跨平台可用：%q", got)
	}

	// 同一秒跑兩次是運維真會做的事（手滑、腳本重試），前綴相同也要靠後綴分家。
	// 同一時刻的兩次備份是運維真會做的事（手滑、腳本重試）：後綴必須取自標識的隨機段。
	for i := 0; i < 200; i++ {
		second, err := idgen.New()
		if err != nil {
			t.Fatal(err)
		}
		if bundleName(now, second) == got {
			t.Fatalf("第 %d 次產生出與第一次相同的包名 %q（後綴取到時間段了？）", i, got)
		}
		got = bundleName(now, second)
	}
}

func TestBackupNoteFunctions(t *testing.T) {
	cfg := defaultConfigForTest(t)
	if note := backupDiskNote(cfg, backup.DiskFact{Path: `D:\x\backups`}); !strings.Contains(note, "未設 disk 下限") {
		t.Errorf("未啟用時要說清楚：%q", note)
	}
	cfg.Disk.MinFreeBytes = 1 << 30
	cfg.Disk.MinFreePercent = 5
	note := backupDiskNote(cfg, backup.DiskFact{Path: `D:\x\backups`, FreeBytes: 3 << 30, TotalBytes: 10 << 30})
	for _, want := range []string{"3.0 GiB", "10.0 GiB", "1.0 GiB", "5%"} {
		if !strings.Contains(note, want) {
			t.Errorf("判定說明缺少 %q：%q", want, note)
		}
	}

	empty := backup.Manifest{}
	if got := tableCountsNote(empty); !strings.Contains(got, "沒有任何資料表") {
		t.Errorf("空清單要說明空：%q", got)
	}
	known, err := migrate.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	if got := schemaNoticeNote(empty); got != "" {
		t.Errorf("版本不該提示時不該有多餘文字：%q", got)
	}
	ahead := empty
	ahead.Database.SchemaVersion = known + 7
	if got := schemaNoticeNote(ahead); !strings.Contains(got, "高於") {
		t.Errorf("快照版本高於執行檔時必須提示：%q", got)
	}
}

// defaultConfigForTest 給一份預設組態（備份的三個注釋函式只看數值欄位，不需要解析路徑）。
func defaultConfigForTest(t *testing.T) config.Config {
	t.Helper()
	return config.Default()
}

// bundleFromReport 從備份報告裡取回包的路徑：目錄裡已有別的備份時，
// 「找唯一一項」這種判據就不成立了，報告說寫到哪一份就檢查哪一份。
func bundleFromReport(t *testing.T, report string) string {
	t.Helper()
	for _, line := range strings.Split(report, "\n") {
		if rest, ok := strings.CutPrefix(line, "備份包："); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("備份報告裡找不到包路徑：\n%s", report)
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
