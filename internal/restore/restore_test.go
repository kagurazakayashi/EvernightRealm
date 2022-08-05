package restore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/backup"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/disk"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// 這一整份測試把 internal/database 以注入的方式隔開：判定的好壞要用「讀到什麼」來固定，
// 而不是靠一個真實資料庫的狀態湊出來。真實資料庫的端到端證據在 internal/app 那一份測試與
// 程序級腳本裡，兩邊各自的失敗路徑都要有歸屬。
const (
	testDatabaseSHA = "0000000000000000000000000000000000000000000000000000000000000000"
	testAppIDText   = "0x4556524c"
)

// bundleSpec 是一份測試用備份包的內容描述。
type bundleSpec struct {
	// ContentFiles 是要放進媒體目錄的檔案名（各檔內容不同，摘要才驗得出來）。
	ContentFiles []string
	// DocumentFiles 是要放進文件目錄的檔案名（落地碰撞那組測試要用到第二個內容目錄）。
	DocumentFiles []string
	// ConfigYAML 是包內那份組態的內容。
	ConfigYAML string
	// Manifest 非 nil 時原樣寫進 manifest.json（用來製造「清單與磁盤不符」）。
	Manifest *backup.Manifest
	// ExtraDirs 是包內要額外建立的目錄（空的子目錄）。
	ExtraDirs []string
	// ExtraFiles 是包內要額外建立的檔案名（清單之外的東西）。
	ExtraFiles []string
}

// writeBundle 建立一份形狀正確的備份包，回傳目錄與它實際寫出的清單。
//
// 摘要一律在檔案落盤後重算，因此「這份包是好的」這個前提是真的而不是假設的——
// 用一組編出來的摘要做測試，第一個通過的測試就會變成對實作的誤導。
func writeBundle(t *testing.T, spec bundleSpec) (string, backup.Manifest) {
	t.Helper()
	dir := t.TempDir()
	if spec.ConfigYAML == "" {
		spec.ConfigYAML = "server:\n  data_dir: \".\"\n"
	}

	dbBytes := []byte("SQLite fake snapshot bytes\n")
	configBytes := []byte(spec.ConfigYAML)
	write := func(rel string, data []byte, mode fs.FileMode) {
		t.Helper()
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("建立目錄失敗: %v", err)
		}
		if err := os.WriteFile(full, data, mode); err != nil {
			t.Fatalf("寫入 %s 失敗: %v", rel, err)
		}
	}
	entry := func(kind, rel string, data []byte) backup.Entry {
		sum := sha256.Sum256(data)
		return backup.Entry{Kind: kind, Path: rel, SizeBytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
	}

	manifest := backup.Manifest{
		FormatVersion: backup.FormatVersion,
		Product:       backup.Product,
		ServerVersion: "0.1.0-test",
		CreatedAt:     "2026-09-27T10:00:00.000Z",
		Database: backup.DatabaseFact{
			Path: backup.DatabaseRel, SchemaVersion: 2, Integrity: "ok", JournalMode: "delete",
			ApplicationID: testAppIDText, HeaderSchemaVersion: 2,
			Tables: []database.TableRows{{Table: "root_audit", Rows: 3}, {Table: "schema_migrations", Rows: 2},
				{Table: "server_settings", Rows: 1}},
		},
		Disk: backup.DiskFact{Path: dir, FreeBytes: 1 << 30, TotalBytes: 1 << 35, Verdict: "ok"},
	}
	manifest.Source.DataDir = filepath.Join(dir, "..", "source-data")
	manifest.Files = append(manifest.Files, entry(kindDatabase, backup.DatabaseRel, dbBytes))
	write(backup.DatabaseRel, dbBytes, 0o644)
	manifest.Files = append(manifest.Files, entry(kindConfig, backup.ConfigRel, configBytes))
	write(backup.ConfigRel, configBytes, 0o600)

	for _, name := range spec.ContentFiles {
		rel := backup.KindMedia + "/" + name
		body := []byte("content of " + name)
		manifest.Files = append(manifest.Files, entry(backup.KindMedia, rel, body))
		write(rel, body, 0o644)
	}
	for _, name := range spec.DocumentFiles {
		rel := backup.KindDocuments + "/" + name
		body := []byte("content of " + rel)
		manifest.Files = append(manifest.Files, entry(backup.KindDocuments, rel, body))
		write(rel, body, 0o644)
	}
	for _, rel := range spec.ExtraDirs {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(rel)), 0o755); err != nil {
			t.Fatalf("建立 %s 失敗: %v", rel, err)
		}
	}
	for _, rel := range spec.ExtraFiles {
		write(rel, []byte("unexpected"), 0o644)
	}

	if spec.Manifest != nil {
		manifest = *spec.Manifest
	}
	// 清單排序與合計由產生端的同一個規則決定（Path 排序），這裡照做，
	// 否則測試裡的包與真實包在「同一份內容」上會有兩種寫法。
	sortEntries(manifest.Files)
	manifest.Totals.Files = len(manifest.Files)
	var total int64
	for _, f := range manifest.Files {
		total += f.SizeBytes
	}
	manifest.Totals.Bytes = total

	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("編碼清單失敗: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, backup.ManifestName), append(data, '\n'), 0o644); err != nil {
		t.Fatalf("寫入清單失敗: %v", err)
	}
	// 空目錄也要在包裡（產生端對沒有檔案的內容目錄一樣建目錄），三份測試包都按這個形狀做。
	for _, kind := range []string{backup.KindMedia, backup.KindDocuments, backup.KindAttachments} {
		if err := os.MkdirAll(filepath.Join(dir, kind), 0o755); err != nil {
			t.Fatalf("建立 %s 失敗: %v", kind, err)
		}
	}
	return dir, manifest
}

// sortEntries 與產生端一樣按路徑排序，讓清單可重複產生。
func sortEntries(entries []backup.Entry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
}

// factsFor 依清單給出一份「與之相符」的讀取結果；測試裡的成功路徑用的就是它。
func factsFor(manifest backup.Manifest) database.SnapshotInfo {
	var appID uint32
	fmt.Sscanf(manifest.Database.ApplicationID, "0x%x", &appID)
	return database.SnapshotInfo{
		SchemaVersion:        manifest.Database.SchemaVersion,
		JournalMode:          manifest.Database.JournalMode,
		Integrity:            manifest.Database.Integrity,
		ForeignKeyViolations: 0,
		ApplicationID:        appID,
		HeaderSchemaVersion:  manifest.Database.HeaderSchemaVersion,
		Tables:               append([]database.TableRows(nil), manifest.Database.Tables...),
	}
}

// options 湊出一份可用的引數（絕對路徑、空的目標、判定全過）。
func options(bundle, target string, manifest backup.Manifest) Options {
	return Options{
		Bundle:             bundle,
		Target:             target,
		CurrentDataDir:     filepath.Join(filepath.Dir(target), "the-live-dir"),
		KnownSchemaVersion: manifest.Database.SchemaVersion,
		Inspect: func(ctx context.Context, path string) (database.SnapshotInfo, error) {
			return factsFor(manifest), nil
		},
		Disk: func() (disk.Verdict, error) {
			return disk.Verdict{Status: disk.StatusOK, Usage: disk.Usage{Path: target, Free: 1 << 30, Total: 1 << 35}}, nil
		},
	}
}

// newTarget 回傳一個「目前不存在」的目標資料目錄（在測試自己的TempDir 之下）。
func newTarget(t *testing.T, name string) string {
	t.Helper()
	root := t.TempDir()
	return filepath.Join(root, name)
}

func TestExecuteHappyPathPublishesTargetDir(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{ContentFiles: []string{"a.png", "b.png"}})
	target := newTarget(t, "restored")
	auditID, err := idgen.New()
	if err != nil {
		t.Fatalf("產生測試標識失敗: %v", err)
	}

	opts := options(bundle, target, manifest)
	opts.AppendAudit = func(ctx context.Context, dbPath string, m backup.Manifest) (idgen.ID, error) {
		if _, err := os.Stat(dbPath); err != nil {
			t.Errorf("審計回呼拿到的庫路徑不可用（%s）: %v", dbPath, err)
		}
		if m.Totals.Files != manifest.Totals.Files {
			t.Errorf("清單傳給回呼的內容不符：%d vs %d", m.Totals.Files, manifest.Totals.Files)
		}
		// 模擬可寫開啟的三個副產物：鎖檔、-shm、以及尚未合併的 -wal。
		base := filepath.Base(dbPath)
		dir := filepath.Dir(dbPath)
		for _, name := range []string{base + ".lock", base + "-shm", base + "-wal"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
				t.Fatalf("寫入副產物 %s 失敗: %v", name, err)
			}
		}
		return auditID, nil
	}
	// 讓第三次 Inspect 回報「追加之後」的狀態（journal_mode 轉 wal、root_audit 多一列）。
	calls := 0
	base := opts.Inspect
	opts.Inspect = func(ctx context.Context, path string) (database.SnapshotInfo, error) {
		calls++
		if calls < 3 {
			return base(ctx, path)
		}
		after := factsFor(manifest)
		after.JournalMode = "wal"
		for i, tbl := range after.Tables {
			if tbl.Table == rootAuditTable {
				after.Tables[i].Rows = tbl.Rows + 1
			}
		}
		return after, nil
	}

	res, err := Execute(context.Background(), opts)
	if err != nil {
		t.Fatalf("恢復失敗: %v", err)
	}
	if !res.Published {
		t.Fatal("已結束但沒有發布，報告上的「已發布」與磁盤狀態不一致")
	}
	if calls != 3 {
		t.Errorf("期望三次讀取（包內、落地、追加後），實際 %d 次", calls)
	}

	// 目標目錄的形狀必須是「一個完整的資料目錄」，不是包內目錄的鏡子。
	for _, want := range []string{"evernight.db", "config.yaml", "media", "documents", "attachments"} {
		if _, err := os.Stat(filepath.Join(target, want)); err != nil {
			t.Errorf("目標目錄缺少 %s: %v", want, err)
		}
	}
	if _, err := os.Stat(filepath.Join(target, backup.DatabaseRel)); err == nil {
		t.Error("包內的 database/ 目錄結構被當成落點，恢復出來的庫不該在那裡")
	}
	// 副產物：鎖檔與 -shm 清掉、-wal 保留（刪掉它等於丟剛寫進去的那筆）。
	if len(res.SideFiles.Removed) != 2 {
		t.Errorf("應清掉 2 個副產物（.lock 與 -shm），實際 %v", res.SideFiles.Removed)
	}
	if len(res.SideFiles.Kept) != 1 || !strings.HasSuffix(res.SideFiles.Kept[0], "-wal") {
		t.Errorf("應保留 -wal，實際 %v", res.SideFiles.Kept)
	}
	for _, name := range res.SideFiles.Removed {
		if _, err := os.Stat(filepath.Join(target, filepath.FromSlash(name))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s 號稱已清理，但它還在目標目錄裡", name)
		}
	}
	if res.AuditID != auditID {
		t.Errorf("回呼傳回的標識沒有交回報告：%s vs %s", res.AuditID, auditID)
	}
	if res.RestoredFacts.Tables[0].Table != rootAuditTable || res.RestoredFacts.Tables[0].Rows != 4 {
		t.Errorf("追加後的 root_audit 應為 4 列，實際 %+v", res.RestoredFacts.Tables)
	}
	if res.FilesWritten != manifest.Totals.Files {
		t.Errorf("寫入檔案數 %d 與清單 %d 不符", res.FilesWritten, manifest.Totals.Files)
	}
	// 暫存目錄在發布之後不該留下來。
	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		t.Fatalf("讀取父目錄失敗: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), stagingSuffix) {
			t.Errorf("發布後仍留著暫存目錄 %s", e.Name())
		}
	}
}

func TestExecuteWithoutAuditCallbackPublishesUnchangedDB(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	target := newTarget(t, "restored")
	opts := options(bundle, target, manifest)

	res, err := Execute(context.Background(), opts)
	if err != nil {
		t.Fatalf("恢復失敗(placeholder): %v", err)
	}
	if res.AuditID != idgen.Nil {
		t.Error("沒有注入審計回呼卻回報了審計標識")
	}
	if res.AuditSkipped != "" {
		t.Errorf("有 root_audit 表時不該回報跳過原因：%q", res.AuditSkipped)
	}
	if res.RestoredFacts.Tables[0].Rows != 3 {
		t.Errorf("未追加時行數不該變動，實際 %+v", res.RestoredFacts.Tables)
	}
}

func TestExecuteSkipsAuditWhenRootAuditTableAbsent(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	// 一份來自「尚未遷移」的庫：沒有 root_audit 表，往它追加記錄不會成功。
	manifest.Database.Tables = []database.TableRows{{Table: "server_settings", Rows: 1}}
	writeManifestOf(t, bundle, manifest)
	target := newTarget(t, "restored")

	opts := options(bundle, target, manifest)
	opts.Inspect = func(ctx context.Context, path string) (database.SnapshotInfo, error) {
		return factsFor(manifest), nil
	}
	opts.KnownSchemaVersion = 2
	called := false
	opts.AppendAudit = func(ctx context.Context, dbPath string, m backup.Manifest) (idgen.ID, error) {
		called = true
		return idgen.Nil, nil
	}

	res, err := Execute(context.Background(), opts)
	if err != nil {
		t.Fatalf("恢復失敗: %v", err)
	}
	if called {
		t.Error("目標庫沒有 root_audit 表時仍然呼叫了審計回呼")
	}
	if res.AuditSkipped == "" {
		t.Error("跳過必須有原因可回報，否則報告會讀成「已寫入」")
	}
	if !res.Published {
		t.Error("沒有審計可寫不該阻止恢復本身（那個目錄之後啟動時才會建表）")
	}
}

func TestExecuteRejectsNonEmptyTarget(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	target := newTarget(t, "restored")
	if err := os.MkdirAll(filepath.Join(target, "someone-elses"), 0o755); err != nil {
		t.Fatalf("建立目錄失敗: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("建立檔案失敗: %v", err)
	}

	res, err := Execute(context.Background(), options(bundle, target, manifest))
	if !errors.Is(err, ErrTargetNotEmpty) {
		t.Fatalf("目標非空時必須拒絕，實際錯誤：%v", err)
	}
	if res.Published {
		t.Error("拒絕路徑上回報了發布")
	}
	// 既有的東西一個都不能少，一個新的也不能多。
	if _, err := os.Stat(filepath.Join(target, "keep.txt")); err != nil {
		t.Errorf("拒絕時動到了既有檔案: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "evernight.db")); !errors.Is(err, os.ErrNotExist) {
		t.Error("拒絕後目標目錄裡出現了恢復出來的庫")
	}
	entries, _ := os.ReadDir(filepath.Dir(target))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), stagingSuffix) {
			t.Errorf("拒絕的路徑上不該留下暫存目錄：%s", e.Name())
		}
	}
}

func TestExecuteRejectsTargetEqualToCurrentDataDir(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	live := newTarget(t, "evernight-data")
	opts := options(bundle, live, manifest)
	opts.CurrentDataDir = live

	_, err := Execute(context.Background(), opts)
	if !errors.Is(err, ErrTargetIsCurrent) {
		t.Fatalf("恢復到本次程序設定的資料目錄必須拒絕，實際錯誤：%v", err)
	}
}

func TestExecuteRejectsTargetEqualToBundleSource(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	target := newTarget(t, "the-source")
	manifest.Source.DataDir = target
	writeManifestOf(t, bundle, manifest)
	opts := options(bundle, target, manifest)
	opts.CurrentDataDir = filepath.Join(target, "..", "elsewhere")

	_, err := Execute(context.Background(), opts)
	if !errors.Is(err, ErrTargetIsSource) {
		t.Fatalf("恢復到這份包的來源目錄必須拒絕，實際錯誤：%v", err)
	}
}

func TestExecuteRejectsOverlappingPaths(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	// 目標在包裡面：複製的邊界就變成「邊讀邊寫同一個目錄」，結果不可預期。
	target := filepath.Join(bundle, "restored")
	_, err := Execute(context.Background(), options(bundle, target, manifest))
	if !errors.Is(err, ErrOverlappingPaths) {
		t.Fatalf("來源與目標互相包含時必須拒絕，實際錯誤：%v", err)
	}
}

func TestExecuteRejectsUnknownFormatVersion(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	manifest.FormatVersion = backup.FormatVersion + 1
	writeManifestOf(t, bundle, manifest)

	_, err := Execute(context.Background(), options(bundle, newTarget(t, "restored"), manifest))
	if !errors.Is(err, ErrFormatUnsupported) {
		t.Fatalf("不認得的內容格式版本必須拒絕（不去猜欄位語意），實際錯誤：%v", err)
	}
}

func TestExecuteRejectsMissingManifest(t *testing.T) {
	dir := t.TempDir()
	_, err := Execute(context.Background(), Options{
		Bundle: dir, Target: newTarget(t, "restored"), CurrentDataDir: filepath.Join(dir, "live"),
		Inspect: func(context.Context, string) (database.SnapshotInfo, error) { return database.SnapshotInfo{}, nil },
		Disk:    func() (disk.Verdict, error) { return disk.Verdict{Status: disk.StatusOK}, nil },
	})
	if !errors.Is(err, ErrManifestMissing) {
		t.Fatalf("一個空目錄不是備份包，必須拒絕，實際錯誤：%v", err)
	}
}

func TestExecuteRejectsTamperedFile(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{ContentFiles: []string{"a.png", "b.png"}})
	if err := os.WriteFile(filepath.Join(bundle, backup.KindMedia, "b.png"), []byte("tampered"), 0o644); err != nil {
		t.Fatalf("植入篡改失敗: %v", err)
	}
	target := newTarget(t, "restored")

	_, err := Execute(context.Background(), options(bundle, target, manifest))
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("摘要不符必須拒絕，實際錯誤：%v", err)
	}
	if !strings.Contains(err.Error(), "media/b.png") {
		t.Errorf("錯誤必須點出是哪一檔，實際：%v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Error("核對未過時不該建立目標目錄")
	}
}

func TestExecuteRejectsMissingFileListedInManifest(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{ContentFiles: []string{"a.png"}})
	if err := os.Remove(filepath.Join(bundle, backup.KindMedia, "a.png")); err != nil {
		t.Fatalf("刪除檔案失敗: %v", err)
	}
	_, err := Execute(context.Background(), options(bundle, newTarget(t, "restored"), manifest))
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("清單記有而磁盤上沒有的檔案必須拒絕，實際錯誤：%v", err)
	}
	if !strings.Contains(err.Error(), "不存在") {
		t.Errorf("這一句要說得出「是少了檔案而不是摘要變了」，實際：%v", err)
	}
}

func TestExecuteRejectsUnlistedFile(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{ExtraFiles: []string{"media/notes.txt"}})
	_, err := Execute(context.Background(), options(bundle, newTarget(t, "restored"), manifest))
	if !errors.Is(err, ErrUnlistedFile) {
		t.Fatalf("清單之外的檔案必須拒絕而不是跳過，實際錯誤：%v", err)
	}
	if !strings.Contains(err.Error(), "media/notes.txt") {
		t.Errorf("錯誤要點出那個檔案，實際：%v", err)
	}
}

func TestExecuteRejectsSchemaVersionAheadOfExecutable(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	manifest.Database.SchemaVersion = 9
	writeManifestOf(t, bundle, manifest)
	opts := options(bundle, newTarget(t, "restored"), manifest)
	opts.KnownSchemaVersion = 2

	_, err := Execute(context.Background(), opts)
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("比本執行檔還新的包必須拒絕，實際錯誤：%v", err)
	}
	if !strings.Contains(err.Error(), "9") || !strings.Contains(err.Error(), "2") {
		t.Errorf("錯誤要寫出兩個版本號讓判讀不用猜，實際：%v", err)
	}
}

func TestExecuteRejectsLowSpaceAndUnknown(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  disk.Status
		wantsOK bool
	}{
		{"不足", disk.StatusLow, false},
		{"查不出來", disk.StatusUnknown, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle, manifest := writeBundle(t, bundleSpec{})
			target := newTarget(t, "restored")
			opts := options(bundle, target, manifest)
			opts.Disk = func() (disk.Verdict, error) {
				return disk.Verdict{Status: tc.status, Reason: tc.name, Usage: disk.Usage{Path: target}}, nil
			}
			_, err := Execute(context.Background(), opts)
			if !errors.Is(err, ErrSpace) {
				t.Fatalf("空間判定未過必須拒絕，實際錯誤：%v", err)
			}
			if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
				t.Error("拒絕時不該建立目標目錄")
			}
		})
	}
}

func TestExecuteRejectsBundleThatDoesNotFit(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{ContentFiles: []string{"a.png"}})
	target := newTarget(t, "restored")
	opts := options(bundle, target, manifest)
	// 一個「閾值沒設到、但裝不下」的卷：兩道問的是不同的問題，只查前一道等于沒查。
	opts.Disk = func() (disk.Verdict, error) {
		return disk.Verdict{Status: disk.StatusOK,
			Usage: disk.Usage{Path: target, Free: 1, Total: 1 << 30}}, nil
	}
	_, err := Execute(context.Background(), opts)
	if !errors.Is(err, ErrSpace) {
		t.Fatalf("裝不下時必須拒絕，實際錯誤：%v", err)
	}
	if !strings.Contains(err.Error(), "剩餘") {
		t.Errorf("錯誤要寫出剩餘容量，讓運維知道差多少，實際：%v", err)
	}
}

func TestExecuteRejectsPathOutsideTargetFromBundleConfig(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{
		ConfigYAML: "server:\n  data_dir: \".\"\nmedia: \"D:\\\\other-machine\\\\media\"\n",
	})
	_, err := Execute(context.Background(), options(bundle, newTarget(t, "restored"), manifest))
	if !errors.Is(err, ErrPathOutsideTarget) {
		t.Fatalf("包內組態把媒體目錄指到目標之外時必須拒絕，實際錯誤：%v", err)
	}
	if !strings.Contains(err.Error(), backup.ConfigRel) {
		t.Errorf("錯誤要說出該改哪一份檔案，實際：%v", err)
	}
}

func TestExecuteRejectsLandingCollision(t *testing.T) {
	// 組態把文件目錄也指到 media/，而包內兩類檔案同名：兩筆都要落地在同一個位置。
	bundle, manifest := writeBundle(t, bundleSpec{
		ContentFiles:  []string{"a.png"},
		DocumentFiles: []string{"a.png"},
		ConfigYAML:    "server:\n  data_dir: \".\"\ndocuments: \"media/\"\n",
	})
	_, err := Execute(context.Background(), options(bundle, newTarget(t, "restored"), manifest))
	if !errors.Is(err, ErrLandingCollision) {
		t.Fatalf("兩個檔案落地到同一路徑必須拒絕，實際：%v", err)
	}
	if !strings.Contains(err.Error(), "media/a.png") {
		t.Errorf("錯誤要點出那個撞在一起的位置，實際：%v", err)
	}
}

func TestExecuteLandsDatabaseAndConfigAtConfiguredPaths(t *testing.T) {
	// 包內的擺法（database/evernight.db、config/config.yaml）不是目標目錄的擺法：
	// 組態說庫叫 db/main.db，恢復出來的目錄裡就必須是 db/main.db。
	bundle, manifest := writeBundle(t, bundleSpec{
		ContentFiles: []string{"a.png"},
		ConfigYAML:   "server:\n  data_dir: \".\"\ndatabase:\n  path: \"db/main.db\"\n",
	})
	target := newTarget(t, "restored")
	if _, err := Execute(context.Background(), options(bundle, target, manifest)); err != nil {
		t.Fatalf("恢復失敗: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "db", "main.db")); err != nil {
		t.Errorf("庫沒有落在組態說的那個位置: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "config.yaml")); err != nil {
		t.Errorf("組態副本要落在資料目錄根（那是 ConfigFile() 的唯一定義）: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, backup.DatabaseRel)); err == nil {
		t.Error("包內的目錄結構被當成落點用了")
	}
}

func TestExecuteRejectsForeignApplicationID(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	target := newTarget(t, "restored")
	opts := options(bundle, target, manifest)
	// 清單與實際讀到的值一致（兩邊都寫 0x99999999），所以「對不上」不是拒絕的理由；
	// 拒絕的理由是那個 application_id 既不是本服務的 EVRL，也不是未標記。
	manifest.Database.ApplicationID = fmt.Sprintf("0x%08x", 0x99999999)
	writeManifestOf(t, bundle, manifest)
	opts.Inspect = func(ctx context.Context, path string) (database.SnapshotInfo, error) {
		return factsFor(manifest), nil
	}
	_, err := Execute(context.Background(), opts)
	if !errors.Is(err, ErrFactMismatch) {
		t.Fatalf("他人的資料庫必須被拒（哪怕清單自己承認），實際：%v", err)
	}
	if !strings.Contains(err.Error(), "他人的資料庫") {
		t.Errorf("這句話要說得出「不是本服務的庫」，實際：%v", err)
	}
}

func TestExecuteRejectsUnsoundIntegrityAndForeignKeyViolations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*database.SnapshotInfo)
		phrase string
	}{
		{"integrity 未過", func(i *database.SnapshotInfo) { i.Integrity = "database disk image is malformed" }, "integrity_check"},
		{"外鍵違規", func(i *database.SnapshotInfo) { i.ForeignKeyViolations = 4 }, "foreign_key_check"},
		{"行數不符", func(i *database.SnapshotInfo) { i.Tables[0].Rows = 99 }, "root_audit"},
		{"多出未記的表", func(i *database.SnapshotInfo) {
			i.Tables = append(i.Tables, database.TableRows{Table: "hand_added", Rows: 1})
		}, "hand_added"},
		{"缺表", func(i *database.SnapshotInfo) { i.Tables = i.Tables[1:] }, "讀不到這張表"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle, manifest := writeBundle(t, bundleSpec{})
			target := newTarget(t, "restored")
			opts := options(bundle, target, manifest)
			opts.Inspect = func(ctx context.Context, path string) (database.SnapshotInfo, error) {
				info := factsFor(manifest)
				tc.mutate(&info)
				return info, nil
			}
			_, err := Execute(context.Background(), opts)
			if !errors.Is(err, ErrFactMismatch) {
				t.Fatalf("實際讀到的值與清單不符必須拒絕，實際錯誤：%v", err)
			}
			if !strings.Contains(err.Error(), tc.phrase) {
				t.Errorf("錯誤要點出「%s」這一項，實際：%v", tc.phrase, err)
			}
			if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
				t.Error("拒絕時不該建立目標目錄")
			}
		})
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{ContentFiles: []string{"a.png"}})
	target := newTarget(t, "restored")
	opts := options(bundle, target, manifest)
	opts.DryRun = true

	res, err := Execute(context.Background(), opts)
	if err != nil {
		t.Fatalf("--dry-run 失敗: %v", err)
	}
	if res.Published || res.FilesWritten != 0 {
		t.Errorf("--dry-run 回報了寫入：published=%v files=%d", res.Published, res.FilesWritten)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Error("--dry-run 建立了目標目錄")
	}
	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		t.Fatalf("讀取父目錄失敗: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), stagingSuffix) {
			t.Errorf("--dry-run 建立了暫存目錄 %s", e.Name())
		}
	}
	// 判定仍然做完：落點規劃與六條路徑都要讀得到，否則 --dry-run 只是把活推給下一次。
	if res.Plan.DatabaseRel != "evernight.db" || len(res.Plan.Review.Effective) != 6 {
		t.Errorf("--dry-run 沒有算出落點：%+v", res.Plan)
	}
	if res.BundleFacts.SchemaVersion != manifest.Database.SchemaVersion {
		t.Error("--dry-run 沒有讀取包內那份快照的事實")
	}
}

func TestExecuteRejectsStagedCopyThatDiffersFromBundle(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{ContentFiles: []string{"a.png"}})
	target := newTarget(t, "restored")
	opts := options(bundle, target, manifest)
	calls := 0
	opts.Inspect = func(ctx context.Context, path string) (database.SnapshotInfo, error) {
		calls++
		info := factsFor(manifest)
		if calls == 2 {
			// 包內原件是好的，落地後讀到的卻少了一列——那時不能發布。
			info.Tables[0].Rows = 2
		}
		return info, nil
	}

	_, err := Execute(context.Background(), opts)
	if !errors.Is(err, ErrFactMismatch) {
		t.Fatalf("落地副本與清單不符必須拒絕，實際錯誤：%v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Error("拒絕後目標目錄被建立了")
	}
	entries, _ := os.ReadDir(filepath.Dir(target))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), stagingSuffix) {
			t.Errorf("拒絕後仍留著暫存目錄 %s（半成品不能冒充成品，也不能留著佔磁碟）", e.Name())
		}
	}
}

func TestExecuteRejectsAuditThatChangesMoreThanOneRow(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	target := newTarget(t, "restored")
	opts := options(bundle, target, manifest)
	calls := 0
	opts.Inspect = func(ctx context.Context, path string) (database.SnapshotInfo, error) {
		calls++
		info := factsFor(manifest)
		if calls >= 3 {
			// 那筆追加順手改了別的表——這不是「追加一筆」，不能當成功發布。
			for i := range info.Tables {
				info.Tables[i].Rows++
			}
		}
		return info, nil
	}
	opts.AppendAudit = func(ctx context.Context, dbPath string, m backup.Manifest) (idgen.ID, error) {
		return idgen.Nil, nil
	}

	_, err := Execute(context.Background(), opts)
	if !errors.Is(err, ErrFactMismatch) {
		t.Fatalf("追加審計造成額外變動時必須拒絕，實際錯誤：%v", err)
	}
	if !strings.Contains(err.Error(), "schema_migrations") {
		t.Errorf("錯誤要點出被動到的那張表，實際：%v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Error("拒絕後目標目錄被建立了")
	}
}

func TestExecuteRejectsAuditThatDidNotSwitchToWal(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	target := newTarget(t, "restored")
	opts := options(bundle, target, manifest)
	calls := 0
	opts.Inspect = func(ctx context.Context, path string) (database.SnapshotInfo, error) {
		calls++
		info := factsFor(manifest)
		if calls >= 3 {
			// 可寫開啟之後 journal_mode 仍是 delete：那筆記錄很可能根本沒落到這個檔案。
			for i := range info.Tables {
				if info.Tables[i].Table == rootAuditTable {
					info.Tables[i].Rows++
				}
			}
		}
		return info, nil
	}
	opts.AppendAudit = func(ctx context.Context, dbPath string, m backup.Manifest) (idgen.ID, error) {
		return idgen.Nil, nil
	}

	_, err := Execute(context.Background(), opts)
	if !errors.Is(err, ErrFactMismatch) {
		t.Fatalf("journal_mode 沒轉成 wal 時必須拒絕，實際錯誤：%v", err)
	}
	if !strings.Contains(err.Error(), "journal_mode") {
		t.Errorf("錯誤要點出 journal_mode，實際：%v", err)
	}
}

func TestExecutePublishesOverExistingEmptyTarget(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	target := newTarget(t, "restored")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("建立空目標目錄失敗: %v", err)
	}
	res, err := Execute(context.Background(), options(bundle, target, manifest))
	if err != nil {
		t.Fatalf("目標存在但為空時應該可以恢復: %v", err)
	}
	if !res.Published {
		t.Error("沒有發布")
	}
	if _, err := os.Stat(filepath.Join(target, "evernight.db")); err != nil {
		t.Errorf("內容沒有落在目標目錄裡: %v", err)
	}
}

func TestExecuteMirrorsEmptyContentSubdirs(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{ExtraDirs: []string{backup.KindMedia + "/2026/09"}})
	target := newTarget(t, "restored")
	if _, err := Execute(context.Background(), options(bundle, target, manifest)); err != nil {
		t.Fatalf("恢復失敗: %v", err)
	}
	if info, err := os.Stat(filepath.Join(target, "media", "2026", "09")); err != nil || !info.IsDir() {
		t.Errorf("空的子目錄沒有被鏡像出來（%v）；來源留了它，恢復出來的目錄就該有它", err)
	}
}

func TestExecuteReportsStaleStagingWithoutDeletingIt(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	target := newTarget(t, "restored")
	other := filepath.Join(filepath.Dir(target), ".other-run"+stagingSuffix)
	if err := os.MkdirAll(filepath.Join(other, "media"), 0o755); err != nil {
		t.Fatalf("建立殘留目錄失敗: %v", err)
	}
	if err := os.WriteFile(filepath.Join(other, "evernight.db"), []byte("half-written"), 0o644); err != nil {
		t.Fatalf("建立殘留檔案失敗: %v", err)
	}

	res, err := Execute(context.Background(), options(bundle, target, manifest))
	if err != nil {
		t.Fatalf("恢復失敗: %v", err)
	}
	if len(res.StaleStaging) != 1 || res.StaleStaging[0] != filepath.Base(other) {
		t.Errorf("既存的殘留必須回報出來：%v", res.StaleStaging)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("殘留暫存目錄被刪掉了（並行的另一次恢復可能正在裡面寫東西）: %v", err)
	}
}

func TestExecuteRejectsUnplannedFileInStaging(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	target := newTarget(t, "restored")
	opts := options(bundle, target, manifest)
	calls := 0
	opts.AppendAudit = func(ctx context.Context, dbPath string, m backup.Manifest) (idgen.ID, error) {
		// 回呼在那個目錄裡留下一個說不出來源的檔案：這次不能發布。
		if err := os.WriteFile(filepath.Join(filepath.Dir(dbPath), "mystery.bin"), []byte("x"), 0o644); err != nil {
			t.Fatalf("寫入非預期檔案失敗: %v", err)
		}
		return idgen.Nil, nil
	}
	opts.Inspect = func(ctx context.Context, path string) (database.SnapshotInfo, error) {
		calls++
		info := factsFor(manifest)
		if calls >= 3 {
			info.JournalMode = "wal"
			for i := range info.Tables {
				if info.Tables[i].Table == rootAuditTable {
					info.Tables[i].Rows++
				}
			}
		}
		return info, nil
	}

	_, err := Execute(context.Background(), opts)
	if !errors.Is(err, ErrUnlistedFile) {
		t.Fatalf("非預期的檔案必須拒絕發布，實際錯誤：%v", err)
	}
}

func TestValidateRejectsBadInputs(t *testing.T) {
	bundle, _ := writeBundle(t, bundleSpec{})
	target := newTarget(t, "restored")
	good := options(bundle, target, backup.Manifest{Database: backup.DatabaseFact{ApplicationID: testAppIDText}})

	for _, tc := range []struct {
		name   string
		mutate func(*Options)
	}{
		{"缺少來源", func(o *Options) { o.Bundle = "" }},
		{"缺少目標", func(o *Options) { o.Target = "" }},
		{"來源是相對路徑", func(o *Options) { o.Bundle = "relative/bundle" }},
		{"目標是相對路徑", func(o *Options) { o.Target = "relative/target" }},
		{"已知版本為負", func(o *Options) { o.KnownSchemaVersion = -1 }},
		{"缺少快照檢查", func(o *Options) { o.Inspect = nil }},
		{"缺少空間判定", func(o *Options) { o.Disk = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := good
			tc.mutate(&opts)
			if _, err := Execute(context.Background(), opts); err == nil {
				t.Fatalf("%s 時應該拒絕", tc.name)
			}
		})
	}
}

func TestValidateRejectsBundleThatIsAFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-bundle")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("建立檔案失敗: %v", err)
	}
	opts := options(file, newTarget(t, "restored"), backup.Manifest{})
	_, err := Execute(context.Background(), opts)
	if !errors.Is(err, ErrBundleShape) {
		t.Fatalf("來源是檔案時必須拒絕，實際錯誤：%v", err)
	}
}

func TestReadManifestRejectsUnknownProduct(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	manifest.Product = "some-other-server"
	manifest.FormatVersion = backup.FormatVersion
	writeManifestOf(t, bundle, manifest)

	_, err := readManifest(bundle)
	if !errors.Is(err, ErrFormatUnsupported) {
		t.Fatalf("別人的產品產出的包不能當成本服務的備份，實際錯誤：%v", err)
	}
}

func TestReadManifestRejectsZeroFormatVersion(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	manifest.FormatVersion = 0
	writeManifestOf(t, bundle, manifest)
	if _, err := readManifest(bundle); !errors.Is(err, ErrFormatUnsupported) {
		t.Fatalf("format_version 缺省時不能當 1 來讀，實際錯誤：%v", err)
	}
}

func TestManifestShapeRequiresOneDatabaseAndOneConfig(t *testing.T) {
	bundle, manifest := writeBundle(t, bundleSpec{})
	// 把資料庫條目改成一個不認識的類別：既找不到快照，也代表這份清單不是本產生端的形狀。
	for i := range manifest.Files {
		if manifest.Files[i].Kind == kindDatabase {
			manifest.Files[i].Kind = "videos"
		}
	}
	writeManifestOf(t, bundle, manifest)
	_, _, err := manifestDatabaseAndConfig(manifest)
	if !errors.Is(err, ErrManifestShape) {
		t.Fatalf("清單裡沒有資料庫條目時必須拒絕，實際錯誤：%v", err)
	}
}

func TestDiffTablesCoversBothSides(t *testing.T) {
	want := []database.TableRows{{Table: "a", Rows: 1}, {Table: "b", Rows: 2}}
	got := []database.TableRows{{Table: "b", Rows: 5}, {Table: "c", Rows: 1}}
	diff := diffTables(got, want)
	joined := strings.Join(diff, "；")
	for _, phrase := range []string{"表 a", "b 實際 5", "c=1"} {
		if !strings.Contains(joined, phrase) {
			t.Errorf("差量描述要包含 %q，實際：%v", phrase, diff)
		}
	}
}

func TestSamePathAndWithinCoverBothDirections(t *testing.T) {
	if !samePath("/data/dev", "/data/dev/") {
		t.Error("尾端斜線不該讓同一個目錄看成兩個")
	}
	if within("/data/dev", "/data/dev") {
		t.Error("等於本身不算「在裡面」")
	}
	if !within("/data", "/data/dev") {
		t.Error("/data/dev 在 /data 之內")
	}
	if within("/data/dev", "/data/other") {
		t.Error("兄弟目錄不在之內")
	}
}

// writeManifestOf 用測試改過的清單覆寫包內的 manifest.json（摘要欄位保持原樣，
// 因為這一組測試問的是「清單說的話與磁盤上的東西對不對得上」而不是哈希本身）。
func writeManifestOf(t *testing.T, bundleDir string, manifest backup.Manifest) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("編碼清單失敗: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, backup.ManifestName), append(data, '\n'), 0o644); err != nil {
		t.Fatalf("寫入清單失敗: %v", err)
	}
}
