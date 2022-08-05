package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/disk"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 本檔測的是「一份備份包怎麼成形」，一律用注入的假快照：
// 真快照的行為（含 WAL、唯讀、拒覆蓋）由 internal/database 的測試與程序級探針負責，
// 兩邊各測各的才不會出現「用同一套實作自己證明自己」。

const fakeSnapshotBytes = "SNAPSHOT-BYTES"

var fixedNow = time.Date(2026, 9, 27, 12, 34, 56, 789_000_000, time.UTC)

type fixture struct {
	outDir   string
	dataDir  string
	media    string
	docs     string
	attach   string
	configAt string
	calls    *int
}

// newFixture 造一個看起來像真的資料目錄：config.yaml 加三個內容目錄（其中媒體有巢狀檔與一個空目錄）。
func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{
		outDir:  filepath.Join(root, "backups"),
		dataDir: root,
		media:   filepath.Join(root, "media"),
		docs:    filepath.Join(root, "documents"),
		attach:  filepath.Join(root, "attachments"),
		calls:   new(int),
	}
	f.configAt = filepath.Join(root, "config.yaml")

	mustWrite(t, f.configAt, "server:\n  listen: \"127.0.0.1:5206\"\nsecurity:\n  root_password_hash: \"argon2id$fake$digest\"\n")
	mustWrite(t, filepath.Join(f.media, "avatar.png"), "PNG-BYTES")
	mustWrite(t, filepath.Join(f.media, "sub", "deep.bin"), strings.Repeat("深層檔案", 50))
	mustWrite(t, filepath.Join(f.attach, "note.txt"), "ATTACHMENT")
	for _, dir := range []string{f.outDir, f.docs} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("建立 %s 失敗: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("寫入 %s 失敗: %v", path, err)
	}
}

// options 給出預設可成功的輸入；各測試只改自己關心的那一個欄位。
func (f *fixture) options(t *testing.T) Options {
	t.Helper()
	return Options{
		OutDir:             f.outDir,
		Name:               "20260927T123456Z-01234567",
		SourceDataDir:      f.dataDir,
		SourceDatabasePath: filepath.Join(f.dataDir, "evernight.db"),
		ConfigPath:         f.configAt,
		ContentDirs: []ContentDir{
			{Kind: KindMedia, Path: f.media},
			{Kind: KindDocuments, Path: f.docs},
			{Kind: KindAttachments, Path: f.attach},
		},
		Snapshot: func(_ context.Context, target string) error {
			*f.calls++
			return os.WriteFile(target, []byte(fakeSnapshotBytes), 0o644)
		},
		Inspect: func(_ context.Context, path string) (database.SnapshotInfo, error) {
			return database.SnapshotInfo{
				SchemaVersion: 2, Integrity: "ok", JournalMode: "delete",
				ApplicationID: 0x4556524C, HeaderSchemaVersion: 2,
				Tables: []database.TableRows{{Table: "probe", Rows: 3}},
			}, nil
		},
		Disk: func() (disk.Verdict, error) {
			return disk.Verdict{Status: disk.StatusOK,
				Usage: disk.Usage{Path: f.outDir, Free: 1 << 30, Total: 1 << 40, CheckedAt: fixedNow}}, nil
		},
		ServerVersion: "0.1.0-test",
		Now:           fixedNow,
	}
}

// entriesOf 讀回包內的清單而不是用函式回傳的那份——清單是要被「事後」驗證的東東。
func entriesOf(t *testing.T, dir string) Manifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		t.Fatalf("讀取清單失敗: %v", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("清單不是合法 JSON: %v", err)
	}
	return m
}

func digestOf(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取 %s 失敗: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func stagingPath(opts Options) string {
	return filepath.Join(opts.OutDir, "."+opts.Name+".tmp")
}

func assertNoLeftovers(t *testing.T, opts Options) {
	t.Helper()
	if _, err := os.Stat(stagingPath(opts)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("失敗路徑留下臨時目錄 %s", stagingPath(opts))
	}
	if _, err := os.Stat(filepath.Join(opts.OutDir, opts.Name)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("失敗路徑留下了備份包目錄（半成品冒充成品）")
	}
}

func TestCreateProducesBundle(t *testing.T) {
	f := newFixture(t)
	opts := f.options(t)
	res, err := Create(context.Background(), opts)
	if err != nil {
		t.Fatalf("備份失敗: %v", err)
	}
	if *f.calls != 1 {
		t.Errorf("快照應只做一次，實際 %d 次", *f.calls)
	}
	if res.Dir != filepath.Join(f.outDir, opts.Name) {
		t.Errorf("回傳路徑不对：%s", res.Dir)
	}
	if _, err := os.Stat(stagingPath(opts)); !errors.Is(err, os.ErrNotExist) {
		t.Error("發布後臨時目錄應已消失（改名即發布）")
	}

	manifest := entriesOf(t, res.Dir)
	if manifest.FormatVersion != FormatVersion || manifest.Product != Product {
		t.Errorf("格式版本或產品識別不對：%+v", manifest)
	}
	if manifest.ServerVersion != "0.1.0-test" {
		t.Errorf("缺少伺服器版本資訊：%q", manifest.ServerVersion)
	}
	if want := timeutil.FormatUTC(fixedNow); manifest.CreatedAt != want {
		t.Errorf("created_at 應為 %s，實際 %s", want, manifest.CreatedAt)
	}
	if manifest.Database.SchemaVersion != 2 || manifest.Database.Integrity != "ok" {
		t.Errorf("資料庫事實未進清單：%+v", manifest.Database)
	}
	if manifest.Database.ApplicationID != "0x4556524c" {
		t.Errorf("application_id 應以十六進位小寫記：%q", manifest.Database.ApplicationID)
	}
	if manifest.Totals.Files != len(manifest.Files) {
		t.Errorf("totals.files=%d 但清單有 %d 筆", manifest.Totals.Files, len(manifest.Files))
	}
	var sum int64
	for _, e := range manifest.Files {
		sum += e.SizeBytes
	}
	if manifest.Totals.Bytes != sum {
		t.Errorf("totals.bytes=%d 與逐檔加總 %d 不符", manifest.Totals.Bytes, sum)
	}

	// 清單自身不能出現在 Files 裡（一份檔案寫不出自己的摘要），但要能在 Result 看到體積。
	for _, e := range manifest.Files {
		if e.Path == ManifestName {
			t.Error("清單把自已列進了檔案清單")
		}
	}
	if onDisk, err := os.ReadFile(filepath.Join(res.Dir, ManifestName)); err != nil || int64(len(onDisk)) != res.ManifestBytes {
		t.Errorf("Result.ManifestBytes=%d 與實際清單大小 %d 不符（%v）", res.ManifestBytes, len(onDisk), err)
	}

	// 最關鍵的一條：清單裡的摘要必須對得上磁盤上那份實際檔案，而不是對上來源或想像值。
	for _, e := range manifest.Files {
		actual := digestOf(t, filepath.Join(res.Dir, filepath.FromSlash(e.Path)))
		if actual != e.SHA256 {
			t.Errorf("%s 清單摘要 %s 與磁盤實際 %s 不符", e.Path, e.SHA256[:12], actual[:12])
		}
		if st, err := os.Stat(filepath.Join(res.Dir, filepath.FromSlash(e.Path))); err != nil || st.Size() != e.SizeBytes {
			t.Errorf("%s 清單大小 %d 與磁盤實際不符（%v）", e.Path, e.SizeBytes, err)
		}
	}

	// 路徑一律斜線且帶類別前綴；清單按路徑排序（兩份清單要能逐字比較）。
	wantPaths := []string{
		"attachments/note.txt", "config/config.yaml", "database/evernight.db",
		"media/avatar.png", "media/sub/deep.bin",
	}
	got := make([]string, 0, len(manifest.Files))
	for _, e := range manifest.Files {
		if strings.Contains(e.Path, `\`) {
			t.Errorf("清單路徑需一律斜線：%s", e.Path)
		}
		got = append(got, e.Path)
	}
	if !reflect.DeepEqual(got, wantPaths) {
		t.Errorf("清單檔案集合與排序不符\nwant %v\ngot  %v", wantPaths, got)
	}

	// 空目錄也要在包裡：恢復出來少一個目錄，服務啟動時又得自己建一次，兩份真相。
	if st, err := os.Stat(filepath.Join(res.Dir, KindDocuments)); err != nil || !st.IsDir() {
		t.Errorf("空的 documents 目錄也應出現在包內（%v）", err)
	}
	if st, err := os.Stat(filepath.Join(res.Dir, KindMedia, "sub")); err != nil || !st.IsDir() {
		t.Errorf("巢狀空結構應保留（%v）", err)
	}
}

// TestCreateCopiesConfigVerbatim 是本步最容易被做錯的一條：
// 組態含 Argon2id 口令摘要，而 §7 的遮罩規則只屬於日誌與審計——遮罩過的值恢復出來是壞的。
func TestCreateCopiesConfigVerbatim(t *testing.T) {
	f := newFixture(t)
	opts := f.options(t)
	res, err := Create(context.Background(), opts)
	if err != nil {
		t.Fatalf("備份失敗: %v", err)
	}

	copyPath := filepath.Join(res.Dir, filepath.FromSlash(ConfigRel))
	got, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatalf("讀取組態副本失敗: %v", err)
	}
	source, _ := os.ReadFile(f.configAt)
	if string(got) != string(source) {
		t.Errorf("組態副本必須與來源逐字相同\nsource %q\ncopy  %q", source, got)
	}
	if !strings.Contains(string(got), "root_password_hash") {
		t.Error("副本裡看不到 root_password_hash，說明被改寫過")
	}
	st, err := os.Stat(copyPath)
	if err != nil {
		t.Fatalf("讀取副本屬性失敗: %v", err)
	}
	// 0600 只在 POSIX 權限的平台上做得到：Windows 上 Go 的 chmod 只能表達「唯讀」位，
	// 檔案實際繼承目錄 ACL。少寫這一行，測試會在本專案的主要開發平台上變成一條假斷言。
	if runtime.GOOS == "windows" {
		t.Logf("Windows 平台上副本權限為 %v（0600 需要 POSIX 權限語意，此處無法主張）", st.Mode().Perm())
	} else if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("組態副本含口令摘要，權限需收斂到 0600，實際 %v", st.Mode().Perm())
	}
}

func TestCreateRefusesExistingName(t *testing.T) {
	f := newFixture(t)
	opts := f.options(t)
	final := filepath.Join(f.outDir, opts.Name)
	mustWrite(t, filepath.Join(final, "keep.txt"), "IMPORTANT-OLD-BACKUP")
	before := digestOf(t, filepath.Join(final, "keep.txt"))

	_, err := Create(context.Background(), opts)
	if !errors.Is(err, ErrBundleExists) {
		t.Fatalf("同名備份包已存在時應回 ErrBundleExists，實際 %v", err)
	}
	if *f.calls != 0 {
		t.Error("拒絕時不應開始取快照")
	}
	if got := digestOf(t, filepath.Join(final, "keep.txt")); got != before {
		t.Errorf("既有備份包被改動（%s → %s）", before[:8], got[:8])
	}
	if _, err := os.Stat(filepath.Join(final, DatabaseRel)); !errors.Is(err, os.ErrNotExist) {
		t.Error("拒絕時不應往既有備份包裡寫快照")
	}
	// 這個測試的最後目錄是測試自己造的，所以只能比「臨時目錄沒留下」與「既有內容一項沒多」。
	if _, err := os.Stat(stagingPath(opts)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("拒絕時不應留下臨時目錄 %s", stagingPath(opts))
	}
	names, err := os.ReadDir(final)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0].Name() != "keep.txt" {
		t.Errorf("拒絕同名時不應動到既有備份包內容，實際有 %d 項：%v", len(names), names)
	}
}

// TestCreateRefusesSpaceLowAndUnknown：不足與查不出來都拒，而且是在動筆之前拒。
// 這裡比寫入門（DEC-033）嚴，是因為這層護的是「這份檔能不能整份恢復」。
func TestCreateRefusesSpaceLowAndUnknown(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  disk.Status
		comment string
	}{
		{"不足", disk.StatusLow, "剩餘低於下限"},
		{"查不出來", disk.StatusUnknown, "取得卷可用空間失敗"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			opts := f.options(t)
			opts.Disk = func() (disk.Verdict, error) {
				return disk.Verdict{Status: tc.status, Reason: tc.comment}, nil
			}
			_, err := Create(context.Background(), opts)
			if !errors.Is(err, ErrSpace) {
				t.Fatalf("應回 ErrSpace，實際 %v", err)
			}
			if !strings.Contains(err.Error(), tc.comment) {
				t.Errorf("錯誤需带上判定原因，方便運維知道要去清哪：%v", err)
			}
			if *f.calls != 0 {
				t.Error("判定未通過時不應取快照")
			}
			assertNoLeftovers(t, opts)
			entries, _ := os.ReadDir(f.outDir)
			if len(entries) != 0 {
				t.Errorf("拒絕時備份目錄應保持空，實際有 %d 項", len(entries))
			}
		})
	}
}

func TestCreatePropagatesDiskProbeError(t *testing.T) {
	f := newFixture(t)
	opts := f.options(t)
	opts.Disk = func() (disk.Verdict, error) { return disk.Verdict{}, errors.New("判定失敗") }
	if _, err := Create(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "判定失敗") {
		t.Fatalf("判定本身出錯時要原樣交代：%v", err)
	}
	assertNoLeftovers(t, opts)
}

// TestCreateCleansUpOnEveryFailure 覆蓋三條「已經開始寫」的失敗路徑：
// 半成品只可能存在於臨時目錄，而任何失敗都要把它清掉。
func TestCreateCleansUpOnEveryFailure(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *fixture, *Options)
		want   error
	}{
		{"快照失敗", func(_ *testing.T, _ *fixture, o *Options) {
			o.Snapshot = func(_ context.Context, target string) error {
				// 模擬「寫到一半就壞」：目標留了半份檔案。
				return os.WriteFile(target, []byte("half"), 0o644)
			}
			o.Snapshot = func(context.Context, string) error { return errors.New("炸了") }
		}, nil},
		{"完整性未過", func(_ *testing.T, _ *fixture, o *Options) {
			o.Inspect = func(context.Context, string) (database.SnapshotInfo, error) {
				return database.SnapshotInfo{Integrity: "*** in database main root ***"}, nil
			}
		}, ErrUnsoundSnapshot},
		{"檢查失敗", func(_ *testing.T, _ *fixture, o *Options) {
			o.Inspect = func(context.Context, string) (database.SnapshotInfo, error) {
				return database.SnapshotInfo{}, errors.New("讀不到")
			}
		}, nil},
		{"找不到組態", func(_ *testing.T, f *fixture, o *Options) {
			o.ConfigPath = filepath.Join(f.dataDir, "沒有這個檔案.yaml")
		}, nil},
		{"內容目錄不存在", func(_ *testing.T, f *fixture, o *Options) {
			o.ContentDirs = []ContentDir{{Kind: KindMedia, Path: filepath.Join(f.dataDir, "ghost")}}
		}, nil},
		{"內容目錄是檔案", func(_ *testing.T, f *fixture, o *Options) {
			o.ContentDirs = []ContentDir{{Kind: KindMedia, Path: o.ConfigPath}}
		}, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			opts := f.options(t)
			tc.mutate(t, f, &opts)

			_, err := Create(context.Background(), opts)
			if err == nil {
				t.Fatal("預期失敗但成功了")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("應是 %v，實際 %v", tc.want, err)
			}
			assertNoLeftovers(t, opts)
		})
	}
}

// TestCreateIgnoresPreexistingStaging：臨時目錄的名字完全由包名派生，
// 裡面的東西只可能是上一次異常留下的半成品——先刪後用，才不會把舊垃圾打包成新備份。
func TestCreateRecreatesStaging(t *testing.T) {
	f := newFixture(t)
	opts := f.options(t)
	staging := stagingPath(opts)
	mustWrite(t, filepath.Join(staging, "stale.txt"), "上一次的殘渣")
	if err := os.MkdirAll(filepath.Join(staging, KindMedia), 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := Create(context.Background(), opts)
	if err != nil {
		t.Fatalf("備份失敗: %v", err)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "stale.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Error("上一次臨時目錄的殘渣被當成這一次的備份內容發布了")
	}
	manifest := entriesOf(t, res.Dir)
	for _, e := range manifest.Files {
		if e.Path == "stale.txt" {
			t.Error("清單裡出現上一次的殘渣")
		}
	}
}

func TestCreateHonoursContextCancellation(t *testing.T) {
	f := newFixture(t)
	opts := f.options(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts.Snapshot = func(ctx context.Context, _ string) error {
		return ctx.Err()
	}
	if _, err := Create(ctx, opts); err == nil {
		t.Fatal("已取消的 context 應讓備份失敗")
	}
	assertNoLeftovers(t, opts)
}

// TestCreateRejectsSpecialFile：內容目錄裡出現非普通檔時要拒絕而不是跳過。
// 跳過的結果是「還原出來少東西」，那比當場失敗難察覺得多。
func TestCreateRejectsSpecialFile(t *testing.T) {
	f := newFixture(t)
	opts := f.options(t)
	link := filepath.Join(f.media, "link.png")
	if err := os.Symlink(filepath.Join(f.media, "avatar.png"), link); err != nil {
		t.Skipf("此環境無法建立符號連結（Windows 需開發者模式或權限）：%v", err)
	}

	_, err := Create(context.Background(), opts)
	if !errors.Is(err, ErrSpecialFile) {
		t.Fatalf("符號連結應讓備份拒絕，實際 %v", err)
	}
	assertNoLeftovers(t, opts)
}

func TestValidateRejectsBadInput(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name   string
		mutate func(*Options)
	}{
		{"名稱帶路徑分隔", func(o *Options) { o.Name = "a/b" }},
		{"名稱帶反斜線", func(o *Options) { o.Name = `a\b` }},
		{"名稱為上層", func(o *Options) { o.Name = ".." }},
		{"名稱留空", func(o *Options) { o.Name = "" }},
		{"輸出目錄留空", func(o *Options) { o.OutDir = "" }},
		{"組態路徑留空", func(o *Options) { o.ConfigPath = "" }},
		{"缺少快照實作", func(o *Options) { o.Snapshot = nil }},
		{"缺少檢查實作", func(o *Options) { o.Inspect = nil }},
		{"缺少空間判定", func(o *Options) { o.Disk = nil }},
		{"缺少備份時刻", func(o *Options) { o.Now = time.Time{} }},
		{"備份時刻不是 UTC", func(o *Options) { o.Now = fixedNow.In(time.FixedZone("UTC+8", 8*3600)) }},
		{"內容目錄缺類別", func(o *Options) { o.ContentDirs = []ContentDir{{Path: f.media}} }},
		{"內容目錄缺路徑", func(o *Options) { o.ContentDirs = []ContentDir{{Kind: KindMedia}} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := f.options(t)
			tc.mutate(&opts)
			if _, err := Create(context.Background(), opts); err == nil {
				t.Fatal("該拒的輸入沒拒")
			}
			if err := opts.validate(); err == nil {
				t.Errorf("validate 未抓到：%s", tc.name)
			}
		})
	}
}

// TestManifestJSONContract 固定清單的欄位名稱與形狀：恢復入口要照這份解析。
// 欄位改名在這裡會讓測試失敗，而不是等到恢復那天才發現「讀到的是 null」。
func TestManifestJSONContract(t *testing.T) {
	f := newFixture(t)
	opts := f.options(t)
	opts.Inspect = func(context.Context, string) (database.SnapshotInfo, error) {
		return database.SnapshotInfo{SchemaVersion: 1, Integrity: "ok", JournalMode: "delete", Tables: nil}, nil
	}
	res, err := Create(context.Background(), opts)
	if err != nil {
		t.Fatalf("備份失敗: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(res.Dir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"format_version", "product", "server_version", "created_at",
		"source", "database", "disk", "files", "totals"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("清單缺少欄位 %s（snake_case 合同）", key)
		}
	}
	for key := range doc {
		if strings.ToUpper(key) != key && strings.ContainsAny(key, "A") {
			t.Errorf("清單欄位需一律 snake_case：%s", key)
		}
	}
	var dbDoc map[string]any
	if err := json.Unmarshal(doc["database"], &dbDoc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"path", "schema_version", "integrity", "journal_mode",
		"application_id", "header_user_version", "tables"} {
		if _, ok := dbDoc[key]; !ok {
			t.Errorf("database 缺少欄位 %s", key)
		}
	}
	// 沒有資料表時寫 [] 而不是 null：解析端不必為一個空庫多判一種型別。
	if !strings.Contains(string(data), `"tables": []`) {
		t.Errorf("空表清單應寫成 []，清單內容：%s", firstLines(string(data), 40))
	}
}

func firstLines(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// TestCreateIsDeterministicAcrossRuns 要保證「同一個資料目錄、同一個時刻」產出的清單
// 除了包名之外逐字相同——否則兩份備份的清單沒法逐字比較，diff 也看不出真差異。
func TestCreateIsDeterministicAcrossRuns(t *testing.T) {
	f := newFixture(t)
	var manifests []string
	for i, name := range []string{"run-a", "run-b"} {
		opts := f.options(t)
		opts.Name = fmt.Sprintf("20260927T123456Z-%s", name)
		res, err := Create(context.Background(), opts)
		if err != nil {
			t.Fatalf("第 %d 次備份失敗: %v", i, err)
		}
		data, err := os.ReadFile(filepath.Join(res.Dir, ManifestName))
		if err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, string(data))
	}
	if manifests[0] != manifests[1] {
		t.Errorf("同一輸入的兩次備份清單應逐字相同\n第一次：%s\n第二次：%s", manifests[0], manifests[1])
	}
}

// TestCreateWritesManifestLast：清單是最後一個被寫入的檔案，
// 因此「包裡有清單」就等於「包內其他檔案都已經就位」。
func TestCreateWritesManifestLast(t *testing.T) {
	f := newFixture(t)
	opts := f.options(t)
	var order []time.Time
	opts.Snapshot = func(_ context.Context, target string) error {
		order = append(order, time.Now())
		return os.WriteFile(target, []byte(fakeSnapshotBytes), 0o644)
	}
	if _, err := Create(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(f.outDir, opts.Name, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if st.ModTime().Before(order[0]) {
		t.Error("清單比快照還早寫好，代表清單可能描述著還不存在的檔案")
	}
}
