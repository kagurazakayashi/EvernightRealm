package app

// 本檔測的是 `evernight-server restore` 這條運維路徑：命令接線、真實資料庫的往返閉環、
// 以及「不覆蓋當前開發目錄」這一條在真實檔案系統上的表現。
// internal/restore 那一份測試把判定逐項固定住，這裡要的是另一件事：
// 恢復出來的目錄真的能用正式流程開起來、裡面的資料真的是清單描述的那一份。

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/backup"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/restore"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// seedAuditRow 用正式通路往指定資料目錄的庫寫一筆 Root 審計，回傳記錄標識。
//
// 這一筆是「恢復之後要比對」的對象，因此走 internal/audit 的正式介面而不是手寫 SQL：
// 手寫的資料讀得回來，證明不了真那條通路留下的東西也在。
func seedAuditRow(t *testing.T, dir string) idgen.ID {
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
	store := audit.NewStore(timeutil.System())
	var id idgen.ID
	err = db.InTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		var appendErr error
		id, appendErr = store.Append(ctx, tx, audit.Record{
			Scope:  audit.ScopeRoot,
			Actor:  audit.Actor{Kind: audit.ActorSystem},
			Action: "server.startup",
			Target: audit.Target{Kind: "server"},
			Changes: []audit.Change{
				{Field: "theme", Before: "old", After: "長夜幻境"},
			},
		})
		return appendErr
	})
	if err != nil {
		t.Fatalf("寫入審計失敗: %v", err)
	}
	return id
}

// upsertServerSetting 改一筆已存在的設定。
//
// 備份之後要讓來源目錄「往前走一步」，用的就是它：seedServerSetting 是 INSERT，
// 同一個鍵第二次寫會撞 UNIQUE——那個撞擊本身是對的（伺服器設定的唯一性由資料庫保證），
// 只是這裡要的是改值而不是多一筆。
func upsertServerSetting(t *testing.T, dir, key, value string) {
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
	err = db.InTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO server_settings (key, value, updated_at) VALUES (?, ?, ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
			key, value, timeutil.ToMillis(timeutil.System().Now()))
		return err
	})
	if err != nil {
		t.Fatalf("更新設定失敗: %v", err)
	}
}

// countRows 以唯讀連線數一張表的列數；判讀恢復結果時不借道寫入通路。
func countRows(t *testing.T, dbPath, table string) int {
	t.Helper()
	info, err := database.InspectSnapshot(context.Background(), dbPath, 2*time.Second)
	if err != nil {
		t.Fatalf("讀取快照事實失敗: %v", err)
	}
	for _, item := range info.Tables {
		if item.Table == table {
			return int(item.Rows)
		}
	}
	t.Fatalf("表 %s 讀不到列數（%+v）", table, info.Tables)
	return 0
}

// readSetting 用正式開庫流程讀一筆 server_settings。
func readSetting(t *testing.T, dir, key string) string {
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
	var value string
	if err := db.InTxReadOnly(ctx, func(ctx context.Context, tx *database.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT value FROM server_settings WHERE key = ?`, key).Scan(&value)
	}); err != nil {
		t.Fatalf("讀取設定 %s 失敗: %v", key, err)
	}
	return value
}

// preparedSource 建好一份「有業務資料、有審計、有媒體檔」的資料目錄並備出一份包，
// 回傳來源目錄、備份包路徑與清單。
func preparedSource(t *testing.T) (string, string, backup.Manifest) {
	t.Helper()
	ctx := context.Background()
	dir := retryTempDir(t)
	if err := Migrate(ctx, []string{"--data-dir", dir}, &bytes.Buffer{}); err != nil {
		t.Fatalf("建立資料庫失敗: %v", err)
	}
	seedServerSetting(t, dir, "theme", "長夜幻境")
	if err := os.WriteFile(filepath.Join(dir, "media", "poster.png"), []byte("PNG-BYTES"), 0o644); err != nil {
		t.Fatalf("寫入媒體檔失敗: %v", err)
	}
	out := &bytes.Buffer{}
	if err := Backup(ctx, []string{"--data-dir", dir}, out); err != nil {
		t.Fatalf("backup 子命令失敗: %v\n輸出：%s", err, out)
	}
	bundle := bundleFromReport(t, out.String())
	return dir, bundle, readManifest(t, bundle)
}

func TestRestoreSubcommandRoundTrip(t *testing.T) {
	dir, bundle, manifest := preparedSource(t)
	seedAuditRow(t, dir)

	// 備份之後再改一次來源目錄：恢復出來的內容必須是包裡那一份，而不是「目前的現況」。
	// 這條區分是這一步的核心——否則恢復讀起來永遠像成功的。
	upsertServerSetting(t, dir, "theme", "備份之後改的名字")
	beforeMain := digestFileBytes(filepath.Join(dir, "evernight.db"))

	target := filepath.Join(retryTempDir(t), "restored")
	out := &bytes.Buffer{}
	if err := Restore(context.Background(), []string{"--bundle", bundle, "--into", target, "--data-dir", dir}, out); err != nil {
		t.Fatalf("restore 子命令失敗: %v\n輸出：%s", err, out)
	}
	report := out.String()
	for _, want := range []string{
		"已發布：", "integrity=ok", "foreign_key_check=0 筆違規", "恢復審計：已追加 1 筆 Root 記錄",
		"包內組態以目標目錄解析後的路徑", "提示：包內 server.data_dir",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("恢復報告缺少 %q：\n%s", want, report)
		}
	}

	// 資料來自包而不是來源目錄。
	if got := readSetting(t, target, "theme"); got != "長夜幻境" {
		t.Errorf("恢復出來的設定值是 %q，清單那份包裡記的是 backup 當時的值（來源後來被改成另一值）", got)
	}
	if got := digestFileBytes(filepath.Join(dir, "evernight.db")); got != beforeMain {
		t.Errorf("恢復動到了來源主檔（%s → %s）", beforeMain[:12], got[:12])
	}

	// 內容目錄也跟著回來。
	if got := digestFileBytes(filepath.Join(target, "media", "poster.png")); got != digestFileBytes(filepath.Join(bundle, "media", "poster.png")) {
		t.Error("媒體檔與包內那份不一致")
	}

	// 組態原樣落盤（不改寫任何一個字），否則清單裡那筆摘要描述的就不再是那個檔案。
	if got, want := digestFileBytes(filepath.Join(target, "config.yaml")),
		digestFileBytes(filepath.Join(bundle, filepath.FromSlash(backup.ConfigRel))); got != want {
		t.Errorf("包內組態被改寫了（%s → %s）", want[:12], got[:12])
	}

	// 結構版本與清單相同、審計表恰好比清單多這一筆。
	// 行數取自內嵌遷移集的最高版本（版本連續 1..N），新增遷移時不必回改這裡。
	maxVersion, err := migrate.MaxVersion()
	if err != nil {
		t.Fatalf("讀取遷移集最高版本失敗: %v", err)
	}
	if got := countRows(t, filepath.Join(target, "evernight.db"), "schema_migrations"); got != maxVersion {
		t.Errorf("schema_migrations 列數 %d，遷移集記 %d", got, maxVersion)
	}
	manifestRootAudit := 0
	for _, item := range manifest.Database.Tables {
		if item.Table == "root_audit" {
			manifestRootAudit = int(item.Rows)
		}
	}
	if got := countRows(t, filepath.Join(target, "evernight.db"), "root_audit"); got != manifestRootAudit+1 {
		t.Errorf("root_audit 應為清單那 %d 筆再加恢復這筆（共 %d），實際 %d", manifestRootAudit, manifestRootAudit+1, got)
	}

	// 副產物：鎖檔在發布前就被清掉了（報告那一行是這次的證據；發布之後再開啟那個庫
	// 會重新出現一把鎖，那是測試自己動的手，不是恢復留下的）。
	if !strings.Contains(report, "已清理") || !strings.Contains(report, "evernight.db.lock") ||
		!strings.Contains(report, "保留 evernight.db-wal") {
		t.Errorf("報告未回報清理掉的鎖檔：\n%s", report)
	}
	for _, e := range mustReadDir(t, filepath.Dir(target)) {
		if strings.HasSuffix(e.Name(), ".restoring.tmp") {
			t.Errorf("發布後仍留著暫存目錄 %s", e.Name())
		}
	}
	// 恢復出來的目錄本身是一份可用的資料目錄：migrate --verify 讀得開、版本與清單一致。
	verify := &bytes.Buffer{}
	if err := Migrate(context.Background(), []string{"--data-dir", target, "--verify"}, verify); err != nil {
		t.Fatalf("對恢復出來的目錄自檢失敗: %v\n%s", err, verify)
	}
	if !strings.Contains(verify.String(), "integrity_check=ok") {
		t.Errorf("自檢沒回報 integrity_check=ok：\n%s", verify)
	}
}

func TestRestoreDryRunWritesNothing(t *testing.T) {
	dir, bundle, _ := preparedSource(t)
	target := filepath.Join(retryTempDir(t), "restored")

	out := &bytes.Buffer{}
	err := Restore(context.Background(), []string{"--bundle", bundle, "--into", target, "--dry-run", "--data-dir", dir}, out)
	if err != nil {
		t.Fatalf("--dry-run 失敗: %v\n%s", err, out)
	}
	report := out.String()
	if !strings.Contains(report, "--dry-run，未寫入任何檔案") {
		t.Errorf("報告要講清楚這一次什麼都沒寫：\n%s", report)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Error("--dry-run 建立了目標目錄")
	}
	for _, e := range mustReadDir(t, filepath.Dir(target)) {
		if strings.HasSuffix(e.Name(), ".restoring.tmp") {
			t.Errorf("--dry-run 建立了暫存目錄 %s", e.Name())
		}
	}
}

func TestRestoreRefusesNonEmptyTarget(t *testing.T) {
	dir, bundle, _ := preparedSource(t)
	target := filepath.Join(retryTempDir(t), "restored")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("建立目錄失敗: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "important.txt"), []byte("別蓋掉我"), 0o644); err != nil {
		t.Fatalf("建立檔案失敗: %v", err)
	}
	before := digestFileBytes(filepath.Join(target, "important.txt"))

	out := &bytes.Buffer{}
	err := Restore(context.Background(), []string{"--bundle", bundle, "--into", target, "--data-dir", dir}, out)
	if !errors.Is(err, restore.ErrTargetNotEmpty) {
		t.Fatalf("目標非空時必須拒絕，實際：%v\n%s", err, out)
	}
	if got := digestFileBytes(filepath.Join(target, "important.txt")); got != before {
		t.Error("拒絕的路徑上動到了既有檔案")
	}
	if _, err := os.Stat(filepath.Join(target, "evernight.db")); err == nil {
		t.Error("拒絕後目標目錄裡出現了恢復出來的庫")
	}
	if !strings.Contains(err.Error(), "本命令不會覆蓋既有目錄") {
		t.Errorf("錯誤要說出這條規則是故意的（並指出該自己先備份），實際：%v", err)
	}
}

func TestRestoreRefusesItsOwnDataDir(t *testing.T) {
	dir, bundle, _ := preparedSource(t)
	out := &bytes.Buffer{}
	// 這一條就是大綱那句「不覆蓋當前開發目錄」：同一個目錄同時是來源設定與落點時直接拒絕。
	err := Restore(context.Background(), []string{"--bundle", bundle, "--into", dir, "--data-dir", dir}, out)
	if !errors.Is(err, restore.ErrTargetIsCurrent) {
		t.Fatalf("恢復到本次程序的資料目錄必須拒絕，實際：%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "evernight.db")); err != nil {
		t.Errorf("拒絕路徑上那個目錄該原封不動（%v）", err)
	}
}

func TestRestoreRefusesTamperedBundleWithoutCreatingTarget(t *testing.T) {
	dir, bundle, _ := preparedSource(t)
	if err := os.WriteFile(filepath.Join(bundle, "media", "poster.png"), []byte("TAMPERED"), 0o644); err != nil {
		t.Fatalf("植入篡改失敗: %v", err)
	}
	target := filepath.Join(retryTempDir(t), "restored")

	out := &bytes.Buffer{}
	err := Restore(context.Background(), []string{"--bundle", bundle, "--into", target, "--data-dir", dir}, out)
	if !errors.Is(err, restore.ErrChecksumMismatch) {
		t.Fatalf("摘要不符必須拒絕，實際：%v\n%s", err, out)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Error("核對未過時不該建立目標目錄")
	}
}

func TestRestoreRefusesMissingFlags(t *testing.T) {
	dir, bundle, _ := preparedSource(t)
	out := &bytes.Buffer{}

	if err := Restore(context.Background(), []string{"--into", filepath.Join(retryTempDir(t), "x"), "--data-dir", dir}, out); err == nil {
		t.Error("沒有 --bundle 時不該恢復「隨便哪一份」")
	} else if !strings.Contains(err.Error(), "--bundle") {
		t.Errorf("錯誤要點出缺哪個引數，實際：%v", err)
	}

	if err := Restore(context.Background(), []string{"--bundle", bundle, "--data-dir", dir}, out); err == nil {
		t.Error("沒有 --into 時不該恢復到目前設定的資料目錄")
	} else if !strings.Contains(err.Error(), "--into") {
		t.Errorf("錯誤要點出缺哪個引數，實際：%v", err)
	}
}

func TestParseRestoreArgsForms(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		bundle     string
		into       string
		dryRun     bool
		restJoined string
		wantErr    string
	}{
		{"空格形式", []string{"--bundle", "B", "--into", "T"}, "B", "T", false, "", ""},
		{"等號形式", []string{"--bundle=B", "--into=T"}, "B", "T", false, "", ""},
		{"混合與順序", []string{"--data-dir", "D", "--bundle=B", "--dry-run", "--into", "T"}, "B", "T", true, "--data-dir D", ""},
		{"重複 bundle", []string{"--bundle", "B1", "--bundle", "B2"}, "", "", false, "", "重複"},
		{"bundle 缺值", []string{"--bundle"}, "", "", false, "", "需要一個值"},
		{"into 缺值", []string{"--into"}, "", "", false, "", "需要一個值"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle, into, dryRun, rest, err := parseRestoreArgs(tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("期望錯誤含 %q，實際：%v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("解析失敗: %v", err)
			}
			if bundle != tc.bundle || into != tc.into || dryRun != tc.dryRun {
				t.Errorf("解析結果不符：%q %q %v", bundle, into, dryRun)
			}
			if strings.Join(rest, " ") != tc.restJoined {
				t.Errorf("交回組態解析的引數不符：%q（期望 %q）", strings.Join(rest, " "), tc.restJoined)
			}
		})
	}
}

func TestRestoreAuditRecordShapeAndValuesSurviveRedaction(t *testing.T) {
	manifest := backup.Manifest{
		CreatedAt: "2026-09-27T10:00:00.000Z",
		Database:  backup.DatabaseFact{SchemaVersion: 2},
		Totals: struct {
			Files int   `json:"files"`
			Bytes int64 `json:"bytes"`
		}{Files: 7, Bytes: 4096},
	}
	record, err := restoreAuditRecord(manifest, `P:\restore-bundle`, `P:\restore-target`)
	if err != nil {
		t.Fatalf("構造恢復審計記錄失敗：%v", err)
	}

	if record.Scope != audit.ScopeRoot || record.Actor.Kind != audit.ActorSystem || !record.Actor.ID.IsNil() {
		t.Errorf("恢復事件的主體與作用域不符：%+v", record)
	}
	if record.Action != "server.restore" || record.Target.Kind != "server" {
		t.Errorf("機器碼不該是句子：%+v", record)
	}
	if record.ActivityID != idgen.Nil || record.RequestID != "" {
		t.Error("Root 事件不屬任何活動，也沒有請求標識；填了就是冒充請求驅動的操作")
	}
	if len(record.Changes) != 6 {
		t.Fatalf("摘要欄位數不符：%+v", record.Changes)
	}
	// 路徑必須以原值查得回來：被 §7 打碼的摘要說不出恢復了哪個目錄。
	fields := map[string]bool{}
	for _, c := range record.Changes {
		fields[c.Field] = true
		if c.Before != nil {
			t.Errorf("%s 不該有 before 值（還原前那個目錄裡沒有這些事實）", c.Field)
		}
	}
	for _, want := range []string{"backup_path", "data_dir", "backup_created_at", "schema_version", "files", "bytes"} {
		if !fields[want] {
			t.Errorf("摘要缺少欄位 %s", want)
		}
	}

	// 真的寫進庫再讀回來，確認那兩條路徑原值仍在欄裡（這是「免於誤傷」的實證，不是推定）。
	dir := retryTempDir(t)
	if err := Migrate(context.Background(), []string{"--data-dir", dir}, &bytes.Buffer{}); err != nil {
		t.Fatalf("建立資料庫失敗: %v", err)
	}
	db, err := database.Open(context.Background(), database.Options{Path: filepath.Join(dir, "evernight.db"), BusyTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("開庫失敗: %v", err)
	}
	defer func() { _ = db.Close() }()
	store := audit.NewStore(timeutil.System())
	var id idgen.ID
	err = db.InTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
		var appendErr error
		id, appendErr = store.Append(ctx, tx, record)
		return appendErr
	})
	if err != nil {
		t.Fatalf("寫入恢復審計失敗: %v", err)
	}
	page, err := store.Query(context.Background(), db.SQL(), audit.Viewer{Kind: audit.ActorRoot},
		audit.Filter{Scope: audit.ScopeRoot, Limit: 10})
	if err != nil {
		t.Fatalf("讀回審計失敗: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("讀到 %d 筆，期望 1 筆", len(page.Records))
	}
	got := page.Records[0]
	if got.ID != id {
		t.Errorf("讀回的標識與寫入的不同：%s vs %s", got.ID, id)
	}
	var foundPath, foundDir bool
	for _, c := range got.Changes {
		if after, ok := c.After.(string); ok {
			if strings.Contains(after, `P:\restore-bundle`) {
				foundPath = true
			}
			if strings.Contains(after, `P:\restore-target`) {
				foundDir = true
			}
		}
	}
	if !foundPath || !foundDir {
		t.Errorf("路徑值被遮罩掉了（bundle=%v target=%v）：%+v", foundPath, foundDir, got.Changes)
	}
}

func TestRestoreReportsConfiguredPathsAndStaleVersion(t *testing.T) {
	note := restoreConfigNote(restore.Result{
		Target: `P:\restored`,
		Plan: restore.Plan{Review: restore.ConfigReview{
			BundleDataDir: ".",
			Effective: map[string]string{"database.path": `P:\restored\evernight.db`,
				"media": `P:\restored\media`, "documents": `P:\restored\documents`,
				"attachments": `P:\restored\attachments`, "backups": `P:\restored\backups`,
				"logs.dir": `P:\restored\logs`},
		}},
	})
	for _, want := range []string{"database.path", "media", "documents", "attachments", "backups", "logs.dir",
		"--data-dir", "不改寫這份組態"} {
		if !strings.Contains(note, want) {
			t.Errorf("配置復核那一段缺少 %q：\n%s", want, note)
		}
	}

	// 結構版本落後時要說出「下次啟動會前向遷移」，而不是讓它讀成一份壞掉的包。
	noteVersion := restoreVersionNote(restore.Result{
		BundleFacts: database.SnapshotInfo{SchemaVersion: 2},
	}, 9)
	if !strings.Contains(noteVersion, "前向遷移") {
		t.Errorf("落後版本要給出下一步：\n%s", noteVersion)
	}
	if restoreVersionNote(restore.Result{BundleFacts: database.SnapshotInfo{SchemaVersion: 9}}, 9) != "" {
		t.Error("版本相符時不該多印一行")
	}
}

// mustReadDir 讀目錄並在失敗時結束測試。
func mustReadDir(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("讀取目錄失敗（%s）: %v", dir, err)
	}
	return entries
}
