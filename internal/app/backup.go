package app

// backup.go 實作 `evernight-server backup`：產出一份最小一致性備份包，不啟動 HTTP 服務。
//
// 與 migrate 同一形狀（一次性命令、報告走 out、結束碼表達成敗），但刻意不走 openDatabase：
// 那條路會取單寫入實例鎖，而「服務運行中也能備份」正是這條路徑要保住的性質。
// 快照因此走 internal/database 的唯讀快照連線——它不取鎖、不寫源庫；
// 程序級實測證明：服務持有鎖並持續寫入期間，另一行程以這條連線仍取出完整快照，
// 且服務的寫入未被阻擋。

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/backup"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/disk"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// Backup 執行 `evernight-server backup`：把資料庫取成一致性快照，連同組態與內容目錄
// 一起放進一個新的備份包目錄，最後寫一份逐檔清單。不啟動監聽器、不改源庫。
//
// 結束條件只有兩種：備份包發布成功（回傳 nil），或任何事情失敗（回傳錯誤、結束碼非 0）。
// 失敗不留下「看起來像備份」的目錄——半成品只存在於以 . 開頭、.tmp 結尾的臨時目錄，
// 而它在任何結束路徑都被清掉。
func Backup(ctx context.Context, args []string, out io.Writer) error {
	// 一次性命令：人類可讀日誌丟棄（與 migrate 同一處置），日誌檔案照寫，
	// 免得同一句話在終端出現兩種格式。
	cfg, lg, err := openConfig(args, io.Discard)
	if err != nil {
		if lg != nil {
			_ = lg.Close()
		}
		return err
	}
	defer func() {
		if closeErr := lg.Close(); closeErr != nil {
			fmt.Fprintf(out, "關閉日誌失敗：%v\n", closeErr)
		}
	}()
	lg.Info("備份子命令開始", "version", Version, "data_dir", cfg.Server.DataDir, "backups", cfg.Backups)

	fmt.Fprintf(out, "evernight-server %s\n", Version)
	res, err := runBackup(ctx, cfg, lg.Logger)
	if err != nil {
		lg.Error("備份失敗", "err", err, "backups", cfg.Backups)
		return err
	}

	fmt.Fprintf(out, "備份包：%s\n", res.Dir)
	fmt.Fprintf(out, "資料庫快照：%s（schema=%d，integrity=%s，journal=%s，application_id=%s，檔頭 user_version=%d）\n",
		filepath.Join(res.Dir, backup.DatabaseRel), res.Manifest.Database.SchemaVersion,
		res.Manifest.Database.Integrity, res.Manifest.Database.JournalMode,
		res.Manifest.Database.ApplicationID, res.Manifest.Database.HeaderSchemaVersion)
	fmt.Fprintf(out, "收錄：%d 個檔案、%s；另有清單 %s（%s）\n",
		res.Manifest.Totals.Files, disk.HumanBytes(uint64(res.Manifest.Totals.Bytes)),
		backup.ManifestName, disk.HumanBytes(uint64(res.ManifestBytes)))
	fmt.Fprint(out, tableCountsNote(res.Manifest))
	fmt.Fprint(out, backupDiskNote(cfg, res.Manifest.Disk))
	fmt.Fprint(out, schemaNoticeNote(res.Manifest))
	fmt.Fprint(out, staleStagingNote(res.StaleStaging))
	fmt.Fprintln(out, "敏感性提示：本備份包含組態檔原值（Argon2id 口令摘要與任何密鑰材料都在內），"+
		"刻意不脫敏——遮罩過的值恢復出來是壞的。請按敏感檔對待它：存放位置、搬運方式與日後刪除都要當回事。")
	fmt.Fprintln(out, "還原入口尚未提供（下一步）；本命令只產出備份包，不會動到現有資料目錄的任何檔案。")
	lg.Info("備份完成", "dir", res.Dir, "files", res.Manifest.Totals.Files,
		"bytes", res.Manifest.Totals.Bytes, "schema_version", res.Manifest.Database.SchemaVersion,
		"created_at", res.Manifest.CreatedAt)
	return nil
}

// runBackup 把組態翻成 backup.Options 並執行。
//
// 三個注入點各自來自既有唯一的實作：快照與快照檢查是存儲層（驅動只在那一層出現）、
// 空間判定是 internal/disk 的監測器（DEC-033 要求備份復用它，而不是另寫一套讀盤邏輯）。
func runBackup(ctx context.Context, cfg config.Config, lg *slog.Logger) (backup.Result, error) {
	// 判定落在備份輸出目錄所在的那個卷：空間不夠寫不出備份的是那個卷，不一定是資料卷。
	space := diskMonitorAt(cfg.Backups, cfg)
	if !space.Enabled() {
		lg.Warn("磁碟寫保護未啟用，備份仍會確認一次該目錄可判定", "path", cfg.Backups)
	}

	snap, err := database.OpenSnapshot(cfg.Database.Path,
		time.Duration(cfg.Database.BusyTimeoutMS)*time.Millisecond)
	if err != nil {
		return backup.Result{}, err
	}
	defer func() {
		if closeErr := snap.Close(); closeErr != nil {
			lg.Error("關閉快照連線失敗", "err", closeErr)
		}
	}()

	// 備份時刻只取一次：目錄名與清單裡的 created_at 必須是同一個值，
	// 否則同一份備份會有兩個時間（跨秒時還會互相不一致）。
	now := timeutil.System().Now().UTC()
	id, err := idgen.New()
	if err != nil {
		// 標識產生失敗就不做備份（DEC-014：不降級成別的格式）。名稱裡那 8 位十六進制
		// 與它同一來源，湊一個「看起來一樣」的替代品只會讓備份包多一種無法判定的命名。
		return backup.Result{}, fmt.Errorf("app: 產生備份包名稱失敗: %w", err)
	}
	busy := time.Duration(cfg.Database.BusyTimeoutMS) * time.Millisecond

	return backup.Create(ctx, backup.Options{
		OutDir:             cfg.Backups,
		Name:               bundleName(now, id),
		SourceDataDir:      cfg.Server.DataDir,
		SourceDatabasePath: cfg.Database.Path,
		ConfigPath:         cfg.ConfigFile(),
		ContentDirs: []backup.ContentDir{
			{Kind: backup.KindMedia, Path: cfg.Media},
			{Kind: backup.KindDocuments, Path: cfg.Documents},
			{Kind: backup.KindAttachments, Path: cfg.Attachments},
		},
		Snapshot: func(ctx context.Context, target string) error {
			return database.Snapshot(ctx, snap, target)
		},
		Inspect: func(ctx context.Context, path string) (database.SnapshotInfo, error) {
			return database.InspectSnapshot(ctx, path, busy)
		},
		Disk:          func() (disk.Verdict, error) { return space.Verify() },
		ServerVersion: Version,
		Now:           now,
	})
}

// bundleName 產生備份包目錄名：<UTC 緊湊時間>-<標識末 8 位十六進制>。
//
// 時間戳讓目錄「按名字排序就是按產生順序」，後綴讓同一秒跑兩次不會撞名。
// 後綴取標識的尾端而不是開頭：UUIDv7 的開頭是毫秒時間戳（DEC-014 的可排序設計），
// 拿它當「隨機後綴」等於把同一秒的兩次備份拿到同一個名字——這條是單元測試實跑抓到的，
// 不是推想。撞名的後果不是覆蓋（同名一律拒絕）而是一次無謂的失敗，所以仍要修。
func bundleName(now time.Time, id idgen.ID) string {
	hex := strings.ReplaceAll(id.String(), "-", "")
	if len(hex) > 8 {
		hex = hex[len(hex)-8:]
	}
	return now.UTC().Format("20060102T150405Z") + "-" + hex
}

// tableCountsNote 把快照內各表列數排成一行，讓運維當場就能看出備到的是不是現況。
func tableCountsNote(manifest backup.Manifest) string {
	if len(manifest.Database.Tables) == 0 {
		return "資料庫表列數：（快照內沒有任何資料表）\n"
	}
	parts := make([]string, 0, len(manifest.Database.Tables))
	for _, t := range manifest.Database.Tables {
		parts = append(parts, fmt.Sprintf("%s=%d", t.Table, t.Rows))
	}
	return "資料庫表列數：" + strings.Join(parts, "、") + "\n"
}

// backupDiskNote 說明這次備份判的是哪個卷、看到了什麼。
//
// 監測未啟用時要說清楚：清單裡那份 free=0／total=0 不含任何探測事實，
// 不寫這一行，讀的人會以為備份檢查過一個 0 容量的卷（與 DEC-033 的啟動摘要同一顧慮）。
func backupDiskNote(cfg config.Config, fact backup.DiskFact) string {
	if cfg.Disk.MinFreeBytes <= 0 && cfg.Disk.MinFreePercent <= 0 {
		return fmt.Sprintf("磁碟判定：%s（未設 disk 下限，因此沒有閾值可判，"+
			"但空間不足時寫入仍會以錯誤中止而不是悄悄寫壞）\n", fact.Path)
	}
	return fmt.Sprintf("磁碟判定：%s 剩餘 %s／總 %s（下限：剩餘低於 %s 或 %g%% 任一命中即拒絕備份）\n",
		fact.Path, disk.HumanBytes(fact.FreeBytes), disk.HumanBytes(fact.TotalBytes),
		disk.HumanBytes(uint64(cfg.Disk.MinFreeBytes)), cfg.Disk.MinFreePercent)
}

// staleStagingNote 回報輸出目錄裡既存的中斷殘留。
//
// 這些目錄只可能是上一次異常結束（例如被強制打掉）留下的半成品。本命令刻意不刪它們：
// 並行的另一次備份可能正在其中寫東西，刪掉等於弄壞別人的動作；但也不能假裝看不見——
// 默默佔著磁碟的垃圾沒有人會去清。
func staleStagingNote(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return fmt.Sprintf("提示：備份目錄有 %d 個未完成的臨時目錄（上一次備份被中斷留下的半成品，\n"+
		"不會被當成備份，也未佔用本次的名稱）：%s\n"+
		"確認沒有備份正在執行之後可以刪除它們。\n", len(names), strings.Join(names, "、"))
}

// schemaNoticeNote 在快照的結構版本高於本執行檔已知版本時提示一句。
//
// 不拒絕：快照讀的是資料庫當前狀態，取一份「比執行檔新」的庫仍然完整；
// 但這個落差必須看得見——它意味著有別的程式動過這個資料目錄，運維要據此決定要不要先升級。
func schemaNoticeNote(manifest backup.Manifest) string {
	known, err := migrate.MaxVersion()
	if err != nil {
		// 已知版本推導失敗屬執行檔自身問題，不值得讓一次已成功的備份改口報錯；如實寫出即可。
		return fmt.Sprintf("提示：無法取得本執行檔已知的結構版本（%v）\n", err)
	}
	if manifest.Database.SchemaVersion <= known {
		return ""
	}
	return fmt.Sprintf("提示：快照的結構版本 %d 高於本執行檔已知的 %d——備份本身完整，"+
		"但請確認日後要用哪個程式版本恢復它。\n", manifest.Database.SchemaVersion, known)
}
