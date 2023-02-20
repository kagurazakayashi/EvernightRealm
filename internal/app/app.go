// Package app 提供服務端啟動入口與版本資訊（最小骨架）。
//
// 啟動函式與 main 分離：main 僅負責組裝與結束碼轉換，
// 實際啟動流程、錯誤處理與日後各模組的組合皆以本包為核心。
package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctreview"
	"github.com/kagurazakayashi/EvernightRealm/internal/adminacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/disk"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/httpapi"
	"github.com/kagurazakayashi/EvernightRealm/internal/invitecode"
	"github.com/kagurazakayashi/EvernightRealm/internal/runlog"
	"github.com/kagurazakayashi/EvernightRealm/internal/selfregister"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/stdacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
	"github.com/kagurazakayashi/EvernightRealm/internal/webassets"
)

// Version 為目前開發版本。正式版號策略待發布流程定案後統一管理。
const Version = "0.1.0-dev"

// Run 啟動服務端，阻塞至收到停止信號（Ctrl+C、SIGTERM）或發生錯誤。
//
// 第一個參數為 `migrate` 時改執行遷移子命令（見 Migrate），為 `backup` 時改執行備份子命令
// （見 Backup），為 `restore` 時改執行恢復子命令（見 Restore），
// 為 `init-root` 時改執行 Root 一次性初始化（見 InitRoot），
// 為 `recover-root` 時改執行 Root 憑據的本機恢復（見 RecoverRoot），
// 為 `root-status` 時只讀地回報 Root 是否已初始化（見 RootStatus）；
// 它們都不啟動 HTTP 服務，也不佔用連接埠。
//
// ctx 為服務的根 context，訊號取消即代表停止請求；日後的背景任務
// （保留期清理、備份排程等）皆須以此 ctx 為取消來源並在返回前結束，
// 確保程序退出時不留殘留工作。正常停止回傳 nil，結束碼為 0。
func Run(args []string) error {
	ctx, releaseSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer releaseSignals()
	if len(args) > 0 {
		switch args[0] {
		case "migrate":
			return Migrate(ctx, args[1:], os.Stdout)
		case "backup":
			return Backup(ctx, args[1:], os.Stdout)
		case "restore":
			return Restore(ctx, args[1:], os.Stdout)
		case "init-root":
			return InitRoot(ctx, args[1:], os.Stdin, os.Stdout)
		case "recover-root":
			return RecoverRoot(ctx, args[1:], os.Stdin, os.Stdout)
		case "root-status":
			return RootStatus(ctx, args[1:], os.Stdout)
		}
	}
	return run(ctx, releaseSignals, args, os.Stdout, os.Stderr)
}

// Migrate 執行 `evernight-server migrate`：套用未套用的資料庫遷移後結束，不啟動 HTTP 服務。
//
// 供運維在備份後先完成遷移再啟動服務（規格附錄 E.5：遷移必須在備份後執行）。
// 執行期間同樣持有單寫入實例鎖，因此服務運行中無法執行；
// 加上 --dry-run 只檢查目前版本與待套用清單，不變更資料庫。
// 遷移失敗回傳錯誤（結束碼非 0），失敗的那一支已整體回滾，資料庫維持原版本。
func Migrate(ctx context.Context, args []string, out io.Writer) error {
	dryRun, verify, rest := parseMigrateArgs(args)
	// migrate 是一次性命令：報告走 out、結束碼表達成敗，人類可讀日誌因此丟棄，
	// 免得終端同時出現兩種格式的同一句話。日誌檔案仍照常記錄（含失敗原因）。
	cfg, lg, db, space, err := prepare(ctx, rest, io.Discard)
	if err != nil {
		if lg != nil {
			_ = lg.Close()
		}
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			fmt.Fprintf(out, "關閉資料庫失敗：%v\n", err)
		} else {
			fmt.Fprintln(out, "資料庫已關閉，單寫入實例鎖已釋放。")
		}
		if err := lg.Close(); err != nil {
			fmt.Fprintf(out, "關閉日誌失敗：%v\n", err)
		}
	}()
	lg.Info("遷移子命令開始", "dry_run", dryRun, "verify", verify)

	fmt.Fprintf(out, "evernight-server %s\n", Version)
	// --verify 為自檢模式：只做完整性與版本檢查，不套用任何遷移（等同 --dry-run 再加完整性自檢）。
	if verify {
		if err := db.CheckIntegrity(ctx); err != nil {
			lg.Error("資料庫自檢失敗", "path", cfg.Database.Path, "err", err)
			return err
		}
		fmt.Fprintln(out, "資料庫自檢：integrity_check=ok，foreign_key_check=無違規")
		dryRun = true
	}
	// 只有會真的改結構時才問磁碟：--dry-run 與 --verify 不落盤，
	// 讓它們在空間不足時仍能報告版本，才是排錯時想要的那個行為。
	if !dryRun {
		if err := checkSpaceBeforeWrite(space, lg.Logger); err != nil {
			return err
		}
	}
	res, err := migrate.Apply(ctx, db.SQL(), migrate.Options{DryRun: dryRun, Clock: timeutil.System()})
	if err != nil {
		lg.Error("資料庫遷移失敗", "err", err, "dry_run", dryRun)
		return err
	}

	if dryRun {
		lg.Info("資料庫版本檢查完成（未變更資料）", "version", res.FromVersion, "pending", len(res.Pending))
		fmt.Fprintf(out, "資料庫版本檢查（不變更資料）：目前 version=%d，待套用 %d 項\n", res.FromVersion, len(res.Pending))
		for _, m := range res.Pending {
			fmt.Fprintf(out, "  - %s\n", m)
		}
		return nil
	}

	if err := stampApplicationID(ctx, db); err != nil {
		lg.Error("寫入資料庫識別標記失敗", "err", err)
		return err
	}
	lg.Info("資料庫遷移完成", "from_version", res.FromVersion, "to_version", res.ToVersion, "applied", len(res.Applied))
	fmt.Fprintln(out, migrationSummary(res))
	for _, m := range res.Applied {
		fmt.Fprintf(out, "  - %s\n", m)
	}
	return nil
}

// diskMonitor 依組態建立磁碟空間監測器，判定依據是資料目錄所在的卷。
//
// 兩個下限全為 0 時，Monitor.Verify 一律回 StatusOK 且**不發任何系統呼叫**，
// 因此「沒啟用」的代價是一條比較分支，不是每筆寫入多一次磁碟查詢。
func diskMonitor(cfg config.Config) *disk.Monitor {
	return diskMonitorAt(cfg.Server.DataDir, cfg)
}

// diskMonitorAt 以同一組閾值建立針對特定目錄所在卷的監測器。
//
// 存在的理由只有一個：備份包寫到哪個卷是由 backups 決定的，而預設值以外的寫法（含環境變數
// ER_BACKUPS 指到別顆盤）很常見——拿資料卷的剩餘空間去判定備份卷會不會寫得下，判定是錯的。
func diskMonitorAt(path string, cfg config.Config) *disk.Monitor {
	return disk.New(path, disk.Thresholds{
		MinFreeBytes:   uint64(maxInt64(cfg.Disk.MinFreeBytes, 0)),
		MinFreePercent: cfg.Disk.MinFreePercent,
	}, time.Duration(cfg.Disk.CheckIntervalMS)*time.Millisecond, timeutil.System())
}

// maxInt64 把負數夾成 0：config.Validate 已拒絕負值下限，這裡只是讓 uint64 轉換
// 不會在繞過校驗的測試路徑上把 -1 變成 18446744073709551615（那會讓服務永久拒寫）。
func maxInt64(v int64, floor int64) int64 {
	if v < floor {
		return floor
	}
	return v
}

// readinessCheck 把「依賴可用否」的判據組合起來交給傳輸層。
//
// 順序是資料庫先、磁碟後：資料庫問了就有答案，磁碟判定自帶快取；而 Ping 失敗時
// 已足以判定不就緒，不必再多問一次。
//
// 兩種失敗回不同的碼：空間不足要用 1008（重試不會讓它自己變好，得有人去清盤），
// 其餘情況沿用 1007。「查不出來」（StatusUnknown）刻意回 1007 而不是放行——
// /ready 回答的是「我能不能確認一切正常」，確認不了就說確認不了，這比假裝正常誠實；
// 但它不影響寫入（寫入門只認 StatusLow），所以不會因為一次探測失敗就把服務弄停。
func readinessCheck(db *database.DB, space *disk.Monitor) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := db.Ping(ctx); err != nil {
			return err
		}
		verdict, err := space.Verify()
		if err != nil {
			return err
		}
		switch verdict.Status {
		case disk.StatusLow:
			return &httpapi.UnreadyError{Code: httpapi.CodeNoSpace,
				Err: fmt.Errorf("%w：%s", disk.ErrNoSpace, verdict.Reason)}
		case disk.StatusUnknown:
			return fmt.Errorf("就緒檢查無法判定磁碟狀態：%s", verdict.Reason)
		default:
			return nil
		}
	}
}

// diskNote 產生啟動摘要裡關於磁碟寫保護的一行。
//
// 未啟用時必須說得出來：下限預設為 0，如果摘要不寫，部署者會以為內建就有保護。
// 這與日誌保留天數的處理同一取向（DEC-028）。
func diskNote(cfg config.Config) string {
	effective := make([]string, 0, 2)
	if cfg.Disk.MinFreeBytes > 0 {
		effective = append(effective, "剩餘低於 "+disk.HumanBytes(uint64(cfg.Disk.MinFreeBytes)))
	}
	if cfg.Disk.MinFreePercent > 0 {
		effective = append(effective, fmt.Sprintf("剩餘比例低於 %g%%", cfg.Disk.MinFreePercent))
	}
	if len(effective) == 0 {
		return "磁碟寫保護：未啟用（disk.min_free_bytes 與 min_free_percent 皆為 0）"
	}
	// 只列實際生效的那幾條：把 0 也印出來會被讀成「設了一個 0% 的下限」，
	// 而 0 在這裡的意思是「這條沒開」。
	return fmt.Sprintf("磁碟寫保護：資料目錄 %s，%s（任一命中即暫停新的寫入）",
		cfg.Server.DataDir, strings.Join(effective, " 或 "))
}

// checkSpaceBeforeWrite 在任何會落盤的寫入開始之前問一次磁碟（啟動期的遷移、
// 一次性命令的憑據覆寫都走這一道）。
//
// 空間不足時回錯誤讓流程中止：遷移會改結構並寫 WAL，憑據恢復則要寫一筆「撤銷＋審計」
// 的資料庫交易，兩者都是典型的「不完整就更糟」的寫入，而在還沒動任何東西之前停下，
// 用戶端就不會拿到一個「已確認但未持久化」的結果。
func checkSpaceBeforeWrite(space *disk.Monitor, lg *slog.Logger) error {
	verdict, err := space.Verify()
	if err != nil {
		return err
	}
	// 只在真的做過探測時留痕：未啟用時那份 StatusOK 不含任何事實，
	// 記成「status=ok free=0 total=0」會讓人以為讀到過一個零容量的卷。
	if space.Enabled() {
		lg.Info("磁碟空間檢查", "status", verdict.Status.String(), "path", verdict.Usage.Path,
			"free", verdict.Usage.Free, "total", verdict.Usage.Total)
	}
	if verdict.Status == disk.StatusLow {
		lg.Error("磁碟空間不足，拒絕開始本次寫入", "reason", verdict.Reason)
		return fmt.Errorf("%w：%s", disk.ErrNoSpace, verdict.Reason)
	}
	return nil
}

// stampApplicationID 在遷移成功後於檔頭寫入本服務識別碼（已標記時不寫）。
//
// 必須在確認資料庫為本服務所有之後執行：對非本服務的資料庫不會留下標記。
func stampApplicationID(ctx context.Context, db *database.DB) error {
	return db.StampApplicationID(ctx)
}

// parseMigrateArgs 取出 migrate 子命令的旗標，其餘參數交回組態解析。
func parseMigrateArgs(args []string) (dryRun bool, verify bool, rest []string) {
	rest = make([]string, 0, len(args))
	for _, arg := range args {
		switch arg {
		case "--dry-run", "-dry-run":
			dryRun = true
		case "--verify", "-verify":
			verify = true
		default:
			rest = append(rest, arg)
		}
	}
	return dryRun, verify, rest
}

// migrationSummary 產生啟動輸出用的遷移摘要（單行，不列出每支名稱）。
func migrationSummary(res migrate.Result) string {
	if len(res.Applied) == 0 {
		return fmt.Sprintf("資料庫遷移：無待套用（version=%d）", res.ToVersion)
	}
	names := make([]string, 0, len(res.Applied))
	for _, m := range res.Applied {
		names = append(names, m.String())
	}
	return fmt.Sprintf("資料庫遷移：已套用 %d 項（version %d → %d：%s）",
		len(res.Applied), res.FromVersion, res.ToVersion, strings.Join(names, "、"))
}

// retentionNote 把保留天數翻成一句人話：不限制要寫成「不限制」而不是 0，
// 否則看到 0 的人會以為日誌一份都不留。
func retentionNote(days int) string {
	if days <= 0 {
		return "不限制（不自動刪除）"
	}
	return fmt.Sprintf("%d 天（含當日）", days)
}

// endpointsNote 產生啟動行括號裡的端點清單。
//
// 只在內嵌產物可用時列舉「/ 網頁介面」：摘要寫了那個位址卻回 404，比不寫更糟——
// 人會先去試它，然後才發現執行檔裡根本沒有前端。
func endpointsNote(status webassets.Status) string {
	const apiNote = "/health 存活、/ready 就緒、/time 伺服器時間、/auth 登入、當前會話與登出"
	if status.Available {
		return "/ 網頁介面、" + apiNote
	}
	return apiNote
}

// prepare 依命令列參數載入組態、規範化路徑、建立資料目錄、開啟日誌與資料庫。
//
// 日誌先於資料庫開啟：資料庫那邊的失敗（預檢拒絕、目錄不可寫、鎖被佔用）
// 必須能在日誌裡查得到，否則最需要先留痕的路徑恰好沒有留痕。
// logStderr 為人類可讀那份日誌的去處（正式路徑給標準錯誤輸出，測試給 io.Discard），
// 日誌檔案那一層由組態的 logs.dir 決定，兩者跟著同一次 Open 一起成立或一起失敗。
// 資料庫開啟即取得單寫入實例鎖；呼叫端負責在結束時關閉連線（釋放鎖）與關閉日誌（釋放檔案）。
// 已知 schema 版本由內嵌遷移推導，用於開庫前預檢的版本比較。
// 回傳的 Logger 在非 nil 時一律由呼叫端負責 Close，即使資料庫開啟失敗也一樣。
func prepare(ctx context.Context, args []string, logStderr io.Writer) (config.Config, *runlog.Logger, *database.DB, *disk.Monitor, error) {
	cfg, lg, err := openConfig(args, logStderr)
	if err != nil {
		return config.Config{}, nil, nil, nil, err
	}
	space := diskMonitor(cfg)
	db, err := openDatabase(ctx, cfg, lg, space)
	if err != nil {
		return config.Config{}, lg, nil, space, err
	}
	return cfg, lg, db, space, nil
}

// openConfig 解析命令列與組態、準備資料目錄並開啟日誌；失敗時日誌可能尚未開啟，
// 回傳的錯誤只能由結束碼與標準錯誤輸出交代。
func openConfig(args []string, logStderr io.Writer) (config.Config, *runlog.Logger, error) {
	opts, err := config.ParseArgs(args)
	if err != nil {
		return config.Config{}, nil, err
	}
	cfg, err := config.Load(opts)
	if err != nil {
		return config.Config{}, nil, err
	}
	if err := cfg.Resolve(); err != nil {
		return config.Config{}, nil, err
	}
	if err := cfg.Prepare(); err != nil {
		return config.Config{}, nil, err
	}
	lg, err := runlog.Open(runlog.Options{
		Dir:           cfg.Logs.Dir,
		FilePrefix:    cfg.Logs.FilePrefix,
		Level:         cfg.Logs.Level,
		RetentionDays: cfg.Logs.RetentionDays,
		// 分檔用的「今天」與 /time 報給客戶端的今天來自同一個來源：顯示時區。
		Location: cfg.DisplayLocation(),
		Stderr:   logStderr,
		Now:      timeutil.System().Now,
	})
	if err != nil {
		return config.Config{}, nil, err
	}
	return cfg, lg, nil
}

// openDatabase 依已解析的組態開啟資料庫連線（含單寫入實例鎖與開庫前預檢）。
//
// 失敗一律記一筆後原樣回傳錯誤：錯誤訊息本身已由 config/database 保證不含機密。
func openDatabase(ctx context.Context, cfg config.Config, lg *runlog.Logger, space *disk.Monitor) (*database.DB, error) {
	knownVersion, err := migrate.MaxVersion()
	if err != nil {
		return nil, err
	}
	preflight, err := database.ParsePreflight(cfg.Database.Preflight)
	if err != nil {
		return nil, err
	}
	policy, err := txPolicy(cfg)
	if err != nil {
		return nil, err
	}

	// 資料庫先於監聽器開啟：單寫入實例鎖、預檢或 WAL 無法生效時直接失敗，不佔用連接埠。
	// 寫入門由監測器給出：空間不足時寫入交易根本不開始（規格 AT-020），
	// 儲存層因此不需要認識磁碟（與傳輸層不認識日誌管線同條邊界）。
	db, err := database.Open(ctx, database.Options{
		Path:               cfg.Database.Path,
		BusyTimeout:        time.Duration(cfg.Database.BusyTimeoutMS) * time.Millisecond,
		KnownSchemaVersion: knownVersion,
		Preflight:          preflight,
		TxPolicy:           policy,
		WriteGuard:         space.Guard(),
	})
	if err != nil {
		lg.Error("資料庫開啟失敗", "path", cfg.Database.Path, "err", err)
		return nil, err
	}
	return db, nil
}

// txPolicy 依組態建立交易策略。
//
// 組態值已在 config.Validate 限定為合法枚舉，這裡的解析錯誤屬防禦性檢查
// （兩處清單漂移時立即在啟動階段暴露，而不是默默採用預設值）。
func txPolicy(cfg config.Config) (database.TxPolicy, error) {
	beginMode, err := database.ParseBeginMode(cfg.Database.Transaction.BeginMode)
	if err != nil {
		return database.TxPolicy{}, fmt.Errorf("config: database.transaction.begin_mode: %w", err)
	}
	nested, err := database.ParseNestedPolicy(cfg.Database.Transaction.Nested)
	if err != nil {
		return database.TxPolicy{}, fmt.Errorf("config: database.transaction.nested: %w", err)
	}
	return database.TxPolicy{
		BeginMode:        beginMode,
		Nested:           nested,
		BusyRetryMax:     cfg.Database.Transaction.BusyRetryMax,
		BusyRetryBackoff: time.Duration(cfg.Database.Transaction.BusyRetryBackoffMS) * time.Millisecond,
		Timeout:          time.Duration(cfg.Database.Transaction.TimeoutMS) * time.Millisecond,
		GuardSchema:      cfg.Database.SchemaGuard == "transaction",
	}, nil
}

// run 為 Run 的可測試主體：ctx 取消即觸發優雅停止（正式路徑由訊號觸發）。
//
// releaseSignals 於停止流程開始時呼叫，用以還原預設訊號處理，
// 使停止期間再次按 Ctrl+C 可立即中止，不必等完優雅停止期限。
// 流程：解析命令列 → 載入並校驗組態 → 路徑規範化 → 資料目錄初始化 → 日誌開啟
// → 資料庫連線（單寫入實例鎖 + 開庫前預檢）→ 資料庫遷移（含檔頭標記）
// → 監聽 → 輸出脫敏摘要與監聽提示 → 服務至停止請求 → 優雅停止 → 關閉資料庫並釋放鎖、關閉日誌。
// 組態非法、目錄不可用或資料庫無法開啟時回傳錯誤（含欄位路徑，不含機密），
// 由 main 決定結束碼；已開啟的日誌在任何結束路徑都會關閉。
// out 為啟動/停止摘要的去處，logStderr 為人類可讀日誌的去處（正式路徑兩者皆標準輸出串，
// 但分別是 stdout 與 stderr；測試把後者給 io.Discard 以保持輸出乾淨）。
func run(ctx context.Context, releaseSignals func(), args []string, out io.Writer, logStderr io.Writer) error {
	cfg, lg, db, space, err := prepare(ctx, args, logStderr)
	if err != nil {
		if lg != nil {
			_ = lg.Close()
		}
		return err
	}
	// defer 確保任何結束路徑都會釋放連線池、鎖與日誌檔案。
	defer func() {
		if err := db.Close(); err != nil {
			fmt.Fprintf(out, "關閉資料庫失敗：%v\n", err)
		} else {
			fmt.Fprintln(out, "資料庫已關閉，單寫入實例鎖已釋放。")
		}
		if err := lg.Close(); err != nil {
			fmt.Fprintf(out, "關閉日誌失敗：%v\n", err)
		}
	}()
	lg.Info("服務啟動", "version", Version, "listen", cfg.Server.Listen, "data_dir", cfg.Server.DataDir)

	// 遷移先於監聽器：遷移失敗即中止啟動，不提供服務，
	// 也不留下半套用的結構（失敗的遷移已整體回滾）。
	if err := checkSpaceBeforeWrite(space, lg.Logger); err != nil {
		return err
	}
	if cfg.Database.IntegrityCheck {
		if err := db.CheckIntegrity(ctx); err != nil {
			lg.Error("資料庫完整性自檢失敗", "path", cfg.Database.Path, "err", err)
			return err
		}
		fmt.Fprintln(out, "資料庫完整性自檢：integrity_check=ok，foreign_key_check=無違規")
	}
	// 遷移記錄的時間戳取自伺服器時鐘；業務時間不得取自請求內容（規格 §27.2）。
	res, err := migrate.Apply(ctx, db.SQL(), migrate.Options{Clock: timeutil.System()})
	if err != nil {
		lg.Error("資料庫遷移失敗", "err", err)
		return err
	}
	if err := stampApplicationID(ctx, db); err != nil {
		lg.Error("寫入資料庫識別標記失敗", "err", err)
		return err
	}

	// 先建立監聽器再輸出啟動資訊：連接埠被佔用等失敗直接回報，
	// 且輸出的是實際監聽地址（監聽埠設為 0 時可見系統指派的埠號）。
	// 就緒與否以資料庫能否回應為準；業務時間一律取自伺服器時鐘。
	// 內嵌的 Web 產物只在判定可用時掛上路徑，不可用時啟動摘要如實寫出缺什麼
	// （判定由 internal/webassets 完成，傳輸層只收到一份檔案系統或 nil）。
	webFS, webStatus := webassets.Dist()
	// 登入用例的組裝：會話期限讀 security.session_ttl_hours（R1-008 預留的裝配點），
	// 各倉儲共用系統時鐘——業務時刻的單一來源在各自構造內注入，這裡只給「此刻」。
	// 失敗一律中斷啟動：缺了會話核心或登入用例的傳輸層只開出一組「連得上但登不進」
	// 的端點，那種半套狀態比啟動失敗更難排查。
	// 裝置登入策略的組裝：模式字串換成領域值（組態層已校驗過列舉，
	// 到這裡還解析不出來只剩「裝配程式碼寫錯」一種可能，一樣中斷啟動不帶病上線）。
	deviceMode, err := session.ParseDeviceMode(cfg.Security.DevicePolicy.Mode)
	if err != nil {
		lg.Error("裝置登入策略組裝失敗", "err", err)
		return err
	}
	sessionPolicy := session.Policy{
		IdleTTL:        time.Duration(cfg.Security.SessionIdleHours) * time.Hour,
		TouchThreshold: time.Duration(cfg.Security.SessionTouchMinutes) * time.Minute,
		CleanupGrace:   time.Duration(cfg.Security.SessionCleanupGraceHours) * time.Hour,
		DeviceMode:     deviceMode,
		MaxDevices:     cfg.Security.DevicePolicy.MaxDevices,
	}
	sessionStore, err := session.NewStoreWithPolicy(timeutil.System(),
		time.Duration(cfg.Security.SessionTTLHours)*time.Hour, sessionPolicy)
	if err != nil {
		lg.Error("會話核心組裝失敗", "err", err)
		return err
	}
	hashingParams, err := cfg.Security.Hashing.Params()
	if err != nil {
		lg.Error("憑據雜湊參數檔不合格", "err", err)
		return err
	}
	// 登入失敗控制與限流：閾值取自 security.login_guard（啟動校驗已過，
	// 這裡的構造失敗只剩「裝配代碼寫錯」一種可能，同樣中斷啟動不帶病上線）。
	loginGuard, err := auth.NewLoginGuard(auth.GuardConfig{
		FailLimit:       cfg.Security.LoginGuard.FailLimit,
		Window:          time.Duration(cfg.Security.LoginGuard.WindowMinutes) * time.Minute,
		Cooldown:        time.Duration(cfg.Security.LoginGuard.CooldownMinutes) * time.Minute,
		SourceFailLimit: cfg.Security.LoginGuard.SourceFailLimit,
		MaxEntries:      cfg.Security.LoginGuard.MaxEntries,
	}, timeutil.System())
	if err != nil {
		lg.Error("登入守衛組裝失敗", "err", err)
		return err
	}
	// 三個倉儲各建立一次、共用一份時鐘：帳戶、授予與審計在登入用例與開設用例之間
	// 必須是同一個實例，否則「同一個欄位有兩份讀法」會隨裝配程式碼的長度慢慢長出來。
	accountsStore := account.NewStore(timeutil.System())
	grantsStore := grant.NewStore(timeutil.System())
	auditStore := audit.NewStore(timeutil.System())
	authService, err := auth.New(auth.Deps{
		DB:               db,
		Sessions:         sessionStore,
		Accounts:         accountsStore,
		Grants:           grantsStore,
		Audits:           auditStore,
		RootPasswordHash: cfg.Security.RootPasswordHash,
		// Root 憑據的正式來源：登入讀它、改密經同一個互斥區覆寫它（見 root_creds.go）。
		RootCreds: newRootCredentialStore(cfg),
		Hashing:   hashingParams,
		Guard:     loginGuard,
		Log:       lg.Logger,
	})
	if err != nil {
		lg.Error("登入用例組裝失敗", "err", err)
		return err
	}
	// 開設管理員用例：依賴與登入用例共用同一批倉儲與同一份參數檔，
	// 這樣「Argon2id 只有一套規則、Root 域審計只有一個出口」在裝配層也成立。
	// 失敗一律中斷啟動：少了它，前端就沒有一個能让 Root 開出第一個管理員的入口，
	// 而「只有 Root 能登入」的狀態不該被一次静默的裝配錯誤当成正常部署。
	adminService, err := adminacct.New(adminacct.Deps{
		DB:       db,
		Accounts: accountsStore,
		Grants:   grantsStore,
		Audits:   auditStore,
		// 停用用例在同一交易裡撤銷目標會話：與登入用例必須是同一個會話倉儲實例，
		// 否則「撤銷落庫的形態」與「驗證讀到的形態」會各長一套。
		Sessions: sessionStore,
		Hashing:  hashingParams,
		Log:      lg.Logger,
	})
	if err != nil {
		lg.Error("開設管理員用例組裝失敗", "err", err)
		return err
	}
	// 帳戶建立策略倉儲與用例：審計倉儲與其餘 Root 域用例同一實例（「Root 域留痕只有一個出口」
	// 在裝配層也成立），倉儲自帶時鐘以確保 updated_at 與審計時刻同源。
	// 少了倉儲，三個建立入口的開關就沒有一個能被設定的地方，而策略只能被寫死在執行檔裡；
	// 同一份倉儲實例也交給建立普通帳戶的用例——「建號前現讀策略」讀的就是這一處，
	// 不各建一份讀法。
	policyStore := acctpolicy.NewStore(timeutil.System())
	policyService, err := acctpolicy.New(acctpolicy.Deps{
		DB:     db,
		Store:  policyStore,
		Audits: auditStore,
		Log:    lg.Logger,
	})
	if err != nil {
		lg.Error("帳戶建立策略用例組裝失敗", "err", err)
		return err
	}
	// 管理員打理普通帳戶用例（建立、目錄、詳情與資料編輯）：帳戶、授予、審計與策略倉儲
	// 都沿用上面的同一批實例，口令派生與 Root 開設管理員共用同一份參數檔。少了它，
	// admin_create_standard 這個開關就只有一份設定而沒有一條通路去執行——策略與現實
	// 開始各說各話；少了目錄與詳情，管理員端就只能建人卻查不到自己建過誰。
	standardAccountService, err := stdacct.New(stdacct.Deps{
		DB:       db,
		Accounts: accountsStore,
		Grants:   grantsStore,
		Policy:   policyStore,
		// 停用普通帳戶時在同一交易裡撤銷目標會話：與登入、Root 開設管理員那條停用
		// 必須是同一個會話倉儲實例，否則「撤銷落庫的形態」與「驗證讀到的形態」各長一套。
		Sessions: sessionStore,
		Audits:   auditStore,
		Hashing:  hashingParams,
		Log:      lg.Logger,
	})
	if err != nil {
		lg.Error("建立普通帳戶用例組裝失敗", "err", err)
		return err
	}
	// 匿名自註冊用例（開放自註冊時門外的人自行建一筆可立即登入的普通帳戶；
	// 核准模式時同一條通路收一份待審批的申請，並讓申請人查本人的狀態）。
	// 頻率守衛是另一個 auth.LoginGuard 實例：與登入守衛分開的記憶體、一組較緊且可組態的閾值
	// （security.register_guard）——自註冊是匿名可達的寫入入口，把它的失敗帳記在登入守衛上
	// 會讓「刷註冊」與「暴力破解登入」共用同一份預算，任一方能餵飽對方把另一條路也擋死。
	// 帳戶、策略與審計倉儲沿用上面同一批實例（「建號現讀的策略只有一份」「Root 域留痕只有
	// 一個出口」在裝配層也成立），口令派生與其餘建號／登入路徑共用同一份參數檔。
	// 少了它，開放自註冊就只是策略上一個能被設成 open 卻沒有一條通路去執行值的開關；
	// 失敗一律中斷啟動，不帶病上線。
	registerGuard, err := auth.NewLoginGuard(auth.GuardConfig{
		FailLimit:       cfg.Security.RegisterGuard.FailLimit,
		Window:          time.Duration(cfg.Security.RegisterGuard.WindowMinutes) * time.Minute,
		Cooldown:        time.Duration(cfg.Security.RegisterGuard.CooldownMinutes) * time.Minute,
		SourceFailLimit: cfg.Security.RegisterGuard.SourceFailLimit,
		MaxEntries:      cfg.Security.RegisterGuard.MaxEntries,
	}, timeutil.System())
	if err != nil {
		lg.Error("自註冊守衛組裝失敗", "err", err)
		return err
	}
	// 邀請碼倉儲：先建這一份，供下面的自註冊用例在 invite 模式的交易內做原子核銷，
	// 也供再下面的管理通路（簽發／名冊／撤銷）復用——兩處必須同源於同一個倉儲與同一份注入時鐘。
	inviteStore := invitecode.NewStore(timeutil.System())
	selfRegisterService, err := selfregister.New(selfregister.Deps{
		DB:       db,
		Accounts: accountsStore,
		Policy:   policyStore,
		// 邀請碼倉儲在 invite 模式的交易內被呼叫一次 Redeem 做原子核銷（見 internal/selfregister）：
		// 與下面簽發／名冊／撤銷那條管理通路共用同一個倉儲實例與同一份注入時鐘，
		// 「一枚碼此刻算不算過期」在两处必须同源。本用例只取倉儲、不取管理用的 Service：
		// 自註冊永不簽碼、永不撤碼、也不回顯任何一枚碼。
		Invites: inviteStore,
		Audits:  auditStore,
		Guard:   registerGuard,
		// 查本人申請狀態用的是登入那一份守衛（同一個實例、同一份記憶體）：
		// 那條通路做的事與登入相同——拿一枚口令對一個名字。給它另立一條分账的預算，
		// 等於讓同一個來源對同一個名字多拿一份猜口令的機會；與上面那條刻意相反，
		// 因為註冊提交不交憑據，它的失敗帳不該記到登入頭上。
		CredentialGuard: loginGuard,
		Hashing:         hashingParams,
		// 同時進入 Argon2id 的註冊數上限：把「併發刷註冊燒 CPU」這條路線的天花板壓住，
		// 閾值取自 security.register_hash_concurrency（啟動校驗已過）。
		HashConcurrency: cfg.Security.RegisterHashConcurrency,
		Log:             lg.Logger,
	})
	if err != nil {
		lg.Error("自註冊用例組裝失敗", "err", err)
		return err
	}
	// 註冊申請的審批用例（待審批名冊＋批准與拒絕那一跳）。
	// 帳戶、授予與審計倉儲沿用上面同一批實例：「批准留下的人是誰」只有 root_audit 一個出口，
	// 「他有沒有被授予過管理權」只有 internal/grant 一個權威，換一份實例就會出現兩套真相。
	// 刻意不注入策略、會話與憑據三個依賴（見 internal/acctreview 的套件頭注）：
	// 審批不問准入策略（模式只管新提交，Root 事後改成 closed 也不該讓等待中的申請消失）、
	// 不動任何會話（待審批的人今日沒有任何會話，他能不能登入由他自己交口令那條既有通路決定）、
	// 也不碰任何一枚口令。少了這個用例，approval 模式就只是策略上一個收得進申請
	// 卻沒有一條通路能把決定做出來的值——申請會永久掛在中間。
	registrationReviewService, err := acctreview.New(acctreview.Deps{
		DB:       db,
		Accounts: accountsStore,
		Grants:   grantsStore,
		Audits:   auditStore,
		Log:      lg.Logger,
	})
	if err != nil {
		lg.Error("審批註冊申請用例組裝失敗", "err", err)
		return err
	}
	// 伺服器級註冊邀請碼管理用例（簽發＋名冊＋撤銷）。倉儲實例 inviteStore 已在上面的自註冊
	// 用例之前建立（invite 模式的核銷要復用它），這裡只把管理通路包成 Service 並沿用同一個實例：
	// 「一枚碼簽發於何時」與「名冊讀到它此刻算不算過期」與「核銷判定這一刻能不能佔用額度」
	// 必須同源於同一份注入時鐘與同一個倉儲，否則三處各讀各的會把到期判定讀漂移。
	// 審計倉儲沿用上面同一批實例（「Root 域留痕只有一個出口」在裝配層也成立）。
	// 刻意不注入策略、會話與憑據三個依賴（見 internal/invitecode 的套件頭注）：簽發一枚准入憑證
	// 不等於把自註冊模式切成 invite（那是 Root 在策略端點上單獨做的另一條決定，本步不借道開放）、
	// 邀請碼換不出任何會話、也不碰任何一枚口令。少了這個用例，invite 就仍是策略上一個谁也签不出码的空名。
	inviteCodeService, err := invitecode.New(invitecode.Deps{
		DB:     db,
		Store:  inviteStore,
		Clock:  timeutil.System(),
		Audits: auditStore,
		Log:    lg.Logger,
	})
	if err != nil {
		lg.Error("伺服器級註冊邀請碼用例組裝失敗", "err", err)
		return err
	}
	srv := httpapi.New(&cfg, Version, httpapi.Deps{
		Ready:    readinessCheck(db, space),
		Clock:    timeutil.System(),
		Web:      webFS,
		Log:      lg.Logger,
		ErrorLog: lg.ErrorLogWriter(slog.LevelError),
		Auth:     authService,
		Admins:   adminService,
		// 帳戶建立策略：Root 讀寫入口與登入前的兩個對外布林都由這一份用例給出，
		// 「策略值不等於能力」的合成只在 internal/acctpolicy 算一次。
		AccountPolicy: policyService,
		// 管理員建立普通帳戶：策略現讀與放行合成由 internal/stdacct 在自己的交易裡做，
		// 傳輸層只負責把受信主體與三個欄位遞進去。
		StandardAccounts: standardAccountService,
		// 匿名自註冊：准入（策略現讀＋模式校驗）、頻率封頂與派生併發封頂都由
		// internal/selfregister 在自己的交易裡做，傳輸層只把三個欄位與實際連線來源遞進去。
		SelfRegister: selfRegisterService,
		// 註冊申請的審批：授權邊界（NeedServerAdmin）、目標此刻的形態核實與那一跳決定
		// 都由 internal/acctreview 在自己的交易裡做，傳輸層只把受信主體、標識與一個決定值遞進去。
		RegistrationReview: registrationReviewService,
		// 伺服器級註冊邀請碼管理：授權邊界（NeedRoot）、明文與驗證材料的分工與那一躍撤銷的落庫
		// 都由 internal/invitecode 在自己的交易裡做，傳輸層只把受信主體、一個簽發輸入或一枚標識遞進去。
		InviteCodes: inviteCodeService,
		// Root 初始化狀態的只讀來源：只查組態檔本身，不開任何寫入通路
		// （初始化仍然只有 evernight-server init-root 這一條路）。
		InitStatus: initStatusSource(cfg),
	})
	ln, err := srv.Listen()
	if err != nil {
		lg.Error("建立監聽器失敗", "listen", cfg.Server.Listen, "err", err)
		return err
	}

	fmt.Fprintf(out, "evernight-server %s\n", Version)
	fmt.Fprintln(out, cfg.Redacted())
	fmt.Fprintf(out, "運行日誌：%s（層級=%s，按 %s 的自然日分檔，保留=%s；人類可讀一份同時寫入標準錯誤輸出）\n",
		lg.Path(), cfg.Logs.Level, cfg.Server.DisplayTimezone, retentionNote(cfg.Logs.RetentionDays))
	fmt.Fprintln(out, diskNote(cfg))
	if note := db.PreflightNote(); note != "" {
		fmt.Fprintf(out, "資料庫預檢提示：%s\n", note)
	}
	fmt.Fprintf(out, "資料庫已就緒：%s（journal_mode=%s，已取得單寫入實例鎖）\n", db.Path(), db.JournalMode())
	fmt.Fprintf(out, "資料庫交易策略：%s\n", db.TxPolicy())
	fmt.Fprintln(out, migrationSummary(res))
	if db.TxPolicy().GuardSchema {
		fmt.Fprintln(out, "資料庫寫入把關：schema_guard=transaction，每個寫入交易在回呼執行前複驗 schema 版本，不符即拒絕該交易。")
	}
	if cfg.ListenAllInterfaces() {
		fmt.Fprintln(out, "風險提示：監聽地址暴露於所有介面（含公網網卡），請確認防火牆與部署範圍。")
	}
	if note := cfg.CORSNotice(); note != "" {
		fmt.Fprintf(out, "跨域提示：%s\n", note)
	}
	fmt.Fprintf(out, "Web 介面：%s\n", webStatus.Summary())
	fmt.Fprintf(out, "HTTP 服務已啟動：http://%s （%s）\n", ln.Addr(), endpointsNote(webStatus))
	lg.Info("HTTP 服務已啟動",
		"listen", ln.Addr().String(),
		"web_bundle", webStatus.Summary(),
		"database", db.Path(),
		"schema_version", res.ToVersion,
		"cors_origins", strings.Join(cfg.Security.CORS.AllowedOrigins, "|"))

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	// 失效會話的清理任務：以本函式專用的可取消 context 為停止來源，因此無論是
	// 收到停止訊號、還是服務自行結束（監聽器失效），都會先取消它再等它收尾，
	// 不會出現「主流程已要返回、背景任務還在等永遠不來的取消」那種死等。
	// 註冊在資料庫關閉之前（defers 反序執行），保證不會有人在連線關閉後還在寫。
	// 週期為 0 表示部署者明確關掉了這個任務——那時完全不起 goroutine，
	// 而不是起一個什麼都不做的背景迴圈。
	if cfg.Security.SessionCleanupMinutes > 0 {
		cleanupCtx, cancelCleanup := context.WithCancel(ctx)
		cleanupDone := make(chan struct{})
		cleanupInterval := time.Duration(cfg.Security.SessionCleanupMinutes) * time.Minute
		go func() {
			defer close(cleanupDone)
			runSessionCleanup(cleanupCtx, sessionStore, db, cleanupInterval, lg.Logger)
		}()
		defer func() {
			cancelCleanup()
			<-cleanupDone
			lg.Info("失效會話清理任務已結束")
		}()
		fmt.Fprintf(out, "失效會話清理：每 %s 一回合，失效後保留 %s 再物理刪除（只動會話記錄，審計一律保留）\n",
			cleanupInterval, time.Duration(cfg.Security.SessionCleanupGraceHours)*time.Hour)
	} else {
		fmt.Fprintln(out, "失效會話清理：已停用（security.session_cleanup_minutes=0），失效憑據仍在請求入口被拒，但記錄不會自動移除。")
	}

	select {
	case err := <-serveErr:
		// 服務在收到停止請求前自行結束（如監聽器失效）：無優雅停止流程可跑。
		lg.Error("服務異常終止", "err", err)
		return err
	case <-ctx.Done():
	}

	// 停止流程：停止接受新連線、等待進行中的請求完成（上限為 shutdown_timeout_ms）；
	// 逾時則強制關閉連線，確保程序結束並釋放監聽資源。
	releaseSignals()
	timeout := srv.ShutdownTimeout()
	lg.Info("收到停止信號，開始優雅停止", "timeout", timeout.String())
	fmt.Fprintf(out, "收到停止信號，開始優雅停止（最長等待 %s）\n", timeout)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		lg.Warn("優雅停止逾時，改以強制關閉連線", "err", err)
		fmt.Fprintf(out, "優雅停止逾時（%v），強制關閉連線\n", err)
		if closeErr := srv.Close(); closeErr != nil {
			lg.Error("強制關閉服務失敗", "err", closeErr)
			return fmt.Errorf("app: 強制關閉服務失敗: %w", closeErr)
		}
	}
	if err := <-serveErr; err != nil {
		lg.Error("服務異常終止", "err", err)
		return err
	}
	lg.Info("服務已停止，監聽資源已釋放")
	fmt.Fprintln(out, "服務已停止，監聽資源已釋放。")
	return nil
}
