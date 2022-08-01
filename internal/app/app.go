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

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/httpapi"
	"github.com/kagurazakayashi/EvernightRealm/internal/runlog"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
	"github.com/kagurazakayashi/EvernightRealm/internal/webassets"
)

// Version 為目前開發版本。正式版號策略待發布流程定案後統一管理。
const Version = "0.1.0-dev"

// Run 啟動服務端，阻塞至收到停止信號（Ctrl+C、SIGTERM）或發生錯誤。
//
// 第一個參數為 `migrate` 時改執行遷移子命令（見 Migrate），不啟動 HTTP 服務。
//
// ctx 為服務的根 context，訊號取消即代表停止請求；日後的背景任務
// （保留期清理、備份排程等）皆須以此 ctx 為取消來源並在返回前結束，
// 確保程序退出時不留殘留工作。正常停止回傳 nil，結束碼為 0。
func Run(args []string) error {
	ctx, releaseSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer releaseSignals()
	if len(args) > 0 && args[0] == "migrate" {
		return Migrate(ctx, args[1:], os.Stdout)
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
	cfg, lg, db, err := prepare(ctx, rest, io.Discard)
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
	const apiNote = "/health 存活、/ready 就緒、/time 伺服器時間"
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
func prepare(ctx context.Context, args []string, logStderr io.Writer) (config.Config, *runlog.Logger, *database.DB, error) {
	cfg, lg, err := openConfig(args, logStderr)
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	db, err := openDatabase(ctx, cfg, lg)
	if err != nil {
		return config.Config{}, lg, nil, err
	}
	return cfg, lg, db, nil
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
func openDatabase(ctx context.Context, cfg config.Config, lg *runlog.Logger) (*database.DB, error) {
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
	db, err := database.Open(ctx, database.Options{
		Path:               cfg.Database.Path,
		BusyTimeout:        time.Duration(cfg.Database.BusyTimeoutMS) * time.Millisecond,
		KnownSchemaVersion: knownVersion,
		Preflight:          preflight,
		TxPolicy:           policy,
	})
	if err != nil {
		lg.Error("資料庫開啟失敗", "path", cfg.Database.Path, "err", err)
		return nil, err
	}
	return db, nil
}

// txPolicy 依組態建立交易策略（STEP-041）。
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
	cfg, lg, db, err := prepare(ctx, args, logStderr)
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
	srv := httpapi.New(&cfg, Version, httpapi.Deps{
		Ready:    db.Ping,
		Clock:    timeutil.System(),
		Web:      webFS,
		Log:      lg.Logger,
		ErrorLog: lg.ErrorLogWriter(slog.LevelError),
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
