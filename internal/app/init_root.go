package app

// init_root.go 實作 `evernight-server init-root` 與 `evernight-server root-status`：
// Root 憑據的一次性初始化，與它的只讀狀態查詢。
//
// 為什麼只有本機命令這一個入口：初始化要交出的東西是「這台伺服器的最高權限」。
// 能在伺服器主機上執行命令，就是這個動作需要的授權；把它改成任何 HTTP 形態，
// 授權依據都會變成「誰先連上線」——而那時候連 CORS、客戶端自報的來源地址、
// 網頁上有沒有這個按鈕都不構成把關。本步因此不新增端點，也不新增監聽。
//
// 三道把關各自擋的是不一樣的東西，少一道都會留下可被誤用的窗口：
//   - 單寫入實例鎖（經 database.Open 取得）：服務運行中一律拒絕初始化。
//     這不只是謹慎，而是事實——啟動時讀進記憶體的組態不會被這次的改動回頭更新，
//     「回報成功了，但還在跑的舊程序不認得它」比拒絕一次命令難查得多；
//   - 環境變數覆蓋檢查（config.RootPasswordHashEnvKey）：那一欄在執行期蓋在檔案之上，
//     這時寫進檔案只會做出兩份 Root，而生效的是看不見的那一份；
//   - root_audit 必須已存在：先確認留得下痕跡，再動組態檔。順序反過來的話，
//     「初始化成功卻查無此事」就成了可能的狀態。
//
// 口令的途徑也只有管道：不讀命令列參數（argv 會被程序清單與 shell 歷史記錄下來），
// 不採「未提供就產生一個隨機口令並印出來」那種做法——那等於把 Root 口令交給自己之外的
// 任何看得見終端的人，而那個值之後再也查不回來。

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/rootinit"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// ErrRootSecretMismatch 表示兩次讀到的口令不一致，寫入在此之前沒有發生。
var ErrRootSecretMismatch = errors.New("app: 兩次輸入的 Root 口令不一致，未改動任何檔案")

// ErrServerStillLocked 表示資料庫的單寫入實例鎖已被佔用（服務正在運行）。
//
// 它存在的目的不是文案好讀，而是讓呼叫端能把「先把服務停下來」這句話只講一次：
// database 那邊的訊息已經點出鎖檔與持有者，這一層只補一句操作者用得上的結論。
var ErrServerStillLocked = errors.New("app: 資料目錄已被執行中的服務鎖定，Root 初始化要在服務停止時進行")

// InitRoot 執行 `evernight-server init-root --password-stdin`：
// 把標準輸入前兩行當作口令與其確認，通過全部前置檢查後才一次性寫進組態檔。
//
// 成功條件只有一個形態：Root 憑據已在組態檔裡讀得回來，且對應的 Root 審計已落庫。
// 其他任何結果都回錯誤（結束碼非 0），且組態檔維持原樣——包括「口令不符」「已有憑據」
// 「環境變數蓋著」「服務還在跑」「審計表還沒建立」「寫入途中的任何失敗」。
func InitRoot(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	rest, err := parseInitRootArgs(args)
	if err != nil {
		return err
	}

	// 一次性命令：人類可讀日誌丟棄（與 backup、migrate、restore 同一處置），日誌檔案照寫。
	cfg, lg, err := openConfig(rest, io.Discard)
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
	fmt.Fprintf(out, "evernight-server %s\n", Version)
	lg.Info("Root 初始化子命令開始", "version", Version, "data_dir", cfg.Server.DataDir)

	params, err := cfg.Security.Hashing.Params()
	if err != nil {
		lg.Error("Root 初始化中止：雜湊參數檔不合格", "err", err)
		return err
	}
	if os.Getenv(config.RootPasswordHashEnvKey) != "" {
		// 不寫、不讀口令、也不取鎖：這種狀態下寫進檔案的那份 Root 永遠不會生效，
		// 留著它只會讓之後的人以為 Root 的口令是這一個。
		err := fmt.Errorf("app: 環境變數 %s 已設定，它會在執行期蓋掉組態檔裡的 Root 憑據；"+
			"請先移除該變數再初始化（本命令不做兩份 Root 的搬遷）", config.RootPasswordHashEnvKey)
		lg.Error("Root 初始化中止：環境變數覆蓋了 Root 憑據", "env", config.RootPasswordHashEnvKey)
		return err
	}

	// 鎖先於口令：取不到鎖時不該浪費一次「輸入兩行口令」，也不該讓操作者以為已經動到東西。
	db, err := openDatabase(ctx, cfg, lg, diskMonitor(cfg))
	if err != nil {
		// 鎖被佔用時把「該做什麼」補在同一個錯誤裡：database 那邊已經點名鎖檔與持有者，
		// 這一層只加一句操作者用得上的結論，並保留 errors.Is 的可判別性。
		if errors.Is(err, database.ErrLocked) {
			return fmt.Errorf("%w（原始錯誤：%v）", ErrServerStillLocked, err)
		}
		return err
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			fmt.Fprintf(out, "關閉資料庫失敗：%v\n", closeErr)
		} else {
			fmt.Fprintln(out, "資料庫已關閉，單寫入實例鎖已釋放。")
		}
	}()

	ready, err := audit.RootTableReady(ctx, db.SQL())
	if err != nil {
		lg.Error("Root 初始化中止：無法確認 Root 審計落點", "err", err)
		return err
	}
	if !ready {
		err := errors.New("app: 這個資料目錄的資料庫還沒有 root_audit 表，初始化無法留下痕跡；" +
			"請先執行 evernight-server migrate（或直接啟動一次服務）建立結構，再重跑本命令")
		lg.Error("Root 初始化中止：Root 審計表尚未建立", "database", cfg.Database.Path)
		return err
	}

	secret, err := readRootSecret(in)
	if err != nil {
		// 連口令都沒湊齊的嘗試也要留痕：同一個人在一分鐘內試了三次「不一致」，
		// 那本身就是值得查的事件（是鍵錯，還是有人在試）。
		lg.Error("Root 初始化中止：口令輸入不合格", "err", err)
		if auditErr := appendRootInitAudit(ctx, db, err, params); auditErr != nil {
			lg.Warn("口令輸入失敗的痕跡未能寫入 Root 審計", "err", auditErr)
		}
		return err
	}

	res, initErr := rootinit.Initialize(rootinit.Options{
		ConfigPath: cfg.ConfigFile(),
		Secret:     secret,
		Params:     params,
	})
	auditErr := appendRootInitAudit(ctx, db, initErr, params)
	if initErr != nil {
		if auditErr != nil {
			// 被拒絕的嘗試連痕跡都沒留下，這件事要用日誌講得出來；錯誤本身仍照原樣回傳，
			// 否則呼叫端無法再用 errors.Is 判別「已被初始化」。
			lg.Warn("Root 初始化的拒絕事件未能寫入 Root 審計", "err", auditErr)
		}
		lg.Error("Root 初始化未成功", "err", initErr, "refused", errors.Is(initErr, config.ErrRootAlreadyInitialized))
		fmt.Fprint(out, rootInitRefusalNote(initErr))
		return initErr
	}
	if auditErr != nil {
		// 到這裡憑據已經落地：回傳錯誤會讓結束碼非 0，報告必須把「哪一半做了、哪一半沒做」
		// 講清楚，否則下一次動手的人會以為檔案還是舊的。
		lg.Error("Root 已寫入組態檔，但 Root 審計未能落庫", "err", auditErr,
			"data_dir", cfg.Server.DataDir)
		fmt.Fprint(out, rootInitReport(cfg, res))
		fmt.Fprintln(out, "警示：對應的 Root 審計這次沒有寫進去（"+auditErr.Error()+"）。"+
			"憑據本身已生效；請先檢查那個資料庫可否寫入，再把這一次初始化補記進維運紀錄。")
		return fmt.Errorf("app: Root 已初始化，但 Root 審計未能寫入: %w", auditErr)
	}

	fmt.Fprint(out, rootInitReport(cfg, res))
	lg.Info("Root 初始化完成", "data_dir", cfg.Server.DataDir,
		"hash_memory_kb", params.MemoryKiB, "hash_time_cost", params.TimeCost,
		"hash_parallelism", params.Parallelism, "hash_key_length", params.KeyLength)
	return nil
}

// RootStatus 執行 `evernight-server root-status`：只讀地回報 Root 是否已初始化。
//
// 它刻意不走 openConfig：那條路裡的 Prepare 會建立資料目錄與範例組態，
// 而「問一個問題」不該留下任何東西。回傳值在這裡永遠是 nil（查詢成功），
// 已初始化與否只在輸出那一句話裡——把它編成結束碼會出現「非 0 就是壞了」的誤讀。
func RootStatus(ctx context.Context, args []string, out io.Writer) error {
	opts, err := config.ParseArgs(args)
	if err != nil {
		return err
	}
	cfg, err := config.Load(opts)
	if err != nil {
		return err
	}
	if err := cfg.Resolve(); err != nil {
		return err
	}

	fmt.Fprintf(out, "evernight-server %s\n", Version)
	state, err := rootinit.Status(cfg.ConfigFile())
	if err != nil {
		// 查不出來就照實回錯誤（結束碼非 0）：把它報成「尚未初始化」會誘發一次多餘的初始化。
		return err
	}
	switch {
	case !state.ConfigExists:
		fmt.Fprintln(out, "Root 狀態：尚未初始化（那個資料目錄裡還沒有組態檔）")
		fmt.Fprintln(out, "下一步：在本機執行 evernight-server init-root --password-stdin "+
			"（會先建立組態檔，再把口令落成 Argon2id 憑據）")
	case state.Initialized:
		fmt.Fprintln(out, "Root 狀態：已初始化（組態檔帶有 Argon2id 憑據；雜湊值不在這裡顯示）")
		fmt.Fprintln(out, "提示：要換 Root 口令請走服務內的已認證改密流程（Root 登入後 POST /auth/password/change），"+
			"再跑一次 init-root 一律會被拒絕——那是設計，不是故障。")
	default:
		fmt.Fprintln(out, "Root 狀態：尚未初始化（組態檔已存在，但還沒有 Root 憑據）")
		fmt.Fprintln(out, "下一步：在本機執行 evernight-server init-root --password-stdin")
	}
	if os.Getenv(config.RootPasswordHashEnvKey) != "" {
		// 這一行要單獨說：它代表「檔案裡沒有」不等於「這個服務沒有 Root」，
		// 兩者混在一起會讓人去初始化一個永遠不會生效的憑據。
		fmt.Fprintf(out, "注意：環境變數 %s 已設定，它會在執行期蓋掉組態檔的值；"+
			"本命令只報告檔案內容。\n", config.RootPasswordHashEnvKey)
	}
	return nil
}

// readRootSecret 從 in 讀取口令與確認各一行。
//
// 只削掉行尾的換行（LF 與 CRLF），不做任何空白修剪：口令的語意是位元組精確的，
// 把尾端空格偷偷去掉會讓「用同一個口令登入」變成一件看運氣的事。
// 兩行都要讀到、而且必須相同，才會把值交回呼叫端；確認行缺失與不一致都算失敗。
func readRootSecret(in io.Reader) (string, error) {
	if in == nil {
		return "", errors.New("app: 需要 --password-stdin：本命令只從標準輸入讀口令")
	}
	reader := bufio.NewReader(in)
	secret, err := readSecretLine(reader, 1)
	if err != nil {
		return "", err
	}
	confirm, err := readSecretLine(reader, 2)
	if err != nil {
		return "", err
	}
	if secret != confirm {
		return "", ErrRootSecretMismatch
	}
	return secret, nil
}

// readSecretLine 讀出一行口令；第 n 行用來產生可判讀的錯誤。
func readSecretLine(reader *bufio.Reader, n int) (string, error) {
	line, err := reader.ReadString('\n')
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if err != nil {
		if errors.Is(err, io.EOF) && line != "" {
			// 最後一行沒有換行（`printf 'x' | ...` 這種寫法）仍是可用的輸入。
			return line, nil
		}
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("app: 標準輸入少了第 %d 行（需要口令與確認各一行）", n)
		}
		return "", fmt.Errorf("app: 讀取標準輸入第 %d 行失敗: %w", n, err)
	}
	return line, nil
}

// parseInitRootArgs 確認 --password-stdin 有給出，並把其餘參數交回組態解析。
//
// 這裡刻意不接受任何「口令旗標」：值放進 argv 會被程序清單與 shell 歷史留住，
// 而 Root 口令一旦洩給那兩個地方，換口令的成本是一整台伺服器。
func parseInitRootArgs(args []string) ([]string, error) {
	var (
		rest   []string
		stdin  bool
		gotDup bool
	)
	for _, arg := range args {
		if arg == "--password-stdin" || arg == "-password-stdin" {
			if stdin {
				gotDup = true
			}
			stdin = true
			continue
		}
		rest = append(rest, arg)
	}
	if gotDup {
		return nil, errors.New("app: init-root 的 --password-stdin 重複給出")
	}
	if !stdin {
		return nil, errors.New("app: init-root 需要 --password-stdin：" +
			"口令只從標準輸入讀取（前兩行為口令與確認），不接受命令列上的口令值")
	}
	return rest, nil
}

// appendRootInitAudit 把這次初始化的結果寫成一筆 Root 審計。
//
// 主體是 system（來源 CLI）而不是 root：這一行記的是「有人在主機上跑了這個命令」，
// 而那一刻 Root 還不存在（或正是被這次動作建立的），把它寫成 root 等於憑空造出一個身份。
// 欄位值一律只用「set／unset」這種形狀描述與參數檔數值——口令與雜湊都不準進審計。
func appendRootInitAudit(ctx context.Context, db *database.DB, initErr error, params credential.Params) error {
	actor, err := cliSystemActor()
	if err != nil {
		return err
	}
	rec := audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  actor,
		Target: audit.Target{Kind: "server"},
		Reason: rootInitAuditReason(initErr, params),
	}
	switch {
	case initErr == nil:
		rec.Action = "server.root_initialize"
		// 欄位名刻意不叫 root_password_hash：那個鍵名在 §7 的清單裡是「值永不記錄」，
		// 寫進去只會得到兩個 [redacted]，反而看不出這次到底動了什麼。這裡記的是狀態差量，
		// 而雜湊與口令永遠不進這張表。
		rec.Changes = []audit.Change{
			{Field: "root_credential", Before: "unset", After: "set"},
		}
	case errors.Is(initErr, config.ErrRootAlreadyInitialized),
		errors.Is(initErr, rootinit.ErrUnusableExistingCredential):
		rec.Action = "server.root_initialize_denied"
		rec.Changes = []audit.Change{
			{Field: "root_credential", Before: "set", After: "set"},
		}
	default:
		rec.Action = "server.root_initialize_failed"
	}

	store := audit.NewStore(timeutil.System())
	if err := db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		_, appendErr := store.Append(tctx, tx, rec)
		return appendErr
	}); err != nil {
		return err
	}
	return nil
}

// rootInitAuditReason 產生那筆審計的原因欄：只講結論與參數檔，不講憑據。
func rootInitAuditReason(initErr error, params credential.Params) string {
	if initErr == nil {
		return fmt.Sprintf("以 init-root 一次性寫入 Root 憑據（Argon2id m=%d,t=%d,p=%d,keylen=%d）",
			params.MemoryKiB, params.TimeCost, params.Parallelism, params.KeyLength)
	}
	if errors.Is(initErr, config.ErrRootAlreadyInitialized) {
		return "拒絕第二次初始化：組態檔已有 Root 憑據，未做任何改動"
	}
	if errors.Is(initErr, rootinit.ErrUnusableExistingCredential) {
		return "拒絕初始化：組態檔已有的 Root 憑據不是可用編碼，未做任何改動"
	}
	// 失敗原因在此只保留一句話：錯誤字串本身已由 config／rootinit／credential 保證
	// 不含口令與雜湊，但仍不該把整條包裝鏈原樣塞進審計表。
	reason := initErr.Error()
	if r := []rune(reason); len(r) > 200 {
		reason = string(r[:200]) + "…"
	}
	return "初始化失敗：" + reason
}

// rootInitReport 產生成功時的報告（逐項把「生效的是什麼、沒做什麼」寫清楚）。
func rootInitReport(cfg config.Config, res rootinit.Result) string {
	var lines strings.Builder
	lines.WriteString("Root 初始化：已完成\n")
	fmt.Fprintf(&lines, "  憑據：Argon2id（m=%d,t=%d,p=%d,keylen=%d），已寫入 %s 的 security.root_password_hash\n",
		res.Params.MemoryKiB, res.Params.TimeCost, res.Params.Parallelism, res.Params.KeyLength,
		cfg.ConfigFile())
	lines.WriteString("  口令：只存在於剛才的標準輸入，本命令不印出它，也不寫進日誌與審計。\n")
	lines.WriteString("  本次未做：沒有啟動監聽、沒有動資料庫內容（只取單寫入實例鎖並追加 1 筆 Root 審計）、" +
		"也沒有新增任何 HTTP 端點。\n")
	lines.WriteString("  之後：再跑一次 init-root 會被拒絕，這是「一次性」的定義；" +
		"要換 Root 口令請走服務內的已認證改密流程（Root 登入後 POST /auth/password/change）。\n")
	fmt.Fprintf(&lines, "下一步：evernight-server --data-dir \"%s\" 啟動服務。\n", cfg.Server.DataDir)
	lines.WriteString("敏感性提示：組態檔現在是敏感檔（裡面的編碼雜湊可以被離線嘗試），" +
		"備分包會原樣收錄它——存放位置與日後刪除都要當回事。\n")
	return lines.String()
}

// rootInitRefusalNote 產生「沒有成功」那幾種結果的報告。
//
// 已初始化這種結果要講得比錯誤更清楚：它不是故障，而是這條通路已經關上了。
func rootInitRefusalNote(initErr error) string {
	// 「已有但不可用」要單獨講：它聽起來像「已經初始化過」，實際意思是「現在沒有人登得進去」，
	// 混為一談會讓操作者以為只能等改密流程，而那是對一個壞值的錯誤期待。
	if errors.Is(initErr, rootinit.ErrUnusableExistingCredential) {
		return "Root 初始化：拒絕（組態檔已經有一份「不可用」的 Root 憑據）\n" +
			"  那一串不是可用的 Argon2id 編碼，也就是現在的 Root 登不進去。\n" +
			"  本命令刻意不把它換掉：先確認那是打字錯誤、被動過，還是真的要放棄這個口令，\n" +
			"  再自行處置組態檔裡那個欄位——處理完重跑本命令即可。\n"
	}
	if errors.Is(initErr, config.ErrRootAlreadyInitialized) {
		return "Root 初始化：拒絕（這個資料目錄已經有 Root 憑據）\n" +
			"  既有憑據與其口令都不受影響，組態檔維持原樣。\n" +
			"  要換口令請走服務內的已認證改密流程（Root 登入後 POST /auth/password/change）；把既有憑據蓋掉不是一條支援的路。\n"
	}
	return fmt.Sprintf("Root 初始化：未成功（%v）\n  組態檔維持原樣。\n", initErr)
}
