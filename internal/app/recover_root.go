package app

// recover_root.go 實作 `evernight-server recover-root --password-stdin --confirm`：
// Root 口令遺失後，在伺服器本機把組態檔裡那份憑據換成新的，並讓舊會話全部失效。
//
// 為什麼又是一條本機命令而不是别的什麼：恢復要交出的是「這台伺服器的最高權限」，
// 而這個場景裡唯一還能依賴的授權事實，是操作者能在主機上跑命令、能讀寫那個組態檔，
// 並且能把服務停下來。這一步因此不新增任何 HTTP 端點、不開放任何監聽、不採信請求裡的
// 任何自報欄位；也不設「后门口令」「恢復金鑰」「可下載的恢復檔」——那些都是把同一個
// 權限再發一份副本出去，洩漏面比組態檔本身大得多。
//
// 為什麼要求服務停止（拿得到資料庫單寫入實例鎖）：這不只是謹慎，而是事實。
//   - 運行中的服務把 Root 憑據讀在記憶體裡（見 internal/app/root_creds.go），另一個進程
//     改檔案不會让它回頭更新——那樣會得到「終端說恢復好了、舊口令其實還登得進去」；
//   - 會話撤銷與 Root 審計必須寫資料庫，而單寫入實例鎖被佔用時連連上都開不了。
// 兩件事在同一個方向上，所以這裡沿用 init-root 已確立的形：離線執行、失敗即整筆沒有發生。
//
// 失敗恢復方案（用戶已批準的形態）：
//  1. 全部前置檢查（環境變數覆蓋、實例鎖、審計落點、磁碟寫入門、組態檔有無現值）
//     都發生在讀口令與動檔案之前；
//  2. 覆寫組態檔在前，會話撤銷與審計在同一個資料庫交易裡在後；
//  3. 第 2 步失敗→ 以「覆寫後讀回的現值」做比較-and-set 把舊雜湊換回去，
//     對外報失敗，狀態與動筆前一致（檔案排版可能被重新編碼，但那不是憑據內容）；
//  4. 回滾也失敗（檔案系統與資料庫同時壞）→ 以 Error 寫進運行日誌檔案（不是只靠一條
//     終端輸出），結束碼非 0，並明確告訴操作者必須人工補記；
//  5. 成功回報的定義要求覆寫與「撤銷＋審計」都落地，不存在「報成功但舊口令仍可用」。
//
// 口令的途徑與 init-root 完全一致：只從標準輸入讀兩行（口令與確認），不讀命令列參數
// ——argv 會被程序清單與 shell 歷史留下。此外多一枚 --confirm：覆蓋是單機爆炸半径最大的
// 動作（舊口令永久失效、Root 的全部裝置被登出），誤跑的代價不是一句「算了」。
//
// 日誌、審計與終端輸出都不出現口令明文或任何一方的雜湊值。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/rootinit"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// RecoverRoot 執行 `evernight-server recover-root --password-stdin --confirm`。
//
// 成功只有一個形態：組態檔讀得回新憑據，Root 名下會話已全部撤銷，且對應的 Root 審計
// 已與撤銷同交易落庫。其他任何結果都回錯誤（結束碼非 0），並且可用狀態與動筆前一致。
func RecoverRoot(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	rest, err := parseRecoverRootArgs(args)
	if err != nil {
		return err
	}

	// 一次性命令：人類可讀日誌丟棄（與 backup、migrate、restore、init-root 同一處置），日誌檔案照寫。
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
	lg.Info("Root 憑據恢復子命令開始", "version", Version, "data_dir", cfg.Server.DataDir)

	params, err := cfg.Security.Hashing.Params()
	if err != nil {
		lg.Error("Root 憑據恢復中止：雜湊參數檔不合格", "err", err)
		return err
	}
	if os.Getenv(config.RootPasswordHashEnvKey) != "" {
		// 與 init-root 同一口徑：環境變數蓋在檔案之上時，寫進檔案的那份永遠不生效，
		// 留著它只會讓之後的人以為 Root 的口令是這一個。本命令不做兩份 Root 的搬遷。
		err := fmt.Errorf("app: 環境變數 %s 已設定，它會在執行期蓋掉組態檔裡的 Root 憑據；"+
			"請先移除該變數再恢復（本命令不做兩份 Root 的搬遷）", config.RootPasswordHashEnvKey)
		lg.Error("Root 憑據恢復中止：環境變數覆蓋了 Root 憑據", "env", config.RootPasswordHashEnvKey)
		return err
	}

	// 鎖先於一切寫入與口令：取不到鎖時不該浪費一次「輸入兩行口令」，也不該讓操作者以為動到東西。
	space := diskMonitor(cfg)
	db, err := openDatabase(ctx, cfg, lg, space)
	if err != nil {
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
		lg.Error("Root 憑據恢復中止：無法確認 Root 審計落點", "err", err)
		return err
	}
	if !ready {
		err := errors.New("app: 這個資料目錄的資料庫還沒有 root_audit 表，恢復無法留下痕跡；" +
			"請先執行 evernight-server migrate（或直接啟動一次服務）建立結構，再重跑本命令")
		lg.Error("Root 憑據恢復中止：Root 審計表尚未建立", "database", cfg.Database.Path)
		return err
	}

	// 磁碟閘問在碰組態檔之前：空間不足時那筆「撤銷＋審計」的交易必然被寫入門擋掉，
	// 事先問出來就根本不必走到「覆寫之後再回滾」那條補償路。
	if err := checkSpaceBeforeWrite(space, lg.Logger); err != nil {
		lg.Error("Root 憑據恢復中止：磁碟空間不足", "err", err)
		return err
	}

	// 現值先讀出來：一是「有沒有可恢復的東西」的前置檢查，二是回滾時要換回去的那個值。
	// 覆寫當下的比對-and-set 由 rootinit.Recover 自己再讀一次檔案做，這裡的讀取不替代它。
	before, err := config.ReadRootFile(cfg.ConfigFile())
	if err != nil {
		lg.Error("Root 憑據恢復中止：讀取組態檔現值失敗", "err", err)
		return err
	}
	if !before.FileExists || !before.Initialized() {
		err := fmt.Errorf("%w：組態檔 %s 裡還沒有 Root 憑據，請改用一次性初始化 evernight-server init-root --password-stdin",
			rootinit.ErrNoExistingCredential, cfg.ConfigFile())
		lg.Error("Root 憑據恢復中止：組態檔尚無 Root 憑據", "err", err)
		if auditErr := appendRecoverRootAudit(ctx, db, err, 0, params); auditErr != nil {
			lg.Warn("Root 憑據恢復的拒絕事件未能寫入 Root 審計", "err", auditErr)
		}
		fmt.Fprint(out, recoverRefusalNote(err))
		return err
	}

	secret, err := readRootSecret(in)
	if err != nil {
		// 連口令都沒湊齊的嘗試也要留痕：同一個人在一分鐘內試了三次「不一致」，
		// 那本身就是值得查的事件（是鍵錯，還是有人在試）。
		lg.Error("Root 憑據恢復中止：口令輸入不合格", "err", err)
		if auditErr := appendRecoverRootAudit(ctx, db, err, 0, params); auditErr != nil {
			lg.Warn("口令輸入失敗的痕跡未能寫入 Root 審計", "err", auditErr)
		}
		return err
	}

	res, recoverErr := rootinit.Recover(rootinit.RecoverOptions{
		ConfigPath: cfg.ConfigFile(),
		Secret:     secret,
		Params:     params,
	})
	if recoverErr != nil {
		auditErr := appendRecoverRootAudit(ctx, db, recoverErr, 0, params)
		lg.Error("Root 憑據恢復未成功", "err", recoverErr)
		if auditErr != nil {
			// 被拒絕的嘗試連痕跡都沒留下，這件事要用日誌講得出來；錯誤本身仍照原樣回傳，
			// 否則呼叫端無法再用 errors.Is 判別「沒有可恢復的憑據」這類結論。
			lg.Warn("Root 憑據恢復的拒絕事件未能寫入 Root 審計", "err", auditErr)
		}
		fmt.Fprint(out, recoverRefusalNote(recoverErr))
		return recoverErr
	}

	// 覆寫已落地。回滾錨點取「檔案現在讀得到的值」而不是記憶體的派生結果：
	// rootinit 的回傳值刻意不含憑據材料，而這裡需要的是檔案事實。
	now, err := config.ReadRootFile(cfg.ConfigFile())
	if err != nil {
		lg.Error("Root 口令已更換，但讀不回組態檔現值，會話撤銷與審計未執行",
			"err", err, "data_dir", cfg.Server.DataDir)
		fmt.Fprint(out, recoverHalfDoneNote(err))
		return fmt.Errorf("app: Root 口令已更換，但會話撤銷與審計未執行（讀不回組態檔現值，無法安全回滾）: %w", err)
	}

	// 會話倉儲在這裡只做一件事：撤銷 Root 名下未撤銷的行。期限與閒置判定都不參與那個
	// UPDATE，但 NewStore 的構造把「期限必須為正」當成裝配錯誤當場拒（否則會造出一個
	// 「建立了就永遠驗不過」的物件），因此照組態給一個真實值而不是隨便湊一個。
	sessions, err := session.NewStore(timeutil.System(),
		time.Duration(cfg.Security.SessionTTLHours)*time.Hour)
	if err != nil {
		lg.Error("Root 口令已更換，但會話倉儲裝配失敗", "err", err)
		fmt.Fprint(out, recoverHalfDoneNote(err))
		return fmt.Errorf("app: Root 口令已更換，但會話撤銷與審計未執行（會話倉儲裝配失敗）: %w", err)
	}

	var revoked int
	err = db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		n, err := sessions.RevokeAllRootSessions(tctx, tx)
		if err != nil {
			return err
		}
		// 審計與撤銷同生同滅（Root 域事件的既有合同）：這裡傳的 nil 表示「這次恢復成立了」，
		// 所以那筆審計記的撤銷數量必須就是這筆交易實際改掉的行數。
		rec, err := recoverRootAuditRecord(nil, n, params)
		if err != nil {
			return err
		}
		if _, err := audit.NewStore(timeutil.System()).Append(tctx, tx, rec); err != nil {
			return err
		}
		revoked = n
		return nil
	})
	if err != nil {
		// 補償：把舊雜湊換回去。方向走的仍是同一條比較-and-set 通路（現值必須還是那次
		// 覆寫留下的新值才換得動），所以並行的第二次恢復不會被這條尾巴誤蓋。
		rollbackErr := config.UpdateRootPasswordHash(cfg.ConfigFile(), now.Hash, before.Hash)
		if rollbackErr != nil {
			lg.Error("Root 恢復回滾失敗：口令已更換但會話撤銷與審計未落地",
				"revoke_err", err, "rollback_err", rollbackErr, "data_dir", cfg.Server.DataDir)
			fmt.Fprint(out, recoverRollbackFailureNote(err, rollbackErr))
			return fmt.Errorf("app: Root 恢復的會話撤銷失敗，且憑據回滾同樣失敗: %v（原始錯誤：%v）", rollbackErr, err)
		}
		lg.Error("Root 恢復的會話撤銷失敗，已回滾憑據", "err", err)
		// 這次嘗試的淨結果是「什麼都沒換」，但仍要留痕：恢復被資料庫的寫入條件擋下，
		// 與「有人在本機跑了幾次不會成功的恢復」是同一類值得查的事件。
		if auditErr := appendRecoverRootAudit(ctx, db, fmt.Errorf("會話撤銷與審計未落地，憑據已回滾: %w", err), 0, params); auditErr != nil {
			lg.Warn("回滾後的失敗痕跡未能寫入 Root 審計", "err", auditErr)
		}
		fmt.Fprint(out, recoverRolledBackNote(err))
		return fmt.Errorf("app: Root 恢復失敗（憑據已回滾，舊口令仍可用）: %w", err)
	}

	fmt.Fprint(out, recoverReport(cfg, res, revoked))
	lg.Info("Root 憑據恢復完成", "data_dir", cfg.Server.DataDir, "revoked_sessions", revoked,
		"hash_memory_kb", params.MemoryKiB, "hash_time_cost", params.TimeCost,
		"hash_parallelism", params.Parallelism, "hash_key_length", params.KeyLength)
	return nil
}

// parseRecoverRootArgs 取出 recover-root 的兩個必要旗標，其餘參數交回組態解析。
//
// 這裡刻意不接受任何「口令旗標」：值放進 argv 會被程序清單與 shell 歷史留住。
// 除 --password-stdin 與 --confirm 之外的未知旗標會落到 config.ParseArgs 那側報
// 「命令列參數錯誤」，因此諸如 --password=... 的寫法不會被靜默忽略。
func parseRecoverRootArgs(args []string) ([]string, error) {
	var (
		rest       []string
		stdin      bool
		confirmed  bool
		dupStdin   bool
		dupConfirm bool
	)
	for _, arg := range args {
		switch arg {
		case "--password-stdin", "-password-stdin":
			if stdin {
				dupStdin = true
			}
			stdin = true
		case "--confirm", "-confirm":
			if confirmed {
				dupConfirm = true
			}
			confirmed = true
		default:
			rest = append(rest, arg)
		}
	}
	if dupStdin {
		return nil, errors.New("app: recover-root 的 --password-stdin 重複給出")
	}
	if dupConfirm {
		return nil, errors.New("app: recover-root 的 --confirm 重複給出")
	}
	if !stdin {
		return nil, errors.New("app: recover-root 需要 --password-stdin：" +
			"新口令只從標準輸入讀取（前兩行為口令與確認），不接受命令列上的口令值")
	}
	if !confirmed {
		return nil, errors.New("app: recover-root 需要 --confirm：這個命令會永久廢除現有 Root 口令，" +
			"並讓 Root 名下全部裝置登出；確認要這麼做才把這個旗標加進命令列")
	}
	return rest, nil
}

// recoverRootAuditRecord 產生恢復事件的 Root 審計記錄。
//
// 主體是 system（來源 CLI）而不是 root：這一行記的是「有人在主機上跑了他自己的口令已經
// 遺失的那個帳戶的恢復命令」，那一刻以 Root 身分自證並沒有依據。欄位值只用
// set／unset 這種狀態差量——口令與雜湊都不準進審計（與 init-root 同一口徑）。
//
// 主體構造失敗時回錯誤而不是退化成「沒有主體的記錄」：與 restore 那側同一約定
// （見 cliSystemActor），一條說不出是誰做的審計，留下來只會佔掉那個場景真正的留痕名額。
func recoverRootAuditRecord(recoverErr error, revoked int, params credential.Params) (audit.Record, error) {
	actor, err := cliSystemActor()
	if err != nil {
		return audit.Record{}, err
	}
	rec := audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  actor,
		Target: audit.Target{Kind: "server"},
		Reason: recoverRootAuditReason(recoverErr, revoked, params),
	}
	switch {
	case recoverErr == nil:
		rec.Action = "server.root_recover"
		rec.Changes = []audit.Change{
			{Field: "root_credential", Before: "set", After: "set"},
		}
	case errors.Is(recoverErr, rootinit.ErrNoExistingCredential):
		rec.Action = "server.root_recover_denied"
		rec.Changes = []audit.Change{
			{Field: "root_credential", Before: "unset", After: "unset"},
		}
	case errors.Is(recoverErr, config.ErrRootCredentialMismatch):
		rec.Action = "server.root_recover_denied"
		rec.Changes = []audit.Change{
			{Field: "root_credential", Before: "set", After: "set"},
		}
	default:
		rec.Action = "server.root_recover_failed"
	}
	return rec, nil
}

// recoverRootAuditReason 產生那筆審計的原因欄：只講結論與參數檔，不講憑據。
func recoverRootAuditReason(recoverErr error, revoked int, params credential.Params) string {
	if recoverErr == nil {
		return fmt.Sprintf("以 recover-root 在本機覆寫 Root 憑據（Argon2id m=%d,t=%d,p=%d,keylen=%d），"+
			"並撤銷 Root 名下 %d 個會話", params.MemoryKiB, params.TimeCost, params.Parallelism,
			params.KeyLength, revoked)
	}
	if errors.Is(recoverErr, rootinit.ErrNoExistingCredential) {
		return "拒絕恢復：組態檔還沒有 Root 憑據（建立憑據屬 init-root 一次性初始化），未做任何改動"
	}
	if errors.Is(recoverErr, config.ErrRootCredentialMismatch) {
		return "拒絕恢復：組態檔現行憑據與預讀值不一致（另有恢復或手工編輯動過檔案），未做任何改動"
	}
	// 失敗原因在此只保留一句話：錯誤字串本身已由 config／rootinit／credential 保證
	// 不含口令與雜湊，但仍不該把整條包裝鏈原樣塞進審計表。
	reason := recoverErr.Error()
	if r := []rune(reason); len(r) > 200 {
		reason = string(r[:200]) + "…"
	}
	return "恢復失敗：" + reason
}

// appendRecoverRootAudit 把恢復事件（成功以外的拒絕與失敗同樣）寫成一筆 Root 審計。
//
// 與撤銷不同，這一條走自己的小交易：它要記的是「這次嘗試發生了」這個事實本身，
// 不與任何憑據變更同生同滅——被拒絕的嘗試沒有可撤銷的東西，回滾後的嘗試也不該把
// 那筆失敗計進成功那一筆的撤銷數量裡。
func appendRecoverRootAudit(ctx context.Context, db *database.DB, recoverErr error,
	revoked int, params credential.Params) error {
	rec, err := recoverRootAuditRecord(recoverErr, revoked, params)
	if err != nil {
		return err
	}
	store := audit.NewStore(timeutil.System())
	return db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		_, err := store.Append(tctx, tx, rec)
		return err
	})
}

// recoverReport 產生成功時的報告（逐項把「生效的是什麼、沒做什麼」寫清楚）。
func recoverReport(cfg config.Config, res rootinit.Result, revoked int) string {
	var lines strings.Builder
	lines.WriteString("Root 憑據恢復：已完成\n")
	fmt.Fprintf(&lines, "  憑據：新的 Argon2id 編碼（m=%d,t=%d,p=%d,keylen=%d），已覆寫 %s 的 security.root_password_hash\n",
		res.Params.MemoryKiB, res.Params.TimeCost, res.Params.Parallelism, res.Params.KeyLength,
		cfg.ConfigFile())
	lines.WriteString("  舊口令：自此永久失效。本命令不問也不驗舊口令——能在這台主機上跑它、" +
		"並讀寫那份組態檔，就是這個動作全部的授權依據。\n")
	fmt.Fprintf(&lines, "  會話：Root 名下 %d 個會話已在同一個資料庫交易裡撤銷（下一个請求即被拒）。"+
		"普通帳戶的會話一個都沒動。\n", revoked)
	lines.WriteString("  口令：只存在於剛才的標準輸入，本命令不印出它，也不寫進日誌與審計。\n")
	lines.WriteString("  本次未做：沒有啟動監聽、沒有開任何 HTTP 端點、沒有產生恢復檔或後門口令；" +
		"資料庫除會話撤銷與 1 筆 Root 審計外沒有其他改動。\n")
	lines.WriteString("  之後：再跑一次 recover-root 仍會成功（它的語意就是覆寫現值），" +
		"而 init-root 依然會被拒絕——那仍是「一次性」的定義。\n")
	fmt.Fprintf(&lines, "下一步：evernight-server --data-dir \"%s\" 啟動服務，並用新口令登入。\n", cfg.Server.DataDir)
	lines.WriteString("敏感性提示：組態檔現在是敏感檔（裡面的編碼雜湊可以被離線嘗試），" +
		"備分包會原樣收錄它——存放位置與日後刪除都要當回事。\n")
	return lines.String()
}

// recoverRefusalNote 產生「沒有碰任何東西就被拒絕」那幾種結果的報告。
func recoverRefusalNote(recoverErr error) string {
	if errors.Is(recoverErr, rootinit.ErrNoExistingCredential) {
		return "Root 憑據恢復：拒絕（組態檔裡還沒有 Root 憑據）\n" +
			"  「建立第一份憑據」與「換掉已有的那份」是兩條路：前者請用 evernight-server init-root --password-stdin。\n" +
			"  組態檔維持原樣。\n"
	}
	if errors.Is(recoverErr, config.ErrRootCredentialMismatch) {
		return "Root 憑據恢復：拒絕（組態檔的現行憑據已不是預讀的那一份）\n" +
			"  在本命令讀取之後，另有恢復跑過、或有人手工編輯過那個欄位。刻意不覆蓋：\n" +
			"  兩個並行的恢復只該有一個成功，否則「誰的口令生效」取決於誰晚寫完。\n" +
			"  請重新讀一次現況（evernight-server root-status）後再跑一次本命令；組態檔維持原樣。\n"
	}
	return fmt.Sprintf("Root 憑據恢復：未成功（%v）\n  組態檔維持原樣，舊口令仍可用。\n", recoverErr)
}

// recoverRolledBackNote 產生「覆寫成功但撤銷＋審計失敗、已回滾」的報告。
func recoverRolledBackNote(err error) string {
	return "Root 憑據恢復：未完成，憑據已回滾\n" +
		"  會話撤銷與 Root 審計這次沒有落地，因此把組態檔換回了動筆前那份憑據：\n" +
		"  舊口令仍然可用，Root 的裝置也沒有被登出——這次恢復整筆沒有發生。\n" +
		fmt.Sprintf("  失敗原因：%v\n", err) +
		"  注意：檔案排版可能被重新編碼（註解與欄位值都保留），但那個欄位的內容已回到原本的值。\n"
}

// recoverRollbackFailureNote 產生雙重故障（撤銷失敗且回滾也失敗）的報告。
func recoverRollbackFailureNote(err, rollbackErr error) string {
	return "Root 憑據恢復：半完成，且回滾失敗——需要人工處置\n" +
		"  新口令已寫進組態檔並生效，但 Root 會話的撤銷與對應的 Root 審計這次沒有落地，\n" +
		"  而把舊憑據換回去這件事也失敗了。也就是說：舊口令已經不能登入，舊會話卻還留在庫裡\n" +
		"  （它們仍受絕對期限與閒置線封頂，到期後自然失效）。\n" +
		fmt.Sprintf("  撤銷失敗原因：%v\n", err) +
		fmt.Sprintf("  回滾失敗原因：%v\n", rollbackErr) +
		"  請立刻處理：修復那個資料目錄的可寫性，再跑一次 recover-root（它會重新覆寫並完成撤銷與審計），\n" +
		"  或手工以初始化的形態重建那份憑據。這句話同時已寫進本次的運行日誌檔案，不是只有終端看得到。\n"
}

// recoverHalfDoneNote 產生「憑據已覆寫但連回滾錨點都拿不到」這種極端結果的報告。
func recoverHalfDoneNote(err error) string {
	return "Root 憑據恢復：未確認完成——需要人工核對\n" +
		"  新口令已覆寫進組態檔（覆寫本身帶有回讀比對），但覆寫之後讀不回現值，\n" +
		"  因此本命令刻意沒有執行會話撤銷與 Root 審計，也不敢憑記憶去回滾那個欄位。\n" +
		fmt.Sprintf("  失敗原因：%v\n", err) +
		"  請立刻用文本編輯器確認那個資料目錄的 config.yaml 裡 security.root_password_hash，\n" +
		"  並重跑一次 recover-root 讓撤銷與審計落地。這句話同時已寫進本次的運行日誌檔案。\n"
}
