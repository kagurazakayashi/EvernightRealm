package app

// restore.go 實作 `evernight-server restore`：把一份備份包恢復成一個新的資料目錄，
// 並在報告裡把核對結果逐項寫出來。與 backup/migrate 同一形狀（一次性命令、報告走 out、
// 結束碼表達成敗），且同樣不開放監聽。
//
// 這一條路刻意「只收空目錄」：規格 OPS-008 要求「恢復前自動建立當前狀態的安全備份」，
// 而本命令沒有先備份誰的能力。受信主體這層已經由 internal/identity 落地，但它對 CLI
// 只能給出「伺服器自身」這個事實；「是誰下令恢復的」要等 Root 認證路徑（尚未落地）。
// 與其做一半然後假裝完整，不如把覆蓋這條通路根本不開——
// 需要覆蓋時，請自己先跑一次 backup，再對那個目錄動手。
//
// 寫入全程發生在目標目錄旁的暫存目錄裡，最後一次改名發布；
// 「恢復出來的資料目錄」這個說法在程式裡對應的是一個具體的不變量：
// 目標目錄不存在、或存在且為空，兩者之外一律拒絕（見 internal/restore）。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/backup"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/disk"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/restore"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// Restore 執行 `evernight-server restore --bundle <備份包> --into <新資料目錄>`。
//
// 順序與 internal/restore 一致：先做完全部判定（清單、逐檔摘要、版本比較、落點規劃、
// 磁碟空間），再寫入暫存目錄，落地後重讀一次與清單核對，最後一次改名發布。
// 任何一步失敗都不會有目標目錄（或目標目錄維持原本的空的狀態），因此
// 「這次恢復到底做了一半還是根本沒做」這個問題在這裡不需要問。
func Restore(ctx context.Context, args []string, out io.Writer) error {
	bundleArg, intoArg, dryRun, rest, err := parseRestoreArgs(args)
	if err != nil {
		return err
	}
	// 一次性命令：人類可讀日誌丟棄（與 backup、migrate 同一處置），日誌檔案照寫。
	// 這個目錄的日誌屬本次動作的運維紀錄，與「恢復出來的目錄裡的 logs/」是兩回事，
	// 後者是那個服務之後自己的日誌。
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

	bundle, err := filepath.Abs(bundleArg)
	if err != nil {
		return fmt.Errorf("app: 解析 --bundle 失敗（%s）: %w", bundleArg, err)
	}
	bundle = filepath.Clean(bundle)
	into, err := filepath.Abs(intoArg)
	if err != nil {
		return fmt.Errorf("app: 解析 --into 失敗（%s）: %w", intoArg, err)
	}
	into = filepath.Clean(into)

	knownVersion, err := migrate.MaxVersion()
	if err != nil {
		return err
	}
	preflight, err := database.ParsePreflight(cfg.Database.Preflight)
	if err != nil {
		return err
	}
	policy, err := txPolicy(cfg)
	if err != nil {
		return err
	}
	busy := time.Duration(cfg.Database.BusyTimeoutMS) * time.Millisecond

	// 空間判定針對目標所在的那個卷，不是備份包那個卷，也不是資料目錄那個卷：
	// 寫不寫得下去問的是落點（與 DEC-033 給備份的處置同一個理由）。
	space := diskMonitorAt(into, cfg)

	fmt.Fprintf(out, "evernight-server %s\n", Version)
	lg.Info("恢復子命令開始", "version", Version, "bundle", bundle, "into", into,
		"dry_run", dryRun, "known_schema_version", knownVersion)

	res, err := restore.Execute(ctx, restore.Options{
		Bundle:             bundle,
		Target:             into,
		CurrentDataDir:     cfg.Server.DataDir,
		KnownSchemaVersion: knownVersion,
		DryRun:             dryRun,
		Inspect: func(ctx context.Context, path string) (database.SnapshotInfo, error) {
			return database.InspectSnapshot(ctx, path, busy)
		},
		Disk: func() (disk.Verdict, error) { return space.Verify() },
		AppendAudit: func(ctx context.Context, databasePath string, manifest backup.Manifest) (idgen.ID, error) {
			return appendRestoreAudit(ctx, cfg, databasePath, manifest, bundle, into, knownVersion, preflight, policy, lg.Logger)
		},
	})
	if err != nil {
		lg.Error("恢復失敗", "err", err, "bundle", bundle, "into", into)
		return err
	}

	fmt.Fprint(out, restoreBundleNote(res))
	fmt.Fprint(out, restoreTargetNote(into))
	fmt.Fprint(out, restoreConfigNote(res))
	fmt.Fprint(out, restoreFactsNote("包內那份快照實際讀到", res.BundleFacts))
	if dryRun {
		fmt.Fprintln(out, "判定結果：以上每項都通過。這一次是 --dry-run，未寫入任何檔案（目標目錄未被建立）。")
		fmt.Fprint(out, restoreVersionNote(res, knownVersion))
		fmt.Fprintln(out, "敏感性提示：核對過程讀過包內那份組態，它的內容含原值（Argon2id 口令摘要在內）；"+
			"本命令不會把這些值寫進日誌或報告，只在恢復後把它原樣落在目標目錄的 config.yaml。")
		lg.Info("恢復檢查完成（--dry-run，未寫入任何檔案）", "bundle", bundle, "into", into,
			"schema_version", res.Manifest.Database.SchemaVersion)
		return nil
	}
	fmt.Fprint(out, restoreFactsNote("恢復後從目標讀回", res.RestoredFacts))
	fmt.Fprint(out, restoreAuditNote(res))
	fmt.Fprint(out, restoreSideFilesNote(res))
	fmt.Fprint(out, restoreStaleNote(res.StaleStaging))
	fmt.Fprint(out, restoreVersionNote(res, knownVersion))
	fmt.Fprintf(out, "已發布：%s（寫入 %d 個檔案、%s；清單與實際讀到的值逐項相符）\n",
		res.Target, res.FilesWritten, disk.HumanBytes(uint64(res.BytesWritten)))
	fmt.Fprintln(out, "敏感性提示：這個目錄現在帶著包內那份組態的原值（Argon2id 口令摘要在內），"+
		"它與備份包同樣是敏感檔；存放位置與日後刪除都要當回事。")
	fmt.Fprintf(out, "下一步：evernight-server --data-dir \"%s\" 啟動這個目錄（會開放監聽）。\n", res.Target)
	lg.Info("恢復完成", "bundle", bundle, "into", res.Target,
		"files", res.FilesWritten, "bytes", res.BytesWritten,
		"schema_version", res.RestoredFacts.SchemaVersion, "audit_id", res.AuditID.String(),
		"audit_skipped", res.AuditSkipped, "side_files_kept", strings.Join(res.SideFiles.Kept, "|"),
		"side_files_removed", strings.Join(res.SideFiles.Removed, "|"))
	return nil
}

// appendRestoreAudit 把一筆 Root 恢復事件寫進「還在上一步的暫存目錄裡」的那個資料庫檔案。
//
// 這是本專案第一次由「沒有身份的一次性命令」寫審計，所以主體一律記 system 而不是 root：
// 能構造出來的「誰備的、誰恢復的」此刻只有執行檔啟動者這個事實，把它寫成 root 是假裝有身份。
// 規格 §24.4 那句「僅 Root 可恢復」的把關屬 S10 之後的事，本命令的把關是「只能落在空目錄」，
// 兩者不同，報告裡不混著講。
//
// 用可寫開啟而不是沿用唯讀快照連線，是因為這一步要落一筆記錄；
// 它同時帶來一個副作用：那個庫的 journal_mode 會從 delete 轉成 wal，
// 而 internal/restore 在核對差量時把這件事當成預期（反向才是問題）。
func appendRestoreAudit(ctx context.Context, cfg config.Config, databasePath string,
	manifest backup.Manifest, bundle, into string, knownVersion int,
	preflight database.Preflight, policy database.TxPolicy, lg *slog.Logger,
) (idgen.ID, error) {
	db, err := database.Open(ctx, database.Options{
		Path:               databasePath,
		BusyTimeout:        time.Duration(cfg.Database.BusyTimeoutMS) * time.Millisecond,
		KnownSchemaVersion: knownVersion,
		Preflight:          preflight,
		TxPolicy:           policy,
	})
	if err != nil {
		return idgen.Nil, err
	}
	defer func() {
		// 關閉失敗不改變回傳值：那筆記錄已在交易裡提交成功，把它報成失敗會讓呼叫端
		// 清掉一個其實完整的暫存目錄——那才是真的損失。留痕即可。
		if closeErr := db.Close(); closeErr != nil {
			lg.Warn("關閉還原庫的連線失敗（那筆記錄已提交）", "path", databasePath, "err", closeErr)
		}
	}()

	record, err := restoreAuditRecord(manifest, bundle, into)
	if err != nil {
		lg.Error("構造恢復審計的主體失敗", "err", err)
		return idgen.Nil, err
	}
	store := audit.NewStore(timeutil.System())
	var id idgen.ID
	if err := db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		var appendErr error
		id, appendErr = store.Append(tctx, tx, record)
		return appendErr
	}); err != nil {
		return idgen.Nil, err
	}
	return id, nil
}

// restoreAuditRecord 湊齊那筆恢復審計的六要素。
//
// 欄位名一律用 §7 清單裡屬於「檔案系統路徑類」的那幾個鍵名（backup_path、data_dir），
// 理由是實測過的具體路徑（含 Go 的暫時目錄名）會被長隨機串規則當成金鑰打碼，
// 那時這條審計反而說不出它恢復了哪個目錄。值本身仍會過形狀掃描，免的是誤傷不是放寬。
//
// Before 一律為 nil：這一筆記的是「這個目錄從此有了這些東西」，
// 而不是「某欄位從 A 變成 B」——恢復前的目標目錄裡沒有這些事實可言。
//
// 主體經 internal/identity 的系統主體構造（來源為 CLI），再由其審計橋換成 audit.Actor：
// 這一筆記的是「執行檔被某人跑了一次」這個事實，不是「Root 登入了」。
// 把來源寫成明確的引數而不是留在註解裡，是為了讓日後接上 Root 認証時，
// 「該換哪一行」只有一個答案，而現在這一行不可能被誤寫成 root。
func restoreAuditRecord(manifest backup.Manifest, bundle, into string) (audit.Record, error) {
	actor, err := cliSystemActor()
	if err != nil {
		return audit.Record{}, err
	}
	return audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  actor,
		Action: "server.restore",
		Target: audit.Target{Kind: "server"},
		Reason: fmt.Sprintf("從備份包恢復到新的資料目錄（清單 %s、結構版本 %d、%d 個檔案）",
			manifest.CreatedAt, manifest.Database.SchemaVersion, manifest.Totals.Files),
		Changes: []audit.Change{
			{Field: "backup_path", After: bundle},
			{Field: "data_dir", After: into},
			{Field: "backup_created_at", After: manifest.CreatedAt},
			{Field: "schema_version", After: manifest.Database.SchemaVersion},
			{Field: "files", After: manifest.Totals.Files},
			{Field: "bytes", After: manifest.Totals.Bytes},
		},
	}, nil
}

// cliSystemActor 把「執行檔被跑了一次」這件事換成受信主體的審計操作者表示。
//
// 單獨抽出來是因為它會回錯誤：構造失敗時這筆審計就不該寫（不降級成
// 「沒有主體的記錄」），而呼叫端要拿到的是原因明確的錯誤，不是猜。
func cliSystemActor() (audit.Actor, error) {
	principal, err := identity.NewSystem(identity.OriginCLI)
	if err != nil {
		return audit.Actor{}, fmt.Errorf("app: 構造 CLI 系統主體失敗: %w", err)
	}
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Actor{}, fmt.Errorf("app: 構造 CLI 審計主體失敗: %w", err)
	}
	return actor, nil
}

// parseRestoreArgs 取出 restore 子命令自己的引數，其餘交回組態解析（--data-dir 等）。
//
// 這裡不用 flag 包：標準 flag 解析遇到第一個非旗標引數就停，而本專案的組態旗標
// （--data-dir）也是這次引數的一部分，兩者混在同一個列表裡。
// 重複給同一個旗標一律拒絕而不是「以最後一次為準」——兩個不同的值同時出現時，
// 靜默選一個就是猜使用者的意思。
func parseRestoreArgs(args []string) (bundle, into string, dryRun bool, rest []string, err error) {
	rest = make([]string, 0, len(args))
	takeValue := func(name string, dst *string, i *int) error {
		if *dst != "" {
			return fmt.Errorf("app: restore 的 --%s 重複給出（%q 與下一個）", name, *dst)
		}
		if *i+1 >= len(args) {
			return fmt.Errorf("app: restore 的 --%s 需要一個值", name)
		}
		*i++
		*dst = args[*i]
		return nil
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--bundle":
			if err = takeValue("bundle", &bundle, &i); err != nil {
				return "", "", false, nil, err
			}
		case strings.HasPrefix(arg, "--bundle="):
			if bundle != "" {
				return "", "", false, nil, fmt.Errorf("app: restore 的 --bundle 重複給出")
			}
			bundle = strings.TrimPrefix(arg, "--bundle=")
		case arg == "--into":
			if err = takeValue("into", &into, &i); err != nil {
				return "", "", false, nil, err
			}
		case strings.HasPrefix(arg, "--into="):
			if into != "" {
				return "", "", false, nil, fmt.Errorf("app: restore 的 --into 重複給出")
			}
			into = strings.TrimPrefix(arg, "--into=")
		case arg == "--dry-run", arg == "-dry-run":
			dryRun = true
		default:
			rest = append(rest, arg)
		}
	}
	if bundle == "" {
		return "", "", false, nil, errors.New("app: restore 需要 --bundle <備份包目錄>；" +
			"本命令不猜要恢復哪一份（備份包在 backups/ 下按 UTC 時間戳命名）")
	}
	if into == "" {
		return "", "", false, nil, errors.New("app: restore 需要 --into <新的空資料目錄>；" +
			"本命令一律不覆蓋既有目錄，所以要明確指出落點")
	}
	return bundle, into, dryRun, rest, nil
}

// restoreBundleNote 產生報告裡關於這個包本身的一段。
func restoreBundleNote(res restore.Result) string {
	m := res.Manifest
	var lines strings.Builder
	lines.WriteString("備份包：" + res.Bundle + "\n")
	fmt.Fprintf(&lines, "  清單：format_version=%d、產生於 %s、產生端 %s %s\n",
		m.FormatVersion, m.CreatedAt, m.Product, m.ServerVersion)
	fmt.Fprintf(&lines, "  來源：%s（只為排錯；落點由 --into 決定，不讀這一行）\n", m.Source.DataDir)
	return lines.String()
}

// restoreTargetNote 產生報告裡目標目錄那一句。
//
// 「目標必須是空的或不存在」這條判定在 internal/restore 裡，報告這裡不重複講條件，
// 只把這次實際落地的地方寫出來。
func restoreTargetNote(into string) string {
	return fmt.Sprintf("目標資料目錄：%s\n", into)
}

// restoreConfigNote 把包內那份組態以目標目錄為基準解析後的六個路徑寫出來。
//
// 這一段存在的理由是決策 4 的那條：不改寫組態，但必須讓「那個目錄之後會去哪裡」看得見。
// data_dir 那一行特別點名：包裡記的多數是「.」，而它對落點沒有影響——
// 影響的是「下次啟動要不要帶 --data-dir」，這件事不寫出來就會變成第二天查半天的疑難。
func restoreConfigNote(res restore.Result) string {
	keys := []string{"database.path", "media", "documents", "attachments", "backups", "logs.dir"}
	var lines strings.Builder
	lines.WriteString("包內組態以目標目錄解析後的路徑（本命令不改寫這份組態，只按這組路徑落地）：\n")
	for _, key := range keys {
		fmt.Fprintf(&lines, "  %s = %s\n", key, res.Plan.Review.Effective[key])
	}
	raw := res.Plan.Review.BundleDataDir
	if raw == "" {
		raw = "（未記載）"
	}
	fmt.Fprintf(&lines, "  提示：包內 server.data_dir 記為 %q，它不影響落點；"+
		"日後啟動這個目錄請帶 --data-dir %q\n", raw, res.Target)
	return lines.String()
}

// restoreFactsNote 把一次「實際讀到的資料庫事實」排成兩行，並點名這一次讀的是哪一份。
//
// 兩個讀取時機（包內原件、落地後）用同一個格式印出來，比較才是逐字可比的；
// 「恢復後的資料庫與清單相符」這句話在報告裡以兩段相同數字的形式存在。
func restoreFactsNote(label string, info database.SnapshotInfo) string {
	var lines strings.Builder
	fmt.Fprintf(&lines, "%s：integrity=%s、foreign_key_check=%d 筆違規、結構版本=%d"+
		"（檔頭 user_version=%d）、application_id=0x%08x、journal_mode=%s\n",
		label, info.Integrity, info.ForeignKeyViolations, info.SchemaVersion,
		info.HeaderSchemaVersion, info.ApplicationID, info.JournalMode)
	if len(info.Tables) == 0 {
		lines.WriteString("  資料庫表列數：（沒有資料表）\n")
		return lines.String()
	}
	parts := make([]string, 0, len(info.Tables))
	for _, t := range info.Tables {
		parts = append(parts, fmt.Sprintf("%s=%d", t.Table, t.Rows))
	}
	fmt.Fprintf(&lines, "  資料庫表列數：%s\n", strings.Join(parts, "、"))
	return lines.String()
}

// restoreAuditNote 說明那筆恢復審計寫進了哪、或為什麼沒寫。
//
// 沒寫時這個目錄裡就少一條 OPS-008 要求的記錄，這件事必須由報告講出來而不是默默通過；
// 目前唯一可能的原因是那份包來自尚未建立 root_audit 表的資料庫（結構版本低於 2）。
func restoreAuditNote(res restore.Result) string {
	if res.AuditSkipped != "" {
		return fmt.Sprintf("恢復審計：未寫入 Root 審計（%s）；"+
			"這代表這個目錄裡的服務啟動後才會建立那張表。\n", res.AuditSkipped)
	}
	return fmt.Sprintf("恢復審計：已追加 1 筆 Root 記錄（id=%s、action=server.restore、actor=system）；"+
		"這一筆是恢復動作自己留下的，所以 root_audit 會比清單多 1 列。\n", res.AuditID)
}

// restoreSideFilesNote 說明可寫開啟留下的副產物怎麼處理了。
//
// -wal 留下不刪是有理由的：剛追加的那筆審計可能就還在那個檔案裡，
// 刪掉它是把已經寫進去的東西丟掉；下次啟動會自行把它合併進主檔。
func restoreSideFilesNote(res restore.Result) string {
	if len(res.SideFiles.Removed) == 0 && len(res.SideFiles.Kept) == 0 {
		return "副產物：無（這一次沒有以可寫開啟那個庫）\n"
	}
	var lines strings.Builder
	if len(res.SideFiles.Removed) > 0 {
		fmt.Fprintf(&lines, "副產物：已清理 %s（單寫入實例鎖檔與 -shm，兩者不含資料）\n",
			strings.Join(res.SideFiles.Removed, "、"))
	}
	if len(res.SideFiles.Kept) > 0 {
		fmt.Fprintf(&lines, "        保留 %s（未合併的已提交內容在裡面，下次啟動自行合併）\n",
			strings.Join(res.SideFiles.Kept, "、"))
	}
	return lines.String()
}

// restoreStaleNote 回報同一個父目錄裡上一次異常結束留下的暫存目錄。
//
// 與備份包同一個道理：不代刪，因為並行的另一次恢復可能正在其中寫東西。
func restoreStaleNote(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return fmt.Sprintf("提示：目標目錄的父目錄有 %d 個未完成的還原暫存目錄：%s\n"+
		"它們不會被當成已恢復的目錄，確認沒有恢復正在執行之後可以刪除。\n",
		len(names), strings.Join(names, "、"))
}

// restoreVersionNote 在包內的結構版本低於本執行檔已知版本時說明之後會發生什麼。
//
// 這一條不動手：恢復流程不執行遷移，讓「恢復出來的庫的結構版本與清單相同」這句話保持為真，
// 升級屬下次啟動服務時的事（DEC-011 只前向）。
func restoreVersionNote(res restore.Result, knownVersion int) string {
	got := res.BundleFacts.SchemaVersion
	if got >= knownVersion {
		return ""
	}
	return fmt.Sprintf("結構版本：%d 低於本執行檔已知的 %d；這個目錄下次啟動時會前向遷移升級，"+
		"本命令不動結構。\n", got, knownVersion)
}
