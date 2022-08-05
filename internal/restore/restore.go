// Package restore 實作從備份包恢復的最小入口：把一份備份包整份落地成一個新的資料目錄，
// 並在發布前把資料核對完。
//
// 為什麼要在恢復當時就核對（規格 NFR-011、OPS-008）：一份沒人核對過的備份，
// 它的價值要到真正要用的那天才知道，而那天通常已經沒有別的副本了。
// 本套件因此把「核對」做成流程的一部分而不是後續動作：
// 逐檔摘要 → 快照內的資料庫事實 → 落地後重讀一次 → 逐表行數與結構版本再比一次，
// 任何一步不符都不發布（目標目錄保持原樣）。
//
// 三條不可讓步：
//   - 不覆蓋任何既有目錄。目標必須是空的或不存在，而且不得是本次程序設定的資料目錄、
//     也不得是清單記著的來源目錄。「先備份當前狀態再覆蓋」這條運維需求落在命令本身之外：
//     本套件不提供一條能寫進既有目錄的路徑，因此也不需要猜「這次是不是真的要蓋」。
//   - 全有或全無。所有內容先在目標目錄旁的暫存目錄裡做完，最後一次改名發布；
//     中途任何失敗都只留下一個以 . 開頭、.restoring.tmp 結尾的目錄，不會留下半個資料目錄。
//   - 判定動筆前先做完。清單解析、摘要核對、版本比較、落點規劃、空間判定全部在
//     寫第一個位元組之前完成，所以「拒絕」的表現是那個目錄根本沒被建立，而不是要刪掉一些東西。
//
// 邊界：本套件認識組態（落點由包內那份 config.yaml 決定）與備份清單（讀取端就是它），
// 但不認識交易策略、身份與日誌管線——那三者由呼叫端注入，與存儲層不認識磁碟、
// 傳輸層不認識日誌管線是同條邊界（DEC-013、DEC-027、DEC-033）。
package restore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/kagurazakayashi/EvernightRealm/internal/backup"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/disk"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// 包內兩個非內容目錄的類別名（與產生端 backup 裡未導出的常量同值；
// 產生端把清單條目的 kind 寫成這兩個字串，讀取端據此分派落點）。
const (
	kindDatabase = "database"
	kindConfig   = "config"

	// configTargetName 是組態副本在目標資料目錄裡的名字——它必須正好是服務要找的那個路徑，
	// 而那個路徑的唯一定義點是 config.Config.ConfigFile()。
	configTargetName = "config.yaml"

	// rootAuditTable 是判斷「這份包能不能收一筆恢復審計」的依據。
	rootAuditTable = "root_audit"

	// stagingSuffix 是暫存目錄的結尾；它和備份包的暫存目錄形狀不同，
	// 因為兩者在同一個目錄裡可能同時存在（一份備份包與一次進行中的恢復）。
	stagingSuffix = ".restoring.tmp"

	// copyBufferSize 是複製用的緩衝區大小；與產生端一致，兩邊的耗時才可直接比較。
	copyBufferSize = 256 << 10
)

// 恢復流程的錯誤；呼叫端以 errors.Is 判定。分類不可混看：
// 「這個包本身壞了」「這個包是好包但不適合落地在這個目錄」「落地過程中斷了」是三種不同的處置。
var (
	// ErrManifestMissing 表示包裡沒有 manifest.json（這不是一份備份包）。
	ErrManifestMissing = errors.New("restore: 備份包裡沒有清單")
	// ErrFormatUnsupported 表示清單的內容格式或產生端不是本程式認得的樣子。
	// 不去猜欄位語意：猜錯的表現是把還原不出來的東西當成已還原。
	ErrFormatUnsupported = errors.New("restore: 備份包格式不受支援")
	// ErrManifestShape 表示清單解析出來但形狀不對（該有的條目不存在或有重複）。
	ErrManifestShape = errors.New("restore: 備份清單形狀不正確")
	// ErrBundleShape 表示包裡的目錄結構與清單的宣稱不符。
	ErrBundleShape = errors.New("restore: 備份包目錄形狀不正確")
	// ErrKindUnknown 表示清單裡出現本程式不認識的類別。
	// 拒絕而不是跳過：跳過的依據是「這個類別大概不重要」，而這個判斷沒有人做過——
	// 一個未來的包多了一類內容，本程式該說「我讀不懂這份包」，而不是恢復出一個少一樣東西的目錄。
	ErrKindUnknown = errors.New("restore: 備份清單裡有本程式不認識的類別")
	// ErrChecksumMismatch 表示至少一個檔案的大小或摘要與清單不符。
	ErrChecksumMismatch = errors.New("restore: 檔案摘要與清單不符，拒絕恢復")
	// ErrUnlistedFile 表示包裡有清單沒記的檔案——那份東西不在任何記錄裡，
	// 既不會被恢復，也不該被假裝不存在。
	ErrUnlistedFile = errors.New("restore: 備份包內有清單未記載的檔案")
	// ErrSpecialFile 表示包裡出現符號連結或非普通檔。跟隨連結等於把包外的檔案當成包內內容，
	// 跳過等於遺漏，兩者都不如當場拒絕。
	ErrSpecialFile = errors.New("restore: 備份包含無法處理的特殊檔案")
	// ErrSchemaTooNew 表示包內的結構版本高於本執行檔已知的版本。
	ErrSchemaTooNew = errors.New("restore: 備份的資料庫版本比本程式還新，請先升級程式再恢復")
	// ErrSpace 表示空間判定未通過（不足、查不出來、或裝不下這份包）。
	ErrSpace = errors.New("restore: 磁碟空間判定未通過，未開始恢復")
	// ErrTargetNotEmpty 表示目標資料目錄已存在且不是空的（或根本不是目錄）。
	// 這一條不開放任何繞過通路：覆蓋既有目錄需要「先備份當前狀態」那一半還沒有的能力。
	ErrTargetNotEmpty = errors.New("restore: 目標資料目錄不是空的，拒絕覆蓋")
	// ErrTargetIsCurrent 表示目標就是本次程序設定的資料目錄。
	ErrTargetIsCurrent = errors.New("restore: 目標目錄是本次程序設定的資料目錄，拒絕覆蓋")
	// ErrTargetIsSource 表示目標就是清單記著的來源目錄。
	ErrTargetIsSource = errors.New("restore: 目標目錄是這份備份的來源目錄，拒絕覆蓋")
	// ErrOverlappingPaths 表示來源與目標互相包含。
	ErrOverlappingPaths = errors.New("restore: 備份包與目標目錄互相包含，無法確定複製的邊界")
	// ErrPathOutsideTarget 表示包內那份組態把某個目錄指到目標目錄之外。
	ErrPathOutsideTarget = errors.New("restore: 包內組態的路徑落在目標目錄之外")
	// ErrLandingCollision 表示兩個包內檔案要落地成同一個路徑。
	ErrLandingCollision = errors.New("restore: 兩個檔案要落地到同一路徑")
	// ErrUnsoundRestored 表示落地後的資料庫自身完整性檢查未過。
	ErrUnsoundRestored = errors.New("restore: 恢復出來的資料庫完整性檢查未通過，不予發布")
	// ErrFactMismatch 表示實際讀到的資料庫事實與清單不符。
	ErrFactMismatch = errors.New("restore: 恢復出來的資料與清單核對不符，不予發布")
	// ErrPublish 表示最後那次改名發布失敗。
	ErrPublish = errors.New("restore: 發布恢復結果失敗")
)

// Options 是一次恢復所需的全部輸入。零值不可用，必要欄位由 validate 檢查。
//
// 三個外部能力以函式值注入：讀快照事實是存儲層、空間判定是 internal/disk、
// 寫那筆恢復審計是呼叫端的事（它才知道交易策略與時鐘從哪裡來）。
type Options struct {
	// Bundle 是備份包目錄的絕對路徑（唯讀來源）。
	Bundle string
	// Target 是目標資料目錄的絕對路徑（本次唯一的寫入落點，含暫存目錄的父目錄）。
	Target string
	// CurrentDataDir 是本次程序依組態設定的資料目錄；等於 Target 即拒絕，
	// 這一條把「不覆蓋當前開發目錄」從使用約定變成程式判定。
	CurrentDataDir string
	// KnownSchemaVersion 是本執行檔內嵌遷移的最高版本，用於版本比較。
	KnownSchemaVersion int
	// DryRun 只做完全部判定並報告，不寫入任何檔案（包含不建立目標目錄）。
	DryRun bool
	// Inspect 讀回一個資料庫檔案的可核對事實（實作在 internal/database，唯讀連線）。
	Inspect func(ctx context.Context, path string) (database.SnapshotInfo, error)
	// Disk 是動筆前的磁碟空間判定（實作在 internal/disk 的 Monitor，針對目標所在卷）。
	Disk func() (disk.Verdict, error)
	// AppendAudit 把一筆恢復事件寫進指定的資料庫檔案，回傳該筆記錄標識。
	// 清單一併傳給呼叫端：那一筆審計要記的是「從哪份包、於何時備的、結構版本幾多少個檔案」，
	// 這些只有清單有，讓呼叫端再去讀一次檔案會多出第三份真相。
	// 為 nil 時不寫（呼叫端自行決定要不要，並在報告裡說明）。
	AppendAudit func(ctx context.Context, databasePath string, manifest backup.Manifest) (idgen.ID, error)
}

// Result 是一次恢復的產出。
type Result struct {
	// Bundle 與 Target 是本次的來源與去處（皆絕對路徑）。
	Bundle string
	Target string
	// Manifest 是包內清單的內容（報告與核對都讀這一份，不再各讀一次檔案）。
	Manifest backup.Manifest
	// Plan 是落點規劃：每個檔案與目錄要落在目標目錄的哪裡，以及包內組態的解析結果。
	Plan Plan
	// BundleFacts 是直接從包內那份快照讀回的事實；核對清單用的就是這一次讀到的值。
	BundleFacts database.SnapshotInfo
	// RestoredFacts 是落地後讀回的事實（含那筆恢復審計在內的最終狀態）。
	// --dry-run 時與 BundleFacts 相同（那時沒有落地，也沒有追加）。
	RestoredFacts database.SnapshotInfo
	// AuditID 是寫入目標庫的恢復審計標識；未寫時為零值。
	AuditID idgen.ID
	// AuditSkipped 是沒有寫入審計時的原因；寫入成功時為空字串。
	//
	// 唯一會發生的原因是那份包來自尚未建立 root_audit 表的資料庫（結構版本低於 2）：
	// 往一個沒有這張庫的檔案追加記錄不會成功，而「恢復了但仍要啟動服務才會建表」
	// 是必須看得見的一句話，不能吞掉。
	AuditSkipped string
	// FilesWritten 與 BytesWritten 是實際寫入目標的內容數量（--dry-run 時皆為 0）。
	FilesWritten int
	BytesWritten int64
	// SideFiles 是本次可寫開啟在暫存目錄裡留下的副產物的分類結果（清掉了哪些、留下了哪個 -wal）。
	SideFiles SideFiles
	// StaleStaging 是目標目錄的父目錄裡、上一次異常結束留下的暫存目錄名。
	// 本命令不刪它們：並行的另一次恢復可能正在其中寫東西。
	StaleStaging []string
	// DryRun 表示這一次只核對、未寫入任何東西。
	DryRun bool
	// Published 表示最後那次改名已完成，目標目錄此刻是一份可用的資料目錄。
	Published bool
}

// Execute 從一份備份包恢復出一個新的資料目錄。
//
// 次序是有意義的：全部判定動筆前做完，落地後再核對一次，最後一次改名發布。
// 任何一步失敗都回傳錯誤且目標目錄維持原狀（通常是「還不存在」）；
// 已寫入的暫存目錄一律清掉，但別次的殘留只回報不代刪。
func Execute(ctx context.Context, opts Options) (Result, error) {
	if err := opts.validate(); err != nil {
		return Result{}, err
	}

	manifest, err := readManifest(opts.Bundle)
	if err != nil {
		return Result{}, err
	}
	dbEntry, configEntry, err := manifestDatabaseAndConfig(manifest)
	if err != nil {
		return Result{}, err
	}

	// 版本比較放在動筆前：一份「比本程式還新」的包現在還恢復不了，
	// 而這件事最好的揭露時機是運維正站在終端機前，不是下次啟動服務的時候。
	if manifest.Database.SchemaVersion > opts.KnownSchemaVersion {
		return Result{}, fmt.Errorf("%w：清單記的結構版本 %d 高於本執行檔已知的 %d；"+
			"請先改用較新的執行檔再恢復（本程式不會把庫降級到它認得的版本）",
			ErrSchemaTooNew, manifest.Database.SchemaVersion, opts.KnownSchemaVersion)
	}

	if err := checkTarget(opts, manifest.Source.DataDir, manifest.CreatedAt); err != nil {
		return Result{}, err
	}

	if err := checkSpace(opts, manifest); err != nil {
		return Result{}, err
	}

	// 摘要核對在讀資料庫之前：清單裡那句話必須先對得上磁盤上的位元組，
	// 之後從包內那份檔案讀到的任何事實才有一個可說的來源。
	if err := verifyBundleFiles(opts.Bundle, manifest); err != nil {
		return Result{}, err
	}

	bundleDB := filepath.Join(opts.Bundle, filepath.FromSlash(dbEntry.Path))
	bundleFacts, err := opts.Inspect(ctx, bundleDB)
	if err != nil {
		return Result{}, err
	}
	if mismatches := compareWithManifest(bundleFacts, manifest.Database); len(mismatches) > 0 {
		return Result{}, fmt.Errorf("%w（尚未寫入任何檔案）：%s", ErrFactMismatch, strings.Join(mismatches, "；"))
	}

	bundleCfg, err := loadBundleConfig(opts.Bundle, opts.Target, configEntry.Path)
	if err != nil {
		return Result{}, err
	}
	plan, err := buildPlan(opts.Bundle, manifest, bundleCfg, opts.Target)
	if err != nil {
		return Result{}, err
	}

	result := Result{
		Bundle: opts.Bundle, Target: opts.Target, Manifest: manifest, Plan: plan,
		BundleFacts: bundleFacts, RestoredFacts: bundleFacts, DryRun: opts.DryRun,
	}
	if opts.DryRun {
		return result, nil
	}

	staging, stale, err := prepareStaging(opts.Target)
	if err != nil {
		return Result{}, err
	}
	result.StaleStaging = stale
	if err := writeBundleTo(opts.Bundle, staging, plan); err != nil {
		_ = os.RemoveAll(staging)
		return Result{}, err
	}
	result.FilesWritten = len(plan.Files)
	result.BytesWritten = manifest.Totals.Bytes

	stagedDB := filepath.Join(staging, filepath.FromSlash(plan.DatabaseRel))
	stagedFacts, err := opts.Inspect(ctx, stagedDB)
	if err != nil {
		_ = os.RemoveAll(staging)
		return Result{}, err
	}
	if mismatches := compareWithManifest(stagedFacts, manifest.Database); len(mismatches) > 0 {
		_ = os.RemoveAll(staging)
		return Result{}, fmt.Errorf("%w（暫存目錄已清，目標目錄未被建立）：%s",
			ErrFactMismatch, strings.Join(mismatches, "；"))
	}
	result.RestoredFacts = stagedFacts

	if opts.AppendAudit != nil {
		if !hasTable(stagedFacts.Tables, rootAuditTable) {
			result.AuditSkipped = fmt.Sprintf("目標庫沒有 %s 表（結構版本 %d），無法追加這筆",
				rootAuditTable, stagedFacts.SchemaVersion)
		} else {
			id, err := opts.AppendAudit(ctx, stagedDB, manifest)
			if err != nil {
				_ = os.RemoveAll(staging)
				return Result{}, fmt.Errorf("restore: 寫入恢復審計失敗（暫存目錄已清，目標目錄未被建立）: %w", err)
			}
			result.AuditID = id
			afterFacts, err := opts.Inspect(ctx, stagedDB)
			if err != nil {
				_ = os.RemoveAll(staging)
				return Result{}, err
			}
			if problems := auditDeltaProblems(stagedFacts, afterFacts); len(problems) > 0 {
				_ = os.RemoveAll(staging)
				return Result{}, fmt.Errorf("%w（追加那筆審計之後讀到的狀態不對，暫存目錄已清）：%s",
					ErrFactMismatch, strings.Join(problems, "；"))
			}
			result.RestoredFacts = afterFacts
		}
	}

	side, err := inspectSideFiles(staging, stagedDB, plan)
	if err != nil {
		_ = os.RemoveAll(staging)
		return Result{}, err
	}
	result.SideFiles = side

	if err := publish(staging, opts.Target); err != nil {
		_ = os.RemoveAll(staging)
		return Result{}, err
	}
	result.Published = true
	return result, nil
}

// checkTarget 確認目標目錄可以成為一份新的資料目錄。
//
// 「非空即拒」在這裡同時擋掉兩種事故：把既有資料蓋掉，以及對一個正在被服務使用的目錄動筆
// （服務跑起來之後它的資料目錄裡必定有 evernight.db 與 -wal，那就不是空目錄）。
// 這條判定因此是本命令取代「維護模式」的那一道門：不開放任何會與線上寫入者相撞的通路。
//
// 來源目錄（清單記的 data_dir）另外比一次：在本機重跑同一份包時，它就是「把自己備份的東西
// 蓋回自己」那句話——那個目錄此刻可能有比備份更新的東西，而本命令沒有先備份它的能力。
func checkTarget(opts Options, sourceDataDir, bundleCreatedAt string) error {
	if samePath(opts.Target, opts.CurrentDataDir) {
		return fmt.Errorf("%w：%s", ErrTargetIsCurrent, opts.Target)
	}
	if sourceDataDir != "" && samePath(opts.Target, sourceDataDir) {
		return fmt.Errorf("%w：%s 是這份包的來源目錄（備份產生於 %s）",
			ErrTargetIsSource, opts.Target, bundleCreatedAt)
	}
	if samePath(opts.Target, opts.Bundle) || within(opts.Bundle, opts.Target) || within(opts.Target, opts.Bundle) {
		return fmt.Errorf("%w：來源 %s 與目標 %s", ErrOverlappingPaths, opts.Bundle, opts.Target)
	}
	info, err := os.Stat(opts.Target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("restore: 檢查目標目錄失敗（%s）: %w", opts.Target, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w：%s 是一個檔案而不是目錄", ErrTargetNotEmpty, opts.Target)
	}
	entries, err := os.ReadDir(opts.Target)
	if err != nil {
		return fmt.Errorf("restore: 讀取目標目錄失敗（%s）: %w", opts.Target, err)
	}
	if len(entries) > 0 {
		names := make([]string, 0, len(entries))
		for i, e := range entries {
			if i >= 5 {
				names = append(names, fmt.Sprintf("…（共 %d 項）", len(entries)))
				break
			}
			names = append(names, e.Name())
		}
		return fmt.Errorf("%w：%s 已存在且不是空的（%s）；請換一個空目錄，或先把那裡的東西自己備份走。"+
			"本命令不會覆蓋既有目錄，也不會替你先做一次備份",
			ErrTargetNotEmpty, opts.Target, strings.Join(names, "、"))
	}
	return nil
}

// checkSpace 在動筆前問一次磁碟：判定未過或裝不下都拒絕。
//
// 兩道是不同的問題：閾值是「部署者設的下限」，裝不下是「這份包本身寫得進去嗎」。
// 只查前者時，沒設下限（預設就是沒設）等於完全沒查——而恢復恰好是最不能寫到一半的時候。
func checkSpace(opts Options, manifest backup.Manifest) error {
	verdict, err := opts.Disk()
	if err != nil {
		return fmt.Errorf("restore: 磁碟空間判定失敗: %w", err)
	}
	if verdict.Status != disk.StatusOK {
		return fmt.Errorf("%w（%s）：%s", ErrSpace, verdict.Status.String(), verdict.Reason)
	}
	required := uint64(manifest.Totals.Bytes)
	// 快照落地後會被可寫開啟一次（追加那筆審計），WAL 與副本都需要餘裕；
	// 這裡用兩倍作為「裝不下」的判準，是一個明講的保守數而不是測出來的門檻。
	need := required + required/2
	if verdict.Usage.Free > 0 && need > verdict.Usage.Free {
		return fmt.Errorf("%w：這份包 %s（連同落地後的暫存餘裕共需約 %s），而 %s 剩餘只有 %s",
			ErrSpace, disk.HumanBytes(required), disk.HumanBytes(need),
			verdict.Usage.Path, disk.HumanBytes(verdict.Usage.Free))
	}
	return nil
}

// loadBundleConfig 讀包內那份 config.yaml，以 target 作為資料目錄解析。
//
// 這一條解析不改動任何檔案，也只回答「服務下次以 --data-dir target 啟動時會看到哪些路徑」。
// 用的就是服務那套 Load+Resolve（含命令列 > 環境 > 檔案 > 預設的優先序），
// 所以本次算出的落點與日後啟動實際用的路徑是同一份規則，不會出現兩套答案。
func loadBundleConfig(bundleDir, target, configRel string) (config.Config, error) {
	opts := config.Options{DataDir: target, ConfigPath: filepath.Join(bundleDir, filepath.FromSlash(configRel))}
	cfg, err := config.Load(opts)
	if err != nil {
		return config.Config{}, err
	}
	if err := cfg.Resolve(); err != nil {
		return config.Config{}, fmt.Errorf("restore: 以目標目錄解析包內組態失敗: %w", err)
	}
	return cfg, nil
}

// prepareStaging 建立暫存目錄並回報父目錄裡既存的殘留。
//
// 暫存目錄是目標目錄的兄弟（同一個卷、同一個父目錄），因此最後一次改名是同名卷內的
// 中斷點搬移，而不是跨卷複製；這是「全有或全無」在檔案系統層的唯一實現方式。
func prepareStaging(target string) (string, []string, error) {
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", nil, fmt.Errorf("restore: 建立目標目錄的父目錄失敗（%s）: %w", parent, err)
	}
	base := filepath.Base(target)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "", nil, fmt.Errorf("restore: 無法從目標目錄 %s 推導暫存目錄名", target)
	}
	staging := filepath.Join(parent, "."+base+stagingSuffix)
	stale, err := listStaleStaging(parent, filepath.Base(staging))
	if err != nil {
		return "", nil, err
	}
	// 自己的暫存目錄先刪後用：這個名字完全由目標目錄名派生，裡面只可能是本命令自己寫的東西；
	// 複用它反而可能把上一次異常留下的半成品當成這一份的一部分。
	if err := os.RemoveAll(staging); err != nil {
		return "", nil, fmt.Errorf("restore: 清理殘留暫存目錄失敗（%s）: %w", staging, err)
	}
	if err := os.MkdirAll(staging, 0o750); err != nil {
		return "", nil, fmt.Errorf("restore: 建立暫存目錄失敗（%s）: %w", staging, err)
	}
	return staging, stale, nil
}

// listStaleStaging 列出父目錄裡「不是本次的」暫存目錄名。
//
// 判據只用名字形狀（以 . 開頭、.restoring.tmp 結尾）。其他東西一律不認也不動，
// 包括同一個資料目錄旁邊的既有目錄——那可能是別人的。
func listStaleStaging(parent, ours string) ([]string, error) {
	entries, err := os.ReadDir(parent)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("restore: 讀取目標目錄的父目錄失敗（%s）: %w", parent, err)
	}
	var stale []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == ours {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") && strings.HasSuffix(e.Name(), stagingSuffix) {
			stale = append(stale, e.Name())
		}
	}
	sort.Strings(stale)
	return stale, nil
}

// writeBundleTo 把包內內容按落點規劃寫進暫存目錄。
//
// 目錄先建、檔案後寫：清單只記檔案，空的內容目錄是靠走訪得來的，
// 不建它們的話恢復出來的資料目錄就少一個服務之後會用到（而不會自己創造）的位置。
// 寫入全程只碰暫存目錄，目標目錄在這一步結束時仍未被建立。
func writeBundleTo(bundleDir, staging string, plan Plan) error {
	for _, dir := range plan.Dirs {
		if err := os.MkdirAll(filepath.Join(staging, filepath.FromSlash(dir.TargetRel)), 0o750); err != nil {
			return fmt.Errorf("restore: 建立目錄失敗（%s）: %w", dir.TargetRel, err)
		}
	}
	for _, landing := range plan.Files {
		if err := copyFile(
			filepath.Join(bundleDir, filepath.FromSlash(landing.BundleRel)),
			filepath.Join(staging, filepath.FromSlash(landing.TargetRel)),
			landing.Mode,
		); err != nil {
			return err
		}
	}
	return nil
}

// copyFile 複製一個檔案並顯式設定權限（不沿用來源：來源在包裡，包在別台機器上也一樣）。
func copyFile(from, to string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
		return fmt.Errorf("restore: 建立 %s 的父目錄失敗: %w", filepath.Dir(to), err)
	}
	src, err := os.Open(from)
	if err != nil {
		return fmt.Errorf("restore: 開啟來源 %s 失敗: %w", from, err)
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return fmt.Errorf("restore: 讀取來源 %s 資訊失敗: %w", from, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w：%s（%s）", ErrSpecialFile, from, info.Mode())
	}

	dst, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("restore: 建立 %s 失敗: %w", to, err)
	}
	buf := make([]byte, copyBufferSize)
	if _, err := io.CopyBuffer(dst, src, buf); err != nil {
		_ = dst.Close()
		return fmt.Errorf("restore: 寫入 %s 失敗: %w", to, err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("restore: 關閉 %s 失敗: %w", to, err)
	}
	// O_EXCL 的建檔權限會被 umask 之類規則改動，因此建完再顯式設一次（與產生端同一處置）。
	if err := os.Chmod(to, mode); err != nil {
		return fmt.Errorf("restore: 設定 %s 權限失敗: %w", to, err)
	}
	return nil
}

// SideFiles 是本次動作在暫存目錄裡看到的副產物的分類結果。
type SideFiles struct {
	// Removed 是清掉的檔名（相對於目標目錄）：單寫入實例鎖檔與 WAL 的 -shm。
	// 兩者都是「本次可寫開啟自己留下的」，且不含任何資料：鎖檔在關閉時已釋放，
	// -shm 是可在下次開啟時重建的共享記憶體。
	Removed []string
	// Kept 是留下不刪的檔名：只有 -wal。
	// 未合併進主檔的已提交資料就在這個檔案裡，刪掉它等於把剛寫進去的那筆審計丟掉；
	// 留下它才是對的——下次服務啟動時會自己把它吸收進主檔（實測見崩潰恢復那組證據）。
	Kept []string
}

// inspectSideFiles 分類暫存目錄裡「不在恢復規劃中」的檔案，並清掉可安全清理的那幾個。
//
// 只認得三種自己造成的東西：<db>.lock、<db>-wal、<db>-shm。其他任何缺席於規劃又出現在暫存
// 目錄裡的東西都是意外，遇到即拒絕發布而不是默默刪——一份還原出來的資料目錄裡不該有
// 說不出來源的檔案，而說得出來源的才輪到我們動手。
func inspectSideFiles(staging, databasePath string, plan Plan) (SideFiles, error) {
	dir := filepath.Dir(databasePath)
	prefix := filepath.Base(databasePath)
	planned := plannedTargets(staging, plan)

	var out SideFiles
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out, fmt.Errorf("restore: 讀取暫存目錄內的資料庫目錄失敗（%s）: %w", dir, err)
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		rel, err := filepath.Rel(staging, path)
		if err != nil {
			return out, fmt.Errorf("restore: 計算暫存目錄內的相對路徑失敗（%s）: %w", path, err)
		}
		relSlash := filepath.ToSlash(rel)
		if planned[relSlash] || e.Name() == prefix {
			continue
		}
		if !e.Type().IsRegular() {
			return out, fmt.Errorf("%w：暫存目錄裡出現 %s（%s）", ErrSpecialFile, relSlash, e.Type())
		}
		switch {
		case e.Name() == prefix+".lock", strings.HasPrefix(e.Name(), prefix+"-shm"):
			if err := os.Remove(path); err != nil {
				return out, fmt.Errorf("restore: 清理副產物 %s 失敗: %w", relSlash, err)
			}
			out.Removed = append(out.Removed, relSlash)
		case strings.HasPrefix(e.Name(), prefix+"-wal"):
			out.Kept = append(out.Kept, relSlash)
		default:
			return out, fmt.Errorf("%w：暫存目錄裡的 %s 不是本次要恢復的內容，也不是本次動作的副產物",
				ErrUnlistedFile, relSlash)
		}
	}
	sort.Strings(out.Removed)
	sort.Strings(out.Kept)
	return out, nil
}

// plannedTargets 把落點規劃換成一個以斜線相對路徑為鍵的集合，用於辨認「本次自己寫的檔案」。
func plannedTargets(staging string, plan Plan) map[string]bool {
	planned := make(map[string]bool, len(plan.Files)+len(plan.Dirs))
	for _, landing := range plan.Files {
		planned[filepath.ToSlash(landing.TargetRel)] = true
	}
	for _, dir := range plan.Dirs {
		planned[filepath.ToSlash(dir.TargetRel)] = true
	}
	return planned
}

// publish 把暫存目錄改名成目標目錄：這是本次恢復唯一讓內容「生效」的動作。
//
// 目標目錄若先前存在且為空，先用 os.Remove（不是 RemoveAll）摘掉它：
// 它在這一步如果不是空的就會失敗，而那正是我們想要的結果——
// 檢查與改名之間有時間差，這段期間若有人往裡放了東西，這條讓本次恢復停住而不是蓋過去。
func publish(staging, target string) error {
	info, err := os.Stat(target)
	switch {
	case err == nil && !info.IsDir():
		return fmt.Errorf("%w：%s 在這次動作期間變成了一個檔案", ErrPublish, target)
	case err == nil:
		if rmErr := os.Remove(target); rmErr != nil {
			return fmt.Errorf("%w：%s 此刻不是空目錄（%v）；沒有覆蓋它", ErrPublish, target, rmErr)
		}
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("restore: 檢查目標目錄失敗（%s）: %w", target, err)
	}
	if err := os.Rename(staging, target); err != nil {
		return fmt.Errorf("%w（%s → %s）: %w", ErrPublish, staging, target, err)
	}
	return nil
}

// compareWithManifest 把實際讀到的資料庫事實與清單那句自述逐項對照，回傳全部不符項。
//
// 一次列全部而不是只報第一個：不符項的數目本身就是判讀（一檔不符像抄過的路徑，
// 全部不符像這個包根本是另一份東西）。外鍵違規不在對照範圍內——
// 清單裡沒有這一項（它是產生端當時未記的事），這裡只要求它為 0。
func compareWithManifest(info database.SnapshotInfo, fact backup.DatabaseFact) []string {
	var mismatches []string
	if !strings.EqualFold(strings.TrimSpace(info.Integrity), "ok") {
		mismatches = append(mismatches, fmt.Sprintf("integrity_check 回 %q（清單記 %q）", info.Integrity, fact.Integrity))
	}
	if info.ForeignKeyViolations != 0 {
		mismatches = append(mismatches, fmt.Sprintf("foreign_key_check 違規 %d 筆", info.ForeignKeyViolations))
	}
	if info.SchemaVersion != fact.SchemaVersion {
		mismatches = append(mismatches, fmt.Sprintf("版本表的結構版本 %d，清單記 %d", info.SchemaVersion, fact.SchemaVersion))
	}
	if info.HeaderSchemaVersion != fact.HeaderSchemaVersion {
		mismatches = append(mismatches, fmt.Sprintf("檔頭 user_version %d，清單記 %d",
			info.HeaderSchemaVersion, fact.HeaderSchemaVersion))
	}
	appID := fmt.Sprintf("0x%08x", info.ApplicationID)
	if !strings.EqualFold(appID, strings.TrimSpace(fact.ApplicationID)) {
		mismatches = append(mismatches, fmt.Sprintf("application_id=%s，清單記 %s", appID, fact.ApplicationID))
	}
	if info.ApplicationID != 0 && info.ApplicationID != database.ApplicationID {
		mismatches = append(mismatches, fmt.Sprintf("application_id=%s 既不是本服務的 0x%08X 也不是未標記，"+
			"這是一份他人的資料庫", appID, database.ApplicationID))
	}
	if tableDiff := diffTables(info.Tables, fact.Tables); len(tableDiff) > 0 {
		mismatches = append(mismatches, tableDiff...)
	}
	return mismatches
}

// diffTables 逐表比對行數，把「只在某一邊出現」與「兩邊數量不同」分成兩類寫出。
//
// 分兩類是因為處置不同：少表通常是包被動過結構，數量不同則是這個檔案在備份之後又被寫過。
func diffTables(actual []database.TableRows, want []database.TableRows) []string {
	got := make(map[string]int64, len(actual))
	for _, t := range actual {
		got[t.Table] = t.Rows
	}
	expect := make(map[string]int64, len(want))
	for _, t := range want {
		expect[t.Table] = t.Rows
	}
	var diff []string
	for _, t := range want {
		if rows, ok := got[t.Table]; !ok {
			diff = append(diff, fmt.Sprintf("表 %s 在清單裡記 %d 列，實際讀不到這張表", t.Table, t.Rows))
		} else if rows != t.Rows {
			diff = append(diff, fmt.Sprintf("表 %s 實際 %d 列，清單記 %d 列", t.Table, rows, t.Rows))
		}
		delete(got, t.Table)
	}
	extra := make([]string, 0, len(got))
	for name, rows := range got {
		extra = append(extra, fmt.Sprintf("%s=%d", name, rows))
	}
	sort.Strings(extra)
	for _, item := range extra {
		diff = append(diff, fmt.Sprintf("實際存在但清單未記的表：%s", item))
	}
	return diff
}

// auditDeltaProblems 檢查「追加一筆恢復審計」前後的狀態差。
//
// 應有的差只有一個：root_audit 多 1 列。其他任何變動（多一個表、別的表多列、
// 結構版本被推高）都代表這個 callback 做的事超出了一筆追加，那時不能發布。
func auditDeltaProblems(before, after database.SnapshotInfo) []string {
	var problems []string
	if !strings.EqualFold(strings.TrimSpace(after.Integrity), "ok") {
		problems = append(problems, fmt.Sprintf("追加審計後 integrity_check 回 %q", after.Integrity))
	}
	if after.ForeignKeyViolations != 0 {
		problems = append(problems, fmt.Sprintf("追加審計後 foreign_key_check 違規 %d 筆", after.ForeignKeyViolations))
	}
	if after.SchemaVersion != before.SchemaVersion {
		problems = append(problems, fmt.Sprintf("追加審計後結構版本變成 %d（原本是 %d）；"+
			"恢復流程不執行遷移，版本升級屬下次啟動服務時的事", after.SchemaVersion, before.SchemaVersion))
	}
	if strings.EqualFold(strings.TrimSpace(after.JournalMode), "delete") {
		// 可寫開啟會把庫轉成 WAL，這是預期的；反向沒轉成 WAL 表示那筆追加可能根本沒落到這個檔案。
		problems = append(problems, fmt.Sprintf("追加審計後 journal_mode 仍是 %q（可寫開啟後應為 wal）", after.JournalMode))
	}

	beforeRows := make(map[string]int64, len(before.Tables))
	for _, t := range before.Tables {
		beforeRows[t.Table] = t.Rows
	}
	seen := make(map[string]bool, len(after.Tables))
	for _, t := range after.Tables {
		seen[t.Table] = true
		base, ok := beforeRows[t.Table]
		if !ok {
			problems = append(problems, fmt.Sprintf("追加審計後多出原本沒有的表 %s", t.Table))
			continue
		}
		want := base
		if t.Table == rootAuditTable {
			want = base + 1
		}
		if t.Rows != want {
			problems = append(problems, fmt.Sprintf("表 %s 的行數從 %d 變成 %d（應為 %d）", t.Table, base, t.Rows, want))
		}
	}
	for _, t := range before.Tables {
		if !seen[t.Table] {
			problems = append(problems, fmt.Sprintf("追加審計後表 %s 讀不到了（原本是 %d 列）", t.Table, t.Rows))
		}
	}
	return problems
}

// hasTable 回傳事實清單裡是否有這張表。
func hasTable(tables []database.TableRows, name string) bool {
	for _, t := range tables {
		if t.Table == name {
			return true
		}
	}
	return false
}

// validate 檢查的是呼叫端寫錯的那一類，不是使用者配錯的那一類。
func (o Options) validate() error {
	if strings.TrimSpace(o.Bundle) == "" {
		return errors.New("restore: 缺少備份包路徑")
	}
	if strings.TrimSpace(o.Target) == "" {
		return errors.New("restore: 缺少目標資料目錄")
	}
	if !filepath.IsAbs(o.Bundle) || !filepath.IsAbs(o.Target) {
		return fmt.Errorf("restore: 來源與目標需為絕對路徑（來源 %q、目標 %q）", o.Bundle, o.Target)
	}
	if o.KnownSchemaVersion < 0 {
		return fmt.Errorf("restore: 已知結構版本不可為負（實際 %d）", o.KnownSchemaVersion)
	}
	if o.Inspect == nil || o.Disk == nil {
		return errors.New("restore: 缺少快照檢查或磁碟空間判定實作")
	}
	info, err := os.Stat(o.Bundle)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w：%s 不存在", ErrBundleShape, o.Bundle)
	}
	if err != nil {
		return fmt.Errorf("restore: 檢查備份包失敗（%s）: %w", o.Bundle, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w：%s 是一個檔案而不是目錄", ErrBundleShape, o.Bundle)
	}
	return nil
}

// samePath 比較兩條已規範化的路徑是否指向同一個地方。
//
// Windows 的路徑大小寫不敏感，而卷標與路徑都可能有兩種寫法；
// 直接用 == 會讓「P:\data」與「p:\data」看起來像兩個目錄，而覆蓋判定就形同虛設。
func samePath(a, b string) bool {
	cleanA, cleanB := filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(cleanA, cleanB)
	}
	return cleanA == cleanB
}

// within 回傳 child 是否在 parent 目錄之內（不含等於）。
func within(parent, child string) bool {
	rel, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	if err != nil {
		return false
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	if runtime.GOOS == "windows" {
		// 不同卷的 Rel 會回傳絕對路徑而不是相對段，這時它一定不在 parent 之內。
		return !filepath.IsAbs(rel)
	}
	return true
}
