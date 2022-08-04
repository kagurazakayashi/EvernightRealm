// Package backup 實作最小一致性備份：一次產出一份可整份搬走的備份包。
//
// 一份備份包是一個目錄，內容是規格 §24.3 點名的六項：資料庫（以一致性快照取出，
// 不是複製活躍的 WAL 主檔）、組態、媒體、文件、上傳檔，以及必要時隨組態一起進包的
// 密鑰材料（例如 Argon2id 的 Root 口令摘要——按原值收錄，因為遮罩過的值恢復出來是壞的）。
// 逐檔記大小與 SHA-256，再加一份 manifest.json 記錄伺服器版本、時間與資料庫可核對事實。
//
// 三個外部能力（取快照、讀回快照事實、磁碟空間判定）以函式值注入，本套件因此不認識
// SQLite 驅動、也不認識磁碟監測的實作——與傳輸層不認識日誌管線、存儲層不認識 Web 產物
// 同條邊界（DEC-016、DEC-033）。
//
// 本步不做：口令加密（§24.3）、自動排程與保留份數淘汰（OPS-007 為 P1）、
// 恢復入口（STEP-069）、下載到其他機器。
package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/disk"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// FormatVersion 是備份包的內容格式版本。
//
// 讀取端（STEP-069 的恢復入口）依這個數字決定怎麼解析，因此欄位語意變動要在這裡遞增，
// 而不是靠「大概還讀得開」。目前為 1。
const FormatVersion = 1

// Product 是清單裡記錄的產品識別。用固定字串而不是執行檔名：日後改名不會讓
// 既有備份包自認成別的東西。
const Product = "evernight-server"

// 備份包內的固定路徑與類別名：恢復端照這組名字找檔案，因此集中成常量而不是散落字串。
const (
	// DatabaseRel 是快照檔在包內的相對路徑。
	DatabaseRel = "database/evernight.db"
	// ConfigRel 是組態副本在包內的相對路徑。
	ConfigRel = "config/config.yaml"
	// ManifestName 是自述檔的檔名。
	ManifestName = "manifest.json"

	kindDatabase = "database"
	kindConfig   = "config"

	// KindMedia 等三項是內容目錄的類別識別，同時也是包內的目錄名。
	KindMedia       = "media"
	KindDocuments   = "documents"
	KindAttachments = "attachments"
)

var (
	// ErrBundleExists 表示同名備份包已存在。備份一律不覆蓋既有備份包：
	// 覆蓋會把「上一次的好備份」和「這一次的半成品」混在同一個名字下。
	ErrBundleExists = errors.New("backup: 同名備份包已存在，拒絕覆蓋")
	// ErrSpace 表示空間判定為不足或查不出來，因此沒有開始寫任何東西。
	ErrSpace = errors.New("backup: 磁碟空間判定未通過，未開始備份")
	// ErrUnsoundSnapshot 表示快照取出來了但自身完整性檢查未過，因此這份備份包不予發布。
	ErrUnsoundSnapshot = errors.New("backup: 快照完整性檢查未通過，不予發布")
	// ErrSpecialFile 表示內容目錄裡出現非普通檔（符號連結、管道、插槽等）。
	// 態度是拒絕而不是跳過：跳過等於遺漏，而「還原出來少東西」比當場失敗難察覺。
	ErrSpecialFile = errors.New("backup: 內容目錄含無法備份的特殊檔案")
)

// ContentDir 是一個要整目錄收進備份包的內容目錄。
type ContentDir struct {
	// Kind 是進清單的類別識別，同時也是包內的目錄名（見 KindMedia 等三個常量）。
	Kind string
	// Path 是來源目錄的絕對路徑（已由 config.Resolve 規範化）。
	Path string
}

// Options 是一次備份所需的全部輸入。零值不可用，必要欄位由 validate 檢查。
//
// Now 由呼叫端給時鐘讀值（DEC-015：「某事發生在幾點」取自注入的時鐘）。
// 備份包名稱與清單裡的時間都出自這同一個值，不會出現兩個版本的「幾點」。
type Options struct {
	// OutDir 是備份包根目錄（對應組態的 backups）。
	OutDir string
	// Name 是本次備份包的目錄名，需為單一檔名層級且不重複。
	Name string
	// SourceDataDir 與 SourceDatabasePath 只記錄進清單供排錯，不參與寫入路徑決定。
	SourceDataDir      string
	SourceDatabasePath string
	// ConfigPath 是要收錄的組態檔絕對路徑。
	ConfigPath string
	// ContentDirs 是要整目錄收錄的內容目錄（媒體、文件、上傳）。
	ContentDirs []ContentDir
	// Snapshot 把源庫取成指定路徑的單檔快照（實作在 internal/database）。
	Snapshot func(ctx context.Context, target string) error
	// Inspect 讀回一份快照的可核對事實（實作在 internal/database）。
	Inspect func(ctx context.Context, path string) (database.SnapshotInfo, error)
	// Disk 是動筆前的磁碟空間判定（實作在 internal/disk 的 Monitor）。
	Disk func() (disk.Verdict, error)
	// ServerVersion 是產生本備份包的執行檔版本。
	ServerVersion string
	// Now 是本次備份的時刻（UTC）。
	Now time.Time
}

// Entry 是備份包裡一個檔案的可核對資訊。
type Entry struct {
	// Kind 是來源類別（database|config|media|documents|attachments）。
	Kind string `json:"kind"`
	// Path 是相對於備份包目錄的路徑，一律斜線分隔——包要能整份搬到別的系統。
	Path string `json:"path"`
	// SizeBytes 是檔案位元組數。
	SizeBytes int64 `json:"size_bytes"`
	// SHA256 是檔案內容摘要（十六進位小寫）。
	SHA256 string `json:"sha256"`
}

// DatabaseFact 是快照那一檔的資料庫層事實。
type DatabaseFact struct {
	// Path 是快照檔在包內的相對路徑。
	Path string `json:"path"`
	// SchemaVersion 是版本表裡的最高版本（0 表示尚無版本表）。
	SchemaVersion int `json:"schema_version"`
	// Integrity 是 integrity_check 的回值；能發布的備份包這裡必定是 ok。
	Integrity string `json:"integrity"`
	// JournalMode 是快照檔自身的 journal 模式（一致性快照的產物為 delete）。
	JournalMode string `json:"journal_mode"`
	// ApplicationID 是副本檔頭的識別碼（十六進位小寫；未標記時為 0x00000000）。
	// 本服務的開庫預檢據此辨認「這是我的庫」，所以要在備份當時就記下來。
	ApplicationID string `json:"application_id"`
	// HeaderSchemaVersion 是副本檔頭的 user_version。
	HeaderSchemaVersion int `json:"header_user_version"`
	// Tables 是快照內各表的列數，依表名排序；恢復後要比對的就是這組數字。
	Tables []database.TableRows `json:"tables"`
}

// DiskFact 是備份當時的磁碟事實（判定由 internal/disk 做，這裡只記數）。
type DiskFact struct {
	// Path 是判定所依據的目錄。
	Path string `json:"path"`
	// FreeBytes 與 TotalBytes 是當時的剩餘與總容量；監測未啟用時兩者皆 0。
	FreeBytes  uint64 `json:"free_bytes"`
	TotalBytes uint64 `json:"total_bytes"`
	// Verdict 是判定的文字結果（ok|low|unknown）。
	Verdict string `json:"verdict"`
}

// Manifest 是一份備份包的自述檔內容（寫成包內的 manifest.json）。
//
// 欄位一律 snake_case（與對外 JSON 同一規則）。這個結構是 STEP-069 恢復入口的解析依據，
// 因此只增不刪；要改語意就遞增 FormatVersion。
type Manifest struct {
	// FormatVersion 是內容格式版本。
	FormatVersion int `json:"format_version"`
	// Product 與 ServerVersion 是產生端識別（§24.3 要求帶伺服器版本資訊）。
	Product       string `json:"product"`
	ServerVersion string `json:"server_version"`
	// CreatedAt 是備份時刻，RFC3339 UTC 且恆含毫秒（與 /time、資料庫同形）。
	CreatedAt string `json:"created_at"`
	// Source 記錄來源位置，只為排錯；恢復流程不得依賴它（包要能在新目錄落地）。
	Source struct {
		DataDir      string `json:"data_dir"`
		DatabaseFile string `json:"database_file"`
		ConfigFile   string `json:"config_file"`
	} `json:"source"`
	// Database 是快照檔的資料庫層事實。
	Database DatabaseFact `json:"database"`
	// Disk 是備份當時的磁碟事實。
	Disk DiskFact `json:"disk"`
	// Files 是包內除 manifest.json 之外的全部檔案，依 Path 排序。
	// 清單不含自己的摘要：一份檔案裡寫不出這份檔案自己的 SHA-256。
	Files []Entry `json:"files"`
	// Totals 是上述檔案的檔案數與位元組數合計。
	Totals struct {
		Files int   `json:"files"`
		Bytes int64 `json:"bytes"`
	} `json:"totals"`
}

// Result 是一次備份的產出。
type Result struct {
	// Dir 是最終備份包的絕對路徑。
	Dir string
	// Manifest 是寫進包內的那份自述，與檔案內容逐字相同（不另加欄位）。
	Manifest Manifest
	// ManifestBytes 是 manifest.json 的位元組數；它在 Files 之外，理由見 Manifest.Files 註解。
	ManifestBytes int64
	// StaleStaging 是本次開始前就在輸出目錄裡的臨時目錄名（以 . 開頭、.tmp 結尾）。
	//
	// 它們只能是上一次異常退出（例如被強制結束）留下的半成品。本函式刻意不刪它們：
	// 並行的第二次備份可能正在其中寫東西，刪掉就是把別人的動作弄壞。但也不能當沒看見——
	// 沒有回報途徑的垃圾只會默默佔著磁碟，因此回傳給呼叫端說明一句。
	StaleStaging []string
}

// Create 產生一份備份包。
//
// 流程刻意是「先在臨時目錄做完，最後一次改名發布」：快照失敗、完整性未過、複製中途出錯，
// 留下的都只是一個以 . 開頭、.tmp 結尾的臨時目錄，不會被當成一次成功的備份——
// 大綱這一步的完成判斷正在這裡落地：半成品不能冒充成品。
// 任何失敗路徑都清掉臨時目錄，改名失敗也清，不留第二種狀態。
func Create(ctx context.Context, opts Options) (Result, error) {
	if err := opts.validate(); err != nil {
		return Result{}, err
	}

	verdict, err := opts.Disk()
	if err != nil {
		return Result{}, fmt.Errorf("backup: 磁碟空間判定失敗: %w", err)
	}
	// 不足與查不出來都拒絕：備份是主動運維動作，失敗的代價是一行錯誤加一次重跑，
	// 而「寫到一半沒空間」的代價是一份看起來像備份的垃圾。這裡比 STEP-067 的寫入門嚴，
	// 是因為那道門護的是線上請求能不能繼續被服務，這一層護的是這份檔能不能整份恢復。
	if verdict.Status != disk.StatusOK {
		return Result{}, fmt.Errorf("%w（%s）：%s", ErrSpace, verdict.Status.String(), verdict.Reason)
	}

	final := filepath.Join(opts.OutDir, opts.Name)
	if _, err := os.Stat(final); err == nil {
		return Result{}, fmt.Errorf("%w：%s", ErrBundleExists, final)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, fmt.Errorf("backup: 檢查備份包目標 %s 失敗: %w", final, err)
	}

	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("backup: 建立備份目錄失敗（%s）: %w", opts.OutDir, err)
	}
	stale, err := listStaleStaging(opts.OutDir, opts.Name)
	if err != nil {
		return Result{}, err
	}
	staging := filepath.Join(opts.OutDir, "."+opts.Name+".tmp")
	// 臨時目錄先刪後用：它的名字完全由備份包名派生，裡面只可能是本函式自己寫的東西；
	// 複用它反而可能把上一次異常留下的半成品當成這一份的一部分。
	if err := os.RemoveAll(staging); err != nil {
		return Result{}, fmt.Errorf("backup: 清理殘留臨時目錄失敗（%s）: %w", staging, err)
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return Result{}, fmt.Errorf("backup: 建立臨時備份目錄失敗（%s）: %w", staging, err)
	}

	manifest, entriesErr := build(ctx, staging, opts, verdict)
	if entriesErr != nil {
		_ = os.RemoveAll(staging)
		return Result{}, entriesErr
	}
	manifestBytes, err := writeManifest(staging, manifest)
	if err != nil {
		_ = os.RemoveAll(staging)
		return Result{}, err
	}
	if err := os.Rename(staging, final); err != nil {
		_ = os.RemoveAll(staging)
		return Result{}, fmt.Errorf("backup: 發布備份包失敗（%s → %s）: %w", staging, final, err)
	}
	return Result{Dir: final, Manifest: manifest, ManifestBytes: manifestBytes, StaleStaging: stale}, nil
}

// listStaleStaging 列出輸出目錄裡「不是本次的」臨時目錄名。
//
// 判據只用名字形狀（以 . 開頭、.tmp 結尾），因為那是本套件唯一的產出形狀；
// 其它任何東西（舊備份包、別人在用的目錄）一律不認、也不動。
func listStaleStaging(outDir, name string) ([]string, error) {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("backup: 讀取備份目錄失敗（%s）: %w", outDir, err)
	}
	ours := "." + name + ".tmp"
	var stale []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == ours {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") && strings.HasSuffix(e.Name(), ".tmp") {
			stale = append(stale, e.Name())
		}
	}
	sort.Strings(stale)
	return stale, nil
}

// build 把全部內容寫進臨時目錄並湊齊清單；失敗時回傳錯誤，臨時目錄原樣留著由呼叫端清理。
func build(ctx context.Context, staging string, opts Options, verdict disk.Verdict) (Manifest, error) {
	var manifest Manifest
	manifest.FormatVersion = FormatVersion
	manifest.Product = Product
	manifest.ServerVersion = opts.ServerVersion
	manifest.CreatedAt = timeutil.FormatUTC(opts.Now)
	manifest.Source.DataDir = opts.SourceDataDir
	manifest.Source.DatabaseFile = opts.SourceDatabasePath
	manifest.Source.ConfigFile = opts.ConfigPath
	// 未設下限時 Verify 回的那個 OK 不含任何探測事實，Usage.Path 也是空的；
	// 清單裡留一個空字串會被讀成「判定過一個路徑不明的目錄」，這裡退回寫本次的輸出目錄。
	diskPath := verdict.Usage.Path
	if diskPath == "" {
		diskPath = opts.OutDir
	}
	manifest.Disk = DiskFact{Path: diskPath, FreeBytes: verdict.Usage.Free,
		TotalBytes: verdict.Usage.Total, Verdict: verdict.Status.String()}

	// 1) 資料庫先做：它是唯一可能「取出來了但自身壞掉」的一項，壞就不該繼續包裝。
	dbTarget := filepath.Join(staging, filepath.FromSlash(DatabaseRel))
	if err := os.MkdirAll(filepath.Dir(dbTarget), 0o755); err != nil {
		return manifest, fmt.Errorf("backup: 建立快照輸出目錄失敗: %w", err)
	}
	if err := opts.Snapshot(ctx, dbTarget); err != nil {
		return manifest, err
	}
	info, err := opts.Inspect(ctx, dbTarget)
	if err != nil {
		return manifest, err
	}
	if !strings.EqualFold(strings.TrimSpace(info.Integrity), "ok") {
		return manifest, fmt.Errorf("%w：integrity_check 回 %q", ErrUnsoundSnapshot, info.Integrity)
	}
	manifest.Database = DatabaseFact{
		Path: DatabaseRel, SchemaVersion: info.SchemaVersion, Integrity: info.Integrity,
		JournalMode: info.JournalMode, ApplicationID: fmt.Sprintf("0x%08x", info.ApplicationID),
		HeaderSchemaVersion: info.HeaderSchemaVersion,
		// 空表清單寫成空陣列而不是 null：恢復端解析時不必多判一種型別。
		Tables: nonNilTables(info.Tables),
	}
	entry, err := digestInto(kindDatabase, DatabaseRel, dbTarget)
	if err != nil {
		return manifest, err
	}
	manifest.Files = append(manifest.Files, entry)

	// 2) 組態：含 Argon2id 口令摘要與可能的密鑰材料，按原值收錄、不脫敏。
	//    internal/redact 是 §7 遮罩的唯一一份，它管的是日誌與審計，不是備份——
	//    備份的意義是可恢復，遮罩過的值恢復出來是壞的。
	if _, err := os.Stat(opts.ConfigPath); err != nil {
		return manifest, fmt.Errorf("backup: 找不到要收錄的組態檔（%s）: %w", opts.ConfigPath, err)
	}
	copyEntry, err := copyInto(kindConfig, ConfigRel, opts.ConfigPath, staging, 0o600)
	if err != nil {
		return manifest, err
	}
	manifest.Files = append(manifest.Files, copyEntry)

	// 3) 內容目錄：媒體、文件、上傳。空目錄也要在包裡存在，否則恢復出來的目錄結構不完整。
	for _, dir := range opts.ContentDirs {
		entries, err := copyTree(dir, staging)
		if err != nil {
			return manifest, err
		}
		manifest.Files = append(manifest.Files, entries...)
	}

	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	manifest.Totals.Files = len(manifest.Files)
	var total int64
	for _, f := range manifest.Files {
		total += f.SizeBytes
	}
	manifest.Totals.Bytes = total
	return manifest, nil
}

// nonNilTables 把 nil 切片換成空切片，讓 JSON 出現 [] 而不是 null。
func nonNilTables(in []database.TableRows) []database.TableRows {
	if in == nil {
		return []database.TableRows{}
	}
	return in
}

// copyInto 把一個來源檔複製到包內的 relInBundle 位置，回傳副本的清單條目。
//
// relInBundle 是包內的相對路徑（含類別前綴），條目的 Path 就是它：清單與磁盤位置只有一個來源，
// 不允許出現「清單寫 media/a.png、實際落在 a.png」這種兩份真相。
// 條目讀的是副本而非來源：落盤後才算數，來源在複製期間被別人改過也不影響這份摘要描述的東西。
func copyInto(kind, relInBundle, from, staging string, mode os.FileMode) (Entry, error) {
	to := filepath.Join(staging, filepath.FromSlash(relInBundle))
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		return Entry{}, fmt.Errorf("backup: 建立 %s 目錄失敗: %w", kind, err)
	}
	src, err := os.Open(from)
	if err != nil {
		return Entry{}, fmt.Errorf("backup: 開啟來源 %s 失敗: %w", from, err)
	}
	defer src.Close()
	dst, err := os.OpenFile(to, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return Entry{}, fmt.Errorf("backup: 建立 %s 失敗: %w", to, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return Entry{}, fmt.Errorf("backup: 複製到 %s 失敗: %w", to, err)
	}
	if err := dst.Close(); err != nil {
		return Entry{}, fmt.Errorf("backup: 關閉 %s 失敗: %w", to, err)
	}
	// 副本權限由引數決定而不是沿用來源：組態副本含口令摘要，包裡其他檔案不需要這層限制。
	if err := os.Chmod(to, mode); err != nil {
		return Entry{}, fmt.Errorf("backup: 設定 %s 權限失敗: %w", to, err)
	}
	return digestInto(kind, relInBundle, to)
}

// copyTree 遞迴複製一個內容目錄，回傳包內每個檔案的清單條目。
//
// 來源目錄即使沒有檔案也會在包裡建立對應目錄；特殊檔（連結、管道）一律拒絕而不是跳過。
func copyTree(dir ContentDir, staging string) ([]Entry, error) {
	var entries []Entry
	root := filepath.Join(staging, dir.Kind)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("backup: 建立 %s 目錄失敗: %w", dir.Kind, err)
	}
	info, err := os.Stat(dir.Path)
	if err != nil {
		return nil, fmt.Errorf("backup: 讀取內容目錄 %s 失敗: %w", dir.Path, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("backup: 內容目錄 %s 不是目錄", dir.Path)
	}

	err = filepath.WalkDir(dir.Path, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(dir.Path, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		relSlash := filepath.ToSlash(filepath.Join(dir.Kind, rel))
		to := filepath.Join(staging, filepath.FromSlash(relSlash))
		if d.IsDir() {
			return os.MkdirAll(to, 0o755)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w：%s（符號連結不進備份，跳過等於遺漏）", ErrSpecialFile, path)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%w：%s（%s）", ErrSpecialFile, path, d.Type().String())
		}
		entry, err := copyInto(dir.Kind, relSlash, path, staging, 0o644)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// digestInto 唸出實際落盤的位元組，算出大小與 SHA-256。
func digestInto(kind, rel, path string) (Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return Entry{}, fmt.Errorf("backup: 開啟 %s 失敗: %w", path, err)
	}
	defer file.Close()

	hasher := sha256.New()
	size, err := io.Copy(io.Discard, io.TeeReader(file, hasher))
	if err != nil {
		return Entry{}, fmt.Errorf("backup: 摘要 %s 失敗: %w", path, err)
	}
	return Entry{Kind: kind, Path: rel, SizeBytes: size, SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

// writeManifest 把清單以易讀縮排寫進包內，回傳寫入的位元組數；這是發布前的最後一個檔案。
func writeManifest(staging string, manifest Manifest) (int64, error) {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("backup: 編碼備份清單失敗: %w", err)
	}
	data = append(data, '\n')
	path := filepath.Join(staging, ManifestName)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return 0, fmt.Errorf("backup: 寫入備份清單失敗（%s）: %w", path, err)
	}
	return int64(len(data)), nil
}

// validate 檢查的不是使用者配錯的東西，而是呼叫端寫錯的那一類：
// 名帶路徑分隔符會寫到 OutDir 之外，函式值為 nil 會讓「有備份包」變成一個永遠不會出現的空目錄。
func (o Options) validate() error {
	if strings.TrimSpace(o.OutDir) == "" {
		return errors.New("backup: 缺少備份輸出目錄")
	}
	if o.Name == "" || o.Name == "." || o.Name == ".." ||
		strings.ContainsAny(o.Name, `/\`) || filepath.Base(o.Name) != o.Name {
		return fmt.Errorf("backup: 備份包名稱需為單一檔名層級，實際為 %q", o.Name)
	}
	if strings.TrimSpace(o.ConfigPath) == "" {
		return errors.New("backup: 缺少組態檔路徑")
	}
	if o.Snapshot == nil || o.Inspect == nil {
		return errors.New("backup: 缺少快照與快照檢查實作")
	}
	if o.Disk == nil {
		return errors.New("backup: 缺少磁碟空間判定")
	}
	if o.Now.IsZero() {
		return errors.New("backup: 缺少備份時刻")
	}
	if o.Now.Location() != time.UTC {
		return errors.New("backup: 備份時刻需為 UTC（時間一律 UTC，顯示時區只影響呈現）")
	}
	for _, dir := range o.ContentDirs {
		if strings.TrimSpace(dir.Kind) == "" || strings.TrimSpace(dir.Path) == "" {
			return fmt.Errorf("backup: 內容目錄需要類別與路徑，實際為 %+v", dir)
		}
	}
	return nil
}
