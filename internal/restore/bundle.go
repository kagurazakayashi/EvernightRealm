// 備份包的讀取側：清單解析、逐檔摘要核對，以及「包內每個檔案落到目標資料目錄哪裡」的規劃。
//
// 落點不由包內的目錄名決定，而由包內那份 config.yaml 決定：來源把媒體目錄寫成
// "media/" 或 "uploads/media/"，恢復出來的資料目錄就該長成那個樣子。按包內目錄名落地時，
// 服務啟動後看的目錄與恢復寫入的目錄會是兩個地方，那時的表現是「恢復明明成功卻查不到資料」——
// 這比恢復失敗難查得多。
package restore

import (
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

	"github.com/kagurazakayashi/EvernightRealm/internal/backup"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"gopkg.in/yaml.v3"
)

// 內容目錄在包內的類別名（與產生端 backup 的常量同一來源，不在這裡重複字串）。
var contentKinds = []string{backup.KindMedia, backup.KindDocuments, backup.KindAttachments}

// Landing 是一個包內檔案在目標資料目錄裡的落點。
type Landing struct {
	// Kind 是來源類別（database|config|media|documents|attachments）。
	Kind string
	// BundleRel 是相對於備份包根目錄的路徑（清單裡一律斜線分隔）。
	BundleRel string
	// TargetRel 是相對於目標資料目錄的路徑（由包內那份組態決定，不是由包內的目錄名決定）。
	TargetRel string
	// Mode 是副本落盤時的權限；含口令摘要的組態副本收得比其他檔案緊。
	Mode os.FileMode
}

// DirLanding 是需要在目標目錄裡鏡像出來的目錄（內容目錄的子目錄；空目錄也算在內）。
//
// 清單裡沒有目錄這一項（Manifest.Files 只列檔案），因此目錄是靠走訪備份包得來的，
// 而且要鏡出來：來源留了一個空的附件目錄，恢復出來的資料目錄就該有它。
type DirLanding struct {
	BundleRel string
	TargetRel string
}

// ConfigReview 是包內那份 config.yaml 以目標資料目錄為基準解析後的結果。
//
// 這一份解析不寫任何檔案，只回答一個問題：把這個目錄交回服務啟動時，它會去哪六個地方。
// 六個地方必須全在目標目錄之內，否則「恢復到隔離目錄」這句話不成立。
type ConfigReview struct {
	// BundleDataDir 是包內原樣記著的 server.data_dir，只為排錯而保留。
	// 它不影響落點：落點由命令列的 --into 決定，而命令列在組態優先序裡最高。
	BundleDataDir string
	// Effective 是六個路徑鍵解析後的絕對路徑，鍵名與組態裡的寫法一致。
	Effective map[string]string
}

// Plan 是「這個包要怎麼落地」的完整答案，動筆前算好。
type Plan struct {
	// Files 是每個包內檔案的落點。
	Files []Landing
	// Dirs 是需要在目標目錄裡鏡像出來的目錄。
	Dirs []DirLanding
	// DatabaseRel 是資料庫快照在目標資料目錄裡的相對路徑；
	// 落地之後要重讀的就是這一個檔案，因此它在規劃裡單獨有一份，而不是讓讀取端再去猜
	// 「清單裡 kind=database 那一條落在哪裡」。
	DatabaseRel string
	// Review 是包內那份組態解析後的結果（報告裡點名越界路徑用的就是它）。
	Review ConfigReview
}

// bundleConfigHead 只取包內組態的 server.data_dir 原值。
//
// 完整解析走 config.Load（含校驗與預設值），但那一層會把 "." 換成預設目錄名、
// 又會被命令列蓋掉，原值就讀不回來了；排錯時要的就是那個原值，所以另外讀一次。
type bundleConfigHead struct {
	Server struct {
		DataDir string `yaml:"data_dir"`
	} `yaml:"server"`
}

// buildPlan 讀包內那份 config.yaml，以 target 為資料目錄解析，算出每個檔案與每個目錄的落點。
//
// target 必須已規範化為絕對路徑；cfg 必須是同一次 config.Load 產出且已 Resolve() 過的結果，
// 否則這裡拿到的還是相對字串，落點會算到進程當前工作目錄底下去。
func buildPlan(bundleDir string, manifest backup.Manifest, cfg config.Config, target string) (Plan, error) {
	head := bundleConfigHead{}
	configBytes, err := os.ReadFile(filepath.Join(bundleDir, filepath.FromSlash(backup.ConfigRel)))
	if err != nil {
		return Plan{}, fmt.Errorf("restore: 讀取包內組態失敗: %w", err)
	}
	if err := yaml.Unmarshal(configBytes, &head); err != nil {
		return Plan{}, fmt.Errorf("restore: 解析包內組態失敗: %w", err)
	}

	roots := make(map[string]string, len(contentKinds)+2)
	for _, pair := range []struct{ kind, path string }{
		{backup.KindMedia, cfg.Media},
		{backup.KindDocuments, cfg.Documents},
		{backup.KindAttachments, cfg.Attachments},
	} {
		rel, err := relWithinTarget(target, pair.path)
		if err != nil {
			return Plan{}, err
		}
		roots[pair.kind] = rel
	}
	dbRel, err := relWithinTarget(target, cfg.Database.Path)
	if err != nil {
		return Plan{}, err
	}
	roots[kindDatabase] = dbRel
	roots[kindConfig] = configTargetName

	// backups 與 logs.dir 不在這次要寫的東西裡，但它們決定服務之後把備份與日誌放到哪：
	// 指到目標目錄之外時一樣拒絕，否則「這個目錄整份搬走就是一個完整的資料目錄」這句話是假的。
	for _, key := range []struct{ name, path string }{
		{"backups", cfg.Backups}, {"logs.dir", cfg.Logs.Dir},
	} {
		if _, err := relWithinTarget(target, key.path); err != nil {
			return Plan{}, err
		}
	}

	review := ConfigReview{
		BundleDataDir: head.Server.DataDir,
		Effective: map[string]string{
			"database.path": cfg.Database.Path,
			"media":         cfg.Media,
			"documents":     cfg.Documents,
			"attachments":   cfg.Attachments,
			"backups":       cfg.Backups,
			"logs.dir":      cfg.Logs.Dir,
		},
	}

	landings, err := planFromManifest(manifest, roots)
	if err != nil {
		return Plan{}, err
	}
	dirs, err := planDirs(bundleDir, roots)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Files: landings, Dirs: dirs, DatabaseRel: dbRel, Review: review}, nil
}

// planFromManifest 把清單條目換成落點，並檢查清單形狀是否認識。
//
// 不認識的類別一律拒絕而不是跳過：跳過等於還原出來少一樣東西，
// 而「少了一份媒體檔」在界面上表現為「檔案打不開」，不會指向恢復流程。
func planFromManifest(manifest backup.Manifest, roots map[string]string) ([]Landing, error) {
	var landings []Landing
	seen := make(map[string]string, len(manifest.Files))
	for _, entry := range manifest.Files {
		root, ok := roots[entry.Kind]
		if !ok {
			return nil, fmt.Errorf("%w：清單裡的類別 %q（路徑 %s）本程式不認識，"+
				"既沒有跳過它的依據，也沒有放進目標目錄的位置", ErrKindUnknown, entry.Kind, entry.Path)
		}
		prefix := entry.Kind + "/"
		if !strings.HasPrefix(filepath.ToSlash(entry.Path), prefix) {
			return nil, fmt.Errorf("%w：條目 %s 不在其所屬類別 %s 的目錄下", ErrManifestShape, entry.Path, entry.Kind)
		}
		inner := filepath.ToSlash(strings.TrimPrefix(filepath.ToSlash(entry.Path), prefix))
		if inner == "" || inner == "." || inner == ".." || strings.HasPrefix(inner, "../") ||
			strings.Contains(inner, "/../") || filepath.IsAbs(inner) {
			return nil, fmt.Errorf("%w：條目 %s 的路徑意圖逃出類別目錄", ErrManifestShape, entry.Path)
		}
		targetRel := landingFor(entry.Kind, root, inner)
		if targetRel == "" || targetRel == "." || filepath.IsAbs(targetRel) {
			return nil, fmt.Errorf("%w：條目 %s 的落點算不出來（roots=%q）", ErrManifestShape, entry.Path, root)
		}
		if owner, dup := seen[targetRel]; dup {
			return nil, fmt.Errorf("%w：%s 與 %s 都要落地成 %s；兩個來源類別在包內是不同的目錄，"+
				"但組態把它們指到同一個地方了", ErrLandingCollision, owner, entry.Path, targetRel)
		}
		seen[targetRel] = entry.Path
		mode := os.FileMode(0o644)
		if entry.Kind == kindConfig {
			mode = 0o600
		}
		landings = append(landings, Landing{
			Kind: entry.Kind, BundleRel: filepath.ToSlash(entry.Path), TargetRel: targetRel, Mode: mode,
		})
	}
	return landings, nil
}

// landingFor 算出一個條目在目標資料目錄裡的相對路徑。
//
// 兩個「單一檔案」的類別（資料庫、組態）的落點就是組態裡那一個路徑本身，不能再拼上包內的檔名：
// 包裡的 "database/evernight.db" 講的是「包怎麼擺」，而還原出來那個庫該叫什麼、在哪一層，
// 由包內那份組態的 database.path 決定。兩邊各拼一次時，表現是恢復出一個服務看不到的庫，
// 而服務在一片空白上重新建了一個資料庫——那種失敗比恢復失敗難察覺得多。
// 內容目錄則要保留包內的相對結構（media/2026/09/x.png 還原後仍在那個層次上）。
func landingFor(kind, root, inner string) string {
	switch kind {
	case kindDatabase, kindConfig:
		return root
	default:
		if inner == "" {
			return root
		}
		return filepath.ToSlash(filepath.Join(root, filepath.FromSlash(inner)))
	}
}

// manifestDatabaseAndConfig 確認清單裡恰好各有一筆資料庫快照與組態副本。
//
// 少了任何一項都無法恢復：沒有快照就沒有庫可開，沒有組態就不知道六個目錄該怎麼擺。
// 多筆同理拒絕——「取哪一個」沒有可判定的答案。
func manifestDatabaseAndConfig(manifest backup.Manifest) (backup.Entry, backup.Entry, error) {
	var db, conf []backup.Entry
	for _, entry := range manifest.Files {
		switch entry.Kind {
		case kindDatabase:
			db = append(db, entry)
		case kindConfig:
			conf = append(conf, entry)
		}
	}
	if len(db) != 1 {
		return backup.Entry{}, backup.Entry{},
			fmt.Errorf("%w：清單裡的資料庫快照應恰好 1 筆，實際 %d 筆", ErrManifestShape, len(db))
	}
	if len(conf) != 1 {
		return backup.Entry{}, backup.Entry{},
			fmt.Errorf("%w：清單裡的組態副本應恰好 1 筆，實際 %d 筆", ErrManifestShape, len(conf))
	}
	return db[0], conf[0], nil
}

// readManifest 讀出並校驗包內的 manifest.json。
//
// 只認得 backup.FormatVersion 這一個內容格式：未知的格式版本一律拒絕，不去猜欄位語意。
// 清單自己不在 Files 那一份清單裡（一份檔案寫不出這份檔案自己的摘要），因此走訪時要排除它。
func readManifest(bundleDir string) (backup.Manifest, error) {
	var manifest backup.Manifest
	path := filepath.Join(bundleDir, backup.ManifestName)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return manifest, fmt.Errorf("%w：%s", ErrManifestMissing, path)
	}
	if err != nil {
		return manifest, fmt.Errorf("restore: 讀取備份清單失敗（%s）: %w", path, err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("restore: 解析備份清單失敗（%s）: %w", path, err)
	}
	if manifest.FormatVersion == 0 {
		return manifest, fmt.Errorf("%w：清單沒有 format_version 欄位（或為 0）", ErrFormatUnsupported)
	}
	if manifest.FormatVersion != backup.FormatVersion {
		return manifest, fmt.Errorf("%w：清單 format_version=%d，本程式只認得 %d",
			ErrFormatUnsupported, manifest.FormatVersion, backup.FormatVersion)
	}
	if manifest.Product != backup.Product {
		return manifest, fmt.Errorf("%w：清單的 product=%q，不是本程式（%q）產出的備份包",
			ErrFormatUnsupported, manifest.Product, backup.Product)
	}
	return manifest, nil
}

// verifyBundleFiles 逐檔核對大小與 SHA-256，並找出「磁盤上有、清單裡沒有」的檔案。
//
// 兩頭都要查，因為它們是兩種不同的壞法：清單有而磁盤不符是被改壞的包，
// 磁盤有而清單沒有則是這份包不在任何一份清單的描述裡——恢復它等於恢復一段沒有記錄的東西。
// 回傳的錯誤一次列舉前若干個不符項，不是只報第一個：運維需要知道壞了幾檔。
func verifyBundleFiles(bundleDir string, manifest backup.Manifest) error {
	listed := make(map[string]backup.Entry, len(manifest.Files))
	var offenders []string
	for _, entry := range manifest.Files {
		listed[filepath.ToSlash(entry.Path)] = entry
		actual, err := digestFile(filepath.Join(bundleDir, filepath.FromSlash(entry.Path)))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				offenders = append(offenders, fmt.Sprintf("%s（清單記有，磁盤上不存在）", entry.Path))
				continue
			}
			return err
		}
		if actual.SizeBytes != entry.SizeBytes {
			offenders = append(offenders, fmt.Sprintf("%s（大小 %d，清單記 %d）",
				entry.Path, actual.SizeBytes, entry.SizeBytes))
		}
		if !strings.EqualFold(actual.SHA256, entry.SHA256) {
			offenders = append(offenders, fmt.Sprintf("%s（摘要 %s，清單記 %s）",
				entry.Path, shortDigest(actual.SHA256), shortDigest(entry.SHA256)))
		}
	}
	if len(offenders) > 0 {
		return fmt.Errorf("%w：%s", ErrChecksumMismatch, summarizeOffenders(offenders))
	}

	var unlisted []string
	err := filepath.WalkDir(bundleDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(bundleDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if d.IsDir() {
			return nil
		}
		if relSlash == backup.ManifestName {
			return nil
		}
		if _, ok := listed[relSlash]; !ok {
			unlisted = append(unlisted, relSlash)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("restore: 走訪備份包失敗（%s）: %w", bundleDir, err)
	}
	if len(unlisted) > 0 {
		sort.Strings(unlisted)
		return fmt.Errorf("%w：%s", ErrUnlistedFile, summarizeOffenders(unlisted))
	}
	return nil
}

// planDirs 走訪包內三個內容目錄的根，把目錄結構鏡像成落點（含空目錄）。
//
// 三個根必須都在：產生端對空的內容目錄一樣會建目錄，缺席代表這個包不是完整的一份。
func planDirs(bundleDir string, roots map[string]string) ([]DirLanding, error) {
	var dirs []DirLanding
	for _, kind := range contentKinds {
		root := filepath.Join(bundleDir, kind)
		info, err := os.Stat(root)
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w：缺少內容目錄 %s/（產生端即使是空目錄也會建出來）",
				ErrBundleShape, kind)
		}
		if err != nil {
			return nil, fmt.Errorf("restore: 讀取內容目錄 %s 失敗: %w", root, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%w：%s 不是目錄", ErrBundleShape, kind)
		}
		targetRoot := roots[kind]
		dirs = append(dirs, DirLanding{BundleRel: kind, TargetRel: targetRoot})
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(bundleDir, path)
			if err != nil {
				return err
			}
			relSlash := filepath.ToSlash(rel)
			if relSlash == kind {
				return nil
			}
			inner := strings.TrimPrefix(relSlash, kind+"/")
			dirs = append(dirs, DirLanding{BundleRel: relSlash, TargetRel: filepath.ToSlash(filepath.Join(targetRoot, filepath.FromSlash(inner)))})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("restore: 走訪內容目錄 %s 失敗: %w", root, err)
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].TargetRel < dirs[j].TargetRel })
	return dirs, nil
}

// digestFile 算出一個檔案的大小與 SHA-256（形狀與產生端一致，因此兩邊可直接比對）。
func digestFile(path string) (backup.Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return backup.Entry{}, err
	}
	defer file.Close()

	hasher := sha256.New()
	size, err := io.Copy(io.Discard, io.TeeReader(file, hasher))
	if err != nil {
		return backup.Entry{}, fmt.Errorf("restore: 摘要 %s 失敗: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		return backup.Entry{}, fmt.Errorf("restore: 讀取 %s 資訊失敗: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return backup.Entry{}, fmt.Errorf("%w：%s（%s）", ErrSpecialFile, path, info.Mode())
	}
	return backup.Entry{Path: filepath.ToSlash(path), SizeBytes: size, SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

// relWithinTarget 把絕對路徑換成相對於目標資料目錄的路徑；逃出目標目錄即拒絕。
//
// 「逃出」在這裡不是風格問題而是落點問題：包內只有媒體、文件、上傳三份內容，
// 而那個鍵指到目標目錄之外時，要嘛把內容寫到別處（留下看不出來的第二份資料），
// 要嘛把外部的既有目錄當成本次恢復的落點（覆蓋別人的東西）。兩者都拒絕，並點出是哪一個鍵。
func relWithinTarget(target, abs string) (string, error) {
	if filepath.IsAbs(abs) {
		base := filepath.VolumeName(abs)
		if !samePathBase(base, filepath.VolumeName(target)) {
			return "", outsideTargetError(abs)
		}
	}
	rel, err := filepath.Rel(target, abs)
	if err != nil {
		return "", fmt.Errorf("restore: 比較路徑失敗（%s 與 %s）: %w", target, abs, err)
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", outsideTargetError(abs)
	}
	return rel, nil
}

// outsideTargetError 產生點出越界路徑的錯誤。
//
// 這句話必須自己就能讀：哪個路徑越界、要改的是包內那份 config.yaml、
// 以及改完之後要重新跑一次（本命令不代改組態）。
func outsideTargetError(abs string) error {
	return fmt.Errorf("%w：%s 落在目標資料目錄之外；請先修改包內的 %s 把它寫成相對路徑，再重新執行一次"+
		"（本命令不改寫組態，也不會把內容寫到目錄之外）", ErrPathOutsideTarget, abs, backup.ConfigRel)
}

// samePathBase 比較兩個卷標（Windows 的 P: 與 p: 是同一個卷）。
func samePathBase(a, b string) bool {
	return strings.EqualFold(a, b)
}

// summarizeOffenders 把不符項收成一行，最多點名 5 筆並說明總數。
//
// 全部列出來會在一個壞掉的包上刷出幾百行；五筆加上總數既夠判讀也不蓋掉後續報告。
func summarizeOffenders(items []string) string {
	const limit = 5
	if len(items) <= limit {
		return strings.Join(items, "、")
	}
	return fmt.Sprintf("%s …（共 %d 筆不符）", strings.Join(items[:limit], "、"), len(items))
}

// shortDigest 取摘要前 12 位元字元，夠對應到具體檔案又不長到把錯誤訊息撐爆。
func shortDigest(sum string) string {
	if len(sum) <= 12 {
		return sum
	}
	return sum[:12] + "…"
}
