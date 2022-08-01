// Package devkit 提供根倉庫開發工具共用的判斷與執行件：定位倉庫根與前端子模組、
// 解析工具鏈可執行檔、執行外部命令。
//
// 為什麼要共用：「哪個目錄是前端」「這支工具鏈在哪」「怎麼判一道命令成敗」如果各工具
// 各寫一份，漏更新的那一份不會讓它自己失敗，只會讓兩個入口在同一個倉庫上得出不同結論。
// tools/buildweb（建置）與 tools/check（品質）讀的是同一套事實，就必須是同一段程式碼。
//
// 邊界（沿用品質入口的驗收條件）：本套件在任何情況下都不執行 git 命令——不初始化子模組、
// 不下載依賴、不改動檢出版本。版本管理是人的決定。
package devkit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GitmodulesFile 是 Git 記錄子模組清單的檔名，也是定位前端目錄的唯一依據。
const GitmodulesFile = ".gitmodules"

// PubspecFile 是 Flutter 專案的身分憑證：目錄在但此檔不在，代表那不是可用的前端。
const PubspecFile = "pubspec.yaml"

// GoModuleFile 是 Go 模組的身分憑證，也是 Go 側命令的基準目錄。
const GoModuleFile = "go.mod"

// ErrSubmoduleMissing 表示前端子模組不存在或內容為空。
//
// 單獨設一個哨兵錯誤，是為了讓呼叫端（與讀錯誤的人）一眼分辨「該去初始化子模組」與
// 「工具自己壞了」。任何呼叫端都不得代替使用者初始化、下載或改動檢出版本。
var ErrSubmoduleMissing = errors.New("前端子模組未就緒")

// ResolveRepoRoot 取得根倉庫目錄。未指名時自目前目錄向上找 .gitmodules。
func ResolveRepoRoot(explicit string) (string, error) {
	return resolveMarkerFrom(currentDir(), explicit, GitmodulesFile, "無法定位前端子模組")
}

// ResolveRepoRootFrom 為 ResolveRepoRoot 的可測試版本：起點目錄由參數給定。
//
// 向上找而非假設「倉庫根就是執行目錄」，是為了讓入口在子目錄裡也能跑；但一律以
// .gitmodules 的存在為準，找不到就停止，不去猜哪個目錄是倉庫根。
func ResolveRepoRootFrom(start, explicit string) (string, error) {
	return resolveMarkerFrom(start, explicit, GitmodulesFile, "無法定位前端子模組")
}

// ResolveModuleRoot 取得 Go 模組根目錄（Go 側命令的工作目錄）。
//
// 錨點是 go.mod 而不是 .gitmodules：兩者在這個倉庫裡剛好同一個目錄，但它們各自的判準不同。
// Go 命令要的是「模組在哪」，拿前端子模組的記錄去推它，等於讓後端檢查依賴前端是否已檢出。
func ResolveModuleRoot(explicit string) (string, error) {
	return resolveMarkerFrom(currentDir(), explicit, GoModuleFile, "無法定位 Go 模組")
}

// ResolveModuleRootFrom 為 ResolveModuleRoot 的可測試版本：起點目錄由參數給定。
func ResolveModuleRootFrom(start, explicit string) (string, error) {
	return resolveMarkerFrom(start, explicit, GoModuleFile, "無法定位 Go 模組")
}

// currentDir 取得目前目錄；查不到時回傳空字串，交由上層訊息如實呈現。
func currentDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return cwd
}

// resolveMarkerFrom 自 start 向上找帶有 marker 檔的目錄；explicit 非空時只認該目錄。
//
// explicit 走同一條路（必須存在、必須是目錄、必須含 marker），是為了讓「明指」與「推得」
// 的差別只剩起點，而出錯時的下一步動作（換一個目錄、或補上 marker）在兩種寫法下一致。
func resolveMarkerFrom(start, explicit, marker, purpose string) (string, error) {
	if target := strings.TrimSpace(explicit); target != "" {
		abs, err := filepath.Abs(target)
		if err != nil {
			return "", fmt.Errorf("無法解析 --repo-root：%w", err)
		}
		if info, err := os.Stat(abs); err != nil || !info.IsDir() {
			return "", fmt.Errorf("--repo-root 不是目錄：%s", abs)
		}
		if !FileExists(filepath.Join(abs, marker)) {
			return "", fmt.Errorf("%s 內找不到 %s，%s", abs, marker, purpose)
		}
		return abs, nil
	}

	if strings.TrimSpace(start) == "" {
		return "", fmt.Errorf("無法取得起點目錄，%s", purpose)
	}
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("無法解析目錄：%w", err)
	}
	for {
		if FileExists(filepath.Join(dir, marker)) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("自 %s 向上都找不到 %s；請在倉庫內執行，或以 --repo-root 指定", start, marker)
		}
		dir = parent
	}
}

// SubmoduleEntry 為 .gitmodules 中的一筆記錄。
type SubmoduleEntry struct {
	Name string
	Path string
}

// ReadSubmodules 讀取並解析倉庫根的 .gitmodules。
func ReadSubmodules(root string) ([]SubmoduleEntry, error) {
	content, err := os.ReadFile(filepath.Join(root, GitmodulesFile))
	if err != nil {
		return nil, fmt.Errorf("讀取 %s 失敗：%w", GitmodulesFile, err)
	}
	entries := ParseGitmodules(string(content))
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s 內沒有任何子模組記錄", GitmodulesFile)
	}
	return entries, nil
}

// ParseGitmodules 解析 .gitmodules 的 name 與 path。
//
// 只認 Git 自己寫出的那個格式（[submodule "名稱"] 之後的 `key = value`），不支援巨集、
// 不支援多行值，也不引入 INI 套件：這裡要的是讀自己倉庫裡那兩行，多出來的解析能力只會
// 多一個會出錯的地方。
func ParseGitmodules(content string) []SubmoduleEntry {
	var entries []SubmoduleEntry
	var current *SubmoduleEntry

	flush := func() {
		if current != nil && current.Path != "" {
			entries = append(entries, *current)
		}
		current = nil
	}

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			flush()
			current = &SubmoduleEntry{Name: sectionName(line)}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(key) == "path" {
			current.Path = unquote(strings.TrimSpace(value))
		}
	}
	flush()
	return entries
}

// sectionName 取 [submodule "EvernightRealmAPP"] 裡的引號內容；取不到回傳空字串。
func sectionName(line string) string {
	parts := strings.Split(line, `"`)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// unquote 去掉組態值兩側的成對雙引號。
func unquote(value string) string {
	if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		return value[1 : len(value)-1]
	}
	return value
}

// SelectSubmodule 依指名挑定子模組記錄；wanted 留空時要求「恰好一筆」。
//
// 不按名稱猜哪一個是 Web 應用：多子模組情況下猜錯的代價是跑到別的目錄去執行命令，
// 而代價要由使用者決定——所以寧可報錯並列出現有記錄。
func SelectSubmodule(entries []SubmoduleEntry, wanted string) (SubmoduleEntry, error) {
	if target := strings.TrimSpace(wanted); target != "" {
		var matches []SubmoduleEntry
		for _, entry := range entries {
			if strings.EqualFold(entry.Name, target) || filepath.ToSlash(entry.Path) == filepath.ToSlash(target) {
				matches = append(matches, entry)
			}
		}
		switch len(matches) {
		case 1:
			return matches[0], nil
		case 0:
			return SubmoduleEntry{}, fmt.Errorf(".gitmodules 內沒有名為或路徑為 %q 的子模組（現有：%s）",
				target, joinNames(entries))
		default:
			return SubmoduleEntry{}, fmt.Errorf("--module %q 同時對上多筆子模組記錄", target)
		}
	}
	if len(entries) != 1 {
		return SubmoduleEntry{}, fmt.Errorf(".gitmodules 內有 %d 筆子模組，請以 --module 指名（現有：%s）",
			len(entries), joinNames(entries))
	}
	return entries[0], nil
}

// joinNames 產生供錯誤訊息使用的子模組名稱清單。
func joinNames(entries []SubmoduleEntry) string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, fmt.Sprintf("%s→%s", entry.Name, entry.Path))
	}
	return strings.Join(names, "、")
}

// SubmoduleDir 由 .gitmodules 記錄的相對路徑算出子模組目錄（絕對路徑）。
//
// 路徑取自倉庫內的組態檔，因此仍要做越界檢查：一旦有人把 path 寫成 "../別處"，
// 工具就會跑到倉庫外面去讀目錄、甚至（建置前的清空動作）刪除東西。
func SubmoduleDir(root string, entry SubmoduleEntry) (string, error) {
	rel := filepath.ToSlash(strings.TrimSpace(entry.Path))
	if rel == "" {
		return "", fmt.Errorf(".gitmodules 中子模組 %q 缺少 path 記錄", entry.Name)
	}
	appDir := filepath.Clean(filepath.Join(filepath.Clean(root), filepath.FromSlash(rel)))
	if !ContainsPath(root, appDir) || appDir == filepath.Clean(root) {
		return "", fmt.Errorf("%w：.gitmodules 記錄的路徑 %q 不在倉庫根之內", ErrSubmoduleMissing, entry.Path)
	}
	return appDir, nil
}

// ContainsPath 回傳 outer 是否等於 inner、或為 inner 的祖先目錄。兩端都先過 Clean。
func ContainsPath(outer, inner string) bool {
	rel, err := filepath.Rel(filepath.Clean(outer), filepath.Clean(inner))
	if err != nil {
		return false
	}
	up := ".." + string(filepath.Separator)
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, up))
}

// RelativeTo 產生給人的摘要用相對路徑；算不出來時如實給絕對路徑。
func RelativeTo(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

// FileExists 回傳路徑是否存在（不區分檔案與目錄）。
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
