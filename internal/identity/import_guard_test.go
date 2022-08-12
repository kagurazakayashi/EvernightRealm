// 「測試身份工廠只能被測試程式碼引用」的結構性檢查。
//
// 這條約定如果只寫在註解裡，它會在某一天被一個看起來無害的改動破壞：
// 某個服務要「先讓它以 Root 跑、認證之後再接」，於是 import 了工廠。
// 本檔把約定變成會紅的測試——它不改任何行為，只在有人越界時喊出來。
package identity_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
)

// identitytestImport 是工廠套件的匯入路徑尾段（比對時只看尾段，不綁帳號與組織名）。
const identitytestImport = "internal/identity/identitytest"

// productionSourceDirs 是被掃描的目錄：前端子模組與其他目錄不屬後端 Go 構建，
// 把它們掃進來的話，一次無關的上游改動就能讓後端測試紅掉——那是誤報，不是把關。
var productionSourceDirs = []string{"internal", "cmd", "tools"}

// TestIdentitytestIsOnlyImportedByTests 走訪全部第一方 Go 原始檔，
// 確認引用工廠的檔案一律是 *_test.go。
func TestIdentitytestIsOnlyImportedByTests(t *testing.T) {
	root, err := devkit.ResolveRepoRoot("")
	if err != nil {
		t.Skipf("找不到倉庫根，跳過引用檢查：%v", err)
	}

	var offenders []string
	for _, dir := range productionSourceDirs {
		base := filepath.Join(root, filepath.FromSlash(dir))
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if !strings.Contains(string(data), identitytestImport) {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			offenders = append(offenders, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			t.Fatalf("走訪 %s 失敗：%v", dir, err)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("%s 只應被 *_test.go 引用，實際出現在生產程式碼：%s",
			identitytestImport, strings.Join(offenders, ", "))
	}
}
