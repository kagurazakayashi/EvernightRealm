package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
)

// writeFile 在指定目錄建立檔案（含父目錄），回傳路徑。
func writeFile(t *testing.T, dir, rel, content string) string {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("建立目錄失敗: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("寫入 %s 失敗: %v", rel, err)
	}
	return path
}

// fakeRepo 建立一個最小的假倉庫：有 .gitmodules、子模組目錄與 pubspec.yaml。
// 回傳（倉庫根, 子模組目錄）。定位規則本身由 internal/devkit 負責驗證，這裡只需要一個
// 形狀正確的目錄。
func fakeRepo(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, devkit.GitmodulesFile, realGitmodules)
	appDir := filepath.Join(root, "frontend-app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("建立子模組目錄失敗: %v", err)
	}
	writeFile(t, appDir, devkit.PubspecFile, "name: frontend_app\n")
	return root, appDir
}

// realGitmodules 是這個倉庫實際使用的那份記錄。
const realGitmodules = `[submodule "EvernightRealmAPP"]
	path = EvernightRealmAPP
	url = git@github.com:kagurazakayashi/EvernightRealmAPP.git
`
