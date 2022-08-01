package devkit

import (
	"os"
	"path/filepath"
	"testing"
)

// stubLookPath 在單一測試期間換掉可執行檔查證，結束時自動復原。
func stubLookPath(t *testing.T, stub func(string) (string, error)) {
	t.Helper()
	restore := lookupExecutable
	t.Cleanup(func() { lookupExecutable = restore })
	lookupExecutable = stub
}

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
// 回傳（倉庫根, 子模組目錄）。
func fakeRepo(t *testing.T, gitmodules string) (string, string) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, GitmodulesFile, gitmodules)
	appDir := filepath.Join(root, "frontend-app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("建立子模組目錄失敗: %v", err)
	}
	writeFile(t, appDir, PubspecFile, "name: frontend_app\n")
	return root, appDir
}

// realGitmodules 是這個倉庫實際使用的那份記錄，測試直接拿它當作真實格式的代表。
const realGitmodules = `[submodule "EvernightRealmAPP"]
	path = EvernightRealmAPP
	url = git@github.com:kagurazakayashi/EvernightRealmAPP.git
`
