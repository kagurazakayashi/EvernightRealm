// ResumeRootProof 使用範圍的結構閘。
//
// RootProof 只能由真實憑據比對產生，這是 R1-006 定下的邊界；會話解析需要
// 「從已驗證的 Root 會話換回證明」，因此開了 ResumeRootProof 這一條窄路，
// 並用本測試把它鎖在 internal/session 一家。若哪天有人從端點或工具裡直接呼叫它，
// 那就不再是「會話延續」而是「憑空造 Root」——必須紅。
package identity_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
)

// resumeRootProofAllowedFiles 是允許引用 ResumeRootProof 的生產原始碼（倉庫根相對路徑）：
// 定義與檔案本身屬 identity 包，唯一的呼叫點是會話解析。
var resumeRootProofAllowedFiles = map[string]bool{
	"internal/identity/root_session.go": true,
	"internal/session/store.go":         true,
}

// TestResumeRootProofUsedOnlyBySession 走訪全部第一方非測試原始檔，
// 確認引用 ResumeRootProof 的檔案落在允許清單內。
func TestResumeRootProofUsedOnlyBySession(t *testing.T) {
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
			if !strings.Contains(string(data), "ResumeRootProof(") {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			if resumeRootProofAllowedFiles[rel] {
				return nil
			}
			offenders = append(offenders, rel)
			return nil
		})
		if err != nil {
			t.Fatalf("走訪 %s 失敗：%v", dir, err)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("ResumeRootProof 只准 internal/session 呼叫，實際出現在：%s",
			strings.Join(offenders, ", "))
	}
}
