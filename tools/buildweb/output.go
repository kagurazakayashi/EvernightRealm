package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
)

// resolveOutput 決定產物目錄，並確認它是一個本工具可以有條件清空的目錄。
//
// 三條限制各有理由：落在倉庫根之外，go:embed 讀不到（它不能引用上級目錄）；等於倉庫根，
// 清空動作等於把整個倉庫端掉；與子模組互相包含，清空時會連前端一起去掉。相對路徑一律
// 以倉庫根為基準，這樣在子目錄執行也不會出現「同樣的命令寫到兩個地方」。
func resolveOutput(root, value, appDir string) (string, error) {
	target := strings.TrimSpace(value)
	if target == "" {
		return "", errors.New("產物目錄不可為空白")
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Clean(root), filepath.FromSlash(target))
	}
	out := filepath.Clean(target)

	rootClean := filepath.Clean(root)
	if out == rootClean || !devkit.ContainsPath(rootClean, out) {
		return "", fmt.Errorf("產物目錄必須落在倉庫根之內且不得為倉庫根本身：%s", out)
	}
	if devkit.ContainsPath(out, appDir) {
		return "", fmt.Errorf("產物目錄 %s 會包住前端子模組 %s，建置前的清空動作會連同子模組一併刪除", out, appDir)
	}
	if devkit.ContainsPath(appDir, out) {
		return "", fmt.Errorf("產物目錄 %s 位於前端子模組之內，請改用倉庫根下的目錄（預設 %s）", out, defaultOutputRel)
	}
	return out, nil
}
