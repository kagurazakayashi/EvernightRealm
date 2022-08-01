package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/webassets/bundle"
)

// noWebResourcesCDN 是本工具存在的理由：少了它，release 產物的 CanvasKit 會改向
// gstatic CDN 取檔，純離線部署的首屏直接白屏。
const noWebResourcesCDN = "--no-web-resources-cdn"

// dartDefineFlag 為 flutter 的編譯期參數旗標，一律用 `--dart-define=K=V` 單詞寫法。
const dartDefineFlag = "--dart-define="

// buildArgs 組出 `flutter build web` 的引數（純函數，便於測試）。
//
// 模式只開 release／debug 兩檔，不給 profile：profile 產物不是可部署的網頁。
// 輸出目錄以 -o 直給絕對路徑，讓產物一次就落在內嵌位置，不留第二份。
func buildArgs(out string, o options) []string {
	mode := "--release"
	if o.debug {
		mode = "--debug"
	}
	args := []string{"build", "web", mode, noWebResourcesCDN, "-o", out}
	for _, define := range o.defines {
		args = append(args, dartDefineFlag+define)
	}
	return args
}

// buildCommand 把建置引數包成可執行命令。
func buildCommand(app devkit.Frontend, out string, o options) devkit.Command {
	return devkit.Command{
		Desc: "Flutter Web 建置",
		Exe:  app.FlutterExe,
		Args: buildArgs(out, o),
	}
}

// cleanOutput 清空產物目錄，並在清空的結果上補回佔位檔。
//
// 為什麼要清：產物最終會被 go:embed 塞進單一執行檔，上一次的殘留檔案（例如改名的字型
// 或舊版 main.dart.js）不會自己消失，只會被一起內嵌進發布檔。flutter 自己不清輸出目錄，
// 所以這一步由本工具負責；路徑已在 resolveOutput 限制於倉庫根內且與子模組互不包含。
//
// 為什麼要補佔位檔：go:embed 匹配不到任何檔案時是「編譯失敗」，而產物目錄不進版本庫。
// 清空後若建置失敗（或根本還沒建置過），留一個空目錄會讓整個後端連編譯都過不了，
// 而錯誤訊息指向的是 go:embed，看不出真正缺的是前端建置。補一個佔位檔讓「前端沒建置」
// 表達成啟動摘要裡的一句說明，而不是一條跟前端無關的編譯錯誤。
func cleanOutput(out string, stdout io.Writer) error {
	info, err := os.Stat(out)
	if errors.Is(err, os.ErrNotExist) {
		return writePlaceholder(out, stdout)
	}
	if err != nil {
		return fmt.Errorf("無法檢查產物目錄 %s：%w", out, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("產物目錄 %s 已存在但不是目錄", out)
	}
	if err := os.RemoveAll(out); err != nil {
		return fmt.Errorf("清空產物目錄 %s 失敗：%w", out, err)
	}
	fmt.Fprintf(stdout, "已清空舊產物：%s\n", out)
	return writePlaceholder(out, stdout)
}

// writePlaceholder 建立產物目錄並寫入佔位檔；內容取自判定標準套件，不在這裡複寫。
func writePlaceholder(out string, stdout io.Writer) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("建立產物目錄 %s 失敗：%w", out, err)
	}
	path := filepath.Join(out, bundle.PlaceholderName)
	if err := os.WriteFile(path, []byte(bundle.PlaceholderNote), 0o644); err != nil {
		return fmt.Errorf("寫入佔位檔 %s 失敗：%w", path, err)
	}
	fmt.Fprintf(stdout, "已在產物目錄補回佔位檔：%s\n", path)
	return nil
}
