package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/kagurazakayashi/EvernightRealm/internal/webassets/bundle"
)

// requiredWebFiles 是判定「這是一份可用的 Flutter Web 產物」的必要檔案清單。
//
// 清單的唯一權威在 internal/webassets/bundle：同一份產物有兩個必須看法一致的場合——
// 建置完當場複核（這裡），以及執行檔啟動時判斷內嵌的這份能不能拿出來服務
// （internal/webassets）。各寫一份遲早會有一個漏更新，而漏更新的結果不是建置失敗，
// 是「建置成功但頁面打不開」。
var requiredWebFiles = bundle.Required()

// artifactReport 為產物統計，只用於啟動摘要與人工核對體積。
type artifactReport struct {
	files int
	bytes int64
}

// verifyArtifacts 確認產物完整，且本地 CanvasKit 設定確實生效。
//
// 為什麼不能只看 flutter 的退出碼：`--no-web-resources-cdn` 哪天被改名、被設成預設關閉、
// 或被 Flutter 換掉實作，建置照樣回傳成功，但產物會變成向 CDN 取 CanvasKit——那正是本工具
// 要避免的事。所以要在產物上驗證「結果」，而不是只驗證「參數有傳出去」。
func verifyArtifacts(out string) (artifactReport, error) {
	report, err := bundle.Verify(os.DirFS(out))
	if err != nil {
		return artifactReport{}, describeVerifyFailure(out, err)
	}
	return artifactReport{files: report.Files, bytes: report.Bytes}, nil
}

// describeVerifyFailure 把判定錯誤改寫成建置工具的描述，並帶上實際產物目錄。
//
// 缺失與否決的理由要分開寫：缺少必要檔案代表「建置沒跑完或被打斷」，
// 未採用本機 CanvasKit 代表「產物會是離線白屏的那一份」，兩者下一步動作不同。
// 工具名前綴由 main 統一加，這裡只描述事實。
func describeVerifyFailure(out string, err error) error {
	var missing *bundle.MissingFileError
	switch {
	case errors.As(err, &missing):
		return fmt.Errorf("產物不完整，缺少 %s（於 %s）", missing.Path, out)
	default:
		return fmt.Errorf("%w（於 %s）", err, out)
	}
}

// humanBytes 把位元組數寫成適合終端輸出的大小寫法。
func humanBytes(bytes int64) string { return bundle.HumanBytes(bytes) }
