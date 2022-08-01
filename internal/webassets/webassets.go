// Package webassets 內嵌 Flutter Web 產物，並回答「本執行檔能不能對外提供網頁介面」。
//
// 內嵌的是 tools/buildweb 的輸出目錄，本套件自己不建置前端，只負責兩件事：
//   - 以 go:embed 把產物放進單一執行檔；
//   - 啟動時按 bundle 的判定標準複核這份產物，把「可用」與「不可用」如實分開。
//
// 不可用時本套件回傳空檔案系統與原因，而不是 panic 也不是假裝可用：
// 只有 API 的服務端仍是有效的部署形態（維運與日後的即時層都要能先跑起來），
// 但啟動摘要必須講清楚少了什麼、怎麼補回來，否則「忘了建置前端」會變成靜默的錯誤產物。
package webassets

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sync"

	"github.com/kagurazakayashi/EvernightRealm/internal/webassets/bundle"
)

// distDir 是產物在本套件目錄下的子目錄名（斜線寫法，與 go:embed 樣式一致）。
const distDir = "dist"

// embedded 為實際內嵌的檔案樹。
//
// 樣式必須用 all: 前綴：go:embed 預設會跳過以「.」與「_」開頭的檔案，
// 而 dist 在未建置時只剩下佔位檔 .keep——不用 all: 的話，那種狀態下根本編不過。
// 產物裡的 .last_build_id 同樣只有 all: 才會被收進內嵌檔案系統。
//
//go:embed all:dist
var embedded embed.FS

// Status 為一次內嵌產物的可用性判定結果，供啟動摘要使用。
type Status struct {
	// Available 表示內嵌產物齊備，可對外提供網頁介面。
	Available bool
	// Files 為內嵌的檔案數（不含佔位檔）；僅在可用時有意義。
	Files int
	// Bytes 為內嵌產物的總位元組數（不含佔位檔）；僅在可用時有意義。
	Bytes int64
	// Reason 為不可用的原因（可用時為空字串）；原樣取自判定標準，供摘要與排查使用。
	Reason string
}

// Summary 產生啟動輸出用的一行說明。
//
// 兩個分支都要寫出「接下來怎麼辦」：可用時告訴人在哪個路徑取得頁面，
// 不可用時指出缺什麼以及該跑哪個命令，避免只留一句「沒有 Web 介面」讓人自行猜測。
func (s Status) Summary() string {
	if s.Available {
		return fmt.Sprintf("已內嵌 %d 個檔案（%s），網頁介面與 API 同源提供",
			s.Files, bundle.HumanBytes(s.Bytes))
	}
	return fmt.Sprintf("未內嵌可用的 Web 介面（%s），本次僅提供 API 端點；先執行 go run ./tools/buildweb 再重新編譯",
		s.Reason)
}

var (
	// distOnce 保證判定只做一次：內嵌內容在程式執行期不會改變，重複走查檔案樹是白做工。
	distOnce sync.Once
	// distFS 與 distStatus 為一次判定的結果，供 Dist 直接回傳。
	distFS     fs.FS
	distStatus Status
)

// Dist 回傳內嵌的 Flutter Web 產物及其可用性判定。
//
// 可用時回傳以產物根目錄為根的檔案系統；不可用時回傳 nil 檔案系統與含原因的狀態。
// 呼叫端（internal/app）據此決定要不要把網頁介面掛上路由。
func Dist() (fs.FS, Status) {
	distOnce.Do(func() {
		distFS, distStatus = inspect(embedded)
	})
	return distFS, distStatus
}

// inspect 從一份含產物目錄的檔案樹裡挑出該目錄並判定可用性；不碰全域狀態，供測試直接給不同檔案樹。
func inspect(source fs.FS) (fs.FS, Status) {
	fsys, err := fs.Sub(source, distDir)
	if err != nil {
		// 目錄不存在屬於內嵌樣式被改壞的程式缺陷；仍按「不可用」如實回報而不 panic。
		return nil, Status{Reason: fmt.Sprintf("讀取內嵌目錄 %s 失敗：%v", distDir, err)}
	}
	report, err := bundle.Verify(fsys)
	if err != nil {
		return nil, Status{Reason: describe(err)}
	}
	return fsys, Status{Available: true, Files: report.Files, Bytes: report.Bytes}
}

// describe 把判定錯誤改寫成摘要裡的一句話。
//
// 缺失與否決的理由要分開寫：MissingFileError 代表「還沒建置或建置不全」，
// 其他錯誤代表「建置出了別的問題」，兩者的下一步動作不同。
func describe(err error) string {
	var missing *bundle.MissingFileError
	if errors.As(err, &missing) {
		return fmt.Sprintf("產物不完整，%s", missing)
	}
	return err.Error()
}
