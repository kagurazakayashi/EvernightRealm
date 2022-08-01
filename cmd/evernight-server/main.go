// Package main 為長夜幻境（EvernightRealm）服務端程式 evernight-server 的進入點。
//
// 本檔案保持「薄殼」：僅組裝並呼叫 internal/app.Run，
// 啟動與業務邏輯分離；配置載入、資料目錄、HTTP 服務於後續步驟
// 逐步加入 internal/app 及其依賴。
package main

import (
	"fmt"
	"os"

	"github.com/kagurazakayashi/EvernightRealm/internal/app"
)

// main 為程式進入點：以 app.Run 的回傳錯誤決定結束碼。
func main() {
	if err := app.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
