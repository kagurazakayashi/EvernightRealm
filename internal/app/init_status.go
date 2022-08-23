package app

// init_status.go 把「這台伺服器有沒有 Root」接成 HTTP 層能用的只讀來源。
//
// 為什麼要繞這一圈，而不是讓傳輸層自己去讀組態檔：傳輸層不認識組態檔、也不認識憑據
// （與 Deps.Ready、Deps.Web 同一條邊界）。它拿到的只是「問一個問題、得到三個布林」
// 的函式，因此這個端點會不會寫東西、會不會碰憑據材料，在型別上就沒有餘地。
//
// 讀的對象是檔案本身（rootinit.Status → config.ReadRootFile），不是啟動時讀進記憶體的那份組態。
// 兩者的分界只有一種情況會出現：有人在服務跑著的時候手改組態檔。那時候真正生效的仍然是
// 記憶體裡的舊值，要換就得重啟——而初始化本來就要求在服務停止、鎖釋放之後才做
// （見 evernight-server init-root 取的單寫入實例鎖），所以對「初始化這件事發生過了沒有」
// 這個問題，檔案才是對的問對象；只讀命令 root-status 問的也是同一個對象，
// 於是用戶在終端與在瀏覽器得到的答案不會是兩套。

import (
	"os"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/httpapi"
	"github.com/kagurazakayashi/EvernightRealm/internal/rootinit"
)

// initStatusSource 產生 Root 初始化狀態的只讀來源，供 httpapi.Deps.InitStatus 注入。
//
// 組態檔路徑在啟動時就固定下來（執行期間不會換檔），因此先在閉包外取好，
// 每次查詢都重新讀檔——這正是「操作者剛在終端跑完 init-root、回到瀏覽器按重新檢查」
// 能立刻看到新狀態的原因。
func initStatusSource(cfg config.Config) func() (httpapi.RootInitStatus, error) {
	configPath := cfg.ConfigFile()
	return func() (httpapi.RootInitStatus, error) {
		state, err := rootinit.Status(configPath)
		if err != nil {
			// 查不出來就照實回錯誤：把它報成「尚未初始化」會誘發一次註定被拒的初始化。
			return httpapi.RootInitStatus{}, err
		}
		return httpapi.RootInitStatus{
			ConfigExists:    state.ConfigExists,
			RootInitialized: state.Initialized,
			// 這一欄只看環境變數「有沒有設定」，永不取值：它蓋住的是檔案裡那份 Root 憑據，
			// 少了這一位，界面會勸操作者去跑一個在這種狀態下必然拒絕寫入的命令。
			EnvOverride: os.Getenv(config.RootPasswordHashEnvKey) != "",
		}, nil
	}
}
