// root_creds.go 是 Root 憑據存儲接口的正式實作：把 auth 用例的「讀現值／覆寫現值」
// 接到真正的組態檔上，並守住這條路上最容易分岔的一件事——檔案與記憶體必須同一時刻
// 認同一個現值。
//
// 為什麼要一個帶互斥的物件而不是直接呼叫 config 那兩個函式：
//   - 登入校驗讀的是記憶體現值（啟動時由組態合成，環境變數蓋在檔案之上時也以它為準），
//     改密寫的是檔案。沒有共同互斥區，就會出現「檔案已換、還在跑的進程按舊值驗口令」
//     或者反過來的兩份 Root——init-root 刻意用單寫入鎖躲開的坑，這裡用串行化正面解決；
//   - 環境變數覆蓋（ER_SECURITY_ROOT_PASSWORD_HASH）下覆寫檔案同樣會造出兩份 Root
//     （生效的永遠是看不見的那一份），所以 Replaceable 直接否，與 init-root 的
//     「不做兩份 Root 的搬遷」同一口徑；檢查取實時 os.Getenv 而不是啟動快照：
//     部署者在服務運行中設上變數的機會不大，但一旦發生，誠實的答桬是「現在不可覆寫」。
//
// 日誌與錯誤鏈一律不帶雜湊值：config 側已保證，這裡的包裝也不回顯任何一方的值。
package app

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
)

// rootCredentialStore 以組態檔為憑據的持久落點、以 current 為運行期生效值，
// 兩者的變更全部發生在同一個互斥區內。零值不可用，請經 newRootCredentialStore 取得。
type rootCredentialStore struct {
	mu sync.Mutex
	// path 是組態檔路徑（覆寫只認這一份檔案）。
	path string
	// current 是運行期生效的 Argon2id 編碼雜湊；高敏感，只準進校驗與覆寫通路。
	current string
}

// newRootCredentialStore 從已載入的組態構造 Root 憑據存儲。
//
// current 取合成後的組態值（內建預設→檔案→環境變數→命令列）：那正是這個進程
// 此刻驗 Root 口令用的東西，改密後的記憶體更新也必須落在同一個值上。
func newRootCredentialStore(cfg config.Config) *rootCredentialStore {
	return &rootCredentialStore{
		path:    cfg.ConfigFile(),
		current: cfg.Security.RootPasswordHash,
	}
}

// CurrentHash 回傳運行期現值。
func (rc *rootCredentialStore) CurrentHash() string {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.current
}

// Replaceable 回報「把新雜湊寫回配置」在當前部署形態下可做否：
// 環境變數正蓋在檔案之上時不可——覆寫只會造出永遠不生效的那一份。
func (rc *rootCredentialStore) Replaceable() bool {
	return os.Getenv(config.RootPasswordHashEnvKey) == ""
}

// Replace 在同一個互斥區內完成「檔案 CAS ＋ 記憶體換值」。
//
// 記憶體的比對先於檔案：現值對不上時不該再多碰檔案系統一次；檔案那一半
// 另有 config 層的比較-and-set 與原子落盤兜底（跨進程的窗口由單寫入實例鎖擋）。
// 任何失敗路徑都不動 current——「覆寫失敗但記憶體已換」是最難查的半套，絕不出現。
func (rc *rootCredentialStore) Replace(oldHash, newHash string) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if os.Getenv(config.RootPasswordHashEnvKey) != "" {
		return fmt.Errorf("%w：環境變數 %s 正蓋在組態檔之上",
			auth.ErrRootCredentialLocked, config.RootPasswordHashEnvKey)
	}
	if rc.current != oldHash {
		return fmt.Errorf("%w（記憶體現值已變更）", auth.ErrRootCredentialStale)
	}
	if err := config.UpdateRootPasswordHash(rc.path, oldHash, newHash); err != nil {
		if errors.Is(err, config.ErrRootCredentialMismatch) {
			// config 那層的「現值不符」翻成用例層的過期結論：並發改密或外部動過檔案，
			// 對呼叫端而言都是「你手上那枚現行口令已經不是現行了」。
			return fmt.Errorf("%w（組態檔現值已變更）", auth.ErrRootCredentialStale)
		}
		return err
	}
	rc.current = newHash
	return nil
}
