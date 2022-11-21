// root_store.go 是 Root 憑據在服務側的讀寫閘：登入校驗讀它、改密經比較-and-set 換它。
//
// 為什麼要把它做成介面而不是繼續拿一個字串欄位（Deps.RootPasswordHash）：
// Root 的憑據唯一落點是組態檔，但「檔裡現值」與「記憶體生效值」在改密這一刻會分岔——
// 沒有單一收口，改密就會做出「檔案換了、還在跑的進程仍按舊雜湊驗登入」這種兩份 Root。
// 裝配層（internal/app）注入的實作把「覆寫檔案」與「換記憶體」釘在同一個互斥區裡；
// 這裡的靜態回退實作不可覆寫，為的是既有測試與「沒接配置寫入通路的部署」得到同一句
// 誠實的話：這條路上的 Root 憑據讀得到、換不掉。
package auth

import "errors"

// RootCredentialStore 是 Root 憑據的受信來源：CurrentHash 供登入與改密的現值校驗，
// Replace 是改密落地時唯一的覆寫通路。實作必須保證：Replace 回傳 nil 之後，
// CurrentHash 讀到的就是新雜湊，且這個對應關係（新口令↔新雜湊）不會再分岔。
type RootCredentialStore interface {
	// CurrentHash 回傳目前生效的 Root Argon2id 編碼雜湊；空字串代表尚未設定。
	// 回傳值屬高敏感材料：只能進校驗函式，不得進日誌、錯誤訊息或任何回應。
	CurrentHash() string
	// Replaceable 回報「覆寫現值」在當前部署形態下可做與否（例如環境變數正蓋在
	// 組態檔之上時必為 false）。呼叫端在動任何資料庫寫入之前先問它——
	// 被拒的改密不該留下任何半套痕跡。
	Replaceable() bool
	// Replace 以比較-and-set 把現值換成 newHash：內部必須核對 oldHash 仍是現值，
	// 並把結果原子地反映到 CurrentHash。失敗時現值（檔案與記憶體）維持不變。
	Replace(oldHash, newHash string) error
}

// ErrRootCredentialLocked 表示這個部署的 Root 憑據不接受經服務改密覆寫。
//
// 它不是「口令不對」也不是資料庫故障：是部署形態（環境變數覆蓋、或裝配時未接
// 寫入通路）決定的能力缺席。對外因此不進 2xxx 憑據段，由傳輸層收斂為 5xx 並
// 把原因講給伺服器日誌——它需要有人去動部署，不是使用者重試一次就好的事。
var ErrRootCredentialLocked = errors.New("auth: Root 憑據在當前部署形態下不可覆寫")

// ErrRootCredentialStale 表示 Replace 的比較-and-set 沒過：檔案／記憶體的現值
// 已經不是呼叫端拿去校驗的那個 oldHash。
//
// 它的來源只有兩種——並發的另一次改密，或服務之外有人動了配置。實作（裝配層）
// 必須用它包裝「現值不符」這一類失敗，讓改密用例能把這種情況收斂為憑據拒絕，
// 而不必認識 config 那側的具體哨兵。
var ErrRootCredentialStale = errors.New("auth: Root 憑據現值已變更，覆寫中止")

// staticRootStore 是由 Deps.RootPasswordHash 合成的唯讀回退實作。
//
// 「唯讀」在這條路上是正確語意而非偷懶：拿一個開機快照字串當憑據的組裝，
// 本來就沒有把新值寫回配置的能力；假裝能寫、寫了又沒人讀，才是真正的危險。
// 接上 live 存儲的裝配（internal/app）不會走到這裡。
type staticRootStore struct {
	hash string
}

// CurrentHash 回傳構造時凍結的雜湊。
func (s staticRootStore) CurrentHash() string { return s.hash }

// Replaceable 恆為 false：這個來源沒有覆寫通路。
func (s staticRootStore) Replaceable() bool { return false }

// Replace 恆失敗，且在任何寫入發生之前失敗。
func (s staticRootStore) Replace(string, string) error { return ErrRootCredentialLocked }
