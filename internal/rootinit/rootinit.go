package rootinit

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
)

// ErrUnusableExistingCredential 表示組態檔已有一份「非空但不可用」的 Root 憑據。
//
// 它與 config.ErrRootAlreadyInitialized 分開是有原因的：後者的意思是「這條路已經關上，
// 請改走改密流程」，前者的意思是「關上的那條路擋在一個登不進去的值前面」。
// 兩句建議完全不同，混成一個錯誤就只能靠人去猜。
var ErrUnusableExistingCredential = errors.New("rootinit: 既有 Root 憑據不可用")

// ErrSecretPolicy 是口令明文不合格時回傳的可判別錯誤。
//
// 它只說明「這一欄不合格」，不說明合格標準之外的事（例如長度差多少會是什麼結果）：
// 呼叫端要的是能回給操作者的句子，不是內部界限的清單。
var ErrSecretPolicy = errors.New("rootinit: Root 口令不合格")

// Options 是一次初始化所需的輸入。
type Options struct {
	// ConfigPath 是組態檔路徑（Root 憑據唯一的持久位置）。
	ConfigPath string
	// Secret 是操作者交上來的口令明文，位元組精確語意：本套件不做前後空白修剪，
	// 也不做任何正規化（NFC／NFD 視為不同明文，屬 internal/credential 已定下的語意）。
	Secret string
	// Params 是新憑據的 Argon2id 參數檔（由組態的 security.hashing 解析而來）。
	Params credential.Params
}

// Result 是初始化的結果。
//
// 刻意不含任何憑據材料：雜湊已在組態檔裡，明文只存活於這次呼叫的記憶體，
// 而把兩者之一放進回傳值都會讓「不進日誌、不進審計」變成要靠呼叫端自律的約定。
type Result struct {
	// Params 是這次實際生效的參數檔（數值不是秘密，可寫進啟動報告）。
	Params credential.Params
}

// State 是「這台伺服器有沒有 Root」的最小事實。
//
// 它是後續界面唯一需要的資訊：有／沒有。組態檔路徑、編碼長度、參數檔與任何
// 憑據片段都不在這裡——未初始化狀態要能被安全地轉成回應，前提就是它不攜帶任何定位資訊。
type State struct {
	// ConfigExists 表示組態檔是否已建立（首次部署時可能還沒跑過任何命令）。
	ConfigExists bool
	// Initialized 表示組態檔是否已帶有非空的 Root 憑據雜湊。
	Initialized bool
}

// Initialize 把操作者交上來的口令變成組態檔裡的 Argon2id 憑據，且只在尚無憑據時成功。
//
// 順序就是安全順序，逐項理由如下：
//  1. 先驗參數檔與口令本身——不合格時連派生都不該開始（不浪費算力，也不留下
//     「已派生但沒落地」這種需要解釋的中間狀態）；
//  2. 派生之後、寫入之前，先對剛產生的編碼自我校驗一次：如果連自己產生來的東西
//     都驗不過，那是執行檔的問題，絕不能把它寫進一個之後關不上的欄位；
//  3. 寫入由 internal/config 完成，它在同一個進程級互斥區內重新讀一次檔案做第二次
//     檢查，並以「臨時檔 → Sync → 改名」落地後逐字回讀比對。
//
// 第二次呼叫（無論口令是否相同）一律回 config.ErrRootAlreadyInitialized。
// 回傳 nil 時可以確定：組態檔裡那份憑據就是這次交上來的口令，而且重開程序後仍讀得回來。
func Initialize(opts Options) (Result, error) {
	if opts.ConfigPath == "" {
		return Result{}, errors.New("rootinit: 需要組態檔路徑")
	}
	if err := opts.Params.Validate(); err != nil {
		return Result{}, fmt.Errorf("rootinit: 雜湊參數檔不合格: %w", err)
	}
	if err := validateSecret(opts.Secret); err != nil {
		return Result{}, err
	}

	// 先確認「還沒有人佔了這個位置」，再花算力派生：
	// 併發競跑時輸家已經寫完，輸家在這裡就停下，不會多產生一份永遠用不到的憑據。
	before, err := config.ReadRootFile(opts.ConfigPath)
	if err != nil {
		return Result{}, err
	}
	if !before.FileExists {
		return Result{}, fmt.Errorf("rootinit: 找不到組態檔 %s（請先在本機執行一次 evernight-server migrate 讓它建立）",
			opts.ConfigPath)
	}
	if before.Initialized() {
		// 「非空但不可用」不當成一般的格式問題：它代表一個永遠登不進去的 Root，
		// 而初始化是唯一能把那個壞值換掉、而不是帶著它往前的時機。
		//
		// 這裡硬擋（config.Validate 那邊只留提醒）的分界在於代價不對等：
		// 啟動那一步擋下來會讓一個正在服務活動的部署停擺，而初始化發生在還沒有人
		// 依賴這個部署的時候——同一個壞值，前者是災難，後者只是多跑一次命令。
		if err := credential.CheckEncoding(before.Hash); err != nil {
			return Result{}, fmt.Errorf("%w：既有值不是可用的 Argon2id 編碼（%v）",
				ErrUnusableExistingCredential, err)
		}
		return Result{}, fmt.Errorf("%w：Root 已初始化，本命令不會覆蓋既有憑據", config.ErrRootAlreadyInitialized)
	}

	encoded, err := credential.Hash(opts.Secret, opts.Params)
	if err != nil {
		return Result{}, fmt.Errorf("rootinit: 產生 Root 憑據失敗: %w", err)
	}
	// 自我校驗：把「產生出來的編碼能不能驗回這次口令」當成寫入的前置條件。
	// 這一次派生的成本與寫入後驗證同階，放在寫入之前才有意義——失敗時檔案還沒被動過。
	ok, err := credential.Verify(encoded, opts.Secret)
	if err != nil {
		return Result{}, fmt.Errorf("rootinit: 新產生的 Root 憑據無法校驗: %w", err)
	}
	if !ok {
		return Result{}, errors.New("rootinit: 新產生的 Root 憑據校驗未通過，未寫入組態檔")
	}

	if err := config.WriteRootPasswordHash(opts.ConfigPath, encoded); err != nil {
		return Result{}, err
	}

	// 寫入後只比對字串，不再跑一次派生：config 那層已保證檔案裡的值逐字等於 encoded，
	// 而 encoded 剛剛驗過這次口令。再派生一次的代價只讓命令變慢，結論不會更可靠。
	after, err := config.ReadRootFile(opts.ConfigPath)
	if err != nil {
		return Result{}, fmt.Errorf("rootinit: 寫入後回讀組態檔失敗: %w", err)
	}
	if after.Hash != encoded {
		return Result{}, errors.New("rootinit: 寫入後回讀到的憑據與產生的值不符，本次初始化不算成功")
	}
	return Result{Params: opts.Params}, nil
}

// Status 回報「這台伺服器有沒有 Root」，供只讀查詢與後續介面使用。
//
// 它只看組態檔本身：環境變數（config.RootPasswordHashEnvKey）能在執行期蓋掉檔案值，
// 那件事由呼叫端另外提示，不在這裡混進「有沒有初始化」這個判斷——
// 否則同一句「已初始化」會有兩種意思。
func Status(configPath string) (State, error) {
	if configPath == "" {
		return State{}, errors.New("rootinit: 需要組態檔路徑")
	}
	file, err := config.ReadRootFile(configPath)
	if err != nil {
		return State{}, err
	}
	return State{ConfigExists: file.FileExists, Initialized: file.Initialized()}, nil
}

// validateSecret 擋下不該落成憑據的明文輸入。
//
// 只檢查「空」與「超過模組上界」這兩種形態，與 internal/credential 的口徑一致：
// 強度策略（長度下限、字類要求）屬產品規則，尚未由批準記錄落地，
// 因此不在這裡自作主張——把 guesses 寫成閘門會讓之後的真實策略難以辨認。
func validateSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("%w：口令不可為空", ErrSecretPolicy)
	}
	if len(secret) > credential.MaxPasswordLength {
		return fmt.Errorf("%w：口令不可超過 %d 位元組", ErrSecretPolicy, credential.MaxPasswordLength)
	}
	// 行尾控制字元幾乎必然是複製貼上或管道換行的殘留，而不是口令的一部分；
	// 留著它會讓人第一次登入就驗不過，而且查不出原因。
	if strings.ContainsAny(secret, "\r\n") {
		return fmt.Errorf("%w：口令不得含換行字元（管道輸入請逐行給）", ErrSecretPolicy)
	}
	return nil
}
