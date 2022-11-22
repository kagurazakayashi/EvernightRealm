// recover.go 是「Root 口令已遺失」時的本機恢復用例：把組態檔裡那一份既有憑據，
// 換成操作者當場交上来的新口令所派生的憑據。
//
// 它與 Initialize（一次性初始化）是兩條獨立的寫入通路，分工就是一句話：
// Initialize 只準把空白格填上、填過就永久關上；Recover 只準換掉已有的那一份，
// 檔案沒有憑據時它拒絕（那種狀態該走 init-root）。兩條路各自只有一種成功形態，
// 合成一個帶 --force 的函式就會出現「旗標決定語意」的第三種狀態，而那最難驗證。
//
// 授權依據是什麼（以及不是什麼）：能在伺服器主機上讀寫那個組態檔、並且把服務停下來。
// 這一條路上刻意不接受的任何東西，都是因為它們不構成授權：
//   - 舊口令：要恢復的就是因為交不出它。既然不能靠「知道舊口令」把關，能把關的就只有
//     檔案存取與本機執行这两件事實，所以這裡不問舊口令、也不驗舊口令；
//   - 任何「後門口令」「恢復金鑰檔」「可下載的恢復憑據」：那等於把同一個權限再發一份
//     副本出去，而且副本的洩漏面比組態檔本身大得多；
//   - HTTP 形態：能在本機跑命令就是要付的代價。改成端點，授權依據會變成「誰先連上線」，
//     而那時候 CORS、來源地址、有沒有按鈕都不算把關。
//
// 失敗的形態與 Initialize 同一条約定：回傳錯誤且組態檔維持原樣。寫入仍經
// config.UpdateRootPasswordHash 的比較-and-set 與同目錄臨時檔原子替換，
// 因此不存在「半份組態」；而它對現值的比對把「兩個人同時恢復」收斂成只有一個成功。
//
// 會話撤銷與 Root 審計不在這一層：那屬於資料庫，由裝配層（internal/app 的 recover-root
// 子命令）在同一個交易裡完成，失敗時由該處按已知現值把這一層的變更回滚。
package rootinit

import (
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
)

// ErrNoExistingCredential 表示組態檔裡沒有可恢復的 Root 憑據。
//
// 它單獨存在是因為建議完全不同：「沒有憑據」的答案是走 init-root 建立第一份，
// 而不是在本條路上開一個「順便建立」的分支——後者會讓一次性初始化那個「永久只開放一次」
// 的合同變成取決於呼叫順序的巧合。
var ErrNoExistingCredential = errors.New("rootinit: 組態檔沒有可恢復的 Root 憑據")

// RecoverOptions 是一次本機恢復所需的輸入。
//
// 它與 Options 分開而不是共用的理由只有一個：恢復不需要、也不應該拿到「預期中的舊口令」
// 這種欄位——只要這個欄位存在，就會有人去填它，然後把「填對了」誤當成授權依據。
type RecoverOptions struct {
	// ConfigPath 是組態檔路徑（Root 憑據唯一的持久位置）。
	ConfigPath string
	// Secret 是操作者當場交上来的新口令明文，位元組精確語意：與 Initialize 同口徑，
	// 本套件不做前後空白修剪，也不做任何正規化。
	Secret string
	// Params 是新憑據的 Argon2id 參數檔（由組態的 security.hashing 解析而來）。
	Params credential.Params
}

// Recover 用操作者交上来的新口令覆寫組態檔裡已有的 Root 憑據。
//
// 順序與理由和 Initialize 同形：
//  1. 先驗路徑、參數檔與新口令本身——不合格時連派生都不開始，檔案一個位元組不動；
//  2. 現讀組態檔：檔案不存在、或裡面沒有非空憑據，都在動任何東西之前拒絕
//     （前者是「這個資料目錄還不屬於這個服務」，後者該走 init-root）；
//  3. 派生新雜湊，並當場用剛交上来的口令自我校驗一次：解不回自己明文的那個值
//     絕不能寫進一個之後要拿它驗登入的欄位；
//  4. 覆寫由 config.UpdateRootPasswordHash 完成：它以步驟 2 讀到的現值做比較-and-set，
//     所以「讀現值」與「蓋掉現值」之間如果有人動過檔案（例如另一個人的恢復），
//     這一步會整筆失敗而不是無聲蓋掉對手；
//  5. 覆寫成功後回讀逐字比對，對不上就報失敗。
//
// 與 Initialize 關鍵的差別在步驟 2：既有值即使解不開（不是可用的 Argon2id 編碼）也照樣可恢復。
// 那個狀態下根本沒有人登得進去，而改密通路又要求先交出現行口令——本條路正是那個狀態的
// 唯一出口，所以它不能像 init-root 那樣對著壞值拒絕。
//
// 回傳值刻意不含新雜湊：Result 裡只有參數檔，因為把憑據材料放進回傳值會讓
// 「不進日誌、不進審計、不進終端輸出」變成要靠呼叫端自律的約定。
func Recover(opts RecoverOptions) (Result, error) {
	if opts.ConfigPath == "" {
		return Result{}, errors.New("rootinit: 需要組態檔路徑")
	}
	if err := opts.Params.Validate(); err != nil {
		return Result{}, fmt.Errorf("rootinit: 雜湊參數檔不合格: %w", err)
	}
	if err := validateSecret(opts.Secret); err != nil {
		return Result{}, err
	}

	before, err := config.ReadRootFile(opts.ConfigPath)
	if err != nil {
		return Result{}, err
	}
	if !before.FileExists {
		return Result{}, fmt.Errorf("rootinit: 找不到組態檔 %s（沒有可恢復的 Root 憑據；恢復只換已有的那一份）",
			opts.ConfigPath)
	}
	if !before.Initialized() {
		return Result{}, fmt.Errorf("%w：建立第一份憑據屬一次性初始化 evernight-server init-root",
			ErrNoExistingCredential)
	}

	encoded, err := credential.Hash(opts.Secret, opts.Params)
	if err != nil {
		return Result{}, fmt.Errorf("rootinit: 產生新 Root 憑據失敗: %w", err)
	}
	ok, err := credential.Verify(encoded, opts.Secret)
	if err != nil {
		return Result{}, fmt.Errorf("rootinit: 新產生的 Root 憑據無法校驗: %w", err)
	}
	if !ok {
		return Result{}, errors.New("rootinit: 新產生的 Root 憑據校驗未通過，未寫入組態檔")
	}

	if err := config.UpdateRootPasswordHash(opts.ConfigPath, before.Hash, encoded); err != nil {
		return Result{}, err
	}

	after, err := config.ReadRootFile(opts.ConfigPath)
	if err != nil {
		return Result{}, fmt.Errorf("rootinit: 覆寫後回讀組態檔失敗: %w", err)
	}
	if after.Hash != encoded {
		return Result{}, errors.New("rootinit: 覆寫後回讀到的憑據與產生的值不符，本次恢復不算成功")
	}
	return Result{Params: opts.Params}, nil
}
