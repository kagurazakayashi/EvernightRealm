// Package acctpolicy 是「伺服器級帳戶建立策略」的領域規則與應用服務層。
//
// 它回答的只有一件事：這個伺服器允許透過哪幾條通路多出一個可登入的主體，
// 以及用戶自註冊走哪一種模式。三個入口各自獨立的開關（管理員建立普通帳戶、
// 用戶自註冊、訪客臨時帳戶）持久在 account_creation_policy 單例表上（遷移 0008），
// 讀寫權限只有 Root，且每一次成功修改都與 Root 域審計落在同一個交易裡。
//
// 為什麼獨立成一個套件，而不是放進 internal/adminacct 或 internal/account：
//   - adminacct 回答的是「Root 如何打理管理員目錄」，那裡每一個用例的對象都是一個帳戶行；
//     本套件的對象是一份伺服器級策略文件，沒有目標標識可傳、也不該傳；
//   - account 是帳戶實體與其倉儲（「一筆帳戶資料長什麼樣」），而「能不能產生一筆帳戶」
//     是使用帳戶的規則，把它塞進帳戶域會讓帳戶型別認得策略、策略又認得 HTTP；
//   - 依賴方向因此保持單向：acctpolicy → identity（主體與授權）、audit（落地痕跡）、
//     database／timeutil，而各建立通路日後讀策略時只經本套件，不自己查那張表。
//
// 四條不可讓步的規定：
//   - 策略值不等於能力。三個開關講的是「部署者想要什麼」，而「這條通路存不存在」
//     由本套件唯一的通路登記（Capabilities）給出；兩者的合成才是可以放行的答案
//     （Allows* 與 EntryOf）。把開關當能力，等於讓一個還沒有實作的入口在界面上看起來能按。
//   - 只有 Root 能讀寫這份策略：判定只經 identity.Authorize(principal, identity.NeedRoot)，
//     持 server_admin 的帳戶主體當場被拒（見 internal/identity/authorize.go）。
//     「管理員能不能建立普通帳戶」是 admin_create_standard 這一欄要回答的問題，
//     而「管理員能不能改伺服器策略」從來不是任何一欄——答案永遠是不能。
//   - 不認識的值一律拒絕，絕不降級：送來的模式字串不是四個已批准名字之一時整個請求失敗，
//     不會被當成 closed（那會把打錯字說成一次「關掉自註冊」的決定），
//     更不會在讀取端被猜成 open（那是把資料缺陷變成對外開放）。
//   - 建立通路落地時必須現讀策略（經本套件的 Service 或 Store），不得快取一份舊值：
//     策略是可以在任何一刻被 Root 改掉的決定，「上次讀到的值」不構成放行依據。
//
// Root 建立管理員帳戶與本機憑據恢復（init-root／recover-root）不在這三個開關之下，
// 而且刻意不讀本套件：前者的依據是「只有 Root 能開管理員」這條已批准的授權邊界，
// 後者的依據是「能在伺服器主機上執行命令」。把 admin_create_standard 拿去套在它們身上，
// 一個關掉的開關會變成「Root 也開不出人、口令丟了也換不掉」——那正是把伺服器鎖進
// 既沒有管理員也沒有恢復通路的狀態，不是一個策略開關可以表達的意思。
//
// 時刻與標識的來源與全專案一致（DEC-011、DEC-014、DEC-015）：updated_at 取自注入時鐘，
// 呼叫端無權代填；審計標識由 internal/audit 產生。
package acctpolicy

import (
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
)

// ErrPermissionDenied 沿用 identity 的判定結論：身分可信、但沒有這件事所需要的權限。
//
// 沿用同一個哨兵而不是另造一個，是為了讓「需要 Root」這句話在全倉庫只有一種判讀方式
// （與 internal/adminacct 同一口徑）。
var ErrPermissionDenied = identity.ErrPermissionDenied

// 對外可判別的結論錯誤：傳輸層據此分流回應，內部故障一律不進這些型別。
var (
	// ErrUnknownMode 表示送來的模式字串不是四個已批准名字之一（含留空）。
	// 它是請求本體的形狀問題，與「名字被批准但本版本沒實作」分開（ErrModeUnavailable）。
	ErrUnknownMode = errors.New("acctpolicy: 不認識的自註冊模式")
	// ErrModeUnavailable 表示模式名字已被批准，但它所需的准入通路在本伺服器版本尚未落地，
	// 因此現在不可寫入。
	//
	// 它與 ErrUnknownMode 分開只為處置不同：一個要人改寫法（打錯字），另一個是
	// 「這個計畫還沒上線」，改寫法換不來結果。界面據此能各自成句，
	// 而不是把所有拒絕都唸成同一句「請求不合法」。
	ErrModeUnavailable = errors.New("acctpolicy: 該自註冊模式在本伺服器版本尚未開放")
	// ErrNoPolicyRow 表示單例策略行讀不到或改不中。
	//
	// 正常部署不會走到這裡：遷移種下這一行，而遷移 0008 的觸發器讓它刪不掉。
	// 會到達這裡的是「資料庫被外部工具動過」那一類結構缺陷，因此它是必須回報的故障，
	// 不是可以用預設值兜過去的空欄——沒有任何一句誠實的話能把「策略不見了」
	// 翻譯成一個放行或拒絕的決定。
	ErrNoPolicyRow = errors.New("acctpolicy: 讀不到帳戶建立策略行")
)

// Mode 是自註冊模式（資料庫欄 self_register_mode）。
//
// 封閉集合，四個取值都是已批准的名字（用戶批准於 R2-006）；新增取值一律走新的遷移
// 放寬 CHECK，並在這裡補上它的寫入資格——這樣「自註冊能走的路變了」在版本史上
// 必然留痕，而不是程式碼裡悄悄多一個字串。
type Mode string

const (
	// ModeClosed 是關閉自註冊：不開放任何人自行建立帳戶。
	ModeClosed Mode = "closed"
	// ModeOpen 是開放自註冊：符合條件者自行建立、無需他人核准。
	ModeOpen Mode = "open"
	// ModeApproval 是需要核准的自註冊：申請落地後須由人批准才可用。
	// 本版本沒有申請與核准的任何通路，因此它是一個「已批准的名字」，不可寫入。
	ModeApproval Mode = "approval"
	// ModeInvite 是邀請碼自註冊：只有持有效邀請碼者可建立帳戶。
	// 本版本沒有邀請碼的產生與核銷通路，因此同樣不可寫入。
	ModeInvite Mode = "invite"
)

// String 回傳資料庫與協議表示。
func (m Mode) String() string { return string(m) }

// valid 回報是否為四個已批准名字之一。
//
// 這裡回答的是「資料庫裡出現這個值合不合形態」，讀取端用它復核現值；
// 「呼叫端能不能要求這個值」是 writable 的問題，兩者刻意分開：
// approval 形態上合法（部署者可能直接用外部工具寫進去），但本版本不給寫入。
func (m Mode) valid() bool {
	switch m {
	case ModeClosed, ModeOpen, ModeApproval, ModeInvite:
		return true
	}
	return false
}

// writable 回報這個模式在本版本能否被 Root 寫入。
//
// closed 永遠寫得：它的意思就是不開放，不需要任何通路支撐。
// open 也寫得，因為「把模式記為開放」本身就是一個合法的策略決定——注意它不等於對外
// 入口可用，那由通路登記決定（見 EntryOf）。
// approval／invite 的名字已批准，但申請／核准與邀請碼的通路尚未落地，現在寫進去只會
// 造出一個「伺服器記錄了一種它自己執行不了的模式」的狀態；等對應步驟完成時，
// 只需在 capabilities 裡把該模式標為已落地，這裡隨之放行——介面與協議都不必再改形狀。
func (m Mode) writable() bool {
	switch m {
	case ModeClosed, ModeOpen:
		return true
	}
	return false
}

// ParseMode 解析自註冊模式字串，只認四個已批准名字。
//
// 不做大小寫正規化、不修剪空白：這一欄的取值是協議上的機器碼，
// 「Closed」與「closed 」都不是任何一句被批准的話，放行它們只會讓同一個模式有兩種寫法。
func ParseMode(text string) (Mode, error) {
	m := Mode(text)
	if !m.valid() {
		return "", fmt.Errorf("%w：%q（僅 closed|open|approval|invite）", ErrUnknownMode, text)
	}
	return m, nil
}

// Policy 是一份帳戶建立策略的領域值。
//
// 三個欄位彼此獨立：改一欄永遠不影響另外兩欄，「只關掉自註冊、訪客照常開放」
// 這種組合必須能被表達也能被讀回，因此不把它們壓成一個列舉。
type Policy struct {
	// AdminCreateStandard 是「管理員可建立普通帳戶」開關。
	AdminCreateStandard bool
	// SelfRegisterMode 是自註冊模式。
	SelfRegisterMode Mode
	// GuestEnabled 是「可建立訪客（臨時）帳戶」開關。
	GuestEnabled bool
	// UpdatedAt 是最後一次修改的時刻（UTC）。
	// 零值是一個有意義的事實：這一列出廠以來沒人改過（見遷移 0008 的 updated_at 約定），
	// 不是「時刻查不到」，因此呼叫端不得拿它冒充「某一刻有人動過」。
	UpdatedAt time.Time
}

// Validate 復核這份策略的形態：模式必須是四個已批准名字之一。
//
// 布林欄位沒有可違反的規則（型別本身就只能是真或假），因此這裡不假裝還有一層檢查。
func (p Policy) Validate() error {
	if !p.SelfRegisterMode.valid() {
		return fmt.Errorf("acctpolicy: self_register_mode 需為 closed|open|approval|invite，實際為 %q",
			string(p.SelfRegisterMode))
	}
	return nil
}

// Capabilities 是「三條建立通路在本版本是否真的存在」的事實。
//
// 這是全倉庫唯一一處回答該問題的地方：日後某條通路落地時，只改 capabilities 這一個
// 函式（以及它的實作），傳輸層、界面與公開入口資訊都經本結構合成結果，
// 不會各處自己猜一份。
type Capabilities struct {
	// AdminCreateStandard 是「管理員建立普通帳戶」的端點與界面是否存在。
	AdminCreateStandard bool
	// SelfRegister 是「用戶自註冊」的端點與界面是否存在。
	SelfRegister bool
	// Guest 是「訪客（臨時）帳戶建立」的通路是否存在。
	Guest bool
}

// capabilities 回傳本版本的通路落地狀況。
//
// 三個都是 false，而且這不是妥協：本步交付的是策略的持久化、Root 的操作界面與審計，
// 三條建立通路任何一條都還沒實作。把某一位先寫成 true，界面就會出現一個按下去
// 必然失敗的入口，或讓一個不存在的端點被當成可用——那正是「未開發的模組冒充可用」。
// 反過來，策略值可以由 Root 先設定成放開：那份意圖是真的，只是還沒有執行它的東西，
// 下面的合成方法會把兩者如實算成「仍不放行」。
func capabilities() Capabilities { return Capabilities{} }

// AllowsAdminCreateStandard 回報「管理員此刻可否建立普通帳戶」：策略開關與通路存在與否。
//
// 日後那個用例落地時要問的就是這一句（並在它自己的交易裡現讀策略）。
// 它刻意不是一個可以被呼叫端「順手當真」的旗標：少了實作，這裡恆為假。
func (p Policy) AllowsAdminCreateStandard() bool {
	return p.AdminCreateStandard && capabilities().AdminCreateStandard
}

// AllowsGuest 回報「此刻可否建立訪客（臨時）帳戶」：策略開關與通路存在與否。
func (p Policy) AllowsGuest() bool {
	return p.GuestEnabled && capabilities().Guest
}

// AllowsSelfRegister 回報「此刻可否以自註冊建立帳戶」，並帶著實際生效的模式。
//
// 模式為 closed 時不放行，其餘模式要放行都還需要對應通路真的存在；
// approval／invite 在通路落地前根本寫不進策略（見 Mode.writable），
// 因此這裡不會出現「記錄了一種執行不了的模式」的中間狀態。
func (p Policy) AllowsSelfRegister() (bool, Mode) {
	if p.SelfRegisterMode == ModeClosed || !capabilities().SelfRegister {
		return false, p.SelfRegisterMode
	}
	return true, p.SelfRegisterMode
}

// EntryCapabilities 是登入前界面需要的最小對外事實：兩個入口開還是關。
//
// 欄位就只有這兩個，是刻意的：普通帳戶由誰建立對還站在門外的人毫無意義；
// 模式名字（closed 還是 approval）也不出去——它不改變「現在能不能自行建立」這個答案，
// 卻屬「這台伺服器打算怎麼做准入」的內部計畫。策略全文、updated_at、任何帳戶資料、
// 任何名額或閾值都不在這裡。
type EntryCapabilities struct {
	// SignUpOpen 是用戶自註冊入口對外是否開放。
	SignUpOpen bool
	// GuestOpen 是訪客（臨時帳戶）入口對外是否開放。
	GuestOpen bool
}

// EntryOf 把策略與通路落地狀況合成對外入口的答案。
//
// 規則只有一條：放開必須同時「策略要求放開」與「這條通路真的存在」。
// 少了任何一側都是關——這讓「不認識的值」在合成上不可能變成放行，
// 也讓尚未實作的入口不可能被一個策略開關變成可點擊的假象。
func (p Policy) EntryOf() EntryCapabilities {
	open, _ := p.AllowsSelfRegister()
	return EntryCapabilities{
		SignUpOpen: open,
		GuestOpen:  p.AllowsGuest(),
	}
}
