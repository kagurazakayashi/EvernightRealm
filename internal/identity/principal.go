package identity

import (
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// Kind 是主體的類別：回答「這個實際操作者是誰這一類」，不回答「他能不能做這件事」。
//
// 它與 Role 分開是有原因的：Root 的權限來自「它就是伺服器本身」這個類別，
// 而不是來自某一筆可被改動的授權記錄；把 Root 也做成一個可授予的角色，
// 就等於承認有一張表能寫出 Root，而那張表一旦可寫，Root 就不再是最後一道防線。
type Kind string

const (
	// KindAnonymous 是匿名／未通過認證的主體。零值 Principal 即此類別，
	// 所以「忘記帶身分」與「刻意匿名」得到同一個結果：沒有任何敏感權限。
	KindAnonymous Kind = "anonymous"
	// KindAccount 是以 accounts 表裡的某個帳戶通過認證的主體（普通帳戶與訪客帳戶）。
	KindAccount Kind = "account"
	// KindRoot 是配置檔案裡的伺服器級 Root 憑據所對應的主體，不屬於任何帳戶、也不屬於任何活動。
	KindRoot Kind = "root"
	// KindSystem 是伺服器自身：啟動流程、CLI 子命令與背景任務。
	// 它的帳戶標識恆為空，因此不可能被誤寫成「某個登入用戶做了這件事」。
	KindSystem Kind = "system"
)

// String 回傳類別的機器表示。
func (k Kind) String() string { return string(k.normalize()) }

// normalize 把零值類別讀成匿名，讓匯出方法與內部判定共用同一個語意。
func (k Kind) normalize() Kind {
	if k == "" {
		return KindAnonymous
	}
	return k
}

// valid 回報是否為已定義類別。
func (k Kind) valid() bool {
	switch k.normalize() {
	case KindAnonymous, KindAccount, KindRoot, KindSystem:
		return true
	}
	return false
}

// Origin 是呼叫來源：同一個主體動作的入口不同，事後追査時必須分得出來。
//
// 它是主體的必要欄位而不是選擇性註解，理由有兩條：
//   - 啟動、CLI 與背景任務必須有明確來源，否則它們寫下的審計只能寫成「system 做了某事」，
//     分不出是開機自檢還是有人跑了還原命令；
//   - 來源與類別互相約束（見 checkOrigin）：背景任務不能宣稱自己是某個登入用戶，
//     帳戶主體也不能宣稱自己來自啟動流程——「偽造登入用戶」因此不是靠約定排除的。
type Origin string

const (
	// OriginHTTPRequest 是 HTTP 請求驅動的操作（未來的會話解析結果走這一條）。
	OriginHTTPRequest Origin = "http_request"
	// OriginCLI 是操作者透過 evernight-server 子命令觸發的操作。
	OriginCLI Origin = "cli"
	// OriginStartup 是服務啟動階段的自動行為（遷移、完整性自檢、寫入檔頭標記）。
	OriginStartup Origin = "startup"
	// OriginBackground 是服務運行期間的背景任務（保留期清理、排程等）。
	OriginBackground Origin = "background"
)

// String 回傳來源的機器表示。
func (o Origin) String() string { return string(o) }

// valid 回報是否為已定義來源。空值不成為合法來源：沒有來源的主體無從追查。
func (o Origin) valid() bool {
	switch o {
	case OriginHTTPRequest, OriginCLI, OriginStartup, OriginBackground:
		return true
	}
	return false
}

// checkOrigin 判定「這個類別能否有這個來源」。
func checkOrigin(k Kind, o Origin) error {
	if !o.valid() {
		return fmt.Errorf("%w：未知的呼叫來源 %q", ErrInvalidPrincipal, string(o))
	}
	switch k {
	case KindAccount, KindRoot:
		// 帳戶與 Root 都是「有人叫伺服器做事」，只能是請求或命令列。
		if o != OriginHTTPRequest && o != OriginCLI {
			return fmt.Errorf("%w：%s 主體的來源不可是 %s（僅 http_request|cli）",
				ErrInvalidPrincipal, k.String(), string(o))
		}
	case KindSystem:
		// 系統主體是「伺服器自己叫自己做事」，因此永不來自 HTTP 請求：
		// 否則一個端點就能把未認證的請求升格成系統行為。
		if o == OriginHTTPRequest {
			return fmt.Errorf("%w：system 主體不可來自 http_request 來源", ErrInvalidPrincipal)
		}
	default:
		return fmt.Errorf("%w：%s 主體不該有呼叫來源", ErrInvalidPrincipal, k.String())
	}
	return nil
}

// Principal 是一次操作所屬的受信主體：不可變值，欄位全部不匯出。
//
// 不匯出欄位就是本套件的核心手段：請求本體、請求頭、任何外部字串都無法被
// encoding/json 這類機制填成一個「自報為 Root」的主體，因為根本沒有可填的欄位。
// 要得到非匿名主體只有三條路，每條都要帶上只有服務端才有的東西：
//   - NewAccountPrincipal：已從資料庫載入且狀態為 active 的帳戶；
//   - Root：VerifyRootCredential 比對過的證明（見 RootProof）；
//   - NewSystem：明確的來源（啟動、CLI、背景）。
//
// 零值可直接使用，語意為「匿名、無任何敏感權限」，適合放進尚未認證的請求上下文。
type Principal struct {
	kind        Kind
	origin      Origin
	accountID   idgen.ID
	accountType account.Type
	roles       []Role
}

// AccountSubject 是構造帳戶主體所需的最小帳戶事實。
//
// 刻意不直接收 account.Account：那樣等於把憑據雜湊一起帶進身份上下文的建構函式，
// 而它在這裡沒有任何用處——「他是誰」由標識、類型與狀態決定，與他的密碼無關。
type AccountSubject struct {
	// ID 為帳戶標識，必須非零值。
	ID idgen.ID
	// Type 為帳戶類型（standard|guest）；訪客帳戶不可持有角色。
	Type account.Type
	// Status 為帳戶狀態；只有 active 能成為主體（disabled 視同不存在）。
	Status account.Status
}

// SubjectOf 從已載入的帳戶取出主體所需的最小事實。
func SubjectOf(a account.Account) AccountSubject {
	return AccountSubject{ID: a.ID, Type: a.Type, Status: a.Status}
}

// accountTypeKnown 回報帳戶類型是否落在 internal/account 的封閉集合內。
//
// 不復用 account 那側的同名判斷是因為它是未匯出方法；重寫一份的代價由測試守住：
// account 新增類型時這邊會把它當成「不認識」拒掉，屬於會被測試問到的失敗，
// 不會靜默放寬權限。
func accountTypeKnown(t account.Type) bool {
	switch t {
	case account.TypeStandard, account.TypeGuest:
		return true
	}
	return false
}

// AccountInput 是構造帳戶主體的引數。
//
// 三個欄位的可信度不對等，這是刻意的：Subject 與 Origin 是「事實」，
// 由服務端從資料庫與請求入口取得；Grants 是「判定結果」，只能由服務端的授權資料產生。
// 因此它不是一個 []Role——後者可以被 encoding/json 從請求本體填滿。
type AccountInput struct {
	// Subject 為帳戶事實。
	Subject AccountSubject
	// Origin 為呼叫來源，僅 http_request|cli 合法。
	Origin Origin
	// Grants 為服務端解析出的伺服器級角色授予（不可來自請求，見 ServerGrants）。
	Grants ServerGrants
}

// ServerGrants 是角色授予的不可匯出欄位載體。
//
// 它存在的唯一理由是把「自報角色」這條路在型別層關死：欄位不匯出、沒有 JSON 標記，
// 所以從請求本體還原出來的 AccountInput 只會帶來一個零值 Grants，
// 而零值 Grants 的語意是「沒有任何角色」。要給出角色就必須顯式呼叫 NewServerGrants，
// 那個呼叫點即審計與審查時要查的「授權資料從哪來」。
type ServerGrants struct {
	roles []Role
}

// NewServerGrants 由服務端已解析的授權資料產生角色授予。
//
// 這裡不做合法性判定（未知的角色、重複授予都留給 NewAccountPrincipal 一次處理），
// 目的是讓「授予從何來」與「授予是否成立」各只有一個說法。
func NewServerGrants(roles ...Role) ServerGrants {
	return ServerGrants{roles: roles}
}

// NewServerGrantsFromStrings 是把授權資料（資料庫欄位、配置字串）轉成授予的入口。
//
// 逐項經 ParseRole，任何一項不認得即整體失敗：一筆寫壞的授權記錄不該被解讀成
// 「他沒有這個角色」，那是把資料缺陷降級成靜默的權限消失。
func NewServerGrantsFromStrings(values ...string) (ServerGrants, error) {
	roles := make([]Role, 0, len(values))
	for i, v := range values {
		r, err := ParseRole(v)
		if err != nil {
			return ServerGrants{}, fmt.Errorf("identity: 角色授予第 %d 項: %w", i+1, err)
		}
		roles = append(roles, r)
	}
	return ServerGrants{roles: roles}, nil
}

// Count 回報這份授予載體攜帶的角色數量；零值回 0，語意是「沒有任何角色」。
//
// 它存在的理由只有一件事：有用例要問「這個帳戶到底有沒有持有授予」這個總量問題
// （訪戶綁定預檢：訪戶按定義应為零授予，查得有任一授予即資料形態缺陷，直接阻止），
// 而 HasRole 只能問「有沒有某一個角色」——對封閉集合逐個探問等於假設角色清單永不增長。
// 欄位 roles 不匯出，計數因此也只能由本載體自己回答：授予的讀法仍只有
// internal/grant 一個來源，這裡不提供繞過它拼裝角色的任何通路。
func (g ServerGrants) Count() int { return len(g.roles) }

// NewAccountPrincipal 構造帳戶主體。
//
// 拒絕清單都是「讓自報身分無處藏身」的具體形態：零值標識（查不到是誰）、
// 禁用帳戶（規格視同不存在）、未知類型（繞過帳戶模型的封閉集合）、
// 訪客帳戶帶角色（無憑據卻有權限）、重複角色（授權資料寫壞）。
func NewAccountPrincipal(in AccountInput) (Principal, error) {
	roles, err := grantedRoles(in.Grants.roles)
	if err != nil {
		return Principal{}, err
	}
	if err := checkOrigin(KindAccount, in.Origin); err != nil {
		return Principal{}, err
	}
	if in.Subject.ID.IsNil() {
		return Principal{}, fmt.Errorf("%w：帳戶主體必須帶帳戶標識", ErrInvalidPrincipal)
	}
	if in.Subject.Status != account.StatusActive {
		return Principal{}, fmt.Errorf("%w：帳戶狀態 %q 不可作為主體（禁用帳戶視同不存在）",
			ErrNotAuthenticated, string(in.Subject.Status))
	}
	if !accountTypeKnown(in.Subject.Type) {
		return Principal{}, fmt.Errorf("%w：不認識的帳戶類型 %q", ErrInvalidPrincipal, string(in.Subject.Type))
	}
	if in.Subject.Type == account.TypeGuest && len(roles) > 0 {
		return Principal{}, fmt.Errorf("%w：訪客帳戶不可持有伺服器級角色", ErrInvalidPrincipal)
	}
	return Principal{
		kind:        KindAccount,
		origin:      in.Origin,
		accountID:   in.Subject.ID,
		accountType: in.Subject.Type,
		roles:       roles,
	}, nil
}

// RootProof 是「Root 憑據已被確實比對通過」的證明，只能由 VerifyRootCredential 發出。
//
// 它存在的目的只有一個：讓 Root 主體無法憑空構造。欄位未匯出且零值視為未通過，
// 所以任何跳過校驗直接呼叫 Root(...) 的寫法都會在構造階段就被拒——
// 「以 Root 身分執行」在生產程式碼裡沒有一條捷徑，只有正確這條路。
type RootProof struct {
	verified bool
}

// Valid 回報證明是否出自一次成功的憑據比對。
func (p RootProof) Valid() bool { return p.verified }

// ErrInvalidCredential 表示憑據比對未通過。
//
// 它是唯一的對外結論：編碼損壞、參數越界與摘要不符在外層收斂成同一個錯誤，
// 呼叫端因此無法用錯誤差異判斷「Root 雜湊是不是這一個」。
var ErrInvalidCredential = errors.New("identity: Root 憑據校驗未通過")

// VerifyRootCredential 比對配置中的 Root Argon2id 雜湊與提供的憑據明文，
// 通過時發出 RootProof。
//
// 這是本套件唯一的 Root 認證入口，也是它不需要新增端點的原因：它不監聽、不開 session、
// 不決定失敗重試策略（那些屬未來的登入路徑），只把「他是不是 Root」這個判斷
// 做成一個無法偽造的憑證。encoding 的解析細節只進被丟棄的包裝鏈，
// 對外一律是 ErrInvalidCredential；明文與雜湊都不進任何錯誤訊息（internal/credential 已保證）。
//
// 空憑據與超長憑據由 credential.Verify 直接判否，不消耗派生資源。
func VerifyRootCredential(encodedHash, secret string) (RootProof, error) {
	if encodedHash == "" {
		// 配置沒寫 Root 雜湊屬部署缺項：報出來，不要退化成「任何憑據都不對」的沉默。
		return RootProof{}, fmt.Errorf("%w：組態未提供 Root 憑據雜湊", ErrInvalidCredential)
	}
	ok, err := credential.Verify(encodedHash, secret)
	if err != nil || !ok {
		return RootProof{}, ErrInvalidCredential
	}
	return RootProof{verified: true}, nil
}

// Root 由已驗證的 Root 憑據構造伺服器級主體。
//
// Root 不帶帳戶標識：它的持久來源是 config.yaml，不在 accounts 表裡（R1-004 決定）。
// 審計需要的穩定主體標識由 RootSubjectID 提供，那是伺服器級常數而非帳戶列。
func Root(proof RootProof, origin Origin) (Principal, error) {
	if !proof.Valid() {
		return Principal{}, fmt.Errorf("%w：構造 Root 主體需要通過校驗的憑據證明", ErrInvalidPrincipal)
	}
	if err := checkOrigin(KindRoot, origin); err != nil {
		return Principal{}, err
	}
	return Principal{kind: KindRoot, origin: origin}, nil
}

// NewSystem 構造伺服器自身的主體（啟動、CLI 子命令、背景任務）。
//
// 它刻意不接受任何帳戶引數：系統行為的主體就是伺服器，把「順帶以某個用戶身分跑」
// 做成參數，等於給了背景任務一條冒充登入用戶的路。
func NewSystem(origin Origin) (Principal, error) {
	if err := checkOrigin(KindSystem, origin); err != nil {
		return Principal{}, err
	}
	return Principal{kind: KindSystem, origin: origin}, nil
}

// Anonymous 回傳匿名主體（零值）。
func Anonymous() Principal { return Principal{} }

// Kind 回傳主體類別（零值讀成 anonymous）。
func (p Principal) Kind() Kind { return p.kind.normalize() }

// Origin 回傳呼叫來源；匿名主體沒有來源。
func (p Principal) Origin() Origin { return p.origin }

// AccountID 回傳帳戶標識；Root、系統與匿名主體回傳零值，呼叫端不得拿它當權限依據。
func (p Principal) AccountID() idgen.ID { return p.accountID }

// AccountType 回傳帳戶類型；非帳戶主體回傳空值。
func (p Principal) AccountType() account.Type { return p.accountType }

// IsAnonymous 回報主體是否未通過認證。
func (p Principal) IsAnonymous() bool { return p.Kind() == KindAnonymous }

// IsRoot 回報主體是否為伺服器級 Root。
func (p Principal) IsRoot() bool { return p.Kind() == KindRoot }

// IsSystem 回報主體是否為伺服器自身。
func (p Principal) IsSystem() bool { return p.Kind() == KindSystem }

// HasRole 回報主體是否持有某個伺服器級角色。Root 一律回傳 false：
// 它的權限不是授予出來的，因此「Root 有沒有 admin 角色」這種問題不該有肯定答案，
// 需要同時接納 Root 與管理員的呼叫端用 Authorize(p, NeedServerAdmin) 而不是 HasRole。
func (p Principal) HasRole(r Role) bool {
	if p.kind != KindAccount {
		return false
	}
	for _, got := range p.roles {
		if got == r {
			return true
		}
	}
	return false
}

// Roles 回傳主體持有的角色副本（不暴露內部切片）；無角色時回傳空值而非 nil 語意的空切片。
func (p Principal) Roles() []Role {
	if len(p.roles) == 0 {
		return nil
	}
	out := make([]Role, len(p.roles))
	copy(out, p.roles)
	return out
}

// String 回傳可安全寫入日誌的摘要：只有類別與來源，不含標識。
//
// 標識本身不是秘密，但把它放進一個「任何地方都能印」的摘要，遲早有人把整行
// 日誌貼進工單；主體摘要要能說明「這是誰這一類、從哪來」就夠了，
// 要追到人請用審計記錄（那裡才有可查的 actor.id）。
func (p Principal) String() string {
	if p.IsAnonymous() {
		return "anonymous"
	}
	return fmt.Sprintf("%s(%s)", p.Kind().String(), string(p.origin))
}

// validate 檢查主體的類別與來源、標識是否自洽。
//
// 構造函式已經擋過一輪，這裡攔的是「以某種方式繞過構造函式得到的值」：
// 目前只可能是零值以外的半成品（例如未匯出欄位被同包程式碼直接賦值）。
// 判定入口一律先呼叫它，缺欄位就報缺陷，不當成權限不足。
func (p Principal) validate() error {
	if p.IsAnonymous() {
		return nil
	}
	if !p.kind.valid() {
		return fmt.Errorf("%w：未知的主體類別 %q", ErrInvalidPrincipal, string(p.kind))
	}
	if err := checkOrigin(p.kind, p.origin); err != nil {
		return err
	}
	switch p.kind {
	case KindAccount:
		if p.accountID.IsNil() {
			return fmt.Errorf("%w：帳戶主體缺少帳戶標識", ErrInvalidPrincipal)
		}
		if !accountTypeKnown(p.accountType) {
			return fmt.Errorf("%w：帳戶主體帶有未知類型 %q", ErrInvalidPrincipal, string(p.accountType))
		}
		if p.accountType == account.TypeGuest && len(p.roles) > 0 {
			return fmt.Errorf("%w：訪客帳戶主體帶有角色", ErrInvalidPrincipal)
		}
	case KindRoot, KindSystem:
		if !p.accountID.IsNil() {
			return fmt.Errorf("%w：%s 主體不可帶帳戶標識", ErrInvalidPrincipal, p.kind.String())
		}
		if len(p.roles) > 0 {
			return fmt.Errorf("%w：%s 主體不可帶授予的角色", ErrInvalidPrincipal, p.kind.String())
		}
	}
	return nil
}

// grantedRoles 校驗並複製授予的角色清單：每項都要落在封閉集合內，且不得重複。
//
// 重複不是無害的整潔問題：同一名角色出現兩次會讓「有幾個角色」這種判斷
// 變成取決於誰數的，而授予資料的來源（未來的授權表）正是最容易重複插入的地方。
func grantedRoles(roles []Role) ([]Role, error) {
	if len(roles) == 0 {
		return nil, nil
	}
	out := make([]Role, 0, len(roles))
	for _, r := range roles {
		if !r.valid() {
			return nil, fmt.Errorf("%w：不認得的伺服器級角色 %q（僅接受已定義值）",
				ErrInvalidPrincipal, string(r))
		}
		for _, got := range out {
			if got == r {
				return nil, fmt.Errorf("%w：角色 %s 重複授予", ErrInvalidPrincipal, string(r))
			}
		}
		out = append(out, r)
	}
	return out, nil
}
