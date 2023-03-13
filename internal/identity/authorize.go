package identity

import (
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// 授權判定的錯誤。分成四類是為了讓「拒絕」與「寫錯了」在日誌與回應裡不可能互换：
//
//   - ErrNotAuthenticated：連是誰都不知道，先談身分再談權限；
//   - ErrPermissionDenied：身分可信、但這個身分沒有這個權限——正常的安全事件，
//     服務層據此回權限錯誤，未來各端點自己決定要不要另記一筆拒絕審計；
//   - ErrInvalidPrincipal / ErrInvalidRequirement：構造或呼叫有缺陷（繞過構造函式拿到的
//     半成品主體、未知的授權需求），不該被當成拒絕存取回報給使用者；
//   - ErrActivityScopeUnsupported：要問的是「這個帳戶在活動內扮演誰」（玩家檔案／NPC 操作者），
//     那一層尚未落地——它與「他是不是這個活動的管理人」不是同一件事，後者見 AuthorizeActivityScope。
//     目前只有審計主體類別這一處回它（見 audit.go 的 AuditActor）。
var (
	ErrNotAuthenticated         = errors.New("identity: 主體未通過認證")
	ErrPermissionDenied         = errors.New("identity: 權限不足")
	ErrInvalidPrincipal         = errors.New("identity: 受信主體不合法")
	ErrInvalidRequirement       = errors.New("identity: 授權需求不合法")
	ErrActivityScopeUnsupported = errors.New("identity: 活動作用域的授權尚未落地")
	// ErrMissingActivityScope 表示要求活動作用域判定時沒帶活動標識。
	//
	// 它跟未實現分開是有必要的：缺標識是呼叫端漏了引數，補上就能继续往下走；
	// 未實現則是整條路都還沒建，補標識也不會有任何改變。
	ErrMissingActivityScope = errors.New("identity: 活動作用域判定缺少 activity 標識")
)

// Need 是要判定的伺服器級授權需求。
//
// 需求是一個封閉枚舉而不是一堆 Require* 各自實作：全服務的角色判定只有 Authorize 一處，
// 新增一檔需求時只需要在這裡補一條規則，不可能出現「某個端點自己寫了一套寬一點的判定」。
type Need string

const (
	// NeedAuthenticated 只要求「知道是誰」：任何已認證主體（帳戶、Root、伺服器自身）通過。
	NeedAuthenticated Need = "authenticated"
	// NeedServerAdmin 要求伺服器級管理權：Root 或持有 RoleServerAdmin 的帳戶通過。
	// 這是 Root 之外唯一能執行跨活動維運的檔位。
	NeedServerAdmin Need = "server_admin"
	// NeedRoot 只讓 Root 通過：Root 域審計、Root 憑據本身的變更這類「不能被下放到帳戶」的動作。
	NeedRoot Need = "root"
)

// String 回傳需求的機器表示。
func (n Need) String() string { return string(n) }

// Authorize 判定「這個主體能否執行一項帶有這個伺服器級需求的動作」，回傳 nil 表示可以。
//
// 規則一覽（意圖寫在一起才看得出漏項）：
//   - 匿名／零值主體：任何敏感需求都不通過。這是預設立場，不是例外；
//   - Root：三檔全過——它是伺服器級主體，不屬於任何活動也不受活動角色制約；
//   - 持有 RoleServerAdmin 的帳戶：NeedAuthenticated 與 NeedServerAdmin 通過，
//     NeedRoot 不通過（Root 域的事不因為「是管理員」就能做，見 internal/audit 的同一取向）；
//   - 普通與訪客帳戶：只過 NeedAuthenticated。它們在活动里的權限属於活动作用域，
//     本函式不假裝知道，也不因「他當然是玩家」而放行；
//   - 系統主體（啟動、CLI、背景）：只過 NeedAuthenticated。它不是任何人的代理，
//     所以不能頂著管理員名義執行需要授權的業務動作——維運類動作的授權主體應當是 Root，
//     系統主體只是「伺服器自己在做事」這件事的記錄者。
//
// 主體自身不合法時一律先報缺陷（ErrInvalidPrincipal）再談權限：一個欄位缺漏的主體
// 被回成「權限不足」，會讓呼叫端以為擋住了，實際是拿到了一個不可信的物件。
func Authorize(p Principal, need Need) error {
	if err := p.validate(); err != nil {
		return err
	}
	switch need {
	case NeedAuthenticated:
		if p.IsAnonymous() {
			return fmt.Errorf("%w：無法判定動作主體", ErrNotAuthenticated)
		}
		return nil
	case NeedServerAdmin:
		if p.IsAnonymous() {
			return fmt.Errorf("%w：敏感動作需要已認證主體", ErrNotAuthenticated)
		}
		if p.IsRoot() || p.HasRole(RoleServerAdmin) {
			return nil
		}
		return fmt.Errorf("%w：%s 主體不具備伺服器級管理權限", ErrPermissionDenied, p.Kind().String())
	case NeedRoot:
		if p.IsAnonymous() {
			return fmt.Errorf("%w：Root 域動作需要已認證主體", ErrNotAuthenticated)
		}
		if p.IsRoot() {
			return nil
		}
		return fmt.Errorf("%w：Root 域動作只接受 Root 主體，實際為 %s", ErrPermissionDenied, p.Kind().String())
	default:
		return fmt.Errorf("%w：未知的授權需求 %q（僅 authenticated|server_admin|root）",
			ErrInvalidRequirement, string(need))
	}
}

// AuthorizeActivityScope 是活動作用域判定的唯一入口：主體是否是「這個活動」的管理人。
//
// 它與 Authorize(p, NeedServerAdmin) 是兩道不一樣的閘，前後都要過：
//   - NeedServerAdmin 回答的是「他屬於管理員這個身份面嗎」——跨活動維運的資格；
//   - 本函式回答的是「這個資格在這個活動上認不認得他」——活動隔離本身。
//     只過第一道就是「拿全域管理員檢查冒充活動隔離」：甲活動的管理員查得到、改得動
//     乙活動的資料，程式碼看起來却有在做授權（R1-006 把這句話寫成警報，本函式是它的落點）。
//
// granted 一律由呼叫端從服務端自己查出的指派資料構造（見 internal/activity 的
// Store.ManagedActivityIDs 與 identity.NewActivityGrants）：請求本體沒有任何格子能填它。
// 空清單是合法輸入，語意是「他在任何活動裡都不是管理人」，因此一律拒——
// 「漏帶授權資料」在這裡不會默默變成「哪個活動都能管」。
//
// 規則（與 Authorize、internal/audit 同一套說法，這裡不放寬也不另立）：
//   - Root：放行。它是伺服器級主體，不屬於任何活動、也不受活動角色制約，
//     跨活動維運本來就是它的職責（審計側同樣是「Root 兩域可讀」）；
//   - 系統主體（啟動、CLI、背景）：拒。它不是任何人的代理，
//     「伺服器自己在某個活動裡做了這件事」要等到有明確的背景用例時再談；
//   - 帳戶：只有指派清單認得這個活動時才放行；
//   - 匿名：先撞在「不知道是誰」上，身分問題的優先級高於作用域問題。
//
// 主體自身不合法時一律先報缺陷（ErrInvalidPrincipal）再談權限；缺 activity 標識回報的是
// 引數缺陷（ErrMissingActivityScope）而不是權限不足——補上標識就能往下走，
// 而「他確實不是這個活動的管理人」補什麼都不會變。
func AuthorizeActivityScope(p Principal, activityID idgen.ID, granted ActivityGrants) error {
	if err := p.validate(); err != nil {
		return err
	}
	if p.IsAnonymous() {
		return fmt.Errorf("%w：活動作用域動作需要已認證主體", ErrNotAuthenticated)
	}
	if activityID.IsNil() {
		return fmt.Errorf("%w：%s 主體的查詢必須指定 activity_id",
			ErrMissingActivityScope, p.Kind().String())
	}
	switch p.Kind() {
	case KindRoot:
		return nil
	case KindSystem:
		return fmt.Errorf("%w：系統主體不是任何人的代理，不能在活動 %s 內代行管理動作",
			ErrPermissionDenied, activityID.String())
	case KindAccount:
		for _, id := range granted.ids {
			if id == activityID {
				return nil
			}
		}
		// 拒絕的訊息不說「這個活動存不存在」：指派清單查不出沒被指派的那個活動是真沒有
		// 還是只是輪不到他，呼叫端因此也沒有多得到一枚可探測的信號。
		return fmt.Errorf("%w：主體 %s 未被指派為活動 %s 的管理人",
			ErrPermissionDenied, p.String(), activityID.String())
	default:
		return fmt.Errorf("%w：%s 主體沒有活動作用域的身分", ErrPermissionDenied, p.Kind().String())
	}
}
