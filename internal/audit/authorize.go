package audit

import (
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// Viewer 是「誰要讀審計」的主體身分，只用於授權判定。
//
// 它與 Actor 分成兩個型別是有原因的：Actor 是寫入時落庫的「誰做了那件事」，其值來自
// 被操作的那筆請求；Viewer 是讀取時的「誰有權看哪一域」。把兩者合成一個型別，就會出現
// 「拿記錄本身當授權依據」的寫法——那時主體類別是呼叫端可控制的輸入，判定等於沒做
// （ER-SEC-001 §4：最小授權的判定輸入必須來自服務端自己認定的身分）。
//
// 零值不可用：Kind 為空字串時 validate 直接拒絕，所以「忘了帶身分」是一種失敗，
// 不是一種預設。
type Viewer struct {
	// Kind 是主體類別，一律取自封閉集合 ActorKind（ER-IA-001 的四類身份加上服務端自身）。
	Kind ActorKind
	// Activities 是該主體得以讀取的活動清單，只有 admin 用得上。
	//
	// Root 屬伺服器級、所有活動都在其轄下，因此不看清單；player、npc、system 兩域都不可讀，
	// 留了清單也不會生效，故一律拒絕（見 validate）。「填了卻不生效」的介面會被當成
	// 已經收窄過權限，那是比沒有權限更糟的誤會。
	Activities []idgen.ID
}

// 授權判定的三種失敗，語意必須分開：
//
//   - ErrDenied 是「這個身分沒有這個權限」：正常會發生的安全事件，服務層據此回權限錯誤、
//     並可能另記一筆拒絕審計；
//   - ErrInvalidViewer 與 ErrIncompleteScope 是「呼叫端寫錯了」：程式缺陷，不該被當成
//     拒絕存取回報給使用者，否則一個漏帶 activity_id 的查詢會偽裝成權限問題。
var (
	// ErrDenied 表示授權判定拒絕本次讀取。
	ErrDenied = fmt.Errorf("audit: 授權不足")
	// ErrInvalidViewer 表示主體身分本身不合法（未知類別或清單與類別矛盾）。
	ErrInvalidViewer = fmt.Errorf("audit: 主體身分不合法")
	// ErrIncompleteScope 表示作用域條件不合法（activity 域缺標識、root 域多帶標識）。
	ErrIncompleteScope = fmt.Errorf("audit: 審計查詢的作用域條件不合法")
)

// Authorize 判定「這個身分能否讀這個作用域裡的這個活動」，回傳 nil 表示可以。
//
// 規則取自 ER-IA-001 的四類身份與規格 §25.1／§25.2 的歸屬：
//   - Root：可讀 Root 域，也可讀任一活動的活動域（§4.1 定其為伺服器級且不屬於任何活動角色）；
//   - 管理員：只可讀自己獲授權活動的活動域，永不觸及 Root 域——Root 審計記的正是
//     管理員自己的增刪與伺服器設定，讓被管理的人看得到管理記錄等於把權限反過來；
//   - 玩家、NPC：兩域皆不可讀（§25 的審計主體是管理動作，玩家的活動內可見內容由
//     各自的業務端點按欄位級可見性過濾，不是把整本審計翻開）；
//   - system：不是一種「閱覽身分」，故也不可讀。
//
// 這裡同時校驗 activity_id 與作用域的匹配：規則只寫在 Authorize 一處，查詢與未來的
// 服務層預檢共用同一份判定，才不會出現「端點先放行、存取層才拒絕」這種兩套答案。
func Authorize(v Viewer, scope Scope, activityID idgen.ID) error {
	if err := v.validate(); err != nil {
		return err
	}
	switch scope {
	case ScopeRoot:
		if !activityID.IsNil() {
			// 靜默忽略會被當成「已經過濾了」：Root 表裡本來就沒有 activity_id 這個欄位。
			return fmt.Errorf("%w：root 作用域的查詢不接受 activity_id", ErrIncompleteScope)
		}
	case ScopeActivity:
		if activityID.IsNil() {
			return fmt.Errorf("%w：查詢 activity 審計必須指定 activity_id", ErrIncompleteScope)
		}
	default:
		if _, err := scope.table(); err != nil {
			return err
		}
	}

	switch v.Kind {
	case ActorRoot:
		return nil
	case ActorAdmin:
		if scope == ScopeRoot {
			return fmt.Errorf("%w：admin 不得讀取 Root 審計（規格 §25.2 將其歸給 Root 控制檯）", ErrDenied)
		}
		for _, id := range v.Activities {
			if id == activityID {
				return nil
			}
		}
		return fmt.Errorf("%w：admin 只能讀自己獲授權活動的審計，指定的活動不在清單內", ErrDenied)
	case ActorPlayer, ActorNPC, ActorSystem:
		return fmt.Errorf("%w：%s 不具備審計查閱權限", ErrDenied, string(v.Kind))
	}
	// 走到這裡代表 Kind 已透過 validate 卻沒有對應規則——日後新增身份時忘了在這裡補一條。
	// 以拒絕收尾：讓漏規則的身份讀不到東西，比讓它讀到一切更容易被發現。
	return fmt.Errorf("%w：主體類別 %q 尚無對應的審計查閱規則", ErrDenied, string(v.Kind))
}

// validate 檢查身分的類別與清單是否自洽。
func (v Viewer) validate() error {
	if !v.Kind.valid() {
		return fmt.Errorf("%w：actor.kind 需為 root|admin|player|npc|system，實際為 %q",
			ErrInvalidViewer, string(v.Kind))
	}
	if v.Kind != ActorAdmin && len(v.Activities) > 0 {
		return fmt.Errorf("%w：%s 的讀取範圍不由清單決定，Activities 應留空", ErrInvalidViewer, string(v.Kind))
	}
	// 零值標識混在清單裡會讓「這一項永不命中」變成沉默事實，不如當場拒絕。
	for i, id := range v.Activities {
		if id.IsNil() {
			return fmt.Errorf("%w：admin 的 Activities 第 %d 項是零值標識", ErrInvalidViewer, i+1)
		}
	}
	return nil
}
