package identity

import (
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// rootSubjectIDText 是伺服器級 Root 主體的保留標識。
//
// 為什麼 Root 需要一個標識：internal/audit 的校驗規定「非 system 主體的記錄必須帶
// actor.id」，否則 Root 做過的管理動作在事後查不出是誰——而全服務只有一個 Root，
// 它的憑據又不在資料庫裡（沒有 accounts 列可指）。這裡放一個保留常數，好處是
// 不必為 Root 造一行帳戶資料、不必放寬那條校驗，也不必把憑據-hash 當身份
// （換密碼不該讓審計裡的身份跟著變）。
//
// 形狀要求：必須是 idgen 接受的正規小寫 UUIDv7（版本欄 7、變體欄 10xx），
// 這樣它才能原樣寫進審計表又被讀回來。字串本身刻意拼出 "root" 的十六進位表示，
// 讓人一眼看出這不是一個真實帳戶的主鍵。它永不進 accounts 表，也不得被當成任何可查詢實體。
const rootSubjectIDText = "00000000-0000-7000-8000-726f6f740000"

// RootSubjectID 回傳 Root 主體的保留標識。
//
// 回傳錯誤而不是 panic：常數理應永遠解析得過（有測試盯著），但拿一個「解析失敗就當它是零值」
// 的寫法去構造 Root 審計主體，失敗時會靜默留下沒有 actor.id 的記錄，那比啟動階段就報出來更糟。
func RootSubjectID() (idgen.ID, error) {
	id, err := idgen.Parse(rootSubjectIDText)
	if err != nil {
		return idgen.Nil, fmt.Errorf("%w：Root 保留主體標識不合法: %w", ErrInvalidPrincipal, err)
	}
	if id.IsNil() {
		// 零值標識會落地成 NULL，讀回時被 audit 當成「系統主體」，等於把 Root 的動作記成伺服器自發。
		return idgen.Nil, fmt.Errorf("%w：Root 保留主體標識不可是零值", ErrInvalidPrincipal)
	}
	return id, nil
}

// AuditActor 把主體換成 S09 審計所需的操作者表示。
//
// 這是「受信上下文 → 審計」的唯一通路：各模組不再自己湊 audit.Actor{Kind: ...}，
// 因為 Kind 一旦能被呼叫端隨意填寫，審計裡的「誰做了那件事」就變成自報。
// 換不出去的一律回錯誤，不降級成 system：把一個查不到身分的动作記成
// 「伺服器自己做的」，這條記錄從此失去追查價值，而且看起來像有記錄。
//
//   - 系統主體 → ActorSystem（無標識，語意就是伺服器自身）；
//   - Root → ActorRoot 帶保留標識；
//   - 持有伺服器級管理權限的帳戶 → ActorAdmin 帶帳戶標識；
//   - 其他帳戶 → ErrActivityScopeUnsupported：玩家／NPC 是活動內身份，未落地前不猜；
//   - 匿名 → ErrNotAuthenticated。
func (p Principal) AuditActor() (audit.Actor, error) {
	if err := p.validate(); err != nil {
		return audit.Actor{}, err
	}
	switch p.Kind() {
	case KindSystem:
		return audit.Actor{Kind: audit.ActorSystem}, nil
	case KindRoot:
		id, err := RootSubjectID()
		if err != nil {
			return audit.Actor{}, err
		}
		return audit.Actor{Kind: audit.ActorRoot, ID: id}, nil
	case KindAccount:
		if !p.HasRole(RoleServerAdmin) {
			return audit.Actor{}, fmt.Errorf("%w：主體 %s 的活動內身份尚未落地，無法決定其審計主體類別",
				ErrActivityScopeUnsupported, p.String())
		}
		return audit.Actor{Kind: audit.ActorAdmin, ID: p.accountID}, nil
	default:
		return audit.Actor{}, fmt.Errorf("%w：匿名主體不可作為審計操作者", ErrNotAuthenticated)
	}
}

// ActivityGrants 是「這個帳戶在哪些活動裡是管理員」的可信清單。
//
// 它只從 NewActivityGrants 產生，內容必須來自服務端自己查出的授權資料，
// 不可取自請求。這個型別存在的意義是把「活動清單」這個輸入顯式化：
// 呼叫端要傳就得先證明它有一個來源，而不是漏帶時以零值默默變成「哪個活動都不能看」。
type ActivityGrants struct {
	ids []idgen.ID
}

// NewActivityGrants 構造活動授權清單，拒絕零值標識與重複項。
//
// 傳進來零值標識時，audit.Viewer 的校驗會當場報錯，但那條錯誤說的是「第 N 項是零值」，
// 而真正的答案是「你的授權資料來源有問題」——在這裡報出來比較接近事實。
// 空清單是合法的：它表示「這個主體沒有活動管理權」，查閱一律被拒。
func NewActivityGrants(ids ...idgen.ID) (ActivityGrants, error) {
	seen := make(map[idgen.ID]bool, len(ids))
	out := make([]idgen.ID, 0, len(ids))
	for i, id := range ids {
		if id.IsNil() {
			return ActivityGrants{}, fmt.Errorf("%w：活動授權清單第 %d 項是零值標識", ErrInvalidPrincipal, i+1)
		}
		if seen[id] {
			return ActivityGrants{}, fmt.Errorf("%w：活動授權清單重複同一個活動（第 %d 項）", ErrInvalidPrincipal, i+1)
		}
		seen[id] = true
		out = append(out, id)
	}
	return ActivityGrants{ids: out}, nil
}

// IDs 回傳活動標識副本（不暴露內部切片）。
func (g ActivityGrants) IDs() []idgen.ID {
	if len(g.ids) == 0 {
		return nil
	}
	out := make([]idgen.ID, len(g.ids))
	copy(out, g.ids)
	return out
}

// AuditViewer 把主體換成 S09 審計查閱所需的閱覽身分。
//
// 與 AuditActor 分成兩件事是沿用 internal/audit 的既有取向：寫入時的「誰做了那件事」
// 與讀取時的「誰有權看哪一域」不能是同一個來源，否則就拿記錄本身當授權依據了。
// granted 只在帳戶主體上用得著（管理員能讀哪些活動），Root 與系統主體帶了會被
// audit.Viewer 的校驗拒絕——那不是疏忽，是把「填了卻不生效」擋在構造階段。
//
// 查閱域完全沿用 internal/audit 既有規則，這裡不加一條也不放寬一條：
// Root 可讀兩域、管理員只讀自己獲授權活動、玩家與 NPC 與系統兩域都不可讀。
func (p Principal) AuditViewer(granted ActivityGrants) (audit.Viewer, error) {
	if err := p.validate(); err != nil {
		return audit.Viewer{}, err
	}
	switch p.Kind() {
	case KindRoot:
		return audit.Viewer{Kind: audit.ActorRoot}, nil
	case KindSystem:
		return audit.Viewer{Kind: audit.ActorSystem}, nil
	case KindAccount:
		if !p.HasRole(RoleServerAdmin) {
			return audit.Viewer{}, fmt.Errorf("%w：主體 %s 不是伺服器級管理員，無活動審計的查閱域",
				ErrPermissionDenied, p.String())
		}
		return audit.Viewer{Kind: audit.ActorAdmin, Activities: granted.IDs()}, nil
	default:
		return audit.Viewer{}, fmt.Errorf("%w：匿名主體不可查閱審計", ErrNotAuthenticated)
	}
}
