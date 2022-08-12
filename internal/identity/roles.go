package identity

import (
	"fmt"
)

// Role 是伺服器級角色：回答「這個帳戶被授權做哪一類跨活動的事」。
//
// 封閉集合，且只有帳戶可以持有。兩個邊界要守住：
//   - Root 不是角色（它是主體類別，見 Kind）。一旦 Root 可以被寫進某張授予表，
//     「誰是 Root」就變成資料問題而不是配置問題，那道最後防線隨之消失；
//   - 活動內角色（活動管理員、玩家、NPC 操作者）不在這裡。把「某活動的管理員」
//     做成伺服器級角色，等於讓它在所有活動都是管理員——那正是「拿全局檢查冒充活動隔離」。
//
// 本輪只定義伺服器管理員一檔：它是 Root 之下、可執行跨活動維運（伺服器設定、
// 備份與恢復、帳戶管理）的主體，仍然讀不到 Root 域審計（規則在 internal/audit）。
type Role string

const (
	// RoleServerAdmin 是伺服器級管理員：Root 之外的維運主體。
	RoleServerAdmin Role = "server_admin"
)

// String 回傳角色的機器表示。
func (r Role) String() string { return string(r) }

// valid 回報是否為已定義角色。
func (r Role) valid() bool {
	switch r {
	case RoleServerAdmin:
		return true
	}
	return false
}

// ErrUnknownRole 表示把一個不認得的角色字串當成角色使用。
//
// 它屬程式缺陷而不是權限判定：一個字串拼錯就等於那次授予永不生效，
// 靜默忽略會讓「我明明給了權限」變成查不出來的幽靈問題。
var ErrUnknownRole = fmt.Errorf("identity: 不認得的伺服器級角色")

// ParseRole 是把外部字串轉成 Role 的唯一入口，供將來的授權資料讀取路徑使用。
//
// 只認封閉集合內的值，因此請求本體或請求頭裡任何自報的角色宣稱都到不了主體：
// 傳進來一個 "root"、"admin" 或 "" 一律拒絕，不存在「先收下再說」的空間。
// 大小寫與空白也不放過——同一個角色有兩種寫法時，授予表就能造出兩個不同的權限。
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if !r.valid() {
		return "", fmt.Errorf("%w：%q（僅接受已定義值，不接受空白與大小寫變體）", ErrUnknownRole, s)
	}
	return r, nil
}
