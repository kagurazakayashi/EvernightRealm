// businessstatus.go 是玩家業務狀態的領域模型：一個成員在活動裡「目前處於哪一種業務狀態」，
// 以及活動內可重複選用的自訂狀態定義。
//
// 這個狀態刻意不是連線狀態：它不是由任何 HTTP 請求、頁面開啟、心跳或最後活動時間推導出來的，
// 也不存在自動翻轉。七個內建鍵由使用者批准並永久穩定；管理人可以改的是「顯示名稱」與
// 「自訂定義的名稱」，不是內部值。任何以顯示名稱查找或改寫狀態的通路都不存在。
//
// 內建鍵（永不改名、永不复用）：
//
//	normal（出廠）／suspended／eliminated／dead／arrested／offline／custom
//
// 狀態的業務後果在今日刻意只有一項：它會被如實顯示。沒有任何一條通路會因為狀態是 dead、
// arrested 或 eliminated 而清空資產、退出活動、凍結帳戶或自動撤銷任何東西——那些語意
// 不在本輪批准的範圍內，也不得從狀態名自行推導。
//
// custom 的關係（用戶批准）：
//   - 成員行保存一個內建鍵；當它是 custom 時，另存一個非空的自訂定義標識。
//   - 選擇任何內建鍵（含 custom 以外的六個）都會把自訂定義標識清成空。
//   - 選擇一個自訂定義就是「業務狀態 custom ＋ 該定義的穩定標識」。
//   - 自訂定義只屬於單一活動；跨活動拼接在資料庫觸發器與服務層都被拒絕。
//
// 顯示名稱的邊界：
//   - 內建狀態的四語言預設文案在用戶端；活動層級的覆蓋存在 labels 表裡，空字串代表
//     「使用預設」。覆蓋可以隨時改回空字串，這不是刪除狀態。
//   - 自訂狀態的名稱是管理員提供的純文字，只能當文字顯示，不得被當成 HTML 或任何可執行內容。
package activity

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// BusinessStatus 是成員目前業務狀態的穩定內部值。
type BusinessStatus string

const (
	// BusinessStatusNormal 是出廠狀態：沒有任何額外業務語意。
	BusinessStatusNormal BusinessStatus = "normal"
	// BusinessStatusSuspended 表示暫停參與；今日只影響顯示，不自動凍結任何能力。
	BusinessStatusSuspended BusinessStatus = "suspended"
	// BusinessStatusEliminated 表示已淘汰；今日只影響顯示，不自動清空資產或退出活動。
	BusinessStatusEliminated BusinessStatus = "eliminated"
	// BusinessStatusDead 表示已死亡；今日只影響顯示，不推出活動、不搬動資產。
	BusinessStatusDead BusinessStatus = "dead"
	// BusinessStatusArrested 表示已被拘束；今日只影響顯示，不構成任何隱含權限。
	BusinessStatusArrested BusinessStatus = "arrested"
	// BusinessStatusOffline 是管理員維護的業務狀態，與連線在線狀態無關。
	BusinessStatusOffline BusinessStatus = "offline"
	// BusinessStatusCustom 表示採用一個活動內的自訂狀態定義；定義標識另存一欄。
	BusinessStatusCustom BusinessStatus = "custom"
)

// builtinBusinessStatuses 是七個內建鍵的固定呈現順序。
//
// 這個切片同時是「合法內建鍵」的唯一清單：解析、顯示名稱覆蓋與介面清單都從它派生，
// 避免多處各列一份而漂移。順序屬展示語意，不是業務優先級。
var builtinBusinessStatuses = []BusinessStatus{
	BusinessStatusNormal,
	BusinessStatusSuspended,
	BusinessStatusEliminated,
	BusinessStatusDead,
	BusinessStatusArrested,
	BusinessStatusOffline,
	BusinessStatusCustom,
}

// BuiltinBusinessStatuses 回傳一份內建狀態鍵的副本（固定順序）。
//
// 回傳副本而不是底層切片：呼叫端不得靠改動它來新增一個「內建」值。
func BuiltinBusinessStatuses() []BusinessStatus {
	out := make([]BusinessStatus, len(builtinBusinessStatuses))
	copy(out, builtinBusinessStatuses)
	return out
}

// valid 回報這個值是否為七個內建鍵之一。
func (s BusinessStatus) valid() bool {
	for _, allowed := range builtinBusinessStatuses {
		if s == allowed {
			return true
		}
	}
	return false
}

// IsCustom 回報這個狀態是否需要一個自訂定義標識。
func (s BusinessStatus) IsCustom() bool { return s == BusinessStatusCustom }

// String 回傳穩定內部值本身（不是顯示名稱）。
func (s BusinessStatus) String() string { return string(s) }

// parseBusinessStatus 把請求裡的穩定內部值解析成 BusinessStatus。
//
// 比對逐字相等且只收小寫鍵：顯示名稱、大小寫變體與任何本地化文字都不是內部值，
// 接受它們等於讓同一個狀態出現多種可寫形態。空白不剔除，寫壞了就回點名欄位的錯誤。
func parseBusinessStatus(raw string) (BusinessStatus, error) {
	status := BusinessStatus(raw)
	if !status.valid() {
		return "", fmt.Errorf("%w：%q 不是內建狀態鍵", ErrInvalidBusinessStatus, raw)
	}
	return status, nil
}

// 狀態域的邊界與可判別結論。
const maxStatusNameRunes = 64

var (
	// ErrInvalidBusinessStatus 表示狀態鍵不在七個內建穩定值內，或 custom 與自訂標識的
	// 成對關係不成立（請求寫法問題，對外點名欄位）。
	ErrInvalidBusinessStatus = errors.New("businessstatus: 業務狀態不合法")
	// ErrInvalidStatusName 表示自訂狀態名稱或顯示名稱不符合文字規則。
	ErrInvalidStatusName = errors.New("businessstatus: 狀態名稱不合法")
	// ErrCustomStatusNotFound 表示這個自訂狀態不在呼叫者的可見範圍內：從未存在、屬於另一場
	// 活動，或活動本身不歸呼叫者管——三種情況一律同一個答案。
	ErrCustomStatusNotFound = errors.New("businessstatus: 該自訂狀態不在可見範圍內")
	// ErrCustomStatusUnavailable 表示這個自訂狀態已停用，不再接收新的選用。
	//
	// 停用不清空任何既有成員的狀態、不改寫標識；既有成員保留原狀態並可由介面標示「已停用」。
	ErrCustomStatusUnavailable = errors.New("businessstatus: 該自訂狀態已停用，不再接收新的選用")
	// ErrCustomStatusNameTaken 表示同一活動內已有另一個自訂狀態使用這個名稱。
	// 正確性來源是 UNIQUE (activity_id, name)，先查只是為了給操作者一句人話。
	ErrCustomStatusNameTaken = errors.New("businessstatus: 該活動內已有同名的自訂狀態")
	// ErrCustomStatusConflict 表示編輯自訂狀態所依據的現值已不是資料庫現值：整個編輯沒有發生。
	ErrCustomStatusConflict = errors.New("businessstatus: 自訂狀態現值已與提交時所依據的不同")
	// ErrStatusLabelConflict 表示編輯內建狀態顯示名稱所依據的現值已不是資料庫現值。
	ErrStatusLabelConflict = errors.New("businessstatus: 狀態顯示名稱現值已與提交時所依據的不同")
)

// CustomStatus 是一個活動內的自訂狀態定義（管理面與玩家投影共用同一個事實形狀）。
//
// 它不含任何「誰正在使用」的清單或計數：今日沒有那條讀法，界面也不得拿 0 冒充。
type CustomStatus struct {
	// ID 是穩定標識（身份只有它；名稱可改）。
	ID idgen.ID
	// ActivityID 是歸屬活動，由觸發器釘成不可就地改寫。
	ActivityID idgen.ID
	// Name 是顯示名稱（同活動內唯一；剔首尾空白後比對）。
	Name string
	// Available 是可用性旗標：假＝停用，既有引用保留，但不再接收新的選用。
	Available bool
	// CreatedAt／UpdatedAt 為建立與最後改動時刻（UTC）。
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CustomStatusFields 是自訂狀態可編輯的兩欄白名單（新值與依據值共用）。
type CustomStatusFields struct {
	// Name 是剔首尾空白後的名稱。
	Name string
	// Available 是可用性旗標。
	Available bool
}

// CustomStatusEdit 是一筆自訂狀態編輯：兩欄新值加兩欄提交所依據的現值。
type CustomStatusEdit struct {
	New      CustomStatusFields
	Expected CustomStatusFields
}

// BuiltinStatusView 是一個內建狀態在某一場活動裡的展示現值。
//
// 它不帶可用性：內建狀態永遠可用；「此刻能不能選」只由活動生命週期與自訂狀態的可用性
// 回答。DisplayName 為空字串表示沒有覆蓋，界面應使用四語言預設文案。
type BuiltinStatusView struct {
	// Key 是穩定內部值。
	Key BusinessStatus
	// DisplayName 是活動層級的覆蓋現值（空字串＝使用預設）。
	DisplayName string
}

// PlayerStatusCatalog 是一個活動的狀態定義目錄：七個內建鍵加上自訂定義。
type PlayerStatusCatalog struct {
	// Builtins 依固定順序排列。
	Builtins []BuiltinStatusView
	// Custom 依建立時刻、標識升序排列。
	Custom []CustomStatus
}

// validateStatusDisplayName 校驗並正規化狀態名稱或顯示名稱。
//
// allowEmpty 為真時空字串代表「沒有覆蓋、使用預設」；自訂狀態的名稱則必須非空。
// 規則與活動內暱稱一致：剔首尾空白、1..64 碼位、不含控制或格式字元。
// 這裡刻意不把尖括號、& 等字元當成錯誤：它們是合法文字，安全性來自顯示端只當純文字，
// 而不是靠拒絕某些字元來替代正確的轉義。
func validateStatusDisplayName(raw string, allowEmpty bool) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		if allowEmpty {
			return "", nil
		}
		return "", fmt.Errorf("%w：不可為空", ErrInvalidStatusName)
	}
	if count := utf8.RuneCountInString(name); count > maxStatusNameRunes {
		return "", fmt.Errorf("%w：長度不可超過 %d 個字元，實際 %d",
			ErrInvalidStatusName, maxStatusNameRunes, count)
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", fmt.Errorf("%w：不得含控制或格式字元（U+%04X）", ErrInvalidStatusName, r)
		}
	}
	return name, nil
}
