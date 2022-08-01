// Package audit 提供統一的操作審計介面：Root 審計與活動審計的只追加存儲與查詢。
//
// 為什麼要有這個套件（規格 §25、決策記錄 DEC-029）：管理動作的「誰、對誰、做了什麼、
// 為什麼、何時、改前後差什麼」必須留得比普通日誌更久。規格 §32 把兩者分成兩個體系：
// 普通日誌可輪替、可淘汰，審計不可——因此審計不經 internal/runlog 的管線，
// 直接落在資料庫的兩張表裡（root_audit、activity_audit），
// 跟著資料庫一起備份與恢復，並由遷移裡的觸發器在 SQL 層擋下修改與刪除。
//
// 三條不可讓步：
//   - 時間與標識不交給呼叫端也不交給客戶端：created_at 取自注入的時鐘（DEC-015），
//     主鍵取自 idgen（DEC-014，全服務唯一產生點）；
//   - 變更摘要的值在離開本套件前一律過 ER-SEC-001 §7 的遮罩管線（internal/redact），
//     PIN、憑證與聊天正文進不了審計表；
//   - 本套件不提供任何修改或刪除的通路。Aud-003 的「不得物理刪除」在應用層與資料庫層各擋一次。
package audit

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/redact"
)

// Scope 決定一筆審計記錄落在哪張表，也決定查詢讀哪張表。
//
// 兩張表而不是「一張表加 scope 欄位」是刻意的：跨作用域讀取因此需要顯式換一個目標，
// 而不是「記得加一個 WHERE」（規格 §25.1 與 §25.2 的可讀範圍本來就不同）。
type Scope string

// 審計作用域。
const (
	// ScopeRoot 是 Root 層審計（Root 登入與失敗、管理員增刪、伺服器設定、備份與恢復、
	// 維護模式、重啟與關閉；規格 §25.2）。
	ScopeRoot Scope = "root"
	// ScopeActivity 是活動層審計（活動、玩家、陣營、資產與權限、規則、刪除訊息、
	// 廣播、撤銷交易、餘額變更與批量操作；規格 §25.1）。
	ScopeActivity Scope = "activity"
)

// ActorKind 是審計主體的身分類別（ER-IA-001 的四類身份加上服務端自身）。
type ActorKind string

// 主體類別。
const (
	ActorRoot   ActorKind = "root"
	ActorAdmin  ActorKind = "admin"
	ActorPlayer ActorKind = "player"
	ActorNPC    ActorKind = "npc"
	ActorSystem ActorKind = "system"
)

// table 回傳本作用域的實際表名（唯一的字串來源，查詢與寫入共用）。
func (s Scope) table() (string, error) {
	switch s {
	case ScopeRoot:
		return "root_audit", nil
	case ScopeActivity:
		return "activity_audit", nil
	default:
		return "", fmt.Errorf("audit: 未知的審計作用域 %q（僅 root|activity）", string(s))
	}
}

// Actor 是誰做了這件事。
type Actor struct {
	// Kind 是主體類別。
	Kind ActorKind
	// ID 是主體的實體標識；ActorSystem（啟動、背景任務、一次性命令）沒有標識，留 Nil。
	ID idgen.ID
}

// Target 是被操作的對象。
type Target struct {
	// Kind 是穩定機器名詞（如 admin、player、server_settings、phase、message），
	// 不是給人讀的句子：它會進資料庫索引與查詢條件。
	Kind string
	// ID 是該對象的標識；沒有可標識對象的動作（例如進入維護模式）留空字串。
	ID string
}

// Change 是一個欄位的變更。
//
// Before／After 採 JSON 原生型別存放：數值與布林原樣保留（餘額從 500 變成 300 這種事實
// 必須查得出來），字串一律先過 §7 遮罩。非字串也非原生型別的值（結構體、切片）
// 先壓成文字再遮罩。
type Change struct {
	Field  string
	Before any
	After  any
}

// 長度上限：與遷移裡的 CHECK 同值，兩邊各寫一份時以這裡為準（啟動階段的校驗擋不住
// 執行期寫入，DB 的 CHECK 才是最後一道；這裡先擋是為了給出可判讀的錯誤）。
const (
	maxActionLen   = 64
	maxTargetLen   = 64
	maxReasonLen   = 500
	maxRequestID   = 64
	maxChanges     = 64
	maxChangesByte = 64 << 10
)

// Record 是一筆審計記錄（規格 §25.1 的六要素：操作者、時間、目標、動作、原因、前後摘要）。
//
// ID 與 CreatedAt 不是呼叫端的欄位：Append 一律拒絕已帶值者並自行產生（標識取自 idgen、
// 時刻取自伺服器時鐘），Query 才把兩者讀回來。放任一端預先填值就等於繞過
// 「標識與時間只有一個來源」（DEC-014、DEC-015）與「不採信客戶端時間」（§27.2）兩條約定。
type Record struct {
	// Scope 決定落點與查詢作用域。
	Scope Scope
	// ID 為記錄標識（UUIDv7）；Append 時由 idgen 產生並經回傳值交還，Query 時由資料庫讀回。
	ID idgen.ID
	// CreatedAt 為記錄寫入時刻（伺服器時鐘，UTC）。
	CreatedAt time.Time
	// ActivityID 僅 ScopeActivity 必填；ScopeRoot 必須為 Nil（Root 事件不屬於任何活動）。
	ActivityID idgen.ID
	// Actor 為操作主體。
	Actor Actor
	// Action 為穩定的機器碼（如 admin.create），四語言介面文字不進這裡：
	// 審計是事實記錄，翻譯屬顯示層。
	Action string
	// Target 為被操作的對象。
	Target Target
	// Reason 為原因。ScopeActivity 必填（§25.1 把它列為每筆記錄的要素）；
	// ScopeRoot 可空（「Root 登入成功」這類事件沒有可寫的原因）。
	// 高風險操作「必須由操作者填寫原因」的約束屬服務層，隨各端點落地。
	Reason string
	// RequestID 為請求關聯 ID，與回應標頭 X-Request-Id 同源；
	// 非請求驅動的操作（啟動、背景任務、一次性命令）留空字串——空值在表裡是 NULL，
	// 語意為「本來就沒有請求」，不拿佔位字串冒充。
	RequestID string
	// Changes 為前/後摘要（可為空：登入、廣播、重啟這類操作沒有欄位差量）。
	Changes []Change
}

// validate 檢查記錄的必填項與格式，錯誤訊息點出欄位名。
//
// 這裡刻意把「誰必須填原因」「哪個作用域要有 activity_id」寫成代碼而不是文件約定：
// 審計表的價值在於事後一定查得到，而放寬一筆就等於那段時間的記錄不可信。
func (r Record) validate() error {
	if _, err := r.Scope.table(); err != nil {
		return err
	}
	if r.Scope == ScopeActivity && r.ActivityID.IsNil() {
		return errors.New("audit: activity 作用域的記錄必須帶 activity_id")
	}
	if r.Scope == ScopeRoot && !r.ActivityID.IsNil() {
		return errors.New("audit: root 作用域的記錄不得帶 activity_id")
	}
	if !r.Actor.Kind.valid() {
		return fmt.Errorf("audit: actor.kind 需為 root|admin|player|npc|system，實際為 %q", string(r.Actor.Kind))
	}
	if r.Actor.Kind != ActorSystem && r.Actor.ID.IsNil() {
		return errors.New("audit: 非系統主體的記錄必須帶 actor.id（否則事後查不出是誰）")
	}
	if r.Actor.Kind == ActorSystem && !r.Actor.ID.IsNil() {
		return errors.New("audit: actor.kind=system 時 actor.id 應留空")
	}
	if err := validateMachineCode("action", r.Action, maxActionLen); err != nil {
		return err
	}
	if err := validateMachineCode("target.kind", r.Target.Kind, maxTargetLen); err != nil {
		return err
	}
	if len(r.Target.ID) > maxTargetLen {
		return fmt.Errorf("audit: target.id 長度不可超過 %d，實際為 %d", maxTargetLen, len(r.Target.ID))
	}
	if len(r.Target.ID) > 0 && !printable(r.Target.ID) {
		return errors.New("audit: target.id 含控制字元")
	}
	if r.Scope == ScopeActivity && strings.TrimSpace(r.Reason) == "" {
		return errors.New("audit: activity 作用域的記錄必須填 reason（規格 §25.1）")
	}
	if n := utf8.RuneCountInString(r.Reason); n > maxReasonLen {
		return fmt.Errorf("audit: reason 長度不可超過 %d 個字元，實際為 %d", maxReasonLen, n)
	}
	if len(r.RequestID) > maxRequestID {
		return fmt.Errorf("audit: request_id 長度不可超過 %d", maxRequestID)
	}
	if len(r.Changes) > maxChanges {
		return fmt.Errorf("audit: 單筆記錄的變更欄位不可超過 %d 個（實際 %d）；批量操作請記一筆摘要而非逐筆展開",
			maxChanges, len(r.Changes))
	}
	for _, c := range r.Changes {
		if err := validateMachineCode("changes.field", c.Field, maxTargetLen); err != nil {
			return err
		}
	}
	return nil
}

// valid 回傳主體類別是否為已定義值。
func (k ActorKind) valid() bool {
	switch k {
	case ActorRoot, ActorAdmin, ActorPlayer, ActorNPC, ActorSystem:
		return true
	default:
		return false
	}
}

// validateMachineCode 檢查會進索引與查詢條件的識別欄位：
// 只收小寫字母、數字與 `_`、`.`、`-`，且不得為空或超長。
//
// 審計的 action／target.kind／欄位名是要被程式比對的穩定碼，
// 放進空格、全形字或控制字元的話，同一個動詞就會出現兩種寫法而查不齊。
func validateMachineCode(name, value string, limit int) error {
	if value == "" {
		return fmt.Errorf("audit: %s 不可為空", name)
	}
	if len(value) > limit {
		return fmt.Errorf("audit: %s 長度不可超過 %d，實際為 %d", name, limit, len(value))
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '.', c == '-':
		default:
			return fmt.Errorf("audit: %s 需為小寫機器碼（a-z0-9_.-），實際為 %q", name, value)
		}
	}
	return nil
}

// printable 回傳文字是否全為可列印字元（含空白）。
func printable(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// maskText 給自由文字欄位（reason、request_id）：鍵名規則不適用，但仍要掃憑證形狀並限長。
func maskText(value string) string {
	return redact.Text(value)
}
