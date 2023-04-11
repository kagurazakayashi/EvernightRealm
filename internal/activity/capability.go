// capability.go 是「業務狀態規則與手動限制的組合判定」的領域模型：
// 六項穩定能力鍵、四個拒絕來源、活動層級的狀態能力矩陣，以及單一判定的結果形狀。
//
// 這一步的組合規則由用戶明確批准，別處不得各講一套：
//   - 逐能力獨立：每一個能力只回答它自己有沒有被任何來源拒絕；login 被拒絕
//     不會自動改寫其餘五項的結果（界面另行標示「無法進入，其餘能力實際不可達」）。
//   - 各來源拒絕優先：identity、lifecycle、status、manual 四個來源並列，
//     任何一個拒絕即該能力拒絕；解除其中一個不覆蓋另一個。
//   - 身份資格是前置來源：帳戶失效、成員行不存在或讀不到時，所有能力一律拒絕。
//   - 生命週期只拒絕五項業務能力，不拒絕 login：停止與歸檔的活動仍可被查看，
//     「活動只讀」是這個意思。生命週期永遠不由狀態規則編輯器改寫。
//   - 狀態只增加禁止項：它不會放寬手動限制、生命週期或身份資格；也沒有任何
//     「管理員身分豁免」——狀態規則作用在成員行上，/admin 通路另按伺服器級授予判定。
//
// 六項能力鍵刻意與六枚分項限制鍵一一對應（login、chat、private_chat、trade、
// transfer、item_use）：手動限制的每一欄就是它同名能力的直接來源，
// 不存在「限制鍵」與「能力鍵」兩套可能漂移的封閉集合。型別別名讓兩者逐字相同。
//
// 自訂業務狀態不進本矩陣：它的名稱由管理員自由填寫，讓名稱參與能力判定等於
// 從名字推測行為。自訂狀態今日只被顯示，不拒絕任何能力；`custom` 那一列在
// 出廠與任何配置裡都應保持全允許，服務層也不接受自訂定義成為規則鍵。
package activity

import (
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
)

// CapabilityKey 是活動內一項能力的穩定鍵。
//
// 它與 MemberRestrictionKey 是同一個型別：今日六項能力正好就是六枚手動限制，
// 讓兩者共用封閉集合與 String()，避免第二份清單漂移。鍵本身永不改名、永不復用。
type CapabilityKey = MemberRestrictionKey

// CapabilityKeys 回傳六項能力鍵的副本（固定順序：login、chat、private_chat、
// trade、transfer、item_use）。
func CapabilityKeys() []CapabilityKey { return MemberRestrictionKeys() }

// CapabilitySource 是一個能力拒絕的來源類別。
//
// 它是對外可讀的分類，不是內部原因句：玩家看到「被業務狀態限制」這句話，
// 讀不到是誰在什麼時候用什麼理由設定的；操作者、時刻與自由文字只活在審計裡。
type CapabilitySource string

const (
	// CapabilitySourceIdentity 表示身份資格失效：帳戶停用／刪除／退休，或成員行
	// 讀不到。它是最前置的來源，拒絕所有能力。
	CapabilitySourceIdentity CapabilitySource = "identity"
	// CapabilitySourceLifecycle 表示活動生命週期：停止與歸檔拒絕五項業務能力，
	// 但不禁用查看（login 不在它的作用範圍內）。
	CapabilitySourceLifecycle CapabilitySource = "lifecycle"
	// CapabilitySourceStatus 表示當前業務狀態的規則矩陣。
	CapabilitySourceStatus CapabilitySource = "status"
	// CapabilitySourceManual 表示成員行上同名的分項限制旗標。
	CapabilitySourceManual CapabilitySource = "manual"
)

// capabilitySourceOrder 是結果裡來源的固定呈現順序。
var capabilitySourceOrder = []CapabilitySource{
	CapabilitySourceIdentity,
	CapabilitySourceLifecycle,
	CapabilitySourceStatus,
	CapabilitySourceManual,
}

// CapabilitySources 回傳來源類別的副本（固定順序）。
func CapabilitySources() []CapabilitySource {
	out := make([]CapabilitySource, len(capabilitySourceOrder))
	copy(out, capabilitySourceOrder)
	return out
}

// valid 回報這個來源是否落在封閉集合內。
func (s CapabilitySource) valid() bool {
	for _, allowed := range capabilitySourceOrder {
		if s == allowed {
			return true
		}
	}
	return false
}

// String 回傳穩定內部值本身。
func (s CapabilitySource) String() string { return string(s) }

// CapabilityRuleGroup 是一列狀態規則：某個內建狀態拒絕哪幾項能力。
//
// 空切片是合法現值，語意是「這個狀態不拒絕任何能力」；它必須是空切片而不是
// 消極缺席——「七個狀態都要出現」由校驗釘住，避免用缺列表達允許的第二語意。
type CapabilityRuleGroup struct {
	// Status 是七個內建狀態鍵之一。
	Status BusinessStatus
	// Denied 是這個狀態拒絕的能力鍵（固定順序、不重複）。
	Denied []CapabilityKey
}

// CapabilityRuleSet 是一個活動的完整狀態能力矩陣。
//
// Revision 為 0 表示活動從未配置過，Groups 是出廠預設；大於 0 表示資料庫裡有一份
// 完整矩陣。每次判定都現讀，不存在進程內快取或長期快照。
type CapabilityRuleSet struct {
	// Revision 是這份矩陣的版本；0＝出廠預設、尚未落地。
	Revision int64
	// Groups 依 builtinBusinessStatuses 的固定順序排列，且恰好七列。
	Groups []CapabilityRuleGroup
}

// CapabilityRuleEdit 是一筆完整的矩陣替換：七列新規則加上提交所依據的版本。
//
// 「完整替換」而不是逐格補丁：42 格是一個整體的產品規則，逐格補丁會讓
// 「這次提交到底有沒有動到某一格」需要另一份差異表才說得清；比較-and-set
// 的依據也只有一個 revision。沒有提交的格不存在。
type CapabilityRuleEdit struct {
	// ExpectedRevision 是提交所依據的版本（未配置時為 0）。
	ExpectedRevision int64
	// Groups 是新的七列規則。
	Groups []CapabilityRuleGroup
}

// 能力組合域的可判別結論。分類原則與其餘活動域同一套：
// 請求寫法錯誤、版本衝突與來源拒絕各自成句，內部故障不進這些型別。
var (
	// ErrInvalidCapabilityRules 表示矩陣不合法：列數不是七、狀態鍵重複或不在
	// 內建集合、能力鍵不在封閉集合內，或能力鍵在同一列重複（請求寫法問題）。
	ErrInvalidCapabilityRules = errors.New("capability: 狀態能力規則不合法")
	// ErrCapabilityRulesConflict 表示提交所依據的 revision 已不是資料庫現值：
	// 整個替換沒有發生，沒有半套格子被改寫。
	ErrCapabilityRulesConflict = errors.New("capability: 狀態能力規則現值已與提交時所依據的不同")
	// ErrMemberStatusRestricted 表示成員當前的業務狀態規則拒絕了活動訪問資格
	// （login 那一格）。它是活動級結論，不是帳戶停用；對外映射為 2044，
	// 與手動限制的 2043 分開。
	ErrMemberStatusRestricted = errors.New("capability: 該玩家的業務狀態規則禁止此活動的訪問資格")
	// ErrMemberIdentityInvalid 表示成員行指向的帳戶此刻不是一個有效身份
	// （停用、刪除、退休、待審批等）。它是前置拒絕；今日沒有對外碼，
	// 將來的業務通路據自己的語意決定怎麼說。
	ErrMemberIdentityInvalid = errors.New("capability: 該成員的帳戶身份此刻無效")
)

// CapabilityDecision 是一項能力在某一刻的有效結論。
//
// Allowed 為真時 Sources 是空切片；為假時 Sources 依固定順序列出所有拒絕來源。
// ManualDenied／StatusDenied／LifecycleDenied／IdentityDenied 是給管理側來源摘要的
// 逐來源布林；玩家側投影不帶這四格，只看得到來源類別。
type CapabilityDecision struct {
	// Key 是能力鍵。
	Key CapabilityKey
	// Allowed 表示沒有任何來源拒絕這項能力。
	Allowed bool
	// Sources 是拒絕來源類別（固定順序；允許時為空）。
	Sources []CapabilitySource
	// ManualDenied 表示同名手動限制為真。
	ManualDenied bool
	// StatusDenied 表示當前業務狀態的規則拒絕這項能力。
	StatusDenied bool
	// LifecycleDenied 表示活動生命週期拒絕這項業務能力。
	LifecycleDenied bool
	// IdentityDenied 表示身份資格失效（拒絕所有能力）。
	IdentityDenied bool
}

// CapabilityEvaluation 是一個成員在一個活動裡的有效能力結果。
//
// 它是派生結果，不是持久事實：手動限制存在 activity_members、狀態規則存在
// activity_capability_rules、生命週期存在 activities、身份資格來自 accounts；
// 這裡只把四者按同一套規則組合一次。每次呼叫都重新現讀，沒有快取。
type CapabilityEvaluation struct {
	// Activity 是活動現值（生命週期來源）。
	Activity Activity
	// Member 是成員行現值（業務狀態與手動限制來源）。
	Member Member
	// AccountStatus 是成員指向的帳戶此刻的狀態；帳戶讀不到時為空字串。
	AccountStatus account.Status
	// RulesRevision 是本次判定所讀到的規則版本（0＝出廠預設）。
	RulesRevision int64
	// Decisions 依 CapabilityKeys 的固定順序排列，恰好六項。
	Decisions []CapabilityDecision
	// AccessAllowed 是 login 那一項的派生結果，方便界面直接說「能不能進入」。
	// 它恆在回應、絕不在請求。
	AccessAllowed bool
}

// Decision 回傳指定能力的結論；鍵不在封閉集合或結果不完整時回 ok=false。
func (e CapabilityEvaluation) Decision(key CapabilityKey) (CapabilityDecision, bool) {
	for _, decision := range e.Decisions {
		if decision.Key == key {
			return decision, true
		}
	}
	return CapabilityDecision{}, false
}

// DefaultCapabilityRuleGroups 回傳用戶批准的分組保守出廠矩陣：
//
//	normal／offline／custom  不拒絕任何能力
//	suspended                拒絕 login 與五項業務能力
//	eliminated／dead         拒絕五項業務能力，可以查看
//	arrested                 拒絕交易、轉賬與使用物品，保留聊天
//
// 每一次都回傳新的切片，呼叫端不得靠改動它來改寫「預設」。
func DefaultCapabilityRuleGroups() []CapabilityRuleGroup {
	business := []CapabilityKey{
		RestrictionChat, RestrictionPrivateChat, RestrictionTrade,
		RestrictionTransfer, RestrictionItemUse,
	}
	return []CapabilityRuleGroup{
		{Status: BusinessStatusNormal, Denied: nil},
		{Status: BusinessStatusSuspended, Denied: []CapabilityKey{
			RestrictionLogin, RestrictionChat, RestrictionPrivateChat,
			RestrictionTrade, RestrictionTransfer, RestrictionItemUse,
		}},
		{Status: BusinessStatusEliminated, Denied: append([]CapabilityKey(nil), business...)},
		{Status: BusinessStatusDead, Denied: append([]CapabilityKey(nil), business...)},
		{Status: BusinessStatusArrested, Denied: []CapabilityKey{
			RestrictionTrade, RestrictionTransfer, RestrictionItemUse,
		}},
		{Status: BusinessStatusOffline, Denied: nil},
		{Status: BusinessStatusCustom, Denied: nil},
	}
}

// DefaultCapabilityRuleSet 回傳出廠矩陣與 revision 0。
func DefaultCapabilityRuleSet() CapabilityRuleSet {
	return CapabilityRuleSet{Revision: 0, Groups: DefaultCapabilityRuleGroups()}
}

// Denied 回答「這個業務狀態是否拒絕這項能力」。
//
// 狀態或能力不在封閉集合內時回 false，但呼叫端不得把這句當成放行依據：
// 完整矩陣由 Validate 核實，判定入口在讀到不完整矩陣時會如實報錯。
func (s CapabilityRuleSet) Denied(status BusinessStatus, key CapabilityKey) bool {
	for _, group := range s.Groups {
		if group.Status != status {
			continue
		}
		for _, denied := range group.Denied {
			if denied == key {
				return true
			}
		}
		return false
	}
	return false
}

// Validate 核實這份矩陣完整且落在封閉集合內。
//
// 它不修改矩陣；建立與讀取路徑都先過這一關，於是「少了某一列」不會被
// 降級成「那一列什麼都不拒絕」。
func (s CapabilityRuleSet) Validate() error {
	if s.Revision < 0 {
		return fmt.Errorf("%w：revision 不可為負數", ErrInvalidCapabilityRules)
	}
	groups, err := normalizeCapabilityRuleGroups(s.Groups)
	if err != nil {
		return err
	}
	if len(groups) != len(builtinBusinessStatuses) {
		return fmt.Errorf("%w：必須恰好包含 %d 個內建狀態",
			ErrInvalidCapabilityRules, len(builtinBusinessStatuses))
	}
	return nil
}

// ValidateCapabilityRuleEdit 校驗一筆矩陣替換：版本不可為負、七列完整且合法。
func ValidateCapabilityRuleEdit(edit CapabilityRuleEdit) ([]CapabilityRuleGroup, error) {
	if edit.ExpectedRevision < 0 {
		return nil, fmt.Errorf("%w：expected_revision 不可為負數", ErrInvalidCapabilityRules)
	}
	return normalizeCapabilityRuleGroups(edit.Groups)
}

// normalizeCapabilityRuleGroups 把提交的七列規則正規化：
// 狀態依內建固定順序排列、能力鍵依固定順序排列、拒絕鍵去重並拒絕未知值。
//
// 排序不是裝飾：回應與審計的順序若跟著請求順序漂移，同一份規則會有兩種
// 可讀形態；固定順序讓「這份矩陣是什麼」在每次讀取時逐字相同。
func normalizeCapabilityRuleGroups(groups []CapabilityRuleGroup) ([]CapabilityRuleGroup, error) {
	if len(groups) != len(builtinBusinessStatuses) {
		return nil, fmt.Errorf("%w：必須恰好包含 %d 個內建狀態，實際 %d",
			ErrInvalidCapabilityRules, len(builtinBusinessStatuses), len(groups))
	}
	byStatus := make(map[BusinessStatus][]CapabilityKey, len(groups))
	for _, group := range groups {
		if !group.Status.valid() {
			return nil, fmt.Errorf("%w：狀態鍵 %q 不在內建集合內",
				ErrInvalidCapabilityRules, string(group.Status))
		}
		if _, dup := byStatus[group.Status]; dup {
			return nil, fmt.Errorf("%w：狀態鍵 %q 出現兩次",
				ErrInvalidCapabilityRules, string(group.Status))
		}
		seen := make(map[CapabilityKey]struct{}, len(group.Denied))
		for _, key := range group.Denied {
			if !key.valid() {
				return nil, fmt.Errorf("%w：能力鍵 %q 不在封閉集合內",
					ErrInvalidCapabilityRules, string(key))
			}
			if _, dup := seen[key]; dup {
				return nil, fmt.Errorf("%w：狀態 %q 的能力鍵 %q 出現兩次",
					ErrInvalidCapabilityRules, string(group.Status), string(key))
			}
			seen[key] = struct{}{}
		}
		if group.Status == BusinessStatusCustom && len(group.Denied) > 0 {
			// 自訂狀態是活動內可變的定義，名稱由管理員自由填寫；讓 `custom`
			// 這一列封鎖能力等於讓「取一個聽起來很兇的名字」得到一組規則。
			// 自訂狀態今日只被顯示，`custom` 那一列必須全允許。
			return nil, fmt.Errorf(
				"%w：自訂狀態不參與能力矩陣，custom 那一列不得拒絕任何能力",
				ErrInvalidCapabilityRules)
		}
		byStatus[group.Status] = normalizeCapabilityKeys(group.Denied)
	}
	out := make([]CapabilityRuleGroup, 0, len(builtinBusinessStatuses))
	for _, status := range builtinBusinessStatuses {
		denied, ok := byStatus[status]
		if !ok {
			return nil, fmt.Errorf("%w：缺少狀態 %q", ErrInvalidCapabilityRules, string(status))
		}
		out = append(out, CapabilityRuleGroup{Status: status, Denied: denied})
	}
	return out, nil
}

// normalizeCapabilityKeys 把一組能力鍵排成固定順序（去重已在呼叫端完成）。
func normalizeCapabilityKeys(keys []CapabilityKey) []CapabilityKey {
	seen := make(map[CapabilityKey]struct{}, len(keys))
	for _, key := range keys {
		seen[key] = struct{}{}
	}
	out := make([]CapabilityKey, 0, len(seen))
	for _, key := range memberRestrictionKeys {
		if _, ok := seen[key]; ok {
			out = append(out, key)
		}
	}
	return out
}

// sameCapabilityRuleGroups 比較兩份已正規化的矩陣是否逐格相同。
//
// 呼叫端必須先各自 normalize；本函式不比對順序以外的形態。
func sameCapabilityRuleGroups(a, b []CapabilityRuleGroup) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Status != b[i].Status || len(a[i].Denied) != len(b[i].Denied) {
			return false
		}
		for j := range a[i].Denied {
			if a[i].Denied[j] != b[i].Denied[j] {
				return false
			}
		}
	}
	return true
}

// cloneCapabilityRuleGroups 回傳深拷貝，呼叫端改動不會污染來源。
func cloneCapabilityRuleGroups(groups []CapabilityRuleGroup) []CapabilityRuleGroup {
	out := make([]CapabilityRuleGroup, 0, len(groups))
	for _, group := range groups {
		denied := make([]CapabilityKey, len(group.Denied))
		copy(denied, group.Denied)
		out = append(out, CapabilityRuleGroup{Status: group.Status, Denied: denied})
	}
	return out
}

// capabilityRuleCellCount 是一份完整矩陣的格子數（七個狀態 × 六項能力）。
const capabilityRuleCellCount = 7 * 6
