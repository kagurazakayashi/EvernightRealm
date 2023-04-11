// memberrestriction.go 是玩家分項限制的領域模型：一行活動成員在這一場活動裡的
// 六枚彼此獨立的限制旗標——禁止登入、禁止聊天、禁止私聊、禁止交易、禁止轉賬、
// 禁止使用物品。
//
// 這一族旗標的形狀由用戶批准的三句話決定，別處不得各講一套：
//   - 六項互相獨立，各存各欄、各改各的：取消聊天限制不會順手取消私聊或登入限制。
//     倉庫裡沒有一枚「總 frozen」布爾，也沒有一張「缺席即不限制」的限制表——
//     前者抹掉六項之間的區別，後者引入「一行缺席算什麼」的第二語意。
//   - 出廠值恆為不限制（遷移 0019 的 DEFAULT 0）：相容遷移不讓任何人升級後
//     突然失去訪問資格，也不需要回填。
//   - restrict_login 是「該活動的訪問資格」，不是全域帳戶停用：它不碰 accounts、
//     不停全域會話、不動其他活動；判定落在服務層（memberrestrictions.go），
//     資料庫只保存事實。
//
// 其餘五項對應的業務（聊天、私聊、交易、轉賬、使用物品）今日都還沒有實現。
// 本步交付的是統一的能力判定介面與領域測試：判定只回答「此刻這一行被沒被限制」，
// 不伪造任何「業務已接入」的證據，也不對外發機器錯誤碼——沒有端點就沒有人收得到碼。
package activity

import (
	"errors"
	"fmt"
)

// MemberRestrictionKey 是一枚分項限制的穩定內部鍵（永不改名、永不復用）。
//
// 內部鍵不是顯示值：四語言文案換字、前端標籤改口都不動這裡的取值集合。
type MemberRestrictionKey string

const (
	// RestrictionLogin 禁止取得或繼續使用該活動的訪問資格（活動級，用戶批准）。
	RestrictionLogin MemberRestrictionKey = "login"
	// RestrictionChat 禁止聊天；聊天業務未實現，今日只保存與顯示。
	RestrictionChat MemberRestrictionKey = "chat"
	// RestrictionPrivateChat 禁止私聊；與公開聊天分欄，業務未實現。
	RestrictionPrivateChat MemberRestrictionKey = "private_chat"
	// RestrictionTrade 禁止交易；交易業務未實現，今日只保存與顯示。
	RestrictionTrade MemberRestrictionKey = "trade"
	// RestrictionTransfer 禁止轉賬；與交易分欄，業務未實現。
	RestrictionTransfer MemberRestrictionKey = "transfer"
	// RestrictionItemUse 禁止使用物品；業務未實現，今日只保存與顯示。
	RestrictionItemUse MemberRestrictionKey = "item_use"
)

// memberRestrictionKeys 是六枚限制鍵的固定呈現順序，同時是「合法限制鍵」的唯一清單：
// 校驗、倉儲欄位清單與介面清單都從它派生，避免多處各列一份而漂移。
var memberRestrictionKeys = []MemberRestrictionKey{
	RestrictionLogin,
	RestrictionChat,
	RestrictionPrivateChat,
	RestrictionTrade,
	RestrictionTransfer,
	RestrictionItemUse,
}

// MemberRestrictionKeys 回傳一份限制鍵的副本（固定順序）。
//
// 回傳副本而不是底層切片：呼叫端不得靠改動它來新增一枚「合法」限制。
func MemberRestrictionKeys() []MemberRestrictionKey {
	out := make([]MemberRestrictionKey, len(memberRestrictionKeys))
	copy(out, memberRestrictionKeys)
	return out
}

// valid 回報這個鍵是否為六枚限制鍵之一。
func (k MemberRestrictionKey) valid() bool {
	for _, allowed := range memberRestrictionKeys {
		if k == allowed {
			return true
		}
	}
	return false
}

// columnName 回傳這枚限制鍵在 activity_members 上的欄位名。
//
// 它是倉儲拼動態 UPDATE 時唯一允許出現的欄位名來源：取值由上面封閉集合派生，
// 呼叫端塞進來的任何字串都到不了這裡——注入面在型別層就不存在。
func (k MemberRestrictionKey) columnName() string {
	return "restrict_" + string(k)
}

// String 回傳穩定內部值本身（不是顯示名稱）。
func (k MemberRestrictionKey) String() string { return string(k) }

// RestrictionValue 讀出這一行在該枚限制上的現值；鍵不在封閉集合內時回 false 與 ok=false。
//
// 六個 case 就是六欄事實的逐欄對應：沒有 default、也沒有「未知鍵當成不限制」的降級，
// 否則一枚寫壞的鍵會被讀成一個合法結論。
func (m Member) RestrictionValue(key MemberRestrictionKey) (value bool, ok bool) {
	switch key {
	case RestrictionLogin:
		return m.RestrictLogin, true
	case RestrictionChat:
		return m.RestrictChat, true
	case RestrictionPrivateChat:
		return m.RestrictPrivateChat, true
	case RestrictionTrade:
		return m.RestrictTrade, true
	case RestrictionTransfer:
		return m.RestrictTransfer, true
	case RestrictionItemUse:
		return m.RestrictItemUse, true
	}
	return false, false
}

// MemberRestrictionChange 是一枚限制的本次改動：新值加上提交所依據的現值。
//
// 依據值不是裝飾：並發下另一個人已經翻過同一欄時，這次提交整個不發生（口徑同
// 昵称與狀態的比較-and-set）。「只改明確選擇的項」在這一格上的表達是——
// 沒出現在 Changes 裡的鍵，倉儲的 UPDATE 語句裡連一個格子都不會有。
type MemberRestrictionChange struct {
	// Key 是被改動的限制鍵，必須落在封閉集合內。
	Key MemberRestrictionKey
	// Value 是本次要寫入的新值。
	Value bool
	// Expected 是提交所依據的現值。
	Expected bool
}

// MemberRestrictionEdit 是一筆分項限制編輯：一組逐鍵的新值與依據值。
type MemberRestrictionEdit struct {
	// Changes 依提交順序排列；同一枚鍵出現兩次屬請求寫法錯誤。
	Changes []MemberRestrictionChange
}

// 分項限制域的可判別結論。分類原則與狀態／標籤同一套：
// 請求寫法錯誤與業務衝突各自成句，內部故障不進這些型別。
var (
	// ErrInvalidRestrictionUpdate 表示編輯的鍵不在封閉集合內、鍵重複、或一欄新值都沒有
	// （請求寫法問題，對外點名欄位；不是業務衝突）。
	ErrInvalidRestrictionUpdate = errors.New("memberrestriction: 分項限制編輯不合法")
	// ErrMemberAccessRestricted 表示這一行成員的 restrict_login 為真：
	// 他被禁止取得或繼續使用「這一場活動」的訪問資格。
	//
	// 它是活動級結論，不是帳戶級：持有這句話的人在其他活動、全域會話與普通登入上
	// 得不到任何差別——那句話只在 accounts.disabled 的語意裡才成立（見 internal/account）。
	ErrMemberAccessRestricted = errors.New("memberrestriction: 該玩家在此活動的訪問資格已被限制")
	// ErrMemberCapabilityRestricted 表示這一行成員在該枚業務限制上為真。
	//
	// 它今日沒有任何 HTTP 呼叫端：聊天、私聊、交易、轉賬與使用物品的業務都還沒有實現，
	// 這句結論只活在服務層判定與領域測試裡。沒有端點就不發機器碼（既有口徑）。
	ErrMemberCapabilityRestricted = errors.New("memberrestriction: 該玩家在此活動被禁止該項能力")
)

// MemberCapabilityRestrictedError 把「被限制的是哪一枚能力」帶在型別上。
//
// 將來的業務通路據 Key 各發各的碼（一枚能力一枚語意），而不是共用一句「你做不了這件事」
// 卻答不出被擋的是哪一項。Sources 是並列的拒絕來源（identity／lifecycle／status／manual），
// 呼叫端可以只問「有沒有被擋」，也可以按來源決定句子；errors.Is 對
// ErrMemberCapabilityRestricted 仍然成立。
type MemberCapabilityRestrictedError struct {
	Key MemberRestrictionKey
	// Sources 是這一刻拒絕該能力的全部來源（固定順序；至少一個）。
	Sources []CapabilitySource
}

// Error 回傳領域句；句內不帶任何帳戶或成員標識（審計與日誌另有結構化欄位）。
func (e *MemberCapabilityRestrictedError) Error() string {
	return fmt.Sprintf("memberrestriction: 該玩家在此活動被禁止能力 %q", string(e.Key))
}

// Unwrap 讓 errors.Is(err, ErrMemberCapabilityRestricted) 成立。
func (e *MemberCapabilityRestrictedError) Unwrap() error {
	return ErrMemberCapabilityRestricted
}

// validateRestrictionEdit 校驗一筆分項限制編輯：至少一項、鍵落在封閉集合內且不重複。
//
// 「新值與現值相同」不在這裡被拒——那是用例層冪等判定（不寫入、不追加審計）的輸入，
// 請求寫法與業務結論分開，口徑同自訂狀態編輯的校驗位階。
func validateRestrictionEdit(edit MemberRestrictionEdit) ([]MemberRestrictionChange, error) {
	if len(edit.Changes) == 0 {
		return nil, fmt.Errorf("%w：至少需要一項限制的新值與依據值", ErrInvalidRestrictionUpdate)
	}
	seen := make(map[MemberRestrictionKey]struct{}, len(edit.Changes))
	out := make([]MemberRestrictionChange, 0, len(edit.Changes))
	for _, change := range edit.Changes {
		if !change.Key.valid() {
			return nil, fmt.Errorf("%w：限制鍵 %q 不在封閉集合內",
				ErrInvalidRestrictionUpdate, string(change.Key))
		}
		if _, dup := seen[change.Key]; dup {
			return nil, fmt.Errorf("%w：限制鍵 %q 出現兩次",
				ErrInvalidRestrictionUpdate, string(change.Key))
		}
		seen[change.Key] = struct{}{}
		out = append(out, change)
	}
	return out, nil
}
