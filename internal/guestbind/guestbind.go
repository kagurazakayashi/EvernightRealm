// Package guestbind 是「訪戶綁定」的持久介質：簽發後短效、限定這一對（來源, 目標）、
// 只准核銷一次的操作憑證，以及綁定關係的不可變留痕。
//
// 本套件只回答「這一枚憑證與這一行留痕長什麼樣、能不能被用掉」，不回答「此刻准不准綁定」：
// 後者是應用服務層的判定（見 internal/stdacct 的綁定用例），它帶著授權、目錄範圍、
// 引用登記表與同意合同。把兩件事分開不是客氣：憑證表若自己判定許可，
// 就会出现「表上的規則與預檢的規則各說一套」那種最難查的缺陷。
//
// 三條寫在形狀上的規定（與 internal/invitecode、internal/session 同一取向，理由也同源）：
//   - 驗證材料而非明文。INSERT 只帶 SHA-256，表裡根本沒有明文那一欄；讀回來的實體也不含明文
//     （明文只在簽發那一次由 newTicket 直接交給服務層的回應，從不入庫、從不經本倉儲的讀法返回）。
//   - 可用性不是欄位。本倉儲沒有任何一條 UPDATE 會去寫 status／expired 之類可被翻動的「狀態」列，
//     因為這張表沒有那一列——一枚憑證能不能用，永遠由 (到期時刻、核銷時刻) 加註入時鐘在讀用時派生。
//   - 併發正確性來自資料庫條件。核銷用帶 WHERE 的單向 UPDATE（釘在「此刻尚未被核銷且尚未到期」），
//     拿 RowsAffected 分辨贏家與落敗者，而不是先查再用；「同一個訪戶只能被綁走一次」
//     則交給留痕表 source 欄的 UNIQUE（見遷移 0011）。正確性不來自讀與寫之間那個窗口。
//
// 依賴方向：guestbind → database／idgen／timeutil。它不認識帳戶、不認識授予、
// 不做任何授權判定，因此也不會被未來模組反向拖成第二套許可規則。
package guestbind

import (
	"errors"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// ConsentModeTargetSelfInitiated 是唯一存在的同意形態：綁定由目標帳戶持有人
// 以自己的已認證會話發起。它在遷移 0011 裡是 CHECK 的封閉集合（資料庫層沒有
// 「管理員代簽」這一格），在這裡是同一個常數——兩處同一字面值，由測試釘住。
const ConsentModeTargetSelfInitiated = "target_self_initiated"

// 倉儲對外可判別的結論錯誤：內部故障一律不進這些型別。
var (
	// ErrNotFound 表示按標識或按驗證材料找不到憑證／留痕。
	//
	// 它與資料庫故障分開：呼叫端拿憑證明文來核銷，查不到多半是幽靈值、已過期或被別人用掉，
	// 對外的處置都是同一句不泄露細節的拒絕；查不了才是要報錯的缺陷。
	ErrNotFound = errors.New("guestbind: 找不到對應的綁定憑證")
	// ErrInvalidDigest 表示計劃摘要的形狀不合（必須是定寬小寫十六進位）。
	//
	// 拒絕任何形狀不對的摘要入庫：摘要的內容由服務層按「哪些事實決定這一次綁定可行」算出，
	// 形狀閘在這裡只保證它確實是一枚摘要，而不是把判定逻辑搬到倉儲。
	ErrInvalidDigest = errors.New("guestbind: 計劃摘要形狀不合法")
	// ErrInvalidTicketShape 表示交來的憑證明文不具備憑證的形狀（長度、字母表、非正規寫法）。
	ErrInvalidTicketShape = errors.New("guestbind: 綁定憑證形狀不合法")
	// ErrNilIdentifier 表示呼叫端少了某個必需的標識（來源／目標／簽發人／憑證）。
	//
	// 它是程式缺陷而不是業務結論：綁定的三個主體缺一個都不該落庫，
	// 而「查無此帳戶」那類可解釋的失敗屬服務層的範圍判定，不属這裡。
	ErrNilIdentifier = errors.New("guestbind: 綁定動作缺少必要標識")
	// ErrInvalidExpiresAt 表示到期時刻不晚於簽發時刻（一枚「出生即已過期」的憑證）。
	ErrInvalidExpiresAt = errors.New("guestbind: 憑證到期時刻必須晚於簽發時刻")
	// ErrInvalidBoundAt 表示留痕的綁定時刻是零值。
	//
	// 那一時刻必须取自剛被退休的帳戶行（見 Store.AppendBinding），零值代表呼叫端
	// 在「退休尚未落地」的狀態下來寫留痕——那是一句還沒有發生的事。
	ErrInvalidBoundAt = errors.New("guestbind: 綁定時刻必須是已落地的事實")
)

// Ticket 是一枚已簽發的綁定憑證（對應遷移 0011 的 guest_bind_tickets 一行）。
//
// 沒有、也不可能有的一欄是憑證明文：表裡存的是它的 SHA-256，讀回的實體因此拿不回明文，
// 任何回應都只能來自簽發那一次內存裡的原值。
type Ticket struct {
	// ID 為憑證的穩定標識（留痕行以它追溯「哪一次准了這一對」）。
	ID idgen.ID
	// SourceAccountID 為簽發時凍結的來源訪戶標識。
	SourceAccountID idgen.ID
	// TargetAccountID 為簽發時凍結的目標帳戶標識：只有這一個人的會話能用掉它。
	TargetAccountID idgen.ID
	// IssuedByAccountID 為簽發這枚憑證的伺服器級管理員標識。
	IssuedByAccountID idgen.ID
	// PlanDigest 為簽發時依據的事實摘要（核銷時重算比對，對上不執行）。
	PlanDigest string
	// SchemaVersion 為簽發時讀到的資料庫 schema 版本（引用登記表的覆盖面隨版本變）。
	SchemaVersion int
	// CreatedAt 為簽發時刻（UTC；落庫為 Unix 毫秒）。
	CreatedAt time.Time
	// ExpiresAt 為到期時刻：憑證必然帶著它，沒有「永不」這一格。
	ExpiresAt time.Time
	// ConsumedAt 為核銷時刻；零值代表尚未被用掉。
	ConsumedAt time.Time
}

// Pending 回報這枚憑證此刻是不是一枚「还能被用掉」的憑證。
//
// 兩個條件都算在注入時鐘交給呼叫端的此刻上：服務層先讀憑證、再判定、最後核銷，
// 這一句只用於「讀到就該拒絕」的早退（省掉一次注定命中零行的寫入）。
// 真正的併發邊界是 Store.Consume 那條 WHERE——這裡回 true 之後仍可能被別人搶先用掉。
func (t Ticket) Pending(now time.Time) bool {
	return t.ConsumedAt.IsZero() && now.Before(t.ExpiresAt)
}

// Binding 是一行綁定留痕（對應遷移 0011 的 guest_account_bindings 一行）。
//
// 它是「歷史解釋」本身的物理形體：X 曾經是訪戶、後來以 X 這個標識被併入 Y。
// 只追加——沒有任何通路改寫它，也沒有任何通路把它改成「從來都是 Y」。
type Binding struct {
	// ID 為留痕行的穩定標識。
	ID idgen.ID
	// SourceAccountID 為被綁走的訪戶標識（該行此後進入退休終態，標識存续）。
	SourceAccountID idgen.ID
	// TargetAccountID 為承接這一段身份的正規帳戶標識（存续身份）。
	TargetAccountID idgen.ID
	// TicketID 為換得這一行留痕的憑證標識。
	TicketID idgen.ID
	// BoundAt 為綁定時刻，與來源行 retired_at 同值（同一筆交易內讀回的那個事實）。
	BoundAt time.Time
	// RevokedSessions 為這次讓幾枚源會話失效（那一次動作的摘要，隨行不可變）。
	RevokedSessions int
	// ConsentMode 為同意形態，恆為 ConsentModeTargetSelfInitiated。
	ConsentMode string
}
