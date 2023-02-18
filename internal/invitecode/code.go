// code.go 是邀請碼的領域實體、狀態派生與標籤校驗。
//
// 本檔不碰數據庫、不認 HTTP：它只回答「一枚邀請碼長什麼樣、此刻算不算數」。
// 時刻與標識不在這裡產生（那屬倉儲與注入時鐘），呼叫端無權代填。
package invitecode

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// Status 是一枚邀請碼在讀用時派生出的狀態。
//
// 它不是數據庫欄位（本表沒有 status 列，見套件頭注）：它是「額度上限、已用次數、有效期、
// 撤銷時刻」這四個事實加一枚注入時鐘算出來的投影。派生有固定的優先序，越靠前的越硬：
//   - StatusRevoked：撤銷時刻已落下。撤銷是人做的、單向的終態決定，一旦成立就壓過其餘一切
//     （哪怕它同時早已用完或早已過期），因為它講的是「人已明確叫停」。
//   - StatusExpired：給了有效期且此刻已到期。它排在額度之前，因為「時間到了」與額度還剩多少無關，
//     是一個更該先讓人看見的事實。
//   - StatusExhausted：未過期，但已用次數打滿額度上限。
//   - StatusActive：以上都不成立——此刻還是一次都沒用完、沒過期、沒被撤銷的有效碼。
//
// 這四個取值是封閉集合，新增取值只改這裡與 deriveStatus 一處，接口形狀不變。
type Status string

const (
	// StatusActive 是此刻可被核銷的有效碼。
	StatusActive Status = "active"
	// StatusExhausted 是額度已用滿（用一次算一次，1 即單次碼，天然落在這裡）。
	StatusExhausted Status = "exhausted"
	// StatusExpired 是過了有效期、此刻不再可被核銷。
	StatusExpired Status = "expired"
	// StatusRevoked 是被撤銷——單向終態，壓過以上所有派生。
	StatusRevoked Status = "revoked"
)

// String 回傳協議表示。
func (s Status) String() string { return string(s) }

// InviteCode 是一枚服務器級註冊邀請碼的領域實體，欄位與 registration_invite_codes 表一一對應。
//
// ID 是穩定標識（簽發後不變，數據庫觸發器釘住）。CodeHash 是明文碼的 SHA-256（小寫十六進位、
// 定寬 64）——庫裡只存這個、不存明文碼本身；它是驗證材料，不是可直接複用的秘密。
// ExpiresAt／RevokedAt 的零值各有一個明確語意：分別為「永不過期」與「尚未被撤銷」，
// 呼叫端不得拿 epoch 時刻或另一個非零值冒充這兩種事實之一。
type InviteCode struct {
	// ID 為穩定碼標識（UUIDv7）。
	ID idgen.ID
	// CodeHash 為明文碼的 SHA-256 十六進位表示；高敏感：不得寫入日誌、審計或任何錯誤訊息。
	CodeHash string
	// Label 為操作員給的標籤（名冊上唯一可讀的人話，不承載任何秘密）。
	Label string
	// MaxUses 為可被成功核銷的次數上限（恆 >= 1；1 即單次碼）。
	MaxUses int64
	// UsedCount 為已被核銷的次數（恆 <= MaxUses，由數據庫 CHECK 與單調觸發器雙重凍結）。
	UsedCount int64
	// CreatedAt 為簽發時刻（UTC；落庫為 Unix 毫秒）。
	CreatedAt time.Time
	// ExpiresAt 為到期時刻；零值代表永不過期（用戶批准：0=永不）。非零時必須晚於 CreatedAt。
	ExpiresAt time.Time
	// RevokedAt 為撤銷時刻；零值代表尚未被撤銷。撤銷是單向終態。
	RevokedAt time.Time
}

// remaining 回傳剩餘額度（MaxUses - UsedCount），下限鉗在 0。
//
// 數據庫 CHECK 已保證 UsedCount <= MaxUses，這裡鉗 0 只是讓「剩餘」在任何構造下都是一個
// 說得通的數，而不是把可能為負的減法直接交給界面去猜。
func (c InviteCode) remaining() int64 {
	if r := c.MaxUses - c.UsedCount; r > 0 {
		return r
	}
	return 0
}

// deriveStatus 用給定的「現在」把四個事實算成一個狀態。
//
// 優先序是刻意的（見 Status 頭注），撤銷最硬、過期次之、用滿再次。時鐘由呼叫端傳入而非直接讀牆鍾：
// 同一行在兩個不同時刻讀出不同狀態是正確行為（過期本就取決於「現在」），因此可測性靠注入時鐘、
// 不靠把「現在」藏進函數體。expires_at = 0 那一側的比較先於到期判斷：0 是「沒有到期這回事」，
// 絕不能被當成「epoch 早已過期」而誤判成 expired。
func (c InviteCode) deriveStatus(now time.Time) Status {
	switch {
	case !c.RevokedAt.IsZero():
		return StatusRevoked
	case !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt):
		return StatusExpired
	case c.UsedCount >= c.MaxUses:
		return StatusExhausted
	default:
		return StatusActive
	}
}

// Status 以注入時鐘讀回一枚碼此刻的狀態（倉儲把行讀成實體後，服務層用它派生名冊那一格）。
func (c InviteCode) Status(now time.Time) Status { return c.deriveStatus(now) }

// consumable 回報此刻這一枚還能不能被核銷——它是撤銷與有效期之外，核銷那條 UPDATE 的守衛語意
// 在領域層的同一種說法：active 與「還沒過期」不是同一句話，只有「此刻還能佔用一次額度」才是。
//
// 用滿（exhausted）、過期（expired）、撤銷（revoked）三種都不是 true，只有 active 是 true。
func (c InviteCode) consumable(now time.Time) bool {
	return c.deriveStatus(now) == StatusActive
}

// 標籤的形狀邊界：與 accounts 兩欄同值（64 碼位），讓「名冊上那一行人話有多長」只有一個定義點。
const maxLabelRunes = 64

// MaxUsesLimit 是一枚碼額度上限的上界，與遷移 0010 的 CHECK（max_uses BETWEEN 1 AND 1000000）同值。
//
// 它導出給傳輸層與測試作為「一份誠實的上界」，避免界面把 1 到 1e6 之外的數字送來再被庫拒——
// 那會回成一句看不出所以然的 500。上限存在是「一行的兩個整數不綁定回應體大小」的既有取向。
const MaxUsesLimit = 1000000

// validateMaxUses 複核額度上限落在 1..MaxUsesLimit。
//
// 0 或負數不是一種額度，「一次都不能用的碼」也不叫單次碼（那是一枚根本核銷不掉的垃圾行）；
// 超過上界同樣拒絕——它落不進庫，與其讓數據庫報約束錯，不如在進交易前點名 max_uses。
func validateMaxUses(n int64) error {
	if n < 1 || n > MaxUsesLimit {
		return fmt.Errorf("%w：%d（必須在 1..%d）", ErrInvalidMaxUses, n, MaxUsesLimit)
	}
	return nil
}

// validateLabel 檢查標籤：去首尾空白後非空、不超長、不含控制或格式字元。
//
// 允許內部空白（「秋季內測」這種帶空格的標籤是正常寫法），但它只用於展示、不參與任何唯一性比對，
// 也不承載秘密——列表那一格讀的就是這個值。返回去空白後的規範寫法供落庫。
func validateLabel(raw string) (string, error) {
	trimmed := strings.TrimFunc(raw, unicode.IsSpace)
	if trimmed == "" {
		return "", fmt.Errorf("%w：不可為空", ErrInvalidLabel)
	}
	count := 0
	for _, r := range trimmed {
		count++
		if count > maxLabelRunes {
			return "", fmt.Errorf("%w：長度不可超過 %d 個字符", ErrInvalidLabel, maxLabelRunes)
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", fmt.Errorf("%w：不得含控制或格式字元（U+%04X）", ErrInvalidLabel, r)
		}
	}
	return trimmed, nil
}
