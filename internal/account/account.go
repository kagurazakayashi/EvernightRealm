package account

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// Type 是帳戶類型（資料庫欄 account_type）。
//
// 封閉集合：Root 不在此列（其憑據屬 config.yaml，見套件註解）；
// NPC Operator 等活動身份也不是帳戶類型，新增取值必須走新遷移放寬 CHECK，
// 目的是讓「主體形態的變化」在版本史上留痕，而不是程式碼裡悄悄多一個字串。
type Type string

const (
	// TypeStandard 是需要一般憑據（Argon2id 雜湊）的普通帳戶。
	TypeStandard Type = "standard"
	// TypeGuest 是允許無一般密碼的訪戶帳戶；password_hash 必為 NULL、
	// must_change_password 必為 0，由資料庫 CHECK 與本套件校驗雙重凍結。
	TypeGuest Type = "guest"
)

// String 回傳資料庫/協議表示。
func (t Type) String() string { return string(t) }

// valid 回報是否為已批准的帳戶類型。
func (t Type) valid() bool {
	switch t {
	case TypeStandard, TypeGuest:
		return true
	}
	return false
}

// Status 是帳戶狀態（資料庫欄 status）。
//
// 兩個級別的刪除語意（本輪決定）：
//   - StatusDisabled：禁用，「視同沒有這個帳戶」但行與登入名鍵保留，
//     其他模組據此對其隱形，登入名不可被復用；
//   - 徹底刪除：物理 DELETE 整行（屬後續帳戶管理步驟），登入名自然釋放。
//     沒有 deleted_at 欄：行不存在就是不存在，狀態欄表達不了已消失的行。
type Status string

const (
	// StatusActive 是正常可用狀態。
	StatusActive Status = "active"
	// StatusDisabled 是禁用狀態：保留資料與登入名佔用，對外視同不存在。
	StatusDisabled Status = "disabled"
)

// String 回傳資料庫/協議表示。
func (s Status) String() string { return string(s) }

// valid 回報是否為已批准的狀態。
func (s Status) valid() bool {
	switch s {
	case StatusActive, StatusDisabled:
		return true
	}
	return false
}

// argon2idPrefix 是憑據雜湊的必填前綴（與 config 對 Root 雜湊的校驗同一形狀要求）。
const argon2idPrefix = "$argon2id$"

// Account 是一個通用帳戶的領域實體，欄位與 accounts 表一一對應（見遷移 0003）。
//
// ID 是穩定標識：一經產生不再改變（資料庫觸發器擋住 UPDATE OF id），
// 下游參照（未來的會話、活動檔案、帳本分錄）只認 ID，不認登入名。
// LoginKey 由 LoginName 經 LoginKey() 派生，兩者必須同行落庫，
// 任何其他程式碼不得自行拼鍵寫庫。
//
// 零值不可直接入庫，請經 Store.Create 取得。
type Account struct {
	// ID 為穩定帳戶標識（UUIDv7）。
	ID idgen.ID
	// LoginName 為登入名的原始寫法（保留大小寫，僅供展示）。
	LoginName string
	// LoginKey 為正規化唯一鍵（NFKC + 大小寫折疊），唯一索引建在此欄。
	LoginKey string
	// DisplayName 為顯示名稱，不承擔唯一性。
	DisplayName string
	// PasswordHash 為 Argon2id 編碼雜湊；空字串代表資料庫 NULL（僅 Guest 合法）。
	// 本欄值屬高敏感材料：不得寫入日誌、審計或任何錯誤訊息。
	PasswordHash string
	// Type 為帳戶類型。
	Type Type
	// Status 為帳戶狀態。
	Status Status
	// MustChangePassword 為「下次登入必須改密」旗標（僅對有憑據的帳戶有意義）。
	MustChangePassword bool
	// CreatedAt 為建立時刻（UTC；落庫為 Unix 毫秒）。
	CreatedAt time.Time
	// LastLoginAt 為最近一次登入時刻；零值代表從未登入（資料庫 NULL）。
	LastLoginAt time.Time
	// DisabledAt 為進入禁用狀態的時刻；Status 為 active 時必須為零值。
	DisabledAt time.Time
}

// New 從建立輸入構造領域實體並完成全部領域校驗。
//
// 標識與建立時刻不在輸入裡：它們由 Store 經 idgen 與注入時鐘產生，
// 呼叫端（未來的註冊服務）无权代填，否則「建立時間」「帳戶身份」就變成自報。
func New(in NewInput) (Account, error) {
	if !in.Type.valid() {
		return Account{}, fmt.Errorf("account: 不認識的帳戶類型 %q（可用 standard|guest）", in.Type)
	}
	if !in.Status.valid() {
		return Account{}, fmt.Errorf("account: 不認識的帳戶狀態 %q（可用 active|disabled）", in.Status)
	}
	key, err := LoginKey(in.LoginName)
	if err != nil {
		return Account{}, err
	}
	if err := validateDisplayName(in.DisplayName); err != nil {
		return Account{}, err
	}
	a := Account{
		LoginName:          trimSpaces(in.LoginName),
		LoginKey:           key,
		DisplayName:        trimSpaces(in.DisplayName),
		PasswordHash:       in.PasswordHash,
		Type:               in.Type,
		Status:             in.Status,
		MustChangePassword: in.MustChangePassword,
		DisabledAt:         in.DisabledAt,
	}
	if in.Type == TypeGuest {
		// Guest 形態凍結：無密可改，也就不可能有改密旗標。
		if a.PasswordHash != "" || a.MustChangePassword {
			return Account{}, errors.New("account: 訪客帳戶不得攜帶憑據雜湊或設 must_change_password")
		}
	} else {
		if err := validatePasswordHash(a.PasswordHash); err != nil {
			return Account{}, err
		}
	}
	// 禁用必帶時刻、啟用必不帶：與資料庫 CHECK (status='disabled')=(disabled_at IS NOT NULL) 同口徑。
	if (a.Status == StatusDisabled) != !a.DisabledAt.IsZero() {
		return Account{}, errors.New("account: status 與 disabled_at 必須同生同滅（disabled 帶時刻、active 不帶）")
	}
	return a, nil
}

// NewInput 是建立帳戶的領域輸入。
type NewInput struct {
	// LoginName 為登入名原始寫法（校驗與鍵計算由 New 完成）。
	LoginName string
	// DisplayName 為顯示名稱。
	DisplayName string
	// PasswordHash 為 Argon2id 編碼雜湊；僅 Type 為 guest 時可空。
	PasswordHash string
	// Type 為帳戶類型。
	Type Type
	// Status 為初始狀態；合法值同 Status 枚舉。
	Status Status
	// MustChangePassword 為首次登入是否必須改密。
	MustChangePassword bool
	// DisabledAt 為禁用時刻；僅 Status 為 disabled 時必填。
	DisabledAt time.Time
}

// validatePasswordHash 檢查憑據雜湊的形狀：只認 Argon2id 編碼字串，不碰內容。
//
// 不在這裡驗雜湊參數（時間成本、記憶體等屬密碼學適配層的工作），
// 只把「拿一個明顯不是憑據的字串冒充雜湊落庫」擋住。長度上界與資料庫 CHECK 同值。
func validatePasswordHash(hash string) error {
	if hash == "" {
		return errors.New("account: 標準帳戶必須提供憑據雜湊")
	}
	if !strings.HasPrefix(hash, argon2idPrefix) {
		return fmt.Errorf("account: 憑據雜湊需為 Argon2id 編碼（%s 前綴）", argon2idPrefix)
	}
	if len(hash) > maxPasswordHashLen {
		return fmt.Errorf("account: 憑據雜湊長度不可超過 %d 位元組", maxPasswordHashLen)
	}
	return nil
}

// maxPasswordHashLen 與遷移 0003 的 password_hash 長度 CHECK 同值（位元組計）。
const maxPasswordHashLen = 512

// trimSpaces 去掉首尾 Unicode 空白（與 LoginKey、顯示名校驗同一個空白定義）。
func trimSpaces(s string) string { return strings.TrimFunc(s, unicode.IsSpace) }
