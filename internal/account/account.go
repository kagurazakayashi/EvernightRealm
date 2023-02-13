package account

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
// 三個級別的刪除語意（0003 定前兩級，0007 增第三級），加上待審批通路帶來的兩級
// （0009 增 pending 與 rejected）：
//   - StatusActive：可登入；
//   - StatusDisabled：停用，「視同沒有這個帳戶」但行與登入名鍵保留，
//     其他模組據此對其隱形，登入名不可被復用，且可經停用/恢復通路重新登入；
//   - StatusDeleted：軟刪除的終態。行與登入名鍵同樣保留，差別在「沒有回去的路」：
//     它只能由 Root 的刪除用例進入，既不是可設定的登入狀態，也不受恢復登入通路承認。
//     保留行而不是刪掉，正是既有審計與其他實際存在的參照仍能指回同一個穩定身份的原因。
//   - StatusPending：待審批的申請。行、標識與登入名鍵都已經存在（統一帳戶模型：
//     申請人從提交那一刻起就是同一個人，批准不是把一筆申請「搬成」一個帳戶），
//     但它既不能登入也不屬於任何一本人可打理的目錄。
//   - StatusRejected：申請被拒絕。與 pending 一樣保留行與登入名佔用，差別只在「審核已做過決定，
//     而那個決定是拒絕」。它不是終態觸發器釘住的那種狀態——是否允許同一人重新申請、
//     或由審核者改判，屬後續審批步驟的產品決定，本枚舉不替它預先關門也不預先開門。
//
// 全部五個取值裡，「可登入」只有一個：現行的登入、主體成形、會話簽發與解析都寫成
// 「status 不是 active 就拒絕」，因此新增取值天然落在門外——安全預設來自既有形狀，
// 不是來自各處再補一個分支。
//
// 物理 DELETE（徹底清庫、登入名因此釋放）屬後續的帳戶管理步驟，不在本枚舉的通路之內。
type Status string

const (
	// StatusActive 是正常可用狀態。
	StatusActive Status = "active"
	// StatusDisabled 是停用狀態：保留資料與登入名佔用，對外視同不存在，可恢復登入。
	StatusDisabled Status = "disabled"
	// StatusDeleted 是軟刪除終態：行保留、登入名仍被佔用，但不可再登入也不可被恢復。
	StatusDeleted Status = "deleted"
	// StatusPending 是待審批：申請已落地、還沒有人做過決定，不可登入也不可經停用/恢復通路變動。
	StatusPending Status = "pending"
	// StatusRejected 是申請已被拒絕：行與登入名佔用保留，差別是審核已做過一次拒絕的決定
	// （時刻記在 reviewed_at，與批准共用那一欄）。
	StatusRejected Status = "rejected"
)

// String 回傳資料庫/協議表示。
func (s Status) String() string { return string(s) }

// valid 回報是否為已批准的狀態。
//
// 這裡回答的是「資料庫裡出現這個值合不合形態」，不是「呼叫端可不可以要求這個值」：
// StatusDeleted 與 StatusRejected 形態上合法（前者由刪除用例、後者由未來的審批用例寫入），
// 卻都不在建立時給得出來（見 creatable）；而 StatusPending 是唯一一個
// 「由某條建立通路生下來就帶著」的狀態——待審批帳戶的出生地就是自註冊的 approval 模式。
func (s Status) valid() bool {
	switch s {
	case StatusActive, StatusDisabled, StatusDeleted, StatusPending, StatusRejected:
		return true
	}
	return false
}

// settable 回報狀態是否可由「停用/恢復」通路寫入。
//
// 這個集合刻意只有兩個取值，而且這正是「待審批不能從這裡被批准」的結構保證：
// 恢復登入的語意是「他曾經可用，現在重新開放他可用」，而一個還沒獲准過的人不屬於那句話。
// 把 pending 放進 settable，等於讓目錄那條「恢復」按下去就把一個申請變成帳戶——
// 那是審批的決定，不是登入能力的開關。
//
// 刪除終態與拒絕態同樣不在其中：一個只能由 MarkDeleted 進入，
// 一個只能由未來的審批用例進入，那條 UPDATE 的形狀本身就是那句話的證據。
func (s Status) settable() bool {
	return s == StatusActive || s == StatusDisabled
}

// creatable 回報建立一筆帳戶時可作為初始狀態的取值。
//
// 與 settable 的差別只有一處、但那處正是本步的要害：待審批是一筆帳戶的出生狀態，
// 而不是任何既有人身上的一次狀態變更。「一出生就是已刪除／已拒絕的帳戶」沒有一個誠實的說法，
// 而 active 與 disabled 的出生各自已有通路在講（管理員建號、Root 開設管理員）。
func (s Status) creatable() bool {
	return s == StatusActive || s == StatusDisabled || s == StatusPending
}

// argon2idPrefix 是憑據雜湊的必填前綴（與 config 對 Root 雜湊的校驗同一形狀要求）。
const argon2idPrefix = "$argon2id$"

// 刪除終態的顯示名佔位規則（用戶批準於 R2-005）：DEL_<UTC 日期>_<原顯示名>。
//
// 前綴常數與日期格式放在一起，是為了讓「活的投影上那個名字長什麼樣」只有一個定義點：
// 界面、測試與交接引用的都是同一個形狀，而不是各處各拼一次字串。
const (
	// deletedNamePrefix 是佔位顯示名的固定前綴。
	deletedNamePrefix = "DEL_"
	// deletedNameDateFormat 是前綴裡的日期部分：UTC 四位年兩位月兩位日（與本專案
	// 「時間戳一律 UTC」的約定同口徑，不拿主機時區決定一個落庫的事實）。
	deletedNameDateFormat = "20060102"
)

// AnonymizedDisplayName 產出刪除時寫回 display_name 的佔位值。
//
// 規則是「DEL_<UTC日期>_<原名>」，整體不超過 maxDisplayNameRunes（與資料庫 CHECK 同值）：
// 前綴本身就佔 13 個碼位，而原顯示名最長可達 64，所以超長時保留原名的**前段**截斷——
// 前段是辨識度和習慣上最有用的部分（人名 firstName 在前），且截斷只依碼位邊界進行，
// 不會切出半個碼位。結果仍要通過與建立時同一個 validateDisplayName：
// 匿名化不是「把欄位清掉」，它給出的是一個合法、非空、且一眼可讀的佔位名。
//
// 這一步只做「活的投影不再顯示本人自取的名字」這一件事實：
// 只追加的審計裡那些已經寫下的舊顯示名（admin.create、profile 改名的前後值）
// 本來就不屬於可改寫的東西，歷史照舊查得到；本函式不假裝能把它們一起抹掉，
// 也不動 login_name 與其唯一鍵（保留佔用，因此登入名不可被復用）。
func AnonymizedDisplayName(deletedAt time.Time, displayName string) string {
	stamp := deletedAt.UTC().Format(deletedNameDateFormat)
	prefix := deletedNamePrefix + stamp + "_"
	original := trimSpaces(displayName)
	// 以碼位計價：先算原名可留多少，避免先拼整串再截時把前綴一起算進截斷點。
	budget := maxDisplayNameRunes - utf8.RuneCountInString(prefix)
	if budget < 0 {
		budget = 0
	}
	keep := original
	if runes := []rune(keep); len(runes) > budget {
		keep = string(runes[:budget])
	}
	return prefix + keep
}

// Account 是一個通用帳戶的領域實體，欄位與 accounts 表一一對應（見遷移 0003 與 0007）。
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
	// DeletedAt 為進入刪除終態的時刻；Status 不為 deleted 時必須為零值。
	// 它記的是「他被刪於何時」這件事本身：軟刪除保留行，沒有這一欄就等於留了一個查不出的時刻。
	DeletedAt time.Time
	// ReviewedAt 為審核做出決定的時刻（批准與拒絕都是決定）；零值代表這筆帳戶不經審批通路。
	//
	// 它與 Status 是兩件事：Status 答「他現在能不能登入」，這一欄答「他是不是走審批進來的、
	// 哪一天定的」。因此 approved 之後被停用或被刪除的帳戶仍然帶著這個時刻——
	// 一句「他不是待審批申請」對一個剛被批准的人來說是錯的，而這個欄位正是把兩者分開的依據。
	// 沒有審核人欄與審核備註欄：審核人是誰屬 root_audit 的事實，自由文本不進資料庫層。
	ReviewedAt time.Time
}

// New 從建立輸入構造領域實體並完成全部領域校驗。
//
// 標識與建立時刻不在輸入裡：它們由 Store 經 idgen 與注入時鐘產生，
// 呼叫端（未來的註冊服務）无权代填，否則「建立時間」「帳戶身份」就變成自報。
func New(in NewInput) (Account, error) {
	if !in.Type.valid() {
		return Account{}, fmt.Errorf("account: 不認識的帳戶類型 %q（可用 standard|guest）", in.Type)
	}
	if !in.Status.creatable() {
		return Account{}, fmt.Errorf("account: 不認識或不可在建立時給出的帳戶狀態 %q（可用 active|disabled|pending）", in.Status)
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
		// 訪客不經審批通路：待審批與拒絕都是「申請人出示憑據」之後才有的說法，
		// 而訪客按定義沒有憑據。與遷移 0009 的同名 CHECK 成對——域層給出可操作錯誤，
		// 資料庫擋住繞過域層的自傷。
		if a.Status == StatusPending || a.Status == StatusRejected {
			return Account{}, errors.New("account: 訪客帳戶不得以待審批或已拒絕的狀態出生")
		}
	} else {
		if err := validatePasswordHash(a.PasswordHash); err != nil {
			return Account{}, err
		}
	}
	// 禁用必帶時刻、其餘狀態必不帶：與遷移 0007 的方向規則加 0009 那條
	// 「pending／rejected 不帶 disabled_at」同口徑（這條判斷本身是雙向的，
	// 所以一個式子就同時罩住「停用卻沒時刻」與「待審批卻有停用時刻」兩件事）。
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
	// Status 為初始狀態；只接受 active|disabled|pending（刪除終態與拒絕態不能憑空建立）。
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
