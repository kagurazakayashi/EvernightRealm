// Package account 提供通用帳戶的領域模型、登入名正規化與持久化倉儲。
//
// 本套件屬領域層（根 AGENTS.md §6）：只依賴 database.Querier、idgen、timeutil 與
// golang.org/x/text 的正規化變換，不依賴 HTTP、會話或任何 Flutter 物件。
// 註冊、登入端點與帳戶管理頁面屬後續步驟，本套件只保證
// 「放進資料庫的帳戶形態正確、登入名唯一性由鍵與資料庫約束共同凍結」。
//
// 主體邊界（本輪決定）：
//   - Root 不在本模型：其憑據的權威來源是資料目錄 config.yaml 的 Argon2id 雜湊
//     （見 internal/config），不搬入 accounts 表、不產生兩套可獨立修改的憑據；
//     日後統一可信主體時經新遷移擴充 account_type。
//   - 活動暱稱屬未來的 Activity Profile，不在此承擔全局唯一性；
//     NPC／NPC Operator 是活動身份，不是可自報的全局帳戶類型。
//   - Guest 允許無一般密碼，其形態由資料庫 CHECK 與本套件校驗雙重凍結，
//     Guest 註冊流程不屬本步範圍。
package account

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// 登入名校驗邊界（字元數以 Unicode 碼位計，與 SQLite length() 同口徑）。
const (
	// maxLoginRunes 是登入名的碼位上限。
	maxLoginRunes = 64
	// maxLoginKeyRunes 是正規化鍵的碼位上限：NFKC 與大小寫折疊都可能使字串變長
	//（如 ﷽ 展開、ß→ss），給一個寬於原值的上界，同时把病態展開擋在校驗層。
	maxLoginKeyRunes = 200
	// maxDisplayNameRunes 是顯示名的碼位上限。
	maxDisplayNameRunes = 64
)

// 校驗錯誤；呼叫端以 errors.Is 判定，訊息可原樣呈現給操作者（不含任何秘密）。
var (
	// ErrInvalidLogin 表示登入名不符合領域規則（空、過長、含空白／控制／格式字元）。
	ErrInvalidLogin = errors.New("account: 登入名不合法")
	// ErrInvalidDisplayName 表示顯示名不符合領域規則。
	ErrInvalidDisplayName = errors.New("account: 顯示名不合法")
)

// LoginKey 計算登入名的正規化唯一鍵：NFKC → 全量大小寫折疊 → NFKC。
//
// 這是全服務唯一的登入名比對依據：域層查重、INSERT 前的鍵計算、資料庫 UNIQUE 索引
// 三者共用本函式，不存在「第二套規則」。為什麼是這個組合：
//   - NFKC 把全角／Ａ、ﬁ/ffi 這類「視覺相同、碼位不同」的等價形收攏，
//     否則註冊了「Ａ」的人能再註冊「A」冒充同一個登入名；
//   - 全量折疊（fold）而非單純 lowercase：ß→ss 這類一對多映射用 ToLower 收不住，
//     且 fold 結果再經一次 NFKC，確保折疊產物本身回到正規形式、鍵寫法唯一穩定。
//
// 拒收規則（先於正規化套用在去首尾空白後的原始值上）：
//   - 不得為空、碼位數不得超過 maxLoginRunes；
//   - 內部不得含任何 Unicode 空白（NBSP 經 NFKC 會變成普通空格，留著它等於
//     讓兩個肉眼不可分的登入名共存於展示層）、控制字元（Cc）或格式字元
//     （Cf，含零寬連接符與雙向覆寫符——同形字攻擊的主原料）。
//
// 正規化之後的鍵再以同口徑复检一次：防的是「折疊／展開恰好引入违禁字元」
// 這種輸入端看不見的退化情形（如 U+2E80 區外的兼容展開）。
func LoginKey(login string) (string, error) {
	trimmed := strings.TrimFunc(login, unicode.IsSpace)
	if err := validateLoginShape("登入名", trimmed, maxLoginRunes); err != nil {
		return "", err
	}
	folded, _, err := transform.String(cases.Fold(), norm.NFKC.String(trimmed))
	if err != nil {
		return "", fmt.Errorf("%w：正規化失敗: %v", ErrInvalidLogin, err)
	}
	key := norm.NFKC.String(folded)
	if err := validateLoginShape("登入名（正規化後）", key, maxLoginKeyRunes); err != nil {
		return "", err
	}
	return key, nil
}

// validateLoginShape 檢查去空白後字串的形狀：非空、長度、字元類別。
func validateLoginShape(field, value string, maxRunes int) error {
	if value == "" {
		return fmt.Errorf("%w：%s不可為空", ErrInvalidLogin, field)
	}
	count := 0
	for _, r := range value {
		count++
		if count > maxRunes {
			return fmt.Errorf("%w：%s長度不可超過 %d 個字元", ErrInvalidLogin, field, maxRunes)
		}
		if err := checkLoginRune(r); err != nil {
			return fmt.Errorf("%w：%s%v（U+%04X）", ErrInvalidLogin, field, err, r)
		}
	}
	return nil
}

// checkLoginRune 判定單個字元是否可入登入名。
func checkLoginRune(r rune) error {
	switch {
	case unicode.IsSpace(r):
		return errors.New("不得含空白字元")
	case unicode.IsControl(r):
		return errors.New("不得含控制字元")
	case unicode.Is(unicode.Cf, r):
		return errors.New("不得含格式字元（零寬字元、雙向覆寫等）")
	}
	return nil
}

// validateDisplayName 檢查顯示名：非空、不超長、不含控制／格式字元。
//
// 與登入名不同，顯示名允許內部空白（「張三 四」是正常名字），
// 也保留原始大小寫——它只用于展示，不參與任何唯一性比對。
func validateDisplayName(name string) error {
	trimmed := strings.TrimFunc(name, unicode.IsSpace)
	if trimmed == "" {
		return fmt.Errorf("%w：不可為空", ErrInvalidDisplayName)
	}
	count := 0
	for _, r := range trimmed {
		count++
		if count > maxDisplayNameRunes {
			return fmt.Errorf("%w：長度不可超過 %d 個字元", ErrInvalidDisplayName, maxDisplayNameRunes)
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%w：不得含控制或格式字元（U+%04X）", ErrInvalidDisplayName, r)
		}
	}
	return nil
}
