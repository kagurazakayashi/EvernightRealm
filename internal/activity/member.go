// member.go 是活動成員與唯一玩家檔案的領域模型：一行成員就是「那個帳戶在那場活動裡的
// 那一份身份」——它有自己在活動內的穩定標識、活動內暱稱，以及此刻的陣營歸屬。
//
// 本檔只管「什麼是一行合法的成員資料」，不管落庫（memberstore.go）也不管用例編排
// （members.go）。四條寫在模型上的規定都來自本輪用戶批准，介面與日後通路都不得另講一套：
//   - 單一權威關係：一個帳戶在一場活動裡只有一份檔案（落庫由 UNIQUE
//     (activity_id, account_id) 釘住），而他此刻屬於哪個陣營只有 faction_id 這一格。
//     不存在另一張「成員→陣營」的映射表，因此也不會出現兩處各說一套的歸屬；
//     日后的分配通路改的就是這一格，而不是另寫一份需要同步的事實。
//   - 標識是身份，暱稱不是。id 是玩家在活動內的穩定標識（日後的資產、聊天指向的是它），
//     account_id 是「他是哪一個人」，activity_id 是「他屬於哪場活動」，三者都由資料庫
//     觸發器釘成不可就地改寫（見遷移 0014）。暱稱可以重複、可以改，不承擔唯一性：
//     同活動兩個玩家重名完全合法，介面靠標識與登入名分辨他們。
//   - 允許無陣營：faction_id 為零值時語意是「尚未分組」，不拿一個讀不回任何陣營的標識
//     或空字串冒充。理由有兩層——活動可以先加人後設陣營；而陣營停用的已批准語意是
//     「禁止新分配＋保留既有歸屬」，若歸屬必填，全停用時會出現既進不去也留不下的硬缺口。
//     本步沒有分配端點，因此今日所有行的這一格都是無陣營；「遷出到無陣營」同屬那一步的合同。
//   - 訪戶也可以是成員：參加不是權限。持有 server_admin 的帳戶也可以是成員，
//     因為成員身份從不賦予任何伺服器級權限，兩套判定各問各的來源。
//   - 目錄覆蓋是這一行的第五欄事實（遷移 0016）：directory_visibility 只回答
//     「其他普通玩家讀不讀得到這一行的投影」，而且只能往收緊的方向覆蓋活動那一側的
//     模式；它不是身份、不是陣營歸屬，也永遠不構成一格能放寬活動規則的開關
//     （判定只在 dirmode.go 那一句純函式裡，別處不重寫）。
//
// 一行成員不承載帳戶的事實：暱稱是活動內的展示名，登入名、口令形態、可用性一律屬
// internal/account；名冊讀回時額外蓋上的顯示名與帳戶狀態只是「此刻那一個人的投影」，
// 不是本表的一欄（見 members.go 的讀法）。
package activity

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// 成員域的可判別結論。分類原則與活動／陣營側同一套：正常會發生的業務衝突、
// 請求寫法錯誤各自成句，內部故障不進這些型別。
var (
	// ErrMemberNotFound 表示這個成員不在呼叫者的可見範圍內。它同時收斂四件事，
	// 而且刻意不分成四句：
	//   - 那個成員標識從未存在；
	//   - 它存在但不屬於這個活動（跨活動拼接——被拒的人不該多得到「那個人在另一場活動裡」
	//     這條信號，口徑同 ErrFactionNotFound）；
	//   - 那個活動本身就不歸呼叫者管（由 requireActivityScope 收斂到同一句話）；
	//   - 要建立成員的目標帳戶此刻不是一個能參加的人（待審批、已被拒絕、已被軟刪除、
	//     已經綁定退休，或根本沒有這個帳戶）。最後這一項走同一句話是用戶批准的口徑
	//     （同帳戶目錄對終態之外的範圍收斂）：能敲這條路徑的人是活動管理人，
	//     而不是帳戶目錄的操作者，為他多開一句「他被刪了」等於新增一枚可列舉的信號。
	ErrMemberNotFound = errors.New("member: 該成員或目標帳戶不在可見範圍內")
	// ErrMemberAccountTaken 表示這個帳戶在該活動裡已經有一份檔案了：本次建立整個沒有發生。
	//
	// 它是「一個帳戶在一場活動裡只有一份 Profile」那句結構保證的可判讀外殼——正確性來自
	// UNIQUE (activity_id, account_id)，先查只是為了給操作者一句人話而不是原始約束錯誤。
	// 重複提交不謊報成功：那會在審計裡記下一件沒發生過的事（口徑同 ErrManagerDuplicate）。
	ErrMemberAccountTaken = errors.New("member: 該帳戶在此活動內已有成員身份")
	// ErrMemberProfileConflict 表示編輯成員暱稱所依據的現值已不是資料庫現值：整個編輯沒有發生。
	//
	// 處置與活動／陣營／帳戶資料編輯同形：重讀服務端現值再決定，而不是拿手上那份再存一次。
	// 回應不回顯雙方的值——那是重讀名冊本來就拿得到的資料。
	ErrMemberProfileConflict = errors.New("member: 成員資料現值已與提交時所依據的不同")
	// ErrInvalidNickname 表示活動內暱稱不符合領域規則（空白、超長、含控制或格式字元）。
	ErrInvalidNickname = errors.New("member: 活動內暱稱不合法")
)

// 暱稱的邊界（本輪用戶批准：不另發明一套尺度）：上界沿用活動與陣營名稱的 64 碼位，
// 與遷移 0014 的 CHECK 同值。下限是 1——剔掉首尾空白之後必須還剩東西，
// 「一個空暱稱的成員」在名冊上既讀不出人也解釋不了何時算改壞。
const maxNicknameRunes = 64

// Member 是一行活動成員的可展示事實（建立回顯、名冊行與編輯結果共用同一個形狀）。
//
// 不含也不該有的東西：帳戶的登入名、口令形態、任何伺服器級角色（成員身份從不承載權限，
// 判定一律回 internal/identity 現讀）、陣營的名稱與顏色（那是 activity_factions 的事實，
// 介面要顯示就另行讀那一張表，不在這裡抄一份會漂移的副本）。
type Member struct {
	// ID 為玩家在活動內的穩定標識（身份只有它；暱稱可改、可重複）。
	ID idgen.ID
	// ActivityID 為所屬活動。它與 ID、AccountID 一起被資料庫觸發器釘成不可就地改寫。
	ActivityID idgen.ID
	// AccountID 為對應的帳戶標識（無外鍵軟參照，口徑同指派表：歷史不搬不改寫）。
	AccountID idgen.ID
	// Nickname 為活動內暱稱（剔首尾空白後的現值；不承擔唯一性）。
	Nickname string
	// FactionID 為此刻的陣營歸屬；零值語意是「尚未分組」（見檔頭第三條規定）。
	// 本步沒有分配端點，所有行的這一格都是零值；它存在是為了讓名冊能如實說出「沒有陣營」，
	// 而不是讓介面把缺席讀成「讀不到」。
	FactionID idgen.ID
	// DirectoryVisibility 是這一行的目錄覆蓋現值（遷移 0016；出廠 inherit）。
	// 它只往「更看不見」的方向覆蓋活動那一側的模式，永不放寬，也不約束管理視角與本人
	// （見 dirmode.go 的第四、五條規定）。名冊與目錄的判定都讀它，因此不會有第二個來源。
	DirectoryVisibility DirectoryVisibility
	// BusinessStatus 是成員此刻的業務狀態（七個內建穩定值之一；出廠 normal）。
	// 它不是連線狀態：沒有任何 HTTP 活躍度、頁面開啟或心跳會自動改寫它。
	BusinessStatus BusinessStatus
	// CustomStatusID 是 business_status 為 custom 時所指的自訂狀態定義標識；
	// 其餘六個內建狀態時為零值。成對關係由資料庫觸發器與倉儲讀法共同釘住。
	CustomStatusID idgen.ID
	// CustomStatusName 是自訂定義此刻的名稱投影（非本表欄位）；非 custom 狀態或定義讀不到時為空。
	// 它是顯示值；改名不會改變 CustomStatusID，也不會改寫任何歷史引用。
	CustomStatusName string
	// StatusDisplayName 是業務狀態的顯示名稱現值：內建狀態取活動層級覆蓋（空字串＝使用四語言
	// 預設文案），自訂狀態取定義名稱（定義讀不到時為空）。它永遠不是內部值。
	StatusDisplayName string
	// StatusAvailable 是這個狀態此刻是否仍可被選用：內建狀態恆為真；自訂狀態取定義的
	// available 現值（定義讀不到時為假，介面據此顯示通用句而不是編一個名稱）。
	StatusAvailable bool
	// DisplayName 為該帳戶此刻的顯示名（經名冊讀法從 internal/account 蓋上，非本表欄位）。
	// 空字串是事實的缺席：軟參照指向的行已被物理清理，介面據此顯示通用句而不編造名字。
	DisplayName string
	// AccountStatus 為該帳戶此刻的狀態（active|disabled|deleted|...）。它存在的理由與
	// 管理人名冊同一句：終態的行仍列、仍可讀，介面要能如實標示「這一行指向一個已被刪除
	// 的帳戶」，而不是把它藏起來讓人以為查無此人。空值表示那一行已讀不回。
	AccountStatus account.Status
	// AdminIdentity 是該帳戶此刻是否持有 server_admin 授予的投影（經 internal/grant 現讀
	// 盖上，非本表欄位；兩條讀法見 members.go 與 memberdirectory.go 的 adminIdentityOf）。
	//
	// 它是「管理員身分」在活動目錄上唯一的可判讀形態，而且判據不是暱稱、顯示名或任何
	// 前端標記。玩家側的目錄投影從不把這一格帶出去：它只在管理名冊與 all_players_except_admin
	// 那一句判定裡出現，否則就等于讓普通玩家多得到一枚「誰是後台的人」的可列舉信號。
	AdminIdentity bool
	// JoinedAt 為成員身份建立的時刻（注入時鐘；UTC）。
	JoinedAt time.Time
	// UpdatedAt 為最後一次改動時刻（今日只有暱稱編輯會推進；UTC）。
	UpdatedAt time.Time
}

// HasFaction 回報這一行是否已有陣營歸屬。
//
// 它只是零值檢查的具名寫法：介面與回應映射都問同一句話，避免各處拿
// `!m.FactionID.IsNil()` 湊出四種「有無陣營」的拼法。
func (m Member) HasFaction() bool { return !m.FactionID.IsNil() }

// validateNickname 校驗並正規化活動內暱稱：剔除首尾空白後必須非空、不超長、
// 且不含控制或格式字元。
//
// 為什麼不在此做唯一性檢查（用戶批准於本步）：暱稱不是身份鍵，同活動重名完全合法。
// 給它加唯一約束會把「兩個玩家都想叫小明」變成寫不進去的錯誤，而換名字從來不是
// 解決身份辨認的辦法——那是標識與登入名的職責。
//
// 內部空白保留：暱稱是給人讀的一句話，「夜 行者」這類寫法屬於它；只剔首尾，
// 否則同一個暱稱會因為一次複製貼上而出現兩種庫中形態。
func validateNickname(raw string) (string, error) {
	nickname := strings.TrimSpace(raw)
	if nickname == "" {
		return "", fmt.Errorf("%w：不可為空", ErrInvalidNickname)
	}
	if count := utf8.RuneCountInString(nickname); count > maxNicknameRunes {
		return "", fmt.Errorf("%w：長度不可超過 %d 個字元，實際 %d",
			ErrInvalidNickname, maxNicknameRunes, count)
	}
	for _, r := range nickname {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", fmt.Errorf("%w：不得含控制或格式字元（U+%04X）", ErrInvalidNickname, r)
		}
	}
	return nickname, nil
}
