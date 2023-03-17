// faction.go 是活動陣營的領域模型：陣營是「一個活動內部的一組」——它屬於且只屬於
// 一個活動（activity_id），有自己的穩定標識、名稱、描述、內建圖標鍵、顏色、排序值
// 與可用性旗標。
//
// 本檔只管「什麼是一行合法的陣營資料」，不管落庫（factionstore.go）也不管用例編排
// （factions.go）。三條寫在模型上的規定（與活動本身同一套口徑）：
//   - 標識是身份，名稱不是。跨活動同名完全合法；同活動內名稱唯一是用戶批准的防呆
//     （避免分配介面還沒落地時操作者對著兩個同名陣營只能數標識），不是把名稱升格成外鍵。
//   - 圖標與顏色是展示輸入，不是身份承載。圖標只收內建標識鍵的封閉集合（空字串＝未選，
//     介面以通用佔位顯示）；顏色只收 #RRGGBB 或空（未選色）。任何界面都不得只靠顏色
//     辨認一個陣營——名稱與標識才是。
//   - 可用性是旗標而不是狀態機。它沒有四態那樣的合法路徑問題，並進通用編輯白名單
//     （用戶批准於本步）；停用與恢復雙向可逆，沒有終態出口。
//
// 停用（available＝假）的四句已批准語意，本套件據此判定，界面與日後通路都不得另講一套：
//   - 禁止新分配：停用後的陣營不再接收新成員，判定只有一處來源（見 factions.go 的
//     EnsureFactionAcceptsNewMembers），日後的分配通路必須在自己的寫入交易內呼叫它。
//   - 保留歸屬與歷史：停用不清空任何既有歸屬、不把人踢出活動、不凍結任何玩家，
//     也不改寫標識與歸屬活動。行仍列、可讀、可改，與帳戶 deleted／活動 archived
//     那個「仍列可讀拒寫」家族同一姿態。
//   - 雙向可逆：恢復啟用就是把那一欄改回真，沒有任何附帶處置，也不會自動改寫任何人的
//     歸屬——停用期間原樣保留的歸屬在恢復後還在原處。
//   - 停用不改變關係語意：停用陣營的既有成員之間仍按「同陣營互見」處理，停用只約束
//     新分配，不撤走任何人已經擁有的可見性。
//
// 歷史引用保護寫在模型上：指向一個陣營的只有它的穩定標識（id），名稱、顏色、圖標、
// 排序與可用狀態都不參與身份。因此改名、改色、停用、再恢復，都不會讓任何既有引用失效；
// 也沒有任何一條通路能用名稱找到或改動一個陣營（同活動名稱唯一只是操作者防呆）。
// 本庫尚未落地成員與任何歷史交易，因此這裡不建快照表、不回填歷史：等歷史記錄落地時，
// 它必須保存「當時的陣營標識與當時的名稱等展示值」，不得靠實時回查陣營名稱來解釋過去。
package activity

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// 陣營域的可判別結論。分類原則與帳戶／活動側同一套：正常會發生的業務衝突、
// 請求寫法錯誤各自成句，內部故障不進這些型別。
var (
	// ErrFactionNotFound 表示這個陣營不在呼叫者的可見範圍內：它可能從未存在，
	// 也可能存在但不屬於這個活動，也可能這個活動本身就不歸呼叫者管——
	// 三種情況一律同一個答案（口徑同 ErrActivityNotFound：被拒的人拿不到
	// 「這個標識確實是一個陣營」這條資訊，也拿不到「那個活動存在」的順帶確認）。
	ErrFactionNotFound = errors.New("faction: 該陣營不在可見範圍內")
	// ErrFactionNameTaken 表示同一個活動內已經有另一個陣營用了這個名稱：本次寫入整個沒有發生。
	//
	// 它是用戶批准的「同活動內名稱唯一」那句話的落點。重複不謊報成功——那會在審計裡
	// 記下一件沒發生過的事；先查再寫也只是友善錯誤來源，UNIQUE (activity_id, name) 才是
	// 正確性保證。跨活動同名不會走到這裡：唯一約束按活動分書，兩場活動都設「黎明軍」
	// 是完全合法的部署形態。
	ErrFactionNameTaken = errors.New("faction: 該活動內已有同名的陣營")
	// ErrFactionProfileConflict 表示編輯陣營資料所依據的現值已不是資料庫現值：整個編輯沒有發生。
	//
	// 處置與活動／帳戶資料編輯同形：重讀服務端現值再決定，而不是拿手上那份再存一次。
	// 回應不回顯雙方的值——那是重讀列表本來就拿得到的資料。
	ErrFactionProfileConflict = errors.New("faction: 陣營資料現值已與提交時所依據的不同")
	// ErrFactionNotAcceptingMembers 表示這個陣營已停用，不再接收新成員。
	//
	// 它是留給「把玩家分進陣營」那一步的結論（見 factions.go 的 EnsureFactionAcceptsNewMembers），
	// 今日還沒有任何一條分配通路，因此這一句只活在服務層：沒有端點就不對外發機器碼
	// （口徑同「成員、資產、聊天尚未存在時不預發碼」）。分配落地時，它該對映成哪一枚碼、
	// 處置是「換個陣營」還是「請管理員重新啟用」，那一次一起批准。
	//
	// 它刻意不與 ErrFactionNotFound 或門禁那兩句混用：停用的陣營是真實存在、也確實歸這個活動管，
	// 操作者需要的是「換一個還開著的陣營」這句處置，而不是「找不到」或「等活动重開」。
	ErrFactionNotAcceptingMembers = errors.New("faction: 該陣營已停用，不再接收新成員")
	// ErrInvalidIcon 表示圖標鍵不在內建標識的封閉集合內（改寫法就能解決）。
	ErrInvalidIcon = errors.New("faction: 陣營圖標不合法")
	// ErrInvalidColor 表示顏色既不是空字串也不是 # 加六位十六進位。
	ErrInvalidColor = errors.New("faction: 陣營顏色不合法")
	// ErrInvalidSortOrder 表示排序值不在 0..上界的閉區間內。
	ErrInvalidSortOrder = errors.New("faction: 陣營排序值不合法")
)

// 陣營欄位的邊界（本步用戶批准：長度規則沿用已批准的活动口徑，不另发明一套）：
// 名稱與描述直接复用 validateName／validateDescription（64／500 碼位，見 activity.go）；
// 這裡只補陣營特有的三個：圖標封閉集合、顏色格式、排序上界。
const (
	// maxFactionSortOrder 是排序值上界。存在的理由是讓比較與回應成本不隨輸入數字膨脹；
	// 同值是合法形態（破平規則見 factionstore.go 的列表讀法），上界只約束單欄寫法。
	maxFactionSortOrder int64 = 99999
)

// factionIconKeys 是圖標鍵的封閉集合：空字串（未選，介面以通用佔位圖標顯示）在前，
// 其餘是前端以本地圖標渲染的內建標識鍵。與遷移 0013 的 CHECK 清單逐字相同，
// 兩側漂移時遷移測試與界面契約測試會各自報紅。加新鍵走新的遷移放寬清單——
// 口徑同活動狀態的四態封閉集合：能選什麼圖標的改變必然在版本史上留痕。
var factionIconKeys = []string{
	"", "star", "bolt", "flame", "wave", "leaf", "moon", "sun", "snow",
	"drop", "shield", "storm", "diamond", "cloud", "trophy", "book", "eye", "anchor",
}

// Faction 是一個陣營的可展示事實（建立回顯、列表行與編輯結果共用同一個形狀）。
//
// 不含也不該有的東西：陣營內的成員名單（尚未落地，本步不冒充）、任何推測出來的
// 「這個玩家該在哪個陣營」。權限判定從不進這個結構——它是事實的投影，不是授權的載體。
type Faction struct {
	// ID 為陣營穩定標識（身份只有它；名稱可改、可跨活動重複）。
	ID idgen.ID
	// ActivityID 為歸屬活動。它與 ID 一起被資料庫觸發器釘成不可就地改寫：
	// 一個陣營從生到死只屬於一場活動。
	ActivityID idgen.ID
	// Name 為陣營名稱（同活動內唯一；剔首尾空白後比對）。
	Name string
	// Description 為陣營描述（可為空字串，意即「沒有寫過描述」）。
	Description string
	// Icon 為內建圖標鍵（空字串＝未選）。
	Icon string
	// Color 為 #RRGGBB（小寫正規化後的現值；空字串＝未選色）。
	Color string
	// SortOrder 為列表排序值（同值時按建立時刻、標識穩定破平）。
	SortOrder int64
	// Available 為可用性旗標：真＝可用，假＝停用。停用不刪除、不改寫歷史、不清空歸屬，
	// 只讓這個陣營不再接收新成員（四句語意見檔頭；判定見 factions.go）。
	Available bool
	// AcceptsNewMembers 是服務端派生的現值：這個陣營「此刻」能不能被分給新成員，
	// 等於 Available 且所屬活動的狀態接受業務寫入（draft／active）。
	//
	// 它不是第七欄可寫資料：任何通路的請求裡都沒有這一格，它由用例在讀回後蓋上，
	// 於是「活動已停止時，連還開著的陣營也收不到新成員」這一句有唯一權威來源，
	// 介面不必自己猜活動狀態與旗標的組合（日後分配通路讀的是 EnsureFactionAcceptsNewMembers，
	// 這一格只負責把同一個結論顯示出來）。
	AcceptsNewMembers bool
	// CreatedAt 為建立時刻（UTC）。
	CreatedAt time.Time
	// UpdatedAt 為最後一次改動時刻（UTC）。
	UpdatedAt time.Time
}

// validateFactionIcon 校驗圖標鍵：剔除首尾空白後必須命中封閉集合，否則點名取值。
//
// 不採信「先存了再說」：一個集合外的鍵會在界面退化成佔位圖標，操作者以為選了、
// 其實選了個不存在的東西——那與把不存在的狀態寫進活動的 status 是同類缺陷。
func validateFactionIcon(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	for _, allowed := range factionIconKeys {
		if key == allowed {
			return key, nil
		}
	}
	return "", fmt.Errorf("%w：不認識的圖標鍵 %q", ErrInvalidIcon, key)
}

// validateFactionColor 校驗顏色：空字串（未選色）或 # 加恰好六位十六進位字元。
// 存下的現值一律正規化成小寫——界面拿到的與庫裡的必須是同一個寫法，
// 否則同一種色會出現兩種字面形态，比對與破平都得先猜「它們是不是同一個意思」。
func validateFactionColor(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if len(value) != 7 || value[0] != '#' {
		return "", fmt.Errorf("%w：顏色必須是 # 加六位十六進位，實際 %q", ErrInvalidColor, raw)
	}
	for _, r := range value[1:] {
		if !unicode.Is(unicode.ASCII_Hex_Digit, r) {
			return "", fmt.Errorf("%w：顏色含非十六進位字元（%q）", ErrInvalidColor, raw)
		}
	}
	return strings.ToLower(value), nil
}

// validateFactionSortOrder 校驗排序值：0..上界的閉區間。
//
// 負數與超大值都是「改寫法就能解決」的輸入錯誤，不是業務衝突：界面據 1004 的欄位點名
// 把那格標紅，而不是讓一個解釋不了的數字進庫影響整張列表的排序。
func validateFactionSortOrder(value int64) (int64, error) {
	if value < 0 || value > maxFactionSortOrder {
		return 0, fmt.Errorf("%w：排序值不可超過 %d 且不可為負，實際 %d",
			ErrInvalidSortOrder, maxFactionSortOrder, value)
	}
	return value, nil
}

// withMemberAcceptance 把「此刻能不能接收新成員」蓋在一行讀回的陣營上（派生規則見
// Faction.AcceptsNewMembers 的文件說明）。
//
// 三個讀法（列表、建立回顯、編輯回讀）都經此處填這一格，於是对外的派生值與
// EnsureFactionAcceptsNewMembers 的判定用的是同一條算式：旗標加活動的業務寫入現值。
// 它只是顯示用的投影，任何通路都不得拿它代替交易內的判定——判定要在交易裡現讀才算數。
func withMemberAcceptance(faction Faction, activityStatus Status) Faction {
	faction.AcceptsNewMembers = faction.Available && activityStatus.AllowsBusinessWrites()
	return faction
}
