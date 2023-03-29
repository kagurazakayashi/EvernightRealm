// tag.go 是活動標籤定義的領域模型：標籤是「一個活動內部的一枚可復用標記」——它屬於且只屬於
// 一個活動（activity_id），有自己的穩定標識、名稱、描述、內建圖標鍵、顏色、排序值、
// 可用性旗標與「普通玩家讀不讀得到這份定義」的公開旗標。
//
// 本檔只管「什麼是一行合法的標籤資料」，不管落庫（tagstore.go）也不管用例編排（tags.go、
// tagcatalog.go）。四條寫在模型上的規定（與陣營同一套口径）：
//   - 標識是身份，名稱不是。跨活動同名完全合法；同活動內名稱唯一是用戶批准的防呆
//     （避免操作者對著兩枚同名標籤只能數標識），不是把名稱升格成外鍵。
//     將來的貼標、通知、文件與自動化引用的都是這個標識：改名、換色、停用都讓既有引用照常成立。
//   - 圖標與顏色是展示輸入，不是身份承載。圖標只收內建標識鍵的封閉集合（與陣營同一份鍵：
//     界面渲染的是同一批本地圖標）；顏色只收 #RRGGBB 或空。任何界面都不得只靠顏色
//     辨認一枚標籤——名稱與標識才是。
//   - 可用性是旗標而不是狀態機，並進通用編輯白名單（用戶批准）；停用與恢復雙向可逆，
//     沒有終態出口，也沒有刪除通路（用戶批准於本步：只停用，不刪除，不級聯清空歷史）。
//   - 公開旗標是「這份定義能不能被普通玩家讀到」，不是權限、不是角色、不是可見性開關。
//     它逐枚標籤獨立決定（用戶批准）：沒有「整場活動一次翻公開」那一格。
//
// 停用（available＝假）的語意與陣營逐句同形，界面與日後通路都不得另講一套：
//   - 禁止新使用：停用後的標籤不再接收新的貼標請求，判定只有一處來源
//     （見 tags.go 的 EnsureTagAcceptsNewAssignments），日後的貼標通路必須在自己的
//     寫入交易內呼叫它。
//   - 保留歸屬與歷史：停用不清空任何既有引用、不逐出任何人、不改寫標識與歸屬活動；
//     行仍列、可讀、可改，與帳戶 deleted／活動 archived 那個「仍列可讀拒寫」家族同一姿態。
//   - 雙向可逆：恢復啟用就是把那一欄改回真，不附帶任何處置，也不會自動補貼任何人。
//
// 公開（public＝真）的邊界同樣寫死在模型上，因為它是一條隱私界而不是功能開關：
//   - 它只決定「這份定義本身讀不讀得到」。把一枚標籤收成公開，絕不讓任何一個本来不在
//     玩家目錄裡的人变得可被查出——一個人被不被看見只由 0016 那兩欄與成員行決定
//     （見 memberdirectory.go），標籤不參與那個判定，也不得被讀成「他因此被公開了」。
//   - 它不授予任何能力：持有公開標籤不讓人讀到內部標籤、篩選候選、貼標名單、
//     內部計數或審計原因，也不讓人多一項操作權限。
//   - 收回公開不改寫任何既有引用：它只讓下一次玩家側查詢不再列出這份定義（倉庫今日
//     沒有快取層，也不宣稱有推送）。
//
// 歷史引用保護寫在模型上：指向一枚標籤的只有它的穩定標識（id），名稱、顏色、圖標、
// 排序、可用狀態與公開旗標都不參與身份。因此改名、改色、停用、翻公開都不會讓任何既有
// 引用失效；也沒有任何一條通路能用名稱找到或改動一枚標籤。本庫尚未落地貼標與任何歷史
// 交易，因此這裡不建快照表、不回填歷史：等歷史記錄落地時，它必須保存「當時的標籤標識與
// 當時的名稱等展示值」，不得靠實時回查標籤名稱來解釋過去。
package activity

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// 標籤域的可判別結論。分類原則與帳戶／活動／陣營側同一套：正常會發生的業務衝突、
// 請求寫法錯誤各自成句，內部故障不進這些型別。
var (
	// ErrTagNotFound 表示這枚標籤不在呼叫者的可見範圍內：它可能從未存在，也可能存在但
	// 不屬於這個活動，也可能這個活動本身就不歸呼叫者管，還可能它存在且屬於這個活動但
	// 對普通玩家不公開——四種情況一律同一個答案（口徑同 ErrFactionNotFound：被拒的人
	// 拿不到「這個標識確實是一枚標籤」這條資訊，也拿不到「那個活動存在」的順帶確認）。
	ErrTagNotFound = errors.New("tag: 該標籤不在可見範圍內")
	// ErrTagNameTaken 表示同一個活動裡已經有另一枚標籤用了這個名稱：本次寫入整個沒有發生。
	//
	// 它是用戶批准的「同活動內名稱唯一」那句話的落點。重複不謊報成功——那會在審計裡
	// 記下一件沒發生過的事；先查再寫也只是友善錯誤來源，UNIQUE (activity_id, name) 才是
	// 正確性保證。跨活動同名不會走到這裡：唯一約束按活動分書，兩場活動都設「冠軍」
	// 是完全合法的部署形態。
	ErrTagNameTaken = errors.New("tag: 該活動內已有同名的標籤")
	// ErrTagProfileConflict 表示編輯標籤資料所依據的現值已不是資料庫現值：整個編輯沒有發生。
	//
	// 處置與活動／帳戶／陣營資料編輯同形：重讀服務端現值再決定，而不是拿手上那份再存一次。
	// 回應不回顯雙方的值——那是重讀列表本來就拿得到的資料。
	ErrTagProfileConflict = errors.New("tag: 標籤資料現值已與提交時所依據的不同")
	// ErrTagNotAcceptingAssignments 表示這枚標籤已停用，不再接收新的貼標請求。
	//
	// 它是留給「把標籤貼在玩家身上」那一步的結論（見 tags.go 的 EnsureTagAcceptsNewAssignments），
	// 今日還沒有任何一條貼標通路，因此這一句只活在服務層：沒有端點就不對外發機器碼
	// （口径同「沒有門就沒有對應的碼」，也同陣營那一步落地自選之後 2036 才順發的先例）。
	//
	// 它刻意不與 ErrTagNotFound 或門禁那兩句混用：停用的標籤是真實存在、也确实歸這個活動管，
	// 操作者需要的是「換一枚還開著的標籤」這句處置，而不是「找不到」或「等活動重開」。
	ErrTagNotAcceptingAssignments = errors.New("tag: 該標籤已停用，不再接收新的貼標請求")
	// ErrInvalidTagIcon 表示圖標鍵不在內建標識的封閉集合內（改寫法就能解決）。
	ErrInvalidTagIcon = errors.New("tag: 標籤圖標不合法")
	// ErrInvalidTagColor 表示顏色既不是空字串也不是 # 加六位十六進位。
	ErrInvalidTagColor = errors.New("tag: 標籤顏色不合法")
	// ErrInvalidTagSortOrder 表示排序值不在 0..上界的閉區間內。
	ErrInvalidTagSortOrder = errors.New("tag: 標籤排序值不合法")
)

// 標籤欄位的邊界（用戶批准於本步：長度與展示口径完全复用陣營那套已批准規則，不另发明一套）。
const (
	// maxTagSortOrder 是排序值上界，與陣營同一個數字：存在的理由是讓比較與回應成本
	// 不隨輸入數字膨脹。同值是合法形態（破平規則見 tagstore.go 的列表讀法）。
	maxTagSortOrder int64 = maxFactionSortOrder
)

// tagIconKeys 是圖標鍵的封閉集合。它刻意指同一個變量而不是再抄一份清單：
// 標籤與陣營渲染的是同一批前端本地圖標，兩處漂移無從發生；集合本身仍與遷移 0017 的
// CHECK 清單逐字相同，兩側漂移時各自的遷移測試與界面契約測試會各自報紅。
// 加新鍵走新的遷移放寬清單（口徑同 0013）。
var tagIconKeys = factionIconKeys

// Tag 是一枚標籤定義的可展示事實（建立回顯、列表行與編輯結果共用同一個形狀）。
//
// 不含也不該有的東西：被貼上這枚標籤的玩家名單（尚未落地，本步不冒充，也不拿空名單
// 或 0 冒充計數）、任何推測出來的「這個人該不該被貼」。權限判定從不進這個結構——
// 它是事實的投影，不是授權的載體。
type Tag struct {
	// ID 為標籤穩定標識（身份只有它；名稱可改、可跨活動重複）。
	ID idgen.ID
	// ActivityID 為歸屬活動。它與 ID 一起被資料庫觸發器釘成不可就地改寫：
	// 一枚標籤從生到死只屬於一場活動。
	ActivityID idgen.ID
	// Name 為標籤名稱（同活動內唯一；剔首尾空白後比對）。
	Name string
	// Description 為標籤描述（可為空字串，意即「沒有寫過描述」）。
	Description string
	// Icon 為內建圖標鍵（空字串＝未選）。
	Icon string
	// Color 為 #RRGGBB（小寫正規化後的現值；空字串＝未選色）。
	Color string
	// SortOrder 為列表排序值（同值時按建立時刻、標識穩定破平）。
	SortOrder int64
	// Available 為可用性旗標：真＝可用，假＝停用。停用不刪除、不改寫歷史、不清空既有引用，
	// 只讓這枚標籤不再接收新的貼標請求（四句語意見檔頭；判定見 tags.go）。
	Available bool
	// Public 為玩家公開旗標：真＝普通成員能讀到這份定義，假＝僅管理面可讀（出廠值）。
	//
	// 它只約束「這份定義讀不讀得到」，不約束任何人看不看得見（那一件事由 0016 決定），
	// 也不授予任何能力。界面必須把它讀成「這枚標籤的內容會不會出現在玩家那邊」，
	// 而不是讀成「公開這枚標籤」。
	Public bool
	// AcceptsNewAssignments 是服務端派生的現值：這枚標籤「此刻」能不能被貼給新對象，
	// 等於 Available 且所屬活動的狀態接受業務寫入（draft／active）。
	//
	// 它不是第九欄可寫資料：任何通路的請求裡都沒有這一格，它由用例在讀回後蓋上，
	// 於是「活動已停止時，連還開著的標籤也貼不出去」這一句有唯一權威來源，
	// 介面不必自己猜兩個欄位的組合（日後貼標通路讀的是 EnsureTagAcceptsNewAssignments，
	// 這一格只負責把同一個結論顯示出來）。
	AcceptsNewAssignments bool
	// CreatedAt 為建立時刻（UTC）。
	CreatedAt time.Time
	// UpdatedAt 為最後一次改動時刻（UTC）。
	UpdatedAt time.Time
}

// validateTagIcon 校驗圖標鍵：剔除首尾空白後必須命中封閉集合，否則點名取值。
//
// 不採信「先存了再說」：一個集合外的鍵會在界面退化成佔位圖標，操作者以為選了、
// 其實選了個不存在的東西（口徑同 validateFactionIcon）。
func validateTagIcon(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	for _, allowed := range tagIconKeys {
		if key == allowed {
			return key, nil
		}
	}
	return "", fmt.Errorf("%w：不認識的圖標鍵 %q", ErrInvalidTagIcon, key)
}

// validateTagColor 校驗顏色：空字串（未選色）或 # 加恰好六位十六進位字元。
// 存下的現值一律正規化成小寫——界面拿到的與庫裡的必須是同一個寫法（口徑同陣營）。
func validateTagColor(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if len(value) != 7 || value[0] != '#' {
		return "", fmt.Errorf("%w：顏色必須是 # 加六位十六進位，實際 %q", ErrInvalidTagColor, raw)
	}
	for _, r := range value[1:] {
		if !unicode.Is(unicode.ASCII_Hex_Digit, r) {
			return "", fmt.Errorf("%w：顏色含非十六進位字元（%q）", ErrInvalidTagColor, raw)
		}
	}
	return strings.ToLower(value), nil
}

// validateTagSortOrder 校驗排序值：0..上界的閉區間。
//
// 負數與超大值都是「改寫法就能解決」的輸入錯誤，不是業務衝突：界面據 1004 的欄位點名
// 把那格標紅，而不是讓一個解釋不了的數字進庫影響整張列表的排序。
func validateTagSortOrder(value int64) (int64, error) {
	if value < 0 || value > maxTagSortOrder {
		return 0, fmt.Errorf("%w：排序值不可超過 %d 且不可為負，實際 %d",
			ErrInvalidTagSortOrder, maxTagSortOrder, value)
	}
	return value, nil
}

// withAssignmentAcceptance 把「此刻能不能被貼給新對象」蓋在一行讀回的標籤上（派生規則見
// Tag.AcceptsNewAssignments 的文件說明）。
//
// 三個管理側讀法（列表、建立回顯、編輯回讀）都經此處填這一格，於是对外的派生值與
// EnsureTagAcceptsNewAssignments 的判定用的是同一條算式：旗標加活動的業務寫入現值。
// 它只是顯示用的投影，任何通路都不得拿它代替交易內的判定——判定要在交易裡現讀才算數。
// 玩家那一族的讀法不蓋這一格：那一側的輸出白名單裡沒有內部可用性（見 tagcatalog.go）。
func withAssignmentAcceptance(tag Tag, activityStatus Status) Tag {
	tag.AcceptsNewAssignments = tag.Available && activityStatus.AllowsBusinessWrites()
	return tag
}
