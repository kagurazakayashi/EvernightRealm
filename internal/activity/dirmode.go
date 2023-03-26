// dirmode.go 是「活動玩家目錄可見性」的領域模型：活動那一側的四態模式、成員那一側的
// 只可收緊覆蓋，以及「這一行的資料投影此刻對這個人成立嗎」那一句話的唯一判定點。
//
// 本檔只管「誰能看見誰」，不管落庫（0016 的兩欄、memberstore.go 與 store.go 的讀寫）
// 也不管用例編排（memberdirectory.go）。五條寫在模型上的規定都來自本輪用戶批准，
// 任何一條通路都不得另講一套：
//   - 四態而不是布林（用戶批准於本步）：hidden｜same_faction_only｜
//     all_players_except_admin｜all_members。出厂 hidden，與 0015 那一欄配置同一條相容規則：
//     新功能不未經批準就向舊活動開放。倉庫裡今日根本沒有玩家目錄，因此「升級後突然有人
//     互相被搜到」是必須由預設值擋掉的那種事故。
//   - 無陣營不構成一個群體（用戶批准於本步）：NULL 的語意是「尚未分組」，不是一組的名字。
//     僅同阵营態下，兩個都沒分組的人彼此不可見，只看得到自己。把它讀成同一組會出現兩個
//     後果：出廠形態（所有人還沒分組）等於一個全開放的目錄，而把某人從陣營裡收回來
//     反而擴大他的可見範圍——兩句都不是批准過的規則。
//   - 覆蓋只能收緊，永不放寬（用戶批准於本步）：inherit 服從活動規則，hidden 在活動規則
//     之外再多收一層。集合裡刻意沒有 visible／public 這類取值：一格能繞過整個活動規則的
//     開關就不是覆蓋，是第二套規則。覆蓋也不改變管理視角——獲准管理該活動的人看得到全部成員。
//   - 管理視角只認服務端現讀的那一句（用戶批准於本步）：NeedServerAdmin 加上該活動的一行
//     指派，兩道閘都過才算 IsManager。它不來自請求的任何一格，也不來自「他是管理員所以
//     哪個活動都能看」——後者是根 AGENTS.md §7 點名的那類漏項。持有 server_admin 但未被指派
//     的人，在目錄裡與普通成員讀得到的一模一樣；他能多看到東西的那條路是名冊與詳情，
//     而那兩條問的是同一道指派閘。
//   - 「管理員身分」只有一個來源：internal/grant 那張表裡此刻有沒有 server_admin 那一行。
//     暱稱、顯示名、前端標記與「看起來像官方」全都不是判據（用戶批准於本步：不按昵稱或
//     前端標籤猜）。這一句是 all_players_except_admin 那態的全部內容。
//
// 判定是一條純函式：輸入全來自服務端在同一個讀取快照裡現讀的事實，輸出是一個布林。
// 列表、搜尋、詳情、計數、篩選候選、分頁與日後的 Target 解析都必須呼叫它，
// 於「先授權篩選、再分頁計數」這句順序只有一處實作，不可能各端點長出第二套答案。
package activity

import (
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// DirectoryMode 是一場活動對「玩家目錄開放多大範圍」的四態配置。
//
// 值與遷移 0016 的 CHECK 封閉集合逐字相同：兩側各寫一份時以資料庫那份為最終把關，
// 這裡先擋是為了給出可判讀的錯誤與可判別的處置。新增取值一律走新的遷移放寬清單。
type DirectoryMode string

const (
	// DirectoryHidden 是完全隱藏：目錄不對任何玩家列出任何人，包括他自己。
	// 本人經「我的資料」那一讀仍讀得到自己的行（那是獨立的本人授權，見 memberdirectory.go）。
	// 這是 activities.member_directory_mode 的出廠值（見遷移 0016）。
	DirectoryHidden DirectoryMode = "hidden"
	// DirectorySameFaction 是僅同陣營：只列與觀看者歸屬同一個陣營的成員。
	// 無陣營的人彼此不可見（只看得到自己）；停用陣營的成員仍按同陣營互見——
	// 判定看的是歸屬本身，不看 0013 的 available 旗標（用戶批准於陣營停用那一步）。
	DirectorySameFaction DirectoryMode = "same_faction_only"
	// DirectoryAllExceptAdmin 是所有玩家但排除管理員身分：列全部成員，
	// 唯獨把「此刻持有 server_admin 授予的那個人」收起來。判據只有 internal/grant 的現讀。
	DirectoryAllExceptAdmin DirectoryMode = "all_players_except_admin"
	// DirectoryAllMembers 是所有活動成員：這場活動的每一行都列（含持有授予的那幾行）。
	DirectoryAllMembers DirectoryMode = "all_members"
)

// String 回傳模式的機器表示（與資料庫欄位值同形）。
func (m DirectoryMode) String() string { return string(m) }

// valid 回報模式是否落在封閉集合內。
func (m DirectoryMode) valid() bool {
	switch m {
	case DirectoryHidden, DirectorySameFaction, DirectoryAllExceptAdmin, DirectoryAllMembers:
		return true
	}
	return false
}

// ParseDirectoryMode 解析資料庫欄位或請求引數為模式。
//
// 未知取值回報 ErrInvalidDirectoryMode：它屬「這個值不存在，改寫法再來」，
// 與「這個值存在但這場活動沒開放目錄」是兩類結論（見 DirectoryHidden 那一態），不可混為一談。
func ParseDirectoryMode(value string) (DirectoryMode, error) {
	m := DirectoryMode(value)
	if !m.valid() {
		return "", fmt.Errorf("%w：不認識的目錄模式 %q"+
			"（僅 hidden|same_faction_only|all_players_except_admin|all_members）",
			ErrInvalidDirectoryMode, value)
	}
	return m, nil
}

// DirectoryVisibility 是一行成員資料對「其他普通玩家」的可見性覆蓋。
//
// 只有兩態，而且第二態只往「更看不見」的方向走（用戶批准於本步）：
//   - inherit：服從活動那一側的模式。这是出廠值，於既有行一個字都沒改。
//   - hidden：在活動模式之外再多收一層——其他普通玩家讀不到這一行的任何投影。
//
// 沒有第三態：一格能放寬整個活動規則的開關，等於把活動級限制變成可被逐擊破的預設值，
// 而本步批准的是「覆蓋只收緊」。它同樣不約束管理視角，也不讓本人看不見自己。
type DirectoryVisibility string

const (
	// DirectoryVisibilityInherit 是不覆蓋：完全按活動的模式判定。
	DirectoryVisibilityInherit DirectoryVisibility = "inherit"
	// DirectoryVisibilityHidden 是收緊一層：除本人與管理視角外，任何人都讀不到這一行的投影。
	DirectoryVisibilityHidden DirectoryVisibility = "hidden"
)

// String 回傳覆蓋的機器表示（與資料庫欄位值同形）。
func (v DirectoryVisibility) String() string { return string(v) }

// valid 回報覆蓋是否落在封閉集合內。
func (v DirectoryVisibility) valid() bool {
	switch v {
	case DirectoryVisibilityInherit, DirectoryVisibilityHidden:
		return true
	}
	return false
}

// ParseDirectoryVisibility 解析資料庫欄位或請求引數為覆蓋值。
//
// 集合外取值回報 ErrInvalidDirectoryVisibility（改寫法就能解決），不降級成 inherit：
// 把一次寫壞的行讀成「他沒被收起來」，等于讓一個壞欄位自己說話擴大可見範圍。
func ParseDirectoryVisibility(value string) (DirectoryVisibility, error) {
	v := DirectoryVisibility(value)
	if !v.valid() {
		return "", fmt.Errorf("%w：不認識的目錄覆蓋值 %q（僅 inherit|hidden）",
			ErrInvalidDirectoryVisibility, value)
	}
	return v, nil
}

// 目錄域的可判別結論。分類原則與活動／陣營／成員／自選側同一套：可預期的業務衝突、
// 請求寫法錯誤各自成句，內部故障不進這些型別。
var (
	// ErrInvalidDirectoryMode 表示模式取值不在封閉集合內。
	ErrInvalidDirectoryMode = errors.New("memberdirectory: 目錄模式取值不合法")
	// ErrInvalidDirectoryVisibility 表示覆蓋取值不在封閉集合內。
	ErrInvalidDirectoryVisibility = errors.New("memberdirectory: 目錄覆蓋取值不合法")
)

// DirectoryViewer 是判定所需的「誰在看」：三份服務端現讀的事實，沒有一格來自請求。
//
// MemberID 為零值時語意是「他在這場活動裡沒有成員行」——今日只有管理視角會走到這裡
// （非成員的管理人能用名冊，不必假裝他能用玩家目錄）。FactionID 為零值是「尚未分組」，
// 它不是一個群體的名字（見檔頭第二條規定）。
type DirectoryViewer struct {
	// MemberID 是觀看者自己在這場活動裡的成員行標識；零值＝他不是成員。
	MemberID idgen.ID
	// FactionID 是他此刻的陣營歸屬；零值＝尚未分組。
	FactionID idgen.ID
	// IsManager 是「NeedServerAdmin 加上這個活動的一行指派」兩道閘都過的結論，
	// 由服務端現讀指派表得出。請求本體沒有一格能填它。
	IsManager bool
}

// DirectorySubject 是「被看的那一行」判定所需的現值。
//
// 它就是那一行 Member：陣營歸屬與覆蓋現值都在行上，而「這一行此刻是不是管理員身分」
// 是 Member.AdminIdentity 那一格——由 internal/grant 現讀盖上的投影，不是暱稱、顯示名
// 或任何展示層的東西（見 member.go 的同一句說明）。
type DirectorySubject struct {
	// Member 是被檢視的那一行（含此刻歸屬、這一欄覆蓋與授予投影）。
	Member Member
}

// memberDirectoryVisible 是「這一行的資料投影，此刻對這個人成立嗎」的唯一判定點。
//
// 順序是結果的一部分，寫成註解而不是各處 if 的拼湊：
//  1. 管理視角先決：獲准管理這個活動的人看得到全部成員，模式與覆蓋都不改這一句
//     （用戶批准於本步；這不授予他任何別的活動的管理權，也不是一個可以被請求觸發的參數）。
//  2. 完全隱藏對所有玩家成立，包括他自己——目錄在這一態下不列任何人；
//     本人的那一讀走 OwnMemberProfile 那條獨立通路，不經這裡。
//  3. 非隱藏態下他永遠在自己的目錄裡看得见自己（用戶批准於本步：隱藏與覆蓋都不該
//     讓人讀不到自己叫什麼），這一跳排在覆蓋之前。
//  4. 這一行的覆蓋是 hidden 時對其他普通玩家收起來（只收緊，見 DirectoryVisibility）。
//  5. 其餘按模式：全量放行；排除管理員身分那態看的是 grant 的現讀；僅同陣營要求
//     雙方都有歸屬且同一個陣營——任何一方尚未分組都不成立（無陣營不是一個群體）。
//
// 它不查庫、不開交易也不讀任何全域狀態：一次呼叫的輸入就是上面那兩份現值，
// 於是列表、詳情、計數、篩選候選與 Target 解析吃的是同一個布林，而不是同一句話的四種寫法。
func memberDirectoryVisible(mode DirectoryMode, viewer DirectoryViewer,
	subject DirectorySubject) bool {
	if viewer.IsManager {
		return true
	}
	if mode == DirectoryHidden {
		return false
	}
	if viewer.MemberID == subject.Member.ID {
		return true
	}
	if subject.Member.DirectoryVisibility == DirectoryVisibilityHidden {
		return false
	}
	switch mode {
	case DirectoryAllMembers:
		return true
	case DirectoryAllExceptAdmin:
		return !subject.Member.AdminIdentity
	case DirectorySameFaction:
		return viewer.FactionID == subject.Member.FactionID && !subject.Member.FactionID.IsNil()
	}
	// 集合外的模式進不到這裡：模式解析在讀取側就會先報缺陷（見 store.go 的 scanRow）。
	// 走到這裡一律回 false——未知取值絕不能被讀成「全都能看到」。
	return false
}
