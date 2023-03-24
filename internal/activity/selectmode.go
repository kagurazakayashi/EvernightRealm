// selectmode.go 是「玩家自選陣營」的領域模型：活動級開關的三態取值、由此派生的
// 時機判定，以及玩家界面那一讀的承載形狀。
//
// 本檔只管「這場活動允不允許玩家自己選、允許幾次、此刻算不算能選」，不管落庫
// （store.go 的 faction_select_mode 欄位與 selfselect.go 的通路）。四條寫在模型上的規定：
//   - 開關屬活動，不屬陣營。「這場活動開不開放自選」只從 activities.faction_select_mode
//     讀一欄（見遷移 0015 檔頭的理由）；「這一個陣營此刻收不收新成員」仍只由 0013 的
//     available 旗標與活動的業務寫入門禁決定（見 factions.go 的 EnsureFactionAcceptsNewMembers）。
//     兩個問題各問各的來源，才不會出現「停用旗標順便要解釋活動有沒有開放自選」這種漂移。
//   - 三態而不是布林（用戶批準於本步）：disabled｜first_only｜free。
//     「允許自選」不等於「可以無限次切換」，也不是「選錯就定終身」——三種語意各有真實的
//     部署場景，收成一枚列舉就把「切換次數規則」寫成一個地方讀得到的事實，
//     而不是散在各端點各自 if 出來的三套說法。本模型沒有人數配額、付費切換、冷卻或審批：
//     那些都不是被批準的規則，發明它們屬越界。
//   - 出廠值是 disabled（用戶批準的相容規則）：既有活動一律不被新功能自動開放，
//     管理人要在活動配置裡明確選一個非 disabled 的值，玩家側才有可能寫入。
//   - 這是配置，不是生命週期狀態。它不進 status 那四態（把「開放自選」寫成活動狀態
//     會讓「這件事進行到哪裡」失去意義，口徑同遷移 0012 檔頭對階段／調度的說明）。
package activity

import (
	"errors"
	"fmt"
)

// FactionSelectMode 是一場活動對「玩家能不能自己在陣營間選」的三態配置。
//
// 值與遷移 0015 的 CHECK 封閉集合逐字相同：兩側各寫一份時以資料庫那份為最終把關，
// 這裡先擋是為了給出可判讀的錯誤與可判別的處置。新增取值一律走新的遷移放寬清單。
type FactionSelectMode string

const (
	// FactionSelectDisabled 是不開放：玩家側任何寫入一律拒絕，歸屬只由管理側通路決定。
	// 這是 activities 表這一欄的出廠值（見遷移 0015）。
	FactionSelectDisabled FactionSelectMode = "disabled"
	// FactionSelectFirstOnly 是僅首次：玩家可以自己選第一次，選定之後自助通路不再改變
	// 他的歸屬。要改已鎖定的歸屬屬管理側通路（尚未落地），不是玩家自己能做的事。
	FactionSelectFirstOnly FactionSelectMode = "first_only"
	// FactionSelectFree 是可反覆：玩家可以在「此刻可用」的陣營之間來回改自己的歸屬。
	FactionSelectFree FactionSelectMode = "free"
)

// String 回傳模式的機器表示（與資料庫欄位值同形）。
func (m FactionSelectMode) String() string { return string(m) }

// valid 回報模式是否落在封閉集合內。
func (m FactionSelectMode) valid() bool {
	switch m {
	case FactionSelectDisabled, FactionSelectFirstOnly, FactionSelectFree:
		return true
	}
	return false
}

// ParseFactionSelectMode 解析資料庫欄位或請求引數為模式。
//
// 未知取值回報 ErrInvalidFactionSelectMode：它屬「這個值不存在，改寫法再來」，
// 與「這個值存在但這場活動沒開放」是兩類結論（見 ErrFactionSelectDisabled），不可混為一談。
func ParseFactionSelectMode(value string) (FactionSelectMode, error) {
	m := FactionSelectMode(value)
	if !m.valid() {
		return "", fmt.Errorf("%w：不認識的自選模式 %q（僅 disabled|first_only|free）",
			ErrInvalidFactionSelectMode, value)
	}
	return m, nil
}

// 自選域的可判別結論。分類原則與活動／陣營／成員側同一套：可預期的業務衝突、
// 請求寫法錯誤各自成句，內部故障不進這些型別。
var (
	// ErrFactionSelectDisabled 表示這場活動目前沒有開放玩家自選陣營（模式為 disabled）。
	//
	// 處置是「等管理人改變配置」，而且改變的是活動的一欄配置，不是任何人的資料——
	// 因此它既不與 1001 那類「不在可見範圍」混用，也不與生命週期那三句混用。
	ErrFactionSelectDisabled = errors.New("factionselect: 該活動未開放玩家自選陣營")
	// ErrFactionSelectNotOpen 表示活動還在草稿：它尚未對玩家開放，因此自選時機未到。
	//
	// 它存在的理由是「草稿接受業務寫入」與「玩家該不該現在就把自己定下來」不是同一句話：
	// 管理人可以在草稿期準備陣營與名單（用戶批準於陣營那一步），但玩家在活動還沒開始時
	// 把自己鎖進某一組，在 first_only 下是一道今日無人能解開的死結（管理側分配通路尚未落地）。
	// 處置與 ErrActivityClosedWrites 分得開：那一句是「等活動重開」，這一句是「等活動開放」。
	ErrFactionSelectNotOpen = errors.New("factionselect: 活動尚未開放，玩家自選時機未到")
	// ErrFactionSelectLockedIn 表示僅首次模式下這個人已經選定過：自助通路不再改變他的歸屬。
	//
	// 它不是「你依據的現值過期」（那個是併發落敗，走資料衝突那一句）：重讀現值對這件事
	// 沒有幫助，現值就是「他已經有歸屬了」。處置只有一句——要改得由管理側通路處理。
	ErrFactionSelectLockedIn = errors.New("factionselect: 該成員已選定陣營，自助通路不再接受改動")
	// ErrInvalidFactionSelectMode 表示模式取值不在封閉集合內（改寫法就能解決）。
	ErrInvalidFactionSelectMode = errors.New("factionselect: 自選模式取值不合法")
	// ErrInvalidFactionSelection 表示自選請求本身講不出任何一次改動：
	// 目標陣營與它所依據的現值是同一格。
	//
	// 它屬請求寫法錯誤而不是業務衝突：這種本體描述的動作是「把 X 改成 X」，
	// 落庫與審計都不該為它產生任何事實（口徑同「不謊報成功」那一族）。
	ErrInvalidFactionSelection = errors.New("factionselect: 自選請求的目標與依據值是同一個陣營")
)

// ensureFactionSelectTiming 回答「這場活動此刻讓不讓玩家自選」，只問活動這一側的兩件事：
// 生命週期與那欄配置。陣營收不收新成員屬另一個問題（見 EnsureFactionAcceptsNewMembers）。
//
// 判定順序固定為「終態→停止→草稿→配置」，因為前兩句承認這個活動存在而後一句不：
//   - archived：一律拒寫的那一句（沒有出口）；
//   - closed：等活動重開那一句；
//   - draft：還輪不到玩家做這件事（見 ErrFactionSelectNotOpen 的理由）；
//   - active 但模式為 disabled：等管理人打開那一句。
//
// 它刻意不自己開交易也不查庫：呼叫端（玩家自選通路）必須在「同一個寫入交易」裡問這句話，
// 否則「問的時候還開著、寫的時候已被人關掉」那段視窗就是真的漏洞——SQLite 只有一個寫入者，
// 同一交易內的讀與寫看見同一個快照。
func ensureFactionSelectTiming(a Activity) error {
	if err := requireNotArchived(a); err != nil {
		return err
	}
	switch a.Status {
	case StatusClosed:
		return ErrActivityClosedWrites
	case StatusDraft:
		return ErrFactionSelectNotOpen
	case StatusActive:
	default:
		// 四態之外進不到這裡：狀態解析在讀取側就會先報缺陷（見 store.go 的 scanRow）。
		return ErrFactionSelectNotOpen
	}
	if a.FactionSelectMode == FactionSelectDisabled {
		return ErrFactionSelectDisabled
	}
	return nil
}

// FactionOption 是玩家自選界面上的一個候選項：一行陣營加上「它此刻能不能被這個玩家選」。
//
// Selectable 是服務端派生值，請求本體裡沒有這一格（口徑同陣營列表的 accepts_new_members）：
// 它等於「這個陣營此刻收新成員」且「這場活動此刻讓玩家自選」兩個結論的合取。
// 界面據此決定哪一項可點，而寫入通路在交易內重新問同樣的兩個問題——
// 藏按鈕永遠不代替服務端那道閘。
type FactionOption struct {
	// Faction 是候選陣營的展示事實（標識、名稱、描述、圖標、顏色、排序與可用旗標）。
	Faction Faction
	// Selectable 回報這個選項此刻能不能被這個玩家選中。
	Selectable bool
}

// FactionSelectionView 是「這個玩家在這場活動裡的陣營現況」一讀的承載形狀。
//
// 它帶三份同源事實：活動（含狀態與自選模式）、這個玩家的成員行（含此刻歸屬）、
// 這場活動的陣營候選清單。分頁刻意不做：一場活動的陣營是小表（口徑同名冊與管理人名冊）。
//
// 不含的東西：別人的歸屬（這一讀只答「我」）、任何帳戶欄位、任何自報的權限。
type FactionSelectionView struct {
	// Activity 是所屬活動的現值（狀態與 faction_select_mode 都在其中）。
	Activity Activity
	// Member 是這個玩家在這一場活動裡的成員行（含此刻的 faction_id）。
	Member Member
	// Options 是這場活動的全部陣營候選項（依排序值、建立時刻、標識的穩定順序）。
	Options []FactionOption
}

// CanSelectNow 回報「這個玩家此刻能不能發起一次自選寫入」——活動那一側的時機判定。
//
// 它是 ensureFactionSelectTiming 的顯示面：同一條規則只有一處實作，介面不再猜組合。
// 這一格不構成本人能不能寫入的決定——寫入通路在交易內重新問一遍，
// 而且還要另問陣營收不收新成員（這裡還沒指定要選哪一個陣營）。
func (v FactionSelectionView) CanSelectNow() bool {
	return ensureFactionSelectTiming(v.Activity) == nil
}

// allowsRepeatSelection 回報這個模式允不允許把既有歸屬換掉。
func (m FactionSelectMode) allowsRepeatSelection() bool {
	return m == FactionSelectFree
}

// factionOptionSelectable 把兩個結論合成一個選項的可點性（理由見 FactionOption.Selectable）。
func factionOptionSelectable(option Faction, timingOK bool) bool {
	return option.Available && timingOK
}
