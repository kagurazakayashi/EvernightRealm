// memberdirectory.go 是「活動玩家目錄可見性」的用例層：活動那一側模式的讀寫、
// 玩家那一側的目錄讀法（列表／搜尋／篩選候選／分頁一次完成、單筆直查、本人資料投影），
// 以及管理人對單一行成員的覆蓋編輯。
//
// 這一層把本步批准的四件事凝成同一条通路：
//   - 判定只有一句話：dirmode.go 的 memberDirectoryVisible。列表、搜尋、詳情、計數、
//     篩選候選、分頁與日後的 Target 解析吃的都是同一份「先授權篩選」之後的結果集，
//     於是「列得出來卻點不進去」與「計數比列表多幾筆」這類形態在結構上就不成立；
//     分頁與計數一律排在授權篩選之後，不是先分頁再逐行問能不能給你看。
//   - 每一次請求都重新現讀：活動的模式、觀看者自己的那一行（含他此刻的歸屬）、
//     名冊的每一行與其覆蓋、以及 internal/grant 對「他此刻是不是管理員身分」的回答。
//     這一族讀法背後沒有任何快取層，也不採信請求交來的任何一格——「上一批的舊陣營或
//     舊配置被繼續信任」在這裡沒有可發生的形態；管理人改完配置後的下一次請求就是新規則，
//     不等未來的推送系統（倉庫裡今日沒有實時層，本檔也不宣稱有）。
//   - 兩套准入邊界，不是一套：配置與覆蓋屬活動管理面（NeedServerAdmin 加上這個活動的
//     一行指派，判定仍是 requireActivityScope 這一處）；目錄與本人資料屬玩家側，
//     先問「這次請求的憑據換出的是哪一個帳戶」再按（活動, 那個帳戶）讀他自己的行。
//     玩家那一族沒有「切換成管理視角」的參數：IsManager 只由服務端現讀的指派決定，
//     請求本體與查詢串裡都沒有那一格——帶了就撞 1004（無處可填）。
//   - 輸出是白名單投影，不是行轉錄：一行目錄項只有他在這場活動內的標識、活動內暱稱、
//     陣營的展示三值與那一欄停用旗標、加入時刻。登入名、口令形態、帳戶狀態、內部標籤與後台原因
//     一律不進這份投影（管理面要那些事實，走 /admin 的名冊，那道閘不同）。
//
// 不可分辨的邊界沿用既有那一句：查無這個活動、他不是這場活動的成員、那一行不屬於這場活動、
// 那一行此刻對他不可見——四件事對外都是同一句話（ErrMemberNotFound／ErrActivityNotFound，
// 傳輸層收斂成 1001）。目錄在 hidden 態下回的是空的一頁而不是拒絕：那本來就是這一態的答案，
// 「這一態不列任何人」對任何敲門者都是同一份回應，不多出任何存在性信號。
//
// 本步沒有的東西，也不假裝有：NPC 目錄與它那套獨立授權（屬 NPC 模組）、把覆蓋放大成
// 一格能繞過整個活動規則的公開開關、實時推送、跨活動的「一口氣看全部」目錄，
// 以及任何把「他是管理員」寫成暱稱或前端標記的判據。
package activity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// DirectoryFactionFilterMax 是篩選候選一次能帶回的陣營數上限。
//
// 它不是產品限制而是一條資源上界：候選清單由可見行分組得出，行數已被分頁上限與名冊規模
// 自然封頂，這一格只是防止某一場活動被塞進大量陣營後把回應體撐到不可預期。
const DirectoryFactionFilterMax = 256

// DirectoryMemberQuery 是玩家目錄一讀的輸入。
//
// 沒有一格能宣告「用管理視角」或「我看的是哪個活動的哪一個人」：可見範圍由服務端現讀，
// 對象由路徑與會話決定。FactionID 為零值語意是「不按陣營篩選」。
type DirectoryMemberQuery struct {
	// Page 為頁碼，從 1 起。
	Page int64
	// PageSize 為每頁筆數；1..DirectoryMaxPageSize。
	PageSize int64
	// Keyword 為活動內暱稱的關鍵字；去首尾空白後為空即不篩選。
	Keyword string
	// FactionID 是陣營篩選；零值＝不篩選。
	FactionID idgen.ID
}

// DirectoryMember 是一行目錄資料的投影：一行成員事實加上它所指陣營的展示三值與停用旗標。
//
// 它是玩家能從目錄裡拿到的全部：沒有帳戶欄位、沒有內部標籤，也沒有「他為什麼不可見」
// 這種後台原因。FactionName／FactionIcon／FactionColor 屬活動自己的展示事實（0013），
// 陣營標識讀不到展示值時如實留空而不是編一個名字（口徑同名冊的顯示名）。
type DirectoryMember struct {
	// MemberID 是那個玩家在這一場活動裡的穩定標識。
	MemberID idgen.ID
	// Nickname 是他的活動內暱稱（可重複、可改；不是身份）。
	Nickname string
	// FactionID 是他此刻的歸屬；零值語意是「尚未分組」，出口為空字串。
	FactionID idgen.ID
	// FactionName／FactionIcon／FactionColor 是那個陣營的展示事實（無歸屬時恆為空字串）。
	FactionName  string
	FactionIcon  string
	FactionColor string
	// FactionAvailable 是那個陣營自己的停用旗標現值（activity_factions.available，不是派生的
	// AcceptsNewMembers）：真＝那一欄是開的，假＝已停用。它刻意不折進活動狀態——活動停止時
	// 目錄照舊可讀，而界面要講的那句「所屬陣營已停用」講的就是這一欄本身。
	//
	// 三種情況下它為假，介面據此分行而不是猜：無歸屬（空字串標識）、歸屬讀不到展示值
	// （資料形態缺陷，此時名稱也為空）、以及真的被停用。因此那句顯示只在
	// 「有歸屬且讀到了名稱」時才准出現，否則講的是各自那一句。
	FactionAvailable bool
	// JoinedAt 是他取得成員身份的時刻（活動內事實，非帳戶資料）。
	JoinedAt time.Time
	// BusinessStatus 是他此刻的業務狀態內部值（七個內建鍵之一）。
	// 它不是連線狀態，也不會隨 HTTP 活躍度自行改變。
	BusinessStatus BusinessStatus
	// CustomStatusID 是自訂狀態定義的穩定標識；非 custom 狀態時為零值。
	CustomStatusID idgen.ID
	// CustomStatusName 是自訂定義此刻的名稱（非 custom 或定義讀不到時為空）。
	CustomStatusName string
	// StatusDisplayName 是展示用名稱：內建狀態取活動覆蓋（空字串＝用戶端四語言預設），
	// 自訂狀態取定義名稱。它是顯示值，不是內部身份。
	StatusDisplayName string
	// StatusAvailable 是這個狀態此刻是否仍可被選用：內建恆為真，自訂取定義現值。
	StatusAvailable bool
}

// DirectoryFacet 是篩選候選的一項：一個陣營與「此刻這個觀看者在他那邊看得见幾個人」。
//
// 計數的口徑必須與列表同源，否則界面會顯示「該陣營有 12 人」而點進去只有 3 行。
// 這一項只從已授權篩選後的結果集分組得出，因此它不可能把「別人看不見的那幾行」
// 算進去，也就不構成一枚繞過模式的人數探測器。
type DirectoryFacet struct {
	FactionID idgen.ID
	Name      string
	Icon      string
	Color     string
	Count     int64
}

// DirectoryMemberPage 是一頁目錄加上同一份結果集派生的計數、模式與篩選候選。
type DirectoryMemberPage struct {
	// Rows 是本頁的目錄項（加入時刻升序、標識破平，與名冊同一個穩定順序）。
	Rows []DirectoryMember
	// Page 與 PageSize 回顯實際生效的分頁引數。
	Page     int64
	PageSize int64
	// Total 是「已授權篩選＋關鍵字＋陣營篩選」之後的總筆數（不受分頁影響）。
	Total int64
	// Mode 是這一讀生效的活動目錄模式（服務端現讀，恆在回應、絕不在請求）。
	Mode DirectoryMode
	// Facets 是篩選候選：按「已授權篩選」而未套關鍵字與陣營篩選的結果集分組。
	Facets []DirectoryFacet
	// SelfID 是觀看者自己在這場活動裡的成員標識（介面用它把「這一行是我」標出來）。
	// 玩家這一族的讀法只允許帳戶主體走到這裡（見 memberDirectorySnapshot），
	// 因此零值只可能出現在「他是獲准管理該活動、自己卻沒有成員行」那一種管理視角下。
	SelfID idgen.ID
}

// OwnMemberProfileView 是「我自己的活動內資料」一讀的承載形狀。
//
// 它帶三份同源事實：活動（含狀態與目錄模式）、自己的那一行（含此刻歸屬與自己那格覆蓋）、
// 以及那一行的對外投影。這一讀不经目錄可見性判定：本人對自己那一行的讀取是獨立的本人
// 授權（用戶批准於本步）——活動把目錄收成 hidden、或管理人把他單獨收起來，
// 都不該讓他讀不到自己叫什麼。
type OwnMemberProfileView struct {
	Activity Activity
	Member   Member
	Item     DirectoryMember
}

// memberDirectoryCandidate 是判定與投影共用的一行候選：一行成員現值加上它的展示事實。
//
// 「他此刻是不是管理員身分」已經在 Member.AdminIdentity 那一格（由 adminIdentityOf 現讀盖上），
// 這裡因此不另帶一份可能與名冊不同步的副本。
type memberDirectoryCandidate struct {
	subject          DirectorySubject
	factionName      string
	factionIcon      string
	factionColor     string
	factionAvailable bool
}

// memberDirectorySnapshot 是一次目錄判定的全部現讀結果：觀看者、活動、候選行與陣營清單。
//
// 把四份事實一次湊齊不是為了少寫幾個變數，而是為了讓「列表、詳情、計數、篩選候選、
// 分頁與 Target 解析吃同一份快照」這句話有對應的程式形狀：四者都從同一個結構派生。
type memberDirectorySnapshot struct {
	viewer     DirectoryViewer
	activity   Activity
	candidates []memberDirectoryCandidate
	factions   []Faction
}

// MemberDirectory 以受信主體讀一頁玩家目錄。
//
// 全部規則在同一次請求內按固定順序問完，而且順序是結論的一部分：
//  1. 主體必須是一個帳戶（會話決定，不是請求決定）——Root 與系統主體在玩家這一族
//     沒有可指向的成員行，與「查無此人」同一句話（口徑同 selfselect.go 的 requireSelfPrincipal）；
//  2. 現讀活動那一行（查無＝不可分辨）；
//  3. 現讀觀看者自己的那一行：讀不到時，只有在「NeedServerAdmin 加上這個活動的指派」
//     兩道閘都過的前提下才繼續（管理視角），否則當場收斂成不可分辨的那句話——
//     這一跳排在模式判定之前，否則非成員能靠「這活動沒開放目錄」確認那個標識確實是一場活動；
//  4. 現讀名冊全部行與這場活動的陣營清單，把每一行湊成一個候選（含覆蓋現值與授予現讀）；
//  5. 逐行呼叫 memberDirectoryVisible 得到「已授權篩選」的結果集——計數、分頁、
//     關鍵字與篩選候選全部從這一份切片派生；
//  6. 再套關鍵字與陣營篩選，統計 Total，切出本頁。
//
// 這裡不開寫入交易也不加任何快取：SQLite WAL 的讀取本身就是快照級的，
// 而「同一份候選切片派生一切」讓列表與計數不可能各說各話。
func (s *Service) MemberDirectory(ctx context.Context, principal identity.Principal,
	activityID idgen.ID, query DirectoryMemberQuery) (DirectoryMemberPage, error) {
	if query.Page < 1 {
		return DirectoryMemberPage{}, fmt.Errorf("%w：page=%d（必須大於 0；沒帶參數由傳輸層填預設）",
			ErrInvalidPage, query.Page)
	}
	if query.PageSize < 1 || query.PageSize > DirectoryMaxPageSize {
		return DirectoryMemberPage{}, fmt.Errorf("%w：page_size=%d（必須在 1..%d）",
			ErrInvalidPageSize, query.PageSize, DirectoryMaxPageSize)
	}
	keyword, err := normalizeKeyword(query.Keyword)
	if err != nil {
		return DirectoryMemberPage{}, err
	}

	snapshot, err := s.memberDirectorySnapshot(ctx, s.db.SQL(), principal, activityID)
	if err != nil {
		return DirectoryMemberPage{}, err
	}
	mode := snapshot.activity.MemberDirectoryMode

	// 授權篩選：一次判定，之後的每一格都從這份結果集讀出來。
	allowed := make([]memberDirectoryCandidate, 0, len(snapshot.candidates))
	for _, candidate := range snapshot.candidates {
		if memberDirectoryVisible(mode, snapshot.viewer, candidate.subject) {
			allowed = append(allowed, candidate)
		}
	}
	facets := directoryFacets(snapshot.factions, allowed)

	filtered := allowed
	if !query.FactionID.IsNil() {
		narrowed := make([]memberDirectoryCandidate, 0, len(filtered))
		for _, candidate := range filtered {
			if candidate.subject.Member.FactionID == query.FactionID {
				narrowed = append(narrowed, candidate)
			}
		}
		filtered = narrowed
	}
	if keyword != "" {
		narrowed := make([]memberDirectoryCandidate, 0, len(filtered))
		for _, candidate := range filtered {
			if nicknameMatchesKeyword(candidate.subject.Member.Nickname, keyword) {
				narrowed = append(narrowed, candidate)
			}
		}
		filtered = narrowed
	}

	page := DirectoryMemberPage{
		Page:     query.Page,
		PageSize: query.PageSize,
		Total:    int64(len(filtered)),
		Mode:     mode,
		Facets:   facets,
		SelfID:   snapshot.viewer.MemberID,
	}
	// 起點落在總數之外時不謊報也不報錯：那是一句「這一頁沒有東西」的事實，
	// 與活動目錄同一口徑（越界頁回空 Rows，Total 照實）。
	offset := int((query.Page - 1) * query.PageSize)
	if offset < len(filtered) {
		end := offset + int(query.PageSize)
		if end > len(filtered) {
			end = len(filtered)
		}
		page.Rows = make([]DirectoryMember, 0, end-offset)
		for _, candidate := range filtered[offset:end] {
			page.Rows = append(page.Rows, candidate.item())
		}
	}
	if page.Rows == nil {
		page.Rows = []DirectoryMember{}
	}
	return page, nil
}

// DirectoryMemberDetail 以同一個判定讀回單筆目錄項（日後的 Target 解析走的是這條）。
//
// 它刻意不另開一條「按標識查一行、然後問能不能給你看」的路：先經同一份現讀快照把
// 這場活動的全部候選湊齊、再用同一句 memberDirectoryVisible 過濾、在過濾後的結果集裡找那個標識。
// 於是「列表裡沒有他」與「按他的標識直查也查不到」必然同進同退，而造出這種結果集的
// 三種原因（從未存在、屬於另一場活動、此刻對他不可見）對外都是同一句話。
func (s *Service) DirectoryMemberDetail(ctx context.Context, principal identity.Principal,
	activityID, memberID idgen.ID) (DirectoryMember, error) {
	if memberID.IsNil() {
		return DirectoryMember{}, ErrMemberNotFound
	}
	snapshot, err := s.memberDirectorySnapshot(ctx, s.db.SQL(), principal, activityID)
	if err != nil {
		return DirectoryMember{}, err
	}
	mode := snapshot.activity.MemberDirectoryMode
	for _, candidate := range snapshot.candidates {
		if candidate.subject.Member.ID != memberID {
			continue
		}
		if !memberDirectoryVisible(mode, snapshot.viewer, candidate.subject) {
			// 找到了行但不給看：這一句與「從未存在」「不屬於這個活動」同形，
			// 敲路徑的人多知道哪一個都不該是信號。
			return DirectoryMember{}, ErrMemberNotFound
		}
		return candidate.item(), nil
	}
	return DirectoryMember{}, ErrMemberNotFound
}

// OwnMemberProfile 讀回「我自己在那場活動裡的資料投影」，不经目錄可見性判定。
//
// 順序與目錄一讀同形但結論不同：主體必須是本次會話換出的那個帳戶，然後按
// （活動, 那個帳戶）讀回他自己的行——讀不到就是與幽靈同形的那句話（1001）。
// 這裡不問模式、不問覆蓋，也不需要指派清單：這一讀的對象永遠是他自己，
// 而「一個人看得見自己叫什麼」不是特權（用戶批准於本步：隱藏與覆蓋都不該讓他
// 讀不到本人的活動內資料）。管理視角在本條通路上沒有任何作用，也無處可放大——
// 路徑與本體裡都沒有一格能填「哪個玩家」。
func (s *Service) OwnMemberProfile(ctx context.Context, principal identity.Principal,
	activityID idgen.ID) (OwnMemberProfileView, error) {
	accountID, err := s.requireSelfPrincipal(principal, "member_directory_self")
	if err != nil {
		return OwnMemberProfileView{}, err
	}
	q := s.db.SQL()
	member, err := s.store.MemberByAccount(ctx, q, activityID, accountID)
	if err != nil {
		return OwnMemberProfileView{}, err
	}
	// 本人投影也是「繼續使用該活動訪問資格」的一環：被禁止登入的人讀得到自己的
	// 六欄限制（OwnMemberRestrictions），讀不到這份活動內資料——那一條通路是本步
	// 為「本人獲准查看有效結果」留的唯一例外，除此之外這一族一律按現值擋下。
	if err := checkMemberActivityAccess(member); err != nil {
		return OwnMemberProfileView{}, err
	}
	if err := s.fillMemberStatus(ctx, q, []*Member{&member}); err != nil {
		return OwnMemberProfileView{}, err
	}
	a, err := s.readActivity(ctx, q, member.ActivityID)
	if err != nil {
		return OwnMemberProfileView{}, err
	}
	factions, err := s.store.Factions(ctx, q, member.ActivityID)
	if err != nil {
		s.log.Error("讀取本人資料的陣營展示值失敗",
			"activity", member.ActivityID.String(), "err", err)
		return OwnMemberProfileView{}, fmt.Errorf("activity: 讀取本人資料的陣營展示值失敗: %w", err)
	}
	item := directoryItemOf(member)
	if display, ok := factionDisplayOf(factions, member.FactionID); ok {
		item.FactionName, item.FactionIcon, item.FactionColor = display.name, display.icon, display.color
		item.FactionAvailable = display.available
	}
	return OwnMemberProfileView{Activity: a, Member: member, Item: item}, nil
}

// UpdateMemberDirectoryMode 以白名單方式編輯一場活動的「玩家目錄可見性」那一欄配置。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 域校驗（在寫之前，不在撞 CHECK 之後）；
//  2. 交易內判定活動作用域（NeedServerAdmin 加上這一行指派）；
//  3. 交易內讀活動現值並核實它還沒進入終態：這是一欄活動配置，與名稱、描述、自選模式同側，
//     因此停止態照樣可以準備「重開之後目錄開放多大範圍」；玩家那一側讀什麼由模式自己回答，
//     這裡不另長一套門禁；
//  4. CAS 更新只碰 member_directory_mode 一欄：changed=false 時整個編輯不發生並回衝突；
//  5. 同一交易內讀回並追加活動域審計——前後只有這一欄。
//
// 改配置不改寫任何人的既有事實：換成 hidden 不會清掉任何一行成員的覆蓋現值，
// 也不會把任何人的陣營歸屬搬走或動到自選開關（口徑同 0015 收回開關不清歸屬）。
// 被拒的編輯（不在可見範圍、已歸檔、併發衝突、取值不合法）不追加審計。
func (s *Service) UpdateMemberDirectoryMode(ctx context.Context, principal identity.Principal,
	activityID idgen.ID, mode, expectedMode DirectoryMode,
	requestID string) (Activity, error) {
	if !mode.valid() {
		return Activity{}, fmt.Errorf("%w：模式 %q 不在封閉集合內",
			ErrInvalidDirectoryMode, string(mode))
	}
	if !expectedMode.valid() {
		return Activity{}, fmt.Errorf("%w：依據值 %q 不在封閉集合內",
			ErrInvalidDirectoryMode, string(expectedMode))
	}

	var updated Activity
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID,
			"member_directory_config_update"); err != nil {
			return err
		}
		before, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		if err := requireNotArchived(before); err != nil {
			return err
		}
		changed, err := s.store.UpdateMemberDirectoryMode(tctx, tx, activityID, mode, expectedMode)
		if err != nil {
			return err
		}
		if !changed {
			return ErrProfileConflict
		}
		after, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		rec, err := s.activityRecord(principal, activityID, "activity.member_directory_update",
			"activity", activityID.String(), "管理員經已認證會話變更玩家目錄可見性設定", requestID,
			auditChange("member_directory_mode", before.MemberDirectoryMode.String(),
				after.MemberDirectoryMode.String()))
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		updated = after
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrActivityNotFound), errors.Is(err, ErrProfileConflict),
			errors.Is(err, ErrArchived), errors.Is(err, ErrInvalidDirectoryMode),
			errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return Activity{}, err
		}
		s.log.Error("變更玩家目錄配置失敗", "request_id", requestID, "err", err)
		return Activity{}, fmt.Errorf("activity: 變更玩家目錄配置失敗: %w", err)
	}
	s.log.Info("已變更玩家目錄配置",
		"activity", updated.ID.String(), "mode", updated.MemberDirectoryMode.String(),
		"request_id", requestID)
	return updated, nil
}

// UpdateMemberDirectoryVisibility 以白名單方式編輯一行成員的目錄覆蓋（只可收緊那一欄）。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 域校驗（在寫之前）；
//  2. 交易內判定活動作用域——這條通路屬管理面，普通成員敲不進；
//  3. 交易內現讀業務寫入門禁：與改暱稱同一側（那是对一行成員資料的改動），
//     停止態拿「現在不行、重開就好」，歸檔拿「這件事已經結束」；
//  4. 按標識讀回成員並核實它確實屬於這個活動——跨活動與從未存在同一句話；
//  5. CAS 更新只碰 directory_visibility 一欄：changed=false 時整個編輯不發生並回衝突；
//  6. 同一交易內讀回並追加活動域審計——前後只有這一欄。
//
// 它不改任何人的陣營歸屬、不動自選開關、也不改活動那一側的模式（各條通路只認自己那一欄，
// 口徑同「改名不會順手換組」）。取值集合裡沒有「放寬」那一格：這一欄能做到的最寬結果
// 就是 inherit，也就是完全服從活動規則。
func (s *Service) UpdateMemberDirectoryVisibility(ctx context.Context, principal identity.Principal,
	activityID, memberID idgen.ID, visibility, expectedVisibility DirectoryVisibility,
	requestID string) (Member, error) {
	if !visibility.valid() {
		return Member{}, fmt.Errorf("%w：覆蓋值 %q 不在封閉集合內",
			ErrInvalidDirectoryVisibility, string(visibility))
	}
	if !expectedVisibility.valid() {
		return Member{}, fmt.Errorf("%w：依據值 %q 不在封閉集合內",
			ErrInvalidDirectoryVisibility, string(expectedVisibility))
	}

	var updated Member
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID,
			"member_directory_visibility_update"); err != nil {
			return err
		}
		if _, err := s.EnsureBusinessWritesAllowed(tctx, tx, activityID); err != nil {
			return err
		}
		before, err := s.store.MemberByID(tctx, tx, memberID)
		if err != nil {
			return err
		}
		if before.ActivityID != activityID {
			// 查無與「不屬於這個活動」收斂成同一句話（口徑同改暱稱那一條）。
			return ErrMemberNotFound
		}
		changed, err := s.store.UpdateMemberDirectoryVisibility(tctx, tx, memberID, activityID,
			visibility, expectedVisibility)
		if err != nil {
			return err
		}
		if !changed {
			return ErrMemberProfileConflict
		}
		after, err := s.store.MemberByID(tctx, tx, memberID)
		if err != nil {
			return err
		}
		rec, err := s.activityRecord(principal, activityID, "member.directory_visibility_update",
			"member", after.ID.String(), "管理員經已認證會話變更成員目錄可見性覆蓋", requestID,
			auditChange("directory_visibility", before.DirectoryVisibility.String(),
				after.DirectoryVisibility.String()))
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		updated = after
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrActivityNotFound), errors.Is(err, ErrMemberNotFound),
			errors.Is(err, ErrMemberProfileConflict),
			errors.Is(err, ErrInvalidDirectoryVisibility),
			errors.Is(err, ErrArchived), errors.Is(err, ErrActivityClosedWrites),
			errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return Member{}, err
		}
		s.log.Error("變更成員目錄覆蓋失敗", "request_id", requestID, "err", err)
		return Member{}, fmt.Errorf("activity: 變更成員目錄覆蓋失敗: %w", err)
	}
	s.log.Info("已變更成員目錄覆蓋",
		"activity", activityID.String(), "member", updated.ID.String(), "request_id", requestID)
	return updated, nil
}

// memberDirectorySnapshot 把一次目錄判定需要的全部現讀湮成一個結構。
//
// 順序（「他不是成員」先於模式判定）寫在這裡而不是各呼叫端自己排：把它移到後面時，
// 一個非成員對一場 hidden 態的活動動手就會聽到「目錄沒開放」，等於承認那個標識
// 確實是一場活動——1001 那層不可分辨性會從這條路徑上漏掉。
//
// 名冊行是逐行現讀的（覆蓋與歸屬都以庫中現值為準），授予也在同一處逐行問 internal/grant；
// 這裡沒有快取，也沒有「這一批剛才算過」的那種記憶可用——這是「下一次請求按新規則判定」
// 在本倉庫今天的形態，而不是對未來實時層的一句承諾。
func (s *Service) memberDirectorySnapshot(ctx context.Context, q database.Querier,
	principal identity.Principal, activityID idgen.ID) (memberDirectorySnapshot, error) {
	if err := identity.Authorize(principal, identity.NeedAuthenticated); err != nil {
		s.log.Warn("玩家目錄請求被拒：主體未通過認證", "subject", principal.String())
		return memberDirectorySnapshot{}, err
	}
	if principal.Kind() != identity.KindAccount || principal.AccountID().IsNil() {
		// Root 與系統主體在 accounts 表裡沒有可指向的成員行，也不該被當成「某個玩家」：
		// 與「查無此人」同一句話（口徑同 selfselect.go）。管理面另有自己的通路。
		return memberDirectorySnapshot{}, ErrMemberNotFound
	}
	if activityID.IsNil() {
		return memberDirectorySnapshot{}, ErrActivityNotFound
	}

	a, err := s.readActivity(ctx, q, activityID)
	if err != nil {
		return memberDirectorySnapshot{}, err
	}
	isManager, err := s.isActivityManager(ctx, q, principal, activityID)
	if err != nil {
		return memberDirectorySnapshot{}, err
	}
	viewer := DirectoryViewer{IsManager: isManager}
	own, err := s.store.MemberByAccount(ctx, q, activityID, principal.AccountID())
	switch {
	case err == nil:
		// 被禁止使用該活動訪問資格的人，在玩家族目錄前同樣被擋（2043）：
		// 這一族讀法使用的是「他在這場活動裡的成員身份」，管理視角不是一張豁免牌——
		// 他要以管理身份看名冊，走的是 /admin 那側由伺服器級授予判定的通路。
		if err := checkMemberActivityAccess(own); err != nil {
			return memberDirectorySnapshot{}, err
		}
		viewer.MemberID = own.ID
		viewer.FactionID = own.FactionID
	case errors.Is(err, ErrMemberNotFound):
		// 他不是這場活動的成員：只有兩道管理閘都過才繼續（管理視角看全部成員），
		// 否則與「從未存在這場活動」同一句話。
		if !isManager {
			return memberDirectorySnapshot{}, ErrMemberNotFound
		}
	default:
		return memberDirectorySnapshot{}, err
	}

	rows, err := s.store.Members(ctx, q, activityID)
	if err != nil {
		s.log.Error("讀取目錄候選名冊失敗", "activity", activityID.String(), "err", err)
		return memberDirectorySnapshot{},
			fmt.Errorf("activity: 讀取目錄候選名冊失敗: %w", err)
	}
	factions, err := s.store.Factions(ctx, q, activityID)
	if err != nil {
		s.log.Error("讀取目錄候選陣營清單失敗", "activity", activityID.String(), "err", err)
		return memberDirectorySnapshot{},
			fmt.Errorf("activity: 讀取目錄候選陣營清單失敗: %w", err)
	}
	candidates := make([]memberDirectoryCandidate, 0, len(rows))
	for _, row := range rows {
		admin, err := s.adminIdentityOf(ctx, q, row.AccountID)
		if err != nil {
			return memberDirectorySnapshot{}, err
		}
		member := row
		member.AdminIdentity = admin
		candidate := memberDirectoryCandidate{subject: DirectorySubject{Member: member}}
		if display, ok := factionDisplayOf(factions, row.FactionID); ok {
			candidate.factionName = display.name
			candidate.factionIcon = display.icon
			candidate.factionColor = display.color
			candidate.factionAvailable = display.available
		}
		candidates = append(candidates, candidate)
	}
	// 狀態投影與名冊、本人資料共用同一份填寫：顯示名稱覆蓋與自訂定義一次讀齊，
	// 於是列表那一行與點進去那一份不可能各說一套。
	pointers := make([]*Member, len(candidates))
	for i := range candidates {
		pointers[i] = &candidates[i].subject.Member
	}
	if err := s.fillMemberStatus(ctx, q, pointers); err != nil {
		return memberDirectorySnapshot{}, err
	}
	return memberDirectorySnapshot{
		viewer: viewer, activity: a, candidates: candidates, factions: factions,
	}, nil
}

// isActivityManager 回答「這個主體是不是這場活動的管理人」，而且只回一句話：
// 兩道閘（NeedServerAdmin 加上這個活動的一行指派）都過才是 true。
//
// 它與 requireActivityScope 的分別是「被拒時給誰聽」：後者在被拒時就要把那個結論當成
// 對外的不可分辨答案；而目錄一讀需要先知道結論，才能決定「非成員還能不能繼續（管理視角）」，
// 於是判定條件逐字複用同一個來源（grantsOf 與 AuthorizeActivityScope），
// 只在被拒時回 false 而不是回一個會被誤當權限答案的錯誤。
// 主體不合法或指派資料讀不到屬缺陷，仍要老實回報：把缺陷讀成「他不是管理人」會讓一次
// 指派表故障變成靜默的降權，反之讀成「他是」更是直接提權——兩邊都不可接受。
func (s *Service) isActivityManager(ctx context.Context, q database.Querier,
	principal identity.Principal, activityID idgen.ID) (bool, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		if errors.Is(err, identity.ErrPermissionDenied) {
			// 他屬於普通玩家這個身份面：目錄完全按活動那一側的模式回答他。
			return false, nil
		}
		return false, err
	}
	granted, err := s.grantsOf(ctx, q, principal)
	if err != nil {
		return false, err
	}
	if err := identity.AuthorizeActivityScope(principal, activityID, granted); err != nil {
		if errors.Is(err, identity.ErrPermissionDenied) {
			// 持有 server_admin 但這個活動不歸他管：目錄裡他和普通成員讀到的一模一樣。
			// 這一句就是「伺服器級管理員不等於所有活動的管理員」在玩家目錄上的落地。
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// adminIdentityOf 回答「這個帳戶此刻是否持有 server_admin 授予」。
//
// 判據只有 internal/grant 這一處（用戶批准於本步：不按昵稱、顯示名或前端標記猜）：
// 查無授予就是「他不是」，而其他失敗原樣上拋。把資料庫故障降級成「他不是」會在一次
// 故障裡把 all_players_except_admin 該收起來的人放大成可見，那是本檔唯一不許犯的錯誤方向。
func (s *Service) adminIdentityOf(ctx context.Context, q database.Querier,
	accountID idgen.ID) (bool, error) {
	if accountID.IsNil() {
		return false, nil
	}
	if _, err := s.grants.GrantedAt(ctx, q, accountID, identity.RoleServerAdmin); err != nil {
		if errors.Is(err, grant.ErrNotFound) {
			return false, nil
		}
		s.log.Error("讀取目錄行的授予失敗", "account", accountID.String(), "err", err)
		return false, fmt.Errorf("activity: 讀取目錄行的授予失敗: %w", err)
	}
	return true, nil
}

// directoryFacets 從「已授權篩選」的結果集分組出篩選候選，並以這場活動的陣營清單定序
// （排序值、建立時刻、標識，與陣營列表同序）。
//
// 尚未分組的那些行不是一個候選：無陣營不是一個群體（用戶批准於本步），把它們列成一項
// 等於在介面上把那群人命名成「一個組」，而那句命名從來不是批准過的規則。
// 計數一律取自已授權篩選後的行，而不是庫中的總行數：否則界面會拿到一個能探到
// 「別人那邊有幾個人」的數字，而那正是模式要擋掉的事。
func directoryFacets(factions []Faction, allowed []memberDirectoryCandidate) []DirectoryFacet {
	counts := make(map[string]int64, len(allowed))
	for _, candidate := range allowed {
		if candidate.subject.Member.FactionID.IsNil() {
			continue
		}
		counts[candidate.subject.Member.FactionID.String()]++
	}
	out := make([]DirectoryFacet, 0, len(counts))
	for _, faction := range factions {
		count, ok := counts[faction.ID.String()]
		if !ok || count == 0 {
			continue
		}
		out = append(out, DirectoryFacet{
			FactionID: faction.ID, Name: faction.Name, Icon: faction.Icon,
			Color: faction.Color, Count: count,
		})
		if len(out) >= DirectoryFactionFilterMax {
			break
		}
	}
	return out
}

// item 把一行候選換成對外的投影（白名單見 DirectoryMember）。
func (c memberDirectoryCandidate) item() DirectoryMember {
	member := directoryItemOf(c.subject.Member)
	member.FactionName = c.factionName
	member.FactionIcon = c.factionIcon
	member.FactionColor = c.factionColor
	member.FactionAvailable = c.factionAvailable
	return member
}

// directoryItemOf 從一行成員湊出不帶陣營展示值的投影：三處讀法（目錄、詳情、本人）
// 共用同一份欄位清單，於是「列表裡那一行的欄位」與「點進去那一份的欄位」不可能各長一套。
//
// 這一格也決定了什麼永遠不出去：AccountID、DisplayName、AccountStatus、AdminIdentity
// 與任何帳戶內部形態都不在清單內（管理面要那些走 /admin 名冊，那道閘不同）。
func directoryItemOf(member Member) DirectoryMember {
	return DirectoryMember{
		MemberID:          member.ID,
		Nickname:          member.Nickname,
		FactionID:         member.FactionID,
		JoinedAt:          member.JoinedAt,
		BusinessStatus:    member.BusinessStatus,
		CustomStatusID:    member.CustomStatusID,
		CustomStatusName:  member.CustomStatusName,
		StatusDisplayName: member.StatusDisplayName,
		StatusAvailable:   member.StatusAvailable,
	}
}

// factionDisplay 是一個陣營的展示事實：三值加上那一欄停用旗標的現值。
type factionDisplay struct {
	name      string
	icon      string
	color     string
	available bool
}

// factionDisplayOf 在清單裡找那個陣營的展示值；零值標識（尚未分組）回 false。
//
// 找不到時回 false 而不是報錯：行帶了歸屬而清單讀不到對應的陣營屬資料形態缺陷，
// 但目錄的職責是如實說「這一行的歸屬我讀不到展示值」（介面顯示通用句），
// 不是因為一次展示值缺失就把整個可見性判死（口徑同名冊對顯示名的處理）。
//
// 旗標跟著展示值一起出去，是因為三處讀法（目錄、詳情、本人）都要能說出同一句
// 「他所屬的那個陣營此刻是停用的」，而這個倉庫今日沒有別的地方能讓他們湊出這句話：
// 目錄與本人的投影裡沒有陣營清單。它不構成新信號——同一個現值在
// GET／HEAD /player/activities/{id}/faction 的選項清單裡對任何成員都是逐陣營敞開的。
func factionDisplayOf(factions []Faction, id idgen.ID) (factionDisplay, bool) {
	if id.IsNil() {
		return factionDisplay{}, false
	}
	for _, faction := range factions {
		if faction.ID == id {
			return factionDisplay{
				name: faction.Name, icon: faction.Icon, color: faction.Color,
				available: faction.Available,
			}, true
		}
	}
	return factionDisplay{}, false
}

// nicknameMatchesKeyword 回答關鍵字是否命中一行暱稱：剔除首尾空白後做子字串比對，
// 大小寫只在 ASCII 範圍內折疊（與 SQLite 對非 ASCII 逐字相等比對的 LIKE 同一口徑）。
//
// 比對的是活動內暱稱，不是帳戶顯示名——後者從不進這份投影，因此也不可能被搜出來。
func nicknameMatchesKeyword(nickname, keyword string) bool {
	return strings.Contains(foldASCIILower(nickname), foldASCIILower(keyword))
}

// foldASCIILower 只把 ASCII 大寫字母換成小寫，其餘位元組原樣保留。
//
// 不直接用 strings.ToLower 的理由只有一個：Unicode 的大小寫規則會把某些字元折成
// 不同長度或不同碼位，而同一個詞在列表與搜尋之間換了寫法，比「搜不到」更難解釋。
func foldASCIILower(value string) string {
	out := []byte(value)
	for i, b := range out {
		if b >= 'A' && b <= 'Z' {
			out[i] = b + ('a' - 'A')
		}
	}
	return string(out)
}

// 目錄用例不碰的任何東西（寫在這裡是為了讓下次加欄位時先看見邊界）：
// 它不讀也不寫帳戶的登入名、口令形態與狀態；不判定「他在活動裡能做什麼」
// （活動內角色尚未落地）；不包含 NPC 的目錄與它那套獨立授權；
// 也不提供任何一格能讓呼叫端宣稱「用管理視角給我全部人」。
