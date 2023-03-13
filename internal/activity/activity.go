// Package activity 提供活動實體的領域模型、生命週期狀態機、活動管理人的指派倉儲，
// 以及「建立／查詢／編輯／轉換狀態／指派管理人」這組用例。
//
// 本套件屬應用服務層與領域層的交界（根 AGENTS.md §6）：它認得資料庫交易與審計倉儲，
// 但不認得 HTTP 請求物件、不認得任何 Flutter 物件，也不自己開第二套權限語意。
//
// 這一步落地的是「活動」這件事的輪廓，不是活動裡的業務：
//   - 已落地：活動實體（穩定標識、名稱、描述、四態生命週期、建立者留痕）、
//     活動管理權的持久來源（activity_manager_grants，補上 R1-006 留下的「落庫來源」空位）、
//     活動作用域的授權判定（經 identity.AuthorizeActivityScope 這一處）、
//     活動域的審計寫入（audit.ScopeActivity），以及留給後續模組複用的「業務寫入門禁」判定；
//   - 未落地、本套件也不冒充：成員身份與活動內暱稱（Membership／Profile）、
//     玩家在活動裡能做什麼（那是活動內角色，不是管理權）、陣營／資產／聊天等業務面。
//     因此這裡沒有任何一處把「他是不是玩家」「他能不能發言」寫成判斷——
//     那些問題的答案現在還不存在，早寫一個就是拿推測冒充合同。
//
// 三條寫在結構上的規定：
//   - 標識是身份，名稱不是。id 由 idgen 產生、資料庫用觸發器擋住就地改寫（見遷移 0012）；
//     名稱可以重複、可以改，跨活動同名彼此無關。所有「指向某個活動」的輸入都是 id，
//     沒有任何一條通路能用名稱找到或改動一個活動。
//   - 管理權只能查，不能自報。主體是不是這個活動的管理人，判定只經
//     identity.AuthorizeActivityScope，輸入的指派清單只來自本套件的倉儲讀法；
//     請求本體沒有欄位能宣告「我是這個活動的管理人」，也沒有欄位能指定「動哪個帳戶」（
//     目標由路徑引數給，且一律先核實在可見範圍內）。
//   - 每一次成功寫入都與它的審計同生同滅。寫入與 audit.Append 落在同一個
//     database.Tx 裡，審計寫不進去則整個活動改動作廢——「存在卻在活動審計裡查不到的改動」
//     與「審計說有而資料庫查不到」同罪。被拒的動作不記審計（與帳戶側各條寫入通路同口徑）。
//
// 時刻唯一來源是注入的 timeutil.Clock（DEC-015）：呼叫端無權代填「何時建立」「何時歸檔」，
// 也不採信請求內容提供的時間。零值 Service 不可用，請經 New 取得。
package activity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// 生命週期的四個狀態（用戶批准於本步：四態，停止可逆、歸檔終態）。
//
// 值與遷移 0012 的 CHECK 封閉集合逐字相同：兩側各寫一份時以資料庫那份為最終把關，
// 這裡先擋是為了給出可判讀的錯誤與可判別的處置。新增取值一律走新的遷移放寬清單，
// 這樣「活動能處於什麼形態」的改變必然在版本史上留痕。
type Status string

const (
	// StatusDraft 是草稿：已建立、尚未開放，允許準備業務資料。
	StatusDraft Status = "draft"
	// StatusActive 是開放：正常進行中。
	StatusActive Status = "active"
	// StatusClosed 是停止：業務寫入一律拒絕，但可以回到開放（與帳戶「停用」同一取向）。
	StatusClosed Status = "closed"
	// StatusArchived 是歸檔：終態，不可逆，一律拒寫；行仍列、仍可讀。
	StatusArchived Status = "archived"
)

// String 回傳狀態的機器表示（與資料庫欄位值同形）。
func (s Status) String() string { return string(s) }

// valid 回報狀態是否落在封閉集合內。
func (s Status) valid() bool {
	switch s {
	case StatusDraft, StatusActive, StatusClosed, StatusArchived:
		return true
	}
	return false
}

// ParseStatus 解析資料庫欄位或請求引數為狀態。
//
// 未知的取值回報 ErrInvalidStatus：它屬「這個值不存在，改寫法再來」，
// 與「這個值存在但此刻輪不到你」是兩類結論，不可混為權限不足。
func ParseStatus(value string) (Status, error) {
	s := Status(value)
	if !s.valid() {
		return "", fmt.Errorf("%w：不認識的活動狀態 %q（僅 draft|active|closed|archived）",
			ErrInvalidStatus, value)
	}
	return s, nil
}

// AllowsBusinessWrites 回報這個狀態是否接受活動內業務資料的寫入。
//
// 草稿與開放允許：陣營、成員名單這些東西本來就該能在開放前準備好。
// 停止與歸檔拒絕：停止是「這件事暫停，不再新增」，歸檔是「這件事結束，一概不動」。
// 兩者的差別在於停止可逆、歸檔不可逆，這一差別表現在「能不能再改狀態」上（見 canReach）。
func (s Status) AllowsBusinessWrites() bool {
	return s == StatusDraft || s == StatusActive
}

// Terminal 回報狀態是否已是終態（一律拒寫，且不再有任何合法轉換出口）。
func (s Status) Terminal() bool { return s == StatusArchived }

// canReach 回報「從這個狀態能否走到那個狀態」。
//
// 合法路徑只有四條（用戶批准於本步）：
//   - draft → active（開放）
//   - active → closed（停止）
//   - closed → active（重新開放：停止不是刪除，恢復的只是「這件事還能繼續發生」）
//   - draft|active|closed → archived（歸檔，終態）
//
// 同態重複（把已開放的再開放一次）不在這裡回答：它的現值本來就等於目標值，
// 誠實的答案是「沒有可發生的物件」，屬狀態衝突那一類（見 Transition 的處置），
// 而不是「這條路不存在」。
// 歸檔的出口一條都沒有：archived 到任何狀態都是非法，而本套件在問路徑之前先答終態。
func (s Status) canReach(target Status) bool {
	if !s.valid() || !target.valid() {
		return false
	}
	switch target {
	case StatusActive:
		return s == StatusDraft || s == StatusClosed
	case StatusClosed:
		return s == StatusActive
	case StatusArchived:
		return s != StatusArchived
	default:
		// draft 只能由「建立活動」那一跳產生，不是一條轉換的目的地。
		return false
	}
}

// Activity 是一個活動的可展示事實（詳情、建立結果與轉換結果共用同一個形狀）。
//
// 不含也不該有的東西：建立者的登入名或憑據材料、活動內的玩家名單、任何推測出來的
// 「他能不能做這件事」。Roles／權限判定從不進這個結構——它是事實的投影，不是授權的載體。
type Activity struct {
	// ID 為活動穩定標識。
	ID idgen.ID
	// Name 為活動名稱（可重複、可改；身份只有 ID）。
	Name string
	// Description 為活動描述（可為空字串，意即「沒有寫過描述」）。
	Description string
	// Status 為當前生命週期狀態。
	Status Status
	// CreatedByAccountID 為建立者的帳戶標識（無外鍵軟參照，口徑同審計表）。
	// Root 建立的活動這一格是零值：Root 不在 accounts 表裡，不拿保留標識冒充帳戶。
	CreatedByAccountID idgen.ID
	// ManagerCount 是此刻持有該活動管理權的帳戶數（含建站時自動指派的建立者）。
	// 目錄與詳情都帶這一格：它回答「這件事有幾個人能管」，而不需要另開一條名冊讀法。
	ManagerCount int64
	// CreatedAt 為建立時刻（UTC）。
	CreatedAt time.Time
	// UpdatedAt 為最後一次改動時刻（資料編輯與狀態轉換都算；UTC）。
	UpdatedAt time.Time
	// ArchivedAt 為進入歸檔終態的時刻；非歸檔態恆為零值。
	ArchivedAt time.Time
}

// 用例的可判別結論。分類原則與帳戶側同一套：正常會發生的安全事件、
// 可預期的業務衝突、請求寫法錯誤三者各自成句，內部故障不進這些型別。
var (
	// ErrActivityNotFound 表示這個活動不在呼叫者的可見範圍內：它可能從未存在，
	// 也可能存在但不是這個主體所管的活動——兩種情況一律同一個答案。
	//
	// 刻意不分成「查無活動」與「你管不著它」：後者等於向任何一個敲得動端點的人
	// 承認「這個標識確實是一個活動」。標識是 UUIDv7，同形不損失任何合法性，
	// 卻少了一枚可列舉的信號（與帳戶目錄把「不存在」與「不在這本目錄」收斂同一句話同一取向）。
	ErrActivityNotFound = errors.New("activity: 該活動不在可見範圍內")
	// ErrArchived 表示目標已是歸檔終態：本次寫入整個沒有可發生的物件——
	// 狀態沒改、資料沒動、審計沒記。
	//
	// 它與 ErrStatusConflict 分開只為處置不同：一個是「你依據的現值已過期，重讀之後
	// 那顆按鈕還可以再按一次」，另一個是重讀之後的答案是「這件事已經結束了」，
	// 再按一次不會讓歸檔被撤銷。它也不降級成 ErrActivityNotFound：
	// 能讀到這個活動的人本來就知道它存在，把終態報成不存在是誤導操作者換目標。
	ErrArchived = errors.New("activity: 活動已歸檔，一律拒寫")
	// ErrActivityClosedWrites 是留給後續業務模組的門禁結論：活動處於停止態時，
	// 活動內的業務寫入一律拒絕。
	//
	// 本步沒有一條端點走它（陣營、成員、資產尚未落地，今日也沒有「停下來之後
	// 還有人要改活動內東西」的通路），因此本步刻意不為它發布機器錯誤碼——
	// 發一枚用不到的碼等於給未來留一個語意還沒被驗過的出口。
	ErrActivityClosedWrites = errors.New("activity: 活動已停止，不接受業務寫入")
	// ErrStatusConflict 表示本次狀態轉換所依據的現值已不是資料庫現值：整個轉換沒有發生。
	//
	// 它是可預期的併發與重複結論而不是故障：兩個人對著同一份畫面先後點「停止」，
	// 後到的那個必然發現「你確認時它還活著，現在已經不是了」——正確性來自帶 WHERE 的
	// 單向 UPDATE，而不是先查後寫那個視窗。同態重複（把已停止的再停止一次）也收斂到這裡，
	// 不謊報成功：把「什麼都沒發生」說成「又停止了一次」，審計與真相就對不上。
	ErrStatusConflict = errors.New("activity: 活動狀態現值已與提交時所依據的不同")
	// ErrInvalidTransition 表示這條路徑本身不存在（如把草稿直接「停止」）。
	//
	// 它與 ErrStatusConflict 分開是因為處置不同：重讀現值對這條沒有幫助——
	// 就算現值如操作者所見，這個狀態也到不了那個狀態；要改的是意圖，不是畫面。
	// 換個身分辨不成這件事，因此它也不是權限問題。
	ErrInvalidTransition = errors.New("activity: 該活動狀態沒有這條轉換路徑")
	// ErrProfileConflict 表示編輯活動資料所依據的現值已不是資料庫現值：整個編輯沒有發生。
	//
	// 處置與帳戶資料編輯同形：重讀服務端現值再決定，而不是拿手上那份再存一次。
	// 回應不回顯雙方的值——那是重讀詳情本來就該拿到的資料。
	ErrProfileConflict = errors.New("activity: 活動資料現值已與提交時所依據的不同")
	// ErrManagerNotFound 表示要指派的目標帳戶不在管理員目錄中（不存在、或從未持有
	// server_admin 授予），或要撤銷的指派本來就不存在。兩者對呼叫端是同一句話：
	// 「這一對（活動, 帳戶）沒有可發生動作的行」。
	ErrManagerNotFound = errors.New("activity: 該帳戶不在可指派的範圍內")
	// ErrManagerDeleted 表示目標是已被軟刪除的管理員帳戶：終態仍列、仍可讀、一律拒寫。
	//
	// 它與 ErrManagerNotFound 分開是因為處置不同：一個是「換個目標」，另一個是
	// 「你眼前這個人都已經被刪掉了，別再對他下任何寫入令」。
	ErrManagerDeleted = errors.New("activity: 目標帳戶已被軟刪除")
	// ErrManagerDuplicate 表示這個帳戶已經是該活動的管理人：本次指派整個沒有發生。
	//
	// 重複指派不謊報成功——那會在審計裡記下一件沒發生過的事。主鍵 (activity_id, account_id)
	// 是這句話的結構保證，先查後插只是友善錯誤來源。
	ErrManagerDuplicate = errors.New("activity: 該帳戶已是此活動的管理人")
	// ErrInvalidStatus 表示傳來的狀態取值不在封閉集合內（改寫法就能解決）。
	ErrInvalidStatus = errors.New("activity: 活動狀態取值不合法")
	// ErrInvalidName 表示活動名稱不符合領域規則（空白、超長、含控制或格式字元）。
	ErrInvalidName = errors.New("activity: 活動名稱不合法")
	// ErrInvalidDescription 表示活動描述不符合領域規則（超長、含控制或格式字元）。
	ErrInvalidDescription = errors.New("activity: 活動描述不合法")
	// ErrInvalidPage 表示分頁引數 page 不在 1..上限。
	ErrInvalidPage = errors.New("activity: 分頁引數 page 不合法")
	// ErrInvalidPageSize 表示分頁引數 page_size 不在 1..上限。
	ErrInvalidPageSize = errors.New("activity: 分頁引數 page_size 不合法")
	// ErrInvalidStatusFilter 表示目錄的狀態篩選取值不在集合內。
	ErrInvalidStatusFilter = errors.New("activity: 狀態篩選不合法")
	// ErrInvalidKeyword 表示目錄關鍵字剔除首尾空白後仍超長。
	ErrInvalidKeyword = errors.New("activity: 目錄關鍵字不合法")
)

// 名稱與描述的邊界（碼位計，與 SQLite length() 同口徑，也和遷移 0012 的 CHECK 同值）：
// 名稱上界沿用帳戶顯示名的 64；描述給到 500，與審計 reason 的上界同一個尺度——
// 兩邊都是「給人讀的一句話到一段話」，不讓其中一處單獨漂移。
const (
	// maxNameRunes 是活動名稱的碼位上限。
	maxNameRunes = 64
	// maxDescriptionRunes 是活動描述的碼位上限。
	maxDescriptionRunes = 500
)

// validateName 校驗並正規化活動名稱：剔除首尾空白後必須非空、不超長、且不含控制或格式字元。
//
// 為什麼不在此做唯一性檢查：名稱不是身份鍵（見套件頭注），跨活動同名完全合法。
// 給它加唯一約束會把「兩個活動都叫同一個名字」變成寫不進去的錯誤，
// 那是把名稱當外鍵用的開頭。
func validateName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("%w：不可為空", ErrInvalidName)
	}
	if count := utf8.RuneCountInString(name); count > maxNameRunes {
		return "", fmt.Errorf("%w：長度不可超過 %d 個字元，實際 %d", ErrInvalidName, maxNameRunes, count)
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", fmt.Errorf("%w：不得含控制或格式字元（U+%04X）", ErrInvalidName, r)
		}
	}
	return name, nil
}

// validateDescription 校驗活動描述：允許空字串（語意是「沒有寫過描述」，不是「描述是空的」），
// 但不剝內部空白——描述是一段給人讀的話，換行與縮排屬於它。
func validateDescription(raw string) (string, error) {
	description := strings.TrimSpace(raw)
	if description == "" {
		return "", nil
	}
	if count := utf8.RuneCountInString(description); count > maxDescriptionRunes {
		return "", fmt.Errorf("%w：長度不可超過 %d 個字元，實際 %d",
			ErrInvalidDescription, maxDescriptionRunes, count)
	}
	for _, r := range description {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return "", fmt.Errorf("%w：不得含控制字元（U+%04X）", ErrInvalidDescription, r)
		}
		if unicode.Is(unicode.Cf, r) {
			return "", fmt.Errorf("%w：不得含格式字元（U+%04X）", ErrInvalidDescription, r)
		}
	}
	return description, nil
}

// trimRequestID 把關聯 ID 裁到審計欄位上界（64 碼位）以內。
//
// 截斷而不是報錯：關聯 ID 是追溯用的附加資訊，它超長不該讓一次已成功的寫入翻臉。
func trimRequestID(requestID string) string {
	if r := []rune(requestID); len(r) > 64 {
		return string(r[:64])
	}
	return requestID
}

// grantsOf 把「這個主體管著哪些活動」換成 identity 的承載型別。
//
// 它是本套件內唯一讀取指派清單的地方：目錄的可見範圍、詳情與各條寫入路徑的作用域判定
// 都經此處取得同一份事實，於是「他能看見哪些活動」與「他能在哪些活動上做事」
// 不是兩套可能各說各話的查詢。
func (s *Service) grantsOf(ctx context.Context, q database.Querier,
	principal identity.Principal) (identity.ActivityGrants, error) {
	if principal.IsRoot() {
		// Root 不需要指派清單：它的權限不來自活動（見 identity.AuthorizeActivityScope）。
		// 給它一份空清單反而會被 audit.Viewer 的校驗拒（Root 的 Activities 應留空），
		// 所以這裡直接回零值承載。
		return identity.ActivityGrants{}, nil
	}
	ids, err := s.store.ManagedActivityIDs(ctx, q, principal.AccountID())
	if err != nil {
		return identity.ActivityGrants{}, err
	}
	granted, err := identity.NewActivityGrants(ids...)
	if err != nil {
		// 指派表裡讀出零值標識屬資料缺陷，不能降級成「他什麼都管不了」：
		// 後者會把一次寫壞的行變成一個安靜失效的管理人。
		return identity.ActivityGrants{}, fmt.Errorf("activity: 指派清單不合法: %w", err)
	}
	return granted, nil
}

// requireActivityScope 是「這個主體能不能在這個活動上動管理動作」的唯一判定點。
//
// 兩道閘都要過，缺一不可（理由見 identity.AuthorizeActivityScope 頭注）：
//
//	NeedServerAdmin 回答「他屬於管理員這個身份面嗎」，活動作用域判定回答
//
// 「這個資格在這個活動上認不認得他」。
//
// 拒絕的結論一律收斂成 ErrActivityNotFound：被拒的人拿不到「這個標識確實是一個活動」
// 這條資訊，也拿不到「你差哪一半」的可列舉信號。
func (s *Service) requireActivityScope(ctx context.Context, q database.Querier,
	principal identity.Principal, activityID idgen.ID, requestTag string) error {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		s.log.Warn("活動管理動作被拒：主體不具備伺服器級管理權",
			"subject", principal.String(), "entry", requestTag)
		return err
	}
	if activityID.IsNil() {
		return ErrActivityNotFound
	}
	granted, err := s.grantsOf(ctx, q, principal)
	if err != nil {
		return err
	}
	if err := identity.AuthorizeActivityScope(principal, activityID, granted); err != nil {
		if errors.Is(err, identity.ErrPermissionDenied) {
			// 不是這個活動管理人 ≠ 沒有這個活動——但對外只許有後一句話。
			return ErrActivityNotFound
		}
		return err
	}
	return nil
}
