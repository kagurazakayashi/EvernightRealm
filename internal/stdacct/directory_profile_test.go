// directory_profile_test.go 是「管理員打理普通帳戶」的查詢與編輯側證據：目錄範圍、
// 分頁與三種篩選、詳情與編輯的目標類型檢查、白名單與併發、審計歸屬，
// 全部走真資料庫＋真用例＋注入時鐘。
//
// 刻意不收的東西：
//   - 沒有替身：授權、範圍核實、CAS、審計都跨層走真路徑，接錯線就會紅；
//   - 不碰任何真實資料目錄、不佔 5206，全程用本次專屬的暫存庫與注入時鐘。
package stdacct

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// seedInput 是種入一筆帳戶時要指定的形態（本檔多數用例需要非默認形態：訪客、停用、管理員）。
type seedInput struct {
	// Login 為登入名原始寫法。
	Login string
	// Display 為顯示名。
	Display string
	// Type 為來源類型；留空視為 standard。
	Type account.Type
	// Status 為狀態；留空視為 active。disabled 會自動補上注入時鐘的停用時刻。
	Status account.Status
	// Admin 表示建完後補一筆 server_admin 授予（把這筆變成「不該出現在普通帳戶目錄」的人）。
	Admin bool
	// Deleted 表示建完後經倉儲寫入刪除終態。刪除自有應用層通路（見 deleted.go），
	// 但夾具要的是「目錄與每一條寫入通路面對已存在終態行時的答案」，
	// 由倉儲直接種出來比走一遍用例更穩定（不把夾具綁在某條通路的現值上）。
	Deleted bool
	// Retired 表示建完後經倉儲寫入綁定退休終態（只有訪戶可以是這個形態）。
	// 它同樣是「種」而不是「綁」：本檔要量的是各條通路面對退休行的回答，
	// 而不是綁定那一步自己（那有 bindexecute_test.go 負責）。
	Retired bool
}

// seed 種入一筆帳戶並回傳實體。
//
// 用倉儲而不是建立用例：本檔要的是「目錄讀到的行長什麼樣」，
// 而建立用例只產得出 standard＋active 這一种形態，訪客與停用得直接種。
func (e *env) seed(t *testing.T, in seedInput) account.Account {
	t.Helper()
	ctx := context.Background()
	typ := in.Type
	if typ == "" {
		typ = account.TypeStandard
	}
	status := in.Status
	if status == "" {
		status = account.StatusActive
	}
	hash := ""
	if typ == account.TypeStandard {
		derived, err := credential.Hash(testInitialPassword, credential.TestParams)
		if err != nil {
			t.Fatalf("產生測試憑據失敗：%v", err)
		}
		hash = derived
	}
	created, err := e.service.accounts.Create(ctx, e.db.SQL(), account.NewInput{
		LoginName:          in.Login,
		DisplayName:        in.Display,
		PasswordHash:       hash,
		Type:               typ,
		Status:             status,
		MustChangePassword: typ == account.TypeStandard,
		DisabledAt:         disabledAtFor(status, e.clock.Now()),
	})
	if err != nil {
		t.Fatalf("種入帳戶 %s 失敗：%v", in.Login, err)
	}
	if in.Admin {
		if err := e.service.grants.Grant(ctx, e.db.SQL(), created.ID, identity.RoleServerAdmin); err != nil {
			t.Fatalf("補上授予失敗：%v", err)
		}
	}
	if in.Deleted {
		ok, err := e.service.accounts.MarkDeleted(ctx, e.db.SQL(), created.ID, created.DisplayName)
		if err != nil || !ok {
			t.Fatalf("寫入刪除終態失敗：%v（changed=%v）", err, ok)
		}
	}
	if in.Retired {
		// 與 RetireGuestForBind 同形的單條 UPDATE：退休態與退休時刻同生，
		// 由注入時鐘給時刻（不拿零值或系統時間湊數）。
		res, err := e.db.SQL().ExecContext(ctx,
			"UPDATE accounts SET status = ?, retired_at = ? WHERE id = ? AND account_type = ?",
			string(account.StatusRetired), timeutil.ToMillis(e.clock.Now()),
			created.ID.String(), account.TypeGuest.String())
		if err != nil {
			t.Fatalf("寫入退休終態失敗：%v", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			t.Fatalf("退休終態應恰好命中一行（n=%d）：%v", n, err)
		}
	}
	return created
}

// disabledAtFor 依狀態補禁用時刻：域規則要求 disabled 與 disabled_at 同生同滅，
// 這個配對在測試夾具裡也必须由同一個時鐘給出，不拿零值或系統時間湊數。
func disabledAtFor(status account.Status, now time.Time) time.Time {
	if status == account.StatusDisabled {
		return now
	}
	return time.Time{}
}

// TestDirectoryAndProfileRequireServerAdmin 授權矩陣：普通帳戶、訪戶帳戶、系統主體與
// 匿名主體對目錄、詳情與編輯三個入口一律被拒，且零寫入零審計。
//
// 這是「普通用戶和訪客不能枚舉全站賬戶」在服務層的钉子：讀目錄這條路本身就只有
// 管理員走得通，不需要靠界面藏起按鈕。
func TestDirectoryAndProfileRequireServerAdmin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	target := e.seed(t, seedInput{Login: "scope.target", Display: "被看的"})
	phantom := identitytest.NewID(t)

	// 先種一筆，確保「空目錄」不構成本檔的僥倖：被拒的主體連一行都讀不到。
	if n := countRows(t, e.db, "accounts"); n != 1 {
		t.Fatalf("測試前提：應有一筆可被讀到的帳戶，實際 %d", n)
	}
	for name, principal := range map[string]identity.Principal{
		"普通帳戶": identitytest.Account(t, identitytest.NewID(t)),
		"訪客帳戶": identitytest.Account(t, identitytest.NewID(t), identitytest.WithGuestType()),
		"系統主體": identitytest.System(t, identity.OriginCLI),
		"匿名主體": identity.Anonymous(),
	} {
		if _, err := e.service.Directory(ctx, principal, DirectoryQuery{
			Page: 1, PageSize: DirectoryDefaultPageSize,
		}); !isDenied(err) {
			t.Errorf("%s 讀目錄應被拒，實際 %v", name, err)
		}
		if _, err := e.service.StandardAccountProfile(ctx, principal, target.ID); !isDenied(err) {
			t.Errorf("%s 讀詳情應被拒，實際 %v", name, err)
		}
		if _, err := e.service.UpdateStandardAccountProfile(ctx, principal, target.ID,
			"改個名", "被看的", "req-deny"); !isDenied(err) {
			t.Errorf("%s 編輯資料應被拒，實際 %v", name, err)
		}
		if _, err := e.service.StandardAccountProfile(ctx, principal, phantom); !isDenied(err) {
			t.Errorf("%s 對幽靈標識也必須先被拒（不得用 1001 洩漏存在性），實際 %v", name, err)
		}
	}
	for _, table := range []string{"accounts", "root_audit", "account_server_roles"} {
		expect := map[string]int{"accounts": 1}[table]
		if n := countRows(t, e.db, table); n != expect {
			t.Errorf("被拒的讀取與編輯不得改動 %s（應 %d 行，實際 %d）", table, expect, n)
		}
	}
}

// isDenied 回報錯誤是否為「身分不足／未認證」這一類：四種主體在 Authorize 那一步
// 各自落在兩個結論錯誤之一（匿名是未認證、其餘是權限不足），兩者都是正當拒絕。
func isDenied(err error) bool {
	return errors.Is(err, identity.ErrPermissionDenied) ||
		errors.Is(err, identity.ErrNotAuthenticated)
}

// TestDirectoryScopeExcludesAdminsAndDeleted 目錄範圍：列不帶伺服器級授予的帳戶
// （普通、訪客，以及已進入刪除終態的那一筆），依建立時刻倒序；持有授予者一律不列。
//
// 已刪者列得進來是用戶批准的展示策略（與 /root/admins 同形）：他的行留著正是為了被讀到，
// 而目錄要把「他被刪於何時」一併給出。他列在這兒不等於還能被他做事——那句話由
// 每一條寫入通路的終態判定回答，不在這一頁的 WHERE 裡判第二次。
func TestDirectoryScopeExcludesAdminsAndDeleted(t *testing.T) {
	e := newEnv(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	ctx := context.Background()

	// 每種一筆就推進注入時鐘：排序斷言要的是「建立時刻倒序」這件事實，
	// 同一毫秒內的三筆會由標識破平，那不是本測試想證的東西。
	e.clock.Advance(time.Minute)
	plain := e.seed(t, seedInput{Login: "scope.plain", Display: "普通帳戶"})
	e.clock.Advance(time.Minute)
	guest := e.seed(t, seedInput{Login: "scope.guest", Display: "訪客帳戶", Type: account.TypeGuest})
	e.clock.Advance(time.Minute)
	e.seed(t, seedInput{Login: "scope.peer", Display: "另一位管理員", Admin: true})
	e.clock.Advance(time.Minute)
	e.seed(t, seedInput{Login: "scope.peer-off", Display: "停用的管理員", Admin: true,
		Status: account.StatusDisabled})
	e.clock.Advance(time.Minute)
	gone := e.seed(t, seedInput{Login: "scope.gone", Display: "已被刪除的", Deleted: true})

	page, err := e.service.Directory(ctx, admin, DirectoryQuery{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("讀目錄失敗：%v", err)
	}
	if page.Total != 3 || len(page.Rows) != 3 {
		t.Fatalf("目錄應列三位非授予者（含訪客與已刪者），實際 total=%d rows=%d",
			page.Total, len(page.Rows))
	}
	// 倒序：最後種的那一筆（已刪者）在前。這裡要證的恰恰是「已刪不會把他從名冊上抹掉」，
	// 所以順序斷言按三筆來量，而不是把他當成不存在。
	if page.Rows[0].AccountID != gone.ID.String() || page.Rows[1].AccountID != guest.ID.String() ||
		page.Rows[2].AccountID != plain.ID.String() {
		t.Errorf("排序應為建立時刻倒序，實際 %s, %s, %s",
			page.Rows[0].AccountID, page.Rows[1].AccountID, page.Rows[2].AccountID)
	}
	if page.Rows[0].Status != account.StatusDeleted.String() ||
		page.Rows[0].DeletedAt.IsZero() {
		t.Errorf("已刪的那一行要同時帶出狀態與刪除時刻，實際 %+v", page.Rows[0])
	}
	for _, row := range page.Rows[1:] {
		if !row.DeletedAt.IsZero() {
			t.Errorf("未刪除的行不該帶刪除時刻（不拿零值之外的東西冒充）：%+v", row)
		}
	}
	for _, row := range page.Rows {
		if row.AccountType == "" || row.Status == "" || row.LoginName == "" {
			t.Errorf("行必須帶齊來源、狀態與登入名，實際 %+v", row)
		}
	}
	// 秘密不外洩在这一层也要有断言：投影沒有憑據格子，行內容因此不可能帶出雜湊或口令。
	text := fmt.Sprintf("%+v", page.Rows)
	for _, forbidden := range []string{"argon2id", testInitialPassword, "login_name_key", "PasswordHash"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Errorf("目錄行不得含 %q，實際 %s", forbidden, text)
		}
	}
}

// TestDirectoryFiltersAndInvalidParams 三種篩選各自生效、非法參數各自點名。
func TestDirectoryFiltersAndInvalidParams(t *testing.T) {
	e := newEnv(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	ctx := context.Background()

	e.seed(t, seedInput{Login: "filter.alpha", Display: "阿爾法"})
	e.seed(t, seedInput{Login: "filter.beta", Display: "貝塔", Status: account.StatusDisabled})
	e.seed(t, seedInput{Login: "filter.guest", Display: "訪客甲", Type: account.TypeGuest})

	for name, tc := range map[string]struct {
		q     DirectoryQuery
		total int64
	}{
		"不篩選":         {DirectoryQuery{Page: 1, PageSize: 10}, 3},
		"狀態 active":   {DirectoryQuery{Page: 1, PageSize: 10, StatusFilter: "active"}, 2},
		"狀態 disabled": {DirectoryQuery{Page: 1, PageSize: 10, StatusFilter: "disabled"}, 1},
		"類型 guest":    {DirectoryQuery{Page: 1, PageSize: 10, TypeFilter: "guest"}, 1},
		"類型 standard": {DirectoryQuery{Page: 1, PageSize: 10, TypeFilter: "standard"}, 2},
		"類型 all":      {DirectoryQuery{Page: 1, PageSize: 10, TypeFilter: "all"}, 3},
		"狀態 all":      {DirectoryQuery{Page: 1, PageSize: 10, StatusFilter: "all"}, 3},
		// 關鍵字比對顯示名與登入名兩欄，大小寫不敏感（ASCII 段）。
		"關鍵字命中顯示名": {DirectoryQuery{Page: 1, PageSize: 10, Keyword: "貝塔"}, 1},
		"關鍵字命中登入名": {DirectoryQuery{Page: 1, PageSize: 10, Keyword: "ALPHA"}, 1},
		"關鍵字不命中":   {DirectoryQuery{Page: 1, PageSize: 10, Keyword: "查無此名"}, 0},
		"關鍵字全是空白":  {DirectoryQuery{Page: 1, PageSize: 10, Keyword: "   "}, 3},
		// 特殊字元：LIKE 的中間萬用字元必須按字面比對，否則一個 % 就把整個目錄交出去。
		"關鍵字含百分號": {DirectoryQuery{Page: 1, PageSize: 10, Keyword: "100%"}, 0},
		"關鍵字含底線":  {DirectoryQuery{Page: 1, PageSize: 10, Keyword: "a_b"}, 0},
		"關鍵字含反斜線": {DirectoryQuery{Page: 1, PageSize: 10, Keyword: `a\b`}, 0},
		// 篩選可以疊加：狀態與關鍵字同時限定。
		"疊加篩選": {DirectoryQuery{Page: 1, PageSize: 10, StatusFilter: "active", Keyword: "訪客"}, 1},
	} {
		page, err := e.service.Directory(ctx, admin, tc.q)
		if err != nil {
			t.Errorf("%s 讀目錄失敗：%v", name, err)
			continue
		}
		if page.Total != tc.total || int64(len(page.Rows)) != tc.total {
			t.Errorf("%s 應得 %d 筆，實際 total=%d rows=%d", name, tc.total, page.Total, len(page.Rows))
		}
	}

	for name, tc := range map[string]struct {
		q   DirectoryQuery
		err error
	}{
		"頁碼為零":   {DirectoryQuery{Page: 0, PageSize: 10}, ErrInvalidPage},
		"頁碼為負":   {DirectoryQuery{Page: -1, PageSize: 10}, ErrInvalidPage},
		"每頁為零":   {DirectoryQuery{Page: 1, PageSize: 0}, ErrInvalidPageSize},
		"每頁超上限":  {DirectoryQuery{Page: 1, PageSize: DirectoryMaxPageSize + 1}, ErrInvalidPageSize},
		"狀態表外值":  {DirectoryQuery{Page: 1, PageSize: 10, StatusFilter: "ghost"}, ErrInvalidStatusFilter},
		"狀態列待審批": {DirectoryQuery{Page: 1, PageSize: 10, StatusFilter: "pending"}, ErrInvalidStatusFilter},
		"類型表外值":  {DirectoryQuery{Page: 1, PageSize: 10, TypeFilter: "root"}, ErrInvalidTypeFilter},
		"關鍵字過長":  {DirectoryQuery{Page: 1, PageSize: 10, Keyword: strings.Repeat("夜", DirectoryKeywordMaxRunes+1)}, ErrInvalidKeyword},
	} {
		if _, err := e.service.Directory(ctx, admin, tc.q); !errors.Is(err, tc.err) {
			t.Errorf("%s 應回 %v，實際 %v", name, tc.err, err)
		}
	}
}

// TestDirectoryPaginationAndOverflow 分頁翻得完、超界回空頁與真實總數、溢出時短路不查庫。
func TestDirectoryPaginationAndOverflow(t *testing.T) {
	e := newEnv(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		e.clock.Advance(time.Minute)
		e.seed(t, seedInput{Login: fmt.Sprintf("page.p%d", i), Display: fmt.Sprintf("分頁%d", i)})
	}

	seen := map[string]bool{}
	for page := int64(1); page <= 3; page++ {
		got, err := e.service.Directory(ctx, admin, DirectoryQuery{Page: page, PageSize: 2})
		if err != nil {
			t.Fatalf("第 %d 頁失敗：%v", page, err)
		}
		if got.Total != 5 || got.Page != page || got.PageSize != 2 {
			t.Errorf("回顯應為 page=%d size=2 total=5，實際 %+v", page, got)
		}
		for _, row := range got.Rows {
			if seen[row.AccountID] {
				t.Errorf("同一筆出現在兩頁：%s", row.AccountID)
			}
			seen[row.AccountID] = true
		}
	}
	if len(seen) != 5 {
		t.Errorf("三頁應翻完五筆，實際 %d", len(seen))
	}
	// 超出總數的合法頁碼：空行＋真實總數（這不是錯誤，是別人把最後一頁翻空的常態）。
	beyond, err := e.service.Directory(ctx, admin, DirectoryQuery{Page: 9, PageSize: 2})
	if err != nil {
		t.Fatalf("超界頁碼不該是錯誤：%v", err)
	}
	if beyond.Rows == nil || len(beyond.Rows) != 0 || beyond.Total != 5 {
		t.Errorf("超界頁碼應回空切片與真實總數，實際 %+v", beyond)
	}
	// int64 邊界外的頁碼：短路回空頁，不把越界偏移當成一次正當查詢。
	huge, err := e.service.Directory(ctx, admin, DirectoryQuery{Page: int64(^uint64(0) >> 1), PageSize: 2})
	if err != nil {
		t.Fatalf("極大頁碼應短路而非報錯：%v", err)
	}
	if len(huge.Rows) != 0 || huge.Total != 5 {
		t.Errorf("極大頁碼應回空行與真實總數，實際 %+v", huge)
	}
}

// TestStandardProfileScopeMatrix 單筆讀取的目標類型檢查：普通與訪客讀得到，
// 管理員（含另一位與操作者自己）、已刪除者、幽靈標識與零值標識讀不到且同形。
func TestStandardProfileScopeMatrix(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	adminID := identitytest.NewID(t)
	admin := identitytest.Account(t, adminID, identitytest.ServerAdmin())
	peer := e.seed(t, seedInput{Login: "one.more.admin", Display: "另一位管理員", Admin: true})
	deleted := e.seed(t, seedInput{Login: "already.gone", Display: "已刪除的", Deleted: true})

	plain, err := e.service.CreateStandardAccount(ctx, admin, CreateInput{
		LoginName: "readable.plain", DisplayName: "讀得到的普通帳戶", InitialPassword: testInitialPassword,
	}, "req-readable")
	if err != nil {
		t.Fatalf("建立普通帳戶失敗：%v", err)
	}
	// 操作者自己也在 accounts 表裡（Root 開設時建的），把他種進來後同樣讀不到。
	// 操作者自己這一類（持有授予的帳戶）即使是 accounts 表裡的一行，也在目錄之外。
	selfSeed := e.seed(t, seedInput{Login: "caller.himself", Display: "操作者自己", Admin: true})

	profile, err := e.service.StandardAccountProfile(ctx, admin, plain.AccountID)
	if err != nil {
		t.Fatalf("讀普通帳戶詳情失敗：%v", err)
	}
	if profile.AccountID != plain.AccountID || profile.Type != account.TypeStandard ||
		profile.Status != account.StatusActive || !profile.MustChangePassword {
		t.Errorf("詳情應帶出服務端判定的形態，實際 %+v", profile)
	}
	if !profile.LastLoginAt.IsZero() {
		t.Errorf("從未登入時應是零值（不是拿建立時刻冒充），實際 %v", profile.LastLoginAt)
	}
	text := fmt.Sprintf("%+v", profile)
	for _, forbidden := range []string{"argon2id", testInitialPassword, "PasswordHash", "LoginKey"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Errorf("詳情不得含 %q，實際 %s", forbidden, text)
		}
	}

	guest := e.seed(t, seedInput{Login: "readable.guest", Display: "訪客詳情", Type: account.TypeGuest})
	got, err := e.service.StandardAccountProfile(ctx, admin, guest.ID)
	if err != nil {
		t.Fatalf("讀訪客詳情失敗：%v", err)
	}
	if got.Type != account.TypeGuest || got.MustChangePassword {
		t.Errorf("訪客詳情應如實顯示來源與旗標形態，實際 %+v", got)
	}

	for name, id := range map[string]idgen.ID{
		"另一位管理員": peer.ID,
		"操作者自己":  selfSeed.ID,
		"幽靈標識":   identitytest.NewID(t),
		"零值標識":   idgen.ID{},
	} {
		if _, err := e.service.StandardAccountProfile(ctx, admin, id); !errors.Is(err, ErrAccountNotFound) {
			t.Errorf("%s 應收斂成「不在這本目錄裡」，實際 %v", name, err)
		}
	}

	// 已刪除帳戶反方向獨立成句：用戶批准的展示策略是「列得出、點得開、一律只讀」，
	// 所以詳情讀得到，而且帶著 deleted_at 與那顆佔位顯示名——界面要把「他已被刪於何時」
	// 講成服務端的事實，而不是讓操作者對著一個查不到的標識猜。
	deletedProfile, err := e.service.StandardAccountProfile(ctx, admin, deleted.ID)
	if err != nil {
		t.Fatalf("已刪除帳戶的詳情必須讀得到（歷史身分回溯），實際 %v", err)
	}
	if deletedProfile.Status != account.StatusDeleted || deletedProfile.DeletedAt.IsZero() {
		t.Errorf("詳情應如實帶出刪除終態與刪除時刻，實際 status=%s deletedAt=%v",
			deletedProfile.Status, deletedProfile.DeletedAt)
	}
	if !strings.HasPrefix(deletedProfile.DisplayName, "DEL_") {
		t.Errorf("詳情讀到的應是服務端寫回的佔位顯示名，實際 %q", deletedProfile.DisplayName)
	}
	if deletedProfile.LoginName != deleted.LoginName {
		t.Errorf("刪除不動登入名（名字繼續被占用）：期望 %q，實際 %q",
			deleted.LoginName, deletedProfile.LoginName)
	}
}

// TestUpdateStandardProfileWritesOnlyDisplayNameAndAudits 編輯的白名單與審計：
// 成功只改 display_name 一欄，其餘整行原封不動；審計帶前后值且 actor 是那位管理員本人。
func TestUpdateStandardProfileWritesOnlyDisplayNameAndAudits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	adminID := identitytest.NewID(t)
	admin := identitytest.Account(t, adminID, identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "edit.target")

	snapshot := rawAccountRow(t, e, created.AccountID)
	updated, err := e.service.UpdateStandardAccountProfile(ctx, admin, created.AccountID,
		"  改名後的顯示名  ", "測試普通帳戶", "req-edit-1")
	if err != nil {
		t.Fatalf("編輯失敗：%v", err)
	}
	// 回應給的是保存後的現值（去首尾空白是域規則的一份形為），不是請求的迴音。
	if updated.DisplayName != "改名後的顯示名" {
		t.Errorf("應回保存後的正規現值，實際 %q", updated.DisplayName)
	}
	after := rawAccountRow(t, e, created.AccountID)
	if after["display_name"] != "改名後的顯示名" {
		t.Errorf("落庫值應是去空白後的現值，實際 %q", after["display_name"])
	}
	for _, column := range []string{"id", "login_name", "login_name_key", "password_hash",
		"account_type", "status", "must_change_password", "created_at", "last_login_at",
		"disabled_at", "deleted_at"} {
		if after[column] != snapshot[column] {
			t.Errorf("編輯不得動 %s（前 %q 後 %q）", column, snapshot[column], after[column])
		}
	}

	var (
		action     string
		actorKind  string
		actorID    string
		targetKind string
		targetID   string
		changes    string
	)
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT action, actor_kind, actor_id,
			target_kind, target_id, changes_json FROM root_audit ORDER BY rowid DESC LIMIT 1`).
		Scan(&action, &actorKind, &actorID, &targetKind, &targetID, &changes); err != nil {
		t.Fatalf("讀審計失敗：%v", err)
	}
	if action != "account.profile_update" {
		t.Errorf("審計動作應是 account.profile_update，實際 %s", action)
	}
	if actorKind != "admin" || actorID != adminID.String() {
		t.Errorf("審計歸屬應是那位管理員本人（不是 Root、不是 system），實際 kind=%s id=%s",
			actorKind, actorID)
	}
	if targetKind != "account" || targetID != created.AccountID.String() {
		t.Errorf("審計目標應是被編輯的帳戶，實際 %s/%s", targetKind, targetID)
	}
	// 「不捏造 activity_id」成立在結構上：root_audit 根本沒有這一欄（遷移 0002 的刻意为之）。
	if hasColumn, err := columnExists(e.db, "root_audit", "activity_id"); err != nil {
		t.Fatalf("查證 root_audit 欄位失敗：%v", err)
	} else if hasColumn {
		t.Error("root_audit 不得出現 activity_id：Root 域事件不屬於任何活動")
	}
	if !strings.Contains(changes, "改名後的顯示名") || !strings.Contains(changes, "測試普通帳戶") {
		t.Errorf("審計應帶顯示名的前後值，實際 %s", changes)
	}
	if strings.Contains(strings.ToLower(changes), "password") ||
		strings.Contains(changes, testInitialPassword) || strings.Contains(changes, "argon2id") {
		t.Errorf("審計不得含憑據材料，實際 %s", changes)
	}
	if n := countProfileAudits(t, e.db); n != 1 {
		t.Errorf("一次成功的編輯恰好一筆審計，實際 %d", n)
	}
}

// TestUpdateStandardProfileConcurrentAndStale 併發與舊畫面：錯的依據值整筆不落，
// 六路並發同依據值恰好一次生效、審計也只多一筆。
func TestUpdateStandardProfileConcurrentAndStale(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "cas.target")

	if _, err := e.service.UpdateStandardAccountProfile(ctx, admin, created.AccountID,
		"錯過的現值", "從來沒這過的顯示名", "req-cas-lose"); !errors.Is(err, ErrProfileConflict) {
		t.Fatalf("依據值不符應回衝突，實際 %v", err)
	}
	if p := rawAccountRow(t, e, created.AccountID); p["display_name"] != "測試普通帳戶" {
		t.Errorf("衝突的編輯一個字都不該寫，實際 %q", p["display_name"])
	}
	if n := countProfileAudits(t, e.db); n != 0 {
		t.Errorf("衝突的編輯不留審計，實際 %d 筆", n)
	}

	const attempts = 6
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		wins    int
		conflic int
		other   []error
	)
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			_, err := e.service.UpdateStandardAccountProfile(context.Background(), admin,
				created.AccountID, fmt.Sprintf("併發改名%d", i), "測試普通帳戶",
				fmt.Sprintf("req-cas-%d", i))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrProfileConflict):
				conflic++
			default:
				other = append(other, err)
			}
		}(i)
	}
	wg.Wait()
	if len(other) > 0 {
		t.Fatalf("併發編輯只該出現成功或衝突，實際 %v", other)
	}
	if wins != 1 || conflic != attempts-1 {
		t.Errorf("併發編輯應恰好一次生效，實際 成功=%d 衝突=%d", wins, conflic)
	}
	if n := countProfileAudits(t, e.db); n != 1 {
		t.Errorf("贏家一筆之外落敗者不配留審計，實際 %d 筆", n)
	}
}

// TestUpdateStandardProfileRefusesOutOfRangeAndBadInput 目標範圍與輸入合規的兩側拒絕：
// 管理員／幽靈標識改不到，終態目標（已刪除、已退休）改不到，
// 非法顯示名不落庫也不留審計。
func TestUpdateStandardProfileRefusesOutOfRangeAndBadInput(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "refuse.target")
	peer := e.seed(t, seedInput{Login: "refuse.peer", Display: "同級管理員", Admin: true})
	deleted := e.seed(t, seedInput{Login: "refuse.gone", Display: "已刪除者", Deleted: true})
	accountsBefore := countRows(t, e.db, "accounts")
	auditsBefore := countRows(t, e.db, "root_audit")

	for name, tc := range map[string]struct {
		id  idgen.ID
		err error
	}{
		"同級管理員":  {peer.ID, ErrAccountNotFound},
		"已刪除者":   {deleted.ID, ErrAccountDeleted},
		"不存在的標識": {identitytest.NewID(t), ErrAccountNotFound},
		"零值標識":   {idgen.ID{}, ErrAccountNotFound},
	} {
		if _, err := e.service.UpdateStandardAccountProfile(ctx, admin, tc.id,
			"不該落庫的名字", rawAccountRow(t, e, created.AccountID)["display_name"],
			"req-out-of-range"); !errors.Is(err, tc.err) {
			t.Errorf("%s 編輯應回 %v，實際 %v", name, tc.err, err)
		}
	}

	tooLong := strings.Repeat("長", testMaxDisplayNameRunes+1)
	for name, bad := range map[string]string{
		"空值":   "",
		"純空白":  "   ",
		"超長":   tooLong,
		"控制字元": "含\x00控制",
		"零寬字元": "含​零寬",
		"雙向覆寫": "含‮覆寫",
		"依據值空": "正常顯示名",
	} {
		expected := "測試普通帳戶"
		if name == "依據值空" {
			if _, err := e.service.UpdateStandardAccountProfile(ctx, admin, created.AccountID,
				bad, "", "req-empty-expected"); !errors.Is(err, ErrProfileConflict) {
				t.Errorf("空依據值永遠比不中，應回衝突而不是成功，實際 %v", err)
			}
			continue
		}
		if _, err := e.service.UpdateStandardAccountProfile(ctx, admin, created.AccountID,
			bad, expected, "req-bad-display"); !errors.Is(err, account.ErrInvalidDisplayName) {
			t.Errorf("%s 應被域規則擋下，實際 %v", name, err)
		}
	}
	if n := countRows(t, e.db, "accounts"); n != accountsBefore {
		t.Errorf("被拒的編輯不得多出帳戶（前 %d 後 %d）", accountsBefore, n)
	}
	if p := rawAccountRow(t, e, created.AccountID); p["display_name"] != "測試普通帳戶" {
		t.Errorf("被拒的編輯不得改現值，實際 %q", p["display_name"])
	}
	if n := countRows(t, e.db, "root_audit"); n != auditsBefore {
		t.Errorf("被拒的編輯不得追加審計（前 %d 後 %d）", auditsBefore, n)
	}
}

// TestUpdateStandardProfileRollsBackWhenAuditCannotBeWritten 審計寫不進去＝改名一起回滾。
func TestUpdateStandardProfileRollsBackWhenAuditCannotBeWritten(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "rollback.edit")
	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("移除審計表失敗（測試前提）：%v", err)
	}
	if _, err := e.service.UpdateStandardAccountProfile(ctx, admin, created.AccountID,
		"回滾驗證", "測試普通帳戶", "req-rollback"); err == nil {
		t.Fatal("審計寫入失敗時編輯必須回報失敗")
	}
	if p := rawAccountRow(t, e, created.AccountID); p["display_name"] != "測試普通帳戶" {
		t.Errorf("回滾後顯示名必須原封不動，實際 %q", p["display_name"])
	}
}

// TestCanceledContextLeavesProfileUntouched 交易開始前就被取消：一個字都不該落盤。
func TestCanceledContextLeavesProfileUntouched(t *testing.T) {
	e := newEnv(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "cancel.edit")

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.service.UpdateStandardAccountProfile(canceled, admin, created.AccountID,
		"沒機會", "測試普通帳戶", "req-cancel"); err == nil {
		t.Fatal("已取消的 context 必須讓編輯失敗")
	}
	if p := rawAccountRow(t, e, created.AccountID); p["display_name"] != "測試普通帳戶" {
		t.Errorf("取消後顯示名必須原封不動，實際 %q", p["display_name"])
	}
}

// TestDirectoryRejectsUnauthorizedBeforeAnyQuery 授權先於參數校驗與查詢：
// 一個非法參數疊在沒權限的主體上，拿到的仍然是權限錯誤而不是「參數哪裡寫壞了」。
func TestDirectoryRejectsUnauthorizedBeforeAnyQuery(t *testing.T) {
	e := newEnv(t)
	plain := identitytest.Account(t, identitytest.NewID(t))
	_, err := e.service.Directory(context.Background(), plain, DirectoryQuery{Page: -5, PageSize: 0})
	if !isDenied(err) {
		t.Errorf("應先被授權擋下，實際 %v", err)
	}
	if n := countRows(t, e.db, "accounts"); n != 0 {
		t.Errorf("被拒的目錄讀取不該有任何寫入，實際 %d 行", n)
	}
}

// rawAccountRow 讀回 accounts 裡那一行的全部欄位原值（字串化），供「不得連動」斷言比對。
//
// 這裡刻意用 SELECT * 而不是白名單：斷言的對象正是「這一行的其他格子有沒有被順手动過」，
// 白名單會把要抓的东西擋在檢查之外。
func rawAccountRow(t *testing.T, e *env, id idgen.ID) map[string]string {
	t.Helper()
	rows, err := e.db.SQL().QueryContext(context.Background(),
		"SELECT * FROM accounts WHERE id = ?", id.String())
	if err != nil {
		t.Fatalf("讀取帳戶整行失敗：%v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatalf("帳戶 %s 不存在（測試前提）", id)
	}
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("取欄位清單失敗：%v", err)
	}
	raw := make([]any, len(cols))
	targets := make([]any, len(cols))
	for i := range raw {
		targets[i] = &raw[i]
	}
	if err := rows.Scan(targets...); err != nil {
		t.Fatalf("掃描整行失敗：%v", err)
	}
	out := make(map[string]string, len(cols))
	for i, col := range cols {
		if raw[i] == nil {
			out[col] = "<NULL>"
			continue
		}
		out[col] = fmt.Sprintf("%v", raw[i])
	}
	return out
}

// countProfileAudits 數 root_audit 裡的編輯審計筆數。
func countProfileAudits(t *testing.T, db *database.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = 'account.profile_update'").
		Scan(&n); err != nil {
		t.Fatalf("計數編輯審計失敗：%v", err)
	}
	return n
}

// testMaxDisplayNameRunes 與 internal/account 的顯示名上界同值（遷移 0003／0007 的 CHECK）。
// 測試檔不直接引用那個未匯出的常數：這裡要的只是「比上界多一個字元」這個形態。
const testMaxDisplayNameRunes = 64

// columnExists 回報一張表裡有沒有某個欄位（結構性斷言用：
// 「root_audit 沒有 activity_id 這一欄」這句話要查得起來，不能只写在註解裡）。
func columnExists(db *database.DB, table, column string) (bool, error) {
	rows, err := db.SQL().QueryContext(context.Background(), "PRAGMA table_info("+table+")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid    int
			name   string
			ctype  string
			notNil int
			dflt   any
			pk     int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNil, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
