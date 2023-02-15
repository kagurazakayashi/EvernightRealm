// acctreview_test.go 是「註冊申請名冊」這側的定向證據：誰讀得到這本名冊、
// 哪幾行列得進來、篩選與分頁的邊界，以及關鍵字比對不會變成把名單交出去。
//
// 全程使用本次專屬的暫存庫與注入時鐘：不佔 5206、不碰任何真實資料目錄，
// 也不在任何地方留下口令、憑據雜湊或會話材料。
package acctreview

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 測試口令：只活在測試進程的記憶體，不是任何環境的憑據。
const (
	testPassword     = "acctreview-test-申請人自選口令"
	testRootPassword = "acctreview-test-root-口令"
)

// testBase 是注入時鐘的錨點。
var testBase = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)

// env 是一次測試的完整現場：專屬暫存庫、注入時鐘，加上組好的審批用例與幾個協作用的倉儲。
//
// 會話倉儲與策略倉儲只在這裡出現，而且都不是審批用例的依賴（Service 裡根本沒有那兩格）：
// 前者是「批准不簽發會話」這句話需要一個可以數的對象，後者是「審批不問准入策略」需要一個
// 可以翻動的開關。把它們接進 Service 反而是本步要擋住的錯誤。
type env struct {
	db       *database.DB
	clock    *timeutil.Test
	logs     *bytes.Buffer
	accounts *account.Store
	grants   *grant.Store
	policy   *acctpolicy.Store
	sessions *session.Store
	service  *Service
}

// newEnv 建立現場。口令雜湊用 credential.TestParams（低成本檔）：本套件的斷言對象是
// 「決定落下的形態與名冊讀到的行」，不是生產參數檔的算力。
func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() {
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			t.Errorf("暫存目錄清理失敗（殘留：%s）：%v", dir, err)
		}
	})
	db, err := database.Open(context.Background(), database.Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := timeutil.NewTest(testBase)
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: clock}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	var logs bytes.Buffer
	accounts := account.NewStore(clock)
	sessions, err := session.NewStoreWithPolicy(clock, time.Hour, session.Policy{})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	service, err := New(Deps{
		DB:       db,
		Accounts: accounts,
		Grants:   grant.NewStore(clock),
		Audits:   audit.NewStore(clock),
		Log:      slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("建立審批用例失敗：%v", err)
	}
	return &env{db: db, clock: clock, logs: &logs, accounts: accounts,
		grants: grant.NewStore(clock), policy: acctpolicy.NewStore(clock),
		sessions: sessions, service: service}
}

// newAdmin 建立一位持有伺服器級授予的受信主體（純測試身份工廠，不落 accounts 表）。
func newAdmin(t *testing.T) identity.Principal {
	t.Helper()
	return identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
}

// mustApplication 種一筆待審批申請（standard＋pending＋本人自選口令的真實雜湊，
// 與 approval 模式的自註冊落成同一個形態）。提交那條通路本身由 internal/selfregister 自己的
// 套件負責取證，這裡要測的是審批這側，因此經倉儲原語把起點形態擺好。
func (e *env) mustApplication(t *testing.T, login, display string) account.Account {
	t.Helper()
	return e.mustSeed(t, account.NewInput{
		LoginName:    login,
		DisplayName:  display,
		Type:         account.TypeStandard,
		Status:       account.StatusPending,
		PasswordHash: e.mustHash(t, testPassword),
	})
}

// mustSeed 經帳戶倉儲種入任意形態並回傳實體。
func (e *env) mustSeed(t *testing.T, in account.NewInput) account.Account {
	t.Helper()
	created, err := e.accounts.Create(context.Background(), e.db.SQL(), in)
	if err != nil {
		t.Fatalf("種入帳戶 %s 失敗：%v", in.LoginName, err)
	}
	return created
}

// mustHash 產生一枚低成本檔的真實憑據雜湊（批准後要用它走既有登入通路復核閉環）。
func (e *env) mustHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := credential.Hash(password, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	return hash
}

// mustReview 下一次決定並在失敗時終止測試。
func (e *env) mustReview(t *testing.T, principal identity.Principal, id idgen.ID,
	decision account.Decision) ReviewOutcome {
	t.Helper()
	outcome, err := e.service.ReviewApplication(context.Background(), principal, id,
		decision, "req-review")
	if err != nil {
		t.Fatalf("對 %s 下 %s 失敗：%v", id, decision, err)
	}
	return outcome
}

// reviewErr 下一次決定並只回傳錯誤。
func (e *env) reviewErr(t *testing.T, principal identity.Principal, id idgen.ID,
	decision account.Decision) error {
	t.Helper()
	_, err := e.service.ReviewApplication(context.Background(), principal, id,
		decision, "req-probe")
	return err
}

// roster 讀一頁名冊並在失敗時終止測試。
func (e *env) roster(t *testing.T, principal identity.Principal, q RosterQuery) RosterPage {
	t.Helper()
	if q.Page == 0 {
		q.Page = 1
	}
	if q.PageSize == 0 {
		q.PageSize = 10
	}
	page, err := e.service.Roster(context.Background(), principal, q)
	if err != nil {
		t.Fatalf("讀名冊失敗：%v", err)
	}
	return page
}

// mustRosterIDs 讀全部名冊並回標識集合（多數範圍用例只關心「誰在這一頁上」）。
func (e *env) mustRosterIDs(t *testing.T, principal identity.Principal, filter string) map[string]bool {
	t.Helper()
	page := e.roster(t, principal, RosterQuery{StatusFilter: filter, PageSize: RosterMaxPageSize})
	seen := make(map[string]bool, len(page.Rows))
	for _, row := range page.Rows {
		seen[row.AccountID] = true
	}
	return seen
}

// grantAdminRole 把一筆帳戶寫成持有伺服器級授予的人（與 internal/adminacct 寫授予同一個倉儲原語）。
func (e *env) grantAdminRole(t *testing.T, id idgen.ID) {
	t.Helper()
	if err := e.grants.Grant(context.Background(), e.db.SQL(), id, identity.RoleServerAdmin); err != nil {
		t.Fatalf("種入授予失敗：%v", err)
	}
}

// setSelfRegisterMode 經策略倉儲（與生產同一個寫入點）翻動 self_register_mode，
// 用在「審批不問准入策略」那條斷言上。
func (e *env) setSelfRegisterMode(t *testing.T, mode acctpolicy.Mode) {
	t.Helper()
	if _, err := e.policy.Put(context.Background(), e.db.SQL(), acctpolicy.Policy{
		AdminCreateStandard: false, SelfRegisterMode: mode, GuestEnabled: false,
	}); err != nil {
		t.Fatalf("設定帳戶建立策略失敗：%v", err)
	}
}

// countRows 數一張表的行數（測試取證用，不參與任何生產判定）。
func countRows(t *testing.T, db *database.DB, table string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("計數 %s 失敗：%v", table, err)
	}
	return n
}

// auditRow 是一筆 Root 域審計的可讀取證據。
type auditRow struct {
	ActorKind   string
	ActorID     sql.NullString
	Action      string
	TargetID    sql.NullString
	Reason      sql.NullString
	RequestID   sql.NullString
	ChangesJSON string
	CreatedAt   int64
}

// mustAudit 讀回指定動作的最後一筆審計（不存在即終止測試）。
func mustAudit(t *testing.T, db *database.DB, action string) auditRow {
	t.Helper()
	var row auditRow
	err := db.SQL().QueryRowContext(context.Background(), `SELECT actor_kind, actor_id, action,
		target_id, reason, request_id, changes_json, created_at
		FROM root_audit WHERE action = ? ORDER BY created_at DESC, id DESC LIMIT 1`, action).
		Scan(&row.ActorKind, &row.ActorID, &row.Action, &row.TargetID, &row.Reason,
			&row.RequestID, &row.ChangesJSON, &row.CreatedAt)
	if err != nil {
		t.Fatalf("讀回 %s 的審計失敗：%v", action, err)
	}
	return row
}

// countAudit 數某個動作的審計筆數。
func countAudit(t *testing.T, db *database.DB, action string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = ?", action).Scan(&n); err != nil {
		t.Fatalf("計數 %s 的審計失敗：%v", action, err)
	}
	return n
}

// TestNewRefusesMissingDependencies 缺任何一個依賴都是組裝缺陷，在啟動階段當場報出：
// 少授予倉儲就分不清「一個被授予過管理權的人是不是也掛在這本名冊上」，
// 少審計倉儲就會落出一個「有人被放行了，卻查不到是誰放的」的決定。
func TestNewRefusesMissingDependencies(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name string
		deps Deps
	}{
		{"缺少 db", Deps{Accounts: e.accounts, Grants: e.grants, Audits: audit.NewStore(e.clock)}},
		{"缺少 accounts", Deps{DB: e.db, Grants: e.grants, Audits: audit.NewStore(e.clock)}},
		{"缺少 grants", Deps{DB: e.db, Accounts: e.accounts, Audits: audit.NewStore(e.clock)}},
		{"缺少 audits", Deps{DB: e.db, Accounts: e.accounts, Grants: e.grants}},
	}
	for _, tc := range cases {
		if _, err := New(tc.deps); err == nil {
			t.Errorf("%s 時必須啟動失敗", tc.name)
		}
	}
	if _, err := New(Deps{DB: e.db, Accounts: e.accounts, Grants: e.grants,
		Audits: audit.NewStore(e.clock)}); err != nil {
		t.Errorf("湊齊四個依賴時不該失敗：%v", err)
	}
}

// TestRosterRequiresServerAdmin 讀名冊的邊界就是 NeedServerAdmin：匿名、普通帳戶與系統主體
// 一個字都讀不到，也不消耗一次查詢；Root 與管理員讀得到同一頁。
func TestRosterRequiresServerAdmin(t *testing.T) {
	e := newEnv(t)
	target := e.mustApplication(t, "Roster.Gate", "名冊門檻")

	// 匿名與其餘主體的結論刻意分開：一個是「連是誰都不知道」（2002 那一句），
	// 另一個是「身分可信但沒有這個權限」（2011 那一句）。混成一句，客戶端就會把
	// 「你沒有管理權」處理成「你被登出了」。
	if _, err := e.service.Roster(context.Background(), identitytest.Anonymous(t),
		RosterQuery{Page: 1, PageSize: 20}); !errors.Is(err, identity.ErrNotAuthenticated) {
		t.Errorf("匿名讀名冊必須回「未通過認證」，實際 %v", err)
	}
	for name, principal := range map[string]identity.Principal{
		"普通帳戶": identitytest.Account(t, identitytest.NewID(t)),
		"系統主體": identitytest.System(t, identity.OriginCLI),
	} {
		if _, err := e.service.Roster(context.Background(), principal,
			RosterQuery{Page: 1, PageSize: 20}); !errors.Is(err, identity.ErrPermissionDenied) {
			t.Errorf("%s 讀名冊必須被拒，實際 %v", name, err)
		}
	}
	for name, principal := range map[string]identity.Principal{
		"管理員":  newAdmin(t),
		"Root": identitytest.Root(t, identity.OriginHTTPRequest),
	} {
		page, err := e.service.Roster(context.Background(), principal,
			RosterQuery{Page: 1, PageSize: 20})
		if err != nil {
			t.Fatalf("%s 讀名冊失敗：%v", name, err)
		}
		if len(page.Rows) != 1 || page.Rows[0].AccountID != target.ID.String() {
			t.Errorf("%s 應讀到那一筆申請，實際 %+v", name, page.Rows)
		}
	}
}

// TestRosterScopeListsPendingAndRejectedOnly 這本名冊的範圍規則：只列 pending 與 rejected，
// 而且把持有伺服器級授予的人排掉。其餘形態各有自己的書，不拿這一頁冒充那一頁。
func TestRosterScopeListsPendingAndRejectedOnly(t *testing.T) {
	e := newEnv(t)
	admin := newAdmin(t)
	ctx := context.Background()

	pending := e.mustApplication(t, "scope.pending", "等待中")
	rejected := e.mustApplication(t, "scope.rejected", "要被拒絕")
	if _, err := e.service.ReviewApplication(ctx, admin, rejected.ID, account.DecisionReject,
		"req-scope"); err != nil {
		t.Fatalf("種出被拒的申請失敗：%v", err)
	}
	approved := e.mustApplication(t, "scope.approved", "會被批准再停用")
	if _, err := e.service.ReviewApplication(ctx, admin, approved.ID, account.DecisionApprove,
		"req-scope-2"); err != nil {
		t.Fatalf("種出被批准的人失敗：%v", err)
	}
	// 一個從沒走過審批通路的既有帳戶（管理員建號、開放自註冊建成的都是這個形態）。
	plain := e.mustSeed(t, account.NewInput{
		LoginName: "scope.plain", DisplayName: "直接建成的", PasswordHash: e.mustHash(t, testPassword),
		Type: account.TypeStandard, Status: account.StatusActive, MustChangePassword: true,
	})
	// 一筆被直寫過授予的申請：今日沒有任何通路能造出這個形態，名冊與寫入通路都必須把他排掉，
	// 否則「批准順手多出一位管理員」就有了發生點。
	granted := e.mustApplication(t, "scope.granted", "被授予過的申請")
	e.grantAdminRole(t, granted.ID)

	seen := e.mustRosterIDs(t, admin, RosterFilterAll)
	for id, want := range map[string]bool{
		pending.ID.String():  true,
		rejected.ID.String(): true,
		approved.ID.String(): false,
		plain.ID.String():    false,
		granted.ID.String():  false,
	} {
		if seen[id] != want {
			t.Errorf("名冊範圍不對：%s 期望列=%v，實際=%v", id, want, seen[id])
		}
	}
	if len(seen) != 2 {
		t.Errorf("名冊應恰好兩行，實際 %+v", seen)
	}

	// 狀態篩選：各取一態，all 取兩態；表外值（含 active）當場點名參數而不是回空頁——
	// 「篩不到」與「不在這本書的語意裡」是兩句話。
	onlyPending := e.mustRosterIDs(t, admin, account.StatusPending.String())
	if len(onlyPending) != 1 || !onlyPending[pending.ID.String()] {
		t.Errorf("pending 篩選應只剩等待中那一筆，實際 %+v", onlyPending)
	}
	onlyRejected := e.mustRosterIDs(t, admin, account.StatusRejected.String())
	if len(onlyRejected) != 1 || !onlyRejected[rejected.ID.String()] {
		t.Errorf("rejected 篩選應只剩被拒那一筆，實際 %+v", onlyRejected)
	}
	if _, err := e.service.Roster(ctx, admin, RosterQuery{Page: 1, PageSize: 20,
		StatusFilter: account.StatusActive.String()}); !errors.Is(err, ErrInvalidStatusFilter) {
		t.Errorf("active 不屬於這本名冊，篩選它必須回可判別的參數結論，實際 %v", err)
	}

	// 被批准的人此後被停用：他仍不在這本書上（那句篩選用的是狀態而不是「有沒有決定時刻」，
	// 否則一個曾被批准的人會從兩本書之間掉下去）。
	if _, err := e.accounts.SetStatus(ctx, e.db.SQL(), approved.ID,
		account.StatusDisabled, account.StatusActive); err != nil {
		t.Fatalf("把被批准的人停用失敗：%v", err)
	}
	if e.mustRosterIDs(t, admin, RosterFilterAll)[approved.ID.String()] {
		t.Error("被批准後停用的人不該出現在這本名冊上")
	}
}

// TestRosterPaginationAndOrder 分頁回顯真實參數與總數，排序是「最新在前＋標識破平」；
// 超出總數的合法頁碼回空行而不是錯誤。非法參數各自點名。
func TestRosterPaginationAndOrder(t *testing.T) {
	e := newEnv(t)
	admin := newAdmin(t)

	first := e.mustApplication(t, "page.one", "最早的申請")
	e.clock.Advance(time.Minute)
	second := e.mustApplication(t, "page.two", "中間的申請")
	e.clock.Advance(time.Minute)
	third := e.mustApplication(t, "page.three", "最新的申請")

	page := e.roster(t, admin, RosterQuery{Page: 1, PageSize: 2})
	if page.Total != 3 || page.Page != 1 || page.PageSize != 2 {
		t.Errorf("分頁回顯不對：total=%d page=%d size=%d", page.Total, page.Page, page.PageSize)
	}
	if len(page.Rows) != 2 || page.Rows[0].AccountID != third.ID.String() ||
		page.Rows[1].AccountID != second.ID.String() {
		t.Fatalf("最新在前這條沒站住：%+v", page.Rows)
	}
	second2 := e.roster(t, admin, RosterQuery{Page: 2, PageSize: 2})
	if len(second2.Rows) != 1 || second2.Rows[0].AccountID != first.ID.String() {
		t.Errorf("第二頁應剩下最早那一筆，實際 %+v", second2.Rows)
	}
	empty := e.roster(t, admin, RosterQuery{Page: 9, PageSize: 2})
	if len(empty.Rows) != 0 || empty.Total != 3 {
		t.Errorf("翻不到的頁該回空行與真實總數，實際 rows=%d total=%d", len(empty.Rows), empty.Total)
	}
	if empty.Rows == nil {
		t.Error("空頁必須是空切片而不是 nil（JSON 回應因此恆為數組）")
	}

	ctx := context.Background()
	cases := []struct {
		name string
		q    RosterQuery
		want error
	}{
		{"頁碼為 0", RosterQuery{Page: 0, PageSize: 20}, ErrInvalidPage},
		{"每頁 0 筆", RosterQuery{Page: 1, PageSize: 0}, ErrInvalidPageSize},
		{"每頁超過上限", RosterQuery{Page: 1, PageSize: RosterMaxPageSize + 1}, ErrInvalidPageSize},
		{"關鍵字過長", RosterQuery{Page: 1, PageSize: 20,
			Keyword: string(bytes.Repeat([]byte("名"), RosterKeywordMaxRunes+1))}, ErrInvalidKeyword},
	}
	for _, tc := range cases {
		if _, err := e.service.Roster(ctx, admin, tc.q); !errors.Is(err, tc.want) {
			t.Errorf("%s 應回 %v，實際 %v", tc.name, tc.want, err)
		}
	}
}

// TestRosterKeywordFilterEscapesWildcards 關鍵字隻影響哪些行出現：
// LIKE 的中間萬用字元與轉義字元必須先還原成字面字元，否則使用者打進去的那個字
// 就不是篩選而是把整本名冊交出去。
func TestRosterKeywordFilterEscapesWildcards(t *testing.T) {
	e := newEnv(t)
	admin := newAdmin(t)

	needle := e.mustApplication(t, "keyword.needle", "含百分比%的名稱")
	e.mustApplication(t, "keyword.other", "無關的顯示名")

	for _, tc := range []struct {
		keyword string
		want    int
	}{
		// 兩個萬用字元各自擋一種後果：% 漏掉時「%」會比對到每一行，
		// _ 漏掉時「_」會命中任何一個非空名字。兩者都不是「篩選」，而是把名單交出去。
		{keyword: "needle", want: 1},
		{keyword: "含百分比", want: 1},
		{keyword: "%", want: 1},
		{keyword: "_", want: 0},
	} {
		page := e.roster(t, admin, RosterQuery{Keyword: tc.keyword, PageSize: RosterMaxPageSize})
		if len(page.Rows) != tc.want {
			t.Errorf("關鍵字 %q 該命中 %d 行（萬用字元必須被當成字面字元），實際 %+v",
				tc.keyword, tc.want, page.Rows)
		}
		for _, row := range page.Rows {
			if row.AccountID != needle.ID.String() {
				t.Errorf("關鍵字 %q 命中了不對的一筆：%+v", tc.keyword, row)
			}
		}
	}
	// 空白關鍵字等價於沒帶：不拿一個空 pattern 去 LIKE '%%' 把全表列出來。
	all := e.roster(t, admin, RosterQuery{Keyword: "   ", PageSize: RosterMaxPageSize})
	if len(all.Rows) != 2 {
		t.Errorf("全空白關鍵字該視為不篩選，實際 %+v", all.Rows)
	}
	none := e.roster(t, admin, RosterQuery{Keyword: "查無此人", PageSize: RosterMaxPageSize})
	if len(none.Rows) != 0 {
		t.Errorf("查無匹配該回空頁，實際 %+v", none.Rows)
	}
}

// TestRosterRowsCarryOnlyReviewFacts 名冊的每一行只帶審核需要的六格，而且一個憑據材料都沒有：
// 被拒的人帶著決定時刻、等待中的人那一格是缺席而不是零值。
func TestRosterRowsCarryOnlyReviewFacts(t *testing.T) {
	e := newEnv(t)
	admin := newAdmin(t)
	ctx := context.Background()

	pending := e.mustApplication(t, "facts.pending", "等待中")
	rejected := e.mustApplication(t, "facts.rejected", "要被拒絕")
	if _, err := e.service.ReviewApplication(ctx, admin, rejected.ID, account.DecisionReject,
		"req-facts"); err != nil {
		t.Fatalf("拒絕失敗：%v", err)
	}

	rows := e.roster(t, admin, RosterQuery{PageSize: RosterMaxPageSize}).Rows
	if len(rows) != 2 {
		t.Fatalf("名冊該有兩行，實際 %+v", rows)
	}
	byID := map[string]Application{}
	for _, row := range rows {
		byID[row.AccountID] = row
	}
	p := byID[pending.ID.String()]
	if p.Status != account.StatusPending.String() || !p.ReviewedAt.IsZero() {
		t.Errorf("等待中的那筆該是 pending 且沒有決定時刻，實際 %+v", p)
	}
	if p.SubmittedAt.IsZero() || p.LoginName != "facts.pending" || p.DisplayName == "" {
		t.Errorf("行裡該有審核要的六格，實際 %+v", p)
	}
	r := byID[rejected.ID.String()]
	if r.Status != account.StatusRejected.String() || r.ReviewedAt.IsZero() {
		t.Errorf("被拒的那筆該是 rejected 並帶著決定時刻，實際 %+v", r)
	}
	// 這一條不是裝飾：名冊的 SQL 一旦被人改成 SELECT *，憑據雜湊就會順著同一個結構體
	// 一路走進回應體。這裡斷言的是「這個型別沒有地方能放它」——型別沒有那格，
	// 就沒有任何一層能把口令材料帶上來；順帶把整頁的轉寫快照掃一遍，多一道網。
	dump := fmt.Sprintf("%+v", rows) + mustAuditDump(t, e.db)
	for _, leak := range []string{"$argon2id$", testPassword} {
		if strings.Contains(dump, leak) {
			t.Errorf("名冊的讀取鏈路上出現憑據材料（%q）", leak)
		}
	}
}

// mustAuditDump 把整張 root_audit 轉成一段文字（測試取證用：脫敏斷言要掃的是全部痕跡，
// 不是某一筆）。
func mustAuditDump(t *testing.T, db *database.DB) string {
	t.Helper()
	rows, err := db.SQL().QueryContext(context.Background(), `SELECT action,
		COALESCE(reason, ''), COALESCE(changes_json, '') FROM root_audit`)
	if err != nil {
		t.Fatalf("讀取審計全文失敗：%v", err)
	}
	defer rows.Close()
	var out strings.Builder
	for rows.Next() {
		var action, reason, changes string
		if err := rows.Scan(&action, &reason, &changes); err != nil {
			t.Fatalf("讀取審計列失敗：%v", err)
		}
		out.WriteString(action)
		out.WriteString(reason)
		out.WriteString(changes)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍曆審計失敗：%v", err)
	}
	return out.String()
}
