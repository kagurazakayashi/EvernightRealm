// activity_test.go 是活動用例的服務層證據：建立者自動成為第一位管理人、
// 跨活動隔離收斂成不可分辨的一句話、名稱與描述各條域規則、目錄的可見範圍只認指派表，
// 以及「沒有伺服器級管理權的人連一個活動都建不出來」。
//
// 刻意不收的東西：
//   - 沒有替身：授權、指派清單、審計與狀態機都走真路徑（真資料庫＋真倉儲＋注入時鐘），
//     接錯線就會紅；
//   - 不測任何活動內業務（成員、陣營、資產）：那些模組尚未落地，本檔也不替它們編造形態。
package activity

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 注入時鐘的錨點：所有時刻斷言都以它為基準，測試裡沒有一處讀牆鐘。
var testBase = time.Date(2026, 10, 10, 3, 0, 0, 0, time.UTC)

// env 是本次測試專屬的現場：真資料庫（套到 0012）、真帳戶／授予／審計倉儲與真活動用例。
type env struct {
	db       *database.DB
	clock    *timeutil.Test
	accounts *account.Store
	grants   *grant.Store
	audits   *audit.Store
	store    *Store
	service  *Service
	logs     *bytes.Buffer
}

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
	accounts := account.NewStore(clock)
	grants := grant.NewStore(clock)
	audits := audit.NewStore(clock)
	store := NewStore(clock)
	var logs bytes.Buffer
	service, err := New(Deps{
		DB: db, Store: store, Accounts: accounts, Grants: grants, Clock: clock, Audits: audits,
		Log: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("建立活動用例失敗：%v", err)
	}
	return &env{db: db, clock: clock, accounts: accounts, grants: grants,
		audits: audits, store: store, service: service, logs: &logs}
}

// seedAccount 落一位真實帳戶並回傳它的實體（主體另由 actor 那條路構造）。
func (e *env) seedAccount(t *testing.T, login, display string,
	accType account.Type, status account.Status) account.Account {
	t.Helper()
	// 訪戶按定義沒有憑據（遷移 0003 的跨欄 CHECK 與域層校驗同一口徑），
	// 這裡的雜湊只給普通帳戶——否則佈資料自己先撞牆。
	hash := ""
	if accType == account.TypeStandard {
		hash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$fakehashfortestonly"
	}
	in := account.NewInput{
		LoginName: login, DisplayName: display, PasswordHash: hash,
		Type: accType, Status: status, MustChangePassword: false,
	}
	if status == account.StatusDisabled {
		// 停用與停用時刻同生同滅（域層與 CHECK 同一口徑）：佈資料得先滿足這條。
		in.DisabledAt = testBase
	}
	a, err := e.accounts.Create(context.Background(), e.db.SQL(), in)
	if err != nil {
		t.Fatalf("種下帳戶 %s 失敗：%v", login, err)
	}
	return a
}

// admin 種一位持有 server_admin 的帳戶並構造它的主體（活動管理通路的正規操作者）。
func (e *env) admin(t *testing.T, login string) (identity.Principal, account.Account) {
	t.Helper()
	a := e.seedAccount(t, login, "管理員"+login, account.TypeStandard, account.StatusActive)
	if err := e.grants.Grant(context.Background(), e.db.SQL(), a.ID, identity.RoleServerAdmin); err != nil {
		t.Fatalf("授予 %s 失敗：%v", login, err)
	}
	return identitytest.Account(t, a.ID, identitytest.ServerAdmin()), a
}

// plain 種一位沒有任何伺服器級授予的普通帳戶（本步它不該能碰任何活動管理面）。
func (e *env) plain(t *testing.T, login string) identity.Principal {
	t.Helper()
	a := e.seedAccount(t, login, "平民"+login, account.TypeStandard, account.StatusActive)
	return identitytest.Account(t, a.ID)
}

func (e *env) root(t *testing.T) identity.Principal {
	return identitytest.Root(t, identity.OriginHTTPRequest)
}

// create 建立一個活動，失敗即終止。
func (e *env) create(t *testing.T, principal identity.Principal, name, description string) Activity {
	t.Helper()
	a, err := e.service.Create(context.Background(), principal, name, description, "req-create")
	if err != nil {
		t.Fatalf("建立活動 %q 應成功：%v", name, err)
	}
	return a
}

// countRows 讀一張表的筆數（審計是否同生同滅、失敗寫入是否留下痕跡都靠它斷言）。
func (e *env) countRows(t *testing.T, table string) int {
	t.Helper()
	var got int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM "+table).Scan(&got); err != nil {
		t.Fatalf("統計 %s 失敗：%v", table, err)
	}
	return got
}

// countAuditRows 統計活動域審計裡「某個活動的某個動作」有幾筆。
//
// 三個條件一起問才有意義：動作名對、activity_id 對、而且落在 activity_audit 這張表上——
// 只數總筆數會讓「Root 域多記一筆」混進活動域的斷言裡。
func (e *env) countAuditRows(t *testing.T, action, activityID string) int {
	t.Helper()
	var got int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM activity_audit WHERE action = ? AND activity_id = ?`,
		action, activityID).Scan(&got); err != nil {
		t.Fatalf("統計審計 %s／%s 失敗：%v", action, activityID, err)
	}
	return got
}

// activityFacts 是一行活動在資料庫裡的可觀察形態（前後對照拿它做等值比較）。
type activityFacts struct {
	name        string
	description string
	status      string
	createdBy   string
	createdAt   int64
	updatedAt   int64
	archivedAt  sql.NullInt64
}

func (e *env) facts(t *testing.T, id idgen.ID) activityFacts {
	t.Helper()
	var f activityFacts
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT name, description, status,
			created_by_account_id, created_at, updated_at, archived_at
		FROM activities WHERE id = ?`, id.String()).
		Scan(&f.name, &f.description, &f.status, &f.createdBy, &f.createdAt, &f.updatedAt, &f.archivedAt)
	if err != nil {
		t.Fatalf("讀取活動 %s 的事實失敗：%v", id.String(), err)
	}
	return f
}

// TestCreateMakesCreatorFirstManager 驗收：新建的活動一律是草稿，建立者在同一筆交易裡
// 成為第一位管理人，而且活動域審計確實帶著這個活動標識落了庫。
func TestCreateMakesCreatorFirstManager(t *testing.T) {
	e := newEnv(t)
	principal, admin := e.admin(t, "Create.Admin")

	created := e.create(t, principal, "秋夜長談", "第一場")
	if created.Status != StatusDraft {
		t.Errorf("新建活動必須是草稿，實際 %s", created.Status)
	}
	if created.ManagerCount != 1 {
		t.Errorf("建立者應已自動被指派為管理人，實際 manager_count=%d", created.ManagerCount)
	}
	if created.CreatedByAccountID != admin.ID {
		t.Errorf("建立者留痕應是操作者本人，實際 %s", created.CreatedByAccountID)
	}
	if created.CreatedAt != testBase || created.UpdatedAt != testBase {
		t.Errorf("時刻必須取自注入時鐘，實際 %v／%v", created.CreatedAt, created.UpdatedAt)
	}

	// 指派清單真的進了倉儲（授權判定的輸入就是它）。
	ids, err := e.store.ManagedActivityIDs(context.Background(), e.db.SQL(), admin.ID)
	if err != nil {
		t.Fatalf("讀取指派清單失敗：%v", err)
	}
	if len(ids) != 1 || ids[0] != created.ID {
		t.Errorf("建立者應管著剛建的活動，實際 %v", ids)
	}

	// 審計落在活動域、帶著這個活動標識與固定原因，且不含任何口令或憑據材料。
	var scopeActivityID, action, reason string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT activity_id, action, IFNULL(reason, '') FROM activity_audit
		ORDER BY created_at DESC, id DESC LIMIT 1`).
		Scan(&scopeActivityID, &action, &reason); err != nil {
		t.Fatalf("讀取審計失敗：%v", err)
	}
	if action != "activity.create" {
		t.Errorf("審計動作應是 activity.create，實際 %q", action)
	}
	if scopeActivityID != created.ID.String() {
		t.Errorf("activity 域審計必須帶活動標識，實際 %q", scopeActivityID)
	}
	if reason == "" {
		t.Error("activity 域審計必須帶原因（規格 §25.1）")
	}
	if strings.Contains(e.logs.String(), "argon2id") || strings.Contains(e.logs.String(), "fakehash") {
		t.Errorf("執行日誌不得複述任何憑據材料：%s", e.logs.String())
	}
}

// TestRootCreateLeavesNoAccountManager 驗收：Root 建的活動沒有帳戶管理人（Root 不在 accounts 表），
// 但 Root 自己進得去每一條通路——這一句要寫成證據，免得日後被誤讀成「指派漏了」。
func TestRootCreateLeavesNoAccountManager(t *testing.T) {
	e := newEnv(t)
	created := e.create(t, e.root(t), "Root 的活動", "")

	if created.ManagerCount != 0 {
		t.Errorf("Root 建立時不寫帳戶指派，實際 manager_count=%d", created.ManagerCount)
	}
	if !created.CreatedByAccountID.IsNil() {
		t.Errorf("Root 沒有帳戶標識，建立者那一格應留零值，實際 %s", created.CreatedByAccountID)
	}
	if _, err := e.service.ActivityDetail(context.Background(), e.root(t), created.ID); err != nil {
		t.Errorf("Root 應能直讀自己建的活動：%v", err)
	}
}

// TestCrossActivityIsolationIsIndistinguishable 驗收：甲活動的管理人管不著乙活動，
// 而且「管不著」與「根本沒有這個活動」是同一句話——少一枚可列舉的信號。
func TestCrossActivityIsolationIsIndistinguishable(t *testing.T) {
	e := newEnv(t)
	alpha, _ := e.admin(t, "Alpha.Admin")
	beta, _ := e.admin(t, "Beta.Admin")

	createdByAlpha := e.create(t, alpha, "甲的活動", "只歸甲管")
	ghost := identitytest.NewID(t)

	// 乙讀甲：查無此活動（與幽靈標識同形）。
	_, err := e.service.ActivityDetail(context.Background(), beta, createdByAlpha.ID)
	if !errors.Is(err, ErrActivityNotFound) {
		t.Errorf("乙讀甲應收斂成不可分辨的查無此活動，實際 %v", err)
	}
	_, ghostErr := e.service.ActivityDetail(context.Background(), beta, ghost)
	if !errors.Is(ghostErr, ErrActivityNotFound) {
		t.Fatalf("幽靈標識應回同一句話，實際 %v", ghostErr)
	}
	if err.Error() != ghostErr.Error() {
		t.Errorf("兩句必須逐字同形，否則就成了一枚探測信號：%q vs %q", err, ghostErr)
	}

	// 乙改甲：同樣收斂，而且一個欄位都不落、一筆審計都不記。
	auditsBefore := e.countRows(t, "activity_audit")
	if _, err := e.service.UpdateActivityProfile(context.Background(), beta, createdByAlpha.ID,
		"被乙改掉", "", "甲的活動", "", "req-evil"); !errors.Is(err, ErrActivityNotFound) {
		t.Errorf("乙改甲應被拒且不可分辨，實際 %v", err)
	}
	if f := e.facts(t, createdByAlpha.ID); f.name != "甲的活動" {
		t.Errorf("被拒的編輯動了名稱：實際 %q", f.name)
	}
	if got := e.countRows(t, "activity_audit"); got != auditsBefore {
		t.Errorf("被拒的編輯不該留下審計，前 %d 筆／實際 %d 筆", auditsBefore, got)
	}

	// 乙轉換甲的狀態：同樣被拒，狀態一位都不動。
	if _, err := e.service.Transition(context.Background(), beta, createdByAlpha.ID,
		StatusArchived, "req-evil-2"); !errors.Is(err, ErrActivityNotFound) {
		t.Errorf("乙歸檔甲應被拒且不可分辨，實際 %v", err)
	}
	if f := e.facts(t, createdByAlpha.ID); f.status != string(StatusDraft) {
		t.Errorf("被拒的轉換動了狀態：實際 %q", f.status)
	}

	// 目錄只列自己管得著的：乙看得見 0 行，甲看得見 1 行。
	betaPage, err := e.service.Directory(context.Background(), beta, DirectoryQuery{Page: 1, PageSize: DirectoryDefaultPageSize})
	if err != nil {
		t.Fatalf("乙讀目錄應成功：%v", err)
	}
	if betaPage.Total != 0 || len(betaPage.Rows) != 0 {
		t.Errorf("乙不該看見甲的活動，實際 Total=%d Rows=%d", betaPage.Total, len(betaPage.Rows))
	}
	alphaPage, err := e.service.Directory(context.Background(), alpha, DirectoryQuery{Page: 1, PageSize: DirectoryDefaultPageSize})
	if err != nil {
		t.Fatalf("甲讀目錄應成功：%v", err)
	}
	if alphaPage.Total != 1 || alphaPage.Rows[0].ID != createdByAlpha.ID {
		t.Errorf("甲應看見自己那一行，實際 Total=%d", alphaPage.Total)
	}

	// Root 的目錄不按指派限制（跨活動維運），這是身份層的同一條規則。
	rootPage, err := e.service.Directory(context.Background(), e.root(t), DirectoryQuery{Page: 1, PageSize: DirectoryDefaultPageSize})
	if err != nil {
		t.Fatalf("Root 讀目錄應成功：%v", err)
	}
	if rootPage.Total != 1 {
		t.Errorf("Root 應看見全部 1 行，實際 %d", rootPage.Total)
	}
}

// TestPrincipalWithoutServerAdminCannotManage 驗收：普通帳戶連目錄都讀不到，
// 更建不出一個活動——「帶著有效會話」不等於「能碰管理面」。
func TestPrincipalWithoutServerAdminCannotManage(t *testing.T) {
	e := newEnv(t)
	plain := e.plain(t, "Plain.Person")

	if _, err := e.service.Create(context.Background(), plain, "平民的活動", "", "req-x"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("普通帳戶建立活動應回報權限不足，實際 %v", err)
	}
	if _, err := e.service.Directory(context.Background(), plain, DirectoryQuery{Page: 1, PageSize: DirectoryDefaultPageSize}); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("普通帳戶讀目錄應回報權限不足，實際 %v", err)
	}
	if got := e.countRows(t, "activities"); got != 0 {
		t.Errorf("被拒的建立不該留下任何活動行，實際 %d 行", got)
	}

	// 匿名主體先撞在「不知道是誰」上，而且同樣什麼都沒寫。
	if _, err := e.service.Create(context.Background(), identitytest.Anonymous(t),
		"匿名建的", "", "req-y"); !errors.Is(err, identity.ErrNotAuthenticated) {
		t.Errorf("匿名建立活動應回報未認證，實際 %v", err)
	}
	if got := e.countRows(t, "activities"); got != 0 {
		t.Errorf("被拒的匿名建立不該留下活動行，實際 %d 行", got)
	}
	// 系統主體不是任何人的代理：它拿不到活動作用域。
	system := identitytest.System(t, identity.OriginBackground)
	if _, err := e.service.Directory(context.Background(), system, DirectoryQuery{Page: 1, PageSize: DirectoryDefaultPageSize}); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("系統主體讀目錄應回報權限不足，實際 %v", err)
	}
}

// TestDomainRulesOnNameAndDescription 驗收：每一種「湊得出來但無法解釋」的資料都當場被點名，
// 而且在進庫之前就被擋（不靠 CHECK 兜底後回一句內部錯誤）。
func TestDomainRulesOnNameAndDescription(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Domain.Admin")

	cases := []struct {
		name        string
		input       string
		description string
		wantErr     error
	}{
		{"空名稱", "", "", ErrInvalidName},
		{"整串都是空白", "   ", "", ErrInvalidName},
		{"超長名稱", strings.Repeat("長", maxNameRunes+1), "", ErrInvalidName},
		{"名稱含控制字元", "甲\x00活動", "", ErrInvalidName},
		{"名稱含格式字元", "甲\u200b活動", "", ErrInvalidName},
		{"超長描述", "正常", strings.Repeat("字", maxDescriptionRunes+1), ErrInvalidDescription},
		{"描述含控制字元", "正常", "甲\x07活動", ErrInvalidDescription},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.service.Create(context.Background(), principal, tc.input, tc.description, "req-domain")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("應回報 %v，實際 %v", tc.wantErr, err)
			}
			if got := e.countRows(t, "activities"); got != 0 {
				t.Fatalf("被拒的建立不該留下活動行，實際 %d 行", got)
			}
		})
	}

	// 描述裡的換行與縮排屬於它本身（不剔除內部空白），而首尾空白只是沒意義的邊界。
	created := e.create(t, principal, "多行描述", "\n  第一行\r\n第二行  \t尾  \n")
	if !strings.Contains(created.Description, "\n") || !strings.HasSuffix(created.Description, "尾") {
		t.Errorf("描述應保留內部換行、只剝首尾空白，實際 %q", created.Description)
	}
	// 名稱可重複：跨活動同名是合法部署形態，不是衝突。
	if again := e.create(t, principal, "多行描述", ""); again.ID == created.ID {
		t.Error("兩次建立必須各有一個標識")
	}
}

// TestDirectoryFilteringAndPaging 驗收：篩選、關鍵字與分頁的界線，
// 以及「關鍵字裡帶通配字元」不會變成「把所有行列出來」。
func TestDirectoryFilteringAndPaging(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Filter.Admin")
	first := e.create(t, principal, "百分比%活動", "含下劃線_a 的描述")
	e.create(t, principal, "另一場", "無關")

	page, err := e.service.Directory(context.Background(), principal, DirectoryQuery{
		Page:         1,
		PageSize:     DirectoryDefaultPageSize,
		StatusFilter: StatusDraft.String(),
	})
	if err != nil {
		t.Fatalf("狀態篩選應成功：%v", err)
	}
	if page.Total != 2 {
		t.Errorf("草稿篩選應命中 2 行，實際 %d", page.Total)
	}
	if _, err := e.service.Directory(context.Background(), principal, DirectoryQuery{
		Page: 1, PageSize: DirectoryDefaultPageSize, StatusFilter: "paused",
	}); !errors.Is(err, ErrInvalidStatusFilter) {
		t.Errorf("未批准的狀態取值應回報篩選不合法，實際 %v", err)
	}

	// 關鍵字是一段子文字串：% 與 _ 不該有能力表達「任意字元」。
	escaped, err := e.service.Directory(context.Background(), principal, DirectoryQuery{Page: 1, PageSize: DirectoryDefaultPageSize, Keyword: "%"})
	if err != nil {
		t.Fatalf("關鍵字查詢應成功：%v", err)
	}
	if escaped.Total != 1 || escaped.Rows[0].ID != first.ID {
		t.Errorf("關鍵字 %% 應只命中名稱裡真的帶 %% 那一行，實際 Total=%d", escaped.Total)
	}
	underscore, err := e.service.Directory(context.Background(), principal, DirectoryQuery{Page: 1, PageSize: DirectoryDefaultPageSize, Keyword: "_a"})
	if err != nil {
		t.Fatalf("關鍵字查詢應成功：%v", err)
	}
	if underscore.Total != 1 {
		t.Errorf("關鍵字 _a 應只命中描述裡真的帶它那一行，實際 %d", underscore.Total)
	}
	blank, err := e.service.Directory(context.Background(), principal, DirectoryQuery{Page: 1, PageSize: DirectoryDefaultPageSize, Keyword: "   "})
	if err != nil {
		t.Fatalf("全空白關鍵字等同沒帶，應成功：%v", err)
	}
	if blank.Total != 2 {
		t.Errorf("全空白關鍵字不應篩掉任何行，實際 Total=%d", blank.Total)
	}

	// 分頁界線：上限存在是讓回應體大小不由資料量決定，越界一律點名是哪個引數。
	if _, err := e.service.Directory(context.Background(), principal,
		DirectoryQuery{Page: 1, PageSize: DirectoryMaxPageSize + 1}); !errors.Is(err, ErrInvalidPageSize) {
		t.Errorf("page_size 越界應回報不合法，實際 %v", err)
	}
	if _, err := e.service.Directory(context.Background(), principal,
		DirectoryQuery{Page: 0, PageSize: 1}); !errors.Is(err, ErrInvalidPage) {
		t.Errorf("page=0 應回報不合法（預設值由傳輸層填，服務層不猜）；實際 %v", err)
	}
	if _, err := e.service.Directory(context.Background(), principal, DirectoryQuery{
		Page: 1, PageSize: DirectoryDefaultPageSize,
		Keyword: strings.Repeat("長", DirectoryKeywordMaxRunes+1),
	}); !errors.Is(err, ErrInvalidKeyword) {
		t.Errorf("超長關鍵字應回報不合法，實際 %v", err)
	}

	// 第二頁是空的但不是錯誤：目錄本來就要能回空頁。
	if page2, err := e.service.Directory(context.Background(), principal,
		DirectoryQuery{Page: 2, PageSize: 1}); err != nil {
		t.Fatalf("翻到第二頁應成功：%v", err)
	} else if len(page2.Rows) != 1 || page2.Total != 2 {
		t.Errorf("第二頁應剩一行而總數仍為 2，實際 Rows=%d Total=%d", len(page2.Rows), page2.Total)
	}
	// 翻過頭是空頁而不是錯誤：目錄本來就要能回空頁（總數不受分頁影響）。
	empty, err := e.service.Directory(context.Background(), principal,
		DirectoryQuery{Page: 3, PageSize: 1})
	if err != nil {
		t.Fatalf("翻過頭應回空頁：%v", err)
	}
	if len(empty.Rows) != 0 || empty.Total != 2 || empty.Page != 3 {
		t.Errorf("第三頁應為空頁而總數仍為 2，實際 Rows=%d Total=%d Page=%d",
			len(empty.Rows), empty.Total, empty.Page)
	}
}
