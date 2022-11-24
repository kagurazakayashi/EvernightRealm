package adminacct

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 測試口令：只活在測試進程的記憶體，不是任何環境的憑據。
const (
	testInitialPassword = "adminacct-test-一次性初始口令"
	testRootPassword    = "adminacct-test-root-口令"
	testNewPassword     = "adminacct-test-改後口令"
)

// testBase 為注入時鐘的錨點。
var testBase = time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

// env 是一次測試的完整現場：本次專屬的暫存庫與注入時鐘，加上組好的開設用例。
type env struct {
	db      *database.DB
	clock   *timeutil.Test
	logs    *bytes.Buffer
	service *Service
}

// newEnv 建立現場。口令雜湊用 credential.TestParams（低成本檔）：
// 本套件的斷言對象是「開設用例的落地與拒絕形態」，不是生產參數檔的算力。
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
		BusyTimeout: 2 * time.Second,
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
	service, err := New(Deps{
		DB:       db,
		Accounts: account.NewStore(clock),
		Grants:   grant.NewStore(clock),
		Audits:   audit.NewStore(clock),
		Hashing:  credential.TestParams,
		Log:      slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("建立開設用例失敗：%v", err)
	}
	return &env{db: db, clock: clock, logs: &logs, service: service}
}

// newAuthService 在同一現場組出登入用例，供「開出來的帳戶真能登入」這條閉環使用。
//
// 只借 authenticating 那套依賴，不改它的任何規定：Root 憑據欄放的是本次測試的
// 測試 Root 雜湊，會話期限取一小時，限流守衛留 nil（閉環不問限流）。
func (e *env) newAuthService(t *testing.T) *auth.Service {
	t.Helper()
	rootHash, err := credential.Hash(testRootPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試 Root 憑據失敗：%v", err)
	}
	sessions, err := session.NewStoreWithPolicy(e.clock, time.Hour, session.Policy{})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	service, err := auth.New(auth.Deps{
		DB:               e.db,
		Sessions:         sessions,
		Accounts:         account.NewStore(e.clock),
		Grants:           grant.NewStore(e.clock),
		Audits:           audit.NewStore(e.clock),
		RootPasswordHash: rootHash,
		Hashing:          credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立登入用例失敗：%v", err)
	}
	return service
}

// countRows 數一張表的行數（測試取證用，不参与任何生產判定）。
func countRows(t *testing.T, db *database.DB, table string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("計數 %s 失敗：%v", table, err)
	}
	return n
}

// mustCreate 開一個管理員並在失敗時終止測試。
func (e *env) mustCreate(t *testing.T, principal identity.Principal, login string) CreatedAdmin {
	t.Helper()
	created, err := e.service.CreateAdmin(context.Background(), principal, CreateInput{
		LoginName:       login,
		DisplayName:     "測試管理員",
		InitialPassword: testInitialPassword,
	}, "req-"+login)
	if err != nil {
		t.Fatalf("開設管理員 %s 失敗：%v", login, err)
	}
	return created
}

// TestCreateAdminWritesAccountGrantAndAudit 成功形態的三件寫入一起落地，且形態正確。
func TestCreateAdminWritesAccountGrantAndAudit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	created := e.mustCreate(t, identitytest.Root(t, identity.OriginHTTPRequest), "Ops-Kagurazaka")

	var (
		loginName, loginKey, hash, accountType, status string
		mustChange, createdAt                          int64
	)
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT login_name, login_name_key, password_hash,
		account_type, status, must_change_password, created_at FROM accounts WHERE id = ?`,
		created.AccountID.String()).
		Scan(&loginName, &loginKey, &hash, &accountType, &status, &mustChange, &createdAt); err != nil {
		t.Fatalf("讀回新建帳戶失敗：%v", err)
	}
	if loginName != "Ops-Kagurazaka" {
		t.Errorf("登入名應保留原始寫法，實際 %q", loginName)
	}
	if loginKey != "ops-kagurazaka" {
		t.Errorf("唯一鍵應為正規化結果，實際 %q", loginKey)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("憑據應為 Argon2id 編碼，實際前綴 %q", hash[:min(len(hash), 12)])
	}
	if hash == testInitialPassword || strings.Contains(hash, testInitialPassword) {
		t.Error("憑據欄不得出現口令明文")
	}
	if accountType != "standard" || status != "active" {
		t.Errorf("新建管理員應為 standard/active，實際 %s/%s", accountType, status)
	}
	if mustChange != 1 {
		t.Error("初始口令是一次性的：must_change_password 必須為 1")
	}
	if got := timeutil.FromMillis(createdAt); !got.Equal(testBase) {
		t.Errorf("建立時刻應取自注入時鐘 %v，實際 %v", testBase, got)
	}

	var grantedRole string
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT role FROM account_server_roles WHERE account_id = ?", created.AccountID.String()).
		Scan(&grantedRole); err != nil {
		t.Fatalf("讀回授予失敗：%v", err)
	}
	if grantedRole != identity.RoleServerAdmin.String() {
		t.Errorf("授予角色應為 %s，實際 %q", identity.RoleServerAdmin, grantedRole)
	}

	var (
		action, targetKind, targetID, actorKind, changes string
		reason                                           string
	)
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT action, target_kind, target_id, actor_kind, changes_json, reason
		FROM root_audit WHERE action = 'admin.create'`).
		Scan(&action, &targetKind, &targetID, &actorKind, &changes, &reason); err != nil {
		t.Fatalf("讀回審計失敗：%v", err)
	}
	if targetKind != "account" || targetID != created.AccountID.String() {
		t.Errorf("審計目標應指向新帳戶，實際 %s/%s", targetKind, targetID)
	}
	if actorKind != string(audit.ActorRoot) {
		t.Errorf("Root 域動作的審計主體應為 root，實際 %q", actorKind)
	}
	// 脫敏把關：整行原始內容（含 changes 的 JSON）既不得出現口令明文，也不得出現那串雜湊。
	rowText := action + targetKind + targetID + actorKind + changes + reason
	if strings.Contains(rowText, testInitialPassword) || strings.Contains(rowText, hash) {
		t.Error("審計記錄不得含口令明文或憑據雜湊")
	}
	if !strings.Contains(changes, identity.RoleServerAdmin.String()) {
		t.Errorf("審計變更摘要應記錄授予了哪個角色，實際 %s", changes)
	}

	if logs := e.logs.String(); strings.Contains(logs, testInitialPassword) || strings.Contains(logs, hash) {
		t.Error("執行日誌不得含口令明文或憑據雜湊")
	}
}

// TestCreateAdminRequiresRootPrincipal 只有 Root 主體能開設：普通帳戶與持角色的管理員都不行。
//
// 這條是「普通管理员不能创建同级管理员」的落點。判定只有一處
// （identity.Authorize + NeedRoot），且主體只能由服務端憑據換出：
// 請求裡沒有任何欄位可以自報 Root，因此也不存在「改一個欄位就升格」的路。
func TestCreateAdminRequiresRootPrincipal(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	plain := identitytest.Account(t, identitytest.NewID(t))
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	system := identitytest.System(t, identity.OriginCLI)

	for name, principal := range map[string]identity.Principal{
		"普通帳戶": plain,
		"管理帳戶": admin,
		"系統主體": system,
		"匿名主體": identity.Anonymous(),
	} {
		if _, err := e.service.CreateAdmin(ctx, principal, CreateInput{
			LoginName: "escalation-" + name, DisplayName: "企圖越權", InitialPassword: testInitialPassword,
		}, "req-deny"); !errors.Is(err, identity.ErrPermissionDenied) && !errors.Is(err, identity.ErrNotAuthenticated) {
			t.Errorf("%s 開設管理員應被拒為權限/身分錯誤，實際 %v", name, err)
		}
	}
	for _, table := range []string{"accounts", "account_server_roles", "root_audit"} {
		if n := countRows(t, e.db, table); n != 0 {
			t.Errorf("被拒的開設不得留下任何寫入（%s 有 %d 行）", table, n)
		}
	}
}

// TestCreateAdminRoleIsNotRequestControlled 開設結果與請求裡的任何角色宣稱無關。
//
// CreateInput 沒有角色欄位：能建出的形態只有一種。這條把「型別層沒有入口」釘成斷言，
// 免得日後有人「順手」加一個 role 欄位，讓建誰變成呼叫端說了算。
func TestCreateAdminRoleIsNotRequestControlled(t *testing.T) {
	e := newEnv(t)
	created := e.mustCreate(t, identitytest.Root(t, identity.OriginHTTPRequest), "no-self-claim")

	if len(created.Roles) != 1 || created.Roles[0] != identity.RoleServerAdmin {
		t.Errorf("結果應只帶服務端判定的授予，實際 %v", created.Roles)
	}
	// 回傳值與任何請求輸入無關：它也不得攜帶憑據材料。
	if strings.Contains(fmt.Sprintf("%+v", created), testInitialPassword) {
		t.Error("回傳結果不得含口令明文")
	}
}

// TestDuplicateLoginNameIsRejectedWithoutSecondWrite 重複登入名（含大小寫變體）：第二筆整筆不發生。
//
// 三個變體打的是同一個正規化鍵，因此資料庫唯一索引給出的就是「上一筆已經存在」這個答案；
// 失敗路徑不回顯任何舊憑據，也不追加第二筆審計——重複提交與丟失回應後的重試因此安全。
func TestDuplicateLoginNameIsRejectedWithoutSecondWrite(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	e.mustCreate(t, root, "Admin.One")

	for _, variant := range []string{"admin.one", "ADMIN.ONE", "Ａｄｍｉｎ.Ｏｎｅ"} {
		_, err := e.service.CreateAdmin(ctx, root, CreateInput{
			LoginName: variant, DisplayName: "重複提交", InitialPassword: "另一个一次性口令",
		}, "req-dup")
		if !errors.Is(err, ErrDuplicateLogin) {
			t.Errorf("%q 應被判為登入名已佔用，實際 %v", variant, err)
		}
		if strings.Contains(err.Error(), "另一个一次性口令") {
			t.Errorf("衝突錯誤不得回顯本次口令：%v", err)
		}
	}
	if n := countRows(t, e.db, "accounts"); n != 1 {
		t.Errorf("三次重複提交後仍只應有一行帳戶，實際 %d", n)
	}
	if n := countRows(t, e.db, "root_audit"); n != 1 {
		t.Errorf("被拒的開設不得追加審計，實際 %d 筆", n)
	}
}

// TestConcurrentSameLoginCreatesExactlyOneAccount 併發同鍵：只有一個贏家，且失敗者不污染資料。
func TestConcurrentSameLoginCreatesExactlyOneAccount(t *testing.T) {
	e := newEnv(t)
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	const attempts = 6
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		created int
		dup     int
		other   []error
	)
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			_, err := e.service.CreateAdmin(context.Background(), root, CreateInput{
				LoginName:       "race-one",
				DisplayName:     "併發開設",
				InitialPassword: fmt.Sprintf("%s-%d", testInitialPassword, i),
			}, fmt.Sprintf("req-race-%d", i))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				created++
			case errors.Is(err, ErrDuplicateLogin):
				dup++
			default:
				other = append(other, err)
			}
		}(i)
	}
	wg.Wait()

	if len(other) > 0 {
		t.Fatalf("併發開設只該出現成功或重複衝突，實際 %v", other)
	}
	if created != 1 {
		t.Errorf("成功開設應恰好一次，實際 %d", created)
	}
	if dup != attempts-1 {
		t.Errorf("其餘 %d 筆應全數被判為已佔用，實際 %d", attempts-1, dup)
	}
	if n := countRows(t, e.db, "accounts"); n != 1 {
		t.Errorf("資料庫應只有一行帳戶，實際 %d", n)
	}
	if n := countRows(t, e.db, "account_server_roles"); n != 1 {
		t.Errorf("授予行應與帳戶同行，實際 %d", n)
	}
}

// TestCreateAdminRollsBackWhenAuditCannotBeWritten 審計寫不進去＝帳戶與授予一起回滾。
//
// 「Root 域特權變更必留痕」这条规定的強度，取決於它能不能退化成一句日誌。
// 这里用 DROP TABLE 把審計那一跳做成必然失敗（測試專屬的暫存庫，不涉任何真實資料）。
func TestCreateAdminRollsBackWhenAuditCannotBeWritten(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("移除審計表失敗（測試前提）：%v", err)
	}

	root := identitytest.Root(t, identity.OriginHTTPRequest)
	if _, err := e.service.CreateAdmin(ctx, root, CreateInput{
		LoginName: "rollback-me", DisplayName: "回滾驗證", InitialPassword: testInitialPassword,
	}, "req-rollback"); err == nil {
		t.Fatal("審計寫入失敗時開設必須回報失敗")
	}
	if n := countRows(t, e.db, "accounts"); n != 0 {
		t.Errorf("回滾後不得留下帳戶，實際 %d 行", n)
	}
	if n := countRows(t, e.db, "account_server_roles"); n != 0 {
		t.Errorf("回滾後不得留下授予，實際 %d 行", n)
	}
}

// TestCreateAdminCanceledContextWritesNothing 交易開始前就被取消：一個字都不該落盤。
func TestCreateAdminCanceledContextWritesNothing(t *testing.T) {
	e := newEnv(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := e.service.CreateAdmin(canceled, identitytest.Root(t, identity.OriginHTTPRequest),
		CreateInput{LoginName: "never-lands", DisplayName: "取消驗證", InitialPassword: testInitialPassword},
		"req-cancel"); err == nil {
		t.Fatal("已取消的 context 必須讓開設失敗")
	}
	for _, table := range []string{"accounts", "account_server_roles"} {
		if n := countRows(t, e.db, table); n != 0 {
			t.Errorf("取消後 %s 不得有寫入，實際 %d 行", table, n)
		}
	}
}

// TestCreateAdminRejectsBadInputs 輸入不合規時不消耗寫入：空口令、超長口令、非法登入名。
func TestCreateAdminRejectsBadInputs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	cases := []struct {
		name  string
		input CreateInput
		want  error
	}{
		{"空口令", CreateInput{LoginName: "empty-pw", DisplayName: "x", InitialPassword: ""}, ErrInvalidInitialPassword},
		{"超長口令", CreateInput{LoginName: "huge-pw", DisplayName: "x",
			InitialPassword: strings.Repeat("長", credential.MaxPasswordLength)}, ErrInvalidInitialPassword},
		{"含空白登入名", CreateInput{LoginName: "bad name", DisplayName: "x",
			InitialPassword: testInitialPassword}, account.ErrInvalidLogin},
		{"空顯示名", CreateInput{LoginName: "empty-display", DisplayName: "  ",
			InitialPassword: testInitialPassword}, account.ErrInvalidDisplayName},
	}
	for _, tc := range cases {
		if _, err := e.service.CreateAdmin(ctx, root, tc.input, "req-bad-"+tc.name); !errors.Is(err, tc.want) {
			t.Errorf("%s 應被判為 %v，實際 %v", tc.name, tc.want, err)
		}
	}
	for _, table := range []string{"accounts", "account_server_roles", "root_audit"} {
		if n := countRows(t, e.db, table); n != 0 {
			t.Errorf("被拒的輸入不得留下任何寫入（%s 有 %d 行）", table, n)
		}
	}
}

// TestFirstSignInLoopCloses 開出來的帳戶真能登入、帶角色、被首次改密門閂約束，改完後一切如常。
//
// 這條是 R1-019 那把「服務端門閂」與本步「生產寫入通路」的接縫：旗標不再是只有測試工廠能造出的形態。
// 步驟按真實使用順序走，全部落在本次專屬的暫存庫與注入時鐘：
//  1. Root 開設 → 帳戶帶一次性口令落庫；
//  2. 新管理員以該口令登入 → 主體持 server_admin、旗標現讀為 true；
//  3. 本人改密 → 名下全部會話（含這一臺）撤銷；
//  4. 以新口令重新登入 → 解析出的主體仍持 server_admin、旗標已是 false。
func TestFirstSignInLoopCloses(t *testing.T) {
	e := newEnv(t)
	authService := e.newAuthService(t)
	ctx := context.Background()

	created := e.mustCreate(t, identitytest.Root(t, identity.OriginHTTPRequest), "first.sign.in")

	outcome, err := authService.LoginAccount(ctx, "First.Sign.In", testInitialPassword, "req-login", "127.0.0.1")
	if err != nil {
		t.Fatalf("新建管理員應能以初始口令登入：%v", err)
	}
	if !outcome.Principal.HasRole(identity.RoleServerAdmin) {
		t.Errorf("登入主體應持 server_admin，實際 %v", outcome.Principal.Roles())
	}
	if !outcome.MustChangePassword {
		t.Error("首次登入應回報「還欠一次改密」")
	}

	// 改密前：除必要入口之外的受保護端點在服務端被擋（這裡用同一把現讀閘的依據來斷言）。
	if mustChange, err := authService.MustChangePassword(ctx, outcome.Principal); err != nil || !mustChange {
		t.Fatalf("旗標現讀應為 true，實際 %v（err %v）", mustChange, err)
	}

	if _, err := authService.ChangePassword(ctx, outcome.Principal, testInitialPassword, testNewPassword, "req-change"); err != nil {
		t.Fatalf("以初始口令完成首次改密失敗：%v", err)
	}

	second, err := authService.LoginAccount(ctx, "first.sign.in", testNewPassword, "req-login-2", "127.0.0.1")
	if err != nil {
		t.Fatalf("改密後應能以新口令登入：%v", err)
	}
	if second.MustChangePassword {
		t.Error("改密成功後旗標必須已解除")
	}
	// 經會話解析換回主體：授予必須從資料庫現讀出來，而不是凍在登入那一刻。
	resolved, _, err := authService.Resolve(ctx, second.Secret)
	if err != nil {
		t.Fatalf("以新會話秘密解析主體失敗：%v", err)
	}
	if !resolved.HasRole(identity.RoleServerAdmin) {
		t.Errorf("會話解析出的主體應持 server_admin，實際 %v", resolved.Roles())
	}
	if _, err := authService.LoginAccount(ctx, "first.sign.in", testInitialPassword, "req-login-3", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("舊的一次性口令必須徹底失效，實際 %v", err)
	}
	if created.AccountID != outcome.Principal.AccountID() {
		t.Errorf("登入換回的主體應就是剛開出的帳戶：%s 對 %s", created.AccountID, outcome.Principal.AccountID())
	}
}

// TestUngrantedAccountResolvesWithoutRoles 沒有授予的帳戶：登入與解析都不帶任何角色。
//
// 這条断言守的是「授予表不能反向放寬」——查無授予是常态而不是缺陷，
// 也不允許把「查不到」解讀成「默認是管理員」。
func TestUngrantedAccountResolvesWithoutRoles(t *testing.T) {
	e := newEnv(t)
	authService := e.newAuthService(t)
	ctx := context.Background()

	hash, err := credential.Hash(testInitialPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	if _, err := e.service.accounts.Create(ctx, e.db.SQL(), account.NewInput{
		LoginName: "plain.account", DisplayName: "普通帳戶", PasswordHash: hash,
		Type: account.TypeStandard, Status: account.StatusActive, MustChangePassword: true,
	}); err != nil {
		t.Fatalf("種入普通帳戶失敗：%v", err)
	}

	outcome, err := authService.LoginAccount(ctx, "plain.account", testInitialPassword, "req-plain", "127.0.0.1")
	if err != nil {
		t.Fatalf("普通帳戶登入失敗：%v", err)
	}
	if len(outcome.Principal.Roles()) != 0 {
		t.Errorf("無授予的帳戶不應帶出角色，實際 %v", outcome.Principal.Roles())
	}
	resolved, _, err := authService.Resolve(ctx, outcome.Secret)
	if err != nil {
		t.Fatalf("解析主體失敗：%v", err)
	}
	if len(resolved.Roles()) != 0 {
		t.Errorf("會話解析也不應凭空多出角色，實際 %v", resolved.Roles())
	}
}

// TestListAdminsShowsOnlyGrantedAccounts 最小列表：只列持有授予者，普通帳戶不出现，且不携带凭据。
func TestListAdminsShowsOnlyGrantedAccounts(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	first := e.mustCreate(t, root, "list.one")
	e.clock.Advance(time.Minute)
	second := e.mustCreate(t, root, "list.two")

	hash, err := credential.Hash(testInitialPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	if _, err := e.service.accounts.Create(ctx, e.db.SQL(), account.NewInput{
		LoginName: "list.plain", DisplayName: "不該出現", PasswordHash: hash,
		Type: account.TypeStandard, Status: account.StatusActive, MustChangePassword: true,
	}); err != nil {
		t.Fatalf("種入普通帳戶失敗：%v", err)
	}

	list, err := e.service.ListAdmins(ctx, root)
	if err != nil {
		t.Fatalf("列舉管理員失敗：%v", err)
	}
	if len(list) != 2 {
		t.Fatalf("應恰好列出兩位管理員，實際 %d 筆", len(list))
	}
	if list[0].AccountID != second.AccountID || list[1].AccountID != first.AccountID {
		t.Errorf("清單應依授予時刻倒序，實際 %s 在前", list[0].AccountID)
	}
	for _, item := range list {
		if item.MustChangePassword != true {
			t.Errorf("%s 仍欠首次改密，列表應如實回報", item.AccountID)
		}
		if !item.LastLoginAt.IsZero() {
			t.Errorf("從未登入的帳戶不得被填上登入時刻，實際 %v", item.LastLoginAt)
		}
	}
	text := fmt.Sprintf("%+v", list)
	if strings.Contains(text, testInitialPassword) || strings.Contains(text, "$argon2id$") {
		t.Error("列表結果不得含口令明文或憑據雜湊")
	}

	// 同一道閘：普通帳戶（含持有角色的）都列不到。
	if _, err := e.service.ListAdmins(ctx, identitytest.Account(t, identitytest.NewID(t),
		identitytest.ServerAdmin())); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("非 Root 列舉應被拒為權限不足，實際 %v", err)
	}
}

// TestListAdminsEmptyBeforeAnyCreation 一個管理員都還沒開過時：回空清單而不是錯誤。
func TestListAdminsEmptyBeforeAnyCreation(t *testing.T) {
	e := newEnv(t)
	list, err := e.service.ListAdmins(context.Background(), identitytest.Root(t, identity.OriginHTTPRequest))
	if err != nil {
		t.Fatalf("空清單不該是錯誤：%v", err)
	}
	if len(list) != 0 {
		t.Errorf("尚無授予時應回空清單，實際 %d 筆", len(list))
	}
}

// TestNewRejectsMissingDeps 缺依賴是組裝缺陷：在啟動階段就報出來，不帶病上線。
func TestNewRejectsMissingDeps(t *testing.T) {
	e := newEnv(t)
	valid := Deps{
		DB: e.db, Accounts: e.service.accounts, Grants: e.service.grants,
		Audits: audit.NewStore(e.clock), Hashing: credential.TestParams,
	}
	for _, mutate := range []func(*Deps){
		func(d *Deps) { d.DB = nil },
		func(d *Deps) { d.Accounts = nil },
		func(d *Deps) { d.Grants = nil },
		func(d *Deps) { d.Audits = nil },
	} {
		deps := valid
		mutate(&deps)
		if _, err := New(deps); err == nil {
			t.Error("缺少必要依賴時 New 必須報錯")
		}
	}
	if _, err := New(Deps{DB: e.db, Accounts: e.service.accounts, Grants: e.service.grants,
		Audits: audit.NewStore(e.clock), Hashing: credential.Params{}}); err == nil {
		t.Error("全零參數檔應被拒：它無法產生可用的憑據")
	}
}
