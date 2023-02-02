// stdacct_test.go 是「管理員建立普通帳戶」用例的定向證據：
// 成功形態、策略現讀的兩個方向、授權矩陣（含 Root 無例外）、重複與併發收口、
// 審計的真實歸屬（actor=admin、ScopeRoot 不帶 activity_id）、事務回滾與脫敏。
//
// 全程使用本次專屬的暫存庫與注入時鐘：不佔 5206、不碰任何真實資料目錄。
package stdacct

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
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
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
	testInitialPassword = "stdacct-test-一次性初始口令"
	testRootPassword    = "stdacct-test-root-口令"
	testNewPassword     = "stdacct-test-改後口令"
)

// testBase 為注入時鐘的錨點。
var testBase = time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)

// env 是一次測試的完整現場：專屬暫存庫、注入時鐘，加上組好的建立用例與策略倉儲。
type env struct {
	db       *database.DB
	clock    *timeutil.Test
	logs     *bytes.Buffer
	policy   *acctpolicy.Store
	sessions *session.Store
	service  *Service
}

// newEnv 建立現場。口令雜湊用 credential.TestParams（低成本檔）：
// 本套件的斷言對象是「建立用例的落地與拒絕形態」，不是生產參數檔的算力。
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
	policyStore := acctpolicy.NewStore(clock)
	sessions, err := session.NewStoreWithPolicy(clock, time.Hour, session.Policy{})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	service, err := New(Deps{
		DB:       db,
		Accounts: account.NewStore(clock),
		Policy:   policyStore,
		Audits:   audit.NewStore(clock),
		Hashing:  credential.TestParams,
		Log:      slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("建立普通帳戶用例失敗：%v", err)
	}
	e := &env{db: db, clock: clock, logs: &logs, policy: policyStore, sessions: sessions, service: service}
	// 出廠策略是三個入口全關；多數用例要的是「開著」的現場，預設把管理員建號打開。
	// 需要的用例各自再關回去——關回去的路徑由那些用例自己斷言。
	e.setAdminCreate(t, true)
	return e
}

// setAdminCreate 經策略倉儲（與生產同一個寫入點）翻動 admin_create_standard，
// 其餘兩欄保持出廠形態：不直寫 SQL，免得像繞過了誰。
func (e *env) setAdminCreate(t *testing.T, on bool) {
	t.Helper()
	_, err := e.policy.Put(context.Background(), e.db.SQL(), acctpolicy.Policy{
		AdminCreateStandard: on,
		SelfRegisterMode:    acctpolicy.ModeClosed,
		GuestEnabled:        false,
	})
	if err != nil {
		t.Fatalf("設定帳戶建立策略失敗：%v", err)
	}
}

// countRows 數一張表的行數（測試取證用，不參與任何生產判定）。
func countRows(t *testing.T, db *database.DB, table string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("計數 %s 失敗：%v", table, err)
	}
	return n
}

// mustCreate 建一個普通帳戶並在失敗時終止測試。
func (e *env) mustCreate(t *testing.T, principal identity.Principal, login string) CreatedAccount {
	t.Helper()
	created, err := e.service.CreateStandardAccount(context.Background(), principal, CreateInput{
		LoginName:       login,
		DisplayName:     "測試普通帳戶",
		InitialPassword: testInitialPassword,
	}, "req-"+login)
	if err != nil {
		t.Fatalf("建立普通帳戶 %s 失敗：%v", login, err)
	}
	return created
}

// TestCreateWritesAccountAndAdminAudit 成功形態：帳戶與 Root 域審計一起落地，
// 且審計的操作者是「那位管理員本人」——actor.kind=admin、actor.id 是他的帳戶標識，
// activity_id 為 NULL（建號不屬於任何活動，不捏造），也不是冒充 Root 的保留標識。
func TestCreateWritesAccountAndAdminAudit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "Player.One")

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
	if loginName != "Player.One" {
		t.Errorf("登入名應保留原始寫法，實際 %q", loginName)
	}
	if loginKey != "player.one" {
		t.Errorf("唯一鍵應為正規化結果，實際 %q", loginKey)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("憑據應為 Argon2id 編碼，實際前綴 %q", hash[:min(len(hash), 12)])
	}
	if hash == testInitialPassword || strings.Contains(hash, testInitialPassword) {
		t.Error("憑據欄不得出現口令明文")
	}
	if accountType != "standard" || status != "active" {
		t.Errorf("新建帳戶應為 standard/active，實際 %s/%s", accountType, status)
	}
	if mustChange != 1 {
		t.Error("初始口令是一次性的：must_change_password 必須為 1")
	}
	if got := timeutil.FromMillis(createdAt); !got.Equal(testBase) {
		t.Errorf("建立時刻應取自注入時鐘 %v，實際 %v", testBase, got)
	}
	// 建的只是 Account：沒有任何授予行——「建號即加入管理員目錄」不成立在資料上。
	if n := countRows(t, e.db, "account_server_roles"); n != 0 {
		t.Errorf("新建普通帳戶不得持有任何伺服器級授予，實際 %d 行", n)
	}

	var (
		action, targetKind, targetID, actorKind, actorID, changes, reason string
	)
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT action, target_kind, target_id, actor_kind,
		actor_id, changes_json, reason FROM root_audit WHERE action = 'account.create_standard'`).
		Scan(&action, &targetKind, &targetID, &actorKind, &actorID, &changes, &reason); err != nil {
		t.Fatalf("讀回審計失敗：%v", err)
	}
	if targetKind != "account" || targetID != created.AccountID.String() {
		t.Errorf("審計目標應指向新帳戶，實際 %s/%s", targetKind, targetID)
	}
	if actorKind != string(audit.ActorAdmin) {
		t.Errorf("管理員的伺服器級動作應記 actor=admin，實際 %q", actorKind)
	}
	if actorID != admin.AccountID().String() {
		t.Errorf("審計應記真實操作者的帳戶標識，實際 %q（應為 %s）", actorID, admin.AccountID())
	}
	// 「不捏造 activity_id」的 strongest 形態是結構性的：root_audit 根本沒有這一欄
	// （遷移 0002 的頭注寫明這是刻意的），想冒充活動歸屬連格子都沒有。
	if _, err := e.db.SQL().ExecContext(ctx,
		"SELECT activity_id FROM root_audit LIMIT 0"); err == nil {
		t.Error("root_audit 不該有 activity_id 欄位：那是「Root 事件不屬於任何活動」的結構證據")
	}
	rowText := action + targetKind + targetID + actorKind + actorID + changes + reason
	if strings.Contains(rowText, testInitialPassword) || strings.Contains(rowText, hash) {
		t.Error("審計記錄不得含口令明文或憑據雜湊")
	}
	if strings.Contains(rowText, "server_roles") {
		t.Error("建的帳戶恆無授予，審計不得記一件不存在的事")
	}
	if logs := e.logs.String(); strings.Contains(logs, testInitialPassword) || strings.Contains(logs, hash) {
		t.Error("執行日誌不得含口令明文或憑據雜湊")
	}
}

// TestPolicyJudgedAtWriteTime 策略在寫入那一刻現讀，兩個方向都必須立即生效：
// 關著不寫一行、開著就建得成、再關回去下一條又必須被拒。
//
// 這一條釘的是「預讀通過後才寫入」那個窗口不存在：判定依據與寫入同屬一筆交易，
// Root 翻開關不需要通知誰，下一條請求讀到的就是新值。
func TestPolicyJudgedAtWriteTime(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())

	e.setAdminCreate(t, false)
	if _, err := e.service.CreateStandardAccount(ctx, admin, CreateInput{
		LoginName: "gated.off", DisplayName: "策略擋下", InitialPassword: testInitialPassword,
	}, "req-gated"); !errors.Is(err, ErrCreateDisabled) {
		t.Errorf("開關關閉時應回可判別的未開放結論，實際 %v", err)
	}
	for _, table := range []string{"accounts", "root_audit"} {
		if n := countRows(t, e.db, table); n != 0 {
			t.Errorf("被策略擋下的建立不得留下任何寫入（%s 有 %d 行）", table, n)
		}
	}

	e.setAdminCreate(t, true)
	e.mustCreate(t, admin, "gated.on")

	e.setAdminCreate(t, false)
	if _, err := e.service.CreateStandardAccount(ctx, admin, CreateInput{
		LoginName: "gated.again", DisplayName: "再關又擋", InitialPassword: testInitialPassword,
	}, "req-gated-2"); !errors.Is(err, ErrCreateDisabled) {
		t.Errorf("重新關閉後的下一條請求必須按新值判定，實際 %v", err)
	}
	if n := countRows(t, e.db, "accounts"); n != 1 {
		t.Errorf("只該有放行那一次的一行帳戶，實際 %d", n)
	}
	if n := countRows(t, e.db, "root_audit"); n != 1 {
		t.Errorf("被策略擋下的建立不得追加審計，實際 %d 筆", n)
	}
}

// TestRootNotExemptWhenClosed 開關對 Root 沒有例外：走這條端點的 Root 同樣被策略擋。
//
// 放行時他的動作照實記 actor=root（不是冒充管理員、也不是降級成 system），
// 而 Root 自己的開管理員通路不在本測試範圍（那由 /root/admins 的合同負責）。
func TestRootNotExemptWhenClosed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	e.setAdminCreate(t, false)
	if _, err := e.service.CreateStandardAccount(ctx, root, CreateInput{
		LoginName: "root.via.admin.path", DisplayName: "Root 走管理員路", InitialPassword: testInitialPassword,
	}, "req-root-off"); !errors.Is(err, ErrCreateDisabled) {
		t.Errorf("Root 走 /admin 通路時同受開關約束，實際 %v", err)
	}

	e.setAdminCreate(t, true)
	created := e.mustCreate(t, root, "root.via.admin.ok")
	var actorKind, actorID string
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT actor_kind, actor_id FROM root_audit WHERE target_id = ?", created.AccountID.String()).
		Scan(&actorKind, &actorID); err != nil {
		t.Fatalf("讀回 Root 建號審計失敗：%v", err)
	}
	rootID, err := identity.RootSubjectID()
	if err != nil {
		t.Fatalf("取得 Root 保留標識失敗：%v", err)
	}
	if actorKind != string(audit.ActorRoot) || actorID != rootID.String() {
		t.Errorf("Root 的動作應照實記 actor=root＋保留標識，實際 %s／%s", actorKind, actorID)
	}
}

// TestAuthorizationMatrix 只有伺服器級管理權的主體碰得到建立通路：
// 普通帳戶、系統主體與匿名都被拒在授權那一跳，不消耗派生、不碰資料庫、不寫審計。
func TestAuthorizationMatrix(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	for name, principal := range map[string]identity.Principal{
		"普通帳戶": identitytest.Account(t, identitytest.NewID(t)),
		"訪客帳戶": identitytest.Account(t, identitytest.NewID(t), identitytest.WithGuestType()),
		"系統主體": identitytest.System(t, identity.OriginCLI),
		"匿名主體": identity.Anonymous(),
	} {
		if _, err := e.service.CreateStandardAccount(ctx, principal, CreateInput{
			LoginName: "escalation-" + name, DisplayName: "企圖越權", InitialPassword: testInitialPassword,
		}, "req-deny"); !errors.Is(err, identity.ErrPermissionDenied) && !errors.Is(err, identity.ErrNotAuthenticated) {
			t.Errorf("%s 建立普通帳戶應被拒為權限/身分錯誤，實際 %v", name, err)
		}
	}
	for _, table := range []string{"accounts", "root_audit"} {
		if n := countRows(t, e.db, table); n != 0 {
			t.Errorf("被拒的建立不得留下任何寫入（%s 有 %d 行）", table, n)
		}
	}
}

// TestCreatedShapeIsNotRequestControlled 建立的形態與請求輸入無關：
// CreateInput 只有三個欄位，類型、狀態、旗標由用例寫死，授予恆零。
//
// 這條把「型別層沒有入口」釘成斷言，免得日後有人「順手」加一個 role 或 status 欄位，
// 讓「建的是哪一類人」變成呼叫端說了算。
func TestCreatedShapeIsNotRequestControlled(t *testing.T) {
	e := newEnv(t)
	created := e.mustCreate(t,
		identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin()), "no-self-claim")

	if created.Status != account.StatusActive || !created.MustChangePassword {
		t.Errorf("結果應只帶服務端判定的形態，實際 %+v", created)
	}
	// 回傳值也不得攜帶憑據材料。
	if strings.Contains(fmt.Sprintf("%+v", created), testInitialPassword) {
		t.Error("回傳結果不得含口令明文")
	}
}

// TestDuplicateLoginNameIsRejectedWithoutSecondWrite 重複登入名（含大小寫／全形變體）：
// 第二筆整筆不發生，第一筆的事實與審計都不動。
func TestDuplicateLoginNameIsRejectedWithoutSecondWrite(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	e.mustCreate(t, admin, "Dup.One")

	for _, variant := range []string{"dup.one", "DUP.ONE", "Ｄｕｐ.Ｏｎｅ"} {
		_, err := e.service.CreateStandardAccount(ctx, admin, CreateInput{
			LoginName: variant, DisplayName: "重複提交", InitialPassword: "另一個一次性口令",
		}, "req-dup")
		if !errors.Is(err, ErrDuplicateLogin) {
			t.Errorf("%q 應被判為登入名已佔用，實際 %v", variant, err)
		}
		if strings.Contains(err.Error(), "另一個一次性口令") {
			t.Errorf("衝突錯誤不得回顯本次口令：%v", err)
		}
	}
	if n := countRows(t, e.db, "accounts"); n != 1 {
		t.Errorf("三次重複提交後仍只應有一行帳戶，實際 %d", n)
	}
	if n := countRows(t, e.db, "root_audit"); n != 1 {
		t.Errorf("被拒的建立不得追加審計，實際 %d 筆", n)
	}
}

// TestConcurrentSameLoginCreatesExactlyOneAccount 併發同鍵：只有一個贏家，其餘收口到已佔用。
func TestConcurrentSameLoginCreatesExactlyOneAccount(t *testing.T) {
	e := newEnv(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())

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
			_, err := e.service.CreateStandardAccount(context.Background(), admin, CreateInput{
				LoginName:       "race-one",
				DisplayName:     "併發建立",
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
		t.Fatalf("併發建立只該出現成功或重複衝突，實際 %v", other)
	}
	if created != 1 {
		t.Errorf("成功建立應恰好一次，實際 %d", created)
	}
	if dup != attempts-1 {
		t.Errorf("其餘 %d 筆應全數被判為已佔用，實際 %d", attempts-1, dup)
	}
	if n := countRows(t, e.db, "accounts"); n != 1 {
		t.Errorf("資料庫應只有一行帳戶，實際 %d", n)
	}
	if n := countRows(t, e.db, "root_audit"); n != 1 {
		t.Errorf("贏家一筆之外落敗者不配留審計，實際 %d 筆", n)
	}
}

// TestCreateRollsBackWhenAuditCannotBeWritten 審計寫不進去＝帳戶一起回滾。
//
// 「管理員的伺服器級動作必留痕」的強度取決於它能不能退化成一句日誌——這裡用
// DROP TABLE 把審計那一跳做成必然失敗（測試專屬暫存庫，不涉任何真實資料）。
func TestCreateRollsBackWhenAuditCannotBeWritten(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("移除審計表失敗（測試前提）：%v", err)
	}
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	if _, err := e.service.CreateStandardAccount(ctx, admin, CreateInput{
		LoginName: "rollback-me", DisplayName: "回滾驗證", InitialPassword: testInitialPassword,
	}, "req-rollback"); err == nil {
		t.Fatal("審計寫入失敗時建立必須回報失敗")
	}
	if n := countRows(t, e.db, "accounts"); n != 0 {
		t.Errorf("回滾後不得留下帳戶，實際 %d 行", n)
	}
}

// TestCanceledContextWritesNothing 交易開始前就被取消：一個字都不該落盤。
func TestCanceledContextWritesNothing(t *testing.T) {
	e := newEnv(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	if _, err := e.service.CreateStandardAccount(canceled, admin, CreateInput{
		LoginName: "never-lands", DisplayName: "取消驗證", InitialPassword: testInitialPassword,
	}, "req-cancel"); err == nil {
		t.Fatal("已取消的 context 必須讓建立失敗")
	}
	for _, table := range []string{"accounts", "root_audit"} {
		if n := countRows(t, e.db, table); n != 0 {
			t.Errorf("取消後 %s 不得有寫入，實際 %d 行", table, n)
		}
	}
}

// TestRejectsBadInputs 輸入不合規時不消耗寫入：空口令、超長口令、非法登入名、空顯示名。
func TestRejectsBadInputs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())

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
		if _, err := e.service.CreateStandardAccount(ctx, admin, tc.input, "req-bad-"+tc.name); !errors.Is(err, tc.want) {
			t.Errorf("%s 應被判為 %v，實際 %v", tc.name, tc.want, err)
		}
	}
	for _, table := range []string{"accounts", "root_audit"} {
		if n := countRows(t, e.db, table); n != 0 {
			t.Errorf("被拒的輸入不得留下任何寫入（%s 有 %d 行）", table, n)
		}
	}
}

// newAuthService 在同一現場組出登入用例，供「建出來的普通帳戶真能登入」這條閉環使用。
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

// TestFirstSignInLoopCloses 建出來的普通帳戶真能走第一部分那條通路：
// 初始口令登入 → 主體不帶任何角色、帶著首次改密義務 → 改密 → 舊口令徹底失效。
//
// 這條是「普通帳戶通過既有的真實登入、改密功能使用系統」的接縫證據：
// 旗標與形態不再是只有測試工廠能造出的東西，而是管理員經端點建出的事實。
func TestFirstSignInLoopCloses(t *testing.T) {
	e := newEnv(t)
	authService := e.newAuthService(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())

	created := e.mustCreate(t, admin, "std.first.sign.in")

	outcome, err := authService.LoginAccount(ctx, "Std.First.Sign.In", testInitialPassword, "req-login", "127.0.0.1")
	if err != nil {
		t.Fatalf("新建普通帳戶應能以初始口令登入：%v", err)
	}
	if len(outcome.Principal.Roles()) != 0 {
		t.Errorf("普通帳戶不應帶出任何伺服器級角色，實際 %v", outcome.Principal.Roles())
	}
	if !outcome.MustChangePassword {
		t.Error("首次登入應回報「還欠一次改密」")
	}
	if mustChange, err := authService.MustChangePassword(ctx, outcome.Principal); err != nil || !mustChange {
		t.Fatalf("旗標現讀應為 true，實際 %v（err %v）", mustChange, err)
	}

	if _, err := authService.ChangePassword(ctx, outcome.Principal, testInitialPassword, testNewPassword, "req-change"); err != nil {
		t.Fatalf("以初始口令完成首次改密失敗：%v", err)
	}
	second, err := authService.LoginAccount(ctx, "std.first.sign.in", testNewPassword, "req-login-2", "127.0.0.1")
	if err != nil {
		t.Fatalf("改密後應能以新口令登入：%v", err)
	}
	if second.MustChangePassword {
		t.Error("改密成功後旗標必須已解除")
	}
	resolved, _, err := authService.Resolve(ctx, second.Secret)
	if err != nil {
		t.Fatalf("以新會話秘密解析主體失敗：%v", err)
	}
	if len(resolved.Roles()) != 0 {
		t.Errorf("會話解析也不該憑空多出角色，實際 %v", resolved.Roles())
	}
	if _, err := authService.LoginAccount(ctx, "std.first.sign.in", testInitialPassword, "req-login-3", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("舊的一次性口令必須徹底失效，實際 %v", err)
	}
	if created.AccountID != outcome.Principal.AccountID() {
		t.Errorf("登入換回的主體應就是剛建出的帳戶：%s 對 %s", created.AccountID, outcome.Principal.AccountID())
	}
}

// TestNewRejectsMissingDeps 缺依賴是組裝缺陷：在啟動階段就報出來，不帶病上線。
func TestNewRejectsMissingDeps(t *testing.T) {
	e := newEnv(t)
	valid := Deps{
		DB: e.db, Accounts: e.service.accounts, Policy: e.policy,
		Audits: audit.NewStore(e.clock), Hashing: credential.TestParams,
	}
	for _, mutate := range []func(*Deps){
		func(d *Deps) { d.DB = nil },
		func(d *Deps) { d.Accounts = nil },
		func(d *Deps) { d.Policy = nil },
		func(d *Deps) { d.Audits = nil },
	} {
		deps := valid
		mutate(&deps)
		if _, err := New(deps); err == nil {
			t.Error("缺少必要依賴時 New 必須報錯")
		}
	}
	if _, err := New(Deps{DB: e.db, Accounts: e.service.accounts, Policy: e.policy,
		Audits: audit.NewStore(e.clock), Hashing: credential.Params{}}); err == nil {
		t.Error("全零參數檔應被拒：它無法產生可用的憑據")
	}
}
