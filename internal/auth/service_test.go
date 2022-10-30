package auth

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 測試口令：只活在測試進程的記憶體，不是任何環境的憑據，也不得進斷言訊息之外的地方。
const (
	testAccountPassword = "auth-test-帳戶口令"
	testRootPassword    = "auth-test-root-口令"
	// testSourceIP 是測試裡固定的「連線來源位址」：登入用例的守衛計量以它為鍵之一，
	// 值本身只是可計量的占位地址，不是任何環境的地址，也不得進斷言之外的輸出。
	testSourceIP = "127.0.0.1"
)

// testBase 為注入時鐘的錨點。
var testBase = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

// env 是一次測試的完整現場：專屬暫存庫、注入時鐘與組好的登入用例。
type env struct {
	db       *database.DB
	clock    timeutil.Clock
	sessions *session.Store
	accounts *account.Store
	service  *Service
	rootHash string
}

// newEnv 建立現場；rootConfigured=false 時 Root 憑據欄留空（重現「尚未初始化」部署）。
func newEnv(t *testing.T, rootConfigured bool) *env {
	t.Helper()
	return newEnvWithPolicy(t, rootConfigured, session.Policy{}, time.Hour, nil)
}

// newEnvWithPolicy 同 newEnv，但會話倉儲帶指定策略與期限，並可接上真實登入守衛。
//
// 存在的理由是裝置名額用例需要「同一現場、不同策略」：名額的判定就落在登入事務裡，
// 換一套現場等於換一組前提，斷言就不再指向同一件事。
func newEnvWithPolicy(t *testing.T, rootConfigured bool, policy session.Policy,
	ttl time.Duration, guard *LoginGuard) *env {
	t.Helper()
	clock := timeutil.NewTest(testBase)
	dir := t.TempDir()
	t.Cleanup(func() {
		// Windows 的 SQLite 句柄釋放有落後：清理走有限次數重試，殘留如實報告。
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			t.Errorf("暫存目錄清理失敗：%v", err)
		}
	})
	dbPath := filepath.Join(dir, "evernight.db")
	db, err := database.Open(context.Background(), database.Options{
		Path:        dbPath,
		BusyTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: clock}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	sessions, err := session.NewStoreWithPolicy(clock, ttl, policy)
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	rootHash := ""
	if rootConfigured {
		rootHash, err = credential.Hash(testRootPassword, credential.TestParams)
		if err != nil {
			t.Fatalf("產生測試 Root 憑據失敗：%v", err)
		}
	}
	service, err := New(Deps{
		DB:               db,
		Sessions:         sessions,
		Accounts:         account.NewStore(clock),
		Audits:           audit.NewStore(clock),
		RootPasswordHash: rootHash,
		Hashing:          credential.TestParams,
		Guard:            guard,
	})
	if err != nil {
		t.Fatalf("建立登入用例失敗：%v", err)
	}
	return &env{db: db, clock: clock, sessions: sessions, accounts: account.NewStore(clock), service: service, rootHash: rootHash}
}

// createAccount 落一個可登入的標準帳戶（憑據為 testAccountPassword 的真實雜湊）。
func (e *env) createAccount(t *testing.T, login string, status account.Status) account.Account {
	t.Helper()
	hash, err := credential.Hash(testAccountPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	in := account.NewInput{
		LoginName:    login,
		DisplayName:  "登入測試帳戶",
		PasswordHash: hash,
		Type:         account.TypeStandard,
		Status:       status,
	}
	if status == account.StatusDisabled {
		in.DisabledAt = e.clock.Now()
	}
	a, err := e.accounts.Create(context.Background(), e.db.SQL(), in)
	if err != nil {
		t.Fatalf("建立測試帳戶失敗：%v", err)
	}
	return a
}

// countSessions 統計會話行數（斷言「失敗零簽發」用）。
func countSessions(t *testing.T, db *database.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sessions").Scan(&n); err != nil {
		t.Fatalf("統計會話失敗：%v", err)
	}
	return n
}

// countRootAudit 按動作統計 Root 域審計。
func countRootAudit(t *testing.T, db *database.DB, action string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = ?", action).Scan(&n); err != nil {
		t.Fatalf("統計審計失敗：%v", err)
	}
	return n
}

// TestLoginAccountSuccessIssuesSession 驗證成功路徑的三件落地：會話行、
// last_login_at、回傳的秘密可被解析回同一主體；且第二次登入簽發的是另一枚新會話。
func TestLoginAccountSuccessIssuesSession(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	a := e.createAccount(t, "login_ok", account.StatusActive)

	first, err := e.service.LoginAccount(ctx, "LOGIN_OK", testAccountPassword, "req-1", testSourceIP)
	if err != nil {
		t.Fatalf("登入應成功：%v", err)
	}
	if first.Principal.AccountID() != a.ID {
		t.Errorf("主體標識不符：%v", first.Principal.AccountID())
	}
	if got := countSessions(t, e.db); got != 1 {
		t.Fatalf("應有 1 行會話，實際 %d", got)
	}
	stored, err := e.accounts.ByID(ctx, e.db.SQL(), a.ID)
	if err != nil {
		t.Fatalf("讀回帳戶失敗：%v", err)
	}
	if stored.LastLoginAt.IsZero() {
		t.Errorf("成功登入必須推進 last_login_at")
	}

	second, err := e.service.LoginAccount(ctx, "login_ok", testAccountPassword, "req-2", testSourceIP)
	if err != nil {
		t.Fatalf("第二次登入應成功：%v", err)
	}
	if second.Session.ID == first.Session.ID || second.Secret == first.Secret {
		t.Errorf("每次登入必須簽發新會話（防固定攻擊）：%v vs %v", first.Session.ID, second.Session.ID)
	}

	principal, _, err := e.service.Resolve(ctx, second.Secret)
	if err != nil || principal.AccountID() != a.ID {
		t.Fatalf("秘密應可解析回同一帳戶：%v %v", principal.AccountID(), err)
	}
}

// TestLoginAccountRejectionsAreIndistinguishable 驗證「查無此人／口令錯／已禁用／
// 訪客帳戶／空口令」全部收斂為同一個 ErrInvalidCredentials，且任何一條都零簽發。
//
// 錯誤型別相同只是第一步；斷言把「回應層拿得到內部原因」這條路也釘死：
// 服務不回任何可供分流的第二個值。
func TestLoginAccountRejectionsAreIndistinguishable(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.createAccount(t, "login_wrongpw", account.StatusActive)
	disabled := e.createAccount(t, "login_disabled", account.StatusDisabled)

	// 訪客帳戶：無口令通路（guest 快捷登入屬後續步驟）。
	guestHash := ""
	guest, err := e.accounts.Create(ctx, e.db.SQL(), account.NewInput{
		LoginName: "login_guest", DisplayName: "訪客", PasswordHash: guestHash,
		Type: account.TypeGuest, Status: account.StatusActive,
	})
	if err != nil || guest.ID.IsNil() {
		t.Fatalf("建立訪客帳戶失敗：%v", err)
	}

	cases := []struct{ name, login, password string }{
		{"unknown", "不存在的登入名", testAccountPassword},
		{"wrong-password", "login_wrongpw", "錯的口令"},
		{"disabled", "login_disabled", testAccountPassword},
		{"guest", "login_guest", testAccountPassword},
		{"empty-password", "login_wrongpw", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.service.LoginAccount(ctx, tc.login, tc.password, "req", testSourceIP)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("應收斂為 ErrInvalidCredentials，實際 %v", err)
			}
			outcome, err2 := e.service.LoginAccount(ctx, tc.login, tc.password, "req", testSourceIP)
			if err2 == nil || outcome.Secret != "" || !outcome.Session.ID.IsNil() || outcome.Principal.Kind() != identity.KindAnonymous {
				t.Fatalf("失敗路徑不可回傳任何結果：%v %+v", err2, outcome)
			}
			if n := countSessions(t, e.db); n != 0 {
				t.Fatalf("拒絕路徑不可簽發會話，現有 %d 行", n)
			}
		})
	}
	_ = disabled
}

// TestLoginRootSuccessAuditsInTransaction 驗證 Root 登入：會話與 root_audit
// 的 auth.login_success 在同一個交易成立，解析換回的主體能過 NeedRoot。
func TestLoginRootSuccessAuditsInTransaction(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	outcome, err := e.service.LoginRoot(ctx, testRootPassword, "req-root-1", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入應成功：%v", err)
	}
	if !outcome.Principal.IsRoot() {
		t.Fatalf("主體應為 Root：%s", outcome.Principal.Kind().String())
	}
	if n := countSessions(t, e.db); n != 1 {
		t.Fatalf("應有 1 行會話，實際 %d", n)
	}
	if n := countRootAudit(t, e.db, "auth.login_success"); n != 1 {
		t.Fatalf("應有 1 筆 Root 登入成功審計，實際 %d", n)
	}
	// 審計與會話同交易：審計裡點名的 target 就是剛簽發的會話。
	if n := countRootAuditNamed(t, e.db, "auth.login_success", outcome.Session.ID.String()); n != 1 {
		t.Errorf("審計 target_id 應指向新會話，實際命中 %d 筆", n)
	}

	principal, _, err := e.service.Resolve(ctx, outcome.Secret)
	if err != nil || !principal.IsRoot() {
		t.Fatalf("Root 秘密應解析回 Root 主體：%v", err)
	}
}

// countRootAuditNamed 按動作與 target 統計（確認審計指向哪枚會話）。
func countRootAuditNamed(t *testing.T, db *database.DB, action, targetID string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = ? AND target_id = ?", action, targetID).Scan(&n); err != nil {
		t.Fatalf("統計審計失敗：%v", err)
	}
	return n
}

// TestLoginRootFailures 驗證 Root 的兩種失敗（口令不符、尚未初始化）都：
// 回同一個 ErrInvalidCredentials、零簽發、並把「失敗本身」記進 root_audit。
// 「尚未初始化」尤其關鍵：外部不能從回應分出「這台有沒有 Root」。
func TestLoginRootFailures(t *testing.T) {
	t.Run("wrong-password", func(t *testing.T) {
		e := newEnv(t, true)
		if _, err := e.service.LoginRoot(context.Background(), "錯的 Root 口令", "req-root-2", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("應收斂為 ErrInvalidCredentials，實際 %v", err)
		}
		if n := countSessions(t, e.db); n != 0 {
			t.Fatalf("失敗不可簽發會話，現有 %d 行", n)
		}
		if n := countRootAudit(t, e.db, "auth.login_failure"); n != 1 {
			t.Fatalf("失敗應留下一筆 Root 域審計，實際 %d", n)
		}
	})
	t.Run("not-configured", func(t *testing.T) {
		e := newEnv(t, false)
		if _, err := e.service.LoginRoot(context.Background(), "任何口令", "req-root-3", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("未初始化時也應回同一結論，實際 %v", err)
		}
		if n := countSessions(t, e.db); n != 0 {
			t.Fatalf("失敗不可簽發會話，現有 %d 行", n)
		}
		if n := countRootAudit(t, e.db, "auth.login_failure"); n != 1 {
			t.Fatalf("未初始化的被試探也該留痕，實際 %d", n)
		}
	})
}

// TestAccountLoginWritesNoAudit 釘住已批准的審計邊界：普通帳戶的登入
// （成功或失敗）一律不進審計表——類別未落地，本包不自行發明也不降級。
func TestAccountLoginWritesNoAudit(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.createAccount(t, "no_audit_acc", account.StatusActive)
	if _, err := e.service.LoginAccount(ctx, "no_audit_acc", testAccountPassword, "req", testSourceIP); err != nil {
		t.Fatalf("登入應成功：%v", err)
	}
	if _, err := e.service.LoginAccount(ctx, "no_audit_acc", "錯口令", "req", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("第二次應被拒：%v", err)
	}
	var n int
	for _, table := range []string{"root_audit", "activity_audit"} {
		if err := e.db.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("統計 %s 失敗：%v", table, err)
		}
		if n != 0 {
			t.Errorf("普通帳戶登入不可寫入 %s（現有 %d 筆）", table, n)
		}
	}
}

// TestResolveCollapsesRejections 驗證解析端的所有拒絕收斂為 ErrInvalidSession，
// 而撤銷後的會話立即解析不出主體（狀態現讀到解析入口）。
func TestResolveCollapsesRejections(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.createAccount(t, "resolve_collapse", account.StatusActive)
	outcome, err := e.service.LoginAccount(ctx, "resolve_collapse", testAccountPassword, "req", testSourceIP)
	if err != nil {
		t.Fatalf("登入應成功：%v", err)
	}
	if _, _, err := e.service.Resolve(ctx, "亂放的秘密"); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("非法秘密應收斂為 ErrInvalidSession，實際 %v", err)
	}
	if _, err := e.sessions.Revoke(ctx, e.db.SQL(), outcome.Session.ID); err != nil {
		t.Fatalf("撤銷失敗：%v", err)
	}
	if _, _, err := e.service.Resolve(ctx, outcome.Secret); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("已撤銷會話應收斂為 ErrInvalidSession，實際 %v", err)
	}
}

// TestLogoutRootRevokesAndAuditsInTransaction 驗證 Root 登出：會話被撤銷（随即解析不出主體）
// 且 root_audit 落下一筆 auth.logout，其 target_id 指向該會話、reason 不含會話秘密。
func TestLogoutRootRevokesAndAuditsInTransaction(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	outcome, err := e.service.LoginRoot(ctx, testRootPassword, "req-root", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入應成功：%v", err)
	}
	if err := e.service.Logout(ctx, outcome.Principal, outcome.Session, "req-logout"); err != nil {
		t.Fatalf("Root 登出應成功：%v", err)
	}
	if _, _, err := e.service.Resolve(ctx, outcome.Secret); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("登出後該秘密應解析失敗：%v", err)
	}
	if n := countRootAudit(t, e.db, "auth.logout"); n != 1 {
		t.Fatalf("Root 登出應留一筆 auth.logout，實際 %d", n)
	}
	var (
		targetID string
		reason   sql.NullString
	)
	err = e.db.SQL().QueryRowContext(ctx,
		"SELECT target_id, reason FROM root_audit WHERE action = 'auth.logout'").Scan(&targetID, &reason)
	if err != nil {
		t.Fatalf("讀回登出審計失敗：%v", err)
	}
	if targetID != outcome.Session.ID.String() {
		t.Errorf("登出審計 target_id 應指向該會話：%q vs %q", targetID, outcome.Session.ID.String())
	}
	// 空 reason 在表裡是 NULL（與 audit 仓储的空值約定一致）；總之不得帶會話秘密。
	if reason.Valid && reason.String != "" {
		t.Errorf("登出審計 reason 應為空，不帶任何秘密：%q", reason.String)
	}
}

// TestLogoutAccountRevokesWithoutAudit 釘住沿用登入的審計邊界：普通帳戶登出只撤銷會話、
// 一律不進審計表（無角色帳戶的審計主體類別仍未批准）。
func TestLogoutAccountRevokesWithoutAudit(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.createAccount(t, "logout_acc", account.StatusActive)
	outcome, err := e.service.LoginAccount(ctx, "logout_acc", testAccountPassword, "req", testSourceIP)
	if err != nil {
		t.Fatalf("登入應成功：%v", err)
	}
	if err := e.service.Logout(ctx, outcome.Principal, outcome.Session, "req-logout"); err != nil {
		t.Fatalf("帳戶登出應成功：%v", err)
	}
	if _, _, err := e.service.Resolve(ctx, outcome.Secret); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("登出後該秘密應解析失敗：%v", err)
	}
	var n int
	for _, table := range []string{"root_audit", "activity_audit"} {
		if err := e.db.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("統計 %s 失敗：%v", table, err)
		}
		if n != 0 {
			t.Errorf("普通帳戶登出不可寫入 %s（現有 %d 筆）", table, n)
		}
	}
}

// TestLogoutIsIdempotentAtServiceLayer 驗證登出在服務層的幂等：重複撤銷同一枚已失效的
// 會話不報錯、不再追加審計、也不簽發任何新會話。
func TestLogoutIsIdempotentAtServiceLayer(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	outcome, err := e.service.LoginRoot(ctx, testRootPassword, "req-root", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入應成功：%v", err)
	}
	if err := e.service.Logout(ctx, outcome.Principal, outcome.Session, "req-logout-1"); err != nil {
		t.Fatalf("首次登出應成功：%v", err)
	}
	if err := e.service.Logout(ctx, outcome.Principal, outcome.Session, "req-logout-2"); err != nil {
		t.Fatalf("重複登出應幂等回 nil，實際 %v", err)
	}
	if n := countRootAudit(t, e.db, "auth.logout"); n != 1 {
		t.Errorf("重複登出不可追加第二筆審計，實際 %d", n)
	}
	if n := countSessions(t, e.db); n != 1 {
		t.Errorf("登出不得產生新會話，現有 %d 行", n)
	}
}

// TestNewRequiresDependencies 驗證組裝缺陷在構造階段就報出來，不留「能建但會炸」的服務。
func TestNewRequiresDependencies(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("零值依賴應在建構階段被拒")
	}
}
