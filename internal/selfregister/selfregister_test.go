// selfregister_test.go 是「匿名用戶自註冊為普通帳戶」用例的定向證據：
// 成功形態（standard／active／首次不必改密）與 Root 域系統主體審計的真實落地、
// 准入判定在寫入那一刻現讀（closed／重新開放／approval 三個方向）、重複與併發收口、
// 匿名防線（頻率封頂擋在查庫與派生之前、派生併發封頂）、輸入不合規與取消都一個字都不落盤、
// 依賴與併發上限的構造校驗，以及「建出來的普通帳戶能立即用自選口令登入」這條閉環。
//
// 全程使用本次專屬的暫存庫與注入時鐘：不佔 5206、不碰任何真實資料目錄。
package selfregister

import (
	"bytes"
	"context"
	"database/sql"
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
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 測試口令：只活在測試進程的記憶體，不是任何環境的憑據。
const (
	testPassword     = "selfregister-test-自選口令"
	testRootPassword = "selfregister-test-root-口令"
)

// testBase 是注入時鐘的錨點。
var testBase = time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)

// env 是一次測試的完整現場：專屬暫存庫、注入時鐘、策略倉儲，加上組好的自註冊用例。
//
// 新環境預設把自註冊模式設為 open（多數用例要的是「門開著」的現場），並掛一個寬鬆守衛
// （上限極高），讓除限流外的用例都不被頻率封頂干擾；需要的用例各自換緊守衛或翻開關，
// 那些方向由對應用例自己斷言。
type env struct {
	db      *database.DB
	clock   *timeutil.Test
	logs    *bytes.Buffer
	policy  *acctpolicy.Store
	service *Service
}

// newEnv 以寬鬆守衛與 open 起點模式建立現場。口令雜湊用 credential.TestParams（低成本檔）：
// 本套件的斷言對象是「自註冊用例的落地與拒絕形態」，不是生產參數檔的算力。
func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWithPolicy(t, lenientGuard(), acctpolicy.ModeOpen)
}

// lenientGuard 是一組「不會在正常用例裡擋人」的守衛閾值：配對與來源上限都拉到構造上界，
// 視窗與冷卻取最小合法值。如此重複／併發用例的失敗只可能來自唯一約束，不會混入限流。
func lenientGuard() auth.GuardConfig {
	return auth.GuardConfig{
		FailLimit:       10000,
		Window:          time.Second,
		Cooldown:        time.Second,
		SourceFailLimit: 10000,
		MaxEntries:      100000,
	}
}

// newEnvWithPolicy 建立現場並以給定模式作為起點策略。
func newEnvWithPolicy(t *testing.T, guard auth.GuardConfig, mode acctpolicy.Mode) *env {
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
	if _, err := policyStore.Put(context.Background(), db.SQL(), acctpolicy.Policy{
		AdminCreateStandard: false,
		SelfRegisterMode:    mode,
		GuestEnabled:        false,
	}); err != nil {
		t.Fatalf("鋪設起點策略失敗：%v", err)
	}
	loginGuard, err := auth.NewLoginGuard(guard, clock)
	if err != nil {
		t.Fatalf("建立自註冊守衛失敗：%v", err)
	}
	service, err := New(Deps{
		DB:              db,
		Accounts:        account.NewStore(clock),
		Policy:          policyStore,
		Audits:          audit.NewStore(clock),
		Guard:           loginGuard,
		Hashing:         credential.TestParams,
		HashConcurrency: 2,
		Log:             slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("建立自註冊用例失敗：%v", err)
	}
	return &env{db: db, clock: clock, logs: &logs, policy: policyStore, service: service}
}

// setSelfRegisterMode 經策略倉儲（與生產同一個寫入點）翻動 self_register_mode，
// 其餘兩欄保持原樣：不直寫 SQL，免得繞過了策略復核那一層。
func (e *env) setSelfRegisterMode(t *testing.T, mode acctpolicy.Mode) {
	t.Helper()
	current, err := e.policy.Get(context.Background(), e.db.SQL())
	if err != nil {
		t.Fatalf("讀取當前策略失敗：%v", err)
	}
	if _, err := e.policy.Put(context.Background(), e.db.SQL(), acctpolicy.Policy{
		AdminCreateStandard: current.AdminCreateStandard,
		SelfRegisterMode:    mode,
		GuestEnabled:        current.GuestEnabled,
	}); err != nil {
		t.Fatalf("設定自註冊模式失敗：%v", err)
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

// mustRegister 註冊一個普通帳戶並在失敗時終止測試。
func (e *env) mustRegister(t *testing.T, login, display, password string) RegisteredAccount {
	t.Helper()
	created, err := e.service.RegisterAccount(context.Background(), RegisterInput{
		LoginName:   login,
		DisplayName: display,
		Password:    password,
	}, "req-"+login, "203.0.113.10")
	if err != nil {
		t.Fatalf("自註冊 %s 失敗：%v", login, err)
	}
	return created
}

// TestRegisterWritesAccountAndSystemAudit 成功形態：普通帳戶與 Root 域系統主體審計一起落地，
// 形態（standard／active／首次不必改密）由用例決定，且審計不冒充任何可信主體、不屬於任何活動。
func TestRegisterWritesAccountAndSystemAudit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	created := e.mustRegister(t, "Player.One", "測試普通帳戶", testPassword)

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
	if hash == testPassword || strings.Contains(hash, testPassword) {
		t.Error("憑據欄不得出現口令明文")
	}
	if accountType != "standard" || status != "active" {
		t.Errorf("自註冊應建出 standard/active，實際 %s/%s", accountType, status)
	}
	// 與管理員建號（恆 true）在形態上唯一的差別就在這裡：口令是本人自選，選完即可登入。
	if mustChange != 0 {
		t.Error("自註冊建的帳戶首次登入不應欠改密：must_change_password 必須為 0")
	}
	if got := timeutil.FromMillis(createdAt); !got.Equal(testBase) {
		t.Errorf("建立時刻應取自注入時鐘 %v，實際 %v", testBase, got)
	}
	if created.MustChangePassword {
		t.Error("回傳結果也應如實回報「首次不必改密」")
	}
	// 建的只是 Account：沒有任何授予行——「自註冊即獲伺服器級角色」不成立在資料上。
	if n := countRows(t, e.db, "account_server_roles"); n != 0 {
		t.Errorf("自註冊不得帶出任何伺服器級授予，實際 %d 行", n)
	}

	var (
		action, targetKind, targetID, actorKind string
		actorID                                 sql.NullString
		changes, reason                         string
	)
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT action, target_kind, target_id, actor_kind,
		actor_id, changes_json, reason FROM root_audit WHERE action = 'account.self_register'`).
		Scan(&action, &targetKind, &targetID, &actorKind, &actorID, &changes, &reason); err != nil {
		t.Fatalf("讀回審計失敗：%v", err)
	}
	if targetKind != "account" || targetID != created.AccountID.String() {
		t.Errorf("審計目標應指向新帳戶，實際 %s/%s", targetKind, targetID)
	}
	if actorKind != string(audit.ActorSystem) {
		t.Errorf("匿名建的動作應記 actor=system，實際 %q", actorKind)
	}
	// 系統主體沒有可信實體標識：actor_id 必須是 NULL，而不是任何湊出來的 ID。
	if actorID.Valid {
		t.Errorf("系統主體的審計 actor_id 必須為 NULL，實際带值 %q", actorID.String)
	}
	// 「Root 事件不屬於任何活動」的 strongest 形態是結構性的：root_audit 根本沒有這一欄。
	if _, err := e.db.SQL().ExecContext(ctx,
		"SELECT activity_id FROM root_audit LIMIT 0"); err == nil {
		t.Error("root_audit 不該有 activity_id 欄位：那是「Root 事件不屬於任何活動」的結構證據")
	}
	rowText := action + targetKind + targetID + actorKind + actorID.String + changes + reason
	if strings.Contains(rowText, testPassword) || strings.Contains(rowText, hash) {
		t.Error("審計記錄不得含口令明文或憑據雜湊")
	}
	if strings.Contains(strings.ToLower(rowText), "password") && !strings.Contains(changes, "must_change_password") {
		// changes 只該有 must_change_password 這個身分欄位名；任何其他 password 字樣都不該出現。
		t.Errorf("審計不得出现除 must_change_password 外的 password 字樣：%s", changes)
	}
	if logs := e.logs.String(); strings.Contains(logs, testPassword) || strings.Contains(logs, hash) {
		t.Error("執行日誌不得含口令明文或憑據雜湊")
	}
}

// TestPolicyJudgedAtWriteTime 准入在寫入那一刻現讀策略，三個方向都必須立即生效：
// 關著不寫一行、開著就建得成、再關回去下一條又必須被拒。
//
// 這一條釘的是「前端讀到入口開、背後策略已關卻仍建成」那個窗口不存在：判定依據與寫入
// 同屬一筆交易，Root 翻開關不需要通知誰，下一條請求讀到的就是新值。
func TestPolicyJudgedAtWriteTime(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	e.setSelfRegisterMode(t, acctpolicy.ModeClosed)
	if _, err := e.service.RegisterAccount(ctx, RegisterInput{
		LoginName: "gated.off", DisplayName: "策略擋下", Password: testPassword,
	}, "req-gated", "203.0.113.11"); !errors.Is(err, ErrRegisterDisabled) {
		t.Errorf("模式關閉時應回可判別的策略未開放結論，實際 %v", err)
	}
	for _, table := range []string{"accounts", "root_audit"} {
		if n := countRows(t, e.db, table); n != 0 {
			t.Errorf("被策略擋下的註冊不得留下任何寫入（%s 有 %d 行）", table, n)
		}
	}

	e.setSelfRegisterMode(t, acctpolicy.ModeOpen)
	e.mustRegister(t, "gated.on", "策略放行", testPassword)

	e.setSelfRegisterMode(t, acctpolicy.ModeClosed)
	if _, err := e.service.RegisterAccount(ctx, RegisterInput{
		LoginName: "gated.again", DisplayName: "再關又擋", Password: testPassword,
	}, "req-gated-2", "203.0.113.11"); !errors.Is(err, ErrRegisterDisabled) {
		t.Errorf("重新關閉後的下一條請求必須按新值判定，實際 %v", err)
	}
	if n := countRows(t, e.db, "accounts"); n != 1 {
		t.Errorf("只該有放行那一次的一行帳戶，實際 %d", n)
	}
	if n := countRows(t, e.db, "root_audit"); n != 1 {
		t.Errorf("被策略擋下的註冊不得追加審計，實際 %d 筆", n)
	}
}

// TestNonOpenModeIsUnsupported 策略放行但不是 open 的模式（approval／invite）：
// 准入流程尚未上線，必須回可判別的模式未開放結論，而且一個帳戶都不建、一條審計都不寫。
//
// 這一條把「AllowsSelfRegister 對任何有效非 closed 模式都回 true」這半句話堵死在用例裡：
// 用例不能因為策略說「放行」就默默按 open 建號——那等於替尚未實作的准入流程冒充可用。
func TestNonOpenModeIsUnsupported(t *testing.T) {
	for _, mode := range []acctpolicy.Mode{acctpolicy.ModeApproval, acctpolicy.ModeInvite} {
		e := newEnv(t)
		e.setSelfRegisterMode(t, mode)
		ctx := context.Background()
		if _, err := e.service.RegisterAccount(ctx, RegisterInput{
			LoginName: "mode." + mode.String(), DisplayName: "模式未上線", Password: testPassword,
		}, "req-mode", "203.0.113.12"); !errors.Is(err, ErrRegisterModeUnsupported) {
			t.Errorf("%s 模式應被拒為「准入流程尚未上線」，實際 %v", mode, err)
		}
		for _, table := range []string{"accounts", "root_audit"} {
			if n := countRows(t, e.db, table); n != 0 {
				t.Errorf("被模式擋下的註冊不得留下任何寫入（%s 有 %d 行）", table, n)
			}
		}
	}
}

// TestDuplicateLoginIsRejectedWithoutSecondWrite 重複登入名（含大小寫／全形變體）：
// 第二筆整筆不發生，第一筆的事實與審計都不動；且衝突錯誤不回顯本次口令。
func TestDuplicateLoginIsRejectedWithoutSecondWrite(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.mustRegister(t, "Dup.One", "第一個", testPassword)

	for _, variant := range []string{"dup.one", "DUP.ONE", "Ｄｕｐ.Ｏｎｅ"} {
		_, err := e.service.RegisterAccount(ctx, RegisterInput{
			LoginName: variant, DisplayName: "重複提交", Password: "另一個自選口令",
		}, "req-dup", "203.0.113.13")
		if !errors.Is(err, ErrDuplicateLogin) {
			t.Errorf("%q 應被判為登入名已佔用，實際 %v", variant, err)
		}
		if strings.Contains(err.Error(), "另一個自選口令") {
			t.Errorf("衝突錯誤不得回顯本次口令：%v", err)
		}
	}
	if n := countRows(t, e.db, "accounts"); n != 1 {
		t.Errorf("三次重複提交後仍只應有一行帳戶，實際 %d", n)
	}
	if n := countRows(t, e.db, "root_audit"); n != 1 {
		t.Errorf("被拒的註冊不得追加審計，實際 %d 筆", n)
	}
}

// TestConcurrentSameLoginCreatesExactlyOneAccount 併發同鍵：只有一個贏家，其餘收口到已佔用。
//
// 用寬鬆守衛，讓失敗只可能來自 UNIQUE(login_name_key)，不會混入限流；這樣「恰好一個成功、
// 其餘全是重名」這條斷言才乾淨地證明了收口發生在資料庫約束而非查插之間的時間窗。
func TestConcurrentSameLoginCreatesExactlyOneAccount(t *testing.T) {
	e := newEnv(t)

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
			_, err := e.service.RegisterAccount(context.Background(), RegisterInput{
				LoginName:   "race-one",
				DisplayName: "併發註冊",
				Password:    fmt.Sprintf("%s-%d", testPassword, i),
			}, fmt.Sprintf("req-race-%d", i), fmt.Sprintf("203.0.113.%d", 100+i))
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
		t.Fatalf("併發註冊只該出現成功或重複衝突，實際 %v", other)
	}
	if created != 1 {
		t.Errorf("成功註冊應恰好一次，實際 %d", created)
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

// TestThrottleBlocksBeforeExpensivePath 頻率封頂擋在查庫、派生與審計之前：
// 打滿配對上限的來源進入冷卻，冷卻期內的下一次嘗試換回可判別的 ThrottledError＋Retry-After，
// 而帳戶數與審計數一個都不動（那正是限流要保護的三樣最貴資源）。
func TestThrottleBlocksBeforeExpensivePath(t *testing.T) {
	// 緊守衛：配對與來源各 3 次就打滿；視窗與冷則取最小合法值（1 秒），不靠時鐘推進即可穩定進入冷卻。
	e := newEnvWithPolicy(t, auth.GuardConfig{
		FailLimit:       3,
		Window:          time.Second,
		Cooldown:        time.Minute,
		SourceFailLimit: 3,
		MaxEntries:      1000,
	}, acctpolicy.ModeOpen)
	ctx := context.Background()

	// 先把名字佔住，讓「同一來源反復撞同一存在名字」走重名分支（每次都記一次失敗）。
	const source = "198.51.100.7"
	e.mustRegister(t, "Throttle.Me", "佔位帳戶", testPassword)

	// 前 3 次撞同一正規化鍵（不同大小寫）都記失敗；第 3 次把配對條目推進冷卻。
	var lastErr error
	for _, variant := range []string{"throttle.me", "Throttle.Me", "THROTTLE.ME"} {
		lastErr = nil
		_, err := e.service.RegisterAccount(ctx, RegisterInput{
			LoginName: variant, DisplayName: "撞名探測", Password: testPassword,
		}, "req-probe", source)
		if !errors.Is(err, ErrDuplicateLogin) {
			lastErr = err
			break
		}
	}
	if lastErr != nil {
		t.Fatalf("冷卻觸發前的撞名都應是重名結論，最後一次實際 %v", lastErr)
	}

	// 額度已打滿：下一次嘗試必須被擋在門檻前，帶著可判別的 ThrottledError 與正的 Retry-After。
	accountsBefore := countRows(t, e.db, "accounts")
	auditsBefore := countRows(t, e.db, "root_audit")
	_, err := e.service.RegisterAccount(ctx, RegisterInput{
		LoginName: "throttle.me", DisplayName: "冷卻期再撞", Password: testPassword,
	}, "req-blocked", source)
	var throttled *ThrottledError
	if !errors.As(err, &throttled) {
		t.Fatalf("打滿額度後的嘗試應被限流擋下，實際 %v", err)
	}
	if !errors.Is(err, ErrThrottled) {
		t.Errorf("ThrottledError 必須讓 errors.Is(err, ErrThrottled) 成立")
	}
	if throttled.RetryAfter <= 0 {
		t.Errorf("被擋的嘗試必須帶著正的剩餘冷卻時間，實際 %v", throttled.RetryAfter)
	}
	// 被擋的這一次不該碰過任何一樣昂貴的東西。
	if n := countRows(t, e.db, "accounts"); n != accountsBefore {
		t.Errorf("被限流擋下的嘗試不得新建帳戶：%d→%d", accountsBefore, n)
	}
	if n := countRows(t, e.db, "root_audit"); n != auditsBefore {
		t.Errorf("被限流擋下的嘗試不得追加審計：%d→%d", auditsBefore, n)
	}
}

// TestEmptySourceIsNotSharedWall 來源位址為空時不共用一堵牆：
// 空來源代表傳輸層沒給出可計量的位址（裝配缺陷信號），照常走正常流程而不是把所有空來源請求一起擋。
func TestEmptySourceIsNotSharedWall(t *testing.T) {
	e := newEnvWithPolicy(t, auth.GuardConfig{
		FailLimit: 1, Window: time.Second, Cooldown: time.Minute, SourceFailLimit: 1, MaxEntries: 1000,
	}, acctpolicy.ModeOpen)
	ctx := context.Background()

	// 同一個空來源連兩次建兩個不同名字：若空來源被計量，第二次會被冷卻擋下；正確行為是放行。
	if _, err := e.service.RegisterAccount(ctx, RegisterInput{
		LoginName: "empty.src.a", DisplayName: "空來源甲", Password: testPassword,
	}, "req-a", ""); err != nil {
		t.Fatalf("空來源第一次註冊應放行，實際 %v", err)
	}
	if _, err := e.service.RegisterAccount(ctx, RegisterInput{
		LoginName: "empty.src.b", DisplayName: "空來源乙", Password: testPassword,
	}, "req-b", ""); err != nil {
		t.Fatalf("空來源第二次註冊不應被共用冷卻擋下（空來源不計量），實際 %v", err)
	}
	if n := countRows(t, e.db, "accounts"); n != 2 {
		t.Errorf("兩次空來源註冊各建成一行，實際 %d", n)
	}
}

// TestHashConcurrencySerializesWithoutLoss 派生併發封頂不吞單也不卡死：
// HashConcurrency=1 時一批不同名字的註冊仍全部建成（訊號量只序列化、不遺漏），
// 證明了「取得額度—派生—歸還額度」的臨界區收口正確。
func TestHashConcurrencySerializesWithoutLoss(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(func() {
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			t.Errorf("暫存目錄清理失敗（殘留：%s）：%v", dir, err)
		}
	})
	db, err := database.Open(context.Background(), database.Options{
		Path: filepath.Join(dir, "evernight.db"), BusyTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	defer func() { _ = db.Close() }()
	clock := timeutil.NewTest(testBase)
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: clock}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	policyStore := acctpolicy.NewStore(clock)
	if _, err := policyStore.Put(context.Background(), db.SQL(), acctpolicy.Policy{
		SelfRegisterMode: acctpolicy.ModeOpen,
	}); err != nil {
		t.Fatalf("鋪設策略失敗：%v", err)
	}
	guard, err := auth.NewLoginGuard(lenientGuard(), clock)
	if err != nil {
		t.Fatalf("建立守衛失敗：%v", err)
	}
	service, err := New(Deps{
		DB: db, Accounts: account.NewStore(clock), Policy: policyStore,
		Audits: audit.NewStore(clock), Guard: guard,
		Hashing: credential.TestParams, HashConcurrency: 1,
	})
	if err != nil {
		t.Fatalf("建立用例失敗：%v", err)
	}

	const total = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []error
	wg.Add(total)
	for i := 0; i < total; i++ {
		go func(i int) {
			defer wg.Done()
			_, err := service.RegisterAccount(context.Background(), RegisterInput{
				LoginName: fmt.Sprintf("serial-%02d", i), DisplayName: "序列化註冊",
				Password: fmt.Sprintf("%s-%d", testPassword, i),
			}, fmt.Sprintf("req-serial-%d", i), fmt.Sprintf("203.0.113.%d", 200+i))
			if err != nil {
				mu.Lock()
				failures = append(failures, err)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("封頂為 1 時不同名字仍應全部建成，失敗：%v", failures)
	}
	if n := countRows(t, db, "accounts"); n != total {
		t.Errorf("应建成 %d 行帳戶，實際 %d", total, n)
	}
}

// TestCanceledContextWritesNothing 取消的 context 換來失敗且不落盤。
func TestCanceledContextWritesNothing(t *testing.T) {
	e := newEnv(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := e.service.RegisterAccount(canceled, RegisterInput{
		LoginName: "never-lands", DisplayName: "取消驗證", Password: testPassword,
	}, "req-cancel", "203.0.113.20"); err == nil {
		t.Fatal("已取消的 context 必須讓註冊失敗")
	}
	for _, table := range []string{"accounts", "root_audit"} {
		if n := countRows(t, e.db, table); n != 0 {
			t.Errorf("取消後 %s 不得有寫入，實際 %d 行", table, n)
		}
	}
}

// TestAuditFailureRollsBackAccount 審計寫不進去＝帳戶一起回滾。
//
// 「匿名建的仍是伺服器級主體變更、必留痕」的強度取決於它能不能退化成一句日誌——這裡用
// DROP TABLE 把審計那一跳做成必然失敗（測試專屬暫存庫，不涉任何真實資料）。
func TestAuditFailureRollsBackAccount(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("移除審計表失敗（測試前提）：%v", err)
	}
	if _, err := e.service.RegisterAccount(ctx, RegisterInput{
		LoginName: "rollback-me", DisplayName: "回滾驗證", Password: testPassword,
	}, "req-rollback", "203.0.113.21"); err == nil {
		t.Fatal("審計寫入失敗時註冊必須回報失敗")
	}
	if n := countRows(t, e.db, "accounts"); n != 0 {
		t.Errorf("回滾後不得留下帳戶，實際 %d 行", n)
	}
}

// TestRejectsBadInputs 輸入不合規時不消耗派生與寫入：空口令、超長口令、非法登入名。
func TestRejectsBadInputs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	cases := []struct {
		name  string
		input RegisterInput
		want  error
	}{
		{"空口令", RegisterInput{LoginName: "empty-pw", DisplayName: "x", Password: ""}, ErrInvalidPassword},
		{"超長口令", RegisterInput{LoginName: "huge-pw", DisplayName: "x",
			Password: strings.Repeat("長", credential.MaxPasswordLength)}, ErrInvalidPassword},
		{"含空白登入名", RegisterInput{LoginName: "bad name", DisplayName: "x",
			Password: testPassword}, account.ErrInvalidLogin},
		{"空顯示名", RegisterInput{LoginName: "empty-display", DisplayName: "  ",
			Password: testPassword}, account.ErrInvalidDisplayName},
	}
	for _, tc := range cases {
		if _, err := e.service.RegisterAccount(ctx, tc.input, "req-bad-"+tc.name, "203.0.113.22"); !errors.Is(err, tc.want) {
			t.Errorf("%s 應被判為 %v，實際 %v", tc.name, tc.want, err)
		}
	}
	for _, table := range []string{"accounts", "root_audit"} {
		if n := countRows(t, e.db, table); n != 0 {
			t.Errorf("被拒的輸入不得留下任何寫入（%s 有 %d 行）", table, n)
		}
	}
}

// TestResultShapeIsNotRequestControlled 建的形態與請求輸入無關：
// RegisterInput 只有三個欄位，類型、狀態、旗標由用例寫死，回傳值不攜帶任何憑據材料。
func TestResultShapeIsNotRequestControlled(t *testing.T) {
	e := newEnv(t)
	created := e.mustRegister(t, "no-self-claim", "無自報", testPassword)

	if created.Status != account.StatusActive || created.MustChangePassword {
		t.Errorf("結果應只帶服務端判定的形態，實際 %+v", created)
	}
	if strings.Contains(fmt.Sprintf("%+v", created), testPassword) {
		t.Error("回傳結果不得含口令明文")
	}
}

// newAuthService 在同一現場組出登入用例，供「建出來的普通帳戶真能立即登入」這條閉環使用。
//
// 刻意不傳登入守衛（nil＝不啟用限流）：本閉環要驗的是「自選口令直接換得出會話、且不欠改密」，
// 與頻率封頂無關，不讓兩條通路的限流互相干擾。
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

// TestFirstSignInLoopCloses 註冊出來的普通帳戶真能走既有登入通路立即使用：
// 自選口令直接登入 → 主體不帶任何角色、不欠首次改密 → 換錯口令被拒。
//
// 這條是「開放自註冊、立即可用」的接縫證據：must_change_password=false 不只是回傳值，
// 而是既有用例在登入時據實放行的事實。
func TestFirstSignInLoopCloses(t *testing.T) {
	e := newEnv(t)
	authService := e.newAuthService(t)
	ctx := context.Background()

	created := e.mustRegister(t, "std.first.sign.in", "立即可用", testPassword)

	outcome, err := authService.LoginAccount(ctx, "Std.First.Sign.In", testPassword, "req-login", "127.0.0.1")
	if err != nil {
		t.Fatalf("新建普通帳戶應能以自選口令立即登入：%v", err)
	}
	if len(outcome.Principal.Roles()) != 0 {
		t.Errorf("自註冊帳戶不應帶出任何伺服器級角色，實際 %v", outcome.Principal.Roles())
	}
	if outcome.MustChangePassword {
		t.Error("自選口令建的帳戶首次登入不該欠改密（立即可用的核心語意）")
	}
	if created.AccountID != outcome.Principal.AccountID() {
		t.Errorf("登入換回的主體應就是剛註冊出的帳戶：%s 對 %s", created.AccountID, outcome.Principal.AccountID())
	}
	if _, err := authService.LoginAccount(ctx, "std.first.sign.in", "錯誤口令", "req-login-2", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("錯口令必須被拒為憑據無效，實際 %v", err)
	}
}

// TestNewRejectsMissingDeps 缺依賴或併發上限裝錯是組裝缺陷：在啟動階段就報出來，不帶病上線。
func TestNewRejectsMissingDeps(t *testing.T) {
	e := newEnv(t)
	guard, err := auth.NewLoginGuard(lenientGuard(), e.clock)
	if err != nil {
		t.Fatalf("建立守衛失敗：%v", err)
	}
	valid := Deps{
		DB: e.db, Accounts: account.NewStore(e.clock), Policy: e.policy,
		Audits: audit.NewStore(e.clock), Guard: guard,
		Hashing: credential.TestParams, HashConcurrency: 2,
	}
	for _, mutate := range []func(*Deps){
		func(d *Deps) { d.DB = nil },
		func(d *Deps) { d.Accounts = nil },
		func(d *Deps) { d.Policy = nil },
		func(d *Deps) { d.Audits = nil },
		func(d *Deps) { d.Guard = nil },
		func(d *Deps) { d.Hashing = credential.Params{} },
		func(d *Deps) { d.HashConcurrency = 0 },
		func(d *Deps) { d.HashConcurrency = -1 },
		func(d *Deps) { d.HashConcurrency = maxHashConcurrency + 1 },
	} {
		deps := valid
		mutate(&deps)
		if _, err := New(deps); err == nil {
			t.Error("依賴缺失或併發上限越界時 New 必須報錯")
		}
	}
}
