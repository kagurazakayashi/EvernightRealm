package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// service_guard_test.go 釘住「守衛接進登入用例之後」的行為合同：
// 觸發時機、查無此人與真帳戶的同形、成功勾銷、冷卻中的嘗試不碰資料庫與審計。
// 全部用注入時鐘推進冷卻，不睡真實時間。

// enableGuard 用同一現場（庫、時鐘、Root 憑據欄）重建接上守衛的登入服務。
// newEnv 預設不注入守衛（既有用例的語意是「無限流」），限流測試經此顯式開啟。
func (e *env) enableGuard(t *testing.T, cfg GuardConfig) *LoginGuard {
	t.Helper()
	guard, err := NewLoginGuard(cfg, e.clock)
	if err != nil {
		t.Fatalf("建立守衛失敗：%v", err)
	}
	service, err := New(Deps{
		DB:               e.db,
		Sessions:         e.sessions,
		Accounts:         e.accounts,
		Audits:           audit.NewStore(e.clock),
		RootPasswordHash: e.rootHash,
		Hashing:          credential.TestParams,
		Guard:            guard,
	})
	if err != nil {
		t.Fatalf("重建登入服務失敗：%v", err)
	}
	e.service = service
	return guard
}

// testClock 取出現場的注入時鐘本體（推進冷卻用）。
func (e *env) testClock(t *testing.T) *timeutil.Test {
	t.Helper()
	clock, ok := e.clock.(*timeutil.Test)
	if !ok {
		t.Fatal("測試現場的時鐘必須是注入式 Test")
	}
	return clock
}

// guardTestCfg 回一份小閾值配置：3 次配對失敗、10 次來源失敗、冷卻 15 分鐘。
func guardTestCfg() GuardConfig {
	return GuardConfig{FailLimit: 3, SourceFailLimit: 10, Window: 15 * time.Minute, Cooldown: 15 * time.Minute}
}

// asThrottled 執行一次「預期被限流」的登入並回傳剩餘冷卻時間。
func asThrottled(t *testing.T, login func() error) time.Duration {
	t.Helper()
	err := login()
	var throttled *ThrottledError
	if !errors.As(err, &throttled) {
		t.Fatalf("應為限流錯誤，實際：%v", err)
	}
	if !errors.Is(err, ErrLoginThrottled) {
		t.Fatal("限流錯誤必須同時 errors.Is(ErrLoginThrottled)")
	}
	if errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("限流與憑據無效必須是可判別的兩種結論")
	}
	return throttled.RetryAfter
}

func TestLoginAccountThrottleAfterConsecutiveFailures(t *testing.T) {
	e := newEnv(t, false)
	e.createAccount(t, "guard_acc", account.StatusActive)
	e.enableGuard(t, guardTestCfg())
	ctx := context.Background()

	// 前三次口令錯：照常的 ErrInvalidCredentials（2001 語意）。
	for i := 0; i < 3; i++ {
		if _, err := e.service.LoginAccount(ctx, "guard_acc", "錯口令", "req", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("第 %d 次應為憑據無效，實際：%v", i+1, err)
		}
	}
	// 打滿後的下一次嘗試：即使口令是對的，也在守衛處被擋——冷卻中不簽發會話（已批准語意）。
	retry := asThrottled(t, func() error {
		_, err := e.service.LoginAccount(ctx, "guard_acc", testAccountPassword, "req", testSourceIP)
		return err
	})
	if retry != 15*time.Minute {
		t.Fatalf("冷卻剩餘應為完整 15 分鐘，實際 %v", retry)
	}
	if n := countSessions(t, e.db); n != 0 {
		t.Fatalf("冷卻中的成功口令也不得簽發會話，實際 %d 行", n)
	}

	// 到期即恢復：推進注入時鐘，不等待真實時間。
	e.testClock(t).Advance(15 * time.Minute)
	if _, err := e.service.LoginAccount(ctx, "guard_acc", testAccountPassword, "req", testSourceIP); err != nil {
		t.Fatalf("冷卻到期後正確口令必須可登入：%v", err)
	}
}

func TestLoginThrottleSameShapeForUnknownAndKnownAccount(t *testing.T) {
	e := newEnv(t, false)
	e.createAccount(t, "guard_known", account.StatusActive)
	e.enableGuard(t, guardTestCfg())
	ctx := context.Background()

	// 對「查無此人」打滿與對「真帳戶」打滿：錯誤型別與冷卻形態完全一致。
	// 若限流透露了任何帳戶存在性資訊（例如只鎖真帳戶），這條會紅。
	var unknownRetry, knownRetry time.Duration
	for i := 0; i < 3; i++ {
		if _, err := e.service.LoginAccount(ctx, "guard_nobody", "錯口令", "req", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("未知帳戶第 %d 次應為憑據無效：%v", i+1, err)
		}
	}
	unknownRetry = asThrottled(t, func() error {
		_, err := e.service.LoginAccount(ctx, "guard_nobody", "錯口令", "req", testSourceIP)
		return err
	})

	for i := 0; i < 3; i++ {
		if _, err := e.service.LoginAccount(ctx, "guard_known", "錯口令", "req", "10.9.9.9"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("已知帳戶第 %d 次應為憑據無效：%v", i+1, err)
		}
	}
	knownRetry = asThrottled(t, func() error {
		_, err := e.service.LoginAccount(ctx, "guard_known", "錯口令", "req", "10.9.9.9")
		return err
	})

	// 兩條路都拿到「從觸發那一刻起的完整冷卻」：任何一側偏短或偏長都意味著
	// 計量與帳戶存在性掛了鈎。
	if unknownRetry != 15*time.Minute || knownRetry != 15*time.Minute {
		t.Fatalf("未知與已知帳戶的冷卻必須同形（皆 15 分鐘起算），實際 %v vs %v", unknownRetry, knownRetry)
	}
}

func TestLoginSuccessClearsFailureBudget(t *testing.T) {
	e := newEnv(t, false)
	e.createAccount(t, "guard_clear", account.StatusActive)
	e.enableGuard(t, guardTestCfg())
	ctx := context.Background()

	// 失敗兩次 → 成功一次（勾銷）→ 再走完整一輪上限才觸發：
	// 誤觸幾次的正常用戶不會被舊帳積惡。
	for i := 0; i < 2; i++ {
		if _, err := e.service.LoginAccount(ctx, "guard_clear", "錯口令", "req", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("第 %d 次失敗結論異常：%v", i+1, err)
		}
	}
	if _, err := e.service.LoginAccount(ctx, "guard_clear", testAccountPassword, "req", testSourceIP); err != nil {
		t.Fatalf("成功登入不應受阻：%v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := e.service.LoginAccount(ctx, "guard_clear", "錯口令", "req", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("勾銷後的第 %d 次失敗仍應是憑據無效（觸發那次本身也是）：%v", i+1, err)
		}
	}
	asThrottled(t, func() error {
		_, err := e.service.LoginAccount(ctx, "guard_clear", "錯口令", "req", testSourceIP)
		return err
	})
}

func TestLoginRootThrottleSkipsAuditWrites(t *testing.T) {
	e := newEnv(t, true)
	e.enableGuard(t, guardTestCfg())
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := e.service.LoginRoot(ctx, "錯的 Root 口令", "req", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("第 %d 次 Root 失敗結論異常：%v", i+1, err)
		}
	}
	failedBefore := countRootAudit(t, e.db, "auth.login_failure")
	if failedBefore != 3 {
		t.Fatalf("打滿前的失敗審計應為 3 筆，實際 %d", failedBefore)
	}

	// 冷卻中被擋的嘗試不寫審計：拒絕仍然成立，但 root_audit 的寫入速率被 fail_limit 封頂。
	for i := 0; i < 10; i++ {
		asThrottled(t, func() error {
			_, err := e.service.LoginRoot(ctx, "錯的 Root 口令", "req", testSourceIP)
			return err
		})
	}
	if n := countRootAudit(t, e.db, "auth.login_failure"); n != failedBefore {
		t.Fatalf("冷卻期內審計不得增長，實際 %d（原 %d）", n, failedBefore)
	}

	// 到期後恢復：Root 的失敗預算重計。
	e.testClock(t).Advance(15 * time.Minute)
	if _, err := e.service.LoginRoot(ctx, "錯的 Root 口令", "req", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("冷卻到期後 Root 嘗試應回到正常通路：%v", err)
	}
}

func TestLoginThrottleSharedSourceKeepsOtherAccountsAlive(t *testing.T) {
	e := newEnv(t, false)
	e.createAccount(t, "guard_roommate", account.StatusActive)
	e.enableGuard(t, guardTestCfg())
	ctx := context.Background()

	// 同一出口位址把「室友甲」打滿：室友乙照常可登入——限流不是整棟樓一堵牆。
	for i := 0; i < 3; i++ {
		if _, err := e.service.LoginAccount(ctx, "guard_roommate", "錯口令", "req", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("甲第 %d 次失敗結論異常：%v", i+1, err)
		}
	}
	asThrottled(t, func() error {
		_, err := e.service.LoginAccount(ctx, "guard_roommate", testAccountPassword, "req", testSourceIP)
		return err
	})

	if _, err := e.service.LoginAccount(ctx, "guard_roommate", testAccountPassword, "req", "10.0.0.2"); err != nil {
		t.Fatalf("同帳戶其他位址不受牽連，實際：%v", err)
	}
}

func TestLoginThrottleNewGuardInstanceMeansFreshBudget(t *testing.T) {
	e := newEnv(t, false)
	e.createAccount(t, "guard_restart", account.StatusActive)
	e.enableGuard(t, guardTestCfg())
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		e.service.LoginAccount(ctx, "guard_restart", "錯口令", "req", testSourceIP)
	}
	asThrottled(t, func() error {
		_, err := e.service.LoginAccount(ctx, "guard_restart", testAccountPassword, "req", testSourceIP)
		return err
	})

	// 「重啟清空」語意的可執行表述：重建守衛（等同進程重啟）後預算全新——
	// 冷卻不跨進程生命週期，這是批准決定而不是實作意外。
	e.enableGuard(t, guardTestCfg())
	if _, err := e.service.LoginAccount(ctx, "guard_restart", testAccountPassword, "req", testSourceIP); err != nil {
		t.Fatalf("重建守衛後應恢復放行：%v", err)
	}
}

func TestLoginOversizedLoginNamesShareTruncatedGuardKey(t *testing.T) {
	e := newEnv(t, false)
	guard := e.enableGuard(t, guardTestCfg())
	ctx := context.Background()

	// 超長隨機名（超過正規化鍵的 200 碼位上限）一律落到同一條截斷鍵：
	// 「靠海量長鍵把限流表撐出無界記憶體」或「每個長鍵各拿一份預算」兩條路線
	// 同時被釘死——前三次照常被拒，第四次開始就進冷卻。
	longPrefix := string(make([]byte, 300))
	blockedSeen := false
	for i := 0; i < 20; i++ {
		_, err := e.service.LoginAccount(ctx, longPrefix+string(rune('A'+i)), "x", "req", testSourceIP)
		if errors.Is(err, ErrLoginThrottled) {
			blockedSeen = true
			continue
		}
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("超長名第 %d 次結論異常：%v", i+1, err)
		}
	}
	if !blockedSeen {
		t.Fatal("海量超長隨機名截斷同鍵後也必須被打滿，不能被當作無限預算")
	}
	if n := guard.entryCount(); n > 2 {
		t.Fatalf("截斷同鍵＋單一來源，條目應不超過 2，實際 %d", n)
	}
}
