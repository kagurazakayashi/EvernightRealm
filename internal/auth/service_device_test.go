package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 這一檔釘住「裝置登入策略接進登入事務」的用例層形態：
//   - 策略在簽發會話之前、且與簽發同屬一個交易（拆開就等於沒有併發保護）；
//   - 名額已滿是策略拒絕：不寫會話、不改 last_login_at、不消耗登入守衛的失敗額度；
//   - Root 與普通帳戶走同一條規則（沒有例外，也沒有繞過入口）；
//   - single 模式造成的撤銷在 Root 域留審計，被拒的登入不留。

// countLiveFor 用與實作無關的 SQL 數出該主體還換得出身份的會話。
//
// 斷言不借被測程式碼自己的計數函式：策略算錯時，借來的計數會跟著一起錯。
func countLiveFor(t *testing.T, e *env, kind string, accountID idgen.ID) int {
	t.Helper()
	query := `SELECT COUNT(*) FROM sessions
		WHERE subject_kind = ? AND revoked_at IS NULL AND expires_at > ?`
	args := []any{kind, timeutil.ToMillis(e.clock.Now())}
	if !accountID.IsNil() {
		query += " AND account_id = ?"
		args = append(args, accountID.String())
	}
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("統計有效會話失敗：%v", err)
	}
	return n
}

// TestLoginAccountSingleModeReplacesPriorSession 是單裝置模式的端到端用例：
// 第二次登入成功之後，第一枚憑據立刻換不出身份，而主體仍然只握有一份有效會話。
func TestLoginAccountSingleModeReplacesPriorSession(t *testing.T) {
	e := newEnvWithPolicy(t, false, session.Policy{DeviceMode: session.DeviceModeSingle}, time.Hour, nil)
	ctx := context.Background()
	a := e.createAccount(t, "device_single", account.StatusActive)

	first, err := e.service.LoginAccount(ctx, "device_single", testAccountPassword, "req-1", testSourceIP)
	if err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	second, err := e.service.LoginAccount(ctx, "device_single", testAccountPassword, "req-2", testSourceIP)
	if err != nil {
		t.Fatalf("第二次登入失敗：%v", err)
	}
	if _, _, err := e.service.Resolve(ctx, first.Secret); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("舊憑據應換不出身份（ErrInvalidSession），實際 %v", err)
	}
	if _, _, err := e.service.Resolve(ctx, second.Secret); err != nil {
		t.Errorf("新憑據應可用：%v", err)
	}
	if got := countSessions(t, e.db); got != 2 {
		t.Errorf("兩次登入各留一行（撤銷不是刪除），實際 %d", got)
	}
	if got := countLiveFor(t, e, "account", a.ID); got != 1 {
		t.Errorf("單設備模式的主體應只有 1 份有效會話，實際 %d", got)
	}
}

// TestLoginAccountLimitedModeRejectsThirdDevice 指定上限：第三份登入被拒，而且
// 「拒絕＝整個沒有發生」——沒有新會話行、兩份既有會話一動未動、last_login_at 也沒被推進。
func TestLoginAccountLimitedModeRejectsThirdDevice(t *testing.T) {
	e := newEnvWithPolicy(t, false,
		session.Policy{DeviceMode: session.DeviceModeLimited, MaxDevices: 2}, time.Hour, nil)
	ctx := context.Background()
	a := e.createAccount(t, "device_limit", account.StatusActive)

	if _, err := e.service.LoginAccount(ctx, "device_limit", testAccountPassword, "req-1", testSourceIP); err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	second, err := e.service.LoginAccount(ctx, "device_limit", testAccountPassword, "req-2", testSourceIP)
	if err != nil {
		t.Fatalf("第二次登入失敗：%v", err)
	}
	rowsBefore := countSessions(t, e.db)
	beforeLogin := readAccountBack(t, e, a.ID).LastLoginAt

	_, err = e.service.LoginAccount(ctx, "device_limit", testAccountPassword, "req-3", testSourceIP)
	if !errors.Is(err, ErrLoginDeviceLimit) {
		t.Fatalf("第三次登入應回名額已滿，實際 %v", err)
	}
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("名額已滿不得被說成憑據無效：那是把對的口令報成錯的口令")
	}
	if got := countSessions(t, e.db); got != rowsBefore {
		t.Errorf("被拒的登入不應留下會話行：%d → %d", rowsBefore, got)
	}
	if after := readAccountBack(t, e, a.ID).LastLoginAt; !after.Equal(beforeLogin) {
		t.Errorf("被拒的登入不應推進 last_login_at：%s → %s", beforeLogin, after)
	}
	if _, _, err := e.service.Resolve(ctx, second.Secret); err != nil {
		t.Errorf("既有第二份會話不得因名額已滿而失效：%v", err)
	}
}

// TestLoginDeviceLimitDoesNotConsumeGuardBudget 釘住「策略拒絕不進限流的帳」：
// 名額已滿的那一次既不是口令錯、也不該讓這個來源離「請稍後再試」更近一步。
func TestLoginDeviceLimitDoesNotConsumeGuardBudget(t *testing.T) {
	guard, err := NewLoginGuard(GuardConfig{
		FailLimit: 1, Window: time.Hour, Cooldown: time.Hour, SourceFailLimit: 10, MaxEntries: 100,
	}, timeutil.NewTest(testBase))
	if err != nil {
		t.Fatalf("建立登入守衛失敗：%v", err)
	}
	e := newEnvWithPolicy(t, false,
		session.Policy{DeviceMode: session.DeviceModeLimited, MaxDevices: 1}, time.Hour, guard)
	ctx := context.Background()
	e.createAccount(t, "device_guard", account.StatusActive)

	if _, err := e.service.LoginAccount(ctx, "device_guard", testAccountPassword, "req-1", testSourceIP); err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	// 第二次是名額拒絕：它必須在守衛的帳本上什麼都不留。
	if _, err := e.service.LoginAccount(ctx, "device_guard", testAccountPassword, "req-2", testSourceIP); !errors.Is(err, ErrLoginDeviceLimit) {
		t.Fatalf("第二次應回名額已滿，實際 %v", err)
	}
	// fail_limit=1：若上面那次被記成失敗，這一次就會先撞上冷卻而不是口令校驗。
	if _, err := e.service.LoginAccount(ctx, "device_guard", "錯誤口令", "req-3", testSourceIP); errors.Is(err, ErrLoginThrottled) {
		t.Fatal("名額拒絕不得消耗來源×目標的失敗額度")
	} else if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("口令錯誤仍應回憑據無效，實際 %v", err)
	}
}

// TestRootSingleModeAuditsRevokedSessions 是 Root 域的留痕要求：單裝置模式下的撤銷
// 屬 Root 域的會話生命週期事件，必須與新會話同交易寫進 root_audit。
func TestRootSingleModeAuditsRevokedSessions(t *testing.T) {
	e := newEnvWithPolicy(t, true, session.Policy{DeviceMode: session.DeviceModeSingle}, time.Hour, nil)
	ctx := context.Background()

	first, err := e.service.LoginRoot(ctx, testRootPassword, "req-1", testSourceIP)
	if err != nil {
		t.Fatalf("Root 首次登入失敗：%v", err)
	}
	if _, err := e.service.LoginRoot(ctx, testRootPassword, "req-2", testSourceIP); err != nil {
		t.Fatalf("Root 第二次登入失敗：%v", err)
	}
	if _, _, err := e.service.Resolve(ctx, first.Secret); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("Root 的舊憑據應已換不出身份，實際 %v", err)
	}
	if got := countRootAudit(t, e.db, "auth.device_revoke"); got != 1 {
		t.Errorf("應有一筆單裝置撤銷審計，實際 %d", got)
	}
	if got := countRootAudit(t, e.db, "auth.login_success"); got != 2 {
		t.Errorf("兩次成功登入應各有一筆審計，實際 %d", got)
	}
	if got := countLiveFor(t, e, "root", idgen.ID{}); got != 1 {
		t.Errorf("Root 在單設備模式下應只握有 1 份有效會話，實際 %d", got)
	}
}

// TestRootDeviceLimitAppliesWithoutException Root 沒有例外：名額佔滿時同樣被拒，
// 而且被拒的登入不寫任何審計（其它被拒的 Root 登入同一口徑，不給寫入放大器）。
func TestRootDeviceLimitAppliesWithoutException(t *testing.T) {
	e := newEnvWithPolicy(t, true,
		session.Policy{DeviceMode: session.DeviceModeLimited, MaxDevices: 1}, time.Hour, nil)
	ctx := context.Background()

	if _, err := e.service.LoginRoot(ctx, testRootPassword, "req-1", testSourceIP); err != nil {
		t.Fatalf("Root 首次登入失敗：%v", err)
	}
	auditBefore := countRootAudit(t, e.db, "auth.login_success")
	_, err := e.service.LoginRoot(ctx, testRootPassword, "req-2", testSourceIP)
	if !errors.Is(err, ErrLoginDeviceLimit) {
		t.Fatalf("Root 名額已滿時應被拒（沒有繞過入口），實際 %v", err)
	}
	if got := countRootAudit(t, e.db, "auth.login_success"); got != auditBefore {
		t.Errorf("被拒的登入不應追加成功審計：%d → %d", auditBefore, got)
	}
	if got := countRootAudit(t, e.db, "auth.login_failure"); got != 0 {
		t.Errorf("名額拒絕不是憑據失敗，不應寫失敗審計，實際 %d", got)
	}
	if got := countSessions(t, e.db); got != 1 {
		t.Errorf("被拒的登入不應簽發新會話，實際 %d 行", got)
	}
}

// TestLogoutReleasesDeviceSlot 名額釋放的另一半：登出（撤銷）之後同一格能立刻再登入。
// 這條路徑必須走用例而不是倉儲，才能證明「撤銷落地」與「下一次登入計數」看到的是同一事實。
func TestLogoutReleasesDeviceSlot(t *testing.T) {
	e := newEnvWithPolicy(t, false,
		session.Policy{DeviceMode: session.DeviceModeLimited, MaxDevices: 1}, time.Hour, nil)
	ctx := context.Background()
	e.createAccount(t, "device_logout", account.StatusActive)

	first, err := e.service.LoginAccount(ctx, "device_logout", testAccountPassword, "req-1", testSourceIP)
	if err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	if _, err := e.service.LoginAccount(ctx, "device_logout", testAccountPassword, "req-2", testSourceIP); !errors.Is(err, ErrLoginDeviceLimit) {
		t.Fatalf("名額應已被佔住，實際 %v", err)
	}
	principal, sess, err := e.service.Resolve(ctx, first.Secret)
	if err != nil {
		t.Fatalf("解析第一份會話失敗：%v", err)
	}
	if err := e.service.Logout(ctx, principal, sess, "req-logout"); err != nil {
		t.Fatalf("登出失敗：%v", err)
	}
	if _, err := e.service.LoginAccount(ctx, "device_logout", testAccountPassword, "req-3", testSourceIP); err != nil {
		t.Errorf("登出後名額應立即釋放：%v", err)
	}
}

// TestRotationKeepsDeviceSlotCount 輪換不佔新名額：上限 1 的主體在輪換之後
// 仍然只握有一份會話，而第二份登入照舊被拒（不是「輪換把格子還回去了」也不是多佔一格）。
func TestRotationKeepsDeviceSlotCount(t *testing.T) {
	e := newEnvWithPolicy(t, false,
		session.Policy{DeviceMode: session.DeviceModeLimited, MaxDevices: 1}, time.Hour, nil)
	ctx := context.Background()
	a := e.createAccount(t, "device_rotate", account.StatusActive)

	first, err := e.service.LoginAccount(ctx, "device_rotate", testAccountPassword, "req-1", testSourceIP)
	if err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	rowsBefore := countSessions(t, e.db)
	rotated, err := e.service.RotateSession(ctx, first.Secret, "req-rotate")
	if err != nil {
		t.Fatalf("輪換失敗：%v", err)
	}
	if got := countSessions(t, e.db); got != rowsBefore {
		t.Errorf("輪換不得新增會話行：%d → %d", rowsBefore, got)
	}
	if rotated.Session.DeviceID != first.Session.DeviceID {
		t.Error("輪換不得換掉設備標識")
	}
	if got := countLiveFor(t, e, "account", a.ID); got != 1 {
		t.Errorf("輪換後有效會話應仍是 1，實際 %d", got)
	}
	if _, err := e.service.LoginAccount(ctx, "device_rotate", testAccountPassword, "req-2", testSourceIP); !errors.Is(err, ErrLoginDeviceLimit) {
		t.Errorf("輪換不應騰出名額，實際 %v", err)
	}
}

// TestDeviceLimitMessageCarriesNoInternals 結論文字裡不得出現上限值或現有行數：
// 這個結論會被回給使用者，而那些屬伺服器內部配置。
func TestDeviceLimitMessageCarriesNoInternals(t *testing.T) {
	e := newEnvWithPolicy(t, false,
		session.Policy{DeviceMode: session.DeviceModeLimited, MaxDevices: 1}, time.Hour, nil)
	ctx := context.Background()
	e.createAccount(t, "device_text", account.StatusActive)
	if _, err := e.service.LoginAccount(ctx, "device_text", testAccountPassword, "req-1", testSourceIP); err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	_, err := e.service.LoginAccount(ctx, "device_text", testAccountPassword, "req-2", testSourceIP)
	if !errors.Is(err, ErrLoginDeviceLimit) {
		t.Fatalf("應回名額已滿，實際 %v", err)
	}
	text := err.Error()
	for _, leak := range []string{testAccountPassword, "max_devices", "上限是 1", "token"} {
		if strings.Contains(text, leak) {
			t.Errorf("結論文字洩露內部資訊 %q：%s", leak, text)
		}
	}
}

// readAccountBack 從庫裡讀回帳戶事實（last_login_at 這類「同一事務」斷言要用庫裡的答案，
// 而不是任何呼叫端手上殘留的副本）。
func readAccountBack(t *testing.T, e *env, id idgen.ID) account.Account {
	t.Helper()
	a, err := e.accounts.ByID(context.Background(), e.db.SQL(), id)
	if err != nil {
		t.Fatalf("讀回帳戶失敗：%v", err)
	}
	return a
}
