package session

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 這一檔釘住「裝置登入策略」的全部語義：
//   - 名額算的是主體此刻還換得出的會話，與請求裡可自報的任何東西無關；
//   - single：新登入讓該主體的舊會話全部失效，並存數恆為 1；
//   - multi：並存且不封頂（零值同樣是這個）；
//   - limited：封頂，滿了就拒絕新登入，而不是淘汰誰；
//   - 輪換不佔名額、撤銷與到期立即釋放名額；
//   - 併發登入的「檢查＋寫入」由同一個交易序列化，不會全部通過而超限。

// loginAt 重現一次「成功登入」在倉儲層的形狀：先在同一個交易裡跑策略、再簽發會話。
//
// 必須走交易而不是兩個 db.SQL() 呼叫：本檔要釘的就是「檢查與寫入協調」這條線，
// 把它拆成兩次 autocommit 就是拿測試模擬一個生產不存在的形狀。
func loginAt(t *testing.T, store *Store, db *database.DB, p identity.Principal) (Session, string, error) {
	t.Helper()
	var (
		sess   Session
		secret string
	)
	err := db.InTx(context.Background(), func(tctx context.Context, tx *database.Tx) error {
		if _, err := store.ApplyLoginSlotPolicy(tctx, tx, p); err != nil {
			return err
		}
		created, issued, err := store.Create(tctx, tx, p)
		if err != nil {
			return err
		}
		sess, secret = created, issued
		return nil
	})
	if err != nil {
		return Session{}, "", err
	}
	return sess, secret, nil
}

// countLiveRows 用一條與實作無關的 SQL 數出「還換得出身份」的行。
//
// 斷言不能借用被測程式碼自己的計數函式，否則策略算錯時測試會跟著一起錯。
func countLiveRows(t *testing.T, db *database.DB, kind string, accountID string, now time.Time, idle time.Duration) int {
	t.Helper()
	query := `SELECT COUNT(*) FROM sessions
		WHERE subject_kind = ? AND revoked_at IS NULL AND expires_at > ?`
	args := []any{kind, timeutil.ToMillis(now)}
	if accountID != "" {
		query += " AND account_id = ?"
		args = append(args, accountID)
	}
	if idle > 0 {
		query += " AND last_active_at + ? > ?"
		args = append(args, idle.Milliseconds(), timeutil.ToMillis(now))
	}
	var n int
	if err := db.SQL().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("統計有效會話失敗：%v", err)
	}
	return n
}

// TestDevicePolicyConstructionRejectsInconsistentPolicy 把「半套策略」關在構造階段：
// 不認識的模式、limited 卻沒有名額、以及其它模式帶著一個名額數字，都當場報錯。
func TestDevicePolicyConstructionRejectsInconsistentPolicy(t *testing.T) {
	cases := []struct {
		name   string
		policy Policy
		want   string
	}{
		{"模式不認識", Policy{DeviceMode: "everywhere"}, "不認識的裝置策略模式"},
		{"limited 沒有名額", Policy{DeviceMode: DeviceModeLimited}, "名額必須為正值"},
		{"limited 負名額", Policy{DeviceMode: DeviceModeLimited, MaxDevices: -1}, "名額必須為正值"},
		{"single 帶名額", Policy{DeviceMode: DeviceModeSingle, MaxDevices: 3}, "只在 limited 模式使用"},
		{"multi 帶名額", Policy{DeviceMode: DeviceModeMulti, MaxDevices: 3}, "只在 limited 模式使用"},
	}
	for _, tc := range cases {
		if _, err := NewStoreWithPolicy(timeutil.NewTest(testBase), time.Hour, tc.policy); err == nil {
			t.Errorf("%s：應在構造時拒絕", tc.name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s：錯誤訊息應含 %q，實際 %v", tc.name, tc.want, err)
		}
	}

	// 合法組合：零值（沿用 multi）、以及三種模式各自的正確寫法。
	for _, policy := range []Policy{
		{},
		{DeviceMode: DeviceModeSingle},
		{DeviceMode: DeviceModeMulti},
		{DeviceMode: DeviceModeLimited, MaxDevices: 5},
	} {
		if _, err := NewStoreWithPolicy(timeutil.NewTest(testBase), time.Hour, policy); err != nil {
			t.Errorf("合法策略 %+v 不應報錯：%v", policy, err)
		}
	}
}

// TestParseDeviceModeAcceptsConfigValuesAndDefaults 確認裝配層的解析邊界：
// 空字串沿用預設（multi），三個已定義值原樣換得，其它一律拒絕。
func TestParseDeviceModeAcceptsConfigValuesAndDefaults(t *testing.T) {
	for value, want := range map[string]DeviceMode{
		"":        DeviceModeMulti,
		"single":  DeviceModeSingle,
		"multi":   DeviceModeMulti,
		"limited": DeviceModeLimited,
	} {
		got, err := ParseDeviceMode(value)
		if err != nil {
			t.Errorf("ParseDeviceMode(%q) 不應報錯：%v", value, err)
			continue
		}
		if got != want {
			t.Errorf("ParseDeviceMode(%q) = %q，期望 %q", value, got, want)
		}
	}
	for _, bad := range []string{"one", "Limited", "1", "any device"} {
		if _, err := ParseDeviceMode(bad); err == nil {
			t.Errorf("ParseDeviceMode(%q) 應拒絕", bad)
		}
	}
}

// TestSingleDeviceLoginRevokesPriorSessions 是規格那條要求的落點：單裝置模式下，
// 新登入成功時舊會話立即失效——不是「舊的還能用一會兒」。
func TestSingleDeviceLoginRevokesPriorSessions(t *testing.T) {
	db, clock, store := newPolicyEnv(t, time.Hour, Policy{DeviceMode: DeviceModeSingle})
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, clock, "single_a")

	first, firstSecret, err := loginAt(t, store, db, principal)
	if err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	second, secondSecret, err := loginAt(t, store, db, principal)
	if err != nil {
		t.Fatalf("第二次登入失敗：%v", err)
	}
	if second.ID == first.ID {
		t.Error("新登入必須簽發新會話（防會話固定）")
	}

	// 舊的那一枚此刻換不出身份，而且是「已撤銷」而不是「查無此秘密」。
	if _, err := store.Verify(ctx, db.SQL(), firstSecret); !errors.Is(err, ErrRevoked) {
		t.Errorf("舊會話應已被撤銷，實際 %v", err)
	}
	if _, err := store.Verify(ctx, db.SQL(), secondSecret); err != nil {
		t.Errorf("新會話應可用：%v", err)
	}
	if got := countLiveRows(t, db, "account", principal.AccountID().String(), clock.Now(), 0); got != 1 {
		t.Errorf("單裝置模式的有效會話應恆為 1，實際 %d", got)
	}
	// 表裡留下 3 行不奇怪（首次登入 1 行 + 第二次 1 行 = 2 行），但只有 1 行是活的。
	if got := countSessions(t, db); got != 2 {
		t.Errorf("兩次登入各留一行記錄（撤銷不是刪除），實際 %d", got)
	}
}

// TestSingleDeviceRevokeCountAndScope 驗確認銷範圍：只動這個主體、只動活的行。
// 回傳值是給日誌與 Root 審計用的可展示事實，不能把別人的會話一起算進去。
func TestSingleDeviceRevokeCountAndScope(t *testing.T) {
	db, clock, store := newPolicyEnv(t, time.Hour, Policy{DeviceMode: DeviceModeSingle})
	ctx := context.Background()
	_, alice := createAccountDirect(t, db, clock, "single_alice")
	_, bob := createAccountDirect(t, db, clock, "single_bob")

	// 首輪登入沒有可撤銷的東西：回傳 0 而不是報錯。
	revoked, err := store.ApplyLoginSlotPolicy(ctx, db.SQL(), alice)
	if err != nil || revoked != 0 {
		t.Fatalf("主體尚無會話時應回傳 0 且不報錯，實際 revoked=%d err=%v", revoked, err)
	}
	if _, _, err := loginAt(t, store, db, alice); err != nil {
		t.Fatalf("Alice 首次登入失敗：%v", err)
	}
	if _, _, err := loginAt(t, store, db, alice); err != nil {
		t.Fatalf("Alice 第二次登入失敗：%v", err)
	}
	bobSess, bobSecret, err := loginAt(t, store, db, bob)
	if err != nil {
		t.Fatalf("Bob 登入失敗：%v", err)
	}

	// Alice 第三次登入：撤銷的恰好是她自己那一份活的會話，Bob 的不受影響。
	revoked, err = store.ApplyLoginSlotPolicy(ctx, db.SQL(), alice)
	if err != nil {
		t.Fatalf("第三次登入的策略執行失敗：%v", err)
	}
	if revoked != 1 {
		t.Errorf("應只撤銷 Alice 的 1 個有效會話，實際 %d", revoked)
	}
	if _, err := store.Verify(ctx, db.SQL(), bobSecret); err != nil {
		t.Errorf("其它主體的會話絕不能被連帶撤銷：%v", err)
	}
	if got := countLiveRows(t, db, "account", bobSess.Subject.AccountID().String(), clock.Now(), 0); got != 1 {
		t.Errorf("Bob 的有效會話應為 1，實際 %d", got)
	}
}

// TestMultiDeviceKeepsSessionsCoexisting 釘住 multi（含零值）的語義：並存、不封頂、
// 一次登入也不會讓既有會話失效。零值必須是這個行為，否則新增欄位就悄悄改了既有部署。
func TestMultiDeviceKeepsSessionsCoexisting(t *testing.T) {
	for name, policy := range map[string]Policy{
		"零值":    {},
		"multi": {DeviceMode: DeviceModeMulti},
	} {
		db, clock, store := newPolicyEnv(t, time.Hour, policy)
		ctx := context.Background()
		_, principal := createAccountDirect(t, db, clock, "multi_"+name)

		secrets := make([]string, 0, 3)
		for i := 0; i < 3; i++ {
			_, secret, err := loginAt(t, store, db, principal)
			if err != nil {
				t.Fatalf("%s 第 %d 次登入失敗：%v", name, i+1, err)
			}
			secrets = append(secrets, secret)
		}
		for i, secret := range secrets {
			if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
				t.Errorf("%s 第 %d 枚憑據應仍然有效：%v", name, i+1, err)
			}
		}
		if got := countLiveRows(t, db, "account", principal.AccountID().String(), clock.Now(), 0); got != 3 {
			t.Errorf("%s：三份登入應有三個有效會話，實際 %d", name, got)
		}
	}
}

// TestLimitedModeRejectsAtLimit 是「指定上限」的核心：滿了就拒絕，且拒絕是整個不發生——
// 既不簽發新會話，也不撤銷任何既有會話（本步批准的處置是拒絕，不是淘汰）。
func TestLimitedModeRejectsAtLimit(t *testing.T) {
	db, clock, store := newPolicyEnv(t, time.Hour, Policy{DeviceMode: DeviceModeLimited, MaxDevices: 2})
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, clock, "limited_two")

	_, firstSecret, err := loginAt(t, store, db, principal)
	if err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	if _, _, err := loginAt(t, store, db, principal); err != nil {
		t.Fatalf("第二次登入（名額 2 的最後一格）失敗：%v", err)
	}
	rowsBefore := countSessions(t, db)

	_, _, err = loginAt(t, store, db, principal)
	if !errors.Is(err, ErrDeviceLimitReached) {
		t.Fatalf("第三次登入應被名額拒絕，實際 %v", err)
	}
	if got := countSessions(t, db); got != rowsBefore {
		t.Errorf("被拒的登入不得留下任何會話行：%d → %d", rowsBefore, got)
	}
	// 兩份既有會話一個都沒被停掉：拒絕不是「擠掉最舊那一臺」。
	if _, err := store.Verify(ctx, db.SQL(), firstSecret); err != nil {
		t.Errorf("既有會話不得因名額已滿而被撤銷：%v", err)
	}
	if got := countLiveRows(t, db, "account", principal.AccountID().String(), clock.Now(), 0); got != 2 {
		t.Errorf("有效會話應停在上限 2，實際 %d", got)
	}
}

// TestLimitedLimitCountsBySubject 確認名額按主體算，而不是全伺服器一把計數器：
// 一個人佔滿不會把別人鎖在門外，Root 與帳戶也各自獨立。
func TestLimitedLimitCountsBySubject(t *testing.T) {
	db, clock, store := newPolicyEnv(t, time.Hour, Policy{DeviceMode: DeviceModeLimited, MaxDevices: 1})
	_, alice := createAccountDirect(t, db, clock, "limit_alice")
	_, bob := createAccountDirect(t, db, clock, "limit_bob")
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	if _, _, err := loginAt(t, store, db, alice); err != nil {
		t.Fatalf("Alice 首次登入失敗：%v", err)
	}
	if _, _, err := loginAt(t, store, db, alice); !errors.Is(err, ErrDeviceLimitReached) {
		t.Errorf("Alice 的名額已滿，第二次應被拒，實際 %v", err)
	}
	if _, _, err := loginAt(t, store, db, bob); err != nil {
		t.Errorf("Bob 的名額與 Alice 無關，不應被拒：%v", err)
	}
	if _, _, err := loginAt(t, store, db, root); err != nil {
		t.Errorf("Root 的名額與帳戶無關，不應被拒：%v", err)
	}
	if _, _, err := loginAt(t, store, db, root); !errors.Is(err, ErrDeviceLimitReached) {
		t.Errorf("Root 走同一條規則：名額已滿時同樣被拒，實際 %v", err)
	}
}

// TestSlotReleasedByRevoke 驗確認銷立即歸還名額：登出之後同一格就能再登入。
func TestSlotReleasedByRevoke(t *testing.T) {
	db, clock, store := newPolicyEnv(t, time.Hour, Policy{DeviceMode: DeviceModeLimited, MaxDevices: 1})
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, clock, "slot_revoke")

	sess, _, err := loginAt(t, store, db, principal)
	if err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	if _, _, err := loginAt(t, store, db, principal); !errors.Is(err, ErrDeviceLimitReached) {
		t.Fatalf("名額應已被佔住，實際 %v", err)
	}
	if _, err := store.Revoke(ctx, db.SQL(), sess.ID); err != nil {
		t.Fatalf("撤銷失敗：%v", err)
	}
	if _, _, err := loginAt(t, store, db, principal); err != nil {
		t.Errorf("撤銷後名額應立即釋放：%v", err)
	}
}

// TestSlotReleasedByAbsoluteExpiry 確認「過了絕對期限」的那一行不再佔名額：
// 會話到期是設計上的死亡時刻，死掉的會話不該繼續把人擋在門外。
func TestSlotReleasedByAbsoluteExpiry(t *testing.T) {
	db, clock, store := newPolicyEnv(t, time.Hour, Policy{DeviceMode: DeviceModeLimited, MaxDevices: 1})
	_, principal := createAccountDirect(t, db, clock, "slot_expire")

	if _, _, err := loginAt(t, store, db, principal); err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	clock.Advance(2 * time.Hour)
	if _, _, err := loginAt(t, store, db, principal); err != nil {
		t.Errorf("會話已過絕對期限，名額應已釋放：%v", err)
	}
}

// TestSlotReleasedByIdleDeadline 確認閒置失效同樣釋放名額：佔格子的判準是「還換得出身份」，
// 而閒置失效的會話已經換不出身份（與 Verify 的拒絕條件同源，不留兩個時鐘）。
func TestSlotReleasedByIdleDeadline(t *testing.T) {
	db, clock, store := newPolicyEnv(t, 24*time.Hour, Policy{
		DeviceMode:     DeviceModeLimited,
		MaxDevices:     1,
		IdleTTL:        time.Hour,
		TouchThreshold: time.Hour,
	})
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, clock, "slot_idle")

	_, secret, err := loginAt(t, store, db, principal)
	if err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	// 絕對期限還在（24 小時），但閒置線已越過：Verify 與計數必須給同一個答案。
	clock.Advance(2 * time.Hour)
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrExpired) {
		t.Fatalf("閒置過期的會話應被 Verify 拒絕，實際 %v", err)
	}
	if _, _, err := loginAt(t, store, db, principal); err != nil {
		t.Errorf("閒置失效的會話不應佔名額：%v", err)
	}
	if got := countLiveRows(t, db, "account", principal.AccountID().String(), clock.Now(), time.Hour); got != 1 {
		t.Errorf("新會話簽發後有效數應回到 1，實際 %d", got)
	}
}

// TestRotationDoesNotConsumeSlot 是「輪換不算新裝置」的落點：同一行換秘密，
// 行數不變、世代號變，名額因此不可能被一次輪換吃掉的格子又還回來、或多佔一格。
func TestRotationDoesNotConsumeSlot(t *testing.T) {
	db, clock, store := newPolicyEnv(t, time.Hour, Policy{DeviceMode: DeviceModeLimited, MaxDevices: 2})
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, clock, "rotate_slot")

	_, firstSecret, err := loginAt(t, store, db, principal)
	if err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	// 連環輪換：每次都是同一行，世代號一路推進，有效會話數始終是 1。
	secret := firstSecret
	for i := 1; i <= 3; i++ {
		rotated, next, err := store.Rotate(ctx, db.SQL(), secret)
		if err != nil {
			t.Fatalf("第 %d 次輪換失敗：%v", i, err)
		}
		if rotated.RotationSeq != int64(i) {
			t.Errorf("世代號應為 %d，實際 %d", i, rotated.RotationSeq)
		}
		if got := countLiveRows(t, db, "account", principal.AccountID().String(), clock.Now(), 0); got != 1 {
			t.Fatalf("輪換不得改變有效會話數，第 %d 次後為 %d", i, got)
		}
		secret = next
	}

	// 佔滿第二格，再輪換一次：仍然只有 2 格，第三份登入被拒。
	if _, _, err := loginAt(t, store, db, principal); err != nil {
		t.Fatalf("第二次登入失敗：%v", err)
	}
	if _, _, err := store.Rotate(ctx, db.SQL(), secret); err != nil {
		t.Fatalf("名額佔滿時的輪換仍應成功：%v", err)
	}
	if got := countLiveRows(t, db, "account", principal.AccountID().String(), clock.Now(), 0); got != 2 {
		t.Errorf("輪換後有效會話數應仍為 2，實際 %d", got)
	}
	if _, _, err := loginAt(t, store, db, principal); !errors.Is(err, ErrDeviceLimitReached) {
		t.Errorf("第三份登入應被名額拒絕，實際 %v", err)
	}
}

// staticClock 是併發測試用的固定時鐘：時刻永不自己前進，也不需要鎖。
//
// 注入式時鐘（timeutil.Test）刻意不加鎖，因此併發用例另給一枚不可變的時鐘，
// 而不是讓資料競態混進「名額有沒有算對」這個要證的事裡。
type staticClock struct{ at time.Time }

func (c staticClock) Now() time.Time { return c.at }

// TestConcurrentLoginsDoNotExceedLimit 是「併發登入不能全部通過而超限」的證據：
// 檢查與寫入同在一個交易裡，SQLite 的單一寫者把六次嘗試串成六個先後，
// 於是「還剩一格」這件事不可能同時對兩個登入成立。
func TestConcurrentLoginsDoNotExceedLimit(t *testing.T) {
	const limit = 2
	clock := staticClock{at: testBase}
	dbPath := filepath.Join(retryTempDir(t), "evernight.db")
	db, err := database.Open(context.Background(), database.Options{Path: dbPath, BusyTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: clock}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	store, err := NewStoreWithPolicy(clock, time.Hour, Policy{DeviceMode: DeviceModeLimited, MaxDevices: limit})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	_, principal := createAccountDirect(t, db, clock, "concurrent")

	const attempts = 6
	var wg sync.WaitGroup
	results := make([]error, attempts)
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // 盡量把六次嘗試壓在同一個瞬間起跑
			results[i] = db.InTx(context.Background(), func(tctx context.Context, tx *database.Tx) error {
				if _, err := store.ApplyLoginSlotPolicy(tctx, tx, principal); err != nil {
					return err
				}
				_, _, err := store.Create(tctx, tx, principal)
				return err
			})
		}(i)
	}
	close(start)
	wg.Wait()

	var accepted, rejected, other int
	for _, e := range results {
		switch {
		case e == nil:
			accepted++
		case errors.Is(e, ErrDeviceLimitReached):
			rejected++
		default:
			other++
			t.Errorf("非預期的失敗：%v", e)
		}
	}
	if accepted != limit {
		t.Errorf("名額 %d 的併發登入應恰好放行 %d 次，實際 %d（拒絕 %d）", limit, limit, accepted, rejected)
	}
	if rejected != attempts-limit {
		t.Errorf("其餘 %d 次應被名額拒絕，實際 %d", attempts-limit, rejected)
	}
	if got := countLiveRows(t, db, "account", principal.AccountID().String(), clock.Now(), 0); got != limit {
		t.Errorf("併發結束後有效會話數必須仍是 %d，實際 %d", limit, got)
	}
}

// TestApplyLoginSlotPolicyRejectsMissingSubjectAndConnection 是入口的兩道Shape檢查：
// 匿名主體沒有「登入」這件事，nil 連線則是要在裝配階段就喊出來的缺陷。
func TestApplyLoginSlotPolicyRejectsMissingSubjectAndConnection(t *testing.T) {
	db, _, store := newPolicyEnv(t, time.Hour, Policy{DeviceMode: DeviceModeSingle})
	anonymous := identity.Anonymous()
	if _, err := store.ApplyLoginSlotPolicy(context.Background(), db.SQL(), anonymous); !errors.Is(err, ErrInvalidSubject) {
		t.Errorf("匿名主體不應執行裝置策略，實際 %v", err)
	}
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	if _, err := store.ApplyLoginSlotPolicy(context.Background(), nil, root); err == nil {
		t.Error("缺少資料庫連線時應報錯，而不是默認放行")
	}
}

// failingInsert 是一個只在「插入會話那一行」時回錯的 Querier 替身。
//
// 存在的理由：要證明「先撤銷、後簽發」確實同生同滅，就得讓後面那一步在交易中途失敗。
// 用 goroutine 去撞那個時窗不可重現，停用帳戶又會讓判據混進主體狀態——
// 這個替身把失敗固定在同一條語句上，斷言就只剩事務邊界本身。
type failingInsert struct {
	database.Querier
}

func (q failingInsert) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if strings.Contains(query, "INSERT INTO sessions") {
		return nil, errors.New("測試注入：寫入會話失敗")
	}
	return q.Querier.ExecContext(ctx, query, args...)
}

// TestSingleDeviceLoginRollsBackOnCreateFailure 驗確認銷與簽發的同生同滅：
// 單裝置模式先撤銷舊會話，若隨後建會話失敗，整個交易回滾，
// 舊會話必須照舊有效——絕不能出現「人被關在門外」的半套結果。
func TestSingleDeviceLoginRollsBackOnCreateFailure(t *testing.T) {
	db, clock, store := newPolicyEnv(t, time.Hour, Policy{DeviceMode: DeviceModeSingle})
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, clock, "rollback_a")

	sess, secret, err := loginAt(t, store, db, principal)
	if err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
		t.Fatalf("前提：首次登入的會話應有效：%v", err)
	}

	injectErr := db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if _, err := store.ApplyLoginSlotPolicy(tctx, failingInsert{Querier: tx}, principal); err != nil {
			return err
		}
		_, _, err := store.Create(tctx, failingInsert{Querier: tx}, principal)
		return err
	})
	if injectErr == nil {
		t.Fatal("注入的寫入失敗應把整個交易打成失敗")
	}

	// 判據直接看庫裡那一行的 revoked_at：策略先寫下去的撤銷必須一起消失。
	var live int
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sessions WHERE id = ? AND revoked_at IS NULL", sess.ID.String()).
		Scan(&live); err != nil {
		t.Fatalf("讀回撤銷事實失敗：%v", err)
	}
	if live != 1 {
		t.Error("策略的撤銷應隨交易一起回滾（revoked_at 仍為 NULL）")
	}
	if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
		t.Errorf("回滾後舊會話應照舊可用：%v", err)
	}
}
