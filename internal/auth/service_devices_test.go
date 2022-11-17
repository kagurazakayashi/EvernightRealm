package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// 這一檔釘住「我的裝置」在登入用例層的三條界線：
//   - 列舉範圍只由受信主體決定，換不出一個人、也漏不出別人的裝置；
//   - 定向撤銷只能碰自己的會話，重複撤銷冪等，被撤銷的憑據立即換不出身份；
//   - Root 的撤銷在 Root 審計留痕、普通帳戶只進執行日誌（審計主體類別未批准）。
//
// 全部走真實的 LoginAccount／LoginRoot 簽發會話，而不是直插資料庫：要釘的是
// 「解析出來的Principal→裝置範圍→撤銷→下一條請求被拒」這條端到端會話生命週期，
// 只有真實簽發才能證明清單看到的就是驗證看到的。

// TestListDevicesScopesToPrincipal 每個主體只列舉到自己的裝置。
func TestListDevicesScopesToPrincipal(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	e.createAccount(t, "dev_a", account.StatusActive)
	e.createAccount(t, "dev_b", account.StatusActive)

	a1, err := e.service.LoginAccount(ctx, "dev_a", testAccountPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("A 首次登入失敗：%v", err)
	}
	a2, err := e.service.LoginAccount(ctx, "dev_a", testAccountPassword, "r2", testSourceIP)
	if err != nil {
		t.Fatalf("A 二次登入失敗：%v", err)
	}
	if _, err := e.service.LoginAccount(ctx, "dev_b", testAccountPassword, "r3", testSourceIP); err != nil {
		t.Fatalf("B 登入失敗：%v", err)
	}
	r1, err := e.service.LoginRoot(ctx, testRootPassword, "r4", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入失敗：%v", err)
	}

	listA, err := e.service.ListDevices(ctx, a1.Principal)
	if err != nil {
		t.Fatalf("列舉 A 失敗：%v", err)
	}
	if len(listA) != 2 {
		t.Fatalf("A 只該看到自己的兩臺，實際 %d", len(listA))
	}
	seen := map[string]bool{listA[0].DeviceID.String(): true, listA[1].DeviceID.String(): true}
	if !seen[a1.Session.DeviceID.String()] || !seen[a2.Session.DeviceID.String()] {
		t.Error("A 的清單未涵蓋它自己簽發的兩枚裝置標識")
	}
	for _, s := range listA {
		if s.Subject.Kind() != session.SubjectAccount || s.Subject.AccountID() != a1.Principal.AccountID() {
			t.Errorf("A 的清單混進了非本帳戶主體：%s", s.DeviceID.String())
		}
	}

	listRoot, err := e.service.ListDevices(ctx, r1.Principal)
	if err != nil {
		t.Fatalf("列舉 Root 失敗：%v", err)
	}
	if len(listRoot) != 1 {
		t.Errorf("Root 只該看到自己那一臺，實際 %d", len(listRoot))
	}
}

// TestRevokeDeviceRejectsSubsequentSecret 撤銷自己的裝置後，那枚憑據立即換不出身份。
func TestRevokeDeviceRejectsSubsequentSecret(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.createAccount(t, "dev_revoke", account.StatusActive)
	out, err := e.service.LoginAccount(ctx, "dev_revoke", testAccountPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}
	// 撤銷前先確認這枚秘密確實有效（否則「撤銷後被拒」說明不了任何事）。
	if _, _, err := e.service.Resolve(ctx, out.Secret); err != nil {
		t.Fatalf("撤銷前憑據應有效：%v", err)
	}
	res, err := e.service.RevokeDevice(ctx, out.Principal, out.Session.DeviceID, "r2")
	if err != nil {
		t.Fatalf("撤銷自己的裝置失敗：%v", err)
	}
	if !res.Revoked {
		t.Error("第一次撤銷有效裝置應回報 Revoked=true")
	}
	if _, _, err := e.service.Resolve(ctx, out.Secret); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("被撤銷裝置的憑據應立即失效（收斂為 ErrInvalidSession），實際 %v", err)
	}
}

// TestRevokeDeviceCrossAccountRejected A 撤銷 B 的裝置標識時收斂為 ErrNotFound，
// 且 B 的會話絲毫不受影響——不给「用撤銷试探别人裝置是否存在」留信号。
func TestRevokeDeviceCrossAccountRejected(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.createAccount(t, "dev_own", account.StatusActive)
	e.createAccount(t, "dev_victim", account.StatusActive)
	a, err := e.service.LoginAccount(ctx, "dev_own", testAccountPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("A 登入失敗：%v", err)
	}
	b, err := e.service.LoginAccount(ctx, "dev_victim", testAccountPassword, "r2", testSourceIP)
	if err != nil {
		t.Fatalf("B 登入失敗：%v", err)
	}
	if _, err := e.service.RevokeDevice(ctx, a.Principal, b.Session.DeviceID, "r3"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("越權撤銷應回 ErrNotFound，實際 %v", err)
	}
	if _, _, err := e.service.Resolve(ctx, b.Secret); err != nil {
		t.Errorf("越權嘗試不得動到 B 的會話：%v", err)
	}
}

// TestRevokeDeviceIdempotent 重複撤銷同一枚裝置冪等：第二次回報 no-op，不報錯。
func TestRevokeDeviceIdempotent(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.createAccount(t, "dev_twice", account.StatusActive)
	out, err := e.service.LoginAccount(ctx, "dev_twice", testAccountPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}
	if _, err := e.service.RevokeDevice(ctx, out.Principal, out.Session.DeviceID, "r2"); err != nil {
		t.Fatalf("第一次撤銷失敗：%v", err)
	}
	res, err := e.service.RevokeDevice(ctx, out.Principal, out.Session.DeviceID, "r3")
	if err != nil {
		t.Fatalf("重複撤銷應冪等成功：%v", err)
	}
	if res.Revoked {
		t.Error("重複撤銷不得再回報 Revoked=true")
	}
}

// TestRevokeDeviceUnknownID 撤銷一枚根本不存在的裝置標識：ErrNotFound，且不落任何會話變更。
func TestRevokeDeviceUnknownID(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.createAccount(t, "dev_unknown", account.StatusActive)
	out, err := e.service.LoginAccount(ctx, "dev_unknown", testAccountPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}
	before := countSessions(t, e.db)
	ghost, err := idgen.New()
	if err != nil {
		t.Fatalf("產生裝置標識失敗：%v", err)
	}
	if _, err := e.service.RevokeDevice(ctx, out.Principal, ghost, "r2"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("撤銷不存在的裝置應回 ErrNotFound，實際 %v", err)
	}
	if countSessions(t, e.db) != before {
		t.Error("撤銷不存在的裝置不應改動任何會話行")
	}
}

// TestRevokeDeviceRootWritesAuditRootOnly Root 撤銷自己的裝置會留 Root 域審計；
// 普通帳戶的同樣操作不得進審計表（審計主體類別未批准，只進執行日誌）。
func TestRevokeDeviceRootWritesAuditRootOnly(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	r1, err := e.service.LoginRoot(ctx, testRootPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("Root 首次登入失敗：%v", err)
	}
	r2, err := e.service.LoginRoot(ctx, testRootPassword, "r2", testSourceIP)
	if err != nil {
		t.Fatalf("Root 二次登入失敗：%v", err)
	}
	if _, err := e.service.RevokeDevice(ctx, r1.Principal, r1.Session.DeviceID, "r3"); err != nil {
		t.Fatalf("Root 撤銷裝置失敗：%v", err)
	}
	if got := countRootAudit(t, e.db, "auth.device_revoke"); got != 1 {
		t.Errorf("Root 撤銷應留 1 筆 auth.device_revoke，實際 %d", got)
	}
	// 撤銷只停掉指到的那一臺，另一臺 Root 會話照常可用。
	if _, _, err := e.service.Resolve(ctx, r2.Secret); err != nil {
		t.Errorf("未被撤銷的另一臺 Root 會話不應受牽連：%v", err)
	}
	if _, _, err := e.service.Resolve(ctx, r1.Secret); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("被撤銷的 Root 憑據應立即失效，實際 %v", err)
	}

	// 冪等：重複撤銷同一枚不再追加第二筆撤銷審計。
	if _, err := e.service.RevokeDevice(ctx, r1.Principal, r1.Session.DeviceID, "r4"); err != nil {
		t.Fatalf("Root 重複撤銷失敗：%v", err)
	}
	if got := countRootAudit(t, e.db, "auth.device_revoke"); got != 1 {
		t.Errorf("冪等撤銷不得追加撤銷審計，實際 %d 筆", got)
	}

	e.createAccount(t, "dev_noaudit", account.StatusActive)
	a, err := e.service.LoginAccount(ctx, "dev_noaudit", testAccountPassword, "r5", testSourceIP)
	if err != nil {
		t.Fatalf("帳戶登入失敗：%v", err)
	}
	if _, err := e.service.RevokeDevice(ctx, a.Principal, a.Session.DeviceID, "r6"); err != nil {
		t.Fatalf("帳戶撤銷裝置失敗：%v", err)
	}
	if got := countRootAudit(t, e.db, "auth.device_revoke"); got != 1 {
		t.Errorf("普通帳戶撤銷不得寫 Root 域審計，實際 %d 筆（應仍只有 Root 那 1 筆）", got)
	}
}
