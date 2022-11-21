package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// 這一檔釘住本人改密的四條界線：
//   - 再認證：現行口令不對就什麼都不發生（不換憑據、不撤會話）；
//   - 生效範圍：改密成功＝舊口令失效＋該主體全部會話退出（已批準策略），
//     帳戶側連 must_change_password 也在同一交易清除；
//   - Root 的跨存儲順序：配置覆寫失敗不碰資料庫，資料庫失敗把配置回滾回去，
//     兩段都失敗時如實報錯且不留「謊報的成功」；
//   - 規則復用：新口令的形狀與「不等於現行」都經同一個 credential 服務判定，
//     失敗路徑不寫審計（Root 除外之成功記錄）、不產新雜湊。
//
// Root 側用注入的假存儲走全部路徑：config 檔案通路的實測在 internal/config
// 與 internal/app 的測試各自負責，這裡釘的是用例的順序與收斂。

const (
	testNewPassword   = "auth-test-改後口令"
	testOtherPassword = "auth-test-第三個口令"
)

// fakeRootStore 是 RootCredentialStore 的測試替身：CAS 語意與真實作同形，
// 並可按腳本讓第 N 次 Replace 失敗，用來重現「覆寫失敗」與「回滾也失敗」。
type fakeRootStore struct {
	mu          sync.Mutex
	hash        string
	replaceable bool
	calls       [][2]string
	errs        []error // 依序消耗；耗盡後回到正常 CAS 行為。
}

func newFakeRootStore(t *testing.T, password string) *fakeRootStore {
	t.Helper()
	hash, err := credential.Hash(password, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試 Root 憑據失敗：%v", err)
	}
	return &fakeRootStore{hash: hash, replaceable: true}
}

func (f *fakeRootStore) CurrentHash() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hash
}

func (f *fakeRootStore) Replaceable() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.replaceable
}

func (f *fakeRootStore) Replace(oldHash, newHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, [2]string{oldHash, newHash})
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		if err != nil {
			return err
		}
	}
	if f.hash != oldHash {
		return ErrRootCredentialStale
	}
	f.hash = newHash
	return nil
}

func (f *fakeRootStore) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// newRootServiceEnv 建立「Root 憑據接在假存儲上」的現場。
func newRootServiceEnv(t *testing.T, store RootCredentialStore) *env {
	t.Helper()
	return newEnvWithPolicy(t, false, session.Policy{}, time.Hour, nil,
		func(d *Deps) { d.RootCreds = store })
}

// createAccountWithFlag 落一個帶 must_change_password 旗標的標準帳戶。
func (e *env) createAccountWithFlag(t *testing.T, login string, mustChange bool) account.Account {
	t.Helper()
	hash, err := credential.Hash(testAccountPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	a, err := e.accounts.Create(context.Background(), e.db.SQL(), account.NewInput{
		LoginName:          login,
		DisplayName:        "改密測試帳戶",
		PasswordHash:       hash,
		Type:               account.TypeStandard,
		Status:             account.StatusActive,
		MustChangePassword: mustChange,
	})
	if err != nil {
		t.Fatalf("建立測試帳戶失敗：%v", err)
	}
	return a
}

// sessionValid 回報一枚會話秘密是否仍換得出身份。
func sessionValid(t *testing.T, e *env, secret string) bool {
	t.Helper()
	_, _, err := e.service.Resolve(context.Background(), secret)
	return err == nil
}

// TestChangePasswordAccountSwitchesAndRevokesAll 改密成功的全套落地：
// 舊口令失效、新口令可登入、全部會話（含發起這臺）撤銷、旗標清除、不寫審計。
func TestChangePasswordAccountSwitchesAndRevokesAll(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	a := e.createAccountWithFlag(t, "pw_switch", true)

	first, err := e.service.LoginAccount(ctx, "pw_switch", testAccountPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("首次登入失敗：%v", err)
	}
	if !first.MustChangePassword {
		t.Error("登入結果應帶上 must_change_password 旗標")
	}
	second, err := e.service.LoginAccount(ctx, "pw_switch", testAccountPassword, "r2", testSourceIP)
	if err != nil {
		t.Fatalf("第二次登入失敗：%v", err)
	}

	res, err := e.service.ChangePassword(ctx, first.Principal, testAccountPassword, testNewPassword, "r3")
	if err != nil {
		t.Fatalf("改密失敗：%v", err)
	}
	if res.RevokedSessions != 2 {
		t.Errorf("應撤銷兩枚會話，實際 %d", res.RevokedSessions)
	}
	if sessionValid(t, e, first.Secret) || sessionValid(t, e, second.Secret) {
		t.Error("改密後舊會話仍換得出身份")
	}
	if _, err := e.service.LoginAccount(ctx, "pw_switch", testAccountPassword, "r4", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("舊口令應被拒為憑據無效，實際 %v", err)
	}
	next, err := e.service.LoginAccount(ctx, "pw_switch", testNewPassword, "r5", testSourceIP)
	if err != nil {
		t.Fatalf("新口令應可登入：%v", err)
	}
	if next.MustChangePassword {
		t.Error("改密成功後 must_change_password 應已清除")
	}
	stored, err := e.accounts.ByID(ctx, e.db.SQL(), a.ID)
	if err != nil || stored.MustChangePassword {
		t.Errorf("庫內旗標未清除：%+v err=%v", stored, err)
	}
	if n := countRootAudit(t, e.db, "auth.password_change"); n != 0 {
		t.Errorf("普通帳戶改密不寫審計（主體類別未批準），root_audit 出現 %d 筆", n)
	}
}

// TestChangePasswordAccountCASRace 併發改密：同一現場兩個 goroutine 帶著同一枚
// 現行口令各改各的，只能有一個成功；輸家收斂為憑據拒絕，且兩者的會話都被贏家撤銷。
func TestChangePasswordAccountCASRace(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	a := e.createAccountWithFlag(t, "pw_race", false)
	out, err := e.service.LoginAccount(ctx, "pw_race", testAccountPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		errs     []error
		startSig = make(chan struct{})
	)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-startSig
			_, err := e.service.ChangePassword(ctx, out.Principal, testAccountPassword, newPws(i), "race")
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
		}(i)
	}
	close(startSig)
	wg.Wait()

	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrInvalidCredentials):
			// 輸家：現值已被贏家換掉（預檢或 CAS 任一關攔下），收斂為憑據拒絕。
		default:
			t.Fatalf("改密競跑出非預期錯誤：%v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("成功次數=%d，期望恰好 1", wins)
	}
	if sessionValid(t, e, out.Secret) {
		t.Error("無論誰贏，發起者的舊會話都該被撤銷")
	}
	stored, err := e.accounts.ByID(ctx, e.db.SQL(), a.ID)
	if err != nil || stored.MustChangePassword {
		t.Errorf("贏家的變更應同時清旗標：%+v err=%v", stored, err)
	}
}

func newPws(i int) string {
	if i == 0 {
		return testNewPassword
	}
	return testOtherPassword
}

// TestChangePasswordRejectsWrongCurrent 現行口令不對時整個動作沒有發生：
// 憑據未換、會話未撤、旗標未動，結論與登入被拒同形。
func TestChangePasswordRejectsWrongCurrent(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	a := e.createAccountWithFlag(t, "pw_wrong", true)
	out, err := e.service.LoginAccount(ctx, "pw_wrong", testAccountPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}

	// 打錯的口令與「乾脆沒填」都收斂同一個憑據拒絕結論。
	for _, bad := range []string{"pw_wrong-打錯的", ""} {
		if _, err := e.service.ChangePassword(ctx, out.Principal, bad, testNewPassword, "r2"); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("現行口令 %q 應回憑據拒絕，實際 %v", bad, err)
		}
	}
	if !sessionValid(t, e, out.Secret) {
		t.Error("被拒的改密不該撤銷任何會話")
	}
	stored, _ := e.accounts.ByID(ctx, e.db.SQL(), a.ID)
	if !stored.MustChangePassword {
		t.Error("被拒的改密不該清除旗標")
	}
	if _, err := e.service.LoginAccount(ctx, "pw_wrong", testNewPassword, "r3", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("新口令不該已經生效，實際 %v", err)
	}
}

// TestChangePasswordRejectsSameOrMalformedNew 新口令等於現行、為空、超長都在
// 任何寫入之前被拒；三種拒絕的結論各是各的，且都不撤會話。
func TestChangePasswordRejectsSameOrMalformedNew(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.createAccount(t, "pw_same", account.StatusActive)
	out, err := e.service.LoginAccount(ctx, "pw_same", testAccountPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}

	if _, err := e.service.ChangePassword(ctx, out.Principal, testAccountPassword, testAccountPassword, "r2"); !errors.Is(err, ErrSamePassword) {
		t.Errorf("新口令等於現行應回 ErrSamePassword，實際 %v", err)
	}
	long := "x" + strings.Repeat("y", credential.MaxPasswordLength)
	for name, bad := range map[string]string{"空字串": "", "超長": long} {
		if _, err := e.service.ChangePassword(ctx, out.Principal, testAccountPassword, bad, "r3"); !errors.Is(err, ErrInvalidNewPassword) {
			t.Errorf("新口令 %s 應回 ErrInvalidNewPassword，實際 %v", name, err)
		}
	}
	if !sessionValid(t, e, out.Secret) {
		t.Error("被拒的改密不該撤銷任何會話")
	}
}

// TestChangePasswordGuestHasNoPasswordPath 訪客帳戶沒有口令通路：改密被拒為
// 憑據無效，且不觸碰資料庫任何行。
func TestChangePasswordGuestHasNoPasswordPath(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	guest, err := e.accounts.Create(ctx, e.db.SQL(), account.NewInput{
		LoginName:   "guest_pw",
		DisplayName: "訪客",
		Type:        account.TypeGuest,
		Status:      account.StatusActive,
	})
	if err != nil {
		t.Fatalf("建立訪客帳戶失敗：%v", err)
	}
	principal, err := identity.NewAccountPrincipal(identity.AccountInput{
		Subject: identity.SubjectOf(guest),
		Origin:  identity.OriginHTTPRequest,
	})
	if err != nil {
		t.Fatalf("構造主體失敗：%v", err)
	}
	if _, err := e.service.ChangePassword(ctx, principal, "", testNewPassword, "r1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("訪客改密應收斂為憑據拒絕，實際 %v", err)
	}
}

// TestMustChangePasswordReadsFresh 旗標是現讀：改密成功後的下一步請求就該看到解除。
func TestMustChangePasswordReadsFresh(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.createAccountWithFlag(t, "pw_flag", true)
	out, err := e.service.LoginAccount(ctx, "pw_flag", testAccountPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}
	if got, err := e.service.MustChangePassword(ctx, out.Principal); err != nil || !got {
		t.Fatalf("旗標設定時應現讀為 true：%v", err)
	}
	if _, err := e.service.ChangePassword(ctx, out.Principal, testAccountPassword, testNewPassword, "r2"); err != nil {
		t.Fatalf("改密失敗：%v", err)
	}
	// 原會話已被撤銷， Principal 仍可用於「查旗標」這個純讀路徑——
	// 它讀的是帳戶行的現在，不是會話的現在。
	if got, err := e.service.MustChangePassword(ctx, out.Principal); err != nil || got {
		t.Errorf("改密成功後應現讀為 false：%v", got)
	}

	// Root 主體沒有這個旗標；查無此人的帳戶主體收斂為 false 而不是錯誤。
	rootStore := newFakeRootStore(t, testRootPassword)
	re := newRootServiceEnv(t, rootStore)
	rootOut, err := re.service.LoginRoot(ctx, testRootPassword, "root-login", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入失敗：%v", err)
	}
	if got, err := re.service.MustChangePassword(ctx, rootOut.Principal); err != nil || got {
		t.Errorf("Root 主體應恆為 false：%v %v", got, err)
	}
	ghost, err := identity.NewAccountPrincipal(identity.AccountInput{
		Subject: identity.AccountSubject{ID: ghostID(t), Type: account.TypeStandard, Status: account.StatusActive},
		Origin:  identity.OriginHTTPRequest,
	})
	if err != nil {
		t.Fatalf("構造幽靈主體失敗：%v", err)
	}
	if got, err := e.service.MustChangePassword(ctx, ghost); err != nil || got {
		t.Errorf("查無此人應收斂 false 且無錯誤：%v %v", got, err)
	}
}

func ghostID(t *testing.T) idgen.ID {
	t.Helper()
	id, err := idgen.New()
	if err != nil {
		t.Fatalf("產生測試標識失敗：%v", err)
	}
	return id
}

// TestChangePasswordRootSuccess Root 改密的完整成功形態：新雜湊生效於存儲、
// 舊口令登入被拒、新口令可登入、全部 Root 會話撤銷、root_audit 留下一筆。
func TestChangePasswordRootSuccess(t *testing.T) {
	store := newFakeRootStore(t, testRootPassword)
	e := newRootServiceEnv(t, store)
	ctx := context.Background()
	first, err := e.service.LoginRoot(ctx, testRootPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入失敗：%v", err)
	}
	second, err := e.service.LoginRoot(ctx, testRootPassword, "r2", testSourceIP)
	if err != nil {
		t.Fatalf("Root 第二次登入失敗：%v", err)
	}

	res, err := e.service.ChangePassword(ctx, first.Principal, testRootPassword, testNewPassword, "r3")
	if err != nil {
		t.Fatalf("Root 改密失敗：%v", err)
	}
	if res.RevokedSessions != 2 {
		t.Errorf("應撤銷兩枚 Root 會話，實際 %d", res.RevokedSessions)
	}
	if sessionValid(t, e, first.Secret) || sessionValid(t, e, second.Secret) {
		t.Error("Root 改密後舊會話仍換得出身份")
	}
	if store.callCount() != 1 {
		t.Errorf("成功路徑只該有一次 Replace，實際 %d 次", store.callCount())
	}
	if _, err := e.service.LoginRoot(ctx, testRootPassword, "r4", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("舊口令應被拒，實際 %v", err)
	}
	if _, err := e.service.LoginRoot(ctx, testNewPassword, "r5", testSourceIP); err != nil {
		t.Errorf("新口令應可登入，實際 %v", err)
	}
	if n := countRootAudit(t, e.db, "auth.password_change"); n != 1 {
		t.Errorf("Root 改密應留下一筆審計，實際 %d", n)
	}
	var targetKind, reason string
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT target_kind, reason FROM root_audit WHERE action = 'auth.password_change'").
		Scan(&targetKind, &reason); err != nil {
		t.Fatalf("讀審計失敗：%v", err)
	}
	if targetKind != "server" {
		t.Errorf("改密審計的對象應是 server，實際 %q", targetKind)
	}
	if strings.Contains(reason, store.currentHash()) || strings.Contains(reason, testNewPassword) {
		t.Errorf("審計 reason 洩露了憑據：%q", reason)
	}
}

func (f *fakeRootStore) currentHash() string { return f.CurrentHash() }

// TestChangePasswordRootWrongCurrentNoWrites 現行口令不對：不覆寫、不撤會話、不寫審計。
func TestChangePasswordRootWrongCurrentNoWrites(t *testing.T) {
	store := newFakeRootStore(t, testRootPassword)
	e := newRootServiceEnv(t, store)
	ctx := context.Background()
	out, err := e.service.LoginRoot(ctx, testRootPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入失敗：%v", err)
	}
	oldHash := store.CurrentHash()

	if _, err := e.service.ChangePassword(ctx, out.Principal, "root-打錯的", testNewPassword, "r2"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("應回憑據拒絕，實際 %v", err)
	}
	if _, err := e.service.ChangePassword(ctx, out.Principal, testRootPassword, testRootPassword, "r3"); !errors.Is(err, ErrSamePassword) {
		t.Fatalf("等於現行應回 ErrSamePassword，實際 %v", err)
	}
	if _, err := e.service.ChangePassword(ctx, out.Principal, testRootPassword, "", "r4"); !errors.Is(err, ErrInvalidNewPassword) {
		t.Fatalf("空新口令應回 ErrInvalidNewPassword，實際 %v", err)
	}
	if store.CurrentHash() != oldHash || store.callCount() != 0 {
		t.Error("被拒的 Root 改密動到了憑據存儲")
	}
	if !sessionValid(t, e, out.Secret) {
		t.Error("被拒的 Root 改密不該撤銷會話")
	}
	if n := countRootAudit(t, e.db, "auth.password_change"); n != 0 {
		t.Errorf("被拒的改密不寫審計，實際 %d 筆", n)
	}
}

// TestChangePasswordRootNotReplaceable 部署形態不接受覆寫時：在一切寫入之前被拒，
// 會話與資料庫都不動。且檢查發生在口令校驗之後——不對的口令先拿到 2001，
// 未授權者探不到部署形態。
func TestChangePasswordRootNotReplaceable(t *testing.T) {
	store := newFakeRootStore(t, testRootPassword)
	store.replaceable = false
	e := newRootServiceEnv(t, store)
	ctx := context.Background()
	out, err := e.service.LoginRoot(ctx, testRootPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入失敗：%v", err)
	}

	if _, err := e.service.ChangePassword(ctx, out.Principal, "錯的口令", testNewPassword, "r2"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("口令不對時應先得到憑據拒絕，實際 %v", err)
	}
	if _, err := e.service.ChangePassword(ctx, out.Principal, testRootPassword, testNewPassword, "r3"); !errors.Is(err, ErrRootCredentialLocked) {
		t.Fatalf("不可覆寫的部署應回 ErrRootCredentialLocked，實際 %v", err)
	}
	if store.callCount() != 0 || !sessionValid(t, e, out.Secret) {
		t.Error("被拒的改密動到了會話或存儲")
	}
}

// TestChangePasswordRootReplaceFailsSkipsDB 覆寫配置失敗時資料庫整個不動：
// 會話還活著，這次改密像沒有發生過一樣失敗。
func TestChangePasswordRootReplaceFailsSkipsDB(t *testing.T) {
	store := newFakeRootStore(t, testRootPassword)
	boom := errors.New("模擬：配置寫不入")
	store.errs = []error{boom}
	e := newRootServiceEnv(t, store)
	ctx := context.Background()
	out, err := e.service.LoginRoot(ctx, testRootPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入失敗：%v", err)
	}

	_, err = e.service.ChangePassword(ctx, out.Principal, testRootPassword, testNewPassword, "r2")
	if !errors.Is(err, boom) {
		t.Fatalf("覆寫失敗應原樣上報，實際 %v", err)
	}
	if !sessionValid(t, e, out.Secret) {
		t.Error("覆寫失敗時不該撤銷任何會話")
	}
	if n := countRootAudit(t, e.db, "auth.password_change"); n != 0 {
		t.Errorf("覆寫失敗不寫審計，實際 %d 筆", n)
	}
	// 舊口令仍可登入：覆寫沒成功就不能把生效說成發生過。
	if _, err := e.service.LoginRoot(ctx, testRootPassword, "r3", testSourceIP); err != nil {
		t.Errorf("覆寫失敗後舊口令該照常可登入，實際 %v", err)
	}
}

// TestChangePasswordRootStaleConcurrent 現值在校驗與覆寫之間被並發改掉：
// 輸家收斂為憑據拒絕，資料庫不動。
func TestChangePasswordRootStaleConcurrent(t *testing.T) {
	store := newFakeRootStore(t, testRootPassword)
	store.errs = []error{ErrRootCredentialStale}
	e := newRootServiceEnv(t, store)
	ctx := context.Background()
	out, err := e.service.LoginRoot(ctx, testRootPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入失敗：%v", err)
	}

	if _, err := e.service.ChangePassword(ctx, out.Principal, testRootPassword, testNewPassword, "r2"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("現值過期應收斂為憑據拒絕，實際 %v", err)
	}
	if !sessionValid(t, e, out.Secret) {
		t.Error("現值過期的改密不該撤銷會話")
	}
}

// TestChangePasswordRootTxFailureRollsBack 配置覆寫成功、資料庫交易失敗：
// 補償把配置與記憶體換回舊雜湊，對外報失敗——不存在「報成功而舊口令仍可用」，
// 也不存在「口令已換但被說成沒換」。
func TestChangePasswordRootTxFailureRollsBack(t *testing.T) {
	store := newFakeRootStore(t, testRootPassword)
	e := newRootServiceEnv(t, store)
	oldHash := store.CurrentHash()
	out, err := e.service.LoginRoot(context.Background(), testRootPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入失敗：%v", err)
	}

	// 用已取消的 context 讓交易在 Begin 處就失敗：撤銷與審計都沒落地，
	// 用例必須走補償路徑把憑據換回去。
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = e.service.ChangePassword(canceled, out.Principal, testRootPassword, testNewPassword, "r2")
	if err == nil {
		t.Fatal("資料庫不可用時改密必須失敗")
	}
	if !strings.Contains(err.Error(), "回滾") {
		t.Errorf("失敗訊息應交代回滾，實際：%v", err)
	}
	if store.CurrentHash() != oldHash {
		t.Error("補償後憑據存儲應回到舊雜湊")
	}
	if !sessionValid(t, e, out.Secret) {
		t.Error("補償路徑不該撤銷會話")
	}
	// 舊口令恢復可用（補償成功的直接可觀察面）。
	if _, err := e.service.LoginRoot(context.Background(), testRootPassword, "r3", testSourceIP); err != nil {
		t.Errorf("回滾後舊口令該照常可登入，實際 %v", err)
	}
}

// TestChangePasswordRootAuditFailureRollsBackRootTable 審計寫不進去＝撤銷整個不發生：
// 沿用 Root 域事件「同生同滅」的合同，並照樣觸發憑據回滾。
func TestChangePasswordRootAuditFailureRollsBackRootTable(t *testing.T) {
	store := newFakeRootStore(t, testRootPassword)
	e := newRootServiceEnv(t, store)
	oldHash := store.CurrentHash()
	ctx := context.Background()
	out, err := e.service.LoginRoot(ctx, testRootPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入失敗：%v", err)
	}
	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("移除審計表失敗：%v", err)
	}

	if _, err := e.service.ChangePassword(ctx, out.Principal, testRootPassword, testNewPassword, "r2"); err == nil {
		t.Fatal("審計寫不進去時改密必須失敗")
	}
	if store.CurrentHash() != oldHash {
		t.Error("交易失敗應補償回舊憑據")
	}
	if !sessionValid(t, e, out.Secret) {
		t.Error("審計缺席時撤銷也該整個回滾")
	}
}

// TestChangePasswordRootRollbackFailsReportsTruth 雙重故障（資料庫壞＋回滾壞）：
// 口令已換、舊會話暫活（受絕對期限封頂）、審計缺席——對外的失敗訊息必須
// 同時講出兩半，不假裝一切如未發生。
func TestChangePasswordRootRollbackFailsReportsTruth(t *testing.T) {
	store := newFakeRootStore(t, testRootPassword)
	boom := errors.New("模擬：回滾也寫不入")
	store.errs = []error{nil, boom}
	e := newRootServiceEnv(t, store)
	ctx := context.Background()
	out, err := e.service.LoginRoot(ctx, testRootPassword, "r1", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入失敗：%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = e.service.ChangePassword(canceled, out.Principal, testRootPassword, testNewPassword, "r2")
	if err == nil {
		t.Fatal("雙重故障必須報錯")
	}
	if !strings.Contains(err.Error(), "回滾") || !strings.Contains(err.Error(), "撤銷") {
		t.Errorf("失敗訊息應交代兩半，實際：%v", err)
	}
	// 此刻新口令已經生效（存儲現值是新雜湊）；舊口令登入被拒。
	if _, err := e.service.LoginRoot(ctx, testNewPassword, "r3", testSourceIP); err != nil {
		t.Errorf("回滾失敗時新口令應生效，實際 %v", err)
	}
	if _, err := e.service.LoginRoot(ctx, testRootPassword, "r4", testSourceIP); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("回滾失敗時舊口令應失效，實際 %v", err)
	}
}

// TestChangePasswordRequiresAccountOrRootPrincipal 匿名與系統主體沒有口令通路：
// 用例層直接拒絕，不觸碰任何存儲。
func TestChangePasswordRequiresAccountOrRootPrincipal(t *testing.T) {
	e := newEnv(t, false)
	if _, err := e.service.ChangePassword(context.Background(), identity.Anonymous(),
		"a", "b", "r1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("匿名主體應被拒，實際 %v", err)
	}
	sys, err := identity.NewSystem(identity.OriginCLI)
	if err != nil {
		t.Fatalf("構造系統主體失敗：%v", err)
	}
	if _, err := e.service.ChangePassword(context.Background(), sys, "a", "b", "r2"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("系統主體應被拒，實際 %v", err)
	}
	if got := countSessions(t, e.db); got != 0 {
		t.Errorf("被拒的路徑不該有任何會話行，實際 %d", got)
	}
}

// 編譯期證據：假存儲確實實現了介面（欄位對不上時第一時間紅在這裏）。
var _ RootCredentialStore = (*fakeRootStore)(nil)
