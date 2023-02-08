// resetpassword_test.go 是「管理員重置普通帳戶登入憑據」用例層的定向證據：
// 真資料庫＋注入時鐘＋真登入與會話倉儲，斷言對象是三件事的合力——舊口令死亡、
// 舊會話撤銷、首次改密義務重設——以及被拒時「一件都不發生」的形態。
//
// 這一檔特別量兩條邊界：
//   - 訪戶帳戶（無一般密碼）出局，且出局點在寫入之前——沿這條通路寫哈希等於
//     替他完成一次身分升級，而那不在本步的職責裡；
//   - 持有授予的人（另一位管理員、操作者自己）與刪除終態同回查無，
//     「管理員不能重置其他管理員或 Root」因此不是界面約定而是判定。
//
// 刻意不收的東西：沒有替身（授權、範圍、派生、撤銷、審計都走真路徑）；
// 不碰任何真實資料目錄、不佔 5206，全程用本次專屬的暫存庫與注入時鐘。
package stdacct

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// 重置測試口令：只活在測試進程的記憶體，不是任何環境的憑據。
const (
	testResetPassword  = "stdacct-test-重置口令甲"
	testResetPassword2 = "stdacct-test-重置口令乙"
)

// resetStoredHash 直讀帳戶的憑據雜湊（測試取證用；生產判定從不直讀這一欄）。
func resetStoredHash(t *testing.T, e *env, accountID idgen.ID) string {
	t.Helper()
	var hash string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT password_hash FROM accounts WHERE id = ?", accountID.String()).Scan(&hash); err != nil {
		t.Fatalf("讀回憑據雜湊失敗：%v", err)
	}
	return hash
}

// mustVerify 斷言某個明文口令能否過現行雜湊（「舊口令死了」的存在證明）。
func mustVerify(t *testing.T, hash, password string) bool {
	t.Helper()
	ok, err := credential.Verify(hash, password)
	if err != nil {
		t.Fatalf("校驗測試口令失敗：%v", err)
	}
	return ok
}

// countResetAudits 數 Root 域裡的重置審計筆數（拒絕不寫審計的證據）。
func countResetAudits(t *testing.T, e *env) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM root_audit WHERE action = 'account.password_reset'`).Scan(&n); err != nil {
		t.Fatalf("計數重置審計失敗：%v", err)
	}
	return n
}

// TestResetStandardReplacesCredentialRevokesSessionsAndAudits
// 重置的三件效果一起落地：哈希換掉且舊口令徹底死亡、目標全部會話（多裝置）失效、
// 義務重設；審計落在 Root 域且操作者是那位管理員本人，而且只碰該碰的兩欄。
func TestResetStandardReplacesCredentialRevokesSessionsAndAudits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "reset.one")
	secrets := newAccountSessions(t, e, created.AccountID, 2)
	beforeHash := resetStoredHash(t, e, created.AccountID)

	result, err := e.service.ResetStandardAccountPassword(ctx, admin, created.AccountID,
		testResetPassword, "req-reset-1")
	if err != nil {
		t.Fatalf("重置失敗：%v", err)
	}
	if result.RevokedSessions != 2 {
		t.Errorf("重置應撤銷目標全部 2 份會話（跨裝置），實際 %d", result.RevokedSessions)
	}
	if !result.Profile.MustChangePassword {
		t.Error("重置後的口令必須帶「首次登入須改密」義務")
	}
	if result.Profile.Status != account.StatusActive {
		t.Errorf("重置不該動狀態欄，實際 %s", result.Profile.Status)
	}
	afterHash := resetStoredHash(t, e, created.AccountID)
	if afterHash == beforeHash {
		t.Fatal("重置必須換掉憑據雜湊")
	}
	if !strings.HasPrefix(afterHash, "$argon2id$") {
		t.Error("新雜湊必須是入庫同款編碼形態（前綴異常）")
	}
	if mustVerify(t, afterHash, testInitialPassword) {
		t.Error("舊口令必須徹底失效")
	}
	if !mustVerify(t, afterHash, testResetPassword) {
		t.Error("新口令必須能過現行雜湊")
	}
	for i, secret := range secrets {
		if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); !errors.Is(err, session.ErrRevoked) {
			t.Errorf("第 %d 份重置前會話應按已撤銷被拒，實際 %v", i+1, err)
		}
	}

	var targetID, actorKind, changes, reason string
	if err := e.db.SQL().QueryRowContext(ctx,
		`SELECT target_id, actor_kind, changes_json, reason FROM root_audit
		 WHERE action = 'account.password_reset'`).
		Scan(&targetID, &actorKind, &changes, &reason); err != nil {
		t.Fatalf("讀回重置審計失敗：%v", err)
	}
	if targetID != created.AccountID.String() || actorKind != string(audit.ActorAdmin) {
		t.Errorf("審計應指向被重置的帳戶且操作者為 admin，實際 %s／%s", targetID, actorKind)
	}
	if !strings.Contains(changes, "must_change_password") || !strings.Contains(changes, "revoked_sessions") {
		t.Errorf("審計摘要應帶義務旗標與撤銷數量，實際 %s", changes)
	}
	// 結構性的那一句：審計本體連一個可能容下憑據材料的格子都沒有。
	for _, secret := range []string{testInitialPassword, testResetPassword, "$argon2id$", "password_hash"} {
		if strings.Contains(changes, secret) || strings.Contains(reason, secret) {
			t.Errorf("重置審計不得含口令明文、雜湊或雜湊欄位影子（命中 %s）", secret)
		}
	}
	for _, secret := range secrets {
		if strings.Contains(changes, secret) || strings.Contains(reason, secret) {
			t.Error("重置審計不得帶出任何會話秘密")
		}
	}
	if strings.Contains(e.logs.String(), testResetPassword) ||
		strings.Contains(e.logs.String(), "$argon2id$") {
		t.Error("執行日誌不得含口令明文或憑據雜湊")
	}
}

// TestResetOnlyTouchesCredentialColumns 整行快照作證：重置只讓 password_hash 與
// must_change_password 兩欄位移，停用時刻、類型、三個時刻、登入名與鍵逐字不動——
// 「重置不是解除停用、不是改名、不是復活」成立在 SQL 形狀上。
func TestResetOnlyTouchesCredentialColumns(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "overlay.reset")
	// 先把他停用再恢復，讓 disabled_at 回到 NULL 之外也有東西可比對；
	// 這裡真正要的是「一行裡除兩欄外都不動」，因此直接用整行快照比對。
	if _, err := e.db.SQL().ExecContext(ctx,
		"UPDATE accounts SET must_change_password = 0 WHERE id = ?", created.AccountID.String()); err != nil {
		t.Fatalf("製造「已改過密」現場失敗：%v", err)
	}
	before := rowSnapshot(t, e, created.AccountID)

	if _, err := e.service.ResetStandardAccountPassword(ctx, admin, created.AccountID,
		testResetPassword, "req-overlay-reset"); err != nil {
		t.Fatalf("重置失敗：%v", err)
	}
	after := rowSnapshot(t, e, created.AccountID)
	if after == before {
		t.Fatal("重置至少必須換掉憑據雜湊（整行逐字不動說明沒寫進去）")
	}
	diff := func(row string) string {
		// 把「不該動的欄位」拼出來比對：只有雜湊與旗標那兩段允許不同。
		segments := strings.Split(row, "|")
		kept := make([]string, 0, len(segments))
		for _, p := range segments {
			if strings.HasPrefix(p, "password_hash=") || strings.HasPrefix(p, "must_change=") {
				continue
			}
			kept = append(kept, p)
		}
		return strings.Join(kept, "|")
	}
	if diff(before) != diff(after) {
		t.Errorf("重置只許動憑據與旗標兩欄，变更前 %s／實際 %s", before, after)
	}
}

// TestResetFirstSignInLoopCloses 交付出去的一次性口令真能走既有的首改閉環：
// 重置口令登入（仍欠改密）→ 本人完成改密 → 義務解除、重置口令徹底死亡。
//
// 這一條是「重置交付的口令與開設交付的口令走同一道門閂」的接縫證據：
// 本步不另造第二套首改規則，一個字节的改密實作都沒複製。
func TestResetFirstSignInLoopCloses(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	authService := e.newAuthService(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "reset.loop")

	// 先把本人已經償還過的義務做實（初始口令登入＋改密），讓重置面對的是「不欠密的人」，
	// 並留下「改過之後仍然欠」的證據——交付的口令永遠是一次性的。
	outcome, err := authService.LoginAccount(ctx, "reset.loop", testInitialPassword,
		"req-loop-login-1", "127.0.0.1")
	if err != nil {
		t.Fatalf("初始口令登入失敗：%v", err)
	}
	if _, err := authService.ChangePassword(ctx, outcome.Principal, testInitialPassword,
		testNewPassword, "req-loop-change-1"); err != nil {
		t.Fatalf("本人完成首次改密失敗：%v", err)
	}
	// 改密會撤掉名下全部會話，因此重新登入一份，作為「重置前活著的會話」。
	live, err := authService.LoginAccount(ctx, "reset.loop", testNewPassword,
		"req-loop-login-2", "127.0.0.1")
	if err != nil {
		t.Fatalf("改密後重新登入失敗：%v", err)
	}

	if _, err := e.service.ResetStandardAccountPassword(ctx, admin, created.AccountID,
		testResetPassword2, "req-loop-reset"); err != nil {
		t.Fatalf("重置失敗：%v", err)
	}
	if _, _, err := authService.Resolve(ctx, live.Secret); err == nil {
		t.Error("重置必須讓重置前那份活著的會話失效")
	}
	// 本人改過的那個口令也同時死亡：重置換掉的是整欄雜湊，不是補發一個並存口令。
	if _, err := authService.LoginAccount(ctx, "reset.loop", testNewPassword,
		"req-loop-login-3", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("本人先前那個口令必須在重置後失效，實際 %v", err)
	}

	reset, err := authService.LoginAccount(ctx, "reset.loop", testResetPassword2,
		"req-loop-login-4", "127.0.0.1")
	if err != nil {
		t.Fatalf("重置口令應能登入：%v", err)
	}
	if !reset.MustChangePassword {
		t.Error("重置交付的口令首次登入必須回報「還欠一次改密」")
	}
	if _, err := authService.ChangePassword(ctx, reset.Principal, testResetPassword2,
		"stdacct-test-本人改後口令", "req-loop-change-2"); err != nil {
		t.Fatalf("以重置口令完成改密失敗：%v", err)
	}
	after, err := authService.LoginAccount(ctx, "reset.loop", "stdacct-test-本人改後口令",
		"req-loop-login-5", "127.0.0.1")
	if err != nil {
		t.Fatalf("本人改密後應能以最終口令登入：%v", err)
	}
	if after.MustChangePassword {
		t.Error("本人完成改密後義務必須解除")
	}
	if _, err := authService.LoginAccount(ctx, "reset.loop", testResetPassword2,
		"req-loop-login-6", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("重置口令在完成改密後必須徹底死亡，實際 %v", err)
	}
}

// TestResetOnDisabledTargetKeepsDisabledState 停用中的目標可以被重置，
// 且重置不解除停用、不復活會話、撤銷數量為 0（其會話早在停用時已撤）。
func TestResetOnDisabledTargetKeepsDisabledState(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	authService := e.newAuthService(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "reset.disabled")
	secrets := newAccountSessions(t, e, created.AccountID, 1)
	if _, err := e.service.UpdateStandardAccountStatus(ctx, admin, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-pre-disable"); err != nil {
		t.Fatalf("預先停用失敗：%v", err)
	}

	result, err := e.service.ResetStandardAccountPassword(ctx, admin, created.AccountID,
		testResetPassword, "req-reset-disabled")
	if err != nil {
		t.Fatalf("對停用目標重置失敗：%v", err)
	}
	if result.Profile.Status != account.StatusDisabled || result.Profile.DisabledAt.IsZero() {
		t.Errorf("重置後目標必須仍是停用且停用時刻不改，實際 %+v", result.Profile)
	}
	if result.RevokedSessions != 0 {
		t.Errorf("停用者的會話早已撤光，這次重置不該再撤到東西，實際 %d", result.RevokedSessions)
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); !errors.Is(err, session.ErrRevoked) {
		t.Errorf("重置不復活停用前會話，實際 %v", err)
	}
	// 重置不給登入開後門：停用期間交出去的那個口令仍登不進去（與口令打錯同形）。
	if _, err := authService.LoginAccount(ctx, "reset.disabled", testResetPassword,
		"req-login-disabled-after-reset", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("重置不解除停用，登入應仍被拒且與憑據錯誤同形，實際 %v", err)
	}
	var statusText string
	var disabledAt, mustFlag int
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT status, disabled_at, must_change_password FROM accounts WHERE id = ?",
		created.AccountID.String()).Scan(&statusText, &disabledAt, &mustFlag); err != nil {
		t.Fatalf("讀回停用形態失敗：%v", err)
	}
	if statusText != "disabled" || disabledAt == 0 || mustFlag != 1 {
		t.Errorf("停用狀態必須原樣保持且重置後欠改密，實際 %s／%d／%d",
			statusText, disabledAt, mustFlag)
	}
}

// TestResetGuestIsRefusedWithoutWrites 訪戶帳戶今日沒有可重置的一般密碼：
// 沿這條通路寫哈希等於替他完成一次訪戶→普通的升級綁定，因此出局點在寫入之前，
// 整行形態（含無哈希、無旗標）逐字不動、零審計。
//
// 這是服務層那句 2018：處置不是「換個目標」（這本目錄列得到他），
// 也不是「改口令寫法」或「換個身分」，而是等後續那條明確的訪戶升級通路。
func TestResetGuestIsRefusedWithoutWrites(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := e.seed(t, seedInput{Login: "reset.overlay.guest", Display: "訪戶帳戶",
		Type: account.TypeGuest})
	before := rowSnapshot(t, e, guest.ID)
	audits := countRows(t, e.db, "root_audit")

	if _, err := e.service.ResetStandardAccountPassword(ctx, admin, guest.ID,
		testResetPassword, "req-guest-reset"); !errors.Is(err, ErrGuestTarget) {
		t.Errorf("訪戶目標應回獨立的可判別結論（2018 的那一句），實際 %v", err)
	}
	if got := rowSnapshot(t, e, guest.ID); got != before {
		t.Errorf("被拒的訪戶重置一個字都不該落庫，變更前 %s／實際 %s", before, got)
	}
	if got := countRows(t, e.db, "root_audit"); got != audits {
		t.Errorf("被拒的重置不得追加審計（前 %d 後 %d）", audits, got)
	}
	// 反面證據：同一個走訪戶的請求，即使先把建號開關關掉也不會變成另一句話——
	// 出局來自目標形態，不來自策略。
	e.setAdminCreate(t, false)
	if _, err := e.service.ResetStandardAccountPassword(ctx, admin, guest.ID,
		testResetPassword, "req-guest-reset-policy-off"); !errors.Is(err, ErrGuestTarget) {
		t.Errorf("策略與訪戶出局各自獨立，實際 %v", err)
	}
}

// TestResetTargetScope 目標範圍：另一位管理員、操作者自己、刪除終態、Root 保留標識、
// 幽靈標識與零值標識一律同一句話（ErrAccountNotFound），且零寫入零審計。
//
// 這一條量的是本步那句邊界：普通管理員不能拿這條通路重置其他管理員，也重置不到 Root。
func TestResetTargetScope(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	self := e.seed(t, seedInput{Login: "reset.scope.self", Display: "我自己"})
	if err := e.service.grants.Grant(ctx, e.db.SQL(), self.ID, identity.RoleServerAdmin); err != nil {
		t.Fatalf("補上操作者授予失敗：%v", err)
	}
	admin := identitytest.Account(t, self.ID, identitytest.ServerAdmin())
	peer := e.seed(t, seedInput{Login: "reset.scope.peer", Display: "另一位管理員", Admin: true})
	deleted := e.seed(t, seedInput{Login: "reset.scope.gone", Display: "已刪除的", Deleted: true})
	audits := countResetAudits(t, e)

	rootSubjectID, err := identity.RootSubjectID()
	if err != nil {
		t.Fatalf("取 Root 保留標識失敗：%v", err)
	}
	for name, id := range map[string]idgen.ID{
		"另一位管理員":    peer.ID,
		"操作者自己":     self.ID,
		"刪除終態":      deleted.ID,
		"Root 保留標識": rootSubjectID,
		"幽靈標識":      identitytest.NewID(t),
		"零值標識":      idgen.ID{},
	} {
		if _, err := e.service.ResetStandardAccountPassword(ctx, admin, id,
			testResetPassword, "req-scope-"+name); !errors.Is(err, ErrAccountNotFound) {
			t.Errorf("%s 應回不在目錄的同形結論，實際 %v", name, err)
		}
	}
	if got := rowSnapshot(t, e, peer.ID); !strings.Contains(got, "password_hash=") {
		t.Errorf("peer 現值讀取異常：%s", got)
	}
	if got := countResetAudits(t, e); got != audits {
		t.Errorf("範圍外的目標不該留下重置審計，應 %d 實際 %d", audits, got)
	}
	if n := countRows(t, e.db, "sessions"); n != 0 {
		t.Errorf("本測試沒簽發過會話，實際 sessions 有 %d 行", n)
	}
}

// TestResetRejectsNonAdminSubjects 授權矩陣：普通帳戶、訪客帳戶、系統主體與匿名主體
// 對重置都回權限或未認證結論，且零寫入、零撤銷、零審計。
func TestResetRejectsNonAdminSubjects(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	target := e.mustCreate(t,
		identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin()), "reset.guard")
	secrets := newAccountSessions(t, e, target.AccountID, 2)
	before := rowSnapshot(t, e, target.AccountID)
	audits := countResetAudits(t, e)

	for name, principal := range map[string]identity.Principal{
		"普通帳戶": identitytest.Account(t, identitytest.NewID(t)),
		"訪客帳戶": identitytest.Account(t, identitytest.NewID(t), identitytest.WithGuestType()),
		"系統主體": identitytest.System(t, identity.OriginCLI),
	} {
		if _, err := e.service.ResetStandardAccountPassword(ctx, principal, target.AccountID,
			testResetPassword, "req-guard-"+name); !errors.Is(err, identity.ErrPermissionDenied) {
			t.Errorf("%s 重置他人憑據應回權限錯誤，實際 %v", name, err)
		}
	}
	if _, err := e.service.ResetStandardAccountPassword(ctx, identitytest.Anonymous(t),
		target.AccountID, testResetPassword, "req-guard-anonymous"); !errors.Is(err, identity.ErrNotAuthenticated) {
		t.Errorf("匿名主體應回未認證而不是權限錯誤，實際 %v", err)
	}
	if got := rowSnapshot(t, e, target.AccountID); got != before {
		t.Errorf("被拒的重置一個字都不該落庫，變更前 %s／實際 %s", before, got)
	}
	for i, secret := range secrets {
		if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); err != nil {
			t.Errorf("被拒的重置不該撤銷任何會話，第 %d 份實際 %v", i+1, err)
		}
	}
	if got := countResetAudits(t, e); got != audits {
		t.Errorf("被拒的請求不該寫審計（寫入放大器），應 %d 實際 %d", audits, got)
	}
}

// TestResetRejectsInvalidPasswordWithoutWrites 口令形狀不合格是請求本體的問題：
// 派生在交易外就被擋下，一個查詢、一次撤銷、一筆審計都不該發生。
func TestResetRejectsInvalidPasswordWithoutWrites(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "reset.badpw")
	secrets := newAccountSessions(t, e, created.AccountID, 1)
	before := rowSnapshot(t, e, created.AccountID)
	audits := countResetAudits(t, e)

	for name, password := range map[string]string{
		"空口令":  "",
		"超長口令": strings.Repeat("長", credential.MaxPasswordLength),
	} {
		if _, err := e.service.ResetStandardAccountPassword(ctx, admin, created.AccountID,
			password, "req-"+name); !errors.Is(err, ErrInvalidResetPassword) {
			t.Errorf("%s：應回口令形狀結論，實際 %v", name, err)
		}
	}
	if got := rowSnapshot(t, e, created.AccountID); got != before {
		t.Error("被拒的重置不得動目標帳戶任何一欄")
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); err != nil {
		t.Errorf("被拒的重置不得半套撤銷會話，實際 %v", err)
	}
	if got := countResetAudits(t, e); got != audits {
		t.Errorf("被拒的重置不得追加審計（前 %d 後 %d）", audits, got)
	}
}

// TestRepeatedResetEachIsWholeOperation 重複請求的批准語意：每次都做一次完整重置。
//
// 這與停用的 2014（「對著舊畫面再點一次」被拒）刻意不同：本用例沒有依據值，
// 第二次提交不是「陳舊的失敗嘗試」，而是又一次真實生效的特權操作——所以它必須
// 如實再撤一輪會話、如實再留一筆審計，界面因此不得在結果不明時自動重發。
func TestRepeatedResetEachIsWholeOperation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "reset.repeat")

	first, err := e.service.ResetStandardAccountPassword(ctx, admin, created.AccountID,
		testResetPassword, "req-repeat-1")
	if err != nil {
		t.Fatalf("首次重置失敗：%v", err)
	}
	if first.RevokedSessions != 0 {
		t.Errorf("還沒有任何會話可撤，首次重置應撤 0，實際 %d", first.RevokedSessions)
	}
	secret := newAccountSessions(t, e, created.AccountID, 1)[0]
	second, err := e.service.ResetStandardAccountPassword(ctx, admin, created.AccountID,
		testResetPassword2, "req-repeat-2")
	if err != nil {
		t.Fatalf("第二次重置失敗：%v", err)
	}
	if second.RevokedSessions != 1 {
		t.Errorf("第二次重置應撤掉新簽發的 1 份會話，實際 %d", second.RevokedSessions)
	}
	hash := resetStoredHash(t, e, created.AccountID)
	if mustVerify(t, hash, testInitialPassword) || mustVerify(t, hash, testResetPassword) {
		t.Error("最終現值必須是第二次重置的口令，先前所有口令一律失效")
	}
	if !mustVerify(t, hash, testResetPassword2) {
		t.Error("第二次交付的口令必須有效")
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); !errors.Is(err, session.ErrRevoked) {
		t.Errorf("第二次重置必須撤銷中間簽發的會話，實際 %v", err)
	}
	if got := countResetAudits(t, e); got != 2 {
		t.Errorf("兩次完整的重置必須各留一筆審計，實際 %d 筆", got)
	}
}

// TestResetRollsBackWhenAuditCannotBeWritten 審計寫不進，重置整筆回滾：
// 哈希、旗標、撤銷一件都不留——不留痕的憑據變更不該被當成成功。
func TestResetRollsBackWhenAuditCannotBeWritten(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "reset.rollback")
	secrets := newAccountSessions(t, e, created.AccountID, 1)
	beforeHash := resetStoredHash(t, e, created.AccountID)

	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("製造審計故障失敗：%v", err)
	}
	if _, err := e.service.ResetStandardAccountPassword(ctx, admin, created.AccountID,
		testResetPassword, "req-dropped"); err == nil {
		t.Fatal("審計表不可用時重置必須失敗")
	}
	if got := resetStoredHash(t, e, created.AccountID); got != beforeHash {
		t.Error("回滾後憑據雜湊必須原封不動（不留只換一半的憑據）")
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); err != nil {
		t.Errorf("回滾後不得留下半套撤銷（會話應仍可用），實際 %v", err)
	}
}

// TestResetCanceledContextWritesNothing 交易尚未開始就帶著已取消的 context：零寫入。
func TestResetCanceledContextWritesNothing(t *testing.T) {
	e := newEnv(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "reset.canceled")
	before := rowSnapshot(t, e, created.AccountID)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.service.ResetStandardAccountPassword(canceled, admin, created.AccountID,
		testResetPassword, "req-canceled"); err == nil {
		t.Fatal("已取消的 context 必須讓重置失敗")
	}
	if got := rowSnapshot(t, e, created.AccountID); got != before {
		t.Error("取消的請求不得留下任何欄位位移")
	}
}

// TestResetConcurrentAllAreWholeOperations 四路併發重置：沒有 CAS 就沒有「落敗者」，
// 每一路都要嘛完整落地（單寫入者串行化）、要嘛是明確的整體失敗（交易回滾、不留半套），
// 但絕不出現「報成功而一個字沒寫」。審計筆數與成功次數嚴格一致。
func TestResetConcurrentAllAreWholeOperations(t *testing.T) {
	e := newEnv(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "reset.race")

	const attempts = 4
	passwords := make([]string, attempts)
	for i := range passwords {
		passwords[i] = testResetPassword + string(rune('a'+i))
	}
	var wg sync.WaitGroup
	results := make([]error, attempts)
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			_, err := e.service.ResetStandardAccountPassword(context.Background(), admin,
				created.AccountID, passwords[i], "req-race")
			results[i] = err
		}(i)
	}
	wg.Wait()

	wins := 0
	for _, err := range results {
		if err == nil {
			wins++
		} else {
			t.Logf("併發重置出現失敗（須為整筆回滾）：%v", err)
		}
	}
	if wins == 0 {
		t.Fatal("四路併發重置不得全軍覆沒（那是缺陷，不是競爭）")
	}
	if got := countResetAudits(t, e); got != wins {
		t.Errorf("每一次成功必須恰好一筆審計（成功 %d，審計 %d）", wins, got)
	}
	hash := resetStoredHash(t, e, created.AccountID)
	latest := 0
	for i, p := range passwords {
		if mustVerify(t, hash, p) {
			latest = i + 1
		}
	}
	if latest == 0 {
		t.Error("最終現值必須是四次嘗試之一的口令")
	}
}
