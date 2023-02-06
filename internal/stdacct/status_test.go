// status_test.go 是「管理員停用與恢復普通帳戶登入」用例層的定向證據：
// 真資料庫＋注入時鐘＋真會話倉儲，斷言對象是三件事的合力——狀態 CAS、
// 同交易撤銷、審計落地——以及它們被拒時「一件都不發生」的形態。
//
// 這一檔特意把「多裝置一起失效」與「恢復之後的邊界」量到會話層：
// 停用不是目錄上的一個標籤，它必須讓那個人在每一臺裝置上的現有會話立刻換不出主體，
// 而恢復只把「新登入」這一件事放回來，其他一切限制原封不動。
//
// 刻意不收的東西：
//   - 沒有替身：授權、範圍核實、CAS、撤銷、審計都跨層走真路徑，接錯線就會紅；
//   - 不碰任何真實資料目錄、不佔 5206，全程用本次專屬的暫存庫與注入時鐘。
package stdacct

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// newAccountSessions 給一筆 active 帳戶簽發 n 份會話（模擬多臺裝置同時在線），
// 回傳全部會話秘密明文。
//
// 主體經 identitytest 構造（與本套件既有測試同路），會話倉儲現讀 accounts 判主體可用。
func newAccountSessions(t *testing.T, e *env, accountID idgen.ID, n int) []string {
	t.Helper()
	ctx := context.Background()
	secrets := make([]string, 0, n)
	for i := 0; i < n; i++ {
		principal := identitytest.Account(t, accountID)
		_, secret, err := e.sessions.Create(ctx, e.db.SQL(), principal)
		if err != nil {
			t.Fatalf("簽發測試會話 %d 失敗：%v", i+1, err)
		}
		secrets = append(secrets, secret)
	}
	return secrets
}

// countStatusAudits 數 Root 域裡的停用／恢復審計筆數（拒絕不寫審計的證據）。
func countStatusAudits(t *testing.T, e *env) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM root_audit WHERE action IN ('account.disable', 'account.enable')`).
		Scan(&n); err != nil {
		t.Fatalf("計數狀態審計失敗：%v", err)
	}
	return n
}

// rowSnapshot 取一筆帳戶的整行原始現值（衝突與被拒時要證明「一個字都沒落」）。
//
// 逐欄取而不是比對結構體：本檔要的證據包含 status_hash 這類本通路不該碰的欄位，
// 實體讀法會替我做形狀校驗，反而看不見「原值被改過」。
func rowSnapshot(t *testing.T, e *env, accountID idgen.ID) string {
	t.Helper()
	var (
		passwordHash *string
		status       string
		mustChange   int
		disabledAt   *int64
		deletedAt    *int64
		displayName  string
		lastLogin    *int64
		createdAt    int64
		loginName    string
		loginKey     string
		accountType  string
	)
	err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT password_hash, status, must_change_password, disabled_at, deleted_at,
		        display_name, last_login_at, created_at, login_name, login_name_key, account_type
		 FROM accounts WHERE id = ?`, accountID.String()).
		Scan(&passwordHash, &status, &mustChange, &disabledAt, &deletedAt, &displayName,
			&lastLogin, &createdAt, &loginName, &loginKey, &accountType)
	if err != nil {
		t.Fatalf("讀回整行現值失敗：%v", err)
	}
	return fmt.Sprintf("password_hash=%v|status=%s|must_change=%d|disabled_at=%v|deleted_at=%v|display_name=%s|last_login=%v|created_at=%d|login_name=%s|login_name_key=%s|account_type=%s",
		derefString(passwordHash), status, mustChange, derefInt(disabledAt), derefInt(deletedAt),
		displayName, derefInt(lastLogin), createdAt, loginName, loginKey, accountType)
}

func derefString(v *string) string {
	if v == nil {
		return "<NULL>"
	}
	return *v
}

func derefInt(v *int64) string {
	if v == nil {
		return "<NULL>"
	}
	return fmt.Sprintf("%d", *v)
}

// TestDisableStandardRevokesEveryDeviceAndAudits 停用的三件效果一起落地：
// 狀態與時刻、目標全部會話（多裝置）一起失效、審計帶前後值與撤銷數量。
func TestDisableStandardRevokesEveryDeviceAndAudits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	authService := e.newAuthService(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "device.one")
	secrets := newAccountSessions(t, e, created.AccountID, 3)

	result, err := e.service.UpdateStandardAccountStatus(ctx, admin, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-disable-1")
	if err != nil {
		t.Fatalf("停用失敗：%v", err)
	}
	if result.RevokedSessions != 3 {
		t.Errorf("停用應撤銷目標全部 3 份會話（跨裝置），實際 %d", result.RevokedSessions)
	}
	if result.Profile.Status != account.StatusDisabled || result.Profile.DisabledAt.IsZero() {
		t.Errorf("回應應是變更後的現值（disabled 帶時刻），實際 %+v", result.Profile)
	}
	if !result.Profile.DisabledAt.Equal(e.clock.Now()) {
		t.Errorf("停用時刻必須取自注入時鐘，實際 %v", result.Profile.DisabledAt)
	}
	for i, secret := range secrets {
		if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); !errors.Is(err, session.ErrRevoked) {
			t.Errorf("第 %d 份停用前會話應按已撤銷被拒，實際 %v", i+1, err)
		}
	}

	var status string
	var disabledAt int64
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT status, disabled_at FROM accounts WHERE id = ?", created.AccountID.String()).
		Scan(&status, &disabledAt); err != nil {
		t.Fatalf("讀回狀態失敗：%v", err)
	}
	if status != "disabled" || !timeutil.FromMillis(disabledAt).Equal(result.Profile.DisabledAt) {
		t.Errorf("落庫形態應為 disabled 帶時刻且與回應同源，實際 %s/%d", status, disabledAt)
	}

	// 停用之後的新登入被拒：收斂到「憑據無效」同形（既有合同），不另造一句「這個帳戶被鎖了」。
	// 這一條量的是「影響這個帳戶所有未來的登入」，而不是某一場活動裡的限制。
	if _, err := authService.LoginAccount(ctx, "device.one", testInitialPassword,
		"req-login-after-disable", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("停用後的登入應與口令錯誤同形被拒，實際 %v", err)
	}

	var action, targetID, actorKind, actorID, changes, reason string
	if err := e.db.SQL().QueryRowContext(ctx,
		`SELECT action, target_id, actor_kind, actor_id, changes_json, reason
		 FROM root_audit WHERE action = 'account.disable'`).
		Scan(&action, &targetID, &actorKind, &actorID, &changes, &reason); err != nil {
		t.Fatalf("讀回停用審計失敗：%v", err)
	}
	if targetID != created.AccountID.String() || actorKind != string(audit.ActorAdmin) {
		t.Errorf("審計應指向被停用的帳戶且操作者為 admin，實際 %s／%s", targetID, actorKind)
	}
	if actorID != admin.AccountID().String() {
		t.Errorf("審計操作者應是那位管理員本人的標識，實際 %s", actorID)
	}
	for _, want := range []string{`"active"`, `"disabled"`, "revoked_sessions", "disabled_at"} {
		if !strings.Contains(changes, want) {
			t.Errorf("審計前後摘要應帶 %s，實際 %s", want, changes)
		}
	}
	if strings.Contains(changes, testInitialPassword) || strings.Contains(changes, "$argon2id$") ||
		strings.Contains(changes, "password") {
		t.Error("停用審計不得含口令、雜湊或任何憑據欄位的影子")
	}
	for _, secret := range secrets {
		if strings.Contains(changes, secret) || strings.Contains(reason, secret) {
			t.Error("停用審計不得帶出任何會話秘密")
		}
	}
}

// TestEnableStandardRestoresLoginQualificationOnly 恢復只恢復新登入資格：
// 舊會話不復活、首次改密義務不解除、撤銷數量恆為 0，而新會話簽得出來。
func TestEnableStandardRestoresLoginQualificationOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	authService := e.newAuthService(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "restore.one")
	before := newAccountSessions(t, e, created.AccountID, 2)

	if _, err := e.service.UpdateStandardAccountStatus(ctx, admin, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-restore-disable"); err != nil {
		t.Fatalf("停用失敗：%v", err)
	}
	result, err := e.service.UpdateStandardAccountStatus(ctx, admin, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusActive, ExpectedStatus: account.StatusDisabled},
		"req-restore-enable")
	if err != nil {
		t.Fatalf("恢復失敗：%v", err)
	}
	if result.RevokedSessions != 0 {
		t.Errorf("恢復不應撤銷任何會話，實際 %d", result.RevokedSessions)
	}
	if result.Profile.Status != account.StatusActive || !result.Profile.DisabledAt.IsZero() {
		t.Errorf("恢復後應是 active 且停用時刻清回 NULL，實際 %+v", result.Profile)
	}
	// 首次改密義務不解除：建號帶的旗標在停用與恢復之後仍是真。
	if !result.Profile.MustChangePassword {
		t.Error("恢復不得清除首次改密義務（must_change_password 不在此通路之內）")
	}
	for i, secret := range before {
		if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); !errors.Is(err, session.ErrRevoked) {
			t.Errorf("第 %d 份停用前會話在恢復後仍應是已撤銷，實際 %v", i+1, err)
		}
	}
	after, _, err := e.sessions.Create(ctx, e.db.SQL(), identitytest.Account(t, created.AccountID))
	if err != nil {
		t.Fatalf("恢復後應能簽發新會話：%v", err)
	}
	if after.ID.IsNil() {
		t.Error("恢復後簽發的新會話應有標識（測試前提）")
	}
	// 恢復的是「新登入資格」：同一個人現在登得進來，而且仍然欠那一次改密。
	outcome, err := authService.LoginAccount(ctx, "restore.one", testInitialPassword,
		"req-login-after-restore", "127.0.0.1")
	if err != nil {
		t.Fatalf("恢復後應能以初始口令重新登入：%v", err)
	}
	if !outcome.MustChangePassword {
		t.Error("恢復不得解除首次改密義務（登入回應仍要回報欠改密）")
	}

	// 已完成的操作不倒退：停用之前本人的寫入（這裡以顯示名代表）在恢復後仍是事實。
	if _, err := e.service.accounts.UpdateDisplayName(ctx, e.db.SQL(), created.AccountID,
		"改名在我停用之前", created.DisplayName); err != nil {
		t.Fatalf("停用前改顯示名失敗：%v", err)
	}
	profile, err := e.service.StandardAccountProfile(ctx, admin, created.AccountID)
	if err != nil || profile.DisplayName != "改名在我停用之前" {
		t.Errorf("恢復不得逆轉停用前已提交的寫入，實際 %+v／%v", profile, err)
	}
}

// TestDisableStacksWithOtherLimits 多重限制不是一個布林：停用只動 status 那一欄，
// 首次改密旗標、來源類型與刪除時刻一律原封不動（以整行快照作證）。
func TestDisableStacksWithOtherLimits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "overlay.one")
	before := rowSnapshot(t, e, created.AccountID)

	if _, err := e.service.UpdateStandardAccountStatus(ctx, admin, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-overlay"); err != nil {
		t.Fatalf("停用失敗：%v", err)
	}
	after := rowSnapshot(t, e, created.AccountID)
	if diff := snapshotDiff(before, after); diff != "status,disabled_at" {
		t.Errorf("停用只該動 status 與 disabled_at，實際差異欄位：%s\n變更前 %s\n變更後 %s",
			diff, before, after)
	}
	profile, err := e.service.StandardAccountProfile(ctx, admin, created.AccountID)
	if err != nil {
		t.Fatalf("停用後的詳情讀取失敗：%v", err)
	}
	if !profile.MustChangePassword || profile.Type != account.TypeStandard {
		t.Errorf("停用不改旗標與類型，實際 %+v", profile)
	}
}

// TestDisableGuestWritesStatusWithoutSessions 訪客帳戶走同一條通路：狀態落庫如實，
// 而今日他沒有可登入的憑據通路，因此撤銷數量為 0（0 是事實，不是失敗）。
func TestDisableGuestWritesStatusWithoutSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := e.seed(t, seedInput{Login: "overlay.guest", Display: "訪戶帳戶",
		Type: account.TypeGuest})

	result, err := e.service.UpdateStandardAccountStatus(ctx, admin, guest.ID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-guest-disable")
	if err != nil {
		t.Fatalf("停用訪客失敗：%v", err)
	}
	if result.Profile.Type != account.TypeGuest || result.Profile.Status != account.StatusDisabled {
		t.Errorf("訪客的來源與狀態都該如實回報，實際 %+v", result.Profile)
	}
	if result.RevokedSessions != 0 {
		t.Errorf("無憑據的訪客沒有會話可撤，撤銷數量應為 0，實際 %d", result.RevokedSessions)
	}
	if result.Profile.MustChangePassword {
		t.Error("訪客的改密旗標恆為假（遷移 0003 的形態凍結），本斷言在測的是夹具而非通路")
	}
}

// TestStatusChangeRejectsNonAdminSubjects 授權矩陣：普通帳戶、訪客帳戶、系統主體與
// 匿名主體對停用與恢復都回權限錯誤，且零寫入、零撤銷、零審計。
//
// 這是「管理員才能關別人的登入」在服務層的釘子：普通帳戶彼此動不了，
// 界面上那顆按鈕藏不藏都不是判定點。
func TestStatusChangeRejectsNonAdminSubjects(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	target := e.mustCreate(t,
		identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin()), "guard.target")
	secrets := newAccountSessions(t, e, target.AccountID, 2)
	before := rowSnapshot(t, e, target.AccountID)
	audits := countStatusAudits(t, e)

	for name, principal := range map[string]identity.Principal{
		"普通帳戶": identitytest.Account(t, identitytest.NewID(t)),
		"訪客帳戶": identitytest.Account(t, identitytest.NewID(t), identitytest.WithGuestType()),
		"系統主體": identitytest.System(t, identity.OriginCLI),
	} {
		_, err := e.service.UpdateStandardAccountStatus(ctx, principal, target.AccountID,
			StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
			"req-guard-"+name)
		if !errors.Is(err, identity.ErrPermissionDenied) {
			t.Errorf("%s 停用他人應回權限錯誤，實際 %v", name, err)
		}
	}
	// 匿名主體是另一句話：它不是「身分可信但沒這個權限」，而是「連自己是誰都還沒證明」。
	// 兩句在傳輸層各自對映 2011 與 2002，混在一起就等於讓未登入的探測讀到「權限不足」。
	if _, err := e.service.UpdateStandardAccountStatus(ctx, identitytest.Anonymous(t),
		target.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-guard-anonymous"); !errors.Is(err, identity.ErrNotAuthenticated) {
		t.Errorf("匿名主體應回未認證而不是權限錯誤，實際 %v", err)
	}
	if got := rowSnapshot(t, e, target.AccountID); got != before {
		t.Errorf("被拒的停用一個字都不該落庫，變更前 %s／實際 %s", before, got)
	}
	for i, secret := range secrets {
		if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); err != nil {
			t.Errorf("被拒的停用不該撤銷任何會話，第 %d 份實際 %v", i+1, err)
		}
	}
	if got := countStatusAudits(t, e); got != audits {
		t.Errorf("被拒的請求不該寫審計（寫入放大器），應 %d 實際 %d", audits, got)
	}
}

// TestStatusChangeTargetScope 目標範圍：另一位管理員、操作者自己、刪除終態、
// 幽靈標識與零值標識一律同一句話（ErrAccountNotFound），且零寫入零審計。
//
// 這一條量的是本步那句邊界：普通管理員不能拿這條通路動管理員，也不能動 Root。
// Root 不在 accounts 表裡，以他的保留標識打進來與幽靈同形；而另一位管理員與操作者自己
// 都持有授予，三道範圍檢查的第二道就把他們請出去——跟詳情與編輯那條通路一模一樣的答案。
func TestStatusChangeTargetScope(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// 操作者本人也要在 accounts 表裡有一行：否則「自己對自己下停用令」這一格測的是
	// 幽靈標識，而不是範圍檢查的第二道（他持有授予）。
	self := e.seed(t, seedInput{Login: "scope.self", Display: "我自己"})
	if err := e.service.grants.Grant(ctx, e.db.SQL(), self.ID, identity.RoleServerAdmin); err != nil {
		t.Fatalf("補上操作者授予失敗：%v", err)
	}
	admin := identitytest.Account(t, self.ID, identitytest.ServerAdmin())

	peer := e.seed(t, seedInput{Login: "scope.peer", Display: "另一位管理員", Admin: true})
	deleted := e.seed(t, seedInput{Login: "scope.gone", Display: "已刪除的", Deleted: true})
	cases := []struct {
		name string
		id   idgen.ID
	}{
		{"另一位管理員", peer.ID},
		{"操作者自己", self.ID},
		{"刪除終態", deleted.ID},
		{"幽靈標識", identitytest.NewID(t)},
		{"零值標識", idgen.ID{}},
	}
	audits := countStatusAudits(t, e)
	for _, tc := range cases {
		_, err := e.service.UpdateStandardAccountStatus(ctx, admin, tc.id,
			StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
			"req-scope-"+tc.name)
		if !errors.Is(err, ErrAccountNotFound) {
			t.Errorf("%s 應回不在目錄的同形結論，實際 %v", tc.name, err)
		}
	}
	// peer 與 deleted 兩筆的整行現值仍該是種入時的形態。
	if got := rowSnapshot(t, e, peer.ID); !strings.Contains(got, "|status=active|") {
		t.Errorf("對另一位管理員的停用不該發生，peer 現值 %s", got)
	}
	if got := countStatusAudits(t, e); got != audits {
		t.Errorf("範圍外的目標不該留下狀態審計，應 %d 實際 %d", audits, got)
	}
	if n := countRows(t, e.db, "sessions"); n != 0 {
		t.Errorf("本測試沒簽發過會話，實際 sessions 有 %d 行", n)
	}
}

// TestStatusChangeRejectsNonChanges 輸入面：同值與表外值（含 deleted、enabled、空白）
// 都在交易外被拒，資料庫一次都沒被問到。
func TestStatusChangeRejectsNonChanges(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "input.one")
	secrets := newAccountSessions(t, e, created.AccountID, 1)
	before := rowSnapshot(t, e, created.AccountID)

	bad := []StatusChangeInput{
		{NewStatus: account.StatusActive, ExpectedStatus: account.StatusActive},
		{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusDisabled},
		{NewStatus: account.StatusDeleted, ExpectedStatus: account.StatusActive},
		{NewStatus: account.StatusActive, ExpectedStatus: account.StatusDeleted},
		{NewStatus: "enabled", ExpectedStatus: account.StatusActive},
		{NewStatus: "", ExpectedStatus: account.StatusActive},
		{NewStatus: account.StatusDisabled, ExpectedStatus: ""},
	}
	for i, in := range bad {
		_, err := e.service.UpdateStandardAccountStatus(ctx, admin, created.AccountID, in,
			fmt.Sprintf("req-input-%d", i))
		if !errors.Is(err, ErrInvalidStatusChange) {
			t.Errorf("第 %d 組非法狀態對應回輸入錯誤，實際 %v", i+1, err)
		}
	}
	if got := rowSnapshot(t, e, created.AccountID); got != before {
		t.Errorf("非法輸入不該落任何一欄，變更前 %s／實際 %s", before, got)
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); err != nil {
		t.Errorf("非法輸入不該撤銷會話，實際 %v", err)
	}
	if got := countStatusAudits(t, e); got != 0 {
		t.Errorf("非法輸入不該寫審計，實際 %d", got)
	}
}

// TestStatusChangeConflictAndRepeat 併發與重複：陳舊依據值回 ErrStatusConflict 且
// 整行與會話都不動；六路同依據並發恰好一次生效、審計只多一筆。
func TestStatusChangeConflictAndRepeat(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "cas.one")
	secrets := newAccountSessions(t, e, created.AccountID, 2)

	// 先把人停掉（依據值正確），隨後拿同一份舊依據再停用一次：那是「你看見的現狀已過期」。
	if _, err := e.service.UpdateStandardAccountStatus(ctx, admin, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-cas-first"); err != nil {
		t.Fatalf("首次停用失敗：%v", err)
	}
	disabledSince := rowSnapshot(t, e, created.AccountID)
	audits := countStatusAudits(t, e)
	_, err := e.service.UpdateStandardAccountStatus(ctx, admin, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-cas-stale")
	if !errors.Is(err, ErrStatusConflict) {
		t.Fatalf("陳舊依據應回狀態衝突，實際 %v", err)
	}
	if got := rowSnapshot(t, e, created.AccountID); got != disabledSince {
		t.Errorf("衝突的停用不該重蓋 disabled_at（那會造出一個從沒發生過的停用時刻），實際 %s", got)
	}
	for i, secret := range secrets {
		if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); !errors.Is(err, session.ErrRevoked) {
			t.Errorf("第 %d 份會話在衝突請求後仍應是首次停用撤掉的那個狀態，實際 %v", i+1, err)
		}
	}
	if got := countStatusAudits(t, e); got != audits {
		t.Errorf("衝突的停用不該再添審計，應 %d 實際 %d", audits, got)
	}

	// 併發：同一份依據值六路同發，贏家一個。
	fresh := e.mustCreate(t, admin, "cas.two")
	newAccountSessions(t, e, fresh.AccountID, 1)
	var wg sync.WaitGroup
	results := make([]error, 6)
	start := make(chan struct{})
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, results[i] = e.service.UpdateStandardAccountStatus(ctx, admin, fresh.AccountID,
				StatusChangeInput{NewStatus: account.StatusDisabled,
					ExpectedStatus: account.StatusActive},
				fmt.Sprintf("req-cas-concurrent-%d", i))
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	for i, err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrStatusConflict):
			// 輸家：前提已失效，這是預期結論。
		default:
			t.Errorf("第 %d 路回了預期外的錯誤：%v", i+1, err)
		}
	}
	if wins != 1 {
		t.Errorf("六路併發同依據應恰好一次生效，實際 %d 次", wins)
	}
	var disabled int
	if err := e.db.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM root_audit WHERE action = 'account.disable'`).Scan(&disabled); err != nil {
		t.Fatalf("計數停用審計失敗：%v", err)
	}
	if disabled != 2 {
		t.Errorf("停用審計應與成功變更同數（首發 1 ＋併發 1＝2），實際 %d", disabled)
	}
}

// TestStatusChangeRollsBackAtomically 交易完整性：審計表不可寫時整個停用回滾——
// 狀態沒改、會話也沒被半套撤銷。
func TestStatusChangeRollsBackAtomically(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "rollback.one")
	secrets := newAccountSessions(t, e, created.AccountID, 2)
	before := rowSnapshot(t, e, created.AccountID)

	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("製造審計故障失敗：%v", err)
	}
	if _, err := e.service.UpdateStandardAccountStatus(ctx, admin, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-rollback"); err == nil {
		t.Fatal("審計寫不入時停用必須失敗")
	}
	if got := rowSnapshot(t, e, created.AccountID); got != before {
		t.Errorf("失敗的停用該整筆回滾，變更前 %s／實際 %s", before, got)
	}
	for i, secret := range secrets {
		if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); err != nil {
			t.Errorf("第 %d 份會話不該被半套撤銷（交易回滾），實際 %v", i+1, err)
		}
	}
}

// TestStatusChangeContextCancelled 已取消的 context 在第一個查詢就失敗：零寫入。
func TestStatusChangeContextCancelled(t *testing.T) {
	e := newEnv(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	created := e.mustCreate(t, admin, "cancel.one")
	before := rowSnapshot(t, e, created.AccountID)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.service.UpdateStandardAccountStatus(ctx, admin, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-cancel"); err == nil {
		t.Fatal("已取消的交易必須失敗")
	}
	if got := rowSnapshot(t, e, created.AccountID); got != before {
		t.Errorf("取消的請求該零寫入，變更前 %s／實際 %s", before, got)
	}
}

// snapshotDiff 回傳兩份整行快照裡數值不同的欄位名（逗號分隔，順序與快照一致）。
//
// 存在理由是把「只動那兩欄」變成可讀的斷言：直接比字串會讓人得自己一行行對，
// 而本檔多數測試要的恰恰是「其他欄位一位都沒變」這句具體的話。
func snapshotDiff(before, after string) string {
	beforeParts := strings.Split(before, "|")
	afterParts := strings.Split(after, "|")
	if len(beforeParts) != len(afterParts) {
		return "<欄位數不同>"
	}
	changed := make([]string, 0, 2)
	for i := range beforeParts {
		if beforeParts[i] != afterParts[i] {
			key, _, _ := strings.Cut(beforeParts[i], "=")
			changed = append(changed, key)
		}
	}
	return strings.Join(changed, ",")
}
