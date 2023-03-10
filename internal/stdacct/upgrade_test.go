// upgrade_test.go 是「管理員把訪戶原地升級成普通帳戶」用例層的定向證據：
// 真資料庫＋注入時鐘＋真會話倉儲，斷言對象是四件事的合力——身分轉正、憑據落地、
// 舊會話撤銷、審計追加——以及它們被拒時「一件都不發生」的形態。
//
// 這一檔把本步要求驗的七件事釘死：
//   - 升級保留原帳戶的穩定標識（ID 逐字不变）与既存引用（審計指向同一標識、
//     舊審計一個字不動）；
//   - 重名失敗不改變訪戶一個字（整筆回滾）；
//   - 重複升級（對已轉正者）被拒且零寫入；
//   - 停用／刪除目標被拒（停用回形態結論、刪除走目錄範圍）；
//   - 舊會話同交易失效（拾獲舊秘密的人登不進，本人須以新憑據重登並先改密）；
//   - 訪戶本人敲這條通路拿到的就是既有授權矩陣的 2011（不能自我提升）；
//   - 升級出來的形態恆為普通帳戶：授予表零行，請求沒有任何格子能宣稱別的類型。
//
// 刻意不收的東西：
//   - 沒有替身：授權、範圍核實、形態判定、撤銷、審計都跨層走真路徑，接錯線就會紅；
//   - 不碰任何真實資料目錄、不佔 5206，全程用本次專屬的暫存庫與注入時鐘。
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
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// 升級測試口令：只活在本次測試進程的記憶體，不是任何環境的憑據。
const (
	testUpgradePassword = "upgrade-test-一次性升級口令"
	testUpgradeLogin    = "Real.Player.One"
)

// seedGuest 種一筆可登入的訪戶帳戶（無憑據、無旗標，由 store 直寫——
// 建立用例只產得出 standard，訪客形態就得由倉儲層種出來，與 seed 同一取向）。
func seedGuest(t *testing.T, e *env, login, display string) account.Account {
	t.Helper()
	a, err := e.service.accounts.Create(context.Background(), e.db.SQL(), account.NewInput{
		LoginName:   login,
		DisplayName: display,
		Type:        account.TypeGuest,
		Status:      account.StatusActive,
	})
	if err != nil {
		t.Fatalf("種入訪戶帳戶失敗：%v", err)
	}
	return a
}

// seedGuestSessions 給一筆訪戶帳戶簽發 n 份會話（多臺裝置同時在線的現場），
// 回傳全部會話秘密明文。主體以零授予＋訪客類型構造，與 guestacct 的生產形態同源。
func seedGuestSessions(t *testing.T, e *env, accountID idgen.ID, n int) []string {
	t.Helper()
	ctx := context.Background()
	secrets := make([]string, 0, n)
	for i := 0; i < n; i++ {
		principal := identitytest.Account(t, accountID, identitytest.WithGuestType())
		_, secret, err := e.sessions.Create(ctx, e.db.SQL(), principal)
		if err != nil {
			t.Fatalf("簽發訪戶測試會話 %d 失敗：%v", i+1, err)
		}
		secrets = append(secrets, secret)
	}
	return secrets
}

// countUpgradeAudits 數 Root 域裡的升級審計筆數（拒絕不寫審計的證據）。
func countUpgradeAudits(t *testing.T, e *env) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM root_audit WHERE action = 'account.guest_upgrade'`).
		Scan(&n); err != nil {
		t.Fatalf("計數升級審計失敗：%v", err)
	}
	return n
}

// mustUpgrade 發一次升級並在失敗時終止測試。
func mustUpgrade(t *testing.T, e *env, admin identity.Principal, accountID idgen.ID,
	login string) GuestUpgrade {
	t.Helper()
	upgraded, err := e.service.UpgradeGuestToStandard(context.Background(), admin, accountID,
		UpgradeInput{LoginName: login, InitialPassword: testUpgradePassword}, "req-upgrade")
	if err != nil {
		t.Fatalf("升級訪戶 %s 失敗：%v", login, err)
	}
	return upgraded
}

// TestUpgradeKeepsIdentityAndWritesCredentialAndAudit 成功形態：同一枚穩定標識、
// 同一個顯示名、同一個建立時刻，變的是分類、登入名與憑據三件事——而且三件事
// 加審計一起落地，「失敗不留下無口令的半升級身份」由此有正面證據。
func TestUpgradeKeepsIdentityAndWritesCredentialAndAudit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := seedGuest(t, e, "guest_seed_login", "旅人小明")
	createdAtBefore := guest.CreatedAt

	upgraded := mustUpgrade(t, e, admin, guest.ID, testUpgradeLogin)

	if upgraded.Profile.AccountID != guest.ID {
		t.Errorf("升級必須保留穩定標識：%s 對 %s", guest.ID, upgraded.Profile.AccountID)
	}
	if upgraded.Profile.DisplayName != "旅人小明" {
		t.Errorf("升級不是改名，顯示名必須原樣保留，實際 %q", upgraded.Profile.DisplayName)
	}
	if !upgraded.Profile.CreatedAt.Equal(createdAtBefore) {
		t.Errorf("建立時刻屬歷史事實，不得被升級改寫：%v 對 %v", createdAtBefore, upgraded.Profile.CreatedAt)
	}
	if upgraded.Profile.Type != account.TypeStandard || upgraded.Profile.Status != account.StatusActive {
		t.Errorf("升級結果應為 standard/active，實際 %s/%s",
			upgraded.Profile.Type, upgraded.Profile.Status)
	}
	if !upgraded.Profile.MustChangePassword {
		t.Error("升級交付的是一次性口令：must_change_password 必須為 1")
	}
	if upgraded.RevokedSessions != 0 {
		t.Errorf("未簽發會話的目標撤銷數應為 0（事實不是失敗），實際 %d", upgraded.RevokedSessions)
	}

	var (
		loginName, loginKey, accountType, hash string
		mustChange                             int
	)
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT login_name, login_name_key,
		account_type, password_hash, must_change_password FROM accounts WHERE id = ?`,
		guest.ID.String()).
		Scan(&loginName, &loginKey, &accountType, &hash, &mustChange); err != nil {
		t.Fatalf("讀回升級後帳戶失敗：%v", err)
	}
	if loginName != testUpgradeLogin {
		t.Errorf("登入名應保留原始寫法，實際 %q", loginName)
	}
	if loginKey != strings.ToLower(testUpgradeLogin) {
		t.Errorf("唯一鍵應為正規化結果，實際 %q", loginKey)
	}
	if accountType != "standard" || mustChange != 1 {
		t.Errorf("落庫形態應為 standard＋欠首改，實際 %s/%d", accountType, mustChange)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Error("憑據必須為 Argon2id 編碼")
	}
	// 升級出來的仍是「只能登入、不能管理」的人：授予表零行。
	if n := countRows(t, e.db, "account_server_roles"); n != 0 {
		t.Errorf("升級不得給出任何伺服器級授予，實際 %d 行", n)
	}

	// 審計：actor=admin、指向同一枚穩定標識、前後值齊備、不含任何口令材料。
	var (
		targetID, actorKind, actorID, changes, reason string
	)
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT target_id, actor_kind, actor_id,
		changes_json, reason FROM root_audit WHERE action = 'account.guest_upgrade'`).
		Scan(&targetID, &actorKind, &actorID, &changes, &reason); err != nil {
		t.Fatalf("讀回升級審計失敗：%v", err)
	}
	if targetID != guest.ID.String() {
		t.Errorf("審計目標應是同一枚穩定標識，實際 %q", targetID)
	}
	if actorKind != string(audit.ActorAdmin) || actorID != admin.AccountID().String() {
		t.Errorf("升級審計應記真實操作者，實際 %s／%s", actorKind, actorID)
	}
	for _, want := range []string{"guest_seed_login", testUpgradeLogin, "guest", "standard"} {
		if !strings.Contains(changes, want) {
			t.Errorf("審計前後值應含 %q，實際 %s", want, changes)
		}
	}
	rowText := targetID + actorKind + actorID + changes + reason + loginKey
	if strings.Contains(rowText, testUpgradePassword) || strings.Contains(rowText, hash) {
		t.Error("審計與鍵值彙總不得含口令明文或憑據雜湊")
	}
	if logs := e.logs.String(); strings.Contains(logs, testUpgradePassword) ||
		strings.Contains(logs, hash) {
		t.Error("執行日誌不得含口令明文或憑據雜湊")
	}
}

// TestUpgradeAppendsAuditWithoutTouchingHistory 升級是追加一筆新事實，不是改寫舊事實：
// 先種一筆 account.guest_enter 審計（與 guestacct 生產形態同形），升級後逐字比對它。
func TestUpgradeAppendsAuditWithoutTouchingHistory(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := seedGuest(t, e, "guest_history_probe", "歷史旅人")

	if _, err := e.service.audits.Append(ctx, e.db.SQL(), audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  audit.Actor{Kind: audit.ActorSystem},
		Action: "account.guest_enter",
		Target: audit.Target{Kind: "account", ID: guest.ID.String()},
		Reason: "測試種入的出生事件（訪客進入的歷史事實）",
		Changes: []audit.Change{
			{Field: "login_name", Before: nil, After: guest.LoginName},
			{Field: "account_type", Before: nil, After: "guest"},
		},
	}); err != nil {
		t.Fatalf("種入出生審計失敗：%v", err)
	}
	var beforeText string
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT action || '|' || changes_json || '|' ||
		reason || '|' || COALESCE(request_id,'') FROM root_audit WHERE action = 'account.guest_enter'`).
		Scan(&beforeText); err != nil {
		t.Fatalf("讀回出生審計失敗：%v", err)
	}

	mustUpgrade(t, e, admin, guest.ID, testUpgradeLogin)

	var afterText string
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT action || '|' || changes_json || '|' ||
		reason || '|' || COALESCE(request_id,'') FROM root_audit WHERE action = 'account.guest_enter'`).
		Scan(&afterText); err != nil {
		t.Fatalf("升級後讀回出生審計失敗：%v", err)
	}
	if afterText != beforeText {
		t.Errorf("歷史審計必須逐字不動（描述發生時的訪戶身份），變更前 %q／實際 %q", beforeText, afterText)
	}
	if n := countUpgradeAudits(t, e); n != 1 {
		t.Errorf("升級應恰好追加一筆新審計，實際 %d", n)
	}
}

// TestUpgradeDuplicateLoginLeavesGuestUntouched 正式登入名已被佔用（含正規化變體）：
// 整筆不發生——訪戶一欄不改、會話一輪不撤、審計一筆不記，結論可判別。
func TestUpgradeDuplicateLoginLeavesGuestUntouched(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	e.mustCreate(t, admin, "Taken.Name")
	guest := seedGuest(t, e, "guest_dup_probe", "撞名旅人")
	secrets := seedGuestSessions(t, e, guest.ID, 2)
	before := rowSnapshot(t, e, guest.ID)

	for _, variant := range []string{"taken.name", "TAKEN.NAME", "Ｔａｋｅｎ.Ｎａｍｅ"} {
		_, err := e.service.UpgradeGuestToStandard(ctx, admin, guest.ID,
			UpgradeInput{LoginName: variant, InitialPassword: testUpgradePassword}, "req-dup")
		if !errors.Is(err, ErrDuplicateLogin) {
			t.Errorf("%q 應被判為登入名已佔用，實際 %v", variant, err)
		}
		if strings.Contains(err.Error(), testUpgradePassword) {
			t.Errorf("衝突錯誤不得回顯口令：%v", err)
		}
	}
	if got := rowSnapshot(t, e, guest.ID); got != before {
		t.Errorf("重名失敗的訪戶一個字都不該變，變更前 %s／實際 %s", before, got)
	}
	for _, secret := range secrets {
		if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); err != nil {
			t.Errorf("被拒的升級不得撤銷任何會話，Verify 實際回 %v", err)
		}
	}
	if n := countUpgradeAudits(t, e); n != 0 {
		t.Errorf("被拒的升級不得追加審計，實際 %d 筆", n)
	}
}

// TestUpgradeAlreadyStandardIsRefused 重複升級（對已轉正者）：獨立可判別的形態結論，
// 目標一個字不動、審計不記——「再按一次那顆按鈕」不會又完成一次升級。
func TestUpgradeAlreadyStandardIsRefused(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := seedGuest(t, e, "guest_twice", "升兩次的人")
	mustUpgrade(t, e, admin, guest.ID, testUpgradeLogin)
	afterFirst := rowSnapshot(t, e, guest.ID)
	if n := countUpgradeAudits(t, e); n != 1 {
		t.Fatalf("第一次升級應恰好一筆審計，實際 %d", n)
	}

	_, err := e.service.UpgradeGuestToStandard(ctx, admin, guest.ID,
		UpgradeInput{LoginName: "Second.Real.Name", InitialPassword: testUpgradePassword}, "req-twice")
	if !errors.Is(err, ErrNotUpgradeableGuest) {
		t.Errorf("對已轉正者重複升級應回形態結論，實際 %v", err)
	}
	if got := rowSnapshot(t, e, guest.ID); got != afterFirst {
		t.Errorf("重複升級一個字都不該落庫，第一次後 %s／實際 %s", afterFirst, got)
	}
	if n := countUpgradeAudits(t, e); n != 1 {
		t.Errorf("被拒的重複升級不得追加審計，實際 %d 筆", n)
	}
}

// TestUpgradeDisabledGuestRefused 停用中的訪戶不可升級：處置是先恢復登入能力，
// 不是讓「升級」順帶完成一次復活（UPDATE 連 status 的格子都不碰）。
func TestUpgradeDisabledGuestRefused(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := e.seed(t, seedInput{Login: "guest_offline", Display: "停用旅人",
		Type: account.TypeGuest, Status: account.StatusDisabled})
	before := rowSnapshot(t, e, guest.ID)

	if _, err := e.service.UpgradeGuestToStandard(ctx, admin, guest.ID,
		UpgradeInput{LoginName: testUpgradeLogin, InitialPassword: testUpgradePassword},
		"req-disabled"); !errors.Is(err, ErrNotUpgradeableGuest) {
		t.Errorf("停用中的訪戶應回形態結論（2024 的那一句），實際 %v", err)
	}
	if got := rowSnapshot(t, e, guest.ID); got != before {
		t.Errorf("被拒的升級一個字都不該落庫（尤其不得順帶復活），變更前 %s／實際 %s", before, got)
	}
	if n := countUpgradeAudits(t, e); n != 0 {
		t.Errorf("被拒的升級不得追加審計，實際 %d 筆", n)
	}
}

// TestUpgradeTargetScopeConvergesToNotFound 持有授予者與幽靈標識走目錄同一句
// ErrAccountNotFound：升級通路不在本目錄範圍的問題上不多發信號。
//
// 兩種終態各自成句（已刪 2027、已退休 2028），不再是查無同形：用戶批准的展示策略把
// 他們留在這本目錄裡，而「換個目標」對一個就在名冊上的人是誤導；退休行每一欄都被
// 庫釘住，少了這一句，直打這條通路的人換到的是一個撞觸發器的 500。
func TestUpgradeTargetScopeConvergesToNotFound(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())

	deleted := e.seed(t, seedInput{Login: "guest_gone", Display: "已刪旅人",
		Type: account.TypeGuest, Deleted: true})
	retired := e.seed(t, seedInput{Login: "guest_retired_scope", Display: "已被綁走的旅人",
		Type: account.TypeGuest, Retired: true})
	ghostID, err := idgen.New()
	if err != nil {
		t.Fatalf("產生幽靈標識失敗：%v", err)
	}
	cases := map[string]idgen.ID{
		"幽靈標識": ghostID,
		"零值標識": idgen.ID{},
	}
	for name, target := range cases {
		if _, err := e.service.UpgradeGuestToStandard(ctx, admin, target,
			UpgradeInput{LoginName: testUpgradeLogin, InitialPassword: testUpgradePassword},
			"req-scope"); !errors.Is(err, ErrAccountNotFound) {
			t.Errorf("%s 應收斂為查無同形，實際 %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		id  idgen.ID
		err error
	}{
		"刪除終態": {deleted.ID, ErrAccountDeleted},
		"退休終態": {retired.ID, ErrAccountRetired},
	} {
		if _, err := e.service.UpgradeGuestToStandard(ctx, admin, tc.id,
			UpgradeInput{LoginName: testUpgradeLogin, InitialPassword: testUpgradePassword},
			"req-scope-"+name); !errors.Is(err, tc.err) {
			t.Errorf("%s 應回自己那句終態的拒絕，期望 %v，實際 %v", name, tc.err, err)
		}
	}
	if n := countUpgradeAudits(t, e); n != 0 {
		t.Errorf("範圍出局不得追加審計，實際 %d 筆", n)
	}
}

// TestUpgradeRevokesOldSessionsAndFirstSignInCloses 本步批准的决定落地：
// 升級同交易撤銷舊全部會話——撿到舊秘密的人什麼也換不到；
// 本人要回到門內只能用新憑據重登，而且首次登入必須先改密。
func TestUpgradeRevokesOldSessionsAndFirstSignInCloses(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := seedGuest(t, e, "guest_session_probe", "兩臺裝置的旅人")
	secrets := seedGuestSessions(t, e, guest.ID, 2)

	upgraded := mustUpgrade(t, e, admin, guest.ID, testUpgradeLogin)
	if upgraded.RevokedSessions != 2 {
		t.Errorf("升級應撤銷目標全部會話，實際 revoked=%d", upgraded.RevokedSessions)
	}
	for _, secret := range secrets {
		if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); !errors.Is(err, session.ErrRevoked) {
			t.Errorf("舊臨時會話必須落庫為已撤銷（不是推導失效），實際 %v", err)
		}
	}

	// 閉環：新憑據走既有登入通路，帶首改義務；改密後舊一次性口令徹底失效。
	authService := e.newAuthService(t)
	outcome, err := authService.LoginAccount(ctx, strings.ToUpper(testUpgradeLogin),
		testUpgradePassword, "req-up-login", "127.0.0.1")
	if err != nil {
		t.Fatalf("升級後應能以新憑據登入：%v", err)
	}
	if outcome.Principal.AccountID() != guest.ID {
		t.Errorf("登入換回的主體應就是同一枚穩定標識：%s 對 %s",
			outcome.Principal.AccountID(), guest.ID)
	}
	if !outcome.MustChangePassword {
		t.Error("升級後首次登入應回報「還欠一次改密」")
	}
	if len(outcome.Principal.Roles()) != 0 {
		t.Errorf("升級不得憑空多出角色，實際 %v", outcome.Principal.Roles())
	}
	if _, err := authService.ChangePassword(ctx, outcome.Principal, testUpgradePassword,
		"改後的新口令", "req-up-change"); err != nil {
		t.Fatalf("以一次性口令完成首次改密失敗：%v", err)
	}
	if _, err := authService.LoginAccount(ctx, testUpgradeLogin, testUpgradePassword,
		"req-up-stale", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("改密後舊的一次性口令必須徹底失效，實際 %v", err)
	}
	if _, err := authService.LoginAccount(ctx, "guest_session_probe", testUpgradePassword,
		"req-old-guest-name", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("伺服器產生的舊訪戶登入名不再是任何人的入口，實際 %v", err)
	}
}

// TestUpgradeRejectsNonAdminSubjects 訪戶本人與其餘非管理主體都被拒在授權那一跳，
// 不消耗派生、不碰資料庫、不寫審計——「Guest 不能給自己提升權限」由此有證據。
func TestUpgradeRejectsNonAdminSubjects(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	guest := seedGuest(t, e, "guest_self_lift", "想自升的旅人")
	before := rowSnapshot(t, e, guest.ID)

	selfLift := identitytest.Account(t, guest.ID, identitytest.WithGuestType())
	cases := map[string]identity.Principal{
		"訪戶本人": selfLift,
		"普通帳戶": identitytest.Account(t, identitytest.NewID(t)),
		"系統主體": identitytest.System(t, identity.OriginCLI),
		"匿名主體": identity.Anonymous(),
	}
	for name, principal := range cases {
		_, err := e.service.UpgradeGuestToStandard(ctx, principal, guest.ID,
			UpgradeInput{LoginName: testUpgradeLogin, InitialPassword: testUpgradePassword},
			"req-deny")
		if !errors.Is(err, identity.ErrPermissionDenied) && !errors.Is(err, identity.ErrNotAuthenticated) {
			t.Errorf("%s 自我升級應被拒為權限/身分錯誤，實際 %v", name, err)
		}
	}
	if got := rowSnapshot(t, e, guest.ID); got != before {
		t.Errorf("被拒的自我升級一個字都不該落庫，變更前 %s／實際 %s", before, got)
	}
	if n := countUpgradeAudits(t, e); n != 0 {
		t.Errorf("被拒的升級不得追加審計，實際 %d 筆", n)
	}
}

// TestUpgradeRejectsBadInputs 輸入不合規時不消耗寫入：空口令、超長口令、非法登入名。
func TestUpgradeRejectsBadInputs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := seedGuest(t, e, "guest_bad_input", "寫壞的申請")
	before := rowSnapshot(t, e, guest.ID)

	cases := []struct {
		name string
		in   UpgradeInput
		want error
	}{
		{"空口令", UpgradeInput{LoginName: "ok.login", InitialPassword: ""}, ErrInvalidUpgradePassword},
		{"超長口令", UpgradeInput{LoginName: "ok.login",
			InitialPassword: strings.Repeat("長", 1000)}, ErrInvalidUpgradePassword},
		{"含空白登入名", UpgradeInput{LoginName: "bad login", InitialPassword: testUpgradePassword},
			account.ErrInvalidLogin},
		{"空登入名", UpgradeInput{LoginName: "   ", InitialPassword: testUpgradePassword},
			account.ErrInvalidLogin},
	}
	for _, tc := range cases {
		if _, err := e.service.UpgradeGuestToStandard(ctx, admin, guest.ID, tc.in,
			"req-bad-"+tc.name); !errors.Is(err, tc.want) {
			t.Errorf("%s 應被判為 %v，實際 %v", tc.name, tc.want, err)
		}
	}
	if got := rowSnapshot(t, e, guest.ID); got != before {
		t.Errorf("被拒的輸入不得留下任何寫入，變更前 %s／實際 %s", before, got)
	}
	if n := countUpgradeAudits(t, e); n != 0 {
		t.Errorf("被拒的輸入不得追加審計，實際 %d 筆", n)
	}
}

// TestUpgradeRollsBackAtomically 會話或審計任一跳壞掉＝升級整筆回滾：
// 庫裡不會出現「已轉正卻沒口令」或「已撤會話卻查不到誰動的」的半升級身份。
func TestUpgradeRollsBackAtomically(t *testing.T) {
	t.Run("會話表壞掉", func(t *testing.T) {
		e := newEnv(t)
		ctx := context.Background()
		if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE sessions"); err != nil {
			t.Fatalf("移除會話表失敗（測試前提）：%v", err)
		}
		admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
		guest := seedGuest(t, e, "guest_rb_sessions", "回滾旅人")
		before := rowSnapshot(t, e, guest.ID)
		if _, err := e.service.UpgradeGuestToStandard(ctx, admin, guest.ID,
			UpgradeInput{LoginName: testUpgradeLogin, InitialPassword: testUpgradePassword},
			"req-rb-sessions"); err == nil {
			t.Fatal("撤銷寫不進去時升級必須回報失敗")
		}
		if got := rowSnapshot(t, e, guest.ID); got != before {
			t.Errorf("回滾後訪戶必須停在原形态（不留無口令的半升級身份），變更前 %s／實際 %s", before, got)
		}
	})
	t.Run("審計表壞掉", func(t *testing.T) {
		e := newEnv(t)
		ctx := context.Background()
		if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
			t.Fatalf("移除審計表失敗（測試前提）：%v", err)
		}
		admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
		guest := seedGuest(t, e, "guest_rb_audit", "回滾旅人")
		secrets := seedGuestSessions(t, e, guest.ID, 1)
		before := rowSnapshot(t, e, guest.ID)
		if _, err := e.service.UpgradeGuestToStandard(ctx, admin, guest.ID,
			UpgradeInput{LoginName: testUpgradeLogin, InitialPassword: testUpgradePassword},
			"req-rb-audit"); err == nil {
			t.Fatal("審計寫不進去時升級必須回報失敗")
		}
		if got := rowSnapshot(t, e, guest.ID); got != before {
			t.Errorf("回滾後訪戶必須停在原形態，變更前 %s／實際 %s", before, got)
		}
		if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); err != nil {
			t.Errorf("回滾後舊會話的 revoked_at 也不該被寫下，實際 %v", err)
		}
	})
}

// TestUpgradeCanceledContextWritesNothing 交易開始前就被取消：一個字都不該落盤。
func TestUpgradeCanceledContextWritesNothing(t *testing.T) {
	e := newEnv(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := seedGuest(t, e, "guest_cancel_probe", "取消旅人")
	before := rowSnapshot(t, e, guest.ID)

	if _, err := e.service.UpgradeGuestToStandard(canceled, admin, guest.ID,
		UpgradeInput{LoginName: testUpgradeLogin, InitialPassword: testUpgradePassword},
		"req-cancel"); err == nil {
		t.Fatal("已取消的 context 必須讓升級失敗")
	}
	if got := rowSnapshot(t, e, guest.ID); got != before {
		t.Errorf("取消後不得有任何寫入，變更前 %s／實際 %s", before, got)
	}
}

// TestUpgradeConcurrentOnlyOneWins 兩次同時到達的升級串行化：只有先提交者完成整筆，
// 後到者拿到形態結論而不是「又升級了一次」的假成功。
func TestUpgradeConcurrentOnlyOneWins(t *testing.T) {
	e := newEnv(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := seedGuest(t, e, "guest_race", "併發旅人")

	const attempts = 2
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		wins   int
		refuse int
		other  []error
	)
	logins := []string{"race.first.name", "race.second.name"}
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			_, err := e.service.UpgradeGuestToStandard(context.Background(), admin, guest.ID,
				UpgradeInput{LoginName: logins[i], InitialPassword: testUpgradePassword},
				"req-race")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrNotUpgradeableGuest):
				refuse++
			default:
				other = append(other, err)
			}
		}(i)
	}
	wg.Wait()
	if len(other) > 0 {
		t.Fatalf("併發升級只該出現成功或形態拒絕，實際 %v", other)
	}
	if wins != 1 || refuse != attempts-1 {
		t.Errorf("成功應恰好一次、其餘被拒，實際 win=%d refuse=%d", wins, refuse)
	}
	var loginName, accountType string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT login_name, account_type FROM accounts WHERE id = ?", guest.ID.String()).
		Scan(&loginName, &accountType); err != nil {
		t.Fatalf("讀回併發後的帳戶失敗：%v", err)
	}
	if loginName != logins[0] && loginName != logins[1] {
		t.Errorf("登入名應是兩個提案之一，實際 %q", loginName)
	}
	if accountType != "standard" {
		t.Errorf("贏家完成後形態應為 standard，實際 %q", accountType)
	}
	if n := countUpgradeAudits(t, e); n != 1 {
		t.Errorf("贏家一筆之外落敗者不配留審計，實際 %d 筆", n)
	}
}

// TestUpgradeNotGatedByCreationSwitches 建立開關管「準不準多出一筆」，不約束升級：
// 三個開關全關時管理員仍要處置得掉既有訪戶（關掉訪客入口不該順帶剝奪升級手段）。
func TestUpgradeNotGatedByCreationSwitches(t *testing.T) {
	e := newEnv(t)
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	e.setAdminCreate(t, false)
	guest := seedGuest(t, e, "guest_no_switch", "開關外旅人")

	upgraded := mustUpgrade(t, e, admin, guest.ID, testUpgradeLogin)
	if upgraded.Profile.Type != account.TypeStandard {
		t.Errorf("開關全關也該能升級既有訪戶，實際 %s", upgraded.Profile.Type)
	}
}
