// resetpassword_test.go 是「Root 重置管理員登入憑據」用例層的定向證據：
// 真資料庫＋注入時鐘＋真會話倉儲，斷言對象是三件事的合力——舊哈希死亡、
// 舊會話撤銷、首次改密義務重設——以及被拒時「一件都不發生」的形態。
// 停用中的目標重置後仍停用、「重置不是解除停用」由整行直讀作證。
package adminacct

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// 重置測試口令：只活在測試進程的記憶體，不是任何環境的憑據。
const (
	testResetPassword  = "adminacct-test-重置口令甲"
	testResetPassword2 = "adminacct-test-重置口令乙"
)

// storedHash 直讀帳戶的憑據雜湊（測試取證用；生產判定從不直讀這一欄）。
func storedHash(t *testing.T, e *env, accountID idgen.ID) string {
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

// TestResetAdminPasswordReplacesCredentialRevokesSessionsAndAudits
// 重置的三件效果一起落地，且只碰該碰的兩欄。
func TestResetAdminPasswordReplacesCredentialRevokesSessionsAndAudits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "reset.one")
	secrets := newAdminSessions(t, e, created.AccountID, 2)
	beforeHash := storedHash(t, e, created.AccountID)

	result, err := e.service.ResetAdminPassword(ctx, root, created.AccountID,
		testResetPassword, "req-reset-1")
	if err != nil {
		t.Fatalf("重置失敗：%v", err)
	}
	if result.RevokedSessions != 2 {
		t.Errorf("重置應撤銷目標全部 2 份會話，實際 %d", result.RevokedSessions)
	}
	if !result.Profile.MustChangePassword {
		t.Error("重置後的口令必須帶「首次登入須改密」義務")
	}
	if result.Profile.Status != account.StatusActive {
		t.Errorf("重置不該動狀態欄，實際 %s", result.Profile.Status)
	}
	afterHash := storedHash(t, e, created.AccountID)
	if afterHash == beforeHash {
		t.Fatal("重置必須換掉憑據雜湊")
	}
	if !strings.HasPrefix(afterHash, "$argon2id$") {
		t.Errorf("新雜湊必須是入庫同款編碼形態，實際前綴異常")
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

	var (
		targetID, actorKind, changes, reason string
	)
	if err := e.db.SQL().QueryRowContext(ctx,
		`SELECT target_id, actor_kind, changes_json, reason FROM root_audit WHERE action = 'admin.password_reset'`).
		Scan(&targetID, &actorKind, &changes, &reason); err != nil {
		t.Fatalf("讀回重置審計失敗：%v", err)
	}
	if targetID != created.AccountID.String() || actorKind != string(audit.ActorRoot) {
		t.Errorf("審計應指向被重置的帳戶且操作者為 root，實際 %s／%s", targetID, actorKind)
	}
	if !strings.Contains(changes, "must_change_password") || !strings.Contains(changes, "revoked_sessions") {
		t.Errorf("審計摘要應帶義務旗標與撤銷數量，實際 %s", changes)
	}
	for _, secret := range []string{testInitialPassword, testResetPassword, "$argon2id$"} {
		if strings.Contains(changes, secret) || strings.Contains(reason, secret) {
			t.Error("重置審計不得含任何口令明文或憑據雜湊")
		}
	}
	for _, secret := range secrets {
		if strings.Contains(changes, secret) || strings.Contains(reason, secret) {
			t.Error("重置審計不得帶出任何會話秘密")
		}
	}
	// 日誌面：成功句只講事實，不含口令與雜湊。
	if strings.Contains(e.logs.String(), testResetPassword) || strings.Contains(e.logs.String(), "$argon2id$") {
		t.Error("執行日誌不得含口令明文或憑據雜湊")
	}
}

// TestResetOnDisabledTargetKeepsDisabledState 停用中的目標可以被重置，
// 且重置不解除停用、不復活會話、撤銷數量為 0（其會話早在停用時已撤）。
func TestResetOnDisabledTargetKeepsDisabledState(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "reset.disabled")
	secrets := newAdminSessions(t, e, created.AccountID, 1)
	if _, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-pre-disable"); err != nil {
		t.Fatalf("預先停用失敗：%v", err)
	}
	snapshot := hiddenFieldsSnapshot(t, e.db, created.AccountID.String())

	// 快照之後再重置：整行比對只允許 password_hash 與 must_change_password 動，
	// status/disabled_at 必須逐字原位——先取「除憑據外」的形態比對。
	result, err := e.service.ResetAdminPassword(ctx, root, created.AccountID,
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
	// 整行形態：快照比對先證「確實寫進去過」（雜湊必變），再逐欄點名「什麼不許變」。
	if got := hiddenFieldsSnapshot(t, e.db, created.AccountID.String()); got == snapshot {
		t.Error("重置至少必須換掉憑據雜湊（整行逐字不動說明沒寫進去）")
	}
	var (
		statusText     string
		disabledAt     int64
		mustChangeFlag int
	)
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT status, disabled_at, must_change_password FROM accounts WHERE id = ?",
		created.AccountID.String()).Scan(&statusText, &disabledAt, &mustChangeFlag); err != nil {
		t.Fatalf("讀回停用形態失敗：%v", err)
	}
	if statusText != "disabled" || disabledAt == 0 || mustChangeFlag != 1 {
		t.Errorf("停用狀態必須原樣保持且重置後欠改密，實際 %s／%d／%d",
			statusText, disabledAt, mustChangeFlag)
	}
}

// TestResetReEnrollsFirstChangeObligation 已完成首次改密的目標被重置後，
// 義務重新生效（旗標由 0 設回 1）——重置交付的永遠是一次性口令。
func TestResetReEnrollsFirstChangeObligation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "reset.reenroll")
	// 直接把旗標清成「已償還」（等價於本人改密後的現值形態），
	// 讓重置面對的是「不欠密的人」——設回 1 才是重置自己的功勞而不是既有值。
	if _, err := e.db.SQL().ExecContext(ctx,
		"UPDATE accounts SET must_change_password = 0 WHERE id = ?", created.AccountID.String()); err != nil {
		t.Fatalf("製造「已改過密」現場失敗：%v", err)
	}

	result, err := e.service.ResetAdminPassword(ctx, root, created.AccountID,
		testResetPassword2, "req-reset-reenroll")
	if err != nil {
		t.Fatalf("重置失敗：%v", err)
	}
	if !result.Profile.MustChangePassword {
		t.Error("重置必須把首次改密義務設回生效")
	}
	var changes string
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT changes_json FROM root_audit WHERE action = 'admin.password_reset'").Scan(&changes); err != nil {
		t.Fatalf("讀回審計失敗：%v", err)
	}
	if !strings.Contains(changes, "must_change_password") {
		t.Errorf("審計應帶旗標前後值，實際 %s", changes)
	}
}

// TestResetRejectsInvalidPasswordWithoutWrites 口令形狀不合格是請求本體的問題：
// 派生在交易外被擋下，一個查詢、一次撤銷、一筆審計都不該發生。
func TestResetRejectsInvalidPasswordWithoutWrites(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "reset.badpw")
	secrets := newAdminSessions(t, e, created.AccountID, 1)
	snapshot := hiddenFieldsSnapshot(t, e.db, created.AccountID.String())
	auditsBefore := countRows(t, e.db, "root_audit")

	for name, password := range map[string]string{
		"空口令":  "",
		"超長口令": strings.Repeat("長", credential.MaxPasswordLength),
	} {
		if _, err := e.service.ResetAdminPassword(ctx, root, created.AccountID,
			password, "req-"+name); !errors.Is(err, ErrInvalidResetPassword) {
			t.Errorf("%s：應回口令形狀結論，實際 %v", name, err)
		}
	}
	if got := hiddenFieldsSnapshot(t, e.db, created.AccountID.String()); got != snapshot {
		t.Error("被拒的重置不得動目標帳戶任何一欄")
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); err != nil {
		t.Errorf("被拒的重置不得半套撤銷會話，實際 %v", err)
	}
	if got := countRows(t, e.db, "root_audit"); got != auditsBefore {
		t.Errorf("被拒的重置不得追加審計（前 %d 後 %d）", auditsBefore, got)
	}
}

// TestResetRejectsNonRootAndNonMember 越權與不在目錄：判定與其餘 Root 用例同一道閘。
func TestResetRejectsNonRootAndNonMember(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "reset.matrix")

	plain := identitytest.Account(t, identitytest.NewID(t))
	otherAdmin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	if _, err := e.service.ResetAdminPassword(ctx, plain, created.AccountID,
		testResetPassword, "req-plain"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("普通帳戶重置管理員應回權限錯誤，實際 %v", err)
	}
	if _, err := e.service.ResetAdminPassword(ctx, otherAdmin, created.AccountID,
		testResetPassword, "req-admin"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("管理員重置同級管理員應回權限錯誤（本步不開放該權限），實際 %v", err)
	}
	if _, err := e.service.ResetAdminPassword(ctx, root, identitytest.NewID(t),
		testResetPassword, "req-ghost"); !errors.Is(err, ErrAdminNotFound) {
		t.Errorf("幽靈標識應回查無同形，實際 %v", err)
	}
	// Root 保留標識：Root 不落帳戶表，與查無同一句話。
	rootSubjectID, err := identity.RootSubjectID()
	if err != nil {
		t.Fatalf("取 Root 保留標識失敗：%v", err)
	}
	if _, err := e.service.ResetAdminPassword(ctx, root, rootSubjectID,
		testResetPassword, "req-rootish"); !errors.Is(err, ErrAdminNotFound) {
		t.Errorf("以 Root 為目標不構成第二個答案，實際 %v", err)
	}
	// 零值標識在進交易前就是查無（不拿「沒帶 ID」去問資料庫）。
	if _, err := e.service.ResetAdminPassword(ctx, root, idgen.ID{},
		testResetPassword, "req-nil"); !errors.Is(err, ErrAdminNotFound) {
		t.Errorf("零值標識應回查無同形，實際 %v", err)
	}
	// 物理刪除目標：先撤授予再刪行（外鍵方向），重置必須回查無。
	if _, err := e.db.SQL().ExecContext(ctx,
		"DELETE FROM account_server_roles WHERE account_id = ?", created.AccountID.String()); err != nil {
		t.Fatalf("刪除測試授予失敗：%v", err)
	}
	if _, err := e.db.SQL().ExecContext(ctx,
		"DELETE FROM accounts WHERE id = ?", created.AccountID.String()); err != nil {
		t.Fatalf("刪除測試帳戶失敗：%v", err)
	}
	if _, err := e.service.ResetAdminPassword(ctx, root, created.AccountID,
		testResetPassword, "req-deleted"); !errors.Is(err, ErrAdminNotFound) {
		t.Errorf("已刪除目標的重置應回查無同形而不是『重置成功』，實際 %v", err)
	}
}

// TestRepeatedResetEachIsWholeOperation 重複請求的批准語意：每次都做一次完整重置。
//
// 這與停用的 2014（「對著舊畫面再點一次」被拒）刻意不同：重置沒有依據值，
// 第二次提交不是「陳舊的失敗嘗試」，而是又一次真實生效的特權操作——所以它必須
// 如實再撤一輪會話、如實再留一筆審計，界面因此不得在結果不明時自動重發。
func TestRepeatedResetEachIsWholeOperation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "reset.repeat")

	first, err := e.service.ResetAdminPassword(ctx, root, created.AccountID,
		testResetPassword, "req-repeat-1")
	if err != nil {
		t.Fatalf("首次重置失敗：%v", err)
	}
	if first.RevokedSessions != 0 {
		t.Errorf("還沒有任何會話可撤，首次重置應撤 0，實際 %d", first.RevokedSessions)
	}
	// 第一次之後新簽發一份會話：第二次重置必須把它也撤掉（撤銷不是只在首次的一次性事件）。
	secret := newAdminSessions(t, e, created.AccountID, 1)[0]
	second, err := e.service.ResetAdminPassword(ctx, root, created.AccountID,
		testResetPassword2, "req-repeat-2")
	if err != nil {
		t.Fatalf("第二次重置失敗：%v", err)
	}
	if second.RevokedSessions != 1 {
		t.Errorf("第二次重置應撤掉新簽發的 1 份會話，實際 %d", second.RevokedSessions)
	}
	hash := storedHash(t, e, created.AccountID)
	if mustVerify(t, hash, testInitialPassword) || mustVerify(t, hash, testResetPassword) {
		t.Error("最終現值必須是第二次重置的口令，先前所有口令一律失效")
	}
	if !mustVerify(t, hash, testResetPassword2) {
		t.Error("第二次交付的口令必須有效")
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); !errors.Is(err, session.ErrRevoked) {
		t.Errorf("第二次重置必須撤銷中間簽發的會話，實際 %v", err)
	}
	var resets int
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.password_reset'").Scan(&resets); err != nil {
		t.Fatalf("計數重置審計失敗：%v", err)
	}
	if resets != 2 {
		t.Errorf("兩次完整的重置必須各留一筆審計，實際 %d 筆", resets)
	}
}

// TestResetRollsBackWhenAuditCannotBeWritten 審計寫不進，重置整筆回滾：
// 哈希、旗標、撤銷一件都不留——不留痕的憑據變更不該被當成成功。
func TestResetRollsBackWhenAuditCannotBeWritten(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "reset.rollback")
	secrets := newAdminSessions(t, e, created.AccountID, 1)
	beforeHash := storedHash(t, e, created.AccountID)

	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("製造審計故障失敗：%v", err)
	}
	if _, err := e.service.ResetAdminPassword(ctx, root, created.AccountID,
		testResetPassword, "req-dropped"); err == nil {
		t.Fatal("審計表不可用時重置必須失敗")
	}
	if got := storedHash(t, e, created.AccountID); got != beforeHash {
		t.Error("回滾後憑據雜湊必須原封不動（不留只換一半的憑據）")
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); err != nil {
		t.Errorf("回滾後不得留下半套撤銷（會話應仍可用），實際 %v", err)
	}
	var flag int
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT must_change_password FROM accounts WHERE id = ?", created.AccountID.String()).Scan(&flag); err != nil {
		t.Fatalf("讀回旗標失敗：%v", err)
	}
	if flag != 1 {
		t.Errorf("開設時的旗標本為 1，回滾後必須仍是 1，實際 %d", flag)
	}
}

// TestResetCanceledContextWritesNothing 交易尚未開始就帶著已取消的 context：零寫入。
func TestResetCanceledContextWritesNothing(t *testing.T) {
	e := newEnv(t)
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "reset.canceled")
	snapshot := hiddenFieldsSnapshot(t, e.db, created.AccountID.String())

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.service.ResetAdminPassword(canceled, root, created.AccountID,
		testResetPassword, "req-canceled"); err == nil {
		t.Fatal("已取消的 context 必須讓重置失敗")
	}
	if got := hiddenFieldsSnapshot(t, e.db, created.AccountID.String()); got != snapshot {
		t.Error("取消的請求不得留下任何欄位位移")
	}
}

// TestResetConcurrentAllAreWholeOperations 四路併發重置：沒有 CAS 就沒有「落敗者」，
// 每一路都要嘛完整落地（單寫入者串行化）、要嘛是明確的基礎設施失敗，
// 但絕不出現「報成功而一個字沒寫」。審計筆數與成功次數嚴格一致。
func TestResetConcurrentAllAreWholeOperations(t *testing.T) {
	e := newEnv(t)
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "reset.race")

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
			_, err := e.service.ResetAdminPassword(context.Background(), root, created.AccountID,
				passwords[i], "req-race")
			results[i] = err
		}(i)
	}
	wg.Wait()

	wins := 0
	for _, err := range results {
		if err == nil {
			wins++
		} else {
			// 併發下出現的錯誤只允許是「整體失敗的基礎設施結論」（交易會回滾，
			// 不留半套）；任何成功都不許是假的，這裡只統計真成功。
			t.Logf("併發重置出現失敗（須為整筆回滾）：%v", err)
		}
	}
	if wins == 0 {
		t.Fatal("四路併發重置不得全軍覆沒（那是缺陷，不是競爭）")
	}
	var resets int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.password_reset'").Scan(&resets); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if resets != wins {
		t.Errorf("每一次成功必須恰好一筆審計（成功 %d，審計 %d）", wins, resets)
	}
	hash := storedHash(t, e, created.AccountID)
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
