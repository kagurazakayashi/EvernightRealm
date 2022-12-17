// status_test.go 是「Root 停用與恢復管理員登入」用例層的定向證據：
// 真資料庫＋注入時鐘＋真會話倉儲，斷言對象是三件事的合力——狀態 CAS、
// 同交易撤銷、審計落地——以及它們被拒時「一件都不發生」的形態。
package adminacct

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// newAdminSessions 給測試管理員簽發 n 份會話，回傳全部秘密明文。
//
// 主體經 identitytest 構造（與本套件既有測試同路），會話倉儲現讀 accounts
// 判帳戶可用——新開的管理員是 active，簽發必然成功。
func newAdminSessions(t *testing.T, e *env, accountID idgen.ID, n int) []string {
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

// TestDisableAdminWritesStatusRevokesSessionsAndAudits 停用的三件效果一起落地。
func TestDisableAdminWritesStatusRevokesSessionsAndAudits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "stop.one")
	secrets := newAdminSessions(t, e, created.AccountID, 2)

	result, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-disable-1")
	if err != nil {
		t.Fatalf("停用失敗：%v", err)
	}
	if result.RevokedSessions != 2 {
		t.Errorf("停用應撤銷目標全部 2 份會話，實際 %d", result.RevokedSessions)
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

	var (
		action, targetID, actorKind, changes, reason string
	)
	if err := e.db.SQL().QueryRowContext(ctx,
		`SELECT action, target_id, actor_kind, changes_json, reason FROM root_audit WHERE action = 'admin.disable'`).
		Scan(&action, &targetID, &actorKind, &changes, &reason); err != nil {
		t.Fatalf("讀回停用審計失敗：%v", err)
	}
	if targetID != created.AccountID.String() || actorKind != string(audit.ActorRoot) {
		t.Errorf("審計應指向被停用的帳戶且操作者為 root，實際 %s／%s", targetID, actorKind)
	}
	if !strings.Contains(changes, `"active"`) || !strings.Contains(changes, `"disabled"`) {
		t.Errorf("審計前後摘要應帶 status 的新舊值，實際 %s", changes)
	}
	if !strings.Contains(changes, "revoked_sessions") || !strings.Contains(changes, "disabled_at") {
		t.Errorf("撤銷數量與停用時刻都要可追蹤，實際 %s", changes)
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

// TestEnableAdminRestoresLoginOnly 恢復只恢復新登入能力：旗標不動、舊會話不復活。
func TestEnableAdminRestoresLoginOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "stop.revive")
	secrets := newAdminSessions(t, e, created.AccountID, 1)

	if _, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-disable-2"); err != nil {
		t.Fatalf("停用失敗：%v", err)
	}
	result, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusActive, ExpectedStatus: account.StatusDisabled},
		"req-enable-1")
	if err != nil {
		t.Fatalf("恢復失敗：%v", err)
	}
	if result.RevokedSessions != 0 {
		t.Errorf("恢復不該撤銷任何會話，實際撤了 %d", result.RevokedSessions)
	}
	if result.Profile.Status != account.StatusActive || !result.Profile.DisabledAt.IsZero() {
		t.Errorf("恢復後應是 active 且不帶停用時刻，實際 %+v", result.Profile)
	}
	if !result.Profile.MustChangePassword {
		t.Error("首次改密義務不因恢復而解除")
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); !errors.Is(err, session.ErrRevoked) {
		t.Errorf("停用前的會話在恢復後仍必須已撤銷，實際 %v", err)
	}
	// 恢復後的帳戶可以簽發新會話（「新登入能力」的存在證明；生產路徑的閉環在 httpapi 層）。
	fresh := identitytest.Account(t, created.AccountID, identitytest.ServerAdmin())
	if _, _, err := e.sessions.Create(ctx, e.db.SQL(), fresh); err != nil {
		t.Errorf("恢復後新會話簽發應成功：%v", err)
	}

	var enableChanges string
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT changes_json FROM root_audit WHERE action = 'admin.enable'").
		Scan(&enableChanges); err != nil {
		t.Fatalf("讀回恢復審計摘要失敗：%v", err)
	}
	if !strings.Contains(enableChanges, `"disabled"`) || !strings.Contains(enableChanges, `"active"`) {
		t.Errorf("恢復審計應帶 status 前後值，實際 %s", enableChanges)
	}
	if strings.Contains(enableChanges, testInitialPassword) || strings.Contains(enableChanges, "$argon2id$") {
		t.Error("恢復審計不得含憑據材料")
	}
}

// TestStatusChangeRejectsRepeatAndConflicts 重複操作與陳舊依據：一件都不發生。
//
// 三段各釘一件事：同值意圖與表外狀態在進交易前就是輸入錯誤；「對著你看見過的
// 現狀下停用令，但現狀已變」是 CAS 落敗；衝突的那些次零撤銷、零審計——
// 把「什麼都沒發生」說成「又停用了一次」，審計和真相就對不上。
func TestStatusChangeRejectsRepeatAndConflicts(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "stop.repeat")
	secrets := newAdminSessions(t, e, created.AccountID, 1)

	if _, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusDisabled},
		"req-same"); !errors.Is(err, ErrInvalidStatusChange) {
		t.Errorf("同值變更應回輸入錯誤，實際 %v", err)
	}
	if _, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
		StatusChangeInput{NewStatus: account.Status("ghost"), ExpectedStatus: account.StatusActive},
		"req-ghost"); !errors.Is(err, ErrInvalidStatusChange) {
		t.Errorf("表外狀態應回輸入錯誤，實際 %v", err)
	}
	auditsBeforeFirst := countRows(t, e.db, "root_audit")

	if _, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-first"); err != nil {
		t.Fatalf("首次停用失敗：%v", err)
	}
	// 重複停用：呼叫端手上那份「他還活著」的舊畫面不再是現值。
	if _, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-dup"); !errors.Is(err, ErrStatusConflict) {
		t.Errorf("對已停用者再停用應回併發衝突，實際 %v", err)
	}
	// 陳舊依據的恢復同理（現值已是 disabled，拿 active 當依據必敗——依據反了）。
	if _, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusActive, ExpectedStatus: account.StatusActive},
		"req-enable-stale"); !errors.Is(err, ErrInvalidStatusChange) {
		t.Errorf("對已停用者拿 disabled 之外的依據恢復應先過輸入閘，實際 %v", err)
	}
	if _, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusActive, ExpectedStatus: account.StatusDisabled},
		"req-ok-once"); err != nil {
		t.Fatalf("合法恢復失敗：%v", err)
	}
	snapshot := hiddenFieldsSnapshot(t, e.db, created.AccountID.String())
	// 手上還停在「他是停用狀態」的人再點一次恢復：依據有效但已不是現值，CAS 落敗。
	if _, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusActive, ExpectedStatus: account.StatusDisabled},
		"req-late"); !errors.Is(err, ErrStatusConflict) {
		t.Errorf("依據過期的恢復應回併發衝突，實際 %v", err)
	}

	// 贏家寫過之後，衝突的那些次沒有把撤銷或狀態改回來（撤銷不可逆也不重放）。
	if got := hiddenFieldsSnapshot(t, e.db, created.AccountID.String()); got != snapshot {
		t.Error("被拒的狀態變更不得觸碰任何欄位（含狀態本身）")
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); !errors.Is(err, session.ErrRevoked) {
		t.Errorf("衝突的停用不該復活或重撤會話，實際 %v", err)
	}
	// 審計恰好兩筆增量：disable 與 enable；輸入錯誤與衝突的每一次都是零。
	if got := countRows(t, e.db, "root_audit"); got != auditsBeforeFirst+2 {
		t.Errorf("被拒與衝突的變更不得追加審計（前 %d，後 %d，預期 %d）",
			auditsBeforeFirst, got, auditsBeforeFirst+2)
	}
}

// TestDisableConcurrentSameExpectedExactlyOne 六路並發同依據：恰好一次生效。
//
// 這釘的是「停用與另一請求同時到達」的最終裁定在資料庫條件裡：
// 六路都宣稱「我看見他活著」，庫裡只可能有一筆 UPDATE 命中，其餘五路全數回衝突——
// 而撤銷與審計只屬於贏家那筆交易。
func TestDisableConcurrentSameExpectedExactlyOne(t *testing.T) {
	e := newEnv(t)
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "stop.race")
	secrets := newAdminSessions(t, e, created.AccountID, 3)

	var wg sync.WaitGroup
	errs := make([]error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := e.service.UpdateAdminStatus(context.Background(), root, created.AccountID,
				StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
				"req-race")
			errs[i] = err
		}(i)
	}
	wg.Wait()

	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrStatusConflict):
			// 正常落敗：一個字都沒寫。
		default:
			// BusyTimeout 兩秒在單寫入鎖下本該把擁堵包成交易重試或衝突結論；
			// 若這裡出現其它錯誤，那是要在本步被當缺陷查到的東西。
			t.Fatalf("並發停用出現了非業務結論的失敗：%v", err)
		}
	}
	if wins != 1 {
		t.Errorf("六路同依據的停用必須恰好一次生效，實際 %d 次", wins)
	}
	if n := countRows(t, e.db, "root_audit"); n != 2 {
		t.Errorf("並發停用只該留下開設與贏家停用共兩筆審計，實際 %d", n)
	}
	for i, secret := range secrets {
		if _, err := e.sessions.Verify(context.Background(), e.db.SQL(), secret); !errors.Is(err, session.ErrRevoked) {
			t.Errorf("第 %d 份會話應已被贏家撤銷，實際 %v", i+1, err)
		}
	}
}

// TestDisableRollsBackWhenAuditCannotBeWritten 審計寫不進，停用整筆回滾：
// 狀態、disabled_at、撤銷一件都不留——不留痕的特權變更不該被當成成功。
func TestDisableRollsBackWhenAuditCannotBeWritten(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "stop.rollback")
	secrets := newAdminSessions(t, e, created.AccountID, 1)

	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("製造審計故障失敗：%v", err)
	}
	if _, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-dropped"); err == nil {
		t.Fatal("審計表不可用時停用必須失敗")
	}
	var status string
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT status FROM accounts WHERE id = ?", created.AccountID.String()).Scan(&status); err != nil {
		t.Fatalf("讀回狀態失敗：%v", err)
	}
	if status != "active" {
		t.Errorf("回滾後帳戶必須仍是 active，實際 %s", status)
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); err != nil {
		t.Errorf("回滾後不得留下半套撤銷（會話應仍可用），實際 %v", err)
	}
}

// TestStatusChangeRejectsNonRootAndNonMember 越權與不在目錄：判定與讀取同一道閘。
func TestStatusChangeRejectsNonRootAndNonMember(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "stop.matrix")

	// 普通帳戶與持角色的管理員都碰不動這個用例：NeedRoot 只放過 Root。
	plain := identitytest.Account(t, identitytest.NewID(t))
	otherAdmin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	if _, err := e.service.UpdateAdminStatus(ctx, plain, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-plain"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("普通帳戶停用管理員應回權限錯誤，實際 %v", err)
	}
	if _, err := e.service.UpdateAdminStatus(ctx, otherAdmin, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-admin"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("管理員停用同級管理員應回權限錯誤（本步不開放該權限），實際 %v", err)
	}
	// 未持有授予的帳戶與幽靈標識同形：狀態通路不比較「差哪一半」。
	if _, err := e.service.UpdateAdminStatus(ctx, root, identitytest.NewID(t),
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-ungranted"); !errors.Is(err, ErrAdminNotFound) {
		t.Errorf("目錄外的標識應回查無同形，實際 %v", err)
	}
	// Root 不落帳戶表也不落授予表：任何以 Root 為「帳戶標識」的目標都過不了成員資格檢查。
	rootSubjectID, err := identity.RootSubjectID()
	if err != nil {
		t.Fatalf("取 Root 保留標識失敗：%v", err)
	}
	if _, err := e.service.UpdateAdminStatus(ctx, root, rootSubjectID,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-rootish"); !errors.Is(err, ErrAdminNotFound) {
		t.Errorf("以 Root 為目標不構成第二個答案，實際 %v", err)
	}
	// 物理刪除的帳戶：查無就是查無，絕不當成「停用過、可以恢復」。
	if _, err := e.db.SQL().ExecContext(ctx,
		"DELETE FROM account_server_roles WHERE account_id = ?", created.AccountID.String()); err != nil {
		t.Fatalf("刪除測試授予失敗：%v", err)
	}
	if _, err := e.db.SQL().ExecContext(ctx,
		"DELETE FROM accounts WHERE id = ?", created.AccountID.String()); err != nil {
		t.Fatalf("刪除測試帳戶失敗：%v", err)
	}
	if _, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
		StatusChangeInput{NewStatus: account.StatusActive, ExpectedStatus: account.StatusDisabled},
		"req-deleted"); !errors.Is(err, ErrAdminNotFound) {
		t.Errorf("已刪除目標的恢復應回查無同形而不是『恢复成功』，實際 %v", err)
	}
}
