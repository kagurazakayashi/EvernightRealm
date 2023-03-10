// deleted_test.go 是「管理員軟刪除普通帳戶與訪戶帳戶」用例的定向證據。
//
// 它要量的不是「有沒有一個按鈕」，而是刪除這句話在資料庫與既有通路上的四件落地：
//   - 新登入被拒、既有會話當場失效（不是等它自然到期）；
//   - 活的投影匿名化，而寫下的歷史（審計、綁定留痕、登入名占用）一個字都不動；
//   - 每一條既有寫入通路面對終態都自成一句話，既不是 1001 那种「查無此人」的謊，
//     也不是撞庫的觸發器換來的 500；
//   - 越權的目標（另一位管理員、操作者自己、Root、還在審批鏈門外的申請）
//     統統不可達，這條端點不是標識探測器。
//
// 全程使用本次專屬的暫存庫與注入時鐘：不佔 5206、不碰任何真實資料目錄，
// 也不動用戶其他進程。測試口令只活在測試進程的記憶體。
package stdacct

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// countDeleteAudits 數 Root 域裡的刪除審計筆數（「拒絕不寫審計」與「重複刪除只一筆」的尺）。
func countDeleteAudits(t *testing.T, e *env) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM root_audit WHERE action = 'account.delete'`).Scan(&n); err != nil {
		t.Fatalf("計數刪除審計失敗：%v", err)
	}
	return n
}

// deletedRow 讀回一筆帳戶的刪除形態（狀態、刪除時刻、顯示名與來源類型）。
//
// 走原始 SQL 而不是實體讀法：這一檔要證的包含「實體讀法自己也會複核的成對規則」，
// 而把證據交給被檢對象的校驗鏈，等於讓它自己给自己開通行證。
func deletedRow(t *testing.T, e *env, accountID idgen.ID) (status, displayName, accountType string,
	deletedAt int64) {
	t.Helper()
	var rawDeletedAt *int64
	err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT status, display_name, account_type, deleted_at FROM accounts WHERE id = ?`,
		accountID.String()).Scan(&status, &displayName, &accountType, &rawDeletedAt)
	if err != nil {
		t.Fatalf("讀回帳戶形態失敗：%v", err)
	}
	if rawDeletedAt != nil {
		deletedAt = *rawDeletedAt
	}
	return status, displayName, accountType, deletedAt
}

// TestDeleteStandardAccountStopsSignInRevokesSessionsAndAudits 正常刪除的三件效果一起落地：
// 換態帶時刻、顯示名匿名化、名下全部會話當場失效，並且新登入被拒；審計的操作者是那位管理員本人。
func TestDeleteStandardAccountStopsSignInRevokesSessionsAndAudits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Delete.StdAdmin")
	created := e.mustCreate(t, admin, "delete.victim")
	secrets := newAccountSessions(t, e, created.AccountID, 2)
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); err != nil {
		t.Fatalf("刪除前那份會話應還換得出身份：%v", err)
	}

	authService := e.newAuthService(t)
	e.clock.Advance(5 * time.Minute)
	beforeDelete := e.clock.Now()
	deletion, err := e.service.DeleteStandardAccount(ctx, admin, created.AccountID, "req-del-std")
	if err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}

	if deletion.RevokedSessions != 2 {
		t.Errorf("這次刪除應撤銷名下 2 枚會話，實際 %d", deletion.RevokedSessions)
	}
	if deletion.Profile.Status != account.StatusDeleted || deletion.Profile.DeletedAt.IsZero() {
		t.Errorf("回應要的是刪除後的資料庫現值，實際 %+v", deletion.Profile)
	}
	if !strings.HasPrefix(deletion.Profile.DisplayName, "DEL_") {
		t.Errorf("活的投影必須換成佔位顯示名，實際 %q", deletion.Profile.DisplayName)
	}
	if deletion.Profile.LoginName != created.LoginName {
		t.Errorf("刪除不動登入名（名字繼續被占用）：期望 %q，實際 %q",
			created.LoginName, deletion.Profile.LoginName)
	}

	// 刪除時刻取的是注入時鐘：不讓呼叫端代填，也不拿系統時間湊數。
	// 這裡断言的是「落在推進之後那一次 Now 上」，而 5 分鐘的推進讓它與建立時刻可分辨。
	wantMillis := timeutil.ToMillis(beforeDelete)
	if status, name, typ, at := deletedRow(t, e, created.AccountID); status != "deleted" ||
		!strings.HasPrefix(name, "DEL_") || typ != account.TypeStandard.String() || at != wantMillis {
		t.Errorf("落庫形態異常：status=%s name=%q type=%s deletedAt=%d（期望 %d）",
			status, name, typ, at, wantMillis)
	}

	// 舊會話當場失效：撤銷是寫下的 revoked_at 事實，不是每次現讀推導的口頭承諾。
	for _, secret := range secrets {
		if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); !errors.Is(err, session.ErrRevoked) {
			t.Errorf("刪除後既有會話應被判撤銷，實際 %v", err)
		}
	}
	// 新登入被拒，而且與口令錯同形：伺服器不對外人說出「這個人被刪了」。
	if _, err := authService.LoginAccount(ctx, "delete.victim", testInitialPassword,
		"req-del-login", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("被刪者的登入應收成憑據無效同形，實際 %v", err)
	}

	// 審計：一筆、落在 Root 域那張表（root_audit 本身沒有 activity_id 欄，
	// 結構上就冒充不了活動歸屬）、actor 是那位管理員本人（不冒充 Root、不降成 system）。
	var action, actorKind, actorID, changesJSON string
	if err := e.db.SQL().QueryRowContext(ctx,
		`SELECT action, actor_kind, actor_id, changes_json FROM root_audit
		  WHERE action = 'account.delete'`).
		Scan(&action, &actorKind, &actorID, &changesJSON); err != nil {
		t.Fatalf("讀回刪除審計失敗：%v", err)
	}
	if actorKind != "admin" || actorID != admin.AccountID().String() {
		t.Errorf("刪除審計的操作者歸屬異常：actor=%s/%s", actorKind, actorID)
	}
	if !strings.Contains(changesJSON, `"revoked_sessions"`) ||
		!strings.Contains(changesJSON, `"deleted_at"`) {
		t.Errorf("刪除審計要帶出撤銷數量與刪除時刻這兩項事實，實際 %s", changesJSON)
	}
	if n := countDeleteAudits(t, e); n != 1 {
		t.Errorf("一次成功刪除只該留一筆審計，實際 %d", n)
	}
}

// TestDeleteGuestRevokesItsEntrySessionsAndKeepsFrozenShape 訪戶走同一條刪除通路：
// 他那一趟臨時會話被撤，而「訪戶沒有口令可重置」的凍結形態不因刪除被改寫。
//
// 這一格也順量界面要講的那句話：訪戶被刪之後 revoked_sessions 通常大於 0，
// 因為訪戶進入時真的有一枚會話在跑（不是「訪客沒有會話」那句旧推測）。
func TestDeleteGuestRevokesItsEntrySessionsAndKeepsFrozenShape(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Delete.GuestAdmin")
	guest := e.seed(t, seedInput{Login: "guest_del_me", Display: "要被浏览的旅人",
		Type: account.TypeGuest})
	secrets := seedGuestSessions(t, e, guest.ID, 1)

	deletion, err := e.service.DeleteStandardAccount(ctx, admin, guest.ID, "req-del-guest")
	if err != nil {
		t.Fatalf("刪除訪戶失敗：%v", err)
	}
	if deletion.RevokedSessions != 1 {
		t.Errorf("訪戶那一趟臨時會話必須被撤，實際 revoked=%d", deletion.RevokedSessions)
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); !errors.Is(err, session.ErrRevoked) {
		t.Errorf("被刪訪戶的會話應被判撤銷，實際 %v", err)
	}
	if status, name, typ, at := deletedRow(t, e, guest.ID); status != "deleted" ||
		typ != account.TypeGuest.String() || at == 0 || !strings.HasPrefix(name, "DEL_") {
		t.Errorf("訪戶的刪除形態異常：status=%s type=%s name=%q deletedAt=%d", status, typ, name, at)
	}
	// 憑據欄一個字都不動：訪戶本來就沒有口令，刪除更不是「清憑據」那一步（屬物理清庫）。
	var hashPresent int
	if err := e.db.SQL().QueryRowContext(ctx,
		`SELECT COUNT(password_hash) FROM accounts WHERE id = ?`, guest.ID.String()).
		Scan(&hashPresent); err != nil {
		t.Fatalf("讀回憑據欄失敗：%v", err)
	}
	if hashPresent != 0 {
		t.Errorf("刪除不得寫入或改動任何憑據欄（訪戶的 password_hash 仍應是 NULL）")
	}
	// 來源類型保留：審計與界面都要還能說出「這個人當初是怎麼進來的」。
	if deletion.Profile.Type != account.TypeGuest {
		t.Errorf("回應要如實帶出來源類型，實際 %s", deletion.Profile.Type)
	}
}

// TestDeleteAnonymizesProjectionButNotHistory 匿名化動的是「活的投影」，不是歷史：
// 刪除之前寫下的審計仍帶著當時的顯示名，而本用例沒有、也不該有任何通路能回去改它們。
func TestDeleteAnonymizesProjectionButNotHistory(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Delete.HistoryAdmin")
	created := e.mustCreate(t, admin, "delete.history")

	// 建號那筆審計的 changes 裡記的就是「測試普通帳戶」這個當時的名字。
	var beforeText string
	if err := e.db.SQL().QueryRowContext(ctx,
		`SELECT changes_json FROM root_audit WHERE action = 'account.create_standard'`).
		Scan(&beforeText); err != nil {
		t.Fatalf("讀回建號審計失敗：%v", err)
	}
	if !strings.Contains(beforeText, "測試普通帳戶") {
		t.Fatalf("建號審計應含當時的顯示名，實際 %s", beforeText)
	}
	auditsBefore := countRows(t, e.db, "root_audit")
	beforeRaw := strings.ReplaceAll(beforeText, " ", "")

	if _, err := e.service.DeleteStandardAccount(ctx, admin, created.AccountID, "req-del-hist"); err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}

	if err := e.db.SQL().QueryRowContext(ctx,
		`SELECT changes_json FROM root_audit WHERE action = 'account.create_standard'`).
		Scan(&beforeText); err != nil {
		t.Fatalf("重讀建號審計失敗：%v", err)
	}
	if strings.ReplaceAll(beforeText, " ", "") != beforeRaw {
		t.Errorf("刪除改寫了歷史審計：前 %s／後 %s", beforeRaw, beforeText)
	}
	if strings.Contains(beforeText, "DEL_") {
		t.Errorf("歷史審計不得被事後匿名化：%s", beforeText)
	}
	if n := countRows(t, e.db, "root_audit"); n != auditsBefore+1 {
		t.Errorf("刪除只該追加自己那一筆（前 %d 後 %d）", auditsBefore, n)
	}

	// 刪除那一筆自己記的是「刪除前的名字 → 佔位名」，這是後來者解釋這次刪除所需的快照。
	var deleteChanges string
	if err := e.db.SQL().QueryRowContext(ctx,
		`SELECT changes_json FROM root_audit WHERE action = 'account.delete'`).
		Scan(&deleteChanges); err != nil {
		t.Fatalf("讀回刪除審計失敗：%v", err)
	}
	if !strings.Contains(deleteChanges, "測試普通帳戶") || !strings.Contains(deleteChanges, "DEL_") {
		t.Errorf("刪除審計要同時帶出刪除前的名字與佔位名，實際 %s", deleteChanges)
	}
}

// TestDeletedAndRetiredRefuseEveryWriteUseCase 兩條終態在全部寫入通路上各自成句：
// 編輯、停用／恢復、重置、升級四條都不許越過終態判定，而且是可判別的結論而不是 500。
//
// 退休那一格量的是本步補上的一道缺口：退休行的每一欄都被庫釘住，
// 少了應用層的判定，顯示名編輯會撞觸發器換成一個「後端壞了」的 500。
func TestDeletedAndRetiredRefuseEveryWriteUseCase(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Delete.WriteAdmin")

	victim := e.mustCreate(t, admin, "delete.writes")
	if _, err := e.service.DeleteStandardAccount(ctx, admin, victim.AccountID, "req-del-w"); err != nil {
		t.Fatalf("先建立刪除態失敗：%v", err)
	}
	victimRow := rowSnapshot(t, e, victim.AccountID)

	// 一筆已綁走的訪戶（retired），與一筆普通停用帳戶（可寫對照組）。
	guest := e.seed(t, seedInput{Login: "guest_w_pair", Display: "併入旅人", Type: account.TypeGuest})
	host := e.seed(t, seedInput{Login: "W.Host", Display: "受體"})
	ticket := mustIssue(t, e, admin, guest.ID, host.ID)
	if _, err := e.service.ConfirmGuestBind(ctx, identitytest.Account(t, host.ID), ticket,
		"req-del-bind"); err != nil {
		t.Fatalf("種出退休形態的綁定失敗：%v", err)
	}
	retiredRow := rowSnapshot(t, e, guest.ID)

	// 已刪除目標在五條寫入通路上全部回同一句 ErrAccountDeleted（含再一次刪除自己）。
	// 停用那一格填的依據值是 disabled：讓它先過參數合規那道閘，才量得到終態判定本身。
	for _, probe := range []struct {
		name string
		fn   func() error
	}{
		{"編輯顯示名", func() error {
			_, err := e.service.UpdateStandardAccountProfile(ctx, admin, victim.AccountID,
				"不該落庫", "測試普通帳戶", "req-w-edit")
			return err
		}},
		{"停用與恢復", func() error {
			_, err := e.service.UpdateStandardAccountStatus(ctx, admin, victim.AccountID,
				StatusChangeInput{NewStatus: account.StatusActive,
					ExpectedStatus: account.StatusDisabled}, "req-w-status")
			return err
		}},
		{"重置憑據", func() error {
			_, err := e.service.ResetStandardAccountPassword(ctx, admin, victim.AccountID,
				testResetPassword, "req-w-reset")
			return err
		}},
		{"升級訪戶", func() error {
			_, err := e.service.UpgradeGuestToStandard(ctx, admin, victim.AccountID,
				UpgradeInput{LoginName: "w.new.name", InitialPassword: testUpgradePassword},
				"req-w-upgrade")
			return err
		}},
		{"再一次刪除", func() error {
			_, err := e.service.DeleteStandardAccount(ctx, admin, victim.AccountID, "req-w-del")
			return err
		}},
	} {
		audits := countRows(t, e.db, "root_audit")
		if err := probe.fn(); !errors.Is(err, ErrAccountDeleted) {
			t.Errorf("%s：對已刪除目標應回 ErrAccountDeleted，實際 %v", probe.name, err)
		}
		if n := countRows(t, e.db, "root_audit"); n != audits {
			t.Errorf("%s：被拒絕的寫入不得追加審計（前 %d 後 %d）", probe.name, audits, n)
		}
	}
	if got := rowSnapshot(t, e, victim.AccountID); got != victimRow {
		t.Errorf("被終態拒絕的寫入動了那一行：前 %s／實際 %s", victimRow, got)
	}

	// 已退休的訪戶：編輯與刪除各自回 2028，而不是撞庫的 500，也不是 1001 的謊。
	if _, err := e.service.UpdateStandardAccountProfile(ctx, admin, guest.ID,
		"不該改的名字", retiredDisplayNameForTest, "req-r-edit"); !errors.Is(err, ErrAccountRetired) {
		t.Errorf("退休訪戶的顯示名編輯應回 ErrAccountRetired（本步補上的缺口），實際 %v", err)
	}
	if _, err := e.service.DeleteStandardAccount(ctx, admin, guest.ID, "req-r-del"); !errors.Is(err, ErrAccountRetired) {
		t.Errorf("退休訪戶的刪除應回 ErrAccountRetired，實際 %v", err)
	}
	if got := rowSnapshot(t, e, guest.ID); got != retiredRow {
		t.Errorf("被退休判定拒絕的寫入動了來源一行：前 %s／實際 %s", retiredRow, got)
	}

	// 綁定的目標帳戶仍然可以被刪（他是普通帳戶，不是終態），而這件事不得波及來源與留痕。
	if _, err := e.service.DeleteStandardAccount(ctx, admin, host.ID, "req-del-host"); err != nil {
		t.Fatalf("刪除綁定目標失敗：%v", err)
	}
	if got := rowSnapshot(t, e, guest.ID); got != retiredRow {
		t.Errorf("刪除目標不得級聯動到已綁走的來源：前 %s／實際 %s", retiredRow, got)
	}
	if n := countWhere(t, e, `SELECT COUNT(*) FROM guest_account_bindings`); n != 1 {
		t.Errorf("綁定留痕必須原樣留在庫裡（歷史身分可回溯），實際 %d 行", n)
	}
	if status, _, typ, _ := deletedRow(t, e, host.ID); status != "deleted" ||
		typ != account.TypeStandard.String() {
		t.Errorf("目標的刪除形態異常：status=%s type=%s", status, typ)
	}
	if n := countDeleteAudits(t, e); n != 2 {
		t.Errorf("兩筆成功刪除各留一筆審計，實際 %d 筆", n)
	}
}

// retiredDisplayNameForTest 是退休行被綁走時服務端保留的那個名字（不做匿名化）。
const retiredDisplayNameForTest = "併入旅人"

// TestDeleteTwiceRefusesSecondAndWritesNothing 重複刪除不是「再做一次」：
// 第二次既不额外撤銷任何會話，也不留第二筆審計，而且帳戶行一個字都不動。
func TestDeleteTwiceRefusesSecondAndWritesNothing(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Delete.TwiceAdmin")
	created := e.mustCreate(t, admin, "delete.twice")
	newAccountSessions(t, e, created.AccountID, 3)

	first, err := e.service.DeleteStandardAccount(ctx, admin, created.AccountID, "req-twice-1")
	if err != nil {
		t.Fatalf("第一次刪除失敗：%v", err)
	}
	rowAfterFirst := rowSnapshot(t, e, created.AccountID)
	revokedRows := countWhere(t, e,
		`SELECT COUNT(*) FROM sessions WHERE revoked_at IS NOT NULL AND account_id = ?`,
		created.AccountID.String())
	auditsAfterFirst := countDeleteAudits(t, e)

	if _, err := e.service.DeleteStandardAccount(ctx, admin, created.AccountID, "req-twice-2"); !errors.Is(err, ErrAccountDeleted) {
		t.Fatalf("第二次刪除應回 ErrAccountDeleted，實際 %v", err)
	}
	if got := rowSnapshot(t, e, created.AccountID); got != rowAfterFirst {
		t.Errorf("第二次刪除寫進了那一行：前 %s／實際 %s", rowAfterFirst, got)
	}
	if n := countWhere(t, e,
		`SELECT COUNT(*) FROM sessions WHERE revoked_at IS NOT NULL AND account_id = ?`,
		created.AccountID.String()); n != revokedRows {
		t.Errorf("第二次刪除不得再撤任何會話（前 %d 後 %d）", revokedRows, n)
	}
	if n := countDeleteAudits(t, e); n != auditsAfterFirst {
		t.Errorf("第二次刪除不得留第二筆審計（前 %d 後 %d）", auditsAfterFirst, n)
	}
	if first.RevokedSessions != 3 {
		t.Errorf("第一次應撤 3 枚，實際 %d", first.RevokedSessions)
	}
}

// TestDeleteTargetMatrix 目標範圍：另一位管理員、操作者自己、Root 保留標識、幽靈、零值、
// 待審批與已拒絕的申請一律同一句 ErrAccountNotFound，而且端點不是標識探測器。
//
// 這一格量的是用戶那句邊界：普通管理員不能借一條統一的刪除接口去刪管理員或 Root，
// 也不能越過名冊的範圍規則去動還沒进门的人。
func TestDeleteTargetMatrix(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	self := e.seed(t, seedInput{Login: "delete.matrix.self", Display: "我自己"})
	if err := e.service.grants.Grant(ctx, e.db.SQL(), self.ID, identity.RoleServerAdmin); err != nil {
		t.Fatalf("補上操作者授予失敗：%v", err)
	}
	admin := identitytest.Account(t, self.ID, identitytest.ServerAdmin())
	peer := e.seed(t, seedInput{Login: "delete.matrix.peer", Display: "另一位管理員", Admin: true})
	pendingID := seedApprovalShaped(t, e, "delete.matrix.pending", account.StatusPending)
	rejectedID := seedApprovalShaped(t, e, "delete.matrix.rejected", account.StatusRejected)
	rootReserved, err := identity.RootSubjectID()
	if err != nil {
		t.Fatalf("取 Root 保留標識失敗：%v", err)
	}

	audits := countRows(t, e.db, "root_audit")
	accounts := countRows(t, e.db, "accounts")
	for name, id := range map[string]idgen.ID{
		"另一位管理員":    peer.ID,
		"操作者自己":     self.ID,
		"Root 保留標識": rootReserved,
		"幽靈標識":      identitytest.NewID(t),
		"零值標識":      idgen.ID{},
		"待審批申請":     pendingID,
		"已拒絕申請":     rejectedID,
	} {
		if _, err := e.service.DeleteStandardAccount(ctx, admin, id, "req-matrix-"+name); !errors.Is(err, ErrAccountNotFound) {
			t.Errorf("%s 應收斂成「不在這本目錄裡」，實際 %v", name, err)
		}
	}
	if got := rowSnapshot(t, e, peer.ID); !strings.Contains(got, "|status=active|") {
		t.Errorf("對另一位管理員的刪除不該發生，peer 現值 %s", got)
	}
	if got := rowSnapshot(t, e, pendingID); !strings.Contains(got, "|status=pending|") {
		t.Errorf("對待審批申請的刪除不該發生，現值 %s", got)
	}
	if n := countRows(t, e.db, "root_audit"); n != audits {
		t.Errorf("被拒的刪除不得成為寫入放大器（前 %d 後 %d）", audits, n)
	}
	if n := countRows(t, e.db, "accounts"); n != accounts {
		t.Errorf("被拒的刪除不得多出任何一筆帳戶（前 %d 後 %d）", accounts, n)
	}
}

// TestDeleteAuthorizationMatrix 沒有伺服器級管理權的主體一律被擋在授權那一步，
// 而且一個查詢都不消耗：普通帳戶、訪戶本人与匿名各拿到自己的那句既有結論。
func TestDeleteAuthorizationMatrix(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Delete.AuthAdmin")
	target := e.mustCreate(t, admin, "delete.auth.target")
	rowBefore := rowSnapshot(t, e, target.AccountID)
	audits := countRows(t, e.db, "root_audit")

	plain := e.seed(t, seedInput{Login: "delete.auth.plain", Display: "普通帳戶自己"})
	guest := e.seed(t, seedInput{Login: "guest_delete_auth", Display: "想刪自己的旅人",
		Type: account.TypeGuest})
	for name, principal := range map[string]identity.Principal{
		"普通帳戶": identitytest.Account(t, plain.ID),
		"訪戶":   identitytest.Account(t, guest.ID),
		"匿名":   identity.Anonymous(),
	} {
		_, err := e.service.DeleteStandardAccount(ctx, principal, target.AccountID, "req-auth-"+name)
		if !errors.Is(err, identity.ErrPermissionDenied) &&
			!errors.Is(err, identity.ErrNotAuthenticated) {
			t.Errorf("%s 應被授權閘擋下（既有的兩個結論之一），實際 %v", name, err)
		}
	}
	if got := rowSnapshot(t, e, target.AccountID); got != rowBefore {
		t.Errorf("被授權擋下的刪除動了目標一行：前 %s／實際 %s", rowBefore, got)
	}
	if n := countRows(t, e.db, "root_audit"); n != audits {
		t.Errorf("被授權擋下的刪除不留審計（前 %d 後 %d）", audits, n)
	}
}

// TestDeletedLoginNameStaysOccupied 刪除釋放的是「能不能登進來」，不是那個名字：
// 同一個登入名此後既登不進去、也註冊不出新的，舊責任不會被算到後來搶名字的人頭上。
func TestDeletedLoginNameStaysOccupied(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Delete.NameAdmin")
	created := e.mustCreate(t, admin, "delete.occupied")
	if _, err := e.service.DeleteStandardAccount(ctx, admin, created.AccountID, "req-occ-del"); err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}

	if _, err := e.service.CreateStandardAccount(ctx, admin, CreateInput{
		LoginName: "delete.occupied", DisplayName: "搶名字", InitialPassword: testInitialPassword,
	}, "req-occ-create"); !errors.Is(err, ErrDuplicateLogin) {
		t.Errorf("已刪者的登入名必須仍被占用，實際 %v", err)
	}
	// 而「大小寫與全形變體也算同一個名字」這條既有正規化規則不因刪除而打折。
	if _, err := e.service.CreateStandardAccount(ctx, admin, CreateInput{
		LoginName: "DELETE.OCCUPIED", DisplayName: "換個寫法搶", InitialPassword: testInitialPassword,
	}, "req-occ-case"); !errors.Is(err, ErrDuplicateLogin) {
		t.Errorf("正規化後的同名也必須被擋，實際 %v", err)
	}
	if n := countRows(t, e.db, "accounts"); n != 2 {
		t.Errorf("兩次搶名字都該整筆不發生，帳戶應仍是 2 筆（管理員與被刪者），實際 %d", n)
	}
}

// TestDeleteRollsBackWholeTransactionWhenAuditFails 審計落地失敗時整筆回滾：
// 不留「已 deleted 而 Root 域查不到是誰刪的」這種半套事實，既有會話也不受影响。
func TestDeleteRollsBackWholeTransactionWhenAuditFails(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Drop.RollbackAdmin")
	created := e.mustCreate(t, admin, "delete.rollback")
	secrets := newAccountSessions(t, e, created.AccountID, 1)
	rowBefore := rowSnapshot(t, e, created.AccountID)

	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("破壞審計表失敗：%v", err)
	}
	if _, err := e.service.DeleteStandardAccount(ctx, admin, created.AccountID,
		"req-drop-rollback"); err == nil {
		t.Fatal("審計落地失敗時刪除必須整體回滾")
	}
	if got := rowSnapshot(t, e, created.AccountID); got != rowBefore {
		t.Errorf("回滾後那一行應逐字原樣：前 %s／實際 %s", rowBefore, got)
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); err != nil {
		t.Errorf("回滾後既有會話應仍可用（撤銷跟著回滾）：%v", err)
	}
}

// TestDeleteRacesWithUpgradeAndBind 刪除與升級、綁定核銷交錯時的結果必須可解釋：
// 單寫入者把兩者串行化，兩個方向各自留下完整事實，不出現「升一半又刪了」或「綁了又回到可登入」。
func TestDeleteRacesWithUpgradeAndBind(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Delete.RaceAdmin")

	// 甲：同一筆訪戶上，刪除與升級同時到達。
	guestA := e.seed(t, seedInput{Login: "guest_race_up", Display: "競賽旅人", Type: account.TypeGuest})
	var wg sync.WaitGroup
	wg.Add(2)
	var delErrA, upErrA error
	go func() {
		defer wg.Done()
		_, delErrA = e.service.DeleteStandardAccount(ctx, admin, guestA.ID, "req-race-del-a")
	}()
	go func() {
		defer wg.Done()
		_, upErrA = e.service.UpgradeGuestToStandard(ctx, admin, guestA.ID,
			UpgradeInput{LoginName: "race.upgraded", InitialPassword: testUpgradePassword},
			"req-race-up-a")
	}()
	wg.Wait()
	if delErrA != nil {
		t.Errorf("刪除這一側必然成功（守衛只擋第二次刪除），實際 %v", delErrA)
	}
	// 升級Either先落地（那时它做完整筆轉正），或者在刪除之後到達並被終態判定擋下。
	// 兩句都可判別、都不是 500，而「既沒轉正又已被刪」與「轉正了卻沒刪除時刻」都不合法。
	if upErrA != nil && !errors.Is(upErrA, ErrAccountDeleted) {
		t.Errorf("升級落敗時應回可判別的終態結論，實際 %v", upErrA)
	}
	var status, accountType string
	var deletedAt int64
	if err := e.db.SQL().QueryRowContext(ctx,
		`SELECT status, account_type, deleted_at FROM accounts WHERE id = ?`, guestA.ID.String()).
		Scan(&status, &accountType, &deletedAt); err != nil {
		t.Fatalf("讀回競賽結果失敗：%v", err)
	}
	if status != "deleted" || deletedAt == 0 {
		t.Errorf("不管順序如何，最終都該是「已刪除且帶時刻」：實際 %s/%d", status, deletedAt)
	}
	if upErrA == nil && accountType != account.TypeStandard.String() {
		t.Errorf("升級成功那一側必須已轉正，實際 %s", accountType)
	}
	if upErrA != nil && accountType != account.TypeGuest.String() {
		t.Errorf("升級被擋那一側不應留下一個改過分類的行，實際 %s", accountType)
	}

	// 乙：綁定執行與刪除同一個訪戶交錯。綁定先落地則訪戶是 retired（且刪除應被拒），
	// 刪除先落地則綁定在交易內的計畫重跑中被拒——兩個方向都不留半套。
	guestB := e.seed(t, seedInput{Login: "guest_race_bind", Display: "競賽旅人乙",
		Type: account.TypeGuest})
	hostB := e.seed(t, seedInput{Login: "B.Host", Display: "受體乙"})
	ticketB := mustIssue(t, e, admin, guestB.ID, hostB.ID)
	wg.Add(2)
	var delErrB, bindErrB error
	go func() {
		defer wg.Done()
		_, delErrB = e.service.DeleteStandardAccount(ctx, admin, guestB.ID, "req-race-del-b")
	}()
	go func() {
		defer wg.Done()
		_, bindErrB = e.service.ConfirmGuestBind(ctx, identitytest.Account(t, hostB.ID), ticketB,
			"req-race-bind-b")
	}()
	wg.Wait()
	// 兩個方向不可能同時成功：綁定把來源寫成 retired，而 retired 是不可刪除的終態；
	// 刪除把來源寫成 deleted，而綁定的計畫重跑在那一刻就讀到「來源已非可登入狀態」。
	if bindErrB == nil && delErrB == nil {
		t.Error("綁定與刪除同時成功：同一個訪戶不可能既是 retired 又是 deleted")
	}
	if bindErrB == nil && !errors.Is(delErrB, ErrAccountRetired) {
		t.Errorf("綁定先落地時，刪除必須回退休那一句，實際 %v", delErrB)
	}
	if delErrB == nil && bindErrB != nil && errors.Is(bindErrB, ErrAccountNotFound) {
		t.Errorf("刪除先落地時，綁定該以可判別的計畫結論失敗而不是範圍拒絕：%v", bindErrB)
	}
	var retiredAt int64
	if err := e.db.SQL().QueryRowContext(ctx,
		`SELECT status, COALESCE(deleted_at, 0), COALESCE(retired_at, 0) FROM accounts WHERE id = ?`,
		guestB.ID.String()).Scan(&status, &deletedAt, &retiredAt); err != nil {
		t.Fatalf("讀回乙側結果失敗：%v", err)
	}
	switch {
	case retiredAt != 0:
		if status != account.StatusRetired.String() || deletedAt != 0 {
			t.Errorf("綁定先落地時該是 retired 且沒有刪除時刻，實際 %s/%d", status, deletedAt)
		}
		if !errors.Is(delErrB, ErrAccountRetired) {
			t.Errorf("綁定先落地後的刪除應回退休那句，實際 %v", delErrB)
		}
	case deletedAt != 0:
		if status != "deleted" {
			t.Errorf("刪除先落地時該是 deleted，實際 %s", status)
		}
		if bindErrB == nil {
			t.Error("刪除先落地時綁定必須失敗（計畫重跑時來源已不是可登入狀態）")
		}
		if n := countWhere(t, e, `SELECT COUNT(*) FROM guest_account_bindings`); n != 0 {
			t.Errorf("失敗的綁定不得留下留痕，實際 %d 行", n)
		}
	default:
		t.Error("兩個方向都該留下一個終態，實際既沒退休也沒刪除")
	}
}

// TestDirectoryAndDetailListDeletedRows 刪除後的展示形態：目錄列得到（含篩選 deleted 與
// deleted_at 投影），詳情讀得到並帶時刻與佔位名，而界面讀到的狀態就是服務端的那一句。
func TestDirectoryAndDetailListDeletedRows(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Delete.ListAdmin")
	kept := e.mustCreate(t, admin, "delete.listed")
	if _, err := e.service.DeleteStandardAccount(ctx, admin, kept.AccountID, "req-list-del"); err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}
	guest := e.seed(t, seedInput{Login: "guest_list_live", Display: "還活著的旅人",
		Type: account.TypeGuest})

	page, err := e.service.Directory(ctx, admin, DirectoryQuery{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("讀目錄失敗：%v", err)
	}
	found := map[string]DirectoryRow{}
	for _, row := range page.Rows {
		found[row.LoginName] = row
	}
	deletedRowSeen, ok := found["delete.listed"]
	if !ok {
		t.Fatalf("已刪者必須仍列在目錄裡（歷史身分回溯），實際 %v", page.Rows)
	}
	if deletedRowSeen.Status != account.StatusDeleted.String() ||
		deletedRowSeen.DeletedAt.IsZero() {
		t.Errorf("目錄行要同時帶出刪除狀態與刪除時刻，實際 %+v", deletedRowSeen)
	}
	if _, ok := found["guest_list_live"]; !ok {
		t.Errorf("活著的訪戶也該在同一頁上： %+v", page.Rows)
	}

	onlyDeleted, err := e.service.Directory(ctx, admin, DirectoryQuery{
		Page: 1, PageSize: 20, StatusFilter: account.StatusDeleted.String()})
	if err != nil {
		t.Fatalf("按 deleted 篩選失敗（這個篩選值自本步起合法）：%v", err)
	}
	if onlyDeleted.Total != 1 || len(onlyDeleted.Rows) != 1 ||
		onlyDeleted.Rows[0].LoginName != "delete.listed" {
		t.Errorf("deleted 篩選只該列出已刪者，實際 %+v", onlyDeleted.Rows)
	}
	if _, err := e.service.Directory(ctx, admin, DirectoryQuery{
		Page: 1, PageSize: 20, StatusFilter: account.StatusPending.String()}); !errors.Is(err, ErrInvalidStatusFilter) {
		t.Errorf("待審批仍不是這本目錄能篩的價值，實際 %v", err)
	}

	detail, err := e.service.StandardAccountProfile(ctx, admin, kept.AccountID)
	if err != nil {
		t.Fatalf("已刪者的詳情必須讀得到：%v", err)
	}
	if detail.Status != account.StatusDeleted || detail.DeletedAt.IsZero() ||
		!strings.HasPrefix(detail.DisplayName, "DEL_") {
		t.Errorf("詳情要自成一句「已被刪於何時、現在顯示什麼」，實際 %+v", detail)
	}

	// 未刪除的那一筆不該帶刪除時刻（零值冒充與事後回填是同一件事的兩種寫法）。
	liveDetail, err := e.service.StandardAccountProfile(ctx, admin, guest.ID)
	if err != nil {
		t.Fatalf("讀活著訪戶的詳情失敗：%v", err)
	}
	if !liveDetail.DeletedAt.IsZero() {
		t.Errorf("非刪除態的詳情不該帶 DeletedAt，實際 %v", liveDetail.DeletedAt)
	}
}

// TestDeleteBystandersUnaffected 刪除只動被點名的那一筆：旁觀者的會話、其他帳戶的行
// 與他們的審計都原樣不動，撤銷與匿名化都不是批量動作。
func TestDeleteBystandersUnaffected(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Delete.ScopeAdmin")
	victim := e.mustCreate(t, admin, "delete.scope.victim")
	bystander := e.mustCreate(t, admin, "delete.scope.other")
	victimSecrets := newAccountSessions(t, e, victim.AccountID, 1)
	bystanderSecrets := newAccountSessions(t, e, bystander.AccountID, 2)
	bystanderRow := rowSnapshot(t, e, bystander.AccountID)

	if _, err := e.service.DeleteStandardAccount(ctx, admin, victim.AccountID,
		"req-scope-del"); err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), victimSecrets[0]); !errors.Is(err, session.ErrRevoked) {
		t.Errorf("被點名的會話應已失效，實際 %v", err)
	}
	for _, secret := range bystanderSecrets {
		if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); err != nil {
			t.Errorf("旁觀者的會話一枚都不該被撤：%v", err)
		}
	}
	if got := rowSnapshot(t, e, bystander.AccountID); got != bystanderRow {
		t.Errorf("旁觀者的行被動了：前 %s／實際 %s", bystanderRow, got)
	}
	if n := countWhere(t, e,
		`SELECT COUNT(*) FROM sessions WHERE revoked_at IS NOT NULL AND account_id = ?`,
		bystander.AccountID.String()); n != 0 {
		t.Errorf("旁觀者名下不得出現撤銷標記，實際 %d 行", n)
	}
}

// TestBoundAccountsCannotBePurgedByStructure 軟刪除是唯一可用的處置，這件事要成立在庫上：
// 綁定留痕（guest_account_bindings）與綁定憑證（guest_bind_tickets）都以帳戶標識為外鍵，
// 所以一筆被引用的帳戶行根本無法被物理 DELETE——把它抹掉會立刻撞外鍵，
// 而不是留下一堆指向空標識的歷史。「不拿物理刪除當捷徑」因此不是自律，是形狀。
//
// 這一格也順帶钉住反向的那句話：软刪除寫得動（它是 UPDATE，不是 DELETE），
// 而寫動之後那一行仍被同一批外鍵引用著，歷史指得回來。
func TestBoundAccountsCannotBePurgedByStructure(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Delete.PurgeAdmin")
	guest := e.seed(t, seedInput{Login: "guest_purge_src", Display: "被綁走的旅人",
		Type: account.TypeGuest})
	host := e.seed(t, seedInput{Login: "Purge.Host", Display: "承接者"})
	ticket := mustIssue(t, e, admin, guest.ID, host.ID)
	if _, err := e.service.ConfirmGuestBind(ctx, identitytest.Account(t, host.ID), ticket,
		"req-purge-bind"); err != nil {
		t.Fatalf("綁定失敗：%v", err)
	}

	// 物理刪來源或目標都必須被外鍵擋住（順序也試兩邊：子表參照的是同一批父行）。
	for name, id := range map[string]idgen.ID{"綁定來源": guest.ID, "綁定目標": host.ID} {
		if _, err := e.db.SQL().ExecContext(ctx, "DELETE FROM accounts WHERE id = ?", id.String()); err == nil {
			t.Errorf("物理刪除%s 應被外鍵擋住，實際寫通了", name)
		} else if !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
			t.Errorf("物理刪除%s 的失敗原因應是外鍵，實際 %v", name, err)
		}
	}

	// 軟刪除寫得動，而且寫完之後留痕仍然指向同一個標識。
	if _, err := e.service.DeleteStandardAccount(ctx, admin, host.ID, "req-purge-del"); err != nil {
		t.Fatalf("軟刪除綁定目標失敗：%v", err)
	}
	var bindingTarget string
	if err := e.db.SQL().QueryRowContext(ctx,
		`SELECT target_account_id FROM guest_account_bindings`).Scan(&bindingTarget); err != nil {
		t.Fatalf("讀回綁定留痕失敗：%v", err)
	}
	if bindingTarget != host.ID.String() {
		t.Errorf("留痕必須仍指向同一個目標標識（不因刪除而搬移或清空），期望 %s，實際 %s",
			host.ID.String(), bindingTarget)
	}
	if status, _, _, at := deletedRow(t, e, host.ID); status != "deleted" || at == 0 {
		t.Errorf("目標的刪除形態異常：status=%s deletedAt=%d", status, at)
	}
}
