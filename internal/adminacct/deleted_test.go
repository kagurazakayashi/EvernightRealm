// deleted_test.go 是「Root 軟刪除管理員」在用例層的定向證據。
//
// 取證的重心不是「按鈕按下去了」，而是四句話各自落成資料庫裡的事實：
//   - 刪除之後他既登不進來、舊會話也立刻作廢（停登與撤銷同交易）；
//   - 刪除是終態：重複刪除寫不出任何一行，其餘三條寫入通路也一律拒絕這個目標；
//   - 歷史不被破壞：授予行、會話行與既有審計都還在，且仍能指回同一個標識；
//   - 匿名化只動「活的投影」那一個欄位，且不越權替後續的清庫步驟做決定。
package adminacct

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// TestDeleteAdminStopsSignInRevokesSessionsAndAudits 刪除落地的三件效果一起生效。
func TestDeleteAdminStopsSignInRevokesSessionsAndAudits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "drop.one")
	secrets := newAdminSessions(t, e, created.AccountID, 2)

	result, err := e.service.DeleteAdmin(ctx, root, created.AccountID, "req-drop-1")
	if err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}
	if result.RevokedSessions != 2 {
		t.Errorf("刪除應撤銷目標全部 2 份會話，實際 %d", result.RevokedSessions)
	}
	if result.Profile.Status != account.StatusDeleted || result.Profile.DeletedAt.IsZero() {
		t.Errorf("回應應是刪除後的現值（deleted 帶時刻），實際 %+v", result.Profile)
	}
	if !result.Profile.DeletedAt.Equal(e.clock.Now()) {
		t.Errorf("刪除時刻必須取自注入時鐘，實際 %v", result.Profile.DeletedAt)
	}
	for i, secret := range secrets {
		if _, err := e.sessions.Verify(ctx, e.db.SQL(), secret); !errors.Is(err, session.ErrRevoked) {
			t.Errorf("第 %d 份刪除前會話應按已撤銷被拒，實際 %v", i+1, err)
		}
	}

	// 新登入被拒：走的是既有「非 active 即拒」那道閘，與口令對錯收斂成同一句。
	authService := e.newAuthService(t)
	if _, err := authService.LoginAccount(ctx, "drop.one", testInitialPassword,
		"req-drop-login", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("已刪除帳戶不應還能登入，實際 %v", err)
	}

	// 落庫形態：終態＋時刻，而承擔歷史身份的欄位逐字不動。
	var (
		status, loginName, loginKey, displayName string
		deletedAt                                int64
	)
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT status, login_name, login_name_key, display_name, deleted_at
		FROM accounts WHERE id = ?`, created.AccountID.String()).
		Scan(&status, &loginName, &loginKey, &displayName, &deletedAt); err != nil {
		t.Fatalf("讀回刪除後的帳戶失敗：%v", err)
	}
	if status != "deleted" {
		t.Errorf("落庫狀態應是 deleted，實際 %q", status)
	}
	if loginName != "drop.one" || loginKey != "drop.one" {
		t.Errorf("登入名與鍵必須保留（因此不可被復用），實際 %q/%q", loginName, loginKey)
	}
	if !strings.HasPrefix(displayName, "DEL_20261002_") {
		t.Errorf("顯示名應是匿名化佔位值，實際 %q", displayName)
	}
	if got := timeutil.FromMillis(deletedAt); !got.Equal(result.Profile.DeletedAt) {
		t.Errorf("落庫刪除時刻應與回應同源，實際 %v vs %v", got, result.Profile.DeletedAt)
	}

	// 審計：刪除前身份快照落地，且不含任何憑據材料。
	var changes, reason string
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT changes_json, reason FROM root_audit WHERE action = 'admin.delete'").
		Scan(&changes, &reason); err != nil {
		t.Fatalf("讀回刪除審計失敗：%v", err)
	}
	for _, want := range []string{"login_name", "drop.one", "測試管理員", "deleted", "revoked_sessions"} {
		if !strings.Contains(changes, want) {
			t.Errorf("刪除審計的快照應含 %q，實際 %s", want, changes)
		}
	}
	for _, forbidden := range []string{testInitialPassword, testNewPassword, "argon2id",
		"password_hash", "token_hash", "deleted_at_hash"} {
		if strings.Contains(changes, forbidden) || strings.Contains(reason, forbidden) {
			t.Errorf("刪除審計不得含 %q 的影子", forbidden)
		}
	}
	if logs := e.logs.String(); strings.Contains(logs, testInitialPassword) {
		t.Error("執行日誌不得含口令明文")
	}
}

// TestDeleteAdminAnonymizesProjectionButNotHistory 匿名化只動帳戶行上的顯示名：
// 目錄與詳情從此顯示佔位值，而先前那筆 admin.create 審計裡的名字照舊查得到——
// 只追加的表不歸本步管，這一條斷言釘的是「沒有順手去改歷史」。
func TestDeleteAdminAnonymizesProjectionButNotHistory(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "drop.names")

	if _, err := e.service.DeleteAdmin(ctx, root, created.AccountID, "req-drop-names"); err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}

	var createChanges string
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT changes_json FROM root_audit WHERE action = 'admin.create'").Scan(&createChanges); err != nil {
		t.Fatalf("讀回開設審計失敗：%v", err)
	}
	if !strings.Contains(createChanges, created.DisplayName) {
		t.Fatalf("前置條件跑掉了：開設審計應含原顯示名，實際 %s", createChanges)
	}

	directory, err := e.service.Directory(ctx, root, DirectoryQuery{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("列舉目錄失敗：%v", err)
	}
	if len(directory.Rows) != 1 {
		t.Fatalf("目錄應仍列出那唯一一位管理員，實際 %d 行", len(directory.Rows))
	}
	row := directory.Rows[0]
	if row.Status != "deleted" || row.DeletedAt.IsZero() {
		t.Errorf("目錄行應標出刪除終態與時刻，實際 %q/%v", row.Status, row.DeletedAt)
	}
	if row.DisplayName == created.DisplayName || !strings.HasPrefix(row.DisplayName, "DEL_") {
		t.Errorf("目錄的活投影應顯示佔位值，實際 %q", row.DisplayName)
	}

	detail, err := e.service.AdminProfile(ctx, root, created.AccountID)
	if err != nil {
		t.Fatalf("已刪除目標的詳情仍應讀得到：%v", err)
	}
	if detail.Status != account.StatusDeleted || detail.DeletedAt.IsZero() {
		t.Errorf("詳情應如實回報刪除態，實際 %+v", detail)
	}
	if len(detail.Roles) != 1 || detail.Roles[0] != identity.RoleServerAdmin {
		t.Errorf("詳情仍應核實他持有 server_admin（成員資格本就是那段歷史的一部分），實際 %v", detail.Roles)
	}

	// 篩選三個現存取值各自只含自己的那一側；deleted 不靠界面排、也不被 all 藏起來。
	for filter, wantRows := range map[string]int{"all": 1, "deleted": 1, "active": 0, "disabled": 0} {
		page, err := e.service.Directory(ctx, root,
			DirectoryQuery{Page: 1, PageSize: 20, StatusFilter: filter})
		if err != nil {
			t.Fatalf("篩選 %s 失敗：%v", filter, err)
		}
		if len(page.Rows) != wantRows || page.Total != int64(wantRows) {
			t.Errorf("篩選 %s 應得 %d 行，實際 %d 行（total %d）",
				filter, wantRows, len(page.Rows), page.Total)
		}
	}
	if _, err := e.service.Directory(ctx, root,
		DirectoryQuery{Page: 1, PageSize: 20, StatusFilter: "archived"}); !errors.Is(err, ErrInvalidStatusFilter) {
		t.Errorf("篩選表外取值應回結論錯誤，實際 %v", err)
	}
}

// TestDeleteAdminTwiceRefusesSecondAndWritesNothing 第二次刪除不是「又刪成功一次」：
// 它寫不出任何一行，因此既不撤會話、也不留第二筆審計。
func TestDeleteAdminTwiceRefusesSecondAndWritesNothing(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "drop.twice")
	newAdminSessions(t, e, created.AccountID, 1)

	first, err := e.service.DeleteAdmin(ctx, root, created.AccountID, "req-drop-first")
	if err != nil {
		t.Fatalf("首次刪除失敗：%v", err)
	}
	if first.RevokedSessions != 1 {
		t.Errorf("前置條件跑掉了：首次刪除應撤 1 份會話，實際 %d", first.RevokedSessions)
	}
	before := adminRowText(t, e, created.AccountID.String())

	if _, err := e.service.DeleteAdmin(ctx, root, created.AccountID, "req-drop-second"); !errors.Is(err, ErrAdminDeleted) {
		t.Fatalf("第二次刪除應回 ErrAdminDeleted，實際 %v", err)
	}
	if after := adminRowText(t, e, created.AccountID.String()); after != before {
		t.Errorf("被拒的重複刪除不得動現值：\n%s\n%s", before, after)
	}
	var deletions int
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.delete'").Scan(&deletions); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if deletions != 1 {
		t.Errorf("被拒的重複刪除不得再加筆審計，實際 %d 筆", deletions)
	}
}

// TestDeletedAdminRefusesEveryWriteUseCase 三條既有寫入通路對刪除目標一律拒絕，
// 而且各自都「一個字都不寫、一筆審計都不留」。
//
// 其中最要緊的是恢復登入那條：把已刪除的人「恢復」等同於繞過刪除的終態語意，
// 它必須在判定入口就被拒，而不是靠 CAS 碰巧寫不中。
func TestDeletedAdminRefusesEveryWriteUseCase(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "drop.writes")
	if _, err := e.service.DeleteAdmin(ctx, root, created.AccountID, "req-drop-writes"); err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}
	before := adminRowText(t, e, created.AccountID.String())

	cases := map[string]func() error{
		"編輯顯示名": func() error {
			_, err := e.service.UpdateAdminProfile(ctx, root, created.AccountID,
				"想改名", "想改名", "req-drop-edit")
			return err
		},
		"恢復登入": func() error {
			_, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
				StatusChangeInput{NewStatus: account.StatusActive, ExpectedStatus: account.StatusDisabled},
				"req-drop-enable")
			return err
		},
		"再次停用": func() error {
			_, err := e.service.UpdateAdminStatus(ctx, root, created.AccountID,
				StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
				"req-drop-disable")
			return err
		},
		"重置憑據": func() error {
			_, err := e.service.ResetAdminPassword(ctx, root, created.AccountID,
				testNewPassword, "req-drop-reset")
			return err
		},
	}
	for name, run := range cases {
		if err := run(); !errors.Is(err, ErrAdminDeleted) {
			t.Errorf("%s：對已刪除目標應回 ErrAdminDeleted，實際 %v", name, err)
		}
	}
	if after := adminRowText(t, e, created.AccountID.String()); after != before {
		t.Errorf("四條被拒的寫入之後現值必須逐字不動：\n%s\n%s", before, after)
	}
	var extra int
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM root_audit WHERE action IN ('admin.profile_update','admin.enable','admin.disable','admin.password_reset')").
		Scan(&extra); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if extra != 0 {
		t.Errorf("被拒的寫入不得留下任何審計，實際 %d 筆", extra)
	}
}

// TestDeleteAdminAuthorizationMatrix 刪除只屬 Root：其他主體當場被拒且零寫入。
func TestDeleteAdminAuthorizationMatrix(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "drop.victim")
	before := adminRowText(t, e, created.AccountID.String())

	// 一位持有 server_admin 的「同級」與一位沒有角色的帳戶：兩者都不該能刪人。
	peer := e.mustCreate(t, root, "drop.peer")
	subjects := map[string]struct {
		principal identity.Principal
		want      error
	}{
		"普通帳戶":  {identitytest.Account(t, identitytest.NewID(t)), identity.ErrPermissionDenied},
		"同級管理員": {identitytest.Account(t, peer.AccountID, identitytest.ServerAdmin()), identity.ErrPermissionDenied},
		// 匿名主體拿到的是「沒通過認證」那一句，而不是「沒有這個權限」：兩句話對介面
		// 是兩個處置（一個該重新登入，一個重試也不會變）。協定層在憑據解析那一步就攔下，
		// 這裡記的是用例層自己的口徑，不順手把兩者混成一句。
		"匿名":   {identitytest.Anonymous(t), identity.ErrNotAuthenticated},
		"係統主體": {identitytest.System(t, identity.OriginCLI), identity.ErrPermissionDenied},
	}
	for name, subject := range subjects {
		if _, err := e.service.DeleteAdmin(ctx, subject.principal, created.AccountID,
			"req-drop-auth"); !errors.Is(err, subject.want) {
			t.Errorf("%s 刪除他人應回 %v，實際 %v", name, subject.want, err)
		}
	}
	if after := adminRowText(t, e, created.AccountID.String()); after != before {
		t.Error("被拒的越權刪除不得動目標")
	}
	var deletions int
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.delete'").Scan(&deletions); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if deletions != 0 {
		t.Errorf("被拒的刪除不得寫入 Root 審計，實際 %d 筆", deletions)
	}
}

// TestDeleteAdminTargetMatrix 不是目錄成員的標識全部同形回查無：幽靈、未授予帳戶、
// 零值、已被物理移除的帳戶，以及 Root 的保留標識——
// 「把配置裡的 Root 刪掉」在這條通路上沒有一個可填的格子。
func TestDeleteAdminTargetMatrix(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	hash, err := credential.Hash(testInitialPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	plain, err := e.service.accounts.Create(ctx, e.db.SQL(), account.NewInput{
		LoginName: "drop.ungranted", DisplayName: "普通帳戶", PasswordHash: hash,
		Type: account.TypeStandard, Status: account.StatusActive,
	})
	if err != nil {
		t.Fatalf("種入普通帳戶失敗：%v", err)
	}
	gone, err := e.service.accounts.Create(ctx, e.db.SQL(), account.NewInput{
		LoginName: "drop.gone", DisplayName: "已被清庫", PasswordHash: hash,
		Type: account.TypeStandard, Status: account.StatusActive,
	})
	if err != nil {
		t.Fatalf("種入待移除帳戶失敗：%v", err)
	}
	if _, err := e.db.SQL().ExecContext(ctx,
		"DELETE FROM accounts WHERE id = ?", gone.ID.String()); err != nil {
		t.Fatalf("物理移除測試帳戶失敗：%v", err)
	}
	reserved, err := identity.RootSubjectID()
	if err != nil {
		t.Fatalf("取 Root 保留標識失敗：%v", err)
	}

	targets := map[string]idgen.ID{
		"幽靈標識":      identitytest.NewID(t),
		"未授予帳戶":     plain.ID,
		"零值標識":      {},
		"已被物理移除":    gone.ID,
		"Root 保留標識": reserved,
	}
	for name, id := range targets {
		if _, err := e.service.DeleteAdmin(ctx, root, id, "req-drop-target"); !errors.Is(err, ErrAdminNotFound) {
			t.Errorf("%s 應與查無同形（ErrAdminNotFound），實際 %v", name, err)
		}
	}
	var deletions int
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.delete'").Scan(&deletions); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if deletions != 0 {
		t.Errorf("非目錄成員的目標不應產生任何刪除審計，實際 %d 筆", deletions)
	}
}

// TestDeleteAdminRollsBackWholeTransactionWhenAuditFails 審計寫不進去時整筆回滾：
// 「狀態改了、會話卻還活著」與「人已刪除而 Root 審計查無此事」都不該存在。
func TestDeleteAdminRollsBackWholeTransactionWhenAuditFails(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "drop.rollback")
	secrets := newAdminSessions(t, e, created.AccountID, 1)

	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("破壞審計表失敗：%v", err)
	}
	if _, err := e.service.DeleteAdmin(ctx, root, created.AccountID, "req-drop-rollback"); err == nil {
		t.Fatal("審計落地失敗時刪除必須整體回滾")
	}

	var (
		status    string
		deletedAt int64
	)
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT status, COALESCE(deleted_at, 0) FROM accounts WHERE id = ?", created.AccountID.String()).
		Scan(&status, &deletedAt); err != nil {
		t.Fatalf("讀回狀態失敗：%v", err)
	}
	if status != "active" || deletedAt != 0 {
		t.Errorf("回滾後帳戶應仍是 active 且沒有刪除時刻，實際 %s/%d", status, deletedAt)
	}
	if _, err := e.sessions.Verify(ctx, e.db.SQL(), secrets[0]); err != nil {
		t.Errorf("回滾後既有會話應仍可用（撤銷跟著回滾）：%v", err)
	}
}

// TestDeleteAdminContextCancelledWritesNothing 已取消的上下文裡一個字都不落。
func TestDeleteAdminContextCancelledWritesNothing(t *testing.T) {
	e := newEnv(t)
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "drop.cancel")
	before := adminRowText(t, e, created.AccountID.String())

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.service.DeleteAdmin(cancelled, root, created.AccountID, "req-drop-cancel"); err == nil {
		t.Fatal("已取消的請求應失敗")
	}
	if after := adminRowText(t, e, created.AccountID.String()); after != before {
		t.Errorf("取消後現值必須逐字不動：\n%s\n%s", before, after)
	}
	var deletions int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.delete'").Scan(&deletions); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if deletions != 0 {
		t.Errorf("取消的刪除不應留下審計，實際 %d 筆", deletions)
	}
}

// TestDeleteAdminKeepsHistoricalAuditsReadableAndUncascadable 歷史審計在刪除之後
// 仍舊查得到，而且沒有人能把它們的對象指向虛空。
//
// 這一條是「不級聯、不把原操作歸到 Root 名下」那兩句禁止事項的正面證據：
// 做得到靠的不是程式碼裡少寫一句 DELETE，而是資料庫根本沒給那兩種寫法留位置。
func TestDeleteAdminKeepsHistoricalAuditsReadableAndUncascadable(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "drop.history")

	if _, err := e.service.DeleteAdmin(ctx, root, created.AccountID, "req-drop-history"); err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}

	page, err := e.service.audits.Query(ctx, e.db.SQL(),
		audit.Viewer{Kind: audit.ActorRoot},
		audit.Filter{Scope: audit.ScopeRoot, Target: &audit.Target{Kind: "account", ID: created.AccountID.String()}})
	if err != nil {
		t.Fatalf("以 Root 視角查詢該帳戶的審計失敗：%v", err)
	}
	if len(page.Records) < 2 {
		t.Fatalf("刪除後該帳戶的審計（開設＋刪除）應至少 2 筆可查，實際 %d 筆", len(page.Records))
	}
	actions := make([]string, 0, len(page.Records))
	for _, rec := range page.Records {
		actions = append(actions, rec.Action)
		if rec.Target.ID != created.AccountID.String() {
			t.Errorf("審計對象被改寫：%s", rec.Target.ID)
		}
	}
	joined := strings.Join(actions, ",")
	if !strings.Contains(joined, "admin.create") || !strings.Contains(joined, "admin.delete") {
		t.Errorf("查得的動作應同時含開設與刪除，實際 %s", joined)
	}

	// 兩種「把歷史指到虛空」的寫法都該被資料庫擋下。
	if _, err := e.db.SQL().ExecContext(ctx,
		"UPDATE root_audit SET actor_id = NULL WHERE target_id = ?", created.AccountID.String()); err == nil {
		t.Error("把歷史操作者設為 NULL 竟能成功（只追加存儲被寫動了）")
	}
	if _, err := e.db.SQL().ExecContext(ctx,
		"DELETE FROM root_audit WHERE target_id = ?", created.AccountID.String()); err == nil {
		t.Error("級聯刪掉該帳戶的歷史審計竟能成功（只追加存儲被寫動了）")
	}
	// 授予行同樣留下：目錄成員資格是他這段歷史的一部分，不是可順手清掉的殘骸。
	var grants int
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM account_server_roles WHERE account_id = ?", created.AccountID.String()).Scan(&grants); err != nil {
		t.Fatalf("計數授予失敗：%v", err)
	}
	if grants != 1 {
		t.Errorf("刪除不得撤走授予行（那等於把他的歷史身分一起清掉），實際 %d 行", grants)
	}
}

// TestDeletedAdminCannotBeIssuedNewSessions 刪除之後以該標識新簽發會話不可能成立：
// 「已刪的人還在產生新事實」這條路在主體構造那道閘就被關掉。
//
// 這同時是尚未開發的帳本／聊天的結構邊界——它們屆時引用的仍是同一個穩定標識，
// 而那個標識此刻已經不可能再換出任何可信主體。
func TestDeletedAdminCannotBeIssuedNewSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	created := e.mustCreate(t, root, "drop.newsession")
	if _, err := e.service.DeleteAdmin(ctx, root, created.AccountID, "req-drop-newsession"); err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}

	principal := identitytest.Account(t, created.AccountID, identitytest.ServerAdmin())
	if _, _, err := e.sessions.Create(ctx, e.db.SQL(), principal); err == nil {
		t.Error("已刪除帳戶不應能被簽發新會話")
	} else if !errors.Is(err, session.ErrSubjectUnavailable) && !errors.Is(err, session.ErrInvalidSubject) {
		t.Errorf("簽發失敗的結論應是可判別的主體不可用，實際 %v", err)
	}
	// 資料庫層也留得住新參照（父行還在）：未來的分錄與訊息仍能指回每一個人。
	now := e.clock.Now()
	if _, err := e.db.SQL().ExecContext(ctx, `INSERT INTO sessions
			(id, device_id, token_hash, subject_kind, account_id, created_at, last_active_at, expires_at)
			VALUES (?, ?, ?, 'account', ?, ?, ?, ?)`,
		identitytest.NewID(t).String(), identitytest.NewID(t).String(), strings.Repeat("c", 64),
		created.AccountID.String(),
		timeutil.ToMillis(now), timeutil.ToMillis(now),
		timeutil.ToMillis(now.Add(time.Hour))); err != nil {
		t.Errorf("刪除後的帳戶標識仍應可被新參照指向（行保留是歷史可解釋的前提）：%v", err)
	}
}

// adminRowText 把帳戶行的全部相關欄位讀成一段可比對的文字（用於「被拒的寫入不動現值」）。
func adminRowText(t *testing.T, e *env, accountID string) string {
	t.Helper()
	var row string
	if err := e.db.SQL().QueryRowContext(context.Background(), `SELECT
			login_name || '|' || login_name_key || '|' || display_name || '|' || status || '|' ||
			account_type || '|' || must_change_password || '|' ||
			COALESCE(last_login_at, 0) || '|' || COALESCE(disabled_at, 0) || '|' || COALESCE(deleted_at, 0) || '|' ||
			COALESCE(password_hash, '')
		FROM accounts WHERE id = ?`, accountID).Scan(&row); err != nil {
		t.Fatalf("讀回帳戶行失敗：%v", err)
	}
	return row
}
