// managers_test.go 是「誰能管哪個活動」的證據：指派權限只在 Root、被指派者必須已是管理員、
// 名冊的可見範圍與活動一致，以及帳戶進入終態之後這一欄照樣仍列、可讀、拒寫。
package activity

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// assign 走一次指派，失敗即終止。
func (e *env) assign(t *testing.T, root identity.Principal, activityID, accountID idgen.ID) Activity {
	t.Helper()
	updated, err := e.service.AssignManager(context.Background(), root, activityID, accountID, "req-assign")
	if err != nil {
		t.Fatalf("指派 %s 管 %s 應成功：%v", accountID, activityID, err)
	}
	return updated
}

// dropGrant 物理拿掉一位帳戶的伺服器級授予（撤銷授予的通路本步尚未落地，
// 測試需要的是「授予不在的那一刻」這個事實，因此直寫倉儲做不到的那一條邊）。
func (e *env) dropGrant(t *testing.T, accountID idgen.ID) {
	t.Helper()
	if _, err := e.db.SQL().ExecContext(context.Background(),
		"DELETE FROM account_server_roles WHERE account_id = ?", accountID.String()); err != nil {
		t.Fatalf("撤下授予失敗：%v", err)
	}
}

// TestAssignIsWhatGrantsActivityAccess 驗收：指派是活動管理權的唯一來源——
// 一位原本管不著這個活動的管理員，在被指派之後立刻能讀能改。
func TestAssignIsWhatGrantsActivityAccess(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.admin(t, "Assign.Owner")
	late, lateAccount := e.admin(t, "Assign.Late")
	root := e.root(t)

	created := e.create(t, owner, "等人來管的場", "")

	// 指派前：他管不著（不可分辨的查無此活動）。
	if _, err := e.service.ActivityDetail(context.Background(), late, created.ID); !errors.Is(err, ErrActivityNotFound) {
		t.Fatalf("指派前另一位管理員讀不到該活動：%v", err)
	}
	updated := e.assign(t, root, created.ID, lateAccount.ID)
	if updated.ManagerCount != 2 {
		t.Errorf("指派後應有兩位管理人（建立者與新指派的），實際 %d", updated.ManagerCount)
	}

	// 指派後：讀與改都走得通，而且這是他第一次真正動到這個活動。
	if _, err := e.service.ActivityDetail(context.Background(), late, created.ID); err != nil {
		t.Fatalf("指派後應能讀取該活動：%v", err)
	}
	if _, err := e.service.UpdateActivityProfile(context.Background(), late, created.ID,
		"接手後改名", "描述", "等人來管的場", "", "req-late"); err != nil {
		t.Errorf("指派後應能編輯該活動：%v", err)
	}
	if got := e.countAuditRows(t, "activity.manager_assign", created.ID.String()); got != 1 {
		t.Errorf("成功的指派應留下一筆 activity.manager_assign，實際 %d 筆", got)
	}

	// 撤銷之後同樣的動作立刻回到「管不著」：指派清單是每次現讀，不是登入時凍結的快照。
	if _, err := e.service.RevokeManager(context.Background(), root, created.ID, lateAccount.ID, "req-revoke"); err != nil {
		t.Fatalf("撤銷指派應成功：%v", err)
	}
	if _, err := e.service.ActivityDetail(context.Background(), late, created.ID); !errors.Is(err, ErrActivityNotFound) {
		t.Errorf("撤銷後應立刻管不著這個活動，實際 %v", err)
	}
	if got := e.countAuditRows(t, "activity.manager_revoke", created.ID.String()); got != 1 {
		t.Errorf("成功的撤銷應留下一筆 activity.manager_revoke，實際 %d 筆", got)
	}
}

// TestAssignRejectsEveryIneligibleTarget 驗收：只有「此刻真的能用的管理員」才進得了指派表。
//
// 這些結論一律不寫入、不留審計，而且分成兩句話：
//   - 「查無此人」（不存在、訪戶、停用、待審批、沒有管理員授予）→ 換個目標；
//   - 「已被刪除終態」→ 別再對他下任何寫入令（與帳戶側各條通路口徑一致）。
func TestAssignRejectsEveryIneligibleTarget(t *testing.T) {
	e := newEnv(t)
	owner, _ := e.admin(t, "Elig.Owner")
	root := e.root(t)
	created := e.create(t, owner, "誰都能指派嗎", "")
	auditsBefore := e.countRows(t, "activity_audit")

	guest := e.seedAccount(t, "elig.guest", "訪戶甲", account.TypeGuest, account.StatusActive)
	disabled := e.seedAccount(t, "elig.stopped", "停用乙", account.TypeStandard, account.StatusDisabled)
	pending := e.seedAccount(t, "elig.pending", "待審丙", account.TypeStandard, account.StatusPending)
	plain := e.seedAccount(t, "elig.plain", "平民丁", account.TypeStandard, account.StatusActive)
	deleted := e.seedAccount(t, "elig.deleted", "已刪戊", account.TypeStandard, account.StatusActive)
	if _, err := e.accounts.MarkDeleted(context.Background(), e.db.SQL(),
		deleted.ID, deleted.DisplayName); err != nil {
		t.Fatalf("讓帳戶進入刪除終態失敗：%v", err)
	}

	cases := []struct {
		name    string
		target  idgen.ID
		wantErr error
	}{
		{"從未存在的標識", identitytest.NewID(t), ErrManagerNotFound},
		{"零值標識", idgen.Nil, ErrManagerNotFound},
		{"訪戶帳戶", guest.ID, ErrManagerNotFound},
		{"已停用的帳戶", disabled.ID, ErrManagerNotFound},
		{"待審批的申請人", pending.ID, ErrManagerNotFound},
		{"沒有管理員授予的普通帳戶", plain.ID, ErrManagerNotFound},
		{"已被軟刪除的管理員", deleted.ID, ErrManagerDeleted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.service.AssignManager(context.Background(), root, created.ID, tc.target, "req-elig")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("應回報 %v，實際 %v", tc.wantErr, err)
			}
			if got := e.countRows(t, "activity_audit"); got != auditsBefore {
				t.Fatalf("被拒的指派不該記審計，前 %d 筆／實際 %d 筆", auditsBefore, got)
			}
		})
	}
	// 唯一進得了指派表的是那位真的持有授予的活躍管理員。
	eligible, eligibleAccount := e.admin(t, "Elig.Ready")
	e.assign(t, root, created.ID, eligibleAccount.ID)
	if _, err := e.service.ActivityDetail(context.Background(), eligible, created.ID); err != nil {
		t.Errorf("合格且已指派的帳戶應能讀取活動：%v", err)
	}
	// 查無此活動的標識一律走不可分辨那一句話，而不是另一套「指派目標不存在」。
	if _, err := e.service.AssignManager(context.Background(), root, identitytest.NewID(t),
		eligibleAccount.ID, "req-ghost"); !errors.Is(err, ErrActivityNotFound) {
		t.Errorf("對不存在活動做指派應回報查無此活動，實際 %v", err)
	}
}

// TestOnlyRootMayChangeTheRoster 驗收：活動管理人自己不能加人也不能刪人。
//
// 這件事必須是程式碼層的閘而不是介面層的自律：若現任管理人能自行擴散權限，
// 一個被駭的管理員帳戶就能把整個活動交給別人，而今日沒有任何獨立的准入口能核實那一步。
func TestOnlyRootMayChangeTheRoster(t *testing.T) {
	e := newEnv(t)
	owner, ownerAccount := e.admin(t, "Roster.Owner")
	other, otherAccount := e.admin(t, "Roster.Other")
	created := e.create(t, owner, "名冊歸 Root", "")

	if _, err := e.service.AssignManager(context.Background(), owner, created.ID,
		otherAccount.ID, "req-self-assign"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("管理人自行加人應回報權限不足，實際 %v", err)
	}
	if _, err := e.service.RevokeManager(context.Background(), owner, created.ID,
		ownerAccount.ID, "req-self-revoke"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("管理人自行刪人應回報權限不足，實際 %v", err)
	}
	// 他管不著別人的名冊，也寫不進自己的名冊：兩句都與「能不能管這個活動」無關。
	if _, err := e.service.AssignManager(context.Background(), other, created.ID,
		ownerAccount.ID, "req-stranger"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("非 Root 的指派意圖都該先撞在 NeedRoot 上，實際 %v", err)
	}
	if got := e.countRows(t, "activity_manager_grants"); got != 1 {
		t.Errorf("三次被拒的寫入不該多出行，實際 %d 行（只有自動指派那一行）", got)
	}
}

// TestDuplicateAssignAndUnknownRevokeRefuseToLie 驗收：重複指派與查無此人的撤銷都不謊報成功。
//
// 把「什麼都沒發生」說成「又指派了一次」或「已撤銷」，會在審計裡記下一件沒發生過的事——
// 與帳戶側的停用／審批那兩條同一取向。
func TestDuplicateAssignAndUnknownRevokeRefuseToLie(t *testing.T) {
	e := newEnv(t)
	owner, ownerAccount := e.admin(t, "Dup.Owner")
	root := e.root(t)
	created := e.create(t, owner, "重複指派取證", "")

	if _, err := e.service.AssignManager(context.Background(), root, created.ID,
		ownerAccount.ID, "req-dup"); !errors.Is(err, ErrManagerDuplicate) {
		t.Errorf("重複指派應回報已存在，實際 %v", err)
	}
	if _, err := e.service.RevokeManager(context.Background(), root, created.ID,
		identitytest.NewID(t), "req-absent"); !errors.Is(err, ErrManagerNotFound) {
		t.Errorf("撤銷不存在的指派應回報查無此人，實際 %v", err)
	}
	auditsBefore := e.countRows(t, "activity_audit")
	if _, err := e.service.RevokeManager(context.Background(), root, created.ID,
		ownerAccount.ID, "req-ok"); err != nil {
		t.Fatalf("撤銷確實存在的指派應成功：%v", err)
	}
	if got := e.countRows(t, "activity_audit"); got != auditsBefore+1 {
		t.Errorf("成功的撤銷應留下一筆審計，前 %d 筆／實際 %d 筆", auditsBefore, got)
	}
	// 撤掉最後一位管理人之後，帳戶側沒有人能進這個活動，而 Root 仍然可以（再指派一次即可）。
	if _, err := e.service.ActivityDetail(context.Background(), owner, created.ID); !errors.Is(err, ErrActivityNotFound) {
		t.Errorf("撤銷最後一行指派後，原管理人應立刻失去可見範圍，實際 %v", err)
	}
	e.assign(t, root, created.ID, ownerAccount.ID)
	if _, err := e.service.ActivityDetail(context.Background(), owner, created.ID); err != nil {
		t.Errorf("Root 重新指派後應恢復可見：%v", err)
	}
}

// TestRosterScopesAndTerminalRowsStayListed 驗收：名冊的讀法跟著活動作用域走，
// 而指向已進入終態帳戶的那一行仍列、仍可讀（軟參照的歷史口徑與審計表一致）。
func TestRosterScopesAndTerminalRowsStayListed(t *testing.T) {
	e := newEnv(t)
	owner, ownerAccount := e.admin(t, "RosterView.Owner")
	stranger, _ := e.admin(t, "RosterView.Stranger")
	created := e.create(t, owner, "名冊的讀法", "")

	roster, err := e.service.ManagerRoster(context.Background(), owner, created.ID)
	if err != nil {
		t.Fatalf("管理人讀自己的名冊應成功：%v", err)
	}
	if len(roster) != 1 || roster[0].AccountID != ownerAccount.ID ||
		roster[0].AccountStatus != account.StatusActive || roster[0].DisplayName == "" {
		t.Fatalf("名冊應列出建立者本人與他的現值，實際 %+v", roster)
	}
	if _, err := e.service.ManagerRoster(context.Background(), stranger, created.ID); !errors.Is(err, ErrActivityNotFound) {
		t.Errorf("別人讀不到這個活動的名冊，應不可分辨，實際 %v", err)
	}
	if _, err := e.service.ManagerRoster(context.Background(), e.root(t), created.ID); err != nil {
		t.Errorf("Root 讀任何活動的名冊都該走得通：%v", err)
	}

	// 把建立者送進刪除終態：指派行不搬不刪，名冊照樣列得出他，狀態如實標為 deleted。
	if _, err := e.accounts.MarkDeleted(context.Background(), e.db.SQL(),
		ownerAccount.ID, ownerAccount.DisplayName); err != nil {
		t.Fatalf("讓管理人進入刪除終態失敗：%v", err)
	}
	after, err := e.service.ManagerRoster(context.Background(), e.root(t), created.ID)
	if err != nil {
		t.Fatalf("終態之後名冊仍應可讀：%v", err)
	}
	if len(after) != 1 || after[0].AccountStatus != account.StatusDeleted {
		t.Errorf("終態行仍列且狀態如實，實際 %+v", after)
	}
	// 他已不可能再持有管理員資格（授予通路會先擋），因此既讀不到也不該被再指派。
	if _, err := e.service.AssignManager(context.Background(), e.root(t), created.ID,
		ownerAccount.ID, "req-redo"); !errors.Is(err, ErrManagerDeleted) {
		t.Errorf("重新指派終態帳戶應回報已被刪除，實際 %v", err)
	}
}

// TestLosingServerAdminRemovesActivityAccessEvenWithGrantRow 驗收：兩道閘真的都要過。
//
// 指派行還在，但這個帳戶已經不是伺服器級管理員——他立刻管不著任何活動。
// 這句話固定的是「活動管理權是管理員資格加上指派」，不是「指派表寫過一次就永久有效」，
// 也不是拿全域管理員檢查冒充活動隔離（反方向那一半由 TestAssignIsWhatGrantsActivityAccess 固定）。
func TestLosingServerAdminRemovesActivityAccessEvenWithGrantRow(t *testing.T) {
	e := newEnv(t)
	owner, ownerAccount := e.admin(t, "Dual.Owner")
	created := e.create(t, owner, "兩道閘都要過", "")

	e.dropGrant(t, ownerAccount.ID)
	// 主體每請求現讀：傳輸層拿的是「此刻庫裡的授予」，因此撤下授予之後換出來的是
	// 一位沒有伺服器級權限的帳戶（這裡用同一個標識重新構造主體，就是那一次現讀的結果）。
	stripped := identitytest.Account(t, ownerAccount.ID)
	if _, err := e.service.ActivityDetail(context.Background(), stripped, created.ID); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("失去伺服器級管理員資格後應回報權限不足，實際 %v", err)
	}
	// 指派行仍然在原處（撤銷授予不等於撤銷指派，兩者各有其通路與審計）。
	if got := e.countRows(t, "activity_manager_grants"); got != 1 {
		t.Errorf("撤下授予不該動到指派行，實際 %d 行", got)
	}
	// Root 不受指派約束，仍然能管這個活動——這是身份層既定的規則，不是這裡漏了閘。
	if _, err := e.service.UpdateActivityProfile(context.Background(), e.root(t), created.ID,
		"Root 仍可改", "", "兩道閘都要過", "", "req-root"); err != nil {
		t.Errorf("Root 的跨活動維運不應被指派表擋下：%v", err)
	}
}
