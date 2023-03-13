// status_test.go 是活動生命週期的證據：四條合法路徑各走一遍、三種拒寫各有各的句子、
// 寫入門禁留給後續模組的判定如實分檔，以及「審計寫不進去時活動那一行也不留」。
package activity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// transition 走一次狀態轉換，失敗即終止。
func (e *env) transition(t *testing.T, principal identity.Principal,
	activityID idgen.ID, target Status) Activity {
	t.Helper()
	updated, err := e.service.Transition(context.Background(), principal, activityID, target, "req-transition")
	if err != nil {
		t.Fatalf("轉換活動 %s 到 %s 應成功：%v", activityID, target, err)
	}
	return updated
}

// TestLegalTransitionPath 驗收：draft→active→closed→active→archived 全程走得通，
// 而 archived_at 只在最後那一跳出現（成對規則由遷移 0012 的 CHECK 兜底，這裡驗的是通路本身）。
func TestLegalTransitionPath(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Path.Admin")
	created := e.create(t, principal, "一場活動", "")

	opened := e.transition(t, principal, created.ID, StatusActive)
	if opened.Status != StatusActive || !opened.ArchivedAt.IsZero() {
		t.Errorf("開放後應是 active 且沒有歸檔時刻，實際 %s／%v", opened.Status, opened.ArchivedAt)
	}
	stopped := e.transition(t, principal, created.ID, StatusClosed)
	if stopped.Status != StatusClosed || !stopped.ArchivedAt.IsZero() {
		t.Errorf("停止後應是 closed 且沒有歸檔時刻，實際 %s／%v", stopped.Status, stopped.ArchivedAt)
	}
	// 停止可逆（用戶批准於本步）：與帳戶「停用／恢復」同一取向，歷史一概保留。
	reopened := e.transition(t, principal, created.ID, StatusActive)
	if reopened.Status != StatusActive {
		t.Errorf("停止後應能重新開放，實際 %s", reopened.Status)
	}

	e.clock.Advance(time.Hour)
	archived := e.transition(t, principal, created.ID, StatusArchived)
	if archived.Status != StatusArchived {
		t.Fatalf("開放後應能歸檔，實際 %s", archived.Status)
	}
	if archived.ArchivedAt != testBase.Add(time.Hour) {
		t.Errorf("歸檔時刻必須取自注入時鐘，實際 %v", archived.ArchivedAt)
	}
	f := e.facts(t, archived.ID)
	if !f.archivedAt.Valid || f.archivedAt.Int64 == 0 {
		t.Errorf("歸檔那一刻必須落庫（狀態與時刻同生同滅），實際 NULL")
	}

	// 四次成功轉換（open、close、reopen、archive）各留一筆審計，而且都帶著這個活動標識。
	if got := e.countAuditRows(t, "activity.status_change", archived.ID.String()); got != 4 {
		t.Errorf("四次轉換應有四筆 activity.status_change，實際 %d 筆", got)
	}
}

// TestIllegalTransitionsEachSayTheirOwnThing 驗收：三種拒絕各有各的句子與處置。
func TestIllegalTransitionsEachSayTheirOwnThing(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Illegal.Admin")
	draft := e.create(t, principal, "草稿場", "")

	// 路徑不存在：草稿沒有「停止」這條出口（要停也得先開放過）。
	if _, err := e.service.Transition(context.Background(), principal, draft.ID,
		StatusClosed, "req-1"); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("draft→closed 應回報非法路徑，實際 %v", err)
	}
	// 草稿不能退回：draft 只能由建立那一跳產生。
	opened := e.transition(t, principal, draft.ID, StatusActive)
	if _, err := e.service.Transition(context.Background(), principal, opened.ID,
		StatusDraft, "req-2"); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("active→draft 應回報非法路徑（那等於偽造「這件事還沒開始」），實際 %v", err)
	}
	// 同態重複：現值已等於目標值，沒有可發生的物件，也不謊報成功。
	if _, err := e.service.Transition(context.Background(), principal, opened.ID,
		StatusActive, "req-3"); !errors.Is(err, ErrStatusConflict) {
		t.Errorf("重複開放應回報狀態衝突，實際 %v", err)
	}
	if f := e.facts(t, opened.ID); f.status != string(StatusActive) {
		t.Errorf("被拒的轉換動了狀態：實際 %q", f.status)
	}
	if got := e.countAuditRows(t, "activity.status_change", opened.ID.String()); got != 1 {
		t.Errorf("三次被拒的轉換不該多記審計，實際 %d 筆（只許開放那一筆）", got)
	}

	// 未批准的目標取值（含 draft 之外的集合外值）當場點名，不進交易。
	if _, err := e.service.Transition(context.Background(), principal, opened.ID,
		Status("paused"), "req-4"); !errors.Is(err, ErrInvalidStatus) {
		t.Errorf("集合外的目標狀態應回報取值不合法，實際 %v", err)
	}

	// 歸檔是終態：任何出口都先撞上那一句「已經結束」，而不是「路徑不存在」。
	archived := e.transition(t, principal, opened.ID, StatusArchived)
	for _, target := range []Status{StatusDraft, StatusActive, StatusClosed, StatusArchived} {
		_, err := e.service.Transition(context.Background(), principal, archived.ID, target, "req-5")
		if !errors.Is(err, ErrArchived) {
			t.Errorf("archived→%s 應回報終態拒寫，實際 %v", target, err)
		}
	}
}

// TestArchivedRefusesEveryWritePath 驗收：歸檔後四條寫入通路一律拒，讀取照舊。
//
// 這一句要覆蓋到「指派與撤銷也算寫入」：名冊是這個活動的一筆事實，
// 終態的活動不再獲得任何新事實，也不刪除既有事實（既有行仍列、仍可讀）。
func TestArchivedRefusesEveryWritePath(t *testing.T) {
	e := newEnv(t)
	principal, admin := e.admin(t, "Archive.Admin")
	created := e.create(t, principal, "將結束的場", "原描述")
	e.transition(t, principal, created.ID, StatusActive)
	e.transition(t, principal, created.ID, StatusArchived)

	before := e.facts(t, created.ID)
	auditsBefore := e.countRows(t, "activity_audit")

	if _, err := e.service.UpdateActivityProfile(context.Background(), principal, created.ID,
		"改得動嗎", "新的", before.name, before.description, "req-a"); !errors.Is(err, ErrArchived) {
		t.Errorf("歸檔後編輯資料應回報終態拒寫，實際 %v", err)
	}
	if _, err := e.service.AssignManager(context.Background(), e.root(t), created.ID,
		admin.ID, "req-b"); !errors.Is(err, ErrArchived) {
		t.Errorf("歸檔後指派管理人應回報終態拒寫，實際 %v", err)
	}
	if _, err := e.service.RevokeManager(context.Background(), e.root(t), created.ID,
		admin.ID, "req-c"); !errors.Is(err, ErrArchived) {
		t.Errorf("歸檔後撤銷管理人應回報終態拒寫，實際 %v", err)
	}

	if after := e.facts(t, created.ID); after != before {
		t.Errorf("三種被拒的寫入動了活動行：前 %+v／實際 %+v", before, after)
	}
	if got := e.countRows(t, "activity_audit"); got != auditsBefore {
		t.Errorf("被拒的寫入不該多記審計，前 %d 筆／實際 %d 筆", auditsBefore, got)
	}

	// 仍可讀：終態是「不再變動」，不是「從不存在」。
	if _, err := e.service.ActivityDetail(context.Background(), principal, created.ID); err != nil {
		t.Errorf("歸檔後詳情仍應可讀：%v", err)
	}
	roster, err := e.service.ManagerRoster(context.Background(), principal, created.ID)
	if err != nil {
		t.Fatalf("歸檔後名冊仍應可讀：%v", err)
	}
	if len(roster) != 1 {
		t.Errorf("歸檔不刪指派行，名冊仍應列著建立者，實際 %d 行", len(roster))
	}
}

// TestBusinessWriteGateIsReusable 驗收：留給後續業務模組（陣營、成員、資產）的門禁
// 把「可寫」「停止」「終態」「查無」分成四句話，且不做任何授權判定。
func TestBusinessWriteGateIsReusable(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Gate.Admin")
	draft := e.create(t, principal, "草稿可寫", "")

	if _, err := e.service.EnsureBusinessWritesAllowed(context.Background(), e.db.SQL(), draft.ID); err != nil {
		t.Errorf("草稿應接受業務寫入（陣營等東西本來就該能在開放前準備）：%v", err)
	}
	opened := e.transition(t, principal, draft.ID, StatusActive)
	if _, err := e.service.EnsureBusinessWritesAllowed(context.Background(), e.db.SQL(), opened.ID); err != nil {
		t.Errorf("開放中的活動應接受業務寫入：%v", err)
	}
	closed := e.transition(t, principal, draft.ID, StatusClosed)
	if _, err := e.service.EnsureBusinessWritesAllowed(context.Background(), e.db.SQL(), closed.ID); !errors.Is(err, ErrActivityClosedWrites) {
		t.Errorf("停止態應回報業務寫入被拒，實際 %v", err)
	}
	archived := e.transition(t, principal, draft.ID, StatusArchived)
	if _, err := e.service.EnsureBusinessWritesAllowed(context.Background(), e.db.SQL(), archived.ID); !errors.Is(err, ErrArchived) {
		t.Errorf("終態應回報終態拒寫而不是「稍後再試」，實際 %v", err)
	}
	if _, err := e.service.EnsureBusinessWritesAllowed(context.Background(), e.db.SQL(),
		identitytest.NewID(t)); !errors.Is(err, ErrActivityNotFound) {
		t.Errorf("查無活動應回報不可分辨的查無此活動，實際 %v", err)
	}
	// 門禁不認得主體，也不因主體而變：它是狀態的判定，授權另有其閘。
	if _, err := e.service.EnsureBusinessWritesAllowed(context.Background(), e.db.SQL(),
		archived.ID); errors.Is(err, identity.ErrPermissionDenied) {
		t.Error("門禁不該回報權限結論，否則各模組會開始自己湊一套授權")
	}
}

// TestStoreStatusGuardSplitsWinnerFromLoser 驗收：正確性來自帶 WHERE 的單向 UPDATE。
//
// 這裡直接探倉儲那一躍，因為本機 SQLite 是單寫者序列、也跑不了 -race：
// 「雨者同時轉換」在真確的併發下會落到同一個守衛上——先提交的那個改變現值，
// 後提交的那個 RowsAffected 為 0。倉儲這一層把這句話固定住，
// 服務層的重讀與回滾只是讓它在單執行緒下也能被觀察到。
func TestStoreStatusGuardSplitsWinnerFromLoser(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Guard.Admin")
	created := e.create(t, principal, "守衛取證", "")

	if _, err := e.service.Transition(context.Background(), principal, created.ID,
		StatusActive, "req-win"); err != nil {
		t.Fatalf("開放應成功：%v", err)
	}
	// 以為還在草稿的那一次（陳舊檢視）在倉儲守衛上落敗，一個位都不動。
	changed, err := e.store.UpdateStatus(context.Background(), e.db.SQL(), created.ID,
		StatusDraft, StatusArchived)
	if err != nil {
		t.Fatalf("倉儲守衛不應回報故障：%v", err)
	}
	if changed {
		t.Error("現值已不是 draft，帶 WHERE 的更新必須落敗")
	}
	if f := e.facts(t, created.ID); f.status != string(StatusActive) {
		t.Errorf("落敗的更新動了狀態：實際 %q", f.status)
	}
	if got := e.countAuditRows(t, "activity.status_change", created.ID.String()); got != 1 {
		t.Errorf("落敗的更新不該有對應審計（它根本沒在交易裡發生），實際 %d 筆", got)
	}
}

// TestProfileCASFailsOnceAndKeepsWinner 驗收：併發編輯只有先提交的那次落地，
// 後到的拿到可判別的衝突，且一個字都不覆蓋。
func TestProfileCASFailsOnceAndKeepsWinner(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Cas.Admin")
	created := e.create(t, principal, "原名", "原描述")
	// 時鐘往前挪一格：編輯的落地時刻必須由注入時鐘給，不該與建立時刻同值而讓斷言分不出有沒有寫入。
	e.clock.Advance(time.Hour)

	winner, err := e.service.UpdateActivityProfile(context.Background(), principal, created.ID,
		"贏家的名字", "贏家的描述", "原名", "原描述", "req-w")
	if err != nil {
		t.Fatalf("第一次編輯應成功：%v", err)
	}
	if winner.Name != "贏家的名字" || winner.Description != "贏家的描述" {
		t.Errorf("成功編輯應回讀資料庫現值，實際 %+v", winner)
	}
	// 同一份畫面上的第二次提交：依據值已過期。
	if _, err := e.service.UpdateActivityProfile(context.Background(), principal, created.ID,
		"輸家的名字", "輸家的描述", "原名", "原描述", "req-l"); !errors.Is(err, ErrProfileConflict) {
		t.Errorf("落敗的編輯應回報資料衝突，實際 %v", err)
	}
	f := e.facts(t, created.ID)
	if f.name != "贏家的名字" || f.description != "贏家的描述" {
		t.Errorf("落敗的編輯覆蓋了現值：實際 %q／%q", f.name, f.description)
	}
	if got := e.countAuditRows(t, "activity.profile_update", created.ID.String()); got != 1 {
		t.Errorf("落敗的編輯不該留審計，實際 %d 筆", got)
	}

	// 白名單是真的白名單：編輯不碰身份、狀態、建立者與時刻。
	if f.status != string(StatusDraft) || f.createdBy != winner.CreatedByAccountID.String() ||
		f.createdAt != winner.CreatedAt.UnixMilli() {
		t.Errorf("資料編輯動到了隱藏欄位： %+v（現值狀態 %q）", f, f.status)
	}
	if f.updatedAt <= f.createdAt {
		t.Errorf("成功編輯必須推進 updated_at，實際 %d／%d", f.updatedAt, f.createdAt)
	}
}

// TestAuditWriteFailureRollsBackTheWholeAction 驗收：審計寫不進去時，活動那一行也不留。
//
// 手法是把 activity_audit 暫時釘成「任何插入都失敗」（測試專屬資料庫、用完即拆）：
// 這條注入在生產裡沒有對應通路，正是要拿它試試那個順序——
// 若寫入與審計不在同一個交易，此處就會看到「庫裡多了一個活動而查不到是誰建的」。
func TestAuditWriteFailureRollsBackTheWholeAction(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Rollback.Admin")
	ctx := context.Background()
	block := `CREATE TRIGGER test_audit_block BEFORE INSERT ON activity_audit
		BEGIN SELECT RAISE(ABORT, '測試注入：審計寫入失敗'); END`
	drop := `DROP TRIGGER test_audit_block`
	if _, err := e.db.SQL().ExecContext(ctx, block); err != nil {
		t.Fatalf("佈下注入觸發器失敗：%v", err)
	}

	_, err := e.service.Create(ctx, principal, "該回滾的活動", "", "req-blocked")
	if err == nil || !strings.Contains(err.Error(), "審計") && !strings.Contains(err.Error(), "測試注入") {
		t.Errorf("審計寫不進時建立必須失敗並帶著原因，實際 %v", err)
	}
	if got := e.countRows(t, "activities"); got != 0 {
		t.Errorf("失敗的建立必須整體回滾，實際留下 %d 行", got)
	}
	if got := e.countRows(t, "activity_manager_grants"); got != 0 {
		t.Errorf("失敗的建立不該留下指派行，實際 %d 行", got)
	}
	if got := e.countRows(t, "root_audit") + e.countRows(t, "activity_audit"); got != 0 {
		t.Errorf("回滾後不該有任何審計痕跡，實際 %d 筆", got)
	}

	if _, err := e.db.SQL().ExecContext(ctx, drop); err != nil {
		t.Fatalf("拆除注入觸發器失敗：%v", err)
	}
	created := e.create(t, principal, "重來一次的活動", "")
	if created.ManagerCount != 1 {
		t.Errorf("同一位操作者重試後應正常落地（建立者自動指派），實際 manager_count=%d", created.ManagerCount)
	}
	if got := e.countAuditRows(t, "activity.create", created.ID.String()); got != 1 {
		t.Errorf("成功的建立該留下一筆 activity.create，實際 %d 筆", got)
	}
	// 已存在的活動同樣受這條保障：狀態轉換失敗時狀態不動。
	e.transition(t, principal, created.ID, StatusActive)
	if _, err := e.db.SQL().ExecContext(ctx, block); err != nil {
		t.Fatalf("再次佈下注入觸發器失敗：%v", err)
	}
	defer func() {
		if _, err := e.db.SQL().ExecContext(ctx, drop); err != nil {
			t.Errorf("收尾拆除注入觸發器失敗：%v", err)
		}
	}()
	if _, err := e.service.Transition(ctx, principal, created.ID, StatusArchived, "req-x"); err == nil {
		t.Error("審計寫不進時狀態轉換必須失敗")
	}
	if f := e.facts(t, created.ID); f.status != string(StatusActive) {
		t.Errorf("失敗的轉換動了狀態：實際 %q", f.status)
	}
}
