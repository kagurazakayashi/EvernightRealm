// pending_scope_test.go 釘住「待審批與已拒絕的申請不屬於管理員的普通帳戶目錄」這件事。
//
// 這一組斷言擋的是一種很具體的越權形態：目錄那條 WHERE 本來只排除刪除終態，
// 少寫一層就會讓 pending／rejected 從「列不到」變成「列得到、點得下去」，
// 而管理員對一個還沒被批准的人能做的每一件事（停用／恢復、重置口令、改顯示名）
// 都不是本步批准的能力——待審批名冊屬下一步的審批通路。
//
// 現場用帳戶倉儲直接種出兩個狀態（審批的處理屬下一步，本步沒有、也不該有任何生產入口
// 能把一筆帳戶推成已批准或已拒絕），因此這裡測的是範圍規則本身，不是審批流程。
package stdacct

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// fakeApplicantHash 是探針帳戶的憑據欄內容：只服務「標準帳戶必帶憑據」這條 CHECK，
// 不是任何環境的口令，也從不參與本檔的判定。
const fakeApplicantHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$fakehashfortestonly"

// seededReviewedOffset 是探針補上的審核決定時刻與建立時刻的距離。
//
// 遷移 0009 有一條「決定不可能早於帳戶誕生」的單調 CHECK，而本套件的注入時鐘把建立時刻
// 固定在 testBase，所以這裡一律取「之後」的一個時刻，而不是隨便一個整數。
const seededReviewedOffset = 90 * time.Minute

// seedApprovalShaped 種出一筆指定狀態的申請形態，回傳它的標識。
//
// 生下來只能是 pending（帳戶域把 rejected 擋在建立之外：沒有人做過決定時，
// 「一出生就被拒絕」沒有一句誠實的話可說），因此這裡一律先建 pending 再補那一跳 UPDATE；
// rejected 必帶審核時刻（遷移 0009 的 CHECK）。整個手法刻意不經任何生產用例——
// 本步沒有審批入口，直寫倉儲是探針手法而不是後門。
func seedApprovalShaped(t *testing.T, e *env, login string, status account.Status) idgen.ID {
	t.Helper()
	ctx := context.Background()
	if status != account.StatusPending && status != account.StatusRejected {
		t.Fatalf("本助手只種審批鏈的兩個形態，請求了 %q", status)
	}
	created, err := account.NewStore(e.clock).Create(ctx, e.db.SQL(), account.NewInput{
		LoginName:    login,
		DisplayName:  "申請人 " + login,
		PasswordHash: fakeApplicantHash,
		Type:         account.TypeStandard,
		Status:       account.StatusPending,
	})
	if err != nil {
		t.Fatalf("種出 %s 失敗：%v", login, err)
	}
	if status == account.StatusRejected {
		reviewedAt := timeutil.ToMillis(e.clock.Now().Add(seededReviewedOffset))
		if _, err := e.db.SQL().ExecContext(ctx,
			"UPDATE accounts SET status = ?, reviewed_at = ? WHERE id = ?",
			string(status), reviewedAt, created.ID.String()); err != nil {
			t.Fatalf("補上審核時刻與狀態失敗：%v", err)
		}
	}
	return created.ID
}

// TestDirectoryExcludesApplications 目錄把兩類申請排在範圍之外，而且總數與行數同源。
//
// 「列不到」而不是「列到但不給寫」：本目錄的語意是可打理的普通帳戶名冊，
// 一個還沒獲准的人不在任何一本名冊上，把他列出來只會得到一個必然失敗的入口。
func TestDirectoryExcludesApplications(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())

	manageable := e.mustCreate(t, admin, "manageable.one")
	pendingID := seedApprovalShaped(t, e, "pending.one", account.StatusPending)
	rejectedID := seedApprovalShaped(t, e, "rejected.one", account.StatusRejected)

	page, err := e.service.Directory(ctx, admin, DirectoryQuery{
		Page: 1, PageSize: DirectoryDefaultPageSize,
	})
	if err != nil {
		t.Fatalf("讀目錄失敗：%v", err)
	}
	if page.Total != 1 || len(page.Rows) != 1 {
		t.Fatalf("目錄應只列那一筆可打理的帳戶，實際 total=%d rows=%d", page.Total, len(page.Rows))
	}
	if page.Rows[0].AccountID != manageable.AccountID.String() {
		t.Errorf("列到的應是那一筆普通帳戶，實際 %s", page.Rows[0].AccountID)
	}

	// 狀態篩選也不該把它們湊進來：篩「全部」與篩任一既有狀態，結果都不含兩類申請。
	for _, filter := range []string{
		DirectoryFilterAll, string(account.StatusActive), string(account.StatusDisabled),
	} {
		filtered, err := e.service.Directory(ctx, admin, DirectoryQuery{
			Page: 1, PageSize: DirectoryDefaultPageSize, StatusFilter: filter,
		})
		if err != nil {
			t.Fatalf("篩選 %s 失敗：%v", filter, err)
		}
		for _, row := range filtered.Rows {
			if row.AccountID == pendingID.String() || row.AccountID == rejectedID.String() {
				t.Errorf("篩選 %s 把申請列進了目錄：%s", filter, row.AccountID)
			}
		}
	}

	// 把 pending 當成篩選值是「拿這本目錄去讀待審批名冊」的那條捷徑，必須被拒。
	if _, err := e.service.Directory(ctx, admin, DirectoryQuery{
		Page: 1, PageSize: DirectoryDefaultPageSize, StatusFilter: string(account.StatusPending),
	}); !errors.Is(err, ErrInvalidStatusFilter) {
		t.Errorf("目錄不該接受 pending 作為篩選值，實際 %v", err)
	}
}

// TestTargetedWritesRefuseApplications 按標識直打四條通路都回「查無此帳戶」，而且一個字都不落。
//
// 回 1001 同形（與詳情打到一個不存在的標識同一句話）是刻意的：這裡要的不是
// 「他在待審批」這種內部狀態的外洩，而是一句「本目錄沒這個人」。少了這一層後果是具體的——
// 停用那條 CAS 會把 pending 當成「依據值不對」的衝突來報（2014），形體上就像後端壞了；
// 重置那條則會真的把一個還沒獲准的人的口令換掉。
func TestTargetedWritesRefuseApplications(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())

	targets := map[string]idgen.ID{
		"待審批": seedApprovalShaped(t, e, "pending.target", account.StatusPending),
		"已拒絕": seedApprovalShaped(t, e, "rejected.target", account.StatusRejected),
	}
	auditsBefore := countRows(t, e.db, "root_audit")

	for name, id := range targets {
		if _, err := e.service.StandardAccountProfile(ctx, admin, id); !errors.Is(err, ErrAccountNotFound) {
			t.Errorf("%s：讀詳情應回查無此帳戶，實際 %v", name, err)
		}
		if _, err := e.service.UpdateStandardAccountProfile(ctx, admin, id,
			"不該落庫的名字", "申請人 "+id.String(), "req-profile"); !errors.Is(err, ErrAccountNotFound) {
			t.Errorf("%s：改顯示名應回查無此帳戶，實際 %v", name, err)
		}
		if _, err := e.service.UpdateStandardAccountStatus(ctx, admin, id,
			StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
			"req-status"); !errors.Is(err, ErrAccountNotFound) {
			t.Errorf("%s：停用應回查無此帳戶，而不是衝突碼，實際 %v", name, err)
		}
		if _, err := e.service.ResetStandardAccountPassword(ctx, admin, id,
			testResetPassword, "req-password"); !errors.Is(err, ErrAccountNotFound) {
			t.Errorf("%s：重置口令應回查無此帳戶，實際 %v", name, err)
		}
	}

	if got := countRows(t, e.db, "root_audit"); got != auditsBefore {
		t.Errorf("被範圍規則擋下的寫入不得追加審計，實際 %d→%d", auditsBefore, got)
	}
	// 目標行一個字都沒被改動：範圍判定在任何寫入之前，display_name 與憑據都還在原處。
	for name, id := range targets {
		var (
			status      string
			displayName string
			mustChange  int64
		)
		if err := e.db.SQL().QueryRowContext(ctx,
			"SELECT status, display_name, must_change_password FROM accounts WHERE id = ?", id.String()).
			Scan(&status, &displayName, &mustChange); err != nil {
			t.Fatalf("讀回目標失敗：%v", err)
		}
		if status != string(account.StatusPending) && status != string(account.StatusRejected) {
			t.Errorf("%s 的目標狀態被寫入通路改動成 %q", name, status)
		}
		if mustChange != 0 {
			t.Errorf("%s 的目標被順手設上了首次改密義務", name)
		}
	}
}

// TestDirectoryStillListsApprovedApplicant 批准之後的人重新變得可打理：
// 目錄排的是「還在審批鏈上」的兩個狀態，不是「曾經走過審批」這個歷史事實。
//
// 這一條擋的是一種過度修正：如果把範圍規則寫成「帶審核時刻的一律不列」，
// 一個被批准的人此後會從名冊上消失，管理員既停不了他、也重置不了他的口令——
// 而 reviewed_at 記的只是他當初怎麼進來的。
func TestDirectoryStillListsApprovedApplicant(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())

	id := seedApprovalShaped(t, e, "approved.one", account.StatusPending)
	if _, err := e.db.SQL().ExecContext(ctx,
		"UPDATE accounts SET status = 'active', reviewed_at = ? WHERE id = ?",
		timeutil.ToMillis(e.clock.Now().Add(seededReviewedOffset)), id.String()); err != nil {
		t.Fatalf("模擬批准那一跳失敗：%v", err)
	}

	page, err := e.service.Directory(ctx, admin, DirectoryQuery{
		Page: 1, PageSize: DirectoryDefaultPageSize,
	})
	if err != nil {
		t.Fatalf("讀目錄失敗：%v", err)
	}
	if page.Total != 1 || page.Rows[0].AccountID != id.String() {
		t.Fatalf("已批准的人應回到目錄上，實際 total=%d rows=%+v", page.Total, page.Rows)
	}
	if _, err := e.service.StandardAccountProfile(ctx, admin, id); err != nil {
		t.Errorf("已批准的人應讀得到詳情：%v", err)
	}
	if _, err := e.service.UpdateStandardAccountStatus(ctx, admin, id,
		StatusChangeInput{NewStatus: account.StatusDisabled, ExpectedStatus: account.StatusActive},
		"req-disable"); err != nil {
		t.Errorf("已批准的人應能被停用：%v", err)
	}
}
