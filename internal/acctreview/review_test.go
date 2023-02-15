// review_test.go 是「批准與拒絕」這一跳的用例層證據：誰能按下、按下之後落下什麼形態、
// 兩個人同時按下會發生什麼、已經在別的書裡的人能不能被這顆按鈕碰到，以及決定留下的痕跡。
//
// 對應本步的驗收要求：批准後的標準登入、拒絕仍無普通權限、非審核者越權、兩人併發審核、
// 停用與審批競爭、內部備註隔離、重複處理。
//
// 全程使用本次專屬的暫存庫與注入時鐘：不佔 5206、不碰任何真實資料目錄。
package acctreview

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// rowFacts 是一筆申請在資料庫裡的可讀取形態（脫敏斷言與回滾斷言都拿它做前後對照）。
type rowFacts struct {
	Status       string
	LoginName    string
	DisplayName  string
	HashLen      int
	MustChange   int64
	ReviewedAt   sql.NullInt64
	DisabledAt   sql.NullInt64
	DeletedAt    sql.NullInt64
	LastLoginAt  sql.NullInt64
	AccountType  string
	CreatedAtMil int64
}

// String 把形態壓成一句可讀的話（斷言失敗時要一眼看出差在哪一欄）。
func (r rowFacts) String() string {
	return fmt.Sprintf("status=%s reviewed_at=%d/%v disabled_at=%d/%v deleted_at=%d/%v "+
		"last_login_at=%d/%v must_change=%d hash_len=%d", r.Status,
		r.ReviewedAt.Int64, r.ReviewedAt.Valid, r.DisabledAt.Int64, r.DisabledAt.Valid,
		r.DeletedAt.Int64, r.DeletedAt.Valid, r.LastLoginAt.Int64, r.LastLoginAt.Valid,
		r.MustChange, r.HashLen)
}

// readRow 讀回一筆帳戶的資料庫現值。
func readRow(t *testing.T, db *database.DB, id idgen.ID) rowFacts {
	t.Helper()
	var row rowFacts
	err := db.SQL().QueryRowContext(context.Background(), `SELECT status, login_name, display_name,
		length(COALESCE(password_hash, '')), must_change_password, reviewed_at, disabled_at,
		deleted_at, last_login_at, account_type, created_at
		FROM accounts WHERE id = ?`, id.String()).
		Scan(&row.Status, &row.LoginName, &row.DisplayName, &row.HashLen, &row.MustChange,
			&row.ReviewedAt, &row.DisabledAt, &row.DeletedAt, &row.LastLoginAt,
			&row.AccountType, &row.CreatedAtMil)
	if err != nil {
		t.Fatalf("讀取帳戶現值失敗：%v", err)
	}
	return row
}

// TestApproveWritesDecisionAndRootAudit 批准落下的是「可登入＋決定時刻＋一條真實歸屬的審計」，
// 而申請人的憑據、首次改密義務、登入名與來源類型一個字都不動。
//
// actor 是按下按鈕的那位管理者（不是 system、也不是 Root），而且這筆審計不屬於任何活動——
// root_audit 結構上根本沒有 activity_id 那一欄。
func TestApproveWritesDecisionAndRootAudit(t *testing.T) {
	e := newEnv(t)
	reviewerID := identitytest.NewID(t)
	reviewer := identitytest.Account(t, reviewerID, identitytest.ServerAdmin())
	target := e.mustApplication(t, "Approve.One", "第一個被批准的人")
	before := readRow(t, e.db, target.ID)

	outcome := e.mustReview(t, reviewer, target.ID, account.DecisionApprove)
	if outcome.Decision != account.DecisionApprove {
		t.Errorf("回顯的決定該是本次落地的那個，實際 %q", outcome.Decision)
	}
	if outcome.Application.Status != account.StatusActive.String() {
		t.Errorf("批准之後回顯的現值必須是 active，實際 %q", outcome.Application.Status)
	}
	if outcome.Application.ReviewedAt.IsZero() {
		t.Error("批准必須同時留下決定時刻（申請人查狀態就是靠它分辨 approved）")
	}
	if outcome.Application.AccountID != target.ID.String() ||
		outcome.Application.LoginName != "Approve.One" {
		t.Errorf("批准不搬身份：回顯該是同一個人，實際 %+v", outcome.Application)
	}

	after := readRow(t, e.db, target.ID)
	if after.Status != "active" || !after.ReviewedAt.Valid {
		t.Fatalf("落庫形態不對：%s", after)
	}
	if after.ReviewedAt.Int64 != timeutil.ToMillis(e.clock.Now()) {
		t.Errorf("決定時刻必須取自注入時鐘（呼叫端無權代填），實際 %v", after.ReviewedAt)
	}
	if after.MustChange != before.MustChange || after.HashLen != before.HashLen {
		t.Errorf("批准不碰憑據也不製造改密義務：%s 對 %s", before, after)
	}
	if after.LoginName != before.LoginName || after.DisplayName != before.DisplayName ||
		after.AccountType != before.AccountType || after.CreatedAtMil != before.CreatedAtMil {
		t.Errorf("批准不順手改頭換面：%s 對 %s", before, after)
	}
	if after.DisabledAt.Valid || after.DeletedAt.Valid || after.LastLoginAt.Valid {
		t.Errorf("批准不偽造任何時刻：%s", after)
	}

	// 授予與會話：批准既不多給一份權限，也不替任何人簽發憑據。
	if n := countRows(t, e.db, "account_server_roles"); n != 0 {
		t.Errorf("批准只造普通帳戶，授予表該是空的，實際 %d 行", n)
	}
	if n := countRows(t, e.db, "sessions"); n != 0 {
		t.Errorf("批准不簽發會話（他能進去由他自己交口令那條通路決定），實際 %d 行", n)
	}

	record := mustAudit(t, e.db, "account.approve")
	if record.ActorKind != "admin" || !record.ActorID.Valid ||
		record.ActorID.String != reviewerID.String() {
		t.Errorf("審核者是誰只能落在 root_audit 的 actor 裡，實際 %s/%v", record.ActorKind, record.ActorID)
	}
	if !record.TargetID.Valid || record.TargetID.String != target.ID.String() {
		t.Errorf("審計要指得出被批准的是哪一筆，實際 %v", record.TargetID)
	}
	if !record.RequestID.Valid || record.RequestID.String != "req-review" {
		t.Errorf("請求驅動的決定必須帶著關聯 ID 接回訪問日誌，實際 %v", record.RequestID)
	}
	if !strings.Contains(record.ChangesJSON, "pending") ||
		!strings.Contains(record.ChangesJSON, "active") {
		t.Errorf("審計該如實記下狀態前後值，實際 %s", record.ChangesJSON)
	}
	// 內部備註隔離的結構面：changes 只有 status 與 reviewed_at 兩格，
	// 沒有一格能容下審核者的隨筆，也沒有一格可能含口令材料。
	if got := auditFieldNames(t, record.ChangesJSON); len(got) != 2 ||
		got[0] != "reviewed_at" || got[1] != "status" {
		t.Errorf("審計的變更欄位該恰好是兩格，實際 %v（原文 %s）", got, record.ChangesJSON)
	}
	blob := record.ChangesJSON + record.Reason.String
	if strings.Contains(blob, "$argon2id$") || strings.Contains(blob, testPassword) {
		t.Error("審計裡出現憑據材料")
	}
}

// TestRootReviewIsRecordedAsRoot Root 走同一條通路時，審計的 actor 換成 Root 而不是冒充管理員；
// 而批准出去的主體形態與管理員批准時完全相同（一個不帶任何授予的普通帳戶）。
func TestRootReviewIsRecordedAsRoot(t *testing.T) {
	e := newEnv(t)
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	target := e.mustApplication(t, "Approve.ByRoot", "由 Root 批准")

	e.mustReview(t, root, target.ID, account.DecisionApprove)

	record := mustAudit(t, e.db, "account.approve")
	if record.ActorKind != "root" {
		t.Errorf("Root 的決定該記為 root 主體，實際 %s", record.ActorKind)
	}
	if n := countRows(t, e.db, "account_server_roles"); n != 0 {
		t.Errorf("Root 批准也不造出授予，實際 %d 行", n)
	}
}

// TestRejectKeepsRowOccupiesNameAndAudits 拒絕落下 rejected＋決定時刻＋一條 account.reject 審計，
// 而行保留、登入名仍被佔用（用戶批准的保留策略）。
func TestRejectKeepsRowOccupiesNameAndAudits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reviewer := newAdmin(t)
	target := e.mustApplication(t, "Reject.One", "要被拒絕的人")

	outcome := e.mustReview(t, reviewer, target.ID, account.DecisionReject)
	if outcome.Application.Status != account.StatusRejected.String() {
		t.Errorf("拒絕後回顯該是 rejected，實際 %q", outcome.Application.Status)
	}
	after := readRow(t, e.db, target.ID)
	if after.Status != "rejected" || !after.ReviewedAt.Valid {
		t.Fatalf("拒絕的落庫形態不對：%s", after)
	}
	if after.HashLen == 0 || after.MustChange != 0 {
		t.Errorf("拒絕不碰憑據也不製造改密義務：%s", after)
	}
	// 同一個登入名不能再被建出來（倉儲原語就是自註冊那條通路用的同一個寫法）：
	// 「拒絕保留行」不等於「釋放名字」，這句話要靠唯一索引站住，而不是靠措辭。
	if _, err := e.accounts.Create(ctx, e.db.SQL(), account.NewInput{
		LoginName: "reject.one", DisplayName: "撞名的人",
		PasswordHash: e.mustHash(t, testPassword), Type: account.TypeStandard,
		Status: account.StatusPending,
	}); !errors.Is(err, account.ErrDuplicateLogin) {
		t.Errorf("被拒的登入名必須仍被佔用，實際 %v", err)
	}
	if n := countRows(t, e.db, "accounts"); n != 1 {
		t.Errorf("撞名的一次提交不該多出第二筆，實際 %d 行", n)
	}

	record := mustAudit(t, e.db, "account.reject")
	if record.ActorKind != "admin" {
		t.Errorf("拒絕也要查得出是誰做的，實際 %s", record.ActorKind)
	}
	blob := record.ChangesJSON + record.Reason.String
	if strings.Contains(blob, testPassword) || strings.Contains(blob, "$argon2id$") {
		t.Error("拒絕的審計裡出現憑據材料")
	}
}

// TestReviewPermissionMatrix 非審核者越權：匿名、普通帳戶、訪客與系統主體都碰不到這一格，
// 而且被拒的請求一個字都不落（狀態、時刻、審計三樣都沒有）。
//
// 匿名與其他主體的結論刻意分開：一個是「連是誰都不知道」（2002 那一句），
// 另一個是「身分可信但沒有這個權限」（2011 那一句）。
func TestReviewPermissionMatrix(t *testing.T) {
	e := newEnv(t)
	target := e.mustApplication(t, "gate.review", "被審核的申請")

	cases := []struct {
		name      string
		principal identity.Principal
		want      error
	}{
		{"匿名", identitytest.Anonymous(t), identity.ErrNotAuthenticated},
		{"普通帳戶", identitytest.Account(t, identitytest.NewID(t)), identity.ErrPermissionDenied},
		{"訪客帳戶", identitytest.Account(t, identitytest.NewID(t), identitytest.WithGuestType()),
			identity.ErrPermissionDenied},
		{"系統主體", identitytest.System(t, identity.OriginCLI), identity.ErrPermissionDenied},
	}
	for _, tc := range cases {
		before := readRow(t, e.db, target.ID)
		err := e.reviewErr(t, tc.principal, target.ID, account.DecisionApprove)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s 下決定應回 %v，實際 %v", tc.name, tc.want, err)
		}
		if got := readRow(t, e.db, target.ID); got.String() != before.String() {
			t.Errorf("%s 的被拒決定落了盤：%s 對 %s", tc.name, before, got)
		}
	}
	if n := countAudit(t, e.db, "account.approve"); n != 0 {
		t.Errorf("被拒的審批不該追加審計（拒絕不是寫入放大器），實際 %d 筆", n)
	}
	if n := countRows(t, e.db, "sessions"); n != 0 {
		t.Errorf("被拒的審批不該簽發任何會話，實際 %d 行", n)
	}
}

// TestReviewTargetScope 六種「不在這本名冊上」的形態一律回同一句話，而且一個字都不寫：
// 空標識、幽靈標識、訪戶、持有伺服器級授予的人、進入刪除終態的人，
// 加上從沒走過審批通路的既有帳戶（管理員建號與開放自註冊建成的都是這個形態）。
func TestReviewTargetScope(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := newAdmin(t)

	ghost := identitytest.NewID(t)
	plain := e.mustSeed(t, account.NewInput{
		LoginName: "scope.plain", DisplayName: "直接建成的帳戶",
		PasswordHash: e.mustHash(t, testPassword), Type: account.TypeStandard,
		Status: account.StatusActive, MustChangePassword: true,
	})
	guest := e.mustSeed(t, account.NewInput{
		LoginName: "scope.guest", DisplayName: "訪戶", Type: account.TypeGuest,
		Status: account.StatusActive,
	})
	granted := e.mustApplication(t, "scope.granted", "被授予過的申請")
	e.grantAdminRole(t, granted.ID)
	doomed := e.mustApplication(t, "scope.deleted", "將被刪除的申請")
	if _, err := e.accounts.MarkDeleted(ctx, e.db.SQL(), doomed.ID, doomed.DisplayName); err != nil {
		t.Fatalf("種出刪除終態失敗：%v", err)
	}

	// 先擋「根本沒這一行」的兩種標識：空標識連查詢都不該發出去，
	// 幽靈標識格式合法但查無此人——兩者都該是同一句話，而且不該 panic 在讀快照上。
	for name, id := range map[string]idgen.ID{"空標識": idgen.Nil, "幽靈標識": ghost} {
		for _, decision := range []account.Decision{account.DecisionApprove, account.DecisionReject} {
			if err := e.reviewErr(t, admin, id, decision); !errors.Is(err, ErrApplicationNotFound) {
				t.Errorf("%s 被 %s 命中時應回「不在這本名冊上」，實際 %v", name, decision, err)
			}
		}
	}

	for name, id := range map[string]idgen.ID{
		"直接建成的": plain.ID, "訪戶": guest.ID,
		"被授予過的申請": granted.ID, "已刪除的申請": doomed.ID,
	} {
		before := readRow(t, e.db, id)
		for _, decision := range []account.Decision{account.DecisionApprove, account.DecisionReject} {
			if err := e.reviewErr(t, admin, id, decision); !errors.Is(err, ErrApplicationNotFound) {
				t.Errorf("%s 被 %s 命中時應回「不在這本名冊上」，實際 %v", name, decision, err)
			}
		}
		if got := readRow(t, e.db, id); got.String() != before.String() {
			t.Errorf("%s 的被拒決定落了盤：%s 對 %s", name, before, got)
		}
	}

	// 被授予過的那一筆同時也不該在名冊上讀到（範圍規則若在兩本書各寫一套就會開始漂移）。
	seen := e.mustRosterIDs(t, admin, RosterFilterAll)
	if seen[granted.ID.String()] {
		t.Error("持有伺服器級授予的申請不該出現在名冊上")
	}
	if seen[doomed.ID.String()] {
		t.Error("已刪除的申請不該出現在名冊上")
	}
}

// TestAlreadyDecidedCannotBeRedone 重複處理與改判都收斂到同一枚結論：
// 已經決定過的人不能再被按下另一顆按鈕，先前那個決定也不會被蓋掉。
func TestAlreadyDecidedCannotBeRedone(t *testing.T) {
	e := newEnv(t)
	first := newAdmin(t)
	second := newAdmin(t)

	approved := e.mustApplication(t, "again.approved", "被批准兩次")
	e.mustReview(t, first, approved.ID, account.DecisionApprove)
	decidedAt := readRow(t, e.db, approved.ID).ReviewedAt.Int64
	e.clock.Advance(time.Hour)

	for _, decision := range []account.Decision{account.DecisionApprove, account.DecisionReject} {
		err := e.reviewErr(t, second, approved.ID, decision)
		if !errors.Is(err, ErrAlreadyReviewed) {
			t.Errorf("對已批准的人再下 %s 必須回「已有決定」，實際 %v", decision, err)
		}
	}
	after := readRow(t, e.db, approved.ID)
	if after.Status != "active" || after.ReviewedAt.Int64 != decidedAt {
		t.Errorf("改判不成立：先前那個決定必須原樣留下，實際 %s", after)
	}
	if n := countAudit(t, e.db, "account.approve"); n != 1 {
		t.Errorf("被拒的重複不該再添審計，實際 %d 筆", n)
	}
	if n := countAudit(t, e.db, "account.reject"); n != 0 {
		t.Errorf("被拒的改判不該留下拒絕的審計，實際 %d 筆", n)
	}

	rejected := e.mustApplication(t, "again.rejected", "被拒絕兩次")
	e.mustReview(t, first, rejected.ID, account.DecisionReject)
	if err := e.reviewErr(t, second, rejected.ID, account.DecisionApprove); !errors.Is(err, ErrAlreadyReviewed) {
		t.Errorf("今日沒有 reopen 通路，實際 %v", err)
	}

	// 從沒走過審批通路的 active 帳戶是另一句話（換個目標），不是「已有決定」。
	plain := e.mustSeed(t, account.NewInput{
		LoginName: "again.plain", DisplayName: "管理員建好的帳戶",
		PasswordHash: e.mustHash(t, testPassword), Type: account.TypeStandard,
		Status: account.StatusActive, MustChangePassword: true,
	})
	if err := e.reviewErr(t, first, plain.ID, account.DecisionApprove); !errors.Is(err, ErrApplicationNotFound) {
		t.Errorf("對一筆從沒申請過的帳戶該回「不在名冊上」，實際 %v", err)
	}
}

// TestTwoReviewersFormOneResult 併發：兩位審核者對著同一份名冊同時按下，只形成一個有效結果。
//
// 六路同發（三批批准、三批拒絕）時，贏家恰好一個，其餘全部拿到「已有決定」；
// 庫裡最後只有一筆決定時刻、一條審計，而那個狀態就是贏家那一次落下的形態——
// 後到的人既沒有一個字落地，也沒有把先前那個決定悄悄蓋掉。
func TestTwoReviewersFormOneResult(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	target := e.mustApplication(t, "race.one", "兩人同時審核")
	reviewers := []identity.Principal{newAdmin(t), newAdmin(t), newAdmin(t)}

	var (
		wg      sync.WaitGroup
		results = make([]error, 6)
		start   = make(chan struct{})
	)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			decision := account.DecisionApprove
			if i%2 == 1 {
				decision = account.DecisionReject
			}
			_, results[i] = e.service.ReviewApplication(ctx, reviewers[i%len(reviewers)],
				target.ID, decision, fmt.Sprintf("req-race-%d", i))
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	for i, err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrAlreadyReviewed):
			// 輸家：前提已失效，這是預期結論。
		default:
			t.Errorf("第 %d 路回了預期外的錯誤：%v", i+1, err)
		}
	}
	if wins != 1 {
		t.Errorf("六路併發應恰好一次生效，實際 %d 次", wins)
	}
	after := readRow(t, e.db, target.ID)
	if after.Status != "active" && after.Status != "rejected" {
		t.Errorf("最終形態必須是兩個決定之一，實際 %s", after)
	}
	if !after.ReviewedAt.Valid {
		t.Fatal("贏家那一次必須留下決定時刻")
	}
	if n := countAudit(t, e.db, "account.approve") + countAudit(t, e.db, "account.reject"); n != 1 {
		t.Errorf("審計筆數必須與真正生效的決定同數，實際 %d 筆", n)
	}
	if pending := e.mustRosterIDs(t, newAdmin(t), account.StatusPending.String()); pending[target.ID.String()] {
		t.Error("已被決定的人不該再出現在 pending 篩選裡")
	}
}

// TestSuspensionAndApprovalRace 停用與審批競爭：批准不解除獨立停用，也不把一個已停用的人撈回來。
//
// 現場是真實的兩條通路交錯：審核者批准（他離開 pending）→ 另一位管理員經既有停用通路
// 把他停用（account.Store.SetStatus，internal/stdacct 那條路用的同一個原語）→
// 審核者再按一次批准。第三跳必須被拒，而 disabled 與 disabled_at 原樣留下——
// 「用批准替他解除停用」在這裡沒有一個可以發生的形狀。
func TestSuspensionAndApprovalRace(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reviewer := newAdmin(t)
	target := e.mustApplication(t, "race.suspend", "批准後被停用")

	e.mustReview(t, reviewer, target.ID, account.DecisionApprove)
	if _, err := e.accounts.SetStatus(ctx, e.db.SQL(), target.ID,
		account.StatusDisabled, account.StatusActive); err != nil {
		t.Fatalf("經停用通路把他停用失敗：%v", err)
	}
	// 注入時鐘往後走，讓「再決定一次會不會蓋掉時刻」這個斷言有分辨力。
	e.clock.Advance(time.Hour)
	disabled := readRow(t, e.db, target.ID)

	if err := e.reviewErr(t, reviewer, target.ID, account.DecisionApprove); !errors.Is(err, ErrAlreadyReviewed) {
		t.Errorf("批准不該能碰一個已被停用的人，實際 %v", err)
	}
	after := readRow(t, e.db, target.ID)
	if after.Status != "disabled" || after.DisabledAt.Int64 != disabled.DisabledAt.Int64 ||
		after.ReviewedAt.Int64 != disabled.ReviewedAt.Int64 {
		t.Errorf("批准不解除停用、也不重寫任何時刻：%s 對 %s", disabled, after)
	}
	if err := e.reviewErr(t, reviewer, target.ID, account.DecisionReject); !errors.Is(err, ErrAlreadyReviewed) {
		t.Errorf("對已批准的人改判拒絕同樣必須被拒，實際 %v", err)
	}
	// 他仍不在這本名冊上（那句篩選用狀態而不是「有沒有決定時刻」，否則這個人會從兩本書之間掉下去）；
	// 他在普通帳戶名冊那一側讀得到——那是 internal/stdacct 的範圍規則，本步一個字沒改。
	if e.mustRosterIDs(t, reviewer, RosterFilterAll)[target.ID.String()] {
		t.Error("批准後被停用的人不該出現在審批名冊上")
	}
}

// TestReviewIgnoresCreationPolicy 審批不問帳戶建立策略：Root 事後把模式改成 closed 或 open，
// 既不該讓等待中的申請消失，也不該讓審核者無法處理他眼前這一筆（用戶批准：模式只管新提交）。
func TestReviewIgnoresCreationPolicy(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reviewer := newAdmin(t)
	pending := e.mustApplication(t, "policy.pending", "切模式之後仍被批准")

	for _, mode := range []acctpolicy.Mode{acctpolicy.ModeClosed, acctpolicy.ModeOpen,
		acctpolicy.ModeApproval} {
		e.setSelfRegisterMode(t, mode)
		if _, err := e.service.Roster(ctx, reviewer,
			RosterQuery{Page: 1, PageSize: RosterMaxPageSize}); err != nil {
			t.Fatalf("模式切成 %s 之後名冊仍該讀得到，實際 %v", mode, err)
		}
	}
	e.setSelfRegisterMode(t, acctpolicy.ModeClosed)
	outcome := e.mustReview(t, reviewer, pending.ID, account.DecisionApprove)
	if outcome.Application.Status != account.StatusActive.String() {
		t.Errorf("closed 之下既有申請照樣可以被批准，實際 %q", outcome.Application.Status)
	}
}

// TestReviewRejectsUnknownDecisionAndRollsBack 決定值不合法點名欄位而不進交易；
// 而審計寫不進去時整筆決定回滾——不留「他已經可登入卻查不到是誰批的」那種半成品。
func TestReviewRejectsUnknownDecisionAndRollsBack(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reviewer := newAdmin(t)

	bad := e.mustApplication(t, "bad.decision", "遇上非法決定值")
	for _, raw := range []string{"", "pending", "approved", "rejected", "Approve", "disable"} {
		err := e.reviewErr(t, reviewer, bad.ID, account.Decision(raw))
		if !errors.Is(err, ErrInvalidDecision) {
			t.Errorf("決定值 %q 必須回可判別的輸入結論，實際 %v", raw, err)
		}
	}
	if got := readRow(t, e.db, bad.ID); got.Status != "pending" || got.ReviewedAt.Valid {
		t.Errorf("非法決定值一個字都不該落：%s", got)
	}

	rollback := e.mustApplication(t, "bad.rollback", "審計寫不進去")
	before := readRow(t, e.db, rollback.ID)
	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("製造審計故障失敗：%v", err)
	}
	if err := e.reviewErr(t, reviewer, rollback.ID, account.DecisionApprove); err == nil {
		t.Fatal("審計寫不進去時批准必須整筆失敗")
	}
	if got := readRow(t, e.db, rollback.ID); got.String() != before.String() {
		t.Errorf("失敗的批准該整筆回滾，前後：%s 對 %s", before, got)
	}
}

// TestReviewContextCancelled 已取消的 context 在第一個查詢就失敗：零寫入、零審計。
func TestReviewContextCancelled(t *testing.T) {
	e := newEnv(t)
	reviewer := newAdmin(t)
	target := e.mustApplication(t, "ctx.cancel", "帶著已取消的交易到達")
	before := readRow(t, e.db, target.ID)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.service.ReviewApplication(ctx, reviewer, target.ID,
		account.DecisionApprove, "req-cancel"); err == nil {
		t.Fatal("已取消的交易必須失敗")
	}
	if got := readRow(t, e.db, target.ID); got.String() != before.String() {
		t.Errorf("已取消的請求該一個字都不落：%s 對 %s", before, got)
	}
}

// TestApprovedApplicantSignInLoop 批准之後的閉環（本步驗收要求第一條）：
// 同一個人、同一枚自選口令，批准前經既有登入通路被拒（與打錯口令同形、零會話），
// 批准那一刻本身仍然不簽發會話，直到他自己交憑據才換到一份——
// 「原受限會話不因前端改狀態就取得完整權限」這句話在這裡的形態更強：他從來沒有會話可升級。
func TestApprovedApplicantSignInLoop(t *testing.T) {
	e := newEnv(t)
	reviewer := newAdmin(t)
	target := e.mustApplication(t, "Loop.SignIn", "會被批准來登入的人")
	authService := e.newAuthService(t)
	ctx := context.Background()

	if _, err := authService.LoginAccount(ctx, "Loop.SignIn", testPassword, "req-pre",
		"127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("批准前必須進不去（與口令打錯同形），實際 %v", err)
	}
	if n := countRows(t, e.db, "sessions"); n != 0 {
		t.Fatalf("批准前不該有任何會話，實際 %d 行", n)
	}

	e.mustReview(t, reviewer, target.ID, account.DecisionApprove)
	if n := countRows(t, e.db, "sessions"); n != 0 {
		t.Fatalf("批准這一步本身不簽發會話，實際 %d 行", n)
	}

	outcome, err := authService.LoginAccount(ctx, "Loop.SignIn", testPassword, "req-post", "127.0.0.1")
	if err != nil {
		t.Fatalf("批准後應能用同一枚自選口令登入：%v", err)
	}
	if outcome.Principal.AccountID() != target.ID {
		t.Errorf("批准前後必須是同一個穩定身份：%s 對 %s", target.ID, outcome.Principal.AccountID())
	}
	if len(outcome.Principal.Roles()) != 0 {
		t.Errorf("批准只給登入能力，不給伺服器級角色，實際 %v", outcome.Principal.Roles())
	}
	if outcome.MustChangePassword {
		t.Error("批准不該製造首次改密義務（口令一直是本人自選的）")
	}
	if n := countRows(t, e.db, "sessions"); n != 1 {
		t.Errorf("登入之後才該有一份會話，實際 %d 行", n)
	}
}

// TestRejectedApplicantStaysOutside 拒絕之後仍然沒有普通權限（本步驗收要求第二條）：
// 他登不進去，庫裡沒有任何授予與會話，而帳戶表根本沒有一格能放審核人或備註——
// 「內部備註與可公開理由都不落庫」要在表形狀上被查證，而不是隻寫在註解裡。
func TestRejectedApplicantStaysOutside(t *testing.T) {
	e := newEnv(t)
	reviewer := newAdmin(t)
	target := e.mustApplication(t, "Loop.Reject", "會被拒絕的人")
	authService := e.newAuthService(t)
	ctx := context.Background()

	e.mustReview(t, reviewer, target.ID, account.DecisionReject)

	if _, err := authService.LoginAccount(ctx, "Loop.Reject", testPassword, "req-reject",
		"127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("被拒的人必須仍進不去，實際 %v", err)
	}
	if n := countRows(t, e.db, "sessions"); n != 0 {
		t.Errorf("被拒的人不該有任何會話，實際 %d 行", n)
	}
	if n := countRows(t, e.db, "account_server_roles"); n != 0 {
		t.Errorf("被拒的人不該有任何授予，實際 %d 行", n)
	}
	// 本人那側仍能查到自己的結局（上一功能的受限狀態通路，本步不改它的形態）：
	// 讀到的形態是 rejected 帶著一個決定時刻，而沒有審核人、理由之類的格子存在。
	row := readRow(t, e.db, target.ID)
	if row.Status != "rejected" || !row.ReviewedAt.Valid {
		t.Errorf("本人查狀態要讀到的形態不對：%s", row)
	}
	columns := accountColumns(t, e.db)
	if !strings.Contains(columns, "reviewed_at") {
		t.Fatalf("accounts 該有決定時刻那一欄（上一功能落的）：%s", columns)
	}
	for _, forbidden := range []string{"reviewer", "note", "reason", "comment"} {
		if strings.Contains(columns, forbidden) {
			t.Errorf("帳戶表不該有審核人或備註欄（內部備註隔離的結構面）：%s", columns)
		}
	}
}

// accountColumns 列出 accounts 表的欄位名（結構斷言用）。
func accountColumns(t *testing.T, db *database.DB) string {
	t.Helper()
	rows, err := db.SQL().QueryContext(context.Background(), "PRAGMA table_info(accounts)")
	if err != nil {
		t.Fatalf("讀取 accounts 形狀失敗：%v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var (
			seq        int64
			name, typ  string
			notNull    int64
			defaultVal sql.NullString
			pk         int64
		)
		if err := rows.Scan(&seq, &name, &typ, &notNull, &defaultVal, &pk); err != nil {
			t.Fatalf("讀取 accounts 列失敗：%v", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍曆 accounts 形狀失敗：%v", err)
	}
	return strings.Join(names, ",")
}

// auditFieldNames 從 changes_json 裡取出被記下的欄位名（排序後回傳，斷言才穩定）。
//
// changes_json 的形態是 [{"field":...,"before":...,"after":...}, ...]，由 internal/audit 編碼；
// 這裡用標準庫解碼只為把欄名取出來比對——這一條釘的是「決定留下的前後摘要裡
// 沒有一格能容下審核者的隨筆」。
func auditFieldNames(t *testing.T, changesJSON string) []string {
	t.Helper()
	var parsed []struct {
		Field string `json:"field"`
	}
	if err := json.Unmarshal([]byte(changesJSON), &parsed); err != nil {
		t.Fatalf("解析審計 changes_json 失敗：%v（原文 %s）", err, changesJSON)
	}
	fields := make([]string, 0, len(parsed))
	for _, item := range parsed {
		fields = append(fields, item.Field)
	}
	sort.Strings(fields)
	return fields
}

// newAuthService 用同一份現場組一個真實的登入用例（批准之後的閉環要經它復核）。
//
// 少這一步就會變成「我斷言了 status 是 active」而不是「他確實進得去了」。
func (e *env) newAuthService(t *testing.T) *auth.Service {
	t.Helper()
	rootHash, err := credential.Hash(testRootPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試 Root 憑據失敗：%v", err)
	}
	sessions, err := session.NewStoreWithPolicy(e.clock, time.Hour, session.Policy{})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	service, err := auth.New(auth.Deps{
		DB:               e.db,
		Sessions:         sessions,
		Accounts:         e.accounts,
		Grants:           e.grants,
		Audits:           audit.NewStore(e.clock),
		RootPasswordHash: rootHash,
		Hashing:          credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立登入用例失敗：%v", err)
	}
	return service
}
