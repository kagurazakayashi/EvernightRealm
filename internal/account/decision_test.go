// decision_test.go 是「審批決定」這一跳在倉儲與資料庫層的定向證據：
// 那一條 UPDATE 寫了哪兩欄、沒寫哪幾欄，守衛擋住的是哪些形態，以及決定為什麼是單向的。
//
// 斷言對象是形態本身而不是介面上的字：批准落下的是「可登入＋一個決定時刻」，
// 而一個被批准的人此後不能再被拒絕、一個被拒絕的人此後不能再被批准——
// 這句話如果只寫在註解裡，遲早會有一條途徑把它改成一臺通用狀態編輯器。
//
// 全程使用本次專屬的暫存庫與注入時鐘：不碰任何真實資料目錄，也不留任何憑據材料。
package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// pendingInput 回傳一份合法的待審批申請輸入（approval 模式自註冊落成的就是這個形態：
// standard＋pending＋口令本人自選故不欠首次改密）。
func pendingInput(login string) NewInput {
	return NewInput{
		LoginName:          login,
		DisplayName:        "申請人",
		PasswordHash:       testHash,
		Type:               TypeStandard,
		Status:             StatusPending,
		MustChangePassword: false,
	}
}

// rowSnapshot 是一行 accounts 的可比對快照：把「動了哪些欄」變成一句逐欄對得起來的
// 相等判斷，而不是靠讀回實體時那幾個已經被解釋過的欄位。直寫 SQL 繞過實體校驗，
// 因為這裡要看的恰恰是「資料庫裡此刻躺著什麼」。
type rowSnapshot struct {
	LoginName          string
	LoginKey           string
	DisplayName        string
	PasswordHash       sql.NullString
	AccountType        string
	Status             string
	MustChangePassword int64
	CreatedAt          int64
	LastLoginAt        sql.NullInt64
	DisabledAt         sql.NullInt64
	DeletedAt          sql.NullInt64
	ReviewedAt         sql.NullInt64
}

// snapshot 讀回一行的全部欄位（欄序與 selectAccountSQL 同源）。
func snapshot(t *testing.T, q database.Querier, id idgen.ID) rowSnapshot {
	t.Helper()
	var row rowSnapshot
	err := q.QueryRowContext(context.Background(), `SELECT login_name, login_name_key,
		display_name, password_hash, account_type, status, must_change_password, created_at,
		last_login_at, disabled_at, deleted_at, reviewed_at
		FROM accounts WHERE id = ?`, id.String()).
		Scan(&row.LoginName, &row.LoginKey, &row.DisplayName, &row.PasswordHash,
			&row.AccountType, &row.Status, &row.MustChangePassword, &row.CreatedAt,
			&row.LastLoginAt, &row.DisabledAt, &row.DeletedAt, &row.ReviewedAt)
	if err != nil {
		t.Fatalf("讀取帳戶快照失敗：%v", err)
	}
	return row
}

// diffAgainst 回報兩份快照之間被動過的欄名（空切片代表一個字都沒動）。
//
// 逐欄列名字而不是只回一個 bool：斷言失敗時要一眼看出「哪一欄被越權改寫了」，
// 而 %+v 打印整個結構體時，兩個 sql.NullInt64 的差別根本看不出來。
func (r rowSnapshot) diffAgainst(other rowSnapshot) []string {
	var changed []string
	push := func(name string, same bool) {
		if !same {
			changed = append(changed, name)
		}
	}
	push("login_name", r.LoginName == other.LoginName)
	push("login_name_key", r.LoginKey == other.LoginKey)
	push("display_name", r.DisplayName == other.DisplayName)
	push("password_hash", r.PasswordHash == other.PasswordHash)
	push("account_type", r.AccountType == other.AccountType)
	push("status", r.Status == other.Status)
	push("must_change_password", r.MustChangePassword == other.MustChangePassword)
	push("created_at", r.CreatedAt == other.CreatedAt)
	push("last_login_at", r.LastLoginAt == other.LastLoginAt)
	push("disabled_at", r.DisabledAt == other.DisabledAt)
	push("deleted_at", r.DeletedAt == other.DeletedAt)
	push("reviewed_at", r.ReviewedAt == other.ReviewedAt)
	return changed
}

// String 把差異變成一句可讀的話（測試失敗訊息用）。
func (r rowSnapshot) String() string {
	return fmt.Sprintf("status=%s reviewed_at=%v disabled_at=%v deleted_at=%v must_change=%v",
		r.Status, r.ReviewedAt, r.DisabledAt, r.DeletedAt, r.MustChangePassword)
}

// mustCreate 建立一筆帳戶並在失敗時終止測試。
func mustCreate(t *testing.T, store *Store, db *database.DB, in NewInput) Account {
	t.Helper()
	created, err := store.Create(context.Background(), db.SQL(), in)
	if err != nil {
		t.Fatalf("種入帳戶 %s 失敗：%v", in.LoginName, err)
	}
	return created
}

// countAccounts 數 accounts 的行數（測試取證用，不參與任何生產判定）。
func countAccounts(t *testing.T, db *database.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM accounts").Scan(&n); err != nil {
		t.Fatalf("計數 accounts 失敗：%v", err)
	}
	return n
}

// millisOf 把時刻換成落庫用的毫秒表示（與倉儲寫法同一個轉換點）。
func millisOf(at time.Time) int64 { return timeutil.ToMillis(at) }

// TestDecideApplicationApproveWritesOnlyStatusAndReviewedAt 批准那一跳同時寫 status 與
// reviewed_at，而且只寫這兩欄：憑據、首次改密義務、停用與刪除時刻、兩個名字與來源類型
// 全部原樣留下。「批准不是去認證、也不是解開別種限制」因此成立在 SQL 形狀上。
func TestDecideApplicationApproveWritesOnlyStatusAndReviewedAt(t *testing.T) {
	store, db, at := newTestStore(t)
	ctx := context.Background()

	created := mustCreate(t, store, db, pendingInput("review.approve"))
	before := snapshot(t, db.SQL(), created.ID)
	if before.Status != "pending" || before.ReviewedAt.Valid {
		t.Fatalf("起點形態應是 pending 且無決定時刻，實際 %s/%v", before.Status, before.ReviewedAt)
	}

	changed, err := store.DecideApplication(ctx, db.SQL(), created.ID, DecisionApprove)
	if err != nil {
		t.Fatalf("批准失敗：%v", err)
	}
	if !changed {
		t.Fatal("對一筆還掛在中間的申請批准應寫入成功")
	}

	after := snapshot(t, db.SQL(), created.ID)
	if after.Status != "active" {
		t.Errorf("批准必須落成那個唯一可登入的狀態，實際 %q", after.Status)
	}
	if !after.ReviewedAt.Valid || after.ReviewedAt.Int64 != millisOf(at) {
		t.Errorf("決定時刻必須取自注入時鐘（呼叫端無權代填），實際 %v", after.ReviewedAt)
	}
	// 差異恰好兩欄：少一欄是「半成品」（離開了 pending 卻查不出是誰何時定的），
	// 多一欄就是越過這條通路的職責去動憑據或別種限制。
	if diff := without(after.diffAgainst(before), "status", "reviewed_at"); len(diff) > 0 {
		t.Errorf("批准動到了不該動的欄位：%s（前後快照：%s 對 %s）",
			strings.Join(diff, ","), before, after)
	}

	// 讀回實體復核同一件事（這是各層用例將拿到的形態）。
	got, err := store.ByID(ctx, db.SQL(), created.ID)
	if err != nil {
		t.Fatalf("讀回批准後的帳戶失敗：%v", err)
	}
	if got.Status != StatusActive || got.ReviewedAt.IsZero() || got.MustChangePassword {
		t.Errorf("批准後的實體形態不對：%s/%v/改密=%v", got.Status, got.ReviewedAt, got.MustChangePassword)
	}
	if got.ID != created.ID || got.LoginName != created.LoginName {
		t.Error("統一帳戶模型：批准不搬身份、不換標識")
	}
}

// TestDecideApplicationRejectKeepsRowAndOccupiesName 拒絕落下 rejected＋決定時刻，
// 而行與登入名佔用都保留：同一個正規化鍵再次建立必然撞唯一索引（用戶批准的保留策略——
// 被拒者不能同名重新提交，別人也拿不到那個名字）。
func TestDecideApplicationRejectKeepsRowAndOccupiesName(t *testing.T) {
	store, db, at := newTestStore(t)
	ctx := context.Background()

	created := mustCreate(t, store, db, pendingInput("Review.Reject"))
	if changed, err := store.DecideApplication(ctx, db.SQL(), created.ID, DecisionReject); err != nil || !changed {
		t.Fatalf("拒絕應寫入成功，實際 changed=%v err=%v", changed, err)
	}

	after := snapshot(t, db.SQL(), created.ID)
	if after.Status != "rejected" || !after.ReviewedAt.Valid ||
		after.ReviewedAt.Int64 != millisOf(at) {
		t.Errorf("拒絕必須落成 rejected 並帶決定時刻，實際 %s/%v", after.Status, after.ReviewedAt)
	}
	if after.PasswordHash.String != testHash || after.MustChangePassword != 0 {
		t.Error("拒絕不碰憑據也不製造改密義務——他等的是決定，不是口令")
	}

	if _, err := store.Create(ctx, db.SQL(), pendingInput("review.reject")); err == nil {
		t.Fatal("被拒的登入名必須仍被佔用（大小寫變體也算同一個名字）")
	} else if !errors.Is(err, ErrDuplicateLogin) {
		t.Errorf("同名重新提交應撞唯一索引，實際 %v", err)
	}
	if n := countAccounts(t, db); n != 1 {
		t.Errorf("整個過程只該留下那一筆申請，實際 %d 行", n)
	}
}

// TestDecideApplicationGuardOnlyMatchesPending 守衛是「他此刻還在等著被決定」這一個可觀測事實：
// 五種已經不在那一站的形態一律命中零行、一個字都不落，也不報錯——
// 呼叫端據 changed=false 回可判別的結論，而不是把「什麼都沒寫」說成審批成功。
func TestDecideApplicationGuardOnlyMatchesPending(t *testing.T) {
	store, db, at := newTestStore(t)
	ctx := context.Background()

	// 五種目標：開放通路建成的 active、生下來就停用的 disabled、進入刪除終態的 deleted、
	// 已被批准的人（active 帶決定時刻）、已被拒絕的人（rejected 帶決定時刻）。
	active := mustCreate(t, store, db, standardInput("review.gate.active"))
	disabled := mustCreate(t, store, db, NewInput{
		LoginName: "review.gate.disabled", DisplayName: "被停用",
		PasswordHash: testHash, Type: TypeStandard, Status: StatusDisabled,
		MustChangePassword: true, DisabledAt: at,
	})
	deleted := mustCreate(t, store, db, standardInput("review.gate.deleted"))
	if _, err := store.MarkDeleted(ctx, db.SQL(), deleted.ID, deleted.DisplayName); err != nil {
		t.Fatalf("種出刪除終態失敗：%v", err)
	}
	approved := mustCreate(t, store, db, pendingInput("review.gate.approved"))
	if _, err := store.DecideApplication(ctx, db.SQL(), approved.ID, DecisionApprove); err != nil {
		t.Fatalf("先批准一份申請失敗：%v", err)
	}
	rejected := mustCreate(t, store, db, pendingInput("review.gate.rejected"))
	if _, err := store.DecideApplication(ctx, db.SQL(), rejected.ID, DecisionReject); err != nil {
		t.Fatalf("先拒絕一份申請失敗：%v", err)
	}

	for _, target := range []idgen.ID{active.ID, disabled.ID, deleted.ID, approved.ID, rejected.ID} {
		before := snapshot(t, db.SQL(), target)
		for _, decision := range []Decision{DecisionApprove, DecisionReject} {
			changed, err := store.DecideApplication(ctx, db.SQL(), target, decision)
			if err != nil {
				t.Fatalf("對 %s 下決定不該報錯（那是守衛要擋的，不是故障）：%v", target, err)
			}
			if changed {
				t.Errorf("對 %s（現值 %q）的下一次決定必須命中零行", target, before.Status)
			}
		}
		if diff := snapshot(t, db.SQL(), target).diffAgainst(before); len(diff) > 0 {
			t.Errorf("守衛擋住之後 %s 被改動了 %s", target, strings.Join(diff, ","))
		}
	}
}

// TestDecisionIsOneWay 決定是單向的：批准之後不能被改判成拒絕，拒絕之後也不能被改判成批准，
// 而且後來那次嘗試連決定時刻都不準蓋掉（它命中零行，先前那個時刻仍是當時那個）。
//
// 這一條釘的是用戶批准的形態——審批不是一臺通用狀態編輯器。把這兩格任何一格改成可寫，
// 「兩個審核者只形成一個有效結果」就開始需要第二套依據值才能表達。
func TestDecisionIsOneWay(t *testing.T) {
	store, db, at := newTestStore(t)
	ctx := context.Background()

	approved := mustCreate(t, store, db, pendingInput("review.oneway.approve"))
	if _, err := store.DecideApplication(ctx, db.SQL(), approved.ID, DecisionApprove); err != nil {
		t.Fatalf("批准失敗：%v", err)
	}
	if changed, err := store.DecideApplication(ctx, db.SQL(), approved.ID, DecisionReject); err != nil || changed {
		t.Errorf("已被批准的人不能被改判成拒絕，實際 changed=%v err=%v", changed, err)
	}
	first := snapshot(t, db.SQL(), approved.ID)
	if first.Status != "active" {
		t.Errorf("改判失敗後狀態必須仍是批准落成的那個值，實際 %q", first.Status)
	}

	rejected := mustCreate(t, store, db, pendingInput("review.oneway.reject"))
	if _, err := store.DecideApplication(ctx, db.SQL(), rejected.ID, DecisionReject); err != nil {
		t.Fatalf("拒絕失敗：%v", err)
	}
	if changed, err := store.DecideApplication(ctx, db.SQL(), rejected.ID, DecisionApprove); err != nil || changed {
		t.Errorf("已被拒絕的人不能被改判成批准（今日沒有 reopen 通路），實際 changed=%v err=%v", changed, err)
	}
	if got := snapshot(t, db.SQL(), rejected.ID); got.Status != "rejected" ||
		got.ReviewedAt.Int64 != millisOf(at) {
		t.Errorf("改判失敗後拒絕形態必須原樣留下，實際 %s/%v", got.Status, got.ReviewedAt)
	}
}

// TestDecideApplicationRefusesUnknownDecision 決定值不在封閉集合內屬缺陷而不是業務結論：
// 它在碰到資料庫之前就報錯，一個字都不落。
func TestDecideApplicationRefusesUnknownDecision(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	target := mustCreate(t, store, db, pendingInput("review.baddecision"))

	for _, raw := range []string{"", "pending", "approved", "rejected", "Approve", "approve ", "disabled"} {
		before := snapshot(t, db.SQL(), target.ID)
		changed, err := store.DecideApplication(ctx, db.SQL(), target.ID, Decision(raw))
		if err == nil {
			t.Errorf("決定值 %q 不該被接受", raw)
		} else if !errors.Is(err, ErrUnknownDecision) {
			t.Errorf("決定值 %q 的結論應是可判別的未知決定，實際 %v", raw, err)
		}
		if changed {
			t.Errorf("決定值 %q 不該回報寫入成功", raw)
		}
		if diff := snapshot(t, db.SQL(), target.ID).diffAgainst(before); len(diff) > 0 {
			t.Errorf("非法決定值 %q 落到了資料庫裡：%s", raw, strings.Join(diff, ","))
		}
	}
}

// TestDecideApplicationRequiresTargetAndQuerier 缺目標標識或缺連線都是呼叫缺陷，當場拒絕：
// 一條沒有 WHERE 條件的 UPDATE 會把每一筆待審批申請一起決定掉，那比報錯嚴重得太多。
func TestDecideApplicationRequiresTargetAndQuerier(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	target := mustCreate(t, store, db, pendingInput("review.requires"))

	if _, err := store.DecideApplication(ctx, nil, target.ID, DecisionApprove); err == nil {
		t.Error("缺少資料庫連線時必須拒絕寫入")
	}
	if _, err := store.DecideApplication(ctx, db.SQL(), idgen.Nil, DecisionApprove); err == nil {
		t.Error("缺少目標標識時必須拒絕寫入")
	}
	if n := countAccounts(t, db); n != 1 {
		t.Errorf("兩次拒絕都不該寫出第二筆，實際 %d 行", n)
	}
	if got := snapshot(t, db.SQL(), target.ID); got.Status != "pending" || got.ReviewedAt.Valid {
		t.Errorf("被拒的呼叫必須一個字都不落，實際 %s", got)
	}
}

// TestDecideApplicationInsideTransaction 決定與呼叫端的其他寫入同生同滅：
// 交易回滾時 status 與 reviewed_at 都回到原點（審批用例把帳戶寫入與審計放在同一筆交易，
// 靠的就是倉儲收 database.Querier 這件事）。
func TestDecideApplicationInsideTransaction(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	target := mustCreate(t, store, db, pendingInput("review.rollback"))

	err := db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if _, err := store.DecideApplication(tctx, tx, target.ID, DecisionApprove); err != nil {
			return err
		}
		return errors.New("模擬後續寫入失敗")
	})
	if err == nil {
		t.Fatal("交易應因模擬失敗而回滾")
	}
	if got := snapshot(t, db.SQL(), target.ID); got.Status != "pending" || got.ReviewedAt.Valid {
		t.Errorf("回滾後申請必須仍在等著被決定，實際 %s", got)
	}
}

// TestParseDecisionAndResultMapping 決定的解析入口與落成形態各自只有一份：
// 只認 approve|reject，批准對應那個唯一可登入的取值、拒絕對應 rejected。
func TestParseDecisionAndResultMapping(t *testing.T) {
	for _, raw := range []string{"approve", "reject"} {
		got, err := ParseDecision(raw)
		if err != nil {
			t.Errorf("ParseDecision(%q) 應成功：%v", raw, err)
		}
		if got.String() != raw {
			t.Errorf("決定值繞一圈後變了形：%q 對 %q", raw, got.String())
		}
	}
	for _, raw := range []string{"", " ", "APPROVE", "Approve", "pending", "approved", "rejected",
		"active", "disabled", "deleted", "approve\n"} {
		if _, err := ParseDecision(raw); !errors.Is(err, ErrUnknownDecision) {
			t.Errorf("ParseDecision(%q) 必須拒絕（不接受空白、大小寫變體與申請人側的說法），實際 %v", raw, err)
		}
	}
	if DecisionApprove.result() != StatusActive {
		t.Errorf("批准該落成 active，實際 %q", DecisionApprove.result())
	}
	if DecisionReject.result() != StatusRejected {
		t.Errorf("拒絕該落成 rejected，實際 %q", DecisionReject.result())
	}
}

// TestPendingAndRejectedAreNotSettable 批准與拒絕都不在「停用／恢復」那條通路的可寫集合裡：
// 借那條路把 pending 翻成 active 在原語層面就不成立（否則目錄一顆「恢復」就替一臺伺服器
// 批准了一個人）。同時復核兩個取值在形態上合法——資料庫裡出現它們不是缺陷，是審批的事實。
func TestPendingAndRejectedAreNotSettable(t *testing.T) {
	for _, s := range []Status{StatusPending, StatusRejected, StatusDeleted} {
		if s.settable() {
			t.Errorf("狀態 %q 不該可由停用/恢復通路寫入", s)
		}
		if !s.valid() {
			t.Errorf("狀態 %q 是資料庫認可的形態，valid 必須承認它", s)
		}
	}
	for _, d := range []Decision{DecisionApprove, DecisionReject} {
		if !d.valid() {
			t.Errorf("決定 %q 該在封閉集合內", d)
		}
	}
	if Decision("ghost").valid() {
		t.Error("不在封閉集合內的決定值不能通過復核")
	}
}

// without 從欄名清單裡拿掉本該被動過的那幾個，回剩下的（即「越權改寫」的欄）。
func without(names []string, allowed ...string) []string {
	skip := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		skip[name] = struct{}{}
	}
	var rest []string
	for _, name := range names {
		if _, ok := skip[name]; !ok {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	return rest
}
