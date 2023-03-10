package selfregister

// 本檔案釘的是「已進入刪除終態的人不能再從查狀態通路取得任何證明」這組服務層事實：
// ApplicationStatus 在口令驗證成立之後、回報結局之前有一道終態閘——它是同一句 2001
// （ErrInvalidCredentials），並記一次憑據失敗，因此一個被刪掉的人既拿不回「我申請過、
// 而且被批了」那句話，也無法反覆敲這條門而各次都算成功。
//
// 為什麼這是最重要的產品形態：軟刪除動的是「這個人不再是任何可用帳戶」這件事，
// 若通路繼續照舊回報 approved，刪除就只關掉了登入門、卻留著一張可隨時複讀的歷史證明；
// 若把「他已被刪除」做成一句可分辨的回覆（或一個新機器碼），這條只靠口令認身份的匿名通路
// 就變成「哪些名字存在過而且被刪過」的探測器。兩側都要擋，所以處置收成與其他憑據失敗同形。
//
// 種出刪除終態的手法與本套件其他「鏈外形態」同一取向：status/reviewed_at 用 plantReview
// 那一跳 UPDATE 模擬審批結果（本包不實作審批），刪除終態則走 account.Store.MarkDeleted
// 這個域層生產原語——它是唯一能如實落下 status+deleted_at+匿名顯示名三欄的寫法，
// 管理端的刪除用例在另一個包，這裡不跨包呼叫。全程使用本次專屬暫存庫與注入時鐘。

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// mustDelete 讓一筆帳戶進入刪除終態（域層原語，與管理端刪除用例走的是同一跳）並在失敗時終止測試。
//
// 現行顯示名直接取自註冊結果：MarkDeleted 刻意不回頭多查一次，呼叫端握著什麼就派生什麼。
func mustDelete(t *testing.T, e *env, accountID idgen.ID, currentDisplayName string) {
	t.Helper()
	changed, err := e.accounts.MarkDeleted(context.Background(), e.db.SQL(), accountID, currentDisplayName)
	if err != nil || !changed {
		t.Fatalf("寫入刪除終態失敗：%v（changed=%v）", err, changed)
	}
}

// queryStatus 直接取回 ApplicationStatus 的兩個返回值（本組用例要的是「結論本身」與
// 「那個零值到底帶不帶得出資料」，不能像 mustStatus 那樣在錯誤時直接終止）。
func queryStatus(t *testing.T, e *env, login, password, source string) (ApplicationStatus, error) {
	t.Helper()
	return e.service.ApplicationStatus(context.Background(),
		ApplicationStatusInput{LoginName: login, Password: password}, "req-deleted", source)
}

// TestApplicationStatusDeletedRefusesWithCredentialShape 刪除終態把「已被批准」那句收回：
// 同一枚原本查得到 approved 的正確口令，被刪之後必須拿到與口令錯誤同一個機器碼的結論，
// 且回傳值是一個什麼都不帶的零值。
//
// 若這一格還回 approved，軟刪除就變成「只有登入門關了」：那張「我申請過而且被批了」的證明
// 是刪除要一併收走的東西之一，而且它會被界面原樣渲染成一個仍可用的狀態句。
func TestApplicationStatusDeletedRefusesWithCredentialShape(t *testing.T) {
	e := newEnvWithPolicy(t, lenientGuard(), acctpolicy.ModeApproval)
	created := e.mustRegister(t, "Apply.Deleted", "會被刪除的人", testPassword)
	plantReview(t, e, created.AccountID, account.StatusActive)

	// 前提：刪除之前這句查得到，而且帶出提交與決定兩個時刻。
	before, err := queryStatus(t, e, "Apply.Deleted", testPassword, "203.0.113.40")
	if err != nil {
		t.Fatalf("刪除前應查得到本人申請，實際 %v", err)
	}
	if before.Outcome != OutcomeApproved {
		t.Fatalf("刪除前結局應為 approved，實際 %q", before.Outcome)
	}
	if before.SubmittedAt.IsZero() || before.ReviewedAt.IsZero() {
		t.Fatalf("刪除前該帶出提交與決定時刻，實際 %+v", before)
	}

	mustDelete(t, e, created.AccountID, created.DisplayName)

	got, err := queryStatus(t, e, "Apply.Deleted", testPassword, "203.0.113.40")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("已刪除者以正確口令查狀態必須收成憑據無效（2001），實際 %v", err)
	}
	if err == nil {
		t.Error("已刪除者不得再回報任何申請結局")
	}
	// 零值必須是真正的零值：錯誤路徑上殘留任何一欄，都是把事實從另一扇門遞出去。
	if got.Outcome != ApplicationOutcome("") {
		t.Errorf("被拒時的 Outcome 必須是空值，實際 %q", got.Outcome)
	}
	if !got.SubmittedAt.IsZero() {
		t.Errorf("被拒時不得帶出提交時刻，實際 %v", got.SubmittedAt)
	}
	if !got.ReviewedAt.IsZero() {
		t.Errorf("被拒時不得帶出決定時刻，實際 %v", got.ReviewedAt)
	}
	// 查狀態這條通路本身仍然一個會話都不簽發、也不因被拒而追加審計。
	if n := countRows(t, e.db, "sessions"); n != 0 {
		t.Errorf("被拒的查詢不得產生會話，實際 %d 行", n)
	}
	if n := countRows(t, e.db, "root_audit"); n != 1 {
		t.Errorf("除提交那筆之外不該有更多審計，實際 %d 筆", n)
	}
}

// TestApplicationStatusDeletedCountsAsCredentialFailure 刪除終態那句計一次憑據失敗：
// 同一來源反覆用正確口令查這個已被刪掉的名字，額度打滿之後連正確口令也不受理，
// 帶著可判別的冷卻結論（與 TestApplicationStatusThrottled 同一組閾值、同一句斷言形態）。
//
// 若不計失敗，這條門就是一個「免費重試器」：被刪的人（或拿到他那份口令的人）可以無限次
// 複讀同一句回覆而不付出任何代價，而限流要保護的正是查庫與 Argon2 派生這兩樣最貴的東西。
func TestApplicationStatusDeletedCountsAsCredentialFailure(t *testing.T) {
	tight := auth.GuardConfig{FailLimit: 3, Window: time.Minute, Cooldown: 5 * time.Minute,
		SourceFailLimit: 1000, MaxEntries: 1000}
	e := newEnvWithGuards(t, lenientGuard(), tight, acctpolicy.ModeApproval)
	created := e.mustRegister(t, "Apply.DeletedGuard", "被刪又敲門", testPassword)
	plantReview(t, e, created.AccountID, account.StatusActive)

	// 刪除前那一次是成功：它勾銷該配對的失敗帳，讓接下來的三次失敗只能記在刪除之後。
	source := "203.0.113.41"
	if got, err := queryStatus(t, e, "Apply.DeletedGuard", testPassword, source); err != nil ||
		got.Outcome != OutcomeApproved {
		t.Fatalf("刪除前該查到 approved，實際 %+v err=%v", got, err)
	}
	mustDelete(t, e, created.AccountID, created.DisplayName)

	for i := 0; i < 3; i++ {
		_, err := queryStatus(t, e, "Apply.DeletedGuard", testPassword, source)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("冷卻前的第 %d 次嘗試應是憑據無效，實際 %v", i+1, err)
		}
	}
	_, err := queryStatus(t, e, "Apply.DeletedGuard", testPassword, source)
	var throttled *ThrottledError
	if !errors.As(err, &throttled) {
		t.Fatalf("打滿額度後的查詢應被限流擋下（正確口令也不受理，表示被刪者每次都被計成失敗），實際 %v", err)
	}
	if throttled.RetryAfter <= 0 {
		t.Errorf("被擋的查詢必須帶正的剩餘冷卻，實際 %v", throttled.RetryAfter)
	}

	// 這是「登入那份帳」而不是註冊那條分账的帳：同一來源換一條路（提交新申請）不受影響。
	if _, err := e.service.RegisterAccount(context.Background(), RegisterInput{
		LoginName: "Apply.AfterDelete", DisplayName: "另一條路的預算", Password: testPassword,
	}, "req-other", source); err != nil {
		t.Errorf("查狀態的冷卻不該擋住註冊提交，實際 %v", err)
	}
}

// TestApplicationStatusDeletedIndistinguishableFromWrongPassword 被刪者與兩種旁人不構成分辨面：
// （已刪除＋正確口令）、（仍在的帳戶＋錯口令）、（查無此名）收斂成同一個錯誤值與同一句文字，
// 而一個仍有效的申請人（旁觀者）查自己那份完全不受影響，被拒的這幾筆也不寫審計。
//
// 這一句是刻意的：如果（被刪＋對口令）比（錯口令）多出一個可分辨的機器碼或訊息，
// 未認證的人只要猜中口令就能確認「這個名字存在過而且被刪過」，甚至拿它當刪除名冊的探測器。
func TestApplicationStatusDeletedIndistinguishableFromWrongPassword(t *testing.T) {
	e := newEnvWithPolicy(t, lenientGuard(), acctpolicy.ModeApproval)
	gone := e.mustRegister(t, "Apply.Gone", "已被刪掉", testPassword)
	plantReview(t, e, gone.AccountID, account.StatusActive)
	live := e.mustRegister(t, "Apply.StillHere", "還在的人", testPassword)
	plantReview(t, e, live.AccountID, account.StatusActive)
	e.mustRegister(t, "Apply.Bystander", "旁觀的申請人", testPassword)
	mustDelete(t, e, gone.AccountID, gone.DisplayName)

	auditsBefore := countRows(t, e.db, "root_audit")

	_, errDeleted := queryStatus(t, e, "Apply.Gone", testPassword, "203.0.113.42")
	_, errWrongPassword := queryStatus(t, e, "Apply.StillHere", "不對的口令", "203.0.113.42")
	_, errUnknown := queryStatus(t, e, "nobody.throws", testPassword, "203.0.113.42")

	for i, err := range []error{errDeleted, errWrongPassword, errUnknown} {
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("第 %d 種下落應是憑據無效，實際 %v", i+1, err)
		}
	}
	// 同一個錯誤值：三條路徑都沒有額外包裝，也沒有任何「被刪／錯口令／查無此名」的字樣可供分辨。
	if errDeleted != errWrongPassword || errWrongPassword != errUnknown {
		t.Errorf("三種下落必須是同一個錯誤值，實際 %q / %q / %q", errDeleted, errWrongPassword, errUnknown)
	}
	if a, b := errDeleted.Error(), errWrongPassword.Error(); a != b || b != errUnknown.Error() {
		t.Errorf("三種下落的錯誤文字必須逐字同形，實際 %q / %q / %q", a, b, errUnknown.Error())
	}

	// 旁觀者那份仍然查得到、也仍然帶得出自己的兩個時刻：這道閘只認刪除終態。
	bystander, err := queryStatus(t, e, "Apply.Bystander", testPassword, "203.0.113.42")
	if err != nil {
		t.Fatalf("旁觀申請人的查詢不受影響才對，實際 %v", err)
	}
	if bystander.Outcome != OutcomePending || bystander.SubmittedAt.IsZero() {
		t.Errorf("旁觀申請人應拿到自己的 pending 與提交時刻，實際 %+v", bystander)
	}
	// 被拒的這幾筆不該成為寫入放大器。
	if n := countRows(t, e.db, "root_audit"); n != auditsBefore {
		t.Errorf("被拒的查詢不得追加審計：%d→%d", auditsBefore, n)
	}
	if n := countRows(t, e.db, "sessions"); n != 0 {
		t.Errorf("被拒的查詢不得產生會話，實際 %d 行", n)
	}
}

// TestApplicationStatusRejectedAndPendingUnaffected 把這道閘的作用域鎖在刪除終態：
// pending 仍回 pending、rejected 仍回 rejected（並帶出決定時刻）、已批准但未刪除的仍回 approved；
// 而在緊守衛下反覆成功查詢不會被計成失敗（否則「只擋刪除態」會被稀釋成「擋所有查狀態」）。
//
// 這一條釘的是反向的失控：把三個正常結局一併收成 2001 會讓還在等的人以為自己沒交過申請，
// 而被拒絕的人拿不回「我被拒過、幾點被拒」那句他需要的答案。
func TestApplicationStatusRejectedAndPendingUnaffected(t *testing.T) {
	e := newEnvWithPolicy(t, lenientGuard(), acctpolicy.ModeApproval)
	pending := e.mustRegister(t, "Apply.StaysPending", "還在等", testPassword)
	rejected := e.mustRegister(t, "Apply.StaysRejected", "被拒絕", testPassword)
	approved := e.mustRegister(t, "Apply.StaysApproved", "批准但沒被刪", testPassword)
	plantReview(t, e, rejected.AccountID, account.StatusRejected)
	plantReview(t, e, approved.AccountID, account.StatusActive)
	if pending.Status != account.StatusPending {
		t.Fatalf("前提跑偏：approval 模式該落成 pending，實際 %q", pending.Status)
	}

	if got := mustStatus(t, e, "Apply.StaysPending", testPassword); got.Outcome != OutcomePending {
		t.Errorf("未刪除的 pending 應照舊回 pending，實際 %q", got.Outcome)
	}
	gotRejected := mustStatus(t, e, "Apply.StaysRejected", testPassword)
	if gotRejected.Outcome != OutcomeRejected {
		t.Errorf("未刪除的 rejected 應照舊回 rejected，實際 %q", gotRejected.Outcome)
	}
	if !gotRejected.ReviewedAt.Equal(reviewedAt.UTC()) {
		t.Errorf("rejected 仍該帶出決定時刻 %v，實際 %v", reviewedAt.UTC(), gotRejected.ReviewedAt)
	}
	if gotApproved := mustStatus(t, e, "Apply.StaysApproved", testPassword); gotApproved.Outcome != OutcomeApproved {
		t.Errorf("批准但未被刪除的應照舊回 approved，實際 %q", gotApproved.Outcome)
	}

	// 另一側：成功不計失敗。守衛擰到 2，同一個人連查三次仍全部回報 approved，
	// 一個都不被冷卻擋下——被計成失敗的只有刪除終態那句。
	tight := auth.GuardConfig{FailLimit: 2, Window: time.Minute, Cooldown: 5 * time.Minute,
		SourceFailLimit: 1000, MaxEntries: 1000}
	e2 := newEnvWithGuards(t, lenientGuard(), tight, acctpolicy.ModeApproval)
	again := e2.mustRegister(t, "Apply.RepeatQuery", "連查三次", testPassword)
	plantReview(t, e2, again.AccountID, account.StatusActive)
	source := "203.0.113.43"
	for i := 0; i < 3; i++ {
		got, err := queryStatus(t, e2, "Apply.RepeatQuery", testPassword, source)
		var throttled *ThrottledError
		if errors.As(err, &throttled) {
			t.Fatalf("第 %d 次成功查詢被誤記成失敗而進入冷卻：%v", i+1, err)
		}
		if err != nil || got.Outcome != OutcomeApproved {
			t.Fatalf("第 %d 次成功查詢應回報 approved，實際 %+v err=%v", i+1, got, err)
		}
	}
}
