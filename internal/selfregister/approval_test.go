package selfregister

// 本檔案釘的是 approval 准入這一側的服務層事實：提交落成的是「等待審批」而不是「已激活」，
// 等待中的人不能經任何既有通路取得登入能力，而他能查到的只有自己那一份申請的結局。
//
// 「批准／拒絕」這個動作本身屬下一步（用戶批准的範圍切分），因此這裡不經任何生產通路改狀態：
// 需要一個「已被批准」或「已被拒絕」的現場時，由測試直接對 accounts 下那一跳 UPDATE，
// 並把這個手法說清楚——它是模擬下一步效果的探針，不是留給產品的一条後門。
// 生產代碼裡沒有一句能把 pending 改成 active：account.Store.SetStatus 的 CAS 只認
// active|disabled 兩側，而那正是「審批不能借用停用／恢復通路」的結構證據（這裡也復核一次）。

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// reviewedAt 是探針種出的「審核決定時刻」：晚於注入時鐘的起點（created_at），
// 因此不會撞上遷移 0009 那條「決定不早於帳戶誕生」的單調 CHECK。
var reviewedAt = testBase.Add(90 * time.Minute)

// plantReview 把一筆申請推到「已被批准」或「已被拒絕」：一條 UPDATE 同時落 status 與
// reviewed_at，正是下一步審批用例將來要做的那一跳。
//
// 刻意不經任何生產方法呼叫：本步不實作審批，也不留一個「能改狀態的入口」讓人誤當成後門。
func plantReview(t *testing.T, e *env, accountID idgen.ID, status account.Status) {
	t.Helper()
	res, err := e.db.SQL().ExecContext(context.Background(),
		"UPDATE accounts SET status = ?, reviewed_at = ? WHERE id = ?",
		string(status), timeutil.ToMillis(reviewedAt), accountID.String())
	if err != nil {
		t.Fatalf("種出審核後的形態失敗：%v", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		t.Fatalf("種出審核後的形態應恰好命中一行，實際 affected=%d err=%v", n, err)
	}
}

// mustStatus 查本人狀態並在失敗時終止測試。
func mustStatus(t *testing.T, e *env, login, password string) ApplicationStatus {
	t.Helper()
	status, err := e.service.ApplicationStatus(context.Background(),
		ApplicationStatusInput{LoginName: login, Password: password}, "req-status", "203.0.113.20")
	if err != nil {
		t.Fatalf("查 %s 的狀態失敗：%v", login, err)
	}
	return status
}

// statusErr 查本人狀態並只回傳錯誤（多數用例要的是那句結論本身）。
func statusErr(t *testing.T, e *env, login, password, source string) error {
	t.Helper()
	_, err := e.service.ApplicationStatus(context.Background(),
		ApplicationStatusInput{LoginName: login, Password: password}, "req-status", source)
	return err
}

// TestApprovalModeCreatesPending 核准模式下提交＝收一筆待審批申請：
// 主體形態仍是 standard、口令仍是本人自選，差別落在 status 一欄，且審計如實記下那個值。
func TestApprovalModeCreatesPending(t *testing.T) {
	e := newEnvWithPolicy(t, lenientGuard(), acctpolicy.ModeApproval)
	created := e.mustRegister(t, "Apply.One", "第一個申請", testPassword)

	if created.Status != account.StatusPending {
		t.Errorf("approval 模式必須落成 pending，實際 %q", created.Status)
	}
	if created.MustChangePassword {
		t.Error("口令是本人自選的，待審批不該順帶給他一個「首次必改密」的義務")
	}
	if created.AccountID.IsNil() {
		t.Error("統一帳戶模型：申請一落地就該有穩定標識")
	}

	var (
		accountType, status  string
		mustChange, reviewed sql.NullInt64
		passwordHash         string
	)
	if err := e.db.SQL().QueryRowContext(context.Background(), `SELECT account_type, status,
		must_change_password, password_hash, reviewed_at FROM accounts WHERE id = ?`,
		created.AccountID.String()).Scan(&accountType, &status, &mustChange, &passwordHash, &reviewed); err != nil {
		t.Fatalf("讀回待審批帳戶失敗：%v", err)
	}
	if accountType != "standard" || status != "pending" {
		t.Errorf("落庫形態應為 standard/pending，實際 %s/%s", accountType, status)
	}
	if mustChange.Int64 != 0 {
		t.Error("must_change_password 必須為 0（口令本人自選）")
	}
	if !strings.HasPrefix(passwordHash, "$argon2id$") {
		t.Error("待審批帳戶也要持有自己的憑據雜湊——否則查狀態時沒有可驗證的下落")
	}
	if reviewed.Valid {
		t.Error("還沒有人做過決定，reviewed_at 必須是 NULL（遷移 0009 的同名 CHECK 在域層也要成立）")
	}

	// 審計如實記下落成的狀態：這是日後區分「收了申請」與「建了帳戶」的唯一留證處。
	var changes string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT changes_json FROM root_audit WHERE action = 'account.self_register'").
		Scan(&changes); err != nil {
		t.Fatalf("讀回審計失敗：%v", err)
	}
	if !strings.Contains(changes, "pending") || strings.Contains(changes, `"active"`) {
		t.Errorf("審計的 status 前後值應記為 pending，實際 %s", changes)
	}
	if n := countRows(t, e.db, "account_server_roles"); n != 0 {
		t.Errorf("待審批的申請人不該有任何伺服器級授予，實際 %d 行", n)
	}
}

// TestPendingApplicationCannotSignIn 待審批不等於已激活：同一枚正確的口令走既有登入通路
// 必須被拒（與「口令錯」同一句話），而且一個會話都不產生。
//
// 這條是整個功能最要緊的接縫：待審批帳戶持有可用的憑據雜湊，如果登入那側的判定
// 從「status 不是 active 就拒」變成任何一種寬鬆，等待中的人就進去了。
func TestPendingApplicationCannotSignIn(t *testing.T) {
	e := newEnvWithPolicy(t, lenientGuard(), acctpolicy.ModeApproval)
	created := e.mustRegister(t, "Apply.Wait", "等待中", testPassword)
	authService := e.newAuthService(t)

	_, err := authService.LoginAccount(context.Background(), "apply.wait", testPassword,
		"req-login", "127.0.0.1")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("待審批帳戶以正確口令登入也必須被拒為憑據無效，實際 %v", err)
	}
	if n := countRows(t, e.db, "sessions"); n != 0 {
		t.Errorf("被拒的登入不得產生會話，實際 %d 行", n)
	}
	// 停用／恢復那條 CAS 通路也碰不到他：兩個狀態值都被鎖在 active|disabled，
	// 而 pending 從兩側都進不去——「借恢復之名批准」沒有這條路。
	changed, err := e.accounts.SetStatus(context.Background(), e.db.SQL(), created.AccountID,
		account.StatusActive, account.StatusPending)
	if err == nil || changed {
		t.Errorf("SetStatus 不該能把待審批帳戶改成可用（changed=%v err=%v）", changed, err)
	}
	if n := countRows(t, e.db, "sessions"); n != 0 {
		t.Errorf("被拒的 CAS 不該留下任何會話，實際 %d 行", n)
	}
}

// TestApplicationStatusReportsPending 本人查狀態：憑據對就回報 pending，
// 帶出提交時刻（＝帳戶建立時刻），且刻意不帶決定時刻。
func TestApplicationStatusReportsPending(t *testing.T) {
	e := newEnvWithPolicy(t, lenientGuard(), acctpolicy.ModeApproval)
	created := e.mustRegister(t, "Apply.Query", "查得到", testPassword)

	status := mustStatus(t, e, "Apply.Query", testPassword)
	if status.Outcome != OutcomePending {
		t.Errorf("結局應為 pending，實際 %q", status.Outcome)
	}
	if !status.SubmittedAt.Equal(created.CreatedAt) {
		t.Errorf("submitted_at 應就是提交時刻 %v，實際 %v", created.CreatedAt, status.SubmittedAt)
	}
	if !status.ReviewedAt.IsZero() {
		t.Errorf("還沒決定就不該有決定時刻，實際 %v", status.ReviewedAt)
	}
	// 大小寫與全形變體是同一個人：正規化鍵比對，與登入同一語意。
	if got := mustStatus(t, e, "ＡＰＰＬＹ.ＱＵＥＲＹ", testPassword); got.Outcome != OutcomePending {
		t.Errorf("正規化變體應查到同一份申請，實際 %q", got.Outcome)
	}
	// 查狀態不是登入：它一次會話都不簽發，也不留下任何可複用的憑據。
	if n := countRows(t, e.db, "sessions"); n != 0 {
		t.Errorf("查狀態不得產生會話，實際 %d 行", n)
	}
	// 也不寫審計：它讀的是申請人自己的事實，拒絕與成功都不該成為寫入放大器。
	if n := countRows(t, e.db, "root_audit"); n != 1 {
		t.Errorf("除提交那筆之外不該有更多審計，實際 %d 筆", n)
	}
}

// TestApplicationStatusApprovedAndRejected 已批准與已拒絕各自回自己的那句，並帶出決定時刻。
//
// 「已批准」這一格特別要釘：一個人被批准之後 status 已是 active，若查詢只看 status，
// 他會收到「你不是待審批申請」那句錯話。區分的依據是 reviewed_at——
// 那個時刻記的是「他確實被審核過」，而它不會因為此後被停用或刪除而消失。
func TestApplicationStatusApprovedAndRejected(t *testing.T) {
	e := newEnvWithPolicy(t, lenientGuard(), acctpolicy.ModeApproval)
	approved := e.mustRegister(t, "Apply.Approved", "已批准", testPassword)
	rejected := e.mustRegister(t, "Apply.Rejected", "已拒絕", testPassword)
	approvedThenDisabled := e.mustRegister(t, "Apply.ThenOff", "批准後停用", testPassword)

	plantReview(t, e, approved.AccountID, account.StatusActive)
	plantReview(t, e, rejected.AccountID, account.StatusRejected)
	// 「批准之後再被停用」要走兩跳：先批准（探針種出），再經既有的停用通路
	// （那是生產原語，active→disabled 對一個已批准的人本來就做得了）。
	plantReview(t, e, approvedThenDisabled.AccountID, account.StatusActive)
	if _, err := e.accounts.SetStatus(context.Background(), e.db.SQL(), approvedThenDisabled.AccountID,
		account.StatusDisabled, account.StatusActive); err != nil {
		t.Fatalf("批准後停用失敗：%v", err)
	}

	if got := mustStatus(t, e, "Apply.Approved", testPassword); got.Outcome != OutcomeApproved {
		t.Errorf("批准後的結局應為 approved，實際 %q", got.Outcome)
	}
	got := mustStatus(t, e, "Apply.Rejected", testPassword)
	if got.Outcome != OutcomeRejected {
		t.Errorf("拒絕後的結局應為 rejected，實際 %q", got.Outcome)
	}
	if !got.ReviewedAt.Equal(reviewedAt.UTC()) {
		t.Errorf("拒絕應帶出決定時刻 %v，實際 %v", reviewedAt.UTC(), got.ReviewedAt)
	}
	// 批准之後被人停用：申請結局仍是已批准（這句回答的是申請，不是他此刻能不能登入）。
	if again := mustStatus(t, e, "Apply.ThenOff", testPassword); again.Outcome != OutcomeApproved {
		t.Errorf("批准後被停用的人不該被說成「不是申請」，實際 %q", again.Outcome)
	}
}

// TestApplicationStatusIsUniformAboutOthers 憑據不成立的四種下落收斂成同一句話：
// 查無此名、口令不符、訪客帳戶（無憑據可對）、以及一個根本不在審批鏈上的普通帳戶。
//
// 前三者必須完全同形，否則這條通路就是一部存在性探測器；第四者只在「已經證明你是他本人」
// 之後才可能出現，因此它只對持有人說話。
func TestApplicationStatusIsUniformAboutOthers(t *testing.T) {
	e := newEnvWithPolicy(t, lenientGuard(), acctpolicy.ModeApproval)
	e.mustRegister(t, "Apply.Known", "認識的名字", testPassword)

	// 訪客帳戶：無口令，因此對任何人都不能回報「他在等」。
	// 用帳戶倉儲直接種一筆（訪客註冊通路尚未實作，這是探針手法不是產品入口）。
	if _, err := e.accounts.Create(context.Background(), e.db.SQL(), account.NewInput{
		LoginName: "guest.holder", DisplayName: "訪客", Type: account.TypeGuest,
		Status: account.StatusActive,
	}); err != nil {
		t.Fatalf("種訪客帳戶失敗：%v", err)
	}

	for _, tc := range []struct{ name, login, password string }{
		{"查無此名", "nobody.here", testPassword},
		{"口令不符", "Apply.Known", "不對的口令"},
		{"口令為空", "Apply.Known", ""},
		{"口令超長", "Apply.Known", strings.Repeat("x", credential.MaxPasswordLength+1)},
		{"訪客帳戶", "guest.holder", testPassword},
	} {
		if err := statusErr(t, e, tc.login, tc.password, "203.0.113.21"); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s：應收斂為憑據無效，實際 %v", tc.name, err)
		}
	}

	// 合規但根本不是申請的帳戶（開放自註冊建的）：先建成 active，再用同一枚口令查。
	e.setSelfRegisterMode(t, acctpolicy.ModeOpen)
	notAnApplication := e.mustRegister(t, "Plain.Open", "直接可用", testPassword)
	if notAnApplication.Status != account.StatusActive {
		t.Fatalf("前提跑偏：開放模式該落成 active，實際 %q", notAnApplication.Status)
	}
	if err := statusErr(t, e, "Plain.Open", testPassword, "203.0.113.22"); !errors.Is(err, ErrNotAnApplication) {
		t.Errorf("已證明身分又不是申請的，應回 ErrNotAnApplication，實際 %v", err)
	}

	// 不合規的登入名是本次寫法的問題，點名欄位、與帳戶存在與否無關。
	if err := statusErr(t, e, "含 空白 的名字", testPassword, "203.0.113.23"); !errors.Is(err, account.ErrInvalidLogin) {
		t.Errorf("不合規登入名應被域規則擋下，實際 %v", err)
	}
}

// TestApplicationStatusSurvivesModeSwitch 模式只管新提交：Root 之後把 approval 改成 closed
// 或 open，都不能替已經交上來的申請做決定，那些申請照樣查得到、也照樣沒有登入能力。
//
// 用戶批准的歷史保留策略在這裡落地：切模式不刪、不放行，只影響之後的提交。
func TestApplicationStatusSurvivesModeSwitch(t *testing.T) {
	e := newEnvWithPolicy(t, lenientGuard(), acctpolicy.ModeApproval)
	created := e.mustRegister(t, "Apply.History", "歷史申請", testPassword)
	if created.Status != account.StatusPending {
		t.Fatalf("前提跑偏：approval 模式該落成 pending，實際 %q", created.Status)
	}

	for _, mode := range []acctpolicy.Mode{acctpolicy.ModeClosed, acctpolicy.ModeOpen, acctpolicy.ModeApproval} {
		e.setSelfRegisterMode(t, mode)
		got := mustStatus(t, e, "Apply.History", testPassword)
		if got.Outcome != OutcomePending {
			t.Errorf("模式切成 %s 後歷史申請該照舊可查，實際 %q", mode, got.Outcome)
		}
		if n := countRows(t, e.db, "sessions"); n != 0 {
			t.Errorf("切模式不該讓任何人取得會話，實際 %d 行", n)
		}
	}

	// 同名重複提交由登入名唯一索引收口：換成 open 也不能拿同一個名字再建一筆，
	// 而切回 closed 之後新的提交一律被策略擋下（這才是「只管新提交」的另一側）。
	e.setSelfRegisterMode(t, acctpolicy.ModeOpen)
	if _, err := e.service.RegisterAccount(context.Background(), RegisterInput{
		LoginName: "apply.history", DisplayName: "想用同一名字", Password: testPassword,
	}, "req-dup", "203.0.113.24"); !errors.Is(err, ErrDuplicateLogin) {
		t.Errorf("歷史申請佔住的登入名重複提交應回重名結論，實際 %v", err)
	}
	e.setSelfRegisterMode(t, acctpolicy.ModeClosed)
	if _, err := e.service.RegisterAccount(context.Background(), RegisterInput{
		LoginName: "apply.brandnew", DisplayName: "關閉後提交", Password: testPassword,
	}, "req-closed", "203.0.113.25"); !errors.Is(err, ErrRegisterDisabled) {
		t.Errorf("closed 之後的新提交必須被拒，實際 %v", err)
	}
	if n := countRows(t, e.db, "accounts"); n != 1 {
		t.Errorf("整個過程只該留下那一筆歷史申請，實際 %d 行", n)
	}
}

// TestApplicationStatusThrottled 查狀態用的是「登入那份帳」：失敗額度打滿之後被擋在
// 查庫與派生之前，帶著可判別的冷卻時間；一次憑據成立的查詢勾銷該配對的失敗帳。
func TestApplicationStatusThrottled(t *testing.T) {
	tight := auth.GuardConfig{FailLimit: 3, Window: time.Minute, Cooldown: 5 * time.Minute,
		SourceFailLimit: 1000, MaxEntries: 1000}
	e := newEnvWithGuards(t, lenientGuard(), tight, acctpolicy.ModeApproval)
	e.mustRegister(t, "Apply.Guard", "守衛對象", testPassword)
	source := "203.0.113.30"
	ctx := context.Background()

	for _, password := range []string{"猜一", "猜二", "猜三"} {
		if err := eErr(t, e, ctx, "Apply.Guard", password, source); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("冷卻前的嘗試應是憑據無效，實際 %v", err)
		}
	}
	_, err := e.service.ApplicationStatus(ctx, ApplicationStatusInput{
		LoginName: "Apply.Guard", Password: testPassword,
	}, "req-blocked", source)
	var throttled *ThrottledError
	if !errors.As(err, &throttled) {
		t.Fatalf("打滿額度後的查詢應被限流擋下（連正確口令也不受理），實際 %v", err)
	}
	if throttled.RetryAfter <= 0 {
		t.Errorf("被擋的查詢必須帶正的剩餘冷卻，實際 %v", throttled.RetryAfter)
	}

	// 同一份帳是刻意的：來源對這個名字已經被擋，換一條路（提交註冊）不受影響，
	// 因為那條路走的是另一份預算——兩條路各自的失敗不互相餵飽。
	if _, err := e.service.RegisterAccount(ctx, RegisterInput{
		LoginName: "Apply.Other", DisplayName: "另一條路的預算", Password: testPassword,
	}, "req-other", source); err != nil {
		t.Errorf("查狀態的冷卻不該擋住註冊提交，實際 %v", err)
	}
}

// eErr 是限流用例的小工具：把 ApplicationStatus 的錯誤單獨取出來。
func eErr(t *testing.T, e *env, ctx context.Context, login, password, source string) error {
	t.Helper()
	_, err := e.service.ApplicationStatus(ctx, ApplicationStatusInput{LoginName: login, Password: password},
		"req-probe", source)
	return err
}

// TestApprovedApplicationCanSignIn 批准的效果（用內部種出的那一跳模擬，不經任何生產入口）：
// 同一個人、同一枚口令，從那一刻起走既有登入通路就進得去——
// 「申請→帳戶」不需要搬資料、不需要換標識，這是統一帳戶模型的實際收益。
func TestApprovedApplicationCanSignIn(t *testing.T) {
	e := newEnvWithPolicy(t, lenientGuard(), acctpolicy.ModeApproval)
	created := e.mustRegister(t, "Apply.ToOpen", "會被批准", testPassword)
	authService := e.newAuthService(t)
	ctx := context.Background()

	if _, err := authService.LoginAccount(ctx, "Apply.ToOpen", testPassword, "req-1", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("批准前必須進不去，實際 %v", err)
	}
	plantReview(t, e, created.AccountID, account.StatusActive)

	outcome, err := authService.LoginAccount(ctx, "Apply.ToOpen", testPassword, "req-2", "127.0.0.1")
	if err != nil {
		t.Fatalf("批准後應能用同一枚自選口令登入：%v", err)
	}
	if outcome.Principal.AccountID() != created.AccountID {
		t.Errorf("批准前後必須是同一個穩定身份：%s 對 %s", created.AccountID, outcome.Principal.AccountID())
	}
	if len(outcome.Principal.Roles()) != 0 {
		t.Errorf("批准只給登入能力，不給伺服器級角色，實際 %v", outcome.Principal.Roles())
	}
	if outcome.MustChangePassword {
		t.Error("批准不該順帶製造一個首次改密義務（口令一直是本人自選的）")
	}
}
