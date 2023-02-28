// guestacct_test.go 是「訪客以臨時受限身分進入」用例的定向證據：
// 成功形態（guest／active／無憑據／零授予）與 Root 域系統主體審計的真實落地、
// 會話與建號同筆交易的原子性（含審計或會話寫入失敗時一個孤兒都不留）、
// 准入判定在寫入那一刻現讀、登入名由伺服器產生且不可當作憑據使用、
// 暱稱同名與留空兩條展示路径、嘗試計量（成功也銷預算）與開關關著時不銷預算、
// 會話与普通帳戶同規格（受撤銷與到期約束）、依賴校驗，
// 以及「訪客主體過不了任何需要管理權的判定」這條授權閉環。
//
// 全程使用本次專屬的暫存庫與注入時鐘：不佔 5206、不碰任何真實資料目錄。
package guestacct

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// testBase 是注入時鐘的錨點；testSource 是測試用的來源位址（文檔範例位址，非真實主機）。
var testBase = time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)

const testSource = "203.0.113.20"

// env 是一次測試的完整現場：專屬暫存庫、注入時鐘、策略與會話倉儲，加上組好的訪客用例。
//
// 新環境預設把訪客開關設為開（多數用例要的是「門開著」的現場），並掛一組寬鬆守衛，
// 讓除限流外的用例都不被頻率封頂干擾；限流用例各自換緊守衛，方向由對應用例自己斷言。
type env struct {
	db       *database.DB
	clock    *timeutil.Test
	logs     *bytes.Buffer
	policy   *acctpolicy.Store
	accounts *account.Store
	sessions *session.Store
	service  *Service
}

// lenientGuard 是一組「不會在正常用例裡擋人」的守衛閾值：配對與來源上限都拉到構造上界，
// 視窗與冷卻取最小合法值。如此除限流外的用例只可能因業務結論而失敗，不會混入頻率封頂。
func lenientGuard() auth.GuardConfig {
	return auth.GuardConfig{
		FailLimit:       10000,
		Window:          time.Second,
		Cooldown:        time.Second,
		SourceFailLimit: 10000,
		MaxEntries:      100000,
	}
}

// newEnv 以寬鬆守衛與「訪客開放」起點建立現場。
func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, lenientGuard(), true)
}

// newEnvWith 建立現場並以給定守衛與訪客開關作為起點。
func newEnvWith(t *testing.T, guard auth.GuardConfig, guestEnabled bool) *env {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() {
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			t.Errorf("暫存目錄清理失敗（殘留：%s）：%v", dir, err)
		}
	})
	db, err := database.Open(context.Background(), database.Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := timeutil.NewTest(testBase)
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: clock}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	policyStore := acctpolicy.NewStore(clock)
	if _, err := policyStore.Put(context.Background(), db.SQL(), acctpolicy.Policy{
		AdminCreateStandard: false,
		SelfRegisterMode:    acctpolicy.ModeClosed,
		GuestEnabled:        guestEnabled,
	}); err != nil {
		t.Fatalf("鋪設起點策略失敗：%v", err)
	}
	loginGuard, err := auth.NewLoginGuard(guard, clock)
	if err != nil {
		t.Fatalf("建立訪客守衛失敗：%v", err)
	}
	// 會話倉儲與生產同源：一份注入時鐘、一份絕對期限。裝置策略取 multi，
	// 因為本用例要證的是「訪客拿到的會話与普通帳戶同規格」，不是名額算法本身。
	sessions, err := session.NewStoreWithPolicy(clock, time.Hour, session.Policy{})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	var logs bytes.Buffer
	service, err := New(Deps{
		DB:       db,
		Accounts: account.NewStore(clock),
		Policy:   policyStore,
		Sessions: sessions,
		Audits:   audit.NewStore(clock),
		Guard:    loginGuard,
		Log:      slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("建立訪客用例失敗：%v", err)
	}
	return &env{db: db, clock: clock, logs: &logs, policy: policyStore,
		accounts: account.NewStore(clock), sessions: sessions, service: service}
}

// setGuestEnabled 經策略倉儲（與生產同一個寫入點）翻動訪客開關，其餘兩欄保持原樣：
// 不直寫 SQL，免得繞過策略復核那一層。
func (e *env) setGuestEnabled(t *testing.T, on bool) {
	t.Helper()
	current, err := e.policy.Get(context.Background(), e.db.SQL())
	if err != nil {
		t.Fatalf("讀取當前策略失敗：%v", err)
	}
	if _, err := e.policy.Put(context.Background(), e.db.SQL(), acctpolicy.Policy{
		AdminCreateStandard: current.AdminCreateStandard,
		SelfRegisterMode:    current.SelfRegisterMode,
		GuestEnabled:        on,
	}); err != nil {
		t.Fatalf("設定訪客開關失敗：%v", err)
	}
}

// countRows 數一張表的行數（測試取證用，不參與任何生產判定）。
func countRows(t *testing.T, db *database.DB, table string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("計數 %s 失敗：%v", table, err)
	}
	return n
}

// mustEnter 進入一次並在失敗時終止測試。
func (e *env) mustEnter(t *testing.T, nickname, source string) Outcome {
	t.Helper()
	outcome, err := e.service.Enter(context.Background(), EnterInput{Nickname: nickname},
		"req-"+nickname, source)
	if err != nil {
		t.Fatalf("訪客進入（%q）失敗：%v", nickname, err)
	}
	return outcome
}

// TestEnterWritesGuestAccountSessionAndAudit 成功形態：訪客帳戶、會話與 Root 域系統主體審計
// 一起落地；形態由用例決定（無憑據、無改密旗標、零授予），而會話真的換得出同一個主體。
func TestEnterWritesGuestAccountSessionAndAudit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	outcome := e.mustEnter(t, "夜訪的旅人", testSource)

	var (
		loginName, loginKey, accountType, status string
		hash                                     sql.NullString
		mustChange, createdAt, lastLogin         int64
	)
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT login_name, login_name_key, password_hash,
		account_type, status, must_change_password, created_at, last_login_at FROM accounts WHERE id = ?`,
		outcome.AccountID.String()).
		Scan(&loginName, &loginKey, &hash, &accountType, &status, &mustChange, &createdAt, &lastLogin); err != nil {
		t.Fatalf("讀回新建訪客帳戶失敗：%v", err)
	}
	if accountType != "guest" || status != "active" {
		t.Errorf("訪客進入應建出 guest/active，實際 %s/%s", accountType, status)
	}
	if hash.Valid || hash.String != "" {
		t.Errorf("訪客帳戶不得攜帶憑據雜湊，實際 %q", hash.String)
	}
	if mustChange != 0 {
		t.Error("訪客無密可改：must_change_password 必須為 0")
	}
	if !strings.HasPrefix(loginName, "guest_") {
		t.Errorf("登入名應由伺服器產生（guest_ 前綴），實際 %q", loginName)
	}
	if loginName == "夜訪的旅人" || loginKey != strings.ToLower(loginName) {
		t.Errorf("登入名不得取自本人交來的暱稱，實際 %q（鍵 %q）", loginName, loginKey)
	}
	if got := timeutil.FromMillis(createdAt); !got.Equal(testBase) {
		t.Errorf("建立時刻應取自注入時鐘 %v，實際 %v", testBase, got)
	}
	// 會話簽發與否不靠回傳值自述：直接查庫，並用同一份倉儲把秘密換回主體。
	if n := countRows(t, e.db, "sessions"); n != 1 {
		t.Fatalf("訪客進入應恰好簽發一枚會話，實際 %d 行", n)
	}
	if got := timeutil.FromMillis(lastLogin); !got.Equal(testBase) {
		t.Errorf("最近登入時刻應與建立時刻同源（同一筆交易），實際 %v", got)
	}
	resolved, sess, err := e.sessions.ResolvePrincipal(ctx, e.db.SQL(), outcome.Secret,
		identity.OriginHTTPRequest)
	if err != nil {
		t.Fatalf("剛簽發的秘密必須換得出身分：%v", err)
	}
	if resolved.AccountID() != outcome.AccountID {
		t.Errorf("會話指向的應就是剛建出的帳戶：%s 對 %s", sess.Subject.String(), outcome.AccountID)
	}
	if resolved.AccountType() != account.TypeGuest {
		t.Errorf("解析出的主體類型應為 guest，實際 %q", resolved.AccountType())
	}
	if len(resolved.Roles()) != 0 {
		t.Errorf("訪客主體不得帶任何伺服器級角色，實際 %v", resolved.Roles())
	}
	if outcome.DisplayName != "夜訪的旅人" {
		t.Errorf("展示名應是本人交的那一串，實際 %q", outcome.DisplayName)
	}
	if outcome.Type != account.TypeGuest {
		t.Errorf("回傳結果應如實帶出帳戶類型，實際 %q", outcome.Type)
	}
	// 「訪客不是被授予者」的資料形態：授予表一個字都沒多。
	if n := countRows(t, e.db, "account_server_roles"); n != 0 {
		t.Errorf("訪客進入不得帶出任何伺服器級授予，實際 %d 行", n)
	}

	var (
		action, targetKind, targetID, actorKind string
		actorID                                 sql.NullString
		changes, reason                         string
	)
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT action, target_kind, target_id, actor_kind,
		actor_id, changes_json, reason FROM root_audit WHERE action = 'account.guest_enter'`).
		Scan(&action, &targetKind, &targetID, &actorKind, &actorID, &changes, &reason); err != nil {
		t.Fatalf("讀回審計失敗：%v", err)
	}
	if targetKind != "account" || targetID != outcome.AccountID.String() {
		t.Errorf("審計目標應指向新帳戶，實際 %s/%s", targetKind, targetID)
	}
	if actorKind != string(audit.ActorSystem) {
		t.Errorf("匿名建的動作應記 actor=system，實際 %q", actorKind)
	}
	if actorID.Valid {
		t.Errorf("系統主體的審計 actor_id 必須為 NULL，實際帶值 %q", actorID.String)
	}
	if !strings.Contains(changes, `"guest"`) || !strings.Contains(changes, "must_change_password") {
		t.Errorf("審計變更應如實記下「這是訪客、且不欠改密」，實際 %s", changes)
	}
	if !strings.Contains(reason, "無任何一般憑據") {
		t.Errorf("審計 reason 應講明憑據形態，實際 %q", reason)
	}
	// 「Root 事件不屬於任何活動」的 strongest 形態是結構性的：root_audit 根本沒有這一欄。
	if _, err := e.db.SQL().ExecContext(ctx,
		"SELECT activity_id FROM root_audit LIMIT 0"); err == nil {
		t.Error("root_audit 不該有 activity_id 欄位：那是「Root 事件不屬於任何活動」的結構證據")
	}
}

// TestNoSecretMaterialLeaks 會話秘密明文的去處只有呼叫端（傳輸層的 Set-Cookie）：
// 執行日誌與審計都不得帶著它。Outcome 本身帶秘密是既定形態（與 internal/auth 的
// 登入結果同形），因此這裡查的是「它會不會自己溜進長期保留的痕跡裡」。
func TestNoSecretMaterialLeaks(t *testing.T) {
	e := newEnv(t)
	outcome := e.mustEnter(t, "不留痕", testSource)
	if outcome.Secret == "" {
		t.Fatal("測試前提：簽發要真的交出一枚秘密")
	}

	if strings.Contains(e.logs.String(), outcome.Secret) {
		t.Error("執行日誌不得出現會話秘密明文")
	}
	var auditCount int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE changes_json LIKE ?", "%"+outcome.Secret+"%",
	).Scan(&auditCount); err != nil {
		t.Fatalf("查審計失敗：%v", err)
	}
	if auditCount != 0 {
		t.Error("審計不得出現會話秘密明文")
	}
}

// TestPolicyJudgedAtWriteTime 准入判定讀的是「寫入那一刻」的策略：開關關著時一個字都不寫，
// 事後翻開即放行；反之翻關後的下一條請求立刻被拒。
func TestPolicyJudgedAtWriteTime(t *testing.T) {
	e := newEnvWith(t, lenientGuard(), false)

	if _, err := e.service.Enter(context.Background(), EnterInput{Nickname: "關著的門"},
		"req-off", testSource); !errors.Is(err, ErrGuestDisabled) {
		t.Errorf("訪客開關關著時必須回 ErrGuestDisabled，實際 %v", err)
	}
	for _, table := range []string{"accounts", "sessions", "root_audit"} {
		if n := countRows(t, e.db, table); n != 0 {
			t.Errorf("被策略擋下時 %s 一個字都不該寫，實際 %d 行", table, n)
		}
	}

	e.setGuestEnabled(t, true)
	outcome := e.mustEnter(t, "開著的門", testSource)
	if outcome.AccountID.IsNil() {
		t.Error("翻開後同一條通路应立即受理")
	}

	// 中途再關掉：已經在手的會話不因開關而失效（那屬撤銷與到期的事），
	// 但下一趟進入按新值判定。
	e.setGuestEnabled(t, false)
	if _, err := e.service.Enter(context.Background(), EnterInput{Nickname: "又關了"},
		"req-off-2", testSource); !errors.Is(err, ErrGuestDisabled) {
		t.Errorf("策略中途被關掉後下一條請求必須按新值被拒，實際 %v", err)
	}
}

// TestDisabledPolicyDoesNotConsumeBudget 伺服器狀態決定的拒絕不銷呼叫端的預算：
// 開關關著時反覆敲門不該把正當用戶在 Root 翻開之後一起擋在門外。
func TestDisabledPolicyDoesNotConsumeBudget(t *testing.T) {
	e := newEnvWith(t, auth.GuardConfig{
		FailLimit: 2, Window: time.Minute, Cooldown: time.Minute,
		SourceFailLimit: 2, MaxEntries: 100000,
	}, false)

	for i := 0; i < 5; i++ {
		if _, err := e.service.Enter(context.Background(), EnterInput{Nickname: "敲門"},
			"req-knock", testSource); !errors.Is(err, ErrGuestDisabled) {
			t.Fatalf("第 %d 次敲門應被策略擋下，實際 %v", i+1, err)
		}
	}
	e.setGuestEnabled(t, true)
	// 若上面那五次有幾次銷了預算，這裡第三次起就會變成 2006 而不是受理。
	e.mustEnter(t, "終於開了", testSource)
	e.mustEnter(t, "還開著", testSource)
}

// TestSameNicknameCreatesDistinctAccounts 暱稱只是展示資訊：同名各自成行、
// 標識與登入名都不同，而兩人的會話各自獨立。本步沒有任何「凭昵称認人」的通路。
func TestSameNicknameCreatesDistinctAccounts(t *testing.T) {
	e := newEnv(t)
	first := e.mustEnter(t, "同一個名字", testSource)
	second := e.mustEnter(t, "同一個名字", "203.0.113.21")

	if first.AccountID == second.AccountID {
		t.Error("同暱稱的兩趟進入必須是兩個不同的穩定標識")
	}
	if first.DisplayName != second.DisplayName {
		t.Errorf("展示名應逐字相同（顯示名不承擔唯一性），實際 %q 對 %q", first.DisplayName, second.DisplayName)
	}
	if first.Secret == second.Secret {
		t.Error("兩次簽發的秘密不得相同")
	}
	var loginNames []string
	rows, err := e.db.SQL().QueryContext(context.Background(), `SELECT login_name FROM accounts ORDER BY created_at, id`)
	if err != nil {
		t.Fatalf("讀取登入名失敗：%v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("掃描失敗：%v", err)
		}
		loginNames = append(loginNames, v)
	}
	if len(loginNames) != 2 || loginNames[0] == loginNames[1] {
		t.Errorf("兩趟應各有一個由伺服器產生的不同登入名，實際 %v", loginNames)
	}
}

// TestEmptyNicknameGetsTemporaryNumber 留空暱稱（含只有空白的輸入）時由伺服器產生一個
// 語言中立的臨時編號，而且同樣是「展示資訊」：它不進登入名、也不構成任何找回依據。
func TestEmptyNicknameGetsTemporaryNumber(t *testing.T) {
	e := newEnv(t)
	outcome := e.mustEnter(t, "   ", testSource)
	other := e.mustEnter(t, "", "203.0.113.21")

	matched, err := regexp.MatchString(`^guest-[0-9a-f]{6}$`, outcome.DisplayName)
	if err != nil {
		t.Fatalf("正規式比對失敗：%v", err)
	}
	if !matched {
		t.Errorf("臨時編號應為 guest-<6 個十六位元字元>，實際 %q", outcome.DisplayName)
	}
	if outcome.DisplayName == other.DisplayName {
		t.Errorf("兩趟留空的進入不應拿到同一個臨時編號：%q", outcome.DisplayName)
	}
	if strings.ContainsAny(outcome.DisplayName, "中日韓") {
		t.Error("伺服器產生的展示名不得內嵌任何語言的字詞")
	}
	if outcome.DisplayName == "" {
		t.Error("顯示名不可為空（資料庫 CHECK 也擋）")
	}
}

// TestInvalidNicknameRejectedWithoutWrites 暱稱不合顯示名規則時當場被拒且一個字都不寫：
// 超長、全空白、含控制字元、含格式字元四類都在交易之外就被擋下。
func TestInvalidNicknameRejectedWithoutWrites(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name     string
		nickname string
	}{
		{"超長暱稱", strings.Repeat("夜", 65)},
		{"含控制字元", "夜\x07人"},
		{"含格式字元（零寬連接符）", "夜\u200d人"},
		{"含雙向覆寫符", "夜\u202e人"},
	}
	for _, tc := range cases {
		if _, err := e.service.Enter(context.Background(), EnterInput{Nickname: tc.nickname},
			"req-"+tc.name, testSource); !errors.Is(err, ErrInvalidNickname) {
			t.Errorf("%s 必須被拒為暱稱不合法，實際 %v", tc.name, err)
		}
	}
	for _, table := range []string{"accounts", "sessions", "root_audit"} {
		if n := countRows(t, e.db, table); n != 0 {
			t.Errorf("被輸入校驗擋下時 %s 一個字都不該寫，實際 %d 行", table, n)
		}
	}
}

// TestThrottleCountsSuccess 這條通路的計量單位是「嘗試」而不是「失敗」：
// 成功的那一趟照樣銷預算，於是「開關亮著就無限刷出訪客帳戶」這條線被封死在常數上。
func TestThrottleCountsSuccess(t *testing.T) {
	e := newEnvWith(t, auth.GuardConfig{
		FailLimit: 2, Window: 15 * time.Minute, Cooldown: 15 * time.Minute,
		SourceFailLimit: 10000, MaxEntries: 100000,
	}, true)

	e.mustEnter(t, "第一趟", testSource)
	e.mustEnter(t, "第二趟", testSource)
	if n := countRows(t, e.db, "accounts"); n != 2 {
		t.Fatalf("前兩趟應各建一筆帳戶，實際 %d 行", n)
	}

	var throttled *ThrottledError
	_, err := e.service.Enter(context.Background(), EnterInput{Nickname: "第三趟"},
		"req-3", testSource)
	if !errors.As(err, &throttled) {
		t.Fatalf("第三趟必須被頻率擋下並帶著冷卻時間，實際 %v", err)
	}
	if throttled.RetryAfter <= 0 {
		t.Errorf("被擋的回應要有可用的 Retry-After，實際 %v", throttled.RetryAfter)
	}
	// 被擋的嘗試到不了查庫與寫入：帳戶、會話、審計三張表都停在兩行。
	if n := countRows(t, e.db, "accounts"); n != 2 {
		t.Errorf("被擋的嘗試不得再建號，實際 %d 行", n)
	}
	if n := countRows(t, e.db, "sessions"); n != 2 {
		t.Errorf("被擋的嘗試不得再簽發會話，實際 %d 行", n)
	}

	// 計量主軸是「來源 × 這條通路」：別的來源各有自己的預算（局域网共享位址不被連坐）。
	e.mustEnter(t, "隔壁來源", "203.0.113.99")

	// 冷卻按觸發時刻固定到期：推進注入時鐘越過冷卻線後，同一來源重新受理。
	e.clock.Advance(16 * time.Minute)
	e.mustEnter(t, "冷卻之後", testSource)
}

// TestGuestSessionIsAnOrdinarySession 訪客會話沒有特殊形態：到期、撤銷、主體被停用三個方向
// 都走既有那條解析鏈，不存在一枚「不受撤銷與到期約束」的憑據。
func TestGuestSessionIsAnOrdinarySession(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	outcome := e.mustEnter(t, "同規格的會話", testSource)

	if sess := outcome.Session.State(e.clock.Now()); sess != session.StateActive {
		t.Errorf("剛簽發時應為 active，實際 %s", sess)
	}
	if !outcome.Session.ExpiresAt.Equal(testBase.Add(time.Hour)) {
		t.Errorf("絕對期限應取自裝配的 TTL（1 小時），實際 %v", outcome.Session.ExpiresAt)
	}

	// 到期：推進注入時鐘越過絕對期限，同一枚秘密換不出身分。
	e.clock.Advance(2 * time.Hour)
	if _, _, err := e.sessions.ResolvePrincipal(ctx, e.db.SQL(), outcome.Secret,
		identity.OriginHTTPRequest); !errors.Is(err, session.ErrExpired) {
		t.Errorf("會話到期必須被拒為已到期，實際 %v", err)
	}

	// 撤銷：與普通帳戶同一個 Revoke 寫法，撤完立即換不出身份。
	e2 := newEnv(t)
	fresh := e2.mustEnter(t, "會被撤銷", testSource)
	if _, err := e2.sessions.Revoke(ctx, e2.db.SQL(), fresh.Session.ID); err != nil {
		t.Fatalf("撤銷訪客會話失敗：%v", err)
	}
	if _, _, err := e2.sessions.ResolvePrincipal(ctx, e2.db.SQL(), fresh.Secret,
		identity.OriginHTTPRequest); !errors.Is(err, session.ErrRevoked) {
		t.Errorf("撤銷後必須被拒為已撤銷，實際 %v", err)
	}

	// 主體被停用：會話行還在，但每次解析都現讀帳戶狀態（「視同不存在」）。
	e3 := newEnv(t)
	revokedByAdmin := e3.mustEnter(t, "被管理員停用", testSource)
	changed, err := e3.accounts.SetStatus(ctx, e3.db.SQL(), revokedByAdmin.AccountID,
		account.StatusDisabled, account.StatusActive)
	if err != nil || !changed {
		t.Fatalf("停用訪客帳戶失敗：%v（changed=%v）", err, changed)
	}
	if _, _, err := e3.sessions.ResolvePrincipal(ctx, e3.db.SQL(), revokedByAdmin.Secret,
		identity.OriginHTTPRequest); !errors.Is(err, session.ErrSubjectUnavailable) {
		t.Errorf("主體被停用時會話必須換不出身分，實際 %v", err)
	}
}

// TestSessionFailureRollsBackAccount 會話簽發或審計寫不入時，訪客帳戶一起回滾：
// 庫裡不會留下一個查無會話的孤兒身分，也不會有一枚指向虛假主體的憑據。
func TestSessionFailureRollsBackAccount(t *testing.T) {
	for _, broken := range []string{"sessions", "root_audit"} {
		e := newEnv(t)
		ctx := context.Background()
		if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE "+broken); err != nil {
			t.Fatalf("破壞 %s 失敗：%v", broken, err)
		}
		if _, err := e.service.Enter(ctx, EnterInput{Nickname: "半套"}, "req-broken", testSource); err == nil {
			t.Fatalf("%s 寫入失敗時訪客進入必須整體失敗", broken)
		}
		if n := countRows(t, e.db, "accounts"); n != 0 {
			t.Errorf("%s 寫入失敗後不得留下孤兒訪客帳戶，實際 %d 行", broken, n)
		}
	}
}

// TestLoginNameIsNotACredential 伺服器產生的登入名不是憑據：拿它去走任何一條要口令的路
// 都收斂成「憑據無效」，於是「知道那個名字就能再進去做客」不成立。
func TestLoginNameIsNotACredential(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	outcome := e.mustEnter(t, "口令不對", testSource)

	var loginName string
	if err := e.db.SQL().QueryRowContext(ctx,
		"SELECT login_name FROM accounts WHERE id = ?", outcome.AccountID.String()).Scan(&loginName); err != nil {
		t.Fatalf("讀回登入名失敗：%v", err)
	}

	service, err := auth.New(auth.Deps{
		DB:       e.db,
		Sessions: e.sessions,
		Accounts: e.accounts,
		Audits:   audit.NewStore(e.clock),
	})
	if err != nil {
		t.Fatalf("建立登入用例失敗：%v", err)
	}
	if _, err := service.LoginAccount(ctx, loginName, "任何口令", "req-guest-login", testSource); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("訪客帳戶走口令登入必須收斂為憑據無效，實際 %v", err)
	}
	// 而且這個名字不來自本人：他交的是暱稱，兩者在庫裡從來不是同一格。
	if loginName == "口令不對" {
		t.Error("登入名不得取自暱稱——否則「知道暱稱」就等于「知道登入名」")
	}
}

// TestGuestPrincipalCarriesNoServerLevelAuthority 授權閉環：訪客主體只過 NeedAuthenticated，
// 需要管理權或 Root 的判定當場被拒。這是「不因為他已取得會話就放行普通管理」的證據。
func TestGuestPrincipalCarriesNoServerLevelAuthority(t *testing.T) {
	e := newEnv(t)
	outcome := e.mustEnter(t, "沒有授予", testSource)

	if err := identity.Authorize(outcome.Principal, identity.NeedAuthenticated); err != nil {
		t.Errorf("訪客當然是已認證主體，實際 %v", err)
	}
	if err := identity.Authorize(outcome.Principal, identity.NeedServerAdmin); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("訪客必須過不了伺服器級管理權判定，實際 %v", err)
	}
	if err := identity.Authorize(outcome.Principal, identity.NeedRoot); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("訪客必須過不了 Root 判定，實際 %v", err)
	}
	// 型別層那道閘也在：想經構造參數塞角色進去，走不到會話這一步。
	if _, err := identity.NewAccountPrincipal(identity.AccountInput{
		Subject: identity.AccountSubject{ID: outcome.AccountID, Type: account.TypeGuest,
			Status: account.StatusActive},
		Origin: identity.OriginHTTPRequest,
		Grants: identity.NewServerGrants(identity.RoleServerAdmin),
	}); err == nil {
		t.Error("訪客帳戶持有伺服器級角色必須在構造期就被拒")
	}
}

// TestCanceledContextWritesNothing 請求在交易裡被取消時一個字都不落：
// 不會有一半的訪客身分留在庫裡。
func TestCanceledContextWritesNothing(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.service.Enter(ctx, EnterInput{Nickname: "沒發生"}, "req-cancel", testSource); err == nil {
		t.Fatal("已取消的請求必須失敗")
	}
	for _, table := range []string{"accounts", "sessions", "root_audit"} {
		if n := countRows(t, e.db, table); n != 0 {
			t.Errorf("被取消的請求不該在 %s 留下任何行，實際 %d 行", table, n)
		}
	}
}

// TestResultShapeIsNotRequestControlled 建的形態與請求輸入無關：EnterInput 只有暱稱一欄，
// 類型、狀態、旗標、登入名都由用例決定，回傳值不攜帶任何憑據材料以外的事。
func TestResultShapeIsNotRequestControlled(t *testing.T) {
	e := newEnv(t)
	outcome := e.mustEnter(t, "不自報", testSource)

	if outcome.Type != account.TypeGuest {
		t.Errorf("類型必須恆為 guest，實際 %q", outcome.Type)
	}
	if outcome.Principal.AccountType() != account.TypeGuest {
		t.Errorf("主體類型必須恆為 guest，實際 %q", outcome.Principal.AccountType())
	}
	if got := outcome.Principal.Kind(); got != identity.KindAccount {
		t.Errorf("訪客的主體類別是帳戶，實際 %q", got)
	}
}

// TestNewRejectsMissingDeps 缺依賴是組裝缺陷：在啟動階段就報出來，不帶病上線。
func TestNewRejectsMissingDeps(t *testing.T) {
	e := newEnv(t)
	guard, err := auth.NewLoginGuard(lenientGuard(), e.clock)
	if err != nil {
		t.Fatalf("建立守衛失敗：%v", err)
	}
	sessions, err := session.NewStoreWithPolicy(e.clock, time.Hour, session.Policy{})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	valid := Deps{
		DB: e.db, Accounts: account.NewStore(e.clock), Policy: e.policy,
		Sessions: sessions, Audits: audit.NewStore(e.clock), Guard: guard,
	}
	for _, mutate := range []func(*Deps){
		func(d *Deps) { d.DB = nil },
		func(d *Deps) { d.Accounts = nil },
		func(d *Deps) { d.Policy = nil },
		func(d *Deps) { d.Sessions = nil },
		func(d *Deps) { d.Audits = nil },
		func(d *Deps) { d.Guard = nil },
	} {
		deps := valid
		mutate(&deps)
		if _, err := New(deps); err == nil {
			t.Error("依賴缺失時 New 必須報錯")
		}
	}
}
