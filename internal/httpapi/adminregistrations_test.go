// adminregistrations_test.go 是「審批註冊申請」在傳輸層的端到端證據：
// 從 Root 把模式設成 approval、門外的人交上一份申請，一路走到管理員讀名冊、批准或拒絕，
// 以及那一跳之後申請人能不能登入。
//
// 刻意不收的東西：
//   - 沒有替身：授權、首次改密門閂、來源判定、範圍核實、決定落庫與審計都跨層走真路徑，
//     接錯線就會紅（審批是最容易被「界面擋住了就算」誤導的一格，協定層與資料庫必須同時站住）；
//   - 不碰任何真實資料目錄、不佔 5206，全程用本次專屬的暫存庫與系統時鐘。
package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctreview"
	"github.com/kagurazakayashi/EvernightRealm/internal/adminacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/guestbind"
	"github.com/kagurazakayashi/EvernightRealm/internal/invitecode"
	"github.com/kagurazakayashi/EvernightRealm/internal/selfregister"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/stdacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 測試口令：只活在測試進程的記憶體，不是任何環境的憑據。
const (
	reviewTestRootPassword  = "adminregistrations-test-root-口令"
	reviewTestAdminPassword = "adminregistrations-test-管理員初始口令"
	reviewTestAdminChanged  = "adminregistrations-test-管理員改後口令"
	reviewTestApplicant     = "adminregistrations-test-申請人自選口令"
)

// reviewEnv 是本次測試專屬的現場：真資料庫＋全部相關用例＋一臺掛了審批端點的測試服務。
type reviewEnv struct {
	ts *httptest.Server
	db *database.DB
	// reviewOnly 為「只注入審批用例」的另一個現場由 newReviewOnlyServer 另給。
}

// newReviewEnv 建立現場並啟動測試服務。
//
// 裝配形狀與 internal/app 一致：自註冊的提交守衛與查狀態守衛是兩個實例，
// 而名冊與決定用的是同一份帳戶、授予與審計倉儲——少一條就會測不到生產上的接線。
func newReviewEnv(t *testing.T) *reviewEnv {
	t.Helper()
	clock := timeutil.System()
	dir := t.TempDir()
	db, err := database.Open(context.Background(), database.Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			t.Errorf("暫存目錄清理失敗（殘留：%s）：%v", dir, err)
		}
	})
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: clock}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}

	accountsStore := account.NewStore(clock)
	grantsStore := grant.NewStore(clock)
	auditStore := audit.NewStore(clock)
	policyStore := acctpolicy.NewStore(clock)
	sessions, err := session.NewStoreWithPolicy(clock, time.Hour, session.Policy{})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	rootHash, err := credential.Hash(reviewTestRootPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試 Root 憑據失敗：%v", err)
	}
	guardConfig := auth.GuardConfig{FailLimit: 10000, Window: time.Second, Cooldown: time.Second,
		SourceFailLimit: 10000, MaxEntries: 100000}
	registerGuard, err := auth.NewLoginGuard(guardConfig, clock)
	if err != nil {
		t.Fatalf("建立註冊守衛失敗：%v", err)
	}
	loginGuard, err := auth.NewLoginGuard(guardConfig, clock)
	if err != nil {
		t.Fatalf("建立登入守衛失敗：%v", err)
	}
	authService, err := auth.New(auth.Deps{
		DB: db, Sessions: sessions, Accounts: accountsStore, Grants: grantsStore,
		Audits: auditStore, RootPasswordHash: rootHash, Hashing: credential.TestParams,
		Guard: loginGuard,
	})
	if err != nil {
		t.Fatalf("建立登入用例失敗：%v", err)
	}
	adminService, err := adminacct.New(adminacct.Deps{
		DB: db, Accounts: accountsStore, Grants: grantsStore,
		Audits: auditStore, Sessions: sessions, Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立管理員用例失敗：%v", err)
	}
	policyService, err := acctpolicy.New(acctpolicy.Deps{DB: db, Store: policyStore, Audits: auditStore})
	if err != nil {
		t.Fatalf("建立策略用例失敗：%v", err)
	}
	stdService, err := stdacct.New(stdacct.Deps{
		DB: db, Accounts: accountsStore, Grants: grantsStore, Policy: policyStore,
		Sessions: sessions, Audits: auditStore,
		BindTickets: guestbind.NewStore(clock), Clock: clock,
		Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立普通帳戶用例失敗：%v", err)
	}
	registerService, err := selfregister.New(selfregister.Deps{
		DB: db, Accounts: accountsStore, Policy: policyStore,
		Invites: invitecode.NewStore(clock), Audits: auditStore,
		Guard: registerGuard, CredentialGuard: loginGuard,
		Hashing: credential.TestParams, HashConcurrency: 2,
	})
	if err != nil {
		t.Fatalf("建立自註冊用例失敗：%v", err)
	}
	reviewService, err := acctreview.New(acctreview.Deps{
		DB: db, Accounts: accountsStore, Grants: grantsStore, Audits: auditStore,
	})
	if err != nil {
		t.Fatalf("建立審批用例失敗：%v", err)
	}
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{
		Auth: authService, Admins: adminService, AccountPolicy: policyService,
		StandardAccounts: stdService, SelfRegister: registerService,
		RegistrationReview: reviewService, Clock: clock,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &reviewEnv{ts: ts, db: db}
}

// rootCookie 以測試 Root 口令登入並取得本次專用的會話 Cookie。
func (e *reviewEnv) rootCookie(t *testing.T) *http.Cookie {
	t.Helper()
	resp := postJSON(t, e.ts, "/auth/root/login",
		`{"password":"`+reviewTestRootPassword+`"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 登入應成功：%d %s", resp.StatusCode, body)
	}
	return loginCookie(t, resp)
}

// setSelfRegisterMode 經策略端點（Root 的真路徑）翻動 self_register_mode，其餘兩欄按出廠形態寫回。
func (e *reviewEnv) setSelfRegisterMode(t *testing.T, mode string) {
	t.Helper()
	root := e.rootCookie(t)
	resp := putJSON(t, e.ts, "/root/account-policy", policyBody(false, mode, false), "",
		map[string]string{"Cookie": cookieHeader(root)})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("保存策略應成功：%d %s", resp.StatusCode, body)
	}
}

// liveAdminCookie 走完整交付鏈取得一位「已完成首次改密」的管理員會話。
func (e *reviewEnv) liveAdminCookie(t *testing.T, login string) *http.Cookie {
	t.Helper()
	root := e.rootCookie(t)
	resp := postJSON(t, e.ts, "/root/admins",
		`{"login_name":"`+login+`","display_name":"現行管理員","password":"`+reviewTestAdminPassword+`"}`,
		"", map[string]string{"Cookie": cookieHeader(root)})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 開設管理員應成功：%d %s", resp.StatusCode, body)
	}
	first := e.loginAs(t, login, reviewTestAdminPassword)
	cookie := loginCookie(t, first)
	changed := postJSON(t, e.ts, "/auth/password/change",
		`{"current_password":"`+reviewTestAdminPassword+`","new_password":"`+reviewTestAdminChanged+`"}`,
		"", map[string]string{"Cookie": cookieHeader(cookie)})
	if changed.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(changed.Body)
		t.Fatalf("首次改密應成功：%d %s", changed.StatusCode, body)
	}
	return loginCookie(t, e.loginAs(t, login, reviewTestAdminChanged))
}

// loginRaw 發一次帳戶登入並原樣回傳回應。
func (e *reviewEnv) loginRaw(t *testing.T, login, password string) *http.Response {
	t.Helper()
	return postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+password+`"}`, "", nil)
}

// loginAs 以登入名與口令取得會話回應，不成功即終止。
func (e *reviewEnv) loginAs(t *testing.T, login, password string) *http.Response {
	t.Helper()
	resp := e.loginRaw(t, login, password)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("登入 %s 應成功：%d %s", login, resp.StatusCode, body)
	}
	return resp
}

// fileApplication 讓一個匿名申請人經 /auth/register 交上一份申請（模式必須已是 approval）。
func (e *reviewEnv) fileApplication(t *testing.T, login, display string) map[string]any {
	t.Helper()
	resp := postJSON(t, e.ts, "/auth/register", registerBody(login, display, reviewTestApplicant),
		"", nil)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("提交申請 %q 應成功：%d %s", login, resp.StatusCode, body)
	}
	return decodeJSONBody(t, resp)
}

// roster 讀一頁名冊（GET），並回解析後的回應本體。
func (e *reviewEnv) roster(t *testing.T, query string, cookie *http.Cookie) *http.Response {
	t.Helper()
	headers := map[string]string{}
	if cookie != nil {
		headers["Cookie"] = cookieHeader(cookie)
	}
	return e.request(t, http.MethodGet, "/admin/registrations"+query, "", headers)
}

// decide 對一筆申請下一次決定（PUT 子資源），本體原樣交出去。
func (e *reviewEnv) decide(t *testing.T, accountID, body string, cookie *http.Cookie,
	extra map[string]string) *http.Response {
	t.Helper()
	headers := map[string]string{}
	if cookie != nil {
		headers["Cookie"] = cookieHeader(cookie)
	}
	for k, v := range extra {
		headers[k] = v
	}
	return e.request(t, http.MethodPut, "/admin/registrations/"+accountID+"/decision",
		body, headers)
}

// decisionBody 產生一份只帶決定一欄的合法本體。
func decisionBody(decision string) string {
	data, err := json.Marshal(map[string]string{"decision": decision})
	if err != nil {
		panic(err)
	}
	return string(data)
}

// request 以任意方法打一條路徑（空 origin、可選附加標頭）。
func (e *reviewEnv) request(t *testing.T, method, path, body string,
	headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("構造請求失敗：%v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("發送請求失敗：%v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// sessionsOf 數某個主體名下的會話行數。
//
// 用「按帳戶數」而不是「數整張表」：審核者自己那幾份登入（初始口令、首改、重登）
// 本來就該在表裡，斷言只有落在「申請人名下有沒有憑空多出一枚憑據」這句話上才說明得清事。
func sessionsOf(t *testing.T, db *database.DB, accountID string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM sessions WHERE account_id = ?", accountID).Scan(&n); err != nil {
		t.Fatalf("計數會話失敗：%v", err)
	}
	return n
}

// grantsOf 數某個主體名下的伺服器級授予行數。
//
// 與 sessionsOf 同一取向：審核者自己那一行授予是 Root 開設時就落下的事實，
// 斷言只有落在「被批准的人名下有沒有多出一格權限」上才說明得清這件事。
func grantsOf(t *testing.T, db *database.DB, accountID string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM account_server_roles WHERE account_id = ?", accountID).Scan(&n); err != nil {
		t.Fatalf("計數授予失敗：%v", err)
	}
	return n
}

// mustRows 解析名冊回應並取出行清單（狀態碼不對即終止）。
func mustRows(t *testing.T, resp *http.Response) []any {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("讀名冊應成功：%d %s", resp.StatusCode, body)
	}
	payload := decodeJSONBody(t, resp)
	rows, ok := payload["applications"].([]any)
	if !ok {
		t.Fatalf("名冊回應的 applications 該是數組：%v", payload)
	}
	return rows
}

// TestRegistrationReviewFullLoop 完整閉環（本步驗收要求第一、二條在傳輸層的形態）：
// Root 設成 approval → 匿名提交落成待審批 → 他登入被拒（與打錯口令同形）→
// 管理員讀到名冊 → 批准 → 他拿同一枚自選口令進得去；另一位被拒絕 → 他仍進不去，
// 但經本人狀態通路查得到「已被拒絕」與決定時刻。
func TestRegistrationReviewFullLoop(t *testing.T) {
	e := newReviewEnv(t)
	e.setSelfRegisterMode(t, "approval")
	admin := e.liveAdminCookie(t, "loop.reviewer")

	approvedApp := e.fileApplication(t, "Loop.Approve", "會被批准的人")
	rejectedApp := e.fileApplication(t, "Loop.Reject", "會被拒絕的人")
	approvedID, _ := approvedApp["account_id"].(string)
	rejectedID, _ := rejectedApp["account_id"].(string)
	if approvedID == "" || rejectedID == "" {
		t.Fatalf("提交回應該帶著穩定標識：%v / %v", approvedApp, rejectedApp)
	}
	if got := approvedApp["status"]; got != "pending" {
		t.Fatalf("approval 模式提交該落成 pending，實際 %v", got)
	}

	// 批准之前：他與打錯口令的人同形（2001），而且名下沒有任何會話。
	if code := envelopeCode(t, e.loginRaw(t, "Loop.Approve", reviewTestApplicant)); code != 2001 {
		t.Fatalf("批准前登入必須被拒為憑據無效，實際碼 %d", code)
	}
	if n := sessionsOf(t, e.db, approvedID); n != 0 {
		t.Fatalf("批准前申請人名下不該有任何會話，實際 %d 行", n)
	}

	// 名冊：雨行都在，而且每行只有審核需要的六格。
	rows := mustRows(t, e.roster(t, "?page_size=100", admin))
	if len(rows) != 2 {
		t.Fatalf("名冊應恰好兩行，實際 %v", rows)
	}
	byID := map[string]map[string]any{}
	for _, item := range rows {
		row, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("名冊行形態不對：%v", item)
		}
		id, _ := row["account_id"].(string)
		byID[id] = row
	}
	pendingRow := byID[approvedID]
	if pendingRow == nil || pendingRow["status"] != "pending" {
		t.Fatalf("等待中的那筆該在名冊上：%v", byID)
	}
	wantKeys := []string{"account_id", "login_name", "display_name", "status", "submitted_at"}
	if len(pendingRow) != len(wantKeys) {
		t.Errorf("等待中的行該恰好是五格（reviewed_at 缺席才是事實），實際 %v", pendingRow)
	}
	for _, key := range wantKeys {
		if _, ok := pendingRow[key]; !ok {
			t.Errorf("名冊行缺少 %s", key)
		}
	}
	if _, ok := pendingRow["reviewed_at"]; ok {
		t.Error("還沒有人做過決定時 reviewed_at 必須缺席，而不是拿零值冒充")
	}

	// 批准：回應是決定之後的現值，而且這一步本身不簽發任何會話。
	approveResp := e.decide(t, approvedID, decisionBody("approve"), admin, nil)
	if approveResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(approveResp.Body)
		t.Fatalf("批准應成功：%d %s", approveResp.StatusCode, body)
	}
	if approveResp.Header.Get("Set-Cookie") != "" {
		t.Error("決定回應不得攜帶任何會話材料")
	}
	approveBody := decodeJSONBody(t, approveResp)
	if approveBody["decision"] != "approve" {
		t.Errorf("回應該回顯本次落地的決定，實際 %v", approveBody["decision"])
	}
	application, _ := approveBody["application"].(map[string]any)
	if application == nil || application["status"] != "active" {
		t.Fatalf("批准後回顯的現值該是 active，實際 %v", approveBody["application"])
	}
	if reviewedAt, ok := application["reviewed_at"].(string); !ok || reviewedAt == "" {
		t.Error("批准後決定時刻必須出現（申請人查狀態靠它分辨 approved）")
	}
	if n := sessionsOf(t, e.db, approvedID); n != 0 {
		t.Errorf("批准這一步本身不簽發會話，申請人名下該是零行，實際 %d 行", n)
	}
	if n := grantsOf(t, e.db, approvedID); n != 0 {
		t.Errorf("批准只造普通帳戶：申請人名下該零行授予，實際 %d 行", n)
	}

	// 批准之後：同一個人、同一枚自選口令，經既有登入通路進得去（這就是「重新認證」的全部內容）。
	e.loginAs(t, "Loop.Approve", reviewTestApplicant)

	// 拒絕：回應如實，而此人仍進不去；他那一側查得到結局與決定時刻。
	rejectResp := e.decide(t, rejectedID, decisionBody("reject"), admin, nil)
	if rejectResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(rejectResp.Body)
		t.Fatalf("拒絕應成功：%d %s", rejectResp.StatusCode, body)
	}
	if code := envelopeCode(t, e.loginRaw(t, "Loop.Reject", reviewTestApplicant)); code != 2001 {
		t.Errorf("被拒的人必須仍進不去，實際碼 %d", code)
	}
	statusResp := postJSON(t, e.ts, "/auth/registration-status",
		`{"login_name":"Loop.Reject","password":"`+reviewTestApplicant+`"}`, "", nil)
	if statusResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(statusResp.Body)
		t.Fatalf("本人查狀態應成功：%d %s", statusResp.StatusCode, body)
	}
	statusBody := decodeJSONBody(t, statusResp)
	if statusBody["outcome"] != "rejected" {
		t.Errorf("被拒的人該查到 rejected，實際 %v", statusBody["outcome"])
	}
	if _, ok := statusBody["reviewed_at"].(string); !ok {
		t.Error("被拒的人也該看到決定時刻")
	}
	for _, forbidden := range []string{"reviewer", "reason", "note", "actor"} {
		if _, ok := statusBody[forbidden]; ok {
			t.Errorf("本人那側的回應不該有 %s 這一格（內部備註與可公開理由都不落庫）", forbidden)
		}
	}

	// 名冊此後只剩被拒的那一筆（批准的人已經離開這本書，進普通帳戶名冊那一側）。
	afterRows := mustRows(t, e.roster(t, "?page_size=100", admin))
	if len(afterRows) != 1 {
		t.Fatalf("批准之後名冊應只剩被拒那一筆，實際 %v", afterRows)
	}
	firstRow, _ := afterRows[0].(map[string]any)
	if firstRow["account_id"] != rejectedID || firstRow["status"] != "rejected" ||
		firstRow["reviewed_at"] == nil {
		t.Errorf("被拒的那一行該帶著決定時刻，實際 %v", firstRow)
	}

	// 審計：兩個決定各一筆，actor 類別是那位真實的管理員而不是 system。
	approveKind, approveAudit := mustReviewAudit(t, e.db, "account.approve")
	rejectKind, rejectAudit := mustReviewAudit(t, e.db, "account.reject")
	for name, record := range map[string]string{"批准": approveAudit, "拒絕": rejectAudit} {
		if approveKind != "admin" && rejectKind != "admin" {
			t.Errorf("%s的審計該記下真實的審核者類別，實際批准=%q 拒絕=%q", name, approveKind, rejectKind)
		}
		for _, forbidden := range []string{reviewTestApplicant, "$argon2id$", "cookie", "token"} {
			if strings.Contains(strings.ToLower(record), strings.ToLower(forbidden)) {
				t.Errorf("%s的審計裡出現憑據或會話材料（%q）", name, forbidden)
			}
		}
	}
	if got := mustAuditFieldNames(t, e.db, "account.approve"); len(got) != 2 {
		t.Errorf("批准的審計前後摘要該恰好是 status 與 reviewed_at 兩格，實際 %v", got)
	}
}

// mustReviewAudit 讀回某個審批動作的審計：主體類別＋（原因與前後摘要合起來的一段文字）。
func mustReviewAudit(t *testing.T, db *database.DB, action string) (string, string) {
	t.Helper()
	var actorKind, reason, changes string
	if err := db.SQL().QueryRowContext(context.Background(),
		`SELECT actor_kind, COALESCE(reason, ''), changes_json FROM root_audit WHERE action = ?`,
		action).Scan(&actorKind, &reason, &changes); err != nil {
		t.Fatalf("讀回 %s 的審計失敗：%v", action, err)
	}
	return actorKind, reason + " " + changes
}

// mustAuditFieldNames 取出某筆審計的 changes_json 裡被記下的欄位名（結構斷言用）。
//
// 這一條釘的是「內部備註與可公開理由都不落庫」在傳輸層現場的形態：
// 決定留下的前後摘要只有 status 與 reviewed_at 兩格，沒有一格能容下審核者的隨筆。
func mustAuditFieldNames(t *testing.T, db *database.DB, action string) []string {
	t.Helper()
	var changes string
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT changes_json FROM root_audit WHERE action = ?", action).Scan(&changes); err != nil {
		t.Fatalf("讀回 %s 的前後摘要失敗：%v", action, err)
	}
	var parsed []struct {
		Field string `json:"field"`
	}
	if err := json.Unmarshal([]byte(changes), &parsed); err != nil {
		t.Fatalf("解析 changes_json 失敗：%v（原文 %s）", err, changes)
	}
	names := make([]string, 0, len(parsed))
	for _, item := range parsed {
		names = append(names, item.Field)
	}
	return names
}

// TestRegistrationDecisionContract 決定端點的協定層形態：本體白名單、方法放行、
// 結論對映與「沒有一格能填角色、口令或理由」。
func TestRegistrationDecisionContract(t *testing.T) {
	e := newReviewEnv(t)
	e.setSelfRegisterMode(t, "approval")
	admin := e.liveAdminCookie(t, "contract.reviewer")
	app := e.fileApplication(t, "Contract.One", "協定層對象")
	id, _ := app["account_id"].(string)

	// 只有 PUT 一個方法；其餘方法回 1002 並附 Allow，不落進靜態服務的回退。
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		resp := e.request(t, method, "/admin/registrations/"+id+"/decision", "",
			map[string]string{"Cookie": cookieHeader(admin)})
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s 該被拒為方法不允許，實際 %d", method, resp.StatusCode)
		}
		if allow := resp.Header.Get("Allow"); allow != http.MethodPut {
			t.Errorf("%s 的 Allow 標頭該恰好是 PUT，實際 %q", method, allow)
		}
		if code := envelopeCode(t, resp); code != 1002 {
			t.Errorf("%s 的回應該是大 1002 的 JSON 信封而不是網頁外殼，實際 %d", method, code)
		}
	}
	// HEAD 走同一道方法閘，但它按協議不帶回應體：只核對狀態與 Allow。
	headResp := e.request(t, http.MethodHead, "/admin/registrations/"+id+"/decision", "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if headResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("HEAD 該被拒為方法不允許，實際 %d", headResp.StatusCode)
	}
	if allow := headResp.Header.Get("Allow"); allow != http.MethodPut {
		t.Errorf("HEAD 的 Allow 標頭該恰好是 PUT，實際 %q", allow)
	}

	// 本體白名單只有 decision 一欄：任何企圖自報身分、湊依據值、帶口令或帶理由的寫法當場拒殺。
	for _, body := range []string{
		`{"decision":"approve","role":"server_admin"}`,
		`{"decision":"approve","account_type":"standard"}`,
		`{"decision":"approve","status":"active"}`,
		`{"decision":"approve","expected_status":"pending"}`,
		`{"decision":"approve","reason":"他看起來可疑"}`,
		`{"decision":"approve","internal_note":"備註"}`,
		`{"decision":"approve","password":"湒進去的口令"}`,
		`{"decision":"approve","activity_id":"任意活動"}`,
		`{"decision":"approve","must_change_password":true}`,
		`{"decision":"approve","granted_at":1}`,
		`{"login_name":"Contract.One"}`,
		``,
	} {
		resp := e.decide(t, id, body, admin, nil)
		if resp.StatusCode != http.StatusBadRequest {
			bodyText, _ := io.ReadAll(resp.Body)
			t.Fatalf("本體 %q 該被拒，實際 %d %s", body, resp.StatusCode, bodyText)
		}
		if code := envelopeCode(t, resp); code != 1004 {
			t.Errorf("本體 %q 該回 1004，實際 %d", body, code)
		}
	}
	// 申請人側的說法與大小寫變體都不是決定值：點名 decision 欄位而不是回衝突。
	for _, raw := range []string{"approved", "Approved", "pending", "rejected", "", "disable"} {
		resp := e.decide(t, id, decisionBody(raw), admin, nil)
		payload := decodeJSONBody(t, resp)
		if payload["code"] != float64(1004) {
			t.Errorf("決定值 %q 該回 1004，實際 %v", raw, payload["code"])
		}
		details, _ := payload["details"].(map[string]any)
		if details["invalid_field"] != "decision" {
			t.Errorf("決定值 %q 該被點名 decision 欄位，實際 %v", raw, details)
		}
	}

	// 未認證與權限不足是兩句話：一個要登入（2002），一個換身分也沒用（2011）。
	if code := envelopeCode(t, e.decide(t, id, decisionBody("approve"), nil, nil)); code != 2002 {
		t.Errorf("沒帶憑據時該回 2002，實際 %d", code)
	}
	playerCookie := func() *http.Cookie {
		other := e.fileApplication(t, "Contract.Player", "會被批准的申請人")
		otherID, _ := other["account_id"].(string)
		e.mustDecide(t, admin, otherID, "approve")
		return loginCookie(t, e.loginAs(t, "Contract.Player", reviewTestApplicant))
	}()
	if code := envelopeCode(t, e.decide(t, id, decisionBody("approve"), playerCookie, nil)); code != 2011 {
		t.Errorf("普通帳戶下決定該被拒為權限不足（2011），實際 %d", code)
	}

	// 跨站來源在動資料庫之前就被擋下（2005），而且狀態仍然可以是 pending。
	crossSite := e.request(t, http.MethodPut, "/admin/registrations/"+id+"/decision",
		decisionBody("approve"), map[string]string{
			"Cookie": cookieHeader(admin), "Origin": "https://evil.example"})
	if envelopeCode(t, crossSite) != 2005 {
		t.Errorf("跨站請求該被擋為來源不接受，實際碼錯")
	}

	// 幽靈標識與路徑形態：都是 1001，而不是「這個人已被決定」。
	ghost := mustTestID(t).String()
	if code := envelopeCode(t, e.decide(t, ghost, decisionBody("approve"), admin, nil)); code != 1001 {
		t.Errorf("查無此人該回 1001，實際 %d", code)
	}
	if code := envelopeCode(t, e.decide(t, "not-a-uuid", decisionBody("approve"), admin, nil)); code != 1001 {
		t.Errorf("標識格式不對也該回同一句 1001，實際 %d", code)
	}

	// 決定一次之後，同一個目標再按任何一顆都是 2021（而不會悄悄覆蓋先前那個決定）。
	e.mustDecide(t, admin, id, "approve")
	for _, raw := range []string{"approve", "reject"} {
		resp := e.decide(t, id, decisionBody(raw), admin, nil)
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("重複按下 %s 該回 409，實際 %d", raw, resp.StatusCode)
		}
		if code := envelopeCode(t, resp); code != 2021 {
			t.Errorf("重複按下 %s 該回本步那枚新碼 2021，實際 %d", raw, code)
		}
	}

	// 名冊上的這個人已被決定掉：篩選只剩 rejected 那一側。
	rows := mustRows(t, e.roster(t, "?status=pending", admin))
	for _, item := range rows {
		row, _ := item.(map[string]any)
		if row["account_id"] == id {
			t.Error("已批准的人不該再出現在 pending 篩選裡")
		}
	}
}

// mustDecide 下一次決定並在不成時終止測試。
func (e *reviewEnv) mustDecide(t *testing.T, cookie *http.Cookie, accountID, decision string) {
	t.Helper()
	resp := e.decide(t, accountID, decisionBody(decision), cookie, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("對 %s 下 %s 應成功：%d %s", accountID, decision, resp.StatusCode, body)
	}
}

// TestRegistrationRosterContract 名冊端點的協定層形態：四個查詢參數各自點名、
// 回應是 no-store、每個主體看到的結論各不相同。
func TestRegistrationRosterContract(t *testing.T) {
	e := newReviewEnv(t)
	e.setSelfRegisterMode(t, "approval")
	admin := e.liveAdminCookie(t, "roster.reviewer")
	first := e.fileApplication(t, "Roster.One", "名冊第一筆")
	e.fileApplication(t, "Roster.Two", "名冊第二筆")

	resp := e.roster(t, "", admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("讀名冊應成功：%d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get(cacheControlHeader); got != "no-store" {
		t.Errorf("名冊是一份會過期的伺服器狀態，該回 no-store，實際 %q", got)
	}
	payload := decodeJSONBody(t, resp)
	for _, key := range []string{"applications", "page", "page_size", "total", "request_id"} {
		if _, ok := payload[key]; !ok {
			t.Errorf("名冊回應缺少 %s：%v", key, payload)
		}
	}
	if payload["total"] != float64(2) || payload["page"] != float64(1) {
		t.Errorf("分頁回顯不對：%v", payload)
	}
	if rows, ok := payload["applications"].([]any); !ok || len(rows) != 2 {
		t.Fatalf("名冊行數不對：%v", payload["applications"])
	}
	// 回應裡絕對不會有的東西：口令材料、正規化鍵、角色、活動、會話。
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("重新編碼回應失敗：%v", err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{"password", "argon2id", "login_name_key", "roles",
		"activity", "token", "cookie", "reviewer", "reason", strings.ToLower(reviewTestApplicant)} {
		if strings.Contains(text, forbidden) {
			t.Errorf("名冊回應不得含 %q：實際 %s", forbidden, text)
		}
	}

	for _, tc := range []struct {
		query string
		field string
	}{
		{"?page=0", "page"},
		{"?page=abc", "page"},
		{"?page_size=0", "page_size"},
		{"?page_size=101", "page_size"},
		{"?status=active", "status"},
		{"?status=deleted", "status"},
		{"?status=ghost", "status"},
		{"?type=standard", "type"},
	} {
		if tc.field == "type" {
			// 本名冊沒有來源篩選：多餘的參數被默默忽略而不是回錯——
			// 這一條釘的是「它不會被當成篩選條件而多送一次查詢」。
			if got := mustRows(t, e.roster(t, tc.query, admin)); len(got) != 2 {
				t.Errorf("未認的篩選參數不該改變結果，實際 %v", got)
			}
			continue
		}
		resp := e.roster(t, tc.query, admin)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("查詢參數 %q 該被拒，實際 %d", tc.query, resp.StatusCode)
		}
		details, _ := decodeJSONBody(t, resp)["details"].(map[string]any)
		if details["invalid_field"] != tc.field {
			t.Errorf("查詢參數 %q 該被點名為 %s，實際 %v", tc.query, tc.field, details)
		}
	}

	// 匿名與普通帳戶讀不到這本名冊（2002／2011），申請人也不例外——
	// 他那一側只有一條「交憑據查自己結局」的路，沒有第二本可翻的書。
	if code := envelopeCode(t, e.roster(t, "", nil)); code != 2002 {
		t.Errorf("匿名讀名冊該回 2002，實際 %d", code)
	}
	otherID, _ := first["account_id"].(string)
	e.mustDecide(t, admin, otherID, "approve")
	player := loginCookie(t, e.loginAs(t, "Roster.One", reviewTestApplicant))
	if code := envelopeCode(t, e.roster(t, "", player)); code != 2011 {
		t.Errorf("剛被批准的申請人讀名冊該回 2011，實際 %d", code)
	}
}

// TestRegistrationReviewEndpointsAbsentWithoutUseCase 沒注入審批用例時一個端點都不掛：
// 路徑與「本執行檔根本沒有這組端點」的版次逐字相同（回 1001 的 JSON 信封，不回網頁外殼），
// 而且不會留下一條能被匿名探測的半成品寫入口。
func TestRegistrationReviewEndpointsAbsentWithoutUseCase(t *testing.T) {
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("測試組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{Clock: timeutil.System()})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	for _, target := range []struct{ method, path string }{
		{http.MethodGet, "/admin/registrations"},
		{http.MethodPut, "/admin/registrations/" + mustTestID(t).String() + "/decision"},
		{http.MethodPost, "/admin/registrations"},
	} {
		req, err := http.NewRequest(target.method, ts.URL+target.path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("構造請求失敗：%v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("發送請求失敗：%v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var envelope ErrorEnvelope
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Errorf("%s %s 該回 JSON 信封，實際 %q", target.method, target.path, body)
			continue
		}
		if envelope.Code != CodeNotFound {
			t.Errorf("%s %s 該回 1001（端點未掛載），實際 %s", target.method, target.path, body)
		}
		if ctype := resp.Header.Get("Content-Type"); !strings.Contains(ctype, "application/json") {
			t.Errorf("%s %s 該回 JSON 信封而不是網頁外殼，實際 Content-Type %q",
				target.method, target.path, ctype)
		}
	}
}

// TestRegistrationReviewNoSessionMaterialAnywhere 決定與名冊雨條路徑都不產生會話：
// 審核者自己的 Cookie 不會被換代、被清除，也不會因為一次批准而多出一枚給申請人。
func TestRegistrationReviewNoSessionMaterialAnywhere(t *testing.T) {
	e := newReviewEnv(t)
	e.setSelfRegisterMode(t, "approval")
	before := e.liveAdminCookie(t, "session.reviewer")
	app := e.fileApplication(t, "Session.One", "看會話的一筆")
	id, _ := app["account_id"].(string)

	rosterResp := e.roster(t, "", before)
	if rosterResp.Header.Get("Set-Cookie") != "" {
		t.Error("讀名冊不該換發或清除任何 Cookie")
	}
	decisionResp := e.decide(t, id, decisionBody("approve"), before, nil)
	if decisionResp.Header.Get("Set-Cookie") != "" {
		t.Error("下一次決定不該換發或清除審核者的 Cookie")
	}
	if n := sessionsOf(t, e.db, id); n != 0 {
		// 申請人名下必須還是零行：批准不替他簽憑據，審核者自己的那幾份登入不在這句話的範圍裡。
		t.Errorf("批准不該替申請人新建任何會話行，實際 %d 行", n)
	}
	// 申請人此刻還沒有任何憑據：他得自己走 /auth/login。
	if code := envelopeCode(t, e.loginRaw(t, "Session.One", "打錯的口令")); code != 2001 {
		t.Errorf("錯誤口令該回 2001，實際 %d", code)
	}
	if n := sessionsOf(t, e.db, id); n != 0 {
		t.Errorf("一次被拒的登入不該留下會話行，實際 %d 行", n)
	}
	e.loginAs(t, "Session.One", reviewTestApplicant)
	if n := sessionsOf(t, e.db, id); n != 1 {
		t.Errorf("申請人自己登入後才該有他那一份會話，實際 %d 行", n)
	}
}

// TestApprovedApplicantIsPlainStandardAccount 批准造出的是「一個普通帳戶，不多不少」：
// 他進得去、讀不到名冊、也碰不到任何管理入口，而庫裡沒有一行授予。
func TestApprovedApplicantIsPlainStandardAccount(t *testing.T) {
	e := newReviewEnv(t)
	e.setSelfRegisterMode(t, "approval")
	admin := e.liveAdminCookie(t, "plain.reviewer")
	app := e.fileApplication(t, "Plain.One", "被批准的普通人")
	id, _ := app["account_id"].(string)
	e.mustDecide(t, admin, id, "approve")

	player := loginCookie(t, e.loginAs(t, "Plain.One", reviewTestApplicant))
	for _, path := range []string{"/admin/registrations", "/admin/accounts"} {
		resp := e.request(t, http.MethodGet, path, "", map[string]string{"Cookie": cookieHeader(player)})
		if code := envelopeCode(t, resp); code != 2011 {
			t.Errorf("普通帳戶打 %s 該回 2011，實際 %d", path, code)
		}
	}
	resp := e.decide(t, mustTestID(t).String(), decisionBody("approve"), player, nil)
	if code := envelopeCode(t, resp); code != 2011 {
		t.Errorf("普通帳戶下決定該回 2011，實際 %d", code)
	}
	var roles int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM account_server_roles WHERE account_id = ?", id).Scan(&roles); err != nil {
		t.Fatalf("讀取授予失敗：%v", err)
	}
	if roles != 0 {
		t.Errorf("批准不能造出管理員，該帳戶不該有任何授予，實際 %d 行", roles)
	}
	// 他也不會出現在「可打理的普通帳戶名冊」之外的書裡：這一條是把 stdacct 的範圍規則
	// 與本步的名冊釘在同一個現場——批准之後他在普通帳戶目錄那一側，而不是兩本都列他。
	var listed int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM accounts WHERE id = ? AND status IN ('pending','rejected')", id).
		Scan(&listed); err != nil {
		t.Fatalf("統計失敗：%v", err)
	}
	if listed != 0 {
		t.Error("被批准的人已經離開審批名冊那一站")
	}
}
