// rootpolicy_test.go 是「伺服器級帳戶建立策略」的傳輸層端到端證據：
// 真資料庫＋真用例＋完整中介層鏈，從 Root 取得會話一路走到讀寫策略、對外界面拿答案，
// 並換一個進程級實例重開一次服務，確認讀回的是同一份策略。
//
// 刻意不收的東西：
//   - 沒有替身：授權、首次改密門閂、審計與現讀都跨層走真路徑，接錯線就會紅；
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
	"github.com/kagurazakayashi/EvernightRealm/internal/adminacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 測試口令：只活在測試進程的記憶體，不是任何環境的憑據。
const (
	policyTestRootPassword  = "rootpolicy-test-root-口令"
	policyTestAdminPassword = "rootpolicy-test-管理員口令"
)

// policyEnv 是本次測試專屬的現場：暫存庫、真實登入用例、真實管理員用例與真實策略用例。
type policyEnv struct {
	ts       *httptest.Server
	db       *database.DB
	path     string
	accounts *account.Store
	grants   *grant.Store
	clock    timeutil.Clock
}

// newPolicyEnv 建立現場並啟動一臺測試服務。
func newPolicyEnv(t *testing.T) *policyEnv {
	t.Helper()
	env := openPolicySite(t)
	env.serve(t)
	return env
}

// openPolicySite 只落地資料庫現場（含遷移與倉儲），不啟動服務。
//
// 拆成兩步是為了讓「重開程序」那條證據能用同一個檔案再組一次裝配：
// 策略若偷偷只活在記憶體裡，第二次組裝就會讀回出廠值。
func openPolicySite(t *testing.T) *policyEnv {
	t.Helper()
	clock := timeutil.System()
	dir := t.TempDir()
	path := filepath.Join(dir, "evernight.db")
	db, err := database.Open(context.Background(), database.Options{
		Path:        path,
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
	return &policyEnv{db: db, path: path, accounts: accountsStore, grants: grantsStore, clock: clock}
}

// serve 在同一個現場上組出 HTTP 服務層並啟動測試伺服器。
func (e *policyEnv) serve(t *testing.T) {
	t.Helper()
	sessions, err := session.NewStoreWithPolicy(e.clock, time.Hour, session.Policy{})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	rootHash, err := credential.Hash(policyTestRootPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試 Root 憑據失敗：%v", err)
	}
	auditStore := audit.NewStore(e.clock)
	authService, err := auth.New(auth.Deps{
		DB:               e.db,
		Sessions:         sessions,
		Accounts:         e.accounts,
		Grants:           e.grants,
		Audits:           auditStore,
		RootPasswordHash: rootHash,
		Hashing:          credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立登入用例失敗：%v", err)
	}
	adminService, err := adminacct.New(adminacct.Deps{
		DB: e.db, Accounts: e.accounts, Grants: e.grants,
		Audits: auditStore, Sessions: sessions, Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立管理員用例失敗：%v", err)
	}
	policyService, err := acctpolicy.New(acctpolicy.Deps{
		DB: e.db, Store: acctpolicy.NewStore(e.clock), Audits: auditStore,
	})
	if err != nil {
		t.Fatalf("建立策略用例失敗：%v", err)
	}
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{
		Auth: authService, Admins: adminService, AccountPolicy: policyService, Clock: e.clock,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	e.ts = ts
}

// rootCookie 以測試 Root 口令登入並取得本次專用的會話 Cookie。
func (e *policyEnv) rootCookie(t *testing.T) *http.Cookie {
	t.Helper()
	resp := postJSON(t, e.ts, "/auth/root/login",
		`{"password":"`+policyTestRootPassword+`"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 登入應成功：%d %s", resp.StatusCode, body)
	}
	return loginCookie(t, resp)
}

// liveAdmin 直接落庫建一個「已完成首次改密義務」的管理員帳戶並取得其會話 Cookie。
//
// 走真路徑而不是替身：帶著改密義務的會話會被既有門閂擋在 2010，
// 那樣就量不到「管理員對伺服器策略沒有讀寫權」這件事（2011）。
func (e *policyEnv) liveAdmin(t *testing.T, login string) *http.Cookie {
	t.Helper()
	hash, err := credential.Hash(policyTestAdminPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	created, err := e.accounts.Create(context.Background(), e.db.SQL(), account.NewInput{
		LoginName: login, DisplayName: "現行管理員", PasswordHash: hash,
		Type: account.TypeStandard, Status: account.StatusActive,
	})
	if err != nil {
		t.Fatalf("建立管理員帳戶失敗：%v", err)
	}
	if err := e.grants.Grant(context.Background(), e.db.SQL(), created.ID, identity.RoleServerAdmin); err != nil {
		t.Fatalf("寫下授予失敗：%v", err)
	}
	resp := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+policyTestAdminPassword+`"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("管理員登入應成功：%d %s", resp.StatusCode, body)
	}
	return loginCookie(t, resp)
}

// getPolicy 發一次 GET /root/account-policy。
func (e *policyEnv) getPolicy(t *testing.T, cookie *http.Cookie) *http.Response {
	t.Helper()
	return getAuth(t, e.ts, "/root/account-policy", cookieHeader(cookie), "", e.ts.URL)
}

// putPolicy 發一次 PUT /root/account-policy，本體原樣交出去。
func (e *policyEnv) putPolicy(t *testing.T, body string, cookie *http.Cookie, origin string,
	extra map[string]string) *http.Response {
	t.Helper()
	headers := map[string]string{"Cookie": cookieHeader(cookie)}
	for k, v := range extra {
		headers[k] = v
	}
	return putJSON(t, e.ts, "/root/account-policy", body, origin, headers)
}

// policyBody 產生一份完整的策略本體（三個欄位一個都不缺）。
func policyBody(adminCreate bool, mode string, guest bool) string {
	payload := map[string]any{
		"admin_create_standard": adminCreate,
		"self_register_mode":    mode,
		"guest_enabled":         guest,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// readPolicyRow 直接問庫裡的四個值（測試取證用，不參與任何生產判定）。
func (e *policyEnv) readPolicyRow(t *testing.T) (admin int, mode string, guest int, updatedAt int64) {
	t.Helper()
	err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT admin_create_standard, self_register_mode, guest_enabled, updated_at
		   FROM account_creation_policy WHERE id = 1`).
		Scan(&admin, &mode, &guest, &updatedAt)
	if err != nil {
		t.Fatalf("讀取策略行失敗：%v", err)
	}
	return admin, mode, guest, updatedAt
}

// auditCount 回傳 root_audit 的筆數。
func (e *policyEnv) auditCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit").Scan(&n); err != nil {
		t.Fatalf("計數審計失敗：%v", n)
	}
	return n
}

// TestAccountPolicyDefaultsAndWriteRoundTrip 走一條完整時間線：出廠現值 → Root 保存 →
// 回應與庫裡一致 → 再讀一次仍一致。
func TestAccountPolicyDefaultsAndWriteRoundTrip(t *testing.T) {
	env := newPolicyEnv(t)
	cookie := env.rootCookie(t)

	resp := env.getPolicy(t, cookie)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 現讀策略應成功：%d %s", resp.StatusCode, body)
	}
	got := decodeJSONBody(t, resp)
	if got["admin_create_standard"] != false || got["guest_enabled"] != false ||
		got["self_register_mode"] != "closed" {
		t.Errorf("出廠現值應為全關＋closed，實際 %v", got)
	}
	if _, present := got["updated_at"]; present {
		t.Errorf("從未被改寫的出廠行不該帶時刻，實際 %v", got["updated_at"])
	}
	entry, _ := got["entry"].(map[string]any)
	if entry == nil || entry["sign_up_open"] != false || entry["guest_open"] != false {
		t.Errorf("回應應帶出對外入口的真相（此時全關），實際 %v", got["entry"])
	}

	write := env.putPolicy(t, policyBody(true, "open", false), cookie, env.ts.URL, nil)
	if write.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(write.Body)
		t.Fatalf("Root 保存策略應成功：%d %s", resp.StatusCode, body)
	}
	saved := decodeJSONBody(t, write)
	if saved["admin_create_standard"] != true || saved["self_register_mode"] != "open" ||
		saved["guest_enabled"] != false {
		t.Errorf("回應應是落庫後的現值，實際 %v", saved)
	}
	if stamp, ok := saved["updated_at"].(string); !ok || !strings.HasSuffix(stamp, "Z") {
		t.Errorf("寫入後應帶 UTC 時刻，實際 %v", saved["updated_at"])
	}
	adminRow, modeRow, guestRow, updatedAt := env.readPolicyRow(t)
	if adminRow != 1 || modeRow != "open" || guestRow != 0 || updatedAt <= 0 {
		t.Errorf("庫裡應寫入 1/open/0 與真實時刻，實際 %d/%q/%d/%d", adminRow, modeRow, guestRow, updatedAt)
	}

	// 再讀一次：答案是庫裡的事實，不是上一次請求的殘留。
	reread := decodeJSONBody(t, env.getPolicy(t, cookie))
	if reread["self_register_mode"] != "open" || reread["admin_create_standard"] != true {
		t.Errorf("重讀應回同一份現值，實際 %v", reread)
	}
}

// TestAccountPolicySurvivesProcessRestart 驗證重開一輪裝配後讀回同一份策略。
//
// 「立即生效」的另一面是「不靠這個進程的記憶」：這裡在同一個檔案上重新組一次服務，
// 策略若被存在記憶體或寫回 config.yaml 的路上丟失，這一步就會讀回出廠值。
func TestAccountPolicySurvivesProcessRestart(t *testing.T) {
	env := openPolicySite(t)
	env.serve(t)
	cookie := env.rootCookie(t)
	if resp := env.putPolicy(t, policyBody(true, "open", true), cookie, env.ts.URL, nil); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("保存策略應成功：%d %s", resp.StatusCode, body)
	}

	// 換一個進程級實例：先按正常程序關掉這一個的資料庫連線（單寫入實例鎖因此釋放），
	// 再重新開一條連線、重組一個 HTTP 服務（同一個庫檔案）。
	if err := env.db.Close(); err != nil {
		t.Fatalf("關閉第一輪測試庫失敗：%v", err)
	}
	reopenedDB, err := database.Open(context.Background(), database.Options{
		Path: env.path, BusyTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("重新開啟測試庫失敗：%v", err)
	}
	// 只關連線、不刪目錄：目錄由第一輪現場的清理負責（本條註冊較晚、因此先跑），
	// 否則兩輪都想刪同一個暫存目錄，會把一次正常的清理報成殘留。
	t.Cleanup(func() { _ = reopenedDB.Close() })
	reopened := &policyEnv{
		db: reopenedDB, path: env.path,
		accounts: account.NewStore(timeutil.System()),
		grants:   grant.NewStore(timeutil.System()),
		clock:    timeutil.System(),
	}
	reopened.serve(t)

	restartedCookie := reopened.rootCookie(t)
	got := decodeJSONBody(t, reopened.getPolicy(t, restartedCookie))
	if got["admin_create_standard"] != true || got["self_register_mode"] != "open" ||
		got["guest_enabled"] != true {
		t.Errorf("重開後應讀回 1/open/1，實際 %v", got)
	}
	if stamp, ok := got["updated_at"].(string); !ok || stamp == "" {
		t.Errorf("重開後的時刻必須仍是那次變更的事實，實際 %v", got["updated_at"])
	}
}

// TestAccountPolicyAuthorizationMatrix 驗證四個身分各得各的結論，且被拒時零寫入。
//
// 管理員那一筆是本步的核心邊界：他能被 Root 管、不能被拿去管伺服器策略。
// 匿名是 2002（沒帶憑據），跨站是 2005（來源不是授權依據）——三者都不碰資料庫。
func TestAccountPolicyAuthorizationMatrix(t *testing.T) {
	env := newPolicyEnv(t)
	rootCookie := env.rootCookie(t)
	adminCookie := env.liveAdmin(t, "policy.admin")

	// 先用 Root 寫一份「可被辨識」的值，確保被拒的請求若真的寫了會立刻看得出來。
	if resp := env.putPolicy(t, policyBody(true, "closed", true), rootCookie, env.ts.URL, nil); resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("前置保存應成功：%d %s", resp.StatusCode, body)
	}
	beforeAdmin, beforeMode, beforeGuest, beforeUpdatedAt := env.readPolicyRow(t)
	auditsBefore := env.auditCount(t)

	cases := []struct {
		name   string
		bodies []string
	}{
		{"管理員企圖保存", []string{policyBody(false, "open", false)}},
	}
	for _, tc := range cases {
		for _, body := range tc.bodies {
			resp := env.putPolicy(t, body, adminCookie, env.ts.URL, nil)
			assertCode(t, tc.name+"（保存）", resp, CodePermissionDenied, http.StatusForbidden)
		}
	}
	// 讀同樣是被拒的：策略的形態不該讓任何主體透過「能不能讀」推出額外資訊。
	assertCode(t, "管理員企圖現讀", env.getPolicy(t, adminCookie), CodePermissionDenied, http.StatusForbidden)

	// 匿名：沒帶任何憑據（2002），而不是「請重新登入」那一句（2003）。
	anonResp := getAuth(t, env.ts, "/root/account-policy", "", "", env.ts.URL)
	assertCode(t, "匿名現讀", anonResp, CodeNotAuthenticated, http.StatusUnauthorized)
	anonWrite := putJSON(t, env.ts, "/root/account-policy", policyBody(false, "open", false), env.ts.URL, nil)
	assertCode(t, "匿名保存", anonWrite, CodeNotAuthenticated, http.StatusUnauthorized)

	// 跨站：帶著有效 Root Cookie 也不行——來源標頭不是身分授權（2005）。
	crossSite := env.putPolicy(t, policyBody(false, "open", false), rootCookie, "http://evil.example", nil)
	assertCode(t, "跨站保存", crossSite, CodeOriginForbidden, http.StatusForbidden)

	// 未知方法：405 而不是落到靜態服務回 HTML。
	methodResp := postJSON(t, env.ts, "/root/account-policy", policyBody(true, "open", true),
		env.ts.URL, map[string]string{"Cookie": cookieHeader(rootCookie)})
	assertCode(t, "未知方法", methodResp, CodeMethodNotAllowed, http.StatusMethodNotAllowed)

	afterAdmin, afterMode, afterGuest, afterUpdatedAt := env.readPolicyRow(t)
	if afterAdmin != beforeAdmin || afterMode != beforeMode || afterGuest != beforeGuest ||
		afterUpdatedAt != beforeUpdatedAt {
		t.Errorf("被拒的讀寫不應改動策略，實際 %d/%q/%d/%d", afterAdmin, afterMode, afterGuest, afterUpdatedAt)
	}
	if got := env.auditCount(t); got != auditsBefore {
		t.Errorf("被拒的讀寫不應追加審計，實際從 %d 筆變成 %d 筆", auditsBefore, got)
	}
}

// TestAccountPolicyRejectsMalformedBodies 驗證本體形態的四種不合格都點名到欄位，且不發生寫入。
//
// 三個欄位一個都不能缺：缺席不是「按關處理」，而是一次漏傳。
// 少了這道斷言，介面某天下載不到某個開關時就會默默把那個入口關掉。
func TestAccountPolicyRejectsMalformedBodies(t *testing.T) {
	env := newPolicyEnv(t)
	cookie := env.rootCookie(t)
	if resp := env.putPolicy(t, policyBody(true, "open", true), cookie, env.ts.URL, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("前置保存應成功：%d", resp.StatusCode)
	}
	auditsBefore := env.auditCount(t)

	cases := []struct {
		name     string
		body     string
		wantCode ErrorCode
		wantBad  string
	}{
		{"缺自註冊模式", `{"admin_create_standard":false,"guest_enabled":false}`, CodeInvalidBody, "self_register_mode"},
		{"缺建號開關", `{"self_register_mode":"open","guest_enabled":false}`, CodeInvalidBody, "admin_create_standard"},
		{"缺訪客開關", `{"admin_create_standard":false,"self_register_mode":"open"}`, CodeInvalidBody, "guest_enabled"},
		{"模式打錯字", policyBody(false, "pending", false), CodeInvalidBody, "self_register_mode"},
		{"模式為空字串", policyBody(false, "", false), CodeInvalidBody, "self_register_mode"},
		{"模式大小寫不同", policyBody(false, "Open", false), CodeInvalidBody, "self_register_mode"},
		{"多帶身分欄位", `{"admin_create_standard":true,"self_register_mode":"open","guest_enabled":true,"role":"root"}`,
			CodeInvalidBody, ""},
		{"多帶依據值欄位", `{"admin_create_standard":true,"self_register_mode":"open","guest_enabled":true,"expected_mode":"closed"}`,
			CodeInvalidBody, ""},
		{"多帶原因文本欄位", `{"admin_create_standard":true,"self_register_mode":"open","guest_enabled":true,"reason":"今天想開"} `,
			CodeInvalidBody, ""},
		{"空本體", ``, CodeInvalidBody, ""},
	}
	for _, tc := range cases {
		resp := env.putPolicy(t, tc.body, cookie, env.ts.URL, nil)
		envelope := assertCode(t, tc.name, resp, tc.wantCode, http.StatusBadRequest)
		if tc.wantBad == "" {
			continue
		}
		if got := envelope.Details["invalid_field"]; got != tc.wantBad {
			t.Errorf("%s：細節應點名 %q，實際 %v", tc.name, tc.wantBad, envelope.Details)
		}
	}
	// 上面全部失敗：現值與審計都該停在成功那一次之後。
	if admin, mode, guest, _ := env.readPolicyRow(t); admin != 1 || mode != "open" || guest != 1 {
		t.Errorf("被拒的寫入不應改動策略，實際 %d/%q/%d", admin, mode, guest)
	}
	if got := env.auditCount(t); got != auditsBefore {
		t.Errorf("被拒的寫入不應追加審計，實際 %d 筆", got)
	}
}

// TestAccountPolicyRejectsUnapprovedModes 驗證 approval／invite 得到屬於自己的那句結論（2016）。
//
// 這是最容易被寫錯的一條：把「尚未開放」降級成 1004，界面就會告訴 Root「你打錯字」，
// 而那個名字是被批准的；反過來把它當成成功，策略就會記下一種伺服器自己執行不了的模式。
func TestAccountPolicyRejectsUnapprovedModes(t *testing.T) {
	env := newPolicyEnv(t)
	cookie := env.rootCookie(t)
	auditsBefore := env.auditCount(t)

	for _, mode := range []string{"approval", "invite"} {
		resp := env.putPolicy(t, policyBody(true, mode, true), cookie, env.ts.URL, nil)
		assertCode(t, "模式 "+mode, resp, CodeAccountPolicyModeUnavailable, http.StatusBadRequest)
	}
	if admin, mode, guest, updatedAt := env.readPolicyRow(t); admin != 0 || mode != "closed" ||
		guest != 0 || updatedAt != 0 {
		t.Errorf("被拒的模式寫入不應改動出廠值，實際 %d/%q/%d/%d", admin, mode, guest, updatedAt)
	}
	if got := env.auditCount(t); got != auditsBefore {
		t.Errorf("被拒的寫入不應追加審計，實際 %d 筆", got)
	}

	// 四語言都要有這句：缺任何一語，訊息會靜默退回英文。
	for _, locale := range []string{LocaleZhCN, LocaleZhTW, LocaleEnUS, LocaleJaJP} {
		if messageFor(CodeAccountPolicyModeUnavailable, locale) == "" {
			t.Errorf("機器碼 2016 缺少 %s 的文案", locale)
		}
	}
}

// TestEntryCapabilitiesAreMinimalAndClosed 驗證對外入口端點：匿名可讀、只有三個鍵，
// 而且 Root 把策略改成放開之後它仍回答「不開放」。
//
// 這一條同時管兩件事：揭露的面要小到不能再用（不得出現模式名字、時刻、建號開關、
// 任何帳戶或閾值資料），以及「策略值不等於能力」不能只寫在注釋裡。
func TestEntryCapabilitiesAreMinimalAndClosed(t *testing.T) {
	env := newPolicyEnv(t)

	resp := getAuth(t, env.ts, "/auth/capabilities", "", "", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("匿名查對外入口答案應成功：%d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("對外答案必須 no-store（策略可被隨時改掉），實際 %q", got)
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("解析回應失敗：%v", err)
	}
	if len(raw) != 3 {
		t.Errorf("回應應恰好三個欄位（兩個布林＋關聯 ID），實際 %v", raw)
	}
	for _, key := range []string{"sign_up_open", "guest_open", "request_id"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("回應應含 %q，實際 %v", key, raw)
		}
	}
	if raw["sign_up_open"] != false || raw["guest_open"] != false {
		t.Errorf("三條通路都未實作，對外答案應全為關，實際 %v", raw)
	}

	// 策略放開之後仍然關：這條是「能力登記」真的在把關的證據。
	cookie := env.rootCookie(t)
	if put := env.putPolicy(t, policyBody(true, "open", true), cookie, env.ts.URL, nil); put.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(put.Body)
		t.Fatalf("Root 保存策略應成功：%d %s", put.StatusCode, body)
	}
	after := getAuth(t, env.ts, "/auth/capabilities", "", "", "")
	afterBody := decodeJSONBody(t, after)
	if afterBody["sign_up_open"] != false || afterBody["guest_open"] != false {
		t.Errorf("通路未落地時對外仍不得放開，實際 %v", afterBody)
	}

	// Root 端的回應裡看得到那份意圖（策略值與對外答案要能同時被核對）。
	policy := decodeJSONBody(t, env.getPolicy(t, cookie))
	if policy["self_register_mode"] != "open" || policy["guest_enabled"] != true {
		t.Errorf("Root 現讀應看到剛保存的值，實際 %v", policy)
	}

	// 兩張回應都不該出現的東西：憑據材料、帳戶資料、內部閾值、策略的其餘形態。
	forbidden := []string{"password", "argon2id", "token", "cookie", "hash", "account_id",
		"login_name", "display_name", "max_devices", "fail_limit", "must_change"}
	for _, text := range []string{stringOf(t, raw), stringOf(t, afterBody), stringOf(t, policy)} {
		for _, word := range forbidden {
			if strings.Contains(strings.ToLower(text), word) {
				t.Errorf("回應洩漏了 %q：%s", word, text)
			}
		}
	}
}

// TestEntryCapabilitiesFailsClosed 驗證庫裡讀不到策略時，對外端點回失敗而不是憑空的一組布林。
//
// 「降級成全關」看起來安全，但它把一次資料庫缺陷說成 Root 做了這個決定，
// 而且讓界面在故障期間顯示一個永遠按不了的入口而沒有人知道為什麼。
func TestEntryCapabilitiesFailsClosed(t *testing.T) {
	env := newPolicyEnv(t)
	ctx := context.Background()
	if _, err := env.db.SQL().ExecContext(ctx,
		`CREATE TABLE account_creation_policy_backup AS SELECT * FROM account_creation_policy`); err != nil {
		t.Fatalf("備份策略行失敗：%v", err)
	}
	if _, err := env.db.SQL().ExecContext(ctx, `DROP TABLE account_creation_policy`); err != nil {
		t.Fatalf("移除策略表失敗：%v", err)
	}
	// 重建一張同名但空的表：單例行被外部工具拿掉，正是這裡要重現的缺陷。
	if _, err := env.db.SQL().ExecContext(ctx,
		`CREATE TABLE account_creation_policy (id INTEGER PRIMARY KEY, admin_create_standard INTEGER,
			self_register_mode TEXT, guest_enabled INTEGER, updated_at INTEGER)`); err != nil {
		t.Fatalf("重建空策略表失敗：%v", err)
	}

	resp := getAuth(t, env.ts, "/auth/capabilities", "", "", "")
	if resp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("缺陷狀態下應回 500：%d %s", resp.StatusCode, body)
	}
	assertCode(t, "缺陷狀態下的對外答案", resp, CodeUnknown, http.StatusInternalServerError)
	body, _ := io.ReadAll(resp.Body)
	for _, forbidden := range []string{"account_creation_policy", "sqlite", "SELECT"} {
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(forbidden)) {
			t.Errorf("對外錯誤信封不得複述內部結構（命中 %q）：%s", forbidden, body)
		}
	}
}

// assertCode 斷言一次回應的狀態碼與機器碼，並回傳已解析的錯誤信封（本體只讀一次，
// 細節斷言因此不必再碰那條已經讀乾的 body）。
func assertCode(t *testing.T, name string, resp *http.Response, wantCode ErrorCode, wantStatus int) ErrorEnvelope {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s：HTTP 狀態應為 %d，實際 %d（%s）", name, wantStatus, resp.StatusCode, body)
	}
	var envelope ErrorEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("%s：錯誤信封解析失敗：%v（%s）", name, err, body)
	}
	if envelope.Code != wantCode {
		t.Errorf("%s：機器碼應為 %d，實際 %d（%s）", name, wantCode, envelope.Code, body)
	}
	if envelope.Message == "" {
		t.Errorf("%s：錯誤回應必須帶一句在地化訊息：%s", name, body)
	}
	return envelope
}

// stringOf 把回應本體壓成一行文字，供「不含敏感字」的掃描使用。
func stringOf(t *testing.T, payload map[string]any) string {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("序列化回應失敗：%v", err)
	}
	return string(data)
}
