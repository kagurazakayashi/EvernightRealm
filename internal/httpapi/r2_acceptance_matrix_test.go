// r2_acceptance_matrix_test.go 是「账户管理与注册准入闭环」的整体验收证据：
// 用同一套自建数据把六个角色（匿名、受限申请人、访客、普通正式账户、管理员、Root）
// 与四个状态（停用、待审批、已删除、已绑定退休）放进同一台真库测试服务里，
// 沿完整中介层链逐端点核对「HTTP 层与服务层是同一道真实限制」。
//
// 与逐步上线时各自的端到端测试的分工：那一批钉的是「单条通路当天的批准」，
// 本档钉的是「全部通路今天并排成立」——跨步骤互相污染（例如注册顺手提权、
// 审批顺带解除停用、访客旧会话接管绑定目标、删除破坏历史引用）会在这里现形，
// 而单步测试看不见。
//
// 刻意不收的东西：
//   - 没有替身：授权、来源判定、首次改密门闸、策略现读、审计都跨层走真路径；
//   - 不碰任何真实资料目录、不占 5206，全程用本次专属的暂存库与回环测试服务；
//   - 口令派生走 credential.TestParams，不与生产参数混用；
//   - 竞态窗口本身仍归服务层的注入时钟用例——本档量的是串行可复现的结论。
package httpapi

import (
	"bytes"
	"context"
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
	"github.com/kagurazakayashi/EvernightRealm/internal/guestacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/guestbind"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/invitecode"
	"github.com/kagurazakayashi/EvernightRealm/internal/selfregister"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/stdacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 测试口令：只活在测试进程的内存与本次暂存库里，不是任何环境的凭据。
const (
	r2RootPw    = "r2-acceptance-Root口令"
	r2InitialPw = "r2-acceptance-一次性初始口令"
	r2ChangedPw = "r2-acceptance-改後口令"
	r2SelfRegPw = "r2-acceptance-自註冊口令"
)

// r2Env 是一套「挂满本闭环全部用例」的真库现场：登入、Root 管理员域、账户建立策略、
// 管理员普通账户域、匿名自注册与申请状态、审批名册、邀请码、访客进入、绑定三段，
// 全部走与 internal/app 相同的构造顺序与同一份注入仓库——少挂一条就测不到跨域串门。
type r2Env struct {
	ts *httptest.Server
	db *database.DB
}

func newR2Env(t *testing.T) *r2Env {
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
	rootHash, err := credential.Hash(r2RootPw, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試 Root 憑據失敗：%v", err)
	}
	// 守卫全部放宽到测试不会自然触发的额度：本档的限流结论归各步端到端，
	// 这里要的是「每一次请求都真的走到准入判定」，不是被内存闸提前挡下。
	guardCfg := auth.GuardConfig{FailLimit: 10000, Window: time.Second, Cooldown: time.Second,
		SourceFailLimit: 10000, MaxEntries: 100000}
	loginGuard, err := auth.NewLoginGuard(guardCfg, clock)
	if err != nil {
		t.Fatalf("建立登入守衛失敗：%v", err)
	}
	registerGuard, err := auth.NewLoginGuard(guardCfg, clock)
	if err != nil {
		t.Fatalf("建立註冊守衛失敗：%v", err)
	}
	guestGuard, err := auth.NewLoginGuard(guardCfg, clock)
	if err != nil {
		t.Fatalf("建立訪客守衛失敗：%v", err)
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
	inviteStore := invitecode.NewStore(clock)
	inviteService, err := invitecode.New(invitecode.Deps{
		DB: db, Store: inviteStore, Clock: clock, Audits: auditStore,
	})
	if err != nil {
		t.Fatalf("建立邀請碼用例失敗：%v", err)
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
	guestService, err := guestacct.New(guestacct.Deps{
		DB: db, Accounts: accountsStore, Policy: policyStore, Sessions: sessions,
		Audits: auditStore, Guard: guestGuard,
	})
	if err != nil {
		t.Fatalf("建立訪客用例失敗：%v", err)
	}
	registerService, err := selfregister.New(selfregister.Deps{
		DB: db, Accounts: accountsStore, Policy: policyStore,
		Invites: inviteStore, Audits: auditStore,
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
		StandardAccounts: stdService, Guest: guestService, GuestBindings: stdService,
		SelfRegister: registerService, RegistrationReview: reviewService,
		InviteCodes: inviteService, Clock: clock,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &r2Env{ts: ts, db: db}
}

// —— 请求与断言助手 ——

// do 打一趟走完整中介层的请求；cookie 为 nil 时不带会话材料，origin 为 "" 时不带来源头
// （httptest 客户端不自动填 Origin，等同同源）。
func (e *r2Env) do(t *testing.T, method, path, body string, cookie *http.Cookie, origin string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("建立 %s %s 請求失敗：%v", method, path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.Header.Set("Cookie", cookieHeader(cookie))
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s 失敗：%v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (e *r2Env) get(t *testing.T, path string, cookie *http.Cookie) *http.Response {
	t.Helper()
	return e.do(t, http.MethodGet, path, "", cookie, "")
}

// wantErr 断言「这是一次被拒的请求，且错误码正是批准的那一枚」；HTTP 状态只钉到「确为 4xx」，
// 因为各码的状态映射已由码表测试逐档钉死，本档不重复量同一件事。
func r2WantErr(t *testing.T, resp *http.Response, want int, what string) {
	t.Helper()
	if resp.StatusCode < 400 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s：應是被拒請求，實際 %d %s", what, resp.StatusCode, body)
	}
	if got := envelopeCode(t, resp); got != want {
		t.Fatalf("%s：錯誤碼應為 %d，實際 %d", what, want, got)
	}
}

// wantOK 断言状态码并交出已解码的响应本体。
func r2WantOK(t *testing.T, resp *http.Response, want int, what string) map[string]any {
	t.Helper()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s：應 %d，實際 %d %s", what, want, resp.StatusCode, body)
	}
	return decodeJSONBody(t, resp)
}

// —— 现场操作助手：每一步都走端点，不从仓储抄近路 ——

func (e *r2Env) root(t *testing.T) *http.Cookie {
	t.Helper()
	return loginCookie(t, e.do(t, http.MethodPost, "/auth/root/login",
		`{"password":"`+r2RootPw+`"}`, nil, ""))
}

func (e *r2Env) login(t *testing.T, login, password string) *http.Response {
	t.Helper()
	return e.do(t, http.MethodPost, "/auth/login",
		`{"login_name":"`+login+`","password":"`+password+`"}`, nil, "")
}

func (e *r2Env) loginOK(t *testing.T, login, password string) *http.Cookie {
	t.Helper()
	resp := e.login(t, login, password)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("以 %s 登入應成功：%d %s", login, resp.StatusCode, body)
	}
	return loginCookie(t, resp)
}

// changePw 以发起会话改密；改密按既有合同撤销名下全部会话，调用端之后必须重新登入。
func (e *r2Env) changePw(t *testing.T, cookie *http.Cookie, current, next string) {
	t.Helper()
	resp := e.do(t, http.MethodPost, "/auth/password/change",
		`{"current_password":"`+current+`","new_password":"`+next+`"}`, cookie, "")
	r2WantOK(t, resp, http.StatusOK, "首次改密")
}

func (e *r2Env) setPolicy(t *testing.T, root *http.Cookie, adminCreate bool, mode string, guestOn bool) {
	t.Helper()
	resp := e.do(t, http.MethodPut, "/root/account-policy",
		policyBody(adminCreate, mode, guestOn), root, "")
	r2WantOK(t, resp, http.StatusOK, "保存帳戶建立策略")
}

func (e *r2Env) caps(t *testing.T) map[string]any {
	t.Helper()
	return r2WantOK(t, e.get(t, "/auth/capabilities", nil), http.StatusOK, "匿名入口能力")
}

// createAdmin 由 Root 经端点开设管理员并钉住响应形态，回账户标识。
func (e *r2Env) createAdmin(t *testing.T, root *http.Cookie, login, display string) string {
	t.Helper()
	created := r2WantOK(t, e.do(t, http.MethodPost, "/root/admins",
		`{"login_name":"`+login+`","display_name":"`+display+`","password":"`+r2InitialPw+`"}`,
		root, ""), http.StatusCreated, "Root 開設 "+login)
	if created["must_change_password"] != true {
		t.Fatalf("%s：新開設者必須欠首改，實際 %v", login, created["must_change_password"])
	}
	if !r2HasString(created["roles"], "server_admin") {
		t.Fatalf("%s：開設應帶出伺服器級授予，實際 %v", login, created["roles"])
	}
	id, _ := created["account_id"].(string)
	if id == "" {
		t.Fatalf("%s：開設回應應帶出帳戶標識", login)
	}
	return id
}

// onboardAdmin 开设并替本人走完首改，交回「可干活的会话」与其标识。
func (e *r2Env) onboardAdmin(t *testing.T, root *http.Cookie, login string) (*http.Cookie, string) {
	t.Helper()
	id := e.createAdmin(t, root, login, "閉環管理員")
	e.changePw(t, e.loginOK(t, login, r2InitialPw), r2InitialPw, r2ChangedPw)
	return e.loginOK(t, login, r2ChangedPw), id
}

// createStandard 由管理员经端点建普通账户（初始口令固定），回账户标识。
func (e *r2Env) createStandard(t *testing.T, admin *http.Cookie, login string) string {
	t.Helper()
	created := r2WantOK(t, e.do(t, http.MethodPost, "/admin/accounts",
		`{"login_name":"`+login+`","display_name":"閉環成員","password":"`+r2InitialPw+`"}`,
		admin, ""), http.StatusCreated, "管理員建立 "+login)
	if created["must_change_password"] != true {
		t.Fatalf("%s：管理員建號必須欠首改，實際 %v", login, created["must_change_password"])
	}
	id, _ := created["account_id"].(string)
	if id == "" {
		t.Fatalf("%s：建立回應應帶出帳戶標識", login)
	}
	return id
}

// onboardStandard 建号并替本人完成首改，交回（标识, 可用会话）。
func (e *r2Env) onboardStandard(t *testing.T, admin *http.Cookie, login string) (string, *http.Cookie) {
	t.Helper()
	id := e.createStandard(t, admin, login)
	e.changePw(t, e.loginOK(t, login, r2InitialPw), r2InitialPw, r2ChangedPw)
	return id, e.loginOK(t, login, r2ChangedPw)
}

func (e *r2Env) enterGuest(t *testing.T, nickname string) (*http.Cookie, string) {
	t.Helper()
	resp := e.do(t, http.MethodPost, "/auth/guest", `{"nickname":"`+nickname+`"}`, nil, "")
	body := r2WantOK(t, resp, http.StatusOK, "訪客進入 "+nickname)
	id, _ := body["account_id"].(string)
	if id == "" || body["account_type"] != "guest" {
		t.Fatalf("訪客進入回應形態不對：%v", body)
	}
	return loginCookie(t, resp), id
}

func (e *r2Env) register(t *testing.T, body string) *http.Response {
	t.Helper()
	return e.do(t, http.MethodPost, "/auth/register", body, nil, "")
}

func (e *r2Env) regStatus(t *testing.T, login, password string) *http.Response {
	t.Helper()
	return e.do(t, http.MethodPost, "/auth/registration-status",
		`{"login_name":"`+login+`","password":"`+password+`"}`, nil, "")
}

func (e *r2Env) decide(t *testing.T, admin *http.Cookie, accountID, body string) *http.Response {
	t.Helper()
	return e.do(t, http.MethodPut, "/admin/registrations/"+accountID+"/decision", body, admin, "")
}

// —— 直读库面的对照助手（只数行、只读结论列，不代为写入） ——

func (e *r2Env) countRows(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("計數 %s 失敗：%v", table, err)
	}
	return n
}

func (e *r2Env) statusOf(t *testing.T, accountID string) string {
	t.Helper()
	var s string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT status FROM accounts WHERE id = ?", accountID).Scan(&s); err != nil {
		t.Fatalf("讀 accounts.status 失敗：%v", err)
	}
	return s
}

// auditActor 交回某个动作最近一笔的审计主体（类别与标识），用来钉「真实操作者」。
func (e *r2Env) auditActor(t *testing.T, action string) (string, string) {
	t.Helper()
	var kind, actor string
	err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT actor_kind, COALESCE(actor_id, '') FROM root_audit WHERE action = ?"+
			" ORDER BY created_at DESC LIMIT 1", action).Scan(&kind, &actor)
	if err != nil {
		t.Fatalf("讀 %s 審計失敗：%v", action, err)
	}
	return kind, actor
}

// auditLeakScan 横扫审计变更摘要：任何一行带着口令明文、哈希前缀或凭证明文都是事故。
func (e *r2Env) auditLeakScan(t *testing.T, needles ...string) {
	t.Helper()
	rows, err := e.db.SQL().QueryContext(context.Background(),
		"SELECT changes_json FROM root_audit")
	if err != nil {
		t.Fatalf("掃描審計失敗：%v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatalf("讀審計本體失敗：%v", err)
		}
		for _, needle := range needles {
			if strings.Contains(raw, needle) {
				t.Fatalf("審計 changes_json 洩漏敏感材料（含 %q）", needle)
			}
		}
	}
}

func r2HasString(v any, want string) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if s, _ := item.(string); s == want {
			return true
		}
	}
	return false
}

func r2Ghost(t *testing.T) string {
	t.Helper()
	id, err := idgen.New()
	if err != nil {
		t.Fatalf("產生幽靈標識失敗：%v", err)
	}
	return id.String()
}

func r2List(v any) []any {
	list, _ := v.([]any)
	return list
}

func r2Find(list []any, key, value string) map[string]any {
	for _, item := range list {
		row, _ := item.(map[string]any)
		if row == nil {
			continue
		}
		if s, _ := row[key].(string); s == value {
			return row
		}
	}
	return nil
}

// r2HasSessionCookie 判断一次响应是否带出了会话 Cookie——准入通路「不签会话」的钉子都读它。
func r2HasSessionCookie(resp *http.Response) bool {
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookieName {
			return true
		}
	}
	return false
}

// TestR2AdminChainClosedLoop 沿 Root 域逐条走「开设 → 首改 → 停用/恢复 → 重置 → 改名
// → 软删除」，并钉住每一跳批准过的对外结论：授予只从 Root 通路来、被拒的来源零写入、
// 停用与删除都是全局登入能力变化、重复操作拿到专码而不是假成功、删除后目录仍列只读。
func TestR2AdminChainClosedLoop(t *testing.T) {
	e := newR2Env(t)
	root := e.root(t)

	adminAID := e.createAdmin(t, root, "R2.Admin.Alpha", "甲號管理員")

	// 欠首改的管理员：登录放行，但除会话/登出/改密外一律 2010——这是服务端门闸，
	// 不是界面上没有按钮。
	cookieA := e.loginOK(t, "R2.Admin.Alpha", r2InitialPw)
	r2WantErr(t, e.get(t, "/root/admins", cookieA), 2010, "欠首改的管理員讀 Root 目錄")
	e.changePw(t, cookieA, r2InitialPw, r2ChangedPw)
	cookieA = e.loginOK(t, "R2.Admin.Alpha", r2ChangedPw)

	sess := r2WantOK(t, e.get(t, "/auth/session", cookieA), http.StatusOK, "已改密管理員的現讀會話")
	if !r2HasString(sess["roles"], "server_admin") || sess["account_type"] != "standard" {
		t.Fatalf("會話現讀應由服務端帶出真實形態：%v", sess)
	}

	// 停用＝全局登入能力变化：名下会话同交易撤销，在途 Cookie 当场失效，登入收成同形 2001。
	st := r2WantOK(t, e.do(t, http.MethodPut, "/root/admins/"+adminAID+"/status",
		`{"status":"disabled","expected_status":"active"}`, root, ""),
		http.StatusOK, "Root 停用管理員")
	if st["revoked_sessions"].(float64) < 1 {
		t.Fatalf("停用應撤走名下會話：%v", st["revoked_sessions"])
	}
	r2WantErr(t, e.get(t, "/admin/accounts", cookieA), 2003, "停用後在途會話")
	r2WantErr(t, e.login(t, "R2.Admin.Alpha", r2ChangedPw), 2001, "停用中的登入")
	r2WantErr(t, e.login(t, "R2.Admin.Nobody", r2ChangedPw), 2001, "查無此人（應與停用同形）")
	// 陈旧底稿的重复停用不是成功：拿状态冲突专码（不构成迁移的同值写法另有 1004，
	// 由传输层的输入校验先行拒绝）。
	r2WantErr(t, e.do(t, http.MethodPut, "/root/admins/"+adminAID+"/status",
		`{"status":"disabled","expected_status":"active"}`, root, ""),
		2014, "底稿已過時的停用")

	r2WantOK(t, e.do(t, http.MethodPut, "/root/admins/"+adminAID+"/status",
		`{"status":"active","expected_status":"disabled"}`, root, ""),
		http.StatusOK, "Root 恢復管理員")
	cookieA = e.loginOK(t, "R2.Admin.Alpha", r2ChangedPw)

	// 改名带可观测事实做底稿：陈旧底稿 2013，不覆盖对方的现值。
	r2WantErr(t, e.do(t, http.MethodPut, "/root/admins/"+adminAID,
		`{"display_name":"甲號新名","expected_display_name":"亂數底稿"}`, root, ""),
		2013, "陳舊底稿改名")
	r2WantOK(t, e.do(t, http.MethodPut, "/root/admins/"+adminAID,
		`{"display_name":"甲號新名","expected_display_name":"甲號管理員"}`, root, ""),
		http.StatusOK, "如實改名")

	// 重置＝换凭据＋全撤＋重新欠首改；旧口令与旧会话同时死。
	rs := r2WantOK(t, e.do(t, http.MethodPut, "/root/admins/"+adminAID+"/password",
		`{"password":"`+r2SelfRegPw+`"}`, root, ""),
		http.StatusOK, "Root 重置管理員憑據")
	if rs["revoked_sessions"].(float64) < 1 {
		t.Fatalf("重置應撤走名下會話：%v", rs["revoked_sessions"])
	}
	r2WantErr(t, e.get(t, "/auth/session", cookieA), 2003, "重置後在途會話")
	r2WantErr(t, e.login(t, "R2.Admin.Alpha", r2ChangedPw), 2001, "重置後的舊口令")
	rebornResp := e.login(t, "R2.Admin.Alpha", r2SelfRegPw)
	reborn := r2WantOK(t, rebornResp, http.StatusOK, "重置後以新初始口令登入")
	if reborn["must_change_password"] != true {
		t.Fatalf("重置必須重新欠首改：%v", reborn)
	}
	e.changePw(t, loginCookie(t, rebornResp), r2SelfRegPw, r2ChangedPw)

	// 跨站来源带真 Cookie：2005 且一个字节都不写。
	accountsBefore := e.countRows(t, "accounts")
	r2WantErr(t, e.do(t, http.MethodPost, "/root/admins",
		`{"login_name":"R2.Admin.CSRF","display_name":"跨站 probe","password":"`+r2InitialPw+`"}`,
		root, "https://evil.invalid"), 2005, "跨站開設")
	if got := e.countRows(t, "accounts"); got != accountsBefore {
		t.Fatalf("跨站被拒之後帳戶行數應不變：before %d after %d", accountsBefore, got)
	}
	// 自报角色没有格子：未知字段死在解码，不进入任何授权判定。
	r2WantErr(t, e.do(t, http.MethodPost, "/root/admins",
		`{"login_name":"R2.Admin.Forged","display_name":"自報角色","password":"`+r2InitialPw+`",`+
			`"roles":["server_admin"]}`, root, ""), 1004, "自報 roles 欄位")
	if got := e.countRows(t, "accounts"); got != accountsBefore {
		t.Fatalf("偽造欄位被拒之後帳戶行數應不變：before %d after %d", accountsBefore, got)
	}

	// 软删除：三件效果一次交易落地，之后是「仍列目录、一律只读」的终态。
	bravoID := e.createAdmin(t, root, "R2.Admin.Bravo", "乙號管理員")
	bravoCookie := e.loginOK(t, "R2.Admin.Bravo", r2InitialPw)
	del := r2WantOK(t, e.do(t, http.MethodDelete, "/root/admins/"+bravoID, "", root, ""),
		http.StatusOK, "Root 軟刪除管理員")
	deleted := del["admin"].(map[string]any)
	if deleted["status"] != "deleted" || deleted["deleted_at"] == nil ||
		!strings.HasPrefix(deleted["display_name"].(string), "DEL_") {
		t.Fatalf("刪除回應應是匿名化的終態現值：%v", deleted)
	}
	if del["revoked_sessions"].(float64) < 1 {
		t.Fatalf("刪除應撤走名下會話：%v", del["revoked_sessions"])
	}
	r2WantErr(t, e.get(t, "/auth/session", bravoCookie), 2003, "被刪者的在途會話")
	r2WantErr(t, e.login(t, "R2.Admin.Bravo", r2InitialPw), 2001, "被刪者的登入")
	r2WantErr(t, e.do(t, http.MethodDelete, "/root/admins/"+bravoID, "", root, ""),
		2015, "重複刪除")
	r2WantErr(t, e.do(t, http.MethodPut, "/root/admins/"+bravoID+"/status",
		`{"status":"active","expected_status":"disabled"}`, root, ""), 2015, "對已刪者停用通路")
	r2WantErr(t, e.do(t, http.MethodPut, "/root/admins/"+bravoID+"/password",
		`{"password":"`+r2ChangedPw+`"}`, root, ""), 2015, "對已刪者重置")
	r2WantErr(t, e.do(t, http.MethodPut, "/root/admins/"+bravoID,
		`{"display_name":"翻案名","expected_display_name":"乙號管理員"}`, root, ""),
		2015, "對已刪者改名")
	directory := r2WantOK(t, e.get(t, "/root/admins?status=deleted", root),
		http.StatusOK, "已刪篩選")
	if r2Find(r2List(directory["admins"]), "account_id", bravoID) == nil {
		t.Fatalf("已刪管理員應仍列於目錄：%v", directory["admins"])
	}
	detail := r2WantOK(t, e.get(t, "/root/admins/"+bravoID, root), http.StatusOK, "已刪詳情")
	if detail["admin"].(map[string]any)["status"] != "deleted" {
		t.Fatalf("詳情應如實帶出終態：%v", detail["admin"])
	}
	r2WantErr(t, e.do(t, http.MethodPost, "/root/admins",
		`{"login_name":"R2.Admin.Bravo","display_name":"重佔名","password":"`+r2InitialPw+`"}`,
		root, ""), 2012, "被刪者的登入名應仍被占用")

	// 审计归因：开设与删除都记真实操作者（Root 域主体），且审计里没有凭据材料。
	if kind, _ := e.auditActor(t, "admin.create"); kind != "root" {
		t.Fatalf("admin.create 的審計主體應為 root，實際 %q", kind)
	}
	if kind, _ := e.auditActor(t, "admin.delete"); kind != "root" {
		t.Fatalf("admin.delete 的審計主體應為 root，實際 %q", kind)
	}
	e.auditLeakScan(t, r2InitialPw, r2ChangedPw, r2SelfRegPw, "$argon2id$", "password_hash")

	// 管理员进不了 Root 域：2011 是用例判出来的，不是界面上没有入口。
	// （重置已撤走此前所有会话，这里用改密后的现行凭据重新换一枚。）
	liveA := e.loginOK(t, "R2.Admin.Alpha", r2ChangedPw)
	r2WantErr(t, e.get(t, "/root/admins", liveA), 2011, "管理員讀 Root 目錄")
}

// TestR2RegistrationModesClosedLoop 把三种自注册模式与策略切换并排走一遍：
// 出厂全关、open 直落、approval 走名册、invite 原子核销、guest 开关独立。
// 每条都钉「准入在服务端交易内现读策略」与「注册建不出任何服务器级授予」。
func TestR2RegistrationModesClosedLoop(t *testing.T) {
	e := newR2Env(t)
	root := e.root(t)

	// 出厂：三条对外通路全关，匿名能力位与准入同向（都是假）。
	caps := e.caps(t)
	if caps["sign_up_open"] != false || caps["invite_code_required"] != false || caps["guest_open"] != false {
		t.Fatalf("出廠入口能力應全關：%v", caps)
	}
	r2WantErr(t, e.register(t, `{"login_name":"R2.Closed.One","display_name":"閉環門外","password":"`+
		r2SelfRegPw+`"}`), 2017, "closed 模式的自註冊")
	r2WantErr(t, e.do(t, http.MethodPost, "/auth/guest", `{"nickname":"閉環訪客"}`, nil, ""),
		2017, "訪客開關關閉時的進入")

	adminCookie, _ := e.onboardAdmin(t, root, "R2.Mode.Admin")

	// —— open：注册即得可用账户，但拿不到会话、更拿不到授予 ——
	e.setPolicy(t, root, true, "open", false)
	caps = e.caps(t)
	if caps["sign_up_open"] != true || caps["invite_code_required"] != false {
		t.Fatalf("open 模式入口能力：%v", caps)
	}
	openOneResp := e.register(t, `{"login_name":"R2.Open.One","display_name":"開門一號","password":"`+
		r2SelfRegPw+`"}`)
	opened := r2WantOK(t, openOneResp, http.StatusCreated, "open 自註冊")
	if opened["must_change_password"] != false || opened["status"] != "active" {
		t.Fatalf("open 建出的形態：%v", opened)
	}
	if opened["roles"] != nil {
		t.Fatalf("自註冊回應不該有 roles 這一格：%v", opened["roles"])
	}
	if r2HasSessionCookie(openOneResp) {
		t.Fatalf("自註冊不簽發會話")
	}
	openTwoResp := e.register(t, `{"login_name":"R2.Open.Two","display_name":"開門二號","password":"`+
		r2SelfRegPw+`"}`)
	r2WantOK(t, openTwoResp, http.StatusCreated, "第二筆 open 自註冊")
	if r2HasSessionCookie(openTwoResp) {
		t.Fatalf("自註冊不簽發會話（第二筆）")
	}
	openTwo := e.loginOK(t, "R2.Open.Two", r2SelfRegPw)
	sess := r2WantOK(t, e.get(t, "/auth/session", openTwo), http.StatusOK, "自註冊者的會話")
	if sess["roles"] != nil {
		t.Fatalf("自註冊帳戶不該被現讀出任何授予：%v", sess["roles"])
	}
	r2WantErr(t, e.register(t, `{"login_name":"R2.Open.One","display_name":"重名","password":"`+
		r2SelfRegPw+`"}`), 2019, "自註冊重名")
	r2WantErr(t, e.register(t, `{"login_name":"R2.Open.Forged","display_name":"自報","password":"`+
		r2SelfRegPw+`","roles":["server_admin"],"account_id":"whatever"}`), 1004, "自報角色的註冊")

	// —— approval：门外的申请等名册做决定；批准既不授予也不解除其他限制 ——
	e.setPolicy(t, root, true, "approval", false)
	applied := r2WantOK(t, e.register(t, `{"login_name":"R2.Apply.One","display_name":"待審一號","password":"`+
		r2SelfRegPw+`"}`), http.StatusCreated, "approval 提交申請")
	if applied["status"] != "pending" {
		t.Fatalf("申請落地應是待審批：%v", applied["status"])
	}
	r2WantErr(t, e.login(t, "R2.Apply.One", r2SelfRegPw), 2001, "待審批者的登入")
	statusResp := e.regStatus(t, "R2.Apply.One", r2SelfRegPw)
	statusBody := r2WantOK(t, statusResp, http.StatusOK, "本人查申請結局")
	if statusBody["outcome"] != "pending" {
		t.Fatalf("查到的應是待審批：%v", statusBody)
	}
	if r2HasSessionCookie(statusResp) {
		t.Fatalf("申請狀態查詢不得簽發會話")
	}
	r2WantErr(t, e.do(t, http.MethodPost, "/auth/registration-status",
		`{"login_name":"R2.Apply.One","password":"`+r2SelfRegPw+`","account_id":"x"}`, nil, ""),
		1004, "自報 account_id 的查詢")
	// 名册：匿名与自注册账户都看不到它。
	r2WantErr(t, e.get(t, "/admin/registrations", nil), 2002, "匿名讀名冊")
	r2WantErr(t, e.get(t, "/admin/registrations", openTwo), 2011, "普通帳戶讀名冊")
	roster := r2WantOK(t, e.get(t, "/admin/registrations", adminCookie), http.StatusOK, "管理員讀名冊")
	row := r2Find(r2List(roster["applications"]), "login_name", "R2.Apply.One")
	if row == nil {
		t.Fatalf("名冊應列待審批申請：%v", roster["applications"])
	}
	applyID := row["account_id"].(string)

	approved := r2WantOK(t, e.decide(t, adminCookie, applyID, `{"decision":"approve"}`),
		http.StatusOK, "批准申請")
	if approved["application"].(map[string]any)["status"] != "active" {
		t.Fatalf("批准後的現值：%v", approved["application"])
	}
	r2WantErr(t, e.decide(t, adminCookie, applyID, `{"decision":"approve"}`), 2021, "重複批准")
	firstLogin := r2WantOK(t, e.login(t, "R2.Apply.One", r2SelfRegPw),
		http.StatusOK, "批准者首次登入")
	if firstLogin["roles"] != nil {
		t.Fatalf("批准不得造出授予：%v", firstLogin["roles"])
	}
	r2WantErr(t, e.do(t, http.MethodPost, "/admin/accounts",
		`{"login_name":"R2.Apply.Promoted","display_name":"想提權","password":"`+r2SelfRegPw+`"}`,
		openTwo, ""), 2011, "自註冊帳戶想建號（註冊沒有提權）")

	// 「审批不解除停用」：批准后停用他，批准通路再也没有一格能替他翻回。
	r2WantOK(t, e.do(t, http.MethodPut, "/admin/accounts/"+applyID+"/status",
		`{"status":"disabled","expected_status":"active"}`, adminCookie, ""),
		http.StatusOK, "停用已批准者")
	r2WantErr(t, e.login(t, "R2.Apply.One", r2SelfRegPw), 2001, "停用中的已批准者")
	r2WantErr(t, e.decide(t, adminCookie, applyID, `{"decision":"approve"}`), 2021,
		"想用批准翻回停用")
	detail := r2WantOK(t, e.get(t, "/admin/accounts/"+applyID, adminCookie),
		http.StatusOK, "已批准又被停用的詳情")
	detailAccount := detail["account"].(map[string]any)
	if detailAccount["status"] != "disabled" || detailAccount["disabled_at"] == nil {
		t.Fatalf("停用事實不因批准而消失：%v", detailAccount)
	}
	r2WantOK(t, e.do(t, http.MethodPut, "/admin/accounts/"+applyID+"/status",
		`{"status":"active","expected_status":"disabled"}`, adminCookie, ""),
		http.StatusOK, "恢復已批准者")

	// 拒绝：行保留、名占住，名册仍列；结局本人查得到。
	two := r2WantOK(t, e.register(t, `{"login_name":"R2.Apply.Two","display_name":"待審二號","password":"`+
		r2SelfRegPw+`"}`), http.StatusCreated, "第二筆申請")
	twoID := two["account_id"].(string)
	r2WantOK(t, e.decide(t, adminCookie, twoID, `{"decision":"reject"}`),
		http.StatusOK, "拒絕申請")
	r2WantErr(t, e.login(t, "R2.Apply.Two", r2SelfRegPw), 2001, "被拒者的登入")
	rejected := r2WantOK(t, e.regStatus(t, "R2.Apply.Two", r2SelfRegPw),
		http.StatusOK, "被拒者查結局")
	if rejected["outcome"] != "rejected" {
		t.Fatalf("被拒的結局：%v", rejected)
	}
	r2WantErr(t, e.do(t, http.MethodDelete, "/admin/accounts/"+twoID, "", adminCookie, ""),
		1001, "已拒絕申請人不是刪除目標（收斂成查無同形）")
	if kind, actor := e.auditActor(t, "account.reject"); kind != "admin" || actor == "" {
		t.Fatalf("拒絕的審計應記真實操作者：%q %q", kind, actor)
	}

	// —— invite：名额的原子消费在 HTTP 侧的形状；码只认 Root 通路 ——
	e.setPolicy(t, root, true, "invite", false)
	caps = e.caps(t)
	// invite 不是把门关上：门仍开（sign_up_open 真），但「要码」另用一格说清。
	if caps["sign_up_open"] != true || caps["invite_code_required"] != true {
		t.Fatalf("invite 模式入口能力：%v", caps)
	}
	r2WantErr(t, e.do(t, http.MethodPost, "/root/invite-codes",
		`{"label":"管理員建碼","max_uses":1}`, adminCookie, ""), 2011, "管理員簽發邀請碼")
	issued := r2WantOK(t, e.do(t, http.MethodPost, "/root/invite-codes",
		`{"label":"驗收兩次用","max_uses":2}`, root, ""), http.StatusCreated, "Root 簽發邀請碼")
	code, _ := issued["code"].(string)
	codeID := issued["invite"].(map[string]any)["code_id"].(string)
	if code == "" {
		t.Fatalf("簽發回應應恰此一次帶出明文")
	}
	// 无码、错码、查无此码：多种失败收成同一句，不泄露差在哪一半。
	bad1 := e.register(t, `{"login_name":"R2.Invite.NoCode","display_name":"無碼","password":"`+r2SelfRegPw+`"}`)
	bad2 := e.register(t, `{"login_name":"R2.Invite.Bad","display_name":"錯碼","password":"`+
		r2SelfRegPw+`","invite_code":"00000000-0000-4000-8000-000000000000"}`)
	if envelopeCode(t, bad1) != 2023 || envelopeCode(t, bad2) != 2023 {
		t.Fatalf("邀請失敗應收斂 2023")
	}
	for i, name := range []string{"R2.Invite.One", "R2.Invite.Two"} {
		r2WantOK(t, e.register(t, `{"login_name":"`+name+`","display_name":"碼進`+
			string(rune('甲'+i))+`","password":"`+r2SelfRegPw+`","invite_code":"`+code+`"}`),
			http.StatusCreated, "持碼註冊")
	}
	rosters := r2WantOK(t, e.get(t, "/root/invite-codes", root), http.StatusOK, "碼名冊")
	codeRow := r2Find(r2List(rosters["invites"]), "code_id", codeID)
	if codeRow == nil || codeRow["status"] != "exhausted" || codeRow["used_count"].(float64) != 2 ||
		codeRow["remaining"].(float64) != 0 {
		t.Fatalf("額度應被恰好耗盡：%v", codeRow)
	}
	accountsBeforeExhausted := e.countRows(t, "accounts")
	r2WantErr(t, e.register(t, `{"login_name":"R2.Invite.Three","display_name":"超發","password":"`+
		r2SelfRegPw+`","invite_code":"`+code+`"}`), 2023, "用盡後的同碼註冊")
	if got := e.countRows(t, "accounts"); got != accountsBeforeExhausted {
		t.Fatalf("被拒的核銷不建號：before %d after %d", accountsBeforeExhausted, got)
	}
	r2WantOK(t, e.do(t, http.MethodDelete, "/root/invite-codes/"+codeID, "", root, ""),
		http.StatusOK, "撤銷邀請碼")
	r2WantErr(t, e.do(t, http.MethodDelete, "/root/invite-codes/"+codeID, "", root, ""),
		2022, "重複撤銷")
	r2WantErr(t, e.register(t, `{"login_name":"R2.Invite.Revoked","display_name":"已撤","password":"`+
		r2SelfRegPw+`","invite_code":"`+code+`"}`), 2023, "已撤銷碼的註冊")
	// 非 invite 模式不看码格：切回 open 后旧码原封不动。
	e.setPolicy(t, root, true, "open", false)
	spare := r2WantOK(t, e.do(t, http.MethodPost, "/root/invite-codes",
		`{"label":"驗收空置碼","max_uses":1}`, root, ""), http.StatusCreated, "第二枚碼")
	spareCode := spare["code"].(string)
	spareID := spare["invite"].(map[string]any)["code_id"].(string)
	r2WantOK(t, e.register(t, `{"login_name":"R2.Open.Late","display_name":"帶碼走open","password":"`+
		r2SelfRegPw+`","invite_code":"`+spareCode+`"}`), http.StatusCreated, "open 模式帶著碼註冊")
	rosters = r2WantOK(t, e.get(t, "/root/invite-codes", root), http.StatusOK, "碼名冊二次讀")
	spareRow := r2Find(r2List(rosters["invites"]), "code_id", spareID)
	if spareRow["used_count"].(float64) != 0 {
		t.Fatalf("open 模式不得核銷：%v", spareRow)
	}

	// 访客开关与三条自注册通路互不牵连：mode 关掉也照样能进（guest 独立）。
	e.setPolicy(t, root, true, "closed", true)
	caps = e.caps(t)
	if caps["guest_open"] != true || caps["sign_up_open"] != false {
		t.Fatalf("guest 開關的獨立性：%v", caps)
	}
	gc, _ := e.enterGuest(t, "策略切換訪客")
	r2WantErr(t, e.get(t, "/admin/accounts", gc), 2011, "訪客的讀也受閘")

	e.auditLeakScan(t, r2SelfRegPw, "$argon2id$", "password_hash", spareCode, code)
}

// TestR2GuestLifecycleClosedLoop 走完访客的全部生命周期：进入、原地升级、
// 绑定预检→签发→本人核销、退休终态、软删除，并逐条核对「访客旧会话不能接管绑定目标」
// 「删除不破坏历史引用」。
func TestR2GuestLifecycleClosedLoop(t *testing.T) {
	e := newR2Env(t)
	root := e.root(t)
	e.setPolicy(t, root, true, "closed", true)
	adminCookie, adminID := e.onboardAdmin(t, root, "R2.Chain.Admin")

	// 进入：拿到的是与普通账户同规格、但零授予的会话；目录列得出他。
	guestCookie, g1 := e.enterGuest(t, "夜訪客一")
	sess := r2WantOK(t, e.get(t, "/auth/session", guestCookie), http.StatusOK, "訪客會話")
	if sess["account_type"] != "guest" || sess["roles"] != nil {
		t.Fatalf("訪客現讀：%v", sess)
	}
	r2WantErr(t, e.do(t, http.MethodPost, "/admin/accounts",
		`{"login_name":"R2.Chain.Hijack","display_name":"企圖","password":"`+r2SelfRegPw+`"}`,
		guestCookie, ""), 2011, "訪客企圖建號")
	r2WantErr(t, e.do(t, http.MethodPost, "/root/invite-codes",
		`{"label":"企圖","max_uses":1}`, guestCookie, ""), 2011, "訪客企圖建碼")
	dir := r2WantOK(t, e.get(t, "/admin/accounts?type=guest", adminCookie),
		http.StatusOK, "目錄篩訪戶")
	if r2Find(r2List(dir["accounts"]), "account_id", g1) == nil {
		t.Fatalf("目錄應列得出訪戶：%v", dir["accounts"])
	}

	// 就地升级：同一个标识换个形态，旧访客会话当场作废，欠首改闭环照常。
	up := r2WantOK(t, e.do(t, http.MethodPut, "/admin/accounts/"+g1+"/upgrade",
		`{"login_name":"R2.Former.One","password":"`+r2InitialPw+`"}`, adminCookie, ""),
		http.StatusOK, "訪戶就地升級")
	upgraded := up["account"].(map[string]any)
	if upgraded["account_id"] != g1 || upgraded["account_type"] != "standard" ||
		upgraded["status"] != "active" || upgraded["must_change_password"] != true {
		t.Fatalf("升級後的現值：%v", upgraded)
	}
	r2WantErr(t, e.get(t, "/auth/session", guestCookie), 2003, "升級後舊訪客會話")
	formerResp := e.login(t, "R2.Former.One", r2InitialPw)
	r2WantOK(t, formerResp, http.StatusOK, "升級者以新憑據登入")
	e.changePw(t, loginCookie(t, formerResp), r2InitialPw, r2ChangedPw)
	r2WantErr(t, e.do(t, http.MethodPut, "/admin/accounts/"+g1+"/upgrade",
		`{"login_name":"R2.Former.Again","password":"`+r2InitialPw+`"}`, adminCookie, ""),
		2024, "重複升級")
	// 访客本人不能给自己升级——那是管理员按下才成立的动作。
	g2Cookie, g2 := e.enterGuest(t, "夜訪客二")
	r2WantErr(t, e.do(t, http.MethodPut, "/admin/accounts/"+g2+"/upgrade",
		`{"login_name":"R2.Self.Upgrade","password":"`+r2InitialPw+`"}`, g2Cookie, ""),
		2011, "訪戶自我升級")

	// —— 绑定三段：预检（只读）→ 签发（管理员）→ 核销（目标本人） ——
	targetID, targetCookie := e.onboardStandard(t, adminCookie, "R2.Bind.Target")
	g3Cookie, g3 := e.enterGuest(t, "夜訪客三")
	pre := r2WantOK(t, e.do(t, http.MethodPost, "/admin/accounts/"+g3+"/bind-preflight",
		`{"target_account_id":"`+targetID+`"}`, adminCookie, ""),
		http.StatusOK, "綁定預檢")
	if pre["executable"] != true || len(r2List(pre["blockers"])) != 0 ||
		pre["consent_mode"] != "target_self_initiated" {
		t.Fatalf("預檢形態：%v", pre)
	}
	issued := r2WantOK(t, e.do(t, http.MethodPost, "/admin/accounts/"+g3+"/bind-ticket",
		`{"target_account_id":"`+targetID+`"}`, adminCookie, ""),
		http.StatusOK, "簽發綁定憑證")
	ticket, _ := issued["ticket"].(string)
	if ticket == "" {
		t.Fatalf("簽發應恰此一次帶出憑證明文")
	}
	// 「Guest 旧会话不能接管绑定目标」的三个面：源本人执行被主体闸挡（他不是目标持有人）、
	// 局外普通账户执行同句拒绝、管理员也不能代按。
	r2WantErr(t, e.do(t, http.MethodPost, "/auth/guest-bindings",
		`{"ticket":"`+ticket+`"}`, g3Cookie, ""), 2011, "訪戶舊會話企圖核銷")
	outsiderID, outsiderCookie := e.onboardStandard(t, adminCookie, "R2.Bind.Outsider")
	r2WantErr(t, e.do(t, http.MethodPost, "/auth/guest-bindings",
		`{"ticket":"`+ticket+`"}`, outsiderCookie, ""), 2025, "局外人企圖核銷")
	r2WantErr(t, e.do(t, http.MethodPost, "/auth/guest-bindings",
		`{"ticket":"`+ticket+`"}`, adminCookie, ""), 2011, "管理員企圖代執行")
	preview := r2WantOK(t, e.do(t, http.MethodPost, "/auth/guest-bindings/preview",
		`{"ticket":"`+ticket+`"}`, targetCookie, ""), http.StatusOK, "目標本人預覽")
	if preview["consent_mode"] != "target_self_initiated" ||
		preview["source"].(map[string]any)["account_type"] != "guest" {
		t.Fatalf("本人預覽形態：%v", preview)
	}
	if got := e.countRows(t, "guest_account_bindings"); got != 0 {
		t.Fatalf("預覽之後留痕表仍應為空：%d", got)
	}
	confirmed := r2WantOK(t, e.do(t, http.MethodPost, "/auth/guest-bindings",
		`{"ticket":"`+ticket+`"}`, targetCookie, ""), http.StatusOK, "目標本人核銷")
	source := confirmed["source"].(map[string]any)
	if source["account_id"] != g3 || source["status"] != "retired" || source["retired_at"] == nil {
		t.Fatalf("核銷後的來源現值：%v", source)
	}
	if confirmed["revoked_sessions"].(float64) < 1 {
		t.Fatalf("綁定應同交易撤走源會話：%v", confirmed["revoked_sessions"])
	}
	r2WantErr(t, e.get(t, "/auth/session", g3Cookie), 2003, "核銷後的源會話")
	r2WantErr(t, e.do(t, http.MethodPost, "/auth/guest-bindings",
		`{"ticket":"`+ticket+`"}`, targetCookie, ""), 2025, "憑證重放")
	if got := e.countRows(t, "guest_account_bindings"); got != 1 {
		t.Fatalf("一次綁定只留一行痕：%d", got)
	}
	list := r2WantOK(t, e.get(t, "/auth/guest-bindings", targetCookie), http.StatusOK, "本人讀留痕")
	if list["total"].(float64) != 1 {
		t.Fatalf("留痕清單：%v", list)
	}
	r2WantOK(t, e.get(t, "/auth/session", targetCookie), http.StatusOK, "目標會話不受牽連")

	// 退休终态：读得到、点得开、一律动不了——四类写入各回 2028，删除也是同一句。
	detail := r2WantOK(t, e.get(t, "/admin/accounts/"+g3, adminCookie),
		http.StatusOK, "退休訪戶詳情")
	if detail["account"].(map[string]any)["status"] != "retired" {
		t.Fatalf("退休現值：%v", detail["account"])
	}
	retiredWrites := []struct{ method, path, body string }{
		{http.MethodPut, "/admin/accounts/" + g3, `{"display_name":"翻案","expected_display_name":"夜訪客三"}`},
		{http.MethodPut, "/admin/accounts/" + g3 + "/status", `{"status":"active","expected_status":"disabled"}`},
		{http.MethodPut, "/admin/accounts/" + g3 + "/password", `{"password":"` + r2ChangedPw + `"}`},
		{http.MethodPut, "/admin/accounts/" + g3 + "/upgrade",
			`{"login_name":"R2.Retry","password":"` + r2InitialPw + `"}`},
	}
	for _, w := range retiredWrites {
		r2WantErr(t, e.do(t, w.method, w.path, w.body, adminCookie, ""), 2028, "對退休者的寫入")
	}
	r2WantErr(t, e.do(t, http.MethodDelete, "/admin/accounts/"+g3, "", adminCookie, ""),
		2028, "對退休者的刪除")

	// 签发与执行之间的事实漂移：2026，一个字节都不落地。
	_, g4 := e.enterGuest(t, "夜訪客四")
	drift := r2WantOK(t, e.do(t, http.MethodPost, "/admin/accounts/"+g4+"/bind-ticket",
		`{"target_account_id":"`+outsiderID+`"}`, adminCookie, ""),
		http.StatusOK, "漂移場景簽發")
	driftTicket := drift["ticket"].(string)
	r2WantOK(t, e.do(t, http.MethodPut, "/admin/accounts/"+g4+"/status",
		`{"status":"disabled","expected_status":"active"}`, adminCookie, ""),
		http.StatusOK, "簽發後停用來源")
	r2WantErr(t, e.do(t, http.MethodPost, "/auth/guest-bindings",
		`{"ticket":"`+driftTicket+`"}`, outsiderCookie, ""), 2026, "執行過時計劃")
	if got := e.statusOf(t, g4); got != "disabled" {
		t.Fatalf("漂移被拒之後來源仍是停用，不是退休：%s", got)
	}
	if got := e.countRows(t, "guest_account_bindings"); got != 1 {
		t.Fatalf("漂移被拒不多留一行痕：%d", got)
	}

	// 软删除不级联：删掉被留痕引用的目标，留痕、退休源、名字占用原样不动。
	deletedTarget := r2WantOK(t, e.do(t, http.MethodDelete, "/admin/accounts/"+targetID, "",
		adminCookie, ""), http.StatusOK, "刪除綁定目標")
	if deletedTarget["account"].(map[string]any)["deleted_at"] == nil {
		t.Fatalf("目標刪除現值：%v", deletedTarget["account"])
	}
	if got := e.countRows(t, "guest_account_bindings"); got != 1 {
		t.Fatalf("刪除不得級聯搬動留痕：%d", got)
	}
	if got := e.statusOf(t, g3); got != "retired" {
		t.Fatalf("目標被刪之後源仍应是退休：%s", got)
	}
	r2WantErr(t, e.do(t, http.MethodPut, "/admin/accounts/"+targetID+"/status",
		`{"status":"active","expected_status":"disabled"}`, adminCookie, ""), 2027, "對已刪目標的寫入")
	r2WantErr(t, e.do(t, http.MethodDelete, "/admin/accounts/"+targetID, "", adminCookie, ""),
		2027, "重複刪除普通目標")
	delDir := r2WantOK(t, e.get(t, "/admin/accounts?status=deleted", adminCookie),
		http.StatusOK, "已刪篩選")
	if r2Find(r2List(delDir["accounts"]), "account_id", targetID) == nil {
		t.Fatalf("已刪普通帳戶應仍列目錄：%v", delDir["accounts"])
	}

	// 被删的申请人在本人证明通路上收敛成与凭据失败同形的一句。
	e.setPolicy(t, root, true, "approval", true)
	gone := r2WantOK(t, e.register(t, `{"login_name":"R2.Gone.One","display_name":"會被刪的申請人","password":"`+
		r2SelfRegPw+`"}`), http.StatusCreated, "為刪除而建的申請")
	goneID := gone["account_id"].(string)
	r2WantOK(t, e.decide(t, adminCookie, goneID, `{"decision":"approve"}`),
		http.StatusOK, "批准後再刪")
	r2WantOK(t, e.do(t, http.MethodDelete, "/admin/accounts/"+goneID, "", adminCookie, ""),
		http.StatusOK, "刪除已批准者")
	r2WantErr(t, e.regStatus(t, "R2.Gone.One", r2SelfRegPw), 2001, "被刪申請人的證明通路")

	// 审计归因到真实操作者，且没有把口令/哈希/凭证明文写进任何一行变更摘要。
	if kind, actor := e.auditActor(t, "account.delete"); kind != "admin" || actor != adminID {
		t.Fatalf("account.delete 的審計主體應是那位管理員：%q %q", kind, actor)
	}
	if kind, actor := e.auditActor(t, "account.guest_bind_ticket_issue"); kind != "admin" || actor != adminID {
		t.Fatalf("簽發的審計主體應是那位管理員：%q %q", kind, actor)
	}
	e.auditLeakScan(t, r2InitialPw, r2ChangedPw, r2SelfRegPw, "$argon2id$", "password_hash", ticket)
}

// TestR2RoleAuthorizationMatrix 用同一套自建数据把「六个调用者 × 每一条受保护通路」
// 并排放进一张表：传输层不做授权（共用前置链只换出受信主体），
// 每一格的结论都由用例的 identity.Authorize 与范围核实给出——
// 因此这一张矩阵同时是 HTTP 层与服务层的证据。
//
// 六个调用者依次是：匿名、受限申请人（他今日没有任何会话材料——这一列因此与匿名同码，
// 这本身就是「申请不是登录主体」的结论）、访客、普通正式账户、管理员、Root。
func TestR2RoleAuthorizationMatrix(t *testing.T) {
	e := newR2Env(t)
	root := e.root(t)
	e.setPolicy(t, root, true, "approval", true)
	adminCookie, adminID := e.onboardAdmin(t, root, "R2.Matrix.Admin")
	_, stdCookie := e.onboardStandard(t, adminCookie, "R2.Matrix.Standard")
	guestCookie, _ := e.enterGuest(t, "矩陣訪客")
	applied := r2WantOK(t, e.register(t, `{"login_name":"R2.Matrix.Pending","display_name":"矩陣申請人","password":"`+
		r2SelfRegPw+`"}`), http.StatusCreated, "矩陣里的待審申請")
	pendingID := applied["account_id"].(string)

	ghostA, ghostB := r2Ghost(t), r2Ghost(t)

	type cell struct {
		status int // >0：期望的 2xx 状态；0：期望错误信封
		code   int // status==0 时期望的错误码
	}
	ok200 := cell{status: http.StatusOK}
	ok201 := cell{status: http.StatusCreated}
	no := func(c int) cell { return cell{code: c} }

	rows := []struct {
		what, method, path, body string
		want                     [6]cell
	}{
		{"匿名入口能力", http.MethodGet, "/auth/capabilities", "",
			[6]cell{ok200, ok200, ok200, ok200, ok200, ok200}},
		{"讀 Root 管理員目錄", http.MethodGet, "/root/admins", "",
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(2011), ok200}},
		{"讀帳戶建立策略", http.MethodGet, "/root/account-policy", "",
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(2011), ok200}},
		{"讀邀請碼名冊", http.MethodGet, "/root/invite-codes", "",
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(2011), ok200}},
		{"讀普通帳戶目錄", http.MethodGet, "/admin/accounts", "",
			[6]cell{no(2002), no(2002), no(2011), no(2011), ok200, ok200}},
		{"讀審批名冊", http.MethodGet, "/admin/registrations", "",
			[6]cell{no(2002), no(2002), no(2011), no(2011), ok200, ok200}},
		// 白名单里没有角色格：这一行量的是「不管你是谁，伪造栏位都死在请求本体验证」；
		// 「越权的人连请求本体都来不及被受理」由上面幽灵目标各行的 2011/2002 列证明。
		{"自報角色的建號", http.MethodPost, "/admin/accounts",
			`{"login_name":"R2.Matrix.Forged","display_name":"自報","password":"` + r2SelfRegPw +
				`","roles":["server_admin"]}`,
			[6]cell{no(2002), no(2002), no(1004), no(1004), no(1004), no(1004)}},
		{"自報身份的申請證明", http.MethodPost, "/auth/registration-status",
			`{"login_name":"R2.Matrix.Pending","password":"` + r2SelfRegPw + `","account_id":"` + pendingID + `"}`,
			[6]cell{no(1004), no(1004), no(1004), no(1004), no(1004), no(1004)}},
		{"非 Root 開設管理員", http.MethodPost, "/root/admins",
			`{"login_name":"R2.Matrix.RootProbe","display_name":"Root probe","password":"` + r2InitialPw + `"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(2011), ok201}},
		{"對幽靈改管理員資料", http.MethodPut, "/root/admins/" + ghostA,
			`{"display_name":"幽靈改名","expected_display_name":"沒這個人"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(2011), no(1001)}},
		{"對幽靈停用管理員", http.MethodPut, "/root/admins/" + ghostA + "/status",
			`{"status":"disabled","expected_status":"active"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(2011), no(1001)}},
		{"對幽靈重置憑據", http.MethodPut, "/root/admins/" + ghostA + "/password",
			`{"password":"` + r2ChangedPw + `"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(2011), no(1001)}},
		{"對幽靈軟刪管理員", http.MethodDelete, "/root/admins/" + ghostA, "",
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(2011), no(1001)}},
		{"對幽靈改普通帳戶資料", http.MethodPut, "/admin/accounts/" + ghostA,
			`{"display_name":"幽靈改名","expected_display_name":"沒這個人"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(1001), no(1001)}},
		{"對幽靈停用普通帳戶", http.MethodPut, "/admin/accounts/" + ghostA + "/status",
			`{"status":"disabled","expected_status":"active"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(1001), no(1001)}},
		{"對幽靈重置普通憑據", http.MethodPut, "/admin/accounts/" + ghostA + "/password",
			`{"password":"` + r2ChangedPw + `"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(1001), no(1001)}},
		{"對幽靈升級訪戶", http.MethodPut, "/admin/accounts/" + ghostA + "/upgrade",
			`{"login_name":"R2.Matrix.Ghost","password":"` + r2InitialPw + `"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(1001), no(1001)}},
		{"對幽靈軟刪普通帳戶", http.MethodDelete, "/admin/accounts/" + ghostA, "",
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(1001), no(1001)}},
		{"對幽靈綁定預檢", http.MethodPost, "/admin/accounts/" + ghostA + "/bind-preflight",
			`{"target_account_id":"` + ghostB + `"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(1001), no(1001)}},
		{"對幽靈簽發憑證", http.MethodPost, "/admin/accounts/" + ghostA + "/bind-ticket",
			`{"target_account_id":"` + ghostB + `"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(1001), no(1001)}},
		{"對幽靈做審批決定", http.MethodPut, "/admin/registrations/" + ghostA + "/decision",
			`{"decision":"approve"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(1001), no(1001)}},
		{"管理員不在普通目錄射程", http.MethodPut, "/admin/accounts/" + adminID + "/status",
			`{"status":"disabled","expected_status":"active"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(1001), no(1001)}},
		{"對待審批申請人停用", http.MethodPut, "/admin/accounts/" + pendingID + "/status",
			`{"status":"disabled","expected_status":"active"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(1001), no(1001)}},
		{"對待審批申請人軟刪", http.MethodDelete, "/admin/accounts/" + pendingID, "",
			[6]cell{no(2002), no(2002), no(2011), no(2011), no(1001), no(1001)}},
		// 自助核销通路的主体闸先于一切查询：访客与管理员/Root 都过不了「目标本人」这一关；
		// 普通账户过关之后才轮到「这枚凭证不是给他的」同一句 2025。
		{"訪戶會話核銷憑證", http.MethodPost, "/auth/guest-bindings",
			`{"ticket":"r2-matrix-not-a-ticket"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2025), no(2011), no(2011)}},
		{"訪戶會話預覽憑證", http.MethodPost, "/auth/guest-bindings/preview",
			`{"ticket":"r2-matrix-not-a-ticket"}`,
			[6]cell{no(2002), no(2002), no(2011), no(2025), no(2011), no(2011)}},
	}

	principals := []*http.Cookie{nil, nil, guestCookie, stdCookie, adminCookie, root}
	names := [6]string{"匿名", "受限申請人", "訪客", "普通帳戶", "管理員", "Root"}

	for _, row := range rows {
		for i, cookie := range principals {
			resp := e.do(t, row.method, row.path, row.body, cookie, "")
			want := row.want[i]
			if want.status > 0 {
				r2WantOK(t, resp, want.status, row.what+"×"+names[i])
			} else {
				r2WantErr(t, resp, want.code, row.what+"×"+names[i])
			}
		}
	}

	// 跨站来源带着各角色的真 Cookie：统一 2005，且在权限矩阵之外同样「零写入」。
	accountsBefore := e.countRows(t, "accounts")
	for i, cookie := range principals[2:] {
		r2WantErr(t, e.do(t, http.MethodPost, "/admin/accounts",
			`{"login_name":"R2.Matrix.CrossSite","display_name":"跨站","password":"`+r2SelfRegPw+`"}`,
			cookie, "https://evil.invalid"), 2005, "跨站建號×"+names[i+2])
	}
	if got := e.countRows(t, "accounts"); got != accountsBefore {
		t.Fatalf("跨站被拒之後不應有任何寫入：before %d after %d", accountsBefore, got)
	}

	e.auditLeakScan(t, r2SelfRegPw, r2InitialPw, "$argon2id$", "password_hash")
}
