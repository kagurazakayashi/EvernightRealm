// identity_device_loop_test.go 是「Root 身份與裝置管理完整閉環」的驗收探針：
// 以審查者視角把已交付的各段（一次性初始化、登入與 Cookie／CSRF、會話恢復、
// 裝置登入策略、本人裝置清單與定向撤銷、本人改密與舊會話失效、撤銷式登出、
// 本機憑據恢復）在同一條時間線上按真實使用順序串起來走一遍，
// 全部落在本次專屬的臨時資料目錄與臨時資料庫。
//
// 邊界（刻意不做的事）：
//   - 不新增任何生產端點或後門：普通帳戶一律經 internal/account 的倉儲介面在
//     測試進程內種入（隔離測試工廠），生產建號通路本來就不存在；
//   - 真實瀏覽器的 Cookie 自動附帶、原生宿主的安全儲存與斷網／證書類場景不在
//     本機可安全重現的範圍內——這裡的取證到 Go HTTP 層為止，其餘照實標未驗證；
//   - 時刻一律來自 timeutil 的注入時鐘：限流冷卻、絕對到期與閒置到期都不等待
//     真實週期，也不觸碰主機時間。
package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/httpapi"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/rootinit"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// loopEnv 是「真實裝配（配置檔 Root 憑據＋真實 SQLite＋中介層鏈）＋進程內 HTTP 服務」的
// 本次專屬現場。它刻意複用 run() 裡同一批構造呼叫（newRootCredentialStore、
// session.NewStoreWithPolicy、auth.NewLoginGuard、auth.New、httpapi.New），
// 差別只有兩件：時鐘換成可注入的測試時鐘、監聽換成 httptest 的記憶體服務
// （不佔任何本機埠，5206 從頭到尾不被觸碰）。
type loopEnv struct {
	ts       *httptest.Server
	client   *http.Client
	db       *database.DB
	clock    *timeutil.Test
	sessions *session.Store
	accounts *account.Store
	cfg      config.Config
	dir      string
	closed   bool
}

// loopGuardOff 是「額度大到本案觸不到」的守衛參數：只有限流場景自己改寫閾值，
// 其餘場景用的仍是與正式裝配同構的真實守衛，而不是無守衛的捷徑。
var loopGuardOff = auth.GuardConfig{
	FailLimit:       1000,
	Window:          15 * time.Minute,
	Cooldown:        15 * time.Minute,
	SourceFailLimit: 1000,
	MaxEntries:      10000,
}

// newLoopEnv 在既有（已遷移、並由 init-root 寫入或尚未寫入憑據的）資料目錄上搭建現場。
//
// Root 憑據的來源與正式啟動逐字相同：config.Load 讀那份 config.yaml，
// newRootCredentialStore 以它合成運行期現值——本檔因此沒有第二份「測試用的 Root 口令」。
func newLoopEnv(t *testing.T, dir string, policy session.Policy, guard auth.GuardConfig) *loopEnv {
	t.Helper()
	clock := timeutil.NewTest(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	db, err := openTestDatabase(context.Background(), dir)
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	cfg, err := config.Load(config.Options{DataDir: dir})
	if err != nil {
		t.Fatalf("載入測試組態失敗：%v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("測試組態不合法：%v", err)
	}
	sessions, err := session.NewStoreWithPolicy(clock,
		time.Duration(cfg.Security.SessionTTLHours)*time.Hour, policy)
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	params, err := cfg.Security.Hashing.Params()
	if err != nil {
		t.Fatalf("雜湊參數檔不合格：%v", err)
	}
	loginGuard, err := auth.NewLoginGuard(guard, clock)
	if err != nil {
		t.Fatalf("建立登入守衛失敗：%v", err)
	}
	service, err := auth.New(auth.Deps{
		DB:       db,
		Sessions: sessions,
		Accounts: account.NewStore(clock),
		Audits:   audit.NewStore(clock),
		// RootCreds 取的就是那份配置檔：與 run() 的注入逐字同構。
		RootCreds: newRootCredentialStore(cfg),
		Hashing:   params,
		Guard:     loginGuard,
	})
	if err != nil {
		t.Fatalf("建立登入用例失敗：%v", err)
	}
	srv := httpapi.New(&cfg, Version, httpapi.Deps{
		Auth:       service,
		Clock:      clock,
		InitStatus: initStatusSource(cfg),
	})
	ts := httptest.NewServer(srv.Handler())
	env := &loopEnv{ts: ts, client: &http.Client{}, db: db, clock: clock, sessions: sessions,
		accounts: account.NewStore(clock), cfg: cfg, dir: dir}
	t.Cleanup(env.close)
	return env
}

// close 關閉進程內服務與資料庫連線（釋放單寫入實例鎖，讓本機 CLI 命令能接手）。
// 冪等：重複呼叫不重複關閉。空閒連線刻意先收掉，不讓本測試的 socket 佔用拖到後面。
func (e *loopEnv) close() {
	if e.closed {
		return
	}
	e.closed = true
	e.client.CloseIdleConnections()
	e.ts.Close()
	_ = e.db.Close()
}

// loopRequest 是一次對現場內 HTTP 服務的請求描述。
//
// 欄位就是瀏覽器／原生客戶端真正能決定的那幾件事：有無 Origin（哪來的頁面）、
// Sec-Fetch-Site（瀏覽器自證）、Cookie 與 Bearer（兩條認證通路）。
type loopRequest struct {
	method   string
	path     string
	body     string
	origin   string
	secFetch string
	cookie   string // evernight_session 的值；空字串表示不帶 Cookie
	bearer   string // Bearer 秘密；空字串表示不帶標頭
}

// loopResult 是回應的可斷言形態：狀態碼、信封解析結果、原始文字與實用的回應標頭。
type loopResult struct {
	status      int
	body        map[string]any
	raw         string
	setCookie   []string
	retryAfter  string
	code        int
	hasEnvelope bool
}

// do 發送請求並解析回應。
func (e *loopEnv) do(t *testing.T, in loopRequest) loopResult {
	t.Helper()
	var rdr io.Reader
	if in.body != "" {
		rdr = strings.NewReader(in.body)
	}
	req, err := http.NewRequest(in.method, e.ts.URL+in.path, rdr)
	if err != nil {
		t.Fatalf("構造請求失敗：%v", err)
	}
	if in.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if in.origin != "" {
		req.Header.Set("Origin", in.origin)
	}
	if in.secFetch != "" {
		req.Header.Set("Sec-Fetch-Site", in.secFetch)
	}
	if in.cookie != "" {
		req.AddCookie(&http.Cookie{Name: "evernight_session", Value: in.cookie})
	}
	if in.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+in.bearer)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatalf("請求失敗：%v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀回應失敗：%v", err)
	}
	out := loopResult{status: resp.StatusCode, raw: string(data),
		setCookie:  resp.Header.Values("Set-Cookie"),
		retryAfter: resp.Header.Get("Retry-After")}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err == nil {
		out.body = parsed
		if c, ok := parsed["code"].(float64); ok {
			out.code = int(c)
			out.hasEnvelope = true
		}
	}
	return out
}

// cookieValue 取回應分發的會話 Cookie 值（秘密的唯一去處；回應本體刻意不含）。
func (r loopResult) cookieValue(t *testing.T) string {
	t.Helper()
	for _, line := range r.setCookie {
		if strings.HasPrefix(line, "evernight_session=") {
			rest := strings.TrimPrefix(line, "evernight_session=")
			if idx := strings.Index(rest, ";"); idx >= 0 {
				return rest[:idx]
			}
			return rest
		}
	}
	t.Fatalf("回應沒有分發會話 Cookie：%v", r.setCookie)
	return ""
}

// loginRoot 以瀏覽器形態（同源 Origin）登入 Root。
func (e *loopEnv) loginRoot(t *testing.T, password string) loopResult {
	t.Helper()
	return e.do(t, loopRequest{
		method: http.MethodPost, path: "/auth/root/login",
		body:   `{"password":"` + password + `"}`,
		origin: e.ts.URL,
	})
}

// loginAccount 以瀏覽器形態登入普通帳戶。
func (e *loopEnv) loginAccount(t *testing.T, loginName, password string) loopResult {
	t.Helper()
	return e.do(t, loopRequest{
		method: http.MethodPost, path: "/auth/login",
		body:   `{"login_name":"` + loginName + `","password":"` + password + `"}`,
		origin: e.ts.URL,
	})
}

// sessionGet 帶 Cookie 問當前會話（客戶端「重新打開後恢復會話」在服務端就是這一問）。
func (e *loopEnv) sessionGet(t *testing.T, cookie string) loopResult {
	t.Helper()
	return e.do(t, loopRequest{method: http.MethodGet, path: "/auth/session",
		cookie: cookie, origin: e.ts.URL})
}

// devicesGet 帶 Cookie 問本人裝置清單。
func (e *loopEnv) devicesGet(t *testing.T, cookie string) loopResult {
	t.Helper()
	return e.do(t, loopRequest{method: http.MethodGet, path: "/auth/devices",
		cookie: cookie, origin: e.ts.URL})
}

// want 斷言狀態碼；code 非零時再斷言信封機器碼。
func (r loopResult) want(t *testing.T, status, code int) {
	t.Helper()
	if r.status != status {
		t.Errorf("狀態碼 %d，期望 %d（回應：%s）", r.status, status, r.raw)
	}
	if code != 0 {
		if !r.hasEnvelope || r.code != code {
			t.Errorf("機器碼 %d（信封？%v），期望 %d（回應：%s）", r.code, r.hasEnvelope, code, r.raw)
		}
	}
}

// deviceIDsFromList 把 /auth/devices 的回應解析成 (device_id → 狀態) 與 current 標記。
func deviceIDsFromList(t *testing.T, r loopResult) (map[string]string, string) {
	t.Helper()
	list, ok := r.body["devices"].([]any)
	if !ok {
		t.Fatalf("裝置清單形狀異常：%s", r.raw)
	}
	out := map[string]string{}
	current := ""
	for _, item := range list {
		d, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("裝置條目形狀異常：%s", r.raw)
		}
		id, _ := d["device_id"].(string)
		status, _ := d["status"].(string)
		out[id] = status
		if cur, _ := d["current"].(bool); cur {
			if current != "" {
				t.Errorf("清單出現了第二枚 current：%s", r.raw)
			}
			current = id
		}
	}
	return out, current
}

// loopAuditCount 讀回指定 action 在 root_audit 的筆數。收 Querier：
// 現場活著時走現場自己的連線（單寫入實例鎖不允許第二條 Open），停著時走新開的連線。
func loopAuditCount(t *testing.T, q database.Querier, action string) int {
	t.Helper()
	var n int
	if err := q.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = ?", action).Scan(&n); err != nil {
		t.Fatalf("統計審計失敗：%v", err)
	}
	return n
}

// scanAuditTableText 把 root_audit 全表讀成文字（僅供「不得出現秘密」的掃描）。
func scanAuditTableText(t *testing.T, q database.Querier) string {
	t.Helper()
	rows, err := q.QueryContext(context.Background(),
		"SELECT COALESCE(action,''), COALESCE(reason,''), COALESCE(target_kind,''), COALESCE(target_id,''), COALESCE(changes_json,''), COALESCE(actor_kind,'') FROM root_audit")
	if err != nil {
		t.Fatalf("讀取審計失敗：%v", err)
	}
	defer func() { _ = rows.Close() }()
	var sb strings.Builder
	for rows.Next() {
		var action, reason, kind, targetID, changes, actor string
		if err := rows.Scan(&action, &reason, &kind, &targetID, &changes, &actor); err != nil {
			t.Fatalf("逐行讀審計失敗：%v", err)
		}
		sb.WriteString(action + "|" + reason + "|" + kind + "|" + targetID + "|" + changes + "|" + actor + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍歷審計失敗：%v", err)
	}
	return sb.String()
}

// auditAtClosedDir 在「沒有現場佔著實例鎖」的時段開一條新連線數審計（本機 CLI 段落用）。
func auditAtClosedDir(t *testing.T, dir string, action string) int {
	t.Helper()
	db, err := openTestDatabase(context.Background(), dir)
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	defer func() { _ = db.Close() }()
	return loopAuditCount(t, db.SQL(), action)
}

// countAccounts 讀 accounts 行數（核對 Root 通路不經 accounts 表）。
func countAccounts(t *testing.T, env *loopEnv) int {
	t.Helper()
	var n int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM accounts").Scan(&n); err != nil {
		t.Fatalf("統計帳戶失敗：%v", err)
	}
	return n
}

// sessionDeviceID 用一枚會話秘密讀出它的 device_id（經會話倉儲的驗證通路，不直查表）。
func sessionDeviceID(t *testing.T, env *loopEnv, secret string) string {
	t.Helper()
	sess, err := env.sessions.Verify(context.Background(), env.db.SQL(), secret)
	if err != nil {
		t.Fatalf("前置：會話應有效：%v", err)
	}
	return sess.DeviceID.String()
}

// TestRootIdentityDeviceClosedLoop 按真實使用順序演練本部分的完整閉環：
// 未初始化 → 安全初始化 → Root 登入 → 重新打開恢復會話 → 裝置策略 →
// 查看與撤銷本人裝置 → 憑據修改 → 舊會話失效 → 退出 → 本機恢復。
func TestRootIdentityDeviceClosedLoop(t *testing.T) {
	const (
		pwInit      = "loop-init-_Pass-1"
		pwChanged   = "loop-changed-_Pass-2"
		pwRecovered = "loop-recovered-_Pass-3"
	)
	ctx := context.Background()
	dir := newRootInitDir(t)
	policyLimited := session.Policy{DeviceMode: session.DeviceModeLimited, MaxDevices: 3}

	// —— 第 1 段：未初始化。恢復命令拒絕、HTTP 登入拒絕、init-status 說真話 ——
	env0 := newLoopEnv(t, dir, policyLimited, loopGuardOff)
	initStatus := env0.do(t, loopRequest{method: http.MethodGet, path: "/root/init-status"})
	initStatus.want(t, http.StatusOK, 0)
	if got, _ := initStatus.body["root_initialized"].(bool); got {
		t.Error("未初始化的目錄上 init-status 竟回報已初始化")
	}
	refused := env0.loginRoot(t, pwInit)
	refused.want(t, http.StatusUnauthorized, int(httpapi.CodeInvalidCredentials))
	if n := loopAuditCount(t, env0.db.SQL(), "auth.login_failure"); n != 1 {
		t.Errorf("未初始化時的 Root 登入拒絕應留一筆失敗審計，實際 %d", n)
	}
	env0.close()
	// 恢復要求服務停止（持有資料庫單寫入實例鎖的進程不能同時存在）：
	// 在完全未初始化的目錄上，它要以「沒有可恢復的憑據」拒絕，且檔案字節不變。
	beforeBytes := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml"))
	if err := RecoverRoot(ctx, recoverArgs(dir), stdinSecrets(pwRecovered, pwRecovered), &syncBuffer{}); !errors.Is(err, rootinit.ErrNoExistingCredential) {
		t.Errorf("尚無憑據時恢復應以「無可恢復憑據」拒絕，實際 %v", err)
	}
	if got := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml")); got != beforeBytes {
		t.Error("被拒的恢復改動了組態檔")
	}

	// —— 第 2 段：安全初始化。一次性合同＋初始化審計落地 ——
	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets(pwInit, pwInit), &syncBuffer{}); err != nil {
		t.Fatalf("初始化失敗：%v", err)
	}
	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("second-_Pass", "second-_Pass"), &syncBuffer{}); !errors.Is(err, config.ErrRootAlreadyInitialized) {
		t.Errorf("重複初始化必須被一次性合同拒絕，實際 %v", err)
	}
	if n := auditAtClosedDir(t, dir, "server.root_initialize"); n != 1 {
		t.Errorf("初始化審計應為 1 筆，實際 %d", n)
	}

	env := newLoopEnv(t, dir, policyLimited, loopGuardOff)
	origin := env.ts.URL

	initStatus2 := env.do(t, loopRequest{method: http.MethodGet, path: "/root/init-status"})
	if got, _ := initStatus2.body["root_initialized"].(bool); !got {
		t.Error("初始化後 init-status 仍回報未初始化")
	}

	// —— 第 3 段：Root 登入與重新打開恢復會話 ——
	wrong := env.loginRoot(t, "wrong-_Pass")
	wrong.want(t, http.StatusUnauthorized, int(httpapi.CodeInvalidCredentials))
	if strings.Contains(wrong.raw, "wrong-_Pass") || strings.Contains(wrong.raw, pwInit) {
		t.Errorf("登入失敗回應回顯了口令：%s", wrong.raw)
	}

	first := env.loginRoot(t, pwInit)
	first.want(t, http.StatusOK, 0)
	cookie1 := first.cookieValue(t)
	var issued string
	for _, line := range first.setCookie {
		if strings.HasPrefix(line, "evernight_session=") {
			issued = line
		}
	}
	for _, want := range []string{"HttpOnly", "SameSite=Lax", "Path=/", "Max-Age="} {
		if !strings.Contains(issued, want) {
			t.Errorf("簽發 Cookie 缺少屬性 %s（原文：%s）", want, issued)
		}
	}
	if strings.Contains(first.raw, cookie1) {
		t.Error("登入回應本體不得含會話秘密")
	}
	if kind, _ := first.body["subject_kind"].(string); kind != "root" {
		t.Errorf("主體類別應為 root：%v", first.body["subject_kind"])
	}
	if _, ok := first.body["account_id"]; ok {
		t.Error("Root 不應帶 account_id")
	}
	if n := countAccounts(t, env); n != 0 {
		t.Errorf("Root 登入不得寫入 accounts 表，實際 %d 行", n)
	}

	// 「重新打開」的語意：客戶端從保存處取出同一枚秘密再問——Web 走 Cookie、
	// 原生走 Bearer（不帶 Origin），兩條路都必須換回同一個受信主體。
	resume := env.sessionGet(t, cookie1)
	resume.want(t, http.StatusOK, 0)
	if kind, _ := resume.body["subject_kind"].(string); kind != "root" {
		t.Errorf("恢復會話的主體類別應為 root：%v", resume.body["subject_kind"])
	}
	native := env.do(t, loopRequest{method: http.MethodGet, path: "/auth/session", bearer: cookie1})
	native.want(t, http.StatusOK, 0)

	// 認證方式獨佔與來源閘：混用與瀏覽器 Bearer 都是 2004；跨站寫入是 2005。
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/logout", cookie: cookie1,
		bearer: cookie1, origin: origin}).want(t, http.StatusBadRequest, int(httpapi.CodeAuthMethodConflict))
	env.do(t, loopRequest{method: http.MethodGet, path: "/auth/session", bearer: cookie1,
		origin: origin}).want(t, http.StatusBadRequest, int(httpapi.CodeAuthMethodConflict))
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/logout", cookie: cookie1,
		origin: "http://evil.example"}).want(t, http.StatusForbidden, int(httpapi.CodeOriginForbidden))
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/logout", cookie: cookie1,
		secFetch: "cross-site"}).want(t, http.StatusForbidden, int(httpapi.CodeOriginForbidden))
	// 被 CSRF 閘擋下的登出沒有生效：會話仍換得出身份。
	env.sessionGet(t, cookie1).want(t, http.StatusOK, 0)

	// —— 第 4 段：裝置登入策略（limited＝3）與本人裝置清單／定向撤銷 ——
	c2 := env.loginRoot(t, pwInit).cookieValue(t)
	c3 := env.loginRoot(t, pwInit).cookieValue(t)
	over := env.loginRoot(t, pwInit)
	over.want(t, http.StatusForbidden, int(httpapi.CodeDeviceLimitReached))
	if v, ok := over.body["details"]; ok && v != nil {
		t.Errorf("2008 回應不得帶出名額／會話等內部資訊：%s", over.raw)
	}
	env.sessionGet(t, c2).want(t, http.StatusOK, 0)

	list := env.devicesGet(t, c3)
	list.want(t, http.StatusOK, 0)
	statuses, _ := deviceIDsFromList(t, list)
	if len(statuses) != 3 {
		t.Errorf("三名額下清單應有 3 行：%v", statuses)
	}
	for id, st := range statuses {
		if st != "active" {
			t.Errorf("裝置 %s 的狀態應為 active，實際 %s", id, st)
		}
	}
	dev2 := sessionDeviceID(t, env, c2)
	revoke := env.do(t, loopRequest{method: http.MethodPost, path: "/auth/devices/revoke",
		body:   `{"device_id":"` + dev2 + `"}`,
		origin: origin, cookie: c3})
	revoke.want(t, http.StatusOK, 0)
	if got, _ := revoke.body["revoked"].(bool); !got {
		t.Error("首次撤銷應回報 revoked=true")
	}
	if got, _ := revoke.body["current"].(bool); got {
		t.Error("撤的是別臺時 current 必須為 false")
	}
	env.sessionGet(t, c2).want(t, http.StatusUnauthorized, int(httpapi.CodeSessionInvalid))
	// 冪等：重複撤銷同一枚早已撤銷的裝置不是錯誤。
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/devices/revoke",
		body: `{"device_id":"` + dev2 + `"}`, origin: origin,
		cookie: c3}).want(t, http.StatusOK, 0)
	// 不存在的裝置收斂為 2009（不洩露存在性）。
	ghost, err := idgen.New()
	if err != nil {
		t.Fatalf("產生隨機裝置標識失敗：%v", err)
	}
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/devices/revoke",
		body: `{"device_id":"` + ghost.String() + `"}`, origin: origin,
		cookie: c3}).want(t, http.StatusNotFound, int(httpapi.CodeDeviceNotFound))
	if n := loopAuditCount(t, env.db.SQL(), "auth.device_revoke"); n < 1 {
		t.Errorf("Root 定向撤銷應留 auth.device_revoke 審計，實際 %d", n)
	}

	// 名額釋放後第四次登入放行。
	c4 := env.loginRoot(t, pwInit)
	c4.want(t, http.StatusOK, 0)
	cookie4 := c4.cookieValue(t)

	// 清單含「已撤銷但未清理」的行：撤掉的裝置不會憑空消失。
	list2 := env.devicesGet(t, cookie4)
	statuses2, _ := deviceIDsFromList(t, list2)
	if len(statuses2) != 4 {
		t.Errorf("清單應含三名額內有效行與一枚尚未清理的已撤銷行：%v", statuses2)
	}
	if statuses2[dev2] != "revoked" {
		t.Errorf("被撤裝置在清單中應標為 revoked，實際 %q", statuses2[dev2])
	}

	// —— 第 5 段：憑據修改與舊會話失效 ——
	change := env.do(t, loopRequest{method: http.MethodPost, path: "/auth/password/change",
		body:   `{"current_password":"` + pwInit + `","new_password":"` + pwChanged + `"}`,
		origin: origin, cookie: cookie4})
	change.want(t, http.StatusOK, 0)
	if n, _ := change.body["revoked_sessions"].(float64); int(n) != 3 {
		t.Errorf("改密應撤銷名下全部 3 枚有效會話，回應回報 %v", change.body["revoked_sessions"])
	}
	// 連發起這一臺的 Cookie 也失效（已批准決定），舊口令立即登不進去。
	env.sessionGet(t, cookie4).want(t, http.StatusUnauthorized, int(httpapi.CodeSessionInvalid))
	env.sessionGet(t, c3).want(t, http.StatusUnauthorized, int(httpapi.CodeSessionInvalid))
	env.loginRoot(t, pwInit).want(t, http.StatusUnauthorized, int(httpapi.CodeInvalidCredentials))
	// 配置檔是唯一落點：檔案現值必須驗得過新口令、驗不過舊口令。
	hashNow := readStoredRootHash(t, dir)
	if _, err := identity.VerifyRootCredential(hashNow, pwChanged); err != nil {
		t.Errorf("配置檔現值應驗得過新口令：%v", err)
	}
	if _, err := identity.VerifyRootCredential(hashNow, pwInit); err == nil {
		t.Error("配置檔現值不應再驗得過舊口令")
	}
	// 錯誤形態各歸各：現行口令不對是 2001（會話保留）；同口令與自報欄位是 1004。
	live := env.loginRoot(t, pwChanged)
	live.want(t, http.StatusOK, 0)
	cookie5 := live.cookieValue(t)
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/password/change",
		body:   `{"current_password":"wrong-_Pass","new_password":"new-_Pass"}`,
		origin: origin, cookie: cookie5}).want(t, http.StatusUnauthorized, int(httpapi.CodeInvalidCredentials))
	env.sessionGet(t, cookie5).want(t, http.StatusOK, 0)
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/password/change",
		body:   `{"current_password":"` + pwChanged + `","new_password":"` + pwChanged + `"}`,
		origin: origin, cookie: cookie5}).want(t, http.StatusBadRequest, int(httpapi.CodeInvalidBody))
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/password/change",
		body:   `{"current_password":"x-_Pass","new_password":"y-_Pass","account_id":"deadbeef"}`,
		origin: origin, cookie: cookie5}).want(t, http.StatusBadRequest, int(httpapi.CodeInvalidBody))
	if n := loopAuditCount(t, env.db.SQL(), "auth.password_change"); n != 1 {
		t.Errorf("Root 改密審計應為 1 筆，實際 %d", n)
	}

	// —— 第 6 段：退出 ——
	logout := env.do(t, loopRequest{method: http.MethodPost, path: "/auth/logout",
		origin: origin, cookie: cookie5})
	logout.want(t, http.StatusOK, 0)
	var cleared string
	for _, line := range logout.setCookie {
		if strings.HasPrefix(line, "evernight_session=") {
			cleared = line
		}
	}
	if !strings.Contains(cleared, "Max-Age=0") || !strings.Contains(cleared, "HttpOnly") {
		t.Errorf("登出應下發與簽發同屬性的刪除指令：%s", cleared)
	}
	env.sessionGet(t, cookie5).want(t, http.StatusUnauthorized, int(httpapi.CodeSessionInvalid))
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/logout",
		origin: origin}).want(t, http.StatusOK, 0)
	if n := loopAuditCount(t, env.db.SQL(), "auth.logout"); n != 1 {
		t.Errorf("Root 登出審計應為 1 筆，實際 %d", n)
	}

	// —— 第 7 段：本機恢復（服務停止態下的唯一換口令通路）＋跨伺服器不混用 ——
	pre := env.loginRoot(t, pwChanged)
	pre.want(t, http.StatusOK, 0)
	cookie6 := pre.cookieValue(t)
	// 跨伺服器不混用：另一份部署（新目錄、獨立簽發）對這枚秘密給出真實的拒。
	foreignDir := newRootInitDir(t)
	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", foreignDir},
		stdinSecrets(pwInit, pwInit), &syncBuffer{}); err != nil {
		t.Fatalf("第二現場初始化失敗：%v", err)
	}
	foreign := newLoopEnv(t, foreignDir, session.Policy{}, loopGuardOff)
	foreign.sessionGet(t, cookie6).want(t, http.StatusUnauthorized, int(httpapi.CodeSessionInvalid))

	env.close() // 釋放單寫入實例鎖：恢復只允許在服務停止時發生
	if err := RecoverRoot(ctx, recoverArgs(dir), stdinSecrets(pwRecovered, pwRecovered), &syncBuffer{}); err != nil {
		t.Fatalf("本機恢復失敗：%v", err)
	}
	if _, err := identity.VerifyRootCredential(readStoredRootHash(t, dir), pwChanged); err == nil {
		t.Error("恢復後舊口令不應再是有效憑據")
	}
	if err := verifySessionSecret(t, dir, cookie6); !errors.Is(err, session.ErrRevoked) {
		t.Errorf("恢復應撤銷既有 Root 會話，實際 %v", err)
	}
	// 恢復是持久狀態：重啟後的服務上，舊口令登不進、新口令登得進。
	restarted := newLoopEnv(t, dir, session.Policy{}, loopGuardOff)
	restarted.loginRoot(t, pwChanged).want(t, http.StatusUnauthorized, int(httpapi.CodeInvalidCredentials))
	restarted.loginRoot(t, pwRecovered).want(t, http.StatusOK, 0)

	// —— 第 8 段：審計與運行日誌都不含秘密 ——
	auditDump := scanAuditTableText(t, restarted.db.SQL()) +
		scanAuditTableText(t, foreign.db.SQL())
	logDump := runLogContents(t, dir) + runLogContents(t, foreignDir)
	dump := auditDump + logDump
	for _, secret := range []string{pwInit, pwChanged, pwRecovered, "$argon2id$", cookie6} {
		if strings.Contains(dump, secret) {
			t.Errorf("審計或運行日誌出現秘密片段（長度 %d）", len(secret))
		}
	}
	// Root 域審計的主體只可能是 root（已認證 Root 動作）或 system（本機命令）：
	// 「以帳戶／管理名義寫 Root 審計」這類混雜主體在這裡無從藏身。
	for _, line := range strings.Split(strings.TrimSuffix(auditDump, "\n"), "\n") {
		if line == "" {
			continue
		}
		segs := strings.Split(line, "|")
		if actor := segs[len(segs)-1]; actor != "root" && actor != "system" {
			t.Errorf("Root 域審計主體超出核准範圍：%q（%s）", actor, line)
		}
	}
}

// TestAccountInnerLoopIsolated 用隔離測試工廠驗證普通帳戶側的內部閉環：
// 首次改密旗標的服務端閘、改密清旗標、跨帳戶不可指認、訪客無口令通路、
// 角色與主體類別不可自報。不為此新增任何生產建號端點。
func TestAccountInnerLoopIsolated(t *testing.T) {
	const (
		pwX1 = "acct-x-first-_Pass"
		pwX2 = "acct-x-new-_Pass"
		pwY1 = "acct-y-live-_Pass"
	)
	ctx := context.Background()
	dir := newRootInitDir(t)
	env := newLoopEnv(t, dir, session.Policy{}, loopGuardOff)
	origin := env.ts.URL

	hashX, err := credential.Hash(pwX1, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	_, err = env.accounts.Create(ctx, env.db.SQL(), account.NewInput{
		LoginName: "NightKeeperX", DisplayName: "守夜人 X", PasswordHash: hashX,
		Type: account.TypeStandard, Status: account.StatusActive, MustChangePassword: true,
	})
	if err != nil {
		t.Fatalf("建立測試帳戶 X 失敗：%v", err)
	}
	hashY, err := credential.Hash(pwY1, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	_, err = env.accounts.Create(ctx, env.db.SQL(), account.NewInput{
		LoginName: "NightKeeperY", DisplayName: "守夜人 Y", PasswordHash: hashY,
		Type: account.TypeStandard, Status: account.StatusActive,
	})
	if err != nil {
		t.Fatalf("建立測試帳戶 Y 失敗：%v", err)
	}
	_, err = env.accounts.Create(ctx, env.db.SQL(), account.NewInput{
		LoginName: "NightGuest", DisplayName: "過夜訪客",
		Type: account.TypeGuest, Status: account.StatusActive,
	})
	if err != nil {
		t.Fatalf("建立測試訪客失敗：%v", err)
	}

	// 旗標帳戶：登入放行但帶出旗標；受保護端點全數 2010，必要入口放行。
	lx := env.loginAccount(t, "NightKeeperX", pwX1)
	lx.want(t, http.StatusOK, 0)
	cookieX := lx.cookieValue(t)
	if flag, _ := lx.body["must_change_password"].(bool); !flag {
		t.Error("帶旗標帳戶的登入回應應帶出 must_change_password=true")
	}
	env.devicesGet(t, cookieX).want(t, http.StatusForbidden, int(httpapi.CodePasswordChangeRequired))
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/session/rotate",
		origin: origin, cookie: cookieX}).want(t, http.StatusForbidden, int(httpapi.CodePasswordChangeRequired))
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/devices/revoke",
		body:   `{"device_id":"00000000-0000-0000-0000-000000000000"}`,
		origin: origin, cookie: cookieX}).want(t, http.StatusForbidden, int(httpapi.CodePasswordChangeRequired))
	env.sessionGet(t, cookieX).want(t, http.StatusOK, 0)

	// 改密還清義務：同一交易換雜湊＋清旗標＋撤銷全部會話（含這一臺）。
	chx := env.do(t, loopRequest{method: http.MethodPost, path: "/auth/password/change",
		body:   `{"current_password":"` + pwX1 + `","new_password":"` + pwX2 + `"}`,
		origin: origin, cookie: cookieX})
	chx.want(t, http.StatusOK, 0)
	env.sessionGet(t, cookieX).want(t, http.StatusUnauthorized, int(httpapi.CodeSessionInvalid))

	reX := env.loginAccount(t, "NightKeeperX", pwX2)
	reX.want(t, http.StatusOK, 0)
	cookieX2 := reX.cookieValue(t)
	if _, ok := reX.body["must_change_password"]; ok {
		t.Errorf("旗標解除後回應不應再帶 must_change_password：%s", reX.raw)
	}
	env.devicesGet(t, cookieX2).want(t, http.StatusOK, 0)

	// 跨帳戶隔離：X 指認 Y 的裝置一律 2009，且 Y 的會話不受牽連。
	ly := env.loginAccount(t, "NightKeeperY", pwY1)
	ly.want(t, http.StatusOK, 0)
	cookieY := ly.cookieValue(t)
	devY := sessionDeviceID(t, env, cookieY)
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/devices/revoke",
		body: `{"device_id":"` + devY + `"}`, origin: origin,
		cookie: cookieX2}).want(t, http.StatusNotFound, int(httpapi.CodeDeviceNotFound))
	env.sessionGet(t, cookieY).want(t, http.StatusOK, 0)
	// Y 自己的清單裡沒有 X 的裝置（範圍只來自受信主體）。
	listY := env.devicesGet(t, cookieY)
	statusesY, _ := deviceIDsFromList(t, listY)
	if len(statusesY) != 1 {
		t.Errorf("Y 的清單只應有自己的裝置：%v", statusesY)
	}
	devX := sessionDeviceID(t, env, cookieX2)
	if _, leaked := statusesY[devX]; leaked {
		t.Error("跨帳戶的裝置來到了本人的清單裡")
	}

	// 同口令是 1004（會話保留）。
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/password/change",
		body:   `{"current_password":"` + pwY1 + `","new_password":"` + pwY1 + `"}`,
		origin: origin, cookie: cookieY}).want(t, http.StatusBadRequest, int(httpapi.CodeInvalidBody))
	env.sessionGet(t, cookieY).want(t, http.StatusOK, 0)

	// 訪客沒有口令通路：任何形式的憑據都是 2001。
	env.loginAccount(t, "NightGuest", "").want(t, http.StatusUnauthorized, int(httpapi.CodeInvalidCredentials))
	env.loginAccount(t, "NightGuest", "anything-_Pass").want(t, http.StatusUnauthorized, int(httpapi.CodeInvalidCredentials))

	// 角色不可自報：兩個登入端點對多出來的「身分宣稱」欄位都是 1004。
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/login",
		body:   `{"login_name":"NightKeeperY","password":"` + pwY1 + `","is_root":true}`,
		origin: origin}).want(t, http.StatusBadRequest, int(httpapi.CodeInvalidBody))
	env.do(t, loopRequest{method: http.MethodPost, path: "/auth/root/login",
		body:   `{"password":"` + pwY1 + `","account_id":"00000000-0000-0000-0000-000000000000","login_name":"NightKeeperX"}`,
		origin: origin}).want(t, http.StatusBadRequest, int(httpapi.CodeInvalidBody))
}

// TestLoginGuardAndExpiryUseInjectedClock 用注入時鐘釘住限流冷卻與到期判定：
// 全部結論不依賴真實等待，也不觸碰主機時間。
func TestLoginGuardAndExpiryUseInjectedClock(t *testing.T) {
	const pw = "guard-loop-_Pass"
	dir := newRootInitDir(t)
	if err := InitRoot(context.Background(), []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets(pw, pw), &syncBuffer{}); err != nil {
		t.Fatalf("初始化失敗：%v", err)
	}
	tight := auth.GuardConfig{
		FailLimit:       3,
		Window:          15 * time.Minute,
		Cooldown:        15 * time.Minute,
		SourceFailLimit: 9,
		MaxEntries:      10000,
	}
	env := newLoopEnv(t, dir, session.Policy{}, tight)

	before := loopAuditCount(t, env.db.SQL(), "auth.login_failure")
	for i := 0; i < 3; i++ {
		env.loginRoot(t, "wrong-"+strconv.Itoa(i)+"-_Pass").want(t, http.StatusUnauthorized, int(httpapi.CodeInvalidCredentials))
	}
	after := loopAuditCount(t, env.db.SQL(), "auth.login_failure")
	if after-before != 3 {
		t.Errorf("三次真實拒絕應各留一筆失敗審計，實際 %d", after-before)
	}
	// 冷卻中：對錯口令統一 2006＋Retry-After，且不再追加審計（不查庫、不派生）。
	throttled := env.loginRoot(t, pw)
	throttled.want(t, http.StatusTooManyRequests, int(httpapi.CodeLoginThrottled))
	if n, err := strconv.Atoi(throttled.retryAfter); err != nil || n < 1 {
		t.Errorf("2006 應附正的 Retry-After，實際 %q", throttled.retryAfter)
	}
	auditFrozen := loopAuditCount(t, env.db.SQL(), "auth.login_failure")
	env.loginRoot(t, pw)
	env.loginRoot(t, "also-wrong-_Pass")
	if now := loopAuditCount(t, env.db.SQL(), "auth.login_failure"); now != auditFrozen {
		t.Error("被限流擋下的嘗試不得寫入審計（不給寫入放大器）")
	}
	// 注入時鐘推進過冷卻：預算整份回來，正確口令立刻可登。
	env.clock.Advance(15*time.Minute + time.Second)
	env.loginRoot(t, pw).want(t, http.StatusOK, 0)
}

// TestSessionExpiryAndIdleDeadlineUseInjectedClock 釘住絕對到期與閒置到期：
// 判定讀庫內時刻，換一條連線（等价於重啟後）第一次驗證就拒。
func TestSessionExpiryAndIdleDeadlineUseInjectedClock(t *testing.T) {
	const pw = "expiry-loop-_Pass"
	dir := newRootInitDir(t)
	if err := InitRoot(context.Background(), []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets(pw, pw), &syncBuffer{}); err != nil {
		t.Fatalf("初始化失敗：%v", err)
	}
	env := newLoopEnv(t, dir, session.Policy{IdleTTL: 30 * time.Minute}, loopGuardOff)
	cookie := env.loginRoot(t, pw).cookieValue(t)
	env.sessionGet(t, cookie).want(t, http.StatusOK, 0)

	// 閒置到期：超過閒置線沒有活動 → 與絕對到期同一對外結論（2003）。
	env.clock.Advance(31 * time.Minute)
	env.sessionGet(t, cookie).want(t, http.StatusUnauthorized, int(httpapi.CodeSessionInvalid))

	// 絕對到期：到期是庫內事實——用另一條全新連線驗證同被拒。
	env.close()
	freshEnv := newLoopEnv(t, dir, session.Policy{IdleTTL: 30 * time.Minute}, loopGuardOff)
	fresh := freshEnv.loginRoot(t, pw).cookieValue(t)
	freshEnv.clock.Advance(time.Duration(freshEnv.cfg.Security.SessionTTLHours)*time.Hour + time.Minute)
	freshEnv.sessionGet(t, fresh).want(t, http.StatusUnauthorized, int(httpapi.CodeSessionInvalid))
	freshEnv.close()
	// 換一條全新連線、以「到期之後的時刻」為時鐘（等價於服務重啟後的第一次驗證）：
	// 到期是庫內事實，不靠進程內倒數。
	if err := verifySecretAt(t, dir, fresh, freshEnv.clock.Now()); !errors.Is(err, session.ErrExpired) {
		t.Errorf("另一條連線（等價重啟）應判出到期，實際 %v", err)
	}
}

// verifySecretAt 以新連線與指定時鐘驗證一枚秘密（到期判定由傳入的時刻決定，不借道現場的鐘）。
func verifySecretAt(t *testing.T, dir, secret string, at time.Time) error {
	t.Helper()
	db, err := openTestDatabase(context.Background(), dir)
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	defer func() { _ = db.Close() }()
	store, err := session.NewStore(timeutil.NewTest(at), time.Hour)
	if err != nil {
		t.Fatalf("構造會話倉儲失敗：%v", err)
	}
	_, err = store.Verify(context.Background(), db.SQL(), secret)
	return err
}
