package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// liveEnv 是「真實用例＋真實資料庫＋完整中介層鏈」的現場：
// R1-008 交接列出的未驗證條件——「登入 → Cookie → 請求 → 解析主體」整鏈——
// 由本檔補上端到端證據；這裡沒有任何替身，跨層接錯線就會紅。
type liveEnv struct {
	ts       *httptest.Server
	db       *database.DB
	sessions *session.Store
	accounts *account.Store
}

// newLiveEnv 建立本次測試專屬的臨時庫與掛上真實 auth.Service 的 HTTP 服務。
// rootPassword 為空時重現「Root 尚未初始化」的部署。
func newLiveEnv(t *testing.T, rootPassword string) *liveEnv {
	t.Helper()
	return newLiveEnvGuarded(t, rootPassword, nil)
}

// newLiveEnvGuarded 同 newLiveEnv，但替登入用例接上真實守衛（限流端到端測試用）；
// guard 為 nil 時維持「無限流」的既有現場。
func newLiveEnvGuarded(t *testing.T, rootPassword string, guard *auth.LoginGuard) *liveEnv {
	t.Helper()
	clock := timeutil.System()
	dir := t.TempDir()
	db, err := database.Open(context.Background(), database.Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: time.Second,
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
	sessions, err := session.NewStore(clock, time.Hour)
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	rootHash := ""
	if rootPassword != "" {
		rootHash, err = credential.Hash(rootPassword, credential.TestParams)
		if err != nil {
			t.Fatalf("產生測試 Root 憑據失敗：%v", err)
		}
	}
	service, err := auth.New(auth.Deps{
		DB:               db,
		Sessions:         sessions,
		Accounts:         account.NewStore(clock),
		Audits:           audit.NewStore(clock),
		RootPasswordHash: rootHash,
		Hashing:          credential.TestParams,
		Guard:            guard,
	})
	if err != nil {
		t.Fatalf("建立登入用例失敗：%v", err)
	}
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{Auth: service, Clock: clock})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &liveEnv{ts: ts, db: db, sessions: sessions, accounts: account.NewStore(clock)}
}

// liveAccount 落一個用真實憑據的標準帳戶。
func (e *liveEnv) liveAccount(t *testing.T, login, password string) account.Account {
	t.Helper()
	hash, err := credential.Hash(password, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	a, err := e.accounts.Create(context.Background(), e.db.SQL(), account.NewInput{
		LoginName: login, DisplayName: "端到端測試帳戶", PasswordHash: hash,
		Type: account.TypeStandard, Status: account.StatusActive,
	})
	if err != nil {
		t.Fatalf("建立帳戶失敗：%v", err)
	}
	return a
}

// TestLoginCookieChainEndToEnd 走完整條關鍵路：
// 登入簽發 Cookie → 帶 Cookie 問當前會話 → 原生以 Set-Cookie 讀得的秘密走 Bearer
// → 第二次登入是新會話（防固定）→ 撤銷後舊秘密立即失效、新秘密不受牽連。
func TestLoginCookieChainEndToEnd(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "e2e_user", "correct-pass")

	resp := postJSON(t, env.ts, "/auth/login", `{"login_name":"e2e_user","password":"correct-pass"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("登入應成功：%d %s", resp.StatusCode, body)
	}
	cookie := loginCookie(t, resp)

	// Cookie 路徑：帶上瀏覽器代管的秘密問當前會話。
	sessResp := getAuth(t, env.ts, "/auth/session", sessionCookieName+"="+cookie.Value, "", "")
	if sessResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(sessResp.Body)
		t.Fatalf("有效 Cookie 應換回會話：%d %s", sessResp.StatusCode, body)
	}
	var facts map[string]any
	if err := json.NewDecoder(sessResp.Body).Decode(&facts); err != nil {
		t.Fatalf("解析當前會話回應失敗：%v", err)
	}
	if facts["subject_kind"] != "account" {
		t.Errorf("主體類別不符：%v", facts["subject_kind"])
	}

	// 原生路徑：同一枚秘密以 Bearer 回傳（不帶 Cookie、不帶 Origin）。
	native := getAuth(t, env.ts, "/auth/session", "", cookie.Value, "")
	if native.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(native.Body)
		t.Fatalf("原生 Bearer 應认证成功：%d %s", native.StatusCode, body)
	}

	// 第二次登入必須是另一枚新會話（防固定攻擊）。
	second := postJSON(t, env.ts, "/auth/login", `{"login_name":"e2e_user","password":"correct-pass"}`, "", nil)
	secondCookie := loginCookie(t, second)
	if secondCookie.Value == cookie.Value {
		t.Error("每次登入必須簽發新的會話秘密")
	}

	// 撤銷第一枚會話（經會話倉儲，模擬設備管理通路）：舊秘密立即失效。
	ids := listAllSessionIDs(t, env.db)
	if len(ids) != 2 {
		t.Fatalf("應有兩行會話，實際 %d", len(ids))
	}
	if _, err := env.sessions.Revoke(context.Background(), env.db.SQL(), ids[0]); err != nil {
		t.Fatalf("撤銷失敗：%v", err)
	}
	after := getAuth(t, env.ts, "/auth/session", sessionCookieName+"="+cookie.Value, "", "")
	assertEnvelopeCode(t, after, CodeSessionInvalid)

	keep := getAuth(t, env.ts, "/auth/session", "", secondCookie.Value, "")
	if keep.StatusCode != http.StatusOK {
		t.Errorf("其他會話不應受牽連：%d", keep.StatusCode)
	}
}

// listAllSessionIDs 讀回會話標識清單（撤銷通路模擬用；測試專屬直查，按簽發順序）。
func listAllSessionIDs(t *testing.T, db *database.DB) []idgen.ID {
	t.Helper()
	rows, err := db.SQL().QueryContext(context.Background(), "SELECT id FROM sessions ORDER BY rowid")
	if err != nil {
		t.Fatalf("查詢會話失敗：%v", err)
	}
	defer rows.Close()
	var out []idgen.ID
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			t.Fatalf("讀會話標識失敗：%v", err)
		}
		id, err := idgen.Parse(text)
		if err != nil {
			t.Fatalf("會話標識異常：%v", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍歷會話失敗：%v", err)
	}
	return out
}

// TestUnknownAndWrongPasswordAreIndistinguishable 把「不可枚舉帳戶」釘在 HTTP 層：
// 查無此人與口令不符的回應——狀態碼、機器碼、文案——逐字相同。
func TestUnknownAndWrongPasswordAreIndistinguishable(t *testing.T) {
	env := newLiveEnv(t, "")
	env.liveAccount(t, "real_user", "correct-pass")

	unknown := postJSON(t, env.ts, "/auth/login", `{"login_name":"ghost_user","password":"whatever"}`, "", nil)
	wrong := postJSON(t, env.ts, "/auth/login", `{"login_name":"real_user","password":"wrong-pass"}`, "", nil)
	if unknown.StatusCode != wrong.StatusCode {
		t.Fatalf("狀態碼必須相同：unknown=%d wrong=%d", unknown.StatusCode, wrong.StatusCode)
	}
	ub, _ := io.ReadAll(unknown.Body)
	wb, _ := io.ReadAll(wrong.Body)
	var ue, we map[string]any
	if err := json.Unmarshal(ub, &ue); err != nil {
		t.Fatalf("查無此人應回信封：%s", ub)
	}
	if err := json.Unmarshal(wb, &we); err != nil {
		t.Fatalf("口令不符應回信封：%s", wb)
	}
	if ue["code"] != we["code"] || ue["message"] != we["message"] {
		t.Errorf("機器碼與文案必須逐字相同：%v vs %v", ue, we)
	}
	if ue["details"] != nil {
		t.Errorf("登入失敗不可帶 details（不洩露內部判定）：%v", ue["details"])
	}
}

// TestRootLoginEndToEndWithAudit 驗證 Root 端到端：登入成功、當前會話報 root、
// root_audit 落下 auth.login_success；錯誤口令被拒且留下失敗審計，審計不含口令明文。
func TestRootLoginEndToEndWithAudit(t *testing.T) {
	env := newLiveEnv(t, "端到端-root-口令")
	resp := postJSON(t, env.ts, "/auth/root/login", `{"password":"端到端-root-口令"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 登入應成功：%d %s", resp.StatusCode, body)
	}
	cookie := loginCookie(t, resp)
	sess := getAuth(t, env.ts, "/auth/session", sessionCookieName+"="+cookie.Value, "", "")
	facts := decodeJSONBody(t, sess)
	if facts["subject_kind"] != "root" {
		t.Errorf("當前會話應報 root：%v", facts["subject_kind"])
	}
	if _, ok := facts["account_id"]; ok {
		t.Errorf("Root 會話不可帶 account_id：%v", facts)
	}
	bad := postJSON(t, env.ts, "/auth/root/login", `{"password":"錯的"}`, "", nil)
	assertEnvelopeCode(t, bad, CodeInvalidCredentials)

	ctx := context.Background()
	var success, failure int
	if err := env.db.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM root_audit WHERE action='auth.login_success'").Scan(&success); err != nil {
		t.Fatalf("統計審計失敗：%v", err)
	}
	if err := env.db.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM root_audit WHERE action='auth.login_failure'").Scan(&failure); err != nil {
		t.Fatalf("統計審計失敗：%v", err)
	}
	if success != 1 || failure != 1 {
		t.Errorf("Root 成敗各應留一筆審計：success=%d failure=%d", success, failure)
	}
	var leaks int
	if err := env.db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM root_audit WHERE reason LIKE ?", "%端到端-root-口令%").Scan(&leaks); err != nil {
		t.Fatalf("檢索審計失敗：%v", err)
	}
	if leaks != 0 {
		t.Error("審計的 reason 不得出現口令明文")
	}
}
