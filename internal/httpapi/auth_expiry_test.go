package httpapi

import (
	"context"
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
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// clockedLiveEnv 是「真實元件 + 可推進時鐘 + 可帶會話策略」的端到端現場。
//
// 比 newLiveEnvGuarded 多兩樣，兩樣都是本步測試必需的：
//   - 注入時鐘：到期與閒置只能靠「把時鐘往前撥」來驗。直接改資料庫裡的時刻會被遷移
//     0004 的 CHECK 擋下（expires_at 必晚於 created_at、last_active_at 不早於
//     created_at），何況那是在偽造事實，而不是讓時間過去；
//   - 會話策略：閒置判定、寫入節流與清理寬限期都要在「真的有策略」的現場上驗，
//     用預設策略的現場測等於只測絕對期限。
//
// 刻意不改 newLiveEnvGuarded 的簽名——它背著既有十幾個現場，改一次就要跟著改一片。
type clockedLiveEnv struct {
	ts       *httptest.Server
	db       *database.DB
	sessions *session.Store
	accounts *account.Store
	clock    *timeutil.Test
}

// newClockedLiveEnv 建立帶注入時鐘與會話策略的端到端現場。
// 時鐘起點取一個正常的當下時刻，之後所有「時間過去」都走 Advance，不碰主機時鐘。
func newClockedLiveEnv(t *testing.T, ttl time.Duration, policy session.Policy) *clockedLiveEnv {
	t.Helper()
	clock := timeutil.NewTest(time.Now().UTC().Truncate(time.Second))
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
	sessions, err := session.NewStoreWithPolicy(clock, ttl, policy)
	if err != nil {
		t.Fatalf("建立帶策略的會話倉儲失敗：%v", err)
	}
	accounts := account.NewStore(clock)
	service, err := auth.New(auth.Deps{
		DB:       db,
		Sessions: sessions,
		Accounts: accounts,
		Audits:   audit.NewStore(clock),
		Hashing:  credential.TestParams,
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
	return &clockedLiveEnv{ts: ts, db: db, sessions: sessions, accounts: accounts, clock: clock}
}

// liveAccount 落一個用真實憑據的標準賬戶。
func (e *clockedLiveEnv) liveAccount(t *testing.T, login, password string) {
	t.Helper()
	hash, err := credential.Hash(password, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試憑據失敗：%v", err)
	}
	if _, err := e.accounts.Create(context.Background(), e.db.SQL(), account.NewInput{
		LoginName: login, DisplayName: "到期端到端測試帳戶", PasswordHash: hash,
		Type: account.TypeStandard, Status: account.StatusActive,
	}); err != nil {
		t.Fatalf("建立帳戶失敗：%v", err)
	}
}

// login 登一次，並把 Web 端拿到的會話秘密取回來。
func (e *clockedLiveEnv) login(t *testing.T, login, password string) string {
	t.Helper()
	resp := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+password+`"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("登入應成功：%d %s", resp.StatusCode, body)
	}
	return loginCookie(t, resp).Value
}

// assertSessionValid 斷言帶這枚 Cookie 問 /auth/session 是 200（前置條件與「還有效」的點位）。
func (e *clockedLiveEnv) assertSessionValid(t *testing.T, secret string) {
	t.Helper()
	resp := getAuth(t, e.ts, "/auth/session", sessionCookieName+"="+secret, "", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("會話應有效：%d %s", resp.StatusCode, body)
	}
}

// sessionCode 帶 Cookie 問一次 /auth/session 並斷言機器碼。
func (e *clockedLiveEnv) sessionCode(t *testing.T, secret string, want ErrorCode) *http.Response {
	t.Helper()
	resp := getAuth(t, e.ts, "/auth/session", sessionCookieName+"="+secret, "", "")
	assertEnvelopeCode(t, resp, want)
	return resp
}

// onlySessionID 取回庫裡唯一那枚會話的標識；不唯一就直接失敗（前置條件寫錯）。
func (e *clockedLiveEnv) onlySessionID(t *testing.T) string {
	t.Helper()
	ids := listAllSessionIDs(t, e.db)
	if len(ids) != 1 {
		t.Fatalf("前置應恰好一枚會話，實際 %d 枚", len(ids))
	}
	return ids[0].String()
}

// countRows 數會話行數（「拒絕不順手刪」與清理兩段都要看資料庫）。
func (e *clockedLiveEnv) countRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM sessions").Scan(&n); err != nil {
		t.Fatalf("統計會話失敗：%v", err)
	}
	return n
}

// readMillis 讀回某枚會話的一個毫秒時刻。可讀欄位以白名單列出，
// 不讓呼叫端把任意字串送進 SQL——測試也不該開這條口子。
func (e *clockedLiveEnv) readMillis(t *testing.T, sessionID, column string) int64 {
	t.Helper()
	var query string
	switch column {
	case "created_at", "last_active_at", "expires_at":
		query = "SELECT " + column + " FROM sessions WHERE id = ?"
	default:
		t.Fatalf("測試不允許讀會話欄位 %q（僅 created_at|last_active_at|expires_at）", column)
	}
	var got int64
	if err := e.db.SQL().QueryRowContext(context.Background(), query, sessionID).Scan(&got); err != nil {
		t.Fatalf("讀取會話 %s 失敗：%v", column, err)
	}
	return got
}

// TestExpiredSessionRejectedAtEntry 把「失效檢查發生在服務入口」端到端釘住：
// 時鐘一越過 expires_at，同一個 Cookie 立刻換不回身份，收到 401／2003 並附帶刪除指令。
//
// 這一條不依賴任何清理任務：行還在庫裡，保留寬限期連開始計都沒開始。
func TestExpiredSessionRejectedAtEntry(t *testing.T) {
	env := newClockedLiveEnv(t, time.Hour, session.Policy{})
	env.liveAccount(t, "expire_entry", "correct-pass")
	secret := env.login(t, "expire_entry", "correct-pass")

	// 到期前一毫秒仍有效，恰好到達即失效：入口與領域層同一個邊界口徑。
	env.clock.Advance(time.Hour - time.Millisecond)
	env.assertSessionValid(t, secret)

	env.clock.Advance(time.Millisecond)
	after := env.sessionCode(t, secret, CodeSessionInvalid)
	if after.StatusCode != http.StatusUnauthorized {
		t.Errorf("到期會話應回 401，實際 %d", after.StatusCode)
	}
	assertCookieCleared(t, after)

	// 同一枚秘密以 Bearer 送出得到同一個機器碼：兩條通路不各長一套語義。
	native := getAuth(t, env.ts, "/auth/session", "", secret, "")
	assertEnvelopeCode(t, native, CodeSessionInvalid)

	// 到期不等於「沒帶憑據」：空手來問仍是 2002，兩個碼不互相冒充。
	noCredential := getAuth(t, env.ts, "/auth/session", "", "", "")
	assertEnvelopeCode(t, noCredential, CodeNotAuthenticated)

	if n := env.countRows(t); n != 1 {
		t.Errorf("入口拒絕不應刪除記錄，實際剩 %d 行", n)
	}
}

// TestIdleExpiredSessionRejectedAtEntry 是閒置判定的端到端證據：
// 絕對期限遠在未來，唯一能把請求擋下來的只有「距最近活動超過閒置閾值」。
func TestIdleExpiredSessionRejectedAtEntry(t *testing.T) {
	env := newClockedLiveEnv(t, 24*time.Hour, session.Policy{IdleTTL: 10 * time.Minute})
	env.liveAccount(t, "idle_entry", "correct-pass")
	secret := env.login(t, "idle_entry", "correct-pass")

	// 第 9 分鐘動一次：閒置線從那一刻重新起算，絕對期限還剩十幾個小時。
	env.clock.Advance(9 * time.Minute)
	env.assertSessionValid(t, secret)

	// 距那次活動正好 10 分鐘：閒置截止，入口拒絕。
	env.clock.Advance(10 * time.Minute)
	env.sessionCode(t, secret, CodeSessionInvalid)

	// 同樣沉默 30 分鐘，閒置判定關閉（IdleTTL=0）的另一套現場必須放行——
	// 否則「0＝不啟用」這個讀法沒有任何證據。
	closed := newClockedLiveEnv(t, 24*time.Hour, session.Policy{})
	closed.liveAccount(t, "idle_off", "correct-pass")
	closedSecret := closed.login(t, "idle_off", "correct-pass")
	closed.clock.Advance(30 * time.Minute)
	closed.assertSessionValid(t, closedSecret)
}

// TestCleanupDoesNotChangeClientOutcome 釘住清理與對外語義的關係：
// 入口先拒（不依賴清理），清理再把行刪掉，客戶端拿到的機器碼始終是同一個 2003。
func TestCleanupDoesNotChangeClientOutcome(t *testing.T) {
	env := newClockedLiveEnv(t, time.Hour, session.Policy{CleanupGrace: 10 * time.Minute})
	env.liveAccount(t, "cleanup_entry", "correct-pass")
	secret := env.login(t, "cleanup_entry", "correct-pass")

	// 剛過期：拒絕，但還在寬限期內，行必須留在庫裡。
	env.clock.Advance(time.Hour + time.Millisecond)
	env.sessionCode(t, secret, CodeSessionInvalid)

	// 寬限期未到就跑清理：什麼都不刪。這一步同時證明「清理沒跑」不影響上面那句拒絕。
	deleted, err := env.sessions.Cleanup(context.Background(), env.db.SQL())
	if err != nil {
		t.Fatalf("寬限期內清理失敗：%v", err)
	}
	if deleted != 0 {
		t.Fatalf("寬限期未過不應刪除，實際 %d", deleted)
	}
	if n := env.countRows(t); n != 1 {
		t.Fatalf("記錄應仍在庫內，實際 %d 行", n)
	}

	// 過了寬限期再跑：行被刪；同一枚舊憑據再來問，結論仍是 2003 而不是 2002。
	env.clock.Advance(10 * time.Minute)
	deleted, err = env.sessions.Cleanup(context.Background(), env.db.SQL())
	if err != nil {
		t.Fatalf("過寬限期清理失敗：%v", err)
	}
	if deleted != 1 {
		t.Fatalf("過寬限期後應刪 1 行，實際 %d", deleted)
	}
	env.sessionCode(t, secret, CodeSessionInvalid)
}

// TestTouchThresholdKeepsWritesOffWithinWindow 在端到端層面複核寫入節流：
// 閾值內的多次已認證查詢不產生資料庫寫入，跨過閾值才落庫。
//
// 這條值得端到端跑一次：它證明傳輸層「每個請求都解析會話」確實走在節流之後，
// 而不是各端點自己另開一條「順手更新活動時刻」的通路。
func TestTouchThresholdKeepsWritesOffWithinWindow(t *testing.T) {
	env := newClockedLiveEnv(t, 24*time.Hour, session.Policy{TouchThreshold: 30 * time.Minute})
	env.liveAccount(t, "touch_entry", "correct-pass")
	secret := env.login(t, "touch_entry", "correct-pass")
	id := env.onlySessionID(t)
	created := env.readMillis(t, id, "created_at")

	for i := 0; i < 5; i++ {
		env.clock.Advance(time.Minute)
		env.assertSessionValid(t, secret)
		if last := env.readMillis(t, id, "last_active_at"); last != created {
			t.Fatalf("第 %d 次驗證在節流窗口內卻寫了庫：last_active_at=%d created_at=%d", i, last, created)
		}
	}

	// 跨過閾值那一次：必須落庫。
	env.clock.Advance(30 * time.Minute)
	env.assertSessionValid(t, secret)
	if last := env.readMillis(t, id, "last_active_at"); last == created {
		t.Fatalf("跨過節流閾值應落庫，last_active_at 仍停在 %d", last)
	}
}
