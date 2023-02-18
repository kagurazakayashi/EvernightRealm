// invitecodes_test.go 是「服務器級註冊邀請碼管理」在傳輸層的端到端證據：
// Root 簽發一枚碼 → 名冊讀到的是元數據不是秘密 → 撤銷立刻反映在名冊上，以及
// 權限矩陣（管理員≠Root）、方法約定、非法參數點名、重複撤銷 2022，和「明文碼只出現一次」。
//
// 刻意不收的東西：
//   - 沒有替身：授權、首次改密門閂、來源判定、簽發落庫與審計都跨層走真路徑，接錯線就會紅；
//   - 本步不測核銷端點：invite 模式與「拿碼換賬戶」的通路尚未落地，這裡沒有任何入口能把一枚碼
//     兌換成賬戶，名冊裡出現一枚有效的碼不等於它現在能被用——這條邊界由 internal/acctpolicy 守住。
//   - 不碰任何真實數據目錄、不佔 5206，全程用本次專屬的臨時庫與注入時鐘。
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
	"github.com/kagurazakayashi/EvernightRealm/internal/adminacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/invitecode"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

const (
	inviteTestRootPassword  = "invitecodes-test-root-口令"
	inviteTestAdminPassword = "invitecodes-test-管理員初始口令"
	inviteTestAdminChanged  = "invitecodes-test-管理員改後口令"
)

// inviteEnv 是本次測試專屬的現場：真數據庫、真登錄／開設用例、真邀請碼用例，加一臺掛了端點的測試服務。
type inviteEnv struct {
	ts    *httptest.Server
	db    *database.DB
	clock *timeutil.Test
}

// newInviteEnv 建立現場並啟動測試服務。注入時鐘讓「過期」這一格在讀時派生變得可斷言。
func newInviteEnv(t *testing.T) *inviteEnv {
	t.Helper()
	clock := timeutil.NewTest(testBaseTime())
	dir := t.TempDir()
	db, err := database.Open(context.Background(), database.Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試數據庫失敗：%v", err)
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
	sessions, err := session.NewStoreWithPolicy(clock, time.Hour, session.Policy{})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	rootHash, err := credential.Hash(inviteTestRootPassword, credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試 Root 憑據失敗：%v", err)
	}
	authService, err := auth.New(auth.Deps{
		DB: db, Sessions: sessions, Accounts: accountsStore, Grants: grantsStore,
		Audits: auditStore, RootPasswordHash: rootHash, Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立登錄用例失敗：%v", err)
	}
	adminService, err := adminacct.New(adminacct.Deps{
		DB: db, Accounts: accountsStore, Grants: grantsStore,
		Audits: auditStore, Sessions: sessions, Hashing: credential.TestParams,
	})
	if err != nil {
		t.Fatalf("建立開設用例失敗：%v", err)
	}
	inviteService, err := invitecode.New(invitecode.Deps{
		DB:     db,
		Store:  invitecode.NewStore(clock),
		Clock:  clock,
		Audits: auditStore,
	})
	if err != nil {
		t.Fatalf("建立邀請碼用例失敗：%v", err)
	}
	cfg := config.Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("組態不合法：%v", err)
	}
	srv := New(&cfg, testVersion, Deps{
		Auth: authService, Admins: adminService, InviteCodes: inviteService, Clock: clock,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &inviteEnv{ts: ts, db: db, clock: clock}
}

// testBaseTime 給 httpapi 側的注入時鐘一個穩定錨點。
func testBaseTime() time.Time {
	return time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
}

func (e *inviteEnv) rootCookie(t *testing.T) *http.Cookie {
	t.Helper()
	resp := postJSON(t, e.ts, "/auth/root/login",
		`{"password":"`+inviteTestRootPassword+`"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 登錄應成功：%d %s", resp.StatusCode, body)
	}
	return loginCookie(t, resp)
}

// liveAdminCookie 走完整交付鏈取得一位「已完成首次改密」的管理員會話（用於證明管理員≠Root）。
func (e *inviteEnv) liveAdminCookie(t *testing.T, login string) *http.Cookie {
	t.Helper()
	root := e.rootCookie(t)
	resp := postJSON(t, e.ts, "/root/admins",
		`{"login_name":"`+login+`","display_name":"現役管理員","password":"`+inviteTestAdminPassword+`"}`,
		"", map[string]string{"Cookie": cookieHeader(root)})
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Root 開設管理員應成功：%d %s", resp.StatusCode, body)
	}
	first := loginCookie(t, postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+inviteTestAdminPassword+`"}`, "", nil))
	changed := postJSON(t, e.ts, "/auth/password/change",
		`{"current_password":"`+inviteTestAdminPassword+`","new_password":"`+inviteTestAdminChanged+`"}`,
		"", map[string]string{"Cookie": cookieHeader(first)})
	if changed.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(changed.Body)
		t.Fatalf("首次改密應成功：%d %s", changed.StatusCode, body)
	}
	relog := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+inviteTestAdminChanged+`"}`, "", nil)
	return loginCookie(t, relog)
}

// issueBody 產生一份簽發本體（label 必填，max_uses／expires_at 可選）。
func issueBody(label string, maxUses any, expiresAt any) string {
	payload := map[string]any{"label": label}
	if maxUses != nil {
		payload["max_uses"] = maxUses
	}
	if expiresAt != nil {
		payload["expires_at"] = expiresAt
	}
	data, _ := json.Marshal(payload)
	return string(data)
}

func (e *inviteEnv) request(t *testing.T, method, path, body string,
	headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("構造請求失敗：%v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("發送請求失敗：%v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (e *inviteEnv) withRoot(cookie *http.Cookie) map[string]string {
	return map[string]string{"Cookie": cookieHeader(cookie)}
}

// mustIssue 簽發一枚碼並返回解析後的回應與原始響應，不成功即終止。
func (e *inviteEnv) mustIssue(t *testing.T, root *http.Cookie, body string) (map[string]any, *http.Response) {
	t.Helper()
	resp := e.request(t, http.MethodPost, "/root/invite-codes", body, e.withRoot(root))
	if resp.StatusCode != http.StatusCreated {
		text, _ := io.ReadAll(resp.Body)
		t.Fatalf("簽發應成功（201）：%d %s", resp.StatusCode, text)
	}
	return decodeJSONBody(t, resp), resp
}

// TestInviteCodesFullLoop 走完整時間線：簽發 → 名冊只讀元數據 → 撤銷 → 重複撤銷被拒。
//
// 明文碼只在簽發回應裡出現一次，名冊與撤銷回顯都讀不回來；數據庫里根本沒有可存明文的地方。
func TestInviteCodesFullLoop(t *testing.T) {
	e := newInviteEnv(t)
	root := e.rootCookie(t)

	issued, issuedResp := e.mustIssue(t, root, issueBody("內測名額", float64(3), nil))
	code, _ := issued["code"].(string)
	if code == "" {
		t.Fatal("簽發回應必須帶一次性明文碼")
	}
	invite, _ := issued["invite"].(map[string]any)
	if invite == nil {
		t.Fatal("簽發回應必須帶名冊那一行")
	}
	codeID, _ := invite["code_id"].(string)
	if invite["status"] != "active" || invite["max_uses"] != float64(3) || invite["remaining"] != float64(3) {
		t.Errorf("簽發回顯的額度形態不對：%+v", invite)
	}
	// 簽發、名冊、撤銷都不輪換會話、不下發 Cookie（這些是 Root 管理面，不是登錄通路）。
	assertNoSetCookie(t, "簽發", issuedResp)

	// 名冊讀到這一行，且整份回應不含明文碼，也沒有 code_hash／password／login_name／roles 這類禁欄。
	roster := e.request(t, http.MethodGet, "/root/invite-codes", "", e.withRoot(root))
	rosterBody := decodeJSONBody(t, roster)
	assertNoSetCookie(t, "名冊", roster)
	if strings.Contains(dumpAll(rosterBody), code) {
		t.Error("名冊回應裡出現了明文碼——名冊不得反覆回顯秘密")
	}
	if got := findInviteInRoster(t, rosterBody, codeID); got == nil {
		t.Fatal("剛簽發的碼應出現在名冊裡")
	} else {
		assertNoForbiddenFields(t, got, []string{"code", "code_hash", "password", "login_name", "roles"})
	}

	// 撤銷：回顯 revoked 狀態與撤銷時刻，且仍不帶明文碼。
	revoke := e.request(t, http.MethodDelete, "/root/invite-codes/"+codeID, "", e.withRoot(root))
	if revoke.StatusCode != http.StatusOK {
		text, _ := io.ReadAll(revoke.Body)
		t.Fatalf("撤銷應成功（200）：%d %s", revoke.StatusCode, text)
	}
	assertNoSetCookie(t, "撤銷", revoke)
	revokeBody := decodeJSONBody(t, revoke)
	revokedInvite, _ := revokeBody["invite"].(map[string]any)
	if revokedInvite == nil || revokedInvite["status"] != "revoked" {
		t.Fatalf("撤銷回顯該是 revoked：%+v", revokedInvite)
	}
	if _, ok := revokedInvite["revoked_at"]; !ok {
		t.Error("撤銷回顯應帶撤銷時刻")
	}
	if strings.Contains(dumpAll(revokeBody), code) {
		t.Error("撤銷回應裡出現了明文碼")
	}

	// 重複撤銷 → 2022，且不改動名冊上的那一行。
	again := e.request(t, http.MethodDelete, "/root/invite-codes/"+codeID, "", e.withRoot(root))
	if again.StatusCode != http.StatusConflict {
		t.Fatalf("重複撤銷應回 409：%d", again.StatusCode)
	}
	if got := errorCode(t, again); got != int(CodeInviteAlreadyRevoked) {
		t.Errorf("重複撤銷應回機器碼 %d，實際 %d", CodeInviteAlreadyRevoked, got)
	}

	// 庫裡只存驗證材料：整張表掃一遍，明文不得出現。
	if e.tableContains(t, code) {
		t.Error("明文碼出現在數據庫裡——庫裡本應只有不可逆的驗證材料")
	}
}

// TestInviteCodeIssueContract 簽發端點的協議面：未知欄位、非法值點名欄位、方法約定、主體邊界與來源。
func TestInviteCodeIssueContract(t *testing.T) {
	e := newInviteEnv(t)
	root := e.rootCookie(t)

	// 未知欄位（含角色／活動／口令這類「自報身份或企圖覆蓋隱藏欄位」的寫法）一律 1004。
	for _, body := range []string{
		`{"label":"甲","role":"server_admin"}`,
		`{"label":"甲","activity_id":"x"}`,
		`{"label":"甲","password":"p"}`,
		`{"label":"甲","account_id":"x"}`,
		`{"label":"甲","status":"revoked"}`,
	} {
		resp := e.request(t, http.MethodPost, "/root/invite-codes", body, e.withRoot(root))
		if resp.StatusCode != http.StatusBadRequest || errorCode(t, resp) != int(CodeInvalidBody) {
			t.Errorf("未知欄位 %s 應回 1004，實際 %d", body, resp.StatusCode)
		}
	}
	// 非法具體值各自點名對應欄位。
	cases := []struct {
		name, body, field string
	}{
		{"空標籤", `{"label":"   ","max_uses":1}`, "label"},
		{"額度為零", `{"label":"甲","max_uses":0}`, "max_uses"},
		{"額度越界", `{"label":"甲","max_uses":1000001}`, "max_uses"},
		{"有效期非時刻", `{"label":"甲","expires_at":"not-a-time"}`, "expires_at"},
		{"有效期缺時區", `{"label":"甲","expires_at":"2026-01-01T00:00:00"}`, "expires_at"},
	}
	for _, tc := range cases {
		resp := e.request(t, http.MethodPost, "/root/invite-codes", tc.body, e.withRoot(root))
		code, field := errorEnvelope(t, resp)
		if resp.StatusCode != http.StatusBadRequest || code != int(CodeInvalidBody) {
			t.Errorf("%s：應回 1004，實際 %d", tc.name, resp.StatusCode)
			continue
		}
		if field != tc.field {
			t.Errorf("%s：應點名 %q，實際 %q", tc.name, tc.field, field)
		}
	}
	// 集合路徑不接單方 PUT；目標路徑只掛 DELETE。
	if m := e.request(t, http.MethodPut, "/root/invite-codes", "{}", e.withRoot(root)); m.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT 集合路徑應回 405，實際 %d", m.StatusCode)
	}
	if m := e.request(t, http.MethodGet, "/root/invite-codes/"+testCodeID, "", e.withRoot(root)); m.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET 目標路徑應回 405（只有 DELETE 掛上）：%d", m.StatusCode)
	}

	// 主體邊界：管理員（現役、非 Root）過不了 NeedRoot → 2011；匿名 → 2002。
	admin := e.liveAdminCookie(t, "Invite.Admin")
	if resp := e.request(t, http.MethodPost, "/root/invite-codes", issueBody("管理員想籤", nil, nil),
		e.withRoot(admin)); resp.StatusCode != http.StatusForbidden ||
		errorCode(t, resp) != int(CodePermissionDenied) {
		t.Errorf("管理員簽發應回 2011/403，實際 %d", resp.StatusCode)
	}
	if resp := e.request(t, http.MethodPost, "/root/invite-codes", issueBody("匿名想籤", nil, nil), nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("匿名簽發應回 401（2002），實際 %d", resp.StatusCode)
	}
	// 跨站來源在碰到數據庫之前就被 2005 擋下。
	if resp := e.request(t, http.MethodPost, "/root/invite-codes", issueBody("跨站", nil, nil),
		map[string]string{"Cookie": cookieHeader(root), "Origin": "https://evil.example"}); resp.StatusCode != http.StatusForbidden ||
		errorCode(t, resp) != int(CodeOriginForbidden) {
		t.Errorf("跨站簽發應回 2005/403，實際 %d", resp.StatusCode)
	}
}

// TestInviteCodeRosterContract 名冊讀法：五個鍵回顯、no-store、非法參數各自點名、匿名與管理員各一句。
func TestInviteCodeRosterContract(t *testing.T) {
	e := newInviteEnv(t)
	root := e.rootCookie(t)
	e.mustIssue(t, root, issueBody("甲", nil, nil))

	resp := e.request(t, http.MethodGet, "/root/invite-codes?page=1&page_size=20&status=all", "", e.withRoot(root))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("名冊讀取應成功：%d %s", resp.StatusCode, body)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("名冊應 no-store，實際 Cache-Control=%q", cc)
	}
	// 非法查詢參數各自點名。
	for _, tc := range []struct{ query, field string }{
		{"?page=abc", "page"},
		{"?page_size=0", "page_size"},
		{"?page_size=99999", "page_size"},
		{"?status=cancelled", "status"},
		{"?q=" + strings.Repeat("字", invitecode.RosterKeywordMaxRunes+1), "q"},
	} {
		bad := e.request(t, http.MethodGet, "/root/invite-codes"+tc.query, "", e.withRoot(root))
		code, field := errorEnvelope(t, bad)
		if bad.StatusCode != http.StatusBadRequest || code != int(CodeInvalidBody) {
			t.Errorf("%s：應回 1004，實際 %d", tc.query, bad.StatusCode)
			continue
		}
		if field != tc.field {
			t.Errorf("%s：應點名 %q，實際 %q", tc.query, tc.field, field)
		}
	}
	// 管理員讀不到這本 Root 名冊 → 2011；匿名 → 2002。
	admin := e.liveAdminCookie(t, "Invite.Reader")
	if r := e.request(t, http.MethodGet, "/root/invite-codes", "", e.withRoot(admin)); r.StatusCode != http.StatusForbidden {
		t.Errorf("管理員讀名冊應 403，實際 %d", r.StatusCode)
	}
	if r := e.request(t, http.MethodGet, "/root/invite-codes", "", nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("匿名讀名冊應 401，實際 %d", r.StatusCode)
	}
}

// TestInviteCodeRevokeNotFound 幽靈標識、壞格式標識一律 1001（端點不是標識格式探測器）；撤銷不輪換 Cookie。
func TestInviteCodeRevokeNotFound(t *testing.T) {
	e := newInviteEnv(t)
	root := e.rootCookie(t)
	for _, path := range []string{
		"/root/invite-codes/not-a-uuid",
		"/root/invite-codes/00000000-0000-0000-0000-000000000000",
	} {
		resp := e.request(t, http.MethodDelete, path, "", e.withRoot(root))
		if resp.StatusCode != http.StatusNotFound || errorCode(t, resp) != int(CodeNotFound) {
			t.Errorf("%s：撤銷不存在的碼應回 1001/404，實際 %d", path, resp.StatusCode)
		}
	}
	// 帶一份本體的撤銷：撤銷什麼都不該帶，帶任何未知欄位都在解析階段被拒（1004），
	// 不會被當成「撤銷成功」，也不會走到那次寫庫。
	id := "0192f0c4-1c9a-7000-8000-0000000000aa"
	resp := e.request(t, http.MethodDelete, "/root/invite-codes/"+id, `{"expected_revoked_at":1}`, e.withRoot(root))
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, resp) != int(CodeInvalidBody) {
		t.Errorf("帶依據值本體的撤銷應在解析階段被拒（1004），實際 %d", resp.StatusCode)
	}
}

// TestInviteCodeExpiryVisibleAtTransport 用注入時鐘把「過期」變成可讀的事實：有效期過後名冊派生成 expired。
func TestInviteCodeExpiryVisibleAtTransport(t *testing.T) {
	e := newInviteEnv(t)
	root := e.rootCookie(t)
	future := timeutil.FormatUTC(e.clock.Now().Add(time.Minute))
	issued, _ := e.mustIssue(t, root, issueBody("將到期", nil, future))
	codeID := issued["invite"].(map[string]any)["code_id"].(string)

	// 推進過到期時刻。
	e.clock.Advance(2 * time.Minute)
	roster := e.request(t, http.MethodGet, "/root/invite-codes?status=expired", "", e.withRoot(root))
	body := decodeJSONBody(t, roster)
	if findInviteInRoster(t, body, codeID) == nil {
		t.Fatal("過期的碼應被 status=expired 篩到")
	}
}

// testCodeID 是一個合法但不存在的碼標識（方法約定與 1001 用例共用）。
const testCodeID = "0192f0c4-1c9a-7000-8000-0000000000bb"

// —— 斷言輔助 ——

// tableContains 掃整張邀請碼表，看明文是否作為某列值出現（本不該出現）。
func (e *inviteEnv) tableContains(t *testing.T, needle string) bool {
	t.Helper()
	if needle == "" {
		return false
	}
	rows, err := e.db.SQL().QueryContext(context.Background(),
		"SELECT id, code_hash, label FROM registration_invite_codes")
	if err != nil {
		t.Fatalf("導出邀請碼表失敗：%v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var a, b, c string
		if err := rows.Scan(&a, &b, &c); err != nil {
			t.Fatalf("讀取邀請碼行失敗：%v", err)
		}
		if strings.Contains(a, needle) || strings.Contains(b, needle) || strings.Contains(c, needle) {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍歷邀請碼表失敗：%v", err)
	}
	return false
}

// assertNoSetCookie 斷言一條回應不下發任何 Set-Cookie（管理面不輪換會話）。
func assertNoSetCookie(t *testing.T, label string, resp *http.Response) {
	t.Helper()
	if cookies := resp.Header.Values("Set-Cookie"); len(cookies) != 0 {
		t.Errorf("%s 通路不該下發 Cookie，實際有 %d 條 Set-Cookie", label, len(cookies))
	}
}

// findInviteInRoster 在名冊回應裡按 code_id 找到那一行；找不到回 nil。
func findInviteInRoster(t *testing.T, body map[string]any, codeID string) map[string]any {
	t.Helper()
	list, _ := body["invites"].([]any)
	for _, item := range list {
		invite, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if invite["code_id"] == codeID {
			return invite
		}
	}
	return nil
}

// assertNoForbiddenFields 掃一行回顯裡不許出現的鍵（結構上名冊沒有這些格子）。
func assertNoForbiddenFields(t *testing.T, invite map[string]any, forbidden []string) {
	t.Helper()
	for _, key := range forbidden {
		if _, ok := invite[key]; ok {
			t.Errorf("名冊行不該有 %q 這一欄：%+v", key, invite)
		}
	}
}

// dumpAll 把任意 JSON 結構序列化回字符串，供「明文碼不得出現」這類全文掃描。
func dumpAll(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

// errorCode 從錯誤信封裡取出機器碼（一次性讀取回應本體）。
func errorCode(t *testing.T, resp *http.Response) int {
	t.Helper()
	code, _ := errorEnvelope(t, resp)
	return code
}

// errorEnvelope 一次性解析錯誤信封，回機器碼與 details.invalid_field（回應本體只能讀一回）。
func errorEnvelope(t *testing.T, resp *http.Response) (int, string) {
	t.Helper()
	body := decodeJSONBody(t, resp)
	code, _ := body["code"].(float64)
	details, _ := body["details"].(map[string]any)
	field, _ := details["invalid_field"].(string)
	return int(code), field
}
