// adminupgrade_test.go 是「管理員把訪戶原地升級成普通帳戶」的傳輸層端到端證據：
// 真資料庫＋真訪客進入＋真管理員交付鏈＋完整中介層，從一枚真實的訪客會話一路走到
// PUT /admin/accounts/{account_id}/upgrade——成功形態與舊憑據失效、偽造欄位、
// 拒絕矩陣（含「訪客本人自我升級」這條本步明令要擋的路）、2024／2012／1004／1001／1002
// 逐條對映，以及歷史審計在升級後逐字不動。
//
// 刻意不收的東西：
//   - 沒有替身：授權、首次改密門閂、範圍核實、撤銷、審計都跨層走真路徑，接錯線就會紅；
//   - 不碰任何真實資料目錄、不佔 5206，全程用本次專屬的暫存庫與系統時鐘。
package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
)

// 升級端點測試口令：只活在本次測試進程，不是任何環境的憑據。
const (
	upgTestAdminInitial  = "adminupgrade-test-管理員初始口令"
	upgTestAdminChanged  = "adminupgrade-test-管理員改後口令"
	upgTestNewPassword   = "adminupgrade-test-一次性升級口令"
	upgTestChangedBySelf = "adminupgrade-test-本人改後口令"
)

// upgLiveAdminCookie 在 guestLive 現場走完整交付鏈取得一位已完成首次改密的管理員會話：
// Root 經端點開設 → 初始口令登入 → 本人改密 → 新口令重登。
func upgLiveAdminCookie(t *testing.T, e *guestLiveEnv, login string) *http.Cookie {
	t.Helper()
	root := e.rootCookie(t)
	created := postJSON(t, e.ts, "/root/admins",
		`{"login_name":"`+login+`","display_name":"升級現場管理員","password":"`+upgTestAdminInitial+`"}`,
		"", map[string]string{"Cookie": cookieHeader(root)})
	if created.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(created.Body)
		t.Fatalf("Root 開設管理員應成功：%d %s", created.StatusCode, body)
	}
	first := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+upgTestAdminInitial+`"}`, "", nil)
	if first.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(first.Body)
		t.Fatalf("管理員首次登入應成功：%d %s", first.StatusCode, body)
	}
	cookie := loginCookie(t, first)
	changed := postJSON(t, e.ts, "/auth/password/change",
		`{"current_password":"`+upgTestAdminInitial+`","new_password":"`+upgTestAdminChanged+`"}`,
		"", map[string]string{"Cookie": cookieHeader(cookie)})
	if changed.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(changed.Body)
		t.Fatalf("管理員首次改密應成功：%d %s", changed.StatusCode, body)
	}
	second := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+upgTestAdminChanged+`"}`, "", nil)
	if second.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(second.Body)
		t.Fatalf("管理員改密後重登應成功：%d %s", second.StatusCode, body)
	}
	return loginCookie(t, second)
}

// upgPut 發一次 PUT /admin/accounts/{id}/upgrade，回應原樣交出去。
func upgPut(t *testing.T, e *guestLiveEnv, accountID, body string,
	cookie *http.Cookie) *http.Response {
	t.Helper()
	headers := map[string]string{}
	if cookie != nil {
		headers["Cookie"] = cookieHeader(cookie)
	}
	return putJSON(t, e.ts, "/admin/accounts/"+accountID+"/upgrade", body, "", headers)
}

// upgEnterGuest 翻開訪客開關並讓一個人真實進入，回傳（會話 Cookie, 帳戶標識）。
func upgEnterGuest(t *testing.T, e *guestLiveEnv, nickname string) (*http.Cookie, string) {
	t.Helper()
	root := e.rootCookie(t)
	e.setGuest(t, root, true)
	resp := e.enter(t, nickname)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("訪客進入應成功：%d %s", resp.StatusCode, body)
	}
	body := decodeJSONBody(t, resp)
	id, _ := body["account_id"].(string)
	if id == "" {
		t.Fatalf("訪客回應應帶出帳戶標識：%v", body)
	}
	return loginCookie(t, resp), id
}

// upgradeAuditCount 數 Root 域裡的升級審計筆數。
func upgradeAuditCount(t *testing.T, e *guestLiveEnv) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM root_audit WHERE action = 'account.guest_upgrade'`).
		Scan(&n); err != nil {
		t.Fatalf("計數升級審計失敗：%v", err)
	}
	return n
}

// accountRow 讀回一筆帳戶的判定欄位（逐欄而不是實體：被拒時要證明「一個字都沒落」）。
func accountRow(t *testing.T, e *guestLiveEnv, accountID string) string {
	t.Helper()
	var (
		loginName, loginKey, accountType, status, displayName string
		passwordHash                                          *string
		mustChange                                            int
	)
	err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT login_name, login_name_key, account_type, status, display_name,
		        password_hash, must_change_password FROM accounts WHERE id = ?`, accountID).
		Scan(&loginName, &loginKey, &accountType, &status, &displayName,
			&passwordHash, &mustChange)
	if err != nil {
		t.Fatalf("讀回帳戶現值失敗：%v", err)
	}
	hash := "<NULL>"
	if passwordHash != nil {
		hash = *passwordHash
	}
	return "login=" + loginName + "|key=" + loginKey + "|type=" + accountType +
		"|status=" + status + "|display=" + displayName + "|hash=" + hash +
		"|must_change=" + string(rune('0'+mustChange))
}

// TestAdminUpgradeFullLoop 完整閉環：一枚真實訪客會話被管理員原地升級——
// 200 回應帶出「同一枚 account_id、standard、欠首改、撤銷 1 份會話」；
// 舊 Cookie 立刻 2003（用戶批准：撿到舊臨時憑據的人不自動獲得正式權限）；
// 新憑據可登入、受 2010 首改門閂、完成改密後舊口令徹底失效；
// 出生審計逐字不動，升級審計指向同一標識且 actor=admin。
func TestAdminUpgradeFullLoop(t *testing.T) {
	e := newGuestLiveEnv(t)
	guest, accountID := upgEnterGuest(t, e, "保留名旅人")
	admin := upgLiveAdminCookie(t, e, "upg.loop.admin")
	before := accountRow(t, e, accountID)
	if !strings.Contains(before, "type=guest") || !strings.Contains(before, "hash=<NULL>") {
		t.Fatalf("升級前應是無憑據的訪戶，實際 %s", before)
	}
	// 伺服器產生的舊訪戶登入名（升級後不再是任何人的入口）。
	var oldGuestLogin string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT login_name FROM accounts WHERE id = ?", accountID).Scan(&oldGuestLogin); err != nil {
		t.Fatalf("讀回舊訪戶登入名失敗：%v", err)
	}
	// 出生審計現值留檔（只追加存儲：升級之後必須逐字對得起來）。
	var enterAuditBefore string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT action || '|' || changes_json || '|' || reason FROM root_audit
		 WHERE action = 'account.guest_enter' AND target_id = ?`, accountID).
		Scan(&enterAuditBefore); err != nil {
		t.Fatalf("讀回出生審計失敗：%v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"login_name": "Real.Upgrade.One",
		"password":   upgTestNewPassword,
	})
	resp := upgPut(t, e, accountID, string(body), admin)
	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("管理員升級訪戶應成功：%d %s", resp.StatusCode, out)
	}
	var report struct {
		Account struct {
			AccountID          string `json:"account_id"`
			LoginName          string `json:"login_name"`
			DisplayName        string `json:"display_name"`
			AccountType        string `json:"account_type"`
			Status             string `json:"status"`
			MustChangePassword bool   `json:"must_change_password"`
		} `json:"account"`
		RevokedSessions int    `json:"revoked_sessions"`
		RequestID       string `json:"request_id"`
	}
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("解析升級回應失敗：%s", raw)
	}

	// 落庫形態（在本人改密之前驗）：轉正行帶憑據且欠首改；目標本人不持任何授予
	//（現場那位開設出來干活的管理員另有授予，所以這裡按目標標識計數）。
	rightAfter := accountRow(t, e, accountID)
	if !strings.Contains(rightAfter, "type=standard") ||
		!strings.Contains(rightAfter, "must_change=1") ||
		strings.Contains(rightAfter, "hash=<NULL>") {
		t.Errorf("落庫應是 standard＋憑據＋欠首改，實際 %s", rightAfter)
	}
	var grantRows int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM account_server_roles WHERE account_id = ?", accountID).
		Scan(&grantRows); err != nil {
		t.Fatalf("計數目標授予失敗：%v", err)
	}
	if grantRows != 0 {
		t.Errorf("升級不得給目標多出任何授予，實際 %d 行", grantRows)
	}
	if report.Account.AccountID != accountID {
		t.Errorf("升級必須保留穩定標識：回應 %q 對 %q", report.Account.AccountID, accountID)
	}
	if report.Account.LoginName != "Real.Upgrade.One" || report.Account.AccountType != "standard" ||
		report.Account.Status != "active" || !report.Account.MustChangePassword {
		t.Errorf("回應應帶出轉正後的服務端現值，實際 %#v", report.Account)
	}
	if report.Account.DisplayName != "保留名旅人" {
		t.Errorf("升級不是改名，顯示名應原樣保留，實際 %q", report.Account.DisplayName)
	}
	if report.RevokedSessions != 1 {
		t.Errorf("該訪戶此刻只有一枚有效會話，撤銷數應為 1，實際 %d", report.RevokedSessions)
	}
	// 回應不含口令明文、雜湊、會話材料與 roles（升級出來的帳戶恆無授予）。
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{strings.ToLower(upgTestNewPassword), "argon2id",
		"password_hash", "token", "cookie", "roles"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("升級回應不得含 %q：實際 %s", forbidden, text)
		}
	}

	// 舊臨時會話：同交易撤銷，同一枚 Cookie 立刻換不出身分（2003）。
	after := decodeJSONBody(t, getAuth(t, e.ts, "/auth/session", cookieHeader(guest), "", ""))
	if int(after["code"].(float64)) != int(CodeSessionInvalid) {
		t.Errorf("升級後舊會話應回 2003，實際 %#v", after)
	}
	// 舊訪戶登入名不再是任何人的入口（憑據也不對）。
	stale := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+oldGuestLogin+`","password":"`+upgTestNewPassword+`"}`, "", nil)
	if stale.StatusCode != http.StatusUnauthorized {
		out, _ := io.ReadAll(stale.Body)
		t.Errorf("伺服器產生的舊訪戶登入名不得成為登入入口，實際 %d %s", stale.StatusCode, out)
	}

	// 新憑據走既有登入與首改門閂。
	first := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"real.upgrade.one","password":"`+upgTestNewPassword+`"}`, "", nil)
	if first.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(first.Body)
		t.Fatalf("升級後應能以新憑據登入：%d %s", first.StatusCode, out)
	}
	convertedBody := decodeJSONBody(t, first)
	if convertedBody["account_type"] != "standard" || convertedBody["must_change_password"] != true {
		t.Errorf("登入回應應如實回報轉正與欠首改，實際 %#v", convertedBody)
	}
	converted := loginCookie(t, first)
	blocked := getAuth(t, e.ts, "/auth/devices", cookieHeader(converted), "", "")
	if blocked.StatusCode != http.StatusForbidden ||
		envelopeCode(t, blocked) != int(CodePasswordChangeRequired) {
		t.Errorf("首改未完成時受保護端點應回 2010/403，實際 %d", blocked.StatusCode)
	}
	changed := postJSON(t, e.ts, "/auth/password/change",
		`{"current_password":"`+upgTestNewPassword+`","new_password":"`+upgTestChangedBySelf+`"}`,
		"", map[string]string{"Cookie": cookieHeader(converted)})
	if changed.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(changed.Body)
		t.Fatalf("本人首次改密應成功：%d %s", changed.StatusCode, out)
	}
	if stalePw := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"Real.Upgrade.One","password":"`+upgTestNewPassword+`"}`, "", nil); stalePw.StatusCode != http.StatusUnauthorized {
		out, _ := io.ReadAll(stalePw.Body)
		t.Errorf("改密後舊一次性口令必須徹底失效，實際 %d %s", stalePw.StatusCode, out)
	}

	// 歷史與審計：出生審計逐字不動、升級審計恰好一筆且 actor=admin。
	var enterAuditAfter string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT action || '|' || changes_json || '|' || reason FROM root_audit
		 WHERE action = 'account.guest_enter' AND target_id = ?`, accountID).
		Scan(&enterAuditAfter); err != nil {
		t.Fatalf("升級後讀回出生審計失敗：%v", err)
	}
	if enterAuditAfter != enterAuditBefore {
		t.Errorf("歷史審計必須逐字不動，變更前 %q／實際 %q", enterAuditBefore, enterAuditAfter)
	}
	if n := upgradeAuditCount(t, e); n != 1 {
		t.Errorf("升級應恰好追加一筆審計，實際 %d 筆", n)
	}
	var actorKind, actorID string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT actor_kind, actor_id FROM root_audit WHERE action = 'account.guest_upgrade'`).
		Scan(&actorKind, &actorID); err != nil {
		t.Fatalf("讀回升級審計操作者失敗：%v", err)
	}
	if actorKind != string(audit.ActorAdmin) || actorID == accountID {
		t.Errorf("升級審計應記真實操作者（admin 本人），實際 %s／%s", actorKind, actorID)
	}
}

// TestAdminUpgradeForgedClaimsRejected 本體帶 account_type／roles／status／
// subject_kind／must_change_password／display_name 六種越界欄位全回 1004，
// 訪戶一個字不動、審計不記：「升成哪一類主體」在協定層就沒有可以填的格子。
func TestAdminUpgradeForgedClaimsRejected(t *testing.T) {
	e := newGuestLiveEnv(t)
	_, accountID := upgEnterGuest(t, e, "企圖自升的旅人")
	admin := upgLiveAdminCookie(t, e, "upg.forged.admin")
	before := accountRow(t, e, accountID)

	bodies := []string{
		`{"login_name":"f1","password":"` + upgTestNewPassword + `","account_type":"standard"}`,
		`{"login_name":"f2","password":"` + upgTestNewPassword + `","roles":["server_admin"]}`,
		`{"login_name":"f3","password":"` + upgTestNewPassword + `","status":"active"}`,
		`{"login_name":"f4","password":"` + upgTestNewPassword + `","subject_kind":"root"}`,
		`{"login_name":"f5","password":"` + upgTestNewPassword + `","must_change_password":false}`,
		`{"login_name":"f6","password":"` + upgTestNewPassword + `","display_name":"順手改名"}`,
	}
	for i, body := range bodies {
		resp := upgPut(t, e, accountID, body, admin)
		if resp.StatusCode != http.StatusBadRequest || envelopeCode(t, resp) != int(CodeInvalidBody) {
			t.Errorf("第 %d 份偽造本體應回 1004/400，實際 %d", i+1, resp.StatusCode)
		}
	}
	if got := accountRow(t, e, accountID); got != before {
		t.Errorf("偽造本體不得改動訪戶一個字，變更前 %s／實際 %s", before, got)
	}
	if n := upgradeAuditCount(t, e); n != 0 {
		t.Errorf("偽造本體不得產生升級審計，實際 %d 筆", n)
	}
}

// TestAdminUpgradeAccessAndFailureMatrix 拒絕矩陣逐條各回各句：
// 匿名 2002、普通帳戶 2011、訪戶本人自我升級 2011（本步明令要擋的路）、
// 幽靈標識 1001、非法標識 1001、已轉正目標 2024、停用中的訪戶 2024、
// 重名 2012、空口令 1004 點名 password、壞登入名 1004 點名 login_name、
// GET 方法 1002；每一次拒絕都不留寫入、不記審計。
func TestAdminUpgradeAccessAndFailureMatrix(t *testing.T) {
	e := newGuestLiveEnv(t)
	root := e.rootCookie(t)
	// 翻開訪客開關與建號開關：矩陣裡要用真實訪戶、真實普通帳戶與停用通路。
	putResp := putJSON(t, e.ts, "/root/account-policy", policyBody(true, "closed", true), "",
		map[string]string{"Cookie": cookieHeader(root)})
	if putResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(putResp.Body)
		t.Fatalf("保存策略應成功：%d %s", putResp.StatusCode, body)
	}
	admin := upgLiveAdminCookie(t, e, "upg.matrix.admin")

	// 三位真實訪戶（開關已亮，直接進入，不再翻策略免得把建號開關順帶關回去）。
	freshResp := e.enter(t, "矩陣旅人")
	if freshResp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(freshResp.Body)
		t.Fatalf("訪客進入應成功：%d %s", freshResp.StatusCode, out)
	}
	freshGuest, _ := decodeJSONBody(t, freshResp)["account_id"].(string)
	guestResp := e.enter(t, "自升旅人")
	guestCookie := loginCookie(t, guestResp)
	guestBody := decodeJSONBody(t, guestResp)
	selfID, _ := guestBody["account_id"].(string)

	// 一位真實普通帳戶（管理員建號），作為「已轉正目標」與重名的既有佔用者。
	created := postJSON(t, e.ts, "/admin/accounts",
		`{"login_name":"taken.by.standard","display_name":"正式帳戶","password":"`+stdTestInitial+`"}`,
		"", map[string]string{"Cookie": cookieHeader(admin)})
	if created.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(created.Body)
		t.Fatalf("建立普通帳戶應成功：%d %s", created.StatusCode, body)
	}
	createdBody := decodeJSONBody(t, created)
	standardID, _ := createdBody["account_id"].(string)

	// 一位停用的訪戶：先真實進入，再由管理員經 /status 停用。
	offResp := e.enter(t, "停用旅人")
	if offResp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(offResp.Body)
		t.Fatalf("訪客進入應成功：%d %s", offResp.StatusCode, out)
	}
	offGuestID, _ := decodeJSONBody(t, offResp)["account_id"].(string)
	disable := putJSON(t, e.ts, "/admin/accounts/"+offGuestID+"/status",
		`{"status":"disabled","expected_status":"active"}`, "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if disable.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(disable.Body)
		t.Fatalf("停用訪戶應成功：%d %s", disable.StatusCode, body)
	}
	// 一位普通帳戶主體會話（非管理員）：用 stdTestInitial 登入並完成首改。
	stdFirst := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"taken.by.standard","password":"`+stdTestInitial+`"}`, "", nil)
	stdCookie := loginCookie(t, stdFirst)
	if code := postJSON(t, e.ts, "/auth/password/change",
		`{"current_password":"`+stdTestInitial+`","new_password":"`+stdTestChanged+`"}`, "",
		map[string]string{"Cookie": cookieHeader(stdCookie)}); code.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(code.Body)
		t.Fatalf("普通帳戶首次改密應成功：%s", body)
	}
	stdReLogin := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"taken.by.standard","password":"`+stdTestChanged+`"}`, "", nil)
	stdCookie = loginCookie(t, stdReLogin)

	goodBody := `{"login_name":"matrix.new.name","password":"` + upgTestNewPassword + `"}`
	beforeFresh := accountRow(t, e, freshGuest)
	cases := []struct {
		name       string
		target     string
		body       string
		cookie     *http.Cookie
		wantStatus int
		wantCode   ErrorCode
	}{
		{"匿名", freshGuest, goodBody, nil, http.StatusUnauthorized, CodeNotAuthenticated},
		{"普通帳戶", freshGuest, goodBody, stdCookie, http.StatusForbidden, CodePermissionDenied},
		{"訪戶本人自我升級", selfID, `{"login_name":"self.lift","password":"` + upgTestNewPassword + `"}`,
			guestCookie, http.StatusForbidden, CodePermissionDenied},
		{"幽靈標識", "00000000-0000-7000-8000-000000000123", goodBody, admin,
			http.StatusNotFound, CodeNotFound},
		{"非法標識", "not-a-uuid", goodBody, admin, http.StatusNotFound, CodeNotFound},
		{"已轉正目標", standardID, goodBody, admin, http.StatusConflict, CodeGuestNotUpgradable},
		{"停用中的訪戶", offGuestID, goodBody, admin, http.StatusConflict, CodeGuestNotUpgradable},
		{"重名", freshGuest, `{"login_name":"TAKEN.BY.STANDARD","password":"` + upgTestNewPassword + `"}`,
			admin, http.StatusConflict, CodeLoginNameTaken},
		{"空口令", freshGuest, `{"login_name":"ok.name","password":""}`, admin,
			http.StatusBadRequest, CodeInvalidBody},
		{"壞登入名", freshGuest, `{"login_name":"bad name","password":"` + upgTestNewPassword + `"}`,
			admin, http.StatusBadRequest, CodeInvalidBody},
	}
	for _, tc := range cases {
		resp := upgPut(t, e, tc.target, tc.body, tc.cookie)
		if resp.StatusCode != tc.wantStatus {
			out, _ := io.ReadAll(resp.Body)
			t.Errorf("%s 應回 %d，實際 %d：%s", tc.name, tc.wantStatus, resp.StatusCode, out)
			continue
		}
		if got := envelopeCode(t, resp); got != int(tc.wantCode) {
			t.Errorf("%s 應回機器碼 %d，實際 %d", tc.name, tc.wantCode, got)
		}
	}
	// 方法分流：升級子路徑只認 PUT。
	notMethod := getAuth(t, e.ts, "/admin/accounts/"+freshGuest+"/upgrade",
		cookieHeader(admin), "", "")
	if notMethod.StatusCode != http.StatusMethodNotAllowed ||
		envelopeCode(t, notMethod) != int(CodeMethodNotAllowed) {
		t.Errorf("GET 升級路徑應回 1002/405，實際 %d", notMethod.StatusCode)
	}
	// 全部被拒：目標訪戶一個字不動、零升級審計。
	if got := accountRow(t, e, freshGuest); got != beforeFresh {
		t.Errorf("拒絕矩陣不得改動目標，變更前 %s／實際 %s", beforeFresh, got)
	}
	if n := upgradeAuditCount(t, e); n != 0 {
		t.Errorf("拒絕矩陣不得產生升級審計，實際 %d 筆", n)
	}
	// 四語言訊息齊備（新碼與既有碼同一張目錄，缺語言由本斷言點名）。
	for _, locale := range []string{LocaleZhCN, LocaleZhTW, LocaleEnUS, LocaleJaJP} {
		if messageFor(CodeGuestNotUpgradable, locale) == "" {
			t.Errorf("2024 缺少 %s 訊息", locale)
		}
	}
}

// TestAdminUpgradePathAbsentWithoutWiring 未注入普通帳戶用例時，升級子路徑與
// 其餘目錄端點一樣根本不掛：回 1001，與未掛載逐字相同（連憑據都不必帶——
// 路由不存在時沒有「先看 Cookie 再說路徑不存在」的順序）。
func TestAdminUpgradePathAbsentWithoutWiring(t *testing.T) {
	noWiring := guestTestServer(t, nil)
	t.Cleanup(noWiring.Close)
	resp := putJSON(t, noWiring, "/admin/accounts/00000000-0000-7000-8000-000000000321/upgrade",
		`{"login_name":"x","password":"`+upgTestNewPassword+`"}`, "", nil)
	if resp.StatusCode != http.StatusNotFound || envelopeCode(t, resp) != int(CodeNotFound) {
		t.Errorf("未注入用例時升級路徑應不掛（1001），實際 %d", resp.StatusCode)
	}
}
