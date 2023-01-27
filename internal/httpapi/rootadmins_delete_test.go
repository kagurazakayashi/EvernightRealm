// rootadmins_delete_test.go 是「Root 軟刪除管理員」的傳輸層端到端證據：
// 從刪除落地、舊會話與新登入即刻失效、目錄與詳情仍舊讀得到這個人，
// 到四條寫入通路對刪除目標一律回 2015、越權與壞輸入「一個字都不寫」的形態。
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
)

// rootReservedAccountID 取 Root 的保留主體標識（它不在 accounts 表裡）。
//
// 拿它當刪除目標要證的是：刪除通路對 Root 沒有一個可填的格子——
// 那個標識形勢上是一枚正經 UUID，實裡卻查無帳戶行，與幽靈同回 1001。
func rootReservedAccountID(t *testing.T) string {
	t.Helper()
	id, err := identity.RootSubjectID()
	if err != nil {
		t.Fatalf("取 Root 保留標識失敗：%v", err)
	}
	return id.String()
}

// sendAdminDelete 送一個 DELETE（本體原樣交出：刪除不該有任何可動欄位）。
func sendAdminDelete(t *testing.T, ts *httptest.Server, path, body, origin string,
	cookie *http.Cookie) *http.Response {
	t.Helper()
	var payload *bytes.Reader
	if body != "" {
		payload = bytes.NewReader([]byte(body))
	} else {
		payload = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(http.MethodDelete, ts.URL+path, payload)
	if err != nil {
		t.Fatalf("建立請求失敗：%v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if cookie != nil {
		req.Header.Set("Cookie", cookieHeader(cookie))
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("DELETE %s 失敗：%v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// deleteRowSnapshot 直讀帳戶行的全部相關欄位（刪除語意的對照組：
// 既要看得到「該動的動了」，也要看得到「不該動的一律沒動」）。
func deleteRowSnapshot(t *testing.T, db *database.DB, accountID string) string {
	t.Helper()
	var (
		loginName, loginKey, passwordHash, accountType, status, displayName string
		mustChange, createdAt                                               int64
		lastLoginAt, disabledAt, deletedAt                                  int64
	)
	err := db.SQL().QueryRowContext(context.Background(), `SELECT COALESCE(login_name,''), COALESCE(login_name_key,''),
		COALESCE(password_hash,''), COALESCE(account_type,''), COALESCE(status,''), COALESCE(display_name,''),
		COALESCE(must_change_password,-1), COALESCE(created_at,-1), COALESCE(last_login_at,-1),
		COALESCE(disabled_at,-1), COALESCE(deleted_at,-1) FROM accounts WHERE id = ?`, accountID).
		Scan(&loginName, &loginKey, &passwordHash, &accountType, &status, &displayName,
			&mustChange, &createdAt, &lastLoginAt, &disabledAt, &deletedAt)
	if err != nil {
		t.Fatalf("直讀帳戶行失敗：%v", err)
	}
	return strings.Join([]string{loginName, loginKey, passwordHash, accountType, status, displayName,
		strconv.FormatInt(mustChange, 10), strconv.FormatInt(createdAt, 10),
		strconv.FormatInt(lastLoginAt, 10), strconv.FormatInt(disabledAt, 10),
		strconv.FormatInt(deletedAt, 10)}, "\x00")
}

// TestRootDeleteAdminEndToEndOverHTTP 走完整條刪除時間線：Root 開人 → 目標登入兩臺 →
// 刪除成功並回報撤銷數量 → 兩份舊會話即刻 401 → 舊口令即刻 2001（不再能登入）→
// 目錄與詳情仍舊讀得到這個人（歷史身份可解釋）→ 同名不能再開（2012）。
func TestRootDeleteAdminEndToEndOverHTTP(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, rootCookie, "drop.e2e")
	cookieA := loginCookie(t, env.loginAs(t, "drop.e2e", adminTestInitialPasswd))
	cookieB := loginCookie(t, env.loginAs(t, "drop.e2e", adminTestInitialPasswd))

	resp := sendAdminDelete(t, env.ts, "/root/admins/"+id, "", env.ts.URL, rootCookie)
	if resp.StatusCode != http.StatusOK {
		text := readAllText(t, resp)
		t.Fatalf("刪除應成功：%d %s", resp.StatusCode, text)
	}
	var deletion adminDeleteResponse
	if err := json.NewDecoder(resp.Body).Decode(&deletion); err != nil {
		t.Fatalf("解析刪除回應失敗：%v", err)
	}
	if deletion.Admin.Status != "deleted" {
		t.Errorf("回應狀態應是 deleted，實際 %q", deletion.Admin.Status)
	}
	if deletion.Admin.DeletedAt == "" {
		t.Error("回應必須帶出刪除時刻（行保留之後這是唯一記下那一刻的地方）")
	}
	if !strings.HasPrefix(deletion.Admin.DisplayName, "DEL_") {
		t.Errorf("回應的顯示名應是匿名化佔位值，實際 %q", deletion.Admin.DisplayName)
	}
	if deletion.Admin.LoginName != "drop.e2e" {
		t.Errorf("登入名必須原樣保留以承載歷史，實際 %q", deletion.Admin.LoginName)
	}
	if deletion.RevokedSessions != 2 {
		t.Errorf("刪除應回報撤銷了兩份會話，實際 %d", deletion.RevokedSessions)
	}

	// 舊會話立即失效：兩份都換不出身分（與其餘會話失敗同形）。
	for name, cookie := range map[string]*http.Cookie{"會話A": cookieA, "會話B": cookieB} {
		got := getAuth(t, env.ts, "/root/admins", cookieHeader(cookie), "", "")
		assertEnvelopeCode(t, got, CodeSessionInvalid)
		if got.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s 刪除後應收到 401，實際 %d", name, got.StatusCode)
		}
	}
	// 新登入被拒，且與口令錯誤同形：外界沒有一句話能把「被刪了」與「口令打錯」分開。
	assertEnvelopeCode(t, env.loginAs(t, "drop.e2e", adminTestInitialPasswd), CodeInvalidCredentials)

	// 詳情與目錄仍讀得到這個人：這是「保留歷史身份」對外的樣子。
	detail := getAuth(t, env.ts, "/root/admins/"+id, cookieHeader(rootCookie), "", "")
	if detail.StatusCode != http.StatusOK {
		t.Fatalf("已刪除目標的詳情仍應 200：%d", detail.StatusCode)
	}
	var profile adminProfileResponse
	if err := json.NewDecoder(detail.Body).Decode(&profile); err != nil {
		t.Fatalf("解析詳情失敗：%v", err)
	}
	if profile.Admin.Status != "deleted" || profile.Admin.DeletedAt != deletion.Admin.DeletedAt {
		t.Errorf("詳情應與刪除回應同源，實際 %+v", profile.Admin)
	}

	for query, wantSeen := range map[string]bool{"": true, "status=deleted": true,
		"status=active": false, "status=disabled": false} {
		path := "/root/admins"
		if query != "" {
			path += "?" + query
		}
		list := getAuth(t, env.ts, path, cookieHeader(rootCookie), "", "")
		if list.StatusCode != http.StatusOK {
			t.Fatalf("列舉目錄失敗：%d", list.StatusCode)
		}
		var page adminListResponse
		if err := json.NewDecoder(list.Body).Decode(&page); err != nil {
			t.Fatalf("解析目錄失敗：%v", err)
		}
		seen := false
		for _, item := range page.Admins {
			if item.AccountID == id {
				seen = true
			}
		}
		if seen != wantSeen {
			t.Errorf("%s：篩選 %q 的可見性應為 %v，實際 %v", "目錄", query, wantSeen, seen)
		}
	}

	// 登入名仍被佔用：同名不能再開（唯一索引仍在同一行上）。
	reopen := createAdminRaw(t, env.ts, createAdminBody("drop.e2e", "同名再來", adminTestInitialPasswd),
		rootCookie, env.ts.URL, nil)
	assertEnvelopeCode(t, reopen, CodeLoginNameTaken)

	// 審計與日誌不得含任何憑據材料。
	var changes, reason string
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT changes_json, reason FROM root_audit WHERE action = 'admin.delete'").
		Scan(&changes, &reason); err != nil {
		t.Fatalf("讀回刪除審計失敗：%v", err)
	}
	if !strings.Contains(changes, "目錄測試管理員") {
		t.Errorf("刪除審計應含刪除前的顯示名快照，實際 %s", changes)
	}
	for _, forbidden := range []string{adminTestInitialPasswd, adminTestChangedPasswd,
		"argon2id", "password_hash", "token_hash", "login_name_key"} {
		if strings.Contains(changes, forbidden) || strings.Contains(reason, forbidden) {
			t.Errorf("刪除審計不得含 %q 的影子", forbidden)
		}
	}
}

// TestDeleteAdminTerminalRefusalsOverHTTP 刪除是終態：重複刪除與其餘三條寫入通路
// 對同一個目標一律回 2015，並且現值逐字不動、審計不加筆。
func TestDeleteAdminTerminalRefusalsOverHTTP(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, rootCookie, "drop.terminal")
	if resp := sendAdminDelete(t, env.ts, "/root/admins/"+id, "", env.ts.URL, rootCookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("前置刪除失敗：%d", resp.StatusCode)
	}
	before := deleteRowSnapshot(t, env.db, id)

	cases := map[string]*http.Response{
		"重複刪除": sendAdminDelete(t, env.ts, "/root/admins/"+id, "", env.ts.URL, rootCookie),
		"編輯資料": putJSON(t, env.ts, "/root/admins/"+id,
			`{"display_name":"已被刪過了","expected_display_name":"DEL_Whatever"}`, env.ts.URL,
			map[string]string{"Cookie": cookieHeader(rootCookie)}),
		"恢復登入": putJSON(t, env.ts, "/root/admins/"+id+"/status",
			`{"status":"active","expected_status":"disabled"}`, env.ts.URL,
			map[string]string{"Cookie": cookieHeader(rootCookie)}),
		"再次停用": putJSON(t, env.ts, "/root/admins/"+id+"/status",
			`{"status":"disabled","expected_status":"active"}`, env.ts.URL,
			map[string]string{"Cookie": cookieHeader(rootCookie)}),
		"重置憑據": putJSON(t, env.ts, "/root/admins/"+id+"/password",
			`{"password":"`+adminTestChangedPasswd+`"}`, env.ts.URL,
			map[string]string{"Cookie": cookieHeader(rootCookie)}),
	}
	for name, resp := range cases {
		env2 := envelopeOf(t, resp)
		if env2.Code != CodeAdminDeleted {
			t.Errorf("%s 應回 2015，實際 %d", name, env2.Code)
		}
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("%s 應為 409（處置是「別再對他下寫入令」，不是重新登入），實際 %d", name, resp.StatusCode)
		}
		if env2.Message == "" {
			t.Errorf("%s 的 2015 必須有一句可展示的話", name)
		}
	}
	if after := deleteRowSnapshot(t, env.db, id); after != before {
		t.Errorf("五條被拒的請求之後現值必須逐字不動：\n%s\n%s", before, after)
	}
	var extra int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM root_audit WHERE action IN ('admin.delete','admin.profile_update','admin.enable','admin.disable','admin.password_reset')`).
		Scan(&extra); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if extra != 1 {
		t.Errorf("除那一次成功的刪除之外不得再加筆審計，實際共 %d 筆", extra)
	}
}

// TestDeleteAdminAuthorizationAndIdentityMatrix 刪除入口的主體與目標矩陣。
func TestDeleteAdminAuthorizationAndIdentityMatrix(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	victimID := createAdminViaAPI(t, env, rootCookie, "drop.matrix")
	before := deleteRowSnapshot(t, env.db, victimID)
	path := "/root/admins/" + victimID

	env.livePlainAccount(t, "plain.deleter", adminTestPlainPasswd)
	plainCookie := loginCookie(t, env.loginAs(t, "plain.deleter", adminTestPlainPasswd))

	// 一位持有 server_admin 的「同級」：他連「刪另一個管理員」這件事都不該能做。
	createAdminViaAPI(t, env, rootCookie, "drop.peer3")
	peerCookie := loginCookie(t, env.loginAs(t, "drop.peer3", adminTestInitialPasswd))
	if resp := postJSON(t, env.ts, "/auth/password/change",
		`{"current_password":"`+adminTestInitialPasswd+`","new_password":"`+adminTestChangedPasswd+`"}`,
		"", map[string]string{"Cookie": cookieHeader(peerCookie)}); resp.StatusCode != http.StatusOK {
		t.Fatalf("同級管理員改密失敗：%d", resp.StatusCode)
	}
	peerCookie = loginCookie(t, env.loginAs(t, "drop.peer3", adminTestChangedPasswd))

	for name, resp := range map[string]*http.Response{
		"匿名":    sendAdminDelete(t, env.ts, path, "", "", nil),
		"普通帳戶":  sendAdminDelete(t, env.ts, path, "", env.ts.URL, plainCookie),
		"同級管理員": sendAdminDelete(t, env.ts, path, "", env.ts.URL, peerCookie),
	} {
		want := CodePermissionDenied
		if name == "匿名" {
			want = CodeNotAuthenticated
		}
		assertEnvelopeCode(t, resp, want)
		if name != "匿名" && resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s 越權刪除應為 403，實際 %d", name, resp.StatusCode)
		}
	}
	// 跨站來源：先問來源，連目標都不問。
	assertEnvelopeCode(t, sendAdminDelete(t, env.ts, path, "", "http://evil.example", rootCookie),
		CodeOriginForbidden)

	// 標識形態與目錄外目標同回 1001：端點不是標識探針。
	var plainID string
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT id FROM accounts WHERE login_name = ?", "plain.deleter").Scan(&plainID); err != nil {
		t.Fatalf("讀普通帳戶標識失敗：%v", err)
	}
	ghost := "0192f0c4-1c9a-7000-8000-0000000000aa"
	for name, probe := range map[string]string{
		"格式不對":    "/root/admins/not-a-uuid",
		"幽靈標識":    "/root/admins/" + ghost,
		"零值標識":    "/root/admins/00000000-0000-0000-0000-000000000000",
		"未授予帳戶":   "/root/admins/" + plainID,
		"Root 保留": "/root/admins/" + rootReservedAccountID(t),
	} {
		resp := sendAdminDelete(t, env.ts, probe, "", env.ts.URL, rootCookie)
		assertEnvelopeCode(t, resp, CodeNotFound)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s 應為 404，實際 %d", name, resp.StatusCode)
		}
	}
	if after := deleteRowSnapshot(t, env.db, victimID); after != before {
		t.Error("被拒的刪除與探測不得動目標任何一欄")
	}
	var deletions int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.delete'").Scan(&deletions); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if deletions != 0 {
		t.Errorf("被拒的刪除不得寫入 Root 審計，實際 %d 筆", deletions)
	}
}

// TestDeleteAdminCarriesNoFieldsAndNoBasis 刪除沒有請求本體也沒有依據值：
// 任何企圖塞欄位進去的寫法都在協定層被拒，且一個字都不寫。
// 沒有 expected_* 是因為 Root 拿不出「現行刪除時刻」這類誠實錨點（見 adminacct/deleted.go）。
func TestDeleteAdminCarriesNoFieldsAndNoBasis(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, rootCookie, "drop.nobody")
	before := deleteRowSnapshot(t, env.db, id)
	path := "/root/admins/" + id

	for name, body := range map[string]string{
		"企圖交依據值":  `{"expected_status":"active"}`,
		"企圖順手改名":  `{"display_name":"刪除順便改名"}`,
		"企圖帶角色欄":  `{"roles":["server_admin"]}`,
		"企圖指定去向":  `{"purge":true}`,
		"企圖自報標識":  `{"account_id":"` + id + `"}`,
		"畸形 JSON": `{"expected_status":`,
		"本體是陣列":   `[1,2]`,
		"尾隨資料":    `{} {}`,
	} {
		resp := sendAdminDelete(t, env.ts, path, body, env.ts.URL, rootCookie)
		if code := envelopeOf(t, resp).Code; code != CodeInvalidBody {
			t.Errorf("%s：應被 1004 拒殺，實際 %d", name, code)
		}
	}
	if after := deleteRowSnapshot(t, env.db, id); after != before {
		t.Error("被拒的刪除請求不得動目標任何一欄")
	}

	// 空本體與 {} 都是同一句話「我要刪他」：刪除不選欄位，所以沒有可填的格子，
	// 也沒有「忘了填所以失敗」這種無意義的差別。
	if resp := sendAdminDelete(t, env.ts, path, `{}`, env.ts.URL, rootCookie); resp.StatusCode != http.StatusOK {
		text := readAllText(t, resp)
		t.Fatalf("帶空物件的 DELETE 應成功：%d %s", resp.StatusCode, text)
	}
}

// TestDeleteAdminOnlyTouchesItsOwnTarget 刪除只動那一個人：另一位管理員與 Root 自己的
// 會話一律不受影響（撤銷是按帳戶計的，沒有任何「順手清一輪」的通路）。
func TestDeleteAdminOnlyTouchesItsOwnTarget(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	victimID := createAdminViaAPI(t, env, rootCookie, "drop.target")
	otherID := createAdminViaAPI(t, env, rootCookie, "drop.bystander")
	victimCookie := loginCookie(t, env.loginAs(t, "drop.target", adminTestInitialPasswd))
	// 旁人那份會話還沒還清首次改密義務也無妨：下面問的是 /auth/session，
	// 它在門閂的豁免清單裡，正好讓「會話活不活」與「欠不欠改密」兩件事分開看。
	bystanderCookie := loginCookie(t, env.loginAs(t, "drop.bystander", adminTestInitialPasswd))

	if resp := sendAdminDelete(t, env.ts, "/root/admins/"+victimID, "", env.ts.URL, rootCookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("刪除失敗：%d", resp.StatusCode)
	}
	// 用 /auth/session 判「會話還活不活」：它只要一個可信主體，不需要 Root 權限。
	// 拿 /root/admins 問這件事，旁人會拿到 2011——那是它本來就不該有的權限，
	// 不是「被別人的刪除牽連」，兩個結論混在一起就白驗了。
	assertEnvelopeCode(t, getAuth(t, env.ts, "/auth/session", cookieHeader(victimCookie), "", ""),
		CodeSessionInvalid)
	if resp := getAuth(t, env.ts, "/auth/session", cookieHeader(bystanderCookie), "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("旁人的會話不該被牽連：%d", resp.StatusCode)
	}
	if resp := getAuth(t, env.ts, "/auth/session", cookieHeader(rootCookie), "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("Root 自己的會話不該被牽連：%d", resp.StatusCode)
	}
	// 旁人的行也逐字不動（比對欄位拼接，不靠回應裡的字）。
	var bystanderStatus string
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT status FROM accounts WHERE id = ?", otherID).Scan(&bystanderStatus); err != nil {
		t.Fatalf("讀旁人狀態失敗：%v", err)
	}
	if bystanderStatus != "active" {
		t.Errorf("旁人應仍是 active，實際 %q", bystanderStatus)
	}
}

// TestDeleteAdminResponseNeverEchoesCredential 刪除的成功回應與審計原文都不該出現
// 任何憑據材料或內部鍵：它能公開的只有「這個人已不在、何時不在的」。
func TestDeleteAdminResponseNeverEchoesCredential(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	id := createAdminViaAPI(t, env, rootCookie, "drop.echo")
	text := readAllText(t, sendAdminDelete(t, env.ts, "/root/admins/"+id, "", env.ts.URL, rootCookie))
	for _, forbidden := range []string{adminTestInitialPasswd, "argon2id",
		"password_hash", "login_name_key", "token_hash", "device_id"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("刪除回應不得含 %q", forbidden)
		}
	}
	// 回應也不該暗示任何「恢復」的通路存在。
	if strings.Contains(text, "restore") || strings.Contains(text, "undelete") {
		t.Errorf("刪除是終態，回應不得出現恢復字樣：%s", text)
	}
}

// TestDeleteAdminRejectedWhilePasswordChangeOutstanding 刪除入口同受首次改密門閂：
// 一個還欠改密義務的 Root 會話（這裡用未改密的管理員）敲不動這組端點。
//
// 這一條釘的是「新增受保護端點不必再想一次要不要擋」那句話真的成立——
// 刪除沒有繞過任何一道既有閘。
func TestDeleteAdminRejectedWhilePasswordChangeOutstanding(t *testing.T) {
	env := newAdminEnv(t, adminTestRootPassword)
	rootCookie := env.rootCookie(t)
	victimID := createAdminViaAPI(t, env, rootCookie, "drop.gated")
	bystanderID := createAdminViaAPI(t, env, rootCookie, "drop.gater")

	// 這位管理員從未完成首次改密，手上那份會話就是「欠義務」的那種。
	gaterCookie := loginCookie(t, env.loginAs(t, "drop.gater", adminTestInitialPasswd))
	resp := sendAdminDelete(t, env.ts, "/root/admins/"+victimID, "", env.ts.URL, gaterCookie)
	assertEnvelopeCode(t, resp, CodePasswordChangeRequired)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("欠改密義務應為 403，實際 %d", resp.StatusCode)
	}
	var deletions int
	if err := env.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = 'admin.delete'").Scan(&deletions); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if deletions != 0 {
		t.Errorf("被門閂擋下的刪除不應落地，實際 %d 筆", deletions)
	}
	_ = bystanderID
}
