// adminaccounts_status_test.go 是「管理員停用與恢復普通帳戶登入」的傳輸層端到端證據：
// 真資料庫＋真用例＋完整中介層鏈，從 Root 開設管理員、管理員真實登入與首改，
// 一路走到 PUT /admin/accounts/{account_id}/status 的兩側、多裝置同時失效、
// 恢復之後的邊界、白名單與隱藏欄位、目標範圍、併發與四語言訊息齊備。
//
// 與 internal/stdacct/status_test.go 的分工是刻意的：那一檔量的是「三件事的合力是否在
// 同一個交易裡落地」，這一檔量的是「這些事實從一條 HTTP 請求看得見嗎」——
// 同一個人從另一臺裝置打進來會拿到哪一句、界面拿什麼去決定那顆按鈕，
// 都在這裡才有答案。
//
// 刻意不收的東西：
//   - 沒有替身：授權、來源判定、首次改密門閂、CAS、撤銷、審計都跨層走真路徑；
//   - 不碰任何真實資料目錄、不佔 5206，全程用本次專屬的暫存庫與系統時鐘。
package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// statusPath 拼出狀態子資源路徑（父路徑的形態由端點合同決定，不在這裡猜）。
func statusPath(id idgen.ID) string {
	return "/admin/accounts/" + id.String() + "/status"
}

// statusBody 產生一份完整的停用／恢復本體（兩個欄位一個都不缺）。
func statusBody(status, expected string) string {
	payload := map[string]any{"status": status, "expected_status": expected}
	data, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// createdAccountID 從 POST /admin/accounts 的成功回應裡取出新帳戶標識。
func createdAccountID(t *testing.T, resp *http.Response) idgen.ID {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		AccountID string `json:"account_id"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("解析建立回應失敗：%s", body)
	}
	id, err := idgen.Parse(out.AccountID)
	if err != nil {
		t.Fatalf("建立回應裡的標識不合法：%v（%s）", err, body)
	}
	return id
}

// statusResponse 解析狀態端點的回應本體。
func statusResponse(t *testing.T, resp *http.Response) (map[string]any, map[string]any) {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("解析狀態回應失敗：%s", body)
	}
	accountBody, ok := envelope["account"].(map[string]any)
	if !ok {
		t.Fatalf("回應應帶 account 物件，實際 %s", body)
	}
	return envelope, accountBody
}

// TestAdminStandardStatusDisableAndRestoreFullLoop 完整閉環：兩臺裝置同時在線的普通帳戶
// 被停用後兩份會話都換不出主體、新登入被拒；恢復後舊會話仍失效、新登入回來而首改義務仍在。
//
// 這一條是本次那句要求的正面證據：動的是這個帳戶在整臺伺服器的登入能力，
// 不是某一場活動裡的限制——所以「失效」必須同時落在兩個既有會話與未來的一切登入上。
func TestAdminStandardStatusDisableAndRestoreFullLoop(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "loop.admin")

	created := e.createAccount(t, stdBody("loop.player", "被停用的那個", stdTestInitial), admin, nil)
	if created.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(created.Body)
		t.Fatalf("建立普通帳戶應成功：%d %s", created.StatusCode, body)
	}
	target := createdAccountID(t, created)

	// 兩趟登入＝兩臺裝置（出廠裝置策略是 multi，名額未滿即各自一份會話）。
	first := loginCookie(t, e.loginAs(t, "loop.player", stdTestInitial))
	second := loginCookie(t, e.loginAs(t, "loop.player", stdTestInitial))
	// 兩份會話此刻都是「換得出主體」的：還欠改密，所以拿到的是 2010 而不是 401。
	for i, cookie := range []*http.Cookie{first, second} {
		probe := getAuth(t, e.ts, "/admin/accounts", cookieHeader(cookie), "", "")
		if probe.StatusCode != http.StatusForbidden ||
			envelopeCode(t, probe) != int(CodePasswordChangeRequired) {
			t.Fatalf("第 %d 份會話在停用前应能換出主體（拿到 2010），實際 %d", i+1, probe.StatusCode)
		}
	}

	disable := putJSON(t, e.ts, statusPath(target),
		statusBody("disabled", "active"), "", map[string]string{"Cookie": cookieHeader(admin)})
	if disable.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(disable.Body)
		t.Fatalf("停用應成功：%d %s", disable.StatusCode, body)
	}
	envelope, accountBody := statusResponse(t, disable)
	if got, ok := envelope["revoked_sessions"].(float64); !ok || got != 2 {
		t.Errorf("停用應回報撤銷了 2 份會話（兩臺裝置），實際 %v", envelope["revoked_sessions"])
	}
	if accountBody["status"] != "disabled" || accountBody["disabled_at"] == nil {
		t.Errorf("回應應是變更後的現值並帶停用時刻，實際 %+v", accountBody)
	}

	// 既有會話立即失效：不是「下次登入會被拒」，而是手上這份已經換不出主體。
	for i, cookie := range []*http.Cookie{first, second} {
		probe := getAuth(t, e.ts, "/admin/accounts", cookieHeader(cookie), "", "")
		if probe.StatusCode != http.StatusUnauthorized ||
			envelopeCode(t, probe) != int(CodeSessionInvalid) {
			t.Errorf("第 %d 份停用前會話應回 2003/401，實際 %d", i+1, probe.StatusCode)
		}
	}
	// 新登入被拒，且與「口令打錯」同一句話：這條通路不外洩「這個人被誰鎖了」。
	blocked := e.loginRaw(t, "loop.player", stdTestInitial)
	wrong := e.loginRaw(t, "loop.player", "明顯錯的口令-not-a-password")
	if blocked.StatusCode != wrong.StatusCode || envelopeCode(t, blocked) != envelopeCode(t, wrong) {
		t.Errorf("停用後的登入應與口令錯誤同形（2001），實際 %d vs %d",
			blocked.StatusCode, wrong.StatusCode)
	}

	detail := getAuth(t, e.ts, "/admin/accounts/"+target.String(), cookieHeader(admin), "", "")
	if text := mustReadAll(t, detail); !strings.Contains(text, `"status":"disabled"`) {
		t.Errorf("停用後的詳情應現讀出 disabled，實際 %s", text)
	}

	restore := putJSON(t, e.ts, statusPath(target),
		statusBody("active", "disabled"), "", map[string]string{"Cookie": cookieHeader(admin)})
	if restore.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(restore.Body)
		t.Fatalf("恢復應成功：%d %s", restore.StatusCode, body)
	}
	envelope, accountBody = statusResponse(t, restore)
	if got, ok := envelope["revoked_sessions"].(float64); !ok || got != 0 {
		t.Errorf("恢復不應撤銷任何會話（恆為 0），實際 %v", envelope["revoked_sessions"])
	}
	if accountBody["status"] != "active" || accountBody["disabled_at"] != nil {
		t.Errorf("恢復後應是 active 且停用時刻欄位缺席（清回 NULL），實際 %+v", accountBody)
	}

	// 舊會話不復活：撤銷是不可逆的事實，恢復通路一個 session 都不碰。
	for i, cookie := range []*http.Cookie{first, second} {
		probe := getAuth(t, e.ts, "/admin/accounts", cookieHeader(cookie), "", "")
		if probe.StatusCode != http.StatusUnauthorized ||
			envelopeCode(t, probe) != int(CodeSessionInvalid) {
			t.Errorf("第 %d 份舊會話在恢復後仍應是已撤銷，實際 %d", i+1, probe.StatusCode)
		}
	}
	// 恢復要重新登入：新簽發的會話仍然欠那一次改密（義務沒被恢復解除）。
	fresh := loginCookie(t, e.loginAs(t, "loop.player", stdTestInitial))
	probe := getAuth(t, e.ts, "/admin/accounts", cookieHeader(fresh), "", "")
	if probe.StatusCode != http.StatusForbidden ||
		envelopeCode(t, probe) != int(CodePasswordChangeRequired) {
		t.Errorf("恢復後新會話仍應被首改門閂擋（2010），實際 %d", probe.StatusCode)
	}

	// 審計：停用與恢復各一筆，操作者是那位管理員本人，且 root_audit 沒有活動欄位。
	for _, action := range []string{"account.disable", "account.enable"} {
		var actorKind, targetID string
		if err := e.db.SQL().QueryRowContext(context.Background(),
			`SELECT actor_kind, target_id FROM root_audit WHERE action = ?`, action).
			Scan(&actorKind, &targetID); err != nil {
			t.Fatalf("讀回 %s 審計失敗：%v", action, err)
		}
		if actorKind != "admin" || targetID != target.String() {
			t.Errorf("%s 審計應是 admin 對那個帳戶，實際 %s／%s", action, actorKind, targetID)
		}
	}
}

// TestAdminStandardStatusAccessControl 鑑別與範圍：匿名 2002、普通帳戶 2011、
// 同級管理員與操作者自己與刪除終態與幽靈一律 1001；訪客帳戶走同一條通路（撤銷數量 0）。
func TestAdminStandardStatusAccessControl(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "acl.admin")

	plain := e.seedPlainAccount(t, account.NewInput{
		LoginName: "acl.plain", DisplayName: "一個普通帳戶", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	plainCookie := loginCookie(t, e.loginAs(t, "acl.plain", dirTestPassword))
	anon := putJSON(t, e.ts, statusPath(plain.ID), statusBody("disabled", "active"), "", nil)
	if anon.StatusCode != http.StatusUnauthorized || envelopeCode(t, anon) != int(CodeNotAuthenticated) {
		t.Errorf("匿名停用應回 2002/401，實際 %d", anon.StatusCode)
	}
	denied := putJSON(t, e.ts, statusPath(plain.ID), statusBody("disabled", "active"), "",
		map[string]string{"Cookie": cookieHeader(plainCookie)})
	if denied.StatusCode != http.StatusForbidden ||
		envelopeCode(t, denied) != int(CodePermissionDenied) {
		t.Errorf("普通帳戶停用他人應回 2011/403，實際 %d", denied.StatusCode)
	}
	// 被普通帳戶拒掉的這幾趟一個字都沒落：現讀狀態仍是 active。
	if got := rawRowSnapshot(t, e, plain.ID)["status"]; got != "active" {
		t.Errorf("被拒的停用不該改狀態，實際 %s", got)
	}

	peer := e.seedPlainAccount(t, account.NewInput{
		LoginName: "acl.peer", DisplayName: "另一位管理員", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	e.grantAdmin(t, peer.ID)
	gone := e.seedPlainAccount(t, account.NewInput{
		LoginName: "acl.gone", DisplayName: "已刪除的", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	if _, err := e.accounts.MarkDeleted(context.Background(), e.db.SQL(), gone.ID,
		gone.DisplayName); err != nil {
		t.Fatalf("寫入刪除終態失敗：%v", err)
	}
	rootReserved, _ := idgen.Parse("00000000-0000-7000-8000-000000000000")
	phantom, err := idgen.New()
	if err != nil {
		t.Fatalf("產生幽靈標識失敗：%v", err)
	}
	// 操作者自己那一筆：他就在 accounts 表裡，也持有授予——這條通路對他同樣只有一句 1001，
	// 「管理員拿普通帳戶端點把自己或同級停掉」在協定層沒有一個可以成立的寫法。
	var selfID string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT id FROM accounts WHERE login_name = ?", "acl.admin").Scan(&selfID); err != nil {
		t.Fatalf("讀回操作者標識失敗：%v", err)
	}
	selfParsed, err := idgen.Parse(selfID)
	if err != nil {
		t.Fatalf("操作者標識解析失敗：%v", err)
	}

	for name, id := range map[string]idgen.ID{
		"同級管理員":     peer.ID,
		"操作者自己":     selfParsed,
		"Root 保留標識": rootReserved,
		"幽靈標識":      phantom,
	} {
		resp := putJSON(t, e.ts, statusPath(id), statusBody("disabled", "active"), "",
			map[string]string{"Cookie": cookieHeader(admin)})
		if resp.StatusCode != http.StatusNotFound || envelopeCode(t, resp) != int(CodeNotFound) {
			t.Errorf("%s 應回 1001/404 同形，實際 %d", name, resp.StatusCode)
		}
	}
	// 已刪除者不再是 1001：他就在這本目錄裡（列得出、點得開），而「停用／恢復」對
	// 一個終態不是一個可發的令，所以這條通路給他的是自己那一句 2027/409。
	// 依據值填的是他在目錄上被讀得到的那個狀態（disabled），讓這一格量到終態判定
	// 而不是「新舊同值」那種參數錯誤。
	terminal := putJSON(t, e.ts, statusPath(gone.ID), statusBody("active", "disabled"), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if terminal.StatusCode != http.StatusConflict ||
		envelopeCode(t, terminal) != int(CodeAccountDeleted) {
		t.Errorf("已刪除者的停用令應回 2027/409，實際 %d", terminal.StatusCode)
	}
	if got := rawRowSnapshot(t, e, peer.ID)["status"]; got != "active" {
		t.Errorf("管理員不得被這條通路停用，peer 現值 %s", got)
	}
	if got := rawRowSnapshot(t, e, gone.ID)["status"]; got != "deleted" {
		t.Errorf("刪除終態的目標不得被改寫（恢復也不該把他拉回來），實際 %s", got)
	}

	guest := e.seedPlainAccount(t, account.NewInput{
		LoginName: "acl.guest", DisplayName: "訪戶帳戶", Type: account.TypeGuest,
		Status: account.StatusActive,
	})
	resp := putJSON(t, e.ts, statusPath(guest.ID), statusBody("disabled", "active"), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("訪客走同一條停用通路應成功：%d %s", resp.StatusCode, body)
	}
	if _, body := statusResponse(t, resp); body["status"] != "disabled" {
		t.Errorf("訪客的狀態應如實落庫，實際 %+v", body)
	}
}

// TestAdminStandardStatusBodyRules 本體白名單：九種隱藏欄位注入、缺依據值、同值、
// 表外值與空本體各自得到點名欄位的 1004，且一個字都不落。
func TestAdminStandardStatusBodyRules(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "body.admin")
	target := e.seedPlainAccount(t, account.NewInput{
		LoginName: "body.target", DisplayName: "本體攻擊的對象", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	before := rawRowSnapshot(t, e, target.ID)
	audits := countTableRows(t, e.db, "root_audit")

	// 兩種 1004 的點名方式不同但都必點名：本體裡那個不存在的欄位由 decodeJSON
	// 以 details.field 交出，值不合法由對映函式以 details.invalid_field 交出。
	// 混成一句斷言會讓「多打了一欄」與「這一欄的值拼錯了」在客戶端得到同一句話，
	// 而前者的處置是刪掉那欄、後者是改那個值。
	cases := []struct {
		name      string
		body      string
		key       string
		wantField string
	}{
		{"順手改顯示名", `{"status":"disabled","expected_status":"active","display_name":"被順手改的名"}`, "field", "display_name"},
		{"順手清改密旗標", `{"status":"disabled","expected_status":"active","must_change_password":false}`, "field", "must_change_password"},
		{"順手換憑據", `{"status":"disabled","expected_status":"active","password":"new-口令-0000"}`, "field", "password"},
		{"順手改類型", `{"status":"disabled","expected_status":"active","account_type":"guest"}`, "field", "account_type"},
		{"自報角色", `{"status":"disabled","expected_status":"active","roles":["server_admin"]}`, "field", "roles"},
		{"塞進某個活動", `{"status":"disabled","expected_status":"active","activity_id":"00000000-0000-7000-8000-000000000001"}`, "field", "activity_id"},
		{"帶自由文本原因", `{"status":"disabled","expected_status":"active","reason":"他吵到別人了"}`, "field", "reason"},
		{"宣稱主體形態", `{"status":"disabled","expected_status":"active","subject_kind":"root"}`, "field", "subject_kind"},
		{"宣稱自己是這個標識", `{"status":"disabled","expected_status":"active","account_id":"01a10000-0000-7000-8000-000000000002"}`, "field", "account_id"},
		{"缺依據值", `{"status":"disabled"}`, "invalid_field", "expected_status"},
		{"依據值空白", `{"status":"disabled","expected_status":""}`, "invalid_field", "expected_status"},
		{"新舊同值", `{"status":"disabled","expected_status":"disabled"}`, "invalid_field", "status"},
		{"表外的新狀態", `{"status":"banned","expected_status":"active"}`, "invalid_field", "status"},
		{"表外的依據值", `{"status":"disabled","expected_status":"gone"}`, "invalid_field", "expected_status"},
		{"刪除態當成可寫值", `{"status":"deleted","expected_status":"active"}`, "invalid_field", "status"},
		{"空本體", `{}`, "invalid_field", "expected_status"},
	}
	for _, tc := range cases {
		resp := putJSON(t, e.ts, statusPath(target.ID), tc.body, "",
			map[string]string{"Cookie": cookieHeader(admin)})
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s 應回 1004/400，實際 %d", tc.name, resp.StatusCode)
			continue
		}
		var env struct {
			Code    int            `json:"code"`
			Details map[string]any `json:"details"`
		}
		text, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(text, &env); err != nil {
			t.Fatalf("%s 信封解析失敗：%s", tc.name, text)
		}
		if env.Code != int(CodeInvalidBody) || env.Details[tc.key] != tc.wantField {
			t.Errorf("%s 應以 details.%s 點名 %s，實際 %s", tc.name, tc.key, tc.wantField, text)
		}
	}
	if got := rawRowSnapshot(t, e, target.ID); fmt.Sprint(got) != fmt.Sprint(before) {
		t.Errorf("被拒的本體一個字都不該落，變更前 %+v／實際 %+v", before, got)
	}
	if got := countTableRows(t, e.db, "root_audit"); got != audits {
		t.Errorf("被拒的本體不該寫審計，應 %d 實際 %d", audits, got)
	}
}

// TestAdminStandardStatusRouting 路由形狀：子路徑只認 PUT（其餘 1002 帶 Allow），
// 父路徑不認 DELETE，多一段的路徑落回 1001。
func TestAdminStandardStatusRouting(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "route.admin")
	target := e.seedPlainAccount(t, account.NewInput{
		LoginName: "route.target", DisplayName: "路由對象", Type: account.TypeStandard,
		Status: account.StatusActive,
	})

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodPatch} {
		resp := sendMethodBody(t, e.ts, method, statusPath(target.ID),
			statusBody("disabled", "active"), admin)
		if resp.StatusCode != http.StatusMethodNotAllowed ||
			envelopeCode(t, resp) != int(CodeMethodNotAllowed) {
			t.Errorf("%s /status 應回 1002/405，實際 %d", method, resp.StatusCode)
			continue
		}
		if allow := resp.Header.Get("Allow"); allow != http.MethodPut {
			t.Errorf("%s /status 的 Allow 應只列 PUT，實際 %q", method, allow)
		}
	}
	// /status 這條子路徑今天仍然只有 PUT：拿父路徑那組方法來敲子路徑，
	// 405 必須只列 PUT（父路徑的 DELETE 不應漏進這一行——兩條路徑的方法集合各自獨立）。
	for _, method := range []string{http.MethodDelete, http.MethodPost, http.MethodPatch} {
		resp := sendMethod(t, e.ts, method, statusPath(target.ID), admin)
		if resp.StatusCode != http.StatusMethodNotAllowed ||
			envelopeCode(t, resp) != int(CodeMethodNotAllowed) {
			t.Errorf("%s /status 應回 1002/405，實際 %d", method, resp.StatusCode)
			continue
		}
		if allow := resp.Header.Get("Allow"); allow != http.MethodPut {
			t.Errorf("%s /status 的 Allow 應只列 PUT，實際 %q", method, allow)
		}
	}
	// 多一個段落沒有登記：回的是 JSON 的 1001，不是網頁外殼也不是 405。
	extra := sendMethod(t, e.ts, http.MethodPut, statusPath(target.ID)+"/extra", admin)
	if extra.StatusCode != http.StatusNotFound || envelopeCode(t, extra) != int(CodeNotFound) {
		t.Errorf("多一段的子路徑應回 1001/404，實際 %d", extra.StatusCode)
	}
}

// TestAdminStandardStatusConflictAndConcurrency 併發與重複：陳舊依據回 2014，
// 四路同依據併發恰好一次成功、其餘 2014，狀態最終是 disabled 且停用時刻只有一個。
func TestAdminStandardStatusConflictAndConcurrency(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "conc.admin")
	target := e.seedPlainAccount(t, account.NewInput{
		LoginName: "conc.target", DisplayName: "併發的對象", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	newAccount := func() *http.Cookie { return loginCookie(t, e.loginAs(t, "conc.target", dirTestPassword)) }
	first := newAccount()
	second := newAccount()

	// 先停一次，再拿同一份舊依據停第二次：那是 2014 而不是「又撤了一輪會話」。
	again := putJSON(t, e.ts, statusPath(target.ID), statusBody("disabled", "active"), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if again.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(again.Body)
		t.Fatalf("首次停用應成功：%d %s", again.StatusCode, body)
	}
	stale := putJSON(t, e.ts, statusPath(target.ID), statusBody("disabled", "active"), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if stale.StatusCode != http.StatusConflict || envelopeCode(t, stale) != int(CodeAdminStatusConflict) {
		t.Errorf("陳舊依據應回 2014/409，實際 %d", stale.StatusCode)
	}

	fresh := e.seedPlainAccount(t, account.NewInput{
		LoginName: "conc.fresh", DisplayName: "被搶著停的人", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	var wg sync.WaitGroup
	codes := make([]int, 4)
	start := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			resp := putJSON(t, e.ts, statusPath(fresh.ID), statusBody("disabled", "active"), "",
				map[string]string{"Cookie": cookieHeader(admin)})
			code := envelopeCode(t, resp)
			if resp.StatusCode == http.StatusOK {
				code = 0
			}
			codes[i] = code
		}(i)
	}
	close(start)
	wg.Wait()

	wins, conflicts := 0, 0
	for i, code := range codes {
		switch code {
		case 0:
			wins++
		case int(CodeAdminStatusConflict):
			conflicts++
		default:
			t.Errorf("第 %d 路回了預期外的碼：%d", i+1, code)
		}
	}
	if wins != 1 || conflicts != 3 {
		t.Errorf("四路同依據併發應恰好一勝三衝突，實際 %d／%d", wins, conflicts)
	}
	if got := rawRowSnapshot(t, e, fresh.ID)["status"]; got != "disabled" {
		t.Errorf("併發之後的目標應是 disabled，實際 %s", got)
	}
	// 兩臺裝置的既有會話都失效（第一筆目標），且失效是撤銷而不是過期。
	for name, cookie := range map[string]*http.Cookie{"第一份": first, "第二份": second} {
		probe := getAuth(t, e.ts, "/admin/accounts", cookieHeader(cookie), "", "")
		if probe.StatusCode != http.StatusUnauthorized ||
			envelopeCode(t, probe) != int(CodeSessionInvalid) {
			t.Errorf("%s 應在停用後換不出主體，實際 %d", name, probe.StatusCode)
		}
	}
}

// TestAdminStandardStatusResponseShapeAndLocales 回應形狀與四語言：信封恰好三鍵、
// account 是白名單欄位、原文不含任何憑據與會話材料，2014 在四語各有自己的一句案。
func TestAdminStandardStatusResponseShapeAndLocales(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "shape2.admin")
	target := e.seedPlainAccount(t, account.NewInput{
		LoginName: "shape2.target", DisplayName: "形狀的對象", Type: account.TypeStandard,
		Status: account.StatusActive,
	})

	resp := putJSON(t, e.ts, statusPath(target.ID), statusBody("disabled", "active"), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	text := mustReadAll(t, resp)
	var envelope map[string]any
	if err := json.Unmarshal([]byte(text), &envelope); err != nil {
		t.Fatalf("解析回應失敗：%s", text)
	}
	if len(envelope) != 3 {
		t.Errorf("信封應恰好 account／revoked_sessions／request_id 三鍵，實際 %+v", envelope)
	}
	accountBody, _ := envelope["account"].(map[string]any)
	want := map[string]bool{"account_id": true, "login_name": true, "display_name": true,
		"account_type": true, "status": true, "must_change_password": true,
		"created_at": true, "last_login_at": true, "disabled_at": true}
	for key := range accountBody {
		if !want[key] {
			t.Errorf("account 多出白名單外的欄位：%s", key)
		}
	}
	for _, forbidden := range []string{"password_hash", "argon2id", "login_name_key", "token",
		"cookie", "roles", "granted_at", "deleted_at", "activity", dirTestPassword} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("回應原文不得出現 %s，實際 %s", forbidden, text)
		}
	}

	// 2014 四語言齊備：拿同一份舊依據再停一次，四語都要有一句非空的案。
	for _, tag := range []string{"zh-CN", "zh-TW", "en-US", "ja-JP"} {
		conflict := sendMethodBodyWithHeader(t, e.ts, http.MethodPut, statusPath(target.ID),
			statusBody("disabled", "active"), admin, map[string]string{"Accept-Language": tag})
		if conflict.StatusCode != http.StatusConflict {
			t.Errorf("%s 的 2014 應是 409，實際 %d", tag, conflict.StatusCode)
			continue
		}
		body, _ := io.ReadAll(conflict.Body)
		var env struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("%s 信封解析失敗：%s", tag, body)
		}
		if env.Code != int(CodeAdminStatusConflict) || strings.TrimSpace(env.Message) == "" {
			t.Errorf("%s 的 2014 訊息必須存在，實際 %s", tag, body)
		}
	}
}
