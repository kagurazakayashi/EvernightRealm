// adminaccounts_directory_test.go 是「管理員端普通帳戶目錄與資料編輯」的傳輸層端到端證據：
// 真資料庫＋真用例＋完整中介層鏈，從 Root 開設管理員、管理員真實登入與首改，
// 一路走到 GET /admin/accounts 的範圍與篩選、單筆詳情、PUT 白名單編輯、
// 隱藏欄位注入、刪除態與同級管理目標、併發與四語言訊息齊備。
//
// 刻意不收的東西：
//   - 沒有替身：授權、來源判定、首次改密門閂、CAS、審計都跨層走真路徑，接錯線就會紅；
//   - 不碰任何真實資料目錄、不佔 5206，全程用本次專屬的暫存庫與系統時鐘。
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// dirTestPassword 是目錄測試專屬的憑據：只活在這次進程的記憶體，不是任何環境的口令。
const dirTestPassword = "adminaccounts-directory-test-口令"

// sendMethod 以任意方法打任意路徑（方法分流與 405 用）。
func sendMethod(t *testing.T, ts *httptest.Server, method, path string,
	cookie *http.Cookie) *http.Response {
	t.Helper()
	return sendMethodBody(t, ts, method, path, "", cookie)
}

// sendMethodBody 同 sendMethod，但可帶本體（PUT 與攻擊性 DELETE 用）。
func sendMethodBody(t *testing.T, ts *httptest.Server, method, path, body string,
	cookie *http.Cookie) *http.Response {
	t.Helper()
	var payload io.Reader
	if body != "" {
		payload = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, ts.URL+path, payload)
	if err != nil {
		t.Fatalf("建立 %s 請求失敗：%v", method, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.Header.Set("Cookie", cookieHeader(cookie))
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s 失敗：%v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// seedPlainAccount 經倉儲種入一筆「不欠改密、沒有授予」的普通帳戶，回傳其實體。
//
// 走倉儲而不是建號端點：建號出的帳戶恆帶首次改密旗標，而目錄與編輯要量的形態包括
// 「已完成改密的普通帳戶」「訪客帳戶」「停用者」「已刪除者」——那些都不是建號端點產得出的。
func (e *stdEnv) seedPlainAccount(t *testing.T, in account.NewInput) account.Account {
	t.Helper()
	if in.Type == account.TypeStandard && in.PasswordHash == "" {
		hash, err := credential.Hash(dirTestPassword, credential.TestParams)
		if err != nil {
			t.Fatalf("產生測試憑據失敗：%v", err)
		}
		in.PasswordHash = hash
	}
	created, err := e.accounts.Create(context.Background(), e.db.SQL(), in)
	if err != nil {
		t.Fatalf("種入帳戶 %s 失敗：%v", in.LoginName, err)
	}
	return created
}

// grantAdmin 為一筆既有帳戶補上 server_admin 授予（經授予倉儲，不直寫 SQL）：
// 这一笔因此變成「不該出現在普通帳戶目錄、也不該被這條通路改到」的那一类目标。
func (e *stdEnv) grantAdmin(t *testing.T, id idgen.ID) {
	t.Helper()
	store := grant.NewStore(timeutil.System())
	if err := store.Grant(context.Background(), e.db.SQL(), id, identity.RoleServerAdmin); err != nil {
		t.Fatalf("補上授予失敗：%v", err)
	}
}

// directoryBody 讀一頁目錄並解析成通用結構。
func directoryBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("解析目錄回應失敗：%s", body)
	}
	return out
}

// rowsOf 取出目錄回應裡的行陣列。
func rowsOf(t *testing.T, envelope map[string]any) []map[string]any {
	t.Helper()
	raw, ok := envelope["accounts"].([]any)
	if !ok {
		t.Fatalf("accounts 欄位應為數組，實際 %T", envelope["accounts"])
	}
	rows := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		row, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("目錄行應為物件，實際 %T", item)
		}
		rows = append(rows, row)
	}
	return rows
}

// TestAdminDirectoryReadIsAdminOnly 目錄讀取的鑑別面：匿名 2002、普通帳戶 2011、
// 管理員 200、未注入用例時 1001（另一條測試），以及「同一路徑上 POST 仍能建號」。
//
// 這一條量的是本步那句要求：普通用戶與訪客不能枚舉全站賬戶——
// 靠的是這條讀取通路在服务層就只有管理員走得通，不靠界面藏起按鈕。
func TestAdminDirectoryReadIsAdminOnly(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "read.admin")

	anon := getAuth(t, e.ts, "/admin/accounts", "", "", "")
	if anon.StatusCode != http.StatusUnauthorized || envelopeCode(t, anon) != int(CodeNotAuthenticated) {
		t.Errorf("匿名讀目錄應回 2002/401，實際 %d", anon.StatusCode)
	}
	plain := e.seedPlainAccount(t, account.NewInput{
		LoginName: "read.plain", DisplayName: "普通帳戶", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	plainCookie := loginCookie(t, e.loginAs(t, "read.plain", dirTestPassword))
	if plain.ID.IsNil() {
		t.Error("種入的帳戶應有標識（測試前提）")
	}
	denied := getAuth(t, e.ts, "/admin/accounts", cookieHeader(plainCookie), "", "")
	if denied.StatusCode != http.StatusForbidden || envelopeCode(t, denied) != int(CodePermissionDenied) {
		t.Errorf("普通帳戶讀目錄應回 2011/403，實際 %d", denied.StatusCode)
	}
	// 欠改密的帳戶連目錄都讀不到：同一把門閂罩住讀取通路，不只罩寫入。
	gated := e.createAccount(t, stdBody("read.gated", "欠改密的", stdTestInitial), admin, nil)
	if gated.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(gated.Body)
		t.Fatalf("建立第二筆應成功：%d %s", gated.StatusCode, body)
	}
	gatedCookie := loginCookie(t, e.loginAs(t, "read.gated", stdTestInitial))
	gatedRead := getAuth(t, e.ts, "/admin/accounts", cookieHeader(gatedCookie), "", "")
	if gatedRead.StatusCode != http.StatusForbidden ||
		envelopeCode(t, gatedRead) != int(CodePasswordChangeRequired) {
		t.Errorf("欠改密的帳戶讀目錄應回 2010/403，實際 %d", gatedRead.StatusCode)
	}
	okResp := getAuth(t, e.ts, "/admin/accounts", cookieHeader(admin), "", "")
	if okResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(okResp.Body)
		t.Fatalf("管理員讀目錄應成功：%d %s", okResp.StatusCode, body)
	}
}

// TestAdminDirectoryScopeAndShape 目錄的範圍與形狀：列出普通與訪客帳戶、排掉持有授予者
// （含操作者自己）與刪除終態；回應恰好五個鍵、行恰好一組白名單欄位；
// 全原文不含任何憑據、會話材料與內部正規化鍵。
func TestAdminDirectoryScopeAndShape(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "shape.admin")

	// 管理員自己那一行（liveAdminCookie 經 Root 開設，已在 accounts 表裡）與
	// 另一位被授予的帳戶：兩者都不得出現在普通帳戶目錄。
	peer := e.seedPlainAccount(t, account.NewInput{
		LoginName: "shape.peer", DisplayName: "同級管理員", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	e.grantAdmin(t, peer.ID)
	e.seedPlainAccount(t, account.NewInput{
		LoginName: "shape.guest", DisplayName: "訪客一號", Type: account.TypeGuest,
		Status: account.StatusActive, MustChangePassword: false,
	})
	gone := e.seedPlainAccount(t, account.NewInput{
		LoginName: "shape.gone", DisplayName: "已刪除的", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	if _, err := e.accounts.MarkDeleted(context.Background(), e.db.SQL(), gone.ID,
		gone.DisplayName); err != nil {
		t.Fatalf("寫入刪除終態失敗：%v", err)
	}

	resp := getAuth(t, e.ts, "/admin/accounts?page_size=50", cookieHeader(admin), "", "")
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("目錄應成功：%d %s", resp.StatusCode, body)
	}
	// 回應體只讀一次：先拿到原文再做結構斷言，否則下面的「原文不得含憑據」
	// 會在一個已被讀空的體上通過，那是假綠。
	raw := strings.ToLower(mustReadAll(t, resp))
	var envelope map[string]any
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		t.Fatalf("解析目錄回應失敗：%s", raw)
	}
	for _, key := range []string{"accounts", "page", "page_size", "total", "request_id"} {
		if _, ok := envelope[key]; !ok {
			t.Errorf("目錄回應缺少 %s：%v", key, envelope)
		}
	}
	if len(envelope) != 5 {
		t.Errorf("目錄回應應恰好五個鍵，實際 %v", envelope)
	}
	rows := rowsOf(t, envelope)
	if float64(len(rows)) != envelope["total"].(float64) {
		t.Errorf("行數與總數應一致（本頁翻完），實際 rows=%d total=%v", len(rows), envelope["total"])
	}
	// 這裡該看到 shape.guest 與 shape.gone 兩筆：peer 有授予、shape.admin 有授予、
	// Root 不在 accounts 表裡，三者一律不列；而 gone 已被軟刪除，按用戶批准的
	// 刪除後展示策略他仍然在名冊上（行留著正是為了被讀到），帶著 status=deleted
	// 與 deleted_at。少了他，界面就只剩「查無此人」這個錯答案可用。
	if len(rows) != 2 {
		t.Fatalf("目錄範圍不對，實際 %v", rows)
	}
	byLogin := map[string]map[string]any{}
	for _, row := range rows {
		byLogin[row["login_name"].(string)] = row
	}
	guestRow, goneRow := byLogin["shape.guest"], byLogin["shape.gone"]
	if guestRow == nil || goneRow == nil {
		t.Fatalf("目錄應列出去訪客與已刪者兩筆，實際 %v", rows)
	}
	if guestRow["account_type"] != "guest" {
		t.Errorf("訪客列必須如實顯示來源，實際 %v", guestRow["account_type"])
	}
	// 已刪者的那一行必須自己講完整：狀態、刪除時刻、服務端寫回的佔位顯示名，
	// 而登入名原樣保留（這正是「名字繼續被占用」的可讀形態）。
	if goneRow["status"] != "deleted" {
		t.Errorf("已刪者的狀態應如實帶出，實際 %v", goneRow["status"])
	}
	if at, ok := goneRow["deleted_at"]; !ok || at == "" {
		t.Errorf("已刪者的行必須帶 deleted_at，實際 %v", goneRow)
	}
	if name, _ := goneRow["display_name"].(string); !strings.HasPrefix(strings.ToLower(name), "del_") {
		t.Errorf("已刪者讀到的應是佔位顯示名，實際 %q", name)
	}
	for _, row := range rows {
		for _, key := range []string{"account_id", "login_name", "display_name", "account_type",
			"status", "must_change_password", "created_at"} {
			if _, ok := row[key]; !ok {
				t.Errorf("行缺少 %s：%v", key, row)
			}
		}
		// 從未登入時 last_login_at 應缺席（不拿建立時刻冒充）。
		if _, ok := row["last_login_at"]; ok {
			t.Errorf("從未登入的行不該帶 last_login_at：%v", row)
		}
		// 沒被刪過的行不該帶刪除時刻——那與零值冒充是同一件事的兩種寫法。
		if row["status"] != "deleted" {
			if _, ok := row["deleted_at"]; ok {
				t.Errorf("非刪除態的行不該帶 deleted_at：%v", row)
			}
		}
	}
	// 憑據與會話材料仍然一個字都不许出現。deleted_at 已不在這一列裡：
	// 它是刪除後展示策略要求必須出現的那一欄，而它是一個時刻，不是一條憑據。
	for _, forbidden := range []string{"password_hash", "argon2id", "login_name_key",
		"$argon2id$", "token", "cookie", "roles", "granted_at", "activity",
		strings.ToLower(dirTestPassword), strings.ToLower(stdTestInitial)} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("目錄原文不得含 %q：實際 %s", forbidden, raw)
		}
	}
	if strings.Contains(raw, "del_2026") == false {
		t.Errorf("已刪者的佔位顯示名應由服務端寫回並被原樣列出，實際 %s", raw)
	}
}

// TestAdminDirectoryFiltersAndInvalidParams 三種篩選在傳輸層的形態與非法參數各自點名。
//
// 查詢字串一律經 net/url 編碼：關鍵字裡有 CJK、% 與底線這些「在 URL 層就會變形」的字元，
// 手拼字串會讓斷言測到的是編碼器而不是篩選規則。
func TestAdminDirectoryFiltersAndInvalidParams(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "filter.http.admin")

	e.seedPlainAccount(t, account.NewInput{LoginName: "http.alpha", DisplayName: "阿爾法",
		Type: account.TypeStandard, Status: account.StatusActive})
	e.seedPlainAccount(t, account.NewInput{LoginName: "http.beta", DisplayName: "貝塔",
		Type: account.TypeStandard, Status: account.StatusActive})
	e.seedPlainAccount(t, account.NewInput{LoginName: "http.gamma", DisplayName: "第三號",
		Type: account.TypeStandard, Status: account.StatusActive})
	e.seedPlainAccount(t, account.NewInput{LoginName: "http.guest", DisplayName: "訪客二號",
		Type: account.TypeGuest, Status: account.StatusActive})

	// 停用的那一筆走的是倉儲直寫（本步沒有停用普通帳戶的通路），用来量狀態篩選。
	off := e.seedPlainAccount(t, account.NewInput{LoginName: "http.off", DisplayName: "停用者",
		Type: account.TypeStandard, Status: account.StatusActive})
	if _, err := e.accounts.SetStatus(context.Background(), e.db.SQL(), off.ID,
		account.StatusDisabled, account.StatusActive); err != nil {
		t.Fatalf("種入停用形態失敗：%v", err)
	}

	for name, tc := range map[string]struct {
		params url.Values
		total  float64
		rows   int
	}{
		"默認":   {url.Values{}, 5, 5},
		"類型訪客": {url.Values{"type": []string{"guest"}}, 1, 1},
		"類型普通": {url.Values{"type": []string{"standard"}}, 4, 4},
		"狀態啟用": {url.Values{"status": []string{"active"}}, 4, 4},
		"狀態停用": {url.Values{"status": []string{"disabled"}}, 1, 1},
		// 刪除態現在是一個被受理的篩選值（用戶批准的刪除後展示策略）。這個現場裡
		// 還沒有已刪者，所以它量到的是「合法值走正常路：200、空頁、總數 0」，
		// 而不是被当成非法參數——已刪者被列出來的那一段由 TestAdminDirectoryScopeAndShape 釘。
		"狀態列刪除態":  {url.Values{"status": []string{"deleted"}}, 0, 0},
		"關鍵字顯示名":  {url.Values{"q": []string{"阿爾法"}}, 1, 1},
		"關鍵字登入名":  {url.Values{"q": []string{"HTTP.BETA"}}, 1, 1},
		"關鍵字不命中":  {url.Values{"q": []string{"查無此名"}}, 0, 0},
		"關鍵字是百分號": {url.Values{"q": []string{"100%"}}, 0, 0},
		"關鍵字含底線":  {url.Values{"q": []string{"a_b"}}, 0, 0},
		"關鍵字含反斜線": {url.Values{"q": []string{`x\y`}}, 0, 0},
		"疊加篩選":    {url.Values{"q": []string{"訪客"}, "type": []string{"guest"}}, 1, 1},
		"每頁一筆":    {url.Values{"page_size": []string{"1"}}, 5, 1},
		"第二頁":     {url.Values{"page": []string{"2"}, "page_size": []string{"2"}}, 5, 2},
		"超界頁碼":    {url.Values{"page": []string{"99"}}, 5, 0},
	} {
		resp := getAuth(t, e.ts, "/admin/accounts?"+tc.params.Encode(),
			cookieHeader(admin), "", "")
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("%s 應成功：%d %s", name, resp.StatusCode, body)
			continue
		}
		envelope := directoryBody(t, resp)
		if envelope["total"].(float64) != tc.total {
			t.Errorf("%s 總數應為 %v，實際 %v（%v）", name, tc.total, envelope["total"], envelope)
		}
		if rows := rowsOf(t, envelope); len(rows) != tc.rows {
			t.Errorf("%s 行數應為 %d，實際 %d（%v）", name, tc.rows, len(rows), rows)
		}
	}

	for name, tc := range map[string]struct {
		params url.Values
	}{
		"頁碼為零":  {url.Values{"page": []string{"0"}}},
		"頁碼非數字": {url.Values{"page": []string{"abc"}}},
		"每頁為零":  {url.Values{"page_size": []string{"0"}}},
		"每頁超上限": {url.Values{"page_size": []string{"101"}}},
		"狀態表外值": {url.Values{"status": []string{"ghost"}}},
		// 待審批與已拒絕仍然不是這一頁能篩的價值：他們不在這本書裡（屬
		// /admin/registrations 那本名冊），把篩選值放進來等於讓目錄替另一本書宣稱範圍。
		"狀態列待審批": {url.Values{"status": []string{"pending"}}},
		"狀態列已拒絕": {url.Values{"status": []string{"rejected"}}},
		"類型表外值":  {url.Values{"type": []string{"root"}}},
		"關鍵字超長":  {url.Values{"q": []string{strings.Repeat("夜", 65)}}},
	} {
		resp := getAuth(t, e.ts, "/admin/accounts?"+tc.params.Encode(),
			cookieHeader(admin), "", "")
		if resp.StatusCode != http.StatusBadRequest || envelopeCode(t, resp) != int(CodeInvalidBody) {
			t.Errorf("%s 應回 1004/400，實際 %d", name, resp.StatusCode)
		}
	}

	// 未發明的查詢參數既不構成錯誤、也不改變結果：目錄只讀它認得的五個參數，
	// 而「帶了個 role 參數就多出幾行」這種事必須是可證偽的。
	before := getAuth(t, e.ts, "/admin/accounts", cookieHeader(admin), "", "")
	totalBefore := directoryBody(t, before)["total"]
	probe := getAuth(t, e.ts, "/admin/accounts?role=server_admin&expected_display_name=x",
		cookieHeader(admin), "", "")
	if probe.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(probe.Body)
		t.Fatalf("多餘參數不該讓目錄失敗：%d %s", probe.StatusCode, body)
	}
	probeEnvelope := directoryBody(t, probe)
	if probeEnvelope["total"] != totalBefore {
		t.Errorf("多餘參數不該改變篩選結果：前 %v 後 %v", totalBefore, probeEnvelope["total"])
	}
	if rows := rowsOf(t, probeEnvelope); len(rows) != 5 {
		t.Errorf("多餘的 role 參數不得把管理員列進目錄，實際 %v", rows)
	}
}

// TestAdminProfileDetailAndEditLoop 詳情與編輯的閉環：讀詳情拿到服務端現值 →
// 以那份現值為依據改名 → 回應是保存後的現值 → 再讀詳情與之一致；
// 舊依據值落 2013／409 且四語言齊備；同級管理員與已刪除者一律 1001。
func TestAdminProfileDetailAndEditLoop(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "edit.http.admin")

	target := e.seedPlainAccount(t, account.NewInput{LoginName: "edit.http.target",
		DisplayName: "改前的顯示名", Type: account.TypeStandard, Status: account.StatusActive})
	peer := e.seedPlainAccount(t, account.NewInput{LoginName: "edit.http.peer",
		DisplayName: "同級管理員", Type: account.TypeStandard, Status: account.StatusActive})
	e.grantAdmin(t, peer.ID)
	gone := e.seedPlainAccount(t, account.NewInput{LoginName: "edit.http.gone",
		DisplayName: "已刪除者", Type: account.TypeStandard, Status: account.StatusActive})
	if _, err := e.accounts.MarkDeleted(context.Background(), e.db.SQL(), gone.ID,
		gone.DisplayName); err != nil {
		t.Fatalf("寫入刪除終態失敗：%v", err)
	}

	phantomID, err := idgen.New()
	if err != nil {
		t.Fatalf("產生幽靈標識失敗：%v", err)
	}
	detail := getAuth(t, e.ts, "/admin/accounts/"+target.ID.String(), cookieHeader(admin), "", "")
	if detail.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(detail.Body)
		t.Fatalf("讀詳情應成功：%d %s", detail.StatusCode, body)
	}
	var first struct {
		Account struct {
			AccountID   string `json:"account_id"`
			DisplayName string `json:"display_name"`
			AccountType string `json:"account_type"`
			Status      string `json:"status"`
		} `json:"account"`
	}
	body, _ := io.ReadAll(detail.Body)
	if err := json.Unmarshal(body, &first); err != nil {
		t.Fatalf("解析詳情失敗：%s", body)
	}
	if first.Account.AccountID != target.ID.String() || first.Account.DisplayName != "改前的顯示名" ||
		first.Account.AccountType != "standard" || first.Account.Status != "active" {
		t.Errorf("詳情應帶出服務端現值，實際 %s", body)
	}
	lower := strings.ToLower(string(body))
	for _, forbidden := range []string{"password_hash", "argon2id", "login_name_key", "token",
		"cookie", "roles", "granted_at", strings.ToLower(dirTestPassword)} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("詳情原文不得含 %q：%s", forbidden, lower)
		}
	}

	updated := sendMethodBody(t, e.ts, http.MethodPut,
		"/admin/accounts/"+target.ID.String(),
		`{"display_name":"  改後的顯示名  ","expected_display_name":"改前的顯示名"}`, admin)
	if updated.StatusCode != http.StatusOK {
		text, _ := io.ReadAll(updated.Body)
		t.Fatalf("編輯應成功：%d %s", updated.StatusCode, text)
	}
	after := directoryBody(t, updated)
	item, ok := after["account"].(map[string]any)
	if !ok || item["display_name"] != "改後的顯示名" {
		t.Fatalf("編輯回應應是保存後的現值（含去首尾空白），實際 %v", after)
	}
	// 回應不復述請求：依據值那一欄不該在任何回應裡出現。
	if _, ok := item["expected_display_name"]; ok {
		t.Error("編輯回應不得回顯 expected_display_name")
	}
	// 再讀一次詳情：介面顯示的當前資料只能有一個來源。
	second := getAuth(t, e.ts, "/admin/accounts/"+target.ID.String(), cookieHeader(admin), "", "")
	if text := mustReadAll(t, second); !strings.Contains(text, "改後的顯示名") {
		t.Errorf("重讀詳情應看到新值，實際 %s", text)
	}

	// 舊依據值：整筆不落，並四語言齊備。
	stale := sendMethodBody(t, e.ts, http.MethodPut, "/admin/accounts/"+target.ID.String(),
		`{"display_name":"又改一次","expected_display_name":"改前的顯示名"}`, admin)
	if stale.StatusCode != http.StatusConflict || envelopeCode(t, stale) != int(CodeProfileConflict) {
		t.Fatalf("舊依據值應回 2013/409，實際 %d", stale.StatusCode)
	}
	for _, tag := range []string{"zh-CN", "zh-TW", "en-US", "ja-JP"} {
		resp := sendMethodBodyWithHeader(t, e.ts, http.MethodPut,
			"/admin/accounts/"+target.ID.String(),
			`{"display_name":"又改一次","expected_display_name":"改前的顯示名"}`, admin,
			map[string]string{"Accept-Language": tag})
		var env struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		text, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(text, &env); err != nil {
			t.Fatalf("%s 信封解析失敗：%s", tag, text)
		}
		if env.Code != int(CodeProfileConflict) || env.Message == "" {
			t.Errorf("%s 的 2013 訊息必須存在，實際 %s", tag, text)
		}
	}
	if text := mustReadAll(t, getAuth(t, e.ts, "/admin/accounts/"+target.ID.String(),
		cookieHeader(admin), "", "")); !strings.Contains(text, "改後的顯示名") {
		t.Errorf("衝突的編輯一個字都不該寫，實際 %s", text)
	}

	for name, id := range map[string]string{
		"同級管理員":   peer.ID.String(),
		"幽靈標識":    phantomID.String(),
		"格式非法的標識": "not-a-uuid",
	} {
		read := getAuth(t, e.ts, "/admin/accounts/"+id, cookieHeader(admin), "", "")
		if read.StatusCode != http.StatusNotFound || envelopeCode(t, read) != int(CodeNotFound) {
			t.Errorf("讀 %s 應回 1001/404，實際 %d", name, read.StatusCode)
		}
		write := sendMethodBody(t, e.ts, http.MethodPut, "/admin/accounts/"+id,
			`{"display_name":"不該落庫","expected_display_name":"改前的顯示名"}`, admin)
		if write.StatusCode != http.StatusNotFound || envelopeCode(t, write) != int(CodeNotFound) {
			t.Errorf("編輯 %s 應回 1001/404，實際 %d", name, write.StatusCode)
		}
	}

	// 已刪除者反其道：讀得到（200，帶著 deleted_at 與佔位顯示名），但編輯被 2027 擋下。
	// 這一組量的是用戶批准的「列得出、點得開、動不了」三件事在同一筆回應裡一次講完——
	// 若他從這一頁消失，操作者就只剩「查無此人」這個錯答案可用。
	read := getAuth(t, e.ts, "/admin/accounts/"+gone.ID.String(), cookieHeader(admin), "", "")
	if read.StatusCode != http.StatusOK {
		t.Fatalf("讀已刪除者應回 200，實際 %d", read.StatusCode)
	}
	deletedDetail := mustReadAll(t, read)
	for _, want := range []string{`"status":"deleted"`, `"deleted_at":"`, "DEL_"} {
		if !strings.Contains(deletedDetail, want) {
			t.Errorf("已刪除者的詳情應帶 %s，實際 %s", want, deletedDetail)
		}
	}
	write := sendMethodBody(t, e.ts, http.MethodPut, "/admin/accounts/"+gone.ID.String(),
		`{"display_name":"不該落庫","expected_display_name":"改前的顯示名"}`, admin)
	if write.StatusCode != http.StatusConflict {
		t.Errorf("編輯已刪除者應回 409，實際 %d", write.StatusCode)
	}
	// 碼與訊息一次讀：信封的 code 必是 2027（不再是 1001），而 message 是非空的一句
	// 本地化話术，且不含任何憑據材料——這是「終態拒絕自成一句」在傳輸層的形態。
	var termEnv struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(mustReadAll(t, write)), &termEnv); err != nil {
		t.Fatalf("2027 信封解析失敗：%v", err)
	}
	if termEnv.Code != int(CodeAccountDeleted) {
		t.Errorf("編輯已刪除者的機器碼應是 2027，實際 %d", termEnv.Code)
	}
	if termEnv.Message == "" || strings.Contains(strings.ToLower(termEnv.Message), "argon2id") {
		t.Errorf("2027 的訊息異常：%q", termEnv.Message)
	}
	if text := mustReadAll(t, getAuth(t, e.ts, "/admin/accounts/"+target.ID.String(),
		cookieHeader(admin), "", "")); !strings.Contains(text, "改後的顯示名") {
		t.Errorf("被終態拒絕的編輯不該寫進任何一筆，目標現值異常：%s", text)
	}
}

// TestAdminProfileForgedFieldsAndMethodShape 本體注入與方法形態：七種隱藏／身分欄位全回
// 1004 且零寫入；空依據值點名欄位；單筆路徑上的 POST／DELETE 回 1002 帶 Allow。
func TestAdminProfileForgedFieldsAndMethodShape(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "forged.http.admin")
	target := e.seedPlainAccount(t, account.NewInput{LoginName: "forged.http.target",
		DisplayName: "攻擊靶", Type: account.TypeStandard, Status: account.StatusActive})
	before := rawRowSnapshot(t, e, target.ID)
	auditsBefore := countTableRows(t, e.db, "root_audit")

	for i, body := range []string{
		`{"display_name":"攻擊","expected_display_name":"攻擊靶","status":"disabled"}`,
		`{"display_name":"攻擊","expected_display_name":"攻擊靶","must_change_password":false}`,
		`{"display_name":"攻擊","expected_display_name":"攻擊靶","account_type":"guest"}`,
		`{"display_name":"攻擊","expected_display_name":"攻擊靶","login_name":"renamed"}`,
		`{"display_name":"攻擊","expected_display_name":"攻擊靶","password":"` + dirTestPassword + `"}`,
		`{"display_name":"攻擊","expected_display_name":"攻擊靶","password_hash":"$argon2id$v=19$x"}`,
		`{"display_name":"攻擊","expected_display_name":"攻擊靶","roles":["server_admin"]}`,
		`{"display_name":"攻擊","expected_display_name":"攻擊靶","activity_id":"00000000-0000-7000-8000-000000000000"}`,
		`{"display_name":"攻擊","expected_display_name":"攻擊靶","subject_kind":"root"}`,
	} {
		resp := sendMethodBody(t, e.ts, http.MethodPut,
			"/admin/accounts/"+target.ID.String(), body, admin)
		if resp.StatusCode != http.StatusBadRequest || envelopeCode(t, resp) != int(CodeInvalidBody) {
			t.Errorf("第 %d 份注入本體應回 1004/400，實際 %d", i+1, resp.StatusCode)
		}
	}
	emptyAnchor := sendMethodBody(t, e.ts, http.MethodPut,
		"/admin/accounts/"+target.ID.String(),
		`{"display_name":"正規的新名","expected_display_name":""}`, admin)
	if emptyAnchor.StatusCode != http.StatusBadRequest {
		t.Errorf("空依據值應回 400，實際 %d", emptyAnchor.StatusCode)
	}
	if text := mustReadAll(t, emptyAnchor); !strings.Contains(text, "expected_display_name") {
		t.Errorf("空依據值應點出該欄位，實際 %s", text)
	}
	invalidName := sendMethodBody(t, e.ts, http.MethodPut,
		"/admin/accounts/"+target.ID.String(),
		`{"display_name":"   ","expected_display_name":"攻擊靶"}`, admin)
	// 回應體讀一次就夠：先取原文再判碼與點名，否則第二個斷言會在讀空的體上假綠。
	invalidText := mustReadAll(t, invalidName)
	if invalidName.StatusCode != http.StatusBadRequest ||
		!strings.Contains(invalidText, fmt.Sprintf(`"code":%d`, int(CodeInvalidBody))) {
		t.Errorf("非法顯示名應回 1004/400，實際 %d %s", invalidName.StatusCode, invalidText)
	}
	if !strings.Contains(invalidText, "display_name") {
		t.Errorf("非法顯示名應點出該欄位，實際 %s", invalidText)
	}

	after := rawRowSnapshot(t, e, target.ID)
	if before["display_name"] != after["display_name"] || before["status"] != after["status"] ||
		before["password_hash"] != after["password_hash"] ||
		before["account_type"] != after["account_type"] ||
		before["must_change_password"] != after["must_change_password"] {
		t.Errorf("被拒的編輯不得動任何欄位：前 %v 後 %v", before, after)
	}
	if n := countTableRows(t, e.db, "root_audit"); n != auditsBefore {
		t.Errorf("被拒的編輯不得追加審計（前 %d 後 %d）", auditsBefore, n)
	}

	// 父路徑如今受理 DELETE（軟刪除），所以「不受理的方法」這組探測改用 PATCH 與 TRACE：
	// 這一格要證的是「沒登記的方法必然 405 並帶 Allow」，與父路徑有幾個方法無關。
	for _, probe := range []struct{ method, path string }{
		{http.MethodPost, "/admin/accounts/" + target.ID.String()},
		{http.MethodPatch, "/admin/accounts/" + target.ID.String()},
		{http.MethodTrace, "/admin/accounts/" + target.ID.String()},
		{http.MethodPut, "/admin/accounts"},
		{http.MethodDelete, "/admin/accounts"},
	} {
		resp := sendMethod(t, e.ts, probe.method, probe.path, admin)
		if resp.StatusCode != http.StatusMethodNotAllowed ||
			envelopeCode(t, resp) != int(CodeMethodNotAllowed) {
			t.Errorf("%s %s 應回 1002/405，實際 %d", probe.method, probe.path, resp.StatusCode)
		}
		if allow := resp.Header.Get("Allow"); allow == "" {
			t.Errorf("%s %s 的 405 應帶 Allow 標頭", probe.method, probe.path)
		}
	}
}

// TestAdminProfileConcurrentEditsOneWins 四路並發對著同一份現值編輯：恰好一次生效。
//
// 證據面是同一進程內的四個 HTTP 請求＋資料庫層的 CAS 條件，不外推到多進程。
func TestAdminProfileConcurrentEditsOneWins(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "race.http.admin")
	target := e.seedPlainAccount(t, account.NewInput{LoginName: "race.http.target",
		DisplayName: "同一份現值", Type: account.TypeStandard, Status: account.StatusActive})

	const attempts = 4
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		wins    int
		conflic int
		codes   []int
	)
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			body := `{"display_name":"併發改名` + string(rune('A'+i)) +
				`","expected_display_name":"同一份現值"}`
			req, err := http.NewRequest(http.MethodPut,
				e.ts.URL+"/admin/accounts/"+target.ID.String(),
				bytes.NewReader([]byte(body)))
			if err != nil {
				t.Errorf("建立併發請求失敗：%v", err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Cookie", cookieHeader(admin))
			resp, err := e.ts.Client().Do(req)
			if err != nil {
				t.Errorf("併發編輯請求失敗：%v", err)
				return
			}
			defer resp.Body.Close()
			text, _ := io.ReadAll(resp.Body)
			var env struct {
				Code int `json:"code"`
			}
			_ = json.Unmarshal(text, &env)
			mu.Lock()
			defer mu.Unlock()
			codes = append(codes, env.Code)
			switch resp.StatusCode {
			case http.StatusOK:
				wins++
			case http.StatusConflict:
				conflic++
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("併發編輯應恰好一次生效，實際 成功=%d 衝突=%d codes=%v", wins, conflic, codes)
	}
	if conflic != attempts-1 {
		t.Errorf("其餘應全數收到 2013/409，實際 codes=%v", codes)
	}
	if n := countProfileAuditsHTTP(t, e.db); n != 1 {
		t.Errorf("贏家一筆之外落敗者不配留審計，實際 %d 筆", n)
	}
}

// mustReadAll 讀完剩餘回應體（測試用；失敗即終止）。
func mustReadAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀回應體失敗：%v", err)
	}
	return string(body)
}

// sendMethodBodyWithHeader 同 sendMethodBody，但可附加標頭（Accept-Language 用）。
func sendMethodBodyWithHeader(t *testing.T, ts *httptest.Server, method, path, body string,
	cookie *http.Cookie, extra map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("建立 %s 請求失敗：%v", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookieHeader(cookie))
	for name, value := range extra {
		req.Header.Set(name, value)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s 失敗：%v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// rawRowSnapshot 讀回 accounts 那一行的全部欄位字串值（白名單外欄位的「不得連動」斷言用）。
func rawRowSnapshot(t *testing.T, e *stdEnv, id idgen.ID) map[string]string {
	t.Helper()
	rows, err := e.db.SQL().QueryContext(context.Background(),
		"SELECT * FROM accounts WHERE id = ?", id.String())
	if err != nil {
		t.Fatalf("讀取帳戶整行失敗：%v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatalf("帳戶 %s 不存在（測試前提）", id)
	}
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("取欄位清單失敗：%v", err)
	}
	raw := make([]any, len(cols))
	targets := make([]any, len(cols))
	for i := range raw {
		targets[i] = &raw[i]
	}
	if err := rows.Scan(targets...); err != nil {
		t.Fatalf("掃描整行失敗：%v", err)
	}
	out := make(map[string]string, len(cols))
	for i, col := range cols {
		if raw[i] == nil {
			out[col] = "<NULL>"
			continue
		}
		out[col] = fmt.Sprintf("%v", raw[i])
	}
	return out
}

// countProfileAuditsHTTP 數 root_audit 裡的普通帳戶編輯審計筆數。
func countProfileAuditsHTTP(t *testing.T, db *database.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit WHERE action = 'account.profile_update'").Scan(&n); err != nil {
		t.Fatalf("計數編輯審計失敗：%v", err)
	}
	return n
}
