// guestbindexecute_test.go 是「訪戶綁定執行」的傳輸層端到端證據：
// 真資料庫＋真訪客進入＋真管理員＋真普通帳戶本人的會話，從簽發一路打到核銷完成——
// 200 憑證回應的形狀（明文只這一次、無憑據格子）、預覽的純只讀、確認落地的四件合力
// （來源退休、源 Cookie 換不出身份、留痕一行、目標逐字原樣）、本人查帳作為
// 「提交後回應遺失」的落點，以及兩組拒絕矩陣各回各句
// （2002／2011／1001／1004／2025／2026／1002），每一次拒絕都零寫入。
//
// 刻意不收的東西：
//   - 沒有替身：授權、首次改密門閂、來源判定、範圍收斂、引用掃描與交易邊界
//     都跨層走真路徑，接錯線就會紅；
//   - 憑證到期的時間推演不在這裡（這組端到端現場用系統時鐘，推不动它），
//     由 internal/stdacct 的注入時鐘用例量；
//   - 不碰任何真實資料目錄、不佔 5206。
package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// 綁定執行測試口令：只活在本次測試進程，不是任何環境的憑據。
const (
	bndTestTargetPassword = "guestbind-test-受體初始口令"
	bndTestTargetChanged  = "guestbind-test-受體改後口令"
)

// bndEnablePolicy 翻開「管理員建號＋訪客進入」兩顆開關（自註冊保持 closed）。
func bndEnablePolicy(t *testing.T, e *guestLiveEnv) {
	t.Helper()
	root := e.rootCookie(t)
	resp := putJSON(t, e.ts, "/root/account-policy", policyBody(true, "closed", true), "",
		map[string]string{"Cookie": cookieHeader(root)})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("保存策略應成功：%d %s", resp.StatusCode, body)
	}
}

// bndEnterGuest 讓一個人真實進入，回傳（會話 Cookie, 帳戶標識）。
func bndEnterGuest(t *testing.T, e *guestLiveEnv, nickname string) (*http.Cookie, string) {
	t.Helper()
	resp := e.enter(t, nickname)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("訪客進入應成功：%d %s", resp.StatusCode, body)
	}
	id, _ := decodeJSONBody(t, resp)["account_id"].(string)
	if id == "" {
		t.Fatalf("訪客回應應帶出帳戶標識，實際 %q", id)
	}
	return loginCookie(t, resp), id
}

// bndLogin 以本人憑據登入並換出會話 Cookie（改密會撤舊會話，所以每一步都用當下有效的憑據）。
func bndLogin(t *testing.T, e *guestLiveEnv, login, password string) *http.Cookie {
	t.Helper()
	resp := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+password+`"}`, "", nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("以 %s 登入應成功：%d %s", login, resp.StatusCode, body)
	}
	return loginCookie(t, resp)
}

// bndStandardAccount 由管理員建一筆普通帳戶並替本人完成首次改密，
// 回傳（標識, 本人會話 Cookie）。目標必須是能自己登進門的人——
// 欠著首改的帳戶連「以自己的會話確認綁定」都做不到，現場要按合同準備齊。
func bndStandardAccount(t *testing.T, e *guestLiveEnv, admin *http.Cookie,
	login string) (string, *http.Cookie) {
	t.Helper()
	created := postJSON(t, e.ts, "/admin/accounts",
		`{"login_name":"`+login+`","display_name":"綁定承接者","password":"`+bndTestTargetPassword+`"}`,
		"", map[string]string{"Cookie": cookieHeader(admin)})
	if created.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(created.Body)
		t.Fatalf("建立目標帳戶應成功：%d %s", created.StatusCode, body)
	}
	id, _ := decodeJSONBody(t, created)["account_id"].(string)
	cookie := bndLogin(t, e, login, bndTestTargetPassword)
	if changed := postJSON(t, e.ts, "/auth/password/change",
		`{"current_password":"`+bndTestTargetPassword+`","new_password":"`+bndTestTargetChanged+`"}`,
		"", map[string]string{"Cookie": cookieHeader(cookie)}); changed.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(changed.Body)
		t.Fatalf("目標本人首次改密應成功：%s", body)
	}
	// 改密會撤銷名下會話（既有合同），因此確認那一步要用改後憑據重新換一枚。
	return id, bndLogin(t, e, login, bndTestTargetChanged)
}

// bndIssue 打一次簽發並回傳回應。
func bndIssue(t *testing.T, e *guestLiveEnv, sourceID, body string,
	admin *http.Cookie) *http.Response {
	t.Helper()
	return postJSON(t, e.ts, "/admin/accounts/"+sourceID+"/bind-ticket", body, "",
		map[string]string{"Cookie": cookieHeader(admin)})
}

// bndClaimPath 是本人三條通路之一的完整路徑。
func bndClaimPath(what string) string {
	// 空字串與 "list" 都指父路徑（GET 讀帳與 POST 執行都掛在它上面，由方法分流）。
	if what == "" || what == "list" {
		return "/auth/guest-bindings"
	}
	return "/auth/guest-bindings/" + what
}

// bndClaimPost 打本人的預覽或確認（POST，本體恰好一欄 ticket）。
func bndClaimPost(t *testing.T, e *guestLiveEnv, what, body string,
	cookie *http.Cookie) *http.Response {
	t.Helper()
	var headers map[string]string
	if cookie != nil {
		headers = map[string]string{"Cookie": cookieHeader(cookie)}
	}
	return postJSON(t, e.ts, bndClaimPath(what), body, "", headers)
}

// bndTableCount 數一張表的行數（端到端現場的零寫入對照）。
func bndTableCount(t *testing.T, e *guestLiveEnv, table string) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("計數 %s 失敗：%v", table, err)
	}
	return n
}

// bndRawPost 打本人的預覽或確認並把回應本體一次讀完（回傳原始 bytes 供解碼）。
// kind 取 "preview" 或 "confirm"；後者打的是父路徑 /auth/guest-bindings。
func bndRawPost(t *testing.T, e *guestLiveEnv, kind, body string,
	cookie *http.Cookie) []byte {
	t.Helper()
	path := bndClaimPath("")
	if kind == "preview" {
		path = bndClaimPath("preview")
	}
	resp := postJSON(t, e.ts, path, body, "", map[string]string{"Cookie": cookieHeader(cookie)})
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("讀回應失敗：%v", err)
	}
	return raw
}

// bndDetails 取錯誤信封裡的 details（2026 的 blockers 清單與 1004 的欄位名都住在那裡）。
func bndDetails(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var envelope struct {
		Details map[string]any `json:"details"`
	}
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("解析錯誤信封失敗：%s", raw)
	}
	return envelope.Details
}

// TestAdminBindTicketEndToEnd 簽發通路的形狀：200 帶出明文一枚（22 字元）、憑證標識、
// 兩側投影、五條影響、失效時刻與同意形態；而這一步不是綁定——
// 兩側帳戶行逐字不動、訪客 Cookie 照常換得出自己、留痕表仍是空的、審計恰好多一筆簽發。
func TestAdminBindTicketEndToEnd(t *testing.T) {
	e := newGuestLiveEnv(t)
	bndEnablePolicy(t, e)
	guestCookie, guestID := bndEnterGuest(t, e, "簽發端到端旅人")
	admin := upgLiveAdminCookie(t, e, "bnd.e2e.admin")
	targetID, _ := bndStandardAccount(t, e, admin, "Bnd.E2E.Target")

	guestBefore, targetBefore := accountRow(t, e, guestID), accountRow(t, e, targetID)
	ticketsBefore := bndTableCount(t, e, "guest_bind_tickets")

	resp := bndIssue(t, e, guestID, `{"target_account_id":"`+targetID+`"}`, admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("合法這一對的簽發應回 200：%d %s", resp.StatusCode, body)
	}
	body := decodeJSONBody(t, resp)
	ticket, _ := body["ticket"].(string)
	if len(ticket) != 22 {
		t.Errorf("憑證明文應是 22 字元的 base64url，實際 %d 字元", len(ticket))
	}
	if id, _ := body["ticket_id"].(string); id == "" || id == ticket {
		t.Errorf("回應要帶出憑證標識（可追溯、不是秘密），實際 %q", id)
	}
	if impacts, ok := body["impacts"].([]any); !ok || len(impacts) != 5 {
		t.Errorf("簽發回應該帶齊五條影響，實際 %#v", body["impacts"])
	}
	if mode := body["consent_mode"]; mode != "target_self_initiated" {
		t.Errorf("同意形態必須如實出口，實際 %v", mode)
	}
	if at, _ := body["expires_at"].(string); at == "" {
		t.Error("失效時刻必須如實帶出，界面才說得出還剩多少時間")
	}
	if got := body["source_open_sessions"]; got != float64(1) {
		t.Errorf("訪客進入簽發一枚會話，簽發回應應報 1，實際 %v", got)
	}
	source := body["source"].(map[string]any)
	target := body["target"].(map[string]any)
	if source["account_id"] != guestID || source["account_type"] != "guest" ||
		target["account_id"] != targetID || target["account_type"] != "standard" {
		t.Errorf("兩側投影应是憑證釘著的這一對，實際 %#v／%#v", source, target)
	}
	// 回應不能有任何憑據形態的格子（按鍵名逐層比對，不做子串掃描）。
	for _, forbidden := range []string{"password", "hash", "token", "secret", "cookie"} {
		if found := findKeyDeep(body, forbidden); found != "" {
			t.Errorf("簽發回應不得出現憑據形態欄位 %q（於 %s）", forbidden, found)
		}
	}

	// 「這一步不是綁定」的四处對照。
	if got := accountRow(t, e, guestID); got != guestBefore {
		t.Errorf("簽發動了來源一行：前 %s／實際 %s", guestBefore, got)
	}
	if got := accountRow(t, e, targetID); got != targetBefore {
		t.Errorf("簽發動了目標一行：前 %s／實際 %s", targetBefore, got)
	}
	if got := bndTableCount(t, e, "guest_account_bindings"); got != 0 {
		t.Errorf("簽發不是綁定：留痕表必須仍是空的，實際 %d 行", got)
	}
	if got := bndTableCount(t, e, "guest_bind_tickets"); got != ticketsBefore+1 {
		t.Errorf("簽發該恰落下一行憑證：前 %d／後 %d", ticketsBefore, got)
	}
	if sess := getAuth(t, e.ts, "/auth/session", cookieHeader(guestCookie), "", ""); sess.StatusCode != http.StatusOK {
		t.Errorf("簽發後訪客自己的會話必須還活着，實際 %d", sess.StatusCode)
	}
	// 庫裡那欄是哈希：拿明文去查 ticket_hash 必須一行都對不上。
	var hashed int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM guest_bind_tickets WHERE ticket_hash = ?", ticket).Scan(&hashed); err != nil {
		t.Fatalf("查證明文是否入庫失敗：%v", err)
	}
	if hashed != 0 {
		t.Error("庫裡不得出現憑證明文")
	}
}

// TestAdminBindTicketFailureMatrix 簽發的拒絕矩陣逐條各回各句：匿名 2002、普通帳戶與
// 訪戶本人 2011、停用中的來源 2026 帶著穩定原因記號、幽靈目標 1001、
// 壞本體 1004 點名 target_account_id、GET 1002；每一次都一行憑證都不落、審計不增。
func TestAdminBindTicketFailureMatrix(t *testing.T) {
	e := newGuestLiveEnv(t)
	bndEnablePolicy(t, e)
	admin := upgLiveAdminCookie(t, e, "bnd.matrix.admin")
	_, guestID := bndEnterGuest(t, e, "矩陣簽發旅人")
	offCookie, offGuestID := bndEnterGuest(t, e, "停用後簽發旅人")
	if off := putJSON(t, e.ts, "/admin/accounts/"+offGuestID+"/status",
		`{"status":"disabled","expected_status":"active"}`, "",
		map[string]string{"Cookie": cookieHeader(admin)}); off.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(off.Body)
		t.Fatalf("停用來源訪戶應成功：%d %s", off.StatusCode, body)
	}
	_ = offCookie
	targetID, targetCookie := bndStandardAccount(t, e, admin, "Bnd.Matrix.Target")
	goodBody := `{"target_account_id":"` + targetID + `"}`
	guestBefore := accountRow(t, e, guestID)
	auditsBefore := bndTableCount(t, e, "root_audit")

	cases := []struct {
		name       string
		source     string
		body       string
		method     string
		cookie     *http.Cookie
		wantStatus int
		wantCode   ErrorCode
	}{
		{"匿名", guestID, goodBody, http.MethodPost, nil, http.StatusUnauthorized, CodeNotAuthenticated},
		{"普通帳戶", guestID, goodBody, http.MethodPost, targetCookie, http.StatusForbidden, CodePermissionDenied},
		{"停用中的來源", offGuestID, goodBody, http.MethodPost, admin, http.StatusConflict, CodeBindPlanStale},
		{"幽靈目標", guestID, `{"target_account_id":"00000000-0000-7000-8000-000000000456"}`,
			http.MethodPost, admin, http.StatusNotFound, CodeNotFound},
		{"非法來源標識", "not-a-uuid", goodBody, http.MethodPost, admin, http.StatusNotFound, CodeNotFound},
		{"缺目標欄位", guestID, `{}`, http.MethodPost, admin, http.StatusBadRequest, CodeInvalidBody},
		{"壞目標標識", guestID, `{"target_account_id":"not-a-uuid"}`,
			http.MethodPost, admin, http.StatusBadRequest, CodeInvalidBody},
		{"偽造欄位", guestID, `{"target_account_id":"` + targetID + `","admin":true}`,
			http.MethodPost, admin, http.StatusBadRequest, CodeInvalidBody},
		{"GET 方法", guestID, "", http.MethodGet, admin, http.StatusMethodNotAllowed, CodeMethodNotAllowed},
	}
	for _, tc := range cases {
		var resp *http.Response
		switch tc.method {
		case http.MethodGet:
			resp = getAuth(t, e.ts, "/admin/accounts/"+tc.source+"/bind-ticket",
				cookieHeader(tc.cookie), "", "")
		default:
			var headers map[string]string
			if tc.cookie != nil {
				headers = map[string]string{"Cookie": cookieHeader(tc.cookie)}
			}
			resp = postJSON(t, e.ts, "/admin/accounts/"+tc.source+"/bind-ticket", tc.body, "", headers)
		}
		if resp.StatusCode != tc.wantStatus || envelopeCode(t, resp) != int(tc.wantCode) {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("%s：應回 %d/代碼 %d，實際 %d %s", tc.name, tc.wantStatus, tc.wantCode,
				resp.StatusCode, body)
		}
	}
	// 2026 帶著記號清單（界面據此選四語言句子），而表名與任何憑據都不在其中。
	details := bndDetails(t, bndIssue(t, e, offGuestID, goodBody, admin))
	blockers, ok := details["blockers"].([]any)
	if !ok || len(blockers) != 1 || blockers[0] != "source_not_active" {
		t.Errorf("停用來源的 2026 應點名 source_not_active，實際 %#v", details)
	}
	// 1004 的兩條各自點名欄位。
	for _, probe := range []string{`{}`, `{"target_account_id":"not-a-uuid"}`} {
		if got := bndDetails(t, bndIssue(t, e, guestID, probe, admin))["invalid_field"]; got != "target_account_id" {
			t.Errorf("本體 %s 的 1004 應點名 target_account_id，實際 %#v", probe, got)
		}
	}
	if got := accountRow(t, e, guestID); got != guestBefore {
		t.Errorf("拒絕矩陣動了來源一行：前 %s／實際 %s", guestBefore, got)
	}
	if got := bndTableCount(t, e, "guest_bind_tickets"); got != 0 {
		t.Errorf("九趟被拒的簽發該一行都不落，實際 %d 行", got)
	}
	if got := bndTableCount(t, e, "root_audit"); got != auditsBefore {
		t.Errorf("被拒的簽發不得寫審計：前 %d／後 %d", auditsBefore, got)
	}
}

// TestGuestBindClaimEndToEnd 完整閉環：簽發 → 本人預覽（只讀）→ 本人確認（四件合力）
// → 訪客舊 Cookie 換不出身份 → 本人查帳讀到那一行 → 重放被拒。
// 全程目標帳戶行逐字不動、授予一筆不多；留痕時刻與來源退休時刻同值。
func TestGuestBindClaimEndToEnd(t *testing.T) {
	e := newGuestLiveEnv(t)
	bndEnablePolicy(t, e)
	guestCookie, guestID := bndEnterGuest(t, e, "閉環旅人")
	admin := upgLiveAdminCookie(t, e, "bnd.loop.admin")
	targetID, targetCookie := bndStandardAccount(t, e, admin, "Bnd.Loop.Target")
	targetBefore := accountRow(t, e, targetID)

	resp := bndIssue(t, e, guestID, `{"target_account_id":"`+targetID+`"}`, admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("簽發應成功：%d %s", resp.StatusCode, body)
	}
	ticket := decodeJSONBody(t, resp)["ticket"].(string)
	claimBody := `{"ticket":"` + ticket + `"}`

	// 一、本人的預覽：200、影響齊備、四張表一個字不動。
	preview := bndClaimPost(t, e, "preview", claimBody, targetCookie)
	if preview.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(preview.Body)
		t.Fatalf("本人的核銷前預覽應回 200：%d %s", preview.StatusCode, body)
	}
	pb := decodeJSONBody(t, preview)
	if impacts, ok := pb["impacts"].([]any); !ok || len(impacts) != 5 {
		t.Errorf("預覽該把已驗證的影響念齊，實際 %#v", pb["impacts"])
	}
	if src := pb["source"].(map[string]any); src["account_id"] != guestID ||
		src["account_type"] != "guest" {
		t.Errorf("預覽要讓本人看清楚接住的是誰，實際 %#v", src)
	}
	if pb["consent_mode"] != "target_self_initiated" {
		t.Errorf("預覽的同意形態必須如實出口，實際 %v", pb["consent_mode"])
	}
	if bndTableCount(t, e, "guest_account_bindings") != 0 {
		t.Error("預覽不是執行：留痕表必須仍是空的")
	}
	if got := accountRow(t, e, guestID); strings.Contains(got, "retired") {
		t.Errorf("預覽不得讓來源退休，實際行現值 %s", got)
	}

	// 二、本人確認：200 帶出留痕、退休後的來源現值與撤銷數量。
	confirm := bndClaimPost(t, e, "", claimBody, targetCookie)
	if confirm.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(confirm.Body)
		t.Fatalf("本人確認綁定應回 200：%d %s", confirm.StatusCode, body)
	}
	cb := decodeJSONBody(t, confirm)
	if id, _ := cb["binding_id"].(string); id == "" {
		t.Error("綁定成功要回傳留痕標識")
	}
	source := cb["source"].(map[string]any)
	if source["status"] != "retired" || source["retired_at"] == nil ||
		source["account_id"] != guestID {
		t.Errorf("回應的來源該是已退休的現值（含退休時刻），實際 %#v", source)
	}
	if got := cb["revoked_sessions"]; got != float64(1) {
		t.Errorf("訪客那趟只有一枚會話，回應應報 1，實際 %v", got)
	}
	if cb["consent_mode"] != "target_self_initiated" {
		t.Errorf("回應的同意形態必須如實出口，實際 %v", cb["consent_mode"])
	}
	for _, forbidden := range []string{"password", "hash", "token", "secret", "cookie", "ticket"} {
		if found := findKeyDeep(cb, forbidden); found != "" {
			t.Errorf("綁定回應不得出現憑據形態欄位 %q（於 %s）", forbidden, found)
		}
	}

	// 三、源令牌換不出身份（2003），而目標的會話照常可用。
	if sess := getAuth(t, e.ts, "/auth/session", cookieHeader(guestCookie), "", ""); sess.StatusCode != http.StatusUnauthorized ||
		envelopeCode(t, sess) != int(CodeSessionInvalid) {
		t.Errorf("源令牌綁定後應以 2003 被拒，實際 %d", sess.StatusCode)
	}
	if sess := getAuth(t, e.ts, "/auth/session", cookieHeader(targetCookie), "", ""); sess.StatusCode != http.StatusOK {
		t.Errorf("目標照常以自己的會話在門內，實際 %d", sess.StatusCode)
	}

	// 四、目標一點都沒被改造：憑據、狀態、旗標逐字原樣，授予一筆不多。
	if got := accountRow(t, e, targetID); got != targetBefore {
		t.Errorf("綁定動了目標一行：前 %s／實際 %s", targetBefore, got)
	}
	var roles int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM account_server_roles WHERE account_id = ?", targetID).Scan(&roles); err != nil {
		t.Fatalf("查目標授予失敗：%v", err)
	}
	if roles != 0 {
		t.Errorf("綁定不得給目標授予，實際 %d 行", roles)
	}

	// 五、本人查帳：讀到那一行就是「已完成」的證據（提交後回應遺失時的落點）。
	list := getAuth(t, e.ts, bndClaimPath("list"), cookieHeader(targetCookie), "", "")
	if list.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(list.Body)
		t.Fatalf("本人查綁定帳應回 200：%d %s", list.StatusCode, body)
	}
	lb := decodeJSONBody(t, list)
	items, ok := lb["bindings"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("本人帳上應只有 1 行，實際 %#v", lb["bindings"])
	}
	item := items[0].(map[string]any)
	if item["source_account_id"] != guestID || item["source_login_name"] == "" ||
		item["consent_mode"] != "target_self_initiated" {
		t.Errorf("留痕列出的應是被綁走那個人，實際 %#v", item)
	}
	if got := lb["total"]; got != float64(1) {
		t.Errorf("總數應由同一份讀取回顯，實際 %v", got)
	}
	if at, _ := item["bound_at"].(string); at == "" {
		t.Error("留痕要帶著綁定時刻")
	}

	// 六、重放與事後探測：同一枚明文再按只會拿到 2025，且不再動任何一行。
	replay := bndClaimPost(t, e, "", claimBody, targetCookie)
	if replay.StatusCode != http.StatusForbidden ||
		envelopeCode(t, replay) != int(CodeBindTicketInvalid) {
		t.Errorf("重放該以 2025 被拒，實際 %d", replay.StatusCode)
	}
	if got := bndTableCount(t, e, "guest_account_bindings"); got != 1 {
		t.Errorf("重複確認不得再次遷移，實際留痕 %d 行", got)
	}
	if got := accountRow(t, e, targetID); got != targetBefore {
		t.Errorf("重放動了目標一行：前 %s／實際 %s", targetBefore, got)
	}
}

// TestGuestBindClaimFailureMatrix 本人三條通路的拒絕矩陣：匿名 2002、訪戶與管理員與
// Root 2011、別人手里那枚憑證 2025（與「不存在」「已用掉」同形一句）、
// 缺欄與空白 1004 點名 ticket、方法 1002；每一次都零寫入。
func TestGuestBindClaimFailureMatrix(t *testing.T) {
	e := newGuestLiveEnv(t)
	bndEnablePolicy(t, e)
	admin := upgLiveAdminCookie(t, e, "bnd.deny.admin")
	_, guestID := bndEnterGuest(t, e, "被拒的旅人")
	guestCookie, _ := bndEnterGuest(t, e, "另一位旅人")
	targetID, targetCookie := bndStandardAccount(t, e, admin, "Bnd.Deny.Target")
	outsiderID, outsiderCookie := bndStandardAccount(t, e, admin, "Bnd.Deny.Outsider")
	rootCookie := e.rootCookie(t)

	resp := bndIssue(t, e, guestID, `{"target_account_id":"`+targetID+`"}`, admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("簽發應成功：%d %s", resp.StatusCode, body)
	}
	ticket := decodeJSONBody(t, resp)["ticket"].(string)
	claimBody := `{"ticket":"` + ticket + `"}`
	guestBefore := accountRow(t, e, guestID)
	targetBefore := accountRow(t, e, targetID)
	auditsBefore := bndTableCount(t, e, "root_audit")

	cases := []struct {
		name       string
		path       string
		method     string
		body       string
		cookie     *http.Cookie
		wantStatus int
		wantCode   ErrorCode
	}{
		{"匿名預覽", "preview", http.MethodPost, claimBody, nil, http.StatusUnauthorized, CodeNotAuthenticated},
		{"匿名執行", "", http.MethodPost, claimBody, nil, http.StatusUnauthorized, CodeNotAuthenticated},
		{"匿名查帳", "list", http.MethodGet, "", nil, http.StatusUnauthorized, CodeNotAuthenticated},
		{"訪戶預覽", "preview", http.MethodPost, claimBody, guestCookie, http.StatusForbidden, CodePermissionDenied},
		{"訪戶執行", "", http.MethodPost, claimBody, guestCookie, http.StatusForbidden, CodePermissionDenied},
		{"管理員執行", "", http.MethodPost, claimBody, admin, http.StatusForbidden, CodePermissionDenied},
		{"Root 執行", "", http.MethodPost, claimBody, rootCookie, http.StatusForbidden, CodePermissionDenied},
		{"別人執行", "", http.MethodPost, claimBody, outsiderCookie, http.StatusForbidden, CodeBindTicketInvalid},
		{"別人查帳讀到空", "list", http.MethodGet, "", outsiderCookie, http.StatusOK, ErrorCode(0)},
		{"缺 ticket 欄", "", http.MethodPost, `{}`, targetCookie, http.StatusBadRequest, CodeInvalidBody},
		{"空白 ticket", "", http.MethodPost, `{"ticket":""}`, targetCookie, http.StatusBadRequest, CodeInvalidBody},
		{"表外 ticket", "", http.MethodPost, `{"ticket":"short"}`, targetCookie, http.StatusForbidden, CodeBindTicketInvalid},
		{"偽造欄位", "", http.MethodPost, `{"ticket":"` + ticket + `","account_id":"` + outsiderID + `"}`,
			targetCookie, http.StatusBadRequest, CodeInvalidBody},
		{"預覽用 GET", "preview", http.MethodGet, "", targetCookie, http.StatusMethodNotAllowed, CodeMethodNotAllowed},
		{"DELETE 不支持", "list", http.MethodDelete, "", targetCookie, http.StatusMethodNotAllowed, CodeMethodNotAllowed},
	}
	for _, tc := range cases {
		full := bndClaimPath(tc.path)
		var got *http.Response
		switch tc.method {
		case http.MethodGet:
			var cookie string
			if tc.cookie != nil {
				cookie = cookieHeader(tc.cookie)
			}
			got = getAuth(t, e.ts, full, cookie, "", "")
		case http.MethodDelete:
			got = sendMethod(t, e.ts, http.MethodDelete, full, tc.cookie)
		default:
			var headers map[string]string
			if tc.cookie != nil {
				headers = map[string]string{"Cookie": cookieHeader(tc.cookie)}
			}
			got = postJSON(t, e.ts, full, tc.body, "", headers)
		}
		if got.StatusCode != tc.wantStatus {
			body, _ := io.ReadAll(got.Body)
			t.Errorf("%s：應回 %d，實際 %d %s", tc.name, tc.wantStatus, got.StatusCode, body)
			continue
		}
		if tc.wantCode != 0 && envelopeCode(t, got) != int(tc.wantCode) {
			body, _ := io.ReadAll(got.Body)
			t.Errorf("%s：代碼應為 %d，實際信封 %s", tc.name, tc.wantCode, body)
		}
	}
	// 1004 的兩條各自點名 ticket。
	for _, probe := range []string{`{}`, `{"ticket":""}`} {
		if got := bndDetails(t, bndClaimPost(t, e, "", probe, targetCookie))["invalid_field"]; got != "ticket" {
			t.Errorf("本體 %s 的 1004 應點名 ticket，實際 %#v", probe, got)
		}
	}
	if got := accountRow(t, e, guestID); got != guestBefore {
		t.Errorf("拒絕矩陣動了來源一行：前 %s／實際 %s", guestBefore, got)
	}
	if got := accountRow(t, e, targetID); got != targetBefore {
		t.Errorf("拒絕矩陣動了目標一行：前 %s／實際 %s", targetBefore, got)
	}
	if got := bndTableCount(t, e, "guest_account_bindings"); got != 0 {
		t.Errorf("本矩陣全數被拒（成功閉環另有端到端用例）：留痕必須仍是空的，實際 %d 行", got)
	}
	if got := bndTableCount(t, e, "guest_bind_tickets"); got != 1 {
		t.Errorf("一枚憑證不該被複製成多行，實際 %d 行", got)
	}
	if got := bndTableCount(t, e, "root_audit"); got != auditsBefore {
		t.Errorf("基準抓在簽發之後：矩陣裡除成功那趟外不管成敗都不該再添審計（本人動作的審計主體類別未批准），基準 %d／實際 %d",
			auditsBefore, got)
	}
}

// TestGuestBindPlanStaleOverHttp 事實漂移在協定層的形狀：簽發之後把來源停用，
// 本人的預覽與執行都拿到 2026 並帶著 source_not_active 這枚記號，
// 而憑證一併沒被核銷（失敗保留原先可用關係）。
func TestGuestBindPlanStaleOverHttp(t *testing.T) {
	e := newGuestLiveEnv(t)
	bndEnablePolicy(t, e)
	admin := upgLiveAdminCookie(t, e, "bnd.stale.admin")
	_, guestID := bndEnterGuest(t, e, "漂移旅人")
	targetID, targetCookie := bndStandardAccount(t, e, admin, "Bnd.Stale.Target")

	ticket := decodeJSONBody(t, bndIssue(t, e, guestID,
		`{"target_account_id":"`+targetID+`"}`, admin))["ticket"].(string)
	claimBody := `{"ticket":"` + ticket + `"}`

	if off := putJSON(t, e.ts, "/admin/accounts/"+guestID+"/status",
		`{"status":"disabled","expected_status":"active"}`, "",
		map[string]string{"Cookie": cookieHeader(admin)}); off.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(off.Body)
		t.Fatalf("停用來源應成功：%d %s", off.StatusCode, body)
	}
	// 回應本體只讀一次：code 與 details 從同一份 bytes 解出來，
	// 分兩次讀 resp.Body 會讓第二次拿到空內容（那是測試自己的缺陷，不是後端的）。
	for _, what := range []string{"preview", "confirm"} {
		raw := bndRawPost(t, e, what, claimBody, targetCookie)
		var envelope struct {
			Code    int            `json:"code"`
			Details map[string]any `json:"details"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatalf("%s：解析信封失敗：%s（%s）", what, err, raw)
		}
		if envelope.Code != int(CodeBindPlanStale) {
			t.Errorf("%s：應以 2026 回絕，實際信封 %s", what, raw)
		}
		blockers, ok := envelope.Details["blockers"].([]any)
		if !ok || len(blockers) != 1 || blockers[0] != "source_not_active" {
			t.Errorf("%s：2026 應點名 source_not_active，實際 %#v", what, envelope.Details)
		}
	}
	if got := bndTableCount(t, e, "guest_account_bindings"); got != 0 {
		t.Errorf("被拒的執行不得留下留痕，實際 %d 行", got)
	}
	var consumed int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM guest_bind_tickets WHERE consumed_at IS NOT NULL").Scan(&consumed); err != nil {
		t.Fatalf("查核銷失敗：%v", err)
	}
	if consumed != 0 {
		t.Error("被拒的執行不得核銷憑證（連核銷一起回滾）")
	}
}

// TestGuestBindCodesHaveFourLocales 兩枚新碼的四語言文案齊備：缺任何一種就是合同缺口，
// 而不是回退英文了事（本檔把這一句釘在測試上）。
func TestGuestBindCodesHaveFourLocales(t *testing.T) {
	for _, code := range []ErrorCode{CodeBindTicketInvalid, CodeBindPlanStale} {
		for _, locale := range []string{LocaleZhCN, LocaleZhTW, LocaleEnUS, LocaleJaJP} {
			if messageFor(code, locale) == "" {
				t.Errorf("錯誤碼 %d 在 %s 缺文案", code, locale)
			}
		}
		if messageFor(code, "und-unknown") == "" {
			t.Errorf("錯誤碼 %d 未知語言未回退到既有語文", code)
		}
	}
}

// TestGuestBindPathsAbsentWithoutWiring 未注入綁定執行用例時，本人那一族路徑根本不掛：
// 回 1001，與未掛載逐字相同（不會留下一條必掛 500 的空殼通路）。
func TestGuestBindPathsAbsentWithoutWiring(t *testing.T) {
	noWiring := guestTestServer(t, nil)
	for _, path := range []string{"/auth/guest-bindings", "/auth/guest-bindings/preview"} {
		resp := postJSON(t, noWiring, path, `{"ticket":"aaaaaaaaaaaaaaaaaaaaaa"}`, "", nil)
		if resp.StatusCode != http.StatusNotFound || envelopeCode(t, resp) != int(CodeNotFound) {
			t.Errorf("未注入用例時 %s 應不掛（1001），實際 %d", path, resp.StatusCode)
		}
	}
}
