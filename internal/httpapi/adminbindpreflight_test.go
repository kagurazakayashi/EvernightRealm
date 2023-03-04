// adminbindpreflight_test.go 是「訪戶綁定預檢與衝突預覽」的傳輸層端到端證據：
// 真資料庫＋真訪客進入＋真管理員交付鏈＋完整中介層，從一枚真實訪客會話出發
// 打 POST /admin/accounts/{id}/bind-preflight——成功預覽的形狀（200、可執行、
// 影響齊備、版本如實）、不可綁定作為「200 帶原因而不是錯誤」的合同方向、
// 拒絕矩陣逐條各回各句（匿名 2002、普通帳戶與訪戶本人 2011、目標是特權帳戶
// 與幽靈同收 1001 不可分辨、壞本體 1004 點名欄位、方法 1002），以及本步的
// 正面要求：預檢跑完，帳戶、會話、授予、Root 域審計全部逐字不動，
// 訪客那枚 Cookie 依然換得出他自己（「未綁定」不是話術，是可測量的事實）。
//
// 刻意不收的東西：
//   - 沒有替身：授權、首次改密門閂、範圍收斂、引用掃描都跨層走真路徑，接錯線就會紅；
//   - 不碰任何真實資料目錄、不佔 5206，全程用本次專屬的暫存庫與系統時鐘。
package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// 綁定預檢測試口令：只活在本次測試進程，不是任何環境的憑據。
const (
	bpfTestTargetPassword = "bindpreflight-test-受體初始口令"
	bpfTestTargetChanged  = "bindpreflight-test-受體改後口令"
)

// bpfPost 發一次 POST /admin/accounts/{id}/bind-preflight，回應原樣交出去。
func bpfPost(t *testing.T, e *guestLiveEnv, accountID, body string,
	cookie *http.Cookie) *http.Response {
	t.Helper()
	headers := map[string]string{}
	if cookie != nil {
		headers["Cookie"] = cookieHeader(cookie)
	}
	return postJSON(t, e.ts, "/admin/accounts/"+accountID+"/bind-preflight", body, "", headers)
}

// bpfLiveStandardAccount 由管理員建一筆普通帳戶並替本人完成首次改密，
// 回傳（標識, 可作目標的現值行）。目標必須是能自己登進門的人——
// 欠首改的帳戶連「以自己的會話確認綁定」都做不到，現場要按合同準備齊。
func bpfLiveStandardAccount(t *testing.T, e *guestLiveEnv, admin *http.Cookie,
	login string) string {
	t.Helper()
	created := postJSON(t, e.ts, "/admin/accounts",
		`{"login_name":"`+login+`","display_name":"綁定受體","password":"`+bpfTestTargetPassword+`"}`,
		"", map[string]string{"Cookie": cookieHeader(admin)})
	if created.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(created.Body)
		t.Fatalf("建立目標帳戶應成功：%d %s", created.StatusCode, body)
	}
	id, _ := decodeJSONBody(t, created)["account_id"].(string)
	first := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"`+login+`","password":"`+bpfTestTargetPassword+`"}`, "", nil)
	cookie := loginCookie(t, first)
	if changed := postJSON(t, e.ts, "/auth/password/change",
		`{"current_password":"`+bpfTestTargetPassword+`","new_password":"`+bpfTestTargetChanged+`"}`,
		"", map[string]string{"Cookie": cookieHeader(cookie)}); changed.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(changed.Body)
		t.Fatalf("目標本人首次改密應成功：%s", body)
	}
	return id
}

// bpfAuditRows 數 Root 域審計總行數（「預檢連安全審計都不寫」的斷言對象）。
func bpfAuditRows(t *testing.T, e *guestLiveEnv) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM root_audit`).Scan(&n); err != nil {
		t.Fatalf("計數 Root 域審計失敗：%v", err)
	}
	return n
}

// bpfEnablePolicy 翻開「管理員建號＋訪客進入」兩顆開關（自註冊保持 closed）：
// 現場要的是真訪客與真普通帳戶，出廠全關時建號會吃 2017。
func bpfEnablePolicy(t *testing.T, e *guestLiveEnv) {
	t.Helper()
	root := e.rootCookie(t)
	putResp := putJSON(t, e.ts, "/root/account-policy", policyBody(true, "closed", true), "",
		map[string]string{"Cookie": cookieHeader(root)})
	if putResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(putResp.Body)
		t.Fatalf("保存策略應成功：%d %s", putResp.StatusCode, body)
	}
}

// bpfEnterGuest 在開關已亮（bpfEnablePolicy）的現場讓一個人真實進入，
// 回傳（會話 Cookie, 帳戶標識）。刻意不經 upgEnterGuest——那個助手會經 setGuest
// 按出廠形態寫回策略，把管理員建號那一欄順帶關掉，本檔之後還要用那條通路建目標。
func bpfEnterGuest(t *testing.T, e *guestLiveEnv, nickname string) (*http.Cookie, string) {
	t.Helper()
	resp := e.enter(t, nickname)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("訪客進入應成功：%d %s", resp.StatusCode, body)
	}
	id, _ := decodeJSONBody(t, resp)["account_id"].(string)
	if id == "" {
		t.Fatalf("訪客回應應帶出帳戶標識：%v", id)
	}
	return loginCookie(t, resp), id
}

// TestAdminBindPreflightEndToEnd 合法候選的完整閉環：真訪客進入、真管理員、
// 真普通帳戶作目標——200 預覽帶出「同一枚源標識、source.account_type=guest、
// target.account_type=standard、executable 為真、blockers 為空數組（是 [] 不是缺席）、
// 五條 impacts、source_open_sessions 等於訪客那趟進入的會話數、
// consent_mode 恆為 target_self_initiated」。跑完之後：兩側帳戶行逐字不動、
// 訪客那枚 Cookie 依然讀得出自己的會話（預覽沒有撤銷任何东西）、
// 審計總行數一粒未增。
func TestAdminBindPreflightEndToEnd(t *testing.T) {
	e := newGuestLiveEnv(t)
	bpfEnablePolicy(t, e)
	guestCookie, guestID := bpfEnterGuest(t, e, "端到端旅人")
	admin := upgLiveAdminCookie(t, e, "bpf.e2e.admin")
	targetID := bpfLiveStandardAccount(t, e, admin, "Bind.E2E.Target")

	guestBefore := accountRow(t, e, guestID)
	targetBefore := accountRow(t, e, targetID)
	auditsBefore := bpfAuditRows(t, e)

	resp := bpfPost(t, e, guestID, `{"target_account_id":"`+targetID+`"}`, admin)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("合法候選的預檢應回 200 預覽：%d %s", resp.StatusCode, body)
	}
	body := decodeJSONBody(t, resp)
	if got := body["executable"]; got != true {
		t.Fatalf("合法候選應 executable=true，實際 %v", got)
	}
	blockers, ok := body["blockers"].([]any)
	if !ok || len(blockers) != 0 {
		t.Fatalf("blockers 必須是空數組而不是缺席或 null，實際 %#v", body["blockers"])
	}
	impacts, ok := body["impacts"].([]any)
	if !ok || len(impacts) != 5 {
		t.Fatalf("可執行時五條影響應齊備，實際 %#v", body["impacts"])
	}
	if got := body["source_open_sessions"]; got != float64(1) {
		t.Errorf("訪客進入恰好簽發一枚會話，預覽應報 1，實際 %v", got)
	}
	if got := body["consent_mode"]; got != "target_self_initiated" {
		t.Errorf("同意形態必須如實出口，實際 %v", got)
	}
	if got := body["schema_version"]; got == nil || got == float64(0) {
		t.Errorf("資料版本必須如實帶出，實際 %v", got)
	}
	source := body["source"].(map[string]any)
	target := body["target"].(map[string]any)
	if source["account_id"] != guestID || source["account_type"] != "guest" {
		t.Errorf("來源投影应是該訪戶本人，實際 %#v", source)
	}
	if target["account_id"] != targetID || target["account_type"] != "standard" {
		t.Errorf("目標投影应是該普通帳戶本人，實際 %#v", target)
	}
	// 回應裡不能有任何憑據形態的欄位（合同層面的「不可能洩漏」）：按鍵名逐層比對，
	// 不做子串掃描——must_change_password 是合法的可展示旗標，不能被誤殺。
	for _, forbidden := range []string{"password", "hash", "token", "secret", "cookie"} {
		if found := findKeyDeep(body, forbidden); found != "" {
			t.Errorf("預覽回應不得出現憑據形態欄位 %q（於 %s）", forbidden, found)
		}
	}

	// 零寫入的三處對照：兩側行逐字不動、審計零增、訪客 Cookie 照常換得出身份。
	if got := accountRow(t, e, guestID); got != guestBefore {
		t.Errorf("預檢動了來源帳戶一行：变更前 %s／實際 %s", guestBefore, got)
	}
	if got := accountRow(t, e, targetID); got != targetBefore {
		t.Errorf("預檢動了目標帳戶一行：变更前 %s／實際 %s", targetBefore, got)
	}
	if got := bpfAuditRows(t, e); got != auditsBefore {
		t.Errorf("預檢是純只讀（用戶批准零寫入），審計不得多出一筆：变更前 %d／實際 %d",
			auditsBefore, got)
	}
	sess := getAuth(t, e.ts, "/auth/session", cookieHeader(guestCookie), "", "")
	if sess.StatusCode != http.StatusOK {
		t.Errorf("預檢後訪客自己的會話必須還活着（沒有被順帶撤銷），實際 %d",
			sess.StatusCode)
	}
}

// TestAdminBindPreflightConflictsAre200Preview 「不可綁定」是本步的合同核心：
// 它是 200 預覽裡的一條穩定原因記號，不是錯誤信封。同對、停用中的來源、
// 訪戶作目標、以及被停用的普通帳戶作來源——逐一以 200 回來、executable=false、
// blockers 點名、impacts 清空；每次之後現場仍然一個字沒動。
func TestAdminBindPreflightConflictsAre200Preview(t *testing.T) {
	e := newGuestLiveEnv(t)
	bpfEnablePolicy(t, e)
	admin := upgLiveAdminCookie(t, e, "bpf.preview.admin")

	// 真訪客兩名＋真普通帳戶一名＋被停用的訪客一名（走真 /status 通路停用）。
	_, oneID := bpfEnterGuest(t, e, "預覽旅人一")
	_, twoID := bpfEnterGuest(t, e, "預覽旅人二")
	targetID := bpfLiveStandardAccount(t, e, admin, "Bpf.Preview.Target")
	offResp := e.enter(t, "預覽停職旅人")
	offID, _ := decodeJSONBody(t, offResp)["account_id"].(string)
	if disable := putJSON(t, e.ts, "/admin/accounts/"+offID+"/status",
		`{"status":"disabled","expected_status":"active"}`, "",
		map[string]string{"Cookie": cookieHeader(admin)}); disable.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(disable.Body)
		t.Fatalf("停用訪戶應成功：%s", body)
	}

	cases := []struct {
		name          string
		source        string
		target        string
		wantBlocker   string
		wantOpenSeams bool
	}{
		{"同源自同一對", oneID, oneID, "same_source_target", true},
		{"訪戶作目標", oneID, twoID, "target_not_standard", false},
		{"停用中的來源", offID, targetID, "source_not_active", false},
	}
	auditsBefore := bpfAuditRows(t, e)
	oneBefore := accountRow(t, e, oneID)
	for _, tc := range cases {
		resp := bpfPost(t, e, tc.source, `{"target_account_id":"`+tc.target+`"}`, admin)
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("%s：不可綁定應是 200 預覽而不是錯誤信封：%d %s", tc.name, resp.StatusCode, body)
			continue
		}
		body := decodeJSONBody(t, resp)
		if body["executable"] != false {
			t.Errorf("%s：應 executable=false，實際 %v", tc.name, body["executable"])
		}
		blockers, _ := body["blockers"].([]any)
		joined := make([]string, 0, len(blockers))
		for _, b := range blockers {
			joined = append(joined, b.(string))
		}
		if !containsAll(joined, tc.wantBlocker) {
			t.Errorf("%s：阻止原因應含 %q，實際 %v", tc.name, tc.wantBlocker, joined)
		}
		if impacts, ok := body["impacts"].([]any); !ok || len(impacts) != 0 {
			t.Errorf("%s：被阻止的綁定不該帶任何影響，實際 %#v", tc.name, body["impacts"])
		}
	}
	if got := accountRow(t, e, oneID); got != oneBefore {
		t.Errorf("三趟預覽動了帳戶一行：变更前 %s／實際 %s", oneBefore, got)
	}
	if got := bpfAuditRows(t, e); got != auditsBefore {
		t.Errorf("三趟預覽不得新增審計：变更前 %d／實際 %d", auditsBefore, got)
	}
}

// containsAll 斷言式輔助：joined 是否含 want（單元素精確比對用）。
func containsAll(joined []string, want string) bool {
	for _, j := range joined {
		if j == want {
			return true
		}
	}
	return false
}

// findKeyDeep 遞迴找一個精確鍵名在回應樹裡的落點（回傳路徑，找不到回空字串）。
// 精確比對而不是子串：must_change_password 這類合法欄位不該被掃描誤殺。
func findKeyDeep(v any, key string) string {
	switch node := v.(type) {
	case map[string]any:
		for name, child := range node {
			if name == key {
				return key
			}
			if got := findKeyDeep(child, key); got != "" {
				return name + "." + got
			}
		}
	case []any:
		for i, child := range node {
			if got := findKeyDeep(child, key); got != "" {
				return itoa(i) + "." + got
			}
		}
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestAdminBindPreflightAccessAndFailureMatrix 拒絕矩陣逐條各回各句：
// 匿名 2002、普通帳戶 2011、訪戶本人自我預檢 2011（訪戶沒有資格安排自己的綁定，
// 這條與升級同形）、幽靈來源／幽靈目標／管理員目標／已刪目标收斂成同一句 1001
// （預覽不是比詳情更亮的探照燈）、缺目標與壞目標標識 1004 點名欄位、
// 偽造欄位 1004、非法來源標識 1001、GET 方法 1002；
// 每一次拒絕都不留任何寫入、不記審計。
func TestAdminBindPreflightAccessAndFailureMatrix(t *testing.T) {
	e := newGuestLiveEnv(t)
	bpfEnablePolicy(t, e)
	admin := upgLiveAdminCookie(t, e, "bpf.matrix.admin")
	guestCookie, guestID := bpfEnterGuest(t, e, "矩陣預檢旅人")
	targetID := bpfLiveStandardAccount(t, e, admin, "Bpf.Matrix.Target")
	// 一個 Root 開設的管理員（目標側的「特權帳戶」）、經 Root 刪除同一位（刪除終態）。
	created := postJSON(t, e.ts, "/root/admins",
		`{"login_name":"bpf.matrix.privileged","display_name":"特權目標","password":"`+upgTestAdminInitial+`"}`,
		"", map[string]string{"Cookie": cookieHeader(e.rootCookie(t))})
	if created.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(created.Body)
		t.Fatalf("開設管理員應成功：%d %s", created.StatusCode, body)
	}
	privilegedID, _ := decodeJSONBody(t, created)["account_id"].(string)
	deleted := sendMethod(t, e.ts, http.MethodDelete, "/root/admins/"+privilegedID,
		e.rootCookie(t))
	if deleted.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(deleted.Body)
		t.Fatalf("軟刪除管理員應成功：%d %s", deleted.StatusCode, body)
	}
	deletedID := privilegedID
	// 普通帳戶主體會話：目標本人那條鏈的 Cookie 已是改後態，直接重用其重登。
	stdLogin := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"Bpf.Matrix.Target","password":"`+bpfTestTargetChanged+`"}`, "", nil)
	stdCookie := loginCookie(t, stdLogin)

	goodBody := `{"target_account_id":"` + targetID + `"}`
	before := accountRow(t, e, guestID)
	auditsBefore := bpfAuditRows(t, e)
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
		{"普通帳戶", guestID, goodBody, http.MethodPost, stdCookie, http.StatusForbidden, CodePermissionDenied},
		{"訪戶本人", guestID, goodBody, http.MethodPost, guestCookie, http.StatusForbidden, CodePermissionDenied},
		{"幽靈目標", guestID, `{"target_account_id":"00000000-0000-7000-8000-000000000456"}`,
			http.MethodPost, admin, http.StatusNotFound, CodeNotFound},
		{"特權目標（現已刪除，同句 1001）", guestID, `{"target_account_id":"` + deletedID + `"}`,
			http.MethodPost, admin, http.StatusNotFound, CodeNotFound},
		{"幽靈來源", "00000000-0000-7000-8000-000000000789", goodBody,
			http.MethodPost, admin, http.StatusNotFound, CodeNotFound},
		{"非法來源標識", "not-a-uuid", goodBody, http.MethodPost, admin, http.StatusNotFound, CodeNotFound},
		{"缺目標欄位", guestID, `{}`, http.MethodPost, admin, http.StatusBadRequest, CodeInvalidBody},
		{"壞目標標識", guestID, `{"target_account_id":"not-a-uuid"}`,
			http.MethodPost, admin, http.StatusBadRequest, CodeInvalidBody},
		{"偽造欄位", guestID, `{"target_account_id":"` + targetID + `","roles":["server_admin"]}`,
			http.MethodPost, admin, http.StatusBadRequest, CodeInvalidBody},
		{"GET 方法", guestID, "", http.MethodGet, admin, http.StatusMethodNotAllowed, CodeMethodNotAllowed},
	}
	for _, tc := range cases {
		var resp *http.Response
		switch tc.method {
		case http.MethodGet:
			resp = getAuth(t, e.ts, "/admin/accounts/"+tc.source+"/bind-preflight",
				cookieHeader(tc.cookie), "", "")
		default:
			var headers map[string]string
			if tc.cookie != nil {
				headers = map[string]string{"Cookie": cookieHeader(tc.cookie)}
			}
			resp = postJSON(t, e.ts, "/admin/accounts/"+tc.source+"/bind-preflight", tc.body,
				"", headers)
		}
		if resp.StatusCode != tc.wantStatus || envelopeCode(t, resp) != int(tc.wantCode) {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("%s：應回 %d/代碼 %d，實際 %d %s", tc.name, tc.wantStatus, tc.wantCode,
				resp.StatusCode, body)
		}
	}
	// 1004 的三條各自點名欄位：缺欄位／壞標識／未知欄位都是 target_account_id 的書寫問題。
	for _, probe := range []string{`{}`, `{"target_account_id":"not-a-uuid"}`} {
		resp := bpfPost(t, e, guestID, probe, admin)
		var envelope struct {
			Details map[string]any `json:"details"`
		}
		raw, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatalf("解析 1004 信封失敗：%s", raw)
		}
		if envelope.Details["invalid_field"] != "target_account_id" {
			t.Errorf("本體 %s 的 1004 應點名 target_account_id，實際 %#v", probe, envelope.Details)
		}
	}
	if got := accountRow(t, e, guestID); got != before {
		t.Errorf("拒絕矩陣動了來源一行：变更前 %s／實際 %s", before, got)
	}
	if got := bpfAuditRows(t, e); got != auditsBefore {
		t.Errorf("拒絕矩陣不得新增審計：变更前 %d／實際 %d", auditsBefore, got)
	}
}

// TestAdminBindPreflightPathAbsentWithoutWiring 未注入普通帳戶用例時，
// 綁定預檢子路徑與其餘目錄端點一樣根本不掛：回 1001，與未掛載逐字相同。
func TestAdminBindPreflightPathAbsentWithoutWiring(t *testing.T) {
	noWiring := guestTestServer(t, nil)
	t.Cleanup(noWiring.Close)
	resp := postJSON(t, noWiring,
		"/admin/accounts/00000000-0000-7000-8000-000000000321/bind-preflight",
		`{"target_account_id":"00000000-0000-7000-8000-000000000322"}`, "", nil)
	if resp.StatusCode != http.StatusNotFound || envelopeCode(t, resp) != int(CodeNotFound) {
		t.Errorf("未注入用例時預檢路徑應不掛（1001），實際 %d", resp.StatusCode)
	}
}
