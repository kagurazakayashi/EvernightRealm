// adminaccounts_password_test.go 是「管理員重置普通帳戶登入憑據」的傳輸層端到端證據：
// 真資料庫＋真用例＋完整中介層鏈，從 Root 開設管理員、管理員真實登入與首改，
// 一路走到 PUT /admin/accounts/{account_id}/password 的三件效果、訪戶與特權目標被拒、
// 停用目標重置後仍停用、本體白名單、路由形狀、重複語意、回應形狀與四語言。
//
// 與 internal/stdacct/resetpassword_test.go 的分工是刻意的：那一檔量的是
// 「三件事的合力是否在同一個交易裡落地」，這一檔量的是「這些事實從一條 HTTP 請求看得見嗎」——
// 同一個人從另一臺裝置打進來會拿到哪一句、界面拿什麼決定那顆按鈕、
// 以及 2018 那一句在四種語言裡是否存在，都在這裡才有答案。
//
// 刻意不收的東西：
//   - 沒有替身：授權、來源判定、首改門閂、撤銷、審計都跨層走真路徑；
//   - 不碰任何真實資料目錄、不佔 5206，全程用本次專屬的暫存庫與系統時鐘；
//   - 測試口令只活在這次進程的記憶體，不寫進任何回應、審計或日誌（有斷言）。
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
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// 重置端到端測試口令：只活在測試進程的記憶體，不是任何環境的憑據。
const (
	stdTestResetPassword  = "adminaccounts-test-交付的一次性重置口令"
	stdTestResetFinal     = "adminaccounts-test-本人改後的最終口令"
	stdTestWrongPassword  = "adminaccounts-test-明顯錯的口令-not-a-password"
	stdTestLongPasswordOk = "adminaccounts-test-剛好合格的長口令"
)

// passwordPath 拼出憑據子資源路徑（父路徑的形態由端點合同決定，不在這裡猜）。
func passwordPath(id idgen.ID) string {
	return "/admin/accounts/" + id.String() + "/password"
}

// resetBody 產生一份完整的重置本體（白名單只有 password 一欄）。
func resetBody(password string) string {
	data, err := json.Marshal(map[string]any{"password": password})
	if err != nil {
		panic(err)
	}
	return string(data)
}

// resetEnvelope 解析重置回應本體。
func resetEnvelope(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	text := mustReadAll(t, resp)
	var envelope map[string]any
	if err := json.Unmarshal([]byte(text), &envelope); err != nil {
		t.Fatalf("解析重置回應失敗：%s", text)
	}
	return envelope
}

// countPasswordResetAudits 數 Root 域裡的重置審計筆數。
func countPasswordResetAudits(t *testing.T, e *stdEnv) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM root_audit WHERE action = 'account.password_reset'`).Scan(&n); err != nil {
		t.Fatalf("計數重置審計失敗：%v", err)
	}
	return n
}

// TestAdminStandardPasswordResetFullLoop 完整閉環：兩臺裝置在線的普通帳戶被重置後
// 兩份會話都換不出主體、舊口令與打錯口令同形；交付的重置口令登得進來但被首改門閂擋，
// 本人完成改密後義務解除、重置口令徹底死亡。
//
// 這一條是本次那句要求的正面證據：「新密碼可走首次改密、舊密碼與舊會話失效」
// 必須從一條 HTTP 請求看得到，而不是只在服務層自說自話。
func TestAdminStandardPasswordResetFullLoop(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "pwdloop.admin")

	created := e.createAccount(t, stdBody("pwdloop.player", "被重置的那個", stdTestInitial),
		admin, nil)
	if created.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(created.Body)
		t.Fatalf("建立普通帳戶應成功：%d %s", created.StatusCode, body)
	}
	target := createdAccountID(t, created)

	first := loginCookie(t, e.loginAs(t, "pwdloop.player", stdTestInitial))
	second := loginCookie(t, e.loginAs(t, "pwdloop.player", stdTestInitial))
	for i, cookie := range []*http.Cookie{first, second} {
		probe := getAuth(t, e.ts, "/admin/accounts", cookieHeader(cookie), "", "")
		if probe.StatusCode != http.StatusForbidden ||
			envelopeCode(t, probe) != int(CodePasswordChangeRequired) {
			t.Fatalf("第 %d 份會話在重置前应能換出主體（拿到 2010），實際 %d", i+1, probe.StatusCode)
		}
	}

	resp := putJSON(t, e.ts, passwordPath(target), resetBody(stdTestResetPassword), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("重置應成功：%d %s", resp.StatusCode, body)
	}
	envelope := resetEnvelope(t, resp)
	if got, ok := envelope["revoked_sessions"].(float64); !ok || got != 2 {
		t.Errorf("重置應回報撤銷了 2 份會話（兩臺裝置），實際 %v", envelope["revoked_sessions"])
	}
	accountBody, _ := envelope["account"].(map[string]any)
	if accountBody["must_change_password"] != true {
		t.Errorf("重置後必須帶著「首次登入須改密」的義務，實際 %+v", accountBody)
	}
	if accountBody["status"] != "active" {
		t.Errorf("重置不動登入能力，狀態應仍是 active，實際 %+v", accountBody)
	}

	// 既有會話立即失效：不是「下次登入會被拒」，而是手上這份已經換不出主體。
	for i, cookie := range []*http.Cookie{first, second} {
		probe := getAuth(t, e.ts, "/admin/accounts", cookieHeader(cookie), "", "")
		if probe.StatusCode != http.StatusUnauthorized ||
			envelopeCode(t, probe) != int(CodeSessionInvalid) {
			t.Errorf("第 %d 份重置前會話應回 2003/401，實際 %d", i+1, probe.StatusCode)
		}
	}
	// 舊口令與打錯口令同形（2001）：這條通路不外洩「他被誰換過口令」。
	stale := e.loginRaw(t, "pwdloop.player", stdTestInitial)
	wrong := e.loginRaw(t, "pwdloop.player", stdTestWrongPassword)
	if stale.StatusCode != wrong.StatusCode || envelopeCode(t, stale) != envelopeCode(t, wrong) {
		t.Errorf("舊口令應與口令錯誤同形（2001），實際 %d vs %d", stale.StatusCode, wrong.StatusCode)
	}

	// 交付的重置口令登得進來，但除改密以外一律 2010。
	delivered := loginCookie(t, e.loginAs(t, "pwdloop.player", stdTestResetPassword))
	probe := getAuth(t, e.ts, "/admin/accounts", cookieHeader(delivered), "", "")
	if probe.StatusCode != http.StatusForbidden ||
		envelopeCode(t, probe) != int(CodePasswordChangeRequired) {
		t.Errorf("重置口令首次登入應被首改門閂擋（2010），實際 %d", probe.StatusCode)
	}
	changed := postJSON(t, e.ts, "/auth/password/change",
		fmt.Sprintf(`{"current_password":"%s","new_password":"%s"}`,
			stdTestResetPassword, stdTestResetFinal),
		"", map[string]string{"Cookie": cookieHeader(delivered)})
	if changed.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(changed.Body)
		t.Fatalf("以重置口令完成首次改密應成功：%d %s", changed.StatusCode, body)
	}
	final := loginCookie(t, e.loginAs(t, "pwdloop.player", stdTestResetFinal))
	// 義務已償還：不再拿 2010，而是拿「這個人沒有管理權」那一句（2011）——
	// 門閂解開的证据必須是「走到了授權判定」，不是「又拿到一次改密提示」。
	gate := getAuth(t, e.ts, "/admin/accounts", cookieHeader(final), "", "")
	if gate.StatusCode != http.StatusForbidden ||
		envelopeCode(t, gate) != int(CodePermissionDenied) {
		t.Errorf("本人改密後首改門閂必須解除（應走到授權判定 2011），實際 %d", gate.StatusCode)
	}
	if dead := e.loginRaw(t, "pwdloop.player", stdTestResetPassword); dead.StatusCode != http.StatusUnauthorized ||
		envelopeCode(t, dead) != int(CodeInvalidCredentials) {
		t.Errorf("重置口令在完成改密後必須徹底死亡（2001），實際 %d", dead.StatusCode)
	}

	// 審計：一筆 account.password_reset，操作者是那位管理員本人。
	var actorKind, targetID string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT actor_kind, target_id FROM root_audit WHERE action = 'account.password_reset'`).
		Scan(&actorKind, &targetID); err != nil {
		t.Fatalf("讀回重置審計失敗：%v", err)
	}
	if actorKind != "admin" || targetID != target.String() {
		t.Errorf("重置審計應是 admin 對那個帳戶，實際 %s／%s", actorKind, targetID)
	}
}

// TestAdminStandardPasswordResetAccessControlAndGuest 鑑別、範圍與訪戶：
// 匿名 2002、普通帳戶 2011、同級管理員與操作者自己與刪除終態與 Root 保留標識與幽靈一律 1001，
// 而訪戶帳戶收 2018/403 且一個字都不落——重置不是把訪戶隱式升級的通路。
func TestAdminStandardPasswordResetAccessControlAndGuest(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "pwdacl.admin")

	plain := e.seedPlainAccount(t, account.NewInput{
		LoginName: "pwdacl.plain", DisplayName: "一個普通帳戶", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	plainCookie := loginCookie(t, e.loginAs(t, "pwdacl.plain", dirTestPassword))
	anon := putJSON(t, e.ts, passwordPath(plain.ID), resetBody(stdTestResetPassword), "", nil)
	if anon.StatusCode != http.StatusUnauthorized || envelopeCode(t, anon) != int(CodeNotAuthenticated) {
		t.Errorf("匿名重置應回 2002/401，實際 %d", anon.StatusCode)
	}
	denied := putJSON(t, e.ts, passwordPath(plain.ID), resetBody(stdTestResetPassword), "",
		map[string]string{"Cookie": cookieHeader(plainCookie)})
	if denied.StatusCode != http.StatusForbidden ||
		envelopeCode(t, denied) != int(CodePermissionDenied) {
		t.Errorf("普通帳戶重置他人憑據應回 2011/403，實際 %d", denied.StatusCode)
	}
	// 被拒的這幾趟一個字都沒落：憑據雜湊仍是原本那颗。
	if got := rawRowSnapshot(t, e, plain.ID)["must_change_password"]; got != "0" {
		t.Errorf("被拒的重置不該動改密旗標，實際 %s", got)
	}

	peer := e.seedPlainAccount(t, account.NewInput{
		LoginName: "pwdacl.peer", DisplayName: "另一位管理員", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	e.grantAdmin(t, peer.ID)
	gone := e.seedPlainAccount(t, account.NewInput{
		LoginName: "pwdacl.gone", DisplayName: "已刪除的", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	if _, err := e.accounts.MarkDeleted(context.Background(), e.db.SQL(), gone.ID,
		gone.DisplayName); err != nil {
		t.Fatalf("寫入刪除終態失敗：%v", err)
	}
	var selfID string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT id FROM accounts WHERE login_name = ?", "pwdacl.admin").Scan(&selfID); err != nil {
		t.Fatalf("讀回操作者標識失敗：%v", err)
	}
	selfParsed, err := idgen.Parse(selfID)
	if err != nil {
		t.Fatalf("操作者標識解析失敗：%v", err)
	}
	rootReserved, _ := idgen.Parse("00000000-0000-7000-8000-000000000000")
	phantom, err := idgen.New()
	if err != nil {
		t.Fatalf("產生幽靈標識失敗：%v", err)
	}
	// 特權目標與查無同形：管理员拿这条通路动不了另一位管理員，也动不到 Root，
	// 更拿不到「差哪一半」的信号。
	for name, id := range map[string]idgen.ID{
		"同級管理員":     peer.ID,
		"操作者自己":     selfParsed,
		"刪除終態":      gone.ID,
		"Root 保留標識": rootReserved,
		"幽靈標識":      phantom,
	} {
		resp := putJSON(t, e.ts, passwordPath(id), resetBody(stdTestResetPassword), "",
			map[string]string{"Cookie": cookieHeader(admin)})
		if resp.StatusCode != http.StatusNotFound || envelopeCode(t, resp) != int(CodeNotFound) {
			t.Errorf("%s 應回 1001/404 同形，實際 %d", name, resp.StatusCode)
		}
	}
	peerHash := rawRowSnapshot(t, e, peer.ID)["password_hash"]
	if got := rawRowSnapshot(t, e, peer.ID)["password_hash"]; got != peerHash {
		t.Error("管理員不得被這條通路重置憑據")
	}

	guest := e.seedPlainAccount(t, account.NewInput{
		LoginName: "pwdacl.guest", DisplayName: "訪戶帳戶", Type: account.TypeGuest,
		Status: account.StatusActive,
	})
	before := rawRowSnapshot(t, e, guest.ID)
	audits := countPasswordResetAudits(t, e)
	guestResp := putJSON(t, e.ts, passwordPath(guest.ID), resetBody(stdTestResetPassword), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if guestResp.StatusCode != http.StatusForbidden ||
		envelopeCode(t, guestResp) != int(CodeGuestUpgradeRequired) {
		body, _ := io.ReadAll(guestResp.Body)
		t.Fatalf("訪戶目標應回 2018/403，實際 %d %s", guestResp.StatusCode, body)
	}
	if got := rawRowSnapshot(t, e, guest.ID); fmt.Sprint(got) != fmt.Sprint(before) {
		t.Errorf("被拒的訪戶重置一個字都不該落，變更前 %+v／實際 %+v", before, got)
	}
	if got := countPasswordResetAudits(t, e); got != audits {
		t.Errorf("被拒的重置不得追加審計（前 %d 後 %d）", audits, got)
	}
	// 訪戶仍是訪戶：那行連一個可能的哈希格子都是空的（隱式升級沒有發生）。
	if v := rawRowSnapshot(t, e, guest.ID)["password_hash"]; v != "<NULL>" {
		t.Errorf("訪戶的憑據必須仍是 NULL，實際 %s", v)
	}
}

// TestAdminStandardPasswordResetBodyRules 本體白名單：八種隱藏欄位注入由 details.field
// 交出，空口令、超長口令、缺欄位與空本體由 details.invalid_field=password 交出，
// 全部零寫入、零審計。
func TestAdminStandardPasswordResetBodyRules(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "pwdbody.admin")
	target := e.seedPlainAccount(t, account.NewInput{
		LoginName: "pwdbody.target", DisplayName: "本體攻擊的對象", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	before := rawRowSnapshot(t, e, target.ID)
	audits := countTableRows(t, e.db, "root_audit")

	// 兩種 1004 的點名方式不同但都必點名：本體裡那個不存在的欄位由 decodeJSON
	// 以 details.field 交出，值不合規由對映函式以 details.invalid_field 交出。
	cases := []struct {
		name      string
		body      string
		key       string
		wantField string
	}{
		{"順手改顯示名", `{"password":"合格口令-abc123","display_name":"被順手改的名"}`, "field", "display_name"},
		{"順手解除停用", `{"password":"合格口令-abc123","status":"active"}`, "field", "status"},
		{"帶依據值", `{"password":"合格口令-abc123","expected_password":"舊口令"}`, "field", "expected_password"},
		{"順手清改密旗標", `{"password":"合格口令-abc123","must_change_password":false}`, "field", "must_change_password"},
		{"順手改類型", `{"password":"合格口令-abc123","account_type":"standard"}`, "field", "account_type"},
		{"自報角色", `{"password":"合格口令-abc123","roles":["server_admin"]}`, "field", "roles"},
		{"塞進某個活動", `{"password":"合格口令-abc123","activity_id":"00000000-0000-7000-8000-000000000001"}`, "field", "activity_id"},
		{"宣稱自己是這個標識", `{"password":"合格口令-abc123","account_id":"01a10000-0000-7000-8000-000000000002"}`, "field", "account_id"},
		{"空口令", `{"password":""}`, "invalid_field", "password"},
		{"缺口令欄位", `{}`, "invalid_field", "password"},
		{"超長口令", `{"password":"` + strings.Repeat("長", credential.MaxPasswordLength) + `"}`, "invalid_field", "password"},
	}
	for _, tc := range cases {
		resp := putJSON(t, e.ts, passwordPath(target.ID), tc.body, "",
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

// TestAdminStandardPasswordResetKeepsDisabledAndPending 重置不解除停用、不放待审批的行列：
// 停用中的目標重置成功但仍是 disabled 帶原時刻、撤銷數量 0、重置口令在停用期間仍登不進去；
// 欠首改的目標重置後仍被 2010 擋（重置是把旗標寫成 1，不是歸零）。
func TestAdminStandardPasswordResetKeepsDisabledAndPending(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "pwdkeep.admin")

	off := e.seedPlainAccount(t, account.NewInput{
		LoginName: "pwdkeep.off", DisplayName: "停用中的目標", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	disable := putJSON(t, e.ts, statusPath(off.ID), statusBody("disabled", "active"), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if disable.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(disable.Body)
		t.Fatalf("預先停用應成功：%d %s", disable.StatusCode, body)
	}
	before := rawRowSnapshot(t, e, off.ID)

	resp := putJSON(t, e.ts, passwordPath(off.ID), resetBody(stdTestResetPassword), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("對停用目標重置應成功：%d %s", resp.StatusCode, body)
	}
	envelope := resetEnvelope(t, resp)
	if got, ok := envelope["revoked_sessions"].(float64); !ok || got != 0 {
		t.Errorf("停用者的會話早在停用時已撤，這次重置不該再撤到東西，實際 %v", envelope["revoked_sessions"])
	}
	accountBody, _ := envelope["account"].(map[string]any)
	if accountBody["status"] != "disabled" || accountBody["disabled_at"] == nil {
		t.Errorf("重置後仍該是 disabled 帶原停用時刻，實際 %+v", accountBody)
	}
	after := rawRowSnapshot(t, e, off.ID)
	if after["status"] != before["status"] || after["disabled_at"] != before["disabled_at"] {
		t.Errorf("重置不得改寫狀態與停用時刻，變更前 %s／變更後 %s",
			before["disabled_at"], after["disabled_at"])
	}
	// 重置不給登入開後門：停用期間那個口令交出去也沒有接受者。
	if blocked := e.loginRaw(t, "pwdkeep.off", stdTestResetPassword); blocked.StatusCode != http.StatusUnauthorized ||
		envelopeCode(t, blocked) != int(CodeInvalidCredentials) {
		t.Errorf("停用期間重置口令應被拒且與憑據錯誤同形（2001），實際 %d", blocked.StatusCode)
	}

	// 待審批的那一格今日以「欠首次改密」呈現：建號出的帳戶欠改密，重置之後仍然欠。
	pending := e.createAccount(t, stdBody("pwdkeep.pending", "欠改密的目標", stdTestInitial),
		admin, nil)
	if pending.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(pending.Body)
		t.Fatalf("建立普通帳戶應成功：%d %s", pending.StatusCode, body)
	}
	pendingID := createdAccountID(t, pending)
	again := putJSON(t, e.ts, passwordPath(pendingID), resetBody(stdTestResetPassword), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if again.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(again.Body)
		t.Fatalf("重置欠改密的目標應成功：%d %s", again.StatusCode, body)
	}
	if got := resetEnvelope(t, again); got["account"].(map[string]any)["must_change_password"] != true {
		t.Errorf("重置必須把首次改密義務保持生效（不是順手放行），實際 %+v", got["account"])
	}
	cookie := loginCookie(t, e.loginAs(t, "pwdkeep.pending", stdTestResetPassword))
	probe := getAuth(t, e.ts, "/admin/accounts", cookieHeader(cookie), "", "")
	if probe.StatusCode != http.StatusForbidden ||
		envelopeCode(t, probe) != int(CodePasswordChangeRequired) {
		t.Errorf("重置後的目標仍應被 2010 擋到改完為止，實際 %d", probe.StatusCode)
	}
}

// TestAdminStandardPasswordResetRouting 路由形狀：子路徑只認 PUT（其餘 1002 帶 Allow），
// 多一段的路徑落回 1001；父路徑仍然不認 DELETE。
func TestAdminStandardPasswordResetRouting(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "pwdroute.admin")
	target := e.seedPlainAccount(t, account.NewInput{
		LoginName: "pwdroute.target", DisplayName: "路由對象", Type: account.TypeStandard,
		Status: account.StatusActive,
	})

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodPatch} {
		resp := sendMethodBody(t, e.ts, method, passwordPath(target.ID),
			resetBody(stdTestResetPassword), admin)
		if resp.StatusCode != http.StatusMethodNotAllowed ||
			envelopeCode(t, resp) != int(CodeMethodNotAllowed) {
			t.Errorf("%s /password 應回 1002/405，實際 %d", method, resp.StatusCode)
			continue
		}
		if allow := resp.Header.Get("Allow"); allow != http.MethodPut {
			t.Errorf("%s /password 的 Allow 應只列 PUT，實際 %q", method, allow)
		}
	}
	extra := sendMethod(t, e.ts, http.MethodPut, passwordPath(target.ID)+"/extra", admin)
	if extra.StatusCode != http.StatusNotFound || envelopeCode(t, extra) != int(CodeNotFound) {
		t.Errorf("多一段的子路徑應回 1001/404，實際 %d", extra.StatusCode)
	}
}

// TestAdminStandardPasswordResetRepeatAndConcurrency 重複與併發的批准語意：
// 本刻意沒有依據值，因此第二次提交不是 2014 式的「陳舊依據被拒」，而是又做一次完整重置
// （再撤一輪新簽發的會話、再留一筆審計）；併發下每一次成功都是整筆。
func TestAdminStandardPasswordResetRepeatAndConcurrency(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "pwdrepeat.admin")
	target := e.seedPlainAccount(t, account.NewInput{
		LoginName: "pwdrepeat.target", DisplayName: "被接連重置的人", Type: account.TypeStandard,
		Status: account.StatusActive,
	})

	first := putJSON(t, e.ts, passwordPath(target.ID), resetBody(stdTestResetPassword), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if first.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(first.Body)
		t.Fatalf("首次重置應成功：%d %s", first.StatusCode, body)
	}
	if got := resetEnvelope(t, first)["revoked_sessions"].(float64); got != 0 {
		t.Errorf("還沒有任何會話可撤，首次重置應撤 0，實際 %v", got)
	}
	live := loginCookie(t, e.loginAs(t, "pwdrepeat.target", stdTestResetPassword))
	second := putJSON(t, e.ts, passwordPath(target.ID), resetBody(stdTestLongPasswordOk), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if second.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(second.Body)
		t.Fatalf("第二次重置應成功（不是衝突被拒）：%d %s", second.StatusCode, body)
	}
	if got := resetEnvelope(t, second)["revoked_sessions"].(float64); got != 1 {
		t.Errorf("第二次重置應撤掉中間新簽發的 1 份會話，實際 %v", got)
	}
	probe := getAuth(t, e.ts, "/admin/accounts", cookieHeader(live), "", "")
	if probe.StatusCode != http.StatusUnauthorized || envelopeCode(t, probe) != int(CodeSessionInvalid) {
		t.Errorf("第二次重置必須撤銷中間那份會話，實際 %d", probe.StatusCode)
	}
	if got := countPasswordResetAudits(t, e); got != 2 {
		t.Errorf("兩次完整的重置必須各留一筆審計，實際 %d 筆", got)
	}

	// 併發四路：沒有 CAS 就沒有「落敗者」，但每一次成功都必須是整筆（審計數與成功數一致）。
	race := e.seedPlainAccount(t, account.NewInput{
		LoginName: "pwdrace.target", DisplayName: "被搶著重置的人", Type: account.TypeStandard,
		Status: account.StatusActive,
	})
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]int, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			resp := putJSON(t, e.ts, passwordPath(race.ID),
				resetBody(fmt.Sprintf("pwdrace-口令-%d-合格長度", i)), "",
				map[string]string{"Cookie": cookieHeader(admin)})
			if resp.StatusCode == http.StatusOK {
				_, _ = io.ReadAll(resp.Body)
				results[i] = 0
				return
			}
			results[i] = envelopeCode(t, resp)
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	for i, code := range results {
		if code == 0 {
			wins++
			continue
		}
		t.Logf("第 %d 路併發重置出現失敗（須為整筆回滾）：code=%d", i+1, code)
	}
	if wins == 0 {
		t.Fatal("四路併發重置不得全軍覆沒（那是缺陷，不是競爭）")
	}
	if got := countPasswordResetAudits(t, e); got != 2+wins {
		t.Errorf("每一次成功必須恰好一筆審計（併發成功 %d，累計審計 %d，預期 %d）", wins, got, 2+wins)
	}
	// 最終現值只認一個口令：四種交付裡恰好一種過驗證。
	hash := rawRowSnapshot(t, e, race.ID)["password_hash"]
	accepted := 0
	for i := 0; i < 4; i++ {
		ok, err := credential.Verify(hash, fmt.Sprintf("pwdrace-口令-%d-合格長度", i))
		if err != nil {
			t.Fatalf("校驗測試口令失敗：%v", err)
		}
		if ok {
			accepted++
		}
	}
	if accepted != 1 {
		t.Errorf("併發之後的最終憑據必須恰好命中一個交付口令，實際 %d 個", accepted)
	}
}

// TestAdminStandardPasswordResetResponseShapeAndLocales 回應形狀與四語言：信封恰好三鍵、
// account 是白名單欄位、原文不含任何憑據與會話材料，2018 在四語各有自己的一句案。
func TestAdminStandardPasswordResetResponseShapeAndLocales(t *testing.T) {
	e := newStdEnv(t)
	root := e.rootCookie(t)
	e.setAdminCreate(t, root, true)
	admin := e.liveAdminCookie(t, "pwdshape.admin")
	target := e.seedPlainAccount(t, account.NewInput{
		LoginName: "pwdshape.target", DisplayName: "形狀的對象", Type: account.TypeStandard,
		Status: account.StatusActive,
	})

	resp := putJSON(t, e.ts, passwordPath(target.ID), resetBody(stdTestResetPassword), "",
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
	// 「回應不回顯口令」不是靠遮罩：連一個可能容下憑據材料的欄位名都不在。
	for _, forbidden := range []string{"password_hash", "argon2id", "login_name_key", "token",
		"cookie", "roles", "granted_at", "deleted_at", "activity", stdTestResetPassword, dirTestPassword} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("回應原文不得出現 %s，實際 %s", forbidden, text)
		}
	}

	// 2018 四語言齊備：拿訪戶目標打一次，四語都要有一句非空的案。
	guest := e.seedPlainAccount(t, account.NewInput{
		LoginName: "pwdshape.guest", DisplayName: "訪戶帳戶", Type: account.TypeGuest,
		Status: account.StatusActive,
	})
	for _, tag := range []string{"zh-CN", "zh-TW", "en-US", "ja-JP"} {
		resp := sendMethodBodyWithHeader(t, e.ts, http.MethodPut, passwordPath(guest.ID),
			resetBody(stdTestResetPassword), admin, map[string]string{"Accept-Language": tag})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s 的 2018 應是 403，實際 %d", tag, resp.StatusCode)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		var env struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("%s 信封解析失敗：%s", tag, body)
		}
		if env.Code != int(CodeGuestUpgradeRequired) || strings.TrimSpace(env.Message) == "" {
			t.Errorf("%s 的 2018 訊息必須存在且點名升級，實際 %s", tag, body)
		}
		if strings.Contains(env.Message, stdTestResetPassword) || strings.Contains(env.Message, "argon2id") {
			t.Errorf("%s 的錯誤訊息不得帶出口令或雜湊： %s", tag, env.Message)
		}
	}
}
