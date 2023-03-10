// adminaccounts_delete_test.go 是「管理員軟刪除普通帳戶與訪戶帳戶」的傳輸層端到端證據：
// 真資料庫＋真用例＋完整中介層鏈，從 Root 開設管理員、管理員真實登入與首改，
// 一路走到 DELETE /admin/accounts/{account_id}——刪除的三件合力（停新登入、撤既有會話、
// 顯示名匿名化）是否在回應、會話、目錄、詳情、審計與其餘寫入通路上同時可見。
//
// 這一檔刻意要釘死的幾類形態：
//   - 刪除是本目錄的終態開關：成功一次之後，重複刪除與編輯／停用／重置／升級
//     一律以 2027（已刪除）或 2028（已被綁走）拒絕，並且一個字都不寫、審計不加筆；
//     若把終態拒絶寫成 1001，界面對一個目錄上明明列著的人就只剩「查無此人」這個錯答案；
//     若讓退休行的寫入去撞資料庫觸發器，對外的形體就是一個查不出原因的 500；
//   - 空本体白名單：DELETE 不帶任何可調欄位——帶 reason／expected_status／purge
//     的寫法在協定層就沒有可以成立的格子，默默忽略等於承認那些欄位本來可以有意義；
//   - 刪除後展示策略：列得出、點得開、動不了，deleted_at 與佔位顯示名必須在同一筆
//     回應裡一次講完（登入名原樣保留是「名字繼續被占用」的可讀形態）；
//   - 端點不是標識探針：管理員、Root 保留標識、幽靈、待審批與已拒絕申請人
//     收斂成與查無此人同一句話；
//   - 任何回應與審計原文都不出現憑據材料（口令明文、Argon2id 雜湊、內部正規化鍵、
//     會話秘密）；
//   - 只動它那一個目標：旁人的行、會話與審計逐字不動。
//
// 刻意不收的東西：
//   - 沒有替身：授權、來源判定、首次改密門閂、範圍核實、撤銷與審計都跨層走真路徑；
//   - 不碰任何真實資料目錄、不佔 5206，全程用本次專屬的暫存庫與系統時鐘；
//   - 併發刪除的串行化由 internal/stdacct 的注入時鐘用例與 SQLite 單寫入者保證，
//     這裡量的是「第二次刪除從 HTTP 看得見的結論」，不是競態窗口本身。
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// delSeedAccount 經倉儲種入一筆帳戶（不走建號端點）：本檔要的形態包括
// 「不欠改密的普通帳戶」「訪戶」「待審批」與「已拒絕」，那些都不是端點產得出的。
// 標準帳戶補上測試憑據，訪戶保持 password_hash 為 NULL（遷移 CHECK 的合法形態）。
func delSeedAccount(t *testing.T, e *guestLiveEnv, in account.NewInput) account.Account {
	t.Helper()
	if in.Type == account.TypeStandard && in.PasswordHash == "" {
		hash, err := credential.Hash(dirTestPassword, credential.TestParams)
		if err != nil {
			t.Fatalf("產生測試憑據失敗：%v", err)
		}
		in.PasswordHash = hash
	}
	store := account.NewStore(timeutil.System())
	created, err := store.Create(context.Background(), e.db.SQL(), in)
	if err != nil {
		t.Fatalf("種入帳戶 %s 失敗：%v", in.LoginName, err)
	}
	return created
}

// delRejectApplication 把一筆待審批申請落成拒絕態（經倉儲的原語，不直寫 SQL）：
// 拒絕與待審批一樣都不在這本目錄裡，刪除通路對他們只有一句 1001。
func delRejectApplication(t *testing.T, e *guestLiveEnv, id idgen.ID) {
	t.Helper()
	store := account.NewStore(timeutil.System())
	changed, err := store.DecideApplication(context.Background(), e.db.SQL(), id,
		account.DecisionReject)
	if err != nil || !changed {
		t.Fatalf("落成拒絕態失敗：%v（changed=%v）", err, changed)
	}
}

// delSnapshotParts 把 deleteRowSnapshot 的逐欄拼接拆回具名欄位。
// 欄序的唯一權威是 rootadmins_delete_test.go 裡那條 SELECT——兩側共讀同一個刪除形態。
func delSnapshotParts(t *testing.T, db *database.DB, accountID string) map[string]string {
	t.Helper()
	parts := strings.Split(deleteRowSnapshot(t, db, accountID), "\x00")
	if len(parts) != 11 {
		t.Fatalf("帳戶快照欄位數異常：%d（%q）", len(parts), parts)
	}
	names := []string{"login_name", "login_name_key", "password_hash", "account_type",
		"status", "display_name", "must_change_password", "created_at", "last_login_at",
		"disabled_at", "deleted_at"}
	out := make(map[string]string, len(names))
	for i, name := range names {
		out[name] = parts[i]
	}
	return out
}

// delActionAuditCount 數 Root 域裡某個審計動作目前的筆數（零寫入斷言的對象）。
func delActionAuditCount(t *testing.T, db *database.DB, action string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM root_audit WHERE action = ?`, action).Scan(&n); err != nil {
		t.Fatalf("計數 %s 審計失敗：%v", action, err)
	}
	return n
}

// delRevokedSessionCount 數某個帳戶名下已撤銷的會話行數。
// 「第二次刪除不會讓撤銷再長一輪」必須查庫說，不能只看回應沒有這個欄位。
func delRevokedSessionCount(t *testing.T, db *database.DB, accountID string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sessions WHERE account_id = ? AND revoked_at IS NOT NULL`,
		accountID).Scan(&n); err != nil {
		t.Fatalf("計數已撤銷會話失敗：%v", err)
	}
	return n
}

// delFailureEnvelope 一次讀完錯誤回應並交出碼、訊息與 details。
// 回應體只能讀一次：分兩次讀會讓第二次拿到空內容而假綠。
func delFailureEnvelope(t *testing.T, resp *http.Response) (int, string, map[string]any) {
	t.Helper()
	text := readAllText(t, resp)
	var env struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Details map[string]any `json:"details"`
	}
	if err := json.Unmarshal([]byte(text), &env); err != nil {
		t.Fatalf("解析錯誤信封失敗：%s", text)
	}
	return env.Code, env.Message, env.Details
}

// TestAdminDeleteEndToEndOverHTTP 端到端happy path：管理員刪除一名有兩臺裝置在線的
// 普通帳戶——200 回應是「刪除後的資料庫現值」（deleted、deleted_at、DEL_ 佔位顯示名、
// 登入名原樣），撤銷數量如實回報；他自己的會話即刻換不出主體，旁人的會話照常，
// 舊口令即刻與打錯同形；審計 actor=admin 且不含任何憑據材料。
//
// 這量的是「刪除的三件合力是不是從一條 HTTP 請求全部看得見」：少任何一件，
// 界面都只能靠猜把「他被刪了、何時、幾臺裝置掉線」講成別的样子。
func TestAdminDeleteEndToEndOverHTTP(t *testing.T) {
	e := newGuestLiveEnv(t)
	bndEnablePolicy(t, e)
	admin := upgLiveAdminCookie(t, e, "del.e2e.admin")

	created := postJSON(t, e.ts, "/admin/accounts",
		stdBody("Del.E2E.Player", "被刪除的那個", stdTestInitial), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("建立目標帳戶應成功：%d %s", created.StatusCode, readAllText(t, created))
	}
	target := createdAccountID(t, created)
	bystander := delSeedAccount(t, e, account.NewInput{LoginName: "del.e2e.bystander",
		DisplayName: "旁觀者", Type: account.TypeStandard, Status: account.StatusActive})

	// 兩趟登入＝兩臺裝置（出廠裝置策略 multi，各自一份會話）。
	first := bndLogin(t, e, "Del.E2E.Player", stdTestInitial)
	second := bndLogin(t, e, "Del.E2E.Player", stdTestInitial)
	bystanderCookie := bndLogin(t, e, "del.e2e.bystander", dirTestPassword)

	resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+target.String(), "", "", admin)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("刪除應成功（200，不是 204）：%d %s", resp.StatusCode, readAllText(t, resp))
	}
	text := readAllText(t, resp)
	var envelope map[string]any
	if err := json.Unmarshal([]byte(text), &envelope); err != nil {
		t.Fatalf("解析刪除回應失敗：%s", text)
	}
	if len(envelope) != 3 {
		t.Errorf("刪除信封應恰好 account／revoked_sessions／request_id 三鍵，實際 %v", envelope)
	}
	if _, ok := envelope["request_id"].(string); !ok || envelope["request_id"] == "" {
		t.Errorf("刪除回應必須帶請求關聯 ID：%s", text)
	}
	if got, ok := envelope["revoked_sessions"].(float64); !ok || got < 1 {
		t.Errorf("刪除應回報至少撤銷了 1 份會話（本例簽發了 2），實際 %v", envelope["revoked_sessions"])
	}
	accountBody, _ := envelope["account"].(map[string]any)
	if accountBody == nil || accountBody["status"] != "deleted" {
		t.Fatalf("回應的 account 應是刪除後的現值，實際 %v", envelope["account"])
	}
	if at, ok := accountBody["deleted_at"].(string); !ok || at == "" {
		t.Errorf("回應必須帶出刪除時刻（行保留之後這是唯一記下那一刻的地方），實際 %v", accountBody)
	}
	name, _ := accountBody["display_name"].(string)
	if !strings.HasPrefix(name, "DEL_") || !strings.HasSuffix(name, "被刪除的那個") {
		t.Errorf("顯示名應是 DEL_<UTC日期>_<原名> 的匿名化佔位值，實際 %q", name)
	}
	if accountBody["login_name"] != "Del.E2E.Player" {
		t.Errorf("登入名必須原樣保留以承載歷史（名字繼續被占用），實際 %v", accountBody["login_name"])
	}
	if accountBody["account_id"] != target.String() {
		t.Errorf("回應的 account_id 應是被刪那一筆本人，實際 %v", accountBody["account_id"])
	}

	// 他自己的兩份會話即刻失效：不是「下次登入會被拒」，是手上這份已換不出主體。
	for i, cookie := range []*http.Cookie{first, second} {
		probe := getAuth(t, e.ts, "/auth/session", cookieHeader(cookie), "", "")
		if probe.StatusCode != http.StatusUnauthorized ||
			envelopeCode(t, probe) != int(CodeSessionInvalid) {
			t.Errorf("第 %d 份刪除前會話應回 2003/401，實際 %d", i+1, probe.StatusCode)
		}
	}
	// 旁人的會話不受牽連。
	if probe := getAuth(t, e.ts, "/auth/session", cookieHeader(bystanderCookie), "", ""); probe.StatusCode != http.StatusOK {
		t.Errorf("旁人的會話不該被牽連：%d", probe.StatusCode)
	}
	// 新登入被拒且與打錯口令同形：這條通路不外洩「他是被刪的」。
	blocked := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"Del.E2E.Player","password":"`+stdTestInitial+`"}`, "", nil)
	wrong := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"Del.E2E.Player","password":"明顯錯的口令-not-a-password"}`, "", nil)
	// 信封只讀一次：錯誤信封的 body 是被消费掉的，第二次去數同一個回應讀到的是空字串，
	// 那會讓「同形」這條斷言測到的是讀取順序而不是伺服器答案。
	blockedCode := envelopeCode(t, blocked)
	wrongCode := envelopeCode(t, wrong)
	if blocked.StatusCode != http.StatusUnauthorized || blockedCode != int(CodeInvalidCredentials) {
		t.Errorf("刪除後舊口令應回 2001/401，實際 %d", blocked.StatusCode)
	}
	if wrong.StatusCode != blocked.StatusCode || wrongCode != blockedCode {
		t.Errorf("被刪與口令打錯都該收斂成同一句話，實際 %d/%d vs %d/%d",
			wrong.StatusCode, wrongCode, blocked.StatusCode, blockedCode)
	}

	// 審計：恰好一筆 account.delete，操作者是那位管理員本人（不是 Root、不是被刪者）。
	// 表與欄位以 raw SQL 直讀：本步明令不新增審計查閱入口，測試也不該假裝有一條 API 讀得到它。
	var actorKind, actorID, targetID string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT actor_kind, actor_id, target_id FROM root_audit WHERE action = 'account.delete'`).
		Scan(&actorKind, &actorID, &targetID); err != nil {
		t.Fatalf("讀回刪除審計失敗：%v", err)
	}
	if actorKind != "admin" || targetID != target.String() {
		t.Errorf("刪除審計應是 admin 對那個帳戶，實際 %s／%s", actorKind, targetID)
	}
	var selfID string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT id FROM accounts WHERE login_name = ?", "del.e2e.admin").Scan(&selfID); err != nil {
		t.Fatalf("讀回操作者標識失敗：%v", err)
	}
	if actorID != selfID {
		t.Errorf("actor_id 應是操作者本人帳戶（%s），實際 %s", selfID, actorID)
	}
	if n := delActionAuditCount(t, e.db, "account.delete"); n != 1 {
		t.Errorf("一次成功刪除恰好一筆審計，實際 %d", n)
	}
	// 審計原文（原因＋前後摘要）同樣不得出現任何憑據材料：能記的只有身份事實。
	var changes, reason string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT COALESCE(changes_json,''), COALESCE(reason,'') FROM root_audit
		  WHERE action = 'account.delete'`).Scan(&changes, &reason); err != nil {
		t.Fatalf("讀回刪除審計原文失敗：%v", err)
	}
	for _, forbidden := range []string{"$argon2id$", "argon2id", stdTestInitial,
		"password_hash", "login_name_key"} {
		if strings.Contains(changes+reason, forbidden) {
			t.Errorf("刪除審計不得含 %q 的影子", forbidden)
		}
	}
	// 旁人的行逐字不動（刪除按帳戶計，沒有「順手清一輪」的通路）。
	if got := delSnapshotParts(t, e.db, bystander.ID.String()); got["status"] != "active" {
		t.Errorf("旁人應仍是 active，實際 %v", got["status"])
	}
}

// TestAdminDeleteGuestKeepsGuestShapeAndRevokesSessions 訪戶目標（type guest、
// password_hash NULL）刪除成功：終態落庫但不改出生形態——仍然是 guest、憑據仍然是 NULL、
// 登入名原樣保留；他那趟臨時會話被撤銷（訪客有會話，這是「刪除使人不能登入」對
// 臨時身分同样成立的證據），佔位顯示名與刪除時刻照常帶出。
//
// 若刪除順手把訪戶寫成 standard 或塞進一枚哈希，「他怎麼來的」這條歷史就不可還原了。
func TestAdminDeleteGuestKeepsGuestShapeAndRevokesSessions(t *testing.T) {
	e := newGuestLiveEnv(t)
	bndEnablePolicy(t, e)
	admin := upgLiveAdminCookie(t, e, "del.guest.admin")
	guestCookie, guestID := bpfEnterGuest(t, e, "被刪的旅人")

	before := delSnapshotParts(t, e.db, guestID)
	if before["account_type"] != "guest" || before["password_hash"] != "" {
		t.Fatalf("訪戶前提不成立（應為 guest 且無憑據）：%v", before)
	}
	if probe := getAuth(t, e.ts, "/auth/session", cookieHeader(guestCookie), "", ""); probe.StatusCode != http.StatusOK {
		t.Fatalf("訪客那趟會話刪除前應換得出主體，實際 %d", probe.StatusCode)
	}

	resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+guestID, "", "", admin)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("刪除訪戶應成功：%d %s", resp.StatusCode, readAllText(t, resp))
	}
	envelope := decodeJSONBody(t, resp)
	if got, ok := envelope["revoked_sessions"].(float64); !ok || got < 1 {
		t.Errorf("訪戶那趟至少有一份會話應被撤銷，實際 %v", envelope["revoked_sessions"])
	}
	accountBody, _ := envelope["account"].(map[string]any)
	if accountBody["status"] != "deleted" || accountBody["account_type"] != "guest" {
		t.Errorf("回應應是「訪戶被刪」的現值，實際 %v", accountBody)
	}
	if got := delSnapshotParts(t, e.db, guestID); got["status"] != "deleted" ||
		got["account_type"] != "guest" || got["password_hash"] != "" ||
		got["login_name"] != before["login_name"] || got["login_name_key"] != before["login_name_key"] ||
		!strings.HasPrefix(got["display_name"], "DEL_") || got["deleted_at"] == "-1" {
		t.Errorf("訪戶刪除後的行應保留出生形態、只動終態三欄，前 %v 後 %v", before, got)
	}
	probe := getAuth(t, e.ts, "/auth/session", cookieHeader(guestCookie), "", "")
	if probe.StatusCode != http.StatusUnauthorized || envelopeCode(t, probe) != int(CodeSessionInvalid) {
		t.Errorf("訪客會話在刪除後應以 2003/401 被拒，實際 %d", probe.StatusCode)
	}
}

// TestAdminDeleteBodyIsAnEmptyWhitelist 刪除的本體白名單是「零欄位」：
// reason／expected_status／purge 三份帶欄位的本體各回 1004 並點名該欄位，
// 零寫入、零審計；空本體與 {} 則是同一句話的兩種合法寫法。
//
// 默默忽略一份帶 expected_status 的本體，等於承認依據值本來可以有意義——
// 而操作者對「現行刪除時刻」拿不出誠實錨點，物理清庫更不是這條通路的能力。
func TestAdminDeleteBodyIsAnEmptyWhitelist(t *testing.T) {
	e := newGuestLiveEnv(t)
	admin := upgLiveAdminCookie(t, e, "del.body.admin")
	one := delSeedAccount(t, e, account.NewInput{LoginName: "del.body.one",
		DisplayName: "本體白名單一號", Type: account.TypeStandard, Status: account.StatusActive})
	two := delSeedAccount(t, e, account.NewInput{LoginName: "del.body.two",
		DisplayName: "本體白名單二號", Type: account.TypeStandard, Status: account.StatusActive})
	beforeOne, beforeTwo := delSnapshotParts(t, e.db, one.ID.String()),
		delSnapshotParts(t, e.db, two.ID.String())
	auditsBefore := countTableRows(t, e.db, "root_audit")

	for name, tc := range map[string]struct {
		body  string
		field string
	}{
		"企圖帶自由文本原因": {`{"reason":"他吵到別人了"}`, "reason"},
		"企圖交依據值":    {`{"expected_status":"active"}`, "expected_status"},
		"企圖指定物理清庫":  {`{"purge":true}`, "purge"},
	} {
		resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+one.ID.String(), tc.body, "", admin)
		code, message, details := delFailureEnvelope(t, resp)
		if resp.StatusCode != http.StatusBadRequest || code != int(CodeInvalidBody) {
			t.Errorf("%s：應回 1004/400，實際 %d（message %q）", name, resp.StatusCode, message)
			continue
		}
		if details["field"] != tc.field {
			t.Errorf("%s：應以 details.field 點名 %s，實際 %v", name, tc.field, details)
		}
		if got := delSnapshotParts(t, e.db, two.ID.String()); fmtEqual(beforeTwo, got) != "" {
			t.Errorf("%s：被拒的刪除不得波及尚未被動的第二筆：%s", name, fmtEqual(beforeTwo, got))
		}
	}
	if got := delSnapshotParts(t, e.db, one.ID.String()); fmtEqual(got, beforeOne) != "" {
		t.Errorf("被拒的刪除本體不得動任何欄：%s", fmtEqual(got, beforeOne))
	}
	if got := countTableRows(t, e.db, "root_audit"); got != auditsBefore {
		t.Errorf("被拒的刪除不得追加審計（前 %d 後 %d）", auditsBefore, got)
	}

	// 空本體與 {} 是同一句話的兩種合法寫法：刪除不選欄位，不該有「忘了填所以失敗」的差別。
	if resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+one.ID.String(), "", "", admin); resp.StatusCode != http.StatusOK {
		t.Fatalf("空本體的 DELETE 應成功：%d %s", resp.StatusCode, readAllText(t, resp))
	}
	if resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+two.ID.String(), `{}`, "", admin); resp.StatusCode != http.StatusOK {
		t.Fatalf("帶空物件的 DELETE 應成功：%d %s", resp.StatusCode, readAllText(t, resp))
	}
}

// fmtEqual 比對兩份快照並回報第一處不一致（空字串為一致）。
// 不一致時把兩側現值都帶進訊息，否則測試失敗只剩一句「動了」而查不出動了哪欄。
func fmtEqual(before, after map[string]string) string {
	for key, want := range before {
		if got := after[key]; got != want {
			return key + "：前 " + want + "／後 " + got
		}
	}
	return ""
}

// TestAdminDeleteRepeatIsTerminalWithOneAudit 重複刪除是終態拒絕而不是第二次成功：
// 第二次 DELETE 回 409/2027 並有一句可展示的小話；刪除審計永遠只有一筆、
// 已撤銷會話數不再成長、現值逐字不動。
//
// 把第二次報成 200 是在審計與真相之間造出一件沒發生過的事；報成 1001 則讓操作者
// 對著目錄裡明明列著的人懷疑標識寫錯了。
func TestAdminDeleteRepeatIsTerminalWithOneAudit(t *testing.T) {
	e := newGuestLiveEnv(t)
	admin := upgLiveAdminCookie(t, e, "del.again.admin")
	target := delSeedAccount(t, e, account.NewInput{LoginName: "del.again.target",
		DisplayName: "被接連刪除的人", Type: account.TypeStandard, Status: account.StatusActive})
	bndLogin(t, e, "del.again.target", dirTestPassword)

	first := sendAdminDelete(t, e.ts, "/admin/accounts/"+target.ID.String(), "", "", admin)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("首次刪除應成功：%d %s", first.StatusCode, readAllText(t, first))
	}
	envelope := decodeJSONBody(t, first)
	revokedFirst, _ := envelope["revoked_sessions"].(float64)
	before := delSnapshotParts(t, e.db, target.ID.String())
	revokedRows := delRevokedSessionCount(t, e.db, target.ID.String())

	second := sendAdminDelete(t, e.ts, "/admin/accounts/"+target.ID.String(), "", "", admin)
	code, message, _ := delFailureEnvelope(t, second)
	if second.StatusCode != http.StatusConflict || code != int(CodeAccountDeleted) {
		t.Errorf("重複刪除應回 2027/409，實際 %d 碼 %d", second.StatusCode, code)
	}
	if strings.TrimSpace(message) == "" {
		t.Error("2027 必須有一句可展示的小話")
	}
	if after := delSnapshotParts(t, e.db, target.ID.String()); fmtEqual(before, after) != "" {
		t.Errorf("被拒的第二次刪除不得動任何欄：%s", fmtEqual(before, after))
	}
	if n := delActionAuditCount(t, e.db, "account.delete"); n != 1 {
		t.Errorf("全程只應有一筆刪除審計，實際 %d", n)
	}
	if got := delRevokedSessionCount(t, e.db, target.ID.String()); got != revokedRows {
		t.Errorf("第二次刪除不得讓撤銷再成長（前 %d 後 %d）", revokedRows, got)
	}
	if revokedFirst < 1 {
		t.Errorf("首次刪除應至少撤銷 1 份會話，實際 %v", envelope["revoked_sessions"])
	}
	// 再登入也不該有任何通路把他帶回門內。
	if login := postJSON(t, e.ts, "/auth/login",
		`{"login_name":"del.again.target","password":"`+dirTestPassword+`"}`, "", nil); login.StatusCode != http.StatusUnauthorized {
		t.Errorf("刪除態的重新登入應被拒（2001/401），實際 %d", login.StatusCode)
	}
}

// TestAdminDeleteOtherWritePathsRefuseDeletedTargets 刪除終態罩住其餘四條寫入通路：
// 編輯、停用／恢復、重置憑據各回 409/2027 且零寫入零審計；被刪除的訪戶走升級
// 也是 2027（終態判定在「他此刻是不是可升級訪戶」之前）——
// 「已刪除」對这四條通路都是同一句話，沒有一條能把他拉回來或順手改一欄。
func TestAdminDeleteOtherWritePathsRefuseDeletedTargets(t *testing.T) {
	e := newGuestLiveEnv(t)
	bndEnablePolicy(t, e)
	admin := upgLiveAdminCookie(t, e, "del.term.admin")
	target := delSeedAccount(t, e, account.NewInput{LoginName: "del.term.target",
		DisplayName: "terminal 靶", Type: account.TypeStandard, Status: account.StatusActive})
	if resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+target.ID.String(), "", "", admin); resp.StatusCode != http.StatusOK {
		t.Fatalf("前置刪除應成功：%d %s", resp.StatusCode, readAllText(t, resp))
	}
	before := delSnapshotParts(t, e.db, target.ID.String())

	cases := map[string]*http.Response{
		"編輯顯示名": putJSON(t, e.ts, "/admin/accounts/"+target.ID.String(),
			`{"display_name":"不該落庫","expected_display_name":"terminal 靶"}`, "",
			map[string]string{"Cookie": cookieHeader(admin)}),
		"停用": putJSON(t, e.ts, statusPath(target.ID), statusBody("disabled", "active"), "",
			map[string]string{"Cookie": cookieHeader(admin)}),
		"重置憑據": putJSON(t, e.ts, passwordPath(target.ID), resetBody(stdTestResetPassword), "",
			map[string]string{"Cookie": cookieHeader(admin)}),
	}
	for name, resp := range cases {
		code, message, _ := delFailureEnvelope(t, resp)
		if resp.StatusCode != http.StatusConflict || code != int(CodeAccountDeleted) {
			t.Errorf("%s：對已刪除者應回 2027/409，實際 %d 碼 %d", name, resp.StatusCode, code)
		}
		if message == "" {
			t.Errorf("%s：2027 必須有一句可展示的案", name)
		}
	}
	if after := delSnapshotParts(t, e.db, target.ID.String()); fmtEqual(before, after) != "" {
		t.Errorf("三條被拒的寫入不得動現值：%s", fmtEqual(before, after))
	}
	for _, action := range []string{"account.profile_update", "account.disable",
		"account.enable", "account.password_reset"} {
		if n := delActionAuditCount(t, e.db, action); n != 0 {
			t.Errorf("被終態拒絕的 %s 不該留審計，實際 %d 筆", action, n)
		}
	}

	// 訪戶被刪之後打升級：2027 而不是 2024——2024 暗示「重讀後那顆按鈕還在」，
	// 而對一個已刪除的人那顆按鈕永遠不會再出現。
	guestCookie, guestID := bpfEnterGuest(t, e, "刪除後升級的旅人")
	_ = guestCookie
	if resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+guestID, "", "", admin); resp.StatusCode != http.StatusOK {
		t.Fatalf("刪除訪戶應成功：%d %s", resp.StatusCode, readAllText(t, resp))
	}
	guestBefore := delSnapshotParts(t, e.db, guestID)
	upgrade := putJSON(t, e.ts, "/admin/accounts/"+guestID+"/upgrade",
		`{"login_name":"del.term.upgrade","password":"`+stdTestInitial+`"}`, "",
		map[string]string{"Cookie": cookieHeader(admin)})
	code, _, _ := delFailureEnvelope(t, upgrade)
	if upgrade.StatusCode != http.StatusConflict || code != int(CodeAccountDeleted) {
		t.Errorf("對已刪除訪戶升級應回 2027/409，實際 %d 碼 %d", upgrade.StatusCode, code)
	}
	if upgrade.StatusCode == http.StatusInternalServerError {
		t.Error("終態拒絕絕不該以 500 對外")
	}
	if after := delSnapshotParts(t, e.db, guestID); fmtEqual(guestBefore, after) != "" {
		t.Errorf("被拒的升級不得動訪戶一行：%s", fmtEqual(guestBefore, after))
	}
	if n := delActionAuditCount(t, e.db, "account.guest_upgrade"); n != 0 {
		t.Errorf("被拒的升級不該留審計，實際 %d 筆", n)
	}
}

// TestAdminDeleteRetiredGuestGetsRetiredSentenceNotFiveHundred 已被綁走（retired）
// 的訪戶是另一種終態：刪除回 409/2028（不是 500、不是 1001、不是 2027），
// 編輯通路對同一目標也回 409/2028——退休行每一欄都被庫釘住，讓寫去撞觸發器
// 只會換成一個查不出原因的 500，這正是本次修掉的缺陷形態。
//
// 2028 那句處置指向綁定留痕而不是「什麼都別再做」，所以不能與 2027 共用一枚碼。
func TestAdminDeleteRetiredGuestGetsRetiredSentenceNotFiveHundred(t *testing.T) {
	e := newGuestLiveEnv(t)
	bndEnablePolicy(t, e)
	admin := upgLiveAdminCookie(t, e, "del.ret.admin")
	guestCookie, guestID := bpfEnterGuest(t, e, "將被綁走的旅人")
	targetID, targetCookie := bndStandardAccount(t, e, admin, "Del.Ret.Target")

	issued := bndIssue(t, e, guestID, `{"target_account_id":"`+targetID+`"}`, admin)
	if issued.StatusCode != http.StatusOK {
		t.Fatalf("簽發應成功：%d %s", issued.StatusCode, readAllText(t, issued))
	}
	ticket := decodeJSONBody(t, issued)["ticket"].(string)
	claim := bndClaimPost(t, e, "", `{"ticket":"`+ticket+`"}`, targetCookie)
	if claim.StatusCode != http.StatusOK {
		t.Fatalf("本人確認綁定應成功：%d %s", claim.StatusCode, readAllText(t, claim))
	}
	before := delSnapshotParts(t, e.db, guestID)
	if before["status"] != "retired" {
		t.Fatalf("綁定後來源應是 retired（測試前提），實際 %v", before["status"])
	}

	resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+guestID, "", "", admin)
	code, message, _ := delFailureEnvelope(t, resp)
	if resp.StatusCode == http.StatusInternalServerError {
		t.Fatal("刪除退休訪戶絕不該以 500 對外（觸發器缺陷形態）")
	}
	if resp.StatusCode != http.StatusConflict || code != int(CodeAccountRetired) {
		t.Errorf("刪除退休訪戶應回 2028/409，實際 %d 碼 %d", resp.StatusCode, code)
	}
	if strings.TrimSpace(message) == "" {
		t.Error("2028 必須有一句可展示的案")
	}

	// 編輯通路對同一目標也換 2028 這一_specific 句（此前撞觸發器露出 500）。
	edit := putJSON(t, e.ts, "/admin/accounts/"+guestID,
		`{"display_name":"不該落庫","expected_display_name":"將被綁走的旅人"}`, "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if edit.StatusCode == http.StatusInternalServerError {
		t.Fatal("編輯退休訪戶絕不該以 500 對外")
	}
	editCode, _, _ := delFailureEnvelope(t, edit)
	if edit.StatusCode != http.StatusConflict || editCode != int(CodeAccountRetired) {
		t.Errorf("編輯退休訪戶應回 2028/409，實際 %d 碼 %d", edit.StatusCode, editCode)
	}

	// 停用通路同樣落在退休那一句（四條寫入通路共用同一個終態判定點）。
	status := putJSON(t, e.ts, "/admin/accounts/"+guestID+"/status",
		statusBody("disabled", "active"), "", map[string]string{"Cookie": cookieHeader(admin)})
	if status.StatusCode == http.StatusInternalServerError {
		t.Fatal("停用退休訪戶絕不該以 500 對外")
	}
	statusCode, _, _ := delFailureEnvelope(t, status)
	if status.StatusCode != http.StatusConflict || statusCode != int(CodeAccountRetired) {
		t.Errorf("停用退休訪戶應回 2028/409，實際 %d 碼 %d", status.StatusCode, statusCode)
	}

	if after := delSnapshotParts(t, e.db, guestID); fmtEqual(before, after) != "" {
		t.Errorf("被 2028 拒絕的請求不得動退休行任何一欄：%s", fmtEqual(before, after))
	}
	if n := delActionAuditCount(t, e.db, "account.delete"); n != 0 {
		t.Errorf("被拒的刪除不得留刪除審計，實際 %d 筆", n)
	}
	if n := delActionAuditCount(t, e.db, "account.profile_update"); n != 0 {
		t.Errorf("被拒的編輯不得留編輯審計，實際 %d 筆", n)
	}
	// 綁定留痕的源會話早已在綁定時撤銷；刪除被拒也不會再多撤什麼。
	if got := delRevokedSessionCount(t, e.db, guestID); got < 1 {
		t.Errorf("綁定應已撤銷來源會話（前提核對），實際 %d", got)
	}
	_ = guestCookie
}

// TestAdminDeleteAuthorizationAndTargetMatrix 刪除入口的主體與目標矩陣：
// 匿名 2002、普通帳戶 2011、跨站來源 2005 且零寫入；目標側的持有授予者
// （另一位管理員）、操作者自己、Root 保留標識、幽靈標識、格式非法標識、
// 待審批與已拒絕申請人——七種企圖收斂成與查無此人同一句 1001。
//
// 這條端點不是標識探針：把它們分開等於讓零權限的人用回應碼列舉「哪些標識属于哪本書」。
func TestAdminDeleteAuthorizationAndTargetMatrix(t *testing.T) {
	e := newGuestLiveEnv(t)
	admin := upgLiveAdminCookie(t, e, "del.acl.admin")
	victim := delSeedAccount(t, e, account.NewInput{LoginName: "del.acl.victim",
		DisplayName: "矩陣靶", Type: account.TypeStandard, Status: account.StatusActive})
	plain := delSeedAccount(t, e, account.NewInput{LoginName: "del.acl.plain",
		DisplayName: "一個普通帳戶", Type: account.TypeStandard, Status: account.StatusActive})
	plainCookie := bndLogin(t, e, "del.acl.plain", dirTestPassword)

	peerCreated := postJSON(t, e.ts, "/root/admins",
		`{"login_name":"del.acl.peer","display_name":"同級管理員","password":"`+upgTestAdminInitial+`"}`,
		"", map[string]string{"Cookie": cookieHeader(e.rootCookie(t))})
	if peerCreated.StatusCode != http.StatusCreated {
		t.Fatalf("開設同級管理員應成功：%d %s", peerCreated.StatusCode, readAllText(t, peerCreated))
	}
	peerID, _ := decodeJSONBody(t, peerCreated)["account_id"].(string)
	if peerID == "" {
		t.Fatal("開設回應應帶 account_id（測試前提）")
	}
	var selfID string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT id FROM accounts WHERE login_name = ?", "del.acl.admin").Scan(&selfID); err != nil {
		t.Fatalf("讀回操作者標識失敗：%v", err)
	}
	pending := delSeedAccount(t, e, account.NewInput{LoginName: "del.acl.pending",
		DisplayName: "待審批的申請", Type: account.TypeStandard, Status: account.StatusPending})
	rejected := delSeedAccount(t, e, account.NewInput{LoginName: "del.acl.rejected",
		DisplayName: "被拒絕的申請", Type: account.TypeStandard, Status: account.StatusPending})
	delRejectApplication(t, e, rejected.ID)
	ghost, err := idgen.New()
	if err != nil {
		t.Fatalf("產生幽靈標識失敗：%v", err)
	}

	// 主體側：匿名 2002、普通帳戶 2011；兩趟都不該碰到目標。
	anon := sendAdminDelete(t, e.ts, "/admin/accounts/"+victim.ID.String(), "", "", nil)
	if anon.StatusCode != http.StatusUnauthorized || envelopeCode(t, anon) != int(CodeNotAuthenticated) {
		t.Errorf("匿名刪除應回 2002/401，實際 %d", anon.StatusCode)
	}
	denied := sendAdminDelete(t, e.ts, "/admin/accounts/"+victim.ID.String(), "", "", plainCookie)
	if denied.StatusCode != http.StatusForbidden || envelopeCode(t, denied) != int(CodePermissionDenied) {
		t.Errorf("普通帳戶刪除應回 2011/403，實際 %d", denied.StatusCode)
	}
	// 跨站來源：先問來源，連目標都不問。
	crossSite := sendAdminDelete(t, e.ts, "/admin/accounts/"+victim.ID.String(), "",
		"http://evil.example", admin)
	if crossSite.StatusCode != http.StatusForbidden ||
		envelopeCode(t, crossSite) != int(CodeOriginForbidden) {
		t.Errorf("跨站來源刪除應回 2005/403，實際 %d", crossSite.StatusCode)
	}

	// 目標側七種企圖同回 1001/404（同形不可分辨）。
	for name, probe := range map[string]string{
		"同級管理員":     peerID,
		"操作者自己":     selfID,
		"Root 保留標識": rootReservedAccountID(t),
		"幽靈標識":      ghost.String(),
		"格式非法的標識":   "not-a-uuid",
		"待審批申請人":    pending.ID.String(),
		"已拒絕申請人":    rejected.ID.String(),
	} {
		resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+probe, "", "", admin)
		if resp.StatusCode != http.StatusNotFound || envelopeCode(t, resp) != int(CodeNotFound) {
			t.Errorf("刪除 %s 應回 1001/404 同形，實際 %d", name, resp.StatusCode)
		}
	}

	// 整組被拒的請求對目標逐字不動、一筆刪除審計都不留。
	if got := delSnapshotParts(t, e.db, victim.ID.String()); got["status"] != "active" ||
		got["deleted_at"] != "-1" {
		t.Errorf("被拒的矩陣不得動目標現值，實際 %v", got)
	}
	// 那個只拿到 2011 的普通帳戶本人也不該被順手改一欄：授權判定不帶副作用。
	if got := delSnapshotParts(t, e.db, plain.ID.String()); got["status"] != "active" ||
		got["deleted_at"] != "-1" {
		t.Errorf("被拒主體的行不得被順手动過，實際 %v", got)
	}
	if n := delActionAuditCount(t, e.db, "account.delete"); n != 0 {
		t.Errorf("被拒的刪除不得寫審計，實際 %d 筆", n)
	}
}

// TestAdminDeleteDirectoryAndDetailStillShowDeletedRows 刪除後的目錄與詳情：
// ?status=deleted 是被受理的篩選值（200 列出該行並帶 deleted_at），默認名冊也含他；
// 未刪除的行不帶 deleted_at 鍵（缺席是事實的缺席）；詳情 200 帶 status=deleted、
// DEL_ 佔位顯示名與 deleted_at；?status=pending 仍然 1004——待審批不屬於這本書。
//
// 已刪者從名冊消失會讓「列得出、點得開、動不了」退化成界面只剩「查無此人」的錯答案，
// 歷史身份回溯無從談起。
func TestAdminDeleteDirectoryAndDetailStillShowDeletedRows(t *testing.T) {
	e := newGuestLiveEnv(t)
	admin := upgLiveAdminCookie(t, e, "del.dir.admin")
	gone := delSeedAccount(t, e, account.NewInput{LoginName: "del.dir.gone",
		DisplayName: "要被刪的", Type: account.TypeStandard, Status: account.StatusActive})
	keep := delSeedAccount(t, e, account.NewInput{LoginName: "del.dir.keep",
		DisplayName: "留下的", Type: account.TypeStandard, Status: account.StatusActive})
	if resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+gone.ID.String(), "", "", admin); resp.StatusCode != http.StatusOK {
		t.Fatalf("刪除應成功：%d %s", resp.StatusCode, readAllText(t, resp))
	}

	filtered := getAuth(t, e.ts, "/admin/accounts?status=deleted", cookieHeader(admin), "", "")
	if filtered.StatusCode != http.StatusOK {
		t.Fatalf("?status=deleted 應是被受理的篩選值（200），實際 %d：%s",
			filtered.StatusCode, readAllText(t, filtered))
	}
	rows := rowsOf(t, directoryBody(t, filtered))
	if len(rows) != 1 || rows[0]["login_name"] != "del.dir.gone" {
		t.Fatalf("deleted 篩選應恰好列出那一筆，實際 %v", rows)
	}
	if at, ok := rows[0]["deleted_at"].(string); !ok || at == "" {
		t.Errorf("目錄行必須自己帶刪除時刻（不必點開詳情才知道），實際 %v", rows[0])
	}

	defaultPage := getAuth(t, e.ts, "/admin/accounts?page_size=50", cookieHeader(admin), "", "")
	defaultRows := rowsOf(t, directoryBody(t, defaultPage))
	seenGone, seenKeep := false, false
	for _, row := range defaultRows {
		switch row["login_name"] {
		case "del.dir.gone":
			seenGone = true
			if row["status"] != "deleted" {
				t.Errorf("默認名冊裡已刪者的狀態應如實帶出，實際 %v", row)
			}
		case "del.dir.keep":
			seenKeep = true
			if _, ok := row["deleted_at"]; ok {
				t.Errorf("非刪除態的行不該帶 deleted_at：%v", row)
			}
		}
	}
	if !seenGone || !seenKeep {
		t.Errorf("默認名冊應同時列出已刪者與在冊者，實際 %v", defaultRows)
	}

	detail := getAuth(t, e.ts, "/admin/accounts/"+gone.ID.String(), cookieHeader(admin), "", "")
	if detail.StatusCode != http.StatusOK {
		t.Fatalf("已刪者的詳情仍應 200：%d", detail.StatusCode)
	}
	text := readAllText(t, detail)
	for _, want := range []string{`"status":"deleted"`, `"deleted_at":"`, "DEL_"} {
		if !strings.Contains(text, want) {
			t.Errorf("已刪者的詳情應帶 %s，實際 %s", want, text)
		}
	}
	_ = keep

	badFilter := getAuth(t, e.ts, "/admin/accounts?status=pending", cookieHeader(admin), "", "")
	if badFilter.StatusCode != http.StatusBadRequest || envelopeCode(t, badFilter) != int(CodeInvalidBody) {
		t.Errorf("?status=pending 應回 1004/400（那不屬於這本書），實際 %d", badFilter.StatusCode)
	}
}

// TestAdminDeleteBindPreflightWithDeletedSidesIsPreviewNotError 綁定預檢遇到終態的一側
// 不是錯誤信封：刪除的來源 → 200 預覽、executable=false、blockers 含 source_not_active；
// 刪除的目標 → 200 預覽、blockers 含 target_not_active。
//
// 預覽回答的是「這一對能不能綁、卡在哪」，終態正是可回答的卡點之一；
// 報成 4xx 錯誤信封會讓界面把「他已被刪」講成「標識寫錯了」。
func TestAdminDeleteBindPreflightWithDeletedSidesIsPreviewNotError(t *testing.T) {
	e := newGuestLiveEnv(t)
	bndEnablePolicy(t, e)
	admin := upgLiveAdminCookie(t, e, "del.bpf.admin")
	sourceCookie, sourceID := bpfEnterGuest(t, e, "刪除後預檢的源")
	targetID := bpfLiveStandardAccount(t, e, admin, "Del.Bpf.Target")

	if resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+sourceID, "", "", admin); resp.StatusCode != http.StatusOK {
		t.Fatalf("刪除來源訪戶應成功：%d %s", resp.StatusCode, readAllText(t, resp))
	}
	resp := bpfPost(t, e, sourceID, `{"target_account_id":"`+targetID+`"}`, admin)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("刪除態來源的預檢應是 200 預覽而不是錯誤信封：%d %s",
			resp.StatusCode, readAllText(t, resp))
	}
	body := decodeJSONBody(t, resp)
	if body["executable"] != false {
		t.Errorf("刪除態來源不可綁定，應 executable=false，實際 %v", body["executable"])
	}
	blockers, _ := body["blockers"].([]any)
	joined := make([]string, 0, len(blockers))
	for _, b := range blockers {
		joined = append(joined, b.(string))
	}
	if !containsAll(joined, "source_not_active") {
		t.Errorf("blockers 應含 source_not_active，實際 %v", joined)
	}
	if impacts, ok := body["impacts"].([]any); !ok || len(impacts) != 0 {
		t.Errorf("被阻止的綁定不該帶任何影響，實際 %#v", body["impacts"])
	}
	// 預檢是純只讀：被刪者的現值不因預覽再動一欄。
	if got := delSnapshotParts(t, e.db, sourceID); got["status"] != "deleted" {
		t.Errorf("預檢不得改寫已刪者現值，實際 %v", got["status"])
	}
	_ = sourceCookie

	// 目標側：另一個活著的訪戶對已刪除的普通帳戶做預檢 → target_not_active。
	otherCookie, otherID := bpfEnterGuest(t, e, "目側預檢的旅人")
	if resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+targetID, "", "", admin); resp.StatusCode != http.StatusOK {
		t.Fatalf("刪除目標普通帳戶應成功：%d %s", resp.StatusCode, readAllText(t, resp))
	}
	resp2 := bpfPost(t, e, otherID, `{"target_account_id":"`+targetID+`"}`, admin)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("刪除態目標的預檢也應是 200 預覽：%d %s", resp2.StatusCode, readAllText(t, resp2))
	}
	body2 := decodeJSONBody(t, resp2)
	if body2["executable"] != false {
		t.Errorf("刪除態目標不可綁定，應 executable=false，實際 %v", body2["executable"])
	}
	blockers2, _ := body2["blockers"].([]any)
	joined2 := make([]string, 0, len(blockers2))
	for _, b := range blockers2 {
		joined2 = append(joined2, b.(string))
	}
	if !containsAll(joined2, "target_not_active") {
		t.Errorf("blockers 應含 target_not_active，實際 %v", joined2)
	}
	// 活著的那位旅人不受牽連：會話照常在、行仍是 active。
	if got := delSnapshotParts(t, e.db, otherID); got["status"] != "active" {
		t.Errorf("預檢不得動另一位訪戶，實際 %v", got["status"])
	}
	if sess := getAuth(t, e.ts, "/auth/session", cookieHeader(otherCookie), "", ""); sess.StatusCode != http.StatusOK {
		t.Errorf("旁戶會話不該被牽連：%d", sess.StatusCode)
	}
}

// TestAdminDeleteRegistrationStatusRefusesDeletedApplicant 申請人經審批轉正之後被刪除：
// 他拿自己正確的登入名與口令查申請狀態，伺服器以「與憑據失敗同一句話」（2001）回絕，
// 而不是復述一份「已批准」的結局，也不是 2020／2021 那兩句。
//
// 若這條匿名通路還能報出 approved，刪除就留了一扇「口令對就等於承認他進來過」的旁門；
// 同形拒絶守的是不外洩「這個名字存在過、並且被誰處置過」。
func TestAdminDeleteRegistrationStatusRefusesDeletedApplicant(t *testing.T) {
	e := newReviewEnv(t)
	e.setSelfRegisterMode(t, "approval")
	admin := e.liveAdminCookie(t, "del.reg.admin")

	application := e.fileApplication(t, "Del.Reg.One", "批准後被刪的申請人")
	accountID, _ := application["account_id"].(string)
	if accountID == "" {
		t.Fatalf("提交回應該帶穩定標識：%v", application)
	}
	if decided := e.decide(t, accountID, decisionBody("approve"), admin, nil); decided.StatusCode != http.StatusOK {
		t.Fatalf("批准應成功：%d %s", decided.StatusCode, readAllText(t, decided))
	}
	// 批准之後他確實進得來（前提核對），刪除之後立刻進不來。
	e.loginAs(t, "Del.Reg.One", reviewTestApplicant)

	resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+accountID, "", "", admin)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("管理員刪除轉正後的申請人應成功：%d %s", resp.StatusCode, readAllText(t, resp))
	}

	status := postJSON(t, e.ts, "/auth/registration-status",
		applicationStatusBody("Del.Reg.One", reviewTestApplicant), "", nil)
	code, _, _ := delFailureEnvelope(t, status)
	if status.StatusCode == http.StatusOK {
		t.Error("已刪除的申請人查狀態絕不該拿到 200（那等於復述 approved）")
	}
	if code == int(CodeNotAnApplication) || code == 2021 {
		t.Errorf("已刪除者該收斂進憑據失敗那一句，而不是暴露審批鏈的結論：%d", code)
	}
	if code != int(CodeInvalidCredentials) || status.StatusCode != http.StatusUnauthorized {
		t.Errorf("憑據成立但人已刪除應以 2001/401 同形拒絶，實際 %d 碼 %d", status.StatusCode, code)
	}
	if login := e.loginRaw(t, "Del.Reg.One", reviewTestApplicant); login.StatusCode != http.StatusUnauthorized ||
		envelopeCode(t, login) != int(CodeInvalidCredentials) {
		t.Errorf("刪除後登入應與口令打錯同形（2001），實際 %d", login.StatusCode)
	}
}

// TestAdminDeleteNeverEchoesCredentialMaterial 刪除的成功回應與它的審計原文都不該出現
// 任何憑據材料：口令明文、Argon2id 雜湊、雜湊欄位名、會話秘密的庫內欄位名、
// 內部正規化鍵——這條通路能公開的只有「這個人已不在、何時不在、幾臺裝置掉線」。
func TestAdminDeleteNeverEchoesCredentialMaterial(t *testing.T) {
	e := newGuestLiveEnv(t)
	bndEnablePolicy(t, e)
	admin := upgLiveAdminCookie(t, e, "del.leak.admin")
	created := postJSON(t, e.ts, "/admin/accounts",
		stdBody("Del.Leak.Player", "不漏的", stdTestInitial), "",
		map[string]string{"Cookie": cookieHeader(admin)})
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("建立應成功：%d %s", created.StatusCode, readAllText(t, created))
	}
	target := createdAccountID(t, created)
	bndLogin(t, e, "Del.Leak.Player", stdTestInitial)

	text := readAllText(t, sendAdminDelete(t, e.ts, "/admin/accounts/"+target.String(), "", "", admin))
	for _, forbidden := range []string{stdTestInitial, "$argon2id$", "argon2id",
		"password_hash", "token_hash", "login_name_key"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("刪除回應不得含 %q：%s", forbidden, text)
		}
	}
	// 刪除是終態：回應也不該暗示存在任何「恢復」的通路。
	if strings.Contains(text, "restore") || strings.Contains(text, "undelete") {
		t.Errorf("刪除是終態，回應不得出現恢復字樣：%s", text)
	}

	var record string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT COALESCE(reason,'') || ' ' || COALESCE(changes_json,'') FROM root_audit
		  WHERE action = 'account.delete'`).Scan(&record); err != nil {
		t.Fatalf("讀回刪除審計失敗：%v", err)
	}
	for _, forbidden := range []string{stdTestInitial, "$argon2id$", "argon2id",
		"password_hash", "token_hash", "login_name_key"} {
		if strings.Contains(record, forbidden) {
			t.Errorf("刪除審計不得含 %q 的影子", forbidden)
		}
	}
	// 審計要盡它的本職：刪除前的顯示名快照必須在。
	if !strings.Contains(record, "不漏的") {
		t.Errorf("刪除審計應含刪除前的顯示名快照，實際 %s", record)
	}
}

// TestAdminDeleteOnlyTouchesItsOwnTarget 刪除只動它那一個目標：旁人的行逐字不動、
// 旁人的會話照常在門內、Root 與操作者的會話不受牽連，root_audit 全表只多那一筆刪除。
//
// 撤銷是按帳戶計的事實；任何「順手清一輪」的實現在這一格都必須是可證偽的。
func TestAdminDeleteOnlyTouchesItsOwnTarget(t *testing.T) {
	e := newGuestLiveEnv(t)
	admin := upgLiveAdminCookie(t, e, "del.only.admin")
	victim := delSeedAccount(t, e, account.NewInput{LoginName: "del.only.victim",
		DisplayName: "唯一該動的", Type: account.TypeStandard, Status: account.StatusActive})
	bystander := delSeedAccount(t, e, account.NewInput{LoginName: "del.only.bystander",
		DisplayName: "不該動的", Type: account.TypeStandard, Status: account.StatusActive})
	bystanderCookie := bndLogin(t, e, "del.only.bystander", dirTestPassword)
	rootCookie := e.rootCookie(t)
	auditsBefore := countTableRows(t, e.db, "root_audit")
	bystanderBefore := delSnapshotParts(t, e.db, bystander.ID.String())

	if resp := sendAdminDelete(t, e.ts, "/admin/accounts/"+victim.ID.String(), "", "", admin); resp.StatusCode != http.StatusOK {
		t.Fatalf("刪除應成功：%d %s", resp.StatusCode, readAllText(t, resp))
	}

	// 旁人的行逐字不動；他與 Root、操作者的會話都在門內。
	if after := delSnapshotParts(t, e.db, bystander.ID.String()); fmtEqual(bystanderBefore, after) != "" {
		t.Errorf("刪除動了旁人一行：%s", fmtEqual(bystanderBefore, after))
	}
	if sess := getAuth(t, e.ts, "/auth/session", cookieHeader(bystanderCookie), "", ""); sess.StatusCode != http.StatusOK {
		t.Errorf("旁人的會話不該被牽連：%d", sess.StatusCode)
	}
	if sess := getAuth(t, e.ts, "/auth/session", cookieHeader(rootCookie), "", ""); sess.StatusCode != http.StatusOK {
		t.Errorf("Root 自己的會話不該被牽連：%d", sess.StatusCode)
	}
	if sess := getAuth(t, e.ts, "/auth/session", cookieHeader(admin), "", ""); sess.StatusCode != http.StatusOK {
		t.Errorf("操作者的會話不該被牽連：%d", sess.StatusCode)
	}
	// 全表只多那一筆刪除審計（別人的一欄都不動，包括旁人在冊期間的既有記錄）。
	if got := countTableRows(t, e.db, "root_audit"); got != auditsBefore+1 {
		t.Errorf("刪除之後 root_audit 應恰好多 1 筆（前 %d 後 %d）", auditsBefore, got)
	}
	// 那一筆唯一的 account.delete 必須指向被刪者（本現場只有這一次刪除動作）。
	if n := delActionAuditCount(t, e.db, "account.delete"); n != 1 {
		t.Fatalf("刪除審計應恰好一筆，實際 %d", n)
	}
	var targetID string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT target_id FROM root_audit WHERE action = 'account.delete'`).
		Scan(&targetID); err != nil {
		t.Fatalf("讀回刪除審計失敗：%v", err)
	}
	if targetID != victim.ID.String() {
		t.Errorf("那唯一一筆新增審計應指向被刪者，實際 %s", targetID)
	}
}

// TestAdminDeleteTerminalCodesCarryAllFourLocales 本步发布的两枚码（2027 已刪除、
// 2028 已退休）必須四語言齊備，而且未支援語言照舊回退英文——錯誤目錄缺任何一格，
// 界面就會把「伺服器沒有這句話」顯示成空白，那是比措辭不當更壞的失敗形態。
//
// 這一格同時釘住一件反向的事：Root 那側已發布的 2015 的措辭一字未動。兩本名冊的
// 範圍規則不同（這本列不到持有授予者），因此各說各話，而不是讓一枚已發布的碼
// 順帶改寫它對操作者說的主體。
func TestAdminDeleteTerminalCodesCarryAllFourLocales(t *testing.T) {
	for _, code := range []ErrorCode{CodeAccountDeleted, CodeAccountRetired} {
		for _, locale := range []string{LocaleZhCN, LocaleZhTW, LocaleEnUS, LocaleJaJP} {
			if messageFor(code, locale) == "" {
				t.Errorf("%d 缺少 %s 訊息", int(code), locale)
			}
		}
		// 未支援語言一律回退英文，且兩枚碼各自的話術不能互相同形——
		// 「已被刪除」與「已被綁走」若收成同一句話，界面就分不出該讀哪條留痕。
		if messageFor(code, "fr-FR") != messageFor(code, LocaleEnUS) {
			t.Errorf("%d 的未支援語言未回退英文", int(code))
		}
	}
	if messageFor(CodeAccountDeleted, LocaleEnUS) ==
		messageFor(CodeAccountRetired, LocaleEnUS) {
		t.Error("2027 與 2028 的訊息同形：兩種終態處置不同，必須各自成句")
	}
	if messageFor(CodeAdminDeleted, LocaleEnUS) == "" {
		t.Error("2015 的既有訊息不得被清空（已發布碼只增不刪）")
	}
}
