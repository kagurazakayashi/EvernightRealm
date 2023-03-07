// bindexecute_test.go 是「訪戶綁定的執行」用例層的定向證據：
// 本步要求驗的每一件都在真庫真交易上量過——正常綁定落地的四件合力、
// 源會話按批准規則失效而源令牌沒有變成目標令牌、目標的憑據與權限一點都沒擴大、
// 同一來源被重複請求與二次簽發時的唯一出口、憑證重放與換人使用、簽發之後事實漂移時的
// 「回去重新預檢」、以及交易中途失敗時原先可用關係完整保留。
//
// 涵蓋範圍是老實的一層：本步只動帳戶層（accounts／sessions／guest_bind_tickets／
// guest_account_bindings／root_audit）。活動名冊、資產帳本與 NPC 關係尚未開發，
// 因此這裡斷言的是「那些引用不存在時綁定可行」與「一旦出现未登记的引用就整体拒绝」，
// 不宣稱驗過跨活動的身分搬遷。
//
// 全程使用本次專屬的暫存庫與注入時鐘：不佔 5206、不碰任何真實資料目錄。
// 測試一律不帶 -race（本機 cgo 工具鏈限制，見既有交接），併發語意以服務層真庫
// 真交易的串行化與資料庫條件斷言覆蓋。
package stdacct

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/guestbind"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// bindIssueAction 是簽發通路的審計動作名（測試用，與 bindissue.go 同一字面值）。
const bindIssueAction = "account.guest_bind_ticket_issue"

// mustIssue 簽發一枚憑證並在失敗時終止測試，回傳明文。
func mustIssue(t *testing.T, e *env, admin identity.Principal, source, target idgen.ID) string {
	t.Helper()
	issued, err := e.service.IssueGuestBindTicket(context.Background(), admin, source, target,
		"req-issue")
	if err != nil {
		t.Fatalf("簽發綁定憑證失敗：%v", err)
	}
	return issued.Ticket
}

// blockersOf 取出一條 BindPlanError 結論裡的阻止原因記號；不是這個型別就終止測試。
func blockersOf(t *testing.T, err error) []BindBlocker {
	t.Helper()
	var planErr *BindPlanError
	if !errors.As(err, &planErr) {
		t.Fatalf("結論應是 *BindPlanError，實際 %T：%v", err, err)
	}
	return planErr.Blockers
}

// retiredSnapshot 讀回來源那一行的四個關鍵事實（退休形態、時刻、登入名與憑據欄）。
//
// 逐欄取而不是讀實體：本步要證的正是「身份存續、名字不改、沒有憑據被複製進來」，
// 而實體讀法會替我做形狀校驗，反而看不見某欄被悄悄動過。
func retiredSnapshot(t *testing.T, e *env, accountID idgen.ID) (
	status string, retiredAt sql.NullInt64, loginName, displayName string, hash sql.NullString) {
	t.Helper()
	err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT status, retired_at, login_name, display_name, password_hash
		 FROM accounts WHERE id = ?`, accountID.String()).
		Scan(&status, &retiredAt, &loginName, &displayName, &hash)
	if err != nil {
		t.Fatalf("讀回來源帳戶失敗：%v", err)
	}
	return status, retiredAt, loginName, displayName, hash
}

// countWhere 取一條帶條件的 COUNT(*)（測試取證用，不參與任何生產判定）。
func countWhere(t *testing.T, e *env, query string, args ...any) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("計數查詢失敗（%s）：%v", query, err)
	}
	return n
}

// consumedTickets 數已被核銷的憑證。
func consumedTickets(t *testing.T, e *env) int {
	t.Helper()
	return countWhere(t, e, "SELECT COUNT(*) FROM guest_bind_tickets WHERE consumed_at IS NOT NULL")
}

// adminActor 種下一筆真正持有伺服器級授予的帳戶並換出它的主體。
//
// 簽發人必須是庫裡的一行：guest_bind_tickets.issued_by_account_id 是外鍵，
// 而「誰准了這一對」這句話要能在事後查同一本名冊——拿一枚不存在於 accounts 的標識
// 去簽發，正是這條通路該拒的形態（測試用 seeded 帳戶而不是虛擬主體，就是為了把這件事
// 驗在库的约束上而不是驗在程式的客氣上）。
func adminActor(t *testing.T, e *env, login string) identity.Principal {
	t.Helper()
	a := e.seed(t, seedInput{Login: login, Display: "簽發管理者", Admin: true})
	return identitytest.Account(t, a.ID, identitytest.ServerAdmin())
}

// TestBindIssueWritesOnlyTicketAndAudit 合法這一對的簽發：落下憑證一行與審計一筆，
// 其餘四件事一個字都不動——訪戶仍是訪戶、目標原樣、會話一枚沒撤、留痕仍是空的。
// 憑證明文只在回應裡出現一次：庫裡只有它的哈希，日誌與審計裡找不到它。
func TestBindIssueWritesOnlyTicketAndAudit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Bind.Issuer")
	guest := e.seed(t, seedInput{Login: "guest_issue", Display: "待發旅人", Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "Issue.Host", Display: "受體"})
	secrets := seedGuestSessions(t, e, guest.ID, 2)
	guestRow, targetRow := rowSnapshot(t, e, guest.ID), rowSnapshot(t, e, target.ID)

	issued, err := e.service.IssueGuestBindTicket(ctx, admin, guest.ID, target.ID, "req-issue-1")
	if err != nil {
		t.Fatalf("合法這一對的簽發不應失敗：%v", err)
	}
	if len(issued.Ticket) != 22 {
		t.Errorf("憑證明文應為 22 字元，實際 %d", len(issued.Ticket))
	}
	if issued.TicketID.IsNil() {
		t.Error("簽發該回傳憑證的穩定標識")
	}
	if got := issued.ExpiresAt.Sub(e.clock.Now()); got != GuestBindTicketTTL {
		t.Errorf("憑證壽命應是碼內的 %v，實際 %v", GuestBindTicketTTL, got)
	}
	if !issued.Plan.Executable || len(issued.Plan.Impacts) != 5 {
		t.Errorf("簽發依據的判定應可執行且五條影響齊備，實際 %+v", issued.Plan.Impacts)
	}
	if issued.Plan.ConsentMode != BindConsentModeTargetSelfInitiated {
		t.Errorf("同意形態應恆為目標端自助發起，實際 %q", issued.Plan.ConsentMode)
	}

	// 四件沒發生的事。
	if got := rowSnapshot(t, e, guest.ID); got != guestRow {
		t.Errorf("簽發動了來源帳戶一行：簽發前 %s／實際 %s", guestRow, got)
	}
	if got := rowSnapshot(t, e, target.ID); got != targetRow {
		t.Errorf("簽發動了目標帳戶一行：簽發前 %s／實際 %s", targetRow, got)
	}
	if n := countWhere(t, e, "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NOT NULL"); n != 0 {
		t.Errorf("簽發不得撤銷任何會話，實際 %d 行帶撤銷標記", n)
	}
	if n := countRows(t, e.db, "guest_account_bindings"); n != 0 {
		t.Errorf("簽發不是綁定：留痕表必須仍是空的，實際 %d 行", n)
	}
	if n := countRows(t, e.db, "guest_bind_tickets"); n != 1 {
		t.Errorf("簽發該恰落下一行憑證，實際 %d 行", n)
	}
	if n := consumedTickets(t, e); n != 0 {
		t.Errorf("簽發不得自個兒把憑證核銷掉，實際 %d 枚已核銷", n)
	}

	// 審計：一筆、actor 是那位管理員、指向來源，而且不含憑證明文。
	var actorKind, actorID, changes, reason string
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT actor_kind, actor_id, changes_json, reason
		FROM root_audit WHERE action = ?`, bindIssueAction).
		Scan(&actorKind, &actorID, &changes, &reason); err != nil {
		t.Fatalf("讀回簽發審計失敗：%v", err)
	}
	if actorKind != string(audit.ActorAdmin) || actorID != admin.AccountID().String() {
		t.Errorf("簽發審計應記真實操作者，實際 %s／%s", actorKind, actorID)
	}
	if !strings.Contains(changes, target.ID.String()) || !strings.Contains(changes, "ticket_id") {
		t.Errorf("簽發審計應能追溯「准給了誰」與那一枚憑證的標識，實際 %s", changes)
	}
	if !strings.Contains(reason, "尚未綁定任何人") {
		t.Error("簽發審計要寫明這一步還沒有綁定任何人")
	}
	if n := countRows(t, e.db, "root_audit"); n != 1 {
		t.Errorf("簽發該只留一筆審計，實際 %d 筆", n)
	}

	// 明文只活在那一次回應裡。
	logs := e.logs.String()
	if strings.Contains(logs, issued.Ticket) {
		t.Error("憑證明文不得進執行日誌")
	}
	if strings.Contains(changes, issued.Ticket) || strings.Contains(reason, issued.Ticket) {
		t.Error("憑證明文不得進審計")
	}
	if n := countWhere(t, e, "SELECT COUNT(*) FROM guest_bind_tickets WHERE ticket_hash = ?",
		issued.Ticket); n != 0 {
		t.Error("庫裡不得出現憑證明文")
	}
	for _, secret := range secrets {
		if strings.Contains(logs, secret) {
			t.Error("會話材料不得進執行日誌")
		}
	}
}

// TestBindIssueBlockersAndDenials 簽發沒有「失敗也成功」那一形：不可行的這一對
// 以可判別結論回來並帶著穩定原因記號，而每一次被拒都一行憑證都不落、一筆審計都不記。
func TestBindIssueBlockersAndDenials(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Bind.BlockAdmin")
	guest := e.seed(t, seedInput{Login: "guest_block", Display: "被擋旅人", Type: account.TypeGuest})
	offGuest := e.seed(t, seedInput{Login: "guest_off", Display: "停用旅人",
		Type: account.TypeGuest, Status: account.StatusDisabled})
	target := e.seed(t, seedInput{Login: "Block.Host", Display: "受體"})
	privileged := e.seed(t, seedInput{Login: "Block.Admin", Display: "持授予者", Admin: true})

	cases := []struct {
		name         string
		source       idgen.ID
		target       idgen.ID
		wantBlockers string
		wantErr      error
	}{
		{"停用中的來源", offGuest.ID, target.ID, string(BindBlockerSourceNotActive), nil},
		{"來源與目標同一人（訪戶）", guest.ID, guest.ID, string(BindBlockerSameAccount), nil},
		{"來源與目標同一人（正式）", target.ID, target.ID, string(BindBlockerSameAccount), nil},
		// 來源可用而目標是「另一位訪戶」：只出口目標那一側那一句——
		// 「他是不是停用」對一個根本不是正式帳戶的人不是處置，多唸一句只會誤導。
		{"目標也是訪戶且已停用", guest.ID, offGuest.ID,
			string(BindBlockerTargetNotStandard), nil},
		{"目標是特權帳戶", guest.ID, privileged.ID, "", ErrAccountNotFound},
		{"零值來源", idgen.Nil, target.ID, "", ErrAccountNotFound},
		{"零值目標", guest.ID, idgen.Nil, "", ErrAccountNotFound},
	}
	for _, tc := range cases {
		_, err := e.service.IssueGuestBindTicket(ctx, admin, tc.source, tc.target, "req-block")
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("%s：結論應是 %v，實際 %v", tc.name, tc.wantErr, err)
			}
			continue
		}
		if got := blockerLine(blockersOf(t, err)); got != tc.wantBlockers {
			t.Errorf("%s：阻止原因應為 %q，實際 %q", tc.name, tc.wantBlockers, got)
		}
	}
	if n := countRows(t, e.db, "guest_bind_tickets"); n != 0 {
		t.Errorf("七次被拒的簽發該一行都不落，實際 %d 行", n)
	}
	if n := countRows(t, e.db, "root_audit"); n != 0 {
		t.Errorf("被拒的簽發不得寫審計，實際 %d 筆", n)
	}
	for _, id := range []idgen.ID{guest.ID, offGuest.ID, target.ID} {
		var status string
		if err := e.db.SQL().QueryRowContext(ctx,
			"SELECT status FROM accounts WHERE id = ?", id.String()).Scan(&status); err != nil {
			t.Fatalf("讀回帳戶失敗：%v", err)
		}
		if status == account.StatusRetired.String() {
			t.Errorf("被拒的簽發把 %s 退休了", id.String())
		}
	}
}

// TestBindIssueAuthorizationMatrix 簽發是伺服器級動作：四類不持管理權的主體一律被拒，
// 而且被拒在查庫之前——一行憑證、一筆審計都不落。
func TestBindIssueAuthorizationMatrix(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	guest := e.seed(t, seedInput{Login: "guest_actor2", Display: "想自簽旅人", Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "No.Sign", Display: "被探者"})

	cases := map[string]identity.Principal{
		"訪戶本人": identitytest.Account(t, guest.ID, identitytest.WithGuestType()),
		"普通帳戶": identitytest.Account(t, identitytest.NewID(t)),
		"系統主體": identitytest.System(t, identity.OriginCLI),
		"匿名主體": identity.Anonymous(),
	}
	for name, principal := range cases {
		_, err := e.service.IssueGuestBindTicket(ctx, principal, guest.ID, target.ID, "req-deny")
		if !errors.Is(err, identity.ErrPermissionDenied) && !errors.Is(err, identity.ErrNotAuthenticated) {
			t.Errorf("%s 簽發綁定憑證應被拒，實際 %v", name, err)
		}
	}
	if n := countRows(t, e.db, "guest_bind_tickets"); n != 0 {
		t.Errorf("被拒的簽發不得落庫，實際 %d 行", n)
	}
	if n := countRows(t, e.db, "root_audit"); n != 0 {
		t.Errorf("被拒的簽發不得寫審計，實際 %d 筆", n)
	}
}

// TestBindConfirmHappyPathIsAtomicAndLeavesTargetUntouched 正常綁定：核銷憑證、來源退休、
// 源會話全數撤銷、留痕追加，四件事同生；而目標那一行逐字原樣、授予一筆不多。
//
// 「源令牌不會變成目標令牌」由兩個方向一起斷言：源那幾行只剩撤銷標記（沒有被改指向別人），
// 而目標名下今天不會憑空多出一枚能換出他會話的秘密。
func TestBindConfirmHappyPathIsAtomicAndLeavesTargetUntouched(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Bind.GateAdmin")
	guest := e.seed(t, seedInput{Login: "guest_bind_ok", Display: "將併入旅人", Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "Ready.Host", Display: "承接者"})
	secrets := seedGuestSessions(t, e, guest.ID, 3)
	targetRow := rowSnapshot(t, e, target.ID)
	ticket := mustIssue(t, e, admin, guest.ID, target.ID)
	totalSessions := countWhere(t, e, "SELECT COUNT(*) FROM sessions")
	y := identitytest.Account(t, target.ID)

	// 一、核銷前預覽：只讀，四張表一個字都不動。
	preview, err := e.service.PreviewGuestBindClaim(ctx, y, ticket, "req-preview")
	if err != nil {
		t.Fatalf("本人的核銷前預覽不應失敗：%v", err)
	}
	if preview.Plan.Source.AccountID != guest.ID || preview.Plan.Target.AccountID != target.ID {
		t.Errorf("預覽唸的应是憑證釘著的那一對，實際 %+v", preview.Plan)
	}
	if len(preview.Plan.Impacts) != 5 || !preview.Plan.Executable {
		t.Errorf("預覽該帶齊五條影響，實際 %+v", preview.Plan.Impacts)
	}
	if preview.TicketID.IsNil() {
		t.Error("預覽該回傳憑證標識供界面追溯")
	}
	if n := countRows(t, e.db, "guest_account_bindings"); n != 0 {
		t.Error("預覽不是執行：留痕表必須仍是空的")
	}
	if n := countWhere(t, e, "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NOT NULL"); n != 0 {
		t.Error("預覽不得撤銷任何會話")
	}
	if n := consumedTickets(t, e); n != 0 {
		t.Error("預覽不得核銷憑證")
	}

	// 二、確認執行：四件合力一起落地。
	done, err := e.service.ConfirmGuestBind(ctx, y, ticket, "req-confirm")
	if err != nil {
		t.Fatalf("本人核銷並完成綁定不應失敗：%v", err)
	}

	status, retiredAt, loginName, displayName, hash := retiredSnapshot(t, e, guest.ID)
	if status != account.StatusRetired.String() || !retiredAt.Valid {
		t.Errorf("來源應已進入退休終態並帶著時刻，實際 %s／%+v", status, retiredAt)
	}
	if loginName != "guest_bind_ok" || displayName != "將併入旅人" {
		t.Errorf("退休不得改寫姓名（歷史要指得回來），實際 %q／%q", loginName, displayName)
	}
	if hash.Valid {
		t.Error("退休不給訪戶變出憑據：password_hash 必須仍是 NULL")
	}
	if done.Source.Status != account.StatusRetired || done.Source.RetiredAt.IsZero() {
		t.Errorf("回應的來源現值應是退休形態，實際 %+v", done.Source)
	}

	if done.RevokedSessions != 3 {
		t.Errorf("應撤銷 3 枚源會話，實際 %d", done.RevokedSessions)
	}
	if n := countWhere(t, e,
		"SELECT COUNT(*) FROM sessions WHERE account_id = ? AND revoked_at IS NULL",
		guest.ID.String()); n != 0 {
		t.Errorf("來源仍有未撤銷會話 %d 行", n)
	}
	if n := countWhere(t, e, "SELECT COUNT(*) FROM sessions WHERE account_id = ?",
		target.ID.String()); n != 0 {
		t.Errorf("綁定不得憑空簽發目標的會話，實際 %d 行", n)
	}
	if n := countWhere(t, e, "SELECT COUNT(*) FROM sessions"); n != totalSessions {
		t.Errorf("綁定不得新增或刪除會話行：前 %d／後 %d", totalSessions, n)
	}
	// 源令牌逐枚換不出主體（被撤銷而不是被改名指向別人）：這條是「不能把源令牌變成
	// 目標令牌」的可執行形式——它連自己的原主體都換不出來，更換不到別人。
	for _, secret := range secrets {
		if _, _, err := e.sessions.ResolvePrincipal(ctx, e.db.SQL(), secret,
			identity.OriginHTTPRequest); err == nil {
			t.Error("源令牌綁定後仍換得出主體——它還在門內通行")
		}
	}

	// 三、目標一點都沒被改造：憑據、狀態、旗標與時刻逐字原樣，授予一筆不多。
	if got := rowSnapshot(t, e, target.ID); got != targetRow {
		t.Errorf("綁定動了目標一行：綁定前 %s／實際 %s", targetRow, got)
	}
	if n := countWhere(t, e, "SELECT COUNT(*) FROM account_server_roles WHERE account_id = ?",
		target.ID.String()); n != 0 {
		t.Errorf("綁定不得給目標授予，實際 %d 行", n)
	}
	if done.Target.Status != account.StatusActive {
		t.Errorf("回應的目標狀態應仍是 active，實際 %s", done.Target.Status)
	}

	// 四、留痕與憑證：一行、指向那枚已核銷的憑證、時刻與來源退休時刻同值。
	if n := countRows(t, e.db, "guest_account_bindings"); n != 1 {
		t.Fatalf("綁定該留下一行留痕，實際 %d 行", n)
	}
	var boundSource, boundTarget, boundTicket, consent string
	var boundAt int64
	var revokedInRow int
	if err := e.db.SQL().QueryRowContext(ctx, `SELECT source_account_id, target_account_id,
		ticket_id, bound_at, revoked_sessions, consent_mode FROM guest_account_bindings`).
		Scan(&boundSource, &boundTarget, &boundTicket, &boundAt, &revokedInRow, &consent); err != nil {
		t.Fatalf("讀回留痕失敗：%v", err)
	}
	if boundSource != guest.ID.String() || boundTarget != target.ID.String() ||
		boundTicket != done.Binding.TicketID.String() {
		t.Errorf("留痕的三枚標識對不上：%s/%s/%s", boundSource, boundTarget, boundTicket)
	}
	if consent != BindConsentModeTargetSelfInitiated {
		t.Errorf("留痕的同意形態應是合同那一個值，實際 %q", consent)
	}
	if revokedInRow != 3 {
		t.Errorf("留痕應記下撤銷 3 枚，實際 %d", revokedInRow)
	}
	if boundAt != retiredAt.Int64 {
		t.Errorf("一次綁定只能有一個時刻：留痕 %d／帳戶行 %d", boundAt, retiredAt.Int64)
	}
	if n := consumedTickets(t, e); n != 1 {
		t.Errorf("憑證應被核銷一枚，實際 %d 枚", n)
	}

	// 五、審計邊界：簽發那一筆還在，而本人執行的這一步不新增審計
	//（普通帳戶本人動作的審計主體類別未批准，沿用 internal/auth 的既有口徑）。
	if n := countWhere(t, e, "SELECT COUNT(*) FROM root_audit WHERE action = ?", bindIssueAction); n != 1 {
		t.Errorf("簽發審計應逐字保留，實際 %d 筆", n)
	}
	if n := countRows(t, e.db, "root_audit"); n != 1 {
		t.Errorf("綁定執行不應新增審計（留痕表才是它的痕跡），實際 root_audit %d 筆", n)
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "已完成訪戶綁定") {
		t.Error("執行成功應有一句可追溯的執行日誌")
	}
	for _, secret := range secrets {
		if strings.Contains(logs, secret) {
			t.Error("會話材料不得進執行日誌")
		}
	}
	if strings.Contains(logs, ticket) {
		t.Error("憑證明文不得進執行日誌")
	}
}

// TestBindClaimSubjectGate 三道本人通路只承認「憑證上釘著的那個普通正式帳戶」：
// 訪戶、Root、持授予的管理員與匿名各自拿到既有結論，而且一個字都不寫。
func TestBindClaimSubjectGate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Bind.OkAdmin")
	guest := e.seed(t, seedInput{Login: "guest_gate", Display: "門口的旅人", Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "Gate.Host", Display: "受體"})
	ticket := mustIssue(t, e, admin, guest.ID, target.ID)
	guestRow := rowSnapshot(t, e, guest.ID)

	denied := map[string]identity.Principal{
		"訪戶本人": identitytest.Account(t, guest.ID, identitytest.WithGuestType()),
		"管理員":  admin,
		"Root": identitytest.Root(t, identity.OriginHTTPRequest),
		"匿名":   identity.Anonymous(),
	}
	for name, principal := range denied {
		want := identity.ErrPermissionDenied
		if name == "匿名" {
			want = identity.ErrNotAuthenticated
		}
		if _, err := e.service.PreviewGuestBindClaim(ctx, principal, ticket, "req-gate"); !errors.Is(err, want) {
			t.Errorf("%s 走預覽通路應被拒為 %v，實際 %v", name, want, err)
		}
		if _, err := e.service.ConfirmGuestBind(ctx, principal, ticket, "req-gate"); !errors.Is(err, want) {
			t.Errorf("%s 走執行通路應被拒為 %v，實際 %v", name, want, err)
		}
		if _, err := e.service.ListGuestBindings(ctx, principal, "req-gate"); !errors.Is(err, want) {
			t.Errorf("%s 走查帳通路應被拒為 %v，實際 %v", name, want, err)
		}
	}
	if got := rowSnapshot(t, e, guest.ID); got != guestRow {
		t.Errorf("被拒的請求動了來源一行：前 %s／實際 %s", guestRow, got)
	}
	if n := consumedTickets(t, e); n != 0 {
		t.Error("被拒的請求不得核銷憑證")
	}
	if n := countRows(t, e.db, "guest_account_bindings"); n != 0 {
		t.Error("被拒的請求不得留下留痕")
	}
}

// TestBindConfirmWrongTargetHolderAndReplay 換人使用與重放：別的正常帳戶拿著這枚憑證
// 只能拿到那句同形的話；同一枚憑證重複提交也只遷移一次；而為已退休的來源再簽一枚根本簽不出。
func TestBindConfirmWrongTargetHolderAndReplay(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Bind.ReplayAdmin")
	guest := e.seed(t, seedInput{Login: "guest_replay", Display: "只綁一次旅人", Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "Right.Host", Display: "正牌受體"})
	other := e.seed(t, seedInput{Login: "Wrong.Host", Display: "拿錯小票者"})
	ticket := mustIssue(t, e, admin, guest.ID, target.ID)
	guestRow := rowSnapshot(t, e, guest.ID)

	if _, err := e.service.ConfirmGuestBind(ctx, identitytest.Account(t, other.ID), ticket,
		"req-foreign"); !errors.Is(err, ErrBindTicketInvalid) {
		t.Errorf("別人拿這枚憑證該拿到同形的那句話，實際 %v", err)
	}
	if _, err := e.service.PreviewGuestBindClaim(ctx, identitytest.Account(t, other.ID), ticket,
		"req-foreign"); !errors.Is(err, ErrBindTicketInvalid) {
		t.Errorf("別人拿這枚憑證預覽也該拿到同一句，實際 %v", err)
	}
	if got := rowSnapshot(t, e, guest.ID); got != guestRow {
		t.Errorf("換人使用動了來源一行：前 %s／實際 %s", guestRow, got)
	}

	if _, err := e.service.ConfirmGuestBind(ctx, identitytest.Account(t, target.ID), ticket,
		"req-first"); err != nil {
		t.Fatalf("正牌本人的第一次綁定不應失敗：%v", err)
	}
	// 重放：同一枚明文再按一次，拿到的是同一句「憑證不可用」，而不是第二次遷移。
	if _, err := e.service.ConfirmGuestBind(ctx, identitytest.Account(t, target.ID), ticket,
		"req-replay"); !errors.Is(err, ErrBindTicketInvalid) {
		t.Errorf("重放該被拒為憑證不可用，實際 %v", err)
	}
	if _, err := e.service.PreviewGuestBindClaim(ctx, identitytest.Account(t, target.ID), ticket,
		"req-replay"); !errors.Is(err, ErrBindTicketInvalid) {
		t.Errorf("已核銷的憑證不該還預覽得動，實際 %v", err)
	}
	if n := countRows(t, e.db, "guest_account_bindings"); n != 1 {
		t.Errorf("重複確認不得再次遷移：留痕應仍是 1 行，實際 %d 行", n)
	}

	// 已綁走的訪戶不得再被簽發：那顆門在源頭就關上（不是靠留痕的 UNIQUE 兜住才不重複）。
	_, err := e.service.IssueGuestBindTicket(ctx, admin, guest.ID, target.ID, "req-second-issue")
	if got := blockerLine(blockersOf(t, err)); got != string(BindBlockerSourceNotActive) {
		t.Errorf("為已退休的來源再簽發該被 source_not_active 擋住，實際 %q", got)
	}
	if n := countRows(t, e.db, "guest_bind_tickets"); n != 1 {
		t.Errorf("第二枚憑證簽不出：表裡應只有 1 行，實際 %d 行", n)
	}
	if n := countWhere(t, e, "SELECT COUNT(*) FROM root_audit WHERE action = ?", bindIssueAction); n != 1 {
		t.Errorf("被拒的簽發不得新增審計，實際 %d 筆", n)
	}
}

// TestBindTicketExpiryEndsThePath 憑證過期就是失效：既預覽不动也執行不动，
// 而那個來源仍是原樣可用的一筆訪戶。
func TestBindTicketExpiryEndsThePath(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Bind.ExpireAdmin")
	guest := e.seed(t, seedInput{Login: "guest_expiry", Display: "等過期旅人", Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "Late.Host", Display: "來遲者"})
	ticket := mustIssue(t, e, admin, guest.ID, target.ID)
	guestRow, targetRow := rowSnapshot(t, e, guest.ID), rowSnapshot(t, e, target.ID)
	secrets := seedGuestSessions(t, e, guest.ID, 1)
	y := identitytest.Account(t, target.ID)

	e.clock.Advance(GuestBindTicketTTL + time.Minute)
	if _, err := e.service.PreviewGuestBindClaim(ctx, y, ticket, "req-late"); !errors.Is(err, ErrBindTicketInvalid) {
		t.Errorf("過期憑證的預覽應回憑證不可用，實際 %v", err)
	}
	if _, err := e.service.ConfirmGuestBind(ctx, y, ticket, "req-late"); !errors.Is(err, ErrBindTicketInvalid) {
		t.Errorf("過期憑證的執行應回憑證不可用，實際 %v", err)
	}
	if got := rowSnapshot(t, e, guest.ID); got != guestRow {
		t.Errorf("過期後的嘗試動了來源一行：前 %s／實際 %s", guestRow, got)
	}
	if got := rowSnapshot(t, e, target.ID); got != targetRow {
		t.Errorf("過期後的嘗試動了目標一行：前 %s／實際 %s", targetRow, got)
	}
	if n := countWhere(t, e, "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NOT NULL"); n != 0 {
		t.Error("過期後的嘗試不得撤銷會話")
	}
	if _, _, err := e.sessions.ResolvePrincipal(ctx, e.db.SQL(), secrets[0],
		identity.OriginHTTPRequest); err != nil {
		t.Errorf("來源的會話此刻仍該可用（失敗保留原先可用關係）：%v", err)
	}
	if n := consumedTickets(t, e); n != 0 {
		t.Error("過期憑證不得被標記為已核銷")
	}
}

// TestBindConfirmAfterFactsDriftRequiresRepreview 簽發之後事實漂了，執行就必須被拒並要求重新預檢：
// 停用來源、以及庫裡多出一張尚未接入登記表的帳戶引用表，兩個方向各自量過。
// 兩者都不得留下核銷標記——「回滾到連小票都還能用」是失敗保留原狀的一部分。
func TestBindConfirmAfterFactsDriftRequiresRepreview(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Bind.DriftAdmin")
	guest := e.seed(t, seedInput{Login: "guest_drift", Display: "會變旅人", Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "Drift.Host", Display: "受體"})
	ticket := mustIssue(t, e, admin, guest.ID, target.ID)
	y := identitytest.Account(t, target.ID)

	// 一、來源被停用：計劃不再成立。
	if _, err := e.service.accounts.SetStatus(ctx, e.db.SQL(), guest.ID,
		account.StatusDisabled, account.StatusActive); err != nil {
		t.Fatalf("停用來源失敗：%v", err)
	}
	_, err := e.service.ConfirmGuestBind(ctx, y, ticket, "req-drift-off")
	if got := blockerLine(blockersOf(t, err)); got != string(BindBlockerSourceNotActive) {
		t.Errorf("停用後的來源該被擋住，實際 %q", got)
	}
	if n := consumedTickets(t, e); n != 0 {
		t.Error("被拒的執行不得核銷憑證（連核銷一起回滾才是失敗保留原狀）")
	}
	if n := countWhere(t, e, "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NOT NULL"); n != 0 {
		t.Error("被拒的執行不得撤銷會話")
	}
	// 同一趟漂移也讓本人的預覽给出同一句（不是讓界面在按下去之後才發現）。
	if _, err := e.service.PreviewGuestBindClaim(ctx, y, ticket, "req-drift-off-preview"); err == nil {
		t.Error("停用中的來源不該還預覽得出可執行的計劃")
	}

	// 恢復登入後，形態回到簽發時那份事實：同一枚憑證仍能完成（摘要比對通過）。
	if _, err := e.service.accounts.SetStatus(ctx, e.db.SQL(), guest.ID,
		account.StatusActive, account.StatusDisabled); err != nil {
		t.Fatalf("恢復來源失敗：%v", err)
	}
	if _, err := e.service.ConfirmGuestBind(ctx, y, ticket, "req-drift-back"); err != nil {
		t.Fatalf("形態回到簽發時那份事實後該能完成，實際 %v", err)
	}
	if status, _, _, _, _ := retiredSnapshot(t, e, guest.ID); status != account.StatusRetired.String() {
		t.Errorf("來源該已退休，實際 %s", status)
	}

	// 二、庫裡出現一張未登記的帳戶引用表：執行被整體阻止，且表名不進結論。
	guest2 := e.seed(t, seedInput{Login: "guest_drift2", Display: "承載未來旅人", Type: account.TypeGuest})
	target2 := e.seed(t, seedInput{Login: "Drift2.Host", Display: "受體乙"})
	ticket2 := mustIssue(t, e, admin, guest2.ID, target2.ID)
	if _, err := e.db.SQL().ExecContext(ctx,
		`CREATE TABLE probe_asset_ownership (
		    account_id TEXT NOT NULL REFERENCES accounts (id),
		    asset_milli INTEGER NOT NULL)`); err != nil {
		t.Fatalf("種入未來引用表失敗：%v", err)
	}
	if _, err := e.db.SQL().ExecContext(ctx,
		`INSERT INTO probe_asset_ownership (account_id, asset_milli) VALUES (?, 1000)`,
		guest2.ID.String()); err != nil {
		t.Fatalf("種入未來引用行失敗：%v", err)
	}
	y2 := identitytest.Account(t, target2.ID)
	_, err = e.service.ConfirmGuestBind(ctx, y2, ticket2, "req-drift-ref")
	if got := blockerLine(blockersOf(t, err)); got != string(BindBlockerUnknownReferences) {
		t.Errorf("未登記的引用該整體阻止綁定，實際 %q", got)
	}
	if strings.Contains(err.Error(), "probe_asset_ownership") {
		t.Error("表名不得進結論值（只准進執行日誌）")
	}
	if status, _, _, _, _ := retiredSnapshot(t, e, guest2.ID); status != account.StatusActive.String() {
		t.Errorf("未知引用被拒後來源仍該可用，實際 %s", status)
	}
	if n := consumedTickets(t, e); n != 1 {
		t.Errorf("第二枚憑證不得被核銷（已核銷的應只有第一對那一枚），實際 %d 枚", n)
	}
	// 卸表之後：引用不存在了，而簽發時那份事實本來也沒有它——同一枚憑證可完成，
	// 不必假裝「一切都要重來一次」；真正該回來接入登記表的是那個新模組自己。
	if _, err := e.db.SQL().ExecContext(ctx, `DROP TABLE probe_asset_ownership`); err != nil {
		t.Fatalf("卸除未來引用表失敗：%v", err)
	}
	if _, err := e.service.ConfirmGuestBind(ctx, y2, ticket2, "req-drift-release"); err != nil {
		t.Errorf("引用卸除後該放行，實際 %v", err)
	}
}

// TestBindConfirmSchemaDriftRequiresRepreview 「形態之外」的那一半：兩側一個字沒變，
// 但資料庫版本推進了——舊憑證釘著的計劃屬於另一個時代（登記表的覆蓋面可能已不同），
// 一律以「需重新預檢」被拒，而且不帶阻止原因記號清單（沒有哪一條形態出了錯）。
func TestBindConfirmSchemaDriftRequiresRepreview(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Bind.VersionAdmin")
	guest := e.seed(t, seedInput{Login: "guest_version", Display: "跨版本旅人", Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "Version.Host", Display: "受體"})
	ticket := mustIssue(t, e, admin, guest.ID, target.ID)

	if _, err := e.db.SQL().ExecContext(ctx,
		`UPDATE schema_migrations SET version = version + 1 WHERE version = (
		    SELECT MAX(version) FROM schema_migrations)`); err != nil {
		t.Fatalf("推進版本失敗：%v", err)
	}
	_, err := e.service.ConfirmGuestBind(ctx, identitytest.Account(t, target.ID), ticket, "req-version")
	if !errors.Is(err, ErrBindPlanStale) {
		t.Fatalf("版本漂移該以「計劃已不合當前事實」被拒，實際 %v", err)
	}
	var planErr *BindPlanError
	if errors.As(err, &planErr) {
		t.Error("版本漂移不是某條阻止原因，不該帶著記號清單（那是形態出錯才有的東西）")
	}
	if status, _, _, _, _ := retiredSnapshot(t, e, guest.ID); status != account.StatusActive.String() {
		t.Errorf("被拒的執行不得動來源，實際 %s", status)
	}
	if n := consumedTickets(t, e); n != 0 {
		t.Error("被拒的執行不得核銷憑證")
	}
	// 同一枚憑證的預覽也給同一句話：界面在按下去之前就能說出「請重新預檢」。
	if _, err := e.service.PreviewGuestBindClaim(ctx, identitytest.Account(t, target.ID), ticket,
		"req-version-preview"); !errors.Is(err, ErrBindPlanStale) {
		t.Errorf("預覽該同樣報出計劃過期，實際 %v", err)
	}
}

// TestBindConfirmRollbackWhenHistoryWriteFails 中途失敗的原子性：把留痕那一寫做成必然失敗
// （外部先行寫入同一來源的留痕，撞 source 欄 UNIQUE）。此時核銷、退休與撤銷都已在同筆交易內
// 發生——全部回滾，原先可用關係一句都不剩地留著。
func TestBindConfirmRollbackWhenHistoryWriteFails(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Bind.RollAdmin")
	guest := e.seed(t, seedInput{Login: "guest_rollback", Display: "回滾旅人", Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "Roll.Host", Display: "受體"})
	secrets := seedGuestSessions(t, e, guest.ID, 2)
	guestRow, targetRow := rowSnapshot(t, e, guest.ID), rowSnapshot(t, e, target.ID)

	// 造出「留痕已存在而來源仍可用」的缺陷形態：先簽一枚並由倉儲直接核銷，
	// 再由外部直寫一行留痕（應用層沒有任何通路能做出這個組合——正是要拿它試試守衛）。
	dummyIssued, err := e.service.IssueGuestBindTicket(ctx, admin, guest.ID, target.ID, "req-dummy")
	if err != nil {
		t.Fatalf("簽發預留憑證失敗：%v", err)
	}
	dummy, err := e.service.bindTickets.TicketByPlain(ctx, e.db.SQL(), dummyIssued.Ticket)
	if err != nil {
		t.Fatalf("讀回預留憑證失敗：%v", err)
	}
	if _, err := e.service.bindTickets.ConsumeTicket(ctx, e.db.SQL(), dummy.ID); err != nil {
		t.Fatalf("預留憑證核銷失敗：%v", err)
	}
	if _, err := e.service.bindTickets.AppendBinding(ctx, e.db.SQL(), guestbind.AppendBindingInput{
		SourceAccountID: guest.ID, TargetAccountID: target.ID, TicketID: dummy.ID,
		BoundAt: e.clock.Now(), RevokedSessions: 0,
	}); err != nil {
		t.Fatalf("預留一行留痕失敗：%v", err)
	}
	ticket := mustIssue(t, e, admin, guest.ID, target.ID)

	// 基準抓在第三枚憑證簽發「之後」：簽發本身就留一筆審計，
	// 而這一條用例要斷言的是「失敗的執行不新增審計」，不能把簽發那筆算成它的。
	auditsBefore := countRows(t, e.db, "root_audit")
	bindingsBefore := countRows(t, e.db, "guest_account_bindings")

	if _, err := e.service.ConfirmGuestBind(ctx, identitytest.Account(t, target.ID), ticket,
		"req-rollback"); err == nil {
		t.Fatal("留痕寫不進時整個綁定必須失敗，實際報了成功")
	}
	if got := rowSnapshot(t, e, guest.ID); got != guestRow {
		t.Errorf("失敗的綁定動了來源一行：前 %s／實際 %s", guestRow, got)
	}
	if got := rowSnapshot(t, e, target.ID); got != targetRow {
		t.Errorf("失敗的綁定動了目標一行：前 %s／實際 %s", targetRow, got)
	}
	if n := countWhere(t, e, "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NOT NULL"); n != 0 {
		t.Errorf("失敗的綁定該回滾掉這一次的所有撤銷，實際 %d 行帶撤銷標記", n)
	}
	for _, secret := range secrets {
		if _, _, err := e.sessions.ResolvePrincipal(ctx, e.db.SQL(), secret,
			identity.OriginHTTPRequest); err != nil {
			t.Errorf("回滾後來源的令牌仍該換得出主體：%v", err)
		}
	}
	if n := consumedTickets(t, e); n != 1 {
		t.Errorf("失敗的綁定不得留下第二枚核銷：應只有預留那 1 枚，實際 %d 枚", n)
	}
	if n := countRows(t, e.db, "guest_account_bindings"); n != bindingsBefore {
		t.Errorf("失敗的綁定不得新增留痕：前 %d／後 %d", bindingsBefore, n)
	}
	if n := countRows(t, e.db, "root_audit"); n != auditsBefore {
		t.Errorf("被拒的執行不得新增審計：前 %d／後 %d", auditsBefore, n)
	}
}

// TestListGuestBindingsScopeAndResultLookup 本人那本帳：範圍只到「目標是我」，
// 而提交後回應遺失時，這裡就是「已完成」的證據（區分失敗／已完成／結果待確認的依據）。
func TestListGuestBindingsScopeAndResultLookup(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := adminActor(t, e, "Bind.LedgerAdmin")
	guest := e.seed(t, seedInput{Login: "guest_ledger", Display: "入帳旅人", Type: account.TypeGuest})
	other := e.seed(t, seedInput{Login: "guest_ledger2", Display: "別人的旅人", Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "Ledger.Host", Display: "受體"})
	outsider := e.seed(t, seedInput{Login: "Other.Host", Display: "旁觀者"})
	seedGuestSessions(t, e, guest.ID, 1)

	if _, err := e.service.ConfirmGuestBind(ctx, identitytest.Account(t, target.ID),
		mustIssue(t, e, admin, guest.ID, target.ID), "req-ledger"); err != nil {
		t.Fatalf("完成一次綁定失敗：%v", err)
	}
	// 別人那一對：由旁觀者接住，本人那本帳不該看得見它。
	if _, err := e.service.ConfirmGuestBind(ctx, identitytest.Account(t, outsider.ID),
		mustIssue(t, e, admin, other.ID, outsider.ID), "req-other"); err != nil {
		t.Fatalf("完成別人的一次綁定失敗：%v", err)
	}

	mine, err := e.service.ListGuestBindings(ctx, identitytest.Account(t, target.ID), "req-list")
	if err != nil {
		t.Fatalf("讀回本人綁定失敗：%v", err)
	}
	if len(mine) != 1 {
		t.Fatalf("本人那本帳應只有 1 行，實際 %d 行：%+v", len(mine), mine)
	}
	item := mine[0]
	if item.SourceAccountID != guest.ID || item.SourceLoginName != "guest_ledger" ||
		item.SourceDisplayName != "入帳旅人" {
		t.Errorf("留痕列出的應是被綁走那個人當下的样子，實際 %+v", item)
	}
	if item.BindingID.IsNil() || item.BoundAt.IsZero() ||
		item.ConsentMode != BindConsentModeTargetSelfInitiated {
		t.Errorf("留痕缺少標識、時刻或同意形態：%+v", item)
	}
	if item.RevokedSessions != 1 {
		t.Errorf("留痕應記下撤銷 1 枚，實際 %d", item.RevokedSessions)
	}

	theirs, err := e.service.ListGuestBindings(ctx, identitytest.Account(t, outsider.ID), "req-list2")
	if err != nil {
		t.Fatalf("讀回旁觀者的綁定失敗：%v", err)
	}
	if len(theirs) != 1 || theirs[0].SourceAccountID != other.ID {
		t.Errorf("兩個人的帳各念各的，實際 %+v", theirs)
	}
	empty, err := e.service.ListGuestBindings(ctx,
		identitytest.Account(t, identitytest.NewID(t)), "req-list3")
	if err != nil {
		t.Fatalf("沒有綁定的人讀帳不該失敗：%v", err)
	}
	if empty == nil || len(empty) != 0 {
		t.Errorf("沒綁過人該回空清單而不是 nil，實際 %+v", empty)
	}
	if _, err := e.service.ListGuestBindings(ctx,
		identitytest.Account(t, guest.ID, identitytest.WithGuestType()), "req-list4"); !errors.Is(err,
		identity.ErrPermissionDenied) {
		t.Errorf("訪戶讀本人綁定帳該被拒，實際 %v", err)
	}
}

// TestBindClaimMalformedTicket 表外形狀與空白明文：一律收成那句不分辨細節的話，
// 不 panic、也不進資料庫探測。
func TestBindClaimMalformedTicket(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	target := e.seed(t, seedInput{Login: "Shape.Host", Display: "受體"})
	guest := e.seed(t, seedInput{Login: "guest_shape", Display: "形狀旅人", Type: account.TypeGuest})
	y := identitytest.Account(t, target.ID)

	for _, bad := range []string{"", " ", "short", "++++++++++++++++++++++", "==",
		strings.Repeat("A", 22), strings.Repeat("a", 23)} {
		if _, err := e.service.PreviewGuestBindClaim(ctx, y, bad, "req-shape"); !errors.Is(err, ErrBindTicketInvalid) {
			t.Errorf("表外明文 %q 的預覽該回憑證不可用，實際 %v", bad, err)
		}
		if _, err := e.service.ConfirmGuestBind(ctx, y, bad, "req-shape"); !errors.Is(err, ErrBindTicketInvalid) {
			t.Errorf("表外明文 %q 的執行該回憑證不可用，實際 %v", bad, err)
		}
	}
	// 簽發側的零值探測：與目錄其餘通路同一句 1001，且一行都不落。
	admin := adminActor(t, e, "Bind.ShapeAdmin")
	for _, pair := range [][2]idgen.ID{{idgen.Nil, guest.ID}, {guest.ID, idgen.Nil}} {
		if _, err := e.service.IssueGuestBindTicket(ctx, admin, pair[0], pair[1], "req-nil"); !errors.Is(err, ErrAccountNotFound) {
			t.Errorf("零值標識的簽發該收斂成「不在目錄」，實際 %v", err)
		}
	}
	if n := countRows(t, e.db, "guest_bind_tickets"); n != 0 {
		t.Errorf("十六趟被拒的請求該一行都不落，實際 %d 行", n)
	}
}
