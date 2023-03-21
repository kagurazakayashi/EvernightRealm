// member_test.go 是活動成員用例的服務層證據：一個帳戶在一場活動裡只有一份檔案（重複即拒且
// 零落地）、目標帳戶的資格邊界（普通與訪戶可、停用可、四種終態收斂成不可分辨的一句）、
// 暱稱的域規則與「不施加唯一約束」、跨活動拼接的不可分辨、停止與歸檔兩道業務寫入門禁、
// 併發編輯的落敗那一句、無權主體連一條通路都進不來、審計寫不進去則整個建立回滾，
// 以及「建立成員不會動到帳戶的憑據、狀態、授予與登入能力」。
//
// 刻意不收的東西：
//   - 沒有替身：授權、門禁、帳戶資格核實、CAS 與審計都走真路徑（真資料庫＋注入時鐘）；
//   - 不測協定層（欄位注入 1004、機器碼對映）：那是 internal/httpapi 的端點證據；
//   - 不測玩家在陣營間的分配：本步沒有分配通路，因此也沒有一處偽造「他被分進哪一組」。
//     這裡斷言的出生形態只有一句：faction_id 恒為 NULL。
package activity

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// mustCreateMember 建立一行成員身份，失敗即終止。
func (e *env) mustCreateMember(t *testing.T, principal identity.Principal,
	activityID, accountID idgen.ID, nickname string) Member {
	t.Helper()
	member, err := e.service.CreateMember(context.Background(), principal, activityID,
		accountID, nickname, "req-member")
	if err != nil {
		t.Fatalf("建立成員 %q 應成功：%v", nickname, err)
	}
	return member
}

// memberFacts 是一行成員在資料庫裡的可觀察形態（身份三欄與陣營歸屬是否被碰過靠它做等值比較）。
//
// faction_id 以可空值讀：出生形態的證據就是「這一格是 NULL」，而不是一個全零的標識字串。
type memberFacts struct {
	activityID string
	accountID  string
	nickname   string
	factionID  sql.NullString
	createdAt  int64
	updatedAt  int64
}

func (e *env) memberFacts(t *testing.T, id idgen.ID) memberFacts {
	t.Helper()
	var f memberFacts
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT activity_id, account_id,
			nickname, faction_id, created_at, updated_at
		FROM activity_members WHERE id = ?`, id.String()).
		Scan(&f.activityID, &f.accountID, &f.nickname, &f.factionID, &f.createdAt, &f.updatedAt)
	if err != nil {
		t.Fatalf("讀取成員 %s 的事實失敗：%v", id.String(), err)
	}
	return f
}

// memberAuditRow 是一筆成員留痕的可觀察形態（操作者、原因句與前後值都問資料庫，不問用例的回憶）。
type memberAuditRow struct {
	actorKind string
	actorID   string
	reason    string
	changes   string
}

func (e *env) latestMemberAudit(t *testing.T, action, activityID string) memberAuditRow {
	t.Helper()
	var row memberAuditRow
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT actor_kind,
			COALESCE(actor_id, ''), reason, changes_json
		FROM activity_audit WHERE action = ? AND activity_id = ?
		ORDER BY created_at DESC, id DESC LIMIT 1`, action, activityID).
		Scan(&row.actorKind, &row.actorID, &row.reason, &row.changes)
	if err != nil {
		t.Fatalf("讀取審計 %s／%s 失敗：%v", action, activityID, err)
	}
	return row
}

// TestMemberCreateAndRoster 驗收：出生形態（標識與時刻由服務端決定、陣營歸屬恒為 NULL）、
// 訪戶同樣可以是成員、名冊帶著帳戶的顯示名與狀態投影，而留痕落在活動域並帶著真實操作者。
func TestMemberCreateAndRoster(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Member.Roster")
	activity := e.create(t, principal, "有名冊的場", "")

	// 空名冊是空的但不是錯誤：「還沒有人加入」本來就是可表達的事實。
	rows, err := e.service.Members(context.Background(), principal, activity.ID)
	if err != nil || len(rows) != 0 {
		t.Fatalf("空名冊應成功且為空：%v（%d 行）", err, len(rows))
	}

	target := e.seedAccount(t, "Member.Player", "玩家甲", account.TypeStandard, account.StatusActive)
	guest := e.seedAccount(t, "Member.Guest", "訪戶乙", account.TypeGuest, account.StatusActive)

	first := e.mustCreateMember(t, principal, activity.ID, target.ID, "深夜行者")
	if first.ID.IsNil() || first.ActivityID != activity.ID || first.AccountID != target.ID {
		t.Errorf("身份三欄必須由服務端決定，實際 %+v", first)
	}
	if !first.FactionID.IsNil() || first.HasFaction() {
		t.Errorf("出生即無陣營（本步沒有分配通路），實際 %s", first.FactionID)
	}
	if f := e.memberFacts(t, first.ID); f.factionID.Valid {
		t.Errorf("faction_id 在库裡必須是 NULL，實際讀到 %q", f.factionID.String)
	}
	if first.JoinedAt != testBase || first.UpdatedAt != testBase {
		t.Errorf("時刻必須取自注入時鐘，實際 %v／%v", first.JoinedAt, first.UpdatedAt)
	}
	if first.DisplayName != "玩家甲" || first.AccountStatus != account.StatusActive {
		t.Errorf("建立回顯要蓋上帳戶投影，實際 %q／%s", first.DisplayName, first.AccountStatus)
	}

	e.clock.Advance(time.Minute)
	second := e.mustCreateMember(t, principal, activity.ID, guest.ID, "訪戶玩家")
	if second.DisplayName != "訪戶乙" || second.AccountStatus != account.StatusActive {
		t.Errorf("訪戶同樣能成為成員並帶出投影，實際 %q／%s", second.DisplayName, second.AccountStatus)
	}

	rows, err = e.service.Members(context.Background(), principal, activity.ID)
	if err != nil {
		t.Fatalf("讀名冊應成功：%v", err)
	}
	if len(rows) != 2 || rows[0].ID != first.ID || rows[1].ID != second.ID {
		t.Fatalf("名冊應按加入時刻穩定呈現兩行，實際 %+v", rows)
	}

	created := e.latestMemberAudit(t, "member.create", activity.ID.String())
	if created.actorKind == "system" || created.actorID == "" {
		t.Errorf("留痕要帶真實操作者，實際 kind=%s id=%q", created.actorKind, created.actorID)
	}
	if !strings.Contains(created.reason, "建立成員身份") {
		t.Errorf("原因句要講建立這件事，實際 %q", created.reason)
	}
	// 最新那一筆對應第二次建立（訪戶）：changes 帶的是它那一份的事實，不是呼叫端的說法。
	if !strings.Contains(created.changes, "訪戶玩家") ||
		!strings.Contains(created.changes, second.AccountID.String()) {
		t.Errorf("changes 要帶暱稱與目標帳戶標識，實際 %s", created.changes)
	}
	if got := e.countAuditRows(t, "member.create", activity.ID.String()); got != 2 {
		t.Errorf("兩次成功建立該留兩筆，實際 %d 筆", got)
	}
	if strings.Contains(e.logs.String(), "argon2id") || strings.Contains(e.logs.String(), "fakehash") {
		t.Errorf("執行日誌不得複述任何憑據材料：%s", e.logs.String())
	}
}

// TestMemberTargetEligibility 驗收：資格邊界的兩側——可恢復的停用允許加入，
// 而待審批、已被拒絕、已軟刪除、已綁定退休與幽靈標識收斂成逐字同形的一句不可分辨。
//
// 這一組同時取證「新增身份引用立即保護帳戶軟刪除與綁定」：那四種形态的人今日進不來，
// 因此不會出現「名冊上躺著一個永遠登不進門的人」之外還有第二種半成品形態。
func TestMemberTargetEligibility(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Member.Eligibility")
	activity := e.create(t, principal, "資格取證的場", "")

	disabled := e.seedAccount(t, "Member.Disabled", "被停用的人", account.TypeStandard, account.StatusDisabled)
	if member, err := e.service.CreateMember(context.Background(), principal, activity.ID,
		disabled.ID, "停用期的名字", "req-disabled"); err != nil {
		t.Fatalf("停用（可恢復形態）應允許加入名冊：%v", err)
	} else if member.AccountStatus != account.StatusDisabled {
		t.Errorf("名冊要如實帶出停用狀態，實際 %s", member.AccountStatus)
	}

	pending := e.seedAccount(t, "Member.Pending", "待審的人", account.TypeStandard, account.StatusPending)
	rejectedAcct := e.seedAccount(t, "Member.Rejected", "被拒的人", account.TypeStandard, account.StatusPending)
	if _, err := e.accounts.DecideApplication(context.Background(), e.db.SQL(), rejectedAcct.ID,
		account.DecisionReject); err != nil {
		t.Fatalf("把申請判成拒絕失敗：%v", err)
	}
	deleted := e.seedAccount(t, "Member.Deleted", "被刪的人", account.TypeStandard, account.StatusActive)
	if changed, err := e.accounts.MarkDeleted(context.Background(), e.db.SQL(), deleted.ID,
		deleted.DisplayName); err != nil || !changed {
		t.Fatalf("把帳戶帶進刪除終態失敗：%v（changed=%v）", err, changed)
	}
	retired := e.seedAccount(t, "Member.Retired", "被綁走的訪戶", account.TypeGuest, account.StatusActive)
	if changed, err := e.accounts.RetireGuestForBind(context.Background(), e.db.SQL(), retired.ID); err != nil || !changed {
		t.Fatalf("把訪戶帶進退休終態失敗：%v（changed=%v）", err, changed)
	}
	ghost := identitytest.NewID(t)
	zero := idgen.ID{}

	cases := []struct {
		who    string
		target idgen.ID
	}{
		{"待審批", pending.ID},
		{"已被拒絕", rejectedAcct.ID},
		{"已被軟刪除", deleted.ID},
		{"已綁定退休", retired.ID},
		{"幽靈標識", ghost},
		{"零值標識", zero},
	}
	auditsBefore := e.countRows(t, "activity_audit")
	for _, tc := range cases {
		_, err := e.service.CreateMember(context.Background(), principal, activity.ID,
			tc.target, "不該進來的名字", "req-ineligible")
		if !errors.Is(err, ErrMemberNotFound) {
			t.Errorf("%s：該收斂成不可分辨的查無，實際 %v", tc.who, err)
		}
		if err.Error() != "member: 該成員或目標帳戶不在可見範圍內" {
			t.Errorf("%s：這句話必須逐字固定，不能洩漏差哪一半，實際 %q", tc.who, err.Error())
		}
	}
	if got := e.countRows(t, "activity_members"); got != 1 {
		t.Errorf("六種不合格目標都不該落庫（只有停用那一行），實際 %d 行", got)
	}
	if got := e.countRows(t, "activity_audit"); got != auditsBefore {
		t.Errorf("被拒的建立不該留審計，前 %d 筆／實際 %d 筆", auditsBefore, got)
	}
}

// TestMemberSingleProfilePerActivity 驗收：一個帳戶在一場活動裡只有一份檔案——
// 重複建立即拒且零落地零留痕，而同一個人在另一場活動裡可以有另一份（跨活動各自獨立）。
func TestMemberSingleProfilePerActivity(t *testing.T) {
	e := newEnv(t)
	alpha, _ := e.admin(t, "Member.SingleAlpha")
	beta, _ := e.admin(t, "Member.SingleBeta")
	actA := e.create(t, alpha, "甲場", "")
	actB := e.create(t, beta, "乙場", "")
	player := e.seedAccount(t, "Member.Repeat", "要重複加入的人", account.TypeStandard, account.StatusActive)

	once := e.mustCreateMember(t, alpha, actA.ID, player.ID, "唯一的檔案")
	auditsBefore := e.countRows(t, "activity_audit")
	_, err := e.service.CreateMember(context.Background(), alpha, actA.ID, player.ID,
		"第二次提交的暱稱", "req-dup")
	if !errors.Is(err, ErrMemberAccountTaken) {
		t.Errorf("同活動重複建立應回報可判別的重複，實際 %v", err)
	}
	if got := e.countRows(t, "activity_members"); got != 1 {
		t.Errorf("重複建立該一行都不多，實際 %d 行", got)
	}
	if got := e.countRows(t, "activity_audit"); got != auditsBefore {
		t.Errorf("重複建立不謊報成功也不記審計，前 %d 筆／實際 %d 筆", auditsBefore, got)
	}
	// 既有檔案的事實不被第二次提交覆蓋（正確性來自 UNIQUE，不來自先查）。
	if f := e.memberFacts(t, once.ID); f.nickname != "唯一的檔案" {
		t.Errorf("被拒的重複建立覆蓋了既有暱稱：實際 %q", f.nickname)
	}

	// 另一場活動同名同人：完全合法——「一個帳戶在一場活動裡一份檔案」按活動分書。
	e.mustCreateMember(t, beta, actB.ID, player.ID, "乙場的檔案")
	if got := e.countRows(t, "activity_members"); got != 2 {
		t.Errorf("跨活動各有一份檔案，實際 %d 行", got)
	}
}

// TestMemberNicknameRules 驗收：暱稱的每一種「湊得出來但無法解釋」的寫法都在進庫前被點名，
// 而「不施加唯一約束」這句話要用兩個同名玩家都進得來證明。
func TestMemberNicknameRules(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Member.Nickname")
	activity := e.create(t, principal, "暱稱取證的場", "")
	player := e.seedAccount(t, "Member.Nick1", "第一個玩家", account.TypeStandard, account.StatusActive)

	cases := []struct {
		what  string
		input string
	}{
		{"空暱稱", ""},
		{"整串都是空白", "   "},
		{"超長暱稱", strings.Repeat("長", maxNicknameRunes+1)},
		{"含控制字元", "甲\x00玩家"},
		{"含格式字元", "甲\u200b玩家"},
	}
	for _, tc := range cases {
		if _, err := e.service.CreateMember(context.Background(), principal, activity.ID,
			player.ID, tc.input, "req-nick"); !errors.Is(err, ErrInvalidNickname) {
			t.Errorf("%s：該回報暱稱不合法，實際 %v", tc.what, err)
		}
	}
	if got := e.countRows(t, "activity_members"); got != 0 {
		t.Fatalf("被拒的寫入不該留下任何成員行，實際 %d 行", got)
	}

	// 只剝首尾、內部空白屬於暱稱本身。
	trimmed := e.mustCreateMember(t, principal, activity.ID, player.ID, "  夜  行者  ")
	if trimmed.Nickname != "夜  行者" {
		t.Errorf("應只剝首尾空白，實際 %q", trimmed.Nickname)
	}

	// 同活動兩個玩家重名完全合法（用戶批准：不施加唯一約束）。
	other := e.seedAccount(t, "Member.Nick2", "第二個玩家", account.TypeStandard, account.StatusActive)
	e.mustCreateMember(t, principal, activity.ID, other.ID, "夜  行者")
	if got := e.countRows(t, "activity_members"); got != 2 {
		t.Errorf("同名的兩份檔案都該進得來，實際 %d 行", got)
	}
}

// TestMemberNicknameEditIsIndistinguishableAndCAS 驗收：跨活動改别人的成員與改幽靈標識
// 是逐字同形的一句話；併發下後到的那一次拿到現值衝突，贏家的值與留痕都不被覆蓋。
func TestMemberNicknameEditIsIndistinguishableAndCAS(t *testing.T) {
	e := newEnv(t)
	alpha, _ := e.admin(t, "Member.EditAlpha")
	beta, _ := e.admin(t, "Member.EditBeta")
	actA := e.create(t, alpha, "甲的成員場", "")
	actB := e.create(t, beta, "乙的成員場", "")
	player := e.seedAccount(t, "Member.Edited", "被編輯的人", account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, alpha, actA.ID, player.ID, "同名的原名")
	ghost := identitytest.NewID(t)

	// 乙拿甲的成員標識掛在乙的活動下編輯：查無（與幽靈同形）。
	_, errOnAlpha := e.service.UpdateMemberNickname(context.Background(), beta, actB.ID,
		member.ID, "被乙改掉", "同名的原名", "req-cross")
	_, errOnGhost := e.service.UpdateMemberNickname(context.Background(), beta, actB.ID,
		ghost, "被乙改掉", "同名的原名", "req-ghost")
	if !errors.Is(errOnAlpha, ErrMemberNotFound) || !errors.Is(errOnGhost, ErrMemberNotFound) {
		t.Fatalf("兩種都該收斂成查無，實際 %v／%v", errOnAlpha, errOnGhost)
	}
	if errOnAlpha.Error() != errOnGhost.Error() {
		t.Errorf("兩句必須逐字同形，否則就是一枚探測信號：%q vs %q", errOnAlpha, errOnGhost)
	}
	if f := e.memberFacts(t, member.ID); f.nickname != "同名的原名" || f.activityID != actA.ID.String() {
		t.Errorf("被拒的跨活動編輯動了現值或歸屬：%+v", f)
	}

	// 兩人對著同一份畫面改名：先提交者贏，後到者拿到衝突且一筆審計都不留。
	if _, err := e.service.UpdateMemberNickname(context.Background(), alpha, actA.ID,
		member.ID, "同名贏家的名字", "同名的原名", "req-win"); err != nil {
		t.Fatalf("先到的改名應成功：%v", err)
	}
	auditsBefore := e.countRows(t, "activity_audit")
	if _, err := e.service.UpdateMemberNickname(context.Background(), alpha, actA.ID,
		member.ID, "輸家的名字", "同名的原名", "req-lose"); !errors.Is(err, ErrMemberProfileConflict) {
		t.Errorf("過期依據值的改名應回報現值衝突，實際 %v", err)
	}
	if f := e.memberFacts(t, member.ID); f.nickname != "同名贏家的名字" {
		t.Errorf("落敗的編輯覆蓋了贏家的值：實際 %q", f.nickname)
	}
	if got := e.countRows(t, "activity_audit"); got != auditsBefore {
		t.Errorf("落敗的編輯不該留審計，前 %d 筆／實際 %d 筆", auditsBefore, got)
	}

	// 成功那一次留下暱稱前後值與真實操作者。
	row := e.latestMemberAudit(t, "member.update", actA.ID.String())
	if !strings.Contains(row.changes, "同名贏家的名字") || !strings.Contains(row.changes, "同名的原名") {
		t.Errorf("留痕要帶暱稱前後值，實際 %s", row.changes)
	}
	if row.actorKind == "system" || row.actorID == "" {
		t.Errorf("留痕要帶真實操作者，實際 kind=%s id=%q", row.actorKind, row.actorID)
	}

	// 身份三欄不因改名而漂移：標識、歸屬、帳戶指向與建立時刻逐字不變。
	before := e.memberFacts(t, member.ID)
	e.clock.Advance(time.Minute)
	if _, err := e.service.UpdateMemberNickname(context.Background(), alpha, actA.ID,
		member.ID, "又改一次", before.nickname, "req-again"); err != nil {
		t.Fatalf("帶著新現值的改名應成功：%v", err)
	}
	after := e.memberFacts(t, member.ID)
	if after.activityID != before.activityID || after.accountID != before.accountID ||
		after.createdAt != before.createdAt {
		t.Errorf("改名動了身份與時刻：%+v → %+v", before, after)
	}
}

// TestMemberWritesRespectLifecycleGate 驗收：草稿可寫（開放前就能備名單）、
// 停止拿到「重開就好」那一句、歸檔拿到「這件事結束了」那一句，而兩態都照樣能讀名冊。
func TestMemberWritesRespectLifecycleGate(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Member.Gate")
	activity := e.create(t, principal, "要過門禁的成員場", "")
	player := e.seedAccount(t, "Member.Gate1", "門禁前的玩家", account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, principal, activity.ID, player.ID, "草稿期加入的")

	if _, err := e.service.Transition(context.Background(), principal, activity.ID,
		StatusActive, "req-open"); err != nil {
		t.Fatalf("開放活動應成功：%v", err)
	}
	e.mustCreateMember(t, principal, activity.ID,
		e.seedAccount(t, "Member.Gate2", "開放期的玩家", account.TypeStandard, account.StatusActive).ID,
		"開放期加入的")

	if _, err := e.service.Transition(context.Background(), principal, activity.ID,
		StatusClosed, "req-close"); err != nil {
		t.Fatalf("停止活動應成功：%v", err)
	}
	if _, err := e.service.CreateMember(context.Background(), principal, activity.ID,
		e.seedAccount(t, "Member.Gate3", "停止期的玩家", account.TypeStandard, account.StatusActive).ID,
		"停止期想加的", "req-closed"); !errors.Is(err, ErrActivityClosedWrites) {
		t.Errorf("停止態的建立應拿到門禁那句，實際 %v", err)
	}
	if _, err := e.service.UpdateMemberNickname(context.Background(), principal, activity.ID,
		member.ID, "停止期想改的", "草稿期加入的", "req-closed-edit"); !errors.Is(err, ErrActivityClosedWrites) {
		t.Errorf("停止態的編輯應拿到門禁那句，實際 %v", err)
	}
	if rows, err := e.service.Members(context.Background(), principal, activity.ID); err != nil || len(rows) != 2 {
		t.Errorf("停止態仍列、可讀：名冊應讀到兩行，實際 %v（%d 行）", err, len(rows))
	}

	if _, err := e.service.Transition(context.Background(), principal, activity.ID,
		StatusArchived, "req-archive"); err != nil {
		t.Fatalf("歸檔活動應成功：%v", err)
	}
	if _, err := e.service.CreateMember(context.Background(), principal, activity.ID,
		e.seedAccount(t, "Member.Gate4", "歸檔期的玩家", account.TypeStandard, account.StatusActive).ID,
		"歸檔後想加的", "req-archived"); !errors.Is(err, ErrArchived) {
		t.Errorf("歸檔態的建立應拿到終態那句，實際 %v", err)
	}
	if _, err := e.service.UpdateMemberNickname(context.Background(), principal, activity.ID,
		member.ID, "歸檔後想改的", "草稿期加入的", "req-archived-edit"); !errors.Is(err, ErrArchived) {
		t.Errorf("歸檔態的編輯應拿到終態那句，實際 %v", err)
	}
	if f := e.memberFacts(t, member.ID); f.nickname != "草稿期加入的" {
		t.Errorf("被門禁擋下的寫入動了現值：實際 %q", f.nickname)
	}
	rows, err := e.service.Members(context.Background(), principal, activity.ID)
	if err != nil || len(rows) != 2 {
		t.Errorf("歸檔態仍列、可讀：名冊應讀到兩行，實際 %v（%d 行）", err, len(rows))
	}
}

// TestMemberAdmissionMatrix 驗收：普通帳戶、匿名與系統主體連一条路都進不來，
// 而活動管理人讀得到名冊卻不能據此動帳戶側的任何東西。
func TestMemberAdmissionMatrix(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Member.Admit")
	activity := e.create(t, principal, "准入取證的場", "")
	player := e.seedAccount(t, "Member.Admit1", "被加入的人", account.TypeStandard, account.StatusActive)
	e.mustCreateMember(t, principal, activity.ID, player.ID, "管理人加的")

	plain := e.plain(t, "Member.Plain")
	auditsBefore := e.countRows(t, "activity_audit")
	if _, err := e.service.CreateMember(context.Background(), plain, activity.ID,
		identitytest.NewID(t), "平民想加的", "req-plain"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("普通帳戶建立成員應回報權限不足，實際 %v", err)
	}
	if _, err := e.service.Members(context.Background(), plain, activity.ID); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("普通帳戶讀名冊應回報權限不足，實際 %v", err)
	}
	if _, err := e.service.CreateMember(context.Background(), identitytest.Anonymous(t), activity.ID,
		player.ID, "匿名想加的", "req-anon"); !errors.Is(err, identity.ErrNotAuthenticated) {
		t.Errorf("匿名應先撞在不知道是誰上，實際 %v", err)
	}
	if _, err := e.service.CreateMember(context.Background(), identitytest.System(t, identity.OriginBackground),
		activity.ID, player.ID, "背景想加的", "req-sys"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("系統主體不是任何人的代理，實際 %v", err)
	}
	if got := e.countRows(t, "activity_members"); got != 1 {
		t.Errorf("四種主體都進不來，名冊該只有一行，實際 %d 行", got)
	}
	if got := e.countRows(t, "activity_audit"); got != auditsBefore {
		t.Errorf("被拒的通路一筆審計都不留，前 %d 筆／實際 %d 筆", auditsBefore, got)
	}

	// Root 不受指派限制：它讀得到任何活動的名冊。
	if rows, err := e.service.Members(context.Background(), e.root(t), activity.ID); err != nil || len(rows) != 1 {
		t.Errorf("Root 應讀到那一份名冊：%v（%d 行）", err, len(rows))
	}
	// 活動管理人也不是 Root：他管得著這份名冊，但帳戶行的一個字都沒因此改變。
	if a, err := e.accounts.ByID(context.Background(), e.db.SQL(), player.ID); err != nil {
		t.Fatalf("讀回目標帳戶失敗：%v", err)
	} else if a.Status != account.StatusActive || a.MustChangePassword || a.Type != account.TypeStandard {
		t.Errorf("建立成員動了帳戶自身的形態：%+v", a)
	}
}

// TestMemberCreateRollsBackWhenAuditFails 驗收：審計寫不進去則整個建立與整個改名作廢——
// 「存在卻在活動審計裡查不到的成員」與「審計說有而庫裡查不到」同罪。
func TestMemberCreateRollsBackWhenAuditFails(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Member.Rollback")
	activity := e.create(t, principal, "回滾取證的場", "")
	player := e.seedAccount(t, "Member.Rb1", "會回滾的人", account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, principal, activity.ID, player.ID, "回滾前的名字")

	block := `CREATE TRIGGER test_audit_block BEFORE INSERT ON activity_audit
		BEGIN SELECT RAISE(ABORT, '測試：審計寫不進去'); END`
	if _, err := e.db.SQL().ExecContext(context.Background(), block); err != nil {
		t.Fatalf("佈下審計阻斷觸發器失敗：%v", err)
	}
	other := e.seedAccount(t, "Member.Rb2", "第二個會回滾的人", account.TypeStandard, account.StatusActive)
	if _, err := e.service.CreateMember(context.Background(), principal, activity.ID,
		other.ID, "該回滾的名字", "req-blocked"); err == nil {
		t.Fatal("審計寫不進去時建立必須整筆失敗")
	}
	if got := e.countRows(t, "activity_members"); got != 1 {
		t.Errorf("失敗的建立必須整體回滾，實際留下 %d 行", got)
	}
	if _, err := e.service.UpdateMemberNickname(context.Background(), principal, activity.ID,
		member.ID, "該回滾的改名", "回滾前的名字", "req-blocked-edit"); err == nil {
		t.Fatal("審計寫不進去時改名必須整筆失敗")
	}
	if f := e.memberFacts(t, member.ID); f.nickname != "回滾前的名字" {
		t.Errorf("回滾的改名動了現值：實際 %q", f.nickname)
	}
}

// TestMemberDoesNotTouchAccountGrants 驗收：建立成員既不授予任何伺服器級權限，
// 也不凍結任何人——帳戶行的口令形態、狀態、必須改密旗標與授予表逐字不變。
func TestMemberDoesNotTouchAccountGrants(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Member.NoGrant")
	activity := e.create(t, principal, "權限不變取證的場", "")
	player := e.seedAccount(t, "Player.NoGrant", "只是玩家", account.TypeStandard, account.StatusActive)

	hashBefore := player.PasswordHash
	member := e.mustCreateMember(t, principal, activity.ID, player.ID, "不當管理人的玩家")

	// 同一個人的帳戶行被引用了，但他的授予、狀態與憑據一位不動。
	if _, err := e.service.Members(context.Background(), principal, activity.ID); err != nil {
		t.Fatalf("讀名冊應成功：%v", err)
	}
	if got := e.countRows(t, "account_server_roles"); got != 1 {
		t.Errorf("操作者自己那一筆授予之外不該多出任何授予，實際 %d 筆", got)
	}
	a, err := e.accounts.ByID(context.Background(), e.db.SQL(), member.AccountID)
	if err != nil {
		t.Fatalf("讀回目標帳戶失敗：%v", err)
	}
	if a.PasswordHash != hashBefore || a.Status != account.StatusActive ||
		a.MustChangePassword || a.Type != account.TypeStandard {
		t.Errorf("建立成員改動了帳戶的憑據、狀態或型別：%+v", a)
	}
	if f := e.memberFacts(t, member.ID); !strings.EqualFold(f.accountID, player.ID.String()) {
		t.Errorf("成員行必須指向那一個帳戶，實際 %q", f.accountID)
	}
}
