// selfselect_test.go 是「玩家自選陣營與活動開關」用例的服務層證據：開關兩態各自的答案、
// 僅首次與可反覆兩種模式的次數規則、寫入者只能動到自己（主體由憑據換出，
// 路徑與本體裡都沒有一格能填「哪個玩家」）、同一帳戶在不同活動各選各的、
// 停用陣營與跨活動拼接的不可分辨、生命週期三句各自的處置，以及
// 「配置變更與自選並發時不能繞過限制」——取證形狀是「客戶端交來的依據值完全合法，
// 但那欄配置已在它看不見的時候被人關掉」，而判定在寫入交易內現讀，於是那次自選整個不發生。
//
// 刻意不收的東西：
//   - 沒有替身：授權、活動作用域、業務寫入門禁、陣營可用性判定、CAS 與審計都走真路徑
//     （真資料庫＋注入時鐘），接錯線就會紅；
//   - 不測協定層（欄位注入 1004、機器碼 2036～2039 的對映）：那是 internal/httpapi 的端點證據；
//   - 不測管理側的分配與遷出：那條通路尚未落地，本檔也不替它編造形態——
//     這裡所有歸屬變更都只來自玩家自己那一條路。
package activity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// millisOf 把注入時鐘讀回的時刻換成庫中形態（比較 updated_at 只問等不等，不問格式）。
func millisOf(value time.Time) int64 { return timeutil.ToMillis(value) }

// mustSetMode 走管理側那一欄配置的通路，依據值取服務端現值
// （本檔關心的是「模式換了之後玩家側怎麼答」，配置那一側的 CAS 另有取證）。
func (e *env) mustSetMode(t *testing.T, principal identity.Principal,
	activityID idgen.ID, want FactionSelectMode) Activity {
	t.Helper()
	current, err := e.service.ActivityDetail(context.Background(), principal, activityID)
	if err != nil {
		t.Fatalf("讀取活動 %s 現值失敗：%v", activityID, err)
	}
	updated, err := e.service.UpdateFactionSelectMode(context.Background(), principal,
		activityID, want, current.FactionSelectMode, "req-mode")
	if err != nil {
		t.Fatalf("設定自選模式 %q 應成功：%v", want, err)
	}
	return updated
}

// mustSelect 走玩家自選那一條通路，失敗即終止。
func (e *env) mustSelect(t *testing.T, principal identity.Principal,
	activityID, factionID, expectedFactionID idgen.ID) Member {
	t.Helper()
	updated, err := e.service.SelectOwnFaction(context.Background(), principal,
		activityID, factionID, expectedFactionID, "req-select")
	if err != nil {
		t.Fatalf("自選陣營 %s 應成功：%v", factionID, err)
	}
	return updated
}

// selectErr 送一次預期失敗的自選並把錯誤原樣交回來。
func (e *env) selectErr(player identity.Principal, activityID, factionID,
	expectedFactionID idgen.ID) error {
	_, err := e.service.SelectOwnFaction(context.Background(), player, activityID,
		factionID, expectedFactionID, "req-probe")
	return err
}

// modeFacts 讀 activities.faction_select_mode 的庫中現值（配置有沒有真的落地只問資料庫）。
func (e *env) modeFacts(t *testing.T, activityID idgen.ID) string {
	t.Helper()
	var mode string
	err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT faction_select_mode FROM activities WHERE id = ?`,
		activityID.String()).Scan(&mode)
	if err != nil {
		t.Fatalf("讀取活動 %s 的配置現值失敗：%v", activityID, err)
	}
	return mode
}

// selectAuditRow 是一筆留痕的可觀察形態：操作者類別、標識、原因句與前後值都問資料庫。
type selectAuditRow struct {
	actorKind string
	actorID   string
	targetID  string
	reason    string
	changes   string
}

// latestAuditOf 讀回某個動作在這一場活動裡最新一筆留痕（時刻同值時以標識破平，
// 與列表讀法同一條規則，所以「最新一筆」在這裡是可定義的）。
func (e *env) latestAuditOf(t *testing.T, action, activityID string) selectAuditRow {
	t.Helper()
	var row selectAuditRow
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT actor_kind,
			COALESCE(actor_id, ''), target_id, reason, changes_json
		FROM activity_audit WHERE action = ? AND activity_id = ?
		ORDER BY created_at DESC, id DESC LIMIT 1`, action, activityID).
		Scan(&row.actorKind, &row.actorID, &row.targetID, &row.reason, &row.changes)
	if err != nil {
		t.Fatalf("讀取審計 %s／%s 失敗：%v", action, activityID, err)
	}
	return row
}

// TestFactionSelectSwitchTwoStates 驗收開關兩態：關閉時玩家連一次寫入都發生不了
// （零落地、零留痕），而現況讀法把「此刻不能選」如實派生出來；管理人打開之後
// 同一份請求就寫得進去；再關回去不會把任何人已經選定的歸屬清掉。
func TestFactionSelectSwitchTwoStates(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.admin(t, "Select.Switch")
	act := e.create(t, admin, "開關兩態的場", "")
	e.transition(t, admin, act.ID, StatusActive)
	faction := e.mustCreateFaction(t, admin, act.ID, factionDraft("黎明軍"))

	target := e.seedAccount(t, "Select.Switch.Player", "玩家甲",
		account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, admin, act.ID, target.ID, "甲")
	player := identitytest.Account(t, target.ID)

	// 出廠現值：連新建的活動都是 disabled（相容規則——新功能不未經批準就開放）。
	if act.FactionSelectMode != FactionSelectDisabled {
		t.Errorf("新活動的自選模式必須是 disabled，實際 %q", act.FactionSelectMode)
	}
	if got := e.modeFacts(t, act.ID); got != "disabled" {
		t.Errorf("庫裡現值必須是 disabled，實際 %q", got)
	}
	view, err := e.service.MyFactionSelection(context.Background(), player, act.ID)
	if err != nil {
		t.Fatalf("本人讀現況應成功：%v", err)
	}
	if view.CanSelectNow() {
		t.Error("disabled 下 CanSelectNow 必須是假")
	}
	for _, option := range view.Options {
		if option.Selectable {
			t.Error("disabled 下每個候選項都必須標成不可選")
		}
	}

	if err := e.selectErr(player, act.ID, faction.ID, idgen.Nil); !errors.Is(err,
		ErrFactionSelectDisabled) {
		t.Errorf("未開放自選應回 ErrFactionSelectDisabled，實際 %v", err)
	}
	if f := e.memberFacts(t, member.ID); f.factionID.Valid {
		t.Errorf("被拒的自選不能留下任何歸屬，實際 %q", f.factionID.String)
	}
	if got := e.countAuditRows(t, "member.faction_select", act.ID.String()); got != 0 {
		t.Errorf("被拒的自選不記審計，實際 %d 筆", got)
	}

	updated := e.mustSetMode(t, admin, act.ID, FactionSelectFirstOnly)
	if updated.FactionSelectMode != FactionSelectFirstOnly {
		t.Errorf("配置寫入要回讀新模式，實際 %q", updated.FactionSelectMode)
	}
	if got := e.mustSelect(t, player, act.ID, faction.ID, idgen.Nil); got.FactionID != faction.ID {
		t.Errorf("打開之後同一份請求應寫得進去，實際 %s", got.FactionID)
	}

	// 再關回去：只動那一欄配置，任何人的既有歸屬原樣保留
	// （開關約束往後能不能發生，不改寫已經發生的事實）。
	e.mustSetMode(t, admin, act.ID, FactionSelectDisabled)
	if f := e.memberFacts(t, member.ID); !f.factionID.Valid ||
		f.factionID.String != faction.ID.String() {
		t.Errorf("收回開關不得清空歸屬，實際 %q", f.factionID.String)
	}
	view, err = e.service.MyFactionSelection(context.Background(), player, act.ID)
	if err != nil {
		t.Fatalf("收回開關後現況讀法仍要成功：%v", err)
	}
	if view.CanSelectNow() {
		t.Error("收回 disabled 後 CanSelectNow 必須回到假")
	}
	if view.Member.FactionID != faction.ID {
		t.Errorf("現況讀法要如實帶出保留下來的歸屬，實際 %s", view.Member.FactionID)
	}
	// 配置那一跳的留痕：管理人身份、前後只有模式一欄。
	row := e.latestAuditOf(t, "activity.faction_select_update", act.ID.String())
	if row.actorKind != "admin" || row.actorID == "" ||
		!strings.Contains(row.changes, FactionSelectFirstOnly.String()) ||
		!strings.Contains(row.changes, FactionSelectDisabled.String()) {
		t.Errorf("配置留痕要帶管理人身份與前後值，實際 %+v", row)
	}
}

// TestFactionSelectFirstOnlyAndFree 驗收兩種模式的次數規則：僅首次下第二次被拒且現值不動，
// 可反覆下來回換都成立；而「想把歸屬清空」與「目標與依據同一格」都在落庫前被當成寫法錯誤。
func TestFactionSelectFirstOnlyAndFree(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.admin(t, "Select.Count")
	act := e.create(t, admin, "次數規則的場", "")
	e.transition(t, admin, act.ID, StatusActive)
	left := e.mustCreateFaction(t, admin, act.ID, factionDraft("左軍"))
	right := e.mustCreateFaction(t, admin, act.ID, factionDraft("右軍"))

	target := e.seedAccount(t, "Select.Count.Player", "玩家乙",
		account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, admin, act.ID, target.ID, "乙")
	player := identitytest.Account(t, target.ID)

	e.mustSetMode(t, admin, act.ID, FactionSelectFirstOnly)
	first := e.mustSelect(t, player, act.ID, left.ID, idgen.Nil)
	if first.FactionID != left.ID {
		t.Fatalf("首次自選應落在左軍，實際 %s", first.FactionID)
	}
	// 自選留痕的操作者是他在這場活動內的玩家身份（不是帳戶、更不是管理人）。
	row := e.latestAuditOf(t, "member.faction_select", act.ID.String())
	if row.actorKind != "player" || row.actorID != member.ID.String() ||
		row.targetID != member.ID.String() {
		t.Errorf("自選留痕的操作者必須是活動內的玩家身份，實際 %+v", row)
	}
	if !strings.Contains(row.changes, left.ID.String()) {
		t.Errorf("changes 要帶出新歸屬，實際 %s", row.changes)
	}

	if err := e.selectErr(player, act.ID, right.ID, left.ID); !errors.Is(err,
		ErrFactionSelectLockedIn) {
		t.Errorf("僅首次模式下的第二次應回 ErrFactionSelectLockedIn，實際 %v", err)
	}
	if f := e.memberFacts(t, member.ID); f.factionID.String != left.ID.String() {
		t.Errorf("被拒的第二次不能動歸屬，實際 %q", f.factionID.String)
	}
	if got := e.countAuditRows(t, "member.faction_select", act.ID.String()); got != 1 {
		t.Errorf("被拒的第二次不能多記一筆審計，實際 %d 筆", got)
	}

	// 換成可反覆：來回換都成立，而且每次都留痕。
	e.mustSetMode(t, admin, act.ID, FactionSelectFree)
	if back := e.mustSelect(t, player, act.ID, right.ID, left.ID); back.FactionID != right.ID {
		t.Errorf("可反覆模式下應換到右軍，實際 %s", back.FactionID)
	}
	if again := e.mustSelect(t, player, act.ID, left.ID, right.ID); again.FactionID != left.ID {
		t.Errorf("再次換回應成立，實際 %s", again.FactionID)
	}
	if got := e.countAuditRows(t, "member.faction_select", act.ID.String()); got != 3 {
		t.Errorf("三次成功的自選各記一筆，實際 %d 筆", got)
	}

	// 兩句寫法錯誤：清空與原地換自己，都不進庫、都不留痕。
	if err := e.selectErr(player, act.ID, idgen.Nil, idgen.Nil); !errors.Is(err,
		ErrInvalidFactionSelection) {
		t.Errorf("自選沒有清空通路，零值目標應回 ErrInvalidFactionSelection，實際 %v", err)
	}
	if err := e.selectErr(player, act.ID, left.ID, left.ID); !errors.Is(err,
		ErrInvalidFactionSelection) {
		t.Errorf("目標與依據同一格應回 ErrInvalidFactionSelection，實際 %v", err)
	}
	if got := e.countAuditRows(t, "member.faction_select", act.ID.String()); got != 3 {
		t.Errorf("寫法錯誤不記審計，實際 %d 筆", got)
	}
	// 自選只碰歸屬一欄：身份三欄與暱稱原樣（暱稱屬另一條白名單通路）。
	if f := e.memberFacts(t, member.ID); f.nickname != "乙" ||
		f.accountID != target.ID.String() || f.activityID != act.ID.String() {
		t.Errorf("自選不得動身份三欄與暱稱，實際 %+v", f)
	}
}

// TestFactionSelectSelfOnly 驗收「寫入者只能動到自己」：主體由憑據換出，
// 同一場活動裡別人的歸屬不會被這份請求碰到；而訪戶同樣是自己動自己，
// Root、系統主體、匿名與「根本不是這個成員的帳戶」全部收斂成同一句不可分辨的話。
func TestFactionSelectSelfOnly(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.admin(t, "Select.Self")
	act := e.create(t, admin, "只動自己的場", "")
	e.transition(t, admin, act.ID, StatusActive)
	faction := e.mustCreateFaction(t, admin, act.ID, factionDraft("只此一家"))
	e.mustSetMode(t, admin, act.ID, FactionSelectFree)

	alice := e.seedAccount(t, "Select.Self.A", "甲", account.TypeStandard, account.StatusActive)
	bob := e.seedAccount(t, "Select.Self.B", "乙", account.TypeStandard, account.StatusActive)
	ghost := e.seedAccount(t, "Select.Self.C", "丙", account.TypeStandard, account.StatusActive)

	mine := e.mustCreateMember(t, admin, act.ID, alice.ID, "甲的本名")
	theirs := e.mustCreateMember(t, admin, act.ID, bob.ID, "乙的本名")

	before := e.memberFacts(t, theirs.ID)
	e.mustSelect(t, identitytest.Account(t, alice.ID), act.ID, faction.ID, idgen.Nil)
	if f := e.memberFacts(t, mine.ID); f.factionID.String != faction.ID.String() {
		t.Errorf("甲的自選要落在甲那一行，實際 %q", f.factionID.String)
	}
	if after := e.memberFacts(t, theirs.ID); after != before {
		t.Errorf("別人的成員行必須逐字不動：\n舊 %+v\n新 %+v", before, after)
	}

	// 訪戶同樣是自己動自己（參加不是權限，也不會因此多出任何伺服器級能力）。
	guestAccount := e.seedAccount(t, "Select.Self.Guest", "訪戶", account.TypeGuest, account.StatusActive)
	guestMember := e.mustCreateMember(t, admin, act.ID, guestAccount.ID, "訪戶的本名")
	guest := identitytest.Account(t, guestAccount.ID, identitytest.WithGuestType())
	if got := e.mustSelect(t, guest, act.ID, faction.ID, idgen.Nil); got.ID != guestMember.ID {
		t.Errorf("訪戶自選動到的必須是他自己那一行，實際 %s", got.ID)
	}

	// 四種門外主體：三種收斂成不可分辨的一句話，匿名先撞在「不知道是誰」上。
	cases := []struct {
		who       string
		principal identity.Principal
		want      error
	}{
		{"非成員帳戶", identitytest.Account(t, ghost.ID), ErrMemberNotFound},
		{"Root", identitytest.Root(t, identity.OriginHTTPRequest), ErrMemberNotFound},
		{"系統", identitytest.System(t, identity.OriginBackground), ErrMemberNotFound},
		{"匿名", identitytest.Anonymous(t), identity.ErrNotAuthenticated},
	}
	for _, caseOf := range cases {
		if err := e.selectErr(caseOf.principal, act.ID, faction.ID, idgen.Nil); !errors.Is(err,
			caseOf.want) {
			t.Errorf("%s 應回 %v，實際 %v", caseOf.who, caseOf.want, err)
		}
	}
	// 非成員對「草稿」與「沒開放自選」的活動動手，拿到的仍是 1001 而不是時機那句：
	// 順序若把時機判定放在成員行核實之前，這兩句話就等於向任何人承認「那個標識確實是一場活動」。
	draftAct := e.create(t, admin, "非成員敲不到的草稿", "")
	draftFaction := e.mustCreateFaction(t, admin, draftAct.ID, factionDraft("草稿軍"))
	if err := e.selectErr(identitytest.Account(t, ghost.ID), draftAct.ID,
		draftFaction.ID, idgen.Nil); !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("非成員在草稿活動上自選應收斂成 1001 那句，實際 %v", err)
	}
	if err := e.selectErr(identitytest.Account(t, ghost.ID), act.ID,
		faction.ID, idgen.Nil); !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("非成員在已開放活動上自選應與上一條同形，實際 %v", err)
	}
	// 同一場草稿活動對「真的成員」答的才是時機那句——兩句話的對象不同，誰也借不到誰的信號。
	e.mustSetMode(t, admin, draftAct.ID, FactionSelectFree)
	draftMemberAccount := e.seedAccount(t, "Select.Self.Draft", "草稿成員",
		account.TypeStandard, account.StatusActive)
	e.mustCreateMember(t, admin, draftAct.ID, draftMemberAccount.ID, "草稿的我")
	if err := e.selectErr(identitytest.Account(t, draftMemberAccount.ID), draftAct.ID,
		draftFaction.ID, idgen.Nil); !errors.Is(err, ErrFactionSelectNotOpen) {
		t.Errorf("場內成員在草稿活動上應回時機未到那一句，實際 %v", err)
	}

	// 幽靈活動與「有這場活動但沒他的份」同形：介面拆不出差異。
	if _, err := e.service.MyFactionSelection(context.Background(),
		identitytest.Account(t, ghost.ID), identitytest.NewID(t)); !errors.Is(err,
		ErrMemberNotFound) {
		t.Errorf("幽靈活動的現況讀法應與『沒他的份』同形，實際 %v", err)
	}
	if _, err := e.service.MyActivityEntries(context.Background(),
		identitytest.Account(t, ghost.ID)); err != nil {
		t.Errorf("非成員的活動清單應是空清單而不是錯誤：%v", err)
	}
	if got := e.countAuditRows(t, "member.faction_select", act.ID.String()); got != 2 {
		t.Errorf("四種門外主體都不記留痕，實際共 %d 筆", got)
	}
}

// TestFactionSelectPerActivityIndependent 驗收「一個帳戶在一場活動裡只有一份檔案」的另一面：
// 他在兩場活動裡的歸屬各選各的，模式與陣營都不跨活動生效。
func TestFactionSelectPerActivityIndependent(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.admin(t, "Select.Independent")
	first := e.create(t, admin, "第一場", "")
	second := e.create(t, admin, "第二場", "")
	e.transition(t, admin, first.ID, StatusActive)
	e.transition(t, admin, second.ID, StatusActive)
	factionA := e.mustCreateFaction(t, admin, first.ID, factionDraft("甲場陣營"))
	factionB := e.mustCreateFaction(t, admin, second.ID, factionDraft("乙場陣營"))

	target := e.seedAccount(t, "Select.Independent.Player", "跨場玩家",
		account.TypeStandard, account.StatusActive)
	inFirst := e.mustCreateMember(t, admin, first.ID, target.ID, "甲場的我")
	inSecond := e.mustCreateMember(t, admin, second.ID, target.ID, "乙場的我")
	player := identitytest.Account(t, target.ID)

	e.mustSetMode(t, admin, first.ID, FactionSelectFirstOnly)
	e.mustSetMode(t, admin, second.ID, FactionSelectFree)

	e.mustSelect(t, player, first.ID, factionA.ID, idgen.Nil)
	e.mustSelect(t, player, second.ID, factionB.ID, idgen.Nil)
	if f := e.memberFacts(t, inFirst.ID); f.factionID.String != factionA.ID.String() {
		t.Errorf("第一場歸屬應落在甲場陣營，實際 %q", f.factionID.String)
	}
	if f := e.memberFacts(t, inSecond.ID); f.factionID.String != factionB.ID.String() {
		t.Errorf("第二場歸屬應落在乙場陣營，實際 %q", f.factionID.String)
	}
	// 第一場已被「僅首次」鎖住：第二次拿到的是鎖定那一句；第二場仍可換（換進第三個陣營）。
	if err := e.selectErr(player, first.ID, factionA.ID, factionA.ID); !errors.Is(err,
		ErrInvalidFactionSelection) {
		t.Errorf("原地換自己先撞在寫法錯誤上，實際 %v", err)
	}
	if err := e.selectErr(player, first.ID, factionB.ID, factionA.ID); !errors.Is(err,
		ErrFactionSelectLockedIn) {
		t.Errorf("僅首次那場的下一次應回鎖定那一句，實際 %v", err)
	}
	// 拿甲場的陣營去選乙場：跨活動拼接與從未存在同一句話，兩行現值都不動。
	if err := e.selectErr(player, second.ID, factionA.ID, factionB.ID); !errors.Is(err,
		ErrFactionNotFound) {
		t.Errorf("跨活動拿別人的陣營應回不可分辨的 ErrFactionNotFound，實際 %v", err)
	}
	if f := e.memberFacts(t, inSecond.ID); f.factionID.String != factionB.ID.String() {
		t.Errorf("被拒的跨場拼接不能動歸屬，實際 %q", f.factionID.String)
	}

	entries, err := e.service.MyActivityEntries(context.Background(), player)
	if err != nil {
		t.Fatalf("本人活動清單應成功：%v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("本人應有兩行，實際 %d 行", len(entries))
	}
	seen := map[idgen.ID]FactionSelectMode{}
	got := map[idgen.ID]idgen.ID{}
	for _, entry := range entries {
		seen[entry.Activity.ID] = entry.Activity.FactionSelectMode
		got[entry.Member.ID] = entry.Member.FactionID
	}
	if seen[first.ID] != FactionSelectFirstOnly || seen[second.ID] != FactionSelectFree {
		t.Errorf("清單逐行要帶出自己那場活動的模式現值，實際 %+v", seen)
	}
	if got[inFirst.ID] != factionA.ID || got[inSecond.ID] != factionB.ID {
		t.Errorf("清單逐行要帶出自己那場活動的歸屬，實際 %+v", got)
	}
}

// TestFactionSelectLifecycleAndAvailability 驗收生命週期三句與陣營停用那一句：
// 草稿、停止、歸檔各有各的處置，停用的陣營收不到人而既有歸屬保留。
func TestFactionSelectLifecycleAndAvailability(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.admin(t, "Select.Life")
	act := e.create(t, admin, "草稿裡的場", "")
	faction := e.mustCreateFaction(t, admin, act.ID, factionDraft("草稿陣營"))
	e.mustSetMode(t, admin, act.ID, FactionSelectFree)

	target := e.seedAccount(t, "Select.Life.Player", "玩家丁",
		account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, admin, act.ID, target.ID, "丁")
	player := identitytest.Account(t, target.ID)

	// 草稿：管理側準備得再齊，玩家那一側還輪不到他把自己定下來。
	if err := e.selectErr(player, act.ID, faction.ID, idgen.Nil); !errors.Is(err,
		ErrFactionSelectNotOpen) {
		t.Errorf("草稿應回 ErrFactionSelectNotOpen，實際 %v", err)
	}
	view, err := e.service.MyFactionSelection(context.Background(), player, act.ID)
	if err != nil {
		t.Fatalf("草稿期的現況讀法仍要成功（仍列、可讀）：%v", err)
	}
	if view.CanSelectNow() {
		t.Error("草稿期 CanSelectNow 必須是假")
	}

	e.transition(t, admin, act.ID, StatusActive)
	e.mustSelect(t, player, act.ID, faction.ID, idgen.Nil)

	// 停止：等活動重開那一句（與草稿那一句分得開）。依據值留成「他以為還沒分組」的
	// 合法寫法，讓這一跳問到的是生命週期而不是寫法錯誤。
	e.transition(t, admin, act.ID, StatusClosed)
	if err := e.selectErr(player, act.ID, faction.ID, idgen.Nil); !errors.Is(err,
		ErrActivityClosedWrites) {
		t.Errorf("停止應回 ErrActivityClosedWrites，實際 %v", err)
	}
	// 停止態下配置仍可編輯（它屬活動自己的資料，與名稱描述同側），玩家照舊寫不進來。
	// 這一跳順手把模式收回 first_only，因此重開前先把它換回 free，
	// 才讓下面那兩句問到的是「停用陣營」而不是「已選過一次」。
	e.mustSetMode(t, admin, act.ID, FactionSelectFirstOnly)

	// 重新開放後把那個陣營停用：換進它被拒，而既有歸屬原樣保留。
	e.transition(t, admin, act.ID, StatusActive)
	e.mustSetMode(t, admin, act.ID, FactionSelectFree)
	other := e.mustCreateFaction(t, admin, act.ID, factionDraft("還開著的軍"))
	if _, err := e.service.UpdateFaction(context.Background(), admin, act.ID, faction.ID,
		func() FactionEdit {
			edit := factionEdit(faction, faction.Name)
			edit.Available = false
			return edit
		}(), "req-disable"); err != nil {
		t.Fatalf("停用陣營應成功：%v", err)
	}
	if err := e.selectErr(player, act.ID, faction.ID, other.ID); !errors.Is(err,
		ErrFactionNotAcceptingMembers) {
		t.Errorf("換進已停用的陣營應回 ErrFactionNotAcceptingMembers，實際 %v", err)
	}
	if f := e.memberFacts(t, member.ID); f.factionID.String != faction.ID.String() {
		t.Errorf("被拒的自選不能動既有歸屬，實際 %q", f.factionID.String)
	}
	view, err = e.service.MyFactionSelection(context.Background(), player, act.ID)
	if err != nil {
		t.Fatalf("停用後的現況讀法仍要成功：%v", err)
	}
	for _, option := range view.Options {
		switch option.Faction.ID {
		case faction.ID:
			if option.Selectable {
				t.Error("停用的陣營在候選清單裡必須標成不可選")
			}
		case other.ID:
			if !option.Selectable {
				t.Error("還開著的陣營必須標成可選")
			}
		}
	}
	// 選一個還開著的：成立——停用只約束新分配，不凍結任何人。
	e.mustSelect(t, player, act.ID, other.ID, faction.ID)

	// 歸檔：終態那一句，讀仍列、寫一律拒。
	e.transition(t, admin, act.ID, StatusArchived)
	if err := e.selectErr(player, act.ID, faction.ID, other.ID); !errors.Is(err, ErrArchived) {
		t.Errorf("歸檔應回 ErrArchived，實際 %v", err)
	}
	if _, err := e.service.MyFactionSelection(context.Background(), player, act.ID); err != nil {
		t.Errorf("歸檔後本人仍讀得到自己的現況（仍列、可讀）：%v", err)
	}
	if _, err := e.service.UpdateFactionSelectMode(context.Background(), admin, act.ID,
		FactionSelectDisabled, FactionSelectFirstOnly, "req-archived-mode"); !errors.Is(err,
		ErrArchived) {
		t.Errorf("歸檔後配置一律拒寫，實際 %v", err)
	}
}

// TestFactionSelectConcurrentWithConfig 驗收「配置變更、停用陣營與自選並發時不能繞過限制」：
// 客戶端交來的依據值完全合法，但那欄配置與那個旗標都在他看不見的時候被人動過——
// 判定在寫入交易內現讀，於是那幾次自選一個字都沒落。CAS 落敗那一句也是同一形狀。
func TestFactionSelectConcurrentWithConfig(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.admin(t, "Select.Race")
	act := e.create(t, admin, "並發的場", "")
	e.transition(t, admin, act.ID, StatusActive)
	faction := e.mustCreateFaction(t, admin, act.ID, factionDraft("並發陣營"))
	e.mustSetMode(t, admin, act.ID, FactionSelectFree)

	target := e.seedAccount(t, "Select.Race.Player", "玩家戊",
		account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, admin, act.ID, target.ID, "戊")
	player := identitytest.Account(t, target.ID)

	// 玩家手上的畫面讀到的是「開著、陣營可用、他還沒分組」，隨後管理側把開關收回。
	e.mustSetMode(t, admin, act.ID, FactionSelectDisabled)
	if err := e.selectErr(player, act.ID, faction.ID, idgen.Nil); !errors.Is(err,
		ErrFactionSelectDisabled) {
		t.Errorf("開關已被收回，自選應回 ErrFactionSelectDisabled，實際 %v", err)
	}
	if f := e.memberFacts(t, member.ID); f.factionID.Valid {
		t.Errorf("繞不過那道閘：庫裡不能有歸屬，實際 %q", f.factionID.String)
	}

	// 重新開放後讓自選落地，再於「玩家仍拿著上一份現值」的時候把目標那個陣營停用。
	e.mustSetMode(t, admin, act.ID, FactionSelectFree)
	e.mustSelect(t, player, act.ID, faction.ID, idgen.Nil)
	other := e.mustCreateFaction(t, admin, act.ID, factionDraft("另一軍"))
	if _, err := e.service.UpdateFaction(context.Background(), admin, act.ID, other.ID,
		func() FactionEdit {
			edit := factionEdit(other, other.Name)
			edit.Available = false
			return edit
		}(), "req-stop-other"); err != nil {
		t.Fatalf("停用另一軍應成功：%v", err)
	}
	if err := e.selectErr(player, act.ID, other.ID, faction.ID); !errors.Is(err,
		ErrFactionNotAcceptingMembers) {
		t.Errorf("換進已被停用的陣營應回 ErrFactionNotAcceptingMembers，實際 %v", err)
	}
	// 同一時的停用也可能發生在活動被停止之後：那一跳的處置是等活動重開，不是繞過去。
	e.transition(t, admin, act.ID, StatusClosed)
	if err := e.selectErr(player, act.ID, faction.ID, other.ID); !errors.Is(err,
		ErrActivityClosedWrites) {
		t.Errorf("活動被停止後的自選應回 ErrActivityClosedWrites，實際 %v", err)
	}
	e.transition(t, admin, act.ID, StatusActive)

	// 同一個人的兩個裝置拿著同一份現值先後送出：帶 WHERE 的單向更新讓第二次落敗，
	// 現值是贏家那份，而且只多一條留痕。
	third := e.mustCreateFaction(t, admin, act.ID, factionDraft("第三軍"))
	fourth := e.mustCreateFaction(t, admin, act.ID, factionDraft("第四軍"))
	winner := e.mustSelect(t, player, act.ID, third.ID, faction.ID)
	// 落敗者的那一份：目標是還開著的陣營、依據值是它讀到過的舊歸屬——
	// 兩個輸入都合法，錯的只是「它看不見中間那一次已成功寫入」。
	if err := e.selectErr(player, act.ID, fourth.ID, faction.ID); !errors.Is(err,
		ErrMemberProfileConflict) {
		t.Errorf("依據值已過期的第二次應回 ErrMemberProfileConflict，實際 %v", err)
	}
	if f := e.memberFacts(t, member.ID); f.factionID.String != third.ID.String() {
		t.Errorf("落敗者不得覆蓋贏家，實際 %q", f.factionID.String)
	}
	if got := e.countAuditRows(t, "member.faction_select", act.ID.String()); got != 2 {
		t.Errorf("兩次成功各記一筆、落敗不記，實際 %d 筆", got)
	}
	if f := e.memberFacts(t, member.ID); f.updatedAt != millisOf(winner.UpdatedAt) {
		t.Errorf("updated_at 必須停在贏家那一跳，實際 %d／%v", f.updatedAt, winner.UpdatedAt)
	}

	// 配置那一側同形：拿過期的模式依據值保存，落敗且一欄都沒動。
	if _, err := e.service.UpdateFactionSelectMode(context.Background(), admin, act.ID,
		FactionSelectFirstOnly, FactionSelectDisabled, "req-mode-loser"); !errors.Is(err,
		ErrProfileConflict) {
		t.Errorf("配置依據值已過期應回 ErrProfileConflict，實際 %v", err)
	}
	if got := e.modeFacts(t, act.ID); got != FactionSelectFree.String() {
		t.Errorf("落敗的配置保存不得改寫現值，實際 %q", got)
	}
}

// TestFactionSelectAdminScope 驗收那一欄配置的準入：它是活動管理面的一道閘，
// 不是伺服器級目錄，也不是玩家可以自己打開的東西。
func TestFactionSelectAdminScope(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.admin(t, "Select.Scope")
	outsider, _ := e.admin(t, "Select.OtherAdmin")
	mine := e.create(t, admin, "我的場", "")

	// 普通帳戶連自己那場活動的模式都改不了（NeedServerAdmin 那一半先擋）。
	plain := e.plain(t, "Select.Scope.Player")
	if _, err := e.service.UpdateFactionSelectMode(context.Background(), plain, mine.ID,
		FactionSelectFree, FactionSelectDisabled, "req-plain"); !errors.Is(err,
		identity.ErrPermissionDenied) {
		t.Errorf("普通帳戶改配置應回權限不足，實際 %v", err)
	}
	// 別的活動的管理員改不到別人活動，而且與「從未存在」同一句話。
	phantom := identitytest.NewID(t)
	for _, id := range []idgen.ID{mine.ID, phantom} {
		if _, err := e.service.UpdateFactionSelectMode(context.Background(), outsider, id,
			FactionSelectFree, FactionSelectDisabled, "req-scope"); !errors.Is(err,
			ErrActivityNotFound) {
			t.Errorf("外人管理員對 %s 應回不可分辨的 ErrActivityNotFound，實際 %v", id, err)
		}
	}
	// Root 讀得到也改得動（NeedServerAdmin 加活動作用域那兩半它都過）。
	updated := e.mustSetMode(t, identitytest.Root(t, identity.OriginHTTPRequest),
		mine.ID, FactionSelectFree)
	if updated.FactionSelectMode != FactionSelectFree {
		t.Errorf("Root 的配置寫入要回讀新值，實際 %q", updated.FactionSelectMode)
	}
	if got := e.modeFacts(t, mine.ID); got != "free" {
		t.Errorf("庫裡現值必須是 free，實際 %q", got)
	}
	// 玩家自己絕過不了配置那一條：他即使是那個活動的成員也一樣。
	target := e.seedAccount(t, "Select.Scope.Member", "場內玩家",
		account.TypeStandard, account.StatusActive)
	e.mustCreateMember(t, admin, mine.ID, target.ID, "場內的我")
	if _, err := e.service.UpdateFactionSelectMode(context.Background(),
		identitytest.Account(t, target.ID), mine.ID, FactionSelectDisabled,
		FactionSelectFree, "req-self-config"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("成員改活動配置應回權限不足，實際 %v", err)
	}
	if got := e.modeFacts(t, mine.ID); got != "free" {
		t.Errorf("被拒的配置寫入不得動現值，實際 %q", got)
	}
}

// TestFactionSelectDoesNotTouchAccount 驗收自選不動帳戶：憑據雜湊、狀態、首改旗標與
// 伺服器級授予筆數前後不變（玩家在活動內換組，與他能不能登入、有沒有權限無關）。
func TestFactionSelectDoesNotTouchAccount(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.admin(t, "Select.Account")
	act := e.create(t, admin, "不動帳戶的場", "")
	e.transition(t, admin, act.ID, StatusActive)
	faction := e.mustCreateFaction(t, admin, act.ID, factionDraft("一個軍"))
	e.mustSetMode(t, admin, act.ID, FactionSelectFree)

	target := e.seedAccount(t, "Select.Account.Player", "玩家庚",
		account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, admin, act.ID, target.ID, "庚")
	before := e.accountFacts(t, target.ID)
	grantsBefore := e.countRows(t, "account_server_roles")

	e.mustSelect(t, identitytest.Account(t, target.ID), act.ID, faction.ID, idgen.Nil)

	if after := e.accountFacts(t, target.ID); after != before {
		t.Errorf("自選改寫了帳戶側事實：\n舊 %s\n新 %s", before, after)
	}
	if got := e.countRows(t, "account_server_roles"); got != grantsBefore {
		t.Errorf("自選不得增減任何授予，實際 %d／%d", got, grantsBefore)
	}
	if f := e.memberFacts(t, member.ID); f.factionID.String != faction.ID.String() {
		t.Errorf("自選要落在成員行的歸屬上，實際 %q", f.factionID.String)
	}
}

// accountFacts 讀一列帳戶裡那些「自選絕不該動」的欄位（等值比較用的單段文本）。
func (e *env) accountFacts(t *testing.T, id idgen.ID) string {
	t.Helper()
	var login, display, hash, status, accType string
	var mustChange int64
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT login_name, display_name,
			password_hash, status, account_type, must_change_password
		FROM accounts WHERE id = ?`, id.String()).
		Scan(&login, &display, &hash, &status, &accType, &mustChange)
	if err != nil {
		t.Fatalf("讀取帳戶 %s 失敗：%v", id, err)
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%d", login, display, hash, status, accType, mustChange)
}
