// memberrestriction_test.go 是玩家分項限制與活動訪問控制在服務層的證據：
// 出廠六欄全不限制、逐欄獨立編輯（取消一項不順手取消另一項）、非目標欄位不變、
// 依據值過期整個編輯不落、冪等重送不製造第二條留痕、請求寫法三種拒法、
// 訪問限制擋下玩家族全部通路而本人查閱與清單照舊、五枚未接入能力的逐鍵判定、
// 跨活動隔離、審計帶操作者與前後值、門禁與准入（管理者編輯權與目標玩家訪問權分離），
// 以及「解除限制後的下一筆請求按新值回答」——倉庫今日沒有實時層，本檔也不宣稱有推送。
//
// 刻意不收的東西：
//   - 沒有替身：授權、門禁、CAS 與審計都走真路徑（真資料庫＋注入時鐘）；
//   - 不測協定層（欄位注入 1004、機器碼 2043 對映）：那是 internal/httpapi 的端點證據；
//   - 不測聊天／私聊／交易／轉賬／使用物品的「業務效果」：那些業務尚未實現，
//     本檔只能取證判定介面與旗標本身，不記成端到端通過。
package activity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// restrictionFacts 是一行成員在資料庫裡與分項限制有關的可觀察形態。
//
// 它把六欄之外的事實（暱稱、歸屬、覆蓋、狀態）也一起讀回來：「只碰被選中的項」
// 這句話要能被逐字比對，而不是靠斷言少寫幾欄蒙對。
type restrictionFacts struct {
	login, chat, privateChat            int64
	trade, transfer, itemUse            int64
	nickname                            string
	factionID                           sql.NullString
	directoryVisibility, businessStatus string
	createdAt, updatedAt                int64
}

func (e *env) restrictionFacts(t *testing.T, id idgen.ID) restrictionFacts {
	t.Helper()
	var f restrictionFacts
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT restrict_login,
			restrict_chat, restrict_private_chat, restrict_trade, restrict_transfer,
			restrict_item_use, nickname, faction_id, directory_visibility,
			business_status, created_at, updated_at
		FROM activity_members WHERE id = ?`, id.String()).
		Scan(&f.login, &f.chat, &f.privateChat, &f.trade, &f.transfer, &f.itemUse,
			&f.nickname, &f.factionID, &f.directoryVisibility, &f.businessStatus,
			&f.createdAt, &f.updatedAt)
	if err != nil {
		t.Fatalf("讀取成員 %s 的限制事實失敗：%v", id.String(), err)
	}
	return f
}

// snapshot 把六欄換成可整體比對的字串（未動的限制用它逐字斷言）。
func (f restrictionFacts) snapshot() string {
	return fmt.Sprintf("%d,%d,%d,%d,%d,%d",
		f.login, f.chat, f.privateChat, f.trade, f.transfer, f.itemUse)
}

func (f restrictionFacts) allUnrestricted() bool { return f.snapshot() == "0,0,0,0,0,0" }

// restrictionEdit 湊一筆只含指定幾對欄位的編輯。
func restrictionEdit(pairs ...MemberRestrictionChange) MemberRestrictionEdit {
	return MemberRestrictionEdit{Changes: pairs}
}

// mustRestrict 送一次必須成功的分項限制編輯。
func (e *env) mustRestrict(t *testing.T, principal identity.Principal,
	activityID, memberID idgen.ID, edit MemberRestrictionEdit) Member {
	t.Helper()
	updated, err := e.service.UpdateMemberRestrictions(context.Background(), principal,
		activityID, memberID, edit, "req-restriction")
	if err != nil {
		t.Fatalf("編輯分項限制應成功：%v", err)
	}
	return updated
}

// restrictErr 送一次預期失敗的編輯並把錯誤原樣交回來。
func (e *env) restrictErr(principal identity.Principal, activityID, memberID idgen.ID,
	edit MemberRestrictionEdit) error {
	_, err := e.service.UpdateMemberRestrictions(context.Background(), principal,
		activityID, memberID, edit, "req-restriction-err")
	return err
}

// restrictionScene 湊一個「兩場活動、兩位玩家、一位管理人」的現場：
// 跨活動隔離與玩家族擋下都需要第二場活動與第二個人做反證。
type restrictionScene struct {
	e        *env
	admin    identity.Principal
	activity Activity
	other    Activity
	player   identity.Principal
	otherGuy identity.Principal
	member   Member
}

func newRestrictionScene(t *testing.T, login string) *restrictionScene {
	t.Helper()
	e := newEnv(t)
	principal, _ := e.admin(t, login)
	current := e.create(t, principal, login+"的場", "")
	other := e.create(t, principal, login+"的另一場", "")
	jia := e.seedAccount(t, login+".甲", "玩家甲", account.TypeStandard, account.StatusActive)
	ying := e.seedAccount(t, login+".乙", "玩家乙", account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, principal, current.ID, jia.ID, login+"的甲")
	e.mustCreateMember(t, principal, current.ID, ying.ID, login+"的乙")
	e.mustCreateMember(t, principal, other.ID, jia.ID, login+"的甲（另一場）")
	return &restrictionScene{
		e: e, admin: principal, activity: current, other: other,
		player: identitytest.Account(t, jia.ID), otherGuy: identitytest.Account(t, ying.ID),
		member: member,
	}
}

// memberIn 從管理名冊裡找出「那個帳戶在那場活動」的成員行（倉儲現读的服務層外殼）。
func (s *restrictionScene) memberIn(t *testing.T, activityID idgen.ID,
	accountID idgen.ID) Member {
	t.Helper()
	rows, err := s.e.service.Members(context.Background(), s.admin, activityID)
	if err != nil {
		t.Fatalf("讀名冊 %s 失敗：%v", activityID, err)
	}
	for _, row := range rows {
		if row.AccountID == accountID {
			return row
		}
	}
	t.Fatalf("名冊 %s 裡沒有帳戶 %s 的行", activityID, accountID)
	return Member{}
}

// setLogin 是本檔最常用的動作：禁止（或恢復）該活動訪問資格。
func (s *restrictionScene) setLogin(t *testing.T, on bool) {
	t.Helper()
	current := s.e.restrictionFacts(t, s.member.ID)
	s.e.mustRestrict(t, s.admin, s.activity.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{
			Key: RestrictionLogin, Value: on, Expected: current.login == 1,
		}))
}

// latestRestrictionAudit 讀 member.restrictions_update 最新一筆活動域留痕。
//
// 它按 id 倒序而不是時刻倒序：注入時鐘在同一毫秒內落多筆時，
// 「最新一筆」必須由 UUIDv7 的時間性標識自己排（口徑同 UNIQUE 破平的理由）。
func (e *env) latestRestrictionAudit(t *testing.T, activityID string) memberAuditRow {
	t.Helper()
	var row memberAuditRow
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT actor_kind,
			COALESCE(actor_id, ''), reason, changes_json
		FROM activity_audit WHERE action = 'member.restrictions_update'
			AND activity_id = ?
		ORDER BY id DESC LIMIT 1`, activityID).
		Scan(&row.actorKind, &row.actorID, &row.reason, &row.changes)
	if err != nil {
		t.Fatalf("讀取分項限制留痕失敗：%v", err)
	}
	return row
}

// TestMemberRestrictionBirthIsUnrestricted 驗收：新成員六欄全假（出廠不限制），
// 本人查閱讀得到六個布林，本人清單與名冊帶著現值。
func TestMemberRestrictionBirthIsUnrestricted(t *testing.T) {
	s := newRestrictionScene(t, "Restrict.Birth")
	e := s.e
	ctx := context.Background()

	facts := e.restrictionFacts(t, s.member.ID)
	if !facts.allUnrestricted() {
		t.Fatalf("新成員必須出廠不限制，實際 %s", facts.snapshot())
	}
	own, err := e.service.OwnMemberRestrictions(ctx, s.player, s.activity.ID)
	if err != nil {
		t.Fatalf("本人查閱限制應成功：%v", err)
	}
	if own.RestrictLogin || own.RestrictChat || own.RestrictPrivateChat ||
		own.RestrictTrade || own.RestrictTransfer || own.RestrictItemUse {
		t.Errorf("本人投影必須逐欄讀出不限制，實際 %+v", own)
	}
	entries, err := e.service.MyActivityEntries(ctx, s.player)
	if err != nil || len(entries) != 2 {
		t.Fatalf("本人清單應讀回兩場：%v（%d 場）", err, len(entries))
	}
	for _, entry := range entries {
		if entry.Member.RestrictLogin {
			t.Errorf("清單的成員行不該帶著限制，實際 %+v", entry.Member)
		}
	}
	roster, err := e.service.Members(ctx, s.admin, s.activity.ID)
	if err != nil || len(roster) != 2 {
		t.Fatalf("名冊應讀回兩行：%v（%d 行）", err, len(roster))
	}
	for _, row := range roster {
		if row.RestrictLogin || row.RestrictTrade {
			t.Errorf("名冊行必須帶著出廠不限制，實際 %+v", row)
		}
	}
}

// TestMemberRestrictionUpdateIsPerField 驗收：逐欄獨立生效——取消聊天不順手取消
// 私聊或登入；每一筆編輯之後，未選中的欄位與身分／歸屬／覆蓋／狀態逐字不動。
func TestMemberRestrictionUpdateIsPerField(t *testing.T) {
	s := newRestrictionScene(t, "Restrict.PerField")
	e := s.e
	before := e.restrictionFacts(t, s.member.ID)

	updated := e.mustRestrict(t, s.admin, s.activity.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionLogin, Value: true, Expected: false}))
	if !updated.RestrictLogin {
		t.Fatalf("編輯結果要如實回顯，實際 %+v", updated)
	}
	facts := e.restrictionFacts(t, s.member.ID)
	if facts.snapshot() != "1,0,0,0,0,0" {
		t.Fatalf("第一筆編輯只准翻 login，實際 %s", facts.snapshot())
	}

	// 一次翻兩欄（聊天＋私聊）。
	e.mustRestrict(t, s.admin, s.activity.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionChat, Value: true, Expected: false},
		MemberRestrictionChange{Key: RestrictionPrivateChat, Value: true, Expected: false}))
	facts = e.restrictionFacts(t, s.member.ID)
	if facts.snapshot() != "1,1,1,0,0,0" {
		t.Fatalf("第二筆編輯該翻 chat 與 private_chat，實際 %s", facts.snapshot())
	}

	// 只取消聊天：私聊與登入必須原樣留下。
	e.mustRestrict(t, s.admin, s.activity.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionChat, Value: false, Expected: true}))
	facts = e.restrictionFacts(t, s.member.ID)
	if facts.snapshot() != "1,0,1,0,0,0" {
		t.Fatalf("取消聊天不該順手取消私聊或登入，實際 %s", facts.snapshot())
	}

	// 非目標欄位逐字不動：暱稱、歸屬、覆蓋、業務狀態與建立時刻。
	if facts.nickname != before.nickname || facts.factionID != before.factionID ||
		facts.directoryVisibility != before.directoryVisibility ||
		facts.businessStatus != before.businessStatus || facts.createdAt != before.createdAt {
		t.Errorf("限制編輯不該碰身分與其餘事實：\n舊 %+v\n新 %+v", before, facts)
	}
	if facts.updatedAt < before.updatedAt {
		t.Errorf("限制編輯不該讓 updated_at 倒退：%d→%d", before.updatedAt, facts.updatedAt)
	}
}

// TestMemberRestrictionConflictAndIdempotent 驗收：任一欄依據值過期時整個編輯不落
// （不半套生效）；新值與現值相同且依據相符是冪等成功——不寫入、不追加第二條留痕。
func TestMemberRestrictionConflictAndIdempotent(t *testing.T) {
	s := newRestrictionScene(t, "Restrict.Conflict")
	e := s.e

	e.mustRestrict(t, s.admin, s.activity.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionLogin, Value: true, Expected: false}))
	auditCount := e.countAuditRows(t, "member.restrictions_update", s.activity.ID.String())
	facts := e.restrictionFacts(t, s.member.ID)

	// 過期依據值（以為 login 還不限制）：衝突、零落地、零留痕。
	err := e.restrictErr(s.admin, s.activity.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionLogin, Value: false, Expected: false},
		MemberRestrictionChange{Key: RestrictionTrade, Value: true, Expected: false}))
	if !errors.Is(err, ErrMemberProfileConflict) {
		t.Fatalf("過期依據值應回衝突，實際 %v", err)
	}
	after := e.restrictionFacts(t, s.member.ID)
	if after.snapshot() != facts.snapshot() || after.updatedAt != facts.updatedAt {
		t.Errorf("落敗的編輯一個字都不該落：\n舊 %s（%d）\n新 %s（%d）",
			facts.snapshot(), facts.updatedAt, after.snapshot(), after.updatedAt)
	}
	if got := e.countAuditRows(t, "member.restrictions_update", s.activity.ID.String()); got != auditCount {
		t.Errorf("被拒的編輯不追加審計：%d→%d", auditCount, got)
	}

	// 冪等重送（新值＝現值且依據相符）：成功、不寫入、不留痕。
	updated := e.mustRestrict(t, s.admin, s.activity.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionLogin, Value: true, Expected: true}))
	if !updated.RestrictLogin {
		t.Errorf("冪等重送要如實回顯現值，實際 %+v", updated)
	}
	after = e.restrictionFacts(t, s.member.ID)
	if after.updatedAt != facts.updatedAt {
		t.Errorf("冪等重送不該推進 updated_at：%d→%d", facts.updatedAt, after.updatedAt)
	}
	if got := e.countAuditRows(t, "member.restrictions_update", s.activity.ID.String()); got != auditCount {
		t.Errorf("冪等重送不製造第二條留痕：%d→%d", auditCount, got)
	}

	// 新值與現值相同、依據值卻過期：仍是衝突，不是冪等（口徑同自訂狀態編輯）。
	if err := e.restrictErr(s.admin, s.activity.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionLogin, Value: true, Expected: false})); !errors.Is(err, ErrMemberProfileConflict) {
		t.Fatalf("「看起來沒變」但依據過期該回衝突，實際 %v", err)
	}
}

// TestMemberRestrictionInvalidWrites 驗收三種請求寫法錯誤逐句同形且零落地：
// 一欄都沒帶、鍵不在封閉集合內、同一鍵出現兩次。
func TestMemberRestrictionInvalidWrites(t *testing.T) {
	s := newRestrictionScene(t, "Restrict.Invalid")
	e := s.e

	cases := []struct {
		name string
		edit MemberRestrictionEdit
	}{
		{"一欄都沒帶", restrictionEdit()},
		{"鍵不在集合內", restrictionEdit(MemberRestrictionChange{
			Key: MemberRestrictionKey("login_admin"), Value: true, Expected: false})},
		{"同一鍵出現兩次", restrictionEdit(
			MemberRestrictionChange{Key: RestrictionChat, Value: true, Expected: false},
			MemberRestrictionChange{Key: RestrictionChat, Value: false, Expected: false})},
	}
	for _, testCase := range cases {
		if err := e.restrictErr(s.admin, s.activity.ID, s.member.ID, testCase.edit); !errors.Is(err, ErrInvalidRestrictionUpdate) {
			t.Errorf("%s 應回請求寫法錯誤，實際 %v", testCase.name, err)
		}
	}
	if !e.restrictionFacts(t, s.member.ID).allUnrestricted() {
		t.Errorf("被拒的寫法不該留下任何限制")
	}
	if got := e.countAuditRows(t, "member.restrictions_update", s.activity.ID.String()); got != 0 {
		t.Errorf("被拒的寫法不留痕，實際 %d 筆", got)
	}
}

// TestMemberAccessGateBlocksPlayerFamily 驗收：禁止登入擋下玩家族全部通路
// （陣營現況、自選、目錄、單筆、本人資料、標籤清單與單筆），
// 而「本人查閱限制」與「本人活動清單」照舊讀得動；解除後的下一筆請求即恢復。
func TestMemberAccessGateBlocksPlayerFamily(t *testing.T) {
	s := newRestrictionScene(t, "Restrict.Gate")
	e := s.e
	e.transitionTo(t, s.admin, s.activity.ID, StatusActive)
	e.mustSetMode(t, s.admin, s.activity.ID, FactionSelectFree)
	faction := e.mustCreateFaction(t, s.admin, s.activity.ID, factionDraft("被試的那個組"))
	tag := e.mustCreateTag(t, s.admin, s.activity.ID, "被試的那枚")
	if _, err := e.setTagPublic(t, s.admin, tag, true); err != nil {
		t.Fatalf("公開標籤失敗：%v", err)
	}

	ctx := context.Background()
	// 出廠形態：全族都讀得動（反證——下面的擋不是本來就擋）。
	if _, err := e.service.MyFactionSelection(ctx, s.player, s.activity.ID); err != nil {
		t.Fatalf("未限制時陣營現況應可讀：%v", err)
	}

	s.setLogin(t, true)

	gated := []struct {
		name string
		call func() error
	}{
		{"陣營現況", func() error {
			_, err := e.service.MyFactionSelection(ctx, s.player, s.activity.ID)
			return err
		}},
		{"陣營自選", func() error {
			_, err := e.service.SelectOwnFaction(ctx, s.player, s.activity.ID,
				faction.ID, idgen.ID{}, "req-gate")
			return err
		}},
		{"玩家目錄", func() error {
			_, err := e.service.MemberDirectory(ctx, s.player, s.activity.ID,
				DirectoryMemberQuery{Page: 1, PageSize: DirectoryDefaultPageSize})
			return err
		}},
		{"目錄單筆", func() error {
			_, err := e.service.DirectoryMemberDetail(ctx, s.player, s.activity.ID, s.member.ID)
			return err
		}},
		{"本人資料", func() error {
			_, err := e.service.OwnMemberProfile(ctx, s.player, s.activity.ID)
			return err
		}},
		{"標籤清單", func() error {
			_, err := e.service.PublicTagCatalog(ctx, s.player, s.activity.ID)
			return err
		}},
		{"標籤單筆", func() error {
			_, err := e.service.PublicTagDetail(ctx, s.player, s.activity.ID, tag.ID)
			return err
		}},
	}
	before := e.restrictionFacts(t, s.member.ID)
	for _, entry := range gated {
		if err := entry.call(); !errors.Is(err, ErrMemberAccessRestricted) {
			t.Errorf("%s：被限制後應回訪問受限，實際 %v", entry.name, err)
		}
	}

	// 本人查閱與清單不在擋的範圍：被限制的人要能問出「我被限制的是哪些項」。
	own, err := e.service.OwnMemberRestrictions(ctx, s.player, s.activity.ID)
	if err != nil || !own.RestrictLogin {
		t.Errorf("被限制的人仍該讀得動本人查閱，實際 %v %+v", err, own)
	}
	entries, err := e.service.MyActivityEntries(ctx, s.player)
	if err != nil || len(entries) != 2 {
		t.Fatalf("被限制不該讓本人清單少一場：%v（%d 場）", err, len(entries))
	}

	// 同場另一位玩家不受牽連（限制掛在那一行，不是掛在活動上）。
	if _, err := e.service.OwnMemberProfile(ctx, s.otherGuy, s.activity.ID); err != nil {
		t.Errorf("未受限玩家的本人資料該照舊可讀：%v", err)
	}

	// 解除：下一筆請求按新值回答（請求級失效，沒有推送可言）。
	s.setLogin(t, false)
	if _, err := e.service.MyFactionSelection(ctx, s.player, s.activity.ID); err != nil {
		t.Errorf("解除後的下一筆請求該恢復可讀：%v", err)
	}
	if _, err := e.service.MemberDirectory(ctx, s.player, s.activity.ID,
		DirectoryMemberQuery{Page: 1, PageSize: DirectoryDefaultPageSize}); err != nil {
		t.Errorf("解除後的目錄該恢復可讀：%v", err)
	}
	after := e.restrictionFacts(t, s.member.ID)
	if after.nickname != before.nickname || after.factionID != before.factionID {
		t.Errorf("擋與放都不該動身分與歸屬： %+v → %+v", before, after)
	}
}

// TestMemberCapabilityJudgementInterface 驗收：統一能力判定介面逐鍵回答——
// login 走訪問受限那句話，其餘五枚各帶自己的鍵；未限制時原樣讀回成員行；
// 非成員在判定之前先收斂成「不在可見範圍」，限制不成為存在性探測器。
func TestMemberCapabilityJudgementInterface(t *testing.T) {
	s := newRestrictionScene(t, "Restrict.Capability")
	e := s.e
	ctx := context.Background()
	q := e.db.SQL()

	// 未限制：逐鍵都原樣讀回成員行。
	for _, key := range MemberRestrictionKeys() {
		member, err := e.service.EnsureMemberCapability(ctx, q, s.activity.ID,
			s.player.AccountID(), key)
		if err != nil || member.ID != s.member.ID {
			t.Errorf("%s：未限制時判定該讀回本人行，實際 %v %+v", key, err, member)
		}
	}

	// 逐枚翻真：每次的依據值取剛讀回的現值，各鍵各的結論互不冒充。
	for _, key := range MemberRestrictionKeys() {
		own, err := e.service.OwnMemberRestrictions(ctx, s.player, s.activity.ID)
		if err != nil {
			t.Fatalf("讀本人現值失敗：%v", err)
		}
		current, ok := own.RestrictionValue(key)
		if !ok {
			t.Fatalf("%s：本人投影讀不出這一欄", key)
		}
		e.mustRestrict(t, s.admin, s.activity.ID, s.member.ID, restrictionEdit(
			MemberRestrictionChange{Key: key, Value: true, Expected: current}))
	}
	for _, key := range MemberRestrictionKeys() {
		_, err := e.service.EnsureMemberCapability(ctx, q, s.activity.ID,
			s.player.AccountID(), key)
		if key == RestrictionLogin {
			if !errors.Is(err, ErrMemberAccessRestricted) {
				t.Errorf("login 被限制應回訪問受限，實際 %v", err)
			}
			continue
		}
		var typed *MemberCapabilityRestrictedError
		if !errors.As(err, &typed) || typed.Key != key {
			t.Errorf("%s：應回帶著自己鍵的能力受限，實際 %v", key, err)
		}
		if !errors.Is(err, ErrMemberCapabilityRestricted) {
			t.Errorf("%s：errors.Is 對共用哨兵也該成立，實際 %v", key, err)
		}
	}

	// 訪問判定與能力判定同一句話：EnsureMemberActivityAccess 就是 login 那一格。
	if _, err := e.service.EnsureMemberActivityAccess(ctx, q, s.activity.ID,
		s.player.AccountID()); !errors.Is(err, ErrMemberAccessRestricted) {
		t.Errorf("EnsureMemberActivityAccess 被限制時該回訪問受限，實際 %v", err)
	}

	// 非成員：判定收斂成 ErrMemberNotFound，與「被限制」是兩句話。
	ghost := identitytest.NewID(t)
	if _, err := e.service.EnsureMemberActivityAccess(ctx, q, s.activity.ID,
		ghost); !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("非成員的訪問判定應收斂為不可見範圍，實際 %v", err)
	}
	// 集合外鍵在判定入口就被拒，不降級成「當成不限制」。
	if _, err := e.service.EnsureMemberCapability(ctx, q, s.activity.ID,
		s.player.AccountID(), MemberRestrictionKey("fly")); !errors.Is(err,
		ErrInvalidRestrictionUpdate) {
		t.Errorf("集合外鍵應回寫法錯誤，實際 %v", err)
	}
}

// TestMemberRestrictionCrossActivityIsolation 驗收：限制掛在（活動, 帳戶）那一行——
// 甲場被凍結不影響乙場，編輯拿別場成員標識拼進來與查無同一句話。
func TestMemberRestrictionCrossActivityIsolation(t *testing.T) {
	s := newRestrictionScene(t, "Restrict.Isolate")
	e := s.e
	ctx := context.Background()

	otherMember := s.memberIn(t, s.other.ID, s.player.AccountID())

	// 甲場禁止登入；乙場同一個人的行必須原樣。
	s.setLogin(t, true)
	if otherMember.RestrictLogin {
		t.Fatalf("另一場的出生行不該帶著限制：%+v", otherMember)
	}
	if _, err := e.service.EnsureMemberActivityAccess(ctx, e.db.SQL(), s.other.ID,
		s.player.AccountID()); err != nil {
		t.Errorf("另一場的訪問判定必須照舊通過：%v", err)
	}
	after := e.restrictionFacts(t, otherMember.ID)
	if !after.allUnrestricted() {
		t.Errorf("甲場的凍結不外溢到乙場：%s", after.snapshot())
	}

	// 拿甲場的成員標識拼進乙場的編輯路徑：與從未存在同一句話，且零落地。
	if err := e.restrictErr(s.admin, s.other.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionTrade, Value: true, Expected: false})); !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("跨活動編輯應收斂為不可見範圍，實際 %v", err)
	}
	if got := e.restrictionFacts(t, otherMember.ID); got.trade != 0 {
		t.Errorf("被拒的跨活動編輯不該在乙場留下限制：%+v", got)
	}

	// 反向：乙場的行被編輯後，甲場現值不受影響。
	e.mustRestrict(t, s.admin, s.other.ID, otherMember.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionChat, Value: true, Expected: false}))
	if got := e.restrictionFacts(t, s.member.ID); got.snapshot() != "1,0,0,0,0,0" {
		t.Errorf("甲場現值不該被乙場編輯牽動：%s", got.snapshot())
	}
}

// TestMemberRestrictionAuditCarriesActorAndChanges 驗收：留痕帶可信操作者、
// changes 逐欄前後值、原因句寫明批准邊界；凍結與解除各唸各的一句。
func TestMemberRestrictionAuditCarriesActorAndChanges(t *testing.T) {
	e := newEnv(t)
	principal, admin := e.admin(t, "Restrict.Audit")
	activity := e.create(t, principal, "有留痕的場", "")
	target := e.seedAccount(t, "Restrict.AuditPlayer", "玩家", account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, principal, activity.ID, target.ID, "被限制的那位")

	e.mustRestrict(t, principal, activity.ID, member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionLogin, Value: true, Expected: false},
		MemberRestrictionChange{Key: RestrictionTrade, Value: true, Expected: false}))

	row := e.latestRestrictionAudit(t, activity.ID.String())
	if row.actorKind != "admin" || row.actorID != admin.ID.String() {
		t.Errorf("留痕必須帶真實操作者，實際 %+v", row)
	}
	for _, want := range []string{"restrict_login", "restrict_trade", "false", "true"} {
		if !strings.Contains(row.changes, want) {
			t.Errorf("changes 必須帶逐欄前後值，缺 %q：實際 %s", want, row.changes)
		}
	}
	if strings.Contains(row.changes, "restrict_chat") {
		t.Errorf("未翻動的限制不進 changes：實際 %s", row.changes)
	}
	if !strings.Contains(row.reason, "不停用全域帳戶與會話") {
		t.Errorf("翻動 login 的原因句要寫明批准邊界，實際 %q", row.reason)
	}

	// 單獨解除 login 的原因句換一句：凍結與解除在查審計時是兩件事。
	e.mustRestrict(t, principal, activity.ID, member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionLogin, Value: false, Expected: true}))
	row = e.latestRestrictionAudit(t, activity.ID.String())
	if !strings.Contains(row.reason, "解除成員活動訪問資格限制") {
		t.Errorf("單獨解除 login 要唸解除那一句，實際 %q", row.reason)
	}
}

// TestMemberRestrictionLifecycleAndAdmission 驗收：編輯屬業務寫入（停止 2033、
// 歸檔 2029），讀法不受生命週期門禁；普通帳戶與未認證主體敲不進管理族編輯；
// 而凍結狀態下管理通路仍能讀與改——防止「凍結目標後連解除都做不了」。
func TestMemberRestrictionLifecycleAndAdmission(t *testing.T) {
	s := newRestrictionScene(t, "Restrict.Lifecycle")
	e := s.e
	ctx := context.Background()

	s.setLogin(t, true)

	// 普通帳戶與未認證主體都敲不進管理族的那條編輯（准入先於一切結論）。
	if err := e.restrictErr(s.player, s.activity.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionChat, Value: true, Expected: false})); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("普通帳戶敲管理編輯應被拒於准入，實際 %v", err)
	}
	if err := e.restrictErr(identitytest.Anonymous(t), s.activity.ID, s.member.ID,
		restrictionEdit(
			MemberRestrictionChange{Key: RestrictionChat, Value: true, Expected: false})); !errors.Is(err, identity.ErrNotAuthenticated) {
		t.Errorf("未認證主體應先撞身分問題，實際 %v", err)
	}

	// 停止態：編輯被門禁擋下；本人查閱與訪問判定照舊按現值回答。
	e.transitionTo(t, s.admin, s.activity.ID, StatusClosed)
	err := e.restrictErr(s.admin, s.activity.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionChat, Value: true, Expected: false}))
	if !errors.Is(err, ErrActivityClosedWrites) {
		t.Fatalf("停止態的編輯應回業務寫入門禁，實際 %v", err)
	}
	own, err := e.service.OwnMemberRestrictions(ctx, s.player, s.activity.ID)
	if err != nil || !own.RestrictLogin {
		t.Errorf("停止態不該擋本人查閱，實際 %v %+v", err, own)
	}
	if _, err := e.service.MemberDirectory(ctx, s.player, s.activity.ID,
		DirectoryMemberQuery{Page: 1, PageSize: DirectoryDefaultPageSize}); !errors.Is(err, ErrMemberAccessRestricted) {
		t.Errorf("停止態的訪問判定仍按現值擋下，實際 %v", err)
	}

	// 歸檔終態：一律拒寫；本人查閱仍讀得動（讀取不受生命週期門禁，口徑同標籤）。
	e.transitionTo(t, s.admin, s.activity.ID, StatusArchived)
	err = e.restrictErr(s.admin, s.activity.ID, s.member.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionChat, Value: true, Expected: false}))
	if !errors.Is(err, ErrArchived) {
		t.Fatalf("歸檔態的編輯應回終態拒寫，實際 %v", err)
	}
	if _, err := e.service.OwnMemberRestrictions(ctx, s.player, s.activity.ID); err != nil {
		t.Errorf("歸檔態不該擋本人查閱：%v", err)
	}
}

// TestMemberRestrictionManagerAuthorityIsIndependent 驗收：被凍結的是「他作為玩家的
// 訪問資格」；凍結目標的玩家不會讓管理名冊讀不出這一行，管理者才能解除它——
// 同時持有 server_admin 的成員在玩家族照樣被擋（批准語意：沒有豁免，只有作用對象之分）。
func TestMemberRestrictionManagerAuthorityIsIndependent(t *testing.T) {
	s := newRestrictionScene(t, "Restrict.Authority")
	e := s.e
	ctx := context.Background()

	yingMember := s.memberIn(t, s.activity.ID, s.otherGuy.AccountID())

	// 凍結「他作為玩家」的訪問資格（管理人經管理通路寫入）。
	e.mustRestrict(t, s.admin, s.activity.ID, yingMember.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionLogin, Value: true, Expected: false}))

	// 給同一個帳戶伺服器級授予：他此刻既是成員又是 server_admin。
	if err := e.grants.Grant(ctx, e.db.SQL(), s.otherGuy.AccountID(),
		identity.RoleServerAdmin); err != nil {
		t.Fatalf("授予第二位管理人失敗：%v", err)
	}

	// 他的玩家族讀法被擋——持有 server_admin 不構成豁免（限制只作用成員身份）。
	if _, err := e.service.MemberDirectory(ctx, s.otherGuy, s.activity.ID,
		DirectoryMemberQuery{Page: 1, PageSize: DirectoryDefaultPageSize}); !errors.Is(err, ErrMemberAccessRestricted) {
		t.Errorf("server_admin 的成員行被凍結時，玩家族該如實擋下，實際 %v", err)
	}

	// 但管理名冊按伺服器級判定走，不受任何一行成員的限制影響：
	// 管理人讀得到被凍結的行、也改得動它——凍結不會把解除通路一起凍掉。
	rows, err := e.service.Members(ctx, s.admin, s.activity.ID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("凍結一位玩家不該讓管理名冊讀不出：%v（%d 行）", err, len(rows))
	}
	for _, row := range rows {
		if row.AccountID == s.otherGuy.AccountID() && !row.RestrictLogin {
			t.Errorf("名冊必須如實帶著限制現值，實際 %+v", row)
		}
	}
	e.mustRestrict(t, s.admin, s.activity.ID, yingMember.ID, restrictionEdit(
		MemberRestrictionChange{Key: RestrictionLogin, Value: false, Expected: true}))
	if got := e.restrictionFacts(t, yingMember.ID); got.login != 0 {
		t.Errorf("管理者解除必須真的落地，實際 %s", got.snapshot())
	}
}
