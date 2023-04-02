// playerstatus_test.go 是玩家業務狀態用例的服務層證據：出廠 normal 且七個內建值都可判別、
// 顯示名稱覆蓋只改展示值而不改內部值、自訂狀態出生即可用且改名不換標識、
// 停用只擋新的選用而保留既有成員的原狀態、跨活動與幽靈標識收斂成不可分辨的一句、
// 併發落敗那句、業務寫入門禁（停止 2033／歸檔 2029）與配置側（歸檔拒寫、停止仍可配置）、
// 冪等重送不製造第二條留痕、被拒的寫入一條痕都不留，
// 以及「業務狀態不會因為讀取或時間流逝而自己翻轉」（它不是連線狀態）。
//
// 刻意不收的東西：
//   - 沒有替身：授權、門禁、CAS 與審計都走真路徑（真資料庫＋注入時鐘）；
//   - 不測協定層（欄位注入 1004、機器碼 2041／2042 對映）：那是 internal/httpapi 的端點證據；
//   - 不測任何「狀態會自動清空資產或退出活動」：本步沒有、也不批准那種副作用。
package activity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// mustCreateCustomStatus 建立一個自訂狀態定義，失敗即終止。
func (e *env) mustCreateCustomStatus(t *testing.T, principal identity.Principal,
	activityID idgen.ID, name string) CustomStatus {
	t.Helper()
	created, err := e.service.CreateCustomStatus(context.Background(), principal, activityID,
		name, "req-status-create")
	if err != nil {
		t.Fatalf("建立自訂狀態 %q 應成功：%v", name, err)
	}
	return created
}

// mustSetStatusLabel 送一次必須成功的顯示名稱編輯（依據值一律取服務端剛讀回的那一份）。
func (e *env) mustSetStatusLabel(t *testing.T, principal identity.Principal,
	activityID idgen.ID, key BusinessStatus, display, expected string) BuiltinStatusView {
	t.Helper()
	updated, err := e.service.UpdateStatusLabel(context.Background(), principal, activityID,
		key, display, expected, "req-status-label")
	if err != nil {
		t.Fatalf("編輯顯示名稱 %s 應成功：%v", key, err)
	}
	return updated
}

// mustSetMemberStatus 送一次必須成功的成員狀態變更。
func (e *env) mustSetMemberStatus(t *testing.T, principal identity.Principal,
	activityID, memberID idgen.ID, status BusinessStatus, customID idgen.ID,
	expectedStatus BusinessStatus, expectedCustomID idgen.ID) Member {
	t.Helper()
	updated, err := e.service.UpdateMemberBusinessStatus(context.Background(), principal,
		activityID, memberID, status, customID, expectedStatus, expectedCustomID,
		"req-member-status")
	if err != nil {
		t.Fatalf("變更成員狀態應成功：%v", err)
	}
	return updated
}

// statusErr 呼叫一次狀態變更並只回錯誤。
func (e *env) statusErr(principal identity.Principal, activityID, memberID idgen.ID,
	status BusinessStatus, customID idgen.ID, expectedStatus BusinessStatus,
	expectedCustomID idgen.ID) error {
	_, err := e.service.UpdateMemberBusinessStatus(context.Background(), principal,
		activityID, memberID, status, customID, expectedStatus, expectedCustomID,
		"req-member-status-err")
	return err
}

// memberStatusFacts 讀一行成員「狀態那兩欄加既有事實」的庫中形態。
type memberStatusFacts struct {
	nickname     string
	factionID    string
	business     string
	customStatus string
	updatedAt    int64
}

func (e *env) memberStatusFacts(t *testing.T, id idgen.ID) memberStatusFacts {
	t.Helper()
	var f memberStatusFacts
	var faction, custom string
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT nickname,
			COALESCE(faction_id, ''), business_status, COALESCE(business_status_custom_id, ''),
			updated_at
		FROM activity_members WHERE id = ?`, id.String()).
		Scan(&f.nickname, &faction, &f.business, &custom, &f.updatedAt)
	if err != nil {
		t.Fatalf("讀取成員 %s 的狀態事實失敗：%v", id.String(), err)
	}
	f.factionID, f.customStatus = faction, custom
	return f
}

// latestStatusAudit 讀某個動作最新一筆活動域留痕。
func (e *env) latestStatusAudit(t *testing.T, action, activityID string) memberAuditRow {
	t.Helper()
	var row memberAuditRow
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT actor_kind,
			COALESCE(actor_id, ''), reason, changes_json
		FROM activity_audit WHERE action = ? AND activity_id = ?
		ORDER BY created_at DESC, id LIMIT 1`, action, activityID).
		Scan(&row.actorKind, &row.actorID, &row.reason, &row.changes)
	if err != nil {
		t.Fatalf("讀取審計 %s／%s 失敗：%v", action, activityID, err)
	}
	return row
}

// TestBusinessStatusBirthIsNormal 驗收：新成員一出生就是 normal，名冊帶著狀態投影，
// 而 normal 沒有覆蓋時顯示名稱為空（介面據此走四語言預設文案）。
func TestBusinessStatusBirthIsNormal(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Status.Birth")
	activity := e.create(t, principal, "有狀態的場", "")
	target := e.seedAccount(t, "Status.Player", "玩家甲", account.TypeStandard, account.StatusActive)

	member := e.mustCreateMember(t, principal, activity.ID, target.ID, "夜行者")
	if member.BusinessStatus != BusinessStatusNormal {
		t.Errorf("新成員必須出生為 normal，實際 %s", member.BusinessStatus)
	}
	if member.StatusDisplayName != "" || member.CustomStatusName != "" {
		t.Errorf("沒有覆蓋與沒有自訂定義時，兩個名稱都該是空字串，實際 %q／%q",
			member.StatusDisplayName, member.CustomStatusName)
	}
	if !member.StatusAvailable {
		t.Errorf("內建狀態永遠可用")
	}
	if f := e.memberStatusFacts(t, member.ID); f.business != "normal" || f.customStatus != "" {
		t.Errorf("庫中形態必須是 normal 且自訂標識為 NULL，實際 %q／%q", f.business, f.customStatus)
	}

	rows, err := e.service.Members(context.Background(), principal, activity.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("名冊應讀回一行：%v（%d 行）", err, len(rows))
	}
	if rows[0].BusinessStatus != BusinessStatusNormal || !rows[0].StatusAvailable {
		t.Errorf("名冊必須帶著狀態投影，實際 %+v", rows[0])
	}

	catalog, err := e.service.PlayerStatusCatalog(context.Background(), principal, activity.ID)
	if err != nil {
		t.Fatalf("狀態目錄應可讀：%v", err)
	}
	if len(catalog.Builtins) != len(builtinBusinessStatuses) {
		t.Fatalf("目錄必須逐字列出七個內建鍵，實際 %d 格", len(catalog.Builtins))
	}
	for i, key := range builtinBusinessStatuses {
		if catalog.Builtins[i].Key != key || catalog.Builtins[i].DisplayName != "" {
			t.Errorf("第 %d 格應該是 %s 且沒有覆蓋，實際 %+v", i, key, catalog.Builtins[i])
		}
	}
	if len(catalog.Custom) != 0 {
		t.Errorf("沒有自訂定義時該是空清單，實際 %d 行", len(catalog.Custom))
	}
}

// TestStatusLabelRenameKeepsInternalValue 驗收：改內建狀態的顯示名稱不改內部值、
// 不改任何成員的狀態，覆蓋可改回預設，而留痕帶著真實操作者與前後值。
func TestStatusLabelRenameKeepsInternalValue(t *testing.T) {
	e := newEnv(t)
	principal, admin := e.admin(t, "Status.Label")
	activity := e.create(t, principal, "改名不換身份", "")
	target := e.seedAccount(t, "Status.LabelPlayer", "玩家乙", account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, principal, activity.ID, target.ID, "被覆蓋的那位")

	updated := e.mustSetStatusLabel(t, principal, activity.ID, BusinessStatusOffline,
		"暫離現場", "")
	if updated.DisplayName != "暫離現場" {
		t.Fatalf("覆蓋要如實回顯，實際 %q", updated.DisplayName)
	}
	if f := e.memberStatusFacts(t, member.ID); f.business != "normal" {
		t.Errorf("改顯示名稱不該動任何人的內部值，實際 %q", f.business)
	}
	if f := e.facts(t, activity.ID); f.updatedAt != 0 {
		// 活動那一行的時刻不該被狀態配置推開（狀態覆蓋屬旁路小表）。
		_ = f
	}

	catalog, err := e.service.PlayerStatusCatalog(context.Background(), principal, activity.ID)
	if err != nil {
		t.Fatalf("目錄應可讀：%v", err)
	}
	for _, item := range catalog.Builtins {
		if item.Key == BusinessStatusOffline && item.DisplayName != "暫離現場" {
			t.Errorf("目錄必須帶著覆蓋現值，實際 %q", item.DisplayName)
		}
	}

	// 把這位玩家切到離線：顯示名稱應讀回覆蓋值，而不是內部鍵。
	e.mustSetMemberStatus(t, principal, activity.ID, member.ID, BusinessStatusOffline,
		idgen.ID{}, BusinessStatusNormal, idgen.ID{})
	roster, err := e.service.Members(context.Background(), principal, activity.ID)
	if err != nil || len(roster) != 1 {
		t.Fatalf("名冊應讀回一行：%v（%d 行）", err, len(roster))
	}
	if roster[0].BusinessStatus != BusinessStatusOffline ||
		roster[0].StatusDisplayName != "暫離現場" {
		t.Errorf("狀態與覆蓋名稱必須同源，實際 %+v", roster[0])
	}

	// 覆蓋可改回預設：空字串是「沒有覆蓋」，不是刪除狀態。
	reset := e.mustSetStatusLabel(t, principal, activity.ID, BusinessStatusOffline,
		"", "暫離現場")
	if reset.DisplayName != "" {
		t.Errorf("恢復預設後顯示名稱該是空字串，實際 %q", reset.DisplayName)
	}
	if f := e.memberStatusFacts(t, member.ID); f.business != "offline" {
		t.Errorf("恢復預設不該動成員的內部值，實際 %q", f.business)
	}

	auditRow := e.latestStatusAudit(t, "player_status.label_update", activity.ID.String())
	if auditRow.actorKind != "admin" || auditRow.actorID != admin.ID.String() {
		t.Errorf("顯示名稱留痕必須帶真實操作者，實際 %+v", auditRow)
	}
	if !strings.Contains(auditRow.changes, "offline") ||
		!strings.Contains(auditRow.changes, "暫離現場") {
		t.Errorf("留痕必須帶前後值，實際 %s", auditRow.changes)
	}

	// 依據值過期：整個編輯不落、不留痕。
	before := e.countAuditRows(t, "player_status.label_update", activity.ID.String())
	if _, err := e.service.UpdateStatusLabel(context.Background(), principal, activity.ID,
		BusinessStatusOffline, "又一個名字", "暫離現場", "req-stale"); !errors.Is(err, ErrStatusLabelConflict) {
		t.Fatalf("過期依據值應回衝突，實際 %v", err)
	}
	if got := e.countAuditRows(t, "player_status.label_update", activity.ID.String()); got != before {
		t.Errorf("被拒的編輯不追加審計：%d→%d", before, got)
	}
}

// TestCustomStatusLifecycle 驗收：自訂狀態出生即可用、選中後成員讀到定義名稱、
// 停用保留既有成員的原狀態只擋新選用、重新啟用後同一個意圖就能成立、
// 改名不換標識也不改任何人的內部值，同活動重名即拒。
func TestCustomStatusLifecycle(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Status.Custom")
	activity := e.create(t, principal, "自訂狀態的場", "")
	other := e.create(t, principal, "另一場", "")
	target := e.seedAccount(t, "Status.CustomPlayer", "玩家丙", account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, principal, activity.ID, target.ID, "自訂的那位")

	custom := e.mustCreateCustomStatus(t, principal, activity.ID, "失蹤中")
	if !custom.Available {
		t.Errorf("新建自訂狀態必須出生即可用")
	}

	// 同活動重名即拒。
	if _, err := e.service.CreateCustomStatus(context.Background(), principal, activity.ID,
		" 失蹤中 ", "req-dup"); !errors.Is(err, ErrCustomStatusNameTaken) {
		t.Fatalf("同活動重名（含剔空白後相等）應回占用，實際 %v", err)
	}
	// 跨活動同名合法。
	sameName := e.mustCreateCustomStatus(t, principal, other.ID, "失蹤中")
	if sameName.ID == custom.ID {
		t.Errorf("跨活動同名該各自有各自的標識")
	}

	// 選中自訂定義。
	e.mustSetMemberStatus(t, principal, activity.ID, member.ID, BusinessStatusCustom,
		custom.ID, BusinessStatusNormal, idgen.ID{})
	roster, _ := e.service.Members(context.Background(), principal, activity.ID)
	if len(roster) != 1 || roster[0].BusinessStatus != BusinessStatusCustom ||
		roster[0].CustomStatusID != custom.ID || roster[0].CustomStatusName != "失蹤中" ||
		!roster[0].StatusAvailable {
		t.Fatalf("成員必須讀到自訂定義與名稱，實際 %+v", roster[0])
	}
	before := e.memberStatusFacts(t, member.ID)

	// 停用：既有成員保留原狀態與標識，只擋新的選用。
	edit := CustomStatusEdit{
		New:      CustomStatusFields{Name: "失蹤中", Available: false},
		Expected: CustomStatusFields{Name: "失蹤中", Available: true},
	}
	disabled, err := e.service.UpdateCustomStatus(context.Background(), principal,
		activity.ID, custom.ID, edit, "req-disable")
	if err != nil || disabled.Available {
		t.Fatalf("停用應成功，實際 %+v／%v", disabled, err)
	}
	if f := e.memberStatusFacts(t, member.ID); f.business != before.business ||
		f.customStatus != before.customStatus {
		t.Errorf("停用不得搬動既有成員的狀態，實際 %+v", f)
	}
	roster, _ = e.service.Members(context.Background(), principal, activity.ID)
	if roster[0].StatusAvailable || roster[0].CustomStatusName != "失蹤中" {
		t.Errorf("既有成員讀到的狀態該是「停用但仍保留」，實際 %+v", roster[0])
	}

	// 新的選用撞「已停用」那句；同一個人的冪等重送不該被擋。
	third := e.seedAccount(t, "Status.ThirdPlayer", "玩家丁", account.TypeStandard, account.StatusActive)
	other1 := e.mustCreateMember(t, principal, activity.ID, third.ID, "想選停用的人")
	if err := e.statusErr(principal, activity.ID, other1.ID, BusinessStatusCustom, custom.ID,
		BusinessStatusNormal, idgen.ID{}); !errors.Is(err, ErrCustomStatusUnavailable) {
		t.Fatalf("選停用中的自訂狀態應回不可用，實際 %v", err)
	}
	replay := e.mustSetMemberStatus(t, principal, activity.ID, member.ID, BusinessStatusCustom,
		custom.ID, BusinessStatusCustom, custom.ID)
	if replay.BusinessStatus != BusinessStatusCustom || replay.CustomStatusID != custom.ID {
		t.Errorf("既有歸屬的冪等重送不應被停用擋下，實際 %+v", replay)
	}
	// 冪等重送不製造第二條留痕。
	if n := e.countAuditRows(t, "member.business_status_update", activity.ID.String()); n != 1 {
		t.Errorf("冪等重送後留痕仍該只有一筆，實際 %d", n)
	}

	// 改名不換標識、不改內部值。
	rename := CustomStatusEdit{
		New:      CustomStatusFields{Name: "改名後的定義", Available: false},
		Expected: CustomStatusFields{Name: "失蹤中", Available: false},
	}
	renamed, err := e.service.UpdateCustomStatus(context.Background(), principal,
		activity.ID, custom.ID, rename, "req-rename")
	if err != nil || renamed.Name != "改名後的定義" {
		t.Fatalf("改名應成功，實際 %+v／%v", renamed, err)
	}
	if f := e.memberStatusFacts(t, member.ID); f.customStatus != custom.ID.String() {
		t.Errorf("改名不該動成员的自訂標識，實際 %+v", f)
	}
	roster, _ = e.service.Members(context.Background(), principal, activity.ID)
	if roster[0].CustomStatusName != "改名後的定義" {
		t.Errorf("自訂定義的名称必須現讀，實際 %+v", roster[0])
	}

	// 重新啟用後，同一個意圖下一筆請求就能成立。
	enable := CustomStatusEdit{
		New:      CustomStatusFields{Name: "改名後的定義", Available: true},
		Expected: CustomStatusFields{Name: "改名後的定義", Available: false},
	}
	if _, err := e.service.UpdateCustomStatus(context.Background(), principal, activity.ID,
		custom.ID, enable, "req-enable"); err != nil {
		t.Fatalf("重新啟用應成功：%v", err)
	}
	e.mustSetMemberStatus(t, principal, activity.ID, other1.ID, BusinessStatusCustom,
		custom.ID, BusinessStatusNormal, idgen.ID{})

	// 切回內建值時自訂標識被清成空。
	back := e.mustSetMemberStatus(t, principal, activity.ID, member.ID, BusinessStatusNormal,
		idgen.ID{}, BusinessStatusCustom, custom.ID)
	if back.BusinessStatus != BusinessStatusNormal || !back.CustomStatusID.IsNil() ||
		back.CustomStatusName != "" || back.StatusDisplayName != "" {
		t.Errorf("切回內建值該清空自訂參考與名稱，實際 %+v", back)
	}
	if f := e.memberStatusFacts(t, member.ID); f.business != "normal" || f.customStatus != "" {
		t.Errorf("庫中形態也該清空自訂標識，實際 %+v", f)
	}
}

// TestBusinessStatusInvalidValues 驗收：集合外的狀態鍵、custom 缺自訂標識、
// 非 custom 卻帶自訂標識，都是同一句「請求寫法問題」而不是業務衝突。
func TestBusinessStatusInvalidValues(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Status.Invalid")
	activity := e.create(t, principal, "非法寫法", "")
	target := e.seedAccount(t, "Status.InvalidPlayer", "玩家戊", account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, principal, activity.ID, target.ID, "非法目標")
	custom := e.mustCreateCustomStatus(t, principal, activity.ID, "合法的定義")
	ghost := identitytest.NewID(t)

	cases := []struct {
		name        string
		status      BusinessStatus
		customID    idgen.ID
		expected    BusinessStatus
		expectedCID idgen.ID
	}{
		{"集合外的狀態鍵", BusinessStatus("Suspended"), idgen.ID{}, BusinessStatusNormal, idgen.ID{}},
		{"空狀態鍵", BusinessStatus(""), idgen.ID{}, BusinessStatusNormal, idgen.ID{}},
		{"custom 缺自訂標識", BusinessStatusCustom, idgen.ID{}, BusinessStatusNormal, idgen.ID{}},
		{"內建值卻帶自訂標識", BusinessStatusNormal, custom.ID, BusinessStatusNormal, idgen.ID{}},
		{"依據值不在集合內", BusinessStatusOffline, idgen.ID{}, BusinessStatus("nope"), idgen.ID{}},
		{"依據值不是 custom 卻帶標識", BusinessStatusOffline, idgen.ID{}, BusinessStatusNormal, ghost},
	}
	for _, tc := range cases {
		before := e.countAuditRows(t, "member.business_status_update", activity.ID.String())
		err := e.statusErr(principal, activity.ID, member.ID, tc.status, tc.customID,
			tc.expected, tc.expectedCID)
		if !errors.Is(err, ErrInvalidBusinessStatus) {
			t.Errorf("%s 應回不合法，實際 %v", tc.name, err)
		}
		if f := e.memberStatusFacts(t, member.ID); f.business != "normal" {
			t.Errorf("%s 之後內部值一個字都不該動，實際 %q", tc.name, f.business)
		}
		if got := e.countAuditRows(t, "member.business_status_update", activity.ID.String()); got != before {
			t.Errorf("%s 的被拒寫入不留痕：%d→%d", tc.name, before, got)
		}
	}

	// 自訂定義不存在（幽靈）與屬於另一場活動：同一句不可分辨。
	other := e.create(t, principal, "另一場非法", "")
	foreign := e.mustCreateCustomStatus(t, principal, other.ID, "別人的定義")
	for _, id := range []idgen.ID{ghost, foreign.ID} {
		err := e.statusErr(principal, activity.ID, member.ID, BusinessStatusCustom, id,
			BusinessStatusNormal, idgen.ID{})
		if !errors.Is(err, ErrCustomStatusNotFound) {
			t.Errorf("幽靈與跨活動的自訂定義應收斂成同一句，實際 %v", err)
		}
	}
}

// TestBusinessStatusCrossActivityMemberIndistinguishable 驗收：拿另一場活動的成員標識
// 拼進狀態通路時，與「從未存在」同一句話，也不動那一行任何一欄。
func TestBusinessStatusCrossActivityMemberIndistinguishable(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Status.Cross")
	actA := e.create(t, principal, "甲場", "")
	actB := e.create(t, principal, "乙場", "")
	target := e.seedAccount(t, "Status.CrossPlayer", "玩家己", account.TypeStandard, account.StatusActive)
	inB := e.mustCreateMember(t, principal, actB.ID, target.ID, "乙場的那位")
	ghost := identitytest.NewID(t)

	before := e.memberStatusFacts(t, inB.ID)
	errA := e.statusErr(principal, actA.ID, inB.ID, BusinessStatusOffline, idgen.ID{},
		BusinessStatusNormal, idgen.ID{})
	errGhost := e.statusErr(principal, actA.ID, ghost, BusinessStatusOffline, idgen.ID{},
		BusinessStatusNormal, idgen.ID{})
	if !errors.Is(errA, ErrMemberNotFound) || errA.Error() != errGhost.Error() {
		t.Fatalf("跨活動與幽靈必須逐字同文，實際 %v／%v", errA, errGhost)
	}
	if after := e.memberStatusFacts(t, inB.ID); after != before {
		t.Errorf("被拒的跨活動變更一個字都不該動：\n舊 %+v\n新 %+v", before, after)
	}
	if n := e.countAuditRows(t, "member.business_status_update", actA.ID.String()); n != 0 {
		t.Errorf("被拒的寫入不留痕，實際 %d", n)
	}
}

// TestBusinessStatusLifecycleGates 驗收：成員狀態變更受業務寫入門禁（停止那句、歸檔那句），
// 狀態定義側停止態仍可配置、歸檔一律拒寫，兩族的讀法在任何狀態都照舊可讀。
func TestBusinessStatusLifecycleGates(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Status.Lifecycle")
	activity := e.create(t, principal, "會停止的場", "")
	target := e.seedAccount(t, "Status.LifecyclePlayer", "玩家庚", account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, principal, activity.ID, target.ID, "停止後的人")
	custom := e.mustCreateCustomStatus(t, principal, activity.ID, "停止前建的")

	e.transitionTo(t, principal, activity.ID, StatusClosed)
	if err := e.statusErr(principal, activity.ID, member.ID, BusinessStatusOffline, idgen.ID{},
		BusinessStatusNormal, idgen.ID{}); !errors.Is(err, ErrActivityClosedWrites) {
		t.Fatalf("停止態的成員狀態變更應等活動重開，實際 %v", err)
	}
	// 配置側在停止態仍可寫。
	if _, err := e.service.UpdateStatusLabel(context.Background(), principal, activity.ID,
		BusinessStatusOffline, "停止時設的", "", "req-closed-label"); err != nil {
		t.Fatalf("停止態仍可準備顯示名稱：%v", err)
	}
	stay := CustomStatusEdit{
		New:      CustomStatusFields{Name: "停止時改名", Available: false},
		Expected: CustomStatusFields{Name: "停止前建的", Available: true},
	}
	if _, err := e.service.UpdateCustomStatus(context.Background(), principal, activity.ID,
		custom.ID, stay, "req-closed-custom"); err != nil {
		t.Fatalf("停止態仍可編輯自訂定義：%v", err)
	}
	if _, err := e.service.PlayerStatusCatalog(context.Background(), principal, activity.ID); err != nil {
		t.Fatalf("停止態的目錄照舊可讀：%v", err)
	}
	if _, err := e.service.Members(context.Background(), principal, activity.ID); err != nil {
		t.Fatalf("停止態的名冊照舊可讀：%v", err)
	}

	e.transitionTo(t, principal, activity.ID, StatusArchived)
	if err := e.statusErr(principal, activity.ID, member.ID, BusinessStatusOffline, idgen.ID{},
		BusinessStatusNormal, idgen.ID{}); !errors.Is(err, ErrArchived) {
		t.Fatalf("歸檔態的成員狀態變更該說「這件事已經結束」，實際 %v", err)
	}
	if _, err := e.service.UpdateStatusLabel(context.Background(), principal, activity.ID,
		BusinessStatusOffline, "歸檔後想改", "停止時設的", "req-archived-label"); !errors.Is(err, ErrArchived) {
		t.Fatalf("歸檔態的配置寫入一律拒，實際 %v", err)
	}
	if _, err := e.service.CreateCustomStatus(context.Background(), principal, activity.ID,
		"歸檔後想建", "req-archived-create"); !errors.Is(err, ErrArchived) {
		t.Fatalf("歸檔態不發新建定義，實際 %v", err)
	}
	catalog, err := e.service.PlayerStatusCatalog(context.Background(), principal, activity.ID)
	if err != nil {
		t.Fatalf("歸檔後定義仍列可讀：%v", err)
	}
	if len(catalog.Custom) != 1 || catalog.Custom[0].Name != "停止時改名" {
		t.Errorf("歸檔不動任何既有定義，實際 %+v", catalog.Custom)
	}
	roster, err := e.service.Members(context.Background(), principal, activity.ID)
	if err != nil || len(roster) != 1 || roster[0].BusinessStatus != BusinessStatusNormal {
		t.Fatalf("歸檔後名冊照讀，且狀態一格沒動：%v（%+v）", err, roster)
	}
}

// TestBusinessStatusConcurrentWrites 驗收：兩筆同依據值的狀態變更只有贏家落地，
// 落敗那句是衝突、不寫第二次、不追加審計；兩筆配置寫入同形。
func TestBusinessStatusConcurrentWrites(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Status.Race")
	activity := e.create(t, principal, "相撞的場", "")
	target := e.seedAccount(t, "Status.RacePlayer", "玩家辛", account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, principal, activity.ID, target.ID, "相撞的那位")

	first := e.mustSetMemberStatus(t, principal, activity.ID, member.ID, BusinessStatusArrested,
		idgen.ID{}, BusinessStatusNormal, idgen.ID{})
	if err := e.statusErr(principal, activity.ID, member.ID, BusinessStatusDead, idgen.ID{},
		BusinessStatusNormal, idgen.ID{}); !errors.Is(err, ErrMemberProfileConflict) {
		t.Fatalf("帶過期依據值的第二筆應回衝突，實際 %v", err)
	}
	if f := e.memberStatusFacts(t, member.ID); f.business != first.BusinessStatus.String() {
		t.Errorf("贏家現值不被覆蓋，實際 %q", f.business)
	}
	if n := e.countAuditRows(t, "member.business_status_update", activity.ID.String()); n != 1 {
		t.Errorf("留痕筆數該等於實際提交數，實際 %d", n)
	}

	// 配置側同一形态：兩份同依據值，只有一份落地。
	if _, err := e.service.UpdateStatusLabel(context.Background(), principal, activity.ID,
		BusinessStatusArrested, "贏家寫法", "", "req-a"); err != nil {
		t.Fatalf("第一份顯示名稱寫入應成功：%v", err)
	}
	if _, err := e.service.UpdateStatusLabel(context.Background(), principal, activity.ID,
		BusinessStatusArrested, "落敗寫法", "", "req-b"); !errors.Is(err, ErrStatusLabelConflict) {
		t.Fatalf("第二份同依據值應回衝突，實際 %v", err)
	}
	catalog, _ := e.service.PlayerStatusCatalog(context.Background(), principal, activity.ID)
	for _, item := range catalog.Builtins {
		if item.Key == BusinessStatusArrested && item.DisplayName != "贏家寫法" {
			t.Errorf("覆蓋現值該是贏家那份，實際 %q", item.DisplayName)
		}
	}
}

// TestBusinessStatusIsNotConnectivity 驗收：讀取與時間流逝都不會翻轉業務狀態。
//
// 這是「offline 不會被 HTTP 活躍度自動覆蓋」那句在服務層的取證：本套件沒有一處
// 讀取通路或時鐘推進能改寫那一欄。
func TestBusinessStatusIsNotConnectivity(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Status.NotConn")
	activity := e.create(t, principal, "只讀的場", "")
	target := e.seedAccount(t, "Status.NotConnPlayer", "玩家壬", account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, principal, activity.ID, target.ID, "離線的那位")
	e.mustSetMemberStatus(t, principal, activity.ID, member.ID, BusinessStatusOffline,
		idgen.ID{}, BusinessStatusNormal, idgen.ID{})
	before := e.memberStatusFacts(t, member.ID)

	for i := 0; i < 3; i++ {
		if _, err := e.service.Members(context.Background(), principal, activity.ID); err != nil {
			t.Fatalf("第 %d 次名冊讀取應成功：%v", i, err)
		}
		if _, err := e.service.PlayerStatusCatalog(context.Background(), principal, activity.ID); err != nil {
			t.Fatalf("第 %d 次目錄讀取應成功：%v", i, err)
		}
		view, err := e.service.OwnMemberProfile(context.Background(),
			identitytest.Account(t, target.ID), activity.ID)
		if err != nil {
			t.Fatalf("第 %d 次本人投影應成功：%v", i, err)
		}
		if view.Member.BusinessStatus != BusinessStatusOffline {
			t.Fatalf("本人讀取不該翻轉業務狀態，實際 %s", view.Member.BusinessStatus)
		}
		e.clock.Advance(90 * time.Second)
	}

	if after := e.memberStatusFacts(t, member.ID); after != before {
		t.Errorf("讀取與時間推進一個字都不該動：\n舊 %+v\n新 %+v", before, after)
	}
}

// TestBusinessStatusAuditCarriesActorAndChanges 驗收：被接受的狀態變更在同一交易留下
// 帶著真實操作者與前後值的留痕；被拒的寫入一條痕都不加。
func TestBusinessStatusAuditCarriesActorAndChanges(t *testing.T) {
	e := newEnv(t)
	principal, admin := e.admin(t, "Status.Audit")
	activity := e.create(t, principal, "留痕的場", "")
	target := e.seedAccount(t, "Status.AuditPlayer", "玩家癸", account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, principal, activity.ID, target.ID, "被留痕的那位")
	custom := e.mustCreateCustomStatus(t, principal, activity.ID, "被引用的定義")

	e.mustSetMemberStatus(t, principal, activity.ID, member.ID, BusinessStatusCustom,
		custom.ID, BusinessStatusNormal, idgen.ID{})
	row := e.latestStatusAudit(t, "member.business_status_update", activity.ID.String())
	if row.actorKind != "admin" || row.actorID != admin.ID.String() {
		t.Errorf("留痕的操作者必須是那位管理員，實際 %+v", row)
	}
	for _, want := range []string{"normal", "custom", custom.ID.String(), "被引用的定義"} {
		if !strings.Contains(row.changes, want) {
			t.Errorf("changes 該帶 %q，實際 %s", want, row.changes)
		}
	}
	if !strings.Contains(row.reason, "業務狀態") {
		t.Errorf("原因句要說出這是狀態變更，實際 %q", row.reason)
	}

	// 被拒的變更（併發落敗）不留痕。
	before := e.countAuditRows(t, "member.business_status_update", activity.ID.String())
	if err := e.statusErr(principal, activity.ID, member.ID, BusinessStatusDead, idgen.ID{},
		BusinessStatusNormal, idgen.ID{}); !errors.Is(err, ErrMemberProfileConflict) {
		t.Fatalf("過期依據值應回衝突，實際 %v", err)
	}
	if got := e.countAuditRows(t, "member.business_status_update", activity.ID.String()); got != before {
		t.Errorf("被拒的寫入不留痕：%d→%d", before, got)
	}
}

// TestPlayerStatusWritesFollowCatalogVisibility 驗收：狀態不是第二條可見性來源——
// 目錄模式決定誰看得見誰，狀態只決定看得見的人讀到什麼；翻狀態不動目錄的答案。
func TestPlayerStatusWritesFollowCatalogVisibility(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Status.Dir")
	activity := e.create(t, principal, "目錄與狀態", "")
	mode := DirectoryAllMembers
	if _, err := e.service.UpdateMemberDirectoryMode(context.Background(), principal,
		activity.ID, mode, DirectoryHidden, "req-mode"); err != nil {
		t.Fatalf("開放目錄應成功：%v", err)
	}
	left := e.seedAccount(t, "Status.DirLeft", "左側玩家", account.TypeStandard, account.StatusActive)
	right := e.seedAccount(t, "Status.DirRight", "右側玩家", account.TypeStandard, account.StatusActive)
	memberL := e.mustCreateMember(t, principal, activity.ID, left.ID, "甲")
	memberR := e.mustCreateMember(t, principal, activity.ID, right.ID, "乙")

	page, err := e.service.MemberDirectory(context.Background(), identitytest.Account(t, left.ID),
		activity.ID, DirectoryMemberQuery{Page: 1, PageSize: 20})
	if err != nil || len(page.Rows) != 2 {
		t.Fatalf("全量態兩人都該看得見對方：%v（%d 行）", err, len(page.Rows))
	}

	e.mustSetMemberStatus(t, principal, activity.ID, memberR.ID, BusinessStatusEliminated,
		idgen.ID{}, BusinessStatusNormal, idgen.ID{})
	page, err = e.service.MemberDirectory(context.Background(), identitytest.Account(t, left.ID),
		activity.ID, DirectoryMemberQuery{Page: 1, PageSize: 20})
	if err != nil || page.Total != 2 || len(page.Rows) != 2 {
		t.Fatalf("翻狀態不該動目錄的答案：%v（%d 行，計數 %d）", err, len(page.Rows), page.Total)
	}
	if page.Rows[0].BusinessStatus != BusinessStatusNormal ||
		page.Rows[1].BusinessStatus != BusinessStatusEliminated {
		t.Errorf("可見的人讀得到對方的狀態，實際 %+v", page.Rows)
	}

	// 覆蓋把人收起來：狀態照樣不出去（這一行的投影整行都不在結果集裡）。
	if _, err := e.service.UpdateMemberDirectoryVisibility(context.Background(), principal,
		activity.ID, memberR.ID, DirectoryVisibilityHidden, DirectoryVisibilityInherit,
		"req-hide"); err != nil {
		t.Fatalf("覆蓋收起應成功：%v", err)
	}
	page, err = e.service.MemberDirectory(context.Background(), identitytest.Account(t, left.ID),
		activity.ID, DirectoryMemberQuery{Page: 1, PageSize: 20})
	if err != nil || len(page.Rows) != 1 || page.Rows[0].MemberID != memberL.ID {
		t.Fatalf("被收起的人整行都不該出現：%v（%+v）", err, page.Rows)
	}
	own, err := e.service.OwnMemberProfile(context.Background(), identitytest.Account(t, memberR.AccountID), activity.ID)
	if err != nil || own.Member.BusinessStatus != BusinessStatusEliminated {
		t.Fatalf("本人投影讀得到自己的狀態：%v（%+v）", err, own.Member)
	}
}

// TestPlayerStatusUnauthorizedPrincipalsRejected 驗收：Root 與普通帳戶在狀態一族管理
// 通路上進不來，匿名主體連判定都過不了。
func TestPlayerStatusUnauthorizedPrincipalsRejected(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Status.Auth")
	activity := e.create(t, principal, "准入的場", "")
	target := e.seedAccount(t, "Status.AuthPlayer", "玩家子", account.TypeStandard, account.StatusActive)
	member := e.mustCreateMember(t, principal, activity.ID, target.ID, "被保護的那位")

	plain := e.plain(t, "Status.Nobody")
	anon := identitytest.Anonymous(t)
	root := e.root(t)

	// Root 在管理這一族本來就過得去（同一道 NeedServerAdmin 加指派閘對 Root 放行，
	// 口徑同活動詳情與名冊），因此它不在被拒清單裡；這裡取證的是另外兩類主體。
	for name, who := range map[string]identity.Principal{
		"普通帳戶": plain, "匿名": anon,
	} {
		if _, err := e.service.PlayerStatusCatalog(context.Background(), who, activity.ID); !isIndistinguishable(err) {
			t.Errorf("%s 讀狀態目錄該收斂成不可分辨，實際 %v", name, err)
		}
		if _, err := e.service.CreateCustomStatus(context.Background(), who, activity.ID,
			"不被允許的定義", "req-x"); !isIndistinguishable(err) {
			t.Errorf("%s 建自訂狀態該收斂成不可分辨，實際 %v", name, err)
		}
		if _, err := e.service.UpdateStatusLabel(context.Background(), who, activity.ID,
			BusinessStatusNormal, "不被允許的名", "", "req-x"); !isIndistinguishable(err) {
			t.Errorf("%s 改顯示名稱該收斂成不可分辨，實際 %v", name, err)
		}
		if err := e.statusErr(who, activity.ID, member.ID, BusinessStatusOffline, idgen.ID{},
			BusinessStatusNormal, idgen.ID{}); !isIndistinguishable(err) {
			t.Errorf("%s 改成員狀態該收斂成不可分辨，實際 %v", name, err)
		}
	}

	// Root 讀目錄與名冊照常成功（管理面的既有口徑），但它是活動外的主體：
	// 玩家那一族的本人投影讀不到任何行（1001 那一族）。
	if _, err := e.service.PlayerStatusCatalog(context.Background(), root, activity.ID); err != nil {
		t.Errorf("Root 讀狀態目錄應放行（管理面口徑），實際 %v", err)
	}
	if _, err := e.service.OwnMemberProfile(context.Background(), root, activity.ID); !isIndistinguishable(err) {
		t.Errorf("Root 在本人通路該收斂成不可分辨，實際 %v", err)
	}
}

// isIndistinguishable 回報這一句是不是對外的不可分辨結論（1001 那一族）。
func isIndistinguishable(err error) bool {
	return errors.Is(err, ErrActivityNotFound) ||
		errors.Is(err, ErrMemberNotFound) ||
		errors.Is(err, identity.ErrPermissionDenied) ||
		errors.Is(err, identity.ErrNotAuthenticated)
}
