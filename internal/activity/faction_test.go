// faction_test.go 是陣營用例的服務層證據：建立與列表的領域規則（新建即可用、
// 未帶排序值排尾）、同活動名稱唯一與跨活動同名的互不相干、跨活動讀改的不可分辨、
// 停止／歸檔兩道業務寫入門禁各有各的句子、無權主體連一條通路都進不來、
// 併發編輯的落敗那一句、白名單編輯不碰身份與時刻，以及「審計寫不進去則整個建立回滾」。
//
// 停用那一步的證據在檔尾四組：停用只翻一欄、行仍列可讀且標識不變（歷史引用不失效）、
// 重复提交與落敗的那一句各有自己的形狀、可分配判定的四種結論各自成形，以及
// 「判定在交易內、停用寫入在同一條串行線上」——今天沒有成員表，所以這些斷言問的都是
// 阵营自身與那一条判定，沒有一處替成員歸屬編造形態。
//
// 刻意不收的東西：
//   - 沒有替身：授權、門禁、重名核實、CAS 與審計都走真路徑（真資料庫＋注入時鐘）；
//   - 不測協定層（欄位注入 1004、機器碼對映）：那是 internal/httpapi 的端點證據；
//   - 不測玩家在陣營間的分配：成員尚未落地，本套件也沒有一条通路能僞造這件事。
package activity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// factionDraft 湊一份最簡合法輸入：除名稱外全部走默認（未選圖標、未選色、未指定排序）。
func factionDraft(name string) FactionDraft {
	return FactionDraft{Name: name}
}

// mustCreateFaction 建立一個陣營，失敗即終止。
func (e *env) mustCreateFaction(t *testing.T, principal identity.Principal,
	activityID idgen.ID, draft FactionDraft) Faction {
	t.Helper()
	faction, err := e.service.CreateFaction(context.Background(), principal, activityID, draft, "req-faction")
	if err != nil {
		t.Fatalf("建立陣營 %q 應成功：%v", draft.Name, err)
	}
	return faction
}

// factionFacts 是一行陣營在資料庫裡的可觀察形態（白名單外欄位是否被碰過靠它做等值比較）。
type factionFacts struct {
	activityID  string
	name        string
	description string
	icon        string
	color       string
	sortOrder   int64
	available   int64
	createdAt   int64
	updatedAt   int64
}

func (e *env) factionFacts(t *testing.T, id idgen.ID) factionFacts {
	t.Helper()
	var f factionFacts
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT activity_id, name, description,
			icon, color, sort_order, available, created_at, updated_at
		FROM activity_factions WHERE id = ?`, id.String()).
		Scan(&f.activityID, &f.name, &f.description, &f.icon, &f.color,
			&f.sortOrder, &f.available, &f.createdAt, &f.updatedAt)
	if err != nil {
		t.Fatalf("讀取陣營 %s 的事實失敗：%v", id.String(), err)
	}
	return f
}

// TestFactionCreateAndList 驗收：新建的陣營一出生即可用、時刻取自注入時鐘、
// 可用性不從請求來；列表按「排序值、建立時刻、標識」穩定呈現，未指定排序值者排在最後。
func TestFactionCreateAndList(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Faction.List")
	activity := e.create(t, principal, "有陣營的場", "")

	// 空活動的列表是空的但不是錯誤：「還沒設陣營」本來就是可表達的事實。
	rows, err := e.service.Factions(context.Background(), principal, activity.ID)
	if err != nil || len(rows) != 0 {
		t.Fatalf("空列表應成功且為空：%v（%d 行）", err, len(rows))
	}

	first := e.mustCreateFaction(t, principal, activity.ID, factionDraft("黎明軍"))
	if !first.Available {
		t.Error("新建的陣營一律可用（領域規則，請求沒有那一格）")
	}
	if first.ID.IsNil() || first.ActivityID != activity.ID {
		t.Errorf("標識與歸屬必須由服務端決定，實際 %s／%s", first.ID, first.ActivityID)
	}
	if first.CreatedAt != testBase || first.UpdatedAt != testBase {
		t.Errorf("時刻必須取自注入時鐘，實際 %v／%v", first.CreatedAt, first.UpdatedAt)
	}
	if first.SortOrder != 0 {
		t.Errorf("空表的第一個排尾值應是 0，實際 %d", first.SortOrder)
	}

	sortValue := int64(5)
	second := e.mustCreateFaction(t, principal, activity.ID, FactionDraft{
		Name: "長夜軍", Icon: "moon", Color: "#1A2B3C", SortOrder: &sortValue,
	})
	if second.Color != "#1a2b3c" {
		t.Errorf("顏色必須正規化成小寫單一寫法，實際 %q", second.Color)
	}
	third := e.mustCreateFaction(t, principal, activity.ID, factionDraft("尾軍"))
	if third.SortOrder != 6 {
		t.Errorf("未指定排序值應排到當前最大值之後（5+1），實際 %d", third.SortOrder)
	}

	rows, err = e.service.Factions(context.Background(), principal, activity.ID)
	if err != nil {
		t.Fatalf("讀列表應成功：%v", err)
	}
	if len(rows) != 3 || rows[0].ID != first.ID || rows[1].ID != second.ID || rows[2].ID != third.ID {
		t.Fatalf("列表應按排序值穩定呈現三行，實際 %+v", rows)
	}

	// 審計落在活動域、帶著歸屬活動的標識與固定的原因句子。
	if got := e.countAuditRows(t, "faction.create", activity.ID.String()); got != 3 {
		t.Errorf("三次成功建立該留三筆 faction.create，實際 %d 筆", got)
	}
	if strings.Contains(e.logs.String(), "argon2id") || strings.Contains(e.logs.String(), "fakehash") {
		t.Errorf("執行日誌不得複述任何憑據材料：%s", e.logs.String())
	}
}

// TestFactionNameRules 驗收：同活動內重名即拒且零落地，撞名編輯同樣被擋；
// 跨活動同名互不相干；名稱沒改的編輯不會撞上自己。
func TestFactionNameRules(t *testing.T) {
	e := newEnv(t)
	alpha, _ := e.admin(t, "Faction.NameAlpha")
	beta, _ := e.admin(t, "Faction.NameBeta")
	actA := e.create(t, alpha, "甲活動", "")
	actB := e.create(t, beta, "乙活動", "")

	dawn := e.mustCreateFaction(t, alpha, actA.ID, factionDraft("黎明軍"))
	if _, err := e.service.CreateFaction(context.Background(), alpha, actA.ID,
		factionDraft("黎明軍"), "req-dup"); !errors.Is(err, ErrFactionNameTaken) {
		t.Errorf("同活動重名應被拒且可判別，實際 %v", err)
	}
	if got := e.countRows(t, "activity_factions"); got != 1 {
		t.Fatalf("被拒的重名建立不該落庫，實際 %d 行", got)
	}

	// 跨活動同名是合法的：唯一約束按活動分書。
	if _, err := e.service.CreateFaction(context.Background(), beta, actB.ID,
		factionDraft("黎明軍"), "req-cross"); err != nil {
		t.Errorf("另一場活動設同名陣營應成功，實際 %v", err)
	}

	// 把甲活動的陣營改名成甲活動裡的另一個名字：撞名即拒，現值一個字不動。
	other := e.mustCreateFaction(t, alpha, actA.ID, factionDraft("黃昏軍"))
	if _, err := e.service.UpdateFaction(context.Background(), alpha, actA.ID, other.ID,
		factionEdit(other, "黎明軍"), "req-rename-taken"); !errors.Is(err, ErrFactionNameTaken) {
		t.Errorf("改名撞上同活動內他人應被拒，實際 %v", err)
	}
	if f := e.factionFacts(t, other.ID); f.name != "黃昏軍" {
		t.Errorf("被拒的改名動了現值：實際 %q", f.name)
	}

	// 名稱沒改的編輯（只改描述）不該撞上自己的那一行。
	edited := factionEdit(other, "黃昏軍")
	edited.Description = "改了的描述"
	if _, err := e.service.UpdateFaction(context.Background(), alpha, actA.ID, other.ID,
		edited, "req-self-name"); err != nil {
		t.Errorf("同名自檢不得撞上自己，實際 %v", err)
	}
	if dawn.ID == other.ID {
		t.Error("兩次建立必須各有一個標識")
	}
}

// factionEdit 以一行陣營的現值為依據值，湊出一份「只打算改指定欄位」的編輯輸入。
func factionEdit(current Faction, name string) FactionEdit {
	return FactionEdit{
		Name:         name,
		Description:  current.Description,
		Icon:         current.Icon,
		Color:        current.Color,
		SortOrder:    current.SortOrder,
		Available:    current.Available,
		ExpectedName: current.Name, ExpectedDescription: current.Description,
		ExpectedIcon: current.Icon, ExpectedColor: current.Color,
		ExpectedSortOrder: current.SortOrder, ExpectedAvailable: current.Available,
	}
}

// TestFactionDomainValidation 驗收：顏色、圖標、排序與名稱每一種湊得出來但無法解釋的
// 寫法都在進庫之前被點名，且不留下任何行。
func TestFactionDomainValidation(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Faction.Domain")
	activity := e.create(t, principal, "取值取證的場", "")

	badSort := int64(100000)
	negativeSort := int64(-1)
	cases := []struct {
		what  string
		draft FactionDraft
		want  error
	}{
		{"空名稱", factionDraft(""), ErrInvalidName},
		{"超長名稱", factionDraft(strings.Repeat("長", maxNameRunes+1)), ErrInvalidName},
		{"顏色少一位", FactionDraft{Name: "甲", Color: "#12345"}, ErrInvalidColor},
		{"顏色不是井開頭", FactionDraft{Name: "甲", Color: "112233"}, ErrInvalidColor},
		{"顏色含非十六進位", FactionDraft{Name: "甲", Color: "#12345g"}, ErrInvalidColor},
		{"圖標不在封閉集合", FactionDraft{Name: "甲", Icon: "dragon"}, ErrInvalidIcon},
		{"排序值越上界", FactionDraft{Name: "甲", SortOrder: &badSort}, ErrInvalidSortOrder},
		{"排序值為負", FactionDraft{Name: "甲", SortOrder: &negativeSort}, ErrInvalidSortOrder},
	}
	for _, tc := range cases {
		t.Run(tc.what, func(t *testing.T) {
			if _, err := e.service.CreateFaction(context.Background(), principal,
				activity.ID, tc.draft, "req-domain"); !errors.Is(err, tc.want) {
				t.Fatalf("應回報 %v，實際 %v", tc.want, err)
			}
		})
	}
	// 合法形態各走一遍：未選圖標、未選色、零與上界排序值都是批淮集合內的寫法。
	for _, icon := range factionIconKeys {
		if _, err := validateFactionIcon("  " + icon + " "); err != nil {
			t.Errorf("封閉集合裡的鍵 %q 都該通過（含首尾空白剔除）：%v", icon, err)
		}
	}
	if _, err := e.mustCreateOK(t, principal, activity.ID); err != nil {
		t.Errorf("空圖標＋空顏色＋排序貼上界應合法：%v", err)
	}
	if got := e.countRows(t, "activity_factions"); got != 1 {
		t.Errorf("八條非法與一條合法，庫裡只該留下一行，實際 %d", got)
	}
}

// mustCreateOK 建立一份「全默認但排序貼上界」的陣營並回報錯誤（供上面的合法性收尾）。
func (e *env) mustCreateOK(t *testing.T, principal identity.Principal,
	activityID idgen.ID) (Faction, error) {
	t.Helper()
	top := maxFactionSortOrder
	return e.service.CreateFaction(context.Background(), principal, activityID,
		FactionDraft{Name: "合法默認", SortOrder: &top}, "req-ok")
}

// TestFactionCrossActivityIsIndistinguishable 驗收：乙在「自己看得見的活动」名下
// 改甲活動的陣營，換到的話與改一個從未存在的標識逐字同形；乙根本讀不到甲的活動列表。
func TestFactionCrossActivityIsIndistinguishable(t *testing.T) {
	e := newEnv(t)
	alpha, _ := e.admin(t, "Faction.XAlpha")
	beta, _ := e.admin(t, "Faction.XBeta")
	actA := e.create(t, alpha, "甲的陣營場", "")
	actB := e.create(t, beta, "乙的陣營場", "")
	faction := e.mustCreateFaction(t, alpha, actA.ID, factionDraft("甲的陣營"))
	ghost := identitytest.NewID(t)

	// 拿甲的陣營標識掛在乙的活動下編輯：查無此陣營（與幽靈標識同形）。
	bad := factionEdit(faction, "被乙改的名")
	_, errOnAlpha := e.service.UpdateFaction(context.Background(), beta, actB.ID, faction.ID,
		bad, "req-cross")
	_, errOnGhost := e.service.UpdateFaction(context.Background(), beta, actB.ID, ghost,
		bad, "req-ghost")
	if !errors.Is(errOnAlpha, ErrFactionNotFound) || !errors.Is(errOnGhost, ErrFactionNotFound) {
		t.Fatalf("兩種都應收斂成查無，實際 %v／%v", errOnAlpha, errOnGhost)
	}
	if errOnAlpha.Error() != errOnGhost.Error() {
		t.Errorf("兩句必須逐字同形，否則就是一枚探測信號：%q vs %q", errOnAlpha, errOnGhost)
	}
	if f := e.factionFacts(t, faction.ID); f.name != "甲的陣營" || f.activityID != actA.ID.String() {
		t.Errorf("被拒的跨活動編輯動了現值或歸屬：%+v", f)
	}

	// 乙直接讀甲活動的列表：收斂成活動不可見那一句（他連活動都管不著）。
	if _, err := e.service.Factions(context.Background(), beta, actA.ID); !errors.Is(err, ErrActivityNotFound) {
		t.Errorf("乙讀甲活動的陣營列表應不可分辨，實際 %v", err)
	}
	// 甲看得見自己的那一行；Root 不受指派限制也讀得到。
	rows, err := e.service.Factions(context.Background(), alpha, actA.ID)
	if err != nil || len(rows) != 1 || rows[0].ID != faction.ID {
		t.Errorf("甲應讀到自己的那一行：%v（%d 行）", err, len(rows))
	}
	if _, err := e.service.Factions(context.Background(), e.root(t), actA.ID); err != nil {
		t.Errorf("Root 應讀得到任何活動的列表：%v", err)
	}
}

// TestFactionWritesRespectLifecycleGate 驗收：草稿可寫（準備期本就該能設陣營）、
// 停止拿到「重開就好」那一句、歸檔拿到「這件事結束了」那一句，而兩態都照樣能讀。
func TestFactionWritesRespectLifecycleGate(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Faction.Gate")
	activity := e.create(t, principal, "要過門禁的場", "")
	faction := e.mustCreateFaction(t, principal, activity.ID, factionDraft("草稿期就設的陣營"))

	// 開放→可寫；停止→業務寫入拒（ErrActivityClosedWrites，可逆那一句）；列表照讀。
	if _, err := e.service.Transition(context.Background(), principal, activity.ID,
		StatusActive, "req-open"); err != nil {
		t.Fatalf("開放活動應成功：%v", err)
	}
	e.mustCreateFaction(t, principal, activity.ID, factionDraft("開放期設的"))
	if _, err := e.service.Transition(context.Background(), principal, activity.ID,
		StatusClosed, "req-close"); err != nil {
		t.Fatalf("停止活動應成功：%v", err)
	}
	if _, err := e.service.CreateFaction(context.Background(), principal, activity.ID,
		factionDraft("停止期想建的"), "req-closed-create"); !errors.Is(err, ErrActivityClosedWrites) {
		t.Errorf("停止態的建立應拿到門禁那句，實際 %v", err)
	}
	if _, err := e.service.UpdateFaction(context.Background(), principal, activity.ID,
		faction.ID, factionEdit(faction, "停止期想改的"), "req-closed-update"); !errors.Is(err, ErrActivityClosedWrites) {
		t.Errorf("停止態的編輯應拿到門禁那句，實際 %v", err)
	}
	if rows, err := e.service.Factions(context.Background(), principal, activity.ID); err != nil || len(rows) != 2 {
		t.Errorf("停止態仍列、可讀：列表應讀到兩行，實際 %v（%d 行）", err, len(rows))
	}

	// 歸檔是終態：建與改都拿到 2029 那族句子（ErrArchived），而不是門禁的另一句。
	if _, err := e.service.Transition(context.Background(), principal, activity.ID,
		StatusArchived, "req-archive"); err != nil {
		t.Fatalf("歸檔活動應成功：%v", err)
	}
	if _, err := e.service.CreateFaction(context.Background(), principal, activity.ID,
		factionDraft("歸檔後想建的"), "req-archived-create"); !errors.Is(err, ErrArchived) {
		t.Errorf("歸檔態的建立應拿到終態那句，實際 %v", err)
	}
	if _, err := e.service.UpdateFaction(context.Background(), principal, activity.ID,
		faction.ID, factionEdit(faction, "歸檔後想改的"), "req-archived-update"); !errors.Is(err, ErrArchived) {
		t.Errorf("歸檔態的編輯應拿到終態那句，實際 %v", err)
	}
	if f := e.factionFacts(t, faction.ID); f.name != "草稿期就設的陣營" {
		t.Errorf("被門禁擋下的寫入動了現值：實際 %q", f.name)
	}
	if rows, err := e.service.Factions(context.Background(), principal, activity.ID); err != nil || len(rows) != 2 {
		t.Errorf("歸檔態仍列、可讀：實際 %v（%d 行）", err, len(rows))
	}
}

// TestFactionUnauthorizedPrincipalsRejected 驗收：普通帳戶、匿名與系統主體
// 在三條陣營通路上各自撞在自己那句話上，庫裡一行都不多。
func TestFactionUnauthorizedPrincipalsRejected(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.admin(t, "Faction.AuthAdmin")
	activity := e.create(t, admin, "權限取證的場", "")
	faction := e.mustCreateFaction(t, admin, activity.ID, factionDraft("取證的陣營"))

	plain := e.plain(t, "Faction.Plain")
	for _, tc := range []struct {
		what string
		run  func() error
	}{
		{"普通帳戶建立", func() error {
			_, err := e.service.CreateFaction(context.Background(), plain, activity.ID,
				factionDraft("平民建的"), "req-p1")
			return err
		}},
		{"普通帳戶列表", func() error {
			_, err := e.service.Factions(context.Background(), plain, activity.ID)
			return err
		}},
		{"普通帳戶編輯", func() error {
			_, err := e.service.UpdateFaction(context.Background(), plain, activity.ID,
				faction.ID, factionEdit(faction, "平民改的"), "req-p2")
			return err
		}},
		{"匿名建立", func() error {
			_, err := e.service.CreateFaction(context.Background(), identitytest.Anonymous(t),
				activity.ID, factionDraft("匿名建的"), "req-a1")
			return err
		}},
		{"系統主體列表", func() error {
			_, err := e.service.Factions(context.Background(),
				identitytest.System(t, identity.OriginBackground), activity.ID)
			return err
		}},
	} {
		err := tc.run()
		want := identity.ErrPermissionDenied
		if tc.what == "匿名建立" {
			want = identity.ErrNotAuthenticated
		}
		if !errors.Is(err, want) {
			t.Errorf("%s 應回報 %v，實際 %v", tc.what, want, err)
		}
	}
	if got := e.countRows(t, "activity_factions"); got != 1 {
		t.Errorf("被拒的通路不該多出行，實際 %d 行", got)
	}
	if got := e.countAuditRows(t, "faction.create", activity.ID.String()); got != 1 {
		t.Errorf("被拒的請求不該記審計（只有取證那次成功），實際 %d 筆", got)
	}
}

// TestFactionConcurrentEditAndWhitelist 驗收：同一份畫面後的第二次提交落敗並回報可判別
// 衝突；落敗者一個字都不覆蓋、一筆審計都不留；贏家只碰白名單六欄，身份與時刻原封不動。
func TestFactionConcurrentEditAndWhitelist(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Faction.Cas")
	activity := e.create(t, principal, "併發取證的場", "")
	faction := e.mustCreateFaction(t, principal, activity.ID,
		FactionDraft{Name: "原名", Icon: "star", Color: "#ff0000"})
	before := e.factionFacts(t, faction.ID)
	// 注入時鐘往前一格：編輯與建立必須能分辨先後（updated_at 的斷言才有意義）。
	e.clock.Advance(time.Minute)

	first := factionEdit(faction, "贏家的名字")
	first.Description = "贏家的描述"
	updated, err := e.service.UpdateFaction(context.Background(), principal, activity.ID,
		faction.ID, first, "req-winner")
	if err != nil {
		t.Fatalf("第一次編輯應成功：%v", err)
	}
	if !updated.Available {
		t.Error("贏家沒動可用性，回讀的現值必須仍是可用")
	}

	second := factionEdit(faction, "輸家的名字")
	if _, err := e.service.UpdateFaction(context.Background(), principal, activity.ID,
		faction.ID, second, "req-loser"); !errors.Is(err, ErrFactionProfileConflict) {
		t.Errorf("落敗的編輯應回報現值衝突，實際 %v", err)
	}
	after := e.factionFacts(t, faction.ID)
	if after.name != "贏家的名字" || after.description != "贏家的描述" {
		t.Errorf("落敗的編輯覆蓋了現值：%+v", after)
	}
	if got := e.countAuditRows(t, "faction.update", activity.ID.String()); got != 1 {
		t.Errorf("落敗的編輯不該留審計，實際 %d 筆", got)
	}

	// 白名單是真的白名單：歸屬、標識與建立時刻不在 UPDATE 裡。
	if after.activityID != before.activityID || after.createdAt != before.createdAt {
		t.Errorf("編輯動了歸屬或建立時刻：舊 %+v 新 %+v", before, after)
	}
	if after.updatedAt <= after.createdAt {
		t.Errorf("成功編輯必須推進 updated_at，實際 %d／%d", after.updatedAt, after.createdAt)
	}

	// 可用性開關走同一条編輯：停一記一筆，前後值在審計的 changes 裡。
	toggle := factionEdit(updated, updated.Name)
	toggle.Available = false
	toggle.ExpectedAvailable = true
	if _, err := e.service.UpdateFaction(context.Background(), principal, activity.ID,
		faction.ID, toggle, "req-toggle"); err != nil {
		t.Fatalf("停用編輯應成功：%v", err)
	}
	if f := e.factionFacts(t, faction.ID); f.available != 0 {
		t.Error("停用沒落庫")
	}
	var changes string
	if err := e.db.SQL().QueryRowContext(context.Background(), `SELECT changes_json FROM activity_audit
		WHERE action = 'faction.update' ORDER BY created_at DESC, id DESC LIMIT 1`).
		Scan(&changes); err != nil {
		t.Fatalf("讀最新一筆陣營編輯審計失敗：%v", err)
	}
	if !strings.Contains(changes, "available") {
		t.Errorf("審計的 changes 要罩住可用性那一欄的前後值，實際 %q", changes)
	}
}

// TestFactionAuditFailureRollsBackWholeAction 驗收：審計寫不進去時陣營那一行也不留、
// 編輯現值也不動（與活動那條注入探针同一手法、同一結論）。
func TestFactionAuditFailureRollsBackWholeAction(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Faction.Rollback")
	activity := e.create(t, principal, "回滾取證的場", "")
	faction := e.mustCreateFaction(t, principal, activity.ID, factionDraft("將被回滾前的陣營"))

	ctx := context.Background()
	block := `CREATE TRIGGER test_audit_block BEFORE INSERT ON activity_audit
		BEGIN SELECT RAISE(ABORT, '測試注入：審計寫入失敗'); END`
	drop := `DROP TRIGGER test_audit_block`
	if _, err := e.db.SQL().ExecContext(ctx, block); err != nil {
		t.Fatalf("佈下注入觸發器失敗：%v", err)
	}

	if _, err := e.service.CreateFaction(ctx, principal, activity.ID,
		factionDraft("該回滾的陣營"), "req-blocked"); err == nil ||
		!strings.Contains(err.Error(), "測試注入") {
		t.Errorf("審計寫不進時建立必須失敗並帶著原因，實際 %v", err)
	}
	if got := e.countRows(t, "activity_factions"); got != 1 {
		t.Errorf("失敗的建立必須整體回滾，實際留下 %d 行", got)
	}

	blocked := factionEdit(faction, "該回滾的改名")
	if _, err := e.service.UpdateFaction(ctx, principal, activity.ID, faction.ID,
		blocked, "req-blocked-update"); err == nil {
		t.Error("審計寫不進時編輯必須整體失敗")
	}
	if f := e.factionFacts(t, faction.ID); f.name != "將被回滾前的陣營" {
		t.Errorf("回滾的編輯動了現值：實際 %q", f.name)
	}

	if _, err := e.db.SQL().ExecContext(ctx, drop); err != nil {
		t.Fatalf("拆除注入觸發器失敗：%v", err)
	}
	created := e.mustCreateFaction(t, principal, activity.ID, factionDraft("重來一次的陣營"))
	if got := e.countAuditRows(t, "faction.create", activity.ID.String()); got != 2 {
		t.Errorf("拆掉注入後同一路徑應成功並留下第二筆，實際 %d 筆", got)
	}
	if !created.Available {
		t.Error("重試建立的陣營仍受同一條領域規則：一出生即可用")
	}
}

// setAvailability 以一行陣營的服務端現值為依據值，送一次「只翻可用性」的編輯：
// 停用與恢復走的就是陣營管理那一步批准的那條六欄白名單通路，沒有第二條。
func (e *env) setAvailability(ctx context.Context, principal identity.Principal,
	faction Faction, want bool) (Faction, error) {
	edit := factionEdit(faction, faction.Name)
	edit.Available = want
	edit.ExpectedAvailable = faction.Available
	return e.service.UpdateFaction(ctx, principal, faction.ActivityID, faction.ID,
		edit, "req-availability")
}

// guardInWriteTx 在一個寫入交易內呼叫「這個陣營此刻收不收新成員」的判定，
// 形状與日後那條分配通路一致（同交易內現讀，判定與寫入共用一個快照）。
func (e *env) guardInWriteTx(t *testing.T, activityID, factionID idgen.ID) (Faction, error) {
	t.Helper()
	var got Faction
	err := e.db.InTx(context.Background(), func(tctx context.Context, tx *database.Tx) error {
		var inner error
		got, inner = e.service.EnsureFactionAcceptsNewMembers(tctx, tx, activityID, factionID)
		return inner
	})
	return got, err
}

// factionAuditRow 是某一動作最新一筆活動域審計裡可觀察的留痕（操作者、原因與 changes）。
type factionAuditRow struct {
	actorKind string
	actorID   string
	reason    string
	changes   string
}

// latestFactionAudit 讀回某一動作最新一筆留痕。時刻取自注入時鐘，同值時以標識破平
// （與列表讀法同一條規則），因此「最新一筆」在本檔裡是可定義的。
func (e *env) latestFactionAudit(t *testing.T, action, activityID string) factionAuditRow {
	t.Helper()
	var row factionAuditRow
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

// TestFactionDisableKeepsRowAndReferences 驗收：停用只翻可用性那一欄，行仍列、可讀，
// 標識與歸屬與建立時刻一個字都沒動（引用因此不會因停用而失效）；停用後的改名照樣
// 走得通且標識不變；留痕帶著真實操作者、服務端換得的原因句與 available 的前後值；
// 重新啟用只是把那一欄翻回來，既不復原也不改寫停用期間保留下来的任何東西。
func TestFactionDisableKeepsRowAndReferences(t *testing.T) {
	e := newEnv(t)
	principal, admin := e.admin(t, "Faction.Disable")
	activity := e.create(t, principal, "停用取證的場", "")
	sortValue := int64(7)
	faction := e.mustCreateFaction(t, principal, activity.ID, FactionDraft{
		Name: "黎明軍", Description: "第一組", Icon: "star", Color: "#FF00AA", SortOrder: &sortValue,
	})
	before := e.factionFacts(t, faction.ID)
	e.clock.Advance(time.Minute)

	disabled, err := e.setAvailability(context.Background(), principal, faction, false)
	if err != nil {
		t.Fatalf("停用應成功：%v", err)
	}
	if disabled.Available || disabled.AcceptsNewMembers {
		t.Errorf("停用後兩者都該是假：available=%v accepts=%v", disabled.Available, disabled.AcceptsNewMembers)
	}

	after := e.factionFacts(t, faction.ID)
	if after.available != 0 {
		t.Error("停用沒落庫")
	}
	// 除那一欄與 updated_at 之外全等：停用不清空、不搬走、不動歷史。
	if after.activityID != before.activityID || after.createdAt != before.createdAt ||
		after.name != before.name || after.description != before.description ||
		after.icon != before.icon || after.color != before.color || after.sortOrder != before.sortOrder {
		t.Errorf("停用動了可用性以外的欄位：舊 %+v 新 %+v", before, after)
	}
	if after.updatedAt <= after.createdAt {
		t.Errorf("成功寫入必須推進 updated_at，實際 %d／%d", after.updatedAt, after.createdAt)
	}

	// 仍列、可讀：標識仍是同一個，界面與任何未來引用都還認得它。
	rows, err := e.service.Factions(context.Background(), principal, activity.ID)
	if err != nil || len(rows) != 1 || rows[0].ID != faction.ID || rows[0].Available {
		t.Fatalf("停用後列表仍要列出行，實際 %v（%+v）", err, rows)
	}

	// 留痕三件：真實操作者、服務端的原因句、available 的前後值。
	auditRow := e.latestFactionAudit(t, "faction.update", activity.ID.String())
	if auditRow.actorID != admin.ID.String() {
		t.Errorf("停用的留痕必須落在實際操作者名下，實際 %s／%s", auditRow.actorKind, auditRow.actorID)
	}
	if !strings.Contains(auditRow.reason, "停用活動陣營") ||
		!strings.Contains(auditRow.reason, "不再接收新分配") {
		t.Errorf("原因句要講清停用那兩句後果，實際 %q", auditRow.reason)
	}
	if !strings.Contains(auditRow.changes, "available") ||
		!strings.Contains(auditRow.changes, "true") || !strings.Contains(auditRow.changes, "false") {
		t.Errorf("changes 要帶 available 的前後值，實際 %q", auditRow.changes)
	}

	// 停用中的陣營收不到新成員：判定這句話，而不是「找不到」。
	if _, err := e.guardInWriteTx(t, activity.ID, faction.ID); !errors.Is(err, ErrFactionNotAcceptingMembers) {
		t.Errorf("停用後的可分配判定應回報不再接收新成員，實際 %v", err)
	}

	// 改名照樣走得通，標識不變：引用錨在 id 上，不在名稱上。
	renamed, err := e.service.UpdateFaction(context.Background(), principal, activity.ID, faction.ID,
		factionEdit(rows[0], "黎明軍（改名）"), "req-rename")
	if err != nil {
		t.Fatalf("停用中的陣營改名應成功：%v", err)
	}
	if renamed.ID != faction.ID {
		t.Errorf("改名動了標識（引用會失效）：舊 %s 新 %s", faction.ID, renamed.ID)
	}
	if renamed.Available || renamed.AcceptsNewMembers {
		t.Error("只改名的編輯不該順手把可用性翻回來")
	}
	renameRow := e.latestFactionAudit(t, "faction.update", activity.ID.String())
	if strings.Contains(renameRow.reason, "停用") {
		t.Errorf("沒有翻轉可用性的編輯不該念成停用句，實際 %q", renameRow.reason)
	}

	// 恢復啟用：那一欄翻回來，其他一切（含停用期間留下的改名）原樣還在。
	e.clock.Advance(time.Minute)
	restored, err := e.setAvailability(context.Background(), principal, renamed, true)
	if err != nil {
		t.Fatalf("重新啟用應成功：%v", err)
	}
	if !restored.Available || !restored.AcceptsNewMembers {
		t.Errorf("恢復後兩者都該是真：available=%v accepts=%v", restored.Available, restored.AcceptsNewMembers)
	}
	restoredFacts := e.factionFacts(t, faction.ID)
	if restoredFacts.name != "黎明軍（改名）" || restoredFacts.sortOrder != before.sortOrder ||
		restoredFacts.createdAt != before.createdAt || restoredFacts.activityID != before.activityID {
		t.Errorf("恢復啟用改寫了既有事實：%+v", restoredFacts)
	}
	restoreRow := e.latestFactionAudit(t, "faction.update", activity.ID.String())
	if !strings.Contains(restoreRow.reason, "重新啟用活動陣營") {
		t.Errorf("恢復那次的留痕要講恢復句，實際 %q", restoreRow.reason)
	}
	if _, err := e.guardInWriteTx(t, activity.ID, faction.ID); err != nil {
		t.Errorf("恢復後可分配判定應放行：%v", err)
	}
	if got := e.countAuditRows(t, "faction.update", activity.ID.String()); got != 3 {
		t.Errorf("停用、改名、恢復各一筆，實際 %d 筆", got)
	}
}

// TestFactionRepeatAndStaleDisableRequests 驗收：重複停用走的是冪等的整份編輯——
// 帶著新讀到的依據值再存一次「仍然停用」會成功但不翻轉任何东西，留痕因此念成編輯句
// 而不是停用句（界面不得把這一次念成「已停用這個陣營」）；而拿舊畫面（當時仍可用）
// 送來的第二次提交落敗在現值衝突上，一個字都不覆蓋、一筆審計都不留。
func TestFactionRepeatAndStaleDisableRequests(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Faction.Repeat")
	activity := e.create(t, principal, "重複請求取證的場", "")
	faction := e.mustCreateFaction(t, principal, activity.ID, factionDraft("會被重複停用的陣營"))
	stale := faction // 兩個人對著同一份「仍可用」的畫面

	disabled, err := e.setAvailability(context.Background(), principal, faction, false)
	if err != nil {
		t.Fatalf("第一次停用應成功：%v", err)
	}

	// 同一個人再存一次「仍然停用」：冪等成功，值一個字不動，留痕是編輯句。
	e.clock.Advance(time.Minute)
	again, err := e.setAvailability(context.Background(), principal, disabled, false)
	if err != nil {
		t.Fatalf("重複停用作為整份編輯應冪等成功：%v", err)
	}
	if again.Available || again.AcceptsNewMembers {
		t.Error("重複提交後可用性仍是停用")
	}
	repeatRow := e.latestFactionAudit(t, "faction.update", activity.ID.String())
	if strings.Contains(repeatRow.reason, "停用活動陣營") ||
		strings.Contains(repeatRow.reason, "重新啟用") {
		t.Errorf("沒有翻轉的重複提交不該念成停用或恢復句，實際 %q", repeatRow.reason)
	}
	if got := e.countAuditRows(t, "faction.update", activity.ID.String()); got != 2 {
		t.Errorf("兩次如實的重存各留一筆，實際 %d 筆", got)
	}

	// 拿舊畫面（依據值仍寫著可用）的那一次：現值已不是他所見，整個編輯不落。
	if _, err := e.setAvailability(context.Background(), principal, stale, false); !errors.Is(err, ErrFactionProfileConflict) {
		t.Errorf("過期依據值的重複停用應回報現值衝突，實際 %v", err)
	}
	if got := e.countAuditRows(t, "faction.update", activity.ID.String()); got != 2 {
		t.Errorf("落敗的重複請求不該留審計，實際 %d 筆", got)
	}
	if f := e.factionFacts(t, faction.ID); f.available != 0 {
		t.Error("落敗的重複請求動了現值")
	}
}

// TestFactionAssignmentGuardConclusions 驗收：可分配判定的四種結論各自成形——
// 可用且活動可寫放行；停用回報不再接收新成員；活動停止與歸檔各自拿到自己那一句
// （而且停止態的列表派生值連可用行也照實說「此刻收不到新成員」）；
// 跨活動與幽靈標識收斂成同一句不可分辨。誤用（交易外或唯讀交易）不降級成放行。
func TestFactionAssignmentGuardConclusions(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Faction.Guard")
	actA := e.create(t, principal, "判定甲", "")
	actB := e.create(t, principal, "判定乙", "")
	faction := e.mustCreateFaction(t, principal, actA.ID, factionDraft("判定用的陣營"))
	ghost := identitytest.NewID(t)

	if got, err := e.guardInWriteTx(t, actA.ID, faction.ID); err != nil || !got.AcceptsNewMembers {
		t.Fatalf("草稿活動裡的可用陣營該放行，實際 %v（%+v）", err, got)
	}

	// 停用之後：同一個標識還在、仍歸這個活動管，但收不到新成員。
	disabled, err := e.setAvailability(context.Background(), principal, faction, false)
	if err != nil {
		t.Fatalf("停用應成功：%v", err)
	}
	if _, err := e.guardInWriteTx(t, actA.ID, faction.ID); !errors.Is(err, ErrFactionNotAcceptingMembers) {
		t.Errorf("停用的判定應拿到不再接收新成員那句，實際 %v", err)
	}

	// 跨活動與幽靈同形：判定不能變成「那個標識確實是甲活動的陣營」探測器。
	_, errOnOther := e.guardInWriteTx(t, actB.ID, faction.ID)
	_, errOnGhost := e.guardInWriteTx(t, actB.ID, ghost)
	if !errors.Is(errOnOther, ErrFactionNotFound) || !errors.Is(errOnGhost, ErrFactionNotFound) {
		t.Fatalf("兩種都該收斂成查無，實際 %v／%v", errOnOther, errOnGhost)
	}
	if errOnOther.Error() != errOnGhost.Error() {
		t.Errorf("兩句必須逐字同形：%q vs %q", errOnOther, errOnGhost)
	}

	// 活動停止：連重新啟用的陣營也收不到新成員（門禁那一句先答，處置是「等活動重開」）。
	reenabled, err := e.setAvailability(context.Background(), principal, disabled, true)
	if err != nil {
		t.Fatalf("重新啟用應成功：%v", err)
	}
	if _, err := e.service.Transition(context.Background(), principal, actA.ID,
		StatusActive, "req-open"); err != nil {
		t.Fatalf("開放活動應成功：%v", err)
	}
	if _, err := e.service.Transition(context.Background(), principal, actA.ID,
		StatusClosed, "req-close"); err != nil {
		t.Fatalf("停止活動應成功：%v", err)
	}
	if _, err := e.guardInWriteTx(t, actA.ID, reenabled.ID); !errors.Is(err, ErrActivityClosedWrites) {
		t.Errorf("停止態的判定應拿到門禁那句，實際 %v", err)
	}
	rows, err := e.service.Factions(context.Background(), principal, actA.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("列表應讀到那一行：%v（%d 行）", err, len(rows))
	}
	if !rows[0].Available || rows[0].AcceptsNewMembers {
		t.Errorf("停止活動裡的可用陣營該派生成「收不到新成員」，實際 available=%v accepts=%v",
			rows[0].Available, rows[0].AcceptsNewMembers)
	}

	// 歸檔是終態：判定拿到終態那一句，而不是「等重開」那一句。
	if _, err := e.service.Transition(context.Background(), principal, actA.ID,
		StatusArchived, "req-archive"); err != nil {
		t.Fatalf("歸檔活動應成功：%v", err)
	}
	if _, err := e.guardInWriteTx(t, actA.ID, reenabled.ID); !errors.Is(err, ErrArchived) {
		t.Errorf("歸檔態的判定應拿到終態那句，實際 %v", err)
	}

	// 誤用兩種都不放行：判定存在的理由就是「與寫入同一個快照」，交易外與唯讀交易都不算。
	if _, err := e.service.EnsureFactionAcceptsNewMembers(context.Background(), nil,
		actA.ID, reenabled.ID); !errors.Is(err, errFactionGuardNeedsWriteTx) {
		t.Errorf("零值交易該報誤用，實際 %v", err)
	}
	readOnlyErr := e.db.InTxReadOnly(context.Background(), func(tctx context.Context, tx *database.Tx) error {
		_, err := e.service.EnsureFactionAcceptsNewMembers(tctx, tx, actA.ID, reenabled.ID)
		if !errors.Is(err, errFactionGuardNeedsWriteTx) {
			t.Errorf("唯讀交易該報誤用而不是放行，實際 %v", err)
		}
		return nil
	})
	if readOnlyErr != nil {
		t.Fatalf("唯讀誤用的斷言該留在回呼裡，回呼本身該正常收尾：%v", readOnlyErr)
	}
}

// TestFactionDisableSerializesWithAssignmentCheck 驗收：停用寫入不能插在「交易內判定」與
// 該交易隨後那筆分配寫入之間——SQLite 只有一個寫入者，寫入交易在 BEGIN 就佔住寫入鎖，
// 於是隨後抵達的那一次停用只能排在本交易之後（既不丟更新，也不會出現
// 「判定說可用、寫進去時已停用」的那段視窗）。
//
// 這一組量的是進程內的串行化（本庫沒有真實分配寫入可插，也不偽造一張成員表）：
// 跨進程與跨機器的 BEGIN IMMEDIATE 等待行為自 R1 起一直列為未取證條件。
func TestFactionDisableSerializesWithAssignmentCheck(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Faction.Race")
	activity := e.create(t, principal, "串行取證的場", "")
	faction := e.mustCreateFaction(t, principal, activity.ID, factionDraft("會被插隊停用的陣營"))
	if _, err := e.service.Transition(context.Background(), principal, activity.ID,
		StatusActive, "req-open"); err != nil {
		t.Fatalf("開放活動應成功：%v", err)
	}
	e.clock.Advance(time.Minute)

	disabled := make(chan error, 1)
	err := e.db.InTx(context.Background(), func(tctx context.Context, tx *database.Tx) error {
		// 日後分配通路的形狀：在自己的寫入交易內現讀判定，判定通過才繼續寫。
		checked, err := e.service.EnsureFactionAcceptsNewMembers(tctx, tx, activity.ID, faction.ID)
		if err != nil {
			return err
		}
		if !checked.Available || !checked.AcceptsNewMembers {
			return fmt.Errorf("判定在交易內讀到的現值不該是停用：%+v", checked)
		}
		go func() {
			_, inner := e.setAvailability(context.Background(), principal, faction, false)
			disabled <- inner
		}()
		time.Sleep(100 * time.Millisecond)
		var available int64
		if err := e.db.SQL().QueryRowContext(context.Background(),
			"SELECT available FROM activity_factions WHERE id = ?", faction.ID.String()).Scan(&available); err != nil {
			return err
		}
		if available != 1 {
			return fmt.Errorf("停用在本交易結束前就落了庫（判定與寫入之間有視窗）")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("判定交易應正常收尾：%v", err)
	}
	if err := <-disabled; err != nil {
		t.Errorf("排在後面的停用該等鎖後照常成功，實際 %v", err)
	}
	if f := e.factionFacts(t, faction.ID); f.available != 0 {
		t.Error("排到鎖的停用必須最終生效（不能丟更新）")
	}
	if _, err := e.guardInWriteTx(t, activity.ID, faction.ID); !errors.Is(err, ErrFactionNotAcceptingMembers) {
		t.Errorf("停用落庫後的判定必須轉為拒絕，實際 %v", err)
	}
}
