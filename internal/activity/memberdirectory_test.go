// memberdirectory_test.go 是「活動玩家目錄可見性」用例的服務層證據：四態模式各自的答案、
// 無陣營不構成一個群體、管理視角只認服務端現讀的指派、覆蓋只收緊且不改管理視角與本人、
// 列表／詳情／計數／篩選候選／分頁同源同進退、跨活動與幽靈標識的不可分辨，
// 以及「改完配置的下一筆請求就按新規則回答」（倉庫裡沒有快取，也沒有推送系統可宣稱）。
//
// 刻意不收的東西：
//   - 沒有替身：准入、活動作用域、業務寫入門禁、授予現讀、CAS 與審計都走真路徑
//     （真資料庫＋真授予＋注入時鐘），接錯線就會紅；
//   - 不測協定層（欄位注入 1004、機器碼對映）：那是 internal/httpapi 的端點證據；
//   - 不測 NPC 目錄與它那套獨立授權：屬 NPC 模組，本步一欄都不碰。
package activity

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// dirScene 是本檔共用的現場：一場已開放的活動、兩個陣營、七行成員，
// 其中一位是「持有授予卻未獲指派」的管理人、一位是「持有授予的成員」。
//
// 七行的分工（每個可見性結論都要有對應的對象，否則斷言會缺角）：
//   - 甲／乙／己：同一個陣營（己是訪戶——參加不是權限，Guest 也在目錄裡）；
//   - 丙：另一個陣營（異陣營對象）；
//   - 丁：無陣營（「尚未分組」對象，不是任何群體的一員）；
//   - 後台的人：持有 server_admin 的成員（all_players_except_admin 那一態該收起來的對象）；
//   - 管理人：這場活動的管理人（也持有授予），管理視角的對象。
type dirScene struct {
	env       *env
	manager   identity.Principal
	outsider  identity.Principal
	activity  Activity
	other     Activity
	fac1      Faction
	fac2      Faction
	dirAudits int

	jia        Member
	yi         Member
	bing       Member
	ding       Member
	guest      Member
	adminRow   Member
	managerRow Member
	otherRow   Member // 另一場活動裡的行：跨活動拼接的對象必須「真的存在」才取得到證

	jiaP   identity.Principal
	yiP    identity.Principal
	bingP  identity.Principal
	dingP  identity.Principal
	guestP identity.Principal
	adminP identity.Principal
	otherP identity.Principal // 既非成員也非管理人：一個純粹的外人帳戶
}

// newDirScene 佈好上述現場。玩家自選那一欄配置在此順帶打開成 free：
// 今日唯一能落下陣營歸屬的通路就是它，而目錄判定吃的就是這個現值。
func newDirScene(t *testing.T) *dirScene {
	t.Helper()
	e := newEnv(t)
	s := &dirScene{env: e}

	managerPrincipal, managerAccount := e.admin(t, "Dir.Manager")
	outsiderPrincipal, _ := e.admin(t, "Dir.Outsider")
	s.manager, s.outsider = managerPrincipal, outsiderPrincipal

	a := e.create(t, managerPrincipal, "有目錄的場", "")
	opened := e.transition(t, managerPrincipal, a.ID, StatusActive)
	s.activity = opened
	// 另一場活動由外人管理：跨活動取證要有「他確實是那場活動的管理人」這個對照組。
	s.other = e.create(t, outsiderPrincipal, "輪不到他的場", "")

	s.fac1 = e.mustCreateFaction(t, managerPrincipal, opened.ID, FactionDraft{Name: "紅隊"})
	s.fac2 = e.mustCreateFaction(t, managerPrincipal, opened.ID, FactionDraft{Name: "藍隊"})
	e.mustSetMode(t, managerPrincipal, opened.ID, FactionSelectFree)

	seed := func(login, display string, accType account.Type) (identity.Principal, account.Account) {
		acc := e.seedAccount(t, login, display, accType, account.StatusActive)
		if accType == account.TypeGuest {
			return identitytest.Account(t, acc.ID, identitytest.WithGuestType()), acc
		}
		return identitytest.Account(t, acc.ID), acc
	}
	jiaP, jiaA := seed("Dir.Jia", "甲", account.TypeStandard)
	yiP, yiA := seed("Dir.Yi", "乙", account.TypeStandard)
	bingP, bingA := seed("Dir.Bing", "丙", account.TypeStandard)
	dingP, dingA := seed("Dir.Ding", "丁", account.TypeStandard)
	guestP, guestA := seed("Dir.Guest", "己", account.TypeGuest)
	otherP, otherA := seed("Dir.Other", "路人", account.TypeStandard)
	adminP, adminA := e.admin(t, "Dir.AdminMember")

	mustMember := func(acc account.Account, nickname string) Member {
		return e.mustCreateMember(t, managerPrincipal, opened.ID, acc.ID, nickname)
	}
	s.jia = mustMember(jiaA, "甲")
	s.yi = mustMember(yiA, "乙")
	s.bing = mustMember(bingA, "丙")
	s.ding = mustMember(dingA, "丁")
	s.guest = mustMember(guestA, "己")
	s.adminRow = mustMember(adminA, "後台的人")
	s.managerRow = mustMember(managerAccount, "管理人")
	// 另一場活動（外人管理、草稿態）裡也種一行：跨活動拼接的取證對象必須真有其行，
	// 否則「查無」與「存在但不屬於這個活動」的收斂沒有被真正問到。
	s.otherRow = e.mustCreateMember(t, outsiderPrincipal, s.other.ID, otherA.ID, "別處的人")

	s.jiaP, s.yiP, s.bingP, s.dingP = jiaP, yiP, bingP, dingP
	s.guestP, s.adminP, s.otherP = guestP, adminP, otherP

	// 歸屬由玩家自己選下去（本倉庫今日唯一能寫這一欄的通路）。
	e.mustSelect(t, jiaP, opened.ID, s.fac1.ID, idgen.Nil)
	e.mustSelect(t, yiP, opened.ID, s.fac1.ID, idgen.Nil)
	e.mustSelect(t, guestP, opened.ID, s.fac1.ID, idgen.Nil)
	e.mustSelect(t, bingP, opened.ID, s.fac2.ID, idgen.Nil)
	// 丁、後台的人、管理人刻意留在「尚未分組」：無陣營與管理視角兩條邊都要有對象。
	return s
}

// setMode 由管理人改活動那一欄目錄模式，並把場景裡的活動現值一起換掉。
func (s *dirScene) setMode(t *testing.T, want DirectoryMode) Activity {
	t.Helper()
	current, err := s.env.service.ActivityDetail(context.Background(), s.manager, s.activity.ID)
	if err != nil {
		t.Fatalf("讀活動現值失敗：%v", err)
	}
	updated, err := s.env.service.UpdateMemberDirectoryMode(context.Background(), s.manager,
		s.activity.ID, want, current.MemberDirectoryMode, "req-set-mode")
	if err != nil {
		t.Fatalf("設定目錄模式 %q 應成功：%v", want, err)
	}
	s.activity = updated
	return updated
}

// list 讀一頁本場景活動的目錄（本檔的七行都進得来：每頁 50）。
func (s *dirScene) list(t *testing.T, p identity.Principal) DirectoryMemberPage {
	t.Helper()
	return s.listIn(t, p, s.activity.ID)
}

// listIn 讀一頁指定活動的目錄：跨活動取證要能拿同一位玩家去敲另一場活動。
func (s *dirScene) listIn(t *testing.T, p identity.Principal, activityID idgen.ID) DirectoryMemberPage {
	t.Helper()
	page, err := s.env.service.MemberDirectory(context.Background(), p, activityID,
		DirectoryMemberQuery{Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("目錄一讀應成功：%v", err)
	}
	return page
}

// modeFacts 讀那一欄配置的庫中現值（改配置的結論只問資料庫，不問用例的回憶）。
func (s *dirScene) modeFacts(t *testing.T) string {
	t.Helper()
	var mode string
	err := s.env.db.SQL().QueryRowContext(context.Background(),
		`SELECT member_directory_mode FROM activities WHERE id = ?`,
		s.activity.ID.String()).Scan(&mode)
	if err != nil {
		t.Fatalf("讀取目錄模式現值失敗：%v", err)
	}
	return mode
}

// visibilityFacts 讀一行成員的覆蓋庫中現值。
func (s *dirScene) visibilityFacts(t *testing.T, memberID idgen.ID) string {
	t.Helper()
	var visibility string
	err := s.env.db.SQL().QueryRowContext(context.Background(),
		`SELECT directory_visibility FROM activity_members WHERE id = ?`,
		memberID.String()).Scan(&visibility)
	if err != nil {
		t.Fatalf("讀取成員 %s 的覆蓋失敗：%v", memberID, err)
	}
	return visibility
}

// setVisibility 由管理人改一行成員的覆蓋。
func (s *dirScene) setVisibility(t *testing.T, memberID idgen.ID,
	want, expected DirectoryVisibility) Member {
	t.Helper()
	updated, err := s.env.service.UpdateMemberDirectoryVisibility(context.Background(), s.manager,
		s.activity.ID, memberID, want, expected, "req-set-visibility")
	if err != nil {
		t.Fatalf("設定覆蓋 %q 應成功：%v", want, err)
	}
	return updated
}

// nicknames 取一頁目錄的暱稱清單（交給 equalSets 比較；斷言只問有哪些人，不依賴行序）。
func nicknames(rows []DirectoryMember) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Nickname)
	}
	return out
}

// TestDirectoryFourModesMatrix 驗收四態模式各自的答案，對象涵蓋同陣營、異陣營、無陣營、
// 管理員身分的成員、普通成員、訪戶與（管理視角那一側）這場活動與非這場活動的管理人。
func TestDirectoryFourModesMatrix(t *testing.T) {
	s := newDirScene(t)
	// 七行的全集（全部活動成員）。
	all := []string{"甲", "乙", "丙", "丁", "己", "後台的人", "管理人"}
	// 紅隊三人（含訪戶）。
	red := []string{"甲", "乙", "己"}
	// 排除管理員身分之後剩下的五人（收起來的是「後台的人」與同样是持有授予者的管理人）。
	notAdmin := []string{"甲", "乙", "丙", "丁", "己"}

	t.Run("出廠讀成 hidden：不經任何配置就是一個都不列", func(t *testing.T) {
		page := s.list(t, s.jiaP)
		if page.Mode != DirectoryHidden {
			t.Fatalf("新模式讀出的出廠值必須是 hidden，實際 %s", page.Mode)
		}
		if len(page.Rows) != 0 || page.Total != 0 {
			t.Errorf("hidden 態必須一個人都沒有，實際 %v／總數 %d", nicknames(page.Rows), page.Total)
		}
		if len(page.Facets) != 0 {
			t.Errorf("hidden 態不該有任何篩選候選，實際 %d 項", len(page.Facets))
		}
	})

	t.Run("same_faction_only：同陣營互見、異陣營不可見、無陣營不是一個群體", func(t *testing.T) {
		s.setMode(t, DirectorySameFaction)
		page := s.list(t, s.jiaP)
		if got := nicknames(page.Rows); !equalSets(got, red) {
			t.Errorf("甲在僅同陣營態下該看到 %v，實際 %v", red, got)
		}
		if page.Total != 3 {
			t.Errorf("計數必須與列表同一份結果集（3 筆），實際 %d", page.Total)
		}
		// 無陣營的兩個人（丁與後台的人）彼此看不見，也看不見紅隊：各自只看得到自己。
		for name, p := range map[string]identity.Principal{"丁": s.dingP, "後台的人": s.adminP} {
			if got := nicknames(s.list(t, p).Rows); !equalSets(got, []string{name}) {
				t.Errorf("%s 無陣營時只該看見自己，實際 %v", name, got)
			}
		}
		// 藍隊只有丙一個人：他的目錄也只有一行，而不是「看得见整場的人」。
		if got := nicknames(s.list(t, s.bingP).Rows); !equalSets(got, []string{"丙"}) {
			t.Errorf("丙在僅同陣營態下只該看見自己，實際 %v", got)
		}
		// 篩選候選只能有他自己那個陣營，計數也不能洩漏別人那邊有幾個人。
		if len(page.Facets) != 1 || page.Facets[0].FactionID != s.fac1.ID || page.Facets[0].Count != 3 {
			t.Errorf("候選必須只剩紅隊且計數為 3，實際 %+v", page.Facets)
		}
	})

	t.Run("all_players_except_admin：收起來的是持有授予的那兩行", func(t *testing.T) {
		s.setMode(t, DirectoryAllExceptAdmin)
		page := s.list(t, s.jiaP)
		if got := nicknames(page.Rows); !equalSets(got, notAdmin) {
			t.Errorf("甲該看到 %v（不含後台的人與管理人），實際 %v", notAdmin, got)
		}
		// 判據是暱稱還是授予？把名字改成聽起來像普通玩家的那一個，他依然被收起來；
		// 反過來撤下授予，同一行立刻變成普通玩家可見（授予才是唯一來源）。
		if _, err := s.env.service.UpdateMemberNickname(context.Background(), s.manager,
			s.activity.ID, s.adminRow.ID, "路人辛", "後台的人", "req-rename"); err != nil {
			t.Fatalf("改名失敗：%v", err)
		}
		if got := nicknames(s.list(t, s.jiaP).Rows); contains(got, "路人辛") {
			t.Errorf("改暱稱不該讓他變得可見（判據不是名字）：%v", got)
		}
		s.env.dropGrant(t, s.adminRow.AccountID)
		if got := nicknames(s.list(t, s.jiaP).Rows); !contains(got, "路人辛") {
			t.Errorf("撤下授予後下一筆請求他就該被列出來：%v", got)
		}
		// 還原：把授予與暱稱放回去，免得污染其他子測試。
		if err := s.env.grants.Grant(context.Background(), s.env.db.SQL(), s.adminRow.AccountID,
			identity.RoleServerAdmin); err != nil {
			t.Fatalf("補回授予失敗：%v", err)
		}
		if _, err := s.env.service.UpdateMemberNickname(context.Background(), s.manager,
			s.activity.ID, s.adminRow.ID, "後台的人", "路人辛", "req-rename-back"); err != nil {
			t.Fatalf("改回名字失敗：%v", err)
		}
	})

	t.Run("all_members：七行全列，訪戶與持有授予者同列", func(t *testing.T) {
		s.setMode(t, DirectoryAllMembers)
		page := s.list(t, s.jiaP)
		if got := nicknames(page.Rows); !equalSets(got, all) {
			t.Errorf("全量態該看到 %v，實際 %v", all, got)
		}
		if page.Total != 7 {
			t.Errorf("總數必須等於可見行數，實際 %d", page.Total)
		}
		// 候選按陣營清單定序：紅隊 3 人、藍隊 1 人；無陣營那三行不成為一項。
		if len(page.Facets) != 2 || page.Facets[0].FactionID != s.fac1.ID ||
			page.Facets[0].Count != 3 || page.Facets[1].FactionID != s.fac2.ID ||
			page.Facets[1].Count != 1 {
			t.Errorf("候選必須是紅隊 3／藍隊 1，實際 %+v", page.Facets)
		}
		if page.SelfID != s.jia.ID {
			t.Errorf("回應要如實標出觀看者自己那一行，實際 %s", page.SelfID)
		}
	})

	t.Run("管理視角：獲准管理這場活動的人在 hidden 態也看得到全部", func(t *testing.T) {
		s.setMode(t, DirectoryHidden)
		page := s.list(t, s.manager)
		if got := nicknames(page.Rows); !equalSets(got, all) {
			t.Errorf("管理人該看到全部 %v，實際 %v", all, got)
		}
		if page.Mode != DirectoryHidden {
			t.Errorf("回應仍要如實說出活動的模式是 hidden，實際 %s", page.Mode)
		}
		// 持有授予但這個活動不歸他管：他連這場活動的目錄都敲不進（非成員＋非管理人同形），
		// 這就是「不授予其他活動管理權」與「玩家不能靠參數提權」的同一句話。
		if _, err := s.env.service.MemberDirectory(context.Background(), s.outsider, s.activity.ID,
			DirectoryMemberQuery{Page: 1, PageSize: 50}); !errors.Is(err, ErrMemberNotFound) {
			t.Errorf("外人管理員該收斂成不可分辨：%v", err)
		}
		// 而他在自己獲准管理的那場活動裡是管理人：那一場只有一行成員（他本人不是成員），
		// 他看得到那一行，而 self_member_id 是零值——介面據此不該把那一行標成「這是我」。
		own := s.listIn(t, s.outsider, s.other.ID)
		if got := nicknames(own.Rows); !equalSets(got, []string{"別處的人"}) {
			t.Errorf("管理視角在他自己管的活動裡該看到那一行的全部成員，實際 %v", got)
		}
		if !own.SelfID.IsNil() {
			t.Errorf("他不是這場活動的成員，self_member_id 該是零值（介面據此不標「這是我」）")
		}
	})
}

// TestDirectoryDetailSharesListPolicy 驗收「列得出來才點得進去」：單筆直查與列表吃同一句判定，
// 而「找到了行但不給看」「它屬於另一場活動」「從未存在」三種原因對外是同一個結論。
func TestDirectoryDetailSharesListPolicy(t *testing.T) {
	s := newDirScene(t)
	s.setMode(t, DirectorySameFaction)
	ctx := context.Background()

	item, err := s.env.service.DirectoryMemberDetail(ctx, s.jiaP, s.activity.ID, s.yi.ID)
	if err != nil || item.Nickname != "乙" || item.FactionName != "紅隊" {
		t.Fatalf("同陣營的那一行該直查得動：%v／%+v", err, item)
	}
	// 列表裡有的每一行都該直查得動，列表裡沒有的每一行都該不可分辨（同一句判定的兩面）。
	page := s.list(t, s.jiaP)
	if !equalSets(nicknames(page.Rows), []string{"甲", "乙", "己"}) {
		t.Fatalf("起手列表該是紅隊三人，實際 %v", nicknames(page.Rows))
	}
	for _, row := range page.Rows {
		if _, err := s.env.service.DirectoryMemberDetail(ctx, s.jiaP, s.activity.ID,
			row.MemberID); err != nil {
			t.Errorf("列出來的 %s 該點得進去：%v", row.Nickname, err)
		}
	}
	ghost := identitytest.NewID(t)
	for name, target := range map[string]idgen.ID{
		"異陣營的丙":    s.bing.ID,
		"無陣營的丁":    s.ding.ID,
		"持有授予的那一行": s.adminRow.ID,
		"本活動的管理人":  s.managerRow.ID,
		"從未存在的標識":  ghost,
	} {
		if _, err := s.env.service.DirectoryMemberDetail(ctx, s.jiaP, s.activity.ID,
			target); !errors.Is(err, ErrMemberNotFound) {
			t.Errorf("%s 在僅同陣營態下該與查無同形，實際 %v", name, err)
		}
	}
	// 跨活動拼接：那一行確實存在，但屬於另一場活動——拿它的標識配這條路徑必須同樣不可分辨。
	if _, err := s.env.service.DirectoryMemberDetail(ctx, s.jiaP, s.activity.ID,
		s.otherRow.ID); !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("拿別處那一行的標識直查該不可分辨：%v", err)
	}
	// 而那一場活動的管理人讀得到它（同一句判定在另一場活動裡的答案不同）：
	// 這條反證釘住的是「不可分辨來自歸屬核實，不是查無此人」。
	if item, err := s.env.service.DirectoryMemberDetail(ctx, s.outsider, s.other.ID,
		s.otherRow.ID); err != nil || item.Nickname != "別處的人" {
		t.Errorf("外人那場活動的管理人該讀得到他自己的行：%v／%+v", err, item)
	}
	// 非隱藏態下，管理人對列表裡沒有的行照樣點得進去（管理視角不看模式與覆蓋）。
	s.setMode(t, DirectoryHidden)
	if _, err := s.env.service.DirectoryMemberDetail(ctx, s.manager, s.activity.ID,
		s.ding.ID); err != nil {
		t.Errorf("hidden 態下管理人該仍點得進任何一行：%v", err)
	}
	// 而普通玩家在 hidden 態連自己都查不到（目錄在這一態就是不列任何人）。
	if _, err := s.env.service.DirectoryMemberDetail(ctx, s.jiaP, s.activity.ID,
		s.jia.ID); !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("hidden 態下本人的標識直查也該不可分辨：%v", err)
	}
	// 但本人的那一讀照舊成功：兩條通路回答的是兩個問題。
	if view, err := s.env.service.OwnMemberProfile(ctx, s.jiaP, s.activity.ID); err != nil ||
		view.Member.ID != s.jia.ID {
		t.Errorf("本人資料那一讀不该受目錄模式影響：%v／%+v", err, view)
	}
}

// TestDirectoryOverrideOnlyTightens 驗收覆蓋那一句：只能收緊，永不放寬，
// 也不改管理視角與本人的那一讀。
func TestDirectoryOverrideOnlyTightens(t *testing.T) {
	s := newDirScene(t)
	s.setMode(t, DirectoryAllMembers)

	s.setVisibility(t, s.yi.ID, DirectoryVisibilityHidden, DirectoryVisibilityInherit)
	page := s.list(t, s.jiaP)
	if contains(nicknames(page.Rows), "乙") {
		t.Errorf("收起來之後其他普通玩家不該再列到他：%v", nicknames(page.Rows))
	}
	if page.Total != 6 {
		t.Errorf("計數要跟著少一行（六行），實際 %d", page.Total)
	}
	if got := nicknames(s.list(t, s.bingP).Rows); contains(got, "乙") {
		t.Errorf("覆蓋跨所有非管理模式生效（全量態也一样收起來）：%v", got)
	}
	// 本人的那一讀不受影響（用戶批准於本步：隱藏與覆蓋都不該讓他讀不到自己）。
	own, err := s.env.service.OwnMemberProfile(context.Background(), s.yiP, s.activity.ID)
	if err != nil {
		t.Fatalf("本人讀自己的行應成功：%v", err)
	}
	if own.Member.DirectoryVisibility != DirectoryVisibilityHidden || own.Member.Nickname != "乙" {
		t.Errorf("本人投影要如實帶出自己的覆蓋與暱稱：%+v", own.Member)
	}
	// 乙自己也還在目錄裡看得見自己（覆蓋收的是「別人能不能看見他」）。
	if got := nicknames(s.list(t, s.yiP).Rows); !contains(got, "乙") {
		t.Errorf("被收起來的人仍該看得見自己，實際 %v", got)
	}
	// 篩選候選也跟著收：紅隊從三人變兩人，計數與列表同源。
	for _, facet := range s.list(t, s.jiaP).Facets {
		if facet.FactionID == s.fac1.ID && facet.Count != 2 {
			t.Errorf("候選計數該跟著覆蓋變成 2，實際 %+v", facet)
		}
	}
	// 管理視角不看覆蓋。
	if got := nicknames(s.list(t, s.manager).Rows); !contains(got, "乙") {
		t.Errorf("管理人該無視覆蓋看到全部，實際 %v", got)
	}

	// 覆蓋不能放寬：活動是 hidden 時，無論那一行是 inherit 還是 hidden 都是空的一頁。
	s.setVisibility(t, s.yi.ID, DirectoryVisibilityInherit, DirectoryVisibilityHidden)
	s.setMode(t, DirectoryHidden)
	if len(s.list(t, s.jiaP).Rows) != 0 {
		t.Errorf("hidden 態下覆蓋是 inherit 也該一個人都沒有")
	}
	// 「放寬」那一格在協定上無處可填：集合外的取值連庫都進不去，庫中現值一個字都沒動。
	if _, err := s.env.service.UpdateMemberDirectoryVisibility(context.Background(), s.manager,
		s.activity.ID, s.yi.ID, DirectoryVisibility("visible"), DirectoryVisibilityInherit,
		"req-widen"); !errors.Is(err, ErrInvalidDirectoryVisibility) {
		t.Errorf("意圖放寬的取值該被域校驗擋掉：%v", err)
	}
	if got := s.visibilityFacts(t, s.yi.ID); got != "inherit" {
		t.Errorf("被拒的放寬不得落庫，庫中現值 %q", got)
	}
}

// TestDirectoryConsistencyAcrossPagingSearchAndCount 驗收「先授權篩選、再分頁計數」：
// 各頁合起來正好等於總數，關鍵字與陣營篩選同時改變列表與計數，而詳情與它們同進退。
func TestDirectoryConsistencyAcrossPagingSearchAndCount(t *testing.T) {
	s := newDirScene(t)
	s.setMode(t, DirectoryAllMembers)
	ctx := context.Background()

	// 逐頁走完整份目錄：合起來必須是不重不漏的七行（游標不吞人、不重複吐人）。
	var seen []string
	for page := int64(1); page <= 4; page++ {
		got, err := s.env.service.MemberDirectory(ctx, s.jiaP, s.activity.ID,
			DirectoryMemberQuery{Page: page, PageSize: 2})
		if err != nil {
			t.Fatalf("第 %d 頁該成功：%v", page, err)
		}
		if got.Total != 7 {
			t.Errorf("總數不受分頁影響（該是 7），實際 %d", got.Total)
		}
		if len(got.Rows) > 2 {
			t.Errorf("每頁不得超過 2 行，實際 %d", len(got.Rows))
		}
		for _, row := range got.Rows {
			seen = append(seen, row.MemberID.String())
		}
	}
	if unique := dedupe(seen); len(unique) != 7 || len(seen) != 7 {
		t.Errorf("四頁合起來必須剛好是那七行（不重不漏），實際共 %d 行、去重後 %d 行",
			len(seen), len(unique))
	}
	// 越界的一頁：空 Rows、Total 照實，不是錯誤也不是「查無此活動」。
	far, err := s.env.service.MemberDirectory(ctx, s.jiaP, s.activity.ID,
		DirectoryMemberQuery{Page: 9, PageSize: 2})
	if err != nil || len(far.Rows) != 0 || far.Total != 7 {
		t.Errorf("越界頁該是空的一頁而 Total 照實：%v／%d／%d", err, len(far.Rows), far.Total)
	}

	// 關鍵字同時收列表與計數（而且只搜活動內暱稱，搜不到任何帳戶欄位）。
	for _, tc := range []struct {
		keyword string
		want    []string
	}{
		{"甲", []string{"甲"}},
		{"人", []string{"管理人", "後台的人"}},
		{"己", []string{"己"}},
		// 顯示名與登入名都不在投影裡：拿帳戶側的字去搜必須命中零行（也零計數）。
		{"平民", []string{}},
		{"查無", []string{}},
	} {
		page, err := s.env.service.MemberDirectory(ctx, s.jiaP, s.activity.ID,
			DirectoryMemberQuery{Page: 1, PageSize: 50, Keyword: tc.keyword})
		if err != nil {
			t.Fatalf("關鍵字 %q 該成功：%v", tc.keyword, err)
		}
		if got := nicknames(page.Rows); !equalSets(got, tc.want) {
			t.Errorf("關鍵字 %q 該命中 %v，實際 %v", tc.keyword, tc.want, got)
		}
		if page.Total != int64(len(tc.want)) {
			t.Errorf("關鍵字 %q 的計數要與列表同源（%d 筆），實際 %d",
				tc.keyword, len(tc.want), page.Total)
		}
	}

	// 陣營篩選：紅隊三行、藍隊一行；外來的陣營標識得到空的一頁而不是任何信號。
	red, err := s.env.service.MemberDirectory(ctx, s.jiaP, s.activity.ID,
		DirectoryMemberQuery{Page: 1, PageSize: 50, FactionID: s.fac1.ID})
	if err != nil || red.Total != 3 || !equalSets(nicknames(red.Rows), []string{"甲", "乙", "己"}) {
		t.Fatalf("紅隊篩選該是甲乙己三行：%v／%+v", err, red)
	}
	foreign := identitytest.NewID(t)
	page, err := s.env.service.MemberDirectory(ctx, s.jiaP, s.activity.ID,
		DirectoryMemberQuery{Page: 1, PageSize: 50, FactionID: foreign})
	if err != nil || page.Total != 0 {
		t.Errorf("外來陣營標識該回空的一頁（不多出存在性信號）：%v／%d", err, page.Total)
	}
	// 篩選候選不受關鍵字與陣營篩選影響，仍由「已授權篩選」那份派生（候選不會自己消失）。
	full, err := s.env.service.MemberDirectory(ctx, s.jiaP, s.activity.ID,
		DirectoryMemberQuery{Page: 1, PageSize: 50, Keyword: "丙", FactionID: s.fac2.ID})
	if err != nil || len(full.Facets) != 2 || full.Total != 1 {
		t.Errorf("篩選後的計數該是 1 而候選仍是兩項：%v／%+v／%d", err, full.Facets, full.Total)
	}

	// 非法分頁與超長關鍵字各有自己那句可判別的話（不降級成「當成沒帶」）。
	if err := s.listErr(s.jiaP, DirectoryMemberQuery{Page: 0, PageSize: 50}); !errors.Is(err,
		ErrInvalidPage) {
		t.Errorf("page=0 該被點名：%v", err)
	}
	if err := s.listErr(s.jiaP, DirectoryMemberQuery{Page: 1, PageSize: 0}); !errors.Is(err,
		ErrInvalidPageSize) {
		t.Errorf("page_size=0 該被點名：%v", err)
	}
	if err := s.listErr(s.jiaP, DirectoryMemberQuery{Page: 1, PageSize: DirectoryMaxPageSize + 1}); !errors.Is(err,
		ErrInvalidPageSize) {
		t.Errorf("超過上限的 page_size 該被點名：%v", err)
	}
	if err := s.listErr(s.jiaP, DirectoryMemberQuery{Page: 1, PageSize: 50,
		Keyword: strings.Repeat("長", DirectoryKeywordMaxRunes+1)}); !errors.Is(err,
		ErrInvalidKeyword) {
		t.Errorf("超長關鍵字該被點名：%v", err)
	}
}

// TestDirectoryReadsFreshStateEachRequest 驗收「不長期信任舊陣營或舊配置」的請求級失效：
// 玩家換了歸屬、管理人換了模式或覆蓋、授予與指派被撤下，下一筆請求就按新規則回答。
func TestDirectoryReadsFreshStateEachRequest(t *testing.T) {
	s := newDirScene(t)
	s.setMode(t, DirectorySameFaction)
	ctx := context.Background()

	if got := nicknames(s.list(t, s.jiaP).Rows); !equalSets(got, []string{"甲", "乙", "己"}) {
		t.Fatalf("起手該是紅隊三人，實際 %v", got)
	}
	// 甲自己換到藍隊：下一筆請求他的可見範圍立刻跟著換（沒有舊歸屬可被繼續信任）。
	s.env.mustSelect(t, s.jiaP, s.activity.ID, s.fac2.ID, s.fac1.ID)
	if got := nicknames(s.list(t, s.jiaP).Rows); !equalSets(got, []string{"丙", "甲"}) {
		t.Errorf("換隊後下一筆請求該只看見藍隊，實際 %v", got)
	}
	// 管理人把模式換成全量：同一位玩家的下一筆請求立刻多看見所有人。
	s.setMode(t, DirectoryAllMembers)
	if page := s.list(t, s.jiaP); page.Total != 7 {
		t.Errorf("改完配置的下一筆請求該是七行，實際 %d", page.Total)
	}
	// 覆蓋落地的那一刻同理：收起來一行，下一筆請求就少一行。
	s.setVisibility(t, s.yi.ID, DirectoryVisibilityHidden, DirectoryVisibilityInherit)
	if page := s.list(t, s.jiaP); page.Total != 6 || contains(nicknames(page.Rows), "乙") {
		t.Errorf("改完覆蓋的下一筆請求該少一行：%d／%v", page.Total, nicknames(page.Rows))
	}
	// 撤銷授予之後，「管理員身分」這一判據也立刻跟著變。
	s.setMode(t, DirectoryAllExceptAdmin)
	if got := nicknames(s.list(t, s.jiaP).Rows); contains(got, "後台的人") {
		t.Fatalf("排除管理員身分那態該把他收起來：%v", got)
	}
	s.env.dropGrant(t, s.adminRow.AccountID)
	if got := nicknames(s.list(t, s.jiaP).Rows); !contains(got, "後台的人") {
		t.Errorf("撤下授予後下一筆請求他就只是普通玩家：%v", got)
	}
	// 撤銷指派的那一刻，管理視角同時消失（同一個現讀來源，沒有第二份真相）：
	// 收起來的那一行他不再看得見，而覆蓋對他也重新生效了。
	if before := len(s.list(t, s.manager).Rows); before != 7 {
		t.Fatalf("撤銷前他作為管理人該看到全部七行（覆蓋不改管理視角），實際 %d", before)
	}
	if _, err := s.env.service.RevokeManager(ctx, s.env.root(t), s.activity.ID,
		s.managerRow.AccountID, "req-revoke"); err != nil {
		t.Fatalf("撤銷指派應成功：%v", err)
	}
	former := s.list(t, s.manager)
	if len(former.Rows) != 6 || contains(nicknames(former.Rows), "乙") {
		t.Errorf("撤銷指派後他只剩普通玩家的可見範圍（被覆蓋收起來的那行不再出現），實際 %v",
			nicknames(former.Rows))
	}
}

// TestDirectoryPrincipalAndScopeConvergence 驗收主體與可見範圍的收斂：匿名先撞身分問題，
// Root 與系統主體在玩家這一族沒有可指向的行，非成員與幽靈同形，外人看不到任何一行。
func TestDirectoryPrincipalAndScopeConvergence(t *testing.T) {
	s := newDirScene(t)
	s.setMode(t, DirectoryAllMembers)
	ctx := context.Background()

	if _, err := s.env.service.MemberDirectory(ctx, identity.Anonymous(), s.activity.ID,
		DirectoryMemberQuery{Page: 1, PageSize: 50}); !errors.Is(err, identity.ErrNotAuthenticated) {
		t.Errorf("匿名該先撞在未通過認證上：%v", err)
	}
	for name, p := range map[string]identity.Principal{
		"Root": s.env.root(t),
		"系統主體": identitytest.System(t, identity.OriginStartup),
	} {
		if _, err := s.env.service.MemberDirectory(ctx, p, s.activity.ID,
			DirectoryMemberQuery{Page: 1, PageSize: 50}); !errors.Is(err, ErrMemberNotFound) {
			t.Errorf("%s 在玩家目錄那一族該與查無同形，而不是得到全量：%v", name, err)
		}
	}
	// 既非成員又非管理人的普通帳戶：同一句話，不多出「那個活動存在」這條資訊。
	if _, err := s.env.service.MemberDirectory(ctx, s.otherP, s.activity.ID,
		DirectoryMemberQuery{Page: 1, PageSize: 50}); !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("外人帳戶該收斂成不可分辨：%v", err)
	}
	// 幽靈活動：不可分辨（與「有這場活動但沒我的份」同樣不外洩存在性）。
	if _, err := s.env.service.MemberDirectory(ctx, s.jiaP, identitytest.NewID(t),
		DirectoryMemberQuery{Page: 1, PageSize: 50}); !errors.Is(err, ErrActivityNotFound) {
		t.Errorf("幽靈活動該報不可見範圍：%v", err)
	}
	// 本人的那一讀同樣只認會話帳戶：外人拿不到任何人的投影。
	if _, err := s.env.service.OwnMemberProfile(ctx, s.otherP, s.activity.ID); !errors.Is(err,
		ErrMemberNotFound) {
		t.Errorf("外人讀本人資料該收斂成不可分辨：%v", err)
	}
	if view, err := s.env.service.OwnMemberProfile(ctx, s.jiaP, s.activity.ID); err != nil ||
		view.Activity.MemberDirectoryMode != DirectoryAllMembers {
		t.Errorf("本人那一讀要帶回活動模式：%v／%+v", err, view.Activity)
	}
	// hidden 態下本人的那一讀照樣成功（用戶批准於本步：列表全隱藏、本人只讀自己的行）。
	s.setMode(t, DirectoryHidden)
	view, err := s.env.service.OwnMemberProfile(ctx, s.jiaP, s.activity.ID)
	if err != nil {
		t.Fatalf("隱藏態下本人那一讀仍該成功：%v", err)
	}
	if view.Item.Nickname != "甲" || view.Item.FactionID != s.fac1.ID ||
		view.Item.FactionName != "紅隊" ||
		view.Member.DirectoryVisibility != DirectoryVisibilityInherit {
		t.Errorf("本人投影要含活動內的展示事實：%+v／%+v", view.Item, view.Member)
	}
	// 白名單：本人投影之外，目錄項裡不該有任何帳戶欄位——這一句用回應的欄位存在性反證
	// （DirectoryMember 型別本身沒有那些欄位，這裡釘住的是「沒有誰把帳戶事實塞進來」）。
	if page := s.list(t, s.jiaP); len(page.Rows) != 0 {
		t.Errorf("同一位玩家在 hidden 態的目錄該是空的（兩句不是同一件事）")
	}
}

// TestDirectoryModeWriteRules 驗收那一欄配置的寫入：白名單只動自己一欄、留痕帶管理人身份與
// 前後值、併發落敗不覆蓋贏家、停止態仍可準備而歸檔終態一律拒、被拒不落痕。
func TestDirectoryModeWriteRules(t *testing.T) {
	s := newDirScene(t)
	ctx := context.Background()
	before := s.env.facts(t, s.activity.ID)

	updated, err := s.env.service.UpdateMemberDirectoryMode(ctx, s.manager, s.activity.ID,
		DirectorySameFaction, DirectoryHidden, "req-mode-1")
	if err != nil {
		t.Fatalf("首次設定模式應成功：%v", err)
	}
	if updated.MemberDirectoryMode != DirectorySameFaction {
		t.Errorf("回應要回顯新值：%s", updated.MemberDirectoryMode)
	}
	if after := s.env.facts(t, s.activity.ID); after.name != before.name ||
		after.description != before.description || after.status != before.status ||
		after.createdAt != before.createdAt || after.createdBy != before.createdBy {
		t.Errorf("改目錄配置不得動到活動的其他事實：%+v → %+v", before, after)
	}
	row := s.env.latestAuditOf(t, "activity.member_directory_update", s.activity.ID.String())
	if row.actorKind != "admin" || row.actorID != s.manager.AccountID().String() ||
		!strings.Contains(row.changes, "member_directory_mode") ||
		!strings.Contains(row.changes, "hidden") ||
		!strings.Contains(row.changes, "same_faction_only") {
		t.Errorf("留痕要帶管理人身份與前後值：%+v", row)
	}
	if row.targetID != s.activity.ID.String() {
		t.Errorf("配置那一筆的目標是活動本身，不是某人：%s", row.targetID)
	}

	// 併發：兩份同依據值只有一筆成功，落敗的那一個不覆蓋現值也不補第二條痕。
	if _, err := s.env.service.UpdateMemberDirectoryMode(ctx, s.manager, s.activity.ID,
		DirectoryAllMembers, DirectoryHidden, "req-stale"); !errors.Is(err, ErrProfileConflict) {
		t.Errorf("依據值已過期該回可判別的衝突：%v", err)
	}
	if got := s.modeFacts(t); got != "same_faction_only" {
		t.Errorf("落敗的那一筆不得覆蓋贏家，庫裡現值是 %q", got)
	}
	if s.env.countAuditRows(t, "activity.member_directory_update",
		s.activity.ID.String()) != 1 {
		t.Errorf("被拒的編輯不追加審計")
	}

	// 取值不在集合內：整個寫入不發生（也不留痕）。
	if _, err := s.env.service.UpdateMemberDirectoryMode(ctx, s.manager, s.activity.ID,
		DirectoryMode("everyone"), DirectorySameFaction, "req-bad"); !errors.Is(err,
		ErrInvalidDirectoryMode) {
		t.Errorf("集合外模式該被域校驗擋掉：%v", err)
	}
	if s.env.countAuditRows(t, "activity.member_directory_update",
		s.activity.ID.String()) != 1 {
		t.Errorf("寫法錯誤也不該留下第二筆留痕")
	}
	// 外人（未獲指派的管理人）敲不進這條：收斂成不可分辨；普通成員拿到的是權限不足。
	if _, err := s.env.service.UpdateMemberDirectoryMode(ctx, s.outsider, s.activity.ID,
		DirectoryAllMembers, DirectorySameFaction, "req-outsider"); !errors.Is(err,
		ErrActivityNotFound) {
		t.Errorf("外人的配置寫入該與查無同形：%v", err)
	}
	if _, err := s.env.service.UpdateMemberDirectoryMode(ctx, s.jiaP, s.activity.ID,
		DirectoryAllMembers, DirectorySameFaction, "req-plain"); !errors.Is(err,
		identity.ErrPermissionDenied) {
		t.Errorf("玩家改配置該拿到權限不足：%v", err)
	}
	// 改配置不改寫任何人的既有事實：歸屬與覆蓋一欄都不動。
	memberBefore := s.env.memberFacts(t, s.jia.ID)
	visibilityBefore := s.visibilityFacts(t, s.jia.ID)
	if _, err := s.env.service.UpdateMemberDirectoryMode(ctx, s.manager, s.activity.ID,
		DirectoryAllMembers, DirectorySameFaction, "req-mode-2"); err != nil {
		t.Fatalf("再次設定模式應成功：%v", err)
	}
	if after := s.env.memberFacts(t, s.jia.ID); after.nickname != memberBefore.nickname ||
		after.factionID.String != memberBefore.factionID.String {
		t.Errorf("收回或放大目錄不得搬動任何人的歸屬：%+v → %+v", memberBefore, after)
	}
	if got := s.visibilityFacts(t, s.jia.ID); got != visibilityBefore {
		t.Errorf("收回或放大目錄不得改任何人的覆蓋現值：%q → %q", visibilityBefore, got)
	}

	// 停止態仍可準備這欄配置（它與名稱、描述同側）；歸檔終態一律拒。
	stopped := s.env.transition(t, s.manager, s.activity.ID, StatusClosed)
	if got, err := s.env.service.UpdateMemberDirectoryMode(ctx, s.manager, s.activity.ID,
		DirectoryHidden, stopped.MemberDirectoryMode, "req-while-closed"); err != nil ||
		got.Status != StatusClosed {
		t.Errorf("停止態該仍能準備目錄配置：%v／%+v", err, got)
	}
	s.env.transition(t, s.manager, s.activity.ID, StatusArchived)
	if _, err := s.env.service.UpdateMemberDirectoryMode(ctx, s.manager, s.activity.ID,
		DirectoryAllMembers, DirectoryHidden, "req-archived"); !errors.Is(err, ErrArchived) {
		t.Errorf("歸檔後的配置寫入該被終態擋下：%v", err)
	}
	// 終態與停止態都不影響讀取：目錄仍列（仍列、可讀的既有口徑）。
	page, err := s.env.service.MemberDirectory(ctx, s.jiaP, s.activity.ID,
		DirectoryMemberQuery{Page: 1, PageSize: 50})
	if err != nil || page.Mode != DirectoryHidden {
		t.Errorf("歸檔後的目錄一讀要如實帶出最後一次生效的配置：%v／%+v", err, page.Mode)
	}
	if len(page.Rows) != 0 {
		t.Errorf("hidden 態在歸檔後依然一份人都沒有：%v", nicknames(page.Rows))
	}
}

// TestDirectoryVisibilityWriteRules 驗收覆蓋的寫入：准入同管理面、業務寫入門禁在此生效、
// 跨活動與併發各得其所、留痕是「管理員對某一行的資料變更」，而且一個字都不動到其他欄。
func TestDirectoryVisibilityWriteRules(t *testing.T) {
	s := newDirScene(t)
	s.setMode(t, DirectoryAllMembers)
	ctx := context.Background()

	memberBefore := s.env.memberFacts(t, s.yi.ID)
	accountBefore := s.env.accountFacts(t, s.yi.AccountID)
	updated, err := s.env.service.UpdateMemberDirectoryVisibility(ctx, s.manager,
		s.activity.ID, s.yi.ID, DirectoryVisibilityHidden, DirectoryVisibilityInherit, "req-hide")
	if err != nil {
		t.Fatalf("收緊覆蓋應成功：%v", err)
	}
	if updated.DirectoryVisibility != DirectoryVisibilityHidden {
		t.Errorf("回應要回顯新值：%s", updated.DirectoryVisibility)
	}
	if after := s.env.memberFacts(t, s.yi.ID); after.nickname != memberBefore.nickname ||
		after.factionID.String != memberBefore.factionID.String ||
		after.accountID != memberBefore.accountID || after.activityID != memberBefore.activityID {
		t.Errorf("改覆蓋不得動到暱稱、歸屬或身份三欄：%+v → %+v", memberBefore, after)
	}
	if after := s.env.accountFacts(t, s.yi.AccountID); after != accountBefore {
		t.Errorf("目錄可見性不是帳戶資料：一個帳戶欄位都不該動\n舊 %s\n新 %s", accountBefore, after)
	}
	row := s.env.latestAuditOf(t, "member.directory_visibility_update",
		s.activity.ID.String())
	if row.actorKind != "admin" || row.actorID != s.manager.AccountID().String() ||
		!strings.Contains(row.changes, "directory_visibility") {
		t.Errorf("留痕要帶管理人身份與前後值：%+v", row)
	}
	if row.targetID != s.yi.ID.String() {
		t.Errorf("留痕的目標是那一行成員，不是活動：%s", row.targetID)
	}

	// 併發：同一依據值的第二次提交拿到可判別的衝突，現值不被覆蓋、也不補第二條痕。
	if _, err := s.env.service.UpdateMemberDirectoryVisibility(ctx, s.manager, s.activity.ID,
		s.yi.ID, DirectoryVisibilityInherit, DirectoryVisibilityInherit, "req-stale"); !errors.Is(err,
		ErrMemberProfileConflict) {
		t.Errorf("依據值已過期該回可判別的衝突：%v", err)
	}
	if got := s.visibilityFacts(t, s.yi.ID); got != "hidden" {
		t.Errorf("落敗的那一筆不得覆蓋贏家，庫裡現值 %q", got)
	}
	if s.env.countAuditRows(t, "member.directory_visibility_update",
		s.activity.ID.String()) != 1 {
		t.Errorf("被拒的編輯不追加審計")
	}
	// 跨活動：拿這一行的標識配別人那場活動的路徑，先撞在那場活動不歸他管上（同樣不可分辨）；
	// 反過來拿別處那一行配他管的活動，則撞在歸屬核實上。兩句對外的話是同一句（1001）。
	if _, err := s.env.service.UpdateMemberDirectoryVisibility(ctx, s.manager, s.other.ID,
		s.yi.ID, DirectoryVisibilityInherit, DirectoryVisibilityHidden, "req-cross-1"); !errors.Is(err,
		ErrActivityNotFound) && !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("外場路徑上的覆蓋寫入該收斂成不可分辨：%v", err)
	}
	if _, err := s.env.service.UpdateMemberDirectoryVisibility(ctx, s.manager, s.activity.ID,
		s.otherRow.ID, DirectoryVisibilityHidden, DirectoryVisibilityInherit,
		"req-cross-2"); !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("拿別處那一行的標識配本場路徑該不可分辨：%v", err)
	}
	if got := s.visibilityFacts(t, s.yi.ID); got != "hidden" {
		t.Errorf("兩次跨活動嘗試一個字都沒落，庫裡現值 %q", got)
	}
	// 普通成員自己改自己的可見性：這條通路屬管理面，他一格都寫不了（不能自我隱藏也不能自我公開）。
	if _, err := s.env.service.UpdateMemberDirectoryVisibility(ctx, s.jiaP, s.activity.ID,
		s.jia.ID, DirectoryVisibilityHidden, DirectoryVisibilityInherit, "req-self"); !errors.Is(err,
		identity.ErrPermissionDenied) {
		t.Errorf("玩家自我收緊或自我放寬都不該走得動：%v", err)
	}
	// 業務寫入門禁在這裡生效：停止態拿到「等重開」那一句。
	s.env.transition(t, s.manager, s.activity.ID, StatusClosed)
	if _, err := s.env.service.UpdateMemberDirectoryVisibility(ctx, s.manager, s.activity.ID,
		s.bing.ID, DirectoryVisibilityHidden, DirectoryVisibilityInherit, "req-closed"); !errors.Is(err,
		ErrActivityClosedWrites) {
		t.Errorf("停止態的覆蓋寫入該撞業務門禁：%v", err)
	}
	// 讀取不受門禁影響：名冊與目錄在停止態仍列（仍列、可讀）。
	// 此處是六行而不是七行：本測試前面把乙收起來了，而覆蓋在停止態一樣生效。
	if page, err := s.env.service.MemberDirectory(ctx, s.jiaP, s.activity.ID,
		DirectoryMemberQuery{Page: 1, PageSize: 50}); err != nil || page.Total != 6 {
		t.Errorf("停止態該照常讀得到目錄（六行，乙仍被覆蓋收著）：%v／%d", err, page.Total)
	}
}

// setFactionAvailable 由管理人翻一個陣營的停用旗標（六欄白名單只動這一欄）。
//
// 依據值取決於本檔自己剛剛翻過幾次，所以這裡按標識現讀那一行再湊編輯輸入：
// 拿場景裡那份舊副本當依據值會撞 2013，而那句話在本測試裡屬干擾而不是結論。
func (s *dirScene) setFactionAvailable(t *testing.T, factionID idgen.ID, want bool) Faction {
	t.Helper()
	rows, err := s.env.service.Factions(context.Background(), s.manager, s.activity.ID)
	if err != nil {
		t.Fatalf("讀取陣營清單失敗：%v", err)
	}
	var current Faction
	for _, row := range rows {
		if row.ID == factionID {
			current = row
		}
	}
	if current.ID.IsNil() {
		t.Fatalf("陣營清單裡讀不到 %s", factionID)
	}
	edit := factionEdit(current, current.Name)
	edit.Available = want
	updated, err := s.env.service.UpdateFaction(context.Background(), s.manager,
		s.activity.ID, factionID, edit, "req-dir-faction-toggle")
	if err != nil {
		t.Fatalf("翻轉陣營 %s 的可用性應成功：%v", factionID, err)
	}
	return updated
}

// rowOf 從一頁目錄裡取某個玩家那一行（讀不到就讓測試停在這裡，不要拿零值繼續斷言）。
func (s *dirScene) rowOf(t *testing.T, p identity.Principal, memberID idgen.ID) DirectoryMember {
	t.Helper()
	for _, row := range s.list(t, p).Rows {
		if row.MemberID == memberID {
			return row
		}
	}
	t.Fatalf("目錄裡讀不到成員 %s 那一行", memberID)
	return DirectoryMember{}
}

// TestDirectoryFactionAvailability 驗收目錄項上那一欄派生值：停用旗標跟著三處讀法
// （目錄、單筆詳情、本人投影）一起出去，而「停用不改變關係語意」意味著可見性不因停用而變——
// 這一欄只是展示事實，不是第二套准入判定（判定只有一處：EnsureFactionAcceptsNewMembers）。
//
// 它刻意不折進活動狀態：停止態下目錄照舊可讀，界面那句「已停用」講的是陣營那一欄本身。
func TestDirectoryFactionAvailability(t *testing.T) {
	ctx := context.Background()
	s := newDirScene(t)
	s.setMode(t, DirectoryAllMembers)

	t.Run("兩隊都開著時三處讀法都讀到真", func(t *testing.T) {
		if row := s.rowOf(t, s.jiaP, s.yi.ID); !row.FactionAvailable {
			t.Errorf("未停用的歸屬該讀到真：%+v", row)
		}
		item, err := s.env.service.DirectoryMemberDetail(ctx, s.jiaP, s.activity.ID, s.yi.ID)
		if err != nil || !item.FactionAvailable {
			t.Errorf("單筆詳情該與列表同一個答案：%v／%+v", err, item)
		}
		view, err := s.env.service.OwnMemberProfile(ctx, s.jiaP, s.activity.ID)
		if err != nil || !view.Item.FactionAvailable {
			t.Errorf("本人投影該讀到真：%v／%+v", err, view.Item)
		}
		// 尚未分組的那一行：這一欄是假，而且名稱也空——界面據此講「尚未分組」而不是「已停用」。
		if row := s.rowOf(t, s.jiaP, s.ding.ID); row.FactionAvailable || row.FactionName != "" ||
			!row.FactionID.IsNil() {
			t.Errorf("無歸屬那行該是假且展示值為空：%+v", row)
		}
	})

	t.Run("停用紅隊只翻那一欄，其他行不受影響", func(t *testing.T) {
		disabled := s.setFactionAvailable(t, s.fac1.ID, false)
		if disabled.Available || disabled.AcceptsNewMembers {
			t.Fatalf("停用後兩者都該是假：available=%v accepts=%v",
				disabled.Available, disabled.AcceptsNewMembers)
		}
		for _, id := range []idgen.ID{s.jia.ID, s.yi.ID, s.guest.ID} {
			row := s.rowOf(t, s.jiaP, id)
			if row.FactionAvailable {
				t.Errorf("紅隊那行（%s）該讀到停用：%+v", id, row)
			}
			if row.FactionName != "紅隊" || row.FactionID != s.fac1.ID {
				t.Errorf("停用不改名稱與歸屬（歷史引用保護）：%+v", row)
			}
		}
		// 藍隊那一行不跟著變：這一欄只屬於被停用的那個陣營。
		if row := s.rowOf(t, s.jiaP, s.bing.ID); !row.FactionAvailable {
			t.Errorf("藍隊那行不該被牽連：%+v", row)
		}
		// 詳情與本人也一起改口：三處讀法共用同一份現讀，不留第二份答案。
		item, err := s.env.service.DirectoryMemberDetail(ctx, s.jiaP, s.activity.ID, s.yi.ID)
		if err != nil || item.FactionAvailable {
			t.Errorf("詳情該讀到停用：%v／%+v", err, item)
		}
		view, err := s.env.service.OwnMemberProfile(ctx, s.jiaP, s.activity.ID)
		if err != nil || view.Item.FactionAvailable {
			t.Errorf("本人投影該讀到停用：%v／%+v", err, view.Item)
		}
	})

	t.Run("停用不撤走任何可見性，也不讓篩選候選消失", func(t *testing.T) {
		// 上面紅隊已被停用：換成僅同陣營態，紅隊三人仍該互見（停用只約束新分配）。
		s.setMode(t, DirectorySameFaction)
		page := s.list(t, s.jiaP)
		if got := nicknames(page.Rows); !equalSets(got, []string{"甲", "乙", "己"}) {
			t.Errorf("停用的陣營裡同隊仍該互見，實際 %v", got)
		}
		if len(page.Facets) != 1 || page.Facets[0].FactionID != s.fac1.ID ||
			page.Facets[0].Count != 3 {
			t.Errorf("停用不該讓候選那一項消失或改計數，實際 %+v", page.Facets)
		}
		// 恢復啟用的下一筆請求就讀到真（這裡沒有快取，也沒有推送可宣稱）。
		restored := s.setFactionAvailable(t, s.fac1.ID, true)
		if !restored.Available {
			t.Fatalf("恢復啟用該翻回真")
		}
		if row := s.rowOf(t, s.jiaP, s.yi.ID); !row.FactionAvailable {
			t.Errorf("恢復後下一筆請求該讀到真：%+v", row)
		}
	})

	t.Run("目錄收成 hidden 時本人仍讀得到自己歸屬的停用旗標", func(t *testing.T) {
		s.setFactionAvailable(t, s.fac1.ID, false)
		s.setMode(t, DirectoryHidden)
		if page := s.list(t, s.jiaP); len(page.Rows) != 0 {
			t.Errorf("hidden 態該是空的一頁，實際 %v", nicknames(page.Rows))
		}
		view, err := s.env.service.OwnMemberProfile(ctx, s.jiaP, s.activity.ID)
		if err != nil {
			t.Fatalf("本人讀法不經目錄判定：%v", err)
		}
		if view.Item.FactionAvailable || view.Activity.MemberDirectoryMode != DirectoryHidden {
			t.Errorf("本人該讀到停用現值與 hidden 模式：%+v／%s", view.Item,
				view.Activity.MemberDirectoryMode)
		}
	})

	// 停止態下這一欄照舊讀得到（它是展示事實，不是門禁）：把活動停下來再讀一次。
	s.setFactionAvailable(t, s.fac1.ID, true)
	s.env.transition(t, s.manager, s.activity.ID, StatusClosed)
	view, err := s.env.service.OwnMemberProfile(ctx, s.jiaP, s.activity.ID)
	if err != nil {
		t.Fatalf("停止態的本人讀法應成功：%v", err)
	}
	if !view.Item.FactionAvailable {
		t.Errorf("這一欄不折進活動狀態：停止態下紅隊仍該讀到真：%+v", view.Item)
	}
}

// equalSets 逐字比較兩個字串集合（先各自排序，於斷言只問「有哪些人」而不依賴行序）。
func equalSets(got, want []string) bool {
	a, b := append([]string(nil), got...), append([]string(nil), want...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// dedupe 回傳去重後的清單（分頁不重不漏那句斷言的輔助）。
func dedupe(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// contains 回報清單裡是否有那一個。
func contains(rows []string, want string) bool {
	for _, row := range rows {
		if row == want {
			return true
		}
	}
	return false
}

// listErr 送一次預期失敗的目錄請求。
func (s *dirScene) listErr(p identity.Principal, query DirectoryMemberQuery) error {
	_, err := s.env.service.MemberDirectory(context.Background(), p, s.activity.ID, query)
	return err
}
