// bindpreflight_test.go 是「訪戶綁定預檢與衝突預覽」用例層的定向證據：
// 本步要求驗的每一件都在真庫上量過——合法候選（executable 為真且影響清單齊備）、
// 目標是特權帳戶（收斂成與幽靈同形的「不在目錄」，預覽不是新的枚舉面）、
// 同源自同一對、已轉正／停用／刪除的兩側形態、未知引用整體阻止且卸表後放行、
// 來源被授予被外部改壞時的保守方向，以及「預檢不改變帳戶、會話、歸屬或資產」的
// 全表快照對照與「連一筆安全審計都不寫」的零審計斷言（用戶批准：純只讀、零寫入）。
//
// 全程使用本次專屬的暫存庫與注入時鐘：不佔 5206、不碰任何真實資料目錄。
package stdacct

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// blockerLine 把阻止原因序列成可比對的一行字（斷言順序穩定性用的形態）。
func blockerLine(bs []BindBlocker) string {
	parts := make([]string, 0, len(bs))
	for _, b := range bs {
		parts = append(parts, b.String())
	}
	return strings.Join(parts, ",")
}

// countQuery 取一條 COUNT(*) 查詢的數值（測試取證用，不參與任何生產判定）。
func countQuery(t *testing.T, e *env, query string, args ...any) int {
	t.Helper()
	var n int
	if err := e.db.SQL().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("計數查詢失敗（%s）：%v", query, err)
	}
	return n
}

// assertNoMutation 對照四張受本步關心的表：帳戶行、會話撤銷標記、授予、Root 域審計。
// 「必要安全審計不算業務綁定」在這裡走的是更保守的用戶批准形態——連審計都不寫，
// 所以 root_audit 的行數也必須逐字不動（本檔用例全部從零審計的現場開始）。
func assertNoMutation(t *testing.T, e *env, guest, target account.Account,
	guestRow, targetRow string) {
	t.Helper()
	if got := rowSnapshot(t, e, guest.ID); got != guestRow {
		t.Errorf("預檢動了來源帳戶一行：变更前 %s／實際 %s", guestRow, got)
	}
	if got := rowSnapshot(t, e, target.ID); got != targetRow {
		t.Errorf("預檢動了目標帳戶一行：变更前 %s／實際 %s", targetRow, got)
	}
	if got := countQuery(t, e, "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NOT NULL"); got != 0 {
		t.Errorf("預檢不得撤銷任何會話：期望 revoked 行數 0，實際 %d", got)
	}
	if got := countRows(t, e.db, "account_server_roles"); got != 0 {
		t.Errorf("預檢不得改動授予：期望 0 行，實際 %d", got)
	}
	if got := countRows(t, e.db, "root_audit"); got != 0 {
		t.Errorf("預檢是純只讀（用戶批准零寫入），root_audit 不得多出一筆，實際 %d 筆", got)
	}
}

// TestBindPreflightHappyPathAndZeroMutation 合法候選：訪戶＋可登入、普通＋可登入、
// 無未知引用——executable 為真、阻止清空、五條影響齊備、源會話計數與 schema 版本
// 如實報出；跑完一趟，四張表一個字都沒動，連一筆審計都不寫。
func TestBindPreflightHappyPathAndZeroMutation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := e.seed(t, seedInput{Login: "guest_to_bind", Display: "待綁旅人",
		Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "Already.Real", Display: "正式受體"})
	seedGuestSessions(t, e, guest.ID, 2)

	guestRow, targetRow := rowSnapshot(t, e, guest.ID), rowSnapshot(t, e, target.ID)
	auditsBefore := countRows(t, e.db, "root_audit")
	if auditsBefore != 0 {
		t.Fatalf("本用例要從零審計現場開始（seed 不寫審計），實際已有 %d 筆", auditsBefore)
	}

	pre, err := e.service.PreflightGuestBind(ctx, admin, guest.ID, target.ID, "req-ok")
	if err != nil {
		t.Fatalf("合法候選的預檢不應失敗：%v", err)
	}
	if !pre.Executable {
		t.Errorf("合法候選應可執行，實際 blockers=%v", blockerLine(pre.Blockers))
	}
	if len(pre.Blockers) != 0 {
		t.Errorf("可執行時阻止應為空，實際 %v", blockerLine(pre.Blockers))
	}
	if len(pre.Impacts) != 5 {
		t.Errorf("可執行時五條影響應齊備，實際 %v", pre.Impacts)
	}
	if pre.SourceOpenSessions != 2 {
		t.Errorf("源未撤銷會話應報 2，實際 %d", pre.SourceOpenSessions)
	}
	wantVersion, err := migrate.Current(ctx, e.db.SQL())
	if err != nil {
		t.Fatalf("讀基準版本失敗：%v", err)
	}
	if pre.SchemaVersion != wantVersion {
		t.Errorf("資料版本應與 migrate.Current 一致，基準 %d／回應 %d", wantVersion, pre.SchemaVersion)
	}
	if pre.ConsentMode != BindConsentModeTargetSelfInitiated {
		t.Errorf("同意形態應恆為目標端自助发起，實際 %q", pre.ConsentMode)
	}
	if pre.Source.AccountID != guest.ID || pre.Source.Type != account.TypeGuest {
		t.Errorf("來源投影應是該訪戶本人，實際 %+v", pre.Source)
	}
	if pre.Target.AccountID != target.ID || pre.Target.Type != account.TypeStandard {
		t.Errorf("目標投影應是該普通帳戶本人，實際 %+v", pre.Target)
	}

	assertNoMutation(t, e, guest, target, guestRow, targetRow)
	if logs := e.logs.String(); strings.Contains(logs, "account.guest_bind") {
		t.Error("本步沒有綁定執行，日誌裡不該出現綁定落地句")
	}
}

// TestBindPreflightPrivilegedTargetConvergesToNotFound 目標持有伺服器級授予時，
// 預檢的回答與「幽靈標識」逐字同形（ErrAccountNotFound）：這條通路不是替目錄
// 探照管理員存在與否的第二枚信號。來源側同判（管理員不是綁定的合法來源，
// 也收進同一句）。
func TestBindPreflightPrivilegedTargetConvergesToNotFound(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := e.seed(t, seedInput{Login: "guest_probe", Display: "probe 旅人",
		Type: account.TypeGuest})
	privileged := e.seed(t, seedInput{Login: "Console.Admin", Display: "持授予者", Admin: true})
	ghostID, err := idgen.New()
	if err != nil {
		t.Fatalf("產生幽靈標識失敗：%v", err)
	}

	_, errTarget := e.service.PreflightGuestBind(ctx, admin, guest.ID, privileged.ID, "req-t")
	_, errGhost := e.service.PreflightGuestBind(ctx, admin, guest.ID, ghostID, "req-g")
	for name, err := range map[string]error{"特權目標": errTarget, "幽靈目標": errGhost} {
		if !errors.Is(err, ErrAccountNotFound) {
			t.Errorf("%s 應收斂成不可分辨的「不在目錄」，實際 %v", name, err)
		}
	}
	// 來源是持授予者：同一句話——本目錄對三種出局形態從來只有一個答案。
	if _, err := e.service.PreflightGuestBind(ctx, admin, privileged.ID, guest.ID, "req-s"); !errors.Is(err, ErrAccountNotFound) {
		t.Errorf("持授予者作來源也應收斂成同一句，實際 %v", err)
	}
	// 對照：目錄內的標識即使形態明顯不合，回應也是「預覽＋原因」而不是 1001——
	// 「查得到的有問題的人」與「查不着的人」各說各話（後者才是上面同句收斂的對象）。
	pre, err := e.service.PreflightGuestBind(ctx, admin, guest.ID, guest.ID, "req-self")
	if err != nil {
		t.Fatalf("訪戶作目標是目錄內事實，預檢應成功返回預覽：%v", err)
	}
	if blockerLine(pre.Blockers) != string(BindBlockerSameAccount) {
		t.Errorf("同對短路應只剩一條原因，實際 %q", blockerLine(pre.Blockers))
	}
}

// TestBindPreflightShapeBlockers 兩側形態的每條出局句各自的結論，以及多因並列時的
// 穩定順序：來源側先於目標側、引用掃描最後。順序不穩，界面就沒法逐條點名。
func TestBindPreflightShapeBlockers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := e.seed(t, seedInput{Login: "guest_shapes", Display: "形態旅人",
		Type: account.TypeGuest})
	upgraded := e.seed(t, seedInput{Login: "Was.Guest.Now.Standard", Display: "已轉正"})
	disabledGuest := e.seed(t, seedInput{Login: "guest_dim", Display: "停用旅人",
		Type: account.TypeGuest, Status: account.StatusDisabled})
	target := e.seed(t, seedInput{Login: "Bound.Target", Display: "受體"})
	disabledTarget := e.seed(t, seedInput{Login: "Bound.Target.Off", Display: "停用受體",
		Status: account.StatusDisabled})

	cases := []struct {
		name            string
		source, target  account.Account
		wantBlockerLine string
	}{
		{"已轉正的來源", upgraded, target, string(BindBlockerSourceNotGuest)},
		{"停用中的來源", disabledGuest, target, string(BindBlockerSourceNotActive)},
		{"訪戶作目標", guest, guest, string(BindBlockerSameAccount)}, // 同對短路優先
		{"停用中的目標", guest, disabledTarget, string(BindBlockerTargetNotActive)},
	}
	for _, c := range cases {
		pre, err := e.service.PreflightGuestBind(ctx, admin, c.source.ID, c.target.ID, "req-shape")
		if err != nil {
			t.Errorf("%s：預檢不應失敗：%v", c.name, err)
			continue
		}
		if pre.Executable {
			t.Errorf("%s：應被阻止而 executable 仍為真", c.name)
		}
		if blockerLine(pre.Blockers) != c.wantBlockerLine {
			t.Errorf("%s：阻止原因應為 %q，實際 %q", c.name, c.wantBlockerLine, blockerLine(pre.Blockers))
		}
		if len(pre.Impacts) != 0 {
			t.Errorf("%s：被阻止的綁定沒有任何將產生的影響，實際 %v", c.name, pre.Impacts)
		}
	}
	// 「訪戶作目標」在非同對時才是那条句子：拿 disabledGuest 當來源、guest 當目標，
	// 兩側原因並列且順序穩定（來源側先、目標側後）。
	pre, err := e.service.PreflightGuestBind(ctx, admin, disabledGuest.ID, guest.ID, "req-both")
	if err != nil {
		t.Fatalf("兩側皆目錄內形態，預檢應成功：%v", err)
	}
	want := string(BindBlockerSourceNotActive) + "," + string(BindBlockerTargetNotStandard)
	if blockerLine(pre.Blockers) != want {
		t.Errorf("並列原因應為 %q，實際 %q", want, blockerLine(pre.Blockers))
	}
}

// TestBindPreflightUnknownReferenceBlocksThenReleases 未知引用的完整閉環：
// 種一筆真實未來形態——新表帶外鍵指向 accounts(id) 並持有該訪戶的行——
// 預檢整體收斂成 unknown_references（表名不進結論、只進執行日誌）；
// 卸掉那張表後重新預檢又放行。這條钉子就是「未來模組未接入預檢前不得綁定」的證據。
func TestBindPreflightUnknownReferenceBlocksThenReleases(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := e.seed(t, seedInput{Login: "guest_future_ref", Display: "承載未來旅人",
		Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "Future.Host", Display: "受體"})

	if _, err := e.db.SQL().ExecContext(ctx,
		`CREATE TABLE probe_activity_members (
		    account_id TEXT NOT NULL REFERENCES accounts (id),
		    joined_at  INTEGER NOT NULL)`); err != nil {
		t.Fatalf("種入未來引用表失敗：%v", err)
	}
	if _, err := e.db.SQL().ExecContext(ctx,
		`INSERT INTO probe_activity_members (account_id, joined_at) VALUES (?, ?)`,
		guest.ID.String(), 1); err != nil {
		t.Fatalf("種入未來引用行失敗：%v", err)
	}

	pre, err := e.service.PreflightGuestBind(ctx, admin, guest.ID, target.ID, "req-unknown")
	if err != nil {
		t.Fatalf("未知引用是預覽裡的原因而不是預檢失敗：%v", err)
	}
	if pre.Executable {
		t.Error("存在未登记的帳戶引用時必須整體阻止")
	}
	if blockerLine(pre.Blockers) != string(BindBlockerUnknownReferences) {
		t.Errorf("阻止原因應只有 unknown_references，實際 %q", blockerLine(pre.Blockers))
	}
	if strings.Contains(errBlockerDump(pre), "probe_activity_members") {
		t.Error("未接入的表名不該出現在任何結論值裡（只准進執行日誌）")
	}
	if !strings.Contains(e.logs.String(), "probe_activity_members") {
		t.Error("表名應進執行日誌，供運維查明是哪張未接入的表")
	}

	if _, err := e.db.SQL().ExecContext(ctx, `DROP TABLE probe_activity_members`); err != nil {
		t.Fatalf("卸除未來引用表失敗：%v", err)
	}
	again, err := e.service.PreflightGuestBind(ctx, admin, guest.ID, target.ID, "req-release")
	if err != nil {
		t.Fatalf("卸表後重新預檢不應失敗：%v", err)
	}
	if !again.Executable || len(again.Blockers) != 0 {
		t.Errorf("引用消失後應重新放行，實際 executable=%v blockers=%v",
			again.Executable, blockerLine(again.Blockers))
	}
}

// errBlockerDump 把預覽結論整體拼成一行（僅供「表名不泄漏」斷言用）。
func errBlockerDump(pre GuestBindPreflight) string {
	var b strings.Builder
	b.WriteString(blockerLine(pre.Blockers))
	for _, i := range pre.Impacts {
		b.WriteString("|" + string(i))
	}
	b.WriteString("|" + pre.ConsentMode)
	return b.String()
}

// TestBindPreflightExternalGrantTamperingFailClosed 外部工具繞過遷移觸發器給訪戶
// 塞了授予時，保守方向釘死：server_admin 行讓來源收進「不在目錄」那句（readStandardProfile
// 對持授予者本來就只有一個答案，與停用／重置／升級同句），而不是多發一枚
// 「他身上有授予」的新信號；現行 CHECK（role IN ('server_admin')）之下壞角色值
// 根本寫不進去，故 source_has_grants 記號要等角色封閉集合擴大後才可達——它與
// Roles() 的復核一同留在那一天接住形態缺陷，今天的证据就是這個方向本身。
func TestBindPreflightExternalGrantTamperingFailClosed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := e.seed(t, seedInput{Login: "guest_tampered", Display: "被改壞旅人",
		Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "Tamper.Host", Display: "受體"})

	// 只有外部握著資料庫把防呆觸發器拆了才走得到這裡；預檢的職責是把那種现场的
	// 處置方向釘住，而不是假裝它不存在。
	if _, err := e.db.SQL().ExecContext(ctx, `DROP TRIGGER account_server_roles_guest_no_role`); err != nil {
		t.Fatalf("移除測試觸發器失敗：%v", err)
	}
	if _, err := e.db.SQL().ExecContext(ctx,
		`INSERT INTO account_server_roles (account_id, role, granted_at) VALUES (?, 'server_admin', ?)`,
		guest.ID.String(), 1); err != nil {
		t.Fatalf("種入被改壞的授予失敗：%v", err)
	}
	if _, err := e.service.PreflightGuestBind(ctx, admin, guest.ID, target.ID, "req-tamper"); !errors.Is(err, ErrAccountNotFound) {
		t.Errorf("持 server_admin 的來源應收進「不在目錄」同句，實際 %v", err)
	}

	// CHECK 擋著封閉集合外的值：壞角色行在資料庫層就寫不進去，
	// 「讀不出授予」的缺陷形態因此不可能從這條通路流入預覽。
	if _, err := e.db.SQL().ExecContext(ctx,
		`INSERT INTO account_server_roles (account_id, role, granted_at) VALUES (?, 'ghost_role', ?)`,
		guest.ID.String(), 2); err == nil {
		t.Error("現行 CHECK 之下壞角色值本該被資料庫當場拒寫——用例前提若變，這裡要重寫")
	}

	// 清掉那筆外部塞入的授予後，同一對重新預檢應回到放行：預檢判的是此刻的事實，
	// 不是給任何一筆歷史行蓋章。
	if _, err := e.db.SQL().ExecContext(ctx,
		`DELETE FROM account_server_roles WHERE account_id = ?`, guest.ID.String()); err != nil {
		t.Fatalf("清掉授予行失敗：%v", err)
	}
	again, err := e.service.PreflightGuestBind(ctx, admin, guest.ID, target.ID, "req-release2")
	if err != nil {
		t.Fatalf("清掉授予後重新預檢不應失敗：%v", err)
	}
	if !again.Executable || len(again.Blockers) != 0 {
		t.Errorf("授予清空後應重新放行，實際 executable=%v blockers=%v",
			again.Executable, blockerLine(again.Blockers))
	}
}

// TestBindPreflightAuthorizationMatrix 四類非管理主體全部被拒在授權那一跳：
// 訪戶本人、普通帳戶、系統主體、匿名——不消耗任何資料庫讀取、不寫審計、不改一行。
// 「訪戶不能替自己安排綁定」與升級同一事實（零授予過不了 NeedServerAdmin）。
func TestBindPreflightAuthorizationMatrix(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	guest := e.seed(t, seedInput{Login: "guest_actor", Display: "想自綁旅人",
		Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "No.Pry", Display: "被探者"})
	guestRow, targetRow := rowSnapshot(t, e, guest.ID), rowSnapshot(t, e, target.ID)

	cases := map[string]identity.Principal{
		"訪戶本人": identitytest.Account(t, guest.ID, identitytest.WithGuestType()),
		"普通帳戶": identitytest.Account(t, identitytest.NewID(t)),
		"系統主體": identitytest.System(t, identity.OriginCLI),
		"匿名主體": identity.Anonymous(),
	}
	for name, principal := range cases {
		_, err := e.service.PreflightGuestBind(ctx, principal, guest.ID, target.ID, "req-deny")
		if !errors.Is(err, identity.ErrPermissionDenied) && !errors.Is(err, identity.ErrNotAuthenticated) {
			t.Errorf("%s 做綁定預檢應被拒為權限/身分錯誤，實際 %v", name, err)
		}
	}
	if got := rowSnapshot(t, e, guest.ID); got != guestRow {
		t.Errorf("被拒的預檢動了來源一行：变更前 %s／實際 %s", guestRow, got)
	}
	if got := rowSnapshot(t, e, target.ID); got != targetRow {
		t.Errorf("被拒的預檢動了目標一行：变更前 %s／實際 %s", targetRow, got)
	}
	if n := countRows(t, e.db, "root_audit"); n != 0 {
		t.Errorf("被拒的預檢不得寫審計，實際 %d 筆", n)
	}
}

// TestBindPreflightNilGhostAndDeleted 零值標識、幽靈與刪除終態在兩側都是同一句
// 「不在目錄」；來源與目標各自独立成句，不洩漏「差哪一半」。
func TestBindPreflightNilGhostAndDeleted(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := e.seed(t, seedInput{Login: "guest_nil_probe", Display: "幽靈probe旅人",
		Type: account.TypeGuest})
	deleted := e.seed(t, seedInput{Login: "guest_gone2", Display: "已刪旅人",
		Type: account.TypeGuest, Deleted: true})
	ghostID, err := idgen.New()
	if err != nil {
		t.Fatalf("產生幽靈標識失敗：%v", err)
	}

	probes := [][2]idgen.ID{
		{idgen.ID{}, guest.ID}, {guest.ID, idgen.ID{}},
		{ghostID, guest.ID}, {guest.ID, ghostID},
		{deleted.ID, guest.ID}, {guest.ID, deleted.ID},
	}
	for i, pair := range probes {
		if _, err := e.service.PreflightGuestBind(ctx, admin, pair[0], pair[1], "req-nil"); !errors.Is(err, ErrAccountNotFound) {
			t.Errorf("第 %d 組零值/幽靈/刪除探測應收斂成「不在目錄」，實際 %v", i+1, err)
		}
	}
}

// TestBindPreflightSessionCountUsesRevokeScale 源會話計數與 RevokeAccount 同尺：
// 已到期但尚未標記撤銷的行照樣計入（「綁定將讓 N 臺裝置重新登入」的 N 是
// 「會被打上撤銷標記的行」，不是「此刻還換得出身分的行」——兩句話在執行落庫時
// 會以同一個 RevokeAccount 數收口，預覽必須按那把尺報）。
func TestBindPreflightSessionCountUsesRevokeScale(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := e.seed(t, seedInput{Login: "guest_stale", Display: "過期仍計旅人",
		Type: account.TypeGuest})
	target := e.seed(t, seedInput{Login: "Scale.Host", Display: "受體"})
	seedGuestSessions(t, e, guest.ID, 2)

	// 把注入時鐘推過會話絕對期限：行還未撤銷，只是換不出身份了。
	e.clock.Advance(2 * time.Hour)
	pre, err := e.service.PreflightGuestBind(ctx, admin, guest.ID, target.ID, "req-scale")
	if err != nil {
		t.Fatalf("預檢不應失敗：%v", err)
	}
	if pre.SourceOpenSessions != 2 {
		t.Errorf("未標記撤銷的行必須按 RevokeAccount 同尺計入，期望 2 實際 %d",
			pre.SourceOpenSessions)
	}
	if !pre.Executable {
		t.Errorf("過期行不應阻止綁定本身，實際 blockers=%v", blockerLine(pre.Blockers))
	}
}
