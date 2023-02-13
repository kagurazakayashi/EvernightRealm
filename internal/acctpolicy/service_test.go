// service_test.go 是帳戶建立策略用例的證據：只有 Root 讀得到與改得了、三個值一次寫入
// 且彼此獨立、尚未開放的模式一律拒、改動與審計同生同滅、重開程序後讀回同一份策略，
// 以及對外入口那個答案在通路未落地時恆為關。
//
// 這裡取的證刻意都落在「資料庫裡現在是什麼」與「root_audit 裡多了幾筆」上，
// 而不是回傳值本身：一次聲稱成功卻沒落地、或一次落地卻沒留痕的變更，
// 都是這個功能最壞的缺陷形態，而兩者都只有直接問庫才看得見。
package acctpolicy

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// testBase 為注入時鐘的錨點（與其餘套件同一取向：時刻斷言要有固定值可比）。
var testBase = time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)

// env 是一次測試的完整現場：本次專屬的暫存庫、注入時鐘，與組好的策略用例。
type env struct {
	db      *database.DB
	path    string
	clock   *timeutil.Test
	audit   *audit.Store
	store   *Store
	service *Service
}

// newEnv 建立現場。策略用例不需要憑據參數檔，因此這裡沒有 credential 的痕跡。
func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "evernight.db")
	t.Cleanup(func() {
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			t.Errorf("暫存目錄清理失敗（殘留：%s）：%v", dir, err)
		}
	})
	db, err := database.Open(context.Background(), database.Options{
		Path:        path,
		BusyTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := timeutil.NewTest(testBase)
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: clock}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	auditStore := audit.NewStore(clock)
	store := NewStore(clock)
	service, err := New(Deps{DB: db, Store: store, Audits: auditStore})
	if err != nil {
		t.Fatalf("建立策略用例失敗：%v", err)
	}
	return &env{db: db, path: path, clock: clock, audit: auditStore, store: store, service: service}
}

// root 回傳一個可信的 Root 主體（來源為 HTTP 請求，與端點解析出的主體同形）。
func root(t *testing.T) identity.Principal {
	t.Helper()
	return identitytest.Root(t, identity.OriginHTTPRequest)
}

// readRow 直接問庫裡的三個值與時刻（測試取證用，不參與任何生產判定）。
func readRow(t *testing.T, db *database.DB) (admin int, mode string, guest int, updatedAt int64) {
	t.Helper()
	err := db.SQL().QueryRowContext(context.Background(),
		`SELECT admin_create_standard, self_register_mode, guest_enabled, updated_at
		   FROM account_creation_policy WHERE id = 1`).
		Scan(&admin, &mode, &guest, &updatedAt)
	if err != nil {
		t.Fatalf("讀取策略行失敗：%v", err)
	}
	return admin, mode, guest, updatedAt
}

// auditRows 回傳 root_audit 的 (action, target_kind, changes_json, reason) 四欄。
func auditRows(t *testing.T, db *database.DB) []struct{ Action, Target, Changes, Reason string } {
	t.Helper()
	rows, err := db.SQL().QueryContext(context.Background(),
		`SELECT action, target_kind, changes_json, COALESCE(reason, '') FROM root_audit ORDER BY created_at, id`)
	if err != nil {
		t.Fatalf("讀取審計失敗：%v", err)
	}
	defer rows.Close()
	var out []struct{ Action, Target, Changes, Reason string }
	for rows.Next() {
		var item struct{ Action, Target, Changes, Reason string }
		if err := rows.Scan(&item.Action, &item.Target, &item.Changes, &item.Reason); err != nil {
			t.Fatalf("掃描審計列失敗：%v", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("讀取審計失敗：%v", err)
	}
	return out
}

// inputOf 產生一份完整的請求本體（三個欄位一個都不缺）。
func inputOf(admin bool, mode string, guest bool) Input {
	return Input{AdminCreateStandard: admin, SelfRegisterMode: mode, GuestEnabled: guest}
}

// TestPolicyReadsStrictDefault 驗證用例讀到的是遷移種下的出廠值，而不是任何憑空補的預設。
func TestPolicyReadsStrictDefault(t *testing.T) {
	e := newEnv(t)
	policy, err := e.service.Policy(context.Background(), root(t))
	if err != nil {
		t.Fatalf("Root 現讀策略應成功：%v", err)
	}
	if policy.AdminCreateStandard || policy.GuestEnabled || policy.SelfRegisterMode != ModeClosed {
		t.Errorf("出廠策略應為全關＋closed，實際 %+v", policy)
	}
	if !policy.UpdatedAt.IsZero() {
		t.Errorf("出廠行的從未被改寫應換成零值時刻，實際 %v", policy.UpdatedAt)
	}
}

// TestOnlyRootMayTouchPolicy 驗證非 Root 的主體讀不到也改不了這份伺服器策略。
//
// 同級管理員那一筆尤其重要：「管理員能不能改伺服器策略」不是任何一欄開關的意思，
// 而 admin_create_standard 講的是他能不能建普通帳戶——把兩者混起來的結局是
// 關掉一個開關就順便把管理員的管理員資格也拿了。
func TestOnlyRootMayTouchPolicy(t *testing.T) {
	e := newEnv(t)
	standard := identitytest.Account(t, identitytest.NewID(t))
	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	guest := identitytest.Account(t, identitytest.NewID(t), identitytest.WithGuestType())
	system := identitytest.System(t, identity.OriginCLI)
	anonymous := identitytest.Anonymous(t)

	before := len(auditRows(t, e.db))
	// 匿名是「根本沒有可信主體」，其餘是「主體可信但沒有這個權限」：兩句結論不同，
	// 但對本用例而言都是完全不發生。傳輸層在更早的地方就把匿名擋掉了（2002），
	// 這裡仍要斷言一次，是因為「少判一層」不該只靠傳輸層的自律。
	cases := []struct {
		name      string
		principal identity.Principal
		wantErr   error
	}{
		{"普通帳戶", standard, ErrPermissionDenied},
		{"同級管理員", admin, ErrPermissionDenied},
		{"訪客帳戶", guest, ErrPermissionDenied},
		{"系統主體", system, ErrPermissionDenied},
		{"匿名", anonymous, identity.ErrNotAuthenticated},
	}
	for _, tc := range cases {
		if _, err := e.service.Policy(context.Background(), tc.principal); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s：現讀策略應被拒（%v），實際 %v", tc.name, tc.wantErr, err)
		}
		if _, err := e.service.UpdatePolicy(context.Background(), tc.principal,
			inputOf(true, "open", true), "req"); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s：變更策略應被拒（%v），實際 %v", tc.name, tc.wantErr, err)
		}
	}
	admin2, mode2, guest2, updatedAt := readRow(t, e.db)
	if admin2 != 0 || mode2 != "closed" || guest2 != 0 || updatedAt != 0 {
		t.Errorf("被拒的讀寫不應改動任何值，實際 %d/%q/%d/%d", admin2, mode2, guest2, updatedAt)
	}
	if got := len(auditRows(t, e.db)); got != before {
		t.Errorf("被拒的讀寫不應追加審計，實際從 %d 筆變成 %d 筆", before, got)
	}
}

// TestUpdateWritesValuesAndAudit 驗證一次成功變更的三件事：值落地、時刻取自注入時鐘、
// 審計帶著前後值且不含任何憑據材料。
func TestUpdateWritesValuesAndAudit(t *testing.T) {
	e := newEnv(t)
	updated, err := e.service.UpdatePolicy(context.Background(), root(t),
		inputOf(true, "open", false), "0192f0c4-1c9a-7000-8000-0000000000aa")
	if err != nil {
		t.Fatalf("Root 變更策略應成功：%v", err)
	}
	if !updated.AdminCreateStandard || updated.SelfRegisterMode != ModeOpen || updated.GuestEnabled {
		t.Fatalf("回傳應是落庫後的現值，實際 %+v", updated)
	}
	if got := updated.UpdatedAt.UTC().Format(time.RFC3339Nano); got != testBase.Format(time.RFC3339Nano) {
		t.Errorf("updated_at 應取自注入時鐘（%v），實際 %v", testBase, got)
	}

	adminRow, modeRow, guestRow, updatedAt := readRow(t, e.db)
	if adminRow != 1 || modeRow != "open" || guestRow != 0 {
		t.Errorf("庫裡應寫入 1/open/0，實際 %d/%q/%d", adminRow, modeRow, guestRow)
	}
	if want := timeutil.ToMillis(testBase); updatedAt != want {
		t.Errorf("庫裡時刻應為 %d，實際 %d", want, updatedAt)
	}

	recs := auditRows(t, e.db)
	if len(recs) != 1 {
		t.Fatalf("一次成功變更應恰好一筆審計，實際 %d 筆", len(recs))
	}
	rec := recs[0]
	if rec.Action != "server.account_policy_update" || rec.Target != "account_creation_policy" {
		t.Errorf("審計動作與目標名詞應為穩定機器碼，實際 %q/%q", rec.Action, rec.Target)
	}
	// 前後值都要查得到：admin_create_standard 與 self_register_mode 兩欄有差，
	// guest_enabled 兩側同值，因此不進 Changes（否則日後無法區分「哪一次真的動過」）。
	for _, want := range []string{`"admin_create_standard"`, `"self_register_mode"`, "false", "true", "closed", "open"} {
		if !strings.Contains(rec.Changes, want) {
			t.Errorf("審計摘要應含 %q，實際 %s", want, rec.Changes)
		}
	}
	if strings.Contains(rec.Changes, "guest_enabled") {
		t.Errorf("沒變化的欄位不该進變更摘要，實際 %s", rec.Changes)
	}
	for _, forbidden := range []string{"password", "argon2id", "token", "cookie", "hash"} {
		if strings.Contains(strings.ToLower(rec.Changes+rec.Reason), forbidden) {
			t.Errorf("審計不得含憑據材料（命中 %q）：%s / %s", forbidden, rec.Changes, rec.Reason)
		}
	}
}

// TestSwitchesIndependent 驗證改一欄永遠不影響另外兩欄。
//
// 這正是整份 PUT 的風險點：實作若把三個值當成一個結構去「重建」，
// 只改模式的請求就會把另外兩欄默默歸零。斷言取的是庫裡的事實。
func TestSwitchesIndependent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.service.UpdatePolicy(ctx, root(t), inputOf(true, "closed", true), "req-1"); err != nil {
		t.Fatalf("前置建立失敗：%v", err)
	}
	if _, err := e.service.UpdatePolicy(ctx, root(t), inputOf(true, "open", true), "req-2"); err != nil {
		t.Fatalf("只改模式的請求應成功：%v", err)
	}
	adminRow, modeRow, guestRow, _ := readRow(t, e.db)
	if adminRow != 1 || modeRow != "open" || guestRow != 1 {
		t.Errorf("兩個開關應保持原樣，實際 %d/%q/%d", adminRow, modeRow, guestRow)
	}

	// 反向確認：只關掉訪客，模式與管理員建號不受影響。
	if _, err := e.service.UpdatePolicy(ctx, root(t), inputOf(true, "open", false), "req-3"); err != nil {
		t.Fatalf("只改訪客的請求應成功：%v", err)
	}
	adminRow, modeRow, guestRow, _ = readRow(t, e.db)
	if adminRow != 1 || modeRow != "open" || guestRow != 0 {
		t.Errorf("模式與建號開關應保持 open/1，實際 %d/%q/%d", adminRow, modeRow, guestRow)
	}
}

// TestRepeatedSaveIsAnotherConfirmation 驗證重複保存不是錯誤，而是「又確認一次」。
//
// 與 R2-004 的憑據重置同一取向：整份 PUT 沒有依據值，因此第二次不衝突；
// 但它仍會蓋上時刻並留下一筆「沒有欄位變化」的審計，界面據此不得自動補發。
func TestRepeatedSaveIsAnotherConfirmation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	body := inputOf(false, "open", true)
	if _, err := e.service.UpdatePolicy(ctx, root(t), body, "req-a"); err != nil {
		t.Fatalf("第一次保存應成功：%v", err)
	}
	e.clock.Advance(time.Minute)
	if _, err := e.service.UpdatePolicy(ctx, root(t), body, "req-b"); err != nil {
		t.Fatalf("重複保存應成功（它不是一次衝突）：%v", err)
	}
	adminRow, modeRow, guestRow, updatedAt := readRow(t, e.db)
	if adminRow != 0 || modeRow != "open" || guestRow != 1 {
		t.Errorf("重複保存不应改動值，實際 %d/%q/%d", adminRow, modeRow, guestRow)
	}
	if want := timeutil.ToMillis(testBase.Add(time.Minute)); updatedAt != want {
		t.Errorf("重複保存應蓋上新時刻（%d），實際 %d", want, updatedAt)
	}
	recs := auditRows(t, e.db)
	if len(recs) != 2 {
		t.Fatalf("兩次保存應各留一筆審計，實際 %d 筆", len(recs))
	}
	if recs[1].Changes != "[]" {
		t.Errorf("第二次沒有欄位差量，摘要應恰好是空陣列，實際 %s", recs[1].Changes)
	}
}

// TestUnapprovedModeRejected 驗證已批准但通路未落地的模式寫不進去，且零副作用。
//
// 這一組現在只剩 invite：approval 的申請與本人查狀態已經落地（R2-012），
// 它從「名字批准了但執行不了」搬到「寫得進去」那一側，由下一個測試釘住。
// 留在這裡的斷言對象沒變——一個本版本執行不了的模式不該被記成伺服器的現值，
// 而且拒絕不留下任何痕跡（既不改策略也不追加審計）。
func TestUnapprovedModeRejected(t *testing.T) {
	e := newEnv(t)
	beforeAdmin, beforeMode, beforeGuest, beforeUpdatedAt := readRow(t, e.db)
	auditBefore := len(auditRows(t, e.db))

	for _, mode := range []string{"invite"} {
		_, err := e.service.UpdatePolicy(context.Background(), root(t), inputOf(true, mode, true), "req")
		if !errors.Is(err, ErrModeUnavailable) {
			t.Errorf("模式 %q 應被拒（ErrModeUnavailable），實際 %v", mode, err)
		}
	}
	admin, m2, guest, updatedAt := readRow(t, e.db)
	if admin != beforeAdmin || m2 != beforeMode || guest != beforeGuest || updatedAt != beforeUpdatedAt {
		t.Errorf("被拒的寫入不應改動策略，實際 %d/%q/%d/%d", admin, m2, guest, updatedAt)
	}
	if got := len(auditRows(t, e.db)); got != auditBefore {
		t.Errorf("被拒的寫入不應追加審計，實際從 %d 筆變成 %d 筆", auditBefore, got)
	}
}

// TestApprovalModeIsWritable 驗證 approval 現在寫得進去，而且落地後合成把「待審批」如實說。
//
// 這一條釘的是通路登記翻真之後的兩側同時對：
//   - Root 能把模式設成 approval，同交易追加一筆審計（前後值都是被批准的那個名字）；
//   - 讀回的策略 AllowsSelfRegister 帶出 approval，而 EntryOf 的 SignUpOpen 為真——
//     門外的人看得到那扇門，因為門後面確實有一條收申請的通路；
//   - 同一份策略下 AllowsGuest 照舊為假（訪客通路與本步無關，不順手翻真）。
func TestApprovalModeIsWritable(t *testing.T) {
	e := newEnv(t)
	beforeMode := ""
	_, m, _, _ := readRow(t, e.db)
	beforeMode = m
	auditBefore := len(auditRows(t, e.db))

	updated, err := e.service.UpdatePolicy(context.Background(), root(t),
		inputOf(false, "approval", false), "req")
	if err != nil {
		t.Fatalf("approval 現在寫得進去，實際失敗：%v", err)
	}
	if beforeMode != "closed" {
		t.Fatalf("測試前提跑偏：起點模式應為 closed，實際 %q", beforeMode)
	}
	if updated.SelfRegisterMode != ModeApproval {
		t.Errorf("回傳應是重讀後的現值 approval，實際 %q", updated.SelfRegisterMode)
	}
	if _, m2, _, _ := readRow(t, e.db); m2 != "approval" {
		t.Errorf("落庫現值應為 approval，實際 %q", m2)
	}
	if got := len(auditRows(t, e.db)); got != auditBefore+1 {
		t.Errorf("成功的策略變更應追加一筆審計，實際 %d→%d", auditBefore, got)
	}

	// 合成兩側：Allows 帶出模式，對外入口因此放開（推得開，但不是「進去就有帳號用」）。
	policy, err := e.service.Policy(context.Background(), root(t))
	if err != nil {
		t.Fatalf("現讀策略失敗：%v", err)
	}
	if ok, mode := policy.AllowsSelfRegister(); !ok || mode != ModeApproval {
		t.Errorf("AllowsSelfRegister 應放行並帶出 approval，實際 %v/%q", ok, mode)
	}
	entry := policy.EntryOf()
	if !entry.SignUpOpen {
		t.Error("approval 已落地，SignUpOpen 應隨之為真（那扇門推得開）")
	}
	if entry.GuestOpen {
		t.Error("訪客通路未落地，GuestOpen 必須仍為關")
	}
	if !ModeServed(ModeApproval) {
		t.Error("通路登記未翻真時 ModeServed 不該回報已落地")
	}
	if ModeServed(ModeInvite) || ModeServed(ModeClosed) {
		t.Error("ModeServed 只回答「提交服務得動」：invite 尚未落地，closed 不是一種提交方式")
	}
}

// TestUnknownModeRejected 驗證打錯字的名字走的是另一句結論（不是「尚未開放」）。
//
// 兩者必須分開：把「pending」說成「這個模式還沒上線」會讓 Root 以為等一個版本就能勾，
// 而那個名字永遠不存在。
func TestUnknownModeRejected(t *testing.T) {
	e := newEnv(t)
	_, err := e.service.UpdatePolicy(context.Background(), root(t), inputOf(false, "pending", false), "req")
	if !errors.Is(err, ErrUnknownMode) {
		t.Fatalf("不認識的模式應回 ErrUnknownMode，實際 %v", err)
	}
	if errors.Is(err, ErrModeUnavailable) {
		t.Error("ErrUnknownMode 不得被判成 ErrModeUnavailable（雨句話的處置不同）")
	}
	if _, m2, _, _ := readRow(t, e.db); m2 != "closed" {
		t.Errorf("被拒的寫入不應改動模式，實際 %q", m2)
	}
}

// TestAuditFailureRollsBackPolicy 驗證「改了策略但查不到是誰改的」這種半套不存在。
//
// 手法是把 root_audit 表先拆掉，讓同交易後半段的 INSERT 必然失敗：
// 若策略與審計不在同一筆交易裡，這裡就會看到「值已改而審計零筆」——
// 那正是特權變更最該被禁止的狀態。
func TestAuditFailureRollsBackPolicy(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.service.UpdatePolicy(ctx, root(t), inputOf(true, "closed", false), "req-seed"); err != nil {
		t.Fatalf("前置建立失敗：%v", err)
	}
	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("拆掉審計表失敗：%v", err)
	}

	if _, err := e.service.UpdatePolicy(ctx, root(t), inputOf(true, "open", true), "req-boom"); err == nil {
		t.Fatal("審計寫不下去時整個變更應失敗")
	}
	admin, mode, guest, updatedAt := readRow(t, e.db)
	if admin != 1 || mode != "closed" || guest != 0 {
		t.Errorf("交易回滚後策略應仍是前置值 1/closed/0，實際 %d/%q/%d", admin, mode, guest)
	}
	if want := timeutil.ToMillis(testBase); updatedAt != want {
		t.Errorf("回滚後的時刻不應被推進（%d），實際 %d", want, updatedAt)
	}
}

// TestPolicySurvivesReopen 驗證重開程序後讀回同一份策略（不需要任何重啟動作）。
//
// 這是「立即生效且不靠記憶體」這句話的另一面：策略的權威在庫裡，
// 進程換一個也還是同一個答案。
func TestPolicySurvivesReopen(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.service.UpdatePolicy(ctx, root(t), inputOf(true, "open", true), "req"); err != nil {
		t.Fatalf("變更失敗：%v", err)
	}
	if err := e.db.Close(); err != nil {
		t.Fatalf("關閉測試庫失敗：%v", err)
	}
	reopened, err := database.Open(ctx, database.Options{Path: e.path, BusyTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("重新開啟測試庫失敗：%v", err)
	}
	defer func() { _ = reopened.Close() }()

	store := NewStore(timeutil.System())
	service, err := New(Deps{DB: reopened, Store: store, Audits: audit.NewStore(timeutil.System())})
	if err != nil {
		t.Fatalf("重新組裝用例失敗：%v", err)
	}
	policy, err := service.Policy(ctx, root(t))
	if err != nil {
		t.Fatalf("重開後現讀策略應成功：%v", err)
	}
	if !policy.AdminCreateStandard || policy.SelfRegisterMode != ModeOpen || !policy.GuestEnabled {
		t.Errorf("重開後應讀回 1/open/1，實際 %+v", policy)
	}
	if policy.UpdatedAt.IsZero() {
		t.Error("重開後的 updated_at 必須仍是那次變更的時刻，不能退回零值")
	}
}

// TestEntryNeedsNoPrincipalButNeverGuesses 驗證對外入口：不用主體就能問，
// 答案如實反映「策略 ∧ 通路 ∧ 可服務的模式」，而庫裡讀不到策略時它是失敗而不是憑空的一組布林。
func TestEntryNeedsNoPrincipalButNeverGuesses(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	entry, err := e.service.Entry(ctx)
	if err != nil {
		t.Fatalf("匿名現讀對外答案應成功：%v", err)
	}
	// 出廠策略是自註冊 closed：通路已落地，但部署者關著，對外仍是全關。
	if entry.SignUpOpen || entry.GuestOpen {
		t.Errorf("出廠狀態（closed）的答案應全為關，實際 %+v", entry)
	}

	// Root 把自註冊設成 open：通路已落地、模式可服務，SignUpOpen 才翻成 true；
	// 訪客通路仍未實作，GuestEnabled 開關再放，GuestOpen 也必須是關（策略值不等於能力）。
	if _, err := e.service.UpdatePolicy(ctx, root(t), inputOf(true, "open", true), "req"); err != nil {
		t.Fatalf("變更失敗：%v", err)
	}
	entry, err = e.service.Entry(ctx)
	if err != nil {
		t.Fatalf("變更後現讀對外答案應成功：%v", err)
	}
	if !entry.SignUpOpen {
		t.Errorf("通路已落地且模式=open 時 SignUpOpen 應為 true，實際 %+v", entry)
	}
	if entry.GuestOpen {
		t.Errorf("訪客通路未實作，GuestOpen 應仍為關，實際 %+v", entry)
	}

	// 單例行被外部工具拿掉：必須回報失敗。降級成一組布林（不管全開或全關）
	// 都是把一次資料庫缺陷說成 Root 的決定。
	if _, err := e.db.SQL().ExecContext(ctx,
		`CREATE TABLE account_creation_policy_backup AS SELECT * FROM account_creation_policy`); err != nil {
		t.Fatalf("備份策略行失敗：%v", err)
	}
	if _, err := e.db.SQL().ExecContext(ctx,
		`DROP TABLE account_creation_policy`); err != nil {
		t.Fatalf("移除策略表失敗：%v", err)
	}
	if _, err := e.db.SQL().ExecContext(ctx,
		`CREATE TABLE account_creation_policy (id INTEGER PRIMARY KEY, admin_create_standard INTEGER,
			self_register_mode TEXT, guest_enabled INTEGER, updated_at INTEGER)`); err != nil {
		t.Fatalf("重建空策略表失敗：%v", err)
	}
	if _, err := e.service.Entry(ctx); !errors.Is(err, ErrNoPolicyRow) {
		t.Errorf("讀不到單例行時應回 ErrNoPolicyRow，實際 %v", err)
	}
	if _, err := e.service.Policy(ctx, root(t)); !errors.Is(err, ErrNoPolicyRow) {
		t.Errorf("Root 現讀在同樣狀態下也應回 ErrNoPolicyRow，實際 %v", err)
	}
	_ = e.db
}

// TestStoreRejectsIllegalModeBeforeSQL 驗證倉儲在進 SQL 之前就擋下不認識的模式。
//
// 表裡的 CHECK 是最後一道，而這裡先擋是為了給出一句點名欄位的可讀錯誤；
// 兩者都必須成立，少任何一條都會出現「半套寫法能過」的狀態。
func TestStoreRejectsIllegalModeBeforeSQL(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.store.Put(ctx, e.db.SQL(), Policy{SelfRegisterMode: Mode("maybe")}); err == nil {
		t.Fatal("不認識的模式應在進 SQL 前就被拒")
	}
	if _, m2, _, _ := readRow(t, e.db); m2 != "closed" {
		t.Errorf("被拒的寫入不應改動模式，實際 %q", m2)
	}

	// nil 連線是組裝缺陷，不是可以靜默降級的空結果。
	if _, err := e.store.Get(ctx, nil); err == nil {
		t.Error("缺少資料庫連線時讀取應失敗")
	}
	if _, err := e.store.Put(ctx, nil, Policy{SelfRegisterMode: ModeClosed}); err == nil {
		t.Error("缺少資料庫連線時寫入應失敗")
	}
}

// TestNewRejectsMissingDependencies 驗證缺依賴在組裝階段就報錯，而不是留一個
// 「改了策略但沒留痕」的空出口。
func TestNewRejectsMissingDependencies(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Error("缺 db／audits 時 New 應失敗")
	}
	e := newEnv(t)
	if _, err := New(Deps{DB: e.db}); err == nil {
		t.Error("缺審計倉儲時 New 應失敗（否則特權變更可以不留痕）")
	}
	// Store 缺席時由 New 自行建一個：倉儲不含任何「必須由裝配層決定」的選擇，
	// 少它不是缺陷，因此這條路要能組裝成功。
	service, err := New(Deps{DB: e.db, Audits: e.audit})
	if err != nil {
		t.Fatalf("Store 缺席時應能組裝：%v", err)
	}
	if _, err := service.Policy(context.Background(), root(t)); err != nil {
		t.Fatalf("自行建立的倉儲應可用：%v", err)
	}
}

// TestDeniedAttemptsAreLoggedWithoutPolicyValues 驗證被拒的嘗試在日誌裡看得見，
// 但不複述策略值：一次非 Root 的嘗試需要被發現，不需要在日誌裡留下它想改成什麼。
func TestDeniedAttemptsAreLoggedWithoutPolicyValues(t *testing.T) {
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	service, err := New(Deps{DB: newEnv(t).db, Audits: audit.NewStore(timeutil.NewTest(testBase)), Log: logger})
	if err != nil {
		t.Fatalf("組裝失敗：%v", err)
	}
	if _, err := service.UpdatePolicy(context.Background(),
		identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin()),
		inputOf(true, "open", true), "req-denied"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("管理員變更策略應被拒：%v", err)
	}
	out := logs.String()
	if !strings.Contains(out, "req-denied") || !strings.Contains(out, "不具備 Root 權限") {
		t.Errorf("被拒的嘗試應留下含關聯 ID 的一句警告，實際日誌：%s", out)
	}
	for _, forbidden := range []string{"open", "true", "approval"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("被拒嘗試的日誌不得複述策略值（命中 %q）：%s", forbidden, out)
		}
	}
}
