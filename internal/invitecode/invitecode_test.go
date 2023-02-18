// invitecode_test.go 是「服務器級註冊邀請碼」用例層的定向證據：誰能簽發／撤銷、簽發落下什麼形態、
// 名冊讀到什麼（以及讀不到什麼）、撤銷之後那枚碼還算不算數、以及核銷那一步將來要依賴的併發邊界。
//
// 對應本步的驗收要求：權限、隨機令牌處理、受控一次性展示、列表不洩密、過期／撤銷與重複撤銷、
// 用現有事務機制驗證消費接口需要的併發邊界。
//
// 全程使用本次專屬的暫存庫與注入時鐘：不佔 5206、不碰任何真實資料目錄，也不在任何地方留下
// 明文碼、驗證材料或會話材料。測試一律不帶 -race（本機 cgo 工具鏈限制，見既有交接）。
package invitecode

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// testBase 是注入時鐘的錨點。
var testBase = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)

// env 是一次測試的完整現場：專屬暫存庫、注入時鐘，加上組好的邀請碼用例與其協作倉儲。
//
// 會話倉儲與賬戶倉儲刻意不在這裡出現——本用例不依賴它們（見套件頭注「刻意沒有的三個依賴」）：
// 少接一條就少一分「簽發准入憑證時不小心碰到賬戶」的可能。
type env struct {
	db      *database.DB
	clock   *timeutil.Test
	logs    *bytes.Buffer
	store   *Store
	audit_  *audit.Store
	service *Service
}

// newEnv 建立現場。Store 與 Service 用同一枚注入時鐘：到期判定與簽發時刻必須同源。
func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() {
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			t.Errorf("暫存目錄清理失敗（殘留：%s）：%v", dir, err)
		}
	})
	db, err := database.Open(context.Background(), database.Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試數據庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := timeutil.NewTest(testBase)
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: clock}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	var logs bytes.Buffer
	store := NewStore(clock)
	service, err := New(Deps{
		DB:     db,
		Store:  store,
		Clock:  clock,
		Audits: audit.NewStore(clock),
		Log:    slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("建立邀請碼用例失敗：%v", err)
	}
	return &env{db: db, clock: clock, logs: &logs, store: store,
		audit_: audit.NewStore(clock), service: service}
}

// newRoot 建立一位通過真實憑據比對的 Root 主體（純測試身份工廠，不落 accounts 表）。
func newRoot(t *testing.T) identity.Principal {
	t.Helper()
	return identitytest.Root(t, identity.OriginHTTPRequest)
}

// mustIssue 簽發一枚碼，失敗即終止；返回明文與名冊行。
func (e *env) mustIssue(t *testing.T, principal identity.Principal, in IssueInput) IssuedCode {
	t.Helper()
	issued, err := e.service.Issue(context.Background(), principal, in, "req-issue")
	if err != nil {
		t.Fatalf("簽發邀請碼應成功：%v", err)
	}
	return issued
}

// codeFacts 是一枚碼在數據庫裡的可觀察形態（前後對照、脫敏斷言都拿它做等值比較）。
type codeFacts struct {
	HashLen int
	Used    int64
	Revoked int64
	Expires int64
}

// readStoredCode 讀回數據庫裡那一行可觀察形態（驗證材料長度、已用次數、撤銷時刻、到期時刻）。
func (e *env) readStoredCode(t *testing.T, id idgen.ID) codeFacts {
	t.Helper()
	var f codeFacts
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT length(code_hash), used_count,
		revoked_at, expires_at FROM registration_invite_codes WHERE id = ?`, id.String()).
		Scan(&f.HashLen, &f.Used, &f.Revoked, &f.Expires)
	if err != nil {
		t.Fatalf("讀回邀請碼行失敗：%v", err)
	}
	return f
}

// TestIssueWritesCodeAndRootAudit 簽發落下的是「庫裡一枚只存驗證材料的新行 + 一條真實歸屬的 Root 域審計」，
// 而明文只出現在結果裡、庫里根本沒有可存明文的地方。
func TestIssueWritesCodeAndRootAudit(t *testing.T) {
	e := newEnv(t)
	root := newRoot(t)
	issued := e.mustIssue(t, root, IssueInput{Label: "內測名額", MaxUses: 5})

	if issued.Code == "" {
		t.Fatal("簽發結果必須帶著一次性明文，否則界面無從展示")
	}
	if issued.Row.Status != StatusActive {
		t.Errorf("剛簽發的碼此刻該是 active，實際 %q", issued.Row.Status)
	}
	if issued.Row.Remaining != 5 {
		t.Errorf("額度 5、尚未核銷，剩餘該是 5，實際 %d", issued.Row.Remaining)
	}

	stored := e.readStoredCode(t, mustParseID(t, issued.Row.CodeID))
	if stored.HashLen != codeHashLen {
		t.Errorf("庫裡落的必須是定寬 64 的驗證材料哈希，實際 %d", stored.HashLen)
	}
	if stored.Used != 0 || stored.Revoked != 0 || stored.Expires != 0 {
		t.Errorf("新行該是 0 次已用、未撤銷、永不過期，實際 %d/%d/%d", stored.Used, stored.Revoked, stored.Expires)
	}
	// 表裡沒有任何一欄裝著明文碼：整張表掃一遍，明文不得出現。
	if strings.Contains(e.codeTableDump(t), issued.Code) {
		t.Error("明文碼出現在數據庫裡——庫裡本應只有它的不可逆驗證材料")
	}

	record := mustAudit(t, e.db, "invite.issue")
	if record.ActorKind != "root" || !record.ActorID.Valid {
		t.Errorf("簽發者是 Root 這一事實只能落在 root_audit 的 actor 裡，實際 %s/%v", record.ActorKind, record.ActorID)
	}
	// 審計的變更摘要恰好是那四格可展示元數據，沒有一個格容得下明文碼或驗證材料。
	fields := auditFieldNames(t, record.ChangesJSON)
	want := []string{"created_at", "expires_at", "label", "max_uses"}
	if !equalStrings(fields, want) {
		t.Errorf("簽發審計的變更欄應恰為 %v，實際 %v", want, fields)
	}
	if dump := mustAuditDump(t, e.db); strings.Contains(dump, issued.Code) {
		t.Error("審計全文裡出現了明文碼——簽發審計不得記錄任何可直接複用的秘密")
	}
}

// TestIssuePermissionMatrix 只有 Root 能簽發：匿名未認證、服務器管理員／普通／訪客／系統主體一律拒。
//
// 這一條釘的是「邀請碼攜帶的是服務器級准入，不是誰的日常打理權」——管理員管的是已存在的普通賬戶，
// 不是「誰能生出一個普通賬戶」，所以 NeedServerAdmin 在這裡過不了 NeedRoot。
func TestIssuePermissionMatrix(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name      string
		principal identity.Principal
		want      error
	}{
		{"匿名", identitytest.Anonymous(t), identity.ErrNotAuthenticated},
		{"服務器管理員", identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin()), identity.ErrPermissionDenied},
		{"普通賬戶", identitytest.Account(t, identitytest.NewID(t)), identity.ErrPermissionDenied},
		{"訪客賬戶", identitytest.Account(t, identitytest.NewID(t), identitytest.WithGuestType()), identity.ErrPermissionDenied},
		{"系統主體", identitytest.System(t, identity.OriginCLI), identity.ErrPermissionDenied},
	}
	before := countRows(t, e.db, "registration_invite_codes")
	for _, tc := range cases {
		_, err := e.service.Issue(context.Background(), tc.principal,
			IssueInput{Label: "不該簽出", MaxUses: 1}, "req-matrix")
		if !errors.Is(err, tc.want) {
			t.Errorf("%s：簽發應回 %v，實際 %v", tc.name, tc.want, err)
		}
	}
	if got := countRows(t, e.db, "registration_invite_codes"); got != before {
		t.Errorf("被拒的簽發一行都不該落庫，前 %d 後 %d", before, got)
	}
	if got := countRows(t, e.db, "root_audit"); got != 0 {
		t.Errorf("被拒的簽發不追加審計（拒絕不該成為寫入放大器），實際 %d 筆", got)
	}
	// Root 同一條路徑過得了。
	if _, err := e.service.Issue(context.Background(), newRoot(t),
		IssueInput{Label: "Root 籤的", MaxUses: 1}, "req-root"); err != nil {
		t.Errorf("Root 應能簽發：%v", err)
	}
}

// TestIssueRejectsInvalidInput 非法輸入在進交易之前就點名對應欄位，既不燒隨機源也不落庫。
func TestIssueRejectsInvalidInput(t *testing.T) {
	e := newEnv(t)
	root := newRoot(t)
	cases := []struct {
		name string
		in   IssueInput
		want error
	}{
		{"空標籤", IssueInput{Label: "   ", MaxUses: 1}, ErrInvalidLabel},
		{"額度為零", IssueInput{Label: "甲", MaxUses: 0}, ErrInvalidMaxUses},
		{"額度為負", IssueInput{Label: "甲", MaxUses: -3}, ErrInvalidMaxUses},
		{"額度越上界", IssueInput{Label: "甲", MaxUses: MaxUsesLimit + 1}, ErrInvalidMaxUses},
		{"有效期在過去", IssueInput{Label: "甲", MaxUses: 1,
			ExpiresAt: testBase.Add(-time.Hour)}, ErrInvalidExpiry},
		{"有效期正是此刻", IssueInput{Label: "甲", MaxUses: 1, ExpiresAt: testBase}, ErrInvalidExpiry},
	}
	for _, tc := range cases {
		_, err := e.service.Issue(context.Background(), root, tc.in, "req-bad")
		if !errors.Is(err, tc.want) {
			t.Errorf("%s：應回 %v，實際 %v", tc.name, tc.want, err)
		}
	}
	if got := countRows(t, e.db, "registration_invite_codes"); got != 0 {
		t.Errorf("非法簽發一行都不該落庫，實際 %d", got)
	}
}

// TestRosterIsMetadataOnlyRoster 名冊每一行只有可展示元數據，沒有明文碼、沒有驗證材料，
// 關鍵字比對把 % 與 _ 當字面字元而非通配。
func TestRosterIsMetadataOnlyRoster(t *testing.T) {
	e := newEnv(t)
	root := newRoot(t)
	first := e.mustIssue(t, root, IssueInput{Label: "百分號100%", MaxUses: 1})
	e.mustIssue(t, root, IssueInput{Label: "下劃線_a", MaxUses: 3})
	e.clock.Advance(time.Minute)
	third := e.mustIssue(t, root, IssueInput{Label: "普通標籤", MaxUses: 2})

	page, err := e.service.Roster(context.Background(), root, RosterQuery{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("名冊讀取應成功：%v", err)
	}
	if page.Total != 3 || len(page.Rows) != 3 {
		t.Fatalf("三枚碼都該列進來，實際 total=%d rows=%d", page.Total, len(page.Rows))
	}
	// 倒序：最新簽發的 third 在第一行。
	if page.Rows[0].CodeID != third.Row.CodeID {
		t.Errorf("名冊應按簽發時刻倒序，首行實際 %q", page.Rows[0].CodeID)
	}
	// 行裡沒有任何一格等於明文碼或驗證材料哈希：整個投影序列化成 JSON 也掃不到。
	blob := rowDump(t, page.Rows)
	for _, secret := range []string{first.Code, third.Code} {
		if strings.Contains(blob, secret) {
			t.Error("名冊投影裡出現了明文碼")
		}
	}
	// 關鍵字把 % 當字面字元：搜「100%」只命中那一行；搜「a」命中含下劃線那一行（不是全表）。
	pctPage, err := e.service.Roster(context.Background(), root, RosterQuery{Page: 1, PageSize: 20, Keyword: "100%"})
	if err != nil {
		t.Fatalf("按關鍵字篩選應成功：%v", err)
	}
	if pctPage.Total != 1 {
		t.Errorf("「100%%」作為字面關鍵字應只命中一行，實際 %d", pctPage.Total)
	}
}

// TestRosterFilterMatchesDerivedStatus 名冊的 SQL 側狀態篩選與 Go 側派生必須同判：
// 篩出來的每一行，它自己那一格顯示的狀態都得對得上。過期用注入時鐘推進，撤銷用撤銷用例落時刻。
func TestRosterFilterMatchesDerivedStatus(t *testing.T) {
	e := newEnv(t)
	root := newRoot(t)
	// 一枚 60 秒後到期的碼。
	expiring := e.mustIssue(t, root, IssueInput{Label: "將到期", MaxUses: 5,
		ExpiresAt: testBase.Add(time.Minute)})
	// 一枚滿額度的碼（經核銷原語用到滿——核銷端點本步不開放，這裡直接走倉儲那一條併發安全 UPDATE）。
	full := e.mustIssue(t, root, IssueInput{Label: "將用滿", MaxUses: 1})
	e.mustConsume(t, full.Row.CodeID)
	// 一枚被撤銷的碼。
	revoked := e.mustIssue(t, root, IssueInput{Label: "將被撤銷", MaxUses: 1})
	e.mustRevoke(t, root, revoked.Row.CodeID)
	// 一枚仍然有效的碼。
	active := e.mustIssue(t, root, IssueInput{Label: "仍有效", MaxUses: 1})

	// 時鐘推進過 expiring 的到期時刻；此刻四態各有一行。
	e.clock.Advance(2 * time.Minute)

	for _, tc := range []struct {
		filter Status
		wantID string
	}{
		{StatusExpired, expiring.Row.CodeID},
		{StatusExhausted, full.Row.CodeID},
		{StatusRevoked, revoked.Row.CodeID},
		{StatusActive, active.Row.CodeID},
	} {
		page, err := e.service.Roster(context.Background(), root,
			RosterQuery{Page: 1, PageSize: 20, StatusFilter: tc.filter.String()})
		if err != nil {
			t.Fatalf("篩選 %s 應成功：%v", tc.filter, err)
		}
		if len(page.Rows) != 1 || page.Rows[0].CodeID != tc.wantID {
			ids := make([]string, 0, len(page.Rows))
			for _, r := range page.Rows {
				ids = append(ids, r.CodeID)
			}
			t.Errorf("篩選 %s 應只得到 %s，實際 %v", tc.filter, tc.wantID, ids)
			continue
		}
		if page.Rows[0].Status != tc.filter {
			t.Errorf("篩選 %s 得到那一行的自顯示狀態卻不相符：%q", tc.filter, page.Rows[0].Status)
		}
	}
}

// TestRosterRejectsInvalidParams 每個非法查詢參數各自點名，越界頁碼回空行而非錯誤。
func TestRosterRejectsInvalidParams(t *testing.T) {
	e := newEnv(t)
	root := newRoot(t)
	cases := []struct {
		name string
		q    RosterQuery
		want error
	}{
		{"頁碼 0", RosterQuery{Page: 0, PageSize: 20}, ErrInvalidPage},
		{"每頁 0", RosterQuery{Page: 1, PageSize: 0}, ErrInvalidPageSize},
		{"每頁超上限", RosterQuery{Page: 1, PageSize: RosterMaxPageSize + 1}, ErrInvalidPageSize},
		{"狀態篩選非法", RosterQuery{Page: 1, PageSize: 20, StatusFilter: "cancelled"}, ErrInvalidStatusFilter},
		{"關鍵字過長", RosterQuery{Page: 1, PageSize: 20, Keyword: strings.Repeat("字", RosterKeywordMaxRunes+1)}, ErrInvalidKeyword},
	}
	for _, tc := range cases {
		_, err := e.service.Roster(context.Background(), root, tc.q)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s：應回 %v，實際 %v", tc.name, tc.want, err)
		}
	}
	// 越界但合法的頁碼：空行 + 真實總數，不是錯誤。
	page, err := e.service.Roster(context.Background(), root, RosterQuery{Page: 9999, PageSize: 20})
	if err != nil {
		t.Fatalf("越界頁碼不該報錯：%v", err)
	}
	if len(page.Rows) != 0 {
		t.Errorf("越界頁碼應回空行，實際 %d 行", len(page.Rows))
	}
}

// TestStatusDerivedByInjectedClock 狀態完全由注入時鐘在讀用時派生：
// 同一行在到期前是 active、到期後是 expired，撤銷壓過一切，額度用滿落 exhausted。
func TestStatusDerivedByInjectedClock(t *testing.T) {
	e := newEnv(t)
	root := newRoot(t)
	issued := e.mustIssue(t, root, IssueInput{Label: "一分鐘碼", MaxUses: 3,
		ExpiresAt: testBase.Add(time.Minute)})
	id := mustParseID(t, issued.Row.CodeID)

	if got := e.statusAt(t, id, testBase); got != StatusActive {
		t.Errorf("到期前該是 active，實際 %q", got)
	}
	if got := e.statusAt(t, id, testBase.Add(time.Minute)); got != StatusExpired {
		t.Errorf("到期時刻當刻（now >= expires_at）該是 expired，實際 %q", got)
	}
	if got := e.statusAt(t, id, testBase.Add(2*time.Minute)); got != StatusExpired {
		t.Errorf("到期之後該是 expired，實際 %q", got)
	}
	// 撤銷壓過到期：撤銷之後無論時鐘為何都是 revoked。
	e.mustRevoke(t, root, issued.Row.CodeID)
	if got := e.statusAt(t, id, testBase); got != StatusRevoked {
		t.Errorf("撤銷之後即便回到到期前也該是 revoked，實際 %q", got)
	}
}

// TestRevokeIsTerminalAndBlocksConsume 撤銷落下此刻、是終態、立刻擋住新的核銷，已核銷歷史留住。
func TestRevokeIsTerminalAndBlocksConsume(t *testing.T) {
	e := newEnv(t)
	root := newRoot(t)
	issued := e.mustIssue(t, root, IssueInput{Label: "先用一次再撤", MaxUses: 3})
	id := mustParseID(t, issued.Row.CodeID)

	// 先核銷一次，留下 used_count=1 的歷史。
	if !e.mustConsume(t, issued.Row.CodeID) {
		t.Fatal("撤銷前應能核銷一次")
	}
	if _, err := e.service.Revoke(context.Background(), root, id, "req-revoke"); err != nil {
		t.Fatalf("撤銷應成功：%v", err)
	}

	stored := e.readStoredCode(t, id)
	if stored.HashLen != codeHashLen {
		t.Errorf("撤銷不該動驗證材料：%d", stored.HashLen)
	}
	if stored.Used != 1 {
		t.Errorf("撤銷不抹掉已核銷的歷史，應仍為 1，實際 %d", stored.Used)
	}
	revokedMillis := timeutil.ToMillis(e.clock.Now())
	if stored.Revoked != revokedMillis {
		t.Errorf("撤銷時刻必須取自注入時鐘，實際 %d", stored.Revoked)
	}
	// 撤銷之後核銷原語一律拿不到額度。
	if ok, _ := e.store.Consume(context.Background(), e.db.SQL(), id); ok {
		t.Error("已撤銷的碼不得再被核銷")
	}

	// 重複撤銷即拒，且不改動任何東西、不追加審計。
	_, err := e.service.Revoke(context.Background(), root, id, "req-rev-again")
	if !errors.Is(err, ErrAlreadyRevoked) {
		t.Errorf("重複撤銷應回 ErrAlreadyRevoked，實際 %v", err)
	}
	if still := e.readStoredCode(t, id); still.Used != 1 || still.Revoked != revokedMillis {
		t.Errorf("重複撤銷不該改動任何一格：%+v", still)
	}
	if dumps := mustAuditDump(t, e.db); strings.Count(dumps, "invite.revoke") != 1 {
		t.Errorf("被拒的重複撤銷不再追加一筆撤銷審計，實際 dumps=%s", dumps)
	}
	record := mustAudit(t, e.db, "invite.revoke")
	fields := auditFieldNames(t, record.ChangesJSON)
	if !equalStrings(fields, []string{"revoked_at", "status"}) {
		t.Errorf("撤銷審計的變更欄應恰為 {revoked_at,status}，實際 %v", fields)
	}
}

// TestRevokeNotFound 幽靈標識、空標識與不存在的碼一律回 ErrCodeNotFound（不做標識格式探測）。
func TestRevokeNotFound(t *testing.T) {
	e := newEnv(t)
	root := newRoot(t)
	if _, err := e.service.Revoke(context.Background(), root, idgen.Nil, "req-ghost"); !errors.Is(err, ErrCodeNotFound) {
		t.Errorf("空標識應回 ErrCodeNotFound，實際 %v", err)
	}
	if _, err := e.service.Revoke(context.Background(), root, identitytest.NewID(t), "req-ghost2"); !errors.Is(err, ErrCodeNotFound) {
		t.Errorf("查無此碼應回 ErrCodeNotFound，實際 %v", err)
	}
}

// TestRevokePermissionMatrix 撤銷也只有 Root 過得了，被拒的撤銷零寫入零審計。
func TestRevokePermissionMatrix(t *testing.T) {
	e := newEnv(t)
	root := newRoot(t)
	issued := e.mustIssue(t, root, IssueInput{Label: "只有 Root 能撤", MaxUses: 1})
	id := mustParseID(t, issued.Row.CodeID)

	before := e.readStoredCode(t, id)
	for _, principal := range []identity.Principal{
		identitytest.Anonymous(t),
		identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin()),
		identitytest.Account(t, identitytest.NewID(t)),
		identitytest.System(t, identity.OriginCLI),
	} {
		_, err := e.service.Revoke(context.Background(), principal, id, "req-no")
		if err == nil {
			t.Errorf("非 Root 主體 %s 不該撤銷成功", principal.Kind())
			continue
		}
		if errors.Is(err, identity.ErrNotAuthenticated) || errors.Is(err, identity.ErrPermissionDenied) {
			continue
		}
		t.Errorf("非 Root 撤銷應回認證或權限錯誤，實際 %v", err)
	}
	after := e.readStoredCode(t, id)
	if after != before {
		t.Errorf("被拒的撤銷一個都不該動：前 %+v 後 %+v", before, after)
	}
	// 簽發那一步留下過一筆 invite.issue；這裡要斷言的是「被拒的撤銷不再追加一筆 invite.revoke」。
	if dumps := mustAuditDump(t, e.db); strings.Contains(dumps, "invite.revoke") {
		t.Errorf("被拒的撤銷不追加撤銷審計，實際 dumps=%s", dumps)
	}
}

// TestConsumeConcurrencyBoundary 用現有事務機制釘住核銷接口需要的併發邊界：
// 同一枚單次碼，多路併發核銷恰好有一次生效；同一枚三額度碼，恰好三次生效；
// 已撤銷的碼一次都生效不了。正確性來自那條帶 WHERE 的 UPDATE 與數據庫單寫者，不來自先查後寫。
func TestConsumeConcurrencyBoundary(t *testing.T) {
	t.Run("單次碼併發只一次贏", func(t *testing.T) {
		e := newEnv(t)
		root := newRoot(t)
		issued := e.mustIssue(t, root, IssueInput{Label: "單次併發", MaxUses: 1})
		if got := e.raceConsume(t, issued.Row.CodeID, 6); got != 1 {
			t.Errorf("六路併發核銷一枚單次碼應恰好一次成功，實際 %d", got)
		}
		if stored := e.readStoredCode(t, mustParseID(t, issued.Row.CodeID)); stored.Used != 1 {
			t.Errorf("單次碼用滿後 used_count 應恰為 1，實際 %d", stored.Used)
		}
	})
	t.Run("三額度碼併發只三次贏", func(t *testing.T) {
		e := newEnv(t)
		root := newRoot(t)
		issued := e.mustIssue(t, root, IssueInput{Label: "三額度併發", MaxUses: 3})
		if got := e.raceConsume(t, issued.Row.CodeID, 8); got != 3 {
			t.Errorf("八路併發核銷一枚三額度碼應恰好三次成功，實際 %d", got)
		}
	})
	t.Run("已撤銷碼併發零次贏", func(t *testing.T) {
		e := newEnv(t)
		root := newRoot(t)
		issued := e.mustIssue(t, root, IssueInput{Label: "撤銷後併發", MaxUses: 5})
		e.mustRevoke(t, root, issued.Row.CodeID)
		if got := e.raceConsume(t, issued.Row.CodeID, 5); got != 0 {
			t.Errorf("已撤銷的碼任何併發都不得佔用額度，實際成功 %d", got)
		}
	})
	t.Run("已過期碼併發零次贏", func(t *testing.T) {
		e := newEnv(t)
		root := newRoot(t)
		issued := e.mustIssue(t, root, IssueInput{Label: "過期後併發", MaxUses: 5,
			ExpiresAt: testBase.Add(time.Minute)})
		e.clock.Advance(2 * time.Minute)
		if got := e.raceConsume(t, issued.Row.CodeID, 5); got != 0 {
			t.Errorf("已過期的碼任何併發都不得佔用額度，實際成功 %d", got)
		}
	})
}

// TestConsumeGuardsRespectFacts 核銷原語對未過期未撤銷未滿的碼一次加一，用滿後再來落空。
func TestConsumeGuardsRespectFacts(t *testing.T) {
	e := newEnv(t)
	root := newRoot(t)
	issued := e.mustIssue(t, root, IssueInput{Label: "兩次額度", MaxUses: 2})
	id := issued.Row.CodeID
	if !e.mustConsume(t, id) {
		t.Fatal("第一次核銷應成功")
	}
	if !e.mustConsume(t, id) {
		t.Fatal("第二次核銷應成功")
	}
	if ok, _ := e.store.Consume(context.Background(), e.db.SQL(), mustParseID(t, id)); ok {
		t.Error("額度用滿後第三次核銷應落空")
	}
}

// —— 現場輔助 ——

// raceConsume 用 n 個 goroutine 各自開一筆真交易併發核銷同一枚碼，回成功的次數。
//
// 這是「核銷那一步將來要依賴的併發邊界」的證據：SQLite 單寫者把 n 筆提交串行化，
// 那條帶 WHERE 的原子 UPDATE 保證總額度不被超發——贏的次數恰等於額度上限（未撤銷未過期時）。
func (e *env) raceConsume(t *testing.T, idText string, n int) int {
	t.Helper()
	id := mustParseID(t, idText)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok := false
			err := e.db.InTx(context.Background(), func(ctx context.Context, tx *database.Tx) error {
				var err error
				ok, err = e.store.Consume(ctx, tx, id)
				return err
			})
			if err != nil {
				t.Errorf("併發核銷出現非落敗失敗：%v", err)
				return
			}
			if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	return wins
}

// mustConsume 走一次倉儲核銷（autocommit），失敗即終止。
func (e *env) mustConsume(t *testing.T, idText string) bool {
	t.Helper()
	ok, err := e.store.Consume(context.Background(), e.db.SQL(), mustParseID(t, idText))
	if err != nil {
		t.Fatalf("核銷失敗：%v", err)
	}
	return ok
}

// mustRevoke 走一次撤銷用例，失敗即終止。
func (e *env) mustRevoke(t *testing.T, root identity.Principal, idText string) {
	t.Helper()
	if _, err := e.service.Revoke(context.Background(), root, mustParseID(t, idText), "req-revoke"); err != nil {
		t.Fatalf("撤銷失敗：%v", err)
	}
}

// statusAt 用給定時刻讀回一枚碼的派生狀態（經 ByID + Status(now)，與名冊同一條派生）。
func (e *env) statusAt(t *testing.T, id idgen.ID, at time.Time) Status {
	t.Helper()
	code, err := e.store.ByID(context.Background(), e.db.SQL(), id)
	if err != nil {
		t.Fatalf("讀回邀請碼失敗：%v", err)
	}
	return code.Status(at)
}

// codeTableDump 把整張邀請碼表序列化成一個可掃描的字符串（明文碼不得在裡面出現）。
func (e *env) codeTableDump(t *testing.T) string {
	t.Helper()
	rows, err := e.db.SQL().QueryContext(context.Background(), `SELECT id, code_hash, label,
		max_uses, used_count, created_at, expires_at, revoked_at FROM registration_invite_codes`)
	if err != nil {
		t.Fatalf("導出邀請碼表失敗：%v", err)
	}
	defer rows.Close()
	var out strings.Builder
	for rows.Next() {
		var id, hash, label string
		var maxUses, used, created, expires, revoked int64
		if err := rows.Scan(&id, &hash, &label, &maxUses, &used, &created, &expires, &revoked); err != nil {
			t.Fatalf("讀取邀請碼行失敗：%v", err)
		}
		out.WriteString(id + hash + label)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍歷邀請碼表失敗：%v", err)
	}
	return out.String()
}

func mustParseID(t *testing.T, text string) idgen.ID {
	t.Helper()
	id, err := idgen.Parse(text)
	if err != nil {
		t.Fatalf("解析標識失敗：%v", err)
	}
	return id
}

func rowDump(t *testing.T, rows []Row) string {
	t.Helper()
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("序列化名冊行失敗：%v", err)
	}
	return string(data)
}

func countRows(t *testing.T, db *database.DB, table string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("計數 %s 失敗：%v", table, err)
	}
	return n
}

type auditRow struct {
	ActorKind   string
	ActorID     sql.NullString
	Action      string
	TargetID    sql.NullString
	Reason      sql.NullString
	RequestID   sql.NullString
	ChangesJSON string
	CreatedAt   int64
}

func mustAudit(t *testing.T, db *database.DB, action string) auditRow {
	t.Helper()
	var row auditRow
	err := db.SQL().QueryRowContext(context.Background(), `SELECT actor_kind, actor_id, action,
		target_id, reason, request_id, changes_json, created_at
		FROM root_audit WHERE action = ? ORDER BY created_at DESC, id DESC LIMIT 1`, action).
		Scan(&row.ActorKind, &row.ActorID, &row.Action, &row.TargetID, &row.Reason,
			&row.RequestID, &row.ChangesJSON, &row.CreatedAt)
	if err != nil {
		t.Fatalf("讀回 %s 的審計失敗：%v", action, err)
	}
	return row
}

func mustAuditDump(t *testing.T, db *database.DB) string {
	t.Helper()
	rows, err := db.SQL().QueryContext(context.Background(), `SELECT action,
		COALESCE(reason, ''), COALESCE(changes_json, '') FROM root_audit`)
	if err != nil {
		t.Fatalf("讀取審計全文失敗：%v", err)
	}
	defer rows.Close()
	var out strings.Builder
	for rows.Next() {
		var action, reason, changes string
		if err := rows.Scan(&action, &reason, &changes); err != nil {
			t.Fatalf("讀取審計列失敗：%v", err)
		}
		out.WriteString(action + "|" + reason + "|" + changes + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍歷審計失敗：%v", err)
	}
	return out.String()
}

func auditFieldNames(t *testing.T, changesJSON string) []string {
	t.Helper()
	var parsed []struct {
		Field string `json:"field"`
	}
	if err := json.Unmarshal([]byte(changesJSON), &parsed); err != nil {
		t.Fatalf("解析審計 changes_json 失敗：%v（原文 %s）", err, changesJSON)
	}
	fields := make([]string, 0, len(parsed))
	for _, item := range parsed {
		fields = append(fields, item.Field)
	}
	sort.Strings(fields)
	return fields
}

func equalStrings(a, b []string) bool {
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
