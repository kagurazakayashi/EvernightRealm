// store_test.go 是綁定介質倉儲層的定向證據：憑證的明文只在簽發那一次離開服務端、
// 核銷只能發生一次且到期即失效、留痕只追加且一個訪戶只被綁走一次、
// 按明文查法不透露「不存在」與「形狀不合」的差別、本人的讀法只讀得到自己那幾行。
//
// 全程使用本次專屬的暫存庫與注入時鐘：不佔 5206、不碰任何真實資料目錄，
// 也不在任何地方留下憑證明文、驗證材料或會話材料。測試一律不帶 -race
// （本機 cgo 工具鏈限制，見既有交接）。
package guestbind

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// testBase 是注入時鐘的錨點。
var testBase = time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)

// testTTL 是測試用的憑證壽命（生產常量在 internal/stdacct，本套件不依賴它）。
const testTTL = 15 * time.Minute

// env 是一次測試的完整現場：專屬暫存庫、注入時鐘、綁定介質倉儲，
// 外加父表需要的帳戶倉儲（外鍵要求來源與目標先存在）。
type env struct {
	db       *database.DB
	clock    *timeutil.Test
	store    *Store
	accounts *account.Store
	guestID  idgen.ID
	targetID idgen.ID
	adminID  idgen.ID
}

// newEnv 建立現場。倉儲與時鐘同源：到期判定與簽發時刻必須走同一座鐘，
// 否則「推鐘過期」這類斷言測的就不是倉儲的規則而是兩處時鐘的差。
func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() {
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			t.Errorf("暫存目錄清理失敗（殘留：%s）：%v", dir, err)
		}
	})
	ctx := context.Background()
	db, err := database.Open(ctx, database.Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clock := timeutil.NewTest(testBase)
	if _, err := migrate.Apply(ctx, db.SQL(), migrate.Options{Clock: clock}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	accounts := account.NewStore(clock)
	e := &env{db: db, clock: clock, store: NewStore(clock), accounts: accounts}
	e.guestID = e.seedAccount(t, "guest.bind", "待綁訪戶", account.TypeGuest, "")
	e.targetID = e.seedAccount(t, "target.bind", "受綁甲", account.TypeStandard, "t-pwd")
	e.adminID = e.seedAccount(t, "admin.bind", "簽發者", account.TypeStandard, "a-pwd")
	return e
}

// seedAccount 經倉儲種入一筆帳戶並回傳標識（訪客無憑據、普通帳戶帶測試雜湊）。
func (e *env) seedAccount(t *testing.T, login, display string,
	typ account.Type, password string) idgen.ID {
	t.Helper()
	hash := ""
	if typ == account.TypeStandard {
		derived, err := credential.Hash(password, credential.TestParams)
		if err != nil {
			t.Fatalf("產生測試憑據失敗：%v", err)
		}
		hash = derived
	}
	created, err := e.accounts.Create(context.Background(), e.db.SQL(), account.NewInput{
		LoginName:          login,
		DisplayName:        display,
		PasswordHash:       hash,
		Type:               typ,
		Status:             account.StatusActive,
		MustChangePassword: typ == account.TypeStandard,
	})
	if err != nil {
		t.Fatalf("種入帳戶 %s 失敗：%v", login, err)
	}
	return created.ID
}

// seedTicketPair 簽發一枚限定給定這一對的憑證，回傳明文與實體。
func (e *env) seedTicketPair(t *testing.T, source, target idgen.ID) (string, Ticket) {
	t.Helper()
	ticket, plain, err := e.store.CreateTicket(context.Background(), e.db.SQL(), CreateTicketInput{
		SourceAccountID:   source,
		TargetAccountID:   target,
		IssuedByAccountID: e.adminID,
		PlanDigest:        testDigest(),
		SchemaVersion:     11,
		ExpiresAt:         e.clock.Now().Add(testTTL),
	})
	if err != nil {
		t.Fatalf("簽發憑證失敗：%v", err)
	}
	return plain, ticket
}

// seedTicket 以現場預置的那一對簽發一枚憑證。
func (e *env) seedTicket(t *testing.T) (string, Ticket) {
	t.Helper()
	return e.seedTicketPair(t, e.guestID, e.targetID)
}

// consumeTicket 核銷一枚憑證（合法留痕的前提：沒有核銷就沒有一次綁定）。
func (e *env) consumeTicket(t *testing.T, id idgen.ID) {
	t.Helper()
	changed, err := e.store.ConsumeTicket(context.Background(), e.db.SQL(), id)
	if err != nil {
		t.Fatalf("核銷憑證失敗：%v", err)
	}
	if !changed {
		t.Fatalf("核銷該命中一行，實際零行（憑證 %s）", id.String())
	}
}

// testDigest 給出一枚形狀合法的計劃摘要（內容對本倉儲毫無意義：它只驗形狀）。
func testDigest() string { return strings.Repeat("a", 64) }

// mustCount 取一條 COUNT(*) 的數值（測試取證用，不參與任何生產判定）。
func mustCount(t *testing.T, db *database.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("計數查詢失敗（%s）：%v", query, err)
	}
	return n
}

// TestTicketRoundTripAndOneTimeConsume 驗收：簽發回來的明文只在這一次出現、
// 庫裡只有它的哈希；按明文讀得回同一枚憑證；核銷成功一次，第二次就是零行。
func TestTicketRoundTripAndOneTimeConsume(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	plain, ticket := e.seedTicket(t)

	if len(plain) != ticketTextLen {
		t.Errorf("憑證明文長度應為 %d，實際 %d", ticketTextLen, len(plain))
	}
	if !ticket.ConsumedAt.IsZero() {
		t.Error("新建憑證讀回來就該是未核銷形態")
	}
	if !ticket.Pending(e.clock.Now()) {
		t.Error("剛簽發的憑證此刻應該還用得上")
	}
	// 庫裡那欄是哈希，不是明文：把明文放進查詢條件必須一行都對不上。
	if got := mustCount(t, e.db, "SELECT COUNT(*) FROM guest_bind_tickets WHERE ticket_hash = ?", plain); got != 0 {
		t.Errorf("庫裡不得出現憑證明文，實際以明文命中 %d 行", got)
	}
	if got := mustCount(t, e.db, "SELECT COUNT(*) FROM guest_bind_tickets WHERE ticket_hash = ?",
		hashTicket(plain)); got != 1 {
		t.Errorf("庫裡應有該明文的 SHA-256 一列，實際 %d 列", got)
	}

	read, err := e.store.TicketByPlain(ctx, e.db.SQL(), plain)
	if err != nil {
		t.Fatalf("按明文讀回憑證失敗：%v", err)
	}
	if read.ID != ticket.ID || read.SourceAccountID != e.guestID || read.TargetAccountID != e.targetID ||
		read.IssuedByAccountID != e.adminID || read.SchemaVersion != 11 {
		t.Errorf("讀回的憑證事實與簽發時不同：%+v", read)
	}
	if read.ExpiresAt.Sub(read.CreatedAt) != testTTL {
		t.Errorf("憑證壽命應是 %v，實際 %v", testTTL, read.ExpiresAt.Sub(read.CreatedAt))
	}

	changed, err := e.store.ConsumeTicket(ctx, e.db.SQL(), ticket.ID)
	if err != nil {
		t.Fatalf("核銷憑證失敗：%v", err)
	}
	if !changed {
		t.Error("第一次核銷必須命中一行")
	}
	after, err := e.store.TicketByPlain(ctx, e.db.SQL(), plain)
	if err != nil {
		t.Fatalf("核銷後仍應讀得回：%v", err)
	}
	if after.ConsumedAt.IsZero() {
		t.Error("核銷時刻沒有落庫")
	}
	if after.Pending(e.clock.Now()) {
		t.Error("已核銷的憑證不該被視為還能用")
	}
	again, err := e.store.ConsumeTicket(ctx, e.db.SQL(), ticket.ID)
	if err != nil {
		t.Fatalf("第二次核銷的查詢本身不該失敗：%v", err)
	}
	if again {
		t.Error("同一枚憑證被核銷了兩次——WHERE 少了一道條件")
	}
	if got := mustCount(t, e.db, "SELECT COUNT(*) FROM guest_bind_tickets"); got != 1 {
		t.Errorf("核銷不是消費掉整行：表裡仍應有 1 行，實際 %d 行", got)
	}
}

// TestTicketExpiryEndsUsability 驗收：推鐘越過到期時刻之後，憑證既「不再可用」也核銷不掉——
// 到期是失效的充分條件，不由讀取時刻決定。
func TestTicketExpiryEndsUsability(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	_, ticket := e.seedTicket(t)

	e.clock.Advance(testTTL + time.Second)
	if ticket.Pending(e.clock.Now()) {
		t.Error("已過期的憑證不該被視為還能用")
	}
	changed, err := e.store.ConsumeTicket(ctx, e.db.SQL(), ticket.ID)
	if err != nil {
		t.Fatalf("核銷過期憑證的查詢本身不該失敗：%v", err)
	}
	if changed {
		t.Error("過期的憑證被核銷掉了——到期條件沒進 WHERE")
	}
	if got := mustCount(t, e.db,
		"SELECT COUNT(*) FROM guest_bind_tickets WHERE consumed_at IS NOT NULL"); got != 0 {
		t.Errorf("過期核銷失敗後不得留下核銷時刻，實際 %d 行帶時刻", got)
	}
}

// TestTicketCreateGuardsFailClosed 驗收：缺標識、來源與目標同一人、摘要形狀不合、
// 到期不晚於簽發、目標不存在——五種寫法一律拒絕落庫，表裡一行都不多。
func TestTicketCreateGuardsFailClosed(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	ghost, err := idgen.New()
	if err != nil {
		t.Fatalf("產生幽靈標識失敗：%v", err)
	}

	cases := []struct {
		name string
		in   CreateTicketInput
		want error
	}{
		{"來源是零值", CreateTicketInput{
			SourceAccountID: idgen.Nil, TargetAccountID: e.targetID, IssuedByAccountID: e.adminID,
			PlanDigest: testDigest(), ExpiresAt: e.clock.Now().Add(testTTL),
		}, ErrNilIdentifier},
		{"目標是零值", CreateTicketInput{
			SourceAccountID: e.guestID, TargetAccountID: idgen.Nil, IssuedByAccountID: e.adminID,
			PlanDigest: testDigest(), ExpiresAt: e.clock.Now().Add(testTTL),
		}, ErrNilIdentifier},
		{"簽發人是零值", CreateTicketInput{
			SourceAccountID: e.guestID, TargetAccountID: e.targetID, IssuedByAccountID: idgen.Nil,
			PlanDigest: testDigest(), ExpiresAt: e.clock.Now().Add(testTTL),
		}, ErrNilIdentifier},
		{"來源與目標同一人", CreateTicketInput{
			SourceAccountID: e.guestID, TargetAccountID: e.guestID, IssuedByAccountID: e.adminID,
			PlanDigest: testDigest(), ExpiresAt: e.clock.Now().Add(testTTL),
		}, ErrNilIdentifier},
		{"摘要太短", CreateTicketInput{
			SourceAccountID: e.guestID, TargetAccountID: e.targetID, IssuedByAccountID: e.adminID,
			PlanDigest: strings.Repeat("a", 63), ExpiresAt: e.clock.Now().Add(testTTL),
		}, ErrInvalidDigest},
		{"摘要含大寫十六進位", CreateTicketInput{
			SourceAccountID: e.guestID, TargetAccountID: e.targetID, IssuedByAccountID: e.adminID,
			PlanDigest: strings.Repeat("A", 64), ExpiresAt: e.clock.Now().Add(testTTL),
		}, ErrInvalidDigest},
		{"到期不晚於簽發", CreateTicketInput{
			SourceAccountID: e.guestID, TargetAccountID: e.targetID, IssuedByAccountID: e.adminID,
			PlanDigest: testDigest(), ExpiresAt: e.clock.Now(),
		}, ErrInvalidExpiresAt},
		// 目標不存在：這裡擋下來的是資料庫外鍵，不是倉儲的輸入閘，
		// 因此只斷言「必須失敗」而不斷言是哪一枚結論。
		{"目標不存在", CreateTicketInput{
			SourceAccountID: e.guestID, TargetAccountID: ghost, IssuedByAccountID: e.adminID,
			PlanDigest: testDigest(), ExpiresAt: e.clock.Now().Add(testTTL),
		}, nil},
	}
	for _, tc := range cases {
		_, _, err := e.store.CreateTicket(ctx, e.db.SQL(), tc.in)
		if err == nil {
			t.Errorf("%s：這次簽發該被拒絕，實際寫成功了", tc.name)
			continue
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s：結論應是 %v，實際 %v", tc.name, tc.want, err)
		}
	}
	if got := mustCount(t, e.db, "SELECT COUNT(*) FROM guest_bind_tickets"); got != 0 {
		t.Errorf("八次被拒的簽發該一行都不落，實際 %d 行", got)
	}
}

// TestTicketByPlainNeverDisclosesWhy 驗收：表外形狀、空白、與「形狀完全合規但不存在」
// 對呼叫端是同一句話——按明文查證的這條路不是憑證探測器。
func TestTicketByPlainNeverDisclosesWhy(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	_, seeded := e.seedTicket(t)

	// 一枚形狀合規但庫裡沒有的明文（拿另一組固定隨機源編碼出來）。
	other, _, err := newTicket(strings.NewReader(strings.Repeat("x", ticketBytes)))
	if err != nil {
		t.Fatalf("產生對照明文失敗：%v", err)
	}
	if _, err := e.store.TicketByPlain(ctx, e.db.SQL(), other); !errors.Is(err, ErrNotFound) {
		t.Errorf("不存在的憑證應回 ErrNotFound，實際 %v", err)
	}

	for _, bad := range []string{"", "short", "a-b_c", "++++++++++++++++++++++", "==",
		strings.ToUpper(seeded.ID.String()), strings.Repeat("A", ticketTextLen)} {
		got, err := e.store.TicketByPlain(ctx, e.db.SQL(), bad)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("形狀不合的輸入 %q 應回同一句 ErrNotFound，實際 %v", bad, err)
		}
		if !got.ID.IsNil() {
			t.Errorf("被拒的查詢不該帶回任何憑證：%+v", got)
		}
	}
}

// TestAppendBindingGuardsAndScope 驗收：留痕的四道輸入閘、它必須指向一枚已核銷的憑證、
// 一個訪戶只被綁走一次，以及本人的讀法只讀得到自己那幾行。
func TestAppendBindingGuardsAndScope(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	_, ticketA := e.seedTicket(t)
	otherTarget := e.seedAccount(t, "target.two", "受綁乙", account.TypeStandard, "t2-pwd")
	e.consumeTicket(t, ticketA.ID)

	bound := func(source, target, ticket idgen.ID, at time.Time) error {
		_, err := e.store.AppendBinding(ctx, e.db.SQL(), AppendBindingInput{
			SourceAccountID: source, TargetAccountID: target, TicketID: ticket,
			BoundAt: at, RevokedSessions: 1,
		})
		return err
	}

	// 四道輸入閘：零值標識、同對、沒有時刻、負數數量。
	if err := bound(idgen.Nil, otherTarget, ticketA.ID, e.clock.Now()); !errors.Is(err, ErrNilIdentifier) {
		t.Errorf("來源零值應回 ErrNilIdentifier，實際 %v", err)
	}
	if err := bound(e.guestID, e.guestID, ticketA.ID, e.clock.Now()); !errors.Is(err, ErrNilIdentifier) {
		t.Errorf("同對應回 ErrNilIdentifier，實際 %v", err)
	}
	if err := bound(e.guestID, otherTarget, ticketA.ID, time.Time{}); !errors.Is(err, ErrInvalidBoundAt) {
		t.Errorf("零時刻應回 ErrInvalidBoundAt，實際 %v", err)
	}
	if _, err := e.store.AppendBinding(ctx, e.db.SQL(), AppendBindingInput{
		SourceAccountID: e.guestID, TargetAccountID: otherTarget, TicketID: ticketA.ID,
		BoundAt: e.clock.Now(), RevokedSessions: -1,
	}); err == nil {
		t.Error("負數撤銷數量該被拒絕")
	}
	// 未核銷的憑證換不出留痕（遷移 0011 那條觸發器在資料庫層說同一句話）。
	_, pendingTicket := e.seedTicketPair(t, e.guestID, otherTarget)
	if err := bound(e.guestID, otherTarget, pendingTicket.ID, e.clock.Now()); err == nil {
		t.Error("指向未核銷憑證的留痕該被資料庫擋下")
	}

	// 合法形態落庫後，同一個來源不能再被綁走第二次（倉儲拿到的是資料庫的 UNIQUE）。
	if err := bound(e.guestID, otherTarget, ticketA.ID, e.clock.Now()); err != nil {
		t.Fatalf("第一次合法留痕應寫得進：%v", err)
	}
	if err := bound(e.guestID, e.targetID, ticketA.ID, e.clock.Now()); err == nil {
		t.Error("同一個訪戶被綁走了第二次——UNIQUE 沒有生效")
	}

	// 範圍：查受綁乙得到剛寫下的一行，查目標甲得到空清單（不是 nil）。
	first, err := e.store.BindingsByTarget(ctx, e.db.SQL(), otherTarget)
	if err != nil {
		t.Fatalf("讀回本人留痕失敗：%v", err)
	}
	if len(first) != 1 || first[0].SourceAccountID != e.guestID ||
		first[0].ConsentMode != ConsentModeTargetSelfInitiated {
		t.Errorf("本人那本帳應只有剛寫下的一行，實際 %+v", first)
	}
	if first[0].TicketID != ticketA.ID {
		t.Error("留痕丟了它指向的那枚憑證")
	}
	none, err := e.store.BindingsByTarget(ctx, e.db.SQL(), e.targetID)
	if err != nil {
		t.Fatalf("讀取無留痕的目標失敗：%v", err)
	}
	if none == nil || len(none) != 0 {
		t.Errorf("沒有綁定時該回空清單而不是 nil，實際 %+v", none)
	}
	if _, err := e.store.BindingsByTarget(ctx, e.db.SQL(), idgen.Nil); !errors.Is(err, ErrNilIdentifier) {
		t.Errorf("零值目標應回 ErrNilIdentifier，實際 %v", err)
	}
}

// TestBindingsByTargetOrderIsNewestFirst 驗收：本人那本帳依綁定時刻倒序，
// 以標識破平——同一時刻的多行也有確定順序（界面與測試都按這一句寫）。
func TestBindingsByTargetOrderIsNewestFirst(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	target := e.seedAccount(t, "target.many", "接住多人者", account.TypeStandard, "m-pwd")

	// 三個訪戶各自一枚憑證、各自一行留痕，綁定時刻依序推進。
	for i := 0; i < 3; i++ {
		guest := e.seedAccount(t, "guest.multi"+string(rune('a'+i)), "多綁訪戶", account.TypeGuest, "")
		_, ticket := e.seedTicketPair(t, guest, target)
		e.consumeTicket(t, ticket.ID)
		boundAt := testBase.Add(time.Duration(i+1) * time.Minute)
		if _, err := e.store.AppendBinding(ctx, e.db.SQL(), AppendBindingInput{
			SourceAccountID: guest, TargetAccountID: target, TicketID: ticket.ID,
			BoundAt: boundAt, RevokedSessions: i,
		}); err != nil {
			t.Fatalf("追加留痕失敗：%v", err)
		}
	}
	items, err := e.store.BindingsByTarget(ctx, e.db.SQL(), target)
	if err != nil {
		t.Fatalf("讀回本人留痕失敗：%v", err)
	}
	if len(items) != 3 {
		t.Fatalf("應讀到 3 行，實際 %d 行", len(items))
	}
	for i := 0; i < 2; i++ {
		if !items[i].BoundAt.After(items[i+1].BoundAt) {
			t.Errorf("第 %d 行的綁定時刻不早於下一行，倒序不成立：%v vs %v",
				i, items[i].BoundAt, items[i+1].BoundAt)
		}
	}
}

// TestStoreRejectsMissingConnection 驗收：五條方法都要求呼叫端交出連線或交易，
// nil 一律當場拒絕——「倉儲自己偷偷開一條」正是把一次綁定拆成四段的那種形態。
func TestStoreRejectsMissingConnection(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	if _, _, err := e.store.CreateTicket(ctx, nil, CreateTicketInput{
		SourceAccountID: e.guestID, TargetAccountID: e.targetID, IssuedByAccountID: e.adminID,
		PlanDigest: testDigest(), ExpiresAt: e.clock.Now().Add(testTTL),
	}); err == nil {
		t.Error("CreateTicket 對 nil 連線該拒絕")
	}
	if _, err := e.store.TicketByPlain(ctx, nil, strings.Repeat("k", ticketTextLen)); err == nil {
		t.Error("TicketByPlain 對 nil 連線該拒絕")
	}
	if _, err := e.store.ConsumeTicket(ctx, nil, e.guestID); err == nil {
		t.Error("ConsumeTicket 對 nil 連線該拒絕")
	}
	if _, err := e.store.AppendBinding(ctx, nil, AppendBindingInput{
		SourceAccountID: e.guestID, TargetAccountID: e.targetID, TicketID: e.guestID,
		BoundAt: e.clock.Now(),
	}); err == nil {
		t.Error("AppendBinding 對 nil 連線該拒絕")
	}
	if _, err := e.store.BindingsByTarget(ctx, nil, e.targetID); err == nil {
		t.Error("BindingsByTarget 對 nil 連線該拒絕")
	}
}
