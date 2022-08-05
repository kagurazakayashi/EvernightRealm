package audit

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/redact"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// fixedClock 為可設定的時鐘：審計時刻必須取自伺服器時鐘且不採信呼叫端（DEC-015、§27.2）。
type fixedClock struct{ at time.Time }

// Now 回傳固定時刻。
func (c fixedClock) Now() time.Time { return c.at }

// newTestStore 開啟暫存資料庫、套用內嵌遷移，回傳審計存取層與原始連線。
func newTestStore(t *testing.T) (*Store, *database.DB, time.Time) {
	t.Helper()
	at := time.Date(2026, 9, 26, 12, 34, 56, 789_000_000, time.UTC)
	db, err := database.Open(context.Background(), database.Options{
		Path:        filepath.Join(retryTempDir(t), "evernight.db"),
		BusyTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: timeutil.System()}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	return NewStore(fixedClock{at: at}), db, at
}

func TestAppendAndQueryRoundTrip(t *testing.T) {
	store, db, at := newTestStore(t)
	ctx := context.Background()
	rec := validActivityRecord()
	rec.RequestID = ""

	id, err := store.Append(ctx, db.SQL(), rec)
	if err != nil {
		t.Fatalf("Append 失敗：%v", err)
	}
	if id.IsNil() {
		t.Error("Append 未回傳記錄標識")
	}

	page, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: ScopeActivity, ActivityID: rec.ActivityID})
	if err != nil {
		t.Fatalf("Query 失敗：%v", err)
	}
	if len(page.Records) != 1 || page.NextCursor != "" {
		t.Fatalf("頁內容不符：%+v", page)
	}
	got := page.Records[0]
	if got.ID != id {
		t.Errorf("標識不符：%v 對 %v", got.ID, id)
	}
	if !got.CreatedAt.Equal(at) {
		t.Errorf("時刻取自注入時鐘：取得 %v，want %v", got.CreatedAt, at)
	}
	if got.Scope != ScopeActivity || got.ActivityID != rec.ActivityID ||
		got.Actor.Kind != ActorAdmin || got.Actor.ID != rec.Actor.ID ||
		got.Action != rec.Action || got.Target != rec.Target || got.Reason != rec.Reason {
		t.Errorf("欄位還原不符：%+v", got)
	}
	// 空字串的關聯 ID 落地為 NULL，讀回來也是空字串（不是「(空)」這類佔位文字）。
	if got.RequestID != "" {
		t.Errorf("request_id 應為空，實際 %q", got.RequestID)
	}
	if len(got.Changes) != 1 || got.Changes[0].Before != float64(500) || got.Changes[0].After != float64(300) {
		t.Errorf("變更摘要不符：%+v", got.Changes)
	}
	// 時間戳以毫秒 INTEGER 存放（DEC-011、DEC-015）。
	var stored int64
	if err := db.SQL().QueryRowContext(ctx, "SELECT created_at FROM activity_audit WHERE id = ?", id.String()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != timeutil.ToMillis(at) {
		t.Errorf("created_at = %d，want %d", stored, timeutil.ToMillis(at))
	}
}

func TestAppendUsesOnlyTheSingleIDSource(t *testing.T) {
	store, db, _ := newTestStore(t)
	broken := errors.New("熵源不可用")
	store.newID = func() (idgen.ID, error) { return idgen.Nil, broken }

	_, err := store.Append(context.Background(), db.SQL(), validActivityRecord())
	if err == nil {
		t.Fatal("標識產生失敗時應拒絕寫入")
	}
	if !errors.Is(err, broken) {
		t.Errorf("錯誤應可被呼叫端辨識（不吞掉原因）：%v", err)
	}
	if strings.Contains(err.Error(), "uuid") || strings.Contains(err.Error(), "v4") {
		t.Errorf("不得降級為其他格式：%v", err)
	}
	assertRowCount(t, db, "activity_audit", 0)
}

func TestAppendRejectsInvalidRecordBeforeTouchingDatabase(t *testing.T) {
	store, db, _ := newTestStore(t)
	rec := validActivityRecord()
	rec.Action = "Balance Adjust"
	if _, err := store.Append(context.Background(), db.SQL(), rec); err == nil {
		t.Fatal("非法記錄應被拒絕")
	}
	assertRowCount(t, db, "activity_audit", 0)

	if _, err := store.Append(context.Background(), nil, validActivityRecord()); err == nil {
		t.Error("q 為 nil 時應回傳錯誤而不是 panic")
	}

	// 代填標識與時刻：這些值不會進資料庫，必須當場拒絕而不是默默改用伺服器產生的。
	for _, mutate := range []func(*Record){
		func(r *Record) { r.ID = mustID(t1) },
		func(r *Record) { r.CreatedAt = time.UnixMilli(1).UTC() },
	} {
		rec := validActivityRecord()
		mutate(&rec)
		if _, err := store.Append(context.Background(), db.SQL(), rec); err == nil {
			t.Error("呼叫端代填標識或時刻時應被拒絕")
		} else if !strings.Contains(err.Error(), "不得代填") {
			t.Errorf("錯誤訊息未點出拒絕原因：%v", err)
		}
	}
	assertRowCount(t, db, "activity_audit", 0)
}

// TestAppendInRolledBackTransactionLeavesNothing 是 DEV-1-10 的驗收專案：
// 「業務事務失敗時不會留下虛假成功審計」。審計與業務變更同交易，靠回滾保證，
// 而不是事後補寫一條「剛剛那筆不算」。
func TestAppendInRolledBackTransactionLeavesNothing(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	business := errors.New("餘額不足")

	err := db.InTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO server_settings (key, value, updated_at) VALUES (?, ?, ?)`,
			"test.key", "1", 1); err != nil {
			return err
		}
		if _, err := store.Append(ctx, tx, validActivityRecord()); err != nil {
			return err
		}
		return business
	})
	if !errors.Is(err, business) {
		t.Fatalf("應把業務錯誤原樣回傳：%v", err)
	}
	assertRowCount(t, db, "activity_audit", 0)
	assertRowCount(t, db, "server_settings", 0)
}

// TestAppendOnlyTablesRejectUpdateAndDelete 固定 AUD-003／§25.3 的資料庫層把關：
// 不是只有我們的程式碼不改不刪，而是透過 SQL 改刪會被觸發器擋下。
func TestAppendOnlyTablesRejectUpdateAndDelete(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	rec := validActivityRecord()
	activityID, err := store.Append(ctx, db.SQL(), rec)
	if err != nil {
		t.Fatal(err)
	}
	root := Record{Scope: ScopeRoot, Actor: Actor{Kind: ActorRoot, ID: mustID(t1)},
		Action: "admin.delete", Target: Target{Kind: "admin", ID: mustID(t2).String()}, Reason: "離職"}
	if _, err := store.Append(ctx, db.SQL(), root); err != nil {
		t.Fatal(err)
	}

	statements := []struct {
		table, query string
		args         []any
	}{
		{"activity_audit", "UPDATE activity_audit SET reason = '抹掉' WHERE 1 = 1", nil},
		{"activity_audit", "DELETE FROM activity_audit WHERE 1 = 1", nil},
		{"activity_audit", "UPDATE activity_audit SET changes_json = '[]' WHERE id = ?", []any{activityID.String()}},
		{"root_audit", "UPDATE root_audit SET reason = NULL WHERE 1 = 1", nil},
		{"root_audit", "DELETE FROM root_audit WHERE 1 = 1", nil},
	}
	for _, st := range statements {
		if _, err := db.SQL().ExecContext(ctx, st.query, st.args...); err == nil {
			t.Errorf("%s 的改刪竟被接受：%s", st.table, st.query)
			continue
		} else if !strings.Contains(err.Error(), "只追加存儲") {
			t.Errorf("%s：錯誤訊息未點出只追加約定：%v", st.table, err)
		}
	}
	// 被拒的語句不能留下半改狀態：原記錄仍要完整讀得回來。
	page, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: ScopeActivity, ActivityID: rec.ActivityID})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("觸發器拒絕後查不到原記錄：%v / %+v", err, page.Records)
	}
	if page.Records[0].Reason != rec.Reason || page.Records[0].Changes[0].After != float64(300) {
		t.Errorf("原記錄內容被改動：%+v", page.Records[0])
	}
	assertRowCount(t, db, "root_audit", 1)
}

// TestChangesAreUnreadableInTheRawColumn 從資料庫原始欄位取證：
// 審計表本身（繞過我們的讀取路徑）也拿不到 PIN、憑證與聊天正文。
func TestChangesAreUnreadableInTheRawColumn(t *testing.T) {
	store, db, _ := newTestStore(t)
	const (
		pin      = "48219375"
		tokenVal = "sess-9f8e7d6c5b4a3210fedcba76543210"
		chatText = "今晚八點在舊倉庫見面，口令是 48219375"
	)
	rec := validActivityRecord()
	rec.Changes = []Change{
		{Field: "pin", Before: "1234", After: pin},
		{Field: "session_token", Before: "old", After: tokenVal},
		{Field: "chat_body", Before: "先前的內容", After: chatText},
		{Field: "recovery_code", Before: nil, After: "crd6-9fk2-m4xx-q7pp"},
	}
	recordID, err := store.Append(context.Background(), db.SQL(), rec)
	if err != nil {
		t.Fatal(err)
	}

	var raw string
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT changes_json FROM activity_audit WHERE id = ?", recordID.String()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{pin, tokenVal, chatText, "crd6-9fk2-m4xx-q7pp", "先前的內容"} {
		if strings.Contains(raw, leak) {
			t.Errorf("原始欄位裡找得到機密 %q：%s", leak, raw)
		}
	}
	for _, want := range []string{redact.Redacted, redact.RefPrefix, "chat_body"} {
		if !strings.Contains(raw, want) {
			t.Errorf("原始欄位缺少 %q：%s", want, raw)
		}
	}
	// 「記錄了事件但不記正文」要能從欄位名判斷出來，因此鍵名一律保留。
	if !strings.Contains(raw, "pin") {
		t.Errorf("鍵名不應一起消失：%s", raw)
	}
}

func TestQueryPaginatesWithoutGapsOrRepeats(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	rec := validActivityRecord()
	const total = 25
	// 同一毫秒也要能穩定排序：靠 UUIDv7 的遞增字首破平（DEC-014）。
	for i := 0; i < total; i++ {
		if _, err := store.Append(ctx, db.SQL(), rec); err != nil {
			t.Fatalf("第 %d 筆寫入失敗：%v", i, err)
		}
	}

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: ScopeActivity, ActivityID: rec.ActivityID, Limit: 10, Cursor: cursor})
		if err != nil {
			t.Fatalf("分頁失敗：%v", err)
		}
		pages++
		if len(page.Records) > 10 {
			t.Fatalf("單頁超過 limit：%d", len(page.Records))
		}
		for _, got := range page.Records {
			if seen[got.ID.String()] {
				t.Fatalf("游標分頁重複回傳 %s", got.ID)
			}
			seen[got.ID.String()] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		if pages > 10 {
			t.Fatal("游標沒有收斂")
		}
	}
	if len(seen) != total {
		t.Errorf("翻完共取得 %d 筆，want %d（漏筆或重複）", len(seen), total)
	}
	if pages != 3 {
		t.Errorf("頁數 = %d，want 3（10 + 10 + 5）", pages)
	}
}

func TestQueryFilters(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	recA := validActivityRecord()
	otherActivity := validActivityRecord()
	otherActivity.ActivityID = mustID(t3)
	otherActivity.Action = "phase.change"
	otherActivity.Target = Target{Kind: "phase", ID: "phase-3"}

	rootRec := Record{Scope: ScopeRoot, Actor: Actor{Kind: ActorSystem}, Action: "maintenance.enter",
		Target: Target{Kind: "server"}}

	for _, rec := range []Record{recA, otherActivity, rootRec} {
		if _, err := store.Append(ctx, db.SQL(), rec); err != nil {
			t.Fatal(err)
		}
	}

	byAction, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: ScopeActivity,
		ActivityID: otherActivity.ActivityID, Action: "phase.change"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byAction.Records) != 1 || byAction.Records[0].Action != "phase.change" {
		t.Errorf("按動作過濾不符：%+v", byAction.Records)
	}
	// 動作碼過濾不能把活動條件擠掉：A 活動裡沒有 phase.change，就算 B 活動有也不該出現。
	if page, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: ScopeActivity,
		ActivityID: recA.ActivityID, Action: "phase.change"}); err != nil || len(page.Records) != 0 {
		t.Errorf("A 活動不該有 B 活動的動作：%d 筆 / %v", len(page.Records), err)
	}

	byTarget, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: ScopeActivity,
		ActivityID: otherActivity.ActivityID, Target: &otherActivity.Target})
	if err != nil {
		t.Fatal(err)
	}
	if len(byTarget.Records) != 1 || byTarget.Records[0].Target.ID != "phase-3" {
		t.Errorf("按對象過濾不符：%+v", byTarget.Records)
	}

	// 活動隔離的技術基礎：查 A 活動查不到 B 活動的記錄。
	cross, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: ScopeActivity, ActivityID: recA.ActivityID})
	if err != nil {
		t.Fatal(err)
	}
	if len(cross.Records) != 1 {
		t.Errorf("跨活動讀到了東西：%+v", cross.Records)
	}

	// 時間窗：未來視窗查不到，含當前時刻的視窗查得到。
	if page, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: ScopeRoot,
		Since: time.Now().Add(24 * time.Hour)}); err != nil || len(page.Records) != 0 {
		t.Errorf("未來的時間窗應查不到：%d 筆 / %v", len(page.Records), err)
	}
	if page, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: ScopeRoot, Until: time.Now()}); err != nil || len(page.Records) != 1 {
		t.Errorf("Root 查詢應取得 1 筆：%d 筆 / %v", len(page.Records), err)
	}
	// Root 表沒有 activity_id：帶進來一定是呼叫端搞錯作用域，不能靜默忽略。
	if _, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: ScopeRoot, ActivityID: mustID(t3)}); err == nil {
		t.Error("root 作用域帶 activity_id 應被拒絕")
	}
	if _, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: ScopeActivity}); err == nil {
		t.Error("activity 作用域未帶 activity_id 應被拒絕（否則會撈出全部活動）")
	}
	if _, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: "session", ActivityID: mustID(t3)}); err == nil {
		t.Error("未知作用域應被拒絕")
	}
	if _, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: ScopeActivity, ActivityID: mustID(t3), Limit: MaxLimit + 1}); !errors.Is(err, ErrLimitTooLarge) {
		t.Errorf("超過上限應回 ErrLimitTooLarge，實際 %v", err)
	}
	if _, err := store.Query(ctx, db.SQL(), rootViewer(), Filter{Scope: ScopeActivity, ActivityID: mustID(t3), Cursor: "胡亂寫的"}); !errors.Is(err, ErrInvalidCursor) {
		t.Errorf("非法游標應回 ErrInvalidCursor（不退回第一頁），實際 %v", err)
	}
}

func TestReadOnlyTransactionCannotAppend(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	err := db.InTxReadOnly(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := store.Append(ctx, tx, validActivityRecord())
		return err
	})
	if err == nil {
		t.Fatal("唯讀交易不應寫入成功")
	}
	assertRowCount(t, db, "activity_audit", 0)
}

func TestAppendOnlyStorageSurvivesReopen(t *testing.T) {
	store, db, at := newTestStore(t)
	ctx := context.Background()
	rec := validActivityRecord()
	recordID, err := store.Append(ctx, db.SQL(), rec)
	if err != nil {
		t.Fatal(err)
	}
	path := db.Path()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := database.Open(ctx, database.Options{Path: path, BusyTimeout: time.Second})
	if err != nil {
		t.Fatalf("重開失敗：%v", err)
	}
	defer reopened.Close()
	page, err := NewStore(fixedClock{at: at}).Query(ctx, reopened.SQL(), rootViewer(),
		Filter{Scope: ScopeActivity, ActivityID: rec.ActivityID})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.Records[0].ID != recordID {
		t.Errorf("重開後讀不回原記錄：%+v", page.Records)
	}
}

// assertRowCount 直接數列數（獨立於本套件的讀取路徑，避免「寫入與讀取用同一個 bug 自證清白」）。
// 不符時列出實際存在的記錄，否則「應為 0 筆」這種斷言只給數字看不出是什麼時候混進來的。
func assertRowCount(t *testing.T, db *database.DB, table string, want int) {
	t.Helper()
	var got int
	if err := db.SQL().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got == want {
		return
	}
	rows, err := db.SQL().QueryContext(context.Background(),
		"SELECT id, action, COALESCE(reason, '') FROM "+table)
	if err != nil {
		t.Fatalf("%s 筆數 = %d，want %d；列出明細時查詢失敗：%v", table, got, want, err)
	}
	defer rows.Close()
	var detail []string
	for rows.Next() {
		var id, action, reason string
		if err := rows.Scan(&id, &action, &reason); err != nil {
			t.Fatalf("%s 筆數 = %d，want %d；列出明細時讀取失敗：%v", table, got, want, err)
		}
		detail = append(detail, fmt.Sprintf("%s/%s/%s", id, action, reason))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s 筆數 = %d，want %d；明細迭代之後仍有錯誤：%v", table, got, want, err)
	}
	t.Errorf("%s 筆數 = %d，want %d，現有記錄：%s", table, got, want, strings.Join(detail, " | "))
}

// t3 是第二個活動標識（用於跨活動過濾的測試）。
const t3 = "0198c2f4-7a3e-7b21-9c8d-1e2f3a4b5c70"
