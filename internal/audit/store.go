package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 分頁參數（DEC-013：一套合同同時覆蓋追加型資料流與深度分頁）。
const (
	// DefaultLimit 是 Filter.Limit 為 0 時的每頁筆數。
	DefaultLimit = 50
	// MaxLimit 是單頁上限：審計是人工回看，不是一次拉十萬筆的匯出通道
	//（匯出屬後續的導出與備份步驟）。
	MaxLimit = 500
)

// ErrInvalidCursor 表示游標不可解析（格式不對、時間戳非法或標識不是 UUIDv7）。
var ErrInvalidCursor = errors.New("audit: 游標無效")

// ErrLimitTooLarge 表示每頁筆數超過上限。
//
// 這裡選擇回報錯誤而不是悄悄夾緊：被夾緊的呼叫端會以為自己拿到了要求的數量，
// 然後用一個比自己以為的更短的結果去做後續判斷。
var ErrLimitTooLarge = fmt.Errorf("audit: limit 不可超過 %d", MaxLimit)

// Store 是審計記錄的存取層：只開放追加與查詢，不提供修改或刪除的通路。
//
// 標識與時刻由 Store 自己產生而不是收在 Record 裡：全服務的標識唯一產生點是 idgen
// （DEC-014），時間唯一來源是 timeutil.Clock（DEC-015），兩者都不接受呼叫端（更不可能
// 是客戶端）代填。零值不可用，請經 NewStore 取得。
type Store struct {
	clock timeutil.Clock
	// newID 以欄位持有是為了讓測試注入失敗情境，驗證產生失敗時拒絕寫入而非降級格式。
	newID func() (idgen.ID, error)
}

// NewStore 建立審計存取層；clock 為 nil 時採用 timeutil.System()。
func NewStore(clock timeutil.Clock) *Store {
	if clock == nil {
		clock = timeutil.System()
	}
	return &Store{clock: clock, newID: idgen.New}
}

// Append 寫入一筆審計記錄，回傳落庫時實際使用的記錄標識。
//
// q 讓呼叫端把審計與業務變更放進同一個交易（DEC-013 的 Querier 介面由 *sql.DB 與 *Tx
// 共同滿足）：DEV-1-10 要求「業務事務失敗時不會留下虛假成功審計」，這件事由同一交易的自然回滾保證，而不是靠「事後補一筆回滾記錄」這種有窗口的手法。
// 記錄非法、標識產生失敗時一律回傳錯誤且不降級（不換成 UUIDv4、不用空值頂替）。
// 標識採回傳而不改寫呼叫端的記錄：Record 按值傳入，偷填引數會變成看不見的副作用。
func (s *Store) Append(ctx context.Context, q database.Querier, rec Record) (idgen.ID, error) {
	if q == nil {
		return idgen.Nil, errors.New("audit: 需要可用的資料庫連線或交易")
	}
	if err := rec.validate(); err != nil {
		return idgen.Nil, err
	}
	if !rec.ID.IsNil() || !rec.CreatedAt.IsZero() {
		// 代填的值不會進資料庫，靜默忽略會讓呼叫端以為自己寫進了某個標識或某個時刻。
		return idgen.Nil, errors.New("audit: 記錄標識與寫入時刻由伺服器產生，呼叫端不得代填")
	}
	table, err := rec.Scope.table()
	if err != nil {
		return idgen.Nil, err
	}
	id, err := s.newID()
	if err != nil {
		return idgen.Nil, fmt.Errorf("audit: 產生記錄標識失敗: %w", err)
	}
	changes, err := encodeChanges(rec.Changes)
	if err != nil {
		return idgen.Nil, err
	}

	// 表名來自 Scope 那個封閉集合（不是字串拼接），因此這裡的 Sprintf 沒有注入面；
	// 所有值一律走參數綁定。
	columns := auditColumns(rec.Scope)
	args := []any{id.String(), timeutil.ToMillis(s.clock.Now())}
	if rec.Scope == ScopeActivity {
		args = append(args, rec.ActivityID.String())
	}
	args = append(args,
		string(rec.Actor.Kind),
		nullableID(rec.Actor.ID),
		rec.Action,
		rec.Target.Kind,
		nullableText(rec.Target.ID),
		nullableText(maskText(rec.Reason)),
		nullableText(rec.RequestID),
		changes,
	)
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		table, strings.Join(columns, ", "), strings.TrimSuffix(strings.Repeat("?, ", len(columns)), ", "))

	if _, err := q.ExecContext(ctx, query, args...); err != nil {
		return idgen.Nil, fmt.Errorf("audit: 寫入 %s 失敗: %w", table, err)
	}
	return id, nil
}

// auditColumns 是兩張審計表共用的欄位順序，活動作用域多一欄 activity_id。
//
// 寫入的佔位符數量、查詢的欄位清單與 scanRecord 的取值順序都由此派生：各寫一份時
// 漂移不會在編譯期出現，只會在執行期變成「12 values for 11 columns」這種跟業務無關的失敗。
func auditColumns(scope Scope) []string {
	columns := []string{"id", "created_at"}
	if scope == ScopeActivity {
		columns = append(columns, "activity_id")
	}
	return append(columns, "actor_kind", "actor_id", "action", "target_kind", "target_id", "reason", "request_id", "changes_json")
}

// Page 是一頁審計記錄與其後繼游標。
type Page struct {
	Records []Record
	// NextCursor 為空表示已到底；非空時原樣帶回 Filter.Cursor 即可接續。
	NextCursor string
}

// Filter 是審計查詢條件。
//
// ScopeActivity 一律要給 ActivityID：作用域隔離的技術基礎在這裡，
// 「誰有權查哪個活動」屬授權判定（下一步的作用域隔離）。沒有這個條件時，
// 一個忘了帶過濾的查詢就會靜默地撈出全部活動的記錄——那不是「查不到」而是「查錯」。
type Filter struct {
	Scope      Scope
	ActivityID idgen.ID
	// Target 不為 nil 時只查這個對象（例如「這位玩家被改過哪些事」）。
	Target *Target
	// Action 不為空時只查這個動作碼。
	Action string
	// Since／Until 為時間窗（含起、含迄）；零值表示該端不限制。
	Since time.Time
	Until time.Time
	// Limit 為每頁筆數；0 表示 DefaultLimit。
	Limit int
	// Cursor 為上一頁回傳的 NextCursor，空字串表示從最新一筆開始。
	Cursor string
}

// Query 按鍵集（keyset）倒序分頁讀取審計記錄。
//
// 順序是 created_at DESC, id DESC：UUIDv7 的前綴按產生時刻遞增（DEC-014），
// 同一毫秒內也能靠 id 穩定破平，因此OFFSET 那種「翻到深處會看到重複或漏筆」的問題不存在。
func (s *Store) Query(ctx context.Context, q database.Querier, f Filter) (Page, error) {
	if q == nil {
		return Page{}, errors.New("audit: 需要可用的資料庫連線或交易")
	}
	table, err := f.Scope.table()
	if err != nil {
		return Page{}, err
	}
	if f.Scope == ScopeActivity && f.ActivityID.IsNil() {
		return Page{}, errors.New("audit: 查詢 activity 審計必須指定 activity_id")
	}
	if f.Scope == ScopeRoot && !f.ActivityID.IsNil() {
		// 靜默忽略會被當成「已經過濾了」：Root 表裡本來就沒有 activity_id 這個欄位。
		return Page{}, errors.New("audit: root 作用域的查詢不接受 activity_id")
	}
	limit := f.Limit
	switch {
	case limit == 0:
		limit = DefaultLimit
	case limit > MaxLimit:
		return Page{}, ErrLimitTooLarge
	}

	where := []string{"1 = 1"}
	args := []any{}
	if f.Scope == ScopeActivity {
		where = append(where, "activity_id = ?")
		args = append(args, f.ActivityID.String())
	}
	if f.Target != nil {
		where = append(where, "target_kind = ?")
		args = append(args, f.Target.Kind)
		if f.Target.ID == "" {
			where = append(where, "target_id IS NULL")
		} else {
			where = append(where, "target_id = ?")
			args = append(args, f.Target.ID)
		}
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}
	if !f.Since.IsZero() {
		where = append(where, "created_at >= ?")
		args = append(args, timeutil.ToMillis(f.Since))
	}
	if !f.Until.IsZero() {
		where = append(where, "created_at <= ?")
		args = append(args, timeutil.ToMillis(f.Until))
	}
	if f.Cursor != "" {
		at, id, err := parseCursor(f.Cursor)
		if err != nil {
			return Page{}, err
		}
		where = append(where, "(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, at, at, id)
	}

	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s ORDER BY created_at DESC, id DESC LIMIT ?",
		strings.Join(auditColumns(f.Scope), ", "), table, strings.Join(where, " AND "))
	// 多取一筆用來判斷還有沒有下一頁：這樣 NextCursor 不會在最後一頁多發一次空查詢。
	rows, err := q.QueryContext(ctx, query, append(args, limit+1)...)
	if err != nil {
		return Page{}, fmt.Errorf("audit: 查詢 %s 失敗: %w", table, err)
	}
	defer rows.Close()

	var (
		page  = Page{Records: []Record{}}
		count int
		last  Record
	)
	for rows.Next() {
		rec, err := scanRecord(f.Scope, rows)
		if err != nil {
			return Page{}, err
		}
		count++
		if count <= limit {
			page.Records = append(page.Records, rec)
			last = rec
		}
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("audit: 讀取 %s 失敗: %w", table, err)
	}
	if count > limit && !last.ID.IsNil() {
		page.NextCursor = makeCursor(last)
	}
	return page, nil
}

// rowScanner 是 *sql.Rows 的最小取行介面（便於測試替身，也避免把 *sql.Rows 帶進簽名）。
type rowScanner interface {
	Scan(dest ...any) error
}

// scanRecord 把一列讀回成記錄。
//
// 標識讀不回來時一律報錯：那代表資料庫被繞過寫入了東西（觸發器只管改刪），
// 靜默跳過會讓那筆記錄在界面上徹底消失。
func scanRecord(scope Scope, rows rowScanner) (Record, error) {
	var (
		rec                 Record
		idText              string
		createdAt           int64
		activityText        string
		actorText           string
		actorID             sql.NullString
		targetID, reason    sql.NullString
		requestID           sql.NullString
		changesJSON         string
		targetKind, actionK string
	)
	dest := []any{&idText, &createdAt}
	if scope == ScopeActivity {
		dest = append(dest, &activityText)
	}
	dest = append(dest, &actorText, &actorID, &actionK, &targetKind, &targetID, &reason, &requestID, &changesJSON)
	if err := rows.Scan(dest...); err != nil {
		return Record{}, fmt.Errorf("audit: 讀取審計記錄失敗: %w", err)
	}
	id, err := idgen.Parse(idText)
	if err != nil {
		return Record{}, fmt.Errorf("audit: 記錄標識無法解析（%s）: %w", idText, err)
	}
	rec.Scope = scope
	rec.ID = id
	rec.CreatedAt = timeutil.FromMillis(createdAt)
	if scope == ScopeActivity {
		activityID, err := idgen.Parse(activityText)
		if err != nil {
			return Record{}, fmt.Errorf("audit: 活動標識無法解析（%s）: %w", activityText, err)
		}
		rec.ActivityID = activityID
	}
	if !actorID.Valid {
		// actor_id 只在主體為系統時為 NULL；其他情況讀不到主體就老實報錯。
		if actorText != string(ActorSystem) {
			return Record{}, fmt.Errorf("audit: 主體類別 %s 的記錄缺少 actor.id", actorText)
		}
	} else {
		parsed, err := idgen.Parse(actorID.String)
		if err != nil {
			return Record{}, fmt.Errorf("audit: actor.id 無法解析（%s）: %w", actorID.String, err)
		}
		rec.Actor.ID = parsed
	}
	rec.Actor.Kind = ActorKind(actorText)
	rec.Action = actionK
	rec.Target = Target{Kind: targetKind, ID: targetID.String}
	rec.Reason = reason.String
	rec.RequestID = requestID.String
	changes, err := decodeChanges(idText, changesJSON)
	if err != nil {
		return Record{}, err
	}
	rec.Changes = changes
	return rec, nil
}

// makeCursor 產生指向「這一筆之後」的游標。
func makeCursor(rec Record) string {
	return formatCursor(timeutil.ToMillis(rec.CreatedAt), rec.ID.String())
}

// formatCursor 拼出 created_at 毫秒 + 記錄標識；兩者都不可讀也能被嚴格解析回來。
func formatCursor(at int64, id string) string {
	return strconv.FormatInt(at, 10) + ":" + id
}

// parseCursor 解析游標；任何不符合形狀的輸入一律 ErrInvalidCursor（不猜、不退回起點）。
//
// 退回第一頁會是更壞的結果：呼叫端以為在翻下一頁，實際拿到的是已經看過的內容。
func parseCursor(cursor string) (int64, string, error) {
	at, id, ok := strings.Cut(cursor, ":")
	if !ok {
		return 0, "", ErrInvalidCursor
	}
	ms, err := strconv.ParseInt(at, 10, 64)
	if err != nil || ms <= 0 {
		return 0, "", ErrInvalidCursor
	}
	parsed, err := idgen.Parse(id)
	if err != nil {
		return 0, "", ErrInvalidCursor
	}
	return ms, parsed.String(), nil
}

// nullableID 把零值標識存成 NULL（而不是「全零的那串字」）。
func nullableID(id idgen.ID) any {
	if id.IsNil() {
		return nil
	}
	return id.String()
}

// nullableText 把空字串存成 NULL。
//
// 「沒有原因」與「原因是一個空字串」在審計裡是同一件事，沒有保留兩者的價值；
// 而 NULL 讓「這欄本來就不適用」在查詢裡一眼可辨。
func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}
