// store.go 是活動與活動管理權指派的持久倉儲：把「一個活動長什麼樣、現在處於哪一態」
// 讀寫在 activities 表上，把「哪個帳戶管哪個活動」讀寫在 activity_manager_grants 表上
// （見遷移 0012）。
//
// 與 internal/account、internal/invitecode 的倉儲同一取向：一律接受 database.Querier，
// 自己不開交易——「活動改一欄」與「記一筆審計」必須同生同滅，那句話只有把兩者交給
// 同一個 *database.Tx 才成立；倉儲自開會把一次動作拆成兩段。
//
// 三條寫在形狀上的規定：
//   - 主鍵與時刻不給呼叫端填。id 由 idgen 產生、時刻由注入時鐘換算，
//     「什麼時候建立的」「這是哪一個活動」因此各只有一個答案。
//   - 狀態與資料的改動都是帶 WHERE 的單向 UPDATE：贏家與落敗者由 RowsAffected 分辨，
//     而不是先查後寫假裝那個視窗不存在。改動現值時一併推進 updated_at，
//     歸檔那一跳同時寫 archived_at（狀態與時刻同生同滅由資料庫 CHECK 釘住）。
//   - 指向帳戶的兩個欄位是無外鍵軟參照（見遷移 0012 檔頭）：本倉儲因此不對
//     「帳戶行還在不在」做任何假設——軟參照的意義正是「歷史指向原標識，不搬不刪」，
//     帳戶被軟刪除後行與標識仍保留，這一份參照永遠解析得到。
package activity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// ErrNotFound 表示按標識讀不到活動。它與資料庫故障刻意分開：
// 呼叫端拿活動標識來查，查不到多半是競態的尾巴或幽靈標識，屬可解釋的業務結論；
// 查不了才是需要報錯的缺陷。服務層把它換成對外的 ErrActivityNotFound（見 create.go 頭注）。
var ErrNotFound = errors.New("activity: 找不到對應的活動")

// Store 是活動與指派的持久倉儲。零值不可用，請經 NewStore 取得。
type Store struct {
	clock timeutil.Clock
	// newID 以欄位持有是為了讓測試注入失敗情境，驗證產生失敗時拒絕寫入而非降級格式。
	newID func() (idgen.ID, error)
}

// NewStore 建立活動倉儲；clock 為 nil 時採用 timeutil.System()。
func NewStore(clock timeutil.Clock) *Store {
	if clock == nil {
		clock = timeutil.System()
	}
	return &Store{clock: clock, newID: idgen.New}
}

// CreateInput 是建立一個活動的倉儲輸入。
//
// 不含 ID、不含建立時刻、不含狀態——那三樣各有唯一產生點（idgen、注入時鐘、
// 「新建的活動一律是草稿」這條領域規則）。讓呼叫端代填等於把
// 「這是什麼時候建的活動」「它一出生算不算正在進行」交給請求鏈上的某一環。
type CreateInput struct {
	// Name 是透過域校驗的活動名稱。
	Name string
	// Description 是透過域校驗的活動描述（可為空字串）。
	Description string
	// CreatedBy 是建立者的帳戶標識；Root 建立時為零值（Root 不在 accounts 表裡）。
	CreatedBy idgen.ID
}

// rowColumns 是 activities 的共用讀取欄位順序：任何一條讀法都從這裡長出來，
// 於是「詳情讀到的」與「目錄讀到的」不可能各說各話。
const rowColumns = `a.id, a.name, a.description, a.status, a.created_by_account_id,
		a.created_at, a.updated_at, a.archived_at,
		(SELECT COUNT(*) FROM activity_manager_grants g WHERE g.activity_id = a.id)`

// rowScanner 是「一列結果可被掃描」的最小形狀：*sql.Rows 與 *sql.Row 都滿足，
// 目錄與單筆讀法因此共用同一份解析，不會各寫一份而日後漂移。
type rowScanner interface {
	Scan(dest ...any) error
}

// scanRow 把一列 activities 讀成 Activity（managerCount 由 rowColumns 的子查詢給）。
//
// *sql.Rows 與 *sql.Row 都滿足 rowScanner，兩條讀法因此共用同一份解析。
func scanRow(rows rowScanner) (Activity, error) {
	var (
		idText, name, description, statusText string
		createdBy                             sql.NullString
		createdAt, updatedAt                  int64
		archivedAt                            sql.NullInt64
		managers                              int64
	)
	if err := rows.Scan(&idText, &name, &description, &statusText, &createdBy,
		&createdAt, &updatedAt, &archivedAt, &managers); err != nil {
		return Activity{}, fmt.Errorf("activity: 解析活動行失敗: %w", err)
	}
	id, err := idgen.Parse(idText)
	if err != nil {
		return Activity{}, fmt.Errorf("%w：活動行的標識 %q 不是正規標識: %w", ErrNotFound, idText, err)
	}
	status, err := ParseStatus(statusText)
	if err != nil {
		// 資料庫裡出現封閉集合之外的狀態屬資料缺陷，不能降級成「當成草稿處理」：
		// 後者會讓一個被外部工具改壞的行繼續接受寫入。
		return Activity{}, fmt.Errorf("%w：活動 %s 的狀態 %q 不認識: %w", ErrNotFound, idText, statusText, err)
	}
	// 建立者是軟參照：Root 建的活動這一格是 NULL（語意是「帳戶層沒有發起人」，
	// 不是「發起人標識讀壞了」），其餘行必須讀得出正規標識——讀不出屬資料缺陷。
	var creator idgen.ID
	if createdBy.Valid {
		creator, err = idgen.Parse(createdBy.String)
		if err != nil {
			return Activity{}, fmt.Errorf("%w：活動 %s 的建立者標識不合法: %w", ErrNotFound, idText, err)
		}
	}
	a := Activity{
		ID:                 id,
		Name:               name,
		Description:        description,
		Status:             status,
		CreatedByAccountID: creator,
		ManagerCount:       managers,
		CreatedAt:          timeutil.FromMillis(createdAt),
		UpdatedAt:          timeutil.FromMillis(updatedAt),
	}
	if archivedAt.Valid {
		a.ArchivedAt = timeutil.FromMillis(archivedAt.Int64)
	}
	return a, nil
}

// Create 寫入一個新活動並回讀它。狀態恆為草稿，時刻恆為注入時鐘。
func (s *Store) Create(ctx context.Context, q database.Querier, in CreateInput) (Activity, error) {
	if q == nil {
		return Activity{}, errors.New("activity: 需要可用的資料庫連線或交易")
	}
	id, err := s.newID()
	if err != nil {
		return Activity{}, fmt.Errorf("activity: 產生活動標識失敗: %w", err)
	}
	now := timeutil.ToMillis(s.clock.Now())
	// Root 沒有帳戶標識：這一格寫 NULL，而不是湊一個「讀不回任何人」的零值標識。
	var createdBy any
	if !in.CreatedBy.IsNil() {
		createdBy = in.CreatedBy.String()
	}
	_, err = q.ExecContext(ctx, `INSERT INTO activities
			(id, name, description, status, created_by_account_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id.String(), in.Name, in.Description, string(StatusDraft), createdBy, now, now)
	if err != nil {
		return Activity{}, fmt.Errorf("activity: 建立活動失敗: %w", err)
	}
	return s.ByID(ctx, q, id)
}

// ByID 按標識讀回一筆活動。查無時回 ErrNotFound。
func (s *Store) ByID(ctx context.Context, q database.Querier, id idgen.ID) (Activity, error) {
	if q == nil {
		return Activity{}, errors.New("activity: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return Activity{}, ErrNotFound
	}
	row := q.QueryRowContext(ctx, "SELECT "+rowColumns+" FROM activities a WHERE a.id = ?",
		id.String())
	a, err := scanRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Activity{}, ErrNotFound
	}
	return a, err
}

// ListQuery 是目錄的輸入。可見範圍由呼叫端（服務層）決定後交進來：
// 倉儲不猜「這一個人能看哪些活動」，它只按交進來的標識集合過濾。
type ListQuery struct {
	// Visible 是可見的活動標識集合；nil 表示不按標識限制（Root 的全量目錄）。
	// 空切片（非 nil）語意是「他什麼都看不到」，倉儲據此回空頁而不退化成全量。
	Visible []idgen.ID
	// StatusFilter 是狀態篩選；空字串或 all 表示不篩選。
	StatusFilter string
	// Keyword 是名稱與描述的關鍵字（呼叫端已正規化：空字串即不篩選）。
	Keyword string
	// Page 與 PageSize 由服務層校驗過（1..上限）。
	Page     int64
	PageSize int64
}

// ListPage 是一頁目錄加上符合條件的總數。
type ListPage struct {
	// Rows 是本頁的活動（依建立時刻倒序，標識破平）。
	Rows []Activity
	// Page 與 PageSize 回顯實際生效的分頁引數（呼叫端據此決定要不要翻下一頁）。
	Page     int64
	PageSize int64
	// Total 是符合篩選條件的總筆數（不受分頁影響）。
	Total int64
}

// List 讀一頁目錄。
//
// 「查無任何符合的行」與「這一頁剛好是空」是同一個結果（Rows 為空、Total 為 0），
// 不是錯誤：目錄本來就要能回空頁。
func (s *Store) List(ctx context.Context, q database.Querier, query ListQuery) (ListPage, error) {
	if q == nil {
		return ListPage{}, errors.New("activity: 需要可用的資料庫連線或交易")
	}
	where := []string{"1 = 1"}
	args := make([]any, 0, len(query.Visible)+2)
	if query.Visible != nil {
		if len(query.Visible) == 0 {
			// 一個標識都不在可見範圍內：當場回空頁，不拼出 `IN ()` 那種語法錯誤。
			return ListPage{Page: query.Page, PageSize: query.PageSize}, nil
		}
		markers := make([]string, 0, len(query.Visible))
		for _, id := range query.Visible {
			markers = append(markers, "?")
			args = append(args, id.String())
		}
		where = append(where, "a.id IN ("+strings.Join(markers, ", ")+")")
	}
	if query.StatusFilter != "" && query.StatusFilter != FilterAll {
		where = append(where, "a.status = ?")
		args = append(args, query.StatusFilter)
	}
	if query.Keyword != "" {
		where = append(where, `(a.name LIKE ? ESCAPE '\' OR a.description LIKE ? ESCAPE '\')`)
		like := "%" + escapeLikeWildcard(query.Keyword) + "%"
		args = append(args, like, like)
	}
	whereSQL := strings.Join(where, " AND ")

	var total int64
	if err := q.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM activities a WHERE "+whereSQL, args...).Scan(&total); err != nil {
		return ListPage{}, fmt.Errorf("activity: 統計目錄總數失敗: %w", err)
	}

	offset := (query.Page - 1) * query.PageSize
	rows, err := q.QueryContext(ctx, "SELECT "+rowColumns+` FROM activities a
		WHERE `+whereSQL+`
		ORDER BY a.created_at DESC, a.id DESC
		LIMIT ? OFFSET ?`, append(args, query.PageSize, offset)...)
	if err != nil {
		return ListPage{}, fmt.Errorf("activity: 讀取目錄失敗: %w", err)
	}
	defer rows.Close()

	page := ListPage{Page: query.Page, PageSize: query.PageSize, Total: total}
	for rows.Next() {
		a, err := scanRow(rows)
		if err != nil {
			return ListPage{}, err
		}
		page.Rows = append(page.Rows, a)
	}
	if err := rows.Err(); err != nil {
		return ListPage{}, fmt.Errorf("activity: 讀取目錄失敗: %w", err)
	}
	return page, nil
}

// UpdateProfile 以比較-and-set 方式編輯活動的資料欄（名稱與描述）。
//
// UPDATE 語句裡只出現 name、description、updated_at 三欄：狀態、建立者、建立時刻
// 與歸檔時刻連一個格子都沒有，「儲存普通資料不會連隱藏欄位一起覆蓋」成立在 SQL 形狀上。
// changed 為 false 表示現值已不是呼叫端所依據的那份（併發編輯落敗），此時一個字都沒落。
func (s *Store) UpdateProfile(ctx context.Context, q database.Querier, id idgen.ID,
	name, description, expectedName, expectedDescription string) (bool, error) {
	if q == nil {
		return false, errors.New("activity: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return false, ErrNotFound
	}
	res, err := q.ExecContext(ctx, `UPDATE activities
		SET name = ?, description = ?, updated_at = ?
		WHERE id = ? AND name = ? AND description = ?`,
		name, description, timeutil.ToMillis(s.clock.Now()), id.String(), expectedName, expectedDescription)
	if err != nil {
		return false, fmt.Errorf("activity: 編輯活動資料失敗: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("activity: 編輯活動資料後確認寫入筆數失敗: %w", err)
	}
	return affected == 1, nil
}

// UpdateStatus 以帶 WHERE 的單向 UPDATE 把活動從 from 推到 to。
//
// 守衛取的是「此刻庫裡的狀態等於你以為的那個狀態」這個可觀測事實，
// 而不是呼叫端交來的依據值——操作者手上的現值有沒有過期，答案只能由資料庫給。
// 進入歸檔時一併寫 archived_at（與狀態同生同滅，見遷移 0012 的成對 CHECK）；
// 其餘轉換不動 archived_at，因為非歸檔態那一欄恆為 NULL。
func (s *Store) UpdateStatus(ctx context.Context, q database.Querier, id idgen.ID,
	from, to Status) (bool, error) {
	if q == nil {
		return false, errors.New("activity: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return false, ErrNotFound
	}
	now := timeutil.ToMillis(s.clock.Now())
	var (
		statement string
		args      []any
	)
	if to == StatusArchived {
		statement = `UPDATE activities
			SET status = ?, archived_at = ?, updated_at = ?
			WHERE id = ? AND status = ? AND archived_at IS NULL`
		args = []any{string(to), now, now, id.String(), string(from)}
	} else {
		statement = `UPDATE activities
			SET status = ?, updated_at = ?
			WHERE id = ? AND status = ?`
		args = []any{string(to), now, id.String(), string(from)}
	}
	res, err := q.ExecContext(ctx, statement, args...)
	if err != nil {
		return false, fmt.Errorf("activity: 轉換活動狀態失敗: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("activity: 轉換活動狀態後確認寫入筆數失敗: %w", err)
	}
	return affected == 1, nil
}

// ManagedActivityIDs 讀出一個帳戶被指派為管理人的全部活動標識。
//
// 這是「活動管理權的落庫來源」唯一的讀取點（補上 R1-006 留的空位）：
// identity.AuthorizeActivityScope 與目錄可見範圍吃的都是這一條查詢的結果，
// 各端點不得自己查本表湊一份清單，否則會出現兩套隔離語意（其中一套總會被繞過）。
func (s *Store) ManagedActivityIDs(ctx context.Context, q database.Querier,
	accountID idgen.ID) ([]idgen.ID, error) {
	if q == nil {
		return nil, errors.New("activity: 需要可用的資料庫連線或交易")
	}
	if accountID.IsNil() {
		// 零值帳戶標識查出來應該是「什麼都沒有」，而不是「整張表」：
		// Root 與系統主體不帶帳戶標識，它們的清單由服務層另外決定（見 grantsOf）。
		return nil, nil
	}
	rows, err := q.QueryContext(ctx, `SELECT activity_id FROM activity_manager_grants
		WHERE account_id = ? ORDER BY granted_at DESC, activity_id DESC`, accountID.String())
	if err != nil {
		return nil, fmt.Errorf("activity: 讀取指派清單失敗: %w", err)
	}
	defer rows.Close()

	var ids []idgen.ID
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return nil, fmt.Errorf("activity: 解析指派行失敗: %w", err)
		}
		id, err := idgen.Parse(text)
		if err != nil {
			return nil, fmt.Errorf("activity: 指派行的活動標識 %q 不合法: %w", text, err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("activity: 讀取指派清單失敗: %w", err)
	}
	return ids, nil
}

// AssignManager 寫下一筆指派。已存在同一配對時回 false（呼叫端據此回報重複衝突）。
//
// 先讀再寫不是正確性來源——主鍵 (activity_id, account_id) 才是——它給的是
// 一句可判讀的「他已經就是了」，而不是把約束違反的原始錯誤丟給上層猜。
func (s *Store) AssignManager(ctx context.Context, q database.Querier,
	activityID, accountID idgen.ID) (bool, error) {
	if q == nil {
		return false, errors.New("activity: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() || accountID.IsNil() {
		return false, ErrManagerNotFound
	}
	var exists int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM activity_manager_grants
		WHERE activity_id = ? AND account_id = ?`, activityID.String(), accountID.String()).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("activity: 核實既有指派失敗: %w", err)
	}
	if exists > 0 {
		return false, nil
	}
	if _, err := q.ExecContext(ctx, `INSERT INTO activity_manager_grants
			(activity_id, account_id, granted_at) VALUES (?, ?, ?)`,
		activityID.String(), accountID.String(), timeutil.ToMillis(s.clock.Now())); err != nil {
		return false, fmt.Errorf("activity: 寫下指派失敗: %w", err)
	}
	return true, nil
}

// RevokeManager 撤銷一筆指派。回傳是否真的刪掉了一行——
// 「本來就沒有這個指派」不是錯誤，但必須能被呼叫端辨認（它要回一句查無此項）。
func (s *Store) RevokeManager(ctx context.Context, q database.Querier,
	activityID, accountID idgen.ID) (bool, error) {
	if q == nil {
		return false, errors.New("activity: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() || accountID.IsNil() {
		return false, ErrManagerNotFound
	}
	res, err := q.ExecContext(ctx, `DELETE FROM activity_manager_grants
		WHERE activity_id = ? AND account_id = ?`, activityID.String(), accountID.String())
	if err != nil {
		return false, fmt.Errorf("activity: 撤銷指派失敗: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("activity: 撤銷指派後確認筆數失敗: %w", err)
	}
	return affected == 1, nil
}

// ManagerRow 是一行指派的可展示事實。
type ManagerRow struct {
	// AccountID 為被指派為管理人的帳戶標識。
	AccountID idgen.ID
	// GrantedAt 為指派寫下的時刻（注入時鐘，不接受呼叫端代填）。
	GrantedAt time.Time
}

// Managers 讀出某個活動的全部管理人指派（依授予時刻倒序，標識破平）。
func (s *Store) Managers(ctx context.Context, q database.Querier,
	activityID idgen.ID) ([]ManagerRow, error) {
	if q == nil {
		return nil, errors.New("activity: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() {
		return nil, ErrNotFound
	}
	rows, err := q.QueryContext(ctx, `SELECT account_id, granted_at FROM activity_manager_grants
		WHERE activity_id = ? ORDER BY granted_at DESC, account_id DESC`, activityID.String())
	if err != nil {
		return nil, fmt.Errorf("activity: 讀取管理人清單失敗: %w", err)
	}
	defer rows.Close()

	var out []ManagerRow
	for rows.Next() {
		var (
			text string
			at   int64
		)
		if err := rows.Scan(&text, &at); err != nil {
			return nil, fmt.Errorf("activity: 解析管理人行失敗: %w", err)
		}
		id, err := idgen.Parse(text)
		if err != nil {
			return nil, fmt.Errorf("activity: 管理人行的帳戶標識 %q 不合法: %w", text, err)
		}
		out = append(out, ManagerRow{AccountID: id, GrantedAt: timeutil.FromMillis(at)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("activity: 讀取管理人清單失敗: %w", err)
	}
	return out, nil
}

// escapeLikeWildcard 把 LIKE 的通配與轉義字元本身還原成字面字元
// （與 internal/invitecode、internal/acctreview 同實現：關鍵字是一段子文字串，
// 不該有能力表達「任意字元」或「開頭是」）。
func escapeLikeWildcard(s string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(s)
}
