// tagstore.go 是標籤定義的持久倉儲：把「一個活動裡有哪些標籤、每一行長什麼樣」
// 讀寫在 activity_tags 表上（見遷移 0017）。
//
// 與本套件其余倉儲同一取向（見 store.go 頭注）：一律接受 database.Querier、
// 自己不開交易——「標籤改一欄」與「記一筆審計」必須同生同滅，那句話只有把兩者
// 交給同一個 *database.Tx 才成立。
//
// 四條寫在形狀上的規定：
//   - 主鍵、歸屬與時刻不給呼叫端填。id 由 idgen 產生、活動標識由用例在作用域判定後
//     交進來、時刻由注入時鐘換算——「這是哪一枚標籤」「屬於哪場活動」「何時建的」
//     各只有一個答案。公開旗標也不給呼叫端填：新建一律內部（見 tags.go 的理由）。
//   - 資料改動是帶 WHERE 的比較-and-set：UPDATE 語句裡只出現七欄白名單資料與
//     updated_at，id、activity_id、created_at 連一個格子都沒有，
//     「儲存標籤資料不會連身份與歸屬一起覆蓋」成立在 SQL 形狀上。
//   - 同活動名稱唯一由 UNIQUE (activity_id, name) 把關：先查只是友善錯誤來源，
//     併發下的正確性來自資料庫約束與單寫者交易串行。
//   - 玩家那一側的讀法（PublicTags）把「只看公開」寫在 SQL 的 WHERE 裡，而不是讀全量
//     再在記憶體裡篩：這樣一來「內部定義被遞出去」需要有人主動繞開這條倉儲讀法，
//     而不是某一處忘了 filter。
package activity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// tagColumns 是 activity_tags 的共用讀取欄位順序：任何一條讀法都從這裡長出來，
// 於是「列表讀到的」與「編輯後回讀的」不可能各說各話。
const tagColumns = `id, activity_id, name, description, icon, color,
		sort_order, available, public, created_at, updated_at`

// scanTagRow 把一列 activity_tags 讀成 Tag。
//
// available 與 public 以 INTEGER 0/1 存放（遷移 0017 的 CHECK 封閉了取值集合），讀回時
// 非零即真是唯一可能的解讀；標識讀不出正規形狀屬資料缺陷，不降級成「查無此標籤」——
// 後者會把一次寫壞的行變成一個安靜消失的標籤。
func scanTagRow(rows interface{ Scan(dest ...any) error }) (Tag, error) {
	var (
		idText, activityIDText         string
		name, description, icon, color string
		sortOrder, available, public   int64
		createdAt, updatedAt           int64
	)
	if err := rows.Scan(&idText, &activityIDText, &name, &description, &icon, &color,
		&sortOrder, &available, &public, &createdAt, &updatedAt); err != nil {
		return Tag{}, fmt.Errorf("tag: 解析標籤行失敗: %w", err)
	}
	id, err := idgen.Parse(idText)
	if err != nil {
		return Tag{}, fmt.Errorf("tag: 標籤行的標識 %q 不是正規標識: %w", idText, err)
	}
	activityID, err := idgen.Parse(activityIDText)
	if err != nil {
		return Tag{}, fmt.Errorf("tag: 標籤行 %s 的活動標識 %q 不合法: %w", idText, activityIDText, err)
	}
	return Tag{
		ID: id, ActivityID: activityID, Name: name, Description: description,
		Icon: icon, Color: color, SortOrder: sortOrder,
		Available: available != 0, Public: public != 0,
		CreatedAt: timeutil.FromMillis(createdAt), UpdatedAt: timeutil.FromMillis(updatedAt),
	}, nil
}

// TagFields 是標籤可編輯的七欄白名單資料（新值與依據值共用同一個型別）。
//
// 七欄之外沒有任何東西：標識、歸屬活動、建立時刻都不在這裡——它們不是「一筆編輯」
// 能表達的事實（口徑同陣營那條六欄白名單，只是本表多一欄公開旗標）。
type TagFields struct {
	// Name／Description／Icon／Color 是展示資料（前兩欄透過域校驗，後兩欄是封閉集合與緊格式）。
	Name        string
	Description string
	Icon        string
	Color       string
	// SortOrder 是列表排序值（0..上界）。
	SortOrder int64
	// Available 是可用性旗標（假＝停用，不再接收新的貼標請求；既有引用一律不動）。
	Available bool
	// Public 是玩家公開旗標（假＝僅管理面讀得到這份定義，出廠值）。
	Public bool
}

// TagEdit 是倉儲的一筆標籤編輯意圖：七欄新值加七欄「提交所依據的現值」。
//
// 依據值不做域校驗——它們描述的是呼叫端看見的舊世界，舊世界裡可能有當時合法的寫法；
// 正確性錨在「庫裡此刻的七欄等於你依據的那七欄」這條可觀測事實上。
type TagEdit struct {
	// New 是新的七欄白名單值。
	New TagFields
	// Expected 是提交所依據的七欄現值。
	Expected TagFields
}

// TagCreateInput 是建立一枚標籤的倉儲輸入。
//
// 不含 ID、不含建立時刻、不含可用性、也不含公開旗標——那幾樣各有唯一產生點（idgen、
// 注入時鐘、「新建的標籤一律可用」與「新建的標籤一律不公開」兩條領域規則，見 tags.go）。
// 讓呼叫端代填等於把「這枚標籤一出生就能被普通玩家讀到」交給請求鏈上的某一環。
type TagCreateInput struct {
	// ActivityID 是作用域判定已核實的歸屬活動。
	ActivityID idgen.ID
	// Name 是透過域校驗、且已核實同活動內未與他人重名的標籤名稱。
	Name string
	// Description 是透過域校驗的標籤描述（可為空字串）。
	Description string
	// Icon 是命中封閉集合的圖標鍵（空字串＝未選）。
	Icon string
	// Color 是正規化後的顏色（空字串＝未選色）。
	Color string
	// SortOrder 是最終生效的排序值（呼叫端未指定時由服務層現算排尾值）。
	SortOrder int64
}

// CreateTag 寫入一枚新標籤並回讀它。可用性恆為真、公開恆為假，時刻恆為注入時鐘。
func (s *Store) CreateTag(ctx context.Context, q database.Querier, in TagCreateInput) (Tag, error) {
	if q == nil {
		return Tag{}, errors.New("tag: 需要可用的資料庫連線或交易")
	}
	if in.ActivityID.IsNil() {
		return Tag{}, ErrTagNotFound
	}
	id, err := s.newID()
	if err != nil {
		return Tag{}, fmt.Errorf("tag: 產生標籤標識失敗: %w", err)
	}
	now := timeutil.ToMillis(s.clock.Now())
	_, err = q.ExecContext(ctx, `INSERT INTO activity_tags
			(id, activity_id, name, description, icon, color, sort_order,
			 available, public, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)`,
		id.String(), in.ActivityID.String(), in.Name, in.Description, in.Icon, in.Color,
		in.SortOrder, now, now)
	if err != nil {
		return Tag{}, fmt.Errorf("tag: 建立標籤失敗: %w", err)
	}
	return s.TagByID(ctx, q, id)
}

// TagByID 按標識讀回一筆標籤定義（管理側讀法：不問公開旗標）。
//
// 查無時回 ErrTagNotFound。這一條讀法刻意不篩 public——「內部定義讀得到」是管理面本來就
// 有的能力，而玩家那一族的不可分辨由 PublicTagByID（另一條 SQL）負責，不靠呼叫端記得 filter。
func (s *Store) TagByID(ctx context.Context, q database.Querier, id idgen.ID) (Tag, error) {
	if q == nil {
		return Tag{}, errors.New("tag: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return Tag{}, ErrTagNotFound
	}
	row := q.QueryRowContext(ctx,
		"SELECT "+tagColumns+" FROM activity_tags WHERE id = ?", id.String())
	tag, err := scanTagRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Tag{}, ErrTagNotFound
	}
	return tag, err
}

// Tags 讀出一個活動的全部標籤（含內部定義，依排序值、建立時刻、標識升序）。
//
// 「這個活動還沒有標籤」與「活動查無」在這裡是分開的：倉儲假設呼叫端已核實活動存在
// （見 tags.go 的列表用例），空列表就是空列表這個事實，不是錯誤。
// 破平規則是穩定且可解釋的：同排序值時先到先排（UUIDv7 標識本身按時間單調，末位破平
// 讓新建立的落在同值段的尾部），界面上的上下移不需要第二份「手動次序表」。
func (s *Store) Tags(ctx context.Context, q database.Querier,
	activityID idgen.ID) ([]Tag, error) {
	if q == nil {
		return nil, errors.New("tag: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() {
		return nil, ErrTagNotFound
	}
	return s.queryTags(ctx, q, `SELECT `+tagColumns+` FROM activity_tags
		WHERE activity_id = ?
		ORDER BY sort_order ASC, created_at ASC, id ASC`, activityID)
}

// PublicTags 讀出一個活動裡「對普通玩家公開」的那幾枚標籤定義。
//
// 篩選落在 SQL 的 WHERE 上（public = 1），因此這一條讀法從結構上就不可能遞出內部定義；
// 排序與 Tags 逐字同形，於是玩家看到的相對次序與管理員看到的那一份是同一個算式的結果。
func (s *Store) PublicTags(ctx context.Context, q database.Querier,
	activityID idgen.ID) ([]Tag, error) {
	if q == nil {
		return nil, errors.New("tag: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() {
		return nil, ErrTagNotFound
	}
	return s.queryTags(ctx, q, `SELECT `+tagColumns+` FROM activity_tags
		WHERE activity_id = ? AND public = 1
		ORDER BY sort_order ASC, created_at ASC, id ASC`, activityID)
}

// queryTags 把「帶條件的多行讀法」收成一個循環：兩條列表讀法共用同一份行解析與同一份
// 錯誤句子，差別只有那一句 WHERE。
func (s *Store) queryTags(ctx context.Context, q database.Querier,
	query string, activityID idgen.ID) ([]Tag, error) {
	rows, err := q.QueryContext(ctx, query, activityID.String())
	if err != nil {
		return nil, fmt.Errorf("tag: 讀取標籤列表失敗: %w", err)
	}
	defer rows.Close()

	out := make([]Tag, 0)
	for rows.Next() {
		tag, err := scanTagRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, tag)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tag: 讀取標籤列表失敗: %w", err)
	}
	return out, nil
}

// PublicTagByID 按標識讀回一筆「對普通玩家公開」的標籤定義。
//
// 「查無此標籤」與「它不屬於這個活動」與「它存在但沒被設成公開」在这一條讀法裡是同一個
// 錯誤（ErrTagNotFound）：這正是玩家那一族需要的不可分辨——把「有這個標識、只是不給你讀」
// 說成另一句話，等於在玩家路徑上掛一枚內部定義的存在性探測器。
func (s *Store) PublicTagByID(ctx context.Context, q database.Querier,
	id, activityID idgen.ID) (Tag, error) {
	if q == nil {
		return Tag{}, errors.New("tag: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() || activityID.IsNil() {
		return Tag{}, ErrTagNotFound
	}
	row := q.QueryRowContext(ctx,
		"SELECT "+tagColumns+" FROM activity_tags WHERE id = ? AND activity_id = ? AND public = 1",
		id.String(), activityID.String())
	tag, err := scanTagRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Tag{}, ErrTagNotFound
	}
	return tag, err
}

// TagNameTaken 核實「同一個活動裡，這個名稱已被另一枚標籤占用」。
//
// exceptID 是編輯時要避開的自己：名稱沒改的編輯不該撞上自己的那一行。
// 這句話的正確性來源是 UNIQUE (activity_id, name)；本讀法只決定「給操作者哪一句話」，
// 併發窗口裡後到的那一跳就算漏過這裡，也會在 INSERT／UPDATE 撞約束整筆回滾。
// 跨活動同名不會走到這裡：條件裡帶的是歸屬活動。
func (s *Store) TagNameTaken(ctx context.Context, q database.Querier,
	activityID idgen.ID, name string, exceptID idgen.ID) (bool, error) {
	if q == nil {
		return false, errors.New("tag: 需要可用的資料庫連線或交易")
	}
	where := `activity_id = ? AND name = ?`
	args := []any{activityID.String(), name}
	if !exceptID.IsNil() {
		// 零值標識語意是「沒有要避開的自己」（建立通路），此時條件裡不出現 id 比較。
		where += ` AND id <> ?`
		args = append(args, exceptID.String())
	}
	var exists int
	err := q.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM activity_tags WHERE "+where, args...).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("tag: 核實標籤名稱占用失敗: %w", err)
	}
	return exists > 0, nil
}

// MaxTagSortOrder 讀出一個活動內當前最大的排序值（無標籤時回 -1，
// 於是「排到最後一格」對空表與已有表都是同一個算式：max+1，且以界內常數為上限）。
func (s *Store) MaxTagSortOrder(ctx context.Context, q database.Querier,
	activityID idgen.ID) (int64, error) {
	if q == nil {
		return -1, errors.New("tag: 需要可用的資料庫連線或交易")
	}
	var max sql.NullInt64
	err := q.QueryRowContext(ctx,
		"SELECT MAX(sort_order) FROM activity_tags WHERE activity_id = ?",
		activityID.String()).Scan(&max)
	if err != nil {
		return -1, fmt.Errorf("tag: 讀取標籤排序值上界失敗: %w", err)
	}
	if !max.Valid {
		return -1, nil
	}
	return max.Int64, nil
}

// UpdateTag 以比較-and-set 方式編輯一筆標籤的七欄白名單資料。
//
// UPDATE 語句裡只出現 name、description、icon、color、sort_order、available、public 與
// updated_at：id、activity_id、created_at 連一個格子都沒有，因此「儲存標籤資料不會連身份、
// 歸屬與建立時刻一起覆蓋」不需要約定，它成立在 SQL 形狀上（口徑同 UpdateFaction）。
// changed 為 false 表示現值已不是呼叫端所依據的那份（併發編輯落敗），此時一個字都沒落。
func (s *Store) UpdateTag(ctx context.Context, q database.Querier, id, activityID idgen.ID,
	edit TagEdit) (bool, error) {
	if q == nil {
		return false, errors.New("tag: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() || activityID.IsNil() {
		return false, ErrTagNotFound
	}
	res, err := q.ExecContext(ctx, `UPDATE activity_tags
		SET name = ?, description = ?, icon = ?, color = ?, sort_order = ?,
		    available = ?, public = ?, updated_at = ?
		WHERE id = ? AND activity_id = ?
		  AND name = ? AND description = ? AND icon = ? AND color = ? AND sort_order = ?
		  AND available = ? AND public = ?`,
		edit.New.Name, edit.New.Description, edit.New.Icon, edit.New.Color, edit.New.SortOrder,
		boolToInt64(edit.New.Available), boolToInt64(edit.New.Public),
		timeutil.ToMillis(s.clock.Now()),
		id.String(), activityID.String(),
		edit.Expected.Name, edit.Expected.Description, edit.Expected.Icon, edit.Expected.Color,
		edit.Expected.SortOrder, boolToInt64(edit.Expected.Available), boolToInt64(edit.Expected.Public))
	if err != nil {
		return false, fmt.Errorf("tag: 編輯標籤資料失敗: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("tag: 編輯標籤資料後確認寫入筆數失敗: %w", err)
	}
	return affected == 1, nil
}

// boolToInt64 把布林換成落進 SQL 的 0/1：新值與依據值都走同一個換算，
// 於是比較的是「可觀測的庫中形態」而不是呼叫端的說法（口徑同 UpdateFaction 裡那兩格）。
func boolToInt64(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
