// factionstore.go 是陣營的持久倉儲：把「一個活動裡有哪些陣營、每一行長什麼樣」
// 讀寫在 activity_factions 表上（見遷移 0013）。
//
// 與本套件其余倉儲同一取向（見 store.go 頭注）：一律接受 database.Querier、
// 自己不開交易——「陣營改一欄」與「記一筆審計」必須同生同滅，那句話只有把兩者
// 交給同一個 *database.Tx 才成立。
//
// 三條寫在形狀上的規定：
//   - 主鍵、歸屬與時刻不給呼叫端填。id 由 idgen 產生、活動標識由用例在作用域判定後
//     交進來、時刻由注入時鐘換算——「這是哪一個陣營」「屬於哪場活動」「何時建的」
//     各只有一個答案。
//   - 資料改動是帶 WHERE 的比較-and-set：UPDATE 語句裡只出現六欄白名單資料與
//     updated_at，id、activity_id、created_at 連一個格子都沒有，
//     「儲存陣營資料不會連身份與歸屬一起覆蓋」成立在 SQL 形狀上。
//   - 同活動名稱唯一由 UNIQUE (activity_id, name) 把關：先查只是友善錯誤來源，
//     併發下的正確性來自資料庫約束與單寫者交易串行。
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

// factionColumns 是 activity_factions 的共用讀取欄位順序：任何一條讀法都從這裡長出來，
// 於是「列表讀到的」與「編輯後回讀的」不可能各說各話。
const factionColumns = `id, activity_id, name, description, icon, color,
		sort_order, available, created_at, updated_at`

// scanFactionRow 把一列 activity_factions 讀成 Faction。
//
// available 以 INTEGER 0/1 存放（遷移 0013 的 CHECK 封閉了取值集合），讀回時
// 非零即真是唯一可能的解讀；標識讀不出正規形狀屬資料缺陷，不降級成「查無此陣營」——
// 後者會把一次寫壞的行變成一個安靜消失的陣營。
func scanFactionRow(rows interface{ Scan(dest ...any) error }) (Faction, error) {
	var (
		idText, activityIDText         string
		name, description, icon, color string
		sortOrder, available           int64
		createdAt, updatedAt           int64
	)
	if err := rows.Scan(&idText, &activityIDText, &name, &description, &icon, &color,
		&sortOrder, &available, &createdAt, &updatedAt); err != nil {
		return Faction{}, fmt.Errorf("faction: 解析陣營行失敗: %w", err)
	}
	id, err := idgen.Parse(idText)
	if err != nil {
		return Faction{}, fmt.Errorf("faction: 陣營行的標識 %q 不是正規標識: %w", idText, err)
	}
	activityID, err := idgen.Parse(activityIDText)
	if err != nil {
		return Faction{}, fmt.Errorf("faction: 陣營行 %s 的活動標識 %q 不合法: %w", idText, activityIDText, err)
	}
	return Faction{
		ID: id, ActivityID: activityID, Name: name, Description: description,
		Icon: icon, Color: color, SortOrder: sortOrder, Available: available != 0,
		CreatedAt: timeutil.FromMillis(createdAt), UpdatedAt: timeutil.FromMillis(updatedAt),
	}, nil
}

// FactionCreateInput 是建立一個陣營的倉儲輸入。
//
// 不含 ID、不含建立時刻、不含可用性——那三樣各有唯一產生點（idgen、注入時鐘、
// 「新建的陣營一律可用」這條領域規則，見 factions.go）。讓呼叫端代填等於把
// 「這是什麼時候誕生的陣營」「它一出生算不算停用」交給請求鏈上的某一環。
type FactionCreateInput struct {
	// ActivityID 是作用域判定已核實的歸屬活動。
	ActivityID idgen.ID
	// Name 是透過域校驗、且已核實同活動內未與他人重名的陣營名稱。
	Name string
	// Description 是透過域校驗的陣營描述（可為空字串）。
	Description string
	// Icon 是命中封閉集合的圖標鍵（空字串＝未選）。
	Icon string
	// Color 是正規化後的顏色（空字串＝未選色）。
	Color string
	// SortOrder 是最終生效的排序值（呼叫端未指定時由服務層現算排尾值）。
	SortOrder int64
}

// CreateFaction 寫入一個新陣營並回讀它。可用性恆為真，時刻恆為注入時鐘。
func (s *Store) CreateFaction(ctx context.Context, q database.Querier, in FactionCreateInput) (Faction, error) {
	if q == nil {
		return Faction{}, errors.New("faction: 需要可用的資料庫連線或交易")
	}
	if in.ActivityID.IsNil() {
		return Faction{}, ErrFactionNotFound
	}
	id, err := s.newID()
	if err != nil {
		return Faction{}, fmt.Errorf("faction: 產生陣營標識失敗: %w", err)
	}
	now := timeutil.ToMillis(s.clock.Now())
	_, err = q.ExecContext(ctx, `INSERT INTO activity_factions
			(id, activity_id, name, description, icon, color, sort_order, available, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
		id.String(), in.ActivityID.String(), in.Name, in.Description, in.Icon, in.Color,
		in.SortOrder, now, now)
	if err != nil {
		return Faction{}, fmt.Errorf("faction: 建立陣營失敗: %w", err)
	}
	return s.FactionByID(ctx, q, id)
}

// FactionByID 按標識讀回一筆陣營。查無時回 ErrFactionNotFound。
func (s *Store) FactionByID(ctx context.Context, q database.Querier, id idgen.ID) (Faction, error) {
	if q == nil {
		return Faction{}, errors.New("faction: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return Faction{}, ErrFactionNotFound
	}
	row := q.QueryRowContext(ctx,
		"SELECT "+factionColumns+" FROM activity_factions WHERE id = ?", id.String())
	faction, err := scanFactionRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Faction{}, ErrFactionNotFound
	}
	return faction, err
}

// Factions 讀出一個活動的全部陣營（依排序值、建立時刻、標識升序）。
//
// 「這個活動還沒有陣營」與「活動查無」在這裡是分開的：倉儲假設呼叫端已核實活動存在
// （見 factions.go 的列表用例），空列表就是空列表這個事實，不是錯誤。
// 破平規則是穩定且可解釋的：同排序值時先到先排（UUIDv7 標識本身按時間單調，末位破平
// 讓新建立的落在同值段的尾部），界面上的上下移不需要第二份「手動次序表」。
func (s *Store) Factions(ctx context.Context, q database.Querier,
	activityID idgen.ID) ([]Faction, error) {
	if q == nil {
		return nil, errors.New("faction: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() {
		return nil, ErrFactionNotFound
	}
	rows, err := q.QueryContext(ctx, `SELECT `+factionColumns+` FROM activity_factions
		WHERE activity_id = ?
		ORDER BY sort_order ASC, created_at ASC, id ASC`, activityID.String())
	if err != nil {
		return nil, fmt.Errorf("faction: 讀取陣營列表失敗: %w", err)
	}
	defer rows.Close()

	out := make([]Faction, 0)
	for rows.Next() {
		faction, err := scanFactionRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, faction)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("faction: 讀取陣營列表失敗: %w", err)
	}
	return out, nil
}

// FactionNameTaken 核實「同一個活動裡，這個名稱已被另一個陣營占用」。
//
// exceptID 是編輯時要避開的自己：名稱沒改的編輯不該撞上自己的那一行。
// 這句話的正確性來源是 UNIQUE (activity_id, name)；本讀法只決定「給操作者哪一句話」，
// 併發窗口裡後到的那一跳就算漏過這裡，也會在 INSERT／UPDATE 撞約束整筆回滾。
func (s *Store) FactionNameTaken(ctx context.Context, q database.Querier,
	activityID idgen.ID, name string, exceptID idgen.ID) (bool, error) {
	if q == nil {
		return false, errors.New("faction: 需要可用的資料庫連線或交易")
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
		"SELECT COUNT(*) FROM activity_factions WHERE "+where, args...).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("faction: 核實陣營名稱占用失敗: %w", err)
	}
	return exists > 0, nil
}

// MaxFactionSortOrder 讀出一個活動內當前最大的排序值（無陣營時回 -1，
// 於是「排到最後一格」對空表與已有表都是同一個算式：max+1，且以界內常數為上限）。
func (s *Store) MaxFactionSortOrder(ctx context.Context, q database.Querier,
	activityID idgen.ID) (int64, error) {
	if q == nil {
		return -1, errors.New("faction: 需要可用的資料庫連線或交易")
	}
	var max sql.NullInt64
	err := q.QueryRowContext(ctx,
		"SELECT MAX(sort_order) FROM activity_factions WHERE activity_id = ?",
		activityID.String()).Scan(&max)
	if err != nil {
		return -1, fmt.Errorf("faction: 讀取排序值上界失敗: %w", err)
	}
	if !max.Valid {
		return -1, nil
	}
	return max.Int64, nil
}

// UpdateFaction 以比較-and-set 方式編輯陣營的六欄白名單資料。
//
// UPDATE 語句裡只出現 name、description、icon、color、sort_order、available、updated_at
// 七欄：id、activity_id、created_at 連一個格子都沒有，因此「儲存陣營資料不會連身份、
// 歸屬與建立時刻一起覆蓋」不需要約定，它成立在 SQL 形狀上（口徑同活動的 UpdateProfile）。
// changed 為 false 表示現值已不是呼叫端所依據的那份（併發編輯落敗），此時一個字都沒落。
func (s *Store) UpdateFaction(ctx context.Context, q database.Querier, id, activityID idgen.ID,
	name, description, icon, color string, sortOrder int64, available bool,
	expectedName, expectedDescription, expectedIcon, expectedColor string,
	expectedSortOrder int64, expectedAvailable bool) (bool, error) {
	if q == nil {
		return false, errors.New("faction: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() || activityID.IsNil() {
		return false, ErrFactionNotFound
	}
	// 依據值裡的布林同樣以 0/1 落進 WHERE：比較的是可觀測的庫中形態，不是呼叫端的說法。
	var wantAvailable int64
	if expectedAvailable {
		wantAvailable = 1
	}
	var setAvailable int64
	if available {
		setAvailable = 1
	}
	res, err := q.ExecContext(ctx, `UPDATE activity_factions
		SET name = ?, description = ?, icon = ?, color = ?, sort_order = ?, available = ?, updated_at = ?
		WHERE id = ? AND activity_id = ?
		  AND name = ? AND description = ? AND icon = ? AND color = ? AND sort_order = ? AND available = ?`,
		name, description, icon, color, sortOrder, setAvailable, timeutil.ToMillis(s.clock.Now()),
		id.String(), activityID.String(),
		expectedName, expectedDescription, expectedIcon, expectedColor, expectedSortOrder, wantAvailable)
	if err != nil {
		return false, fmt.Errorf("faction: 編輯陣營資料失敗: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("faction: 編輯陣營資料後確認寫入筆數失敗: %w", err)
	}
	return affected == 1, nil
}
