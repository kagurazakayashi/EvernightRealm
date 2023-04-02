// statusstore.go 是玩家業務狀態的持久倉儲：活動層級的內建顯示名稱覆蓋、
// 自訂狀態定義，以及成員那一欄目前狀態。
//
// 與本套件其余倉儲同一取向：一律接受 database.Querier，自己不開交易——
// 「改一欄」與「記一筆審計」必須同生同滅，那句話只有把兩者交給同一個 *database.Tx 才成立。
//
// 寫在形狀上的四條規定：
//   - 內建鍵、活動歸屬與自訂定義標識不給呼叫端代填。標識由 idgen 產生、時刻由注入時鐘
//     換算；請求裡沒有格子能宣告「這是哪一場活動的哪一個定義」。
//   - 顯示名稱覆蓋的恢復預設是「把那一欄清成空字串」或刪掉那一行，不是刪除一個狀態；
//     比較-and-set 讓「依據值已過期」的編輯一個字都不落。
//   - 自訂狀態只有改名與可用性兩欄可改：id、activity_id、created_at 連一個格子都沒有，
//     因此改名或停用不會把定義連同歷史搬到別場活動，也不會更換標識。
//   - 成員狀態的更新只碰 business_status、business_status_custom_id 與 updated_at；
//     兩欄成對比較，custom 指向哪一個定義也由服務層在同一個交易內現讀核實。
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

// customStatusColumns 是 activity_player_statuses 的共用讀取欄位順序。
const customStatusColumns = `id, activity_id, name, available, created_at, updated_at`

// scanCustomStatusRow 把一列自訂狀態定義讀成 CustomStatus。
func scanCustomStatusRow(rows interface{ Scan(dest ...any) error }) (CustomStatus, error) {
	var (
		idText, activityIDText string
		name                   string
		available              int64
		createdAt, updatedAt   int64
	)
	if err := rows.Scan(&idText, &activityIDText, &name, &available,
		&createdAt, &updatedAt); err != nil {
		return CustomStatus{}, fmt.Errorf("businessstatus: 解析自訂狀態行失敗: %w", err)
	}
	id, err := idgen.Parse(idText)
	if err != nil {
		return CustomStatus{}, fmt.Errorf("businessstatus: 自訂狀態行的標識 %q 不是正規標識: %w",
			idText, err)
	}
	activityID, err := idgen.Parse(activityIDText)
	if err != nil {
		return CustomStatus{}, fmt.Errorf("businessstatus: 自訂狀態 %s 的活動標識 %q 不合法: %w",
			idText, activityIDText, err)
	}
	return CustomStatus{
		ID: id, ActivityID: activityID, Name: name, Available: available != 0,
		CreatedAt: timeutil.FromMillis(createdAt), UpdatedAt: timeutil.FromMillis(updatedAt),
	}, nil
}

// StatusLabelOverrides 讀出一個活動裡「有覆蓋」的內建狀態顯示名稱。
//
// 沒有行的內建鍵不在回傳的 map 裡，語意是「使用四語言預設文案」；空字串的覆蓋
// （恢復預設後留在表裡的行）同樣不進 map。呼叫端因此只需要問「有沒有覆蓋」。
func (s *Store) StatusLabelOverrides(ctx context.Context, q database.Querier,
	activityID idgen.ID) (map[BusinessStatus]string, error) {
	if q == nil {
		return nil, errors.New("businessstatus: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() {
		return nil, ErrActivityNotFound
	}
	rows, err := q.QueryContext(ctx, `SELECT status_key, display_name
		FROM activity_player_status_labels WHERE activity_id = ?`, activityID.String())
	if err != nil {
		return nil, fmt.Errorf("businessstatus: 讀取狀態顯示名稱覆蓋失敗: %w", err)
	}
	defer rows.Close()

	out := make(map[BusinessStatus]string, len(builtinBusinessStatuses))
	for rows.Next() {
		var key, displayName string
		if err := rows.Scan(&key, &displayName); err != nil {
			return nil, fmt.Errorf("businessstatus: 解析狀態顯示名稱覆蓋失敗: %w", err)
		}
		status, err := parseBusinessStatus(key)
		if err != nil {
			// 集合外的鍵屬資料缺陷，不降級成「沒有覆蓋」：後者會讓一次寫壞的行
			// 悄悄退回預設文案，而管理員以為自己設過的覆蓋還在。
			return nil, fmt.Errorf("businessstatus: 顯示名稱覆蓋的鍵 %q 不認識: %w", key, err)
		}
		if displayName == "" {
			continue
		}
		out[status] = displayName
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("businessstatus: 讀取狀態顯示名稱覆蓋失敗: %w", err)
	}
	return out, nil
}

// StatusLabelOverride 讀出一個內建狀態在此活動的覆蓋現值（空字串＝使用預設）。
func (s *Store) StatusLabelOverride(ctx context.Context, q database.Querier,
	activityID idgen.ID, key BusinessStatus) (string, error) {
	if q == nil {
		return "", errors.New("businessstatus: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() || !key.valid() {
		return "", ErrActivityNotFound
	}
	var displayName string
	err := q.QueryRowContext(ctx, `SELECT display_name FROM activity_player_status_labels
		WHERE activity_id = ? AND status_key = ?`, activityID.String(), key.String()).
		Scan(&displayName)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("businessstatus: 讀取狀態顯示名稱覆蓋失敗: %w", err)
	}
	return displayName, nil
}

// UpsertStatusLabel 以比較-and-set 方式寫入一個內建狀態的顯示名稱覆蓋。
//
// target 為空字串代表恢復預設：刪掉那一行（若存在且現值等於 expected）。
// target 非空時，沒有行且 expected 為空就新增；已有行且現值等於 expected 就更新。
// changed 為 false 表示現值已不是呼叫端所依據的那份；此時不會有第二條審計。
func (s *Store) UpsertStatusLabel(ctx context.Context, q database.Querier,
	activityID idgen.ID, key BusinessStatus, target, expected string) (bool, error) {
	if q == nil {
		return false, errors.New("businessstatus: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() || !key.valid() {
		return false, ErrActivityNotFound
	}
	now := timeutil.ToMillis(s.clock.Now())
	if target == "" {
		res, err := q.ExecContext(ctx, `DELETE FROM activity_player_status_labels
			WHERE activity_id = ? AND status_key = ? AND display_name = ?`,
			activityID.String(), key.String(), expected)
		if err != nil {
			return false, fmt.Errorf("businessstatus: 恢復狀態顯示名稱預設失敗: %w", err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return false, fmt.Errorf("businessstatus: 恢復顯示名稱後確認寫入筆數失敗: %w", err)
		}
		return affected == 1, nil
	}
	// INSERT ... SELECT 只在 expected 為空（沒有可依據的現值）時嘗試新增；
	// ON CONFLICT 的 WHERE 再把「已有行」的情況收斂成同一條比較-and-set。
	res, err := q.ExecContext(ctx, `INSERT INTO activity_player_status_labels
			(activity_id, status_key, display_name, updated_at)
		SELECT ?, ?, ?, ? WHERE ? = ''
		ON CONFLICT(activity_id, status_key) DO UPDATE SET
			display_name = excluded.display_name,
			updated_at = excluded.updated_at
		WHERE activity_player_status_labels.display_name = ?`,
		activityID.String(), key.String(), target, now, expected, expected)
	if err != nil {
		return false, fmt.Errorf("businessstatus: 寫入狀態顯示名稱覆蓋失敗: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("businessstatus: 寫入顯示名稱後確認寫入筆數失敗: %w", err)
	}
	return affected == 1, nil
}

// CustomStatuses 讀出一個活動的全部自訂狀態定義（依建立時刻、標識升序）。
func (s *Store) CustomStatuses(ctx context.Context, q database.Querier,
	activityID idgen.ID) ([]CustomStatus, error) {
	if q == nil {
		return nil, errors.New("businessstatus: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() {
		return nil, ErrActivityNotFound
	}
	rows, err := q.QueryContext(ctx, `SELECT `+customStatusColumns+`
		FROM activity_player_statuses WHERE activity_id = ?
		ORDER BY created_at ASC, id ASC`, activityID.String())
	if err != nil {
		return nil, fmt.Errorf("businessstatus: 讀取自訂狀態列表失敗: %w", err)
	}
	defer rows.Close()

	out := make([]CustomStatus, 0)
	for rows.Next() {
		status, err := scanCustomStatusRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, status)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("businessstatus: 讀取自訂狀態列表失敗: %w", err)
	}
	return out, nil
}

// CustomStatusByID 按標識讀回一個自訂狀態定義；查無時回 ErrCustomStatusNotFound。
//
// 「不屬於哪場活動」不在這裡回答：倉儲只按 id 取行，歸屬核實屬用例的事
// （跨活動與從未存在必須收斂成同一句話）。
func (s *Store) CustomStatusByID(ctx context.Context, q database.Querier,
	id idgen.ID) (CustomStatus, error) {
	if q == nil {
		return CustomStatus{}, errors.New("businessstatus: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return CustomStatus{}, ErrCustomStatusNotFound
	}
	row := q.QueryRowContext(ctx,
		"SELECT "+customStatusColumns+" FROM activity_player_statuses WHERE id = ?", id.String())
	status, err := scanCustomStatusRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CustomStatus{}, ErrCustomStatusNotFound
	}
	return status, err
}

// CustomStatusNameTaken 核實同活動內是否已有另一個自訂狀態使用這個名稱。
//
// exceptID 是編輯時要避開的自己；零值表示建立通路。正確性來源是
// UNIQUE (activity_id, name)，本讀法只決定給操作者哪一句話。
func (s *Store) CustomStatusNameTaken(ctx context.Context, q database.Querier,
	activityID idgen.ID, name string, exceptID idgen.ID) (bool, error) {
	if q == nil {
		return false, errors.New("businessstatus: 需要可用的資料庫連線或交易")
	}
	where := `activity_id = ? AND name = ?`
	args := []any{activityID.String(), name}
	if !exceptID.IsNil() {
		where += ` AND id <> ?`
		args = append(args, exceptID.String())
	}
	var exists int
	err := q.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM activity_player_statuses WHERE "+where, args...).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("businessstatus: 核實自訂狀態名稱占用失敗: %w", err)
	}
	return exists > 0, nil
}

// CreateCustomStatus 寫入一個新的自訂狀態定義並回讀它。
//
// 新定義出生即可用（口徑同陣營與標籤）；可用性不是請求能決定的事。
func (s *Store) CreateCustomStatus(ctx context.Context, q database.Querier,
	activityID idgen.ID, name string) (CustomStatus, error) {
	if q == nil {
		return CustomStatus{}, errors.New("businessstatus: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() {
		return CustomStatus{}, ErrActivityNotFound
	}
	id, err := s.newID()
	if err != nil {
		return CustomStatus{}, fmt.Errorf("businessstatus: 產生自訂狀態標識失敗: %w", err)
	}
	now := timeutil.ToMillis(s.clock.Now())
	_, err = q.ExecContext(ctx, `INSERT INTO activity_player_statuses
			(id, activity_id, name, available, created_at, updated_at)
		VALUES (?, ?, ?, 1, ?, ?)`,
		id.String(), activityID.String(), name, now, now)
	if err != nil {
		return CustomStatus{}, fmt.Errorf("businessstatus: 建立自訂狀態失敗: %w", err)
	}
	return s.CustomStatusByID(ctx, q, id)
}

// UpdateCustomStatus 以比較-and-set 方式編輯自訂狀態的名稱與可用性。
//
// UPDATE 語句裡只出現 name、available 與 updated_at：id、activity_id、created_at
// 連一個格子都沒有，因此「改名或停用不會換掉身份、歸屬與建立時刻」成立在 SQL 形狀上。
// 歸屬核實寫在 WHERE 裡：拿另一場活動的標識拼進來時 RowsAffected 是 0。
func (s *Store) UpdateCustomStatus(ctx context.Context, q database.Querier,
	id, activityID idgen.ID, edit CustomStatusEdit) (bool, error) {
	if q == nil {
		return false, errors.New("businessstatus: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() || activityID.IsNil() {
		return false, ErrCustomStatusNotFound
	}
	res, err := q.ExecContext(ctx, `UPDATE activity_player_statuses
		SET name = ?, available = ?, updated_at = ?
		WHERE id = ? AND activity_id = ? AND name = ? AND available = ?`,
		edit.New.Name, boolToInt64(edit.New.Available), timeutil.ToMillis(s.clock.Now()),
		id.String(), activityID.String(),
		edit.Expected.Name, boolToInt64(edit.Expected.Available))
	if err != nil {
		return false, fmt.Errorf("businessstatus: 編輯自訂狀態失敗: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("businessstatus: 編輯自訂狀態後確認寫入筆數失敗: %w", err)
	}
	return affected == 1, nil
}

// UpdateMemberBusinessStatus 以比較-and-set 方式編輯成員目前的業務狀態。
//
// UPDATE 語句裡只出現 business_status、business_status_custom_id 與 updated_at：
// 身份三欄、暱稱、陣營歸屬、目錄覆蓋與建立時刻連一個格子都沒有，因此「改狀態不會順手
// 改名、換組或搬身份」成立在 SQL 形狀上。
// 兩欄依據值一起比較，且自訂標識用 `IS ?` 做 NULL 安全比對：出生那一份的
// business_status_custom_id 是 NULL，「我以為他是一般內建狀態」要能比對得動。
// 歸屬核實寫在 WHERE 裡：跨活動的成員標識拼進來時 RowsAffected 是 0。
func (s *Store) UpdateMemberBusinessStatus(ctx context.Context, q database.Querier,
	id, activityID idgen.ID, status BusinessStatus, customStatusID idgen.ID,
	expectedStatus BusinessStatus, expectedCustomStatusID idgen.ID) (bool, error) {
	if q == nil {
		return false, errors.New("businessstatus: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() || activityID.IsNil() || !status.valid() || !expectedStatus.valid() {
		return false, ErrMemberNotFound
	}
	var newCustom, expectedCustom any
	if !customStatusID.IsNil() {
		newCustom = customStatusID.String()
	}
	if !expectedCustomStatusID.IsNil() {
		expectedCustom = expectedCustomStatusID.String()
	}
	res, err := q.ExecContext(ctx, `UPDATE activity_members
		SET business_status = ?, business_status_custom_id = ?, updated_at = ?
		WHERE id = ? AND activity_id = ? AND business_status = ?
		  AND business_status_custom_id IS ?`,
		status.String(), newCustom, timeutil.ToMillis(s.clock.Now()),
		id.String(), activityID.String(), expectedStatus.String(), expectedCustom)
	if err != nil {
		return false, fmt.Errorf("businessstatus: 變更成員業務狀態失敗: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("businessstatus: 變更成員業務狀態後確認寫入筆數失敗: %w", err)
	}
	return affected == 1, nil
}
