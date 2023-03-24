// memberstore.go 是活動成員的持久倉儲：把「一個帳戶在哪場活動裡有身份、他在裡面叫什麼、
// 此刻屬於哪個陣營」讀寫在 activity_members 表上（見遷移 0014）。
//
// 與本套件其余倉儲同一取向（見 store.go 頭注）：一律接受 database.Querier、
// 自己不開交易——「成員多一行」與「記一筆審計」必須同生同滅，那句話只有把兩者
// 交給同一個 *database.Tx 才成立。
//
// 四條寫在形狀上的規定：
//   - 主鍵、歸屬、帳戶指向與時刻不給呼叫端填。id 由 idgen 產生、活動與帳戶標識由用例在
//     作用域與資格核實後交進來、時刻由注入時鐘換算——「這是哪一個玩家」「他是誰」
//     「他在哪場活動」「何時加入」各只有一個答案。
//   - 出生時 faction_id 恆為 NULL：本步沒有分配端點，而「他屬於哪個陣營」從來不是請求能
//     說服的欄位。倉儲的建立輸入因此根本沒有那一格——不是被拒，是無處可填。
//   - 暱稱改動是帶 WHERE 的比較-and-set：UPDATE 語句裡只出現 nickname 與 updated_at 兩欄，
//     id、activity_id、account_id、faction_id、created_at 連一個格子都沒有，
//     「儲存暱稱不會連身份、歸屬與陣營一起覆蓋」成立在 SQL 形狀上（口徑同陣營的 UpdateFaction）。
//   - 「一個帳戶在一場活動裡只有一份檔案」由 UNIQUE (activity_id, account_id) 把關：
//     先查只是友善錯誤來源，併發下的正確性來自資料庫約束與單寫者交易串行。
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

// memberColumns 是 activity_members 的共用讀取欄位順序：任何一條讀法都從這裡長出來，
// 於是「名冊讀到的」與「編輯後回讀的」不可能各說各話。
//
// 欄位裡沒有帳戶的顯示名與狀態：那兩格屬 internal/account 的事實，由名冊讀法在讀回後
// 逐行蓋上（見 members.go）。倉儲不 JOIN accounts，否則「指向的帳戶行已被物理清理」
// 這種形態會被 SQL 的 INNER 語意默默吞成一筆少掉的行，而它恰恰是需要如實說出來的事。
const memberColumns = `id, activity_id, account_id, nickname, faction_id,
		created_at, updated_at`

// scanMemberRow 把一列 activity_members 讀成 Member（DisplayName／AccountStatus 留空，
// 由服務層投影時蓋上）。
//
// faction_id 是可空欄：NULL 讀成零值標識，語意是「尚未分組」而不是「讀坏了」。
// 反之，非 NULL 卻解析不出正規標識屬資料缺陷，不降級成「當成無陣營」——後者會把
// 一次寫壞的行讀成一個合法的分組狀態。
func scanMemberRow(rows interface{ Scan(dest ...any) error }) (Member, error) {
	var (
		idText, activityIDText, accountIDText string
		nickname                              string
		factionID                             sql.NullString
		joinedAt, updatedAt                   int64
	)
	if err := rows.Scan(&idText, &activityIDText, &accountIDText, &nickname,
		&factionID, &joinedAt, &updatedAt); err != nil {
		return Member{}, fmt.Errorf("member: 解析成員行失敗: %w", err)
	}
	id, err := idgen.Parse(idText)
	if err != nil {
		return Member{}, fmt.Errorf("member: 成員行的標識 %q 不是正規標識: %w", idText, err)
	}
	activityID, err := idgen.Parse(activityIDText)
	if err != nil {
		return Member{}, fmt.Errorf("member: 成員行 %s 的活動標識 %q 不合法: %w",
			idText, activityIDText, err)
	}
	accountID, err := idgen.Parse(accountIDText)
	if err != nil {
		return Member{}, fmt.Errorf("member: 成員行 %s 的帳戶標識 %q 不合法: %w",
			idText, accountIDText, err)
	}
	member := Member{
		ID: id, ActivityID: activityID, AccountID: accountID, Nickname: nickname,
		JoinedAt:  timeutil.FromMillis(joinedAt),
		UpdatedAt: timeutil.FromMillis(updatedAt),
	}
	if factionID.Valid {
		faction, err := idgen.Parse(factionID.String)
		if err != nil {
			return Member{}, fmt.Errorf("member: 成員行 %s 的陣營標識 %q 不合法: %w",
				idText, factionID.String, err)
		}
		member.FactionID = faction
	}
	return member, nil
}

// MemberCreateInput 是建立一行成員身份的倉儲輸入。
//
// 不含 ID、不含建立時刻、不含陣營歸屬——那三樣各有唯一產生點（idgen、注入時鐘、
// 「出生即無陣營」這條領域規則，見遷移 0014 檔頭）。讓呼叫端代填等於把
// 「他是哪一個玩家」「他一加入就屬於哪一組」交給請求鏈上的某一環。
type MemberCreateInput struct {
	// ActivityID 是作用域判定已核實的歸屬活動。
	ActivityID idgen.ID
	// AccountID 是資格核實已通過的目標帳戶（無外鍵軟參照，指向 accounts.id）。
	AccountID idgen.ID
	// Nickname 是透過域校驗的活動內暱稱。
	Nickname string
}

// CreateMember 寫入一行成員身份並回讀它。陣營歸屬恆為 NULL，時刻恆為注入時鐘。
func (s *Store) CreateMember(ctx context.Context, q database.Querier,
	in MemberCreateInput) (Member, error) {
	if q == nil {
		return Member{}, errors.New("member: 需要可用的資料庫連線或交易")
	}
	if in.ActivityID.IsNil() || in.AccountID.IsNil() {
		return Member{}, ErrMemberNotFound
	}
	id, err := s.newID()
	if err != nil {
		return Member{}, fmt.Errorf("member: 產生成員標識失敗: %w", err)
	}
	now := timeutil.ToMillis(s.clock.Now())
	// faction_id 不出現在欄位清單裡：讓它走 DEFAULT NULL，出生形態因此只有一個答案。
	_, err = q.ExecContext(ctx, `INSERT INTO activity_members
			(id, activity_id, account_id, nickname, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		id.String(), in.ActivityID.String(), in.AccountID.String(), in.Nickname, now, now)
	if err != nil {
		return Member{}, fmt.Errorf("member: 建立成員身份失敗: %w", err)
	}
	return s.MemberByID(ctx, q, id)
}

// MemberByID 按標識讀回一行成員。查無時回 ErrMemberNotFound。
//
// 「不屬於哪個活動」不在這裡回答：倉儲只按 id 取行，歸屬核實屬用例的事
// （見 members.go——跨活動與從未存在必須收斂成同一句話）。
func (s *Store) MemberByID(ctx context.Context, q database.Querier,
	id idgen.ID) (Member, error) {
	if q == nil {
		return Member{}, errors.New("member: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return Member{}, ErrMemberNotFound
	}
	row := q.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM activity_members WHERE id = ?",
		id.String())
	member, err := scanMemberRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Member{}, ErrMemberNotFound
	}
	return member, err
}

// Members 讀出一個活動的全部成員（依加入時刻、標識升序）。
//
// 「這個活動還沒有成員」與「活動查無」在這裡是分開的：倉儲假設呼叫端已核實活動存在
// （見 members.go 的名冊用例），空列表就是空列表這個事實，不是錯誤。
// 名冊不分頁：本步的成員是一場活動的參加名單，與管理人、陣營兩張小表同樣全量讀回。
func (s *Store) Members(ctx context.Context, q database.Querier,
	activityID idgen.ID) ([]Member, error) {
	if q == nil {
		return nil, errors.New("member: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() {
		return nil, ErrMemberNotFound
	}
	rows, err := q.QueryContext(ctx, `SELECT `+memberColumns+` FROM activity_members
		WHERE activity_id = ?
		ORDER BY created_at ASC, id ASC`, activityID.String())
	if err != nil {
		return nil, fmt.Errorf("member: 讀取成員名冊失敗: %w", err)
	}
	defer rows.Close()

	out := make([]Member, 0)
	for rows.Next() {
		member, err := scanMemberRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, member)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("member: 讀取成員名冊失敗: %w", err)
	}
	return out, nil
}

// MemberByAccount 按（活動, 帳戶）讀回一行成員；查無時回 ErrMemberNotFound。
//
// 它走 UNIQUE (activity_id, account_id) 那一條邊：一句查詢就是「一個帳戶在一場活動裡
// 只有一份檔案」的讀取形態。本步的用例只需要「在不在」，但讀回整行讓日後要拿
// 成員標識的通路不必再抄一次 SQL。
func (s *Store) MemberByAccount(ctx context.Context, q database.Querier,
	activityID, accountID idgen.ID) (Member, error) {
	if q == nil {
		return Member{}, errors.New("member: 需要可用的資料庫連線或交易")
	}
	if activityID.IsNil() || accountID.IsNil() {
		return Member{}, ErrMemberNotFound
	}
	row := q.QueryRowContext(ctx, "SELECT "+memberColumns+` FROM activity_members
		WHERE activity_id = ? AND account_id = ?`, activityID.String(), accountID.String())
	member, err := scanMemberRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Member{}, ErrMemberNotFound
	}
	return member, err
}

// MemberExistsForAccount 核實「這個帳戶在該活動裡已經有成員身份了」。
//
// 這句話的正確性來源是 UNIQUE (activity_id, account_id)；本讀法只決定「給操作者哪一句話」。
// 併發窗口裡後到的那一跳就算漏過這裡，也會在 INSERT 撞約束整筆回滾，
// 於是庫裡永遠不會有第二份同一個人的檔案。
func (s *Store) MemberExistsForAccount(ctx context.Context, q database.Querier,
	activityID, accountID idgen.ID) (bool, error) {
	if q == nil {
		return false, errors.New("member: 需要可用的資料庫連線或交易")
	}
	var exists int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM activity_members
		WHERE activity_id = ? AND account_id = ?`,
		activityID.String(), accountID.String()).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("member: 核實成員身份占用失敗: %w", err)
	}
	return exists > 0, nil
}

// MembersByAccount 按帳戶讀回他在各場活動裡的成員行（依加入時刻倒序、標識破平）。
//
// 它是「我參加了哪些活動」這一讀的唯一來源：走 UNIQUE (activity_id, account_id) 的左側，
// 一個帳戶在一場活動裡至多一行，因此這份清單裡不會出現同一個活動兩次。
// 刻意不 JOIN activities 帶出活動名稱與狀態：那些屬活動那一張表的事實，由服務層逐行
// 經現成的單筆讀法讀回（見 selfselect.go），於是「目錄讀到的活動」與「玩家讀到的活動」
// 是同一份解析，不會因為這裡抄了一份欄位清單而漂移。加入時刻倒序的理由與名冊正向排相反：
// 這一讀的場景是「我最近被拉進哪場活動」，最近的在前才不用翻。
func (s *Store) MembersByAccount(ctx context.Context, q database.Querier,
	accountID idgen.ID) ([]Member, error) {
	if q == nil {
		return nil, errors.New("member: 需要可用的資料庫連線或交易")
	}
	if accountID.IsNil() {
		return nil, ErrMemberNotFound
	}
	rows, err := q.QueryContext(ctx, `SELECT `+memberColumns+` FROM activity_members
		WHERE account_id = ?
		ORDER BY created_at DESC, id DESC`, accountID.String())
	if err != nil {
		return nil, fmt.Errorf("member: 讀取本人成員身份失敗: %w", err)
	}
	defer rows.Close()

	out := make([]Member, 0)
	for rows.Next() {
		member, err := scanMemberRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, member)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("member: 讀取本人成員身份失敗: %w", err)
	}
	return out, nil
}

// UpdateMemberFaction 以比較-and-set 方式編輯一個成員此刻的陣營歸屬。
//
// UPDATE 語句裡只出現 faction_id 與 updated_at 兩欄：身分三欄（id、activity_id、
// account_id）、暱稱與建立時刻連一個格子都沒有，因此「換組不會順手改名或搬身份」
// 成立在 SQL 形狀上（口徑同 UpdateMemberNickname 只碰暱稱一欄）。
// 目標恆為非零值標識：自選通路沒有「清空歸屬」這一步（用戶批準於本步），
// 把歸屬改回 NULL 屬管理側分配通路，今日不存在。
// 依據值用 `IS ?` 做 NULL 安全比對：出生那一份檔案的歸屬是 NULL，
// 「我以為他還沒分組」要能比對得動，而 `= ?` 在兩側都是 NULL 時永遠不成立。
// 歸屬核實也寫在 WHERE 裡（activity_id）：呼叫端交來的活動與這一行所屬活動不符時
// RowsAffected 是 0，寫入不發生——跨活動改他人的歸屬因此拿不到任何可探測的差異。
// changed 為 false 表示現值已不是呼叫端所依據的那份（併發落敗或結果不明的補發），
// 此時一個字都沒落，也不會留下第二條審計。
func (s *Store) UpdateMemberFaction(ctx context.Context, q database.Querier,
	id, activityID, factionID, expectedFactionID idgen.ID) (bool, error) {
	if q == nil {
		return false, errors.New("member: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() || activityID.IsNil() || factionID.IsNil() {
		return false, ErrMemberNotFound
	}
	// 零值依據值綁成 NULL：SQLite 的 IS 把 NULL 當成可比對的值，
	// 「此刻尚未分組」與「此刻已分組」兩態才共用同一條語句。
	var expected any
	if !expectedFactionID.IsNil() {
		expected = expectedFactionID.String()
	}
	res, err := q.ExecContext(ctx, `UPDATE activity_members
		SET faction_id = ?, updated_at = ?
		WHERE id = ? AND activity_id = ? AND faction_id IS ?`,
		factionID.String(), timeutil.ToMillis(s.clock.Now()), id.String(), activityID.String(),
		expected)
	if err != nil {
		return false, fmt.Errorf("member: 玩家自選陣營失敗: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("member: 玩家自選陣營後確認寫入筆數失敗: %w", err)
	}
	return affected == 1, nil
}

// UpdateMemberNickname 以比較-and-set 方式編輯成員的活動內暱稱。
//
// UPDATE 語句裡只出現 nickname 與 updated_at 兩欄：id、activity_id、account_id、
// faction_id、created_at 連一個格子都沒有，因此「儲存暱稱不會連身份、歸屬、
// 陣營與建立時刻一起覆蓋」不需要約定，它成立在 SQL 形狀上。
// 歸屬核實也寫在 WHERE 裡：呼叫端交來的 activity_id 與這一行所屬活動不符時，
// RowsAffected 是 0，編輯不發生——跨活動改别人的成員因此拿不到任何可探測的差異。
// changed 為 false 表示現值已不是呼叫端所依據的那份（併發編輯落敗），此時一個字都沒落。
func (s *Store) UpdateMemberNickname(ctx context.Context, q database.Querier,
	id, activityID idgen.ID, nickname, expectedNickname string) (bool, error) {
	if q == nil {
		return false, errors.New("member: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() || activityID.IsNil() {
		return false, ErrMemberNotFound
	}
	res, err := q.ExecContext(ctx, `UPDATE activity_members
		SET nickname = ?, updated_at = ?
		WHERE id = ? AND activity_id = ? AND nickname = ?`,
		nickname, timeutil.ToMillis(s.clock.Now()), id.String(), activityID.String(),
		expectedNickname)
	if err != nil {
		return false, fmt.Errorf("member: 編輯成員暱稱失敗: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("member: 編輯成員暱稱後確認寫入筆數失敗: %w", err)
	}
	return affected == 1, nil
}
