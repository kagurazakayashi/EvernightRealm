// Package grant 提供伺服器級角色授予的持久倉儲：把「哪個帳戶被授予了哪個伺服器級角色」
// 這條事實讀寫在 account_server_roles 表上（見遷移 0006）。
//
// 為什麼獨立成一個套件，而不是塞進 internal/account 或 internal/identity：
//   - 角色的語意（封閉集合、ParseRole、ServerGrants 載體）屬 internal/identity，
//     而那個套件至今不碰資料庫——它是純領域層，把 SQL 放進去等於讓身份判定依賴存儲；
//   - 帳戶的事實（登入名、狀態、憑據雜湊）屬 internal/account，但 identity 已依賴 account，
//     反向讓 account 認得角色就會成環；
//   - 授予本身是「帳戶 × 角色」的關聯事實，它需要同時認得兩者，因此落在
//     兩個套件之外的這一層，依賴方向保持單向：grant → identity、account → 無。
//
// 本套件是「角色授予的來源」唯一實作點。internal/identity 把 ServerGrants 的欄位藏起來、
// 只經 NewServerGrantsFromStrings 產生，正是為了讓「授予從哪來」在程式碼裡只有一個答案；
// 各端點不得自己查本表湊一份角色，否則會出現兩套權限語意（其中一套總會被繞過）。
//
// 與 internal/account 同一取向：時刻唯一來源是注入的 timeutil.Clock（DEC-015），
// 呼叫端無權代填「何時授予」。零值不可用，請經 NewStore 取得。
package grant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// ErrNotFound 表示按標識找不到對應的帳戶或授予。
//
// 它與資料庫故障刻意分開：呼叫端拿账户標識來查，查不到多半是競態的尾巴
// （帳戶在另一筆交易裡被物理刪除），屬可解釋的業務結論；查不了才是需要報錯的缺陷。
var ErrNotFound = errors.New("grant: 找不到對應的授予")

// Store 是授予的持久倉儲。
type Store struct {
	clock timeutil.Clock
}

// NewStore 建立授予倉儲；clock 為 nil 時採用 timeutil.System()。
func NewStore(clock timeutil.Clock) *Store {
	if clock == nil {
		clock = timeutil.System()
	}
	return &Store{clock: clock}
}

// Grant 為一個帳戶写下一筆伺服器級角色授予。
//
// q 讓呼叫端把「建立帳戶＋授予＋審計」放進同一個交易（依 database.Querier 合同，
// *sql.DB 與 *Tx 皆可用）：一個被授予了角色卻沒建好的帳戶，或一個建好了
// 卻查不到角色的帳戶，都是不可解釋的半成品狀態。
//
// 正確性來自主鍵 (account_id, role)：同一帳戶同一角色不可能有兩行。
// 呼叫端在開設新路徑上拿到的是剛產生的標識，衝突只可能是「拿既有帳戶重復授予」，
// 那個失敗原樣回報、不靜默降級成成功——把重復授予說成沒事，
// 等於讓未來的管理界面以為自己改動了什麼。
//
// 訪客帳戶帶角色由遷移 0006 的觸發器當場拒掉（SQL 錯誤原樣包装回報）。
func (s *Store) Grant(ctx context.Context, q database.Querier, accountID idgen.ID,
	role identity.Role) error {
	if q == nil {
		return errors.New("grant: 需要可用的資料庫連線或交易")
	}
	if accountID.IsNil() {
		return fmt.Errorf("%w：授予必須帶帳戶標識", ErrNotFound)
	}
	if err := requireRole(role); err != nil {
		return err
	}
	_, err := q.ExecContext(ctx,
		"INSERT INTO account_server_roles (account_id, role, granted_at) VALUES (?, ?, ?)",
		accountID.String(), string(role), timeutil.ToMillis(s.clock.Now()))
	if err != nil {
		return fmt.Errorf("grant: 写下授予失敗: %w", err)
	}
	return nil
}

// Roles 讀回一個帳戶持有的全部伺服器級角色，換成 identity 的授予載體。
//
// 回傳型別刻意是 identity.ServerGrants 而不是 []string 或 []Role：那是「角色只能由服務端的
// 授權資料產生」這條約定的型別形態（欄位不匯出、無 JSON 標記，請求本體填不進去）。
// 換不出載體就等于沒有任何角色，因此這裡不存在「回個空值讓呼叫端自己拼」的分支。
//
// 逐項經 identity 的封閉集合解析，任何一項不認得即整體失敗：一筆寫壞的授予記錄
// 不該被解讀成「他沒有這個角色」——那是把資料缺陷降級成一次靜默的權限消失，
// 而「我明明給了權限」從此變成查不出來的幽靈問題。
// 查無任何行回傳零值載體與 nil：它的意思是「這個帳戶確實沒有被授予任何伺服器級角色」，
// 這正是普通帳戶的常态，不是錯誤。
func (s *Store) Roles(ctx context.Context, q database.Querier, accountID idgen.ID) (identity.ServerGrants, error) {
	if q == nil {
		return identity.ServerGrants{}, errors.New("grant: 需要可用的資料庫連線或交易")
	}
	if accountID.IsNil() {
		return identity.ServerGrants{}, fmt.Errorf("%w：查詢授予必須帶帳戶標識", ErrNotFound)
	}
	rows, err := q.QueryContext(ctx,
		"SELECT role FROM account_server_roles WHERE account_id = ? ORDER BY role",
		accountID.String())
	if err != nil {
		return identity.ServerGrants{}, fmt.Errorf("grant: 讀取授予失敗: %w", err)
	}
	defer rows.Close()

	var values []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return identity.ServerGrants{}, fmt.Errorf("grant: 讀取授予列失敗: %w", err)
		}
		values = append(values, role)
	}
	if err := rows.Err(); err != nil {
		return identity.ServerGrants{}, fmt.Errorf("grant: 讀取授予失敗: %w", err)
	}
	return identity.NewServerGrantsFromStrings(values...)
}

// GrantedAt 讀回「某帳戶的某角色是何時授予的」；查無該授予回 ErrNotFound。
//
// 存在的理由只有一件：單筆管理員資料要如實講出「他是什麼時候變成管理員的」，
// 而這句話的權威只在授予表裡。倉儲不猜：查無就是查無，呼叫端不得拿
// 「帳戶建立時刻」冒充「授予時刻」——那兩者本来就可能不同生。
func (s *Store) GrantedAt(ctx context.Context, q database.Querier,
	accountID idgen.ID, role identity.Role) (time.Time, error) {
	if q == nil {
		return time.Time{}, errors.New("grant: 需要可用的資料庫連線或交易")
	}
	if accountID.IsNil() {
		return time.Time{}, fmt.Errorf("%w：查詢授予時刻必須帶帳戶標識", ErrNotFound)
	}
	if err := requireRole(role); err != nil {
		return time.Time{}, err
	}
	var grantedAt int64
	err := q.QueryRowContext(ctx,
		"SELECT granted_at FROM account_server_roles WHERE account_id = ? AND role = ?",
		accountID.String(), string(role)).Scan(&grantedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, fmt.Errorf("%w：帳戶 %s 未持有角色 %s",
			ErrNotFound, accountID, role)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("grant: 讀取授予時刻失敗: %w", err)
	}
	return timeutil.FromMillis(grantedAt), nil
}

// requireRole 用 identity 唯一的角色入口复核一次角色：這裡不另寫一份「合法角色清單」。
//
// 直接把 identity.Role 的內部判定當公開 API 用會多出第二個真相來源；
// 經 ParseRole 走一趟，本套件認得的角色集合永遠與 internal/identity 一致，
// 不一致時（例如有人加了角色卻忘了放寬遷移的 CHECK）在寫入前就報錯。
func requireRole(role identity.Role) error {
	if _, err := identity.ParseRole(role.String()); err != nil {
		return err
	}
	return nil
}
