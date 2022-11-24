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

// Entry 是一筆授予的讀取結果：誰被授予、何時写下。
//
// 不含角色欄位：呼叫它的方式是「按某個角色反查」，清單裡每一行的角色就是那個查詢條件，
// 再存一份只会多出一個可以與查詢不一致的事實。
type Entry struct {
	// AccountID 為被授予角色的帳戶標識。
	AccountID idgen.ID
	// GrantedAt 為授予写下的時刻（UTC；落庫為 Unix 毫秒）。
	GrantedAt time.Time
}

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

// ListByRole 按角色反查被授予的帳戶，依授予時刻倒序、至多 limit 筆。
//
// 存在的理由只有一個：「伺服器級管理員有哪些」這句話需要一個由資料庫說出口的來源。
// limit 必為正值——本方法服務的是確認用的最小列表，不是一個可以一次拉出全表的口子；
// 「沒有上限」在一個會長期增長的表上等於把回應體大小交給資料量決定。
//
// 只回傳授予事實（帳戶標識、時刻），不回傳帳戶資料：登入名與狀態屬 internal/account，
// 由呼叫端按標識讀回（見 internal/adminacct 的列表用例）。兩張表各自只由自己的倉儲解釋，
// 才不会出現「同一個欄位有兩份讀法、其中一份繞過了實體校驗」。
func (s *Store) ListByRole(ctx context.Context, q database.Querier,
	role identity.Role, limit int) ([]Entry, error) {
	if q == nil {
		return nil, errors.New("grant: 需要可用的資料庫連線或交易")
	}
	if err := requireRole(role); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, fmt.Errorf("grant: ListByRole 的 limit 必須為正值，實際 %d", limit)
	}
	rows, err := q.QueryContext(ctx, `SELECT account_id, granted_at FROM account_server_roles
		WHERE role = ? ORDER BY granted_at DESC, account_id DESC LIMIT ?`,
		string(role), limit)
	if err != nil {
		return nil, fmt.Errorf("grant: 讀取授予清單失敗: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var (
			idText    string
			grantedAt int64
		)
		if err := rows.Scan(&idText, &grantedAt); err != nil {
			return nil, fmt.Errorf("grant: 讀取授予清單列失敗: %w", err)
		}
		id, err := idgen.Parse(idText)
		if err != nil {
			// 標識讀不回來代表資料庫被繞過校驗寫入了東西，或執行檔比資料庫舊：
			// 靜默跳過會讓那一筆授予在介面上徹底消失。
			return nil, fmt.Errorf("grant: 授予的帳戶標識無法解析（%s）: %w", redactID(idText), err)
		}
		entries = append(entries, Entry{AccountID: id, GrantedAt: timeutil.FromMillis(grantedAt)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("grant: 讀取授予清單失敗: %w", err)
	}
	return entries, nil
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

// redactID 把無法解析的標識縮成前綴：它不是秘密，但把一整段任意文字原樣帶進錯誤訊息，
// 等於讓資料庫內容直接決定日誌的長度與形狀。
func redactID(value string) string {
	r := []rune(value)
	if len(r) > 8 {
		return string(r[:8]) + "…"
	}
	return value
}
