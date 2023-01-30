// store.go 是帳戶建立策略的持久倉儲：把那份單例策略讀寫在
// account_creation_policy 表上（見遷移 0008）。
//
// 為什麼倉儲只認資料庫連線而不自己開交易：
//
//	「改策略」與「記審計」必須同生同滅，而那句話只有把兩者放進同一個 *database.Tx 才成立。
//	倉儲因此一律接受 database.Querier——讀取端可以傳 autocommit 連線（*db.SQL()），
//	寫入端則由用例把 UPDATE 與 audit.Append 串在同一筆交易裡；
//	倉儲自己不開交易，也就沒辦法「不小心」把一次改動拆成兩段。
//
// 讀取端不放寬、也不代填預設值：
//
//	表裡出現不認識的模式字串時整個讀取失敗（ErrUnknownMode 包著現值），
//	一行都讀不到時回 ErrNoPolicyRow。兩者都不換成「closed」或出廠預設——
//	讀取端猜一個答案，等於讓一次資料庫缺陷以 Root 的名義變成一個政策決定。
//	原值讀不回來就照實報錯，由人去看那張表，這比「伺服器和昨天不一樣但沒人知道」好。
//
// 寫入端的形態限制落在 SQL 上（遷移 0008 的 CHECK 與觸發器），這裡只做「進 SQL 之前」
// 那層同形的復核：呼叫端拿到的是能讀懂的欄位級錯誤，而不是 sqlite 的約束訊息。
package acctpolicy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// policySelectSQL 是讀取單例策略的查詢（唯一拼寫來源）。
const policySelectSQL = `SELECT admin_create_standard, self_register_mode, guest_enabled, updated_at
   FROM account_creation_policy WHERE id = 1`

// Store 是策略的持久倉儲。零值不可用，請經 NewStore 取得。
type Store struct {
	clock timeutil.Clock
}

// NewStore 建立策略倉儲；clock 為 nil 時採用 timeutil.System()。
func NewStore(clock timeutil.Clock) *Store {
	if clock == nil {
		clock = timeutil.System()
	}
	return &Store{clock: clock}
}

// Get 讀回當前生效的策略。
//
// q 讓呼叫端決定這是 autocommit 現讀還是交易內現讀；建立通路日後判定放行與否時
// 必須傳自己那筆交易（「以策略生效後為準」這句話要求讀到的就是那一刻的值）。
// 回傳值一定通過 Policy.Validate：庫裡讀到不認識的模式時回錯誤而不是回半份策略。
func (s *Store) Get(ctx context.Context, q database.Querier) (Policy, error) {
	if q == nil {
		return Policy{}, errors.New("acctpolicy: 讀取策略需要可用的資料庫連線或交易")
	}
	var (
		adminCreate int64
		modeText    string
		guestOn     int64
		updatedAt   int64
	)
	err := q.QueryRowContext(ctx, policySelectSQL).
		Scan(&adminCreate, &modeText, &guestOn, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, fmt.Errorf("%w（單例行不存在，通常是資料庫被外部工具動過）", ErrNoPolicyRow)
	}
	if err != nil {
		return Policy{}, fmt.Errorf("acctpolicy: 讀取帳戶建立策略失敗: %w", err)
	}

	policy := Policy{
		AdminCreateStandard: adminCreate != 0,
		SelfRegisterMode:    Mode(modeText),
		GuestEnabled:        guestOn != 0,
	}
	// 0 是「出廠以來沒人改過」這個事實本身（見遷移 0008），不是查不到的時刻，
	// 因此換成零值 time.Time 而不是硬湊一個epoch 時刻。
	if updatedAt > 0 {
		policy.UpdatedAt = timeutil.FromMillis(updatedAt)
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

// Put 寫入策略的三個值，並以注入時鐘蓋上本次修改的時刻，回傳落庫後的現值。
//
// 只有一條 UPDATE 語句，而且 WHERE id = 1：單例表不可能有第二行可改，
// 「改不到行」在這裡不是正常的空結果而是結構缺陷，因此回 ErrNoPolicyRow，
// 讓呼叫端那筆交易連審計一起回滾——「策略沒改但審計說改過了」是最難查的半套。
//
// 呼叫端交來的 UpdatedAt 一律被忽略（時刻只有一個來源，DEC-015）；
// 值必須先通過 Policy.Validate，因此這裡不存在把不認識的模式寫進表的路。
func (s *Store) Put(ctx context.Context, q database.Querier, next Policy) (Policy, error) {
	if q == nil {
		return Policy{}, errors.New("acctpolicy: 寫入策略需要可用的資料庫連線或交易")
	}
	if err := next.Validate(); err != nil {
		return Policy{}, err
	}
	at := s.clock.Now()
	res, err := q.ExecContext(ctx, `UPDATE account_creation_policy
           SET admin_create_standard = ?, self_register_mode = ?, guest_enabled = ?, updated_at = ?
         WHERE id = 1`,
		boolToSQL(next.AdminCreateStandard), next.SelfRegisterMode.String(),
		boolToSQL(next.GuestEnabled), timeutil.ToMillis(at))
	if err != nil {
		return Policy{}, fmt.Errorf("acctpolicy: 寫入帳戶建立策略失敗: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return Policy{}, fmt.Errorf("acctpolicy: 確認策略寫入影響列數失敗: %w", err)
	}
	if affected != 1 {
		return Policy{}, fmt.Errorf("%w（UPDATE 未命中單例行）", ErrNoPolicyRow)
	}
	next.UpdatedAt = at.UTC()
	return next, nil
}

// boolToSQL 把布林換成 SQLite 的 0/1：表裡的 CHECK 認的是整數 0 與 1，
// 直接傳 Go 布林會由驅動決定怎麼綁定，而這個決定不在本倉庫的合同裡。
func boolToSQL(v bool) int {
	if v {
		return 1
	}
	return 0
}
