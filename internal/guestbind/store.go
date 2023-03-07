// store.go 是綁定介質的持久倉儲：把憑證與留痕讀寫在遷移 0011 建的兩張表上。
//
// 與 internal/account、internal/invitecode 的倉儲同一取向：一律接受 database.Querier，
// 自己不開交易——「核銷憑證」「來源退休」「撤銷源會話」「寫下留痕」必須同生同滅，
// 那句話只有把四件事交給同一個 *database.Tx 才成立；倉儲自開會把一次綁定拆成四段，
// 而拆開的每一段都可以被併發的另一次綁定插隊。
package guestbind

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// Store 是綁定介質的持久倉儲。零值不可用，請經 NewStore 取得。
//
// 標識唯一產生點是 idgen（DEC-014）、時刻唯一來源是注入時鐘（DEC-015）、
// 憑證明文與驗證材料唯一產生點是 secret.go——三者都不接受呼叫端代填。
type Store struct {
	clock timeutil.Clock
	// newID 以欄位持有是為了讓測試注入失敗情境，驗證產生失敗時拒絕寫入而非降級格式。
	newID func() (idgen.ID, error)
	// newPlain 同上：讓測試能注入固定隨機源斷言明文形狀。
	newPlain func() (plain string, hash string, err error)
}

// NewStore 建立綁定介質倉儲；clock 為 nil 時採用 timeutil.System()。
func NewStore(clock timeutil.Clock) *Store {
	if clock == nil {
		clock = timeutil.System()
	}
	return &Store{clock: clock, newID: idgen.New, newPlain: func() (string, string, error) {
		return newTicket(nil)
	}}
}

// CreateTicketInput 是一次憑證簽發的倉儲輸入。
//
// 不含 ID、不含簽發時刻、不含明文、也不含驗證材料哈希——那四樣各有唯一產生點
// （idgen、注入時鐘、secret.go），讓呼叫端代填等於把「這枚憑證是什麼、何時生的」
// 交給請求鏈上的某一環。
type CreateTicketInput struct {
	// SourceAccountID 為綁定的來源訪戶標識（簽發時凍結，核銷時逐字比對）。
	SourceAccountID idgen.ID
	// TargetAccountID 為綁定的目標帳戶標識（只有這一个人的會話能用掉憑證）。
	TargetAccountID idgen.ID
	// IssuedByAccountID 為簽發人（伺服器級管理員）的帳戶標識。
	IssuedByAccountID idgen.ID
	// PlanDigest 為服務層按「哪些事實決定這一次綁定可行」算出的摘要（64 字元小寫十六進位）。
	PlanDigest string
	// SchemaVersion 為簽發時讀到的資料庫版本；核銷時版本不同即視為計劃過期。
	SchemaVersion int
	// ExpiresAt 為到期時刻：必由服務層依碼內常量算出，且必須晚於本次簽發時刻。
	ExpiresAt time.Time
}

// CreateTicket 持久化一枚新憑證，回傳補上標識與簽發時刻的實體，
// 並另回一次憑證明文（明文不落庫、不经任何讀法返回，這是它唯一離開服務端的机会）。
//
// 三個標識都必須非零，且來源與目標不得相同：後者不是這裡的業務判定（預檢早就把它
// 當成一條阻止原因），而是倉儲的自衛——遷移 0011 用 CHECK 把同一句話釘在表上，
// 兩處同向是为了讓「繞過服務層的直寫」也寫不出那種行。
// 到期時刻由呼叫端給（它來自注入時鐘加碼內常量），倉儲複查它晚於本次簽發時刻。
func (s *Store) CreateTicket(ctx context.Context, q database.Querier,
	in CreateTicketInput) (Ticket, string, error) {
	if q == nil {
		return Ticket{}, "", errors.New("guestbind: 需要可用的資料庫連線或交易")
	}
	if in.SourceAccountID.IsNil() || in.TargetAccountID.IsNil() || in.IssuedByAccountID.IsNil() {
		return Ticket{}, "", ErrNilIdentifier
	}
	if in.SourceAccountID == in.TargetAccountID {
		return Ticket{}, "", fmt.Errorf("%w：來源與目標是同一枚標識", ErrNilIdentifier)
	}
	digest, err := parseDigest(in.PlanDigest)
	if err != nil {
		return Ticket{}, "", err
	}
	id, err := s.newID()
	if err != nil {
		return Ticket{}, "", fmt.Errorf("guestbind: 產生憑證標識失敗: %w", err)
	}
	plain, hash, err := s.newPlain()
	if err != nil {
		return Ticket{}, "", err
	}
	createdAt := s.clock.Now()
	if !in.ExpiresAt.After(createdAt) {
		return Ticket{}, "", ErrInvalidExpiresAt
	}
	if _, err := q.ExecContext(ctx, `INSERT INTO guest_bind_tickets
			(id, ticket_hash, source_account_id, target_account_id, issued_by_account_id,
			 plan_digest, schema_version, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id.String(), hash, in.SourceAccountID.String(), in.TargetAccountID.String(),
		in.IssuedByAccountID.String(), digest, in.SchemaVersion,
		timeutil.ToMillis(createdAt), timeutil.ToMillis(in.ExpiresAt)); err != nil {
		return Ticket{}, "", fmt.Errorf("guestbind: 簽發綁定憑證失敗: %w", err)
	}
	return Ticket{
		ID:                id,
		SourceAccountID:   in.SourceAccountID,
		TargetAccountID:   in.TargetAccountID,
		IssuedByAccountID: in.IssuedByAccountID,
		PlanDigest:        digest,
		SchemaVersion:     in.SchemaVersion,
		CreatedAt:         createdAt,
		ExpiresAt:         in.ExpiresAt,
	}, plain, nil
}

// selectTicketSQL 是憑證欄位清單的唯一定義點（欄序與 scanTicket 的取值順序同源）。
//
// 刻意不含 ticket_hash：讀回的實體不需要也不該帶著驗證材料——它對外的用途只有追溯，
// 而把哈希帶在實體上迟早會讓某處把它寫進日誌或回應。
const selectTicketSQL = `SELECT id, source_account_id, target_account_id, issued_by_account_id,
		plan_digest, schema_version, created_at, expires_at, consumed_at
	FROM guest_bind_tickets`

// TicketByPlain 按憑證明文讀回憑證：明文先經 ParseTicket 收驗成正規形狀，
// 再在倉儲內部派生哈希去查——派生寫法只有 secret.go 這一處，呼叫端碰不到哈希。
//
// 查無此行、與形狀不合，對呼叫端意味著同一句話（一枚用不上的憑證），
// 因此兩者都回 ErrNotFound／ErrInvalidTicketShape，不透露「差在哪一半」：
// 這正是 2025 那句同形話的依據，不是這裡的将就。
func (s *Store) TicketByPlain(ctx context.Context, q database.Querier, plain string) (Ticket, error) {
	if q == nil {
		return Ticket{}, errors.New("guestbind: 需要可用的資料庫連線或交易")
	}
	if _, err := ParseTicket(plain); err != nil {
		return Ticket{}, ErrNotFound
	}
	row := q.QueryRowContext(ctx, selectTicketSQL+" WHERE ticket_hash = ?", hashTicket(plain))
	ticket, err := scanTicket(row)
	if err != nil {
		return Ticket{}, err
	}
	// 三個標識讀不回來代表庫被外部動過（外鍵欄不可能為 NULL 卻缺值）：
	// 那種行不能參與綁定判定，失敗方向是拒絕而不是猜。
	if ticket.SourceAccountID.IsNil() || ticket.TargetAccountID.IsNil() ||
		ticket.IssuedByAccountID.IsNil() {
		return Ticket{}, fmt.Errorf("guestbind: 憑證 %s 的標識欄異常", ticket.ID.String())
	}
	return ticket, nil
}

// ConsumeTicket 以單向條件把一枚憑證標記為已核銷；成功回 true。
//
// 這條 UPDATE 的形狀本身就是併發邊界，而不是「先查再用」：
//   - WHERE 同時釘住三件事——它存在（id = ?）、尚未被核銷（consumed_at IS NULL）、
//     此刻仍早於到期時刻（expires_at > ?）。三個條件裡任何一個不滿足，
//     這一條就是零行命中，回 false；
//   - SQLite 單寫者把同時到達的兩次核銷串行化，先提交者拿到那一行，
//     後到者拿到零行——不會出現「同一枚憑證綁了兩次」或「一枚憑證被兩個人各自用掉」。
//
// 已過期的憑證即使還帶著 consumed_at IS NULL 也用不掉：到期是失效的充分條件，
// 而「過期後還能不能用」不該由讀取时刻決定。
func (s *Store) ConsumeTicket(ctx context.Context, q database.Querier, id idgen.ID) (bool, error) {
	if q == nil {
		return false, errors.New("guestbind: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return false, errors.New("guestbind: 核銷憑證必須帶標識")
	}
	now := timeutil.ToMillis(s.clock.Now())
	res, err := q.ExecContext(ctx, `UPDATE guest_bind_tickets SET consumed_at = ?
		 WHERE id = ? AND consumed_at IS NULL AND expires_at > ?`,
		now, id.String(), now)
	if err != nil {
		return false, fmt.Errorf("guestbind: 核銷綁定憑證失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("guestbind: 讀取核銷結果失敗: %w", err)
	}
	return n > 0, nil
}

// AppendBindingInput 是一行綁定留痕的倉儲輸入。
//
// BoundAt 必須是「剛被退休的那一行上的 retired_at」——它由服務層在同一筆交易內讀回，
// 不是倉儲自己再看一次時鐘：一次綁定在資料庫裡只能有一個時刻，
// 留痕與退休行各取一次 now 會做出兩個毫秒差，而那正是「兩行各說一套」最小的形態。
// 這是本倉儲唯一接受呼叫端交來時刻的地方，理由就是上面那句（不是圖方便）。
type AppendBindingInput struct {
	// SourceAccountID 為被綁走的訪戶標識。
	SourceAccountID idgen.ID
	// TargetAccountID 為承接身份的正式帳戶標識。
	TargetAccountID idgen.ID
	// TicketID 為換得這一行留痕的憑證標識。
	TicketID idgen.ID
	// BoundAt 為綁定時刻（取自來源行的 retired_at）。
	BoundAt time.Time
	// RevokedSessions 為這次撤銷的源會話數量（0 是事實，不是失敗）。
	RevokedSessions int
}

// AppendBinding 追加一行綁定留痕。
//
// 只追加：本倉儲沒有任何改寫或删除留痕的方法（遷移 0011 的兩條觸發器把這句話
// 釘在表上，即使有人绕过這裡直寫也寫不成）。同意形態不在輸入欄裡——
// 它是常量，因為今日只有一種誠實的同意形態；留一欄給呼叫端填，
// 等於把「誰同意了這次綁定」變成自報。
func (s *Store) AppendBinding(ctx context.Context, q database.Querier,
	in AppendBindingInput) (Binding, error) {
	if q == nil {
		return Binding{}, errors.New("guestbind: 需要可用的資料庫連線或交易")
	}
	if in.SourceAccountID.IsNil() || in.TargetAccountID.IsNil() || in.TicketID.IsNil() {
		return Binding{}, ErrNilIdentifier
	}
	if in.SourceAccountID == in.TargetAccountID {
		return Binding{}, fmt.Errorf("%w：來源與目標是同一枚標識", ErrNilIdentifier)
	}
	if in.BoundAt.IsZero() {
		return Binding{}, ErrInvalidBoundAt
	}
	if in.RevokedSessions < 0 {
		return Binding{}, fmt.Errorf("guestbind: 撤銷數量不可能是負數（%d）", in.RevokedSessions)
	}
	id, err := s.newID()
	if err != nil {
		return Binding{}, fmt.Errorf("guestbind: 產生留痕標識失敗: %w", err)
	}
	if _, err := q.ExecContext(ctx, `INSERT INTO guest_account_bindings
			(id, source_account_id, target_account_id, ticket_id, bound_at,
			 revoked_sessions, consent_mode)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id.String(), in.SourceAccountID.String(), in.TargetAccountID.String(),
		in.TicketID.String(), timeutil.ToMillis(in.BoundAt), in.RevokedSessions,
		ConsentModeTargetSelfInitiated); err != nil {
		// source 欄的 UNIQUE 衝突原樣上拋：呼叫端拿它判定「這一對早已綁過了」，
		// 而那是讓整筆綁定回滾的結論，不是一次可以降級成「就当成功」的噪音。
		return Binding{}, fmt.Errorf("guestbind: 追加綁定留痕失敗: %w", err)
	}
	return Binding{
		ID:              id,
		SourceAccountID: in.SourceAccountID,
		TargetAccountID: in.TargetAccountID,
		TicketID:        in.TicketID,
		BoundAt:         in.BoundAt,
		RevokedSessions: in.RevokedSessions,
		ConsentMode:     ConsentModeTargetSelfInitiated,
	}, nil
}

// selectBindingSQL 是留痕欄位清單的唯一定義點。
const selectBindingSQL = `SELECT id, source_account_id, target_account_id, ticket_id,
		bound_at, revoked_sessions, consent_mode
	FROM guest_account_bindings`

// BindingsByTarget 讀回「目標是我」的全部綁定留痕（依綁定時刻倒序）。
//
// 這是本人查詢已完成綁定的唯一讀法：範圍由傳進來的目標標識決定，而那個標識
// 只能來自服務端換出的受信主體（見 internal/stdacct 的綁定用例），
// 所以這條通路問不出別人的綁定。沒有分頁、沒有篩選：一個人接住幾個訪戶
// 是個位數的事實，為它建分頁是把界面複雜度換成一個不存在的規模問題。
//
// 讀取路徑只做兩件事：把標識解析回來、確認同意形態仍是那個封閉值。
// 任何一樣對不上都讓整個查詢失敗——留痕是歷史解釋，
// 「讀不懂」的時候不能降級成「就当沒有」。
func (s *Store) BindingsByTarget(ctx context.Context, q database.Querier,
	targetID idgen.ID) ([]Binding, error) {
	if q == nil {
		return nil, errors.New("guestbind: 需要可用的資料庫連線或交易")
	}
	if targetID.IsNil() {
		return nil, ErrNilIdentifier
	}
	rows, err := q.QueryContext(ctx, selectBindingSQL+
		" WHERE target_account_id = ? ORDER BY bound_at DESC, id DESC", targetID.String())
	if err != nil {
		return nil, fmt.Errorf("guestbind: 讀取綁定留痕失敗: %w", err)
	}
	defer rows.Close()

	// 空帳本是「一筆都沒有」這件事本身，不是「查不到」：回 nil 會讓下游每一處
	// 都要自己判一次 nil 才能安全遍歷，而回應層把空清單編成 [] 的正直性就靠這裡。
	out := []Binding{}
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("guestbind: 讀取綁定留痕失敗: %w", err)
	}
	return out, nil
}

// scanTicket 收攏一列憑證欄位的取值與形態複核。
func scanTicket(row *sql.Row) (Ticket, error) {
	var (
		idText, sourceText, targetText, issuerText string
		digest                                     string
		schemaVersion                              int
		createdAt, expiresAt                       int64
		consumedAt                                 sql.NullInt64
	)
	err := row.Scan(&idText, &sourceText, &targetText, &issuerText,
		&digest, &schemaVersion, &createdAt, &expiresAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Ticket{}, ErrNotFound
	}
	if err != nil {
		return Ticket{}, fmt.Errorf("guestbind: 讀取綁定憑證失敗: %w", err)
	}
	return ticketFromRow(idText, sourceText, targetText, issuerText,
		digest, schemaVersion, createdAt, expiresAt, consumedAt)
}

// ticketFromRow 把一列欄位讀回憑證實體並做入庫後校驗。
//
// 標識與摘要都必須解析得回來：那代表庫被繞過校驗寫入了東西（或執行檔比資料庫舊），
// 靜默放行等於讓一枚「讀不懂的憑證」去參與綁定判定。
func ticketFromRow(idText, sourceText, targetText, issuerText, digest string,
	schemaVersion int, createdAt, expiresAt int64, consumedAt sql.NullInt64) (Ticket, error) {
	id, err := idgen.Parse(idText)
	if err != nil {
		return Ticket{}, fmt.Errorf("guestbind: 憑證標識無法解析（%s）: %w", idText, err)
	}
	source, err := idgen.Parse(sourceText)
	if err != nil {
		return Ticket{}, fmt.Errorf("guestbind: 憑證來源標識無法解析（%s）: %w", sourceText, err)
	}
	target, err := idgen.Parse(targetText)
	if err != nil {
		return Ticket{}, fmt.Errorf("guestbind: 憑證目標標識無法解析（%s）: %w", targetText, err)
	}
	issuer, err := idgen.Parse(issuerText)
	if err != nil {
		return Ticket{}, fmt.Errorf("guestbind: 憑證簽發人標識無法解析（%s）: %w", issuerText, err)
	}
	if _, err := parseDigest(digest); err != nil {
		return Ticket{}, fmt.Errorf("guestbind: 憑證 %s 的計劃摘要形狀異常: %w", idText, err)
	}
	ticket := Ticket{
		ID:                id,
		SourceAccountID:   source,
		TargetAccountID:   target,
		IssuedByAccountID: issuer,
		PlanDigest:        digest,
		SchemaVersion:     schemaVersion,
		CreatedAt:         timeutil.FromMillis(createdAt),
		ExpiresAt:         timeutil.FromMillis(expiresAt),
	}
	if consumedAt.Valid {
		ticket.ConsumedAt = timeutil.FromMillis(consumedAt.Int64)
	}
	return ticket, nil
}

// scanBinding 收攏一列留痕欄位的取值與形態複核。
func scanBinding(rows *sql.Rows) (Binding, error) {
	var (
		idText, sourceText, targetText, ticketText string
		boundAt                                    int64
		revoked                                    int
		consent                                    string
	)
	if err := rows.Scan(&idText, &sourceText, &targetText, &ticketText,
		&boundAt, &revoked, &consent); err != nil {
		return Binding{}, fmt.Errorf("guestbind: 讀取綁定留痕失敗: %w", err)
	}
	id, err := idgen.Parse(idText)
	if err != nil {
		return Binding{}, fmt.Errorf("guestbind: 留痕標識無法解析（%s）: %w", idText, err)
	}
	source, err := idgen.Parse(sourceText)
	if err != nil {
		return Binding{}, fmt.Errorf("guestbind: 留痕來源標識無法解析（%s）: %w", sourceText, err)
	}
	target, err := idgen.Parse(targetText)
	if err != nil {
		return Binding{}, fmt.Errorf("guestbind: 留痕目標標識無法解析（%s）: %w", targetText, err)
	}
	ticketID, err := idgen.Parse(ticketText)
	if err != nil {
		return Binding{}, fmt.Errorf("guestbind: 留痕憑證標識無法解析（%s）: %w", ticketText, err)
	}
	// 同意形態只認那個封閉值：讀到表外值代表庫被外部動過，
	// 而「這一次綁定是誰同意的」不能靠猜。
	if consent != ConsentModeTargetSelfInitiated {
		return Binding{}, fmt.Errorf("guestbind: 留痕 %s 帶著表外的同意形態（%q）", idText, consent)
	}
	return Binding{
		ID:              id,
		SourceAccountID: source,
		TargetAccountID: target,
		TicketID:        ticketID,
		BoundAt:         timeutil.FromMillis(boundAt),
		RevokedSessions: revoked,
		ConsentMode:     consent,
	}, nil
}
