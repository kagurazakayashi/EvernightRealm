package account

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

// 倉儲錯誤；呼叫端以 errors.Is 判定。
var (
	// ErrDuplicateLogin 表示登入名的正規化鍵已被佔用。
	//
	// 這是「可預期的業務衝突」而不是異常：註冊流程據此回安撫性錯誤，
	// 不把資料庫原始訊息（含索引名，屬實作細節）帶給呼叫端。
	ErrDuplicateLogin = errors.New("account: 登入名已被佔用")
	// ErrNotFound 表示按標識或登入名找不到帳戶。
	ErrNotFound = errors.New("account: 帳戶不存在")
)

// Store 是帳戶的持久化倉儲。
//
// 與 audit.Store 同一取向：標識唯一產生點是 idgen（DEC-014），
// 建立時刻唯一來源是 timeutil.Clock（DEC-015），兩者都不接受呼叫端代填。
// 零值不可用，請經 NewStore 取得。
type Store struct {
	clock timeutil.Clock
	// newID 以欄位持有是為了讓測試注入失敗情境，驗證產生失敗時拒絕寫入而非降級格式。
	newID func() (idgen.ID, error)
}

// NewStore 建立帳戶倉儲；clock 為 nil 時採用 timeutil.System()。
func NewStore(clock timeutil.Clock) *Store {
	if clock == nil {
		clock = timeutil.System()
	}
	return &Store{clock: clock, newID: idgen.New}
}

// Create 持久化一個新帳戶，回傳補上標識與建立時刻的實體。
//
// q 讓呼叫端把帳戶建立與後續關聯寫入（未來的初始活動檔案、審計）放進同一交易，
// 依 database.Querier 合同 *sql.DB 與 *Tx 皆可用。
// 唯一性走「先算鍵、INSERT 由 UNIQUE 索引兜底」：並發註冊同鍵時後到的收到
// ErrDuplicateLogin——正確性來自資料庫約束，不來自查插之間的時間窗。
// New 已完成全部領域校驗，那裏不重複檢查，也不採信呼叫端填了 ID/CreatedAt。
func (s *Store) Create(ctx context.Context, q database.Querier, in NewInput) (Account, error) {
	if q == nil {
		return Account{}, errors.New("account: 需要可用的資料庫連線或交易")
	}
	a, err := New(in)
	if err != nil {
		return Account{}, err
	}
	id, err := s.newID()
	if err != nil {
		return Account{}, fmt.Errorf("account: 產生帳戶標識失敗: %w", err)
	}
	a.ID = id
	a.CreatedAt = s.clock.Now()

	_, err = q.ExecContext(ctx, `INSERT INTO accounts (
			id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password,
			created_at, last_login_at, disabled_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID.String(), a.LoginName, a.LoginKey, a.DisplayName, nullableText(a.PasswordHash),
		string(a.Type), string(a.Status), boolInt(a.MustChangePassword),
		timeutil.ToMillis(a.CreatedAt), nullableMillis(a.LastLoginAt), nullableMillis(a.DisabledAt))
	if err != nil {
		if isUniqueLoginKeyError(err) {
			return Account{}, ErrDuplicateLogin
		}
		return Account{}, fmt.Errorf("account: 寫入帳戶失敗: %w", err)
	}
	return a, nil
}

// ByID 按穩定標識讀回帳戶；不存在時回傳 ErrNotFound。
func (s *Store) ByID(ctx context.Context, q database.Querier, id idgen.ID) (Account, error) {
	if q == nil {
		return Account{}, errors.New("account: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return Account{}, ErrNotFound
	}
	return scanOne(q.QueryRowContext(ctx, selectAccountSQL+" WHERE id = ?", id.String()))
}

// ByLoginName 按登入名讀回帳戶：輸入經 LoginKey 正規化後比對鍵，
// 因此「Admin」與「admin」找到同一帳戶——比對語意與唯一約束同源，不各寫一套。
// 無法通過登入名校驗的輸入原樣回傳 ErrInvalidLogin（查不到就是格式問題）。
func (s *Store) ByLoginName(ctx context.Context, q database.Querier, login string) (Account, error) {
	if q == nil {
		return Account{}, errors.New("account: 需要可用的資料庫連線或交易")
	}
	key, err := LoginKey(login)
	if err != nil {
		return Account{}, err
	}
	return scanOne(q.QueryRowContext(ctx, selectAccountSQL+" WHERE login_name_key = ?", key))
}

// RecordLogin 把帳戶的 last_login_at 推進到注入時鐘的當前時刻。
//
// 「何時登入成功」屬帳戶的事實而不是會話的事實（會話核心刻意不碰這一欄，
// 見 internal/session），所以更新點在登入用例：它會把本方法與 session.Create
// 放進同一個交易，兩者同生同滅。目標不存在時回傳 ErrNotFound——
// 登入用例拿到的帳戶標識必然有效，找不到只可能是程式缺陷，靜默成功會掩蓋它。
func (s *Store) RecordLogin(ctx context.Context, q database.Querier, id idgen.ID) error {
	if q == nil {
		return errors.New("account: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return ErrNotFound
	}
	res, err := q.ExecContext(ctx, "UPDATE accounts SET last_login_at = ? WHERE id = ?",
		timeutil.ToMillis(s.clock.Now()), id.String())
	if err != nil {
		return fmt.Errorf("account: 更新最近登入時刻失敗: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}

// RotatePassword 以比較-and-set 更換帳戶憑據：只有 password_hash 仍逐字等於
// expectedOldHash 時，才把它換成 newHash 並清除 must_change_password 旗標。
//
// 兩個設計點各自擋的是不一樣的東西：
//   - CAS 條件（WHERE 帶著預期舊值）：並發的兩次改密只可能有一次生效。讀舊值與寫
//     新值之間哪怕只隔一個請求，輸家也不會把贏家剛換好的雜湊蓋回去——回傳
//     changed=false 就是「你手上那份舊憑據已經不是現值」，呼叫端據此重走認證，
//     而不是先查後寫地假裝窗口不存在。
//   - 同一條 UPDATE 清掉 must_change_password：「換口令」與「首次改密義務解除」
//     是同一個事實的兩面，分兩條語句就會出現改完密還被鎖在改密頁的半套狀態。
//
// newHash 必須通過與入庫同一個形狀閘（validatePasswordHash）：倉儲不接受
// 「看起來像但解不開」的憑據，正如建立時不收一樣。
// 目標不存在與現值不符收斂為同一個 changed=false：呼叫端帶來的標識來自
// 它自己剛讀到的帳戶，兩者對它意味著同一句話——「前提已失效，重來」。
func (s *Store) RotatePassword(ctx context.Context, q database.Querier, id idgen.ID,
	newHash, expectedOldHash string) (bool, error) {
	if q == nil {
		return false, errors.New("account: 需要可用的資料庫連線或交易")
	}
	if err := validatePasswordHash(newHash); err != nil {
		return false, err
	}
	if id.IsNil() || expectedOldHash == "" {
		return false, errors.New("account: 更換憑據必須帶目標標識與預期中的現有雜湊")
	}
	res, err := q.ExecContext(ctx,
		"UPDATE accounts SET password_hash = ?, must_change_password = 0 WHERE id = ? AND password_hash = ?",
		newHash, id.String(), expectedOldHash)
	if err != nil {
		return false, fmt.Errorf("account: 更換帳戶憑據失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("account: 讀取更換結果失敗: %w", err)
	}
	return n > 0, nil
}

// UpdateDisplayName 以比較-and-set 更換帳戶顯示名：只有 display_name 仍逐字等於
// expectedDisplayName 時，才把它換成新值。
//
// 這是 RotatePassword 同一形的併發控制搬到了可展示資料上：
//   - CAS 條件擋的是「對著一份舊畫面保存」——讀現值與寫新值之間哪怕只隔一個請求，
//     後到的那筆也不會把別人剛保存好的顯示名蓋回去；changed=false 就是
//     「你手上那份現值已經不是資料庫裡的現值」，呼叫端據此重讀再改，而不是靜默覆蓋。
//   - 目标不存在與現值不符收斂為同一個 changed=false：呼叫端帶來的標識來自
//     它自己剛讀到的帳戶，兩者對它意味著同一句話——「前提已失效，重來」。
//
// 只碰 display_name 一欄：狀態、憑據、首次改密旗標與帳戶類型不在此通路之內，
// 「普通資料的保存不能連隱藏欄位一起覆蓋」因此成立在 SQL 語句的形狀上，
// 不靠呼叫端自律。新值經與建立同一個顯示名校驗（域規則只有一份），
// 落庫的是去掉首尾空白後的寫法（與 New 的入庫形態一致）。
func (s *Store) UpdateDisplayName(ctx context.Context, q database.Querier, id idgen.ID,
	newDisplayName, expectedDisplayName string) (bool, error) {
	if q == nil {
		return false, errors.New("account: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return false, errors.New("account: 更換顯示名必須帶帳戶標識")
	}
	if err := validateDisplayName(newDisplayName); err != nil {
		return false, err
	}
	res, err := q.ExecContext(ctx,
		"UPDATE accounts SET display_name = ? WHERE id = ? AND display_name = ?",
		trimSpaces(newDisplayName), id.String(), expectedDisplayName)
	if err != nil {
		return false, fmt.Errorf("account: 更換顯示名失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("account: 讀取更換結果失敗: %w", err)
	}
	return n > 0, nil
}

// SetStatus 以比較-and-set 變更帳戶的啟用狀態：只有 status 仍逐字等於
// expectedStatus 時，才寫入新狀態；進入 disabled 時由注入時鐘補上 disabled_at，
// 回到 active 時一併清回 NULL。
//
// 與 RotatePassword、UpdateDisplayName 同一形的併發控制，但擋的物件不同：
// 那兩條挡的是「對著舊畫面保存資料」，這條挡的是「對著名義上還活著的人下停用令，
// 實際上他已被別人停用（或根本已被改過）」。狀態是安全欄位，變更的正當性
// 只能錨在「你看见的那一刻它是什麼」上——先查後寫假裝窗口不存在，
// 就會出現兩個 Root 各發一次停用、第二次被說成又撤销了一輪會話的假成功。
//
// 三條域不变量在落庫前當場校驗，不接受呼叫端把資料庫推入 CHECK 才會擋的形態：
//   - 兩個狀態值都必須落在封閉集合內（active|disabled）；
//   - 新舊狀態必須不同：同值的「變更」沒有新事實可寫，且會把 disabled_at
//     與 status 的同生同滅关系推向自相矛盾的寫法（例如 active 帶時刻）；
//   - disabled 與 disabled_at 同生同滅（與遷移 0003 的跨欄 CHECK 同口徑），
//     時刻的唯一來源是注入時鐘，呼叫端無法代填「何時停的」。
//
// 目標不存在與現值不符收斂為同一個 changed=false：呼叫端帶來的標識與現值
// 都來自它自己剛讀到的帳戶，兩者對它意味著同一句話——「前提已失效，重讀再說」。
// 只碰 status 與 disabled_at 兩欄：憑據、首次改密旗標與帳戶類型不在此通路之內，
// 「停用不順手清別旗標」因此成立在 SQL 語句的形狀上，不靠呼叫端自律。
func (s *Store) SetStatus(ctx context.Context, q database.Querier, id idgen.ID,
	newStatus, expectedStatus Status) (bool, error) {
	if q == nil {
		return false, errors.New("account: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return false, errors.New("account: 變更狀態必須帶帳戶標識")
	}
	if !newStatus.valid() || !expectedStatus.valid() {
		return false, fmt.Errorf("account: 不認識的帳戶狀態 %q/%q（可用 active|disabled）",
			string(newStatus), string(expectedStatus))
	}
	if newStatus == expectedStatus {
		return false, fmt.Errorf("account: 新舊狀態同為 %q，沒有可變更為的事實", string(newStatus))
	}
	disabledAt := any(nil)
	if newStatus == StatusDisabled {
		disabledAt = timeutil.ToMillis(s.clock.Now())
	}
	res, err := q.ExecContext(ctx,
		"UPDATE accounts SET status = ?, disabled_at = ? WHERE id = ? AND status = ?",
		string(newStatus), disabledAt, id.String(), string(expectedStatus))
	if err != nil {
		return false, fmt.Errorf("account: 變更帳戶狀態失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("account: 讀取變更結果失敗: %w", err)
	}
	return n > 0, nil
}

// selectAccountSQL 是欄位清單的唯一定義點（查詢用的欄序與 scanRow 的取值順序同源）。
const selectAccountSQL = `SELECT id, login_name, login_name_key, display_name, password_hash,
		account_type, status, must_change_password, created_at, last_login_at, disabled_at
	FROM accounts`

// scanOne 收攏 QueryRow 的取行與錯誤映射。
func scanOne(row *sql.Row) (Account, error) {
	var (
		idText, loginName, loginKey, displayName string
		passwordHash                             sql.NullString
		typeText, statusText                     string
		mustChange, createdAt                    int64
		lastLoginAt, disabledAt                  sql.NullInt64
	)
	err := row.Scan(&idText, &loginName, &loginKey, &displayName, &passwordHash,
		&typeText, &statusText, &mustChange, &createdAt, &lastLoginAt, &disabledAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	if err != nil {
		return Account{}, fmt.Errorf("account: 讀取帳戶失敗: %w", err)
	}
	return accountFromRow(idText, loginName, loginKey, displayName, passwordHash,
		typeText, statusText, mustChange, createdAt, lastLoginAt, disabledAt)
}

// accountFromRow 把一列欄位讀回實體並做入庫後校驗。
//
// 標識讀不回來、或帶著表外枚舉值時一律報錯：那代表資料庫被繞過校驗寫入了東西
// （或執行檔比資料庫舊），靜默跳過會讓那筆帳戶在介面上徹底消失。
func accountFromRow(
	idText, loginName, loginKey, displayName string,
	passwordHash sql.NullString,
	typeText, statusText string,
	mustChange, createdAt int64,
	lastLoginAt, disabledAt sql.NullInt64,
) (Account, error) {
	id, err := idgen.Parse(idText)
	if err != nil {
		return Account{}, fmt.Errorf("account: 帳戶標識無法解析（%s）: %w", idText, err)
	}
	a := Account{
		ID:                 id,
		LoginName:          loginName,
		LoginKey:           loginKey,
		DisplayName:        displayName,
		PasswordHash:       passwordHash.String,
		Type:               Type(typeText),
		Status:             Status(statusText),
		MustChangePassword: mustChange != 0,
		CreatedAt:          timeutil.FromMillis(createdAt),
	}
	if !a.Type.valid() || !a.Status.valid() {
		return Account{}, fmt.Errorf("account: 帳戶 %s 帶著不認識的類型/狀態（%s/%s）", idText, typeText, statusText)
	}
	if lastLoginAt.Valid {
		a.LastLoginAt = timeutil.FromMillis(lastLoginAt.Int64)
	}
	if disabledAt.Valid {
		a.DisabledAt = timeutil.FromMillis(disabledAt.Int64)
	}
	return a, nil
}

// isUniqueLoginKeyError 判定驅動錯誤是否恰為 login_name_key 唯一衝突。
//
// 先以結果碼（2067 = SQLITE_CONSTRAINT_UNIQUE；主鍵衝突為 1555，不在此列）篩掉
// 無關失敗，再以訊息中的索引名確認撞的是登入名鍵而不是主鍵——
// 把主鍵衝突誤報成「登入名已被佔用」會掩蓋程式缺陷。
func isUniqueLoginKeyError(err error) bool {
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		if coded.Code() != 2067 {
			return false
		}
	}
	return strings.Contains(err.Error(), "accounts.login_name_key")
}

// nullableText 把空字串存成 NULL（與 audit 倉儲同一約定：空值不冒充有效資料）。
func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// nullableMillis 把零值時刻存成 NULL。
func nullableMillis(at time.Time) any {
	if at.IsZero() {
		return nil
	}
	return timeutil.ToMillis(at)
}

// boolInt 把布林存成 SQLite 的 0/1 INTEGER。
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
