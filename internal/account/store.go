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
//
// 語句裡刻意沒有 reviewed_at：沒有人做過決定時，一筆新行不該帶決定時刻
// （遷移 0009 的 accounts_insert_not_reviewed 觸發器把這條釘在資料庫層）。
// 待審批帳戶因此是這張表唯一一個「出生就帶著一個非登入狀態」的形態，
// 而它帶的也只有 status 一欄。
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

// SetPassword 以强制替换更換帳戶憑據：把 password_hash 換成新雜湊，並在兩欄
// 唯一被觸碰的 UPDATE 裡同步把 must_change_password 設回 1（重置後的口令是
// 一次性的，下次登入必須改掉）。
//
// 它與 RotatePassword 是同一張表上的兩條不同授權通路，而不是彼此的重用：
// RotatePassword 的 CAS 錨點是「現行雜湊」，那驗證的是「本人交得出現行口令」；
// 強制替換的發起人（Root 重置他人口令、管理員重置普通帳戶口令）拿不出也不該拿出該雜湊——
// 「拿不出舊口令」恰恰是这次操作存在的理由。因此本方法不做任何「舊值是什麼」的比對，
// 只把形状閘（validatePasswordHash，與入庫同一道）留在倉儲層；
// 「誰有資格對誰強制換口令」是使用例（internal/adminacct 經 NeedRoot 與管理員目錄成員資格、
// internal/stdacct 經 NeedServerAdmin 與普通帳戶目錄範圍規則）判定的事，
// 倉儲不假裝認識主體。
//
// 沒有 CAS 不等於沒有併發語意：SQLite 單寫入者把每次重置串行化，每次提交都是
// 「換哈希＋清旗標＋撤會話（由使用例同交易完成）」的整筆事實；後到的重置覆蓋
// 先前的哈希是既定順序的事實，不是半套狀態。
//
// UPDATE 只碰 password_hash 與 must_change_password 兩欄：status、disabled_at、
// 顯示名與各類時刻都不在語句裡——「重置不是解除停用、不是改名、不是復活」
// 成立在 SQL 形狀上，不靠呼叫端自律。
//
// 零行命中（changed=false 且無錯誤）代表目標行不存在：呼叫端通常已在同一交易
// 核實過成員資格或目錄範圍，走到 false 只剩併發刪除或程式缺陷，兩者都該讓交易回滾而不是
// 把「一個字沒寫」報成重置成功。訪客帳戶被遷移 0003 的 CHECK 凍結為
// 「無哈希、無旗標」：本方法對它必然落庫失敗。這條失敗是後一道閘，不是第一道——
// internal/stdacct 的重置用例在同一條交易的寫入之前就把訪客出局（那叫隱式升級，
// 不叫資料庫帮忙擋住了一半），adminacct 的目錄則由授予觸發器根本不含訪客。
func (s *Store) SetPassword(ctx context.Context, q database.Querier, id idgen.ID,
	newHash string) (bool, error) {
	if q == nil {
		return false, errors.New("account: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return false, errors.New("account: 強制更換憑據必須帶目標標識")
	}
	if err := validatePasswordHash(newHash); err != nil {
		return false, err
	}
	res, err := q.ExecContext(ctx,
		"UPDATE accounts SET password_hash = ?, must_change_password = 1 WHERE id = ?",
		newHash, id.String())
	if err != nil {
		return false, fmt.Errorf("account: 強制更換帳戶憑據失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("account: 讀取更換結果失敗: %w", err)
	}
	return n > 0, nil
}

// UpgradeGuestToStandard 以一條 UPDATE 把一個可用狀態的訪戶原地升級成普通帳戶：
// login_name 與它的正規化鍵換成正式登入名、account_type 落為 standard、
// password_hash 換成呼叫端派生好的雜湊、must_change_password 強制寫成 1。
//
// 這裡動的是「同一個穩定身份的分類與憑據」，不是新建一筆再刪舊一筆：
// SET 清單裡刻意沒有 id、created_at、display_name、status、last_login_at 與任何
// 刪除／審核時刻——「升級不改穩定標識、不改顯示名、不順手啟用或停用、
// 不重寫歷史時刻」因此成立在 SQL 語句的形狀上而不是呼叫端自律上。
// 舊行與舊標識原樣保留，既有審計與其他實際存在的參照繼續指回同一個人。
//
// 五欄必須同一條 UPDATE（與 MarkDeleted 三欄同形、與 SetStatus 兩欄同形的理由一致）：
// 「分類轉正、憑據落地、首次改密義務生效」是同一次升級的三面。拆開寫就會出現
// 遷移 0003 跨欄 CHECK 直接拒收的半成品（standard 卻無雜湊），或更糟的
// 「已是普通帳戶卻沒有任何口令」——那個形態連登入都進不去，卻在目錄裡像個正常人。
//
// 守衛是「他此刻確實是活著的訪戶」（WHERE account_type='guest' AND status='active'），
// 不是呼叫端交來的依據值：升級的發起人（管理員）拿不出「現行分類」這類誠實的錨點——
// 那一欄的現值就是分支本身要改的東西；而「訪戶且可用」是目錄詳情本来就读得到的事實，
// 把它放進 WHERE 就足以讓「對已轉正者的重複升級」「對已停用者的升級」都命中零行。
// 使用例會在同一個交易裡先讀回實體做範圍核實，走到 changed=false 只剩併發的另一次
// 寫入或程式缺陷，兩者都該讓交易回滾而不是報升級成功。
//
// 兩個域閘前置在寫入之前：LoginKey（與建立、登入比對同一個唯一鍵來源，因此
// 「正式登入名合不合規」「和誰撞鍵」都不抄第二套規則）與 validatePasswordHash
// （與入庫同一道形狀閘）。登入名撞唯一索引映射為 ErrDuplicateLogin，與 Create 同口徑：
// 正確性來自資料庫約束，不來自查插之間的時間窗。
func (s *Store) UpgradeGuestToStandard(ctx context.Context, q database.Querier, id idgen.ID,
	loginName, passwordHash string) (bool, error) {
	if q == nil {
		return false, errors.New("account: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return false, errors.New("account: 升級訪戶必須帶目標標識")
	}
	key, err := LoginKey(loginName)
	if err != nil {
		return false, err
	}
	if err := validatePasswordHash(passwordHash); err != nil {
		return false, err
	}
	res, err := q.ExecContext(ctx,
		`UPDATE accounts SET login_name = ?, login_name_key = ?, account_type = ?,
			password_hash = ?, must_change_password = 1
		WHERE id = ? AND account_type = 'guest' AND status = 'active'`,
		trimSpaces(loginName), key, string(TypeStandard), passwordHash, id.String())
	if err != nil {
		if isUniqueLoginKeyError(err) {
			return false, ErrDuplicateLogin
		}
		return false, fmt.Errorf("account: 升級訪戶帳戶失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("account: 讀取升級結果失敗: %w", err)
	}
	return n > 0, nil
}

// RetireGuestForBind 讓一名此刻可用的訪戶進入退休終態：同一條 UPDATE 落下
// status='retired' 與 retired_at，兩個欄位同生同滅（遷移 0011 的成對 CHECK 不接受半成品）。
//
// 這一跳只做兩件事，而且 SQL 的形狀就是那兩句話的證據：
//   - 不動 display_name：與 MarkDeleted 的區別正在這裡。退休不做匿名化——X 那個名字是歷史
//     的一部分，「他曾經叫這個名字、後來以這個標識被併入 Y」要能在讀一行資料時原样看見；
//   - 不動 account_type、不動 login_name 與其鍵、不動任何時刻欄：穩定標識存续、
//     登入名繼續被佔用（「不可複用」因此是落庫的事實而不是介面的一句勸告）、
//     憑據欄本來就為 NULL（訪戶形態凍結）也沒有可複製的東西。
//
// WHERE 守衛取的是可觀測事實而不是呼叫端交來的依據值（與 UpgradeGuestToStandard 同一取向）：
// 「訪戶且可用」是目錄詳情本来就读得到的事實，放進 WHERE 就足以讓
// 「對已退休訪戶的重複綁定」「對停用訪戶的綁定」命中零行。呼叫端已在同一筆交易裡
// 先做範圍核實與形態判定，走到 changed=false 只剩併發的另一次綁定或程式缺陷，
// 兩者都該讓交易回滾而不是報綁定成功。
//
// 時刻取自注入時鐘並由呼叫端在同筆交易內重讀取得（留痕行的 bound_at 用的就是那一個值）：
// 一次綁定在資料庫裡只有一個時刻，不留「兩行各記各的」的空间。
func (s *Store) RetireGuestForBind(ctx context.Context, q database.Querier, id idgen.ID) (bool, error) {
	if q == nil {
		return false, errors.New("account: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return false, errors.New("account: 退休訪戶必須帶目標標識")
	}
	res, err := q.ExecContext(ctx,
		`UPDATE accounts SET status = ?, retired_at = ?
		WHERE id = ? AND account_type = 'guest' AND status = 'active'`,
		string(StatusRetired), timeutil.ToMillis(s.clock.Now()), id.String())
	if err != nil {
		return false, fmt.Errorf("account: 讓訪戶進入退休終態失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("account: 讀取退休結果失敗: %w", err)
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
	if !newStatus.settable() || !expectedStatus.settable() {
		return false, fmt.Errorf("account: 停用/恢復只認 active|disabled，實際 %q/%q",
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

// DecideApplication 以一條 UPDATE 對一筆待審批申請做出決定：把 status 落成這個決定對應的
// 狀態，並在同一個語句裡把決定時刻寫進 reviewed_at；守衛是「他此刻還在等著被決定」
// （WHERE status = 'pending'），不是呼叫端交來的依據值。
//
// 為什麼必須是一條專門的語句而不是借用 SetStatus（用戶批准的取向）：
//   - SetStatus 的 CAS 硬鎖 active|disabled 兩側，那是「登入能力的開關」這條語意，
//     把 pending 塞進去等於讓目錄那顆「恢復」按鈕替你批准一個人；
//   - 批准與拒絕都必須同時留下決定時刻，而 SetStatus 的 SET 清單裡根本沒有 reviewed_at 那格。
//     拆成兩條語句就會出現「已經 active 卻查不出他是走審批進來的」那種半成品——
//     申請人查狀態那條通路分辨 approved 的依據恰恰就是這一欄。
//
// 為什麼守衛不採呼叫端交來的「我看見的是 pending」：審核者手上有誠實的依據值嗎？沒有——
// 一個還未被決定的行，其現值就是「pending」這個詞本身，把它放進本體只會多出一個
// 「填錯就注定落敗」的格子，而真正的併發控制本來就在這道 WHERE 上。與 MarkDeleted 同一取向
// （那條也是用可觀測的事實當守衛，而不是湊一個依據值）。兩個審核者同時按下時，
// SQLite 的單寫入者把兩次提交串行化，後到的那一條命中零行，回 changed=false：
// 一個字都沒寫、先前那個決定也不會被蓋掉。
//
// 時刻的唯一來源是注入時鐘：呼叫端無法代填「何時定的」（與 Create 的 created_at、
// SetStatus 的 disabled_at 同一取向）。reviewed_at >= created_at 這條單調規則由遷移 0009 的
// CHECK 在落庫時把最後一道——時鐘被往回撥過的部署會看到一條約束錯誤而不是靜默寫出一個
// 比申請還早的決定。
//
// 這隻語句不碰的欄位同樣是要害：password_hash、must_change_password、disabled_at、deleted_at、
// display_name、login_name、account_type 都不在 SET 裡。「批准不替他改口令、不清掉任何既有義務、
// 不解除任何獨立停用、不順手改頭換面」因此成立在 SQL 形狀上而不是自律上：
// 一個曾被批准此後被停用的人，approval 通路對他沒有任何可做的事（他早離開 pending 了）。
//
// 目標不存在與「已不再等待決定」收斂為同一個 changed=false：呼叫端通常已在同一交易讀回
// 實體並核實過形態，走到 false 只剩併發的另一次決定或程式缺陷，兩者都該讓交易回滾而不是
// 把「一個字沒寫」報成審批成功。
func (s *Store) DecideApplication(ctx context.Context, q database.Querier, id idgen.ID,
	decision Decision) (bool, error) {
	if q == nil {
		return false, errors.New("account: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return false, errors.New("account: 做出審批決定必須帶目標標識")
	}
	if _, err := ParseDecision(string(decision)); err != nil {
		// 復核走 ParseDecision 那唯一的入口：這裡不另寫一份「哪些詞算決定」的清單，
		// 兩處各記一套時，總有一處會先被忘了改。
		return false, err
	}
	res, err := q.ExecContext(ctx,
		"UPDATE accounts SET status = ?, reviewed_at = ? WHERE id = ? AND status = ?",
		string(decision.result()), timeutil.ToMillis(s.clock.Now()),
		id.String(), string(StatusPending))
	if err != nil {
		return false, fmt.Errorf("account: 寫入審批決定失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("account: 讀取審批決定結果失敗: %w", err)
	}
	return n > 0, nil
}

// MarkDeleted 以一條 UPDATE 讓帳戶進入刪除終態：status 落為 deleted、deleted_at 取注入時鐘、
// display_name 換成匿名化佔位值。
//
// 三個設計點各自擋的是不一樣的東西：
//   - 守衛是「他還沒被刪」（WHERE deleted_at IS NULL），不是呼叫端交來的依據值。
//     Root 對「現行刪除時刻」拿不出任何誠實的錨點（未被刪時那一欄本來就是 NULL），
//     湊一個出來驗證的也不是它宣稱的東西；而 status 是唯一的可觀測事實，
//     把它寫進 WHERE 就足以讓「第二次刪除」一個字都不落。
//   - 時刻的唯一來源是注入時鐘：呼叫端無法代填「何時刪的」，也出不了未來或零值的刪除時刻
//     （與 Create 的 created_at、SetStatus 的 disabled_at 同一取向）。
//   - 一句 UPDATE 同時改三欄：「停止登入」「留下刪除時刻」「活的投影不再顯示本人自取的名字」
//     是同一次刪除的三面，拆開寫就會出現「已 deleted 但還掛著原名」的半成品。
//
// 這隻語句不碰的欄位同樣是要害：login_name、login_name_key、password_hash、
// account_type、must_change_password、created_at、last_login_at、disabled_at 都不在 SET 裡——
// 「刪除不等於把帳戶改頭換面成另一個人」「刪除不清憑據（清憑據屬後續的物理清庫步驟）」
// 「刪除不偽造停用時刻也不抹掉既有停用時刻」因此成立在 SQL 形狀上。
// 已停用者被刪除時保留原 disabled_at：那仍是「他何時被停的」的歷史事實。
//
// 現行顯示名由呼叫端在同一個交易裡讀出後交給這裡派生：派生規則（AnonymizedDisplayName）
// 只有域層一份，呼叫端不自己拼字串，這裡也不回頭多查一次——多一次查詢就多一個
// 「兩次讀到不同值」的窗口，而呼叫端正握著那次讀的結果。
//
// 目標不存在與已被刪除收斂為同一個 changed=false：兩者對呼叫端意味著同一句話——
// 「這一次刪除沒有可發生的對象」。呼叫端通常已在同一交易核實過目錄成員資格與狀態，
// 走到 false 只剩併發刪除或程式缺陷，兩者都該讓交易回滾而不是報刪除成功。
func (s *Store) MarkDeleted(ctx context.Context, q database.Querier, id idgen.ID,
	currentDisplayName string) (bool, error) {
	if q == nil {
		return false, errors.New("account: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return false, errors.New("account: 刪除帳戶必須帶目標標識")
	}
	anonymized := AnonymizedDisplayName(s.clock.Now(), currentDisplayName)
	if err := validateDisplayName(anonymized); err != nil {
		// 派生結果不合域規則屬程式缺陷（前綴為純 ASCII、截斷只依碼位邊界），
		// 它在任何一行資料上都該永不成真；就地報錯而不是把非法值送進資料庫讓 CHECK 去擋。
		return false, fmt.Errorf("account: 匿名化顯示名不合格: %w", err)
	}
	res, err := q.ExecContext(ctx,
		"UPDATE accounts SET status = ?, display_name = ?, deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
		string(StatusDeleted), anonymized, timeutil.ToMillis(s.clock.Now()), id.String())
	if err != nil {
		return false, fmt.Errorf("account: 讓帳戶進入刪除終態失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("account: 讀取刪除結果失敗: %w", err)
	}
	return n > 0, nil
}

// selectAccountSQL 是欄位清單的唯一定義點（查詢用的欄序與 scanRow 的取值順序同源）。
const selectAccountSQL = `SELECT id, login_name, login_name_key, display_name, password_hash,
		account_type, status, must_change_password, created_at, last_login_at, disabled_at, deleted_at,
		reviewed_at, retired_at
	FROM accounts`

// scanOne 收攏 QueryRow 的取行與錯誤映射。
func scanOne(row *sql.Row) (Account, error) {
	var (
		idText, loginName, loginKey, displayName string
		passwordHash                             sql.NullString
		typeText, statusText                     string
		mustChange, createdAt                    int64
		lastLoginAt, disabledAt, deletedAt       sql.NullInt64
		reviewedAt                               sql.NullInt64
		retiredAt                                sql.NullInt64
	)
	err := row.Scan(&idText, &loginName, &loginKey, &displayName, &passwordHash,
		&typeText, &statusText, &mustChange, &createdAt, &lastLoginAt, &disabledAt, &deletedAt,
		&reviewedAt, &retiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	if err != nil {
		return Account{}, fmt.Errorf("account: 讀取帳戶失敗: %w", err)
	}
	return accountFromRow(idText, loginName, loginKey, displayName, passwordHash,
		typeText, statusText, mustChange, createdAt, lastLoginAt, disabledAt, deletedAt, reviewedAt,
		retiredAt)
}

// accountFromRow 把一列欄位讀回實體並做入庫後校驗。
//
// 標識讀不回來、或帶著表外枚舉值時一律報錯：那代表資料庫被繞過校驗寫入了東西
// （或執行檔比資料庫舊），靜默跳過會讓那筆帳戶在介面上徹底消失。
// 狀態與五個時刻的配對也在這裡複核（遷移 0007 的三條方向規則加 0009 的三條、
// 0011 的一條）：讀取路徑是「帳戶實體」唯一的成形點，
// 放行一個形態矛盾的行，等於讓下游每個用例各自決定「rejected 但沒有 reviewed_at」算什麼。
func accountFromRow(
	idText, loginName, loginKey, displayName string,
	passwordHash sql.NullString,
	typeText, statusText string,
	mustChange, createdAt int64,
	lastLoginAt, disabledAt, deletedAt, reviewedAt, retiredAt sql.NullInt64,
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
	if deletedAt.Valid {
		a.DeletedAt = timeutil.FromMillis(deletedAt.Int64)
	}
	if reviewedAt.Valid {
		a.ReviewedAt = timeutil.FromMillis(reviewedAt.Int64)
	}
	if retiredAt.Valid {
		a.RetiredAt = timeutil.FromMillis(retiredAt.Int64)
	}
	// 形態複核：0007 的三條方向規則逐字承接。
	//   - disabled 必帶停用時刻；
	//   - active 必不帶停用時刻（重新啟用時清回 NULL）；
	//   - deleted 與刪除時刻同生同滅；deleted 可保留停用時刻（被刪前本就是停用者，
	//     「何時停的」仍是歷史），所以這裡不要求「非 disabled 就必須沒有它」。
	if (a.Status == StatusDeleted) != !a.DeletedAt.IsZero() {
		return Account{}, fmt.Errorf("account: 帳戶 %s 的 status 與 deleted_at 不成對（%s/%v）",
			idText, statusText, a.DeletedAt)
	}
	if a.Status == StatusDisabled && a.DisabledAt.IsZero() {
		return Account{}, fmt.Errorf("account: 帳戶 %s 是停用狀態卻沒有停用時刻", idText)
	}
	if a.Status == StatusActive && !a.DisabledAt.IsZero() {
		return Account{}, fmt.Errorf("account: 帳戶 %s 是可用狀態卻帶著停用時刻", idText)
	}
	// 0009 新增的三條：待審批與已拒絕都不在「被停用過」那條鏈上，而決定時刻只與其中一個成對
	// （pending 必無、rejected 必有）。
	//   - pending 帶著決定時刻＝一句話裡同時有「還在等」與「已經定案」；
	//   - rejected 沒有決定時刻＝一句查不出是哪一次審核說的話；
	//   - pending／rejected 帶著停用時刻：審核中的申請人沒被誰停過用。
	// approved 那一跳之後的行（active／disabled／deleted）帶著決定時刻是合法形態，
	// 因此這裡刻意不寫「非 pending／rejected 就必須如何」——那會把開放自註冊建成的
	// 帳戶（時刻恆為 NULL）判成形態矛盾。
	if a.Status == StatusPending && !a.ReviewedAt.IsZero() {
		return Account{}, fmt.Errorf("account: 帳戶 %s 還在待審批卻帶著審核時刻", idText)
	}
	if a.Status == StatusRejected && a.ReviewedAt.IsZero() {
		return Account{}, fmt.Errorf("account: 帳戶 %s 已被拒絕卻沒有審核時刻", idText)
	}
	if (a.Status == StatusPending || a.Status == StatusRejected) && !a.DisabledAt.IsZero() {
		return Account{}, fmt.Errorf("account: 帳戶 %s 是審批鏈的狀態卻帶著停用時刻（%s）",
			idText, statusText)
	}
	// 0011 新增的三條：退休時刻只與退休態成對，而退休只屬於訪戶、不屬於「被停用過」那條鏈。
	//   - retired 必帶時刻：一句「他被併走了」沒有時刻就無從核實是哪一次綁定說的話；
	//   - 非 retired 卻帶著時刻：兩套真相同時成立（狀態說他還在，時刻說他已被併走）；
	//   - 退休行帶著停用時刻：綁定只從「可用」那一跳進入，停用中的訪戶要綁走
	//     得先恢復他的登入能力，那是另一句話（資料庫 CHECK 同樣擋死，這裡讓讀取路徑
	//     也說同一句話，外部工具改壞庫時不會有一處靜默放行）。
	if (a.Status == StatusRetired) != !a.RetiredAt.IsZero() {
		return Account{}, fmt.Errorf("account: 帳戶 %s 的 status 與 retired_at 不成對（%s/%v）",
			idText, statusText, a.RetiredAt)
	}
	if a.Status == StatusRetired && a.Type != TypeGuest {
		return Account{}, fmt.Errorf("account: 帳戶 %s 是 %s 類型卻帶著退休終態（只有訪戶會被綁走）",
			idText, typeText)
	}
	if a.Status == StatusRetired && !a.DisabledAt.IsZero() {
		return Account{}, fmt.Errorf("account: 帳戶 %s 已退休卻帶著停用時刻", idText)
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
