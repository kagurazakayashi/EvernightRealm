// store.go 是邀請碼的持久倉儲：把「一枚服務器級註冊邀請碼長什麼樣」讀寫在
// registration_invite_codes 表上（見遷移 0010）。
//
// 與 internal/account、internal/acctpolicy 的倉儲同一取向：一律接受 database.Querier，
// 自己不開交易——「簽發落庫」與「記審計」必須同生同滅，那句話只有把兩者交給同一個 *database.Tx
// 才成立；倉儲自開會「不小心」把一次簽發拆成兩段。
//
// 三條寫在形狀上的規定：
//   - 驗證材料而非明文。INSERT 只帶 SHA-256，表裡根本沒有明文碼那一列；讀回來的實體也不含明文
//     （明文只在簽發那一次由 newCode 直接交給服務層的回應，從不入庫、從不經本倉儲的任何讀法返回）。
//   - 狀態不是欄位。本倉儲沒有任何一條 UPDATE 會去寫 status／expired／used 之外可被翻動的「狀態」列，
//     因為這張表沒有那一列——可用性永遠由 (撤銷、有效期、額度、已用) 加註入時鐘在讀用時派生。
//   - 併發正確性來自數據庫條件。撤銷與核銷都用帶 WHERE 的單向 UPDATE（撤銷釘在 revoked_at = 0、
//     核銷釘在「此刻仍可核銷」的四重條件上），拿 RowsAffected 分辨贏家與落敗者，而不是先查後寫。
package invitecode

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

// ErrNotFound 表示按標識找不到邀請碼。它與數據庫故障分開：呼叫端拿碼標識來查，查不到多半是競態的尾巴
// （剛被別人撤銷並清理）或幽靈標識，屬可解釋的業務結論；查不了才是要報錯的缺陷。
var ErrNotFound = errors.New("invitecode: 找不到對應的邀請碼")

// Store 是邀請碼的持久倉儲。零值不可用，請經 NewStore 取得。
//
// 標識唯一產生點是 idgen（DEC-014）、時刻唯一來源是注入時鐘（DEC-015）、驗證材料唯一產生點是
// secret.go——三者都不接受呼叫端代填。
type Store struct {
	clock timeutil.Clock
	// newID 以欄位持有是為了讓測試注入失敗情境，驗證產生失敗時拒絕寫入而非降級格式。
	newID func() (idgen.ID, error)
}

// NewStore 建立邀請碼倉儲；clock 為 nil 時採用 timeutil.System()。
func NewStore(clock timeutil.Clock) *Store {
	if clock == nil {
		clock = timeutil.System()
	}
	return &Store{clock: clock, newID: idgen.New}
}

// CreateInput 是一次簽發的倉儲輸入。
//
// 不含 ID、不含創建時刻、不含明文碼、也不含驗證材料哈希——那四樣各有唯一產生點（idgen、注入時鐘、
// secret.go），讓呼叫端代填等於把「誰籤的、什麼時候籤的、這枚碼的秘密是什麼」交給請求鏈上的某一環。
type CreateInput struct {
	// CodeHash 是明文碼的 SHA-256 十六進位（由服務層經 newCode 取得，倉儲不重新派生）。
	CodeHash string
	// Label 是通過域校驗的標籤。
	Label string
	// MaxUses 是額度上限（>=1）。
	MaxUses int64
	// ExpiresAt 是到期時刻；零值代表永不過期（落庫為 0）。
	ExpiresAt time.Time
}

// Create 持久化一枚新邀請碼，回傳補上標識與簽發時刻的實體。
//
// q 讓呼叫端把「落庫」與「記審計」放進同一筆交易。CodeHash 必須是定寬小寫十六進位的驗證材料：
// 倉儲拒絕任何形狀不對的哈希入庫，正如它不接受明文碼——庫裡那欄本來就沒有裝明文的地方。
// ExpiresAt 非零時必須晚於本次注入時鐘的簽發時刻（域規則與遷移 0010 的 CHECK 同口徑），
// 一枚「出生即已過期」的碼不會到這裡才被攔住第二次——它在服務層就換 ErrInvalidExpiry，
// 這裡的複查擋的是繞過服務層的直寫。
func (s *Store) Create(ctx context.Context, q database.Querier, in CreateInput) (InviteCode, error) {
	if q == nil {
		return InviteCode{}, errors.New("invitecode: 需要可用的數據庫連接或交易")
	}
	if len(in.CodeHash) != codeHashLen || strings.TrimRight(in.CodeHash, "0123456789abcdef") != "" {
		return InviteCode{}, errors.New("invitecode: 驗證材料必須是定寬 64 的小寫十六進位哈希")
	}
	label, err := validateLabel(in.Label)
	if err != nil {
		return InviteCode{}, err
	}
	if in.MaxUses < 1 {
		return InviteCode{}, fmt.Errorf("%w：max_uses=%d（須 >= 1）", ErrInvalidMaxUses, in.MaxUses)
	}
	id, err := s.newID()
	if err != nil {
		return InviteCode{}, fmt.Errorf("invitecode: 產生邀請碼標識失敗: %w", err)
	}
	createdAt := s.clock.Now()
	if !in.ExpiresAt.IsZero() && !in.ExpiresAt.After(createdAt) {
		return InviteCode{}, fmt.Errorf("%w：到期時刻不晚於簽發時刻", ErrInvalidExpiry)
	}

	var expiresMillis int64
	if !in.ExpiresAt.IsZero() {
		expiresMillis = timeutil.ToMillis(in.ExpiresAt)
	}
	_, err = q.ExecContext(ctx, `INSERT INTO registration_invite_codes
			(id, code_hash, label, max_uses, used_count, created_at, expires_at, revoked_at)
			VALUES (?, ?, ?, ?, 0, ?, ?, 0)`,
		id.String(), in.CodeHash, label, in.MaxUses,
		timeutil.ToMillis(createdAt), expiresMillis)
	if err != nil {
		return InviteCode{}, fmt.Errorf("invitecode: 寫入邀請碼失敗: %w", err)
	}
	return InviteCode{
		ID:        id,
		CodeHash:  in.CodeHash,
		Label:     label,
		MaxUses:   in.MaxUses,
		CreatedAt: createdAt.UTC(),
		ExpiresAt: in.ExpiresAt.UTC(),
	}, nil
}

// ByID 按穩定標識讀回一枚邀請碼；不存在時回傳 ErrNotFound。
//
// 讀回的實體含 CodeHash（驗證材料），但絕不含明文碼——表裡根本沒有那一列可讀。
// 呼叫端（撤銷用例）拿它核實目標此刻的形態，不拿它對外回答任何東西。
func (s *Store) ByID(ctx context.Context, q database.Querier, id idgen.ID) (InviteCode, error) {
	if q == nil {
		return InviteCode{}, errors.New("invitecode: 需要可用的數據庫連接或交易")
	}
	if id.IsNil() {
		return InviteCode{}, ErrNotFound
	}
	return scanCode(q.QueryRowContext(ctx, inviteCodeSelectSQL+" WHERE id = ?", id.String()))
}

// inviteCodeSelectSQL 是讀回一整枚碼的欄位清單唯一定義點（欄序與 scanCode 的取值順序同源）。
const inviteCodeSelectSQL = `SELECT id, code_hash, label, max_uses, used_count,
		created_at, expires_at, revoked_at
	FROM registration_invite_codes`

// Revoke 以一條 UPDATE 讓一枚邀請碼進入撤銷終態：把 revoked_at 落成注入時鐘的當前時刻。
//
// 守衛是「它此刻還沒被撤銷」（WHERE revoked_at = 0），不是呼叫端交來的依據值——撤銷者手上沒有
// 一枚未撤銷的碼的「現行撤銷時刻」（那一欄本來就是 0），湊一個出來驗證的也不是它宣稱的東西；
// 與 account.MarkDeleted、account.DecideApplication 同一取向。兩個撤銷者同時按下時，SQLite 的單寫者
// 把兩次提交串行化，後到的那一條命中零行，回 changed=false：一個字都沒寫、先前那個撤銷時刻也不會被改。
//
// 這條語句不碰的欄位同樣是要害：used_count 不在 SET 裡，撤銷不抹掉已核銷的歷史；
// code_hash、label、max_uses、created_at、expires_at 都不在——撤銷只是叫停這枚碼此後還能不能被核銷，
// 不是改寫它是誰籤的、能籤幾次、什麼時候過期。目標不存在與已被撤銷收斂為同一個 changed=false：
// 呼叫端通常已在同一交易核實過目標形態，走到 false 只剩併發的另一次撤銷或程序缺陷。
func (s *Store) Revoke(ctx context.Context, q database.Querier, id idgen.ID) (bool, error) {
	if q == nil {
		return false, errors.New("invitecode: 需要可用的數據庫連接或交易")
	}
	if id.IsNil() {
		return false, errors.New("invitecode: 撤銷邀請碼必須帶目標標識")
	}
	res, err := q.ExecContext(ctx,
		"UPDATE registration_invite_codes SET revoked_at = ? WHERE id = ? AND revoked_at = 0",
		timeutil.ToMillis(s.clock.Now()), id.String())
	if err != nil {
		return false, fmt.Errorf("invitecode: 撤銷邀請碼失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("invitecode: 讀取撤銷結果失敗: %w", err)
	}
	return n > 0, nil
}

// Consume 是核銷那一條通路的原子額度扣減：只有「此刻仍有效」的碼才佔用得了一次額度，
// 成功佔用回 true、目標不存在或此刻不可核銷回 false。
//
// 為什麼這條 UPDATE 的形狀本身就是併發邊界，而不是「先查再用」：
//   - WHERE 同時釘住四件事——未被撤銷（revoked_at = 0）、未過期（expires_at = 0 OR 此刻早於到期）、
//     額度沒用滿（used_count < max_uses）、且它存在（id = ?）。四個條件裡任何一個不滿足，
//     這一條就是零行命中，回 false；
//   - 「一次加一」交給單調觸發器釘死（見遷移 0010）：併發多路核銷同一條語句，SQLite 單寫者把它們
//     串行化，總額度用滿之後所有後續核銷都是零行——不會出現「兩個人各讀到剩餘額度 = 1，於是多創建一個
//     帳戶」那種超發。正確性來自數據庫條件，不來自讀與寫之間那個根本不存在的窗口。
//
// 本步不開任何對外的核銷通路（見套件頭注：invite 模式仍未落地、沒有任何端點能把碼換成帳戶）。
// 這條原語存在的唯一理由，是把「核銷接口需要的併發邊界」用現有交易機制釘進測試：未來的准入通路會
// 在自己的交易裡調用它、據 changed 決定要不要建號，而它此刻已經站得住。
func (s *Store) Consume(ctx context.Context, q database.Querier, id idgen.ID) (bool, error) {
	if q == nil {
		return false, errors.New("invitecode: 需要可用的數據庫連接或交易")
	}
	if id.IsNil() {
		return false, errors.New("invitecode: 核銷邀請碼必須帶目標標識")
	}
	now := timeutil.ToMillis(s.clock.Now())
	res, err := q.ExecContext(ctx, `UPDATE registration_invite_codes SET used_count = used_count + 1
		 WHERE id = ? AND revoked_at = 0 AND used_count < max_uses
		   AND (expires_at = 0 OR expires_at > ?)`, id.String(), now)
	if err != nil {
		return false, fmt.Errorf("invitecode: 核銷邀請碼失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("invitecode: 讀取核銷結果失敗: %w", err)
	}
	return n > 0, nil
}

// scanCode 收攏 QueryRow 的取行與錯誤映射，並做一次入庫後的形態複核。
//
// 標識讀不回來、定寬哈希讀壞、或某個時刻把「0 = 無此事實」和真實時刻混起來時一律報錯：
// 那代表數據庫被繞過校驗寫入過東西，靜默放行會讓一枚畸形碼在名冊上冒充一個可解釋的事實。
func scanCode(row *sql.Row) (InviteCode, error) {
	var (
		idText, codeHash, label string
		maxUses, usedCount      int64
		createdAt, expiresAt    int64
		revokedAt               int64
	)
	if err := row.Scan(&idText, &codeHash, &label, &maxUses, &usedCount,
		&createdAt, &expiresAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return InviteCode{}, ErrNotFound
		}
		return InviteCode{}, fmt.Errorf("invitecode: 讀取邀請碼失敗: %w", err)
	}
	id, err := idgen.Parse(idText)
	if err != nil {
		return InviteCode{}, fmt.Errorf("invitecode: 邀請碼標識無法解析（%s）: %w", idText, err)
	}
	if len(codeHash) != codeHashLen {
		return InviteCode{}, fmt.Errorf("invitecode: 邀請碼 %s 的驗證材料長度不是 %d", idText, codeHashLen)
	}
	code := InviteCode{
		ID:        id,
		CodeHash:  codeHash,
		Label:     label,
		MaxUses:   maxUses,
		UsedCount: usedCount,
		CreatedAt: timeutil.FromMillis(createdAt),
	}
	// 0 是「沒有這個事實」本身（永不過期 / 尚未撤銷），不是查不到的時刻，因此換回零值 time.Time。
	if expiresAt > 0 {
		code.ExpiresAt = timeutil.FromMillis(expiresAt)
	}
	if revokedAt > 0 {
		code.RevokedAt = timeutil.FromMillis(revokedAt)
	}
	// 形態複核：額度與已用次數不成對（負剩餘或超發）在庫層已被 CHECK 擋住，這裡讀到的若是壞行
	// 說明庫被外部工具動過，照實報錯而不是派生出一個自相矛盾的狀態。
	if usedCount < 0 || usedCount > maxUses || maxUses < 1 {
		return InviteCode{}, fmt.Errorf("invitecode: 邀請碼 %s 的額度形態矛盾（%d/%d）", idText, usedCount, maxUses)
	}
	return code, nil
}
