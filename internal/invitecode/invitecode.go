// Package invitecode 是「伺服器級註冊邀請碼」的領域規則、持久倉儲與應用服務層。
//
// 它回答的只有一件事：一臺伺服器可以簽發哪些「拿得多一個普通帳戶」的准入憑證，
// 以及這些憑證此刻還算不算數。邀請碼是建立普通帳戶的准入憑證——它不攜帶 Root／管理員權限，
// 也不代表加入任何活動；它只是「這個人被允許自行註冊」這件事的一個可核驗的憑証。
//
// 本套件只落地簽發、列表元數據與撤銷這三件事。真正拿邀請碼換出一筆帳戶的那一跳（核銷）
// 與「把自註冊模式切到 invite」屬後續步驟，本步刻意不做：internal/acctpolicy 仍把 invite
// 登記為「名字已批准、通路未落地」，所以沒有任何對外端點能把一枚碼兌換成帳戶，也沒有任何
// 通路能讓 invite 成為可寫的策略值。本套件因此不開任何核銷入口，只在存儲層預留那條
// 併發安全的核銷原語（Store.Consume）並把它釘進測試，供未來的准入通路在自己的交易裡組合。
//
// 為什麼獨立成一個套件，而不是塞進 internal/account 或 internal/acctpolicy：
//   - account 認的是「一筆已存在的穩定身分長什麼樣」，邀請碼不是身分，是「能不能長出一個身分」
//     的准入憑證（見遷移 0010 的檔頭注：把兩者混進一張表會讓一枚還沒換出任何人的碼佔住一個帳戶標識）；
//   - acctpolicy 認的是「部署者想讓哪幾條建立通路打開」這一份單例策略，它的對象是三個開關＋一個模式，
//     沒有「一枚具體的碼」這種可標識的行；邀請碼是每一枚各有額度／有效期／撤銷狀態的一份憑証，
//     兩者是不同的數據形態與生命週期，硬並在一起會讓策略表長出「一行一枚碼」的怪胎；
//   - 依賴方向因此保持單向：invitecode → identity（主體與授權）、audit（簽發與撤銷的落痕）、
//     database／idgen／timeutil；它不認 acctpolicy（簽發一枚碼不等於把准入模式打開，這是兩句話）、
//     不認 session（邀請碼換不出會話，今天也沒有任何兌換通路）、不認 account／credential
//     （本套件不碰任何一個人的憑據或行）。
//
// 四條不可讓步的規定：
//   - 邀請碼是准入憑証、不是權限。能簽發／撤銷的人只有 Root（identity.NeedRoot，與賬戶建立策略
//     同側：那三個開關決定「有沒有邀請碼這條路」，誰來拿路條本身就是服務器級的准入決定）；
//     簽出的碼不攜帶任何服務器級角色，也不代表任何活動成員身份——結構上沒有一處能寫入這些，
//     因為簽發根本不碰 accounts／account_server_roles／sessions 任何一張表。
//   - 庫裡只存驗證材料、不存碼本身。一枚碼的明文只在簽發成功的那一次回應裡出現，之後任何人
//     都讀不回來；數據庫落的是這枚隨機值的 SHA-256（小寫十六進位、定寬 64）。丟了就重新簽發一枚，
//     而不是把庫存的秘密翻出來給操作者看——這與 R2-004／R2-010 的一次性口令交付、
//     internal/session 的會話秘密同一取向。用 SHA-256 而非 Argon2id，前提是被哈希的對象是密碼學安全
//     的隨機值、不是人想出來的口令：慢哈希對隨機值換不來抗暴破強度，卻會把派生成本搬上每一次核銷。
//   - 狀態不寫成一個可被設定的欄位，而是由「已用次數＋額度上限＋有效期＋撤銷時刻」加註入時鐘
//     在讀用時派生（用戶批准：讀時判定可用性，永不自動清理）。於是這張表沒有任何一列叫 status，
//     也就沒有「兩個時鐘讀到兩個互相矛盾的 status」這種可被寫壞的真相；到期不需要排程去翻動行，
//     撤銷之外的一切狀態變化都是同一份事實的不同投影。
//   - 撤銷是單向的終態，而且撤銷碼不等於撤銷帳戶。落一次 revoked_at 之後這行不再有任何可寫
//     的東西：不能重新生效、不能再被核銷，已核銷的次數作為必要歷史留住。撤銷擋住的是「這枚碼
//     此後還能不能被用」，不是一個已經合法建出來的帳戶——本套件從不因為撤銷碼而觸碰任何帳戶、
//     會話或授予，那四件事各有自己的欄位與通路。寫庫與審計落在同一筆交易，自由文本一個都不進數據庫。
//
// 時刻與標識的來源與全專案一致（DEC-011、DEC-014、DEC-015）：created_at／revoked_at 取自注入時鐘，
// 呼叫端無權代填；標識由 idgen 產生；審計標識由 internal/audit 產生。
package invitecode

import (
	"errors"
	"log/slog"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// ErrPermissionDenied 沿用 identity 的判定結論：身分可信，但沒有這件事所需要的權限。
//
// 沿用同一個哨兵而不是另造一個，是為了讓「需要 Root」這句話在全倉庫只有一種判讀方式
// （與 internal/acctpolicy、internal/adminacct 同一口徑）。
var ErrPermissionDenied = identity.ErrPermissionDenied

// 對外可判別的結論錯誤：傳輸層據此分流回應，內部故障一律不進這些型別。
var (
	// ErrCodeNotFound 表示撤銷目標不是這張表上的一枚碼：標識不合法（非 UUID）、查無此行，
	// 或它根本不存在。三種情況一律同一個答案，不提供「差哪一半」的信號——標識是 UUIDv7，
	// 把「格式對但查無」與「格式不對」分開講等於給一條 Root 端點做碼存在性探測。
	ErrCodeNotFound = errors.New("invitecode: 該邀請碼不存在")
	// ErrAlreadyRevoked 表示這枚碼在你按下那一刻之前已經被撤銷過：整個操作沒有發生——
	// 撤銷時刻沒改、已用次數沒動、審計沒記。
	//
	// 它與 ErrCodeNotFound 分開只為處置不同：一個是「換個目標」（這張表上沒有這枚碼），
	// 另一個是「別再對同一枚已撤銷的碼按第二次」（它就在眼前這一頁，只是已經沒有第二顆按鈕）。
	// 重複操作與併發落敗收斂到同一個結論，不謊報成功，也不會把先前那次撤銷改寫成別的樣子。
	ErrAlreadyRevoked = errors.New("invitecode: 該邀請碼已被撤銷")
	// ErrInvalidLabel 表示標籤不滿足領域規則（空、過長、含控制或格式字元）。屬請求本體的寫法問題，
	// 走 1004 點名 label 欄位。
	ErrInvalidLabel = errors.New("invitecode: 邀請碼標籤不合法")
	// ErrInvalidMaxUses 表示額度上限不在許可區間（小於 1 或超過上限）。它是業務輸入錯誤，走 1004
	// 點名 max_uses：一個「零次可用」的碼不叫單次碼，而是一枚根本核銷不掉的垃圾行。
	ErrInvalidMaxUses = errors.New("invitecode: 邀請碼額度上限不合法")
	// ErrInvalidExpiry 表示有效期不合法：給了一個不晚於簽發時刻的到期時間。
	//
	// 一枚「出生即已過期」的碼沒有一句誠實的話能說清它想准入誰——它既不能被核銷、又會在下一次
	// 列表讀取時被派生成「已過期」。要麼別填（永不過期），要麼填一個未來的時刻。走 1004 點名 expires_at。
	ErrInvalidExpiry = errors.New("invitecode: 邀請碼有效期不合法")
)

// Deps 是本用例的外部依賴，全部由裝配層（internal/app）注入。
type Deps struct {
	// DB 提供交易邊界與 autocommit 查詢。
	DB *database.DB
	// Store 是邀請碼持久倉儲；nil 時由 New 以系統時鐘建一個。裝配層若要注入測試時鐘就自己傳。
	Store *Store
	// Clock 是用「現在」派生狀態的來源；nil 時採用 timeutil.System()。
	// 它與 Store 的時鐘在同一裝配裡取自同一實例：簽發落庫的時刻與列表讀到的「現在」必須同源，
	// 否則一張名冊裡的「已過期」會隨兩處時鐘不同而漂移。
	Clock timeutil.Clock
	// Audits 是 Root 域審計倉儲。缺它就開出一個「簽發／撤銷了服務器准入憑據卻查不到是誰幹的」
	// 的特權變更，正是審計要防的那件事，因此 New 把它列為必要依賴。
	Audits *audit.Store
	// Log 為伺服器端記錄出口；nil 時丟棄。
	Log *slog.Logger
}

// Service 是服務器級註冊邀請碼用例（簽發＋名冊＋撤銷）的編排者。零值不可用，請經 New 取得。
type Service struct {
	db     *database.DB
	store  *Store
	clock  timeutil.Clock
	audits *audit.Store
	log    *slog.Logger
}

// New 校驗依賴並建立服務。
//
// 少任何一個依賴都是組裝缺陷，在啟動階段當場報出：少倉儲就落不下一枚碼，
// 少審計倉儲就會簽發／撤銷服務器准入憑據而不留痕。
//
// 刻意沒有的三個依賴也是同一句話：不注入 acctpolicy（簽發一枚碼不等於把自注冊模式切到 invite，
// 那是兩條獨立的決定，模式仍由 Root 在策略端點上單獨設）、不注入 session（本套件這輩子不籤會話）、
// 不注入 account／credential（不碰任何一個人的行或憑據）。
func New(deps Deps) (*Service, error) {
	if deps.DB == nil || deps.Audits == nil {
		return nil, errors.New("invitecode: 用例缺少必要依賴（db/audits）")
	}
	clock := deps.Clock
	if clock == nil {
		clock = timeutil.System()
	}
	store := deps.Store
	if store == nil {
		store = NewStore(clock)
	}
	logger := deps.Log
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{db: deps.DB, store: store, clock: clock, audits: deps.Audits, log: logger}, nil
}

// requireRoot 把「只有 Root 能碰服務器級註冊准入憑據」收在一處：判定只經 identity.Authorize。
//
// 被拒時記一句 Warn（含主體的脫敏表示與關聯 ID），但絕不記任何標籤、碼、驗證材料或請求本體內容：
// 一個非 Root 的嘗試在日誌裡需要被看見，不需要被複述。requestTag 讓三條入口（簽發／名冊／撤銷）
// 的拒絕日誌各能認出自己是誰，而不必在每一處重寫同一段判讀。
func (s *Service) requireRoot(principal identity.Principal, requestTag string) error {
	if err := identity.Authorize(principal, identity.NeedRoot); err != nil {
		s.log.Warn("邀請碼操作被拒：主體不具備 Root 權限",
			"subject", principal.String(), "entry", requestTag)
		return err
	}
	return nil
}

// trimRequestID 保證關聯 ID 不超過審計欄位上限（與 internal/adminacct、internal/acctreview 同口徑）。
func trimRequestID(requestID string) string {
	if r := []rune(requestID); len(r) > 64 {
		return string(r[:64])
	}
	return requestID
}

// nullableFormatUTC 把零值時刻換成 nil（審計的變更前空值不冒充有效時刻），
// 其餘交 timeutil.FormatUTC（與回應本體同一個時刻表示，追查時兩邊對得起來）。
func nullableFormatUTC(at time.Time) any {
	if at.IsZero() {
		return nil
	}
	return timeutil.FormatUTC(at)
}
