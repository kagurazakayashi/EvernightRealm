// Package selfregister 是「匿名用戶自註冊為普通帳戶」的應用服務用例層：
// 開放自註冊（self_register_mode=open）時讓還沒登入的人自行建立一個可立即登入的普通帳戶，
// 核准模式（self_register_mode=approval）時讓同一個人提交一份「等待管理員審批」的申請，
// 並讓申請人憑自己的憑據查本人的申請結果。
//
// 本套件回答的是「門外的一個人此刻能不能自己開一個普通帳戶、以及他那份申請現在怎麼樣了」
// 這一句話。它與 internal/stdacct 建的是同一種主體（standard ＋ 不帶任何伺服器級角色），
// 走的卻是完全不同的授權邊界：stdacct 的主體必須持有伺服器級管理權（NeedServerAdmin），
// 而這裡根本沒有主體——呼叫者是匿名，唯一的准入依據是「寫入那一刻」的帳戶建立策略。
// 把兩者混進一個套件，「誰能建、建不建得成」就要靠同一個 Service 上的分支記，
// 那是兩套准入最容易互相污染形態；因此刻意分開。
//
// 五條不可讓步的規定：
//   - 建出來的只能是普通帳戶。角色、帳戶類型、首次改密要求都由本用例決定，
//     請求裡沒有任何格子可填：傳輸層的未知欄位規則把 role／account_type／status／
//     subject_kind／must_change_password 之類的宣稱當場拒殺（1004）。「建的是哪一類主體」
//     由「打的哪個端點、走的哪個用例」決定，不由請求內容決定。本用例不碰 internal/adminacct，
//     也永遠不可能經這條通路建出管理員。
//   - 建立前先問策略、而且問的是「寫入那一刻」的策略與模式。准入判定發生在同一筆交易內
//     讀回的現值上（acctpolicy.Store.Get 收的是呼叫端自己的交易）：Root 在任何一刻把模式
//     改回 closed 或關掉通路，下一條註冊請求就必然按新值判定，不存在「頁面還開著、
//     背地裡策略已關卻仍建成」的窗口。前端依 /auth/capabilities 顯示入口只是體驗，
//     不是准入——真正的閘門永遠在這裡、在交易內。
//   - 服務模式與落成的狀態一起看：open 落成 active（口令本人自選、選完就能登入），
//     approval 落成 pending（同一個口令、同一形態的普通帳戶，只是還沒有人批准過他），
//     invite 落成 active（同一個口令、同一形態的普通帳戶，差別只在准入依據換成一枚被原子核銷的
//     邀請碼——它與 open 在「建完就能登入」這一句完全一致，多的一道核銷不改登入行為）；
//     尚未落地的模式（本版本三條准入通路 open／approval／invite 都已翻真，故只剩不認識的值）
//     一律回 ErrRegisterModeUnsupported（2016）而不是默默按 open 建號——那等於替尚未實作的
//     准入流程冒充可用。待審批不等於已激活這句話不是靠措辭成立的：
//     它落在 accounts.status 上，而登入、主體成形、會話簽發與解析都寫成「不是 active 就拒絕」。
//   - 待審批的申請人不取得任何登入能力，也拿不到一枚會話。他查本人狀態的那條通路
//     （ApplicationStatus）每次都要重新出示憑據、成功也不寫 Set-Cookie、不回任何會話材料：
//     「我申請了、我想知道結果」與「我能進去了」必須是兩道獨立證明的兩件事，
//     否則待審批者就握著一枚能碰普通業務的憑據，而這正是本步刻意不造的東西。
//   - 寫入與審計落在同一筆交易。匿名建的仍是「一個能登入伺服器的人」，這是伺服器級動作，
//     痕跡因此落在 root_audit（ScopeRoot）。匿名請求沒有可信主體，actor 用 ActorSystem
//     （actor.id 為 Nil）：既不冒充 Root／管理員，也不給一個「查得出是誰建的」的假承諾——
//     本來就查不出（沒有人知道的那個申請人）。操作者資訊只有來源位址與請求關聯 ID，
//     它們進執行日誌與訪問日誌，不進審計 actor。
//
// 憑據一律經 internal/credential 以裝配層注入的當前參數檔派生（與登入、Root 初始化、
// 本人改密、開設管理員、管理員建號同一個實作點），本套件不另寫一套口令規則，
// 也不落庫、不回傳任何口令明文。
//
// 匿名入口的兩道資源防線（使用者批准的「最完整機制」，閾值全在組態檔可調）：
//   - 頻率：提交申請走一條專屬的 auth.LoginGuard 實例（與登入守衛分開的記憶體、分開的閾值），
//     計量主軸是「來源位址 × 登入名正規化鍵」。重名與不合規輸入計為失敗、成功註冊勾銷該配對；
//     被擋的嘗試統一回可判別 ThrottledError（傳輸層映射 2006＋Retry-After），
//     而且到不了查庫、派生與審計那三樣最貴的資源。
//   - 派生併發：一個以 RegisterHashConcurrency 大小的訊號量封頂同時進入 Argon2id 的註冊數，
//     把「併發刷註冊燒 CPU」這條路線的天花板壓住；超出的請求在訊號量上等待、可被 context 取消，
//     等待期不佔交易、不寫審計、不做派生。
//
// 查狀態那條通路用的是另一份帳：它與登入一樣是「拿一枚口令去對一個名字」，
// 所以共用裝配層那一個登入守衛實例（同一份記憶體）。给它另立一條分账的預算，
// 等於讓同一個攻擊者對同一個「來源×名字」多拿一份猜口令的機會，
// 而那恰恰是這條通路唯一能燒的資源。
//
// 關於「枚舉」：任何讓匿名者「自行選一個唯一登入名」的端點，結構上就是一個存在性探測器——
// 一次成功即代表這個名字還沒被佔用。這不是措辭能掩蓋的（也刻意不掩蓋：對外用可判別的重名碼 2019，
// 讓正常用戶知道要換名字），真正的批量防護來自上面的緊限流與併發封頂，而非把回應整形成全同形。
// 查狀態則相反：它先要證明口令，查無此名、訪客帳戶與口令不符收斂成同一句話（2001），
// 因此它對「誰的名字存在」不新增任何信號。
// 機械驗證碼（機器人雲）與郵件服務都不在本步範圍（既定邊界），因此這裡不引入、也不宣稱已具備那兩道防線。
package selfregister

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/invitecode"
)

// 對外可判別的結論錯誤：傳輸層據此分流回應，內部故障一律不進這些型別。
var (
	// ErrThrottled 是來源被限流擋下的結論哨兵（經 ThrottledError 帶著剩餘冷卻時間上拋）。
	//
	// 它是「此刻這個來源對這個名字嘗試過多」的狀態，不是権限、也不是登入名本身的對錯。
	// 傳輸層據此回 2006＋Retry-After，與登入限流同一個機器碼：被擋的嘗試不透露
	// 它擋的是哪個名字、也不因為「這是註冊而非登入」就多開一個可分辨的外在信號。
	ErrThrottled = errors.New("selfregister: 自註冊嘗試過於頻繁")
	// ErrRegisterDisabled 表示帳戶建立策略此刻不開放自註冊（模式為 closed、值不認識、
	// 或通路未落地）。
	//
	// 它是策略決定而不是權限或輸入問題：請求本體沒有任何可改的欄位，重新整理或換名字都不會讓它變成放行，
	// 因此必須有自己的結論讓傳輸層回 2017，不能報 1004 誤導人去改欄位，也不能報 2011
	// 誤導人「換個身分或重登就有效」。
	ErrRegisterDisabled = errors.New("selfregister: 開放自註冊此刻未啟用")
	// ErrRegisterModeUnsupported 表示策略放開了自註冊，但生效的模式是本版本服務不動的那一種
	// （通路登記尚未翻真，或送來一個不認識的模式值）。
	//
	// 與 ErrRegisterDisabled 分開，是因為這兩句話對操作者的意義不同：一個是「伺服器沒開這條路」，
	// 另一個是「這條路開著、但它要求的准入功能還沒上線」。回 2016（模式尚未開放）而不是 2017，
	// 也和 internal/acctpolicy 對「策略值不等於能力」的同款區分對齊。
	// open、approval 與 invite 三種准入通路現都已翻真，這一格今日留給「不認識的模式值」與
	// 裝配缺陷（策略記了一個本執行檔不服務的模式），不再是用戶路徑上會遇到的結論。
	ErrRegisterModeUnsupported = errors.New("selfregister: 該自註冊模式對應的准入流程尚未上線")
	// ErrInviteRejected 是 invite 模式下「這一枚碼這一次換不出一筆帳戶」的對外結論。
	//
	// 它把 internal/invitecode 的三類內部原因（形状不合格、查無此碼、此刻不可核銷——後者又含
	// 撤銷／過期／用盡／併發落敗）以及「完全沒帶碼」一律收斂成同一句話：呼叫端據此無法分辨一枚碼
	// 是拼錯、被撤銷、用完了、還是這臺伺服器根本沒簽過它，於是這條准入通路不會淪為逐枚探測碼
	// 有效性的探測器。批量防護交給與 open 同一條緊限流（來源×登入名）與併發封頂，而非把回應整形。
	// 它是策略放開 invite 之後、這個請求缺的那一味准入憑證——換名字、改寫法、重新整理都換不來結果，
	// 要等的是發碼的人再給一枚有效碼，所以它自有一枚可判別碼（對映 2023），不與 1004／2016／2017 混。
	ErrInviteRejected = errors.New("selfregister: 邀請碼無效或此路徑未帶邀請碼")
	// ErrDuplicateLogin 表示登入名的正規化鍵已被佔用。
	//
	// 對外用可判別的 2019（建號重名），與需要已認證主體的 2012 分開：2012 的既有合同寫明
	// 「只在 Root 的開設入口上出現」，不讓它順帶變成匿名端點的回應。正常用戶據此知道要換名字；
	// 這同時承認了匿名選名端點天然的存在性探測性質，批量防護交給限流與併發封頂。
	ErrDuplicateLogin = errors.New("selfregister: 登入名已被佔用")
	// ErrInvalidPassword 表示口令不滿足憑據模組的形狀界線（空或超長）。
	//
	// 走 1004（點名 password 欄位）：這是請求本體哪個欄位不合規，與策略、與名字是否存在無關。
	// 刻意不設口令最低強度——那是一個尚未批准的産品決定；本用例沿用內部既有建號路徑同款的
	// 「非空、不超長」界線，強度政策若要加須另案。
	ErrInvalidPassword = errors.New("selfregister: 口令不滿足憑據形狀界線")
	// ErrInvalidCredentials 表示查狀態時「這個名字配上這枚口令」不成立。
	//
	// 查無此名、訪客帳戶（無憑據可對）、口令形狀不合格與口令不符收斂成同一句話，
	// 而且四條路徑都做過等時的佔位派生：這條通路對「誰的名字存在」不新增任何信號，
	// 與登入端點同形（沿用 2001，不為「這是查狀態而不是登入」另開一枚可分辨的碼）。
	ErrInvalidCredentials = errors.New("selfregister: 憑據無效")
	// ErrNotAnApplication 表示憑據成立，但這一筆帳戶不經審批通路。
	//
	// 它只在「已經證明你是他本人」之後才可能回出來，所以對外人是一個探測不到的回答；
	// 處置也與其他結論都不同：不是換名字、不是等冷卻、不是等策略放開，而是「直接去登入」。
	// 一個剛被批准的申請人不會拿到這句話——他帶著審核時刻，因而回的是 approved。
	ErrNotAnApplication = errors.New("selfregister: 這個帳戶不是待審批的申請")
)

// ThrottledError 是帶著剩餘冷卻時間的 ErrThrottled。
//
// 它讓 errors.Is(err, ErrThrottled) 成立，不認識這個型別的呼叫端也不會漏判；
// RetryAfter 給傳輸層算 Retry-After 標頭用。
type ThrottledError struct {
	RetryAfter time.Duration
}

func (e *ThrottledError) Error() string {
	return "selfregister: 自註冊嘗試過於頻繁，暫不受理"
}

// Unwrap 讓 errors.Is(err, ErrThrottled) 成立。
func (e *ThrottledError) Unwrap() error { return ErrThrottled }

// RegisterInput 是匿名自註冊所需的領域輸入。
//
// 沒有任何角色、帳戶類型、審批狀態或旗標欄位：本用例建的只有
// 「standard ＋ 不帶任何伺服器級角色 ＋ 口令本人自選故首次不必改密」這一種主體，
// 而它落地成 active 還是 pending 由「策略此刻是哪個模式」決定，不由請求欄位決定。
type RegisterInput struct {
	// LoginName 為登入名原始寫法；正規化唯一鍵由帳戶域層計算。
	LoginName string
	// DisplayName 為顯示名稱（不承擔唯一性）。
	DisplayName string
	// Password 為申請人自選的口令明文。它只在本次調用期間短暫停留：派生成雜湊後即不再被引用，
	// 不進回應、日誌、審計或任何錯誤訊息。
	Password string
	// InviteCode 為申請人帶來的邀請碼明文，只在 invite 模式被讀取：其他模式一概不看它、不核銷它，
	// 於是一支碼在 open／approval 那一側永遠不會被順手吃掉，也不會有「多塞一格就把准入改成另一種」的格子。
	// 它屬短暫停留的秘密：不進回應、日誌、審計、任何錯誤訊息，也不進 URL；正規化為「正規形態」與派生
	// 驗證材料都由 internal/invitecode 那一個寫法負責（ParseCode＋哈希），本用例不自己拼一份。
	InviteCode string
}

// RegisteredAccount 是一次成功註冊的結果，全部為可展示的事實（不含任何憑據材料）。
type RegisteredAccount struct {
	// AccountID 為新帳戶的穩定標識——註冊成功即得到它，與是否加入任何活動無關。
	// 待審批的申請人也有它：統一帳戶模型下，申請人從提交那一刻起就是同一個人，
	// 批准不是把一筆申請「搬成」一個帳戶。
	AccountID idgen.ID
	// LoginName 為登入名原始寫法。
	LoginName string
	// DisplayName 為顯示名稱。
	DisplayName string
	// Status 為帳戶狀態：open 模式落成 active（立即可登入），approval 模式落成 pending
	// （等管理員審批）。這兩句話的處置完全不同，而界面要的依據就是這一欄——
	// /auth/capabilities 那個匿名入口不透露模式名字（用戶批准），因此「提交之後是
	// 立刻能用還是得等」由寫入那一刻的伺服器回答，不由界面猜。
	Status account.Status
	// MustChangePassword 為首次登入是否必須改密（本用例恆為 false：口令是本人自選的，
	// 「選完之後不需要再被人改一次才能登入」是既定語意，與 open／approval 兩種模式都成立——
	// 後者等的不是口令，是批准）。
	MustChangePassword bool
	// CreatedAt 為建立時刻（UTC，取自注入時鐘）。待審批的那一筆它是「申請提交於何時」，
	// 所以申請人查狀態時看到的 submitted_at 就是這個時刻，不需要另設一個「申請時間」欄。
	CreatedAt time.Time
}

// Deps 是本用例的外部依賴，全部由裝配層（internal/app）注入。
type Deps struct {
	// DB 提供交易邊界與 autocommit 查詢。
	DB *database.DB
	// Accounts 是帳戶倉儲（登入名正規化與唯一鍵的公共能力即來自它）。
	Accounts *account.Store
	// Policy 是帳戶建立策略倉儲。准入放不放行、按哪種模式放行問的是 acctpolicy，
	// 不自己查那張表——策略的解讀規則（含「策略值不等於能力」的合成）必須只有那一個來源。
	Policy *acctpolicy.Store
	// Invites 是邀請碼倉儲，只在 invite 模式的交易內被呼叫一次 Redeem 做原子核銷：
	// 它接受本用例交來的 *database.Tx，於是「佔用一次額度」與「建一筆帳戶＋記審計」同生同滅。
	// 依賴方向單向（selfregister → invitecode）：本套件認得「核銷一枚准入憑證」這一步，
	// internal/invitecode 卻不認得註冊／帳戶／會話（簽發一枚碼不等於把它兌成帳戶，那句話在兩側都成立）。
	// 只取倉儲、不取簽發／撤銷那半個 Service：本用例永不簽碼、永不撤碼、也不回顯任何一枚碼。
	Invites *invitecode.Store
	// Audits 是 Root 域審計倉儲。匿名建號的痕跡與其餘伺服器級動作落在同一張表。
	Audits *audit.Store
	// Guard 是「提交註冊」這條通路專屬的頻率守衛。它是獨立於登入守衛的另一個 auth.LoginGuard
	// 實例（另一份記憶體、一組較緊且可組態的閾值），呼叫者是匿名的，
	// 被擋的嘗試不查庫、不派生、不寫審計。
	Guard *auth.LoginGuard
	// CredentialGuard 是「查本人申請狀態」用的頻率守衛，而且刻意是裝配層給登入用的那一個
	// 實例（同一份記憶體、同一組閾值）。理由不是省一個結構：這條通路與登入做的是同一件事
	// ——拿一枚口令去對一個名字——另立一條分账的預算，等於讓同一個來源對同一個名字
	// 多拿一份猜口令的機會，而那正是這條通路唯一能燒的資源。
	CredentialGuard *auth.LoginGuard
	// Hashing 是當前參數檔（與登入、Root 初始化、開設管理員、建號共用同一來源）。
	Hashing credential.Params
	// HashConcurrency 封頂同時進入 Argon2id 派生的註冊數（由 RegisterHashConcurrency 給）。
	// 必須 >=1：0 或負值會在訊號量上永久卡死每一筆註冊，屬組裝缺陷，New 當場擋。
	HashConcurrency int
	// Log 為伺服器端記錄出口；nil 時丟棄。
	Log *slog.Logger
}

// Service 是自註冊用例的編排者。零值不可用，請經 New 取得。
type Service struct {
	db              *database.DB
	accounts        *account.Store
	policy          *acctpolicy.Store
	invites         *invitecode.Store
	audits          *audit.Store
	guard           *auth.LoginGuard
	credentialGuard *auth.LoginGuard
	hashing         credential.Params
	hashSem         chan struct{}
	log             *slog.Logger
}

// New 校驗依賴並建立服務。
//
// 缺任何一個依賴都是組裝缺陷，在啟動階段當場報出：少策略倉儲就問不到「此刻准不准自註冊」，
// 等於默認放行；少守衛就少了一道匿名防線，等於默認接受無限刷；少審計倉儲就建出一個不留痕的
// 伺服器級主體變更。CredentialGuard 與 Guard 可以是同一個實例（本版本的裝配層讓註冊用獨立實例、
// 查狀態用登入那份實例），但兩者都不能是 nil——少它就是少一道口令暴力防護。
// HashConcurrency 不在 1..上限內同樣中斷啟動——訊號量容量是防線本身，裝錯一個數量級不該帶著上路。
func New(deps Deps) (*Service, error) {
	if deps.DB == nil || deps.Accounts == nil || deps.Policy == nil || deps.Invites == nil ||
		deps.Audits == nil || deps.Guard == nil || deps.CredentialGuard == nil {
		return nil, errors.New("selfregister: 用例缺少必要依賴（db/accounts/policy/invites/audits/guard/credential_guard）")
	}
	if err := deps.Hashing.Validate(); err != nil {
		return nil, fmt.Errorf("selfregister: 憑據雜湊參數檔不合格: %w", err)
	}
	if deps.HashConcurrency < 1 || deps.HashConcurrency > maxHashConcurrency {
		return nil, fmt.Errorf("selfregister: 派生併發上限需為 1..%d，實際為 %d", maxHashConcurrency, deps.HashConcurrency)
	}
	logger := deps.Log
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		db:       deps.DB,
		accounts: deps.Accounts,
		policy:   deps.Policy,
		invites:  deps.Invites,
		audits:   deps.Audits,
		guard:    deps.Guard,
		// 兩個守衛欄位存的都只是呼叫端交來的實例：本步的裝配層讓 Guard 指向註冊專屬那一份、
		// CredentialGuard 指向登入那一份。要不要同一個實例由裝配層決定，本套件不自己換。
		credentialGuard: deps.CredentialGuard,
		hashing:         deps.Hashing,
		// 緩衝通道當作計數訊號量：容量即同時允許的派生數，寫入取得額度、讀出歸還額度。
		hashSem: make(chan struct{}, deps.HashConcurrency),
		log:     logger,
	}, nil
}

// maxHashConcurrency 是派生併發上限在本層的構造界線（組態層另有更小的上界 1..64）。
// 這裡放寬到千位元組量級只是為了「不把一個明顯荒謬的大緩衝區分配成功」——訊號量本身是有限資源。
const maxHashConcurrency = 4096

// guardTargetMaxRunes 與 internal/auth 的登入守衛同款：正規化失敗時退回截斷後的原始登入名，
// 截到這個碼位上限，海量隨機髒名就不可能用超長鍵撐爆守衛記憶體。
const guardTargetMaxRunes = 200

// statusForMode 把「策略此刻是哪個模式」換成「這筆帳戶生下來是什麼狀態」。
//
// 第二個回傳值是「這個模式在本版本服務不服務得動」——它經 acctpolicy.ModeServed 問通路登記，
// 不在這裡另寫一份模式名單：同一條「策略值不等於能力」的規則有兩處實作時，總有一處會被忘了改。
//
//   - open／invite → active：開放自註冊的既定語意就是「選完口令立刻能用」，invite 只是准入依據
//     換成一枚被原子核銷的碼，建成之後的登入行為與 open 完全一致（都是 active、都能立即登入、
//     都不在註冊這一步簽會話）；
//   - approval → pending：同一個口令、同一類主體，差別只在還沒有人批准過他。
//     待審批不是「半可用的 active」，而是一個自己的狀態，理由寫在 internal/account 的 Status 頭注：
//     現行所有登入能力閘門都寫成「status 不是 active 就拒絕」，把待審批做成一個 status 取值，
//     那些閘門一個字都不用改就自動把他擋在門外；
//   - 其餘（不認識的值，或某條通路登記被撤下）→ false：呼叫端據此回 ErrRegisterModeUnsupported，
//     不默默按 open 建號。
func statusForMode(mode acctpolicy.Mode) (account.Status, bool) {
	if !acctpolicy.ModeServed(mode) {
		return "", false
	}
	if mode == acctpolicy.ModeApproval {
		return account.StatusPending, true
	}
	return account.StatusActive, true
}

// ApplicationOutcome 是申請人查本人狀態時能得到的結果。
//
// 三個取值就是那個人需要知道的三種結局，沒有第四種：這裡不回答「審核排到第幾位」「還有人嗎」
// 「誰在審」「為什麼拒」——前兩者屬伺服器的內部狀態；「誰在審」屬 root_audit 的事實
// （帳戶表沒有一格放審核人，見 internal/acctreview）；而「為什麼拒」今日根本不存在：
// 用戶批准的形態是內部備註與可公開理由都不落庫，所以這條通路也沒有東西可以藏。
type ApplicationOutcome string

const (
	// OutcomePending 是Still在等：申請已落地，還沒有人做過決定。
	OutcomePending ApplicationOutcome = "pending"
	// OutcomeApproved 是已批准：他當初被放行成一個可登入的帳戶。
	// 注意這一格回答的是「申請的結局」，不是「他現在還能不能登入」——批准之後被人停用或刪除的，
	// 申請結局仍是已批准，而登入那一步會按現行的停用／刪除語意如實拒絕他。
	// 把兩者混成一格的話，受限狀態通路就變成第二套登入能力判定，而那正是本步要避免的事。
	OutcomeApproved ApplicationOutcome = "approved"
	// OutcomeRejected 是已拒絕：審核做過一次拒絕的決定（時刻可回溯，理由不在這一格裡）。
	OutcomeRejected ApplicationOutcome = "rejected"
)

// String 回傳協議表示。
func (o ApplicationOutcome) String() string { return string(o) }

// ApplicationStatusInput 是查本人申請狀態所需的領域輸入。
//
// 只有登入名與口令兩欄：沒有任何「申請編號」「帳戶標識」可填。這不是省事——
// 一個可猜測的編號就等於一條「不用出示憑據也能讀別人申請」的通路，
// 而用戶批准的形態是「每一次查詢都重新證明你是他本人」。
type ApplicationStatusInput struct {
	// LoginName 為登入名原始寫法（經正規化鍵比對，與登入同一語意）。
	LoginName string
	// Password 為申請人自選的口令明文，只用於本次校驗：不進回應、日誌、審計或任何錯誤訊息。
	Password string
}

// ApplicationStatus 是一次成功查詢的結果，全部為申請人自己的事實（不含任何憑據材料）。
type ApplicationStatus struct {
	// Outcome 是申請的結局。
	Outcome ApplicationOutcome
	// SubmittedAt 是申請提交時刻（即帳戶的建立時刻，UTC）。
	SubmittedAt time.Time
	// ReviewedAt 是審核做出決定的時刻；零值代表「還沒有決定」（Outcome 為 pending 時必然如此）。
	ReviewedAt time.Time
}

// ApplicationStatus 讓一個申請人憑自己的憑據查本人申請的狀態，不簽發任何會話。
//
// 為什麼這條通路存在：待審批的人既不能登入（status 不是 active），也不該拿到一枚能碰普通業務的
// 憑據，但他已經交了自己的口令、值得一個「我的申請現在怎麼樣了」的答案。
// 於是這一條通路只做一件事——驗證憑據、回報他自己那筆申請的結局——
// 不寫 Set-Cookie、不產生會話行、不進 session 表，也沒有任何「狀態證明令牌」需要壽命與撤銷邊界：
// 每一次查詢都是一次全新的憑據證明，關掉頁面就什麼都不剩下。
//
// 順序與每一跳的理由：
//  1. 頻率先於查庫與派生：用的是裝配層給登入的那一份守衛（見 Deps.CredentialGuard），
//     計量主軸與登入同為「來源位址 × 登入名正規化鍵」，所以「先刷登入再刷查狀態」
//     用的是同一份預算，不會因為多了一條門而多拿一份猜口令的機會。
//  2. 登入名先過帳戶域的正規化閘：與註冊同一道閘、同一個失敗計價（可歸因於呼叫端的輸入）。
//  3. 口令形狀先做廉價檢查：空或超長時不進 Argon2，結論直接是「憑據無效」（2001），
//     與「口令不符」同形——這一條通路不是表單校驗，點名欄位對攻擊者只有好處。
//  4. 查無此名與訪客帳戶都做等時佔位派生再回同一句話：與登入端點逐字同形，
//     因此「誰的名字存在」「誰是訪客」在這裡探不到（時間差與回應文字都沒有）。
//  5. 憑據成立之後才分辨結局（見 outcomeOfApplication）。被拒的查詢一律不寫審計：
//     它讀的是申請人自己的事實，而拒絕的結論不該成為寫入放大器；
//     那次嘗試的來源、時刻與關聯 ID 在執行日誌與訪問日誌裡都有。
//
// 這條通路不問帳戶建立策略：用戶批准的語意是「模式只管新提交，歷史申請原地保留」。
// Root 把 approval 改成 closed 或 open，都不能替任何一份已經交上來的申請做決定，
// 所以那些申請此刻照樣查得到——查得到不等於放行，放行屬 internal/acctreview 那條
// 需要已認證管理者的通路，與這條驗憑據的匿名通路是兩道獨立證明。
func (s *Service) ApplicationStatus(ctx context.Context, in ApplicationStatusInput,
	requestID, sourceIP string) (ApplicationStatus, error) {
	target := guardTarget(in.LoginName)

	if blocked := s.credentialGuardCheck(sourceIP, target); blocked != nil {
		return ApplicationStatus{}, blocked
	}

	if _, err := account.LoginKey(in.LoginName); err != nil {
		s.credentialGuardFailure(sourceIP, target)
		if errors.Is(err, account.ErrInvalidLogin) {
			s.log.Warn("查申請狀態被拒：登入名不合領域規則", "request_id", requestID)
			return ApplicationStatus{}, err
		}
		s.log.Error("查申請狀態的登入名正規化失敗", "request_id", requestID, "err", err)
		return ApplicationStatus{}, fmt.Errorf("selfregister: 正規化登入名失敗: %w", err)
	}

	if !passwordShapeValid(in.Password) {
		// 口令形狀不合格與「口令不符」收斂成同一句話：前者是本次憑據不成立，
		// 後者也是。這一條通路的對外結論不該替攻擊者排除任何一種憑據失敗。
		s.credentialGuardFailure(sourceIP, target)
		s.log.Warn("查申請狀態被拒：口令不成立", "request_id", requestID)
		return ApplicationStatus{}, ErrInvalidCredentials
	}

	a, err := s.accounts.ByLoginName(ctx, s.db.SQL(), in.LoginName)
	if err != nil {
		if errors.Is(err, account.ErrNotFound) {
			s.equalize(in.Password)
			s.credentialGuardFailure(sourceIP, target)
			s.log.Warn("查申請狀態被拒：查無此登入名", "login_name", in.LoginName, "request_id", requestID)
			return ApplicationStatus{}, ErrInvalidCredentials
		}
		if errors.Is(err, account.ErrInvalidLogin) {
			// 上面已過同一道閘，走到這裡是倉儲內部的二次校驗攔下的同一件事，不另分類。
			s.credentialGuardFailure(sourceIP, target)
			return ApplicationStatus{}, err
		}
		s.log.Error("查申請狀態時讀取帳戶失敗", "request_id", requestID, "err", err)
		return ApplicationStatus{}, fmt.Errorf("selfregister: 讀取帳戶失敗: %w", err)
	}

	if a.Type == account.TypeGuest {
		// 訪客無憑據可對：與「查無此人」同一句話，不透露「這個名字存在但他是個訪客」。
		s.equalize(in.Password)
		s.credentialGuardFailure(sourceIP, target)
		s.log.Warn("查申請狀態被拒：訪客帳戶無口令通路", "account", a.ID.String(), "request_id", requestID)
		return ApplicationStatus{}, ErrInvalidCredentials
	}
	ok, err := credential.Verify(a.PasswordHash, in.Password)
	if err != nil {
		// 入庫憑據解不開屬資料缺陷：對外仍是「憑據無效」（與登入同一取向），對內這是一條要查的錯誤。
		s.log.Error("查申請狀態時發現憑據編碼不可校驗", "account", a.ID.String(),
			"request_id", requestID, "err", err)
		return ApplicationStatus{}, ErrInvalidCredentials
	}
	if !ok {
		s.credentialGuardFailure(sourceIP, target)
		s.log.Warn("查申請狀態被拒：口令不符", "account", a.ID.String(), "request_id", requestID)
		return ApplicationStatus{}, ErrInvalidCredentials
	}

	// 到這裡身分已證明：接下來兩句都只對「他本人」說，因此不再是探測信號。
	outcome, known := outcomeOfApplication(a)
	if !known {
		// 口令對了，但這一筆帳戶根本沒走過審批通路（開放自註冊建的、管理員建的、Root 開的）。
		// 回一句「你不是待審批的申請，請直接登入」：換名字、等冷卻、等策略都不是處置，
		// 而這句話對已經證明身分的人不新增任何洩漏——他本來就知道自己的帳號怎麼來的。
		s.credentialGuardSuccess(sourceIP, target)
		s.log.Info("查申請狀態被拒：該帳戶不經審批通路", "account", a.ID.String(), "request_id", requestID)
		return ApplicationStatus{}, ErrNotAnApplication
	}
	s.credentialGuardSuccess(sourceIP, target)
	status := ApplicationStatus{
		Outcome:     outcome,
		SubmittedAt: a.CreatedAt,
		ReviewedAt:  a.ReviewedAt,
	}
	s.log.Info("已回報本人申請狀態",
		"account", a.ID.String(), "outcome", outcome.String(), "request_id", requestID)
	return status, nil
}

// outcomeOfApplication 把一筆已證明憑據的帳戶換成申請結局。
//
// 判定順序是刻意的：先問 status（他此刻在審批鏈的哪一站），再問 reviewed_at
// （他是不是走審批進來的）。
//   - pending／rejected 直接回答，兩個狀態各對應一句；
//   - 其餘狀態（active／disabled／deleted）帶著審核時刻的，就是「當初被批准過」——
//     一個剛被批准的人若在這裡拿到 ErrNotAnApplication，那句「你不是待審批申請」對他是錯的；
//   - 不帶審核時刻的則根本沒走過審批通路（開放自註冊、管理員建號、Root 開的），
//     由呼叫端換成 ErrNotAnApplication。
//
// 這一格不判「他現在能不能登入」：那是 active 與各道閘門的事，本函式只回答「申請怎麼樣了」。
func outcomeOfApplication(a account.Account) (ApplicationOutcome, bool) {
	switch a.Status {
	case account.StatusPending:
		return OutcomePending, true
	case account.StatusRejected:
		return OutcomeRejected, true
	}
	if !a.ReviewedAt.IsZero() {
		return OutcomeApproved, true
	}
	return "", false
}

// passwordShapeValid 是「這枚輸入還可能是一把口令」的廉價閘：非空且不超過憑據模組的長度上界。
//
// 它不做強度判定（那是尚未批准的產品決定），只把「明顯不是口令」的輸入攔在 Argon2 之前。
// 與 internal/auth 的登入路徑同款界線，差的是這裡不拿它回 1004——查狀態的失敗一律同形。
func passwordShapeValid(password string) bool {
	return password != "" && len(password) <= credential.MaxPasswordLength
}

// equalize 在「憑據注定不成立」的分支上做一次等時的佔位派生，與 internal/auth 的登入同一手法：
// 一個不存在的人與一個打錯口令的人必須花同樣長的時間，否則回應延遲本身就是一部探測器。
// 形狀不合格的輸入不派生（它連「像一把口令」都談不上，而且登入那邊也是這個順序）。
func (s *Service) equalize(password string) {
	if passwordShapeValid(password) {
		credential.VerifyPlaceholder(password, s.hashing)
	}
}

// credentialGuardCheck 用「登入那份帳」問守衛還許不許；被擋的嘗試只留 Debug 級痕跡，
// 理由與 guardCheck 相同：冷卻期內對方可以無限發請求，每請求一條 Warn 就是把限流變成放大器。
func (s *Service) credentialGuardCheck(source, target string) error {
	blocked, retryAfter := s.credentialGuard.Allow(source, target)
	if !blocked {
		return nil
	}
	s.log.Debug("查申請狀態被限流擋下", "source", source, "retry_after", retryAfter.String())
	return &ThrottledError{RetryAfter: retryAfter}
}

// credentialGuardFailure 記一次可歸因於呼叫端的查狀態失敗（名字不存在、訪客、口令不合規或不符）。
// 與註冊那側同一個口徑：伺服器狀態造成的拒絕不計在申請人帳上。
func (s *Service) credentialGuardFailure(source, target string) {
	if triggered := s.credentialGuard.RecordFailure(source, target); triggered {
		s.log.Warn("查申請狀態失敗額度打滿，來源進入冷卻", "source", source)
	}
}

// credentialGuardSuccess 勾銷該來源×名字的失敗帳。
//
// 「口令對了但這一筆不經審批通路」也計為成功：守衛記的是「這個來源確實持有這個名字的憑據」，
// 而不是一筆申請的結局好壞。
func (s *Service) credentialGuardSuccess(source, target string) {
	s.credentialGuard.RecordSuccess(source, target)
}

// RegisterAccount 讓一個匿名申請人自註冊為普通帳戶。
//
// 順序與每一跳的理由：
//  1. 頻率先於一切：guardCheck 在查庫、派生、審計之前就問守衛還許不許。冷卻中的請求到這裡為止，
//     不消耗任何 Argon2、不碰資料庫、不寫審計——限流要保護的恰恰是這三樣最貴的資源。
//     目標鍵取登入名正規化鍵（見 guardTarget），使「反復撞同一個名字」撞配對上限、
//     「橫掃多個不同名字」撞來源級上限。
//  2. 登入名先過帳戶域的正規化閘：形狀不合格不消耗口令派生，也不進交易。這一步放在派生之前，
//     是因為匿名入口最便宜的拒絕就是「不花 CPU 就不接」；計一次失敗（可歸因於呼叫端的輸入）。
//  3. 口令形狀先做廉價檢查（空／超長）：把明顯不合格的輸入攔在 Argon2 之前，同為不燒 CPU 的拒否。
//  4. 派生放在訊號量保護下、交易之外：Argon2id 按生產參數檔是數百毫秒級的 CPU 計算，
//     放進交易等於讓單寫入鎖在整個派生期間被佔住；臨界區只包住派生這一步，算完立即釋放額度。
//     取額度時尊重 ctx：等待期被取消（客戶端斷線或請求逾時）就原樣返回，不產生任何寫入。
//  5. 交易內現讀策略並校驗模式：判定依據必須是「寫入那一刻」的現值。closed／不認識值／通路未落地
//     → ErrRegisterDisabled（2017）；策略對但本版本服務不動的模式（今日三條都已翻真，故只剩裝配缺陷）
//     → ErrRegisterModeUnsupported（2016）。放行後依模式決定落成的狀態（open／invite→active，
//     approval→pending）；invite 那一側還要在同一筆交易內把一枚有效碼的額度原子核銷掉，
//     核銷不到就整筆回滾、不建號也不記審計，回 ErrInviteRejected（2023，不泄露是差哪一半）。
//  6. 重複提交與併發在同一個地方收口：登入名的正規化鍵上有 UNIQUE 索引，後到的那筆拿到
//     ErrDuplicateLogin（2019）。本用例因此不需要（也不該）先查再插。
//
// 失敗的審計與限流口徑：被拒的註冊中，只有「可歸因於呼叫端輸入」的（登入名／顯示名不合規、
// 口令形狀不合格、登入名已佔用）記一次守衛失敗；「策略關著」「模式尚未上線」「讀不到策略單例行」
// 這些伺服器狀態決定的拒絕不記失敗——那不該讓部署者的開關變成給合法用戶扣次數的理由。
// 被拒的註冊一律不追加審計（拒絕的結論不該成為寫入放大器）；那次嘗試的來源、時刻與關聯 ID
// 在執行日誌與訪問日誌裡都有。
func (s *Service) RegisterAccount(ctx context.Context, in RegisterInput, requestID, sourceIP string) (RegisteredAccount, error) {
	target := guardTarget(in.LoginName)

	if blocked := s.guardCheck(sourceIP, target); blocked != nil {
		return RegisteredAccount{}, blocked
	}

	if _, err := account.LoginKey(in.LoginName); err != nil {
		s.guardFailure(sourceIP, target)
		if errors.Is(err, account.ErrInvalidLogin) {
			// 可展示的原因（空、過長、含空白／控制字元）由帳戶域給出，訊息點名欄位、不含任何憑據。
			s.log.Warn("自註冊被拒：登入名不合領域規則", "request_id", requestID)
			return RegisteredAccount{}, err
		}
		s.log.Error("自註冊的登入名正規化失敗", "request_id", requestID, "err", err)
		return RegisteredAccount{}, fmt.Errorf("selfregister: 正規化登入名失敗: %w", err)
	}

	if in.Password == "" || len(in.Password) > credential.MaxPasswordLength {
		s.guardFailure(sourceIP, target)
		s.log.Warn("自註冊被拒：口令不滿足憑據形狀界線", "request_id", requestID)
		return RegisteredAccount{}, ErrInvalidPassword
	}

	select {
	case s.hashSem <- struct{}{}:
	case <-ctx.Done():
		// 等待額度期間請求結束：沒有派生、沒有寫入，結論就是這次操作沒發生。
		s.log.Info("自註冊在等待口令派生額度時被取消", "request_id", requestID, "err", ctx.Err())
		return RegisteredAccount{}, fmt.Errorf("selfregister: 等待口令派生額度時請求結束: %w", ctx.Err())
	}
	passwordHash, err := credential.Hash(in.Password, s.hashing)
	<-s.hashSem // 臨界區只到派生為止：立即歸還額度，不把它帶進漫長的交易。
	if err != nil {
		// 形狀已在上面擋掉，走到這裡是派生本身出錯（採鹽／派生失敗），屬系統故障：
		// 不記守衛失敗（不是呼叫端的錯），原樣上拋讓傳輸層回 5xx。
		s.log.Error("自註冊口令派生失敗", "request_id", requestID, "err", err)
		return RegisteredAccount{}, fmt.Errorf("selfregister: 產生憑據雜湊失敗: %w", err)
	}

	var created RegisteredAccount
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		policy, err := s.policy.Get(tctx, tx)
		if err != nil {
			return err
		}
		allowed, mode := policy.AllowsSelfRegister()
		if !allowed {
			return ErrRegisterDisabled
		}
		initialStatus, served := statusForMode(mode)
		if !served {
			return ErrRegisterModeUnsupported
		}
		// invite 模式在這一筆交易裡多佔一道准入憑證：把一枚碼的額度原子扣掉，扣不到（缺碼、形状不合、
		// 查無、撤銷、過期、用滿、併發落敗）就讓整筆回滾——帳戶一個也不多、審計一筆也不記、
		// 名額一個也不誤耗（used_count 的加一隨回滾一起退回）。這正是「註冊失敗不誤耗名額」與
		// 「一次性碼併發只一個有效」能同時成立的落點：核銷與建號共用同一個 *database.Tx，
		// BEGIN IMMEDIATE 讓併發的註冊整體串行化，落敗者取到的是對手已扣減後的新快照。
		// open／approval 一個字都不看這格，一支碼因此絕不會在非 invite 那一側被順手吃掉。
		if mode == acctpolicy.ModeInvite {
			if _, err := s.invites.Redeem(tctx, tx, strings.TrimSpace(in.InviteCode)); err != nil {
				return fmt.Errorf("%w（%v）", ErrInviteRejected, err)
			}
		}
		a, err := s.accounts.Create(tctx, tx, account.NewInput{
			LoginName:          in.LoginName,
			DisplayName:        in.DisplayName,
			PasswordHash:       passwordHash,
			Type:               account.TypeStandard,
			Status:             initialStatus,
			MustChangePassword: false,
		})
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, s.auditRecord(a, mode, requestID)); err != nil {
			return err
		}
		created = RegisteredAccount{
			AccountID:          a.ID,
			LoginName:          a.LoginName,
			DisplayName:        a.DisplayName,
			Status:             a.Status,
			MustChangePassword: a.MustChangePassword,
			CreatedAt:          a.CreatedAt,
		}
		return nil
	})
	if err != nil {
		return RegisteredAccount{}, s.classifyFailure(err, sourceIP, target, requestID)
	}

	s.guardSuccess(sourceIP, target)
	s.log.Info("已受理自註冊",
		"account", created.AccountID.String(), "status", created.Status.String(),
		"must_change_password", created.MustChangePassword, "request_id", requestID)
	return created, nil
}

// guardCheck 在一切校驗之前問守衛「還許不許」。被擋的嘗試只留 Debug 級痕跡：
// 冷卻期內攻擊者可以無限發請求，每請求一條 Warn 就是把「限流」變成新的資源放大器。
func (s *Service) guardCheck(source, target string) error {
	blocked, retryAfter := s.guard.Allow(source, target)
	if !blocked {
		return nil
	}
	s.log.Debug("自註冊嘗試被限流擋下", "source", source, "retry_after", retryAfter.String())
	return &ThrottledError{RetryAfter: retryAfter}
}

// guardFailure 記一次可歸因於呼叫端的被拒註冊；把某個條目推進冷卻時才升 Warn 日誌
// （每個條目每視窗至多喊一次）。日誌只帶來源、不帶目標：登入名不是可以隨常規欄位外流的資訊。
func (s *Service) guardFailure(source, target string) {
	if triggered := s.guard.RecordFailure(source, target); triggered {
		s.log.Warn("自註冊失敗額度打滿，來源進入冷卻", "source", source)
	}
}

// guardSuccess 勾銷該來源×名字的失敗帳（一次成功註冊代表這個來源對這個名字是合法操作）。
func (s *Service) guardSuccess(source, target string) {
	s.guard.RecordSuccess(source, target)
}

// classifyFailure 把交易回傳的錯誤映射成對外結論，並決定要不要補記一次守衛失敗。
//
// 只有「可歸因於呼叫端輸入」的拒絕才計失敗（重名是枚舉探測的主要信號、不合規輸入是髒請求）；
// 策略關著、模式尚未上線、讀不到策略單例行這些伺服器狀態決定的拒絕一律不計——
// 部署者的開關不該變成給合法用戶扣次數的理由。所有分支都把原始錯誤的型別保住了給 errors.Is 判定。
func (s *Service) classifyFailure(err error, source, target, requestID string) error {
	switch {
	case errors.Is(err, ErrRegisterDisabled):
		s.log.Warn("自註冊被拒：帳戶建立策略未開放自註冊", "request_id", requestID)
		return ErrRegisterDisabled
	case errors.Is(err, ErrRegisterModeUnsupported):
		s.log.Warn("自註冊被拒：該模式對應的准入流程尚未上線", "request_id", requestID)
		return ErrRegisterModeUnsupported
	case errors.Is(err, ErrInviteRejected):
		// invite 模式下這一枚碼換不出一筆帳戶（缺碼、形状不合、查無、撤銷、過期、用滿、併發落敗）：
		// 可歸因於呼叫端帶來的那一味准入憑證，所以記一次守衛失敗（撞一枚固定失效碼試名額正是探測用法，
		// 來源×名字與來源級上限都要能因它而觸發）。對外是單一不泄露細節的結論（映射 2023），
		// 內部那句原始原因只進日誌、不回傳——探測者據回應分辨不出自己差的是哪一半。
		s.guardFailure(source, target)
		s.log.Warn("自註冊被拒：邀請碼無效或未帶邀請碼", "request_id", requestID, "err", err)
		return ErrInviteRejected
	case errors.Is(err, account.ErrDuplicateLogin):
		// 業務衝突：不是故障、不寫審計，但記一次守衛失敗——反復撞同一個存在名字的來源
		// 正是探測器的主用法，配對上限與來源級上限都要能因它而觸發。
		s.guardFailure(source, target)
		s.log.Warn("自註冊被拒：登入名已被佔用", "request_id", requestID)
		return fmt.Errorf("%w（%v）", ErrDuplicateLogin, err)
	case errors.Is(err, account.ErrInvalidLogin), errors.Is(err, account.ErrInvalidDisplayName):
		// 交易內帳戶域二次把關攔下的不合規輸入（多為顯示名）：可安全展示，點名欄位、與憑據無關。
		s.guardFailure(source, target)
		s.log.Warn("自註冊被拒：輸入不合領域規則", "request_id", requestID, "err", err)
		return err
	case errors.Is(err, acctpolicy.ErrNoPolicyRow):
		// 結構缺陷：單例策略行讀不到。原樣上拋讓交易回滾，不猜成關也不猜成開。
		s.log.Error("自註冊的策略讀取失敗", "request_id", requestID, "err", err)
		return err
	default:
		s.log.Error("自註冊落地失敗", "request_id", requestID, "err", err)
		return fmt.Errorf("selfregister: 自註冊失敗: %w", err)
	}
}

// auditRecord 產生一筆 Root 域的建號審計，操作者是服務端自身（系統主體）。
//
// actor 用 ActorSystem 且 actor.id 留 Nil：匿名請求沒有可信主體，既不能冒充 Root／管理員，
// 也不該給一個「查得出是哪個人建的」的假承諾——申請人的身分本來就還沒被證明過。
// internal/audit 的校驗在兩個方向都把這條釘死（系統主體不得帶 actor.id、root 記錄不得帶 activity_id）。
//
// ScopeRoot 而不捏造 activity_id：建號是伺服器級動作，不屬於任何活動。
//
// 絕不落進記錄的東西：口令明文、Argon2id 雜湊、來源 IP（那屬執行／訪問日誌，不是審計要素）、
// 任何錯誤鏈原文。changes 只有可展示的身分欄位，且刻意不帶任何 password 字樣的鍵，
// 讓「審計表裡沒有一個欄位可能含口令」成立在結構上而不是成立在遮罩會幫忙的期待上。
// status 如實落成 active 或 pending——這是兩種模式在審計裡唯一必須看得出的差別，
// 而它不需要另外一欄：變更是從無到有的那個值本身。
// must_change_password 記為 false：這是本用例與管理員建號（恆 true）在形態上唯一的差別，
// 值得在審計裡如實留證——它記的是「口令是本人自選、不需要別人先替他改一次」這件事；
// 待審批的那一筆等的不是口令，是批准。
func (s *Service) auditRecord(a account.Account, mode acctpolicy.Mode, requestID string) audit.Record {
	reason := "匿名自註冊（策略於交易內現讀放行，模式 open），建立普通帳戶，口令為本人自選故首次登入不必改密"
	if a.Status == account.StatusPending {
		reason = "匿名提交自註冊申請（策略於交易內現讀放行，模式 approval），落成待審批帳戶：" +
			"申請人自此持有穩定標識與自己選的口令，但在有人批准之前沒有任何登入能力"
	} else if mode == acctpolicy.ModeInvite {
		reason = "匿名持有效邀請碼自註冊（策略於交易內現讀放行，模式 invite），在同一筆交易內原子核銷該碼的一次額度並建立普通帳戶，" +
			"口令為本人自選故首次登入不必改密；邀請碼不攜帶任何權限，建出的仍是普通帳戶"
	}
	return audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  audit.Actor{Kind: audit.ActorSystem},
		Action: "account.self_register",
		Target: audit.Target{Kind: "account", ID: a.ID.String()},
		Reason: reason,
		// actor.kind=system 與 request_id 同源：這不是「查不出是誰」，而是「本來就沒有已知的誰」；
		// request_id 把這筆審計接回訪問日誌，那裡才有來源與時刻。
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "login_name", Before: nil, After: a.LoginName},
			{Field: "display_name", Before: nil, After: a.DisplayName},
			{Field: "account_type", Before: nil, After: a.Type.String()},
			{Field: "status", Before: nil, After: a.Status.String()},
			{Field: "must_change_password", Before: nil, After: false},
		},
	}
}

// guardTarget 導出守衛計量用的目標鍵，與 internal/auth 的登入路徑同構：
// 正規化成功的登入名用正規化鍵——大小寫／全形不同的同一登入名必須落在同一個條目，
// 否則「Alice、ALICE、ａｌｉｃｅ 輪流各撞幾次」就能把配對上限繞成數倍。
// 正規化失敗（形狀不合格的輸入）沒有正規化鍵可用，退回截斷後的原始字串。
func guardTarget(loginName string) string {
	if key, err := account.LoginKey(loginName); err == nil {
		return key
	}
	if r := []rune(loginName); len(r) > guardTargetMaxRunes {
		return string(r[:guardTargetMaxRunes])
	}
	return loginName
}

// trimRequestID 保證關聯 ID 不超過審計欄位上限（與 internal/adminacct、internal/stdacct 同口徑）。
func trimRequestID(requestID string) string {
	if r := []rune(requestID); len(r) > 64 {
		return string(r[:64])
	}
	return requestID
}
