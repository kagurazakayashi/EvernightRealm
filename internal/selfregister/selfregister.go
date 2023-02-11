// Package selfregister 是「匿名用戶自註冊為普通帳戶」的應用服務用例層：
// 在開放自註冊（self_register_mode=open）時，讓還沒登入的人自行建立一個可立即登入的普通帳戶。
//
// 本套件回答的是「門外的一個人此刻能不能自己開一個普通帳戶」這一句話。它與 internal/stdacct
// 建的是同一種形態（standard ＋ active ＋ 不帶任何伺服器級角色），走的卻是完全不同的授權邊界：
// stdacct 的主體必須持有伺服器級管理權（NeedServerAdmin），而這裡根本沒有主體——呼叫者是匿名，
// 唯一的准入依據是「寫入那一刻」的帳戶建立策略。把兩者混進一個套件，「誰能建、建不建得成」
// 就要靠同一個 Service 上的分支記，那是兩套准入最容易互相污染形態；因此刻意分開。
//
// 四條不可讓步的規定：
//   - 建出來的只能是普通帳戶。角色、帳戶類型、審批狀態、首次改密要求都由本用例決定，
//     請求裡沒有任何格子可填：傳輸層的未知欄位規則把 role／account_type／status／
//     subject_kind／must_change_password 之類的宣稱當場拒殺（1004）。「建的是哪一類主體」
//     由「打的哪個端點、走的哪個用例」決定，不由請求內容決定。本用例不碰 internal/adminacct，
//     也永遠不可能經這條通路建出管理員。
//   - 建立前先問策略、而且問的是「寫入那一刻」的策略與模式。准入判定發生在同一筆交易內
//     讀回的現值上（acctpolicy.Store.Get 收的是呼叫端自己的交易）：Root 在任何一刻把模式
//     改回 closed 或關掉通路，下一條註冊請求就必然按新值判定，不存在「頁面還開著、
//     背地裡策略已關卻仍建成」的窗口。前端依 /auth/capabilities 顯示入口只是體驗，
//     不是准入——真正的閘門永遠在這裡、在交易內。
//   - 只服務 open 模式。approval／invite 需要的准入流程尚未上線： AllowsSelfRegister 對
//     任何有效非 closed 模式都回 true，所以本用例必須自己再看一眼模式，非 open 一律回
//     ErrRegisterModeUnsupported（2016）而不是默默按 open 建號——那等於替尚未實作的准入流程
//     冒充可用。
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
//   - 頻率：一個獨立的 auth.LoginGuard 實例（與登入守衛分開的記憶體、分開的閾值），
//     計量主軸是「來源位址 × 登入名正規化鍵」。重名與不合規輸入計為失敗、成功註冊勾銷該配對；
//     被擋的嘗試統一回可判別 ThrottledError（傳輸層映射 2006＋Retry-After），
//     而且到不了查庫、派生與審計那三樣最貴的資源。
//   - 派生併發：一個以 RegisterHashConcurrency 大小的訊號量封頂同時進入 Argon2id 的註冊數，
//     把「併發刷註冊燒 CPU」這條路線的天花板壓住；超出的請求在訊號量上等待、可被 context 取消，
//     等待期不佔交易、不寫審計、不做派生。
//
// 關於「枚舉」：任何讓匿名者「自行選一個唯一登入名」的端點，結構上就是一個存在性探測器——
// 一次成功即代表這個名字還沒被佔用。這不是措辭能掩蓋的（也刻意不掩蓋：對外用可判別的重名碼 2019，
// 讓正常用戶知道要換名字），真正的批量防護來自上面的緊限流與併發封頂，而非把回應整形成全同形。
// 機器驗證碼（機器人雲）與郵件服務都不在本步範圍（既定邊界），因此這裡不引入、也不宣稱已具備那兩道防線。
package selfregister

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
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
	// ErrRegisterModeUnsupported 表示策略放開了自註冊，但生效的模式是 approval／invite 這種
	// 准入流程尚未上線的類型。
	//
	// 與 ErrRegisterDisabled 分開，是因為這兩句話對操作者的意義不同：一個是「伺服器沒開這條路」，
	// 另一個是「這條路開著、但它要求的准入功能還沒上線」。回 2016（模式尚未開放）而不是 2017，
	// 也和 internal/acctpolicy 對「策略值不等於能力」的同款區分對齊。
	ErrRegisterModeUnsupported = errors.New("selfregister: 该自註冊模式對應的准入流程尚未上線")
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
// 沒有任何角色、帳戶類型、審批狀態或旗標欄位：本用例建的就是
// 「standard ＋ active ＋ 無伺服器級角色 ＋ 首次不必改密」這一種形態，
// 由端點形態而不是請求欄位決定。
type RegisterInput struct {
	// LoginName 為登入名原始寫法；正規化唯一鍵由帳戶域層計算。
	LoginName string
	// DisplayName 為顯示名稱（不承擔唯一性）。
	DisplayName string
	// Password 為申請人自選的口令明文。它只在本次調用期間短暫停留：派生成雜湊後即不再被引用，
	// 不進回應、日誌、審計或任何錯誤訊息。
	Password string
}

// RegisteredAccount 是一次成功註冊的結果，全部為可展示的事實（不含任何憑據材料）。
type RegisteredAccount struct {
	// AccountID 為新帳戶的穩定標識——註冊成功即得到它，與是否加入任何活動無關。
	AccountID idgen.ID
	// LoginName 為登入名原始寫法。
	LoginName string
	// DisplayName 為顯示名稱。
	DisplayName string
	// Status 為帳戶狀態（註冊成功必為 active）。
	Status account.Status
	// MustChangePassword 為首次登入是否必須改密（本用例恆為 false：口令是本人自選的，
	// 選完就能直接登入，這是「開放自註冊、立即可用」的既定語意）。
	MustChangePassword bool
	// CreatedAt 為建立時刻（UTC，取自注入時鐘）。
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
	// Audits 是 Root 域審計倉儲。匿名建號的痕跡與其餘伺服器級動作落在同一張表。
	Audits *audit.Store
	// Guard 是這個通路專屬的頻率守衛。它是獨立於登入守衛的另一個 auth.LoginGuard 實例
	// （另一份記憶體、另一組較緊的閾值），呼叫者是匿名的，被擋的嘗試不查庫、不派生、不寫審計。
	Guard *auth.LoginGuard
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
	db       *database.DB
	accounts *account.Store
	policy   *acctpolicy.Store
	audits   *audit.Store
	guard    *auth.LoginGuard
	hashing  credential.Params
	hashSem  chan struct{}
	log      *slog.Logger
}

// New 校驗依賴並建立服務。
//
// 缺任何一個依賴都是組裝缺陷，在啟動階段當場報出：少策略倉儲就問不到「此刻准不准自註冊」，
// 等於默認放行；少守衛就少了一道匿名防線，等於默認接受無限刷；少審計倉儲就建出一個不留痕的
// 伺服器級主體變更。HashConcurrency 不在 1..上限內同樣中斷啟動——訊號量容量是防線本身，
// 裝錯一個數量級不該帶著上路。
func New(deps Deps) (*Service, error) {
	if deps.DB == nil || deps.Accounts == nil || deps.Policy == nil ||
		deps.Audits == nil || deps.Guard == nil {
		return nil, errors.New("selfregister: 用例缺少必要依賴（db/accounts/policy/audits/guard）")
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
		audits:   deps.Audits,
		guard:    deps.Guard,
		hashing:  deps.Hashing,
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
//     → ErrRegisterDisabled（2017）；非 open 的有效模式（approval／invite）→ ErrRegisterModeUnsupported（2016）；
//     放行後依序寫入帳戶與 Root 域審計，任何一跳失敗整筆回滾。
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
		if mode != acctpolicy.ModeOpen {
			return ErrRegisterModeUnsupported
		}
		a, err := s.accounts.Create(tctx, tx, account.NewInput{
			LoginName:          in.LoginName,
			DisplayName:        in.DisplayName,
			PasswordHash:       passwordHash,
			Type:               account.TypeStandard,
			Status:             account.StatusActive,
			MustChangePassword: false,
		})
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, s.auditRecord(a, requestID)); err != nil {
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
	s.log.Info("已自註冊普通帳戶",
		"account", created.AccountID.String(), "must_change_password", created.MustChangePassword,
		"request_id", requestID)
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
// 也不該給一個「查得出是哪個人建的」的假承諾——申請人的身分本來就還沒建立。
// internal/audit 的校驗在兩個方向都把這條釘死（系統主體不得帶 actor.id、root 記錄不得帶 activity_id）。
//
// ScopeRoot 而不捏造 activity_id：建號是伺服器級動作，不屬於任何活動。
//
// 絕不落進記錄的東西：口令明文、Argon2id 雜湊、來源 IP（那屬執行／訪問日誌，不是審計要素）、
// 任何錯誤鏈原文。changes 只有可展示的身分欄位，且刻意不帶任何 password 字樣的鍵，
// 讓「審計表裡沒有一個欄位可能含口令」成立在結構上而不是成立在遮罩會幫忙的期待上。
// must_change_password 記為 false：這是本用例與管理員建號（恆 true）在形態上唯一的差別，
// 值得在審計裡如實留證——它記的是「口令是本人自選、建完就能直接登入」這件事。
func (s *Service) auditRecord(a account.Account, requestID string) audit.Record {
	return audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  audit.Actor{Kind: audit.ActorSystem},
		Action: "account.self_register",
		Target: audit.Target{Kind: "account", ID: a.ID.String()},
		Reason: "匿名自註冊（策略 open 現讀放行），建立普通帳戶，口令為本人自選故首次登入不必改密",
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
