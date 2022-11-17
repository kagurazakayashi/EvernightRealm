package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// 對外可判別的結論錯誤。內部的具體失敗原因（查無此人／口令錯／已禁用／訪客帳戶／
// Root 未設定）一律只進日誌，不進回傳給傳輸層的結論——那兩個錯誤型別的存在意義，
// 就是讓傳輸層根本拿不到可以洩露的細節。
var (
	// ErrInvalidCredentials 是登入被拒時唯一的結論。
	// 凡「憑據不對、或這個主體此刻不能登入」都收斂到這裡，回應層不得據內部原因分流。
	ErrInvalidCredentials = errors.New("auth: 登入憑據無效")
	// ErrInvalidSession 是會話解析被拒時唯一的結論：無效秘密、已撤銷、已到期、
	// 主體不可用在外層是同一句話（拿秘密來的人只需要知道「重新登入」）。
	ErrInvalidSession = errors.New("auth: 會話無效")
	// ErrStaleSession 表示來的是上一代憑據：它換不出任何身份，但也不是「從未有效過」。
	//
	// 單獨留一個結論只為一件事——讓呼叫端知道這一次的失敗是「與一次輪換交錯」，
	// 處置是重試而不是把使用者踢回登入頁。它不帶任何會話資料，也不帶新秘密。
	ErrStaleSession = errors.New("auth: 會話憑據已是上一代")
	// ErrLoginThrottled 表示該來源對該目標的失敗額度已打滿，正處於冷卻。
	// 它與 ErrInvalidCredentials 是兩個不同的對外結論（429「稍後再試」對 401「憑據無效」），
	// 但冷卻對「查無此人」與「真帳戶口令錯」完全同形：計量發生在查庫之前，
	// 觸發條件只看來源×目標的失敗次數，回應裡沒有任何欄位指出觸發的是誰。
	ErrLoginThrottled = errors.New("auth: 登入嘗試過於頻繁")
	// ErrLoginDeviceLimit 表示憑據已經校驗通過，但該主體的有效會話名額已滿，
	// 因此這次登入整個沒有發生（既沒簽發新會話，也沒撤銷任何既有會話）。
	//
	// 它必須與 ErrInvalidCredentials 分開，因為兩者的處置完全不同：口令錯的人該再想一次口令，
	// 而這個人在這裡的失敗跟口令毫無關係，把兩件事說成同一句「憑據無效」會讓人
	// 對著一個正確的口令反覆懷疑自己。分開報也**不**提供任何新資訊：能收到這一句的
	// 前提是他剛剛證明瞭自己是誰，因此它不是可列舉帳戶的訊號（計數發生在憑據校驗之後）。
	// 結論本身只有一句固定文字：不含上限值、現有會話數或任何裝置標識。
	ErrLoginDeviceLimit = errors.New("auth: 裝置登入名額已滿")
)

// ThrottledError 是帶著剩餘冷卻時間的 ErrLoginThrottled。
//
// 傳輸層據 RetryAfter 寫 Retry-After 標頭（標準 429 語意）；除這個秒數之外
// 它不提供任何可分辨的狀態——errors.Is(err, ErrLoginThrottled) 照常成立，
// 不認識 ThrottledError 的呼叫端不會漏判。
type ThrottledError struct {
	// RetryAfter 是冷卻解除所需的時間（取兩條規則中較晚解除的那個）。
	RetryAfter time.Duration
}

// Error 實作 error 介面；文字恆為固定一句，不含來源、目標或剩餘時間。
func (e *ThrottledError) Error() string { return "auth: 登入嘗試過於頻繁，暫不受理" }

// Unwrap 讓 errors.Is(err, ErrLoginThrottled) 成立。
func (e *ThrottledError) Unwrap() error { return ErrLoginThrottled }

// Outcome 是一次成功登入的結果。
//
// Secret 是會話秘密的一次性明文：它唯一的去處是傳輸層寫進 Set-Cookie，
// 不得進 JSON 回應、日誌、審計或任何錯誤訊息。Principal 與 Session 供回應對映
// 與上下文使用；主體在構造當時的事實已凍結在 Principal 裡，後續請求的許可權判定
// 仍按「狀態現讀」原則由會話解析重走（見 Service.Resolve）。
type Outcome struct {
	// Principal 是透過認證的受信主體。
	Principal identity.Principal
	// Session 是剛簽發的會話實體。
	Session session.Session
	// Secret 是會話秘密的一次性明文（只准進 Set-Cookie）。
	Secret string
}

// Deps 是登入用例的外部依賴，全部由組裝層（internal/app）注入。
type Deps struct {
	// DB 提供交易邊界與 autocommit 查詢。
	DB *database.DB
	// Sessions 是會話核心。
	Sessions *session.Store
	// Accounts 是帳戶倉儲。
	Accounts *account.Store
	// Audits 是 Root 登入事件的審計倉儲。
	Audits *audit.Store
	// RootPasswordHash 是組態中的 Root Argon2id 憑據；空字串代表尚未初始化。
	RootPasswordHash string
	// Hashing 是佔位派生使用的當前參數檔（令「查無此人」與「口令不符」外部耗時同階）。
	Hashing credential.Params
	// Guard 是登入失敗控制與限流（見 guard.go）；nil 表示不啟用——
	// 裝配層必須注入，留 nil 只為讓既有測試與將來的非網路通路能繞過計量。
	Guard *LoginGuard
	// Log 為伺服器端記錄出口；nil 時丟棄。具體失敗原因只能進這裡。
	Log *slog.Logger
}

// Service 是登入用例的編排者。零值不可用，請經 New 取得。
type Service struct {
	db       *database.DB
	sessions *session.Store
	accounts *account.Store
	audits   *audit.Store
	rootHash string
	hashing  credential.Params
	guard    *LoginGuard
	log      *slog.Logger
}

// New 校驗依賴並建立登入服務。
//
// 缺失任何一個依賴都是組裝缺陷，直接在啟動階段報出來；
// Hashing 全零時退回生產預設檔（佔位派生仍消耗真實參數檔的真實成本這一目的不變）。
func New(deps Deps) (*Service, error) {
	if deps.DB == nil || deps.Sessions == nil || deps.Accounts == nil || deps.Audits == nil {
		return nil, errors.New("auth: 登入用例缺少必要依賴（db/sessions/accounts/audits）")
	}
	params := deps.Hashing
	if params.MemoryKiB == 0 || params.TimeCost == 0 || params.Parallelism == 0 || params.KeyLength == 0 {
		params = credential.ProductionParams
	}
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("auth: 佔位派生參數檔不合格: %w", err)
	}
	logger := deps.Log
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		db:       deps.DB,
		sessions: deps.Sessions,
		accounts: deps.Accounts,
		audits:   deps.Audits,
		rootHash: deps.RootPasswordHash,
		hashing:  params,
		guard:    deps.Guard,
		log:      logger,
	}, nil
}

// passwordShapeValid 回報口令長度是否落在憑據模組的派生界限內。
//
// 空口令與超長口令不會進入真實派生（credential.Verify 直接判否），
// 這種輸入不需要時延掩護：它們能洩露的只有「本模組的長度規則」，與帳戶存在與否無關。
func passwordShapeValid(password string) bool {
	return password != "" && len(password) <= credential.MaxPasswordLength
}

// equalize 在「本不該消耗派生」的拒絕分支上補一次真實參數檔的佔位派生。
//
// 只在口令形狀合格時執行；耗的是 CPU，換的是「查無此人」與「口令不符」
// 在回應時間上不可區分——時間差和文案一樣能列舉帳戶。
func (s *Service) equalize(password string) {
	if passwordShapeValid(password) {
		credential.VerifyPlaceholder(password, s.hashing)
	}
}

// accountGuardTarget 計算帳戶登入在守衛裡的目標標識。
//
// 正規化成功的登入名用正規化鍵——大小寫／全形不同的同一登入名必須落在同一個條目，
// 否則「Alice、ALICE、ａｌｉｃｅ 輪流各打三次」就能把配對上限繞成三倍。
// 正規化失敗（形状不合格的輸入）沒有正規化鍵可用，退回「截斷後的原始字串」：
// 截斷到正規化鍵同款的碼位上限，海量隨機髒名就不可能用超長鍵撐爆守衛記憶體。
func accountGuardTarget(loginName string) string {
	if key, err := account.LoginKey(loginName); err == nil {
		return key
	}
	if r := []rune(loginName); len(r) > 200 {
		return string(r[:200])
	}
	return loginName
}

// guardCheck 在一切校驗之前問守衛「還許不許」。
//
// 順序就是它的防線意義：被擋的嘗試不查庫、不寫審計、不做任何 Argon2 派生——
// 限流要保護的恰恰是這三樣最貴的資源。守衛未注入時放行（見 Deps.Guard 註解）。
func (s *Service) guardCheck(ip, target string) error {
	if s.guard == nil {
		return nil
	}
	blocked, retryAfter := s.guard.Allow(ip, target)
	if !blocked {
		return nil
	}
	// 被擋的嘗試只留 Debug 級痕跡：冷卻期內攻擊者可以無限發請求，
	// 每請求一條 Warn 就是把「限流」變成新的資源放大器。
	s.log.Debug("登入嘗試被限流擋下", "source", ip, "retry_after", retryAfter.String())
	return &ThrottledError{RetryAfter: retryAfter}
}

// guardFailure 記一次被拒的憑據嘗試；把某個條目推進冷卻時才升 Warn 日誌——
// 每個條目每視窗至多喊一次，攻擊轟炸期反而把日誌量壓到最低。
func (s *Service) guardFailure(ip, target string) {
	if s.guard == nil {
		return
	}
	if triggered := s.guard.RecordFailure(ip, target); triggered {
		s.log.Warn("登入失敗額度打滿，來源進入冷卻", "source", ip, "target_kind", loginTargetKind(target))
	}
}

// guardSuccess 勾銷該來源×目標的失敗帳。
func (s *Service) guardSuccess(ip, target string) {
	if s.guard == nil {
		return
	}
	s.guard.RecordSuccess(ip, target)
}

// loginTargetKind 只回報「是不是 Root 目標」這一件事，不回傳目標本身——
// 登入名不是可以隨日誌常規欄位外流的資訊，這裡只給分類不給值。
func loginTargetKind(target string) string {
	if target == RootTarget {
		return "root"
	}
	return "login_name"
}

// LoginAccount 以登入名與口令為普通帳戶簽發會話。
//
// 順序與理由：
//  0. 來源×目標先過登入守衛（見 guardCheck）：冷卻中的嘗試到這裡為止，
//     查無此人與真帳戶的失敗計入同一個鍵、同一組閾值——限流不透露帳戶存在性；
//  1. 登入名先過帳戶模組自己的正規化閘（形狀不合格根本不查庫）；
//  2. 查無此人 → 佔位派生對齊耗時後收斂為 ErrInvalidCredentials；
//  3. 訪客帳戶沒有口令通路（無密快捷登入屬後續步驟，本步一律按憑據無效處理）；
//  4. 口令比對用入庫時自帶的參數檔；比對先於狀態檢查——「禁用＋正確口令」與
//     「口令錯」的外部耗時與結論同形，狀態本身不是可枚舉的信號；
//  5. 主體構造（NewAccountPrincipal 再擋一次禁用，讀與構造之間的競態方向保守）；
//  6. 同一個交易裡執行裝置名額策略、簽發會話並推進 accounts.last_login_at。
//
// 第 6 步的策略拒絕（ErrLoginDeviceLimit）不計入守衛的失敗帳，也不勾銷已有預算：
// 被擋的原因是「這個主體的會話佔滿了」，與這次嘗試的口令對錯無關，
// 讓它消耗來源額度等於把裝置策略變成第二把限流刀。
//
// 普通帳戶的登入事件不寫審計表（已批准決定：無角色帳戶的審計主體類別未落地），
// 成敗都只進執行日誌；日誌記內部原因，但永不記口令。
// ip 是傳輸層從實際連線取到的來源位址：轉發標頭一概不採信（無既有的可信代理約定，
// 就不新增信任），空字串代表無來源可計量，守衛对此不設閘（見 LoginGuard.Allow）。
func (s *Service) LoginAccount(ctx context.Context, loginName, password, requestID, ip string) (Outcome, error) {
	target := accountGuardTarget(loginName)
	if err := s.guardCheck(ip, target); err != nil {
		return Outcome{}, err
	}
	outcome, rejected, err := s.attemptAccount(ctx, loginName, password, requestID)
	if err != nil {
		return Outcome{}, err
	}
	if rejected {
		s.guardFailure(ip, target)
		return Outcome{}, ErrInvalidCredentials
	}
	s.guardSuccess(ip, target)
	return outcome, nil
}

// attemptAccount 是 LoginAccount 的校驗本體；rejected 與 err 分工明確：
// rejected 是「對外要說憑據無效」的拒絕，err 是「對外要說伺服器出錯」的內部故障。
// 內部故障不記失敗帳——自家資料庫打嗝不該讓來源消耗登入預算。
func (s *Service) attemptAccount(ctx context.Context, loginName, password, requestID string) (Outcome, bool, error) {
	if _, err := account.LoginKey(loginName); err != nil {
		return Outcome{}, true, nil
	}
	a, err := s.accounts.ByLoginName(ctx, s.db.SQL(), loginName)
	if err != nil {
		if errors.Is(err, account.ErrNotFound) {
			s.equalize(password)
			s.log.Warn("帳戶登入被拒：查無此登入名", "login_name", loginName, "request_id", requestID)
			return Outcome{}, true, nil
		}
		return Outcome{}, false, fmt.Errorf("auth: 讀取帳戶失敗: %w", err)
	}

	if a.Type == account.TypeGuest {
		s.equalize(password)
		s.log.Warn("帳戶登入被拒：訪客帳戶無口令通路", "account", a.ID.String(), "request_id", requestID)
		return Outcome{}, true, nil
	}
	if !passwordShapeValid(password) {
		s.log.Warn("帳戶登入被拒：口令形狀不合格", "account", a.ID.String(), "request_id", requestID)
		return Outcome{}, true, nil
	}
	ok, err := credential.Verify(a.PasswordHash, password)
	if err != nil {
		// 入庫憑據解不開屬資料缺陷：對外仍是「憑據無效」，對內這是一條要查的錯誤。
		s.log.Error("帳戶憑據編碼不可校驗", "account", a.ID.String(), "err", err, "request_id", requestID)
		return Outcome{}, true, nil
	}
	if !ok {
		s.log.Warn("帳戶登入被拒：口令不符", "account", a.ID.String(), "request_id", requestID)
		return Outcome{}, true, nil
	}
	if a.Status != account.StatusActive {
		s.log.Warn("帳戶登入被拒：帳戶已禁用", "account", a.ID.String(), "request_id", requestID)
		return Outcome{}, true, nil
	}

	principal, err := identity.NewAccountPrincipal(identity.AccountInput{
		Subject: identity.SubjectOf(a),
		Origin:  identity.OriginHTTPRequest,
		// Grants 為零值：伺服器級角色的授予資料來源尚未存在，登入不假裝讀得出來。
	})
	if err != nil {
		if errors.Is(err, identity.ErrNotAuthenticated) {
			// 讀取與構造之間賬戶恰好被禁用：與狀態檢查同口徑收斂。
			return Outcome{}, true, nil
		}
		return Outcome{}, false, fmt.Errorf("auth: 構造帳戶主體失敗: %w", err)
	}

	outcome, err := s.issue(ctx, principal, a.ID, requestID)
	if err != nil {
		// issue 把「主體此刻不可用」的拒絕也收斂成 ErrInvalidCredentials 鏈；
		// 區分靠 errors.Is——那是憑據路徑的拒絕，不是內部故障。
		if errors.Is(err, ErrInvalidCredentials) {
			return Outcome{}, true, nil
		}
		// 名額已滿（ErrLoginDeviceLimit）原樣上報：它既不是憑據拒絕（不記失敗帳、
		// 不勾銷預算，否則一個佔滿名額的主體會順帶把來源的登入額度耗光），
		// 也不是內部故障（不該報 5xx）。
		return Outcome{}, false, err
	}
	s.log.Info("帳戶登入成功", "account", a.ID.String(), "request_id", requestID)
	return outcome, false, nil
}

// LoginRoot 以組態中的 Root 憑據簽發 Root 會話，成敗都寫入 root_audit。
//
// 與帳戶路徑的差別只有兩件事，而且都有依據：
//   - Root 不在 accounts 表：憑據的唯一來源是組態，比對走 identity.VerifyRootCredential，
//     「自報一個角色換 Root 主體」在型別層就不存在；
//   - Root 的登入與失敗屬規格 §25.2 的 Root 域事件：成功記錄與會話在同一個交易裡落地
//     （審計寫不進去，會話就不存在——見 internal/session 的事務合同），
//     失敗記錄是獨立的一筆追加，寫失敗只進日誌、不改變拒絕結論。
//
// 組態尚未設定 Root 憑據時同樣回 ErrInvalidCredentials：對外不告訴試探者「這臺伺服器有沒有 Root」，
// 內部補一次佔位派生對齊耗時，並在日誌裡如實記「未設定」。
//
// 失敗控制走同一把守衛、固定目標 RootTarget：「Root 未設定」與「口令不符」不只對外同形，
// 在計量上也同形——探測者無法用「哪個口令會開始被 429」反推這臺有沒有 Root。
// 冷卻中的嘗試連失敗審計都不追加：root_audit 的寫入速率被 fail_limit 封頂，
// 這正是「有攻擊而無痕跡」的反面——痕跡留在觸發冷卻的那一筆與執行日誌，
// 而不是留給攻擊者免費的寫入放大。
//
// 裝置名額策略對 Root 與對普通帳戶用的是同一條規則、同一個上限，沒有例外也沒有繞過入口：
// Root 主體按 subject_kind='root' 計數（全服務只有一個 Root）。這同時意味著
// 「Root 把自己鎖在門外」在上限模式下是可發生的（名額佔滿時新登入被拒），
// 而解法仍是既有那兩條——從任一線上裝置登出釋放名額，或等會話到期；
// 伺服器不為 Root 保留一條「永遠能登入」的後門，因為那正是任何人想繞過限制時的路徑。
func (s *Service) LoginRoot(ctx context.Context, password, requestID, ip string) (Outcome, error) {
	if err := s.guardCheck(ip, RootTarget); err != nil {
		return Outcome{}, err
	}
	outcome, rejected, err := s.attemptRoot(ctx, password, requestID)
	if err != nil {
		return Outcome{}, err
	}
	if rejected {
		s.guardFailure(ip, RootTarget)
		return Outcome{}, ErrInvalidCredentials
	}
	s.guardSuccess(ip, RootTarget)
	return outcome, nil
}

// attemptRoot 是 LoginRoot 的校驗本體；rejected/err 分工與 attemptAccount 相同。
func (s *Service) attemptRoot(ctx context.Context, password, requestID string) (Outcome, bool, error) {
	if s.rootHash == "" {
		s.equalize(password)
		s.appendRootFailureAudit(ctx, requestID, "組態未設定 Root 憑據")
		s.log.Warn("Root 登入被拒：組態未設定 Root 憑據", "request_id", requestID)
		return Outcome{}, true, nil
	}
	if !passwordShapeValid(password) {
		s.appendRootFailureAudit(ctx, requestID, "口令形狀不合格")
		s.log.Warn("Root 登入被拒：口令形狀不合格", "request_id", requestID)
		return Outcome{}, true, nil
	}
	proof, err := identity.VerifyRootCredential(s.rootHash, password)
	if err != nil {
		// identity 刻意把「口令不符」與「編碼損壞」收斂成同一個錯誤，這裡也不猜：
		// 用 credential.CheckEncoding 問一次「庫裡那串本身可用嗎」，只為決定日誌口徑，
		// 對外的結論與審計的 reason 都不因它而變。
		if checkErr := credential.CheckEncoding(s.rootHash); checkErr != nil {
			s.log.Error("Root 憑據編碼不可校驗（組態缺陷）", "err", checkErr, "request_id", requestID)
		} else {
			s.log.Warn("Root 登入被拒：憑據不符", "request_id", requestID)
		}
		s.appendRootFailureAudit(ctx, requestID, "Root 憑據校驗未透過")
		return Outcome{}, true, nil
	}
	principal, err := identity.Root(proof, identity.OriginHTTPRequest)
	if err != nil {
		return Outcome{}, false, fmt.Errorf("auth: 構造 Root 主體失敗: %w", err)
	}

	subjectID, err := identity.RootSubjectID()
	if err != nil {
		return Outcome{}, false, fmt.Errorf("auth: Root 審計主體標識異常: %w", err)
	}

	var outcome Outcome
	var revokedPrior int
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		revoked, err := s.sessions.ApplyLoginSlotPolicy(tctx, tx, principal)
		if err != nil {
			return err
		}
		revokedPrior = revoked
		sess, secret, err := s.sessions.Create(tctx, tx, principal)
		if err != nil {
			return err
		}
		// single 模式這次真的停掉了舊會話：Root 域的會話生命週期事件必須在 Root 審計留痕，
		// 「誰的 Root 會話被停掉、為什麼」不該只存在於會被輪轉的執行日誌裡。
		// target 帶的是這一次新簽發的會話標識：被撤銷的是「其餘全部」，逐行 ID 無以復數，
		// 而「是哪一次登入造成的」永遠只有一個答案；撤銷的個數記在 reason。
		// 名額已滿的拒絕不寫任何審計（跟其它被拒的 Root 登入同一口徑：拒絕的結論
		// 不該給任何能碰到這個端點的來源一個寫入放大器）。
		if revoked > 0 {
			rec := s.rootSessionRecord(subjectID, "auth.device_revoke", sess.ID.String(), requestID,
				fmt.Sprintf("單裝置策略：新登入前撤銷 %d 個舊會話", revoked))
			if _, err := s.audits.Append(tctx, tx, rec); err != nil {
				return err
			}
		}
		if _, err := s.audits.Append(tctx, tx, s.rootSessionRecord(subjectID, "auth.login_success", sess.ID.String(), requestID, "")); err != nil {
			return err
		}
		outcome = Outcome{Principal: principal, Session: sess, Secret: secret}
		return nil
	})
	if err != nil {
		if errors.Is(err, session.ErrDeviceLimitReached) {
			// 策略拒絕：整個交易已回滾，沒簽發會話、也沒撤銷任何既有會話。
			return Outcome{}, false, fmt.Errorf("%w（%v）", ErrLoginDeviceLimit, err)
		}
		// 交易失敗不猜原因是哪一半：會話與審計同生同滅，這次登入就是沒有發生。
		return Outcome{}, false, fmt.Errorf("auth: Root 登入落地失敗: %w", err)
	}
	if revokedPrior > 0 {
		s.log.Info("Root 單裝置策略已撤銷舊會話", "revoked", revokedPrior, "request_id", requestID)
	}
	s.log.Info("Root 登入成功", "request_id", requestID)
	return outcome, false, nil
}

// rootSessionRecord 產生 Root 域的會話生命週期審計（登入成功、登出撤銷）。
//
// 失敗記錄與成功記錄共用這裡：兩者只差 action 與 sessionID。
// reason 只講結論（「憑據校驗未透過」這種內部分類），不帶口令、不帶雜湊、
// 不帶錯誤鏈——那些屬日誌，不屬要長期保留的審計事實。
// sessionID 在失敗記錄上是空字串：那一次登入沒有簽發任何會話，
// 拿「不存在的會話標識」冒充 target 等於造出一個查無此事的指紋。
func (s *Service) rootSessionRecord(subjectID idgen.ID, action, sessionID, requestID, reason string) audit.Record {
	return audit.Record{
		Scope:     audit.ScopeRoot,
		Actor:     audit.Actor{Kind: audit.ActorRoot, ID: subjectID},
		Action:    action,
		Target:    audit.Target{Kind: "session", ID: sessionID},
		Reason:    reason,
		RequestID: trimRequestID(requestID),
	}
}

// appendRootFailureAudit 把一次被拒的 Root 登入追加進 root_audit。
//
// 失敗記錄寫不進去不改變拒絕結論（拒絕已經成立），但必須在日誌裡喊出來：
// 「有攻擊而無痕跡」正是這條審計要防的狀態的反面教材。
func (s *Service) appendRootFailureAudit(ctx context.Context, requestID, reason string) {
	subjectID, err := identity.RootSubjectID()
	if err != nil {
		s.log.Warn("Root 登入失敗的審計未寫入：保留標識異常", "err", err)
		return
	}
	rec := s.rootSessionRecord(subjectID, "auth.login_failure", "", requestID, reason)
	if _, err := s.audits.Append(ctx, s.db.SQL(), rec); err != nil {
		s.log.Warn("Root 登入失敗的審計未寫入", "err", err, "request_id", requestID)
	}
}

// Resolve 把一枚會話秘密換回受信主體：登陸後的每一個請求都經此通路取得身份。
//
// 會話核心的五類拒絕（形狀不合格／查無此秘密／已撤銷／已到期／主體不可用）
// 在這裡收斂為同一個 ErrInvalidSession：來持秘密的人只需要知道「要重新登入」，
// 區分它們不提供任何合法流程需要的資訊。資料庫故障這類非拒絕的錯誤原樣上報，
// 由傳輸層回 5xx——把「查不了」報成「沒許可權」會把人朝錯誤的方向排查。
func (s *Service) Resolve(ctx context.Context, secret string) (identity.Principal, session.Session, error) {
	principal, sess, err := s.sessions.ResolvePrincipal(ctx, s.db.SQL(), secret, identity.OriginHTTPRequest)
	if err != nil {
		if errors.Is(err, session.ErrStaleSecret) {
			// 「上一代」必須在收斂為 ErrInvalidSession 之前分出去：否則一次正常輪換
			// 會讓與之交錯的那條請求被判成「會話已失效」，客戶端據此把人踢回登入頁。
			return identity.Principal{}, session.Session{}, fmt.Errorf("%w（%v）", ErrStaleSession, err)
		}
		if errors.Is(err, session.ErrInvalidSecret) || errors.Is(err, session.ErrRevoked) ||
			errors.Is(err, session.ErrExpired) || errors.Is(err, session.ErrSubjectUnavailable) ||
			errors.Is(err, session.ErrNotFound) || errors.Is(err, session.ErrInvalidSubject) {
			return identity.Principal{}, session.Session{}, fmt.Errorf("%w（%v）", ErrInvalidSession, err)
		}
		return identity.Principal{}, session.Session{}, fmt.Errorf("auth: 會話解析失敗: %w", err)
	}
	return principal, sess, nil
}

// Logout 撤銷一個「剛經 Resolve 換回主體」的會話；這是登出端點的領域入口。
//
// 「幂等」在這裡的意義：撤銷一個早已不在的會話不是錯誤，目標狀態（這個憑據不再換得出身份）
// 本就已經達成。Revoke 的 ErrNotFound 對呼叫端一律收斂為 nil——重複登出、
// 或在「解析→撤銷」這段窗口內被並發撤銷／過期，都不應該把使用者朝「重新登入」推。
//
// 審計的落地範圍沿用 R1-009 已批准的判定：
//   - Root 主體：撤銷與 root_audit 的 `auth.logout` 落在同一個交易——審計寫不進去，
//     會話就不撤銷，兩者同生同滅。這是「Root 域事件必須在 Root 審計留痕」的合同，
//     也是「不留下無痕跡的特權變更」的具體形態。
//   - 普通帳戶（含 server_admin）：只進執行日誌，不進審計表。R1-006／008／009 把
//     「普通帳戶的審計主體類別」留在未批准邊界；本步不擅自歸類，也不降级成 system。
//     Root 撤銷那筆審計的 actor 用保留的 Root 主體標識、target 指向會話標識；
//     target、reason 與 request_id 全部經 audit 模組的遮罩管線與長度閘。
//
// 呼叫端（傳輸層）必須只在「已解析出一個有效會話」的路徑上呼叫本方法，
// 這樣「撤銷不存在的會話」永遠是幂等 no-op，而不是被誤用成一個可探測的信號。
func (s *Service) Logout(ctx context.Context, principal identity.Principal, sess session.Session, requestID string) error {
	if principal.IsRoot() {
		subjectID, err := identity.RootSubjectID()
		if err != nil {
			return fmt.Errorf("auth: Root 審計主體標識異常: %w", err)
		}
		err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
			if _, err := s.sessions.Revoke(tctx, tx, sess.ID); err != nil {
				return err
			}
			rec := s.rootSessionRecord(subjectID, "auth.logout", sess.ID.String(), requestID, "")
			if _, err := s.audits.Append(tctx, tx, rec); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			if errors.Is(err, session.ErrNotFound) {
				// 竄改、過期或已被別處撤銷：登出的目標已達成，不追加審計。
				s.log.Info("Root 登出：會話已不在，按幂等收斂", "request_id", requestID)
				return nil
			}
			return fmt.Errorf("auth: Root 登出落地失敗: %w", err)
		}
		s.log.Info("Root 登出成功", "request_id", requestID)
		return nil
	}
	if _, err := s.sessions.Revoke(ctx, s.db.SQL(), sess.ID); err != nil {
		if errors.Is(err, session.ErrNotFound) {
			s.log.Info("帳戶登出：會話已不在，按幂等收斂", "request_id", requestID)
			return nil
		}
		return fmt.Errorf("auth: 撤銷會話失敗: %w", err)
	}
	s.log.Info("帳戶登出成功",
		"account", principal.AccountID().String(), "request_id", requestID)
	return nil
}

// RotateSession 用一枚當代的會話秘密換發一枚新秘密：同一行、同一裝置、同一絕對期限。
//
// 意圖只有一個——縮短一枚被偷看到的秘密還能用多久。它不是續期（會話的death時刻在
// 建立時就定死，見 internal/session 與遷移 0005），也不是重新登入（device_id 不動，
// 同一臺裝置換密不會在裝置清單裡多出一臺裝置，也不會丟掉原本的裝置身份）。
//
// 誰準它：只有「這枚秘密本身」。這裡不查角色、不看請求裡任何可自報的欄位——
// 拿一枚還活著的會話秘密來，就是這個動作的全部授權；拿一枚已失效的來，
// 得到的就是與任何其它被拒請求同樣的結論。
//
// 落地邊界：
//   - 舊秘密在那條 UPDATE 生效的一刻起徹底失效，沒有任何寬限視窗；庫裡只多留一個
//     世代號與上一代的雜湊，用來把「你晚了」和「你從來不對」分開（見 ErrStaleSession）。
//   - Root 主體：輪換與 root_audit 的 `auth.rotate` 落在同一個交易——審計寫不進去，
//     秘密就不換，兩件事實同生同滅。普通帳戶仍只進執行日誌（審計主體類別未批准，
//     與登入／登出同一口徑，本步不擅自歸類）。
//   - 被拒的輪換不寫審計：拒絕的理由是「你手上那枚不行」，把它記成一筆長期事實等於
//     給任何能碰到這個端點的來源一個寫入放大器，而它不提供任何審計要提供的東西。
//   - 日誌只記主體摘要、世代號與請求關聯 ID；新秘密明文不進日誌、不進審計、
//     不進回應 JSON 本體（它的唯一去處是傳輸層的 Set-Cookie）。
func (s *Service) RotateSession(ctx context.Context, secret, requestID string) (Outcome, error) {
	var outcome Outcome
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		sess, newSecret, err := s.sessions.Rotate(tctx, tx, secret)
		if err != nil {
			return err
		}
		// 換發後立刻用新秘密走一次「秘密→主體」：這一步既產生回應要用的主體，
		// 也順帶證明這枚新秘密真的換得出身份——發不出去的秘密不該被交給任何人。
		principal, _, err := s.sessions.ResolvePrincipal(tctx, tx, newSecret, identity.OriginHTTPRequest)
		if err != nil {
			return err
		}
		if principal.IsRoot() {
			subjectID, err := identity.RootSubjectID()
			if err != nil {
				return fmt.Errorf("auth: Root 審計主體標識異常: %w", err)
			}
			rec := s.rootSessionRecord(subjectID, "auth.rotate", sess.ID.String(), requestID, "")
			if _, err := s.audits.Append(tctx, tx, rec); err != nil {
				return err
			}
		}
		outcome = Outcome{Principal: principal, Session: sess, Secret: newSecret}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, session.ErrStaleSecret):
			return Outcome{}, fmt.Errorf("%w（%v）", ErrStaleSession, err)
		case errors.Is(err, session.ErrInvalidSecret), errors.Is(err, session.ErrRevoked),
			errors.Is(err, session.ErrExpired), errors.Is(err, session.ErrSubjectUnavailable),
			errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrInvalidSubject):
			return Outcome{}, fmt.Errorf("%w（%v）", ErrInvalidSession, err)
		}
		s.log.Error("會話輪換失敗", "request_id", requestID, "err", err)
		return Outcome{}, fmt.Errorf("auth: 會話輪換失敗: %w", err)
	}
	s.log.Info("會話秘密已輪換",
		"subject", outcome.Session.Subject.String(), "rotation_seq", outcome.Session.RotationSeq,
		"request_id", requestID)
	return outcome, nil
}

// DeviceRevokeResult 是一次定向撤銷的結果（僅供「我的裝置」撤銷端點使用）。
//
// Revoked 區分「這次真的停掉了一枚原本有效的會話」與「目標早已不在有效狀態」——
// 後者是冪等 no-op，不是錯誤。Session 帶回被撤銷（或本就撤銷過）的那一行，
// 讓傳輸層能判出「撤的是不是目前這臺」。不含任何憑據材料。
type DeviceRevokeResult struct {
	// Session 是被指向的會話行（在本主體範圍內讀得）。
	Session session.Session
	// Revoked 為 true 表示本次寫入了 revoked_at；false 表示目標本就已是失效態。
	Revoked bool
}

// ListDevices 列舉當前受信主體名下的全部裝置（會話）。
//
// 查詢範圍只由 Principal 換得的 Subject 決定（見 session.ListBySubject）：請求裡沒有任何
// 可以改寫「列誰的裝置」的欄位——連 account_id 都不是輸入，它是解析出來的身份。
// 因此 Root 與普通帳戶走同一個機制，沒有一條靠客戶端特判放寬的旁路。
// 回傳的實體不含任何秘密；失效行是否出現由倉儲的收錄範圍決定（含寬限期內尚未清理的行）。
func (s *Service) ListDevices(ctx context.Context, principal identity.Principal) ([]session.Session, error) {
	subject, err := session.SubjectOf(principal)
	if err != nil {
		return nil, err
	}
	list, err := s.sessions.ListBySubject(ctx, s.db.SQL(), subject)
	if err != nil {
		return nil, fmt.Errorf("auth: 列舉裝置失敗: %w", err)
	}
	return list, nil
}

// RevokeDevice 在當前受信主體的範圍內按 device_id 撤銷一枚會話。
//
// 誰準它：只有「剛經 Resolve 換回的一個有效主體」——呼叫它的傳輸層入口必須先讓本次
// 請求的憑據過一次 Verify（見 handleDeviceRevoke），這就兌現了「敏感操作重新檢查當前
// 會話有效」。目標歸屬由 Subject 範圍把關：只能撤自己的裝置，別人的 device_id 與
// 根本不存在的裝置收斂為同一個 ErrNotFound（session 層保證），不給枚舉留信号。
//
// 幂等邊界：重複撤銷一枚已撤銷的裝置不是錯誤（Revoked=false 的 no-op）；撤銷一枚
// 已到期但還留在庫裡的行仍寫下 revoked_at，統一走「已撤銷」這個最終態。
//
// 審計落地沿用 Root 域事件的既有口徑（見 Logout／RotateSession）：
//   - Root 主體：撤銷與 root_audit 的 auth.device_revoke 落在同一個交易，審計寫不進去
//     就不撤銷；只在「這次真的撤銷成功（Revoked=true）」時記一筆，重複撤銷的 no-op 不記。
//   - 普通帳戶：只進執行日誌，不進審計表（審計主體類別未批准，與登入/登出/輪換同一口徑）。
//   - 被拒（查無此裝置）不寫任何審計，也不給寫入放大器。
//
// 日誌與審計只記可展示事實（主體、裝置標識、請求關聯 ID）；本方法全程不經手任何秘密。
// 「被撤銷裝置後續請求立即被拒」由 revoked_at 落庫 guarantees：那枚會話的下一個請求在
// Verify 的第一道關卡就拿到 ErrRevoked。本步不假裝已透過 WebSocket 強制斷開連線——
// 目前尚無即時通道，撤銷的生效邊界是「下一個請求」。
func (s *Service) RevokeDevice(ctx context.Context, principal identity.Principal,
	deviceID idgen.ID, requestID string) (DeviceRevokeResult, error) {
	subject, err := session.SubjectOf(principal)
	if err != nil {
		return DeviceRevokeResult{}, err
	}
	if principal.IsRoot() {
		subjectID, err := identity.RootSubjectID()
		if err != nil {
			return DeviceRevokeResult{}, fmt.Errorf("auth: Root 審計主體標識異常: %w", err)
		}
		var res DeviceRevokeResult
		err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
			sess, revoked, err := s.sessions.RevokeDeviceBySubject(tctx, tx, subject, deviceID)
			if err != nil {
				return err
			}
			if revoked {
				rec := s.rootSessionRecord(subjectID, "auth.device_revoke", sess.ID.String(), requestID,
					"本人從裝置清單撤銷一台裝置")
				if _, err := s.audits.Append(tctx, tx, rec); err != nil {
					return err
				}
			}
			res = DeviceRevokeResult{Session: sess, Revoked: revoked}
			return nil
		})
		if err != nil {
			if errors.Is(err, session.ErrNotFound) {
				// 查無此裝置：原樣透出 ErrNotFound 鏈，讓傳輸層回「目標不存在」，
				// 不進撤銷審計（撤銷根本沒發生）。
				return DeviceRevokeResult{}, err
			}
			return DeviceRevokeResult{}, fmt.Errorf("auth: Root 裝置撤銷落地失敗: %w", err)
		}
		s.log.Info("Root 撤銷裝置會話",
			"device", res.Session.DeviceID.String(), "revoked", res.Revoked, "request_id", requestID)
		return res, nil
	}

	sess, revoked, err := s.sessions.RevokeDeviceBySubject(ctx, s.db.SQL(), subject, deviceID)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			return DeviceRevokeResult{}, err
		}
		return DeviceRevokeResult{}, fmt.Errorf("auth: 撤銷裝置會話失敗: %w", err)
	}
	s.log.Info("帳戶撤銷裝置會話",
		"account", principal.AccountID().String(), "device", sess.DeviceID.String(),
		"revoked", revoked, "request_id", requestID)
	return DeviceRevokeResult{Session: sess, Revoked: revoked}, nil
}

// issue 在一個交易裡執行裝置名額策略、簽發會話並推進帳戶的最近登入時刻。
//
// 三者同交易是「何時登入成功」這句話的完整性：會話存在而 last_login_at 未動，
// 或反過來，都讓帳戶頁面上的登入時間與裝置列表對不上同一次登入。
// 名額檢查也必須在這裡、而且在 Create 之前：檢查與寫入之間一旦跨出事務邊界，
// 併發的兩次登入會各自數到「還差一格」（見 session.Store.ApplyLoginSlotPolicy）。
// single 模式的撤銷同樣落在這個交易裡，所以「舊會話被停掉但新會話沒簽發」
// 這種把人關在門外的半套結果，在事務回滾時一起不存在。
// 普通帳戶這條路不寫審計（見套件檔案），交易裡只有這些寫入。
func (s *Service) issue(ctx context.Context, principal identity.Principal, accountID idgen.ID,
	requestID string) (Outcome, error) {
	var outcome Outcome
	var revokedPrior int
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		revoked, err := s.sessions.ApplyLoginSlotPolicy(tctx, tx, principal)
		if err != nil {
			return err
		}
		revokedPrior = revoked
		sess, secret, err := s.sessions.Create(tctx, tx, principal)
		if err != nil {
			return err
		}
		if err := s.accounts.RecordLogin(tctx, tx, accountID); err != nil {
			return err
		}
		outcome = Outcome{Principal: principal, Session: sess, Secret: secret}
		return nil
	})
	if err != nil {
		if errors.Is(err, session.ErrDeviceLimitReached) {
			// 名額已滿是策略拒絕：既沒寫會話也沒改 last_login_at，整個交易回滾。
			return Outcome{}, fmt.Errorf("%w（%v）", ErrLoginDeviceLimit, err)
		}
		if errors.Is(err, session.ErrSubjectUnavailable) || errors.Is(err, session.ErrInvalidSubject) {
			return Outcome{}, fmt.Errorf("%w（%v）", ErrInvalidCredentials, err)
		}
		return Outcome{}, fmt.Errorf("auth: 登入落地失敗: %w", err)
	}
	if revokedPrior > 0 {
		s.log.Info("單裝置策略已撤銷該主體的舊會話",
			"account", accountID.String(), "revoked", revokedPrior, "request_id", requestID)
	}
	return outcome, nil
}

// trimRequestID 保證關聯 ID 不超過審計欄位上限（中斷在傳輸層之前先發生在這裡）。
func trimRequestID(requestID string) string {
	if r := []rune(requestID); len(r) > 64 {
		return string(r[:64])
	}
	return strings.TrimSpace(requestID)
}
