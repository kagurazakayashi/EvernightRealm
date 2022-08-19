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
	// ErrLoginThrottled 表示該來源對該目標的失敗額度已打滿，正處於冷卻。
	// 它與 ErrInvalidCredentials 是兩個不同的對外結論（429「稍後再試」對 401「憑據無效」），
	// 但冷卻對「查無此人」與「真帳戶口令錯」完全同形：計量發生在查庫之前，
	// 觸發條件只看來源×目標的失敗次數，回應裡沒有任何欄位指出觸發的是誰。
	ErrLoginThrottled = errors.New("auth: 登入嘗試過於頻繁")
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
//  6. 同一個交易裡簽發會話並推進 accounts.last_login_at。
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

	outcome, err := s.issue(ctx, principal, a.ID)
	if err != nil {
		// issue 把「主體此刻不可用」的拒絕也收斂成 ErrInvalidCredentials 鏈；
		// 區分靠 errors.Is——那是憑據路徑的拒絕，不是內部故障。
		if errors.Is(err, ErrInvalidCredentials) {
			return Outcome{}, true, nil
		}
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
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		sess, secret, err := s.sessions.Create(tctx, tx, principal)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, s.rootLoginRecord(subjectID, "auth.login_success", sess.ID.String(), requestID, "")); err != nil {
			return err
		}
		outcome = Outcome{Principal: principal, Session: sess, Secret: secret}
		return nil
	})
	if err != nil {
		// 交易失敗不猜原因是哪一半：會話與審計同生同滅，這次登入就是沒有發生。
		return Outcome{}, false, fmt.Errorf("auth: Root 登入落地失敗: %w", err)
	}
	s.log.Info("Root 登入成功", "request_id", requestID)
	return outcome, false, nil
}

// rootLoginRecord 產生 Root 域登入審計。
//
// reason 只講結論（「憑據校驗未透過」這種內部分類），不帶口令、不帶雜湊、
// 不帶錯誤鏈——那些屬日誌，不屬要長期保留的審計事實。
// sessionID 在失敗記錄上是空字串：那一次登入沒有簽發任何會話，
// 拿「不存在的會話標識」冒充 target 等於造出一個查無此事的指紋。
func (s *Service) rootLoginRecord(subjectID idgen.ID, action, sessionID, requestID, reason string) audit.Record {
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
	rec := s.rootLoginRecord(subjectID, "auth.login_failure", "", requestID, reason)
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
		if errors.Is(err, session.ErrInvalidSecret) || errors.Is(err, session.ErrRevoked) ||
			errors.Is(err, session.ErrExpired) || errors.Is(err, session.ErrSubjectUnavailable) ||
			errors.Is(err, session.ErrNotFound) || errors.Is(err, session.ErrInvalidSubject) {
			return identity.Principal{}, session.Session{}, fmt.Errorf("%w（%v）", ErrInvalidSession, err)
		}
		return identity.Principal{}, session.Session{}, fmt.Errorf("auth: 會話解析失敗: %w", err)
	}
	return principal, sess, nil
}

// issue 在一個交易裡簽發會話並推進帳戶的最近登入時刻。
//
// 兩者同交易是「何時登入成功」這句話的完整性：會話存在而 last_login_at 未動，
// 或反過來，都讓帳戶頁面上的登入時間與裝置列表對不上同一次登入。
// 普通帳戶這條路不寫審計（見套件檔案），交易裡只有這兩筆寫入。
func (s *Service) issue(ctx context.Context, principal identity.Principal, accountID idgen.ID) (Outcome, error) {
	var outcome Outcome
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
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
		if errors.Is(err, session.ErrSubjectUnavailable) || errors.Is(err, session.ErrInvalidSubject) {
			return Outcome{}, fmt.Errorf("%w（%v）", ErrInvalidCredentials, err)
		}
		return Outcome{}, fmt.Errorf("auth: 登入落地失敗: %w", err)
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
