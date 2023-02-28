// Package guestacct 是「匿名訪客以臨時受限身分進入伺服器」的應用服務用例層：
// 帳戶建立策略允許訪客時（guest_enabled 為真而且這條通路在本次執行檔真的落地），
// 讓還沒登入的人自願換得一個由伺服器命名的訪客帳戶，並在同一个交易裡拿到一枚
// 与普通帳戶完全同規格的會話。
//
// 本套件回答的只有一句話：「此刻門外的人能不能自願成一個臨時身分進去」。
// 它與 internal/selfregister 建的都不是同一種主體（standard 帶口令、可由本人反覆證明
// 身分；guest 無口令、其存在只綁在这一枚會話上），准入依據也不同（前者看自註冊模式，
// 後者看訪客開關），因此刻意分成兩個套件：把兩種准入塞進一個 Service，
// 「建的是哪一類主體」就要靠同一個函式上的分支記，那是兩套邊界最容易互相污染形態。
//
// 六條不可讓步的規定：
//   - 訪客帳戶的形態由帳戶域與資料庫 CHECK 雙重凍結：無憑據雜湊、無首次改密旗標
//     （見 internal/account 的 New 與遷移 0003）。本套件因此不可能交出一枚「可以用口令
//     再登進去」的東西——他手上唯一的憑據就是會話，而會話照樣受撤銷與到期約束。
//   - 登入名一律由伺服器產生（見 guestLoginName），請求裡沒有任何格子能填它。
//     這不是省事：一個呼叫端可選的登入名就是一個存在性探測器，而且會讓他能用
//     「假訪客名」去佔住将来某個真人想用的名字。暱稱是展示資訊，不是登入主鍵、
//     也不是憑據；它允许彼此同名（顯示名从來不承擔唯一性）。
//   - 建號、簽發會話、審計落在同一筆交易。「訪客拿到了會話」與「訪客帳戶存在」
//     因此不可能只有一半：任何一步失敗都整筆回滾，庫裡不會留下一個查無會話的孤兒行，
//     也不會有一枚指向不存在主體的憑據。這同時是「不產生特殊 Cookie」的落點——
//     會話由 internal/session 那唯一的簽發點產生，本套件沒有第二套會話形態。
//   - 訪客不帶任何伺服器級授予，而且結構上拿不到：主體經 identity.NewAccountPrincipal
//     構造時遞交的是空的 Grants（nil），而該構造函式對「訪客帳戶持有角色」直接判錯。
//     「因此他做不了管理動作」不是本套件的決定，是 internal/identity 與各端點
//     （NeedServerAdmin／NeedRoot）早已存在的判定；本套件只保證不给他任何東西可被放行。
//   - 准入判定發生在交易內現讀的策略上。Root 在任何一刻關掉訪客開關，下一條請求
//     就必然按新值判定；/auth/capabilities 那個匿名布林只是顯示依據，不是准入。
//   - 每一次嘗試（成功與可歸因於呼叫端的拒絕都算）都要銷一份守衛預算。
//     這是本通路與登入／自註冊最大的語意差別，而且理由是資源而不是禮貌：
//     自註冊那側的匿名寫入有「登入名唯一」這條天然_self_limiting_——同一個來源
//     反復提交同一個名字只會拿到 2019 並被記一次失敗；而訪客的登入名由伺服器產生，
//     每一次嘗試都必然換出一個新帳戶，如果只記失敗不記成功，「不限開關、只管刷」
//     就等於用一條匿名 GET 之外的通路把 accounts 與 sessions 兩張表無限撐大。
//     因此計量單位是「嘗試」，冷卻閾值沿用 security.register_guard（見 internal/app）。
//
// 關於「失去會話之後怎麼辦」：本套件刻意沒有一条「凭暱稱找回」的通路。一個可被本人
// 複述的暱稱如果換得出會話，它就是一把口令——而它比口令更糟，因為它由本人自報、
// 可重複、可枚舉。於是既定處置只有一種：會話到期、主動退出、換裝置或清掉本機憑據之後，
// 這一趟臨時身分就結束了；要找回那個人，由管理員在普通帳戶目錄（本就把訪客列進去）
// 核實之後另行處理。本套件也不做任何「自動重建」：重建是呼叫端（界面）的決定，
// 而界面只在人主動按的時候打這條路徑。
//
// 時刻、標識與審計的來源與全倉庫一致（DEC-011、DEC-014、DEC-015）：建立時刻與帳戶標識
// 由 internal/account 的倉儲經注入時鐘與 idgen 產生，會話時刻由 internal/session 產生，
// 呼叫端無權代填；審計標識由 internal/audit 產生。
package guestacct

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// GuestTarget 是訪客進入通路在頻率守衛裡的固定目標標識。
//
// 它是一個保留字，與 internal/auth 的 RootTarget 同形：普通帳戶那兩條路徑的鍵由登入名
// 正規化派生，而訪客請求根本不帶登入名，計量主軸因此只能是「來源位址 × 這一個固定目標」。
// 用常數而不是「暱稱的正規化鍵」有一個必須守住的理由：暱稱可重複、可自報，
// 拿它當鍵等於讓攻擊者自己挑選要落進哪個計量條目，配對上限就此形同虛設。
const GuestTarget = "guest_entry"

// 對外可判別的結論錯誤：傳輸層據此分流回應，內部故障一律不進這些型別。
var (
	// ErrThrottled 是來源被限流擋下的結論哨兵（經 ThrottledError 帶著剩餘冷卻時間上拋）。
	//
	// 它講的是「這個來源此刻已經用完了訪客入口的嘗試預算」，不是權限、也不是暱稱本身的對錯。
	// 傳輸層據此回 2006＋Retry-After，與登入、自註冊同一個機器碼：被擋的嘗試不透露
	// 它擋的是哪一趟，也不因為「這是訪客入口而不是註冊」就多開一枚可分辨的外在信號。
	ErrThrottled = errors.New("guestacct: 訪客進入嘗試過於頻繁")
	// ErrGuestDisabled 表示帳戶建立策略此刻不開放訪客：開關是關的，
	// 或（理論上不會發生在本次執行檔）通路登記已被撤下。
	//
	// 它是策略決定而不是權限或輸入問題：請求本體沒有任何可改的欄位，換暱稱、重新整理
	// 都不會讓它變成放行，要等的是 Root 把訪客開關打開。沿用自註冊那側的 2017
	// （CodeAccountCreationDisabled：「這條帳戶建立通路此刻被伺服器策略關閉」）——
	// 那句話本來就是為「帳戶建立通路」寫的，不為訪客另開一枚碼。
	// 被這條擋下的嘗試不銷守衛預算：那該讓部署者的開關去扣正當用戶的次數。
	ErrGuestDisabled = errors.New("guestacct: 訪客進入此刻未啟用")
	// ErrInvalidNickname 表示送來的暱稱不滿足顯示名的領域規則。
	//
	// 走 1004（點名 nickname 欄位）：這是本次輸入的形狀問題，與策略、與帳戶存在與否無關，
	// 可以安全地分開說。它記一次守衛預算（可歸因於呼叫端的輸入），而且不進交易——
	// 形狀不合格的暱稱不該佔一次建號寫入。
	ErrInvalidNickname = errors.New("guestacct: 暱稱不滿足顯示名規則")
)

// ThrottledError 是帶著剩餘冷卻時間的 ErrThrottled。
//
// 它讓 errors.Is(err, ErrThrottled) 成立，不認識這個型別的呼叫端也不會漏判；
// RetryAfter 給傳輸層算 Retry-After 標頭用。
type ThrottledError struct {
	RetryAfter time.Duration
}

func (e *ThrottledError) Error() string {
	return "guestacct: 訪客進入嘗試過於頻繁，暫不受理"
}

// Unwrap 讓 errors.Is(err, ErrThrottled) 成立。
func (e *ThrottledError) Unwrap() error { return ErrThrottled }

// EnterInput 是一次訪客進入所需的領域輸入。
//
// 只有暱稱這一格，而且可空：沒有任何「帳戶標識」「角色」「主體類別」「活動標識」可填，
// 也沒有任何依據值欄位——這是一條匿名通路，呼叫端此刻还不是一個可被指認的人。
// 空暱稱時由伺服器產生臨時編號（見 temporaryNickname），它同樣只是展示資訊。
type EnterInput struct {
	// Nickname 為本人自報的展示用暱稱；不承擔唯一性，也不是憑據。
	// 它只在本次調用期間短暫停留，不進審計以外任何地方——它會落進 accounts.display_name，
	// 因為「后來管理目錄的人要看得到這個人自報過什麼」是這趟臨時身分唯一留下的可讀線索。
	Nickname string
}

// Outcome 是一次成功進入的結果，全部為可展示的事實（不含任何憑據材料）。
//
// Secret 是會話秘密的一次性明文：它唯一的去處是傳輸層寫進 Set-Cookie，
// 不得進 JSON 回應、日誌、審計或任何錯誤訊息。Principal 與 Session 供回應對映
// 與上下文使用，其形態與 internal/auth 的登入結果逐字同規格（同一個簽發點、
// 同一份到期時刻、同一套撤銷與輪換規則）。
type Outcome struct {
	// Principal 是剛構造的訪客主體：KindAccount、TypeGuest、零授予。
	Principal identity.Principal
	// AccountID 是伺服器產生的穩定帳戶標識。它是這趟臨時身分唯一的長期身份——
	// 暱稱可以重複、會話會到期，而標識指向 accounts 表那一行，不會被第二個人撿走。
	AccountID idgen.ID
	// DisplayName 是最終落庫的展示名：本人給的暱稱，或伺服器產生的臨時編號。
	DisplayName string
	// Type 恆為 account.TypeGuest：它是傳輸層回報 account_type 的唯一來源，
	// 也是「界面之後講的是臨時身分而不是普通帳戶」這句話的依據（見 httpapi 的 loginResponse）。
	Type account.Type
	// Session 是剛簽發的會話實體。
	Session session.Session
	// Secret 是會話秘密的一次性明文（只准進 Set-Cookie）。
	Secret string
}

// Deps 是本用例的外部依賴，全部由裝配層（internal/app）注入。
type Deps struct {
	// DB 提供交易邊界與 autocommit 查詢。
	DB *database.DB
	// Accounts 是帳戶倉儲（登入名正規化、顯示名校驗與標識產生的唯一來源）。
	Accounts *account.Store
	// Policy 是帳戶建立策略倉儲。準不準放客問的是 acctpolicy，不自己查那張表——
	// 「策略值不等於能力」的合成必須只有那一個來源（見 internal/acctpolicy 的 AllowsGuest）。
	Policy *acctpolicy.Store
	// Sessions 是会話核心。訪客用的就是全服務唯一的那個簽發點與那套裝置名額策略：
	// 本套件不、也不得自己寫一份會話行。
	Sessions *session.Store
	// Audits 是 Root 域審計倉儲。匿名建號的痕跡與其餘伺服器級動作落在同一張表。
	Audits *audit.Store
	// Guard 是「訪客進入」這條通路專屬的頻率守衛。它是獨立於登入與自註冊的第三個
	// auth.LoginGuard 實例（另一份記憶體），閾值沿用 security.register_guard：
	// 三個入口各自燒的是各自的預算，但同一套匿名寫入的緊度由同一份組態決定，
	// 部署者不必為第三條路再記一組數字。
	Guard *auth.LoginGuard
	// Log 為伺服器端記錄出口；nil 時丟棄。
	Log *slog.Logger
}

// Service 是訪客進入用例的編排者。零值不可用，請經 New 取得。
type Service struct {
	db       *database.DB
	accounts *account.Store
	policy   *acctpolicy.Store
	sessions *session.Store
	audits   *audit.Store
	guard    *auth.LoginGuard
	log      *slog.Logger
}

// New 校驗依賴並建立服務。
//
// 缺任何一個依賴都是組裝缺陷，在啟動階段當場報出：少策略倉儲就問不到「此刻准不准放訪客」，
// 等於默認放行；少會話倉儲就只能建號不簽發，那是一個查不到任何會話的孤兒帳戶；
// 少守衛就少一道匿名寫入的資源封頂；少審計就建出一個不留痕的伺服器級主體變更。
func New(deps Deps) (*Service, error) {
	if deps.DB == nil || deps.Accounts == nil || deps.Policy == nil ||
		deps.Sessions == nil || deps.Audits == nil || deps.Guard == nil {
		return nil, errors.New("guestacct: 用例缺少必要依賴（db/accounts/policy/sessions/audits/guard）")
	}
	logger := deps.Log
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		db:       deps.DB,
		accounts: deps.Accounts,
		policy:   deps.Policy,
		sessions: deps.Sessions,
		audits:   deps.Audits,
		guard:    deps.Guard,
		log:      logger,
	}, nil
}

// Enter 讓一個匿名的人自願換得一個臨時受限身分與一枚會話。
//
// 順序與每一跳的理由：
//  1. 頻率先於一切：guardCheck 在查庫、建號、簽發、審計之前就問守衛還許不許。冷卻中的
//     請求到這裡為止，不碰資料庫、不寫任何一行——限流要保護的恰恰是這幾個最貴的資源。
//     目標鍵固定為 GuestTarget（來源×這一個通路），見該常數的註解。
//  2. 暱稱先做廉價的形狀檢查（交易之外）：一個超長或含控制字元的暱稱不該佔一次建號寫入。
//     這裡只復核「還可能是一個顯示名嗎」，真正的規則仍以帳戶域為準（見第 5 步的二次把關）。
//  3. 交易內現讀策略並判定訪客開關：依據必須是「寫入那一刻」的現值。關著、
//     或通路登記不支援 → ErrGuestDisabled（2017），整筆交易一個字都不寫。
//  4. 產生登入名與（必要時的）臨時暱稱：兩者都來自 idgen 這唯一的標識產生點。
//     登入名是「佔住唯一鍵的那個符號」，帳戶標識才是穩定身份——Store.Create 自己產生標識，
//     本套件不代填，所以這裡用的是另一個隨機標識，兩者互不冒充。
//  5. 建號（TypeGuest、StatusActive、無憑據、無改密旗標）→ 構造主體（零授予）→
//     裝置名額策略 → 簽發會話 → 推進 last_login_at → 記 Root 域審計，全部同一筆交易。
//     任何一步出錯整筆回滾：這正是「不會有查無會話的孤兒帳戶」與「不會有指向虛假主體的憑據」
//     同時成立的落點。名額策略在這裡對一個剛出生的主體必然通過（他名下沒有任何會話），
//     因此那條策略拒絕在本通路上不可達，本套件也不為它寫一支會誤導人的對映。
//  6. 銷一份嘗試預算：成功與可歸因於呼叫端的拒絕都銷，只有伺服器狀態（開關關著）
//     與內部故障不銷。理由寫在套件頭注——這條通路沒有「唯一鍵自限」那道天花板，
//     嘗試計量就是它唯一的寫入放大器封頂。
func (s *Service) Enter(ctx context.Context, in EnterInput, requestID, sourceIP string) (Outcome, error) {
	if blocked := s.guardCheck(sourceIP); blocked != nil {
		return Outcome{}, blocked
	}

	nickname := strings.TrimSpace(in.Nickname)
	if nickname != "" && !nicknameShapePlausible(nickname) {
		// 可歸因於呼叫端的輸入：銷預算，並給傳輸層一句可以安全點名欄位的話。
		s.guardAttempt(sourceIP)
		s.log.Warn("訪客進入被拒：暱稱不合領域規則", "request_id", requestID)
		return Outcome{}, ErrInvalidNickname
	}

	outcome, err := s.enterInTx(ctx, nickname, requestID)
	if err != nil {
		return Outcome{}, s.classifyFailure(err, sourceIP, requestID)
	}
	s.guardAttempt(sourceIP)
	s.log.Info("已受理訪客進入",
		"account", outcome.AccountID.String(), "nickname", outcome.DisplayName,
		"request_id", requestID)
	return outcome, nil
}

// enterInTx 在單一交易裡完成「現讀策略→建號→簽發會話→審計」，回傳全為服務端事實的成果。
//
// 策略判定放在交易內而不是 Enter 裡：與自註冊、管理員建號同一口徑——開關可以在任何一刻
// 被 Root 改掉，「上次讀到的值」不構成放行依據。BEGIN IMMEDIATE（見 internal/database）
// 讓併發的進入串行化，於是不會有兩筆訪客帳戶共用同一個臨時登入名，
// 也不會有兩枚會話指向同一行尚未落庫的帳戶。
func (s *Service) enterInTx(ctx context.Context, nickname, requestID string) (Outcome, error) {
	var outcome Outcome
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		policy, err := s.policy.Get(tctx, tx)
		if err != nil {
			return err
		}
		if !policy.AllowsGuest() {
			return ErrGuestDisabled
		}

		// 兩個隨機標識各有其職：一個撐住唯一鍵（並因而撐住「這趟進入對應 accounts 的哪一行」），
		// 一個只給人看（臨時編號）。帳戶的穩定標識由 Store.Create 另行產生，這裡不代填。
		nameSeed, err := idgen.New()
		if err != nil {
			return fmt.Errorf("guestacct: 產生訪客登入名失敗: %w", err)
		}
		loginName := guestLoginName(nameSeed)
		if nickname == "" {
			nickname = temporaryNickname(nameSeed)
		}

		a, err := s.accounts.Create(tctx, tx, account.NewInput{
			LoginName:          loginName,
			DisplayName:        nickname,
			PasswordHash:       "",
			Type:               account.TypeGuest,
			Status:             account.StatusActive,
			MustChangePassword: false,
		})
		if err != nil {
			return err
		}

		principal, err := identity.NewAccountPrincipal(identity.AccountInput{
			Subject: identity.SubjectOf(a),
			Origin:  identity.OriginHTTPRequest,
			// 空的 Grants：這是「訪客不帶任何伺服器級角色」的構造期落點。
			// NewAccountPrincipal 對「訪客卻持有角色」直接判錯，所以這裡給的不只是
			// 「本套件不想給他」，而是任何後續改寫都要先撞過的那道型別閘。
			Grants: identity.NewServerGrants(),
		})
		if err != nil {
			return fmt.Errorf("guestacct: 構造訪客主體失敗: %w", err)
		}

		if _, err := s.sessions.ApplyLoginSlotPolicy(tctx, tx, principal); err != nil {
			return err
		}
		sess, secret, err := s.sessions.Create(tctx, tx, principal)
		if err != nil {
			return err
		}
		// 與登入路徑同一個寫法：會話簽發成功的同時推進最近登入時刻，
		// 否則目錄上「他最近用過嗎」與裝置清單對不上同一趟進入。
		if err := s.accounts.RecordLogin(tctx, tx, a.ID); err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, s.auditRecord(a, requestID)); err != nil {
			return err
		}

		outcome = Outcome{
			Principal:   principal,
			AccountID:   a.ID,
			DisplayName: a.DisplayName,
			Type:        a.Type,
			Session:     sess,
			Secret:      secret,
		}
		return nil
	})
	if err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}

// guardCheck 在一切寫入之前問守衛「還許不許」。被擋的嘗試只留 Debug 級痕跡：
// 冷卻期內對方可以無限發請求，每請求一條 Warn 就是把限流變成新的資源放大器。
func (s *Service) guardCheck(source string) error {
	blocked, retryAfter := s.guard.Allow(source, GuestTarget)
	if !blocked {
		return nil
	}
	s.log.Debug("訪客進入嘗試被限流擋下", "source", source, "retry_after", retryAfter.String())
	return &ThrottledError{RetryAfter: retryAfter}
}

// guardAttempt 銷一份該來源的嘗試預算。
//
// 它調的是 RecordFailure，但語意是「記一次嘗試」而不是「記一次失敗」，這個差別是刻意的，
// 而且不能改成 RecordSuccess：那條通路沒有唯一鍵自限，成功的那一趟才是它真正消耗的資源
// （一筆帳戶列、一枚會話列、一筆審計）。把成功從帳上摘掉，等於給任何來源一條
// 「開關只要亮著就能無限建號」的路，而那不是一個策略開關擋得住的東西。
// 冷卻觸發時才升 Warn 日誌（每個條目每視窗至多喊一次），且只帶來源、不帶暱稱。
func (s *Service) guardAttempt(source string) {
	if triggered := s.guard.RecordFailure(source, GuestTarget); triggered {
		s.log.Warn("訪客進入嘗試額度打滿，來源進入冷卻", "source", source)
	}
}

// classifyFailure 把交易回傳的錯誤映射成對外結論，並決定要不要補銷一份嘗試預算。
//
// 口徑與 internal/selfregister 同源但計量單位不同（這裡成功也計）：
//   - 伺服器狀態決定的拒絕（開關關著、策略行讀不到）與內部故障不補銷——前者已經在
//     入口被擋，後者不是呼叫端的錯；
//   - 可歸因於呼叫端的輸入（帳戶域在交易內二次把關攔下的暱稱）補銷一次。
//     訪客登入名由伺服器產生，理論上不與任何人撞鍵；真撞上了（idgen 故障那一類）
//     屬內部故障，走 default 原樣上拋讓傳輸層回 5xx，不降级成「請換一個暱稱」。
func (s *Service) classifyFailure(err error, source, requestID string) error {
	switch {
	case errors.Is(err, ErrGuestDisabled):
		s.log.Warn("訪客進入被拒：帳戶建立策略未開放訪客", "request_id", requestID)
		return ErrGuestDisabled
	case errors.Is(err, account.ErrInvalidDisplayName):
		s.guardAttempt(source)
		s.log.Warn("訪客進入被拒：暱稱不合領域規則", "request_id", requestID, "err", err)
		return fmt.Errorf("%w（%v）", ErrInvalidNickname, err)
	case errors.Is(err, acctpolicy.ErrNoPolicyRow):
		// 結構缺陷：單例策略行讀不到。原樣上拋讓交易回滾，不猜成關也不猜成開。
		s.log.Error("訪客進入時讀取帳戶建立策略失敗", "request_id", requestID, "err", err)
		return err
	default:
		s.log.Error("訪客進入落地失敗", "request_id", requestID, "err", err)
		return fmt.Errorf("guestacct: 訪客進入失敗: %w", err)
	}
}

// auditRecord 產生一筆 Root 域的建號審計，操作者是服務端自身（系統主體）。
//
// 與匿名自註冊同一個口徑：actor 用 ActorSystem 且 actor.id 留 Nil——匿名請求沒有可信主體，
// 既不能冒充 Root／管理員，也不該給一個「查得出是誰建的」的假承諾。
// ScopeRoot 而不捏造 activity_id：建號是伺服器級動作，不屬於任何活動。
//
// 絕不落進記錄的東西：任何會話材料、來源 IP（那屬執行／訪問日誌）、錯誤鏈原文。
// changes 只記可展示的身分欄位；account_type=guest 與 must_change_password=false
// 是這條通路在審計裡最必須看得見的兩個事實——它們一起說明「這個人沒有口令可被猜」，
// 而日後有人在目錄裡看到這一行時，那是唯一能追溯他怎麼出生的證據。
func (s *Service) auditRecord(a account.Account, requestID string) audit.Record {
	return audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  audit.Actor{Kind: audit.ActorSystem},
		Action: "account.guest_enter",
		Target: audit.Target{Kind: "account", ID: a.ID.String()},
		Reason: "匿名自願進入為訪客臨時身分（策略於交易內現讀放行），登入名由伺服器產生、" +
			"無任何一般憑據，不帶伺服器級角色；會話與建號同筆交易簽發",
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

// guestLoginName 由隨機標識導出訪客的登入名。
//
// 形態固定為 `guest_<36 字元 UUIDv7>`（42 個字元，落在帳戶域與資料庫的 64 上界之內）：
// 前綴讓目錄與審計一眼分得出這一行是怎麼出生的，後面那串由 idgen 保证唯一，
// 於是「同一個来源刷出兩筆同一個名字的訪客」不是靠先查後插、而是靠標識本身不可能重複。
// 它不参与任何登入：訪客沒有口令通路，這個名字既不是憑據也不是找回依據（見套件頭注）。
func guestLoginName(seed idgen.ID) string {
	return "guest_" + seed.String()
}

// temporaryNickname 由同一個隨機標識導出一個語言中立的臨時編號。
//
// 取 UUID 尾巴 6 個十六位元字元、冠以 `guest-`：它純粹是展示資訊，與登入名同源但更短、
// 好念好認。刻意不含任何語言的字詞——伺服器产生的東西會出現在操作者的目錄與訪客的界面上，
// 而界面文案的四語言責任在 Flutter 端，不在一欄資料裡。
// 它也不是秘密：真正指認這趟進入的是帳戶標識與手上那枚會話。
func temporaryNickname(seed idgen.ID) string {
	hex := strings.ReplaceAll(seed.String(), "-", "")
	if len(hex) > 6 {
		hex = hex[len(hex)-6:]
	}
	return "guest-" + hex
}

// nicknameShapePlausible 是「這串還可能是個顯示名嗎」的廉價閘：非空、不超長、
// 不含控制或格式字元。它與帳戶域的規則同口徑但不是權威（權威是 account.New 裡那次校驗，
// 它會在交易內再擋一次）——放在交易之外只為省下明顯不合格的輸入那次寫入。
// 長度上界取帳戶域的顯示名上界（64 個碼位）。
func nicknameShapePlausible(nickname string) bool {
	if len([]rune(nickname)) > maxNicknameRunes {
		return false
	}
	for _, r := range nickname {
		if unicode.IsSpace(r) {
			continue
		}
		// 與 internal/account 同一判準：控制字元與格式字元（零寬、雙向覆寫）一進顯示名，
		// 同形字攻擊就有一塊地方可以藏身，而顯示名是會被人在目錄裡唸出來的欄位。
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// 顯示名的形狀界線（與 internal/account 的常量同值；那边未匯出，這裡只做廉價預閘）。
const maxNicknameRunes = 64

// trimRequestID 保證關聯 ID 不超過審計欄位上限（與 internal/selfregister、internal/stdacct 同口徑）。
func trimRequestID(requestID string) string {
	if r := []rune(requestID); len(r) > 64 {
		return string(r[:64])
	}
	return requestID
}
