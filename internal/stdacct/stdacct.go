// Package stdacct 是「伺服器級管理員打理普通帳戶」的應用服務層：
// 建立（受信主體判定 → 策略現讀 → 憑據派生 → 帳戶建立與審計落地的原子用例）、
// 分頁目錄與單筆詳情、非安全資料（顯示名）的白名單編輯、登入能力的停用與恢復、
// 登入憑據的重置。
//
// 本套件的用例共用同一條授權邊界（NeedServerAdmin）與同一批仓储實例，
// 卻各自回答不同的一句話：建立問「此刻准不准多出一筆」、目錄問「哪些人在我這本名冊上」、
// 詳情與編輯問「這一筆的現值是什麼、能不能按白名單改一欄」、
// 狀態問「能不能動這個帳戶的伺服器級登入能力（以及動了之後既有會話怎麼辦）」、
// 重置問「這個帳戶的口令換成操作者親自交的那一次性口令之後，舊口令與舊會話怎麼辦」、
// 升級問「這個訪戶能不能就地轉正、轉正時他手上那枚臨時憑據怎麼辦」、
// 綁定預檢問「若要把這個訪戶併入另一個既有正式帳戶，此刻可不可行、被什麼擋著」、
// 憑證簽發問「這一對既然可行，准不准把最後一動交給那個目標本人」、
// 核銷與留痕問「目標本人現在要按下去了，那一刻的事實還對嗎」。
// 預檢那一問是純只讀的衝突預覽（零寫入）；執行那一動只屬於憑證上那個目標帳戶的
// 已認證會話（用戶批准的同意形態 target_self_initiated），
// 管理員拿得到簽發、拿不到代他人按下執行——那一格在協定層與資料庫層都不存在。
// 把「建號」與「目錄」放進同一個套件是刻意的：兩者認的是同一類主體（不持有伺服器級角色的
// 普通與訪戶帳戶）、落的是同一個審計域（Root 域、actor 是真實操作者），
// 拆成兩套就會出現「建號認得管理員排除規則、目錄卻把他列進來」這種兩處真相。
//
// 為什麼獨立成一個套件而不是放進 internal/adminacct 或 internal/account：
//   - adminacct 回答的是「Root 如何打理管理員目錄」，每一個用例的授權邊界都是 NeedRoot，
//     且建出的形態恆帶 server_admin 授予；本套件的授權邊界是 NeedServerAdmin，
//     建出的形態恆「不帶任何伺服器級角色」，而目錄的範圍定義恰恰是「把持有授予的人排掉」——
//     把兩者混進一個套件，「誰能碰哪一類人」就要靠同一個 Service 上的分支來記，
//     那是兩套邊界最容易互相污染的形態；
//   - account 是帳戶實體與其倉儲（「一筆帳戶資料長什麼樣」），而「此刻准不准多出一筆帳戶」
//     「這個人歸不歸管理員管」是使用帳戶的規則，屬策略與授權，不屬實體；
//   - 依賴方向因此保持單向：stdacct → acctpolicy（策略現讀與放行合成）、
//     grant（授予有無）、account（實體與唯一鍵）、session（停用與重置時的定向撤銷、
//     綁定預檢時的只讀計數）、guestbind（綁定憑證與綁定留痕：那兩張表唯一被碰到的地方，
//     本套件不抄它們的 SQL）、audit（落地痕跡）、database/migrate（綁定預檢現讀
//     schema 版本——「這個庫跑到哪一版」只有那一個實作點）、credential／database／identity。
//
// 目錄那條跨表只讀 SQL 屬用戶批准的「只讀展示投影例外」（原為 internal/adminacct 而立，
// 本步經用戶批准首次擴展到第二個套件）。三條邊界一個字不減：只讀、欄位白名單、
// 永不參與授權判定；單筆詳情與編輯的範圍核實仍經 account 實體讀法＋grant 授予讀法，
// 見 directory.go 與 profile.go 的頭注。
//
// 四條不可讓步的規定：
//   - 角色、帳戶類型、審批狀態、首次改密要求都由本用例決定，請求裡沒有任何格子可填。
//     CreateInput 只有登入名、顯示名與初始口令三個欄位，而傳輸層的未知欄位規則
//     把 role／account_type／status／subject_kind 之類的宣稱當場拒殺（1004）：
//     「建的是哪一類主體」由「打的哪個端點、走的哪個用例」決定，不是由請求內容決定；
//   - 建立前先問策略、而且問的是「寫入那一刻」的策略。放行判定（AllowsAdminCreateStandard）
//     發生在同一筆交易內讀回的現值上（acctpolicy.Store.Get 收的是呼叫端自己的交易），
//     不是裝配時算好的一份、也不是交易開始前的舊快照——Root 在任何一刻關掉開關，
//     下一條建號請求就必然按新值判定，不存在「預讀通過後才寫入」的窗口；
//   - Root 沒有例外。admin_create_standard 關閉時，走這條通路的 Root 同被拒：
//     NeedServerAdmin 本來放過 Root，若在這裡加分支，同一個端點就有了兩種身分兩套答案，
//     策略表說的和執行的不再一致（與設備策略「上限已滿 Root 無例外」同一口徑）。
//     Root 自己的開入口（/root/admins 與 init-root／recover-root）不在本開關之下，
//     那由 acctpolicy 的既有邊界決定，本套件不重複那個決定；
//   - 寫入與審計落在同一個交易。管理員建的是「一個能登入伺服器的人」，這是伺服器級動作，
//     痕跡因此落在 root_audit（ScopeRoot）而 actor 是真實操作者的帳戶標識
//     （principal.AuditActor() 對持有 server_admin 的帳戶換得 ActorAdmin）：
//     既不冒充 Root，也不為「塞得進活動審計」而捏造 activity_id——
//     ScopeRoot 的校驗本來就要求 activity_id 為 Nil。操作者由此可查，
//     但本套件不給任何人新增查閱 Root 域的能力（查閱規則屬 internal/audit，一分未動）。
//
// 憑據一律經 internal/credential 以裝配層注入的當前參數檔派生（與登入、Root 初始化、
// 本人改密、Root 開設管理員同一個實作點），本套件不另寫一套口令規則，
// 也不落庫、不回傳任何口令明文。
//
// 初始口令與重置口令的交付語意沿用 Root 開設管理員、Root 重置管理員時用戶批准的形態：
// 交入口的一次性口令由操作者親自交、must_change_password=1 落庫、
// 伺服端不生成口令、不在任何回應裡回顯、不設默認口令。
// 建出來的帳戶此刻只是一個 Account：沒有 Activity Profile、沒有活動資產、
// 不在任何名冊上——「已建立」與「已加入活動」是兩句話，本套件只說得了前一句。
package stdacct

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/guestbind"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 對外可判別的結論錯誤：傳輸層據此分流回應，內部故障一律不進這些型別。
var (
	// ErrCreateDisabled 表示帳戶建立策略此刻不允許這條通路（admin_create_standard 為關）。
	//
	// 它是策略決定而不是權限問題：操作者的身分可信、也確實持有管理權，
	// 缺的是伺服器對「這條通路開不開」的現值。因此它必須有自己的結論讓傳輸層
	// 回 2017，不能報成 2011——那句話會誤導人「換個身分或重登就有效」，
	// 而兩者都不是處置。也不回 1004：請求本體沒有任何可改的欄位。
	ErrCreateDisabled = errors.New("stdacct: 管理員建立普通帳戶的通路此刻未開放")
	// ErrDuplicateLogin 表示登入名的正規化鍵已被佔用。
	//
	// 與 internal/adminacct 的同名結論同一語意：可預期的業務衝突，不是缺陷。
	// 正確性來自資料庫唯一索引（遷移 0003），「先查再插」從來不是正確性來源。
	ErrDuplicateLogin = errors.New("stdacct: 登入名已被佔用")
	// ErrInvalidInitialPassword 表示初始口令不滿足憑據模組的形狀界線（空或超長）。
	ErrInvalidInitialPassword = errors.New("stdacct: 初始口令不滿足憑據形狀界線")
	// ErrPermissionDenied 沿用 identity 的判定結論：身分可信但沒有這個權限。
	ErrPermissionDenied = identity.ErrPermissionDenied
)

// CreateInput 是建立一個普通帳戶所需的領域輸入。
//
// 沒有任何角色、帳戶類型、審批狀態或旗標欄位：本用例建的就是
// 「standard ＋ active ＋ 無伺服器級角色 ＋ 首次必改密」這一種形態，
// 由端點形態而不是請求欄位決定。
type CreateInput struct {
	// LoginName 為登入名原始寫法；正規化唯一鍵由帳戶域層計算。
	LoginName string
	// DisplayName 為顯示名稱（不承擔唯一性）。
	DisplayName string
	// InitialPassword 為操作者親自交的一次性初始口令明文。
	// 它只在本次調用期間短暫停留：派生成雜湊後即不再被引用，
	// 不進回應、日誌、審計或任何錯誤訊息。
	InitialPassword string
}

// CreatedAccount 是一次成功建立的結果，全部為可展示的事實（不含任何憑據材料）。
type CreatedAccount struct {
	// AccountID 為新帳戶的穩定標識——建立成功即得到它，與是否加入任何活動無關。
	AccountID idgen.ID
	// LoginName 為登入名原始寫法。
	LoginName string
	// DisplayName 為顯示名稱。
	DisplayName string
	// Status 為帳戶狀態（建立成功必為 active）。
	Status account.Status
	// MustChangePassword 為首次登入是否必須改密（本用例恆為 true）。
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
	// Grants 是伺服器級授予倉儲。目錄與詳情問「他是不是隻有普通帳戶這一層身份」時，
	// 這句話的權威只在這裡——展示投影負責列出、授予倉儲負責答覆，兩處不各寫一套。
	Grants *grant.Store
	// Policy 是帳戶建立策略倉儲。放不放行問的是 acctpolicy，不自己查那張表——
	// 策略的解讀規則（含「策略值不等於能力」的合成）必須只有那一個來源。
	Policy *acctpolicy.Store
	// Sessions 是會話倉儲，在停用與重置這兩條通路上有作用：狀態寫入、憑據換新與
	// 目標全部會話的撤銷必須落在同一個交易裡，否則「停用」就只剩一句「他下次登入會被拒」、
	// 「重置」就只剩一句「他舊口令登不進了」，而他手上那些還活著的裝置一個都沒被處理。
	// 綁定執行走的是同一個手段（來源訪戶的會話與綁定同交易撤銷）。
	Sessions *session.Store
	// Audits 是 Root 域審計倉儲（管理員的伺服器級動作也落在這張表，actor 為 admin）。
	Audits *audit.Store
	// BindTickets 是綁定介質倉儲（短期單次操作憑證與不可變綁定留痕，見 internal/guestbind）：
	// 簽發、核銷預覽、核銷執行與本人查詢四條通路都經它碰到那兩張表，
	// 本套件自己不抄那兩張表的 SQL。
	BindTickets *guestbind.Store
	// Clock 是注入時鐘（nil 時取 timeutil.System）：綁定憑證的失效時刻與
	// 「這枚憑證此刻還用不用得上」的判定都以它為依據，不接受請求側交來的時刻。
	Clock timeutil.Clock
	// Hashing 是當前參數檔（與登入、Root 初始化、開設管理員同一來源）。
	Hashing credential.Params
	// Log 為伺服器端記錄出口；nil 時丟棄。
	Log *slog.Logger
}

// Service 是普通帳戶用例（建立、目錄、詳情、資料編輯與登入狀態）的編排者。零值不可用，請經 New 取得。
type Service struct {
	db          *database.DB
	accounts    *account.Store
	grants      *grant.Store
	policy      *acctpolicy.Store
	sessions    *session.Store
	audits      *audit.Store
	bindTickets *guestbind.Store
	clock       timeutil.Clock
	hashing     credential.Params
	log         *slog.Logger
}

// New 校驗依賴並建立服務。
//
// 缺任何一個依賴都是組裝缺陷，在啟動階段當場報出：少策略倉儲就問不到「此刻准不准建」，
// 等於默認放行；少授予倉儲就分不清目錄裡誰是管理員（要嘛把管理員列進普通帳戶目錄、
// 要嘛把普通帳戶誤判成出局）；少會話倉儲就會落出「狀態改了、舊裝置還活著」的半套停用或半套重置；
// 少審計倉儲就建出或改出一個不留痕的伺服器級主體變更——
// 後三者正是審計要防的那件事。少綁定介質倉儲則四條綁定通路一條也走不了：
// 憑證讀不到、核銷不掉、留痕也追加不了，而「半套綁定」比綁不了更糟。
func New(deps Deps) (*Service, error) {
	if deps.DB == nil || deps.Accounts == nil || deps.Grants == nil ||
		deps.Policy == nil || deps.Sessions == nil || deps.Audits == nil ||
		deps.BindTickets == nil {
		return nil, errors.New("stdacct: 用例缺少必要依賴（db/accounts/grants/policy/sessions/audits/bindTickets）")
	}
	if err := deps.Hashing.Validate(); err != nil {
		return nil, fmt.Errorf("stdacct: 憑據雜湊參數檔不合格: %w", err)
	}
	clock := deps.Clock
	if clock == nil {
		clock = timeutil.System()
	}
	logger := deps.Log
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		db:          deps.DB,
		accounts:    deps.Accounts,
		grants:      deps.Grants,
		policy:      deps.Policy,
		sessions:    deps.Sessions,
		audits:      deps.Audits,
		bindTickets: deps.BindTickets,
		clock:       clock,
		hashing:     deps.Hashing,
		log:         logger,
	}, nil
}

// CreateStandardAccount 以持有伺服器級管理權的受信主體建立一個普通帳戶。
//
// 順序與每一跳的理由：
//  1. 授權先於一切：identity.Authorize(principal, NeedServerAdmin)。匿名、普通帳戶
//     與系統主體在這裡就結束，不消耗任何派生、不碰資料庫、不寫審計。
//     principal 只能來自「本次請求的憑據換出的受信主體」，請求裡沒有任何欄位能自報角色；
//  2. 口令派生放在交易之外：Argon2id 按生產參數檔是數百毫秒級的計算，
//     把它放進交易等於讓單寫入鎖在整個派生期間被佔住。
//     派生失敗（空口令、超長口令）在此回輸入錯誤，一條寫入都沒有發生；
//  3. 交易內現讀策略並問 AllowsAdminCreateStandard：判定依據必須是「寫入那一刻」的現值，
//     所以在同一筆 *database.Tx 裡讀——讀到關就回 ErrCreateDisabled，
//     這筆交易一個字都沒寫過，回滾是空操作；
//  4. 放行後依序寫入帳戶與 Root 域審計：任何一跳失敗，整筆回滾，
//     不會出現「帳戶建好了而 Root 域查不到是誰建的」；
//  5. 重複提交與併發在同一個地方收口：登入名的正規化鍵上有 UNIQUE 索引，
//     後到的那筆拿到 ErrDuplicateLogin。本方法因此不需要（也不該）先查再插。
//
// 失敗的審計口徑與既有合同同形：被拒的建立（權限不足、策略未開放、登入名已佔用、
// 口令形狀不合格）一律不追加審計——拒絕的結論不該成為寫入放大器；
// 那次嘗試的來源、時刻與關聯 ID 在執行日誌與訪問日誌裡都有。
func (s *Service) CreateStandardAccount(ctx context.Context, principal identity.Principal,
	in CreateInput, requestID string) (CreatedAccount, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		s.log.Warn("建立普通帳戶被拒：主體不具備伺服器級管理權",
			"subject", principal.String(), "request_id", requestID)
		return CreatedAccount{}, err
	}

	passwordHash, err := credential.Hash(in.InitialPassword, s.hashing)
	if err != nil {
		var hashErr *credential.HashError
		if errors.As(err, &hashErr) {
			// 可展示的原因（空口令／超長）進結論；訊息本身不含任何口令材料。
			return CreatedAccount{}, fmt.Errorf("%w: %v", ErrInvalidInitialPassword, hashErr.Reason)
		}
		return CreatedAccount{}, fmt.Errorf("stdacct: 產生憑據雜湊失敗: %w", err)
	}

	var created CreatedAccount
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		policy, err := s.policy.Get(tctx, tx)
		if err != nil {
			return err
		}
		if !policy.AllowsAdminCreateStandard() {
			return ErrCreateDisabled
		}
		a, err := s.accounts.Create(tctx, tx, account.NewInput{
			LoginName:          in.LoginName,
			DisplayName:        in.DisplayName,
			PasswordHash:       passwordHash,
			Type:               account.TypeStandard,
			Status:             account.StatusActive,
			MustChangePassword: true,
		})
		if err != nil {
			return err
		}
		rec, err := s.creationRecord(principal, a, requestID)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		created = CreatedAccount{
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
		if errors.Is(err, ErrCreateDisabled) {
			s.log.Warn("建立普通帳戶被拒：帳戶建立策略未開放", "request_id", requestID)
			return CreatedAccount{}, err
		}
		if errors.Is(err, account.ErrDuplicateLogin) {
			// 業務衝突：不是故障，不報 5xx，也不寫審計（見方法註解）。
			s.log.Warn("建立普通帳戶被拒：登入名已被佔用", "request_id", requestID)
			return CreatedAccount{}, fmt.Errorf("%w（%v）", ErrDuplicateLogin, err)
		}
		// 帳戶域的校驗錯誤（登入名／顯示名不合規）原樣上報：它的訊息可安全展示，
		// 點出的是請求本體哪個欄位不合規，與憑據無關。
		if errors.Is(err, account.ErrInvalidLogin) || errors.Is(err, account.ErrInvalidDisplayName) {
			s.log.Warn("建立普通帳戶被拒：輸入不合領域規則", "request_id", requestID, "err", err)
			return CreatedAccount{}, err
		}
		if errors.Is(err, acctpolicy.ErrNoPolicyRow) {
			// 結構缺陷：單例策略行讀不到。原樣上拋讓交易回滾，不猜成關也不猜成開。
			s.log.Error("建立普通帳戶的策略讀取失敗", "request_id", requestID, "err", err)
			return CreatedAccount{}, err
		}
		s.log.Error("建立普通帳戶落地失敗", "request_id", requestID, "err", err)
		return CreatedAccount{}, fmt.Errorf("stdacct: 建立普通帳戶失敗: %w", err)
	}

	s.log.Info("已建立普通帳戶",
		"account", created.AccountID.String(), "request_id", requestID)
	return created, nil
}

// creationRecord 產生一筆 Root 域的建號審計，操作者是真實的那位管理員。
//
// actor 一律經 principal.AuditActor() 換得（不是手拼 audit.Actor）：那是「受信上下文 →
// 審計」的唯一通路。對持有 server_admin 的帳戶它換得 ActorAdmin＋帳戶標識——
// 既不冒充 Root，也不降級成 system。換不出操作者時回錯誤讓整筆建立回滾：
// 一個查不到是誰建的帳戶，比建不出帳戶更糟。
//
// ScopeRoot 而不捏造 activity_id：建號是伺服器級動作，不屬於任何活動；
// internal/audit 的校驗在兩個方向都把它釘死（root 記錄不得帶 activity_id、
// activity 記錄必須帶）。
//
// 絕不落進記錄的東西：初始口令明文、Argon2id 雜湊、任何錯誤鏈原文。
// changes 只有可展示的身分欄位，且刻意不帶任何 password 字樣的鍵，
// 讓「審計表裡沒有一個欄位可能含口令」成立在結構上，而不是成立在遮罩會幫忙的期待上。
// 「不帶 server_roles」也是結構性的：本用例建的帳戶恆無授予，審計不記一件不存在的事。
func (s *Service) creationRecord(principal identity.Principal, a account.Account,
	requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("stdacct: 主體無法換得審計操作者: %w", err)
	}
	return audit.Record{
		Scope:     audit.ScopeRoot,
		Actor:     actor,
		Action:    "account.create_standard",
		Target:    audit.Target{Kind: "account", ID: a.ID.String()},
		Reason:    "伺服器級管理員經已認證會話建立普通帳戶（策略開關現讀放行），首次登入須改密",
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "login_name", Before: nil, After: a.LoginName},
			{Field: "display_name", Before: nil, After: a.DisplayName},
			{Field: "account_type", Before: nil, After: a.Type.String()},
			{Field: "status", Before: nil, After: a.Status.String()},
			{Field: "must_change_password", Before: nil, After: true},
		},
	}, nil
}

// trimRequestID 保證關聯 ID 不超過審計欄位上限（與 internal/adminacct 同口徑）。
func trimRequestID(requestID string) string {
	if r := []rune(requestID); len(r) > 64 {
		return string(r[:64])
	}
	return requestID
}
