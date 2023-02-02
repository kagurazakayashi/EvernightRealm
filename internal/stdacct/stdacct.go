// Package stdacct 是「伺服器級管理員建立普通帳戶」的應用服務層：
// 受信主體判定 → 策略現讀 → 憑據派生 → 帳戶建立與審計落地的原子用例。
//
// 為什麼獨立成一個套件而不是放進 internal/adminacct 或 internal/account：
//   - adminacct 回答的是「Root 如何打理管理員目錄」，每一個用例的授權邊界都是 NeedRoot，
//     且建出的形態恆帶 server_admin 授予；本套件的授權邊界是 NeedServerAdmin，
//     建出的形態恆「不帶任何伺服器級角色」——把兩者混進一個套件，
//     「誰能建哪一類人」就要靠同一個 Service 上的分支來記，那是兩套邊界最容易互相污染的形状；
//   - account 是帳戶實體與其倉儲（「一筆帳戶資料長什麼樣」），而「此刻准不准多出一筆帳戶」
//     是使用帳戶的規則，屬策略與授權，不屬實體；
//   - 依賴方向因此保持單向：stdacct → acctpolicy（策略現讀與放行合成）、
//     account（實體與唯一鍵）、audit（落地痕跡）、credential／database／identity。
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
// 初始口令的交付語意沿用 Root 開設管理員時用戶批准的形態：交入口的一次性口令、
// must_change_password=1 落庫、伺服端不生成口令、不在任何回應裡回顯、不設默認口令。
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
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
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
	// Policy 是帳戶建立策略倉儲。放不放行問的是 acctpolicy，不自己查那張表——
	// 策略的解讀規則（含「策略值不等於能力」的合成）必須只有那一個來源。
	Policy *acctpolicy.Store
	// Audits 是 Root 域審計倉儲（管理員的伺服器級動作也落在這張表，actor 為 admin）。
	Audits *audit.Store
	// Hashing 是當前參數檔（與登入、Root 初始化、開設管理員同一來源）。
	Hashing credential.Params
	// Log 為伺服器端記錄出口；nil 時丟棄。
	Log *slog.Logger
}

// Service 是建立普通帳戶用例的編排者。零值不可用，請經 New 取得。
type Service struct {
	db       *database.DB
	accounts *account.Store
	policy   *acctpolicy.Store
	audits   *audit.Store
	hashing  credential.Params
	log      *slog.Logger
}

// New 校驗依賴並建立服務。
//
// 缺任何一個依賴都是組裝缺陷，在啟動階段當場報出：少策略倉儲就問不到「此刻准不准建」，
// 等於默認放行；少審計倉儲就建出一個不留痕的伺服器級主體變更——後者正是審計要防的那件事。
func New(deps Deps) (*Service, error) {
	if deps.DB == nil || deps.Accounts == nil || deps.Policy == nil || deps.Audits == nil {
		return nil, errors.New("stdacct: 用例缺少必要依賴（db/accounts/policy/audits）")
	}
	if err := deps.Hashing.Validate(); err != nil {
		return nil, fmt.Errorf("stdacct: 憑據雜湊參數檔不合格: %w", err)
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
		hashing:  deps.Hashing,
		log:      logger,
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
