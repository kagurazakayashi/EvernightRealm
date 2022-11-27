// Package adminacct 是「Root 對伺服器級管理員帳戶的目錄性操作」的應用服務層：
// 開設（憑據派生 → 帳戶建立 → 角色授予 → 審計落地的原子用例）、
// 目錄分頁與單筆詳情、非安全資料（顯示名）的白名單編輯。
//
// 為什麼獨立成一個套件而不是放進 internal/auth：auth 回答的是「憑據換身份、身份換會話」，
// 本套件回答的是「一個可登入主體如何被創造、被查到、被改名字」。兩者共用的只有
// internal/credential 這一套派生規則與 internal/identity 的主體形態，
// 混在一个套件裡會讓「登入不假裝會建號、建號不假裝會登入」這條邊界模糊。
//
// 三條不可讓步的規定：
//   - 只有 Root 能碰這些用例。判定經 identity.Authorize(principal, identity.NeedRoot)，
//     而 NeedRoot 只放過 Root 主體：持 server_admin 的帳戶过不去（見 internal/identity/authorize.go）。
//     「普通管理员能不能管理同级管理员」因此不是产品约定，而是唯一的判定入口；
//   - 請求裡的任何角色/類型宣稱都不生效。開設的輸入只有登入名、顯示名與初始口令，
//     編輯的輸入只有顯示名與它所依據的現值，「動的是哪一類資料」由「調用的是哪一個用例」
//     決定，沒有任何欄位可以讓呼叫端自報；identity.ServerGrants 的欄位不匯出，
//     請求本體也填不進去；
//   - 寫入與審計落在同一個交易。同生同滅：一個被授予了角色卻查不到的帳戶、
//     或一次真實存在卻在 Root 審計裡查不到的改名，都是不可解釋的半成品。
//
// 憑據一律經 internal/credential 以裝配層注入的當前參數檔派生（與登入、Root 初始化、
// 本人改密同一個實作點），本套件不另寫一套口令規則，也不落庫、不回傳任何口令明文。
//
// 初始口令的交付語意（用戶批准）：Root 在開設時親自交一個一次性口令，帳戶帶著
// must_change_password=1 落庫，首次登入必須改密（消費端與服務端門閂見 internal/httpapi
// 的 requirePasswordChangeDone 與 R1-019 的 2010）。伺服端不生成口令、不在任何回應裡
// 回顯口令，也不設任何默認口令——「默認口令」等於把同一把門鑰分給所有實例。
package adminacct

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// 對外可判別的結論錯誤：傳輸層據此分流回應，內部故障一律不進這些型別。
var (
	// ErrDuplicateLogin 表示登入名的正規化鍵已被佔用。
	//
	// 它是可預期的業務衝突，不是缺陷：重複提交、與併發的另一次開設撞上同一個鍵，
	// 都收斂到這裡。正確性來自資料庫唯一索引（見 internal/account 與遷移 0003），
	// 「先查再插」從來不是正確性來源，只是較早給出友善錯誤的手段。
	ErrDuplicateLogin = errors.New("adminacct: 登入名已被佔用")
	// ErrInvalidInitialPassword 表示初始口令不滿足憑據模組的形狀界線（空或超長）。
	// 它是請求本體的問題，屬呼叫端可修正的輸入錯誤。
	ErrInvalidInitialPassword = errors.New("adminacct: 初始口令不滿足憑據形狀界線")
	// ErrPermissionDenied 沿用 identity 的判定結論：身分可信但沒有這個權限。
	// 單獨透出只為一件事——傳輸層要能把它報成「權限不足」而不是「未登入」。
	ErrPermissionDenied = identity.ErrPermissionDenied
)

// CreateInput 是開設一個管理員帳戶所需的領域輸入。
//
// 沒有任何角色、帳戶類型或狀態欄位：本用例建的就是「standard ＋ active ＋ server_admin ＋
// 首次必改密」這一種形態，且由端點形態而不是請求欄位決定。
type CreateInput struct {
	// LoginName 為登入名原始寫法；正規化唯一鍵由帳戶域層計算。
	LoginName string
	// DisplayName 為顯示名稱（不承擔唯一性）。
	DisplayName string
	// InitialPassword 為 Root 親自交的一次性初始口令明文。
	// 它只在本次調用期間短暫停留：派生成雜湊後即不再被引用，
	// 不進回應、日誌、審計或任何錯誤訊息。
	InitialPassword string
}

// CreatedAdmin 是一次成功開設的結果，全部為可展示的事實（不含任何憑據材料）。
type CreatedAdmin struct {
	// AccountID 為新帳戶的穩定標識。
	AccountID idgen.ID
	// LoginName 為登入名原始寫法。
	LoginName string
	// DisplayName 為顯示名稱。
	DisplayName string
	// Status 為帳戶狀態（開設成功必為 active）。
	Status account.Status
	// MustChangePassword 為首次登入是否必須改密（本用例恆為 true）。
	MustChangePassword bool
	// Roles 為該帳戶持有的伺服器級角色。
	Roles []identity.Role
	// CreatedAt 為建立時刻（UTC，取自注入時鐘）。
	CreatedAt time.Time
}

// Deps 是本用例的外部依賴，全部由裝配層（internal/app）注入。
type Deps struct {
	// DB 提供交易邊界與 autocommit 查詢。
	DB *database.DB
	// Accounts 是帳戶倉儲。
	Accounts *account.Store
	// Grants 是伺服器級角色授予倉儲。
	Grants *grant.Store
	// Audits 是 Root 域審計倉儲。
	Audits *audit.Store
	// Hashing 是當前參數檔（與登入、Root 初始化同一來源）。
	Hashing credential.Params
	// Log 為伺服器端記錄出口；nil 時丟棄。
	Log *slog.Logger
}

// Service 是開設用例的編排者。零值不可用，請經 New 取得。
type Service struct {
	db       *database.DB
	accounts *account.Store
	grants   *grant.Store
	audits   *audit.Store
	hashing  credential.Params
	log      *slog.Logger
}

// New 校驗依賴並建立服務。
//
// 缺任何一個依賴都是組裝缺陷，在啟動階段當場報出：少授予倉儲就開不出「有角色的人」，
// 少審計倉儲就開出一個不留痕的特權變更——後者正是審計要防的那件事。
func New(deps Deps) (*Service, error) {
	if deps.DB == nil || deps.Accounts == nil || deps.Grants == nil || deps.Audits == nil {
		return nil, errors.New("adminacct: 開設用例缺少必要依賴（db/accounts/grants/audits）")
	}
	if err := deps.Hashing.Validate(); err != nil {
		return nil, fmt.Errorf("adminacct: 憑據雜湊參數檔不合格: %w", err)
	}
	logger := deps.Log
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		db:       deps.DB,
		accounts: deps.Accounts,
		grants:   deps.Grants,
		audits:   deps.Audits,
		hashing:  deps.Hashing,
		log:      logger,
	}, nil
}

// CreateAdmin 以 Root 主體開設一個持有伺服器級管理員角色的新帳戶。
//
// 順序與每一跳的理由：
//  1. 授權先於一切：identity.Authorize(principal, NeedRoot)。普通帳戶與系統主體
//     在這裡就結束，不消耗任何派生、不碰資料庫、不寫審計。
//     principal 只能來自「本次請求的憑據換出的受信主體」，請求裡没有任何欄位能填出 Root；
//  2. 口令派生放在交易之外：Argon2id 按生產參數檔是數百毫秒級的計算，
//     把它放進交易等於讓單寫入鎖在整个派生期間被占住——一次慢派生不該讓全服停筆。
//     派生失敗（空口令、超長口令）在此回輸入錯誤，一条寫入都沒有發生；
//  3. 交易內依序寫入帳戶、授予、Root 域審計：任何一跳失敗，整筆回滾，
//     不會出現「帳戶建好了但沒被授予角色」（那個人將以普通帳戶身分登入）
//     或「審計说有这个人而資料庫裡查不到」；
//  4. 重複提交與併發在同一個地方收口：登入名的正規化鍵上有 UNIQUE 索引，
//     後到的那筆拿到 ErrDuplicateLogin。本方法因此不需要（也不該）先查再插——
//     查插之間的時間窗正是重複帳戶的來源。
//
// 失敗的審計口徑：被拒的開設（權限不足、登入名已佔用、口令形狀不合格）一律不追加審計。
// 這與既有合同同形：被拒的輪換、被拒的裝置撤銷都不寫審計，理由是「拒絕的結論不該成為
// 任何能碰到這個端點的來源的寫入放大器」。至於「Root 該不該知道有人试过」——
// 那次嘗試的來源、時刻與關聯 ID 在執行日誌與訪問日誌裡都有，無需把它記成一筆長期事實。
func (s *Service) CreateAdmin(ctx context.Context, principal identity.Principal,
	in CreateInput, requestID string) (CreatedAdmin, error) {
	if err := identity.Authorize(principal, identity.NeedRoot); err != nil {
		s.log.Warn("開設管理員被拒：主體不具备 Root 權限",
			"subject", principal.String(), "request_id", requestID)
		return CreatedAdmin{}, err
	}

	passwordHash, err := credential.Hash(in.InitialPassword, s.hashing)
	if err != nil {
		var hashErr *credential.HashError
		if errors.As(err, &hashErr) {
			// 可展示的原因（空口令／超長）進結論；訊息本身不含任何口令材料。
			return CreatedAdmin{}, fmt.Errorf("%w: %v", ErrInvalidInitialPassword, hashErr.Reason)
		}
		return CreatedAdmin{}, fmt.Errorf("adminacct: 產生憑據雜湊失敗: %w", err)
	}

	var created CreatedAdmin
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
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
		if err := s.grants.Grant(tctx, tx, a.ID, identity.RoleServerAdmin); err != nil {
			return err
		}
		rec, err := s.creationRecord(principal, a, requestID)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		created = CreatedAdmin{
			AccountID:          a.ID,
			LoginName:          a.LoginName,
			DisplayName:        a.DisplayName,
			Status:             a.Status,
			MustChangePassword: a.MustChangePassword,
			Roles:              []identity.Role{identity.RoleServerAdmin},
			CreatedAt:          a.CreatedAt,
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, account.ErrDuplicateLogin) {
			// 業務衝突：不是故障，不報 5xx，也不寫審計（見方法註解）。
			s.log.Warn("開設管理員被拒：登入名已被佔用", "request_id", requestID)
			return CreatedAdmin{}, fmt.Errorf("%w（%v）", ErrDuplicateLogin, err)
		}
		// 帳戶域的校驗錯誤（登入名／顯示名不合規）原樣上報：它的訊息可安全展示，
		// 點出的是請求本體哪個欄位不合規，與憑據無關。
		if errors.Is(err, account.ErrInvalidLogin) || errors.Is(err, account.ErrInvalidDisplayName) {
			s.log.Warn("開設管理員被拒：輸入不合領域規則", "request_id", requestID, "err", err)
			return CreatedAdmin{}, err
		}
		s.log.Error("開設管理員落地失敗", "request_id", requestID, "err", err)
		return CreatedAdmin{}, fmt.Errorf("adminacct: 開設管理員失敗: %w", err)
	}

	s.log.Info("Root 已開設伺服器級管理員帳戶",
		"account", created.AccountID.String(), "request_id", requestID)
	return created, nil
}

// creationRecord 產生一筆 Root 域的開設審計。
//
// actor 一律經 principal.AuditActor() 換得（不是手拼 audit.Actor）：那是「受信上下文 →
// 審計」的唯一通路，Kind 可被呼叫端隨意填寫的審計等於沒有審計。換不出操作者時
// 回錯誤讓整筆開設回滾——不留痕的特權變更不該被當成成功，也不該被降級記成 system。
//
// 絕不落進記錄的東西：初始口令明文、Argon2id 雜湊、任何錯誤鏈原文。
// changes 只有可展示的身分欄位，值一律再經 internal/audit 的 §7 遮罩管線與長度閘；
// 這裡刻意不帶任何 password 字樣的鍵，讓「審計表裡沒有一個欄位可能含口令」
// 這句話成立在結構上，而不是成立在「遮罩會幫我擋」的期待上。
func (s *Service) creationRecord(principal identity.Principal, a account.Account,
	requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("adminacct: 主體無法換得審計操作者: %w", err)
	}
	return audit.Record{
		Scope:     audit.ScopeRoot,
		Actor:     actor,
		Action:    "admin.create",
		Target:    audit.Target{Kind: "account", ID: a.ID.String()},
		Reason:    "Root 經已認證會話開設伺服器級管理員帳戶，首次登入須改密",
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "login_name", Before: nil, After: a.LoginName},
			{Field: "display_name", Before: nil, After: a.DisplayName},
			{Field: "account_type", Before: nil, After: a.Type.String()},
			{Field: "status", Before: nil, After: a.Status.String()},
			{Field: "must_change_password", Before: nil, After: true},
			{Field: "server_roles", Before: nil, After: identity.RoleServerAdmin.String()},
		},
	}, nil
}

// trimRequestID 保證關聯 ID 不超過審計欄位上限（與 internal/auth 同名輔助同一規則）。
func trimRequestID(requestID string) string {
	if r := []rune(requestID); len(r) > 64 {
		return string(r[:64])
	}
	return requestID
}
