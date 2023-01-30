// service.go 是帳戶建立策略的應用服務層：Root 現讀策略、Root 改策略（同交易落審計）、
// 以及給登入前界面的對外入口答案。
//
// 為什麼現讀而不是裝配時算好一份放記憶體：
//
//	策略是一個可以在任何一刻被改掉的決定，而「這條請求放行嗎」問的是此刻的值。
//	快取一份舊值就會出現「Root 已關掉自註冊，而之後三秒內的請求仍按舊值放行」這種
//	需要解釋的窗口；SQLite 的單寫入者讓現讀的成本只有一行 SELECT，
//	沒有理由用一個多餘的結構去換。
//
// 三個入口的授權形態各不相同，而且各對其用途：
//   - Policy（讀策略）與 UpdatePolicy（改策略）都要 Root：前者會把模式與開關講出來，
//     後者是變更伺服器准入；判定都只經 identity.Authorize(principal, identity.NeedRoot)，
//     普通管理員與匿名在這一層就結束，不碰資料庫、不寫審計。
//   - Entry（對外入口答案）沒有主體：它是給站在門外的人看的，因此它只能回答
//     「這兩個入口開不開」（見 EntryOf），讀不到策略時照實回錯誤，
//     由傳輸層換成一句通用失敗——不降級成「全開」，也不降級成「全關但假裝是 Root 的決定」。
//
// 失敗的審計口徑與既有合同同形：被拒的讀寫（非 Root、模式不認識、模式尚未開放）
// 一律不追加審計，理由是「拒絕的結論不該成為任何能碰到這個端點的來源的寫入放大器」；
// 那次嘗試的來源、時刻與關聯 ID 在訪問日誌與執行日誌裡都有。
//
// 刻意沒有的東西：依據值（CAS 錨點）。這是一份單例文件，能改它的只有 Root 一個主體，
// 而一次提交交的是完整的三個值——「兩個人對著同一份畫面先後改」在這裡的形態是
// 後寫的那份成為現值，這正是整份文件PUT 的語意。重複保存同樣不是錯誤而是「又確認一次」
// （與 R2-004 的憑據重置同一取向），所以界面不得自動補發。
package acctpolicy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
)

// Input 是一次策略變更的領域輸入。
//
// SelfRegisterMode 刻意是原始字串而不是 Mode：傳輸層交來的是請求本體裡的文字，
// 「不認識這個名字」（ErrUnknownMode）與「認識但它尚未開放」（ErrModeUnavailable）
// 是兩句必須分開的話，而轉換成 Mode 型別的那一步正是分岔點。
// 沒有依據值、也沒有原因文本：後者的措辭屬服務端固定敘述，不讓任何主體往審計裡寫任意文字。
type Input struct {
	// AdminCreateStandard 是「管理員可建立普通帳戶」的目標值。
	AdminCreateStandard bool
	// SelfRegisterMode 是自註冊模式的目標值（原始寫法，逐字比對四個已批准名字）。
	SelfRegisterMode string
	// GuestEnabled 是「可建立訪客（臨時）帳戶」的目標值。
	GuestEnabled bool
}

// Deps 是本用例的外部依賴，全部由裝配層（internal/app）注入。
type Deps struct {
	// DB 提供交易邊界與 autocommit 查詢。
	DB *database.DB
	// Store 是策略倉儲；nil 時由 New 以系統時鐘建一個，裝配層若要注入測試時鐘就自己傳。
	Store *Store
	// Audits 是 Root 域審計倉儲。缺它就開出一個「改了伺服器准入卻查不到是誰改的」的
	// 特權變更，正是審計要防的那件事，因此 New 把它列為必要依賴。
	Audits *audit.Store
	// Log 為伺服器端記錄出口；nil 時丟棄。
	Log *slog.Logger
}

// Service 是策略用例的編排者。零值不可用，請經 New 取得。
type Service struct {
	db     *database.DB
	store  *Store
	audits *audit.Store
	log    *slog.Logger
}

// New 校驗依賴並建立服務。
//
// 少任何一個依賴都是組裝缺陷，在啟動階段當場報出：少倉儲就讀不到策略，
// 少審計倉儲就會改動准入而不留痕。
func New(deps Deps) (*Service, error) {
	if deps.DB == nil || deps.Audits == nil {
		return nil, errors.New("acctpolicy: 用例缺少必要依賴（db/audits）")
	}
	store := deps.Store
	if store == nil {
		store = NewStore(nil)
	}
	logger := deps.Log
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{db: deps.DB, store: store, audits: deps.Audits, log: logger}, nil
}

// Policy 以當前受信主體現讀生效中的帳戶建立策略。
//
// 授權先於查詢：非 Root 的主體不該多得到一次資料庫讀取，也不該從回應形狀或延遲
// 差異裡推出「這份策略存在與否」。
func (s *Service) Policy(ctx context.Context, principal identity.Principal) (Policy, error) {
	if err := s.requireRoot(principal, ""); err != nil {
		return Policy{}, err
	}
	return s.store.Get(ctx, s.db.SQL())
}

// Entry 回報登入前界面需要的最小對外入口答案（無需主體）。
//
// 它只經策略現讀與通路登記合成（EntryOf），除兩個布林之外不帶任何資料：
// 模式名字、updated_at、管理員建號開關、名額與閾值都在這一層之外，
// 而「三條通路存在與否」是本版本的形態事實、不是這個部署的狀態，因此也不在這裡。
// 讀不到策略時回錯誤：這個入口的失敗形態只能是「查不出來」，
// 絕不能是憑空猜出的一組布林。
func (s *Service) Entry(ctx context.Context) (EntryCapabilities, error) {
	policy, err := s.store.Get(ctx, s.db.SQL())
	if err != nil {
		return EntryCapabilities{}, err
	}
	return policy.EntryOf(), nil
}

// UpdatePolicy 以 Root 主體一次寫入三個值，並在同一個交易裡追加一筆 Root 域審計。
//
// 順序與每一跳的理由：
//  1. 授權與輸入復核在交易外：被拒的請求一個查詢都不該多花，
//     而「模式名字不認識」與「尚未開放」兩者都發生在任何寫入之前；
//  2. 交易內先讀現值（同一筆交易，因此前後值是同一個快照上的兩件事實），
//     再 UPDATE 單例行，最後落審計：任何一跳失敗整筆回滾，
//     不會出現「准入改了而 Root 域查不到」或「審計說改過了而表裡還是舊值」；
//  3. 回傳的是重讀後的資料庫現值，不是呼叫端的意圖回音——界面要講的是「伺服器現在是什麼」。
//
// 三個值一次寫入、彼此獨立：本次沒變的欄位照樣以同一條 UPDATE 寫回同一個值，
// 這不會讓它「被順便改動」，因為寫入的值就是它現值；
// 「只關掉自註冊而訪客照常開放」因此不需要一整套部分欄位協議。
func (s *Service) UpdatePolicy(ctx context.Context, principal identity.Principal,
	in Input, requestID string) (Policy, error) {
	if err := s.requireRoot(principal, requestID); err != nil {
		return Policy{}, err
	}
	mode, err := ParseMode(in.SelfRegisterMode)
	if err != nil {
		s.log.Warn("變更帳戶建立策略被拒：模式字串不被承認", "request_id", requestID)
		return Policy{}, err
	}
	if !mode.writable() {
		s.log.Warn("變更帳戶建立策略被拒：該模式在本版本尚未開放",
			"mode", mode.String(), "request_id", requestID)
		return Policy{}, fmt.Errorf("%w：%s", ErrModeUnavailable, mode.String())
	}
	next := Policy{
		AdminCreateStandard: in.AdminCreateStandard,
		SelfRegisterMode:    mode,
		GuestEnabled:        in.GuestEnabled,
	}

	var updated Policy
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		before, err := s.store.Get(tctx, tx)
		if err != nil {
			return err
		}
		stored, err := s.store.Put(tctx, tx, next)
		if err != nil {
			return err
		}
		rec, err := s.changeRecord(principal, before, stored, requestID)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		updated = stored
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrNoPolicyRow), errors.Is(err, ErrUnknownMode),
			errors.Is(err, ErrModeUnavailable), errors.Is(err, ErrPermissionDenied):
			return Policy{}, err
		}
		s.log.Error("變更帳戶建立策略失敗", "request_id", requestID, "err", err)
		return Policy{}, fmt.Errorf("acctpolicy: 變更帳戶建立策略失敗: %w", err)
	}
	s.log.Info("Root 已變更帳戶建立策略",
		"admin_create_standard", updated.AdminCreateStandard,
		"self_register_mode", updated.SelfRegisterMode.String(),
		"guest_enabled", updated.GuestEnabled, "request_id", requestID)
	return updated, nil
}

// requireRoot 把「只有 Root 能碰這份策略」收在一處：判定只經 identity.Authorize。
//
// 被拒時記一句 Warn（含主體的脫敏表示與關聯 ID），但絕不記任何策略值或請求本體內容：
// 一個非 Root 的嘗試在日誌裡需要被看見，不需要被複述。
func (s *Service) requireRoot(principal identity.Principal, requestID string) error {
	if err := identity.Authorize(principal, identity.NeedRoot); err != nil {
		s.log.Warn("帳戶建立策略操作被拒：主體不具備 Root 權限",
			"subject", principal.String(), "request_id", requestID)
		return err
	}
	return nil
}

// changeRecord 產生一筆 Root 域的策略變更審計。口徑與 adminacct 各用例同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆變更回滾。
//
// Changes 只展開真正有差的欄位：一份三次都要寫的策略文件，如果每次都記三對值，
// 日後查的人無法從審計裡看出「哪一次其實是重複按下」；沒有一欄變動時 Changes 為空，
// 那筆記錄說的是「Root 又確認了一次這份策略」，這正是它事實上的內容。
//
// 絕不落進記錄的東西：任何帳戶標識、口令、憑據雜湊、會話材料，以及三個值之外的策略細節
// （本表也只有這三個值，沒有可漏的其他欄位）。
func (s *Service) changeRecord(principal identity.Principal, before, after Policy,
	requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("acctpolicy: 主體無法換得審計操作者: %w", err)
	}
	var changes []audit.Change
	if before.AdminCreateStandard != after.AdminCreateStandard {
		changes = append(changes, audit.Change{
			Field: "admin_create_standard", Before: before.AdminCreateStandard, After: after.AdminCreateStandard})
	}
	if before.SelfRegisterMode != after.SelfRegisterMode {
		changes = append(changes, audit.Change{
			Field: "self_register_mode", Before: before.SelfRegisterMode.String(),
			After: after.SelfRegisterMode.String()})
	}
	if before.GuestEnabled != after.GuestEnabled {
		changes = append(changes, audit.Change{
			Field: "guest_enabled", Before: before.GuestEnabled, After: after.GuestEnabled})
	}
	return audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  actor,
		Action: "server.account_policy_update",
		// 單例文件沒有可標識的對象：Target.ID 留空字串（表裡換成 NULL），
		// 語意是「本來就沒有這一個東西的標識」，不是「查不到」。
		Target:    audit.Target{Kind: "account_creation_policy"},
		Reason:    "Root 經已認證會話變更伺服器級帳戶建立策略：三個建立入口的值以本記錄前後值為準（策略值不等於通路已實作，放行與否另由能力登記合成）",
		RequestID: trimRequestID(requestID),
		Changes:   changes,
	}, nil
}

// trimRequestID 把關聯 ID 壓進審計表的長度上限（與 internal/adminacct 同口徑）。
//
// 正常 ID 是 36 字元的 UUIDv7，這道修剪永遠不該生效；它擋的是呼叫端把自由文字
// 塞進這個參數的那條路——修剪讓寫入成功，而超長在 audit 層會直接讓整筆交易回滾。
func trimRequestID(requestID string) string {
	if r := []rune(requestID); len(r) > 64 {
		return string(r[:64])
	}
	return requestID
}
