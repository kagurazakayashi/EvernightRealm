// bindclaim.go 是「目標帳戶本人把一枚綁定憑證換成一次真實綁定」的應用服務層：
// 只读的核銷前預覽、核銷與執行、以及本人查自己已完成綁定的那本帳。
//
// 這裡才是綁定本身。一次成功的執行落地的是四件事的合力，缺一件都是半套：
//   - 憑證核銷：同一筆交易裡把 consumed_at 從 NULL 變成一個時刻，條件釘在
//     「尚未被核銷且尚未到期」上（見 internal/guestbind 的 ConsumeTicket）；
//   - 來源退休：訪戶 X 那一行進入 retired 終態（status 與 retired_at 同一條 UPDATE），
//     行與登入名鍵保留、顯示名不改寫、不新增任何憑據；
//   - 舊會話失效：同交易 RevokeAccount 落庫 revoked_at——X 手上那幾枚臨時憑據
//     不會因為「他後來屬於 Y」就變成能進 Y 家門的令牌，它們被撤銷，如此而已。
//     把源令牌直接變成目標令牌是本步明確禁止的形態，而禁止的形態是 SQL 的形狀：
//     這條通路上沒有一行會去動 sessions 的 token_hash、account_id 或任何身分欄；
//   - 可追溯：留痕表追加一行（來源、目標、憑證、時刻、撤銷數量、同意形態）。
//     它沒有把 X 的歷史改寫成「從來都是 Y」：X 那一行還在、標識還在、
//     既有審計仍指向那個標識；留痕說的恰恰是「這一段先前是 X，此後歸 Y」。
//
// 誰能按這顆按鈕（用戶批准的 R2-018／R2-019 決定）：只有憑證上那個 target_account_id
// 的持有人，以自己的已認證會話。因此這三道通路的主體判定都先於任何查詢：
// 匿名 2002 族、訪戶本人、Root、以及持有伺服器級授予的管理員一律 2011——
// 「管理員代 Y 按下執行」在這一層沒有格子，也不是漏判：那正是被否決過的形態。
// 呼叫端交來的主體標識只有一個來源：principal.AccountID()，即本次憑據換出的那個人。
// 請求本體裡沒有任何「我要以誰的身分綁定」的欄位，因此也就沒有自報即生效的空隙。
//
// 目標的權限不因綁定而擴大，這句話有三個各自獨立的落點：
//   - 這條通路不寫 account_server_roles（一個字都不碰授予表）；
//   - 這條通路不寫目標那一行（UPDATE 清單裡根本沒有 target，見 account.Store.RetireGuestForBind
//     只帶來源標識）；
//   - 目標的憑據、狀態、顯示名與首次改密旗標全部原樣（測試以逐字快照斷言）。
//
// 為什麼本步的執行動作不寫 Root 域審計：操作者是一位普通正式帳戶，而
// internal/identity 的 AuditActor 只認 Root／管理員／系統三類主體——
// 「帳戶本人的伺服器級動作」的審計主體類別今日未批准（玩家與 NPC 是活動內身份，尚未落地）。
// 沿用既有口徑（internal/auth 的本人改密同一取向：普通帳戶不寫審計表，只進執行日誌），
// 而不是為這一步僆造一個 actor、或把 Y 的動作記成管理員簽發那一步的延伸。
// 代償是可追溯性沒有變薄：誰准的（憑證 issued_by 欄＋簽發那筆審計）、
// 誰同意的（留痕行的 consent_mode 與 target_account_id）、什麼時候定的（bound_at）
// 全都在 guest_account_bindings 與 guest_bind_tickets 兩行不可變的資料裡。
//
// 過期計劃不能執行（用戶批准）：核銷前在同一筆交易內重做一遍判定，並把當前事實壓出的
// 摘要與憑證行上釘著的摘要比對。版本變了、兩側任一欄的形態變了、或庫裡多了一張沒接入
// 登記表的帳戶引用表——都是同一句 ErrBindPlanStale（2026）：回去重新預檢並重新簽發。
// 本步不因「預檢說過可行」而放行，也不允許執行端把那句當成憑據。
package stdacct

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/guestbind"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// GuestBindClaimPreview 是核銷前那份只讀預覽：憑證換到的「這一次會做什麼」。
//
// 它的用途是让本人在按下確認之前看見服务端认定的影響與警告，而不是半個執行：
// 這条通路不核銷憑證、不寫一行資料，同一枚憑證可以被它讀任意多次（直到過期或被用掉）。
type GuestBindClaimPreview struct {
	// TicketID 為這枚憑證的穩定標識（可展示；明文本身不在此型別裡）。
	TicketID idgen.ID
	// Plan 為當前事實下重做的完整判定（兩側最小資料、影響清單、源會話數、資料庫版本）。
	// 兩側的現值取自本次讀取，不是簽發時的回音：這正是本人該看見的東西——
	// 「此刻」綁定會發生什麼。
	Plan GuestBindPreflight
	// ExpiresAt 為這枚憑證的失效時刻（界面要能如實說出「还剩多少時間」）。
	ExpiresAt time.Time
}

// GuestBindResult 是一次成功綁定的結果。
type GuestBindResult struct {
	// Binding 為剛追加的那行留痕（含標識與同意形態）。
	Binding guestbind.Binding
	// Source 為來源訪戶退休後經實體校驗的單筆資料（Status 恆為 retired）。
	Source StandardProfile
	// Target 為目標帳戶的單筆資料：綁定不碰它，這一欄是「仍未改變」的正面證據。
	Target StandardProfile
	// RevokedSessions 為這次撤銷的源會話數量：界面據此說出「讓 N 臺裝置重新登入」，
	// 不許自己猜。0 是事實（那一趟訪客可能早已到期），不是失敗。
	RevokedSessions int
}

// GuestBindingItem 是本人那本帳上的一行已完成綁定。
//
// 它是「結果待確認」的落點：一次提交若因為斷線而沒有回應，本人重讀這一頁就知道
// 那次綁定究竟有沒有落地，界面因此可以分成失敗／已完成／結果待確認三種說法，
// 而不是把「我沒收到回應」講成「它沒發生」或「它成功了」。
// 來源以被綁走那一刻的样子展示（不匿名化、不搬歷史），因為這一頁的用途就是歷史解釋。
type GuestBindingItem struct {
	// BindingID 為留痕行的穩定標識。
	BindingID idgen.ID
	// SourceAccountID 為被綁走的訪戶標識（存续身分）。
	SourceAccountID idgen.ID
	// SourceLoginName 為來源訪戶的登入名原始寫法。
	SourceLoginName string
	// SourceDisplayName 為來源訪戶的顯示名（退休不改名）。
	SourceDisplayName string
	// BoundAt 為綁定時刻（與來源行的退休時刻同值）。
	BoundAt time.Time
	// RevokedSessions 為那次動作撤銷的源會話數量。
	RevokedSessions int
	// ConsentMode 為同意形態，恆為 BindConsentModeTargetSelfInitiated。
	ConsentMode string
}

// authorizeBindClaim 是本套件的自助作用域閘：只有「此刻是普通正式帳戶、且不持有
// 伺服器級授予」的已認證主體能通過。
//
// 三道檢查各自擋一個主體形態，而且都回 identity.ErrPermissionDenied（對外 2011）：
//  1. NeedAuthenticated：匿名主體（2002 族屬傳輸層的既有映射）——沒有會話就沒有「本人」；
//  2. 必須是帳戶主體且類型為 standard：訪戶不能给自己綁定（零授予主體過不了這一關），
//     Root 也不是「憑證上的那個目標持有人」；
//  3. 不得持有 server_admin：管理員有自己那本目錄與簽發通路，代他人按下執行是被否決的形態，
//     而把它擋在入口比擋在判定裡少一個「分支記錯就放行」的位置。
//
// 這裡回 2011 而不是 1001：這三句話說的是「你沒有這條通路的資格」，
// 而不是「你指的那個人不在目錄」——後者對自助通路根本無從成立（主體就是呼叫端自己）。
func authorizeBindClaim(principal identity.Principal) error {
	if err := identity.Authorize(principal, identity.NeedAuthenticated); err != nil {
		return err
	}
	if principal.Kind() != identity.KindAccount ||
		principal.AccountType() != account.TypeStandard {
		return identity.ErrPermissionDenied
	}
	if principal.HasRole(identity.RoleServerAdmin) {
		return identity.ErrPermissionDenied
	}
	return nil
}

// PreviewGuestBindClaim 讓憑證上的那個目標本人，以只讀方式看見這枚憑證換來的執行會做什麼。
//
// 步驟（全部 autocommit 快照、零交易、零寫入——與只讀預檢同一取向）：
//  1. 主體判定先於任何查詢；
//  2. 憑證按明文讀回（形狀不合與查無此行都是同一句 ErrBindTicketInvalid）；
//  3. 憑證准的是不是此刻這位呼叫端：不是即同一句話，不透露它准的是誰；
//  4. 此刻還用不用得上：已被核銷或已過期同样是那一句（處置都是回去請人重簽）；
//  5. 重做判定：不可行即帶着阻止原因回 2026，讓本人在按下去之前就知道該重新預檢。
func (s *Service) PreviewGuestBindClaim(ctx context.Context, principal identity.Principal,
	ticketPlain, requestID string) (GuestBindClaimPreview, error) {
	if err := authorizeBindClaim(principal); err != nil {
		s.log.Warn("綁定核銷預覽被拒：主體不是憑證適用的目標本人",
			"subject", principal.String(), "request_id", requestID)
		return GuestBindClaimPreview{}, err
	}
	q := s.db.SQL()
	ticket, err := s.bindTickets.TicketByPlain(ctx, q, ticketPlain)
	if err != nil {
		return GuestBindClaimPreview{}, classifyBindTicketRead(err)
	}
	if ticket.TargetAccountID != principal.AccountID() {
		return GuestBindClaimPreview{}, ErrBindTicketInvalid
	}
	if !ticket.Pending(s.clock.Now()) {
		return GuestBindClaimPreview{}, ErrBindTicketInvalid
	}
	plan, unknownRefs, err := s.evaluateBindPlan(ctx, q, ticket.SourceAccountID, ticket.TargetAccountID)
	if err != nil {
		return GuestBindClaimPreview{}, err
	}
	if err := matchBindPlan(plan, len(unknownRefs), ticket); err != nil {
		return GuestBindClaimPreview{}, err
	}
	s.log.Info("已完成綁定憑證的核銷前預覽（只讀，未綁定）",
		"ticket", ticket.ID.String(), "target", ticket.TargetAccountID.String(),
		"request_id", requestID)
	return GuestBindClaimPreview{TicketID: ticket.ID, Plan: plan, ExpiresAt: ticket.ExpiresAt}, nil
}

// ConfirmGuestBind 由憑證上的那個目標本人核銷憑證並完成綁定：本套件唯一的綁定寫入點。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 主體判定先於一切（見 authorizeBindClaim）；零值標識不進資料庫；
//  2. 交易內讀憑證並核對目標與此刻可用性：與預覽同一套結論，差別只在這裡讀的是
//     即將寫入的那筆交易——「先讀到能用、再被別人用掉」的窗口由 ConsumeTicket 的 WHERE 關死；
//  3. 交易內重做判定並比對計劃摘要：這就是「預檢通過不等於之後永久有權執行」與
//     「不能執行過時計劃」那兩句話的落地形態；
//  4. 核銷憑證（單向條件 UPDATE）：零行即同一句憑證不可用，整筆回滾——
//     包括還未發生的退休，所以不存在「憑證用掉了但人沒綁」的半套；
//  5. 來源退休（單條 UPDATE，WHERE 帶「訪戶且可用」）：零行即 ErrBindConflict，
//     連同步驟 4 的核銷一起回滾；
//  6. 同交易撤銷來源全部會話（與升級、停用、重置同一個執行手段）；
//  7. 同交易讀回來源現值，用它的 retired_at 作為留痕時刻（一次綁定只有一個時刻），
//     再追加留痕行：source 欄的 UNIQUE 是「同一個訪戶不能被綁走兩次」的最後一道閘，
//     而此刻它已在步驟 5 的守衛之後，重複到達不可能寫出第二行；
//  8. 讀回目標現值（不做任何寫入）並組裝回應。
//
// 失敗保留原先可用關係：上面任何一跳失敗，這筆交易一個字都沒落地——
// 憑證仍可核銷（若失敗发生在核銷之前）、訪戶仍是訪戶、會話仍有效、留痕表仍是空的。
// 提交成功但回應遺失的處置不靠重試同一條 POST（那會拿到「憑證已被核銷」），
// 而靠本人的 ListGuestBindings：那一行留痕就是已完成的證據。
func (s *Service) ConfirmGuestBind(ctx context.Context, principal identity.Principal,
	ticketPlain, requestID string) (GuestBindResult, error) {
	if err := authorizeBindClaim(principal); err != nil {
		s.log.Warn("訪戶綁定被拒：主體不是憑證適用的目標本人",
			"subject", principal.String(), "request_id", requestID)
		return GuestBindResult{}, err
	}

	var result GuestBindResult
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		ticket, err := s.bindTickets.TicketByPlain(tctx, tx, ticketPlain)
		if err != nil {
			return classifyBindTicketRead(err)
		}
		if ticket.TargetAccountID != principal.AccountID() {
			return ErrBindTicketInvalid
		}
		if !ticket.Pending(s.clock.Now()) {
			return ErrBindTicketInvalid
		}
		plan, unknownRefs, err := s.evaluateBindPlan(tctx, tx,
			ticket.SourceAccountID, ticket.TargetAccountID)
		if err != nil {
			return err
		}
		if err := matchBindPlan(plan, len(unknownRefs), ticket); err != nil {
			return err
		}
		consumed, err := s.bindTickets.ConsumeTicket(tctx, tx, ticket.ID)
		if err != nil {
			return err
		}
		if !consumed {
			// 讀到「還能用」與真正寫下核銷之間被別人搶先，或時鐘越過到期時刻：
			// 兩者對呼叫端意味著同一句話，整筆交易回滾。
			return ErrBindTicketInvalid
		}
		changed, err := s.accounts.RetireGuestForBind(tctx, tx, ticket.SourceAccountID)
		if err != nil {
			return err
		}
		if !changed {
			// 交易內剛判定「訪戶且可用」、轉眼寫不中：併發的另一次綁定或程式缺陷。
			return ErrBindConflict
		}
		revoked, err := s.sessions.RevokeAccount(tctx, tx, ticket.SourceAccountID)
		if err != nil {
			return err
		}
		// 退休之後重讀來源：留痕的時刻用的就是那一行剛落庫的 retired_at，
		// 不是本套件另取的一次時鐘——一次綁定在資料庫裡只能有一個時刻。
		source, err := s.readStandardProfile(tctx, tx, ticket.SourceAccountID)
		if err != nil {
			return err
		}
		binding, err := s.bindTickets.AppendBinding(tctx, tx, guestbind.AppendBindingInput{
			SourceAccountID: ticket.SourceAccountID,
			TargetAccountID: ticket.TargetAccountID,
			TicketID:        ticket.ID,
			BoundAt:         source.RetiredAt,
			RevokedSessions: revoked,
		})
		if err != nil {
			return err
		}
		target, err := s.readStandardProfile(tctx, tx, ticket.TargetAccountID)
		if err != nil {
			return err
		}
		result = GuestBindResult{
			Binding:         binding,
			Source:          source,
			Target:          target,
			RevokedSessions: revoked,
		}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrBindTicketInvalid), errors.Is(err, ErrBindPlanStale),
			errors.Is(err, ErrBindConflict), errors.Is(err, ErrAccountNotFound):
			return GuestBindResult{}, err
		}
		s.log.Error("訪戶綁定失敗", "request_id", requestID, "err", err)
		return GuestBindResult{}, fmt.Errorf("stdacct: 訪戶綁定失敗: %w", err)
	}
	// 執行動作不寫 Root 域審計的理由見檔案頭注（普通帳戶本人的動作，審計主體類別未批准）；
	// 這一句日誌帶著三個可追溯的標識，而沒有一個憑據材料。
	s.log.Info("已完成訪戶綁定（來源退休、舊會話撤銷、留痕已追加；目標憑據與權限未變）",
		"source", result.Source.AccountID.String(), "target", result.Target.AccountID.String(),
		"ticket", result.Binding.TicketID.String(), "revoked_sessions", result.RevokedSessions,
		"request_id", requestID)
	return result, nil
}

// ListGuestBindings 讀回「目標是我」的全部綁定留痕（依綁定時刻倒序）。
//
// 範圍由換出的主體決定，請求裡沒有任何可填的主體欄位，因此這條通路問不出別人的綁定；
// 它也不是目錄：訪戶退休後仍在管理員那本目錄裡（這是刻意保留的可回溯性），
// 而這一頁說的其實是「哪些人經我本人同意併入了我」。
// 每一行的來源現值經 readStandardProfile 讀回並做實體校驗：留痕指向的是一個查無此人的
// 標識時（庫被外部動過）整個查詢失敗，而不是降級成一行沒有名字的歷史。
func (s *Service) ListGuestBindings(ctx context.Context, principal identity.Principal,
	requestID string) ([]GuestBindingItem, error) {
	if err := authorizeBindClaim(principal); err != nil {
		return nil, err
	}
	q := s.db.SQL()
	bindings, err := s.bindTickets.BindingsByTarget(ctx, q, principal.AccountID())
	if err != nil {
		s.log.Error("讀取本人綁定留痕失敗", "request_id", requestID, "err", err)
		return nil, fmt.Errorf("stdacct: 讀取本人綁定留痕失敗: %w", err)
	}
	items := make([]GuestBindingItem, 0, len(bindings))
	for _, b := range bindings {
		source, err := s.readStandardProfile(ctx, q, b.SourceAccountID)
		if err != nil {
			return nil, classifyBindPreflightRead(err)
		}
		items = append(items, GuestBindingItem{
			BindingID:         b.ID,
			SourceAccountID:   b.SourceAccountID,
			SourceLoginName:   source.LoginName,
			SourceDisplayName: source.DisplayName,
			BoundAt:           b.BoundAt,
			RevokedSessions:   b.RevokedSessions,
			ConsentMode:       b.ConsentMode,
		})
	}
	return items, nil
}

// matchBindPlan 核對「憑證上釘著的計劃」與「此刻重算出的計劃」是否同一份。
//
// 兩句話各自擋一件事，順序也是刻意的：
//   - 先問可不可行：不可行時真正的答案是「被這些原因擋住了」，把它報成摘要不相等
//     會讓操作者去查一堆對不上的欄位，而處置本來就是重新預檢並重新簽發；
//   - 再問摘要：可行但事實已漂（版本升級、兩側任一欄的形態换过、多了未接入的引用表）
//     代表手上這份計劃不是眼前這份，執行它等於執行一份沒人預覽過的東西。
func matchBindPlan(plan GuestBindPreflight, unknownRefCount int, ticket guestbind.Ticket) error {
	if !plan.Executable {
		return &BindPlanError{Blockers: plan.Blockers}
	}
	if bindPlanDigest(plan, unknownRefCount) != ticket.PlanDigest ||
		plan.SchemaVersion != ticket.SchemaVersion {
		return ErrBindPlanStale
	}
	return nil
}

// classifyBindTicketRead 把憑證倉儲的讀取失敗收斂成綁定通路對外的可判別結論。
//
// 口徑與本目錄其餘通路一致：查無此行、標識零值、憑證明文形狀不合，一律換成
// 同一句 ErrBindTicketInvalid（2025 那句不分辨細節的話）；
// 標識解析異常之類的內部故障原樣上拋讓交易回滾——那種時候報「憑證不可用」是謊，
// 報缺陷才是誠實，而兩種話對呼叫端的處置本來也不同。
func classifyBindTicketRead(err error) error {
	switch {
	case errors.Is(err, guestbind.ErrNotFound), errors.Is(err, guestbind.ErrNilIdentifier):
		return ErrBindTicketInvalid
	default:
		return err
	}
}
