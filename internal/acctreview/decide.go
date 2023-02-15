// decide.go 是「對一筆註冊申請做出批准或拒絕」的應用服務層。
//
// 這裡動的是「這個人能不能從門外走進這台伺服器」這一個決定，不是他的登入能力開關、
// 不是他的憑據、也不是他的身分形態：
//   - 批准落成的形態由端點與用例決定（status 從 pending 換成 active，帶著決定時刻），
//     請求本體只有一個決定值，沒有任何角色、帳戶類型、口令或活動欄位可填；
//   - 那條 UPDATE 連 account_server_roles 與 sessions 兩張表都不在語句裡，
//     因此「批准順手多出一位管理員」「批准順手替他簽一枚憑據」在 SQL 形狀上就沒有發生點，
//     不是靠界面把按鈕藏起來；
//   - 拒絕落成的形態是 rejected ＋ 決定時刻，行與登入名佔用都保留（用戶批准的保留策略）。
//
// 併發與重複都收在同一道守衛上：寫入的 WHERE 帶著「他此刻還在等著被決定」這個可觀測事實。
// 兩個審核者各按一次時，SQLite 的單寫入者把兩次提交串行化——先落地的那一次是唯一有效結果，
// 後到的拿到 changed=false，整個操作不發生（狀態沒改、決定時刻沒寫、審計沒記），
// 也不會把先前那個決定悄悄蓋掉。對已決定過的人重複按下同一個動作是同一句話，
// 界面要的是「重讀這份名冊」而不是「再點一次那顆按鈕」。
//
// 批准不是一道認證：本套件不簽發、不撤銷、也不復活任何會話。待審批的人今日沒有任何會話
// （internal/session 的簽發與逐請求解析都以「帳戶是 active」為前提），因此也沒有一枚
// 「受限會話」需要在批准時被換掉或升格——他能不能進來由他自己拿口令走既有 /auth/login 決定，
// 而那一刻起他拿到的是一般帳戶該有的能力，不多也不少（不含任何伺服器級授予）。
//
// 批准也不解除任何獨立限制：must_change_password、disabled_at、deleted_at 都不在語句裡。
// 一個曾被批准、此後被停用的人不在這本書上（他早已離開 pending），任何一條審批通路都碰不到他，
// 「用批准來解除停用」這種越權在這裡沒有一格可以按。
//
// 被拒的申請（非管理員、不在名冊、併發落敗、決定值不合法）一律不追加審計：
// 與被拒的建號、被拒的編輯同口徑——拒絕的結論不該成為寫入放大器；
// 那次嘗試的來源、時刻與關聯 ID 在執行日誌與訪問日誌裡都有。
package acctreview

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// ReviewOutcome 是一次成功決定的結果：決定之後的單筆真相，加上本次做出的那個決定。
//
// Application 是「寫入之後的資料庫現值」（交易內重讀），不是呼叫端意圖的迴音：
// 批准之後那一行帶著 active 與決定時刻，雖然他已經不在這本名冊上（名冊只列 pending 與
// rejected），界面要的回顯依據仍是同一份形態——六格一個不多一個不少，不必為兩本書再各造一個形狀。
// Decision 讓界面能把「你按下的是哪一顆」與伺服器落地的結果一起講，而不是事後自己猜。
type ReviewOutcome struct {
	// Application 為決定之後經實體校驗的單筆申請資料。
	Application Application
	// Decision 為本次落地的那個決定。
	Decision account.Decision
}

// ReviewApplication 以持有伺服器級管理權的受信主體對一筆待審批申請做出批准或拒絕。
//
// 全部寫入落在同一筆交易，順序與每一跳的理由：
//  1. 授權（NeedServerAdmin，與建號、目錄、停用同一道閘）與輸入校驗在交易外：
//     被拒的請求一個查詢都不該多花；決定值不合法是請求本體的問題，點名欄位比回衝突誠實；
//  2. 交易內核實目標此刻的形態（readPendingApplication）：帳戶存在、不是訪戶、
//     不持有伺服器級授予、未進入刪除終態、而且確實還掛在中間。五道檢查各擋一種
//     「不該被這條通路動到」的行，全部在讀到實體之後當場判，不依賴名冊那段 SQL 替它作答；
//  3. 帶守衛地寫入決定（account.Store.DecideApplication）：changed=false 即回 ErrAlreadyReviewed
//     並讓交易回滾——狀態、決定時刻、審計三件事沒有一件發生，衝突的決定不是「部分成功」；
//  4. 同一交易內重讀經實體校驗的現值並追加 Root 域審計：決定與其痕跡同生同滅，
//     「真實存在卻在 Root 域查不到是誰批的」與「審計說有而資料庫查不到」同罪。
//
// 這一跳不問帳戶建立策略、不簽發或撤銷會話、也不動任何憑據欄位（理由見套件頭注）。
func (s *Service) ReviewApplication(ctx context.Context, principal identity.Principal,
	accountID idgen.ID, decision account.Decision, requestID string) (ReviewOutcome, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		s.log.Warn("處理註冊申請被拒：主體不具備伺服器級管理權",
			"subject", principal.String(), "request_id", requestID)
		return ReviewOutcome{}, err
	}
	if accountID.IsNil() {
		return ReviewOutcome{}, ErrApplicationNotFound
	}
	if err := requireDecision(decision); err != nil {
		return ReviewOutcome{}, err
	}

	var outcome ReviewOutcome
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		before, err := s.readPendingApplication(tctx, tx, accountID)
		if err != nil {
			return err
		}
		changed, err := s.accounts.DecideApplication(tctx, tx, accountID, decision)
		if err != nil {
			return err
		}
		if !changed {
			// 讀與寫之間的那個窗口由資料庫的 WHERE 收口：有人在我們之前決定了他。
			return ErrAlreadyReviewed
		}
		// 交易內重讀：回應要的是「決定之後的資料庫現值」，不是呼叫端的意圖迴音。
		after, err := s.accounts.ByID(tctx, tx, accountID)
		if err != nil {
			return err
		}
		rec, err := s.decisionRecord(principal, before, after, decision, requestID)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		outcome = ReviewOutcome{Application: applicationOf(after), Decision: decision}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, account.ErrNotFound):
			// 交易內重讀落空只剩併發的物理清庫或程式缺陷：對呼叫端仍是那句「不在這本名冊上」，
			// 但這一條要進日誌，它不是一次正經的拒絕。
			s.log.Error("處理註冊申請時目標帳戶消失", "request_id", requestID, "err", err)
			return ReviewOutcome{}, ErrApplicationNotFound
		case errors.Is(err, ErrApplicationNotFound), errors.Is(err, ErrAlreadyReviewed),
			errors.Is(err, ErrInvalidDecision):
			return ReviewOutcome{}, err
		}
		s.log.Error("處理註冊申請失敗", "request_id", requestID, "err", err)
		return ReviewOutcome{}, fmt.Errorf("acctreview: 處理註冊申請失敗: %w", err)
	}
	s.log.Info("已做出註冊申請的審批決定",
		"account", outcome.Application.AccountID, "decision", decision.String(),
		"status", outcome.Application.Status, "request_id", requestID)
	return outcome, nil
}

// readPendingApplication 核實目標此刻是不是這本名冊上一筆可以被決定的申請，
// 回傳經實體校驗的帳戶（q 由呼叫端給：本方法只在交易內使用）。
//
// 五道檢查各擋一種形態，順序是刻意的：先問帳戶本身在不在（不在就不必再問他是誰），
// 再問來源與授予，最後才分辨狀態。除「已有決定」之外的出局都回同一個
// ErrApplicationNotFound，讓呼叫端拿不到「差哪一半」的信號——標識是 UUIDv7，
// 把「存在但他是管理員／訪戶／已被刪除」講出來等於讓一條管理員端點替別人做帳戶枚舉。
func (s *Service) readPendingApplication(ctx context.Context, q database.Querier,
	accountID idgen.ID) (account.Account, error) {
	if accountID.IsNil() {
		return account.Account{}, ErrApplicationNotFound
	}
	a, err := s.accounts.ByID(ctx, q, accountID)
	if err != nil {
		if errors.Is(err, account.ErrNotFound) {
			return account.Account{}, ErrApplicationNotFound
		}
		return account.Account{}, err
	}
	// 訪戶不經審批通路：遷移 0009 的 CHECK 把那個形態凍在資料庫層（無憑據可出示的人
	// 沒有一份等待批准的申請），這裡是同一句話在域層的寫法，擋的是繞過應用層的直寫。
	if a.Type == account.TypeGuest {
		return account.Account{}, ErrApplicationNotFound
	}
	// 「查無授予」在這裡是好消息：他還沒被任何人授予過伺服器級角色。
	// 這句話的權威在 internal/grant，本套件只是讀者；grant 的其他失敗（資料庫故障）
	// 原樣上拋，不降級成「不在名冊」。少這一層的後果很具體：一筆被人直寫過授予的 pending 行
	// 被批准之後，會同時是可登入的、持有管理權的主體——而沒有任何一位審核者說過要授予他什麼。
	if _, err := s.grants.GrantedAt(ctx, q, accountID, identity.RoleServerAdmin); err == nil {
		return account.Account{}, ErrApplicationNotFound
	} else if !errors.Is(err, grant.ErrNotFound) {
		return account.Account{}, err
	}
	// 刪除終態先於「有沒有決定過」判定：他不再屬於任何一本可寫的書，
	// 回「查無此帳戶」與 internal/stdacct 對已刪者的口徑一致（那句話是 Root 管理員目錄的處置，
	// 而這本名冊按定義也不列已刪者）。
	if a.Status == account.StatusDeleted {
		return account.Account{}, ErrApplicationNotFound
	}
	// 還掛在中間的申請是唯一的處理對象。離開 pending 的人分兩類說法，因為兩句話的處置不同：
	//   - 帶著決定時刻的（rejected，或被批准後又被停用的 active／disabled）：
	//     「這份申請已經有過決定」→ ErrAlreadyReviewed。他還在審批鏈的話上，只是沒有第二顆按鈕；
	//   - 從沒走過審批通路的（管理員建號、Root 開設、開放自註冊建成的那些行）：
	//     他根本不在這本書上 → ErrApplicationNotFound。把他們報成「已有決定」，
	//     是對一個從沒提交過申請的人謊稱存在一個決定。
	if a.Status != account.StatusPending {
		if !a.ReviewedAt.IsZero() {
			return account.Account{}, ErrAlreadyReviewed
		}
		return account.Account{}, ErrApplicationNotFound
	}
	return a, nil
}

// requireDecision 用帳戶域唯一的決定入口復核一次決定值：這裡不另寫一份「哪些詞算決定」。
//
// 直接把 account.Decision 的內部判定當公開 API 用會多出第二個真相來源；經 ParseDecision
// 走一趟，本套件認得的決定集合永遠與 internal/account 一致，不一致時（例如有人加了決定
// 卻忘了放寬對應的落庫形態）在寫入之前就換成可展示的 ErrInvalidDecision。
func requireDecision(decision account.Decision) error {
	if _, err := account.ParseDecision(decision.String()); err != nil {
		return fmt.Errorf("%w：%q", ErrInvalidDecision, decision.String())
	}
	return nil
}

// applicationOf 把經實體校驗的帳戶換成名冊那一個形狀（欄位白名單見 roster.go 頭注）。
//
// 單筆讀法與名冊投影共用這一個換形點，為了同一筆資料在「列出來」與「決定之後回顯」
// 兩個場合長得不一樣，界面就要各記一套欄位。
func applicationOf(a account.Account) Application {
	return Application{
		AccountID:   a.ID.String(),
		LoginName:   a.LoginName,
		DisplayName: a.DisplayName,
		Status:      a.Status.String(),
		SubmittedAt: a.CreatedAt,
		ReviewedAt:  a.ReviewedAt,
	}
}

// decisionRecord 產生一筆 Root 域的審批審計。口徑與 internal/stdacct 同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆決定回滾——
// 「審核者是誰」是這整件事唯一需要長期留證的一格，它落在這裡而不是落在帳戶表的某一欄。
//
// ScopeRoot 而不捏造 activity_id：批准一個伺服器級帳戶的進入是伺服器級動作，不屬於任何活動，
// root_audit 結構上也沒有那一欄。動作名以 account. 前綴與建號、停用、編輯同一組，
// 表示「動的是普通帳戶這一類主體」，與管理員那組 admin.* 分家。
//
// 絕不落進記錄的東西：口令明文與任何一側的憑據雜湊（申請人的口令從頭到尾沒被讀過）、
// 會話材料、來源 IP、任何錯誤鏈原文，以及「為什麼拒他」這種自由文本——
// Reason 是服務端固定措辭，而 changes 只有 status 與 reviewed_at 兩格的前後值，
// 讓「審計表裡沒有一個欄位可能含口令，也沒有一格能容下審核者的隨筆」成立在結構上。
func (s *Service) decisionRecord(principal identity.Principal, before, after account.Account,
	decision account.Decision, requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("acctreview: 主體無法換得審計操作者: %w", err)
	}
	action := "account.approve"
	reason := "伺服器級管理員經已認證會話批准註冊申請：落成可登入的普通帳戶並留下決定時刻，" +
		"不帶任何伺服器級授予、不簽發任何會話，登入仍由本人持自選口令經既有入口完成"
	if decision == account.DecisionReject {
		action = "account.reject"
		reason = "伺服器級管理員經已認證會話拒絕註冊申請：保留行與登入名佔用並留下決定時刻，" +
			"決定是單向的（今日無改判通路）；理由不落庫也不對外，本人只能查到結局與決定時刻"
	}
	return audit.Record{
		Scope:     audit.ScopeRoot,
		Actor:     actor,
		Action:    action,
		Target:    audit.Target{Kind: "account", ID: after.ID.String()},
		Reason:    reason,
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "status", Before: before.Status.String(), After: after.Status.String()},
			{Field: "reviewed_at", Before: nullableFormatUTC(before.ReviewedAt),
				After: nullableFormatUTC(after.ReviewedAt)},
		},
	}, nil
}
