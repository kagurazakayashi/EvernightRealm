// bindissue.go 是「管理員把一份可行的綁定預覽換成一枚短期操作憑證」的應用服務層。
//
// 這一步動的是資料庫：它簽發一枚憑證。它不是綁定本身，也不是綁定的半程——
// 簽發之後，訪戶 X 一個字沒變、目標 Y 一個字沒變、X 的會話一枚沒撤。
// 它落的唯一事實是「某位伺服器級管理員在某一時刻，按當時的事實准了這一對（X, Y），
// 並把『最後由誰按下執行』交給 Y 本人」。那句「由 Y 本人」寫在同意形態裡（恆為
// ConsentModeTargetSelfInitiated），也寫在憑證的 target_account_id 上：
// 除了 Y 自己的已認證會話，沒有任何主體能用掉這枚憑證。
//
// 為什麼需要這一層介質（用戶批准的 R2-019 決定）：預檢是管理員發起的只讀通路、
// 零落庫，而執行必須由 Y 本人發起——兩者之間沒有一座橋的話，「目標本人發起」就只剩
// 「任何知道那枚 36 字元標識的人都能宣稱自己是目標」。憑證把來源側的授權
// （管理員准過這一對）與目標側的同意（Y 用自己的會話核銷）钉在同一行上，
// 並且自帶三道限制：限定這一對（換目標重放用不掉）、限定用途（它只能換這一次綁定）、
// 限定時間與次數（15 分鐘、只准核銷一次）。
//
// 與「收集目標口令」的差別是本檔存在的全部理由：管理員在這裡交出的是一段短效、
// 單次、只能由 Y 自己的會話使用的操作憑證，不是 Y 的口令，也不是任何可長期持有的秘密。
// 本套件不因綁定而讀、寫、复制或回報任何憑據材料（訪戶按定義無憑據，目標的憑據與這一跳無關）。
//
// 為什麼放在 stdacct 而不是新套件：授權閘（NeedServerAdmin）、目錄範圍核實
// （readStandardProfile）、綁定可行性判定（evaluateBindPlan）與引用登記表都在這裡，
// 簽發要的恰好是「與預檢逐字相同的那份判定，在寫入那一刻重做一次」。
// 拆開就會有第二套「准不准綁」的規則，而兩套規則的差距正是可被利用的窗口。
//
// 有效期是碼內常量而非配置欄：一個「可以調到一週」的綁定憑證就不再是短期憑證，
// 而本步也沒有給它一個撤销通路（未核銷者由到期時刻失效，這是它唯一的失效方式）。
package stdacct

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/guestbind"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// GuestBindTicketTTL 是綁定憑證的有效期（用戶批准：短效、不可經配置加長、無撤銷通路）。
//
// 15 分鐘cover的是「管理員把憑證交給 Y、Y 登錄並按下確認」這一段線下動作的合理長度；
// 它不是一個安全邊界（安全邊界是單次核銷與限定這一對），所以寧短勿長。
const GuestBindTicketTTL = 15 * time.Minute

// 綁定執行通路的結論錯誤：傳輸層據此分流回應，內部故障一律不進這些型別。
var (
	// ErrBindTicketInvalid 表示交來的那枚操作憑證用不了：不存在、形狀不合、已過期、
	// 已被核銷，或它本來准的是別人而不是此刻這位呼叫端。
	//
	// 五種情況刻意收成同一個結論、同一句話（對外映射 2025）：它們對呼叫端的處置
	// 完全相同（回去找簽發的那位管理員要一枚新的），而把「差在哪一半」講出來
	// 等於讓這個端點變成一枚探測器——能分辨「這枚碼存在但已被用掉」與「這枚碼不存在」
	// 的人，就在用一條本該只服务綁定的通路做枚舉。標識是隨機值，但「可分辨」本身就是信號。
	ErrBindTicketInvalid = errors.New("stdacct: 綁定憑證不可用")
	// ErrBindPlanStale 表示這份計劃已經不符合當前事實，必須重新預檢後再簽發／核銷。
	// 它由 *BindPlanError 繼承（Unwrap 到這裡），傳輸層據此回 2026。
	ErrBindPlanStale = errors.New("stdacct: 這份綁定計劃已不合當前事實")
	// ErrBindConflict 表示倉儲守衛命中零行：交易內剛判定可行，轉眼寫不中。
	//
	// 正常串行下它現讀就被阻止原因擋住，這裡只兜住併發的尾巴與缺陷形態，
	// 對外沿用既有 2014「目標的可用性已不是你確認時那樣」——處置同形：重讀現狀再決定。
	ErrBindConflict = errors.New("stdacct: 綁定目标的可用性已與提交時所依據的不同")
)

// BindPlanError 是「這一對此刻不可綁定」的可判別結論：它既是 sentinel ErrBindPlanStale
// （錯誤碼因此可以是 2026），又帶著具體的阻止原因記號讓傳輸層寫進 details。
//
// 為什麼用型別而不是把原因塞進訊息字串：那些記號是穩定枚舉、界面要按記號選四語言句子，
// 而訊息字串是给人看的散文——把協議欄位寄存在散文裡，等於讓文案改動變成合同破壞。
type BindPlanError struct {
	// Blockers 是判定當下全部適用的阻止原因記號（至少一條，否則不會走到這個錯誤）。
	Blockers []BindBlocker
}

// Error 給出一句不含任何帳戶標識的概括話：日誌與錯誤鏈都不靠它傳達細節。
func (e *BindPlanError) Error() string {
	return fmt.Sprintf("stdacct: 這一對此刻不可綁定（%d 條阻止原因）", len(e.Blockers))
}

// Unwrap 讓 errors.Is(err, ErrBindPlanStale) 成立：結論的分類靠 sentinel，
// 細節靠欄位，兩件事不互相頂替。
func (e *BindPlanError) Unwrap() error { return ErrBindPlanStale }

// IssuedBindTicket 是一次成功簽發的結果。
//
// Ticket 是憑證明文，只在這一次回傳裡存在：落庫的是它的 SHA-256（見 internal/guestbind），
// 任何讀法都拿不回明文，因此回應丟了就只能重新簽發，不會出現「事後查證據洩露」。
type IssuedBindTicket struct {
	// Ticket 為憑證明文（22 字元 base64url）；交付一次，不進日誌與審計。
	Ticket string
	// TicketID 為憑證的穩定標識（可展示、可用於追溯，不是秘密）。
	TicketID idgen.ID
	// Plan 為簽發那一刻的完整判定：兩側最小資料、影響清單、源會話數與資料庫版本。
	// 它是「這份憑證准的是什麼」的回音，不是預覽的替代品（界面仍要能重跑只讀預覽）。
	Plan GuestBindPreflight
	// ExpiresAt 為這枚憑證的失效時刻（簽發時刻加 GuestBindTicketTTL）。
	ExpiresAt time.Time
}

// IssueGuestBindTicket 以持有伺服器級管理權的受信主體，為一對（來源, 目標）簽發一枚
// 限定這一對、15 分鐘有效、只准核銷一次的綁定憑證。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 授權（NeedServerAdmin）與零值標識在交易外：與只讀預檢同一道閘、同一句話；
//  2. 交易內重做判定（evaluateBindPlan）：這是「預檢通過不等於之後永久有權執行」的落地形態——
//     簽發依的是寫入那一刻的事實，不是呼叫端手上那份舊預覽；有任一阻止原因即整個不發生，
//     並把原因記號原樣帶回（被拒的簽發零寫入、零審計，與被拒的建號同口徑）；
//  3. 憑證落庫：三個標識、計劃摘要、資料庫版本與失效時刻一起釘在行上
//     （見 internal/guestbind 的 CreateTicket）；
//  4. 同交易追加 Root 域審計：這一次的動作是「准了這一對」，操作者是那位管理員，
//     因此它有審計（與 Y 本人的核銷動作相反：普通帳戶本人的動作今日不寫審計表，
//     見檔案末段）。審計帶的是憑證標識而不是明文——一枚已被簽發的憑證可以被查到，
//     一枚憑證的明文不可以。
//
// 同一對重複簽發是合法的，也是安全的：每一枚都是獨立的一行，先被核銷的那枚把來源退休，
// 其後任何一枚到達時都會在步驟 2 拿到 source_not_active 而被拒——
// 「重複請求不能改變其他帳戶」因此不靠去重，靠的是寫入那一刻的重新判定。
func (s *Service) IssueGuestBindTicket(ctx context.Context, principal identity.Principal,
	sourceID, targetID idgen.ID, requestID string) (IssuedBindTicket, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		s.log.Warn("簽發綁定憑證被拒：主體不具備伺服器級管理權",
			"subject", principal.String(), "request_id", requestID)
		return IssuedBindTicket{}, err
	}
	if sourceID.IsNil() || targetID.IsNil() {
		return IssuedBindTicket{}, ErrAccountNotFound
	}

	var issued IssuedBindTicket
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		plan, unknownRefs, err := s.evaluateBindPlan(tctx, tx, sourceID, targetID)
		if err != nil {
			return err
		}
		if !plan.Executable {
			return &BindPlanError{Blockers: plan.Blockers}
		}
		digest := bindPlanDigest(plan, len(unknownRefs))
		ticket, plain, err := s.bindTickets.CreateTicket(tctx, tx, guestbind.CreateTicketInput{
			SourceAccountID:   sourceID,
			TargetAccountID:   targetID,
			IssuedByAccountID: principal.AccountID(),
			PlanDigest:        digest,
			SchemaVersion:     plan.SchemaVersion,
			ExpiresAt:         s.clock.Now().Add(GuestBindTicketTTL),
		})
		if err != nil {
			return err
		}
		rec, err := s.bindTicketIssueRecord(principal, ticket, requestID)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		issued = IssuedBindTicket{
			Ticket:    plain,
			TicketID:  ticket.ID,
			Plan:      plan,
			ExpiresAt: ticket.ExpiresAt,
		}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrAccountNotFound), errors.Is(err, ErrBindPlanStale),
			errors.Is(err, ErrBindTicketInvalid), errors.Is(err, ErrBindConflict):
			return IssuedBindTicket{}, err
		}
		s.log.Error("簽發綁定憑證失敗", "request_id", requestID, "err", err)
		return IssuedBindTicket{}, fmt.Errorf("stdacct: 簽發綁定憑證失敗: %w", err)
	}
	s.log.Info("已簽發訪戶綁定憑證（限定這一對、短效、只准核銷一次；尚未綁定任何人）",
		"source", sourceID.String(), "target", targetID.String(),
		"ticket", issued.TicketID.String(), "request_id", requestID)
	return issued, nil
}

// bindPlanDigest 把「這份計劃依據的那些事實」壓成一枚定寬摘要。
//
// 進摘要的欄位是刻意的最小集合，而且只進「決定這一次綁定可不可行」的那幾項：
// 資料庫版本（引用登記表的覆盖面隨版本變）、兩個標識、兩側的類型與狀態、
// 以及未接入登記表的引用表數量。源會話數量刻意不在其中——那一句「將讓 N 臺裝置重新登入」
// 描述的是動作的幅度，不是動作的許可；它變了不代表這份計劃該作廢，
// 而執行回應老實報出的是撤銷當下的真實數量，不是簽發時的那個 N。
//
// 摘要比對不是安全邊界的第一道（第一道是核銷那一刻重新做的完整判定）：
// 它擋的是「拿舊計劃去執行一份新事實」這種自相矛盾，讓過期以一句可判別的話出現，
// 而不是讓它靠在場機率僥倖。
func bindPlanDigest(plan GuestBindPreflight, unknownRefCount int) string {
	canonical := strings.Join([]string{
		"v1",
		fmt.Sprintf("schema=%d", plan.SchemaVersion),
		"source=" + plan.Source.AccountID.String(),
		"source_type=" + plan.Source.Type.String(),
		"source_status=" + plan.Source.Status.String(),
		"target=" + plan.Target.AccountID.String(),
		"target_type=" + plan.Target.Type.String(),
		"target_status=" + plan.Target.Status.String(),
		fmt.Sprintf("unknown_refs=%d", unknownRefCount),
	}, "|")
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// bindTicketIssueRecord 產生一筆 Root 域的簽發審計。口徑與 creationRecord 同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆簽發回滾。
//
// Target 記的是來源訪戶：這一次動作的對象是「這個人將被併到誰那裡去」，
// 而「誰准的」在 actor 欄、「准給了誰」在 changes 的 target_account_id 欄。
// ScopeRoot 而不捏造 activity_id：簽發綁定憑證是伺服器級動作，不屬於任何活動。
//
// 絕不落進記錄的東西：憑證明文（它連庫裡都沒有）、任何憑據材料、會話材料。
// ticket_id 不是秘密：它是那行的主鍵，而驗證材料是另一欄的哈希，兩者都出不了這個回應。
func (s *Service) bindTicketIssueRecord(principal identity.Principal,
	ticket guestbind.Ticket, requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("stdacct: 主體無法換得審計操作者: %w", err)
	}
	return audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  actor,
		Action: "account.guest_bind_ticket_issue",
		Target: audit.Target{Kind: "account", ID: ticket.SourceAccountID.String()},
		Reason: "伺服器級管理員經已認證會話為一對（訪戶, 正式帳戶）簽發短期單次的綁定操作憑證：" +
			"依據寫入那一刻重做的綁定可行性判定；憑證限定這一對、只准核銷一次，" +
			"執行動作只能由目標本人以自己的會話發起。此時尚未綁定任何人",
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "ticket_id", Before: nil, After: ticket.ID.String()},
			{Field: "target_account_id", Before: nil, After: ticket.TargetAccountID.String()},
			{Field: "schema_version", Before: nil, After: ticket.SchemaVersion},
			{Field: "expires_at", Before: nil, After: ticket.ExpiresAt.UTC().Format(time.RFC3339Nano)},
		},
	}, nil
}
