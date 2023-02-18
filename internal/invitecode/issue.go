// issue.go 是「簽發一枚服務器級註冊邀請碼」的應用服務層。
//
// 這一跳落下的是「一枚新碼 + 一筆 Root 域審計」兩件事，落在同一筆交易裡同生同滅：
// 查不到是誰籤的這枚碼，與簽了卻沒落庫，同樣是不可接受的半套。它不做的事同樣是要害——
// 不碰 accounts、不碰 account_server_roles、不碰 sessions、不讀 acctpolicy：
// 「簽出一枚准入憑證」與「把自注冊模式切成 invite」是兩條獨立的決定，前者不等於後者，
// 一枚此刻簽出的碼在模式沒切之前換不出任何賬戶，這正是本步刻意保留的形態（見套件頭注）。
//
// 明文碼只在成功回傳裡出現這一次：庫裡落的是它的 SHA-256 驗證材料，此後任何讀法都拿不回明文。
// 丟了就重新簽發一枚，而不是把庫存的秘密翻出來——這與一次性口令、會話秘密同一交付語意。
//
// 被拒的簽發（非 Root、標籤不合法、額度不合法、有效期不合法）一律不追加審計：
// 與被拒的開設、被拒的改名同口徑——拒絕的結論不該成為寫入了放大器；那次嘗試的、時刻與關聯 ID
// 在執行日誌與訪問日誌裡都有。
package invitecode

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// IssueInput 是一次簽發的領域輸入。
//
// 沒有 ID、沒有創建時刻、沒有明文碼：那三樣各有唯一產生點（idgen、注入時鐘、secret.go），
// 讓呼叫端代填等於把「這枚碼是誰、什麼時候生的、它的秘密是什麼」交給請求鏈上的某一環。
// ExpiresAt 是零值代表永不過期；非零時它是一個未來的時刻（在本方法裡、簽發之前當場複核，
// 一枚「一出生就過期」的碼不進庫）。MaxUses 恆 >= 1；1 即單次碼。
type IssueInput struct {
	Label     string
	MaxUses   int64
	ExpiresAt time.Time
}

// IssuedCode 是一次成功簽發的結果。
//
// Code 是明文碼本身——全倉庫唯一允許它離開服務端的出口，只在簽發成功的這一份回傳裡出現一次，
// 絕不寫庫、不寫日誌、不寫審計、不出現在名冊或撤銷回顯上。其餘欄位（Entry）是可長期展示的名冊行，
// 與 GET 名冊同源同形，界面拿到簽發結果就能直接把它併入列表，不必自己再拼一份形狀。
type IssuedCode struct {
	Code string
	Row  Row
}

// Issue 以 Root 主體簽發一枚服務器級註冊邀請碼，並在同一個交易裡落一筆 Root 域審計。
//
// 順序與每一跳的理由：
//  1. 授權與輸入複核在交易外：被拒的請求一個查詢都不該多花，一枚碼都不該多燒一次隨機源；
//     標籤、額度、有效期各自是「請求本體哪個欄位寫壞了」，當場點名比進庫撞 CHECK 誠實；
//  2. 交易內先落庫、再落審計：任何一跳失敗整筆回滾，不會出現「庫裡多了一枚碼而 Root 域查不到是誰籤的」
//     或「審計說簽過而庫裡沒有這行」；
//  3. 明文只在落庫與審計都成功之後才隨結果交回——回傳即意味著庫裡已經有了它的驗證材料。
//
// 有效期此刻與注入時鐘同源：非零的 ExpiresAt 必須晚於當下，一枚在過去或此刻到期的碼沒有存在的餘地。
func (s *Service) Issue(ctx context.Context, principal identity.Principal,
	in IssueInput, requestID string) (IssuedCode, error) {
	if err := s.requireRoot(principal, "issue"); err != nil {
		return IssuedCode{}, err
	}
	label, err := validateLabel(in.Label)
	if err != nil {
		return IssuedCode{}, err
	}
	if err := validateMaxUses(in.MaxUses); err != nil {
		return IssuedCode{}, err
	}
	now := s.clock.Now()
	if !in.ExpiresAt.IsZero() && !in.ExpiresAt.After(now) {
		return IssuedCode{}, fmt.Errorf("%w：到期時刻不晚於簽發時刻", ErrInvalidExpiry)
	}

	code, hash, err := newCode(nil)
	if err != nil {
		// 隨機源失敗不降級：換一種隨機繼續簽發正是最不該靜默發生的那件事，細節只進日誌。
		s.log.Error("簽發邀請碼時產生隨機碼失敗", "request_id", requestID, "err", err)
		return IssuedCode{}, err
	}

	var issued IssuedCode
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		stored, err := s.store.Create(tctx, tx, CreateInput{
			CodeHash:  hash,
			Label:     label,
			MaxUses:   in.MaxUses,
			ExpiresAt: in.ExpiresAt,
		})
		if err != nil {
			return err
		}
		rec, err := s.issueRecord(principal, stored, requestID)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		issued = IssuedCode{
			Code: code,
			Row: rowOf(stored.ID.String(), stored.Label, stored.MaxUses, stored.UsedCount,
				stored.CreatedAt, millisOrZero(stored.ExpiresAt), millisOrZero(stored.RevokedAt), now),
		}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidLabel), errors.Is(err, ErrInvalidMaxUses),
			errors.Is(err, ErrInvalidExpiry):
			return IssuedCode{}, err
		}
		s.log.Error("簽發邀請碼失敗", "request_id", requestID, "err", err)
		return IssuedCode{}, fmt.Errorf("invitecode: 簽發邀請碼失敗: %w", err)
	}
	s.log.Info("Root 已簽發服務器級註冊邀請碼",
		"code", issued.Row.CodeID, "max_uses", issued.Row.MaxUses, "request_id", requestID)
	return issued, nil
}

// issueRecord 產生一筆 Root 域的簽發審計。口徑與 internal/acctpolicy、internal/acctreview 同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆簽發回滾——
// 「簽了某人一枚准入憑證卻查不到是誰籤的」是簽發這件事最不能缺的一格。
//
// Changes 只展開可展示的准入參數（標籤、額度上限、有效期、簽發時刻），恰好這幾格回答
// 「 Root 造了一把能開幾次、開到什麼時候的門」。絕不落進記錄的東西：明文碼、它的任何前綴或長度、
// SHA-256 驗證材料——讓「審計表裡沒有一個欄位可能含邀請碼」成立在結構上，而不是成立在「掩碼會幫我擋」的期待上。
func (s *Service) issueRecord(principal identity.Principal, stored InviteCode,
	requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("invitecode: 主體無法換得審計操作者: %w", err)
	}
	return audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  actor,
		Action: "invite.issue",
		Target: audit.Target{Kind: "registration_invite_code", ID: stored.ID.String()},
		Reason: "Root 經已認證會話簽發服務器級註冊邀請碼：這是建立普通賬戶的准入憑證，" +
			"不攜帶任何服務器級角色、不代表加入任何活動；庫中只存其驗證材料哈希，明文僅本次交付一次",
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "label", Before: nil, After: stored.Label},
			{Field: "max_uses", Before: nil, After: stored.MaxUses},
			{Field: "expires_at", Before: nil, After: nullableFormatUTC(stored.ExpiresAt)},
			{Field: "created_at", Before: nil, After: timeutil.FormatUTC(stored.CreatedAt)},
		},
	}, nil
}

// millisOrZero 把一個零值代表「無此事實」的時刻換成它的 Unix 毫秒（零值 → 0），
// 供 rowOf 與倉儲欄位表示同一種編碼：0 恆等於「永不過期 / 尚未撤銷」。
func millisOrZero(at time.Time) int64 {
	if at.IsZero() {
		return 0
	}
	return timeutil.ToMillis(at)
}
