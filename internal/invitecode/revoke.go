// revoke.go 是「撤銷一枚服務器級註冊邀請碼」的應用服務層。
//
// 撤銷擋住的是「這枚碼此後還能不能被核銷」，不是一個已經合法建出來的賬戶：本套件從不因為撤銷一枚碼
// 而觸碰任何 accounts 行、任何會話、任何授予——那幾件事各有自己的欄位與通路，「撤銷邀請碼」這句話
// 在結構上沒有一處能把它們一起做掉（這條 UPDATE 連那幾張表都不在語句裡）。
//
// 撤銷是單向的終態：庫裡那一躍只把 revoked_at 從 0 落成注入時鐘的此刻，之後這行不再有任何可寫的東西
// （見遷移 0010 的終態觸發器）。已核銷的次數作為必要歷史留住——撤銷不抹掉「它曾被用過幾次」這件事。
//
// 重複撤銷與併發落敗收在同一道守衛上：寫庫的 WHERE 帶著「它此刻還沒被撤銷」這個可觀測事實。
// 兩個撤銷者各按一次時，SQLite 的單寫者把兩次提交串行化——先落地的那一次是唯一有效結果，
// 後到的拿到 changed=false，整個操作不發生（撤銷時刻沒改、已用次數沒動、審計沒記），
// 也不會把先前那次撤銷悄悄改寫成別的時刻。對已撤銷的碼重複按下是同一句話，
// 界面要的是「重讀這本名冊」而不是「再點一次那顆按鈕」。
//
// 被拒的撤銷（非 Root、目標不在名冊、已被撤銷、併發落敗）一律不追加審計：
// 與被拒的刪除、被拒的審批同一口徑——拒絕的結論不該成為寫入放大器。
package invitecode

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// RevokedCode 是一次成功撤銷的結果：撤銷之後的單碼真相（名冊那一行的形狀，供界面就地改掉那一行）。
//
// Row 是「寫入之後的數據庫現值」（交易內重讀），不是呼叫端意圖的迴音：撤銷之後那一行帶著 revoked
// 派生狀態與撤銷時刻，界面顯示的當前資料必須來自服務端保存的結果。它不含明文碼、也不含驗證材料——
// 撤銷回顯與名冊共用同一個 Row，多一格都沒有。
type RevokedCode struct {
	Row Row
}

// Revoke 以 Root 主體讓一枚邀請碼進入撤銷終態，並在同一個交易裡落一筆 Root 域審計。
//
// 全部寫入落在同一筆交易，順序與每一跳的理由：
//  1. 授權（NeedRoot，與簽發、名冊同一道閘）在交易外：被拒的請求一個查詢都不該多花；
//  2. 交易內核實目標此刻的形態（readCode）：標識命中一行、且它此刻還沒被撤銷——
//     已被撤銷的當場回 ErrAlreadyRevoked，不進那條 UPDATE，也就不寫審計；
//  3. 帶守衛地撤銷（store.Revoke）：changed=false 即回 ErrAlreadyRevoked 並讓交易回滾——
//     撤銷時刻、已用次數、審計三件事沒有一件發生，衝突的撤銷不是「部分成功」；
//  4. 同一交易內重讀經實體校驗的現值並追加 Root 域審計：撤銷與其痕跡同生同滅，
//     「真實撤銷了卻在 Root 域查不到是誰撤的」與「審計說有而庫裡那行還在生效」同罪。
//
// 這一跳不簽發給任何會話、不解除任何獨立的到期或額度事實、不觸碰任何賬戶（理由見套件頭注）。
func (s *Service) Revoke(ctx context.Context, principal identity.Principal,
	codeID idgen.ID, requestID string) (RevokedCode, error) {
	if err := s.requireRoot(principal, "revoke"); err != nil {
		return RevokedCode{}, err
	}
	if codeID.IsNil() {
		return RevokedCode{}, ErrCodeNotFound
	}

	var revoked RevokedCode
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		// 撤銷落庫與審計記錄都問同一個「現在」：狀態派生與撤銷時刻必須來自同一枚注入時鐘的一讀，
		// 否則「撤銷之前的狀態」會與寫進去的那一刻各算各的。
		now := s.clock.Now()
		before, err := s.store.ByID(tctx, tx, codeID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return ErrCodeNotFound
			}
			return err
		}
		// 已帶著撤銷時刻的先出局：重複撤銷是同一句「別再對同一枚已撤銷的碼按第二次」，
		// 與併發落敗收斂到同一個結論，不謊報成功，也不改判先前那次撤銷。
		if !before.RevokedAt.IsZero() {
			return ErrAlreadyRevoked
		}
		changed, err := s.store.Revoke(tctx, tx, codeID)
		if err != nil {
			return err
		}
		if !changed {
			// 讀與寫之間的那個窗口由數據庫的 WHERE 收口：有人在我們之前撤銷了它。
			return ErrAlreadyRevoked
		}
		// 交易內重讀：回顯要的是「撤銷之後的數據庫現值」，不是呼叫端的意圖迴音。
		after, err := s.store.ByID(tctx, tx, codeID)
		if err != nil {
			return err
		}
		rec, err := s.revokeRecord(principal, before, after, now, requestID)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		revoked = RevokedCode{Row: rowOf(after.ID.String(), after.Label, after.MaxUses, after.UsedCount,
			after.CreatedAt, millisOrZero(after.ExpiresAt), millisOrZero(after.RevokedAt), now)}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrCodeNotFound), errors.Is(err, ErrAlreadyRevoked):
			return RevokedCode{}, err
		case errors.Is(err, ErrNotFound):
			// 交易內重讀落空只剩併發的物理清理或程序缺陷：對呼叫端仍是那句「這枚碼不在名冊上」，
			// 但這一條要進日誌，它不是一次正經的拒絕。
			s.log.Error("撤銷邀請碼時目標行消失", "request_id", requestID, "err", err)
			return RevokedCode{}, ErrCodeNotFound
		}
		s.log.Error("撤銷邀請碼處理失敗", "request_id", requestID, "err", err)
		return RevokedCode{}, fmt.Errorf("invitecode: 撤銷邀請碼失敗: %w", err)
	}
	s.log.Info("Root 已撤銷服務器級註冊邀請碼",
		"code", revoked.Row.CodeID, "request_id", requestID)
	return revoked, nil
}

// revokeRecord 產生一筆 Root 域的撤銷審計。口徑與簽發同源：actor 只能經 principal.AuditActor() 換得。
//
// Changes 恰好是 revoked_at 與派生 status 兩格的前後值：撤銷落下的就是「叫停這枚碼」這一個事實，
// 它帶著撤銷時刻、把狀態從（簽發當時的）有效改派生成 revoked。絕不落進記錄的東西：明文碼、
// 驗證材料哈希、任何賬戶資料——撤銷針對的是准入憑證，不是任何一個人，記錄裡因此沒有可外流的東西。
func (s *Service) revokeRecord(principal identity.Principal, before, after InviteCode,
	now time.Time, requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("invitecode: 主體無法換得審計操作者: %w", err)
	}
	return audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  actor,
		Action: "invite.revoke",
		Target: audit.Target{Kind: "registration_invite_code", ID: after.ID.String()},
		Reason: "Root 經已認證會話撤銷服務器級註冊邀請碼：立刻阻止此後任何新的核銷，" +
			"撤銷是單向終態、已核銷的次數作為歷史保留；撤銷憑證不等於撤銷任何已合法建立的賬戶",
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "revoked_at", Before: nullableFormatUTC(before.RevokedAt),
				After: nullableFormatUTC(after.RevokedAt)},
			{Field: "status", Before: before.deriveStatus(now).String(),
				After: StatusRevoked.String()},
		},
	}, nil
}
