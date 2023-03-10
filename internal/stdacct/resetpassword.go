// resetpassword.go 是「管理員重置普通帳戶登入憑據」的應用服務層。
//
// 它與 Root 重置管理員憑據（internal/adminacct/resetpassword.go）是三件事裡的两件：
// 兩者共用同一個強制換哈希的倉儲寫法（account.Store.SetPassword）與同一把撤銷刀
// （session.RevokeAccount），也共用「重置不是本人改密」這條用例分界；
// 不同的是授權閘與目標範圍——那一側經 NeedRoot 且只認管理員目錄，
// 這一側經 NeedServerAdmin（與建號、目錄、資料編輯、停用、刪除同一道閘）且目標範圍
// 逐字沿用本套件的範圍規則：不持有 server_admin 授予、不在審批鏈門外、未進入任何終態。
// 因此一位管理員拿這條通路動不了另一位管理員，也動不了他自己，更動不到 Root
// （Root 本来就不落 accounts 表）——那些形態與查無此人收斂成同一個 ErrAccountNotFound；
// 而已刪除與已退休的帳戶就在這本目錄裡，他們各自得到自己那句拒絕（2027／2028），
// 而不是被「換個目標」誤導。
//
// 一次成功重置落地的是三件事的合力，缺一件都是半套：
//   - 舊口令失效：password_hash 整欄換掉，拿舊明文永遠過不了 Verify；
//   - 舊會話失效：同交易 RevokeAccount 落庫 revoked_at，「改密即全部會話退出」
//     沿用 R1-019 批准的口徑（含本人此刻在其它裝置上的會話）；
//   - 首次改密義務生效：must_change_password=1 與新哈希同一條 UPDATE 寫入——
//     交付出去的那個口令只用一次，本人首次登入必須改掉（門閂與 2010 沿用既有閘）。
//
// 重置不改的事實同樣必須如實列出：停用狀態保持原樣（UPDATE 語句裡沒有 status 與
// disabled_at 兩欄，「重置不是解除停用」成立在 SQL 形狀上）、授予與顯示名與刪除時刻
// 都不動（重置不是復活、不是撤權、不是改名，而兩個終態根本進不到這條通路）、尚未完成的首次改密義務不會被清掉
// （這一步是把旗標寫成 1，不是把它歸零）。換言之：一個待审批（欠首改）的人被重置之後
// 仍然欠首改，一個被停用的人被重置之後仍然登不進去——想解開那兩件事各有自己的通路。
//
// 訪戶帳戶（account_type=guest）不在這條通路裡：遷移 0003 的 CHECK 把他凍結成
// 「無雜湊、無旗標」，這裡若真把哈希寫進去，就是讓「重置憑據」這個動詞偷偷完成了一次
// 訪戶→普通的升級綁定——那既不是本步批准的范围，也不該由一條安全欄位的 PUT 順手決定。
// 判定讀的是剛核實過範圍那一行的 type，不额外多查一次；出局点在寫入之前，
// 所以被拒的重置一個字都不落、也不留審計。對外的結論是獨立的一枚
// （ErrGuestTarget → 2018），因為處置與「改改口令寫法」「換個目標」都不是同一句話：
// 要動的是身分而不是一欄口令，那條通路現在存在了——同一本目錄下的
// PUT /admin/accounts/{account_id}/upgrade（見 upgrade.go），而它不是這條 PUT 的順帶效果。
//
// 併發與重複請求：與 Root 那一側同樣刻意沒有 CAS 依據值——操作者拿不出「現行雜湊」
// 這類誠實的錨點，任何湊出來的依據值驗證的不是它宣稱的東西。SQLite 單寫入者把每次重置
// 串行化，每一次成功都是完整的「換哈希＋撤會話＋審計」；重複提交是如實再做一次重置
// （再撤一輪可能新簽發的會話、再留一筆審計），界面據此不得在結果不明時自動重發。
//
// 交付語意沿用 Root 開設管理員與重置管理員時用戶批准的形態：一次性口令由操作者親自交，
// 伺服器不生成、不在任何回應裡回顯、不設默認口令；線下交付管道在協議之外。
package stdacct

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// 重置用例的結論錯誤：口令形狀不合格與目標形態不合各自可判別，內部故障一律不進這些型別。
// 「目標不在本目錄」不另發一型：沿用詳情、編輯、停用同一枚 ErrAccountNotFound，
// 因為這幾條通路對「他是管理員／他還在門外／查無此人」的回答本來就是同一句話。
// 已刪除與已退休不在這句裡：他們在本目錄之內，各回自己的那枚結論。
var (
	// ErrInvalidResetPassword 表示操作者交出的新口令不滿足憑據模組的形狀界線（空或超長）。
	//
	// 它與建號那側的 ErrInvalidInitialPassword 分開只為訊息各自點名自己的場合，
	// 兩者的判定來自同一個實作點（internal/credential.Hash）。
	ErrInvalidResetPassword = errors.New("stdacct: 重置口令不滿足憑據形狀界線")
	// ErrGuestTarget 表示目標是訪戶帳戶：他今日沒有可置換的一般密碼，
	// 沿這條通路寫入哈希等於把訪戶隱式升級成普通帳戶，而那該由後續一條明確的
	// 升級通路決定。它是目標形態的出局條件，不是權限問題（換身分沒用）、
	// 也不是請求寫法問題（改口令沒用）——傳輸層據此回 2018，不降級成 1001，
	// 因為本目錄按定義把他列得進去，「換個目標」根本不是處置。
	ErrGuestTarget = errors.New("stdacct: 訪戶帳戶沒有可重置的登入憑據")
)

// StandardPasswordReset 是一次成功重置的結果：更新後的單筆真相加撤銷數量。
type StandardPasswordReset struct {
	// Profile 為重置後經實體校驗的單筆資料（與詳情同形；must_change_password 恆為 true）。
	Profile StandardProfile
	// RevokedSessions 為這次撤銷的會話數量。存在的理由與停用同形：界面要能如實說出
	// 「這次讓 N 臺裝置重新登入」，不許界面自己猜。對停用中的目標這個數通常是 0
	// （其會話早在停用時已撤）——0 是事實，不是失敗。
	RevokedSessions int
}

// ResetStandardAccountPassword 以持有伺服器級管理權的受信主體重置一名目錄內
// 普通帳戶的登入憑據。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 授權（NeedServerAdmin）與零值標識在交易外：被拒的請求一個查詢都不該多花；
//  2. 口令派生放在交易之外：Argon2id 按生產參數檔是數百毫秒級的計算，
//     與建號、Root 重置管理員同一理由——一次慢派生不該讓全服停筆。
//     派生失敗（空口令、超長口令）在此回輸入錯誤，一條寫入都沒有發生；
//  3. 交易內 readStandardProfile：帳戶存在、是否持有授予、是否還在審批鏈門外
//     三道範圍檢查一起核實，對不在本目錄的標識整個操作不發生；
//     已刪除與已退休都在這裡讀得到，由緊隨的 requireNotTerminal 回自己那句話
//     （他們就在這本目錄裡，說「換個目標」是誤導，而撞庫的觸發器只會換成 500）；
//  4. 訪戶帳戶在這裡出局（寫入之前）：一行的 type 是剛讀回來的事實，
//     不再多查一次；被拒的重置零寫入、零撤銷、零審計；
//  5. 強制換哈希（SetPassword）：旗標與哈希同一條 UPDATE，「換口令」與
//     「下次登入必須改密」是同一個事實的兩面，不存在改完還欠清另一半的窗口；
//     零行命中回查無同形並讓交易回滾——「一個字沒寫」不報成功；
//  6. 同交易撤銷目標全部會話：「重置使舊會話失效」因此是落庫的事實，
//     與停用那一步同一個執行手段（session.RevokeAccount）；
//  7. 同交易重讀並追加 Root 域審計：變更與其審計同生同滅。
//
// 被拒的重置（非管理員、不在目錄、終態目標、訪戶目標、口令形狀不合格）不追加審計：
// 與被拒的建號、編輯、停用、Root 重置管理員同口徑——拒絕的結論不該成為寫入放大器。
func (s *Service) ResetStandardAccountPassword(ctx context.Context, principal identity.Principal,
	accountID idgen.ID, newPassword, requestID string) (StandardPasswordReset, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		s.log.Warn("重置普通帳戶憑據被拒：主體不具備伺服器級管理權",
			"subject", principal.String(), "request_id", requestID)
		return StandardPasswordReset{}, err
	}
	if accountID.IsNil() {
		return StandardPasswordReset{}, ErrAccountNotFound
	}

	passwordHash, err := credential.Hash(newPassword, s.hashing)
	if err != nil {
		var hashErr *credential.HashError
		if errors.As(err, &hashErr) {
			// 可展示的原因（空口令／超長）進結論；訊息本身不含任何口令材料。
			return StandardPasswordReset{}, fmt.Errorf("%w：%v", ErrInvalidResetPassword, hashErr.Reason)
		}
		return StandardPasswordReset{}, fmt.Errorf("stdacct: 產生重置憑據雜湊失敗: %w", err)
	}

	var result StandardPasswordReset
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		before, err := s.readStandardProfile(tctx, tx, accountID)
		if err != nil {
			return err
		}
		// 終態判定在類型判定之前：一個已退休的訪戶該拿到的是「他已被綁走」那一句，
		// 而不是「他是訪戶、重置要等升級通路」——後者對他是一句不會兌現的等待。
		if err := requireNotTerminal(before); err != nil {
			return err
		}
		if before.Type == account.TypeGuest {
			return ErrGuestTarget
		}
		changed, err := s.accounts.SetPassword(tctx, tx, accountID, passwordHash)
		if err != nil {
			return err
		}
		if !changed {
			// 交易內剛讀到、轉眼寫不中：目標已被物理刪除一類的前提失效。
			// 對外的句子與查無同形——重置不回報「差哪一半」。
			return ErrAccountNotFound
		}
		revoked, err := s.sessions.RevokeAccount(tctx, tx, accountID)
		if err != nil {
			return err
		}
		// 交易內重讀：回應要的是「重置之後的資料庫現值」，不是呼叫端的意圖回音。
		after, err := s.readStandardProfile(tctx, tx, accountID)
		if err != nil {
			return err
		}
		rec, err := s.passwordResetRecord(principal, before, after, revoked, requestID)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		result = StandardPasswordReset{Profile: after, RevokedSessions: revoked}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, account.ErrNotFound), errors.Is(err, grant.ErrNotFound):
			return StandardPasswordReset{}, ErrAccountNotFound
		case errors.Is(err, ErrAccountNotFound), errors.Is(err, ErrGuestTarget),
			errors.Is(err, ErrInvalidResetPassword), errors.Is(err, ErrAccountDeleted),
			errors.Is(err, ErrAccountRetired):
			return StandardPasswordReset{}, err
		}
		s.log.Error("重置普通帳戶憑據失敗", "request_id", requestID, "err", err)
		return StandardPasswordReset{}, fmt.Errorf("stdacct: 重置普通帳戶憑據失敗: %w", err)
	}
	s.log.Info("已重置普通帳戶登入憑據（舊口令與既有會話失效，停用狀態未變）",
		"account", result.Profile.AccountID.String(),
		"revoked_sessions", result.RevokedSessions, "request_id", requestID)
	return result, nil
}

// passwordResetRecord 產生一筆 Root 域的重置審計。口徑與 statusChangeRecord 同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆重置回滾。
//
// 動作名沿用本套件的 account. 前綴（動的是普通帳戶），與管理員那組 admin.password_reset 分家；
// ScopeRoot 而不捏造 activity_id：重置一個伺服器級帳戶的登入能力不屬於任何活動。
//
// 絕不落進記錄的東西：新口令明文、舊口令明文（服務端本來就不知道）、
// 任何一側的 Argon2id 雜湊、會話秘密。Changes 刻意不帶任何可能容下憑據材料的格子——
// 記的是可展示的義務事實：改密旗標的前後值與這次撤銷的會話數量。
func (s *Service) passwordResetRecord(principal identity.Principal, before, after StandardProfile,
	revoked int, requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("stdacct: 主體無法換得審計操作者: %w", err)
	}
	return audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  actor,
		Action: "account.password_reset",
		Target: audit.Target{Kind: "account", ID: after.AccountID.String()},
		Reason: "伺服器級管理員經已認證會話重置普通帳戶的登入憑據：舊口令與既有會話失效，" +
			"首次登入須改密，停用狀態不變（已刪除與已退休的終態目標進不到這條通路）",
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "must_change_password", Before: before.MustChangePassword,
				After: after.MustChangePassword},
			{Field: "revoked_sessions", Before: nil, After: revoked},
		},
	}, nil
}
