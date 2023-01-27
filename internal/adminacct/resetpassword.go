// resetpassword.go 是「Root 重置管理員登入憑據」的應用服務層。
//
// 它與本人改密（internal/auth 的 ChangePassword）是同一張 accounts 表上的兩個
// 不同用例，共用的只有憑據派生（internal/credential）與撤銷通路（internal/session）：
//   - 本人改密的授權錨點是「交得出現行口令」，成功的義務清償把
//     must_change_password 清回 0；
//   - Root 重置他人恰恰發生在「交不出现行口令」的场合：授权锚点是
//     「本次請求換出的主體是 Root，且目標在管理員目錄裡」，成功則把旗標反向
//     設回 1——重置出來的口令是一次性的，首次登入必須改掉（門閂與 2010 沿用
//     R1-019 的服务端闸，这里不另造第二套）。
//
// 把兩件事併進一個方法，任何一側的規則改動都會殃及另一側；分成兩個用例，
// 「重置不是本人改密、本人改密不是重置」就成立在型別上。
//
// 一次成功重置落地的是三件事的合力，缺一件都是半套：
//   - 舊口令失效：password_hash 被整欄換掉，拿舊明文永遠過不了 Verify；
//   - 舊會話失效：同交易 RevokeAccount 落庫 revoked_at，「改密即全部會話退出」
//     沿用 R1-019 批准的口徑（含本人此刻在其它裝置上的會話）；
//   - 首次改密義務生效：must_change_password=1 與新哈希同一條 UPDATE 寫入。
//
// 重置不改的事實同樣必須如實列出：停用狀態保持原樣（UPDATE 語句裡沒有
// status 與 disabled_at 兩欄，「重置不是解除停用」成立在 SQL 形狀上）、
// 授予與目錄成員資格不動（重置不是撤權）、帳戶資料不動（重置不是改名）、
// 已物理刪除的目標與幽靈標識同回查無（重置不是復出通路）。
//
// 併發與重複請求：本用例刻意沒有 CAS 依據值——Root 拿不出「現行雜湊」這樣的
// 錨點，而任何湊出來的依據值（拿狀態、拿顯示名當錨）驗證的不是它宣稱的東西。
// SQLite 單寫入者把每次重置串行化，每一次成功都是完整的「換哈希＋撤會話＋審計」，
// 後到的重置覆蓋先前的哈希是既定順序的事實而不是半套狀態；因此重複提交
// 「同一份重置」會如實再做一次（再撤一輪可能新簽發的會話、再留一筆審計），
// 界面據此不得在結果不明時自動重發（那是又一次真實的重置）。
//
// 目標不能是 Root：Root 不落帳戶表，任何以 Root 保留標識為目標的請求過不了
// 目錄成員資格檢查，與「查無此人」收斂成同一個結論（ErrAdminNotFound）。
// 管理員重置其他管理員不在這條通路裡：授權只經 identity.NeedRoot。
package adminacct

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

// 重置用例的結論錯誤：口令形狀不合格與目標不在目錄各自可判別，
// 內部故障一律不進這些型別。
var (
	// ErrInvalidResetPassword 表示 Root 交出的新口令不滿足憑據模組的形狀界線
	// （空或超長）。它是請求本體的問題，屬呼叫端可修正的輸入錯誤，
	// 與開設用例的 ErrInvalidInitialPassword 分開只為訊息各自點名自己的場合，
	// 兩者的判定來自同一個實作點（internal/credential.Hash）。
	ErrInvalidResetPassword = errors.New("adminacct: 重置口令不滿足憑據形狀界線")
)

// PasswordReset 是一次成功重置的結果：更新後的單筆真相加撤銷數量。
type PasswordReset struct {
	// Profile 為重置後經實體校驗的單筆資料（與詳情同形；must_change_password 恆為 true）。
	Profile Profile
	// RevokedSessions 為這次撤銷的會話數量。存在的理由與停用同形：界面要能
	// 如實說出「這次讓 N 臺裝置重新登入」，不許界面自己猜。對停用中的目標
	// 這個數通常是 0（其會話早在停用時已撤）——0 是事實，不是失敗。
	RevokedSessions int
}

// ResetAdminPassword 以 Root 主體重置一名目錄內管理員的登入憑據。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 授權（NeedRoot，與開設、目錄、編輯、停用同一道閘）在交易外：
//     被拒的請求一個查詢都不該多花；
//  2. 口令派生放在交易之外：Argon2id 按生產參數檔是數百毫秒級的計算，
//     與 CreateAdmin 同一理由——一次慢派生不該讓全服停筆。
//     派生失敗（空口令、超長口令）在此回輸入錯誤，一條寫入都沒有發生；
//  3. 交易內 readProfile：帳戶存在與目錄成員資格一起核實，對不在目錄裡的標識
//     整個操作不發生；「已物理刪除的帳戶」在這裡自然得到同一個結論；
//  4. 強制換哈希（SetPassword）：旗標與哈希同一條 UPDATE，「換口令」與
//     「下次登入必須改密」是同一個事實的兩面，不存在改完還欠清另一半的窗口；
//     零行命中回查無同形並讓交易回滾——「一個字沒寫」不報成功；
//  5. 同交易撤銷目標全部會話：「重置使舊會話失效」因此是落庫的事實，
//     與停用那一步同一個執行手段（session.RevokeAccount）；
//  6. 同交易重讀並追加 Root 域審計：變更與其審計同生同滅。
//
// 被拒的重置（非 Root、非目錄成員、口令形狀不合格）不追加審計：
// 與被拒的開設、編輯、停用同口徑——拒絕的結論不該成為寫入放大器。
func (s *Service) ResetAdminPassword(ctx context.Context, principal identity.Principal,
	accountID idgen.ID, newPassword, requestID string) (PasswordReset, error) {
	if err := identity.Authorize(principal, identity.NeedRoot); err != nil {
		s.log.Warn("重置管理員憑據被拒：主體不具備 Root 權限",
			"subject", principal.String(), "request_id", requestID)
		return PasswordReset{}, err
	}
	if accountID.IsNil() {
		return PasswordReset{}, ErrAdminNotFound
	}

	passwordHash, err := credential.Hash(newPassword, s.hashing)
	if err != nil {
		var hashErr *credential.HashError
		if errors.As(err, &hashErr) {
			// 可展示的原因（空口令／超長）進結論；訊息本身不含任何口令材料。
			return PasswordReset{}, fmt.Errorf("%w：%v", ErrInvalidResetPassword, hashErr.Reason)
		}
		return PasswordReset{}, fmt.Errorf("adminacct: 產生重置憑據雜湊失敗: %w", err)
	}

	var result PasswordReset
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		before, err := s.readProfile(tctx, tx, accountID)
		if err != nil {
			return err
		}
		// 已刪除的帳戶不進這條通路：重置憑據的意義是「讓一個還能上任的人換一把一次性口令」，
		// 對一個不再可登入且不再可恢復的帳戶交出口令，交出去的那一句話沒有接受者。
		// 判定在派生之後、寫入之前：被拒的重置一個字都不落，也不留審計。
		if err := requireNotDeleted(before); err != nil {
			return err
		}
		changed, err := s.accounts.SetPassword(tctx, tx, accountID, passwordHash)
		if err != nil {
			return err
		}
		if !changed {
			// 交易內剛讀到、轉眼寫不中：目標已被物理刪除一類的前提失效。
			// 對外的句子與查無同形——重置不回報「差哪一半」。
			return ErrAdminNotFound
		}
		revoked, err := s.sessions.RevokeAccount(tctx, tx, accountID)
		if err != nil {
			return err
		}
		// 交易內重讀：回應要的是「重置之後的資料庫現值」，不是呼叫端的意圖回音。
		after, err := s.readProfile(tctx, tx, accountID)
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
		result = PasswordReset{Profile: after, RevokedSessions: revoked}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, account.ErrNotFound), errors.Is(err, grant.ErrNotFound):
			return PasswordReset{}, ErrAdminNotFound
		case errors.Is(err, ErrAdminNotFound), errors.Is(err, ErrInvalidResetPassword),
			errors.Is(err, ErrAdminDeleted):
			return PasswordReset{}, err
		}
		s.log.Error("重置管理員憑據失敗", "request_id", requestID, "err", err)
		return PasswordReset{}, fmt.Errorf("adminacct: 重置管理員憑據失敗: %w", err)
	}
	s.log.Info("Root 已重置管理員登入憑據（舊口令與既有會話失效，舊停用狀態未變）",
		"account", result.Profile.AccountID.String(),
		"revoked_sessions", result.RevokedSessions, "request_id", requestID)
	return result, nil
}

// passwordResetRecord 產生一筆 Root 域的重置審計。口徑與 creationRecord 同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆重置回滾。
//
// 絕不落進記錄的東西：新口令明文、舊口令明文（服務端本來就不知道）、
// 任何一侧的 Argon2id 雜湊、會話秘密。Changes 刻意不帶任何 password 字樣以外
// 憑據欄位的值——連「password_hash 前後值」都不記（那是兩串不可展示的東西），
// 記錄的是可展示的義務事實：改密旗標的前後值與這次撤銷的會話數量。
func (s *Service) passwordResetRecord(principal identity.Principal, before, after Profile,
	revoked int, requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("adminacct: 主體無法換得審計操作者: %w", err)
	}
	return audit.Record{
		Scope:     audit.ScopeRoot,
		Actor:     actor,
		Action:    "admin.password_reset",
		Target:    audit.Target{Kind: "account", ID: after.AccountID.String()},
		Reason:    "Root 經已認證會話重置伺服器級管理員的登入憑據：舊口令與既有會話失效，首次登入須改密，停用狀態不變",
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "must_change_password", Before: before.MustChangePassword,
				After: after.MustChangePassword},
			{Field: "revoked_sessions", Before: nil, After: revoked},
		},
	}, nil
}
