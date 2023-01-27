// deleted.go 是「Root 軟刪除管理員帳戶」的應用服務層。
//
// 刪除與停用是兩個不同的狀態，這件事必須成立在資料形狀與通路上，不是成立在文案上：
//   - 停用（status.go）回答的是「他的登入能力暫時開還是關」，兩側都是可逆的，
//     恢復登入是他本來就能拿到的東西；
//   - 刪除（本檔）回答的是「這個人不再是一個可用的帳戶，但我們不假裝他沒存在過」。
//     它是一個終態：行保留、登入名鍵保留（因此名字不可被復用）、授予與會話行保留，
//     而「恢復登入」那條通路對他一律拒絕（見 requireNotDeleted 在 status.go 的落點）。
//
// 保留行是本步全部價值的落點：root_audit 的 actor_id／target_id 存的是帳戶標識，
// 而審計是只追加存儲（遷移 0002）——把人物理刪掉，等於讓那段歷史裡的操作者
// 指向一個查不到的標識，或者更糟：讓後人把舊責任算到後來搶到同一個名字的帳戶頭上。
// 因此本用例不寫 NULL、不做級聯、不把原操作歸到 Root 名下，也不動任何一條既有審計。
//
// 一次成功刪除落地的是三件事的合力，缺一件都是半套：
//   - 新登入被拒：status 落為 deleted，而全部既有的閘都是「非 active 即拒」
//     （internal/auth 的登入、internal/session 的簽發與逐請求現讀、internal/identity
//     的主體構造），所以「刪除使人不能登入」不需要任何一處新增特例；
//   - 舊會話失效：同交易 RevokeAccount 落庫 revoked_at，與停用、重置同一把刀
//     （session.RevokeAccount），不另造第二套撤銷語意；
//   - 顯示名匿名化：同一條 UPDATE 把 display_name 換成 account.AnonymizedDisplayName
//     派生的佔位值（規則只有域層一份）。這是「活的投影不再顯示本人自取的名字」，
//     不是「把歷史抹掉」：已寫下的只追加審計裡那些舊顯示名照舊查得到，
//     本用例不碰、也碰不到它們。
//
// 併發與重複請求：本用例刻意沒有 CAS 依據值（用戶批準）。Root 對「現行刪除時刻」
// 拿不出任何誠實的錨點——未被刪除時那一欄本來就是 NULL，湊一個依據值驗證的
// 也不是它宣稱的東西。正當性錨在狀態機守衛上（MarkDeleted 的 WHERE deleted_at IS NULL）：
// 第二次刪除寫不中任何一行，於是被判為「他已經是刪除態」而不是謊報「又刪了一次」。
// SQLite 單寫入者把兩次刪除串行化，贏家留一整筆事實（換態＋撤會話＋審計），
// 輸家零寫入零審計；這與重置憑據那條「重複即再做一次」的語意不同，因為刪除
// 本身就只允許發生一次。
//
// 目標不能是 Root：Root 不落帳戶表（R1-004 決定），任何以 Root 保留標識或幽靈標識
// 為目標的請求都過不了目錄成員資格檢查，與「查無此人」收斂成同一個結論
// （ErrAdminNotFound）。「把配置裡的 Root 憑據刪掉」在這條通路上沒有一個可填的格子。
// 管理員刪除其他管理員同樣不在這條通路裡：授權只經 identity.NeedRoot。
package adminacct

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

// 刪除用例的結論錯誤：目標已是刪除態與目標不在目錄各自可判別，
// 內部故障一律不進這些型別。
var (
	// ErrAdminDeleted 表示目標在目錄裡、但已是刪除終態：本次處置沒有可發生的對象。
	//
	// 它與 ErrAdminNotFound 分開只為一件事：兩句話的處置不同——一個是「這個人不在
	// 這本目錄裡，換個目標」，另一個是「你看著的那個人已經被刪掉了，別再對他下任何
	// 寫入令」。把後者報成 1001，Root 會對著一個目錄裏明明列著的人反覆懷疑標識寫錯了；
	// 把它報成成功，則是在審計與真相之間造出一件沒發生過的事。
	//
	// 它對外的可見範圍只有 Root（本套件全部入口都經 NeedRoot），因此不構成
	// 任何人可用的帳戶列舉信號：能收到這句話的人已經是目錄的所有者。
	ErrAdminDeleted = errors.New("adminacct: 該帳戶已被刪除")
)

// Deletion 是一次成功刪除的結果：刪除後的單筆真相加撤銷數量。
type Deletion struct {
	// Profile 為刪除後經實體校驗的單筆資料（status 恆為 deleted，display_name 為佔位值）。
	Profile Profile
	// RevokedSessions 為這次撤銷的會話數量：界面要能如實說出「這次讓 N 臺裝置
	// 失去登入狀態」，而不是讓 Root 對著一句「已刪除」猜影響範圍。
	// 對一個早就停用的目標這個數通常是 0（其會話早在停用時已撤）——0 是事實，不是失敗。
	RevokedSessions int
}

// DeleteAdmin 以 Root 主體軟刪除一名目錄內管理員的帳戶：停止登入、撤銷其有效會話、
// 顯示名匿名化，而行、登入名鍵、授予與歷史參照一律保留。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 授權（NeedRoot，與開設、目錄、編輯、停用、重置同一道閘）與標識檢查在交易外：
//     被拒的請求一個查詢都不該多花；零值標識直接回查無同形，不去問資料庫；
//  2. 交易內 readProfile：帳戶存在與目錄成員資格一起核實。已刪除的目標在這裡
//     仍然讀得到（Root 需要查得出「當年那個人是誰」），所以它是本檔第二道閘的落點：
//     requireNotDeleted 當場把刪除態的目標擋下，整個操作不發生；
//  3. MarkDeleted 以狀態機守衛寫入終態（WHERE deleted_at IS NULL）：零行命中即回
//     ErrAdminDeleted 並讓交易回滾——「一個字都沒寫」不報刪除成功；
//  4. 同交易撤銷目標全部會話：「刪除使舊會話立刻失效」因此是落庫的事實，
//     不是每次現讀推導出來的口頭承諾（現讀仍在那裡，兩者不互相代替）；
//  5. 同交易重讀並追加 Root 域審計：刪除與其審計同生同滅。
//
// 被拒的刪除（非 Root、非目錄成員、已是刪除態）不追加審計：
// 與被拒的開設、編輯、停用、重置同口徑——拒絕的結論不該成為寫入放大器。
func (s *Service) DeleteAdmin(ctx context.Context, principal identity.Principal,
	accountID idgen.ID, requestID string) (Deletion, error) {
	if err := identity.Authorize(principal, identity.NeedRoot); err != nil {
		s.log.Warn("刪除管理員被拒：主體不具備 Root 權限",
			"subject", principal.String(), "request_id", requestID)
		return Deletion{}, err
	}
	if accountID.IsNil() {
		return Deletion{}, ErrAdminNotFound
	}

	var result Deletion
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		before, err := s.readProfile(tctx, tx, accountID)
		if err != nil {
			return err
		}
		if err := requireNotDeleted(before); err != nil {
			return err
		}
		// 派生所需的現值來自同一交易內剛讀到的那一行：不另查一次，
		// 也不讓呼叫端自己拼佔位字串（規則只有域層一份）。
		changed, err := s.accounts.MarkDeleted(tctx, tx, accountID, before.DisplayName)
		if err != nil {
			return err
		}
		if !changed {
			// 交易內剛讀到還不是刪除態、轉眼寫不中：併發的另一次刪除先到了。
			// 對外的句子與「他已經是刪除態」同一句話——兩次刪除只應有一次成功。
			return ErrAdminDeleted
		}
		revoked, err := s.sessions.RevokeAccount(tctx, tx, accountID)
		if err != nil {
			return err
		}
		// 交易內重讀：回應要的是「刪除之後的資料庫現值」，不是呼叫端的意圖回音。
		after, err := s.readProfile(tctx, tx, accountID)
		if err != nil {
			return err
		}
		rec, err := s.deletionRecord(principal, before, after, revoked, requestID)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		result = Deletion{Profile: after, RevokedSessions: revoked}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, account.ErrNotFound), errors.Is(err, grant.ErrNotFound):
			return Deletion{}, ErrAdminNotFound
		case errors.Is(err, ErrAdminDeleted), errors.Is(err, ErrAdminNotFound):
			return Deletion{}, err
		}
		s.log.Error("刪除管理員失敗", "request_id", requestID, "err", err)
		return Deletion{}, fmt.Errorf("adminacct: 刪除管理員失敗: %w", err)
	}
	s.log.Info("Root 已軟刪除管理員帳戶（新登入被拒、既有會話撤銷、顯示名匿名化，行與登入名保留）",
		"account", result.Profile.AccountID.String(),
		"revoked_sessions", result.RevokedSessions, "request_id", requestID)
	return result, nil
}

// requireNotDeleted 是「刪除態不接受任何寫入」這條規則唯一的判定點。
//
// 它必須存在成一個函式而不是在三處各比一次：編輯資料、停用/恢復、重置憑據
// 三個用例都要問同一句話，而「已刪除的人還能不能被改名字」這類問題
// 只要有兩套答案，就一定有一套被繞過。
//
// 判定讀的是現值而不是呼叫端交來的宣稱：請求本體裡沒有任何欄位可以把自己
// 寫成「我以為他還活著」。
func requireNotDeleted(target Profile) error {
	if target.Status == account.StatusDeleted {
		return fmt.Errorf("%w：%s", ErrAdminDeleted, target.AccountID.String())
	}
	return nil
}

// deletionRecord 產生一筆 Root 域的刪除審計。口徑與其餘寫入同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆刪除回滾。
//
// 「刪除前身份快照」記的是哪些：login_name、刪除前的 display_name、刪除前的 status、
// 以及 deleted_at 這個時刻。前兩項在這次寫入裡可能看起來「沒變」或「將不存在」，
// 但它們正是這一筆存在的理由——行保留、只追加的表不可改，而界面與運維都要能回答
// 「這個人當時叫什麼、以什麼狀態被刪」。
//
// 絕不落進記錄的東西：憑據雜湊（任何一側）、口令明文、會話秘密或其標識。
// revoked_sessions 是數量而不是清單——逐條撤銷的事實在 sessions 表的 revoked_at 裡。
func (s *Service) deletionRecord(principal identity.Principal, before, after Profile,
	revoked int, requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("adminacct: 主體無法換得審計操作者: %w", err)
	}
	return audit.Record{
		Scope:     audit.ScopeRoot,
		Actor:     actor,
		Action:    "admin.delete",
		Target:    audit.Target{Kind: "account", ID: after.AccountID.String()},
		Reason:    "Root 經已認證會話軟刪除伺服器級管理員帳戶：新登入被拒、既有會話全部撤銷、顯示名匿名化；帳戶行與登入名保留以承載歷史身份",
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "login_name", Before: before.LoginName, After: after.LoginName},
			{Field: "display_name", Before: before.DisplayName, After: after.DisplayName},
			{Field: "status", Before: before.Status.String(), After: after.Status.String()},
			{Field: "deleted_at", Before: nullableFormatUTC(before.DeletedAt),
				After: nullableFormatUTC(after.DeletedAt)},
			{Field: "revoked_sessions", Before: nil, After: revoked},
		},
	}, nil
}
