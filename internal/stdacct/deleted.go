// deleted.go 是「伺服器級管理員軟刪除普通帳戶或訪戶帳戶」的應用服務層。
//
// 這一檔動的是 Root 那側已批准的同一個終態（accounts.status 的 deleted 與 deleted_at，
// 見遷移 0007），差的是誰來動與動誰：
//   - internal/adminacct/deleted.go 回答「Root 如何處置一本管理員名冊裡的人」，
//     授權邊界是 NeedRoot，目標必須持有伺服器級授予；
//   - 本檔回答「管理員如何處置他服務的那本普通帳戶與訪戶名冊」，授權邊界是
//     NeedServerAdmin，而目標範圍恰恰是「把持有授予的人排掉」。
//
// 兩條通路各自獨立核實操作者管理範圍與目標類型，因此「普通管理員借一條統一的刪除
// 接口去刪另一位管理員或 Root」在協定層與用例層都沒有落點：他打的這條端點
// 對管理員標識只會拿到與查無此人同一句話（ErrAccountNotFound），而 Root 根本
// 不落 accounts 表。把兩件事合成一條端點才會逼出「同一個 Service 上兩套範圍規則」，
// 那是權限語意最容易互相污染的形態。
//
// 刪除在這裡是一句關於「整台伺服器的登入能力」的話，不是一句活動內的話：
// 一次成功刪除同時收走這個帳戶在所有活動、所有裝置上的登入能力，而它不碰、
// 也無力碰任何活動作用域的限制（活動尚未實作，AuthorizeActivityScope 那把閘還在
// 未來）。界面必須把這個影響範圍講清楚，而授權不足的請求不能靠一顆確認按鈕補足——
// 判定只發生在本方法第一行的 identity.Authorize 與交易內的範圍核實。
//
// 可刪除的目標只有「在這本目錄裡、且此刻還能被處置」的兩態：active 與 disabled。
// 其餘每一種都有自己出局的一句话，而且各是各的處置，不能互相冒充：
//   - pending／rejected：他還在門外，那本名冊是 internal/acctreview 的書，
//     本目錄按定義列不到他，這裡也照樣收斂成 ErrAccountNotFound（1001）——
//     「換個目標」對兩個狀態都是正確處置，而審批那條通路是另一句話；
//   - retired：已被綁走的訪戶。他是終態，而且庫裡把他每一欄都釘住了
//     （accounts_retired_no_update）——本方法在寫入之前就回 ErrAccountRetired，
//     不是讓他撞觸發器換一個 500。那句處置與「已被刪除」不同形：他還在，
//     以另一個人的一部分存在著，留痕查得到，而沒有任何通路能讓他重新可用；
//   - deleted：已是刪除終態。第二次刪除沒有可發生的對象，回 ErrAccountDeleted，
//     既不重複撤銷會話也不追加第二筆審計。
//
// 「已綁定的源訪戶」這一路要特別說清：本通路永不級聯。刪掉綁定的目標帳戶，
// 那條 guest_account_bindings 留痕、那個 retired 的源頭行、以及源頭占用的登入名
// 一個字都不動——刪除使一行的活的投影轉為只讀，不是把兩個身份的指向搬回來。
// 反過來說，源訪戶那一行本來就不可刪除，因此「先刪源頭再說目标」這種順序
// 在這裡並不存在。
//
// 一次成功刪除落地的是三件事的合力，缺一件都是半套（與 Root 那側逐字同形）：
//   - 新登入被拒：status 落為 deleted，而全部既有的閘都是「非 active 即拒」
//     （internal/auth 的登入、internal/session 的簽發與逐請求現讀、internal/identity
//     的主體構造），所以「刪除使人不能登入」不需要任何一處新增特例；
//   - 舊會話失效：同交易 RevokeAccount 落庫 revoked_at，與停用、重置、升級同一把刀，
//     訪戶那一趟臨時會話也一起被撤（本目錄的範圍本來就把訪戶算在內）；
//   - 顯示名匿名化：同一條 UPDATE 把 display_name 換成 account.AnonymizedDisplayName
//     派生的佔位值（規則只有域層一份）。這是「活的投影不再顯示本人自取的名字」，
//     不是「把歷史抹掉」：已寫下的只追加審計與綁定留痕裡那些舊名字照舊查得到，
//     本用例不碰、也碰不到它們。
//
// 保留行與保留登入名是本步全部價值的落點：帳戶標識是歷史審計、會話、授予與
// 綁定留痕共同指向的主體，而登入名繼續被占用意味著「後來的人搶不到同一個名字」，
// 於是舊責任不會被算到新頭上。因此本用例不寫 NULL、不做級聯、不把原操作歸到
// 管理員或 Root 名下，也不動任何一條既有審計。物理清庫與任何自動保留期任務
// 都不在本通路之內（那一步要自己回答引用怎麼處置）。
//
// 併發與重複請求：本用例刻意沒有 CAS 依據值（沿用 Root 那侧的用戶批准）——操作者對
// 「現行刪除時刻」拿不出任何誠實的錨點。正當性錨在狀態機守衛上（MarkDeleted 的
// WHERE deleted_at IS NULL）：第二次刪除寫不中任何一行，於是被判為「他已經是刪除態」
// 而不是謊報「又刪了一次」。SQLite 單寫入者把並發的兩次刪除串行化，贏家留一整筆事實
// （換態＋撤會話＋審計），輸家零寫入零審計。與刪除交錯的其餘寫入（本人的改密、
// 審批決定、升級、綁定執行與簽發）都由各自通路在交易內的現讀＋形態判定回答：
// 刪除先落地時它们一律拿終態拒絕，它們先落地時刪除拿的是「他已經不是你確認時那樣」
// 的那一句——兩個方向都有可解釋的結論，沒有一個方向會写出半筆事實。
package stdacct

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

// 刪除用例的結論錯誤：目標已是刪除終態、目標已是退休終態與目標不在本目錄
// 各自可判別，內部故障一律不進這些型別。
var (
	// ErrAccountDeleted 表示目標在目錄裡、但已是刪除終態：本次處置沒有可發生的對象。
	//
	// 它與 ErrAccountNotFound 分開只為一件事：兩句話的處置不同——一個是「這個人不在
	// 這本目錄裡，換個目標」，另一個是「你看著的這個人已經被刪掉了，別再對他下任何
	// 寫入令」。把後者報成 1001，管理員會對著一個目錄裡明明列著的人反覆懷疑標識寫錯了；
	// 把它報成成功，則是在審計與真相之間造出一件沒發生過的事。
	//
	// 它也與 Root 那側的 adminacct.ErrAdminDeleted 是兩枚結論而不是同一枚搬兩次：
	// 兩本目錄的範圍規則不同（這裡按定義列不到持有授予者），而對外它們各自映射到
	// 自己那枚機器碼（2015 只描述 Root 的管理員目錄，不為另一本名冊改寫已發布的語意）。
	//
	// 它的可見範圍只有伺服器級管理員（本套件全部入口都經 NeedServerAdmin），因此不構成
	// 任何人可用的帳戶列舉信號：能收到這句話的人已經是這本目錄的所有者。
	ErrAccountDeleted = errors.New("stdacct: 該帳戶已被軟刪除")
	// ErrAccountRetired 表示目標是已經被綁走、進入退休終態的訪戶：他不可被刪除，
	// 也沒有任何通路能讓他重新可用。
	//
	// 它不降成 1001：這個人就在這本目錄裡，詳情讀得到、綁定留痕查得到；
	// 也不併入 ErrAccountDeleted：那句話說的是「他被刪掉了」，而這裡的事實是
	// 「他被併進另一個人了」——兩件事在歷史裡的含義不同，處置也不同
	// （前者什麼都別再做，後者要去看的是那條綁定留痕）。
	// 少這一句的後果是具體的：退休行的每一欄都被庫釘住，讓寫去撞觸發器
	// 只會換來一個「後端壞了」的 500。
	ErrAccountRetired = errors.New("stdacct: 該訪戶已經綁定退休")
)

// Deletion 是一次成功刪除的結果：刪除後的單筆真相加撤銷數量。
type Deletion struct {
	// Profile 為刪除後經實體校驗的單筆資料（status 恆為 deleted，display_name 為佔位值）。
	Profile StandardProfile
	// RevokedSessions 為這次撤銷的會話數量：界面要能如實說出「這次讓 N 臺裝置
	// 失去登入狀態」，而不是讓操作者對著一句「已刪除」猜影響範圍。
	// 對一個早就停用、或本來就沒有會話在跑的訪戶，這個數通常是 0——0 是事實，不是失敗。
	RevokedSessions int
}

// DeleteStandardAccount 以持有伺服器級管理權的受信主體軟刪除一名目錄內的普通帳戶
// 或訪戶帳戶：停止登入、撤銷其有效會話、顯示名匿名化，而行、登入名鍵與歷史參照一律保留。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 授權（NeedServerAdmin，與建號、目錄、詳情、編輯、停用、重置、升級、綁定簽發
//     同一道閘）與零值標識在交易外：被拒的請求一個查詢都不該多花；
//  2. 交易內 readStandardProfile：帳戶存在與「他在這本目錄裡」一起核實。已刪除與已退休
//     的目標在這裡仍然讀得到（操作者要查得出「當年那個人是誰」），所以它是本檔
//     第二道閘的落點：requireNotTerminal 當場把兩種終態擋下，整個操作不發生；
//  3. MarkDeleted 以狀態機守衛寫入終態（WHERE deleted_at IS NULL）：零行命中即回
//     ErrAccountDeleted 並讓交易回滾——「一個字都沒寫」不報刪除成功；
//  4. 同交易撤銷目標全部會話：「刪除使舊會話立刻失效」因此是落庫的事實，
//     不是每次現讀推導出來的口頭承諾（現讀仍在那裡，兩者不互相代替）；
//  5. 同交易重讀並追加 Root 域審計：刪除與其審計同生同滅。
//
// 被拒的刪除（非管理員、不在目錄、已是刪除態或退休態）不追加審計：
// 與被拒的建號、編輯、停用、重置、升級同口徑——拒絕的結論不該成為寫入放大器。
func (s *Service) DeleteStandardAccount(ctx context.Context, principal identity.Principal,
	accountID idgen.ID, requestID string) (Deletion, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		s.log.Warn("刪除普通帳戶被拒：主體不具備伺服器級管理權",
			"subject", principal.String(), "request_id", requestID)
		return Deletion{}, err
	}
	if accountID.IsNil() {
		return Deletion{}, ErrAccountNotFound
	}

	var result Deletion
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		before, err := s.readStandardProfile(tctx, tx, accountID)
		if err != nil {
			return err
		}
		if err := requireNotTerminal(before); err != nil {
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
			return ErrAccountDeleted
		}
		revoked, err := s.sessions.RevokeAccount(tctx, tx, accountID)
		if err != nil {
			return err
		}
		// 交易內重讀：回應要的是「刪除之後的資料庫現值」，不是呼叫端的意圖回音。
		after, err := s.readStandardProfile(tctx, tx, accountID)
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
			return Deletion{}, ErrAccountNotFound
		case errors.Is(err, ErrAccountDeleted), errors.Is(err, ErrAccountRetired),
			errors.Is(err, ErrAccountNotFound):
			return Deletion{}, err
		}
		s.log.Error("刪除普通帳戶失敗", "request_id", requestID, "err", err)
		return Deletion{}, fmt.Errorf("stdacct: 刪除普通帳戶失敗: %w", err)
	}
	s.log.Info("已軟刪除普通帳戶（新登入被拒、既有會話撤銷、顯示名匿名化，行與登入名保留）",
		"account", result.Profile.AccountID.String(),
		"account_type", result.Profile.Type.String(),
		"revoked_sessions", result.RevokedSessions, "request_id", requestID)
	return result, nil
}

// requireNotTerminal 是「兩種終態不接受任何寫入」這條規則唯一的判定點。
//
// 它必須存在成一個函式而不是在各條通路各比一次：編輯資料、停用／恢復、重置憑據、
// 訪戶升級與刪除五個用例都要問同一句話，而「已退休的人還能不能被改名」這類問題
// 只要有兩套答案，就一定有一套被繞過——被繞過的那一套在資料庫層是觸發器 ABORT，
// 對外的形體是一個查不出原因的 500。
//
// 判定讀的是現值而不是呼叫端交來的宣稱：請求本體裡沒有任何欄位可以把自己
// 寫成「我以為他還活著」。待審批鏈的兩態不在此列——它們根本讀不到本檔的
// StandardProfile（在 readStandardProfile 就已出局成 ErrAccountNotFound），
// 把它們再判一次只會造出第二個真相。
func requireNotTerminal(target StandardProfile) error {
	switch target.Status {
	case account.StatusDeleted:
		return fmt.Errorf("%w：%s", ErrAccountDeleted, target.AccountID.String())
	case account.StatusRetired:
		return fmt.Errorf("%w：%s", ErrAccountRetired, target.AccountID.String())
	}
	return nil
}

// deletionRecord 產生一筆 Root 域的刪除審計。口徑與其餘寫入同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆刪除回滾。
//
// 「刪除前身份快照」記的是哪些：login_name、刪除前的 display_name、刪除前的 status、
// 來源類型（他是普通帳戶還是訪戶——這句話決定界面怎麼說明這個人怎麼來的），
// 以及 deleted_at 這個時刻。前幾項在這次寫入裡可能看起來「沒變」或「將不存在」，
// 但它們正是這一筆存在的理由——行保留、只追加的表不可改，而界面與運維都要能回答
// 「這個人當時叫什麼、以什麼狀態被刪」。
//
// 絕不落進記錄的東西：憑據雜湊（任何一側）、口令明文、會話秘密或其標識。
// revoked_sessions 是數量而不是清單——逐條撤銷的事實在 sessions 表的 revoked_at 裡。
func (s *Service) deletionRecord(principal identity.Principal, before, after StandardProfile,
	revoked int, requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("stdacct: 主體無法換得審計操作者: %w", err)
	}
	return audit.Record{
		Scope:     audit.ScopeRoot,
		Actor:     actor,
		Action:    "account.delete",
		Target:    audit.Target{Kind: "account", ID: after.AccountID.String()},
		Reason:    "伺服器級管理員經已認證會話軟刪除普通帳戶或訪戶帳戶：全伺服器新登入被拒、既有會話全部撤銷、顯示名匿名化；帳戶行與登入名保留以承載歷史身份",
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "login_name", Before: before.LoginName, After: after.LoginName},
			{Field: "display_name", Before: before.DisplayName, After: after.DisplayName},
			{Field: "account_type", Before: before.Type.String(), After: after.Type.String()},
			{Field: "status", Before: before.Status.String(), After: after.Status.String()},
			{Field: "deleted_at", Before: nullableFormatUTC(before.DeletedAt),
				After: nullableFormatUTC(after.DeletedAt)},
			{Field: "revoked_sessions", Before: nil, After: revoked},
		},
	}, nil
}
