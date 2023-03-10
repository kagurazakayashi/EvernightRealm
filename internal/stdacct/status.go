// status.go 是「管理員停用與恢復普通帳戶登入」的應用服務層。
//
// 這裡動的是「通用帳戶的伺服器級登入能力」，不是某一場活動裡的玩家狀態：
// 一次停用同時影響這個帳戶現有的全部會話與未來的全部登入，跨所有活動生效，
// 而它不碰活動身份、禁言、交易凍結與陣營限制——那些是活動作用域的規則，
// 其判定落在尚未實作的 AuthorizeActivityScope 之後，本套件不冒充能做。
//
// 停用的實際效果由三件事同時構成，缺一件都是半套（與 internal/adminacct 的停用同形）：
//   - 新登入被拒：accounts.status 落為 disabled，登入用例現讀狀態後收斂到
//     「憑據無效」同形（見 internal/auth），不是另造一句「這個帳戶被鎖了」；
//   - 已有會話立即失效：主體有效性逐請求現讀（session.Verify），加上本用例在同一個
//     交易裡撤銷目標的全部會話——「失效」是寫下的 revoked_at 事實，不是每次現讀推導；
//   - 可追溯：Root 域審計記下 status 前後值、disabled_at 前後值與這次讓多少會話落地失效。
//
// 底層機制逐字複用管理員停用那兩條倉儲寫法（account.Store.SetStatus 的 CAS、
// session.Store.RevokeAccount 的定向撤銷），但目標範圍由本套件獨立判定：
// 範圍規則是「不持有 server_admin 授予、不在審批鏈門外，且未進入任何終態」，所以管理員拿這條通路
// 動不了另一位管理員，也動不了他自己（那三種形態與查無此人收斂成同一個
// ErrAccountNotFound），而 Root 本来就不在 accounts 表裡；兩種終態（已刪、已退休）
// 各自回自己那句話，因為它們就在這本目錄裡，說「換個目標」是誤導。
// 授權仍然是 NeedServerAdmin——與建號、目錄、資料編輯、刪除同一道閘，本步不新增檔位也不下放。
//
// 恢復只恢復「新登入資格」這一件事：不復活停用前被撤銷的會話（撤銷不可逆，
// 恢復通路一個 session 都不碰）、不清除尚未完成的首次改密旗標（UPDATE 語句不碰那欄）、
// 也不解開任何別的限制。帳戶的多重限制從來不是一個 Active 布林：status 管「能不能登入」、
// must_change_password 管「登入後要先改密」、account_type 管來源、刪除是終態，
// 四件事各由各自的欄位與通路回答，本用例只動前兩欄裡的那一欄。
//
// 「停用與另一請求同時到達」由 CAS 處理：呼叫端交出它看見過的現狀，現狀已變時
// 整個操作不發生、零撤銷、零審計。SQLite 單寫入者把併發串行化——先提交完成的寫入
// 是不倒退的事實，停用生效後的新操作在會話解析邊界就被拒。本層不假裝能關掉
// 「讀與寫之間」的微觀窗口，錨點是「以停用生效後為準，新操作必須被拒」。
//
// 訪戶帳戶（account_type=guest）與普通帳戶走同一條通路：本目錄的範圍定義本來就把兩者
// 都算在內（見 directory.go），再按類型分叉就會出現「目錄列得到、寫入通路說他不在」
// 的兩套真相。訪客今日沒有任何可登入的憑據通路，因此對他的停用通常撤不到會話
// （revoked_sessions 為 0）；狀態落庫仍然是如實事實，界面據實陳述。
package stdacct

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 狀態用例的結論錯誤：非法意圖、併發落敗各自可判別，內部故障一律不進這些型別。
// 「目標不在本目錄」不另發一型：它沿用資料編輯那條同樣的 ErrAccountNotFound，
// 因為兩種通路對「他是管理員／他已刪除／查無此人」的回答本來就是同一句話。
var (
	// ErrInvalidStatusChange 表示請求的狀態對不構成一次變更：值不在封閉集合內，
	// 或新舊同值（例如「把已停用的人再停用一次」的寫法）。它是請求本體的問題，
	// 屬呼叫端可修正的輸入錯誤，與資料庫現值無關。
	ErrInvalidStatusChange = errors.New("stdacct: 目標狀態不合停用/恢復的規則")
	// ErrStatusConflict 表示提交所依據的狀態現值已不是資料庫現值：
	// 整個操作沒有發生——狀態沒改、會話沒撤、審計沒記。
	//
	// 它與 ErrProfileConflict 分開只為處置不同：改名落敗是「重讀那個欄位再改」，
	// 狀態落敗是「目標的可用性已經不是你確認時的那樣」，界面要重讀整個現狀
	// 並重新走一次確認，而不是把人手上那顆按鈕再點一遍。
	// 重複操作（對已停用者再停用）也收斂到這裡，不謊報成功。
	ErrStatusConflict = errors.New("stdacct: 目標狀態已與提交時所依據的不同")
)

// StatusChangeInput 是停用/恢復所需的領域輸入。
//
// 沒有原因文本欄位：審計的 Reason 由服務端固定措辭產生，與 admin.disable、
// account.create_standard、account.profile_update 同口徑——「為什麼停他」的措辭
// 不該成為任何能碰到這個端點的主體往審計表裡寫的任意文本。
type StatusChangeInput struct {
	// NewStatus 為要進入的狀態（active 恢復 | disabled 停用）。
	NewStatus account.Status
	// ExpectedStatus 為呼叫端提交所依據的當前狀態（CAS 錨點）。
	ExpectedStatus account.Status
}

// StatusChange 是一次成功變更的結果：更新後的單筆真相加撤銷數量。
type StatusChange struct {
	// Profile 為變更後經實體校驗的單筆資料（與詳情同形）。
	Profile StandardProfile
	// RevokedSessions 為這次撤銷的會話數量；恢復恆為 0（不復活、也不新撤任何會話）。
	// 它的用途是讓界面能如實說出「這次讓 N 臺裝置重新登入」，
	// 而不是讓管理員對著一句「已停用」猜影響範圍。
	RevokedSessions int
}

// UpdateStandardAccountStatus 以持有伺服器級管理權的受信主體停用或恢復
// 一名目錄內普通帳戶的登入能力。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 授權（NeedServerAdmin，與建號、目錄、編輯同一道閘）與輸入校驗在交易外：
//     被拒的請求一個查詢都不該多花；
//  2. 交易內 readStandardProfile：帳戶存在、是否持有授予、是否還在審批鏈門外
//     三道範圍檢查一起核實。對不在本目錄的標識整個操作不發生；
//  3. requireNotTerminal：已刪除與已退休都讀得到，但兩態都不接受停用／恢復的寫入——
//     刪除是終態而「恢復登入」對它從來不是一個可發的令，退休行每一欄都被庫釘住，
//     少了這一道只會換成一個撞觸發器的 500（判定點只有一個，見 deleted.go）；
//  4. CAS 寫狀態（WHERE 帶著呼叫端所依據的現狀）：changed=false 即回 ErrStatusConflict
//     並讓交易回滾——狀態、disabled_at、會話、審計四件事沒有一件發生，
//     衝突的停用不是「部分成功」；
//  5. 僅在進入 disabled 時同交易撤銷目標全部會話：恢復永不撤銷，
//     「不復活停用前會話」因此成立在第 4 步已落庫的 revoked_at 上，不靠解析路徑各加特例；
//  6. 同交易重讀並追加 Root 域審計：變更與其審計同生同滅。
//
// 被拒的變更（非管理員、不在目錄、目標是終態、併發衝突、輸入不構成變更）不追加審計：
// 與被拒的建號、編輯、重置同口徑——拒絕的結論不該成為寫入放大器。
func (s *Service) UpdateStandardAccountStatus(ctx context.Context, principal identity.Principal,
	accountID idgen.ID, in StatusChangeInput, requestID string) (StatusChange, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		s.log.Warn("變更普通帳戶狀態被拒：主體不具備伺服器級管理權",
			"subject", principal.String(), "request_id", requestID)
		return StatusChange{}, err
	}
	if accountID.IsNil() {
		return StatusChange{}, ErrAccountNotFound
	}
	if !statusChangeValid(in) {
		return StatusChange{}, fmt.Errorf("%w：%s → %s（僅 active|disabled 且新舊必須不同）",
			ErrInvalidStatusChange, string(in.ExpectedStatus), string(in.NewStatus))
	}

	var result StatusChange
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		before, err := s.readStandardProfile(tctx, tx, accountID)
		if err != nil {
			return err
		}
		// 已刪除與已退休都不進這條通路：「恢復登入」承認的是停用過的帳戶，
		// 把終態當成「一個還能被恢復的停用」是這條通路最壞的誤讀（用戶批准：
		// 停用與刪除是不同狀態，而綁定後的訪戶沒有任何通路可恢復）。
		// 判定在 CAS 之前，因此這次拒絕既不改狀態、也不撤會話、也不留審計。
		// 一個說明：statusChangeValid 在交易外先擋掉「expected_status 填了終態值」的寫法
		// （那根本不是一條可選的遷移，屬請求本體的問題），這一跳擋的是「他現在是終態」
		// 這個資料庫事實——兩句的話題不同，誰也不代替誰。
		if err := requireNotTerminal(before); err != nil {
			return err
		}
		changed, err := s.accounts.SetStatus(tctx, tx, accountID, in.NewStatus, in.ExpectedStatus)
		if err != nil {
			return err
		}
		if !changed {
			return ErrStatusConflict
		}
		revoked := 0
		if in.NewStatus == account.StatusDisabled {
			revoked, err = s.sessions.RevokeAccount(tctx, tx, accountID)
			if err != nil {
				return err
			}
		}
		// 交易內重讀：回應要的是「變更之後的資料庫現值」，不是呼叫端的意圖回音。
		after, err := s.readStandardProfile(tctx, tx, accountID)
		if err != nil {
			return err
		}
		rec, err := s.statusChangeRecord(principal, before, after, revoked, requestID)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		result = StatusChange{Profile: after, RevokedSessions: revoked}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, account.ErrNotFound), errors.Is(err, grant.ErrNotFound):
			return StatusChange{}, ErrAccountNotFound
		case errors.Is(err, ErrStatusConflict), errors.Is(err, ErrAccountNotFound),
			errors.Is(err, ErrInvalidStatusChange), errors.Is(err, ErrAccountDeleted),
			errors.Is(err, ErrAccountRetired):
			return StatusChange{}, err
		}
		s.log.Error("變更普通帳戶狀態失敗", "request_id", requestID, "err", err)
		return StatusChange{}, fmt.Errorf("stdacct: 變更普通帳戶狀態失敗: %w", err)
	}
	s.log.Info("已變更普通帳戶登入狀態",
		"account", result.Profile.AccountID.String(),
		"status", string(result.Profile.Status), "request_id", requestID)
	return result, nil
}

// statusChangeValid 把「這是一次有意義的狀態變更」的判定收在一處：
// 兩側都必須落在封閉集合內且互不相同。同值不發給交易與 CAS 的理由寫在
// account.Store.SetStatus 的域不變量裡（沒有新事實可寫，且 disabled→disabled
// 會把 disabled_at 重新蓋一次「此刻被停」的假時刻）。
// 兩種終態（deleted／retired）作為任一側也過不了 valid：它們不是一條可選的遷移。
// 但這一格擋的是「請求寫法」（呼叫端宣稱的 expected_status 根本不在可選集合裡），
// 目標此刻是不是終態仍由交易內的現讀判定（requireNotTerminal），兩者話題不同。
func statusChangeValid(in StatusChangeInput) bool {
	valid := func(s account.Status) bool {
		return s == account.StatusActive || s == account.StatusDisabled
	}
	return valid(in.NewStatus) && valid(in.ExpectedStatus) && in.NewStatus != in.ExpectedStatus
}

// statusChangeRecord 產生一筆 Root 域的停用/恢復審計。口徑與 creationRecord 同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆變更回滾。
//
// 動作名沿用本套件的 account. 前綴（動的是普通帳戶），與管理員那組 admin.* 分家；
// ScopeRoot 而不捏造 activity_id：停用一個伺服器級帳戶的登入能力不屬於任何活動，
// root_audit 結構上也沒有那一欄。
//
// 絕不落進記錄的東西：口令、憑據雜湊、任何會話秘密或 token_hash。
// disabled_at 是「何時停的」這一個時刻事實；revoked_sessions 是數量而不是清單——
// 撤銷的逐條事實在 sessions 表的 revoked_at 裡，審計不複製會話標識。
func (s *Service) statusChangeRecord(principal identity.Principal, before, after StandardProfile,
	revoked int, requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("stdacct: 主體無法換得審計操作者: %w", err)
	}
	action := "account.enable"
	reason := "伺服器級管理員經已認證會話恢復普通帳戶的新登入能力（停用前會話不復活，首次改密義務不解除）"
	if after.Status == account.StatusDisabled {
		action = "account.disable"
		reason = "伺服器級管理員經已認證會話停用普通帳戶：全伺服器新登入被拒，既有會話全部撤銷"
	}
	return audit.Record{
		Scope:     audit.ScopeRoot,
		Actor:     actor,
		Action:    action,
		Target:    audit.Target{Kind: "account", ID: after.AccountID.String()},
		Reason:    reason,
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "status", Before: before.Status.String(), After: after.Status.String()},
			{Field: "disabled_at", Before: nullableFormatUTC(before.DisabledAt),
				After: nullableFormatUTC(after.DisabledAt)},
			{Field: "revoked_sessions", Before: nil, After: revoked},
		},
	}, nil
}

// nullableFormatUTC 把零值時刻換成 nil（審計的變更前空值不冒充有效時刻），
// 其餘交 timeutil.FormatUTC（與回應本體同一個時刻表示，追查時兩邊對得起來）。
func nullableFormatUTC(at time.Time) any {
	if at.IsZero() {
		return nil
	}
	return timeutil.FormatUTC(at)
}
