// status.go 是「Root 停用與恢復管理員登入」的應用服務層。
//
// 停用的實際效果由三件事同時構成，缺一件都是半套：
//   - 新登入被拒：accounts.status 落為 disabled，登入用例現讀狀態後收斂到
//     「憑據無效」同形（見 internal/auth），不是另造一句「這個帳戶被鎖了」；
//   - 已有會話不能繼續執行管理操作：主體有效性逐請求現讀（session.Verify），
//     停用提交後的下一條請求就換不出受信主體；本用例在同一個交易裡撤銷目標
//     的全部會話，讓「失效」是落庫的事實而不是每次現讀的推導；
//   - 狀態變更與撤銷語意可追溯：Root 域審計記下 status 前後值、disabled_at
//     前後值，以及這次讓多少會話落地失效（revoked_sessions）。
//
// 恢復只恢復「新登入能力」這一件事：不復活停用前的任何會話（它們已被撤銷，
// 撤銷不可逆）、不清除尚未完成的首次改密旗標（UPDATE 語句不碰那些欄位，
// 見 account.Store.SetStatus 的形狀約定）、也不把帳戶之外的任何資料改回來。
//
// 「停用與另一請求同時到達」的競爭由 CAS 處理：呼叫端交出它看見過的現狀，
// 現狀已變時整個操作不發生、零撤銷、零審計。SQLite 單寫入者讓「已完成的操作
// 不倒退」天然成立：另一筆交易提交成功的寫入，要嘛先於停用提交（那是明確完成
// 的事實，停用不刪除、不逆转），要嘛在它之後——之後的敏感寫入在會話解析邊界
// 就被拒。本層不假裝能關掉「讀與寫之間」的微觀窗口，錨點是「以停用生效後
// 為準，新操作必須被拒」。
//
// 目標不能是 Root：Root 沒有帳戶標識、不落授予表，任何以 Root 為目標的標識
// 都過不了目錄成員資格檢查，與「查無此人」收斂成同一個結論（ErrAdminNotFound）。
// 管理員停用其他管理员也不在這條通路裡：授權只經 identity.NeedRoot，
// 持 server_admin 的帳戶主體當場被拒（見 internal/identity/authorize.go）。
package adminacct

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

// 狀態用例的結論錯誤：非法意圖、併發落敗、目標不在目錄各自可判別，
// 內部故障一律不進這些型別。
var (
	// ErrInvalidStatusChange 表示請求的狀態對不构成一次變更：值不在封閉集合內，
	// 或新舊同值（例如「把已停用的人再停用一次」的寫法）。它是請求本體的問題，
	// 屬呼叫端可修正的輸入錯誤，與資料庫現值無關。
	ErrInvalidStatusChange = errors.New("adminacct: 目標狀態不合停用/恢復的規則")
	// ErrStatusConflict 表示提交所依據的狀態現值已不是資料庫現值：
	// 整個操作沒有發生——沒有改狀態、沒有撤會話、沒有審計。
	//
	// 它與 ErrProfileConflict 分開只為處置不同：改名落敗是「重讀那個欄位再改」，
	// 狀態落敗是「目標的可用性已經不是你確認時的那樣」，界面要重讀整個目標狀態
	// 並重新走一次確認，而不是把人手上那顆按鈕再點一遍。
	ErrStatusConflict = errors.New("adminacct: 目標狀態已與提交時所依據的不同")
)

// StatusChangeInput 是停用/恢復所需的領域輸入。
//
// 沒有原因文本欄位：審計的 Reason 由服務端固定措辭產生，與 admin.create、
// admin.profile_update 同口徑——「為什麼停他」的措辭不該成為任何能碰到這個
// 端點的主體往審計表裡寫的任意文本。
type StatusChangeInput struct {
	// NewStatus 為要進入的狀態（active 恢復 | disabled 停用）。
	NewStatus account.Status
	// ExpectedStatus 為呼叫端提交所依據的當前狀態（CAS 錨點）。
	ExpectedStatus account.Status
}

// StatusChange 是一次成功變更的結果：更新後的單筆真相加撤銷數量。
type StatusChange struct {
	// Profile 為變更後經實體校驗的單筆資料（與詳情同形）。
	Profile Profile
	// RevokedSessions 為這次撤銷的會話數量；恢復恆為 0（不復活、也不新撤任何會話）。
	// 它的用途是讓界面能如實說出「這次讓 N 臺裝置重新登入」，
	// 而不是讓 Root 對著一句「已停用」猜影響範圍。
	RevokedSessions int
}

// UpdateAdminStatus 以 Root 主體停用或恢復一名目錄內管理員的登入能力。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 授權（NeedRoot，與開設、目錄、編輯同一道閘）與輸入校驗在交易外：
//     被拒的請求一個查詢都不該多花；
//  2. 交易內 readProfile：帳戶存在與目錄成員資格一起核實，對不在目錄裡的標識
//     整個操作不發生；「已物理刪除的帳戶」在這裡自然得到同一個結論；
//  3. CAS 寫狀態（WHERE 帶著呼叫端所依據的現狀）：changed=false 即回
//     ErrStatusConflict 並讓交易回滾——狀態、disabled_at、會話、審計四件事
//     沒有一件發生，衝突的停用不是「部分成功」；
//  4. 僅在進入 disabled 時同交易撤銷目標全部會話：恢復永不撤銷，
//     「不復活停用前會話」因此成立在第 3 步已成功落庫的 revoked_at 上，
//     不靠解析路徑各自加特例；
//  5. 同交易重讀並追加 Root 域審計：變更與其審計同生同滅。
//
// 被拒的變更（非 Root、非目錄成員、併發衝突、輸入不構成變更）不追加審計：
// 與被拒的開設、編輯、撤銷同口徑——拒絕的結論不該成為寫入放大器。
func (s *Service) UpdateAdminStatus(ctx context.Context, principal identity.Principal,
	accountID idgen.ID, in StatusChangeInput, requestID string) (StatusChange, error) {
	if err := identity.Authorize(principal, identity.NeedRoot); err != nil {
		s.log.Warn("變更管理員狀態被拒：主體不具備 Root 權限",
			"subject", principal.String(), "request_id", requestID)
		return StatusChange{}, err
	}
	if accountID.IsNil() {
		return StatusChange{}, ErrAdminNotFound
	}
	if !statusChangeValid(in) {
		return StatusChange{}, fmt.Errorf("%w：%s → %s（僅 active|disabled 且新舊必須不同）",
			ErrInvalidStatusChange, string(in.ExpectedStatus), string(in.NewStatus))
	}

	var result StatusChange
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		before, err := s.readProfile(tctx, tx, accountID)
		if err != nil {
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
		after, err := s.readProfile(tctx, tx, accountID)
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
			return StatusChange{}, ErrAdminNotFound
		case errors.Is(err, ErrStatusConflict), errors.Is(err, ErrAdminNotFound):
			return StatusChange{}, err
		}
		s.log.Error("變更管理員狀態失敗", "request_id", requestID, "err", err)
		return StatusChange{}, fmt.Errorf("adminacct: 變更管理員狀態失敗: %w", err)
	}
	s.log.Info("Root 已變更管理員登入狀態",
		"account", result.Profile.AccountID.String(),
		"status", string(result.Profile.Status), "request_id", requestID)
	return result, nil
}

// statusChangeValid 把「這是一次有意義的狀態變更」的判定收在一處：
// 兩側都必須落在封閉集合內且互不相同。同值不發給交易與 CAS 的理由寫在
// account.Store.SetStatus 的域不变量裡（沒有新事實可寫，且 disabled→disabled
// 會把 disabled_at 重新蓋一次「此刻被停」的假時刻）。
func statusChangeValid(in StatusChangeInput) bool {
	valid := func(s account.Status) bool {
		return s == account.StatusActive || s == account.StatusDisabled
	}
	return valid(in.NewStatus) && valid(in.ExpectedStatus) && in.NewStatus != in.ExpectedStatus
}

// statusChangeRecord 產生一筆 Root 域的停用/恢復審計。口徑與 creationRecord 同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆變更回滾。
//
// 絕不落進記錄的東西：口令、憑據雜湊、任何會話秘密或 token_hash。
// disabled_at 是「何時停的」這一個時刻事實，屬可追溯性需要的內容；
// revoked_sessions 是數量而不是清單——撤銷的逐條事實在 sessions 表的
// revoked_at 裡，審計不需要（也不該）複製會話標識。
func (s *Service) statusChangeRecord(principal identity.Principal, before, after Profile,
	revoked int, requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("adminacct: 主體無法換得審計操作者: %w", err)
	}
	action := "admin.enable"
	reason := "Root 經已認證會話恢復伺服器級管理員的新登入能力（停用前會話不復活，首次改密義務不解除）"
	if after.Status == account.StatusDisabled {
		action = "admin.disable"
		reason = "Root 經已認證會話停用伺服器級管理員帳戶：新登入被拒，既有會話全部撤銷"
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

// nullableFormatUTC 把零值時刻換成 nil（審計的变更前空值不冒充有效時刻），
// 其餘交 timeutil.FormatUTC（與回應本體同一個時刻表示，追查時兩邊對得起來）。
func nullableFormatUTC(at time.Time) any {
	if at.IsZero() {
		return nil
	}
	return timeutil.FormatUTC(at)
}
