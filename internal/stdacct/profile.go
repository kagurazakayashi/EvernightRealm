// profile.go 是「管理員查看與編輯普通帳戶的非安全資料」：單筆詳情與顯示名編輯。
//
// 與目錄（directory.go）的分工是刻意的：目錄是展示投影，這裡是經過實體校驗的
// 單筆真相——詳情與編輯結果都經 internal/account 的倉儲讀法換回，
// 「介面上呈現的當前資料」與「資料庫保存的結果」因此不可能各說各話。
//
// 目標範圍（誰算「這本目錄裡的一筆」）在這裡獨立判定，不復用目錄那段 SQL：
//   - internal/account.ByID 給經過實體校驗的帳戶真相（含狀態與三個時刻的成對複核）；
//   - internal/grant 的公開讀法回答「他是不是持有 server_admin 的管理員」——
//     查無授予正是「他在這本目錄裡」的正面答案，查得有授予則一律出局；
//   - 刪除終態出局（與目錄同一條邊界，理由見 directory.go 頭注）。
//     三個問題各自有自己的權威實作點，不拿展示投影反向回答授權與範圍。
//
// 編輯的白名單只有一欄：display_name。狀態、憑據、首次改密旗標與帳戶類型
// 不在此通路之內（UPDATE 語句裡連這些欄位都不出現，見 account.Store.UpdateDisplayName），
// 「保存普通資料不能連隱藏欄位一起覆蓋」成立在 SQL 形狀上而不是自律上。
// 併發控制沿用同一倉儲的比較-and-set：呼叫端交出它看見過的現值，
// 現值已變時整個編輯不發生並回可判別的衝突結論。
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
)

// 資料用例的結論錯誤：非管理員、不在目錄、併發落敗各自可判別，內部故障一律不進這些型別。
var (
	// ErrAccountNotFound 表示目標不是這本目錄裡的一筆：帳戶不存在、他是持有伺服器級
	// 角色的管理員（含敲這條端點的操作者自己）、或他已進入刪除終態。三種情況一律
	// 同一個答案，且不提供「差哪一半」的信號——標識是 UUIDv7，把「存在但是個管理員」
	// 講出來等於讓這個端點替普通帳戶目錄做枚舉，而那本該是 Root 端點才能說的話。
	ErrAccountNotFound = errors.New("stdacct: 該帳戶不在普通帳戶目錄中")
	// ErrProfileConflict 表示提交所依據的顯示名現值已不是資料庫現值（併發編輯落敗）。
	//
	// 它與 ErrAccountNotFound 分開只為一件事：兩句話的處置不同——一個要人換目標，
	// 另一個只要重讀最新現值再決定改不改。它不該被報成內部錯誤，那是把正常的
	// 併發尾巴說成服務壞了。
	ErrProfileConflict = errors.New("stdacct: 顯示名現值已與提交時所依據的不同")
)

// StandardProfile 是單筆普通帳戶的可展示資料（詳情與編輯結果共用同一個形狀）。
//
// 不含也不可能有：憑據雜湊、會話材料、login_name_key 的內部正規化產物、
// 刪除時刻（刪除終態不在本目錄之內）、授予與角色（本目錄的定義就是「沒有伺服器級授予」，
// 回應不描述一件不存在的事）。Type 是來源事實：普通帳戶與訪戶帳戶在這本目錄裡
// 一律如實顯示他是哪一類，但這只讀不寫——類型不在任何白名單之內。
type StandardProfile struct {
	// AccountID 為帳戶穩定標識。
	AccountID idgen.ID
	// LoginName 為登入名原始寫法（本步不提供修改通路）。
	LoginName string
	// DisplayName 為顯示名稱。
	DisplayName string
	// Type 為來源類型（standard|guest，讀自經實體校驗的帳戶）。
	Type account.Type
	// Status 為帳戶狀態（只讀展示；改它走另一條通路：見 status.go 的停用與恢復，
	// 這條編輯白名單裡沒有狀態那一格）。active 與 disabled 都讀得到，
	// disabled_at 也只在單筆詳情裡出現（見 internal/httpapi 的 standardAccountItem）。
	Status account.Status
	// DisabledAt 為進入禁用狀態的時刻；active 時恆為零值（資料庫 NULL）。
	DisabledAt time.Time
	// RetiredAt 為進入綁定退休終態的時刻；不為 retired 時恆為零值（資料庫 NULL）。
	// 它與 Status 一同把「這個人已被誰綁走、哪一刻被綁走」講成讀得到的事實：
	// 退休行仍在本目錄之內（刻意保留的可回溯性），而這一欄是那句話的時間部分。
	RetiredAt time.Time
	// MustChangePassword 為是否仍欠首次改密（只讀展示；解除它的唯一通路是本人改密）。
	MustChangePassword bool
	// CreatedAt 為帳戶建立時刻。
	CreatedAt time.Time
	// LastLoginAt 為最近一次登入時刻；零值代表從未登入。
	LastLoginAt time.Time
}

// StandardAccountProfile 以管理員主體讀回單筆普通帳戶詳情。
//
// 授權先於任何查詢：非管理員在這裡就結束，不消耗一次資料庫讀取，
// 也不因為「他讀不到別人」而拿到一句可以推斷目標存在與否的答案。
func (s *Service) StandardAccountProfile(ctx context.Context, principal identity.Principal,
	accountID idgen.ID) (StandardProfile, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		return StandardProfile{}, err
	}
	profile, err := s.readStandardProfile(ctx, s.db.SQL(), accountID)
	if err != nil {
		if errors.Is(err, account.ErrNotFound) {
			return StandardProfile{}, ErrAccountNotFound
		}
		return StandardProfile{}, err
	}
	return profile, nil
}

// UpdateStandardAccountProfile 以白名單編輯一名普通帳戶的顯示名。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 授權（NeedServerAdmin，與建號、目錄同一道閘）；
//  2. 交易內讀帳戶（經倉儲實體校驗）並核實他在本目錄範圍內：管理員、已刪除者、
//     幽靈標識與不存在的帳戶都是同一句話，編輯整個不發生，也絕不「先改再說」；
//  3. CAS 更新只碰 display_name：changed=false 時回 ErrProfileConflict 並讓交易回滾，
//     一個字都不落——衝突的保存不是「部分成功」；
//  4. 同一交易內讀回更新後的實體並追加 Root 域審計：編輯與其審計同生同滅，
//     「真實存在卻在 Root 審計裡查不到的改動」與「審計說有而資料庫查不到」同罪。
//
// 被拒的編輯（非管理員、不在目錄、併發衝突、輸入不合規）不追加審計：
// 與被拒的建號、被拒的管理員編輯同口徑——拒絕的結論不該成為寫入放大器。
// 成功的編輯必留審計，前後只有 display_name 一欄的舊值與新值：
// 「必要前後摘要」不含其他個人資料，更沒有一個可能容下憑據材料的格子。
func (s *Service) UpdateStandardAccountProfile(ctx context.Context, principal identity.Principal,
	accountID idgen.ID, displayName, expectedDisplayName, requestID string) (StandardProfile, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		return StandardProfile{}, err
	}
	if accountID.IsNil() {
		return StandardProfile{}, ErrAccountNotFound
	}

	var updated StandardProfile
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		before, err := s.readStandardProfile(tctx, tx, accountID)
		if err != nil {
			return err
		}
		changed, err := s.accounts.UpdateDisplayName(tctx, tx, accountID,
			displayName, expectedDisplayName)
		if err != nil {
			// 域校驗錯誤（空顯示名、超長、控制字元）原樣上報：訊息點出的是請求本體
			// 哪個欄位不合規，與憑據無關；其餘（資料庫故障）走下面的包裝分支。
			return err
		}
		if !changed {
			return ErrProfileConflict
		}
		// 交易內重讀：回應要的是「保存之後的資料庫現值」，不是呼叫端交來的意圖。
		after, err := s.readStandardProfile(tctx, tx, accountID)
		if err != nil {
			return err
		}
		rec, err := s.profileUpdateRecord(principal, before, after, requestID)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		updated = after
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, account.ErrNotFound), errors.Is(err, grant.ErrNotFound):
			return StandardProfile{}, ErrAccountNotFound
		case errors.Is(err, ErrProfileConflict), errors.Is(err, ErrAccountNotFound):
			return StandardProfile{}, err
		case errors.Is(err, account.ErrInvalidDisplayName):
			// 可展示的域規則結論：傳輸層據此回 1004 並點出欄位，不進「內部故障」分支。
			return StandardProfile{}, err
		}
		s.log.Error("編輯普通帳戶資料失敗", "request_id", requestID, "err", err)
		return StandardProfile{}, fmt.Errorf("stdacct: 編輯普通帳戶資料失敗: %w", err)
	}
	s.log.Info("已編輯普通帳戶顯示名",
		"account", updated.AccountID.String(), "request_id", requestID)
	return updated, nil
}

// readStandardProfile 是詳情與編輯前後共用的單筆讀法：q 由呼叫端給（autocommit 連線或交易）。
//
// 三道範圍檢查各擋一種「不該被這條通路動到」的行的形態，順序是刻意的：
// 先問帳戶本身存不存在（不在就不必再問他是誰），再問他是不是管理員，
// 最後問他是不是已進入刪除終態。任何一道出局都回同一個 ErrAccountNotFound，
// 讓呼叫端拿不到「差哪一半」的信號。
func (s *Service) readStandardProfile(ctx context.Context, q database.Querier,
	accountID idgen.ID) (StandardProfile, error) {
	if accountID.IsNil() {
		return StandardProfile{}, ErrAccountNotFound
	}
	a, err := s.accounts.ByID(ctx, q, accountID)
	if err != nil {
		return StandardProfile{}, err
	}
	// 「查無授予」在這裡是好消息：他確實只是一個普通帳戶。拿 ErrNotFound 對照
	// 而不是另寫一份「他是不是管理員」的探測，是因為這句話的權威在 internal/grant，
	// 本套件只是讀者；grant 內部的其他失敗（資料庫故障）原樣上拋，不降級成「不在目錄」。
	if _, err := s.grants.GrantedAt(ctx, q, accountID, identity.RoleServerAdmin); err == nil {
		return StandardProfile{}, ErrAccountNotFound
	} else if !errors.Is(err, grant.ErrNotFound) {
		return StandardProfile{}, err
	}
	// 刪除終態與審批鏈的兩個狀態都在這裡出局，而且對它們都回同一句 ErrAccountNotFound：
	//   - deleted：沿用既有語意（本目錄按定義不列已刪者，因此不該拿到 2015 那句
	//     「列得到但不接受寫入」的話）；
	//   - pending／rejected：他還在門外，本目錄沒這個人可打理。回「查無此帳戶」而不是
	//     另發一枚「他在待審批」的碼，是因為這句話對操作者與外人意味著同一件事——
	//     這條通路對他沒有可做的動作；待審批名冊是 internal/acctreview 那本獨立的書
	//     （用戶批准的範圍規則：兩本書各寫各的條件，不共用一條 WHERE）。
	// 少這一層的後果是具體的：目錄的 WHERE 把他藏起來之後，只剩按 ID 直打這條路能碰到他，
	// 而 SetStatus 的 CAS 會把他的 pending 當成 expected_status 之外的一種值拒掉——
	// 那是一句「參數不合法」的內部故障而不是範圍拒絕，形體上就像後端壞了。
	if a.Status == account.StatusDeleted || a.Status == account.StatusPending ||
		a.Status == account.StatusRejected {
		return StandardProfile{}, ErrAccountNotFound
	}
	// 退休態刻意留在本目錄的讀取範圍內：那個人被綁走了，但他存在過、他的歷史指得回來，
	// 而「這一行是綁定留痕的來源」正是操作者要看得見的事實。
	// 它不是一個可再被寫入的目標——停用／恢復、重置、升級、再一次綁定四條通路各按
	// 自己的 WHERE 守衛與形態判定把它拒在門外（不是靠這裡不出局來放行的）。
	return StandardProfile{
		AccountID:          a.ID,
		LoginName:          a.LoginName,
		DisplayName:        a.DisplayName,
		Type:               a.Type,
		Status:             a.Status,
		DisabledAt:         a.DisabledAt,
		RetiredAt:          a.RetiredAt,
		MustChangePassword: a.MustChangePassword,
		CreatedAt:          a.CreatedAt,
		LastLoginAt:        a.LastLoginAt,
	}, nil
}

// profileUpdateRecord 產生一筆 Root 域的編輯審計。口徑與 creationRecord 同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆編輯回滾。
//
// ScopeRoot 而不捏造 activity_id：編輯一個伺服器級帳戶的資料不屬於任何活動，
// root_audit 也沒有那一欄（結構上就冒充不了活動歸屬）。審計的動作名以 account.
// 前綴與建號同源，表示「動的是普通帳戶」，與管理員那組 admin.* 分家。
func (s *Service) profileUpdateRecord(principal identity.Principal, before, after StandardProfile,
	requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("stdacct: 主體無法換得審計操作者: %w", err)
	}
	return audit.Record{
		Scope:     audit.ScopeRoot,
		Actor:     actor,
		Action:    "account.profile_update",
		Target:    audit.Target{Kind: "account", ID: after.AccountID.String()},
		Reason:    "伺服器級管理員經已認證會話編輯普通帳戶的顯示名",
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "display_name", Before: before.DisplayName, After: after.DisplayName},
		},
	}, nil
}
