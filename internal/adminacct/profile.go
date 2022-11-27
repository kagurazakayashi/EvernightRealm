// profile.go 是「Root 查看與編輯管理員的非安全資料」：單筆詳情與顯示名編輯。
//
// 與目錄（directory.go）的分工是刻意的：目錄是展示投影，這裡是經過實體校驗的
// 單筆真相——詳情與編輯結果都經 internal/account 的倉儲讀法換回，
// 「介面上呈現的當前資料」與「資料庫保存的結果」因此不可能各說各話。
//
// 編輯的白名單只有一欄：display_name。狀態、憑據、首次改密旗標與帳戶類型
// 不在此通路之內（UPDATE 語句裡連這些欄位都不出現，見 account.Store.UpdateDisplayName），
// 「保存普通資料不能連隱藏欄位一起覆蓋」成立在 SQL 形狀上而不是自律上。
// 併發控制沿用 RotatePassword 的比較-and-set：呼叫端交出它看見過的現值，
// 現值已變時整個編輯不發生並回可判別的衝突錯誤。
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
)

// 資料用例的結論錯誤：非 Root、非目錄成員、併發落敗各自可判別，
// 內部故障一律不進這些型別。
var (
	// ErrAdminNotFound 表示目標不是這本目錄裡的成員：帳戶不存在、或存在但沒有
	// server_admin 授予，兩者收斂成同一個答案。它不提供「差哪一半」的信號——
	// 標識是 UUIDv7，而這個端點本來就只有 Root 敲得動，同形不損失合法性，
	// 卻讓「探測某個標識是不是管理員」少了一種確證。
	ErrAdminNotFound = errors.New("adminacct: 該帳戶不在管理員目錄中")
	// ErrProfileConflict 表示提交所依據的顯示名現值已不是資料庫現值（併發編輯落敗）。
	//
	// 它與 ErrAdminNotFound 分開只為一件事：兩句話的處置不同——一個要人換目標，
	// 另一個只要重讀最新現值再決定改不改。它不該被報成內部錯誤，那是把正常的
	// 併發尾巴說成服務壞了。
	ErrProfileConflict = errors.New("adminacct: 顯示名現值已與提交時所依據的不同")
)

// Profile 是單筆管理員的可展示資料（詳情與編輯結果共用同一個形狀）。
//
// 不含也不可能有：憑據雜湊、會話材料、login_name_key 的內部正規化產物、
// 禁用以外的一切時間以外的隱藏欄位。Roles 由目錄成員資格檢查換得：
// 本端點回答的是「這個管理員的授予事實」，当前集合裡管理員目錄只由
// server_admin 一檔定義（見遷移 0006 的 CHECK）；若未來新增角色檔次，
// 詳情要帶出全量角色時必須經 internal/identity 的載體讀取路徑，
// 而不是在這裡憑猜測多塞一個字串。
type Profile struct {
	// AccountID 為帳戶穩定標識。
	AccountID idgen.ID
	// LoginName 為登入名原始寫法（本步不提供修改通路）。
	LoginName string
	// DisplayName 為顯示名稱。
	DisplayName string
	// Status 為帳戶狀態（只讀展示；停用屬後續步驟）。
	Status account.Status
	// MustChangePassword 為是否仍欠首次改密（只讀展示）。
	MustChangePassword bool
	// Roles 為該帳戶在目錄語境下被核實持有的角色。
	Roles []identity.Role
	// CreatedAt 為帳戶建立時刻。
	CreatedAt time.Time
	// LastLoginAt 為最近一次登入時刻；零值代表從未登入。
	LastLoginAt time.Time
	// GrantedAt 為 server_admin 授予寫下的時刻。
	GrantedAt time.Time
}

// AdminProfile 以 Root 主體讀回單筆管理員詳情。
//
// 讀路徑三步各有其人：accounts.ByID 給經過實體校驗的帳戶真相；
// grants.GrantedAt 同時回答「他在不在目錄裡」與「何時成為管理員」——
// 查無授予就是不在目錄，不另寫第二份成員資格判定。
func (s *Service) AdminProfile(ctx context.Context, principal identity.Principal,
	accountID idgen.ID) (Profile, error) {
	if err := identity.Authorize(principal, identity.NeedRoot); err != nil {
		return Profile{}, err
	}
	profile, err := s.readProfile(ctx, s.db.SQL(), accountID)
	if err != nil {
		// 「查無帳戶」與「查無授予」對 Root 是同一句話：他不在這本目錄裡。
		if errors.Is(err, account.ErrNotFound) || errors.Is(err, grant.ErrNotFound) {
			return Profile{}, ErrAdminNotFound
		}
		return Profile{}, err
	}
	return profile, nil
}

// UpdateAdminProfile 以白名單方式編輯一名管理員的顯示名。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 授權（NeedRoot，與開設、目錄同一道閘）；
//  2. 交易內讀帳戶（經倉儲實體校驗）與核實目錄成員資格：對不在目錄裡的標識，
//     編輯整個不發生，也絕不「先改再說」；
//  3. CAS 更新只碰 display_name：changed=false 時回 ErrProfileConflict 並讓交易回滾，
//     一個字都不落——衝突的保存不是「部分成功」；
//  4. 同一交易內讀回更新後的實體並追加 Root 域審計：編輯與其審計同生同滅，
//     「真实存在卻在 Root 審計裡查不到的改動」與「審計说有而資料庫查不到」同罪。
//
// 被拒的編輯（非 Root、非目錄成員、併發衝突、輸入不合規）不追加審計：
// 與被拒的開設、被拒的撤銷同口徑——拒絕的結論不該成為寫入放大器。
// 成功的編輯必留審計，前後只有 display_name 一欄的舊值與新值：
// 「必要前後摘要」不含其他個人資料，更沒有一個可能容下憑據材料的格子。
func (s *Service) UpdateAdminProfile(ctx context.Context, principal identity.Principal,
	accountID idgen.ID, displayName, expectedDisplayName, requestID string) (Profile, error) {
	if err := identity.Authorize(principal, identity.NeedRoot); err != nil {
		return Profile{}, err
	}
	if accountID.IsNil() {
		return Profile{}, ErrAdminNotFound
	}

	var updated Profile
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		before, err := s.readProfile(tctx, tx, accountID)
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
		after, err := s.readProfile(tctx, tx, accountID)
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
			return Profile{}, ErrAdminNotFound
		case errors.Is(err, ErrProfileConflict), errors.Is(err, ErrAdminNotFound):
			return Profile{}, err
		case errors.Is(err, account.ErrInvalidDisplayName):
			// 可展示的域規則結論：傳輸層據此回 1004 並點出欄位，不進「內部故障」分支。
			return Profile{}, err
		}
		s.log.Error("編輯管理員資料失敗", "request_id", requestID, "err", err)
		return Profile{}, fmt.Errorf("adminacct: 編輯管理員資料失敗: %w", err)
	}
	s.log.Info("Root 已編輯管理員顯示名",
		"account", updated.AccountID.String(), "request_id", requestID)
	return updated, nil
}

// readProfile 是詳情與編輯前後共用的單筆讀法：q 由呼叫端給（autocommit 連線或交易）。
//
// 成員資格以 GrantedAt 查有無為準：它和「何時授予」是同一条查詢的兩句話，
// 不另寫一份存在性探測，避免兩處判定日後各說各話。
func (s *Service) readProfile(ctx context.Context, q database.Querier, accountID idgen.ID) (Profile, error) {
	if accountID.IsNil() {
		return Profile{}, ErrAdminNotFound
	}
	a, err := s.accounts.ByID(ctx, q, accountID)
	if err != nil {
		return Profile{}, err
	}
	grantedAt, err := s.grants.GrantedAt(ctx, q, accountID, identity.RoleServerAdmin)
	if err != nil {
		return Profile{}, err
	}
	return Profile{
		AccountID:          a.ID,
		LoginName:          a.LoginName,
		DisplayName:        a.DisplayName,
		Status:             a.Status,
		MustChangePassword: a.MustChangePassword,
		Roles:              []identity.Role{identity.RoleServerAdmin},
		CreatedAt:          a.CreatedAt,
		LastLoginAt:        a.LastLoginAt,
		GrantedAt:          grantedAt,
	}, nil
}

// profileUpdateRecord 產生一筆 Root 域的編輯審計。口徑與 creationRecord 同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆編輯回滾。
func (s *Service) profileUpdateRecord(principal identity.Principal, before, after Profile,
	requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("adminacct: 主體無法換得審計操作者: %w", err)
	}
	return audit.Record{
		Scope:     audit.ScopeRoot,
		Actor:     actor,
		Action:    "admin.profile_update",
		Target:    audit.Target{Kind: "account", ID: after.AccountID.String()},
		Reason:    "Root 經已認證會話編輯伺服器級管理員的顯示名",
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "display_name", Before: before.DisplayName, After: after.DisplayName},
		},
	}, nil
}
