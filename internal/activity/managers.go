// managers.go 是「誰能管哪個活動」的持久通路：Root 指派與撤銷活動管理人，
// 以及活動自己的管理人名冊讀法。
//
// 這一層補的是 R1-006 留下的空位：身份層與審計層當時都預留了「這個帳戶在哪些活動裡是管理人」
// 這個輸入（identity.NewActivityGrants、audit.Viewer.Activities），但沒有任何落庫來源，
// 於是那句話只能靠測試代用工廠餵進去。本檔提供那個來源，全服務只此一處。
//
// 為什麼指派權限在 Root 而不是活動管理人自己（用戶批准於本步）：
// 「把一個帳戶變成能管某個活動」是一次權限授予，與 Root 開設管理員、Root 簽發准入憑證同側；
// 若讓現任管理人自行加人，一個被駭的管理員帳戶就能把權限自我擴散，而那道動作今天
// 沒有任何獨立的准入口可以核實。Root 之外的一條讀法（管理人看得見自己活動的名冊）
// 不改變這件事：它能讀，不能寫。
//
// 為什麼被指派者必須已經持有 server_admin（用戶批准於本步的邊界）：
// 本步落地的是「活動管理權」，不是「活動內身份」。帳戶在活動裡扮演誰（玩家檔案、NPC 操作者）
// 仍未落地，審計主體換不出那一類（見 identity.AuditActor）。把管理人限在已批准的
// 伺服器級管理員集合裡，因此不需要在此刻發明的新的審計主體類別，也不會出現
// 「一個沒有口令的訪戶持有活動管理權」這種形態（遷移 0012 用觸發器在資料庫層也擋了它）。
// 代價寫清楚：今日要讓某人管一個活動，必須先請 Root 開設或授予他管理員——
// 這是本步的批准邊界，不是實作偷懶。
//
// 三條寫入的規則各自成句，因為處置不同：
//   - 目標帳戶不在管理員目錄（不存在、訪戶、待審批、被拒絕、已被停用）→ ErrManagerNotFound；
//   - 目標已是軟刪除終態 → ErrManagerDeleted（重讀之後也沒有那顆按鈕）；
//   - 他已經是這個活動的管理人 → ErrManagerDuplicate（重複指派不謊報成功，也不記審計）。
package activity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// Manager 是一行活動管理權指派的可展示事實。
type Manager struct {
	// AccountID 為被指派為管理人的帳戶標識。
	AccountID idgen.ID
	// DisplayName 為該帳戶的顯示名（取自帳戶倉儲的實體讀法，不在這裡重新發明的二次真相）。
	DisplayName string
	// GrantedAt 為指派寫下的時刻（注入時鐘；呼叫端無權代填）。
	GrantedAt time.Time
	// AccountStatus 為該帳戶此刻的狀態（active|disabled|deleted 等）。
	//
	// 它存在的理由只有一件事：已進入終態的行仍列、仍可讀（與帳戶目錄同一口徑），
	// 介面要能如實標示「這一行指向一個已被刪除的帳戶」，而不是把它藏起來讓人以為查無此人。
	AccountStatus account.Status
}

// AssignManager 由 Root 把一個既有管理員指派為某個活動的管理人。
//
// 全部寫入落在同一個交易：活動核實、帳戶與授予現讀、指派行、審計四件事同生同滅。
// 「多了一行查不到是誰指派的特權授予」與「審計說指派過而庫裡沒有這行」同罪。
//
// 目標帳戶一律經 internal/account 與 internal/grant 現讀，採信的是「此刻的事實」：
// 請求本體沒有任何欄位能宣告「他有 server_admin」，也沒有格子能填「哪種帳戶」。
func (s *Service) AssignManager(ctx context.Context, principal identity.Principal,
	activityID, accountID idgen.ID, requestID string) (Activity, error) {
	if err := identity.Authorize(principal, identity.NeedRoot); err != nil {
		s.log.Warn("指派活動管理人被拒：主體不具備 Root 權限",
			"subject", principal.String(), "entry", "manager_assign")
		return Activity{}, err
	}
	if activityID.IsNil() || accountID.IsNil() {
		return Activity{}, ErrManagerNotFound
	}

	var updated Activity
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		current, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		if err := requireNotArchived(current); err != nil {
			return err
		}
		if err := s.requireEligibleManager(tctx, tx, accountID); err != nil {
			return err
		}
		assigned, err := s.store.AssignManager(tctx, tx, activityID, accountID)
		if err != nil {
			return err
		}
		if !assigned {
			return ErrManagerDuplicate
		}
		rec, err := s.activityRecord(principal, activityID, "activity.manager_assign", "account",
			accountID.String(), "Root 經已認證會話指派活動管理人", requestID,
			auditChange("manager", "", accountID.String()))
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		// 回讀一次：回應要帶著倉儲算出的 manager_count，不是呼叫端推測的那份。
		latest, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		updated = latest
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrActivityNotFound), errors.Is(err, ErrArchived),
			errors.Is(err, ErrManagerNotFound), errors.Is(err, ErrManagerDeleted),
			errors.Is(err, ErrManagerDuplicate), errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return Activity{}, err
		}
		s.log.Error("指派活動管理人失敗", "request_id", requestID, "err", err)
		return Activity{}, fmt.Errorf("activity: 指派活動管理人失敗: %w", err)
	}
	s.log.Info("Root 已指派活動管理人",
		"activity", updated.ID.String(), "account", accountID.String(), "request_id", requestID)
	return updated, nil
}

// requireEligibleManager 核實目標帳戶此刻有資格被指派為活動管理人。
//
// 三條現讀缺一不可，而且都要問對來源：
//   - internal/account 給帳戶實體（型別與狀態）：訪戶按定義不可持有任何管理權，
//     進入終態者一律拒寫，待審批與被拒絕的還不在任何目錄裡；
//   - internal/grant 給伺服器級授予：本步批准的管理人來源是「已持有的管理員」，
//     因此這句話只問 grant，不在這裡攪一份角色；
//   - 停用（disabled）按既有語意「視同不存在」，收斂成查無此人而不是另一句「他被停用了」：
//     能收到這句話的人已經是 Root，而 Root 對停用帳戶本來就有一條恢復的通路。
func (s *Service) requireEligibleManager(ctx context.Context, q database.Querier,
	accountID idgen.ID) error {
	a, err := s.accounts.ByID(ctx, q, accountID)
	if err != nil {
		if errors.Is(err, account.ErrNotFound) {
			return ErrManagerNotFound
		}
		return err
	}
	if a.Type != account.TypeStandard {
		// 訪戶（以及其他不在此列的型別）不可持有活動管理權：資料庫的觸發器也釘著同一句話。
		return ErrManagerNotFound
	}
	switch a.Status {
	case account.StatusDeleted:
		return ErrManagerDeleted
	case account.StatusActive:
	default:
		return ErrManagerNotFound
	}
	if _, err := s.grants.GrantedAt(ctx, q, accountID, identity.RoleServerAdmin); err != nil {
		if errors.Is(err, grant.ErrNotFound) {
			return ErrManagerNotFound
		}
		return err
	}
	return nil
}

// RevokeManager 由 Root 撤銷一筆活動管理權指派。
//
// 撤銷走 DELETE 而不是「改一欄 revoked_at」：指派行的生命週期只有插入與刪除兩種形態
// （與 0006 的授予同一取向），而「他曾經是這個活動的管理人」這件事的留痕在審計裡，
// 不需要在結構裡留一排只服務已消失行的時間戳。
//
// 「本來就沒有這個指派」回報 ErrManagerNotFound 而不是靜默成功：後者會在審計裡
// 記下一件沒發生過的事。已歸檔的活動一律拒寫（包括改名冊）——終態就是終態。
func (s *Service) RevokeManager(ctx context.Context, principal identity.Principal,
	activityID, accountID idgen.ID, requestID string) (Activity, error) {
	if err := identity.Authorize(principal, identity.NeedRoot); err != nil {
		s.log.Warn("撤銷活動管理人被拒：主體不具備 Root 權限",
			"subject", principal.String(), "entry", "manager_revoke")
		return Activity{}, err
	}
	if activityID.IsNil() || accountID.IsNil() {
		return Activity{}, ErrManagerNotFound
	}

	var updated Activity
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		current, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		if err := requireNotArchived(current); err != nil {
			return err
		}
		revoked, err := s.store.RevokeManager(tctx, tx, activityID, accountID)
		if err != nil {
			return err
		}
		if !revoked {
			return ErrManagerNotFound
		}
		rec, err := s.activityRecord(principal, activityID, "activity.manager_revoke", "account",
			accountID.String(), "Root 經已認證會話撤銷活動管理人", requestID,
			auditChange("manager", accountID.String(), ""))
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		latest, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		updated = latest
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrActivityNotFound), errors.Is(err, ErrArchived),
			errors.Is(err, ErrManagerNotFound), errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return Activity{}, err
		}
		s.log.Error("撤銷活動管理人失敗", "request_id", requestID, "err", err)
		return Activity{}, fmt.Errorf("activity: 撤銷活動管理人失敗: %w", err)
	}
	s.log.Info("Root 已撤銷活動管理人",
		"activity", updated.ID.String(), "account", accountID.String(), "request_id", requestID)
	return updated, nil
}

// ManagerRoster 讀回某個活動當前的管理人名冊。
//
// 授權邊界與指派／撤銷不同：這一條走活動作用域判定（Root 或該活動的管理人），
// 因此一個管理人看得見「還有誰在管這個活動」，但他不能據此加人或刪人。
// 它不併進詳情那一個回應：名冊是一筆可大可小的列表，詳情是一行的事實，
// 兩者的分頁與成本不同，混在一起只會讓詳情變成一條能拖出整張表的讀法。
func (s *Service) ManagerRoster(ctx context.Context, principal identity.Principal,
	activityID idgen.ID) ([]Manager, error) {
	q := s.db.SQL()
	if err := s.requireActivityScope(ctx, q, principal, activityID, "manager_roster"); err != nil {
		return nil, err
	}
	// 先確認活動本身存在再去讀名冊：Root 不受指派約束，若跳過這一步，
	// 「一個從沒存在的活動」會在它眼前回成一份空名冊，而空名冊的語意是「這活動還沒管理人」。
	if _, err := s.readActivity(ctx, q, activityID); err != nil {
		return nil, err
	}
	rows, err := s.store.Managers(ctx, q, activityID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrActivityNotFound
		}
		s.log.Error("讀取活動管理人名冊失敗", "err", err)
		return nil, fmt.Errorf("activity: 讀取活動管理人名冊失敗: %w", err)
	}
	out := make([]Manager, 0, len(rows))
	for _, row := range rows {
		m := Manager{AccountID: row.AccountID, GrantedAt: row.GrantedAt}
		a, err := s.accounts.ByID(ctx, q, row.AccountID)
		if err != nil {
			// 軟參照的代價在這裡露面：指向的帳戶行被物理清理後，這一行的顯示名讀不到。
			// 此時如實標成查無此人、狀態照讀得的留空——不偽造一個名字，也不把整份名冊判死。
			if !errors.Is(err, account.ErrNotFound) {
				return nil, err
			}
			m.AccountStatus = ""
			m.DisplayName = ""
			out = append(out, m)
			continue
		}
		m.DisplayName = a.DisplayName
		m.AccountStatus = a.Status
		out = append(out, m)
	}
	return out, nil
}
