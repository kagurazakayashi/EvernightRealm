// selfselect.go 是「玩家自選陣營」的三條用例：活動側那一欄配置的寫入、
// 玩家在某一場活動裡的現況讀法（含他參加了哪些活動），以及玩家自己的陣營寫入。
//
// 這一層把本步批準的四件事凝成同一條通路：
//   - 準入是兩套，不是一套：配置屬活動管理面（NeedServerAdmin 加上這個活動的一行指派，
//     判定仍是 requireActivityScope 這一處）；自選屬玩家本人的活動內身份，
//     只問「這次請求的憑據此刻換出的是哪一個帳戶」，再按（活動, 那個帳戶）讀回他自己的
//     成員行。請求本體沒有任何格子能填「動哪一個玩家」，也沒有格子能填「哪一場活動」，
//     兩者都由路徑與會話決定——把管理面那條通用編輯通路開放給玩家並不等於授權，
//     它是「任何人可以改任何人的資料」，因此這裡另開一條只碰自己一欄的路。
//   - 每一次寫入都在自己的交易內重新問全部規則：活動的生命週期、那一欄配置、
//     他自己是不是成員、僅首次模式下是否已經選過、目標陣營此刻收不收新成員。
//     規則檢查與歸屬寫入落在同一個一致性邊界內：關閉自選、停用陣營與玩家的寫入併發時，
//     SQLite 的單寫者串行保證「檢查時的現值」與「隨後那筆寫入」看見同一個快照，
//     不會出現先查後在另一條無保護交易裡寫的那段視窗。
//   - 自選只能設定歸屬，不能清空（用戶批準於本步）：把歸屬改回「尚未分組」屬管理側分配通路，
//     今日不存在那條路，因此這條通路的本體裡沒有一個格子能表達「無陣營」。
//   - 寫入與其審計同生同滅，而審計主體是他在這場活動內的玩家身份
//     （見 identity.AuditActorAsActivityMember 的理由）。
//
// 本步沒有的東西，也不假裝有：管理員把人分進陣營與遷出（另一條通路）、把成員移出活動、
// 活動內角色、人數配額、付費切換、冷卻與審批——後四項從未被批準，這裡一欄都不加。
package activity

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// MemberActivityEntry 是「這個帳戶在哪一場活動裡有身份」加上那場活動的現值。
//
// 兩份事實各自來自自己的表與自己的讀法（成員行走 activity_members，活動經單筆讀法），
// 因此這裡不是第三個答案來源；它只回答介面那一張清單要同時顯示的兩欄事實。
type MemberActivityEntry struct {
	// Activity 是該成員行所屬活動的現值（狀態與自選模式都在其中）。
	Activity Activity
	// Member 是這個帳戶在那場活動裡的成員行（含此刻的陣營歸屬）。
	Member Member
}

// MyActivityEntries 以當前受信主體讀「我參加了哪些活動」。
//
// 它是玩家側唯一的活動入口讀法：清單只由他自己的成員行決定，不多出一條「所有活動目錄」
// 的讀法——玩家能看到哪些活動，答案就是「他有身份的那些」，這不需要另外發明規則。
// 每一行的活動現值經單筆讀法逐行讀回（口徑同 Members 逐行現讀帳戶）：
// 某一行讀不回時整個讀法回報錯誤而不是默默少一列，因為「他是不是這場活動的成員」與
// 「這場活動現在什麼狀態」必須同時成立才有意義。
func (s *Service) MyActivityEntries(ctx context.Context,
	principal identity.Principal) ([]MemberActivityEntry, error) {
	accountID, err := s.requireSelfPrincipal(principal, "faction_select_directory")
	if err != nil {
		return nil, err
	}
	q := s.db.SQL()
	rows, err := s.store.MembersByAccount(ctx, q, accountID)
	if err != nil {
		s.log.Error("讀取本人成員身份失敗", "err", err)
		return nil, fmt.Errorf("activity: 讀取本人成員身份失敗: %w", err)
	}
	out := make([]MemberActivityEntry, 0, len(rows))
	for _, row := range rows {
		entry := MemberActivityEntry{Member: row}
		a, err := s.readActivity(ctx, q, row.ActivityID)
		if err != nil {
			if errors.Is(err, ErrActivityNotFound) {
				// 成員行指向的活動讀不到屬資料缺陷（0014 對 activities 配的是硬外鍵，
				// 今日也沒有任何物理刪除活動的通路）：少一列比報錯更容易被當成「我沒參加」，
				// 因此如實回錯，讓它成為一個查得出來的缺陷而不是一個靜默的事實缺失。
				s.log.Error("本人成員行指向的活動讀不到", "member", row.ID.String(),
					"activity", row.ActivityID.String())
			}
			return nil, err
		}
		entry.Activity = a
		out = append(out, entry)
	}
	return out, nil
}

// MyFactionSelection 讀回「我在這場活動裡的陣營現況」：活動配置、我自己的成員行、
// 這場活動的陣營候選清單與每一項此刻可不可選。
//
// 順序只有兩跳，而且第一跳就決定可見範圍：先按（活動, 本次會話的帳戶）讀自己的成員行，
// 讀不到就是 ErrMemberNotFound——它與「根本沒有這場活動」「他不是任何地方的成員」
// 同一句話，玩家因此不會因為敲路徑就多知道「那個活動存在但沒我」。
// 讀到之後才讀活動與陣營清單。這裡不重複寫入通路的時機判定：CanSelectNow 只是顯示面，
// 真正擋住寫入的是 SelectOwnFaction 在自己交易內的那幾句。
func (s *Service) MyFactionSelection(ctx context.Context,
	principal identity.Principal, activityID idgen.ID) (FactionSelectionView, error) {
	accountID, err := s.requireSelfPrincipal(principal, "faction_select_view")
	if err != nil {
		return FactionSelectionView{}, err
	}
	q := s.db.SQL()
	member, err := s.store.MemberByAccount(ctx, q, activityID, accountID)
	if err != nil {
		return FactionSelectionView{}, err
	}
	// 訪問判定排在讀到自己的行之後、湊候選清單之前：被限制的人對這一族的回答
	// 只有一句話（2043），而查無與跨活動仍然先收斂成 1001 那句不可分辨的話。
	if err := checkMemberActivityAccess(member); err != nil {
		return FactionSelectionView{}, err
	}
	a, err := s.readActivity(ctx, q, member.ActivityID)
	if err != nil {
		return FactionSelectionView{}, err
	}
	factions, err := s.store.Factions(ctx, q, member.ActivityID)
	if err != nil {
		s.log.Error("讀取自選陣營候選清單失敗", "activity", member.ActivityID.String(), "err", err)
		return FactionSelectionView{}, fmt.Errorf("activity: 讀取自選陣營候選清單失敗: %w", err)
	}
	timingOK := ensureFactionSelectTiming(a) == nil
	options := make([]FactionOption, 0, len(factions))
	for _, faction := range factions {
		options = append(options, FactionOption{
			Faction:    faction,
			Selectable: factionOptionSelectable(faction, timingOK),
		})
	}
	return FactionSelectionView{Activity: a, Member: member, Options: options}, nil
}

// SelectOwnFaction 讓本次會話的帳戶在自己那一場活動裡把陣營歸屬換成一個此刻可用的陣營。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 主體必須是一個帳戶（會話決定，不是請求決定）；
//  2. 交易內讀活動現值（查無與「不歸你管」同一句話）；
//  3. 交易內按（活動, 這個帳戶）讀回他自己的成員行——「動的是誰」到這裡才有了唯一答案。
//     這一跳刻意排在時機判定之前：非成員若先聽到「還在草稿」或「沒開放自選」，
//     他就確認了那個標識確實是一場活動，1001 的不可分辨性等於白寫；
//  4. 交易內問時機那句話（終態→停止→草稿→配置，見 ensureFactionSelectTiming）；
//  5. 僅首次模式下他已有歸屬時當場拒絕（ErrFactionSelectLockedIn）；
//  6. 目標與依據值同一格時當場拒絕（那請求講不出任何一次改動，落庫與審計都不該為它有事發生）；
//  7. 交易內呼叫 EnsureFactionAcceptsNewMembers——這是它的第一個呼叫端：目標陣營必須屬於
//     這個活動、且此刻仍接收新成員（停用即 ErrFactionNotAcceptingMembers）；
//  8. 帶 WHERE 的單向 UPDATE 只碰 faction_id 一欄：贏家與落敗者由 RowsAffected 分辨，
//     落敗的那一個一個字都沒落，也不留下第二條審計；
//  9. 同一交易內讀回並追加活動域審計，操作者是他在這場活動內的玩家身份。
//
// 被拒的自選（無資格、時機未到、已鎖定、停用、併發落敗）不追加審計（口徑同其餘活動域寫入）。
func (s *Service) SelectOwnFaction(ctx context.Context, principal identity.Principal,
	activityID, factionID, expectedFactionID idgen.ID, requestID string) (Member, error) {
	accountID, err := s.requireSelfPrincipal(principal, "faction_select_self")
	if err != nil {
		return Member{}, err
	}
	if factionID.IsNil() {
		// 自選沒有「清空歸屬」這一步：零值目標不是「把他改成未分組」的合法寫法。
		return Member{}, ErrInvalidFactionSelection
	}
	if factionID == expectedFactionID {
		return Member{}, ErrInvalidFactionSelection
	}

	var updated Member
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		a, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		// 成員行的核實排在時機判定之前：順序反過來時，一個非成員就能靠「這活動還在草稿」
		// 或「還沒開放自選」那兩句確認「這個標識確實是一場活動」，1001 那層不可分辨性就漏了。
		// 讀不到成員行一律 ErrMemberNotFound，與幽靈活動、與「有這場活動但沒我的份」同一句話。
		before, err := s.store.MemberByAccount(tctx, tx, activityID, accountID)
		if err != nil {
			return err
		}
		// 訪問資格與其餘規則同在這一筆交易內現讀：單寫者串行下，
		// 「剛被設成禁止登入」與「這次自選」不會各拿一份舊快照（口徑同時機判定與停用核實）。
		if err := checkMemberActivityAccess(before); err != nil {
			return err
		}
		if err := ensureFactionSelectTiming(a); err != nil {
			return err
		}
		if before.HasFaction() && !a.FactionSelectMode.allowsRepeatSelection() {
			return ErrFactionSelectLockedIn
		}
		if _, err := s.EnsureFactionAcceptsNewMembers(tctx, tx, activityID, factionID); err != nil {
			return err
		}
		changed, err := s.store.UpdateMemberFaction(tctx, tx, before.ID, activityID,
			factionID, expectedFactionID)
		if err != nil {
			return err
		}
		if !changed {
			return ErrMemberProfileConflict
		}
		after, err := s.store.MemberByID(tctx, tx, before.ID)
		if err != nil {
			return err
		}
		rec, err := s.selfSelectionRecord(principal, after, before.FactionID, requestID)
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
		case errors.Is(err, ErrActivityNotFound), errors.Is(err, ErrMemberNotFound),
			errors.Is(err, ErrFactionNotFound), errors.Is(err, ErrInvalidFactionSelection),
			errors.Is(err, ErrFactionNotAcceptingMembers),
			errors.Is(err, ErrFactionSelectDisabled), errors.Is(err, ErrFactionSelectNotOpen),
			errors.Is(err, ErrFactionSelectLockedIn), errors.Is(err, ErrMemberProfileConflict),
			errors.Is(err, ErrArchived), errors.Is(err, ErrActivityClosedWrites),
			errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated):
			return Member{}, err
		}
		s.log.Error("玩家自選陣營失敗", "request_id", requestID, "err", err)
		return Member{}, fmt.Errorf("activity: 玩家自選陣營失敗: %w", err)
	}
	s.log.Info("已完成玩家自選陣營",
		"activity", activityID.String(), "member", updated.ID.String(), "request_id", requestID)
	return updated, nil
}

// UpdateFactionSelectMode 以白名單方式編輯一場活動的「玩家自選陣營」那一欄配置。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 域校驗（在寫之前，不在撞 CHECK 之後）；
//  2. 交易內判定活動作用域（NeedServerAdmin 加上這一行指派）；
//  3. 交易內讀活動現值並核實它還沒進入終態：這是一欄活動配置，與名稱／描述同側，
//     因此停止態照樣可以準備「重開之後要不要讓玩家自己選」；
//     而玩家在停止態本來就寫不進來（自選通路問的是 active，見 ensureFactionSelectTiming），
//     這裡不需要另外一套門禁；
//  4. CAS 更新只碰 faction_select_mode 一欄：changed=false 時整個編輯不發生並回衝突；
//  5. 同一交易內讀回並追加活動域審計——前後只有這一欄。
//
// 改配置不改寫任何人的既有歸屬：從 free 收回 first_only 或 disabled，也不會把任何人
//
//	已經選過的陣營清掉或搬走（保留歸屬是陣營停用那一步同樣的態度：開關只約束往後
//
// 能不能發生，不改寫已經發生的事實）。被拒的編輯不追加審計。
func (s *Service) UpdateFactionSelectMode(ctx context.Context, principal identity.Principal,
	activityID idgen.ID, mode, expectedMode FactionSelectMode,
	requestID string) (Activity, error) {
	if !mode.valid() {
		return Activity{}, fmt.Errorf("%w：模式 %q 不在封閉集合內",
			ErrInvalidFactionSelectMode, string(mode))
	}
	if !expectedMode.valid() {
		return Activity{}, fmt.Errorf("%w：依據值 %q 不在封閉集合內",
			ErrInvalidFactionSelectMode, string(expectedMode))
	}

	var updated Activity
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID,
			"faction_select_config_update"); err != nil {
			return err
		}
		before, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		if err := requireNotArchived(before); err != nil {
			return err
		}
		changed, err := s.store.UpdateFactionSelectMode(tctx, tx, activityID, mode, expectedMode)
		if err != nil {
			return err
		}
		if !changed {
			return ErrProfileConflict
		}
		after, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		rec, err := s.activityRecord(principal, activityID, "activity.faction_select_update",
			"activity", activityID.String(), "管理員經已認證會話變更玩家自選陣營設定", requestID,
			auditChange("faction_select_mode", before.FactionSelectMode.String(),
				after.FactionSelectMode.String()))
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
		case errors.Is(err, ErrActivityNotFound), errors.Is(err, ErrProfileConflict),
			errors.Is(err, ErrArchived), errors.Is(err, ErrInvalidFactionSelectMode),
			errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return Activity{}, err
		}
		s.log.Error("變更自選陣營配置失敗", "request_id", requestID, "err", err)
		return Activity{}, fmt.Errorf("activity: 變更自選陣營配置失敗: %w", err)
	}
	s.log.Info("已變更自選陣營配置",
		"activity", updated.ID.String(), "mode", updated.FactionSelectMode.String(),
		"request_id", requestID)
	return updated, nil
}

// requireSelfPrincipal 回答「這次請求的憑據此刻換出的是哪一個帳戶」。
//
// 它是玩家側通路唯一的身份來源：路徑引數裡沒有一格能填「哪個玩家」，請求本體也沒有，
// 而 Root 與系統主體根本不在 accounts 表裡，沒有可指向的成員行——兩者一律收斂成
// ErrMemberNotFound（對外與幽靈同形），不另開一句「你不是帳戶」。
// 未通過認證的主體先撞在 ErrNotAuthenticated 上：身分問題的優先級高於「他是不是成員」。
func (s *Service) requireSelfPrincipal(principal identity.Principal, requestTag string) (idgen.ID, error) {
	if err := identity.Authorize(principal, identity.NeedAuthenticated); err != nil {
		s.log.Warn("玩家自選動作被拒：主體未通過認證",
			"subject", principal.String(), "entry", requestTag)
		return idgen.Nil, err
	}
	if principal.Kind() != identity.KindAccount {
		return idgen.Nil, ErrMemberNotFound
	}
	accountID := principal.AccountID()
	if accountID.IsNil() {
		return idgen.Nil, ErrMemberNotFound
	}
	return accountID, nil
}

// selfSelectionRecord 產生一筆玩家自選的活動域審計：前後只有 faction_id 一欄。
//
// 操作者經 AuditActorAsActivityMember 換得，輸入是剛在同一個交易內讀回的那一行成員的標識——
// 不是呼叫端交來的任何東西。換不出主體就讓整個自選回滾（口徑同其餘寫入通路：
// 一條「改了東西卻查不到是誰」的記錄正是審計要防的那件事）。
// before 與 after 的歸屬都是標識字串；無陣營側出口成空字串，它屬合法現值（尚未分組）。
func (s *Service) selfSelectionRecord(principal identity.Principal, after Member,
	beforeFactionID idgen.ID, requestID string) (audit.Record, error) {
	actor, err := principal.AuditActorAsActivityMember(after.ID)
	if err != nil {
		return audit.Record{}, fmt.Errorf("activity: 主體無法換得活動內審計操作者: %w", err)
	}
	return activityRecordWith(actor, after.ActivityID, "member.faction_select", "member",
		after.ID.String(), "玩家經已認證會話在活動內自選陣營", requestID,
		auditChange("faction_id", factionIDForAudit(beforeFactionID),
			factionIDForAudit(after.FactionID))), nil
}

// factionIDForAudit 把歸屬換成審計 changes 裡的可比對字串：零值（尚未分組）出口為空字串，
// 而不是把全零的 UUID 寫進前後值——那個寫法既解析不回任何陣營也不是一句人話。
func factionIDForAudit(id idgen.ID) string {
	if id.IsNil() {
		return ""
	}
	return id.String()
}
