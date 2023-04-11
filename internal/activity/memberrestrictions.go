// memberrestrictions.go 是「玩家分項限制與活動訪問控制」的用例層：
// 六枚限制旗標的統一能力判定介面、管理人對單一行成員的逐項編輯，
// 以及本人查閱自己有效結果的讀法。
//
// 這一層把本步批准的四件事凝成同一條通路：
//   - 「禁止登入」作用於該活動的訪問資格（用戶批准）： EnsureMemberActivityAccess 是
//     玩家族活動通路唯一的訪問判定點，每一次請求都在自己的連線或交易內現讀成員行，
//     不是「只在新登入時查一次」；普通登入仍可建立全域會話，其他活動與 accounts
//     的任何欄位都不受這一欄影響。管理族的 /admin 通路按伺服器級授予與活動指派判定，
//     不在這六枚旗標的作用對象內——凍結目標玩家不會讓管理者連解除都做不了。
//   - 其餘五項（聊天、私聊、交易、轉賬、使用物品）對應的業務今日尚未實現：
//     EnsureMemberCapability 只交付判定介面與領域測試，沒有任何真實業務呼叫端，
//     也不對外發機器錯誤碼。將來的業務通路必須在自己的寫入交易內呼叫它。
//   - 六項彼此獨立、預設不限制：編輯只碰明確提交的鍵（倉儲的 SET 子句形状即保證），
//     依據值過期時整個編輯不落；沒有總開關，也沒有「一次全清」。
//   - 寫入與其審計同生同滅，被拒的編輯一條痕都不留；審計帶操作者、時間、請求標識
//     與逐欄前後值。原因句是服務端固定敘述，玩家讀不到——本人那一側只拿到六個布林。
//
// 豁免在這裡不存在也不被否認：旗標掛在成員行上，Root、系統與訪客主體在玩家族
// 沒有可指向的行或與普通帳戶同一判定（requireSelfPrincipal 口徑）；
// 同時持有 server_admin 的成員在玩家族照樣受限，那是「限制只作用成員身份」
// 的本步批准語意，不是發明的例外。
package activity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// EnsureMemberActivityAccess 回答「這個帳戶此刻能不能繼續使用這一場活動的訪問資格」。
//
// 它是玩家族活動通路唯一的訪問判定點，讀的是 activity_members 現值（遷移 0019）：
//   - 按（活動, 帳戶）讀不到成員行時原樣上拋 ErrMemberNotFound——查無、跨活動與
//     「沒有這份身份」必須先收斂成 1001 那句不可分辨的話，被限制的人才能聽到 2043；
//     順序反過來（先判限制再判存在）會讓敲路徑的人拿一枚「存在但被擋」的存在性信號。
//   - 讀到且 restrict_login 為真時回 ErrMemberAccessRestricted。
//   - 每一次呼叫都重新現讀：這一刻沒有快取，也不採信請求交來的任何一格。
//     倉庫今日沒有實時層，本步的失效形態就是「下一次請求按新值回答」，不宣稱推送。
//
// 它接受 Querier 而不是強制 *database.Tx：讀端點在只讀連線内呼叫，寫入通路
// （如將來的分配、貼標）必須在自己的寫入交易內呼叫——兩者拿到的都是同一句現讀。
func (s *Service) EnsureMemberActivityAccess(ctx context.Context, q database.Querier,
	activityID, accountID idgen.ID) (Member, error) {
	return s.EnsureMemberCapability(ctx, q, activityID, accountID, RestrictionLogin)
}

// EnsureMemberCapability 是六項分項限制與狀態規則的統一能力判定介面。
//
// 判定在同一次現讀裡合併四個來源，任何一個拒絕即拒絕：
//   - identity：成員行讀不到（原樣上拋 ErrMemberNotFound）或成員指向的帳戶此刻
//     不是可用的普通／訪戶身份；
//   - lifecycle：活動停止或歸檔時拒絕五項業務能力，login 不受它影響（仍可查看）；
//   - status：當前業務狀態的能力矩陣（每個活動一份，現讀，無快取）；
//   - manual：成員行上同名的分項限制旗標。
//
// login 的對外順序：身份失效先答（前置拒絕），其後是已批准的手動先於狀態
// （2043 先於 2044）；兩者同時存在時回 2043，能力摘要仍並列列出兩個來源。
// 其餘五項回帶鍵與來源的型別錯誤，將來的業務通路據自己的語意發碼——
// 今日沒有端點，故不發碼。
//
// 將來的每一條業務通路必須在自己的寫入交易內呼叫本函式（q 傳那個 *database.Tx），
// 讓「檢查時的現值」與「隨後那筆寫入」看見同一個快照。
func (s *Service) EnsureMemberCapability(ctx context.Context, q database.Querier,
	activityID, accountID idgen.ID, key MemberRestrictionKey) (Member, error) {
	if !key.valid() {
		return Member{}, fmt.Errorf("%w：限制鍵 %q 不在封閉集合內",
			ErrInvalidRestrictionUpdate, string(key))
	}
	member, err := s.store.MemberByAccount(ctx, q, activityID, accountID)
	if err != nil {
		return Member{}, err
	}
	a, err := s.readActivity(ctx, q, activityID)
	if err != nil {
		return Member{}, err
	}
	rules, err := s.store.CapabilityRuleSet(ctx, q, activityID)
	if err != nil {
		return Member{}, err
	}
	if !member.BusinessStatus.valid() {
		return Member{}, fmt.Errorf("capability: 成員 %s 的業務狀態 %q 不在內建集合內",
			member.ID.String(), member.BusinessStatus.String())
	}

	identityDenied := false
	if acct, err := s.accounts.ByID(ctx, q, accountID); err != nil {
		if !errors.Is(err, account.ErrNotFound) {
			return Member{}, err
		}
		identityDenied = true
	} else {
		switch acct.Type {
		case account.TypeStandard, account.TypeGuest:
		default:
			identityDenied = true
		}
		if acct.Status != account.StatusActive {
			identityDenied = true
		}
	}

	restricted, ok := member.RestrictionValue(key)
	if !ok {
		// RestrictionValue 的 ok 只可能因封閉集合漂移而出假；這裡如實報錯，
		// 不降級成「當成不限制」。
		return Member{}, fmt.Errorf("%w：限制鍵 %q 在領域層讀不到對應欄位",
			ErrInvalidRestrictionUpdate, string(key))
	}
	statusDenied := rules.Denied(member.BusinessStatus, key)
	lifecycleDenied := key != RestrictionLogin && !a.Status.AllowsBusinessWrites()

	sources := make([]CapabilitySource, 0, len(capabilitySourceOrder))
	if identityDenied {
		sources = append(sources, CapabilitySourceIdentity)
	}
	if lifecycleDenied {
		sources = append(sources, CapabilitySourceLifecycle)
	}
	if statusDenied {
		sources = append(sources, CapabilitySourceStatus)
	}
	if restricted {
		sources = append(sources, CapabilitySourceManual)
	}
	if len(sources) == 0 {
		return member, nil
	}
	if key == RestrictionLogin {
		switch {
		case identityDenied:
			// 身份資格是前置拒絕：帳戶失效時先答這一句，不把它說成某一項業務限制。
			return Member{}, ErrMemberIdentityInvalid
		case restricted:
			return Member{}, ErrMemberAccessRestricted
		case statusDenied:
			return Member{}, ErrMemberStatusRestricted
		}
	}
	return Member{}, &MemberCapabilityRestrictedError{Key: key, Sources: sources}
}

// checkMemberActivityAccess 把一行剛現讀的成員換成活動訪問結論。
//
// 玩家族的所有讀法與寫入都在自己那條現讀之後問這一句；判定輸入永遠是
// 庫中現值，不是請求交來的任何一格。訪問資格只看兩件事：手動 restrict_login
// 與當前業務狀態規則裡的 login 那一格。生命週期不拒絕查看（停止與歸檔仍可讀），
// 身份資格由會話與成員行本身負責（讀不到成員行時先收斂 ErrMemberNotFound）。
//
// 手動先於狀態是已批准的對外顺序：兩者同時存在時回 2043，能力摘要仍並列兩個來源；
// 解除手動後若狀態仍拒絕，下一筆請求回 2044——不會出現「已解凍」的假話。
func (s *Service) checkMemberActivityAccess(ctx context.Context, q database.Querier,
	member Member) error {
	if member.RestrictLogin {
		// 手動限制先答：它是已發布的 2043，且不必為一個已被手動擋下的人再讀矩陣。
		return ErrMemberAccessRestricted
	}
	rules, err := s.store.CapabilityRuleSet(ctx, q, member.ActivityID)
	if err != nil {
		return err
	}
	if rules.Denied(member.BusinessStatus, RestrictionLogin) {
		return ErrMemberStatusRestricted
	}
	return nil
}

// OwnMemberRestrictions 讀回「本次會話帳戶在那場活動裡的六枚限制現值」。
//
// 這是用戶批准的「本人獲准查看有效結果」那一側：即使 restrict_login 為真、
// 該活動的其他讀法一律 2043，這一條仍然讀得動——被限制的人必須能問出
// 「我被限制的是什麼」，否則限制對他自己是一句無法核實的指控。
// 判定順序與玩家族其餘讀法同形：主體必須是帳戶（會話決定，不是請求決定），
// 然後按（活動, 那個帳戶）現讀他自己的行；查無與跨活動同收斂成 1001 那句話。
// 這一行刻意排在限制判定之外：本通路是「讀自己的六欄事實」，不是「使用該活動的訪問資格」。
// 回應只有六個布林與標識：沒有原因、沒有操作者、沒有時間——那些屬審計，
// 而本倉庫今日沒有審計查詢的 HTTP 入口（批准邊界）。
func (s *Service) OwnMemberRestrictions(ctx context.Context,
	principal identity.Principal, activityID idgen.ID) (Member, error) {
	accountID, err := s.requireSelfPrincipal(principal, "member_restriction_self")
	if err != nil {
		return Member{}, err
	}
	q := s.db.SQL()
	return s.store.MemberByAccount(ctx, q, activityID, accountID)
}

// UpdateMemberRestrictions 以欄位白名單加比較-and-set 編輯一行成員被選中的那幾枚限制。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 域校驗（在寫之前）：至少一項、鍵在封閉集合內、不重複；
//  2. 交易內判定活動作用域（NeedServerAdmin 加上這個活動的一行指派）——這條屬管理面，
//     普通成員敲不進，而且管理者對目標玩家的編輯權與目標玩家自己的訪問權是兩套判定；
//  3. 交易內現讀業務寫入門禁（停止 2033、歸檔 2029）：限制是對一行成員資料的改動，
//     與改暱稱、改目錄覆蓋同一側；
//  4. 按標識讀回成員並核實它屬於這個活動——跨活動與從未存在同一句話；
//  5. 核實每一枚提交鍵的依據值與庫中現值一致（任一欄過期即整個編輯不落，2013）；
//  6. 全部新值與現值相同時視為冪等成功：不寫入、不追加審計（口徑同成員狀態變更）；
//  7. CAS 更新只碰提交的 restrict_* 欄：changed=false 時整個編輯不發生；
//  8. 同一交易內讀回並追加活動域審計，changes 帶每一枚實際翻動欄位的前後值。
//
// 被拒的編輯（無權、門禁攔下、跨活動、依據值過期、請求寫法不合法）不追加審計。
// 這條通路不碰暱稱、陣營、目錄覆蓋、業務狀態或任何帳戶欄位；
// 它也不停全域會話——「禁止登入」的批准語意是活動級訪問資格。
func (s *Service) UpdateMemberRestrictions(ctx context.Context, principal identity.Principal,
	activityID, memberID idgen.ID, edit MemberRestrictionEdit,
	requestID string) (Member, error) {
	changes, err := validateRestrictionEdit(edit)
	if err != nil {
		return Member{}, err
	}

	var updated Member
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID,
			"member_restriction_update"); err != nil {
			return err
		}
		if _, err := s.EnsureBusinessWritesAllowed(tctx, tx, activityID); err != nil {
			return err
		}
		before, err := s.store.MemberByID(tctx, tx, memberID)
		if err != nil {
			return err
		}
		if before.ActivityID != activityID {
			// 跨活動與從未存在收斂成同一句話（口徑同改暱稱與改狀態）。
			return ErrMemberNotFound
		}
		for _, change := range changes {
			current, ok := before.RestrictionValue(change.Key)
			if !ok {
				return fmt.Errorf("%w：限制鍵 %q 在領域層讀不到對應欄位",
					ErrInvalidRestrictionUpdate, string(change.Key))
			}
			if current != change.Expected {
				return ErrMemberProfileConflict
			}
		}
		flipped := make([]MemberRestrictionChange, 0, len(changes))
		for _, change := range changes {
			current, _ := before.RestrictionValue(change.Key)
			if current != change.Value {
				flipped = append(flipped, change)
			}
		}
		if len(flipped) == 0 {
			// 冪等重送：不寫入、不追加審計。
			if a, err := s.accounts.ByID(tctx, tx, before.AccountID); err == nil {
				before.DisplayName = a.DisplayName
				before.AccountStatus = a.Status
			} else if !errors.Is(err, account.ErrNotFound) {
				return err
			}
			if err := s.fillMemberStatus(tctx, tx, []*Member{&before}); err != nil {
				return err
			}
			updated = before
			return nil
		}
		// 只寫翻動的那幾欄：依據值仍逐欄核實（提交的每一欄都進 WHERE），
		// 與現值相同的那幾欄以同值重寫，不影響正確性也不擴大白名單。
		changed, err := s.store.UpdateMemberRestrictions(tctx, tx, memberID, activityID, changes)
		if err != nil {
			return err
		}
		if !changed {
			return ErrMemberProfileConflict
		}
		after, err := s.store.MemberByID(tctx, tx, memberID)
		if err != nil {
			return err
		}
		if a, err := s.accounts.ByID(tctx, tx, after.AccountID); err == nil {
			after.DisplayName = a.DisplayName
			after.AccountStatus = a.Status
		} else if !errors.Is(err, account.ErrNotFound) {
			return err
		}
		if err := s.fillMemberStatus(tctx, tx, []*Member{&after}); err != nil {
			return err
		}
		auditChanges := make([]audit.Change, 0, len(flipped))
		for _, change := range flipped {
			current, _ := before.RestrictionValue(change.Key)
			auditChanges = append(auditChanges,
				auditChange(change.Key.columnName(),
					fmt.Sprint(current), fmt.Sprint(change.Value)))
		}
		rec, err := s.activityRecord(principal, activityID, "member.restrictions_update",
			"member", after.ID.String(), restrictionEditReason(flipped), requestID,
			auditChanges...)
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
		case errors.Is(err, ErrInvalidRestrictionUpdate), errors.Is(err, ErrActivityNotFound),
			errors.Is(err, ErrMemberNotFound), errors.Is(err, ErrMemberProfileConflict),
			errors.Is(err, ErrArchived), errors.Is(err, ErrActivityClosedWrites),
			errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return Member{}, err
		}
		s.log.Error("變更成員分項限制失敗", "request_id", requestID, "err", err)
		return Member{}, fmt.Errorf("activity: 變更成員分項限制失敗: %w", err)
	}
	s.log.Info("已變更成員分項限制",
		"activity", activityID.String(), "member", updated.ID.String(), "request_id", requestID)
	return updated, nil
}

// restrictionEditReason 換出編輯分項限制那筆審計的原因句子。
//
// 句子按翻動的鍵分岔，因為「凍結了一個玩家」與「解除了一個凍結」在查審計時是兩件事：
//   - 翻動 login 那一句明確寫出批准邊界——活動級訪問資格、立即於下一次請求生效、
//     不停全域會話、不動其他活動、不等帳戶停用；
//   - 其餘五項明確寫出「業務尚未接入」，查痕的人不會把一欄旗標讀成一道已生效的封鎖；
//   - 全部翻回不限制時說「解除」，混合時說「變更」。
//
// 操作者、時間與前後值在記錄的其他欄位，原因句不重複它們。
func restrictionEditReason(flipped []MemberRestrictionChange) string {
	names := make([]string, 0, len(flipped))
	setLogin, clearedLogin := false, false
	for _, change := range flipped {
		if change.Key == RestrictionLogin {
			if change.Value {
				setLogin = true
			} else {
				clearedLogin = true
			}
		}
		names = append(names, restrictionKeyDisplayName(change.Key))
	}
	list := strings.Join(names, "、")
	switch {
	case setLogin:
		return "管理員經已認證會話限制成員活動訪問資格（" + list +
			"）：禁止取得或繼續使用該活動的訪問資格，下一次請求即生效；" +
			"不停用全域帳戶與會話，不影響其他活動，其餘五項業務尚未接入、僅為判定依據"
	case clearedLogin && len(flipped) == 1:
		return "管理員經已認證會話解除成員活動訪問資格限制（" + list +
			"）：下一次請求按現值判定，既不補做也不恢復任何當時被擋的請求"
	default:
		return "管理員經已認證會話變更成員分項限制（" + list +
			"）：逐欄獨立生效，聊天與資產業務尚未接入、限制僅為統一判定依據"
	}
}

// restrictionKeyDisplayName 回傳限制鍵的領域可讀名（審計原因句用，繁體固定敘述）。
//
// 這是服務端句子里的詞，不是四語言文案：玩家看到的永远是六個布林與前端自己的標籤。
func restrictionKeyDisplayName(key MemberRestrictionKey) string {
	switch key {
	case RestrictionLogin:
		return "登入"
	case RestrictionChat:
		return "聊天"
	case RestrictionPrivateChat:
		return "私聊"
	case RestrictionTrade:
		return "交易"
	case RestrictionTransfer:
		return "轉賬"
	case RestrictionItemUse:
		return "使用物品"
	}
	return key.String()
}
