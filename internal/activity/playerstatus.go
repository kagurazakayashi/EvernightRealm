// playerstatus.go 是玩家業務狀態的三組用例：讀寫活動內的狀態定義目錄（七個內建鍵的
// 顯示名稱覆蓋與自訂狀態）、變更單一成員目前的業務狀態，以及把狀態投影填進成員、
// 名冊、目錄與本人資料的共用讀法。
//
// 這一層把本步批准的五件事凝成同一條通路：
//   - 准入沿用活動管理權的現讀口徑（NeedServerAdmin 加上這個活動的一行指派，
//     判定只有 requireActivityScope 這一處）；普通成員敲不開任何一條寫入路徑。
//   - 狀態定義的改名與停用屬活動配置：停止態仍可準備，歸檔態一律拒寫（2029）；
//     成員目前狀態的變更屬業務寫入，先過 EnsureBusinessWritesAllowed（停止 2033、
//     歸檔 2029）。
//   - 寫入與其審計同生同滅；被拒的寫入一條痕都不留。
//   - 顯示名稱只是展示值：改名不改內部鍵、不改自訂定義標識，也不改寫任何成員的目前狀態。
//   - 自訂狀態只停用、不刪除：停用不清空任何既有成員的狀態、不改寫標識，雙向可逆。
//
// 狀態不是連線狀態：這一層沒有任何一條路徑會因為請求抵達、頁面開啟或時間流逝而改寫狀態；
// offline 只能由管理員經本檔的變更用例明確寫入。
package activity

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// PlayerStatusCatalog 以當前受信主體讀一個活動的狀態定義目錄（七個內建鍵與自訂定義）。
//
// 這是管理面的讀法：停止與歸檔的活動照樣可讀，因為「這場活動當時定義了什麼狀態」是
// 歷史事實。普通玩家沒有這一條讀法；他們只會在可見的成員投影裡看到對方的狀態名稱。
func (s *Service) PlayerStatusCatalog(ctx context.Context, principal identity.Principal,
	activityID idgen.ID) (PlayerStatusCatalog, error) {
	q := s.db.SQL()
	if err := s.requireActivityScope(ctx, q, principal, activityID, "player_status_list"); err != nil {
		return PlayerStatusCatalog{}, err
	}
	if _, err := s.readActivity(ctx, q, activityID); err != nil {
		return PlayerStatusCatalog{}, err
	}
	labels, err := s.store.StatusLabelOverrides(ctx, q, activityID)
	if err != nil {
		s.log.Error("讀取狀態顯示名稱覆蓋失敗", "activity", activityID.String(), "err", err)
		return PlayerStatusCatalog{}, fmt.Errorf("activity: 讀取狀態顯示名稱覆蓋失敗: %w", err)
	}
	custom, err := s.store.CustomStatuses(ctx, q, activityID)
	if err != nil {
		s.log.Error("讀取自訂狀態列表失敗", "activity", activityID.String(), "err", err)
		return PlayerStatusCatalog{}, fmt.Errorf("activity: 讀取自訂狀態列表失敗: %w", err)
	}
	builtins := make([]BuiltinStatusView, 0, len(builtinBusinessStatuses))
	for _, key := range builtinBusinessStatuses {
		builtins = append(builtins, BuiltinStatusView{Key: key, DisplayName: labels[key]})
	}
	return PlayerStatusCatalog{Builtins: builtins, Custom: custom}, nil
}

// CreateCustomStatus 在一個活動裡建立自訂狀態定義。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 域校驗（在寫之前，不在撞 CHECK 之後）；
//  2. 交易內判定活動作用域；
//  3. 交易內讀活動現值並核實它還沒進入終態（停止態仍可準備自訂狀態）；
//  4. 交易內核實同活動內名稱未占用（UNIQUE 才是正確性來源）；
//  5. 交易內落庫（出生即可用，標識與時刻各只有一個產生點）；
//  6. 同一交易內追加活動域審計。
//
// 被拒的建立（無權、已歸檔、重名、名稱不合法）不追加審計。
func (s *Service) CreateCustomStatus(ctx context.Context, principal identity.Principal,
	activityID idgen.ID, name, requestID string) (CustomStatus, error) {
	checkedName, err := validateStatusDisplayName(name, false)
	if err != nil {
		return CustomStatus{}, err
	}

	var created CustomStatus
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID,
			"player_status_create"); err != nil {
			return err
		}
		before, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		if err := requireNotArchived(before); err != nil {
			return err
		}
		taken, err := s.store.CustomStatusNameTaken(tctx, tx, activityID, checkedName, idgen.ID{})
		if err != nil {
			return err
		}
		if taken {
			return ErrCustomStatusNameTaken
		}
		stored, err := s.store.CreateCustomStatus(tctx, tx, activityID, checkedName)
		if err != nil {
			return err
		}
		rec, err := s.activityRecord(principal, activityID, "player_status.create",
			"player_status", stored.ID.String(), "管理員經已認證會話建立自訂玩家狀態", requestID,
			auditChange("name", "", stored.Name),
			auditChange("available", "", fmt.Sprint(stored.Available)))
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		created = stored
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidStatusName), errors.Is(err, ErrActivityNotFound),
			errors.Is(err, ErrCustomStatusNameTaken), errors.Is(err, ErrArchived),
			errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return CustomStatus{}, err
		}
		s.log.Error("建立自訂玩家狀態失敗", "request_id", requestID, "err", err)
		return CustomStatus{}, fmt.Errorf("activity: 建立自訂玩家狀態失敗: %w", err)
	}
	s.log.Info("已建立自訂玩家狀態",
		"activity", activityID.String(), "status", created.ID.String(), "request_id", requestID)
	return created, nil
}

// UpdateCustomStatus 以白名單方式編輯自訂狀態的名稱與可用性。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 域校驗（在寫之前）；
//  2. 交易內判定活動作用域；
//  3. 交易內讀活動現值並核實它還沒進入終態（停止態仍可停用或恢復）；
//  4. 按標識讀回定義並核實它屬於這個活動——跨活動與從未存在同一句話；
//  5. 核實新名稱沒有撞上同活動內的另一個定義（自己的那一行除外）；
//  6. 新值與現值相同時視為冪等成功：不寫入、不追加審計（重送不會製造第二條痕）；
//  7. CAS 更新只碰名稱與可用性：changed=false 時整個編輯不發生並回衝突；
//  8. 同一交易內讀回並追加活動域審計。
//
// 停用只翻 available 那一欄：不搬動任何成員的目前狀態、不改寫標識、不級聯清空歷史。
func (s *Service) UpdateCustomStatus(ctx context.Context, principal identity.Principal,
	activityID, statusID idgen.ID, edit CustomStatusEdit, requestID string) (CustomStatus, error) {
	checkedName, err := validateStatusDisplayName(edit.New.Name, false)
	if err != nil {
		return CustomStatus{}, err
	}
	edit.New.Name = checkedName
	if expected, err := validateStatusDisplayName(edit.Expected.Name, false); err == nil {
		edit.Expected.Name = expected
	}

	var updated CustomStatus
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID,
			"player_status_update"); err != nil {
			return err
		}
		beforeActivity, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		if err := requireNotArchived(beforeActivity); err != nil {
			return err
		}
		before, err := s.store.CustomStatusByID(tctx, tx, statusID)
		if err != nil {
			return err
		}
		if before.ActivityID != activityID {
			// 查無與「不屬於這個活動」收斂成同一句話。
			return ErrCustomStatusNotFound
		}
		taken, err := s.store.CustomStatusNameTaken(tctx, tx, activityID, edit.New.Name, statusID)
		if err != nil {
			return err
		}
		if taken {
			return ErrCustomStatusNameTaken
		}
		if edit.New.Name == before.Name && edit.New.Available == before.Available {
			// 依據值已過期時，同一份「看起來沒變」的提交仍然是衝突；只有依據值也相符
			// 才是一次如實的冪等重送。
			if edit.Expected.Name != before.Name || edit.Expected.Available != before.Available {
				return ErrCustomStatusConflict
			}
			updated = before
			return nil
		}
		changed, err := s.store.UpdateCustomStatus(tctx, tx, statusID, activityID, edit)
		if err != nil {
			return err
		}
		if !changed {
			return ErrCustomStatusConflict
		}
		after, err := s.store.CustomStatusByID(tctx, tx, statusID)
		if err != nil {
			return err
		}
		rec, err := s.activityRecord(principal, activityID, "player_status.update",
			"player_status", after.ID.String(), customStatusEditReason(before, after), requestID,
			auditChange("name", before.Name, after.Name),
			auditChange("available", fmt.Sprint(before.Available), fmt.Sprint(after.Available)))
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
		case errors.Is(err, ErrInvalidStatusName), errors.Is(err, ErrActivityNotFound),
			errors.Is(err, ErrCustomStatusNotFound), errors.Is(err, ErrCustomStatusNameTaken),
			errors.Is(err, ErrCustomStatusConflict), errors.Is(err, ErrArchived),
			errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return CustomStatus{}, err
		}
		s.log.Error("編輯自訂玩家狀態失敗", "request_id", requestID, "err", err)
		return CustomStatus{}, fmt.Errorf("activity: 編輯自訂玩家狀態失敗: %w", err)
	}
	s.log.Info("已編輯自訂玩家狀態",
		"activity", activityID.String(), "status", updated.ID.String(), "request_id", requestID)
	return updated, nil
}

// customStatusEditReason 換出編輯自訂狀態那筆審計的原因句子。
//
// 停用那一句明確寫出「既有成員保留原狀態、不級聯清空」：查審計的人要能讀出這一欄
// 當時被允許做什麼、不被允許做什麼，而不是只看到 available false→true。
func customStatusEditReason(before, after CustomStatus) string {
	switch {
	case before.Available && !after.Available:
		return "管理員經已認證會話停用自訂玩家狀態：自此不再接收新的選用，既有成員保留原狀態與標識"
	case !before.Available && after.Available:
		return "管理員經已認證會話重新啟用自訂玩家狀態：恢復接收新的選用，不改寫任何人既有狀態"
	case before.Name != after.Name:
		return "管理員經已認證會話變更自訂玩家狀態的顯示名稱：內部標識與既有引用不變"
	default:
		return "管理員經已認證會話編輯自訂玩家狀態"
	}
}

// UpdateStatusLabel 以比較-and-set 方式編輯一個內建狀態在本活動的顯示名稱覆蓋。
//
// target 為空字串是「恢復四語言預設」，不是刪除一個狀態；expected 是提交所依據的
// 覆蓋現值（沒有覆蓋時為空字串）。停止態仍可準備顯示名稱，歸檔態一律拒寫。
// 被拒的編輯（無權、已歸檔、依據值過期、文字不合法）不追加審計。
func (s *Service) UpdateStatusLabel(ctx context.Context, principal identity.Principal,
	activityID idgen.ID, key BusinessStatus, displayName, expectedDisplayName,
	requestID string) (BuiltinStatusView, error) {
	if !key.valid() {
		return BuiltinStatusView{}, fmt.Errorf("%w：%q 不是內建狀態鍵",
			ErrInvalidBusinessStatus, string(key))
	}
	checkedName, err := validateStatusDisplayName(displayName, true)
	if err != nil {
		return BuiltinStatusView{}, err
	}
	checkedExpected, err := validateStatusDisplayName(expectedDisplayName, true)
	if err != nil {
		return BuiltinStatusView{}, err
	}

	var updated BuiltinStatusView
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID,
			"player_status_label_update"); err != nil {
			return err
		}
		before, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		if err := requireNotArchived(before); err != nil {
			return err
		}
		current, err := s.store.StatusLabelOverride(tctx, tx, activityID, key)
		if err != nil {
			return err
		}
		if current != checkedExpected {
			return ErrStatusLabelConflict
		}
		if checkedName == current {
			// 冪等重送：不寫入、不追加審計。
			updated = BuiltinStatusView{Key: key, DisplayName: current}
			return nil
		}
		changed, err := s.store.UpsertStatusLabel(tctx, tx, activityID, key,
			checkedName, checkedExpected)
		if err != nil {
			return err
		}
		if !changed {
			return ErrStatusLabelConflict
		}
		rec, err := s.activityRecord(principal, activityID, "player_status.label_update",
			"player_status_label", key.String(), "管理員經已認證會話變更玩家狀態顯示名稱", requestID,
			auditChange("status_key", key.String(), key.String()),
			auditChange("display_name", current, checkedName))
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		updated = BuiltinStatusView{Key: key, DisplayName: checkedName}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidBusinessStatus), errors.Is(err, ErrInvalidStatusName),
			errors.Is(err, ErrActivityNotFound), errors.Is(err, ErrStatusLabelConflict),
			errors.Is(err, ErrArchived), errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return BuiltinStatusView{}, err
		}
		s.log.Error("變更玩家狀態顯示名稱失敗", "request_id", requestID, "err", err)
		return BuiltinStatusView{}, fmt.Errorf("activity: 變更玩家狀態顯示名稱失敗: %w", err)
	}
	s.log.Info("已變更玩家狀態顯示名稱",
		"activity", activityID.String(), "status", key.String(), "request_id", requestID)
	return updated, nil
}

// UpdateMemberBusinessStatus 以比較-and-set 方式變更一個成員目前的業務狀態。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 交易內判定活動作用域；
//  2. 交易內現讀業務寫入門禁（停止 2033、歸檔 2029）；
//  3. 按標識讀回成員並核實它屬於這個活動——跨活動與從未存在同一句話；
//  4. 核實提交所依據的現值與庫中現值一致（不一致回衝突，不猜）；
//  5. 目標與現值相同時視為冪等成功：不寫入、不追加審計；
//  6. 目標為 custom 時，交易內現讀那個自訂定義並核實同活動、仍可用（停用 2041）；
//  7. CAS 更新只碰狀態兩欄：changed=false 時整個變更不發生；
//  8. 同一交易內讀回並追加活動域審計，changes 帶內部值與當時的顯示名稱。
//
// 被拒的變更（無權、門禁攔下、跨活動、依據值過期、狀態不合法、自訂狀態停用）不追加審計。
// 這條通路不碰暱稱、陣營、目錄覆蓋或任何帳戶欄位；狀態變更也不清空資產、不退出活動。
func (s *Service) UpdateMemberBusinessStatus(ctx context.Context, principal identity.Principal,
	activityID, memberID idgen.ID, status BusinessStatus, customStatusID idgen.ID,
	expectedStatus BusinessStatus, expectedCustomStatusID idgen.ID,
	requestID string) (Member, error) {
	if !status.valid() {
		return Member{}, fmt.Errorf("%w：%q 不是內建狀態鍵",
			ErrInvalidBusinessStatus, string(status))
	}
	if status.IsCustom() && customStatusID.IsNil() {
		return Member{}, fmt.Errorf("%w：custom 必須帶自訂狀態標識", ErrInvalidBusinessStatus)
	}
	if !status.IsCustom() && !customStatusID.IsNil() {
		return Member{}, fmt.Errorf("%w：非 custom 狀態不得帶自訂狀態標識",
			ErrInvalidBusinessStatus)
	}
	if !expectedStatus.valid() {
		return Member{}, fmt.Errorf("%w：依據值 %q 不是內建狀態鍵",
			ErrInvalidBusinessStatus, string(expectedStatus))
	}
	if !expectedStatus.IsCustom() && !expectedCustomStatusID.IsNil() {
		return Member{}, fmt.Errorf("%w：依據值不是 custom 卻帶自訂狀態標識",
			ErrInvalidBusinessStatus)
	}

	var updated Member
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID,
			"member_business_status_update"); err != nil {
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
			// 跨活動與從未存在收斂成同一句話。
			return ErrMemberNotFound
		}
		if before.BusinessStatus != expectedStatus ||
			before.CustomStatusID != expectedCustomStatusID {
			return ErrMemberProfileConflict
		}
		if before.BusinessStatus == status && before.CustomStatusID == customStatusID {
			// 冪等重送：不寫入、不追加審計。停用中的自訂狀態也不例外——
			// 這次提交沒有做出任何新的選用。
			if err := s.fillMemberStatus(tctx, tx, []*Member{&before}); err != nil {
				return err
			}
			updated = before
			return nil
		}
		if status.IsCustom() {
			target, err := s.store.CustomStatusByID(tctx, tx, customStatusID)
			if err != nil {
				return err
			}
			if target.ActivityID != activityID {
				return ErrCustomStatusNotFound
			}
			if !target.Available {
				return ErrCustomStatusUnavailable
			}
		}
		changed, err := s.store.UpdateMemberBusinessStatus(tctx, tx, memberID, activityID,
			status, customStatusID, expectedStatus, expectedCustomStatusID)
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
		rec, err := s.activityRecord(principal, activityID, "member.business_status_update",
			"member", after.ID.String(), "管理員經已認證會話變更成員業務狀態", requestID,
			auditChange("business_status", before.BusinessStatus.String(), after.BusinessStatus.String()),
			auditChange("custom_status_id", statusIDOrEmpty(before.CustomStatusID),
				statusIDOrEmpty(after.CustomStatusID)),
			auditChange("status_display_name", before.StatusDisplayName, after.StatusDisplayName))
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
		case errors.Is(err, ErrInvalidBusinessStatus), errors.Is(err, ErrActivityNotFound),
			errors.Is(err, ErrMemberNotFound), errors.Is(err, ErrMemberProfileConflict),
			errors.Is(err, ErrCustomStatusNotFound), errors.Is(err, ErrCustomStatusUnavailable),
			errors.Is(err, ErrArchived), errors.Is(err, ErrActivityClosedWrites),
			errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return Member{}, err
		}
		s.log.Error("變更成員業務狀態失敗", "request_id", requestID, "err", err)
		return Member{}, fmt.Errorf("activity: 變更成員業務狀態失敗: %w", err)
	}
	s.log.Info("已變更成員業務狀態",
		"activity", activityID.String(), "member", updated.ID.String(),
		"status", updated.BusinessStatus.String(), "request_id", requestID)
	return updated, nil
}

// fillMemberStatus 把一個活動的顯示名稱覆蓋與自訂定義蓋到成員投影上。
//
// 三個讀法（名冊、目錄與本人資料）都走這一份填寫，於是「列表裡那一行」與「點進去那一份」
// 不可能各說一套。自訂定義讀不到時如實留空並標成不可用，不編一個名稱，也不把整份讀法判死。
func (s *Service) fillMemberStatus(ctx context.Context, q database.Querier,
	members []*Member) error {
	if len(members) == 0 {
		return nil
	}
	activityID := members[0].ActivityID
	for _, member := range members[1:] {
		if member.ActivityID != activityID {
			return fmt.Errorf("activity: 狀態投影收到跨活動的成員行")
		}
	}
	labels, err := s.store.StatusLabelOverrides(ctx, q, activityID)
	if err != nil {
		return err
	}
	custom, err := s.store.CustomStatuses(ctx, q, activityID)
	if err != nil {
		return err
	}
	byID := make(map[idgen.ID]CustomStatus, len(custom))
	for _, status := range custom {
		byID[status.ID] = status
	}
	for _, member := range members {
		if member.BusinessStatus.IsCustom() {
			if status, ok := byID[member.CustomStatusID]; ok {
				member.CustomStatusName = status.Name
				member.StatusDisplayName = status.Name
				member.StatusAvailable = status.Available
			} else {
				member.CustomStatusName = ""
				member.StatusDisplayName = ""
				member.StatusAvailable = false
			}
			continue
		}
		member.CustomStatusName = ""
		member.StatusDisplayName = labels[member.BusinessStatus]
		member.StatusAvailable = true
	}
	return nil
}

// statusIDOrEmpty 把零值標識換成空字串（審計與回應共用同一句可讀值）。
func statusIDOrEmpty(id idgen.ID) string {
	if id.IsNil() {
		return ""
	}
	return id.String()
}
