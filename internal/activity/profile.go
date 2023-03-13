// profile.go 是「編輯一個活動的非安全資料」：名稱與描述的白名單編輯。
//
// 白名單只有兩欄。UPDATE 語句裡不出現 status、archived_at、created_by_account_id、
// created_at（見 Store.UpdateProfile），因此「儲存資料不會連隱藏欄位一起覆蓋」、
// 「編輯資料不能把活動挪進另一個活動、也不能改它的身份」成立在 SQL 形狀上而不是自律上：
//   - 活動 ID 由路徑引數給，且一律先核實在可見範圍內；本體裡沒有一格能填「目標活動」；
//   - 狀態與歸檔時刻只能經 status.go 那一條轉換通路改，兩條通路各認各的欄位；
//   - 建立者是歷史事實：它回答「這件事由誰發起」，不隨任何後續編輯漂移，
//     也不被拿去當成管理權的依據（管理權只認指派表）。
//
// 併發控制沿用帳戶資料編輯的比較-and-set：呼叫端交出它看見過的現值
// （名稱與描述兩欄一起作為依據），現值已變時整個編輯不落、審計不記，
// 並回可判別的衝突讓介面重讀。
//
// 歸檔終態一律拒寫（見 requireNotArchived）：判定的位置在作用域核實之後，
// 於是「這個活動不屬於你」永遠優先於「這個活動已結束」——前者不承認它存在。
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

// UpdateActivityProfile 以白名單方式編輯一個活動的名稱與描述。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 交易內讀指派清單並判定活動作用域（NeedServerAdmin 加上這一行指派）；
//  2. 交易內讀活動現值並核實它還沒進入終態；
//  3. 域校驗（在寫之前，不在撞 CHECK 之後）；
//  4. CAS 更新只碰 name 與 description：changed=false 時整個編輯不發生並回衝突；
//  5. 同一交易內讀回更新後的實體並追加活動域審計——前後只有這兩欄。
//
// 被拒的編輯（不在可見範圍、已歸檔、併發衝突、輸入不合規）不追加審計。
func (s *Service) UpdateActivityProfile(ctx context.Context, principal identity.Principal,
	activityID idgen.ID, name, description, expectedName, expectedDescription,
	requestID string) (Activity, error) {
	checkedName, err := validateName(name)
	if err != nil {
		return Activity{}, err
	}
	checkedDescription, err := validateDescription(description)
	if err != nil {
		return Activity{}, err
	}

	var updated Activity
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID, "profile_update"); err != nil {
			return err
		}
		before, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		if err := requireNotArchived(before); err != nil {
			return err
		}
		changed, err := s.store.UpdateProfile(tctx, tx, activityID,
			checkedName, checkedDescription, expectedName, expectedDescription)
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
		case errors.Is(err, ErrActivityNotFound), errors.Is(err, ErrArchived),
			errors.Is(err, ErrProfileConflict), errors.Is(err, ErrInvalidName),
			errors.Is(err, ErrInvalidDescription), errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return Activity{}, err
		}
		s.log.Error("編輯活動資料失敗", "request_id", requestID, "err", err)
		return Activity{}, fmt.Errorf("activity: 編輯活動資料失敗: %w", err)
	}
	s.log.Info("已編輯活動資料", "activity", updated.ID.String(), "request_id", requestID)
	return updated, nil
}

// profileUpdateRecord 產生一筆活動域的編輯審計。口徑與建立那筆同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆編輯回滾。
//
// changes 只放名稱與描述的前後值：狀態的變化屬 status.go 那條通路的事件，
// 在這裡多寫一欄會讓「誰改了狀態」有兩個答案來源。
func (s *Service) profileUpdateRecord(principal identity.Principal, before, after Activity,
	requestID string) (audit.Record, error) {
	return s.activityRecord(principal, after.ID, "activity.profile_update", "activity",
		after.ID.String(), "管理員經已認證會話編輯活動資料", requestID,
		auditChange("name", before.Name, after.Name),
		auditChange("description", before.Description, after.Description))
}
