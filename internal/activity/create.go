// create.go 是「建立一個活動」的用例：把名稱與描述落成一行草稿狀態的活動，
// 並在同一個交易裡把建立者指派為這個活動的第一位管理人。
//
// 為什麼建立者要被自動指派（用戶批准於本步）：沒有指派的活動就沒有人能管——
// 建完第一個活動卻要 Root 再補一刀才能編輯，那是把一次動作拆成兩段半完成態。
// 自動指派不等於「只有建立者能管」：指派表裡同一活動可以有更多人，
// Root 經 /root/activities/{id}/managers 增減（見 managers.go），
// 而建立者本人的伺服器級管理權被撤銷時，這一行指派不會自己消失（指派是事實，不是推論）。
//
// Root 建立時不寫指派：Root 不在 accounts 表裡，沒有可指派的帳戶標識，
// 而它的活動管理權本來就不來自指派（見 identity.AuthorizeActivityScope）。
// 因此 Root 建的活動在 Root 指派某位管理員之前，管理面只有 Root 自己進得去——
// 目錄與詳情把這個事實帶在 manager_count 那一格（0 就是 0，介面據實顯示）。
//
// 新建的活動一律是草稿：這是領域規則而不是引數。「先建起來再決定要不要開放」
// 是這一步唯一的出生形態，因此請求裡沒有一個能把自己寫成 active 的格子。
package activity

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// Create 以受信主體建立一個活動。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 授權（NeedServerAdmin：建立活動屬跨活動維運，與打理帳戶目錄同一檔位）；
//  2. 域校驗（名稱必填且合規、描述可空但有上界）——當場點名是哪一欄，不進庫撞 CHECK；
//  3. 交易內落庫（標識與時刻各只有一個產生點，見 store.go）；
//  4. 交易內指派建立者（帳戶主體時）：活動與其第一位管理人同生同滅，
//     不存在「建好了卻沒人能接著管」的中間態；
//  5. 同一交易內追加活動域審計：這一步之後回讀的實體是回應的依據，
//     不是呼叫端交來的意圖。
//
// 被拒的建立（非管理員、名稱或描述不合法）不追加審計：與被拒的開設、被拒的簽發同口徑。
func (s *Service) Create(ctx context.Context, principal identity.Principal,
	name, description, requestID string) (Activity, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		s.log.Warn("建立活動被拒：主體不具備伺服器級管理權",
			"subject", principal.String(), "entry", "create")
		return Activity{}, err
	}
	checkedName, err := validateName(name)
	if err != nil {
		return Activity{}, err
	}
	checkedDescription, err := validateDescription(description)
	if err != nil {
		return Activity{}, err
	}

	// 建立者留痕：帳戶主體用他自己的穩定標識；Root 沒有帳戶標識，這一格留零值。
	// 它不是權限依據——「他能管這個活動」由指派表與身份判定回答。
	var createdBy idgen.ID
	if principal.Kind() == identity.KindAccount {
		createdBy = principal.AccountID()
	}

	var created Activity
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		stored, err := s.store.Create(tctx, tx, CreateInput{
			Name:        checkedName,
			Description: checkedDescription,
			CreatedBy:   createdBy,
		})
		if err != nil {
			return err
		}
		if !createdBy.IsNil() {
			assigned, err := s.store.AssignManager(tctx, tx, stored.ID, createdBy)
			if err != nil {
				return err
			}
			if !assigned {
				// 一座剛建好的活動不可能已有指派；查得已有即資料形態缺陷，
				// 整體回滾而不是「當做已指派」——後者會讓回應與庫裡的現實分開。
				return fmt.Errorf("activity: 新建活動已存在指派行（%s）", stored.ID.String())
			}
			// 回讀一次，讓回應帶著倉儲算出的 manager_count 而不是推測值。
			stored, err = s.store.ByID(tctx, tx, stored.ID)
			if err != nil {
				return err
			}
		}
		rec, err := s.activityRecord(principal, stored.ID, "activity.create", "activity",
			stored.ID.String(), "管理員經已認證會話建立活動", requestID,
			auditChange("name", "", stored.Name),
			auditChange("status", "", stored.Status.String()))
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
		case errors.Is(err, ErrInvalidName), errors.Is(err, ErrInvalidDescription):
			return Activity{}, err
		}
		s.log.Error("建立活動失敗", "request_id", requestID, "err", err)
		return Activity{}, fmt.Errorf("activity: 建立活動失敗: %w", err)
	}
	s.log.Info("已建立活動",
		"activity", created.ID.String(), "status", created.Status.String(), "request_id", requestID)
	return created, nil
}
