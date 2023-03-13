// status.go 是活動生命週期的兩件事：狀態轉換通路，與留給後續業務模組複用的「寫入門禁」。
//
// 為什麼轉換要單獨一條通路（而不是讓資料編輯順帶把 status 一起存）：
// 狀態決定「這件事還能不能繼續發生」，把它放進一個能自由填欄位的編輯請求裡，
// 等於讓任何一次改名都能順手把歸檔的活動改回開放——而歸檔是沒有出口的終態。
// 因此本通路只吃一個目標狀態，不交依據值：
//   - 正當性錨在「庫裡此刻的狀態等於你以為的那個狀態」這條可觀測事實上（帶 WHERE 的單向 UPDATE）；
//   - 同態重複（把已停止的再停止一次）不謊報成功，收斂成狀態衝突——
//     把「什麼都沒發生」說成「又停止了一次」，審計與真相就對不上（與帳戶停用同一口徑）。
//
// 三道拒寫各自有獨立的句子，因為操作者的處置完全不同：
//   - ErrArchived：這件事已經結束，重讀之後也沒有第二顆按鈕（終態）；
//   - ErrStatusConflict：你看見的現值已過期，重讀之後那顆按鈕可能還能按；
//   - ErrInvalidTransition：就算現值如你所見，這條路也不存在（如把草稿直接「停止」）。
//
// 「業務寫入門禁」是另一件事，它屬狀態的語意而不是管理面：停止與歸檔的活動不接受
// 活動內的業務寫入（成員、陣營、資產……）。本步沒有任何一條端點動過業務資料，
// 因此這裡只交付判定本身，並刻意不為停止態發布機器錯誤碼（見 ErrActivityClosedWrites）。
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

// Transition 把一個活動推到呼叫端指定的目標狀態。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 交易內判定活動作用域（NeedServerAdmin 加上這一行指派）；
//  2. 交易內讀現值：終態先答（它不給任何合法出口），同態與無路徑各自答自己那句；
//  3. 帶 WHERE 的單向 UPDATE：贏家與落敗者由 RowsAffected 分辨，讀與寫之間被人改掉時
//     整個轉換不發生（狀態沒改、歸檔時刻沒寫、審計沒記）；
//  4. 同一交易內讀回並追加活動域審計：回應帶著資料庫現值，不是呼叫端的意圖迴音。
//
// 目標是 draft 時一律回報非法路徑：草稿只能由「建立活動」那一跳產生，
// 把已開放或已歸檔的活動「退回草稿」不是本步批准的形態（它等於偽造「這件事還沒開始」）。
func (s *Service) Transition(ctx context.Context, principal identity.Principal,
	activityID idgen.ID, target Status, requestID string) (Activity, error) {
	if !target.valid() {
		return Activity{}, fmt.Errorf("%w：目標狀態 %q 不在封閉集合內", ErrInvalidStatus, string(target))
	}

	var updated Activity
	err := s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID, "status"); err != nil {
			return err
		}
		before, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		if err := requireNotArchived(before); err != nil {
			return err
		}
		if before.Status == target {
			return ErrStatusConflict
		}
		if !before.Status.canReach(target) {
			return ErrInvalidTransition
		}
		changed, err := s.store.UpdateStatus(tctx, tx, activityID, before.Status, target)
		if err != nil {
			return err
		}
		if !changed {
			// 現值在第 2 跳之後被別人改掉：這次轉換整個沒有發生，一句話就夠——
			// 不回顯現在的狀態是什麼，那是重讀詳情本來就該拿到的資料。
			return ErrStatusConflict
		}
		after, err := s.readActivity(tctx, tx, activityID)
		if err != nil {
			return err
		}
		rec, err := s.statusChangeRecord(principal, before, after, requestID)
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
			errors.Is(err, ErrStatusConflict), errors.Is(err, ErrInvalidTransition),
			errors.Is(err, ErrInvalidStatus), errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return Activity{}, err
		}
		s.log.Error("轉換活動狀態失敗", "request_id", requestID, "err", err)
		return Activity{}, fmt.Errorf("activity: 轉換活動狀態失敗: %w", err)
	}
	s.log.Info("已轉換活動狀態",
		"activity", updated.ID.String(), "status", updated.Status.String(), "request_id", requestID)
	return updated, nil
}

// statusChangeRecord 產生一筆活動域的狀態轉換審計：前後只有狀態一欄。
//
// 歸檔那一跳也記在同一條句子裡（前後值本身就把「進入終態」這件事說清楚了），
// 不再多記歸檔時刻：時刻屬欄位值，而審計記的是「哪個欄位從什麼變成什麼」。
func (s *Service) statusChangeRecord(principal identity.Principal, before, after Activity,
	requestID string) (audit.Record, error) {
	return s.activityRecord(principal, after.ID, "activity.status_change", "activity",
		after.ID.String(), "管理員經已認證會話轉換活動狀態", requestID,
		auditChange("status", before.Status.String(), after.Status.String()))
}

// EnsureBusinessWritesAllowed 是留給活動內業務模組的寫入門禁：現讀給定活動此刻
// 是否接受業務資料的寫入，並把「這個活動不在可見範圍」與「已歸檔」「已停止」分成三句話回。
//
// 它刻意只做狀態判定、不做授權判定：呼叫端（陣營、成員、資產那一步）本來就要先過
// requireActivityScope 那道閘，這裡再判一次只會造出第二套權限語意。
// 也刻意不自己開交易：門禁與那筆業務寫入必須看見同一個快照，
// 否則「檢查時還開著、寫入時已被人停止」這段視窗就成了真的漏洞。
//
// 停止與歸檔都拒，但兩句不共用：停止可逆（重開後業務寫入恢復），歸檔不可逆。
// 把兩者收斂成同一個錯誤，呼叫端的介面就只能對使用者念一句「現在不行」，
// 而「等一等再試」與「這件事已經結束了」是完全不同的處置。
func (s *Service) EnsureBusinessWritesAllowed(ctx context.Context, q database.Querier,
	activityID idgen.ID) (Activity, error) {
	a, err := s.readActivity(ctx, q, activityID)
	if err != nil {
		return Activity{}, err
	}
	if err := requireNotArchived(a); err != nil {
		return Activity{}, err
	}
	if !a.Status.AllowsBusinessWrites() {
		return Activity{}, ErrActivityClosedWrites
	}
	return a, nil
}
