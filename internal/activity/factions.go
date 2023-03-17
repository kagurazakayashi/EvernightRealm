// factions.go 是「打理一個活動裡的陣營」的三条用例：建立、列表、編輯，
// 外加留給日後分配通路複用的「這個陣營此刻還收不收新成員」判定。
//
// 這一層把本步批准的四件事湮成同一条通路：
//   - 准入沿用活動管理權的現讀口徑（NeedServerAdmin 加上這個活動的一行指派，
//     判定只有 requireActivityScope 這一處）——普通成員敲不開這裡的任何一条路；
//     本步交付的是活動內的「管理面」，不是活動內的玩家身份，也不冒充那個尚未落地的東西；
//   - 建與改都是活動內業務寫入：先過 EnsureBusinessWritesAllowed 那道門禁
//     （草稿與開放可寫；停止拿到「現在不行、重開就好」那一句，歸檔拿到「這件事已經結束」那一句）；
//   - 寫入與其審計同生同滅（交易內 append，審計寫不進去整個動作作廢）；
//   - 身份、歸屬與時刻都不是請求能說服的欄位：FactionDraft／FactionEdit 裡沒有一格
//     能填 activity_id、建立者或時間，「誰在做」由憑據決定，「動哪個活動」「動哪個陣營」
//     由路徑決定，「現在是什麼時刻」由注入時鐘決定。
//
// 新建的陣營一律是可用：這是領域規則而不是引數（口徑同「新建的活動一律是草稿」）。
// 「建出來先停用」的意圖走建好之後的一跳編輯即可表達，請求裡因此不設可用性那一格。
// 未帶排序值時排到最後一格：由服務層在交易內現算 max+1，呼叫端代填的數字只能是建議，
// 不能是事實。
//
// 停用與恢復都走那條六欄白名單編輯，不另發通路（用戶批准於陣營管理那一步）：可用性是
// 旗標而不是狀態機，因此不套用「同態重複即拒」那條狀態規則——把一份「仍然停用」的整份
// 編輯再存一次，是一次如實的重存（值沒翻轉、updated_at 前進、審計記下 available 前後同值）。
// 界面因此必須把「當前狀態」與「本次操作結果」分開講：沒有翻轉時不得念成「已停用這個陣營」。
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

// FactionDraft 是建立陣營的域層輸入（全部欄位都已透過域校驗）。
type FactionDraft struct {
	// Name 是剔首尾空白後的陣營名稱。
	Name string
	// Description 是陣營描述（可為空字串）。
	Description string
	// Icon 是命中封閉集合的圖標鍵（空字串＝未選）。
	Icon string
	// Color 是正規化後的 #RRGGBB（空字串＝未選色）。
	Color string
	// SortOrder 為 nil 時由服務層現算排尾值；非 nil 時已透過域校驗。
	SortOrder *int64
}

// FactionEdit 是編輯陣營的域層輸入：六欄白名單新值，加六欄「提交所依據的現值」。
//
// 依據值不做域校驗——它們描述的是呼叫端看見的舊世界，舊世界裡可能有當時合法的寫法；
// 正確性錨在「庫裡此刻的六欄等於你依據的那六欄」這條可觀測事實上（見 factionstore.go）。
type FactionEdit struct {
	// Name／Description／Icon／Color／SortOrder／Available 是新的六欄白名單值。
	Name        string
	Description string
	Icon        string
	Color       string
	SortOrder   int64
	Available   bool
	// Expected* 是提交所依據的現值（逐欄對應上面六欄）。
	ExpectedName        string
	ExpectedDescription string
	ExpectedIcon        string
	ExpectedColor       string
	ExpectedSortOrder   int64
	ExpectedAvailable   bool
}

// CreateFaction 以受信主體在一個活動裡建立陣營。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 域校驗（在寫之前，不在撞 CHECK 之後）；
//  2. 交易內判定活動作用域（NeedServerAdmin 加上這一行指派；被拒的人不會知道
//     這個活動存不存在）；
//  3. 交易內現讀業務寫入門禁（停止與歸檔各有各的句子，檢查與寫入看見同一個快照）；
//  4. 交易內核實同活動內名稱未占用，並現算排尾值（呼叫端未指定排序時）；
//  5. 交易內落庫（標識與時刻各只有一個產生點，可用性由領域規則決定）；
//  6. 同一交易內追加活動域審計：回讀的實體是回應的依據，不是呼叫端交來的意圖。
//
// 被拒的建立（無權、門禁攔下、重名、欄位不合法）不追加審計：與被拒的活動建立同口徑。
func (s *Service) CreateFaction(ctx context.Context, principal identity.Principal,
	activityID idgen.ID, draft FactionDraft, requestID string) (Faction, error) {
	checkedName, err := validateName(draft.Name)
	if err != nil {
		return Faction{}, err
	}
	checkedDescription, err := validateDescription(draft.Description)
	if err != nil {
		return Faction{}, err
	}
	checkedIcon, err := validateFactionIcon(draft.Icon)
	if err != nil {
		return Faction{}, err
	}
	checkedColor, err := validateFactionColor(draft.Color)
	if err != nil {
		return Faction{}, err
	}
	var explicitSort int64
	if draft.SortOrder != nil {
		explicitSort, err = validateFactionSortOrder(*draft.SortOrder)
		if err != nil {
			return Faction{}, err
		}
	}

	var created Faction
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID, "faction_create"); err != nil {
			return err
		}
		gate, err := s.EnsureBusinessWritesAllowed(tctx, tx, activityID)
		if err != nil {
			return err
		}
		taken, err := s.store.FactionNameTaken(tctx, tx, activityID, checkedName, idgen.ID{})
		if err != nil {
			return err
		}
		if taken {
			return ErrFactionNameTaken
		}
		sortOrder := explicitSort
		if draft.SortOrder == nil {
			// 排到最後一格：交易內現讀最大值加一；已貼著上界時就落在上界同值排尾
			// （同值是合法形態，破平規讓新建的那個自然落在末位）。
			maxOrder, err := s.store.MaxFactionSortOrder(tctx, tx, activityID)
			if err != nil {
				return err
			}
			sortOrder = maxOrder + 1
			if sortOrder > maxFactionSortOrder {
				sortOrder = maxFactionSortOrder
			}
		}
		stored, err := s.store.CreateFaction(tctx, tx, FactionCreateInput{
			ActivityID:  activityID,
			Name:        checkedName,
			Description: checkedDescription,
			Icon:        checkedIcon,
			Color:       checkedColor,
			SortOrder:   sortOrder,
		})
		if err != nil {
			return err
		}
		// 門禁剛在同一个快照裡放行，因此這一格的派生值是可信的：新建即可用、活動又可寫。
		stored = withMemberAcceptance(stored, gate.Status)
		rec, err := s.activityRecord(principal, activityID, "faction.create", "faction",
			stored.ID.String(), "管理員經已認證會話建立活動陣營", requestID,
			auditChange("name", "", stored.Name),
			auditChange("sort_order", "", fmt.Sprint(stored.SortOrder)))
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
		case errors.Is(err, ErrInvalidName), errors.Is(err, ErrInvalidDescription),
			errors.Is(err, ErrInvalidIcon), errors.Is(err, ErrInvalidColor),
			errors.Is(err, ErrInvalidSortOrder), errors.Is(err, ErrActivityNotFound),
			errors.Is(err, ErrFactionNameTaken), errors.Is(err, ErrArchived),
			errors.Is(err, ErrActivityClosedWrites),
			errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return Faction{}, err
		}
		s.log.Error("建立陣營失敗", "request_id", requestID, "err", err)
		return Faction{}, fmt.Errorf("activity: 建立陣營失敗: %w", err)
	}
	s.log.Info("已建立陣營",
		"activity", activityID.String(), "faction", created.ID.String(), "request_id", requestID)
	return created, nil
}

// Factions 以當前受信主體讀一個活動的陣營列表（仍列、可讀：停止與歸檔的活動照樣能讀）。
//
// 它與名冊讀法同一道准入閘（Root 或該活動的管理人），也沿用同一句前置核實：
// 先確認活動本身在可見範圍內再讀列表，否則「一個從未存在的活動」會在 Root 眼前
// 回成一份空列表，而空列表的語意是「這活動還沒設陣營」。
func (s *Service) Factions(ctx context.Context, principal identity.Principal,
	activityID idgen.ID) ([]Faction, error) {
	q := s.db.SQL()
	if err := s.requireActivityScope(ctx, q, principal, activityID, "faction_list"); err != nil {
		return nil, err
	}
	gate, err := s.readActivity(ctx, q, activityID)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.Factions(ctx, q, activityID)
	if err != nil {
		s.log.Error("讀取陣營列表失敗", "activity", activityID.String(), "err", err)
		return nil, fmt.Errorf("activity: 讀取陣營列表失敗: %w", err)
	}
	// 停止與歸檔的活動裡，連 available 仍為真的陣營也收不到新成員：這一句由服務端
	// 說出來（同一個快照讀到的活動狀態），而不是讓介面去猜兩個欄位的組合。
	for i, row := range rows {
		rows[i] = withMemberAcceptance(row, gate.Status)
	}
	return rows, nil
}

// UpdateFaction 以白名單方式編輯一個陣營的六欄資料（含可用性開關）。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 域校驗（在寫之前）；
//  2. 交易內判定活動作用域；
//  3. 交易內現讀業務寫入門禁；
//  4. 按標識讀回陣營並核實它確實屬於這個活動——不屬於時與「從未存在」同一句話
//     （跨活動改陣營不給任何可探測的信號，口徑同活動的不可分辨）；
//  5. 核實新名稱沒有撞上同活動內的另一個陣營（自己的那一行除外）；
//  6. CAS 更新只碰六欄白名單：changed=false 時整個編輯不發生並回衝突；
//  7. 同一交易內讀回更新後的實體並追加活動域審計——前後只有這六欄。
//
// 被拒的編輯（無權、門禁攔下、跨活動、撞名、併發衝突、輸入不合規）不追加審計。
//
// 停用與恢復就是這一條通路上「available 那一欄翻轉」的編輯：除了那一欄與 updated_at，
// 一個字都不該動——尤其不會動任何人的歸屬（今日還沒有歸屬可動，日後也不准借這一跳清人）。
func (s *Service) UpdateFaction(ctx context.Context, principal identity.Principal,
	activityID, factionID idgen.ID, edit FactionEdit, requestID string) (Faction, error) {
	checkedName, err := validateName(edit.Name)
	if err != nil {
		return Faction{}, err
	}
	checkedDescription, err := validateDescription(edit.Description)
	if err != nil {
		return Faction{}, err
	}
	checkedIcon, err := validateFactionIcon(edit.Icon)
	if err != nil {
		return Faction{}, err
	}
	checkedColor, err := validateFactionColor(edit.Color)
	if err != nil {
		return Faction{}, err
	}
	checkedSortOrder, err := validateFactionSortOrder(edit.SortOrder)
	if err != nil {
		return Faction{}, err
	}

	var updated Faction
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID, "faction_update"); err != nil {
			return err
		}
		gate, err := s.EnsureBusinessWritesAllowed(tctx, tx, activityID)
		if err != nil {
			return err
		}
		before, err := s.store.FactionByID(tctx, tx, factionID)
		if err != nil {
			if errors.Is(err, ErrFactionNotFound) {
				// 查無與「不屬於這個活動」收斂成同一句話：呼叫端多知道哪一個都不該是信號。
				return ErrFactionNotFound
			}
			return err
		}
		if before.ActivityID != activityID {
			return ErrFactionNotFound
		}
		taken, err := s.store.FactionNameTaken(tctx, tx, activityID, checkedName, factionID)
		if err != nil {
			return err
		}
		if taken {
			return ErrFactionNameTaken
		}
		changed, err := s.store.UpdateFaction(tctx, tx, factionID, activityID,
			checkedName, checkedDescription, checkedIcon, checkedColor, checkedSortOrder, edit.Available,
			edit.ExpectedName, edit.ExpectedDescription, edit.ExpectedIcon, edit.ExpectedColor,
			edit.ExpectedSortOrder, edit.ExpectedAvailable)
		if err != nil {
			return err
		}
		if !changed {
			return ErrFactionProfileConflict
		}
		after, err := s.store.FactionByID(tctx, tx, factionID)
		if err != nil {
			return err
		}
		after = withMemberAcceptance(after, gate.Status)
		rec, err := s.factionUpdateRecord(principal, before, after, requestID)
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
		case errors.Is(err, ErrInvalidName), errors.Is(err, ErrInvalidDescription),
			errors.Is(err, ErrInvalidIcon), errors.Is(err, ErrInvalidColor),
			errors.Is(err, ErrInvalidSortOrder), errors.Is(err, ErrActivityNotFound),
			errors.Is(err, ErrFactionNotFound), errors.Is(err, ErrFactionNameTaken),
			errors.Is(err, ErrFactionProfileConflict), errors.Is(err, ErrArchived),
			errors.Is(err, ErrActivityClosedWrites),
			errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return Faction{}, err
		}
		s.log.Error("編輯陣營失敗", "request_id", requestID, "err", err)
		return Faction{}, fmt.Errorf("activity: 編輯陣營失敗: %w", err)
	}
	s.log.Info("已編輯陣營",
		"activity", activityID.String(), "faction", updated.ID.String(), "request_id", requestID)
	return updated, nil
}

// factionUpdateRecord 產生一筆活動域的陣營編輯審計：前後只有白名單六欄。
//
// 口徑與活動資料編輯同源——actor 只能經 principal.AuditActor() 換得，換不出就讓
// 整筆編輯回滾；狀態的變化不進這條句子（陣營沒有狀態機，available 是白名單的一欄，
// 它的前後值在這裡就是它的全部事實）。
//
// 原因句子按可用性是否翻轉分岔：查審計的人要能一眼分辨「這一次動的是收不收新成員」
// 還是「這一次只是改資料」。兩句都只描述服務端已經發生的事，不寫操作者自報的意圖
// （請求本體裡沒有一格能填原因，也不准填——口徑同帳戶停用與活動狀態轉換）。
func (s *Service) factionUpdateRecord(principal identity.Principal, before, after Faction,
	requestID string) (audit.Record, error) {
	return s.activityRecord(principal, after.ActivityID, "faction.update", "faction",
		after.ID.String(), factionEditReason(before, after), requestID,
		auditChange("name", before.Name, after.Name),
		auditChange("description", before.Description, after.Description),
		auditChange("icon", before.Icon, after.Icon),
		auditChange("color", before.Color, after.Color),
		auditChange("sort_order", fmt.Sprint(before.SortOrder), fmt.Sprint(after.SortOrder)),
		auditChange("available", fmt.Sprint(before.Available), fmt.Sprint(after.Available)))
}

// factionEditReason 換出那一筆審計的原因句子（含可用性翻轉與否兩種）。
func factionEditReason(before, after Faction) string {
	switch {
	case before.Available && !after.Available:
		return "管理員經已認證會話停用活動陣營：自此不再接收新分配，既有歸屬與歷史保留"
	case !before.Available && after.Available:
		return "管理員經已認證會話重新啟用活動陣營：恢復接收新分配，不改寫任何人既有歸屬"
	default:
		return "管理員經已認證會話編輯活動陣營"
	}
}

// EnsureFactionAcceptsNewMembers 是留給「把玩家分進陣營」那一步的可復用判定：
// 在呼叫端的寫入交易內現讀，回報這個陣營此刻能不能接收新成員。
//
// 三件事依次判定，前一件不過就停在那一句話上（順序與陣營的建／改兩條通路一致）：
//  1. 所屬活動的業務寫入門禁（停止與歸檔各有各的句子）；
//  2. 按標識讀回陣營，並核實它確實屬於這個活動——不属于時與「從未存在」同一句話，
//     分配通路不能把「那個陣營在另一場活動裡」變成一枚可探測的信號；
//  3. 可用性旗標：停用即 ErrFactionNotAcceptingMembers。
//
// 簽名刻意收 *database.Tx 而不是任何 Querier，也刻意在自己的寫入交易內檢查：
// 「先在一个交易查可用，再在另一个無保護的交易寫入」是這個判定存在的理由要防的那件事——
// 中間那一跳裡停用可以照常發生，於是分配把玩家分進了一個已停用的陣營。
// 收 *Tx 之後，拿 db.SQL() 或唯讀交易來呼叫連編譯／啟動檢查都過不了（唯讀交易在
// 這裡直接回報內部錯誤，不降級成「可以分配」）。SQLite 只有一個寫入者，於是
// 「判定時的現值」與「同一交易內隨後那筆分配寫入」看見的是同一個快照：
// 要插入的分配與要停用這一行的那一次編輯必然串行，不會各寫各的。
//
// 它不做授權判定（呼叫端本來就要先過 requireActivityScope 那道閘），也不發任何
// 對外錯誤碼：今日還沒有分配端點，那一步落地時才決定這一句對映成哪一枚碼。
func (s *Service) EnsureFactionAcceptsNewMembers(ctx context.Context, tx *database.Tx,
	activityID, factionID idgen.ID) (Faction, error) {
	if tx == nil || tx.ReadOnly() {
		return Faction{}, errFactionGuardNeedsWriteTx
	}
	gate, err := s.EnsureBusinessWritesAllowed(ctx, tx, activityID)
	if err != nil {
		return Faction{}, err
	}
	faction, err := s.store.FactionByID(ctx, tx, factionID)
	if err != nil {
		return Faction{}, err
	}
	if faction.ActivityID != activityID {
		return Faction{}, ErrFactionNotFound
	}
	if !faction.Available {
		return Faction{}, ErrFactionNotAcceptingMembers
	}
	return withMemberAcceptance(faction, gate.Status), nil
}

// errFactionGuardNeedsWriteTx 是呼叫端用法錯誤，不是業務結論：把判定挪到交易外
// （或挪到唯讀交易裡）得到的答案隨時可能被別人改掉，因此不給它一條「湊合著用」的出口。
var errFactionGuardNeedsWriteTx = errors.New("activity: 陣營可分配判定必須在呼叫端自己的寫入交易內執行")
