// members.go 是「打理一個活動裡的成員身份」的三条用例：建立成員與唯一檔案、讀名冊、
// 編輯活動內暱稱。
//
// 這一層把本步批准的四件事凝成同一条通路：
//   - 准入沿用活動管理權的現讀口徑（NeedServerAdmin 加上這個活動的一行指派，
//     判定只有 requireActivityScope 這一處）——普通成員敲不開這裡的任何一条路；
//     本步交付的是活動內的「成員名冊管理面」，不是活動內的玩家權限，也不冒充尚未落地的東西；
//   - 建立與編輯都是活動內業務寫入：先過 EnsureBusinessWritesAllowed 那道門禁
//     （草稿與開放可寫；停止拿到「現在不行、重開就好」那一句，歸檔拿到「這件事已經結束」那一句）；
//   - 目標帳戶一律經 internal/account 現讀，採信的是「此刻的事實」：請求本體沒有欄位能宣告
//     「他是個能參加的人」，也沒有格子能填「哪種帳戶」「什麼狀態」「是哪一個活動」；
//   - 寫入與其審計同生同滅（交易內 append，審計寫不進去整個動作作廢）。
//
// 「一個帳戶在一場活動裡只有一份檔案」的落地形態有兩層：結構上是 UNIQUE
// (activity_id, account_id)（遷移 0014），服務層先查一次只為了給操作者一句可判讀的
// 「他已經是成員了」而不是原始約束錯誤。重複建立不謊報成功——那會在審計裡記下
// 一件沒發生過的事（口徑同 ErrManagerDuplicate）。
//
// 目標帳戶的資格邊界（用戶批准於本步）：普通帳戶與訪戶都可以成為成員（參加不是權限，
// 訪戶是現場最常見的臨時身分，持有 server_admin 授予者也不會因為成為成員而多得到任何能力）；
// 待審批、已被拒絕、已被軟刪除、已綁定退休這四種一律拒，而且與「根本沒有這個帳戶」收斂成
// 同一句話——能敲這條路徑的人是活動管理人，不是帳戶目錄的操作者，為他多開一句
// 「他被刪了」等於新增一枚可列舉的信號。停用（disabled）屬可恢復形態，允許加入：
// 管理人在活動開放前把名單備好是正常操作，而那個人隨時可以被恢復登入能力。
//
// 本步沒有的東西，也不假裝有：玩家在陣營間的分配（下一歩）、自助申請與審批、邀請碼加入、
// 把成員移出活動、活動內角色與權限。因此這一族路徑上不存在 DELETE，也沒有任何一格能填
// 「陣營」「角色」「操作者」。
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

// CreateMember 以受信主體在一個活動裡為一個既有帳戶建立成員身份與唯一檔案。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 域校驗（在寫之前，不在撞 CHECK 之後）；
//  2. 交易內判定活動作用域（NeedServerAdmin 加上這一行指派；被拒的人不會知道
//     這個活動存不存在）；
//  3. 交易內現讀業務寫入門禁（停止與歸檔各有各的句子，檢查與寫入看見同一個快照）；
//  4. 交易內現讀目標帳戶的型別與狀態（資格判定見 requireEligibleMemberTarget）；
//  5. 交易內核實這個帳戶在該活動裡還沒有檔案（UNIQUE 才是正確性來源）；
//  6. 交易內落庫（標識與時刻各只有一個產生點，陣營歸屬恆為無）；
//  7. 同一交易內追加活動域審計：回讀的實體是回應的依據，不是呼叫端交來的意圖。
//
// 被拒的建立（無權、門禁攔下、目標沒資格、重複、暱稱不合法）不追加審計：
// 與被拒的活動與陣營建立同口徑。
func (s *Service) CreateMember(ctx context.Context, principal identity.Principal,
	activityID, accountID idgen.ID, nickname, requestID string) (Member, error) {
	checkedNickname, err := validateNickname(nickname)
	if err != nil {
		return Member{}, err
	}

	var created Member
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID, "member_create"); err != nil {
			return err
		}
		if _, err := s.EnsureBusinessWritesAllowed(tctx, tx, activityID); err != nil {
			return err
		}
		target, err := s.requireEligibleMemberTarget(tctx, tx, accountID)
		if err != nil {
			return err
		}
		taken, err := s.store.MemberExistsForAccount(tctx, tx, activityID, accountID)
		if err != nil {
			return err
		}
		if taken {
			return ErrMemberAccountTaken
		}
		stored, err := s.store.CreateMember(tctx, tx, MemberCreateInput{
			ActivityID: activityID,
			AccountID:  accountID,
			Nickname:   checkedNickname,
		})
		if err != nil {
			return err
		}
		// 帳戶事實由剛才那次現讀蓋上：名冊行與建立回顯因此同一來源，而不是呼叫端的說法。
		stored.DisplayName = target.DisplayName
		stored.AccountStatus = target.Status
		if err := s.fillMemberStatus(tctx, tx, []*Member{&stored}); err != nil {
			return err
		}
		rec, err := s.activityRecord(principal, activityID, "member.create", "member",
			stored.ID.String(), "管理員經已認證會話在活動內建立成員身份", requestID,
			auditChange("account", "", accountID.String()),
			auditChange("nickname", "", stored.Nickname))
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
		case errors.Is(err, ErrInvalidNickname), errors.Is(err, ErrActivityNotFound),
			errors.Is(err, ErrMemberNotFound), errors.Is(err, ErrMemberAccountTaken),
			errors.Is(err, ErrArchived), errors.Is(err, ErrActivityClosedWrites),
			errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return Member{}, err
		}
		s.log.Error("建立活動成員失敗", "request_id", requestID, "err", err)
		return Member{}, fmt.Errorf("activity: 建立活動成員失敗: %w", err)
	}
	s.log.Info("已建立活動成員",
		"activity", activityID.String(), "member", created.ID.String(), "request_id", requestID)
	return created, nil
}

// requireEligibleMemberTarget 核實目標帳戶此刻有資格在活動裡取得成員身份。
//
// 判定只問 internal/account 這一個來源（本套件不抄一份帳戶狀態），而且採信現讀：
//   - 型別：普通與訪戶皆可（見檔頭），其餘型別今天不存在，也不預留出口；
//   - 狀態：active 與 disabled 皆可——一個是能登入的人，另一個是可恢復的暫停；
//     pending、rejected、deleted、retired 四種一律收斂成 ErrMemberNotFound，
//     與「根本沒有這個帳戶」同一句話（不新增可列舉信號，口徑同帳戶目錄的範圍規則）；
//   - 讀不到行（物理清理或幽靈標識）同樣是那句不可分辨的話。
//
// 它刻意不查 internal/grant：成員身份不承載任何伺服器級權限，「他是不是管理人」
// 對「他能不能參加這場活動」沒有任何影響——兩件事各問各的來源，才不會出現
// 「拿管理權檢查冒充參加資格」這種看起來像授權的漏項。
func (s *Service) requireEligibleMemberTarget(ctx context.Context, q database.Querier,
	accountID idgen.ID) (account.Account, error) {
	if accountID.IsNil() {
		return account.Account{}, ErrMemberNotFound
	}
	a, err := s.accounts.ByID(ctx, q, accountID)
	if err != nil {
		if errors.Is(err, account.ErrNotFound) {
			return account.Account{}, ErrMemberNotFound
		}
		return account.Account{}, err
	}
	switch a.Type {
	case account.TypeStandard, account.TypeGuest:
	default:
		// 型別集合外的行屬資料缺陷形態：既不是「查無此人」也不是「他能參加」，
		// 不降級放行，對外仍給不可分辨的那句話，但對內留一條線索——
		// 靜默當成查無會把一次寫壞的行讀成一個從不存在的人。
		s.log.Warn("成員目標帳戶的型別不在已批准集合內，按不可分辨結論處理",
			"account", accountID.String(), "type", a.Type.String())
		return account.Account{}, ErrMemberNotFound
	}
	switch a.Status {
	case account.StatusActive, account.StatusDisabled:
		return a, nil
	default:
		return account.Account{}, ErrMemberNotFound
	}
}

// Members 以當前受信主體讀一個活動的成員名冊（仍列、可讀：停止與歸檔的活動照樣能讀）。
//
// 它與陣營列表、名冊讀法同一道准入閘（Root 或該活動的管理人），也沿用同一句前置核實：
// 先確認活動本身在可見範圍內再讀名冊，否則「一個從未存在的活動」會在 Root 眼前
// 回成一份空名冊，而空名冊的語意是「這活動還沒有人加入」。
//
// 每一行的顯示名與帳戶狀態經 internal/account 逐行現讀後蓋上（口徑同管理人名冊）：
// 軟參照指向的帳戶行已被物理清理時，那一格如實留空而不是偽造一個名字，也不把整份
// 名冊判死——「這一行指向一個查不到的帳戶」本來就是操作者該看到的事實。
func (s *Service) Members(ctx context.Context, principal identity.Principal,
	activityID idgen.ID) ([]Member, error) {
	q := s.db.SQL()
	if err := s.requireActivityScope(ctx, q, principal, activityID, "member_roster"); err != nil {
		return nil, err
	}
	if _, err := s.readActivity(ctx, q, activityID); err != nil {
		return nil, err
	}
	rows, err := s.store.Members(ctx, q, activityID)
	if err != nil {
		s.log.Error("讀取成員名冊失敗", "activity", activityID.String(), "err", err)
		return nil, fmt.Errorf("activity: 讀取成員名冊失敗: %w", err)
	}
	out := make([]Member, 0, len(rows))
	for _, row := range rows {
		member := row
		// 「他此刻是不是管理員身分」與顯示名、帳戶狀態同屬投影：由 internal/grant 現讀盖上，
		// 不是 activity_members 的一欄。名冊把這一格帶出來，管理人才能看懂
		// all_players_except_admin 那一態此刻收起來的是誰；玩家側的目錄投影從不帶它。
		admin, err := s.adminIdentityOf(ctx, q, row.AccountID)
		if err != nil {
			return nil, err
		}
		member.AdminIdentity = admin
		a, err := s.accounts.ByID(ctx, q, row.AccountID)
		if err != nil {
			if !errors.Is(err, account.ErrNotFound) {
				return nil, err
			}
			// 軟參照的代價在這裡露面：指向的帳戶行已被物理清理，讀不回任何事實。
			// 如實標成空顯示名與空狀態，介面據此念「查無此人」而不是崩在解析上。
			member.DisplayName = ""
			member.AccountStatus = ""
			out = append(out, member)
			continue
		}
		member.DisplayName = a.DisplayName
		member.AccountStatus = a.Status
		out = append(out, member)
	}
	pointers := make([]*Member, len(out))
	for i := range out {
		pointers[i] = &out[i]
	}
	if err := s.fillMemberStatus(ctx, q, pointers); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateMemberNickname 以白名單方式編輯一個成員的活動內暱稱（唯一可編輯的資料欄）。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 域校驗（在寫之前）；
//  2. 交易內判定活動作用域；
//  3. 交易內現讀業務寫入門禁；
//  4. 按標識讀回成員並核實它確實屬於這個活動——不屬於時與「從未存在」同一句話
//     （跨活動改别人的成員不能多給出一枚可探測的信號，口徑同陣營與活動的不可分辨）；
//  5. CAS 更新只碰暱稱一欄：changed=false 時整個編輯不發生並回衝突；
//  6. 同一交易內讀回更新後的實體並追加活動域審計——前後只有暱稱一欄。
//
// 被拒的編輯（無權、門禁攔下、跨活動、併發衝突、輸入不合規）不追加審計。
//
// 這一条通路不碰 faction_id：陣營歸屬的寫入屬下一步的分配命令，而「改名」與「換組」
// 各有一條通路、各有各的審計句子，才不會出現「儲存名字順手把人搬進另一個陣營」這種
// 一鍵兩件事的寫法（口徑同活動的資料編輯與狀態轉換分成兩條路徑）。
func (s *Service) UpdateMemberNickname(ctx context.Context, principal identity.Principal,
	activityID, memberID idgen.ID, nickname, expectedNickname, requestID string) (Member, error) {
	checkedNickname, err := validateNickname(nickname)
	if err != nil {
		return Member{}, err
	}

	var updated Member
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.requireActivityScope(tctx, tx, principal, activityID, "member_update"); err != nil {
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
			// 查無與「不屬於這個活動」收斂成同一句話：呼叫端多知道哪一個都不該是信號。
			return ErrMemberNotFound
		}
		changed, err := s.store.UpdateMemberNickname(tctx, tx, memberID, activityID,
			checkedNickname, expectedNickname)
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
		rec, err := s.activityRecord(principal, activityID, "member.update", "member",
			after.ID.String(), "管理員經已認證會話編輯活動成員暱稱", requestID,
			auditChange("nickname", before.Nickname, after.Nickname))
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
		case errors.Is(err, ErrInvalidNickname), errors.Is(err, ErrActivityNotFound),
			errors.Is(err, ErrMemberNotFound), errors.Is(err, ErrMemberProfileConflict),
			errors.Is(err, ErrArchived), errors.Is(err, ErrActivityClosedWrites),
			errors.Is(err, identity.ErrPermissionDenied),
			errors.Is(err, identity.ErrNotAuthenticated),
			errors.Is(err, identity.ErrMissingActivityScope):
			return Member{}, err
		}
		s.log.Error("編輯成員暱稱失敗", "request_id", requestID, "err", err)
		return Member{}, fmt.Errorf("activity: 編輯成員暱稱失敗: %w", err)
	}
	s.log.Info("已編輯成員暱稱",
		"activity", activityID.String(), "member", updated.ID.String(), "request_id", requestID)
	return updated, nil
}
