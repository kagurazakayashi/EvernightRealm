// upgrade.go 是「管理員把一個訪戶帳戶原地升級成普通帳戶」的應用服務層。
//
// 這是在地升級，不是綁定：動的是 accounts 表裡既有那一行——穩定標識、建立時刻、
// 顯示名與既有審計與其他實際存在的參照全部原樣保留，不新建一筆再把訪戶刪掉。
// 「綁定到另一個既有正式帳戶」是另一句話（那要處理兩個身份的合併與指向搬遷），
// 不在這條通路之內，界面必須把兩者分開呈現。
//
// 一次成功升級落地的是四件事的合力，缺一件都是半套：
//   - 身分轉正：account_type 由 guest 變 standard，正式登入名與它的正規化鍵同一條
//     UPDATE 落下（見 account.Store.UpgradeGuestToStandard）；
//   - 憑據落地：口令由操作者親自交的一次性明文經 internal/credential 派生成雜湊，
//     與 must_change_password=1 寫入同一條 UPDATE——升級出來的是「普通帳戶首次進入
//     必須改密」這個既有形態，不是管理員的代理口令；
//   - 舊會話失效：同交易 RevokeAccount 落庫 revoked_at。這是用戶批准的決定（R2-017）：
//     會話解析每請求現讀帳戶行，若不撤銷，撿到舊臨時 Cookie 的人在升級那一刻就自動
//     以正式帳戶身份通行，沒有任何一步需要新憑據——「撿到舊令牌即獲得正式權限」
//     正是要擋的事。本人要回到門內，必須用新憑據重新登入（且首次登入先改密）；
//   - 可追溯：Root 域審計記下 login_name 與 account_type 的前後值、改密旗標與
//     這次撤銷的會話數量。既有的 account.guest_enter 審計一個字都不動——
//     歷史事件描述的就是發生時那個訪戶身份，升級不重寫歷史（只追加存儲）。
//
// 升級出來的形態恆為普通帳戶：account_type 的取值集合裡沒有第三格，授予表更不在
// 這條 UPDATE 之內（遷移 0006 的授予由 grant 域各自的通路書寫，訪戶按定義不曾持有）。
// 「把訪客升級成管理員」在協定層就沒有一個可以填的格子（本體白名單只有登入名與口令，
// 未知欄位由 decodeJSON 當場拒殺），在用例層也沒有可寫的地方。
//
// 目標範圍在既有的 readStandardProfile（加上所有寫入通路共用的 requireNotTerminal）
// 之上再加兩道只屬於這條通路的檢查：
//   - 必須是訪戶（account_type=guest）：他已是普通帳戶時本次整個不發生——
//     那顆按鈕對這個人不再存在，重複提交只會再拿到同一句 ErrNotUpgradeableGuest；
//   - 必須是可登入狀態（active）：停用中的訪戶今天不能升級，處置是先恢復他的登入能力
//     （或直接讓他這一趟臨時身分自然到期）。「停用不是刪除、升級不是復活」因此都
//     寫在判定形狀上；已進入刪除終態者與已被綁走的退休訪戶更早在 requireNotTerminal
//     就出局，各回「他已被刪除」「他已綁定退休」那一句（2027／2028）——
//     他們都還在這本目錄裡，把他們報成「查無此人」是誤導，
//     而退休行每一欄都被庫釘住，讓寫去撞觸發器只會換成一個 500。
//     「已轉正」與「已停用」兩者都回同一枚獨立結論（不是 1001、不是 2011）：這個人就躺在這本目錄裡、
//     操作者的權限也足夠，缺的是目標此刻的形態——把「已是正式帳戶」和「已被停用」
//     收進同一句話是刻意的：界面在發起請求前就按服務端讀回的來源與狀態分岔，
//     這枚碼在正路徑上只兜住併發與繞過界面的直打，不值得為兩種內部原因發兩枚碼。
//
// 策略開關不約束這條通路：三個建立開關管的是「准不准多出一筆帳戶」，而升級動的是
// 一筆已存在帳戶的分類與憑據，與「訪客入口此刻開不開了」無關（關掉訪客入口不該
// 順帶剝奪管理員處置既有訪戶的手段）。憑據交付語意沿用建號與重置同一套：一次性口令
// 由操作者親自交、伺服端不生成、不在任何回應裡回顯、不設默認口令；線下交付管道在協議之外。
//
// 併發與重複請求：倉儲守衛（WHERE account_type='guest' AND status='active'）加上
// SQLite 單寫入者，把兩次同時到達的升級串行化——先提交者完成整筆「轉正＋撤會話＋審計」，
// 後到者在交易內的現讀裡就看見他已是普通帳戶，拿到同一句不可升級；
// 守衛命中零行的兜底結論（ErrUpgradeConflict）只在讀寫之間的缺陷形態可達，映射 2014。
// 登入名的重名衝突不改變訪戶一個字（UPDATE 整條不生效），結論沿用目錄同族已發布的
// ErrDuplicateLogin → 2012：要換的是名字而不是拼寫。
package stdacct

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// 升級用例的結論錯誤：口令形狀不合格、目標形態不可升級、併發落敗各自可判別，
// 內部故障一律不進這些型別。「目標不在本目錄」不另發一型：沿用詳情、編輯、停用、
// 重置同一枚 ErrAccountNotFound——「他不存在／他是管理員／他還在審批鏈門外」在本目錄
// 從來只有一個答案；已刪除與已退休是另兩句（見 deleted.go）。
var (
	// ErrInvalidUpgradePassword 表示操作者交出的初始口令不滿足憑據模組的形狀界線（空或超長）。
	//
	// 它與建號、重置那兩枚分開只為訊息各自點名自己的場合，三者的判定來自
	// 同一個實作點（internal/credential.Hash）。
	ErrInvalidUpgradePassword = errors.New("stdacct: 升級口令不滿足憑據形狀界線")
	// ErrNotUpgradeableGuest 表示目標此刻不是可升級的訪戶：他已是普通帳戶
	// （重複升級），或他的登入能力此刻被停用。這是目標形態的出局條件，
	// 不是權限問題（換身分沒用）、也不是請求寫法問題（改口令沒用）——
	// 傳輸層據此回 2024。不降成 1001：這本目錄按定義把他列得進去，
	// 「換個目標」對「再升一次已經轉正的人」是誤導；也不降成 2018：那句話的
	// 方向恰好相反（他說的是「他是訪戶，重置口令等升級通路」，而這條通路就是那個升級）。
	ErrNotUpgradeableGuest = errors.New("stdacct: 目標此刻不是一個可升級的訪戶")
	// ErrUpgradeConflict 表示倉儲守衛命中零行：交易內剛讀到的「訪戶且可用」轉眼寫不中。
	//
	// 正常串行下它在現讀就已被 ErrNotUpgradeableGuest 擋住，這裡只兜住缺陷形態；
	// 對外映射沿用 2014「目標的可用性已不是你確認時那樣」——處置同形：重讀現狀再決定。
	ErrUpgradeConflict = errors.New("stdacct: 目標形態已與提交時所依據的不同")
)

// UpgradeInput 是一次訪戶原地升級所需的領域輸入。
//
// 只有正式登入名與一次性初始口令兩個欄位：沒有角色、沒有帳戶類型、沒有狀態、
// 沒有任何依據值欄位——「升級成哪一類主體」由「打的哪個端點、走的哪個用例」決定
// （恆為 standard＋active＋首次必改密），請求裡沒有任何格子能宣稱別的形態；
// 顯示名也不在這裡動（那是既有編輯白名單那條通路的一句话，升級不是改名）。
type UpgradeInput struct {
	// LoginName 為正式登入名原始寫法；正規化唯一鍵由帳戶域層計算。
	LoginName string
	// InitialPassword 為操作者親自交的一次性初始口令明文。
	// 它只在本次調用期間短暫停留：派生成雜湊後即不再被引用，
	// 不進回應、日誌、審計或任何錯誤訊息。
	InitialPassword string
}

// GuestUpgrade 是一次成功升級的結果：更新後的單筆真相加撤銷數量。
type GuestUpgrade struct {
	// Profile 為升級後經實體校驗的單筆資料（與詳情同形；Type 恆為 standard、
	// MustChangePassword 恆為 true）。
	Profile StandardProfile
	// RevokedSessions 為這次撤銷的會話數量：界面要能如實說出「這次讓 N 臺裝置
	// 必須用新憑據重新登入」，不許界面自己猜。0 是事實（那一趟訪客可能早已到期），
	// 不是失敗。
	RevokedSessions int
}

// UpgradeGuestToStandard 以持有伺服器級管理權的受信主體，把一名目錄內可登入的
// 訪戶帳戶原地升級成普通帳戶（保留穩定標識與既有歷史引用）。
//
// 全部寫入落在同一個交易，順序與每一跳的理由：
//  1. 授權（NeedServerAdmin，與建號、目錄、編輯、停用、重置同一道閘）與零值標識在交易外：
//     匿名與訪戶本人在這裡就拿到 2011——「Guest 不能給自己提升權限」不是本步新造的規則，
//     而是既有授權矩陣對零授予主體的事實；
//  2. 口令派生放在交易之外：Argon2id 按生產參數檔是數百毫秒級的計算，與建號、
//     重置同一理由。派生失敗（空口令、超長口令）在此回輸入錯誤，一條寫入都沒有發生；
//  3. 交易內 readStandardProfile：帳戶存在、是否持有授予、是否還在審批鏈門外
//     一起核實，對不在本目錄的標識整個操作不發生並回 ErrAccountNotFound；
//  4. 形態三道檢查（不是終態、必須是訪戶、必須可登入）：出局點都在寫入之前，
//     被拒的升級零寫入、零撤銷、零審計——與被拒的建號、重置同口徑；
//  5. 單條 UPDATE 轉正（UpgradeGuestToStandard）：分類、正式登入名與鍵、雜湊、
//     改密旗標同生同滅，「失敗不留無口令的半升級身份」由此成立；重名回 ErrDuplicateLogin、
//     守衛零行回 ErrUpgradeConflict，兩者都讓整筆交易回滾；
//  6. 同交易撤銷目標全部會話：「升級使舊訪戶憑據失效」因此是落庫的事實，
//     與停用、重置同一個執行手段（session.RevokeAccount）；
//  7. 同交易重讀並追加 Root 域審計：變更與其審計同生同滅，回應要的是
//     「升級之後的資料庫現值」，不是呼叫端的意圖回音。
func (s *Service) UpgradeGuestToStandard(ctx context.Context, principal identity.Principal,
	accountID idgen.ID, in UpgradeInput, requestID string) (GuestUpgrade, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		s.log.Warn("升級訪戶被拒：主體不具備伺服器級管理權",
			"subject", principal.String(), "request_id", requestID)
		return GuestUpgrade{}, err
	}
	if accountID.IsNil() {
		return GuestUpgrade{}, ErrAccountNotFound
	}

	passwordHash, err := credential.Hash(in.InitialPassword, s.hashing)
	if err != nil {
		var hashErr *credential.HashError
		if errors.As(err, &hashErr) {
			// 可展示的原因（空口令／超長）進結論；訊息本身不含任何口令材料。
			return GuestUpgrade{}, fmt.Errorf("%w：%v", ErrInvalidUpgradePassword, hashErr.Reason)
		}
		return GuestUpgrade{}, fmt.Errorf("stdacct: 產生升級憑據雜湊失敗: %w", err)
	}

	var result GuestUpgrade
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		before, err := s.readStandardProfile(tctx, tx, accountID)
		if err != nil {
			return err
		}
		// 終態判定在類型與狀態兩道檢查之前：一個已刪除或已被綁走的人，該拿到的是
		// 他那句終態的話，而不是「他此刻不是可升級的訪戶」這句還暗示重讀後可以再按一次的話。
		if err := requireNotTerminal(before); err != nil {
			return err
		}
		if before.Type != account.TypeGuest || before.Status != account.StatusActive {
			return ErrNotUpgradeableGuest
		}
		changed, err := s.accounts.UpgradeGuestToStandard(tctx, tx, accountID,
			in.LoginName, passwordHash)
		if err != nil {
			return err
		}
		if !changed {
			// 交易內剛讀到「訪戶且可用」、轉眼寫不中：併發的另一次寫入或程式缺陷。
			return ErrUpgradeConflict
		}
		revoked, err := s.sessions.RevokeAccount(tctx, tx, accountID)
		if err != nil {
			return err
		}
		after, err := s.readStandardProfile(tctx, tx, accountID)
		if err != nil {
			return err
		}
		rec, err := s.guestUpgradeRecord(principal, before, after, revoked, requestID)
		if err != nil {
			return err
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		result = GuestUpgrade{Profile: after, RevokedSessions: revoked}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, account.ErrNotFound), errors.Is(err, grant.ErrNotFound):
			return GuestUpgrade{}, ErrAccountNotFound
		case errors.Is(err, account.ErrDuplicateLogin):
			// 業務衝突：不是故障，不報 5xx，也不寫審計；訪戶一欄都沒被改。
			s.log.Warn("升級訪戶被拒：正式登入名已被佔用", "request_id", requestID)
			return GuestUpgrade{}, fmt.Errorf("%w（%v）", ErrDuplicateLogin, err)
		case errors.Is(err, account.ErrInvalidLogin):
			// 可展示的域結論：訊息點出的是請求本體哪個欄位不合規，與憑據無關。
			s.log.Warn("升級訪戶被拒：正式登入名不合領域規則", "request_id", requestID)
			return GuestUpgrade{}, err
		case errors.Is(err, ErrNotUpgradeableGuest), errors.Is(err, ErrUpgradeConflict),
			errors.Is(err, ErrInvalidUpgradePassword), errors.Is(err, ErrAccountNotFound),
			errors.Is(err, ErrAccountDeleted), errors.Is(err, ErrAccountRetired):
			return GuestUpgrade{}, err
		}
		s.log.Error("升級訪戶失敗", "request_id", requestID, "err", err)
		return GuestUpgrade{}, fmt.Errorf("stdacct: 升級訪戶失敗: %w", err)
	}
	s.log.Info("已將訪戶帳戶原地升級為普通帳戶（舊憑據分類與既有會話失效，首次登入須改密）",
		"account", result.Profile.AccountID.String(),
		"revoked_sessions", result.RevokedSessions, "request_id", requestID)
	return result, nil
}

// guestUpgradeRecord 產生一筆 Root 域的升級審計。口徑與 creationRecord 同源：
// actor 只能經 principal.AuditActor() 換得，換不出就讓整筆升級回滾。
//
// 動作名以 account. 前綴與本套件其餘用例分家於管理員那組 admin.*，Target 是同一枚
// 穩定帳戶標識——升級前後是同一個人，審計的指向因此不需要任何搬遷。
// ScopeRoot 而不捏造 activity_id：升級一個伺服器級帳戶的身份不屬於任何活動。
//
// 這是「追加一筆新事實」，不是「改寫舊事實」：那筆 account.guest_enter 審計描述的是
// 發生時那個訪戶身份，本方法不碰它，也沒有任何其他通路能碰它（只追加存儲）。
//
// 絕不落進記錄的東西：初始口令明文、Argon2id 雜湊、會話材料、任何錯誤鏈原文。
// Changes 只有可展示的身分欄位與這次撤銷的會話數量——刻意不帶任何可能容下
// 憑據材料的格子，讓「審計表裡沒有一個欄位可能含口令」繼續成立在結構上。
func (s *Service) guestUpgradeRecord(principal identity.Principal, before, after StandardProfile,
	revoked int, requestID string) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("stdacct: 主體無法換得審計操作者: %w", err)
	}
	return audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  actor,
		Action: "account.guest_upgrade",
		Target: audit.Target{Kind: "account", ID: after.AccountID.String()},
		Reason: "伺服器級管理員經已認證會話將訪戶帳戶原地升級為普通帳戶：保留穩定標識與" +
			"既有歷史引用，舊會話全部撤銷，本人須以新憑據重新登入並完成首次改密",
		RequestID: trimRequestID(requestID),
		Changes: []audit.Change{
			{Field: "login_name", Before: before.LoginName, After: after.LoginName},
			{Field: "account_type", Before: before.Type.String(), After: after.Type.String()},
			{Field: "must_change_password", Before: before.MustChangePassword,
				After: after.MustChangePassword},
			{Field: "revoked_sessions", Before: nil, After: revoked},
		},
	}, nil
}
