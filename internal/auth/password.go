// password.go 是「本人修改自己的憑據」的用例：普通帳戶換 accounts 表裡的雜湊，
// Root 換組態檔裡的唯一雜湊，兩者都讓舊口令失效、並按批準策略撤銷主體名下全部會話。
//
// 這一條路刻意不收的東西：
//   - 管理員重置他人口令——那是另一個產品面（需要權限語義與作用域判定），本檔不預做；
//   - 「近期強認證」之類的寬限通道——這裡的再認證就是「當場交出現行口令」本身，
//     會話有效不能替代它：被偷走的 Cookie 不該擁有改密權；
//   - 第二套口令規則——長度與形狀界線沿用 credential 模組那一套（passwordShapeValid），
//     派生與比對沿用同一個雜湊服務，不在這裡另立門戶。
//
// 撤銷策略是用戶已批準的決定：改密成功＝該主體全部會話退出（含發起這一次的裝置），
// 所以成功路徑上沒有一枚「還活著的舊會話」，客戶端下一步就是重新登入。
// 普通帳戶的整串變更（換雜湊、清 must_change_password、撤銷全部會話）落在同一個
// SQLite 交易裡，天然原子；Root 的憑據在配置檔、會話在資料庫，跨存儲無法同交易，
// 失敗恢復方案見 changeRootPassword 的註解。
package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// 改密用例的對外結論（憑據不對一律沿用 ErrInvalidCredentials，不新造第二個「口令錯」）。
var (
	// ErrInvalidNewPassword 表示新口令不滿足憑據模組的形狀界線（空或超長）。
	// 它是請求本體的問題——與「現行口令不對」分開，否則界面會把「你打的新密碼太短」
	// 講成「你現在的密碼不對」，那是兩句不同的話。
	ErrInvalidNewPassword = errors.New("auth: 新口令不滿足憑據形狀界線")
	// ErrSamePassword 表示新口令與現行口令校驗相同。
	//
	// 它單獨報出來不是爲了懲罰「設了同一個密碼」這個動作本身——換雜湊照樣會成功——
	// 而是因為這次操作真正的目的（讓舊口令失效、讓全部裝置重新登入）在換了個
	// 等價口令的前提下完全沒有達成。讓人以為「我已經把密碼換掉了」比讓人再想一次
	// 更危險，所以這條路上沒有「照做但其實什麼都沒變」的成功。
	ErrSamePassword = errors.New("auth: 新口令與現行口令相同")
)

// PasswordChangeResult 是一次成功改密的結果。
//
// RevokedSessions 是「這次真的被撤銷的會話數」（含發起這一次的裝置）：它是本人
// 名下會話的數量，不涉他人，可供界面講出「已讓 N 臺裝置重新登入」這句真實的話。
// 不含任何憑據材料。
type PasswordChangeResult struct {
	RevokedSessions int
}

// MustChangePassword 回報該受信主體是否帶有「必須改密」旗標。
//
// 這是一次現讀而不是會話簽發時的快照：旗標在改密成功的那一刻清除，之後的請求
// 必須立刻看到解除——判定如果凍進 Principal 或 Session，「改了密卻還被鎖在改密頁」
// 或「還沒改密就提前放行」都會成為可能，兩者都是把一個安全門閂交給了時序運氣。
// 只對帳戶主體有意義：Root 憑據不在 accounts 表（無此旗標），回傳 false；
// 訪客帳戶由資料庫 CHECK 凍結為 0，不需要特判。查無此人回 false 而不是錯誤：
// 那種會話在 Verify 那一關就換不出身份，走到這裡只剩競態的尾巴，
// 限制判定不該把資料缺陷放大成第二種 externally-visible 失敗。
func (s *Service) MustChangePassword(ctx context.Context, principal identity.Principal) (bool, error) {
	if !principal.IsRoot() && principal.Kind() != identity.KindAccount {
		return false, nil
	}
	if principal.IsRoot() {
		return false, nil
	}
	a, err := s.accounts.ByID(ctx, s.db.SQL(), principal.AccountID())
	if err != nil {
		if errors.Is(err, account.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("auth: 讀取必須改密旗標失敗: %w", err)
	}
	return a.MustChangePassword, nil
}

// ChangePassword 讓「剛經解析換回主體」的本人更換自己的口令。
//
// 授權形態與登出/輪換同族：呼叫它的前提是本次請求的憑據此刻仍換得出身份
// （傳輸層先走 resolveCredentials），而「交出現行口令」是這一步額外的再認證——
// 兩者都成立才動到憑據本身。請求裡沒有任何可以指定「改誰」的欄位：主體
// 由那枚憑據解析出來，改密因此天然只可能改到自己。
//
// 普通帳戶（changeAccountPassword）：換雜湊、清旗標、撤銷名下全部會話，
// 三件事落在同一個資料庫交易裡——成功回傳時不存在任何舊口令還能用的會話，
// 失敗回滾時也不存在「改了一半」。Root（changeRootPassword）見該方法註解。
//
// 現行口令不對一律收斂為 ErrInvalidCredentials（沿用登入的合同語意）：
// 它不區分「打錯」「被並發改掉」「編碼壞了」，外部沒有可以用差異探測的縫。
// 日誌記內部原因與主體摘要，永不記口令或雜湊。
func (s *Service) ChangePassword(ctx context.Context, principal identity.Principal,
	currentPassword, newPassword, requestID string) (PasswordChangeResult, error) {
	if principal.IsRoot() {
		return s.changeRootPassword(ctx, principal, currentPassword, newPassword, requestID)
	}
	if principal.Kind() != identity.KindAccount {
		return PasswordChangeResult{}, fmt.Errorf("auth: %w 之外的主體沒有口令通路（%s）",
			ErrInvalidCredentials, principal.Kind().String())
	}
	return s.changeAccountPassword(ctx, principal, currentPassword, newPassword, requestID)
}

// changeAccountPassword 在單一交易內完成帳戶改密的全部寫入。
//
// 順序與把關：
//  1. 現讀帳戶：訪客帳戶擋下（無口令通路，資料庫 CHECK 也凍著旗標，兩道閘同口徑）；
//  2. 現行口令比對用入庫時自帶的參數檔（credential.Verify）——與登入同一個雜湊服務；
//  3. 新口令先過形狀閘與「不等於現行口令」，才允許消耗一次派生；
//  4. 交易內 CAS 換雜湊（WHERE 帶著校驗過的那個舊值）：讀與寫之間被並發改掉的
//     那一路會整筆失敗回滾，出贏家之外的第二次「成功」不存在；
//  5. CAS 生效後在同一交易內 RevokeSubject：撤銷與新雜湊同生同滅。
//     「口令已換但舊會話還活著」因此在帳戶這條路上不是狀態，而是事務缺陷。
//
// 普通帳戶不寫審計表（審計主體類別未批準，與登入/登出/輪換同一口徑），只進執行日誌。
func (s *Service) changeAccountPassword(ctx context.Context, principal identity.Principal,
	currentPassword, newPassword, requestID string) (PasswordChangeResult, error) {
	a, err := s.accounts.ByID(ctx, s.db.SQL(), principal.AccountID())
	if err != nil {
		if errors.Is(err, account.ErrNotFound) {
			return PasswordChangeResult{}, fmt.Errorf("%w（帳戶已不存在）", ErrInvalidCredentials)
		}
		return PasswordChangeResult{}, fmt.Errorf("auth: 讀取帳戶失敗: %w", err)
	}
	if a.Type == account.TypeGuest {
		s.log.Warn("改密被拒：訪客帳戶無口令通路", "account", a.ID.String(), "request_id", requestID)
		return PasswordChangeResult{}, fmt.Errorf("%w（訪客帳戶沒有口令）", ErrInvalidCredentials)
	}
	if !passwordShapeValid(currentPassword) {
		// 空口令與超長口令不會進入派生（credential.Verify 直接判否），這裡先擋的
		// 意義是讓日誌分得清「人沒填現行口令」與「填了但不對」——對外兩者仍是同一個
		// ErrInvalidCredentials，與登入路的收斂逐字同形。
		s.log.Warn("改密被拒：現行口令形狀不合格", "account", a.ID.String(), "request_id", requestID)
		return PasswordChangeResult{}, fmt.Errorf("%w（現行口令形狀不合格）", ErrInvalidCredentials)
	}
	ok, err := credential.Verify(a.PasswordHash, currentPassword)
	if err != nil {
		s.log.Error("帳戶憑據編碼不可校驗（改密路徑）", "account", a.ID.String(),
			"err", err, "request_id", requestID)
		return PasswordChangeResult{}, fmt.Errorf("%w（既有憑據不可用）", ErrInvalidCredentials)
	}
	if !ok {
		s.log.Warn("改密被拒：現行口令不符", "account", a.ID.String(), "request_id", requestID)
		return PasswordChangeResult{}, ErrInvalidCredentials
	}
	if err := s.newPasswordUsable(a.PasswordHash, newPassword); err != nil {
		return PasswordChangeResult{}, err
	}
	newHash, err := credential.Hash(newPassword, s.hashing)
	if err != nil {
		return PasswordChangeResult{}, fmt.Errorf("auth: 產生新憑據雜湊失敗: %w", err)
	}

	subject, err := session.SubjectOf(principal)
	if err != nil {
		return PasswordChangeResult{}, err
	}
	var result PasswordChangeResult
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		changed, err := s.accounts.RotatePassword(tctx, tx, a.ID, newHash, a.PasswordHash)
		if err != nil {
			return err
		}
		if !changed {
			// 校驗到寫入之間現值已被換掉（並發改密／管理側動作）：這次嘗試的前提
			// 已不存在，整筆回滾，按「憑據不對」收斂——與登入合同的收斂方向一致。
			return fmt.Errorf("%w（現行憑據已被更換）", ErrInvalidCredentials)
		}
		n, err := s.sessions.RevokeSubject(tctx, tx, subject)
		if err != nil {
			return err
		}
		result = PasswordChangeResult{RevokedSessions: n}
		return nil
	})
	if err != nil {
		s.log.Error("帳戶改密落地失敗", "account", a.ID.String(), "err", err, "request_id", requestID)
		return PasswordChangeResult{}, fmt.Errorf("auth: 帳戶改密失敗: %w", err)
	}
	s.log.Info("帳戶口令已更換，名下全部會話已撤銷",
		"account", a.ID.String(), "revoked_sessions", result.RevokedSessions, "request_id", requestID)
	return result, nil
}

// newPasswordUsable 用同一個雜湊服務判定新口令的兩件事：形狀合格、不等於現行口令。
//
// 「是否相同」的比對走 credential.Verify（拿現行雜湊校驗明文），不比字串也不比雜湊：
// Argon2id 帶隨機鹽，同一明文兩次雜湊本來就不相等，能回答「是不是同一個口令」的
// 只有校驗這條路。現行雜湊解不開時按「不相同」放行——那屬於既有憑據不可用，
// 在上一步的現行口令比對就已經攔下了，走到這裡只剩理論上的殘影。
func (s *Service) newPasswordUsable(currentHash, newPassword string) error {
	if !passwordShapeValid(newPassword) {
		return ErrInvalidNewPassword
	}
	ok, err := credential.Verify(currentHash, newPassword)
	if err != nil {
		return nil
	}
	if ok {
		return ErrSamePassword
	}
	return nil
}

// changeRootPassword 更換組態檔裡的 Root 憑據，並讓名下全部會話退出。
//
// Root 的口令在配置檔、會話在資料庫，兩邊沒有共用的事務——跨存儲的失敗恢復
// 因此是這條路設計的主體，順序把每一種半途結果都收在「可解釋、可恢復」的一側：
//
//  1. 全部校驗（現行口令、新口令形狀與「不相同」）在任何寫入之前完成：被拒的
//     改密不動檔案、不動資料庫、不動記憶體；
//  2. Replaceable() 在第一次寫入之前問：環境變數覆蓋下覆寫檔案只會造出兩份 Root，
//     這種部署形態的拒絕發生在一切寫入之前，外部只會看到一句 5xx；
//  3. 先覆寫配置（含記憶體生效值，同一個互斥區）：成功回傳即「檔案現值＝新雜湊」；
//     失敗則到此為止——舊口令照用、會話照活，這次改密整筆沒有發生；
//  4. 交易內撤銷全部 Root 會話並追加 root_audit 的 auth.password_change
//     （撤銷與審計同生同滅，沿用 Root 域事件的既有合同）；
//  5. 這一步失敗（資料庫寫不進）→ 補償：把配置與記憶體換回舊雜湊（同一條 CAS 通路）。
//     補償成功＝對外報失敗、狀態與動筆前一致；補償也失敗（檔案系統與資料庫同時壞）＝
//     口令已換、舊會話仍在但受絕對期限封頂、審計缺席——日誌以 Error 把這句話如實寫出，
//     對外仍報失敗，不假裝成功。這個雙重故障窗口是本步能誠實交代的最壞一半，
//     它不產生「頁面報成功而舊口令仍可登入」，因為成功的定義要求 3 與 4 都落地。
//
// 先寫配置再撤會話的代價是一次競態尾巴：第 3 步與第 4 步之間以新口令登入的會話
// 會隨第 4 步一起被撤（RevokeSubject 撤的是「此刻未撤銷的全部」，讀不讀得到
// 那幾毫秒裡新簽發的行取決於提交時序，SQLite 單寫入者讓兩筆交易串行，不存在
// 交叉覆蓋）。代價換來的是失敗路徑全部落在「舊狀態完整」那一側——比反向
// （先撤會話、檔案寫壞、留下一地已登出裝置與一句謊報的失敗）更不傷人。
func (s *Service) changeRootPassword(ctx context.Context, principal identity.Principal,
	currentPassword, newPassword, requestID string) (PasswordChangeResult, error) {
	rootHash := s.root.CurrentHash()
	if rootHash == "" {
		// 能持有 Root 會話卻讀不到憑據現值，只剩「改密進行中剛被換掉／配置壞了」一類：
		// 對外與口令不符同形，內部留一條要查的日誌。
		s.log.Warn("Root 改密被拒：讀不到現行憑據", "request_id", requestID)
		return PasswordChangeResult{}, fmt.Errorf("%w（組態未提供 Root 憑據）", ErrInvalidCredentials)
	}
	if !passwordShapeValid(currentPassword) {
		s.log.Warn("Root 改密被拒：現行口令形狀不合格", "request_id", requestID)
		return PasswordChangeResult{}, fmt.Errorf("%w（現行口令形狀不合格）", ErrInvalidCredentials)
	}
	ok, err := credential.Verify(rootHash, currentPassword)
	if err != nil {
		s.log.Error("Root 憑據編碼不可校驗（改密路徑）", "err", err, "request_id", requestID)
		return PasswordChangeResult{}, fmt.Errorf("%w（既有憑據不可用）", ErrInvalidCredentials)
	}
	if !ok {
		s.log.Warn("Root 改密被拒：現行口令不符", "request_id", requestID)
		return PasswordChangeResult{}, ErrInvalidCredentials
	}
	if err := s.newPasswordUsable(rootHash, newPassword); err != nil {
		return PasswordChangeResult{}, err
	}
	if !s.root.Replaceable() {
		// 檢查放在口令校驗之後：部署形態不是可以被未授權嘗試探測的內容。
		s.log.Error("Root 改密被拒：當前部署形態下憑據不可覆寫", "request_id", requestID)
		return PasswordChangeResult{}, ErrRootCredentialLocked
	}
	newHash, err := credential.Hash(newPassword, s.hashing)
	if err != nil {
		return PasswordChangeResult{}, fmt.Errorf("auth: 產生新 Root 憑據失敗: %w", err)
	}

	if err := s.root.Replace(rootHash, newHash); err != nil {
		if errors.Is(err, ErrRootCredentialStale) {
			// 現值在「校驗」與「覆寫」之間被並發改密或外部動作換掉了：這次嘗試的
			// 前提已不存在，按憑據拒絕收斂——來人手上那枚現行口令已經不是現行了。
			s.log.Warn("Root 改密被拒：現行憑據已被更換", "request_id", requestID)
			return PasswordChangeResult{}, fmt.Errorf("%w（現行憑據已被更換）", ErrInvalidCredentials)
		}
		s.log.Error("Root 憑據覆寫失敗", "err", err, "request_id", requestID)
		return PasswordChangeResult{}, fmt.Errorf("auth: Root 憑據覆寫失敗: %w", err)
	}

	subject, err := session.SubjectOf(principal)
	if err != nil {
		return PasswordChangeResult{}, err
	}
	var result PasswordChangeResult
	err = s.db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		n, err := s.sessions.RevokeSubject(tctx, tx, subject)
		if err != nil {
			return err
		}
		subjectID, err := identity.RootSubjectID()
		if err != nil {
			return fmt.Errorf("auth: Root 審計主體標識異常: %w", err)
		}
		rec := audit.Record{
			Scope:  audit.ScopeRoot,
			Actor:  audit.Actor{Kind: audit.ActorRoot, ID: subjectID},
			Action: "auth.password_change",
			// target 記 server 而不是某枚會話：這次變更的對象是伺服器級憑據本身，
			// 「哪幾枚會話被撤」數量進 reason，逐行 ID 無以復數也無須復數。
			Target:    audit.Target{Kind: "server"},
			Reason:    fmt.Sprintf("本人經已認證會話更換 Root 口令，並撤銷名下 %d 個會話", n),
			RequestID: trimRequestID(requestID),
		}
		if _, err := s.audits.Append(tctx, tx, rec); err != nil {
			return err
		}
		result = PasswordChangeResult{RevokedSessions: n}
		return nil
	})
	if err != nil {
		// 補償：把配置與記憶體換回舊雜湊。方向反過來走的仍是那條 CAS 通路
		// （現值必須還是 newHash 才換回去），並行的後續改密不會被這條尾巴誤蓋。
		if rbErr := s.root.Replace(newHash, rootHash); rbErr != nil {
			s.log.Error("Root 改密回滾失敗：口令已更換但會話撤銷與審計未落地",
				"revoke_err", err, "rollback_err", rbErr, "request_id", requestID)
			return PasswordChangeResult{}, fmt.Errorf("auth: Root 改密會話撤銷失敗，且憑據回滾同樣失敗: %v（原始錯誤：%v）", rbErr, err)
		}
		s.log.Error("Root 改密會話撤銷失敗，已回滾憑據", "err", err, "request_id", requestID)
		return PasswordChangeResult{}, fmt.Errorf("auth: Root 改密失敗（憑據已回滾）: %w", err)
	}
	s.log.Info("Root 口令已更換，名下全部會話已撤銷",
		"revoked_sessions", result.RevokedSessions, "request_id", requestID)
	return result, nil
}
