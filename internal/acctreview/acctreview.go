// Package acctreview 是「伺服器級管理者處理帳戶註冊申請」的應用服務層：
// 一本待審批與已拒絕的名冊（只讀投影＋分頁＋篩選），以及對一筆申請做出批准或拒絕的決定
// （與審計落地同交易的那一跳）。
//
// 本套件回答的是「哪些申請還在等、由誰把它決定下來、決定之後留下什麼」這一句話。
// 它與現存的三個鄰居各認一件事，邊界都是刻意畫的：
//   - internal/selfregister 認的是「門外的一個人能不能把申請交進來、他本人查得到什麼」，
//     那一側根本沒有主體（呼叫者是匿名，准入依據是寫入那一刻的策略）。把審核放進去，
//     同一個 Service 上就會同時住著「匿名者提交的通路」與「管理者翻動別人命運的通路」，
//     那是兩套准入最容易互相污染形態；
//   - internal/stdacct 認的是「管理員能打理的普通帳戶名冊」，而那本名冊按範圍規則把
//     pending 與 rejected 排在門外（見其 directory.go 頭注）。本套件不拿那本 WHERE 冒充這本名冊，
//     也不回頭把它改寬——「可打理的普通帳戶」與「等審批的申請」是兩句話，各有各的條件；
//   - internal/adminacct 認的是「Root 如何打理管理員目錄」，授權邊界是 NeedRoot。
//
// 依賴方向因此保持單向：acctreview → account（實體與倉儲寫法）、grant（授予有無）、
// audit（決定留下的痕跡）、database／identity／timeutil。本套件不碰 acctpolicy、
// 不碰 credential、不碰 session，理由寫在下面第二條與第四條規定裡。
//
// 四條不可讓步的規定：
//   - 授權只有 NeedServerAdmin 一檔，而且批准造不出管理員。能讀名冊、能下決定的人是
//     持有伺服器級管理權的主體（Root 與管理員都過，與建號、目錄、停用、重置同一道閘，
//     本步不下放也不另立檔位）；而「批成哪一類主體」由端點形態與用例決定，請求本體
//     只有一個決定值、沒有任何角色格子。結構上的保證更直接：那條 UPDATE 連 account_server_roles
//     這張表都不在語句裡，「批准順手授予角色」在這裡沒有一個可以發生的形狀。
//   - 只准對「還在等的那一筆」做決定，而且決定是單向的。寫入的守衛是資料庫現值
//     status = 'pending'（不是呼叫端交來的依據值，理由見 account.Store.DecideApplication）：
//     兩個審核者同時按下時，SQLite 的單寫入者把兩次提交串行化，只有先提交的那一次真正落地，
//     後到的拿到 changed=false，一個字都沒寫、也不會把先前那個決定蓋掉。
//     已批准過的人（哪怕此後被停用或刪除）與已拒絕過的人都離開了那格守衛：
//     今日沒有任何通路能改判，用戶批准的保留策略是「拒絕就是留下那個決定」。
//   - 審批不是一道認證，也不是一把解開別種限制的鑰匙。本套件不問帳戶建立策略
//     （用戶批准：「模式只管新提交，歷史申請原地保留」——Root 事後把模式改成 closed，
//     既不該讓已交上來的申請消失，也不該讓審核者無法處理他眼前那份等待中的申請）；
//     不簽發、不撤銷、也不復活任何會話（待審批的人今日沒有任何會話，而「他現在能登入了」
//     這句話由他自己拿口令走 /auth/login 那條既有的認證通路得到，不是由審核者的畫面替他完成）；
//     不解除任何獨立的停用、首改義務或刪除終態（那四件事各有自己的欄位與通路）。
//   - 寫入與審計落在同一筆交易，而自由文本一個字都不進資料庫。審核者是誰這個事實
//     只存在 root_audit 的 actor 裡（經 principal.AuditActor() 換得，換不出就讓整筆決定回滾——
//     一個查不到是誰批准的人，比批不出去更糟）；審計的 Reason 由服務端固定措辭產生，
//     與 account.disable、account.profile_update 同口徑。「為什麼拒他」既沒有一格可填、
//     也沒有格子可讀，內部備註與可公開理由因此不是兩套措辭而是一回事都沒有——
//     申請人經上一功能那條受限狀態通道拿到的只有自己那筆申請的結局與決定時刻。
//
// 名冊那條跨表 SQL 仍是用戶批准的「只讀展示投影例外」（原為 internal/adminacct 而立、
// R2-008 經用戶批准首次擴展到 internal/stdacct，本步是同一條例外在第三個套件的落點）：
// 三條邊界一個字不減——只讀、欄位白名單（連 password_hash 與 login_name_key 都不在語句裡）、
// 永不參與授權判定。逐筆的目標範圍核實仍經 internal/account 的實體讀法與 internal/grant
// 的公開讀法，見 decide.go 的 readApplication。
package acctreview

import (
	"errors"
	"log/slog"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 對外可判別的結論錯誤：傳輸層據此分流回應，內部故障一律不進這些型別。
var (
	// ErrApplicationNotFound 表示目標不是這本名冊上的一筆：帳戶不存在、他是訪戶、
	// 他持有伺服器級授予、已進入刪除終態，或他根本沒走過審批通路（管理員建號、Root 開設、
	// 開放自註冊建成的那些行）。五種情況一律同一個答案，也不提供「差哪一半」的信號——
	// 與 internal/stdacct 對 1001 的同一取向：這本名冊的範圍規則本身就是那句話，
	// 把「存在但他是管理員」講出來等於讓一條管理員端點做帳戶枚舉。
	ErrApplicationNotFound = errors.New("acctreview: 該帳戶不在註冊申請名冊中")
	// ErrAlreadyReviewed 表示這一筆申請已經有過決定，或在你按下那一刻被別人先決定了：
	// 整個操作沒有發生——狀態沒改、決定時刻沒寫、審計沒記。
	//
	// 它與 ErrApplicationNotFound 分開只為處置不同：一個是「換個目標」（這本名冊裡沒這個人），
	// 另一個是「別再對著同一份申請按第二次」（他還在名冊上，只是已經被決定過了）。
	// 重複操作與併發落敗收斂到同一枚結論，不謊報成功，也不悄悄覆蓋先前那個決定。
	ErrAlreadyReviewed = errors.New("acctreview: 這份申請已經做過決定")
	// ErrInvalidDecision 表示要做的決定不在封閉集合內（只認 approve|reject）。
	// 它是請求本體的問題，屬呼叫端可修正的輸入錯誤，走 1004 點名 decision 欄位。
	ErrInvalidDecision = errors.New("acctreview: 審批決定值不合法")
	// ErrPermissionDenied 沿用 identity 的判定結論：身分可信但沒有這個權限。
	ErrPermissionDenied = identity.ErrPermissionDenied
)

// Deps 是本用例的外部依賴，全部由裝配層（internal/app）注入。
type Deps struct {
	// DB 提供交易邊界與 autocommit 查詢。
	DB *database.DB
	// Accounts 是帳戶倉儲：名冊的只讀投影與「那一跳決定」都由它給，
	// 本套件不自己拼 UPDATE 語句——帳戶列的寫法只有 internal/account 一份。
	Accounts *account.Store
	// Grants 是伺服器級授予倉儲。名冊與逐筆範圍核實都要問「他是不是已經被授予過管理權」，
	// 這句話的權威只在這裡；展示投影負責列出、授予倉儲負責答覆，兩處不各寫一套。
	Grants *grant.Store
	// Audits 是 Root 域審計倉儲。審核者是誰只存在這張表的 actor 裡（用戶批准的形態：
	// 帳戶表沒有審核人欄，也沒有備註欄）。
	Audits *audit.Store
	// Log 為伺服器端記錄出口；nil 時丟棄。
	Log *slog.Logger
}

// Service 是註冊申請審批用例（名冊＋批准與拒絕）的編排者。零值不可用，請經 New 取得。
type Service struct {
	db       *database.DB
	accounts *account.Store
	grants   *grant.Store
	audits   *audit.Store
	log      *slog.Logger
}

// New 校驗依賴並建立服務。
//
// 缺任何一個依賴都是組裝缺陷，在啟動階段當場報出：少授予倉儲就分不清「一個被授予過管理權的人
// 是不是也掛在待審批的名冊上」（要嘛把他列進來、要嘛讓他經批准變成第二份可登入的管理員身份）；
// 少審計倉儲就會落出一個「有人被放行了，卻查不到是誰放的」的決定——
// 那正是審批這件事最不能缺的一格。
//
// 刻意沒有的三個依賴也是同一句話：不注入 acctpolicy（審批不問准入策略，
// 模式只管新提交）、不注入 session（決定不動任何會話）、不注入 credential
// （本套件這輩子不碰任何一枚口令）。
func New(deps Deps) (*Service, error) {
	if deps.DB == nil || deps.Accounts == nil || deps.Grants == nil || deps.Audits == nil {
		return nil, errors.New("acctreview: 用例缺少必要依賴（db/accounts/grants/audits）")
	}
	logger := deps.Log
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		db:       deps.DB,
		accounts: deps.Accounts,
		grants:   deps.Grants,
		audits:   deps.Audits,
		log:      logger,
	}, nil
}

// trimRequestID 保證關聯 ID 不超過審計欄位上限（與 internal/adminacct、internal/stdacct 同口徑）。
func trimRequestID(requestID string) string {
	if r := []rune(requestID); len(r) > 64 {
		return string(r[:64])
	}
	return requestID
}

// nullableFormatUTC 把零值時刻換成 nil（審計的變更前空值不冒充有效時刻），
// 其餘交 timeutil.FormatUTC（與回應本體同一個時刻表示，追查時兩邊對得起來）。
func nullableFormatUTC(at time.Time) any {
	if at.IsZero() {
		return nil
	}
	return timeutil.FormatUTC(at)
}
