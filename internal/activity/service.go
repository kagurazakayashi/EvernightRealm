// service.go 是活動用例的入口與依賴裝配：把「資料庫交易、指派倉儲、帳戶與授予的現讀、
// 審計出口、注入時鐘」湮成一個 Service，讓每個用例都在同一份實例上跑。
//
// 為什麼依賴要由裝配層交進來而不是本套件自己 new：一個程式裡「活動的真相」只能有一份。
// 帳戶倉儲、授予倉儲與審計倉儲都沿用 internal/app 那一批實例，於是
// 「他是誰」「他有沒有管理員資格」「這件事留痕在哪裡」各只有一個出口——
// 換一份實例就會出現兩套真相，而其中一套總會被某條通路當成權威。
//
// 刻意沒有的依賴：會話倉儲與憑據引數。本套件的每一條通路都只問「這次請求的主體是誰」，
// 不簽發會話、不改任何口令，也不撤任何人的登入能力；少接一條就少一分
// 「管活動的時候不小心動到帳戶登入」的可能（與 internal/acctreview、internal/invitecode
// 把會話與憑據留在依賴之外同一取向）。
package activity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// Deps 是活動用例的外部依賴。
type Deps struct {
	// DB 提供交易邊界與 autocommit 查詢；必要依賴。
	DB *database.DB
	// Store 是活動與指派的持久倉儲；nil 時由 New 以注入時鐘（或系統時鐘）建一個。
	Store *Store
	// Accounts 是帳戶實體的唯一讀取點：指派管理人前要現讀目標帳戶的型別與狀態
	// （訪戶與已進入終態的帳戶都不能持有活動管理權）。必要依賴。
	Accounts *account.Store
	// Grants 是伺服器級授予的唯一讀取點：活動管理人按批准口徑必須同時是伺服器級管理員，
	// 這一句問的是 internal/grant，不是本套件自己攊一份角色。必要依賴。
	Grants *grant.Store
	// Clock 是「現在」的唯一來源；nil 時採用 timeutil.System()。
	// Store 與 Service 沿用同一個實例：建立時刻與目錄派生的「何時算晚近」必須同源。
	Clock timeutil.Clock
	// Audits 是活動域審計倉儲。缺它就開出一條「改了活動卻查不到是誰改的」的特權通路，
	// 正是審計要防的那件事，因此 New 把它列為必要依賴。
	Audits *audit.Store
	// Log 為伺服器端記錄出口；nil 時丟棄。
	Log *slog.Logger
}

// Service 是活動管理用例的入口。
type Service struct {
	db       *database.DB
	store    *Store
	accounts *account.Store
	grants   *grant.Store
	clock    timeutil.Clock
	audits   *audit.Store
	log      *slog.Logger
}

// New 裝配活動用例；缺少必要依賴時回錯誤而不是湊一個半可用的實例。
//
// 「少注入了什麼」必須在啟動階段就被說出來：一個沒有審計倉儲的活動服務能開得起來，
// 卻會把每一條寫入通路變成無痕特權變更，那比啟動失敗嚴重得多。
func New(deps Deps) (*Service, error) {
	if deps.DB == nil || deps.Audits == nil || deps.Accounts == nil || deps.Grants == nil {
		return nil, errors.New("activity: 用例缺少必要依賴（db/audits/accounts/grants）")
	}
	clock := deps.Clock
	if clock == nil {
		clock = timeutil.System()
	}
	store := deps.Store
	if store == nil {
		store = NewStore(clock)
	}
	logger := deps.Log
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{
		db: deps.DB, store: store, accounts: deps.Accounts, grants: deps.Grants,
		clock: clock, audits: deps.Audits, log: logger,
	}, nil
}

// readActivity 是詳情與各條寫入通路共用的單筆讀法：q 由呼叫端給（autocommit 連線或交易）。
//
// 倉儲的「查無此活動」在這裡換成對外的不可分辨結論：呼叫端不再需要知道
// 它是沒查到、還是查到了但不屬於你（後者由 requireActivityScope 收斂到同一個錯誤）。
func (s *Service) readActivity(ctx context.Context, q database.Querier,
	activityID idgen.ID) (Activity, error) {
	a, err := s.store.ByID(ctx, q, activityID)
	if errors.Is(err, ErrNotFound) {
		return Activity{}, ErrActivityNotFound
	}
	if err != nil {
		return Activity{}, err
	}
	return a, nil
}

// requireNotArchived 是「歸檔終態一律拒寫」這一句話唯一的判定點。
//
// 資料編輯、狀態轉換、指派與撤銷四條寫入通路問的是同一句話，判定點也只有一個
// （與 internal/adminacct 的 requireNotDeleted 同取向）。它放在作用域判定之後：
// 「你管不著這個活動」優先於「這個活動已結束」——前一句不承認這個活動存在，
// 後一句承認，順序錯了就會多出一枚可探測的信號。
func requireNotArchived(a Activity) error {
	if a.Status.Terminal() {
		return ErrArchived
	}
	return nil
}

// activityRecord 產生一筆活動域的審計記錄。
//
// actor 只能經 principal.AuditActor() 換得，換不出就讓整個動作回滾——
// 把一個換不出身分的動作記成「伺服器自己做的」，這條記錄從此失去追查價值，
// 而且看起來像有記錄（與 internal/adminacct 的 creationRecord 同一口徑）。
//
// reason 是服務端固定敘述，不接受任何主體填寫：本步沒有任何端點能把操作者的自由文字
// 塞進審計（規格 §25.1 要求 activity 域每筆都帶原因，而「原因」不該成為寫入放大器）。
// target.id 帶的是活動標識的字串形式；changes 只放欄位前後值，一個秘密都不放。
func (s *Service) activityRecord(principal identity.Principal, activityID idgen.ID,
	action, targetKind, targetID, reason, requestID string,
	changes ...audit.Change) (audit.Record, error) {
	actor, err := principal.AuditActor()
	if err != nil {
		return audit.Record{}, fmt.Errorf("activity: 主體無法換得審計操作者: %w", err)
	}
	return audit.Record{
		Scope:      audit.ScopeActivity,
		ActivityID: activityID,
		Actor:      actor,
		Action:     action,
		Target:     audit.Target{Kind: targetKind, ID: targetID},
		Reason:     reason,
		RequestID:  trimRequestID(requestID),
		Changes:    changes,
	}, nil
}

// auditChange 湊一筆前／後摘要。
//
// 存在的理由只有一個：讓各條寫入通路的 changes 形狀讀起來是同一套程式碼長出來的
// （欄位名是穩定機器碼，值一律轉成字串），於是日後要查「哪個欄位被寫過」時
// 不必在各處對不同的寫法做第二次翻譯。
func auditChange(field, before, after string) audit.Change {
	return audit.Change{Field: field, Before: before, After: after}
}
