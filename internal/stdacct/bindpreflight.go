// bindpreflight.go 是「把訪戶綁定到既有正式帳戶」的只讀預檢與衝突預覽應用服務層。
//
// 這是預覽，不是綁定：本檔案裡沒有一條寫入語句——帳戶一行不改、會話一列不撤、
// 授予一筆不動、審計一筆不記（用戶批准的 R2-018 決定：純只讀、零寫入，「必要安全
// 審計」也不寫）。它回答的問題只有一句：「若日後要把訪戶帳戶 X 綁進既有正式帳戶 Y，
// 此刻可不可行；不可行的話，是哪些事擋著」。綁定動作本身（身份合併、源帳戶退休、
// 未來歸屬轉移）屬後續執行步驟，今日不存在那顆按鈕，界面與回應都不許把它寫成可用。
//
// 與原地升級（upgrade.go）的分野是一條邊界而不是一句措辭：升級動的是訪戶自己那一行，
// 穩定標識 X 存续；綁定是把訪戶 X 併入另一個已存在的正式帳戶 Y——Y 的標識是存续身份，
// X 在執行步進入退休終態（用戶批准的留痕方向：不可登入、不可复用的退休終態，
// 需一次未來遷移，本步不落）。兩處歷史引用（審計／會話）都指向原標識，不搬不刪——
// 「綁定不重寫歷史」與升級同一口徑，差別只在「活下來的是哪一行」。
//
// 同意的來源（用戶批准的 R2-018 決定）：綁定的執行動詞屬於目標帳戶持有人 Y 本人——
// 只有 Y 以自己的已認證會話發起，才構成「目標帳戶同意」；管理員（本預檢的呼叫主體）
// 只能取得只讀預覽，永遠不能代替 Y 完成綁定。登入名相同、操作者輸入目標標識、
// 收集目標口令，都不是同意——前兩者證明的只是「操作者相信他們是同一個人」，
// 後者被明確排除。回應因此恒帶一個穩定的 consent_mode 值（target_self_initiated），
// 把這件事寫進合同而不只寫在界面文案裡：任何呼叫端都不可能把這份預覽
// 誤讀成「綁定已完成了半程」。
//
// 目標範圍與隱私邊界：來源與目標都經 readStandardProfile 讀取，所以「不在目錄」的
// 任何一方（不存在／幽靈／持有伺服器級授予的管理員／待審批鏈）一律收斂成
// 同一句不可分辨的 ErrAccountNotFound——與詳情端點逐字同形，預檢因此不新增任何
// 枚舉信號；目錄內的事實（訪戶或正式、可用、停用，以及已刪除與已退休這兩種終態）
// 本來就對本目錄的操作者可見，預覽的阻止原因不是新的披露面：兩種終態走得是
// 「非可登入狀態」那條 blocker，而不是另一套拒絕語意。本端點一次只吃一對（來源, 目標）：沒有任何
// 「替這個訪戶列出可綁定目標」的讀法，請求形態本身就是反枚舉邊界。
//
// 引用登記表與未知引用阻止（AGENTS §7：歷史身分保留與跨活動隔離是領域要求）：
// 本部署目前實際引用帳戶標識的表只有——
//   - sessions（硬外鍵）：執行時與綁定同交易撤銷，與升級同一手段；
//   - account_server_roles（硬外鍵）：訪戶的行集按遷移 0006 的觸發器恆空，
//     預檢現讀復核一次，查得有任一授予即判形態缺陷並阻止（source_has_grants）；
//   - guest_bind_tickets（硬外鍵，三個標識欄）：綁定憑證，承載的是「准了這一對」的
//     授權痕跡，不是待搬遷的歸屬；
//   - guest_account_bindings（硬外鍵，兩個標識欄）：綁定的不可變留痕，本身就是「留痕」
//     而不是衝突；
//   - root_audit／activity_audit（無外鍵的軟參照、只追加）：歷史指向原標識，
//     原樣保留，既不搬也不改寫，因此不構成衝突——它們是「留痕」本身，
//     不是「待搬遷的引用」。
//
// 其餘現存的表（server_settings、策略單例、邀請碼、幾支遷移的守衛表）不引用帳戶。
// 這份登記表就是綁定通路能宣稱的全部覆蓋範圍——所以判定不用碼內寫死的靜態清單交差了事：
// 每次運行都現掃實庫的外鍵邊（sqlite_master＋PRAGMA foreign_key_list），只要存在
// 一張引用 accounts 而不在登記表上的表（未來活動、帳本、NPC 模組新加的表），
// 整體收斂成阻止原因 unknown_references：評估不了的引用就拒絕，
// 絕不靜默合併權限或資產，也絕不假裝看不見。未來模組必須先把自己的引用
// 接入這份登記表（與那時的執行通路一起），綁定才重新被允許。
//
// 數據版本：結論帶實庫當前的 schema 版本（migrate.Current 這一處唯一實作點讀取）。
// 這句話告訴呼叫端「這份判定是按哪一版本的登記表跑的」；預覽天生就是會過期的快照，
// 而寫入通路（見 bindissue.go 與 bindclaim.go）在寫之前必須重讀版本與全部可觀測事實
// 並重新判定——那是那兩條通路的職責，本檔案这一條不負責把預覽鎖成憑證，
// 也不提供把預覽當依據的任何通路（零寫入、零落庫憑據）。
package stdacct

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/grant"
	"github.com/kagurazakayashi/EvernightRealm/internal/guestbind"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// BindBlocker 是預覽回給界面的穩定阻止原因記號：機器可判別、四語言文案由界面側
// （Flutter ARB）落地，後端不產句子——與目錄回應只帶事實欄位、不帶本地化散文的
// 既有口徑一致。枚舉值只增不刪；界面對認不得的記號顯示通用句而不是崩潰，
// 這是 API「只增不刪」相容演進的既有策略。
type BindBlocker string

const (
	// BindBlockerSameAccount 表示來源與目標是同一行：那句話本身就是病——
	// 「把訪戶併入他自己」沒有任何可發生的動作。命中這條時其餘按帳戶形態的檢查
	// 一概不再追加（兩側讀的是同一行，堆疊出的原因句只會誤導）。
	BindBlockerSameAccount BindBlocker = "same_source_target"
	// BindBlockerSourceNotGuest 表示來源此刻不是訪戶：他已被就地升級、或未來
	// 已綁定並進入退休終態——綁定的主詞只能落在 account_type='guest' 那行人身上。
	// 這同時就是「已綁定過的訪戶不得再綁第二次」的檢測形態（退休之後他不再是 guest）。
	BindBlockerSourceNotGuest BindBlocker = "source_not_guest"
	// BindBlockerSourceNotActive 表示來源訪戶此刻不是一個可登入的帳戶：被停用，
	// 或已進入刪除／綁定退休的終態。綁定不該順帶復活誰（與升級同一口徑：
	// 停用的處置是先恢復登入或讓那趟臨時身分自然到期，而終態沒有回去的路）。
	BindBlockerSourceNotActive BindBlocker = "source_not_active"
	// BindBlockerSourceHasGrants 表示來源這行人名下查得有伺服器級授予——訪戶帶授予
	// 按遷移 0006 的觸發器在本來形態下不可能出生，查到即是外部改壞庫的缺陷形態；
	// 預檢在這裡拒絕而不是假裝沒看見，守的是「不靜默合併權限」那句話。
	BindBlockerSourceHasGrants BindBlocker = "source_has_grants"
	// BindBlockerTargetNotStandard 表示目標此刻是訪戶：訪戶併訪戶沒有承接受方——
	// 綁定推薦方向是受控的「訪戶→普通正式帳戶」，兩個臨時身分相加還是臨時身分。
	// （持有伺服器級授予的目標到不了這裡：readStandardProfile 已把管理員收進
	// 「不在目錄」那句不可分辨的話，這是刻意設計，不是漏判。）
	BindBlockerTargetNotStandard BindBlocker = "target_not_standard"
	// BindBlockerTargetNotActive 表示目標此刻不是一個可登入的正式帳戶（被停用，
	// 或已進入刪除終態）：一個登不進門的人
	// 沒有能力在自己的會話裡完成「確認並接受綁定」那一步（同意的來源見檔案頭注），
	// 所以這樣的目標對綁定不是候選——停用的處置是先恢復他的登入能力，
	// 而刪除是終態，沒有任何通路能把他帶回門內（那一對必須換一個承接受方）。
	BindBlockerTargetNotActive BindBlocker = "target_not_active"
	// BindBlockerUnknownReferences 表示這個庫裡存在引用帳戶、而本預檢尚未登記如何
	// 處置的表：它的行可能承載評估不了的歸屬（未來的活動名冊、資產所有權、NPC 關係），
	// 綁定會被整體阻止。表名只進執行日誌、不進回應——那句话對操作者的意義是
	// 「等對應模組接入預檢」，不是「數一數有幾張表」。
	BindBlockerUnknownReferences BindBlocker = "unknown_references"
)

// String 回傳阻止原因的機器表示。
func (b BindBlocker) String() string { return string(b) }

// BindImpact 是「可行時綁定將會產生的影響」的穩定記號，只在 executable 為真時出現：
// 不可行的綁定什麼影響都不會產生，那時候回應裡只有阻止原因。界面把每個記號唸成
// 四語言的一句人話；記號集合只增不刪，認不得的記號顯示通用句。
type BindImpact string

const (
	// BindImpactRevokesSourceSessions 表示執行時來源名下尚未撤銷的會話將與綁定
	// 同交易全部撤銷（與升級、停用同一手段）；數量在 source_open_sessions 老實報出。
	BindImpactRevokesSourceSessions BindImpact = "revoke_source_sessions"
	// BindImpactRetiresSource 表示來源訪戶那一行將進入退休終態：不可登入、
	// 不可複用、不復原（用戶批准的留痕方向；終態的落庫形態屬執行步的遷移）。
	BindImpactRetiresSource BindImpact = "retire_source_account"
	// BindImpactKeepsHistory 表示既有歷史引用（審計的 actor／target 標識等）
	// 逐字保留：綁定不重寫任何人過去的行動記錄，兩段歷史各自指向發生時的標識。
	BindImpactKeepsHistory BindImpact = "keep_history_references"
	// BindImpactMovesFutureAttribution 表示「此後」的身分歸屬將落在目標 Y 的
	// 穩定標識上：未來的 Membership／Profile 只認 Y，X 不再是任何未來事實的主詞。
	// 活動模組尚未開發——這句是執行步必須遵守的合同，不是本步能驗證的事。
	BindImpactMovesFutureAttribution BindImpact = "transfer_future_attribution"
	// BindImpactTargetShapeUnchanged 表示目標 Y 的憑據、狀態、授予與顯示名一概不動：
	// 綁定搬的是歸屬，不是把 Y 改造成別的主體——「訪戶經綁定獲得權限」在這個
	// 影響清單裡找不到格子，正是要它找不到的意思。
	BindImpactTargetShapeUnchanged BindImpact = "target_unchanged"
)

// String 回傳影響記號的機器表示。
func (i BindImpact) String() string { return string(i) }

// BindConsentModeTargetSelfInitiated 是唯一已批准的同意形態：綁定只能由目標帳戶
// 持有人以自己的已認證會話發起。它寫在回應的 consent_mode 欄裡（恆為此值），
// 因為「誰有資格按下執行」是合同的一部分，不是界面文案的修辭。
//
// 字面值的權威在 internal/guestbind（那裡它是落庫 CHECK 的封閉集合），
// 這裡只是同一個值的對外名字——兩處各拼一次字串，遲早有一處拼錯而另一處不知道。
const BindConsentModeTargetSelfInitiated = guestbind.ConsentModeTargetSelfInitiated

// bindKnownAccountReferences 是硬引用（外鍵指向 accounts(id)）的處置登記表：
// 表名 → 處置一句。登記表外的引用表一律觸發 unknown_references（見檔案頭注）。
// root_audit／activity_audit 不在這裡——它們是無外鍵的軟參照，掃描根本看不見它們，
// 由「歷史只追加、原樣保留」的頭注句子處置，永不構成阻止。
var bindKnownAccountReferences = map[string]string{
	"sessions":             "綁定執行時與綁定同交易撤銷（RevokeAccount 手段，與升級同源）",
	"account_server_roles": "訪戶行集按遷移 0006 觸發器恆空；預檢現讀復核，非空即 source_has_grants",
	// 遷移 0011 建的兩張表是綁定通路自己的介質與留痕，必須同批登記：
	// 漏登記的后果不是「少一句說明」，而是預檢從此把自己的表讀成未知引用、
	// 把整條綁定通路永久封死（fail-closed 的方向是對的，但那會是一個自己造出來的死鎖）。
	"guest_bind_tickets": "簽發後短效、限定這一對、只准核銷一次的憑證：核銷時同交易標記 consumed_at，" +
		"未核銷者到期即失效；它承載的是「准了這一對」的授權痕跡，不是待搬遷的歸屬",
	"guest_account_bindings": "綁定的不可變留痕（只追加）：來源標識存續、指向原行，" +
		"既有歷史從不被改寫成「從來都是目標帳戶」；source 欄的 UNIQUE 是「一個訪戶只被綁走一次」的結構保證",
}

// bindTableIdentifier 是能把表名安全拼進 PRAGMA 的形狀閘。sqlite_master 裡的表名
// 由資料庫自己報告，正常永遠過閘；過不了閘的名字代表這庫被外部工具動出了
// 拼不出查詢的形態——那種表按「評估不了」處理（失敗即阻止方向），不跳過。
var bindTableIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// GuestBindPreflight 是一次綁定預檢的完整結論：兩側的最小資料、可執行性、
// 阻止原因、將產生的影響、源會話計數與這份快照運行的資料版本。
//
// 沒有、也不可能有的一欄是「綁定完成的憑據」：本用例零寫入，產不出任何生效中的東西。
// 兩側 Profile 沿用目錄詳情的同一個可展示形狀（StandardProfile）：預覽不披露
// 目錄本來看不到的任何欄位，憑據材料更是從形狀上就放不進來。
type GuestBindPreflight struct {
	// Source 為來源訪戶經實體校驗的單筆資料。
	Source StandardProfile
	// Target 為目標帳戶經實體校驗的單筆資料。
	Target StandardProfile
	// Executable 表示此刻是否存在一條可安全執行的綁定：所有阻止原因清空才為真。
	// 它是「預覽可執行」，不是「已執行」，更不是綁定的憑據或許可。
	Executable bool
	// Blockers 為全部適用原因的穩定記號（可執行時為空切片，不是 nil 冒充缺欄）。
	Blockers []BindBlocker
	// Impacts 為可執行時將產生的影響記號；不可執行時恆為空——不會發生的動作
	// 沒有任何「將產生的影響」可報。
	Impacts []BindImpact
	// SourceOpenSessions 為來源名下尚未撤銷的會話數（RevokeAccount 的同一把尺）：
	// 「綁定將讓 N 臺裝置重新登入」那句的依據。0 是事實，不是失敗。
	SourceOpenSessions int
	// SchemaVersion 為這份預覽運行時的實庫 schema 版本：引用登記表覆盖面隨版本變，
	// 執行步必須復核這個版本與全部事實，預覽本身不具持久效力。
	SchemaVersion int
	// ConsentMode 恆為 BindConsentModeTargetSelfInitiated：同意只能由目標本人給。
	ConsentMode string
}

// PreflightGuestBind 以持有伺服器級管理權的受信主體，對一對（來源, 目標）帳戶標識
// 做只讀的綁定預檢與衝突預覽；本次調用不寫下任何一行資料。
//
// 步驟與每一跳的理由（全部讀取走 autocommit 快照，不進交易——BEGIN IMMEDIATE 是
// 寫交易的邊界，為一次預覽去排單寫入者的鎖是把「讀」當「寫」用）：
//  1. 授權先於一切（NeedServerAdmin，與建號、目錄、編輯、停用、重置、升級同一道閘）：
//     匿名 2002 族、訪戶本人与普通帳戶 2011 都是既有授權矩陣的事實，本用例不新造規則；
//  2. 零值標識不進資料庫也不分句：與其餘通路「不在目錄」同一句話；
//  3. 其餘判定全部在 evaluateBindPlan 裡，與簽發／核銷那兩條通路共用同一份實作——
//     「預覽說可行」與「執行時重讀到的可行性」必須是同一句話，不是兩套規則裡恰好写得像的兩句。
func (s *Service) PreflightGuestBind(ctx context.Context, principal identity.Principal,
	sourceID, targetID idgen.ID, requestID string) (GuestBindPreflight, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		s.log.Warn("綁定預檢被拒：主體不具備伺服器級管理權",
			"subject", principal.String(), "request_id", requestID)
		return GuestBindPreflight{}, err
	}
	if sourceID.IsNil() || targetID.IsNil() {
		// 零值標識不進資料庫也不分句：與其餘通路「不在目錄」同一句話。
		return GuestBindPreflight{}, ErrAccountNotFound
	}

	// 本條路徑是純預覽：走 autocommit 快照、零交易、零寫入。
	plan, unknownRefs, err := s.evaluateBindPlan(ctx, s.db.SQL(), sourceID, targetID)
	if err != nil {
		return GuestBindPreflight{}, err
	}
	// 未知引用的表名只進執行日誌：回應給操作者的意義是「有模組還沒接入預檢」，
	// 數表名既幫不上處置，也不是這條通路該出口的細節。
	if len(unknownRefs) > 0 {
		s.log.Warn("綁定預檢發現未接入登記表的帳戶引用表",
			"tables", fmt.Sprint(unknownRefs), "request_id", requestID)
	}
	s.log.Info("已完成訪戶綁定預檢（只讀，未綁定）",
		"source", sourceID.String(), "target", targetID.String(),
		"executable", plan.Executable, "request_id", requestID)
	return plan, nil
}

// evaluateBindPlan 是對一對（來源, 目標）綁定可行性的唯一判定實作：
// 只讀預檢、憑證簽發與憑證核銷三條通路都經它在「各自那一刻」取得結論。
//
// q 由呼叫端給（autocommit 連線或交易）：這正是三條通路共用同一份判定而不各寫一套的條件——
// 預覽用 autocommit，簽發與核銷用它們各自的寫交易，判定內容逐字相同、讀到的時代不同。
// 回傳的第二個值是未接入登記表的引用表名清單（只供日誌與摘要，不進回應），
// 錯誤只可能是被分過類的結論（ErrAccountNotFound 一族）或內部故障。
//
// 判定順序與每一跳的理由：
//  1. 兩側經 readStandardProfile 讀取：不在目錄的一方（不存在／幽靈／管理員／
//     待審批鏈）讓整個預檢以不可分辨的 ErrAccountNotFound 收場——與詳情端點
//     同形，預覽不是新的枚舉面；已刪除與已退休在這本目錄的讀取範圍之內，
//     他們在第 3 步以非可登入狀態被擋，而不是在第 1 步假裝查無此人；
//     （第 3 步那一支判定的取值見下方 blocker 常數：兩種終態都落在 not_active 那一句，
//     因為綁定要問的是「他現在還登不登得進來」，而 deleting 與 retired 都答「不了」。）
//  2. 現掃實庫外鍵邊（findUnregisteredAccountReferences）：登記表外的任何帳戶引用表
//     記一條 unknown_references，並將本對綁定整體阻止；
//  3. 形態與歸屬判定：同對／非訪戶來源／來源非可登入狀態（停用、已刪除或已退休）／
//     帶授予的來源／訪戶目標／目標非可登入狀態（停用或已刪除）——
//     每一條都是「此刻的安全邊界」，不是一個可以繞過的建議；
//  4. 源會話計數與 schema 版本讀取：結論要如實說出影響範圍和這份快照的時代背景；
//  5. 組裝：blockers 清空才 executable，可執行才帶 impacts。
func (s *Service) evaluateBindPlan(ctx context.Context, q database.Querier,
	sourceID, targetID idgen.ID) (GuestBindPreflight, []string, error) {
	source, err := s.readStandardProfile(ctx, q, sourceID)
	if err != nil {
		return GuestBindPreflight{}, nil, classifyBindPreflightRead(err)
	}
	target, err := s.readStandardProfile(ctx, q, targetID)
	if err != nil {
		return GuestBindPreflight{}, nil, classifyBindPreflightRead(err)
	}
	unknownRefs, err := s.findUnregisteredAccountReferences(ctx, q)
	if err != nil {
		return GuestBindPreflight{}, nil, fmt.Errorf("stdacct: 綁定預檢掃描帳戶引用失敗: %w", err)
	}
	openSessions, err := s.sessions.OpenAccountSessionCount(ctx, q, sourceID)
	if err != nil {
		return GuestBindPreflight{}, nil, fmt.Errorf("stdacct: 綁定預檢統計源會話失敗: %w", err)
	}
	// 版本讀取複用 migrate.Current——「這個庫跑到哪一版」在整個倉庫只有那一個實作點；
	// 在這裡自己抄一句 SELECT MAX(version) 就是養出第二個真相。
	// 取 autocommit 連線而不是呼叫端那條 q：migrate.Current 的簽名要的是 *sql.DB，
	// 而這個讀取在交易內也安全——遷移自己必須拿一條寫交易才能推進版本，
	// 而 SQLite 只有一個寫入者，本交易進行期間版本不可能改變。
	schemaVersion, err := migrate.Current(ctx, s.db.SQL())
	if err != nil {
		return GuestBindPreflight{}, nil, fmt.Errorf("stdacct: 綁定預檢讀取資料庫版本失敗: %w", err)
	}

	result := GuestBindPreflight{
		Source:             source,
		Target:             target,
		Blockers:           []BindBlocker{},
		Impacts:            []BindImpact{},
		SourceOpenSessions: openSessions,
		SchemaVersion:      schemaVersion,
		ConsentMode:        BindConsentModeTargetSelfInitiated,
	}

	// 同對短路：來源與目標讀的是同一行，再按兩側形態堆原因句只會製造噪音
	// （一個 guest 的「同對」預覽同時說「目標不是正式帳戶」是精確的廢話）。
	if sourceID == targetID {
		result.Blockers = append(result.Blockers, BindBlockerSameAccount)
		return result, unknownRefs, nil
	}

	// 來源側：綁定的主詞只能是「此刻是訪戶且可登入且名下沒有評估不了的授予」的這行人。
	if source.Type != account.TypeGuest {
		result.Blockers = append(result.Blockers, BindBlockerSourceNotGuest)
	} else {
		if source.Status != account.StatusActive {
			result.Blockers = append(result.Blockers, BindBlockerSourceNotActive)
		}
		// 授予復核讀 grant 倉儲的公開讀法（授予的權威只在那裡，本套件不抄 SQL）。
		// Roles() 對壞值（認不得的角色字串）失敗即整次判定失敗：那是「評估不了」，
		// 絕不能降級成「他沒有授予」放行綁定——靜默放行才是這條通路最壞的結局。
		roles, err := s.grants.Roles(ctx, q, sourceID)
		if err != nil {
			return GuestBindPreflight{}, nil, fmt.Errorf("stdacct: 綁定預檢復核來源授予失敗: %w", err)
		}
		if roles.Count() > 0 {
			result.Blockers = append(result.Blockers, BindBlockerSourceHasGrants)
		}
	}

	// 目標側：承接受方必須是「此刻是普通正式帳戶且可登入」的這行人。管理員與待審批者
	// 到不了這裡（已在範圍檢查收進 1001 那句），所以這裡不需要、也不應該
	// 再判一次「他是不是特權帳戶」——那句话早已是一句不可分辨的「不在目錄」。
	// 已刪除的目標會走到這裡，由下面那一支 Status != active 的判定擋住：刪除是終態，
	// 「先恢復他的登入能力再綁」對他不是處置，而界面早在讀回的 status 上就把這條
	// 通路收起了——這一格擋的是繞過界面的直打與併發尾巴。
	if target.Type != account.TypeStandard {
		result.Blockers = append(result.Blockers, BindBlockerTargetNotStandard)
	} else if target.Status != account.StatusActive {
		result.Blockers = append(result.Blockers, BindBlockerTargetNotActive)
	}

	// 未知引用最後追加：它是對「本判定自己的認知邊界」的判定，優先級上與形態原因
	// 平級並列，但處置完全不同——形態原因有重讀後再試的通路，未知引用要等的是
	// 未來模組把自己接入登記表，催誰重試都沒用。記號只出現一次：表名不進結論。
	if len(unknownRefs) > 0 {
		result.Blockers = append(result.Blockers, BindBlockerUnknownReferences)
	}

	result.Executable = len(result.Blockers) == 0
	if result.Executable {
		result.Impacts = []BindImpact{
			BindImpactRevokesSourceSessions,
			BindImpactRetiresSource,
			BindImpactKeepsHistory,
			BindImpactMovesFutureAttribution,
			BindImpactTargetShapeUnchanged,
		}
	}
	return result, unknownRefs, nil
}

// classifyBindPreflightRead 把 readStandardProfile 的失敗收斂成預檢對外的可判別結論。
// 口徑與詳情、編輯、停用、重置、升級逐字同源：帳戶不存在與授予倉儲查無收斂成
// 同一句 ErrAccountNotFound，其餘原樣上拋交裝配外層報缺陷——預覽不是第六套說法。
func classifyBindPreflightRead(err error) error {
	switch {
	case errors.Is(err, account.ErrNotFound), errors.Is(err, grant.ErrNotFound),
		errors.Is(err, ErrAccountNotFound):
		return ErrAccountNotFound
	default:
		return err
	}
}

// findUnregisteredAccountReferences 現掃實庫，回報「外鍵指向 accounts(id)、
// 卻不在處置登記表上」的表名集合（按名字典序）。
//
// 為什麼掃庫而不是數碼內清單：碼內的清單只能證明「寫清單的人想到了什麼」，
// 而本條規矩要防的恰恰是「日後有人加了預檢沒想到的引用」。只有問資料庫本身，
// 新表落地的那一天預檢才會自己變紅，而不是依賴那個人還記得回來改這份清單——
// 他若不記得，綁定會被 unknown_references 擋住而不是靜默出錯，方向保守一致。
//
// 讀取失敗一律上拋（呼叫端收斂為整次預檢失敗）：查不成就是評估不了，
// 評估不了就不能說「可行」。
func (s *Service) findUnregisteredAccountReferences(ctx context.Context,
	q database.Querier) ([]string, error) {
	if q == nil {
		return nil, errors.New("stdacct: 綁定預檢缺少資料庫連線或交易")
	}
	rows, err := q.QueryContext(ctx,
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("stdacct: 列舉資料庫表失敗: %w", err)
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, fmt.Errorf("stdacct: 讀取資料庫表清單失敗: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("stdacct: 讀取資料庫表清單失敗: %w", err)
	}
	rows.Close()

	var unknown []string
	for _, name := range names {
		// accounts 自己不算「引用帳戶的表」；登記表內的表由處置合同覆蓋，不必再問外鍵。
		if name == "accounts" {
			continue
		}
		if _, known := bindKnownAccountReferences[name]; known {
			continue
		}
		// 名字過不了形狀閘的表：拼不出 PRAGMA 就評估不了，按未知引用方向收斂（不跳過）。
		if !bindTableIdentifier.MatchString(name) {
			unknown = append(unknown, name)
			continue
		}
		referencesAccounts, err := tableReferencesAccounts(ctx, q, name)
		if err != nil {
			return nil, err
		}
		if referencesAccounts {
			unknown = append(unknown, name)
		}
	}
	return unknown, nil
}

// tableReferencesAccounts 回報一張表是否帶有指向 accounts(id) 的外鍵。
//
// 表名已由呼叫端過形狀閘，拼進 PRAGMA 的雙引號識別符沒有注入面；
// PRAGMA 的結果列（id, seq, table, from, to, on_update, on_delete, match）是 SQLite
// 的穩定協議，to 在隱式參照主鍵時可能為 NULL，因此掃成可空值再比較。
func tableReferencesAccounts(ctx context.Context, q database.Querier, table string) (bool, error) {
	rows, err := q.QueryContext(ctx, `PRAGMA foreign_key_list("`+table+`")`)
	if err != nil {
		return false, fmt.Errorf("stdacct: 讀取表 %s 的外鍵失敗: %w", table, err)
	}
	defer rows.Close()

	var (
		fkID, seq          int
		referenced         string
		fromCol, toCol     sql.NullString
		onUpdate, onDelete string
		match              string
	)
	found := false
	for rows.Next() {
		if err := rows.Scan(&fkID, &seq, &referenced, &fromCol, &toCol,
			&onUpdate, &onDelete, &match); err != nil {
			return false, fmt.Errorf("stdacct: 解析表 %s 的外鍵列失敗: %w", table, err)
		}
		if referenced != "accounts" {
			continue
		}
		// to 為 NULL 是「參照 accounts 的隱式主鍵」——主鍵就是 id，同一回事。
		if !toCol.Valid || toCol.String == "id" {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("stdacct: 讀取表 %s 的外鍵失敗: %w", table, err)
	}
	return found, nil
}
