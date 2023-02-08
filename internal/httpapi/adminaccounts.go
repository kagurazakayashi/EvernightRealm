// adminaccounts.go 是「伺服器級管理員打理普通帳戶」的傳輸層落點：
// /admin/accounts 一個路徑做兩件事（GET／HEAD 分頁目錄、POST 建立），
// /admin/accounts/{account_id} 一個路徑做兩件事（GET／HEAD 單筆詳情、PUT 編輯非安全資料），
// /admin/accounts/{account_id}/status 一條路徑做一件事（PUT 停用或恢復登入能力），
// /admin/accounts/{account_id}/password 一條路徑做一件事（PUT 重置登入憑據，
// 唯一白名單欄位是新口令）。
//
// 這個檔案刻意只做協定層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 consolePrincipal 那條共用鏈，
//     不在這裡重寫一份「先看 Cookie 再看標頭」的順序；
//  2. 首次改密門閂——同一條鏈上的 requirePasswordChangeDone，與其餘受保護端點同一把閘；
//  3. 請求本體與查詢參數的形態——建立只有 login_name／display_name／password，
//     編輯只有 display_name 與它所依據的現值，
//     狀態只有 status 與它所依據的現狀，重置只有 password 一欄，
//     目錄只認 page／page_size／status／type／q 五個查詢參數；
//     未知欄位（含 role、account_type、status、subject_kind、must_change_password
//     這類「自報身分或企圖覆蓋隱藏欄位」的嘗試）由 decodeJSON 的 DisallowUnknownFields
//     當場拒殺：「動的是哪一類資料」由「打的哪個端點、用的哪個方法」決定，
//     不是由請求內容決定；「哪個活動」更是連格子都沒有——
//     普通帳戶目錄不屬於任何活動，也塞不進任何活動；
//  4. 結論對映——把用例回傳的可判別錯誤一一映射到機器碼，其餘一律 500 且細節只進日誌。
//     這組端點用到的碼：1001（不在這本目錄裡）、1004（改寫法）、2011（換身分也沒用）、
//     2012（那個名字是別人的）、2013（你看見的現值已過期）、2014（他的可用性已不是你確認時那樣）、
//     2017（策略此刻不放開這條建號通路）、2018（他是訪戶，沒有可重置的憑據）。
//     其中只有 2018 是本步新發布的一枚：它說的是「要等後續那條明確的訪戶升級通路」，
//     與改寫法（1004）、換目標（1001）、換身分（2011）都不是同一處置。
//
// 與 /root/admins 的分工是一條邊界而不是一個目錄慣例：那組端點管的是「持有伺服器級
// 角色的主體」，經 NeedRoot 判定、不受三個建立開關約束；這組端點管的是「不帶任何
// 伺服器級授予的普通與訪戶帳戶」，經 NeedServerAdmin 判定，而建號這一條另受
// admin_create_standard 約束且對所有主體一視同仁（Root 走這條路同樣被關擋）。
// 憑據重置不受那三個開關約束：開關管的是「准不准多出一筆帳戶」，
// 而重置動的是一筆已存在帳戶的口令，把它掛在建號開關下等於讓「關掉建號」
// 順帶剝奪管理員恢復他人登入能力的手段。
// 兩組端點各自把「誰能碰哪一類人」答完整，也不合成第三份意思：
// 普通帳戶目錄把持有授予的人排掉（包括敲這條端點的操作者自己），
// Root 的管理員目錄則只列持有授予的人。
//
// 開關不預讀：這裡沒有「先問一次能不能建」的端點，策略現值只有 Root 讀得到；
// 管理員表單照常提交，開著就建、關著就收 2017 那一句。判定只發生在用例的交易內
// 現讀那一刻，界面預讀與否都改不了這個事實，多一個讀端點只是多一張會過期的答案。
//
// 回應本體絕不含口令明文、憑據雜湊、會話材料或任何內部正規化鍵；也刻意不帶 roles
// 欄位——本目錄的定義就是「沒有伺服器級授予」，回應不描述一件不存在的事，
// 免得界面把「沒有這一行」讀成「查不到」。同理也沒有 activity、資產、訊息任何一欄：
// 那些模組尚未實作，這裡不拿空陣列或 0 冒充一份查得到的真相。
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/stdacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// StdAccountUseCase 是「管理員打理普通帳戶」用例在傳輸層的入口形態
// （由 internal/app 注入 *stdacct.Service）。
//
// 與 Deps.Admins、Deps.AccountPolicy 分開一個介面、分開一個 Deps 欄位，理由同前兩步：
// 「裝配了什麼就服務什麼」——沒注入本用例的執行檔一個 /admin/accounts 端點都不掛。
//
// principal 一律是「本次請求的憑據剛換出的受信主體」；授權（NeedServerAdmin）、
// 策略現讀與放行合成、目錄與單筆的範圍核實都在用例裡判，不在傳輸層先判一次——
// 兩處各判一套的結局是其中一套被繞過。
type StdAccountUseCase interface {
	// CreateStandardAccount 以持有伺服器級管理權的受信主體建立一個普通帳戶。
	// 策略開關在建立交易的同一快照上現讀復核，關閉時整筆不發生並回
	// stdacct.ErrCreateDisabled。
	CreateStandardAccount(ctx context.Context, principal identity.Principal,
		in stdacct.CreateInput, requestID string) (stdacct.CreatedAccount, error)
	// Directory 以當前受信主體分頁列舉普通帳戶目錄（含名稱、來源與狀態篩選及總數）。
	// 「某一筆列不列得進來」由用例的範圍規則回答（排除持有伺服器級授予者與刪除終態），
	// 傳輸層只負責把五個查詢參數原樣遞進去，不在這裡判一次篩選語意。
	Directory(ctx context.Context, principal identity.Principal,
		q stdacct.DirectoryQuery) (stdacct.DirectoryPage, error)
	// StandardAccountProfile 讀回單筆普通帳戶詳情（經帳戶實體校驗的當前資料）。
	StandardAccountProfile(ctx context.Context, principal identity.Principal,
		accountID idgen.ID) (stdacct.StandardProfile, error)
	// UpdateStandardAccountProfile 以白名單編輯一名普通帳戶的顯示名；
	// expectedDisplayName 是呼叫端提交所依據的現值，兩者不符時整個編輯不發生
	// 並回可判別的衝突結論。
	UpdateStandardAccountProfile(ctx context.Context, principal identity.Principal,
		accountID idgen.ID, displayName, expectedDisplayName, requestID string) (stdacct.StandardProfile, error)
	// UpdateStandardAccountStatus 停用或恢復一名目錄內普通帳戶的伺服器級登入能力；
	// expectedStatus 是呼叫端提交所依據的現狀，現狀已變時整個操作不發生
	// （狀態沒改、會話沒撤、審計沒記）並回可判別的衝突結論。
	// 撤銷目標既有會話與狀態寫入落在同一個交易，見 internal/stdacct/status.go。
	UpdateStandardAccountStatus(ctx context.Context, principal identity.Principal,
		accountID idgen.ID, in stdacct.StatusChangeInput,
		requestID string) (stdacct.StatusChange, error)
	// ResetStandardAccountPassword 重置一名目錄內普通帳戶的登入憑據：舊口令與既有會話
	// 同交易失效、首次改密義務重設、停用與刪除狀態不動。
	// 刻意不設依據值（操作者拿不出「現行哈希」那類誠實錨點），因此沒有 2013/2014
	// 那樣的併發結論——重複提交是又做了一次完整重置，見 internal/stdacct/resetpassword.go。
	ResetStandardAccountPassword(ctx context.Context, principal identity.Principal,
		accountID idgen.ID, newPassword, requestID string) (stdacct.StandardPasswordReset, error)
}

// createStandardAccountRequest 是建立請求的本體。只有這三個欄位可用：
// 「角色」「帳戶類型」「審批狀態」「活動標識」之類的宣稱會被未知欄位規則當場拒殺
// （回 1004），因此「普通帳戶把自己建成管理員」在協定層就沒有一個可以填的格子。
type createStandardAccountRequest struct {
	LoginName   string `json:"login_name"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

// updateStandardAccountProfileRequest 是編輯請求的本體。白名單只有顯示名一欄，
// 外加它所依據的現值：status／must_change_password／account_type／password／login_name
// 與 roles、activity_id 這些隱藏或身分欄位在本體裡沒有格子可填（未知欄位 1004），
// 「保存普通資料順手把旗標清了」在協定層就沒有發生點。
type updateStandardAccountProfileRequest struct {
	DisplayName         string `json:"display_name"`
	ExpectedDisplayName string `json:"expected_display_name"`
}

// updateStandardAccountStatusRequest 是停用／恢復請求的本體。白名單只有狀態一欄，
// 外加它所依據的現狀：這兩欄是 /status 子資源特有的，父路徑那份編輯白名單不認它們，
// 反之本體也不能帶 display_name／password／must_change_password 之類的欄位（未知欄位 1004）。
type updateStandardAccountStatusRequest struct {
	Status         string `json:"status"`
	ExpectedStatus string `json:"expected_status"`
}

// resetStandardAccountPasswordRequest 是重置憑據請求的本體。白名單只有新口令一欄：
// 沒有 expected_*、沒有 status、沒有 must_change_password——前兩者是別的白名單通路
// 的欄位（未知欄位 1004），第三者是本次重置要「強制寫成 1」的義務旗標，
// 絕無可能被請求反向清掉（「重置不順手免義務」成立在本體連格子都沒有的形狀上）。
// 它也絕不是「自報身分」的格子：account_id 在路徑上、roles 與 activity_id 不認。
type resetStandardAccountPasswordRequest struct {
	Password string `json:"password"`
}

// createdStandardAccountResponse 是建立成功的回應本體。
//
// 全部為可展示事實；刻意缺席的：初始口令（連同它的任何前綴或長度）、Argon2id 雜湊、
// 新帳戶的會話材料、roles 欄位（見檔案頭注）。must_change_password 恆為 true，
// 讓界面能把「這個口令只用一次」講給操作者聽；account_id 是穩定標識，
// 而「已建立」不等於「已加入活動」——回應裡沒有任何活動欄位可被誤讀。
type createdStandardAccountResponse struct {
	AccountID          string `json:"account_id"`
	LoginName          string `json:"login_name"`
	DisplayName        string `json:"display_name"`
	Status             string `json:"status"`
	MustChangePassword bool   `json:"must_change_password"`
	CreatedAt          string `json:"created_at"`
	RequestID          string `json:"request_id"`
}

// standardAccountItem 是目錄行與單筆詳情共用的形狀（同一筆資料在不同回應裡的形狀必須同源）。
//
// 與管理員那一個的兩處差異都是事實差：沒有的 granted_at（普通帳戶沒有授予可言）、
// 多有的 account_type（他是普通帳戶還是訪戶帳戶，是本目錄必須講清楚的來源）。
// disabled_at 只可能在單筆回應裡出現（目錄行不帶，與 /root/admins 同一分工）：
// 目錄要答的是「他在不在、是哪一類、能不能登入」，「何時被停的」屬於那一筆的細節。
type standardAccountItem struct {
	AccountID          string `json:"account_id"`
	LoginName          string `json:"login_name"`
	DisplayName        string `json:"display_name"`
	AccountType        string `json:"account_type"`
	Status             string `json:"status"`
	MustChangePassword bool   `json:"must_change_password"`
	CreatedAt          string `json:"created_at"`
	// LastLoginAt 為最近一次登入時刻；從未登入時欄位缺席（不拿建立時刻冒充）。
	LastLoginAt string `json:"last_login_at,omitempty"`
	// DisabledAt 為進入禁用狀態的時刻；可用狀態時欄位缺席（不拿零值冒充「停過」）。
	// 與 /root/admins 同一分工：只可能在單筆回應裡出現，目錄行不帶。
	DisabledAt string `json:"disabled_at,omitempty"`
}

// standardAccountListResponse 是 GET／HEAD /admin/accounts 的回應本體。
//
// 分頁三元組回顯「你問的是哪一頁、一頁多大、總共幾筆」：客戶端據此算頁數與
// 標空狀態，不需要（也不准）自己拿行數猜。accounts 恆為數組，空頁是 []。
type standardAccountListResponse struct {
	Accounts  []standardAccountItem `json:"accounts"`
	Page      int64                 `json:"page"`
	PageSize  int64                 `json:"page_size"`
	Total     int64                 `json:"total"`
	RequestID string                `json:"request_id"`
}

// standardAccountProfileResponse 是 GET／PUT /admin/accounts/{account_id} 的回應本體。
//
// PUT 成功回的是「保存之後的資料庫現值」而不是請求本體的迴音：
// 界面顯示的當前資料必須來自服務端保存結果，這條從回應的來源就成立。
type standardAccountProfileResponse struct {
	Account   standardAccountItem `json:"account"`
	RequestID string              `json:"request_id"`
}

// standardAccountStatusResponse 是 PUT /admin/accounts/{account_id}/status 的回應本體。
//
// 帶 revoked_sessions 不是修飾：影響範圍是這次操作的实际结果之一，界面要能如實說出
// 「這次讓 N 臺裝置必須重新登入」，而不是讓操作者對著一句「已停用」自己猜。
// 恢復時恆為 0（這條通路不撤也不復活任何會話），0 是事實而不是失敗。
// account 仍是「變更之後的資料庫現值」，與詳情、編輯同一個來源。
type standardAccountStatusResponse struct {
	Account         standardAccountItem `json:"account"`
	RevokedSessions int                 `json:"revoked_sessions"`
	RequestID       string              `json:"request_id"`
}

// standardAccountPasswordResetResponse 是 PUT /admin/accounts/{account_id}/password 的回應本體。
//
// account 是「重置之後的資料庫現值」：must_change_password 恆為 true（這正是界面要把
// 「這個口令只用一次」講給操作者聽的依據），status 與 disabled_at 保持原樣。
// revoked_sessions 與停用回應同一理由：界面要能如實說出「這次讓 N 臺裝置重新登入」。
// 回應裡絕對不會有的東西：新口令的任何回顯（連同前綴或長度）、任一側的雜湊、
// 會話材料——口令只在請求本體裡出現一次，回應與交付都不碰它；線下的交付管道在協議之外。
type standardAccountPasswordResetResponse struct {
	Account         standardAccountItem `json:"account"`
	RevokedSessions int                 `json:"revoked_sessions"`
	RequestID       string              `json:"request_id"`
}

// standardAccountEndpoints 回傳普通帳戶端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深連結回退用的 API 首段清單（/admin）因此自動同步。
// 同一路徑上由方法決定做哪件事：分流都發生在各自 handle 的第一層，
// 拆成多條路徑樣式反而會多出「幾個端點共用一份授權語意」的維護點。
// {account_id} 匹配恰好一個路徑段；多出的段落只有 /status 這一條已登記的子路徑，
// 其他多段仍落到 catch-all，回 JSON 的 1001。
// 詳情與編輯共用父路徑（與 /root/admins/{account_id} 同形）：那條白名單只有
// display_name 一欄非安全資料，不需要為它另開子路徑去宣稱動的是哪一欄。
// 狀態走 /status 子資源（同樣與 /root/admins/{account_id}/status 同形）：
// 狀態是安全欄位，與普通資料各有一把白名單閘，混在一條 PUT 裡就等於
// 「能改顯示名的人也能順手改登入能力」，而那正是兩套邊界互相污染的地方。
// 憑據走 /password 子資源（與 /root/admins/{account_id}/password 同形）：憑據與狀態同屬
// 安全欄位，但兩條白名單、兩套確認語意、兩個審計動作各是各的——
// 「重置不是解除停用、停用不是重置」在路由形狀上就分開。
// 普通帳戶今日沒有刪除通路，所以父路徑上只有 GET／HEAD／PUT（Root 那側的 DELETE
// 不在这裡複製一份）。
func (s *Server) standardAccountEndpoints() []apiRoute {
	if s.stdAccounts == nil {
		return nil
	}
	return []apiRoute{
		{"/admin/accounts", s.allowMethods(s.handleAdminAccounts,
			http.MethodGet, http.MethodHead, http.MethodPost)},
		{"/admin/accounts/{account_id}", s.allowMethods(s.handleAdminAccountProfile,
			http.MethodGet, http.MethodHead, http.MethodPut)},
		{"/admin/accounts/{account_id}/status", s.allowMethods(s.handleAdminAccountStatus,
			http.MethodPut)},
		{"/admin/accounts/{account_id}/password", s.allowMethods(s.handleAdminAccountPassword,
			http.MethodPut)},
	}
}

// handleAdminAccountPassword 處理 PUT /admin/accounts/{account_id}/password：重置登入憑據。
//
// 這條子路徑只有 PUT 一個方法（allowMethods 已登記，其餘方法回 1002 帶 Allow）：
// 「動憑據」在協定層就只有一個入口，讀現值本來就在父路徑上，不在這裡開第二份讀法。
// 前置鏈與父路徑逐字相同（consolePrincipal：來源判定 → 憑據解析 → 首次改密門閂），
// 授權、目標範圍與訪戶出局都由用例判，傳輸層不先判一次。
//
// 標識解析失敗與「查無此人／他是管理員／他已刪除」同樣是 1001；口令本身的形狀不合格
// 不在此處判（那是 credential 模組那道閘，經用例映射為 1004＋點名 password 欄位）——
// 傳輸層不抄寫第二份口令規則。
func (s *Server) handleAdminAccountPassword(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	id, err := idgen.Parse(r.PathValue("account_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in resetStandardAccountPasswordRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	reset, err := s.stdAccounts.ResetStandardAccountPassword(r.Context(), principal, id,
		in.Password, requestIDFromRequest(r))
	if err != nil {
		s.writeResetStandardAccountPasswordFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, standardAccountPasswordResetResponse{
		Account:         profileItemOf(reset.Profile),
		RevokedSessions: reset.RevokedSessions,
		RequestID:       requestIDFromRequest(r),
	})
}

// handleAdminAccountStatus 處理 PUT /admin/accounts/{account_id}/status：停用或恢復登入。
//
// 這條子路徑只有 PUT 一個方法（allowMethods 已登記，其餘方法回 1002 帶 Allow）：
// 「動狀態」在協定層就只有一個入口，讀現狀本來就在父路徑上，不在這裡開第二份讀法。
// 前置鏈與父路徑逐字相同（consolePrincipal：來源判定 → 憑據解析 → 首次改密門閂），
// 授權與目標範圍都由用例判，傳輸層不先判一次。
//
// 標識非法與「查無此人／他是管理員／他已刪除」同樣是 1001：這句話在本組端點的
// 三個入口裡一直只有一個答案，加一個方法不該多出另一套語意。
func (s *Server) handleAdminAccountStatus(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	id, err := idgen.Parse(r.PathValue("account_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in updateStandardAccountStatusRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	// 兩個欄位都必須落在封閉集合內：值取自 internal/account 的常數（字面值只有一份）。
	// 非法值當場 1004 點名欄位，不帶進用例——那是拼寫問題，不是併發問題。
	newStatus, expectedStatus, badField := parseAdminStatusPair(in.Status, in.ExpectedStatus)
	if badField != "" {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": badField})
		return
	}
	// 新舊同值是一次必然寫不出新事實的請求（見 account.Store.SetStatus 的域不變量），
	// 在這裡點名比回 2014 誠實：資料庫根本還不需要被問到。
	if newStatus == expectedStatus {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "status"})
		return
	}
	changed, err := s.stdAccounts.UpdateStandardAccountStatus(r.Context(), principal, id,
		stdacct.StatusChangeInput{NewStatus: newStatus, ExpectedStatus: expectedStatus},
		requestIDFromRequest(r))
	if err != nil {
		s.writeUpdateStandardAccountStatusFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, standardAccountStatusResponse{
		Account:         profileItemOf(changed.Profile),
		RevokedSessions: changed.RevokedSessions,
		RequestID:       requestIDFromRequest(r),
	})
}

// handleAdminAccounts 依方法分流：POST 建立、GET／HEAD 分頁目錄。
//
// 兩件事共用同一條前置鏈與同一道 NeedServerAdmin 判定（判定的實作點在各自用例裡）：
// 「能建號的人讀不到目錄」或「能讀目錄的人建不了號」這類分裂在這一層沒有發生點，
// 差別只在建號那一步還要多問一次策略開關（讀取不需要，見檔案頭注「開關不預讀」）。
func (s *Server) handleAdminAccounts(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		s.createStandardAccount(w, r, principal)
		return
	}
	s.directoryStandardAccounts(w, r, principal)
}

// handleAdminAccountProfile 處理 /admin/accounts/{account_id}：GET／HEAD 詳情、PUT 編輯。
//
// 標識解析失敗與「查無此人」是同一句話：不告訴敲門的人他猜的格式對不對。
// 這一句同樣罩住「他其實是個管理員」與「他已在刪除終態裡」兩種情況——兩者都不在
// 這本目錄的範圍內（三道範圍檢查見 internal/stdacct/profile.go），把它們報成可區分的
// 結論就等於讓一條普通帳戶端點替 Root 的管理員目錄做枚舉。
func (s *Server) handleAdminAccountProfile(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	id, err := idgen.Parse(r.PathValue("account_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	if r.Method == http.MethodPut {
		s.updateStandardAccount(w, r, principal, id)
		return
	}
	profile, err := s.stdAccounts.StandardAccountProfile(r.Context(), principal, id)
	if err != nil {
		s.writeStandardAccountReadFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, standardAccountProfileResponse{
		Account:   profileItemOf(profile),
		RequestID: requestIDFromRequest(r),
	})
}

// createStandardAccount 處理 POST /admin/accounts。
func (s *Server) createStandardAccount(w http.ResponseWriter, r *http.Request,
	principal identity.Principal) {
	var in createStandardAccountRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	created, err := s.stdAccounts.CreateStandardAccount(r.Context(), principal, stdacct.CreateInput{
		LoginName:       in.LoginName,
		DisplayName:     in.DisplayName,
		InitialPassword: in.Password,
	}, requestIDFromRequest(r))
	if err != nil {
		s.writeCreateStandardFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, createdStandardAccountResponse{
		AccountID:          created.AccountID.String(),
		LoginName:          created.LoginName,
		DisplayName:        created.DisplayName,
		Status:             created.Status.String(),
		MustChangePassword: created.MustChangePassword,
		CreatedAt:          timeutil.FormatUTC(created.CreatedAt),
		RequestID:          requestIDFromRequest(r),
	})
}

// directoryStandardAccounts 處理 GET／HEAD /admin/accounts：解析查詢參數後交目錄用例。
//
// 「參數沒帶」與「參數帶了但不合形」分開處置：前者用本倉庫的默認常數（值只有一份），
// 後者當場回 1004 點出是哪個查詢參數——把 0 或負數默默當成「沒帶」會讓分頁錯誤
// 變成空頁，而空頁是合法回應，錯誤因此永遠查不出來。
// q（名稱關鍵字）不做任何解析：它是一段原字串比對，長短與取值集合由用例判，
// 空字串與「沒帶」在用例裡收斂成同一句話。
func (s *Server) directoryStandardAccounts(w http.ResponseWriter, r *http.Request,
	principal identity.Principal) {
	q := r.URL.Query()
	query := stdacct.DirectoryQuery{Page: 1, PageSize: stdacct.DirectoryDefaultPageSize}
	if raw := q.Get("page"); raw != "" {
		page, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
				map[string]any{"invalid_field": "page"})
			return
		}
		query.Page = page
	}
	if raw := q.Get("page_size"); raw != "" {
		size, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
				map[string]any{"invalid_field": "page_size"})
			return
		}
		query.PageSize = size
	}
	query.StatusFilter = q.Get("status")
	query.TypeFilter = q.Get("type")
	query.Keyword = q.Get("q")

	page, err := s.stdAccounts.Directory(r.Context(), principal, query)
	if err != nil {
		s.writeStandardAccountDirectoryFailure(w, r, err)
		return
	}
	items := make([]standardAccountItem, 0, len(page.Rows))
	for _, row := range page.Rows {
		items = append(items, directoryItemOf(row))
	}
	writeJSON(w, http.StatusOK, standardAccountListResponse{
		Accounts:  items,
		Page:      page.Page,
		PageSize:  page.PageSize,
		Total:     page.Total,
		RequestID: requestIDFromRequest(r),
	})
}

// updateStandardAccount 處理 PUT /admin/accounts/{account_id}。
func (s *Server) updateStandardAccount(w http.ResponseWriter, r *http.Request,
	principal identity.Principal, accountID idgen.ID) {
	var in updateStandardAccountProfileRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	// 空依據值不進用例：顯示名在域規則裡恆非空，拿空字串當「我看見的現值」
	// 永遠比不中，那是一次必然落敗的請求，直接點出欄位比回衝突誠實。
	if in.ExpectedDisplayName == "" {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "expected_display_name"})
		return
	}
	updated, err := s.stdAccounts.UpdateStandardAccountProfile(r.Context(), principal, accountID,
		in.DisplayName, in.ExpectedDisplayName, requestIDFromRequest(r))
	if err != nil {
		s.writeUpdateStandardAccountFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, standardAccountProfileResponse{
		Account:   profileItemOf(updated),
		RequestID: requestIDFromRequest(r),
	})
}

// writeCreateStandardFailure 把建立用例的錯誤對映為對外回應。
//
// 失敗映射逐條對應不同的處置，不互相冒充：
//   - 1004：本體欄位不合規（登入名含空白／顯示名為空／口令形狀不合格）。details 只點出
//     是哪一個欄位，不復述伺服器的域規則原文，也不含任何輸入內容；
//   - 2012：登入名已被佔用。這是業務衝突，帳戶一個也沒多出來；
//   - 2017：策略此刻不開放這條通路。它不是權限問題（2011），也不是寫法問題（1004）——
//     要等的是 Root 打開開關，換名字、換身分、重登都不是處置；
//   - 2011：這個主體沒有伺服器級管理權（普通帳戶與系統主體都在這裡被拒）；
//   - 500：其餘（策略行缺失、資料庫故障這類非拒絕錯誤），細節只進日誌。
func (s *Server) writeCreateStandardFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, stdacct.ErrDuplicateLogin):
		writeError(w, r, CodeLoginNameTaken, http.StatusConflict)
	case errors.Is(err, stdacct.ErrInvalidInitialPassword):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "password"})
	case errors.Is(err, account.ErrInvalidLogin):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "login_name"})
	case errors.Is(err, account.ErrInvalidDisplayName):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "display_name"})
	case errors.Is(err, stdacct.ErrCreateDisabled):
		writeError(w, r, CodeAccountCreationDisabled, http.StatusForbidden)
	case errors.Is(err, identity.ErrPermissionDenied):
		// 403：憑據有效，缺的是權限。不發刪除指令——那枚 Cookie 此刻仍換得出同一個主體。
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	case errors.Is(err, acctpolicy.ErrNoPolicyRow):
		// 結構缺陷：單例策略行被外部工具動過。對外只有一句通用失敗，細節只進日誌。
		s.logger.Error("建立普通帳戶時讀不到帳戶建立策略", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	case errors.Is(err, identity.ErrNotAuthenticated), errors.Is(err, identity.ErrInvalidPrincipal):
		// 到這裡只剩「帶著有效會話卻換不出可信主體」一種可能，那是服務端缺陷而不是拒絕：
		// 照 500 報，讓它被當成缺陷查，而不是報成 2011 讓操作者以為自己沒登入。
		s.logger.Error("建立普通帳戶的主體不合法", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	default:
		s.logger.Error("建立普通帳戶處理失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// writeStandardAccountDirectoryFailure 把目錄用例的錯誤對映為對外回應。
//
// 每一個結論參數各自點名：把「page=0」與「status=ghost」混成一句通用 1004，
// 客戶端就只剩「亂猜是哪個參數寫壞了」；而 2011 與 500 更是兩句話——
// 一個是「這本目錄你讀不到」，另一個是「服務端此刻查不了」，重試的意義完全不同。
func (s *Server) writeStandardAccountDirectoryFailure(w http.ResponseWriter, r *http.Request,
	err error) {
	switch {
	case errors.Is(err, stdacct.ErrInvalidPage):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "page"})
	case errors.Is(err, stdacct.ErrInvalidPageSize):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "page_size"})
	case errors.Is(err, stdacct.ErrInvalidStatusFilter):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "status"})
	case errors.Is(err, stdacct.ErrInvalidTypeFilter):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "type"})
	case errors.Is(err, stdacct.ErrInvalidKeyword):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "q"})
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	default:
		s.logger.Error("列舉普通帳戶目錄失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// writeStandardAccountReadFailure 把詳情讀取的錯誤對映為對外回應。
func (s *Server) writeStandardAccountReadFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, stdacct.ErrAccountNotFound):
		// 「不存在」「是管理員」「已刪除」三種情況同形（見 stdacct.ErrAccountNotFound 的說明）。
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	default:
		s.logger.Error("讀取普通帳戶詳情失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// writeUpdateStandardAccountFailure 把編輯用例的錯誤對映為對外回應。
//
// 每一句的處置都不同，所以各是各的碼：1004 要人改輸入、2013 要人重讀現值、
// 1001 是目標根本不在這本目錄、2011 是主體不對——把它們混成一句，
// 客戶端就只剩「再試一次」這把錘子，而再試一次對這四種情況都不是答案。
// 2013 沿用管理員資料編輯那枚已發布的碼：兩處的處置逐字相同（重讀服務端現值再決定），
// 為同一句話再發一個數字只會讓界面多出一條「兩個碼要不要各寫一句案」的維護點。
func (s *Server) writeUpdateStandardAccountFailure(w http.ResponseWriter, r *http.Request,
	err error) {
	switch {
	case errors.Is(err, account.ErrInvalidDisplayName):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "display_name"})
	case errors.Is(err, stdacct.ErrProfileConflict):
		writeError(w, r, CodeProfileConflict, http.StatusConflict)
	case errors.Is(err, stdacct.ErrAccountNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	default:
		s.logger.Error("編輯普通帳戶資料失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// writeUpdateStandardAccountStatusFailure 把停用／恢復用例的錯誤對映為對外回應。
//
// 這組端點仍然一個新碼都不新增：1004 說「改寫法」、2014 說「重讀目標現狀再重新確認」、
// 1001 說「他不在這本目錄」、2011 說「換個身分也沒用」，四句處置各不相同。
// 2014 是 Root 那條停用通路已發布的碼，兩處處置逐字相同（都是「你確認時的那個可用性
// 已經不是現值」），為同一句話再發一個數字只會讓界面多一條「兩個碼要不要各寫一句案」的
// 維護點——與 R2-008 把資料衝突收斂到 2013 同一取向。
// 已刪除的普通帳戶走的是 1001 而不是 2015：那本目錄按定義就不列他，
// 「不在目錄」本來就是這裡對三種出局形態唯一的一句-answer（見 internal/stdacct/profile.go
// 的三道範圍檢查），而 2015 說的是 Root 目錄裡列得到、但不再接受寫入的那個人。
func (s *Server) writeUpdateStandardAccountStatusFailure(w http.ResponseWriter,
	r *http.Request, err error) {
	switch {
	case errors.Is(err, stdacct.ErrInvalidStatusChange):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "status"})
	case errors.Is(err, stdacct.ErrStatusConflict):
		writeError(w, r, CodeAdminStatusConflict, http.StatusConflict)
	case errors.Is(err, stdacct.ErrAccountNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	default:
		s.logger.Error("變更普通帳戶登入狀態失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// writeResetStandardAccountPasswordFailure 把重置用例的錯誤對映為對外回應。
//
// 刻意沒有「衝突」這一句：本用例不設依據值（操作者拿不出「現行口令」那類誠實的錨點），
// 所以不存在 2013/2014 那樣的併發結論——重複提交是又做了一次完整重置，每次都留一筆審計。
// 處置各歸各：1004 要人改口令、2018 說「他是訪戶，今日沒有憑據可重置，要等後續那條
// 明確的訪戶升級通路」、1001 是目標不在目錄、2011 是主體不對。
// 2018 不降級成 1001：這本目錄按定義把訪戶列得進去，叫操作者「換個目標」是誤導；
// 也不降級成 2011：那不是身分不夠，而是這個目標的形態不在這條通路的職責裡。
// 其餘細節只進日誌。
func (s *Server) writeResetStandardAccountPasswordFailure(w http.ResponseWriter,
	r *http.Request, err error) {
	switch {
	case errors.Is(err, stdacct.ErrInvalidResetPassword):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "password"})
	case errors.Is(err, stdacct.ErrGuestTarget):
		writeError(w, r, CodeGuestUpgradeRequired, http.StatusForbidden)
	case errors.Is(err, stdacct.ErrAccountNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	default:
		s.logger.Error("重置普通帳戶憑據失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// directoryItemOf 把目錄的一行投影成回應本體（欄位白名單見 internal/stdacct/directory.go）。
func directoryItemOf(row stdacct.DirectoryRow) standardAccountItem {
	item := standardAccountItem{
		AccountID:          row.AccountID,
		LoginName:          row.LoginName,
		DisplayName:        row.DisplayName,
		AccountType:        row.AccountType,
		Status:             row.Status,
		MustChangePassword: row.MustChangePassword,
		CreatedAt:          timeutil.FormatUTC(row.CreatedAt),
	}
	if !row.LastLoginAt.IsZero() {
		item.LastLoginAt = timeutil.FormatUTC(row.LastLoginAt)
	}
	return item
}

// profileItemOf 把單筆經實體校驗的資料成回應本體；與目錄行同形，外加禁用時刻。
func profileItemOf(p stdacct.StandardProfile) standardAccountItem {
	item := standardAccountItem{
		AccountID:          p.AccountID.String(),
		LoginName:          p.LoginName,
		DisplayName:        p.DisplayName,
		AccountType:        p.Type.String(),
		Status:             p.Status.String(),
		MustChangePassword: p.MustChangePassword,
		CreatedAt:          timeutil.FormatUTC(p.CreatedAt),
	}
	if !p.LastLoginAt.IsZero() {
		item.LastLoginAt = timeutil.FormatUTC(p.LastLoginAt)
	}
	if !p.DisabledAt.IsZero() {
		item.DisabledAt = timeutil.FormatUTC(p.DisabledAt)
	}
	return item
}
