// adminregistrations.go 是「伺服器級管理者審批帳戶註冊申請」的傳輸層落點：
// /admin/registrations 一條路徑做一件事（GET／HEAD 分頁名冊），
// /admin/registrations/{account_id}/decision 一條路徑做一件事（PUT 批准或拒絕）。
//
// 這個檔案刻意只做協定層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 consolePrincipal 那條共用鏈，
//     不在這裡重寫一份「先看 Cookie 再看標頭」的順序；
//  2. 首次改密門閂——同一條鏈上的 requirePasswordChangeDone，與其餘受保護端點同一把閘；
//  3. 請求本體與查詢參數的形態——決定只有一個欄位 decision（approve|reject），
//     名冊只認 page／page_size／status／q 四個查詢參數；
//     未知欄位由 decodeJSON 的 DisallowUnknownFields 當場拒殺（1004），因此
//     「順手把角色、帳戶類型、停用狀態、活動標識或一枚口令一起送進來」在本體裡
//     沒有一個可以填的格子——「這個人被批成哪一類主體」由打的哪個端點決定，不由請求內容決定；
//  4. 結論對映——把用例回傳的可判別錯誤一一映射到機器碼，其餘一律 500 且細節只進日誌。
//     這組端點用到的碼：1001（不在這本名冊裡）、1004（改寫法）、2011（換個也沒用）、
//     2021（這份申請已經有過決定，本步唯一新發布的一枚）。
//
// 為什麼刻意不帶「依據值」（expected_status 那樣的欄位）：審核者手上沒有誠實的錨點——
// 一筆還沒被決定的申請，其現值就是「pending」這個詞本身，把它放進本體只會多出一格
// 「填錯就注定落敗」的表單欄位，而真正的併發控制本來就在資料庫那道 WHERE status='pending' 上
// （與 R2-005 的刪除、R2-010 的重置同一取向：那兩條也沒有依據值）。
// 因此這條路徑沒有 2013／2014 那種「你看見的現值已過期」的結論：落敗的一方拿到的是 2021，
// 處置是「重讀名冊、這顆按鈕對他已經不存在」，而不是「湊一份新的依據值再按一次」。
//
// 為什麼另一側不能借用這組端點：申請人查自己的結局走 POST /auth/registration-status
// （那條通路每次重新交憑據、只回答他本人那一份），而這裡的主體必須是已認證的管理者。
// 兩條通路各自回答一句話，沒有一條能替另一條多給一個格子：匿名這側永遠讀不到名冊，
// 管理這側永遠不需要、也拿不到任何申請人的口令。
//
// 回應本體絕不含口令明文、憑據雜湊、會話材料、登入名的內部正規化鍵，也不含 roles 欄位：
// 這本名冊按定義把持有伺服器級授予的人排掉，回應不描述一件不存在的事。
// 名冊也不帶 must_change_password、last_login_at 與 account_type——它們對
// 「要不要放行這個人」不構成依據，多一格就多一個可外流的格子。
// 沒有審核人是誰、沒有理由文本：那兩樣今日在資料庫裡就沒有格子（用戶批准的形態），
// 審核者的身分只存在 Root 域審計的 actor 裡，而本步不新增任何審計查閱入口。
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctreview"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// RegistrationReviewUseCase 是「審批註冊申請」用例在傳輸層的入口形態
// （由 internal/app 注入 *acctreview.Service）。
//
// 與 Deps.StandardAccounts、Deps.SelfRegister 分開一個介面、分開一個 Deps 欄位，理由同前幾步：
// 「裝配了什麼就服務什麼」——沒注入本用例的執行檔一個 /admin/registrations 端點都不掛。
//
// principal 一律是「本次請求的憑據剛換出的受信主體」；授權（NeedServerAdmin）、
// 目標此刻的形態核實與那一跳決定的落庫都在用例裡判，不在傳輸層先判一次——
// 兩處各判一套的結局是其中一套被繞過。
type RegistrationReviewUseCase interface {
	// Roster 以當前受信主體分頁列舉註冊申請名冊（含狀態與名稱篩選及總數）。
	// 「某一筆列不列得進來」由用例的範圍規則回答（只列待審批與已拒絕、排除持有授予者），
	// 傳輸層只負責把四個查詢參數原樣遞進去，不在這裡判一次篩選語意。
	Roster(ctx context.Context, principal identity.Principal,
		q acctreview.RosterQuery) (acctreview.RosterPage, error)
	// ReviewApplication 對一筆待審批申請做出批准或拒絕。刻意不設依據值：
	// 現值已不是 pending 時整個操作不發生（狀態、決定時刻、審計一個字都沒落地）
	// 並回可判別的 acctreview.ErrAlreadyReviewed，見 internal/acctreview/decide.go。
	ReviewApplication(ctx context.Context, principal identity.Principal,
		accountID idgen.ID, decision account.Decision, requestID string) (acctreview.ReviewOutcome, error)
}

// reviewApplicationRequest 是審批請求的本體。白名單只有決定一欄：
// 沒有 expected_*、沒有 status、沒有 role／account_type／password／reason——
// 前兩格是別條白名單通路的欄位（未知欄位 1004），後兩樣則根本不屬於這條通路的職責：
// 「批准順手把人改成管理員」「批准順手換掉他的口令」在本體連格子都沒有的形狀上就不成立。
// 也沒有 reason：內部備註與可公開理由今日都不落庫（用戶批准的形態），
// 所以這不是一句「界面少擺一個欄位」，而是一個在協定層就沒有發生點的欄位。
type reviewApplicationRequest struct {
	Decision string `json:"decision"`
}

// applicationRosterItem 是名冊行與決定之後回顯共用的形狀（同一筆資料在不同回應裡的形狀必須同源）。
//
// 六格就是審核一個人需要的全部依據：他是誰、他在審批鏈的哪一站、他等了多久、
// 有沒有已經落地的決定。submitted_at 取帳戶建立時刻（統一帳戶模型下那就是申請送進來的那一刻），
// reviewed_at 只在「已經有決定」時出現（omitempty 的缺席是事實的缺席，
// 不是拿 1970 年冒充一個還沒做出的決定）。
type applicationRosterItem struct {
	AccountID   string `json:"account_id"`
	LoginName   string `json:"login_name"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	SubmittedAt string `json:"submitted_at"`
	ReviewedAt  string `json:"reviewed_at,omitempty"`
}

// applicationRosterResponse 是 GET／HEAD /admin/registrations 的回應本體。
//
// 分頁三元組回顯「你問的是哪一頁、一頁多大、總共幾筆」：客戶端據此算頁數與標空狀態，
// 不需要（也不準）自己拿行數猜。applications 恆為數組，空頁是 []。
type applicationRosterResponse struct {
	Applications []applicationRosterItem `json:"applications"`
	Page         int64                   `json:"page"`
	PageSize     int64                   `json:"page_size"`
	Total        int64                   `json:"total"`
	RequestID    string                  `json:"request_id"`
}

// reviewApplicationResponse 是 PUT /admin/registrations/{account_id}/decision 的回應本體。
//
// application 是「決定之後的資料庫現值」而不是請求本體的迴音：界面顯示的當前資料必須來自
// 服務端保存的結果。decision 把本次落地的那個決定如實回顯（它不是憑據、也不是個人資料，
// 只是操作者自己按下的那一顆），讓成功句能講出「你批准了這一份」或「你拒絕了這一份」。
// 被批准的那一欄 status 會是 active——他此刻已經不在這本名冊上了（名冊只列 pending 與 rejected），
// 此後的停用、重置與改名都在普通帳戶目錄那一側；這句話由界面說，不靠回應多帶一個旗標。
type reviewApplicationResponse struct {
	Application applicationRosterItem `json:"application"`
	Decision    string                `json:"decision"`
	RequestID   string                `json:"request_id"`
}

// registrationReviewEndpoints 回傳審批端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深連結回退用的 API 首段清單（/admin）因此自動同步。
// 名冊與決定分佈在兩條路徑上（與 /admin/accounts 與 /admin/accounts/{account_id}/status
// 那兩組同一形態）：讀是一條只認 GET／HEAD 的列表路徑，寫是一條掛在目標標識下的子資源，
// 兩者不共用一條 PUT——「能列出名冊」與「能決定一個人」本來就該在路由形狀上是兩件事。
// 這裡刻意沒有 /admin/registrations/{account_id} 這條單筆讀法：名冊一行就是審核需要的全部資料，
// 再開一條同義的讀取路徑只會多出「兩處答案可能不一致」的維護點；
// 而那條路徑根本沒有登記，落到 catch-all 時回的是 JSON 的 1001，不是網頁外殼。
func (s *Server) registrationReviewEndpoints() []apiRoute {
	if s.regReview == nil {
		return nil
	}
	return []apiRoute{
		{"/admin/registrations", s.allowMethods(s.handleAdminRegistrations,
			http.MethodGet, http.MethodHead)},
		{"/admin/registrations/{account_id}/decision", s.allowMethods(s.handleAdminRegistrationDecision,
			http.MethodPut)},
	}
}

// handleAdminRegistrations 處理 GET／HEAD /admin/registrations：解析查詢參數後交名冊用例。
//
// 前置鏈與 /admin/accounts 逐字相同（consolePrincipal：來源判定 → 憑據解析 → 首次改密門閂），
// 授權與範圍都由用例判，傳輸層不先判一次。
//
// 「參數沒帶」與「參數帶了但不合形」分開處置：前者用本倉庫的默認常數（值只有一份），
// 後者當場回 1004 點出是哪個查詢參數——把 0 或負數默默當成「沒帶」會讓分頁錯誤
// 變成空頁，而空頁是合法回應，錯誤因此永遠查不出來。
// q（名稱關鍵字）不做任何解析：它是一段原字串比對，長短與取值集合由用例判，
// 空字串與「沒帶」在用例裡收斂成同一句話。
func (s *Server) handleAdminRegistrations(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	query := acctreview.RosterQuery{Page: 1, PageSize: acctreview.RosterDefaultPageSize}
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
	query.Keyword = q.Get("q")

	page, err := s.regReview.Roster(r.Context(), principal, query)
	if err != nil {
		s.writeRegistrationRosterFailure(w, r, err)
		return
	}
	items := make([]applicationRosterItem, 0, len(page.Rows))
	for _, row := range page.Rows {
		items = append(items, applicationItemOf(row))
	}
	writeJSON(w, http.StatusOK, applicationRosterResponse{
		Applications: items,
		Page:         page.Page,
		PageSize:     page.PageSize,
		Total:        page.Total,
		RequestID:    requestIDFromRequest(r),
	})
}

// handleAdminRegistrationDecision 處理 PUT /admin/registrations/{account_id}/decision：批准或拒絕。
//
// 這條子路徑只有 PUT 一個方法（allowMethods 已登記，其餘方法回 1002 帶 Allow）：
// 「做決定」在協定層就只有一個入口，讀名冊本來就在父路徑上，不在這裡開第二份讀法。
//
// 標識解析失敗與「查無此人／他是訪戶／他是被授予者／他已刪除／他沒走過審批通路」同樣是 1001：
// 這句話在本組端點的兩個入口裡一直只有一個答案，加一個方法不該多出另一套語意。
// 決定值本身不在封閉集合內不進用例（那是拼寫問題，不是併發問題）：值取自
// internal/account 的解析入口，字面值因此只有那一個來源。
func (s *Server) handleAdminRegistrationDecision(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	id, err := idgen.Parse(r.PathValue("account_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	var in reviewApplicationRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	decision, err := account.ParseDecision(in.Decision)
	if err != nil {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "decision"})
		return
	}
	outcome, err := s.regReview.ReviewApplication(r.Context(), principal, id,
		decision, requestIDFromRequest(r))
	if err != nil {
		s.writeReviewApplicationFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, reviewApplicationResponse{
		Application: applicationItemOf(outcome.Application),
		Decision:    outcome.Decision.String(),
		RequestID:   requestIDFromRequest(r),
	})
}

// writeRegistrationRosterFailure 把名冊用例的錯誤對映為對外回應。
//
// 每一個結論參數各自點名：把「page=abc」與「status=active」混成一句通用 1004，
// 客戶端就只剩「亂猜是哪個參數寫壞了」；而 2011 與 500 更是兩句話——
// 一個是「這本名冊你讀不到」，另一個是「服務端此刻查不了」，重試的意義完全不同。
func (s *Server) writeRegistrationRosterFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, acctreview.ErrInvalidPage):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "page"})
	case errors.Is(err, acctreview.ErrInvalidPageSize):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "page_size"})
	case errors.Is(err, acctreview.ErrInvalidStatusFilter):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "status"})
	case errors.Is(err, acctreview.ErrInvalidKeyword):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "q"})
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	default:
		s.logger.Error("列舉註冊申請名冊失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// writeReviewApplicationFailure 把審批用例的錯誤對映為對外回應。
//
// 每一句的處置都不同，所以各是各的碼：1004 要人改決定值的寫法、2021 要人重讀名冊
// （那一格按鈕對他已經不存在）、1001 是目標根本不在這本名冊裡、2011 是主體不對——
// 混成一句，客戶端就只剩「再點一次」這把錘子，而對 2021 來說再點一次恰恰是最壞的處置
// （它會被讀成「剛才那次沒生效」，而真正生效的是別人那一次）。
//
// 2021 是本步唯一新發布的一枚：它說的是「這份申請已有決定」，與 2013／2014 那句
// 「你依據的現值已過期，重新湊一份再來一次」不是同一處置，因此不沿用那兩者；
// 也不降級成 1001：那句話叫操作者換一個目標，而他要處理的人就躺在眼前這一頁上。
// 主體不合法（帶著有效會話卻換不出可信主體）照 500 報，讓它被當成缺陷查，
// 而不是報成 2011 讓操作者以為自己沒登入。其餘細節只進日誌。
func (s *Server) writeReviewApplicationFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, acctreview.ErrInvalidDecision):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "decision"})
	case errors.Is(err, acctreview.ErrAlreadyReviewed):
		writeError(w, r, CodeApplicationDecided, http.StatusConflict)
	case errors.Is(err, acctreview.ErrApplicationNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, identity.ErrPermissionDenied):
		// 403：憑據有效，缺的是權限。不發刪除指令——那枚 Cookie 此刻仍換得出同一個主體。
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	case errors.Is(err, identity.ErrNotAuthenticated), errors.Is(err, identity.ErrInvalidPrincipal):
		s.logger.Error("審批註冊申請的主體不合法", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	default:
		s.logger.Error("審批註冊申請處理失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// applicationItemOf 把一筆申請換成回應本體（欄位白名單見 internal/acctreview/roster.go 頭注）。
//
// reviewed_at 的缺席走 omitempty 而不是零值：一個還在等的人不該看到一個 1970 年的決定時刻，
// 而界面要的依據本來就是「這一格有沒有出現」（與 /auth/registration-status 那條通路同一寫法，
// 兩側對同一個事實用同一種缺席表達）。
func applicationItemOf(row acctreview.Application) applicationRosterItem {
	item := applicationRosterItem{
		AccountID:   row.AccountID,
		LoginName:   row.LoginName,
		DisplayName: row.DisplayName,
		Status:      row.Status,
		SubmittedAt: timeutil.FormatUTC(row.SubmittedAt),
	}
	if !row.ReviewedAt.IsZero() {
		item.ReviewedAt = timeutil.FormatUTC(row.ReviewedAt)
	}
	return item
}
