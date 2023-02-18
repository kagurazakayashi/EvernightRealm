// invitecodes.go 是「Root 管理服務器級註冊邀請碼」的傳輸層落點：
// /root/invite-codes 一條路徑做兩件事（GET／HEAD 分頁名冊、POST 簽發），
// /root/invite-codes/{code_id} 一條路徑做一件事（DELETE 撤銷，無本體、無依據值）。
//
// 這個檔案刻意只做協議層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 consolePrincipal 那條共用鏈，不在這裡重寫一份
//     「先看 Cookie 再看標頭」的順序；
//  2. 首次改密門閂——同一條鏈上的 requirePasswordChangeDone，與其餘受保護端點同一把閘；
//  3. 請求本體與查詢參數的形態——簽發只認 label／max_uses／expires_at 三個欄位，
//     名冊只認 page／page_size／status／q 四個查詢參數，撤銷什麼都不帶；
//     未知欄位由 decodeJSON 的 DisallowUnknownFields 當場拒殺（1004），因此
//     「順手把角色、活動標識、會話或一枚口令一起送進來」在本體裡沒有一個可以填的格子——
//     「簽出的是什麼東西」由打的哪個端點決定，不由請求內容決定；
//  4. 結論對映——把用例回傳的可判別錯誤一一映射到機器碼，其餘一律 500 且細節只進日誌。
//     這組端點用到的碼：1001（撤銷目標不在這本名冊裡）、1004（改寫法）、2011（換個也沒用）、
//     2022（這枚碼已經被撤銷，本步唯一新發布的一枚）。
//
// 為什麼是 Root、不是管理員（用戶批准於 R2-014）：邀請碼是「服務器級註冊准入憑證」，
// 誰來拿這張路條本身就是服務器的准入決定，與「Root 設哪三個建立開關」同側（見 /root/account-policy）；
// 管理員打理的是已經存在的普通賬戶，不是「誰能生出一個普通賬戶」。因此這組端點的授權邊界是 NeedRoot，
// 判定只經 internal/invitecode 用例裡的 identity.Authorize(principal, NeedRoot)，管理員與匿名在這一層就結束。
//
// 明文碼只在簽發成功的那一次回應裡出現：庫裡落的是它的 SHA-256 驗證材料，名冊與撤銷回顯都讀不回來。
// 因此 POST 的回應帶一枚完整碼、而 GET 名冊的每一行都刻意不帶——「丟了就重新簽發一枚，
// 而不是把庫存的秘密翻出來」這句話要成立在回應形狀上，不靠界面自律。
//
// 回應本體絕不含明文碼的第二次露出、驗證材料哈希、任何賬戶資料、任何會話材料、任何角色：
// 一枚邀請碼換不出這些，今天也沒有任何通路能讓它換出這些（invite 模式與核銷通路仍未落地）。
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/invitecode"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// InviteCodeUseCase 是「服務器級註冊邀請碼管理」用例在傳輸層的入口形態（由 internal/app 注入 *invitecode.Service）。
//
// 與 Deps.AccountPolicy、Deps.RegistrationReview 分開一個介面、分開一個 Deps 欄位，理由同前幾步：
// 「裝配了什麼就服務什麼」——沒注入本用例的執行檔一個 /root/invite-codes 端點都不掛。
//
// principal 一律是「本次請求的憑據剛換出的受信主體」；授權（NeedRoot）、目標此刻的形態核實與
// 那一躍撤銷／簽發的落庫都在用例裡判，不在傳輸層先判一次——兩處各判一套的結局是其中一套被繞過。
type InviteCodeUseCase interface {
	// Issue 以當前受信主體簽發一枚邀請碼，回傳一次性明文與名冊那一行（授權由用例內的 NeedRoot 判定）。
	Issue(ctx context.Context, principal identity.Principal,
		in invitecode.IssueInput, requestID string) (invitecode.IssuedCode, error)
	// Roster 以當前受信主體分頁列舉邀請碼名冊（含狀態篩選、標籤關鍵字與總數）。「哪些行落在這一頁」
	// 由用例的派生規則回答（讀時用狀態而非任何 status 欄位篩選），傳輸層只把四個查詢參數原樣遞進去。
	Roster(ctx context.Context, principal identity.Principal,
		q invitecode.RosterQuery) (invitecode.RosterPage, error)
	// Revoke 讓一枚邀請碼進入撤銷終態。刻意不設依據值：已被撤銷時整個操作不發生
	// （撤銷時刻沒改、已用次數沒動、審計沒記）並回可判別的 invitecode.ErrAlreadyRevoked。
	Revoke(ctx context.Context, principal identity.Principal,
		codeID idgen.ID, requestID string) (invitecode.RevokedCode, error)
}

// issueInviteCodeRequest 是簽發請求的本體。白名單只有這三個欄位：
// 沒有 role／account_type／activity_id／password——「簽出的是能建哪種主體的東西」由打的哪個端點決定，
// 一枚註冊邀請碼按定義只能換來一個普通賬戶，本體連一個能把它寫成別的東西的格子都沒有。
// max_uses 與 expires_at 用指標承載：缺席是一個決定（額度默認單次、有效期默認永不），
// 而「填了 0」或「填了一個過去的時刻」是另一回事，要能被分開判。
type issueInviteCodeRequest struct {
	Label     string  `json:"label"`
	MaxUses   *int64  `json:"max_uses"`
	ExpiresAt *string `json:"expires_at"`
}

// revokeInviteCodeRequest 是撤銷請求的本體：一個空格都沒有。撤銷不選欄位、也不交依據值——
// 正當地性錨在「這枚碼此刻還沒被撤銷」這條狀態機守衛上（與 R2-005 管理員刪除同一取向）。
// 帶任何非空本體都會被 DisallowUnknownFields 當場拒殺為 1004，因此「撤銷順手表態點什麼」
// 在協議層就沒有一個可以發生的形狀。
type revokeInviteCodeRequest struct{}

// inviteCodeItem 是名冊行、簽發回顯與撤銷回顯共用的形狀（同一筆資料在不同回應裡的形狀必須同源）。
//
// 這一格里沒有明文碼、沒有驗證材料哈希——那是簽發那一跳之外任何回應都不該出現的東西。
// expires_at 與 revoked_at 走 omitempty：缺席是事實的缺席（永不過期 / 尚未撤銷），
// 不是拿 epoch 時刻冒充一個還沒發生或將不發生的決定。
type inviteCodeItem struct {
	CodeID    string `json:"code_id"`
	Label     string `json:"label"`
	Status    string `json:"status"`
	MaxUses   int64  `json:"max_uses"`
	UsedCount int64  `json:"used_count"`
	Remaining int64  `json:"remaining"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	RevokedAt string `json:"revoked_at,omitempty"`
}

// issuedInviteCodeResponse 是 POST /root/invite-codes 的回應本體。
//
// code 是明文碼——全回應鏈路裡唯一允許它出現的一格，僅這一次；code 之外的一切與名冊行同源。
// 界面據這一格做受控一次性展示，而它此後讀不回來（名冊那一行沒有 code 欄位）。
type issuedInviteCodeResponse struct {
	Code      string         `json:"code"`
	Invite    inviteCodeItem `json:"invite"`
	RequestID string         `json:"request_id"`
}

// inviteCodeRosterResponse 是 GET／HEAD /root/invite-codes 的回應本體。
type inviteCodeRosterResponse struct {
	Invites   []inviteCodeItem `json:"invites"`
	Page      int64            `json:"page"`
	PageSize  int64            `json:"page_size"`
	Total     int64            `json:"total"`
	RequestID string           `json:"request_id"`
}

// revokeInviteCodeResponse 是 DELETE /root/invite-codes/{code_id} 的回應本體。
//
// invite 是「撤銷之後的數據庫現值」（派生出 revoked 狀態、帶著撤銷時刻），不是呼叫端意圖的迴音。
type revokeInviteCodeResponse struct {
	Invite    inviteCodeItem `json:"invite"`
	RequestID string         `json:"request_id"`
}

// inviteCodeEndpoints 回傳邀請碼管理端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深鏈接回退用的 API 首段清單（/root）因此自動同步。
// 名冊與簽發分佈在同一條父路徑的兩個方法上（GET 讀、POST 寫），撤銷掛在目標標識下的 DELETE——
// 與 /root/admins 的「父路徑讀＋寫、目標路徑刪」同一形態：簽發會產出一枚一次性秘密，
// 因此它是 POST 一條新建，而撤銷是終態、掛在被撤銷那枚碼的標識上。
// 這裡刻意沒有 /root/invite-codes/{code_id} 的單筆讀法：名冊一行就是管理一枚碼需要的全部資料，
// 而那一枚碼的明文在簽發之後根本讀不回來——單開一條同義讀法只會造出「兩處答案可能不一致」的維護點。
func (s *Server) inviteCodeEndpoints() []apiRoute {
	if s.inviteCodes == nil {
		return nil
	}
	return []apiRoute{
		{"/root/invite-codes", s.allowMethods(s.handleInviteCodes,
			http.MethodGet, http.MethodHead, http.MethodPost)},
		{"/root/invite-codes/{code_id}", s.allowMethods(s.handleInviteCodeRevoke,
			http.MethodDelete)},
	}
}

// handleInviteCodes 依方法分流：GET／HEAD 分頁名冊、POST 簽發一枚碼。
func (s *Server) handleInviteCodes(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		s.issueInviteCode(w, r, principal)
		return
	}
	s.rosterInviteCodes(w, r, principal)
}

// rosterInviteCodes 處理 GET／HEAD /root/invite-codes：解析查詢參數後交名冊用例。
//
// 「參數沒帶」與「參數帶了但不合形」分開處置：前者用本倉庫的默認常數（值只有一份），
// 後者當場回 1004 點名是哪個查詢參數。q（標籤關鍵字）不做任何解析：它是一段原字串比對，
// 長短與取值集合由用例判，空字串與「沒帶」在用例裡收斂成同一句話。
func (s *Server) rosterInviteCodes(w http.ResponseWriter, r *http.Request, principal identity.Principal) {
	q := r.URL.Query()
	query := invitecode.RosterQuery{Page: 1, PageSize: invitecode.RosterDefaultPageSize}
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

	page, err := s.inviteCodes.Roster(r.Context(), principal, query)
	if err != nil {
		s.writeInviteRosterFailure(w, r, err)
		return
	}
	items := make([]inviteCodeItem, 0, len(page.Rows))
	for _, row := range page.Rows {
		items = append(items, inviteItem(row))
	}
	writeJSON(w, http.StatusOK, inviteCodeRosterResponse{
		Invites:   items,
		Page:      page.Page,
		PageSize:  page.PageSize,
		Total:     page.Total,
		RequestID: requestIDFromRequest(r),
	})
}

// issueInviteCode 處理 POST /root/invite-codes：簽發一枚碼並受控一次性展示其明文。
//
// max_uses 缺席即單次（1）：一個「沒填額度」的請求，其誠實默認是最保守的那一側——一枚只能用一次的碼，
// 而不是一個額度不明的碼。expires_at 缺席即永不過期；填了就必須是一個合法的 RFC 3339 且帶時區的時刻
// （解析失敗點名 expires_at，不猜成「永不過期」，因為那會把一次寫法錯誤說成一個准入決定）。
// 這兩個默認值的合成在用例外只做一次形狀轉換，域規則（額度 >= 1、有效期須晚於此刻）仍由用例判。
func (s *Server) issueInviteCode(w http.ResponseWriter, r *http.Request, principal identity.Principal) {
	var in issueInviteCodeRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	domain := invitecode.IssueInput{Label: in.Label, MaxUses: 1}
	if in.MaxUses != nil {
		domain.MaxUses = *in.MaxUses
	}
	if in.ExpiresAt != nil {
		at, err := timeutil.ParseUTC(*in.ExpiresAt)
		if err != nil {
			writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
				map[string]any{"invalid_field": "expires_at"})
			return
		}
		domain.ExpiresAt = at
	}
	issued, err := s.inviteCodes.Issue(r.Context(), principal, domain, requestIDFromRequest(r))
	if err != nil {
		s.writeIssueInviteFailure(w, r, err)
		return
	}
	// 明文碼隨這一次 201 回應交回；此後任何讀法都不再帶著它（見檔案頭注）。
	writeJSON(w, http.StatusCreated, issuedInviteCodeResponse{
		Code:      issued.Code,
		Invite:    inviteItem(issued.Row),
		RequestID: requestIDFromRequest(r),
	})
}

// handleInviteCodeRevoke 處理 DELETE /root/invite-codes/{code_id}：讓一枚碼進入撤銷終態。
//
// 這條子路徑只有 DELETE 一個方法（allowMethods 已登記，其餘方法回 1002 帶 Allow）：
// 「撤銷一枚碼」在協議層只有一個入口，讀名冊本來就在父路徑上，不在這裡開第二份讀法。
// 本體什麼都不許帶：它不選欄位、也不交依據值，正當地性錨在「它此刻還沒被撤銷」這條狀態機守衛上
// （與 R2-005 管理員刪除同一取向）。標識解析失敗與查無此碼同樣是 1001——這句話不區分
// 「格式不對」與「沒有這枚碼」，免得端點變成一臺標識格式探測器。
func (s *Server) handleInviteCodeRevoke(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	id, err := idgen.Parse(r.PathValue("code_id"))
	if err != nil {
		writeError(w, r, CodeNotFound, http.StatusNotFound)
		return
	}
	// 撤銷什麼都不許帶：不選欄位、也不交依據值，帶任何非空本體都會多出一個
	// 「這個端點似乎可以設定點什麼」的誤讀（與 R2-005 的管理員刪除同一約定：空對象或無本體，
	// 任何未知欄位由 decodeJSON 當場拒殺為 1004）。
	var in revokeInviteCodeRequest
	if r.ContentLength != 0 && !decodeJSON(w, r, &in) {
		return
	}
	revoked, err := s.inviteCodes.Revoke(r.Context(), principal, id, requestIDFromRequest(r))
	if err != nil {
		s.writeRevokeInviteFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, revokeInviteCodeResponse{
		Invite:    inviteItem(revoked.Row),
		RequestID: requestIDFromRequest(r),
	})
}

// inviteItem 把一行邀請碼換成回應本體（欄位白名單見 internal/invitecode/roster.go 頭注）。
//
// expires_at 與 revoked_at 的缺席走 omitempty 而不是零值：一枚永不過期的碼不該看到一個 1970 年的
// 到期時刻，一枚還沒被撤銷的碼也不該看到一個撤銷時刻——界面要的依據本來就是「這一格有沒有出現」。
func inviteItem(row invitecode.Row) inviteCodeItem {
	item := inviteCodeItem{
		CodeID:    row.CodeID,
		Label:     row.Label,
		Status:    row.Status.String(),
		MaxUses:   row.MaxUses,
		UsedCount: row.UsedCount,
		Remaining: row.Remaining,
		CreatedAt: timeutil.FormatUTC(row.CreatedAt),
	}
	if !row.ExpiresAt.IsZero() {
		item.ExpiresAt = timeutil.FormatUTC(row.ExpiresAt)
	}
	if !row.RevokedAt.IsZero() {
		item.RevokedAt = timeutil.FormatUTC(row.RevokedAt)
	}
	return item
}

// writeInviteRosterFailure 把名冊用例的錯誤映射為對外回應。每一個結論參數各自點名。
func (s *Server) writeInviteRosterFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, invitecode.ErrInvalidPage):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "page"})
	case errors.Is(err, invitecode.ErrInvalidPageSize):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "page_size"})
	case errors.Is(err, invitecode.ErrInvalidStatusFilter):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "status"})
	case errors.Is(err, invitecode.ErrInvalidKeyword):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "q"})
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	default:
		s.logger.Error("列舉邀請碼名冊失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// writeIssueInviteFailure 把簽發用例的錯誤映射為對外回應。
//
// 每一句的處置都不同：1004 要人改寫法（標籤空／過長、額度越界、有效期不晚於此刻），
// 2011 是主體不對（再按一次也不會變）、500 是服務端此刻籤不出（要人去查的東西在服務器裡）。
// 主體不合法（帶著有效會話卻換不出可信主體）照 500 報，讓它被當成缺陷查，而不是報成 2011
// 讓操作者以為自己沒登入。其餘細節只進日誌。
func (s *Server) writeIssueInviteFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, invitecode.ErrInvalidLabel):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "label"})
	case errors.Is(err, invitecode.ErrInvalidMaxUses):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "max_uses"})
	case errors.Is(err, invitecode.ErrInvalidExpiry):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "expires_at"})
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	case errors.Is(err, identity.ErrNotAuthenticated), errors.Is(err, identity.ErrInvalidPrincipal):
		s.logger.Error("簽發邀請碼的主體不合法", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	default:
		s.logger.Error("簽發邀請碼處理失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// writeRevokeInviteFailure 把撤銷用例的錯誤映射為對外回應。
//
// 2022 是本步唯一新發布的一枚：它說的是「這枚碼已經被撤銷」，與 2014／2013 那句
// 「你依據的現值已過期，重讀再來一次」不是同一處置，因此不沿用那兩者（重讀之後的答案是「它已經不在
// 有效那一側了」，再按一次那顆按鈕不是處置）；也不降級成 1001：那句是「這枚碼根本不在這本名冊上，
// 換個目標」，而這裡目標就躺在名冊上，只是已經沒有第二顆按鈕。主體不合法照 500 報。其餘細節只進日誌。
func (s *Server) writeRevokeInviteFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, invitecode.ErrAlreadyRevoked):
		writeError(w, r, CodeInviteAlreadyRevoked, http.StatusConflict)
	case errors.Is(err, invitecode.ErrCodeNotFound):
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, identity.ErrPermissionDenied):
		// 403：憑據有效，缺的是權限。不發刪除指令——那枚 Cookie 此刻仍換得出同一個主體。
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	case errors.Is(err, identity.ErrNotAuthenticated), errors.Is(err, identity.ErrInvalidPrincipal):
		s.logger.Error("撤銷邀請碼的主體不合法", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	default:
		s.logger.Error("撤銷邀請碼處理失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}
