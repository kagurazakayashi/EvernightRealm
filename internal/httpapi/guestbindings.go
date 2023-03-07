// guestbindings.go 是「訪戶綁定的執行側」傳輸層：目標本人那三条通路。
//
// 路徑族落在 /auth 之下而不是 /admin 之下，這一句就是本步最重要的邊界：
// /admin/* 那一側的入口全部經 NeedServerAdmin（含綁定預檢與憑證簽發），
// 而這裡的三道門只承認「憑證上釘著的那個目標本人」——主體判定在服務層第一行，
// 不是靠界面把按鈕藏起來。管理員讀得到别人的目錄，卻按不了這一動；
// 访戶自己、Root 與匿名也各自拿到既有的 2011／2002 族。
//
// 三道門各自回答一句話，而且只有中間那道會寫：
//   - POST /auth/guest-bindings/preview：這枚憑證換來的執行會做什麼？（只讀，不核銷）
//   - POST /auth/guest-bindings：按下去，完成綁定。（唯一的寫入點）
//   - GET／HEAD /auth/guest-bindings：我接住過哪些人？（本人查已完成，回應遺失時的落點）
//
// 為什麼「先預覽、再確認」是兩次請求而不是一次加一個本地勾選框：
// 界面要展示的影響與警告必須是「服務端此刻核過的」，而不是簽發時那份快照的回音——
// 中間可能過了十分鐘、訪戶可能被停用、庫裡可能多了一張沒接入的引用表。
// 預覽那趟把當前事實念給本人聽，確認那趟在同一筆交易裡再核一次並寫入；
// 兩趟之間世界變了，第二趟就回 2026 而不是把舊計劃執行掉。
//
// 為什麼憑證走請求本體而不是查詢串或路徑段：它是被使用的憑據，不是資源地址。
// 放進 URL 會進訪問日誌、進瀏覽器歷史、也可被書籤複製——一枚還没被用掉的小票
// 不該在這些地方出現。本檔案所有回應都不回顯明文，包括失敗回應。
//
// CSRF 與會話邊界沿用 /auth 那一側的既有合同：不允許跨來源的不安全方法（2005）、
// 未帶憑據 2002、失效 2003、混用 2004、上一代 2007、尚未完成首次改密 2010，
// 一律經共用前置鏈，不為綁定另起一套。
package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/stdacct"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// GuestBindClaimUseCase 是「目標本人執行訪戶綁定」用例在傳輸層的入口形態
// （由 internal/app 注入 *stdacct.Service）。
//
// 它與 Deps.StandardAccounts 分開一個介面、分開一個 Deps 欄位，理由與自註冊側同形：
// 「管理員打理普通帳戶」與「帳戶本人處置自己接住的身份」是兩套准入邊界，
// 共用一個有無判定就會出現「只裝了管理端用例，本人的執行入口也一起掛上」的形態。
// principal 一律是本次憑據剛換出的受信主體；三道門的主體判定、憑證歸屬、
// 計劃復核與交易邊界都在用例裡判，傳輸層不在這裡判一次。
type GuestBindClaimUseCase interface {
	// PreviewGuestBindClaim 以只讀方式回答「這枚憑證換來的執行會做什麼」，
	// 不核銷憑證、不寫一行資料。憑證用不了回 stdacct.ErrBindTicketInvalid，
	// 計劃已不合當前事實回 stdacct.ErrBindPlanStale。
	PreviewGuestBindClaim(ctx context.Context, principal identity.Principal,
		ticket, requestID string) (stdacct.GuestBindClaimPreview, error)
	// ConfirmGuestBind 是今日唯一的綁定執行入口，而且只能由憑證上的目標本人通過：
	// 核銷憑證、來源訪戶退休、源會話同交易撤銷、追加不可變留痕（見 internal/stdacct/bindclaim.go）。
	ConfirmGuestBind(ctx context.Context, principal identity.Principal,
		ticket, requestID string) (stdacct.GuestBindResult, error)
	// ListGuestBindings 列舉「目標是我」的已完成綁定留痕；範圍由受信主體決定，
	// 沒有任何欄位可以代填別人的帳戶。
	ListGuestBindings(ctx context.Context, principal identity.Principal,
		requestID string) ([]stdacct.GuestBindingItem, error)
}

// guestBindClaimRequest 是本人兩條 POST 通路的本體。白名單恰好一欄：憑證明文。
//
// 沒有來源標識、沒有目標標識、也沒有任何「我要以誰的身分」的格子——
// 這一對是誰，憑證行上早已釘死，而「我是誰」由本次會話換出的主體決定。
// 讓呼叫端能宣稱其中任何一端，就等於把「限定這一對」降格成一句建議。
type guestBindClaimRequest struct {
	Ticket string `json:"ticket"`
}

// guestBindClaimPreviewResponse 是核銷前預覽的回應本體。
//
// 兩側沿用目錄單筆的另一個視角，欄位白名單與 standardAccountItem 逐字相同
// （不含任何憑據格子）。blockers 刻意不在這裡：不可行的那一份计划走 2026 並自帶記號清單，
// 讓「预览成功」永遠意味著「這份计划是可行的」，界面不必在 200 裡再判一次布爾值。
type guestBindClaimPreviewResponse struct {
	TicketID           string              `json:"ticket_id"`
	Source             standardAccountItem `json:"source"`
	Target             standardAccountItem `json:"target"`
	Impacts            []string            `json:"impacts"`
	SourceOpenSessions int                 `json:"source_open_sessions"`
	SchemaVersion      int                 `json:"schema_version"`
	ExpiresAt          string              `json:"expires_at"`
	ConsentMode        string              `json:"consent_mode"`
	RequestID          string              `json:"request_id"`
}

// guestBindResultResponse 是綁定成功的回應本體。
//
// Source 是退休之後的現值（status 恆為 retired，帶著 retired_at），Target 是目標的現值：
// 兩欄並列就是「動的是誰、沒動的是誰」的正面證據。revoked_sessions 取自落庫結果，
// 界面據此說出「讓 N 臺裝置重新登入」，不許自己猜；0 是事實而不是失敗。
// 這裡沒有 ticket 欄：明文用掉了就不該在任何回應裡再出現第二次。
type guestBindResultResponse struct {
	BindingID       string              `json:"binding_id"`
	Source          standardAccountItem `json:"source"`
	Target          standardAccountItem `json:"target"`
	RevokedSessions int                 `json:"revoked_sessions"`
	BoundAt         string              `json:"bound_at"`
	ConsentMode     string              `json:"consent_mode"`
	RequestID       string              `json:"request_id"`
}

// guestBindingItemResponse 是本人那本帳上的一行。
type guestBindingItemResponse struct {
	BindingID         string `json:"binding_id"`
	SourceAccountID   string `json:"source_account_id"`
	SourceLoginName   string `json:"source_login_name"`
	SourceDisplayName string `json:"source_display_name"`
	BoundAt           string `json:"bound_at"`
	RevokedSessions   int    `json:"revoked_sessions"`
	ConsentMode       string `json:"consent_mode"`
}

// guestBindingListResponse 是 GET／HEAD /auth/guest-bindings 的回應本體。
//
// bindings 恆為數組（沒有過是 []，不是缺席），total 取同一份讀取的行數：
// 這一頁沒有分頁，因為「一個人接住幾個訪戶」是個位數的事實，
// 為它建分頁是把界面複雜度換成一個不存在的規模問題。
type guestBindingListResponse struct {
	Bindings  []guestBindingItemResponse `json:"bindings"`
	Total     int                        `json:"total"`
	RequestID string                     `json:"request_id"`
}

// guestBindClaimEndpoints 回傳本人綁定端點的登記清單；未注入用例時為空。
//
// 登記與否只這一處來源，深連結回退用的 API 首段清單（/auth）因此自動同步——
// 而 /auth 這個首段本來就存在，所以未注入時這裡只是少三条路徑，不改变回退行為。
// 父路徑上做兩件事，由方法分流（與 /admin/accounts 同一取向）：
// GET 讀自己的帳，POST 執行綁定。預覽是 POST 而不是 GET，因為它的輸入是一段憑據：
// 放進查詢串就會進訪問日誌與瀏覽器歷史（理由見檔案頭注）。
func (s *Server) guestBindClaimEndpoints() []apiRoute {
	if s.guestBinds == nil {
		return nil
	}
	return []apiRoute{
		{"/auth/guest-bindings", s.allowMethods(s.handleGuestBindClaim,
			http.MethodGet, http.MethodHead, http.MethodPost)},
		{"/auth/guest-bindings/preview", s.allowMethods(s.handleGuestBindClaimPreview,
			http.MethodPost)},
	}
}

// handleGuestBindClaimPreview 處理 POST /auth/guest-bindings/preview：
// 目標本人以只讀方式看見這枚憑證換來的執行會做什麼。
//
// 前置鏈與 /auth 那一側其餘通路逐字相同（來源判定 → 憑據解析 → 首次改密門閂）：
// 欠著首次改密的帳戶先改密，再處置「有人要把一個訪戶併進我」這件事——
// 那不是為綁定新造的規則，而是 requirePasswordChangeDone 對全部寫入與敏感讀取的既有立場。
//
// 憑證欄缺失或空白是請求寫法問題（1004 點名 ticket）；形狀合規但用不了是 2025；
// 不可行或計劃已過期是 2026；主體不對是 2011。四句話各給各的出口，不互相冒充。
func (s *Server) handleGuestBindClaimPreview(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	if !s.allowRequestOrigin(r) {
		writeError(w, r, CodeOriginForbidden, http.StatusForbidden)
		return
	}
	resolved, ok := s.resolveSession(w, r)
	if !ok {
		return
	}
	if !s.requirePasswordChangeDone(w, r, resolved.Principal) {
		return
	}
	var in guestBindClaimRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Ticket == "" {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "ticket"})
		return
	}
	preview, err := s.guestBinds.PreviewGuestBindClaim(r.Context(), resolved.Principal,
		in.Ticket, requestIDFromRequest(r))
	if err != nil {
		s.writeGuestBindClaimFailure(w, r, err)
		return
	}
	impacts := make([]string, 0, len(preview.Plan.Impacts))
	for _, i := range preview.Plan.Impacts {
		impacts = append(impacts, i.String())
	}
	writeJSON(w, http.StatusOK, guestBindClaimPreviewResponse{
		TicketID:           preview.TicketID.String(),
		Source:             profileItemOf(preview.Plan.Source),
		Target:             profileItemOf(preview.Plan.Target),
		Impacts:            impacts,
		SourceOpenSessions: preview.Plan.SourceOpenSessions,
		SchemaVersion:      preview.Plan.SchemaVersion,
		ExpiresAt:          timeutil.FormatUTC(preview.ExpiresAt),
		ConsentMode:        preview.Plan.ConsentMode,
		RequestID:          requestIDFromRequest(r),
	})
}

// handleGuestBindClaim 按方法分流父路徑：POST 執行綁定，GET／HEAD 讀自己的帳。
//
// 分流放在第一層（與 /admin/accounts 同一手法），因為兩種方法的前置鏈與結論完全不同：
// POST 是一筆寫入，GET 是一趟只讀。放在同一個 handle 裡按 r.Method 岔開，
// 是這條路徑上唯一的分流點。
func (s *Server) handleGuestBindClaim(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.handleGuestBindingList(w, r)
	default:
		s.handleGuestBindConfirm(w, r)
	}
}

// handleGuestBindConfirm 處理 POST /auth/guest-bindings：本人核銷憑證並完成綁定。
//
// 這是最需要「不猜」的一條通路，也是唯一一条：任何一步失敗都讓整筆交易回滾——
// 憑證仍可核銷（若失敗發生在核銷之前）、訪戶仍是訪戶、會話仍有效、留痕仍不存在。
// 因此回應裡沒有一句「部分成功」，而失敗映射見 writeGuestBindClaimFailure。
//
// 提交成功但回應遺失（斷線、代理中斷）時，界面對它說的應該是「結果待確認」而不是
// 「失敗」或「成功」：重試同一枚憑證只會拿到 2025（它已被用掉），
// 而 GET /auth/guest-bindings 讀到的那一行留痕才是完成的證據。
// 這條通路因此不帶任何「依據值」欄位也不做自動重發：小票只有一張，按兩次不會變成兩次綁定。
func (s *Server) handleGuestBindConfirm(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	if !s.allowRequestOrigin(r) {
		writeError(w, r, CodeOriginForbidden, http.StatusForbidden)
		return
	}
	resolved, ok := s.resolveSession(w, r)
	if !ok {
		return
	}
	if !s.requirePasswordChangeDone(w, r, resolved.Principal) {
		return
	}
	var in guestBindClaimRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Ticket == "" {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "ticket"})
		return
	}
	done, err := s.guestBinds.ConfirmGuestBind(r.Context(), resolved.Principal,
		in.Ticket, requestIDFromRequest(r))
	if err != nil {
		s.writeGuestBindClaimFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, guestBindResultResponse{
		BindingID:       done.Binding.ID.String(),
		Source:          profileItemOf(done.Source),
		Target:          profileItemOf(done.Target),
		RevokedSessions: done.RevokedSessions,
		BoundAt:         timeutil.FormatUTC(done.Binding.BoundAt),
		ConsentMode:     done.Binding.ConsentMode,
		RequestID:       requestIDFromRequest(r),
	})
}

// handleGuestBindingList 處理 GET／HEAD /auth/guest-bindings：讀回「目標是我」的綁定留痕。
//
// 沒有任何查詢參數可填，也沒有本體：範圍就是換出的主體。
// 它不是管理員那本目錄的替代品，也讀不到別人的綁定——那兩句話由同一個事實支撐：
// 這趟查詢的 WHERE 只經 principal.AccountID()，而那個值來自本次憑據。
func (s *Server) handleGuestBindingList(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	resolved, ok := s.resolveSession(w, r)
	if !ok {
		return
	}
	if !s.requirePasswordChangeDone(w, r, resolved.Principal) {
		return
	}
	items, err := s.guestBinds.ListGuestBindings(r.Context(), resolved.Principal,
		requestIDFromRequest(r))
	if err != nil {
		s.writeGuestBindClaimFailure(w, r, err)
		return
	}
	out := make([]guestBindingItemResponse, 0, len(items))
	for _, item := range items {
		out = append(out, guestBindingItemResponse{
			BindingID:         item.BindingID.String(),
			SourceAccountID:   item.SourceAccountID.String(),
			SourceLoginName:   item.SourceLoginName,
			SourceDisplayName: item.SourceDisplayName,
			BoundAt:           timeutil.FormatUTC(item.BoundAt),
			RevokedSessions:   item.RevokedSessions,
			ConsentMode:       item.ConsentMode,
		})
	}
	writeJSON(w, http.StatusOK, guestBindingListResponse{
		Bindings:  out,
		Total:     len(out),
		RequestID: requestIDFromRequest(r),
	})
}

// writeGuestBindClaimFailure 對映本人三條通路的失敗。三句话各有自己的出口，
// 而它們共同的特點是「不帶任何憑證資訊」——失敗回應也不回顯明文或標識以外的細節。
func (s *Server) writeGuestBindClaimFailure(w http.ResponseWriter, r *http.Request, err error) {
	var planErr *stdacct.BindPlanError
	switch {
	case errors.Is(err, stdacct.ErrBindTicketInvalid):
		// 403：憑據有效，但那張小票換不出這一次綁定（五種內部原因同形，見碼注）。
		writeError(w, r, CodeBindTicketInvalid, http.StatusForbidden)
	case errors.As(err, &planErr):
		blockers := make([]string, 0, len(planErr.Blockers))
		for _, b := range planErr.Blockers {
			blockers = append(blockers, b.String())
		}
		writeErrorDetails(w, r, CodeBindPlanStale, http.StatusConflict,
			map[string]any{"blockers": blockers})
	case errors.Is(err, stdacct.ErrBindPlanStale):
		// 事實已漂但說不出哪一条阻止原因（版本推進或摘要對不上）：同一枚碼，不帶記號清單。
		writeError(w, r, CodeBindPlanStale, http.StatusConflict)
	case errors.Is(err, stdacct.ErrAccountNotFound):
		// 憑證指向的帳戶已不在可讀範圍：與詳情端點同句 1001，不另發新話。
		writeError(w, r, CodeNotFound, http.StatusNotFound)
	case errors.Is(err, stdacct.ErrBindConflict):
		// 併發尾巴：交易內剛判定可行、轉眼寫不中。沿用既有 2014「重讀現狀再決定」。
		writeError(w, r, CodeAdminStatusConflict, http.StatusConflict)
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	case errors.Is(err, identity.ErrNotAuthenticated), errors.Is(err, identity.ErrInvalidPrincipal):
		s.logger.Error("綁定執行通路的主體不合法", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	default:
		s.logger.Error("訪戶綁定請求處理失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}
