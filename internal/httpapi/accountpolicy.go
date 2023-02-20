// accountpolicy.go 是「伺服器級帳戶建立策略」的傳輸層落點：
// /root/account-policy 一個路徑做兩件事（GET／HEAD 現讀策略、PUT 一次寫入三個值），
// /auth/capabilities 一個路徑做一件事（GET／HEAD 回報登入前界面的兩個入口答案）。
//
// 這個檔案刻意只做協定層該做的四件事，一條領域規則都不寫在這裡：
//  1. 來源（CSRF）判定與憑據解析——逐字複用 consolePrincipal 那條共用鏈，
//     不在這裡重寫一份「先看 Cookie 再看標頭」的順序；
//  2. 請求本體的形態——PUT 的白名單就是那三個欄位，一個都不能省（省掉等於默默按
//     「關」處理，而「關」是一個決定不是缺席）；未知欄位由 decodeJSON 的
//     DisallowUnknownFields 當場拒殺，所以「順手把 account_id／expected_*／reason
//     之類的東西塞進策略保存」在協定層就沒有一個可以填的格子；
//  3. 欄位換型——模式字串交acctpolicy 換成枚舉（這裡不抄寫第二份模式清單），
//     換不過去點名 self_register_mode 欄位；
//  4. 結論對映——用例回傳的可判別錯誤一一映射到機器碼，其餘一律 500 且細節只進日誌。
//
// 兩條路徑的鑑別完全不同，這是它們分開的理由：
//   - /root/account-policy 需要受信主體，而且只有 Root 讀得到內容（判定在用例裡，
//     不在傳輸層判一次）；回應是策略全文加由策略合成的對外答案。
//   - /auth/capabilities 匿名可讀，回應只有兩個布林。它與 /root/init-status 同一取向：
//     登入前的畫面要能被引導，就必須有一件可以匿名問的事，而這件事的揭露由使用者
//     在批准本步時明確接受。除這兩個布林之外，模式名字、最後修改時刻、
//     管理員建號開關、任何帳戶資料與任何閾值都不在這張回應裡——它們不改變
//     「現在能不能自行建立帳戶」這個答案，卻會讓一個匿名呼叫端多讀到伺服器的准入計畫。
//
// 策略值不等於能力：界面把開關打開，並不會讓註冊或訪客入口真的可用，
// 因為兩個布林是「策略 ∧ 這條通路已實作」的合成結果（見 internal/acctpolicy 的 EntryOf）。
// 這裡刻意不自己算一次——同一個合成規則有兩處實作時，總有一處會被忘了改。
package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// AccountPolicyUseCase 是帳戶建立策略用例在傳輸層的入口形態（由 internal/app 注入 *acctpolicy.Service）。
//
// 與 Deps.Admins 分開一個介面、分開一個 Deps 欄位，理由是「裝配了什麼就服務什麼」：
// 沒注入本用例的執行檔一個策略端點都不掛，協定層行為與本步之前逐字相同。
type AccountPolicyUseCase interface {
	// Policy 以當前受信主體現讀生效中的帳戶建立策略（授權由用例內的 NeedRoot 判定）。
	Policy(ctx context.Context, principal identity.Principal) (acctpolicy.Policy, error)
	// UpdatePolicy 以 Root 主體一次寫入三個值，並在同一個交易裡落下 Root 域審計。
	// 本用例刻意沒有依據值：這是一份單例文件，整份 PUT 的語意就是「以這三個值為現值」。
	UpdatePolicy(ctx context.Context, principal identity.Principal,
		in acctpolicy.Input, requestID string) (acctpolicy.Policy, error)
	// Entry 回報登入前界面需要的兩個入口答案（不需要主體，也讀不到任何策略細節）。
	Entry(ctx context.Context) (acctpolicy.EntryCapabilities, error)
}

// updateAccountPolicyRequest 是策略保存請求的本體。白名單只有這三個欄位：
// 兩個開關以指標承載，是因為「欄位缺席」與「欄位填了 false」是兩件不同的事——
// 前者要拒（那是漏傳，默默當關會讓一次介面缺陷變成一個准入決定），後者是合法的決定。
// expected_* 之類依據欄位、reason 之類自由文字、account_id 之類目標欄位在本體裡都沒有格子。
type updateAccountPolicyRequest struct {
	AdminCreateStandard *bool   `json:"admin_create_standard"`
	SelfRegisterMode    *string `json:"self_register_mode"`
	GuestEnabled        *bool   `json:"guest_enabled"`
}

// entryCapabilitiesBody 是對外入口答案的本體（Root 端與匿名端共用同一個形狀）。
//
// invite_code_required 是「這一趟自行註冊需不需要一枚邀請碼」這一個最小事實，由策略現讀合成
// （只在生效模式確為 invite 且通路已落地時為 true）；它不是模式名字，closed／open／approval
// 一律回 false，因此仍守住 R2-006「模式內部計畫不出口」那條界線。界面據它決定要不要顯示邀請碼欄位，
// 但它只是顯示依據、不是准入：寫入那一刻由 internal/selfregister 現讀策略重判，前端瞞不過那道檢查。
type entryCapabilitiesBody struct {
	SignUpOpen         bool `json:"sign_up_open"`
	InviteCodeRequired bool `json:"invite_code_required"`
	GuestOpen          bool `json:"guest_open"`
}

// accountPolicyResponse 是 GET／PUT /root/account-policy 的回應本體。
//
// 三個值就是策略全文（這張表只有這三個值），updated_at 缺席時語意是「出廠以來沒人改過」
// 而不是「時刻查不到」；entry 是「這份策略此刻讓對外入口成什麼樣」，
// 讓 Root 在同一張畫面上看見意圖與結果，而不是自己推。
// 回應裡絕對不會有的東西：任何帳戶標識、口令、憑據雜湊、會話材料，以及通路落地狀況的
// 內部清單（那屬本執行檔的形態，不是這個部署的狀態）。
type accountPolicyResponse struct {
	AdminCreateStandard bool                  `json:"admin_create_standard"`
	SelfRegisterMode    string                `json:"self_register_mode"`
	GuestEnabled        bool                  `json:"guest_enabled"`
	UpdatedAt           *string               `json:"updated_at,omitempty"`
	Entry               entryCapabilitiesBody `json:"entry"`
	RequestID           string                `json:"request_id"`
}

// entryCapabilitiesResponse 是 GET／HEAD /auth/capabilities 的回應本體。
//
// 三個布林加 request_id，沒有別的：這是「還站在門外的人」唯一需要知道的事——能不能自行註冊、
// 這一趟要不要帶一枚邀請碼、能不能開訪客。模式名字、最後修改時刻、管理員建號開關、任何帳戶資料
// 與任何閾值都不在這裡（見檔案頭注：它們不改變「現在能不能自行建立帳戶」這個答案，卻會多泄露准入計畫）。
type entryCapabilitiesResponse struct {
	SignUpOpen         bool   `json:"sign_up_open"`
	InviteCodeRequired bool   `json:"invite_code_required"`
	GuestOpen          bool   `json:"guest_open"`
	RequestID          string `json:"request_id"`
}

// accountPolicyEndpoints 回傳帳戶建立策略端點的登記清單；未注入用例時為空清單。
//
// 登記與否只有這一個來源，深連結回退用的 API 首段清單因此自動同步。
// 兩個 Root 入口（讀與寫）共用同一路徑，方法決定做哪件事；
// 對外的兩個布林掛在 /auth 首段下——它屬「登入前後都問得出的入口資訊」這一類，
// 與 /auth/login 同樣是匿名可達的准入面，而不是 Root 面。
func (s *Server) accountPolicyEndpoints() []apiRoute {
	if s.accountPolicy == nil {
		return nil
	}
	return []apiRoute{
		{"/root/account-policy", s.allowMethods(s.handleAccountPolicy,
			http.MethodGet, http.MethodHead, http.MethodPut)},
		{"/auth/capabilities", s.allowMethods(s.handleEntryCapabilities,
			http.MethodGet, http.MethodHead)},
	}
}

// handleAccountPolicy 依方法分流：GET／HEAD 現讀策略、PUT 一次寫入三個值。
func (s *Server) handleAccountPolicy(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.consolePrincipal(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPut {
		s.updateAccountPolicy(w, r, principal)
		return
	}
	policy, err := s.accountPolicy.Policy(r.Context(), principal)
	if err != nil {
		s.writeAccountPolicyFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policyResponse(policy, requestIDFromRequest(r)))
}

// updateAccountPolicy 處理 PUT /root/account-policy：三個欄位一個都不能缺。
//
// 缺欄位在這裡就點名（不進用例）：那是請求本體的形狀問題，
// 讓它進用例只會得到同一句 1004，卻多花一次授權與一次資料庫讀取。
func (s *Server) updateAccountPolicy(w http.ResponseWriter, r *http.Request, principal identity.Principal) {
	var in updateAccountPolicyRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.AdminCreateStandard == nil {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "admin_create_standard"})
		return
	}
	if in.SelfRegisterMode == nil {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "self_register_mode"})
		return
	}
	if in.GuestEnabled == nil {
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "guest_enabled"})
		return
	}
	policy, err := s.accountPolicy.UpdatePolicy(r.Context(), principal, acctpolicy.Input{
		AdminCreateStandard: *in.AdminCreateStandard,
		SelfRegisterMode:    *in.SelfRegisterMode,
		GuestEnabled:        *in.GuestEnabled,
	}, requestIDFromRequest(r))
	if err != nil {
		s.writeAccountPolicyFailure(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policyResponse(policy, requestIDFromRequest(r)))
}

// handleEntryCapabilities 處理 GET／HEAD /auth/capabilities：回報兩個對外入口的答案。
//
// 匿名可達、只讀、no-store：策略可以被 Root 隨時改掉，而登入前的畫面若拿到一份快取的
// 舊答案，就會在「已經關掉」的伺服器上顯示一個不該點的入口。
// 判定失敗就照實回錯誤（通用信封），不猜成「全關」也不猜成「全開」：
// 前者把一次資料庫故障說成 Root 的決定，後者直接把門打開。
func (s *Server) handleEntryCapabilities(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	entry, err := s.accountPolicy.Entry(r.Context())
	if err != nil {
		s.logger.Error("對外入口能力查詢失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, entryCapabilitiesResponse{
		SignUpOpen:         entry.SignUpOpen,
		InviteCodeRequired: entry.InviteCodeRequired,
		GuestOpen:          entry.GuestOpen,
		RequestID:          requestIDFromRequest(r),
	})
}

// policyResponse 把領域值換成回應本體：模式取枚舉的穩定字串，時刻用與其餘端點
// 同一個 UTC 表示（兩邊對得起來），零值換成缺席而不是任何一個時刻。
func policyResponse(policy acctpolicy.Policy, requestID string) accountPolicyResponse {
	out := accountPolicyResponse{
		AdminCreateStandard: policy.AdminCreateStandard,
		SelfRegisterMode:    policy.SelfRegisterMode.String(),
		GuestEnabled:        policy.GuestEnabled,
		Entry:               entryBody(policy.EntryOf()),
		RequestID:           requestID,
	}
	if !policy.UpdatedAt.IsZero() {
		stamp := timeutil.FormatUTC(policy.UpdatedAt)
		out.UpdatedAt = &stamp
	}
	return out
}

// entryBody 把領域的入口答案換成回應形狀（唯一的換算點，兩條路徑共用）。
func entryBody(entry acctpolicy.EntryCapabilities) entryCapabilitiesBody {
	return entryCapabilitiesBody{
		SignUpOpen:         entry.SignUpOpen,
		InviteCodeRequired: entry.InviteCodeRequired,
		GuestOpen:          entry.GuestOpen,
	}
}

// writeAccountPolicyFailure 把策略用例的錯誤對映為對外回應。
//
// 每一句的處置都不同，所以各是各的碼：1004 要人改寫法（那個模式名字根本不存在）、
// 2016 是「這個計畫還沒上線」（改寫法換不來結果，要等的是對應通路）、
// 2011 是主體不對（再點一次也不會變）、500 是資料庫讀不出策略（要人去看的東西在伺服器裡）。
func (s *Server) writeAccountPolicyFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, acctpolicy.ErrUnknownMode):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"invalid_field": "self_register_mode"})
	case errors.Is(err, acctpolicy.ErrModeUnavailable):
		writeError(w, r, CodeAccountPolicyModeUnavailable, http.StatusBadRequest)
	case errors.Is(err, identity.ErrPermissionDenied):
		writeError(w, r, CodePermissionDenied, http.StatusForbidden)
	case errors.Is(err, acctpolicy.ErrNoPolicyRow):
		// 結構缺陷：單例行被動過。對外只有一句通用失敗，細節（表名、SQL 原因）只進日誌。
		s.logger.Error("帳戶建立策略讀取失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	default:
		s.logger.Error("變更帳戶建立策略失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}
