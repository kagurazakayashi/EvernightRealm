// auth.go 是登入端點與瀏覽器請求防護的落點：Cookie 形態、來源（CSRF）策略、
// 認證方式獨佔，以及「當前會話」這個最小消費點。
//
// 四條策略在這裡一次定形，之後的端點（退出、裝置管理、業務寫入）只准複用，
// 不準各寫一套——兩套來源判定意味著其中一套會被繞過：
//
//  1. 會話 Cookie：HttpOnly＋SameSite=Lax＋Path=/，Secure 只跟隨實際 TLS 連線
//     （r.TLS != nil）。Lan HTTP 部署因此不依賴 Secure Cookie——瀏覽器的 CSRF 防線
//     由 SameSite=Lax（跨站 POST 不攜帶 Cookie）加來源判定兩層共同承擔，
//     「HTTP 相容」從來不是放寬 CSRF 的理由。過期屬性寫 Max-Age 與 Expires 雙份，
//     語意同於會話到期時刻；清除用同名同屬性的 Max-Age=-1 刪除指令，留給退出端點複用。
//  2. 來源／CSRF：對有副作用的方法（除 GET/HEAD/OPTIONS 外），凡請求帶 Origin，
//     必須等於請求本身的 scheme://host，或列在組態的跨域白名單內；Sec-Fetch-Site
//     宣告 cross-site 一律拒絕。不帶 Origin 的請求（原生客戶端、curl）視為非瀏覽器
//     ——CSRF 的威脅模型是瀏覽器自動附帶憑據，脫離該模型沒有 CSRF 可言。
//     白名單放行的是「這個來源可以提出請求」，不是「這個來源就是身分」。
//  3. 認證方式獨佔：Cookie 與 Authorization: Bearer 同時出現即拒絕（混用意圖繞過
//     來源校驗）；Bearer 只准無 Origin 的請求使用——瀏覽器路徑的會話秘密由
//     HttpOnly Cookie 獨佔承載，同源指令碼即便拿到路徑也不準改用 Bearer。
//  4. 會話秘密的分發：登入回應的 JSON 本體永不含秘密。原生客戶端從 Set-Cookie
//     標頭讀取（package:http 在非瀏覽器平臺可得；瀏覽器平臺由規範隔絕，
//     這正是 HttpOnly 的定義），後續以 Bearer 回傳；瀏覽器路徑由瀏覽器代管。
//
// 登入成功一律簽發「新」會話並覆寫 Cookie：舊 Cookie 無論有效與否都不延續，
// 這同時堵死會話固定攻擊（先種一個再等 victim 用同一枚提權）。
package httpapi

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/auth"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 會話 Cookie 與認證標頭的固定名稱。
const (
	// sessionCookieName 是全服務唯一的會話 Cookie 名。
	// 名字不帶秘密也不隨主體變化：Cookie 名本身在瀏覽器擴充與日誌裡四處可見，
	// 「er_session=...」要能一眼認出是哪個服務，而不是認出是哪個帳戶。
	sessionCookieName = "evernight_session"

	// authorizationHeader 與 bearerScheme 界定原生客戶端的回傳通路。
	authorizationHeader = "Authorization"
	bearerScheme        = "Bearer "

	// secFetchSiteHeader 與 crossSiteDirective 是瀏覽器來源自證標頭及其跨站值。
	secFetchSiteHeader = "Sec-Fetch-Site"
	crossSiteDirective = "cross-site"
)

// AuthUseCase 是登入用例在傳輸層的入口形態（由 internal/app 注入 *auth.Service）。
//
// 以介面接收而不是直接收 *auth.Service：傳輸層組合的是「能做這幾件事的能力」，
// 未來換實作（或測試替身）不動傳輸層程式碼；nil 時不掛載 auth 端點，
// 協定層行為與本步之前逐字相同（與 Deps.Web 同一取向）。
//
// ip 是失敗控制的計量來源：只能由傳輸層從「實際連線」取（remoteHost），
// 轉發標頭一概不傳進來——本專案沒有已批准的可信代理約定，就沒有資格替別人
// 宣稱來源；把標頭值當 ip 等於把限流鍵交給請求方隨意填寫。
type AuthUseCase interface {
	// LoginAccount 為普通帳戶簽發會話。
	LoginAccount(ctx context.Context, loginName, password, requestID, ip string) (auth.Outcome, error)
	// LoginRoot 以組態憑據為 Root 簽發會話。
	LoginRoot(ctx context.Context, password, requestID, ip string) (auth.Outcome, error)
	// Resolve 把一枚會話秘密換回受信主體。
	Resolve(ctx context.Context, secret string) (identity.Principal, session.Session, error)
	// Logout 撤銷一個剛經 Resolve 換回的主體其所綁定的會話（幂等）。
	// 呼叫端只在「已解析出一個有效會話」的路徑上調它；撤銷結果的審計落地由用例承擔。
	Logout(ctx context.Context, principal identity.Principal, sess session.Session, requestID string) error
}

// loginRequest 為普通帳戶登入的請求本體。欄位只准出現這兩個：
// 「角色」「主體類別」之類的宣稱會被 DisallowUnknownFields 當場拒殺——
// 主體類別由「打的端點」決定，端點本身就是分流，請求裡沒有任何可自報的欄位。
type loginRequest struct {
	LoginName string `json:"login_name"`
	Password  string `json:"password"`
}

// rootLoginRequest 為 Root 登入的請求本體：只有口令，沒有也不需要登入名。
type rootLoginRequest struct {
	Password string `json:"password"`
}

// loginResponse 是登入成功的回應本體。
//
// 刻意的缺席：會話秘密不在這裡（只在 Set-Cookie）；口令、雜湊、會話內部標識
// 也都不在——device_id 才是可展示的（它洩露了也換不來操作能力）。
// account_id 僅帳戶主體出現（UUIDv7 字串，跨 Web 大整數合同與此無關）；
// Root 沒有帳戶標識，欄位直接缺席而不是空字串冒充。
type loginResponse struct {
	SubjectKind string `json:"subject_kind"`
	AccountID   string `json:"account_id,omitempty"`
	DeviceID    string `json:"device_id"`
	ExpiresAt   string `json:"expires_at"`
	RequestID   string `json:"request_id"`
}

// sessionResponse 是「當前會話」的回應本體，在登入回應之上多帶建立與最近活動時刻。
type sessionResponse struct {
	SubjectKind  string `json:"subject_kind"`
	AccountID    string `json:"account_id,omitempty"`
	DeviceID     string `json:"device_id"`
	CreatedAt    string `json:"created_at"`
	LastActiveAt string `json:"last_active_at"`
	ExpiresAt    string `json:"expires_at"`
	RequestID    string `json:"request_id"`
}

// logoutResponse 是登出成功的回應本體：只有請求關聯 ID。
//
// 刻意不再_echo_任何身分或會話欄位——登出之後那枚憑據已換不出身份，回應裡留它
// 只是給探測者一個「這枚秘密對應誰」的旁證。撤銷是否實際發生、是否幂等，
// 由 2xx 與（Web 路徑的）刪除指令共同表達，不需要額外欄位。
type logoutResponse struct {
	RequestID string `json:"request_id"`
}

// authEndpoints 回傳 auth 端點登記清單；未注入用例時為空。
//
// 掛在 apiRoutes 的登記流裡，「/auth 首段屬於 API」因此自動成立，
// 深連結回退不會把登入路徑誤當頁面。
func (s *Server) authEndpoints() []apiRoute {
	if s.auth == nil {
		return nil
	}
	return []apiRoute{
		{"/auth/login", s.allowMethods(s.handleLogin, http.MethodPost)},
		{"/auth/root/login", s.allowMethods(s.handleRootLogin, http.MethodPost)},
		{"/auth/session", s.allowMethods(s.handleSession, http.MethodGet, http.MethodHead)},
		{"/auth/logout", s.allowMethods(s.handleLogout, http.MethodPost)},
	}
}

// handleLogin 處理普通帳戶登入：POST /auth/login。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	if !s.allowRequestOrigin(r) {
		writeError(w, r, CodeOriginForbidden, http.StatusForbidden)
		return
	}
	var in loginRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	outcome, err := s.auth.LoginAccount(r.Context(), in.LoginName, in.Password,
		requestIDFromRequest(r), remoteHost(r))
	if err != nil {
		s.writeLoginFailure(w, r, err)
		return
	}
	s.setSessionCookie(w, r, outcome.Session, outcome.Secret)
	body := s.loginResponseFor(outcome)
	body.RequestID = requestIDFromRequest(r)
	writeJSON(w, http.StatusOK, body)
}

// handleRootLogin 處理 Root 登入：POST /auth/root/login。
//
// 與帳戶端點分開的意義在「分流由端點承擔」：這個端點的校驗物件是組態裡的 Root 憑據，
// accounts 表全程不被觸及；反過來 /auth/login 也永遠到不了 Root 憑據。
// 兩條路對外的失敗結論同形（2001），探測者從回應上分不出打的是哪一扇門。
func (s *Server) handleRootLogin(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	if !s.allowRequestOrigin(r) {
		writeError(w, r, CodeOriginForbidden, http.StatusForbidden)
		return
	}
	var in rootLoginRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	outcome, err := s.auth.LoginRoot(r.Context(), in.Password,
		requestIDFromRequest(r), remoteHost(r))
	if err != nil {
		s.writeLoginFailure(w, r, err)
		return
	}
	s.setSessionCookie(w, r, outcome.Session, outcome.Secret)
	body := s.loginResponseFor(outcome)
	body.RequestID = requestIDFromRequest(r)
	writeJSON(w, http.StatusOK, body)
}

// handleSession 回報當前會話：GET /auth/session。
//
// 它是 Cookie／Bearer 防護鏈的最小消費點：解析、獨佔判定、失效清除都發生在
// resolveSession 這個共用入口裡，未來的退出與業務端點調同一個函式，
// 而不是各寫一份「先看 Cookie 再看標頭」的順序。
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	resolved, ok := s.resolveSession(w, r)
	if !ok {
		return
	}
	body := sessionResponse{
		SubjectKind:  subjectKindOf(resolved.Principal),
		DeviceID:     resolved.Session.DeviceID.String(),
		CreatedAt:    timeutil.FormatUTC(resolved.Session.CreatedAt),
		LastActiveAt: timeutil.FormatUTC(resolved.Session.LastActiveAt),
		ExpiresAt:    timeutil.FormatUTC(resolved.Session.ExpiresAt),
		RequestID:    requestIDFromRequest(r),
	}
	if id := resolved.Principal.AccountID(); !id.IsNil() {
		body.AccountID = id.String()
	}
	writeJSON(w, http.StatusOK, body)
}

// handleLogout 撤銷當前請求所綁定的會話：POST /auth/logout。
//
// 這是「退出必須讓伺服器端會話失效，而不只是清前端標記」那条要求的落點：
//  1. 有副作用的方法——先過 allowRequestOrigin（CSRF 來源策略），避免跨站 forced logout；
//  2. 憑據解析走共用的 resolveCredentials 一份入口——Cookie／Bearer 獨佔判定
//     與「會話換主體」的規則與 /auth/session 逐字相同，不會出現「退出绕過混用校驗」的平行語意；
//  3. 有效會話：交會話层的 Logout 用例（Root 同交易追加 root_audit 的 auth.logout；
//     普通帳戶只進執行日誌）。Web 路徑順帶下發刪除指令，讓瀏覽器真正丟掉 Cookie；
//     原生路徑的秘密由客戶端自己保管與刪除，伺服器不發無意義的 Cookie；
//  4. 無憑據（credAbsent）或憑據已失效（credInvalid）：都是幂等 no-op——目標狀態
//     （這枚憑據不再換得出身份）本已達成，一律 2xx、不創建任何新會話、
//     不報 2003「請重新登入」。Web 路徑仍在回應裡附刪除指令，讓下一次請求乾乾淨淨。
//
// 冪等的邊界：本端點只撤銷「本請求憑據所指向的那一枚會話」——不做全設備退出，
// 因為那是另一個產品決定（需要 RevokeSubject 加可信的多設備清單 UI）。
//
// 503／500 與 /auth/session 同形：未注入用藥、資料庫不可用都不做靜默降級。
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	if !s.allowRequestOrigin(r) {
		writeError(w, r, CodeOriginForbidden, http.StatusForbidden)
		return
	}
	res := s.resolveCredentials(r)
	switch res.status {
	case credOK:
		// 有效會話：交撤銷用例；冪等收斂（ErrNotFound）在用例內已是 nil。
		if err := s.auth.Logout(r.Context(), res.resolved.Principal, res.resolved.Session,
			requestIDFromRequest(r)); err != nil {
			// 到這裡只剩資料庫故障這類非拒絕錯誤：回 500，細節只進日誌。
			s.logger.Error("登出撤銷失敗", "request_id", requestIDFromRequest(r), "err", err)
			writeError(w, r, CodeUnknown, http.StatusInternalServerError)
			return
		}
		if res.viaCookie {
			http.SetCookie(w, s.clearedSessionCookie(r))
		}
		writeJSON(w, http.StatusOK, logoutResponse{RequestID: requestIDFromRequest(r)})
		return
	case credAbsent, credInvalid:
		// 幂等：沒有可撤銷的活會話，或目標憑據早已不在——一律 2xx。
		if res.viaCookie {
			http.SetCookie(w, s.clearedSessionCookie(r))
		}
		writeJSON(w, http.StatusOK, logoutResponse{RequestID: requestIDFromRequest(r)})
		return
	case credNotReady:
		writeError(w, r, CodeNotReady, http.StatusServiceUnavailable)
		return
	case credConflict:
		writeError(w, r, CodeAuthMethodConflict, http.StatusBadRequest)
		return
	case credUnavailable:
		// resolveCredentials 已把內部原因進日誌；這裡只寫对外回應。
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		return
	}
}

// writeLoginFailure 把登入用例的錯誤對映為對外回應：
// 拒絕收斂為 2001，限流收斂為 2006（附 Retry-After），其餘（資料庫故障等）屬內部缺陷——
// 統一 500，細節只進日誌。
//
// 2001 與 2006 的界線就是「現在重試有沒有意義」：前者口令再來一百次也是錯，
// 後者等冷卻到期就有全新預算。兩者都只有一句固定文案，沒有 details——
// 限流回應不允許以任何形式指出被擋的是哪個帳戶（規格要求同形）。
func (s *Server) writeLoginFailure(w http.ResponseWriter, r *http.Request, err error) {
	var throttled *auth.ThrottledError
	if errors.As(err, &throttled) {
		seconds := int64(math.Ceil(throttled.RetryAfter.Seconds()))
		if seconds < 1 {
			// 冷卻只剩不足一秒：報 0 秒會被讀成「立刻再試」，寧可多等一粒鐘。
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeError(w, r, CodeLoginThrottled, http.StatusTooManyRequests)
		return
	}
	if errors.Is(err, auth.ErrInvalidCredentials) {
		writeError(w, r, CodeInvalidCredentials, http.StatusUnauthorized)
		return
	}
	s.logger.Error("登入處理失敗", "request_id", requestIDFromRequest(r), "err", err)
	writeError(w, r, CodeUnknown, http.StatusInternalServerError)
}

// loginResponseFor 產生登入成功回應本體（秘密不在這裡，見 loginResponse 註解）。
func (s *Server) loginResponseFor(outcome auth.Outcome) loginResponse {
	body := loginResponse{
		SubjectKind: subjectKindOf(outcome.Principal),
		DeviceID:    outcome.Session.DeviceID.String(),
		ExpiresAt:   timeutil.FormatUTC(outcome.Session.ExpiresAt),
	}
	if id := outcome.Principal.AccountID(); !id.IsNil() {
		body.AccountID = id.String()
	}
	return body
}

// subjectKindOf 把主體類別換成對外表示。只有兩類能拿到會話，
// default 分支是缺陷信號而不是第三種可選值。
func subjectKindOf(p identity.Principal) string {
	switch {
	case p.IsRoot():
		return string(session.SubjectRoot)
	case p.Kind() == identity.KindAccount:
		return string(session.SubjectAccount)
	default:
		return string(identity.KindAnonymous)
	}
}

// noStore 禁止認證回應被快取：登入與當前會話的內容都是「此刻的主體狀態」，
// 任何中間快取（瀏覽器、代理）留存它們，等於把一枚已過期的可信讀寫留給下一個請求。
func (s *Server) noStore(w http.ResponseWriter) {
	w.Header().Set(cacheControlHeader, "no-store")
}

// requestOriginOf 還原本請求自身的來源（scheme://host），用於同源比對。
//
// scheme 以實際連線是否 TLS 為準：這是與 Cookie 的 Secure 屬性同一個判定來源，
// 兩處若各猜各的，會出現「Cookie 標成 Secure 而來源判定按 http」的分裂。
func (s *Server) requestOriginOf(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// allowRequestOrigin 是來源（CSRF）策略的唯一判定點，供全部有副作用的端點複用。
//
// 判定順序與理由：
//  1. 安全方法（GET/HEAD/OPTIONS）直接透過——CSRF 防的是「改變伺服器狀態的跨站請求」，
//     對只讀請求拒絕只會誤傷 <img> 之外的正常導航（會話副作用由端點自己承諾）；
//  2. Sec-Fetch-Site: cross-site 先拒：這是瀏覽器對「我從別的站點發起的」的自證，
//     比 Origin 更難被某些剝奪 Origin 的舊式剝削手法繞過；同源／同站／none 放進下一輪；
//  3. Origin 預設視為非瀏覽器客戶端（原生、curl）：瀏覽器對跨站請求必定附 Origin，
//     對同站 POST 至少附 same-origin 語意，缺失只剩非瀏覽器一種解釋；
//  4. 同源比對：Origin 必須逐字等於 requestOriginOf（scheme+host，含埠）；
//  5. 落空後查組態跨域白名單：白名單是部署者明確放寬的開發來源，放行它等於放行
//     該來源的請求到達端點——但 Cookie 的 SameSite 仍由瀏覽器把關，
//     跨站 Cookie 在 HTTP 下本來就發不出去，這裡不假裝能繞過。
func (s *Server) allowRequestOrigin(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get(secFetchSiteHeader)), crossSiteDirective) {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get(originHeader))
	if origin == "" {
		return true
	}
	if strings.EqualFold(origin, s.requestOriginOf(r)) {
		return true
	}
	return s.cors.allowOrigin(strings.ToLower(origin))
}

// parseBearerToken 從 Authorization 標頭取出 Bearer 秘密；不存在或形狀不合格時回 false。
//
// scheme 比對不分大小寫（RFC 7235 的 token 比較規定），但整個值只准兩段：
// 「Bearer 多個空格」「Basic xxx」都算不存在 Bearer——寧可判「沒帶」走匿名拒絕，
// 也不把含糊的標頭內容猜成一種認證方式。
func parseBearerToken(header string) (string, bool) {
	scheme, rest, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, strings.TrimSpace(bearerScheme)) {
		return "", false
	}
	token := strings.TrimSpace(rest)
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}
	return token, true
}

// resolvedSession 是透過驗證的會話與其主體。
type resolvedSession struct {
	Principal identity.Principal
	Session   session.Session
	// ViaCookie 記錄本次憑據的來路：失效時只有 Cookie 路徑需要發刪除指令
	// （Bearer 客戶端自己保管秘密，伺服器單方面發 Cookie 沒有意義）。
	ViaCookie bool
}

// credentialStatus 是「請求 → 憑據 → 會話」解析的結論，供不同端點各自映射对外回應。
//
// 分成這個列舉而不是一路寫到 writeError，是因為登出要能在「無憑據」與「憑據已失效」
// 上把幂等 no-op 報成 2xx，而 /auth/session 這類只讀端點必須把同一件事報成 2002／2003——
// 解析規則只有一份（杜絕兩套 Cookie／Bearer 判定），错误映射則按端點職責分岔。
type credentialStatus int

const (
	// credOK 解析出一個有效的會話；resolved 欄位可用。
	credOK credentialStatus = iota
	// credNotReady 未注入登入用例（等同服務尚未具備該能力）。
	credNotReady
	// credConflict 認證方式混用（Cookie＋Bearer，或瀏覽器帶 Origin 企圖用 Bearer）。
	credConflict
	// credAbsent 請求沒有任何憑據。
	credAbsent
	// credInvalid 帶了憑據但伺服器判定它換不出身分（撤銷／過期／主體不可用）。
	credInvalid
	// credUnavailable 非拒絕類故障（資料庫等）：屬內部缺陷，不回 4xx。
	credUnavailable
)

// credentialResolution 是一次憑據解析的結果。
type credentialResolution struct {
	status    credentialStatus
	viaCookie bool
	resolved  resolvedSession // 僅 credOK 有效
}

// resolveCredentials 是「請求 → 會話 → 主體」的唯一解析核心：讀取、獨佔判定、
// 驗證全部發生在這裡，但不寫任何 HTTP 回應——回應的形态由呼叫端依端點職責決定。
//
// resolveSession 與 handleLogout 都調這一處，因此 Cookie／Bearer 的順序、混用拒絕、
// 「帶 Origin 不準用 Bearer」與「拿秘密換主體」的規則在全服務只有一份實作。
func (s *Server) resolveCredentials(r *http.Request) credentialResolution {
	if s.auth == nil {
		return credentialResolution{status: credNotReady}
	}

	cookie, cookieErr := r.Cookie(sessionCookieName)
	hasCookie := cookieErr == nil && cookie.Value != ""
	bearer, hasBearer := parseBearerToken(r.Header.Get(authorizationHeader))

	switch {
	case hasCookie && hasBearer:
		// 混用即拒：讓 Cookie 請求繞過來源校驗的唯一通路就是「再帶一枚 Bearer」。
		return credentialResolution{status: credConflict}
	case hasBearer && r.Header.Get(originHeader) != "":
		// 瀏覽器請求（任何 Origin，含同源）禁用 Bearer：瀏覽器路徑的會話由
		// HttpOnly Cookie 獨佔，這條規則把「認證方式選擇」從客戶端手裡收走。
		return credentialResolution{status: credConflict}
	}

	var secret string
	viaCookie := false
	switch {
	case hasCookie:
		secret, viaCookie = cookie.Value, true
	case hasBearer:
		secret = bearer
	default:
		return credentialResolution{status: credAbsent, viaCookie: viaCookie}
	}

	principal, sess, err := s.auth.Resolve(r.Context(), secret)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidSession) {
			return credentialResolution{status: credInvalid, viaCookie: viaCookie}
		}
		s.logger.Error("會話解析失敗", "request_id", requestIDFromRequest(r), "err", err)
		return credentialResolution{status: credUnavailable, viaCookie: viaCookie}
	}
	return credentialResolution{
		status:    credOK,
		viaCookie: viaCookie,
		resolved:  resolvedSession{Principal: principal, Session: sess, ViaCookie: viaCookie},
	}
}

// resolveSession 是 /auth/session 這類端點使用的「解析並寫錯誤」入口：
// 呼叫端拿到 true 時一定有可信主體，拿到 false 時回應已由本函式寫好、必須立即返回。
//
// 「回傳 false 時錯誤已寫出」這條約定讓「忘了判錯誤」在呼叫點無從發生
// （拿不到主體就寫不出回應）。它只把 resolveCredentials 的結論對映成既有合同
// 的 2002／2003／2004／500／503，行為與 R1-009 發布時逐字一致。
func (s *Server) resolveSession(w http.ResponseWriter, r *http.Request) (resolvedSession, bool) {
	res := s.resolveCredentials(r)
	switch res.status {
	case credOK:
		return res.resolved, true
	case credNotReady:
		writeError(w, r, CodeNotReady, http.StatusServiceUnavailable)
	case credConflict:
		writeError(w, r, CodeAuthMethodConflict, http.StatusBadRequest)
	case credAbsent:
		writeError(w, r, CodeNotAuthenticated, http.StatusUnauthorized)
	case credInvalid:
		if res.viaCookie {
			// 順帶下發刪除指令：無效 Cookie 留在瀏覽器裡，只會讓下一次請求
			// 再撞同一堵牆；清掉它，客戶端的「重新登入」引導才乾淨。
			http.SetCookie(w, s.clearedSessionCookie(r))
		}
		writeError(w, r, CodeSessionInvalid, http.StatusUnauthorized)
	case credUnavailable:
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
	return resolvedSession{}, false
}

// setSessionCookie 寫入會話 Cookie。
//
// Secure 只跟實際 TLS：區域網 HTTP 是批准部署形態，強制 Secure 等於把瀏覽器
// 登入整個弄停。CSRF 不靠 Secure——靠 SameSite=Lax 加 allowRequestOrigin 的來源判定，
// 兩層在 HTTP 下都成立（SameSite 的「站點」定義不看協議）。
// Path 固定根路徑：全域只有一枚會話 Cookie，作用域切得越細，
// 「哪個端點該帶哪枚 Cookie」就越會變成各端點各記一套的隱形規則。
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, sess session.Session, secret string) {
	seconds := int(sess.ExpiresAt.Sub(s.clock.Now()).Seconds())
	if seconds < 1 {
		// 理論不可達（會話剛建），但時鐘回撥類故障若造出非正壽命，
		// 寧可發一枚 1 秒就過期的 Cookie 也不發刪除指令——後者會被讀成「登出成功」。
		seconds = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    secret,
		Path:     "/",
		Expires:  sess.ExpiresAt.UTC(),
		MaxAge:   seconds,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearedSessionCookie 產生刪除指令（Max-Age=-1），屬性組合與簽發時逐字一致——
// 瀏覽器的 Cookie 替換按「同名同域同路徑」匹配，路徑寫錯一位就刪不掉。
func (s *Server) clearedSessionCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	}
}
