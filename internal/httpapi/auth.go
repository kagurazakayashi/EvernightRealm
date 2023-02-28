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
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
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
	// RotateSession 用一枚當代會話秘密換發一枚新秘密（同一行、同一裝置、同一絕對期限）。
	// 授權就是那枚秘密本身：呼叫端不得先把請求裡任何可自報的欄位當成身分。
	RotateSession(ctx context.Context, secret, requestID string) (auth.Outcome, error)
	// ListDevices 列舉當前受信主體名下的全部裝置（會話）。
	// 範圍只由主體決定：請求裡沒有任何欄位可以改寫「列誰的裝置」，包括 account_id。
	ListDevices(ctx context.Context, principal identity.Principal) ([]session.Session, error)
	// RevokeDevice 在當前主體的範圍內按 device_id 撤銷一枚會話（撤銷他人/不存在一律
	// 收斂為 session.ErrNotFound）。呼叫端必須先讓本次請求的憑據過一次解析，
	// 才拿得到 principal——這是「敏感操作重檢當前會話有效」的落點。
	RevokeDevice(ctx context.Context, principal identity.Principal, deviceID idgen.ID, requestID string) (auth.DeviceRevokeResult, error)
	// ChangePassword 更換「剛經解析換回主體」的本人口令，並按其名下全部會話。
	// 呼叫端必須先帶本次請求的憑據過解析、並在請求本體裡交出現行口令——
	// 「會話還活著」從來不是改密的授權，再認證是口令本身。
	ChangePassword(ctx context.Context, principal identity.Principal,
		currentPassword, newPassword, requestID string) (auth.PasswordChangeResult, error)
	// MustChangePassword 現讀該主體是否仍帶有「首次登入必須改密」旗標。
	// 逐請求現讀（不是會話簽發時的快照）：改密成功後的下一個請求就該看到解除。
	MustChangePassword(ctx context.Context, principal identity.Principal) (bool, error)
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
	// AccountType 是帳戶主體的類型（standard|guest）；Root 與匿名主體欄位缺席。
	//
	// 它是只增不刪的相容演進，存在的意義與 Roles 同族——「客戶端不必猜自己是哪一類人」：
	// subject_kind 只分 account／root（會話形態），而「這一趟是不是臨時受限身分」
	// 由這一欄給出，界面據此決定摘要卡講「訪客（臨時身分）」還是講「普通帳戶」。
	// 它不是權限的依據（每一次判定的真相仍在 internal/identity.Authorize），
	// 也不受會話簽發時的快照束縛：它是解析階段的現讀帳戶事實（見 sessionResponse 同名欄位）。
	AccountType string `json:"account_type,omitempty"`
	DeviceID    string `json:"device_id"`
	ExpiresAt   string `json:"expires_at"`
	// MustChangePassword 是帳戶旗標的現讀值（只增不刪的合同演進）：為 true 時
	// 客戶端必須先把人帶進改密流程——受保護功能在服務端本來就被 2010 擋著，
	// 這個欄位的意義是讓界面能主動講對句話，而不是讓人撞上去才知道。
	// 為 false 時欄位缺席（omitempty）：Root 與已完成義務的帳戶都讀不到它，
	// 客戶端按「缺席即 false」解讀即可。
	MustChangePassword bool `json:"must_change_password,omitempty"`
	// Roles 是服務端現讀到的伺服器級角色授予（只增不刪的合同演進；無授予時欄位缺席）。
	//
	// 它存在的意義是「客戶端不必猜自己是誰」：主體類別只分 account／root（會話形态），
	// 而「這個帳戶能不能做維運」由這裡給出，前端據此載入入口。它不是權限的依據——
	// 每一次判定的真相仍在服務端（見 internal/identity.Authorize），
	// 回應裡的這個清單只是可展示事實，改它不會讓任何端點放行。
	Roles     []string `json:"roles,omitempty"`
	RequestID string   `json:"request_id"`
}

// sessionResponse 是「當前會話」的回應本體，在登入回應之上多帶建立與最近活動時刻。
//
// rotation_seq 是後來增補的欄位（只增不刪的相容策略）：它讓客戶端能把「手上這一枚
// 是第幾代」與伺服器的權威事實對上一次，於是一次丟失的輪換回應可以被查出來，
// 而不是讓客戶端只能靠猜。
type sessionResponse struct {
	SubjectKind string `json:"subject_kind"`
	AccountID   string `json:"account_id,omitempty"`
	// AccountType 同 loginResponse：帳戶主體的類型（standard|guest），非帳戶主體缺席。
	// 這一端點是「刷新與重開之後界面還認不認得自己是訪客」的唯一依據，
	// 少了它，恢復過來的會話會被唸成普通帳戶——那是一句不準確的話。
	AccountType  string `json:"account_type,omitempty"`
	DeviceID     string `json:"device_id"`
	RotationSeq  int64  `json:"rotation_seq"`
	CreatedAt    string `json:"created_at"`
	LastActiveAt string `json:"last_active_at"`
	ExpiresAt    string `json:"expires_at"`
	// MustChangePassword 同 loginResponse：現讀的帳戶旗標，false 時欄位缺席。
	// /auth/session 永遠不被本旗標擋（它正是客戶端得知「還欠一次改密」的入口），
	// 這也讓「改密成功後刷新即放行」有一條單一的可輪詢事實來源。
	MustChangePassword bool `json:"must_change_password,omitempty"`
	// Roles 同 loginResponse：服務端現讀到的伺服器級角色授予，無授予時欄位缺席。
	Roles     []string `json:"roles,omitempty"`
	RequestID string   `json:"request_id"`
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
		{"/auth/session/rotate", s.allowMethods(s.handleRotate, http.MethodPost)},
		{"/auth/devices", s.allowMethods(s.handleDevices, http.MethodGet, http.MethodHead)},
		{"/auth/devices/revoke", s.allowMethods(s.handleDeviceRevoke, http.MethodPost)},
		{"/auth/password/change", s.allowMethods(s.handlePasswordChange, http.MethodPost)},
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
		AccountType:  accountTypeOf(resolved.Principal),
		DeviceID:     resolved.Session.DeviceID.String(),
		RotationSeq:  resolved.Session.RotationSeq,
		CreatedAt:    timeutil.FormatUTC(resolved.Session.CreatedAt),
		LastActiveAt: timeutil.FormatUTC(resolved.Session.LastActiveAt),
		ExpiresAt:    timeutil.FormatUTC(resolved.Session.ExpiresAt),
		Roles:        rolesOf(resolved.Principal),
		RequestID:    requestIDFromRequest(r),
	}
	if id := resolved.Principal.AccountID(); !id.IsNil() {
		body.AccountID = id.String()
	}
	// 旗標現讀：這一端點是客戶端得知「還欠改密」的唯一入口，本身必須永遠可讀——
	// 讀取失敗屬內部故障（照 500 報），不借「還沒改密」的名義把人擋在門外。
	mustChange, err := s.auth.MustChangePassword(r.Context(), resolved.Principal)
	if err != nil {
		s.logger.Error("讀取必須改密旗標失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		return
	}
	body.MustChangePassword = mustChange
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
	case credStale:
		// 落後一代的憑據不該能撤銷一個還活著的會話：那是把「舊秘密被看到」
		// 變成「使用者被踢下線」的服務中斷通路。冪等的好意圖只在「目標本就失效」時成立，
		// 這裡目標並沒有失效，所以老實報 2007，不做任何撤銷。
		writeError(w, r, CodeSessionStale, http.StatusUnauthorized)
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

// rotateResponse 是輪換成功的回應本體。
//
// 與 loginResponse 同一套缺席規則：新秘密不在這裡（只在 Set-Cookie），
// 會話內部標識也不在這裡。rotation_seq 是計數器而不是秘密，可以公開給
// 自己的客戶端——它存在的意義就是讓客戶端判得出一個回應描述的是哪一代憑據，
// 從而不讓倒序送達的舊響應蓋掉手上更新的那一枚。
type rotateResponse struct {
	SubjectKind string `json:"subject_kind"`
	AccountID   string `json:"account_id,omitempty"`
	DeviceID    string `json:"device_id"`
	RotationSeq int64  `json:"rotation_seq"`
	ExpiresAt   string `json:"expires_at"`
	RequestID   string `json:"request_id"`
}

// handleRotate 換髮新會話秘密：POST /auth/session/rotate。
//
// 這個端點做的事只有一件：把「本請求憑據指向的那一枚會話」的秘密換代。
// 它的關鍵語義都寫在用例與會話層裡，這裡只負責協議層該負責的四件事：
//  1. 有副作用的方法——先過 allowRequestOrigin（CSRF 來源策略），不讓跨站頁面
//     替使用者換掉秘密並把後續請求打成失敗；
//  2. 憑據解析走共用的 resolveCredentials 一份入口：Cookie／Bearer 獨佔判定、
//     「帶 Origin 不準用 Bearer」與「拿秘密換主體」的規則與 /auth/session 逐字相同；
//  3. 新秘密只經 setSessionCookie 送出（與登入同一條分發通路：Web 由瀏覽器代管，
//     原生客戶端從 Set-Cookie 讀取後改用 Bearer 回傳），回應本體只有可展示的
//     事實與世代號；屬性組合（HttpOnly／SameSite／Secure／Path）也與簽發時一致，
//     瀏覽器按同名同域同路徑替換，輪換才不會變成「多出第二枚 Cookie」；
//  4. 失敗按端點職責分流，不復制一套：未帶憑據 2002、混用 2004、來源不符 2005、
//     憑據已失效 2003（Web 順帶刪除指令）、落後一代 2007（不發刪除指令，見 resolveSession）。
//
// 沒有 grace window、沒有請求體：請求裡沒有任何可自報的欄位，因此也沒有
// 「客戶端聲稱自己要換哪一枚」這種越權空間。
func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	if !s.allowRequestOrigin(r) {
		writeError(w, r, CodeOriginForbidden, http.StatusForbidden)
		return
	}
	res := s.resolveCredentials(r)
	switch res.status {
	case credOK:
		if !s.requirePasswordChangeDone(w, r, res.resolved.Principal) {
			return
		}
		// 到這裡res.secret 已是「當代」憑據：Resolve 成功意味著它此刻換得出身份。
		outcome, err := s.auth.RotateSession(r.Context(), res.secret, requestIDFromRequest(r))
		if err != nil {
			s.writeRotationFailure(w, r, err, res.viaCookie)
			return
		}
		s.setSessionCookie(w, r, outcome.Session, outcome.Secret)
		body := rotateResponse{
			SubjectKind: subjectKindOf(outcome.Principal),
			DeviceID:    outcome.Session.DeviceID.String(),
			RotationSeq: outcome.Session.RotationSeq,
			ExpiresAt:   timeutil.FormatUTC(outcome.Session.ExpiresAt),
			RequestID:   requestIDFromRequest(r),
		}
		if id := outcome.Principal.AccountID(); !id.IsNil() {
			body.AccountID = id.String()
		}
		writeJSON(w, http.StatusOK, body)
		return
	case credAbsent:
		writeError(w, r, CodeNotAuthenticated, http.StatusUnauthorized)
		return
	case credInvalid:
		// 失效憑據在瀏覽器裡只會讓下一次請求再撞同一堵牆，清掉它；
		// 這裡的刪除指令不撤銷任何東西，也不簽發新會話。
		if res.viaCookie {
			http.SetCookie(w, s.clearedSessionCookie(r))
		}
		writeError(w, r, CodeSessionInvalid, http.StatusUnauthorized)
		return
	case credStale:
		writeError(w, r, CodeSessionStale, http.StatusUnauthorized)
		return
	case credNotReady:
		writeError(w, r, CodeNotReady, http.StatusServiceUnavailable)
		return
	case credConflict:
		writeError(w, r, CodeAuthMethodConflict, http.StatusBadRequest)
		return
	case credUnavailable:
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		return
	}
}

// deviceResponse 是「我的裝置」清單裡的一枚裝置。
//
// 只帶可展示事實：裝置標識、建立／最近活動／到期時刻、推導狀態、是否本請求所用的這一臺。
// 刻意不帶的：任何憑據材料（库里本就只有雜湊，見 secret.go）、內部會話 ID、來源位址
// 與瀏覽器指紋——後兩項本服務根本沒有採集（見遷移 0004 的欄位），因此無從洩露。
// device_id 即使用者可見的裝置展示名：它帶了 UNIQUE 約束、隨機 UUIDv7，看到也換不來任何
// 操作能力（認證只認秘密），所以可以放心展示與用於指認撤銷目標。
type deviceResponse struct {
	DeviceID     string `json:"device_id"`
	CreatedAt    string `json:"created_at"`
	LastActiveAt string `json:"last_active_at"`
	ExpiresAt    string `json:"expires_at"`
	Status       string `json:"status"`
	Current      bool   `json:"current"`
}

// deviceListResponse 是 GET /auth/devices 的回應本體。
type deviceListResponse struct {
	Devices   []deviceResponse `json:"devices"`
	RequestID string           `json:"request_id"`
}

// deviceRevokeRequest 是定向撤銷的請求本體：只准帶目標裝置標識。
// 沒有任何可自報的 account_id／主體類別欄位——歸屬由解析出來的受信主體決定，
// 多帶的欄位會被 decodeJSON 的未知欄位規則打成 1004。
type deviceRevokeRequest struct {
	DeviceID string `json:"device_id"`
}

// deviceRevokeResponse 是撤銷成功的回應本體。
//
// Revoked 區分「這次真的停掉了一枚原本有效的會話」與「目標本就已是失效態」（冪等 no-op）；
// Current 告訴呼叫端「剛撤的是不是自己這臺」——為 true 時客戶端要進入退出態。
type deviceRevokeResponse struct {
	DeviceID  string `json:"device_id"`
	Revoked   bool   `json:"revoked"`
	Current   bool   `json:"current"`
	RequestID string `json:"request_id"`
}

// handleDevices 列舉當前主體自己的裝置：GET /auth/devices。
//
// 這是 Cookie／Bearer 防護鏈又一個只讀消費點：解析走共用的 resolveSession，
// 未帶憑據 2002、失效 2003、混用 2004、上一代 2007 全部沿用既有合同，不另起一套。
// 查詢範圍來自解析出的受信主體（見 auth.ListDevices），因此「改一個 account_id 就看到
// 別人裝置」在這條路上沒有入口——GET 沒有任何請求體。
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	resolved, ok := s.resolveSession(w, r)
	if !ok {
		return
	}
	if !s.requirePasswordChangeDone(w, r, resolved.Principal) {
		return
	}
	list, err := s.auth.ListDevices(r.Context(), resolved.Principal)
	if err != nil {
		s.logger.Error("列舉裝置失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		return
	}
	now := s.clock.Now()
	currentDevice := resolved.Session.DeviceID.String()
	items := make([]deviceResponse, 0, len(list))
	for _, sess := range list {
		items = append(items, deviceResponse{
			DeviceID:     sess.DeviceID.String(),
			CreatedAt:    timeutil.FormatUTC(sess.CreatedAt),
			LastActiveAt: timeutil.FormatUTC(sess.LastActiveAt),
			ExpiresAt:    timeutil.FormatUTC(sess.ExpiresAt),
			Status:       string(sess.State(now)),
			Current:      sess.DeviceID.String() == currentDevice,
		})
	}
	writeJSON(w, http.StatusOK, deviceListResponse{
		Devices:   items,
		RequestID: requestIDFromRequest(r),
	})
}

// handleDeviceRevoke 撤銷當前主體名下的一枚裝置：POST /auth/devices/revoke。
//
// 四道關卡，逐字複用既有策略，不新造第二套：
//  1. 有副作用的方法——先過 allowRequestOrigin（CSRF 來源策略）；
//  2. 憑據解析走共用的 resolveCredentials，credOK 意味著「本次請求的憑據此刻仍換得出身份」——
//     這正是敏感操作要求的「重檢當前會話有效」，不是拿到一個舊 principal 就放行；
//  3. 目標 device_id 經 idgen 解析，形狀不合格屬客戶端輸入錯誤，回 1004（不對外猜它是誰的）；
//  4. 撤銷落在本主體範圍內（auth.RevokeDevice），別人的 device_id 與不存在的 device_id
//     收斂為同一個 ErrNotFound → 2009，給「列表已陳舊」這句真實提示而不洩露存在性。
//
// 撤銷的正是本請求這一臺時：該行已被撤銷，本憑據再換不出身份；Web 路徑順帶下發刪除指令
// （與登出同一條通路），Current=true 讓客戶端進入退出態。撤銷別的裝置不影響本會話，
// Current=false、不發刪除指令。冪等：重複撤銷同一枚早已失效的裝置回 200 且 revoked=false。
func (s *Server) handleDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	if !s.allowRequestOrigin(r) {
		writeError(w, r, CodeOriginForbidden, http.StatusForbidden)
		return
	}
	res := s.resolveCredentials(r)
	switch res.status {
	case credOK:
		if !s.requirePasswordChangeDone(w, r, res.resolved.Principal) {
			return
		}
		var in deviceRevokeRequest
		if !decodeJSON(w, r, &in) {
			return
		}
		deviceID, err := idgen.Parse(in.DeviceID)
		if err != nil {
			// 形狀不合格的 device_id 是請求本體錯誤，不是「查無此裝置」：
			// 客戶端連一個合法標識都沒給出來，沒有可歸屬的目標可言。
			writeError(w, r, CodeInvalidBody, http.StatusBadRequest)
			return
		}
		result, err := s.auth.RevokeDevice(r.Context(), res.resolved.Principal, deviceID,
			requestIDFromRequest(r))
		if err != nil {
			if errors.Is(err, session.ErrNotFound) {
				writeError(w, r, CodeDeviceNotFound, http.StatusNotFound)
				return
			}
			s.logger.Error("撤銷裝置失敗", "request_id", requestIDFromRequest(r), "err", err)
			writeError(w, r, CodeUnknown, http.StatusInternalServerError)
			return
		}
		current := result.Session.DeviceID.String() == res.resolved.Session.DeviceID.String()
		if res.viaCookie && result.Revoked && current {
			http.SetCookie(w, s.clearedSessionCookie(r))
		}
		writeJSON(w, http.StatusOK, deviceRevokeResponse{
			DeviceID:  result.Session.DeviceID.String(),
			Revoked:   result.Revoked,
			Current:   current,
			RequestID: requestIDFromRequest(r),
		})
		return
	case credAbsent:
		writeError(w, r, CodeNotAuthenticated, http.StatusUnauthorized)
		return
	case credInvalid:
		if res.viaCookie {
			http.SetCookie(w, s.clearedSessionCookie(r))
		}
		writeError(w, r, CodeSessionInvalid, http.StatusUnauthorized)
		return
	case credStale:
		writeError(w, r, CodeSessionStale, http.StatusUnauthorized)
		return
	case credNotReady:
		writeError(w, r, CodeNotReady, http.StatusServiceUnavailable)
		return
	case credConflict:
		writeError(w, r, CodeAuthMethodConflict, http.StatusBadRequest)
		return
	case credUnavailable:
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		return
	}
}

// requirePasswordChangeDone 是「首次登入必須改密」在服務端的執行點：帶有旗標的帳戶
// 只準訪問完成改密與退出所需的入口，其餘已認證端點在這裡統一喫 2010。
//
// 為什麼閘必須在這裡而不是界面：規格裏「必須改密」這句話的強度，等於它在
// 最直接的繞過路徑（不看界面的呼叫者）面前還剩多少。藏按鈕從來不是授權，
// 提示也不是——只有每一個受保護端點在每一次請求上現讀旗標，「只能訪問必要入口」
// 才是事實。必要入口的清單此刻是：/auth/session（得知欠改）、/auth/logout（退出）、
// /auth/password/change（還清義務）；三者之外一律擋，未來新增的業務端點接同一條
// resolve 通路時也調用這把閘，不在各處另寫一份「他改過密了沒有」。
// 判定現讀帳戶行（見 AuthUseCase.MustChangePassword）：改密成功的下一個請求即放行。
// 回傳 false 時回應已由本函式寫好，呼叫端必須立即返回。
func (s *Server) requirePasswordChangeDone(w http.ResponseWriter, r *http.Request, principal identity.Principal) bool {
	mustChange, err := s.auth.MustChangePassword(r.Context(), principal)
	if err != nil {
		// 「查不出旗標」不能當成「沒欠改密」放行，也不能借 2010 的名義拒絕——
		// 那是把內部故障僞裝成一個會誤導排查方向的策略結論。照 500 報，細節進日誌。
		s.logger.Error("讀取必須改密旗標失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		return false
	}
	if mustChange {
		writeError(w, r, CodePasswordChangeRequired, http.StatusForbidden)
		return false
	}
	return true
}

// passwordChangeRequest 是本人改密的請求本體：只準帶現行口令與新口令。
// 沒有任何可自報的 account_id／主體類別——改誰由憑據解析出的受信主體決定，
// 多帶的欄位被 decodeJSON 的未知欄位規則打成 1004。
type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// passwordChangeResponse 是改密成功的回應本體。
//
// 刻意不回任何「新憑據相關」的東西：新口令不復述，帳戶與會話內部標識也不 echo。
// revoked_sessions 是本人名下會話的數量——改密已讓全部失效（已批準策略），
// 客戶端據此講出「已讓 N 臺裝置重新登入」，並進入退出態。
type passwordChangeResponse struct {
	RevokedSessions int    `json:"revoked_sessions"`
	RequestID       string `json:"request_id"`
}

// handlePasswordChange 更換本人的口令：POST /auth/password/change。
//
// 關卡順序與其餘敏感寫入端點逐字同族，不新造第二套：
//  1. allowRequestOrigin（CSRF 來源策略）——Web 的強制改密攻擊先被來源擋下；
//  2. resolveCredentials——credOK 意味著本次請求的憑據此刻仍換得出身份；
//     它只是必要條件：用例還要求當場交出現行口令（再認證），
//     「客戶端自報已經驗證過」在這條路上沒有任何對應字段；
//  3. ChangePassword 用例：帳戶側單一交易換雜湊＋清旗標＋撤銷全部會話，
//     Root 側按「先覆寫配置、後撤會話、失敗回滾」的順序跨存儲落地（見 internal/auth）。
//
// 失敗映射各是各的處置，不互相冒充：現行口令不對 2001（會話仍有效，
// 不發刪除指令）；新口令形狀或等於現行 1004（改的是表單輸入）；
// 部署形態不接受覆寫或存儲故障 500（細節只進日誌）。
// 成功時 Web 路徑下發刪除指令：剛生效的改密已讓這一枚會話一起失效，
// Cookie 留在瀏覽器裡只會在下一次請求撞上 2003。
func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	if !s.allowRequestOrigin(r) {
		writeError(w, r, CodeOriginForbidden, http.StatusForbidden)
		return
	}
	res := s.resolveCredentials(r)
	switch res.status {
	case credOK:
		var in passwordChangeRequest
		if !decodeJSON(w, r, &in) {
			return
		}
		result, err := s.auth.ChangePassword(r.Context(), res.resolved.Principal,
			in.CurrentPassword, in.NewPassword, requestIDFromRequest(r))
		if err != nil {
			s.writePasswordChangeFailure(w, r, err)
			return
		}
		if res.viaCookie {
			http.SetCookie(w, s.clearedSessionCookie(r))
		}
		writeJSON(w, http.StatusOK, passwordChangeResponse{
			RevokedSessions: result.RevokedSessions,
			RequestID:       requestIDFromRequest(r),
		})
		return
	case credAbsent:
		writeError(w, r, CodeNotAuthenticated, http.StatusUnauthorized)
		return
	case credInvalid:
		if res.viaCookie {
			http.SetCookie(w, s.clearedSessionCookie(r))
		}
		writeError(w, r, CodeSessionInvalid, http.StatusUnauthorized)
		return
	case credStale:
		writeError(w, r, CodeSessionStale, http.StatusUnauthorized)
		return
	case credNotReady:
		writeError(w, r, CodeNotReady, http.StatusServiceUnavailable)
		return
	case credConflict:
		writeError(w, r, CodeAuthMethodConflict, http.StatusBadRequest)
		return
	case credUnavailable:
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		return
	}
}

// writePasswordChangeFailure 把改密用例的錯誤對映為對外回應（口徑見 handler 註解）。
func (s *Server) writePasswordChangeFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		// 現行口令不對／現值已被並發改掉：兩者對外的處置同一句——重新想一次口令。
		// 刻意不發刪除指令：這一枚會話還好好的，把人踢下線才是多餘的傷害。
		writeError(w, r, CodeInvalidCredentials, http.StatusUnauthorized)
	case errors.Is(err, auth.ErrSamePassword):
		writeErrorDetails(w, r, CodeInvalidBody, http.StatusBadRequest,
			map[string]any{"reason": "same_as_current"})
	case errors.Is(err, auth.ErrInvalidNewPassword):
		writeError(w, r, CodeInvalidBody, http.StatusBadRequest)
	default:
		// ErrRootCredentialLocked（部署形態要有人去動環境）與存儲層故障都屬
		// 「不是使用者能重試解決」的內部問題：統一 500，細節只進日誌。
		s.logger.Error("改密處理失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// writeRotationFailure 把輪換用例的錯誤對映為對外回應。
//
// 三條規則，全部沿用已釋出的合同語義，不新造第二套：
//   - ErrStaleSession → 2007：在解析與換髮之間被併發的另一次輪換搶先。
//     不發刪除指令（有效憑據可能就在瀏覽器裡），也說不出「請重新登入」。
//   - ErrInvalidSession → 2003：在同一個窗口裡被撤銷或到期。Web 順帶刪除指令，
//     因為那枚 Cookie 此刻確實再也換不出身份。
//   - 其餘（資料庫故障這類非拒絕錯誤）→ 500，細節只進日誌。
func (s *Server) writeRotationFailure(w http.ResponseWriter, r *http.Request, err error, viaCookie bool) {
	switch {
	case errors.Is(err, auth.ErrStaleSession):
		writeError(w, r, CodeSessionStale, http.StatusUnauthorized)
	case errors.Is(err, auth.ErrInvalidSession):
		if viaCookie {
			http.SetCookie(w, s.clearedSessionCookie(r))
		}
		writeError(w, r, CodeSessionInvalid, http.StatusUnauthorized)
	default:
		s.logger.Error("會話輪換處理失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
	}
}

// writeLoginFailure 把登入用例的錯誤對映為對外回應：
// 拒絕收斂為 2001，限流收斂為 2006（附 Retry-After），裝置名額已滿收斂為 2008，
// 其餘（資料庫故障等）屬內部缺陷——統一 500，細節只進日誌。
//
// 2001 與 2006 的界線就是「現在重試有沒有意義」：前者口令再來一百次也是錯，
// 後者等冷卻到期就有全新預算。兩者都只有一句固定文案，沒有 details——
// 限流回應不允許以任何形式指出被擋的是哪個帳戶（規格要求同形）。
//
// 2008 用 403 而不是 401／429：憑據本身已經被接受（401「憑據無效」在這裡是錯話，
// 那會讓人對著一個正確的口令反覆懷疑自己），而立刻重試也不會變好（429 的語意是
// 「等一會兒就有預算」，名額要等到某個會話被登出或到期才釋放）。
// 回應同樣只有固定一句文案：不含上限值、現有會話數或任何裝置標識。
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
	if errors.Is(err, auth.ErrLoginDeviceLimit) {
		writeError(w, r, CodeDeviceLimitReached, http.StatusForbidden)
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
		SubjectKind:        subjectKindOf(outcome.Principal),
		AccountType:        accountTypeOf(outcome.Principal),
		DeviceID:           outcome.Session.DeviceID.String(),
		ExpiresAt:          timeutil.FormatUTC(outcome.Session.ExpiresAt),
		MustChangePassword: outcome.MustChangePassword,
		Roles:              rolesOf(outcome.Principal),
	}
	if id := outcome.Principal.AccountID(); !id.IsNil() {
		body.AccountID = id.String()
	}
	return body
}

// rolesOf 把主體持有的伺服器級角色換成對外表示；無角色時回 nil（欄位因此缺席）。
//
// Root 不在這裡出現：它的權限來自主體類別而不是授予（identity.Role 刻意不含 root），
// 客戶端要用「是不是 Root」判分流仍看 subject_kind。
func rolesOf(p identity.Principal) []string { return roleNames(p.Roles()) }

// roleNames 把角色清單換成對外表示（與 rolesOf 同一個形状，來源不同而已）。
func roleNames(roles []identity.Role) []string {
	if len(roles) == 0 {
		return nil
	}
	out := make([]string, len(roles))
	for i, role := range roles {
		out[i] = role.String()
	}
	return out
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

// accountTypeOf 把帳戶主體的類型換成對外表示；非帳戶主體（Root、系統、匿名）回空字串，
// 欄位因此缺席而不是拿空值冒充一類帳戶。
//
// 值來自構造主體時凍結的帳戶事實（identity.Principal.AccountType，來源是 accounts 表現讀那一行），
// 不是請求裡任何可自報的欄位：呼叫端改不動它，正如他改不動 roles。
func accountTypeOf(p identity.Principal) string {
	if p.Kind() != identity.KindAccount {
		return ""
	}
	return p.AccountType().String()
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
	// credStale 帶的是「上一代」憑據：會話還在，但已換發過新秘密。
	//
	// 單獨一檔不是為了寬待舊秘密——它一樣換不出身份——而是為了不讓一次正常輪換
	// 把與之交錯的那條請求說成「會話已失效」。對照 handleLogout 必須把這種失敗
	// 當成冪等成功之外的一類，/auth/session 則要把它報成可重試的 401 而非登出。
	credStale
	// credUnavailable 非拒絕類故障（資料庫等）：屬內部缺陷，不回 4xx。
	credUnavailable
)

// credentialResolution 是一次憑據解析的結果。
type credentialResolution struct {
	status    credentialStatus
	viaCookie bool
	resolved  resolvedSession // 僅 credOK 有效
	// secret 是本請求帶來的憑據明文，僅在需要拿它去換發新憑據時用（見 handleRotate）。
	// 它與 resolved 一樣只在解析成功的路上有意義，不得進日誌、回應或審計。
	secret string
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
		if errors.Is(err, auth.ErrStaleSession) {
			return credentialResolution{status: credStale, viaCookie: viaCookie, secret: secret}
		}
		if errors.Is(err, auth.ErrInvalidSession) {
			return credentialResolution{status: credInvalid, viaCookie: viaCookie, secret: secret}
		}
		s.logger.Error("會話解析失敗", "request_id", requestIDFromRequest(r), "err", err)
		return credentialResolution{status: credUnavailable, viaCookie: viaCookie, secret: secret}
	}
	return credentialResolution{
		status:    credOK,
		viaCookie: viaCookie,
		secret:    secret,
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
	case credStale:
		// 刻意不發刪除指令：瀏覽器裡那一枚可能已經是更新後的憑據（本輪換的 Set-Cookie
		// 已生效），只是這條請求出發時帶的是舊的。刪掉它等於把有效憑據清走，
		// 把一個可重試的失敗做成一次真的登出。
		writeError(w, r, CodeSessionStale, http.StatusUnauthorized)
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
