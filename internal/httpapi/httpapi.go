// Package httpapi 提供服務端 HTTP 層：路由掛載、中介層鏈、統一錯誤信封與存活檢查端點。
//
// 業務端點一律掛在根路徑（無版本前綴，依 S02 決策），由 apiRoutes 集中登記。
// 基礎端點有三個：/health 回答進程存活、/ready 回答依賴（資料庫）就緒與否、
// /time 回答伺服器當前時間與顯示時區；三者都是 GET/HEAD，且不採信請求內容提供的時間。
// 其餘路徑由 web 層接手：內嵌的 Flutter Web 產物以同一路徑空間提供靜態資源，
// 深連結回退應用外殼；未內嵌產物時這些路徑一律回統一 404 信封（見 web.go）。
// 輸入保護（請求體上限、處理期限、連線層期限、JSON 解碼限制）於中介層與 http.Server 設定；
// 安全回應頭（CSP、內容型別保護、Frame 限制等）由 withSecurityHeaders 對所有回應套用。
// 每個請求由 withAccessLog 留一列結構化訪問日誌（方法、路徑、狀態、時間、來源位址與關聯 ID）；
// 本層只把記錄交給注入的出口，日誌的去處、層級與脫敏由 internal/runlog 與組合層負責。
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// Deps 為 HTTP 服務層的外部依賴；零值表示沒有外部依賴。
type Deps struct {
	// Ready 為就緒檢查：回傳錯誤表示業務尚不可用（例如資料庫無法回應）。
	// 為 nil 時表示本服務沒有外部依賴，程序存活即視為就緒。
	Ready func(context.Context) error
	// Clock 為業務時間來源；為 nil 時採用 timeutil.System()。
	Clock timeutil.Clock
	// Web 為可對外服務的靜態產物檔案系統（根目錄即產物根）。
	// 為 nil 表示本執行檔沒有可用的網頁介面：/ 與未知路徑回到統一 404 信封，
	// 協定層行為與尚未內嵌 Web 的版次逐字相同。是否「可用」由呼叫端判定
	// （internal/app 取 internal/webassets 的結果），傳輸層不自行猜測內嵌格式。
	Web fs.FS
	// Log 為伺服器端記錄出口；為 nil 時記錄被丟棄。
	// 日誌的去處（檔案、標準錯誤、層級、脫敏規則）由組合層決定，
	// 傳輸層只交出「發生了什麼」——否則每個子系統會各自開一條日誌管線。
	Log *slog.Logger
	// ErrorLog 為 net/http 自身錯誤訊息的寫入去處（畸形請求行、標頭超限、交握失敗）。
	// 組合層給的是「會把整行轉成結構化記錄」的寫入器；為 nil 時丟棄。
	ErrorLog io.Writer
}

// Server 為 HTTP 服務層。
type Server struct {
	cfg     *config.Config
	version string
	logger  *slog.Logger
	httpSrv *http.Server
	// secHeaders 為啟動時算好的安全回應頭（組態留空時為內建基線）。
	secHeaders securityHeaderSet
	// cors 為啟動時算好的跨域策略（組態未列來源時完全關閉）。
	cors corsPolicy
	// newID 為伺服器側標識的產生器，固定為 idgen.New（全服務唯一產生點）；
	// 以欄位持有是為了讓測試能注入失敗情境，驗證該路徑不降級而是拒絕請求。
	newID func() (idgen.ID, error)
	// ready 為就緒檢查（可為 nil）；與 newID 同樣以欄位持有，供測試注入失敗情境。
	ready func(context.Context) error
	// clock 為業務時間來源；時刻一律取自此處，不接受請求內容提供的時間。
	clock timeutil.Clock
	// displayZone 為啟動時由組態解析出的顯示時區，供時間回應輸出 UTC 偏移。
	displayZone *time.Location
	// web 為內嵌的靜態產物（可為 nil）；nil 時所有非端點路徑回到統一 404 信封。
	web fs.FS
}

// New 以組態、版本字串與外部依賴建立 HTTP 服務層。
func New(cfg *config.Config, version string, deps Deps) *Server {
	clock := deps.Clock
	if clock == nil {
		clock = timeutil.System()
	}
	logger := deps.Log
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	errorLog := deps.ErrorLog
	if errorLog == nil {
		errorLog = io.Discard
	}
	s := &Server{
		cfg:         cfg,
		version:     version,
		logger:      logger,
		secHeaders:  buildSecurityHeaders(cfg),
		cors:        buildCORSPolicy(cfg),
		newID:       idgen.New,
		ready:       deps.Ready,
		clock:       clock,
		displayZone: cfg.DisplayLocation(),
		web:         deps.Web,
	}
	s.httpSrv = &http.Server{
		Addr:    cfg.Server.Listen,
		Handler: s.Handler(),
		// 連線層期限（STEP-034）：標頭、整個請求讀取、回應寫入與 keep-alive 空閒。
		ReadHeaderTimeout: time.Duration(cfg.Server.ReadHeaderTimeoutMS) * time.Millisecond,
		ReadTimeout:       time.Duration(cfg.Server.ReadTimeoutMS) * time.Millisecond,
		WriteTimeout:      time.Duration(cfg.Server.WriteTimeoutMS) * time.Millisecond,
		IdleTimeout:       time.Duration(cfg.Server.IdleTimeoutMS) * time.Millisecond,
		// 標頭總量上限：一般請求（含 Cookie）遠低於此值，用於擋標頭洪水。
		MaxHeaderBytes: maxHeaderBytes,
		// net/http 的錯誤訊息內容是任意文字（可能含請求行原字），一律經組合層給的
		// 寫入器轉成記錄後才落地；前綴留空是刻意的——時間由記錄本身攜帶。
		ErrorLog: log.New(errorLog, "", 0),
	}
	return s
}

// maxHeaderBytes 為請求行與標頭總量上限（64 KiB）。
const maxHeaderBytes = 1 << 16

// Handler 回傳套用中介層鏈後的路由樹，供 http.Server 或測試伺服器使用。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	return s.wrap(mux)
}

// wrap 為路由樹套上完整中介層鏈（測試亦以本方法組裝，確保與正式路徑一致）。
// 中介層由外而內為：安全回應頭 → 請求關聯 ID → 訪問日誌 → 跨域標頭 → panic 恢復 → 處理期限 → 請求體上限 → 路由。
//
// 跨域放在關聯 ID 之後、panic 恢復之前：預檢與被拒的來源也要能對應到日誌裡的
// request_id；而它必須在請求體上限之外——OPTIONS 預檢沒有本體，不該被本體規則波及。
//
// 安全回應頭固定最外層，讓鏈上任何一層自行寫出的回應（含無法產生關聯 ID 時的拒絕）
// 都帶著標頭，不外洩未受保護的回應。
//
// 訪問日誌緊跟在關聯 ID 之後：這樣一筆記錄同時取得到 request_id，也罩得住後續每一層
// 自己寫出的回應（含 panic 恢復的 500 與預檢的 204）。放在跨域之內的話，
// 被跨域規則擋掉的請求就不會留下任何痕跡。
func (s *Server) wrap(h http.Handler) http.Handler {
	return chain(h, s.withSecurityHeaders, s.withRequestID, s.withAccessLog, s.withCORS, s.withRecovery, s.withTimeout, s.withBodyLimit)
}

// registerRoutes 集中登記路由：先登記全部 API 端點，再把其餘路徑交給靜態服務與回退。
//
// 回退用的「API 首段清單」直接由這份登記清單派生（見 apiRoutes），因此新增端點時
// 不需要在第二處聲明「這個前綴是我的」；兩處各寫一份的結局是端點開始回傳 HTML。
// 未命中端點、又不像深連結的路徑（含被拒的方法、隱藏檔案、不存在的檔案）仍回傳統一錯誤信封。
func (s *Server) registerRoutes(mux *http.ServeMux) {
	routes := s.apiRoutes()
	for _, route := range routes {
		mux.Handle(route.pattern, route.handler)
	}
	mux.Handle("/", s.webHandler(apiFirstSegments(routes)))
}

// allowMethods 包裝處理函式，只放行指定方法；其他方法回 405 並附 Allow 標頭。
func (s *Server) allowMethods(handler http.HandlerFunc, methods ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, method := range methods {
			if r.Method == method {
				handler(w, r)
				return
			}
		}
		w.Header().Set("Allow", strings.Join(methods, ", "))
		writeError(w, r, CodeMethodNotAllowed, http.StatusMethodNotAllowed)
	}
}

// Listen 依組態建立 TCP 監聽器；失敗時回傳含地址的錯誤（如連接埠被佔用）。
//
// 監聽與服務分離，讓呼叫端（internal/app）能先取得實際地址再啟動服務，
// 並在停止時掌握監聽資源的生命週期。
func (s *Server) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", s.cfg.Server.Listen)
	if err != nil {
		return nil, fmt.Errorf("httpapi: 監聽 %s 失敗: %w", s.cfg.Server.Listen, err)
	}
	return ln, nil
}

// Serve 在已建立的監聽器上提供服務，阻塞至服務停止或異常終止。
// 正常停止（呼叫 Shutdown 或 Close）回傳 nil，其他錯誤包裝後回傳。
func (s *Server) Serve(ln net.Listener) error {
	if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("httpapi: 服務異常終止: %w", err)
	}
	return nil
}

// Shutdown 優雅停止服務：停止接受新連線、等待進行中的請求完成，並釋放監聽資源。
// ctx 逾時時回傳 ctx.Err()，由呼叫端決定是否改以 Close 強制關閉。
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// Close 立即關閉服務與所有連線，不等待進行中的請求；
// 僅用於優雅停止逾時的兵底，正常停止請用 Shutdown。
func (s *Server) Close() error {
	return s.httpSrv.Close()
}

// ShutdownTimeout 回傳組態的優雅停止等待上限，供呼叫端設定停止期限。
func (s *Server) ShutdownTimeout() time.Duration {
	return time.Duration(s.cfg.Server.ShutdownTimeoutMS) * time.Millisecond
}

// serviceName 為回應與日誌使用的服務識別名。
const serviceName = "evernight-server"

// readyCheckTimeout 為就緒檢查的等待上限。
//
// 資料庫一時的鎖競爭或延遲不應讓探測請求掛住；此值也必須短於
// server.request_timeout_ms（預設 10 秒），否則用戶端只會看到處理逾時（1006）
// 而不是明確的未就緒回應（1007）。
const readyCheckTimeout = 3 * time.Second

// healthResponse 為存活檢查回應；request_id 供用戶端對應伺服器端診斷日誌。
//
// 本端點只回答「進程還活著」，不代表業務可用——依賴狀態由 /ready 回答。
type healthResponse struct {
	Status    string `json:"status"`
	Service   string `json:"service"`
	Version   string `json:"version"`
	RequestID string `json:"request_id"`
}

// handleHealth 提供存活檢查：GET /health → 200 與結構化狀態。
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{
		Status:    "ok",
		Service:   serviceName,
		Version:   s.version,
		RequestID: requestIDFromRequest(r),
	})
}

// readyResponse 為就緒檢查的成功回應。
type readyResponse struct {
	Status    string `json:"status"`
	Service   string `json:"service"`
	RequestID string `json:"request_id"`
}

// UnreadyError 讓注入的就緒檢查能同時表達「不就緒」與「該回哪個機器碼」。
//
// 傳輸層不認識磁碟或資料庫（與 Deps.Ready、Deps.Web 同一條邊界：DEC-016、DEC-025），
// 因此具體原因由注入方包裝帶進來，handler 只問「有沒有指定碼」。
// 這樣做換來的是用戶端能區分「等一下就可能會好」與「得有人去清磁碟」——
// 兩者在前端是兩句不同的話（機器碼映射 ARB，DEC-020），合併成 1007 就只剩一句。
type UnreadyError struct {
	// Code 為要回給用戶端的機器碼；0 表示沿用 CodeNotReady。
	Code ErrorCode
	// Err 是底層原因，只進伺服器端日誌，不會出現在回應裡。
	Err error
}

// Error 回傳底層原因：讓這個包裝對人也是可讀的一行，不是一個空殼。
func (e *UnreadyError) Error() string {
	if e == nil || e.Err == nil {
		return "service is not ready"
	}
	return e.Err.Error()
}

// Unwrap 讓 errors.Is/As 仍能穿透到底層原因，日誌與測試據此判定真正的失敗點。
func (e *UnreadyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// readyErrorCode 從就緒錯誤裡取出注入方指定的機器碼；未指定時沿用 CodeNotReady。
//
// unready != nil 這一道檢查不是防禦性贅字：errors.As 對「型別對但值為 nil」的指標
// 一樣回報匹配成功，少了它就會在解引用 Code 時 panic，而 panic 的位置在寫日誌的路上，
// 比原本那個未就緒原因更難查。
func readyErrorCode(err error) ErrorCode {
	var unready *UnreadyError
	if errors.As(err, &unready) && unready != nil && unready.Code != 0 {
		return unready.Code
	}
	return CodeNotReady
}

// handleReady 提供就緒檢查：外部依賴無法回應時回 503 與穩定錯誤碼，
// 不對外報告業務可用（規格 §27.2 的時間與資料來源須確實可用）。
//
// 判定失敗的內部原因（驅動訊息、資料庫路徑、連線池狀態）只寫伺服器端日誌，
// 回應一律是脫敏信封；未註冊依賴時視同已就緒（存活即業務可用）。
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.ready != nil {
		ctx, cancel := context.WithTimeout(r.Context(), readyCheckTimeout)
		defer cancel()
		if err := s.ready(ctx); err != nil {
			code := readyErrorCode(err)
			s.logger.Error("就緒檢查失敗", "request_id", requestIDFromRequest(r), "err", err, "code", code)
			writeError(w, r, code, http.StatusServiceUnavailable)
			return
		}
	}
	writeJSON(w, http.StatusOK, readyResponse{
		Status:    "ready",
		Service:   serviceName,
		RequestID: requestIDFromRequest(r),
	})
}

// timeResponse 為伺服器時間查詢回應。
//
// time 一律為 UTC 的 RFC 3339 字串（恆含三位毫秒、以 Z 結尾，格式由 timeutil 統一負責）；
// timezone 為組態的 IANA 時區名稱，utc_offset_seconds 為該時刻在此時區的偏移秒數，
// 用戶端據此顯示當地時間而無需自帶時區資料庫（規格 §27.2）。
// 本端點不受就緒門控：時刻取自進程時鐘，資料庫短暫不可用時用戶端仍需校時與顯示斷線狀態。
type timeResponse struct {
	Time             string `json:"time"`
	Timezone         string `json:"timezone"`
	UTCOffsetSeconds int    `json:"utc_offset_seconds"`
	RequestID        string `json:"request_id"`
}

// handleTime 回應伺服器當前時間與顯示時區。
//
// 時刻一律由注入的時鐘產生，不接受也不採信請求內容提供的任何時間
// （規格 §27.2、SYS-006、DEC-015）。
func (s *Server) handleTime(w http.ResponseWriter, r *http.Request) {
	at := s.clock.Now()
	_, offset := at.In(s.displayZone).Zone()
	writeJSON(w, http.StatusOK, timeResponse{
		Time:             timeutil.FormatUTC(at),
		Timezone:         s.cfg.Server.DisplayTimezone,
		UTCOffsetSeconds: offset,
		RequestID:        requestIDFromRequest(r),
	})
}
