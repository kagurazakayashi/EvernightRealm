package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
)

// 跨域（CORS）標頭名稱常數。
const (
	originHeader                    = "Origin"
	accessControlAllowOrigin        = "Access-Control-Allow-Origin"
	accessControlAllowCredentials   = "Access-Control-Allow-Credentials"
	accessControlAllowMethods       = "Access-Control-Allow-Methods"
	accessControlAllowHeaders       = "Access-Control-Allow-Headers"
	accessControlExposeHeaders      = "Access-Control-Expose-Headers"
	accessControlMaxAge             = "Access-Control-Max-Age"
	accessControlRequestMethod      = "Access-Control-Request-Method"
	accessControlRequestHeadersName = "Access-Control-Request-Headers"
	varyHeader                      = "Vary"
)

// corsPolicy 為啟動時由組態算好的跨域策略，之後每個請求只做查表比對。
//
// 設計前提（也是本步的驗收條件）：**預設完全關閉**。AllowedOrigins 為空時
// enabled=false，中介層直接放行且不寫任何跨域標頭，行為與開啟此功能之前逐字相同；
// 正式部署的組態裡沒有這段設定，就不存在跨域出口。開發期要放寬，必須明確寫入來源。
//
// 比對採「精確來源 + 一個 `*`」兩檔：不接受萬用子網域、不接受路徑前綴比對。
// 原因是放行範圍必須一眼看得懂——`http://lan` 放不放 `http://lan/secret` 這種問題
// 不該留給讀組態的人猜。
type corsPolicy struct {
	// enabled 表示有任一放行來源；false 時本中介層完全不動作。
	enabled bool
	// wildcard 表示來源清單含 `*`（任意來源可讀）。
	wildcard bool
	// origins 為精確來源集合（已轉小寫）。
	origins map[string]struct{}
	// methods 為預檢可放行的方法集合（大寫）。
	methods map[string]struct{}
	// headers 為預檢可放行的請求標頭集合（小寫比對）。
	headers map[string]struct{}
	// methodList / headerList / exposed 為回應時原樣帶出的清單字串。
	methodList string
	headerList string
	exposed    string
	// credentials 允許附帶憑據；與 `*` 的組合已在組態校驗階段拒絕。
	credentials bool
	// maxAge 為預檢結果快取秒數的字串形式。
	maxAge string
}

// buildCORSPolicy 依組態建立跨域策略。組態已由 config.Validate 正規化過，
// 這裡不再做格式判斷，只做查表用的整形。
func buildCORSPolicy(cfg *config.Config) corsPolicy {
	c := cfg.Security.CORS
	p := corsPolicy{
		credentials: c.AllowCredentials,
		maxAge:      strconv.Itoa(c.MaxAgeSeconds),
		origins:     make(map[string]struct{}, len(c.AllowedOrigins)),
		methods:     make(map[string]struct{}, len(c.AllowedMethods)),
		headers:     make(map[string]struct{}, len(c.AllowedHeaders)),
	}
	for _, origin := range c.AllowedOrigins {
		if origin == "*" {
			p.wildcard = true
			continue
		}
		p.origins[origin] = struct{}{}
		p.enabled = true
	}
	if p.wildcard {
		p.enabled = true
	}
	for _, method := range c.AllowedMethods {
		p.methods[method] = struct{}{}
	}
	p.methodList = strings.Join(c.AllowedMethods, ", ")
	for _, header := range c.AllowedHeaders {
		p.headers[strings.ToLower(header)] = struct{}{}
	}
	p.headerList = strings.Join(c.AllowedHeaders, ", ")
	p.exposed = strings.Join(c.ExposedHeaders, ", ")
	return p
}

// allowOrigin 判斷請求來源是否被放行。
func (p corsPolicy) allowOrigin(origin string) bool {
	if !p.enabled || origin == "" {
		return false
	}
	if p.wildcard {
		return true
	}
	_, ok := p.origins[strings.ToLower(strings.TrimSpace(origin))]
	return ok
}

// allowHeaders 判斷預檢請求要帶的自訂標頭是否全數放行。
//
// 客戶端只列它要用的標頭，因此回應也照樣回給它（保留其順序與寫法），
// 而不是把整份白名單倒回去——那等於向任何頁面宣告服務端還接受哪些標頭。
func (p corsPolicy) allowHeaders(requested string) (string, bool) {
	if requested == "" {
		return p.headerList, true
	}
	for _, raw := range strings.Split(requested, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if _, ok := p.headers[name]; !ok {
			return "", false
		}
	}
	return requested, true
}

// withCORS 為跨域請求下發 CORS 標頭，並就地回答預檢（preflight）請求。
//
// 三條判斷順序有其理由：
//  1. 未啟用或請求不帶 Origin（同源請求、curl、健康檢查）時完全不加標頭——
//     給同源回應加跨域標頭沒有意義，只會讓差異難以察覺；
//  2. 先加 Vary: Origin 再判斷是否放行：即使這個來源沒被放行，回應也不能被
//     快取成「所有來源都不行」或反之；
//  3. 不被放行的來源一律**不下發任何跨域標頭**，也不告訴對方「哪個來源才可以」，
//     避免端點變成來源探測器。
//
// 預檢在此層直接結束，不進業務處理也不進請求體上限：OPTIONS 沒有本體，
// 讓它走完整鏈只會把一個協定層問答變成業務請求的錯誤。
func (s *Server) withCORS(next http.Handler) http.Handler {
	policy := s.cors
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !policy.enabled {
			next.ServeHTTP(w, r)
			return
		}
		origin := strings.TrimSpace(r.Header.Get(originHeader))
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add(varyHeader, originHeader)
		if !policy.allowOrigin(origin) {
			next.ServeHTTP(w, r)
			return
		}

		if policy.wildcard && !policy.credentials {
			w.Header().Set(accessControlAllowOrigin, "*")
		} else {
			w.Header().Set(accessControlAllowOrigin, origin)
		}
		if policy.credentials {
			w.Header().Set(accessControlAllowCredentials, "true")
		}

		if isPreflight(r) {
			s.handlePreflight(w, r, policy)
			return
		}
		if policy.exposed != "" {
			w.Header().Set(accessControlExposeHeaders, policy.exposed)
		}
		next.ServeHTTP(w, r)
	})
}

// isPreflight 判定是否為 CORS 預檢：OPTIONS 且帶 Access-Control-Request-Method。
//
// 只認「瀏覽器發出的預檢」，不把所有 OPTIONS 都攔下來——那會讓日後想自訂
// OPTIONS 行為（例如 OpenAPI 的 CORS 探索）變成改不動的殭屍程式碼。
func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get(accessControlRequestMethod) != ""
}

// handlePreflight 回答預檢：方法與標頭都在放行範圍內才回 204，
// 否則回傳統一錯誤信封（405 + CodeMethodNotAllowed）。
func (s *Server) handlePreflight(w http.ResponseWriter, r *http.Request, policy corsPolicy) {
	method := strings.ToUpper(strings.TrimSpace(r.Header.Get(accessControlRequestMethod)))
	if _, ok := policy.methods[method]; !ok {
		writeError(w, r, CodeMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	headers, ok := policy.allowHeaders(r.Header.Get(accessControlRequestHeadersName))
	if !ok {
		writeError(w, r, CodeMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set(accessControlAllowMethods, policy.methodList)
	if headers != "" {
		w.Header().Set(accessControlAllowHeaders, headers)
	}
	if policy.maxAge != "" {
		w.Header().Set(accessControlMaxAge, policy.maxAge)
	}
	// 204 不帶本體：預檢只要標頭，回位址或信封都是多餘的資訊。
	w.WriteHeader(http.StatusNoContent)
}
