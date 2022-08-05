package httpapi

import (
	"net/http"
	"strings"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
)

// 內建安全回應頭策略（SEC-007）：組態留空時即採用這些值，也是本專案的安全基線。
//
// defaultCSP 的設計同時兼顧安全基線與本機 Flutter Web 相容：
//   - script-src 'self' 'wasm-unsafe-eval'：只載入同源指令碼；CanvasKit 為 WebAssembly，
//     需允許 WASM 編譯，但不放 'unsafe-eval'（故仍禁止字串動態執行）。
//   - style-src 'self' 'unsafe-inline'：Flutter Web 會注入行內樣式（文字編輯、語意樹）。
//   - worker-src blob:：Flutter Web 以 blob URL 建立 Worker。
//   - img-src/font-src data: blob:：Flutter Web 將字型與圖示內嵌為 data URL。
//   - connect-src 'self'：REST API 與同源 WebSocket 即時推送。
//   - frame-ancestors 'none'、object-src 'none'、base-uri/form-action 'self'：
//     禁止本站被嵌入、禁止外掛內容、限制 base 標籤與表單外送。
const (
	defaultCSP = "default-src 'self'; " +
		"script-src 'self' 'wasm-unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: blob:; " +
		"font-src 'self' data:; " +
		"connect-src 'self'; " +
		"worker-src 'self' blob:; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'"

	// defaultFrameOptions 為預設 Frame 限制：本應用獨立運行，不被任何頁面嵌入。
	defaultFrameOptions = "DENY"

	// defaultReferrerPolicy 為預設來源參照策略：不外送參照位址，避免洩漏內網路徑。
	defaultReferrerPolicy = "no-referrer"

	// defaultPermissionsPolicy 為預設裝置權限策略：
	// 相機僅允許同源（QR 掃碼功能需要），麥克風與定位一律關閉。
	defaultPermissionsPolicy = "camera=(self), microphone=(), geolocation=()"

	// hstsValue 為 TLS 連線上的 HSTS 期限（一年）。
	hstsValue = "max-age=31536000"

	// contentSecurityPolicyHeader 等為標頭名稱常數。
	contentSecurityPolicyHeader = "Content-Security-Policy"
	hstsHeader                  = "Strict-Transport-Security"
)

// securityHeaderSet 為預先算好的安全回應頭集合。
//
// 標頭於建立服務時算好（順序固定），避免每個請求重組字串，也便於測試與審計比對。
type securityHeaderSet struct {
	// static 為每個回應都會輸出的標頭。
	static [][2]string
	// hsts 僅在 TLS 連線上輸出：HTTP 基礎模式（規格 §30.5）下 HSTS 無意義，
	// 且會讓瀏覽器對純 HTTP 來源強制跳轉而無法連線。
	// 經反向代理終結 TLS 的部署，需由代理層自行輸出 HSTS。
	hsts string
}

// buildSecurityHeaders 依組態建立安全回應頭集合；組態留空時採用內建預設策略。
func buildSecurityHeaders(cfg *config.Config) securityHeaderSet {
	headers := cfg.Security.Headers

	return securityHeaderSet{
		static: [][2]string{
			{contentSecurityPolicyHeader, orDefaultString(headers.ContentSecurityPolicy, defaultCSP)},
			{"X-Content-Type-Options", "nosniff"},
			{"X-Frame-Options", orDefaultString(headers.FrameOptions, defaultFrameOptions)},
			{"Referrer-Policy", orDefaultString(headers.ReferrerPolicy, defaultReferrerPolicy)},
			{"Permissions-Policy", orDefaultString(headers.PermissionsPolicy, defaultPermissionsPolicy)},
			// 禁止其他來源透過視窗參照取得本站控制權，並禁止跨來源讀取本站資源。
			{"Cross-Origin-Opener-Policy", "same-origin"},
			{"Cross-Origin-Resource-Policy", "same-origin"},
		},
		hsts: hstsValue,
	}
}

// orDefaultString 回傳去除空白後的非空值，空值時回傳預設。
func orDefaultString(value, fallback string) string {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		return trimmed
	}
	return fallback
}

// withSecurityHeaders 為所有回應（含錯誤信封與 404）套上安全回應頭（SEC-007）。
// 中介層位於鏈前端，故標頭在任何處理器寫入回應前即已設定。
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		for _, kv := range s.secHeaders.static {
			header.Set(kv[0], kv[1])
		}
		if r.TLS != nil {
			header.Set(hstsHeader, s.secHeaders.hsts)
		}
		next.ServeHTTP(w, r)
	})
}
