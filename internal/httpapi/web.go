package httpapi

// 內嵌 Web 產物的靜態檔案服務與單頁應用回退。
//
// 這裡的難處不在於送檔案，而在於「同一個根路徑下同時住著 API 與網頁」。業務端點掛在根路徑
// （無版本前綴），所以無法靠前綴分辨「這條路徑是端點」還是「這是前端一條深連結」。
// 判定標準只有一句：已登記的端點與像檔案的請求一律不回退，其餘 GET/HEAD 交回應用外殼。
// 「已登記的端點」由 apiRoutes 這份登記清單派生，而不是另寫一份排除清單——
// 兩份清單遲早會漂移，屆時的症狀是「新增的端點回傳 HTML」，比 404 更難查。

import (
	"io/fs"
	"net/http"
	"strings"
)

// indexFileName 為單頁應用外殼的檔案名（位於產物根目錄）。
const indexFileName = "index.html"

// 外殼的快取策略。
//
// 只給外殼：升級執行檔後，舊外殼若被快取住，瀏覽器會帶著舊的 main.dart.js 清單打新的服務端。
// no-cache 的語意是「可以存，但每次使用前要回報伺服器確認」，在區域網的成本只有一次標頭往返。
// 其餘靜態檔案本回合不宣告長效快取：內嵌產物的 URL 不隨版本變動（main.dart.js 永遠是同一個位址），
// 宣告 immutable 之後的失效手段要連前端快取機制一起設計，屬於升級與發布步驟的範圍。
const (
	cacheControlHeader = "Cache-Control"
	noCacheDirective   = "no-cache"
)

// hiddenPrefix 為不對外提供的第一字元：以「.」開頭的檔案。
//
// 產物樹裡的點開頭檔案（建置工具的 .last_build_id、倉庫的佔位檔 .keep）是構建殘留，
// 頁面不需要它們，把內容原樣送出去只會多一條「這個位址能拿到什麼」的猜測空間。
const hiddenPrefix = "."

// apiRoute 為一筆已登記的 API 端點：路徑樣式與它的處理器。
type apiRoute struct {
	// pattern 為掛在 http.ServeMux 上的路徑樣式（以 / 開頭）。
	pattern string
	// handler 為套用了方法限制的處理器。
	handler http.Handler
}

// apiRoutes 為全部 API 端點的登記清單，也是「哪些首段屬於 API」的唯一來源。
//
// 新增端點時只改這一處：登記與排除清單因此不可能各說各話。方法放行規則由 allowMethods
// 帶上，未知方法仍回 405 與 Allow 標頭，不落入靜態服務的分流。
func (s *Server) apiRoutes() []apiRoute {
	routes := []apiRoute{
		{"/health", s.allowMethods(s.handleHealth, http.MethodGet, http.MethodHead)},
		{"/ready", s.allowMethods(s.handleReady, http.MethodGet, http.MethodHead)},
		{"/time", s.allowMethods(s.handleTime, http.MethodGet, http.MethodHead)},
	}
	// auth 端點由注入的用例決定有無（未注入時清單為空）：登記與否都只有這一個來源，
	// 回退排除清單因此自動同步——「端點不存在但首段被排除」與「反過來」都無法發生。
	routes = append(routes, s.authEndpoints()...)
	// 開設管理員端點同一個來源、同一個有無判定（未注入用例時不掛）。
	routes = append(routes, s.rootAdminEndpoints()...)
	// 初始化狀態端點同一個來源、同一個有無判定（未注入來源時不掛）。
	return append(routes, s.initStatusEndpoints()...)
}

// apiFirstSegments 從登記清單導出各端點的路徑首段集合。
//
// 用首段而非整條樣式比對：/health 只精準配對 /health，而 /health/extra 會落到 catch-all，
// 那仍是一個「API 底下的子路徑」，該回 JSON 的 404 而不是網頁外殼。
func apiFirstSegments(routes []apiRoute) map[string]struct{} {
	segments := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		if segment := firstPathSegment(route.pattern); segment != "" {
			segments[segment] = struct{}{}
		}
	}
	return segments
}

// firstPathSegment 回傳路徑的第一段（不含首斜線與其後的內容）；根路徑回傳空字串。
func firstPathSegment(requestPath string) string {
	trimmed := strings.TrimPrefix(requestPath, "/")
	if segment, _, found := strings.Cut(trimmed, "/"); found {
		return segment
	}
	return trimmed
}

// isHiddenName 表示檔案樹中的這個路徑有任何一段以「.」開頭。
func isHiddenName(name string) bool {
	for _, segment := range strings.Split(name, "/") {
		if strings.HasPrefix(segment, hiddenPrefix) {
			return true
		}
	}
	return false
}

// looksLikeFile 表示路徑最後一段附帶副檔名。
//
// 用於區分「要一個檔案」與「要到某個頁面」：缺失的 .js／.wasm／.png 必須回 404，
// 把 HTML 當成套錯名字的腳本回給瀏覽器，會讓問題變成一段看不懂的控制台錯誤而不是明確的狀態碼。
// 代價是含句號的路徑段（如 /room/1.5）會被當成檔案；前端的路由名稱不該含句號，
// 這條取捨寫在這裡而不是藏在實作裡。
func looksLikeFile(name string) bool {
	last := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		last = name[idx+1:]
	}
	dot := strings.LastIndex(last, ".")
	return dot > 0 && dot < len(last)-1
}

// isHTMLName 表示該檔案是 HTML 外殼（含副檔名寫法與無副檔名的根路徑）。
func isHTMLName(name string) bool {
	return strings.HasSuffix(name, ".html") || strings.HasSuffix(name, ".htm")
}

// webHandler 回傳靜態資源與深連結回退的處理器。
//
// apiSegments 由路由登記清單派生（見 apiRoutes），本處理器因此不需要另外維護排除清單。
// 判定順序是「先決定該不應由網頁接手，再決定拿哪個檔案」：
// 未內嵌產物、非取回類方法、命中 API 首段、隱藏檔案、像檔案卻不存在——五種情況一律
// 回統一 404 信封，回應格式與未內嵌 Web 之前逐字相同。
func (s *Server) webHandler(apiSegments map[string]struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, r, CodeNotFound, http.StatusNotFound)
			return
		}
		if s.web == nil {
			writeError(w, r, CodeNotFound, http.StatusNotFound)
			return
		}
		if _, ok := apiSegments[firstPathSegment(r.URL.Path)]; ok {
			writeError(w, r, CodeNotFound, http.StatusNotFound)
			return
		}

		name := strings.TrimPrefix(r.URL.Path, "/")
		// 尾端斜線先去掉：深連結寫成 /npc/ 時該回外殼，而不是被 fs.ValidPath 以「尾端斜線」
		// 這條格式規則擋掉。去掉之後 /canvaskit/ 仍會查到目錄而下回 404，語意反而更準。
		name = strings.TrimSuffix(name, "/")
		if name == "" {
			name = indexFileName
		}
		// fs.ValidPath 同時擋掉空段、點段與連「..」的各種寫法：它要求路徑為相對於根目錄的
		// 純淨寫法，所以不需要在此重複 path.Clean 的規則，也不可能走到產物目錄之外。
		if !fs.ValidPath(name) || isHiddenName(name) {
			writeError(w, r, CodeNotFound, http.StatusNotFound)
			return
		}

		info, err := fs.Stat(s.web, name)
		switch {
		case err == nil && info.IsDir():
			// 不列目錄也不回外殼：/assets/ 之類的路徑既不是頁面也不是檔案。
			writeError(w, r, CodeNotFound, http.StatusNotFound)
			return
		case err == nil:
			if isHTMLName(name) {
				w.Header().Set(cacheControlHeader, noCacheDirective)
			}
			http.ServeFileFS(w, r, s.web, name)
			return
		case looksLikeFile(name):
			writeError(w, r, CodeNotFound, http.StatusNotFound)
			return
		}

		// 到這裡代表：一條不存在、不像檔案、也不屬於 API 的 GET/HEAD 路徑——單頁應用深連結。
		// 外殼本身不存在時不能回 200 空白頁，仍回信封；產物完整時這個分支不會命中，
		// 但路由層收到的是呼叫端給的任意 fs.FS，契約上必須自己站住。
		if _, err := fs.Stat(s.web, indexFileName); err != nil {
			writeError(w, r, CodeNotFound, http.StatusNotFound)
			return
		}
		w.Header().Set(cacheControlHeader, noCacheDirective)
		http.ServeFileFS(w, r, s.web, indexFileName)
	}
}
