// initstatus.go 是「這台伺服器有沒有 Root」這個只讀事實的對外落點。
//
// 它是給首次啟動引導頁用的，不是初始化入口：整條路上沒有任何寫入路徑——不動組態檔、
// 不動資料庫、不簽發會話、不寫審計，回應只有三個布林。初始化的授權依據仍然是
// 「能在伺服器主機上執行命令」（見 internal/rootinit 與 evernight-server init-root），
// 這裡把它改成 HTTP 形態的那一件事並沒有發生，也不會發生。
//
// 說得明白一點，這個端點的代價是什麼：它讓任何連得上的呼叫端都能查出「這台還沒有 Root」，
// 而登入那條路是刻意把「Root 未設定」與「口令不符」收斂成同一句回應（2001）的，
// 兩者取向相反。這一位資訊的揭露由使用者在批准本步時明確接受，
// 與 /health 已匿名公開服務名與版本屬同一量級；換口令、重置 Root 之類的動作
// 仍然一律不在 HTTP 面上。
//
// 三個欄位的取值依據是組態檔本身，與 internal/rootinit 的 Status、以及只讀命令
// root-status 逐字同源，於是不會出現「命令說一套、網頁說另一套」。
// 其中 env_override 那一位不是裝飾：環境變數 ER_SECURITY_ROOT_PASSWORD_HASH
// 能在執行期蓋住檔案值，少了它，網頁會對一個「檔案裡沒有、但其實有 Root」的部署
// 建議操作者去跑 init-root——而那個命令在這種狀態下必然拒絕寫入。
package httpapi

import (
	"net/http"
)

// RootInitStatus 是初始化狀態端點要回報的最小事實（由 internal/app 從 internal/rootinit 取）。
//
// 欄位刻意只到「有沒有」這個層次：組態檔路徑、編碼長度、雜湊參數檔與任何憑據片段
// 都不在這裡——一個匿名可讀的回應要能安全地發出去，前提就是它不攜帶任何定位資訊。
type RootInitStatus struct {
	// ConfigExists 表示組態檔是否已建立（首次部署可能還沒跑過任何會建立它的命令）。
	ConfigExists bool
	// RootInitialized 表示組態檔是否已帶有非空的 Root 憑據雜湊。
	RootInitialized bool
	// EnvOverride 表示 Root 憑據的環境變數覆蓋是否處於設定狀態。
	EnvOverride bool
}

// initStatusResponse 為只讀狀態端點的回應本體。
//
// request_id 讓畫面左上角那行診斷能對應到伺服器端的訪問日誌；
// 其餘三欄就是 rootinit.State 加上一位環境覆蓋旗標，沒有別的。
type initStatusResponse struct {
	ConfigExists    bool   `json:"config_exists"`
	RootInitialized bool   `json:"root_initialized"`
	EnvOverride     bool   `json:"env_override"`
	RequestID       string `json:"request_id"`
}

// initStatusEndpoints 回傳初始化狀態端點的登記清單；未注入狀態來源時為空清單。
//
// 與 Deps.Auth、Deps.Web 同一取向：裝配了什麼就服務什麼，傳輸層不自行猜。
// 未注入時端點根本不存在，路由與深連結回退的行為和本步之前逐字相同
// （回退用的 API 首段清單由這份登記清單派生，因此不會各說各話）。
func (s *Server) initStatusEndpoints() []apiRoute {
	if s.initStatus == nil {
		return nil
	}
	return []apiRoute{
		{"/root/init-status", s.allowMethods(s.handleInitStatus, http.MethodGet, http.MethodHead)},
	}
}

// handleInitStatus 處理 GET／HEAD /root/init-status：回報 Root 初始化的有或沒有。
//
// 端點只在注入狀態來源時登記（見 initStatusEndpoints），這裡不必再判一次 nil：
// 「有路徑可進來」與「有來源可問」是同一件事的兩面，分成兩處判斷遲早會不一致。
//
// 判定失敗就照實回錯誤，不猜成「尚未初始化」：把查不出來報成未初始化，
// 會誘發一次根本多餘的初始化嘗試（只讀命令 root-status 同一個取向）。
// 內部原因（檔案路徑、YAML 行號）只進伺服器端日誌，對外是通用的 1000 信封。
//
// no-store 是這張畫面能用「重新檢查」收尾的前提：操作者在另一台機器上跑完 init-root
// 回到瀏覽器，快取的舊狀態會讓那一次重新檢查毫無意義。
func (s *Server) handleInitStatus(w http.ResponseWriter, r *http.Request) {
	s.noStore(w)
	status, err := s.initStatus()
	if err != nil {
		s.logger.Error("Root 初始化狀態查詢失敗", "request_id", requestIDFromRequest(r), "err", err)
		writeError(w, r, CodeUnknown, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, initStatusResponse{
		ConfigExists:    status.ConfigExists,
		RootInitialized: status.RootInitialized,
		EnvOverride:     status.EnvOverride,
		RequestID:       requestIDFromRequest(r),
	})
}
