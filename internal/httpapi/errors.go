package httpapi

import (
	"encoding/json"
	"net/http"
)

// ErrorCode 為對外的穩定機器錯誤碼。
//
// 分段規劃（S02 決策）：1xxx 通用與協定層、2xxx 帳號與身分、3xxx 資產與帳務，
// 其餘分段隨端點實作細分。已發布的數值不得變更或重用。
type ErrorCode int

const (
	// CodeUnknown 表示未分類的內部錯誤；對外只回固定文案，不洩漏細節。
	CodeUnknown ErrorCode = 1000
	// CodeNotFound 表示請求的路徑不存在。
	CodeNotFound ErrorCode = 1001
	// CodeMethodNotAllowed 表示路徑存在，但不支援該 HTTP 方法。
	CodeMethodNotAllowed ErrorCode = 1002
	// CodePayloadTooLarge 表示請求體超過 server.max_body_bytes 上限。
	CodePayloadTooLarge ErrorCode = 1003
	// CodeInvalidBody 表示請求體無法解析（畸形 JSON、未知欄位、空本體或尾隨資料）。
	CodeInvalidBody ErrorCode = 1004
	// CodeUnsupportedMediaType 表示請求體不是 JSON 內容型別。
	CodeUnsupportedMediaType ErrorCode = 1005
	// CodeRequestTimeout 表示處理超過 server.request_timeout_ms 期限。
	CodeRequestTimeout ErrorCode = 1006
	// CodeNotReady 表示服務尚未就緒（依賴的資料庫無法回應），業務操作暫不可執行。
	CodeNotReady ErrorCode = 1007
	// CodeNoSpace 表示資料目錄所在卷的可用空間已低於設定下限：新的寫入被暫停。
	//
	// 與 CodeNotReady 分開是因為用戶端的處置不同：一個是「等一會兒再試」，
	// 另一個要有人去清磁碟或改下限，重試不會讓它自己變好（規格 AT-020）。
	// 下限未設時這個碼永遠不會出現。
	CodeNoSpace ErrorCode = 1008
)

// ErrorEnvelope 是所有錯誤回應的統一信封，也是錯誤回應格式的唯一權威定義。
//
// 欄位依 S02 決策固定為穩定數字錯誤碼、在地化使用者訊息、選用細節與請求關聯 ID；
// Details 供輸入驗證錯誤標示可公開的判定依據（如上限值、未知欄位名），
// 不得放入伺服器內部狀態；值為空時不出現在回應中。
type ErrorEnvelope struct {
	Code      ErrorCode      `json:"code"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	RequestID string         `json:"request_id"`
}

// writeJSON 以 JSON 內容型別輸出回應；標頭送出後才編碼，編碼失敗無法再改寫狀態碼。
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeError 以統一信封輸出錯誤回應：狀態碼依 status，訊息依 Accept-Language 協商。
func writeError(w http.ResponseWriter, r *http.Request, code ErrorCode, status int) {
	writeErrorDetails(w, r, code, status, nil)
}

// writeErrorDetails 同 writeError，並附上選用細節（如解碼失敗原因、上限值）。
// details 僅限用戶端自身輸入相關資訊，不得帶入伺服器內部狀態或堆疊。
func writeErrorDetails(w http.ResponseWriter, r *http.Request, code ErrorCode, status int, details map[string]any) {
	writeJSON(w, status, ErrorEnvelope{
		Code:      code,
		Message:   messageFor(code, negotiateLocale(r.Header.Get("Accept-Language"))),
		Details:   details,
		RequestID: requestIDFromRequest(r),
	})
}
