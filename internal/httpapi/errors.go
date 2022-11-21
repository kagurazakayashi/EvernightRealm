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

	// —— 以下為 2xxx 帳號與身分分段（R1-009 起發布，數值不得變更或重用）。——

	// CodeInvalidCredentials 表示登入被拒。它是登入失敗時唯一的對外結論：
	// 「帳戶不存在」「口令錯誤」「訪客帳戶」「已禁用」「Root 憑據不符或未設定」
	// 全部收斂到這一個碼與同一句文案——外部因此沒有一枚可以枚舉帳戶的信號。
	// 後續步驟若加「嘗試次數過多請稍後再試」，必須是全帳戶同形的限流語意，
	// 不得出現「這個帳戶被鎖了」這種把內部原因放回回應的變體。
	CodeInvalidCredentials ErrorCode = 2001
	// CodeNotAuthenticated 表示請求沒有攜帶任何會話憑據（Cookie 與 Bearer 都沒有），
	// 而該端點需要身分。它與 CodeSessionInvalid 分開：一個是「沒帶」，
	// 另一個是「帶了但無效」，用戶端的處置文案不同（前者是首次登入引導）。
	CodeNotAuthenticated ErrorCode = 2002
	// CodeSessionInvalid 表示攜帶的會話憑據無效：形狀不合格、查無此會話、
	// 已被撤銷、已到期，或其主體此刻不可用（帳戶被禁用）。對內這些原因可區分，
	// 對外一律同一句「請重新登入」——持秘密的人不需要知道它是哪一半壞的。
	CodeSessionInvalid ErrorCode = 2003
	// CodeAuthMethodConflict 表示請求把兩種認證方式混在一起用：同時帶會話 Cookie 與
	// Bearer，或瀏覽器請求（帶 Origin）企圖用 Bearer 認證。混用的危害是 Cookie 請求
	// 借 Bearer 繞過來源校驗，因此這不是偏好問題，而是直接拒絕的缺陷信號。
	CodeAuthMethodConflict ErrorCode = 2004
	// CodeOriginForbidden 表示有副作用的請求來源未通過 CSRF 來源策略：
	// Origin 既非同源、也不在組態白名單內，或 Sec-Fetch-Site 宣告跨站。
	// 預檢放行與否不影響此判定——來源標頭不是身分授權（與 cors.go 同一取向）。
	CodeOriginForbidden ErrorCode = 2005
	// CodeLoginThrottled 表示該來源的登入失敗額度已打滿，正處於冷卻（HTTP 429，
	// 附 Retry-After）。它是「稍後再試」而不是「憑據不對」：冷卻到期後同一枚正確
	// 口令照常可登入。回應同樣只有一句固定文案——不指出被擋的是哪個帳戶、
	// 觸發的是來源×目標配對上限還是來源總量上限，與 2001 的不可枚舉要求同形。
	CodeLoginThrottled ErrorCode = 2006
	// CodeSessionStale 表示帶來的會話秘密是「上一代」的：它對應的會話還在，但已經
	// 換發過新秘密，因此這枚憑據換不出任何身份。
	//
	// 它與 CodeSessionInvalid 分開只為一件事：這一句失敗的處置是「重試」，
	// 不是「重新登入」——把一次正常換密說成一次登出，會把與輪換交錯的那條請求
	// 變成使用者的意外掉線。它不給任何訪問能力，也不給新秘密：落後一代的人
	// 本來就沒有資格知道新一代是什麼。舊秘密的失效依然是即時的。
	CodeSessionStale ErrorCode = 2007
	// CodeDeviceLimitReached 表示憑據正確，但該主體的有效會話名額已達伺服器策略的上限，
	// 這次登入整個沒有發生（沒簽發新會話，也沒撤銷任何既有會話）。
	//
	// 它與 CodeInvalidCredentials 分開只為一件事：這一次的失敗跟口令無關，
	// 把「你手上那個正確的口令」報成「憑據無效」會讓人對著對的口令反覆懷疑自己。
	// 它也與 CodeLoginThrottled 分開：限流等冷卻結束就有全新預算，名額則要等到
	// 某個會話被登出或到期——同一句「稍後再試」對兩者都不是準確的指引。
	// 回應不含上限值、現有會話數或任何裝置標識：那些屬伺服器的內部配置。
	CodeDeviceLimitReached ErrorCode = 2008
	// CodeDeviceNotFound 表示「我的裝置」定向撤銷指向的 device_id 不在本人的會話範圍內：
	// 它可能從未存在、已被清理，或本就是別的裝置／別人的裝置——三種情況一律同一個答案。
	//
	// 它存在只為給客戶端一句準確的「列表已陳舊，請重新整理」：使用者對著一份舊清單點撤銷，
	// 而那枚裝置其實已經不在，這既不是憑據問題（該重新登入），也不該謊報成撤銷成功。
	// 它絕不透露「這個 device_id 是否存在於他人名下」：device_id 是隨機 UUIDv7，
	// 猜中它已等同盲猜一枚憑據，把「不屬於你」與「不存在」收斂同形不損失任何合法性。
	CodeDeviceNotFound ErrorCode = 2009
	// CodePasswordChangeRequired 表示該帳戶帶有「首次登入必須改密」旗標，而這個端點
	// 不在改密必要入口之內：先完成改密（或登出），其他能力才重新的開放。
	//
	// 它存在是因爲強制改密必須是服務端的門，而不是頁面上的一句提示：只在界面攔、
	// 接口照常放行，等於給任何繞過界面的調用者留了正門。判定每請求現讀帳戶行，
	// 改密成功的下一條請求就拿到放行——旗標的解除因此不存在「改了密還被鎖着」的滯留。
	// 403 而不是 401：憑據本身有效（401 會錯指「重新登錄」能解決），
	// 缺的是完成改密這項義務。
	CodePasswordChangeRequired ErrorCode = 2010
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
