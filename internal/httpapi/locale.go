package httpapi

import (
	"sort"
	"strconv"
	"strings"
)

// 支援的使用者語言鍵，與前端四語言鍵對齊；缺漏時回退 defaultLocale。
const (
	LocaleZhCN = "zh-CN"
	LocaleZhTW = "zh-TW"
	LocaleEnUS = "en-US"
	LocaleJaJP = "ja-JP"

	// defaultLocale 為查無相符語言時的固定回退語言。
	defaultLocale = LocaleEnUS
)

// maxLanguageRanges 限制單次協商解析的語言範圍數量，避免超長標頭造成額外負擔。
const maxLanguageRanges = 16

// errorMessages 為錯誤碼的在地化使用者訊息目錄。
//
// 每個錯誤碼都必須提供全部支援語言；缺漏由測試把關，不依賴執行期回退掩蓋。
var errorMessages = map[ErrorCode]map[string]string{
	CodeUnknown: {
		LocaleZhCN: "服务器内部错误，请稍后重试。",
		LocaleZhTW: "伺服器內部錯誤，請稍後重試。",
		LocaleEnUS: "Internal server error. Please try again later.",
		LocaleJaJP: "サーバー内部エラーが発生しました。しばらくしてからお試しください。",
	},
	CodeNotFound: {
		LocaleZhCN: "请求的资源不存在。",
		LocaleZhTW: "請求的資源不存在。",
		LocaleEnUS: "The requested resource does not exist.",
		LocaleJaJP: "要求されたリソースは存在しません。",
	},
	CodeMethodNotAllowed: {
		LocaleZhCN: "该请求方法不被允许。",
		LocaleZhTW: "此請求方法不被允許。",
		LocaleEnUS: "The request method is not allowed.",
		LocaleJaJP: "このリクエストメソッドは許可されていません。",
	},
	CodePayloadTooLarge: {
		LocaleZhCN: "请求内容过大，超出服务器允许的上限。",
		LocaleZhTW: "請求內容過大，超出伺服器允許的上限。",
		LocaleEnUS: "The request body is too large and was rejected.",
		LocaleJaJP: "リクエスト本文が大きすぎるため、受け付けられませんでした。",
	},
	CodeInvalidBody: {
		LocaleZhCN: "请求内容格式不正确，请检查后重试。",
		LocaleZhTW: "請求內容格式不正確，請檢查後重試。",
		LocaleEnUS: "The request body is malformed or contains unsupported fields.",
		LocaleJaJP: "リクエスト本文の形式が正しくないか、未対応の項目が含まれています。",
	},
	CodeUnsupportedMediaType: {
		LocaleZhCN: "请求内容类型不受支持，请使用 application/json。",
		LocaleZhTW: "請求內容型別不受支援，請使用 application/json。",
		LocaleEnUS: "Unsupported request content type. Use application/json.",
		LocaleJaJP: "リクエストの Content-Type に対応していません。application/json を使用してください。",
	},
	CodeRequestTimeout: {
		LocaleZhCN: "服务器处理该请求超时，请稍后重试。",
		LocaleZhTW: "伺服器處理該請求逾時，請稍後重試。",
		LocaleEnUS: "The server timed out while processing the request. Please try again.",
		LocaleJaJP: "サーバーがリクエストの処理中にタイムアウトしました。しばらくしてからお試しください。",
	},
	CodeNotReady: {
		LocaleZhCN: "服务尚未就绪，暂时无法处理业务操作，请稍后重试。",
		LocaleZhTW: "服務尚未就緒，暫時無法處理業務操作，請稍後重試。",
		LocaleEnUS: "The service is not ready yet and cannot handle business operations. Please try again later.",
		LocaleJaJP: "サービスはまだ準備ができておらず、操作を処理できません。しばらくしてからもう一度お試しください。",
	},
	CodeNoSpace: {
		LocaleZhCN: "服务器存储空间不足，已暂停新的写入操作，请清理磁盘后重试。",
		LocaleZhTW: "伺服器儲存空間不足，已暫停新的寫入操作，請清理磁碟後重試。",
		LocaleEnUS: "The server is low on storage space and has paused new write operations. Free up disk space, then try again.",
		LocaleJaJP: "サーバーのストレージ容量が不足しているため、新しい書き込み操作を一時停止しています。ディスク領域を確保してから再試行してください。",
	},
	CodeInvalidCredentials: {
		LocaleZhCN: "登录名或密码不正确，或该账户当前无法登录。",
		LocaleZhTW: "登入名或密碼不正確，或該帳戶目前無法登入。",
		LocaleEnUS: "The login name or password is incorrect, or this account cannot sign in right now.",
		LocaleJaJP: "ログイン名またはパスワードが正しくないか、このアカウントは現在サインインできません。",
	},
	CodeNotAuthenticated: {
		LocaleZhCN: "此请求未携带会话，请先登录。",
		LocaleZhTW: "此請求未攜帶會話，請先登入。",
		LocaleEnUS: "This request carries no session. Please sign in first.",
		LocaleJaJP: "このリクエストにはセッションが含まれていません。まずサインインしてください。",
	},
	CodeSessionInvalid: {
		LocaleZhCN: "会话已失效（过期、被撤销或账户状态变化），请重新登录。",
		LocaleZhTW: "會話已失效（過期、被撤銷或帳戶狀態變化），請重新登入。",
		LocaleEnUS: "The session is no longer valid (expired, revoked, or the account state changed). Please sign in again.",
		LocaleJaJP: "セッションは無効になりました（期限切れ、失効、またはアカウント状態の変化）。再度サインインしてください。",
	},
	CodeAuthMethodConflict: {
		LocaleZhCN: "请求混用了多种认证方式，或浏览器请求使用了不允许的认证方式。",
		LocaleZhTW: "請求混用了多種認證方式，或瀏覽器請求使用了不允許的認證方式。",
		LocaleEnUS: "The request mixes multiple authentication methods, or a browser request used a disallowed method.",
		LocaleJaJP: "リクエストが複数の認証方式を混在しているか、ブラウザークエストが許可されない方式を使用しています。",
	},
	CodeOriginForbidden: {
		LocaleZhCN: "请求来源未通过跨站防护检查，已被拒绝。",
		LocaleZhTW: "請求來源未通過跨站防護檢查，已被拒絕。",
		LocaleEnUS: "The request origin failed the cross-site protection check and was rejected.",
		LocaleJaJP: "リクエストの送信元がクロスサイト保護チェックを通過しなかったため、拒否されました。",
	},
	CodeLoginThrottled: {
		LocaleZhCN: "登录尝试过多，请稍后再试。",
		LocaleZhTW: "登入嘗試次數過多，請稍後再試。",
		LocaleEnUS: "Too many login attempts. Please try again later.",
		LocaleJaJP: "ログイン試行回数が多すぎます。しばらくしてからもう一度お試しください。",
	},
	CodeSessionStale: {
		LocaleZhCN: "本次请求携带的会话凭据已被更新的凭据取代，请重试这一次操作。",
		LocaleZhTW: "本次請求攜帶的會話憑據已被更新的憑據取代，請重試這一次操作。",
		LocaleEnUS: "The session credential in this request has been superseded by a newer one. Please retry this operation.",
		LocaleJaJP: "このリクエストのセッション資格情報は新しいものに置き換えられました。この操作をもう一度実行してください。",
	},
}

// messageFor 取得錯誤碼在指定語言的使用者訊息；語言未支援或訊息為空時回退 defaultLocale。
func messageFor(code ErrorCode, locale string) string {
	messages, ok := errorMessages[code]
	if !ok {
		return ""
	}
	if message := messages[locale]; message != "" {
		return message
	}
	return messages[defaultLocale]
}

// localePreference 為解析後的單一語言範圍與其權重。
type localePreference struct {
	tag string
	q   float64
}

// negotiateLocale 依 Accept-Language 標頭選擇最合適的支援語言。
// 依權重由高至低、同權重依標頭出現順序比對；無相符或標頭為空時回退 defaultLocale。
func negotiateLocale(acceptLanguage string) string {
	header := strings.TrimSpace(acceptLanguage)
	if header == "" {
		return defaultLocale
	}

	preferences := make([]localePreference, 0, maxLanguageRanges)
	for _, part := range strings.Split(header, ",") {
		if len(preferences) >= maxLanguageRanges {
			break
		}
		tag, q, ok := parseLanguageRange(part)
		if !ok || q <= 0 {
			continue
		}
		preferences = append(preferences, localePreference{tag: tag, q: q})
	}
	// 穩定排序：同權重時保留標頭中的先後順序。
	sort.SliceStable(preferences, func(i, j int) bool { return preferences[i].q > preferences[j].q })

	for _, preference := range preferences {
		if locale, ok := matchLocale(preference.tag); ok {
			return locale
		}
	}
	return defaultLocale
}

// parseLanguageRange 解析單一 Accept-Language 項目（如 "zh-TW;q=0.9"）。
// 標籤為空或權重無法解析時回傳 ok=false，代表該項目不可用。
func parseLanguageRange(part string) (string, float64, bool) {
	tag := strings.TrimSpace(part)
	q := 1.0

	if semicolon := strings.Index(tag, ";"); semicolon >= 0 {
		params := tag[semicolon+1:]
		tag = strings.TrimSpace(tag[:semicolon])
		for _, param := range strings.Split(params, ";") {
			param = strings.TrimSpace(param)
			value, found := strings.CutPrefix(strings.ToLower(param), "q=")
			if !found {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil {
				return "", 0, false
			}
			q = parsed
		}
	}

	if tag == "" {
		return "", 0, false
	}
	return tag, q, true
}

// matchLocale 將語言標籤對應到支援的語言鍵；無法對應時回傳 ok=false。
// 只比對主語言與地區／字體子標籤，其餘子標籤忽略；"*" 不視為相符，交由回退語言處理。
func matchLocale(tag string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(tag))
	if normalized == "" || normalized == "*" {
		return "", false
	}

	parts := strings.Split(normalized, "-")
	subtag := ""
	if len(parts) > 1 {
		subtag = parts[1]
	}

	switch parts[0] {
	case "zh":
		switch subtag {
		case "tw", "hk", "mo", "hant":
			return LocaleZhTW, true
		case "cn", "sg", "my", "hans", "":
			return LocaleZhCN, true
		default:
			// 未識別的地區子標籤：仍視為中文，採簡體為預設。
			return LocaleZhCN, true
		}
	case "en":
		return LocaleEnUS, true
	case "ja":
		return LocaleJaJP, true
	default:
		return "", false
	}
}
