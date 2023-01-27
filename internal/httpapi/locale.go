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
	CodeDeviceLimitReached: {
		LocaleZhCN: "此账号的登录设备数已达服务器设定的上限，本次登录未生效。请先在其他设备退出登录，或等待现有登录到期后再试。",
		LocaleZhTW: "此帳號已達伺服器設定的登入裝置數量上限，本次登入未生效。請先在其他裝置登出，或等待現有登入到期後再試。",
		LocaleEnUS: "This account has reached the server's limit on signed-in devices, so this sign-in was not applied. Sign out on another device, or wait for an existing session to expire, then try again.",
		LocaleJaJP: "このアカウントのログイン済み端末数がサーバーの設定上限に達しているため、今回のログインは適用されませんでした。他の端末でログアウトするか、既存のセッションの期限切れを待ってから再度お試しください。",
	},
	CodeDeviceNotFound: {
		LocaleZhCN: "该设备已不在你的登录设备中，可能已被移除，或列表在刷新前已过期，请刷新后重试。",
		LocaleZhTW: "該裝置已不在你的登入裝置中，可能已被移除，或清單在重新整理前已過期，請重新整理後重試。",
		LocaleEnUS: "This device is no longer among your signed-in devices. It may have been removed, or your list is out of date. Please refresh and try again.",
		LocaleJaJP: "この端末はサインイン済み端末の一覧に存在しません。削除されたか、一覧が最新でない可能性があります。更新してからもう一度お試しください。",
	},
	CodePasswordChangeRequired: {
		LocaleZhCN: "此账号尚未完成首次登录的密码修改，请先修改密码或退出登录，再使用其他功能。",
		LocaleZhTW: "此帳號尚未完成首次登入的密碼修改，請先修改密碼或登出，再使用其他功能。",
		LocaleEnUS: "This account has not completed the password change required at first sign-in. Please change your password or sign out before using other features.",
		LocaleJaJP: "このアカウントは初回サインイン時に必要なパスワード変更が未完了です。他の機能を使う前に、パスワードを変更するかサインアウトしてください。",
	},
	CodePermissionDenied: {
		LocaleZhCN: "该账号没有执行这项操作的权限。重新登录不会改变这一点，请勿以此为由反复尝试。",
		LocaleZhTW: "此帳號沒有執行這項操作的權限。重新登入不會改變這一點，請勿因此反覆嘗試。",
		LocaleEnUS: "This account does not have permission for this operation. Signing in again will not change that, so retrying won't help.",
		LocaleJaJP: "このアカウントにはこの操作を実行する権限がありません。サインインし直しても変わらないため、繰り返しても解決しません。",
	},
	CodeLoginNameTaken: {
		LocaleZhCN: "该登录名已被占用（比对会吸收大小写与全角／半角等差异写法）。请换一个名字后重新提交。",
		LocaleZhTW: "此登入名已被佔用（比對會吸收大小寫與全形／半形等差異寫法）。請換一個名字後重新提交。",
		LocaleEnUS: "This login name is already taken (matching absorbs case and width variants such as full-width letters). Choose another name and submit again.",
		LocaleJaJP: "このログイン名はすでに使用されています（比較では大小文字や全角・半角などの表記の差異が吸収されます）。別の名前を選んで再度送信してください。",
	},
	CodeProfileConflict: {
		LocaleZhCN: "你要修改的资料在你打开页面之后已被他人改动，本次修改没有保存。请刷新查看最新内容，再决定要不要重新提交。",
		LocaleZhTW: "你要修改的資料在你打開頁面之後已被他人改動，本次修改沒有保存。請重新整理查看最新內容，再決定要不要重新提交。",
		LocaleEnUS: "The record you are editing has changed since you opened it, so this edit was not saved. Refresh to see the latest values before deciding whether to submit again.",
		LocaleJaJP: "編集しようとした内容は、ページを開いた後で他者によって変更されていました。今回の変更は保存されていません。最新の内容を確認してから、再送信するかどうか決めてください。",
	},
	CodeAdminStatusConflict: {
		LocaleZhCN: "这名管理员的登录状态在你打开页面之后已经改变，本次停用或恢复没有执行。请刷新目录查看最新状态，再决定要不要重新确认。",
		LocaleZhTW: "這名管理員的登入狀態在你打開頁面之後已經改變，本次停用或恢復沒有執行。請重新整理目錄查看最新狀態，再決定要不要重新確認。",
		LocaleEnUS: "This administrator's sign-in status changed after you opened the page, so this disable or restore was not carried out. Refresh the directory to see the latest status before confirming again.",
		LocaleJaJP: "この管理者のログイン状態は、ページを開いた後で変更されていました。今回の停止または再開は実行されていません。一覧を更新して最新の状態を確認したうえで、もう一度実行するかどうか決めてください。",
	},
	CodeAdminDeleted: {
		LocaleZhCN: "这名管理员已被删除，本次操作没有执行。已删除的账户不再接受任何修改，也不会被恢复登录；重复删除同样不会成功。他仍会留在目录里，是为了让过往的操作与记录指得回同一个身份。",
		LocaleZhTW: "這名管理員已被刪除，本次操作沒有執行。已刪除的帳戶不再接受任何修改，也不會被恢復登入；重複刪除同樣不會成功。他仍會留在目錄裡，是為了讓過往的操作與記錄指得回同一個身分。",
		LocaleEnUS: "This administrator has already been deleted, so this operation did not run. A deleted account accepts no further changes and cannot be restored to sign-in, and deleting it again will not succeed either. It stays in the directory so that past actions and records keep pointing to the same identity.",
		LocaleJaJP: "この管理者はすでに削除されているため、今回の操作は実行されませんでした。削除済みのアカウントは以降どんな変更も受け付けず、サインインを復帰させることもできません。もう一度削除しても成功しません。過去の操作と記録を同じ身份に辿れるよう、この人は一覧に残ります。",
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
