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
	CodeAccountPolicyModeUnavailable: {
		LocaleZhCN: "这个自注册模式在本服务器版本尚未开放：名字是认得的，但它需要的准入流程还没有上线，所以策略不会记成它。请改选现在支持的模式（closed 或 open），或等对应功能上线后再保存。",
		LocaleZhTW: "這個自註冊模式在本伺服器版本尚未開放：名字是認得的，但它需要的准入流程還沒有上線，所以策略不會記成它。請改選現在支援的模式（closed 或 open），或等對應功能上線後再儲存。",
		LocaleEnUS: "This self-registration mode is not enabled in this server version: the name is recognised, but the admission flow it needs has not shipped, so the policy will not record it. Choose a mode supported today (closed or open), or save again once that feature ships.",
		LocaleJaJP: "この自己登録モードは現在のサーバー版では有効ではありません。名前は認識されますが、必要な申請受け入れ処理がまだ提供されていないため、ポリシーとして保存できません。現在対応しているモード（closed または open）を選び、該当機能が提供されてからもう一度保存してください。",
	},
	CodeAccountCreationDisabled: {
		LocaleZhCN: "服务器当前的账户建立策略没有开放这条通路，本次建立没有执行。你的权限没有问题，改登录名或重新登录都不会改变这件事；请Root在服务器账户建立策略中打开对应开关后再试。",
		LocaleZhTW: "伺服器目前的帳戶建立策略沒有開放這條通路，本次建立沒有執行。你的權限沒有問題，改登入名或重新登入都不會改變這件事；請 Root 在伺服器帳戶建立策略中打開對應開關後再試。",
		LocaleEnUS: "The server's account-creation policy does not open this path right now, so this creation did not run. Your permissions are fine, and changing the login name or signing in again will not change that; ask Root to turn on the matching switch in the server account-creation policy, then try again.",
		LocaleJaJP: "サーバーの現在のアカウント作成ポリシーはこの経路を開放していないため、今回の作成は実行されませんでした。権限に問題はありません。ログイン名を変えても再ログインしても状況は変わりません。Root にサーバーのアカウント作成ポリシーで対応するスイッチを有効にしてもらうまでお待ちください。",
	},
	CodeGuestUpgradeRequired: {
		LocaleZhCN: "这名成员是访客账户，本来就没有一般密码，所以本次凭据重置没有执行。给他设置一个密码等于把他的身份改成普通账户，那要走专门的访客升级功能，不能顺带由重置口令完成；换一个目标、改写法或重新登录都不会改变这件事。",
		LocaleZhTW: "這名成員是訪戶帳戶，本來就沒有一般密碼，所以本次憑據重置沒有執行。給他設定一個密碼等於把他的身分改成普通帳戶，那要走專門的訪戶升級功能，不能順帶由重置口令完成；換一個目標、改寫法或重新登入都不會改變這件事。",
		LocaleEnUS: "This member is a guest account and has no general password, so this credential reset did not run. Setting a password for them would amount to converting them into a standard account, which needs the dedicated guest-upgrade feature rather than a password reset; choosing another target, rewording the request, or signing in again will not change that.",
		LocaleJaJP: "このメンバーはゲストアカウントのためもともと一般的なパスワードを持たず、今回の認証情報リセットは実行されませんでした。パスワードを設定することは通常アカウントへの変更と同じであり、パスワードリセットではなく専用のゲスト昇格機能で行う必要があります。対象を変えても、書き直しても、再ログインしても状況は変わりません。",
	},
	CodeSelfRegisterNameTaken: {
		LocaleZhCN: "这个登录名已被占用（比对会吸收大小写与全角／半角等差异写法），本次注册没有创建账户。请换一个名字后重新提交。",
		LocaleZhTW: "這個登入名已被佔用（比對會吸收大小寫與全形／半形等差異寫法），本次註冊沒有建立帳戶。請換一個名字後重新提交。",
		LocaleEnUS: "This login name is already taken (matching absorbs case and width variants such as full-width letters), so this sign-up created no account. Choose another name and submit again.",
		LocaleJaJP: "このログイン名はすでに使用されています（比較では大小文字や全角・半角などの表記の差異が吸収される）ため、今回の登録ではアカウントが作成されませんでした。別の名前を選んで再度送信してください。",
	},
	CodeNotAnApplication: {
		LocaleZhCN: "凭据有效，但这个账户不是待审批的申请——它由开放自注册、管理员创建或 Root 开设直接生效。请改用登录入口。",
		LocaleZhTW: "憑據有效，但這個帳戶不是待審批的申請——它由開放自註冊、管理員建立或 Root 開設直接生效。請改用登入入口。",
		LocaleEnUS: "These credentials are valid, but this account is not an application awaiting approval; it was created directly by open sign-up, an administrator, or Root. Please use the sign-in page.",
		LocaleJaJP: "認証情報は有効ですが、このアカウントは承認待ちの申請ではありません。公開登録、管理者、または Root によって直接有効化されています。ログイン画面をご利用ください。",
	},
	CodeApplicationDecided: {
		LocaleZhCN: "这份注册申请已经有了决定，本次审批没有生效。请重新读取申请名册；已批准的人请到普通账户目录处理，已拒绝的人没有改判通道。",
		LocaleZhTW: "這份註冊申請已經有過決定，本次審批沒有生效。請重新讀取申請名冊；已批准的人請到普通帳戶目錄處理，已拒絕的人沒有改判通路。",
		LocaleEnUS: "This registration has already been decided, so your review did not take effect. Reload the application roster: approved accounts are managed in the standard account directory, and rejected ones cannot be reversed.",
		LocaleJaJP: "この登録申請はすでに判定済みため、今回の承認操作は反映されませんでした。申請一覧を再読み込みしてください。承認済みのアカウントは一般アカウント一覧で、却下された申請は元に戻せません。",
	},
	CodeInviteAlreadyRevoked: {
		LocaleZhCN: "这枚邀请码已经被撤销，本次撤销没有生效。撤销是单向的终点：请重新读取邀请码名册，已撤销的码不会重新生效，也不能再被核销，重按一次不会改写先前那次撤销。",
		LocaleZhTW: "這枚邀請碼已經被撤銷，本次撤銷沒有生效。撤銷是單向的終點：請重新讀取邀請碼名冊，已撤銷的碼不會重新生效，也不能再被核銷，重按一次不會改寫先前那次撤銷。",
		LocaleEnUS: "This invite code has already been revoked, so this revocation did not take effect. Revocation is one-way: reload the invite-code roster. A revoked code cannot be reactivated or redeemed again, and pressing once more will not rewrite the earlier revocation.",
		LocaleJaJP: "この招待コードはすでに失効済みで、今回の失効操作は反映されませんでした。失効は元に戻せません。招待コード一覧を再読み込みしてください。失効済みのコードを再有効化したり再度利用したりすることはできず、もう一度押しても以前の失効は書き換わりません。",
	},
	CodeInviteRejected: {
		LocaleZhCN: "这台服务器当前要求凭有效邀请码注册，而你这次用的邀请码换不出一个账户——可能是没有填写、写得不完整、已经过期或被撤销、名额已用完，或恰好被另一次注册抢先使用。出于安全，服务器不指出具体是哪一种。请向发放邀请码的人索取一枚新的有效码后再提交；换一个登录名、改写这一栏或重新登录都不会改变这件事。",
		LocaleZhTW: "這臺伺服器目前要求憑有效邀請碼註冊，而你這一次用的邀請碼換不出一個帳戶——可能是沒有填寫、寫得不完整、已經過期或被撤銷、名額已用完，或恰好被另一次註冊搶先使用。出於安全，伺服器不指出具體是哪一種。請向發放邀請碼的人索取一枚新的有效碼後再提交；換一個登入名、改寫這一欄或重新登入都不會改變這件事。",
		LocaleEnUS: "This server currently requires a valid invite code to sign up, and the code you used this time cannot create an account — it may be missing, malformed, expired or revoked, fully used, or just consumed by another sign-up. For safety the server does not say which. Ask whoever issues invite codes for a fresh valid one and submit again; choosing another login name, rewording this field, or signing in again will not change that.",
		LocaleJaJP: "このサーバーは現在、有効な招待コードによる登録を要求していますが、今回使用した招待コードではアカウントを作成できません。記入漏れ、形式が不完全、期限切れまたは失効、枠を使い切り、あるいは別の登録に先に使用された可能性があります。セキュリティ上、サーバーはどれに該当するかは示しません。招待コードを発行した人に新しい有効なコードを依頼してから再度送信してください。ログイン名を変えても、この欄を書き直しても、再ログインしても状況は変わりません。",
	},
	CodeGuestNotUpgradable: {
		LocaleZhCN: "这名成员此刻不是一个可升级的访客：他要么已经是正式账户（不需要再升级），要么登录能力已被停用（请先恢复他的登录，再决定是否升级）。本次升级没有执行——身份没改、凭据没落地、会话没撤销、审计没记。请重新读取这一笔的服务端现值；换一个身份或改写口令都不会改变这件事。",
		LocaleZhTW: "這名成員此刻不是一個可升級的訪戶：他要嘛已經是正式帳戶（不需要再升級），要嘛登入能力已被停用（請先恢復他的登入，再決定是否升級）。本次升級沒有執行——身分沒改、憑據沒落地、會話沒撤銷、審計沒記。請重新讀取這一筆的伺服器端現值；換一個身分或改寫口令都不會改變這件事。",
		LocaleEnUS: "This member is not an upgradable guest right now: either they are already a standard account (no upgrade needed), or their sign-in capability is disabled (restore it first, then decide whether to upgrade). This upgrade did not run — the identity was not changed, no credential was stored, no session was revoked, and no audit entry was written. Reload this record's server-side values; switching identities or rewording the password will not change that.",
		LocaleJaJP: "このメンバーは現在、昇格可能なゲストではありません。すでに通常アカウントか（昇格の必要はありません）、ログイン機能が停止されています（まず再開してから昇格するかどうか決めてください）。今回の昇格は実行されていません。身份は変更されず、認証情報は保存されず、セッションも失効せず、監査記録も残されていません。サーバー側の最新値を再読み込みしてください。別の身份にしたりパスワードの書き方を変えたりしても状況は変わりません。",
	},
	CodeBindTicketInvalid: {
		LocaleZhCN: "这次用的访客绑定凭证换不出一次绑定——它可能不存在、写得不完整、已经过期、已经被用掉，或者它批准的目标不是你本人。出于安全，服务器不指出具体是哪一种，也不回显凭证的任何信息。本次绑定没有执行——访客没被退休、会话没撤销、留痕没追加、你的账户也没被改动。请请管理员重新做一次绑定预检并签发一枚新的凭证；改写这一栏、换个目标或重复提交都不会让它变成有效。",
		LocaleZhTW: "這一次用的訪戶綁定憑證換不出一次綁定——它可能不存在、寫得不完整、已經過期、已被用掉，或者它批准的目標不是你本人。出於安全，伺服器不指出具體是哪一種，也不回顯憑證的任何資訊。本次綁定沒有執行——訪戶沒被退休、會話沒撤銷、留痕沒追加、你的帳戶也沒被改動。請請管理員重新做一次綁定預檢並簽發一枚新的憑證；改寫這一欄、換個目標或重複提交都不會讓它變成有效。",
		LocaleEnUS: "The guest-binding ticket used this time cannot produce a binding — it may not exist, be malformed, have expired, already be consumed, or name someone other than you as the target. For safety the server does not say which, and it never echoes any ticket information. Nothing ran this time: the guest was not retired, no session was revoked, no history row was added, and your account was not changed. Ask an administrator to run the binding pre-check again and issue a fresh ticket; rewording this field, pointing it at another account, or resubmitting will not make it valid.",
		LocaleJaJP: "今回使われたゲストバインド用証跡はバインドを生み出せません。存在しない、形式が不完全、期限切れ、すでに使用済み、または証跡が認めた対象があなた本人でない可能性があります。セキュリティ上、サーバーはどれに該当するかを示さず、証跡の情報も一切返しません。今回バインドは実行されていません。ゲストは退席せず、セッションも失効せず、履歴行も追加されず、あなたのアカウントも変更されていません。管理者にバインド事前チェックをやり直して新しい証跡を発行してもらってください。この欄を書き直したり、別の相手向けに出し直したりしても有効にはなりません。",
	},
	CodeBindPlanStale: {
		LocaleZhCN: "这份绑定计划已经不符合服务器当前的实况，所以没有执行——可能多了一张尚未接入绑定预检的账户引用表、这一对里某一方的身份或登录能力变了，或数据库版本已经推进。旧凭证上钉着的那份计划不会因为你再按一次就变成新计划：请重新预检，并凭新的凭证再确认一次。本次一个字节都没写入——访客没被退休、会话没撤销、留痕没追加、目标账户也没被改动。",
		LocaleZhTW: "這份綁定計劃已經不符合伺服器當下的實況，所以沒有執行——可能多了一張尚未接入綁定預檢的帳戶引用表、這一對裡某一方的身分或登入能力變了，或資料庫版本已經推進。舊憑證上釘著的那份計劃不會因為你再按一次就變成新計劃：請重新預檢，並憑新的憑證再確認一次。本次一個字元都沒寫入——訪戶沒被退休、會話沒撤銷、留痕沒追加、目標帳戶也沒被改動。",
		LocaleEnUS: "This binding plan no longer matches the server's current facts, so nothing ran — an account-reference table that the binding pre-check has not been wired for may have appeared, one side's identity or sign-in capability may have changed, or the database schema may have moved on. A plan pinned to an old ticket does not become new by pressing it again: run the pre-check again and confirm with a fresh ticket. Nothing was written this time: the guest was not retired, no session was revoked, no history row was added, and the target account was not changed.",
		LocaleJaJP: "このバインド計画はサーバーの現在の状況と一致しないため実行されませんでした。バインド事前チェック未接続のアカウント参照表が増えた、この一組のいずれかの身份またはログイン機能が変わった、あるいはデータベースのバージョンが進んだ可能性があります。古い証跡に釘付けられた計画は、もう一度押しても新しい計画にはなりません。事前チェックをやり直し、新しい証跡で改めて確認してください。今回は一文字も書き込まれていません。ゲストは退席せず、セッションも失効せず、履歴行も追加されず、対象アカウントも変更されていません。",
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
