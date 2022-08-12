package identity

import (
	"context"
)

// principalKey 是主體在 context 裡的鍵型別（未匯出）。
//
// 用未匯出的空結構體而不是字串：字串鍵谁都能拼出一個同名鍵去覆寫上下文裡的內容，
// 而「把主體換掉」正是本套件要防的那類操作。型別本身不匯出，鍵值也不匯出，
// 外部程式碼因此只能經 NewContext／FromContext 與上下文往來。
type principalKey struct{}

// NewContext 把主體放進上下文，回傳新的上下文。
//
// 只有「已經從認證結果得出一個 Principal」的程式碼才有東西可放：傳輸層的職責到此為止——
// 它負責把會話解析結果換成受信上下文，不負責判定權限，也不從請求內容讀角色。
// 放匿名主體是有意義的（公開端點的上下文本來就該是匿名），所以這裡不拒零值。
//
// ctx 不得為 nil（Go 的 context 約定）；nil 值在標準函式裡panic，本函式不額外攔一次，
// 因為傳 nil 上下文的程式碼在任何一處都會以同一種方式失敗，提早崩潰比默默改寫好。
func NewContext(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext 取回上下文裡的主體；不存在時回傳匿名主體。
//
// 找不到就給匿名，而不是回 (Principal, error) 或 panic：服務層每一個判定入口都會
// 先過 Authorize，匿名主體在任何敏感需求前必然被拒。換言之「忘了帶」與「刻意匿名」
// 得到同一個安全結果，不需要每個呼叫端自己記得檢查有沒有。
func FromContext(ctx context.Context) Principal {
	p, ok := ctx.Value(principalKey{}).(Principal)
	if !ok {
		return Anonymous()
	}
	return p
}
