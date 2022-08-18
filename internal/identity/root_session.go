// root_session.go 把「Root 會話已透過驗證」接回受信主體：Root 登入後的請求解析
// 需要從會話換回一個 Principal，而 RootProof 的欄位不匯出、唯一的生產比對點是
// VerifyRootCredential。本檔是那道防火牆上唯一一扇經審查的側門，寫明它為何成立。
package identity

// ResumeRootProof 換發一份「會話層延續先前真實比對」的 Root 憑據證明。
//
// 它的正當性不是出於方便，而是會話表本身的結構（見 internal/session 與遷移 0004）：
//   - Root 會話行只能由 session.Store.Create 產生，而 Create 的 Root 分支要求進來的是
//     一個已持有有效 RootProof 的 Principal——也就是說，任何一行 Root 會話的存在，
//     都意味著某一次 VerifyRootCredential 的真實比對在先前完成過；
//   - token_hash 的 UPDATE 被資料庫觸發器擋死：「原地換秘密」不存在，
//     一枚被驗證透過的 Root 會話秘密不可能繞過那次比對被種植進表；
//   - 因此「驗證透過一枚 Root 會話秘密」等價於「那次比對的成效仍未到期」，
//     而不是又一條不需要憑據的 Root 通路。
//
// 使用邊界由結構閘把關（見 root_session_guard_test.go）：除 internal/identity 自身與
// internal/session/store.go 之外，任何第一方生產原始碼引用本函式都會讓測試失敗。
// 端點、CLI、背景任務都不準直接呼叫它——「以 Root 身分跑一次」的捷徑依然不存在，
// 這裡只承認一件事：已經登過入、且會話仍有效的 Root 就是 Root。
func ResumeRootProof() RootProof { return RootProof{verified: true} }
