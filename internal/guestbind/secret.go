// secret.go 是一枚綁定憑證的明文產生與落庫驗證材料派生。
//
// 形狀與 internal/invitecode/secret.go、internal/session/secret.go 同源，理由也同源：
// 被哈希的對象是一枚密碼學安全的隨機值、不是人想出來的口令，所以用 SHA-256 而不是 Argon2id——
// 慢哈希對隨機值換不來抗暴破強度，卻會把一次派生成本搬到每一次核銷請求上。
// 口令側的 Argon2id 在 internal/credential，兩件事不互相頂替。
package guestbind

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// ticketBytes 是憑證明文隨機熵源的長度（位元組）。
//
// 16 位元組 = 128 位元，取自 crypto/rand：一枚憑證被猜中的概率要低到「就算把整張表洩露、
// 拿未核銷的行去撞也撞不動」。與邀請碼同長度而不是會話的 256 位元：憑證是短效、單次、
// 限定一對的中介憑據，128 位元已遠超可暴力枚舉的範圍，而更短的明文方便操作者抄寫與核對。
const ticketBytes = 16

// ticketEncoding 是憑證明文對外的傳輸形態：base64url、無填充。
//
// 選 base64url 而不是標準 base64：明文要能被貼進表單而不需二次轉義，
// '_'、'-' 與字母數字是安全字符集，'+/' 和 '=' 不是。
var ticketEncoding = base64.RawURLEncoding

// ticketTextLen 是編碼後的字串長度（RawURLEncoding 對 16 位元組恆為 22 字元），
// 也是傳輸層可以按形狀先擋一道、不必碰資料庫的依據。
const ticketTextLen = 22

// digestHexLen 是驗證材料與計劃摘要兩個哈希欄的定寬（SHA-256 → 64 字元小寫十六進位），
// 與遷移 0011 的 CHECK 同值。
const digestHexLen = 64

// newTicket 產生一枚新的不透明憑證明文，並一併給出它的落庫驗證材料（SHA-256 十六進位）。
//
// 明文只在這一次回傳裡存在：倉儲把它交給簽發成功的回應本體一次，服務端此後只認它的哈希
// （見 hashTicket）。隨機源失敗時回傳錯誤而不降級——「換一種隨機繼續簽發」正是最不該靜默發生的替換。
// reader 讓測試注入固定隨機源以斷言形狀；產製路徑一律經 crypto/rand。
func newTicket(reader io.Reader) (plain string, hash string, err error) {
	if reader == nil {
		reader = rand.Reader
	}
	buf := make([]byte, ticketBytes)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return "", "", fmt.Errorf("guestbind: 產生綁定憑證失敗: %w", err)
	}
	plain = ticketEncoding.EncodeToString(buf)
	return plain, hashTicket(plain), nil
}

// hashTicket 把明文憑證換成落庫與查找用的驗證材料（SHA-256 小寫十六進位）。
//
// 它假定輸入已是 newTicket 產生的正規形狀；核銷通路在比對前一律先經 ParseTicket
// 把外部輸入校驗成同一形狀，絕不把任意字串直接喂進來。
func hashTicket(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// ParseTicket 是把外部交來的明文憑證轉成「可哈希、可比對」形態的唯一入口。
//
// 只認 newTicket 那一套形狀：長度恆 22、字母表是 base64url、且再編碼一次逐字相等
// （擋掉同一明文的非正規寫法，否則兩個不同字串能命中同一哈希，等於自創第二條准入通路）。
// 形狀不合的回傳值一律是空字串：呼叫端據錯誤結論收斂成那句不泄露細節的拒絕，
// 不會拿著一個「看起來像但派生不出對得上的哈希」继续往下走。
func ParseTicket(plain string) (string, error) {
	if len(plain) != ticketTextLen {
		return "", fmt.Errorf("%w：長度應為 %d，實際 %d", ErrInvalidTicketShape, ticketTextLen, len(plain))
	}
	raw, err := ticketEncoding.DecodeString(plain)
	if err != nil || len(raw) != ticketBytes {
		return "", ErrInvalidTicketShape
	}
	if ticketEncoding.EncodeToString(raw) != plain {
		return "", ErrInvalidTicketShape
	}
	return plain, nil
}

// parseDigest 複核一枚摘要的形狀（定寬小寫十六進位）。
//
// 計劃摘要與憑證哈希兩個欄都用它：形狀不對就不該入庫，否則比對階段的「不相等」
// 會被讀成「事實變過了」，而事實上一開始就沒有一枚可比對的摘要。
func parseDigest(digest string) (string, error) {
	if len(digest) != digestHexLen {
		return "", fmt.Errorf("%w：長度應為 %d，實際 %d", ErrInvalidDigest, digestHexLen, len(digest))
	}
	for _, r := range digest {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return "", fmt.Errorf("%w：含非小寫十六進位字元", ErrInvalidDigest)
		}
	}
	return digest, nil
}
