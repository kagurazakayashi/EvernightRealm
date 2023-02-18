// secret.go 是一枚邀請碼的明文產生與落庫驗證材料派生。
//
// 形狀與 internal/session/secret.go 同源，理由也同源：被哈希的對象是一枚密碼學安全的隨機值、
// 不是人想出來的口令，所以用 SHA-256 而不是 Argon2id——慢哈希對隨機值換不來抗暴破強度，
// 卻會把一次派生成本搬到每一次核銷請求上。口令側的 Argon2id 在 internal/credential，
// 兩件事不互相頂替。
package invitecode

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// codeBytes 是邀請碼明文隨機熵源的長度（位元組）。
//
// 16 位元組 = 128 位元，取自 crypto/rand（作業系統的密碼學隨機源）：一枚碼被猜中的概率要低到
// 「就算把名冊全洩露、拿剩餘額度去撞也撞不動」。這裡刻意用 128 位元而非會話的 256：邀請碼是
// 一次性交付、有額度上限、可被撤銷的短命憑據，128 位元已遠超可暴力枚舉的範圍，而更短的明文
// 更方便操作員抄寫與核對。可預測性才是唯一真正要防的屬性，math/rand 可復現、時間派生可猜測，
// 都不滿足「拿到若干歷史碼也推不出下一枚」。
const codeBytes = 16

// codeEncoding 是邀請碼明文對外的傳輸形態：base64url、無填充。
//
// 選 base64url 而不是標準 base64：明文要能被貼進任意鏈接、表單而不需二次轉義，
// '_'、'-' 與字母數字是安全字符集，'+/' 和 '=' 不是。
var codeEncoding = base64.RawURLEncoding

// codeTextLen 是編碼後的字串長度（RawURLEncoding 對 16 位元組恆為 22 字元）。
const codeTextLen = 22

// codeHashLen 是驗證材料十六進位表示的長度（SHA-256 → 64 字元），與遷移 0010 的 CHECK 同值。
const codeHashLen = 64

// ErrInvalidCode 表示交來的明文碼不具備邀請碼的形狀（長度不對、非 base64url、含填充或安全集外字元、
// 或非正規寫法）。
//
// 形狀不合格的輸入不送進哈希：短字典值的碰撞嘗試與庫失敗因此不會混在一起，拒絕在門前比拒絕在門後說得清。
var ErrInvalidCode = errors.New("invitecode: 邀請碼形狀不合法")

// newCode 產生一枚新的不透明邀請碼明文，並一併給出它的落庫驗證材料（SHA-256 十六進位）。
//
// 明文只在這一次回傳裡存在：倉儲把它交給簽發成功的回應本體一次，服務端此後只認它的哈希
// （見 hashCode）。隨機源失敗時回傳錯誤而不降級——「換一種隨機繼續簽發」正是最不該靜默發生的替換。
// reader 讓測試注入固定隨機源以斷言形狀；產製路徑一律經 crypto/rand。
func newCode(reader io.Reader) (code string, hash string, err error) {
	if reader == nil {
		reader = rand.Reader
	}
	buf := make([]byte, codeBytes)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return "", "", fmt.Errorf("invitecode: 產生邀請碼失敗: %w", err)
	}
	code = codeEncoding.EncodeToString(buf)
	return code, hashCode(code), nil
}

// hashCode 把明文碼換成落庫與查找用的驗證材料（SHA-256 小寫十六進位）。
//
// 它假定輸入已是 newCode 產生的正規形狀；核銷那一條通路（未來落地）在比對前會先經
// ParseCode 把外部輸入校驗成同一形狀，絕不把任意字串直接喂進來。
func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// ParseCode 是把外部交來的明文碼轉成「可哈希、可比對」形態的唯一入口。
//
// 只認 newCode 那一套形狀：長度恆 22、字母表是 base64url、且再編碼一次逐字相等（擋掉同一明文的
// 非正規寫法，否則兩個不同字串能命中同一哈希，等於自創第二條准入通路）。它供未來的核銷通路與
// 本套件的自校驗使用；本步沒有任何端點會調用它，但它在這裡釘住「驗證材料怎麼從明文算出來」的
// 唯一寫法，避免核銷那一步各拼一份、總有一份與簽發對不上。
func ParseCode(code string) (string, error) {
	if len(code) != codeTextLen {
		return "", fmt.Errorf("%w：長度應為 %d，實際 %d", ErrInvalidCode, codeTextLen, len(code))
	}
	raw, err := codeEncoding.DecodeString(code)
	if err != nil || len(raw) != codeBytes {
		return "", ErrInvalidCode
	}
	if codeEncoding.EncodeToString(raw) != code {
		return "", ErrInvalidCode
	}
	return code, nil
}
