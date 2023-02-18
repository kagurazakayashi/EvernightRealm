// secret_test.go 是邀請碼明文與驗證材料的形狀證據：形狀契約、唯一性、哈希確定性與「同一明文只有一種
// 正規寫法」這條把守。隨機源用的是 crypto/rand（作業系統密碼學源）——結構上，非測試源碼不得 import
// math/rand；本檔只斷言形狀與不可預測性的外顯性質，不去測量熵本身。
package invitecode

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestNewCodeShape 驗證明文碼的形狀契約：22 字元 base64url、解碼恰為 16 位元組、驗證材料定寬 64 小寫十六進位。
func TestNewCodeShape(t *testing.T) {
	code, hash, err := newCode(nil)
	if err != nil {
		t.Fatalf("產生邀請碼失敗：%v", err)
	}
	if len(code) != codeTextLen {
		t.Errorf("明文碼應恆為 %d 字元，實際 %d", codeTextLen, len(code))
	}
	// base64url 安全字元集：不得含 +／/／=。
	if strings.ContainsAny(code, "+/=") {
		t.Errorf("明文碼須為 base64url 安全字元集：%s", code)
	}
	raw, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil || len(raw) != codeBytes {
		t.Errorf("明文碼應可解回 %d 位元組：%v", codeBytes, err)
	}
	if len(hash) != codeHashLen || strings.ToLower(hash) != hash {
		t.Errorf("驗證材料應為定寬 64 小寫十六進位，實際 %q", hash)
	}
	// 哈希確定：同一明文再算必得同一驗證材料（核銷那一步據此比對）。
	if hashCode(code) != hash {
		t.Error("同一明文的驗證材料必須可重複算出，否則核銷比對無從成立")
	}
}

// TestNewCodeUnpredictable 抽樣多次產生：明文碼彼此不同，且都落進 ParseCode 認得的形狀。
func TestNewCodeUnpredictable(t *testing.T) {
	seen := make(map[string]bool, 200)
	for i := 0; i < 200; i++ {
		code, _, err := newCode(nil)
		if err != nil {
			t.Fatalf("產生邀請碼失敗：%v", err)
		}
		if seen[code] {
			t.Fatalf("第 %d 次產生了重複的明文碼：%s", i, code)
		}
		seen[code] = true
		if _, err := ParseCode(code); err != nil {
			t.Fatalf("產生的碼應通過自身形狀校驗：%v", err)
		}
	}
}

// TestParseCodeRejectsNonCanonical ParseCode 只認正規 base64url 寫法：非安全字元、錯長度、
// 帶填充或非正規往返都不進哈希。
func TestParseCodeRejectsNonCanonical(t *testing.T) {
	_, good, err := newCode(nil)
	if err != nil {
		t.Fatalf("產生邀請碼失敗：%v", err)
	}
	_ = good
	cases := map[string]string{
		"空串":      "",
		"太短":      "abc",
		"含填充":     strings.Repeat("a", 21) + "=",
		"含非字母表字元": strings.Repeat("a", 21) + "!",
	}
	for name, code := range cases {
		if _, err := ParseCode(code); err == nil {
			t.Errorf("%s：非正規寫法應被拒絕：%q", name, code)
		}
	}
}
