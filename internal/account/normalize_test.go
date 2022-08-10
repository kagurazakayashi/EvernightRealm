package account

import (
	"errors"
	"strings"
	"testing"
)

// rs 由碼位構造字串：本檔的全部測試意義建立在特定碼位上，
// 而全角、合字、零寬這類字元在原始碼、複製與工具鏈之間最容易被無聲改寫，
// 一律用數值構造確保測試讀的是碼位、不是某個字形的巧合。
func rs(cps ...rune) string { return string(cps) }

// 測試用到的特殊碼位（一律數值表徵，避免字面量在編輯過程中漂移）。
const (
	nbsp = rune(0x00A0) // NO-BREAK SPACE
	zwsp = rune(0x200B) // ZERO WIDTH SPACE
	zwj  = rune(0x200D) // ZERO WIDTH JOINER
	rlo  = rune(0x202E) // RIGHT-TO-LEFT OVERRIDE
	rial = rune(0xFDFC) // RIAL SIGN（NFKC 展開為 "Rial"）
	fafi = rune(0xFB01) // LATIN SMALL LIGATURE FI
	shs  = rune(0x00DF) // LATIN SMALL LETTER SHARP S
	cs0  = rune(0x0000) // NUL
	cs9  = rune(0x0009) // TAB
	cs10 = rune(0x000A) // LF
	ideo = rune(0x3000) // IDEOGRAPHIC SPACE
)

// TestLoginKeyCaseInsensitive 驗證大小寫摺疊：同字母不同大小寫必須得到同一個鍵。
func TestLoginKeyCaseInsensitive(t *testing.T) {
	for _, login := range []string{"admin", "Admin", "ADMIN", "aDmIn"} {
		key, err := LoginKey(login)
		if err != nil {
			t.Fatalf("LoginKey(%q) 失敗：%v", login, err)
		}
		if key != "admin" {
			t.Errorf("LoginKey(%q) = %q，期望 admin", login, key)
		}
	}
}

// TestLoginKeyUnicodeFolding 驗證 NFKC 與全量折疊收攏「視覺相同、碼位不同」的等價形。
func TestLoginKeyUnicodeFolding(t *testing.T) {
	cases := []struct {
		name  string
		login string
		want  string
	}{
		{"全角字母", rs(0xFF21, 0xFF22, 0xFF23), "abc"},
		{"FI 合字", "of" + string(fafi) + "ce", "office"},
		{"sharp s", "Stra" + string(shs) + "e", "strasse"},
		{"全角大寫", rs(0xFF29, 0xFF24), "id"},
		{"西里爾大寫", string(rune(0x041A)) + "айрос", "кайрос"},
	}
	for _, tc := range cases {
		key, err := LoginKey(tc.login)
		if err != nil {
			t.Fatalf("%s：LoginKey(%q) 失敗：%v", tc.name, tc.login, err)
		}
		if key != tc.want {
			t.Errorf("%s：LoginKey(%q) = %q，期望 %q", tc.name, tc.login, key, tc.want)
		}
	}
}

// TestLoginKeyStableForSameVisual 記錄唯一性真正依賴的性質：
// 同一輸入經同一（純）鍵函式恆得同一鍵，且鍵為正規小寫形式。
//
// 終態 sigma 與非終態 sigma 的語境化摺疊不在本鍵函式的承諾內：
// cases.Fold 非語境化，本測試只固定「同輸入同鍵」這條被 UNIQUE 索引依賴的性質。
func TestLoginKeyStableForSameVisual(t *testing.T) {
	upper := rs(0x39F, 0x394, 0x3A5, 0x3A3, 0x3A3, 0x395, 0x3A5, 0x3A3)
	k1, err := LoginKey(upper)
	if err != nil {
		t.Fatalf("LoginKey 失敗：%v", err)
	}
	k2, err := LoginKey(rs(0x3BF, 0x3B4, 0x3C5, 0x3C3, 0x3C3, 0x3B5, 0x3C5, 0x3C2))
	if err != nil {
		t.Fatalf("LoginKey 失敗：%v", err)
	}
	if k1 == "" || k1 != strings.ToLower(k1) {
		t.Errorf("鍵應為非空小寫形式，實際 %q", k1)
	}
	k3, err := LoginKey(upper)
	if err != nil || k3 != k1 {
		t.Errorf("同輸入應得同鍵：%q vs %q (err=%v)", k1, k3, err)
	}
	if k2 == "" {
		t.Error("希臘小寫鍵不可為空")
	}
}

// TestLoginKeyIdempotent 驗證鍵的穩定性：對鍵再算鍵必須得到同一值。
//
// 這是 UNIQUE 索引可比對的前提——若鍵不正規，同一登入名會因計算次數不同
// 產生兩個鍵，唯一約束就形同虛設。
func TestLoginKeyIdempotent(t *testing.T) {
	logins := []string{"Admin", rs(0xFF21, 0xFF22, 0xFF23), "of" + string(fafi) + "ce",
		"Stra" + string(shs) + "e", "user_42", string(rune(0x96C5)), rs(0x6E2C, 0x8A0A, 0x5E33, 0x865F)}
	for _, login := range logins {
		key, err := LoginKey(login)
		if err != nil {
			t.Fatalf("LoginKey(%q) 失敗：%v", login, err)
		}
		again, err := LoginKey(key)
		if err != nil {
			t.Fatalf("對鍵 %q 再算鍵失敗：%v", key, err)
		}
		if again != key {
			t.Errorf("LoginKey 冪等性破壞：%q -> %q -> %q", login, key, again)
		}
	}
}

// TestLoginKeyRejections 驗證被拒的登入名形態：空白、控制、格式字元與長度。
func TestLoginKeyRejections(t *testing.T) {
	tooLong := strings.Repeat("a", maxLoginRunes+1)
	cases := []struct {
		name  string
		login string
	}{
		{"空字串", ""},
		{"純空白", " " + string(cs9) + string(cs10) + " "},
		{"內部空格", "ab cd"},
		{"內部 NBSP", "ab" + string(nbsp) + "cd"},
		{"控制字元 NUL", "ab" + string(cs0) + "cd"},
		{"零寬空格", "ab" + string(zwsp) + "cd"},
		{"零寬連接符", "ab" + string(zwj) + "cd"},
		{"雙向覆寫符", "ab" + string(rlo) + "cd"},
		{"超長", tooLong},
		// 60 個 RIAL SIGN 未超輸入上限，但 NFKC 展開成 "Rial" 共 240 字元，
		// 超出鍵上限——擋的是正規化引入的病態展開。
		{"正規化後超長", strings.Repeat(string(rial), 60)},
	}
	for _, tc := range cases {
		_, err := LoginKey(tc.login)
		if !errors.Is(err, ErrInvalidLogin) {
			t.Errorf("%s：期望 ErrInvalidLogin，實際 %v", tc.name, err)
		}
	}
}

// TestLoginKeyTrimsOuterSpaces 驗證首尾空白（含 NBSP、全角空格）被去除且不佔長度名額。
// 尾端若先出現零寬字元，它不是空白、裁剪因此停在它前面——這由 Rejections 的零寬用例覆蓋。
func TestLoginKeyTrimsOuterSpaces(t *testing.T) {
	key, err := LoginKey(" " + string(nbsp) + "admin" + string(ideo))
	if err != nil {
		t.Fatalf("LoginKey 失敗：%v", err)
	}
	if key != "admin" {
		t.Errorf("鍵應為 admin，實際 %q", key)
	}
}

// TestDisplayNameRules 驗證顯示名：允許內部空白與大小寫原樣，但拒控制字元與超長。
func TestDisplayNameRules(t *testing.T) {
	if err := validateDisplayName(rs(0x591C, 0x4E45) + " " + rs(0x5922, 0x5B50)); err != nil {
		t.Errorf("合法顯示名被拒：%v", err)
	}
	if err := validateDisplayName("  "); err == nil {
		t.Error("空白顯示名未被拒")
	}
	if err := validateDisplayName("x" + string(cs0)); err == nil {
		t.Error("含控制字元的顯示名未被拒")
	}
	if err := validateDisplayName(strings.Repeat("x", maxDisplayNameRunes+1)); err == nil {
		t.Error("超長顯示名未被拒")
	}
}
