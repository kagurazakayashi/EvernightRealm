package credential

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// 本套件一律使用 TestParams（低成本檔）：測試要快靠的是「測試自備參數」，
// 絕不借用或調低 ProductionParams。生產檔只在本檔最後一組測試裡實跑一次，
// 證明出廠預設本身可產生、可校驗。

func TestHashVerifyRoundTrip(t *testing.T) {
	encoded, err := Hash("正確馬蹄#7", TestParams)
	if err != nil {
		t.Fatalf("Hash 失敗: %v", err)
	}
	ok, err := Verify(encoded, "正確馬蹄#7")
	if err != nil || !ok {
		t.Fatalf("正確密碼應通過（ok=%t err=%v）", ok, err)
	}
	ok, err = Verify(encoded, "錯誤密碼")
	if err != nil || ok {
		t.Fatalf("錯誤密碼應拒絕（ok=%t err=%v）", ok, err)
	}
}

func TestHashSaltIndependent(t *testing.T) {
	a, err := Hash("same-password", TestParams)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Hash("same-password", TestParams)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("同一明文的兩次 Hash 不得產生相同編碼（鹽必須獨立）")
	}
	// 兩份都要能獨立校驗通過。
	for _, h := range []string{a, b} {
		if ok, err := Verify(h, "same-password"); err != nil || !ok {
			t.Fatalf("獨立鹽的兩份雜湊都應可校驗（ok=%t err=%v）", ok, err)
		}
	}
}

func TestHashRejectsEmptyAndOversized(t *testing.T) {
	if _, err := Hash("", TestParams); err == nil {
		t.Error("空憑據必須拒絕")
	}
	if _, err := Hash(strings.Repeat("a", MaxPasswordLength+1), TestParams); err == nil {
		t.Error("超過 MaxPasswordLength 的明文必須拒絕")
	}
	if _, err := Hash(strings.Repeat("a", MaxPasswordLength), TestParams); err != nil {
		t.Errorf("恰為上限的明文應可產生: %v", err)
	}
}

func TestVerifySkipsDeriveForBadPasswordLength(t *testing.T) {
	encoded, err := Hash("x", TestParams)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := Verify(encoded, ""); err != nil || ok {
		t.Errorf("空明文應直接判否（ok=%t err=%v）", ok, err)
	}
	if ok, err := Verify(encoded, strings.Repeat("x", MaxPasswordLength+1)); err != nil || ok {
		t.Errorf("超長明文應直接判否（ok=%t err=%v）", ok, err)
	}
}

func TestHashInvalidParamsRejected(t *testing.T) {
	bad := []Params{
		{MemoryKiB: 0, TimeCost: 1, Parallelism: 1, KeyLength: 16},
		{MemoryKiB: MinMemoryKiB, TimeCost: 0, Parallelism: 1, KeyLength: 16},
		{MemoryKiB: MaxMemoryKiB + 1024, TimeCost: 1, Parallelism: 1, KeyLength: 16},
		{MemoryKiB: MinMemoryKiB, TimeCost: 1, Parallelism: 0, KeyLength: 16},
		{MemoryKiB: MinMemoryKiB, TimeCost: 1, Parallelism: MaxParallelism + 1, KeyLength: 16},
		{MemoryKiB: MinMemoryKiB, TimeCost: 1, Parallelism: 1, KeyLength: 8},
		{MemoryKiB: MinMemoryKiB, TimeCost: 1, Parallelism: 1, KeyLength: MaxKeyLength + 1},
		{MemoryKiB: MinMemoryKiB, TimeCost: MaxTimeCost + 1, Parallelism: 1, KeyLength: 16},
	}
	for i, p := range bad {
		if _, err := Hash("x", p); err == nil {
			t.Errorf("第 %d 組非法參數必須在進入 argon2 前被擋下（防 panic）", i)
		}
	}
}

// 合法形狀樣板（無填補 base64）：15B 鹽、16B 摘要。
const (
	sampleSalt = "c29tZXNhbHRzbXRoOiE"
	sampleSum  = "AAAAAAAAAAAAAAAAAAAAAA"
)

func TestVerifyMalformedEncodings(t *testing.T) {
	cases := []struct {
		name    string
		encoded string
	}{
		{"空字串", ""},
		{"非編碼", "plaintext-secret"},
		{"段數不足", "$argon2id$v=19"},
		{"段數過多", "$argon2id$v=19$m=8192,t=1,p=1$" + sampleSalt + "$" + sampleSum + "$extra"},
		{"缺前導$", "argon2id$v=19$m=8192,t=1,p=1$" + sampleSalt + "$" + sampleSum},
		{"算法名錯（argon2d）", "$argon2d$v=19$m=8192,t=1,p=1$" + sampleSalt + "$" + sampleSum},
		{"算法名錯（argon2i）", "$argon2i$v=19$m=8192,t=1,p=1$" + sampleSalt + "$" + sampleSum},
		{"版本段錯", "$argon2id$v=16$m=8192,t=1,p=1$" + sampleSalt + "$" + sampleSum},
		{"參數段缺項", "$argon2id$v=19$m=8192,t=1$" + sampleSalt + "$" + sampleSum},
		{"參數段多項", "$argon2id$v=19$m=8192,t=1,p=1,x=2$" + sampleSalt + "$" + sampleSum},
		{"參數段亂序", "$argon2id$v=19$t=1,m=8192,p=1$" + sampleSalt + "$" + sampleSum},
		{"m 非數字", "$argon2id$v=19$m=abc,t=1,p=1$" + sampleSalt + "$" + sampleSum},
		{"m 帶正負號", "$argon2id$v=19$m=+8192,t=1,p=1$" + sampleSalt + "$" + sampleSum},
		{"m 前導零", "$argon2id$v=19$m=08192,t=1,p=1$" + sampleSalt + "$" + sampleSum},
		{"t 為零", "$argon2id$v=19$m=8192,t=0,p=1$" + sampleSalt + "$" + sampleSum},
		{"鹽段非法 base64", "$argon2id$v=19$m=8192,t=1,p=1$***bad***$" + sampleSum},
		{"鹽過短", "$argon2id$v=19$m=8192,t=1,p=1$AAAAAAAA$" + sampleSum},
		{"摘要過短", "$argon2id$v=19$m=8192,t=1,p=1$" + sampleSalt + "$AAAA"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := Verify(tc.encoded, "whatever")
			if ok {
				t.Error("非法編碼不得回報匹配")
			}
			if err == nil {
				t.Error("非法編碼應回報解析錯誤供運維追溯")
			}
			if err != nil && tc.encoded != "" && strings.Contains(err.Error(), tc.encoded) {
				t.Errorf("錯誤訊息不得回顯完整編碼: %v", err)
			}
		})
	}
}

func TestVerifyRejectsOutOfRangeParams(t *testing.T) {
	// 越界參數必須在解析階段被硬性上限擋下，進不了派生——
	// 這就是「壞雜湊不能要求無限記憶體／CPU」的執行點。
	oversized := []string{
		"m=1048577,t=1,p=1",    // 剛越過 1 GiB 上限
		"m=4294967295,t=1,p=1", // 遠超上限
		"m=8192,t=33,p=1",      // 越過 MaxTimeCost
		"m=8192,t=1,p=255",     // 越過 MaxParallelism
	}
	for _, params := range oversized {
		enc := "$argon2id$v=19$" + params + "$" + sampleSalt + "$" + sampleSum
		ok, err := Verify(enc, "x")
		if ok || !errors.Is(err, ErrUnsupportedParams) {
			t.Errorf("越界參數 %q 應被上限擋下，實際 ok=%t err=%v", params, ok, err)
		}
	}
	// 大到進不了 uint32 的數值屬「非法數字」而非「越界參數」，同样拒。
	enc := "$argon2id$v=19$m=8192,t=999999999999999999999,p=1$" + sampleSalt + "$" + sampleSum
	if ok, err := Verify(enc, "x"); ok || err == nil {
		t.Error("超大數值必須拒絕")
	}
}

func TestVerifyToleratesBase64PaddingVariants(t *testing.T) {
	// 產生端用無填補；帶填補的既有外部雜湊也要能校验——寬容只給填補與否。
	raw, err := Hash("padded-or-not", TestParams)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, "$")
	for i := 4; i <= 5; i++ {
		b, _ := base64.RawStdEncoding.DecodeString(parts[i])
		parts[i] = base64.StdEncoding.EncodeToString(b) // 補上 '='
	}
	padded := strings.Join(parts, "$")
	if padded == raw {
		t.Skip("該隨機編碼恰好不需填補，換一輪再驗")
	}
	if ok, err := Verify(padded, "padded-or-not"); err != nil || !ok {
		t.Errorf("帶填補的合法編碼應可校驗（ok=%t err=%v）", ok, err)
	}
}

func TestEncodingShapeIsCanonical(t *testing.T) {
	// 固定鹽斷言編碼形狀：$argon2id$v=19$m=,t=,p= 依序、無填補 base64。
	salt := bytes.Repeat([]byte{0xAB}, SaltLength)
	encoded, err := hashWithRand("shape-check", TestParams, bytes.NewReader(salt))
	if err != nil {
		t.Fatal(err)
	}
	prefix := "$argon2id$v=19$m=8192,t=1,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$"
	if !strings.HasPrefix(encoded, prefix) {
		t.Fatalf("編碼形狀不符：%s", encoded)
	}
	if strings.ContainsRune(strings.TrimPrefix(encoded, prefix), '=') {
		t.Error("產生端編碼的 base64 不得帶填補")
	}
	if len(encoded) > MaxEncodedLength {
		t.Errorf("編碼長度 %d 超過落庫上限 %d", len(encoded), MaxEncodedLength)
	}
}

func TestMemoryRoundingConsistency(t *testing.T) {
	// m 非 MiB 整數倍時派生就近向上取整；產生與校驗走同一折算，往返必須成立。
	p := Params{MemoryKiB: 8193, TimeCost: 1, Parallelism: 1, KeyLength: 16}
	encoded, err := Hash("rounding", p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(encoded, "m=8193") {
		t.Errorf("編碼應保留原值 m=8193: %s", encoded)
	}
	if ok, err := Verify(encoded, "rounding"); err != nil || !ok {
		t.Fatalf("取整後的往返應成立（ok=%t err=%v）", ok, err)
	}
	// 原值不同即標記升級，即使取整後算力相同（寧多換不漏換）。
	up, err := NeedsUpgrade(encoded, Params{MemoryKiB: 8192, TimeCost: 1, Parallelism: 1, KeyLength: 16})
	if err != nil || !up {
		t.Errorf("m 原值不同應標記升級（up=%t err=%v）", up, err)
	}
}

func TestNeedsUpgrade(t *testing.T) {
	encoded, err := Hash("upgrade-me", TestParams)
	if err != nil {
		t.Fatal(err)
	}
	if up, err := NeedsUpgrade(encoded, TestParams); err != nil || up {
		t.Errorf("同檔參數不得標記升級（up=%t err=%v）", up, err)
	}
	higher := TestParams
	higher.TimeCost = 2
	if up, err := NeedsUpgrade(encoded, higher); err != nil || !up {
		t.Errorf("策略已升檔應標記升級（up=%t err=%v）", up, err)
	}
	if _, err := NeedsUpgrade("$argon2id$v=19$junk", TestParams); err == nil {
		t.Error("非法編碼應回報錯誤，是否重置憑據由上層決策")
	}
}

func TestVerifyPlaceholderAlwaysFalseAndSafe(t *testing.T) {
	if VerifyPlaceholder("anything", TestParams) {
		t.Error("佔位校驗恆為 false")
	}
	if VerifyPlaceholder("", TestParams) || VerifyPlaceholder(strings.Repeat("x", MaxPasswordLength+1), TestParams) {
		t.Error("空/超長明文在佔位校驗同樣為 false")
	}
	if VerifyPlaceholder("x", Params{}) {
		t.Error("非法參數檔的佔位校驗不得 panic 或回報成功")
	}
}

func TestUnicodePasswords(t *testing.T) {
	cases := []struct{ name, password string }{
		{"簡體", "长夜幻境·账户"},
		{"繁體", "長夜幻境·帳戶"},
		{"日文", "長い夜—幻境"},
		{"Emoji 與ZWJ", "🌙‍🏮🎑"},
		{"組合字元", "café"}, // 拉丁小寫 e + U+0301 組合附加符
		{"零寬字元混入", "密‌碼"},
		{"全形半形混排", "ＰＩＮ：８８９９"},
		{"CRLF 控制序列", "a\r\nb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := Hash(tc.password, TestParams)
			if err != nil {
				t.Fatalf("Unicode 明文應可產生: %v", err)
			}
			if ok, err := Verify(encoded, tc.password); err != nil || !ok {
				t.Errorf("同明文往返應成立（ok=%t err=%v）", ok, err)
			}
		})
	}
	// 位元組精確語意：NFC 與 NFD 是兩個不同明文，不自動歸一。
	nfc := "café"  // 預組形式
	nfd := "café" // e + 組合附加符
	encoded, err := Hash(nfc, TestParams)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := Verify(encoded, nfd); ok {
		t.Error("本套件不做 Unicode 歸一：NFC/NFD 必須視為不同憑據（歸一與否屬上層策略）")
	}
}

func TestErrorMessagesCarryNoSecrets(t *testing.T) {
	const password = "極度機密的口令"
	encoded, err := Hash(password, TestParams)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(strings.ReplaceAll(encoded, "v=19", "v=16"), password)
	if err == nil {
		t.Fatal("應有解析錯誤")
	}
	// 錯誤鏈裡既不得出現明文，也不得出現鹽/摘要段的任何完整 base64。
	if strings.Contains(err.Error(), password) {
		t.Errorf("錯誤訊息含明文: %v", err)
	}
	for _, seg := range strings.Split(encoded, "$")[4:] {
		if strings.Contains(err.Error(), seg) {
			t.Errorf("錯誤訊息回顯編碼段 %q: %v", seg, err)
		}
	}
}

func TestProductionParamsRoundTrip(t *testing.T) {
	// 生產檔只實跑這一次：證明出廠預設可產生、可校驗、可被 NeedsUpgrade 認得。
	if err := ProductionParams.Validate(); err != nil {
		t.Fatalf("生產預設檔必須本身合法: %v", err)
	}
	if ProductionParams.MemoryKiB != 64*1024 || ProductionParams.TimeCost != 3 ||
		ProductionParams.Parallelism != 4 || ProductionParams.KeyLength != 32 {
		t.Errorf("生產檔偏離已批准的最低推薦檔: %+v", ProductionParams)
	}
	encoded, err := Hash("生產檔口令β", ProductionParams)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(encoded, "生產檔口令β")
	if err != nil || !ok {
		t.Fatalf("生產檔往返失敗（ok=%t err=%v）", ok, err)
	}
	if up, err := NeedsUpgrade(encoded, ProductionParams); err != nil || up {
		t.Errorf("剛以生產檔產生的憑據不應標記升級（up=%t err=%v）", up, err)
	}
}
