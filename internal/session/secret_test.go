package session

import (
	"errors"
	"go/parser"
	"go/token"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errReader 是一次性失败的随机源替身。
type errReader struct{}

// Read 恒失败，用于注入「随机源不可用」路径。
func (errReader) Read([]byte) (int, error) { return 0, errors.New("注入：隨機源失效") }

// 编译期确认替身满足 io.Reader。
var _ io.Reader = errReader{}

// TestNewSecretShape 验证秘密的形状契约：43 字元 base64url、解码恰为 32 位元组。
func TestNewSecretShape(t *testing.T) {
	secret, err := newSecret(nil)
	if err != nil {
		t.Fatalf("產生秘密失敗：%v", err)
	}
	if len(secret) != secretTextLen {
		t.Fatalf("秘密長度應為 %d，實際 %d", secretTextLen, len(secret))
	}
	if strings.ContainsAny(secret, "+/=") {
		t.Fatalf("秘密須為 base64url 安全字符集（不得含 +／/／=）：%s", secret)
	}
	raw, err := secretEncoding.DecodeString(secret)
	if err != nil || len(raw) != secretBytes {
		t.Fatalf("秘密應可還原為 %d 位元組：err=%v len=%d", secretBytes, err, len(raw))
	}
}

// TestNewSecretUsesCryptographicSource 从两个方向钉住「随机秘密必须来自
// crypto/rand」：结构上，包内非测试源码不得 import math/rand；
// 统计上，批量样本互不重复且比特密度接近真随机。
func TestNewSecretUsesCryptographicSource(t *testing.T) {
	// 结构闸：math/rand 是可复现序列，绝不能出现在会话秘密的产生路径上
	//（与 identity 套件的 import 走查同一手法：把约定变成会红的测试）。
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("讀取套件目錄失敗：%v", err)
	}
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("解析 %s 失敗：%v", name, err)
		}
		scanned++
		for _, imp := range file.Imports {
			if path := strings.Trim(imp.Path.Value, `"`); path == "math/rand" {
				t.Errorf("%s 不得 import math/rand（秘密必須取自密碼學隨機源）", name)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("走查未檢查任何檔案（目錄結構變化？）")
	}

	const samples = 512
	seen := make(map[string]bool, samples)
	var ones, total int
	for i := 0; i < samples; i++ {
		secret, err := newSecret(nil)
		if err != nil {
			t.Fatalf("第 %d 枚秘密產生失敗：%v", i, err)
		}
		if seen[secret] {
			t.Fatalf("第 %d 枚與先前重複（%d 枚 256 位元隨機值重複即為缺陷）", i, samples)
		}
		seen[secret] = true
		raw, err := secretEncoding.DecodeString(secret)
		if err != nil {
			t.Fatalf("樣本解碼失敗：%v", err)
		}
		for _, b := range raw {
			ones += bits.OnesCount8(b)
			total += 8
		}
	}
	// 公平硬币的 131072 个比特偏离 50% 超过 5 个标准差的概率按真随机几乎为零，
	// 该区间足以抓住「恒定前缀」「计数器递增」「小种子展开」这类伪随机退化。
	if ratio := float64(ones) / float64(total); ratio < 0.47 || ratio > 0.53 {
		t.Errorf("隨機位元密度 %.4f 偏離 0.5 過遠，疑似非密碼學隨機源", ratio)
	}
}

// TestNewSecretFailurePropagates 验证随机源失败时回传错误而不是降级。
func TestNewSecretFailurePropagates(t *testing.T) {
	secret, err := newSecret(errReader{})
	if err == nil {
		t.Fatalf("隨機源失敗時應回錯誤，實際拿到秘密（長度 %d）", len(secret))
	}
	if secret != "" {
		t.Error("失敗時不得回傳任何秘密片段")
	}
	if !strings.Contains(err.Error(), "session:") {
		t.Errorf("錯誤應帶套件前綴：%v", err)
	}
}

// TestHashSecretProperties 验证查找键的性质：同明文同哈希、异明文异哈希、
// 输出恰为 64 字元小写十六进位、且哈希与明文互不成包含（库里读不出秘密）。
func TestHashSecretProperties(t *testing.T) {
	first := mustSecret(t)
	second := mustSecret(t)
	h1, err := hashSecret(first)
	if err != nil {
		t.Fatalf("合格秘密應可哈希：%v", err)
	}
	again, err := hashSecret(first)
	if err != nil || again != h1 {
		t.Fatalf("同明文哈希應確定：%v / %v", again, err)
	}
	h2, err := hashSecret(second)
	if err != nil {
		t.Fatalf("合格秘密應可哈希：%v", err)
	}
	if h1 == h2 {
		t.Fatal("兩枚不同秘密哈希相同")
	}
	for _, h := range []string{h1, h2} {
		if len(h) != tokenHashLen || strings.ToLower(h) != h || hexBad(h) {
			t.Fatalf("哈希應為 64 字元小寫十六進位：%s", h)
		}
	}
	if strings.Contains(h1, first) || strings.Contains(first, h1[:20]) {
		t.Fatal("哈希與明文互相暴露")
	}
}

// hexBad 回报字符串是否含非十六进位字符。
func hexBad(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return true
		}
	}
	return false
}

// TestHashSecretRejectsMalformed 钉住门前拒绝：形状不合格的输入一律
// ErrInvalidSecret，不送进哈希。
func TestHashSecretRejectsMalformed(t *testing.T) {
	valid := mustSecret(t)
	// 32 位元組的 RawURLEncoding 尾字符只可能是字母表索引 4 的倍数（末两位必为 0）；
	// 'B'（索引 1）是「解得开码但重编不回原样」的非正规写法，必须被拒。
	// newSecret 的产物尾字符恒在正规集内，因此替换后必不等于原串。
	nonCanonical := valid[:secretTextLen-1] + "B"
	if nonCanonical == valid {
		t.Fatalf("測試前提被破壞：正規秘密尾字符不应为 B（%s）", valid)
	}
	// 全零秘密在数学上是 crypto/rand 的小概率合法取值，必须被接受：
	// 拒绝它反而制造「某些秘密永远登不进去」的缺陷。
	if _, err := hashSecret(strings.Repeat("A", secretTextLen)); err != nil {
		t.Errorf("全零但形狀合法的秘密應被接受：%v", err)
	}
	cases := map[string]string{
		"空字串":         "",
		"過短":          valid[:40],
		"過長":          valid + "x",
		"含 URL 不安全字元": strings.Repeat("A", secretTextLen-1) + "/",
		"含 '+'":       strings.Repeat("A", secretTextLen-1) + "+",
		"非正規尾字符":      nonCanonical,
		"含空白":         " " + valid[1:],
	}
	for name, input := range cases {
		hash, err := hashSecret(input)
		if !errors.Is(err, ErrInvalidSecret) {
			t.Errorf("%s：應回 ErrInvalidSecret，實際 %v", name, err)
		}
		if hash != "" {
			t.Errorf("%s：拒絕時不得回哈希：%s", name, hash)
		}
	}
}

// mustSecret 产生一枚合格秘密（测试辅助）。
func mustSecret(t *testing.T) string {
	t.Helper()
	secret, err := newSecret(nil)
	if err != nil {
		t.Fatalf("產生測試秘密失敗：%v", err)
	}
	return secret
}
