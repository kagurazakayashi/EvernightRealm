package credential

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2 編碼與輸入的尺寸常數。
const (
	// algorithm 是 PHC 編碼裡的算法標識，也是 config/account 前綴校驗認的那一段。
	algorithm = "argon2id"
	// version 是 Argon2 規範版本（RFC 9106 固定 v19）；校驗只認此值，
	// 未來若實作新版本也走「識別→拒絕或遷移」，不靜默當同版本處理。
	version = 19
	// SaltLength 是 Hash 產生之隨機鹽的長度（位元組）；
	// 校驗側接受 8~MaxSaltLength，兼容既有外部工具產生的合法雜湊。
	SaltLength = 16
	// MaxSaltLength 是校驗可接受的鹽長度上限（位元組）。
	MaxSaltLength = 64
	// MaxEncodedLength 是編碼字串長度上限（位元組），與 accounts.password_hash
	// 的資料庫 CHECK 及 config Root 雜湊的落庫形态同口徑；超長字串在解析前就拒，
	// 不給「靠巨型 base64 撐爆記憶體」的機會。
	MaxEncodedLength = 512
	// MaxPasswordLength 是明文密碼的位元組上限。上層（HTTP 層）另有請求體上限，
	// 這裡的界線是模組自衛：派生的輸入必須有界，Unicode 長口令也遠不到此值。
	MaxPasswordLength = 1024
)

// placeholderSalt 是 VerifyPlaceholder 使用的固定鹽。
//
// 它不是秘密——只用來把「帳戶不存在」分支的耗時拉到與真實校驗同階，
// 派生結果直接丟棄，因此固定值不構成任何可被利用的差異。
var placeholderSalt = []byte("evernight-placeholder-salt") // 26 bytes，落在 [8,64]

// ErrMalformedEncoding 表示編碼字串不是合法的 Argon2id PHC 編碼。
//
// 具體哪一段壞掉屬內部解析細節：只能寫進被丟棄的包裝鏈，不進任何
// 對外錯誤、日誌或回應；對外一律收斂為「校驗未通過」。
var ErrMalformedEncoding = errors.New("credential: 憑據編碼不合法")

// ErrUnsupportedParams 表示編碼內參數超出許可區間（損壞、惡意或超出上界）。
var ErrUnsupportedParams = errors.New("credential: 憑據參數超出許可區間")

// HashError 是本套件可回報的輸入類錯誤（不含派生本身的故障）。
type HashError struct {
	// Reason 是可安全展示的原因描述，絕不含憑據材料。
	Reason string
}

// Error 實作 error。
func (e *HashError) Error() string { return "credential: " + e.Reason }

// Hash 以 p 檔參數產生 password 的 Argon2id 編碼雜湊（PHC 字串）。
//
// 每次調用都用 crypto/rand 新採一枚 SaltLength 位元組的鹽：同一明文兩次
// 產生必得不同編碼，跨帳戶不可互推。上層應在明文的長度／強度策略上先行把關，
// 本函數只擋「空憑據」與「超出模組界限的輸入」這兩種不應落庫的形態。
func Hash(password string, p Params) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	return hashWithRand(password, p, rand.Reader)
}

// hashWithRand 是 Hash 的可注入隨機源版本，僅供測試構造固定鹽以斷言編碼形狀；
// 產製路徑永遠經 Hash 使用 crypto/rand。
func hashWithRand(password string, p Params, saltSrc io.Reader) (string, error) {
	if password == "" {
		return "", &HashError{Reason: "憑據明文不得為空"}
	}
	if len(password) > MaxPasswordLength {
		return "", &HashError{Reason: fmt.Sprintf("憑據明文不得超過 %d 位元組", MaxPasswordLength)}
	}
	salt := make([]byte, SaltLength)
	if _, err := io.ReadFull(saltSrc, salt); err != nil {
		return "", fmt.Errorf("credential: 採集隨機鹽失敗: %w", err)
	}
	sum, err := derive(password, salt, p)
	if err != nil {
		return "", err
	}
	return encode(p, salt, sum), nil
}

// Verify 校驗 password 是否與 encoded 匹配，結果只以布爾值回報。
//
// 「匹配與否」是唯一的對外結論：編碼損壞、參數越界、摘要不符一律 false，
// 呼叫端（未來的登入路徑）因此天然不會把解析細節暴露給攻擊者。
// err 僅在「encoded 根本無法視為憑據」這種運維層面的異常時非 nil，
// 便於把配置寫壞的 Root 雜湊在啟動階段報出來；錯誤內容同樣不含憑據材料。
//
// 校驗按 encoded 內自帶的參數派生（不是按當前策略），所以調參／升檔
// 不影响既有憑據的可校驗性。
func Verify(encoded, password string) (bool, error) {
	p, salt, sum, err := decode(encoded)
	if err != nil {
		return false, err
	}
	if password == "" || len(password) > MaxPasswordLength {
		// 不合規的明文不需要派生：直接判否。空字串與超長輸入都不該
		// 消耗計算資源，也不因跳過派生而泄露什麼（上層另有輸入校驗）。
		return false, nil
	}
	got, err := derive(password, salt, p)
	if err != nil {
		// 派生失敗（超出本模組上界的參數已被 decode 擋掉，這裡只剩
		// argon2 實作自身的故障）：視為校驗未通過，錯誤只供運維追溯。
		return false, err
	}
	return subtle.ConstantTimeCompare(got, sum) == 1, nil
}

// CheckEncoding 只做編碼形狀與參數界線的解析，不執行派生，也不回傳任何解析結果。
//
// 它存在的理由只有一個：啟動摘要要能說出「檔案裡那一串不是可用的憑據」，
// 而把 decode 直接匯出等於多開一條能拿到鹽與摘要的通路——那個需求一個布爾結論就夠了。
// 錯誤一律是 ErrMalformedEncoding／ErrUnsupportedParams 的包裝鏈，訊息只含欄位名與數值，
// 不回顯鹽、摘要或整個編碼。
func CheckEncoding(encoded string) error {
	if _, _, _, err := decode(encoded); err != nil {
		return err
	}
	return nil
}

// NeedsUpgrade 回報 encoded 的參數是否不同於當前檔 p（供上層決定是否
// 在登入成功後順手重寫憑據）。
//
// 「不同」按編碼內的原始值逐欄比較（含記憶體 KiB 原值）：取整後實際算力
// 相同但原值不同的編碼也會被標記，多換一次雜湊無害，漏換才有害。
// 編碼不合法時回 err——是否把損壞編碼當作「必須重置憑據」屬產品決策，本層只報事實。
func NeedsUpgrade(encoded string, p Params) (bool, error) {
	got, _, _, err := decode(encoded)
	if err != nil {
		return false, err
	}
	if err := p.Validate(); err != nil {
		return false, err
	}
	return got != p, nil
}

// VerifyPlaceholder 以 p 檔參數對一個固定佔位鹽做完整派生並丟棄結果，
// 恆回 false。
//
// 用途：登入路徑在「帳戶不存在」分支調用它，讓兩個分支的外部耗時同階，
// 使攻擊者無法用時間差枚舉帳戶。它消耗的是真實參數檔的真實成本——
// 這正是它的存在意義，呼叫端不要省。
func VerifyPlaceholder(password string, p Params) bool {
	if err := p.Validate(); err != nil {
		return false
	}
	if password == "" || len(password) > MaxPasswordLength {
		return false
	}
	// 派生失敗同樣只以 false 對外：佔位校驗沒有任何對外可觀察的失敗語意。
	sum, err := derive(password, placeholderSalt, p)
	if err != nil {
		return false
	}
	_ = sum
	return false
}

// derive 執行 Argon2id 派生。
//
// argon2.IDKey 的簽名不接受錯誤，非法參數會 panic，所以全部約束
// （t>0、m>=8p、p>0、keylen∈[16,64]、salt>=8B）都必須在進入前校驗完畢：
// Validate 與 decode 就是那兩道閘。記憶體按「就近向上取整」折算成 MiB 整數倍。
func derive(password string, salt []byte, p Params) ([]byte, error) {
	if len(salt) < 8 {
		return nil, fmt.Errorf("%w: 鹽長度不足", ErrMalformedEncoding)
	}
	mib := (p.MemoryKiB + 1023) / 1024
	return argon2.IDKey([]byte(password), salt, p.TimeCost, mib*1024, p.Parallelism, p.KeyLength), nil
}

// encode 產出 PHC 編碼字串。base64 用標準字母表、無填補（RFC 9106 形式）。
func encode(p Params, salt, sum []byte) string {
	var b strings.Builder
	b.WriteString("$")
	b.WriteString(algorithm)
	b.WriteString("$v=")
	b.WriteString(strconv.Itoa(version))
	b.WriteString("$m=")
	b.WriteString(strconv.FormatUint(uint64(p.MemoryKiB), 10))
	b.WriteString(",t=")
	b.WriteString(strconv.FormatUint(uint64(p.TimeCost), 10))
	b.WriteString(",p=")
	b.WriteString(strconv.FormatUint(uint64(p.Parallelism), 10))
	b.WriteString("$")
	b.WriteString(base64.RawStdEncoding.EncodeToString(salt))
	b.WriteString("$")
	b.WriteString(base64.RawStdEncoding.EncodeToString(sum))
	return b.String()
}

// decodedCredential 是 decode 的解析結果。
type decodedCredential struct {
	params Params
	salt   []byte
	sum    []byte
}

// decode 嚴格解析編碼字串，任何一步不滿足即回 ErrMalformedEncoding／
// ErrUnsupportedParams 包裝錯誤（訊息只含欄位名與數值範圍，不回顯輸入內容）。
//
// 嚴格清單（缺一律拒）：
//   - 總長度 ≤ MaxEncodedLength；
//   - 恰好六段、以 $ 分隔，算法名固定 argon2id，版本固定 v=19；
//   - 參數段必須依序恰好是 m=,t=,p= 三項十進位非負整數（不許正負號、不許空白、
//     不許 0x 前綴），且逐欄落在許可區間；
//   - 鹽、摘要為合法 base64（接受帶填補或不帶，字母表必須是標準表）、
//     長度各自有界，摘要長度落值後補區間校驗。
func decode(encoded string) (Params, []byte, []byte, error) {
	if len(encoded) > MaxEncodedLength {
		return Params{}, nil, nil, fmt.Errorf("%w: 長度超過 %d 位元組", ErrMalformedEncoding, MaxEncodedLength)
	}
	parts := strings.Split(encoded, "$")
	// 前導 $ 使 parts[0] 恆為空；多一個 $（例如鹽裡混入）會把段數撐破。
	if len(parts) != 6 || parts[0] != "" {
		return Params{}, nil, nil, fmt.Errorf("%w: 段數不符", ErrMalformedEncoding)
	}
	if parts[1] != algorithm {
		return Params{}, nil, nil, fmt.Errorf("%w: 算法為 %q，僅支持 %q", ErrMalformedEncoding, parts[1], algorithm)
	}
	if parts[2] != fmt.Sprintf("v=%d", version) {
		return Params{}, nil, nil, fmt.Errorf("%w: 版本段 %q 不受支持", ErrMalformedEncoding, parts[2])
	}
	p, err := parseParams(parts[3])
	if err != nil {
		return Params{}, nil, nil, err
	}
	salt, err := decodeB64(parts[4])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: 鹽段無效", ErrMalformedEncoding)
	}
	if len(salt) < 8 || len(salt) > MaxSaltLength {
		return Params{}, nil, nil, fmt.Errorf("%w: 鹽長度 %d 不在 [%d,%d]",
			ErrUnsupportedParams, len(salt), 8, MaxSaltLength)
	}
	sum, err := decodeB64(parts[5])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: 摘要段無效", ErrMalformedEncoding)
	}
	// PHC 不聲明 KeyLength，摘要段實際長度即是；落值後補上區間校驗，
	// 越界（如 4 位元組摘要冒充憑據）在此擋下，不進 argon2 的 panic 區。
	p.KeyLength = uint32(len(sum))
	if p.KeyLength < MinKeyLength || p.KeyLength > MaxKeyLength {
		return Params{}, nil, nil, fmt.Errorf("%w: 摘要長度 %d 不在 [%d,%d]",
			ErrUnsupportedParams, len(sum), MinKeyLength, MaxKeyLength)
	}
	return p, salt, sum, nil
}

// parseParams 解析 "m=65536,t=3,p=4" 形式參數段。
func parseParams(s string) (Params, error) {
	fields := strings.Split(s, ",")
	if len(fields) != 3 {
		return Params{}, fmt.Errorf("%w: 參數段須恰有 m,t,p 三項", ErrMalformedEncoding)
	}
	var out [3]uint64
	keys := [3]string{"m", "t", "p"}
	for i, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok || k != keys[i] {
			return Params{}, fmt.Errorf("%w: 參數段第 %d 項應為 %s=<整數>", ErrMalformedEncoding, i+1, keys[i])
		}
		n, err := parseStrictUint(v)
		if err != nil {
			return Params{}, fmt.Errorf("%w: %s 欄 %q", ErrMalformedEncoding, k, v)
		}
		out[i] = n
	}
	if out[0] > math.MaxUint32 || out[1] > math.MaxUint32 || out[2] > math.MaxUint8 {
		return Params{}, fmt.Errorf("%w: 參數數值超出可表示範圍", ErrUnsupportedParams)
	}
	p := Params{
		MemoryKiB:   uint32(out[0]),
		TimeCost:    uint32(out[1]),
		Parallelism: uint8(out[2]),
	}
	if err := p.validateCosts(); err != nil {
		return Params{}, err
	}
	return p, nil
}

// decodeB64 以標準字母表解 base64，容忍帶填補與不帶填補兩種寫法。
//
// 先按 RawStd 試解；帶 '=' 填補的輸入會失敗，再退化到 StdEncoding。
// 兩條路都不接受非字母表字元，「寬容」只給填補與否這一個維度。
func decodeB64(s string) ([]byte, error) {
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// paramRange 產生「欄位 xxx=v 不在 [lo,hi]」樣式錯誤（數值非秘密，可入訊息）。
func paramRange(field string, v, lo, hi any) error {
	return fmt.Errorf("%w: %s=%v 不在 [%v,%v]", ErrUnsupportedParams, field, v, lo, hi)
}

// parseStrictUint 只接受「純十進位數字」字串：拒絕空串、正負號、
// 空白、0x/0b 前綴與底數技巧（strconv 的 ParseUint 接受 0x 前綴當 base=0，
// 這裡固定 base=10 就關掉了這個口）。前導零（"064"）同樣拒：
// PHC 正規形式沒有前導零，放進來只會讓「同一參數兩種寫法」成為解析歧義源。
func parseStrictUint(s string) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, errors.New("credential: 非正規整數寫法")
	}
	return strconv.ParseUint(s, 10, 64)
}
