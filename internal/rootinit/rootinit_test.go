package rootinit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
)

// testConfig 在測試專屬目錄建立一份「尚未初始化」的組態檔並回傳路徑。
//
// 內容刻意帶上 ExampleYAML（產品首次啟動真的會寫出的那一份），
// 這樣初始化路徑跑的就是實際檔案形狀，不是測試自己編的簡化版。
func testConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(config.ExampleYAML), 0o600); err != nil {
		t.Fatalf("建立測試組態檔失敗: %v", err)
	}
	return path
}

// storedHash 讀出檔案裡的憑據；未初始化時讓測試直接失敗。
func storedHash(t *testing.T, path string) string {
	t.Helper()
	state, err := config.ReadRootFile(path)
	if err != nil {
		t.Fatalf("讀取組態檔失敗: %v", err)
	}
	if !state.Initialized() {
		t.Fatalf("組態檔內沒有 Root 憑據，測試前置條件不成立")
	}
	return state.Hash
}

// mustVerify 斷言某個明文能驗過檔案裡那份憑據。
func mustVerify(t *testing.T, hash, secret string) bool {
	t.Helper()
	ok, err := credential.Verify(hash, secret)
	if err != nil {
		t.Fatalf("校驗失敗: %v", err)
	}
	return ok
}

func TestInitializeFirstSuccess(t *testing.T) {
	path := testConfig(t)
	const secret = "first-root-secret-_pass"

	res, err := Initialize(Options{ConfigPath: path, Secret: secret, Params: credential.TestParams})
	if err != nil {
		t.Fatalf("首次初始化失敗: %v", err)
	}
	if res.Params != credential.TestParams {
		t.Errorf("結果未回報生效的參數檔：%+v", res.Params)
	}

	hash := storedHash(t, path)
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("落進組態檔的不是 Argon2id 編碼：%q", hash)
	}
	if !mustVerify(t, hash, secret) {
		t.Error("寫入後的憑據驗不過這次交上來的口令")
	}
	// 參數檔要以編碼內自帶值落地（之後校驗按檔案裡的值，不按當前策略）。
	if ok, err := credential.NeedsUpgrade(hash, credential.TestParams); err != nil || ok {
		t.Errorf("用同一檔產生卻被標記為需升級: ok=%v err=%v", ok, err)
	}
	// 載入路徑必須讀得到它，否則「啟動後生效」這句話是空的。
	cfg, err := config.Load(config.Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("初始化後 Load 失敗: %v", err)
	}
	if cfg.Security.RootPasswordHash != hash {
		t.Error("Load 讀到的 Root 憑據與檔案不一致")
	}
	if strings.Contains(cfg.Redacted(), hash) {
		t.Error("啟動摘要輸出了 Root 憑據內容")
	}

	state, err := Status(path)
	if err != nil {
		t.Fatalf("Status 失敗: %v", err)
	}
	if !state.ConfigExists || !state.Initialized {
		t.Errorf("初始化後的狀態不正確: %+v", state)
	}
}

func TestInitializeRefusesSecondAttempt(t *testing.T) {
	path := testConfig(t)
	const first = "the-one-root-secret"
	const second = "another-root-secret"

	if _, err := Initialize(Options{ConfigPath: path, Secret: first, Params: credential.TestParams}); err != nil {
		t.Fatalf("首次初始化失敗: %v", err)
	}
	before := readFileBytes(t, path)

	_, err := Initialize(Options{ConfigPath: path, Secret: second, Params: credential.TestParams})
	if !errors.Is(err, config.ErrRootAlreadyInitialized) {
		t.Fatalf("第二次初始化應回 ErrRootAlreadyInitialized，實際 %v", err)
	}
	if after := readFileBytes(t, path); after != before {
		t.Error("被拒絕的第二次初始化改動了組態檔")
	}
	// 既有憑據仍是第一個口令，第二個不可能頂替它。
	hash := storedHash(t, path)
	if !mustVerify(t, hash, first) {
		t.Error("既有 Root 憑據被換掉了（第一個口令驗不過）")
	}
	if ok := mustVerify(t, hash, second); ok {
		t.Error("第二個口令竟然驗過了既有憑據")
	}
	// 錯誤訊息不能把口令或憑據講出去。
	if strings.Contains(err.Error(), first) || strings.Contains(err.Error(), second) {
		t.Errorf("錯誤訊息回顯了口令: %v", err)
	}
}

func TestInitializeRejectsUnqualifiedSecret(t *testing.T) {
	cases := map[string]string{
		"空口令":  "",
		"超長口令": strings.Repeat("夜", credential.MaxPasswordLength),
		"含換行":  "line1\nline2",
		"含回車":  "line1\r\n",
	}
	for name, secret := range cases {
		t.Run(name, func(t *testing.T) {
			path := testConfig(t)
			before := readFileBytes(t, path)

			_, err := Initialize(Options{ConfigPath: path, Secret: secret, Params: credential.TestParams})
			if err == nil {
				t.Fatal("不合格的口令應被拒絕")
			}
			if after := readFileBytes(t, path); after != before {
				t.Error("被拒絕的呼叫改動了組態檔")
			}
			if state, err := Status(path); err != nil || state.Initialized {
				t.Errorf("被拒絕後仍應是未初始化: %+v err=%v", state, err)
			}
			if secret != "" && strings.Contains(err.Error(), secret) {
				t.Errorf("錯誤訊息回顯了口令: %v", err)
			}
		})
	}
}

func TestInitializeRejectsInvalidParams(t *testing.T) {
	// 零值參數檔繞不過 credential.Params 的區間校驗，也不該讓檔案被碰過。
	for _, params := range []credential.Params{
		{},
		{MemoryKiB: 1024, TimeCost: 0, Parallelism: 1, KeyLength: 16},
		{MemoryKiB: 1024, TimeCost: 1, Parallelism: 0, KeyLength: 16},
		{MemoryKiB: 1024, TimeCost: 1, Parallelism: 1, KeyLength: 8},
	} {
		path := testConfig(t)
		_, err := Initialize(Options{ConfigPath: path, Secret: "a-secret-value", Params: params})
		if err == nil {
			t.Fatalf("不合格參數檔 %+v 竟被接受", params)
		}
		if state, err := Status(path); err != nil || state.Initialized {
			t.Errorf("拒絕路徑改動了狀態: %+v err=%v", state, err)
		}
	}
}

func TestInitializeNeedsExistingConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	_, err := Initialize(Options{ConfigPath: path, Secret: "a-secret-value", Params: credential.TestParams})
	if err == nil || !strings.Contains(err.Error(), "找不到組態檔") {
		t.Fatalf("組態檔不存在時應明確回報，實際 %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("失敗路徑不得建立組態檔")
	}

	if _, err := Initialize(Options{Secret: "a-secret-value", Params: credential.TestParams}); err == nil {
		t.Fatal("缺少組態檔路徑應回報錯誤")
	}
}

func TestInitializeConcurrentAttemptsWriteOnlyOnce(t *testing.T) {
	path := testConfig(t)
	const racers = 6

	secrets := make([]string, racers)
	errs := make([]error, racers)
	results := make([]Result, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range secrets {
		secrets[i] = fmt.Sprintf("contending-root-secret-%02d", i)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = Initialize(Options{
				ConfigPath: path, Secret: secrets[i], Params: credential.TestParams,
			})
		}(i)
	}
	close(start)
	wg.Wait()

	var winners []int
	for i, err := range errs {
		switch {
		case err == nil:
			winners = append(winners, i)
		case errors.Is(err, config.ErrRootAlreadyInitialized):
		default:
			t.Fatalf("第 %d 個競跑的錯誤不在預期內: %v", i, err)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("成功次數=%d，期望恰好 1", len(winners))
	}
	hash := storedHash(t, path)
	if !mustVerify(t, hash, secrets[winners[0]]) {
		t.Error("檔案裡的憑據不是成功那次交上來的口令")
	}
	for i := range errs {
		if i == winners[0] {
			continue
		}
		if mustVerify(t, hash, secrets[i]) {
			t.Errorf("落敗的第 %d 個口令竟也驗得過", i)
		}
	}
}

func TestInitializeKeepsByteExactSecretSemantics(t *testing.T) {
	cases := map[string]string{
		"簡體":        "长夜幻境--root-2026",
		"繁體":        "長夜幻境-Root-2026",
		"日文":        "よる-幻境-2026",
		"Emoji＋ZWJ": "root👨‍👩‍👧-2026",
		"組合字元":      "ròot-幻境",
		"零寬字元":      "ro​ot-幻境",
		"全形字元":      "ｒｏｏｔ-幻境",
	}
	for name, secret := range cases {
		t.Run(name, func(t *testing.T) {
			path := testConfig(t)
			if _, err := Initialize(Options{ConfigPath: path, Secret: secret, Params: credential.TestParams}); err != nil {
				t.Fatalf("初始化失敗: %v", err)
			}
			if !mustVerify(t, storedHash(t, path), secret) {
				t.Error("該明文與落盤憑據不相符")
			}
		})
	}

	// NFC 與 NFD 是兩個不同的口令：初始化用哪一種，另一種就不能登進來。
	nfc := "ròot"       // 預組形：r + U+00F2 + o + t
	nfd := "ro\u0300ot" // 組合形：r + o + U+0300 + o + t
	if nfc == nfd {
		t.Fatal("測試前置條件不成立：兩種寫法應為不同位元組")
	}
	path := testConfig(t)
	if _, err := Initialize(Options{ConfigPath: path, Secret: nfc, Params: credential.TestParams}); err != nil {
		t.Fatalf("初始化失敗: %v", err)
	}
	if mustVerify(t, storedHash(t, path), nfd) {
		t.Error("NFD 寫法驗過了 NFC 初始化的憑據（位元組精確語意被放寬）")
	}
}

func TestInitializeErrorsNeverContainCredentialMaterial(t *testing.T) {
	const secret = "do-not-leak-this-root-secret"
	path := testConfig(t)
	if _, err := Initialize(Options{ConfigPath: path, Secret: secret, Params: credential.TestParams}); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	_, err := Initialize(Options{ConfigPath: path, Secret: secret, Params: credential.TestParams})
	if err == nil {
		t.Fatal("第二次應失敗")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), storedHash(t, path)) {
		t.Errorf("錯誤訊息含口令或憑據: %v", err)
	}
	// Result 本身也不該帶著材料（它沒有那種欄位；這條斷言把「別加欄位」釘住）。
	if fmt.Sprintf("%+v", Result{}) == "" {
		t.Fatal("Result 的表示不可為空字串")
	}
}

func TestStatusReportsMinimalState(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "config.yaml")

	state, err := Status(missing)
	if err != nil {
		t.Fatalf("組態檔不存在不是錯誤: %v", err)
	}
	if state.ConfigExists || state.Initialized {
		t.Errorf("不存在的組態檔應回報兩者皆 false: %+v", state)
	}
	// 這個狀態被序列化成任何東西時都不該出現路徑或憑據——它是給界面用的。
	if strings.Contains(fmt.Sprintf("%+v", state), "config.yaml") || strings.Contains(fmt.Sprintf("%+v", state), "$argon2id$") {
		t.Errorf("狀態攜帶了不應外洩的資訊: %+v", state)
	}

	if _, err := Status(""); err == nil {
		t.Error("缺少路徑應回報錯誤")
	}

	path := testConfig(t)
	state, err = Status(path)
	if err != nil || !state.ConfigExists || state.Initialized {
		t.Fatalf("新建的範例組態應是「已存在、未初始化」: %+v err=%v", state, err)
	}
	if _, err := Initialize(Options{ConfigPath: path, Secret: "status-check-secret", Params: credential.TestParams}); err != nil {
		t.Fatalf("初始化失敗: %v", err)
	}
	if state, err = Status(path); err != nil || !state.Initialized {
		t.Fatalf("初始化後的狀態不正確: %+v err=%v", state, err)
	}
}

func TestStatusRejectsMalformedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("security:\n  root_password_hash: [a, b]\n"), 0o600); err != nil {
		t.Fatalf("建立測試組態檔失敗: %v", err)
	}
	if _, err := Status(path); err == nil {
		t.Fatal("欄位形狀不合格時應回報錯誤，而不是當成未初始化")
	}
}

// readFileBytes 讀出檔案原始位元組供「有沒有被改動」比對。
func readFileBytes(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取 %s 失敗: %v", path, err)
	}
	return string(data)
}

func TestInitializeRefusesUnusableExistingCredential(t *testing.T) {
	// 「已有但不可用」要回自己的錯誤，而不是偽裝成「已初始化」：
	// 前者的意思是現在根本登不進去，後者的意思是請改走改密流程，建議完全不同。
	const garbage = "$argon2id$v=19$m=8192,t=1,p=1$not-base64!!$also-not-base64!!"
	// 壞值是手工放進檔案的（真實形態就是「有人在編輯器裡貼錯了一串」）：
	// 寫入通路本身已拒絕這種值，所以不能再用它來構造前置條件。
	path := filepath.Join(t.TempDir(), "config.yaml")
	planted := "server:\n  listen: \"127.0.0.1:5206\"\n" +
		"security:\n  root_password_hash: \"" + garbage + "\"\n"
	if err := os.WriteFile(path, []byte(planted), 0o600); err != nil {
		t.Fatalf("放入壞值失敗: %v", err)
	}

	_, err := Initialize(Options{ConfigPath: path, Secret: "wanna-fix-pw", Params: credential.TestParams})
	if !errors.Is(err, ErrUnusableExistingCredential) {
		t.Fatalf("應回 ErrUnusableExistingCredential，實際 %v", err)
	}
	if strings.Contains(err.Error(), "wanna-fix-pw") {
		t.Errorf("錯誤回顯了口令: %v", err)
	}
	// 刻意不-cover 那個壞值：留著它，操作者才能自己判斷那是打字錯誤還是被動過。
	if got := readFileBytesForRootinitTest(t, path); !strings.Contains(got, garbage) {
		t.Error("拒絕路徑改動了既有（壞）憑據")
	}
}

// readFileBytesForRootinitTest 讀出檔案原始位元組供「有沒有被改動」比對。
func readFileBytesForRootinitTest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取 %s 失敗: %v", path, err)
	}
	return string(data)
}
