package rootinit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
)

// recoverGarbageHash 是一個「非空但解不開」的憑據值：形状像 Argon2id，base64 段却是壞的。
const recoverGarbageHash = "$argon2id$v=19$m=8192,t=1,p=1$not-base64!!$also-not-base64!!"

// initializedConfig 造出「已經有 Root 憑據」的組態檔：先走一次正式初始化，
// 而不是測試自己拼那個欄位——兩條寫入通路面对的檔案形狀必須是同一個。
func initializedConfig(t *testing.T, secret string) string {
	t.Helper()
	path := testConfig(t)
	if _, err := Initialize(Options{ConfigPath: path, Secret: secret, Params: credential.TestParams}); err != nil {
		t.Fatalf("建立測試用 Root 憑據失敗: %v", err)
	}
	return path
}

// replaceStoredHashLine 把檔案裡那一行憑據值換成指定字串（保留其他全部行與註解）。
//
// 只按行替換而不重寫整份檔案：測試要造的狀態是「那個欄位的內容壞了」，
// 不是「測試自己擁有一套 YAML 寫檔能力」。
func replaceStoredHashLine(t *testing.T, path, value string) {
	t.Helper()
	lines := strings.Split(readFileForRecoverTest(t, path), "\n")
	replaced := 0
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "root_password_hash:") {
			lines[i] = `  root_password_hash: "` + value + `"`
			replaced++
		}
	}
	if replaced != 1 {
		t.Fatalf("測試前置條件：組態檔裡的憑據行應恰好一行，實際 %d", replaced)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatalf("改寫測試憑據行失敗: %v", err)
	}
}

// readFileForRecoverTest 讀出檔案原始字串，供「有沒有被改動／殘骸」比對。
func readFileForRecoverTest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取 %s 失敗: %v", path, err)
	}
	return string(data)
}

func TestRecoverReplacesExistingCredential(t *testing.T) {
	const oldSecret = "old-lost-root-_pass"
	const newSecret = "new-recovered-root-_pass"
	path := initializedConfig(t, oldSecret)
	before := storedHash(t, path)

	if _, err := Recover(RecoverOptions{ConfigPath: path, Secret: newSecret, Params: credential.TestParams}); err != nil {
		t.Fatalf("恢復失敗: %v", err)
	}

	hash := storedHash(t, path)
	if hash == before {
		t.Fatal("覆寫後的憑據與原本逐字相同，等於根本沒換")
	}
	if !mustVerify(t, hash, newSecret) {
		t.Error("新憑據驗不過這次交上來的口令")
	}
	if mustVerify(t, hash, oldSecret) {
		t.Error("舊口令竟然還驗得過新憑據")
	}
	// 節點級覆寫的代價是排版可能被重新編碼，但內容必須還在：範例組態的註解與其他欄位不許丟。
	got := readFileForRecoverTest(t, path)
	if !strings.Contains(got, "root_password_hash") || !strings.Contains(got, "data_dir") ||
		strings.Contains(got, oldSecret) || strings.Contains(got, newSecret) {
		t.Errorf("覆寫後的組態檔形狀不對：%s", got)
	}
	// 載入路徑讀得到新值，否則「重開程序後生效」這句話是空的。
	cfg, err := config.Load(config.Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("覆寫後載入組態失敗: %v", err)
	}
	if cfg.Security.RootPasswordHash != hash {
		t.Error("載入讀到的憑據與檔案不一致")
	}
	if cfg.RootHashNotice != "" {
		t.Errorf("合格的憑據不該產生提醒：%s", cfg.RootHashNotice)
	}
}

// TestRecoverAcceptsUnusableExistingCredential 釘住本條路與 init-root 的關鍵差別：
// 既有值壞到沒有人登得進去時，初始化會拒絕，而恢復正是那個狀態的出口。
func TestRecoverAcceptsUnusableExistingCredential(t *testing.T) {
	const newSecret = "fix-the-broken-root-_pass"
	path := initializedConfig(t, "was-fine-root-_pass")
	replaceStoredHashLine(t, path, recoverGarbageHash)

	if _, err := Initialize(Options{ConfigPath: path, Secret: newSecret, Params: credential.TestParams}); !errors.Is(err, ErrUnusableExistingCredential) {
		t.Fatalf("前置條件：init-root 對壞憑據應回 ErrUnusableExistingCredential，實際 %v", err)
	}
	if _, err := Recover(RecoverOptions{ConfigPath: path, Secret: newSecret, Params: credential.TestParams}); err != nil {
		t.Fatalf("恢復壞憑據失敗: %v", err)
	}
	hash := storedHash(t, path)
	if hash == recoverGarbageHash {
		t.Fatal("壞憑據沒有被換掉")
	}
	if !mustVerify(t, hash, newSecret) {
		t.Error("換好的憑據驗不過新口令")
	}
	// 載入那側的提醒應隨著壞值消失（同一個 config.Load 讀到可用憑據時不該再抱怨）。
	cfg, err := config.Load(config.Options{ConfigPath: path})
	if err != nil || cfg.RootHashNotice != "" {
		t.Errorf("壞值已修好卻仍有提醒: %+v err=%v", cfg.RootHashNotice, err)
	}
}

func TestRecoverRefusesWithoutExistingCredential(t *testing.T) {
	// 尚未初始化：建議是走 init-root，而不是在本條路上順手建立第一份憑據。
	path := testConfig(t)
	before := readFileForRecoverTest(t, path)

	_, err := Recover(RecoverOptions{ConfigPath: path, Secret: "no-credential-_pass", Params: credential.TestParams})
	if !errors.Is(err, ErrNoExistingCredential) {
		t.Fatalf("應回 ErrNoExistingCredential，實際 %v", err)
	}
	if got := readFileForRecoverTest(t, path); got != before {
		t.Error("被拒絕的恢復改動了組態檔")
	}
	if strings.Contains(err.Error(), "no-credential-_pass") {
		t.Errorf("錯誤回顯了口令: %v", err)
	}
}

func TestRecoverRefusesMissingConfigFile(t *testing.T) {
	// 檔案不存在不是「可以順便建立」的狀態：那個資料目錄還不屬於這個服務。
	path := filepath.Join(t.TempDir(), "no-such-config.yaml")
	if _, err := Recover(RecoverOptions{ConfigPath: path, Secret: "any-_pass", Params: credential.TestParams}); err == nil {
		t.Fatal("檔案不存在時應拒絕")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("被拒絕的恢復不該建立組態檔")
	}
}

func TestRecoverBrokenYAMLLosesNothing(t *testing.T) {
	// 配置損壞（YAML 語法壞）：讀現值這一步就失敗，檔案一個位元組都不動，也不留臨時檔殘骸。
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	const broken = "server:\n  data_dir: \".\"\nsecurity:\n  hashing: [unclosed\n"
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatalf("寫入損壞組態失敗: %v", err)
	}
	if _, err := Recover(RecoverOptions{ConfigPath: path, Secret: "any-_pass", Params: credential.TestParams}); err == nil ||
		!strings.Contains(err.Error(), "解析") {
		t.Fatalf("應回報解析失敗，實際 %v", err)
	}
	if got := readFileForRecoverTest(t, path); got != broken {
		t.Error("語法損壞的組態檔被改動了")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("讀取目錄失敗: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("留下殘骸：%v", entries)
	}
}

func TestRecoverSecretPolicy(t *testing.T) {
	const existing = "existing-root-_pass"
	cases := []struct {
		name   string
		secret string
	}{
		{name: "空口令", secret: ""},
		{name: "超過上界", secret: strings.Repeat("a", credential.MaxPasswordLength+1)},
		{name: "含換行", secret: "line1\nline2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := initializedConfig(t, existing)
			before := storedHash(t, path)

			_, err := Recover(RecoverOptions{ConfigPath: path, Secret: tc.secret, Params: credential.TestParams})
			if !errors.Is(err, ErrSecretPolicy) {
				t.Fatalf("應回 ErrSecretPolicy，實際 %v", err)
			}
			if storedHash(t, path) != before {
				t.Error("不合格輸入改動了憑據")
			}
			if err != nil && strings.Contains(err.Error(), existing) {
				t.Errorf("錯誤回顯了既有口令: %v", err)
			}
		})
	}
}

func TestRecoverInvalidParams(t *testing.T) {
	// 參數檔不合格必須在派生之前拒絕：那一欄寫下去是要長期驗登入的。
	const existing = "params-guard-root-_pass"
	path := initializedConfig(t, existing)
	before := readFileForRecoverTest(t, path)

	_, err := Recover(RecoverOptions{ConfigPath: path, Secret: "fine-_pass", Params: credential.Params{}})
	if err == nil || !strings.Contains(err.Error(), "參數檔不合格") {
		t.Fatalf("應回報參數檔不合格，實際 %v", err)
	}
	if got := readFileForRecoverTest(t, path); got != before {
		t.Error("參數檔不合格時改動了組態檔")
	}
}

// TestRecoverConcurrentAttemptsOnlyOneWins 釘住「兩個並行的恢復不會互相無聲蓋掉」：
// 輸家拿去比對的現值已經不是檔案裡那一份，比較-and-set 讓它整筆失敗。
func TestRecoverConcurrentAttemptsOnlyOneWins(t *testing.T) {
	path := initializedConfig(t, "shared-old-root-_pass")

	const racers = 3
	secrets := []string{"contending-a-root-_pass", "contending-b-root-_pass", "contending-c-root-_pass"}
	var wg sync.WaitGroup
	starts := make(chan struct{})
	errs := make([]error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-starts
			_, errs[i] = Recover(RecoverOptions{ConfigPath: path, Secret: secrets[i], Params: credential.TestParams})
		}(i)
	}
	close(starts)
	wg.Wait()

	var winners int
	for i, err := range errs {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, config.ErrRootCredentialMismatch):
		default:
			t.Fatalf("第 %d 個競跑出現預期外的錯誤: %v", i, err)
		}
	}
	if winners != 1 {
		t.Fatalf("成功次數=%d，期望恰好 1", winners)
	}
	hash := storedHash(t, path)
	var matched int
	for _, secret := range secrets {
		if mustVerify(t, hash, secret) {
			matched++
		}
	}
	if matched != 1 {
		t.Errorf("落盤的憑據應恰好對應一個競跑口令，實際符合 %d 個", matched)
	}
}

// TestRecoverIsRepeatable 釘住「恢復可以連跑兩次」：第二次換掉的是第一次留下的那份憑據，
// 更舊的口令一枚都不剩。這與 init-root 的「第二次必被拒絕」是兩句話，不許混用。
func TestRecoverIsRepeatable(t *testing.T) {
	path := initializedConfig(t, "round-one-root-_pass")

	if _, err := Recover(RecoverOptions{ConfigPath: path, Secret: "round-two-root-_pass", Params: credential.TestParams}); err != nil {
		t.Fatalf("第一次恢復失敗: %v", err)
	}
	first := storedHash(t, path)
	if _, err := Recover(RecoverOptions{ConfigPath: path, Secret: "round-three-root-_pass", Params: credential.TestParams}); err != nil {
		t.Fatalf("第二次恢復失敗: %v", err)
	}
	second := storedHash(t, path)
	if first == second {
		t.Error("第二次恢復沒有換出新憑據")
	}
	if !mustVerify(t, second, "round-three-root-_pass") {
		t.Error("最終憑據驗不過最後交上來的口令")
	}
	for _, stale := range []string{"round-one-root-_pass", "round-two-root-_pass"} {
		if mustVerify(t, second, stale) {
			t.Errorf("舊口令 %q 竟然還驗得過最終憑據", stale)
		}
	}
}

// TestRecoverDoesNotOverwriteWhenCasLost 钉住「覆寫只認檔案現值」這條比較-and-set 界線：
// 由併發測試（TestRecoverConcurrentAttemptsOnlyOneWins）在真實競跑裡覆蓋，
// 單線程下 Recover 自己會重讀現值，因此這裡只釘另一個方向——
// 現值被人手工換成另一份可用憑據後，下一次恢復照常成功換掉它，而不是拒絕。
func TestRecoverFollowsFileCurrentHash(t *testing.T) {
	path := initializedConfig(t, "origin-root-_pass")

	externalHash, err := credential.Hash("external-root-_pass", credential.TestParams)
	if err != nil {
		t.Fatalf("產生對照憑據失敗: %v", err)
	}
	replaceStoredHashLine(t, path, externalHash)

	if _, err := Recover(RecoverOptions{ConfigPath: path, Secret: "after-external-_pass", Params: credential.TestParams}); err != nil {
		t.Fatalf("恢復應以檔案現值為準並成功: %v", err)
	}
	hash := storedHash(t, path)
	if hash == externalHash || !mustVerify(t, hash, "after-external-_pass") {
		t.Error("沒有以檔案現值為前提完成覆寫")
	}
}
