package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/rootinit"
)

// rootInitConfig 是測試專屬資料目錄裡的組態檔內容。
//
// 雜湊參數檔刻意壓到許可區間的下限（8 MiB、1 遍）：初始化路徑每次都會真的跑
// Argon2id 派生與自我校驗，用生產檔（64 MiB）會讓每個測試多花好幾秒；
// 而「參數檔由組態決定」這件事本身就是這條路的一部分，所以走同一個機制而不是換程式碼。
//
// listen 不寫：migrate、init-root、root-status 都是不開放監聽的程序級命令，
// 拿預設值就夠，也不需要「埠號 0」那種通不過組態校驗的寫法。
const rootInitConfig = "server:\n  data_dir: \".\"\n" +
	"security:\n  hashing:\n    memory_kb: 8192\n    time_cost: 1\n    parallelism: 1\n    key_length: 16\n"

// newRootInitDir 建立一個「已遷移、尚未初始化」的測試資料目錄。
//
// 遷移走正式的 Migrate 子命令而不是直接開庫建表：那樣 Root 初始化要面對的
// 就是啟動流程留下的同一個資料庫形狀（含 root_audit 與其觸發器）。
func newRootInitDir(t *testing.T) string {
	t.Helper()
	dir := retryTempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(rootInitConfig), 0o600); err != nil {
		t.Fatalf("寫入測試組態失敗: %v", err)
	}
	if err := Migrate(context.Background(), []string{"--data-dir", dir}, &syncBuffer{}); err != nil {
		t.Fatalf("建立測試資料庫（遷移）失敗: %v", err)
	}
	return dir
}

// stdinSecrets 產生「口令＋確認」的標準輸入內容。
func stdinSecrets(secret, confirm string) io.Reader {
	return strings.NewReader(secret + "\n" + confirm + "\n")
}

// readStoredRootHash 讀出測試資料目錄裡那份 Root 憑據。
func readStoredRootHash(t *testing.T, dir string) string {
	t.Helper()
	state, err := config.ReadRootFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("讀取測試組態失敗: %v", err)
	}
	if !state.Initialized() {
		t.Fatal("測試資料目錄裡沒有 Root 憑據")
	}
	return state.Hash
}

// rootAuditActions 把 root_audit 裡的動作按寫入順序讀回來（測試據此核對留痕）。
func rootAuditActions(t *testing.T, dir string) []string {
	t.Helper()
	db, err := database.Open(context.Background(), database.Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows, err := db.SQL().QueryContext(context.Background(),
		"SELECT action, actor_kind, reason, changes_json FROM root_audit ORDER BY created_at ASC, id ASC")
	if err != nil {
		t.Fatalf("讀取 Root 審計失敗: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var actions []string
	for rows.Next() {
		var action, kind, reason string
		var changes *string
		if err := rows.Scan(&action, &kind, &reason, &changes); err != nil {
			t.Fatalf("解析 Root 審計失敗: %v", err)
		}
		actions = append(actions, fmt.Sprintf("%s/%s/%s/%s",
			action, kind, reason, func() string {
				if changes == nil {
					return ""
				}
				return *changes
			}()))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("讀取 Root 審計列失敗: %v", err)
	}
	return actions
}

func TestInitRootFirstSuccessSecondRefused(t *testing.T) {
	dir := newRootInitDir(t)
	const first = "first-root-pw-_1234"
	const second = "second-root-pw-_5678"
	ctx := context.Background()

	var out syncBuffer
	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir}, stdinSecrets(first, first), &out); err != nil {
		t.Fatalf("首次初始化失敗: %v（輸出：%s）", err, out.String())
	}
	report := out.String()
	if !strings.Contains(report, "Root 初始化：已完成") {
		t.Errorf("報告未寫出成功結論：%s", report)
	}
	if strings.Contains(report, first) || strings.Contains(report, "$argon2id$") {
		t.Errorf("報告回顯了口令或憑據內容：%s", report)
	}

	hash := readStoredRootHash(t, dir)
	if !strings.Contains(hash, "m=8192,t=1,p=1") {
		t.Errorf("憑據未採用組態給定的參數檔：%s", hash)
	}
	ok, err := credential.Verify(hash, first)
	if err != nil || !ok {
		t.Errorf("落盤的憑據驗不過第一次的口令: ok=%v err=%v", ok, err)
	}
	if ok, err := credential.Verify(hash, second); err != nil || ok {
		t.Error("第二次口令竟然驗過了既有憑據")
	}

	// 第二次：拒絕，而且憑據一個位元組都不動。
	before := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml"))
	var out2 syncBuffer
	err = InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir}, stdinSecrets(second, second), &out2)
	if !errors.Is(err, config.ErrRootAlreadyInitialized) {
		t.Fatalf("第二次應回 ErrRootAlreadyInitialized，實際 %v", err)
	}
	if got := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml")); got != before {
		t.Error("被拒絕的第二次改動了組態檔")
	}
	if note := out2.String(); !strings.Contains(note, "拒絕") || strings.Contains(note, second) {
		t.Errorf("拒絕報告不正確：%s", note)
	}

	// 兩次都要留痕，且留痕的內容不含口令。
	actions := rootAuditActions(t, dir)
	if len(actions) != 2 {
		t.Fatalf("Root 審計應有 2 筆，實際 %d 筆：%v", len(actions), actions)
	}
	if !strings.HasPrefix(actions[0], "server.root_initialize/system/") {
		t.Errorf("成功那筆的動作或主體不正確：%s", actions[0])
	}
	if !strings.Contains(actions[0], `"root_credential"`) ||
		!strings.Contains(actions[0], `"before":"unset"`) ||
		!strings.Contains(actions[0], `"after":"set"`) {
		t.Errorf("成功那筆未記錄欄位差量：%s", actions[0])
	}
	if strings.Contains(actions[0], "[redacted]") {
		t.Errorf("成功那筆的差量被脫敏掉了，欄位名要改用狀態而不是憑據：%s", actions[0])
	}
	if !strings.HasPrefix(actions[1], "server.root_initialize_denied/system/拒絕第二次初始化") {
		t.Errorf("拒絕那筆的動作或原因不正確：%s", actions[1])
	}
	for _, entry := range actions {
		if strings.Contains(entry, first) || strings.Contains(entry, second) ||
			strings.Contains(entry, "$argon2id$") {
			t.Errorf("審計記錄含口令或憑據：%s", entry)
		}
	}
	// 日誌也不準出現口令。
	if got := runLogContents(t, dir); strings.Contains(got, first) || strings.Contains(got, second) {
		t.Error("運行日誌含口令")
	}
}

func TestInitRootStateSurvivesProcessRestart(t *testing.T) {
	// 「重啟後的已初始化狀態」：同一份目錄重新走一遍載入路徑，憑據仍在且仍可用，
	// 而初始化通路依然關閉。
	dir := newRootInitDir(t)
	const secret = "restart-proof-root-pw"
	ctx := context.Background()

	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir}, stdinSecrets(secret, secret), &syncBuffer{}); err != nil {
		t.Fatalf("初始化失敗: %v", err)
	}
	hash := readStoredRootHash(t, dir)

	cfg, err := config.Load(config.Options{DataDir: dir})
	if err != nil {
		t.Fatalf("重新載入組態失敗: %v", err)
	}
	if cfg.Security.RootPasswordHash != hash {
		t.Error("重新載入讀到的憑據與檔案不一致")
	}
	if cfg.RootHashNotice != "" {
		t.Errorf("合格的憑據不該產生提醒：%s", cfg.RootHashNotice)
	}
	if ok, err := credential.Verify(cfg.Security.RootPasswordHash, secret); err != nil || !ok {
		t.Errorf("重啟後的憑據驗不過原口令: ok=%v err=%v", ok, err)
	}

	err = InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("new-pw-value", "new-pw-value"), &syncBuffer{})
	if !errors.Is(err, config.ErrRootAlreadyInitialized) {
		t.Fatalf("重啟後仍應拒絕第二次初始化，實際 %v", err)
	}
	if readStoredRootHash(t, dir) != hash {
		t.Error("重啟後的第二次改動了憑據")
	}
}

func TestInitRootConcurrentAttemptsOnlyOneSucceeds(t *testing.T) {
	// 併發競爭：單寫入實例鎖讓第二次連庫都開不了，而拿到鎖的那一次一定只有一個。
	// 這條釘的是「同時兩個初始化不會蓋掉彼此」，不管它們相不相撞。
	dir := newRootInitDir(t)
	const racers = 4

	var wg sync.WaitGroup
	errs := make([]error, racers)
	starts := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-starts
			secret := fmt.Sprintf("contending-pw-%02d-xyz", i)
			errs[i] = InitRoot(context.Background(),
				[]string{"--password-stdin", "--data-dir", dir}, stdinSecrets(secret, secret), &syncBuffer{})
		}(i)
	}
	close(starts)
	wg.Wait()

	var winners int
	for i, err := range errs {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, config.ErrRootAlreadyInitialized), errors.Is(err, ErrServerStillLocked):
		default:
			t.Fatalf("第 %d 個競跑出現預期外的錯誤: %v", i, err)
		}
	}
	if winners != 1 {
		t.Fatalf("成功次數=%d，期望恰好 1", winners)
	}
	hash := readStoredRootHash(t, dir)
	var matched int
	for i := 0; i < racers; i++ {
		ok, err := credential.Verify(hash, fmt.Sprintf("contending-pw-%02d-xyz", i))
		if err != nil {
			t.Fatalf("校驗失敗: %v", err)
		}
		if ok {
			matched++
		}
	}
	if matched != 1 {
		t.Errorf("落盤的憑據應恰好對應一個競跑口令，實際符合 %d 個", matched)
	}
}

func TestInitRootRefusesWhileServerHoldsInstanceLock(t *testing.T) {
	// 服務（或任何持有鎖的程序）在跑時一律拒絕：那時啟動讀進記憶體的組態不會被回頭更新。
	dir := newRootInitDir(t)
	holder, err := database.Open(context.Background(), database.Options{
		Path: filepath.Join(dir, "evernight.db"), BusyTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("持有測試鎖失敗: %v", err)
	}
	defer func() { _ = holder.Close() }()

	err = InitRoot(context.Background(), []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("locked-out-pw", "locked-out-pw"), &syncBuffer{})
	if !errors.Is(err, ErrServerStillLocked) {
		t.Fatalf("應回 ErrServerStillLocked，實際 %v", err)
	}
	if !strings.Contains(err.Error(), "單寫入實例約束") {
		t.Errorf("錯誤應保留鎖檔那邊的診斷：%v", err)
	}
	state, err := rootinit.Status(filepath.Join(dir, "config.yaml"))
	if err != nil || state.Initialized {
		t.Errorf("被鎖擋下時組態不該被動過: %+v err=%v", state, err)
	}
}

func TestInitRootRefusesWithoutAuditTable(t *testing.T) {
	// 沒有 root_audit 就 initializing would leave no trace：必須在碰組態檔之前停下。
	dir := retryTempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(rootInitConfig), 0o600); err != nil {
		t.Fatalf("寫入測試組態失敗: %v", err)
	}
	before := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml"))

	err := InitRoot(context.Background(), []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("no-audit-pw", "no-audit-pw"), &syncBuffer{})
	if err == nil || !strings.Contains(err.Error(), "root_audit") {
		t.Fatalf("應指明審計落點尚未建立，實際 %v", err)
	}
	if got := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml")); got != before {
		t.Error("無法留痕時仍改動了組態檔")
	}
}

func TestInitRootRefusesEnvOverride(t *testing.T) {
	dir := newRootInitDir(t)
	// 環境變數會蓋掉檔案值：這種狀態下寫進檔案的 Root 永遠不會生效，所以要硬擋。
	t.Setenv(config.RootPasswordHashEnvKey, "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$dW51c2Vk")
	before := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml"))

	err := InitRoot(context.Background(), []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("env-clash-pw", "env-clash-pw"), &syncBuffer{})
	if err == nil || !strings.Contains(err.Error(), config.RootPasswordHashEnvKey) {
		t.Fatalf("應點名該環境變數並拒絕，實際 %v", err)
	}
	if got := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml")); got != before {
		t.Error("環境變數覆蓋狀態下仍改動了組態檔")
	}
}

func TestInitRootSecretConfirmationRules(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr error
		wantSub string
	}{
		{name: "兩次不一致", input: "aaaa-pw-value\nbbbb-pw-value\n", wantErr: ErrRootSecretMismatch},
		{name: "缺少確認行", input: "only-one-line-pw\n", wantSub: "少了第 2 行"},
		{name: "空口令", input: "\n\n", wantSub: "口令不可為空"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := newRootInitDir(t)
			before := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml"))

			err := InitRoot(context.Background(), []string{"--password-stdin", "--data-dir", dir},
				strings.NewReader(tc.input), &syncBuffer{})
			if err == nil {
				t.Fatal("應被拒絕")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("錯誤應為 %v，實際 %v", tc.wantErr, err)
			}
			if tc.wantSub != "" && !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("錯誤應含 %q，實際 %v", tc.wantSub, err)
			}
			if got := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml")); got != before {
				t.Error("口令不合格時改動了組態檔")
			}
			if strings.Contains(err.Error(), "aaaa-pw-value") || strings.Contains(err.Error(), "bbbb-pw-value") {
				t.Errorf("錯誤回顯了口令: %v", err)
			}
			// 這些嘗試也要在 Root 審計裡留痕。
			actions := rootAuditActions(t, dir)
			if len(actions) != 1 || !strings.HasPrefix(actions[0], "server.root_initialize_failed/system/") {
				t.Errorf("失敗嘗試未留下正確審計：%v", actions)
			}
		})
	}
}

func TestInitRootRequiresPasswordStdin(t *testing.T) {
	dir := newRootInitDir(t)
	before := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml"))

	err := InitRoot(context.Background(), []string{"--data-dir", dir},
		stdinSecrets("unused-pw-value", "unused-pw-value"), &syncBuffer{})
	if err == nil || !strings.Contains(err.Error(), "--password-stdin") {
		t.Fatalf("未給 --password-stdin 時應明確拒絕，實際 %v", err)
	}
	if got := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml")); got != before {
		t.Error("參數不合格時改動了組態檔")
	}

	err = InitRoot(context.Background(), []string{"--password-stdin", "--password-stdin", "--data-dir", dir},
		stdinSecrets("unused-pw-value", "unused-pw-value"), &syncBuffer{})
	if err == nil || !strings.Contains(err.Error(), "重複") {
		t.Fatalf("重複旗標應被拒絕，實際 %v", err)
	}
}

func TestInitRootWriteFailureLeavesConfigUnchanged(t *testing.T) {
	// 寫入失敗：檔案維持原樣、狀態仍是未初始化、報告講出不成功，而且名額還沒用掉。
	//
	// 這一條走的是真實檔案系統權限，而且只動測試專屬目錄。POSIX 的 rename 不看目標檔的
	// 寫入位（只看目錄位），所以同樣的故障在 Unix 上無法用這個方式重現——那邊的
	// 「寫入／同步／改名」三階段失敗由 internal/config 的 root_credential_test.go 逐段覆蓋。
	if runtime.GOOS != "windows" {
		t.Skip("此故障需要「改名被目標檔的唯讀屬性擋下」語意，僅 Windows 成立；Unix 見 config 層測試")
	}
	dir := newRootInitDir(t)
	configPath := filepath.Join(dir, "config.yaml")
	before := readFileBytesForRootTest(t, configPath)

	if err := os.Chmod(configPath, 0o444); err != nil {
		t.Fatalf("設為唯讀失敗: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(configPath, 0o600); err != nil {
			t.Errorf("還原組態檔可寫位失敗: %v", err)
		}
	})

	err := InitRoot(context.Background(), []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("failing-pw-value", "failing-pw-value"), &syncBuffer{})
	if err == nil {
		t.Fatal("寫入被擋下時應回報錯誤")
	}
	if !strings.Contains(err.Error(), "維持原樣") && !strings.Contains(err.Error(), "替換") {
		t.Logf("實際錯誤：%v", err)
	}
	if got := readFileBytesForRootTest(t, configPath); got != before {
		t.Error("寫入失敗改動了組態檔")
	}
	state, err := rootinit.Status(configPath)
	if err != nil || state.Initialized {
		t.Errorf("寫入失敗後仍應是未初始化: %+v err=%v", state, err)
	}

	// 故障撤掉之後同一次口令要能成功：一次失敗不該把「只開放一次」的名額用掉。
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatalf("恢復可寫失敗: %v", err)
	}
	if err := InitRoot(context.Background(), []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("failing-pw-value", "failing-pw-value"), &syncBuffer{}); err != nil {
		t.Fatalf("故障撤除後重試失敗: %v", err)
	}
	if ok, err := credential.Verify(readStoredRootHash(t, dir), "failing-pw-value"); err != nil || !ok {
		t.Errorf("重試後的憑據不可用: ok=%v err=%v", ok, err)
	}
}

func TestInitRootRefusesUnusableExistingCredential(t *testing.T) {
	// 「已有但不可用」要與「已初始化」分開報：前者代表現在根本登不進去，
	// 而這條路刻意不替操作者決定要不要放棄那個值。
	dir := retryTempDir(t)
	configPath := filepath.Join(dir, "config.yaml")
	const garbage = "$argon2id$v=19$m=8192,t=1,p=1$not-base64!!$also-not-base64!!"
	content := rootInitConfig + "  root_password_hash: \"" + garbage + "\"\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("寫入測試組態失敗: %v", err)
	}
	if err := Migrate(context.Background(), []string{"--data-dir", dir}, &syncBuffer{}); err != nil {
		t.Fatalf("建立測試資料庫失敗: %v", err)
	}
	// 載入那側只留提醒、不擋啟動（正在服務活動的部署不該被一個壞值停擺）。
	cfg, err := config.Load(config.Options{DataDir: dir})
	if err != nil {
		t.Fatalf("壞憑據不該讓載入失敗: %v", err)
	}
	if cfg.RootHashNotice == "" {
		t.Error("啟動摘要缺少 Root 憑據不合格的提醒")
	}

	err = InitRoot(context.Background(), []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("wanna-fix-pw", "wanna-fix-pw"), &syncBuffer{})
	if !errors.Is(err, rootinit.ErrUnusableExistingCredential) {
		t.Fatalf("應回 ErrUnusableExistingCredential，實際 %v", err)
	}
	if got := readFileBytesForRootTest(t, configPath); !strings.Contains(got, garbage) {
		t.Error("拒絕路徑改動了既有（壞）憑據")
	}
	actions := rootAuditActions(t, dir)
	if len(actions) != 1 || !strings.HasPrefix(actions[0], "server.root_initialize_denied/system/拒絕初始化") {
		t.Errorf("壞憑據的拒絕嘗試未留下正確審計：%v", actions)
	}
	if !strings.Contains(actions[0], `"root_credential"`) {
		t.Errorf("拒絕那筆應記錄憑據仍為 set 的差量：%s", actions[0])
	}
}

func TestRootStatusReportsMinimalState(t *testing.T) {
	dir := newRootInitDir(t)
	ctx := context.Background()

	var out syncBuffer
	if err := RootStatus(ctx, []string{"--data-dir", dir}, &out); err != nil {
		t.Fatalf("查詢失敗: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "尚未初始化") ||
		strings.Contains(got, "$argon2id$") || strings.Contains(got, "root_password_hash") {
		t.Errorf("未初始化時的報告不正確：%s", got)
	}

	const secret = "status-visible-pw"
	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir}, stdinSecrets(secret, secret), &syncBuffer{}); err != nil {
		t.Fatalf("初始化失敗: %v", err)
	}
	out2 := &syncBuffer{}
	if err := RootStatus(ctx, []string{"--data-dir", dir}, out2); err != nil {
		t.Fatalf("查詢失敗: %v", err)
	}
	got := out2.String()
	if !strings.Contains(got, "已初始化") || strings.Contains(got, secret) || strings.Contains(got, "$argon2id$") {
		t.Errorf("已初始化時的報告不正確：%s", got)
	}

	// 環境變數蓋著時要多講一句：否則「檔案裡沒有」會被讀成「這個服務沒有 Root」。
	t.Setenv(config.RootPasswordHashEnvKey, "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$dW51c2Vk")
	out3 := &syncBuffer{}
	if err := RootStatus(ctx, []string{"--data-dir", dir}, out3); err != nil {
		t.Fatalf("查詢失敗: %v", err)
	}
	if got := out3.String(); !strings.Contains(got, config.RootPasswordHashEnvKey) {
		t.Errorf("未提示環境變數覆蓋：%s", got)
	}
}

func TestRootStatusDoesNotCreateAnything(t *testing.T) {
	// 「問一個問題」不該留下目錄或範例組態：這條路刻意不走 Prepare。
	root := retryTempDir(t)
	dir := filepath.Join(root, "not-created-yet")
	var out syncBuffer
	if err := RootStatus(context.Background(), []string{"--data-dir", dir}, &out); err != nil {
		t.Fatalf("查詢失敗: %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("查詢狀態不該建立資料目錄（現況：%v）", err)
	}
	if got := out.String(); !strings.Contains(got, "還沒有組態檔") {
		t.Errorf("缺少組態檔時的報告不正確：%s", got)
	}
}

// runLogContents 讀回測試資料目錄 logs/ 下的全部日誌（用來斷言口令不在裡面）。
func runLogContents(t *testing.T, dir string) string {
	t.Helper()
	logs := filepath.Join(dir, "logs")
	entries, err := os.ReadDir(logs)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatalf("讀取日誌目錄失敗: %v", err)
	}
	var all strings.Builder
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(logs, entry.Name()))
		if err != nil {
			t.Fatalf("讀取日誌 %s 失敗: %v", entry.Name(), err)
		}
		all.Write(data)
	}
	return all.String()
}

// readFileBytesForRootTest 讀出檔案原始位元組供「有沒有被改動」比對。
func readFileBytesForRootTest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取 %s 失敗: %v", path, err)
	}
	return string(data)
}
