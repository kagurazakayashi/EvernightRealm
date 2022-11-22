package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/rootinit"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// recoverGarbageHash 是「非空但解不開」的憑據值：形狀像 Argon2id，base64 段是壞的。
const recoverGarbageHash = "$argon2id$v=19$m=8192,t=1,p=1$not-base64!!$also-not-base64!!"

// recoverArgs 是 recover-root 的標準引數（新口令仍走標準輸入，不放命令列）。
func recoverArgs(dir string) []string {
	return []string{"--password-stdin", "--confirm", "--data-dir", dir}
}

// replaceStoredHashLine 把測試組態檔裡那一行憑據值換掉（保留其他全部行與註解）。
func replaceStoredHashLine(t *testing.T, path, value string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取測試組態失敗: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	replaced := 0
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "root_password_hash:") {
			lines[i] = `  root_password_hash: "` + value + `"`
			replaced++
		}
	}
	if replaced != 1 {
		t.Fatalf("測試前置條件：憑據行應恰好一行，實際 %d", replaced)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatalf("改寫測試憑據行失敗: %v", err)
	}
}

// plantSessions 在測試資料目錄裡種下一枚 Root 會話與一枚普通帳戶會話，回傳兩枚一次性秘密。
//
// 用 identitytest 工廠而不是「先真的登入一次」：本步測的是恢復如何處置既有會話，
// 不是登入通路（那是 R1-009 的事），拿工廠種行可以讓前置條件不依賴被测物件。
func plantSessions(t *testing.T, dir string) (rootSecret, accountSecret string) {
	t.Helper()
	ctx := context.Background()
	db, err := openTestDatabase(ctx, dir)
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗: %v", err)
	}
	defer func() { _ = db.Close() }()

	store, err := session.NewStore(timeutil.System(), time.Hour)
	if err != nil {
		t.Fatalf("構造會話倉儲失敗: %v", err)
	}
	if _, rootSecret, err = store.Create(ctx, db.SQL(), identitytest.Root(t, identity.OriginHTTPRequest)); err != nil {
		t.Fatalf("種 Root 會話失敗: %v", err)
	}

	hash, err := credential.Hash("plant-session-pw", credential.TestParams)
	if err != nil {
		t.Fatalf("產生測試帳戶憑據失敗: %v", err)
	}
	a, err := account.NewStore(timeutil.System()).Create(ctx, db.SQL(), account.NewInput{
		LoginName:    "NightKeeper",
		DisplayName:  "守夜人",
		PasswordHash: hash,
		Type:         account.TypeStandard,
		Status:       account.StatusActive,
	})
	if err != nil {
		t.Fatalf("種測試帳戶失敗: %v", err)
	}
	p, err := identity.NewAccountPrincipal(identity.AccountInput{
		Subject: identity.SubjectOf(a),
		Origin:  identity.OriginHTTPRequest,
	})
	if err != nil {
		t.Fatalf("構造測試主體失敗: %v", err)
	}
	if _, accountSecret, err = store.Create(ctx, db.SQL(), p); err != nil {
		t.Fatalf("種帳戶會話失敗: %v", err)
	}
	return rootSecret, accountSecret
}

// openTestDatabase 以測試專屬資料目錄開庫（呼叫端負責關閉以釋放單寫入實例鎖）。
func openTestDatabase(ctx context.Context, dir string) (*database.DB, error) {
	return database.Open(ctx, database.Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: 2 * time.Second,
	})
}

// verifySessionSecret 重開一次連線，回報那枚會話秘密現在換不換得出身份（回錯誤即拒）。
func verifySessionSecret(t *testing.T, dir, secret string) error {
	t.Helper()
	ctx := context.Background()
	db, err := openTestDatabase(ctx, dir)
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗: %v", err)
	}
	defer func() { _ = db.Close() }()
	store, err := session.NewStore(timeutil.System(), time.Hour)
	if err != nil {
		t.Fatalf("構造會話倉儲失敗: %v", err)
	}
	_, err = store.Verify(ctx, db.SQL(), secret)
	return err
}

// countRootAudits 數 root_audit 現有幾筆（用來釘「被拒絕的嘗試有沒有留痕」）。
func countRootAudits(t *testing.T, dir string) int {
	t.Helper()
	db, err := openTestDatabase(context.Background(), dir)
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗: %v", err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM root_audit").Scan(&n); err != nil {
		t.Fatalf("計算 Root 審計失敗: %v", err)
	}
	return n
}

// TestRecoverRootForgottenPasswordEndToEnd 是本步的主場景：口令遺失、服務停著，
// 在本機把憑據換掉，舊 Root 裝置全部失效，普通帳戶一枚都不動，且留得下審計。
func TestRecoverRootForgottenPasswordEndToEnd(t *testing.T) {
	const lostSecret = "lost-root-_pass"
	const newSecret = "recovered-root-_pass"
	dir := newRootInitDir(t)
	ctx := context.Background()

	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets(lostSecret, lostSecret), &syncBuffer{}); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	oldHash := readStoredRootHash(t, dir)
	rootSecret, accountSecret := plantSessions(t, dir)
	// 前置：兩枚會話此刻都還換得出身份（否則後面的斷言沒有意義）。
	if err := verifySessionSecret(t, dir, rootSecret); err != nil {
		t.Fatalf("前置 Root 會話應有效: %v", err)
	}

	var out syncBuffer
	err := RecoverRoot(ctx, recoverArgs(dir), stdinSecrets(newSecret, newSecret), &out)
	if err != nil {
		t.Fatalf("恢復失敗: %v（輸出：%s）", err, out.String())
	}
	report := out.String()
	if !strings.Contains(report, "Root 憑據恢復：已完成") || !strings.Contains(report, "1 個會話") {
		t.Errorf("報告未寫出成功結論與撤銷數量：%s", report)
	}
	for _, leak := range []string{lostSecret, newSecret, oldHash, "$argon2id$"} {
		if strings.Contains(report, leak) {
			t.Errorf("報告回顯了口令或憑據內容：%s", report)
		}
	}

	hash := readStoredRootHash(t, dir)
	if hash == oldHash {
		t.Fatal("憑據未被更換")
	}
	if ok, _ := credential.Verify(hash, newSecret); !ok {
		t.Error("新憑據驗不過新口令")
	}
	if ok, _ := credential.Verify(hash, lostSecret); ok {
		t.Error("遺失的舊口令竟然還驗得過")
	}
	// 以登入那條路的同一個比對點再問一次：新口令換得出 Root 主體、舊口令換不出。
	if _, err := identity.VerifyRootCredential(hash, newSecret); err != nil {
		t.Errorf("恢復後的憑據在登入比對點上不合格: %v", err)
	}
	if _, err := identity.VerifyRootCredential(hash, lostSecret); err == nil {
		t.Error("舊口令竟然通過了登入比對點")
	}
	// 舊 Root 會話立即失效（生效邊界是下一個請求——這裡就是那個請求）。
	if err := verifySessionSecret(t, dir, rootSecret); !errors.Is(err, session.ErrRevoked) {
		t.Errorf("Root 舊會話應已被撤銷，實際 %v", err)
	}
	// 普通帳戶的會話不受牵连。
	if err := verifySessionSecret(t, dir, accountSecret); err != nil {
		t.Errorf("帳戶會話不應被波及: %v", err)
	}

	actions := rootAuditActions(t, dir)
	if len(actions) != 2 {
		t.Fatalf("Root 審計應有 2 筆（初始化＋恢復），實際 %d：%v", len(actions), actions)
	}
	if !strings.HasPrefix(actions[1], "server.root_recover/system/") {
		t.Errorf("恢復那筆的動作或主體不正確：%s", actions[1])
	}
	if !strings.Contains(actions[1], "撤銷 Root 名下 1 個會話") {
		t.Errorf("恢復那筆未記錄撤銷數量：%s", actions[1])
	}
	if !strings.Contains(actions[1], `"before":"set"`) || !strings.Contains(actions[1], `"after":"set"`) {
		t.Errorf("恢復那筆應記錄憑據 set→set 的狀態差量：%s", actions[1])
	}
	for _, entry := range actions {
		if strings.Contains(entry, lostSecret) || strings.Contains(entry, newSecret) ||
			strings.Contains(entry, "$argon2id$") || strings.Contains(entry, "[redacted]") {
			t.Errorf("審計記錄含口令、憑據或被脫敏到不可讀：%s", entry)
		}
	}
	logged := runLogContents(t, dir)
	if strings.Contains(logged, lostSecret) || strings.Contains(logged, newSecret) ||
		strings.Contains(logged, oldHash) {
		t.Error("運行日誌含口令或憑據")
	}
	// 不留下半寫入檔殘骸。
	residue, _ := filepath.Glob(filepath.Join(dir, ".config.yaml.tmp-*"))
	if len(residue) != 0 {
		t.Errorf("殘留臨時組態檔：%v", residue)
	}
}

// TestRecoverRootRepairsUnusableCredential 釘住「壞值沒人登得進去」這一態：
// init-root 對它拒絕，recover-root 把它換掉。
func TestRecoverRootRepairsUnusableCredential(t *testing.T) {
	const fixedSecret = "fixed-after-garbage-_pass"
	dir := newRootInitDir(t)
	configPath := filepath.Join(dir, "config.yaml")
	ctx := context.Background()

	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("was-fine-_pass", "was-fine-_pass"), &syncBuffer{}); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	replaceStoredHashLine(t, configPath, recoverGarbageHash)

	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets(fixedSecret, fixedSecret), &syncBuffer{}); !errors.Is(err, rootinit.ErrUnusableExistingCredential) {
		t.Fatalf("前置：init-root 對壞值應回 ErrUnusableExistingCredential，實際 %v", err)
	}
	var out syncBuffer
	if err := RecoverRoot(ctx, recoverArgs(dir), stdinSecrets(fixedSecret, fixedSecret), &out); err != nil {
		t.Fatalf("恢復壞憑據失敗: %v（輸出：%s）", err, out.String())
	}
	hash := readStoredRootHash(t, dir)
	if hash == recoverGarbageHash {
		t.Fatal("壞憑據沒被換掉")
	}
	if ok, _ := credential.Verify(hash, fixedSecret); !ok {
		t.Error("換好的憑據驗不過新口令")
	}
	if _, err := config.Load(config.Options{DataDir: dir}); err != nil {
		t.Fatalf("恢復後組態應可載入: %v", err)
	}
	actions := rootAuditActions(t, dir)
	last := actions[len(actions)-1]
	if !strings.HasPrefix(last, "server.root_recover/system/") {
		t.Errorf("壞憑據的恢復未留正確審計：%s", last)
	}
}

func TestRecoverRootRefusesWhileServerHoldsInstanceLock(t *testing.T) {
	dir := newRootInitDir(t)
	ctx := context.Background()
	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("locked-out-_pass", "locked-out-_pass"), &syncBuffer{}); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	// 基線要在還拿得到鎖的時候量：持有者還沒關閉之前，連「數一筆審計」都開不了第二條連線
	// （那正是本步要驗證的互斥形態）。
	before := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml"))
	auditsBefore := countRootAudits(t, dir)

	holder, err := openTestDatabase(ctx, dir)
	if err != nil {
		t.Fatalf("持有測試鎖失敗: %v", err)
	}
	err = RecoverRoot(ctx, recoverArgs(dir), stdinSecrets("locked-recover-_pass", "locked-recover-_pass"), &syncBuffer{})
	if closeErr := holder.Close(); closeErr != nil {
		t.Fatalf("釋放測試鎖失敗: %v", closeErr)
	}

	if !errors.Is(err, ErrServerStillLocked) {
		t.Fatalf("應回 ErrServerStillLocked，實際 %v", err)
	}
	if got := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml")); got != before {
		t.Error("服務運行中仍改動了組態檔")
	}
	if n := countRootAudits(t, dir); n != auditsBefore {
		t.Errorf("被鎖擋下的嘗試不該寫審計（%d → %d）", auditsBefore, n)
	}
}

func TestRecoverRootRefusesEnvOverride(t *testing.T) {
	dir := newRootInitDir(t)
	ctx := context.Background()
	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("env-old-_pass", "env-old-_pass"), &syncBuffer{}); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	// 環境變數蓋著時覆寫檔案只會做出永遠不生效的那一份：與 init-root 同一口徑，零寫入。
	t.Setenv(config.RootPasswordHashEnvKey, "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$dW51c2Vk")
	before := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml"))

	err := RecoverRoot(ctx, recoverArgs(dir), stdinSecrets("env-new-_pass", "env-new-_pass"), &syncBuffer{})
	if err == nil || !strings.Contains(err.Error(), config.RootPasswordHashEnvKey) {
		t.Fatalf("應點名該環境變數並拒絕，實際 %v", err)
	}
	if got := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml")); got != before {
		t.Error("環境變數覆蓋狀態下仍改動了組態檔")
	}
}

// TestRecoverRootArgGuard 釘住兩個旗標都是必需的：少了任何一個，命令不碰檔案也不開庫。
func TestRecoverRootArgGuard(t *testing.T) {
	dir := newRootInitDir(t)
	ctx := context.Background()
	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("arg-guard-_pass", "arg-guard-_pass"), &syncBuffer{}); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	before := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml"))
	auditsBefore := countRootAudits(t, dir)

	cases := []struct {
		name    string
		args    []string
		wantSub string
	}{
		{name: "缺少 --confirm", args: []string{"--password-stdin", "--data-dir", dir}, wantSub: "--confirm"},
		{name: "缺少 --password-stdin", args: []string{"--confirm", "--data-dir", dir}, wantSub: "--password-stdin"},
		{name: "--confirm 重複", args: []string{"--password-stdin", "--confirm", "--confirm", "--data-dir", dir}, wantSub: "重複"},
		{name: "--password-stdin 重複", args: []string{"--password-stdin", "--password-stdin", "--confirm", "--data-dir", dir}, wantSub: "重複"},
		// 把口令放上命令列的寫法必須被明確拒絕（未知旗標由組態解析擋下，不靜默忽略）。
		{
			name:    "命令列上的口令值",
			args:    []string{"--password-stdin", "--password", "oops-in-argv", "--confirm", "--data-dir", dir},
			wantSub: "命令列參數錯誤",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RecoverRoot(ctx, tc.args, stdinSecrets("guard-_pass", "guard-_pass"), &syncBuffer{})
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("錯誤應含 %q，實際 %v", tc.wantSub, err)
			}
			if got := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml")); got != before {
				t.Error("參數不合格時改動了組態檔")
			}
		})
	}
	if n := countRootAudits(t, dir); n != auditsBefore {
		t.Errorf("被參數閘擋下的嘗試不該寫審計（%d → %d）", auditsBefore, n)
	}
}

func TestRecoverRootSecretMismatchLeavesTrace(t *testing.T) {
	dir := newRootInitDir(t)
	ctx := context.Background()
	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("mismatch-old-_pass", "mismatch-old-_pass"), &syncBuffer{}); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	before := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml"))

	err := RecoverRoot(ctx, recoverArgs(dir), stdinSecrets("aaaa-_pass", "bbbb-_pass"), &syncBuffer{})
	if !errors.Is(err, ErrRootSecretMismatch) {
		t.Fatalf("應回 ErrRootSecretMismatch，實際 %v", err)
	}
	if got := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml")); got != before {
		t.Error("口令不一致時改動了組態檔")
	}
	actions := rootAuditActions(t, dir)
	last := actions[len(actions)-1]
	if !strings.HasPrefix(last, "server.root_recover_failed/system/") {
		t.Errorf("口令輸入失敗應留痕，實際：%s", last)
	}
	if strings.Contains(last, "aaaa-_pass") || strings.Contains(last, "bbbb-_pass") {
		t.Errorf("審計回顯了口令：%s", last)
	}

	// 這次失敗沒有用掉任何「名額」：湊齊兩行之後仍然可以成功。
	if err := RecoverRoot(ctx, recoverArgs(dir), stdinSecrets("aaaa-_pass", "aaaa-_pass"), &syncBuffer{}); err != nil {
		t.Fatalf("失敗後重試應成功: %v", err)
	}
}

// TestRecoverRootRefusesWithoutCredential 釘住兩條寫入通路的分界：沒有憑據時該走 init-root。
func TestRecoverRootRefusesWithoutCredential(t *testing.T) {
	dir := newRootInitDir(t)
	before := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml"))

	var out syncBuffer
	err := RecoverRoot(context.Background(), recoverArgs(dir),
		stdinSecrets("nothing-to-recover-_pass", "nothing-to-recover-_pass"), &out)
	if !errors.Is(err, rootinit.ErrNoExistingCredential) {
		t.Fatalf("應回 ErrNoExistingCredential，實際 %v", err)
	}
	if got := readFileBytesForRootTest(t, filepath.Join(dir, "config.yaml")); got != before {
		t.Error("被拒絕的恢復改動了組態檔")
	}
	note := out.String()
	if !strings.Contains(note, "init-root") || strings.Contains(note, "nothing-to-recover-_pass") {
		t.Errorf("拒絕報告未指向一次性初始化：%s", note)
	}
	actions := rootAuditActions(t, dir)
	last := actions[len(actions)-1]
	if !strings.HasPrefix(last, "server.root_recover_denied/system/") ||
		!strings.Contains(last, `"before":"unset"`) || !strings.Contains(last, `"after":"unset"`) {
		t.Errorf("這個拒絕應記為 unset→unset，實際：%s", last)
	}
}

func TestRecoverRootRefusesWithoutAuditTable(t *testing.T) {
	// 留不下痕跡就不動憑據：順序與 init-root 同形（審計落點檢查在碰檔案之前）。
	dir := retryTempDir(t)
	configPath := filepath.Join(dir, "config.yaml")
	content := rootInitConfig + "  root_password_hash: \"" + recoverGarbageHash + "\"\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("寫入測試組態失敗: %v", err)
	}
	before := readFileBytesForRootTest(t, configPath)

	err := RecoverRoot(context.Background(), recoverArgs(dir),
		stdinSecrets("no-audit-_pass", "no-audit-_pass"), &syncBuffer{})
	if err == nil || !strings.Contains(err.Error(), "root_audit") {
		t.Fatalf("應指明審計落點尚未建立，實際 %v", err)
	}
	if got := readFileBytesForRootTest(t, configPath); got != before {
		t.Error("無法留痕時仍改動了組態檔")
	}
}

func TestRecoverRootRefusesCorruptConfigWithoutDamage(t *testing.T) {
	// 配置損壞（YAML 語法壞）：載入階段就停，檔案一個位元組不動，也不留臨時檔。
	dir := newRootInitDir(t)
	configPath := filepath.Join(dir, "config.yaml")
	ctx := context.Background()
	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("corrupt-old-_pass", "corrupt-old-_pass"), &syncBuffer{}); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	broken := "server:\n  data_dir: \".\"\nsecurity:\n  hashing: [unclosed\n"
	if err := os.WriteFile(configPath, []byte(broken), 0o600); err != nil {
		t.Fatalf("寫入損壞組態失敗: %v", err)
	}

	err := RecoverRoot(ctx, recoverArgs(dir), stdinSecrets("corrupt-new-_pass", "corrupt-new-_pass"), &syncBuffer{})
	if err == nil || !strings.Contains(err.Error(), "解析") {
		t.Fatalf("應回報解析失敗，實際 %v", err)
	}
	if got := readFileBytesForRootTest(t, configPath); got != broken {
		t.Error("語法損壞的組態檔被改動了")
	}
	residue, _ := filepath.Glob(filepath.Join(dir, ".config.yaml.tmp-*"))
	if len(residue) != 0 {
		t.Errorf("留下臨時檔殘骸：%v", residue)
	}
}

// TestRecoverRootRollsBackWhenDatabaseWriteFails 是本步最重要的失敗恢復演練：
// 憑據已覆寫、但「撤銷＋審計」那筆交易寫不進去時，必須把舊憑據換回去、報失敗，
// 並且不留下任何「報成功」的痕迹。故障注入用既有機制（schema_guard=transaction +
// 降档 user_version），不改主機、不碰真實資料。
func TestRecoverRootRollsBackWhenDatabaseWriteFails(t *testing.T) {
	const oldSecret = "rollback-old-_pass"
	const newSecret = "rollback-new-_pass"
	dir := retryTempDir(t)
	configPath := filepath.Join(dir, "config.yaml")
	ctx := context.Background()

	// 這份組態開了交易邊界的 schema 把關（預設只在啟動把關，那對本場景不夠）。
	guarded := rootInitConfig + "database:\n  schema_guard: \"transaction\"\n"
	if err := os.WriteFile(configPath, []byte(guarded), 0o600); err != nil {
		t.Fatalf("寫入測試組態失敗: %v", err)
	}
	if err := Migrate(ctx, []string{"--data-dir", dir}, &syncBuffer{}); err != nil {
		t.Fatalf("建立測試資料庫失敗: %v", err)
	}
	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets(oldSecret, oldSecret), &syncBuffer{}); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	originalHash := readStoredRootHash(t, dir)
	rootSecret, _ := plantSessions(t, dir)
	auditsBefore := countRootAudits(t, dir)

	// 把 schema 版本降到執行檔已知版本之下：Root 審計落點仍在（檢查得到），
	// 但之後每一筆寫入交易都會在邊界被拒——這正是「覆寫成功、撤銷失敗」的形状。
	demoteSchemaVersion(t, dir)

	var out syncBuffer
	err := RecoverRoot(ctx, recoverArgs(dir), stdinSecrets(newSecret, newSecret), &out)
	if err == nil {
		t.Fatalf("交易寫不進去時應報失敗（輸出：%s）", out.String())
	}
	if !strings.Contains(err.Error(), "回滾") {
		t.Errorf("錯誤應說明憑據已回滾，實際 %v", err)
	}
	note := out.String()
	if !strings.Contains(note, "未完成") || !strings.Contains(note, "舊口令仍然可用") {
		t.Errorf("回滾報告未說清現況：%s", note)
	}
	if strings.Contains(note, newSecret) || strings.Contains(note, "$argon2id$") {
		t.Errorf("回滾報告回顯了口令或憑據：%s", note)
	}
	if got := readStoredRootHash(t, dir); got != originalHash {
		t.Error("回滾後憑據不是原本那一份")
	}
	if ok, _ := credential.Verify(readStoredRootHash(t, dir), oldSecret); !ok {
		t.Error("回滾後舊口令應仍然可用")
	}
	if ok, _ := credential.Verify(readStoredRootHash(t, dir), newSecret); ok {
		t.Error("回滾後新口令竟然可用")
	}
	if err := verifySessionSecret(t, dir, rootSecret); err != nil {
		t.Errorf("回滾後 Root 會話應維持原狀（仍有效），實際 %v", err)
	}
	if n := countRootAudits(t, dir); n != auditsBefore {
		t.Errorf("回滾情境不該多出成功審計（%d → %d）", auditsBefore, n)
	}
	// 審計寫不進去這件事本身必須落在持久處，而不是只有一條終端輸出。
	logged := runLogContents(t, dir)
	if !strings.Contains(logged, "Root 恢復的會話撤銷失敗，已回滾憑據") {
		t.Errorf("運行日誌缺少回滾事實：%s", truncateForTest(logged))
	}
	if !strings.Contains(logged, "未能寫入 Root 審計") {
		t.Errorf("運行日誌未如實記錄「痕跡沒留下」：%s", truncateForTest(logged))
	}

	// 故障撤除之後重跑同一次口令要能真的成功（回滾沒有把狀態弄壞）。
	restoreSchemaVersion(t, dir)
	var out2 syncBuffer
	if err := RecoverRoot(ctx, recoverArgs(dir), stdinSecrets(newSecret, newSecret), &out2); err != nil {
		t.Fatalf("故障撤除後重試失敗: %v（輸出：%s）", err, out2.String())
	}
	if ok, _ := credential.Verify(readStoredRootHash(t, dir), newSecret); !ok {
		t.Error("重試後的憑據驗不過新口令")
	}
	if err := verifySessionSecret(t, dir, rootSecret); !errors.Is(err, session.ErrRevoked) {
		t.Errorf("重試後 Root 舊會話應已被撤銷，實際 %v", err)
	}
}

// TestRecoverRootWriteFailureKeepsOldCredential 用真實檔案系統重現「改名替換被擋下」：
// 覆寫不成立時，舊憑據、舊會話與可用狀態一律維持原樣。
//
// 這個故障形態只在 Windows 成立（POSIX 的 rename 不看目標檔的寫入位），
// Unix 側的「寫入／同步／改名」三階段失敗由 internal/config 的 root_credential_test.go 覆蓋。
func TestRecoverRootWriteFailureKeepsOldCredential(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("此故障需要「改名被目標檔的唯讀屬性擋下」語意，僅 Windows 成立")
	}
	const oldSecret = "writefail-old-_pass"
	const newSecret = "writefail-new-_pass"
	dir := newRootInitDir(t)
	configPath := filepath.Join(dir, "config.yaml")
	ctx := context.Background()

	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets(oldSecret, oldSecret), &syncBuffer{}); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	before := readFileBytesForRootTest(t, configPath)
	rootSecret, _ := plantSessions(t, dir)

	if err := os.Chmod(configPath, 0o444); err != nil {
		t.Fatalf("設為唯讀失敗: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(configPath, 0o600); err != nil {
			t.Errorf("還原組態檔可寫位失敗: %v", err)
		}
	})

	err := RecoverRoot(ctx, recoverArgs(dir), stdinSecrets(newSecret, newSecret), &syncBuffer{})
	if err == nil {
		t.Fatal("覆寫被擋下時應回報錯誤")
	}
	if got := readFileBytesForRootTest(t, configPath); got != before {
		t.Error("寫入失敗改動了組態檔")
	}
	if ok, _ := credential.Verify(readStoredRootHash(t, dir), oldSecret); !ok {
		t.Error("寫入失敗後舊口令應仍然可用")
	}
	if err := verifySessionSecret(t, dir, rootSecret); err != nil {
		t.Errorf("寫入失敗後不應動到任何會話: %v", err)
	}
	residue, _ := filepath.Glob(filepath.Join(dir, ".config.yaml.tmp-*"))
	if len(residue) != 0 {
		t.Errorf("留下臨時檔殘骸：%v", residue)
	}

	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatalf("恢復可寫失敗: %v", err)
	}
	if err := RecoverRoot(ctx, recoverArgs(dir), stdinSecrets(newSecret, newSecret), &syncBuffer{}); err != nil {
		t.Fatalf("故障撤除後重試失敗: %v", err)
	}
	if ok, _ := credential.Verify(readStoredRootHash(t, dir), newSecret); !ok {
		t.Error("重試後的憑據驗不過新口令")
	}
}

// TestRecoverRootTwiceInARow 釘住「重複操作」的語意：恢復不是只能跑一次的動作，
// 第二次換掉的是第一次留下的那份憑據，而且不會重複撤銷出第二筆虛帳。
func TestRecoverRootTwiceInARow(t *testing.T) {
	dir := newRootInitDir(t)
	ctx := context.Background()
	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets("twice-first-_pass", "twice-first-_pass"), &syncBuffer{}); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	firstHash := readStoredRootHash(t, dir)

	if err := RecoverRoot(ctx, recoverArgs(dir),
		stdinSecrets("twice-second-_pass", "twice-second-_pass"), &syncBuffer{}); err != nil {
		t.Fatalf("第一次恢復失敗: %v", err)
	}
	secondHash := readStoredRootHash(t, dir)

	var out syncBuffer
	if err := RecoverRoot(ctx, recoverArgs(dir),
		stdinSecrets("twice-third-_pass", "twice-third-_pass"), &out); err != nil {
		t.Fatalf("第二次恢復失敗: %v（輸出：%s）", err, out.String())
	}
	if !strings.Contains(out.String(), "0 個會話") {
		t.Errorf("第二輪沒有任何未撤銷的 Root 會話，報告應寫 0：%s", out.String())
	}
	thirdHash := readStoredRootHash(t, dir)
	if thirdHash == secondHash || thirdHash == firstHash {
		t.Error("連跑兩次沒有換出新憑據")
	}
	for _, stale := range []string{"twice-first-_pass", "twice-second-_pass"} {
		if ok, _ := credential.Verify(thirdHash, stale); ok {
			t.Errorf("舊口令 %q 竟然還驗得過", stale)
		}
	}
	if ok, _ := credential.Verify(thirdHash, "twice-third-_pass"); !ok {
		t.Error("最終憑據驗不過最後交上來的口令")
	}
	actions := rootAuditActions(t, dir)
	var recovered int
	for _, entry := range actions {
		if strings.HasPrefix(entry, "server.root_recover/system/") {
			recovered++
		}
	}
	if recovered != 2 {
		t.Errorf("兩次恢復各留一筆，實際 %d 筆：%v", recovered, actions)
	}
}

// TestRecoverRootRefusesWhenDiskLow 釘住「空間不足時根本不上手」：磁碟寫入門在讀口令之前
// 就把命令擋下，因此不會出現「憑據已覆寫、交易卻寫不進去」那種需要回滾的中間態。
//
// 判定用的是本命令自己那份組態的假下限（一個不可能滿足的 min_free_bytes），
// 不寫滿真實磁碟、也不動任何系統狀態。
func TestRecoverRootRefusesWhenDiskLow(t *testing.T) {
	const oldSecret = "dislow-old-_pass"
	dir := retryTempDir(t)
	configPath := filepath.Join(dir, "config.yaml")
	ctx := context.Background()

	// 先用正常組態把目錄建好並初始化，再把下限改成不可能滿足的值：
	// 順序反過來的話 migrate 自己就會被同一把門擋住，測不到恢復這條路。
	if err := os.WriteFile(configPath, []byte(rootInitConfig), 0o600); err != nil {
		t.Fatalf("寫入測試組態失敗: %v", err)
	}
	if err := Migrate(ctx, []string{"--data-dir", dir}, &syncBuffer{}); err != nil {
		t.Fatalf("建立測試資料庫失敗: %v", err)
	}
	if err := InitRoot(ctx, []string{"--password-stdin", "--data-dir", dir},
		stdinSecrets(oldSecret, oldSecret), &syncBuffer{}); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	rootSecret, _ := plantSessions(t, dir)

	tight := readFileBytesForRootTest(t, configPath) + "disk:\n  min_free_bytes: 9223372036854775807\n"
	if err := os.WriteFile(configPath, []byte(tight), 0o600); err != nil {
		t.Fatalf("改寫磁碟下限失敗: %v", err)
	}
	tightHash := readStoredRootHash(t, dir)

	err := RecoverRoot(ctx, recoverArgs(dir), stdinSecrets("toolow-new-_pass", "toolow-new-_pass"), &syncBuffer{})
	if err == nil {
		t.Fatal("空間不足時應拒絕")
	}
	if !strings.Contains(err.Error(), "空間不足") {
		t.Errorf("應回報磁碟空間不足，實際 %v", err)
	}
	if readStoredRootHash(t, dir) != tightHash {
		t.Error("被磁碟門擋下時仍改動了憑據")
	}
	if ok, _ := credential.Verify(tightHash, oldSecret); !ok {
		t.Error("被擋下後舊口令應仍然可用")
	}
	if err := verifySessionSecret(t, dir, rootSecret); err != nil {
		t.Errorf("被擋下後不應動到任何會話: %v", err)
	}
	residue, _ := filepath.Glob(filepath.Join(dir, ".config.yaml.tmp-*"))
	if len(residue) != 0 {
		t.Errorf("留下臨時檔殘骸：%v", residue)
	}
}

// demoteSchemaVersion 把測試資料庫的 user_version 降到已知版本之下（觸發交易邊界的 schema 拒絕）。
func demoteSchemaVersion(t *testing.T, dir string) {
	t.Helper()
	db, err := openTestDatabase(context.Background(), dir)
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗: %v", err)
	}
	defer func() { _ = db.Close() }()
	var current int
	if err := db.SQL().QueryRowContext(context.Background(), "PRAGMA user_version").Scan(&current); err != nil {
		t.Fatalf("讀取 schema 版本失敗: %v", err)
	}
	if current <= 1 {
		t.Fatalf("測試前置條件：schema 版本應高於 1，實際 %d", current)
	}
	setSchemaVersion(t, dir, 1)
}

// restoreSchemaVersion 把 user_version 換回降档前的值。
func restoreSchemaVersion(t *testing.T, dir string) {
	t.Helper()
	setSchemaVersion(t, dir, maxSchemaVersionForTest(t))
}

// setSchemaVersion 以測試專屬連線直接改 PRAGMA：這是降档／復原動作的唯一寫法，
// 走的是本任務專屬的資料庫檔，不碰任何真實資料目錄。
func setSchemaVersion(t *testing.T, dir string, version int) {
	t.Helper()
	path := filepath.ToSlash(filepath.Join(dir, "evernight.db"))
	pool, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(2000)")
	if err != nil {
		t.Fatalf("開啟測試資料庫（直接連線）失敗: %v", err)
	}
	defer func() { _ = pool.Close() }()
	if _, err := pool.ExecContext(context.Background(), fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		t.Fatalf("設定 schema 版本失敗: %v", err)
	}
}

// maxSchemaVersionForTest 讀出內嵌遷移集的最高版本（降档後要用它還原）。
func maxSchemaVersionForTest(t *testing.T) int {
	t.Helper()
	version, err := migrate.MaxVersion()
	if err != nil {
		t.Fatalf("讀取內嵌遷移最高版本失敗: %v", err)
	}
	return version
}

// truncateForTest 只在斷言失敗時把長字串截短，避免把整個日誌檔貼進輸出。
func truncateForTest(s string) string {
	if r := []rune(s); len(r) > 800 {
		return string(r[:800]) + "…"
	}
	return s
}
