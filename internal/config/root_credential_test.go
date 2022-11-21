package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
)

// fakeHash 產生形狀合格的 Argon2id 編碼字串，供不需要真實派生的組態層測試使用。
//
// 組態層只認前綴與長度（真實校驗屬 internal/credential 與 rootinit 那兩層），
// 因此這裡用假值可以把測試 focus 在「檔案改了什麼、沒改到什麼」。
//
// tag 是這段編碼的身分標記：它先補齊成 16 位元組再編 base64，因為嚴格解析要求摘要長度
// 落在 [16,64]。直接塞一個短字串會讓「這是一份可用憑據」這一組測試先去讀到提醒欄位，
// 於是測到的就是錯的東西。
func fakeHash(tag string) string {
	padded := fmt.Sprintf("%-16s", tag)
	if len(padded) > 16 {
		padded = padded[:16]
	}
	return "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$" +
		base64.StdEncoding.EncodeToString([]byte(padded))
}

// readFileOrFail 讀出檔案內容供比對；檔案不存在時回傳缺失標記。
func readFileOrFail(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "(檔案不存在)"
		}
		t.Fatalf("讀取 %s 失敗: %v", path, err)
	}
	return string(data)
}

// listDir 回傳目錄下的檔案名清單（用於斷言失敗路徑沒有留下臨時檔殘骸）。
func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("列出 %s 失敗: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// installSeams 換掉檔案系統動作的注入點並在測試結束還原。
//
// 還原一律用 t.Cleanup：中途 t.Fatalf 也不會把壞掉的注入留給下一個測試
// （同包的測試共用行程，一個沒還原的替身會讓之後的失敗難以解讀）。
func installSeams(t *testing.T, create func(dir, pattern string) (*os.File, error),
	rename func(oldPath, newPath string) error, remove func(string) error) {
	t.Helper()
	oldCreate, oldRename, oldRemove := createTempFile, renamePath, removePath
	t.Cleanup(func() { createTempFile, renamePath, removePath = oldCreate, oldRename, oldRemove })
	if create != nil {
		createTempFile = create
	}
	if rename != nil {
		renamePath = rename
	}
	if remove != nil {
		removePath = remove
	}
}

func TestReadRootFileMissingConfigIsNotAnError(t *testing.T) {
	// 首次部署的正常狀態：檔案還沒建立。
	state, err := ReadRootFile(filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatalf("組態檔不存在不該回報錯誤: %v", err)
	}
	if state.FileExists || state.Initialized() {
		t.Errorf("不存在的組態檔應為未初始化，實際 %+v", state)
	}
}

func TestReadRootFileStates(t *testing.T) {
	const hash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aWxsbHVzaGFzaA"
	cases := []struct {
		name          string
		content       string
		wantExists    bool
		wantInit      bool
		wantHash      string
		wantErrSubstr string
	}{
		{
			name: "沒有 security 區塊", content: "server:\n  listen: \"127.0.0.1:5206\"\n",
			wantExists: true,
		},
		{
			name: "security 為空值", content: "security:\n",
			wantExists: true,
		},
		{
			name: "欄位不存在", content: "security:\n  session_ttl_hours: 24\n",
			wantExists: true,
		},
		{
			name: "欄位為空字串", content: "security:\n  root_password_hash: \"\"\n",
			wantExists: true,
		},
		{
			// Hash 保留檔案裡的原始值（忠實讀取），「空白視同未設定」由 Initialized() 判斷。
			name: "欄位只有空白", content: "security:\n  root_password_hash: \"   \"\n",
			wantExists: true, wantHash: "   ",
		},
		{
			name:       "欄位已設定",
			content:    "security:\n  root_password_hash: \"" + hash + "\"\n",
			wantExists: true, wantInit: true, wantHash: hash,
		},
		{
			name:       "單引號寫法",
			content:    "security:\n  root_password_hash: '" + hash + "'\n",
			wantExists: true, wantInit: true, wantHash: hash,
		},
		{
			name: "欄位是清單（不是憑據形狀）", content: "security:\n  root_password_hash: [a, b]\n",
			wantExists: true, wantErrSubstr: "不是純量值",
		},
		{
			name: "security 是純量", content: "security: 5\n",
			wantExists: true, wantErrSubstr: "不是映射",
		},
		{
			name: "根節點是清單", content: "- a\n- b\n",
			wantExists: false, wantErrSubstr: "根節點不是映射",
		},
		{
			name: "YAML 語法壞掉", content: "security:\n  session_ttl_hours: 24\n   broken: [\n",
			wantExists: false, wantErrSubstr: "解析組態檔失敗",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, tc.content)
			state, err := ReadRootFile(path)
			if tc.wantErrSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Fatalf("錯誤應含 %q，實際 %v", tc.wantErrSubstr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadRootFile 失敗: %v", err)
			}
			if state.FileExists != tc.wantExists {
				t.Errorf("FileExists=%v，期望 %v", state.FileExists, tc.wantExists)
			}
			if state.Initialized() != tc.wantInit {
				t.Errorf("Initialized=%v，期望 %v", state.Initialized(), tc.wantInit)
			}
			if state.Hash != tc.wantHash {
				t.Errorf("Hash=%q，期望 %q", state.Hash, tc.wantHash)
			}
		})
	}
}

func TestReadRootFileErrorsDoNotEchoFileContent(t *testing.T) {
	// 壞掉的檔案裡可能有真憑據：錯誤訊息只能說「哪裡不對」，不能把內容帶出去。
	const secret = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$dG9wc2VjcmV0"
	path := writeConfig(t, "security:\n  root_password_hash: \""+secret+"\"\n  session_ttl_hours: [1, 2\n")
	_, err := ReadRootFile(path)
	if err == nil {
		t.Fatal("語法壞掉的組態檔應回報錯誤")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "dG9wc2VjcmV0") {
		t.Errorf("錯誤訊息回顯了檔案內容: %v", err)
	}
}

func TestWriteRootPasswordHashFirstSuccess(t *testing.T) {
	path := writeConfig(t, ExampleYAML)
	hash := fakeHash("c2VjcmV0dmFsdWUx")

	if err := WriteRootPasswordHash(path, hash); err != nil {
		t.Fatalf("首次寫入失敗: %v", err)
	}
	state, err := ReadRootFile(path)
	if err != nil {
		t.Fatalf("回讀失敗: %v", err)
	}
	if !state.Initialized() || state.Hash != hash {
		t.Fatalf("檔案內的憑據不正確: %+v", state)
	}

	// 寫出來的檔案必須還能被正常載入與校驗（這才是「生效」的意思）。
	cfg, err := Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("寫入後 Load 失敗: %v", err)
	}
	if cfg.Security.RootPasswordHash != hash {
		t.Errorf("Load 讀到的 Root 雜湊不一致")
	}
	if got := cfg.Redacted(); strings.Contains(got, hash) || !strings.Contains(got, "[REDACTED]") {
		t.Errorf("啟動摘要未脫敏 Root 雜湊: %s", got)
	}
}

func TestWriteRootPasswordHashPreservesCommentsAndUnknownKeys(t *testing.T) {
	// 這條釘住「節點級編輯」而不是結構體重寫：註解與本服務不認識的欄位都要活下來。
	content := `# 開檔說明行
server:
  listen: "127.0.0.1:5206"          # 監聽地址註解
  data_dir: "."

# 部署者自己加的欄位，服務端不認識但必須保留
operations:
  note: "this line must survive"

security:
  session_ttl_hours: 48             # 會話時數註解
  headers:
    frame_options: "DENY"
`
	path := writeConfig(t, content)
	hash := fakeHash("cHJlc2VydmUtbWU")
	if err := WriteRootPasswordHash(path, hash); err != nil {
		t.Fatalf("寫入失敗: %v", err)
	}
	after := readFileOrFail(t, path)
	for _, must := range []string{
		"開檔說明行", "監聽地址註解", "this line must survive", "會話時數註解", "frame_options",
		"session_ttl_hours", "root_password_hash", hash,
	} {
		if !strings.Contains(after, must) {
			t.Errorf("寫入後的檔案少了 %q：\n%s", must, after)
		}
	}
	// 插入位置在 session_ttl_hours 之後，不是塞在巢狀區塊裡。
	if strings.Index(after, "session_ttl_hours") > strings.Index(after, "root_password_hash") {
		t.Errorf("root_password_hash 沒有插在 session_ttl_hours 之後：\n%s", after)
	}
	// 縮排維持 2 格：只改一個欄位的檔案不該被整份重新縮排（yaml.v3 的預設是 4 格）。
	if !strings.Contains(after, "\n  root_password_hash: \"") {
		t.Errorf("新欄位的縮排不是 2 格：\n%s", after)
	}

	cfg, err := Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("保留內容後的檔案仍須可載入: %v", err)
	}
	if cfg.Security.SessionTTLHours != 48 || cfg.Security.Headers.FrameOptions != "DENY" {
		t.Errorf("既有欄位的值被改動: %+v", cfg.Security)
	}
}

func TestWriteRootPasswordHashReplacesExistingEmptyValue(t *testing.T) {
	// 範例組態未來若寫上 `root_password_hash: ""`，寫入要落在原本那一行而不是多出一個鍵。
	path := writeConfig(t, "security:\n  root_password_hash: \"\"\n  session_ttl_hours: 24\n")
	hash := fakeHash("ZW1wdHl0b3NldA")
	if err := WriteRootPasswordHash(path, hash); err != nil {
		t.Fatalf("寫入失敗: %v", err)
	}
	after := readFileOrFail(t, path)
	if got := strings.Count(after, "root_password_hash"); got != 1 {
		t.Errorf("鍵出現 %d 次，期望 1 次：\n%s", got, after)
	}
	state, err := ReadRootFile(path)
	if err != nil || state.Hash != hash {
		t.Fatalf("回讀結果不正確: %+v err=%v", state, err)
	}
}

func TestWriteRootPasswordHashCreatesMissingSecuritySection(t *testing.T) {
	cases := map[string]string{
		"沒有 security": "server:\n  listen: \"127.0.0.1:5206\"\n",
		"security 空值": "security:\n",
		"空檔案":         "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, content)
			hash := fakeHash("bmV3c2VjdGlvbg")
			if err := WriteRootPasswordHash(path, hash); err != nil {
				t.Fatalf("寫入失敗: %v", err)
			}
			state, err := ReadRootFile(path)
			if err != nil || !state.Initialized() || state.Hash != hash {
				t.Fatalf("寫入後狀態不正確: %+v err=%v", state, err)
			}
			cfg, err := Load(Options{ConfigPath: path})
			if err != nil {
				t.Fatalf("Load 失敗: %v", err)
			}
			if cfg.Security.RootPasswordHash != hash {
				t.Errorf("Load 讀不到新寫入的憑據")
			}
		})
	}
}

func TestWriteRootPasswordHashRefusesSecondWrite(t *testing.T) {
	path := writeConfig(t, ExampleYAML)
	first := fakeHash("Zmlyc3RvbmU")
	if err := WriteRootPasswordHash(path, first); err != nil {
		t.Fatalf("首次寫入失敗: %v", err)
	}
	before := readFileOrFail(t, path)

	second := fakeHash("nGVjb25kb25l")
	err := WriteRootPasswordHash(path, second)
	if !errors.Is(err, ErrRootAlreadyInitialized) {
		t.Fatalf("第二次寫入應回 ErrRootAlreadyInitialized，實際 %v", err)
	}
	if after := readFileOrFail(t, path); after != before {
		t.Errorf("拒絕路徑改動了組態檔：\n%s\n---\n%s", before, after)
	}
	if strings.Contains(err.Error(), first) || strings.Contains(err.Error(), second) {
		t.Errorf("拒絕錯誤回顯了憑據內容: %v", err)
	}
}

func TestWriteRootPasswordHashRejectsMalformedHash(t *testing.T) {
	cases := map[string]string{
		"空字串":        "",
		"只有空白":       "   ",
		"非 Argon2id": "$argon2i$v=19$m=1024,t=1,p=1$c2FsdA$ZGln",
		"前綴對但解不開":    "$argon2id$v=19$m=8192,t=1,p=1$not-base64!!$also-not-base64!!",
		"前綴對但摘要過短":   "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$ZGln",
		"一般文字":       "hunter2",
		"超長":         "$argon2id$" + strings.Repeat("x", credential.MaxEncodedLength+1),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, ExampleYAML)
			before := readFileOrFail(t, path)
			err := WriteRootPasswordHash(path, value)
			if err == nil {
				t.Fatalf("不合格的形狀應被拒絕")
			}
			if after := readFileOrFail(t, path); after != before {
				t.Errorf("拒絕路徑改動了組態檔")
			}
			dir := filepath.Dir(path)
			if names := listDir(t, dir); len(names) != 1 || names[0] != "config.yaml" {
				t.Errorf("拒絕路徑留下殘骸: %v", names)
			}
		})
	}
}

func TestWriteRootPasswordHashMissingConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.yaml")
	err := WriteRootPasswordHash(path, fakeHash("bm9maWxl"))
	if err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Fatalf("組態檔不存在時應明確回報，實際 %v", err)
	}
}

func TestWriteRootPasswordHashFailureAtEachStageLeavesOriginal(t *testing.T) {
	const original = "server:\n  listen: \"127.0.0.1:5206\"\nsecurity:\n  session_ttl_hours: 24\n"
	hash := fakeHash("ZmFpbHVyZQ")

	stages := []struct {
		name    string
		create  func(dir, pattern string) (*os.File, error)
		rename  func(oldPath, newPath string) error
		wantSub string
	}{
		{
			name: "臨時檔建立失敗",
			create: func(string, string) (*os.File, error) {
				return nil, errors.New("模擬：目錄不可寫")
			},
			wantSub: "建立臨時組態檔失敗",
		},
		{
			name: "改名替換失敗",
			rename: func(string, string) error {
				return errors.New("模擬：佔用中")
			},
			wantSub: "替換",
		},
	}
	for _, stage := range stages {
		t.Run(stage.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatalf("建立測試組態失敗: %v", err)
			}
			installSeams(t, stage.create, stage.rename, nil)

			err := WriteRootPasswordHash(path, hash)
			if err == nil || !strings.Contains(err.Error(), stage.wantSub) {
				t.Fatalf("錯誤應含 %q，實際 %v", stage.wantSub, err)
			}
			if got := readFileOrFail(t, path); got != original {
				t.Errorf("失敗路徑改動了原檔案：\n%s", got)
			}
			state, err := ReadRootFile(path)
			if err != nil {
				t.Fatalf("回讀失敗: %v", err)
			}
			if state.Initialized() {
				t.Errorf("失敗路徑不應讓憑據變成已設定")
			}
			// 臨時檔必須被清掉：留著只會多一個「看起來像組態檔」的檔案。
			if names := listDir(t, dir); len(names) != 1 || names[0] != "config.yaml" {
				t.Errorf("失敗路徑留下臨時檔殘骸: %v", names)
			}
		})
	}
}

func TestWriteRootPasswordHashDetectsContentThatDidNotLand(t *testing.T) {
	// 模擬「改名回報成功，但檔案裡不是我們送進去的那個值」：回讀比對必須擋下來。
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	const original = "security:\n  session_ttl_hours: 24\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("建立測試組態失敗: %v", err)
	}
	installSeams(t, nil, func(_, newPath string) error {
		return os.WriteFile(newPath, []byte("security:\n  root_password_hash: \"\"\n"), 0o600)
	}, nil)

	err := WriteRootPasswordHash(path, fakeHash("bm90bGFuZGluZw"))
	if err == nil || !strings.Contains(err.Error(), "不算成功") {
		t.Fatalf("回讀不符時應回報失敗，實際 %v", err)
	}
}

func TestWriteRootPasswordHashRealFileSystemFailure(t *testing.T) {
	// 不走注入點：讓標準庫自己在「目錄不存在」的真實檔案系統錯誤上失敗。
	missing := filepath.Join(t.TempDir(), "does-not-exist", "config.yaml")
	if err := os.WriteFile(missing, nil, 0o600); err == nil {
		// 有的平台會真的建出檔案；那就改以「目標是不可寫的位置」驗證，這裡先確認前置條件。
		t.Skip("此平台允許在不存在的目錄建立檔案，改由注入點覆蓋失敗路徑")
	}
	installSeams(t, nil, nil, func(string) error { return nil })
	if err := WriteRootPasswordHash(missing, fakeHash("cmVhbGZz")); err == nil {
		t.Fatal("目錄不存在時應回報寫入失敗")
	}
}

func TestWriteRootPasswordHashConcurrentCallsWriteOnce(t *testing.T) {
	// 併發初始化：只能有一次成功，其餘一律撞「已初始化」，檔案裡是成功那次的值。
	path := writeConfig(t, ExampleYAML)
	const racers = 8

	var wg sync.WaitGroup
	errs := make([]error, racers)
	hashes := make([]string, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		hashes[i] = fakeHash(fmt.Sprintf("cmFjZXIwMA%d", i))
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = WriteRootPasswordHash(path, hashes[i])
		}(i)
	}
	close(start)
	wg.Wait()

	var succeeded []string
	for i, err := range errs {
		switch {
		case err == nil:
			succeeded = append(succeeded, hashes[i])
		case errors.Is(err, ErrRootAlreadyInitialized):
		default:
			t.Fatalf("第 %d 個競跑的錯誤不在預期內: %v", i, err)
		}
	}
	if len(succeeded) != 1 {
		t.Fatalf("成功次數=%d，期望 1（%v）", len(succeeded), succeeded)
	}
	state, err := ReadRootFile(path)
	if err != nil {
		t.Fatalf("回讀失敗: %v", err)
	}
	if state.Hash != succeeded[0] {
		t.Errorf("檔案裡的憑據不是成功那次寫入的值")
	}
	cfg, err := Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("競跑後的檔案不可載入: %v", err)
	}
	if cfg.Security.RootPasswordHash != state.Hash {
		t.Errorf("Load 與檔案讀取的結果不一致")
	}
}

func TestWriteRootPasswordHashKeepsMinimalPermissions(t *testing.T) {
	// 只對測試專屬目錄斷言，不碰部署者的真實檔案權限。
	// Windows 的權限模型不由模式位表達（Go 在那邊一律回報 0666／0444），因此跳過。
	if runtime.GOOS == "windows" {
		t.Skip("Windows 不以 Unix 模式位表示權限；原子寫入固定以 0600 建立臨時檔，由改名帶過去")
	}
	path := writeConfig(t, ExampleYAML)
	if err := WriteRootPasswordHash(path, fakeHash("cGVybWlzc2lvbg")); err != nil {
		t.Fatalf("寫入失敗: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat 失敗: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("組態檔權限過寬：%o（期望只有擁有者可讀寫）", perm)
	}
}

func TestLoadKeepsUnusableRootHashWithNotice(t *testing.T) {
	// 一個寫壞的 Root 值代表「目前沒有可用的 Root」，但不代表該讓整個服務開不起來：
	// 載入照過、提醒要看得見、脫敏摘要仍不得輸出值本身。
	const garbage = "$argon2id$v=19$m=8192,t=1,p=1$not-base64!!$also-not-base64!!"
	path := writeConfig(t, "security:\n  root_password_hash: \""+garbage+"\"\n")

	cfg, err := Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("不合格的 Root 值不應讓載入失敗: %v", err)
	}
	if cfg.RootHashNotice == "" {
		t.Error("啟動摘要缺少 Root 憑據不合格的提醒")
	}
	summary := cfg.Redacted()
	if strings.Contains(summary, garbage) || !strings.Contains(summary, "[REDACTED]") {
		t.Errorf("摘要回顯了憑據內容或未脫敏: %s", summary)
	}
	if !strings.Contains(summary, cfg.RootHashNotice) {
		t.Errorf("提醒沒有出現在啟動摘要裡: %s", summary)
	}

	// 前綴都不對的寫法仍是啟動階段的硬錯誤（那代表有人把別的東西放進了這一欄）。
	badPrefix := writeConfig(t, "security:\n  root_password_hash: \"hunter2\"\n")
	if _, err := Load(Options{ConfigPath: badPrefix}); err == nil {
		t.Error("非 Argon2id 前綴應在載入階段報錯")
	}
}

func TestLoadHasNoNoticeForUsableRootHash(t *testing.T) {
	path := writeConfig(t, ExampleYAML)
	hash := fakeHash("dXNhYmxlbm90aWNl")
	if err := WriteRootPasswordHash(path, hash); err != nil {
		t.Fatalf("寫入失敗: %v", err)
	}
	cfg, err := Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if cfg.RootHashNotice != "" {
		t.Errorf("可用的憑據不該產生提醒: %q", cfg.RootHashNotice)
	}
	//  yaml:"-" 的保證：把整個 Config 編碼出來時不能出現那句話。
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("yaml.Marshal 失敗: %v", err)
	}
	if strings.Contains(string(out), "RootHashNotice") || strings.Contains(string(out), "憑據形狀不合格") {
		t.Errorf("提醒欄位被寫進 YAML 了:\n%s", out)
	}
}

func TestWriteRootPasswordHashKeepsEveryOtherValue(t *testing.T) {
	// 「只動一個值」不能只是註解裡的承諾：把寫入前後的檔案各自解成結構體逐欄比對，
	// 除了 Root 憑據本身，任何一欄都不准變。縮排與註解位置可以被重新排版（那是 yaml.v3
	// 的行為），但語意必须完全一致——這條測試認的是語意，不是字面差异。
	path := writeConfig(t, ExampleYAML)
	before, err := Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("寫入前 Load 失敗: %v", err)
	}
	before.RootHashNotice = ""

	hash := fakeHash("only-this-changes")
	if err := WriteRootPasswordHash(path, hash); err != nil {
		t.Fatalf("寫入失敗: %v", err)
	}
	after, err := Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("寫入後 Load 失敗: %v", err)
	}
	after.Security.RootPasswordHash = before.Security.RootPasswordHash
	after.RootHashNotice = ""
	if !reflect.DeepEqual(after, before) {
		t.Errorf("除了 Root 憑據，其他組態值被改動了：before=%+v after=%+v", before, after)
	}
}

func TestUpdateRootPasswordHashReplacesExistingValue(t *testing.T) {
	path := writeConfig(t, ExampleYAML)
	oldHash := fakeHash("b2xkcm9vdA")
	newHash := fakeHash("bmV3cm9vdA")
	if err := WriteRootPasswordHash(path, oldHash); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}

	if err := UpdateRootPasswordHash(path, oldHash, newHash); err != nil {
		t.Fatalf("覆寫失敗: %v", err)
	}
	state, err := ReadRootFile(path)
	if err != nil || !state.Initialized() || state.Hash != newHash {
		t.Fatalf("覆寫後的檔案狀態不正確: %+v err=%v", state, err)
	}
	after := readFileOrFail(t, path)
	if strings.Contains(after, oldHash) {
		t.Errorf("舊憑據仍留在檔案裡")
	}
	// 註解文字裡本來就提過 security.root_password_hash，所以數的是「帶值的鍵」而不是裸鍵名。
	if got := strings.Count(after, "root_password_hash: \""); got != 1 {
		t.Errorf("值鍵行出現 %d 次，期望 1 次：\n%s", got, after)
	}
	cfg, err := Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("覆寫後的檔案不可載入: %v", err)
	}
	if cfg.Security.RootPasswordHash != newHash {
		t.Errorf("Load 讀到的不是新憑據")
	}
}

func TestUpdateRootPasswordHashPreservesCommentsAndOtherValues(t *testing.T) {
	// 覆寫同樣只準動那一個值：註解、鍵序、未知欄位與其餘全部欄位都要活下來。
	content := `# 開檔說明行
server:
  listen: "127.0.0.1:5206"          # 監聽地址註解
  data_dir: "."

operations:
  note: "this line must survive"

security:
  session_ttl_hours: 48             # 會話時數註解
  root_password_hash: "PLACEHOLDER"
  headers:
    frame_options: "DENY"
`
	path := writeConfig(t, strings.Replace(content, "PLACEHOLDER", fakeHash("cHJlc2VydmUtbWU"), 1))
	before, err := Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("覆寫前 Load 失敗: %v", err)
	}
	before.RootHashNotice = ""

	newHash := fakeHash("bmV3LXByZXNlcnZl")
	if err := UpdateRootPasswordHash(path, before.Security.RootPasswordHash, newHash); err != nil {
		t.Fatalf("覆寫失敗: %v", err)
	}
	after := readFileOrFail(t, path)
	for _, must := range []string{
		"開檔說明行", "監聽地址註解", "this line must survive", "會話時數註解", "frame_options",
		"session_ttl_hours", newHash,
	} {
		if !strings.Contains(after, must) {
			t.Errorf("覆寫後的檔案少了 %q：\n%s", must, after)
		}
	}

	reloaded, err := Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("覆寫後 Load 失敗: %v", err)
	}
	reloaded.Security.RootPasswordHash = before.Security.RootPasswordHash
	reloaded.RootHashNotice = ""
	if !reflect.DeepEqual(reloaded, before) {
		t.Errorf("除了 Root 憑據，其他組態值被改動了：before=%+v after=%+v", before, reloaded)
	}
}

func TestUpdateRootPasswordHashMismatchLeavesFileUntouched(t *testing.T) {
	path := writeConfig(t, ExampleYAML)
	current := fakeHash("Y3VycmVudA")
	if err := WriteRootPasswordHash(path, current); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	before := readFileOrFail(t, path)

	err := UpdateRootPasswordHash(path, fakeHash("b3RoZXJvbmU"), fakeHash("bmV3b25l"))
	if !errors.Is(err, ErrRootCredentialMismatch) {
		t.Fatalf("現值不符應回 ErrRootCredentialMismatch，實際 %v", err)
	}
	if after := readFileOrFail(t, path); after != before {
		t.Errorf("拒絕路徑改動了組態檔：\n%s\n---\n%s", before, after)
	}
	if strings.Contains(err.Error(), current) {
		t.Errorf("拒絕錯誤回顯了憑據內容: %v", err)
	}
	dir := filepath.Dir(path)
	if names := listDir(t, dir); len(names) != 1 || names[0] != "config.yaml" {
		t.Errorf("拒絕路徑留下殘骸: %v", names)
	}
}

func TestUpdateRootPasswordHashRefusesMissingPrerequisites(t *testing.T) {
	// 這四種都不是「可覆寫的形態」：尚未初始化、檔案不存在、沒給預期現值、新值形狀不合格。
	t.Run("尚未初始化", func(t *testing.T) {
		path := writeConfig(t, ExampleYAML)
		err := UpdateRootPasswordHash(path, fakeHash("YW55"), fakeHash("bmV3b25l"))
		if !errors.Is(err, ErrRootCredentialMismatch) {
			t.Fatalf("沒有現值時應回現值不符，實際 %v", err)
		}
		state, err := ReadRootFile(path)
		if err != nil || state.Initialized() {
			t.Errorf("拒絕路徑建立了憑據: %+v err=%v", state, err)
		}
	})
	t.Run("檔案不存在", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nested", "config.yaml")
		err := UpdateRootPasswordHash(path, fakeHash("YW55"), fakeHash("bmV3b25l"))
		if err == nil || !strings.Contains(err.Error(), "不存在") {
			t.Fatalf("組態檔不存在時應明確回報，實際 %v", err)
		}
	})
	t.Run("預期現值為空", func(t *testing.T) {
		path := writeConfig(t, ExampleYAML)
		err := UpdateRootPasswordHash(path, "   ", fakeHash("bmV3b25l"))
		if err == nil || !strings.Contains(err.Error(), "預期") {
			t.Fatalf("缺少預期現值應被拒絕，實際 %v", err)
		}
	})
	for name, bad := range map[string]string{
		"空字串":        "",
		"非 Argon2id": "$argon2i$v=19$m=1024,t=1,p=1$c2FsdA$ZGln",
		"一般文字":       "hunter2",
	} {
		t.Run("新值不合格："+name, func(t *testing.T) {
			path := writeConfig(t, ExampleYAML)
			current := fakeHash("Y3VycmVudA")
			if err := WriteRootPasswordHash(path, current); err != nil {
				t.Fatalf("前置初始化失敗: %v", err)
			}
			before := readFileOrFail(t, path)
			if err := UpdateRootPasswordHash(path, current, bad); err == nil {
				t.Fatal("形狀不合格的新值應被拒絕")
			}
			if after := readFileOrFail(t, path); after != before {
				t.Errorf("拒絕路徑改動了組態檔")
			}
		})
	}
}

func TestUpdateRootPasswordHashFailureAtRenameLeavesOriginal(t *testing.T) {
	path := writeConfig(t, ExampleYAML)
	current := fakeHash("Y3VycmVudA")
	if err := WriteRootPasswordHash(path, current); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	before := readFileOrFail(t, path)
	installSeams(t, nil, func(string, string) error {
		return errors.New("模擬：佔用中")
	}, nil)

	if err := UpdateRootPasswordHash(path, current, fakeHash("bmV3b25l")); err == nil ||
		!strings.Contains(err.Error(), "替換") {
		t.Fatalf("改名失敗應回報替換失敗，實際 %v", err)
	}
	if after := readFileOrFail(t, path); after != before {
		t.Errorf("失敗路徑改動了原檔案")
	}
	dir := filepath.Dir(path)
	if names := listDir(t, dir); len(names) != 1 || names[0] != "config.yaml" {
		t.Errorf("失敗路徑留下臨時檔殘骸: %v", names)
	}
}

func TestUpdateRootPasswordHashConcurrentCallsOnlyOneWins(t *testing.T) {
	// 併發改密：所有競跑者都帶著同一個「預期現值」，只能有一個成功；
	// 輸家一律收到現值不符，檔案裡是贏家那次的值。
	path := writeConfig(t, ExampleYAML)
	current := fakeHash("Y3VycmVudA")
	if err := WriteRootPasswordHash(path, current); err != nil {
		t.Fatalf("前置初始化失敗: %v", err)
	}
	const racers = 8

	var wg sync.WaitGroup
	errs := make([]error, racers)
	hashes := make([]string, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		hashes[i] = fakeHash(fmt.Sprintf("bmV3cmFjZXIwMA%d", i))
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = UpdateRootPasswordHash(path, current, hashes[i])
		}(i)
	}
	close(start)
	wg.Wait()

	var succeeded []string
	for i, err := range errs {
		switch {
		case err == nil:
			succeeded = append(succeeded, hashes[i])
		case errors.Is(err, ErrRootCredentialMismatch):
		default:
			t.Fatalf("第 %d 個競跑的錯誤不在預期內: %v", i, err)
		}
	}
	if len(succeeded) != 1 {
		t.Fatalf("成功次數=%d，期望 1（%v）", len(succeeded), succeeded)
	}
	state, err := ReadRootFile(path)
	if err != nil || state.Hash != succeeded[0] {
		t.Errorf("檔案裡的憑據不是贏家那次的值: %+v err=%v", state, err)
	}
}

func TestUpdateRootPasswordHashRealFileSystemFailure(t *testing.T) {
	// 不走注入點：目標目錄不存在時，覆寫必須以真實檔案系統錯誤失敗而不是降級。
	missing := filepath.Join(t.TempDir(), "does-not-exist", "config.yaml")
	if err := os.WriteFile(missing, nil, 0o600); err == nil {
		t.Skip("此平臺允許在不存在的目錄建立檔案，改由注入點覆蓋失敗路徑")
	}
	installSeams(t, nil, nil, func(string) error { return nil })
	if err := UpdateRootPasswordHash(missing, fakeHash("YW55b25l"), fakeHash("bmV3b25l")); err == nil {
		t.Fatal("目錄不存在時應回報失敗")
	}
}
