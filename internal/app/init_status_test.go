package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/httpapi"
	"github.com/kagurazakayashi/EvernightRealm/internal/rootinit"
)

// cheapInitConfig 建立「已寫入測試組態檔、尚未初始化」的資料目錄與對應組態。
//
// 雜湊參數檔壓到許可區間下限：這條路每次都會真的跑一次 Argon2id 派生與自我校驗，
// 用生產檔會讓測試多花好幾秒，而「參數檔由組態決定」本身就是要走的路徑。
func cheapInitConfig(t *testing.T) (config.Config, string) {
	t.Helper()
	dir := retryTempDir(t)
	cfg := config.Default()
	cfg.Server.DataDir = dir
	cfg.Security.Hashing.MemoryKiB = 8192
	cfg.Security.Hashing.TimeCost = 1
	cfg.Security.Hashing.Parallelism = 1
	cfg.Security.Hashing.KeyLength = 16
	if err := os.WriteFile(cfg.ConfigFile(), []byte(rootInitConfig), 0o600); err != nil {
		t.Fatalf("寫入測試組態檔失敗：%v", err)
	}
	return cfg, dir
}

// readConfigBytes 讀回組態檔原始位元組，用於證明「查狀態」動不到檔案。
func readConfigBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取測試組態檔失敗：%v", err)
	}
	return data
}

func TestInitStatusSourceTracksConfigFile(t *testing.T) {
	cfg, _ := cheapInitConfig(t)
	source := initStatusSource(cfg)

	// 組態檔存在但還沒有憑據：這是「跑過 migrate、還沒 init-root」的形狀。
	first, err := source()
	if err != nil {
		t.Fatalf("查詢失敗：%v", err)
	}
	if !first.ConfigExists || first.RootInitialized {
		t.Errorf("應為「有檔案、未初始化」，實際 %+v", first)
	}
	if first.EnvOverride {
		t.Error("未設定環境變數時不該回報覆蓋狀態")
	}

	// 重複查詢同一份檔案：結果必須逐字相同，而且不能動到檔案。
	before := readConfigBytes(t, cfg.ConfigFile())
	again, err := source()
	if err != nil {
		t.Fatalf("第二次查詢失敗：%v", err)
	}
	if again != first {
		t.Errorf("重複查詢結果不一致：%+v 對 %+v", first, again)
	}
	if got := readConfigBytes(t, cfg.ConfigFile()); string(got) != string(before) {
		t.Error("查詢狀態動到了組態檔")
	}

	// 真的初始化一次之後，下一次查詢就要講出新狀態——這正是界面「重新檢查」
	// 能收斂的依據（初始化在服務停止時完成，重啟後的程序讀的是同一份檔案）。
	if _, err := rootinit.Initialize(rootinit.Options{
		ConfigPath: cfg.ConfigFile(),
		Secret:     "重新檢查專用的測試口令",
		Params:     mustTestParams(t, cfg),
	}); err != nil {
		t.Fatalf("測試初始化失敗：%v", err)
	}
	after, err := source()
	if err != nil {
		t.Fatalf("初始化後查詢失敗：%v", err)
	}
	if !after.ConfigExists || !after.RootInitialized {
		t.Errorf("初始化後應回報已就緒，實際 %+v", after)
	}

	// 第二次初始化仍被拒絕：狀態端點沒有把那一扇門開大。
	if _, err := rootinit.Initialize(rootinit.Options{
		ConfigPath: cfg.ConfigFile(),
		Secret:     "不該被接受的第二次口令",
		Params:     mustTestParams(t, cfg),
	}); err == nil {
		t.Fatal("重複初始化居然成功了，這違反一次性邊界")
	}
	if third, err := source(); err != nil || !third.RootInitialized {
		t.Errorf("被拒的第二次之後狀態仍應是已初始化，實際 %+v（err %v）", third, err)
	}
}

func TestInitStatusSourceFlagsEnvOverride(t *testing.T) {
	cfg, _ := cheapInitConfig(t)
	// 環境變數只給一個佔位值：來源只看「有沒有設定」，永不讀值。
	// 這一位的存在是為了不把「檔案裡沒有」講成「這個服務沒有 Root」——
	// 少了它，界面會勸操作者去跑一個必然被拒的 init-root。
	t.Setenv(config.RootPasswordHashEnvKey, "$argon2id$占位")

	status, err := initStatusSource(cfg)()
	if err != nil {
		t.Fatalf("查詢失敗：%v", err)
	}
	if !status.EnvOverride {
		t.Error("環境變數已設定時必須回報覆蓋狀態")
	}
	if status.RootInitialized {
		t.Error("檔案裡沒有憑據，狀態端點不該跟著環境變數說已初始化")
	}
}

func TestInitStatusSourceFailsInsteadOfGuessing(t *testing.T) {
	cfg, _ := cheapInitConfig(t)
	// 語法壞掉的組態檔：查不出來就回錯誤，不猜成「尚未初始化」。
	// 把故障報成未初始化，會讓界面建議一次根本不必要的初始化。
	if err := os.WriteFile(cfg.ConfigFile(), []byte("security:\n\troot_password_hash: x\n"), 0o600); err != nil {
		t.Fatalf("寫入壞組態檔失敗：%v", err)
	}
	if _, err := initStatusSource(cfg)(); err == nil {
		t.Fatal("壞掉的組態檔應回報查詢失敗")
	}
}

// TestInitStatusOverLiveService 用測試專屬服務走一遍首次啟動的真實節奏：
// 未初始化 →（操作者在本機完成初始化）→ 重新檢查 → 已初始化。
//
// 這裡刻意不直接呼叫來源函式而是打 HTTP：要驗的是「端點在完整中介層鏈之後
// 仍如實轉達檔案狀態」，也包括「兩趟 GET 之間檔案一個位元組都沒變」。
func TestInitStatusOverLiveService(t *testing.T) {
	cfg, _ := cheapInitConfig(t)
	srv := httpapi.New(&cfg, "test", httpapi.Deps{InitStatus: initStatusSource(cfg)})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	before := readConfigBytes(t, cfg.ConfigFile())
	if body := getInitStatus(t, ts); body["root_initialized"] != false {
		t.Fatalf("首次啟動應回報未初始化，實際 %v", body)
	}

	if _, err := rootinit.Initialize(rootinit.Options{
		ConfigPath: cfg.ConfigFile(),
		Secret:     "端到端專用的測試口令",
		Params:     mustTestParams(t, cfg),
	}); err != nil {
		t.Fatalf("測試初始化失敗：%v", err)
	}

	after := getInitStatus(t, ts)
	if after["root_initialized"] != true {
		t.Fatalf("重新檢查應看到已初始化，實際 %v", after)
	}
	if after["config_exists"] != true {
		t.Errorf("組態檔存在應回報 true，實際 %v", after["config_exists"])
	}
	if got := readConfigBytes(t, cfg.ConfigFile()); string(got) == string(before) {
		t.Fatal("初始化沒有動到檔案，前面的斷言就不成立")
	}
	// 再按一次重新檢查：狀態穩定，且這趟請求本身不再改檔案。
	stamp := readConfigBytes(t, cfg.ConfigFile())
	if again := getInitStatus(t, ts); again["root_initialized"] != true {
		t.Fatalf("第三次查詢狀態漂移：%v", again)
	}
	if got := readConfigBytes(t, cfg.ConfigFile()); string(got) != string(stamp) {
		t.Error("只讀端點改動了組態檔")
	}
}

// getInitStatus 向測試服務要一次狀態並還原成欄位表。
func getInitStatus(t *testing.T, ts *httptest.Server) map[string]any {
	t.Helper()
	resp, err := http.Get(ts.URL + "/root/init-status")
	if err != nil {
		t.Fatalf("請求失敗：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("狀態端點應回 200，實際 %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("解析回應失敗：%v", err)
	}
	return body
}

// mustTestParams 取組態裡的雜湊參數檔（與啟動路徑同一個解析入口）。
func mustTestParams(t *testing.T, cfg config.Config) credential.Params {
	t.Helper()
	params, err := cfg.Security.Hashing.Params()
	if err != nil {
		t.Fatalf("測試參數檔不合格：%v", err)
	}
	return params
}
