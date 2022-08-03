package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestDiskDefaultsAreUnlimited 固定「預設不做寫保護」這條決定。
//
// 它必須是被測試守住的取捨，而不是一行註解：把預設改成「5%」看起來更負責任，
// 但那樣一個從來沒讀過組態檔的部署者會在某一天突然發現自己的服務停止寫入，
// 而那個故障比空間耗盡本身更難歸因。
func TestDiskDefaultsAreUnlimited(t *testing.T) {
	got := Default().Disk
	if got.MinFreeBytes != 0 || got.MinFreePercent != 0 {
		t.Errorf("兩個下限預設應為 0（不設限），實際 %+v", got)
	}
	if got.CheckIntervalMS != 10000 {
		t.Errorf("快取期限預設應為 10 秒，實際 %d", got.CheckIntervalMS)
	}
}

func TestDiskValidate(t *testing.T) {
	accept := []DiskConfig{
		{MinFreeBytes: 0, MinFreePercent: 0, CheckIntervalMS: 10000},
		{MinFreeBytes: 1 << 30, CheckIntervalMS: 0},
		{MinFreePercent: 5.5, CheckIntervalMS: 3600000},
		// 100% 允許：效果是永久拒寫，那是部署者自己拉的閘，不是打錯數字的形態。
		{MinFreePercent: 100},
	}
	for i, want := range accept {
		cfg := Default()
		cfg.Disk = want
		if err := cfg.Validate(); err != nil {
			t.Errorf("第 %d 組 %+v 應被接受：%v", i+1, want, err)
		}
	}

	reject := []struct {
		name string
		disk DiskConfig
	}{
		{"負的絕對下限", DiskConfig{MinFreeBytes: -1}},
		{"負的百分比", DiskConfig{MinFreePercent: -0.5}},
		{"百分比超過 100", DiskConfig{MinFreePercent: 100.1}},
		{"快取期限為負", DiskConfig{MinFreeBytes: 1, CheckIntervalMS: -1}},
		{"快取期限超過一小時", DiskConfig{MinFreeBytes: 1, CheckIntervalMS: 3600001}},
	}
	for _, tc := range reject {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Disk = tc.disk
			if err := cfg.Validate(); err == nil {
				t.Errorf("%+v 應被拒絕而不是靜默修正", tc.disk)
			} else if !strings.Contains(err.Error(), "disk.") {
				t.Errorf("錯誤訊息要點出欄位路徑便於排錯：%v", err)
			}
		})
	}
}

// TestDiskEnvOverrides 驗證三個鍵都能由環境變數給定（開發與排錯時不改檔）。
func TestDiskEnvOverrides(t *testing.T) {
	t.Setenv("ER_DISK_MIN_FREE_BYTES", "1073741824")
	t.Setenv("ER_DISK_MIN_FREE_PERCENT", "7.5")
	t.Setenv("ER_DISK_CHECK_INTERVAL_MS", "30000")

	cfg, err := Load(Options{DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Load 失敗：%v", err)
	}
	if cfg.Disk.MinFreeBytes != 1<<30 || cfg.Disk.MinFreePercent != 7.5 || cfg.Disk.CheckIntervalMS != 30000 {
		t.Errorf("環境變數未生效：%+v", cfg.Disk)
	}
	// 啟用的下限必須出現在啓動摘要裏：這是部署狀態，不是實作細節。
	if summary := cfg.Redacted(); !strings.Contains(summary, "min_free_percent=7.5") ||
		!strings.Contains(summary, "min_free_bytes=1073741824") {
		t.Errorf("Redacted() 摘要缺少磁碟保護資訊：%s", summary)
	}

	for _, tc := range []struct{ key, value string }{
		{"ER_DISK_MIN_FREE_BYTES", "abc"},
		{"ER_DISK_MIN_FREE_PERCENT", "五"},
		{"ER_DISK_CHECK_INTERVAL_MS", "1e9"},
	} {
		t.Setenv(tc.key, tc.value)
		if _, err := Load(Options{DataDir: t.TempDir()}); err == nil {
			t.Errorf("%s=%q 非數字時應啟動失敗", tc.key, tc.value)
		}
		t.Setenv(tc.key, "")
	}
}

// TestDiskSummaryStates 把「未啟用要說得出來」這條寫進測試：
// 摘要只印 disk=[0 0 10000] 時，沒有人會知道那代表完全沒有保護。
func TestDiskSummaryStates(t *testing.T) {
	off := Default()
	if got := off.Disk.summary(); !strings.Contains(got, "未啟用") {
		t.Errorf("未設下限時摘要應明確寫未啟用：%q", got)
	}

	on := Default()
	on.Disk.MinFreeBytes = 1 << 30
	on.Disk.MinFreePercent = 5
	got := on.Disk.summary()
	for _, want := range []string{"min_free_bytes=1073741824", "min_free_percent=5"} {
		if !strings.Contains(got, want) {
			t.Errorf("啟用後的摘要缺少 %q：%q", want, got)
		}
	}
}

// TestExampleYAMLDocumentsDiskKeys 確保範例組態把三個鍵都寫出來且解得開：
// 同一個鍵寫兩次時，報錯發生在「首次啟動生成的 config.yaml 被讀回來」那一刻。
func TestExampleYAMLDocumentsDiskKeys(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte(ExampleYAML), &cfg); err != nil {
		t.Fatalf("ExampleYAML 解不開（是否有重複鍵）：%v", err)
	}
	for _, key := range []string{"min_free_bytes", "min_free_percent", "check_interval_ms"} {
		if !strings.Contains(ExampleYAML, key) {
			t.Errorf("ExampleYAML 缺少 disk.%s", key)
		}
	}
	// 範例值必須與程式內預設一致，否則「首次啟動的組態」與「文件上的組態」會分成兩份答案。
	if cfg.Disk.MinFreeBytes != 0 || cfg.Disk.MinFreePercent != 0 || cfg.Disk.CheckIntervalMS != 10000 {
		t.Errorf("ExampleYAML 的 disk 段與預設不符：%+v", cfg.Disk)
	}
}
