package config

import (
	"strings"
	"testing"
)

// 這一檔釘住裝置登入策略的組態邊界：三個模式的列舉、名額只在 limited 下存在、
// 預設值是「不擅自改變既有部署」的那一個（multi），以及四條覆蓋路徑
// （預設 → yaml → 環境變數 → 內嵌範例）都講同一件事。

// TestDevicePolicyDefaultsKeepExistingBehaviour 預設必須是 multi：
// 這個鍵存在之前的行為就是「每次登入各簽發一份互不影響的會話」。
// 把預設改成 single 或 limited 會在一次「新增開關」的改動裡順帶把人踢下線，
// 那是部署者的決定，不是程式碼的偏好。
func TestDevicePolicyDefaultsKeepExistingBehaviour(t *testing.T) {
	d := Default().Security.DevicePolicy
	if d.Mode != "multi" {
		t.Errorf("device_policy.mode 預設應為 multi（沿用既有行為），實際 %q", d.Mode)
	}
	if d.MaxDevices != 0 {
		t.Errorf("非 limited 模式下名額應留 0，實際 %d", d.MaxDevices)
	}
	base := Default()
	if err := base.Validate(); err != nil {
		t.Errorf("預設組態應合法：%v", err)
	}
}

// TestDevicePolicyYAMLAndEnvOverride 確認兩個鍵都能按既有分層順序被覆蓋，
// 且單欄覆蓋不牽動其它欄（與會話策略那幾支測試同一判準）。
func TestDevicePolicyYAMLAndEnvOverride(t *testing.T) {
	path := writeConfig(t, "security:\n  device_policy:\n    mode: limited\n    max_devices: 4\n")
	cfg, err := Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if cfg.Security.DevicePolicy.Mode != "limited" || cfg.Security.DevicePolicy.MaxDevices != 4 {
		t.Errorf("yaml 覆蓋未生效: %+v", cfg.Security.DevicePolicy)
	}
	// 同段的其它鍵不應被裝置策略這一段吃掉。
	if cfg.Security.SessionTTLHours != 24 {
		t.Errorf("session_ttl_hours 不應受影響，實際 %d", cfg.Security.SessionTTLHours)
	}

	// 環境變數只改名額：模式沿用 yaml 的 limited，兩層覆蓋各管自己那一欄。
	t.Setenv("ER_SECURITY_DEVICE_POLICY_MAX_DEVICES", "7")
	cfg, err = Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("帶環境變數的 Load 失敗: %v", err)
	}
	if cfg.Security.DevicePolicy.Mode != "limited" || cfg.Security.DevicePolicy.MaxDevices != 7 {
		t.Errorf("環境變數應只覆蓋名額，實際: %+v", cfg.Security.DevicePolicy)
	}

	// 環境變數把模式改成 single，而 yaml 那個 7 還留著：這是互相矛盾的寫法，
	// 啟動必須拒而不是「挑一個來用」。
	t.Setenv("ER_SECURITY_DEVICE_POLICY_MODE", "single")
	if _, err := Load(Options{ConfigPath: path}); err == nil ||
		!strings.Contains(err.Error(), "security.device_policy.max_devices") {
		t.Errorf("single 搭配殘留名額應被拒絕並指出鍵名，實際: %v", err)
	}

	// 換一份沒寫名額的組態：環境變數設 single 就該順利啟動
	// （環境變數給空值等於「沒設」，這是 applyEnv 既有的分層規則）。
	t.Setenv("ER_SECURITY_DEVICE_POLICY_MAX_DEVICES", "")
	bare := writeConfig(t, "security:\n  session_ttl_hours: 12\n")
	cfg, err = Load(Options{ConfigPath: bare})
	if err != nil {
		t.Fatalf("single（未帶名額）應合法: %v", err)
	}
	if cfg.Security.DevicePolicy.Mode != "single" || cfg.Security.DevicePolicy.MaxDevices != 0 {
		t.Errorf("環境變數未落到正確欄位: %+v", cfg.Security.DevicePolicy)
	}
	if cfg.Security.SessionTTLHours != 12 {
		t.Errorf("其它鍵不應受影響，實際 %d", cfg.Security.SessionTTLHours)
	}
}

// TestDevicePolicyRejectsInvalidCombinations 是兩個鍵的界限：
// 模式限列舉、limited 必須有名額且不超過上界、其它模式不得帶名額。
func TestDevicePolicyRejectsInvalidCombinations(t *testing.T) {
	cases := []struct {
		name string
		set  func(*DevicePolicyConfig)
		want string
	}{
		{"模式不認識", func(d *DevicePolicyConfig) { d.Mode = "one-device-per-week" }, "mode"},
		{"模式大小寫不符", func(d *DevicePolicyConfig) { d.Mode = "Single" }, "mode"},
		{"limited 缺名額", func(d *DevicePolicyConfig) { d.Mode = "limited" }, "max_devices"},
		{"limited 負名額", func(d *DevicePolicyConfig) { d.Mode = "limited"; d.MaxDevices = -1 }, "max_devices"},
		{"limited 零名額", func(d *DevicePolicyConfig) { d.Mode = "limited"; d.MaxDevices = 0 }, "max_devices"},
		{"limited 越界", func(d *DevicePolicyConfig) { d.Mode = "limited"; d.MaxDevices = maxDeviceSlots + 1 }, "max_devices"},
		{"single 帶名額", func(d *DevicePolicyConfig) { d.Mode = "single"; d.MaxDevices = 3 }, "max_devices"},
		{"multi 帶名額", func(d *DevicePolicyConfig) { d.Mode = "multi"; d.MaxDevices = 3 }, "max_devices"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.set(&cfg.Security.DevicePolicy)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "security.device_policy."+tc.want) {
				t.Errorf("應拒絕並指出 security.device_policy.%s，實際: %v", tc.want, err)
			}
		})
	}

	// 合法組合：三種模式各自的正確寫法（含 limited 的上界那一格）。
	for _, d := range []DevicePolicyConfig{
		{Mode: ""},
		{Mode: "multi"},
		{Mode: "single"},
		{Mode: "limited", MaxDevices: 1},
		{Mode: "limited", MaxDevices: maxDeviceSlots},
	} {
		cfg := Default()
		cfg.Security.DevicePolicy = d
		if err := cfg.Validate(); err != nil {
			t.Errorf("合法組合 %+v 不應報錯：%v", d, err)
		}
	}
}

// TestDevicePolicyEmptyModeNormalises 空值（組態檔整段不寫）正規化為預設值，
// 而不是留下一個「讀起來像第三種模式」的空字串。
func TestDevicePolicyEmptyModeNormalises(t *testing.T) {
	cfg := Default()
	cfg.Security.DevicePolicy = DevicePolicyConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("整段缺省應合法：%v", err)
	}
	if cfg.Security.DevicePolicy.Mode != "multi" {
		t.Errorf("空模式應正規化為 multi，實際 %q", cfg.Security.DevicePolicy.Mode)
	}
}

// TestDevicePolicyAppearsInRedactedSummary 啟動摘要要看得見策略：
// 「這臺伺服器現在允許幾臺裝置同時線上」是部署狀態，不是秘密。
func TestDevicePolicyAppearsInRedactedSummary(t *testing.T) {
	cfg := Default()
	cfg.Security.DevicePolicy = DevicePolicyConfig{Mode: "limited", MaxDevices: 3}
	got := cfg.Redacted()
	if !strings.Contains(got, "device_policy=[mode=limited max_devices=3]") {
		t.Errorf("摘要應含裝置策略，實際: %s", got)
	}

	// 沒走過 Validate 的零值（測試直接構造）不能顯示成空白模式。
	zero := Config{}
	if !strings.Contains(zero.Redacted(), "device_policy=[mode=multi max_devices=0]") {
		t.Errorf("零值模式應按預設顯示，實際: %s", zero.Redacted())
	}
}

// TestExampleYAMLCarriesDevicePolicyKeys 內嵌範例與 config.example.yaml 都要帶上兩個鍵：
// 只寫在其中一份，等於另一份的部署者永遠看不到這個開關。
func TestExampleYAMLCarriesDevicePolicyKeys(t *testing.T) {
	for _, key := range []string{"device_policy:", "mode:", "max_devices:"} {
		if !strings.Contains(ExampleYAML, key) {
			t.Errorf("內嵌範例組態缺少 %s", key)
		}
	}
	cfg, err := Load(Options{ConfigPath: writeConfig(t, ExampleYAML)})
	if err != nil {
		t.Fatalf("解析內嵌範例失敗: %v", err)
	}
	if cfg.Security.DevicePolicy != Default().Security.DevicePolicy {
		t.Errorf("內嵌範例的裝置策略與預設值不一致: %+v vs %+v",
			cfg.Security.DevicePolicy, Default().Security.DevicePolicy)
	}
}

// TestDevicePolicyEnvModeMustBeValid 環境變數給的模式同樣要過校驗：
// 「設了一個不認識的模式然後靜默沿用預設」是最難查的那種部署事故。
func TestDevicePolicyEnvModeMustBeValid(t *testing.T) {
	t.Setenv("ER_SECURITY_DEVICE_POLICY_MODE", "everything")
	path := writeConfig(t, "security:\n  session_ttl_hours: 12\n")
	if _, err := Load(Options{ConfigPath: path}); err == nil {
		t.Fatal("不認識的模式應讓啟動失敗")
	} else if !strings.Contains(err.Error(), "security.device_policy.mode") {
		t.Errorf("錯誤應指出鍵名，實際: %v", err)
	}
}
