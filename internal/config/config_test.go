package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kagurazakayashi/EvernightRealm/internal/runlog"
)

// 寫入臨時組態檔並回傳路徑。
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("寫入測試組態失敗: %v", err)
	}
	return p
}

func TestLoadDefaults(t *testing.T) {
	// 組態檔不存在 → 全部使用內建預設值
	cfg, err := Load(Options{ConfigPath: filepath.Join(t.TempDir(), "nope.yaml")})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:5206" {
		t.Errorf("預設 listen 錯誤: %q", cfg.Server.Listen)
	}
	if cfg.Server.DataDir != "evernight-data" {
		t.Errorf("預設 data_dir 錯誤: %q", cfg.Server.DataDir)
	}
	if cfg.Database.BusyTimeoutMS != 5000 {
		t.Errorf("預設 busy_timeout_ms 錯誤: %d", cfg.Database.BusyTimeoutMS)
	}
	if cfg.Security.SessionTTLHours != 24 {
		t.Errorf("預設 session_ttl_hours 錯誤: %d", cfg.Security.SessionTTLHours)
	}
}

func TestLoadYAMLOverrides(t *testing.T) {
	p := writeConfig(t, `
server:
  listen: "0.0.0.0:8090"
  display_timezone: "America/New_York"
database:
  busy_timeout_ms: 3000
logs:
  level: "debug"
`)
	cfg, err := Load(Options{ConfigPath: p})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if cfg.Server.Listen != "0.0.0.0:8090" {
		t.Errorf("listen 覆蓋失敗: %q", cfg.Server.Listen)
	}
	if cfg.Server.DisplayTimezone != "America/New_York" {
		t.Errorf("時區覆蓋失敗: %q", cfg.Server.DisplayTimezone)
	}
	if cfg.Database.BusyTimeoutMS != 3000 {
		t.Errorf("busy_timeout 覆蓋失敗: %d", cfg.Database.BusyTimeoutMS)
	}
	if cfg.Logs.Level != "debug" {
		t.Errorf("日誌層級覆蓋失敗: %q", cfg.Logs.Level)
	}
	// 未覆蓋欄位保持預設
	if cfg.Database.Path != "evernight.db" {
		t.Errorf("未覆蓋欄位應保持預設: %q", cfg.Database.Path)
	}
}

func TestLoadDataDirDotMeansDefault(t *testing.T) {
	p := writeConfig(t, "server:\n  data_dir: \".\"\n")
	cfg, err := Load(Options{ConfigPath: p})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if cfg.Server.DataDir != "evernight-data" {
		t.Errorf("data_dir \".\" 應視為預設: %q", cfg.Server.DataDir)
	}
}

func TestLoadEnvOverridesYAML(t *testing.T) {
	p := writeConfig(t, "server:\n  listen: \"127.0.0.1:5206\"\n")
	t.Setenv("ER_SERVER_LISTEN", "127.0.0.1:9090")
	cfg, err := Load(Options{ConfigPath: p})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:9090" {
		t.Errorf("環境變數應覆蓋 yaml: %q", cfg.Server.Listen)
	}
}

func TestLoadInvalidEnvInt(t *testing.T) {
	t.Setenv("ER_DATABASE_BUSY_TIMEOUT_MS", "abc")
	_, err := Load(Options{ConfigPath: filepath.Join(t.TempDir(), "none.yaml")})
	if err == nil || !strings.Contains(err.Error(), "ER_DATABASE_BUSY_TIMEOUT_MS") {
		t.Errorf("非法環境變數整數應報錯並指出變數名，實際: %v", err)
	}
}

func TestDefaultHTTPProtectionValues(t *testing.T) {
	cfg := Default()
	if cfg.Server.RequestTimeoutMS <= 0 || cfg.Server.ReadHeaderTimeoutMS <= 0 ||
		cfg.Server.ReadTimeoutMS <= 0 || cfg.Server.WriteTimeoutMS <= 0 || cfg.Server.IdleTimeoutMS <= 0 ||
		cfg.Server.ShutdownTimeoutMS <= 0 {
		t.Errorf("HTTP 層逾時預設值應為正數: %+v", cfg.Server)
	}
	if cfg.Server.ShutdownTimeoutMS != 10000 {
		t.Errorf("優雅停止期限預設應為 10000 毫秒，實際 %d", cfg.Server.ShutdownTimeoutMS)
	}
	if cfg.Server.RequestTimeoutMS > cfg.Server.WriteTimeoutMS {
		t.Errorf("預設處理期限不得大於回應寫入期限: request=%d write=%d",
			cfg.Server.RequestTimeoutMS, cfg.Server.WriteTimeoutMS)
	}
	if cfg.Server.MaxBodyBytes != 1<<20 {
		t.Errorf("請求體上限預設應為 1 MiB，實際 %d", cfg.Server.MaxBodyBytes)
	}
}

func TestLoadHTTPProtectionFromYAMLAndEnv(t *testing.T) {
	p := writeConfig(t, "server:\n  request_timeout_ms: 3000\n  shutdown_timeout_ms: 6000\n  max_body_bytes: 2048\n")
	cfg, err := Load(Options{ConfigPath: p})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if cfg.Server.RequestTimeoutMS != 3000 || cfg.Server.MaxBodyBytes != 2048 || cfg.Server.ShutdownTimeoutMS != 6000 {
		t.Errorf("yaml 應覆蓋 HTTP 保護參數: request=%d body=%d shutdown=%d",
			cfg.Server.RequestTimeoutMS, cfg.Server.MaxBodyBytes, cfg.Server.ShutdownTimeoutMS)
	}

	t.Setenv("ER_SERVER_REQUEST_TIMEOUT_MS", "4000")
	t.Setenv("ER_SERVER_MAX_BODY_BYTES", "8192")
	t.Setenv("ER_SERVER_SHUTDOWN_TIMEOUT_MS", "7000")
	cfg, err = Load(Options{ConfigPath: p})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if cfg.Server.RequestTimeoutMS != 4000 || cfg.Server.MaxBodyBytes != 8192 || cfg.Server.ShutdownTimeoutMS != 7000 {
		t.Errorf("環境變數應覆蓋 yaml: request=%d body=%d shutdown=%d",
			cfg.Server.RequestTimeoutMS, cfg.Server.MaxBodyBytes, cfg.Server.ShutdownTimeoutMS)
	}
}

func TestDefaultSecurityHeadersAreEmpty(t *testing.T) {
	// 預設留空即採用 httpapi 套件的內建基線；組態不重複寫死策略，避免兩處漂移。
	h := Default().Security.Headers
	if h.ContentSecurityPolicy != "" || h.FrameOptions != "" ||
		h.ReferrerPolicy != "" || h.PermissionsPolicy != "" {
		t.Errorf("安全回應頭預設應留空（用內建基線），實際 %+v", h)
	}
}

func TestValidateDatabaseGates(t *testing.T) {
	// 預檢模式與寫入把關層級限枚舉值；空值代表採用內建預設。
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"預檢模式非法值", func(c *Config) { c.Database.Preflight = "strict" }, "database.preflight"},
		{"寫入把關層級非法值", func(c *Config) { c.Database.SchemaGuard = "always" }, "database.schema_guard"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("應報錯包含 %q，實際: %v", tc.want, err)
			}
		})
	}

	t.Run("預設值與空值回退", func(t *testing.T) {
		cfg := Default()
		if cfg.Database.Preflight != "header" {
			t.Errorf("預設預檢模式應為 header，實際 %q", cfg.Database.Preflight)
		}
		if cfg.Database.SchemaGuard != "startup" {
			t.Errorf("預設寫入把關層級應為 startup，實際 %q", cfg.Database.SchemaGuard)
		}
		if cfg.Database.IntegrityCheck {
			t.Error("預設不應在啟動時執行完整性自檢")
		}

		cfg.Database.Preflight = ""
		cfg.Database.SchemaGuard = ""
		if err := cfg.Validate(); err != nil {
			t.Fatalf("空值應回退為預設: %v", err)
		}
		if cfg.Database.Preflight != "header" || cfg.Database.SchemaGuard != "startup" {
			t.Errorf("空值應回退為 header/startup，實際 %q/%q", cfg.Database.Preflight, cfg.Database.SchemaGuard)
		}
	})

	t.Run("YAML 可設定三項閘門", func(t *testing.T) {
		p := writeConfig(t, `
database:
  preflight: "readonly"
  integrity_check: true
  schema_guard: "transaction"
`)
		cfg, err := Load(Options{ConfigPath: p})
		if err != nil {
			t.Fatalf("Load 失敗: %v", err)
		}
		if cfg.Database.Preflight != "readonly" || !cfg.Database.IntegrityCheck ||
			cfg.Database.SchemaGuard != "transaction" {
			t.Errorf("資料庫閘門組態未生效: %+v", cfg.Database)
		}
	})
}

func TestValidateTransactionBoundary(t *testing.T) {
	// 交易邊界（STEP-041）：預設值、非法值、空值回退、YAML 與環境變數覆蓋。
	t.Run("預設值", func(t *testing.T) {
		tx := Default().Database.Transaction
		if tx.BeginMode != "immediate" {
			t.Errorf("預設 begin_mode 應為 immediate（失敗點固定於交易開始前），實際 %q", tx.BeginMode)
		}
		if tx.Nested != "reject" {
			t.Errorf("預設 nested 應為 reject，實際 %q", tx.Nested)
		}
		if tx.BusyRetryMax != 0 {
			t.Errorf("預設 busy_retry_max 應為 0（重試會重跑交易，需明確開啟），實際 %d", tx.BusyRetryMax)
		}
		if tx.BusyRetryBackoffMS != 50 {
			t.Errorf("預設 busy_retry_backoff_ms 應為 50，實際 %d", tx.BusyRetryBackoffMS)
		}
		if tx.TimeoutMS != 10000 {
			t.Errorf("預設 timeout_ms 應為 10000，實際 %d", tx.TimeoutMS)
		}
	})

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"BEGIN 模式非法值", func(c *Config) { c.Database.Transaction.BeginMode = "exclusive" },
			"database.transaction.begin_mode"},
		{"嵌套策略非法值", func(c *Config) { c.Database.Transaction.Nested = "merge" },
			"database.transaction.nested"},
		{"重試次數負數", func(c *Config) { c.Database.Transaction.BusyRetryMax = -1 },
			"database.transaction.busy_retry_max"},
		{"退避負數", func(c *Config) { c.Database.Transaction.BusyRetryBackoffMS = -1 },
			"database.transaction.busy_retry_backoff_ms"},
		{"交易期限負數", func(c *Config) { c.Database.Transaction.TimeoutMS = -1 },
			"database.transaction.timeout_ms"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("應報錯包含 %q，實際: %v", tc.want, err)
			}
		})
	}

	t.Run("空值回退與零值允許", func(t *testing.T) {
		cfg := Default()
		cfg.Database.Transaction = TransactionConfig{}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("空值應回退為預設: %v", err)
		}
		if cfg.Database.Transaction.BeginMode != "immediate" || cfg.Database.Transaction.Nested != "reject" {
			t.Errorf("空值應回退為 immediate/reject，實際 %+v", cfg.Database.Transaction)
		}
		// timeout_ms=0 表示不限制、busy_retry_backoff_ms=0 表示立即重試，皆為合法設定。
		cfg.Database.Transaction.TimeoutMS = 0
		cfg.Database.Transaction.BusyRetryBackoffMS = 0
		if err := cfg.Validate(); err != nil {
			t.Errorf("0 應被接受（不限制／立即重試）: %v", err)
		}
	})

	t.Run("YAML 與環境變數覆蓋", func(t *testing.T) {
		p := writeConfig(t, `
database:
  transaction:
    begin_mode: "deferred"
    nested: "savepoint"
    busy_retry_max: 3
    busy_retry_backoff_ms: 25
    timeout_ms: 2000
`)
		cfg, err := Load(Options{ConfigPath: p})
		if err != nil {
			t.Fatalf("Load 失敗: %v", err)
		}
		tx := cfg.Database.Transaction
		if tx.BeginMode != "deferred" || tx.Nested != "savepoint" || tx.BusyRetryMax != 3 ||
			tx.BusyRetryBackoffMS != 25 || tx.TimeoutMS != 2000 {
			t.Fatalf("YAML 覆蓋失敗: %+v", tx)
		}

		t.Setenv("ER_DATABASE_TRANSACTION_BEGIN_MODE", "immediate")
		t.Setenv("ER_DATABASE_TRANSACTION_NESTED", "reuse")
		t.Setenv("ER_DATABASE_TRANSACTION_BUSY_RETRY_MAX", "5")
		t.Setenv("ER_DATABASE_TRANSACTION_TIMEOUT_MS", "1500")
		cfg, err = Load(Options{ConfigPath: p})
		if err != nil {
			t.Fatalf("Load 失敗: %v", err)
		}
		tx = cfg.Database.Transaction
		if tx.BeginMode != "immediate" || tx.Nested != "reuse" || tx.BusyRetryMax != 5 || tx.TimeoutMS != 1500 {
			t.Fatalf("環境變數覆蓋失敗: %+v", tx)
		}
		if tx.BusyRetryBackoffMS != 25 {
			t.Errorf("未以環境變數覆蓋的欄位應保留 YAML 值，實際 %d", tx.BusyRetryBackoffMS)
		}
	})
}

func TestRedactedIncludesTransactionSummary(t *testing.T) {
	// 啟動摘要需可見交易邊界設定（不含機密），供運維核對實際生效值。
	summary := Default().Redacted()
	for _, want := range []string{"immediate", "reject", "10000", "schema_guard=startup"} {
		if !strings.Contains(summary, want) {
			t.Errorf("脫敏摘要應含交易設定 %q，實際: %s", want, summary)
		}
	}
}

func TestValidateSecurityHeaders(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"Frame 限制非法值", func(c *Config) { c.Security.Headers.FrameOptions = "ALLOWALL" }, "frame_options"},
		{"CSP 缺少必要指令", func(c *Config) { c.Security.Headers.ContentSecurityPolicy = "img-src 'self'" }, "default-src"},
		{"CSP 含 unsafe-eval", func(c *Config) {
			c.Security.Headers.ContentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-eval'"
		}, "'unsafe-eval'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("應報錯包含 %q，實際: %v", tc.want, err)
			}
		})
	}

	t.Run("合法覆寫與正規化", func(t *testing.T) {
		cfg := Default()
		cfg.Security.Headers.FrameOptions = " sameorigin "
		cfg.Security.Headers.ContentSecurityPolicy = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("合法安全頭組態不應報錯: %v", err)
		}
		if cfg.Security.Headers.FrameOptions != "SAMEORIGIN" {
			t.Errorf("frame_options 應正規化為大寫，實際 %q", cfg.Security.Headers.FrameOptions)
		}
	})
}

func TestLoadSecurityHeadersFromYAMLAndEnv(t *testing.T) {
	p := writeConfig(t, "security:\n  headers:\n    frame_options: DENY\n    referrer_policy: no-referrer\n")
	cfg, err := Load(Options{ConfigPath: p})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if cfg.Security.Headers.FrameOptions != "DENY" || cfg.Security.Headers.ReferrerPolicy != "no-referrer" {
		t.Errorf("yaml 應載入安全回應頭: %+v", cfg.Security.Headers)
	}

	t.Setenv("ER_SECURITY_HEADERS_PERMISSIONS_POLICY", "camera=(self)")
	t.Setenv("ER_SECURITY_HEADERS_FRAME_OPTIONS", "sameorigin")
	cfg, err = Load(Options{ConfigPath: p})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if cfg.Security.Headers.PermissionsPolicy != "camera=(self)" {
		t.Errorf("環境變數應覆蓋權限策略，實際 %q", cfg.Security.Headers.PermissionsPolicy)
	}
	if cfg.Security.Headers.FrameOptions != "SAMEORIGIN" {
		t.Errorf("環境變數值應同樣正規化，實際 %q", cfg.Security.Headers.FrameOptions)
	}
}

func TestValidateHTTPProtection(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"處理期限非正數", func(c *Config) { c.Server.RequestTimeoutMS = 0 }, "server.request_timeout_ms"},
		{"標頭期限非正數", func(c *Config) { c.Server.ReadHeaderTimeoutMS = -1 }, "server.read_header_timeout_ms"},
		{"讀取期限非正數", func(c *Config) { c.Server.ReadTimeoutMS = 0 }, "server.read_timeout_ms"},
		{"寫入期限非正數", func(c *Config) { c.Server.WriteTimeoutMS = 0 }, "server.write_timeout_ms"},
		{"空閒期限非正數", func(c *Config) { c.Server.IdleTimeoutMS = 0 }, "server.idle_timeout_ms"},
		{"停止期限非正數", func(c *Config) { c.Server.ShutdownTimeoutMS = 0 }, "server.shutdown_timeout_ms"},
		{"處理期限長於寫入期限", func(c *Config) { c.Server.RequestTimeoutMS = 60000 }, "不得大於 server.write_timeout_ms"},
		{"請求體上限過小", func(c *Config) { c.Server.MaxBodyBytes = 16 }, "server.max_body_bytes"},
		{"請求體上限過大", func(c *Config) { c.Server.MaxBodyBytes = 1 << 30 }, "server.max_body_bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("應報錯包含 %q，實際: %v", tc.want, err)
			}
		})
	}
}

func TestValidateBadListen(t *testing.T) {
	cases := []struct {
		listen string
		want   string
	}{
		{"", "server.listen 不可為空"},
		{"localhost", "格式無效"},
		{":5206", "缺少主機"},
		{"127.0.0.1:99999", "連接埠無效"},
		{"127.0.0.1:0", "連接埠無效"},
	}
	for _, tc := range cases {
		cfg := Default()
		cfg.Server.Listen = tc.listen
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("listen=%q 應報錯包含 %q，實際: %v", tc.listen, tc.want, err)
		}
	}
}

func TestValidateBadTimezone(t *testing.T) {
	cfg := Default()
	cfg.Server.DisplayTimezone = "Not/AZone"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "display_timezone") {
		t.Errorf("非法時區應指出 display_timezone，實際: %v", err)
	}
}

// TestDisplayLocation 驗證顯示時區的解析與「當刻」偏移：偏移必須隨該時刻的日光節約
// 狀態改變，否則下發給客戶端的偏移會在半年內把顯示時間錯開一小時。
func TestDisplayLocation(t *testing.T) {
	january := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	july := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name       string
		timezone   string
		at         time.Time
		wantOffset int
	}{
		{"無 daylight saving 的亞洲時區", "Asia/Shanghai", january, 8 * 3600},
		{"同一時區全年偏移相同", "Asia/Shanghai", july, 8 * 3600},
		{"紐約冬季 -05:00", "America/New_York", january, -5 * 3600},
		{"紐約夏季 -04:00（日光節約）", "America/New_York", july, -4 * 3600},
		{"UTC", "UTC", january, 0},
		{"空白名稱視為 UTC", "", january, 0},
		{"非法名稱回退 UTC", "Not/AZone", january, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.DisplayTimezone = tc.timezone

			_, offset := tc.at.In(cfg.DisplayLocation()).Zone()
			if offset != tc.wantOffset {
				t.Errorf("時區 %q 在 %v 的偏移應為 %d 秒，實際 %d 秒", tc.timezone, tc.at, tc.wantOffset, offset)
			}
		})
	}

	// 零值組態（未經 Default）也不得回傳 nil，否則呼叫端換算偏移時會 panic。
	var zero Config
	if loc := zero.DisplayLocation(); loc == nil {
		t.Fatal("零值組態的顯示時區不得為 nil")
	}
}

func TestValidateBadBusyTimeout(t *testing.T) {
	cfg := Default()
	cfg.Database.BusyTimeoutMS = 0
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "busy_timeout_ms") {
		t.Errorf("busy_timeout_ms=0 應報錯指出欄位，實際: %v", err)
	}
}

func TestValidateBadLogLevel(t *testing.T) {
	cfg := Default()
	cfg.Logs.Level = "verbose"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "logs.level") {
		t.Errorf("非法日誌層級應指出 logs.level，實際: %v", err)
	}
}

func TestValidateBadSessionTTL(t *testing.T) {
	cfg := Default()
	cfg.Security.SessionTTLHours = 0
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "session_ttl_hours") {
		t.Errorf("session_ttl_hours=0 應報錯指出欄位，實際: %v", err)
	}
}

func TestValidateRootPasswordHash(t *testing.T) {
	cfg := Default()
	cfg.Security.RootPasswordHash = "plaintext-secret"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "root_password_hash") {
		t.Errorf("非 Argon2id 雜湊應報錯指出欄位，實際: %v", err)
	}

	cfg.Security.RootPasswordHash = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$hashvalue"
	if err := cfg.Validate(); err != nil {
		t.Errorf("合法 Argon2id 雜湊不應報錯: %v", err)
	}
}

func TestRedactedNeverLeaksSecret(t *testing.T) {
	secret := "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$topsecret-hash"
	cfg := Default()
	cfg.Security.RootPasswordHash = secret
	out := cfg.Redacted()
	if strings.Contains(out, secret) || strings.Contains(out, "topsecret") {
		t.Errorf("Redacted 不得洩漏機密明文: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("Redacted 應顯示 [REDACTED] 標記: %s", out)
	}
}

func TestListenAllInterfaces(t *testing.T) {
	cfg := Default()
	cfg.Server.Listen = "0.0.0.0:5206"
	if !cfg.ListenAllInterfaces() {
		t.Error("0.0.0.0 應判定為暴露所有介面")
	}
	cfg.Server.Listen = "127.0.0.1:5206"
	if cfg.ListenAllInterfaces() {
		t.Error("127.0.0.1 不應判定為暴露所有介面")
	}
}

func TestResolvePathsWithSpacesAndNonASCII(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "活動 資料 目录")
	cfg := Default()
	cfg.Server.DataDir = dir
	if err := cfg.Resolve(); err != nil {
		t.Fatalf("Resolve 失敗（空格/非 ASCII 路徑）: %v", err)
	}
	if !filepath.IsAbs(cfg.Database.Path) {
		t.Errorf("database.path 應解析為絕對路徑: %q", cfg.Database.Path)
	}
	if !strings.Contains(cfg.Database.Path, dir) {
		t.Errorf("database.path 應位於資料目錄內: %q", cfg.Database.Path)
	}
	if cfg.Media != filepath.Join(dir, "media") {
		t.Errorf("media 解析錯誤: %q", cfg.Media)
	}
}

func TestResolveKeepsAbsolutePaths(t *testing.T) {
	cfg := Default()
	cfg.Server.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.Database.Path = "D:/external/evernight.db"
	cfg.Media = "/opt/media"
	if err := cfg.Resolve(); err != nil {
		t.Fatalf("Resolve 失敗: %v", err)
	}
	if !filepath.IsAbs(cfg.Database.Path) || !filepath.IsAbs(cfg.Media) {
		t.Error("絕對路徑應原樣保留")
	}
}

func TestResolveRejectsTraversal(t *testing.T) {
	cfg := Default()
	cfg.Server.DataDir = t.TempDir()
	cfg.Media = "../../../escape"
	err := cfg.Resolve()
	if err == nil || !strings.Contains(err.Error(), "路徑穿越拒絕") {
		t.Errorf("相對路徑穿越應被拒絕，實際: %v", err)
	}
}

func TestPrepareCreatesDirsAndExampleConfig(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evernight-data 測試")
	cfg := Default()
	cfg.Server.DataDir = dir
	if err := cfg.Resolve(); err != nil {
		t.Fatalf("Resolve 失敗: %v", err)
	}
	if err := cfg.Prepare(); err != nil {
		t.Fatalf("Prepare 失敗: %v", err)
	}
	for _, d := range []string{cfg.Media, cfg.Documents, cfg.Attachments, cfg.Backups, cfg.Logs.Dir} {
		fi, err := os.Stat(d)
		if err != nil || !fi.IsDir() {
			t.Errorf("子目錄未建立: %s (%v)", d, err)
		}
	}
	configPath := filepath.Join(dir, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("範例組態未建立: %v", err)
	}
	if !strings.Contains(string(data), "listen") {
		t.Error("範例組態內容不完整")
	}

	// 冪等：重複 Prepare 不報錯、不覆蓋已修改的組態
	modified := []byte("# 使用者修改\nserver:\n  listen: \"127.0.0.1:9999\"\n")
	if err := os.WriteFile(configPath, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Prepare(); err != nil {
		t.Fatalf("重複 Prepare 應冪等: %v", err)
	}
	after, _ := os.ReadFile(configPath)
	if string(after) != string(modified) {
		t.Error("重複 Prepare 不應覆蓋使用者組態")
	}
}

func TestParseArgs(t *testing.T) {
	opts, err := ParseArgs([]string{"--data-dir", "D:/my data/er"})
	if err != nil || opts.DataDir != "D:/my data/er" {
		t.Errorf("--data-dir 解析失敗: opts=%+v err=%v", opts, err)
	}
	if _, err := ParseArgs([]string{"--nope"}); err == nil {
		t.Error("未知參數應報錯")
	}
	if _, err := ParseArgs([]string{"extra"}); err == nil {
		t.Error("位置參數應報錯")
	}
}

func TestLoadCommandLineOverridesYAML(t *testing.T) {
	p := writeConfig(t, "server:\n  data_dir: \"yaml-dir\"\n")
	cfg, err := Load(Options{ConfigPath: p, DataDir: "cli-dir"})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if cfg.Server.DataDir != "cli-dir" {
		t.Errorf("命令列 --data-dir 應優先於 yaml: %q", cfg.Server.DataDir)
	}
}

// --- 跨域（CORS）組態 ---

func TestCORSDefaultsAreClosed(t *testing.T) {
	cfg, err := Load(Options{ConfigPath: filepath.Join(t.TempDir(), "nope.yaml")})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if len(cfg.Security.CORS.AllowedOrigins) != 0 {
		t.Errorf("跨域預設必須完全關閉，實際 %v", cfg.Security.CORS.AllowedOrigins)
	}
	if cfg.Security.CORS.MaxAgeSeconds != 600 {
		t.Errorf("預設 max_age_seconds 應為 600，實際 %d", cfg.Security.CORS.MaxAgeSeconds)
	}
	// 方法與標頭清單即使沒開啟也預先備好：日後只放來源一項就能用。
	if !contains(cfg.Security.CORS.AllowedMethods, "OPTIONS") {
		t.Errorf("預設方法清單應含 OPTIONS，實際 %v", cfg.Security.CORS.AllowedMethods)
	}
	if !contains(cfg.Security.CORS.AllowedHeaders, "Idempotency-Key") {
		t.Errorf("預設標頭清單應含 Idempotency-Key（後續寫請求需要），實際 %v", cfg.Security.CORS.AllowedHeaders)
	}
	if !contains(cfg.Security.CORS.ExposedHeaders, "X-Request-Id") {
		t.Errorf("預設暴露清單應含 X-Request-Id，實際 %v", cfg.Security.CORS.ExposedHeaders)
	}
	if cfg.CORSNotice() != "" {
		t.Errorf("未開啟時不應有跨域提示，實際 %q", cfg.CORSNotice())
	}
	if !strings.Contains(cfg.Redacted(), "cors=[關閉]") {
		t.Errorf("啟動摘要應標示跨域關閉，實際 %s", cfg.Redacted())
	}
}

func TestCORSFromYAMLOriginIsNormalized(t *testing.T) {
	p := writeConfig(t, "security:\n  cors:\n    allowed_origins:\n      - HTTP://Page.Example:8765/\n    allow_credentials: true\n    max_age_seconds: 30\n")
	cfg, err := Load(Options{ConfigPath: p})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if got := cfg.Security.CORS.AllowedOrigins; len(got) != 1 || got[0] != "http://page.example:8765" {
		t.Errorf("來源應正規化為小寫並去掉尾端斜線，實際 %v", got)
	}
	if !cfg.Security.CORS.AllowCredentials || cfg.Security.CORS.MaxAgeSeconds != 30 {
		t.Errorf("憑據與快取時間未如載入: %+v", cfg.Security.CORS)
	}
	notice := cfg.CORSNotice()
	if !strings.Contains(notice, "http://page.example:8765") {
		t.Errorf("啟動提示必須列出被放寬的來源，實際 %q", notice)
	}
	if !strings.Contains(cfg.Redacted(), "cors=[origins=http://page.example:8765") {
		t.Errorf("摘要應含跨域狀態，實際 %s", cfg.Redacted())
	}
}

func TestCORSAllowedOriginsFromEnv(t *testing.T) {
	t.Setenv("ER_SECURITY_CORS_ALLOWED_ORIGINS", " http://127.0.0.1:8765 , http://localhost:8766 ,,")
	cfg, err := Load(Options{ConfigPath: filepath.Join(t.TempDir(), "nope.yaml")})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	want := []string{"http://127.0.0.1:8765", "http://localhost:8766"}
	got := cfg.Security.CORS.AllowedOrigins
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("環境變數應解析為精確來源清單（去空白、跳過空項），實際 %v", got)
	}
}

func TestValidateCORSRejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"來源帶路徑", func(c *Config) {
			c.Security.CORS.AllowedOrigins = []string{"http://127.0.0.1:5206/admin"}
		}, "不得帶路徑"},
		{"來源帶查詢", func(c *Config) {
			c.Security.CORS.AllowedOrigins = []string{"http://127.0.0.1:5206?a=1"}
		}, "不得帶查詢"},
		{"來源帶認證資訊", func(c *Config) {
			c.Security.CORS.AllowedOrigins = []string{"http://root:pw@127.0.0.1"}
		}, "不得帶"},
		{"來源不是絕對位址", func(c *Config) {
			c.Security.CORS.AllowedOrigins = []string{"127.0.0.1:5206"}
		}, "scheme://host"},
		{"萬用子網域", func(c *Config) {
			c.Security.CORS.AllowedOrigins = []string{"http://*.example"}
		}, "不支援萬用子網域"},
		{"來源含換行（回應分割注入）", func(c *Config) {
			c.Security.CORS.AllowedOrigins = []string{"http://127.0.0.1\r\nX-Forged: 1"}
		}, "控制字元"},
		{"萬用來源加憑據", func(c *Config) {
			c.Security.CORS.AllowedOrigins = []string{"*"}
			c.Security.CORS.AllowCredentials = true
		}, "allow_credentials"},
		{"方法名含非法字元", func(c *Config) {
			c.Security.CORS.AllowedOrigins = []string{"http://127.0.0.1:5206"}
			c.Security.CORS.AllowedMethods = []string{"GET POST"}
		}, "非法方法名"},
		{"標頭名含分隔字元", func(c *Config) {
			c.Security.CORS.AllowedOrigins = []string{"http://127.0.0.1:5206"}
			c.Security.CORS.AllowedHeaders = []string{"X-A;B"}
		}, "非法標頭名"},
		{"快取時間過大", func(c *Config) {
			c.Security.CORS.AllowedOrigins = []string{"http://127.0.0.1:5206"}
			c.Security.CORS.MaxAgeSeconds = 999999
		}, "max_age_seconds"},
		{"快取時間為負", func(c *Config) {
			c.Security.CORS.AllowedOrigins = []string{"http://127.0.0.1:5206"}
			c.Security.CORS.MaxAgeSeconds = -1
		}, "max_age_seconds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("%s 應被拒絕", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("錯誤訊息應含 %q，實際 %q", tc.want, err.Error())
			}
			if !strings.HasPrefix(err.Error(), "config:") {
				t.Errorf("組態錯誤應統一帶 config: 前綴，實際 %q", err.Error())
			}
		})
	}
}

func TestValidateCORSSingleWildcardIsAllowed(t *testing.T) {
	// `*` 是明確選擇而非誤寫，因此允许，但不得與憑據同用（已由上一組測試把關）。
	cfg := Default()
	cfg.Security.CORS.AllowedOrigins = []string{"*"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("單獨使用 * 應可通過: %v", err)
	}
	if notice := cfg.CORSNotice(); !strings.Contains(notice, "全面開放") {
		t.Errorf("* 必須在啟動提示裡被點名，實際 %q", notice)
	}
}

// contains 回傳清單是否含指定值（測試用的小工具）。
func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// TestLogsLevelAgreesWithRunlog 固定「組態接受的層級」與「記錄層接受的層級」是同一份清單。
//
// 兩處各寫一份清單時，漏更新的那一份不會讓建置失敗——只會讓某個層級在啟動時被接受、
// 在開日誌時被拒絕（或反過來），部署者要等到執行檔起不來才知道。
func TestLogsLevelAgreesWithRunlog(t *testing.T) {
	for _, name := range []string{"debug", "info", "warn", "error"} {
		cfg := Default()
		cfg.Logs.Level = name
		if err := cfg.Validate(); err != nil {
			t.Errorf("config 應接受層級 %q：%v", name, err)
		}
		if _, err := runlog.ParseLevel(name); err != nil {
			t.Errorf("runlog 應接受層級 %q（config 已接受）：%v", name, err)
		}
	}
	for _, name := range []string{"", "verbose", "trace", "DEBUG", "info "} {
		cfg := Default()
		cfg.Logs.Level = name
		cfgErr := cfg.Validate()
		_, runlogErr := runlog.ParseLevel(name)
		if cfgErr == nil && runlogErr != nil {
			t.Errorf("config 接受了 %q 但 runlog 拒絕：%v", name, runlogErr)
		}
		if cfgErr != nil && runlogErr == nil {
			t.Errorf("runlog 接受了 %q 但 config 拒絕：%v", name, cfgErr)
		}
	}
}

// TestLogsRotationDefaults 固定日誌分檔與保留的內建值。
//
// retention_days 的預設是「不限制」，這是刻意的取向而不是遗漏：
// 活動進行中自動刪掉日誌，等於在最需要線索的時候把線索清了。
func TestLogsRotationDefaults(t *testing.T) {
	cfg := Default()
	if cfg.Logs.FilePrefix != "evernight-run" {
		t.Errorf("預設前綴 = %q", cfg.Logs.FilePrefix)
	}
	if cfg.Logs.RetentionDays != 0 {
		t.Errorf("預設保留天數 = %d，want 0（不限制）", cfg.Logs.RetentionDays)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("預設組態應通過校驗：%v", err)
	}
}

func TestLogsFilePrefixValidation(t *testing.T) {
	accepted := []struct{ in, want string }{
		{"moe.yashi.run", "moe.yashi.run"}, // 含點合法：清理規則認得帶點前綴
		{"  evernight-run  ", "evernight-run"},
		{"", "evernight-run"}, // 留空回填內建預設
	}
	for _, tc := range accepted {
		cfg := Default()
		cfg.Logs.FilePrefix = tc.in
		if err := cfg.Validate(); err != nil {
			t.Errorf("前綴 %q 應被接受：%v", tc.in, err)
			continue
		}
		if cfg.Logs.FilePrefix != tc.want {
			t.Errorf("前綴 %q 正規化後 = %q，want %q", tc.in, cfg.Logs.FilePrefix, tc.want)
		}
	}

	rejected := []string{
		"a/b",
		"a" + string(rune(0x5C)) + "b", // 反斜線以碼位寫：原始碼裡的跳脫最容易被工具吃掉一層
		"..",
		".",
		"run:1",
		"run*1",
		`run"1`,
		"run<1",
		"run|1",
		"run\n1",
		strings.Repeat("r", 65),
	}
	for _, prefix := range rejected {
		cfg := Default()
		cfg.Logs.FilePrefix = prefix
		if err := cfg.Validate(); err == nil {
			t.Errorf("前綴 %q 應被拒絕（它會被直接拼成檔案名）", prefix)
		}
	}
}

func TestLogsRetentionDaysValidation(t *testing.T) {
	for _, days := range []int{0, 1, 7, 3650} {
		cfg := Default()
		cfg.Logs.RetentionDays = days
		if err := cfg.Validate(); err != nil {
			t.Errorf("保留 %d 天應被接受：%v", days, err)
		}
	}
	for _, days := range []int{-1, 3651, 100000} {
		cfg := Default()
		cfg.Logs.RetentionDays = days
		if err := cfg.Validate(); err == nil {
			t.Errorf("保留 %d 天應被拒絕", days)
		}
	}
}

// TestLogsEnvOverrides 驗證兩個新鍵都能由環境變數給定（開發與排錯時不改檔）。
func TestLogsEnvOverrides(t *testing.T) {
	t.Setenv("ER_LOGS_FILE_PREFIX", "er-prefix")
	t.Setenv("ER_LOGS_RETENTION_DAYS", "14")
	cfg, err := Load(Options{DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Load 失敗：%v", err)
	}
	if cfg.Logs.FilePrefix != "er-prefix" {
		t.Errorf("ER_LOGS_FILE_PREFIX 未生效：%q", cfg.Logs.FilePrefix)
	}
	if cfg.Logs.RetentionDays != 14 {
		t.Errorf("ER_LOGS_RETENTION_DAYS 未生效：%d", cfg.Logs.RetentionDays)
	}
	// 摘要裡要看得見這兩個值：分檔與保留是部署狀態，不是實作細節。
	summary := cfg.Redacted()
	if !strings.Contains(summary, "logs_prefix=er-prefix") || !strings.Contains(summary, "logs_retention_days=14") {
		t.Errorf("Redacted() 摘要缺少日誌分檔資訊：%s", summary)
	}

	t.Setenv("ER_LOGS_RETENTION_DAYS", "abc")
	if _, err := Load(Options{DataDir: t.TempDir()}); err == nil {
		t.Error("ER_LOGS_RETENTION_DAYS 非整數時應啟動失敗")
	}
}

// TestExampleYAMLDocumentsLogKeys 確保範例組態把日誌的四個鍵都寫出來。
//
// 少了任何一個，部署者就只會看到「dir 與 level」，
// 而「保留不限制」這件事必須在檔案裡寫明白，否則没人知道日誌會一直長。
func TestExampleYAMLDocumentsLogKeys(t *testing.T) {
	for _, want := range []string{"logs:", "dir:", "level:", "file_prefix:", "retention_days:"} {
		if !strings.Contains(ExampleYAML, want) {
			t.Errorf("ExampleYAML 缺少 %q", want)
		}
	}
	if !strings.Contains(ExampleYAML, "不限制") {
		t.Error("ExampleYAML 應說明 retention_days=0 的含義")
	}
	// 範例組態自己必須解得開：同一個鍵寫兩次時，YAML 解析器會在「第一次啟動生成的
	// config.yaml 被讀回來」時才報錯——那已經是用戶的執行目錄，不是這支測試。
	var fromExample Config
	if err := yaml.Unmarshal([]byte(ExampleYAML), &fromExample); err != nil {
		t.Fatalf("ExampleYAML 解析失敗（是否有重複鍵）：%v", err)
	}
	if fromExample.Logs.FilePrefix != Default().Logs.FilePrefix ||
		fromExample.Logs.RetentionDays != Default().Logs.RetentionDays {
		t.Errorf("ExampleYAML 的日誌鍵與內建預設不同：%+v", fromExample.Logs)
	}
	if fromExample.Server.Listen != Default().Server.Listen {
		t.Errorf("ExampleYAML 的監聽地址與內建預設不同：%q", fromExample.Server.Listen)
	}
}
