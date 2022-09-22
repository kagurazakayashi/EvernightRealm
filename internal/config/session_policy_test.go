package config

import (
	"strings"
	"testing"
	"time"
)

// TestSessionPolicyDefaultsAreApprovedValues 釘住本步批准的預設量級：
// 閒置關閉、寫入節流 5 分鐘、清理每 30 分鐘一回合、失效後保留 7 天。
//
// 閒置留 0 是這裡唯一需要解釋的一項：在「活動永不延長絕對期限」的語意下，
// 任何不小於 session_ttl_hours 的閒置值都被絕對期限完全蓋住（等於沒作用），
// 而小於它的值等於是「多久沒動就必須重新登入」這個尚未批准的產品決定。
func TestSessionPolicyDefaultsAreApprovedValues(t *testing.T) {
	s := Default().Security
	if s.SessionTTLHours != 24 {
		t.Errorf("session_ttl_hours 預設應為 24，實際 %d", s.SessionTTLHours)
	}
	if s.SessionIdleHours != 0 {
		t.Errorf("session_idle_hours 預設應為 0（不啟用），實際 %d", s.SessionIdleHours)
	}
	if s.SessionTouchMinutes != 5 {
		t.Errorf("session_touch_minutes 預設應為 5，實際 %d", s.SessionTouchMinutes)
	}
	if s.SessionCleanupMinutes != 30 {
		t.Errorf("session_cleanup_minutes 預設應為 30，實際 %d", s.SessionCleanupMinutes)
	}
	if s.SessionCleanupGraceHours != 168 {
		t.Errorf("session_cleanup_grace_hours 預設應為 168，實際 %d", s.SessionCleanupGraceHours)
	}
}

// TestSessionPolicyYAMLAndEnvOverride 確認四個新鍵都能按既有分層順序被覆蓋：
// 預設 → yaml → 環境變數，且單欄覆蓋不牽動其他欄。
func TestSessionPolicyYAMLAndEnvOverride(t *testing.T) {
	path := writeConfig(t, "security:\n  session_idle_hours: 6\n  session_touch_minutes: 0\n")
	cfg, err := Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	s := cfg.Security
	if s.SessionIdleHours != 6 || s.SessionTouchMinutes != 0 {
		t.Errorf("yaml 覆蓋未生效: %+v", s)
	}
	if s.SessionCleanupMinutes != 30 || s.SessionCleanupGraceHours != 168 {
		t.Errorf("單欄覆蓋不應牽動其他欄，實際: %+v", s)
	}

	t.Setenv("ER_SECURITY_SESSION_CLEANUP_MINUTES", "1")
	t.Setenv("ER_SECURITY_SESSION_CLEANUP_GRACE_HOURS", "24")
	cfg, err = Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("帶環境變數的 Load 失敗: %v", err)
	}
	if cfg.Security.SessionCleanupMinutes != 1 || cfg.Security.SessionCleanupGraceHours != 24 {
		t.Errorf("環境變數應覆蓋 yaml 欄位，實際: %+v", cfg.Security)
	}
	if cfg.Security.SessionIdleHours != 6 {
		t.Errorf("環境變數不應抹去 yaml 已設的閒置值，實際 %d", cfg.Security.SessionIdleHours)
	}
}

// TestSessionPolicyRejectsOutOfRange 是四個新鍵的邊界：0 各有明確含義，負值與越界一律拒絕。
func TestSessionPolicyRejectsOutOfRange(t *testing.T) {
	cases := []struct {
		name string
		set  func(*SecurityConfig)
		want string
	}{
		{"閒置為負", func(s *SecurityConfig) { s.SessionIdleHours = -1 }, "session_idle_hours"},
		{"閒置越界", func(s *SecurityConfig) { s.SessionIdleHours = maxSessionIdleHours + 1 }, "session_idle_hours"},
		{"節流為負", func(s *SecurityConfig) { s.SessionTouchMinutes = -1 }, "session_touch_minutes"},
		{"節流越界", func(s *SecurityConfig) { s.SessionTouchMinutes = maxSessionTouchMinutes + 1 }, "session_touch_minutes"},
		{"清理週期為負", func(s *SecurityConfig) { s.SessionCleanupMinutes = -1 }, "session_cleanup_minutes"},
		{"清理週期越界", func(s *SecurityConfig) { s.SessionCleanupMinutes = maxSessionCleanupMinutes + 1 }, "session_cleanup_minutes"},
		{"寬限期為負", func(s *SecurityConfig) { s.SessionCleanupGraceHours = -1 }, "session_cleanup_grace_hours"},
		{"寬限期越界", func(s *SecurityConfig) { s.SessionCleanupGraceHours = maxSessionIdleHours + 1 }, "session_cleanup_grace_hours"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.set(&cfg.Security)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "security."+tc.want) {
				t.Errorf("應拒絕並指出 security.%s，實際: %v", tc.want, err)
			}
		})
	}
	// 三個 0 的組合合法：關閉閒置、每次驗證都寫、不起背景清理。
	cfg := Default()
	cfg.Security.SessionIdleHours = 0
	cfg.Security.SessionTouchMinutes = 0
	cfg.Security.SessionCleanupMinutes = 0
	if err := cfg.Validate(); err != nil {
		t.Errorf("全 0 組合應合法: %v", err)
	}
}

// TestSessionIdleNoticeWhenNeverBinds 確認「閒置比絕對期限還長」不會被偽裝成正常配置：
// 這種組合下閒置截止永遠被絕對期限蓋住，實際生效的只有絕對期限。
//
// 判定標準是提醒而不是拒絕——它不影響任何功能，但部署者大概不是這個意思。
func TestSessionIdleNoticeWhenNeverBinds(t *testing.T) {
	cfg := Default()
	cfg.Security.SessionTTLHours = 24
	cfg.Security.SessionIdleHours = 48
	if err := cfg.Validate(); err != nil {
		t.Fatalf("合法組合不應報錯: %v", err)
	}
	if cfg.SessionIdleNotice == "" {
		t.Error("閒置大於絕對期限時應留下提醒")
	}
	if !strings.Contains(cfg.Redacted(), "閒置判定未生效") {
		t.Errorf("提醒應進啟動摘要，實際: %s", cfg.Redacted())
	}

	// 相等那一格同樣完全不生效：last_active_at 不早於 created_at，所以
	// 「活動 + 閒置」恆不早於「建立 + 絕對期限」，封頂後就是絕對到期時刻本身。
	same := Default()
	same.Security.SessionIdleHours = same.Security.SessionTTLHours
	if err := same.Validate(); err != nil {
		t.Fatalf("合法組合不應報錯: %v", err)
	}
	if same.SessionIdleNotice == "" {
		t.Error("閒置等於絕對期限時同樣應留下提醒（這一格也不會生效）")
	}

	// 閒置小於絕對期限：判定會真的生效，不該有提醒。
	cfg = Default()
	cfg.Security.SessionIdleHours = 6
	if err := cfg.Validate(); err != nil {
		t.Fatalf("合法組合不應報錯: %v", err)
	}
	if cfg.SessionIdleNotice != "" {
		t.Errorf("閒置判定會生效時不應提醒，實際: %s", cfg.SessionIdleNotice)
	}

	// 預設為關閉（0）同樣不該提醒：那是明確決定，不是配錯。
	base := Default()
	if err := base.Validate(); err != nil {
		t.Fatalf("預設組態應合法: %v", err)
	}
	if base.SessionIdleNotice != "" {
		t.Errorf("預設（閒置關閉）不應提醒，實際: %s", base.SessionIdleNotice)
	}
	if base.Security.SessionIdleHours > base.Security.SessionTTLHours {
		t.Error("預設閒置值不應大於預設絕對期限")
	}
}

// TestSessionPolicyAppearsInRedactedSummary 確認四個新鍵進了脫敏摘要：
// 運維看一行啟動日誌就該知道自己配的會話壽命與清理節奏是什麼。
func TestSessionPolicyAppearsInRedactedSummary(t *testing.T) {
	cfg := Default()
	cfg.Security.SessionIdleHours = 8
	cfg.Security.SessionTouchMinutes = 2
	cfg.Security.SessionCleanupMinutes = 45
	cfg.Security.SessionCleanupGraceHours = 12
	got := cfg.Redacted()
	for _, want := range []string{
		"session_idle_hours=8",
		"session_touch_minutes=2",
		"session_cleanup=[minutes=45 grace_hours=12]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("摘要缺少 %q，實際: %s", want, got)
		}
	}
}

// TestExampleYAMLCarriesSessionPolicyKeys 把「首次啟動自動寫出的那份配置」與預設值釘在一起：
// 新鍵只寫在 config.example.yaml 而沒寫進內嵌模板，等於部署者永遠看不到它們。
func TestExampleYAMLCarriesSessionPolicyKeys(t *testing.T) {
	for _, key := range []string{
		"session_idle_hours:",
		"session_touch_minutes:",
		"session_cleanup_minutes:",
		"session_cleanup_grace_hours:",
	} {
		if !strings.Contains(ExampleYAML, key) {
			t.Errorf("內嵌範例組態缺少 %s", key)
		}
	}
	// 內嵌模板解析出來的會話策略值必須等於內建預設值：兩份「同一件事」不能各有說法。
	// 只比這四個鍵而不是整個 SecurityConfig——CORS 段帶切片，結構體不可直接比較。
	cfg, err := Load(Options{ConfigPath: writeConfig(t, ExampleYAML)})
	if err != nil {
		t.Fatalf("解析內嵌範例失敗: %v", err)
	}
	want := Default().Security
	if cfg.Security.SessionIdleHours != want.SessionIdleHours ||
		cfg.Security.SessionTouchMinutes != want.SessionTouchMinutes ||
		cfg.Security.SessionCleanupMinutes != want.SessionCleanupMinutes ||
		cfg.Security.SessionCleanupGraceHours != want.SessionCleanupGraceHours {
		t.Errorf("內嵌範例的會話策略與預設值不一致: %+v vs %+v",
			cfg.Security, want)
	}
}

// TestSessionPolicyDurationsMatchConfiguredUnits 確認配置單位與實現的換算口徑一致：
// 小時欄就是小時、分鐘欄就是分鐘，裝配層寫反了這裡就該紅。
func TestSessionPolicyDurationsMatchConfiguredUnits(t *testing.T) {
	cfg := Default()
	cfg.Security.SessionIdleHours = 3
	cfg.Security.SessionTouchMinutes = 7
	cfg.Security.SessionCleanupMinutes = 11
	cfg.Security.SessionCleanupGraceHours = 5

	idle := time.Duration(cfg.Security.SessionIdleHours) * time.Hour
	touch := time.Duration(cfg.Security.SessionTouchMinutes) * time.Minute
	interval := time.Duration(cfg.Security.SessionCleanupMinutes) * time.Minute
	grace := time.Duration(cfg.Security.SessionCleanupGraceHours) * time.Hour

	if idle != 3*time.Hour || touch != 7*time.Minute || interval != 11*time.Minute || grace != 5*time.Hour {
		t.Errorf("單位換算不正確：idle=%s touch=%s cleanup=%s grace=%s", idle, touch, interval, grace)
	}
}
