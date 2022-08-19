// Package config 提供伺服器組態的載入、預設值與校驗。
//
// 載入順序：內建預設值 → {資料目錄}/config.yaml → 環境變數（ER_ 前綴）。
// 命令列參數（--data-dir）與資料目錄初始化於後續步驟加入。
//
// 校驗失敗時，錯誤訊息會指出具體欄位路徑（如 server.listen），
// 但絕不輸出任何機密明文；啟動日誌一律使用 Redacted() 的脫敏檢視。
package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"gopkg.in/yaml.v3"
)

// Options 為 Load 的外部輸入。空值表示使用對應的預設/組態值。
type Options struct {
	// DataDir 由命令列或環境變數指定的資料目錄；空字串表示用組態或預設值。
	DataDir string
	// ConfigPath 組態檔路徑；空字串表示 {DataDir 或預設}/config.yaml。
	ConfigPath string
}

// Config 為服務端執行期組態。
type Config struct {
	Server      ServerConfig   `yaml:"server"`
	Database    DatabaseConfig `yaml:"database"`
	Media       string         `yaml:"media"`
	Documents   string         `yaml:"documents"`
	Attachments string         `yaml:"attachments"`
	Backups     string         `yaml:"backups"`
	Logs        LogsConfig     `yaml:"logs"`
	Disk        DiskConfig     `yaml:"disk"`
	Security    SecurityConfig `yaml:"security"`

	// RootHashNotice 不是組態欄位（不帶 yaml 標記，因此也不會被解讀）：
	// 它記錄載入階段對 Root 憑據形狀的一句提醒，由 Redacted() 帶進啟動摘要。
	// 放在 Config 上是因為「這句提醒屬於哪個部署」必須跟著這份組態走，
	// 而不是變成套件級全域狀態（那樣兩個資料目錄的測試就會互相污染）。
	RootHashNotice string `yaml:"-"`
}

// ServerConfig 為伺服器層組態。
type ServerConfig struct {
	Listen          string `yaml:"listen"`           // HTTP 監聽地址，預設 127.0.0.1:5206
	DataDir         string `yaml:"data_dir"`         // 執行資料目錄；"." 或空表示預設 evernight-data
	DisplayTimezone string `yaml:"display_timezone"` // 顯示時區（IANA 名稱）；資料庫仍以 UTC 儲存

	// HTTP 層保護參數：逾時單位為毫秒，請求體上限單位為位元組。
	// 逾時分工：read_header 限制標頭讀取、read 限制整個請求讀取、
	// write 限制回應寫入、request 為單次處理的處理器期限、idle 限制 keep-alive 空閒。
	ReadHeaderTimeoutMS int   `yaml:"read_header_timeout_ms"`
	ReadTimeoutMS       int   `yaml:"read_timeout_ms"`
	WriteTimeoutMS      int   `yaml:"write_timeout_ms"`
	IdleTimeoutMS       int   `yaml:"idle_timeout_ms"`
	RequestTimeoutMS    int   `yaml:"request_timeout_ms"`
	MaxBodyBytes        int64 `yaml:"max_body_bytes"` // JSON API 請求體上限；上傳路由日後單獨放寬

	// ShutdownTimeoutMS 為優雅停止時等待進行中請求完成的上限。
	// 逾時則強制關閉連線，確保程序能結束並釋放監聽資源。
	ShutdownTimeoutMS int `yaml:"shutdown_timeout_ms"`
}

// DatabaseConfig 為 SQLite 資料庫組態。
type DatabaseConfig struct {
	Path          string `yaml:"path"`            // 資料庫檔名（相對資料目錄）
	BusyTimeoutMS int    `yaml:"busy_timeout_ms"` // 鎖等待超時（毫秒）
	// Preflight 為開庫前預檢模式：
	// header（預設）只讀檔頭標記，零寫入即可攔截非本服務檔與較新版本；
	// readonly 另以唯讀連線讀取版本（可攔截檔頭落後的較新版本）；off 不預檢。
	Preflight string `yaml:"preflight"`
	// IntegrityCheck 為啟動時是否執行完整性自檢（integrity_check + foreign_key_check）。
	// 預設關閉：大庫上自檢可能明顯耗時，需要時再開，或手動執行 `migrate --verify`。
	IntegrityCheck bool `yaml:"integrity_check"`
	// SchemaGuard 為不識別 schema 版本時的寫入把關層級（規格附錄 E.5）：
	// startup（預設）於啟動時拒絕不相容版本；
	// transaction 另於每個寫入交易的回呼執行前複驗版本（見 database.TxPolicy.GuardSchema），
	// 可攔截執行期資料庫被替換或還原成其他版本。
	SchemaGuard string `yaml:"schema_guard"`
	// Transaction 為交易邊界行為。
	Transaction TransactionConfig `yaml:"transaction"`
}

// TransactionConfig 為交易邊界行為。
//
// 回呼式交易由 database.InTx 提供：回呼回傳錯誤或 panic 時整體回滾。
type TransactionConfig struct {
	// BeginMode 為寫入交易的 BEGIN 模式：
	// immediate（預設）在交易開始即取得寫入鎖，失敗點固定於交易開始前；
	// deferred 則延到首次寫入才取得，失敗點落在回呼執行途中（不建議）。
	BeginMode string `yaml:"begin_mode"`
	// Nested 為同一交易內再開交易的行為：
	// reject（預設）直接拒絕；savepoint 以儲存點實現真嵌套（內層可獨立回滾）；
	// reuse 加入外層交易（內層失敗需由外層決定是否整體回滾）。
	Nested string `yaml:"nested"`
	// BusyRetryMax 為遇到忙鎖（SQLITE_BUSY/LOCKED）時自動重試整個交易的次數；
	// 0（預設）不重試。重試會重跑回呼，故僅適用於冪等交易。
	BusyRetryMax int `yaml:"busy_retry_max"`
	// BusyRetryBackoffMS 為重試的線性退避基數（毫秒）；0 表示立即重試。
	BusyRetryBackoffMS int `yaml:"busy_retry_backoff_ms"`
	// TimeoutMS 為單一交易的執行期限（毫秒）；0 表示不限制。
	// 短交易可避免長期持有寫入鎖（規格 RSK-003）。
	TimeoutMS int `yaml:"timeout_ms"`
}

// LogsConfig 為本地日誌組態。
//
// 日誌依「顯示時區的自然日」分檔（檔名帶日期，不重命名舊檔），因此同目錄下會隨日期增加檔案；
// 淘汰只按天數，且預設不淘汰（保留完整歷史直到部署者設定上限）。
type LogsConfig struct {
	Dir   string `yaml:"dir"`
	Level string `yaml:"level"` // debug | info | warn | error
	// FilePrefix 為日誌檔名前綴；當日檔案名為 `<前綴>.<YYYY-MM-DD>.log`。
	// 前綴不得含路徑分隔符或 Windows 檔名禁忌字元：它會被直接拼成檔案名。
	FilePrefix string `yaml:"file_prefix"`
	// RetentionDays 為日誌保留天數（含當日）；0（預設）表示不限制、不淘汰任何舊檔。
	// 換言之「日誌不會無限增大」是要部署者明確設定的選項，不是內建行為——
	// 自動刪檔在活動進行中可能是刪除唯一的事後線索，預設因此偏向保留。
	RetentionDays int `yaml:"retention_days"`
}

// DiskConfig 為磁碟空間監測與寫保護組態（規格 OPS-009、AT-020）。
//
// 兩個下限是「取較嚴者」：任一命中即判定空間不足。預設全為 0＝不設限，
// 與日誌保留天數同取向（DEC-028）——「設了正值才有上限」必須寫進啟動摘要與維運手冊，
// 不在程式碼裡偷偷給一個看起來比較安全的預設值。
//
// 不在這裡給預設值的理由與日誌相同：自動攔截寫入在活動進行中可能是把「還在進行的事」
// 停掉，那個後果比讓 SQLite 自己因為空間耗盡而失敗更難預料，因此由部署者明確開啟。
type DiskConfig struct {
	// MinFreeBytes 是剩餘空間的絕對下限（位元組）；0 表示不按絕對值設限。
	MinFreeBytes int64 `yaml:"min_free_bytes"`
	// MinFreePercent 是剩餘空間佔卷總容量的下限百分比（如 5 代表 5%）；0 表示不按比例設限。
	//
	// 大卷上 5% 可能是 50 GiB，會過早拒寫；小卷上 512 MiB 卻已經太晚——所以兩條都給，
	// 取較嚴的那條。
	MinFreePercent float64 `yaml:"min_free_percent"`
	// CheckIntervalMS 是可用空間讀值的快取期限（毫秒）；0 表示每個寫入前都實測。
	//
	// 這是效能與新鮮度的折衷，不是安全開關：預設 10 秒只影響「剛清完空間後多久恢復放行」，
	// 下限本身仍是上面兩個值決定。
	CheckIntervalMS int `yaml:"check_interval_ms"`
}

// SecurityConfig 為安全相關組態。
type SecurityConfig struct {
	SessionTTLHours int `yaml:"session_ttl_hours"`
	// Root 憑據（Argon2id 雜湊）僅存於資料目錄 config.yaml；
	// Redacted() 與所有日誌永不輸出其明文。
	RootPasswordHash string `yaml:"root_password_hash"`
	// Hashing 是新產生憑據的 Argon2id 參數檔（Root 與普通帳戶共用同一檔）。
	Hashing HashingConfig `yaml:"hashing"`
	// LoginGuard 是登入失敗控制與限流的閾值（見 internal/auth 的 LoginGuard）。
	LoginGuard LoginGuardConfig `yaml:"login_guard"`
	// Headers 為 HTTP 安全回應頭。
	Headers SecurityHeadersConfig `yaml:"headers"`
	// CORS 為跨來源存取策略；預設不開放任何來源。
	CORS CORSConfig `yaml:"cors"`
}

// LoginGuardConfig 為登入失敗控制與限流組態。
//
// 計量主軸是「來源位址 × 登入目標」配對（某一帳戶被打滿只冷卻該來源對該帳戶），
// 來源級總量是橫掃大量帳戶時的補集——兩層閾值的悬殊比例就是為局域网共享出口
// 留的餘地：一百個用戶各自打錯幾次密碼，不該讓整棟樓登入不了的來源級閘門落下。
//
// 狀態純在記憶體、重啟即清空（使用者批准的語意）；這裡只有閾值，沒有持久資料。
type LoginGuardConfig struct {
	// FailLimit 是視窗內單一「來源×目標」的失敗上限。
	FailLimit int `yaml:"fail_limit"`
	// WindowMinutes 是失敗計數的滑動視窗長度（分鐘）。
	WindowMinutes int `yaml:"window_minutes"`
	// CooldownMinutes 是觸發上限後的冷卻長度（分鐘）；冷卻期內被擋的嘗試不延長它。
	CooldownMinutes int `yaml:"cooldown_minutes"`
	// SourceFailLimit 是視窗內單一來源跨全部目標的失敗上限。
	SourceFailLimit int `yaml:"source_fail_limit"`
	// MaxEntries 是限流條目總數上限：限流自己必須是有限資源，
	// 否則「餵海量隨機鍵耗盡伺服器記憶體」會成為攻擊登入端點的新路線。
	MaxEntries int `yaml:"max_entries"`
}

// Validate 正規化並校驗登入失敗控制閾值。
//
// 界限與 internal/auth 的 LoginGuard 構造校驗一致（兩邊都擋：啟動時組態層先報
// 帶鍵名的可讀錯誤，構造層再守最後一道——組裝代碼出錯也不讓半套閾值上線）。
// 上界的意義是「這個值本身還構不構成資源風險」：MaxEntries 十萬條約十 MB 量級，
// 分鐘数超過一天就不再是「稍後再試」而是變相永久鎖人。
func (g LoginGuardConfig) Validate() error {
	if g.FailLimit < 1 || g.FailLimit > maxLoginGuardLimit {
		return fmt.Errorf("config: security.login_guard.fail_limit 需為 1..%d，實際為 %d", maxLoginGuardLimit, g.FailLimit)
	}
	if g.SourceFailLimit < 1 || g.SourceFailLimit > maxLoginGuardLimit {
		return fmt.Errorf("config: security.login_guard.source_fail_limit 需為 1..%d，實際為 %d", maxLoginGuardLimit, g.SourceFailLimit)
	}
	if g.SourceFailLimit < g.FailLimit {
		return fmt.Errorf("config: security.login_guard.source_fail_limit(%d) 不得低於 fail_limit(%d)（否則單一帳戶就會鎖死整個來源）",
			g.SourceFailLimit, g.FailLimit)
	}
	if g.WindowMinutes < 1 || g.WindowMinutes > maxLoginGuardMinutes {
		return fmt.Errorf("config: security.login_guard.window_minutes 需為 1..%d，實際為 %d", maxLoginGuardMinutes, g.WindowMinutes)
	}
	if g.CooldownMinutes < 1 || g.CooldownMinutes > maxLoginGuardMinutes {
		return fmt.Errorf("config: security.login_guard.cooldown_minutes 需為 1..%d，實際為 %d", maxLoginGuardMinutes, g.CooldownMinutes)
	}
	if g.MaxEntries < 1 || g.MaxEntries > maxLoginGuardEntries {
		return fmt.Errorf("config: security.login_guard.max_entries 需為 1..%d，實際為 %d", maxLoginGuardEntries, g.MaxEntries)
	}
	return nil
}

// 登入失敗控制的硬界限（與 internal/auth 的 LoginGuard 上界對齊）。
const (
	maxLoginGuardLimit   = 10000
	maxLoginGuardMinutes = 1440
	maxLoginGuardEntries = 100000
)

// HashingConfig 為憑據雜湊的參數策略（新產生時生效）。
//
// 語意（用戶決定）：生產用最低推薦檔是預設，但各欄可在組態檔覆蓋——
// 欄位留 0（或整段缺省）即沿用該欄的生產預設值，不引入「隱式半自訂檔」的歧義：
// 解析後的最終檔必須整體通過 credential.Params 的區間校驗。
//
// 只影響之後新產生的憑據；既有憑據（Root 雜湊、帳戶 password_hash）
// 按編碼內自帶參數校驗，換檔不會讓它們突然失效。「是否該順手升級某份既有憑據」
// 由 internal/credential 的 NeedsUpgrade 判定，屬登入路徑的未來工作。
type HashingConfig struct {
	// MemoryKiB 是記憶體成本（KiB）；0 表示沿用預設。
	MemoryKiB int `yaml:"memory_kb"`
	// TimeCost 是時間成本（遍數）；0 表示沿用預設。
	TimeCost int `yaml:"time_cost"`
	// Parallelism 是並行度；0 表示沿用預設。
	Parallelism int `yaml:"parallelism"`
	// KeyLength 是摘要輸出長度（位元組）；0 表示沿用預設。
	KeyLength int `yaml:"key_length"`
}

// Params 把組態解析為 credential.Params：0 欄位回落生產預設檔對應欄位。
//
// 區間檢查在轉 uint 之前完成，超大正數與負數都在此拒絕而不是繞成小值；
// 錯誤訊息只含欄位名與數值（參數非秘密），不含任何憑據材料。
func (h HashingConfig) Params() (credential.Params, error) {
	out := credential.ProductionParams
	pairs := []struct {
		name   string
		src    int
		lo, hi int64
		set    func(uint32)
	}{
		{"security.hashing.memory_kb", h.MemoryKiB, credential.MinMemoryKiB, credential.MaxMemoryKiB,
			func(v uint32) { out.MemoryKiB = v }},
		{"security.hashing.time_cost", h.TimeCost, credential.MinTimeCost, credential.MaxTimeCost,
			func(v uint32) { out.TimeCost = v }},
		{"security.hashing.parallelism", h.Parallelism, credential.MinParallelism, credential.MaxParallelism,
			func(v uint32) { out.Parallelism = uint8(v) }},
		{"security.hashing.key_length", h.KeyLength, credential.MinKeyLength, credential.MaxKeyLength,
			func(v uint32) { out.KeyLength = v }},
	}
	for _, f := range pairs {
		if f.src == 0 {
			continue // 沿用預設欄位值。
		}
		if int64(f.src) < f.lo || int64(f.src) > f.hi {
			return credential.Params{}, fmt.Errorf(
				"config: %s 需為 0（沿用預設）或 %d..%d，實際為 %d", f.name, f.lo, f.hi, f.src)
		}
		f.set(uint32(f.src))
	}
	if err := out.Validate(); err != nil {
		return credential.Params{}, fmt.Errorf("config: security.hashing 參數組合無效: %w", err)
	}
	return out, nil
}

// summary 回傳雜湊參數檔在啟動摘要裡的樣子。參數不是秘密，直接實值輸出；
// 尚未通過校驗的組合（啟動會失敗）退化为顯示原始配置值，不在此处報錯。
func (h HashingConfig) summary() string {
	p, err := h.Params()
	if err != nil {
		return fmt.Sprintf("無效組合(m=%d,t=%d,p=%d,keylen=%d)",
			h.MemoryKiB, h.TimeCost, h.Parallelism, h.KeyLength)
	}
	return fmt.Sprintf("m=%d,t=%d,p=%d,keylen=%d", p.MemoryKiB, p.TimeCost, p.Parallelism, p.KeyLength)
}

// CORSConfig 為跨來源（CORS）策略組態。
//
// 預設值是「完全關閉」：AllowedOrigins 空 ⇒ 服務端不下發任何跨域標頭，
// 行為與本步之前逐字相同。開發期要讓瀏覽器直接呼叫 Go，必須在組態裡
// 明確寫入來源；這道「預設不寬鬆」的門就是「開發設定不會無條件進入正式組態」
// 的實作——正式組態裡沒有這一段，就沒有跨域出口。
//
// 校驗刻意嚴格：來源只收 `*` 或 `scheme://host[:port]` 的精確寫法（不接受路徑、
// 不接受萬用子網域），標頭與方法名稱必須是 HTTP token。原因有兩個：回應值會
// 直接反射到標頭裡，任何可注入字元（CR/LF）都會變成回應分割；而 `*.example`
// 這類半萬用寫法的實際放行範圍常被部署者誤解。
type CORSConfig struct {
	// AllowedOrigins 為放行來源清單；空清單代表關閉，`*` 代表任意來源。
	AllowedOrigins []string `yaml:"allowed_origins"`
	// AllowedMethods 為預檢可放行的請求方法（一律轉大寫比對）。
	AllowedMethods []string `yaml:"allowed_methods"`
	// AllowedHeaders 為預檢可放行的請求標頭（客戶端自訂標頭需列在此處）。
	AllowedHeaders []string `yaml:"allowed_headers"`
	// ExposedHeaders 為允許客戶端腳本讀回的回應標頭。
	ExposedHeaders []string `yaml:"exposed_headers"`
	// AllowCredentials 允許附帶憑據（Cookie / 授權標頭）；與 `*` 同時使用一律拒絕。
	AllowCredentials bool `yaml:"allow_credentials"`
	// MaxAgeSeconds 為預檢結果快取時間；0 表示不允許快取。
	MaxAgeSeconds int `yaml:"max_age_seconds"`
}

// SecurityHeadersConfig 為 HTTP 安全回應頭組態。
//
// 空值代表採用內建預設策略（見 httpapi 套件的預設常數）；只有確實需要時才覆寫。
// 覆寫內容由部署者自行負責，服務端僅校驗基本健全性，阻擋明顯放寬（如 'unsafe-eval'）。
type SecurityHeadersConfig struct {
	// ContentSecurityPolicy 為完整 CSP 策略字串；空值表示使用內建預設（相容本機 Flutter Web）。
	ContentSecurityPolicy string `yaml:"content_security_policy"`
	// FrameOptions 為 X-Frame-Options；空值表示 DENY，可選 DENY 或 SAMEORIGIN。
	FrameOptions string `yaml:"frame_options"`
	// ReferrerPolicy 為 Referrer-Policy；空值表示內建預設。
	ReferrerPolicy string `yaml:"referrer_policy"`
	// PermissionsPolicy 為 Permissions-Policy；空值表示內建預設（相機僅允許同源）。
	PermissionsPolicy string `yaml:"permissions_policy"`
}

// Default 回傳內建安全預設值（與 config.example.yaml 一致）。
func Default() Config {
	return Config{
		Server: ServerConfig{
			Listen:              "127.0.0.1:5206",
			DataDir:             "evernight-data",
			DisplayTimezone:     "Asia/Shanghai",
			ReadHeaderTimeoutMS: 5000,
			ReadTimeoutMS:       15000,
			WriteTimeoutMS:      30000,
			IdleTimeoutMS:       60000,
			RequestTimeoutMS:    10000,
			MaxBodyBytes:        1 << 20,
			ShutdownTimeoutMS:   10000,
		},
		Database: DatabaseConfig{
			Path:          "evernight.db",
			BusyTimeoutMS: 5000,
			Preflight:     "header",
			SchemaGuard:   "startup",
			Transaction: TransactionConfig{
				BeginMode:          "immediate",
				Nested:             "reject",
				BusyRetryMax:       0,
				BusyRetryBackoffMS: 50,
				TimeoutMS:          10000,
			},
		},
		Media:       "media/",
		Documents:   "documents/",
		Attachments: "attachments/",
		Backups:     "backups/",
		Logs: LogsConfig{
			Dir:           "logs/",
			Level:         "info",
			FilePrefix:    "evernight-run",
			RetentionDays: 0,
		},
		// 磁碟寫保護預設關閉：兩個下限都明確寫 0（是決定，不是遺漏），
		// 只有 check_interval_ms 給一個純效能預設值。
		Disk: DiskConfig{
			MinFreeBytes:    0,
			MinFreePercent:  0,
			CheckIntervalMS: 10000,
		},
		Security: SecurityConfig{
			SessionTTLHours: 24,
			// 登入失敗控制的預設閾值（使用者批准）：配對 10 次、來源 50 次、
			// 視窗與冷卻各 15 分鐘、限流表封頂一萬條。
			LoginGuard: LoginGuardConfig{
				FailLimit:       10,
				WindowMinutes:   15,
				CooldownMinutes: 15,
				SourceFailLimit: 50,
				MaxEntries:      10000,
			},
			CORS: CORSConfig{
				// 來源清單刻意留空：跨域預設關閉，需要時由部署者明確開啟。
				AllowedMethods: []string{"GET", "HEAD", "OPTIONS"},
				AllowedHeaders: []string{"Accept", "Accept-Language", "Content-Type", "Idempotency-Key", "X-Request-Id"},
				ExposedHeaders: []string{"X-Request-Id"},
				MaxAgeSeconds:  600,
			},
		},
	}
}

// ParseArgs 解析命令列參數，目前支援 --data-dir；未知參數回傳錯誤。
func ParseArgs(args []string) (Options, error) {
	var opts Options
	fs := flag.NewFlagSet("evernight-server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.DataDir, "data-dir", "", "執行資料目錄（預設 evernight-data/）")
	if err := fs.Parse(args); err != nil {
		return Options{}, fmt.Errorf("命令列參數錯誤: %w", err)
	}
	if fs.NArg() > 0 {
		return Options{}, fmt.Errorf("命令列參數錯誤: 不認識的位置參數 %q", fs.Arg(0))
	}
	return opts, nil
}

// Load 依序以預設值、config.yaml、環境變數、命令列建構組態並校驗。
//
// config.yaml 的位置由 opts.ConfigPath 決定；未指定時以
// {opts.DataDir 或預設 evernight-data}/config.yaml 為準。
// 組態檔不存在時以預設值執行（首次啟動時建立範例組態）。
// 優先序：命令列 --data-dir > 環境變數 > config.yaml > 預設值。
func Load(opts Options) (Config, error) {
	cfg := Default()

	// 組態檔位置由外部指定或預設資料目錄決定；
	// yaml 內部的 data_dir 不影響組態檔讀取位置（避免循環依賴）。
	configDir := opts.DataDir
	if configDir == "" {
		configDir = Default().Server.DataDir
	}

	configPath := opts.ConfigPath
	if configPath == "" {
		configPath = filepath.Join(configDir, "config.yaml")
	}

	if data, err := os.ReadFile(configPath); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("config: 解析 %s 失敗（請檢查 YAML 語法）: %w", configPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("config: 讀取 %s 失敗: %w", configPath, err)
	}

	if err := applyEnv(&cfg); err != nil {
		return Config{}, err
	}

	// 命令列 --data-dir 優先於環境變數與 yaml。
	if opts.DataDir != "" {
		cfg.Server.DataDir = opts.DataDir
	}

	// "." 或空 data_dir 表示採用預設資料目錄（與 config.example.yaml 語意一致）。
	if cfg.Server.DataDir == "" || cfg.Server.DataDir == "." {
		cfg.Server.DataDir = Default().Server.DataDir
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate 校驗組態值，錯誤訊息包含欄位路徑（如 server.listen）。
func (c *Config) Validate() error {
	if c.Server.Listen == "" {
		return errors.New("config: server.listen 不可為空")
	}
	host, port, err := net.SplitHostPort(c.Server.Listen)
	if err != nil {
		return fmt.Errorf("config: server.listen 格式無效（需 host:port，如 127.0.0.1:5206）: %q", c.Server.Listen)
	}
	if host == "" {
		return errors.New("config: server.listen 缺少主機（禁止裸埠監聽）")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("config: server.listen 連接埠無效（需 1–65535）: %q", port)
	}

	if c.Server.DataDir == "" {
		return errors.New("config: server.data_dir 不可為空")
	}
	if _, err := time.LoadLocation(c.Server.DisplayTimezone); err != nil {
		return fmt.Errorf("config: server.display_timezone 不是有效 IANA 時區: %q", c.Server.DisplayTimezone)
	}

	// HTTP 層保護參數：全部需為正數；處理期限不得長於回應寫入期限，
	// 否則連線期限會先觸發，用戶端得到連線中斷而非穩定錯誤碼。
	timeouts := []struct {
		name  string
		value int
	}{
		{"server.read_header_timeout_ms", c.Server.ReadHeaderTimeoutMS},
		{"server.read_timeout_ms", c.Server.ReadTimeoutMS},
		{"server.write_timeout_ms", c.Server.WriteTimeoutMS},
		{"server.idle_timeout_ms", c.Server.IdleTimeoutMS},
		{"server.request_timeout_ms", c.Server.RequestTimeoutMS},
		{"server.shutdown_timeout_ms", c.Server.ShutdownTimeoutMS},
	}
	for _, t := range timeouts {
		if t.value < 1 {
			return fmt.Errorf("config: %s 必須為正整數（毫秒）", t.name)
		}
	}
	if c.Server.RequestTimeoutMS > c.Server.WriteTimeoutMS {
		return fmt.Errorf("config: server.request_timeout_ms（%d）不得大於 server.write_timeout_ms（%d）",
			c.Server.RequestTimeoutMS, c.Server.WriteTimeoutMS)
	}
	if c.Server.MaxBodyBytes < minBodyBytes || c.Server.MaxBodyBytes > maxBodyBytes {
		return fmt.Errorf("config: server.max_body_bytes 需介於 %d 與 %d 之間（位元組），實際為 %d",
			minBodyBytes, maxBodyBytes, c.Server.MaxBodyBytes)
	}

	if c.Database.Path == "" {
		return errors.New("config: database.path 不可為空")
	}
	if c.Database.BusyTimeoutMS < 1 {
		return errors.New("config: database.busy_timeout_ms 必須為正整數（毫秒）")
	}
	// 預檢模式與寫入把關層級限枚舉值；空值代表採用內建預設（與 Default() 一致）。
	if c.Database.Preflight == "" {
		c.Database.Preflight = "header"
	}
	switch c.Database.Preflight {
	case "header", "readonly", "off":
	default:
		return fmt.Errorf("config: database.preflight 需為 header|readonly|off，實際為 %q", c.Database.Preflight)
	}
	if c.Database.SchemaGuard == "" {
		c.Database.SchemaGuard = "startup"
	}
	switch c.Database.SchemaGuard {
	case "startup", "transaction":
	default:
		return fmt.Errorf("config: database.schema_guard 需為 startup|transaction，實際為 %q", c.Database.SchemaGuard)
	}
	// 交易邊界：空值代表採用內建預設（與 Default() 一致）。
	tx := &c.Database.Transaction
	if tx.BeginMode == "" {
		tx.BeginMode = "immediate"
	}
	switch tx.BeginMode {
	case "immediate", "deferred":
	default:
		return fmt.Errorf("config: database.transaction.begin_mode 需為 immediate|deferred，實際為 %q", tx.BeginMode)
	}
	if tx.Nested == "" {
		tx.Nested = "reject"
	}
	switch tx.Nested {
	case "reject", "savepoint", "reuse":
	default:
		return fmt.Errorf("config: database.transaction.nested 需為 reject|savepoint|reuse，實際為 %q", tx.Nested)
	}
	if tx.BusyRetryMax < 0 {
		return fmt.Errorf("config: database.transaction.busy_retry_max 不可為負數，實際為 %d", tx.BusyRetryMax)
	}
	if tx.BusyRetryBackoffMS < 0 {
		return fmt.Errorf("config: database.transaction.busy_retry_backoff_ms 不可為負數，實際為 %d", tx.BusyRetryBackoffMS)
	}
	if tx.TimeoutMS < 0 {
		return fmt.Errorf("config: database.transaction.timeout_ms 不可為負數（0 表示不限制），實際為 %d", tx.TimeoutMS)
	}

	for name, v := range map[string]string{
		"media":       c.Media,
		"documents":   c.Documents,
		"attachments": c.Attachments,
		"backups":     c.Backups,
	} {
		if v == "" {
			return fmt.Errorf("config: %s 目錄不可為空", name)
		}
	}
	if c.Logs.Dir == "" {
		return errors.New("config: logs.dir 不可為空")
	}
	// 層級名稱先正規化再校驗：環境變數常由 shell 給出（ER_LOGS_LEVEL=DEBUG、尾端空白），
	// 校驗的門禁照舊，但不要把「大小寫不同」變成啟動失敗。
	// 正規化放在這一層是因為它是組態邊界的工作，runlog 那邊的容錯只是替直接呼叫者兜底。
	c.Logs.Level = strings.ToLower(strings.TrimSpace(c.Logs.Level))
	switch c.Logs.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: logs.level 需為 debug|info|warn|error，實際為 %q", c.Logs.Level)
	}
	// 日誌檔名前綴：空值代表採用內建預設（與 Default() 一致）；前後空白一律去掉。
	c.Logs.FilePrefix = strings.TrimSpace(c.Logs.FilePrefix)
	if c.Logs.FilePrefix == "" {
		c.Logs.FilePrefix = Default().Logs.FilePrefix
	}
	if err := validateLogFilePrefix(c.Logs.FilePrefix); err != nil {
		return err
	}
	// 保留天數為 0 時不淘汰（預設）；上限只是把「打錯一個大數」攔在啟動階段。
	if c.Logs.RetentionDays < 0 || c.Logs.RetentionDays > maxLogRetentionDays {
		return fmt.Errorf("config: logs.retention_days 需為 0（不限制）或 1..%d，實際為 %d",
			maxLogRetentionDays, c.Logs.RetentionDays)
	}

	// 磁碟寫保護的兩個下限：要嘛 0（不設限），要嘛在可用範圍內。
	// 負數拒絕而不是歸零：負的下限永遠不會命中，靜默接受會讓一個打錯的數字變成
	// 「保護看起來開著、其實沒有效」，那比啟動失敗難查得多。
	if c.Disk.MinFreeBytes < 0 {
		return fmt.Errorf("config: disk.min_free_bytes 需為 0（不設限）或正整數，實際為 %d", c.Disk.MinFreeBytes)
	}
	if c.Disk.MinFreePercent < 0 || c.Disk.MinFreePercent > maxDiskFreePercent {
		return fmt.Errorf("config: disk.min_free_percent 需為 0（不設限）或 0..%g，實際為 %v",
			maxDiskFreePercent, c.Disk.MinFreePercent)
	}
	if c.Disk.CheckIntervalMS < 0 || c.Disk.CheckIntervalMS > maxDiskCheckIntervalMS {
		return fmt.Errorf("config: disk.check_interval_ms 需介於 0..%d，實際為 %d",
			maxDiskCheckIntervalMS, c.Disk.CheckIntervalMS)
	}

	if c.Security.SessionTTLHours < 1 {
		return errors.New("config: security.session_ttl_hours 必須為正整數")
	}
	// Root 憑據的形狀：先以內建常數比對前綴（攔住「拿一般文字冒充雜湊」），
	// 再用 credential 的嚴格解析確認它真的可用。
	//
	// 這裡刻意「只記一句提醒、不擋啟動」，理由是兩句話的權衡：
	//   - 一個寫壞的 Root 欄位代表目前根本沒有可用的 Root。把這種部署變成開不起來，
	//     等於用一個運維瑕疵換掉「整個服務停止保護」——活動進行中的代價更大；
	//   - 反過來，若靜默通過，啟動的人不會知道自己其實登不進去。
	// 所以結論是：照樣啟動，但這一句要出現在啟動摘要裡；而一次性初始化通路（internal/rootinit）
	// 在寫入前硬擋——那裡才是「不能再留著壞值」的時機。
	if c.Security.RootPasswordHash != "" {
		if !strings.HasPrefix(c.Security.RootPasswordHash, argon2IDPrefix) {
			return fmt.Errorf("config: security.root_password_hash 需為 Argon2id 雜湊（%s 前綴）", argon2IDPrefix)
		}
		if err := credential.CheckEncoding(c.Security.RootPasswordHash); err != nil {
			c.RootHashNotice = " Root 憑據形狀不合格（" + err.Error() + "）：這個 Root 口令無法通過校驗，" +
				"請用 evernight-server init-root 建立可用憑據（它在寫入前會先確認形狀）"
		}
	}
	// 雜湊參數檔在啟動即整體校驗：把「打錯一個參數導致憑據檔半生不熟」
	// 關在啟動門外，之後 Hash 路徑拿到的 Params 一定合法。
	if _, err := c.Security.Hashing.Params(); err != nil {
		return err
	}

	// 登入失敗控制閾值同樣在啟動整體校驗：0 在这里不是「沿用預設」的語意
	// （Default() 已填好預設值，寫出 0 只可能是組態檔打錯），一律拒絕。
	if err := c.Security.LoginGuard.Validate(); err != nil {
		return err
	}

	// 安全回應頭：Frame 限制正規化為大寫並限枚舉值；
	// CSP 覆寫必須是有效策略且不得引入 'unsafe-eval'（專案安全基線）。
	c.Security.Headers.FrameOptions = strings.ToUpper(strings.TrimSpace(c.Security.Headers.FrameOptions))
	switch c.Security.Headers.FrameOptions {
	case "", "DENY", "SAMEORIGIN":
	default:
		return fmt.Errorf("config: security.headers.frame_options 需為 DENY 或 SAMEORIGIN，實際為 %q",
			c.Security.Headers.FrameOptions)
	}
	if csp := strings.TrimSpace(c.Security.Headers.ContentSecurityPolicy); csp != "" {
		if !strings.Contains(csp, "default-src") && !strings.Contains(csp, "script-src") {
			return errors.New("config: security.headers.content_security_policy 需至少包含 default-src 或 script-src 指令")
		}
		if strings.Contains(csp, "'unsafe-eval'") {
			return errors.New("config: security.headers.content_security_policy 不得包含 'unsafe-eval'（專案安全基線）")
		}
	}

	return c.Security.CORS.Validate()
}

// 預檢快取時間上限：一天。超過這個值通常意味著把開發期設定留進了正式組態。
const maxCORSMaxAge = 86400

// Validate 正規化並校驗跨域組態；空來源清單代表關閉，直接通過。
//
// 正規化包含：來源轉小寫並去掉尾端 `/`、方法轉大寫、標頭名稱去空白。
// 拒絕項目：含 CR/LF 或其他控制字元的值（會進入回應標頭）、非 token 形狀的
// 方法與標頭名、帶路徑/查詢/萬用子網域的來源、`*` 與 allow_credentials 並存。
func (c *CORSConfig) Validate() error {
	if len(c.AllowedOrigins) == 0 {
		// 關閉狀態下其餘欄位仍要正規化，避免日後開啟時帶著髒值。
		c.normalizeLists()
		return nil
	}

	origins := make([]string, 0, len(c.AllowedOrigins))
	wildcard := false
	for _, raw := range c.AllowedOrigins {
		origin := strings.ToLower(strings.TrimSpace(raw))
		// 尾端斜線一律去掉：瀏覽器送出的 Origin 永不含路徑，留著 `http://host/`
		// 這種寫法會讓人以為設好了、實際永遠比對不上。
		origin = strings.TrimSuffix(origin, "/")
		if origin == "" {
			continue
		}
		if err := validateCORSHeaderValue("security.cors.allowed_origins", origin); err != nil {
			return err
		}
		if origin == "*" {
			wildcard = true
			origins = append(origins, "*")
			continue
		}
		if err := validateCORSOrigin(origin); err != nil {
			return err
		}
		origins = append(origins, origin)
	}
	c.AllowedOrigins = origins

	if c.AllowCredentials && wildcard {
		return errors.New("config: security.cors.allow_credentials 不得與 allowed_origins 的 \"*\" 同時使用" +
			"（瀏覽器一律拒絕此組合，等於沒有放行）")
	}
	if c.MaxAgeSeconds < 0 || c.MaxAgeSeconds > maxCORSMaxAge {
		return fmt.Errorf("config: security.cors.max_age_seconds 需為 0..%d，實際為 %d", maxCORSMaxAge, c.MaxAgeSeconds)
	}
	return c.normalizeLists()
}

// normalizeLists 正規化方法與標頭清單並逐項校驗形狀。
func (c *CORSConfig) normalizeLists() error {
	methods := make([]string, 0, len(c.AllowedMethods))
	for _, raw := range c.AllowedMethods {
		method := strings.ToUpper(strings.TrimSpace(raw))
		if method == "" {
			continue
		}
		if !isHTTPToken(method) {
			return fmt.Errorf("config: security.cors.allowed_methods 含非法方法名 %q", raw)
		}
		methods = append(methods, method)
	}
	c.AllowedMethods = methods

	for _, entry := range []struct {
		name string
		src  []string
		dst  *[]string
	}{
		{"allowed_headers", c.AllowedHeaders, &c.AllowedHeaders},
		{"exposed_headers", c.ExposedHeaders, &c.ExposedHeaders},
	} {
		out := make([]string, 0, len(entry.src))
		for _, raw := range entry.src {
			token := strings.TrimSpace(raw)
			if token == "" {
				continue
			}
			if err := validateCORSHeaderValue("security.cors."+entry.name, token); err != nil {
				return err
			}
			if !isHTTPToken(token) {
				return fmt.Errorf("config: security.cors.%s 含非法標頭名 %q", entry.name, raw)
			}
			out = append(out, token)
		}
		*entry.dst = out
	}
	return nil
}

// validateCORSOrigin 檢查精確來源的形狀：scheme://host[:port]，不得帶路徑、
// 查詢、片段、認證資訊或萬用子網域。
func validateCORSOrigin(origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("config: security.cors.allowed_origins 需為 * 或 scheme://host[:port] 精確來源，實際為 %q", origin)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("config: security.cors.allowed_origins 不得帶路徑，實際為 %q", origin)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return fmt.Errorf("config: security.cors.allowed_origins 不得帶查詢、片段或憑據，實際為 %q", origin)
	}
	if strings.HasPrefix(parsed.Hostname(), "*") {
		return fmt.Errorf("config: security.cors.allowed_origins 不支援萬用子網域（放行範圍易被誤解），實際為 %q", origin)
	}
	return nil
}

// validateCORSHeaderValue 擋下會破壞 HTTP 標頭的值：控制字元（含 CR/LF）一律拒絕。
func validateCORSHeaderValue(field, value string) error {
	for _, r := range value {
		if r <= 0x20 || r == 0x7F {
			return fmt.Errorf("config: %s 含空白或控制字元，無法用於回應標頭：%q", field, value)
		}
	}
	return nil
}

// isHTTPToken 依 RFC 7230 判定 token：只允許 ASCII 可見字元，且不得為 separator。
//
// 方法名與標頭名都會被反射進回應標頭，任何放寬都等於給注入留口子。
func isHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c <= 0x20 || c >= 0x7F || isHTTPSeparator(c) {
			return false
		}
	}
	return true
}

// isHTTPSeparator 為 RFC 7230 的 separator 集合（含水平定位字元與空格）。
//
// 逐字元列出而非塞進字串常數：這個集合本身含反斜線與雙引號，
// 寫成字串常數會需要一層容易看錯的跳脫。
func isHTTPSeparator(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}', 0x09, ' ':
		return true
	}
	return false
}

// 日誌保留與檔名前綴的邊界值。
const (
	// maxLogRetentionDays 為保留天數上限（十年）：超過這個值通常意味著打錯數字，
	// 而「不限制」另有 0 這個寫法，不需要靠一個巨大的數字表達。
	maxLogRetentionDays = 3650
	// maxLogFilePrefixLen 為日誌檔名前綴長度上限：檔案名還要裝下日期與副檔名，
	// 過長的前綴在舊版檔案系統上會直接讓建立失敗。
	maxLogFilePrefixLen = 64
	// maxDiskFreePercent 是剩餘空間百分比下限的上界。100 是刻意允許的：要求整個卷都空著
	// 等於永久拒寫，那是部署者自己拉的閘，不是打錯數字的形態——會打錯的是 5000 這種。
	maxDiskFreePercent = 100.0
	// maxDiskCheckIntervalMS 是可用空間讀值快取期限的上限（一小時）。超過它，
	// 「清完空間後恢復放行」會慢到像卡死，那時攔截造成的問題比它要防的那個更大。
	maxDiskCheckIntervalMS = 3_600_000
)

// illegalFileNameChars 為檔案名禁忌字元：路徑分隔符、Windows 保留字元與 DEL。
//
// 刻意以碼位而不是字面量寫出：這條規則的全部內容就是幾個標點符號，
// 而其中反斜線在原始碼、腳本與轉換工具之間最容易被吞掉一層跳脫
// （本專案已踩過兩次），用 0x5C 就沒有這種風險。
var illegalFileNameChars = map[rune]bool{
	0x2F: true, // /
	0x5C: true, // \
	0x3A: true, // :
	0x2A: true, // *
	0x3F: true, // ?
	0x22: true, // \"
	0x3C: true, // <
	0x3E: true, // >
	0x7C: true, // |
	0x7F: true, // DEL
}

// validateLogFilePrefix 檢查前綴能安全拼進檔案名（<前綴>.YYYY-MM-DD.log）。
//
// 這裡攔的是「拼出來之後才發現」的那類問題：含路徑分隔符會把日誌寫到別處、
// Windows 保留字元會直接建不出檔案。控制字元也要擋，
// 否則前綴本身就會把終端與檔案總管的顯示搞亂。
func validateLogFilePrefix(prefix string) error {
	if prefix == "." || prefix == ".." {
		return fmt.Errorf("config: logs.file_prefix 不可為 %q（與日期拼出的檔名無效）", prefix)
	}
	if len(prefix) > maxLogFilePrefixLen {
		return fmt.Errorf("config: logs.file_prefix 長度不可超過 %d 個字元，實際為 %d",
			maxLogFilePrefixLen, len(prefix))
	}
	for _, r := range prefix {
		if illegalFileNameChars[r] {
			return fmt.Errorf("config: logs.file_prefix 含檔案系統禁忌字元（0x%02X）: %q", r, prefix)
		}
		if r < 0x20 {
			return fmt.Errorf("config: logs.file_prefix 含控制字元（0x%02X）: %q", r, prefix)
		}
	}
	return nil
}

// 請求體上限的合理區間：過小會使正常 JSON 請求失效，過大則失去保護意義。
const (
	minBodyBytes int64 = 1 << 10  // 1 KiB
	maxBodyBytes int64 = 64 << 20 // 64 MiB
)

// ListenAllInterfaces 回傳 true 表示監聽地址暴露於所有介面（含公網網卡），
// 供啟動日誌輸出風險提示。
func (c Config) ListenAllInterfaces() bool {
	host, _, err := net.SplitHostPort(c.Server.Listen)
	if err != nil {
		return false
	}
	return host == "0.0.0.0" || host == "::" || host == "[::]"
}

// DisplayLocation 回傳解析後的顯示時區，供時刻換算 UTC 偏移使用。
//
// 組態以 IANA 名稱儲存（Validate 已校驗其合法性），資料庫與協議一律以 UTC 存取，
// 本方法只負責「顯示」這一層：名稱無法解析時回退 UTC，
// 讓未經校驗的組態（如測試直接構造的零值）也有確定的行為。
func (c Config) DisplayLocation() *time.Location {
	if loc, err := time.LoadLocation(c.Server.DisplayTimezone); err == nil {
		return loc
	}
	return time.UTC
}

// Redacted 回傳組態的脫敏摘要（供啟動日誌），機密欄位一律顯示 [REDACTED]。
func (c Config) Redacted() string {
	return fmt.Sprintf("組態摘要：listen=%s data_dir=%s timezone=%s db=%s busy_timeout_ms=%d media=%s documents=%s attachments=%s backups=%s logs_dir=%s logs_level=%s logs_prefix=%s logs_retention_days=%d session_ttl_hours=%d root_password_hash=%s%s hashing=[%s] http_timeouts_ms=[read_header=%d read=%d write=%d idle=%d request=%d shutdown=%d] max_body_bytes=%d security_headers=[frame_options=%s csp=%s referrer_policy=%s permissions_policy=%s] cors=[%s] disk=[%s] tx=[begin_mode=%s nested=%s busy_retry_max=%d busy_retry_backoff_ms=%d timeout_ms=%d schema_guard=%s]",
		c.Server.Listen, c.Server.DataDir, c.Server.DisplayTimezone,
		c.Database.Path, c.Database.BusyTimeoutMS,
		c.Media, c.Documents, c.Attachments, c.Backups,
		c.Logs.Dir, c.Logs.Level, c.Logs.FilePrefix, c.Logs.RetentionDays,
		c.Security.SessionTTLHours, redact(c.Security.RootPasswordHash), c.RootHashNotice,
		c.Security.Hashing.summary(),
		c.Server.ReadHeaderTimeoutMS, c.Server.ReadTimeoutMS, c.Server.WriteTimeoutMS,
		c.Server.IdleTimeoutMS, c.Server.RequestTimeoutMS, c.Server.ShutdownTimeoutMS, c.Server.MaxBodyBytes,
		orDefault(c.Security.Headers.FrameOptions, "DENY"),
		presence(c.Security.Headers.ContentSecurityPolicy),
		presence(c.Security.Headers.ReferrerPolicy),
		presence(c.Security.Headers.PermissionsPolicy),
		c.Security.CORS.summary(),
		c.Disk.summary(),
		c.Database.Transaction.BeginMode, c.Database.Transaction.Nested,
		c.Database.Transaction.BusyRetryMax, c.Database.Transaction.BusyRetryBackoffMS,
		c.Database.Transaction.TimeoutMS, c.Database.SchemaGuard)
}

// CORSNotice 回傳啟動時該說的一句跨域提示；未開啟時回傳空字串。
//
// 開啟狀態必須在啟動輸出裡看得見：這組設定通常是為了開發期聯調才改的，
// 改完忘了改回來的成本（內網任何頁面都能讀端點）遠高於多印一行字。
func (c Config) CORSNotice() string {
	cors := c.Security.CORS
	if len(cors.AllowedOrigins) == 0 {
		return ""
	}
	if cors.wildcard() {
		return "跨域已全面開放（allowed_origins=\"*\"）：內網任何頁面都能讀取本服務端點。" +
			"此設定只應用於開發期聯調，正式部署請改回精確來源或留空。"
	}
	return fmt.Sprintf("跨域已放寬：%d 個來源（%s）；此設定多為開發期聯調所用，正式部署請確認是否需要保留。",
		len(cors.AllowedOrigins), strings.Join(cors.AllowedOrigins, ", "))
}

// wildcard 表示來源清單含 `*`。
func (c CORSConfig) wildcard() bool {
	for _, origin := range c.AllowedOrigins {
		if origin == "*" {
			return true
		}
	}
	return false
}

// summary 產生跨域策略的一行摘要；開啟時把放行來源原樣列出，
// 因為「哪幾個來源被放寬」是部署狀態，不是憑據，藏在日誌裡只會讓人以為沒開。
func (c CORSConfig) summary() string {
	if len(c.AllowedOrigins) == 0 {
		return "關閉"
	}
	return fmt.Sprintf("origins=%s credentials=%t max_age=%d",
		strings.Join(c.AllowedOrigins, "|"), c.AllowCredentials, c.MaxAgeSeconds)
}

// summary 回傳磁碟寫保護在啟動摘要裡的樣子。
//
// 未設下限時要說得明顯：這是 DEC-028 定下的取向——「設了正值才有上限」這件事必須讓部署者
// 在啟動輸出裡看得見，而不是藏在一份可能永遠不會被讀的組態檔註解裡。
func (d DiskConfig) summary() string {
	if d.MinFreeBytes == 0 && d.MinFreePercent <= 0 {
		return "未啟用（未設下限，不做寫保護）"
	}
	return fmt.Sprintf("min_free_bytes=%d min_free_percent=%g cache_ttl_ms=%d",
		d.MinFreeBytes, d.MinFreePercent, d.CheckIntervalMS)
}

// presence 將安全回應頭的覆寫值表示為「自訂」或「(預設)」，避免摘要輸出整段策略。
func presence(value string) string {
	if strings.TrimSpace(value) == "" {
		return "(預設)"
	}
	return "自訂"
}

// orDefault 回傳非空值，空值時回傳預設表示。
func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func redact(s string) string {
	if s == "" {
		return "(未設定)"
	}
	return "[REDACTED]"
}

// 環境變數覆蓋規則：ER_ 前綴 + 全大寫欄位名（如 ER_SERVER_LISTEN）。
// 環境變數優先於 config.yaml。

func applyEnv(cfg *Config) error {
	type strField struct {
		dst *string
		env string
	}
	strs := []strField{
		{&cfg.Server.Listen, "ER_SERVER_LISTEN"},
		{&cfg.Server.DataDir, "ER_SERVER_DATA_DIR"},
		{&cfg.Server.DisplayTimezone, "ER_SERVER_DISPLAY_TIMEZONE"},
		{&cfg.Database.Path, "ER_DATABASE_PATH"},
		{&cfg.Database.Transaction.BeginMode, "ER_DATABASE_TRANSACTION_BEGIN_MODE"},
		{&cfg.Database.Transaction.Nested, "ER_DATABASE_TRANSACTION_NESTED"},
		{&cfg.Media, "ER_MEDIA"},
		{&cfg.Documents, "ER_DOCUMENTS"},
		{&cfg.Attachments, "ER_ATTACHMENTS"},
		{&cfg.Backups, "ER_BACKUPS"},
		{&cfg.Logs.Dir, "ER_LOGS_DIR"},
		{&cfg.Logs.Level, "ER_LOGS_LEVEL"},
		{&cfg.Logs.FilePrefix, "ER_LOGS_FILE_PREFIX"},
		{&cfg.Security.RootPasswordHash, "ER_SECURITY_ROOT_PASSWORD_HASH"},
		{&cfg.Security.Headers.ContentSecurityPolicy, "ER_SECURITY_HEADERS_CONTENT_SECURITY_POLICY"},
		{&cfg.Security.Headers.FrameOptions, "ER_SECURITY_HEADERS_FRAME_OPTIONS"},
		{&cfg.Security.Headers.ReferrerPolicy, "ER_SECURITY_HEADERS_REFERRER_POLICY"},
		{&cfg.Security.Headers.PermissionsPolicy, "ER_SECURITY_HEADERS_PERMISSIONS_POLICY"},
	}
	for _, f := range strs {
		if v := os.Getenv(f.env); v != "" {
			*f.dst = v
		}
	}

	// 跨域來源以逗號分隔清單由環境變數給定：開發期不改組態檔就能放行本機來源，
	// 也正因如此，它不會被寫進正式部署的 config.yaml（該檔由範例模板生成）。
	if v := os.Getenv("ER_SECURITY_CORS_ALLOWED_ORIGINS"); v != "" {
		origins := []string{}
		for _, part := range strings.Split(v, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				origins = append(origins, trimmed)
			}
		}
		cfg.Security.CORS.AllowedOrigins = origins
	}

	type intField struct {
		dst *int
		env string
	}
	ints := []intField{
		{&cfg.Database.BusyTimeoutMS, "ER_DATABASE_BUSY_TIMEOUT_MS"},
		{&cfg.Database.Transaction.BusyRetryMax, "ER_DATABASE_TRANSACTION_BUSY_RETRY_MAX"},
		{&cfg.Database.Transaction.BusyRetryBackoffMS, "ER_DATABASE_TRANSACTION_BUSY_RETRY_BACKOFF_MS"},
		{&cfg.Database.Transaction.TimeoutMS, "ER_DATABASE_TRANSACTION_TIMEOUT_MS"},
		{&cfg.Security.SessionTTLHours, "ER_SECURITY_SESSION_TTL_HOURS"},
		{&cfg.Security.Hashing.MemoryKiB, "ER_SECURITY_HASHING_MEMORY_KB"},
		{&cfg.Security.Hashing.TimeCost, "ER_SECURITY_HASHING_TIME_COST"},
		{&cfg.Security.Hashing.Parallelism, "ER_SECURITY_HASHING_PARALLELISM"},
		{&cfg.Security.Hashing.KeyLength, "ER_SECURITY_HASHING_KEY_LENGTH"},
		{&cfg.Security.LoginGuard.FailLimit, "ER_SECURITY_LOGIN_GUARD_FAIL_LIMIT"},
		{&cfg.Security.LoginGuard.WindowMinutes, "ER_SECURITY_LOGIN_GUARD_WINDOW_MINUTES"},
		{&cfg.Security.LoginGuard.CooldownMinutes, "ER_SECURITY_LOGIN_GUARD_COOLDOWN_MINUTES"},
		{&cfg.Security.LoginGuard.SourceFailLimit, "ER_SECURITY_LOGIN_GUARD_SOURCE_FAIL_LIMIT"},
		{&cfg.Security.LoginGuard.MaxEntries, "ER_SECURITY_LOGIN_GUARD_MAX_ENTRIES"},
		{&cfg.Logs.RetentionDays, "ER_LOGS_RETENTION_DAYS"},
		{&cfg.Disk.CheckIntervalMS, "ER_DISK_CHECK_INTERVAL_MS"},
		{&cfg.Server.ReadHeaderTimeoutMS, "ER_SERVER_READ_HEADER_TIMEOUT_MS"},
		{&cfg.Server.ReadTimeoutMS, "ER_SERVER_READ_TIMEOUT_MS"},
		{&cfg.Server.WriteTimeoutMS, "ER_SERVER_WRITE_TIMEOUT_MS"},
		{&cfg.Server.IdleTimeoutMS, "ER_SERVER_IDLE_TIMEOUT_MS"},
		{&cfg.Server.RequestTimeoutMS, "ER_SERVER_REQUEST_TIMEOUT_MS"},
		{&cfg.Server.ShutdownTimeoutMS, "ER_SERVER_SHUTDOWN_TIMEOUT_MS"},
	}
	for _, f := range ints {
		if v := os.Getenv(f.env); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("config: 環境變數 %s 需為整數，實際為 %q", f.env, v)
			}
			*f.dst = n
		}
	}

	// 請求體上限為 int64，單獨解析以免在 32 位元平台溢位。
	if v := os.Getenv("ER_SERVER_MAX_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("config: 環境變數 ER_SERVER_MAX_BODY_BYTES 需為整數，實際為 %q", v)
		}
		cfg.Server.MaxBodyBytes = n
	}
	// 磁碟下限同理：min_free_bytes 動輒數十 GiB，放 int 會在 32 位元平台溢位；
	// min_free_percent 允許小數（5.5 這種寫法在 TB 級卷上才有意義），兩者都進不了上面那份 int 清單。
	if v := os.Getenv("ER_DISK_MIN_FREE_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("config: 環境變數 ER_DISK_MIN_FREE_BYTES 需為整數，實際為 %q", v)
		}
		cfg.Disk.MinFreeBytes = n
	}
	if v := os.Getenv("ER_DISK_MIN_FREE_PERCENT"); v != "" {
		n, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("config: 環境變數 ER_DISK_MIN_FREE_PERCENT 需為數字，實際為 %q", v)
		}
		cfg.Disk.MinFreePercent = n
	}
	return nil
}

// ExampleYAML 為首次啟動時寫入資料目錄的脫敏範例組態（不含任何真實憑據）。
const ExampleYAML = `# EvernightRealm 服務端組態（首次啟動自動建立）
#
# 本檔案不含真實憑據，也不會自動產生任何「出廠口令」。
# Root 憑據（security.root_password_hash）由伺服器本機的一次性命令寫入：
#   evernight-server init-root --password-stdin --data-dir <這個目錄>
# 它只從標準輸入讀口令（前兩行是口令與確認），存進檔案的是 Argon2id 編碼而不是明文，
# 而且這個欄位一旦有值就不再開放第二次初始化。
# 想知道現在有沒有 Root，用不寫任何東西的只讀命令：evernight-server root-status
# 修改後重啟服務端生效。

server:
  listen: "127.0.0.1:5206"          # HTTP 監聽地址；區域網部署時改為主機區域網 IP
  data_dir: "."                     # 執行資料目錄（預設 evernight-data/）
  display_timezone: "Asia/Shanghai" # 伺服器顯示時區；資料庫仍以 UTC 儲存

  # HTTP 層保護參數（單位：毫秒 / 位元組）；request 不得大於 write。
  read_header_timeout_ms: 5000      # 標頭讀取逾時
  read_timeout_ms: 15000            # 整個請求讀取逾時
  write_timeout_ms: 30000           # 回應寫入逾時
  idle_timeout_ms: 60000            # keep-alive 空閒逾時
  request_timeout_ms: 10000         # 單次處理期限（超過回 503）
  max_body_bytes: 1048576           # JSON 請求體上限（1 MiB）

database:
  path: "evernight.db"              # SQLite 檔案（相對 data_dir）
  busy_timeout_ms: 5000              # 鎖等待超時

media: "media/"                     # 媒體檔案
# documents / attachments / backups 與 media 同理，省略時沿用預設。

logs:
  dir: "logs/"
  level: "info"                     # debug | info | warn | error
  file_prefix: "evernight-run"      # 當日檔案名為 <前綴>.<YYYY-MM-DD>.log（依顯示時區的自然日分檔）
  retention_days: 0                 # 保留天數（含當日）；0 = 不限制、永不自動刪除
                                    # 要「日誌不會無限增大」必須在這裡設一個正值；淘汰只認得本服務的日誌檔名

disk:
  min_free_bytes: 0                 # 剩餘空間的絕對下限（位元組）；0 = 不按絕對值設限
  min_free_percent: 0               # 剩餘空間占卷總容量的下限百分比（如 5 = 5%）；0 = 不按比例設限
                                    # 兩條任一命中即判定空間不足（取較嚴者）；全為 0 時不做寫保護
  check_interval_ms: 10000          # 可用空間讀值的快取期限；0 = 每個寫入前都實測

security:
  session_ttl_hours: 24

  # 登入失敗控制與限流（純記憶體狀態：服務重啟即清空，不寫入資料庫）。
  # 計量主軸是「來源位址 × 登入目標」配對；來源級總量是橫掃大量帳戶時的補集。
  # 來源位址一律取實際連線（沒有可信代理約定，不採信任何轉發標頭）。
  login_guard:
    fail_limit: 10                  # 視窗內單一「來源×目標」的失敗上限
    window_minutes: 15              # 失敗計數的滑動視窗（分鐘）
    cooldown_minutes: 15            # 觸發後的冷卻長度（分鐘）；冷卻期內的嘗試不延長它
    source_fail_limit: 50           # 視窗內單一來源跨全部目標的失敗上限（不得低於 fail_limit）
    max_entries: 10000              # 限流條目總數上限（限流自身的記憶體封頂）

  # 憑據雜湊（Argon2id）參數檔：只在「新產生憑據」時生效，
  # 既有 Root 雜湊與帳戶雜湊按編碼內自帶參數校驗，換檔不影響登入。
  # 各欄留 0（或整段不寫）＝沿用生產預設（最低推薦檔：64 MiB、3 遍、4 並行、32B 摘要）。
  hashing:
    memory_kb: 0                    # 記憶體成本（KiB）；8192..1048576，0=預設
    time_cost: 0                    # 時間成本（遍數）；1..32，0=預設
    parallelism: 0                  # 並行度；1..8，0=預設
    key_length: 0                   # 摘要長度（位元組）；16..64，0=預設

  # HTTP 安全回應頭；留空即用內建預設，只有確實需要時才覆寫。
  # frame_options 可選 DENY | SAMEORIGIN；csp 不得含 'unsafe-eval'。
  headers:
    content_security_policy: ""       # 空 = 內建預設（相容本機 Flutter Web）
    frame_options: ""                 # 空 = DENY
    referrer_policy: ""               # 空 = no-referrer
    permissions_policy: ""            # 空 = camera=(self), microphone=(), geolocation=()

  # 跨來源（CORS）策略。預設完全關閉：不放行任何來源時，
  # 服務端不下發任何跨域標頭，瀏覽器端只能同源存取。
  # 開發期要讓瀏覽器直接呼叫本服務，才把頁面來源寫進來（或設環境變數
  # ER_SECURITY_CORS_ALLOWED_ORIGINS=http://127.0.0.1:8765）；正式部署留空。
  cors:
    allowed_origins: []               # 空 = 關閉；可寫 "*"... 但等於對內網所有頁面開放
    allowed_methods: [GET, HEAD, OPTIONS]
    allowed_headers: [Accept, Accept-Language, Content-Type, Idempotency-Key, X-Request-Id]
    exposed_headers: [X-Request-Id]   # 允許客戶端腳本讀回的回應標頭
    allow_credentials: false          # 與 "*" 同時使用會被拒絕啟動
    max_age_seconds: 600              # 預檢結果快取；0 = 不快取
`

// Resolve 將所有相對路徑欄位解析為資料目錄下的絕對路徑並清除冗餘片段。
// 相對路徑不得逃出資料目錄（拒絕路徑穿越）；絕對路徑原樣保留。
// 含空格與非 ASCII 字元的路徑由 Go 字串原生支援，不需額外處理。
func (c *Config) Resolve() error {
	absDir, err := filepath.Abs(c.Server.DataDir)
	if err != nil {
		return fmt.Errorf("config: 解析資料目錄 %q 失敗: %w", c.Server.DataDir, err)
	}
	dataDir := filepath.Clean(absDir)
	c.Server.DataDir = dataDir

	type field struct {
		dst  *string
		name string
	}
	fields := []field{
		{&c.Database.Path, "database.path"},
		{&c.Media, "media"},
		{&c.Documents, "documents"},
		{&c.Attachments, "attachments"},
		{&c.Backups, "backups"},
		{&c.Logs.Dir, "logs.dir"},
	}
	for _, f := range fields {
		resolved, err := joinWithin(dataDir, *f.dst)
		if err != nil {
			return fmt.Errorf("config: %s %v", f.name, err)
		}
		*f.dst = resolved
	}
	return nil
}

// joinWithin 將相對路徑解析於 base 內；絕對路徑保留。
func joinWithin(base, p string) (string, error) {
	if p == "" {
		return "", errors.New("不可為空")
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p), nil
	}
	resolved := filepath.Clean(filepath.Join(base, p))
	rel, err := filepath.Rel(base, resolved)
	if err != nil {
		return "", fmt.Errorf("解析失敗: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("路徑穿越拒絕: %q", p)
	}
	return resolved, nil
}

// ConfigFile 回傳組態檔的絕對路徑（資料目錄下的 config.yaml）。
//
// 這是「組態檔在哪」的唯一定義點：Prepare 用它建立範例組態，備份用它決定要收錄哪一份——
// 兩處各拼一次字串時，改動其中一處會讓備份收錄到一個不存在（或不是同一份）的檔案。
func (c Config) ConfigFile() string {
	return filepath.Join(c.Server.DataDir, "config.yaml")
}

// Prepare 建立資料目錄與子目錄、探測可寫性，並在缺少組態檔時寫入範例組態。
// 重複執行（重複啟動）為冪等操作。
func (c *Config) Prepare() error {
	dirs := []string{
		c.Server.DataDir,
		c.Media,
		c.Documents,
		c.Attachments,
		c.Backups,
		c.Logs.Dir,
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return fmt.Errorf("config: 建立目錄 %s 失敗: %w", d, err)
		}
	}

	// 可寫性探測：寫入後立即刪除，確保資料目錄實際可寫（SYS-010）。
	//
	// 檔名由建立器給：固定的「.write-probe」會讓同時跑了在同一個目錄上的兩個命令
	// 互相刪掉對方的探測檔（第二個 Remove 撞「檔案不存在」，於是啟動／子命令莫名失敗）。
	// 探測問的是「這個目錄能不能寫」，用不用同一個名字對答案沒有影響。
	probe, err := os.CreateTemp(c.Server.DataDir, ".write-probe-*")
	if err != nil {
		return fmt.Errorf("config: 資料目錄 %s 不可寫: %w", c.Server.DataDir, err)
	}
	probeName := probe.Name()
	if _, err := probe.Write([]byte("ok")); err != nil {
		_ = probe.Close()
		_ = os.Remove(probeName)
		return fmt.Errorf("config: 資料目錄 %s 不可寫: %w", c.Server.DataDir, err)
	}
	if err := probe.Close(); err != nil {
		_ = os.Remove(probeName)
		return fmt.Errorf("config: 資料目錄探測檔關閉失敗: %w", err)
	}
	if err := os.Remove(probeName); err != nil {
		return fmt.Errorf("config: 資料目錄清理失敗: %w", err)
	}

	configPath := c.ConfigFile()
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(configPath, []byte(ExampleYAML), 0o600); err != nil {
			return fmt.Errorf("config: 建立範例組態 %s 失敗: %w", configPath, err)
		}
	}
	return nil
}
