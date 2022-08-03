package disk

import (
	"fmt"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// Prober 是一次「取指定目錄所在卷的可用空間」的呼叫，抽成欄位是為了在單元層測失敗路徑。
//
// 正式來源只有 volumeSpace 一個；注入別實作的唯一用途是讓「查不到」這種情況
// 能在測試裡穩定出現——真把開發機寫滿來測判定，證明的反而是另一件事。
type Prober func(path string) (free, total uint64, err error)

// Monitor 是磁碟空間判定的唯一出口：惰性探測、短快取、依閾值給出三態結果。
//
// 為什麼要快取（本專案的拍板）：判定讀的是卷級資訊，寫請求一個接一個時每次都發系統呼叫
// 沒有意義；但把值緩存太久又會讓「剛清完空間就還在拒寫」變成常態。故 TTL 是可配的，
// 且 0 表示不緩存、每筆都實測。
//
// 零值不可用，請經 New 取得。
type Monitor struct {
	path    string
	th      Thresholds
	ttl     time.Duration
	clock   timeutil.Clock
	probe   Prober
	mu      sync.Mutex
	cached  *Verdict
	fetched time.Time
}

// New 建立監測器。
//
// path 是判定所依據的目錄（資料目錄，即資料庫與日誌實際落盤的地方）；
// th 兩條下限都為 0 時判定等於關閉（Unlimited 為真，一律回 StatusOK 且不發系統呼叫）；
// ttl 是快取期限，0 表示每筆都實測；clock 為 nil 時採用 timeutil.System()。
func New(path string, th Thresholds, ttl time.Duration, clock timeutil.Clock) *Monitor {
	if clock == nil {
		clock = timeutil.System()
	}
	if ttl < 0 {
		ttl = 0
	}
	return &Monitor{path: path, th: th, ttl: ttl, clock: clock, probe: volumeSpace}
}

// newWithProber 給單元層注入探測實作。
func newWithProber(path string, th Thresholds, ttl time.Duration, clock timeutil.Clock, probe Prober) *Monitor {
	m := New(path, th, ttl, clock)
	m.probe = probe
	return m
}

// Enabled 回傳本監測器是否真的在做判定（等同於「至少設了一條下限」）。
//
// 存在的理由是要把「未啟用」與「啟用了但剛好通過」分開：未啟用時 Verify 回的那個
// StatusOK 不含任何探測事實（Usage 是零值），把它記成一行「status=ok free=0 total=0」
// 會讓排錯的人以為讀到過一個 0 容量的卷。
func (m *Monitor) Enabled() bool { return !m.th.Unlimited() }

// Verify 回傳最近一次的判定。
//
// 下限未設時直接回 StatusOK 且不發系統呼叫——「沒有設定保護」與「設定為很寬」是兩件事，
// 前者不該付出任何探測成本，也不該在日誌裡留下看似已檢查過的記錄。
//
// 探測在持鎖期間進行：GetDiskFreeSpaceEx 與 Statfs 都是微秒級的本地呼叫，
// 串行化比「先解鎖再併發探測、回來雙重檢查」少一整條競態路徑，而這裡沒有可以等待的東西。
func (m *Monitor) Verify() (Verdict, error) {
	if m.th.Unlimited() {
		return Verdict{Status: StatusOK}, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cached != nil && m.ttl > 0 && m.clock.Now().Sub(m.fetched) < m.ttl {
		return *m.cached, nil
	}

	free, total, err := m.probe(m.path)
	if err != nil {
		// 查不到不攔寫入（見套件註釋），但原因必須留得下來：/ready 要據此報不就緒，
		// 而排錯的人要知道的是哪個目錄、什麼錯誤。
		verdict := Verdict{Status: StatusUnknown, Usage: Usage{Path: m.path, Total: total, Free: free},
			Reason: fmt.Sprintf("取得 %s 所在卷的可用空間失敗：%v", m.path, err)}
		m.cached, m.fetched = &verdict, m.clock.Now()
		return verdict, nil
	}

	usage := Usage{Path: m.path, Free: free, Total: total, CheckedAt: m.clock.Now()}
	verdict, err := m.th.Evaluate(usage)
	if err != nil {
		// 只有下限本身不合法時走到這裡（組態階段已校驗過，這是防呆不是常規路徑）：
		// 回錯誤而不是一個看起來像結論的狀態，否則配錯的閾值會被讀成「空間足夠」。
		return Verdict{}, err
	}
	m.cached, m.fetched = &verdict, usage.CheckedAt
	return verdict, nil
}

// Guard 回傳可直接交給寫入路徑的前置檢查：不足時回 ErrNoSpace，其餘情況回 nil。
//
// StatusUnknown 回 nil 是刻意的：把「探測失敗」升格成「拒絕服務」會讓一個系統呼叫的抖動
// 變成整站寫不進去，而那個故障比它要防的那個更常發生。SQLite 自己在空間耗盡時會失敗，
// 交易層的整體回滾保證不會留下半筆（DEC-013），所以這裡放行的代價是有界的。
//
// 判定失敗（下限不合法）回錯誤：那種情況下放行與攔截都是猜，不如讓呼叫端當場失敗。
func (m *Monitor) Guard() func() error {
	return func() error {
		verdict, err := m.Verify()
		if err != nil {
			return err
		}
		if verdict.Status == StatusLow {
			return fmt.Errorf("%w：%s", ErrNoSpace, verdict.Reason)
		}
		return nil
	}
}
