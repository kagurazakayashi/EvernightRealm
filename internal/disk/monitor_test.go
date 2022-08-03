package disk

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// probeFunc 記錄被實際呼叫了幾次，用來證明「未設下限就不發系統呼叫」與快取生效。
type probeFunc struct {
	calls int
	free  uint64
	total uint64
	err   error
}

func (p *probeFunc) at(string) (uint64, uint64, error) {
	p.calls++
	return p.free, p.total, p.err
}

func testMonitor(t *testing.T, th Thresholds, ttl time.Duration, p Prober) (*Monitor, *timeutil.Test) {
	t.Helper()
	clock := timeutil.NewTest(time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC))
	return newWithProber("evernight-data/dev", th, ttl, clock, p), clock
}

func TestVerifyDoesNotProbeWhenUnlimited(t *testing.T) {
	probe := &probeFunc{free: 1, total: 1 << 40}
	m, _ := testMonitor(t, Thresholds{}, time.Minute, probe.at)

	verdict, err := m.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != StatusOK {
		t.Errorf("未設下限應回 OK，實際 %v", verdict.Status)
	}
	if probe.calls != 0 {
		t.Errorf("未設下限卻仍發了 %d 次系統呼叫", probe.calls)
	}
}

func TestVerifyCachesWithinTTLAndReprobesAfter(t *testing.T) {
	probe := &probeFunc{free: 4 << 30, total: 100 << 30}
	m, clock := testMonitor(t, Thresholds{MinFreeBytes: 8 << 30}, 15*time.Second, probe.at)

	for i := 0; i < 5; i++ {
		verdict, err := m.Verify()
		if err != nil {
			t.Fatal(err)
		}
		if verdict.Status != StatusLow {
			t.Fatalf("第 %d 次判定 = %v，want low", i+1, verdict.Status)
		}
	}
	if probe.calls != 1 {
		t.Errorf("TTL 內呼叫了 %d 次探測，want 1", probe.calls)
	}

	// 清出空間後，TTL 未過時仍讀到舊判定——這是快取的代價，必須是已知的而不是意外發現的。
	probe.free = 90 << 30
	if verdict, _ := m.Verify(); verdict.Status != StatusLow {
		t.Errorf("TTL 未過時應沿用快取，實際 %v", verdict.Status)
	}

	clock.Advance(15 * time.Second)
	verdict, err := m.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != StatusOK {
		t.Errorf("TTL 過期後應重新探測並轉為 OK，實際 %v", verdict.Status)
	}
	if probe.calls != 2 {
		t.Errorf("總共探測 %d 次，want 2", probe.calls)
	}
}

func TestZeroTTLProbesEveryTime(t *testing.T) {
	probe := &probeFunc{free: 100 << 30, total: 100 << 30}
	m, _ := testMonitor(t, Thresholds{MinFreeBytes: 1}, 0, probe.at)

	for i := 0; i < 3; i++ {
		if _, err := m.Verify(); err != nil {
			t.Fatal(err)
		}
	}
	if probe.calls != 3 {
		t.Errorf("TTL=0 時探測 %d 次，want 3（每筆都實測）", probe.calls)
	}
}

// TestProbeFailureIsUnknownNotLow 固定本套件最容易被改壞的一條取捨：
// 查不到時不攔寫入，但要把原因留下來。
func TestProbeFailureIsUnknownNotLow(t *testing.T) {
	probe := &probeFunc{err: errors.New("Access is denied.")}
	m, _ := testMonitor(t, Thresholds{MinFreeBytes: 1 << 30}, time.Minute, probe.at)

	verdict, err := m.Verify()
	if err != nil {
		t.Fatalf("探測失敗是判定結果的一種，不應回錯誤：%v", err)
	}
	if verdict.Status != StatusUnknown {
		t.Errorf("狀態 = %v，want unknown", verdict.Status)
	}
	if !strings.Contains(verdict.Reason, "Access is denied.") || !strings.Contains(verdict.Reason, "evernight-data/dev") {
		t.Errorf("原因要點得出目錄與原始錯誤：%q", verdict.Reason)
	}
	if err := m.Guard()(); err != nil {
		t.Errorf("unknown 不應攔住寫入：%v", err)
	}
}

func TestGuardMapsStatuses(t *testing.T) {
	cases := []struct {
		name    string
		th      Thresholds
		free    uint64
		wantErr error
	}{
		{"足夠時放行", Thresholds{MinFreeBytes: 1 << 30}, 50 << 30, nil},
		{"不足時拒絕", Thresholds{MinFreeBytes: 1 << 30}, 512 << 20, ErrNoSpace},
		{"未設下限時放行", Thresholds{}, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := &probeFunc{free: tc.free, total: 100 << 30}
			m, _ := testMonitor(t, tc.th, time.Minute, probe.at)
			err := m.Guard()()
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("應放行，實際 %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("錯誤 = %v，want %v", err, tc.wantErr)
			}
			// 拒絕的原因要跟著錯誤出去，否則呼叫端只能回一句「空間不足」而排錯的人查不到門檻。
			if !strings.Contains(err.Error(), "低於") {
				t.Errorf("錯誤未帶判定原因：%v", err)
			}
		})
	}
}

func TestVerifyPropagatesUnusableThreshold(t *testing.T) {
	probe := &probeFunc{free: 1, total: 100}
	m, _ := testMonitor(t, Thresholds{MinFreePercent: 400}, time.Minute, probe.at)

	if _, err := m.Verify(); err == nil {
		t.Fatal("下限不合法時要回錯誤，不能回一個看起來像結論的狀態")
	}
	if err := m.Guard()(); err == nil {
		t.Error("Guard 在同樣情況下也必須失敗（放行與攔截都是猜）")
	}
}

func TestConcurrentVerifyIsSafeAndSingleFlighted(t *testing.T) {
	probe := &probeFunc{free: 50 << 30, total: 100 << 30}
	m, _ := testMonitor(t, Thresholds{MinFreeBytes: 1 << 30}, time.Minute, probe.at)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Verify(); err != nil {
				t.Errorf("併發判定回錯：%v", err)
			}
			_ = m.Guard()()
		}()
	}
	wg.Wait()
	if probe.calls == 0 {
		t.Error("設了下限卻一次都沒探測")
	}
}

func TestEnabledDistinguishesUnlimitedFromPassing(t *testing.T) {
	// 「沒設下限」與「設了且剛好通過」在日誌與啟動摘要裡必須能分開表達，
	// 否則部署者會以為保護開著。
	if New("x", Thresholds{}, time.Minute, nil).Enabled() {
		t.Error("未設下限時不應視為啟用")
	}
	for _, th := range []Thresholds{{MinFreeBytes: 1}, {MinFreePercent: 5}} {
		if !New("x", th, time.Minute, nil).Enabled() {
			t.Errorf("%+v 應視為啟用", th)
		}
	}
}

func TestNewDefaultsToRealProberAndSystemClock(t *testing.T) {
	// 真實探測在測試裡也要跑得出結果：這支是「標準庫到底能不能用」的現場證據，
	// 尤其 Windows 側走的是 golang.org/x/sys/windows 而非 syscall。
	m := New(t.TempDir(), Thresholds{MinFreeBytes: 1}, time.Minute, nil)
	verdict, err := m.Verify()
	if err != nil {
		t.Fatal(err)
	}
	switch verdict.Status {
	case StatusOK, StatusLow:
	default:
		t.Fatalf("對暫時目錄應取得到實際數值：%+v", verdict)
	}
	if verdict.Usage.Total == 0 || verdict.Usage.CheckedAt.IsZero() {
		t.Errorf("事實欄位未填齊：%+v", verdict.Usage)
	}
	if !verdict.Usage.CheckedAt.UTC().Equal(verdict.Usage.CheckedAt) {
		t.Errorf("CheckedAt 必須是 UTC（DEC-015）：%v", verdict.Usage.CheckedAt)
	}
}
