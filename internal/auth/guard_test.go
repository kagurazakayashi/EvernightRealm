package auth

import (
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 守衛測試全部走注入時鐘：時刻由 timeutil.Test 推進，不碰主機系統時間，
// 也不睡真實的秒——「冷卻到期」在這裡是一次 Advance，不是一段等待。

// guardTestClock 建立錨定在固定時刻的測試時鐘。
func guardTestClock() *timeutil.Test {
	return timeutil.NewTest(testBase)
}

// smallGuard 建一把小閾值的守衛：failLimit 次配對失敗、sourceLimit 次來源失敗，
// 視窗與冷卻固定 10 分鐘，方便把「觸發／到期」兩條界線釘死。
func smallGuard(t *testing.T, clock timeutil.Clock, failLimit, sourceLimit, maxEntries int) *LoginGuard {
	t.Helper()
	guard, err := NewLoginGuard(GuardConfig{
		FailLimit:       failLimit,
		Window:          10 * time.Minute,
		Cooldown:        10 * time.Minute,
		SourceFailLimit: sourceLimit,
		MaxEntries:      maxEntries,
	}, clock)
	if err != nil {
		t.Fatalf("建立守衛失敗：%v", err)
	}
	return guard
}

// mustAllow 斷言此刻不被擋，否則直接終止測試。
func mustAllow(t *testing.T, guard *LoginGuard, source, target string) {
	t.Helper()
	if blocked, retry := guard.Allow(source, target); blocked {
		t.Fatalf("%s→%s 不應被擋，實際冷卻剩 %v", source, target, retry)
	}
}

// mustBlock 斷言此刻被擋並回傳剩餘時間。
func mustBlock(t *testing.T, guard *LoginGuard, source, target string) time.Duration {
	t.Helper()
	blocked, retry := guard.Allow(source, target)
	if !blocked {
		t.Fatalf("%s→%s 應被擋，實際放行", source, target)
	}
	return retry
}

func TestGuardConsecutiveFailuresTriggerCooldown(t *testing.T) {
	clock := guardTestClock()
	guard := smallGuard(t, clock, 3, 9, 100)

	for i := 0; i < 2; i++ {
		mustAllow(t, guard, "10.0.0.1", "alice")
		if triggered := guard.RecordFailure("10.0.0.1", "alice"); triggered {
			t.Fatalf("第 %d 次失敗不該觸發冷卻", i+1)
		}
	}
	mustAllow(t, guard, "10.0.0.1", "alice")
	if triggered := guard.RecordFailure("10.0.0.1", "alice"); !triggered {
		t.Fatal("打滿上限的那一次必須上報觸發")
	}
	if retry := mustBlock(t, guard, "10.0.0.1", "alice"); retry != 10*time.Minute {
		t.Fatalf("冷卻剩餘應為完整 10 分鐘，實際 %v", retry)
	}
}

func TestGuardCooldownRecoversOnClockExpiry(t *testing.T) {
	clock := guardTestClock()
	guard := smallGuard(t, clock, 2, 9, 100)

	guard.RecordFailure("10.0.0.1", "alice")
	guard.RecordFailure("10.0.0.1", "alice")
	mustBlock(t, guard, "10.0.0.1", "alice")

	// 到期前一秒仍在冷卻；到期瞬間放行，且帶著全新的失敗預算（舊帳已隨觸發清空）。
	clock.Advance(10*time.Minute - time.Second)
	mustBlock(t, guard, "10.0.0.1", "alice")
	clock.Advance(time.Second)
	mustAllow(t, guard, "10.0.0.1", "alice")

	if triggered := guard.RecordFailure("10.0.0.1", "alice"); triggered {
		t.Fatal("冷卻解除後第一次失敗不該立刻再觸發（舊帳不續算）")
	}
}

func TestGuardBlockedAttemptsDoNotExtendCooldown(t *testing.T) {
	clock := guardTestClock()
	guard := smallGuard(t, clock, 2, 9, 100)

	guard.RecordFailure("10.0.0.1", "alice")
	guard.RecordFailure("10.0.0.1", "alice")

	// 冷卻期內持續轟炸：每次 Allow 都只是被擋，不記帳、不續命。
	for i := 0; i < 50; i++ {
		clock.Advance(10 * time.Second)
		mustBlock(t, guard, "10.0.0.1", "alice")
	}
	// 轟炸了 500 秒，但冷卻仍以最初的觸發為準：再等剩餘時間即解除。
	_, retry := guard.Allow("10.0.0.1", "alice")
	clock.Advance(retry)
	mustAllow(t, guard, "10.0.0.1", "alice")
}

func TestGuardSuccessClearsPairFailures(t *testing.T) {
	clock := guardTestClock()
	guard := smallGuard(t, clock, 3, 9, 100)

	guard.RecordFailure("10.0.0.1", "alice")
	guard.RecordFailure("10.0.0.1", "alice")
	guard.RecordSuccess("10.0.0.1", "alice")

	// 成功勾銷後要能再吃滿一整輪上限才觸發。
	for i := 0; i < 2; i++ {
		if triggered := guard.RecordFailure("10.0.0.1", "alice"); triggered {
			t.Fatalf("成功後的第 %d 次失敗不該觸發", i+1)
		}
	}
	if triggered := guard.RecordFailure("10.0.0.1", "alice"); !triggered {
		t.Fatal("成功後的第 3 次失敗必須觸發冷卻")
	}
}

func TestGuardSharedSourcePairIsolation(t *testing.T) {
	clock := guardTestClock()
	guard := smallGuard(t, clock, 2, 9, 100)

	// 同一出口位址：alice 打滿被擋，bob 與 root 各用各的預算。
	guard.RecordFailure("10.0.0.1", "alice")
	guard.RecordFailure("10.0.0.1", "alice")
	mustBlock(t, guard, "10.0.0.1", "alice")
	mustAllow(t, guard, "10.0.0.1", "bob")
	mustAllow(t, guard, "10.0.0.1", RootTarget)

	// 其他位址對 alice 也不受牽連：冷卻的單位是「來源×目標」。
	mustAllow(t, guard, "10.0.0.2", "alice")
}

func TestGuardSourceSweepTriggersSourceLevelCooldown(t *testing.T) {
	clock := guardTestClock()
	// 配對上限 2、來源上限 5：橫掃五個帳戶即可打滿來源級，但單一帳戶打滿不會。
	guard := smallGuard(t, clock, 2, 5, 100)

	for _, target := range []string{"t1", "t2"} {
		guard.RecordFailure("10.0.0.1", target)
		guard.RecordFailure("10.0.0.1", target)
	}
	// 第 5 次失敗跨兩個目標：來源級觸發。
	guard.RecordFailure("10.0.0.1", "t3")

	mustBlock(t, guard, "10.0.0.1", "t3")
	mustBlock(t, guard, "10.0.0.1", "any-new-target")
	// 來源級冷卻不波及其他位址，也不因某個配對成功而解除（見 RecordSuccess 註解）。
	mustAllow(t, guard, "10.0.0.2", "t3")
}

func TestGuardWindowDecaysOldFailures(t *testing.T) {
	clock := guardTestClock()
	guard := smallGuard(t, clock, 3, 9, 100)

	guard.RecordFailure("10.0.0.1", "alice")
	guard.RecordFailure("10.0.0.1", "alice")
	clock.Advance(10*time.Minute + time.Second)
	// 舊帳滑出視窗：再失敗一次只算第一筆。
	if triggered := guard.RecordFailure("10.0.0.1", "alice"); triggered {
		t.Fatal("滑出視窗的舊失敗不該計入")
	}
	mustAllow(t, guard, "10.0.0.1", "alice")
}

func TestGuardMaxEntriesBoundsMemory(t *testing.T) {
	clock := guardTestClock()
	// 來源上限放到 999：本測試只驗「表長封頂」，不該先被來源級冷卻搶跑。
	guard := smallGuard(t, clock, 2, 999, 10)

	// 100 個不同的隨機鍵各失敗一次：表長必須封頂在 max_entries。
	for i := 0; i < 100; i++ {
		guard.RecordFailure("10.0.0.1", string(rune('a'+i%26))+string(rune('A'+i/26)))
	}
	if n := guard.entryCount(); n > 10 {
		t.Fatalf("條目數 %d 超過封頂值 10", n)
	}
	// 封頂不製造錯誤：新鍵照常可記帳。
	mustAllow(t, guard, "10.0.0.1", "zz")
	guard.RecordFailure("10.0.0.1", "zz")
}

func TestGuardEvictionKeepsActiveCooldownsFirst(t *testing.T) {
	clock := guardTestClock()
	guard := smallGuard(t, clock, 2, 999, 8)

	// 先把表填滿殭屍條目（各失敗一次後讓視窗滑過，條目既不冷卻也無視窗內失敗）。
	for i := 0; i < 6; i++ {
		guard.RecordFailure("10.0.0.1", string(rune('a'+i)))
	}
	clock.Advance(11 * time.Minute)
	// 塞入冷卻中的條目＋更多新鍵，逼出回收：先清殭屍，不逐出冷卻中的鍵。
	guard.RecordFailure("10.0.0.1", "hot")
	guard.RecordFailure("10.0.0.1", "hot")
	mustBlock(t, guard, "10.0.0.1", "hot")
	for i := 0; i < 20; i++ {
		guard.RecordFailure("10.0.0.1", string(rune('A'+i%26))+string(rune('0'+i/26)))
	}
	mustBlock(t, guard, "10.0.0.1", "hot")
}

func TestGuardEmptySourceIsNotMetered(t *testing.T) {
	clock := guardTestClock()
	guard := smallGuard(t, clock, 2, 2, 100)

	for i := 0; i < 5; i++ {
		guard.RecordFailure("", "alice")
	}
	mustAllow(t, guard, "", "alice")
	if n := guard.entryCount(); n != 0 {
		t.Fatalf("空來源不該產生條目，實際 %d", n)
	}
}

func TestGuardConcurrentFailuresTriggerOnce(t *testing.T) {
	clock := guardTestClock()
	guard := smallGuard(t, clock, 10, 999, 100)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			guard.RecordFailure("10.0.0.1", "alice")
			// Allow 併發讀取同一路徑，驗證鎖內判定與記帳不會互相踩到。
			guard.Allow("10.0.0.1", "alice")
		}()
	}
	wg.Wait()

	// 32 發失敗遠超上限 10：無論交錯順序如何，最終必須處於冷卻。
	mustBlock(t, guard, "10.0.0.1", "alice")
	if n := guard.entryCount(); n != 2 {
		t.Fatalf("配對與來源各一條，實際 %d", n)
	}
}

func TestGuardZeroConfigFallsBackToApprovedDefaults(t *testing.T) {
	clock := guardTestClock()
	guard, err := NewLoginGuard(GuardConfig{}, clock)
	if err != nil {
		t.Fatalf("零值閾值應回落預設： %v", err)
	}
	// 預設配對上限 10：前 9 次放行、第 10 次觸發；來源上限 50 不該搶先。
	for i := 0; i < 9; i++ {
		if triggered := guard.RecordFailure("10.0.0.1", "alice"); triggered {
			t.Fatalf("預設上限 10，第 %d 次不該觸發", i+1)
		}
	}
	if triggered := guard.RecordFailure("10.0.0.1", "alice"); !triggered {
		t.Fatal("預設上限 10：第 10 次必須觸發")
	}
	mustBlock(t, guard, "10.0.0.1", "alice")
	// 預設冷卻 15 分鐘。
	if _, retry := guard.Allow("10.0.0.1", "alice"); retry != 15*time.Minute {
		t.Fatalf("預設冷卻應為 15 分鐘，實際 %v", retry)
	}
}

func TestGuardConfigValidation(t *testing.T) {
	// 來源級低於配對級、零與負數、超界值都必須在構造門外被拒。
	for name, cfg := range map[string]GuardConfig{
		"來源低於配對":  {FailLimit: 10, SourceFailLimit: 5},
		"負上限":     {FailLimit: -1},
		"超界上限":    {FailLimit: guardMaxLimit + 1},
		"零視窗由預設補": {}, // 這是唯一合法的特例：0=沿用預設，不列入拒絕清單
	} {
		_, err := NewLoginGuard(cfg, timeutil.System())
		if name == "零視窗由預設補" {
			if err != nil {
				t.Fatalf("%s：零值應回落預設，實際 %v", name, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s：非法閾值必須被拒", name)
		}
	}
}
