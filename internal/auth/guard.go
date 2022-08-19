// guard.go 是登入失敗控制與限流的核心：一臺在記憶體裡、容量封頂的失敗計數器。
//
// 它回答三個問題，而且只由登入用例（service.go）提問：
//   - Allow：這個來源位址現在還允許對這個目標嘗試登入嗎？（冷卻中就回否＋剩餘時間）
//   - RecordFailure：一次被拒的憑據嘗試要記在帳上；
//   - RecordSuccess：一次成功登入把該「來源×目標」的失敗帳一筆勾銷。
//
// 三條邊界決定本檔的全部形狀：
//
//  1. 有限資源佔用。每「來源×目標」一個條目、每來源一個總量條目，條目內只保留
//     滑動視窗內的失敗時刻（長度不超過上限值本身）；條目總數由 MaxEntries 封頂，
//     滿員時先回收早已不活躍的舊條目，再逐出最久未觸碰的——攻擊者用海量隨機
//     登入名「餵」限流鍵來耗盡記憶體的路線，在這一條封頂面前不成立。
//  2. 區域網共享來源。計量主軸是「來源×目標」配對：同一出口位址後面的眾多使用者
//     各有自己的配對預算，某個帳戶被擋不波及其他人。來源級的跨目標總量
//     （SourceFailLimit）閾值刻意高出很多，只在「一個位址橫掃大量帳戶」這種
//     配對計量擋不住的形態下才把整個源頭冷卻——它是補集，不是主閘。
//  3. 不可枚舉。本模組不區分「帳戶存不存在」：查無此人的嘗試與真帳戶的失敗嘗試
//     走同一個鍵、同一組閾值、同一個冷卻——對外永遠是同一句「嘗試過多請稍後再試」，
//     沒有任何回應能指出「是哪個帳戶觸發了限制」。冷卻中的配對被逐出也不改變
//     任何其他配對的可見行為。
//
// 狀態只存在於進程記憶體：服務重啟即清空（已批准語意——能重啟服務的對象已在本機；
// 持久化冷卻反而把每次失敗變成資料庫寫入，與「有限資源佔用」相悖）。
// 時刻一律取自注入時鐘，測試可任意推進而不動主機系統時間。
package auth

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// RootTarget 是 Root 登入端點在守衛裡的目標標識。
//
// 它是一個保留字：普通帳戶路徑的鍵一律由登入名正規化派生並帶 isSource=false，
// 而 Root 端點只用自己的固定鍵——兩類條目同表共存卻互不冒充，Root 冷卻
// 也不依賴 accounts 表的任何狀態。
const RootTarget = "root"

// 守衛預設參數（使用者批准的預設值；組態可覆蓋，見 config.LoginGuardConfig）。
const (
	defaultGuardFailLimit       = 10
	defaultGuardWindow          = 15 * time.Minute
	defaultGuardCooldown        = 15 * time.Minute
	defaultGuardSourceFailLimit = 50
	defaultGuardMaxEntries      = 10000
)

// GuardConfig 是登入守衛的閾值組。零值欄位逐一回落上方預設；
// 負值或超界正值由 NewLoginGuard 拒絕——把「打錯一個數量級」關在構造門外，
// 而不是讓服務帶著 0 次上限開門（那等於對所有人永久拒絕登入）。
type GuardConfig struct {
	// FailLimit 是單一「來源×目標」在滑動視窗內的失敗上限。
	FailLimit int
	// Window 是失敗計數的滑動視窗長度。
	Window time.Duration
	// Cooldown 是觸發上限後的冷卻長度；冷卻期內被擋的嘗試不延長它。
	Cooldown time.Duration
	// SourceFailLimit 是單一來源跨全部目標在視窗內的失敗上限。
	SourceFailLimit int
	// MaxEntries 是守衛條目總數上限（配對條目與來源條目合併計數）。
	MaxEntries int
}

// 守衛各欄位的硬界限：下限 1（0 意味著「一次都不允許」或「表不裝東西」，
// 都不是有效策略），上限取決於「這個值本身還構不構成資源風險」。
const (
	guardMaxLimit    = 10000  // 失敗上限：再高就不是防暴力破解而是記帳了
	guardMaxEntries  = 100000 // 條目上限：每條目 O(百位元組)，十萬條仍在十 MB 量級
	guardMaxDuration = 24 * time.Hour
)

// gKey 是守衛條目的索引鍵。用結構體而不是字串拼接：
// source 與 target 都是外部輸入，任何分隔符方案都要論證「它不會出現在輸入裡」，
// 而結構體欄位天然不給碰撞留縫隙。
type gKey struct {
	// isSource 標記這是「來源總量」條目（true，此時 target 恆為空）
	// 還是「來源×目標」配對條目（false）。
	isSource bool
	source   string
	target   string
}

// gEntry 是一個守衛條目：視窗內的失敗時刻與冷卻截止。
//
// failures 按時刻遞增存放：長度不超過該條目的上限值，所以「一個來源製造幾萬次
// 失敗」的記憶體佔用停在常數上。key 回存一份，讓 LRU 逐出時能不經額外參數
// 從 map 移除同一條目。
type gEntry struct {
	key           gKey
	failures      []time.Time
	cooldownUntil time.Time
}

// LoginGuard 是執行緒安全的登入失敗計數器。零值不可用，請經 NewLoginGuard 取得。
//
// 並發語意：判定與記帳在同一把鎖內完成，因此「同時兩發打滿最後一次額度」不會
// 把上限打穿——冷卻由先取得鎖的那次觸發，後者看到的已是冷卻中的條目。
// 不做背景刷新、不起 goroutine：條目回收發生在「要放新條目」的那一刻，
// 空閒時記憶體佔用單調不增，也沒有需要管理生命週期的執行緒。
type LoginGuard struct {
	mu      sync.Mutex
	cfg     GuardConfig
	clock   timeutil.Clock
	entries map[gKey]*list.Element
	// lru 的元素值為 *gEntry，front 為最近觸碰。
	lru *list.List
}

// NewLoginGuard 以閾值組與時鐘建立守衛；nil 時鐘視為系統時鐘。
func NewLoginGuard(cfg GuardConfig, clock timeutil.Clock) (*LoginGuard, error) {
	if cfg.FailLimit == 0 {
		cfg.FailLimit = defaultGuardFailLimit
	}
	if cfg.Window == 0 {
		cfg.Window = defaultGuardWindow
	}
	if cfg.Cooldown == 0 {
		cfg.Cooldown = defaultGuardCooldown
	}
	if cfg.SourceFailLimit == 0 {
		cfg.SourceFailLimit = defaultGuardSourceFailLimit
	}
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = defaultGuardMaxEntries
	}
	if cfg.FailLimit < 1 || cfg.FailLimit > guardMaxLimit {
		return nil, fmt.Errorf("auth: 登入守衛 fail_limit 需為 1..%d，實際為 %d", guardMaxLimit, cfg.FailLimit)
	}
	if cfg.SourceFailLimit < 1 || cfg.SourceFailLimit > guardMaxLimit {
		return nil, fmt.Errorf("auth: 登入守衛 source_fail_limit 需為 1..%d，實際為 %d", guardMaxLimit, cfg.SourceFailLimit)
	}
	if cfg.MaxEntries < 1 || cfg.MaxEntries > guardMaxEntries {
		return nil, fmt.Errorf("auth: 登入守衛 max_entries 需為 1..%d，實際為 %d", guardMaxEntries, cfg.MaxEntries)
	}
	if cfg.Window < time.Second || cfg.Window > guardMaxDuration {
		return nil, fmt.Errorf("auth: 登入守衛 window 需為 1 秒..24 小時，實際為 %v", cfg.Window)
	}
	if cfg.Cooldown < time.Second || cfg.Cooldown > guardMaxDuration {
		return nil, fmt.Errorf("auth: 登入守衛 cooldown 需為 1 秒..24 小時，實際為 %v", cfg.Cooldown)
	}
	// 來源總量至少要不低於配對上限，否則「單一帳戶打滿配對上限」會順帶鎖死整個源頭——
	// 共享出口的區域網立刻全滅，這與「配對為主軸」的設計相矛盾。
	if cfg.SourceFailLimit < cfg.FailLimit {
		return nil, fmt.Errorf("auth: 登入守衛 source_fail_limit(%d) 不得低於 fail_limit(%d)",
			cfg.SourceFailLimit, cfg.FailLimit)
	}
	if clock == nil {
		clock = timeutil.System()
	}
	return &LoginGuard{
		cfg:     cfg,
		clock:   clock,
		entries: make(map[gKey]*list.Element),
		lru:     list.New(),
	}, nil
}

// Allow 回報該來源此刻是否還能對該目標嘗試登入。
//
// blocked 為 true 時，retryAfter 是「配對與來源兩個冷卻都解除」所需的時間——
// 告訴客戶端更早的時刻只會換來一次同樣的被拒。被擋的嘗試不做任何記帳：
// 冷卻按觸發時刻固定到期（恢復語意確定，攻擊者不能用持續轟炸把冷卻無限期續命），
// 同時這也是一條完全不觸碰資料庫、審計與口令派生的路徑。
//
// 來源為空字串時回「不擋」：空來源意味著傳輸層沒有給出可計量的位址，
// 這是裝配缺陷的信號，照常走正常流程即可，而不是讓所有空來源請求共用一堵牆。
func (g *LoginGuard) Allow(source, target string) (blocked bool, retryAfter time.Duration) {
	if source == "" {
		return false, 0
	}
	now := g.clock.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, key := range [2]gKey{
		{source: source, target: target},
		{isSource: true, source: source},
	} {
		elem, ok := g.entries[key]
		if !ok {
			continue
		}
		entry := elem.Value.(*gEntry)
		if rem := entry.cooldownUntil.Sub(now); rem > 0 {
			g.lru.MoveToFront(elem)
			if rem > retryAfter {
				retryAfter = rem
			}
			blocked = true
		}
	}
	return blocked, retryAfter
}

// RecordFailure 記下一次被拒的憑據嘗試：配對條目與來源條目各進一筆。
//
// 任一條目累計到上限即進入冷卻，並清空該條目的失敗時刻——冷卻到期後該條目
// 帶著全新的預算回來（而不是「一出獄就被同一批舊帳再鎖一次」）。
// 兩個條目各自獨立判定：配對打滿只冷卻該配對；來源打滿冷卻該源頭的一切登入。
//
// 回傳 triggered 表示「這一次失敗把某個條目推進了冷卻」。呼叫端用它決定要不要
// 留下 Warn 級記錄：觸發每個條目每視窗至多一次，因此日誌量有界；
// 反之心來一筆記一筆的寫法會在冷卻期被轟炸時製造無界日誌放大。
func (g *LoginGuard) RecordFailure(source, target string) (triggered bool) {
	if source == "" {
		return false
	}
	now := g.clock.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	a := g.bump(gKey{source: source, target: target}, g.cfg.FailLimit, now)
	b := g.bump(gKey{isSource: true, source: source}, g.cfg.SourceFailLimit, now)
	return a || b
}

// RecordSuccess 勾銷一次成功登入：該「來源×目標」的失敗帳整體刪除。
//
// 來源條目刻意不清：源頭後面的合法用戶成功，不代表該源頭的橫掃歷史可以作廢——
// 來源級計量只隨滑動視窗自然衰減。成功也不解除任何冷卻：冷卻中的條目根本到不了
// 這裡（Allow 先擋），能走到這裡的成功都發生在正常通路上。
func (g *LoginGuard) RecordSuccess(source, target string) {
	if source == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	key := gKey{source: source, target: target}
	if elem, ok := g.entries[key]; ok {
		delete(g.entries, key)
		g.lru.Remove(elem)
	}
}

// entryCount 回傳當前條目總數，僅供測試觀察封頂是否生效。
func (g *LoginGuard) entryCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.entries)
}

// bump 對 key 對應的條目記一次失敗；條目不存在時先確保容量再建立。
//
// 失敗時刻恆不遞減（同一時鐘單調推進），所以視窗修剪只從頭部丟；修剪後
// 長度必小於上限，追加不會越界。達到上限即轉入冷卻並清空時刻清單，
// 並回傳 true 讓呼叫端知道「就是這一次把閘門放下」。
func (g *LoginGuard) bump(key gKey, limit int, now time.Time) (triggered bool) {
	elem, ok := g.entries[key]
	if !ok {
		elem = g.insert(key)
	}
	g.lru.MoveToFront(elem)
	entry := elem.Value.(*gEntry)

	cutoff := now.Add(-g.cfg.Window)
	drop := 0
	for drop < len(entry.failures) && entry.failures[drop].Before(cutoff) {
		drop++
	}
	if drop > 0 {
		entry.failures = append(entry.failures[:0], entry.failures[drop:]...)
	}
	entry.failures = append(entry.failures, now)

	if len(entry.failures) >= limit {
		entry.cooldownUntil = now.Add(g.cfg.Cooldown)
		entry.failures = nil
		return true
	}
	return false
}

// insert 在條目已滿時先回收再放入新鍵，保證表長恆不超過封頂值。
//
// 回收順序服從「保秩序、不保攻擊者」：先清既不冷卻、視窗內也無失敗的殭屍條目；
// 若全表都在冷卻（表被冷卻中的鍵塞滿）才退而逐出最久未觸碰的——那種局面下
// 各源頭已被來源級冷卻罩住，逐出個別配對不給攻擊者新增可用預算。
func (g *LoginGuard) insert(key gKey) *list.Element {
	now := g.clock.Now()
	if len(g.entries) >= g.cfg.MaxEntries {
		g.reclaim(now)
	}
	for len(g.entries) >= g.cfg.MaxEntries {
		g.evictOldest(now)
	}
	entry := &gEntry{key: key}
	elem := g.lru.PushFront(entry)
	g.entries[key] = elem
	return elem
}

// reclaim 按 LRU 從尾部清除不活躍條目以騰出位置。
//
// 「不活躍」以時鐘現況判定：不在冷卻，且視窗內沒有任何失敗時刻
// （failures 遞增，檢查最後一個即可）。找不到可清的就原樣返回，
// 由 insert 的兜底迴圈接手逐出。
func (g *LoginGuard) reclaim(now time.Time) {
	cutoff := now.Add(-g.cfg.Window)
	elem := g.lru.Back()
	for elem != nil {
		prev := elem.Prev()
		entry := elem.Value.(*gEntry)
		inCooldown := entry.cooldownUntil.After(now)
		hasFreshFailure := len(entry.failures) > 0 && !entry.failures[len(entry.failures)-1].Before(cutoff)
		if !inCooldown && !hasFreshFailure {
			delete(g.entries, entry.key)
			g.lru.Remove(elem)
		}
		elem = prev
	}
}

// evictOldest 是表被塞滿時的最後手段：從 LRU 尾部找「當前不在冷卻」的最舊條目逐出，
// 全表都在冷卻才逐出尾部——冷卻中的鍵被海量新鍵擠掉，等於給轟炸者免費補發預算，
// 這是封頂策略裡最不該發生的一種，能避則避。
func (g *LoginGuard) evictOldest(now time.Time) {
	for elem := g.lru.Back(); elem != nil; elem = elem.Prev() {
		entry := elem.Value.(*gEntry)
		if !entry.cooldownUntil.After(now) {
			delete(g.entries, entry.key)
			g.lru.Remove(elem)
			return
		}
	}
	if elem := g.lru.Back(); elem != nil {
		entry := elem.Value.(*gEntry)
		delete(g.entries, entry.key)
		g.lru.Remove(elem)
	}
}
