package database

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// openGuardedDB 開一個帶寫入前門的資料庫，門的呼叫次數由回傳的計數器給出。
func openGuardedDB(t *testing.T, guard func() error) (*DB, *int) {
	t.Helper()
	calls := 0
	wrapped := func() error {
		calls++
		return guard()
	}
	db, err := Open(context.Background(), Options{
		Path:       filepath.Join(retryTempDir(t), "evernight.db"),
		WriteGuard: wrapped,
	})
	if err != nil {
		t.Fatalf("Open 失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.SQL().ExecContext(context.Background(),
		"CREATE TABLE guarded (id INTEGER PRIMARY KEY, note TEXT)"); err != nil {
		t.Fatalf("建表失敗：%v", err)
	}
	return db, &calls
}

// errNoSpace 借用本包的測試立場模擬一個外部拒絕原因。
var errNoSpace = errors.New("可用空間不足")

func TestWriteGuardBlocksTransactionBeforeBegin(t *testing.T) {
	db, calls := openGuardedDB(t, func() error { return errNoSpace })
	ctx := context.Background()

	executed := false
	err := db.InTx(ctx, func(context.Context, *Tx) error {
		executed = true
		return nil
	})
	if !errors.Is(err, errNoSpace) {
		t.Fatalf("應把門的錯誤原樣傳出，實際 %v", err)
	}
	// 回呼不得執行：空間不足時最壞的寫法是「先做事，事後發現不該做」。
	if executed {
		t.Error("門拒絕後仍執行了交易回呼")
	}
	if *calls != 1 {
		t.Errorf("門被呼叫 %d 次，want 1", *calls)
	}
	// 拒絕必須不留任何痕跡：表仍是空的。
	var n int
	if err := db.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM guarded").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("拒絕後庫裡有 %d 筆，want 0", n)
	}
}

func TestWriteGuardAllowsAndIsCalledPerTransaction(t *testing.T) {
	db, calls := openGuardedDB(t, func() error { return nil })
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			_, err := tx.ExecContext(ctx, "INSERT INTO guarded (note) VALUES ('ok')")
			return err
		}); err != nil {
			t.Fatalf("第 %d 筆交易失敗：%v", i+1, err)
		}
	}
	if *calls != 3 {
		t.Errorf("門被呼叫 %d 次，want 3（每筆寫入交易都要問，快取由門自己負責）", *calls)
	}
	var n int
	if err := db.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM guarded").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("提交後庫裡 %d 筆，want 3", n)
	}
}

// TestWriteGuardNotUsedByReadOnlyTransactions 固定一條容易做錯的取捨：
// 唯讀交易不落盤，攔它只會讓人在空間不足時連現況都看不到。
func TestWriteGuardNotUsedByReadOnlyTransactions(t *testing.T) {
	db, calls := openGuardedDB(t, func() error { return errNoSpace })
	ctx := context.Background()

	if err := db.InTxReadOnly(ctx, func(ctx context.Context, tx *Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM guarded").Scan(&n); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("唯讀交易不應被門擋下：%v", err)
	}
	if *calls != 0 {
		t.Errorf("唯讀交易叫了 %d 次門，want 0", *calls)
	}
}

// TestWriteGuardDoesNotCoverAutocommit 把門的邊界固定成證據而不是誤解：
// 只取 SQL() 那條 autocommit 路徑的寫入不經門。
//
// 這是已知限制而不是遺漏：要把 autocommit 也包住，要嘛放棄暴露原始連線
// （遷移與既有測試都依賴它），要嘛在 *sql.DB 外再包一層寫入口徑——後者改動的範圍
// 遠大於本步的驗收。啟動期那條會改結構的寫入（遷移）由 internal/app 的前置檢查覆蓋，
// 因此現在的實際覆蓋面是「交易式寫入 + 啟動期寫入」，而本測試把缺口留在明處：
// 日後任何走 autocommit 的業務寫入都必須自己問一次門，或改用 InTx。
func TestWriteGuardDoesNotCoverAutocommit(t *testing.T) {
	db, calls := openGuardedDB(t, func() error { return errNoSpace })

	if _, err := db.SQL().ExecContext(context.Background(),
		"INSERT INTO guarded (note) VALUES ('autocommit')"); err != nil {
		t.Fatalf("autocommit 寫入目前不經門，若這個前提變了請同步改掉 app 層的前置檢查：%v", err)
	}
	if *calls != 0 {
		t.Errorf("autocommit 竟叫了 %d 次門，want 0（門只在交易入口）", *calls)
	}
}

// TestNilWriteGuardMeansNoGate 未注入門時一切照舊。
func TestNilWriteGuardMeansNoGate(t *testing.T) {
	db, err := Open(context.Background(), Options{
		Path: filepath.Join(retryTempDir(t), "evernight.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.InTx(context.Background(), func(ctx context.Context, tx *Tx) error {
		_, err := tx.ExecContext(ctx, "CREATE TABLE plain (id INTEGER)")
		return err
	}); err != nil {
		t.Errorf("未注入門時寫入交易應照常進行：%v", err)
	}
}

// TestWriteGuardRunsBeforeBegin 確認門的位置在「開始交易」這一步之前：
// 交易已開始才拒絕會白拿一次寫入鎖再回滾，那個窗口在即時空間耗盡時是可觀察到的阻塞。
//
// 做法是在同一個實例內先讓一個交易持有寫入鎖，再把門切成拒絕：
// 若門排在 BEGIN 之後，這次呼叫會先等到 busy_timeout 才失敗（錯誤也不是門的那個）；
// 若門排在之前，它應該立刻被拒。另外必須用同一個實例——第二個 Open 會直接被單寫入鎖拒開，
// 那種情況下測到的是鎖而不是門。
func TestWriteGuardRunsBeforeBegin(t *testing.T) {
	guardOn := atomic.Bool{}
	guard := func() error {
		if guardOn.Load() {
			return errNoSpace
		}
		return nil
	}
	db, err := Open(context.Background(), Options{
		Path:        filepath.Join(retryTempDir(t), "evernight.db"),
		BusyTimeout: 800 * time.Millisecond,
		WriteGuard:  guard,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	holding := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- db.InTx(ctx, func(context.Context, *Tx) error {
			close(holding)
			<-release
			return nil
		})
	}()
	<-holding // 回呼開始執行即代表 BEGIN 已生效、寫入鎖已在手上

	guardOn.Store(true)
	started := time.Now()
	err = db.InTx(ctx, func(context.Context, *Tx) error { return nil })
	elapsed := time.Since(started)

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("持有鎖的那筆交易失敗：%v", err)
	}

	if !errors.Is(err, errNoSpace) {
		t.Fatalf("應由門拒絕，實際 %v", err)
	}
	// busy_timeout 是 800ms：門若排在 BEGIN 之後，這次呼叫必然先等過鎖。
	if elapsed >= 400*time.Millisecond {
		t.Errorf("門拒絕前花了 %v，看起來是先等鎖再被拒", elapsed)
	}
}
