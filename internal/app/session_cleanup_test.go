package app

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// newCleanupEnv 建立「本次測試專屬庫 + 注入時鐘 + 帶清理寬限期的會話倉儲」。
//
// 清理任務的正確性只能看資料庫，因此這裡給的是真庫而不是替身：背景迴圈
// 與清理通路之間接錯線（比如拿錯連線、或把刪除寫成了更新）在替身上不會紅。
func newCleanupEnv(t *testing.T, ttl time.Duration, grace time.Duration) (*database.DB, *timeutil.Test, *session.Store) {
	t.Helper()
	clock := timeutil.NewTest(time.Now().UTC().Truncate(time.Second))
	db, err := database.Open(context.Background(), database.Options{
		Path:        filepath.Join(retryTempDir(t), "evernight.db"),
		BusyTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: clock}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	store, err := session.NewStoreWithPolicy(clock, ttl, session.Policy{CleanupGrace: grace})
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	return db, clock, store
}

// seedSessions 落 n 枚 Root 會話（同一時刻建立，之後的差別全靠撥鍾）。
func seedSessions(t *testing.T, db *database.DB, store *session.Store, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		root := identitytest.Root(t, identity.OriginHTTPRequest)
		if _, _, err := store.Create(ctx, db.SQL(), root); err != nil {
			t.Fatalf("建立第 %d 枚會話失敗：%v", i, err)
		}
	}
}

// sessionCount 讀會話行數。
func sessionCount(t *testing.T, db *database.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sessions").Scan(&n); err != nil {
		t.Fatalf("統計會話失敗：%v", err)
	}
	return n
}

// quietLogger 是不出聲的日誌器：本檔只關心清理有沒有真的動資料庫。
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestCleanupPassDeletesOnlyPastGraceRows 單看一回合的行為：寬限期內的失效行留著，
// 過了寬限期的刪掉，活躍的一律不動。
func TestCleanupPassDeletesOnlyPastGraceRows(t *testing.T) {
	db, clock, store := newCleanupEnv(t, time.Hour, 10*time.Minute)
	ctx := context.Background()

	// 第一批：兩枚會先到期。
	seedSessions(t, db, store, 2)
	clock.Advance(2 * time.Hour)
	// 第二批：剛建立，仍在絕對期限內。
	seedSessions(t, db, store, 3)

	deleted, err := cleanupPass(ctx, store, db, quietLogger())
	if err != nil {
		t.Fatalf("第一回合清理失敗：%v", err)
	}
	if deleted != 2 {
		t.Errorf("只應刪掉過期且過寬限期的 2 行，實際 %d", deleted)
	}
	if n := sessionCount(t, db); n != 3 {
		t.Errorf("活躍三枚應留下，實際剩 %d 行", n)
	}

	// 第二批也到期，但還在 10 分鐘的寬限期內：這一回合刪不掉任何東西。
	clock.Advance(30 * time.Minute)
	deleted, err = cleanupPass(ctx, store, db, quietLogger())
	if err != nil {
		t.Fatalf("第二回合清理失敗：%v", err)
	}
	if deleted != 0 {
		t.Errorf("寬限期內不應刪除，實際 %d", deleted)
	}

	// 越過寬限期：剩下的都被清掉。
	clock.Advance(70 * time.Minute)
	deleted, err = cleanupPass(ctx, store, db, quietLogger())
	if err != nil {
		t.Fatalf("第三回合清理失敗：%v", err)
	}
	if deleted != 3 {
		t.Errorf("過寬限期後應刪 3 行，實際 %d", deleted)
	}
	if n := sessionCount(t, db); n != 0 {
		t.Errorf("表應為空，實際剩 %d 行", n)
	}
}

// TestRunSessionCleanupDoesFirstPassImmediately 確認啟動後第一回合不必等滿一個週期：
// 「上一次執行攢下的失效行」在服務一起來就被處理。
func TestRunSessionCleanupDoesFirstPassImmediately(t *testing.T) {
	db, clock, store := newCleanupEnv(t, time.Hour, 0)
	seedSessions(t, db, store, 4)
	clock.Advance(2 * time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		// 週期給一個永遠不會到的小時數：能看到刪除就只可能是第一回合乾的。
		runSessionCleanup(ctx, store, db, time.Hour, quietLogger())
	}()

	deadline := time.Now().Add(5 * time.Second)
	for sessionCount(t, db) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("啟動回合未在期限內完成清理")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("取消後清理任務未結束")
	}
}

// TestRunSessionCleanupRepeatsOnInterval 確認任務會按週期重複，而不是跑一次就退出。
func TestRunSessionCleanupRepeatsOnInterval(t *testing.T) {
	db, clock, store := newCleanupEnv(t, time.Hour, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		runSessionCleanup(ctx, store, db, 20*time.Millisecond, quietLogger())
	}()

	// 第一回合之後陸續建立再撥鍾到期：只要迴圈還在跑，第二枚就會被清掉。
	seedSessions(t, db, store, 1)
	clock.Advance(2 * time.Hour)
	waitForCount(t, db, 0)

	seedSessions(t, db, store, 2)
	clock.Advance(2 * time.Hour)
	waitForCount(t, db, 0)

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("取消後清理任務未結束")
	}
}

// TestRunSessionCleanupStopsBeforeFirstPassWhenAlreadyCancelled 是啟動即取消的形狀：
// 任務不應在「已經要退出了」之後還去寫資料庫。
func TestRunSessionCleanupStopsBeforeFirstPassWhenAlreadyCancelled(t *testing.T) {
	db, clock, store := newCleanupEnv(t, time.Hour, 0)
	seedSessions(t, db, store, 3)
	clock.Advance(2 * time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSessionCleanup(ctx, store, db, time.Millisecond, quietLogger())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("已取消的 context 下任務未 promptly 返回")
	}
	if n := sessionCount(t, db); n != 3 {
		t.Errorf("取消後的任務不應動過資料庫，實際剩 %d 行（應為 3）", n)
	}
}

// waitForCount 輪詢到會話行數等於 want 為止（週期任務的測試只能等，不能假裝有事件）。
func waitForCount(t *testing.T, db *database.DB, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for sessionCount(t, db) != want {
		if time.Now().After(deadline) {
			t.Fatalf("未在期限內等到行數 %d，實際 %d", want, sessionCount(t, db))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
