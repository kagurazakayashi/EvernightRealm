package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/session"
)

// cleanupPass 執行一回合失效會話清理，回傳刪除行數。
//
// 走 autocommit（db.SQL()）而不是 InTx：database 的寫入前閘門只在寫入交易 BEGIN 之前
// 生效，而本回合的目的恰恰是騰出空間——把它塞進交易，等於在磁碟最吃緊的那一刻
// 正好把這把鑰擰上，方向是反的。入口推進最近活動時刻那一寫也走同一條 autocommit
// 通路（見 session.Store.Verify 的呼叫端），兩邊一致。
//
// 停止流程打斷進行的那一回合不當成失敗：那時 ctx 已取消，「清理沒跑完」是優雅停止
// 的正常結果，不是需要排錯的事故；把它記成警告會讓每次正常關機都帶一行假警報。
// 週期由呼叫端保證為正值（0 表示不啟動本任務，在啟動流程裡就地判斷）。
//
// 抽成獨立函式是為了讓啟動接線可以被測試直接觀察一回合的結果，
// 不需要真的等過一個週期，也不需要 fake 資料庫。
func cleanupPass(ctx context.Context, store *session.Store, db *database.DB, log *slog.Logger) (int, error) {
	deleted, err := store.Cleanup(ctx, db.SQL())
	switch {
	case err != nil && ctx.Err() != nil:
		log.Debug("失效會話清理回合被停止流程打斷", "err", err)
	case err != nil:
		log.Warn("失效會話清理回合失敗，等下一個週期再試", "err", err)
	case deleted > 0:
		log.Info("失效會話清理完成", "deleted", deleted)
	}
	return deleted, err
}

// runSessionCleanup 按周期刪除「已失效且過了保留寬限期」的會話記錄，直到 ctx 被取消。
//
// 這個任務的存在只關係「不再可能換出身份的記錄別無限堆積」，不關係安全：
// 失效憑據在請求入口就被會話驗證拒掉，清理跑不跑、什麼時候跑都不改變那一點。
// 因此單回合失敗一律記一筆警告後等下一個周期，既不中斷服務，也不退化成更激進的刪除。
//
// 第一回合在啟動後立即執行：上一次運行期間累積的失效行不必再等一個完整周期，
// 而提早執行也不改變任何判定依據（依據本來就只有庫內時刻與伺服器時鐘）。
func runSessionCleanup(ctx context.Context, store *session.Store, db *database.DB,
	interval time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if ctx.Err() != nil {
			return
		}
		cleanupPass(ctx, store, db, log)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
