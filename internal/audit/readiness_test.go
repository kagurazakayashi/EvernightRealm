package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
)

func TestRootTableReadyFollowsMigrationState(t *testing.T) {
	ctx := context.Background()

	// 剛開出來、還沒套遷移的庫：表不存在，這一條要回 false 而不是錯誤。
	fresh, err := database.Open(ctx, database.Options{
		Path: filepath.Join(retryTempDir(t), "evernight.db"), BusyTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	ready, err := RootTableReady(ctx, fresh.SQL())
	if err != nil {
		t.Fatalf("未遷移的庫不應回報錯誤：%v", err)
	}
	if ready {
		t.Error("未套用遷移時 root_audit 不應被判定為已就緒")
	}
	if err := fresh.Close(); err != nil {
		t.Fatalf("關閉失敗：%v", err)
	}

	// 套完遷移後同一條判定要翻成 true——一次性命令就是靠它決定要不要動組態檔。
	_, db, _ := newTestStore(t)
	ready, err = RootTableReady(ctx, db.SQL())
	if err != nil || !ready {
		t.Fatalf("已遷移的庫應判定為就緒（ready=%t err=%v）", ready, err)
	}
}

func TestRootTableReadyRejectsMissingQuerier(t *testing.T) {
	if _, err := RootTableReady(context.Background(), nil); err == nil {
		t.Fatal("沒有查詢介面時應回報錯誤，而不是當成「未就緒」")
	}
}
