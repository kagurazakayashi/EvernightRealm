// 驗證：統一審計記錄介面的實際落庫行為（寫入用正式代碼，判讀由外部腳本做）。
//
// 目的：為「操作者、目標、原因、時間、變更摘要可追蹤」與「只追加存儲」取得進程級證據。
// 每個子命令各自開庫、工作、關庫，因此跨次呼叫同時證明重開後仍讀得回來。
// 結論見同目錄 README.md。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// sensitiveValues 是必須查證「不會出現在任何地方」的四種內容（規格 §25.1、ER-SEC-001 §7）。
const (
	sensitivePIN   = "48219375"
	sensitiveToken = "sess-9f8e7d6c5b4a3210fedcba76543210"
	sensitiveChat  = "今晚八點在舊倉庫見面，口令是 48219375"
	sensitiveNote  = "9f8e7d6c5b4a3210fedcba0b1c2d3e4f"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法：step065-audit <migrate|append|rollback|readback> -db <路徑> [參數]")
		os.Exit(2)
	}
	command := os.Args[1]
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	dbPath := fs.String("db", "", "資料庫檔案路徑")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "缺少 -db")
		os.Exit(2)
	}

	ctx := context.Background()
	db, err := database.Open(ctx, database.Options{Path: *dbPath, BusyTimeout: 30 * time.Second})
	if err != nil {
		fmt.Fprintf(os.Stderr, "開庫失敗：%v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := db.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "關庫失敗：%v\n", err)
		}
	}()

	store := audit.NewStore(timeutil.System())
	switch command {
	case "migrate":
		result, err := migrate.Apply(ctx, db.SQL(), migrate.Options{Clock: timeutil.System()})
		if err != nil {
			fmt.Fprintf(os.Stderr, "遷移失敗：%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("version=%d applied=%d\n", result.ToVersion, len(result.Applied))
	case "append":
		if err := appendRecords(ctx, db, store); err != nil {
			fmt.Fprintf(os.Stderr, "寫入失敗：%v\n", err)
			os.Exit(1)
		}
	case "rollback":
		if err := rolledBackAppend(ctx, db, store); err != nil {
			fmt.Fprintf(os.Stderr, "回滾場景失敗：%v\n", err)
			os.Exit(1)
		}
	case "readback":
		if err := readBack(ctx, db, store); err != nil {
			fmt.Fprintf(os.Stderr, "讀取失敗：%v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "未知子命令：%s\n", command)
		os.Exit(2)
	}
}

// appendRecords 寫入兩筆活動作用域與一筆 Root 作用域記錄，並把產生的標識印成 key=value。
//
// 標識一律由 idgen 產生：審計表的 id 欄位有 length=36 的 CHECK，而且只有正規 UUIDv7 才讀得回來。
func appendRecords(ctx context.Context, db *database.DB, store *audit.Store) error {
	activityID, err := idgen.New()
	if err != nil {
		return err
	}
	adminID, err := idgen.New()
	if err != nil {
		return err
	}
	playerID, err := idgen.New()
	if err != nil {
		return err
	}
	fmt.Printf("activity_id=%s\nactor_id=%s\nplayer_id=%s\n", activityID, adminID, playerID)

	records := []audit.Record{
		{
			Scope:      audit.ScopeActivity,
			ActivityID: activityID,
			Actor:      audit.Actor{Kind: audit.ActorAdmin, ID: adminID},
			Action:     "balance.adjust",
			Target:     audit.Target{Kind: "player", ID: playerID.String()},
			Reason:     "活動結算糾錯",
			RequestID:  requestID(),
			Changes: []audit.Change{
				{Field: "balance", Before: 500, After: 300},
				{Field: "pin", Before: "1234", After: sensitivePIN},
				{Field: "session_token", Before: "old-token-value", After: sensitiveToken},
				{Field: "chat_body", Before: "先前的內容", After: sensitiveChat},
				{Field: "remark", Before: "舊備註", After: sensitiveNote},
			},
		},
		{
			// 沒有欄位差量的操作（登入）仍是一筆合法記錄：變化摘要為空不等於記錄不完整。
			Scope:      audit.ScopeActivity,
			ActivityID: activityID,
			Actor:      audit.Actor{Kind: audit.ActorPlayer, ID: playerID},
			Action:     "player.login",
			Target:     audit.Target{Kind: "player", ID: playerID.String()},
			Reason:     "掃碼進入活動",
			RequestID:  requestID(),
		},
		{
			// 系統主體沒有 actor_id（表裡為 NULL），原因是 Root 事件不屬於任何活動。
			Scope:  audit.ScopeRoot,
			Actor:  audit.Actor{Kind: audit.ActorSystem},
			Action: "maintenance.enter",
			Target: audit.Target{Kind: "server"},
		},
	}
	for _, rec := range records {
		id, err := store.Append(ctx, db.SQL(), rec)
		if err != nil {
			return err
		}
		fmt.Printf("record_id=%s scope=%s action=%s\n", id, rec.Scope, rec.Action)
	}
	return nil
}

// rolledBackAppend 把業務寫入與審計寫入放進同一個交易，並讓業務那端失敗。
//
// 印出「回滾前的筆數」而不印回滾後的：後者由外部腳本用自己的連線去數，
// 免得寫入與判讀用的是同一條路徑而自證清白。
func rolledBackAppend(ctx context.Context, db *database.DB, store *audit.Store) error {
	activityID, err := idgen.New()
	if err != nil {
		return err
	}
	adminID, err := idgen.New()
	if err != nil {
		return err
	}
	business := errors.New("餘額不足")
	err = db.InTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO server_settings (key, value, updated_at) VALUES (?, ?, ?)`,
			"verify.rollback", "1", timeutil.ToMillis(time.Now())); err != nil {
			return err
		}
		if _, err := store.Append(ctx, tx, audit.Record{
			Scope:      audit.ScopeActivity,
			ActivityID: activityID,
			Actor:      audit.Actor{Kind: audit.ActorAdmin, ID: adminID},
			Action:     "balance.adjust",
			Target:     audit.Target{Kind: "player", ID: adminID.String()},
			Reason:     "這一筆不該留在資料庫裡",
			Changes:    []audit.Change{{Field: "balance", Before: 100, After: 0}},
		}); err != nil {
			return err
		}
		return business
	})
	if !errors.Is(err, business) {
		return fmt.Errorf("應把業務錯誤原樣回傳，實際 %w", err)
	}
	fmt.Printf("rolled_back=true business_error=%q activity_id=%s\n", business, activityID)
	return nil
}

// readBack 用正式讀取路徑把記錄取回並逐欄印出，作為「六要素可追蹤」的直接證據。
func readBack(ctx context.Context, db *database.DB, store *audit.Store) error {
	activityID, err := idgen.Parse(mustEnv("AUDIT_ACTIVITY_ID"))
	if err != nil {
		return err
	}
	page, err := store.Query(ctx, db.SQL(), audit.Filter{Scope: audit.ScopeActivity, ActivityID: activityID})
	if err != nil {
		return err
	}
	fmt.Printf("activity_records=%d next_cursor=%q\n", len(page.Records), page.NextCursor)
	for _, rec := range page.Records {
		fmt.Printf("record id=%s actor=%s/%s action=%s target=%s/%s reason=%q time_ms=%d request_id=%q\n",
			rec.ID, rec.Actor.Kind, rec.Actor.ID, rec.Action, rec.Target.Kind, rec.Target.ID,
			rec.Reason, timeutil.ToMillis(rec.CreatedAt), rec.RequestID)
		for i, change := range rec.Changes {
			fmt.Printf("  change[%d] field=%s before=%v after=%v\n", i, change.Field, change.Before, change.After)
		}
	}

	root, err := store.Query(ctx, db.SQL(), audit.Filter{Scope: audit.ScopeRoot})
	if err != nil {
		return err
	}
	fmt.Printf("root_records=%d\n", len(root.Records))
	for _, rec := range root.Records {
		fmt.Printf("root id=%s actor=%s/%s action=%s target=%s reason=%q time_ms=%d changes=%d\n",
			rec.ID, rec.Actor.Kind, rec.Actor.ID, rec.Action, rec.Target.Kind, rec.Reason,
			timeutil.ToMillis(rec.CreatedAt), len(rec.Changes))
	}
	return nil
}

// requestID 取一個與正式路徑同源的關聯 ID（由 idgen 產生，不另造格式）。
func requestID() string {
	id, err := idgen.New()
	if err != nil {
		// 探針沒有可降級的餘地：產生不出來就讓寫入失敗，比頂一個假 ID 更老實。
		panic(err)
	}
	return id.String()
}

// mustEnv 取必要環境變數；缺失時直接結束，不拿預設值把判讀帶偏。
func mustEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		fmt.Fprintf(os.Stderr, "缺少環境變數 %s\n", name)
		os.Exit(1)
	}
	return value
}
