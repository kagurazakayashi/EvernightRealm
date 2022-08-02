// 驗證：統一審計記錄介面的實際落庫行為（寫入用正式程式碼，判讀由外部指令碼做）。
//
// 目的：為「操作者、目標、原因、時間、變更摘要可追蹤」與「只追加存儲」取得程序級證據。
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
		fmt.Fprintln(os.Stderr, "用法：step065-audit <migrate|append|rollback|readback> -db <路徑> [引數]")
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
	case "scopes":
		if err := scopeMatrix(ctx, db, store); err != nil {
			fmt.Fprintf(os.Stderr, "作用域矩陣失敗：%v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "未知子命令：%s\n", command)
		os.Exit(2)
	}
}

// scopeMatrix 寫入兩個活動與一個 Root 事件，再以不同的閱覽身分讀同一批記錄。
//
// 意圖是把「讀不到」與「沒有資料」分開判斷：同一個查詢條件換個身分就讀得到，
// 才證明拒絕來自授權判定而不是來自空的結果集。各筆標識一律印出，
// 由外部腳本用 SQLite 獨立核對庫裡實際存在幾筆。
func scopeMatrix(ctx context.Context, db *database.DB, store *audit.Store) error {
	activityA, err := idgen.New()
	if err != nil {
		return err
	}
	activityB, err := idgen.New()
	if err != nil {
		return err
	}
	adminID, err := idgen.New()
	if err != nil {
		return err
	}
	fmt.Printf("activity_a=%s\nactivity_b=%s\nactor_admin=%s\n", activityA, activityB, adminID)

	actor := audit.Actor{Kind: audit.ActorAdmin, ID: adminID}
	records := []audit.Record{
		{Scope: audit.ScopeActivity, ActivityID: activityA, Actor: actor, Action: "balance.adjust",
			Target: targetOf("player", activityA), Reason: "A 活動結算", RequestID: requestID()},
		{Scope: audit.ScopeActivity, ActivityID: activityA, Actor: actor, Action: "phase.change",
			Target: targetOf("phase", activityA), Reason: "A 活動切換階段", RequestID: requestID()},
		{Scope: audit.ScopeActivity, ActivityID: activityB, Actor: actor, Action: "asset.grant",
			Target: targetOf("asset", activityB), Reason: "B 活動發放", RequestID: requestID()},
		{Scope: audit.ScopeRoot, Actor: audit.Actor{Kind: audit.ActorRoot, ID: adminID}, Action: "admin.create",
			Target: audit.Target{Kind: "admin", ID: adminID.String()}, RequestID: requestID()},
	}
	for _, rec := range records {
		if _, err := store.Append(ctx, db.SQL(), rec); err != nil {
			return err
		}
	}

	cases := []struct {
		label  string
		viewer audit.Viewer
		filter audit.Filter
	}{
		{"root_reads_a", audit.Viewer{Kind: audit.ActorRoot}, audit.Filter{Scope: audit.ScopeActivity, ActivityID: activityA}},
		{"root_reads_b", audit.Viewer{Kind: audit.ActorRoot}, audit.Filter{Scope: audit.ScopeActivity, ActivityID: activityB}},
		{"root_reads_root", audit.Viewer{Kind: audit.ActorRoot}, audit.Filter{Scope: audit.ScopeRoot}},
		{"admin_a_reads_a", audit.Viewer{Kind: audit.ActorAdmin, Activities: []idgen.ID{activityA}},
			audit.Filter{Scope: audit.ScopeActivity, ActivityID: activityA}},
		{"admin_a_reads_b", audit.Viewer{Kind: audit.ActorAdmin, Activities: []idgen.ID{activityA}},
			audit.Filter{Scope: audit.ScopeActivity, ActivityID: activityB}},
		{"admin_a_reads_root", audit.Viewer{Kind: audit.ActorAdmin, Activities: []idgen.ID{activityA}},
			audit.Filter{Scope: audit.ScopeRoot}},
		{"admin_b_reads_b", audit.Viewer{Kind: audit.ActorAdmin, Activities: []idgen.ID{activityB}},
			audit.Filter{Scope: audit.ScopeActivity, ActivityID: activityB}},
		{"player_reads_a", audit.Viewer{Kind: audit.ActorPlayer}, audit.Filter{Scope: audit.ScopeActivity, ActivityID: activityA}},
		{"npc_reads_root", audit.Viewer{Kind: audit.ActorNPC}, audit.Filter{Scope: audit.ScopeRoot}},
		{"no_viewer_reads_root", audit.Viewer{}, audit.Filter{Scope: audit.ScopeRoot}},
	}
	for _, c := range cases {
		page, err := store.Query(ctx, db.SQL(), c.viewer, c.filter)
		outcome := denyOutcome(err)
		fmt.Printf("matrix case=%s outcome=%s records=%d\n", c.label, outcome, len(page.Records))
		for _, rec := range page.Records {
			// 放行時才逐筆印出：動作碼是外部腳本判讀「哪一組真的讀到了內容」的依據。
			fmt.Printf("matrix case=%s record action=%s actor=%s\n", c.label, rec.Action, rec.Actor.Kind)
		}
	}
	return nil
}

// targetOf 以活動標識造一個可判讀的對象，避免同一活動的多筆記錄全部落在同一個對象上。
func targetOf(kind string, id idgen.ID) audit.Target {
	return audit.Target{Kind: kind, ID: id.String()}
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
// 印出「回滾前的筆數」而不印回滾後的：後者由外部指令碼用自己的連線去數，
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
//
// 讀取一律帶 Root 身分：查詢的授權判定是存取層的必要條件，探針代表的是 Root 控制檯
// 的回看能力（規格 §25.2）。同一趟最後再以管理員身分重讀一次，印出被拒的類別，
// 作為「兩類查詢讀不到彼此」的正面證據。
func readBack(ctx context.Context, db *database.DB, store *audit.Store) error {
	activityID, err := idgen.Parse(mustEnv("AUDIT_ACTIVITY_ID"))
	if err != nil {
		return err
	}
	page, err := store.Query(ctx, db.SQL(), audit.Viewer{Kind: audit.ActorRoot},
		audit.Filter{Scope: audit.ScopeActivity, ActivityID: activityID})
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

	root, err := store.Query(ctx, db.SQL(), audit.Viewer{Kind: audit.ActorRoot}, audit.Filter{Scope: audit.ScopeRoot})
	if err != nil {
		return err
	}
	fmt.Printf("root_records=%d\n", len(root.Records))
	for _, rec := range root.Records {
		fmt.Printf("root id=%s actor=%s/%s action=%s target=%s reason=%q time_ms=%d changes=%d\n",
			rec.ID, rec.Actor.Kind, rec.Actor.ID, rec.Action, rec.Target.Kind, rec.Reason,
			timeutil.ToMillis(rec.CreatedAt), len(rec.Changes))
	}

	// 越權讀取一律以「發不出查詢」為準：管理員讀 Root 審計、玩家讀活動審計，
	// 兩者都必須回傳錯誤且交不出任何記錄。
	denials := []struct {
		label  string
		viewer audit.Viewer
		filter audit.Filter
	}{
		{"admin_reads_root", audit.Viewer{Kind: audit.ActorAdmin, Activities: []idgen.ID{activityID}},
			audit.Filter{Scope: audit.ScopeRoot}},
		{"player_reads_activity", audit.Viewer{Kind: audit.ActorPlayer},
			audit.Filter{Scope: audit.ScopeActivity, ActivityID: activityID}},
		{"admin_reads_other_activity", audit.Viewer{Kind: audit.ActorAdmin},
			audit.Filter{Scope: audit.ScopeActivity, ActivityID: activityID}},
	}
	for _, d := range denials {
		refused, err := store.Query(ctx, db.SQL(), d.viewer, d.filter)
		fmt.Printf("deny_%s=%s records=%d\n", d.label, denyOutcome(err), len(refused.Records))
	}
	return nil
}

// denyOutcome 把越權讀取的判定結果印成一個可被外部指令碼斷言的詞。
//
// 只印「有錯誤」不夠：權限拒絕與程式錯誤（未帶 activity_id、身分不合法）在畫面上
// 都只是一行文字，分成三個詞才看得出判定走的是哪一條路。
func denyOutcome(err error) string {
	switch {
	case err == nil:
		return "ALLOWED"
	case errors.Is(err, audit.ErrDenied):
		return "DENIED"
	case errors.Is(err, audit.ErrIncompleteScope):
		return "INCOMPLETE_SCOPE"
	case errors.Is(err, audit.ErrInvalidViewer):
		return "INVALID_VIEWER"
	default:
		return "OTHER:" + err.Error()
	}
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
