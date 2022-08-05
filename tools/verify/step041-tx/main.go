// 驗證：SQLite 交易邊界在 Windows 上的實際行為（BEGIN 模式、SAVEPOINT、唯讀、忙鎖錯誤）。
//
// 目的：為服務端交易封裝定案提供實證依據。列印各場景的實際結果，
// 不作為正式程式碼；結論見同目錄 README.md。
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// envChild 為子程序模式標記：設定時只執行「交易中途退出」模擬；envChildDB 傳入父程序的資料庫路徑。
const (
	envChild   = "STEP041_CHILD"
	envChildDB = "STEP041_DB"
)

// dsn 與正式實作相同形式：file: + URL 編碼路徑 + PRAGMA。
func dsn(path string, extra string) string {
	q := url.Values{}
	q.Set("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(200)")
	if extra != "" {
		for _, kv := range strings.Split(extra, "&") {
			if k, v, ok := strings.Cut(kv, "="); ok {
				q.Add(k, v)
			}
		}
	}
	return "file:" + filepath.ToSlash(path) + "?" + q.Encode()
}

func mustOpen(path, extra string) *sql.DB {
	pool, err := sql.Open("sqlite", dsn(path, extra))
	if err != nil {
		fmt.Println("   開啟失敗：", err)
		os.Exit(1)
	}
	pool.SetMaxOpenConns(1)
	return pool
}

func mustExec(ctx context.Context, pool *sql.DB, query string) {
	if _, err := pool.ExecContext(ctx, query); err != nil {
		fmt.Printf("   執行 %q 失敗：%v\n", query, err)
		os.Exit(1)
	}
}

func mustExecTx(ctx context.Context, tx *sql.Tx, query string) {
	if _, err := tx.ExecContext(ctx, query); err != nil {
		fmt.Printf("   交易內執行 %q 失敗：%v\n", query, err)
		os.Exit(1)
	}
}

// classify 印出驅動錯誤型別、原始碼與主碼（SQLITE_BUSY=5、SQLITE_LOCKED=6）。
func classify(err error) string {
	var se *sqlite.Error
	if errors.As(err, &se) {
		code := se.Code()
		primary := code & 0xff
		return fmt.Sprintf("type=*sqlite.Error code=%d primary=%d（%s）",
			code, primary, sqlite.ErrorCodeString[code])
	}
	if err == nil {
		return "err=nil"
	}
	return fmt.Sprintf("type=%T err=%v", err, err)
}

func main() {
	if os.Getenv(envChild) != "" {
		runChild(context.Background(), os.Getenv(envChildDB))
		return
	}
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "step041-tx")
	if err != nil {
		fmt.Println("建立暫存目錄失敗：", err)
		os.Exit(1)
	}
	defer func() {
		// 清理失敗必須單獨報告並讓探針以非零碼結束：場景全過但目錄殘留時
		// 不能假裝清理成功；子程序崩潰模擬留下的鎖與句柄釋放有落後，正是
		// 這道重試要吸收的競爭。原本已失敗的路徑在此之前已由 os.Exit 定案退出碼。
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			fmt.Printf("暫存目錄清理失敗（殘留：%s）：%v\n", dir, err)
			os.Exit(1)
		}
	}()
	dbPath := filepath.Join(dir, "tx.db")

	setup := mustOpen(dbPath, "")
	mustExec(ctx, setup, "CREATE TABLE ledger (id INTEGER PRIMARY KEY, amount INTEGER NOT NULL)")
	mustExec(ctx, setup, "CREATE TABLE note (id INTEGER PRIMARY KEY, body TEXT NOT NULL)")
	_ = setup.Close()

	fmt.Println("== 1) 忙鎖錯誤的型別與碼 ==")
	holder := mustOpen(dbPath, "")
	holderTx, err := holder.BeginTx(ctx, nil)
	if err != nil {
		fmt.Println("   holder BeginTx 失敗：", err)
		os.Exit(1)
	}
	if _, err := holderTx.ExecContext(ctx, "INSERT INTO ledger (amount) VALUES (1)"); err != nil {
		fmt.Println("   holder 寫入失敗：", err)
		os.Exit(1)
	}
	blocked := mustOpen(dbPath, "")
	start := time.Now()
	_, writeErr := blocked.ExecContext(ctx, "INSERT INTO ledger (amount) VALUES (2)")
	fmt.Printf("   第二寫入者（busy_timeout=200ms）耗時 %v → %s\n", time.Since(start).Round(time.Millisecond), classify(writeErr))
	_ = holderTx.Rollback()
	_ = holder.Close()
	_ = blocked.Close()

	fmt.Println("== 2) BEGIN DEFERRED vs BEGIN IMMEDIATE（第二寫入者持有寫入鎖時）==")
	holder2 := mustOpen(dbPath, "")
	holder2Tx, _ := holder2.BeginTx(ctx, nil)
	if _, err := holder2Tx.ExecContext(ctx, "INSERT INTO ledger (amount) VALUES (3)"); err != nil {
		fmt.Println("   holder2 寫入失敗：", err)
	}
	// 以獨立連線嘗試兩種 BEGIN 模式。
	for _, mode := range []string{"DEFERRED", "IMMEDIATE", "EXCLUSIVE"} {
		probe := mustOpen(dbPath, "")
		conn, _ := probe.Conn(ctx)
		t0 := time.Now()
		_, beginErr := conn.ExecContext(ctx, "BEGIN "+mode)
		elapsed := time.Since(t0).Round(time.Millisecond)
		detail := classify(beginErr)
		if beginErr == nil {
			_, werr := conn.ExecContext(ctx, "INSERT INTO ledger (amount) VALUES (99)")
			detail = fmt.Sprintf("BEGIN 成功 → 首次寫入：%s", classify(werr))
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
		fmt.Printf("   BEGIN %-9s 耗時 %-8v %s\n", mode, elapsed, detail)
		_ = conn.Close()
		_ = probe.Close()
	}
	_ = holder2Tx.Rollback()
	_ = holder2.Close()

	fmt.Println("== 3) SAVEPOINT：內層回滾、外層仍可提交 ==")
	sp := mustOpen(dbPath, "")
	spTx, _ := sp.BeginTx(ctx, nil)
	if _, err := spTx.ExecContext(ctx, "INSERT INTO ledger (amount) VALUES (10)"); err != nil {
		fmt.Println("   外層寫入失敗：", err)
	}
	mustExecTx(ctx, spTx, "SAVEPOINT inner")
	_, _ = spTx.ExecContext(ctx, "INSERT INTO ledger (amount) VALUES (11)")
	_, _ = spTx.ExecContext(ctx, "ROLLBACK TO inner")
	_, _ = spTx.ExecContext(ctx, "RELEASE inner")
	if err := spTx.Commit(); err != nil {
		fmt.Println("   外層提交失敗：", err)
	}
	var amounts string
	rows, _ := sp.QueryContext(ctx, "SELECT group_concat(amount) FROM ledger")
	if rows.Next() {
		_ = rows.Scan(&amounts)
	}
	_ = rows.Close()
	fmt.Printf("   提交後 ledger 金額＝[%s]（預期僅 10：外層保留、內層 11 消失；前兩節的 1、3 已隨各自交易回滾）\n", amounts)
	_ = sp.Close()

	fmt.Println("== 4) 交易內 PRAGMA query_only(1) ==")
	ro := mustOpen(dbPath, "")
	roTx, _ := ro.BeginTx(ctx, nil)
	_, qerr := roTx.ExecContext(ctx, "PRAGMA query_only = 1")
	if qerr != nil {
		fmt.Println("   設定 query_only 失敗：", qerr)
	}
	_, werr2 := roTx.ExecContext(ctx, "INSERT INTO ledger (amount) VALUES (77)")
	fmt.Printf("   設 query_only=1 後寫入：%s\n", classify(werr2))
	var seen int
	_ = roTx.QueryRowContext(ctx, "SELECT count(*) FROM ledger").Scan(&seen)
	fmt.Printf("   唯讀交易仍可讀取：count=%d\n", seen)
	_, _ = roTx.ExecContext(ctx, "PRAGMA query_only = 0")
	_, werr3 := roTx.ExecContext(ctx, "INSERT INTO ledger (amount) VALUES (78)")
	fmt.Printf("   還原 query_only=0 後寫入：%s\n", classify(werr3))
	_ = roTx.Rollback()
	_ = ro.Close()

	fmt.Println("== 5) 嵌套 BEGIN（同一連線）==")
	ne := mustOpen(dbPath, "")
	conn2, err := ne.Conn(ctx)
	if err != nil {
		fmt.Println("   取得連線失敗：", err)
		os.Exit(1)
	}
	if _, err := conn2.ExecContext(ctx, "BEGIN"); err != nil {
		fmt.Println("   外層 BEGIN 失敗：", err)
	}
	_, nestedErr := conn2.ExecContext(ctx, "BEGIN")
	fmt.Printf("   交易內再 BEGIN：%s\n", classify(nestedErr))
	_, spErr := conn2.ExecContext(ctx, "SAVEPOINT sp_nested")
	fmt.Printf("   交易內 SAVEPOINT：%s\n", classify(spErr))
	_, _ = conn2.ExecContext(ctx, "ROLLBACK")
	_ = conn2.Close()
	_ = ne.Close()

	fmt.Println("== 6) 唯讀（deferred）交易的快照一致性 ==")
	snap := mustOpen(dbPath, "")
	snapTx, _ := snap.BeginTx(ctx, nil)
	var first int
	_ = snapTx.QueryRowContext(ctx, "SELECT count(*) FROM ledger").Scan(&first)
	other := mustOpen(dbPath, "")
	mustExec(ctx, other, "INSERT INTO ledger (amount) VALUES (55)")
	var second int
	_ = snapTx.QueryRowContext(ctx, "SELECT count(*) FROM ledger").Scan(&second)
	var after int
	_ = other.QueryRowContext(ctx, "SELECT count(*) FROM ledger").Scan(&after)
	fmt.Printf("   交易內兩次讀取＝%d、%d（期間他連線已提交，外部看到 %d）→ 快照一致=%v\n",
		first, second, after, first == second)
	_ = snapTx.Rollback()
	_ = snap.Close()
	_ = other.Close()

	fmt.Println("== 7) 驅動對忙碌錯誤的可重試判定（主碼 5/6）==")
	fmt.Printf("   SQLITE_BUSY=%d SQLITE_LOCKED=%d；主碼判定：code&0xff ∈ {5,6}\n",
		sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)

	fmt.Println("== 8) 交易中途程序退出：不產生半筆（NFR-010）==")
	kill := mustOpen(dbPath, "")
	mustExec(ctx, kill, "CREATE TABLE crash_log (id INTEGER PRIMARY KEY, body TEXT NOT NULL)")
	_ = kill.Close()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), envChild+"=1", envChildDB+"="+dbPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	var exitErr *exec.ExitError
	fmt.Printf("   子程序在交易內強制退出：err=%v（退出碼 %d）\n", err, func() int {
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		return 0
	}())
	verify := mustOpen(dbPath, "")
	var leftover int
	_ = verify.QueryRowContext(ctx, "SELECT count(*) FROM crash_log").Scan(&leftover)
	var integrity string
	_ = verify.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity)
	fmt.Printf("   重開後 crash_log 筆數=%d（預期 0）／integrity_check=%s\n", leftover, integrity)
	_ = verify.Close()

	fmt.Println("完成")
}

// runChild 模擬「交易中途程序退出」：寫入多筆後直接結束程序，不提交也不回滾。
func runChild(ctx context.Context, dbPath string) {
	pool := mustOpen(dbPath, "")
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		fmt.Println("   子程序 BeginTx 失敗：", err)
		os.Exit(1)
	}
	for i := 0; i < 50; i++ {
		if _, err := tx.ExecContext(ctx, "INSERT INTO crash_log (body) VALUES ('半筆')"); err != nil {
			fmt.Println("   子程序寫入失敗：", err)
			os.Exit(1)
		}
	}
	fmt.Println("   子程序已寫入 50 筆但未提交，現強制退出")
	os.Exit(3)
}
