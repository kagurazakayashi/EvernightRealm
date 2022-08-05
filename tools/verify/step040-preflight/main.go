// 探針：資料庫檔頭標記、唯讀開啟與預檢可行性實證。
//
// 目的：在實作開庫前預檢前，先確認下列事實（純 Go，無 cgo）：
//  1. 純檔案讀取可正確解析 SQLite 檔頭的 user_version 與 application_id；
//  2. modernc.org/sqlite 支援 mode=ro + query_only 唯讀開啟，且唯讀連線無法寫入；
//  3. WAL 已提交但未 checkpoint 時，主檔檔頭落後、而 SQLite 連線（含唯讀）看得到新值；
//  4. 以可寫 DSN 開啟非 SQLite 檔會失敗，且是否改動原檔；
//  5. 以可寫 DSN 開啟「他人的 SQLite 檔」（application_id 非本服務）會成功——即驅動層不做識別。
//
// 執行：go run ./tools/verify/step040-preflight
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	_ "modernc.org/sqlite"
)

// 檔頭欄位偏移（SQLite 檔案格式）。
const (
	offsetUserVersion      = 60
	offsetApplicationID    = 68
	sqliteHeaderSize       = 100
	evernightApplicationID = 0x4556524C // 'EVRL'
)

// dsn 與正式服務相同的可寫連線字串形式。
func dsn(path string, extra string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	base := "file:" + strings.Join(parts, "/")
	if extra != "" {
		return base + "?" + extra
	}
	return base + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
}

// header 以純檔案讀取解析檔頭。
func header(path string) (userVersion, applicationID int, magicOK bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false, err
	}
	if len(data) < sqliteHeaderSize {
		return 0, 0, false, fmt.Errorf("檔案長度不足（%d 位元組）", len(data))
	}
	magicOK = string(data[:16]) == "SQLite format 3\x00"
	userVersion = int(binary.BigEndian.Uint32(data[offsetUserVersion : offsetUserVersion+4]))
	applicationID = int(binary.BigEndian.Uint32(data[offsetApplicationID : offsetApplicationID+4]))
	return userVersion, applicationID, magicOK, nil
}

func hashOf(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "（不存在）"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

func main() {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "step040-probe")
	if err != nil {
		fmt.Println("建立暫存目錄失敗：", err)
		os.Exit(1)
	}
	defer func() {
		// 清理失敗必須單獨報告並讓探針以非零碼結束：觀察全過但目錄殘留時
		// 不能假裝清理成功；原本已失敗的路徑在此之前已由 os.Exit 定案退出碼。
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			fmt.Printf("暫存目錄清理失敗（殘留：%s）：%v\n", dir, err)
			os.Exit(1)
		}
	}()
	dbPath := filepath.Join(dir, "probe.db")

	// 準備：建立含標記的資料庫。
	setup, err := sql.Open("sqlite", dsn(dbPath, ""))
	if err != nil {
		fmt.Println("開啟失敗：", err)
		os.Exit(1)
	}
	mustExec(ctx, setup, "CREATE TABLE probe_table (id INTEGER PRIMARY KEY)")
	mustExec(ctx, setup, fmt.Sprintf("PRAGMA application_id = %d", evernightApplicationID))
	mustExec(ctx, setup, "PRAGMA user_version = 7")
	if err := setup.Close(); err != nil {
		fmt.Println("關閉失敗：", err)
		os.Exit(1)
	}

	fmt.Println("== 1) 純檔案讀取檔頭 ==")
	uv, appID, magicOK, err := header(dbPath)
	fmt.Printf("   magicOK=%v user_version=%d application_id=0x%08X（預期 7 與 0x%08X）err=%v\n",
		magicOK, uv, appID, evernightApplicationID, err)

	fmt.Println("== 2) 唯讀開啟（mode=ro + query_only）==")
	ro, err := sql.Open("sqlite", dsn(dbPath, "mode=ro&_pragma=query_only(1)"))
	if err != nil {
		fmt.Println("   sql.Open 失敗：", err)
	} else {
		var got int
		queryErr := ro.QueryRowContext(ctx, "PRAGMA user_version").Scan(&got)
		fmt.Printf("   讀取 user_version=%d err=%v\n", got, queryErr)
		_, writeErr := ro.ExecContext(ctx, "CREATE TABLE should_fail (id INTEGER)")
		fmt.Printf("   唯讀連線寫入（預期失敗）：%v\n", writeErr)
		_ = ro.Close()
	}
	fmt.Printf("   唯讀開啟後主檔雜湊：%s（WAL 檔存在=%v）\n", hashOf(dbPath), exists(dbPath+"-wal"))

	fmt.Println("== 3) WAL 已提交未 checkpoint：主檔檔頭 vs 連線所見 ==")
	holder, err := sql.Open("sqlite", dsn(dbPath, ""))
	if err != nil {
		fmt.Println("   開啟失敗：", err)
	} else {
		mustExec(ctx, holder, "PRAGMA user_version = 9")
		uv2, _, _, _ := header(dbPath)
		var viaConn int
		_ = holder.QueryRowContext(ctx, "PRAGMA user_version").Scan(&viaConn)
		fmt.Printf("   主檔檔頭 user_version=%d（落後）／同連線所見=%d（預期 9）\n", uv2, viaConn)
		ro2, err := sql.Open("sqlite", dsn(dbPath, "mode=ro&_pragma=query_only(1)"))
		if err != nil {
			fmt.Println("   唯讀開啟失敗：", err)
		} else {
			var viaRO int
			roErr := ro2.QueryRowContext(ctx, "PRAGMA user_version").Scan(&viaRO)
			fmt.Printf("   唯讀連線所見 user_version=%d err=%v\n", viaRO, roErr)
			_ = ro2.Close()
		}
		_ = holder.Close()
	}
	uv3, _, _, _ := header(dbPath)
	fmt.Printf("   關閉後（自動 checkpoint）主檔檔頭 user_version=%d（預期 9）\n", uv3)

	fmt.Println("== 4) 可寫 DSN 開啟非 SQLite 檔 ==")
	junkPath := filepath.Join(dir, "junk.db")
	junk := []byte("這不是資料庫檔，只是純文字。\n")
	if err := os.WriteFile(junkPath, junk, 0o600); err != nil {
		fmt.Println("   寫入測試檔失敗：", err)
	}
	before := hashOf(junkPath)
	conn, err := sql.Open("sqlite", dsn(junkPath, ""))
	pingErr := error(nil)
	if err == nil {
		pingErr = conn.PingContext(ctx)
		_ = conn.Close()
	}
	after, err2 := os.ReadFile(junkPath)
	fmt.Printf("   sql.Open err=%v ping err=%v\n", err, pingErr)
	fmt.Printf("   原檔內容不變=%v（雜湊 %s → %s）\n", string(after) == string(junk), before, hashOf(junkPath))
	_ = err2

	fmt.Println("== 5) 可寫 DSN 開啟他人的 SQLite 檔（application_id 不同）==")
	foreignPath := filepath.Join(dir, "foreign.db")
	foreign, err := sql.Open("sqlite", dsn(foreignPath, ""))
	if err != nil {
		fmt.Println("   建立失敗：", err)
	} else {
		mustExec(ctx, foreign, "CREATE TABLE someone_elses (id INTEGER PRIMARY KEY)")
		mustExec(ctx, foreign, "PRAGMA application_id = 305419896")
		_ = foreign.Close()
	}
	fuv, fapp, _, _ := header(foreignPath)
	fmt.Printf("   他人的檔：user_version=%d application_id=0x%08X\n", fuv, fapp)
	foreignRO, err := sql.Open("sqlite", dsn(foreignPath, ""))
	if err == nil {
		var tables int
		scanErr := foreignRO.QueryRowContext(ctx,
			"SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables)
		fmt.Printf("   以本服務可寫 DSN 開啟：err=%v 使用者資料表數=%d（驅動層不做識別，需自行預檢）\n", scanErr, tables)
		_ = foreignRO.Close()
	}
}

func mustExec(ctx context.Context, db *sql.DB, query string) {
	if _, err := db.ExecContext(ctx, query); err != nil {
		fmt.Printf("   執行 %q 失敗：%v\n", query, err)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
