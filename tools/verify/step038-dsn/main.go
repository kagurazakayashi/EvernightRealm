// 驗證 modernc.org/sqlite 的 DSN 形式在 Windows 上對特殊路徑的相容性（探針原型，可丟棄）。
//
// 背景：資料目錄可能含空格、非 ASCII（中文）甚至 '%' 與 '#' 字元。
// modernc.org/sqlite 會把 DSN 交給 sqlite3_open_v2 並帶 SQLITE_OPEN_URI 旗標，
// 因此以 "file:" 開頭的 DSN 會被 SQLite 當成 URI 解析並做 %XX 解碼；
// 未帶 "file:" 前綴時則視為純檔案路徑，不做 URI 解碼。
//
// 驗證場景：對每種路徑分別嘗試四種 DSN 形式，並檢查
//  1. 連線、建表、寫入與 PRAGMA 是否成功；
//  2. 實際落地的檔案是否為預期檔名（避免 URI 誤判造成「路徑被改寫」或建立奇怪檔案）。
//
// 用法：於倉庫根目錄執行 `go run ./tools/verify/step038-dsn`
// 結果以 PASS/FAIL 輸出；本程式不引入正式資產業務。
package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	_ "modernc.org/sqlite"
)

// 固定參數組（與決策記錄 DEC-002 一致）。
const params = "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"

var failures int

func report(name string, ok bool, detail string) {
	status := "PASS"
	if !ok {
		status = "FAIL"
		failures++
	}
	fmt.Printf("[%s] %s — %s\n", status, name, detail)
}

// encodePath 逐段以 URL 路徑規則編碼（空格→%20、非 ASCII→UTF-8 %XX、'%'→%25、'#'→%23），
// 保留 '/' 作為分隔；Windows 磁碟機代號的 ':' 不編碼。
func encodePath(p string) string {
	parts := strings.Split(filepath.ToSlash(p), "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// tryForm 以指定 DSN 開啟資料庫、建表寫入後關閉，並回報實際檔案狀態。
func tryForm(label, dsn, wantPath string) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		report(label, false, "sql.Open 失敗: "+err.Error())
		return
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS probe (id INTEGER PRIMARY KEY, note TEXT)`); err != nil {
		report(label, false, "建表失敗: "+err.Error())
		return
	}
	if _, err := db.Exec(`INSERT INTO probe (note) VALUES ('ok')`); err != nil {
		report(label, false, "寫入失敗: "+err.Error())
		return
	}
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		report(label, false, "讀取 journal_mode 失敗: "+err.Error())
		return
	}

	// 檢查預期檔案是否存在（比對檔名，避免 URI 解碼把路徑改寫成別的檔名）。
	info, statErr := os.Stat(wantPath)
	if statErr != nil {
		report(label, false, fmt.Sprintf("預期檔案不存在: %v（journal_mode=%s）", statErr, mode))
		return
	}
	report(label, true, fmt.Sprintf("journal_mode=%s，檔案 %s（%d bytes）", mode, filepath.Base(wantPath), info.Size()))
}

func main() {
	root, err := os.MkdirTemp("", "step038-dsn-*")
	if err != nil {
		fmt.Println("建立暫存目錄失敗:", err)
		os.Exit(1)
	}
	defer func() {
		// 清理失敗必須單獨報告並讓探針以非零碼結束：樣本全過但目錄殘留時
		// 不能假裝清理成功；原本已失敗的路徑在此之前已由 os.Exit 定案退出碼。
		if err := devkit.RemoveAllWithRetry(root); err != nil {
			fmt.Printf("暫存目錄清理失敗（殘留：%s）：%v\n", root, err)
			os.Exit(1)
		}
	}()

	// 四種路徑樣本：純 ASCII、含空格、含中文、含 '%' 與 '#'。
	cases := []struct {
		name string
		dir  string
	}{
		{"純ASCII", filepath.Join(root, "plain")},
		{"含空格", filepath.Join(root, "with space", "sub dir")},
		{"含中文", filepath.Join(root, "資料 目錄", "長夜")},
		{"含%與#", filepath.Join(root, "pct%dir", "hash#tag")},
	}

	forms := []struct {
		label string
		build func(p string) string
	}{
		{"file:+原始路徑", func(p string) string { return "file:" + filepath.ToSlash(p) + params }},
		{"file:+URI編碼路徑", func(p string) string { return "file:" + encodePath(p) + params }},
		{"file:///+URI編碼路徑", func(p string) string { return "file:///" + encodePath(p) + params }},
		{"裸路徑(無file:前綴)", func(p string) string { return filepath.ToSlash(p) + params }},
	}

	fmt.Printf("== modernc.org/sqlite DSN 形式相容性驗證 ==\n暫存根目錄: %s\n\n", root)
	for _, c := range cases {
		if err := os.MkdirAll(c.dir, 0o750); err != nil {
			fmt.Println("建立樣本目錄失敗:", err)
			os.Exit(1)
		}
		fmt.Printf("-- 路徑樣本：%s\n   目錄: %s\n", c.name, c.dir)
		for _, f := range forms {
			label := fmt.Sprintf("%s / %s", c.name, f.label)
			// 每個形式用不同檔名，避免互相影響。
			dbPath := filepath.Join(c.dir, strings.NewReplacer("/", "_", " ", "_").Replace(f.label)+".db")
			tryForm(label, f.build(dbPath), dbPath)
		}
		fmt.Println()
	}

	fmt.Printf("== 結果：%d 個失敗 ==\n", failures)
	if failures > 0 {
		os.Exit(1)
	}
}
