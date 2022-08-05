// 驗證 modernc.org/sqlite 在 Windows 上的事務與 WAL 行為（探針原型，可丟棄）。
//
// 驗證場景：
//  1. WAL 模式生效（journal_mode=wal 且生成 -wal 檔案）。
//  2. 事務原子性：單一事務內部分失敗應整體回滾。
//  3. 外鍵約束生效（PRAGMA foreign_keys=ON）。
//  4. 併發寫：無 busy_timeout 時第二寫者應收到 SQLITE_BUSY；有 busy_timeout 時應等待後成功。
//  5. WAL 讀寫併發：寫事務未提交時，另一連線可讀到舊快照（讀不阻塞）。
//
// 用法：於倉庫根目錄執行 `go run ./tools/verify/step024-sqlite-wal`
// 結果以 PASS/FAIL 輸出；本程式不引入正式資產業務。
package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	_ "modernc.org/sqlite"
)

var failures int

func report(name string, ok bool, detail string) {
	status := "PASS"
	if !ok {
		status = "FAIL"
		failures++
	}
	fmt.Printf("[%s] %s — %s\n", status, name, detail)
}

func main() {
	dir, err := os.MkdirTemp("", "step024-wal-*")
	if err != nil {
		fmt.Println("建立暫存目錄失敗:", err)
		os.Exit(1)
	}
	defer func() {
		// 清理失敗必須單獨報告並讓探針以非零碼結束：場景全過但目錄殘留時
		// 不能假裝清理成功；原本已失敗的路徑在此之前已由 os.Exit 定案退出碼。
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			fmt.Printf("暫存目錄清理失敗（殘留：%s）：%v\n", dir, err)
			os.Exit(1)
		}
	}()

	dbPath := filepath.Join(dir, "verify.db")
	fmt.Printf("== SQLite WAL/事務驗證 ==\n資料庫: %s\n\n", dbPath)

	// 場景 1：WAL 模式
	dsn := "file:" + filepath.ToSlash(dbPath) + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db1, err := sql.Open("sqlite", dsn)
	if err != nil {
		report("場景1 WAL 開啟", false, err.Error())
		os.Exit(1)
	}
	defer db1.Close()

	var mode string
	if err := db1.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		report("場景1 WAL 模式", false, err.Error())
	} else {
		report("場景1 WAL 模式", mode == "wal", "journal_mode="+mode)
	}

	// 建表（含外鍵）
	_, err = db1.Exec(`CREATE TABLE parent (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
		CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL REFERENCES parent(id));`)
	if err != nil {
		report("場景2 建表", false, err.Error())
		os.Exit(1)
	}
	report("場景2 建表與外鍵", true, "parent/child 已建立")

	// 場景 2：事務原子性（第二條違反 NOT NULL 約束 → 整體回滾）
	tx, err := db1.Begin()
	if err != nil {
		report("場景2 開啟事務", false, err.Error())
	} else {
		_, _ = tx.Exec(`INSERT INTO parent(id, name) VALUES (1, 'A')`)
		_, err2 := tx.Exec(`INSERT INTO parent(id, name) VALUES (2, NULL)`) // 違反 NOT NULL
		rollErr := tx.Rollback()
		_ = rollErr
		var cnt int
		_ = db1.QueryRow(`SELECT COUNT(*) FROM parent`).Scan(&cnt)
		report("場景2 事務原子性", err2 != nil && cnt == 0,
			fmt.Sprintf("第二筆錯誤=%v，回滾後 parent 筆數=%d", err2, cnt))
	}

	// 場景 3：外鍵約束
	_, _ = db1.Exec(`INSERT INTO parent(id, name) VALUES (10, 'P')`)
	_, fkErr := db1.Exec(`INSERT INTO child(id, parent_id) VALUES (100, 999)`) // 不存在的 parent
	report("場景3 外鍵約束", fkErr != nil, fmt.Sprintf("插入非法子記錄錯誤=%v", fkErr))

	// 場景 4：併發寫（busy_timeout=0 → 第二寫者 BUSY）
	dsnNoBusy := "file:" + filepath.ToSlash(dbPath) + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(0)"
	db2, err := sql.Open("sqlite", dsnNoBusy)
	if err != nil {
		report("場景4 連線2", false, err.Error())
		os.Exit(1)
	}
	defer db2.Close()
	db2.SetMaxOpenConns(1)

	tx1, _ := db1.Begin()
	_, _ = tx1.Exec(`INSERT INTO parent(id, name) VALUES (20, 'locked')`)
	_, busyErr := db2.Exec(`INSERT INTO parent(id, name) VALUES (30, 'busy')`)
	_ = tx1.Rollback()
	report("場景4 併發寫 BUSY", busyErr != nil,
		fmt.Sprintf("busy_timeout=0 時第二寫者錯誤=%v（期望 SQLITE_BUSY）", busyErr))

	// 場景 4b：busy_timeout=5000 → 等待後成功
	dsnBusy := "file:" + filepath.ToSlash(dbPath) + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db3, err := sql.Open("sqlite", dsnBusy)
	if err != nil {
		report("場景4b busy 連線", false, err.Error())
		os.Exit(1)
	}
	defer db3.Close()
	db3.SetMaxOpenConns(1)

	txA, _ := db1.Begin()
	_, _ = txA.Exec(`INSERT INTO parent(id, name) VALUES (40, 'A')`)
	start := time.Now()
	writeDone := make(chan error, 1)
	go func() {
		_, err := db3.Exec(`INSERT INTO parent(id, name) VALUES (50, 'B')`)
		writeDone <- err
	}()
	time.Sleep(200 * time.Millisecond) // 確保第二寫者已進入等待
	_ = txA.Commit()
	waitErr := <-writeDone
	elapsed := time.Since(start)
	report("場景4b busy_timeout 等待", waitErr == nil,
		fmt.Sprintf("第二寫者等待 %v 後成功（錯誤=%v）", elapsed.Round(time.Millisecond), waitErr))

	// 場景 5：WAL 讀寫併發（寫未提交，讀舊快照）
	db4, _ := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	defer db4.Close()
	db4.SetMaxOpenConns(1)
	_, _ = db4.Exec(`DELETE FROM parent`)

	var wg sync.WaitGroup
	readResult := make(chan int, 1)
	wg.Add(1)
	txW, _ := db1.Begin()
	_, _ = txW.Exec(`INSERT INTO parent(id, name) VALUES (70, 'uncommitted')`)
	go func() {
		defer wg.Done()
		var c int
		_ = db4.QueryRow(`SELECT COUNT(*) FROM parent`).Scan(&c)
		readResult <- c
	}()
	_ = txW.Commit()
	wg.Wait()
	readCount := <-readResult
	report("場景5 WAL 讀寫併發", readCount == 0,
		fmt.Sprintf("寫事務未提交期間另一連線讀到 %d 筆（期望 0，WAL 舊快照）", readCount))

	// 場景 6：WAL 檔案生成
	walPath := dbPath + "-wal"
	if info, err := os.Stat(walPath); err == nil {
		report("場景6 -wal 檔案", info.Size() >= 0, fmt.Sprintf("%s 存在（%d bytes）", filepath.Base(walPath), info.Size()))
	} else {
		report("場景6 -wal 檔案", false, err.Error())
	}

	fmt.Printf("\n== 結果：%d 個失敗 ==\n", failures)
	if failures > 0 {
		os.Exit(1)
	}
}
