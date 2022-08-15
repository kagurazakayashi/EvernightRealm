// 單寫入實例約束：以資料庫檔旁的鎖檔配合作業系統層級檔案鎖實現。
//
// 選用檔案鎖而非「鎖檔是否存在」的判斷，是因為程序崩潰或被強制結束時
// 作業系統會自動釋放鎖，不會留下需要人工清理的殘留狀態。
// 鎖檔一律不刪除：刪除會與「另一程序已開啟同一鎖檔、正要上鎖」形成競態，
// 反而可能讓兩個程序同時寫入。
package database

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// lockSuffix 為鎖檔副檔名；與資料庫檔同目錄，確保與資料庫一同位於可寫位置。
const lockSuffix = ".lock"

// lockFilePerm 為鎖檔權限：僅供本機服務程序使用。
const lockFilePerm = 0o600

// holderInfoLimit 為讀取持有者資訊的位元組上限。
const holderInfoLimit = 256

// fileLock 為持有中的檔案鎖。
type fileLock struct {
	file *os.File
	path string
}

// ErrLocked 表示鎖檔由別的程式持有（單寫入實例約束生效）。
//
// 它存在的理由只有一個：讓呼叫端能用 errors.Is 判出「服務正在跑」這種可預期的拒絕，
// 而不是去比對錯誤字串——訊息會改，判別不該跟著壞。
var ErrLocked = errors.New("database: 資料庫已被其他服務程序鎖定")

// acquireLock 對 <資料庫檔>.lock 取得獨佔鎖。
//
// 已被其他程序持有時回傳可診斷的錯誤（含鎖檔路徑），
// 由呼叫端決定結束碼；本函式不嘗試等待或搶佔。
func acquireLock(dbPath string) (*fileLock, error) {
	lockPath := dbPath + lockSuffix
	file, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, lockFilePerm)
	if err != nil {
		return nil, fmt.Errorf("database: 建立鎖檔失敗（%s）: %w", lockPath, err)
	}
	if err := lockFile(file); err != nil {
		holder := readHolderInfo(file)
		_ = file.Close()
		message := fmt.Sprintf(
			"database: 資料庫已被其他服務程序鎖定（單寫入實例約束），拒絕第二個寫入者（%s）",
			lockPath)
		if holder != "" {
			message += "；目前持有者：" + holder
		}
		message += "；請確認沒有第二個 evernight-server 正在使用同一資料目錄"
		return nil, fmt.Errorf("%s: %w（系統錯誤：%v）", message, ErrLocked, err)
	}

	// 寫入持有者資訊僅供診斷（人工查看鎖檔即可得知誰持有）；不作為任何判斷依據。
	_ = file.Truncate(0)
	info := fmt.Sprintf("pid=%d started=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	if _, err := file.WriteAt([]byte(info), 0); err != nil {
		_ = file.Sync()
	}
	return &fileLock{file: file, path: lockPath}, nil
}

// readHolderInfo 讀出鎖檔內由持有者寫入的診斷資訊（僅供訊息提示，不作為判斷依據）。
//
// 取不到鎖的程序仍然可以讀檔，因此能直接告訴使用者是誰持有；
// 內容一律截短並去除換行與控制字元，避免訊息被污染。
func readHolderInfo(file *os.File) string {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ""
	}
	buf := make([]byte, holderInfoLimit)
	n, err := file.Read(buf)
	if err != nil && n == 0 {
		return ""
	}
	info := strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return -1
		}
		return r
	}, string(buf[:n]))
	return strings.TrimSpace(info)
}

// release 釋放檔案鎖並關閉鎖檔；可安全重複呼叫。
func (l *fileLock) release() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unlockFile(l.file)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return fmt.Errorf("database: 釋放鎖檔失敗（%s）: %w", l.path, unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("database: 關閉鎖檔失敗（%s）: %w", l.path, closeErr)
	}
	return nil
}
