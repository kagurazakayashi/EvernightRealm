package devkit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"syscall"
	"time"
)

// 暫存目錄清理在 Windows 上會與句柄釋放競爭：SQLite 關閉連線後 -wal/-shm 的
// 釋放有落後，防毒與索引服務也可能在刪除期間碰目錄，因此單次 os.RemoveAll
// 偶發「目錄非空／檔被佔用」。重試採有限次數與固定間隔，總等待有上限，
// 不讓清理問題拖慢或掩蓋測試本身的結果。
const (
	tempRemoveAttempts = 5                      // 含首次在內的刪除次數上限
	tempRemoveInterval = 200 * time.Millisecond // 每次重試之間的等待
)

// RemoveAllWithRetry 刪除整個暫存目錄，只在「占用類」錯誤時有限重試。
//
// 目錄已不存在視同清理成功；權限、路徑非法等真實錯誤原樣回傳、不重試也不吞掉。
// 重試耗盡時回傳最後一次錯誤並附重試次數，呼叫端據此報告殘留絕對路徑。
func RemoveAllWithRetry(dir string) error {
	return removeAllWithRetry(dir, os.RemoveAll, tempRemoveAttempts, tempRemoveInterval)
}

// removeAllWithRetry 是 RemoveAllWithRetry 的可注入核心：remove 讓測試能用
// 可控替身精確重現「短暫占用」「耗盡」與「真實錯誤」三類路徑。
func removeAllWithRetry(dir string, remove func(string) error, attempts int, interval time.Duration) error {
	var last error
	for i := 1; i <= attempts; i++ {
		err := remove(dir)
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if !isBusyError(err) {
			return err
		}
		last = err
		if i < attempts {
			time.Sleep(interval)
		}
	}
	return fmt.Errorf("清理 %d 次後暫存目錄仍被占用: %w", attempts, last)
}

// isBusyError 判定錯誤是否屬於「稍後重試有機會成功」的占用類。
//
// UNIX 上對應 EBUSY／ENOTEMPTY；Windows 上刪除進行中的檔案會以原生錯誤碼
// 回報共享違反（32）與鎖違反（33），這些數字在 UNIX 上是完全不相干的 errno，
// 因此只在 windows 平台比對。其餘錯誤（如權限拒絕）一律視真實錯誤。
func isBusyError(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.EBUSY, syscall.ENOTEMPTY:
		return true
	}
	if runtime.GOOS == "windows" {
		switch int(errno) {
		case 32, 33: // ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION
			return true
		}
	}
	return false
}
