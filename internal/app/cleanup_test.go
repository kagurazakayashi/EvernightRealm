package app

import (
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
)

// retryTempDir 在 t.TempDir 的清理之上補一道「有限次數、帶間隔」的重試。
//
// Windows 上 SQLite 連線關閉後 -wal/-shm 的句柄釋放有落後，防毒與索引服務
// 也可能與刪除並發，單次 os.RemoveAll 偶發「目錄非空／檔被占用」。重試次數
// 與總等待上限集中在 internal/devkit；耗盡時把殘留絕對路徑報告給本測試，
// 先於 t.TempDir 自身的清理執行，不覆蓋原有測試結果與退出碼語意。
func retryTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() {
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			t.Errorf("暫存目錄清理失敗（殘留：%s）：%v", dir, err)
		}
	})
	return dir
}
