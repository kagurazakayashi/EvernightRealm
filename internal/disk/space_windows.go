//go:build windows

package disk

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// volumeSpace 取得 path 所在卷的可用空間與總容量。
//
// 標準庫的 syscall 在 Windows 沒有匯出 GetDiskFreeSpaceEx（實測 undefined），
// 故與單寫入鎖一樣走 golang.org/x/sys/windows——它已是本專案的直接依賴，未新增anything。
//
// 第一個回傳值是「給本程序可用的剩餘位元組」（考慮磁碟配額），比第二個「卷的總剩餘」
// 更適合拿來判斷「我們寫得下去嗎」，因此 Free 取它；Total 取卷總容量，讓百分比下限
// 對齊人的直覺（看的是這個卷還剩多少）。
func volumeSpace(path string) (free, total uint64, err error) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	var freeToCaller, totalBytes, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(pointer, &freeToCaller, &totalBytes, &totalFree); err != nil {
		return 0, 0, err
	}
	return freeToCaller, totalBytes, nil
}
