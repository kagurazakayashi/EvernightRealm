//go:build !windows

package disk

import "golang.org/x/sys/unix"

// volumeSpace 取得 path 所在卷的可用空間與總容量。
//
// Bavail 是「給非特權程序」的可用區塊數（Linux 預設保留 5% 給 root，故 ext4 上
// Bfree 與 Bavail 差那 5%）：跑在保留區之外才是本程序寫得進去的量，取 Bavail 才誠實。
//
// Bsize 與基礎區塊大小的單位在多數平台一致，但 Bsize 可能是有號型別（darwin 為 int32），
// 因此一律先轉 int64 再乘，不假設它是 uint64。
func volumeSpace(path string) (free, total uint64, err error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, 0, err
	}
	blockSize := int64(stat.Bsize)
	if blockSize <= 0 {
		return 0, 0, ErrUnknown
	}
	return uint64(stat.Bavail) * uint64(blockSize), uint64(stat.Blocks) * uint64(blockSize), nil
}
