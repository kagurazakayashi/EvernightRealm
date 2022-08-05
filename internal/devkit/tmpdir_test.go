package devkit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// busyErr 造出一個判定為「占用類」的錯誤，與 Windows 實測到的 os.RemoveAll
// 失敗同形（*PathError 包 syscall.Errno）。
func busyErr(dir string) error {
	return &os.PathError{Op: "remove", Path: dir, Err: syscall.Errno(32)}
}

// TestRemoveAllWithRetryFirstSuccess 首次即成功的正常路徑：只呼叫一次 remove。
func TestRemoveAllWithRetryFirstSuccess(t *testing.T) {
	calls := 0
	err := removeAllWithRetry("/tmp/x", func(string) error {
		calls++
		return nil
	}, 3, time.Millisecond)
	if err != nil {
		t.Fatalf("應清理成功，實際 %v", err)
	}
	if calls != 1 {
		t.Errorf("首次成功不應再重試，呼叫 %d 次", calls)
	}
}

// TestRemoveAllWithRetryBusyThenSuccess 短暫占用後成功：前兩次回占用類錯誤，
// 第三次交還真實刪除，目錄必須被實際清掉且不回錯。
func TestRemoveAllWithRetryBusyThenSuccess(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := removeAllWithRetry(dir, func(p string) error {
		calls++
		if calls <= 2 {
			return busyErr(p)
		}
		return os.RemoveAll(p)
	}, 5, time.Millisecond)
	if err != nil {
		t.Fatalf("占用解除後應清理成功，實際 %v", err)
	}
	if calls != 3 {
		t.Errorf("應第 3 次成功，實際呼叫 %d 次", calls)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("目錄應已被刪除，實際 %v", err)
	}
}

// TestRemoveAllWithRetryExhausted 重試耗盡：占用類錯誤不消失時，必須回傳包含
// 最後一次占用原因的錯誤（附重試次數），且呼叫次數不超過上限。
func TestRemoveAllWithRetryExhausted(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	err := removeAllWithRetry(dir, func(p string) error {
		calls++
		return busyErr(p)
	}, 4, time.Millisecond)
	if err == nil {
		t.Fatal("耗盡時應回錯誤，不得假裝清理成功")
	}
	if calls != 4 {
		t.Errorf("重試次數應止於上限 4，實際 %d", calls)
	}
	if !errors.Is(err, syscall.Errno(32)) {
		t.Errorf("錯誤鏈應保留最後一次占用原因，實際 %v", err)
	}
	// 目錄本體仍在（替身沒真的刪）：殘留路徑由呼叫端報告，這裡確認不被吞。
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Errorf("替身未刪除，目錄應仍存在，實際 %v", statErr)
	}
}

// TestRemoveAllWithRetryRealErrorUntouched 真實錯誤不被當成占用：權限類錯誤
// 只呼叫一次就原樣回傳，不重試、不包裝成「仍被占用」。
func TestRemoveAllWithRetryRealErrorUntouched(t *testing.T) {
	calls := 0
	perm := &os.PathError{Op: "remove", Path: "/tmp/y", Err: syscall.EACCES}
	err := removeAllWithRetry("/tmp/y", func(string) error {
		calls++
		return perm
	}, 5, time.Millisecond)
	if calls != 1 {
		t.Errorf("非占用類錯誤不應重試，呼叫 %d 次", calls)
	}
	if !errors.Is(err, syscall.EACCES) {
		t.Errorf("應原樣回傳權限錯誤，實際 %v", err)
	}
}

// TestRemoveAllWithRetryMissingDir 目錄不存在視同已清理：真實 os.RemoveAll
// 對不存在路徑回 nil，注入的 ErrNotExist 錯誤也必須判成功。
func TestRemoveAllWithRetryMissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-dir")
	if err := RemoveAllWithRetry(missing); err != nil {
		t.Errorf("不存在目錄應回 nil，實際 %v", err)
	}
	notExist := fmt.Errorf("wrap: %w", os.ErrNotExist)
	err := removeAllWithRetry("/tmp/z", func(string) error { return notExist }, 3, time.Millisecond)
	if err != nil {
		t.Errorf("ErrNotExist 類錯誤應視同清理成功，實際 %v", err)
	}
}

// TestRemoveAllWithRetryWindowsRealDir Windows 實測路徑：只操作本測試自建的
// 目錄，走真實 os.RemoveAll，首次即成功且目錄確實消失。
func TestRemoveAllWithRetryWindowsRealDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "f.txt"), []byte("v"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveAllWithRetry(dir); err != nil {
		t.Fatalf("自建目錄清理失敗：%v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("目錄應已消失，實際 %v", err)
	}
}
