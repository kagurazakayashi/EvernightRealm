package app

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/config"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/disk"
	"github.com/kagurazakayashi/EvernightRealm/internal/httpapi"
	"github.com/kagurazakayashi/EvernightRealm/internal/runlog"
)

// impossibleThreshold 是一個任何真實卷都不可能滿意的下限：用它來測「不足」
// 比去把開發機寫滿更可靠，也不會影響其他測試（判定只問這個目錄所在的那個卷）。
const impossibleThreshold = int64(1) << 62

func TestDiskNoteNamesBothStates(t *testing.T) {
	cfg := config.Default()
	if got := diskNote(cfg); !strings.Contains(got, "未啟用") {
		t.Errorf("預設組態的啟動摘要應明確寫未啟用：%q", got)
	}
	cfg.Disk.MinFreeBytes = 1 << 30
	cfg.Disk.MinFreePercent = 5
	got := diskNote(cfg)
	for _, want := range []string{"1.0 GiB", "5%"} {
		if !strings.Contains(got, want) {
			t.Errorf("啟用後的摘要缺少 %q：%q", want, got)
		}
	}
}

func TestCheckSpaceBeforeWriteRejectsWhenLow(t *testing.T) {
	space := disk.New(retryTempDir(t), disk.Thresholds{MinFreeBytes: uint64(impossibleThreshold)}, 0, nil)
	err := checkSpaceBeforeWrite(space, runlog.WriterLogger(io.Discard))
	if !errors.Is(err, disk.ErrNoSpace) {
		t.Fatalf("空間不足時應回 ErrNoSpace，實際 %v", err)
	}
	// 原因要跟著錯誤出去：啟動失敗只有結束碼可看時，排錯的人會從這裡得到第一個線索。
	if !strings.Contains(err.Error(), "低於") {
		t.Errorf("錯誤未帶判定原因：%v", err)
	}
}

func TestCheckSpaceBeforeWritePassesWhenUnlimited(t *testing.T) {
	space := disk.New(retryTempDir(t), disk.Thresholds{}, time.Minute, nil)
	if err := checkSpaceBeforeWrite(space, runlog.WriterLogger(io.Discard)); err != nil {
		t.Errorf("未設下限時不應阻擋啟動：%v", err)
	}
}

func TestReadinessCheckMapsLowSpaceToNoSpaceCode(t *testing.T) {
	db := openPlainDB(t)
	ctx := context.Background()

	low := disk.New(retryTempDir(t), disk.Thresholds{MinFreeBytes: uint64(impossibleThreshold)}, time.Minute, nil)
	err := readinessCheck(db, low)(ctx)
	var unready *httpapi.UnreadyError
	if !errors.As(err, &unready) {
		t.Fatalf("空間不足應回帶碼的就緒錯誤，實際 %v", err)
	}
	if unready.Code != httpapi.CodeNoSpace {
		t.Errorf("機器碼 = %d，want %d", unready.Code, httpapi.CodeNoSpace)
	}

	// 未設下限（預設）時，磁碟不參與判定：就緒與否仍只取決於資料庫。
	open := disk.New(retryTempDir(t), disk.Thresholds{}, time.Minute, nil)
	if err := readinessCheck(db, open)(ctx); err != nil {
		t.Errorf("未啟用時不應報不就緒：%v", err)
	}
}

// TestReadinessCheckReportsUnknownAsNotReady 固定一個刻意的取捨：
// 探測失敗時不假裝正常，但仍把原因留在 1007 而不是 1008（那時候我們不知道夠不夠）。
func TestReadinessCheckReportsUnknownAsNotReady(t *testing.T) {
	db := openPlainDB(t)
	// 一個不可能存在的目錄：探測必然失敗，判定成為 StatusUnknown。
	space := disk.New(`Q:\definitely-not-mounted\evernight-data`,
		disk.Thresholds{MinFreeBytes: 1 << 20}, time.Minute, nil)

	err := readinessCheck(db, space)(context.Background())
	if err == nil {
		t.Fatal("查不出來時不應回報就緒")
	}
	var unready *httpapi.UnreadyError
	if errors.As(err, &unready) {
		t.Errorf("無法判定不是「空間不足」，不應借用 1008：%v", err)
	}
}

// TestRunRefusesStartupWhenDiskLow 是「仍能診斷並安全停止」的進程級證據（單元層版）：
// 空間不足時啟動中止、不開放監聽、也不執行任何遷移。
func TestRunRefusesStartupWhenDiskLow(t *testing.T) {
	dir := retryTempDir(t)
	t.Setenv("ER_SERVER_DATA_DIR", dir)
	// 一個卷不可能有 2 EiB 的自由空間：這條檢查在任何機器上都成立。
	t.Setenv("ER_DISK_MIN_FREE_BYTES", "4611686018427387904")

	out := &syncBuffer{}
	err := run(t.Context(), func() {}, []string{"--data-dir", dir}, out, io.Discard)
	if err == nil {
		t.Fatalf("空間不足時啟動應失敗，輸出：%s", out.String())
	}
	if !errors.Is(err, disk.ErrNoSpace) {
		t.Errorf("應由磁碟檢查拒絕，實際 %v", err)
	}
	got := out.String()
	if strings.Contains(got, "資料庫遷移：已套用") || strings.Contains(got, "監聽") {
		t.Errorf("拒絕發生在遷移與監聽之前，輸出卻顯示已進行：%s", got)
	}
	if !strings.Contains(err.Error(), "低於") {
		t.Errorf("錯誤要帶得出原因：%v", err)
	}
}

// openPlainDB 開一個只為了滿足 readinessCheck 那個「依賴還活著」判斷的資料庫。
//
// 它刻意不跑遷移：本檔測的是磁碟那一半，把遷移摻進來只會讓失敗時分不清是誰。
func openPlainDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(context.Background(), database.Options{
		Path: filepath.Join(retryTempDir(t), "evernight.db"),
	})
	if err != nil {
		t.Fatalf("開測試資料庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
