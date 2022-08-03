// 本文件實作磁碟空間的監測與寫保護判定，是全服務對此問題的唯一出口。
//
// 為什麼要有這個套件（規格 OPS-009、AT-020、RSK-005）：可用空間耗盡時，資料庫與檔案
// 都會寫不下去，而最壞的結果不是「失敗」，是「回報成功卻沒有落盤」。因此「還夠不夠」
// 必須有一個說得出口的判定，而不是等 SQLite 丟出 disk I/O error 之後從訊息裡猜。
//
// 三條不可讓步：
//   - 判定只有一處：任何要攔寫入的地方都問同一個 Monitor，不在各自的地方重寫閾值算式；
//   - 查不出來不等於夠，也不等於不夠：Unknown 不攔寫入（一個系統呼叫失敗就把服務弄成
//     不可用是更壞的故障），但必須如實回報，讓 /ready 與日誌看得出「現在是看不見」；
//   - 閾值預設為 0＝不設限（DEC-028 的既定取向）：設了正值才有上限，這件事寫進啟動摘要
//     與維運手冊，不在程式碼裡偷偷給一個「比較安全」的預設值。
package disk

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// ErrNoSpace 表示可用空間低於設定的下限，新的不安全寫入應拒絕。
//
// 呼叫端用 errors.Is 判定，不要比對字串：這顆哨兵同時是寫交易回給上層的錯誤，
// 也是 /ready 判不就緒的理由之一，比對訊息文字會讓兩邊各寫一份。
var ErrNoSpace = errors.New("disk: 可用空間不足，拒絕新的寫入")

// ErrUnknown 表示無法取得卷的可用空間（目錄不存在、權限、或不支援的平台）。
//
// 這是「查不到」而不是「查過且足夠」：把它與 ErrNoSpace 分成兩顆哨兵，
// 呼叫端才能決定哪一個要攔、哪一個只報告。
var ErrUnknown = errors.New("disk: 無法判定磁碟可用空間")

// Status 是判定的三種結果之一。
type Status int

// 判定結果。
const (
	// StatusOK 是空間足夠（或未設任何下限）。
	StatusOK Status = iota
	// StatusLow 是空間低於下限：新的不安全寫入要拒絕。
	StatusLow
	// StatusUnknown 是查不出來：不攔寫入，但要如實回報「無法判定」。
	StatusUnknown
)

// String 回傳可寫進日誌與診斷輸出的狀態詞。
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusLow:
		return "low"
	case StatusUnknown:
		return "unknown"
	default:
		// 不回傳空字串：狀態詞會進日誌，空白比一個點出數值的unknown更難查。
		return fmt.Sprintf("invalid(%d)", int(s))
	}
}

// Usage 是一次探測得到的事實。
type Usage struct {
	// Path 是實際查詢的目錄（判定所依據的卷由它決定）。
	Path string
	// Free 是該目錄可用給本程序的位元組數。
	Free uint64
	// Total 是該卷的總容量；為 0 時視為查不到（避免把「除以 0」讀成 0% 剩餘）。
	Total uint64
	// CheckedAt 是取得這兩個數字的時刻（UTC，取自注入的時鐘）。
	CheckedAt time.Time
}

// Verdict 是判定結果與可寫進日誌的原因。
//
// Reason 在 StatusOK 時是空字串：湊一句「一切正常」讓日誌多一行沒有資訊量的文字，
// 而告警與否正是靠「有沒有原因」判斷的。
type Verdict struct {
	Status Status
	Usage  Usage
	Reason string
}

// Thresholds 是下限設定。兩個條件任一命中即為不足（取較嚴者）。
//
// 取較嚴者的理由：512 MiB 在 8 GiB 的隨身碟上是災難，在 4 TiB 的資料盤上只是零頭；
// 只用絕對值會讓小盤沒有保護，只用百分比會讓大盤保護得過晚（或過早）。
// 零值＝該條件不設限。
type Thresholds struct {
	// MinFreeBytes 是剩餘空間的絕對下限；0 表示不按絕對值設限。
	MinFreeBytes uint64
	// MinFreePercent 是剩餘空間佔總容量的下限百分比（如 5 代表 5%）；0 表示不按比例設限。
	//
	// 這是給人的寫法，內部換算成萬分比再比較，避免浮點誤差讓同一個輸入在不同機器上
	// 得到不同判定——帳務不用浮點是 DEC-001 的基線，判定雖不是帳務，也沒有理由留浮點。
	MinFreePercent float64
}

// bpsScale 是萬分比的分母。
const bpsScale = 10_000

// Unlimited 回傳是否兩條下限都沒設（即本步的判定等於關閉）。
func (t Thresholds) Unlimited() bool {
	return t.MinFreeBytes == 0 && t.MinFreePercent <= 0
}

// basisPoints 把百分比換成萬分比（無效或過大一律拒用，不猜意圖）。
func (t Thresholds) basisPoints() (uint64, error) {
	if t.MinFreePercent <= 0 {
		return 0, nil
	}
	if math.IsNaN(t.MinFreePercent) || t.MinFreePercent > 100 {
		return 0, fmt.Errorf("disk: min_free_percent 需介於 0～100，實際為 %v", t.MinFreePercent)
	}
	return uint64(math.Round(t.MinFreePercent * bpsScale / 100)), nil
}

// Evaluate 依下限判定這次探測。
//
// 探測本身失敗（Usage.Total 為 0 代表查不到）回 StatusUnknown，不混進 StatusLow：
// 「不知道」與「知道不夠」要給人的處置不同，前者是去修探測，後者是去清盤。
func (t Thresholds) Evaluate(u Usage) (Verdict, error) {
	bps, err := t.basisPoints()
	if err != nil {
		return Verdict{Status: StatusUnknown, Usage: u}, err
	}
	if u.Total == 0 {
		return Verdict{Status: StatusUnknown, Usage: u,
			Reason: "未取得卷容量，無法判定可用空間"}, nil
	}

	if t.MinFreeBytes > 0 && u.Free < t.MinFreeBytes {
		return Verdict{Status: StatusLow, Usage: u,
			Reason: fmt.Sprintf("剩餘 %s 低於絕對下限 %s", HumanBytes(u.Free), HumanBytes(t.MinFreeBytes))}, nil
	}
	// total × bps 需要超過 33 PB 的卷才會溢位 uint64，這裡不另做大數處理，
	// 但把邊界寫下來：真有人拿這個量級的卷部署時，這行註解是唯一的提醒。
	if bps > 0 && u.Free*bpsScale < u.Total*bps {
		return Verdict{Status: StatusLow, Usage: u,
			Reason: fmt.Sprintf("剩餘 %.2f%% 低於下限 %.2f%%",
				float64(u.Free)/float64(u.Total)*100, t.MinFreePercent)}, nil
	}
	return Verdict{Status: StatusOK, Usage: u}, nil
}

// HumanBytes 把位元組數壓成適合寫進摘要的寫法。
//
// 只有一個地方需要這個格式（啟動摘要與告警），故放在本套件而不是 internal/webassets/bundle：
// 那邊的 HumanBytes 負責的是內嵌產物體積，兩者對「MiB」的取捨不同，合併只會讓一方出現小數。
func HumanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	value := float64(n)
	for _, u := range units {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, u)
		}
	}
	return fmt.Sprintf("%.1f EiB", value/unit)
}
