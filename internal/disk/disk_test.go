package disk

import (
	"math"
	"strings"
	"testing"
)

func TestThresholdsUnlimited(t *testing.T) {
	if !(Thresholds{}).Unlimited() {
		t.Error("零值應為不設限")
	}
	for _, th := range []Thresholds{{MinFreeBytes: 1}, {MinFreePercent: 0.01}} {
		if th.Unlimited() {
			t.Errorf("設了下限卻回報不設限：%+v", th)
		}
	}
	// 負的百分比是配錯，不是「比 0 更寬」：目前等同不設限，若改成拒絕請同步更新此斷言。
	if (Thresholds{MinFreePercent: -5}).Unlimited() != true {
		t.Error("負百分比目前等同不設限，若改成拒絕請同步更新此斷言")
	}
}

func TestEvaluatePicksTheStricterBound(t *testing.T) {
	cases := []struct {
		name       string
		th         Thresholds
		free       uint64
		total      uint64
		wantStatus Status
		wantReason string
	}{
		{"未設下限一律通過", Thresholds{}, 1, 100 << 30, StatusOK, ""},
		{"絕對下限命中", Thresholds{MinFreeBytes: 64 << 20}, 32 << 20, 100 << 30, StatusLow, "絕對下限"},
		{"絕對下限剛好等於", Thresholds{MinFreeBytes: 64 << 20}, 64 << 20, 100 << 30, StatusOK, ""},
		{"百分比下限命中", Thresholds{MinFreePercent: 5}, 4 << 30, 100 << 30, StatusLow, "5.00%"},
		{"百分比下限剛好等於", Thresholds{MinFreePercent: 5}, 5 << 30, 100 << 30, StatusOK, ""},
		// 取較嚴者：絕對下限在此比百分比更嚴（100 GiB 的 1% 是 1 GiB，低於 2 GiB）。
		{"兩條都設時由較嚴的那條決定", Thresholds{MinFreeBytes: 2 << 30, MinFreePercent: 1},
			1 << 30, 100 << 30, StatusLow, "絕對下限"},
		{"兩條都設但都未命中", Thresholds{MinFreeBytes: 1 << 20, MinFreePercent: 1},
			50 << 30, 100 << 30, StatusOK, ""},
		{"查不到容量算無法判定", Thresholds{MinFreeBytes: 1}, 0, 0, StatusUnknown, "無法判定"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := tc.th.Evaluate(Usage{Free: tc.free, Total: tc.total})
			if err != nil {
				t.Fatalf("不應回報錯誤：%v", err)
			}
			if verdict.Status != tc.wantStatus {
				t.Errorf("狀態 = %v，want %v", verdict.Status, tc.wantStatus)
			}
			if tc.wantReason == "" && verdict.Reason != "" {
				t.Errorf("通過時不應給原因：%q", verdict.Reason)
			}
			if tc.wantReason != "" && !strings.Contains(verdict.Reason, tc.wantReason) {
				t.Errorf("原因未含 %q：%q", tc.wantReason, verdict.Reason)
			}
		})
	}
}

func TestEvaluateRejectsUnusablePercent(t *testing.T) {
	for _, pct := range []float64{101, math.Inf(1), math.NaN()} {
		if _, err := (Thresholds{MinFreePercent: pct}).Evaluate(Usage{Free: 1, Total: 100}); err == nil {
			t.Errorf("百分比 %v 應被拒絕而不是當成無效", pct)
		}
	}
}

func TestBasisPointsRoundingKeepsFractionalPercent(t *testing.T) {
	// 5.5% 換算成萬分比必須是 550：小數被無條件捨去會讓下限偏小，也就是判得更寬。
	bps, err := (Thresholds{MinFreePercent: 5.5}).basisPoints()
	if err != nil {
		t.Fatal(err)
	}
	if bps != 550 {
		t.Errorf("萬分比 = %d，want 550", bps)
	}
}

func TestHumanBytesUnits(t *testing.T) {
	cases := map[uint64]string{
		0:          "0 B",
		1023:       "1023 B",
		1024:       "1.0 KiB",
		5 << 20:    "5.0 MiB",
		3 << 30:    "3.0 GiB",
		1 << 50:    "1.0 PiB",
		32 << 50:   "32.0 PiB",
		1024 << 50: "",
	}
	for n, want := range cases {
		got := HumanBytes(n)
		if want == "" {
			if !strings.HasSuffix(got, "EiB") {
				t.Errorf("超大數值應收斂到 EiB 而不是溢位或回空：%d → %q", n, got)
			}
			continue
		}
		if got != want {
			t.Errorf("HumanBytes(%d) = %q，want %q", n, got, want)
		}
	}
}

func TestStatusStringNeverEmpty(t *testing.T) {
	// 狀態詞會進日誌與啟動摘要：空字串會讓「沒有狀態」看起來像「狀態正常」。
	for _, s := range []Status{StatusOK, StatusLow, StatusUnknown, Status(42)} {
		if got := s.String(); got == "" {
			t.Errorf("Status(%d) 回傳空字串", int(s))
		}
	}
	if got := Status(42).String(); !strings.Contains(got, "42") {
		t.Errorf("未知狀態應把數值露出來：%q", got)
	}
}
