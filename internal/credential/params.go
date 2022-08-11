package credential

// 本檔集中參數策略與資源上限的唯一定義點。
//
// 「生產參數」與「測試參數」的分界在這裡：ProductionParams 是出廠預設，
// 任何降低強度的取值（小記憶體、小時間成本）只應出現在測試程式碼裡，
// 由測試自行構造 Params 傳入，而不是改動本檔常數或讓配置校驗放寬下限。

// Params 是一份 Argon2id 參數策略。
//
// 欄位與 PHC 編碼一一對應；MemoryKiB 以 KiB 計，但 Argon2 實作只接受
// MiB 整數倍，非整數倍在派生時就近向上取整（見 derive）。
// 編碼字串保留寫入時的原始值，因此校驗也做同樣的取整，雙向一致。
type Params struct {
	// MemoryKiB 是記憶體成本（KiB）。
	MemoryKiB uint32
	// TimeCost 是時間成本（遍數）。
	TimeCost uint32
	// Parallelism 是並行度（執行緒數）。
	Parallelism uint8
	// KeyLength 是摘要輸出長度（位元組）。
	KeyLength uint32
}

// 參數合法區間。下限取自 Argon2 規範與 OWASP 對「可配置最低檔」的姿態：
// 允許部署者把記憶體調到 8 MiB 這種除錯檔，但不允許 0／1 這種「等於沒算」的取值。
// 上限同時是校驗惡意編碼時的硬性資源天花板（見 Verify）。
const (
	// MinMemoryKiB 是記憶體成本下限（8 MiB）。
	MinMemoryKiB = 8 * 1024
	// MaxMemoryKiB 是記憶體成本上限（1 GiB）：超過即視為損壞或惡意編碼，
	// 直接拒絕，不進入派生——這條上限就是「壞雜湊不能要求無限記憶體」的執行點。
	MaxMemoryKiB = 1024 * 1024
	// MinTimeCost 是時間成本下限。
	MinTimeCost = 1
	// MaxTimeCost 是時間成本上限：與 MaxMemoryKiB 相乘即單次派生的最壞工作量，
	// 「壞雜湊不能要求無限 CPU」由這個乘積有界保證。
	MaxTimeCost = 32
	// MinParallelism 是並行度下限。
	MinParallelism = 1
	// MaxParallelism 是並行度上限（區域網單機場景沒有超過 8 的合理需求，
	// 收緊上限同時壓小 memoryKiB >= 8*p 的邊界情形）。
	MaxParallelism = 8
	// MinKeyLength 是摘要長度下限（位元組）。
	MinKeyLength = 16
	// MaxKeyLength 是摘要長度上限（位元組，argon2 實作的硬上限）。
	MaxKeyLength = 64
)

// ProductionParams 是出廠預設的生產參數檔：最低推薦檔（約 64 MiB、3 遍、4 並行）。
//
// 可被組態檔 security.hashing 各欄覆蓋（用戶決定：參數進配置，不鎖死），
// 覆蓋只影響「之後新產生的憑據」；既有憑據按編碼內參數校驗，永不因為換檔而失效。
var ProductionParams = Params{
	MemoryKiB:   64 * 1024,
	TimeCost:    3,
	Parallelism: 4,
	KeyLength:   32,
}

// TestParams 是專供測試的低成本檔（1 MiB、1 遍、1 並行）。
//
// 放在產製碼裡只為一個目的：讓「測試必須快速」與「測試不得借用生產檔」
// 寫在同一處、彼此可見。測試直接使用本值，不許拿 ProductionParams 減速，
// 也不許四處散落自造的更小參數。
var TestParams = Params{
	MemoryKiB:   MinMemoryKiB,
	TimeCost:    MinTimeCost,
	Parallelism: MinParallelism,
	KeyLength:   MinKeyLength,
}

// Validate 回報參數是否落在許可區間，並檢查 Argon2 規範的關聯約束
// （記憶體不得低于 8×並行度 KiB，否則並行執行緒無從分配工作區）。
//
// 錯誤訊息只複述欄位值（參數不是秘密），不含任何憑據材料。
func (p Params) Validate() error {
	if err := p.checkCosts(); err != nil {
		return err
	}
	if p.KeyLength < MinKeyLength || p.KeyLength > MaxKeyLength {
		return paramRange("keylen", p.KeyLength, MinKeyLength, MaxKeyLength)
	}
	return nil
}

// validateCosts 只校驗 m/t/p 三項成本欄（不含 KeyLength）。
//
// PHC 編碼不聲明摘要長度——長度就是摘要段的實際長度，要等解析完才知道，
// 所以參數段先行只能驗到這裡；KeyLength 由 decode 落值後補驗。
func (p Params) validateCosts() error { return p.checkCosts() }

// checkCosts 是 Validate 的成本部分（m/t/p 與 8p 關聯），不含 KeyLength。
func (p Params) checkCosts() error {
	switch {
	case p.MemoryKiB < MinMemoryKiB || p.MemoryKiB > MaxMemoryKiB:
		return paramRange("m", p.MemoryKiB, MinMemoryKiB, MaxMemoryKiB)
	case p.TimeCost < MinTimeCost || p.TimeCost > MaxTimeCost:
		return paramRange("t", p.TimeCost, MinTimeCost, MaxTimeCost)
	case p.Parallelism < MinParallelism || p.Parallelism > MaxParallelism:
		return paramRange("p", p.Parallelism, MinParallelism, MaxParallelism)
	case uint64(p.MemoryKiB) < 8*uint64(p.Parallelism):
		return paramRange("m>=8*p", p.MemoryKiB, 8*uint32(p.Parallelism), MaxMemoryKiB)
	}
	return nil
}
