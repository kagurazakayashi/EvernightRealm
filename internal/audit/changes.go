package audit

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/redact"
)

// changeWire 是變更摘要在資料庫裡的單筆形状（欄位名 + 遮罩後的前後值）。
type changeWire struct {
	Field  string `json:"field"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
	// HadBefore／HadAfter 區分「值是空字串／false」與「這個值本來就沒有」：
	// 只靠 omitempty 會讓 `暱稱從 空字串 改成 X` 變成看不出起點。
	HadBefore bool `json:"had_before"`
	HadAfter  bool `json:"had_after"`
}

// ErrChangesTooLarge 表示展開後的摘要超出單筆記錄可容納的體積。
//
// 這是失敗而不是截斷：審計的價值在於「查得出來」，靜默丟掉後半段會留下一筆
// 看起來完整的記錄，而它恰好少了最關鍵的幾欄。批量操作請記一筆摘要（例如影響多少筆）。
var ErrChangesTooLarge = errors.New("audit: 變更摘要超過單筆上限，請改記摘要而非逐欄展開")

// encodeChanges 序列化變更摘要，並在序列化前逐值遮罩（實作 ER-SEC-001 §7）。
//
// 數值與布林保留 JSON 原生型別（餘額從 500 變成 300 這種事實必須查得出來），
// 字串走 redact.Value：欄位名命中「永不記錄」時值變成 [redacted]，
// 命中「只留標識」時變成 ref#短識別，其餘仍要掃憑證形狀與限長。
func encodeChanges(changes []Change) (string, error) {
	if len(changes) == 0 {
		// 空摘要也是合法記錄（登入、廣播、重啟都沒有欄位差量）；存成 "[]" 而非空字串，
		// 讓「沒有差量」與「忘了寫」在資料庫裡是可區分的兩件事。
		return "[]", nil
	}
	wire := make([]changeWire, 0, len(changes))
	for _, c := range changes {
		before, hasBefore := maskValue(c.Field, c.Before)
		after, hasAfter := maskValue(c.Field, c.After)
		wire = append(wire, changeWire{
			Field: c.Field, Before: before, After: after,
			HadBefore: hasBefore, HadAfter: hasAfter,
		})
	}
	data, err := json.Marshal(wire)
	if err != nil {
		return "", fmt.Errorf("audit: 序列化變更摘要失敗: %w", err)
	}
	if len(data) > maxChangesByte {
		return "", ErrChangesTooLarge
	}
	return string(data), nil
}

// maskValue 把一個變更值轉成可落庫的形狀，並回傳「呼叫端確實給這個值」。
func maskValue(field string, value any) (any, bool) {
	if value == nil {
		return nil, false
	}
	switch typed := value.(type) {
	case string:
		return redact.Value(field, typed), true
	case bool:
		// 布林不掃描：它只能是 true/false，沒有可遮罩的內容；欄位名規則仍適用。
		if redact.ActionFor(field) == redact.NeverRecord {
			return redact.Redacted, true
		}
		return typed, true
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, float32, float64:
		// 數值同理（例如餘額、數量）；低熵數值本身可能就是 PIN，這類欄位一律走
		// 「永不記錄」的名單，因此仍會被換成佔標。
		if redact.ActionFor(field) == redact.NeverRecord {
			return redact.Redacted, true
		}
		return typed, true
	default:
		return redact.Value(field, fmt.Sprint(value)), true
	}
}

// decodeChanges 還原資料庫裡的變更摘要；內容不合法時回傳錯誤而非靜默丟棄。
//
// 讀不出來的摘要若被跳過，那筆審計就變成「有記錄、看不出改什麼」，
// 這比報錯更難查——寧可讓查詢失敗並點出記錄標識。
func decodeChanges(recordID, raw string) ([]Change, error) {
	if raw == "" {
		return nil, nil
	}
	var wire []changeWire
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		return nil, fmt.Errorf("audit: 記錄 %s 的變更摘要不是合法 JSON: %w", recordID, err)
	}
	out := make([]Change, 0, len(wire))
	for _, item := range wire {
		out = append(out, Change{Field: item.Field, Before: presence(item.Before, item.HadBefore), After: presence(item.After, item.HadAfter)})
	}
	return out, nil
}

// presence 把「值不存在」與「值為空字串／false」分開還原。
func presence(value any, had bool) any {
	if !had {
		return nil
	}
	return value
}
