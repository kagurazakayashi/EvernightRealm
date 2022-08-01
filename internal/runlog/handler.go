package runlog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/redact"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// redactingHandler 是日誌鏈的最外層：把記錄的時間正規化為 UTC、
// 並在交給下游任何寫出器之前遮罩訊息與欄位值。
//
// 脫敏放在最外層（而非每個寫出器各做一遍）有兩個理由：
// 一是下游寫出器只有「一份已脫敏的記錄」這個事實來源，不會各寫一套規則；
// 二是下游若日後新增（詳細健康狀態、審計轉存），忘接脫敏的那一份不會變成漏網之魚。
type redactingHandler struct {
	next  slog.Handler
	now   func() time.Time
	group string
}

// newRedacting 以最外層規則包裝下游寫出器；now 為 nil 時沿用記錄原有時刻（只轉 UTC）。
func newRedacting(next slog.Handler, now func() time.Time) *redactingHandler {
	return &redactingHandler{next: next, now: now}
}

// Enabled 交由下游判斷層級是否可記錄。
func (h *redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

// Handle 遮罩後把同一份記錄交給下游。
//
// 時刻一律轉為 UTC：本服務的資料庫與協議都存 UTC（規格 §27.2、DEC-015），
// 日誌若用本機時區會在跨日與日光節約邊界上對不上記錄。
// now 非 nil 時以它取代記錄原有時刻——測試注入固定時鐘，
// 也讓「時刻取自何處」與 timeutil.Clock 的既有約定保持同一個答案。
func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	at := r.Time.UTC()
	if h.now != nil {
		at = h.now().UTC()
	}
	out := slog.NewRecord(at, r.Level, redact.Text(r.Message), r.PC)
	attrs := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, redactAttr(a, h.group))
		return true
	})
	out.AddAttrs(attrs...)
	// 呼叫端資訊（PC）隨 NewRecord 一併帶過去，由下游寫出器依自己的組態決定要不要展開，
	// 本層不代為判定——否則「是否記錄來源行號」這種事會在兩處各說一次。
	return h.next.Handle(ctx, out)
}

// WithAttrs 先把附加欄位遮罩好再交給下游。
//
// 這一步不能省：以 logger.With(...) 綁定的欄位不會再經過 Handle，
// 只擋記錄欄位的話，`logger.With("password", 明細)` 就從側門把值原帶出去。
func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &redactingHandler{
		next:  h.next.WithAttrs(redactAttrs(attrs, h.group)),
		now:   h.now,
		group: h.group,
	}
}

// WithGroup 把群組名累積進判定用的前綴。
//
// 下游在輸出時才把群組名展現，本層看到的是逐筆欄位；不自己累積的話，
// `logger.WithGroup("session").Info("m", "id", 憑證)` 這類「敏感度由群組名決定」的
// 欄位就會被當成普通欄位放過。
func (h *redactingHandler) WithGroup(name string) slog.Handler {
	group := name
	if h.group != "" && name != "" {
		group = h.group + "." + name
	}
	return &redactingHandler{next: h.next.WithGroup(name), now: h.now, group: group}
}

// redactAttrs 逐筆遮罩欄位（供 WithAttrs 使用）。
func redactAttrs(attrs []slog.Attr, prefix string) []slog.Attr {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = redactAttr(a, prefix)
	}
	return out
}

// redactAttr 依「群組全名 → 欄位名」的處置規則遮罩值，並保留原本的鍵名與群組結構。
//
// 判定用全名（如 session.token 正規化成 sessiontoken），輸出仍留在群組內用短名，
// 否則 JSON 會變成 {"session":{"session.token":…}} 這種兩層重複的形狀。
func redactAttr(a slog.Attr, prefix string) slog.Attr {
	effective := a.Key
	if prefix != "" && a.Key != "" {
		effective = prefix + "." + a.Key
	}
	switch a.Value.Kind() {
	case slog.KindGroup:
		inner := a.Value.Group()
		out := make([]slog.Attr, len(inner))
		for i, sub := range inner {
			out[i] = redactAttr(sub, effective)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	case slog.KindString:
		return slog.String(a.Key, redact.Value(effective, a.Value.String()))
	case slog.KindAny:
		// 任意型別（error、結構體）只能先壓成文字再遮罩：這正是值裡最常見到憑證的一條路。
		return slog.String(a.Key, redact.Text(fmt.Sprint(a.Value.Any())))
	default:
		return a
	}
}

// fanoutHandler 把同一份記錄同時交給多個寫出器（日誌檔案與標準錯誤輸出）。
//
// 一份事實、兩個呈現：兩邊各存一份記錄會產生「畫面說有、檔案說沒有」這種查不清的分歧。
type fanoutHandler struct {
	handlers []slog.Handler
}

// Enabled 在任何一個下游可記錄時回傳 true（全部同層級時等同於單個下游的判定）。
func (f *fanoutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// Handle 寫入全部下游；即使某個下游失敗，其餘下游仍要寫完，失敗以合併的錯誤回傳。
//
// 日誌檔案寫入失敗（磁碟已滿屬後續步驟的監測範圍）不該順帶讓標準錯誤輸出也閉嘴，
// 否則故障當下恰好失去唯一看得見的記錄管道。
func (f *fanoutHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range f.handlers {
		if err := h.Handle(ctx, r); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// WithAttrs 對每個下游各自附加。
func (f *fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &fanoutHandler{handlers: mapHandlers(f.handlers, func(h slog.Handler) slog.Handler { return h.WithAttrs(attrs) })}
}

// WithGroup 對每個下游各自展開群組。
func (f *fanoutHandler) WithGroup(name string) slog.Handler {
	return &fanoutHandler{handlers: mapHandlers(f.handlers, func(h slog.Handler) slog.Handler { return h.WithGroup(name) })}
}

// mapHandlers 對每個下游套用變換並回傳新清單（不共用同一切片，避免串接後相互覆寫）。
func mapHandlers(handlers []slog.Handler, fn func(slog.Handler) slog.Handler) []slog.Handler {
	out := make([]slog.Handler, len(handlers))
	for i, h := range handlers {
		out[i] = fn(h)
	}
	return out
}

// humanHandler 把記錄寫成一行人類可讀的文字：時間 層級 訊息 鍵=值 …
//
// 存在的理由是要能在本機 Ctrl+C 終端裡直接讀懂發生什麼；程式判讀一律走 JSON 那份。
// 值一律經過 Escape：控制字元（含換行）若原樣送出，客戶端可控的文字
// （標頭、路徑、錯誤訊息）就能在日誌裡偽造出額外行，把排錯引到別處去。
type humanHandler struct {
	w     io.Writer
	mu    *sync.Mutex
	level slog.Level
	attrs []slog.Attr
	group []string
}

// newHumanHandler 建立寫往 w 的人類可讀寫出器；w 為 nil 時丟棄記錄。
// mu 為 nil 時自行建立（單一封鎖讓多個下游共用同一個寫入器時不交錯）。
func newHumanHandler(w io.Writer, level slog.Level, mu *sync.Mutex) *humanHandler {
	if mu == nil {
		mu = &sync.Mutex{}
	}
	return &humanHandler{w: w, mu: mu, level: level}
}

// Enabled 回傳層級是否達到組態門檻。
func (h *humanHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle 寫出一行；無寫入器時靜默丟棄（供不想要 stderr 輸出的場合）。
func (h *humanHandler) Handle(_ context.Context, r slog.Record) error {
	if h.w == nil {
		return nil
	}
	var b strings.Builder
	b.WriteString(timeutil.FormatUTC(r.Time))
	b.WriteByte(' ')
	b.WriteString(r.Level.String())
	b.WriteByte(' ')
	if r.Message != "" {
		b.WriteString(escapeHuman(r.Message))
	}
	for _, a := range h.attrs {
		writeHumanAttr(&b, a, h.group)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeHumanAttr(&b, a, h.group)
		return true
	})
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

// WithAttrs 回傳附加欄位後的寫出器（共享同一把鎖與同一個寫入器）。
func (h *humanHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := *h
	out.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &out
}

// WithGroup 回傳展開群組名後的寫出器。
func (h *humanHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	out := *h
	out.group = append(append([]string{}, h.group...), name)
	return &out
}

// writeHumanAttr 輸出一個欄位（群組欄位以「群組名.鍵名」展平，值仍各自遮罩）。
func writeHumanAttr(b *strings.Builder, a slog.Attr, groups []string) {
	key := a.Key
	if len(groups) > 0 {
		key = strings.Join(append(append([]string{}, groups...), key), ".")
	}
	if a.Value.Kind() == slog.KindGroup {
		nested := append(append([]string{}, groups...), a.Key)
		for _, sub := range a.Value.Group() {
			writeHumanAttr(b, sub, nested)
		}
		return
	}
	b.WriteByte(' ')
	b.WriteString(sanitizeKey(key))
	b.WriteByte('=')
	b.WriteString(escapeHuman(humanValue(a.Value)))
}

// humanValue 把欄位值壓成文字；時刻與歷時另有慣用格式，其餘交由 slog.Value.String()。
func humanValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindTime:
		return timeutil.FormatUTC(v.Time())
	case slog.KindDuration:
		return v.Duration().String()
	default:
		return v.String()
	}
}

// sanitizeKey 把鍵名裡的空白、控制字元與分隔符換成底線。
//
// 鍵名由程式碼給定，正常情況不會觸發；這是一道防呆，
// 避免日後有人把客戶端輸入直接當成欄位名傳進來。
func sanitizeKey(key string) string {
	if key == "" {
		return "_"
	}
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		switch {
		case r <= 0x20, r == 0x7f, r == '=', r == '"', r == '\\':
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// escapeHuman 必要時加上雙引號並跳脫控制字元，使一個欄位值永遠只佔一行。
func escapeHuman(value string) string {
	if value == "" {
		return `""`
	}
	plain := !strings.ContainsAny(value, " \t\r\n\"\\") && !hasControl(value)
	if plain {
		return value
	}
	var b strings.Builder
	b.Grow(len(value) + 2)
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			// 空白本身照原樣保留（值已在引號內），只有會破壞行結構的控制字元才跳脫。
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// hasControl 回傳文字是否含 ASCII 控制字元（含空白與跳脫符）。
func hasControl(value string) bool {
	for _, r := range value {
		if r <= 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
