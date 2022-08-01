package audit

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/redact"
)

// validActivityRecord 是一筆合法的活動審計記錄（測試逐條偏離它來驗證校驗規則）。
func validActivityRecord() Record {
	return Record{
		Scope:      ScopeActivity,
		ActivityID: mustID(t0),
		Actor:      Actor{Kind: ActorAdmin, ID: mustID(t1)},
		Action:     "balance.adjust",
		Target:     Target{Kind: "player", ID: mustID(t2).String()},
		Reason:     "活動結束後糾錯",
		RequestID:  "01a0de44-91d2-73b1-afe3-d98997199751",
		Changes:    []Change{{Field: "balance", Before: 500, After: 300}},
	}
}

// 幾個固定標識（測試用，避免每處重複產生）。
const (
	t0 = "0198c2f4-7a3e-7b21-9c8d-1e2f3a4b5c6d"
	t1 = "0198c2f4-7a3e-7b21-9c8d-1e2f3a4b5c6e"
	t2 = "0198c2f4-7a3e-7b21-9c8d-1e2f3a4b5c6f"
)

func mustID(text string) idgen.ID {
	id, err := idgen.Parse(text)
	if err != nil {
		panic(err)
	}
	return id
}

func TestValidateAcceptsBothScopes(t *testing.T) {
	root := Record{
		Scope:  ScopeRoot,
		Actor:  Actor{Kind: ActorSystem},
		Action: "maintenance.enter",
		Target: Target{Kind: "server"},
		Reason: "維護視窗",
	}
	if err := root.validate(); err != nil {
		t.Errorf("Root 審計（系統主體、無請求 ID）應合法：%v", err)
	}
	if err := validActivityRecord().validate(); err != nil {
		t.Errorf("活動審計應合法：%v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name  string
		spoil func(*Record)
		want  string
	}{
		{"未知作用域", func(r *Record) { r.Scope = "session" }, "未知的審計作用域"},
		{"活動域缺 activity_id", func(r *Record) { r.ActivityID = idgen.Nil }, "必須帶 activity_id"},
		{"Root 域多 activity_id", func(r *Record) { r.Scope = ScopeRoot }, "不得帶 activity_id"},
		{"主體類別未知", func(r *Record) { r.Actor.Kind = "owner" }, "actor.kind"},
		{"非系統主體缺標識", func(r *Record) { r.Actor.ID = idgen.Nil }, "非系統主體"},
		{"系統主體不該帶標識", func(r *Record) { r.Actor.Kind = ActorSystem }, "actor.kind=system"},
		{"動作碼為空", func(r *Record) { r.Action = "" }, "action 不可為空"},
		{"動作碼含空白", func(r *Record) { r.Action = "balance adjust" }, "小寫機器碼"},
		{"動作碼大寫", func(r *Record) { r.Action = "Balance.Adjust" }, "小寫機器碼"},
		{"動作碼含控制字元", func(r *Record) { r.Action = "a\nb" }, "小寫機器碼"},
		{"動作碼超長", func(r *Record) { r.Action = strings.Repeat("a", maxActionLen+1) }, "長度不可超過"},
		{"對象類型為空", func(r *Record) { r.Target.Kind = "" }, "target.kind 不可為空"},
		{"對象 ID 含換行", func(r *Record) { r.Target.ID = "a\nb" }, "含控制字元"},
		{"活動域缺原因", func(r *Record) { r.Reason = "   " }, "必須填 reason"},
		{"原因超長", func(r *Record) { r.Reason = strings.Repeat("字", maxReasonLen+1) }, "reason 長度"},
		{"關聯 ID 超長", func(r *Record) { r.RequestID = strings.Repeat("x", maxRequestID+1) }, "request_id 長度"},
		{"變更多到上限", func(r *Record) {
			r.Changes = make([]Change, maxChanges+1)
			for i := range r.Changes {
				r.Changes[i] = Change{Field: "f"}
			}
		}, "變更欄位不可超過"},
		{"變更欄位名不合法", func(r *Record) { r.Changes = []Change{{Field: "新暱稱"}} }, "changes.field"},
	}
	for _, tc := range cases {
		rec := validActivityRecord()
		tc.spoil(&rec)
		err := rec.validate()
		if err == nil {
			t.Errorf("%s：應拒絕但通過了", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s：錯誤訊息未點出 %q：%v", tc.name, tc.want, err)
		}
	}
}

func TestValidateAllowsEmptyChanges(t *testing.T) {
	rec := validActivityRecord()
	rec.Changes = nil
	if err := rec.validate(); err != nil {
		t.Errorf("登入、廣播這類操作沒有欄位差量，應合法：%v", err)
	}
}

func TestEncodeChangesKeepsNumbersAndMasksStrings(t *testing.T) {
	const rawToken = "9f8e7d6c5b4a3210fedcba0b1c2d3e4f"
	changes := []Change{
		{Field: "balance", Before: 500, After: 300},
		{Field: "frozen", Before: false, After: true},
		{Field: "nickname", Before: "舊暱稱", After: "新暱稱"},
		{Field: "pin", Before: "1234", After: "4821"},
		{Field: "session_token", Before: "sess-9f8e7d6c5b4a3210fedcba", After: "sess-1111116c5b4a3210fedcba"},
		{Field: "chat_body", Before: "", After: "今晚八點在舊倉庫見面"},
		{Field: "acl", Before: nil, After: []string{"read", "write"}},
		{Field: "nickname", Before: "", After: "首次設定"},
		// 欄位名不在清單上也要靠值形狀兜住：管理員備註這類自由文字最常被人貼進金鑰。
		{Field: "remark", Before: "舊備註", After: rawToken},
	}
	raw, err := encodeChanges(changes)
	if err != nil {
		t.Fatalf("encodeChanges 失敗：%v", err)
	}
	for _, leak := range []string{"4821", "1234", "今晚八點在舊倉庫見面", "sess-9f8e7d6c5b4a3210fedcba", "sess-1111116c5b4a3210fedcba", rawToken} {
		if strings.Contains(raw, leak) {
			t.Errorf("原始憑證或正文出現在審計摘要裡：%s → %s", leak, raw)
		}
	}
	// 三種處置各要留下一個可見佔標：[redacted]（永不記錄）、ref#（只留標識）、[masked]（值形狀）。
	for _, want := range []string{"500", "300", "舊暱稱", "新暱稱", redact.Redacted, redact.RefPrefix, redact.Masked} {
		if !strings.Contains(raw, want) {
			t.Errorf("摘要缺少 %q：%s", want, raw)
		}
	}

	decoded, err := decodeChanges("x", raw)
	if err != nil {
		t.Fatalf("decodeChanges 失敗：%v", err)
	}
	if len(decoded) != len(changes) {
		t.Fatalf("還原筆數 = %d，want %d", len(decoded), len(changes))
	}
	if decoded[0].Before != float64(500) || decoded[0].After != float64(300) {
		t.Errorf("數值摘要被改了型別：%v → %v", decoded[0].Before, decoded[0].After)
	}
	// 「本來沒有這個值」與「值是空字串」必須仍可區分：前者是 nil，後者是 ""。
	if decoded[6].Before != nil {
		t.Errorf("未提供的 Before 應還原成 nil，實際 %#v", decoded[6].Before)
	}
	if decoded[7].Before != "" {
		t.Errorf("空字串的 Before 不應被當成 nil，實際 %#v", decoded[7].Before)
	}
}

func TestEncodeChangesEmptyIsExplicit(t *testing.T) {
	raw, err := encodeChanges(nil)
	if err != nil {
		t.Fatal(err)
	}
	if raw != "[]" {
		t.Errorf("空摘要應序列化成 [] （讓『沒有差量』與『忘了寫』可區分），實際 %q", raw)
	}
	decoded, err := decodeChanges("x", raw)
	if err != nil || len(decoded) != 0 {
		t.Errorf("空摘要讀回不符：%v / %v", decoded, err)
	}
}

func TestEncodeChangesRejectsOversizedPayload(t *testing.T) {
	changes := make([]Change, maxChanges)
	long := strings.Repeat("長", 500)
	for i := range changes {
		changes[i] = Change{Field: "note", Before: long, After: long}
	}
	if _, err := encodeChanges(changes); !errors.Is(err, ErrChangesTooLarge) {
		t.Errorf("超體積應回 ErrChangesTooLarge（拒絕而非截斷），實際 %v", err)
	}
}

func TestDecodeChangesRejectsGarbage(t *testing.T) {
	if _, err := decodeChanges("id-1", "{不是 JSON"); err == nil {
		t.Fatal("壞摘要應報錯：靜默跳過會讓那筆審計在介面上徹底消失")
	} else if !strings.Contains(err.Error(), "id-1") {
		t.Errorf("錯誤訊息應點出記錄標識：%v", err)
	}
}

func TestCursorFormatAndParse(t *testing.T) {
	id := mustID(t1)
	rec := Record{ID: id, CreatedAt: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}
	cursor := makeCursor(rec)
	at, gotID, err := parseCursor(cursor)
	if err != nil {
		t.Fatalf("游標解析失敗：%v", err)
	}
	if gotID != id.String() {
		t.Errorf("游標裡的標識 = %q，want %q", gotID, id.String())
	}
	if want := "2026-09-26T12:00:00.000Z"; timeutilFormat(at) != want {
		t.Errorf("游標裡的時刻 = %s，want %s", timeutilFormat(at), want)
	}
	for _, bad := range []string{"", "123", "abc:def", "0:" + t1, "-5:" + t1, "1758888000000:not-a-uuid",
		"1758888000000:0198c2f4-7a3e-4b21-9c8d-1e2f3a4b5c6d"} {
		if _, _, err := parseCursor(bad); !errors.Is(err, ErrInvalidCursor) {
			t.Errorf("游標 %q 應被拒絕（不退回第一頁），實際 %v", bad, err)
		}
	}
}

func TestLimitBounds(t *testing.T) {
	if DefaultLimit < 1 || DefaultLimit > MaxLimit {
		t.Errorf("DefaultLimit=%d 應落在 1..%d", DefaultLimit, MaxLimit)
	}
	if MaxLimit > 1000 {
		t.Errorf("MaxLimit=%d 過大：審計分頁是人工回看，不是匯出通道", MaxLimit)
	}
}

// timeutilFormat 只為比較游標裡的毫秒值，避免測試直接依賴 timeutil 的導入。
func timeutilFormat(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000") + "Z"
}
