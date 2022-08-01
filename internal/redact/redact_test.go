package redact

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestKeyActionsAreNormalized 固定清單一前提：表裡的鍵名必須已是正規化形狀。
//
// 比對時正規化的是「輸入的鍵名」，因此表裡只要出現底線、連字號或大寫，
// 那一條規則就永遠不會命中——寫錯一個字元的代價是一道悄悄失效的屏蔽，而不是編譯失敗。
func TestKeyActionsAreNormalized(t *testing.T) {
	for key, action := range keyActions {
		if action == Keep {
			t.Errorf("keyActions[%q] 不應出現 Keep", key)
		}
		if got := normalizeKey(key); got != key {
			t.Errorf("鍵名 %q 未正規化（正規化後為 %q），該規則永遠不會命中", key, got)
		}
	}
}

// TestActionForKeyNormalization 驗證不同寫法的同一欄位名落到同一個判定。
func TestActionForKeyNormalization(t *testing.T) {
	writings := []string{"session_token", "Session-Token", "session.token", "sessionToken", `"sessiontoken"`, "SESSION_TOKEN"}
	for _, writing := range writings {
		if got := ActionFor(writing); got != KeepReference {
			t.Errorf("ActionFor(%q) = %v，want KeepReference", writing, got)
		}
	}
	if got := ActionFor("password"); got != NeverRecord {
		t.Errorf("password 應永不記錄，實際 %v", got)
	}
	// request_id 是關聯識別碼而非憑據：被遮住的話日誌就再也對應不回回應標頭。
	if got := ActionFor("request_id"); got != Keep {
		t.Errorf("request_id 不應被遮罩，實際 %v", got)
	}
	if got := ActionFor(""); got != Keep {
		t.Errorf("空鍵名不應命中任何規則，實際 %v", got)
	}
}

// TestRedactValueNeverRecorded 逐一驗證「永不記錄」類欄位：值必須完全消失。
func TestRedactValueNeverRecorded(t *testing.T) {
	secrets := map[string]string{
		"password":           "hunter2Secret!",
		"pin":                "4821",
		"recovery_code":      "crd6-9fk2-m4xx-q7pp",
		"passphrase":         "correct horse battery staple",
		"private_key":        "MIIEvQIBADANBgqhkiGMw0BAQEF",
		"tls_key":            "-----BEGIN PRIVATE KEY-----",
		"secret":             "srv-shared-secret",
		"client_secret":      "oauth-client-secret",
		"signing_key":        "aXdf-signing-key",
		"root_password_hash": "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$hashvalue",
		"message":            "今晚八點在舊倉庫見面，口令是 4821",
		"content":            "私聊正文：把密語告訴你了",
		"body":               `{"pin":"4821","text":"正文"}`,
		"text":               "聊天正文",
		"private_message":    "只有兩個人看得到的內容",
	}
	for key, value := range secrets {
		got := Value(key, value)
		if got != Redacted {
			t.Errorf("Value(%q,…) = %q，want %q", key, got, Redacted)
		}
		if strings.Contains(got, value) {
			t.Errorf("欄位 %q 的原值仍出現在輸出裡：%q", key, got)
		}
	}
}

// TestRedactValueReference 驗證「只留標識」類欄位：原值消失、同一值穩定、不同值不同標識。
func TestRedactValueReference(t *testing.T) {
	keys := []string{
		"token", "session_token", "cookie", "authorization", "csrf_token",
		"api_key", "idempotency_key", "qr_code", "sid", "bearer",
	}
	for _, key := range keys {
		value := "value-for-" + key + "-5geg8Q3wF7pL"
		got := Value(key, value)
		if !strings.HasPrefix(got, RefPrefix) {
			t.Errorf("Value(%q,…) = %q，應以 %s 開頭", key, got, RefPrefix)
		}
		if strings.Contains(got, value) {
			t.Errorf("欄位 %q 的原值仍出現在輸出裡：%q", key, got)
		}
		if again := Value(key, value); again != got {
			t.Errorf("同一值兩次標識不同：%q 對 %q", got, again)
		}
		if other := Value(key, value+"X"); other == got {
			t.Errorf("不同值得到同一標識：%q", got)
		}
	}
}

// TestRedactTextShapes 驗證沒有鍵名可依據時的值形狀規則（客戶端可控文字全走這條）。
func TestRedactTextShapes(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"PEM 區塊", "載入金鑰失敗：-----BEGIN PRIVATE KEY-----\nMIIEvAIBADAN\n-----END PRIVATE KEY----- 結束"},
		{"Bearer 值", "標頭 Authorization: Bearer abcdef.1234567890 遭到拒絕"},
		{"JWT", "解析 token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4i.fGhWkN0nq3rS7tVwXyZabcdefg123 失敗"},
		{"長十六進位", "雜湊比對不符 5f4dcc3b5aa765d61d83d2b6cff44e13a1b2c3d4"},
		{"帶填充 Base64", "簽名 MTIzNDU2Nzg5MDEyMzQ1Njc4OTBhYmM="},
		{"長英數含數字", "金鑰 AKIAIOSFODNN7EXAMPLE1234567890ABCDEF 外洩"},
		{"URI 內嵌憑據", "開啟 postgres://admin:sup3rsecretpw@10.0.0.5:5432/db 失敗"},
	}
	for _, tc := range cases {
		got := Text(tc.input)
		if got == tc.input {
			t.Errorf("%s：未被遮罩：%q", tc.name, got)
		}
		for _, leak := range []string{"MIIEvAIBADAN", "abcdef.1234567890", "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4i",
			"5f4dcc3b5aa765d61d83d2b6cff44e13a1b2c3d4", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTBhYmM=",
			"AKIAIOSFODNN7EXAMPLE1234567890ABCDEF", "sup3rsecretpw"} {
			if strings.Contains(got, leak) {
				t.Errorf("%s：原值片段 %q 仍出現在輸出：%q", tc.name, leak, got)
			}
		}
	}
}

// TestRedactTextPairsWithoutKey 驗證自由文字裡的鍵值對同樣被遮罩，
// 含前端踩過的坑：前一個鍵的值剛好是下一個鍵名。
func TestRedactTextPairsWithoutKey(t *testing.T) {
	cases := []struct {
		name  string
		input string
		leak  string
	}{
		{"等號寫法", "更新失敗 password=hunter2 於第 3 步", "hunter2"},
		{"冒號寫法", "更新失敗：password: hunter2", "hunter2"},
		{"JSON 寫法", `請求體無效 {"pin":"4821","note":"ok"}`, "4821"},
		{"值即下一鍵名", "取得失敗 StateError: password=abcdef 未通過校驗", "abcdef"},
		{"大標頭寫法", "Request header Cookie: sid=abc123def456 rejected", "abc123def456"},
	}
	for _, tc := range cases {
		got := Text(tc.input)
		if strings.Contains(got, tc.leak) {
			t.Errorf("%s：值 %q 未被遮罩：%q", tc.name, tc.leak, got)
		}
	}
	// 鍵名要留下來：擋住值之後還得知道擋住的是哪個欄位，否則排錯只能靠猜。
	if got := Text("password=hunter2"); !strings.Contains(got, "password") {
		t.Errorf("鍵名不應一起消失：%q", got)
	}
}

// TestRedactTextKeepsDiagnostics 驗證排錯必要資訊不被誤傷。
//
// 這半邊比遮罩更重要：規則打太寬會把路徑、函式名、驅動錯誤訊息一起抹掉，
// 日誌就從排錯工具變成只說明「出錯了」的那張畫面。
func TestRedactTextKeepsDiagnostics(t *testing.T) {
	kept := []string{
		"attempt to write a readonly database (8)",
		"listen tcp 127.0.0.1:5206: bind: 只能每次使用一個位址",
		"goroutine 22 [running]:",
		"D:\\share\\evernightrealm\\internal\\database\\database.go:198",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"內容型別必須為 application/json，實際為 text/plain",
		"請求體超過上限 1048576 位元組",
		"request_id=0198c2f4-7a3e-7b21-9c8d-1e2f3a4b5c6d",
		"time=2026-09-26T12:34:56.789Z",
		"journal_mode=wal foreign_keys=1 busy_timeout=5000",
		"Content-Type: application/json; charset=utf-8",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"版本 0 → 1（0001_server_settings）",
	}
	for _, input := range kept {
		if got := Text(input); got != input {
			t.Errorf("不應被改動：\n  輸入 %q\n  輸出 %q", input, got)
		}
	}
}

// TestTruncateRunesNotBytes 驗證截斷以字元計且不切出半個 UTF-8 序列。
func TestTruncateRunesNotBytes(t *testing.T) {
	long := strings.Repeat("日", MaxValueRunes+50)
	got := Text(long)
	if utf8.RuneCountInString(got) != MaxValueRunes+1 {
		t.Errorf("截斷後的字元數 = %d，want %d", utf8.RuneCountInString(got), MaxValueRunes+1)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("截斷應以刪節標記收尾：%q", got[len(got)-8:])
	}
	if !utf8.ValidString(got) {
		t.Error("截斷後出現非法 UTF-8 序列")
	}
	short := strings.Repeat("日", MaxValueRunes)
	if got := Text(short); got != short {
		t.Errorf("恰好等於上限的長度不應被截斷，實際長度 %d", utf8.RuneCountInString(got))
	}
	// 刻意不用連續的 a-f 做這半段：600 個 a 是合法的長十六進位形狀，
	// 會先被 longHex 當成金鑰打碼（前端 redaction.dart 同一條規則、同一結果），
	// 拿它測截斷只會測到遮罩。
}

// TestMaskBeforeTruncate 驗證長值是先遮罩再截斷。
//
// 順序反過來的話，一個把憑證放在第 700 字元的長字串會連被看見的權利都沒有，
// 而前 600 字元裡的憑證卻原樣留下。
func TestMaskBeforeTruncate(t *testing.T) {
	value := strings.Repeat("x", 590) + " password=hunter2" + strings.Repeat("y", 500)
	got := Text(value)
	if strings.Contains(got, "hunter2") {
		t.Error("值在截斷點之前的憑證未被遮罩")
	}
	if !strings.Contains(got, "password") {
		t.Error("鍵名不應一起消失")
	}
}

// TestSummarizeStack 驗證堆疊摘要保留前段、標明省略行數，並仍走同一條遮罩。
func TestSummarizeStack(t *testing.T) {
	stack := "goroutine 1 [running]:\n" +
		"main.boom(0x1)\n\tD:/share/evernightrealm/main.go:12 +0x20\n" +
		"runtime.main()\n\t/usr/local/go/src/runtime/proc.go:250 +0xc0\n" +
		"created token=supersecretvalue1 於此處\n"
	got := SummarizeStack(stack, 3)
	if !strings.Contains(got, "goroutine 1 [running]:") {
		t.Errorf("第一行堆疊影格應保留：%q", got)
	}
	if strings.Contains(got, "supersecretvalue1") {
		t.Errorf("堆疊裡的憑證未被遮罩：%q", got)
	}
	if !strings.Contains(got, "另有") {
		t.Errorf("應標明省略的行數：%q", got)
	}
	if strings.Contains(got, "\n") {
		t.Errorf("堆疊摘要不得含換行（會偽造日誌行）：%q", got)
	}
	if full := SummarizeStack(stack, 50); strings.Contains(full, "另有") {
		t.Errorf("行數足夠時不應出現省略說明：%q", full)
	}
}

// TestStructuralPathKeysKeepPaths 驗證檔案系統路徑類鍵名不被「長隨機串」規則誤傷。
//
// 這條規則是為了抓住沒有鍵名的金鑰，但 Go 的暫時目錄名（測試名＋亂數）與
// 帶日期的備份目錄名剛好長得一樣；把 data_dir 打成 [masked] 之後，
// 「資料庫開啟失敗」這條記錄就再也說不出是哪個目錄壞了。
func TestStructuralPathKeysKeepPaths(t *testing.T) {
	dir := `C:\Users\yashi\AppData\Local\Temp\2\TestRunWritesStructuredRunLog284736102\001`
	if got := Value("data_dir", dir); got != dir {
		t.Errorf("data_dir 被誤傷：%q", got)
	}
	if got := Value("database", `D:\evernight-data\backup-20260926T123456Z\evernight.db`); strings.Contains(got, Masked) {
		t.Errorf("database 路徑被誤傷：%q", got)
	}

	// 免除的只有長隨機串三條；路徑裡出現真正不該存在的東西仍然擋。
	if got := Value("data_dir", `D:\downloads\Bearer abcdef1234567890`); strings.Contains(got, "abcdef1234567890") {
		t.Errorf("路徑值裡的認證方案未被遮罩：%q", got)
	}

	// URL 路徑不在免除清單內：QR 令牌正是會出現在路徑上的憑證。
	const qr = "9f8e7d6c5b4a3210fedcba76543210"
	if got := Value("path", "/qr/"+qr); strings.Contains(got, qr) {
		t.Errorf("URL 路徑裡的令牌形狀未被遮罩：%q", got)
	}

	// 訊息與自由文字一律走完整規則（沒有鍵名可依據）。
	if got := Text(dir + " 建立失敗"); !strings.Contains(got, Masked) {
		t.Errorf("自由文字未套用長隨機串規則：%q", got)
	}
}

// TestReferenceOfFixedWidth 固定短辨識碼恆為 7 位十六進位。
//
// 這條是回測一個真實的崩潰路徑：雜湊出來可能只剩兩三位，
// 「直接切前 7 位」在短值上會 slice out of range——
// 也就是但凡有一筆記錄帶著短令牌進日誌，服務就當場掛掉。
func TestReferenceOfFixedWidth(t *testing.T) {
	for _, value := range []string{"", "a", "42", "4821", "0", "zz", "token", "eyJ", "e3b0c442"} {
		got := referenceOf(value)
		if len(got) != 7 {
			t.Errorf("referenceOf(%q) = %q，長度應恆為 7", value, got)
		}
		if _, err := strconv.ParseUint(got, 16, 32); err != nil {
			t.Errorf("referenceOf(%q) = %q，不是十六進位", value, got)
		}
	}
	// 走完整管線也要活著（這條路徑是記錄寫入時真的會走到的）。
	if got := Value("session_token", "a"); !strings.HasPrefix(got, RefPrefix) || len(got) != len(RefPrefix)+7 {
		t.Errorf("短令牌的記錄形狀不符：%q", got)
	}
}
