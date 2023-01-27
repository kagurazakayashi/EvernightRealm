// store_delete_test.go 是「帳戶刪除終態」在倉儲與資料庫層的定向證據：
// MarkDeleted 落下的形態、刪除後那一行不再接受任何寫入、跨欄 CHECK 與讀取側校驗
// 把自相矛盾的形態擋在兩個地方，以及匿名化派生的長度邊界。
// 斷言對象是形態本身而不是介面上的字：形態正確了，上面每一層才無處可謊。
package account

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// mustParseID 把測試用的字面標識解析成 ID（失敗即終止測試，不讓壞夾具污染斷言）。
func mustParseID(t *testing.T, raw string) idgen.ID {
	t.Helper()
	id, err := idgen.Parse(raw)
	if err != nil {
		t.Fatalf("解析測試標識 %s 失敗：%v", raw, err)
	}
	return id
}

// TestMarkDeletedWritesTerminalShapeAndKeepsIdentity 刪除落下的是「終態＋時刻＋匿名化顯示名」，
// 而承擔歷史身份的那幾欄（登入名、正規化鍵、憑據雜湊、建立時刻）一個字都不動。
func TestMarkDeletedWritesTerminalShapeAndKeepsIdentity(t *testing.T) {
	store, db, at := newTestStore(t)
	ctx := context.Background()

	created, err := store.Create(ctx, db.SQL(), standardInput("del.shape"))
	if err != nil {
		t.Fatalf("建立測試帳戶失敗：%v", err)
	}
	changed, err := store.MarkDeleted(ctx, db.SQL(), created.ID, created.DisplayName)
	if err != nil {
		t.Fatalf("MarkDeleted 失敗：%v", err)
	}
	if !changed {
		t.Fatal("對一個還活著的帳戶刪除應寫入成功")
	}

	after, err := store.ByID(ctx, db.SQL(), created.ID)
	if err != nil {
		t.Fatalf("讀回已刪除帳戶失敗：%v", err)
	}
	if after.Status != StatusDeleted {
		t.Errorf("狀態應已是刪除終態，實際 %q", after.Status)
	}
	if !after.DeletedAt.Equal(at) {
		t.Errorf("刪除時刻必須取自注入時鐘（呼叫端無權代填），實際 %v", after.DeletedAt)
	}
	if want := AnonymizedDisplayName(at, created.DisplayName); after.DisplayName != want {
		t.Errorf("顯示名應是佔位值 %q，實際 %q", want, after.DisplayName)
	}
	// 身分的承載者必須原樣留下：審計與未來的參照全靠這幾欄指回同一個人。
	if after.LoginName != created.LoginName || after.LoginKey != created.LoginKey {
		t.Errorf("登入名與鍵必須逐字保留，實際 %q/%q", after.LoginName, after.LoginKey)
	}
	if after.PasswordHash != created.PasswordHash || after.Type != created.Type ||
		after.MustChangePassword != created.MustChangePassword || !after.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("刪除不該動憑據、類型、旗標與建立時刻，實際 %+v", after)
	}
	if !after.LastLoginAt.Equal(created.LastLoginAt) {
		t.Error("刪除不該動最近登入時刻")
	}
	// 被刪前是 active：沒有「何時停的」這回事，不偽造一個。
	if !after.DisabledAt.IsZero() {
		t.Errorf("由 active 直接刪除的帳戶不該帶著停用時刻，實際 %v", after.DisabledAt)
	}

	// 同一行不再被任何通路重複刪除：守衛是「他還沒被刪」，不是呼叫端交來的依據值。
	again, err := store.MarkDeleted(ctx, db.SQL(), created.ID, after.DisplayName)
	if err != nil {
		t.Fatalf("第二次刪除應以結論而非故障回報，實際 err=%v", err)
	}
	if again {
		t.Error("第二次刪除不得寫入任何一行（重複刪除不是又刪一次成功）")
	}
	third, err := store.ByID(ctx, db.SQL(), created.ID)
	if err != nil {
		t.Fatalf("第二次刪除後讀回失敗：%v", err)
	}
	if !third.DeletedAt.Equal(after.DeletedAt) || third.DisplayName != after.DisplayName {
		t.Errorf("被拒的重複刪除不得改寫現值，實際 %v/%q", third.DeletedAt, third.DisplayName)
	}
}

// TestMarkDeletedKeepsDisabledHistory 由停用態進入刪除態：停用時刻是既有歷史，保留；
// 刪除時刻另記一件事，不覆蓋它。
func TestMarkDeletedKeepsDisabledHistory(t *testing.T) {
	store, db, at := newTestStore(t)
	ctx := context.Background()

	in := standardInput("del.wasdisabled")
	in.Status = StatusDisabled
	in.DisabledAt = at
	created, err := store.Create(ctx, db.SQL(), in)
	if err != nil {
		t.Fatalf("建立停用帳戶失敗：%v", err)
	}
	if _, err := store.MarkDeleted(ctx, db.SQL(), created.ID, created.DisplayName); err != nil {
		t.Fatalf("刪除停用帳戶失敗：%v", err)
	}
	after, err := store.ByID(ctx, db.SQL(), created.ID)
	if err != nil {
		t.Fatalf("讀回失敗：%v", err)
	}
	if after.Status != StatusDeleted {
		t.Errorf("狀態應為刪除終態，實際 %q", after.Status)
	}
	if !after.DisabledAt.Equal(at) {
		t.Errorf("停用時刻屬既有歷史，必須保留，實際 %v", after.DisabledAt)
	}
	if after.DeletedAt.IsZero() {
		t.Error("刪除時刻必須另記一件事，不能與停用時刻混為一談")
	}
}

// TestMarkDeletedRejectsUnknownTarget 目標不存在時 changed=false 且不報錯：
// 呼叫端通常已在同一交易核實過成員資格，走到這裡只剩前提失效一種可能，
// 那既不該被報成刪除成功，也不該被謊報成資料庫故障。
func TestMarkDeletedRejectsUnknownTarget(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()

	ghost := mustParseID(t, "0192f0c4-1c9a-7000-8000-0000000000aa")
	changed, err := store.MarkDeleted(ctx, db.SQL(), ghost, "任何名字")
	if err != nil {
		t.Fatalf("查無目標不應回故障，實際 err=%v", err)
	}
	if changed {
		t.Error("查無目標不得報刪除成功")
	}
	if changed, err := store.MarkDeleted(ctx, db.SQL(), idgen.ID{}, "任何名字"); err == nil || changed {
		t.Errorf("零值標識必須當場拒絕，實際 changed=%v err=%v", changed, err)
	}
	// 超長原顯示名不是拒絕理由：派生規則自己負責把它截進欄位上限內。
	if changed, err := store.MarkDeleted(ctx, db.SQL(), idgen.ID{}, strings.Repeat("長", 200)); err == nil || changed {
		t.Errorf("零值標識搭配超長原名仍應當場拒絕，實際 changed=%v err=%v", changed, err)
	}
}

// TestDeletedRowRefusesEveryLaterWrite 已刪除行是終態：繞過域層直寫資料庫也改不動它。
//
// 這一組斷言的是「恢復登入通路對刪除帳戶無能為力」這句話的資料庫側：
// 界面少放一顆按鈕不是安全邊界，寫不進去才是。
func TestDeletedRowRefusesEveryLaterWrite(t *testing.T) {
	store, db, at := newTestStore(t)
	ctx := context.Background()
	created, err := store.Create(ctx, db.SQL(), standardInput("del.terminal"))
	if err != nil {
		t.Fatalf("建立失敗：%v", err)
	}
	if _, err := store.MarkDeleted(ctx, db.SQL(), created.ID, created.DisplayName); err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}

	for name, statement := range map[string]string{
		"改回可用":        `UPDATE accounts SET status = 'active', deleted_at = NULL`,
		"改回停用":        `UPDATE accounts SET status = 'disabled'`,
		"清掉刪除時刻":      `UPDATE accounts SET deleted_at = NULL`,
		"換回原本顯示名":     `UPDATE accounts SET display_name = '我又回來了'`,
		"順手改憑據":       `UPDATE accounts SET password_hash = '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$fake'`,
		"順手免首次改密義務":   `UPDATE accounts SET must_change_password = 0`,
		"順手記一筆新登入時刻":  `UPDATE accounts SET last_login_at = 1730000000000`,
		"順手把停用時刻偽造出來": `UPDATE accounts SET disabled_at = 1730000000000`,
	} {
		if _, err := db.SQL().ExecContext(ctx, statement+" WHERE id = ?", created.ID.String()); err == nil {
			t.Errorf("%s：已刪除行竟然被寫動了", name)
		}
	}
	after, err := store.ByID(ctx, db.SQL(), created.ID)
	if err != nil {
		t.Fatalf("失敗的直寫之後帳戶應仍可讀回：%v", err)
	}
	if after.Status != StatusDeleted || !after.DeletedAt.Equal(at) {
		t.Errorf("被拒的直寫之後現值必須逐字不動，實際 %q/%v", after.Status, after.DeletedAt)
	}
}

// TestDatabaseChecksPinDeletedShape 跨欄 CHECK 與建立閘：
// 「是刪除態卻沒有刪除時刻」「還沒被刪卻帶著刪除時刻」在資料庫層都放不進去。
func TestDatabaseChecksPinDeletedShape(t *testing.T) {
	_, db, _ := newTestStore(t)
	ctx := context.Background()

	for name, statement := range map[string]string{
		"deleted 卻沒有刪除時刻": `INSERT INTO accounts (id, login_name, login_name_key, display_name,
			password_hash, account_type, status, must_change_password, created_at)
			VALUES (?, 'no-stamp', 'no-stamp', 'x', ?, 'standard', 'deleted', 0, 1730000000000)`,
		"active 卻帶著刪除時刻": `INSERT INTO accounts (id, login_name, login_name_key, display_name,
			password_hash, account_type, status, must_change_password, created_at, deleted_at)
			VALUES (?, 'with-stamp', 'with-stamp', 'x', ?, 'standard', 'active', 0, 1730000000000, 1730000000001)`,
		"deleted 帶著早於建立的刪除時刻": `INSERT INTO accounts (id, login_name, login_name_key, display_name,
			password_hash, account_type, status, must_change_password, created_at, deleted_at)
			VALUES (?, 'old-stamp', 'old-stamp', 'x', ?, 'standard', 'deleted', 0, 1730000000000, 1700000000000)`,
	} {
		if _, err := db.SQL().ExecContext(ctx, statement, mustID(t), testHash); err == nil {
			t.Errorf("%s：非法形態竟然寫入成功", name)
		}
	}
}

// TestNewRejectsDeletedAtBirth 建立通路（域層）那一側：刪除態不能當初始狀態。
//
// 這與資料庫的 accounts_insert_not_deleted 觸發器是兩道各自成立的閘：
// 域層給出可操作的錯誤，資料庫擋掉繞過域層的直寫。
func TestNewRejectsDeletedAtBirth(t *testing.T) {
	in := standardInput("del.at-birth")
	in.Status = StatusDeleted
	if _, err := New(in); err == nil {
		t.Error("建立帳戶時不應允許直接進入刪除終態")
	}

	// 停用/恢復通路不接受刪除態作為任何一側：那條通路的語意是「登入能力開或關」。
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	target := mustID(t)
	for _, pair := range [][2]Status{
		{StatusActive, StatusDeleted},
		{StatusDeleted, StatusActive},
		{StatusDisabled, StatusDeleted},
		{StatusDeleted, StatusDisabled},
	} {
		if _, err := store.SetStatus(ctx, db.SQL(), mustParseID(t, target), pair[0], pair[1]); err == nil {
			t.Errorf("SetStatus %q→%q 應被當場拒絕", pair[1], pair[0])
		}
	}
	// 同值仍然拒絕（既有規則不因新增狀態而放鬆）。
	if _, err := store.SetStatus(ctx, db.SQL(), mustParseID(t, target), StatusActive, StatusActive); err == nil {
		t.Error("新舊同值的狀態變更沒有可寫的事實，應被拒絕")
	}
}

// TestReadRowRejectsContradictoryShape 讀取側不後門：資料庫被繞過校驗寫入矛盾形態時，
// 實體成形失敗並報錯，而不是靜默產生一個「既不是刪除也沒有時刻」的半成品。
//
// 資料庫 CHECK 已經把絕大多數矛盾形態擋在外面（見上一個測試），這一組打的是
// 「執行檔比資料庫新、而庫裏留有更早規則寫進去的行」這種真實的降級場景：
// 靜默放行會讓那筆帳戶在每一個介面上以一個無法解釋的樣子出現。
func TestReadRowRejectsContradictoryShape(t *testing.T) {
	cases := []struct {
		name      string
		status    string
		disabled  sql.NullInt64
		deletedAt sql.NullInt64
	}{
		{"刪除態卻沒有刪除時刻", "deleted", sql.NullInt64{}, sql.NullInt64{}},
		{"可用態卻帶著刪除時刻", "active", sql.NullInt64{}, sql.NullInt64{Int64: 1730000000001, Valid: true}},
		{"停用態卻沒有停用時刻", "disabled", sql.NullInt64{}, sql.NullInt64{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := accountFromRow(mustID(t), "l", "l", "n",
				sql.NullString{String: testHash, Valid: true}, "standard", tc.status, 0, 1730000000000,
				sql.NullInt64{}, tc.disabled, tc.deletedAt)
			if err == nil {
				t.Error("矛盾形態應在成形階段報錯，實際靜默放行")
			}
		})
	}

	// 同一組欄位換成一致形態就必須讀得出來——否則上面那條拒絕只是「什麼都拒」。
	ok, err := accountFromRow(mustID(t), "l", "l", "n",
		sql.NullString{String: testHash, Valid: true}, "standard", "deleted", 0, 1730000000000,
		sql.NullInt64{}, sql.NullInt64{}, sql.NullInt64{Int64: 1730000000001, Valid: true})
	if err != nil {
		t.Fatalf("一致的刪除形態應讀得出來：%v", err)
	}
	if ok.Status != StatusDeleted || ok.DeletedAt.IsZero() {
		t.Errorf("讀回的刪除形態不正確：%+v", ok)
	}
}

// TestAnonymizedDisplayNameShape 佔位顯示名的形狀邊界：前綴固定、日期取自 UTC、
// 超長原名截斷到欄位上限內，且不產生非法值。
func TestAnonymizedDisplayNameShape(t *testing.T) {
	stamp := time.Date(2026, 10, 2, 23, 59, 59, 0, time.UTC)
	if got, want := AnonymizedDisplayName(stamp, "張三"), "DEL_20261002_張三"; got != want {
		t.Errorf("佔位值應是 %q，實際 %q", want, got)
	}
	// UTC 日期而不是本地時區：同一個實例不因主機時區不同而落下兩個不同的事實。
	shanghai := time.Date(2026, 10, 3, 7, 0, 0, 0, time.FixedZone("UTC+8", 8*3600))
	if got, want := AnonymizedDisplayName(shanghai, "李四"), "DEL_20261002_李四"; got != want {
		t.Errorf("日期必須按 UTC 取，實際 %q（希望 %q）", got, want)
	}

	long := strings.Repeat("長", maxDisplayNameRunes)
	got := AnonymizedDisplayName(stamp, long)
	if runes := []rune(got); len(runes) > maxDisplayNameRunes {
		t.Errorf("佔位值必須落在欄位上限 %d 內，實際 %d", maxDisplayNameRunes, len(runes))
	}
	if !strings.HasPrefix(got, "DEL_20261002_") {
		t.Errorf("截斷只該動原名那一段，前綴必須完整，實際 %q", got)
	}
	if err := validateDisplayName(got); err != nil {
		t.Errorf("佔位值必須通過與建立時同一個顯示名校驗：%v", err)
	}
	// 空原值（域層本來不接受）也不該產出非法空值：前綴自己就是非空佔位。
	if strings.TrimSpace(AnonymizedDisplayName(stamp, "")) == "" {
		t.Error("佔位值不可為空")
	}
}

// TestDeletedAccountStillPinsItsReferencesByStructure 結構邊界：行保留之後，
// 指向它的既有參照不會消失，也不會因為「人沒了」而被級聯帶走。
//
// 這裡刻意只驗「結構」而不偽造任何業務：帳本與聊天都還沒開發，
// 能取證的是同一件事——accounts(id) 這條被參照的關係在刪除之後依然存在，
// 而想要物理移除這一行，會先被既存參照擋住。那正是「保留歷史身份」
// 在資料庫層的含義，也是後續帳本／聊天落地時不需要回頭改這條約定的原因。
func TestDeletedAccountStillPinsItsReferencesByStructure(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	created, err := store.Create(ctx, db.SQL(), standardInput("del.references"))
	if err != nil {
		t.Fatalf("建立失敗：%v", err)
	}
	// 造一份既有參照（會話行）：直接寫 SQL 是因為本套件不該依賴 internal/session，
	// 而這條斷言要問的只是資料庫的關係，不是會話語意。
	if _, err := db.SQL().ExecContext(ctx, `INSERT INTO sessions
			(id, device_id, token_hash, subject_kind, account_id, created_at, last_active_at, expires_at)
			VALUES (?, ?, ?, 'account', ?, ?, ?, ?)`,
		mustID(t), mustID(t), strings.Repeat("a", 64), created.ID.String(),
		timeutil.ToMillis(created.CreatedAt), timeutil.ToMillis(created.CreatedAt),
		timeutil.ToMillis(created.CreatedAt.Add(time.Hour))); err != nil {
		t.Fatalf("寫入測試參照行失敗：%v", err)
	}

	if _, err := store.MarkDeleted(ctx, db.SQL(), created.ID, created.DisplayName); err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}
	var refs int
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sessions WHERE account_id = ?", created.ID.String()).Scan(&refs); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if refs != 1 {
		t.Errorf("刪除不得級聯帶走既有參照，實際剩 %d 行", refs)
	}
	// 新的參照依然寫得進去（父行還在）：未來的帳本分錄、聊天訊息都靠這句話指回每一個人。
	if _, err := db.SQL().ExecContext(ctx, `INSERT INTO sessions
			(id, device_id, token_hash, subject_kind, account_id, created_at, last_active_at, expires_at)
			VALUES (?, ?, ?, 'account', ?, ?, ?, ?)`,
		mustID(t), mustID(t), strings.Repeat("b", 64), created.ID.String(),
		timeutil.ToMillis(created.CreatedAt), timeutil.ToMillis(created.CreatedAt),
		timeutil.ToMillis(created.CreatedAt.Add(time.Hour))); err != nil {
		t.Errorf("刪除後的帳戶仍應是可被參照的穩定身份：%v", err)
	}
	// 物理移除這一行會被既存參照擋住：想清庫就必須先顯式處理每一處引用，不許悄悄發生。
	if _, err := db.SQL().ExecContext(ctx,
		"DELETE FROM accounts WHERE id = ?", created.ID.String()); err == nil {
		t.Error("帶著既有參照的帳戶行不應能被物理刪除（那等於讓歷史指向虛空）")
	}
}

// TestDeletedAccountStillHoldsItsLoginName 刪除不釋放登入名：同鍵再建必須撞唯一索引。
func TestDeletedAccountStillHoldsItsLoginName(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	created, err := store.Create(ctx, db.SQL(), standardInput("del.reuse"))
	if err != nil {
		t.Fatalf("建立失敗：%v", err)
	}
	if _, err := store.MarkDeleted(ctx, db.SQL(), created.ID, created.DisplayName); err != nil {
		t.Fatalf("刪除失敗：%v", err)
	}
	// 大小寫與全形差異仍算同一個人（鍵規則不因刪除而變）。
	if _, err := store.Create(ctx, db.SQL(), standardInput("DEL.Reuse")); !errors.Is(err, ErrDuplicateLogin) {
		t.Errorf("已刪除帳戶的登入名不應可被復用，實際 err=%v", err)
	}
}
