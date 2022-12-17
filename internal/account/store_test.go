package account

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 合法的 Argon2id 編碼雜湊外形（內容是假資料，僅供形狀校驗；絕非任何真實憑據）。
const testHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$cmVhbGx5ZmFrZWhhc2g"

// fixedClock 為可設定的時鐘：建立時刻必須取自伺服器時鐘且不採信呼叫端（DEC-015）。
type fixedClock struct{ at time.Time }

// Now 回傳固定時刻。
func (c fixedClock) Now() time.Time { return c.at }

// retryTempDir 在 t.TempDir 的清理之上補一道「有限次數、帶間隔」的重試
// （Windows 上 SQLite 句柄釋放有落後；约定見 internal/devkit 與 audit 同名輔助）。
func retryTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() {
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			t.Errorf("暫存目錄清理失敗（殘留：%s）：%v", dir, err)
		}
	})
	return dir
}

// newTestStore 開啟本次測試專屬的暫存資料庫、套用內嵌遷移，回傳倉儲與連線。
func newTestStore(t *testing.T) (*Store, *database.DB, time.Time) {
	t.Helper()
	at := time.Date(2026, 9, 28, 3, 4, 5, 600_000_000, time.UTC)
	db, err := database.Open(context.Background(), database.Options{
		Path:        filepath.Join(retryTempDir(t), "evernight.db"),
		BusyTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: timeutil.System()}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	return NewStore(fixedClock{at: at}), db, at
}

// mustID 產生一個正規 UUIDv7 字串供直寫 SQL 使用（測試專屬；正式程式碼一律經 Store）。
func mustID(t *testing.T) string {
	t.Helper()
	id, err := idgen.New()
	if err != nil {
		t.Fatalf("產生測試標識失敗：%v", err)
	}
	return id.String()
}

// standardInput 回傳一份合法的標準帳戶輸入（可按欄位覆寫）。
func standardInput(login string) NewInput {
	return NewInput{
		LoginName:          login,
		DisplayName:        "測試帳戶",
		PasswordHash:       testHash,
		Type:               TypeStandard,
		Status:             StatusActive,
		MustChangePassword: true,
	}
}

// TestMigrationCreatesAccountsTable 驗證 0003 遷移落地：版本推進到遷移集最高版、
// accounts 表與唯一索引存在。
func TestMigrationCreatesAccountsTable(t *testing.T) {
	_, db, _ := newTestStore(t)
	ctx := context.Background()

	current, err := migrate.Current(ctx, db.SQL())
	if err != nil {
		t.Fatalf("讀取版本失敗：%v", err)
	}
	known, err := migrate.Load()
	if err != nil {
		t.Fatalf("載入遷移集失敗：%v", err)
	}
	if want := known[len(known)-1].Version; current != want {
		t.Errorf("套用後版本應為 %d，實際 %d", want, current)
	}

	var name string
	err = db.SQL().QueryRowContext(ctx,
		"SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?", "accounts_login_name_key_unique").Scan(&name)
	if err != nil {
		t.Fatalf("唯一索引 accounts_login_name_key_unique 不存在：%v", err)
	}
}

// TestCreateAndReadBack 驗證帳戶持久化與讀回：全部欄位（含正規化鍵、固定時鐘的
// 建立時刻、NULL 時間戳）往返一致。
func TestCreateAndReadBack(t *testing.T) {
	store, db, at := newTestStore(t)
	ctx := context.Background()

	in := standardInput("ＡｄｍｉｎＵｓｅｒ") // 全角寫法：經 NFKC 收攏後與半角小寫同鍵
	in.DisplayName = "長夜幻境管理員"
	created, err := store.Create(ctx, db.SQL(), in)
	if err != nil {
		t.Fatalf("Create 失敗：%v", err)
	}
	if created.ID.IsNil() {
		t.Fatal("Create 未指派標識")
	}
	if !created.CreatedAt.Equal(at) {
		t.Errorf("建立時刻應取自注入時鐘 %v，實際 %v", at, created.CreatedAt)
	}
	if created.LoginKey != "adminuser" {
		t.Errorf("全角鍵應經 NFKC+折疊收攏為 adminuser，實際 %q", created.LoginKey)
	}

	byID, err := store.ByID(ctx, db.SQL(), created.ID)
	if err != nil {
		t.Fatalf("ByID 失敗：%v", err)
	}
	if byID.PasswordHash != testHash || byID.Type != TypeStandard || byID.Status != StatusActive {
		t.Errorf("讀回實體與建立不一致：%+v", byID)
	}
	if !byID.MustChangePassword || !byID.LastLoginAt.IsZero() || !byID.DisabledAt.IsZero() {
		t.Error("must_change/last_login/disabled 的 NULL 語意讀回不正確")
	}
	if !byID.CreatedAt.Equal(at) {
		t.Errorf("時刻往返回不正確：%v vs %v", byID.CreatedAt, at)
	}

	// 按登入名查：不同大小寫、不同全角寫法都必須命中同一帳戶（比對語意與唯一約束同源）。
	for _, probe := range []string{"ADMINUSER", "ａｄｍｉｎｕｓｅｒ", "AdminUser"} {
		found, err := store.ByLoginName(ctx, db.SQL(), probe)
		if err != nil {
			t.Errorf("ByLoginName(%q) 失敗：%v", probe, err)
			continue
		}
		if found.ID != created.ID {
			t.Errorf("ByLoginName(%q) 命中了別的帳戶", probe)
		}
	}
}

// TestDuplicateLoginVariantsRejected 驗證重複登入名：不同寫法（大小寫／全角）經
// 正規化得到同鍵時，第二次建立必須收到 ErrDuplicateLogin——查插之間沒有時間窗，
// 兜底的是 UNIQUE 索引。
func TestDuplicateLoginVariantsRejected(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()

	if _, err := store.Create(ctx, db.SQL(), standardInput("NightWriter")); err != nil {
		t.Fatalf("首個帳戶建立失敗：%v", err)
	}
	for _, dup := range []string{"nightwriter", "NIGHTWRITER", "ＮｉｇｈｔＷｒｉｔｅｒ"} {
		_, err := store.Create(ctx, db.SQL(), standardInput(dup))
		if !errors.Is(err, ErrDuplicateLogin) {
			t.Errorf("重複寫法 %q：期望 ErrDuplicateLogin，實際 %v", dup, err)
		}
	}

	// 繞過域層直接拼同鍵 INSERT：資料庫必須自己擋下（唯一性不靠先查後插的最直接證明）。
	_, err := db.SQL().ExecContext(ctx, `INSERT INTO accounts (
			id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at)
		VALUES (?, 'NightWriter', 'nightwriter', 'x', ?, 'standard', 'active', 0, 1730000000000)`,
		mustID(t), testHash)
	if err == nil {
		t.Fatal("繞過域層的同鍵插入未被 UNIQUE 索引擋下")
	}
}

// TestGuestForm 驗證 Guest 形態：無憑據可建；帶憑據或改密旗標一律被域層拒絕。
func TestGuestForm(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()

	guest, err := store.Create(ctx, db.SQL(), NewInput{
		LoginName:          "guest-tmp",
		DisplayName:        "臨時訪客",
		Type:               TypeGuest,
		Status:             StatusActive,
		MustChangePassword: false,
	})
	if err != nil {
		t.Fatalf("無憑據 Guest 建立失敗：%v", err)
	}
	if guest.PasswordHash != "" {
		t.Error("Guest 不該有憑據")
	}

	in := NewInput{LoginName: "guest-bad", DisplayName: "壞形 Guest", Type: TypeGuest, Status: StatusActive}
	in.PasswordHash = testHash
	if _, err := store.Create(ctx, db.SQL(), in); err == nil {
		t.Error("帶憑據的 Guest 未被域層拒絕")
	}
	in.PasswordHash = ""
	in.MustChangePassword = true
	if _, err := store.Create(ctx, db.SQL(), in); err == nil {
		t.Error("帶改密旗標的 Guest 未被域層拒絕")
	}
}

// TestStandardRequiresCredential 驗證標準帳戶的憑據必填與形狀校驗（不填入任何默認密碼）。
func TestStandardRequiresCredential(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()

	in := standardInput("treasury-bot")
	in.PasswordHash = ""
	if _, err := store.Create(ctx, db.SQL(), in); err == nil {
		t.Error("無憑據的標準帳戶未被拒絕")
	}
	in.PasswordHash = "not-argon2-form"
	if _, err := store.Create(ctx, db.SQL(), in); err == nil {
		t.Error("非 Argon2id 形狀的憑據未被拒絕")
	}
}

// TestStatusDisabledConsistency 驗證 status 與 disabled_at 的同生同滅。
func TestStatusDisabledConsistency(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()

	// active 卻帶禁用時刻 → 域層拒絕。
	in := standardInput("confused-one")
	in.DisabledAt = time.Now()
	if _, err := store.Create(ctx, db.SQL(), in); err == nil {
		t.Error("active 帶 disabled_at 未被拒絕")
	}
	// disabled 不帶時刻 → 域層拒絕。
	in = standardInput("confused-two")
	in.Status = StatusDisabled
	if _, err := store.Create(ctx, db.SQL(), in); err == nil {
		t.Error("disabled 缺少 disabled_at 未被拒絕")
	}
	// disabled + 時刻 → 成立且讀回一致。
	at := time.Date(2026, 9, 28, 5, 0, 0, 0, time.UTC)
	in = standardInput("retired-writer")
	in.Status = StatusDisabled
	in.DisabledAt = at
	created, err := store.Create(ctx, db.SQL(), in)
	if err != nil {
		t.Fatalf("禁用帳戶建立失敗：%v", err)
	}
	found, err := store.ByLoginName(ctx, db.SQL(), "Retired-Writer")
	if err != nil {
		t.Fatalf("讀回禁用帳戶失敗：%v", err)
	}
	if found.Status != StatusDisabled || !found.DisabledAt.Equal(at) || found.ID != created.ID {
		t.Errorf("禁用狀態讀回不正確：%+v", found)
	}
}

// TestDatabaseCheckConstraints 驗證繞過域層的直寫同歩被資料庫 CHECK 擋下：
// 枚舉外值、狀態與時刻不一致、Guest 帶憑據、時間倒掛、欄位超長。
func TestDatabaseCheckConstraints(t *testing.T) {
	_, db, _ := newTestStore(t)
	ctx := context.Background()

	// 基礎合法行（各失敗用例在此之上改一處）。
	base := `INSERT INTO accounts (
		id, login_name, login_name_key, display_name, password_hash,
		account_type, status, must_change_password, created_at, last_login_at, disabled_at
	) VALUES (?, ?, ?, 'x', ?, ?, ?, ?, 1730000000000, ?, ?)`
	cases := []struct {
		name string
		args []any
	}{
		{"status 枚舉外值", []any{mustID(t), "l1", "l1", testHash, "standard", "deleted", 0, nil, nil}},
		{"account_type 枚舉外值", []any{mustID(t), "l2", "l2", testHash, "npc_operator", "active", 0, nil, nil}},
		{"disabled 缺時刻", []any{mustID(t), "l3", "l3", testHash, "standard", "disabled", 0, nil, nil}},
		{"active 帶時刻", []any{mustID(t), "l4", "l4", testHash, "standard", "active", 0, nil, int64(1730000000001)}},
		{"guest 帶憑據", []any{mustID(t), "l5", "l5", testHash, "guest", "active", 0, nil, nil}},
		{"guest 帶改密旗標", []any{mustID(t), "l6", "l6", nil, "guest", "active", 1, nil, nil}},
		{"標準帳戶缺憑據", []any{mustID(t), "l7", "l7", nil, "standard", "active", 0, nil, nil}},
		{"last_login 早於 created", []any{mustID(t), "l8", "l8", testHash, "standard", "active", 0, int64(1729999999999), nil}},
		{"must_change 非 0/1", []any{mustID(t), "l9", "l9", testHash, "standard", "active", 2, nil, nil}},
		{"login_name 超長", []any{mustID(t), longName(t), longName(t), testHash, "standard", "active", 0, nil, nil}},
		{"id 長度非 36", []any{"short-id", "l11", "l11", testHash, "standard", "active", 0, nil, nil}},
	}
	for i, tc := range cases {
		_, err := db.SQL().ExecContext(ctx, base, tc.args...)
		if err == nil {
			t.Errorf("%s：非法行竟然寫入成功", tc.name)
		}
		_ = i
	}

	// 同一 login_name_key 的第二行（id 不同）也必須被 UNIQUE 擋下。
	_, err := db.SQL().ExecContext(ctx, base, mustID(t), "dup", "dup", testHash, "standard", "active", 0, nil, nil)
	if err != nil {
		t.Fatalf("建立 dup 基準行失敗：%v", err)
	}
	if _, err := db.SQL().ExecContext(ctx, base, mustID(t), "DUP", "dup", testHash, "standard", "active", 0, nil, nil); err == nil {
		t.Error("同鍵第二行未被 UNIQUE 索引擋下")
	}
}

// longName 回傳超過域層與資料庫上界的登入名。
func longName(t *testing.T) string {
	t.Helper()
	name := make([]byte, maxLoginRunes+1)
	for i := range name {
		name[i] = 'a'
	}
	return string(name)
}

// TestStableIDImmutable 驗證 ID 穩定性：主鍵 UPDATE 被觸發器擋下，
// 讀回的 ID 與建立時一致（下游未來只認 ID）。
func TestStableIDImmutable(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()

	created, err := store.Create(ctx, db.SQL(), standardInput("ledger-cat"))
	if err != nil {
		t.Fatalf("Create 失敗：%v", err)
	}
	if _, err := db.SQL().ExecContext(ctx,
		"UPDATE accounts SET id = ? WHERE id = ?", mustID(t), created.ID.String()); err == nil {
		t.Error("修改主鍵未被觸發器擋下")
	}
	roundTrip, err := store.ByID(ctx, db.SQL(), created.ID)
	if err != nil {
		t.Fatalf("主鍵 UPDATE 失敗後應仍可讀回：%v", err)
	}
	if roundTrip.ID != created.ID {
		t.Errorf("ID 往返回不正確：%v vs %v", roundTrip.ID, created.ID)
	}
}

// TestDeleteFreesLoginNameDisabledKeepsIt 驗證兩個刪除級別的登入名語意（本輪決定）：
// 禁用仍佔用名稱；物理徹底刪除後名稱釋放。
func TestDeleteFreesLoginNameDisabledKeepsIt(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()

	// 禁用：佔用。
	in := standardInput("gone-soon")
	in.Status = StatusDisabled
	in.DisabledAt = timeutil.System().Now()
	if _, err := store.Create(ctx, db.SQL(), in); err != nil {
		t.Fatalf("建立禁用帳戶失敗：%v", err)
	}
	if _, err := store.Create(ctx, db.SQL(), standardInput("Gone-Soon")); !errors.Is(err, ErrDuplicateLogin) {
		t.Errorf("禁用帳戶的登入名不應可復用，實際 err=%v", err)
	}

	// 徹底刪除：物理 DELETE 整行後，同鍵可再建。
	var count int
	if err := db.SQL().QueryRowContext(ctx, "SELECT count(*) FROM accounts WHERE login_name_key = ?", "gone-soon").Scan(&count); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if count != 1 {
		t.Fatalf("期望 1 行，實際 %d", count)
	}
	if _, err := db.SQL().ExecContext(ctx, "DELETE FROM accounts WHERE login_name_key = ?", "gone-soon"); err != nil {
		t.Fatalf("物理刪除失敗：%v", err)
	}
	if _, err := store.Create(ctx, db.SQL(), standardInput("gone-soon")); err != nil {
		t.Errorf("徹底刪除後登入名應可復用，實際 err=%v", err)
	}
}

// TestCreateRejectsIDGenerationFailure 驗證標識產生失敗時拒絕寫入而非降級格式。
func TestCreateRejectsIDGenerationFailure(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()

	store.newID = func() (idgen.ID, error) { return idgen.Nil, errors.New("test: 注入的亂數失敗") }
	if _, err := store.Create(ctx, db.SQL(), standardInput("never-stored")); err == nil {
		t.Error("標識產生失敗時應拒絕建立")
	}
	var count int
	if err := db.SQL().QueryRowContext(ctx, "SELECT count(*) FROM accounts").Scan(&count); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if count != 0 {
		t.Errorf("失敗的建立不應留下任何行，實際 %d 行", count)
	}
}

// TestTxScopedCreate 驗證倉儲可在呼叫端交易內使用（Querier 合同）：
// 交易回滾時帳戶不落庫，提交時落庫。
func TestTxScopedCreate(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()

	rollbackErr := errors.New("test: 主動回滾")
	err := db.InTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		if _, err := store.Create(ctx, tx, standardInput("tx-rollback")); err != nil {
			return err
		}
		return rollbackErr
	})
	if !errors.Is(err, rollbackErr) {
		t.Fatalf("期望交易回滾錯誤，實際 %v", err)
	}
	if _, err := store.ByLoginName(ctx, db.SQL(), "tx-rollback"); !errors.Is(err, ErrNotFound) {
		t.Errorf("回滾交易內的帳戶不該落庫，查回 err=%v", err)
	}

	err = db.InTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := store.Create(ctx, tx, standardInput("tx-commit"))
		return err
	})
	if err != nil {
		t.Fatalf("提交交易失敗：%v", err)
	}
	if _, err := store.ByLoginName(ctx, db.SQL(), "TX-COMMIT"); err != nil {
		t.Errorf("提交交易內的帳戶應可讀回：%v", err)
	}
}

// TestRotatePasswordCAS 釘住換密三件事：CAS 只認預期舊值、同一條語句清掉旗標、
// 以及不合格輸入在觸碰資料庫之前就被擋下。
func TestRotatePasswordCAS(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	a, err := store.Create(ctx, db.SQL(), standardInput("rotate_ok"))
	if err != nil {
		t.Fatalf("建立測試帳戶失敗：%v", err)
	}
	const newHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$dGhpc2lzbm90YXJlYWxoYXNo"

	// 現值對不上：不換、不報錯成「已換」，changed=false 就是「前提已失效」。
	if changed, err := store.RotatePassword(ctx, db.SQL(), a.ID, newHash, "不是現值"); err != nil || changed {
		t.Errorf("預期舊值不符應回 changed=false 且無錯誤：%v %v", changed, err)
	}
	// 成功一次：雜湊與旗標同行落定。
	if changed, err := store.RotatePassword(ctx, db.SQL(), a.ID, newHash, testHash); err != nil || !changed {
		t.Fatalf("CAS 命中時應回 changed=true：%v %v", changed, err)
	}
	got, err := store.ByID(ctx, db.SQL(), a.ID)
	if err != nil {
		t.Fatalf("讀回失敗：%v", err)
	}
	if got.PasswordHash != newHash || got.MustChangePassword {
		t.Errorf("換密後的欄位不正確：%+v", got)
	}
	// 用同一個「預期舊值」再打一次：現值已經不是它了，第二次不該有任何效果。
	if changed, err := store.RotatePassword(ctx, db.SQL(), a.ID, testHash, testHash); err != nil || changed {
		t.Errorf("重複 CAS 應失敗：%v %v", changed, err)
	}
	// 查無此人也收斂為 changed=false（呼叫端帶來的標識來自它剛讀到的帳戶）。
	ghostID, err := idgen.New()
	if err != nil {
		t.Fatalf("產生測試標識失敗：%v", err)
	}
	if changed, err := store.RotatePassword(ctx, db.SQL(), ghostID, newHash, testHash); err != nil || changed {
		t.Errorf("幽靈帳戶應回 changed=false：%v %v", changed, err)
	}
	// 不合格輸入在 Exec 之前擋下：新雜湊形狀、空預期值、零值標識。
	for name, call := range map[string]func() (bool, error){
		"新雜湊不是 Argon2id": func() (bool, error) {
			return store.RotatePassword(ctx, db.SQL(), a.ID, "hunter2", newHash)
		},
		"預期舊值為空": func() (bool, error) {
			return store.RotatePassword(ctx, db.SQL(), a.ID, newHash, "")
		},
		"零值標識": func() (bool, error) {
			return store.RotatePassword(ctx, db.SQL(), idgen.ID{}, newHash, newHash)
		},
	} {
		if changed, err := call(); err == nil || changed {
			t.Errorf("%s：應回報錯誤且未寫入（changed=%v err=%v）", name, changed, err)
		}
	}
	// 上述拒絕路徑都不該動到現值。
	if got, err := store.ByID(ctx, db.SQL(), a.ID); err != nil || got.PasswordHash != newHash {
		t.Errorf("拒絕路徑動到了憑據：%+v err=%v", got, err)
	}
}

// TestUpdateDisplayNameCAS 顯示名的比較-and-set：只碰這一欄，其餘原位不動。
//
// 與 RotatePasswordCAS 同形但斷言對象不同：這裡要釘死的是「白名單編輯」的結構性——
// UPDATE 的 WHERE 沒命中時一個欄位都不變，命中時也只有 display_name 變，
// 憑據、狀態、旗標、類型與任何時刻欄位都原封不動（由整行直讀比對作證）。
func TestUpdateDisplayNameCAS(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	a, err := store.Create(ctx, db.SQL(), standardInput("cas_display"))
	if err != nil {
		t.Fatalf("建立測試帳戶失敗：%v", err)
	}
	rawRow := func() string {
		t.Helper()
		var row [10]string
		err := db.SQL().QueryRowContext(ctx, `SELECT
				id, login_name, login_name_key, display_name,
				COALESCE(password_hash,''), account_type, status,
				must_change_password, created_at, COALESCE(last_login_at,'')
			FROM accounts WHERE id = ?`, a.ID.String()).
			Scan(&row[0], &row[1], &row[2], &row[3], &row[4], &row[5], &row[6], &row[7], &row[8], &row[9])
		if err != nil {
			t.Fatalf("直讀帳戶行失敗：%v", err)
		}
		return strings.Join(row[:], "\x00")
	}
	before := rawRow()

	// 現值對不上：changed=false、整行逐字不動。
	if changed, err := store.UpdateDisplayName(ctx, db.SQL(), a.ID, "新名字", "沒見過的現值"); err != nil || changed {
		t.Errorf("預期現值不符應回 changed=false 且無錯誤：%v %v", changed, err)
	}
	if got := rawRow(); got != before {
		t.Error("落空的 CAS 不得留下任何欄位位移")
	}

	// 命中：只有 display_name 變，且帶進域規則的空白整理（首尾空白不落庫）。
	if changed, err := store.UpdateDisplayName(ctx, db.SQL(), a.ID, "  更名後的顯示  ", "測試帳戶"); err != nil || !changed {
		t.Fatalf("CAS 命中時應回 changed=true：%v %v", changed, err)
	}
	mid := rawRow()
	got, err := store.ByID(ctx, db.SQL(), a.ID)
	if err != nil {
		t.Fatalf("讀回失敗：%v", err)
	}
	if got.DisplayName != "更名後的顯示" {
		t.Errorf("落庫值應為去空白後的域規範形態，實際 %q", got.DisplayName)
	}
	if got.PasswordHash != testHash || got.Status != StatusActive || !got.MustChangePassword ||
		got.Type != TypeStandard || got.CreatedAt.IsZero() || got.LoginName != "cas_display" ||
		got.LoginKey != "cas_display" {
		t.Errorf("隱藏欄位必須原封不動：%+v", got)
	}

	// 查無此人與不合格輸入：各自收斂，且都不動到既有行。
	ghostID, err := idgen.New()
	if err != nil {
		t.Fatalf("產生測試標識失敗：%v", err)
	}
	if changed, err := store.UpdateDisplayName(ctx, db.SQL(), ghostID, "幽靈改名", "任何現值"); err != nil || changed {
		t.Errorf("幽靈帳戶應回 changed=false：%v %v", err, changed)
	}
	for name, call := range map[string]func() (bool, error){
		"空顯示名": func() (bool, error) { return store.UpdateDisplayName(ctx, db.SQL(), a.ID, "  ", "更名後的顯示") },
		"超長顯示名": func() (bool, error) {
			return store.UpdateDisplayName(ctx, db.SQL(), a.ID, strings.Repeat("長", maxDisplayNameRunes+1), "更名後的顯示")
		},
		"含控制字元": func() (bool, error) {
			return store.UpdateDisplayName(ctx, db.SQL(), a.ID, "名字\x00壞", "更名後的顯示")
		},
		"零值標識": func() (bool, error) {
			return store.UpdateDisplayName(ctx, db.SQL(), idgen.ID{}, "新名", "任何現值")
		},
		"nil 連線": func() (bool, error) {
			return store.UpdateDisplayName(ctx, nil, a.ID, "新名", "任何現值")
		},
	} {
		if changed, err := call(); err == nil || changed {
			t.Errorf("%s：應回報錯誤或明確失敗且未寫入（changed=%v err=%v）", name, changed, err)
		}
	}
	// 上一次成功 CAS 後的形態仍是唯一正解：本輪拒絕路徑不得再動行。
	if again := rawRow(); again != mid {
		t.Error("拒絕路徑不得再動到任何欄位")
	}
	if got, err := store.ByID(ctx, db.SQL(), a.ID); err != nil || got.DisplayName != "更名後的顯示" {
		t.Errorf("拒絕路徑動到了顯示名：%+v err=%v", got, err)
	}
}

// TestSetStatusCAS 狀態變更的比較-and-set：只碰 status 與 disabled_at 兩欄。
//
// 與 RotatePasswordCAS 同形，但斷言對象是「安全欄位的同生同滅」：
// disabled 必然帶注入時鐘的時刻、active 必然把時刻清回 NULL，憑據與旗標
// 整行其餘欄位逐字不動——「停用在 SQL 形狀上不順手清別旗標」的直接證據。
func TestSetStatusCAS(t *testing.T) {
	store, db, at := newTestStore(t)
	ctx := context.Background()
	a, err := store.Create(ctx, db.SQL(), standardInput("cas_status"))
	if err != nil {
		t.Fatalf("建立測試帳戶失敗：%v", err)
	}
	// 除 status/disabled_at 外的整行直讀拼接：任何一次狀態寫入都不該動到它。
	otherCols := func() string {
		t.Helper()
		var (
			id, loginName, loginKey, displayName, accountType string
			passwordHash                                      string
			mustChange, createdAt, lastLoginAt                int64
		)
		err := db.SQL().QueryRowContext(ctx, `SELECT
				id, login_name, login_name_key, display_name,
				COALESCE(password_hash,''), account_type,
				must_change_password, created_at, COALESCE(last_login_at,0)
			FROM accounts WHERE id = ?`, a.ID.String()).
			Scan(&id, &loginName, &loginKey, &displayName, &passwordHash,
				&accountType, &mustChange, &createdAt, &lastLoginAt)
		if err != nil {
			t.Fatalf("直讀帳戶行失敗：%v", err)
		}
		return strings.Join([]string{
			id, loginName, loginKey, displayName, passwordHash, accountType,
			strconv.FormatInt(mustChange, 10), strconv.FormatInt(createdAt, 10),
			strconv.FormatInt(lastLoginAt, 10),
		}, "\x00")
	}
	frozen := otherCols()

	// 輸入不合格在 Exec 之前擋下：表外值、同值變更、零值標識、nil 連線。
	for name, call := range map[string]func() (bool, error){
		"表外新狀態":  func() (bool, error) { return store.SetStatus(ctx, db.SQL(), a.ID, Status("ghost"), StatusActive) },
		"表外預期狀態": func() (bool, error) { return store.SetStatus(ctx, db.SQL(), a.ID, StatusDisabled, Status("ghost")) },
		"同值變更":   func() (bool, error) { return store.SetStatus(ctx, db.SQL(), a.ID, StatusActive, StatusActive) },
		"零值標識":   func() (bool, error) { return store.SetStatus(ctx, db.SQL(), idgen.ID{}, StatusDisabled, StatusActive) },
		"nil 連線": func() (bool, error) { return store.SetStatus(ctx, nil, a.ID, StatusDisabled, StatusActive) },
	} {
		if changed, err := call(); err == nil || changed {
			t.Errorf("%s：應回報錯誤且未寫入（changed=%v err=%v）", name, changed, err)
		}
	}
	if got := otherCols(); got != frozen {
		t.Error("被擋的輸入不得留下任何欄位位移")
	}

	// 預期現值不符：changed=false、行逐字不動（呼叫端手上的舊畫面不是現值）。
	if changed, err := store.SetStatus(ctx, db.SQL(), a.ID, StatusActive, StatusDisabled); err != nil || changed {
		t.Errorf("現值不符應回 changed=false 且無錯誤：%v %v", changed, err)
	}
	if got := otherCols(); got != frozen {
		t.Error("落空的 CAS 不得留下任何欄位位移")
	}

	// 命中：disabled 帶注入時鐘的時刻；其餘欄位原封不動。
	if changed, err := store.SetStatus(ctx, db.SQL(), a.ID, StatusDisabled, StatusActive); err != nil || !changed {
		t.Fatalf("CAS 命中時應回 changed=true：%v %v", changed, err)
	}
	got, err := store.ByID(ctx, db.SQL(), a.ID)
	if err != nil {
		t.Fatalf("讀回失敗：%v", err)
	}
	if got.Status != StatusDisabled || !got.DisabledAt.Equal(at) {
		t.Errorf("落庫形態應為 disabled 帶時鐘時刻，實際 %s/%v", got.Status, got.DisabledAt)
	}
	if got.PasswordHash != testHash || !got.MustChangePassword || got.Type != TypeStandard ||
		got.LoginName != "cas_status" {
		t.Errorf("狀態通路不得觸碰憑據、旗標與類型：%+v", got)
	}
	if snap := otherCols(); snap != frozen {
		t.Error("除 status/disabled_at 外的欄位必須逐字不動")
	}

	// 重複打同一個陳舊依據：第二次什麼都不發生。
	if changed, err := store.SetStatus(ctx, db.SQL(), a.ID, StatusDisabled, StatusActive); err != nil || changed {
		t.Errorf("陳舊依據應回 changed=false：%v %v", changed, err)
	}

	// 回到 active：disabled_at 清回 NULL（同生同滅由資料庫 CHECK 兜底，形態在這裡釘死）。
	if changed, err := store.SetStatus(ctx, db.SQL(), a.ID, StatusActive, StatusDisabled); err != nil || !changed {
		t.Fatalf("恢復的 CAS 命中應回 changed=true：%v %v", changed, err)
	}
	got, err = store.ByID(ctx, db.SQL(), a.ID)
	if err != nil {
		t.Fatalf("讀回失敗：%v", err)
	}
	if got.Status != StatusActive || !got.DisabledAt.IsZero() {
		t.Errorf("恢復後應是 active 且不帶停用時刻，實際 %s/%v", got.Status, got.DisabledAt)
	}

	// 查無此人收斂為 changed=false（與 RotatePasswordCAS 同一句話）。
	ghostID, err := idgen.New()
	if err != nil {
		t.Fatalf("產生測試標識失敗：%v", err)
	}
	if changed, err := store.SetStatus(ctx, db.SQL(), ghostID, StatusDisabled, StatusActive); err != nil || changed {
		t.Errorf("幽靈帳戶應回 changed=false：%v %v", changed, err)
	}
}
