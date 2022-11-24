package grant

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 測試用時刻與合法憑據外形（假資料，僅供滿足 accounts 的形状校驗；絕非任何真實口令）。
const testHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$cmVhbGx5ZmFrZWhhc2g"

// fixedClock 為可設定的時鐘：授予時刻必須取自伺服器時鐘且不採信呼叫端（DEC-015）。
type fixedClock struct{ at time.Time }

// Now 回傳固定時刻。
func (c fixedClock) Now() time.Time { return c.at }

// retryTempDir 在 t.TempDir 的清理之上補一道有限次數、帶間隔的重試
// （Windows 上 SQLite 句柄釋放有落後；約定見 internal/devkit 與同名輔助）。
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

// newTestStore 開啟本次測試專屬的暫存資料庫並套用內嵌遷移，回傳倉儲、連線與固定時鐘時刻。
func newTestStore(t *testing.T) (*Store, *database.DB, time.Time) {
	t.Helper()
	at := time.Date(2026, 10, 2, 1, 2, 3, 400_000_000, time.UTC)
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

// insertAccount 直寫一行帳戶，回傳標識。
//
// 用直寫 SQL 而不是 internal/account 的倉儲：本套件的測試不該依賴另一個倉儲的正確性，
// 而且「绕过應用層写進去的授予」正是這裡要問的路徑。
func insertAccount(t *testing.T, db *database.DB, accountType, login string) idgen.ID {
	t.Helper()
	id, err := idgen.New()
	if err != nil {
		t.Fatalf("產生測試標識失敗：%v", err)
	}
	var hash any = testHash
	mustChange := 1
	if accountType == "guest" {
		// Guest 形態由遷移 0003 的 CHECK 凍結：無憑據、無改密要求。
		hash = nil
		mustChange = 0
	}
	_, err = db.SQL().ExecContext(context.Background(), `INSERT INTO accounts (
		id, login_name, login_name_key, display_name, password_hash,
		account_type, status, must_change_password, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
		id.String(), login, strings.ToLower(login), login, hash, accountType,
		mustChange, timeutil.ToMillis(time.Now().UTC()))
	if err != nil {
		t.Fatalf("寫入測試帳戶失敗：%v", err)
	}
	return id
}

// TestGrantAndRolesRoundTrip 授予寫進去後讀得出同一個角色，且時刻取自注入時鐘。
func TestGrantAndRolesRoundTrip(t *testing.T) {
	s, db, at := newTestStore(t)
	ctx := context.Background()
	id := insertAccount(t, db, "standard", "admin-one")

	if err := s.Grant(ctx, db.SQL(), id, identity.RoleServerAdmin); err != nil {
		t.Fatalf("写下授予失敗：%v", err)
	}
	grants, err := s.Roles(ctx, db.SQL(), id)
	if err != nil {
		t.Fatalf("讀取授予失敗：%v", err)
	}
	principal, err := identity.NewAccountPrincipal(identity.AccountInput{
		Subject: identity.AccountSubject{ID: id, Type: "standard", Status: "active"},
		Origin:  identity.OriginHTTPRequest,
		Grants:  grants,
	})
	if err != nil {
		t.Fatalf("以讀回的授予構造主體失敗：%v", err)
	}
	if !principal.HasRole(identity.RoleServerAdmin) {
		t.Errorf("讀回的授予應持有 server_admin，實際角色 %v", principal.Roles())
	}

	var grantedAt int64
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT granted_at FROM account_server_roles WHERE account_id = ?", id.String()).Scan(&grantedAt); err != nil {
		t.Fatalf("讀取授予時刻失敗：%v", err)
	}
	if got := timeutil.FromMillis(grantedAt); !got.Equal(at) {
		t.Errorf("授予時刻應取自注入時鐘 %v，實際 %v", at, got)
	}
}

// TestRolesOfUngrantedAccountIsEmpty 沒有任何授予的普通帳戶：回零值載體而不是錯誤。
//
// 「他沒有角色」是普通帳戶的常态；若這裡回錯誤，每個普通帳戶的登入與請求都會被報成缺陷。
func TestRolesOfUngrantedAccountIsEmpty(t *testing.T) {
	s, db, _ := newTestStore(t)
	id := insertAccount(t, db, "standard", "plain-one")

	grants, err := s.Roles(context.Background(), db.SQL(), id)
	if err != nil {
		t.Fatalf("查無授予應回 nil 錯誤，實際 %v", err)
	}
	principal, err := identity.NewAccountPrincipal(identity.AccountInput{
		Subject: identity.AccountSubject{ID: id, Type: "standard", Status: "active"},
		Origin:  identity.OriginHTTPRequest,
		Grants:  grants,
	})
	if err != nil {
		t.Fatalf("零值授予構造主體失敗：%v", err)
	}
	if len(principal.Roles()) != 0 {
		t.Errorf("零值授予不應帶出任何角色，實際 %v", principal.Roles())
	}
}

// TestUnknownRoleCannotBeStored 表外的角色寫不進資料庫，也讀不出半套授予。
//
// 兩道閘各有對象：遷移 0006 的 CHECK 擋的是繞過應用層的直寫（外部工具、誤操作），
// identity 的封閉集合擋的是讀取側——一筆寫壞的授予記錄不該被解讀成「他沒有這個角色」，
// 那是把資料缺陷降級成一次靜默的權限消失。
func TestUnknownRoleCannotBeStored(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	id := insertAccount(t, db, "standard", "broken-one")
	if _, err := db.SQL().ExecContext(ctx,
		"INSERT INTO account_server_roles (account_id, role, granted_at) VALUES (?, 'root', ?)",
		id.String(), timeutil.ToMillis(time.Now().UTC())); err == nil {
		t.Fatal("遷移 0006 的 role CHECK 應拒表外角色（Root 不是可授予的角色）")
	} else if !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Fatalf("拒絕原因應是 role 的 CHECK，實際 %v", err)
	}

	if _, err := s.Roles(ctx, db.SQL(), id); err != nil {
		t.Errorf("查無授予的帳戶應回零值載體而不是錯誤，實際 %v", err)
	}
}

// TestGrantRejectsUnknownRole 呼叫端拿表外的角色來：在抵達資料庫之前就被拒。
func TestGrantRejectsUnknownRole(t *testing.T) {
	s, db, _ := newTestStore(t)
	id := insertAccount(t, db, "standard", "bad-role")

	for _, role := range []identity.Role{"", "root", "Server_Admin", "admin"} {
		if err := s.Grant(context.Background(), db.SQL(), id, role); !errors.Is(err, identity.ErrUnknownRole) {
			t.Errorf("角色 %q 應被拒為 ErrUnknownRole，實際 %v", role, err)
		}
	}
	var count int
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM account_server_roles WHERE account_id = ?", id.String()).Scan(&count); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if count != 0 {
		t.Errorf("被拒的授予不得留下任何行，實際 %d 行", count)
	}
}

// TestGrantBlocksGuestAccount 訪客帳戶帶角色：遷移 0006 的觸發器在 SQL 層拒掉。
func TestGrantBlocksGuestAccount(t *testing.T) {
	s, db, _ := newTestStore(t)
	id := insertAccount(t, db, "guest", "guest-one")

	err := s.Grant(context.Background(), db.SQL(), id, identity.RoleServerAdmin)
	if err == nil {
		t.Fatal("訪客帳戶持有伺服器級角色應被資料庫拒絕")
	}
	if !strings.Contains(err.Error(), "訪客帳戶") {
		t.Logf("拒絕訊息形狀：%v", err)
	}
}

// TestGrantDuplicateFails 同一帳戶同一角色的第二次授予必須失敗，而不是靜默成功。
func TestGrantDuplicateFails(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	id := insertAccount(t, db, "standard", "twice")

	if err := s.Grant(ctx, db.SQL(), id, identity.RoleServerAdmin); err != nil {
		t.Fatalf("首次授予失敗：%v", err)
	}
	if err := s.Grant(ctx, db.SQL(), id, identity.RoleServerAdmin); err == nil {
		t.Error("重複授予應失敗：靜默成功會讓呼叫端以為自己改動了授予")
	}
}

// TestGrantRollsWithTransaction 授予與同交易的其它寫入同生同滅：交易回滾時不留半行。
func TestGrantRollsWithTransaction(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	id := insertAccount(t, db, "standard", "rolled-back")

	err := db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := s.Grant(tctx, tx, id, identity.RoleServerAdmin); err != nil {
			return err
		}
		return errors.New("測試用的必然失敗")
	})
	if err == nil {
		t.Fatal("交易應以測試錯誤失敗")
	}
	var count int
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM account_server_roles WHERE account_id = ?", id.String()).Scan(&count); err != nil {
		t.Fatalf("計數失敗：%v", err)
	}
	if count != 0 {
		t.Errorf("回滾後不得留下授予行，實際 %d 行", count)
	}
}

// TestListByRoleOrdersNewestFirstAndCaps 按角色反查：最新在前、受 limit 封頂、標識可解析。
func TestListByRoleOrdersNewestFirstAndCaps(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()

	// 三個帳戶、三次授予，授予時刻刻意拉开（用直寫 SQL 覆蓋倉儲的固定時鐘）。
	ids := make([]string, 0, 3)
	for i, login := range []string{"admin-a", "admin-b", "admin-c"} {
		id := insertAccount(t, db, "standard", login)
		if _, err := db.SQL().ExecContext(ctx,
			"INSERT INTO account_server_roles (account_id, role, granted_at) VALUES (?, 'server_admin', ?)",
			id.String(), timeutil.ToMillis(time.Now().UTC())+int64(i)); err != nil {
			t.Fatalf("寫入授予失敗：%v", err)
		}
		ids = append(ids, id.String())
	}
	entries, err := s.ListByRole(ctx, db.SQL(), identity.RoleServerAdmin, 2)
	if err != nil {
		t.Fatalf("反查授予失敗：%v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("limit 未被尊重，實際 %d 筆", len(entries))
	}
	if entries[0].AccountID.String() != ids[2] {
		t.Errorf("最新一筆應排在最前，實際 %s（期望 %s）", entries[0].AccountID.String(), ids[2])
	}
	if _, err := s.ListByRole(ctx, db.SQL(), identity.RoleServerAdmin, 0); err == nil {
		t.Error("limit 非正值應被拒：它等於允許一次拉出全表")
	}
}

// TestNilQuerierRejected 任何方法拿到 nil 連線都是組裝缺陷，當場報出不降級。
func TestNilQuerierRejected(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	id := idgen.Nil

	if err := s.Grant(ctx, nil, id, identity.RoleServerAdmin); err == nil {
		t.Error("Grant 應拒 nil 連線")
	}
	if _, err := s.Roles(ctx, nil, id); err == nil {
		t.Error("Roles 應拒 nil 連線")
	}
	if _, err := s.ListByRole(ctx, nil, identity.RoleServerAdmin, 10); err == nil {
		t.Error("ListByRole 應拒 nil 連線")
	}
}
