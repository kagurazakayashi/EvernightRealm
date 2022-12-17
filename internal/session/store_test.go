package session

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 合法的 Argon2id 編碼雜湊外形（內容是假資料，僅供形状校驗；絕非任何真實憑據）。
const testHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$cmVhbGx5ZmFrZWhhc2g"

// testBase 是全部时间断言的锚点（UTC，避开夏令时换算的歧义）。
var testBase = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

// retryTempDir 在 t.TempDir 的清理之上补一道「有限次数、带间隔」的重试
// （Windows 上 SQLite 句柄释放有落后；约定见 internal/devkit 与同名辅助）。
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

// newTestEnv 建立「专属临时库 + 注入时钟 + 会话仓储」的最小现场。
func newTestEnv(t *testing.T, ttl time.Duration) (*database.DB, *timeutil.Test, *Store) {
	t.Helper()
	clock := timeutil.NewTest(testBase)
	dbPath := filepath.Join(retryTempDir(t), "evernight.db")
	db, err := database.Open(context.Background(), database.Options{
		Path:        dbPath,
		BusyTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: clock}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	store, err := NewStore(clock, ttl)
	if err != nil {
		t.Fatalf("建立會話倉儲失敗：%v", err)
	}
	return db, clock, store
}

// createAccountDirect 用真实账户仓储落一个账户，回传实体与受信主体。
func createAccountDirect(t *testing.T, db *database.DB, clock timeutil.Clock, login string) (account.Account, identity.Principal) {
	t.Helper()
	a, err := account.NewStore(clock).Create(context.Background(), db.SQL(), account.NewInput{
		LoginName:    login,
		DisplayName:  "會話測試帳戶",
		PasswordHash: testHash,
		Type:         account.TypeStandard,
		Status:       account.StatusActive,
	})
	if err != nil {
		t.Fatalf("建立測試帳戶失敗：%v", err)
	}
	p, err := identity.NewAccountPrincipal(identity.AccountInput{
		Subject: identity.SubjectOf(a),
		Origin:  identity.OriginHTTPRequest,
	})
	if err != nil {
		t.Fatalf("構造帳戶主體失敗：%v", err)
	}
	return a, p
}

// countSessions 读全表行数（失败路径「没留下任何东西」的统一断言）。
func countSessions(t *testing.T, db *database.DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sessions").Scan(&n); err != nil {
		t.Fatalf("統計會話失敗：%v", err)
	}
	return n
}

// TestCreateVerifyRevokeRoundTripAccount 是核心往返：创建出的会话带正确的
// 三标识分工与时间字段，验证推进最近活动，撤销立即生效且不可重复。
func TestCreateVerifyRevokeRoundTripAccount(t *testing.T) {
	db, clock, store := newTestEnv(t, 2*time.Hour)
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, clock, "roundtrip")

	sess, secret, err := store.Create(ctx, db.SQL(), principal)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	if sess.Subject.Kind() != SubjectAccount || sess.Subject.AccountID() != principal.AccountID() {
		t.Errorf("主體搬運不正確：%+v", sess.Subject)
	}
	if sess.ID.IsNil() || sess.DeviceID.IsNil() || sess.ID == sess.DeviceID {
		t.Errorf("會話 ID 與設備 ID 必須各自獨立：%s / %s", sess.ID, sess.DeviceID)
	}
	if !sess.CreatedAt.Equal(testBase) || !sess.ExpiresAt.Equal(testBase.Add(2*time.Hour)) {
		t.Errorf("時間欄位不正確：created=%s expires=%s", sess.CreatedAt, sess.ExpiresAt)
	}
	if !sess.LastActiveAt.Equal(testBase) || !sess.RevokedAt.IsZero() {
		t.Errorf("初始最近活動應等於建立時刻且未撤銷")
	}
	if secret == "" || len(secret) != secretTextLen {
		t.Fatalf("秘密形狀不正確")
	}
	// 三个标识互不顶替：秘密不是 ID，ID 不是秘密。
	if secret == sess.ID.String() || secret == sess.DeviceID.String() {
		t.Fatal("秘密與標識混用")
	}

	// 验证通过并把最近活动推进 5 分钟。
	clock.Advance(5 * time.Minute)
	got, err := store.Verify(ctx, db.SQL(), secret)
	if err != nil {
		t.Fatalf("驗證失敗：%v", err)
	}
	if got.ID != sess.ID || got.DeviceID != sess.DeviceID {
		t.Errorf("驗證讀回的實體不一致：%+v", got)
	}
	if !got.LastActiveAt.Equal(testBase.Add(5 * time.Minute)) {
		t.Errorf("最近活動應已推進，實際 %s", got.LastActiveAt)
	}
	var lastActive int64
	if err := db.SQL().QueryRowContext(ctx, "SELECT last_active_at FROM sessions WHERE id = ?", sess.ID.String()).Scan(&lastActive); err != nil {
		t.Fatalf("讀回最近活動失敗：%v", err)
	}
	if want := timeutil.ToMillis(testBase.Add(5 * time.Minute)); lastActive != want {
		t.Errorf("落庫最近活動 %d 應為 %d", lastActive, want)
	}

	// 撤销后验证立即被拒；重复撤销报「不存在或早已撤销」。
	clock.Advance(time.Minute)
	revoked, err := store.Revoke(ctx, db.SQL(), sess.ID)
	if err != nil {
		t.Fatalf("撤銷失敗：%v", err)
	}
	if revoked.RevokedAt.IsZero() {
		t.Error("撤銷後應帶撤銷時刻")
	}
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrRevoked) {
		t.Errorf("撤銷後驗證應回 ErrRevoked，實際 %v", err)
	}
	if _, err := store.Revoke(ctx, db.SQL(), sess.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("重複撤銷應回 ErrNotFound，實際 %v", err)
	}
	if _, err := store.Revoke(ctx, db.SQL(), identitytest.NewID(t)); !errors.Is(err, ErrNotFound) {
		t.Errorf("撤銷不存在的會話應回 ErrNotFound")
	}
	if _, err := store.Revoke(ctx, db.SQL(), idgen.Nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("零值標識應按 ErrNotFound 收斂（查無此會話）")
	}
}

// TestDatabaseNeverHoldsReusableSecret 验证「库里读不出可用会话」：
// 数据库主档与 WAL 中能找到哈希（查找键确实落库），找不到秘密明文。
func TestDatabaseNeverHoldsReusableSecret(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, clock, "noplain")

	sess, secret, err := store.Create(ctx, db.SQL(), principal)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	hash, err := hashSecret(secret)
	if err != nil {
		t.Fatalf("哈希計算失敗：%v", err)
	}

	files, err := filepath.Glob(filepath.Join(filepath.Dir(db.Path()), "evernight.db*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("收集資料庫檔案失敗：%v（%d 個檔案）", err, len(files))
	}
	var blob []byte
	for _, f := range files {
		// 锁文件是 Windows 强制锁的载体，不承载数据且可能正被系统锁定，跳过。
		if strings.HasSuffix(f, ".lock") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("讀取 %s 失敗：%v", f, err)
		}
		blob = append(blob, data...)
	}
	if !strings.Contains(string(blob), hash) {
		t.Fatal("查找鍵（哈希）未在資料庫檔案中命中，本測試的探測方法失效")
	}
	if strings.Contains(string(blob), secret) {
		t.Fatal("資料庫檔案中能找到秘密明文——落庫方式錯誤")
	}
	// 内部标识可以落库（它不是秘密），但不得与查找键相同列。
	var storedHash string
	if err := db.SQL().QueryRowContext(ctx, "SELECT token_hash FROM sessions WHERE id = ?", sess.ID.String()).Scan(&storedHash); err != nil {
		t.Fatalf("讀回查找鍵失敗：%v", err)
	}
	if storedHash == secret || storedHash != hash {
		t.Errorf("查找鍵落庫不正確")
	}
}

// TestVerifyRejectsExpired 验证到期拒绝与边界：恰好到达到期时刻即过期，
// 边界前一毫秒仍有效；到期拒绝不会推进最近活动。
func TestVerifyRejectsExpired(t *testing.T) {
	db, clock, store := newTestEnv(t, 90*time.Minute)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	sess, secret, err := store.Create(ctx, db.SQL(), root)
	if err != nil {
		t.Fatalf("建立 Root 會話失敗：%v", err)
	}
	clock.Advance(90*time.Minute - time.Millisecond)
	if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
		t.Fatalf("到期前一毫秒應有效：%v", err)
	}
	clock.Set(testBase.Add(90 * time.Minute))
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrExpired) {
		t.Fatalf("恰到到期時刻應回 ErrExpired，實際 %v", err)
	}
	// 到期行的 last_active_at 停在最后一次成功验证，不被失败的验证推进。
	var lastActive int64
	if err := db.SQL().QueryRowContext(ctx, "SELECT last_active_at FROM sessions WHERE id = ?", sess.ID.String()).Scan(&lastActive); err != nil {
		t.Fatalf("讀回最近活動失敗：%v", err)
	}
	if want := timeutil.ToMillis(testBase.Add(90*time.Minute - time.Millisecond)); lastActive != want {
		t.Errorf("到期拒絕不應推進最近活動：%d != %d", lastActive, want)
	}
	// 已过期但仍可撤销（写下行事实，供审计与清理统一处理）。
	if _, err := store.Revoke(ctx, db.SQL(), sess.ID); err != nil {
		t.Errorf("過期會話仍應可撤銷：%v", err)
	}
	// 撤销优先于到期展示。
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrRevoked) {
		t.Errorf("撤銷+過期應先報撤銷，實際 %v", err)
	}
}

// TestVerifyReadsCurrentSubjectStatus 钉住本步的核心安全语义：
// 会话行存在不代表主体有效，禁用账户的会话在下一笔验证即被拒。
func TestVerifyReadsCurrentSubjectStatus(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	a, principal := createAccountDirect(t, db, clock, "statuscheck")

	_, secret, err := store.Create(ctx, db.SQL(), principal)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
		t.Fatalf("禁用前驗證應通過：%v", err)
	}

	// 直接落库禁用（账户管理的更新通路属后续步骤，这里模拟其结果）。
	if _, err := db.SQL().ExecContext(ctx,
		"UPDATE accounts SET status = 'disabled', disabled_at = ? WHERE id = ?",
		timeutil.ToMillis(clock.Now()), a.ID.String()); err != nil {
		t.Fatalf("禁用測試帳戶失敗：%v", err)
	}
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrSubjectUnavailable) {
		t.Fatalf("禁用後驗證應回 ErrSubjectUnavailable，實際 %v", err)
	}
	// 禁用不抹掉会话行：恢复启用属后续流程，届时旧会话是否放行必须由产品决定，
	// 本步只保证「禁用的每一刻都验不过」。
	var n int
	if err := db.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE account_id = ?", a.ID.String()).Scan(&n); err != nil || n != 1 {
		t.Errorf("驗證拒絕不應刪除會話行：n=%d err=%v", n, err)
	}
	// 重新启用则同一会话恢复可用（状态是现读的，不是会话里的快照）。
	if _, err := db.SQL().ExecContext(ctx,
		"UPDATE accounts SET status = 'active', disabled_at = NULL WHERE id = ?", a.ID.String()); err != nil {
		t.Fatalf("重新啟用失敗：%v", err)
	}
	if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
		t.Errorf("重新啟用後驗證應通過：%v", err)
	}
}

// TestCreateRejectsStaleOrBogusPrincipals 验证创建侧同样现读主体状态：
// 拿着「账户还有效」的旧快照（或直接伪造指向不存在账户的主体）都建不出会话。
func TestCreateRejectsStaleOrBogusPrincipals(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	a, principal := createAccountDirect(t, db, clock, "stale")

	// 账户被禁用后，用禁用之前构造好的合法 Principal 来创建——仍必须被拒。
	if _, err := db.SQL().ExecContext(ctx,
		"UPDATE accounts SET status = 'disabled', disabled_at = ? WHERE id = ?",
		timeutil.ToMillis(clock.Now()), a.ID.String()); err != nil {
		t.Fatalf("禁用失敗：%v", err)
	}
	if _, _, err := store.Create(ctx, db.SQL(), principal); !errors.Is(err, ErrSubjectUnavailable) {
		t.Errorf("旧快照（已禁用）應回 ErrSubjectUnavailable，實際 %v", err)
	}

	// 指向不存在账户的主体（数据库里没有这一行）。
	ghost, err := identity.NewAccountPrincipal(identity.AccountInput{
		Subject: identity.AccountSubject{ID: identitytest.NewID(t), Type: account.TypeStandard, Status: account.StatusActive},
		Origin:  identity.OriginHTTPRequest,
	})
	if err != nil {
		t.Fatalf("構造幽靈主體失敗：%v", err)
	}
	if _, _, err := store.Create(ctx, db.SQL(), ghost); !errors.Is(err, ErrSubjectUnavailable) {
		t.Errorf("幽靈帳戶應回 ErrSubjectUnavailable，實際 %v", err)
	}
	if n := countSessions(t, db); n != 0 {
		t.Fatalf("失敗的建立必須零落庫，實際 %d 行", n)
	}
	// 匿名与系统主体连门都进不来（ErrInvalidSubject，先于任何读写）。
	if _, _, err := store.Create(ctx, db.SQL(), identitytest.Anonymous(t)); !errors.Is(err, ErrInvalidSubject) {
		t.Errorf("匿名應回 ErrInvalidSubject，實際 %v", err)
	}
	if _, _, err := store.Create(ctx, db.SQL(), identitytest.System(t, identity.OriginCLI)); !errors.Is(err, ErrInvalidSubject) {
		t.Errorf("系統主體應回 ErrInvalidSubject，實際 %v", err)
	}
	// 零值 Querier 拒绝。
	if _, _, err := store.Create(ctx, nil, identitytest.Root(t, identity.OriginHTTPRequest)); err == nil {
		t.Error("無資料庫時應拒絕")
	}
}

// errNamer 计数式标识替身：第 failOn 次调用失败。
type errNamer struct {
	n      int
	failOn int
}

func (e *errNamer) call() (idgen.ID, error) {
	e.n++
	if e.n == e.failOn {
		return idgen.Nil, errors.New("注入：標識產生失敗")
	}
	return idgen.New()
}

// TestCreateFailurePathsLeaveNothing 验证标识与秘密的产生失败都不留半行会话，
// 且错误不降级（不换格式、不换随机源继续发）。
func TestCreateFailurePathsLeaveNothing(t *testing.T) {
	db, clock, _ := newTestEnv(t, time.Hour)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	_, principal := createAccountDirect(t, db, clock, "failpaths")

	cases := []struct {
		name   string
		mutate func(s *Store)
	}{
		{"帳戶標識失敗", func(s *Store) { s.newID = (&errNamer{failOn: 1}).call }},
		{"設備標識失敗", func(s *Store) { s.newID = (&errNamer{failOn: 2}).call }},
	}
	for _, tc := range cases {
		store, err := NewStore(clock, time.Hour)
		if err != nil {
			t.Fatalf("建立倉儲失敗：%v", err)
		}
		tc.mutate(store)
		if _, _, err := store.Create(ctx, db.SQL(), principal); err == nil {
			t.Errorf("%s：應回錯誤", tc.name)
		} else if !strings.Contains(err.Error(), "注入") {
			t.Errorf("%s：錯誤鏈被吞掉：%v", tc.name, err)
		}
	}
	// 随机源失败。
	store, err := NewStore(clock, time.Hour)
	if err != nil {
		t.Fatalf("建立倉儲失敗：%v", err)
	}
	store.randReader = errReader{}
	if _, _, err := store.Create(ctx, db.SQL(), root); err == nil || !strings.Contains(err.Error(), "session:") {
		t.Errorf("隨機源失敗時應回帶前綴的錯誤：%v", err)
	}
	if n := countSessions(t, db); n != 0 {
		t.Fatalf("三條失敗路徑都必須零落庫，實際 %d 行", n)
	}
}

// TestVerifyUnknownAndMalformedSecretsConverge 验证「查无此秘密」与「形状不合格」
// 收敛到同一个错误，且合法的过期内存活会话也不受影响。
func TestVerifyUnknownAndMalformedSecretsConverge(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	_, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))

	_, err := store.Verify(ctx, db.SQL(), strings.Repeat("A", secretTextLen-1)+"U")
	if !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("合法形狀但查無此秘密應回 ErrInvalidSecret，實際 %v", err)
	}
	if _, err := store.Verify(ctx, db.SQL(), "short"); !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("過短輸入應回 ErrInvalidSecret，實際 %v", err)
	}
	// 拿别人会话的哈希当秘密来试：哈希不是秘密，验不过。
	hash, _ := hashSecret(secret)
	if _, err := store.Verify(ctx, db.SQL(), hash); !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("哈希當秘密用應回 ErrInvalidSecret，實際 %v", err)
	}
	// 原秘密仍然可用（以上尝试都不改变会话状态）。
	if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
		t.Errorf("嘗試不應損傷原會話：%v", err)
	}
}

// mustCreate 建立会话并做最小形状断言，回传实体与秘密。
func mustCreate(t *testing.T, store *Store, db *database.DB, p identity.Principal) (Session, string) {
	t.Helper()
	sess, secret, err := store.Create(context.Background(), db.SQL(), p)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	if sess.ID.IsNil() || secret == "" {
		t.Fatalf("建立結果不完整：%+v", sess)
	}
	return sess, secret
}

// TestGuestAccountSession 确认 guest 形态的账户同样能建立并通过验证
// （会话层不区分账户类型，角色与权限本来就不在会话里）。
func TestGuestAccountSession(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	guest, err := account.NewStore(clock).Create(ctx, db.SQL(), account.NewInput{
		LoginName:   "visitor-1",
		DisplayName: "訪客",
		Type:        account.TypeGuest,
		Status:      account.StatusActive,
	})
	if err != nil {
		t.Fatalf("建立訪客帳戶失敗：%v", err)
	}
	p, err := identity.NewAccountPrincipal(identity.AccountInput{
		Subject: identity.SubjectOf(guest),
		Origin:  identity.OriginHTTPRequest,
	})
	if err != nil {
		t.Fatalf("構造訪客主體失敗：%v", err)
	}
	_, secret := mustCreate(t, store, db, p)
	if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
		t.Fatalf("訪客會話驗證失敗：%v", err)
	}
}

// TestRevokeSubjectScopesCorrectly 验证按主体批量撤销的边界：
// Root 的一把全撤且不碰账户会话；账户的只撤自己的。
func TestRevokeSubjectScopesCorrectly(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	_, rootSecret1 := mustCreate(t, store, db, root)
	_, rootSecret2 := mustCreate(t, store, db, root)

	_, aliceP := createAccountDirect(t, db, clock, "alice")
	_, aliceSecret := mustCreate(t, store, db, aliceP)
	_, bobP := createAccountDirect(t, db, clock, "bob")
	_, bobSecret := mustCreate(t, store, db, bobP)

	n, err := store.RevokeSubject(ctx, db.SQL(), Subject{kind: SubjectRoot})
	if err != nil {
		t.Fatalf("撤銷 Root 主體失敗：%v", err)
	}
	if n != 2 {
		t.Errorf("Root 撤銷數量應為 2，實際 %d", n)
	}
	for _, s := range []string{rootSecret1, rootSecret2} {
		if _, err := store.Verify(ctx, db.SQL(), s); !errors.Is(err, ErrRevoked) {
			t.Errorf("Root 會話應已被撤銷（秘密一律打碼不入輸出），實際 %v", err)
		}
	}
	// 账户会话不受 Root 批量撤销影响。
	if _, err := store.Verify(ctx, db.SQL(), aliceSecret); err != nil {
		t.Errorf("alice 會話不應被波及：%v", err)
	}

	// 按账户撤销只动自己的；再次撤销数量为 0（都是 revoked_at IS NULL 条件的一部分）。
	subject, err := SubjectOf(aliceP)
	if err != nil {
		t.Fatalf("換會話主體失敗：%v", err)
	}
	if n, err := store.RevokeSubject(ctx, db.SQL(), subject); err != nil || n != 1 {
		t.Fatalf("alice 撤銷應為 1 筆，實際 %d（%v）", n, err)
	}
	if n, err := store.RevokeSubject(ctx, db.SQL(), subject); err != nil || n != 0 {
		t.Fatalf("重複撤銷應為 0 筆，實際 %d（%v）", n, err)
	}
	if _, err := store.Verify(ctx, db.SQL(), aliceSecret); !errors.Is(err, ErrRevoked) {
		t.Errorf("alice 會話應已被撤銷，實際 %v", err)
	}
	if _, err := store.Verify(ctx, db.SQL(), bobSecret); err != nil {
		t.Errorf("bob 會話不應被波及：%v", err)
	}
	// 零值主体（类别缺失）拒绝而不是「撤销一切」。
	if _, err := store.RevokeSubject(ctx, db.SQL(), Subject{}); !errors.Is(err, ErrInvalidSubject) {
		t.Errorf("零值主體應回 ErrInvalidSubject，實際 %v", err)
	}
}

// TestRevokeAccountTargetsOnlyItself 釘住停用用例依賴的帳戶定向撤銷入口：
// 只動目標帳戶名下的行，Root 與其他帳戶的會話一条都不碰；零值標識在 Exec 前就被拒——
// 「忘了帶條件」在這裡不可能退化成「撤光全服」。
func TestRevokeAccountTargetsOnlyItself(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	_, rootSecret := mustCreate(t, store, db, root)

	_, aliceP := createAccountDirect(t, db, clock, "alice")
	_, aliceSecret1 := mustCreate(t, store, db, aliceP)
	_, aliceSecret2 := mustCreate(t, store, db, aliceP)
	_, bobP := createAccountDirect(t, db, clock, "bob")
	_, bobSecret := mustCreate(t, store, db, bobP)

	if n, err := store.RevokeAccount(ctx, db.SQL(), aliceP.AccountID()); err != nil || n != 2 {
		t.Fatalf("alice 撤銷應為 2 筆，實際 %d（%v）", n, err)
	}
	if n, err := store.RevokeAccount(ctx, db.SQL(), aliceP.AccountID()); err != nil || n != 0 {
		t.Fatalf("重複撤銷應為 0 筆，實際 %d（%v）", n, err)
	}
	for _, s := range []string{aliceSecret1, aliceSecret2} {
		if _, err := store.Verify(ctx, db.SQL(), s); !errors.Is(err, ErrRevoked) {
			t.Errorf("alice 會話應已被撤銷，實際 %v", err)
		}
	}
	if _, err := store.Verify(ctx, db.SQL(), bobSecret); err != nil {
		t.Errorf("bob 會話不應被波及：%v", err)
	}
	if _, err := store.Verify(ctx, db.SQL(), rootSecret); err != nil {
		t.Errorf("Root 會話不應被帳戶撤銷波及：%v", err)
	}
	// 零值標識拒絕而不是「撤掉 account_id 為 NULL 的行」（Root 行正是 NULL）。
	if _, err := store.RevokeAccount(ctx, db.SQL(), idgen.ID{}); !errors.Is(err, ErrInvalidSubject) {
		t.Errorf("零值標識應回 ErrInvalidSubject，實際 %v", err)
	}
}

// TestRevokeAllRootSessionsIsMaintenanceOnly 釘住本機維護用的撤銷入口（口令遺失後// 拿不出 RootProof，因此換不到 Subject）：它只動 Root 名下未撤銷的行，
// 且與 RevokeSubject 共用同一套最終態語意（已到期但尚未清理的行照樣寫 revoked_at）。
func TestRevokeAllRootSessionsIsMaintenanceOnly(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	_, rootSecret1 := mustCreate(t, store, db, root)
	_, rootSecret2 := mustCreate(t, store, db, root)
	_, aliceP := createAccountDirect(t, db, clock, "alice")
	_, aliceSecret := mustCreate(t, store, db, aliceP)

	n, err := store.RevokeAllRootSessions(ctx, db.SQL())
	if err != nil {
		t.Fatalf("撤銷 Root 全部會話失敗：%v", err)
	}
	if n != 2 {
		t.Errorf("應撤銷 2 枚 Root 會話，實際 %d", n)
	}
	for _, s := range []string{rootSecret1, rootSecret2} {
		if _, err := store.Verify(ctx, db.SQL(), s); !errors.Is(err, ErrRevoked) {
			t.Errorf("Root 會話應已被撤銷（秘密一律打碼不入輸出），實際 %v", err)
		}
	}
	// 普通帳戶的會話一枚都不該被這個命令動到——恢復 Root 口令不是登出所有人。
	if _, err := store.Verify(ctx, db.SQL(), aliceSecret); err != nil {
		t.Errorf("alice 會話不應被波及：%v", err)
	}

	// 重複執行回 0 而不是錯誤：沒有未撤銷的行就沒有要撤銷的東西。
	if n, err := store.RevokeAllRootSessions(ctx, db.SQL()); err != nil || n != 0 {
		t.Errorf("第二次應為 0 筆且無錯誤，實際 %d（%v）", n, err)
	}

	// 已到期但尚未清理的行照樣寫下 revoked_at：審計要能說出「這次讓 N 臺裝置登出」，
	// 而那句話的依據是同一個最終態，不是「到期」與「撤銷」兩套事實各記一處。
	_, lateSecret := mustCreate(t, store, db, root)
	clock.Advance(2 * time.Hour)
	if n, err := store.RevokeAllRootSessions(ctx, db.SQL()); err != nil || n != 1 {
		t.Fatalf("到期未清理的 Root 會話應仍可撤銷 1 筆，實際 %d（%v）", n, err)
	}
	if _, err := store.Verify(ctx, db.SQL(), lateSecret); !errors.Is(err, ErrRevoked) {
		t.Errorf("到期又被撤銷的行應以撤銷為準，實際 %v", err)
	}
}

// TestCreateDoesNotWriteLoginFacts 钉住分工：会话仓储不写 accounts.last_login_at，
// 「何时登录成功」属登录用例在同一交易里写的事实。
func TestCreateDoesNotWriteLoginFacts(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	a, principal := createAccountDirect(t, db, clock, "nofacts")

	_, _, err := store.Create(ctx, db.SQL(), principal)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	var lastLogin sql.NullInt64
	if err := db.SQL().QueryRowContext(ctx, "SELECT last_login_at FROM accounts WHERE id = ?", a.ID.String()).Scan(&lastLogin); err != nil {
		t.Fatalf("讀回 last_login_at 失敗：%v", err)
	}
	if lastLogin.Valid {
		t.Error("會話建立不得更新 last_login_at（那是登入用例的事實）")
	}
}

// TestTransactionAtomicityWithAudit 用真实的登录用例组合演示事务边界（DEC-013）：
// 会话写入与审计追加在同一个 InTx 里——审计失败整体回滚不留无声的特权会话，
// 会话失败也不留下虚假的登录成功审计。
func TestTransactionAtomicityWithAudit(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	auditStore := audit.NewStore(clock)
	rootSubjectID, err := identity.RootSubjectID()
	if err != nil {
		t.Fatalf("Root 保留標識異常：%v", err)
	}
	recFor := func(id idgen.ID) audit.Record {
		return audit.Record{
			Scope:  audit.ScopeRoot,
			Actor:  audit.Actor{Kind: audit.ActorRoot, ID: rootSubjectID},
			Action: "session.create",
			Target: audit.Target{Kind: "session", ID: id.String()},
		}
	}
	countAudit := func() int {
		t.Helper()
		var n int
		if err := db.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM root_audit WHERE action = 'session.create'").Scan(&n); err != nil {
			t.Fatalf("統計審計失敗：%v", err)
		}
		return n
	}
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	// 正常路径：会话 + 审计同一交易提交。
	if err := db.InTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		sess, _, err := store.Create(ctx, tx, root)
		if err != nil {
			return err
		}
		_, err = auditStore.Append(ctx, tx, recFor(sess.ID))
		return err
	}); err != nil {
		t.Fatalf("正常登錄交易應成功：%v", err)
	}
	if n := countSessions(t, db); n != 1 {
		t.Fatalf("應有 1 行會話，實際 %d", n)
	}
	if n := countAudit(); n != 1 {
		t.Fatalf("應有 1 筆審計，實際 %d", n)
	}

	// 审计失败路径：故意让审计 INSERT 撞 CHECK（action 空串），整个交易回滚——
	// 不能出现「会话有效但没有任何记录」的特权会话。
	err = db.InTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		if _, _, err := store.Create(ctx, tx, root); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO root_audit
				(id, created_at, actor_kind, actor_id, action, target_kind, target_id, reason, request_id, changes_json)
			VALUES (?, ?, 'root', ?, '', 'session', NULL, NULL, NULL, '[]')`,
			identitytest.NewID(t).String(), timeutil.ToMillis(clock.Now()), rootSubjectID.String()); err != nil {
			return err
		}
		return nil
	})
	if err == nil {
		t.Fatal("審計寫入失敗時交易應整體失敗")
	}
	if n := countSessions(t, db); n != 1 {
		t.Errorf("審計失敗必須回滾會話寫入，實際會話 %d 行", n)
	}
	if n := countAudit(); n != 1 {
		t.Errorf("失敗交易不應留下審計行，實際 %d 筆", n)
	}

	// 会话失败路径：审计先行成功也在同一交易内被回滚——不存在「虚假的登录成功」。
	broken := &Store{clock: clock, ttl: time.Hour, newID: idgen.New, randReader: errReader{}, accounts: account.NewStore(clock)}
	err = db.InTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		if _, err := auditStore.Append(ctx, tx, recFor(identitytest.NewID(t))); err != nil {
			return err
		}
		_, _, err := broken.Create(ctx, tx, root)
		return err
	})
	if err == nil {
		t.Fatal("會話建立失敗時交易應整體失敗")
	}
	if n := countSessions(t, db); n != 1 {
		t.Errorf("會話失敗不得留下新行，實際 %d", n)
	}
	if n := countAudit(); n != 1 {
		t.Errorf("會話失敗不得留下『登入成功』審計，實際 %d 筆", n)
	}
}

// TestNewStoreGuards 验证装配层错误当场报：非正期限拒绝构造，nil 时钟退回系统钟。
func TestNewStoreGuards(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Hour} {
		if _, err := NewStore(timeutil.NewTest(testBase), ttl); err == nil {
			t.Errorf("ttl=%s 應拒絕", ttl)
		}
	}
	store, err := NewStore(nil, time.Hour)
	if err != nil {
		t.Fatalf("nil 時鐘應退回系統鐘：%v", err)
	}
	if store.clock == nil {
		t.Fatal("時鐘未設定")
	}
}
