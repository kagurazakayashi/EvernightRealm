package session

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// newPolicyEnv 建立「專屬臨時庫 + 注入時鐘 + 帶策略的會話倉儲」。
//
// 與 store_test.go 的 newTestEnv 同一形態，只差多帶一個 Policy：閒置判定、
// 活動寫入節流與清理寬限期都要在有策略的倉儲上才成立，用預設倉儲測它們等於沒測。
func newPolicyEnv(t *testing.T, ttl time.Duration, policy Policy) (*database.DB, *timeutil.Test, *Store) {
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
	store, err := NewStoreWithPolicy(clock, ttl, policy)
	if err != nil {
		t.Fatalf("建立帶策略的會話倉儲失敗：%v", err)
	}
	return db, clock, store
}

// readLastActive 直接讀庫裡的最近活動時刻（毫秒）：節流判據必須是資料庫本身。
//
// 只看方法回傳的實體會漏掉節流的全部意義——「回傳值推進而庫裡不推進」正是預期行為。
func readLastActive(t *testing.T, db *database.DB, id idgen.ID) int64 {
	t.Helper()
	var last int64
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT last_active_at FROM sessions WHERE id = ?", id.String()).Scan(&last); err != nil {
		t.Fatalf("讀回最近活動失敗：%v", err)
	}
	return last
}

// countAudit 讀一張審計表的行數（清理不得動它們的斷言）。
func countAudit(t *testing.T, db *database.DB, table string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("統計 %s 失敗：%v", table, err)
	}
	return n
}

// seedAuditRows 用 audit 倉儲在兩張表各落一筆「清理可能順手刪掉」的記錄。
//
// 走倉儲而不是手寫 INSERT：欄位形狀與 CHECK 由 audit 套件和遷移 0002 定義，
// 測試自己拼欄位只會因遷移演進而莫名失敗，而這裡要的只是「表裡確實有東西」。
func seedAuditRows(t *testing.T, db *database.DB, clock timeutil.Clock) {
	t.Helper()
	ctx := context.Background()
	audits := audit.NewStore(clock)

	subjectID, err := identity.RootSubjectID()
	if err != nil {
		t.Fatalf("取得 Root 審計主體標識失敗：%v", err)
	}
	if _, err := audits.Append(ctx, db.SQL(), audit.Record{
		Scope:  audit.ScopeRoot,
		Actor:  audit.Actor{Kind: audit.ActorRoot, ID: subjectID},
		Action: "fake.login",
		Target: audit.Target{Kind: "session"},
	}); err != nil {
		t.Fatalf("寫入 root_audit 測試筆失敗：%v", err)
	}

	activityID, err := idgen.New()
	if err != nil {
		t.Fatalf("產生測試活動標識失敗：%v", err)
	}
	targetID, err := idgen.New()
	if err != nil {
		t.Fatalf("產生測試對象標識失敗：%v", err)
	}
	if _, err := audits.Append(ctx, db.SQL(), audit.Record{
		Scope:      audit.ScopeActivity,
		ActivityID: activityID,
		Actor:      audit.Actor{Kind: audit.ActorSystem},
		Action:     "fake.action",
		Target:     audit.Target{Kind: "session", ID: targetID.String()},
		Reason:     "清理測試的前置記錄",
	}); err != nil {
		t.Fatalf("寫入 activity_audit 測試筆失敗：%v", err)
	}

	if n := countAudit(t, db, "root_audit"); n != 1 {
		t.Fatalf("root_audit 前置應為 1 筆，實際 %d", n)
	}
	if n := countAudit(t, db, "activity_audit"); n != 1 {
		t.Fatalf("activity_audit 前置應為 1 筆，實際 %d", n)
	}
}

// TestIdleDeadlineNeverExtendsAbsolute 是「閒置截止、不延長絕對期」這條已批准語義的直接斷言。
//
// 測試點位刻意全都在「剛剛還在動」的時刻：只要活動能換來更長的壽命，
// 下面任意一個點位就會變成有效——而在絕對期限之上，活動什麼都換不來。
func TestIdleDeadlineNeverExtendsAbsolute(t *testing.T) {
	policy := Policy{IdleTTL: 6 * time.Hour}
	db, clock, store := newPolicyEnv(t, time.Hour, policy)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	sess, secret, err := store.Create(ctx, db.SQL(), root)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	if !sess.ExpiresAt.Equal(testBase.Add(time.Hour)) {
		t.Fatalf("絕對期限應由建立時刻定死：%s", sess.ExpiresAt)
	}

	// 絕對期限內反覆活動：每一次都還有效，但 expires_at 從不因活動而後移。
	for _, at := range []time.Duration{10 * time.Minute, 30 * time.Minute, 50 * time.Minute} {
		clock.Set(testBase.Add(at))
		got, err := store.Verify(ctx, db.SQL(), secret)
		if err != nil {
			t.Fatalf("%s 的活動應通過驗證：%v", at, err)
		}
		if !got.ExpiresAt.Equal(testBase.Add(time.Hour)) {
			t.Fatalf("活動把絕對期限推後了：%s", got.ExpiresAt)
		}
		if deadline := got.IdleDeadline(policy.IdleTTL); !deadline.Equal(testBase.Add(time.Hour)) {
			t.Errorf("閒置截止應被絕對期限封頂，實際 %s", deadline)
		}
	}

	// 絕對期限一到就失效，哪怕上一毫秒才活動過。
	clock.Set(testBase.Add(time.Hour - time.Millisecond))
	if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
		t.Fatalf("到期前一毫秒仍應有效：%v", err)
	}
	clock.Set(testBase.Add(time.Hour))
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrExpired) {
		t.Fatalf("恰到絕對期限應回 ErrExpired，實際 %v", err)
	}
}

// TestIdleExpiryBeforeAbsolute 驗證「一直不動」的會話在絕對期限之前就被閒置線拒掉，
// 並且 0（關閉）的含義是「不啟用」，不是「立即失效」。
func TestIdleExpiryBeforeAbsolute(t *testing.T) {
	db, clock, store := newPolicyEnv(t, 24*time.Hour, Policy{IdleTTL: 30 * time.Minute})
	ctx := context.Background()

	// 兩枚會話都建立在同一刻：一枚用來看「截止前一毫秒還有效」，
	// 另一枚從沒被驗證過（活動會把閒置線重新起算），用來看「恰到達線即失效」。
	movable := identitytest.Root(t, identity.OriginHTTPRequest)
	_, movingSecret, err := store.Create(ctx, db.SQL(), movable)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	still := identitytest.Root(t, identity.OriginHTTPRequest)
	stillSess, silentSecret, err := store.Create(ctx, db.SQL(), still)
	if err != nil {
		t.Fatalf("建立第二枚會話失敗：%v", err)
	}

	// 閒置線到的前一毫秒：絕對期限還有整整一天，放行只可能來自「還沒到閒置線」。
	clock.Set(testBase.Add(30*time.Minute - time.Millisecond))
	if _, err := store.Verify(ctx, db.SQL(), movingSecret); err != nil {
		t.Fatalf("閒置截止前一毫秒應有效：%v", err)
	}
	// 恰到達（那枚從沒動過的會話）：與絕對期限同一口徑，now >= 截止即失效。
	clock.Set(testBase.Add(30 * time.Minute))
	if _, err := store.Verify(ctx, db.SQL(), silentSecret); !errors.Is(err, ErrExpired) {
		t.Fatalf("閒置截止應回 ErrExpired，實際 %v", err)
	}
	if got := stillSess.IdleDeadline(30 * time.Minute); !got.Equal(testBase.Add(30 * time.Minute)) {
		t.Errorf("未活動過的閒置截止應為建立 + 30 分鐘，實際 %s", got)
	}

	// 同一時刻、同一個庫，換一個 IdleTTL=0 的倉儲就必須有效：
	// 0 是「不啟用閒置判定」。若把它讀成「立即失效」，這一步會直接失敗。
	if _, err := mustPolicyStore(t, clock, 24*time.Hour, Policy{}).Verify(ctx, db.SQL(), silentSecret); err != nil {
		t.Fatalf("IdleTTL=0 不應啟用閒置判定：%v", err)
	}
}

// TestIdleResumesAfterActivity 確認活動把閒置線重新往前推（但仍被絕對期限封頂）。
func TestIdleResumesAfterActivity(t *testing.T) {
	policy := Policy{IdleTTL: 30 * time.Minute}
	db, clock, store := newPolicyEnv(t, 24*time.Hour, policy)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	sess, secret, err := store.Create(ctx, db.SQL(), root)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	if !sess.ExpiresAt.Equal(testBase.Add(24 * time.Hour)) {
		t.Fatalf("絕對期限應是 24 小時後：%s", sess.ExpiresAt)
	}
	if want := testBase.Add(30 * time.Minute); !sess.IdleDeadline(policy.IdleTTL).Equal(want) {
		t.Fatalf("剛建立時的閒置截止應為 %s，實際 %s", want, sess.IdleDeadline(policy.IdleTTL))
	}
	// 沉默 20 分鐘後活動一次：以那次活動起算新的 30 分鐘。
	clock.Set(testBase.Add(20 * time.Minute))
	got, err := store.Verify(ctx, db.SQL(), secret)
	if err != nil {
		t.Fatalf("20 分鐘的活動應通過驗證：%v", err)
	}
	if want := testBase.Add(50 * time.Minute); !got.IdleDeadline(policy.IdleTTL).Equal(want) {
		t.Fatalf("活動後的閒置截止應為 %s，實際 %s", want, got.IdleDeadline(policy.IdleTTL))
	}
	// 建立後 45 分鐘：以最後活動（20 分）計才 25 分鐘，仍有效。
	clock.Set(testBase.Add(45 * time.Minute))
	again, err := store.Verify(ctx, db.SQL(), secret)
	if err != nil {
		t.Fatalf("以最後活動計 25 分鐘應仍有效：%v", err)
	}
	// 從這一次活動（45 分）再往後 31 分鐘：越過閒置線，失效。
	clock.Set(testBase.Add(76 * time.Minute))
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrExpired) {
		t.Fatalf("距最後活動 31 分鐘應回 ErrExpired，實際 %v", err)
	}
	if want := testBase.Add(75 * time.Minute); !again.IdleDeadline(policy.IdleTTL).Equal(want) {
		t.Errorf("第二次活動的截止應為 %s，實際 %s", want, again.IdleDeadline(policy.IdleTTL))
	}
}

// TestTouchThresholdThrottlesWrites 是本步「不讓每次查詢造成無意義 SQLite 寫競爭」的直接斷言：
// 閾值內的驗證只在記憶體裡推進活動時刻，不寫庫；跨過閾值才寫一行。
func TestTouchThresholdThrottlesWrites(t *testing.T) {
	db, clock, store := newPolicyEnv(t, 24*time.Hour, Policy{TouchThreshold: 5 * time.Minute})
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	sess, secret, err := store.Create(ctx, db.SQL(), root)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	written := readLastActive(t, db, sess.ID)

	for _, at := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute} {
		clock.Set(testBase.Add(at))
		got, err := store.Verify(ctx, db.SQL(), secret)
		if err != nil {
			t.Fatalf("%s 的驗證應有效：%v", at, err)
		}
		if !got.LastActiveAt.Equal(testBase.Add(at)) {
			t.Errorf("回傳實體應推進到 %s，實際 %s", at, got.LastActiveAt)
		}
		if now := readLastActive(t, db, sess.ID); now != written {
			t.Fatalf("未超過節流閾值不應寫庫：%d != %d", now, written)
		}
	}

	// 恰好到閾值：寫。比較用「>=」，等於閾值那一格就必須落庫。
	clock.Set(testBase.Add(5 * time.Minute))
	if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
		t.Fatalf("到節流閾值的驗證應有效：%v", err)
	}
	if now := readLastActive(t, db, sess.ID); now != timeutil.ToMillis(testBase.Add(5*time.Minute)) {
		t.Fatalf("到達節流閾值應落庫，實際 %d", now)
	}

	// 閾值是從「上次落庫」起算的，不是從建立起算：跨過一格就再寫一次。
	clock.Set(testBase.Add(9 * time.Minute))
	if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
		t.Fatalf("第二個節流窗口內的驗證應有效：%v", err)
	}
	if now := readLastActive(t, db, sess.ID); now != timeutil.ToMillis(testBase.Add(5*time.Minute)) {
		t.Fatalf("距上次落庫 4 分鐘不應再寫，實際 %d", now)
	}
	clock.Set(testBase.Add(10 * time.Minute))
	if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
		t.Fatalf("跨過第二格的驗證應有效：%v", err)
	}
	if now := readLastActive(t, db, sess.ID); now != timeutil.ToMillis(testBase.Add(10*time.Minute)) {
		t.Fatalf("跨過第二格應再落庫，實際 %d", now)
	}
}

// TestTouchZeroWritesEveryVerify 釘住預設（無策略）倉儲的可觀察行為沒因新增欄位而改變：
// 閾值為 0 時每次驗證都寫庫——既有測試對「驗證推進最近活動」的斷言依賴這一條。
func TestTouchZeroWritesEveryVerify(t *testing.T) {
	db, clock, store := newPolicyEnv(t, 24*time.Hour, Policy{})
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	sess, secret, err := store.Create(ctx, db.SQL(), root)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	clock.Set(testBase.Add(time.Minute))
	if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
		t.Fatalf("驗證應有效：%v", err)
	}
	if now := readLastActive(t, db, sess.ID); now != timeutil.ToMillis(testBase.Add(time.Minute)) {
		t.Fatalf("閾值為 0 應每次驗證都寫，實際 %d", now)
	}
}

// TestExpirySurvivesProcessRestart 是「重啟後仍能正確判斷到期，不使用程序內倒計時」的構造性證明：
// 關掉庫、丟棄舊倉儲，再用同一份資料庫檔案建一個全新倉儲與全新時鐘。
//
// 新倉儲對「會話何時建立」毫無記憶，判定只能落在庫內的 last_active_at 上；
// 換成程序內倒計時的實現，這裡就會拿到「仍然有效」。
func TestExpirySurvivesProcessRestart(t *testing.T) {
	dir := retryTempDir(t)
	dbPath := filepath.Join(dir, "evernight.db")
	ctx := context.Background()
	policy := Policy{IdleTTL: 30 * time.Minute, CleanupGrace: 7 * 24 * time.Hour}

	firstClock := timeutil.NewTest(testBase)
	firstDB, err := database.Open(ctx, database.Options{Path: dbPath, BusyTimeout: time.Second})
	if err != nil {
		t.Fatalf("首次開啟資料庫失敗：%v", err)
	}
	if _, err := migrate.Apply(ctx, firstDB.SQL(), migrate.Options{Clock: firstClock}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	// 絕對期限 24 小時：重啟後落在「閒置早已超時、絕對期限還遠」的時刻，
	// 唯一能判出失效的依據就是庫裡那一格 last_active_at。
	firstStore, err := NewStoreWithPolicy(firstClock, 24*time.Hour, policy)
	if err != nil {
		t.Fatalf("首次建立倉儲失敗：%v", err)
	}
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	_, secret, err := firstStore.Create(ctx, firstDB.SQL(), root)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	if err := firstDB.Close(); err != nil {
		t.Fatalf("關閉第一段資料庫失敗：%v", err)
	}

	secondClock := timeutil.NewTest(testBase.Add(6 * time.Hour))
	secondDB, err := database.Open(ctx, database.Options{Path: dbPath, BusyTimeout: time.Second})
	if err != nil {
		t.Fatalf("重開資料庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = secondDB.Close() })
	secondStore, err := NewStoreWithPolicy(secondClock, 24*time.Hour, policy)
	if err != nil {
		t.Fatalf("重開後建立倉儲失敗：%v", err)
	}
	if _, err := secondStore.Verify(ctx, secondDB.SQL(), secret); !errors.Is(err, ErrExpired) {
		t.Fatalf("重啟後應按庫內時刻判出閒置失效，實際 %v", err)
	}
	// 清理任務在這個「新程序」裡從沒跑過，行仍在庫裡——入口拒絕與物理刪除是兩件事。
	if n := countSessions(t, secondDB); n != 1 {
		t.Fatalf("清理未執行時失效行應仍在庫內，實際 %d 行", n)
	}
}

// TestVerifyRejectsExpiredBeforeAnyCleanup 把「失效檢查發生在服務入口，不依賴後臺清理」
// 釘成一個不需要清理參與的事實：寬限期都還沒開始計，驗證就已經在拒。
func TestVerifyRejectsExpiredBeforeAnyCleanup(t *testing.T) {
	db, clock, store := newPolicyEnv(t, time.Hour, Policy{CleanupGrace: 30 * 24 * time.Hour})
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	_, secret, err := store.Create(ctx, db.SQL(), root)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	clock.Set(testBase.Add(2 * time.Hour))

	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrExpired) {
		t.Fatalf("入口應直接拒絕過期會話，實際 %v", err)
	}
	// 傳輸層真正用的是「拿秘密換主體」這條路，結論必須一致：不存在
	// 「Verify 拒了但換主體還能過」的第二通路。
	if _, _, err := store.ResolvePrincipal(ctx, db.SQL(), secret, identity.OriginHTTPRequest); !errors.Is(err, ErrExpired) {
		t.Fatalf("主體解析同樣應拒絕過期會話，實際 %v", err)
	}
	if n := countSessions(t, db); n != 1 {
		t.Errorf("入口拒絕不應順帶刪除記錄，實際 %d 行", n)
	}
}

// TestCleanupBatchAndGraceBoundary 是一次完整的批次清理：五枚會話同庫共存，
// 只有「已失效且過了寬限期」的那幾行被刪，且刪除線兩側各差一毫秒的行為都被釘住。
//
// 現場（絕對期限 24 小時、閒置 30 分鐘、寬限期 7 天）：
//   - 第 1～3 枚：建立後再沒動過，靠絕對到期失效（刪除線＝建立 + 24h + 7d）；
//   - 第 4 枚：閒置失效，但絕對期限未到——清理不看閒置，它留到絕對期限過後才一起走；
//   - 第 5 枚：建立後 2 小時被撤銷（刪除線＝撤銷 + 7d），它是第一個越過寬限期的。
func TestCleanupBatchAndGraceBoundary(t *testing.T) {
	policy := Policy{IdleTTL: 30 * time.Minute, CleanupGrace: 7 * 24 * time.Hour}
	db, clock, store := newPolicyEnv(t, 24*time.Hour, policy)
	ctx := context.Background()

	var ids []idgen.ID
	var secrets []string
	for i := 0; i < 5; i++ {
		root := identitytest.Root(t, identity.OriginHTTPRequest)
		sess, secret, err := store.Create(ctx, db.SQL(), root)
		if err != nil {
			t.Fatalf("建立第 %d 枚會話失敗：%v", i, err)
		}
		ids = append(ids, sess.ID)
		secrets = append(secrets, secret)
	}
	// 第 4 枚：閒置失效（30 分鐘沒動），絕對期限（24 小時）與寬限期都還沒到。
	clock.Set(testBase.Add(40 * time.Minute))
	if _, err := store.Verify(ctx, db.SQL(), secrets[3]); !errors.Is(err, ErrExpired) {
		t.Fatalf("第 4 枚應已閒置失效：%v", err)
	}
	// 第 5 枚：建立後 2 小時被撤銷。
	clock.Set(testBase.Add(2 * time.Hour))
	if _, err := store.Revoke(ctx, db.SQL(), ids[4]); err != nil {
		t.Fatalf("撤銷第 5 枚失敗：%v", err)
	}
	// 閒置失效的行不該因為「閒置」而被刪：它此刻仍留在庫裡。
	if deleted, err := store.Cleanup(ctx, db.SQL()); err != nil || deleted != 0 {
		t.Fatalf("此刻不應有任何刪除，刪 %d 行 err %v", deleted, err)
	}

	// 撤銷那枚的刪除線前一毫秒：撤銷 + 7 天。
	clock.Set(testBase.Add(2*time.Hour + 7*24*time.Hour - time.Millisecond))
	if deleted, err := store.Cleanup(ctx, db.SQL()); err != nil || deleted != 0 {
		t.Fatalf("刪除線前一毫秒不應刪除，刪 %d 行 err %v", deleted, err)
	}

	// 恰好到達：只有撤銷那枚被刪（絕對到期的刪除線還在 22 小時之後）。
	clock.Set(testBase.Add(2*time.Hour + 7*24*time.Hour))
	deleted, err := store.Cleanup(ctx, db.SQL())
	if err != nil {
		t.Fatalf("撤銷刪除線清理失敗：%v", err)
	}
	if deleted != 1 {
		t.Fatalf("撤銷刪除線應只刪那 1 枚，實際 %d", deleted)
	}
	if n := countSessions(t, db); n != 4 {
		t.Fatalf("其餘四枚應仍在庫內，實際 %d", n)
	}

	// 絕對到期的刪除線前一毫秒：建立 + 24h + 7d。
	clock.Set(testBase.Add(8*24*time.Hour - time.Millisecond))
	if deleted, err := store.Cleanup(ctx, db.SQL()); err != nil || deleted != 0 {
		t.Fatalf("絕對刪除線前一毫秒不應刪除，刪 %d 行 err %v", deleted, err)
	}

	// 恰好到達：剩下四枚（含那枚閒置失效的）一起被刪。
	clock.Set(testBase.Add(8 * 24 * time.Hour))
	deleted, err = store.Cleanup(ctx, db.SQL())
	if err != nil {
		t.Fatalf("絕對刪除線清理失敗：%v", err)
	}
	if deleted != 4 {
		t.Fatalf("絕對刪除線應刪掉剩餘 4 枚，實際 %d", deleted)
	}
	if n := countSessions(t, db); n != 0 {
		t.Fatalf("清理後表應為空，實際 %d 行", n)
	}
}

// TestCleanupKeepsActiveAndGraceWindowRows 是清理的另一半：活躍行與寬限期內的失效行都留下。
func TestCleanupKeepsActiveAndGraceWindowRows(t *testing.T) {
	db, clock, store := newPolicyEnv(t, 2*time.Hour, Policy{CleanupGrace: time.Hour})
	ctx := context.Background()

	first := identitytest.Root(t, identity.OriginHTTPRequest)
	active, activeSecret, err := store.Create(ctx, db.SQL(), first)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	second := identitytest.Root(t, identity.OriginHTTPRequest)
	dying, _, err := store.Create(ctx, db.SQL(), second)
	if err != nil {
		t.Fatalf("建立第二枚會話失敗：%v", err)
	}

	// 走到絕對期限後 30 分鐘：兩行都失效，但都還在 1 小時的寬限期內。
	clock.Set(testBase.Add(2*time.Hour + 30*time.Minute))
	if _, err := store.Verify(ctx, db.SQL(), activeSecret); !errors.Is(err, ErrExpired) {
		t.Fatalf("入口應拒絕過期會話：%v", err)
	}
	if deleted, err := store.Cleanup(ctx, db.SQL()); err != nil || deleted != 0 {
		t.Fatalf("寬限期內不應刪除，刪 %d 行 err %v", deleted, err)
	}

	// 剛好跨過寬限期：兩行一起刪，活躍行也早已到期（同一批）。
	clock.Set(testBase.Add(3 * time.Hour))
	deleted, err := store.Cleanup(ctx, db.SQL())
	if err != nil {
		t.Fatalf("清理失敗：%v", err)
	}
	if deleted != 2 {
		t.Errorf("過寬限期後應刪 2 行，實際 %d", deleted)
	}
	if n := countSessions(t, db); n != 0 {
		t.Errorf("兩行都應被清掉，實際剩 %d", n)
	}
	if active.ID == dying.ID {
		t.Error("前置兩枚會話标识相同")
	}
}

// TestCleanupWithNeverActiveSessionStays 確認「從未被使用」的會話同樣按絕對期限清理，
// 且 last_active_at 等於 created_at 不會讓它被特殊對待。
func TestCleanupWithNeverActiveSessionStays(t *testing.T) {
	db, clock, store := newPolicyEnv(t, time.Hour, Policy{CleanupGrace: 10 * time.Minute})
	ctx := context.Background()

	root := identitytest.Root(t, identity.OriginHTTPRequest)
	sess, _, err := store.Create(ctx, db.SQL(), root)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	if got := readLastActive(t, db, sess.ID); got != timeutil.ToMillis(testBase) {
		t.Fatalf("未使用過的最近活動應等於建立時刻，實際 %d", got)
	}
	// 到期後、寬限期內：留著。
	clock.Set(testBase.Add(time.Hour + time.Minute))
	if deleted, err := store.Cleanup(ctx, db.SQL()); err != nil || deleted != 0 {
		t.Fatalf("寬限期內不應刪除，刪 %d 行 err %v", deleted, err)
	}
	// 到期後滿 10 分鐘：刪掉。
	clock.Set(testBase.Add(time.Hour + 10*time.Minute))
	deleted, err := store.Cleanup(ctx, db.SQL())
	if err != nil {
		t.Fatalf("清理失敗：%v", err)
	}
	if deleted != 1 {
		t.Fatalf("過寬限期後應刪 1 行，實際 %d", deleted)
	}
}

// TestCleanupZeroGraceDeletesImmediately 說明 0 是一個明確的運維選擇：失效即刪。
func TestCleanupZeroGraceDeletesImmediately(t *testing.T) {
	db, clock, store := newPolicyEnv(t, time.Hour, Policy{CleanupGrace: 0})
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	_, secret, err := store.Create(ctx, db.SQL(), root)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	clock.Set(testBase.Add(time.Hour))
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrExpired) {
		t.Fatalf("到期應先被入口拒絕：%v", err)
	}
	deleted, err := store.Cleanup(ctx, db.SQL())
	if err != nil {
		t.Fatalf("清理失敗：%v", err)
	}
	if deleted != 1 {
		t.Fatalf("寬限期為 0 應立即刪除，實際 %d", deleted)
	}
	// 行刪掉之後，同一枚秘密的拒絕理由從「已到期」變成「查無此秘密」，
	// 兩者在對外口徑上收斂為同一個錯誤——刪除不會改變客戶端的處置。
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("刪除後應收斂為 ErrInvalidSecret，實際 %v", err)
	}
}

// TestCleanupNeverTouchesAudit 釘住「不透過刪除審計來節省空間」：
// 清理掉的會話行再多，兩張審計表一行都不動。
func TestCleanupNeverTouchesAudit(t *testing.T) {
	db, clock, store := newPolicyEnv(t, time.Hour, Policy{CleanupGrace: 0})
	ctx := context.Background()
	seedAuditRows(t, db, clock)

	for i := 0; i < 2; i++ {
		root := identitytest.Root(t, identity.OriginHTTPRequest)
		if _, _, err := store.Create(ctx, db.SQL(), root); err != nil {
			t.Fatalf("建立第 %d 枚會話失敗：%v", i, err)
		}
	}
	clock.Set(testBase.Add(2 * time.Hour))
	deleted, err := store.Cleanup(ctx, db.SQL())
	if err != nil {
		t.Fatalf("清理失敗：%v", err)
	}
	if deleted != 2 {
		t.Fatalf("兩枚過期會話都應被清掉，實際 %d", deleted)
	}
	for _, table := range []string{"root_audit", "activity_audit"} {
		if n := countAudit(t, db, table); n != 1 {
			t.Errorf("%s 不應被清理變動，實際 %d 筆", table, n)
		}
	}
}

// TestCleanupOnNilQuerierIsRejected 與其他倉儲同一口徑：拿不到連線就報錯，不靜默成功。
func TestCleanupOnNilQuerierIsRejected(t *testing.T) {
	store := mustPolicyStore(t, timeutil.NewTest(testBase), time.Hour, Policy{})
	if _, err := store.Cleanup(context.Background(), nil); err == nil {
		t.Fatal("nil Querier 應回報錯誤")
	}
}

// TestNewStoreWithPolicyGuards 是策略引數的前置閘門：負值一律拒絕，0 各有明確含義。
func TestNewStoreWithPolicyGuards(t *testing.T) {
	clock := timeutil.NewTest(testBase)
	for name, policy := range map[string]Policy{
		"idle":  {IdleTTL: -time.Minute},
		"touch": {TouchThreshold: -time.Minute},
		"grace": {CleanupGrace: -time.Minute},
	} {
		if _, err := NewStoreWithPolicy(clock, time.Hour, policy); err == nil {
			t.Errorf("%s 為負值時應拒絕建立", name)
		}
	}
	if _, err := NewStoreWithPolicy(clock, 0, Policy{}); err == nil {
		t.Error("絕對期限不為正值時應拒絕建立")
	}
	// 全 0 策略合法：關閉閒置與節流、失效即刪。
	if _, err := NewStoreWithPolicy(clock, time.Hour, Policy{}); err != nil {
		t.Errorf("零值策略應合法：%v", err)
	}
	// 舊入口沿用同一份校驗，且不會悄悄帶上任何預設策略。
	legacy, err := NewStore(clock, time.Hour)
	if err != nil {
		t.Fatalf("NewStore 建立失敗：%v", err)
	}
	if legacy.policy != (Policy{}) {
		t.Errorf("NewStore 應帶零值策略，實際 %+v", legacy.policy)
	}
}

// mustPolicyStore 是測試內「建不出來就直接失敗」的簡寫。
func mustPolicyStore(t *testing.T, clock timeutil.Clock, ttl time.Duration, policy Policy) *Store {
	t.Helper()
	store, err := NewStoreWithPolicy(clock, ttl, policy)
	if err != nil {
		t.Fatalf("建立帶策略的會話倉儲失敗：%v", err)
	}
	return store
}
