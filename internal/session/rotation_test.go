package session

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 這一檔釘住「會話秘密輪換」的全部語義：
//   - 換密不換命：同一行、同一個 device_id、同一個絕對期限；
//   - 舊秘密在提交那一刻起徹底失效，且失效邊界可驗證（不是「大概失效了」）；
//   - 已撤銷／已到期／主體已失效的會話，輪換救不回來；
//   - 併發輪換只有一個贏家，輸家拿到「上一代」而不是「成功」；
//   - 讀與寫之間的撤銷、到期與並發輪換，都由那一條 UPDATE 的 WHERE 擋住，
//     不出現「已撤銷的會話又拿到一枚新秘密」這種半套結果。

// readRotationRow 直接讀庫裡的輪換事實：世代號、當今雜湊、上一代雜湊。
//
// 判據必須是資料庫本身而不是方法回傳值——「回傳說換了、庫裡沒換」正是輪換最壞的失敗形態。
func readRotationRow(t *testing.T, db *database.DB, id idgen.ID) (seq int64, hash, prev string) {
	t.Helper()
	var prevHash sql.NullString
	if err := db.SQL().QueryRowContext(context.Background(),
		"SELECT rotation_seq, token_hash, previous_token_hash FROM sessions WHERE id = ?", id.String()).
		Scan(&seq, &hash, &prevHash); err != nil {
		t.Fatalf("讀回輪換行失敗：%v", err)
	}
	return seq, hash, prevHash.String
}

// countSessions 讀全錶行數的輔助沿用 store_test.go 那份（輪換是就地換代，行數恆不變）。

// TestRotateIssuesNewSecretAndBumpsGeneration：正常輪換——換出新秘密、世代號加一、
// 身份與期限一個字不動，且新秘密當場就換得出主體。
func TestRotateIssuesNewSecretAndBumpsGeneration(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	sess, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))
	_, oldHash, _ := readRotationRow(t, db, sess.ID)

	rotated, newSecret, err := store.Rotate(ctx, db.SQL(), secret)
	if err != nil {
		t.Fatalf("輪換失敗：%v", err)
	}
	if newSecret == "" {
		t.Fatal("輪換必須回傳一枚新秘密（它唯一的去處是 Set-Cookie）")
	}
	if newSecret == secret {
		t.Error("輪換回傳的秘密不得與舊秘密相同：相同即沒有換")
	}
	if rotated.RotationSeq != 1 {
		t.Errorf("世代號應為 1，實際 %d", rotated.RotationSeq)
	}
	if rotated.ID != sess.ID || rotated.DeviceID != sess.DeviceID {
		t.Errorf("輪換不得換掉會話或設備身份：%v / %v vs %v / %v",
			rotated.ID, rotated.DeviceID, sess.ID, sess.DeviceID)
	}
	if !rotated.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Errorf("輪換不得延長絕對期限：%s vs %s", rotated.ExpiresAt, sess.ExpiresAt)
	}
	if !rotated.CreatedAt.Equal(sess.CreatedAt) {
		t.Errorf("建立時刻不得變動：%s vs %s", rotated.CreatedAt, sess.CreatedAt)
	}

	// 庫內事實：世代號推進、查詢鍵換掉、舊雜湊被記成「上一代」。
	seq, hash, prev := readRotationRow(t, db, sess.ID)
	if seq != 1 {
		t.Errorf("庫內世代號應為 1，實際 %d", seq)
	}
	if hash == oldHash {
		t.Error("庫內查找鍵應已換成新一枚的哈希")
	}
	if prev != oldHash {
		t.Errorf("上一代哈希應留下換代前那一枚，實際 %s", prev)
	}

	if _, err := store.Verify(ctx, db.SQL(), newSecret); err != nil {
		t.Errorf("新秘密應通過驗證：%v", err)
	}
	if _, _, err := store.ResolvePrincipal(ctx, db.SQL(), newSecret, identity.OriginHTTPRequest); err != nil {
		t.Errorf("新秘密應換得出主體：%v", err)
	}
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrStaleSecret) {
		t.Errorf("舊秘密應回 ErrStaleSecret，實際 %v", err)
	}
}

// TestRotateRepeatedStaysOneDevice：連換三次仍是同一行同一裝置，世代號 1→2→3。
//
// 「同一臺裝置輪換不是新增裝置」因此可驗證：行數恆為 1，device_id 恆不變，
// 世代號每次恰好加一。庫裡只留最近一代，被擠掉的那一代連「上一代」都不是了。
func TestRotateRepeatedStaysOneDevice(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	sess, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))
	first := secret
	current := secret
	var prevSeq int64
	for i := 0; i < 3; i++ {
		rotated, next, err := store.Rotate(ctx, db.SQL(), current)
		if err != nil {
			t.Fatalf("第 %d 次輪換失敗：%v", i+1, err)
		}
		if next == current {
			t.Fatalf("第 %d 次輪換回傳的秘密與上一枚相同", i+1)
		}
		if rotated.RotationSeq != int64(i+1) {
			t.Errorf("第 %d 次輪換後世代號應為 %d，實際 %d", i+1, i+1, rotated.RotationSeq)
		}
		if rotated.RotationSeq != prevSeq+1 {
			t.Errorf("世代號必須恰好加一：%d → %d", prevSeq, rotated.RotationSeq)
		}
		prevSeq = rotated.RotationSeq
		current = next
	}
	if n := countSessions(t, db); n != 1 {
		t.Errorf("三次輪換後仍應只有一行，實際 %d 行", n)
	}
	seq, _, prev := readRotationRow(t, db, sess.ID)
	if seq != 3 {
		t.Errorf("庫內世代號應為 3，實際 %d", seq)
	}
	if prev == "" {
		t.Error("庫內仍應留著最近一代的上一代哈希")
	}
	// 最早那一枚已被擠出「上一代」的位置：它換不出身份，也得不到較友善的措辭。
	if _, err := store.Verify(ctx, db.SQL(), first); !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("已被擠掉的舊舊秘密應回 ErrInvalidSecret，實際 %v", err)
	}
}

// TestRotateDoesNotExtendAbsoluteExpiry：輪換不是續期——到期那一刻仍然到期，
// 哪怕到期前一毫秒才換過秘密。
func TestRotateDoesNotExtendAbsoluteExpiry(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	sess, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))

	clock.Advance(59 * time.Minute)
	_, newSecret, err := store.Rotate(ctx, db.SQL(), secret)
	if err != nil {
		t.Fatalf("到期前輪換失敗：%v", err)
	}
	if seq, _, _ := readRotationRow(t, db, sess.ID); seq != 1 {
		t.Errorf("世代號應為 1，實際 %d", seq)
	}

	// 到期前一毫秒：新秘密仍有效。
	clock.Advance(time.Minute - time.Millisecond)
	if _, err := store.Verify(ctx, db.SQL(), newSecret); err != nil {
		t.Errorf("到期前新秘密應有效：%v", err)
	}
	// 恰好到期：新秘密立刻失效，輪換沒有把壽命往後推一毫秒。
	clock.Advance(time.Millisecond)
	if _, err := store.Verify(ctx, db.SQL(), newSecret); !errors.Is(err, ErrExpired) {
		t.Errorf("到期後新秘密應回 ErrExpired，實際 %v", err)
	}
	if _, _, err := store.Rotate(ctx, db.SQL(), newSecret); !errors.Is(err, ErrExpired) {
		t.Errorf("到期後輪換應回 ErrExpired，實際 %v", err)
	}
}

// TestRotateRefusesRevokedSession：已撤銷的會話輪換不了——撤銷不可逆，
// 換密不是「救回來」的通路，而且失敗的輪換不得在庫裡留下任何痕跡。
func TestRotateRefusesRevokedSession(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	sess, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))
	_, hashBefore, _ := readRotationRow(t, db, sess.ID)
	if _, err := store.Revoke(ctx, db.SQL(), sess.ID); err != nil {
		t.Fatalf("撤銷失敗：%v", err)
	}
	if _, _, err := store.Rotate(ctx, db.SQL(), secret); !errors.Is(err, ErrRevoked) {
		t.Errorf("已撤銷會話輪換應回 ErrRevoked，實際 %v", err)
	}
	seq, hash, prev := readRotationRow(t, db, sess.ID)
	if seq != 0 {
		t.Errorf("失敗的輪換不應推進世代號，實際 %d", seq)
	}
	if prev != "" {
		t.Error("失敗的輪換不應留下上一代哈希")
	}
	if hash != hashBefore {
		t.Error("失敗的輪換不應換掉查找鍵")
	}
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrRevoked) {
		t.Errorf("撤銷後的會話仍應回 ErrRevoked，實際 %v", err)
	}
}

// TestRotateRefusesExpiredSession：已絕對到期的會話輪換不了，新秘密無從產生。
func TestRotateRefusesExpiredSession(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	sess, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))
	clock.Advance(time.Hour + time.Minute)
	if _, _, err := store.Rotate(ctx, db.SQL(), secret); !errors.Is(err, ErrExpired) {
		t.Errorf("已到期會話輪換應回 ErrExpired，實際 %v", err)
	}
	if seq, _, _ := readRotationRow(t, db, sess.ID); seq != 0 {
		t.Errorf("失敗的輪換不應推進世代號，實際 %d", seq)
	}
}

// TestRotateRefusesIdleExpiredSession：閒置失效的會話同樣輪換不了。
//
// 這一條與絕對到期分開測，因為它們走的是不同的判定（閒置線在庫內時刻之上疊算），
// 而「輪換不得把一個閒置失效的會話救回來」是輪換最容易漏掉的一半。
func TestRotateRefusesIdleExpiredSession(t *testing.T) {
	db, clock, store := newPolicyEnv(t, 6*time.Hour, Policy{IdleTTL: 30 * time.Minute})
	ctx := context.Background()
	sess, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))
	clock.Advance(45 * time.Minute)
	if _, _, err := store.Rotate(ctx, db.SQL(), secret); !errors.Is(err, ErrExpired) {
		t.Errorf("閒置失效會話輪換應回 ErrExpired，實際 %v", err)
	}
	if seq, _, _ := readRotationRow(t, db, sess.ID); seq != 0 {
		t.Errorf("失敗的輪換不應推進世代號，實際 %d", seq)
	}
	// 絕對期限還遠，失效純粹來自閒置：證明這條拒絕走的是閒置判定而不是期限判定。
	if !clock.Now().Before(sess.ExpiresAt) {
		t.Fatal("前置條件不成立：絕對期限應尚未到達")
	}
}

// TestRotateRefusesDisabledSubject：主體已被停用的會話輪換不了——
// 換秘密是繼續用這個身分的前提，不是讓被停用者保住會話的通路。
func TestRotateRefusesDisabledSubject(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	a, principal := createAccountDirect(t, db, clock, "rotate-disabled-probe")
	sess, secret := mustCreate(t, store, db, principal)
	if _, err := db.SQL().ExecContext(ctx,
		"UPDATE accounts SET status = 'disabled', disabled_at = ? WHERE id = ?",
		timeutil.ToMillis(clock.Now()), a.ID.String()); err != nil {
		t.Fatalf("禁用帳戶失敗：%v", err)
	}
	if _, _, err := store.Rotate(ctx, db.SQL(), secret); !errors.Is(err, ErrSubjectUnavailable) {
		t.Errorf("主體被禁用時輪換應回 ErrSubjectUnavailable，實際 %v", err)
	}
	if seq, _, prev := readRotationRow(t, db, sess.ID); seq != 0 || prev != "" {
		t.Errorf("失敗的輪換不應動世代號或上一代哈希，實際 seq=%d prev=%q", seq, prev)
	}
}

// TestRotateRefusesStaleAndUnknownSecrets：拿「上一代」秘密、一枚陌生秘密、
// 或形狀不合格的輸入來輪換，一律拒絕——而且三者得到的結論各不相同的理由只有兩個：
// 「你晚了」（可重試）與「你從來不對」（重新登入）。
func TestRotateRefusesStaleAndUnknownSecrets(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	sess, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))
	if _, _, err := store.Rotate(ctx, db.SQL(), secret); err != nil {
		t.Fatalf("首次輪換失敗：%v", err)
	}
	// 落後一代：拒絕，且不得因此再換一次（那會讓舊秘密成為一條並行的認證通路）。
	if _, _, err := store.Rotate(ctx, db.SQL(), secret); !errors.Is(err, ErrStaleSecret) {
		t.Errorf("用上一代秘密輪換應回 ErrStaleSecret，實際 %v", err)
	}
	if seq, _, _ := readRotationRow(t, db, sess.ID); seq != 1 {
		t.Errorf("落後一代的嘗試不得推進世代號，實際 %d", seq)
	}
	// 陌生但形狀合格的秘密：查無此事，一律 ErrInvalidSecret（不是較友善的 ErrStaleSecret）。
	unknown := strings.Repeat("A", secretTextLen)
	if _, _, err := store.Rotate(ctx, db.SQL(), unknown); !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("陌生秘密應回 ErrInvalidSecret，實際 %v", err)
	}
	// 形狀不合格的秘密在門前就被拒，不進查詢。
	if _, _, err := store.Rotate(ctx, db.SQL(), "not-a-secret"); !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("形狀不合格的秘密應回 ErrInvalidSecret，實際 %v", err)
	}
	if seq, _, _ := readRotationRow(t, db, sess.ID); seq != 1 {
		t.Errorf("任何一次被拒的輪換都不得推進世代號，實際 %d", seq)
	}
}

// TestRotateNilQuerierRejected：沒有連線就什麼都不做（與 Create/Verify 同一口徑）。
func TestRotateNilQuerierRejected(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	_, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))
	if _, _, err := store.Rotate(context.Background(), nil, secret); err == nil {
		t.Error("nil Querier 應被拒絕")
	}
}

// TestRotateConcurrentOnlyOneWins：多個並發輪換用同一枚秘密，恰好一個成功。
//
// 這是輪換在併發下唯一的正確答案：贏家拿到新秘密，其餘拿到「上一代」。
// 若兩個都「成功」，等於同一行上出現了兩枚都能換出身份的憑據，輪換的意義就沒了。
func TestRotateConcurrentOnlyOneWins(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	sess, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))

	const racers = 8
	results := make([]error, racers)
	secrets := make([]string, racers)
	var wg sync.WaitGroup
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func(idx int) {
			defer wg.Done()
			_, newSecret, err := store.Rotate(ctx, db.SQL(), secret)
			results[idx], secrets[idx] = err, newSecret
		}(i)
	}
	wg.Wait()

	var winners, stale int
	for i := 0; i < racers; i++ {
		switch {
		case results[i] == nil:
			winners++
			if secrets[i] == "" {
				t.Errorf("贏家必須拿到新秘密，第 %d 個沒有", i)
			}
		case errors.Is(results[i], ErrStaleSecret):
			stale++
			if secrets[i] != "" {
				t.Errorf("輸家不得拿到任何秘密，第 %d 個拿到了", i)
			}
		default:
			t.Errorf("第 %d 個並發輪換得到非預期錯誤：%v", i, results[i])
		}
	}
	if winners != 1 {
		t.Errorf("恰好應有一個贏家，實際 %d 個（另有 %d 個落後一代）", winners, stale)
	}
	if seq, _, _ := readRotationRow(t, db, sess.ID); seq != 1 {
		t.Errorf("並發輪換後世代號應為 1，實際 %d", seq)
	}
	if n := countSessions(t, db); n != 1 {
		t.Errorf("併發輪換不得新增行，實際 %d 行", n)
	}
}

// interferingQuerier 是一個測試用 Querier 替身：在把「輪換那條 UPDATE」交出去之前，
// 先在真實資料庫上做一次干擾動作（撤銷、或另一次輪換），只做一次。
//
// 存在理由：讀與寫之間的視窗只有幾微秒，用 goroutine 去撞它既不可重現也不可斷言。
// 這個替身把視窗撐開成一個確定的時序，讓「WHERE 條件確實關住了視窗」變成可測的事實。
type interferingQuerier struct {
	database.Querier
	interfere func()
	fired     bool
}

// ExecContext 攔截輪換那條 UPDATE（以 SET 子句裡的 token_hash 辨認），其餘原樣轉發。
func (q *interferingQuerier) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if !q.fired && strings.Contains(query, "SET token_hash = ?") {
		q.fired = true
		q.interfere()
	}
	return q.Querier.ExecContext(ctx, query, args...)
}

// TestRotateLosesToConcurrentRevoke：Verify 透過之後、寫入之前被撤銷——
// 輪換整個不發生，回的是「已撤銷」，不是「換成功」。
func TestRotateLosesToConcurrentRevoke(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	sess, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))

	q := &interferingQuerier{Querier: db.SQL()}
	q.interfere = func() {
		if _, err := store.Revoke(ctx, db.SQL(), sess.ID); err != nil {
			t.Errorf("干擾動作（撤銷）失敗：%v", err)
		}
	}
	if _, _, err := store.Rotate(ctx, q, secret); !errors.Is(err, ErrRevoked) {
		t.Errorf("讀寫之間被撤銷的輪換應回 ErrRevoked，實際 %v", err)
	}
	if !q.fired {
		t.Fatal("干擾動作沒有觸發：這個用例沒有測到它想測的窗口")
	}
	seq, _, prev := readRotationRow(t, db, sess.ID)
	if seq != 0 {
		t.Errorf("被撤銷的會話不得推進世代號，實際 %d", seq)
	}
	if prev != "" {
		t.Error("被撤銷的會話不得留下上一代哈希")
	}
	// 舊秘密仍然是「已撤銷」而不是「上一代」：它沒有被換掉過。
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrRevoked) {
		t.Errorf("撤銷後的舊秘密應回 ErrRevoked，實際 %v", err)
	}
}

// TestRotateLosesToConcurrentRotation：Verify 透過之後、寫入之前，另一個輪換先贏了——
// 這次輪換回「上一代」，庫內只推進一格。
func TestRotateLosesToConcurrentRotation(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	sess, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))

	q := &interferingQuerier{Querier: db.SQL()}
	q.interfere = func() {
		if _, _, err := store.Rotate(ctx, db.SQL(), secret); err != nil {
			t.Errorf("干擾動作（並發輪換）失敗：%v", err)
		}
	}
	if _, _, err := store.Rotate(ctx, q, secret); !errors.Is(err, ErrStaleSecret) {
		t.Errorf("讀寫之間被搶先輪換的那次應回 ErrStaleSecret，實際 %v", err)
	}
	if !q.fired {
		t.Fatal("干擾動作沒有觸發：這個用例沒有測到它想測的窗口")
	}
	if seq, _, _ := readRotationRow(t, db, sess.ID); seq != 1 {
		t.Errorf("只應推進一格（世代號 1），實際 %d", seq)
	}
}

// steppingClock 是「按呼叫次序換檔」的測試時鐘：第 n 次 Now 回傳第 n 個時刻，
// 用完之後重複最後一個。
//
// 它存在的唯一目的是把「Verify 讀到還活著、輪換寫入時已到期」這個幾微秒的視窗
// 撐成一個確定時序：沒有它，這條 WHERE expires_at > ? 的條件永遠不會被走到，
// 而「一次輪換能不能給一個剛到期的會話續命」就成了沒有答案的問題。
type steppingClock struct {
	steps []time.Time
	calls int
}

// Now 依呼叫次序回傳預置時刻。
func (c *steppingClock) Now() time.Time {
	idx := c.calls
	if idx >= len(c.steps) {
		idx = len(c.steps) - 1
	}
	c.calls++
	return c.steps[idx]
}

// TestRotateLosesToConcurrentExpiry：Verify 透過之後、寫入時已過絕對期限——
// 輪換不發生，回「已到期」，世代號不動。
func TestRotateLosesToConcurrentExpiry(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	sess, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))

	past := testBase.Add(time.Hour + time.Minute)
	store.clock = &steppingClock{steps: []time.Time{testBase, past, past}}
	if _, _, err := store.Rotate(ctx, db.SQL(), secret); !errors.Is(err, ErrExpired) {
		t.Errorf("讀寫之間到期的輪換應回 ErrExpired，實際 %v", err)
	}
	seq, _, prev := readRotationRow(t, db, sess.ID)
	if seq != 0 {
		t.Errorf("到期後不得推進世代號，實際 %d", seq)
	}
	if prev != "" {
		t.Error("到期後不得留下上一代哈希")
	}
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrExpired) {
		t.Errorf("到期後的秘密應回 ErrExpired，實際 %v", err)
	}
}

// TestRotateInsideTransactionRollsBackWithCaller：輪換在呼叫端的交易裡，
// 交易回滾時秘密也不換——這是「會話寫入＋審計追加」同生同滅的前提。
func TestRotateInsideTransactionRollsBackWithCaller(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	sess, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))
	_, hashBefore, _ := readRotationRow(t, db, sess.ID)

	err := db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if _, _, err := store.Rotate(tctx, tx, secret); err != nil {
			return err
		}
		return errors.New("呼叫端自行失敗")
	})
	if err == nil {
		t.Fatal("交易應以呼叫端的錯誤失敗")
	}
	seq, hashAfter, prev := readRotationRow(t, db, sess.ID)
	if seq != 0 {
		t.Errorf("回滾後世代號應仍為 0，實際 %d", seq)
	}
	if hashAfter != hashBefore {
		t.Error("回滾後查找鍵不應變動")
	}
	if prev != "" {
		t.Error("回滾後不得留下上一代哈希")
	}
	if _, err := store.Verify(ctx, db.SQL(), secret); err != nil {
		t.Errorf("回滾後原秘密應仍然有效：%v", err)
	}
}

// TestStaleLookupIsOnlyForPreviousGeneration：「上一代」這個措辭只留給真正的那一代——
// 形狀合格但從未存在過的秘密、以及被擠掉的更早世代，都只能是 ErrInvalidSecret。
func TestStaleLookupIsOnlyForPreviousGeneration(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	_, first := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))
	_, second, err := store.Rotate(ctx, db.SQL(), first)
	if err != nil {
		t.Fatalf("第一次輪換失敗：%v", err)
	}
	_, third, err := store.Rotate(ctx, db.SQL(), second)
	if err != nil {
		t.Fatalf("第二次輪換失敗：%v", err)
	}
	if _, err := store.Verify(ctx, db.SQL(), second); !errors.Is(err, ErrStaleSecret) {
		t.Errorf("上一代應回 ErrStaleSecret，實際 %v", err)
	}
	if _, err := store.Verify(ctx, db.SQL(), first); !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("被擠掉的世代應回 ErrInvalidSecret，實際 %v", err)
	}
	if _, err := store.Verify(ctx, db.SQL(), third); err != nil {
		t.Errorf("當代秘密應有效：%v", err)
	}
}
