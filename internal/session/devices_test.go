package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// 這一檔釘住「我的裝置」在倉儲層的兩件事：列舉的範圍、定向撤銷的歸屬與冪等。
// 它要防的失敗形態很具體——「列得出來卻撤不掉」或「撤掉了沒列出的東西」，
// 兩者都源自清單與撤銷各寫一套主體邊界。這一檔把兩條路釘在同一個 subjectFilter 上：
// 清單看到的裝置，正是撤銷能觸及的裝置，反過來也成立。

// deviceSecret 讀回某 device_id 對應會話的一枚可用憑據（驗證「撤銷後立即被拒」用）。
//
// 測試不該拿 mustCreate 回傳的 secret 去猜它是哪一行；按 device_id 現查 token_hash 之外
// 我們讀不到秘密明文，因此這裡改走「建立時就記下 secret」的路線，這個 helper 只做標識比對。
func mustSubjectOf(t *testing.T, p identity.Principal) Subject {
	t.Helper()
	s, err := SubjectOf(p)
	if err != nil {
		t.Fatalf("換得會話主體失敗：%v", err)
	}
	return s
}

// TestListBySubjectOnlyOwnSessions 釘住「改不動的範圍」：列舉只回本主體的會話。
//
// 兩個帳戶 + 一個 Root 各自簽發會話後，任取其一的主體列舉，只應看到自己的行，
// 且絕不會出現別的帳戶標識——查詢範圍由主體決定，請求裡沒有任何欄位能改寫它。
func TestListBySubjectOnlyOwnSessions(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()

	acctA, principalA := createAccountDirect(t, db, store.clock, "list_a")
	_, principalB := createAccountDirect(t, db, store.clock, "list_b")
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	sessA1, _ := mustCreate(t, store, db, principalA)
	clock.Advance(time.Minute) // 讓 A2 的建立時刻晚於 A1，排序斷言才不依賴並列时的 rowid 順序。
	sessA2, _ := mustCreate(t, store, db, principalA)
	sessB1, _ := mustCreate(t, store, db, principalB)
	mustCreate(t, store, db, root)

	listA, err := store.ListBySubject(ctx, db.SQL(), mustSubjectOf(t, principalA))
	if err != nil {
		t.Fatalf("列舉 A 失敗：%v", err)
	}
	if len(listA) != 2 {
		t.Fatalf("A 只該看到自己的兩行，實際 %d", len(listA))
	}
	for _, s := range listA {
		if s.Subject.AccountID() != acctA.ID {
			t.Errorf("A 的清單混進了非本帳戶的會話：%s", s.DeviceID.String())
		}
	}
	// 排序為建立時刻新到舊：後建立的那一行在前。
	if listA[0].DeviceID != sessA2.DeviceID || listA[1].DeviceID != sessA1.DeviceID {
		t.Errorf("清單未按建立時刻新到舊排序：%s / %s",
			listA[0].DeviceID.String(), listA[1].DeviceID.String())
	}

	listB, err := store.ListBySubject(ctx, db.SQL(), mustSubjectOf(t, principalB))
	if err != nil {
		t.Fatalf("列舉 B 失敗：%v", err)
	}
	if len(listB) != 1 || listB[0].DeviceID != sessB1.DeviceID {
		t.Errorf("B 的清單應只含它自己那一行，實際 %+v", listB)
	}
}

// TestListBySubjectIncludesDeadRowsWithinGrace 釘住批准的收錄範圍：
// 已撤銷、已過絕對期限但仍留在庫裡的行都要出現，狀態各自可推。
//
// 這是 R1-015 保留 cleanup_grace 的對象——剛撤銷的裝置不會憑空消失，使用者才看得到
// 「我剛剛撤掉的那一臺」。狀態是推導值（撤銷優先於到期），不在庫裡多存一個欄位。
func TestListBySubjectIncludesDeadRowsWithinGrace(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, store.clock, "dead_rows")
	subject := mustSubjectOf(t, principal)

	revoked, _ := mustCreate(t, store, db, principal)
	if _, err := store.Revoke(ctx, db.SQL(), revoked.ID); err != nil {
		t.Fatalf("撤銷失敗：%v", err)
	}
	clock.Advance(2 * time.Hour) // 讓下一行的絕對期限也走過去。
	expired, _ := mustCreate(t, store, db, principal)
	clock.Advance(2 * time.Hour) // 此刻 expired 已過 expires_at；revoked 從未被清理（沒跑 Cleanup）。

	list, err := store.ListBySubject(ctx, db.SQL(), subject)
	if err != nil {
		t.Fatalf("列舉失敗：%v", err)
	}
	if len(list) != 2 {
		t.Fatalf("兩行失效記錄在清理前都該看到，實際 %d", len(list))
	}
	byDevice := map[string]State{}
	for _, s := range list {
		byDevice[s.DeviceID.String()] = s.State(clock.Now())
	}
	if byDevice[revoked.DeviceID.String()] != StateRevoked {
		t.Errorf("被撤銷的行狀態應為 revoked，實際 %v", byDevice[revoked.DeviceID.String()])
	}
	if byDevice[expired.DeviceID.String()] != StateExpired {
		t.Errorf("過絕對期限的行狀態應為 expired，實際 %v", byDevice[expired.DeviceID.String()])
	}
}

// TestCleanupRemovesRowsFromList 對照：清理之後的行不再出現在清單裡。
//
// 這一行是「收錄失效行」那條決定的邊界——清單反映的是「還在庫裡的事實」，不是
// 「永遠的歷史」。寬限期一到、Cleanup 跑過，裝置就從清單消失，符合清理策略的語義。
func TestCleanupRemovesRowsFromList(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, store.clock, "cleaned")
	subject := mustSubjectOf(t, principal)

	sess, _ := mustCreate(t, store, db, principal)
	if _, err := store.Revoke(ctx, db.SQL(), sess.ID); err != nil {
		t.Fatalf("撤銷失敗：%v", err)
	}
	// 預設 NewStore 的清理寬限期為 0（失效即刪）：把時鐘推過到期與撤銷時刻即可被刪除。
	clock.Advance(2 * time.Hour)
	if _, err := store.Cleanup(ctx, db.SQL()); err != nil {
		t.Fatalf("清理失敗：%v", err)
	}
	list, err := store.ListBySubject(ctx, db.SQL(), subject)
	if err != nil {
		t.Fatalf("列舉失敗：%v", err)
	}
	if len(list) != 0 {
		t.Errorf("清理後清單應為空，實際 %d 行", len(list))
	}
}

// TestRevokeDeviceBySubjectScope 釘住「只能撤自己的裝置」：
// 拿别人的 device_id 來撤，與撤一枚根本不存在的裝置，收斂為同一個 ErrNotFound。
func TestRevokeDeviceBySubjectScope(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	_, principalA := createAccountDirect(t, db, store.clock, "rev_a")
	_, principalB := createAccountDirect(t, db, store.clock, "rev_b")
	subjectA := mustSubjectOf(t, principalA)

	sessB, secretB := mustCreate(t, store, db, principalB)
	unknown := identitytest.NewID(t)

	if _, _, err := store.RevokeDeviceBySubject(ctx, db.SQL(), subjectA, sessB.DeviceID); !errors.Is(err, ErrNotFound) {
		t.Errorf("撤銷他人裝置應回 ErrNotFound，實際 %v", err)
	}
	if _, _, err := store.RevokeDeviceBySubject(ctx, db.SQL(), subjectA, unknown); !errors.Is(err, ErrNotFound) {
		t.Errorf("撤銷不存在裝置應回 ErrNotFound，實際 %v", err)
	}
	// 兩者的結論逐字相同（都只是一個 ErrNotFound），沒有「存在但不屬於你」的第二種答案，
	// 因此清單之外的人無從枚舉別人的裝置標識。
	if _, err := store.Verify(ctx, db.SQL(), secretB); err != nil {
		t.Errorf("越權撤銷嘗試不得動到別人的會話：%v", err)
	}
}

// TestRevokeDeviceMarksAndRejectsSubsequent 釘住「被撤銷裝置的後續請求立即被拒」：
// 定向撤銷落地後，同一枚憑據再拿去驗證就得到 ErrRevoked。
func TestRevokeDeviceMarksAndRejectsSubsequent(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, store.clock, "rev_now")
	subject := mustSubjectOf(t, principal)

	sess, secret := mustCreate(t, store, db, principal)
	out, revoked, err := store.RevokeDeviceBySubject(ctx, db.SQL(), subject, sess.DeviceID)
	if err != nil {
		t.Fatalf("撤銷自己的裝置失敗：%v", err)
	}
	if !revoked {
		t.Error("第一次撤銷一枚有效裝置應回報『新生效』")
	}
	if out.RevokedAt.IsZero() {
		t.Error("撤銷必須寫下 revoked_at")
	}
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrRevoked) {
		t.Errorf("被撤銷裝置的憑據應立即被拒（ErrRevoked），實際 %v", err)
	}
}

// TestRevokeDeviceIdempotent 重複撤銷同一枚裝置不是錯誤：第二次回報 no-op。
func TestRevokeDeviceIdempotent(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, store.clock, "rev_twice")
	subject := mustSubjectOf(t, principal)

	sess, _ := mustCreate(t, store, db, principal)
	if _, ok, err := store.RevokeDeviceBySubject(ctx, db.SQL(), subject, sess.DeviceID); err != nil || !ok {
		t.Fatalf("第一次撤銷應成功：%v / %v", err, ok)
	}
	out, ok, err := store.RevokeDeviceBySubject(ctx, db.SQL(), subject, sess.DeviceID)
	if err != nil {
		t.Fatalf("重複撤銷應冪等成功，不得報錯：%v", err)
	}
	if ok {
		t.Error("重複撤銷不得再回報『新生效』")
	}
	if out.DeviceID != sess.DeviceID {
		t.Error("冪等撤銷仍應回傳被指向的那一行")
	}
}

// TestRevokeDeviceExpiredStillMarks 已過絕對期限但未被清理的行仍可撤銷，
// 統一走「已撤銷」這個最終態（與 Revoke 同一口徑）。
func TestRevokeDeviceExpiredStillMarks(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, store.clock, "rev_expired")
	subject := mustSubjectOf(t, principal)

	sess, _ := mustCreate(t, store, db, principal)
	clock.Advance(2 * time.Hour) // 過絕對期限，但沒跑 Cleanup，行還在。
	out, ok, err := store.RevokeDeviceBySubject(ctx, db.SQL(), subject, sess.DeviceID)
	if err != nil || !ok {
		t.Fatalf("撤銷一枚已到期未清理的行應成功：%v / %v", err, ok)
	}
	if out.State(clock.Now()) != StateRevoked {
		t.Errorf("撤銷優先於到期展示，狀態應為 revoked，實際 %v", out.State(clock.Now()))
	}
}

// TestRevokeDeviceNilIDRejected 零值裝置標識不是任何人的有效裝置：直接按查無收斂。
func TestRevokeDeviceNilIDRejected(t *testing.T) {
	db, _, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, store.clock, "rev_nil")
	if _, _, err := store.RevokeDeviceBySubject(ctx, db.SQL(), mustSubjectOf(t, principal), idgen.ID{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("零值裝置標識應回 ErrNotFound，實際 %v", err)
	}
}

// TestAnonymousPrincipalCannotBecomeSubject 是列舉/撤銷共用的第一道門：匿名主體連
// 「會話主體」都換不成，因此「列出匿名者的裝置」這種根本不存在的概念沒有通路。
// 倉儲的 subject.validate 是第二道閘（主體一旦構造就必然合法），這裡釘住源頭。
func TestAnonymousPrincipalCannotBecomeSubject(t *testing.T) {
	if _, err := SubjectOf(identitytest.Anonymous(t)); !errors.Is(err, ErrInvalidSubject) {
		t.Errorf("匿名主體不可換成會話主體，實際 %v", err)
	}
}
