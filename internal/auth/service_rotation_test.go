package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
)

// 這一檔釘住輪換用例（Service.RotateSession）的邊界：
//   - 授權只有「那枚秘密本身」，不看請求裡任何可自報的欄位；
//   - Root 的輪換與 root_audit 的 auth.rotate 同生同滅，普通帳戶只進執行日誌；
//   - 被拒的輪換（落後一代、已撤銷、已到期、主體失效、陌生秘密）不寫審計、不換秘密；
//   - 新舊秘密都不出現在審計的任何一欄裡。
//
// 會話層自己的語義（原子性、世代號、併發贏家）在 internal/session 的輪換測試裡，
// 這裡不重複測同一件事，只測「用例把會話層的結論對映成對外結論」這一段。

// auditFields 讀出 root_audit 全部行的可顯示欄位，供「任何一欄都不得出現秘密」的斷言。
func auditFields(t *testing.T, e *env) [][]string {
	t.Helper()
	rows, err := e.db.SQL().QueryContext(context.Background(),
		"SELECT action, target_kind, target_id, reason, request_id FROM root_audit")
	if err != nil {
		t.Fatalf("讀取審計失敗：%v", err)
	}
	defer rows.Close()
	var out [][]string
	for rows.Next() {
		var (
			action, targetKind, targetID, requestID string
			reason                                  sql.NullString
		)
		if err := rows.Scan(&action, &targetKind, &targetID, &reason, &requestID); err != nil {
			t.Fatalf("掃描審計失敗：%v", err)
		}
		out = append(out, []string{action, targetKind, targetID, reason.String, requestID})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍歷審計失敗：%v", err)
	}
	return out
}

// assertNoSecretInAudit 斷言審計的任何一欄都不含這些秘密明文。
func assertNoSecretInAudit(t *testing.T, e *env, secrets ...string) {
	t.Helper()
	for _, fields := range auditFields(t, e) {
		for _, field := range fields {
			for _, secret := range secrets {
				if secret != "" && strings.Contains(field, secret) {
					t.Errorf("審計欄位洩露了會話秘密：%q", field)
				}
			}
		}
	}
}

// readRotationFacts 讀回會話行的輪換事實（世代號與查詢鍵），判據一律是資料庫本身。
func readRotationFacts(t *testing.T, e *env, id string) (int64, string) {
	t.Helper()
	var (
		seq  int64
		hash string
	)
	if err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT rotation_seq, token_hash FROM sessions WHERE id = ?", id).Scan(&seq, &hash); err != nil {
		t.Fatalf("讀回會話行失敗：%v", err)
	}
	return seq, hash
}

// TestRotateSessionRootAuditsInSameTransaction：Root 輪換成功——換出新秘密、
// 身分與期限不變、舊秘密立刻變成「上一代」，並留下恰好一筆 auth.rotate。
func TestRotateSessionRootAuditsInSameTransaction(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	login, err := e.service.LoginRoot(ctx, testRootPassword, "req-rotate-1", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入失敗：%v", err)
	}

	outcome, err := e.service.RotateSession(ctx, login.Secret, "req-rotate-2")
	if err != nil {
		t.Fatalf("Root 輪換失敗：%v", err)
	}
	if outcome.Secret == "" || outcome.Secret == login.Secret {
		t.Error("輪換必須換出一枚不同的新秘密")
	}
	if outcome.Session.ID != login.Session.ID || outcome.Session.DeviceID != login.Session.DeviceID {
		t.Errorf("輪換不得換掉會話或設備身份：%v/%v vs %v/%v",
			outcome.Session.ID, outcome.Session.DeviceID, login.Session.ID, login.Session.DeviceID)
	}
	if !outcome.Session.ExpiresAt.Equal(login.Session.ExpiresAt) {
		t.Errorf("輪換不得延長絕對期限：%s vs %s", outcome.Session.ExpiresAt, login.Session.ExpiresAt)
	}
	if outcome.Session.RotationSeq != 1 {
		t.Errorf("世代號應為 1，實際 %d", outcome.Session.RotationSeq)
	}
	if !outcome.Principal.IsRoot() {
		t.Error("輪換後回傳的主體仍應是 Root")
	}
	if got := countSessions(t, e.db); got != 1 {
		t.Errorf("輪換不得新增會話行，實際 %d 行", got)
	}

	// 新秘密換得出同一個 Root 主體；舊秘密換不出任何主體，而且結論是「上一代」。
	if _, _, err := e.service.Resolve(ctx, outcome.Secret); err != nil {
		t.Errorf("新秘密應可解析：%v", err)
	}
	if _, _, err := e.service.Resolve(ctx, login.Secret); !errors.Is(err, ErrStaleSession) {
		t.Errorf("舊秘密應回 ErrStaleSession，實際 %v", err)
	}
	if errors.Is(mustResolveErr(t, e, ctx, login.Secret), ErrInvalidSession) {
		t.Error("落後一代不得被收斂成 ErrInvalidSession（那會讓客戶端判成登出）")
	}

	if n := countRootAudit(t, e.db, "auth.rotate"); n != 1 {
		t.Errorf("Root 輪換應留下恰好一筆 auth.rotate，實際 %d", n)
	}
	fields := auditFields(t, e)
	if len(fields) != 2 { // 一筆登入成功＋一筆輪換
		t.Fatalf("審計行數應為 2，實際 %d", len(fields))
	}
	if fields[1][2] != login.Session.ID.String() {
		t.Errorf("輪換審計的 target 應指向該會話，實際 %q", fields[1][2])
	}
	assertNoSecretInAudit(t, e, login.Secret, outcome.Secret)
}

// mustResolveErr 回傳一次解析的錯誤（斷言錯誤分類用）。
func mustResolveErr(t *testing.T, e *env, ctx context.Context, secret string) error {
	t.Helper()
	_, _, err := e.service.Resolve(ctx, secret)
	return err
}

// TestRotateSessionAccountWritesNoAudit：普通帳戶的輪換只進執行日誌，兩張審計表恆零
// （沿用已批准的判定：無角色帳戶的審計主體類別尚未落地，本步不擅自歸類）。
func TestRotateSessionAccountWritesNoAudit(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	a := e.createAccount(t, "rotate_acc", account.StatusActive)
	login, err := e.service.LoginAccount(ctx, "rotate_acc", testAccountPassword, "req-1", testSourceIP)
	if err != nil {
		t.Fatalf("帳戶登入失敗：%v", err)
	}

	outcome, err := e.service.RotateSession(ctx, login.Secret, "req-2")
	if err != nil {
		t.Fatalf("帳戶輪換失敗：%v", err)
	}
	if outcome.Principal.AccountID() != a.ID {
		t.Errorf("輪換後主體應仍是同一帳戶：%v vs %v", outcome.Principal.AccountID(), a.ID)
	}
	if outcome.Session.DeviceID != login.Session.DeviceID {
		t.Error("輪換不得換掉設備身份")
	}
	if n := countRootAudit(t, e.db, "auth.rotate"); n != 0 {
		t.Errorf("普通帳戶輪換不應寫 Root 審計，實際 %d 筆", n)
	}
	var activity int
	if err := e.db.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM activity_audit").Scan(&activity); err != nil {
		t.Fatalf("統計活動審計失敗：%v", err)
	}
	if activity != 0 {
		t.Errorf("普通帳戶輪換不應寫活動審計，實際 %d 筆", activity)
	}
	assertNoSecretInAudit(t, e, login.Secret, outcome.Secret)
}

// TestRotateSessionStaleSecretRejected：拿落後一代的秘密來輪換一律拒絕，
// 而且不得因此再換一次（那會讓舊秘密變成一條並行的認證通路）。
func TestRotateSessionStaleSecretRejected(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.createAccount(t, "rotate_stale", account.StatusActive)
	login, err := e.service.LoginAccount(ctx, "rotate_stale", testAccountPassword, "req-1", testSourceIP)
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}
	first, err := e.service.RotateSession(ctx, login.Secret, "req-2")
	if err != nil {
		t.Fatalf("首次輪換失敗：%v", err)
	}

	if _, err := e.service.RotateSession(ctx, login.Secret, "req-3"); !errors.Is(err, ErrStaleSession) {
		t.Errorf("落後一代的秘密輪換應回 ErrStaleSession，實際 %v", err)
	}
	seq, _ := readRotationFacts(t, e, first.Session.ID.String())
	if seq != 1 {
		t.Errorf("被拒的輪換不得推進世代號，實際 %d", seq)
	}
	if _, _, err := e.service.Resolve(ctx, first.Secret); err != nil {
		t.Errorf("當代秘密不應受影響：%v", err)
	}
}

// TestRotateSessionRevokedRejected：已登出（撤銷）的會話輪換不了，
// 對外結論與任何其它失效憑據同形（ErrInvalidSession），不多給一個可探測類別。
func TestRotateSessionRevokedRejected(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.createAccount(t, "rotate_revoked", account.StatusActive)
	login, err := e.service.LoginAccount(ctx, "rotate_revoked", testAccountPassword, "req-1", testSourceIP)
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}
	if err := e.service.Logout(ctx, login.Principal, login.Session, "req-2"); err != nil {
		t.Fatalf("登出失敗：%v", err)
	}
	seqBefore, hashBefore := readRotationFacts(t, e, login.Session.ID.String())

	if _, err := e.service.RotateSession(ctx, login.Secret, "req-3"); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("已撤銷會話輪換應回 ErrInvalidSession，實際 %v", err)
	}
	seq, hash := readRotationFacts(t, e, login.Session.ID.String())
	if seq != seqBefore || hash != hashBefore {
		t.Errorf("被拒的輪換不得改動會話行：seq %d→%d", seqBefore, seq)
	}
	if n := countRootAudit(t, e.db, "auth.rotate"); n != 0 {
		t.Errorf("被拒的輪換不應寫審計，實際 %d 筆", n)
	}
}

// TestRotateSessionExpiredRejected：已過絕對期限的會話輪換不了——輪換不是續期。
func TestRotateSessionExpiredRejected(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.createAccount(t, "rotate_expired", account.StatusActive)
	login, err := e.service.LoginAccount(ctx, "rotate_expired", testAccountPassword, "req-1", testSourceIP)
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}
	e.testClock(t).Advance(time.Hour + time.Minute)

	if _, err := e.service.RotateSession(ctx, login.Secret, "req-2"); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("已到期會話輪換應回 ErrInvalidSession，實際 %v", err)
	}
	if seq, _ := readRotationFacts(t, e, login.Session.ID.String()); seq != 0 {
		t.Errorf("被拒的輪換不得推進世代號，實際 %d", seq)
	}
}

// TestRotateSessionDisabledSubjectRejected：主體已被停用的會話輪換不了。
func TestRotateSessionDisabledSubjectRejected(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	a := e.createAccount(t, "rotate_disabled", account.StatusActive)
	login, err := e.service.LoginAccount(ctx, "rotate_disabled", testAccountPassword, "req-1", testSourceIP)
	if err != nil {
		t.Fatalf("登入失敗：%v", err)
	}
	if _, err := e.db.SQL().ExecContext(ctx,
		"UPDATE accounts SET status = 'disabled', disabled_at = ? WHERE id = ?",
		e.clock.Now().UnixMilli(), a.ID.String()); err != nil {
		t.Fatalf("禁用帳戶失敗：%v", err)
	}
	if _, err := e.service.RotateSession(ctx, login.Secret, "req-2"); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("主體被禁用時輪換應回 ErrInvalidSession，實際 %v", err)
	}
	if seq, _ := readRotationFacts(t, e, login.Session.ID.String()); seq != 0 {
		t.Errorf("被拒的輪換不得推進世代號，實際 %d", seq)
	}
}

// TestRotateSessionUnknownSecretRejected：一枚從來不存在的秘密輪換不了，
// 結論與「已失效」同形——不給試探者任何可區分的訊號。
func TestRotateSessionUnknownSecretRejected(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, err := e.service.RotateSession(ctx, strings.Repeat("A", 43), "req-1")
	if !errors.Is(err, ErrInvalidSession) {
		t.Errorf("陌生秘密輪換應回 ErrInvalidSession，實際 %v", err)
	}
	if errors.Is(err, ErrStaleSession) {
		t.Error("陌生秘密不得被報成「上一代」")
	}
	if got := countSessions(t, e.db); got != 0 {
		t.Errorf("被拒的輪換不得簽發任何會話，實際 %d 行", got)
	}
}

// TestRotateSessionAuditFailureRollsBack：審計寫不進去，秘密就不換。
//
// 這是「Root 域事件必須留痕」那條合同的另一半：只驗「成功時有審計」不足以證明
// 兩者同生同滅，必須讓審計那一步真的失敗一次，看會話行有沒有跟著回滾。
func TestRotateSessionAuditFailureRollsBack(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	login, err := e.service.LoginRoot(ctx, testRootPassword, "req-1", testSourceIP)
	if err != nil {
		t.Fatalf("Root 登入失敗：%v", err)
	}
	seqBefore, hashBefore := readRotationFacts(t, e, login.Session.ID.String())
	// 讓審計那一步必定失敗：表不在，INSERT 就無從落地。
	if _, err := e.db.SQL().ExecContext(ctx, "DROP TABLE root_audit"); err != nil {
		t.Fatalf("移除審計表失敗：%v", err)
	}

	if _, err := e.service.RotateSession(ctx, login.Secret, "req-2"); err == nil {
		t.Fatal("審計無法落地時輪換應失敗")
	} else if errors.Is(err, ErrInvalidSession) || errors.Is(err, ErrStaleSession) {
		t.Errorf("這是內部故障，不應被報成憑據拒絕：%v", err)
	}
	seq, hash := readRotationFacts(t, e, login.Session.ID.String())
	if seq != seqBefore || hash != hashBefore {
		t.Errorf("審計失敗時會話行必須原樣回滾：seq %d→%d", seqBefore, seq)
	}
	// 原秘密仍然有效：這次輪換等於沒有發生過。
	if _, _, err := e.service.Resolve(ctx, login.Secret); err != nil {
		t.Errorf("回滾後原秘密應仍然有效：%v", err)
	}
}
