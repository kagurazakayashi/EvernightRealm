package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// TestResolvePrincipalAccountRoundTrip 驗證「帳戶會話 → 帳戶主體」的換回：
// 標識與類型一致、來源保留，且主體不帶任何角色（授予來源未落地，零值是唯一正確答案）。
func TestResolvePrincipalAccountRoundTrip(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, clock, "resolve_acc")

	_, secret, err := store.Create(ctx, db.SQL(), principal)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	got, sess, err := store.ResolvePrincipal(ctx, db.SQL(), secret, identity.OriginHTTPRequest)
	if err != nil {
		t.Fatalf("解析會話失敗：%v", err)
	}
	if got.Kind() != identity.KindAccount || got.AccountID() != principal.AccountID() {
		t.Fatalf("主體不匹配：%s %v", got.Kind().String(), got.AccountID())
	}
	if got.AccountType() != account.TypeStandard {
		t.Errorf("帳戶類型應現讀為 standard，實際 %q", got.AccountType())
	}
	if len(got.Roles()) != 0 {
		t.Errorf("解析結果不可帶著角色（授予來源未落地）：%v", got.Roles())
	}
	if sess.State(clock.Now()) != StateActive {
		t.Errorf("回傳會話應為有效：%s", sess.State(clock.Now()))
	}
}

// TestResolvePrincipalRootRoundTrip 驗證 Root 會話換回的是 IsRoot 主體。
//
// 這條路之所以敢走，靠的是「Root 會話行只能由真實比對換來」的結構
// （見 identity.ResumeRootProof 的文件與結構閘）；測試把斷言釘在
// 「拿到的是能過 NeedRoot 判定的 Root 主體」上，日後誰改壞延續通路，這裡先紅。
func TestResolvePrincipalRootRoundTrip(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	root := identitytest.Root(t, identity.OriginHTTPRequest)

	_, secret, err := store.Create(ctx, db.SQL(), root)
	if err != nil {
		t.Fatalf("建立 Root 會話失敗：%v", err)
	}
	got, _, err := store.ResolvePrincipal(ctx, db.SQL(), secret, identity.OriginHTTPRequest)
	if err != nil {
		t.Fatalf("解析 Root 會話失敗：%v", err)
	}
	if !got.IsRoot() {
		t.Fatalf("應換回 Root 主體，實際 %s", got.Kind().String())
	}
	if err := identity.Authorize(got, identity.NeedRoot); err != nil {
		t.Errorf("解析出的 Root 主體應能通過 NeedRoot 判定：%v", err)
	}
	if err := identity.Authorize(got, identity.NeedAuthenticated); err != nil {
		t.Errorf("NeedAuthenticated 也應通過：%v", err)
	}
	_ = clock
}

// TestResolvePrincipalRejections 驗證解析入口原樣承接 Verify 的拒絕分類：
// 非法秘密與被撤銷的會話各自回既有錯誤，不在解析層被重新發明。
func TestResolvePrincipalRejections(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	_, principal := createAccountDirect(t, db, clock, "resolve_reject")

	_, secret, err := store.Create(ctx, db.SQL(), principal)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	if _, _, err := store.ResolvePrincipal(ctx, db.SQL(), "非法秘密", identity.OriginHTTPRequest); !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("非法秘密應得 ErrInvalidSecret，實際 %v", err)
	}

	sess, err := store.Verify(ctx, db.SQL(), secret)
	if err != nil {
		t.Fatalf("驗證失敗：%v", err)
	}
	if _, err := store.Revoke(ctx, db.SQL(), sess.ID); err != nil {
		t.Fatalf("撤銷失敗：%v", err)
	}
	if _, _, err := store.ResolvePrincipal(ctx, db.SQL(), secret, identity.OriginHTTPRequest); !errors.Is(err, ErrRevoked) {
		t.Errorf("已撤銷會話應得 ErrRevoked，實際 %v", err)
	}
}

// TestResolvePrincipalReadsLiveSubjectState 把「狀態現讀」延伸到主體換回：
// 帳戶在會話簽發後被禁用，解析一律 ErrSubjectUnavailable——會話行還在不算數。
func TestResolvePrincipalReadsLiveSubjectState(t *testing.T) {
	db, clock, store := newTestEnv(t, time.Hour)
	ctx := context.Background()
	a, principal := createAccountDirect(t, db, clock, "resolve_disabled")

	_, secret, err := store.Create(ctx, db.SQL(), principal)
	if err != nil {
		t.Fatalf("建立會話失敗：%v", err)
	}
	if _, _, err := store.ResolvePrincipal(ctx, db.SQL(), secret, identity.OriginHTTPRequest); err != nil {
		t.Fatalf("禁用前解析應成功：%v", err)
	}
	if _, err := db.SQL().ExecContext(ctx,
		"UPDATE accounts SET status='disabled', disabled_at=? WHERE id=?",
		timeutil.ToMillis(clock.Now()), a.ID.String()); err != nil {
		t.Fatalf("禁用帳戶失敗：%v", err)
	}
	if _, _, err := store.ResolvePrincipal(ctx, db.SQL(), secret, identity.OriginHTTPRequest); !errors.Is(err, ErrSubjectUnavailable) {
		t.Fatalf("禁用後解析應得 ErrSubjectUnavailable，實際 %v", err)
	}
}
