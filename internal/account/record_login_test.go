package account

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// TestRecordLoginAdvancesLastLoginAt 驗證登入時刻推進並落庫、可讀回。
//
// 「何時登入成功」屬帳戶的事實，由登入用例在同一個交易呼叫本方法——
// 測試把「寫得進去、讀得回來、用的時鐘是注入的那枚」釘在一起。
func TestRecordLoginAdvancesLastLoginAt(t *testing.T) {
	store, db, createdAt := newTestStore(t)
	ctx := context.Background()

	a, err := store.Create(ctx, db.SQL(), standardInput("record_login_ok"))
	if err != nil {
		t.Fatalf("建立帳戶失敗：%v", err)
	}
	if !a.LastLoginAt.IsZero() {
		t.Fatalf("新帳戶不應帶著登入時刻：%v", a.LastLoginAt)
	}

	later := createdAt.Add(90 * time.Second)
	clockStore := NewStore(constClock{at: later})
	if err := clockStore.RecordLogin(ctx, db.SQL(), a.ID); err != nil {
		t.Fatalf("推進 last_login_at 失敗：%v", err)
	}

	got, err := store.ByID(ctx, db.SQL(), a.ID)
	if err != nil {
		t.Fatalf("讀回失敗：%v", err)
	}
	if !got.LastLoginAt.Equal(later) {
		t.Errorf("last_login_at 應為 %v，實際 %v", later, got.LastLoginAt)
	}
}

// TestRecordLoginInsideTransaction 驗證本方法收 Querier 的分工：
// 交易內回滾時 last_login_at 不留痕——登入用例靠這件事把「會話簽發」與
// 「帳戶被登入過」釘成同一件事的兩半。
func TestRecordLoginInsideTransaction(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()
	a, err := store.Create(ctx, db.SQL(), standardInput("record_login_tx"))
	if err != nil {
		t.Fatalf("建立帳戶失敗：%v", err)
	}

	boom := errors.New("測試性失敗")
	err = db.InTx(ctx, func(tctx context.Context, tx *database.Tx) error {
		if err := store.RecordLogin(tctx, tx, a.ID); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("交易應以測試性失敗結束：%v", err)
	}
	got, err := store.ByID(ctx, db.SQL(), a.ID)
	if err != nil {
		t.Fatalf("讀回失敗：%v", err)
	}
	if !got.LastLoginAt.IsZero() {
		t.Errorf("回滾後 last_login_at 應維持空：%v", got.LastLoginAt)
	}
}

// TestRecordLoginUnknownAccount 驗證找不到目標時如實回 ErrNotFound：
// 靜默成功會讓「會話已簽發但帳戶從沒被登入過」變成查不出來的幽靈狀態。
func TestRecordLoginUnknownAccount(t *testing.T) {
	store, db, _ := newTestStore(t)
	ghost, err := idgen.Parse(mustID(t))
	if err != nil {
		t.Fatalf("產生未知標識失敗：%v", err)
	}
	if err := store.RecordLogin(context.Background(), db.SQL(), ghost); !errors.Is(err, ErrNotFound) {
		t.Errorf("未知帳戶應得 ErrNotFound，實際 %v", err)
	}
	if err := store.RecordLogin(context.Background(), db.SQL(), idgen.Nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("零值標識應得 ErrNotFound，實際 %v", err)
	}
}

// constClock 為可指定時刻的測試時鐘。
type constClock struct{ at time.Time }

// Now 回傳固定時刻。
func (c constClock) Now() time.Time { return c.at }
