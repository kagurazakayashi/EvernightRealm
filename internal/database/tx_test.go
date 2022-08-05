package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 編譯期契約：*sql.DB（autocommit）與 *Tx（交易內）皆滿足 Querier，
// 因此同一組倉儲方法可同時服務兩種情境，並可在同一交易內組合多個倉儲。
var (
	_ Querier = (*sql.DB)(nil)
	_ Querier = (*Tx)(nil)
)

// 測試用倉儲：只依賴 Querier，不綁定 *sql.DB 或 *Tx。
type ledgerRepo struct{ q Querier }

// Insert 新增一筆金額。
func (r ledgerRepo) Insert(ctx context.Context, amount int64) error {
	_, err := r.q.ExecContext(ctx, "INSERT INTO ledger (amount) VALUES (?)", amount)
	return err
}

// Amounts 依序取回所有金額。
func (r ledgerRepo) Amounts(ctx context.Context) ([]int64, error) {
	rows, err := r.q.QueryContext(ctx, "SELECT amount FROM ledger ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var amounts []int64
	for rows.Next() {
		var amount int64
		if err := rows.Scan(&amount); err != nil {
			return nil, err
		}
		amounts = append(amounts, amount)
	}
	return amounts, rows.Err()
}

// Count 回傳筆數。
func (r ledgerRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.q.QueryRowContext(ctx, "SELECT count(*) FROM ledger").Scan(&count)
	return count, err
}

type noteRepo struct{ q Querier }

// Insert 新增一則備註。
func (r noteRepo) Insert(ctx context.Context, body string) error {
	_, err := r.q.ExecContext(ctx, "INSERT INTO note (body) VALUES (?)", body)
	return err
}

// Count 回傳筆數。
func (r noteRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.q.QueryRowContext(ctx, "SELECT count(*) FROM note").Scan(&count)
	return count, err
}

// openTxDB 以指定交易策略開啟測試資料庫並建立兩張表（測試結束自動關閉）。
func openTxDB(t *testing.T, policy TxPolicy, busyTimeout time.Duration, knownVersion int) *DB {
	t.Helper()
	db, err := Open(context.Background(), Options{
		Path:               filepath.Join(retryTempDir(t), "evernight.db"),
		BusyTimeout:        busyTimeout,
		KnownSchemaVersion: knownVersion,
		TxPolicy:           policy,
	})
	if err != nil {
		t.Fatalf("Open 失敗: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close 失敗: %v", err)
		}
	})
	for _, statement := range []string{
		"CREATE TABLE ledger (id INTEGER PRIMARY KEY, amount INTEGER NOT NULL)",
		"CREATE TABLE note (id INTEGER PRIMARY KEY, body TEXT NOT NULL)",
	} {
		if _, err := db.SQL().ExecContext(context.Background(), statement); err != nil {
			t.Fatalf("建立資料表失敗（%s）: %v", statement, err)
		}
	}
	return db
}

// rawPool 以驅動層直接開啟獨立連線池（不取單寫入鎖、不使用本套件的交易封裝），
// 用於模擬「另一個寫入者」與「交易進行中的外部提交」。
func rawPool(t *testing.T, path string, busyTimeout time.Duration) *sql.DB {
	t.Helper()
	pool, err := sql.Open("sqlite", dsn(path, busyTimeout, BeginImmediate))
	if err != nil {
		t.Fatalf("建立外部連線池失敗: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

// wantAmounts 比對帳本內容（順序敏感）。
func wantAmounts(t *testing.T, ctx context.Context, q Querier, want ...int64) {
	t.Helper()
	got, err := ledgerRepo{q}.Amounts(ctx)
	if err != nil {
		t.Fatalf("讀取帳本失敗: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("帳本內容應為 %v，實際 %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("帳本內容應為 %v，實際 %v", want, got)
		}
	}
}

func TestInTxCommitsMultipleRepositoriesTogether(t *testing.T) {
	// 服務層能在同一交易內呼叫多個倉儲，且提交後外部可見。
	ctx := context.Background()
	db := openTxDB(t, TxPolicy{Nested: NestedReject}, 2*time.Second, 0)

	// autocommit：同一組倉儲方法直接掛在 *sql.DB 上（不需交易）。
	if err := (ledgerRepo{db.SQL()}).Insert(ctx, 1); err != nil {
		t.Fatalf("autocommit 寫入失敗: %v", err)
	}

	err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
		ledger, note := ledgerRepo{tx}, noteRepo{tx}
		if err := ledger.Insert(ctx, 10); err != nil {
			return err
		}
		if err := note.Insert(ctx, "同一交易內的兩個倉儲"); err != nil {
			return err
		}
		// 交易內可見彼此尚未提交的變更。
		if count, err := ledger.Count(ctx); err != nil || count != 2 {
			return fmt.Errorf("交易內帳本筆數應為 2，實際 %d（%v）", count, err)
		}
		if count, err := note.Count(ctx); err != nil || count != 1 {
			return fmt.Errorf("交易內備註筆數應為 1，實際 %d（%v）", count, err)
		}
		if tx.ReadOnly() || tx.Depth() != 0 || tx.Savepoint() != "" {
			return fmt.Errorf("頂層寫入交易狀態不符：readonly=%v depth=%d savepoint=%q",
				tx.ReadOnly(), tx.Depth(), tx.Savepoint())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("InTx 失敗: %v", err)
	}

	wantAmounts(t, ctx, db.SQL(), 1, 10)
	if count, err := (noteRepo{db.SQL()}).Count(ctx); err != nil || count != 1 {
		t.Fatalf("提交後備註筆數應為 1，實際 %d（%v）", count, err)
	}
}

func TestInTxRollsBackWholeTransactionOnError(t *testing.T) {
	// 回呼回傳錯誤時整體回滾，兩個倉儲的寫入一併消失。
	ctx := context.Background()
	db := openTxDB(t, TxPolicy{Nested: NestedReject}, 2*time.Second, 0)
	errBoom := errors.New("業務規則不成立")

	err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
		ledger, note := ledgerRepo{tx}, noteRepo{tx}
		if err := ledger.Insert(ctx, 100); err != nil {
			return err
		}
		if err := note.Insert(ctx, "將被回滾"); err != nil {
			return err
		}
		if count, err := ledger.Count(ctx); err != nil || count != 1 {
			return fmt.Errorf("交易內應看得到自己的寫入，實際 %d（%v）", count, err)
		}
		return errBoom
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("InTx 應回傳回呼的錯誤，實際 %v", err)
	}

	wantAmounts(t, ctx, db.SQL())
	if count, err := (noteRepo{db.SQL()}).Count(ctx); err != nil || count != 0 {
		t.Fatalf("回滾後備註筆數應為 0，實際 %d（%v）", count, err)
	}
	// 回滾後連線仍可正常使用（未殘留進行中的交易）。
	if err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
		return (ledgerRepo{tx}).Insert(ctx, 7)
	}); err != nil {
		t.Fatalf("回滾後的下一筆交易應成功: %v", err)
	}
	wantAmounts(t, ctx, db.SQL(), 7)
}

func TestInTxRollsBackOnPanicAndRepanics(t *testing.T) {
	// 回呼 panic 也要整體回滾，且 panic 必須繼續往外拋（不可被吞掉）。
	ctx := context.Background()
	db := openTxDB(t, TxPolicy{Nested: NestedReject}, 2*time.Second, 0)

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_ = db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			if err := (ledgerRepo{tx}).Insert(ctx, 55); err != nil {
				return err
			}
			panic("回呼爆炸")
		})
	}()
	if recovered != "回呼爆炸" {
		t.Fatalf("panic 應原樣往外拋，實際 %v", recovered)
	}

	wantAmounts(t, ctx, db.SQL())
	if err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
		return (ledgerRepo{tx}).Insert(ctx, 8)
	}); err != nil {
		t.Fatalf("panic 回滾後的下一筆交易應成功: %v", err)
	}
	wantAmounts(t, ctx, db.SQL(), 8)
}

func TestInTxNestedPolicies(t *testing.T) {
	// 嵌套策略：reject（拒絕）、savepoint（內層獨立回滾）、reuse（加入外層）。
	ctx := context.Background()
	errInner := errors.New("內層失敗")

	t.Run("reject 拒絕嵌套且不外洩內層寫入", func(t *testing.T) {
		db := openTxDB(t, TxPolicy{Nested: NestedReject}, 2*time.Second, 0)
		err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			if err := (ledgerRepo{tx}).Insert(ctx, 1); err != nil {
				return err
			}
			inner := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
				return (ledgerRepo{tx}).Insert(ctx, 2)
			})
			if !errors.Is(inner, ErrTxNested) {
				return fmt.Errorf("內層應被拒絕並回報 ErrTxNested，實際 %v", inner)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("外層交易應成功: %v", err)
		}
		wantAmounts(t, ctx, db.SQL(), 1)
	})

	t.Run("savepoint 內層回滾而外層照常提交", func(t *testing.T) {
		db := openTxDB(t, TxPolicy{Nested: NestedSavepoint}, 2*time.Second, 0)
		err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			if err := (ledgerRepo{tx}).Insert(ctx, 1); err != nil {
				return err
			}
			inner := db.InTx(ctx, func(ctx context.Context, inner *Tx) error {
				if inner.Depth() != 1 || inner.Savepoint() == "" {
					return fmt.Errorf("內層應為深度 1 且帶儲存點，實際 depth=%d savepoint=%q",
						inner.Depth(), inner.Savepoint())
				}
				if err := (ledgerRepo{inner}).Insert(ctx, 2); err != nil {
					return err
				}
				return errInner
			})
			if !errors.Is(inner, errInner) {
				return fmt.Errorf("內層錯誤應原樣回報，實際 %v", inner)
			}
			// 內層已回滾，外層仍可繼續使用同一交易。
			return (ledgerRepo{tx}).Insert(ctx, 3)
		})
		if err != nil {
			t.Fatalf("外層交易應成功: %v", err)
		}
		wantAmounts(t, ctx, db.SQL(), 1, 3)
	})

	t.Run("reuse 內層加入外層交易", func(t *testing.T) {
		db := openTxDB(t, TxPolicy{Nested: NestedReuse}, 2*time.Second, 0)
		err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			if err := (ledgerRepo{tx}).Insert(ctx, 1); err != nil {
				return err
			}
			// 內層失敗不自動回滾（沒有儲存點），由外層決定整體結果：
			// 此處外層選擇忽略錯誤繼續提交，故內層的 2 會一起被提交。
			_ = db.InTx(ctx, func(ctx context.Context, inner *Tx) error {
				if err := (ledgerRepo{inner}).Insert(ctx, 2); err != nil {
					return err
				}
				return errInner
			})
			return nil
		})
		if err != nil {
			t.Fatalf("外層交易應成功: %v", err)
		}
		wantAmounts(t, ctx, db.SQL(), 1, 2)
	})
}

func TestInTxAfterEndedTransaction(t *testing.T) {
	// 交易結束後再使用同一個 Tx（或把交易 ctx 帶到交易外）必須被拒絕。
	ctx := context.Background()
	db := openTxDB(t, TxPolicy{Nested: NestedReject}, 2*time.Second, 0)

	var (
		escapedTx  *Tx
		escapedCtx context.Context
	)
	if err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
		escapedTx, escapedCtx = tx, ctx
		return (ledgerRepo{tx}).Insert(ctx, 1)
	}); err != nil {
		t.Fatalf("InTx 失敗: %v", err)
	}

	if _, err := escapedTx.ExecContext(ctx, "INSERT INTO ledger (amount) VALUES (2)"); !errors.Is(err, ErrTxFinished) {
		t.Errorf("結束後的 ExecContext 應回報 ErrTxFinished，實際 %v", err)
	}
	if _, err := escapedTx.QueryContext(ctx, "SELECT count(*) FROM ledger"); !errors.Is(err, ErrTxFinished) {
		t.Errorf("結束後的 QueryContext 應回報 ErrTxFinished，實際 %v", err)
	}
	var count int
	if err := escapedTx.QueryRowContext(ctx, "SELECT count(*) FROM ledger").Scan(&count); !errors.Is(err, ErrTxFinished) {
		t.Errorf("結束後的 QueryRowContext 應於 Scan 回報 ErrTxFinished，實際 %v", err)
	}
	if err := db.InTx(escapedCtx, func(context.Context, *Tx) error { return nil }); !errors.Is(err, ErrTxFinished) {
		t.Errorf("把交易 ctx 帶到交易外使用應回報 ErrTxFinished，實際 %v", err)
	}
	// 交易期間的資料仍正常提交，未被上述誤用影響。
	wantAmounts(t, ctx, db.SQL(), 1)

	// 零值 Tx 的存取子不得 panic，且誤用時同樣回報 ErrTxFinished。
	var zero *Tx
	if zero.ReadOnly() || zero.Depth() != 0 || zero.Savepoint() != "" {
		t.Errorf("零值 Tx 的存取子應回報零值")
	}
	if err := zero.QueryRowContext(ctx, "SELECT 1").Scan(&count); !errors.Is(err, ErrTxFinished) {
		t.Errorf("零值 Tx 應回報 ErrTxFinished，實際 %v", err)
	}
}

func TestInTxReadOnlyRejectsWritesAndKeepsSnapshot(t *testing.T) {
	// 唯讀交易：走實體唯讀連線（寫入必失敗），且交易期間外部提交不影響本交易的快照。
	ctx := context.Background()
	db := openTxDB(t, TxPolicy{Nested: NestedReject}, 2*time.Second, 0)
	if err := (ledgerRepo{db.SQL()}).Insert(ctx, 1); err != nil {
		t.Fatalf("前置寫入失敗: %v", err)
	}
	outsider := rawPool(t, db.Path(), 2*time.Second)

	err := db.InTxReadOnly(ctx, func(ctx context.Context, tx *Tx) error {
		if !tx.ReadOnly() {
			return errors.New("唯讀交易的 ReadOnly 應為 true")
		}
		if _, err := (ledgerRepo{tx}).Amounts(ctx); err != nil {
			return err
		}
		if err := (ledgerRepo{tx}).Insert(ctx, 99); err == nil {
			return errors.New("唯讀交易內的寫入應失敗")
		}
		first, err := (ledgerRepo{tx}).Count(ctx)
		if err != nil {
			return err
		}
		if _, err := outsider.ExecContext(ctx, "INSERT INTO ledger (amount) VALUES (50)"); err != nil {
			return fmt.Errorf("外部寫入失敗: %v", err)
		}
		second, err := (ledgerRepo{tx}).Count(ctx)
		if err != nil {
			return err
		}
		if first != second {
			return fmt.Errorf("唯讀交易內兩次讀取應一致（快照），實際 %d → %d", first, second)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("InTxReadOnly 失敗: %v", err)
	}

	// 交易結束後，外部提交的資料在正常連線上可見；唯讀交易內的寫入未被寫入。
	wantAmounts(t, ctx, db.SQL(), 1, 50)
}

func TestInTxTimeoutRollsBackAndMarksError(t *testing.T) {
	// 交易期限：逾時整體回滾，並以 ErrTxTimeout 標記（含「回呼已返回、期限在提交前到」的情況）。
	ctx := context.Background()
	t.Run("回呼因逾時失敗", func(t *testing.T) {
		db := openTxDB(t, TxPolicy{Nested: NestedReject, Timeout: 80 * time.Millisecond}, 2*time.Second, 0)
		err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			if err := (ledgerRepo{tx}).Insert(ctx, 1); err != nil {
				return err
			}
			<-ctx.Done()
			return ctx.Err()
		})
		if !errors.Is(err, ErrTxTimeout) {
			t.Fatalf("逾時應回報 ErrTxTimeout，實際 %v", err)
		}
		wantAmounts(t, ctx, db.SQL())
		if err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			return (ledgerRepo{tx}).Insert(ctx, 2)
		}); err != nil {
			t.Fatalf("逾時回滾後的下一筆交易應成功: %v", err)
		}
		wantAmounts(t, ctx, db.SQL(), 2)
	})

	t.Run("回呼成功但期限在提交前到期", func(t *testing.T) {
		db := openTxDB(t, TxPolicy{Nested: NestedReject, Timeout: 80 * time.Millisecond}, 2*time.Second, 0)
		err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			if err := (ledgerRepo{tx}).Insert(ctx, 3); err != nil {
				return err
			}
			<-ctx.Done()
			return nil
		})
		if !errors.Is(err, ErrTxTimeout) {
			t.Fatalf("期限已過時不得提交，應回報 ErrTxTimeout，實際 %v", err)
		}
		wantAmounts(t, ctx, db.SQL())
		if err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			return (ledgerRepo{tx}).Insert(ctx, 4)
		}); err != nil {
			t.Fatalf("逾時回滾後的下一筆交易應成功: %v", err)
		}
		wantAmounts(t, ctx, db.SQL(), 4)
	})
}

func TestInTxBusyLockWithoutRetryFailsBeforeCallback(t *testing.T) {
	// 忙鎖（busy_retry_max=0）：交易開始前即失敗，回呼完全不執行，也不留下寫入。
	ctx := context.Background()
	db := openTxDB(t, TxPolicy{Nested: NestedReject}, 200*time.Millisecond, 0)
	holder := rawPool(t, db.Path(), time.Second)
	holderTx, err := holder.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("外部交易開始失敗: %v", err)
	}
	if _, err := holderTx.ExecContext(ctx, "INSERT INTO ledger (amount) VALUES (1000)"); err != nil {
		t.Fatalf("外部寫入失敗: %v", err)
	}

	callbackRan := false
	err = db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
		callbackRan = true
		return (ledgerRepo{tx}).Insert(ctx, 1)
	})
	if err == nil {
		t.Fatal("另一個寫入者持有寫入鎖時，交易應失敗")
	}
	if !IsBusyError(err) {
		t.Fatalf("錯誤應判定為忙鎖（SQLITE_BUSY/LOCKED），實際 %v", err)
	}
	if callbackRan {
		t.Error("BEGIN IMMEDIATE 失敗於交易開始前，回呼不應被執行")
	}
	_ = holderTx.Rollback()
	wantAmounts(t, ctx, db.SQL())
}

func TestInTxBusyRetryRunsCallbackOnlyOnSuccessfulAttempt(t *testing.T) {
	// busy_retry_max>0：重試整個交易；因 BEGIN IMMEDIATE 的失敗點固定於回呼之前，
	// 回呼只會在真正拿到寫入鎖的那一次被執行一次。
	ctx := context.Background()
	db := openTxDB(t, TxPolicy{
		Nested:           NestedReject,
		BusyRetryMax:     20,
		BusyRetryBackoff: 50 * time.Millisecond,
	}, 100*time.Millisecond, 0)

	holder := rawPool(t, db.Path(), time.Second)
	holderTx, err := holder.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("外部交易開始失敗: %v", err)
	}
	if _, err := holderTx.ExecContext(ctx, "INSERT INTO ledger (amount) VALUES (1000)"); err != nil {
		t.Fatalf("外部寫入失敗: %v", err)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(400 * time.Millisecond)
		_ = holderTx.Rollback()
		close(released)
	}()

	calls := 0
	start := time.Now()
	err = db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
		calls++
		return (ledgerRepo{tx}).Insert(ctx, 1)
	})
	<-released
	if err != nil {
		t.Fatalf("外部鎖釋放後重試應成功: %v（耗時 %v）", err, time.Since(start).Round(time.Millisecond))
	}
	if calls != 1 {
		t.Fatalf("回呼只應執行 1 次（失敗發生於交易開始前），實際 %d 次", calls)
	}
	wantAmounts(t, ctx, db.SQL(), 1)
}

func TestInTxSchemaGuardAtTransactionBoundary(t *testing.T) {
	// schema_guard=transaction：寫入交易在回呼執行前複驗版本，不符即拒絕；
	// startup（預設）只在啟動時把關，交易邊界不複驗。
	ctx := context.Background()
	setVersion := func(t *testing.T, db *DB, version int) {
		t.Helper()
		if _, err := db.SQL().ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
			t.Fatalf("設定檔頭版本失敗: %v", err)
		}
	}

	t.Run("transaction 把關", func(t *testing.T) {
		db := openTxDB(t, TxPolicy{Nested: NestedReject, GuardSchema: true}, 2*time.Second, 1)
		setVersion(t, db, 1)
		if err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			return (ledgerRepo{tx}).Insert(ctx, 1)
		}); err != nil {
			t.Fatalf("版本相符時交易應成功: %v", err)
		}

		setVersion(t, db, 2)
		callbackRan := false
		err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			callbackRan = true
			return (ledgerRepo{tx}).Insert(ctx, 2)
		})
		if !errors.Is(err, ErrSchemaTooNew) {
			t.Fatalf("較新版本應於交易邊界被拒絕並回報 ErrSchemaTooNew，實際 %v", err)
		}
		if callbackRan {
			t.Error("把關失敗時回呼不應被執行")
		}

		setVersion(t, db, 0)
		if err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			return (ledgerRepo{tx}).Insert(ctx, 3)
		}); !errors.Is(err, ErrSchemaBehind) {
			t.Fatalf("較舊版本應於交易邊界被拒絕並回報 ErrSchemaBehind，實際 %v", err)
		}

		// 唯讀交易不寫入，故即使在版本不符時仍可讀取。
		setVersion(t, db, 2)
		if err := db.InTxReadOnly(ctx, func(ctx context.Context, tx *Tx) error {
			_, err := (ledgerRepo{tx}).Count(ctx)
			return err
		}); err != nil {
			t.Fatalf("唯讀交易不應受 schema 把關影響: %v", err)
		}

		// 被拒絕的交易不得留下任何寫入。
		setVersion(t, db, 1)
		wantAmounts(t, ctx, db.SQL(), 1)
	})

	t.Run("startup 預設不在交易邊界把關", func(t *testing.T) {
		db := openTxDB(t, TxPolicy{Nested: NestedReject}, 2*time.Second, 1)
		setVersion(t, db, 2)
		if err := db.InTx(ctx, func(ctx context.Context, tx *Tx) error {
			return (ledgerRepo{tx}).Insert(ctx, 1)
		}); err != nil {
			t.Fatalf("預設（startup）不在交易邊界把關，交易應成功: %v", err)
		}
		wantAmounts(t, ctx, db.SQL(), 1)
	})
}

// fakeSQLiteError 模擬驅動的 *sqlite.Error（帶結果碼），用於驗證忙鎖判定。
type fakeSQLiteError struct {
	code int
}

func (e fakeSQLiteError) Error() string { return fmt.Sprintf("sqlite error %d", e.code) }
func (e fakeSQLiteError) Code() int     { return e.code }

func TestIsBusyErrorClassifiesDriverCodes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"一般錯誤", errors.New("no such table"), false},
		{"SQLITE_BUSY", fakeSQLiteError{code: 5}, true},
		{"SQLITE_LOCKED", fakeSQLiteError{code: 6}, true},
		{"SQLITE_BUSY 擴充碼", fakeSQLiteError{code: 5 | (1 << 8)}, true},
		{"SQLITE_LOCKED 擴充碼", fakeSQLiteError{code: 6 | (2 << 8)}, true},
		{"其他結果碼", fakeSQLiteError{code: 19}, false},
		{"訊息後備：database is locked", errors.New("database is locked"), true},
		{"訊息後備：table is locked", errors.New("database table is locked"), true},
		{"包裝後的忙鎖", fmt.Errorf("交易無法開始: %w", fakeSQLiteError{code: 5}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsBusyError(tc.err); got != tc.want {
				t.Errorf("IsBusyError(%v) 應為 %v，實際 %v", tc.err, tc.want, got)
			}
		})
	}
}

func TestTxPolicyParsingAndSummary(t *testing.T) {
	// 組態值 ↔ 策略列舉；摘要字串供啟動輸出（含 schema_guard 層級）。
	if mode, err := ParseBeginMode("immediate"); err != nil || mode != BeginImmediate {
		t.Errorf("immediate 應解析為 BeginImmediate，實際 %v（%v）", mode, err)
	}
	if mode, err := ParseBeginMode("deferred"); err != nil || mode != BeginDeferred {
		t.Errorf("deferred 應解析為 BeginDeferred，實際 %v（%v）", mode, err)
	}
	if _, err := ParseBeginMode("exclusive"); err == nil {
		t.Error("不認識的 BEGIN 模式應報錯")
	}
	if nested, err := ParseNestedPolicy("savepoint"); err != nil || nested != NestedSavepoint {
		t.Errorf("savepoint 應解析為 NestedSavepoint，實際 %v（%v）", nested, err)
	}
	if _, err := ParseNestedPolicy("merge"); err == nil {
		t.Error("不認識的嵌套策略應報錯")
	}

	policy := TxPolicy{
		BeginMode:        BeginDeferred,
		Nested:           NestedSavepoint,
		BusyRetryMax:     2,
		BusyRetryBackoff: 25 * time.Millisecond,
		Timeout:          3 * time.Second,
		GuardSchema:      true,
	}
	want := "begin_mode=deferred nested=savepoint busy_retry_max=2 busy_retry_backoff_ms=25 timeout_ms=3000 schema_guard=transaction"
	if got := policy.String(); got != want {
		t.Errorf("策略摘要應為 %q，實際 %q", want, got)
	}
	if got := (TxPolicy{}).SchemaGuard(); got != "startup" {
		t.Errorf("零值策略的 schema_guard 應為 startup，實際 %q", got)
	}

	// BEGIN 模式經 DSN 的 _txlock 傳給驅動（實證見 tools/verify/step041-tx）。
	if dsn := dsn("db.sqlite", time.Second, BeginDeferred); !strings.Contains(dsn, "_txlock=deferred") {
		t.Errorf("deferred 策略的 DSN 應帶 _txlock=deferred，實際 %q", dsn)
	}
	if dsn := dsn("db.sqlite", time.Second, BeginImmediate); !strings.Contains(dsn, "_txlock=immediate") {
		t.Errorf("immediate 策略的 DSN 應帶 _txlock=immediate，實際 %q", dsn)
	}
}

func TestInTxRejectsInvalidUsage(t *testing.T) {
	ctx := context.Background()
	db := openTxDB(t, TxPolicy{Nested: NestedReject}, 2*time.Second, 0)

	if err := db.InTx(ctx, nil); err == nil || !strings.Contains(err.Error(), "不可為空") {
		t.Errorf("空回呼應被拒絕，實際 %v", err)
	}
	if err := db.InTxReadOnly(ctx, nil); err == nil || !strings.Contains(err.Error(), "不可為空") {
		t.Errorf("空回呼應被拒絕（唯讀），實際 %v", err)
	}

	var closed *DB
	if err := closed.InTx(ctx, func(context.Context, *Tx) error { return nil }); err == nil {
		t.Error("零值 DB 應回報資料庫未開啟")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("關閉失敗: %v", err)
	}
	if err := db.InTx(ctx, func(context.Context, *Tx) error { return nil }); err == nil {
		t.Error("已關閉的資料庫應拒絕開交易")
	}
}
