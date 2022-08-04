// 驗證：資料庫一致性快照的實際可取條件（開庫與寫入一律用正式程式碼，檔案判讀由外部指令碼做）。
//
// 目的：在決定「備份要採哪一種快照取法」之前，先把候選路線的行為取成實測事實而不是文件預期——
// VACUUM INTO 是否可用、是否需要對源庫的寫入鎖、服務運行中能否由另一個程序以唯讀連線完成、
// 快照是否含 WAL 裡已提交但尚未 checkpoint 的資料、檔頭標記是否隨副本一起出來、
// 快照檔能否被本服務自己的開庫流程接受。
//
// 每個子命令只測一件事，一律把觀測結果以「OBS 鍵=值」逐行印到標準輸出；
// 判讀規則（哪些值算通過）留在外層指令碼，避免「受測者自己宣佈自己通過」。
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

const (
	defaultRows        = 20000
	defaultPayloadByte = 200
	defaultBusyMS      = 3000
	// probeTable 是探針自有的資料表，用來構造「可核對的數量與連續前綴」；
	// 不借用業務表，是為了讓快照內容的判讀與業務語義無關。
	probeTable = "snapshot_probe"
)

// stampAfterMigrate 由 -stamp 設定：真實服務在遷移後會寫入檔頭識別標記，
// 快照是否把這個標記一起帶出來，決定了還原時的預檢會不會把副本當成「他人的資料庫」。
var stampAfterMigrate bool

// obs 印一行觀測值；值不截斷，因為被截斷的錯誤訊息正好是最想知道的那一段。
func obs(key string, value any) {
	fmt.Printf("OBS %s=%v\n", key, value)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法：step068-snapshot <basic|targetexists|externalwriter|readonlystandalone|serve|consistency|restore|intrx|nodir> [引數]")
		os.Exit(2)
	}
	command := os.Args[1]
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	dbPath := fs.String("db", "", "源資料庫路徑")
	into := fs.String("into", "", "快照輸出路徑")
	from := fs.String("from", "", "還原來源（快照檔）")
	rows := fs.Int("rows", defaultRows, "植入列數")
	payload := fs.Int("payload", defaultPayloadByte, "每列載重位元組數")
	busyMS := fs.Int("busy", defaultBusyMS, "busy_timeout 毫秒")
	queryOnly := fs.Bool("query-only", false, "唯讀連線加上 query_only(1)")
	seconds := fs.Int("seconds", 20, "serve 場景的持續寫入秒數")
	holdAfter := fs.Int("hold-after", 0, "操作完成後多持有連線的秒數（0=立即釋放）")
	stamp := fs.Bool("stamp", false, "遷移後寫入檔頭識別標記（與正式啟動順序一致）")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	stampAfterMigrate = *stamp
	obs("scenario", command)
	obs("stamp", *stamp)
	obs("platform", runtime.GOOS+"/"+runtime.GOARCH)
	obs("pid", os.Getpid())

	ctx := context.Background()
	var err error
	switch command {
	case "basic":
		err = scenarioBasic(ctx, *dbPath, *into, *rows, *payload, *busyMS)
	case "targetexists":
		err = scenarioTargetExists(ctx, *dbPath, *into, *rows, *payload, *busyMS)
	case "externalwriter":
		err = scenarioExternalWriter(ctx, *dbPath, *into, *rows, *payload, *busyMS)
	case "readonlystandalone":
		err = scenarioReadOnlyStandalone(*dbPath, *into, *busyMS, *queryOnly)
	case "serve":
		err = scenarioServe(ctx, *dbPath, *rows, *payload, *busyMS, *seconds)
	case "consistency":
		err = scenarioConsistency(ctx, *dbPath, *into, *rows, *payload, *busyMS)
	case "restore":
		err = scenarioRestore(ctx, *from, *dbPath, *busyMS)
	case "intrx":
		err = scenarioInTx(ctx, *dbPath, *into, *rows, *payload, *busyMS)
	case "nodir":
		err = scenarioNoDir(ctx, *dbPath, *into, *rows, *payload, *busyMS)
	default:
		err = fmt.Errorf("未知場景 %q", command)
	}
	if err != nil {
		obs("fatal", err)
		os.Exit(1)
	}
	if *holdAfter > 0 {
		// 只在指令碼需要「另一個程序此時還活著」時使用；持有期間不做事，純屬延遲釋放。
		time.Sleep(time.Duration(*holdAfter) * time.Second)
	}
}

// openOfficial 用正式開庫流程取庫（含單寫入實例鎖與預檢），並把內嵌遷移套用到最高版本。
//
// 探針刻意不自己建業務表：結構一律由本專案的遷移產生，快照才算覆蓋到真實結構。
// stamp 為真時補上檔頭識別標記，與正式啟動順序一致（遷移成功後才標記），
// 否則測到的會是「未標記的庫」，還原場景的預檢判定就對不上真實部署。
func openOfficial(ctx context.Context, path string, busyMS int, stamp bool) (*database.DB, error) {
	known, err := migrate.MaxVersion()
	if err != nil {
		return nil, err
	}
	db, err := database.Open(ctx, database.Options{
		Path:               path,
		BusyTimeout:        time.Duration(busyMS) * time.Millisecond,
		KnownSchemaVersion: known,
	})
	if err != nil {
		return nil, err
	}
	if _, err := migrate.Apply(ctx, db.SQL(), migrate.Options{Clock: timeutil.System()}); err != nil {
		_ = db.Close()
		return nil, err
	}
	if stamp {
		if err := db.StampApplicationID(ctx); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if _, err := db.SQL().ExecContext(ctx, fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s (n INTEGER PRIMARY KEY, payload TEXT NOT NULL)`, probeTable)); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// seed 以單筆交易植入 rows 列；n 從 1 起連續編號，這是「快照必須是完整前綴」那條判定的前提。
func seed(ctx context.Context, db *database.DB, rows, payloadByte int) error {
	payload := strings.Repeat("長夜幻境", payloadByte/3+1)
	return db.InTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		for n := 1; n <= rows; n++ {
			if _, err := tx.ExecContext(ctx,
				fmt.Sprintf(`INSERT INTO %s (n, payload) VALUES (?, ?)`, probeTable), n, payload); err != nil {
				return err
			}
		}
		return nil
	})
}

// stats 是源庫與 WAL 的位元組數；WalBytes 為 0 表示當下沒有 -wal 檔。
type stats struct {
	DBBytes  int64
	WalBytes int64
}

func measure(dbPath string) stats {
	s := stats{}
	if st, err := os.Stat(dbPath); err == nil {
		s.DBBytes = st.Size()
	}
	if st, err := os.Stat(dbPath + "-wal"); err == nil {
		s.WalBytes = st.Size()
	}
	return s
}

// vacuumInto 執行 VACUUM INTO，並回報實際生效的書寫形式。
//
// 先試參數綁定：綁定不成立時才退回字串字面值。生產代碼能用哪一種、
// 要不要自行加引號，取決於這裡測到的是哪一種，所以兩種都要留原文。
func vacuumInto(ctx context.Context, q database.Querier, into string) (form string, err error) {
	if _, err := q.ExecContext(ctx, `VACUUM INTO ?`, into); err == nil {
		return "bound-parameter", nil
	} else {
		bound := err
		escaped := "'" + strings.ReplaceAll(into, "'", "''") + "'"
		if _, err2 := q.ExecContext(ctx, "VACUUM INTO "+escaped); err2 != nil {
			return "neither", fmt.Errorf("綁定形式：%v；字面值形式：%v", bound, err2)
		}
		return "literal", bound
	}
}

// reportVacuum 印出快照結果與耗時；成敗以「有沒有產出可用檔案」為準，不只看回傳碼。
func reportVacuum(err error, started time.Time, into string) {
	obs("vacuum_ok", err == nil)
	obs("vacuum_elapsed_ms", time.Since(started).Milliseconds())
	if err != nil {
		obs("vacuum_err", err)
		return
	}
	obs("out_bytes", sizeOf(into))
}

func scenarioBasic(ctx context.Context, dbPath, into string, rows, payloadByte, busyMS int) error {
	if err := requireArgs(dbPath, into); err != nil {
		return err
	}
	db, err := openOfficial(ctx, dbPath, busyMS, stampAfterMigrate)
	if err != nil {
		return err
	}
	defer closeDB(db)

	if err := seed(ctx, db, rows, payloadByte); err != nil {
		return err
	}
	var ver string
	if err := db.SQL().QueryRowContext(ctx, `SELECT sqlite_version()`).Scan(&ver); err != nil {
		return err
	}
	obs("sqlite_version", ver)
	obs("rows_seeded", rows)
	before := measure(dbPath)
	obs("src_db_bytes", before.DBBytes)
	obs("src_wal_bytes", before.WalBytes)

	started := time.Now()
	form, err := vacuumInto(ctx, db.SQL(), into)
	obs("vacuum_form", form)
	reportVacuum(err, started, into)
	after := measure(dbPath)
	obs("src_db_bytes_after", after.DBBytes)
	obs("src_wal_bytes_after", after.WalBytes)
	obs("journal_mode", db.JournalMode())
	return err
}

// scenarioTargetExists 測「輸出檔已存在」時的行為：文件規則是拒絕覆蓋，
// 但拒絕的同時有沒有動過那個檔，決定生產代碼需不需要「臨時檔＋改名」。
func scenarioTargetExists(ctx context.Context, dbPath, into string, rows, payloadByte, busyMS int) error {
	if err := requireArgs(dbPath, into); err != nil {
		return err
	}
	db, err := openOfficial(ctx, dbPath, busyMS, stampAfterMigrate)
	if err != nil {
		return err
	}
	defer closeDB(db)
	if err := seed(ctx, db, rows, payloadByte); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(into), 0o755); err != nil {
		return err
	}
	sentinel := []byte("SENTINEL-CONTENT-MUST-SURVIVE")
	if err := os.WriteFile(into, sentinel, 0o644); err != nil {
		return err
	}
	digestBefore := sha256Hex(into)
	started := time.Now()
	form, err := vacuumInto(ctx, db.SQL(), into)
	obs("vacuum_form", form)
	reportVacuum(err, started, into)
	obs("target_digest_before", digestBefore)
	obs("target_digest_after", sha256Hex(into))
	obs("target_unchanged", digestBefore == sha256Hex(into))
	if err == nil {
		obs("warning", "目標已存在卻仍寫入成功——覆蓋語意與文件不同，必須記進定案")
	}
	return nil
}

// scenarioExternalWriter 測源庫被另一條連線的寫入交易佔住時，快照能不能成。
//
// 這裡用同一程序內的第二個連線池代表「另一個寫入者」：SQLite 的檔案鎖以連線與程序為單位，
// 同程序的獨立連線在鎖的層面上與另一個程序等效，但不是真的獨立程序，
// 因此判讀把這條當旁證，主證是 serve 加 readonlystandalone 那一組。
func scenarioExternalWriter(ctx context.Context, dbPath, into string, rows, payloadByte, busyMS int) error {
	if err := requireArgs(dbPath, into); err != nil {
		return err
	}
	db, err := openOfficial(ctx, dbPath, busyMS, stampAfterMigrate)
	if err != nil {
		return err
	}
	defer closeDB(db)
	if err := seed(ctx, db, rows, payloadByte); err != nil {
		return err
	}

	holder, err := sql.Open("sqlite", rawDSN(dbPath, busyMS))
	if err != nil {
		return err
	}
	defer holder.Close()
	tx, err := holder.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// 寫入一句才真的取得 RESERVED 鎖；唯讀交易在 WAL 下不擋讀者，也擋不住快照。
	if _, err := tx.ExecContext(ctx,
		fmt.Sprintf(`INSERT INTO %s (n, payload) VALUES (?, ?)`, probeTable), rows+1, "佔住寫入鎖"); err != nil {
		_ = tx.Rollback()
		return err
	}
	obs("holder_tx", "BEGIN IMMEDIATE 加 INSERT 未提交")

	started := time.Now()
	form, err := vacuumInto(ctx, db.SQL(), into)
	obs("vacuum_form", form)
	reportVacuum(err, started, into)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交占位交易失敗：%w", err)
	}
	obs("holder_committed", true)
	return nil
}

// scenarioReadOnlyStandalone 不取單寫入實例鎖，只用唯讀連線嘗試快照。
//
// 這一條回答的是交付形態上最關鍵的問題：服務還在跑的時候，
// 「備份」能不能作為另一個程序完成，而不必先停服務。
func scenarioReadOnlyStandalone(dbPath, into string, busyMS int, queryOnly bool) error {
	if err := requireArgs(dbPath, into); err != nil {
		return err
	}
	obs("query_only", queryOnly)
	ro, err := sql.Open("sqlite", readOnlyDSN(dbPath, busyMS, queryOnly))
	if err != nil {
		return err
	}
	defer ro.Close()

	// 先確認這條唯讀連線真的讀得到源庫（讀不到就別把連線失敗算到 VACUUM 頭上）。
	var n int64
	if err := ro.QueryRow(fmt.Sprintf(`SELECT count(*) FROM %s`, probeTable)).Scan(&n); err != nil {
		obs("readonly_readable", false)
		obs("readonly_read_err", err)
		return err
	}
	obs("readonly_readable", true)
	obs("readonly_visible_rows", n)

	started := time.Now()
	form, err := vacuumInto(context.Background(), ro, into)
	obs("vacuum_form", form)
	reportVacuum(err, started, into)
	return err
}

// scenarioServe 模擬「服務正在運行」：正式開庫（持鎖）後持續寫入一段時間。
// READY 行是外部指令碼的同步點，出現即代表鎖已取得、寫入已開始。
func scenarioServe(ctx context.Context, dbPath string, rows, payloadByte, busyMS, seconds int) error {
	if dbPath == "" {
		return errors.New("缺少 -db")
	}
	db, err := openOfficial(ctx, dbPath, busyMS, stampAfterMigrate)
	if err != nil {
		return err
	}
	defer closeDB(db)
	if err := seed(ctx, db, rows, payloadByte); err != nil {
		return err
	}
	fmt.Printf("READY pid=%d rows=%d\n", os.Getpid(), rows)

	payload := strings.Repeat("快照進行中的新寫入", 32)
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	n := rows
	writes := 0
	for time.Now().Before(deadline) {
		n++
		if _, err := db.SQL().ExecContext(ctx,
			fmt.Sprintf(`INSERT INTO %s (n, payload) VALUES (?, ?)`, probeTable), n, payload); err != nil {
			obs("serve_write_err", err)
			break
		}
		writes++
		time.Sleep(20 * time.Millisecond)
	}
	obs("serve_rows_total", n)
	obs("serve_writes_after_ready", writes)
	final := measure(dbPath)
	obs("serve_final_db_bytes", final.DBBytes)
	obs("serve_final_wal_bytes", final.WalBytes)
	return nil
}

// scenarioConsistency 在快照進行的同時逐筆提交寫入，檢視取出的快照是不是一個完整前綴。
//
// 這是「一致性」最直接的可判讀定義：n 連續編號，快照裡若有洞、或有任何一筆寫了一半的內容，
// 就表示快照落在某筆寫入的中間——而那正是「直接複製主檔」這條路線可能出現的結果。
func scenarioConsistency(ctx context.Context, dbPath, into string, rows, payloadByte, busyMS int) error {
	if err := requireArgs(dbPath, into); err != nil {
		return err
	}
	db, err := openOfficial(ctx, dbPath, busyMS, stampAfterMigrate)
	if err != nil {
		return err
	}
	defer closeDB(db)
	if err := seed(ctx, db, rows, payloadByte); err != nil {
		return err
	}
	obs("rows_seeded", rows)

	writer, err := sql.Open("sqlite", rawDSN(dbPath, busyMS))
	if err != nil {
		return err
	}
	defer writer.Close()

	var next atomic.Int64
	next.Store(int64(rows))
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		payload := strings.Repeat("併發寫入載重", payloadByte/6+1)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n := next.Add(1)
			if _, err := writer.ExecContext(ctx,
				fmt.Sprintf(`INSERT INTO %s (n, payload) VALUES (?, ?)`, probeTable), n, payload); err != nil {
				obs("concurrent_write_err", fmt.Errorf("n=%d: %w", n, err))
				return
			}
		}
	}()

	started := time.Now()
	time.Sleep(50 * time.Millisecond)
	form, vacErr := vacuumInto(ctx, db.SQL(), into)
	obs("vacuum_form", form)
	reportVacuum(vacErr, started, into)
	close(stop)
	<-done

	obs("rows_at_end", next.Load())
	var srcCount int64
	if err := db.SQL().QueryRowContext(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, probeTable)).Scan(&srcCount); err != nil {
		return err
	}
	obs("src_count_at_end", srcCount)
	return vacErr
}

// scenarioInTx 測「把快照放進寫入交易的回呼裡」會怎樣。
//
// 生產代碼裡最自然的錯誤寫法就是這個：備份和業務變更在同一個交易，看起來很安全。
// 實測結果決定快照能不能進交易邊界，也決定 ErrTxFinished 那類約束要不要多寫一條。
func scenarioInTx(ctx context.Context, dbPath, into string, rows, payloadByte, busyMS int) error {
	if err := requireArgs(dbPath, into); err != nil {
		return err
	}
	db, err := openOfficial(ctx, dbPath, busyMS, stampAfterMigrate)
	if err != nil {
		return err
	}
	defer closeDB(db)
	if err := seed(ctx, db, rows, payloadByte); err != nil {
		return err
	}

	inTxErr := db.InTx(ctx, func(ctx context.Context, tx *database.Tx) error {
		_, err := vacuumInto(ctx, tx, into)
		return err
	})
	obs("intrx_err", inTxErr)
	obs("intrx_snapshot_exists", sizeOf(into) > 0)
	// 交易失敗後源庫必須仍然完好且資料還在，否則這個錯誤寫法會變成資料事故。
	var n int64
	if err := db.SQL().QueryRowContext(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, probeTable)).Scan(&n); err != nil {
		return err
	}
	obs("rows_after_tx_failure", n)
	return db.CheckIntegrity(ctx)
}

// scenarioNoDir 測目標父目錄不存在時的行為：決定生產代碼需不需要先建目錄。
func scenarioNoDir(ctx context.Context, dbPath, into string, rows, payloadByte, busyMS int) error {
	if err := requireArgs(dbPath, into); err != nil {
		return err
	}
	db, err := openOfficial(ctx, dbPath, busyMS, stampAfterMigrate)
	if err != nil {
		return err
	}
	defer closeDB(db)
	if err := seed(ctx, db, rows, payloadByte); err != nil {
		return err
	}
	into = filepath.Join(filepath.Dir(into), "not-created-dir", "snap.db")
	started := time.Now()
	form, err := vacuumInto(ctx, db.SQL(), into)
	obs("vacuum_form", form)
	reportVacuum(err, started, into)
	return nil
}

// scenarioRestore 把快照檔放進一個新的位置，用正式開庫流程讀回來。
//
// 這一條判定的是「快照產物能不能被本服務自己接受」：預檢（application_id、user_version）、
// 遷移版本檢查、完整性自檢都必須對副本成立，否則備份做出來也還原不回去。
func scenarioRestore(ctx context.Context, fromPath, dbPath string, busyMS int) error {
	if fromPath == "" || dbPath == "" {
		return errors.New("restore 需要 -from 與 -db")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return err
	}
	if err := copyFile(fromPath, dbPath); err != nil {
		return err
	}
	obs("copied_bytes", sizeOf(dbPath))
	obs("copy_identical", sha256Hex(fromPath) == sha256Hex(dbPath))

	db, err := openOfficialWithoutMigrate(ctx, dbPath, busyMS)
	if err != nil {
		obs("official_open_ok", false)
		obs("official_open_err", err)
		return err
	}
	defer closeDB(db)
	obs("official_open_ok", true)
	obs("journal_mode_after_open", db.JournalMode())
	head := db.Header()
	obs("header_application_id", fmt.Sprintf("0x%08X", head.ApplicationID))
	obs("header_user_version", head.SchemaVersion)

	if err := db.CheckIntegrity(ctx); err != nil {
		obs("integrity_ok", false)
		obs("integrity_err", err)
	} else {
		obs("integrity_ok", true)
	}
	res, err := migrate.Apply(ctx, db.SQL(), migrate.Options{DryRun: true, Clock: timeutil.System()})
	if err != nil {
		obs("migrate_check_err", err)
		return err
	}
	obs("schema_version", res.FromVersion)
	obs("pending_migrations", len(res.Pending))

	for _, table := range []string{probeTable, "server_settings", "root_audit", "activity_audit", "schema_migrations"} {
		var count int64
		if err := db.SQL().QueryRowContext(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, table)).Scan(&count); err != nil {
			obs("rows_"+table, "ERR "+err.Error())
			continue
		}
		obs("rows_"+table, count)
	}
	return nil
}

// openOfficialWithoutMigrate 只走正式開庫（含鎖與預檢），不套用遷移：
// 還原驗證要看的是「副本原本的版本」，先套遷移會把這件事掩蓋掉。
func openOfficialWithoutMigrate(ctx context.Context, path string, busyMS int) (*database.DB, error) {
	known, err := migrate.MaxVersion()
	if err != nil {
		return nil, err
	}
	return database.Open(ctx, database.Options{
		Path:               path,
		BusyTimeout:        time.Duration(busyMS) * time.Millisecond,
		KnownSchemaVersion: known,
	})
}

func requireArgs(dbPath, into string) error {
	if dbPath == "" || into == "" {
		return errors.New("缺少 -db 或 -into")
	}
	return nil
}

func closeDB(db *database.DB) {
	if err := db.Close(); err != nil {
		obs("close_err", err)
	}
}

// rawDSN 產生與正式寫入池同參數的連線字串，供探針自建「第二個寫入者」。
//
// _txlock=immediate 是既有基線的一部分（DEC-002），自建連線不沿用就會測到不一樣的失敗點。
func rawDSN(path string, busyMS int) string {
	return "file:" + encodePath(path) +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		fmt.Sprintf("&_pragma=busy_timeout(%d)", busyMS) +
		"&_txlock=immediate"
}

// readOnlyDSN 產生唯讀連線字串；要不要加 query_only 由引數決定，兩者的差別就是這一條要測的東西。
func readOnlyDSN(path string, busyMS int, queryOnly bool) string {
	value := "file:" + encodePath(path) + "?mode=ro"
	if queryOnly {
		value += "&_pragma=query_only(1)"
	}
	return value + fmt.Sprintf("&_pragma=busy_timeout(%d)", busyMS) + "&_txlock=deferred"
}

// encodePath 逐段 URL 編碼，與本專案的 DSN 規則同形（路徑含空格與中文時才看得出差異）。
func encodePath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	parts := strings.Split(filepath.ToSlash(abs), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func sha256Hex(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unreadable:" + err.Error()
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "unreadable:" + err.Error()
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func sizeOf(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return st.Size()
}

func copyFile(from, to string) error {
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(to, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	return dst.Close()
}
