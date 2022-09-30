package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// timeHourFallback 是本套件測試倉儲的預設會話期限。
const timeHourFallback = time.Hour

// TestMigrationCreatesSessionsTable 驗證 0004 與 0005 遷移落地：版本推進到遷移集最高版、
// sessions 表、兩個列級 UNIQUE 的自動索引、普通索引與輪換時代的觸發器存在。
func TestMigrationCreatesSessionsTable(t *testing.T) {
	db, _, _ := newTestEnv(t, time.Hour)
	ctx := context.Background()

	known, err := migrate.Load()
	if err != nil {
		t.Fatalf("讀取遷移集失敗：%v", err)
	}
	maxVersion := known[len(known)-1].Version
	var version int
	if err := db.SQL().QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("讀取 schema 版本失敗：%v", err)
	}
	if version != maxVersion {
		t.Fatalf("schema 版本應為 %d，實際 %d", maxVersion, version)
	}

	for _, want := range []struct{ kind, name string }{
		{"table", "sessions"},
		{"index", "sessions_expires_at_idx"},
		{"index", "sessions_account_id_idx"},
		{"index", "sessions_previous_token_hash_idx"},
		{"trigger", "sessions_id_no_update"},
		{"trigger", "sessions_device_no_update"},
		{"trigger", "sessions_token_hash_rotation"},
		{"trigger", "sessions_rotation_seq_no_update"},
		{"trigger", "sessions_expires_at_no_update"},
	} {
		var found string
		if err := db.SQL().QueryRowContext(ctx,
			"SELECT name FROM sqlite_master WHERE type = ? AND name = ?", want.kind, want.name).Scan(&found); err != nil {
			t.Errorf("%s %s 應存在：%v", want.kind, want.name, err)
		}
	}
	// 0004 那道「device_id 與 token_hash 一起不可變」的觸發器必須確實消失：
	// 留著它，輪換那條 UPDATE 會被它先擋下，新觸發器根本沒有上場的機會。
	var stale int
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = 'sessions_security_no_update'").Scan(&stale); err != nil {
		t.Fatalf("查詢舊觸發器失敗：%v", err)
	}
	if stale != 0 {
		t.Errorf("sessions_security_no_update 應已被 0005 移除，實際存在 %d 個", stale)
	}
	// device_id 与 token_hash 用的是列级 UNIQUE：索引由 SQLite 自动创建，
	// 名称不归本迁移管，这里按数量核对「三个唯一性约束（含 TEXT 主键）都真的建了索引」。
	var uniqueIndexes int
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = 'sessions' AND name LIKE 'sqlite_autoindex_sessions_%'").Scan(&uniqueIndexes); err != nil {
		t.Fatalf("統計自動索引失敗：%v", err)
	}
	if uniqueIndexes != 3 {
		t.Errorf("主鍵＋device_id＋token_hash 應各有自動唯一索引（共 3 個），實際 %d 個", uniqueIndexes)
	}
}

// TestMigrationConstraintsRejectInvalidRows 用直写 SQL 验证数据库层的封闭性：
// 域层（internal/session）被绕过后，CHECK、UNIQUE 与外键仍然拦住每一个坏形状。
func TestMigrationConstraintsRejectInvalidRows(t *testing.T) {
	db, clock, _ := newTestEnv(t, timeHourFallback)
	ctx := context.Background()
	realAccount := identitytest.NewID(t)
	if _, err := db.SQL().ExecContext(ctx,
		`INSERT INTO accounts (id, login_name, login_name_key, display_name, password_hash,
			account_type, status, must_change_password, created_at, last_login_at, disabled_at)
		VALUES (?, ?, ?, ?, ?, 'standard', 'active', 0, ?, NULL, NULL)`,
		realAccount.String(), "constraint-probe", "constraint-probe", "約束探針", testHash,
		timeutil.ToMillis(clock.Now())); err != nil {
		t.Fatalf("植入測試帳戶失敗：%v", err)
	}
	now := timeutil.ToMillis(clock.Now())
	hash := strings.Repeat("a", tokenHashLen)
	other := strings.Repeat("b", tokenHashLen)
	device := identitytest.NewID(t)
	device2 := identitytest.NewID(t)
	sessionID := identitytest.NewID(t)

	// 先放两条合法行：Root 一条、账户一条（后续拒绝用例以它们为重复来源）。
	if _, err := db.SQL().ExecContext(ctx,
		`INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
			created_at, last_active_at, expires_at, revoked_at)
		VALUES (?, ?, ?, 'root', NULL, ?, ?, ?, NULL)`,
		sessionID.String(), device.String(), hash, now, now, now+3600_000); err != nil {
		t.Fatalf("合法 Root 行應插入成功：%v", err)
	}
	if _, err := db.SQL().ExecContext(ctx,
		`INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
			created_at, last_active_at, expires_at, revoked_at)
		VALUES (?, ?, ?, 'account', ?, ?, ?, ?, NULL)`,
		identitytest.NewID(t).String(), device2.String(), other, realAccount.String(), now, now, now+3600_000); err != nil {
		t.Fatalf("合法帳戶行應插入成功：%v", err)
	}

	rejections := []struct {
		name  string
		query string
		args  []any
		frag  string // 期望的错误关键词（防止「因无关原因失败」被当成通过）
	}{
		{
			name: "root 帶帳戶標識",
			query: `INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
				created_at, last_active_at, expires_at) VALUES (?, ?, ?, 'root', ?, ?, ?, ?)`,
			args: []any{identitytest.NewID(t).String(), identitytest.NewID(t).String(), strings.Repeat("c", tokenHashLen), realAccount.String(), now, now, now + 1000},
			frag: "CHECK",
		},
		{
			name: "account 缺帳戶標識",
			query: `INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
				created_at, last_active_at, expires_at) VALUES (?, ?, ?, 'account', NULL, ?, ?, ?)`,
			args: []any{identitytest.NewID(t).String(), identitytest.NewID(t).String(), strings.Repeat("d", tokenHashLen), now, now, now + 1000},
			frag: "CHECK",
		},
		{
			name: "未知主體類別",
			query: `INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
				created_at, last_active_at, expires_at) VALUES (?, ?, ?, 'system', NULL, ?, ?, ?)`,
			args: []any{identitytest.NewID(t).String(), identitytest.NewID(t).String(), strings.Repeat("e", tokenHashLen), now, now, now + 1000},
			frag: "CHECK",
		},
		{
			name: "幽靈帳戶外鍵",
			query: `INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
				created_at, last_active_at, expires_at) VALUES (?, ?, ?, 'account', ?, ?, ?, ?)`,
			args: []any{identitytest.NewID(t).String(), identitytest.NewID(t).String(), strings.Repeat("f", tokenHashLen), identitytest.NewID(t).String(), now, now, now + 1000},
			frag: "FOREIGN KEY",
		},
		{
			name: "查找鍵重複",
			query: `INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
				created_at, last_active_at, expires_at) VALUES (?, ?, ?, 'account', ?, ?, ?, ?)`,
			args: []any{identitytest.NewID(t).String(), identitytest.NewID(t).String(), hash, realAccount.String(), now, now, now + 1000},
			frag: "UNIQUE",
		},
		{
			name: "設備標識重複",
			query: `INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
				created_at, last_active_at, expires_at) VALUES (?, ?, ?, 'account', ?, ?, ?, ?)`,
			args: []any{identitytest.NewID(t).String(), device.String(), other, realAccount.String(), now, now, now + 1000},
			frag: "UNIQUE",
		},
		{
			name: "查找鍵長度不對",
			query: `INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
				created_at, last_active_at, expires_at) VALUES (?, ?, ?, 'account', ?, ?, ?, ?)`,
			args: []any{identitytest.NewID(t).String(), identitytest.NewID(t).String(), strings.Repeat("0", 63), realAccount.String(), now, now, now + 1000},
			frag: "CHECK",
		},
		{
			name: "到期不早於建立",
			query: `INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
				created_at, last_active_at, expires_at) VALUES (?, ?, ?, 'account', ?, ?, ?, ?)`,
			args: []any{identitytest.NewID(t).String(), identitytest.NewID(t).String(), strings.Repeat("1", tokenHashLen), realAccount.String(), now, now, now},
			frag: "CHECK",
		},
		{
			name: "最近活動不早於建立",
			query: `INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
				created_at, last_active_at, expires_at) VALUES (?, ?, ?, 'account', ?, ?, ?, ?)`,
			args: []any{identitytest.NewID(t).String(), identitytest.NewID(t).String(), strings.Repeat("2", tokenHashLen), realAccount.String(), now, now - 1, now + 1000},
			frag: "CHECK",
		},
		{
			name: "撤銷不早於建立",
			query: `INSERT INTO sessions (id, device_id, token_hash, subject_kind, account_id,
				created_at, last_active_at, expires_at, revoked_at) VALUES (?, ?, ?, 'account', ?, ?, ?, ?, ?)`,
			args: []any{identitytest.NewID(t).String(), identitytest.NewID(t).String(), strings.Repeat("3", tokenHashLen), realAccount.String(), now, now, now + 1000, now - 1},
			frag: "CHECK",
		},
	}
	for _, tc := range rejections {
		if _, err := db.SQL().ExecContext(ctx, tc.query, tc.args...); err == nil {
			t.Errorf("%s：應被資料庫拒絕", tc.name)
		} else if !strings.Contains(strings.ToUpper(err.Error()), strings.ToUpper(tc.frag)) {
			t.Errorf("%s：失敗原因應含 %q，實際 %v", tc.name, tc.frag, err)
		}
	}

	// 觸發器：身份與期限類的更新一律擋下；換查詢鍵只有「伴隨世代號加一併留下舊雜湊」
	// 這一種合法形狀（這裡每條都是繞過應用層的直寫，正是觸發器要對付的物件）。
	//
	// 拒絕原因的斷言各自盯一條觸發器的措辭，不只盯「有錯誤發生」：否則一個語法錯誤
	// 或無關約束也能讓用例變綠，而觸發器本身早已被改壞。
	otherHash := strings.Repeat("e", tokenHashLen)
	updateRejections := []struct {
		name  string
		query string
		args  []any
		frag  string
	}{
		{"改主鍵", "UPDATE sessions SET id = ? WHERE id = ?",
			[]any{identitytest.NewID(t).String(), sessionID.String()}, "不得修改"},
		{"改設備標識", "UPDATE sessions SET device_id = ? WHERE id = ?",
			[]any{identitytest.NewID(t).String(), sessionID.String()}, "不可變"},
		{"裸換查找鍵（不動世代號）", "UPDATE sessions SET token_hash = ? WHERE id = ?",
			[]any{otherHash, sessionID.String()}, "只能經輪換更新"},
		{"換查找鍵但不留舊哈希", "UPDATE sessions SET token_hash = ?, rotation_seq = rotation_seq + 1 WHERE id = ?",
			[]any{otherHash, sessionID.String()}, "只能經輪換更新"},
		// 這一條同時踩到兩道觸發器（世代號跳兩格、新雜湊也沒留舊雜湊），
		// 先跑哪一道由 SQLite 決定，因此只斷言「是世代號那條不變量擋的」。
		{"世代號一次跳兩格", "UPDATE sessions SET token_hash = ?, previous_token_hash = token_hash, rotation_seq = rotation_seq + 2 WHERE id = ?",
			[]any{otherHash, sessionID.String()}, "rotation_seq"},
		{"只動世代號不換哈希", "UPDATE sessions SET rotation_seq = rotation_seq + 1 WHERE id = ?",
			[]any{sessionID.String()}, "世代號"},
		{"改絕對期限（輪換不是續期）", "UPDATE sessions SET expires_at = expires_at + 3600000 WHERE id = ?",
			[]any{sessionID.String()}, "不可變"},
	}
	for _, tc := range updateRejections {
		if _, err := db.SQL().ExecContext(ctx, tc.query, tc.args...); err == nil {
			t.Errorf("%s：應被觸發器擋下", tc.name)
		} else if !strings.Contains(err.Error(), tc.frag) {
			t.Errorf("%s：錯誤應含 %q，實際 %v", tc.name, tc.frag, err)
		}
	}

	// 合法形狀的對照面：同一張表上，帶著世代號加一並留下舊雜湊的那條 UPDATE 必須過——
	// 少了這一句，上面的七條拒絕可能只是「寫法全都碰不得」的假象。
	legalHash := strings.Repeat("9", tokenHashLen)
	if _, err := db.SQL().ExecContext(ctx,
		"UPDATE sessions SET token_hash = ?, previous_token_hash = token_hash, "+
			"rotation_seq = rotation_seq + 1 WHERE id = ?", legalHash, sessionID.String()); err != nil {
		t.Fatalf("合法的輪換形狀應被放行：%v", err)
	}
	var (
		storedHash    string
		storedPrev    string
		storedSeq     int64
		storedExpires int64
	)
	if err := db.SQL().QueryRowContext(ctx,
		"SELECT token_hash, previous_token_hash, rotation_seq, expires_at FROM sessions WHERE id = ?",
		sessionID.String()).Scan(&storedHash, &storedPrev, &storedSeq, &storedExpires); err != nil {
		t.Fatalf("讀回輪換結果失敗：%v", err)
	}
	if storedHash != legalHash || storedSeq != 1 {
		t.Errorf("輪換後應為 hash=%s seq=%d，實際 hash=%s seq=%d", legalHash, 1, storedHash, storedSeq)
	}
	if storedPrev != hash {
		t.Errorf("previous_token_hash 應留下換代前那枚哈希，實際 %s", storedPrev)
	}
	if storedExpires != now+3600_000 {
		t.Errorf("expires_at 不可被輪換碰動，實際 %d", storedExpires)
	}

	// 外键不配 CASCADE 的另一半：带着会话的账户不允许被物理删除——
	// 「删了人还留着可验证的会话」不是数据库默认允许的写法。
	if _, err := db.SQL().ExecContext(ctx, "DELETE FROM accounts WHERE id = ?", realAccount.String()); err == nil {
		t.Error("帳戶帶有會話時 DELETE 應被外鍵擋下（未來刪除流程必須先撤銷會話）")
	} else if !strings.Contains(strings.ToUpper(err.Error()), "FOREIGN KEY") {
		t.Errorf("失敗原因應為外鍵：%v", err)
	}

	// 撤销只是写 revoked_at——那是允许的更新（触发器只锁三个安全标识）。
	if _, err := db.SQL().ExecContext(ctx, "UPDATE sessions SET revoked_at = ? WHERE id = ?", now+10, sessionID.String()); err != nil {
		t.Errorf("revoked_at 應可更新：%v", err)
	}
}

// TestScanRestoresNullRevokedAsActive 是读回路径的对照面：NULL 撤销时刻还原为
// 零值（有效），直写 revoked_at 后验证立刻按撤销拒绝——读与写没有两套答案。
func TestScanRestoresNullRevokedAsActive(t *testing.T) {
	db, clock, store := newTestEnv(t, timeHourFallback)
	ctx := context.Background()
	_, secret := mustCreate(t, store, db, identitytest.Root(t, identity.OriginHTTPRequest))
	sess, err := store.Verify(ctx, db.SQL(), secret)
	if err != nil {
		t.Fatalf("驗證失敗：%v", err)
	}
	if !sess.RevokedAt.IsZero() {
		t.Errorf("NULL revoked_at 應還原為零值，實際 %s", sess.RevokedAt)
	}
	if sess.State(clock.Now()) != StateActive {
		t.Errorf("新建會話應為 active")
	}
	// 验证撤销后的行读回带撤销时刻。
	if _, err := db.SQL().ExecContext(ctx, "UPDATE sessions SET revoked_at = ? WHERE id = ?",
		timeutil.ToMillis(clock.Now()), sess.ID.String()); err != nil {
		t.Fatalf("直寫撤銷時刻失敗：%v", err)
	}
	if _, err := store.Verify(ctx, db.SQL(), secret); !errors.Is(err, ErrRevoked) {
		t.Errorf("直寫撤銷後驗證應回 ErrRevoked，實際 %v", err)
	}
}
