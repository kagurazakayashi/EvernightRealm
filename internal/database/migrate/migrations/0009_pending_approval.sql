-- 待審批自註冊的兩個帳戶狀態：status 新增 'pending' 與 'rejected'，並留下「審核決定的時刻」。
--
-- 本步的邊界由用戶批準（R2-012）：approval 模式下匿名自註冊建的是一筆「等待管理員審批」的帳戶——
-- 它從出生起就是一個穩定的 Account 身份（有自己的標識、佔住登入名），但既不能登入也不能經任何
-- 既有通路被當成一筆可打理的普通帳戶；申請人只能憑自己的憑據查本人的申請結果。審批的處理
-- （誰批准、誰拒絕、以什麼依據）屬下一步，本支遷移只把「這件事在資料層有沒有合法形態」定下來。
--
-- 為什麼落在 accounts.status 而不是另一張申請表（用戶批准的「統一帳戶模型」）：
--   申請人一旦提交就得到一個穩定標識，日後審批通過不需要「從申請行搬成帳戶行」這種身份遷移，
--   審計與其他實際存在的參照從第一天起指的就是同一個人。反過來，另建一張 registration_requests
--   會讓登入名的唯一性橫跨兩張表（申請佔名與帳戶佔名各有一套查重，批准時仍可能撞既有帳戶），
--   並且在同一個伺服器裡留下兩個身份來源。
--
-- 為什麼是 status 加值而不是另開一個 approval_state 欄：
--   現行的登入能力判定全是一條方向的閘——internal/auth 的登入、internal/identity 的主體成形、
--   internal/session 的簽發與逐請求解析，都寫成「status 不是 active 就拒絕」。把待審批做成一個
--   status 取值，這些閘門一個字都不用改就自動把待審批者擋在門外（安全預設來自既有形狀，
--   不是來自新加的分支）；而另開一個欄位就必須指望「每個讀帳戶的人都記得再多問一欄」，
--   那正是後到的人最容易漏問的那種規則。
--
-- 為什麼必須連 sessions 與 account_server_roles 一起重建（理由與 0007 同源，不是風格問題）：
--   status 的 CHECK 是表內約束，SQLite 無法就地放寬，只能重建 accounts 整張表；
--   而遷移器把每支遷移放在單一交易裡執行，交易期間無法改 `PRAGMA foreign_keys`，
--   開啟外鍵時 DROP 一張「仍有子行參照」的父表會做隱式 DELETE 並觸發外鍵檢查。
--   因此順序仍是：先把兩張子表重建為參照新表，舊 accounts 再也沒有子行參照，此時 DROP 它才合法；
--   新表正名為 accounts 後，SQLite（3.25 起）會把子表的 REFERENCES 子句一起改寫。
--   同樣地，正文寫著 `FROM accounts ...` 的觸發器一律等父表正名完成後最後重建，
--   否則正名之後正文仍指向已不存在的名字。
--
-- reviewed_at 這一欄負責的是「這筆帳戶走過審批」這個事實本身：
--   pending 必為 NULL（還沒有人做過決定）；rejected 必非 NULL；
--   批准是把 status 從 pending 改成 active 的那一跳，同一跳把時刻寫進 reviewed_at，
--   於是此後不論他被停用還是刪除，「他當初是被批准進來的」都查得到——
--   受限狀態查詢通路據此才能把「已批准」與「開放自註冊直接建成」分開講，
--   而不是對一個剛被批准的人說「你不是待審批申請」。
--   沒有審核人欄、也沒有審核備註欄：審核人是誰屬 root_audit 的事實（actor 由受信主體換得），
--   而自由文本不進資料庫層（與 R2-003「請求不帶原因文本」同一口徑）。
--
-- 資料搬移的形態：status、disabled_at、deleted_at、login_name、login_name_key 逐字保留，
--   reviewed_at 對既有每一行都是 NULL（他們都沒經過審批——這是事實的還原，不是回填）。
--   其餘 CHECK、觸發器與索引逐字承接 0003／0004／0005／0006／0007 的現狀，不順手加寬也不順手加嚴。
--
-- 交易末尾的守衛與 0007 同形：重建之後逐條查證兩張子表都沒有孤兒子行，
--   任何一條對不上就讓 CHECK 失敗、整支遷移回滾、資料庫停在原版本。
--
-- 時間戳與標識約定不變（DEC-011／DEC-014）：Unix 毫秒 UTC、TEXT 36 字元小寫正規 UUIDv7。

-- 1) 新帳戶表：先以暫名建好並搬入既有行（尚未動任何舊表）。
CREATE TABLE accounts_pendingapproval (
    id                   TEXT PRIMARY KEY CHECK (length(id) = 36),
    login_name           TEXT NOT NULL CHECK (length(login_name) BETWEEN 1 AND 64),
    login_name_key       TEXT NOT NULL CHECK (length(login_name_key) BETWEEN 1 AND 200),
    display_name         TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 64),
    -- 憑據雜湊的取值規則與 0003 相同。待審批帳戶帶著自己選的口令雜湊是這張表的本來形態：
    -- 「口令是本人自選的」與「還沒獲准登入」是兩件獨立的事，後者由 status 表達，
    -- 不需要（也不該）把憑據留到批准時才落庫——那時口令明文早就不在了。
    password_hash        TEXT CHECK (password_hash IS NULL OR length(password_hash) BETWEEN 1 AND 512),
    account_type         TEXT NOT NULL CHECK (account_type IN ('standard', 'guest')),
    -- 五個狀態的登入能力只有一條正向規則：只有 active 可登入。
    -- pending（待審批）與 rejected（已拒絕）都落在這條規則之外，因此既有的一切閘門
    -- （登入、主體成形、會話簽發與解析）不需改動即自動拒絶它們。
    -- 鏈的形狀：pending → active（批准，帶 reviewed_at）／pending → rejected（拒絕，帶 reviewed_at）；
    -- active ⇄ disabled → deleted 那三段屬既有通路，本步不動。
    status               TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'deleted', 'pending', 'rejected')),
    must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1)),
    created_at           INTEGER NOT NULL CHECK (created_at > 0),
    last_login_at        INTEGER CHECK (last_login_at IS NULL OR last_login_at > 0),
    disabled_at          INTEGER CHECK (disabled_at IS NULL OR disabled_at > 0),
    deleted_at           INTEGER CHECK (deleted_at IS NULL OR deleted_at > 0),
    -- reviewed_at：審核做出決定的時刻（批准或拒絕都是決定）。NULL 表示這筆帳戶不經審批通路。
    reviewed_at          INTEGER CHECK (reviewed_at IS NULL OR reviewed_at > 0),

    -- 狀態一致性：0007 的三條方向規則逐字承接。
    CHECK (status <> 'disabled' OR disabled_at IS NOT NULL),
    CHECK (status <> 'active' OR disabled_at IS NULL),
    CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
    -- 待審批與已拒絕都還沒有「被停用」這回事：disabled_at 只屬於 active ⇄ disabled 那條鏈。
    -- 擋的是拿 disabled_at 湊成「他在審核中被停過」這種無法解釋的行。
    CHECK (status NOT IN ('pending', 'rejected') OR disabled_at IS NULL),
    -- 決定時刻與決定必須同生同滅的兩個方向各自擋一件事：
    --   - pending 不帶時刻：「還在等」與「已經做過決定」不能同時為真；
    --   - rejected 必帶時刻：一句沒有時刻的「他被拒絕了」無從核實是哪一次審核說的話。
    CHECK (status <> 'pending' OR reviewed_at IS NULL),
    CHECK (status <> 'rejected' OR reviewed_at IS NOT NULL),
    -- 批准那一跳留下的時刻（status 已離開 pending／rejected）不與 status 成對：
    -- 它是「曾經走過審批」的歷史事實，被停用、被刪除都不該抹掉它。
    -- 因此除了下面這條單調規則，不再加任何「非 pending 就必須如何」的等式——
    -- 開放自註冊建成的 active 帳戶 reviewed_at 恆為 NULL，那是正確形態，不是缺欄。
    CHECK (reviewed_at IS NULL OR reviewed_at >= created_at),
    -- 訪客帳戶不經審批通路：訪客按定義無憑據，而受限狀態查詢問的恰恰是「請出示你的口令」，
    -- 一個無口令可出示的待審批帳戶在整套設計裡沒有能回答的問題。訪客註冊本身尚未實作，
    -- 這條是把那個形態在資料庫層也凍住，等它實作時由那一步自己說明理由。
    CHECK (account_type <> 'guest' OR status NOT IN ('pending', 'rejected')),
    -- Guest 形態凍結：與 0003 逐字同義。
    CHECK (account_type <> 'guest' OR (password_hash IS NULL AND must_change_password = 0)),
    -- 標準帳戶憑據必填：與 0003 逐字同義。
    CHECK (account_type <> 'standard' OR password_hash IS NOT NULL),
    -- 時間單調：登入、禁用、刪除、審核都不可能早於帳戶誕生。
    CHECK (last_login_at IS NULL OR last_login_at >= created_at),
    CHECK (disabled_at IS NULL OR disabled_at >= created_at),
    CHECK (deleted_at IS NULL OR deleted_at >= created_at)
);

INSERT INTO accounts_pendingapproval (id, login_name, login_name_key, display_name, password_hash,
        account_type, status, must_change_password, created_at, last_login_at, disabled_at, deleted_at,
        reviewed_at)
    SELECT id, login_name, login_name_key, display_name, password_hash,
        account_type, status, must_change_password, created_at, last_login_at, disabled_at, deleted_at,
        NULL
    FROM accounts;

-- 2) 兩張子表重建為參照新帳戶表（與 0007 同因：只是把「誰參照 accounts」這條連結從舊表挪到新表上）。
CREATE TABLE sessions_pendingapproval (
    id             TEXT PRIMARY KEY CHECK (length(id) = 36),
    device_id      TEXT NOT NULL UNIQUE CHECK (length(device_id) = 36),
    token_hash     TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    subject_kind   TEXT NOT NULL CHECK (subject_kind IN ('root', 'account')),
    account_id     TEXT REFERENCES accounts_pendingapproval (id),

    created_at     INTEGER NOT NULL CHECK (created_at > 0),
    last_active_at INTEGER NOT NULL CHECK (last_active_at >= created_at),
    expires_at     INTEGER NOT NULL CHECK (expires_at > created_at),
    revoked_at     INTEGER CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    rotation_seq   INTEGER NOT NULL DEFAULT 0,
    previous_token_hash TEXT,

    CHECK ((subject_kind = 'root' AND account_id IS NULL)
        OR (subject_kind = 'account' AND account_id IS NOT NULL))
);

INSERT INTO sessions_pendingapproval (id, device_id, token_hash, subject_kind, account_id,
        created_at, last_active_at, expires_at, revoked_at, rotation_seq, previous_token_hash)
    SELECT id, device_id, token_hash, subject_kind, account_id,
        created_at, last_active_at, expires_at, revoked_at, rotation_seq, previous_token_hash
    FROM sessions;

CREATE TABLE account_server_roles_pendingapproval (
    account_id  TEXT NOT NULL REFERENCES accounts_pendingapproval (id),
    role        TEXT NOT NULL CHECK (role IN ('server_admin')),
    granted_at  INTEGER NOT NULL CHECK (granted_at > 0),

    PRIMARY KEY (account_id, role)
);

INSERT INTO account_server_roles_pendingapproval (account_id, role, granted_at)
    SELECT account_id, role, granted_at FROM account_server_roles;

-- 3) 丟掉舊表：先子後父。此刻已沒有任何表參照名為 accounts 的舊表，DROP 才不會撞外鍵。
DROP TABLE account_server_roles;
DROP TABLE sessions;
DROP TABLE accounts;

-- 4) 正名。SQLite 3.25 起會把子表定義裡的 REFERENCES accounts_pendingapproval 一起改寫。
ALTER TABLE account_server_roles_pendingapproval RENAME TO account_server_roles;
ALTER TABLE sessions_pendingapproval RENAME TO sessions;
ALTER TABLE accounts_pendingapproval RENAME TO accounts;

-- 5) 索引與觸發器用最終表名重建（名稱與 0003／0004／0005／0007 一致）。
CREATE UNIQUE INDEX accounts_login_name_key_unique ON accounts (login_name_key);
CREATE INDEX accounts_created_at_idx ON accounts (created_at DESC, id DESC);

CREATE TRIGGER accounts_id_no_update
    BEFORE UPDATE OF id ON accounts
BEGIN
    SELECT RAISE(ABORT, 'accounts.id 是穩定標識：不得修改主鍵（改主鍵等於改實體身份）');
END;

-- 刪除是終態：規則逐字承接 0007（含新增的 reviewed_at——已刪除行連「何時被批准」都不準改寫，
-- 否則可以把一段審批歷史改寫成沒有一段）。
CREATE TRIGGER accounts_deleted_no_update
    BEFORE UPDATE ON accounts
    WHEN OLD.deleted_at IS NOT NULL AND (
        NEW.deleted_at IS NOT OLD.deleted_at
     OR NEW.status IS NOT OLD.status
     OR NEW.login_name IS NOT OLD.login_name
     OR NEW.login_name_key IS NOT OLD.login_name_key
     OR NEW.display_name IS NOT OLD.display_name
     OR NEW.password_hash IS NOT OLD.password_hash
     OR NEW.account_type IS NOT OLD.account_type
     OR NEW.must_change_password IS NOT OLD.must_change_password
     OR NEW.created_at IS NOT OLD.created_at
     OR NEW.last_login_at IS NOT OLD.last_login_at
     OR NEW.disabled_at IS NOT OLD.disabled_at
     OR NEW.reviewed_at IS NOT OLD.reviewed_at
    )
BEGIN
    SELECT RAISE(ABORT, 'accounts 的刪除態是終態：已刪除行不得再寫（恢復登入請走停用/恢復通路，而那條通路對已刪除目標一律拒絕）');
END;

CREATE TRIGGER accounts_insert_not_deleted
    BEFORE INSERT ON accounts
BEGIN
    SELECT RAISE(ABORT, '新建帳戶不得直接帶有 deleted_at：刪除只能發生在已存在的帳戶上')
    WHERE NEW.deleted_at IS NOT NULL;
END;

-- 與上一條同一取向：「出生時就帶著審核決定時刻」沒有合法語意——
-- 沒有人做過決定，卻留了一個決定時刻。這一條順帶把「憑空建出一個 rejected」擋死
-- （rejected 必帶 reviewed_at 是上面的 CHECK），因此待審批是唯一能在建立時出現的審批形態。
CREATE TRIGGER accounts_insert_not_reviewed
    BEFORE INSERT ON accounts
BEGIN
    SELECT RAISE(ABORT, '新建帳戶不得直接帶有 reviewed_at：審批決定只能發生在已存在的申請上')
    WHERE NEW.reviewed_at IS NOT NULL;
END;

CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
CREATE INDEX sessions_account_id_idx ON sessions (account_id);

CREATE TRIGGER sessions_id_no_update
    BEFORE UPDATE OF id ON sessions
BEGIN
    SELECT RAISE(ABORT, 'sessions.id 是穩定標識：不得修改主鍵（改主鍵等於改實體身份）');
END;

CREATE TRIGGER sessions_device_no_update
    BEFORE UPDATE OF device_id ON sessions
BEGIN
    SELECT RAISE(ABORT, 'sessions.device_id 建立後不可變：設備身份不隨秘密換代而改變');
END;

CREATE TRIGGER sessions_token_hash_rotation
    BEFORE UPDATE OF token_hash ON sessions
    WHEN NEW.rotation_seq IS NOT OLD.rotation_seq + 1
      OR NEW.previous_token_hash IS NOT OLD.token_hash
      OR NEW.token_hash IS OLD.token_hash
BEGIN
    SELECT RAISE(ABORT, 'sessions.token_hash 只能經輪換更新：必須同時把 rotation_seq 加一並留下舊雜湊');
END;

CREATE TRIGGER sessions_rotation_seq_no_update
    BEFORE UPDATE OF rotation_seq ON sessions
    WHEN NEW.rotation_seq IS NOT OLD.rotation_seq + 1
      OR NEW.token_hash IS OLD.token_hash
BEGIN
    SELECT RAISE(ABORT, 'sessions.rotation_seq 世代號只能隨一枚新秘密一起加一');
END;

CREATE TRIGGER sessions_expires_at_no_update
    BEFORE UPDATE OF expires_at ON sessions
BEGIN
    SELECT RAISE(ABORT, 'sessions.expires_at 建立後不可變：輪換與活動都不延長絕對期限');
END;

CREATE INDEX sessions_previous_token_hash_idx
    ON sessions (previous_token_hash)
    WHERE previous_token_hash IS NOT NULL;

CREATE INDEX account_server_roles_role_idx
    ON account_server_roles (role, granted_at DESC, account_id DESC);

CREATE TRIGGER account_server_roles_no_update
    BEFORE UPDATE OF account_id, role ON account_server_roles
BEGIN
    SELECT RAISE(ABORT, '授予行不可就地改寫：改授予請撤銷舊行再插入新行');
END;

-- 最後一條：正文引用父表名，必須等 accounts 正名完成後才建（見 0007 檔頭「必踩的坑」）。
CREATE TRIGGER account_server_roles_guest_no_role
    BEFORE INSERT ON account_server_roles
BEGIN
    SELECT RAISE(ABORT, '訪客帳戶不可持有伺服器級角色（無憑據卻有權限不是合法形態）')
    WHERE EXISTS (SELECT 1 FROM accounts
                   WHERE accounts.id = NEW.account_id AND accounts.account_type = 'guest');
END;

-- 6) 搬移守衛：任何一條子行指不回父行，這條 INSERT 就會撞上 CHECK 並讓整支遷移回滾。
CREATE TABLE pending_approval_migration_guard (
    orphan_rows INTEGER NOT NULL CHECK (orphan_rows = 0)
);
INSERT INTO pending_approval_migration_guard (orphan_rows)
    SELECT (SELECT COUNT(*) FROM sessions s
             WHERE s.account_id IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = s.account_id))
         + (SELECT COUNT(*) FROM account_server_roles r
             WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = r.account_id));
DROP TABLE pending_approval_migration_guard;
