-- 帳戶的軟刪除終態：status 新增 'deleted'，並留下「何時被刪除」的時刻。
--
-- 本步的邊界由用戶批準（R2-005）：Root 可軟刪除一名管理員帳戶——停止新登入、撤銷其有效會話、
-- 行與登入名鍵保留，讓既有審計與其他實際存在的參照仍能指回同一個穩定身份。
-- 物理清庫、其他欄位的匿名化、批量刪除都不在本支遷移的範圍之內。
--
-- 為什麼要動 0003 那個「沒有 deleted_at 欄」的決定：0003 寫這句話時的刪除語意只有一種，
-- 就是物理 DELETE——行都沒了，存一個只服務已消失行的時間戳確實是自娛。
-- 而本步把「刪除」改成保留行的終態後，「他存在過、他被刪於何時」變成必須查得到的事實，
-- 欄位因此有了自己的職責；disabled（可恢復登入）與 deleted（終態）是兩個不同狀態，
-- 靠同一個 status 欄的不同取值區分，比再造一張標記表少一處「兩張表各說一套」的判定點。
--
-- 為什麼必須連 sessions 與 account_server_roles 一起重建（本支遷移看起來過大的原因）：
--   status 的 CHECK 是表內約束，SQLite 無法就地放寬，只能重建 accounts 整張表；
--   而遷移器把每支遷移放在單一交易裡執行（見 migrate.go），交易期間無法改
--   `PRAGMA foreign_keys`（事實在交易內改不了），開啟外鍵時 DROP 一張「仍有子行參照」
--   的父表會做隱式 DELETE 並觸發外鍵檢查。實測兩條捷徑都走不通：
--     - 直接 DROP：當下即 FOREIGN KEY constraint failed；
--     - `PRAGMA defer_foreign_keys=ON`：DROP 過得了，但隱式刪除留下的待驗證記錄在
--       COMMIT 階段仍判定 FOREIGN KEY constraint failed，整支遷移回滾——
--       同名重建並補回相同標識的事實無法滿足那個「父鍵已被刪掉」的判定。
--   唯一可行的順序因此是：先把兩張子表重建為參照新表，舊 accounts 就再也沒有子行參照，
--   此時 DROP 它才合法；新表正名為 accounts 後，SQLite（3.25 起）會把子表的
--   REFERENCES 子句一起改寫，外鍵關係回到原處。
--
-- 一個必踩的坑（故本支遷移的語句順序不是風格問題）：`ALTER TABLE ... RENAME` 只改寫
--   其他表定義裡的 REFERENCES 子句，不改寫觸發器正文與視圖定義。
--   account_server_roles 的「訪客帳戶不可持有角色」觸發器正文寫著 `FROM accounts ...`，
--   若在中間狀態就把它建在新表上，正名之後正文仍指向已不存在的名字，
--   此後的授予插入會直接以 parse error 失敗。因此它一律等父表正名完成後最後重建，
--   正文與 ON 目標都寫最終的表名。
--
-- 資料搬移的形態：status、disabled_at、login_name、login_name_key 逐字保留，
--   deleted_at 對既有每一行都是 NULL（他們都還沒被刪除過——這是事實的還原，不是回填）。
--   原本的跨欄 CHECK `(status='disabled')=(disabled_at IS NOT NULL)` 拆成三條方向明確的規則：
--     - disabled 必帶 disabled_at（與 0003 同義）；
--     - active 必不帶 disabled_at（重新啟用清回 NULL，與 0003 同義）；
--     - deleted 與 deleted_at 同生同滅；disabled_at 對已刪除行可留可空——
--       被刪前是停用者，那個「何時停的」仍是歷史；被刪前還活著，就沒有停用時刻，
--       不為了湊對稱而偽造一個。
--   其餘 CHECK、觸發器與索引逐字承接 0003／0004／0005／0006 的現狀，不順手加寬也不順手加嚴。
--
-- 交易末尾的守衛不是裝飾：重建之後逐條查證兩張子表都沒有孤兒子行，
--   任何一條對不上就讓 CHECK 失敗、整支遷移回滾、資料庫停在原版本。
--   用 `PRAGMA foreign_key_check` 的表值函式做同一件事更簡短，但那依賴驅動對表值函式的支援；
--   這裡要的是「搬完之後關係一定還在」這句話本身，寫成明確的反查更可靠。
--
-- 時間戳與標識約定不變（DEC-011／DEC-014）：Unix 毫秒 UTC、TEXT 36 字元小寫正規 UUIDv7。

-- 1) 新帳戶表：先以暫名建好並搬入既有行（尚未動任何舊表）。
CREATE TABLE accounts_presoftdelete (
    id                   TEXT PRIMARY KEY CHECK (length(id) = 36),
    login_name           TEXT NOT NULL CHECK (length(login_name) BETWEEN 1 AND 64),
    login_name_key       TEXT NOT NULL CHECK (length(login_name_key) BETWEEN 1 AND 200),
    display_name         TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 64),
    -- 憑據雜湊的取值規則與 0003 相同；軟刪除不改憑據欄的形態（刪除不清憑據，
    -- 清憑據屬後續的物理清庫步驟，屆時由那一步自己說明理由）。
    password_hash        TEXT CHECK (password_hash IS NULL OR length(password_hash) BETWEEN 1 AND 512),
    account_type         TEXT NOT NULL CHECK (account_type IN ('standard', 'guest')),
    -- 三個狀態構成一條單向鏈：active ⇄ disabled → deleted。
    -- 「deleted 之後還能回到任何一個可登入狀態」在本表中沒有一個合法的寫法：
    -- 進入 deleted 必帶 deleted_at，而要離開它就必須把 deleted_at 清成 NULL，
    -- 那條 UPDATE 同時要改 status 與 deleted_at 兩欄，屬使用例不提供的通路；
    -- 資料庫層另由 accounts_deleted_no_update 觸發器把已刪除行整個釘住。
    status               TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),
    must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1)),
    created_at           INTEGER NOT NULL CHECK (created_at > 0),
    last_login_at        INTEGER CHECK (last_login_at IS NULL OR last_login_at > 0),
    disabled_at          INTEGER CHECK (disabled_at IS NULL OR disabled_at > 0),
    -- deleted_at：進入刪除終態的時刻；從未刪除為 NULL（不拿 disabled_at 或 created_at 冒充）。
    deleted_at           INTEGER CHECK (deleted_at IS NULL OR deleted_at > 0),

    -- 狀態一致性：三條方向明確的配對規則（取代 0003 那條雙向等式，理由見檔頭）。
    CHECK (status <> 'disabled' OR disabled_at IS NOT NULL),
    CHECK (status <> 'active' OR disabled_at IS NULL),
    CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
    -- Guest 形態凍結：與 0003 逐字同義。
    CHECK (account_type <> 'guest' OR (password_hash IS NULL AND must_change_password = 0)),
    -- 標準帳戶憑據必填：與 0003 逐字同義。
    CHECK (account_type <> 'standard' OR password_hash IS NOT NULL),
    -- 時間單調：登入、禁用、刪除都不可能早於帳戶誕生。
    CHECK (last_login_at IS NULL OR last_login_at >= created_at),
    CHECK (disabled_at IS NULL OR disabled_at >= created_at),
    CHECK (deleted_at IS NULL OR deleted_at >= created_at)
);

INSERT INTO accounts_presoftdelete (id, login_name, login_name_key, display_name, password_hash,
        account_type, status, must_change_password, created_at, last_login_at, disabled_at, deleted_at)
    SELECT id, login_name, login_name_key, display_name, password_hash,
        account_type, status, must_change_password, created_at, last_login_at, disabled_at, NULL
    FROM accounts;

-- 2) 兩張子表重建為參照新帳戶表。此舉不是要改它們的任何規則，
--    只是把「誰參照 accounts」這條連結從舊表挪到新表上——舊表隨之可以被合法 DROP。
CREATE TABLE sessions_presoftdelete (
    id             TEXT PRIMARY KEY CHECK (length(id) = 36),
    device_id      TEXT NOT NULL UNIQUE CHECK (length(device_id) = 36),
    token_hash     TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    subject_kind   TEXT NOT NULL CHECK (subject_kind IN ('root', 'account')),
    account_id     TEXT REFERENCES accounts_presoftdelete (id),

    created_at     INTEGER NOT NULL CHECK (created_at > 0),
    last_active_at INTEGER NOT NULL CHECK (last_active_at >= created_at),
    expires_at     INTEGER NOT NULL CHECK (expires_at > created_at),
    revoked_at     INTEGER CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    rotation_seq   INTEGER NOT NULL DEFAULT 0,
    previous_token_hash TEXT,

    CHECK ((subject_kind = 'root' AND account_id IS NULL)
        OR (subject_kind = 'account' AND account_id IS NOT NULL))
);

INSERT INTO sessions_presoftdelete (id, device_id, token_hash, subject_kind, account_id,
        created_at, last_active_at, expires_at, revoked_at, rotation_seq, previous_token_hash)
    SELECT id, device_id, token_hash, subject_kind, account_id,
        created_at, last_active_at, expires_at, revoked_at, rotation_seq, previous_token_hash
    FROM sessions;

CREATE TABLE account_server_roles_presoftdelete (
    account_id  TEXT NOT NULL REFERENCES accounts_presoftdelete (id),
    role        TEXT NOT NULL CHECK (role IN ('server_admin')),
    granted_at  INTEGER NOT NULL CHECK (granted_at > 0),

    PRIMARY KEY (account_id, role)
);

INSERT INTO account_server_roles_presoftdelete (account_id, role, granted_at)
    SELECT account_id, role, granted_at FROM account_server_roles;

-- 3) 丟掉舊表：先子後父。此刻已沒有任何表參照名為 accounts 的舊表，DROP 才不會撞外鍵。
DROP TABLE account_server_roles;
DROP TABLE sessions;
DROP TABLE accounts;

-- 4) 正名。SQLite 3.25 起會把子表定義裡的 REFERENCES accounts_presoftdelete 一起改寫。
ALTER TABLE account_server_roles_presoftdelete RENAME TO account_server_roles;
ALTER TABLE sessions_presoftdelete RENAME TO sessions;
ALTER TABLE accounts_presoftdelete RENAME TO accounts;

-- 5) 索引與觸發器用最終表名重建（名稱與 0003／0004／0005 一致，運維查 sql 時不必認暫名）。
CREATE UNIQUE INDEX accounts_login_name_key_unique ON accounts (login_name_key);
CREATE INDEX accounts_created_at_idx ON accounts (created_at DESC, id DESC);

CREATE TRIGGER accounts_id_no_update
    BEFORE UPDATE OF id ON accounts
BEGIN
    SELECT RAISE(ABORT, 'accounts.id 是穩定標識：不得修改主鍵（改主鍵等於改實體身份）');
END;

-- 刪除是終態：已帶 deleted_at 的行，除「本身就是進入刪除態的那一跳」（OLD.deleted_at 為 NULL）
-- 之外不再接受任何 UPDATE。擋的是繞過應用層的直寫——例如把已刪除帳戶的 status 改回 active、
-- 或清掉 deleted_at 冒充復活。登入名與顯示名的改寫同樣擋在前面那條使用例路徑裡，
-- 這裡是後一道閘。
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
    )
BEGIN
    SELECT RAISE(ABORT, 'accounts 的刪除態是終態：已刪除行不得再寫（恢復登入請走停用/恢復通路，而那條通路對已刪除目標一律拒絕）');
END;

-- 不得憑空建出一個「已刪除」的帳戶：建立時就帶著 deleted_at 沒有合法語意
-- （沒有人被刪除過，卻留了一個刪除時刻）。
CREATE TRIGGER accounts_insert_not_deleted
    BEFORE INSERT ON accounts
BEGIN
    SELECT RAISE(ABORT, '新建帳戶不得直接帶有 deleted_at：刪除只能發生在已存在的帳戶上')
    WHERE NEW.deleted_at IS NOT NULL;
END;

CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
CREATE INDEX sessions_account_id_idx ON sessions (account_id);

CREATE TRIGGER sessions_id_no_update
    BEFORE UPDATE OF id ON sessions
BEGIN
    SELECT RAISE(ABORT, 'sessions.id 是稳定标识：不得修改主键（改主键等于改实体身份）');
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
    SELECT RAISE(ABORT, 'sessions.token_hash 只能經輪換更新：必須同時把 rotation_seq 加一並留下舊哈希');
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

-- 最後一條：正文引用父表名，必須等 accounts 正名完成後才建（見檔頭「必踩的坑」）。
CREATE TRIGGER account_server_roles_guest_no_role
    BEFORE INSERT ON account_server_roles
BEGIN
    SELECT RAISE(ABORT, '訪客帳戶不可持有伺服器級角色（無憑據卻有權限不是合法形態）')
    WHERE EXISTS (SELECT 1 FROM accounts
                   WHERE accounts.id = NEW.account_id AND accounts.account_type = 'guest');
END;

-- 6) 搬移守衛：任何一條子行指不回父行，這條 INSERT 就會撞上 CHECK 並讓整支遷移回滾。
CREATE TABLE soft_delete_migration_guard (
    orphan_rows INTEGER NOT NULL CHECK (orphan_rows = 0)
);
INSERT INTO soft_delete_migration_guard (orphan_rows)
    SELECT (SELECT COUNT(*) FROM sessions s
             WHERE s.account_id IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = s.account_id))
         + (SELECT COUNT(*) FROM account_server_roles r
             WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = r.account_id));
DROP TABLE soft_delete_migration_guard;
