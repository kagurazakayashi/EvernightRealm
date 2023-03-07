-- 訪戶綁定的執行形態：accounts 新增「退休」終態，另建綁定憑證與綁定留痕兩張表。
--
-- 本支遷移把「訪戶 X 併入既有正式帳戶 Y」從一句預覽變成可以落地的動作，同時把
--   「X 此後怎麼辦」寫成資料庫認得的形態。三件事各自有自己的職責，不互相代替：
--     - accounts.status 的 'retired'：X 那一行的終態（不可登入、不可複用、不可翻回）；
--     - guest_bind_tickets：一經伺服器級管理員簽發、限定這一對（來源, 目標）、
--       短效且只能核銷一次的操作憑證——它是「兩端归属」中來源側證據的落庫形態；
--     - guest_account_bindings：綁定關係的不可變留痕（Historical Identity 的物理形體），
--       「這個人曾經是訪戶 X、後來以 X 這個標識被併入 Y」因此永遠查得到，
--       不會因為 X 退休就變成「從來都是 Y」。
--
-- 為什麼退休落在 status 而不是另開一張標記表（與 0007 的刪除態、0009 的審批鏈同一取向）：
--   登入、主體成形、會話簽發與逐請求解析現存的規則全部寫成「status 不是 active 就拒絕」，
--   把退休做成一個 status 取值，這些閘門一個字都不用改就自動把退休者擋在門外——
--   安全預設來自既有形狀，而不是靠各處再補一個分支。另開標記表則每一處閘門都要記得
--   去問那張表一次，漏問一處就是一個「已退休卻還登得進去」的洞。
--   退休與 deleted 刻意是两个取值而不是同一個：一個說「他被併進別人了」，
--   一個說「他被刪掉了」，兩句話在歷史裡的含義不同，混成一個值就再也分不出來
--   （用戶批准的留痕方向：綁定的源頭進入退休終態，不复用刪除態）。
--
-- 為什麼必須連 sessions 與 account_server_roles 一起重建（本支遷移看起來過大的原因）：
--   status 的 CHECK 是表內約束，SQLite 無法就地放寬，只能重建 accounts 整張表；
--   而遷移器把每支遷移放在單一交易裡執行，交易期間無法改 `PRAGMA foreign_keys`，
--   開啟外鍵時 DROP 一張「仍有子行參照」的父表會做隱式 DELETE 並觸發外鍵檢查。
--   順序與 0007／0009 逐字同形：先把兩張子表重建為參照新表，舊 accounts 就再也沒有
--   子行參照，此時 DROP 它才合法；正名後 SQLite（3.25 起）會把子表的 REFERENCES
--   子句一起改寫。觸發器正文引用父表名的那條（訪戶不可持授予）一律等正名完成後最後建。
--   兩張新表放在正名之後建立，直接參照最終的 accounts，不参与上面的舞蹈。
--
-- 資料搬移的形態：全部既有欄位逐字保留，retired_at 對既有每一行都是 NULL
--   （沒有人被綁走过——這是事實的還原，不是回填）。0009 的其餘 CHECK、觸發器與索引
--   逐字承接，不順手加寬也不順手加嚴；唯一的例外是「已刪除行不得再寫」那條觸發器的
--   欄位清單多了 retired_at：已刪者連「何時被綁走」都不準被事後寫上或抹掉。
--
-- 憑證表的取值規則（與 0010 的邀請碼同一套取向，理由也同源）：
--   ticket_hash 是本表唯一帶秘密形狀的欄，存的是 SHA-256 十六進位而非原文；
--   UNIQUE 把「同一枚憑證被簽發兩次」在結構上擋死；
--   expires_at 不留 0 這個「永不」的選項——短效憑證的意義就是過期即失效，
--   一枚可以長期擱著的綁定憑證正是本步要防的東西；
--   consumed_at 只准從 NULL 變成一個時刻（見下方觸發器）：撤銷核銷、把憑證還給
--   呼叫端再按一次，都沒有誠實語意。
--   plan_digest 與 schema_version 把「這份計劃是按哪一版資料庫、哪幾項事實簽發的」
--   釘在行上：核銷時重算比對，對不上就不執行——預覽通過不等於之後永久有權執行。
--
-- 留痕表的取值規則：
--   source_account_id 上的 UNIQUE 是「同一個訪戶只能被綁走一次」的結構保證，
--   重複核銷在資料庫層就寫不進第二行，不靠應用層記得先查；
--   consent_mode 是封閉集合且只有一个取值：綁定只能由目標帳戶持有人以自己的
--   已認證會話發起（用戶批准的同意形態）。把它寫進 CHECK 而不是只在碼內斷言，
--   是為了讓「管理員代他人綁定」這種形態在資料庫層也沒有落點；
--   revoked_sessions 記的是「這次讓幾枚源會話失效」這個當時的數量，
--   不是可事後改寫的統計欄——它是那一次動作的摘要，所以隨行不可變。
--   兩張表都是只追加：不準 UPDATE、不準 DELETE（與 0002 的審計表同一口徑）。
--   綁定留痕不帶任何憑據材料：口令雜湌不複製、不搬遷、不引用，
--   目標那一行也不因綁定而被改寫（這三句話各自有對應的測試）。
--
-- 時間戳與標識約定不變（DEC-011／DEC-014）：Unix 毫秒 UTC、TEXT 36 字元小寫正規 UUIDv7。

-- 1) 新帳戶表：先以暫名建好並搬入既有行（尚未動任何舊表）。
CREATE TABLE accounts_guestbind (
    id                   TEXT PRIMARY KEY CHECK (length(id) = 36),
    login_name           TEXT NOT NULL CHECK (length(login_name) BETWEEN 1 AND 64),
    login_name_key       TEXT NOT NULL CHECK (length(login_name_key) BETWEEN 1 AND 200),
    display_name         TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 64),
    password_hash        TEXT CHECK (password_hash IS NULL OR length(password_hash) BETWEEN 1 AND 512),
    account_type         TEXT NOT NULL CHECK (account_type IN ('standard', 'guest')),
    -- 六個狀態的登入能力仍然只有一條正向規則：只有 active 可登入。
    -- 退休落在這條規則之外，因此登入、主體成形、會話簽發與解析不需改動即自動拒絶它。
    -- 鏈的形狀：active ⇄ disabled → deleted 屬既有通路；pending → active／rejected 屬審批通路；
    -- active → retired 是本次新增的那一跳，而且只能由綁定用例進入（見下方 CHECK 與觸發器）。
    status               TEXT NOT NULL CHECK (
        status IN ('active', 'disabled', 'deleted', 'pending', 'rejected', 'retired')),
    must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1)),
    created_at           INTEGER NOT NULL CHECK (created_at > 0),
    last_login_at        INTEGER CHECK (last_login_at IS NULL OR last_login_at > 0),
    disabled_at          INTEGER CHECK (disabled_at IS NULL OR disabled_at > 0),
    deleted_at           INTEGER CHECK (deleted_at IS NULL OR deleted_at > 0),
    reviewed_at          INTEGER CHECK (reviewed_at IS NULL OR reviewed_at > 0),
    -- retired_at：這行人被綁走、進入退休終態的時刻。從未退休為 NULL
    -- （不拿 created_at 或 deleted_at 冒充「他什麼時候被併掉的」）。
    retired_at           INTEGER CHECK (retired_at IS NULL OR retired_at > 0),

    -- 狀態一致性：0007 的三條與 0009 的五條方向規則逐字承接。
    CHECK (status <> 'disabled' OR disabled_at IS NOT NULL),
    CHECK (status <> 'active' OR disabled_at IS NULL),
    CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
    CHECK (status NOT IN ('pending', 'rejected') OR disabled_at IS NULL),
    CHECK (status <> 'pending' OR reviewed_at IS NULL),
    CHECK (status <> 'rejected' OR reviewed_at IS NOT NULL),
    CHECK (reviewed_at IS NULL OR reviewed_at >= created_at),
    -- 退休與退休時刻同生同滅：一句「他已被綁走」沒有時刻就無從核實是哪一次綁定說的話，
    -- 而一個帶著退休時刻、狀態卻寫別的东西的行，是兩套真相同時成立。
    CHECK ((status = 'retired') = (retired_at IS NOT NULL)),
    -- 退休只能從「可用」那一跳進入（綁定用例的 WHERE 守衛就是這句話），
    -- 因此退休行不帶停用時刻：一個被停用過的訪戶要綁走，處置是先恢復他的登入能力。
    CHECK (status <> 'retired' OR disabled_at IS NULL),
    -- 退休是訪戶經綁定後留下的終態：普通帳戶沒有「被併入別人」這件事，
    -- 一個 retired 的 standard 行沒有任何通路能解釋它是怎麼來的。
    CHECK (status <> 'retired' OR account_type = 'guest'),
    -- 訪客帳戶不經審批通路：與 0009 逐字同義。
    CHECK (account_type <> 'guest' OR status NOT IN ('pending', 'rejected')),
    -- Guest 形態凍結：與 0003 逐字同義（退休不給訪戶變出憑據）。
    CHECK (account_type <> 'guest' OR (password_hash IS NULL AND must_change_password = 0)),
    -- 標準帳戶憑據必填：與 0003 逐字同義。
    CHECK (account_type <> 'standard' OR password_hash IS NOT NULL),
    -- 時間單調：登入、禁用、刪除、審核、退休都不可能早於帳戶誕生。
    CHECK (last_login_at IS NULL OR last_login_at >= created_at),
    CHECK (disabled_at IS NULL OR disabled_at >= created_at),
    CHECK (deleted_at IS NULL OR deleted_at >= created_at),
    CHECK (retired_at IS NULL OR retired_at >= created_at)
);

INSERT INTO accounts_guestbind (id, login_name, login_name_key, display_name, password_hash,
        account_type, status, must_change_password, created_at, last_login_at, disabled_at,
        deleted_at, reviewed_at, retired_at)
    SELECT id, login_name, login_name_key, display_name, password_hash,
        account_type, status, must_change_password, created_at, last_login_at, disabled_at,
        deleted_at, reviewed_at, NULL
    FROM accounts;

-- 2) 兩張子表重建為參照新帳戶表（與 0007／0009 同因：只是把「誰參照 accounts」這條連結
--    從舊表挪到新表上，兩張表的規則一個字都不改）。
CREATE TABLE sessions_guestbind (
    id             TEXT PRIMARY KEY CHECK (length(id) = 36),
    device_id      TEXT NOT NULL UNIQUE CHECK (length(device_id) = 36),
    token_hash     TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    subject_kind   TEXT NOT NULL CHECK (subject_kind IN ('root', 'account')),
    account_id     TEXT REFERENCES accounts_guestbind (id),

    created_at     INTEGER NOT NULL CHECK (created_at > 0),
    last_active_at INTEGER NOT NULL CHECK (last_active_at >= created_at),
    expires_at     INTEGER NOT NULL CHECK (expires_at > created_at),
    revoked_at     INTEGER CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    rotation_seq   INTEGER NOT NULL DEFAULT 0,
    previous_token_hash TEXT,

    CHECK ((subject_kind = 'root' AND account_id IS NULL)
        OR (subject_kind = 'account' AND account_id IS NOT NULL))
);

INSERT INTO sessions_guestbind (id, device_id, token_hash, subject_kind, account_id,
        created_at, last_active_at, expires_at, revoked_at, rotation_seq, previous_token_hash)
    SELECT id, device_id, token_hash, subject_kind, account_id,
        created_at, last_active_at, expires_at, revoked_at, rotation_seq, previous_token_hash
    FROM sessions;

CREATE TABLE account_server_roles_guestbind (
    account_id  TEXT NOT NULL REFERENCES accounts_guestbind (id),
    role        TEXT NOT NULL CHECK (role IN ('server_admin')),
    granted_at  INTEGER NOT NULL CHECK (granted_at > 0),

    PRIMARY KEY (account_id, role)
);

INSERT INTO account_server_roles_guestbind (account_id, role, granted_at)
    SELECT account_id, role, granted_at FROM account_server_roles;

-- 3) 丟掉舊表：先子後父。此刻已沒有任何表參照名為 accounts 的舊表，DROP 才不會撞外鍵。
DROP TABLE account_server_roles;
DROP TABLE sessions;
DROP TABLE accounts;

-- 4) 正名。SQLite 3.25 起會把子表定義裡的 REFERENCES accounts_guestbind 一起改寫。
ALTER TABLE account_server_roles_guestbind RENAME TO account_server_roles;
ALTER TABLE sessions_guestbind RENAME TO sessions;
ALTER TABLE accounts_guestbind RENAME TO accounts;

-- 5) 索引與觸發器用最終表名重建（名稱與 0003／0004／0005／0007／0009 一致，
--    運維查 sql 時不必認暫名）。
CREATE UNIQUE INDEX accounts_login_name_key_unique ON accounts (login_name_key);
CREATE INDEX accounts_created_at_idx ON accounts (created_at DESC, id DESC);

CREATE TRIGGER accounts_id_no_update
    BEFORE UPDATE OF id ON accounts
BEGIN
    SELECT RAISE(ABORT, 'accounts.id 是穩定標識：不得修改主鍵（改主鍵等於改實體身份）');
END;

-- 刪除是終態：規則承接 0007／0009，欄位清單多了 retired_at——已刪除行連「何時被綁走」
-- 都不準事後寫上或抹掉，否則可以把一段綁定歷史偽造成「他從來沒被綁走過」。
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
     OR NEW.retired_at IS NOT OLD.retired_at
    )
BEGIN
    SELECT RAISE(ABORT, 'accounts 的刪除態是終態：已刪除行不得再寫（恢復登入請走停用/恢復通路，而那條通路對已刪除目標一律拒絕）');
END;

-- 退休同样是終態，而且比刪除更嚴：連顯示名都不准改。
--   - 不準改 status：退休之後沒有任何通路能把他翻回 active／disabled，
--     「已被綁走的訪戶」不該有復活的說法（要再進來是另行建一筆帳戶，那是另一句話）；
--   - 不準改 login_name／login_name_key：退休行繼續占用登入名，這正是「不可複用」
--     的落庫形態，也是既有審計與留痕能指回同一身份的依據；
--   - 不準改 display_name：與刪除通路不同，綁定不做匿名化——X 這個名字是歷史的一部分，
--     「他曾經叫這個名字被併進 Y」這句話要能在讀一行資料時原样看見；
--   - 不準改 retired_at：那個時刻屬於已經發生的那一次綁定。
-- 擋的是繞過應用層的直寫；正常通路裡唯一合法的寫入是「進入退休的那一跳」本身
-- （OLD.retired_at 為 NULL 時本觸發器不適用）。
CREATE TRIGGER accounts_retired_no_update
    BEFORE UPDATE ON accounts
    WHEN OLD.retired_at IS NOT NULL AND (
        NEW.retired_at IS NOT OLD.retired_at
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
     OR NEW.deleted_at IS NOT OLD.deleted_at
    )
BEGIN
    SELECT RAISE(ABORT, 'accounts 的退休態是終態：已被綁走的訪戶行不得再寫（不得複用其登入名、不得改寫其顯示名、更不得翻回可登入狀態）');
END;

CREATE TRIGGER accounts_insert_not_deleted
    BEFORE INSERT ON accounts
BEGIN
    SELECT RAISE(ABORT, '新建帳戶不得直接帶有 deleted_at：刪除只能發生在已存在的帳戶上')
    WHERE NEW.deleted_at IS NOT NULL;
END;

CREATE TRIGGER accounts_insert_not_reviewed
    BEFORE INSERT ON accounts
BEGIN
    SELECT RAISE(ABORT, '新建帳戶不得直接帶有 reviewed_at：審批決定只能發生在已存在的申請上')
    WHERE NEW.reviewed_at IS NOT NULL;
END;

-- 與上兩條同一取向：「一出生就帶著退休時刻」沒有合法語意——
-- 沒有人做過綁定，卻留了一次綁定的時刻。這一條順帶把「憑空建出一個已退休的訪戶」擋死。
CREATE TRIGGER accounts_insert_not_retired
    BEFORE INSERT ON accounts
BEGIN
    SELECT RAISE(ABORT, '新建帳戶不得直接帶有 retired_at：退休只能發生在已被綁走的既存訪戶上')
    WHERE NEW.retired_at IS NOT NULL;
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

-- 6) 綁定憑證表：一經伺服器級管理員簽發、限定這一對（來源, 目標）、短效且只准核銷一次。
CREATE TABLE guest_bind_tickets (
    id          TEXT PRIMARY KEY CHECK (length(id) = 36),
    -- 存的是 SHA-256 十六進位，不是憑證原文：與邀請碼、會話令牌同一取向——
    -- 被哈希的對象是密碼學隨機值，落庫的驗證材料洩露了也換不回明文。
    ticket_hash TEXT NOT NULL UNIQUE CHECK (length(ticket_hash) = 64),
    -- 兩個標識都是簽發那一刻凍結的事實：核銷時必須逐字對得上呼叫端換得的主體，
    -- 「換一個目標重放同一枚憑證」因此在結構上沒有落點。
    source_account_id  TEXT NOT NULL REFERENCES accounts (id),
    target_account_id  TEXT NOT NULL REFERENCES accounts (id),
    -- 簽發人：動作物是「管理員准了這一對」，這句話要查得出是誰說的。
    issued_by_account_id TEXT NOT NULL REFERENCES accounts (id),
    -- 計劃摘要與資料庫版本：簽發時依據的那份事實。核銷時重算比對，
    -- 對不上就不執行（預覽通過不等於之後永久有權執行）。
    plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 64),
    schema_version INTEGER NOT NULL CHECK (schema_version >= 0),
    created_at  INTEGER NOT NULL CHECK (created_at > 0),
    -- 憑證必帶到期時刻，沒有「永不」這一格（理由見檔頭）：到期時刻只能晚於簽發時刻。
    expires_at  INTEGER NOT NULL CHECK (expires_at > created_at),
    -- 核銷時刻：NULL 表示還沒有人用掉它。只准從 NULL 變成一個時刻（見觸發器）。
    consumed_at INTEGER CHECK (consumed_at IS NULL OR consumed_at >= created_at),

    -- 「把訪戶併入他自己」這句話在憑證層就先被擋掉：預檢把它當一條阻止原因，
    -- 這裡把它做成寫不进庫的形態——繞過應用層的直寫同樣沒有出路。
    CHECK (source_account_id <> target_account_id)
);

-- 按來源與目標各自可查：核銷走 ticket_hash 的 UNIQUE，這兩條索引服務的是事後追溯
-- （「這一對之間簽過幾枚憑證」「這個人簽發過哪些憑證」），不是熱路徑。
CREATE INDEX guest_bind_tickets_source_idx
    ON guest_bind_tickets (source_account_id, created_at DESC, id DESC);
CREATE INDEX guest_bind_tickets_target_idx
    ON guest_bind_tickets (target_account_id, created_at DESC, id DESC);
CREATE INDEX guest_bind_tickets_created_at_idx
    ON guest_bind_tickets (created_at DESC, id DESC);

CREATE TRIGGER guest_bind_tickets_id_no_update
    BEFORE UPDATE OF id ON guest_bind_tickets
BEGIN
    SELECT RAISE(ABORT, 'guest_bind_tickets.id 是穩定標識：不得修改主鍵');
END;

-- 憑證的事實欄位一經簽發即不可變：換來源、換目標、改有效期、改計劃摘要，
-- 都是「拿著一枚已交付的憑證重新定義它准了什麼」，那正是本表要防的形態。
CREATE TRIGGER guest_bind_tickets_immutable_no_update
    BEFORE UPDATE OF ticket_hash, source_account_id, target_account_id,
                     issued_by_account_id, plan_digest, schema_version,
                     created_at, expires_at ON guest_bind_tickets
BEGIN
    SELECT RAISE(ABORT, '綁定憑證的簽發事實不可改寫：要換這一对就撤銷這份認知、重新預檢並另簽一枚');
END;

-- 核銷是單向的一躍：已核銷的憑證不能被「還回去」再按一次，
-- 也不能把核銷時刻改成另一個值（那等於改寫「他什麼時候綁定的」）。
CREATE TRIGGER guest_bind_tickets_consumed_once
    BEFORE UPDATE OF consumed_at ON guest_bind_tickets
    WHEN OLD.consumed_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, '綁定憑證只能核銷一次：已核銷行不得再寫 consumed_at');
END;

-- 簽發時不得帶著核銷時刻：那是一句「憑證一出生就被用掉了」的謊，
-- 而且會把綁定留痕指向一枚沒有任何一次真實核銷的憑證。
CREATE TRIGGER guest_bind_tickets_insert_not_consumed
    BEFORE INSERT ON guest_bind_tickets
BEGIN
    SELECT RAISE(ABORT, '新建綁定憑證不得直接帶有 consumed_at：核銷只能發生在已簽發的憑證上')
    WHERE NEW.consumed_at IS NOT NULL;
END;

-- 憑證行不準刪除：未核銷者由到期時刻失效（不需要刪），已核銷者是那一次綁定的證據
-- （刪不得）。留痕表的 ticket_id 外鍵也靠這條保住指向的完整性。
CREATE TRIGGER guest_bind_tickets_no_delete
    BEFORE DELETE ON guest_bind_tickets
BEGIN
    SELECT RAISE(ABORT, '綁定憑證行不可刪除：未核銷者到期即失效，已核銷者是綁定證據');
END;

-- 7) 綁定留痕表：不可變的歷史解釋（Historical Identity 的物理形體）。
CREATE TABLE guest_account_bindings (
    id          TEXT PRIMARY KEY CHECK (length(id) = 36),
    -- 一個訪戶只能被綁走一次：這條 UNIQUE 是「重複核銷不會再遷移一次」的結構保證。
    -- 第二次插入同一枚 source 直接撞約束，整筆綁定交易回滾——
    -- 不靠應用層記得先查，也不靠退休態被讀對。
    source_account_id TEXT NOT NULL UNIQUE REFERENCES accounts (id),
    target_account_id TEXT NOT NULL REFERENCES accounts (id),
    -- 是哪一枚憑證換來這一行：追溯鏈從「綁定」回到「管理員准了這一對」與「Y 本人核銷」。
    ticket_id   TEXT NOT NULL REFERENCES guest_bind_tickets (id),
    bound_at    INTEGER NOT NULL CHECK (bound_at > 0),
    -- 這次讓幾枚源會話失效：那一次動作的摘要，隨行不可變（不是可事後重算的統計欄）。
    revoked_sessions INTEGER NOT NULL CHECK (revoked_sessions >= 0),
    -- 同意形態是封閉集合且只有一格：綁定只能由目標帳戶持有人以自己的會話發起。
    -- 寫進 CHECK 而不是只在碼內斷言，讓「管理員代他人綁定」在資料庫層也沒有落點。
    consent_mode TEXT NOT NULL CHECK (consent_mode IN ('target_self_initiated')),

    CHECK (source_account_id <> target_account_id)
);

-- 本人查詢自己的綁定史（結果待確認時的落點）與按時間追溯都走這條。
CREATE INDEX guest_account_bindings_target_idx
    ON guest_account_bindings (target_account_id, bound_at DESC, id DESC);

CREATE TRIGGER guest_account_bindings_no_update
    BEFORE UPDATE ON guest_account_bindings
BEGIN
    SELECT RAISE(ABORT, '綁定留痕是只追加存儲：歷史解釋不得改寫（改寫它等於說這個人從來都是目標帳戶）');
END;

CREATE TRIGGER guest_account_bindings_no_delete
    BEFORE DELETE ON guest_account_bindings
BEGIN
    SELECT RAISE(ABORT, '綁定留痕是只追加存儲：不得刪除既有記錄（源身份的歷史因此查得到）');
END;

-- 留痕只能指向一枚已核銷的憑證：把「行存在但憑證沒被用過」這種自相矛盾的形状
-- 擋在寫入那一刻。這裡讀的是 guest_bind_tickets 現名，兩張表都已建立，順序不是風格問題。
CREATE TRIGGER guest_account_bindings_ticket_consumed
    BEFORE INSERT ON guest_account_bindings
BEGIN
    SELECT RAISE(ABORT, '綁定留痕只能指向一枚已核銷的憑證：沒有核銷就沒有一次綁定')
    WHERE NOT EXISTS (SELECT 1 FROM guest_bind_tickets t
                      WHERE t.id = NEW.ticket_id AND t.consumed_at IS NOT NULL);
END;

-- 8) 最後一條：正文引用父表名，必須等 accounts 正名完成後才建（見 0007 檔頭「必踩的坑」）。
CREATE TRIGGER account_server_roles_guest_no_role
    BEFORE INSERT ON account_server_roles
BEGIN
    SELECT RAISE(ABORT, '訪客帳戶不可持有伺服器級角色（無憑據卻有權限不是合法形態）')
    WHERE EXISTS (SELECT 1 FROM accounts
                   WHERE accounts.id = NEW.account_id AND accounts.account_type = 'guest');
END;

-- 9) 搬移守衛：任何一條子行指不回父行，這條 INSERT 就會撞上 CHECK 並讓整支遷移回滾。
--    兩張新表此刻必然是空的（遷移不做任何回填），把它們也列進守衛是為了把
--    「遷移落地時四張子表都乾淨」這句話留成可查的事實，而不是靠人回憶。
CREATE TABLE guest_bind_migration_guard (
    orphan_rows INTEGER NOT NULL CHECK (orphan_rows = 0)
);
INSERT INTO guest_bind_migration_guard (orphan_rows)
    SELECT (SELECT COUNT(*) FROM sessions s
             WHERE s.account_id IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = s.account_id))
         + (SELECT COUNT(*) FROM account_server_roles r
             WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = r.account_id))
         + (SELECT COUNT(*) FROM guest_bind_tickets t
             WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = t.source_account_id)
                OR NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = t.target_account_id)
                OR NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = t.issued_by_account_id))
         + (SELECT COUNT(*) FROM guest_account_bindings b
             WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = b.source_account_id)
                OR NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = b.target_account_id));
DROP TABLE guest_bind_migration_guard;
