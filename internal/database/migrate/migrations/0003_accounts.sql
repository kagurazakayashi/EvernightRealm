-- 通用帳戶模型（R1-004 範疇：持久模型與登入名唯一性約束，不含註冊／登入端點）。
--
-- 表結構約定（DEC-011）：一般表（非 STRICT）；時間戳一律 INTEGER，Unix 毫秒 UTC。
-- 標識約定（DEC-014）：主鍵為 TEXT 36 字元小寫正規 UUIDv7，由 internal/idgen 產生。
--
-- 登入名唯一性（本輪用戶決定）：
--   不區分大小寫 + Unicode NFKC 規範化。唯一性由 login_name_key 承載——鍵在 Go 域層
--   （internal/account）計算：NFKC → 全量大小寫對照折疊 → NFKC，資料庫不做二次解釋
--   （不用 SQLite NOCASE：它只覆蓋 ASCII，與域層規則不一致會造出兩個鍵）。
--   UNIQUE 索引把「查重再插入」的競態窗口關死：併發插入同鍵時由 SQLite 直接拒絕，
--   先查後插只是友善錯誤來源，從來不是正確性來源。
--   login_name 保留使用者原始寫法供展示；鍵與原值同表同行，改寫登入名時兩者一起改，
--   不存在「展示與唯一性分家漂移」的空間。
--
-- 刪除語意（本輪用戶決定，兩個級別）：
--   禁用（status='disabled'）：視同不存在但仍佔用登入名——行保留、鍵保留，
--     其他模組據 status 把它藏起來；年資與審計回溯都在。
--   徹底刪除：物理 DELETE 整行，登入名自然釋放可復用。審計／帳本屬另外兩張
--     只追加表（0002），不隨帳戶消失，本表不假裝能靠狀態欄表達「一切已毀」。
--   因此沒有 deleted_at／anonymized_at 欄：行不存在就是不存在，摆一個永遠
--     只服務已消失行的時間戳是自娛。disabled_at 則有意義（何时改的）。
--
-- Root 不入表（用戶決定）：Root 憑據的權威來源是資料目錄 config.yaml 的 Argon2id
--   雜湊（規格要求，見 internal/config），不搬進本表、不產生兩套可獨立修改的憑據。
--   日後統一可信主體時在 account_type 增值並補遷移，不在這裡預放一個無憑據的
--   'root' 值冒充整合——枚舉 CHECK 收緊容易放寬難，但增值走新遷移重建檢查即可。
--
-- Guest：允許無一般密碼，形態由 CHECK 凍結——account_type='guest' 時
--   password_hash 必為 NULL 且 must_change_password 必為 0（無密可改）。
--   Guest 註冊流程屬後續步驟，本表只保證放進來的是形態正確的 Guest。
--
-- 活動內的玩家暱稱屬於未來的 Activity Profile，與本表的登入名無關，
--   不承載任何全局唯一性；NPC 是活動身份、NPC Operator 不是全局帳戶角色，
--   本表不為它們開放枚舉值（防止「自報即生效」的假超管）。
--
-- ID 穩定性：主鍵由觸發器擋 UPDATE——改主鍵等於改實體身份，會把審計與帳本參照
--   留在舊值上（0002 的做法同源）。
--
-- 欄位长度上界以 Unicode 字元計（SQLite length() 對 TEXT 回傳字元數），
--   與 internal/account 的域層校驗同口徑；超長在插入前就被域層拒絕，
--   CHECK 只是把繞過域層的自傷擋在資料庫層。

CREATE TABLE accounts (
    id                   TEXT PRIMARY KEY CHECK (length(id) = 36),
    login_name           TEXT NOT NULL CHECK (length(login_name) BETWEEN 1 AND 64),
    login_name_key       TEXT NOT NULL CHECK (length(login_name_key) BETWEEN 1 AND 200),
    display_name         TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 64),
    -- 憑據雜湊：Argon2id 編碼字串（$argon2id$...）。可空是 Guest 的合法形態，
    -- 「標準帳戶必帶憑據、Guest 必無憑據」由下方跨欄 CHECK 成對鎖定。
    -- 雜湊不是秘密到不能落庫（它就是為落庫設計的單向形式），但絕不進日誌與審計。
    password_hash        TEXT CHECK (password_hash IS NULL OR length(password_hash) BETWEEN 1 AND 512),
    account_type         TEXT NOT NULL CHECK (account_type IN ('standard', 'guest')),
    status               TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1)),
    created_at           INTEGER NOT NULL CHECK (created_at > 0),
    -- last_login_at：從未登入為 NULL（不拿 created_at 冒充「上一次登入」）。
    last_login_at        INTEGER CHECK (last_login_at IS NULL OR last_login_at > 0),
    disabled_at          INTEGER CHECK (disabled_at IS NULL OR disabled_at > 0),

    -- 狀態一致性：disabled 與 disabled_at 同生同滅（重新啟用時一併清回 NULL）。
    CHECK ((status = 'disabled') = (disabled_at IS NOT NULL)),
    -- Guest 形態凍結：無憑據、無改密要求。
    CHECK (account_type <> 'guest' OR (password_hash IS NULL AND must_change_password = 0)),
    -- 標準帳戶憑據必填：與上一條成對，跨欄一致性在資料庫層也是封閉的，
    -- 域層校驗（internal/account.New）只負責給出可操作錯誤，不獨扛正確性。
    CHECK (account_type <> 'standard' OR password_hash IS NOT NULL),
    -- 時間單調：登入與禁用不可能早於帳戶誕生（時鐘回撥或程式寫錯都在此攔下）。
    CHECK (last_login_at IS NULL OR last_login_at >= created_at),
    CHECK (disabled_at IS NULL OR disabled_at >= created_at)
);

-- 唯一性只建在鍵上；login_name 原值刻意不建唯一索引——
-- 「Admin」與「admin」必須視為同一人，若原值也唯一等於開了第二套規則。
CREATE UNIQUE INDEX accounts_login_name_key_unique ON accounts (login_name_key);

-- 展示與後續查詢（如按顯示名搜尋）走建立時間倒序 + 標識破平，與 0002 同套路。
CREATE INDEX accounts_created_at_idx ON accounts (created_at DESC, id DESC);

CREATE TRIGGER accounts_id_no_update
    BEFORE UPDATE OF id ON accounts
BEGIN
    SELECT RAISE(ABORT, 'accounts.id 是穩定標識：不得修改主鍵（改主鍵等於改實體身份）');
END;
