-- 活動玩家的業務狀態（活動內業務：目前狀態、自訂狀態定義與顯示名稱覆蓋）。
--
-- 表結構約定（DEC-011）：一般表（非 STRICT）；時間戳一律 INTEGER，Unix 毫秒 UTC。
-- 標識約定（DEC-014）：主鍵為 TEXT 36 字元小寫正規 UUIDv7，由 internal/idgen 產生。
--
-- 為什麼狀態分三處而不是一張表：
--   - 「這個玩家此刻的業務狀態」是那份活動內身份(R4-003 的 activity_members)的一欄，
--     一個人只有一份檔案、也只需要一個目前狀態；把它拆成關係表會多出「同一個人同時有兩個
--     目前狀態」這種今天沒有任何業務語意的形態。
--   - 「自訂狀態」是一個活動內部可被反覆使用的具名定義，有自己的穩定標識、名稱與可用性；
--     它與內建狀態的語意不同，因此另立 activity_player_statuses。指向它的引用只有標識，
--     改名與停用都不讓引用失效。
--   - 「內建狀態的顯示名稱」是活動層級的展示覆蓋，不是新的狀態定義；一行一鍵（七個內建鍵
--     之一），沒有行或 display_name 為空字串都表示採用前端四語言的預設文案。
--     另立 activity_player_status_labels 讓「改顯示名」不會被誤讀成「改內部值」。
--
-- 內建穩定值（用戶批准，永不重命名、永不复用）：
--   normal／suspended／eliminated／dead／arrested／offline／custom
--   這七個鍵是跨活動的語意，不是活動內可自訂的枚舉。顯示名稱可以按活動覆寫，但內部值
--   不變；歷史與其它模組引用的是這個鍵或自訂定義的標識，不是顯示名稱。
--   offline 是管理員維護的業務狀態之一，與「連線在線」無關：本遷移不建任何心跳、
--   最後活動時間或連線狀態欄位，任何 HTTP 活躍度都不會自動改寫這一欄。
--
-- 單一目前狀態（用戶批准）：
--   activity_members.business_status 是七個內建鍵之一，出廠 normal；當它是 custom 時，
--   business_status_custom_id 必須非空並指向同一場活動的自訂定義；其餘六個鍵則必須為 NULL。
--   SQLite 的欄位 CHECK 看不見另一個欄位，因此這條成對規則由下方兩條觸發器釘住。
--   「自訂定義屬於同一場活動」也由觸發器釘住：外鍵只看定義存不存在，看不見跨活動拼接。
--
-- 自訂狀態只停用、不刪除（用戶批准的推薦項，口徑同 0013／0017）：
--   available 是「這個自訂狀態此刻還能不能被選用」的旗標，不是生命週期狀態機。
--   本表沒有物理刪除通路；停用不清空任何人的既有狀態、不級聯改寫歷史，雙向可逆。
--
-- 顯示名稱覆蓋沒有刪除語意：
--   display_name 為空字串代表「沒有覆蓋、使用四語言預設文案」，因此恢復預設只是把那一欄
--   清空，不是刪除一行。本表的主鍵（activity_id, status_key）與歸屬由觸發器釘成不可就地改寫。
--
-- 與 accounts 的關係：本支三張表都沒有指向 accounts 的欄位（成員表原有的 account_id
--   仍是 0014 的無外鍵軟參照），因此不觸發 internal/stdacct 綁定預檢的引用登記要求。

CREATE TABLE activity_player_statuses (
    id          TEXT PRIMARY KEY CHECK (length(id) = 36),
    activity_id TEXT NOT NULL CHECK (length(activity_id) = 36)
        REFERENCES activities (id),
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    available   INTEGER NOT NULL DEFAULT 1 CHECK (available IN (0, 1)),
    created_at  INTEGER NOT NULL CHECK (created_at > 0),
    updated_at  INTEGER NOT NULL CHECK (updated_at >= created_at),

    -- 同活動內名稱唯一（跨活動同名互不相干，口徑同 0013／0017）。
    UNIQUE (activity_id, name)
);

-- 自訂狀態列表：一個活動的定義按「建立時刻、標識」穩定呈現。
CREATE INDEX activity_player_statuses_activity_idx
    ON activity_player_statuses (activity_id, created_at, id);

-- 標識與歸屬不可就地改寫：id 是定義身份，activity_id 是「它屬於哪一場活動」。
-- 改名與停用只動 name／available／updated_at 三欄，引用者持有的標識不會失效。
CREATE TRIGGER activity_player_statuses_no_update_identity
    BEFORE UPDATE OF id, activity_id ON activity_player_statuses
BEGIN
    SELECT RAISE(ABORT, '自訂玩家狀態的標識與歸屬活動不可就地改寫');
END;

CREATE TABLE activity_player_status_labels (
    activity_id  TEXT NOT NULL CHECK (length(activity_id) = 36)
        REFERENCES activities (id),
    status_key   TEXT NOT NULL CHECK (status_key IN
        ('normal', 'suspended', 'eliminated', 'dead', 'arrested', 'offline', 'custom')),
    -- 空字串＝沒有覆蓋，使用前端四語言預設文案（見檔頭）。
    display_name TEXT NOT NULL DEFAULT '' CHECK (length(display_name) BETWEEN 0 AND 64),
    updated_at   INTEGER NOT NULL CHECK (updated_at > 0),

    PRIMARY KEY (activity_id, status_key)
);

-- 顯示名稱覆蓋的身份是（活動, 內建鍵）：改任何一欄都等於換了一個被覆蓋的目標。
CREATE TRIGGER activity_player_status_labels_no_update_identity
    BEFORE UPDATE OF activity_id, status_key ON activity_player_status_labels
BEGIN
    SELECT RAISE(ABORT, '玩家狀態顯示名稱的活動與內建鍵不可就地改寫');
END;

-- 成員目前的業務狀態：出廠 normal，既有 Profile 因此不需要「重置」就能讀到合法值。
ALTER TABLE activity_members ADD COLUMN business_status TEXT NOT NULL DEFAULT 'normal'
    CHECK (business_status IN
        ('normal', 'suspended', 'eliminated', 'dead', 'arrested', 'offline', 'custom'));

-- 只有 business_status = custom 時才允許非空，指向同一場活動的自訂狀態定義。
ALTER TABLE activity_members ADD COLUMN business_status_custom_id TEXT
    CHECK (business_status_custom_id IS NULL OR length(business_status_custom_id) = 36)
    REFERENCES activity_player_statuses (id);

-- 插入時的成對規則與同活動規則（欄位 CHECK 看不見另一個欄位，外鍵看不見活動歸屬）。
CREATE TRIGGER activity_members_custom_status_insert
    BEFORE INSERT ON activity_members
    FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, '業務狀態為 custom 時必須指向一個自訂狀態定義')
        WHERE NEW.business_status = 'custom' AND NEW.business_status_custom_id IS NULL;
    SELECT RAISE(ABORT, '業務狀態不是 custom 時不得帶自訂狀態標識')
        WHERE NEW.business_status <> 'custom' AND NEW.business_status_custom_id IS NOT NULL;
    SELECT RAISE(ABORT, '自訂狀態必須與成員同屬一場活動')
        WHERE NEW.business_status = 'custom' AND NEW.business_status_custom_id IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM activity_player_statuses s
                           WHERE s.id = NEW.business_status_custom_id
                             AND s.activity_id = NEW.activity_id);
END;

-- 更新時的同一組規則（日後的狀態變更通路走的是 UPDATE 這兩欄）。
CREATE TRIGGER activity_members_custom_status_update
    BEFORE UPDATE OF business_status, business_status_custom_id ON activity_members
    FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, '業務狀態為 custom 時必須指向一個自訂狀態定義')
        WHERE NEW.business_status = 'custom' AND NEW.business_status_custom_id IS NULL;
    SELECT RAISE(ABORT, '業務狀態不是 custom 時不得帶自訂狀態標識')
        WHERE NEW.business_status <> 'custom' AND NEW.business_status_custom_id IS NOT NULL;
    SELECT RAISE(ABORT, '自訂狀態必須與成員同屬一場活動')
        WHERE NEW.business_status = 'custom' AND NEW.business_status_custom_id IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM activity_player_statuses s
                           WHERE s.id = NEW.business_status_custom_id
                             AND s.activity_id = OLD.activity_id);
END;
