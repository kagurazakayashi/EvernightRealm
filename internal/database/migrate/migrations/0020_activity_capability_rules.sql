-- 活動業務狀態的能力規則（活動內業務：狀態來源對六項能力的封鎖矩陣）。
--
-- 表結構約定（DEC-011）：一般表（非 STRICT）；時間戳一律 INTEGER，Unix 毫秒 UTC。
-- 標識約定（DEC-014）：活動主鍵為 TEXT 36 字元小寫正規 UUIDv7。
--
-- 為什麼規則落在資料庫而不是寫死在代碼裡：
--   「哪一種業務狀態封鎖哪幾項能力」是產品決定，不是部署常數；同一個活動可能
--   因為敘事規則不同而需要不同的組合。把它寫死會讓每一次調整都變成一次發版，
--   而把它做成通用腳本或規則語言則遠超本步批准的範圍。這裡的形狀刻意只有
--   七個內建狀態 × 六項能力的固定矩陣：每一格只回答「封鎖／不封鎖」，
--   沒有條件、沒有優先級、沒有腳本，也沒有第八種狀態或第七項能力的入口。
--
-- 兩張表的分工：
--   - activity_capability_rule_sets：一個活動至多一行，保存這份矩陣的
--     revision 與最後改動時刻。沒有這一行＝活動從未配置過，讀出廠預設
--     （revision 0）。revision 是編輯通路的比較-and-set 依據，也是回應裡
--     「你看到的是哪一版規則」的誠實標記。
--   - activity_capability_rules：七個狀態 × 六項能力 = 42 格。每一格都有一行
--     （含 denied=0 的允許格），於是「這份矩陣是否完整」可以由行數與主鍵核實，
--     不需要用「缺席即允許」的第二語意去猜。42 行對一場活動是小表。
--
-- 為什麼 status_key 只收七個內建鍵、自訂狀態不進這張表：
--   自訂狀態是活動內可變的定義，名稱由管理員自由填寫；若讓名稱參與能力判定，
--   就等於讓「取一個聽起來很兇的名字」自動得到一組封鎖語意，而那正是本步
--   明確禁止的「從名稱推測行為」。自訂狀態今日只被顯示，不拒絕任何能力；
--   要讓某個自訂狀態封鎖能力，那是一次新的、明確批准的功能，不是本表的空白格。
--
-- 與生命週期、手動限制、身份資格的關係（用戶批准的組合規則）：
--   本表只保存「狀態來源」的規則。手動限制仍是 activity_members 的六欄旗標；
--   活動停止／歸檔等生命週期限制由服務層現讀活動狀態決定，永遠不由這張表覆蓋；
--   帳戶／會話／成員失效是前置拒絕。判定時各來源並列，任何一個拒絕即拒絕，
--   解除其中一個不覆蓋另一個——這些都是服務層的規則，資料庫只保存狀態矩陣。
--
-- 與 accounts 的關係：本支兩張表都沒有指向 accounts 的欄位，只有指向 activities
--   的硬外鍵（活動永不物理刪除，故不配 CASCADE）。因此不觸發 internal/stdacct
--   綁定預檢的引用登記要求。

CREATE TABLE activity_capability_rule_sets (
    activity_id TEXT PRIMARY KEY CHECK (length(activity_id) = 36)
        REFERENCES activities (id),
    -- 從未配置時沒有行（讀成 revision 0 與出廠預設）；第一次寫入從 1 開始。
    revision    INTEGER NOT NULL CHECK (revision >= 1),
    updated_at  INTEGER NOT NULL CHECK (updated_at > 0)
);

CREATE TABLE activity_capability_rules (
    activity_id    TEXT NOT NULL CHECK (length(activity_id) = 36)
        REFERENCES activity_capability_rule_sets (activity_id),
    status_key     TEXT NOT NULL CHECK (status_key IN
        ('normal', 'suspended', 'eliminated', 'dead', 'arrested', 'offline', 'custom')),
    capability_key TEXT NOT NULL CHECK (capability_key IN
        ('login', 'chat', 'private_chat', 'trade', 'transfer', 'item_use')),
    denied         INTEGER NOT NULL CHECK (denied IN (0, 1)),

    -- 自訂狀態不參與能力矩陣：`custom` 只是「採用某個自訂定義」的標記，
    -- 定義名稱由管理員自由填寫，不能讓名稱推測出封鎖規則。服務層與
    -- internal/activity 的領域校驗也擋這一格；資料庫這一條守的是繞過應用層的直寫。
    CHECK (NOT (status_key = 'custom' AND denied = 1)),

    PRIMARY KEY (activity_id, status_key, capability_key)
);

-- 讀取一份矩陣時走這一條邊：按活動一次取回 42 格。
CREATE INDEX activity_capability_rules_activity_idx
    ON activity_capability_rules (activity_id, status_key, capability_key);
