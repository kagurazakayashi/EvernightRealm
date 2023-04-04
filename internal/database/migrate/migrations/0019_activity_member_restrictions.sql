-- 活動玩家的分項限制（活動內業務：六枚彼此獨立的限制旗標）。
--
-- 表結構約定（DEC-011）：一般表（非 STRICT）；時間戳一律 INTEGER，Unix 毫秒 UTC。
--
-- 為什麼是六欄旗標而不是一張限制表、也不是一個總 frozen 布爾：
--   - 六項限制（禁止登入、禁止聊天、禁止私聊、禁止交易、禁止轉賬、禁止使用物品）
--     各自的批准口徑是「一欄獨立事實」：每一欄可以單獨設定、單獨取消，
--     取消聊天限制不會順手取消私聊或登入限制。做成一張表會引入「一行缺席算什麼」
--     這種第二語意；做成一個總開關則直接抹掉六項之間的区别，兩邊都不是批准過的規則。
--   - 旗標是身分行的一欄，與 directory_visibility（0016）、business_status（0018）
--     同一形態：一行 activity_members 就是那份活動內身份的全部可編輯事實。
--
-- 相容遷移策略（出廠值 0＝不限制）：
--   ALTER TABLE ... ADD COLUMN ... NOT NULL DEFAULT 0 讓每一行既有 Profile 直接讀成
--   「沒被限制」，升級後不有任何人突然失去訪問資格，也不需要回填作業。
--   反方向（預設 1）會把「新增一欄」變成「全员被凍結」，那是相容遷移唯一不許犯的形態。
--
-- 六欄的分工與作用對象（用戶批准於本步）：
--   - restrict_login：禁止取得或繼續使用「該活動的訪問資格」。它不是全域帳戶停用：
--     不碰 accounts 表、不停用全域會話、不動其他活動；普通登入照舊可以建立全域會話，
--     随后進入該活動的受保護讀法由服務層現讀拒絕。作用點在 internal/activity，
--     不在本遷移（資料庫只保存事實，不判定通路）。
--   - restrict_chat／restrict_private_chat／restrict_trade／restrict_transfer／
--     restrict_item_use：五項業務在今日尚未實現，本步只交付統一的能力判定介面與
--     領域測試；這五欄今天只被保存、被如實顯示，沒有任何業務接入。
--
-- 沒有刪除與停用級聯：
--   限制只改這一行的這六欄；不改暱稱、不改陣營歸屬、不改目錄覆蓋、不改業務狀態，
--   也不動 accounts 的任何欄位。取消限制只是翻回 0，不恢復任何「當時被擋住的操作」
--   ——被擋住的請求從來沒有發生過，沒有效果可補。
--
-- 與 accounts 的關係：本支不新增表，六欄都在 activity_members 上；該表的 account_id
--   仍是 0014 的無外鍵軟參照，因此不觸發 internal/stdacct 綁定預檢的引用登記要求。

-- 禁止取得或繼續使用該活動的訪問資格（用戶批准：活動級，不停全域帳戶、不動其他活動）。
ALTER TABLE activity_members ADD COLUMN restrict_login INTEGER NOT NULL DEFAULT 0
    CHECK (restrict_login IN (0, 1));

-- 禁止聊天（業務未實現：本步只保存與顯示，判定介面供日後聊天通路呼叫）。
ALTER TABLE activity_members ADD COLUMN restrict_chat INTEGER NOT NULL DEFAULT 0
    CHECK (restrict_chat IN (0, 1));

-- 禁止私聊（與公開聊天分欄：取消一項不順手取消另一項，用戶批准）。
ALTER TABLE activity_members ADD COLUMN restrict_private_chat INTEGER NOT NULL DEFAULT 0
    CHECK (restrict_private_chat IN (0, 1));

-- 禁止交易（業務未實現：同上）。
ALTER TABLE activity_members ADD COLUMN restrict_trade INTEGER NOT NULL DEFAULT 0
    CHECK (restrict_trade IN (0, 1));

-- 禁止轉賬（與交易分欄：轉賬是賬本動作，批准口徑裡它不等於交易，同上）。
ALTER TABLE activity_members ADD COLUMN restrict_transfer INTEGER NOT NULL DEFAULT 0
    CHECK (restrict_transfer IN (0, 1));

-- 禁止使用物品（業務未實現：同上）。
ALTER TABLE activity_members ADD COLUMN restrict_item_use INTEGER NOT NULL DEFAULT 0
    CHECK (restrict_item_use IN (0, 1));
