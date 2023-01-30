-- 伺服器級「帳戶建立策略」的持久落點（規格 §5.2 的三個開關與自註冊模式）。
--
-- 為什麼是資料庫的一張單例表，而不是 config.yaml 的三個鍵：
--   這一項與 security.device_policy 那一類「部署者改檔、重啟生效」的參數不同——它是
--   Root 在已認證的界面上隨時可改的運作決定，而且改完必須立刻對下一個建立請求生效。
--   寫回 config.yaml 要嘛讓檔案與記憶體的現值各說各話（部署者在服務跑著時手工改檔），
--   要嘛讓每一次保存都重寫那份帶著 Root 憑據的檔案；兩者都不如把「策略」放在
--   與帳戶、授予、審計同一個事務邊界裡的資料庫：改動與其審計同生同滅，
--   逐請求現讀有權威值，重啟什麼都不必做就能讀回同一份事實。
--
-- 為什麼不復用 0001 的 server_settings 鍵值表：
--   那一張是「伺服器配置與版本」用的泛用 K/V，值欄是沒有形態約束的 TEXT。
--   本策略的取值是一個封閉枚舉加兩個布林，而「寫進去的值必須被結構擋住非法值」
--   正是這一項安全相關配置最需要的部分：把枚舉塞進 TEXT 值裡，約束就只剩應用層的自覺，
--   繞過應用層直寫資料庫的那條路（誤操作、外部工具）會留下一個誰也判讀不了的策略。
--
-- 三個值各自的意義（出廠全為最嚴的一側，與本表存在之前的行為逐字相同）：
--   admin_create_standard：管理員能否建立普通帳戶；
--   self_register_mode：用戶自註冊的模式（封閉集合，見下方 CHECK）；
--   guest_enabled：能否建立訪客（臨時）帳戶。
--   三個都是「策略值」，不是「能力」：對應的建立通路尚未實作時，把這裡改成放開
--   也不會讓任何對外入口真的可用（能力登記見 internal/acctpolicy）。
--
-- Root 建立管理員帳戶與本機憑據恢復（init-root／recover-root）不在這三個開關之下：
--   前者的依據是「只有 Root 能開管理員」這條已批准的授權邊界，後者的依據是
--   「能在伺服器主機上執行命令」，兩者都不讀本表，也不因這裡的任何值而改變。
--
-- 時間戳約定（DEC-011）：updated_at 為 Unix 毫秒 UTC，由注入時鐘在寫入時給，
--   呼叫端無權代填。0 是一個有意義的值：「這一列出廠以來根本沒人改過」——
--   遷移種下的這一行沒有「某一刻的修改」這個事實可記，拿套用遷移的時刻冒充
--   會讓日後查的人以為確實有人動過它。
--
-- 單例的釘法（規格要求「策略只有一份權威值」的結構形態）：
--   id 的 CHECK 讓這張表不可能有第二行；BEFORE DELETE 觸發器讓它不可能沒有行——
--   「行不見了」必須在 SQL 層就被擋死，否則讀取端就必須回答「沒有策略時算什麼」，
--   而任何答案都是一次憑空猜測的降級（猜最寬等於出廠即開放自註冊，猜最嚴等於
--   把一次資料庫缺陷說成 Root 的決定）。
--   UPDATE 只能改三個值與 updated_at：改 id 等於把單例換了對象，一並擋掉。

CREATE TABLE account_creation_policy (
    id                     INTEGER PRIMARY KEY CHECK (id = 1),
    admin_create_standard  INTEGER NOT NULL DEFAULT 0 CHECK (admin_create_standard IN (0, 1)),
    self_register_mode     TEXT NOT NULL DEFAULT 'closed'
        CHECK (self_register_mode IN ('closed', 'open', 'approval', 'invite')),
    guest_enabled          INTEGER NOT NULL DEFAULT 0 CHECK (guest_enabled IN (0, 1)),
    updated_at             INTEGER NOT NULL DEFAULT 0 CHECK (updated_at >= 0)
);

-- 出廠默認值：三個建立入口全關、自註冊模式 closed。
-- 這正是本表存在之前伺服器的真實行為（除 Root 外沒有任何通路能造出一個普通帳戶），
-- 因此種下這一行不改變任何對外可見能力，只是把「尚未決定」換成「決定為最嚴的一側」。
INSERT INTO account_creation_policy
    (id, admin_create_standard, self_register_mode, guest_enabled, updated_at)
    VALUES (1, 0, 'closed', 0, 0);

CREATE TRIGGER account_creation_policy_no_delete
    BEFORE DELETE ON account_creation_policy
BEGIN
    SELECT RAISE(ABORT, '帳戶建立策略行不可刪除：沒有策略時無人能誠實回答該放行什麼');
END;

CREATE TRIGGER account_creation_policy_no_id_update
    BEFORE UPDATE OF id ON account_creation_policy
BEGIN
    SELECT RAISE(ABORT, '帳戶建立策略是單例：改 id 等於換一個策略對象，不允許就地改寫');
END;
