-- 伺服器級角色的持久授予（Root 開設管理員帳戶的落點：把「哪個帳戶是伺服器管理員」寫進資料庫）。
--
-- 為什麼是一張獨立的授予表，而不是 accounts 加一個角色欄：
--   0003 的 accounts 表把欄位形態凍在跨欄 CHECK 與觸發器裡，SQLite 要動它的 CHECK
--   就必須重建整張表——把既有帳戶資料壓在一支增量遷移的路上，風險與收益不成比例。
--   授予是「帳戶 × 角色」的多對多事實：一個帳戶可以有零個或多個伺服器級角色，
--   主鍵 (account_id, role) 同時把「同一個角色不可能授予兩次」寫進結構本身，
--   而單欄形態只能表達一個角色，将来多一档角色就必然再来一次重建。
--
-- 主體邊界（與 internal/identity 同一套說法，不得在此放寬）：
--   Root 不是被授予出來的角色，它是主體類別、憑據屬 config.yaml，本表沒有 'root' 這個值；
--   活動內角色（活動管理員／玩家／NPC 操作者）屬活動作用域層，也不在這裡。
--   role 的 CHECK 是封閉集合：新增取值一律走新的遷移放寬清單，
--   這樣「主體能做的事變了」在版本史上必然留痕，而不是程式碼裡悄悄多一個字串。
--
-- 訪客帳戶不可持有角色（本表用觸發器把它釘在資料庫層）：
--   internal/identity 在構造主體時就拒「guest ＋ 任何角色」，但那是應用層的閘；
--   「無憑據卻有伺服器級權限」是權限形態的缺陷而不是格式瑕疵，值得在 SQL 層再擋一次
--   ——繞過應用層直寫資料庫的那條路（誤操作、外部工具）同樣必須擋住。
--
-- 外鍵刻意不配 CASCADE（與 0004 的 sessions 同一取向）：
--   物理刪除帳戶屬後續的帳戶管理步驟，屆時必須在同一個交易裡先顯式處理授予與會話——
--   「刪了人還留著一份查得出的特權授予」不該是資料庫預設就允許的寫法。
--   禁用帳戶（status='disabled'）不動本表：行保留、授予也保留，重新啟用時權限如前，
--   這與「禁用視同不存在但年資保留」的既有語意一致；生效與否由驗證時的現讀狀態決定。
--
-- 一行的生命週期只有「插入」與「刪除」兩種形態，沒有就地改寫：
--   UPDATE 主鍵任一段等於把「誰被授予了什麼」這條事實原地換掉，事後查不出原本是什麼，
--   因此觸發器擋住；改授予的正確表達是撤銷舊行（未來的帳戶管理步驟）再插入新行。
--
-- 時間戳約定（DEC-011）：granted_at 為 Unix 毫秒 UTC，取自注入時鐘，不接受呼叫端代填；
-- 它記錄的是「這筆授予何時写下」，不是「角色何時生效」——授予寫進這裡的那一刻就是生效點。
-- 標識約定（DEC-014）：account_id 是 accounts.id（TEXT 36 字元正規 UUIDv7）。

CREATE TABLE account_server_roles (
    account_id  TEXT NOT NULL REFERENCES accounts (id),
    role        TEXT NOT NULL CHECK (role IN ('server_admin')),
    granted_at  INTEGER NOT NULL CHECK (granted_at > 0),

    PRIMARY KEY (account_id, role)
);

-- 按角色反查（「伺服器的管理員有哪些」）走這條：role 等值後依授予時刻倒序，
-- 與 0002／0003 的「最新在前 + 標識破平」同一套路，讓最小列表不必額外排序。
CREATE INDEX account_server_roles_role_idx
    ON account_server_roles (role, granted_at DESC, account_id DESC);

CREATE TRIGGER account_server_roles_guest_no_role
    BEFORE INSERT ON account_server_roles
BEGIN
    SELECT RAISE(ABORT, '訪客帳戶不可持有伺服器級角色（無憑據卻有權限不是合法形態）')
    WHERE EXISTS (SELECT 1 FROM accounts
                   WHERE accounts.id = NEW.account_id AND accounts.account_type = 'guest');
END;

CREATE TRIGGER account_server_roles_no_update
    BEFORE UPDATE OF account_id, role ON account_server_roles
BEGIN
    SELECT RAISE(ABORT, '授予行不可就地改寫：改授予請撤銷舊行再插入新行');
END;
