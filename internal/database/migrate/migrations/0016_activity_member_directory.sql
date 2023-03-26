-- 活動玩家目錄的可見性配置（活動內業務第四步：「誰能在目錄裡看見誰」釘在兩張既有表上）。
--
-- 表結構約定（DEC-011）：一般表（非 STRICT）；本支只 ADD COLUMN 兩欄，不改寫任何舊行、
-- 不重建表、不動 0012／0014 已落地的欄位與觸發器，也不新增任何表。
--
-- 為什麼是「活動一欄 ＋ 成員一欄」而不是獨立設定表或映射表：
--   「這場活動的目錄對玩家開放多大範圍」是一場活動的属性，與 faction_select_mode（0015）
--   同一側；「這一個人要不要從同屏玩家的目錄裡收起來」是這一份活動內身份的屬性。
--   兩句各只有一個地方讀得到。另建設定表會讓「一場活動的目錄規則」出現兩個答案來源，
--   而本日也沒有需要第三張表的事實（可見性是既有兩行的屬性，不是新的一等實體）。
--
-- 四態而不是布林（本輪用戶批准）：
--   hidden（預設）：目錄對任何玩家都不列出任何人，包括他自己（本人經「我的資料」那一讀仍
--     讀得到自己的行——那是獨立的本人授權，與本表的活動規則無關）。
--   same_faction_only：只列同陣營的成員。無陣營（faction_id 為 NULL）不構成一個群體：
--     尚未分組的兩個人彼此不可見，只看得到自己（用戶批准於本輪，理由寫在 internal/activity
--     的目錄域頭注）。已批准態度「停用陣營的成員仍按同陣營互見」在这一態下照常成立：
--     判定看的是歸屬本身，不看 0013 的 available 旗標。
--   all_players_except_admin：列所有玩家，但把「此刻持有 server_admin 授予的那個人」收起來。
--     「管理員身分」的來源只有 internal/grant 那一張表（0006），永遠不是暱稱、顯示名或
--     任何前端標記——這一態是產品上「誰是後台的人」的隐藏手段，把判定寫成別的東西
--     會讓它變成一枚可被昵稱碰瓷的信號。
--   all_members：列這場活動的全部成員（涵蓋管理員身分的成員）。
--
-- 出廠值是 hidden 而且是 DEFAULT（本輪用戶批准的相容規則，口徑同 0015 的 disabled）：
--   ALTER TABLE ADD COLUMN 的 DEFAULT 讓既有每一行自動讀成「目錄不開放」。今天倉庫裡根本
--   沒有玩家目錄這條讀法，升級因此不該讓任何一場舊活動裡的人突然變得可被搜尋到；
--   管理人要開放，必須在活動配置裡明確選一個非 hidden 的值。
--   把預設設成 same_faction_only 等於在用戶不知情時向每一場活動開一個可見面。
--
-- 成員那一欄是「只能收緊」的覆蓋（本輪用戶批准的優先級）：
--   inherit（預設）＝服從活動那一側的規則；hidden＝在活動規則之外再多收起來一層。
--   集合裡刻意沒有 visible／public 這類放寬取值：一格能繞過整個活動規則的開關就不是覆蓋
--   而是第二套規則。收回活動規則（換成 hidden）也不會清掉任何人的覆蓋現值——配置只約束
--   往後讀得到什麼，不改寫已經寫下的事實（口徑同 0015 收回開關不清歸屬）。
--   這一欄從不約束管理視角：獲准管理該活動的人在目錄與名冊裡照樣看到全部成員。
--
-- CHECK 是封閉集合（口徑同 0012 的 status、0013 的 icon、0015 的模式）：
--   新增取值一律走新的遷移放寬清單，讓「玩家能被誰看見」的改變必然在版本史上留痕。
--   SQLite 的 ADD COLUMN 可帶表內 CHECK：新欄的 CHECK 對其後的每次插入與更新生效，
--   既有行由 DEFAULT 直接落在集合內（有定向測試釘住這兩件事，不靠「應該如此」）。
--
-- 沒有刪除通路，也沒有「清回未設定」：活動那一側的 hidden 與成員那一側的 inherit 就是兩句
--   可逆的話。本支不回填、不搬動任何人的陣營歸屬，也不碰 0014 那三條觸發器釘住的身份欄。

ALTER TABLE activities ADD COLUMN member_directory_mode TEXT NOT NULL DEFAULT 'hidden'
    CHECK (member_directory_mode IN
        ('hidden', 'same_faction_only', 'all_players_except_admin', 'all_members'));

ALTER TABLE activity_members ADD COLUMN directory_visibility TEXT NOT NULL DEFAULT 'inherit'
    CHECK (directory_visibility IN ('inherit', 'hidden'));
