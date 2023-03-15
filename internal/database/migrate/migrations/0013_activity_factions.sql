-- 活動陣營（第三部分陣營管理一步：活動內的陣營實體，不含玩家在陣營間的分配）。
--
-- 表結構約定（DEC-011）：一般表（非 STRICT）；時間戳一律 INTEGER，Unix 毫秒 UTC。
-- 標識約定（DEC-014）：主鍵為 TEXT 36 字元小寫正規 UUIDv7，由 internal/idgen 產生。
--
-- 為什麼陣營是一張新表而不是 activities 的一欄或一張 JSON：
--   陣營有自己的身份（穩定標識）、自己的可編輯欄位與自己的可用性開關，未來成員分配要指向
--   「哪一個陣營」——那個被指向的必須是標識，不能是名稱或數組裡的第幾格。
--   一個活動有一組陣營（一比多），關係只能落在獨立表上。
--
-- 陣營以穩定標識關聯唯一活動（本輪用戶決定）：
--   activity_id 是歸屬，且與主鍵一起由觸發器釘成不可就地改寫——「通用編輯改不了陣營 ID、
--   也挪不動歸屬活動」因此成立在資料庫結構上，而不是各端點的自律上。要改歸屬沒有通路：
--   那是把一個實體連同它的歷史搬到另一件事名下，屬身份遷移，本步不發明。
--
-- activity_id 對 activities 配硬外鍵（且不配 CASCADE，口徑同 0012 的指派表）：
--   被參照的是活動行，與帳戶身份無關——本表沒有任何指向 accounts 的欄位，因此不觸發
--   internal/stdacct 綁定預檢的引用登記要求（見該檔引用清單；本表在 0013 之後如實補一行）。
--   「一行指向不存在活動的陣營」沒有可解釋的形態，值得讓資料庫直接攔住；
--   不配 CASCADE 是因為活動永不物理刪除（歸檔是終態、行保留），將來若真出現物理清理，
--   必須在同一交易裡顯式處理指向它的行，而不是讓預設替人做決定。
--
-- 同活動內名稱唯一、跨活動同名互不相干（本輪用戶批准的推薦項）：
--   UNIQUE (activity_id, name) 只約束一個活動之內：給名稱加全局唯一會把「兩個活動都設
--   『黎明軍』」這種完全合法的部署形態變成寫不進去；放同活動內重複則讓管理人在尚未落地
--   的分配介面裡對著兩個同名陣營只能靠標識區分。比對採 SQLite 預設的 BINARY（逐字相等，
--   不分大小寫折叠）：折疊規則（-titlecase、全半角）每加一分都在發明明稱號的重寫語意，
--   而那還沒被批准；名稱不是身份鍵（id 才是），唯一約束只是操作者的防呆，不是外鍵。
--   剔首尾空白屬域層正規化（見 internal/activity/faction.go），資料庫這層保住
--   「繞過域層的自傷也撞牆」。
--
-- 沒有刪除通路，只有可用／停用（本輪用戶批准的推薦項）：
--   available 是「這個陣營此刻還能不能被使用」的一欄旗標，不是生命週期狀態機——
--   它沒有四態那樣的合法路徑問題，因此並進通用編輯白名單而不另設狀態子路徑（同輪決定）。
--   本表沒有任何物理刪除通路：陣營行「仍列、可讀、可改可用旗標」；停用後的成員處置
--   要等成員落地才有可處置的對象（本步明確不做），今日一欄旗標就足以把這件事說清楚。
--   日後若要真刪除，那是一次需要單獨批准的資料處置決定，不是補一顆按鈕。
--
-- 排序是一欄整數而不是整表重排端點（本輪用戶批准的推薦項）：
--   sort_order 允許同值，同值時按建立時刻、標識穩定破平（見下方索引與 internal/activity
--   的列表讀法）。整表重排要把「依據值」攤在整張表上，兩個人同時拖動的語意要到處都是，
--   而一欄可 CAS 的數字沿用帳戶資料編輯那條已被驗證的通路形狀。上界 99999 讓回應與
--   比較成本不隨輸入數字膨脹；新建時不帶排序值由服務層在交易內現算「当前最大值加一」，
--   請求裡沒有格子能填「时刻」或「標識」。
--
-- 圖標是封閉集合、顏色是緊格式（本步自行決定的實作邊界，配合「不提前增加媒體上传、
--   远程图片或 CDN」的批准邊界）：
--   icon 只收本檔 CHECK 列出的內建標識鍵（空字串＝未選，界面以通用佔位圖標顯示）；
--   加新鍵走新遷移放寬清單，口徑同 0012 的狀態封閉集合。color 收空字串（未選色）
--   或 # 加六位十六進位；GLOB 用 SQLite 核心自帶語法，不依賴正則擴充。
--   兩者的完整校驗在域層（錯誤可點名欄位回 1004），CHECK 只擋繞過域層的直寫。
--   顏色不單獨承載身份：名稱與標識才是——這句是介面規則（根 AGENTS §7 與本步提示詞），
--   結構上無從表達，寫在這裡是為了讓改介面的人讀得到。
--
-- 欄位長度上界以 Unicode 字元計（SQLite length() 對 TEXT 回傳字元數），與
--   internal/activity 的域層校驗同口徑（名稱沿用活動的 64、描述沿用 500）。

CREATE TABLE activity_factions (
    id          TEXT PRIMARY KEY CHECK (length(id) = 36),
    activity_id TEXT NOT NULL CHECK (length(activity_id) = 36)
        REFERENCES activities (id),
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) BETWEEN 0 AND 500),
    icon        TEXT NOT NULL DEFAULT '' CHECK (
        icon IN ('', 'star', 'bolt', 'flame', 'wave', 'leaf', 'moon', 'sun', 'snow',
                 'drop', 'shield', 'storm', 'diamond', 'cloud', 'trophy', 'book', 'eye', 'anchor')
    ),
    color       TEXT NOT NULL DEFAULT '' CHECK (
        color = '' OR color GLOB
            '#[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]'
    ),
    sort_order  INTEGER NOT NULL DEFAULT 0 CHECK (sort_order BETWEEN 0 AND 99999),
    available   INTEGER NOT NULL DEFAULT 1 CHECK (available IN (0, 1)),
    created_at  INTEGER NOT NULL CHECK (created_at > 0),
    updated_at  INTEGER NOT NULL CHECK (updated_at >= created_at),

    -- 同活動內名稱唯一（跨活動同名互不相干，見檔頭）。
    UNIQUE (activity_id, name)
);

-- 列表讀法：一個活動的陣營按「排序值、建立時刻、標識」穩定呈現（同值破平寫在索引形狀上）。
CREATE INDEX activity_factions_activity_idx
    ON activity_factions (activity_id, sort_order, created_at, id);

-- 身分與歸屬不可就地改寫：id 是實體身份，activity_id 是「這個陣營屬於哪一場活動」。
-- 改任何一欄都等於把一個實體連同它的歷史原地搬到別名下；指向它們的未來引用會留在舊值上。
CREATE TRIGGER activity_factions_no_update_identity
    BEFORE UPDATE OF id, activity_id ON activity_factions
BEGIN
    SELECT RAISE(ABORT, '陣營標識與歸屬活動不可就地改寫：id 是實體身份，activity_id 是歸屬');
END;
