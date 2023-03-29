-- 活動標籤的定義（活動內業務的標籤一步：一組可复用的標記本身，不含誰被貼上哪個標籤）。
--
-- 表結構約定（DEC-011）：一般表（非 STRICT）；時間戳一律 INTEGER，Unix 毫秒 UTC。
-- 標識約定（DEC-014）：主鍵為 TEXT 36 字元小寫正規 UUIDv7，由 internal/idgen 產生。
--
-- 為什麼標籤是一張新表而不是 activities 的一欄、陣營的一欄或一張 JSON：
--   標籤有自己的身份（穩定標識）、自己的可編輯欄位、自己的可用性開關與自己的公開旗標，
--   未來的「給某個玩家貼上某個標籤」要指向「哪一個標籤」——那個被指向的必須是標識，
--   不能是名稱、顏色或陣列裡的第幾格。標籤與陣營是兩個正交的維度：一個陣營可以有多個標籤，
--   同一個標籤可以被貼在多個陣營的人身上，因此它既不是 activity_factions 的一欄
--   （那会把「標籤」限死成「一組一個」），也不是 activities 的一欄。
--
-- 標籤以穩定標識關聯唯一活動（本輪用戶決定，口徑同 0013）：
--   activity_id 是歸屬，且與主鍵一起由觸發器釘成不可就地改寫——「通用編輯改不了標籤 ID、
--   也挪不動歸屬活動」因此成立在資料庫結構上，而不是各端點的自律上。要改歸屬沒有通路：
--   那是把一個實體連同它的歷史搬到另一件事名下，屬身份遷移，本步不發明。
--
-- activity_id 對 activities 配硬外鍵（且不配 CASCADE，口徑同 0012 的指派表與 0013）：
--   被參照的是活動行，與帳戶身份無關——本表沒有任何指向 accounts 的欄位（貼標籤那张關係表
--   尚未落地），因此不觸發 internal/stdacct 綁定預檢的引用登記要求（見該檔引用清單；
--   日後出现指向 accounts 的欄位時必須在同一跳補登記與定向測試）。
--   不配 CASCADE 是因為活動永不物理刪除（歸檔是終態、行保留）。
--
-- 同活動內名稱唯一、跨活動同名互不相干（用戶批准：復用陣營那套已批准口径）：
--   UNIQUE (activity_id, name) 只約束一個活動之內；比對採 SQLite 預設的 BINARY（逐字相等，
--   不做大小寫折疊）。名稱不是身份鍵（id 才是），唯一約束只是操作者的防呆，不是外鍵——
--   將來的引用一律指向標識，改名不讓任何引用失效。
--
-- 沒有刪除通路，只有可用／停用（本輪用戶批准的推薦項，口徑同 0013）：
--   available 是「這個標籤此刻還能不能被使用」的一欄旗標，不是生命週期狀態機，因此並進
--   通用編輯白名單而不另設狀態子路徑。本表沒有任何物理刪除通路：標籤行「仍列、可讀、
--   可改旗標」，停用不搬動任何既有引用、不級聯清空歷史。日後若要真刪除，那是一次需要
--   單獨批准的資料處置決定，不是補一顆按鈕。
--
-- 公開旗標預設為 0（本輪用戶決定：標籤預設是管理員內部資訊，公開要一格一格明確配置）：
--   public 的每一行都是獨立決定，不是活動級開關——把整場活動一次性翻公開會讓「哪些標籤
--   被對外說過」這件事沒有逐筆留痕，也讓人無法只公開其中一兩個。出廠 0 讓既有與新建活動
--   都不未經批准就被開放（口徑同 0015 的 disabled、0016 的 hidden）。
--   這一欄只約束「普通玩家讀不讀得到這份定義」（見 internal/activity/tagcatalog.go），
--   它不是權限、不是角色，也不放寬任何可見性：它從不讓一個本來不在目錄裡的人变得可被查出，
--   也不讓任何人多得到一项能力。收回公開（1→0）不改寫任何既有引用，只讓下一次查詢不再列出它。
--
-- 圖標是封閉集合、顏色是緊格式（復用 0013 已批准的口径，不另發一套展示輸入）：
--   icon 只收本檔 CHECK 列出的內建標識鍵（空字串＝未選，界面以通用佔位圖標顯示）；
--   color 收空字串（未選色）或 # 加六位十六進位。完整校驗在域層（可點名欄位回 1004），
--   CHECK 只擋繞過域層的直寫。顏色與圖標都不單獨承載身份：名稱與標識才是，
--   界面不得只靠顏色辨認一個標籤。
--
-- 排序是一欄整數而不是整表重排端點（口徑同 0013）：sort_order 允許同值，同值時按建立時刻、
--   標識穩定破平。新建時不帶排序值由服務層在交易內現算「當前最大值加一」。
--
-- 欄位長度上界以 Unicode 字元計（SQLite length() 對 TEXT 回傳字元數），與 internal/activity
--   的域層校驗同口径（名稱沿用 64、描述沿用 500，與活動與陣營那兩份同一套數字）。

CREATE TABLE activity_tags (
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
    public      INTEGER NOT NULL DEFAULT 0 CHECK (public IN (0, 1)),
    created_at  INTEGER NOT NULL CHECK (created_at > 0),
    updated_at  INTEGER NOT NULL CHECK (updated_at >= created_at),

    -- 同活動內名稱唯一（跨活動同名互不相干，見檔頭）。
    UNIQUE (activity_id, name)
);

-- 列表讀法：一個活動的標籤按「排序值、建立時刻、標識」穩定呈現（同值破平寫在索引形狀上）。
CREATE INDEX activity_tags_activity_idx
    ON activity_tags (activity_id, sort_order, created_at, id);

-- 玩家那一側只按公開旗標筛過的讀法：public 恆被問到，因此與歸屬一起進索引。
CREATE INDEX activity_tags_public_idx
    ON activity_tags (activity_id, public, sort_order, created_at, id);

-- 身分與歸屬不可就地改寫：id 是實體身份，activity_id 是「這個標籤屬於哪一場活動」。
-- 改任何一欄都等於把一個實體連同它的歷史原地搬到別名下；指向它們的未來引用會留在舊值上。
CREATE TRIGGER activity_tags_no_update_identity
    BEFORE UPDATE OF id, activity_id ON activity_tags
BEGIN
    SELECT RAISE(ABORT, '標籤標識與歸屬活動不可就地改寫：id 是實體身份，activity_id 是歸屬');
END;
