-- 活動成員與唯一玩家檔案（第三部分成員身份一步：一個帳戶在一場活動裡的那一份身份，不含陣營分配端點）。
--
-- 表結構約定（DEC-011）：一般表（非 STRICT）；時間戳一律 INTEGER，Unix 毫秒 UTC。
-- 標識約定（DEC-014）：主鍵為 TEXT 36 字元小寫正規 UUIDv7，由 internal/idgen 產生。
--
-- 為什麼成員是一張新表而不是 activities 的一欄或 accounts 的一欄：
--   「誰參加了哪場活動、在裡面叫什麼」是一件一比多的事：一個帳戶可以出現在多場活動裡，
--   一場活動有很多成員。塞進 activities 表達不了「哪一個人」，塞進 accounts 表達不了
--   「同一個人在兩個活動裡有兩份身份」——而後者正是本表存在的理由（0012 檔頭早就把這件事
--   寫成「後續 Membership 步的前提」）。
--
-- 單一權威關係（本輪用戶批准的推薦項：一張表，不拆兩張、不另建映射表）：
--   一行就是「那個人在那場活動裡的那一份身份」：id 是玩家在活動內的穩定標識（日後的資產、
--   聊天、帳務指向的是它，不是名稱也不是帳戶標識），activity_id 與 account_id 說明他屬於
--   哪場活動、是哪一個人，nickname 是他的活動內展示名，faction_id 是他此刻的陣營歸屬。
--   「一個玩家此刻只有一個陣營」因此成立在行結構上：歸屬只有這一格，不存在另一個可以
--   各說各話的映射表；「一個帳戶在一場活動裡只有一份檔案」由 UNIQUE (activity_id, account_id)
--   在資料庫層釘住，重複建立撞的是約束而不是約定的自律。
--   拆兩張表（membership ＋ profile）今日不會多出生任何能力，只會多出一種說不清的壞形態
--   （有 membership 卻查不到 profile），因此本輪否決。
--
-- 暱稱不施加唯一約束（本輪用戶批准的推薦項）：
--   身份只有 id 與 (activity_id, account_id)，暱稱是展示值。同活動內兩個玩家重名完全合法——
--   一個幾十上百人的 LAN 活動裡，強制重名即拒會把正常加入的人擋在門外，而改名從來不是
--   解決身份的辦法。這與陣營那一側不同（同活動陣營名稱唯一是用戶批准的防呆，因為陣營是
--   管理人精心命名的少數幾組），介面要靠標識與登入名分辨同一場活動裡的兩個同名玩家。
--   控制字元與長度上界屬域層校驗（見 internal/activity/member.go），這裡的 CHECK 只擋
--   繞過應用層的直寫。
--
-- Profile 只有暱稱一欄（本輪用戶批准的推薦項）：
--   不放頭像、不放自訂屬性、不放等級或積分、不放備註。本步沒有需要這些的用例，任何新欄
--   都要單獨批准並走新的遷移。
--
-- account_id 是無外鍵軟參照（本輪用戶批准的推薦項，口徑同 0012 的
--   created_by_account_id／activity_manager_grants.account_id）：
--   指向 accounts.id 但不寫 REFERENCES——歷史指向原標識，不搬不刪。帳戶經軟刪除（0007）
--   或綁定退休（0011）後行與標識仍在，這份參照永遠解析得到；名冊據此能把「這一行指向一個
--   已被刪除的帳戶」如實說出來，而不是藏起一行或改寫成別人。
--   刻意不配硬外鍵的理由與 0012 相同：配了就等於要求「訪戶被綁走時這張表怎麼辦」在本步
--   有一個身份遷移答案，而綁定的已批准合同是「未來歸屬只認目標帳戶，既有歷史不搬不刪」。
--   這句話不靠本註解自我聲明：internal/stdacct/bindpreflight.go 的實時掃描是邊界——本表
--   不在該檔的硬引用登記表裡，正是因為它對 accounts 沒有外鍵邊；日後誰把這一欄加上
--   REFERENCES，預檢當場把它當成未登記引用並整體 fail-closed，直到處置合同補齊為止。
--   因此「新增身份引用要立即保護帳戶軟刪除與 Guest 綁定」這一條在本表的落地形態是
--   兩句可執行的話：本表的行永不因綁定而被搬走或改寫（觸發器釘住 account_id），
--   而建立成員的通路在服務層拒絕對終態帳戶下寫入令（見 internal/activity/members.go）。
--
-- 訪戶可以成為活動成員（本輪用戶批准的推薦項）：
--   與 0012 擋「訪戶持有活動管理權」正好相反——那是權限，這是參加。訪戶是現場最常見的
--   臨時玩家身分，擋在門外等於把這群人排除在活動之外。他日後經原地升級（0011 之外的
--   upgrade 通路，標識不變）時這一行自動繼續有效；經綁定併入他人時這一行的處置見上一段。
--   持有 server_admin 授予的帳戶也可以是成員：成員身份從不賦予任何伺服器級權限，
--   兩套身份互不干涉，判定各問各的來源。
--
-- faction_id 可空、且配硬外鍵（本輪用戶批准的推薦項）：
--   空（NULL）是「尚未分組」這個事實本身，不拿零值 UUID 或空字串冒充一個陣營。允許無陣營
--   的理由有兩層：活動可以先加人後設陣營；而 0013 批准的停用語意是「禁止新分配＋保留既有
--   歸屬」，若歸屬必填，全停用時會出一個「既不能分進去、又不能留在原處」的硬缺口。
--   配硬外鍵（不配 CASCADE）是因為「一行指向從未存在的陣營」沒有可解釋的形態，值得讓資料庫
--   直接攔住；而陣營沒有物理刪除通路（0013），這條邊今日也不會被任何合法操作打破。
--   「指向不存在的陣營」與「指向另一場活動的陣營」是兩件事，後者外鍵看不見，因此由下方
--   兩條觸發器在 SQL 層補上——跨活動拼接在資料庫層就不成立，而不是各端點的自律。
--   今日沒有任何一條分配端點（那是下一步的批准範圍），本欄因此只有出生時為 NULL 一種現值。
--
-- 身份三欄不可就地改寫（觸發器）：
--   id 是玩家的活動內身份、activity_id 是他屬於哪場活動、account_id 他是哪一個人。
--   改任何一欄都等於把一個人連同他的歷史原地搬到別人名下或別場活動裡，而指向 id 的未來
--   引用會留在舊值上。正確表達是「移出舊行＋建立新行」，而移出本步未批准，因此今日
--   這一族路徑上既沒有 DELETE 也沒有改身份。暱稱是唯一可編輯的資料欄（見 updated_at 那對）。

CREATE TABLE activity_members (
    id          TEXT PRIMARY KEY CHECK (length(id) = 36),
    activity_id TEXT NOT NULL CHECK (length(activity_id) = 36)
        REFERENCES activities (id),
    -- account_id：無外鍵軟參照（見檔頭）。長度 CHECK 保證它永遠解析得回一個正規標識。
    account_id  TEXT NOT NULL CHECK (length(account_id) = 36),
    nickname    TEXT NOT NULL CHECK (length(nickname) BETWEEN 1 AND 64),
    -- faction_id：可空＝尚未分組（見檔頭）；不空時由兩條觸發器保證與本行同屬一場活動。
    faction_id  TEXT CHECK (faction_id IS NULL OR length(faction_id) = 36)
        REFERENCES activity_factions (id),
    created_at  INTEGER NOT NULL CHECK (created_at > 0),
    updated_at  INTEGER NOT NULL CHECK (updated_at >= created_at),

    -- 一個帳戶在一場活動裡只有一份檔案：「唯一 Profile」的結構保證。
    UNIQUE (activity_id, account_id)
);

-- 名冊讀法：一個活動的成員按「加入時刻、標識」穩定呈現（UUIDv7 本身按時間單調，
-- 末位破平讓同一毫秒寫入的兩行也有確定順序）。
CREATE INDEX activity_members_activity_idx
    ON activity_members (activity_id, created_at, id);

-- 身份三欄不可就地改寫：id／activity_id／account_id 是這一行「是誰、在哪場活動、
-- 是哪一個人」的全部答案，改任何一欄都不是編輯而是換了一個主體。
CREATE TRIGGER activity_members_no_update_identity
    BEFORE UPDATE OF id, activity_id, account_id ON activity_members
BEGIN
    SELECT RAISE(ABORT, '成員標識、所屬活動與帳戶指向不可就地改寫：要換人請移出舊行並新建（本版本未開放）');
END;

-- 陣營歸屬不得跨活動拼接（寫入那一跳）：faction_id 不空時，它必須指向一個確實屬於
-- 同一場活動的陣營。外鍵只看「那個陣營存不存在」，這一句是它看不見的部分。
CREATE TRIGGER activity_members_faction_same_activity
    BEFORE INSERT ON activity_members
    FOR EACH ROW
    WHEN NEW.faction_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, '成員歸屬的陣營必須屬於同一場活動：跨活動拼接不是合法形態')
        WHERE NOT EXISTS (SELECT 1 FROM activity_factions f
                           WHERE f.id = NEW.faction_id AND f.activity_id = NEW.activity_id);
END;

-- 同一條規則在更新那一跳也成立（日后的陣營分配通路走的是 UPDATE faction_id）：
-- 拿另一場活動的陣營標識寫進來時，資料庫當場擋下，不依賴呼叫端還記得先查一次。
CREATE TRIGGER activity_members_faction_same_activity_on_update
    BEFORE UPDATE OF faction_id ON activity_members
    FOR EACH ROW
    WHEN NEW.faction_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, '成員歸屬的陣營必須屬於同一場活動：跨活動拼接不是合法形態')
        WHERE NOT EXISTS (SELECT 1 FROM activity_factions f
                           WHERE f.id = NEW.faction_id AND f.activity_id = OLD.activity_id);
END;
