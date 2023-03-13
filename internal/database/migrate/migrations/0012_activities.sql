-- 活動實體與活動管理人指派（第三部分第一步：活動生命週期的持久落腳點，不含成員身份與陣營）。
--
-- 表結構約定（DEC-011）：一般表（非 STRICT）；時間戳一律 INTEGER，Unix 毫秒 UTC。
-- 標識約定（DEC-014）：主鍵為 TEXT 36 字元小寫正規 UUIDv7，由 internal/idgen 產生。
--
-- 為什麼活動是一張新表而不是 accounts 的一欄：
--   帳戶是「誰」，活動是「一件事」；兩者生命週期與唯一性規則都不同。把活動塞進帳戶行
--   會讓「同一個人在兩個活動裡有兩種身份」在結構上無法表達，而那正是後續 Membership 步的前提。
--
-- 名稱不是身份鍵、也不受唯一約束（本輪用戶決定）：
--   id 才是活動的穩定標識；name 可重複、可改，同名活動彼此無關。因此這裡沒有 UNIQUE(name)：
--   給一個「拿來代替身份」的唯一約束，等於鼓勵把名稱當外鍵用，還會讓「兩個活動都叫
--   《秋夜長談》」這種完全合法的部署形態變成寫不進去的錯誤。操作者靠 id 與列表區分它們。
--   活動內陣營的名稱規則屬陣營那一步，不在本表預設。
--
-- 狀態機的封閉集合（本輪用戶決定：四態，停止可逆、歸檔終態）：
--   draft（草稿）：已建立、尚未開放；允許業務寫入（陣營與資料在開放前就該能準備）。
--   active（開放）：正常進行中。
--   closed（停止）：業務寫入一律拒絕，但可回到 active——與帳戶「停用」同一取向：
--     停用不是刪除，恢復的只是「這件事還能不能繼續發生」，歷史一概保留。
--   archived（歸檔）：終態，不可逆，一律拒寫；行仍可讀（與 0007 的 deleted、0011 的 retired
--     同一「仍列、可讀、拒寫」口徑）。
--   CHECK 是封閉集合：新增取值一律走新的遷移放寬清單，這樣「活動能處於什麼形態」
--   的改變必然在版本史上留痕，而不是程式碼裡多一個字串。
--   階段／調度（主題、階段與調度）屬另一模組，不在本表放一個 status 冒充——
--   把「現在是第三階段」寫進 status 會讓上面那四態失去意義。
--
-- archived_at 與 archived 態成對（同生同滅）：
--   「何時歸檔」是歸檔這一跳留下的唯一時間事實，與狀態分開寫就會出現「狀態是 archived 而
--   時刻是 NULL」這種說不清發生過什麼的半成品行。closed 沒有對應時刻欄：它可逆，
--   一個「上次何時停止」的欄位會在每次往返後變成誰都不認識的現值；轉換歷史在 activity_audit。
--
-- 建立者與管理人一律無外鍵軟參照（本輪用戶決定）：
--   created_by_account_id 與 activity_manager_grants.account_id 指向 accounts.id，但都不寫
--   REFERENCES——口徑與 0002 的 root_audit／activity_audit 相同：歷史指向原標識，不搬不刪。
--   帳戶軟刪除（0007）保留行與標識，因此這份參照永遠解析得到；而若配成硬外鍵，
--   「訪戶綁定時這張表該怎麼處置」就成了本步必須回答的身份遷移問題（internal/stdacct 的
--   綁定預檢會把它當成未登記的引用並整體 fail-closed）。刻意選擇軟參照把這件事留在門外：
--   「誰建立了活動」「誰被指派為活動管理人」是要留痕的事實，不是待搬遷的歸屬。
--   這份選擇同時寫進 internal/stdacct/bindpreflight.go 的引用清單，不讓它成為沉默的例外。
--
-- activity_id 對 activities 配硬外鍵（且不配 CASCADE）：
--   被參照的是本步新建的活動行，與帳戶身份無關，因此不觸發上面那條綁定預檢規則；
--   而「一行指向不存在活動的管理人指派」沒有任何可解釋的形態，值得讓資料庫直接攔住。
--   不配 CASCADE 的理由與 0004／0006 一致：活動永不物理刪除（歸檔是終態、行保留），
--   將來若真出現物理清理，必須在同一交易裡顯式處理指向它的行，而不是讓預設替人做決定。
--
-- 訪戶不可持有活動管理權（與 0006 擋「訪戶＋伺服器級角色」同一形態要求）：
--   internal/identity 拒絕「guest ＋ 任何角色」，應用層也只在目標持有 server_admin 時才開放指派；
--   「無憑據卻對一個活動有管理權」是權限形態的缺陷而不是格式瑕疵，因此在 SQL 層再擋一次，
--   繞過應用層直寫資料庫的那條路（誤操作、外部工具）同樣必須擋住。
--
-- 指派行只有「插入」與「刪除」兩種形態，沒有就地改寫（與 0006 同取向）：
--   UPDATE 主鍵任一段等於把「誰管哪個活動」這條事實原地換掉，事後查不出原本是誰；
--   改指派的正確表達是撤銷舊行再插入新行，兩跳都各有審計。
--
-- 欄位長度上界以 Unicode 字元計（SQLite length() 對 TEXT 回傳字元數），
--   與 internal/activity 的域層校驗同口徑；超長在插入前就被域層拒絕，
--   CHECK 只是把繞過域層的自傷擋在資料庫層。

CREATE TABLE activities (
    id         TEXT PRIMARY KEY CHECK (length(id) = 36),
    name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) BETWEEN 0 AND 500),
    status     TEXT NOT NULL CHECK (status IN ('draft', 'active', 'closed', 'archived')),
    -- created_by_account_id：建立者。它是「這件事由誰發起」的歷史事實，不是權限依據——
    -- 管理權一律看 activity_manager_grants，建立者只是在建站那一跳被自動指派進去。
    -- 可空是 Root 建的活動：Root 不在 accounts 表裡（憑據屬 config.yaml），也沒有可填的帳戶標識，
    -- 拿零值 UUID 冒充「建立者」會讓这一格在事後讀不回任何人和任何意義。
    created_by_account_id TEXT CHECK (created_by_account_id IS NULL OR length(created_by_account_id) = 36),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    archived_at INTEGER CHECK (archived_at IS NULL OR archived_at > 0),

    -- 狀態一致性：archived 與 archived_at 同生同滅（歸檔那一跳一起寫、沒有解除歸檔這條路）。
    CHECK ((status = 'archived') = (archived_at IS NOT NULL))
);

-- 目錄讀法：按狀態篩選後「最新在前 + 標識破平」，與 0002／0003／0006 同一套路。
CREATE INDEX activities_status_idx
    ON activities (status, created_at DESC, id DESC);

-- 全量目錄（不帶狀態篩選）走這條：created_at 倒序，標識破平保證分頁穩定。
CREATE INDEX activities_created_at_idx
    ON activities (created_at DESC, id DESC);

-- 主鍵不可就地改寫：改主鍵等於改實體身份，會把指派與後續模組的外鍵留在舊值上。
CREATE TRIGGER activities_no_update_id
    BEFORE UPDATE OF id ON activities
BEGIN
    SELECT RAISE(ABORT, '活動主鍵不可就地改寫：id 是實體身份，改它等於換了一個活動');
END;

CREATE TABLE activity_manager_grants (
    activity_id TEXT NOT NULL CHECK (length(activity_id) = 36)
        REFERENCES activities (id),
    -- account_id 無外鍵（軟參照，見檔頭說明）：指向 accounts.id 的留痕式參照，
    -- 不搬不刪；帳戶被軟刪除後這一行仍解析得到那一個人，歷史不因刪除而改寫。
    account_id  TEXT NOT NULL CHECK (length(account_id) = 36),
    granted_at  INTEGER NOT NULL CHECK (granted_at > 0),

    PRIMARY KEY (activity_id, account_id)
);

-- 按帳戶反查「他管哪些活動」——活動作用域授權判定與活動目錄的可見範圍都走這條。
CREATE INDEX activity_manager_grants_account_idx
    ON activity_manager_grants (account_id, granted_at DESC, activity_id DESC);

CREATE TRIGGER activity_manager_grants_guest_no_manager
    BEFORE INSERT ON activity_manager_grants
BEGIN
    SELECT RAISE(ABORT, '訪戶帳戶不可持有活動管理權（無憑據卻有權限不是合法形態）')
    WHERE EXISTS (SELECT 1 FROM accounts
                   WHERE accounts.id = NEW.account_id AND accounts.account_type = 'guest');
END;

CREATE TRIGGER activity_manager_grants_no_update
    BEFORE UPDATE OF activity_id, account_id ON activity_manager_grants
BEGIN
    SELECT RAISE(ABORT, '指派行不可就地改寫：改指派請撤銷舊行再插入新行');
END;
