-- 伺服器級「註冊邀請碼」的持久落點（規格 §5.2 的 invite 准入，本步只做簽發／列表／撤銷那一側）。
--
-- 這一張表負責的是「誰手握一張可以多出一個普通帳戶的憑證」，而不是「那個人是誰」：
--   邀請碼是建立伺服器普通帳戶的准入憑證，它不攜帶 Root／管理員權限，也不代表加入任何活動。
--   真正拿邀請碼換出一筆帳戶的那一跳（核銷）屬後續步驟，本支遷移先把「一枚碼長什麼樣、
--   被用掉幾次、有沒有被撤銷」這三件事的合法形態凍在資料庫層。
--
-- 為什麼只存代碼的雜湊、不存代碼本身（用戶批准的取向）：
--   邀請碼的明文只在簽發那一刻受控展示一次，之後誰都不該再拿到它——丟了就重新簽發一枚，
--   而不是把庫存起來的秘密翻出來給你看。因此表裡落的是這枚亂數值的 SHA-256（小寫十六進位、
--   定寬 64 字元），不是可直接複用的原文：整檔外洩也造不出可用的碼，而核銷是拿交來的原文
--   現算雜湊去比對，比得中才認。用 SHA-256 而非 Argon2id，與 internal/session 對會話秘密
--   同口徑：被雜湊的對象是一枚密碼學安全的隨機值、不是人想出來的口令，慢哈希換來的是每個
--   核銷請求都要付一次派生成本，而對隨機值它並不增加抗暴破的強度。口令側的 Argon2id 在
--   internal/credential，兩件事不互相頂替。
--
-- 為什麼是獨立一張表，而不是塞進 accounts：
--   accounts 的每一行都是「一個已經存在的穩定身分」；邀請碼不是身分，是「能不能長出一個身分」的
--   准入憑證。把兩者混在一張表裡，就等於讓一枚還沒換出任何人的代碼佔住一個帳戶標識與登入名，
--   而統一帳戶模型（0009）的整個前提是「一行 accounts 就是一個人」。
--
-- 有效期、額度與撤銷的取值語意（用戶批准於 R2-014）：
--   max_uses：一枚碼可被成功核銷幾次，恆 >= 1；1 即單次使用，不另開一個「是否單次」的布林——
--     那個說法會在兩處各記一份而遲早對不上。
--   used_count：已被核銷幾次，>= 0 且不得超過 max_uses（由 CHECK 與下面「只能一次加一」的觸發器
--     雙重凍結）。剩餘額度就是 max_uses - used_count，列表讀的是這個差值，不另存一欄。
--   expires_at：到期時刻（Unix 毫秒 UTC），0 表示永不過期（用戶批准：每枚可選到期、0=永不）。
--     非零時必須晚於簽發時刻。核銷那條 UPDATE 以「expires_at = 0 OR expires_at > 現值」為守衛。
--   revoked_at：撤銷時刻，0 表示尚未被撤銷。撤銷是單向的終態：一旦落下一刻就不能改判、
--     不能重新生效，撤銷後 used_count 也隨之凍結（已核銷的歷史必須留住）。
--   這四個取值沒有一個是「可被設定的狀態欄」：狀態（active／exhausted／expired／revoked）是
--     由這些事實加註入時鐘在讀取時派生出來的（用戶批准：讀時判定可用性，永不自動清理），
--     因此本表沒有一個 status 欄位可被寫壞、也不需要任何排程去翻動它。
--
-- 沒有簽發人欄，也沒有標籤之外的自由文本：簽發者是誰屬 root_audit 的事實（actor 由受信主體換得），
--   與 0009「沒有審核人欄」同一口徑。label 是唯一可展示的必要元數據（一句人話標籤，
--   長度與 accounts 兩欄同界，見域層校驗），不承載任何秘密。
--
-- 時間戳與標識約定不變（DEC-011／DEC-014／DEC-015）：Unix 毫秒 UTC、TEXT 36 字元小寫正規 UUIDv7，
--   created_at 取自注入時鐘、呼叫端無權代填。

CREATE TABLE registration_invite_codes (
    id          TEXT PRIMARY KEY CHECK (length(id) = 36),
    -- code_hash 是本表唯一帶秘密形狀的欄，而且存的已是雜湊、不是原文：
    -- UNIQUE 讓「同一枚碼被簽發兩次」在結構上不可能（隨機值碰撞本就可忽略，這條是把缺陷也擋住）。
    code_hash   TEXT NOT NULL UNIQUE CHECK (length(code_hash) = 64),
    label       TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 64),
    max_uses    INTEGER NOT NULL CHECK (max_uses BETWEEN 1 AND 1000000),
    used_count  INTEGER NOT NULL DEFAULT 0 CHECK (used_count BETWEEN 0 AND max_uses),
    created_at  INTEGER NOT NULL CHECK (created_at > 0),
    -- 0 是「這枚碼沒有到期這回事」這個事實本身（用戶批准：0=永不），不是查不到的時刻。
    expires_at  INTEGER NOT NULL DEFAULT 0 CHECK (expires_at >= 0),
    revoked_at  INTEGER NOT NULL DEFAULT 0 CHECK (revoked_at >= 0),

    -- 非零的到期時刻必須晚於簽發時刻：一枚「出生即已過期」的碼沒有一句誠實的說法，
    -- 它既不能被核銷、又會在下一次列表讀取時被派生成「已到期」，屬純粹的垃圾行。
    CHECK (expires_at = 0 OR expires_at > created_at),
    -- 撤銷時刻同理不可能早於簽發。
    CHECK (revoked_at = 0 OR revoked_at >= created_at)
);

-- 名冊依簽發時刻倒序（與 accounts／註冊申請名冊同一取向：最新的排最前，遊標分頁以 id 破平）。
CREATE INDEX registration_invite_codes_created_at_idx
    ON registration_invite_codes (created_at DESC, id DESC);

-- 標識是穩定主鍵：改 id 等於換一枚碼的對象，不允許就地改寫。
CREATE TRIGGER registration_invite_codes_id_no_update
    BEFORE UPDATE OF id ON registration_invite_codes
BEGIN
    SELECT RAISE(ABORT, 'registration_invite_codes.id 是穩定標識：不得修改主鍵（改主鍵等於改實體身份）');
END;

-- 驗證材料建立後不可變：換一枚碼的秘密不叫「編輯」，叫「重新簽發一枚」。
-- 這一條把「改 code_hash 冒充舊碼」與「洩了就去翻出原文再塞回去」兩條路一起關掉（表裡根本沒有原文）。
CREATE TRIGGER registration_invite_codes_hash_no_update
    BEFORE UPDATE OF code_hash ON registration_invite_codes
BEGIN
    SELECT RAISE(ABORT, 'registration_invite_codes.code_hash 建立後不可變：邀請碼丟失請重新簽發一枚，不就地換秘密');
END;

-- 簽發時定下、此後不動的元數據：有效期、額度上限、標籤、簽發時刻。
-- 本步沒有「編輯邀請碼」這條通路，把它們凍在 SQL 層，就不會有人順手開出一條改額度的路——
-- 而「把 max_uses 調大」正是一種未經審計的准入擴權。
CREATE TRIGGER registration_invite_codes_meta_no_update
    BEFORE UPDATE OF created_at, expires_at, max_uses, label ON registration_invite_codes
BEGIN
    SELECT RAISE(ABORT, '邀請碼的簽發事實（時刻、有效期、額度上限、標籤）建立後不可變：要改就重新簽發一枚');
END;

-- 新建的一枚碼必須是「一次都沒用過、且沒被撤銷」：
--   used_count > 0 等於簽發一枚天生就被用過的碼（那該是核銷那一步的事，不是建立時能自報的）；
--   revoked_at <> 0 等於憑空造一枚「已撤銷」的碼（撤銷只能發生在已存在的碼上）。
CREATE TRIGGER registration_invite_codes_insert_new
    BEFORE INSERT ON registration_invite_codes
BEGIN
    SELECT RAISE(ABORT, '新建邀請碼不得帶有已核銷次數：用掉幾次只能由核銷那一步寫入')
    WHERE NEW.used_count <> 0;
    SELECT RAISE(ABORT, '新建邀請碼不得直接帶有撤銷時刻：撤銷只能發生在已存在的碼上')
    WHERE NEW.revoked_at <> 0;
END;

-- 核銷計數只能一次加一：這正是核銷那條 UPDATE 的併發合同在 SQL 層的寫法。
-- 它同時擋掉三種非法改動——一次跳兩格（湊雨量的併發核銷竄改計數）、往回減（把已用的歷史抹掉）、
-- 以及超出 max_uses 的寫法（另一側由 CHECK 兜住）。
CREATE TRIGGER registration_invite_codes_used_monotonic
    BEFORE UPDATE OF used_count ON registration_invite_codes
    WHEN NEW.used_count <> OLD.used_count + 1
BEGIN
    SELECT RAISE(ABORT, 'registration_invite_codes.used_count 只能隨一次成功核銷加一：不得跳號、不得回減');
END;

-- 撤銷是終態：一刻落庫之後，這行不再有任何可寫的東西——
--   不能被重新生效（revoked_at 改回 0 或換個時刻）、不能被再核銷（used_count 不許再動）。
-- 撤銷之後留下的已核銷次數屬必要歷史，因此這行不刪、也不許改寫既有事實。
CREATE TRIGGER registration_invite_codes_revoked_terminal
    BEFORE UPDATE ON registration_invite_codes
    WHEN OLD.revoked_at <> 0 AND (
        NEW.revoked_at IS NOT OLD.revoked_at
     OR NEW.used_count IS NOT OLD.used_count
    )
BEGIN
    SELECT RAISE(ABORT, '邀請碼的撤銷態是終態：已撤銷的碼不得重新生效、不得再被核銷，也不得抹掉已核銷的歷史');
END;
