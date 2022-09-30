-- 會話秘密的就地輪換：把「換一枚秘密」從「新建一行」改成「同一行的秘密換代」。
--
-- 為什麼必須動上一支遷移的不可變觸發器：輪換要保住的是裝置身份——同一臺裝置換秘密
-- 不是多出一臺裝置，因此 device_id 與這一行都留在原處，只有驗證材料換掉。
-- 原觸發器用 BEFORE UPDATE OF device_id, token_hash 把兩欄一起擋死，等於把「換秘密」
-- 唯一合法的形態釘成「撤銷舊會話＋新建會話」；而新建一行必然撞 device_id 的 UNIQUE
-- 約束（舊行還要為維運留著「這枚憑據何時失效」的事實，不能當場刪）。兩邊都走不通時，
-- 就地換代加一個世代號是改動面最小的解法，不變量本身一個都沒鬆。
--
-- 兩個新欄位的分工：
--   rotation_seq         秘密的世代號：建立時為 0，每換發一枚新秘密恰好加一。
--                        它讓客戶端能判出一個回應描述的是「哪一代」憑據，
--                        因此倒序送達的舊回應不可能蓋掉手上更新的那一枚。
--   previous_token_hash  上一代的驗證材料：只用於把「拿著落後一代憑據來」與
--                        「憑據從來就無效」區分開（兩者都換不出任何身份，
--                        差別只在客戶端該重試還是該重新登入），不參與授權判定。
--                        它永遠換不來一枚新秘密，因此不構成舊憑據的有效期。
--
-- 觸發器把「合法形狀只有一種」寫進資料庫本身：動 token_hash 必須同時把 rotation_seq
-- 加一、並把舊雜湊留進 previous_token_hash，且新雜湊不得與舊值相同；反過來動
-- rotation_seq 也必須帶著一枚真的換掉了的雜湊。繞過應用層直寫資料庫仍然擋得住。
-- device_id 維持絕對不可變；expires_at 新增一條不可變觸發器——輪換只換秘密，
-- 絕不延長會話壽命（絕對期限在建立那一刻定死，這是既有語義的顯式化，不是新規則）。
--
-- ADD COLUMN 帶 NOT NULL DEFAULT 0：既有的每一行都還沒換過秘密，世代號本來就是 0，
-- 這是事實的還原而不是回填假資料；previous_token_hash 對同樣那些行是 NULL，
-- 「沒有上一代」與「上一代是某個雜湊」分得開。
-- 查落後一代憑據是一條按值查單行的路徑，故為它建部分索引（只收非 NULL 行）。

ALTER TABLE sessions ADD COLUMN rotation_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN previous_token_hash TEXT;

DROP TRIGGER sessions_security_no_update;

CREATE TRIGGER sessions_device_no_update
    BEFORE UPDATE OF device_id ON sessions
BEGIN
    SELECT RAISE(ABORT, 'sessions.device_id 建立後不可變：設備身份不隨秘密換代而改變');
END;

CREATE TRIGGER sessions_token_hash_rotation
    BEFORE UPDATE OF token_hash ON sessions
    WHEN NEW.rotation_seq IS NOT OLD.rotation_seq + 1
      OR NEW.previous_token_hash IS NOT OLD.token_hash
      OR NEW.token_hash IS OLD.token_hash
BEGIN
    SELECT RAISE(ABORT, 'sessions.token_hash 只能經輪換更新：必須同時把 rotation_seq 加一並留下舊哈希');
END;

CREATE TRIGGER sessions_rotation_seq_no_update
    BEFORE UPDATE OF rotation_seq ON sessions
    WHEN NEW.rotation_seq IS NOT OLD.rotation_seq + 1
      OR NEW.token_hash IS OLD.token_hash
BEGIN
    SELECT RAISE(ABORT, 'sessions.rotation_seq 世代號只能隨一枚新秘密一起加一');
END;

CREATE TRIGGER sessions_expires_at_no_update
    BEFORE UPDATE OF expires_at ON sessions
BEGIN
    SELECT RAISE(ABORT, 'sessions.expires_at 建立後不可變：輪換與活動都不延長絕對期限');
END;

CREATE INDEX sessions_previous_token_hash_idx
    ON sessions (previous_token_hash)
    WHERE previous_token_hash IS NOT NULL;
