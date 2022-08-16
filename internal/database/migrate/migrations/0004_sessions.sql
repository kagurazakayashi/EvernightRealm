-- 可撤销的服务端会话（R1-008 范畴：会话持久模型，不含登录端点与设备管理界面）。
--
-- 表结构约定（DEC-011）：一般表（非 STRICT）；时间戳一律 INTEGER，Unix 毫秒 UTC。
-- 标识约定（DEC-014）：主键为 TEXT 36 字元小写正规 UUIDv7，由 internal/idgen 产生。
--
-- 三个标识严格分工（本步决定，不得混用）：
--   id          内部会话标识：主键，供外键参照与运维定位，不承担认证，也不当展示名；
--   device_id   用户可见设备标识：独立随机 UUIDv7，展示与"撤销这台设备"用，
--                即使它泄露也换不来任何操作能力（认证只认秘密）；
--   token_hash  会话秘密的验证材料：SHA-256(不透明秘密) 的小写十六进位，
--                秘密本体永不落库——数据库整档外泄时攻击者拿到的哈希
--                无法反推秘密，也就无法复用任何会话。
-- 唯一索引只建在 token_hash（认证查找）与 device_id（用户端定位）上。
--
-- 主体形态（与 internal/identity 的受信主体对齐，只有两类可为会话主体）：
--   subject_kind='root'     配置 Root：account_id 必为 NULL（Root 不入 accounts 表，
--                            见 R1-004 决定；Root 的审计主体是保留常数列，与本表无关）。
--   subject_kind='account'  普通账户：account_id 必为非 NULL 且外键指向 accounts(id)。
--   外键不配 CASCADE：禁用账户靠状态挡验证（行保留），彻底删除账户属后续账户管理步骤，
--   届时必须先撤销其会话——"删了人还留着可验证的会话"不该是数据库默认允许的写法。
--
-- 状态是推导值而不是栏位：revoked_at 非 NULL 即已撤销，now >= expires_at 即已到期，
-- 其余为有效。多存一个 status 栏就会多出一个"和事实不一致"的机会；
-- 账户禁用更是每次验证现读 accounts.status（见 internal/session），绝不冻结进会话行。
--
-- 时间语义：
--   created_at      建立时刻（服务器时钟）；
--   last_active_at  最近一次验证通过的时刻，初值等于 created_at（"刚建好就被用"与
--                    "建立后一直没动"分得开：后者 last_active_at = created_at）；
--   expires_at      到期时刻 = created_at + 组态的会话期限，建立后不再改变
--                    （续期与轮换属后续步骤，走"撤销旧会话 + 建新会话"，不改既有行）；
--   revoked_at      撤销时刻；NULL 表示从未撤销。撤销不可逆，因此没有 un-revoke 路径。
--   CHECK 保证 expires_at 晚于 created_at（期限必为正）、撤销不早于建立、
--   最近活动不早于建立。验证通过的更新不会把 last_active_at 推过 expires_at：
--   到期行在应用层先被拒绝，落不到数据库上。
--
-- ID 稳定性：主键与两个安全标识由触发器挡 UPDATE——改主键等于改实体身份，
-- 换 device_id 会让用户端指不到自己的会话，换 token_hash 等于凭空发新秘密，
-- 三者都只允许"新建一行"来表达（0002/0003 的做法同源）。
--
-- 清理索引：expires_at 上的普通索引供未来的过期会话清理任务使用；
-- 本表记录只增不删是错的（会话寿命到期就是历史），但删除通路属未来的清理步骤，
-- 本迁移不假装有。

CREATE TABLE sessions (
    id             TEXT PRIMARY KEY CHECK (length(id) = 36),
    device_id      TEXT NOT NULL UNIQUE CHECK (length(device_id) = 36),
    token_hash     TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    subject_kind   TEXT NOT NULL CHECK (subject_kind IN ('root', 'account')),
    account_id     TEXT REFERENCES accounts (id),

    created_at     INTEGER NOT NULL CHECK (created_at > 0),
    last_active_at INTEGER NOT NULL CHECK (last_active_at >= created_at),
    expires_at     INTEGER NOT NULL CHECK (expires_at > created_at),
    revoked_at     INTEGER CHECK (revoked_at IS NULL OR revoked_at >= created_at),

    -- 主体形态成对锁定：root 必无 account_id、account 必有（与 0003 的跨栏 CHECK 同套路）。
    CHECK ((subject_kind = 'root' AND account_id IS NULL)
        OR (subject_kind = 'account' AND account_id IS NOT NULL))
);

-- 认证查找主路径就是 device_id 与 token_hash 上的 UNIQUE 索引（SQLite 为 UNIQUE
-- 约束自动建索引）：按秘密哈希单行命中，不另建重复索引。UNIQUE 同时保证
-- 两个会话不可能共享同一秘密。

-- 过期清理与运维查询按到期时刻扫；主体维度（"这个账户还有多少会话"）按 account_id。
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
CREATE INDEX sessions_account_id_idx ON sessions (account_id);

CREATE TRIGGER sessions_id_no_update
    BEFORE UPDATE OF id ON sessions
BEGIN
    SELECT RAISE(ABORT, 'sessions.id 是稳定标识：不得修改主键（改主键等于改实体身份）');
END;

CREATE TRIGGER sessions_security_no_update
    BEFORE UPDATE OF device_id, token_hash ON sessions
BEGIN
    SELECT RAISE(ABORT, 'sessions.device_id/token_hash 建立后不可变：换秘密等于新建会话，撤销旧会话');
END;
