package session

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// Store 是会话的领域服务兼持久仓储：创建、验证、撤销三个入口覆盖全部生命周期。
//
// 与 internal/account 同一取向：标识唯一产生点是 idgen（DEC-014）、时刻唯一来源是
// 注入的 timeutil.Clock（DEC-015）、秘密唯一产生点是 crypto/rand（见 secret.go），
// 三者都不接受呼叫端代填。所有方法收 database.Querier：*sql.DB 与 *Tx 皆可，
// 因此未来的登录用例能把「会话写入 + 审计追加」组合进同一个交易——
// 审计失败时会话行一起回滚，业务失败时也不会留下虚假的登录成功审计。
//
// 零值不可用，请经 NewStore 取得。
type Store struct {
	clock timeutil.Clock
	// ttl 是会话寿命：到期时刻在创建时定死（created + ttl），验证通过不延长。
	// 滑动续期与轮换属后续步骤，届时走「撤销旧会话 + 建新会话」，不改既有行。
	ttl time.Duration
	// newID 与 randReader 以字段持有是为了让测试注入失败情境，
	// 验证产生失败时拒绝创建而非降级（换 UUIDv4、换伪随机继续发会话都不可接受）。
	newID      func() (idgen.ID, error)
	randReader io.Reader
	accounts   *account.Store
}

// NewStore 建立会话仓储。
//
// clock 为 nil 时采用 timeutil.System()；ttl 必须为正——期限为零或负的会话
// 是一个「创建了就永远验证不过」的对象，那种装配错误要在建立仓储时当场报出来，
// 而不是等某个登录请求莫名其妙失败。上限组态（security.session_ttl_hours）
// 的读取属装配层（internal/app），本套件不认识组态结构体。
func NewStore(clock timeutil.Clock, ttl time.Duration) (*Store, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("session: 會話期限必須為正值，實際 %s", ttl)
	}
	if clock == nil {
		clock = timeutil.System()
	}
	return &Store{
		clock:    clock,
		ttl:      ttl,
		newID:    idgen.New,
		accounts: account.NewStore(clock),
	}, nil
}

// Create 为一个已认证的受信主体创建会话，回传会话实体与一次性秘密明文。
//
// 主体只可能来自 internal/identity：账户主体要真实账户构造过校验，Root 主体要
// VerifyRootCredential 比通过的证明——所以「创建 Root 会话」在类型层就要求
// 先完成 Root 凭据校验，不存在自报身份的旁路。通过之后这里仍会现读 accounts：
// Principal 里的状态是构造那一刻的事实，账户可能在同一时刻前后被禁用，
// 「校验成功后才创建」的判定以创建当时库里的状态为准。
//
// 失败路径不写任何东西：主体不合格、标识或秘密产生失败、INSERT 撞约束，
// 都回传错误且不留半行会话——登录成功这件事只有本方法回传成功才算数。
// 本方法也不改 accounts.last_login_at：那是登录用例在同一交易里写的事实，
// 会话仓储碰它就越过了「会话只回答谁在、登录回答何时登录」的分工。
func (s *Store) Create(ctx context.Context, q database.Querier, p identity.Principal) (Session, string, error) {
	if q == nil {
		return Session{}, "", errors.New("session: 需要可用的資料庫連線或交易")
	}
	subject, err := SubjectOf(p)
	if err != nil {
		return Session{}, "", err
	}
	if subject.kind == SubjectAccount {
		a, err := s.accounts.ByID(ctx, q, subject.accountID)
		if err != nil {
			if errors.Is(err, account.ErrNotFound) {
				return Session{}, "", fmt.Errorf("%w：帳戶不存在，不可建立會話", ErrSubjectUnavailable)
			}
			return Session{}, "", err
		}
		if a.Status != account.StatusActive {
			return Session{}, "", fmt.Errorf("%w：帳戶狀態 %q 不可建立會話（禁用帳戶視同不存在）",
				ErrSubjectUnavailable, string(a.Status))
		}
	}

	id, err := s.newID()
	if err != nil {
		return Session{}, "", fmt.Errorf("session: 產生會話標識失敗: %w", err)
	}
	deviceID, err := s.newID()
	if err != nil {
		return Session{}, "", fmt.Errorf("session: 產生設備標識失敗: %w", err)
	}
	secret, err := newSecret(s.randReader)
	if err != nil {
		return Session{}, "", err
	}
	tokenHash, err := hashSecret(secret)
	if err != nil {
		// newSecret 的产物必然过得了 hashSecret；走到这里代表实现有缺陷，
		// 宁可报错也不能把一枚「发得出去但形状可疑」的秘密交出去。
		return Session{}, "", fmt.Errorf("session: 會話秘密自我檢驗未通過: %w", err)
	}

	now := s.clock.Now()
	sess := Session{
		ID:           id,
		DeviceID:     deviceID,
		Subject:      subject,
		CreatedAt:    now,
		LastActiveAt: now,
		ExpiresAt:    now.Add(s.ttl),
	}
	_, err = q.ExecContext(ctx, `INSERT INTO sessions (
			id, device_id, token_hash, subject_kind, account_id,
			created_at, last_active_at, expires_at, revoked_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		sess.ID.String(), sess.DeviceID.String(), tokenHash,
		string(sess.Subject.kind), nullableID(sess.Subject.accountID),
		timeutil.ToMillis(sess.CreatedAt), timeutil.ToMillis(sess.LastActiveAt),
		timeutil.ToMillis(sess.ExpiresAt))
	if err != nil {
		return Session{}, "", fmt.Errorf("session: 寫入會話失敗: %w", err)
	}
	return sess, secret, nil
}

// Verify 用会话秘密验证实体：通过时回传会话并把最近活动时刻推进到现在。
//
// 判定顺序即安全顺序，每一步都可能拒绝：
//  1. 秘密形状与哈希查找——不合格与查无此秘密同样回 ErrInvalidSecret，不给差分信号；
//  2. 到期与撤销——到期时刻由创建定死，撤销由 Revoke 落库，两者都以服务器时钟为准；
//  3. 主体当前状态——账户主体现读 accounts.status，禁用或已不存在的账户，
//     哪怕会话行完好也一律 ErrSubjectUnavailable。「有会话记录」从来不是授权依据。
//
// 注意本方法会写一行 UPDATE（last_active_at），因此 Querier 必须可写；
// 把「验证」与「记录最近活动」合成一步，是为了让设备展示和未来的闲置策略
// 拿到的是服务器自己确认过的活动事实，而不是另一个需要记得调用的入口。
// UPDATE 带 revoked_at IS NULL 条件：读与写之间会话恰好被撤销时，
// 本次验证按撤销处理，不给「撤销命令之后又成功一次」留窗口。
func (s *Store) Verify(ctx context.Context, q database.Querier, secret string) (Session, error) {
	if q == nil {
		return Session{}, errors.New("session: 需要可用的資料庫連線或交易")
	}
	tokenHash, err := hashSecret(secret)
	if err != nil {
		return Session{}, err
	}
	sess, err := scanSession(q.QueryRowContext(ctx, selectSessionSQL+" WHERE token_hash = ?", tokenHash))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// 「查无此秘密」与「秘密形状不合格」必须收敛到同一个错误（见 ErrInvalidSecret 注释），
			// 不把 ErrNotFound 原样透出——那会告诉试探者「形状是对的，只差没这条记录」。
			return Session{}, ErrInvalidSecret
		}
		return Session{}, err
	}

	now := s.clock.Now()
	switch sess.State(now) {
	case StateRevoked:
		return Session{}, ErrRevoked
	case StateExpired:
		return Session{}, ErrExpired
	}
	if sess.Subject.kind == SubjectAccount {
		a, err := s.accounts.ByID(ctx, q, sess.Subject.accountID)
		if err != nil {
			if errors.Is(err, account.ErrNotFound) {
				return Session{}, fmt.Errorf("%w：帳戶已不存在", ErrSubjectUnavailable)
			}
			return Session{}, err
		}
		if a.Status != account.StatusActive {
			return Session{}, fmt.Errorf("%w：帳戶狀態 %q（會話存在不代表主體有效）",
				ErrSubjectUnavailable, string(a.Status))
		}
	}

	res, err := q.ExecContext(ctx,
		"UPDATE sessions SET last_active_at = ? WHERE id = ? AND revoked_at IS NULL",
		timeutil.ToMillis(now), sess.ID.String())
	if err != nil {
		return Session{}, fmt.Errorf("session: 更新最近活動失敗: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return Session{}, ErrRevoked
	}
	sess.LastActiveAt = now
	return sess, nil
}

// Revoke 按内部会话标识撤销一个会话，回传撤销后的实体。
//
// UPDATE 只在 revoked_at IS NULL 时生效：撤销不可逆，第二次撤销不再更新时刻，
// 也回传 ErrNotFound——「目标不存在或早已撤销」对调用端是同一个答案。
// 已过期的会话仍可撤销（写下行事实，便于审计与清理统一处理）。
func (s *Store) Revoke(ctx context.Context, q database.Querier, id idgen.ID) (Session, error) {
	if q == nil {
		return Session{}, errors.New("session: 需要可用的資料庫連線或交易")
	}
	if id.IsNil() {
		return Session{}, ErrNotFound
	}
	res, err := q.ExecContext(ctx, "UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
		timeutil.ToMillis(s.clock.Now()), id.String())
	if err != nil {
		return Session{}, fmt.Errorf("session: 撤銷會話失敗: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return Session{}, ErrNotFound
	}
	return scanSession(q.QueryRowContext(ctx, selectSessionSQL+" WHERE id = ?", id.String()))
}

// RevokeSubject 撤销某主体的全部未撤销会话，回传撤销数量。
//
// 这是为「凭据更换必须让所有旧设备重新登录」「管理员禁用账户前先停掉其会话」
// 这类流程预留的唯一入口：撤销的语义是数据事实，必须由服务端一条 UPDATE 完成，
// 不能指望每个调用端自己先列出会话再逐个撤销——那样漏一个就是一个还活着的会话。
// Root 主体没有账户标识，按 subject_kind 整体撤销（全服务只有一个 Root）。
func (s *Store) RevokeSubject(ctx context.Context, q database.Querier, subject Subject) (int, error) {
	if q == nil {
		return 0, errors.New("session: 需要可用的資料庫連線或交易")
	}
	if err := subject.validate(); err != nil {
		return 0, err
	}
	query := "UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL"
	args := []any{timeutil.ToMillis(s.clock.Now())}
	if subject.kind == SubjectAccount {
		query += " AND account_id = ?"
		args = append(args, subject.accountID.String())
	} else {
		query += " AND subject_kind = ?"
		args = append(args, string(SubjectRoot))
	}
	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("session: 撤銷主體會話失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("session: 讀取撤銷數量失敗: %w", err)
	}
	return int(n), nil
}

// ResolvePrincipal 驗證會話秘密，並把通過的結果換回一個受信主體。
//
// 這是「會話 → 身份」的唯一生產通路，存在的理由是傳輸層需要把一枚 Cookie／Bearer
// 換成 identity.Principal 才能進上下文與授權判定，而 Principal 的構造規則
// （帳戶要真實帳戶事實、Root 要憑據證明）不允許在包外拼裝：
//   - 帳戶主體：現讀 accounts 取類型與狀態後走 NewAccountPrincipal——Verify 已擋過
//     「不存在／禁用」，這裡再構造一次是雙閘而不是重複功課（讀與構造之間被禁用的競態
//     會在這裡被拒，方向和保守一致）；
//   - Root 主體：經 identity.ResumeRootProof 換發延續證明。正當性與使用邊界寫在該函式的
//     文件裡（會話行只能由帶著真實證明的 Create 簽發，token_hash 又不可變），
//     並由 internal/identity 的結構閘鎖在本包。
//
// Grants 一律為零值：伺服器級角色的授予資料來源至今不存在，解析結果因此不帶任何角色。
// 未來的授予表落地時，唯一要改的是這裡（把授予讀出來填入），各端點不會各長出一套
// 「從 Cookie 裡讀角色」的平行語意。
func (s *Store) ResolvePrincipal(ctx context.Context, q database.Querier, secret string,
	origin identity.Origin) (identity.Principal, Session, error) {
	sess, err := s.Verify(ctx, q, secret)
	if err != nil {
		return identity.Principal{}, Session{}, err
	}
	switch sess.Subject.kind {
	case SubjectRoot:
		p, err := identity.Root(identity.ResumeRootProof(), origin)
		if err != nil {
			return identity.Principal{}, Session{}, err
		}
		return p, sess, nil
	case SubjectAccount:
		a, err := s.accounts.ByID(ctx, q, sess.Subject.accountID)
		if err != nil {
			if errors.Is(err, account.ErrNotFound) {
				return identity.Principal{}, Session{}, fmt.Errorf("%w：帳戶已不存在", ErrSubjectUnavailable)
			}
			return identity.Principal{}, Session{}, err
		}
		p, err := identity.NewAccountPrincipal(identity.AccountInput{
			Subject: identity.SubjectOf(a),
			Origin:  origin,
		})
		if err != nil {
			return identity.Principal{}, Session{}, err
		}
		return p, sess, nil
	default:
		// scanSession 只可能帶出 root|account 兩類；走到這裡代表資料庫被寫進了
		// 本包不認識的狀態，屬缺陷而不是拒絕理由。
		return identity.Principal{}, Session{}, fmt.Errorf("%w：會話 %s 帶著無法解析的主體類別",
			ErrInvalidSubject, sess.ID.String())
	}
}

// selectSessionSQL 是会话列清单的唯一定义点（栏序与 scanSession 的取值顺序同源）。
const selectSessionSQL = `SELECT id, device_id, subject_kind, account_id,
		created_at, last_active_at, expires_at, revoked_at
	FROM sessions`

// scanSession 把一列读回实体。
//
// 标识读不回来、主体枚举不认识时一律报错：那代表数据库被绕过校验写入过东西
// （或执行档比数据库旧），静默跳过会让那条会话在验证里永远「查无秘密」，
// 把一个数据问题伪装成一个安全问题。
func scanSession(row *sql.Row) (Session, error) {
	var (
		idText, deviceText, kindText string
		accountID                    sql.NullString
		createdAt, lastActive        int64
		expiresAt                    int64
		revokedAt                    sql.NullInt64
	)
	err := row.Scan(&idText, &deviceText, &kindText, &accountID,
		&createdAt, &lastActive, &expiresAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("session: 讀取會話失敗: %w", err)
	}
	id, err := idgen.Parse(idText)
	if err != nil {
		return Session{}, fmt.Errorf("session: 會話標識無法解析（%s）: %w", idText, err)
	}
	deviceID, err := idgen.Parse(deviceText)
	if err != nil {
		return Session{}, fmt.Errorf("session: 設備標識無法解析（%s）: %w", deviceText, err)
	}
	subject := Subject{kind: SubjectKind(kindText)}
	switch subject.kind {
	case SubjectRoot:
		if accountID.Valid {
			return Session{}, fmt.Errorf("session: 會話 %s 的 Root 主體帶著帳戶標識", idText)
		}
	case SubjectAccount:
		if !accountID.Valid {
			return Session{}, fmt.Errorf("session: 會話 %s 的帳戶主體缺少帳戶標識", idText)
		}
		parsed, err := idgen.Parse(accountID.String)
		if err != nil {
			return Session{}, fmt.Errorf("session: 帳戶標識無法解析（%s）: %w", accountID.String, err)
		}
		subject.accountID = parsed
	default:
		return Session{}, fmt.Errorf("session: 會話 %s 帶著不認識的主體類別 %q", idText, kindText)
	}
	sess := Session{
		ID:           id,
		DeviceID:     deviceID,
		Subject:      subject,
		CreatedAt:    timeutil.FromMillis(createdAt),
		LastActiveAt: timeutil.FromMillis(lastActive),
		ExpiresAt:    timeutil.FromMillis(expiresAt),
	}
	if revokedAt.Valid {
		sess.RevokedAt = timeutil.FromMillis(revokedAt.Int64)
	}
	return sess, nil
}

// nullableID 把零值标识存成 NULL（与 audit 仓储同一约定：空值不冒充有效数据）。
func nullableID(id idgen.ID) any {
	if id.IsNil() {
		return nil
	}
	return id.String()
}
