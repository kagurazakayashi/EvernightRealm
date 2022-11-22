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

// Policy 是會話的有效期與清理策略。
//
// 各項彼此獨立，且都不由呼叫端代填「此刻」：期限與間隔屬組態決定，判定用的
// 當前時刻一律來自注入時鐘。零值代表「絕對期限之外全部沿用既有行為」——
// 閒置判定與寫入節流關閉，因此只給絕對期限的 NewStore 不會因新增欄位而改語意。
type Policy struct {
	// IdleTTL 是閒置有效期：距最近活動超過它即視同到期。0 或負值＝不啟用閒置判定。
	// 閒置只把失效時刻往前拉，永不延長絕對期限（見 Session.IdleDeadline）。
	IdleTTL time.Duration
	// TouchThreshold 是「最近活動時刻」落庫的最小間隔：距上次落庫超過它才寫一行
	// UPDATE，沒超過就只在記憶體推進。這是單寫鎖 SQLite 下的寫放大閘門——
	// 每個已認證請求都寫一行，等於把讀多寫少的會話表變成每請求一寫。
	// 0 或負值＝每次驗證都寫（沿用新增節流前的可觀察行為）。
	// 閒置截止因此以「最近一次落庫的活動時刻」起算：它最多比真實活動早一個閾值被判失效
	// （保守方向——不會讓一個本該閒置失效的會話多活），兩者必須一起配置。
	TouchThreshold time.Duration
	// CleanupGrace 是失效後的保留寬限期：過期或已撤銷的行再留這麼久才物理刪除。
	//
	// 這段窗口的對象是運維與未來的裝置清單，不是客戶端的提示：對拿著舊憑據的請求而言，
	// 「行還在但已失效」與「行已刪除」是同一個答案（查無此秘密與已到期都收斂為
	// ErrInvalidSecret，見 Verify），兩邊都不會因此收到不一樣的機器碼。
	// 寬限期真正保住的是「這一枚憑據是什麼時候失效的」這條事實還能被查到的時間；
	// 設 0 就是失效即刪，表最小，但剛失效的會話在運維側也一起消失。
	CleanupGrace time.Duration
	// DeviceMode 是裝置登入策略（一個主體能同時握有幾份有效會話）；空值＝DeviceModeMulti，
	// 即「並存且不封頂」，也就是本項存在之前的行為（見 internal/session/device.go）。
	// 零值沿用既有語意而不是挑一個更安全的規定：策略是組態決定，不該由倉儲構造代勞。
	DeviceMode DeviceMode
	// MaxDevices 是 DeviceModeLimited 下的名額（主體可並存的有效會話數）。
	// 只在 DeviceModeLimited 時要求正值；其它模式下這個欄位不參與任何判定。
	MaxDevices int
}

// Store 是會話的領域服務兼持久倉儲：建立、驗證、輪換、撤銷四個入口覆蓋全部生命週期，
// Cleanup 只刪除「服務端已認定失效、且過了寬限期」的記錄，不參與任何授權判定。
//
// 与 internal/account 同一取向：标识唯一产生点是 idgen（DEC-014）、时刻唯一来源是
// 注入的 timeutil.Clock（DEC-015）、秘密唯一产生点是 crypto/rand（见 secret.go），
// 三者都不接受呼叫端代填。所有方法收 database.Querier：*sql.DB 与 *Tx 皆可，
// 因此未来的登录用例能把「会话写入 + 审计追加」组合进同一个交易——
// 审计失败时会话行一起回滚，业务失败时也不会留下虚假的登录成功审计。
//
// 到期判定完全以庫內時刻為準（expires_at、revoked_at、last_active_at），
// 沒有任何程序內倒數計時：服務重啟後第一次驗證就能正確判出到期與閒置失效。
//
// 零值不可用，請經 NewStore 或 NewStoreWithPolicy 取得。
type Store struct {
	clock timeutil.Clock
	// ttl 是会话寿命：到期时刻在创建时定死（created + ttl），验证通过不延长。
	// 輪換（Rotate）同理只換秘密：絕對期限由遷移 0005 的觸發器釘住，
	// 閒置線又被絕對期限封頂，因此兩條通路都不可能把一個會話續命。
	ttl time.Duration
	// policy 是閒置有效期、活動寫入節流與清理寬限期；零值即「關閉／沿用既有行為」。
	policy Policy
	// newID 与 randReader 以字段持有是为了让测试注入失败情境，
	// 验证产生失败时拒绝创建而非降级（换 UUIDv4、换伪随机继续发会话都不可接受）。
	newID      func() (idgen.ID, error)
	randReader io.Reader
	accounts   *account.Store
}

// NewStore 建立會話倉儲：只有絕對期限，閒置判定與活動寫入節流都關閉。
//
// clock 为 nil 时采用 timeutil.System()；ttl 必须为正——期限为零或负的会话
// 是一个「创建了就永远验证不过」的对象，那种装配错误要在建立仓储时当场报出来，
// 而不是等某个登录请求莫名其妙失败。上限组态（security.session_ttl_hours）
// 的读取属装配层（internal/app），本套件不认识组态结构体。
func NewStore(clock timeutil.Clock, ttl time.Duration) (*Store, error) {
	return NewStoreWithPolicy(clock, ttl, Policy{})
}

// NewStoreWithPolicy 建立帶完整有效期與清理策略的會話倉儲。
//
// 策略的合法性在構造時當場校驗，不留到執行時：負值的閒置期限、節流間隔與寬限期
// 只會造成歧義（到底是「不啟用」還是「立即失效」？），而裝配錯誤應該在啟動階段
// 就拿到明確錯誤。寬限期允許為 0——那是「失效即刪」的運維選擇，語義清楚
// （放棄 2003 與 2002 的可區分性，換一張最小的表），不屬於裝配錯誤；
// 閒置與節流「不為正＝關閉」寫在 Policy 各欄自己的說明裡。
func NewStoreWithPolicy(clock timeutil.Clock, ttl time.Duration, policy Policy) (*Store, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("session: 會話期限必須為正值，實際 %s", ttl)
	}
	if policy.IdleTTL < 0 {
		return nil, fmt.Errorf("session: 閒置期限不可為負值（0 表示不啟用），實際 %s", policy.IdleTTL)
	}
	if policy.TouchThreshold < 0 {
		return nil, fmt.Errorf("session: 活動寫入節流間隔不可為負值（0 表示每次驗證都寫），實際 %s", policy.TouchThreshold)
	}
	if policy.CleanupGrace < 0 {
		return nil, fmt.Errorf("session: 清理寬限期不可為負值，實際 %s", policy.CleanupGrace)
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}
	if clock == nil {
		clock = timeutil.System()
	}
	return &Store{
		clock:    clock,
		ttl:      ttl,
		policy:   policy,
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

// Verify 用會話秘密驗證實體：透過時回傳會話，並按節流規則推進最近活動時刻。
//
// 判定顺序即安全顺序，每一步都可能拒绝：
//  1. 秘密形状与哈希查找——不合格与查无此秘密同样回 ErrInvalidSecret，不给差分信号；
//  2. 到期與撤銷——絕對到期時刻由建立定死，閒置截止以庫內 last_active_at 起算，
//     撤銷由 Revoke 落庫，三者都以伺服器時鐘為準；
//  3. 主体当前状态——账户主体现读 accounts.status，禁用或已不存在的账户，
//     哪怕会话行完好也一律 ErrSubjectUnavailable。「有会话记录」从来不是授权依据。
//
// 閒置判定是「讀庫內時刻比較」，不是倒計時：程序重啟、清理任務有沒有跑過，
// 都不改變第一次驗證就能正確判出失效這件事。
//
// 透過後的最近活動推進受 policy.TouchThreshold 約束：距上次落庫沒超過閾值時
// 只在回傳的實體上推進，不寫資料庫。這一條讓「每個已認證請求一寫」退回成
// 「每個會話每閾值一寫」；代價是閒置線以「上次落庫的活動時刻」為準，最多比真實活動
// 早一個閾值把會話判失效（往保守的那一侧偏），配置時兩者要一起決定。
// 真要寫時，UPDATE 帶 revoked_at IS NULL 條件：讀與寫之間會話恰好被撤銷時，
// 本次驗證按撤銷處理，不給「撤銷命令之後又成功一次」留窗口。
// 被節流跳過寫入的那一次沒有這層附加檢測——但本方法每次都先整行現讀，revoked_at
// 就在里面，所以撤销最迟在下一个请求就被拒；那条 UPDATE 条件一向只是把
// 「讀與寫之間」這幾微秒的窗口壓到最小，不是關掉窗口的機制。
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
			// 「查無此秘密」與「秘密形狀不合格」必須收斂到同一個錯誤（見 ErrInvalidSecret 註解），
			// 不把 ErrNotFound 原樣透出——那會告訴試探者「形狀是對的，只差沒這條記錄」。
			//
			// 唯一例外是「上一代」：這一枚確實換不出身份，但它的主人在剛發生過輪換的
			// 那條請求路上是常態，把兩者混為一談會讓客戶端把一次換密判成一次登出。
			// 判定只是多讀一欄索引查詢，絕不因此給出任何訪問能力。
			if s.matchesPreviousGeneration(ctx, q, tokenHash) {
				return Session{}, ErrStaleSecret
			}
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
	// 閒置截止與絕對期限共用 ErrExpired：客戶端要做的處置是同一件（重新登入），
	// 而「你多久沒動」屬於伺服器內部策略，不值得在對外的機器碼上分出一個可探測的類別。
	if deadline := sess.IdleDeadline(s.policy.IdleTTL); !deadline.IsZero() && !now.Before(deadline) {
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

	if s.shouldTouch(sess.LastActiveAt, now) {
		res, err := q.ExecContext(ctx,
			"UPDATE sessions SET last_active_at = ? WHERE id = ? AND revoked_at IS NULL",
			timeutil.ToMillis(now), sess.ID.String())
		if err != nil {
			return Session{}, fmt.Errorf("session: 更新最近活動失敗: %w", err)
		}
		if n, err := res.RowsAffected(); err == nil && n == 0 {
			return Session{}, ErrRevoked
		}
	}
	sess.LastActiveAt = now
	return sess, nil
}

// Rotate 用一枚當前的會話秘密換發一枚新秘密，世代號同時加一。
//
// 語義邊界就是「換密而不換命」這一件事：
//   - 同一行、同一個 device_id：同一臺裝置輪換秘密不是新增裝置，因此不佔用新的
//     裝置名額，也不讓使用者在將來的裝置清單裡看到兩個自己；
//   - expires_at 與 created_at 一個字都不動（資料庫另有觸發器把它釘死，見遷移 0005）：
//     輪換不是續期。絕對期限仍在，閒置線又被絕對期限封頂，兩條路都不可能把
//     一個本該失效的會話救回來；
//   - 舊秘密在提交的那一刻起徹底失效：庫裡不再有它的查詢鍵，換不出身份、
//     也換不來新秘密。失效邊界因此是一個點（那次 UPDATE 生效的瞬間），不是一段視窗。
//
// 原子性靠一條 UPDATE 完成全部換代（新雜湊、舊雜湊入 previous_token_hash、世代號加一、
// 推進最近活動），WHERE 帶著「還是舊那一枚、未撤銷、未過絕對期限、未過閒置線」四個條件：
// 讀與寫之間發生的任何撤銷、到期或並發輪換都會讓條件不成立，這次輪換就整個不發生，
// 不會出現「已撤銷的會話又拿到一枚新秘密」這種半套結果。SQLite 只有一個寫者，
// 這條語句本身即序列化點，不需要額外鎖。
//
// 前置檢查整個複用 Verify（形狀、存在、撤銷、絕對到期、閒置、主體可用性一個都不少），
// 不在這裡重寫一套判定——兩套判定遲早會有一種被繞過。主體狀態（帳戶被停用）無法寫進
// 這張表的 WHERE，它與 Verify 的活動寫入共用同一個「讀與寫之間」的微觀視窗：
// 停用最遲在下一個請求被拒，這裡不假裝能關掉那個視窗。
//
// 回傳的新秘密明文與 Create 同一個等級的機密：唯一的去處是傳輸層寫進 Set-Cookie，
// 不得進日誌、審計、錯誤訊息或回應 JSON 本體。
// 未命中任何行時（並發輸給對手、或剛被撤銷／到期）用同一枚舊秘密重跑一次 Verify，
// 把這次輪換按它本該得到的結論報回去，不另創一套錯誤分類。
func (s *Store) Rotate(ctx context.Context, q database.Querier, secret string) (Session, string, error) {
	if q == nil {
		return Session{}, "", errors.New("session: 需要可用的資料庫連線或交易")
	}
	oldHash, err := hashSecret(secret)
	if err != nil {
		return Session{}, "", err
	}
	sess, err := s.Verify(ctx, q, secret)
	if err != nil {
		return Session{}, "", err
	}

	newSecret, err := newSecret(s.randReader)
	if err != nil {
		return Session{}, "", err
	}
	newHash, err := hashSecret(newSecret)
	if err != nil {
		return Session{}, "", fmt.Errorf("session: 會話秘密自我檢驗未通過: %w", err)
	}

	now := s.clock.Now()
	// 世代號由資料庫自己加一（rotation_seq = rotation_seq + 1），不在這裡算好再寫：
	// 把算計留在語句內，綁架這條 UPDATE 的並發寫者就無法用一個過期的計數蓋掉事實。
	query := `UPDATE sessions
			SET token_hash = ?, previous_token_hash = ?, rotation_seq = rotation_seq + 1,
				last_active_at = ?
			WHERE id = ? AND token_hash = ? AND revoked_at IS NULL AND expires_at > ?`
	args := []any{newHash, oldHash, timeutil.ToMillis(now),
		sess.ID.String(), oldHash, timeutil.ToMillis(now)}
	if s.policy.IdleTTL > 0 {
		// 閒置線也進 WHERE，讓「Verify 讀到還活著、寫入時已閒置失效」這個視窗同樣關閉。
		// 寫成算術而不是把閒置秒數交給呼叫端：閾值是本倉儲的事實，只有這裡知道怎麼換算。
		query += " AND ? < last_active_at + ?"
		args = append(args, timeutil.ToMillis(now), s.policy.IdleTTL.Milliseconds())
	}
	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return Session{}, "", fmt.Errorf("session: 輪換會話秘密失敗: %w", err)
	}
	// 秘密明文不在錯誤、不在日誌：失敗路徑與成功時一樣，它唯一的去處是 Set-Cookie。
	n, err := res.RowsAffected()
	if err != nil {
		return Session{}, "", fmt.Errorf("session: 讀取輪換結果失敗: %w", err)
	}
	if n == 0 {
		if _, vErr := s.Verify(ctx, q, secret); vErr != nil {
			return Session{}, "", vErr
		}
		return Session{}, "", fmt.Errorf("session: 輪換未命中會話 %s", sess.ID.String())
	}
	rotated, err := scanSession(q.QueryRowContext(ctx, selectSessionSQL+" WHERE id = ?", sess.ID.String()))
	if err != nil {
		return Session{}, "", err
	}
	return rotated, newSecret, nil
}

// matchesPreviousGeneration 回報這枚雜湊是否是某一行的「上一代」驗證材料。
//
// 命中只改變拒絕的措辭（ErrStaleSecret 對 ErrInvalidSecret），不改變結論：
// 兩者都換不出身份。查無這一行、或該行的上一代已被下一次輪換擠掉，都是未命中。
func (s *Store) matchesPreviousGeneration(ctx context.Context, q database.Querier, tokenHash string) bool {
	var one int
	err := q.QueryRowContext(ctx,
		"SELECT 1 FROM sessions WHERE previous_token_hash = ? LIMIT 1", tokenHash).Scan(&one)
	if err != nil {
		return false
	}
	return true
}

// shouldTouch 回報本次驗證是否值得把最近活動時刻寫進資料庫。
//
// 閾值不為正＝沿用「每次都寫」；否則只有距上次落庫超過閾值才寫。
// 比較用「非正差值也寫」的保守方向：庫內時刻意外落後於當前時鐘（例如時鐘被
// 往前調過）時，多寫一行不是錯誤，少寫一行才會讓閒置判定一直停在舊時刻。
func (s *Store) shouldTouch(lastWritten, now time.Time) bool {
	if s.policy.TouchThreshold <= 0 {
		return true
	}
	return now.Sub(lastWritten) >= s.policy.TouchThreshold
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

// RevokeAllRootSessions 撤銷 Root 主體名下全部未撤銷的會話，回傳撤銷數量。
//
// 這是 RevokeSubject 的本機維護變體，存在的理由只有一件事：口令遺失後的憑據恢復
// 拿不出舊口令，因此也換不到 RootProof，而那恰恰是 SubjectOf 構造 Root 主體的必要條件。
// 換句話說，「恢復 Root 口令」這個用例在型別層就無法湊出自己需要撤銷的那批會話的
// 主體憑證——這不是缺口，而是它不需要的憑證：撤銷的授權依據是「持有資料庫單寫入實例鎖
// 的本機命令」，不是「已經以 Root 身分登進來」。
//
// 因此這裡刻意不收 Subject 也不收 Principal：主體由本套件內部凍結為 Root，呼叫端
// 沒有任何可以填錯或自報的東西（全服務只有一個 Root 主體，見遷移 0004 的 subject_kind
// 檢查）。除了撤銷自己一個函式都不做，不簽發憑據、不發會話、不回覆「我是 Root」。
//
// 已到期但尚未清理的 Root 會話照樣寫下 revoked_at（與 RevokeSubject 同口徑）：
// 恢復之後的審計要能說出「這次讓 N 臺裝置重新登入」，而統一收斂到「已撤銷」這個
// 最終態才算得出來。第二次呼叫回傳 0 而不是錯誤——沒有未撤銷的行就沒有要撤銷的東西。
func (s *Store) RevokeAllRootSessions(ctx context.Context, q database.Querier) (int, error) {
	return s.RevokeSubject(ctx, q, Subject{kind: SubjectRoot})
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

// Cleanup 刪除「已失效且過了寬限期」的會話記錄，回傳刪除行數。
//
// 刪除條件只有兩類，都以庫內時刻為準（不看程序內經過了多少時間）：
//   - 絕對到期：expires_at 已過去，且再過去 CleanupGrace；
//   - 已撤銷：revoked_at 已過去，且再過去 CleanupGrace。
//
// 閒置失效不在這裡單獨判定，也不是遺漏：閒置截止恆不超過絕對期限
// （見 Session.IdleDeadline），所以一條閒置失效的行必然已經過了絕對到期時刻，
// 會隨絕對到期那一批一起被刪掉。反過來，把「now - last_active_at > 閒置」寫進
// 刪除條件，等於在絕對期限之外再多出一個以「最後一次活動」起算的錨點，
// 同一件事就有兩個刪除時鐘，寬限期也再不能用一句话说清。
// expires_at 與 revoked_at 各自不早於（或晚於）created_at 由遷移 0004 的 CHECK 保證，
// 因此這兩個條件不需要再疊一層建立時刻的下界。
//
// 只刪 sessions 表，絕不碰任何審計表：清理的目標是「不再可能換出身份的憑據記錄」，
// 不是歷史事實。審計的保留策略屬日誌／運維那條線，不在本方法裡順帶處理。
//
// 單條 DELETE 完成整批：SQLite 下這天然是一個原子的寫操作，不需要也故意不做
// 分批遊標——會話行數由「活躍會話數＋寬限期內的失效行」封頂，量級不需要遊標分頁。
//
// Cleanup 是維護動作，不參與授權判定：入口的失效拒絕在 Verify 裡，
// 清理任務沒跑、跑失敗或還沒跑到，都不會讓一個失效憑據繼續換出身份。
// 刪除也換不來任何資訊增益：對客戶端而言「行還在但已過期」與「行已不存在」
// 是同一個拒絕理由（見 ErrInvalidSecret 與 ErrExpired 的收斂）。
func (s *Store) Cleanup(ctx context.Context, q database.Querier) (int, error) {
	if q == nil {
		return 0, errors.New("session: 需要可用的資料庫連線或交易")
	}
	cutoff := timeutil.ToMillis(s.clock.Now().Add(-s.policy.CleanupGrace))
	res, err := q.ExecContext(ctx,
		"DELETE FROM sessions WHERE expires_at <= ? OR (revoked_at IS NOT NULL AND revoked_at <= ?)",
		cutoff, cutoff)
	if err != nil {
		return 0, fmt.Errorf("session: 清理失效會話失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("session: 讀取清理數量失敗: %w", err)
	}
	return int(n), nil
}

// selectSessionSQL 是会话列清单的唯一定义点（栏序与 scanSession 的取值顺序同源）。
const selectSessionSQL = `SELECT id, device_id, subject_kind, account_id, rotation_seq,
		created_at, last_active_at, expires_at, revoked_at
	FROM sessions`

// rowScanner 是「掃描一行結果」的最小抽象：*sql.Row 與 *sql.Rows 都滿足它，
// 於是單行查詢（按秘密、按標識）與多行遍歷（裝置清單）共用同一份列解析，
// 欄序與取值順序只在 scanSession 一處定義，不會長成兩套會互相漂移的讀取。
type rowScanner interface {
	Scan(dest ...any) error
}

// scanSession 把一列读回实体。
//
// 标识读不回来、主体枚举不认识时一律报错：那代表数据库被绕过校验写入过东西
// （或执行档比数据库旧），静默跳过会让那条会话在验证里永远「查无秘密」，
// 把一个数据问题伪装成一个安全问题。
func scanSession(row rowScanner) (Session, error) {
	var (
		idText, deviceText, kindText string
		accountID                    sql.NullString
		rotationSeq                  int64
		createdAt, lastActive        int64
		expiresAt                    int64
		revokedAt                    sql.NullInt64
	)
	err := row.Scan(&idText, &deviceText, &kindText, &accountID, &rotationSeq,
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
		RotationSeq:  rotationSeq,
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
