package session

import (
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// SubjectKind 是会话主体的类别（数据库栏 subject_kind）。
//
// 只有两类主体可以拥有会话：配置 Root 与 accounts 表里的账户。系统主体（启动、
// CLI、背景任务）没有「登录」这件事——它就是服务器自己，给它开会话等于伪造一个
// 不存在的认证过程；匿名主体还没通过认证，更无从谈起。
type SubjectKind string

const (
	// SubjectRoot 是配置来源的服务器级 Root（accounts 表外，见 R1-004 决定）。
	SubjectRoot SubjectKind = "root"
	// SubjectAccount 是 accounts 表中的某个账户；AccountID 必有值。
	SubjectAccount SubjectKind = "account"
)

// String 回传数据库/协议表示。
func (k SubjectKind) String() string { return string(k) }

// valid 回报是否为已定义类别。
func (k SubjectKind) valid() bool {
	switch k {
	case SubjectRoot, SubjectAccount:
		return true
	}
	return false
}

// Subject 是一个可拥有会话的受信主体：类别加可选的账户标识。
//
// 字段不导出，唯一的生产入口是 SubjectOf（从 internal/identity 的 Principal 换得）：
// Principal 本身已是「只有服务端能构造」的类型，Root 分支更是要经真实凭据比对才拿得到
// 证明。把这条链接到会话创建上，「凭空造一个 Root 会话」和「自报身份登录」在类型层
// 就没有通路，不靠调用端自觉。
type Subject struct {
	kind      SubjectKind
	accountID idgen.ID
}

// Kind 回传主体类别。
func (s Subject) Kind() SubjectKind { return s.kind }

// AccountID 回传账户标识；Root 主体回传零值，调用端不得拿零值当查询条件。
func (s Subject) AccountID() idgen.ID { return s.accountID }

// String 回传可安全写日志的摘要：只有类别与账户标识。
//
// 不含任何秘密材料——会话秘密的允许露出点只有 Create 的回传值一处。
func (s Subject) String() string {
	if s.kind == SubjectAccount {
		return fmt.Sprintf("%s(%s)", string(s.kind), s.accountID.String())
	}
	return string(s.kind)
}

// validate 检查类别与账户标识是否自洽（与迁移 0004 的跨栏 CHECK 同口径）。
func (s Subject) validate() error {
	if !s.kind.valid() {
		return fmt.Errorf("%w：不认识的会话主体类别 %q（仅 root|account）", ErrInvalidSubject, string(s.kind))
	}
	switch s.kind {
	case SubjectAccount:
		if s.accountID.IsNil() {
			return fmt.Errorf("%w：账户主体必须带账户标识", ErrInvalidSubject)
		}
	case SubjectRoot:
		if !s.accountID.IsNil() {
			return fmt.Errorf("%w：Root 主体不可带账户标识", ErrInvalidSubject)
		}
	}
	return nil
}

// SubjectOf 从受信主体换得会话主体。
//
// 匿名与系统主体一律拒绝（ErrInvalidSubject）：它们不是「还没登录的人」，
// 而是根本不存在登录这件事，降级放行等于给伪造会话留门。
func SubjectOf(p identity.Principal) (Subject, error) {
	switch p.Kind() {
	case identity.KindRoot:
		return Subject{kind: SubjectRoot}, nil
	case identity.KindAccount:
		return Subject{kind: SubjectAccount, accountID: p.AccountID()}, nil
	default:
		return Subject{}, fmt.Errorf("%w：%s 主体不可拥有会话（仅已认证的账户与 Root）",
			ErrInvalidSubject, p.Kind().String())
	}
}

// State 是会话的推导状态。
//
// 刻意不落库成栏位：revoked_at 与 expires_at 已经记录了全部事实，再存一份「状态」
// 就多出一个可以与事实不一致的栏位。账户禁用连推导都不算——它不属于会话本身，
// 只在每次验证时现读（见 Store.Verify）。
type State string

const (
	// StateActive 未到期且未撤销。
	StateActive State = "active"
	// StateExpired 已过到期时刻；撤销与否都以此为最终态的候选（先查撤销）。
	StateExpired State = "expired"
	// StateRevoked 已被撤销。撤销优先于到期展示：运维想知道的是「它被谁停的」。
	StateRevoked State = "revoked"
)

// String 回传状态的机器表示。
func (s State) String() string { return string(s) }

// IdleDeadline 回傳「閒置截止時刻」：最近活動之後沒有再動過，就在這個時刻失效。
//
// idleTTL 不為正（閒置判定關閉）時回傳零值，呼叫端以 IsZero 判別，不必自己記規則。
// 返回值一律不超過 ExpiresAt——這是「閒置截止、不延長絕對期」這條已批准語義的落點：
// 活動能把失效時刻往後推到閒置線，但永遠推不過建立時定死的絕對期限，
// 因此本方法不可能造出一個「一直動就永遠不退登」的會話。
func (s Session) IdleDeadline(idleTTL time.Duration) time.Time {
	if idleTTL <= 0 {
		return time.Time{}
	}
	deadline := s.LastActiveAt.Add(idleTTL)
	if deadline.After(s.ExpiresAt) {
		return s.ExpiresAt
	}
	return deadline
}

// Session 是一个服务端会话的领域实体，字段与 sessions 表一一对应（见迁移 0004）。
//
// 与迁移注释同一套三标识分工：ID 是内部主键、DeviceID 是用户可见设备标识、
// 认证秘密本体不在这里（库内只有其 SHA-256，见 secret.go）。
// 零值不可直接入库，请经 Store.Create 取得。
type Session struct {
	// ID 为内部会话标识（UUIDv7），不承担认证也不作展示名。
	ID idgen.ID
	// DeviceID 为用户可见设备标识（独立随机 UUIDv7），展示与按设备撤销用。
	DeviceID idgen.ID
	// Subject 为会话关联的受信主体。
	Subject Subject
	// CreatedAt 为建立时刻（服务器时钟，UTC）。
	CreatedAt time.Time
	// LastActiveAt 为最近一次验证通过的时刻；初值等于 CreatedAt。
	LastActiveAt time.Time
	// ExpiresAt 为到期时刻（Created 时按组态期限定死，之后不延长）。
	ExpiresAt time.Time
	// RevokedAt 为撤销时刻；零值表示从未撤销。
	RevokedAt time.Time
}

// State 按给定时刻推导会话状态；撤销优先于到期。
//
// 這裡只看絕對期限：閒置截止屬於策略（多長不動算閒置是組態決定），
// 不寫進實體自己的狀態推導，否則同一個實體在不同策略下會有兩套「狀態」事實。
// 需要含閒置的失效判定時呼叫 IdleDeadline（見 Store.Verify 的組合方式）。
func (s Session) State(now time.Time) State {
	switch {
	case !s.RevokedAt.IsZero():
		return StateRevoked
	case !now.Before(s.ExpiresAt):
		return StateExpired
	default:
		return StateActive
	}
}

// IsExpired 回报会话在给定时刻是否已过到期线（不含撤销判定，供清理类查询用）。
func (s Session) IsExpired(now time.Time) bool { return !now.Before(s.ExpiresAt) }

// String 回传可安全写日志的摘要：标识与状态，不含秘密。
func (s Session) String() string {
	return fmt.Sprintf("session(%s,%s)", s.ID.String(), s.Subject.String())
}

// 仓储与领域错误；呼叫端以 errors.Is 判定。
var (
	// ErrInvalidSubject 表示主体不可拥有会话（匿名、系统，或形态自相矛盾的会话主体）。
	ErrInvalidSubject = errors.New("session: 主体不可拥有会话")
	// ErrInvalidSecret 表示会话秘密不合格：格式不对、查无对应会话，统报这一个错误。
	//
	// 「格式错」与「哈希没查到」不分开，是因为对拿着秘密来验证的人而言两个答案
	// 都只会得到同一件事：拒绝。分开报不提供任何合法流程需要的信息。
	ErrInvalidSecret = errors.New("session: 会话秘密无效")
	// ErrRevoked 表示会话已被撤销。只有持有有效秘密的人才查得到这个答案，
	// 告知本人「你的会话被撤销了」是设备管理需要的信息，不是泄露。
	ErrRevoked = errors.New("session: 会话已被撤销")
	// ErrExpired 表示会话已到期。续期与轮换属后续步骤，一律走「建新会话」，
	// 不存在把过期会话改回有效的通路。
	ErrExpired = errors.New("session: 会话已到期")
	// ErrSubjectUnavailable 表示会话记录本身有效，但其主体当前不可用：
	// 账户已被禁用或已不存在。「会话还在就能继续操作」从设计上不成立，
	// 主体的有效性只以 accounts 表现读结果为准。
	ErrSubjectUnavailable = errors.New("session: 会话主体当前不可用")
	// ErrNotFound 表示按标识找不到可撤销的会话（不存在的，以及已被撤销的——
	// 撤销不可逆，第二次撤销没有新事实可写，报告目标不存在最接近真相）。
	ErrNotFound = errors.New("session: 会话不存在")
)
