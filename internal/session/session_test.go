package session

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
)

// TestSubjectOfAcceptsAuthenticatedPrinciples 验证只有账户与 Root 两类受信主体
// 能换成会话主体，且字段搬运正确。
func TestSubjectOfAcceptsAuthenticatedPrinciples(t *testing.T) {
	acctID := identitytest.NewID(t)
	acct := identitytest.Account(t, acctID)
	subject, err := SubjectOf(acct)
	if err != nil {
		t.Fatalf("帳戶主體應可換得會話主體：%v", err)
	}
	if subject.Kind() != SubjectAccount || subject.AccountID() != acctID {
		t.Fatalf("帳戶主體換得不正確：%+v", subject)
	}

	root := identitytest.Root(t, identity.OriginHTTPRequest)
	subject, err = SubjectOf(root)
	if err != nil {
		t.Fatalf("Root 主體應可換得會話主體：%v", err)
	}
	if subject.Kind() != SubjectRoot || !subject.AccountID().IsNil() {
		t.Fatalf("Root 主體應無帳戶標識：%+v", subject)
	}
	// Root 摘要不得混進任何憑據材料（identitytest 的一次性憑據只活在記憶體）。
	if strings.Contains(subject.String(), "$argon2id$") {
		t.Fatalf("主體摘要含憑據形狀：%s", subject.String())
	}
}

// TestSubjectOfRejectsNonLoginablePrinciples 钉住「匿名与系统主体不可拥有会话」：
// 它们不是「还没登录的人」，而是不存在登录这件事。
func TestSubjectOfRejectsNonLoginablePrinciples(t *testing.T) {
	cases := map[string]identity.Principal{
		"匿名":   identitytest.Anonymous(t),
		"系統":   identitytest.System(t, identity.OriginCLI),
		"啟動系統": mustSystem(t, identity.OriginStartup),
	}
	for name, p := range cases {
		subject, err := SubjectOf(p)
		if !errors.Is(err, ErrInvalidSubject) {
			t.Errorf("%s 主體應回 ErrInvalidSubject，實際 %v", name, err)
		}
		if subject.Kind() != "" || !subject.AccountID().IsNil() {
			t.Errorf("%s 主體失敗時應回零值主體：%+v", name, subject)
		}
	}
}

// mustSystem 构造系统主体（测试内辅助，失败即终止）。
func mustSystem(t *testing.T, origin identity.Origin) identity.Principal {
	t.Helper()
	p, err := identity.NewSystem(origin)
	if err != nil {
		t.Fatalf("構造系統主體失敗：%v", err)
	}
	return p
}

// TestSubjectValidate 检查会话主体形态的自洽性（与迁移 0004 的跨栏 CHECK 同口径）。
func TestSubjectValidate(t *testing.T) {
	realID := identitytest.NewID(t)
	cases := []struct {
		name    string
		subject Subject
		wantErr bool
	}{
		{"root 無帳戶標識", Subject{kind: SubjectRoot}, false},
		{"account 帶標識", Subject{kind: SubjectAccount, accountID: realID}, false},
		{"空類別", Subject{}, true},
		{"未知類別", Subject{kind: SubjectKind("player")}, true},
		{"account 缺標識", Subject{kind: SubjectAccount}, true},
		{"root 帶標識", Subject{kind: SubjectRoot, accountID: realID}, true},
	}
	for _, tc := range cases {
		err := tc.subject.validate()
		if (err != nil) != tc.wantErr {
			t.Errorf("%s：期望錯誤=%v，實際=%v", tc.name, tc.wantErr, err)
		}
		if err != nil && !errors.Is(err, ErrInvalidSubject) {
			t.Errorf("%s：錯誤應收斂到 ErrInvalidSubject：%v", tc.name, err)
		}
	}
}

// TestSessionStateDerivation 验证状态是推导值：撤销优先于到期，
// 且「正好到达到期时刻」按到期处理（now >= expires 即过期，没有含混的边界）。
func TestSessionStateDerivation(t *testing.T) {
	base := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	sess := Session{
		CreatedAt: base,
		ExpiresAt: base.Add(2 * time.Hour),
	}
	if got := sess.State(base.Add(time.Hour)); got != StateActive {
		t.Errorf("窗口內應為 active，實際 %s", got)
	}
	if got := sess.State(base.Add(2 * time.Hour)); got != StateExpired {
		t.Errorf("恰到到期時刻應為 expired，實際 %s", got)
	}
	if got := sess.State(base.Add(3 * time.Hour)); got != StateExpired {
		t.Errorf("過期後應為 expired，實際 %s", got)
	}
	// 撤销与到期同时成立时，展示撤销：运维想知道的是「它被谁停的」。
	revoked := sess
	revoked.RevokedAt = base.Add(time.Hour)
	if got := revoked.State(base.Add(3 * time.Hour)); got != StateRevoked {
		t.Errorf("撤銷應優先於到期，實際 %s", got)
	}
	if got := revoked.State(base); got != StateRevoked {
		t.Errorf("撤銷即刻生效，實際 %s", got)
	}
	if !sess.IsExpired(base.Add(2*time.Hour)) || sess.IsExpired(base.Add(time.Hour)) {
		t.Error("IsExpired 邊界不正確")
	}
}

// TestZeroValueStateFailClosed 确认零值会话推导为到期：
// 半初始化的对象不可能被当成有效会话，fail-closed 是默认而不是分支。
func TestZeroValueStateFailClosed(t *testing.T) {
	var s Session
	if got := s.State(time.Now().UTC()); got != StateExpired {
		t.Fatalf("零值 Session 應推導為 expired，實際 %s", got)
	}
	if !s.IsExpired(time.Now().UTC()) {
		t.Fatal("零值 Session 的 IsExpired 應為 true")
	}
}
