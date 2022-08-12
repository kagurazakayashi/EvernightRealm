// 主體構造的測試：哪些東西能被換成一個 Principal，哪些必須在構造階段就被拒。
//
// 這一檔關注的是「受信上下文的入口」，不是權限判定（判定見 authorize_test.go）：
// 構造階段的拒绝清單決定了請求內容還有沒有地方藏身，所以每條拒绝都要有對應的測試，
// 少一條就等於那條防線只是註解。
package identity_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// TestZeroPrincipalIsAnonymous 固定住「零值即匿名」這條預設立場。
//
// 它是整套判定能fail-closed 的地基：忘了帶主體、上下文裡根本沒有主體、
// 從請求還原出一個空物件——三種疏失都必須落在同一個「沒有任何權限」的結果上。
func TestZeroPrincipalIsAnonymous(t *testing.T) {
	var p identity.Principal
	if p.Kind() != identity.KindAnonymous {
		t.Errorf("零值主體的類別應為 anonymous，實際 %s", p.Kind().String())
	}
	if !p.IsAnonymous() {
		t.Error("零值主體必須被讀成匿名")
	}
	if p.IsRoot() || p.IsSystem() {
		t.Error("零值主體不可被讀成 Root 或系統")
	}
	if !p.AccountID().IsNil() {
		t.Error("零值主體不可帶帳戶標識")
	}
	if len(p.Roles()) != 0 {
		t.Errorf("零值主體不可帶有角色，實際 %v", p.Roles())
	}
	if got := p.String(); got != "anonymous" {
		t.Errorf("零值主體的摘要應為 anonymous，實際 %q", got)
	}
	// 零值可以直接拿去判定，且必須是拒絕；這裡不期待錯誤（那是「寫錯了」而不是「沒權限」）。
	if err := identity.Authorize(p, identity.NeedAuthenticated); !errors.Is(err, identity.ErrNotAuthenticated) {
		t.Errorf("零值主體經 NeedAuthenticated 應為未認證，實際 %v", err)
	}
}

// TestAccountPrincipalAccepted 列出合法形態的帳戶主體。
func TestAccountPrincipalAccepted(t *testing.T) {
	id := identitytest.NewID(t)
	admin := identitytest.NewID(t)
	guest := identitytest.NewID(t)
	cases := []struct {
		name     string
		in       identity.AccountInput
		wantKind identity.Kind
		wantRole identity.Role
	}{
		{
			name: "標準帳戶、無角色、HTTP 來源",
			in: identity.AccountInput{
				Subject: identity.AccountSubject{ID: id, Type: account.TypeStandard, Status: account.StatusActive},
				Origin:  identity.OriginHTTPRequest,
			},
			wantKind: identity.KindAccount,
		},
		{
			name: "伺服器管理員、命令列來源",
			in: identity.AccountInput{
				Subject: identity.AccountSubject{ID: admin, Type: account.TypeStandard, Status: account.StatusActive},
				Origin:  identity.OriginCLI,
				Grants:  identity.NewServerGrants(identity.RoleServerAdmin),
			},
			wantKind: identity.KindAccount,
			wantRole: identity.RoleServerAdmin,
		},
		{
			name: "訪客帳戶、無角色",
			in: identity.AccountInput{
				Subject: identity.AccountSubject{ID: guest, Type: account.TypeGuest, Status: account.StatusActive},
				Origin:  identity.OriginHTTPRequest,
			},
			wantKind: identity.KindAccount,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := identity.NewAccountPrincipal(tc.in)
			if err != nil {
				t.Fatalf("合法主體構造失敗：%v", err)
			}
			if p.Kind() != tc.wantKind {
				t.Errorf("類別為 %s，期待 %s", p.Kind().String(), tc.wantKind.String())
			}
			if p.AccountID() != tc.in.Subject.ID {
				t.Errorf("帳戶標識應原樣保留，實際 %s", p.AccountID())
			}
			if p.AccountType() != tc.in.Subject.Type {
				t.Errorf("帳戶類型應原樣保留，實際 %q", p.AccountType())
			}
			if got := p.HasRole(tc.wantRole); got != (tc.wantRole != "") {
				t.Errorf("HasRole(%s) 為 %v，期待 %v", tc.wantRole, got, tc.wantRole != "")
			}
		})
	}
}

// TestAccountPrincipalRejected 是構造階段的拒絕清單：每一條都對應一種「自報身分」的可能形態。
func TestAccountPrincipalRejected(t *testing.T) {
	validID := identitytest.NewID(t)
	subject := func(mut func(*identity.AccountSubject)) identity.AccountSubject {
		s := identity.AccountSubject{ID: validID, Type: account.TypeStandard, Status: account.StatusActive}
		if mut != nil {
			mut(&s)
		}
		return s
	}
	cases := []struct {
		name string
		in   identity.AccountInput
		want error
	}{
		{
			name: "零值帳戶標識",
			in: identity.AccountInput{
				Subject: subject(nil),
				Origin:  identity.OriginHTTPRequest,
			},
			want: identity.ErrInvalidPrincipal,
		},
		{
			name: "禁用帳戶",
			in: identity.AccountInput{
				Subject: subject(func(s *identity.AccountSubject) { s.Status = account.StatusDisabled }),
				Origin:  identity.OriginHTTPRequest,
			},
			want: identity.ErrNotAuthenticated,
		},
		{
			name: "未知帳戶狀態",
			in: identity.AccountInput{
				Subject: subject(func(s *identity.AccountSubject) { s.Status = account.Status("deleted") }),
				Origin:  identity.OriginHTTPRequest,
			},
			want: identity.ErrNotAuthenticated,
		},
		{
			name: "未知帳戶類型",
			in: identity.AccountInput{
				Subject: subject(func(s *identity.AccountSubject) { s.Type = account.Type("root") }),
				Origin:  identity.OriginHTTPRequest,
			},
			want: identity.ErrInvalidPrincipal,
		},
		{
			name: "未知來源",
			in: identity.AccountInput{
				Subject: subject(nil),
				Origin:  identity.Origin("cookie"),
			},
			want: identity.ErrInvalidPrincipal,
		},
		{
			name: "背景任務來源的帳戶主體",
			in: identity.AccountInput{
				Subject: subject(nil),
				Origin:  identity.OriginBackground,
			},
			want: identity.ErrInvalidPrincipal,
		},
		{
			name: "帳戶未知角色",
			in: identity.AccountInput{
				Subject: subject(nil),
				Origin:  identity.OriginHTTPRequest,
				Grants:  identity.NewServerGrants(identity.Role("root")),
			},
			want: identity.ErrInvalidPrincipal,
		},
		{
			name: "空字串角色",
			in: identity.AccountInput{
				Subject: subject(nil),
				Origin:  identity.OriginHTTPRequest,
				Grants:  identity.NewServerGrants(identity.Role("")),
			},
			want: identity.ErrInvalidPrincipal,
		},
		{
			name: "重複授予同一角色",
			in: identity.AccountInput{
				Subject: subject(nil),
				Origin:  identity.OriginHTTPRequest,
				Grants:  identity.NewServerGrants(identity.RoleServerAdmin, identity.RoleServerAdmin),
			},
			want: identity.ErrInvalidPrincipal,
		},
		{
			name: "訪客帳戶持有角色",
			in: identity.AccountInput{
				Subject: subject(func(s *identity.AccountSubject) { s.Type = account.TypeGuest }),
				Origin:  identity.OriginHTTPRequest,
				Grants:  identity.NewServerGrants(identity.RoleServerAdmin),
			},
			want: identity.ErrInvalidPrincipal,
		},
	}
	// 零值標識那一條要用不一樣的 Subject：預設帶的是有效標識。
	cases[0].in.Subject.ID = idgen.Nil

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := identity.NewAccountPrincipal(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("錯誤應為 %v，實際 %v", tc.want, err)
			}
			if !p.IsAnonymous() {
				t.Error("構造失敗時必須回零值（匿名）主體，不可回半成品")
			}
			if err := identity.Authorize(p, identity.NeedServerAdmin); err == nil {
				t.Error("構造失敗回的主體竟然通過了敏感判定")
			}
		})
	}
}

// TestSubjectOfCarriesOnlyMinimalFacts 確認從帳戶取出的最小事實不含憑據。
func TestSubjectOfCarriesOnlyMinimalFacts(t *testing.T) {
	a := account.Account{ID: identitytest.NewID(t), Type: account.TypeStandard, Status: account.StatusActive}
	s := identity.SubjectOf(a)
	if s.ID != a.ID || s.Type != a.Type || s.Status != a.Status {
		t.Errorf("最小事實與帳戶不一致：%+v", s)
	}
	// AccountSubject 不帶憑據欄位：這行只是把「新增欄位時要想過為什麼」寫成測試。
	if strings.Contains(fmt.Sprintf("%+v", s), "PasswordHash") {
		t.Error("AccountSubject 不應攜帶憑據相關欄位")
	}
}

// TestRootPrincipalRequiresProof 是「沒有生產可用的 Root 捷徑」這條約定的核心測試。
func TestRootPrincipalRequiresProof(t *testing.T) {
	cases := []struct {
		name   string
		proof  identity.RootProof
		origin identity.Origin
		want   error
	}{
		{"零值證明", identity.RootProof{}, identity.OriginCLI, identity.ErrInvalidPrincipal},
		{"有效證明但來源是啟動流程", identitytest.RootProof(t), identity.OriginStartup, identity.ErrInvalidPrincipal},
		{"有效證明但來源是背景任務", identitytest.RootProof(t), identity.OriginBackground, identity.ErrInvalidPrincipal},
		{"有效證明但來源未知", identitytest.RootProof(t), identity.Origin("magic"), identity.ErrInvalidPrincipal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := identity.Root(tc.proof, tc.origin)
			if !errors.Is(err, tc.want) {
				t.Fatalf("錯誤應為 %v，實際 %v", tc.want, err)
			}
			if !p.IsAnonymous() {
				t.Error("構造失敗時必須回零值主體")
			}
		})
	}
}

// TestRootPrincipalShape 檢查 Root 主體的形態：它不是帳戶，也不持有授予的角色。
func TestRootPrincipalShape(t *testing.T) {
	root := identitytest.Root(t, identity.OriginHTTPRequest)
	if !root.IsRoot() {
		t.Fatal("主體應為 Root")
	}
	if !root.AccountID().IsNil() {
		t.Error("Root 主體不可帶帳戶標識（Root 不在 accounts 表裡）")
	}
	if len(root.Roles()) != 0 {
		t.Errorf("Root 主體不可帶有授予角色，實際 %v", root.Roles())
	}
	if root.HasRole(identity.RoleServerAdmin) {
		t.Error("Root 不是角色，HasRole 對它一律 false")
	}
	if got := root.String(); got != "root(http_request)" {
		t.Errorf("Root 摘要為 %q", got)
	}
}

// TestVerifyRootCredentialPaths 區分「憑據不對」與「配置沒寫」，兩者都不洩漏材料。
func TestVerifyRootCredentialPaths(t *testing.T) {
	encoded, secret := identitytest.RootCredential(t)

	proof, err := identity.VerifyRootCredential(encoded, secret)
	if err != nil || !proof.Valid() {
		t.Fatalf("正確憑據應發出證明：%v", err)
	}

	if proof, err := identity.VerifyRootCredential(encoded, secret+"被改過一個字"); err == nil || proof.Valid() {
		t.Error("錯誤憑據不可發出證明")
	}
	// 配置沒寫 Root 雜湊：屬部署缺項，必須报得出來，不能退化成「憑據不對」。
	if _, err := identity.VerifyRootCredential("", secret); err == nil {
		t.Error("空 Root 雜湊應回報配置缺項")
	}
	// 編碼損壞時對外與「憑據不對」同一個結論，不暴露是哪一段壞掉。
	_, err = identity.VerifyRootCredential("$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aaaa", secret)
	if !errors.Is(err, identity.ErrInvalidCredential) {
		t.Errorf("非法編碼應收斂為憑據校驗未通過，實際 %v", err)
	}
	if strings.Contains(fmt.Sprint(err), "c2FsdA") {
		t.Error("錯誤訊息不可回顯憑據材料")
	}
	// 空明文由 credential 判否，不消耗派生也不報錯——對外仍是同一個「未通過」。
	if proof, err := identity.VerifyRootCredential(encoded, ""); err == nil || proof.Valid() {
		t.Error("空憑據不可通過")
	}
}

// TestSystemPrincipalOrigins 固定系統主體的來源清單：它只能是啟動、CLI 或背景任務。
func TestSystemPrincipalOrigins(t *testing.T) {
	for _, o := range []identity.Origin{identity.OriginStartup, identity.OriginCLI, identity.OriginBackground} {
		p, err := identity.NewSystem(o)
		if err != nil {
			t.Errorf("來源 %s 應可構造系統主體：%v", o, err)
			continue
		}
		if !p.IsSystem() || !p.AccountID().IsNil() || len(p.Roles()) != 0 {
			t.Errorf("系統主體形態不正確：%v", p)
		}
	}
	// 最關鍵的一條：背景／啟動路徑不能把自己升格成「一個發請求的用戶」。
	if _, err := identity.NewSystem(identity.OriginHTTPRequest); !errors.Is(err, identity.ErrInvalidPrincipal) {
		t.Errorf("system 主體帶 http_request 來源應被拒，實際 %v", err)
	}
	if _, err := identity.NewSystem(identity.Origin("")); !errors.Is(err, identity.ErrInvalidPrincipal) {
		t.Errorf("system 主體缺來源應被拒，實際 %v", err)
	}
}

// TestRolesAccessorReturnsCopy 確認角色清單不可被呼叫端改寫。
//
// 主體是不可變值，但切片是可變的：匯出內部切片就等於任何拿到主體的程式碼
// 都能給自己補一個角色（虽然改不了原物件的長度，卻能改內容）。
func TestRolesAccessorReturnsCopy(t *testing.T) {
	id := identitytest.NewID(t)
	p := identitytest.Account(t, id, identitytest.ServerAdmin())
	roles := p.Roles()
	if len(roles) != 1 {
		t.Fatalf("應有一個角色，實際 %v", roles)
	}
	roles[0] = identity.Role("root")
	if !p.HasRole(identity.RoleServerAdmin) || p.HasRole(identity.Role("root")) {
		t.Error("改寫副本影響了主體本身")
	}
	if noRoles := identitytest.Account(t, identitytest.NewID(t)).Roles(); noRoles != nil {
		t.Errorf("無角色時應回 nil，實際 %v", noRoles)
	}
}

// TestStringOmitsIdentifiers 確認主體摘要不會把標識帶進日誌。
func TestStringOmitsIdentifiers(t *testing.T) {
	id := identitytest.NewID(t)
	p := identitytest.Account(t, id, identitytest.ServerAdmin())
	for _, s := range []string{p.String(), fmt.Sprintf("%v", p), fmt.Sprintf("%s", p)} {
		if strings.Contains(s, id.String()) {
			t.Errorf("摘要 %q 含有帳戶標識", s)
		}
	}
	if !strings.Contains(p.String(), "account") || !strings.Contains(p.String(), "http_request") {
		t.Errorf("摘要應說明類別與來源，實際 %q", p.String())
	}
}
