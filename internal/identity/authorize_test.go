// 伺服器級角色判定的測試矩陣：六種主體乘三檔需求，每格都有一個明確答案。
//
// 這一檔是「服務層集中執行角色判定」的證據所在。判定表整齊地攤在測試裡是有意的：
// 任何一格被改動（尤其是把某個 deny 改成 allow）都會在這裡留下刺眼的差異，
// 而各端點各自寫判定，這類改動會散落在幾十個檔案裡，審查時看不出來。
package identity_test

import (
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// TestAuthorizeMatrix 逐格核對判定結果。
func TestAuthorizeMatrix(t *testing.T) {
	adminID := identitytest.NewID(t)
	plainID := identitytest.NewID(t)
	guestID := identitytest.NewID(t)

	principals := []struct {
		name string
		p    identity.Principal
	}{
		{"匿名", identitytest.Anonymous(t)},
		{"普通帳戶", identitytest.Account(t, plainID)},
		{"訪客帳戶", identitytest.Account(t, guestID, identitytest.WithGuestType())},
		{"伺服器管理員", identitytest.Account(t, adminID, identitytest.ServerAdmin())},
		{"Root", identitytest.Root(t, identity.OriginHTTPRequest)},
		{"系統（CLI）", identitytest.System(t, identity.OriginCLI)},
	}

	// want 是三檔需求的預期錯誤：nil 表示通過。
	want := map[string]map[identity.Need]error{
		"匿名": {
			identity.NeedAuthenticated: identity.ErrNotAuthenticated,
			identity.NeedServerAdmin:   identity.ErrNotAuthenticated,
			identity.NeedRoot:          identity.ErrNotAuthenticated,
		},
		"普通帳戶": {
			identity.NeedAuthenticated: nil,
			identity.NeedServerAdmin:   identity.ErrPermissionDenied,
			identity.NeedRoot:          identity.ErrPermissionDenied,
		},
		"訪客帳戶": {
			identity.NeedAuthenticated: nil,
			identity.NeedServerAdmin:   identity.ErrPermissionDenied,
			identity.NeedRoot:          identity.ErrPermissionDenied,
		},
		"伺服器管理員": {
			identity.NeedAuthenticated: nil,
			identity.NeedServerAdmin:   nil,
			identity.NeedRoot:          identity.ErrPermissionDenied,
		},
		"Root": {
			identity.NeedAuthenticated: nil,
			identity.NeedServerAdmin:   nil,
			identity.NeedRoot:          nil,
		},
		// 系統主體不是任何人的代理：它能通過「知道是誰」這一檔（它就是伺服器），
		// 但不能頂著管理員名義執行需要授權的業務動作。
		"系統（CLI）": {
			identity.NeedAuthenticated: nil,
			identity.NeedServerAdmin:   identity.ErrPermissionDenied,
			identity.NeedRoot:          identity.ErrPermissionDenied,
		},
	}

	for _, tc := range principals {
		t.Run(tc.name, func(t *testing.T) {
			table, ok := want[tc.name]
			if !ok {
				t.Fatalf("測試主體 %q 沒有對應的預期列", tc.name)
			}
			for _, need := range []identity.Need{identity.NeedAuthenticated, identity.NeedServerAdmin, identity.NeedRoot} {
				err := identity.Authorize(tc.p, need)
				expect := table[need]
				if expect == nil {
					if err != nil {
						t.Errorf("%s / %s 應通過，實際 %v", tc.name, need, err)
					}
					continue
				}
				if !errors.Is(err, expect) {
					t.Errorf("%s / %s 應為 %v，實際 %v", tc.name, need, expect, err)
				}
			}
		})
	}
}

// TestAuthorizeUnknownNeedIsDefect 確認未知的授權需求不會被當成「沒權限」。
//
// 一個拼錯的 Need 如果回權限不足，端點會老老實實回 403，那個缺陷可以藏很久；
// 回 ErrInvalidRequirement 才能在測試與日誌裡被認出來是程式寫錯。
func TestAuthorizeUnknownNeedIsDefect(t *testing.T) {
	for _, need := range []identity.Need{"", "admin", "activity_admin", "ROOT"} {
		err := identity.Authorize(identitytest.Root(t, identity.OriginCLI), need)
		if !errors.Is(err, identity.ErrInvalidRequirement) {
			t.Errorf("需求 %q 應回報授權需求不合法，實際 %v", need, err)
		}
	}
}

// TestAuthorizeActivityScopeIsExplicitBoundary 是「不用全局管理員檢查冒充活動隔離」的測試。
//
// 三件事都要固定住：缺 activity 標識回報的是引數缺陷；帶了標識回報的是未實現邊界；
// 兩個結果都不是「通過」。第三條尤其要緊——若本函式哪天回 nil，所有拿它當活動授權的
// 呼叫端會立刻變成無條件放行，這條測試就是那個變故的警報。
func TestAuthorizeActivityScopeIsExplicitBoundary(t *testing.T) {
	activityID := identitytest.NewID(t)
	other := identitytest.NewID(t)

	principals := []struct {
		name string
		p    identity.Principal
	}{
		{"普通帳戶", identitytest.Account(t, activityID)},
		{"伺服器管理員", identitytest.Account(t, other, identitytest.ServerAdmin())},
		{"Root", identitytest.Root(t, identity.OriginHTTPRequest)},
		{"系統（背景）", identitytest.System(t, identity.OriginBackground)},
	}
	for _, tc := range principals {
		t.Run(tc.name+"帶活動標識", func(t *testing.T) {
			err := identity.AuthorizeActivityScope(tc.p, activityID)
			if !errors.Is(err, identity.ErrActivityScopeUnsupported) {
				t.Fatalf("應回報活動作用域未實現，實際 %v", err)
			}
		})
		t.Run(tc.name+"缺活動標識", func(t *testing.T) {
			err := identity.AuthorizeActivityScope(tc.p, idgen.Nil)
			if !errors.Is(err, identity.ErrMissingActivityScope) {
				t.Fatalf("應回報缺少 activity 標識，實際 %v", err)
			}
			if errors.Is(err, identity.ErrActivityScopeUnsupported) {
				t.Error("缺引數屬呼叫端缺陷，不可與未實現混為同一個結論")
			}
		})
	}

	// 匿名主體先撞在「不知道是誰」上：身分問題的優先級高於作用域問題。
	err := identity.AuthorizeActivityScope(identitytest.Anonymous(t), activityID)
	if !errors.Is(err, identity.ErrNotAuthenticated) {
		t.Errorf("匿名主體應先回報未認證，實際 %v", err)
	}
}
