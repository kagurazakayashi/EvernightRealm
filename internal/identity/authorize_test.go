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

	// want 是三檔需求的預期錯誤：nil 表示透過。
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
		// 系統主體不是任何人的代理：它能透過「知道是誰」這一檔（它就是伺服器），
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
						t.Errorf("%s / %s 應透過，實際 %v", tc.name, need, err)
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

// TestAuthorizeActivityScopeJudgesGrants 是「不用全域性管理員檢查冒充活動隔離」的測試。
//
// 這一層落地之前，它固定的是「一律不放行」；落地之後它固定的是同一句話的另一半：
// 放行只能來自指派清單，不能來自主體自帶的伺服器級角色。四件事都要固定住：
//   - 伺服器管理員沒有被指派就是沒有——這條是整個型別存在的理由，若哪天實作改成
//     「有 server_admin 就放行所有活動」，本測試當場紅；
//   - 被指派的帳戶放行，指派清單為空時一律拒（漏帶授權資料不會默默變成「哪個活動都能管」）；
//   - 缺 activity 標識回報的是引數缺陷而不是權限不足；
//   - 系統主體不放行：它不是任何人的代理，不能替人在活動內代行管理動作。
func TestAuthorizeActivityScopeJudgesGrants(t *testing.T) {
	activityID := identitytest.NewID(t)
	other := identitytest.NewID(t)
	grantedOne := identitytest.Grants(t, activityID)
	grantedOther := identitytest.Grants(t, other)
	empty := identitytest.Grants(t)

	cases := []struct {
		name    string
		p       identity.Principal
		granted identity.ActivityGrants
		wantErr error
	}{
		{"被指派的帳戶放行", identitytest.Account(t, other), grantedOne, nil},
		{"未被指派的帳戶拒", identitytest.Account(t, other), grantedOther, identity.ErrPermissionDenied},
		{"指派清單為空一律拒", identitytest.Account(t, other), empty, identity.ErrPermissionDenied},
		{"伺服器管理員但未被指派仍拒", identitytest.Account(t, other, identitytest.ServerAdmin()),
			grantedOther, identity.ErrPermissionDenied},
		{"普通帳戶未被指派拒", identitytest.Account(t, other), grantedOther, identity.ErrPermissionDenied},
		{"Root 跨活動放行", identitytest.Root(t, identity.OriginHTTPRequest), empty, nil},
		{"系統主體不放行", identitytest.System(t, identity.OriginBackground), grantedOne,
			identity.ErrPermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := identity.AuthorizeActivityScope(tc.p, activityID, tc.granted)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("應放行，實際 %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("應回報 %v，實際 %v", tc.wantErr, err)
			}
			// 拒絕的結論不可是「程式缺陷」：那會讓呼叫端把正常的拒絕當 500 報給操作者。
			if errors.Is(err, identity.ErrInvalidPrincipal) ||
				errors.Is(err, identity.ErrActivityScopeUnsupported) {
				t.Errorf("正常的權限拒絕被報成缺陷：%v", err)
			}
		})
	}

	// 缺 activity 標識是引數缺陷，對每一類主體都先於作用域判定回報。
	principals := []struct {
		name string
		p    identity.Principal
	}{
		{"普通帳戶", identitytest.Account(t, other)},
		{"伺服器管理員", identitytest.Account(t, other, identitytest.ServerAdmin())},
		{"Root", identitytest.Root(t, identity.OriginHTTPRequest)},
		{"系統（背景）", identitytest.System(t, identity.OriginBackground)},
	}
	for _, tc := range principals {
		t.Run(tc.name+"缺活動標識", func(t *testing.T) {
			err := identity.AuthorizeActivityScope(tc.p, idgen.Nil, grantedOne)
			if !errors.Is(err, identity.ErrMissingActivityScope) {
				t.Fatalf("應回報缺少 activity 標識，實際 %v", err)
			}
			if errors.Is(err, identity.ErrPermissionDenied) {
				t.Error("缺引數屬呼叫端缺陷，不可與「他沒有這個活動的管理權」混為同一個結論")
			}
		})
	}

	// 匿名主體先撞在「不知道是誰」上：身分問題的優先順序高於作用域問題。
	err := identity.AuthorizeActivityScope(identitytest.Anonymous(t), activityID, grantedOne)
	if !errors.Is(err, identity.ErrNotAuthenticated) {
		t.Errorf("匿名主體應先回報未認證，實際 %v", err)
	}
}
