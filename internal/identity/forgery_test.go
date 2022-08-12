// 「請求內容能不能把自己說成一個有權限的人」的測試：這一檔每條斷言都在守同一條邊界。
//
// 之所以把這些寫成測試而不是註解：主體型別的安全性靠的是「沒有可填的欄位」這種
// 結構性事實，而結構性事實最容易被後來的人以「加個 JSON 標記而已」破壞掉。
// 一旦有人給 Principal 或 ServerGrants 補上匯出欄位或編解碼支援，這裡就會紅。
package identity_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
)

// TestUntrustedPrincipalJSONYieldsAnonymous 確認外部 JSON 無法填出一個有權限的主體。
//
// Principal 沒有匯出欄位，也沒有 UnmarshalJSON：解碼一個自報為 Root 的物件之後，
// 拿到的仍然是匿名主體，任何敏感判定都必須拒絕。
func TestUntrustedPrincipalJSONYieldsAnonymous(t *testing.T) {
	payload := `{"Kind":"root","Origin":"cli","Roles":["server_admin"],"AccountID":"00000000-0000-7000-8000-726f6f740000"}`

	var forged identity.Principal
	err := json.Unmarshal([]byte(payload), &forged)
	if err != nil {
		// 解碼直接報錯也是可接受的結果，重點是主體不可被填出内容。
		t.Logf("解碼回報：%v", err)
	}
	if !forged.IsAnonymous() {
		t.Fatalf("外部 JSON 把主體填成了 %s", forged.Kind().String())
	}
	for _, need := range []identity.Need{identity.NeedAuthenticated, identity.NeedServerAdmin, identity.NeedRoot} {
		if err := identity.Authorize(forged, need); !errors.Is(err, identity.ErrNotAuthenticated) {
			t.Errorf("%s 應被拒，實際 %v", need, err)
		}
	}
	if _, err := forged.AuditActor(); !errors.Is(err, identity.ErrNotAuthenticated) {
		t.Errorf("自報主體不可換成審計操作者，實際 %v", err)
	}
}

// TestAccountInputFromWireHasNoRoles 確認「把 AccountInput 直接當請求 DTO」這條捷徑走不通。
//
// 這一條是整套型別設計裡最容易被誤解的地方：AccountInput 的 Subject 與 Origin
// 確實能被 JSON 填起來（它倆是字串與標識），但 Grants 的欄位不匯出，填不進去。
// 於是就算端點偷懒把請求直接解進 AccountInput，做出來的也只是「一個沒有角色的普通帳戶」——
// 自報權限落到無權限，而不是落到成功。
func TestAccountInputFromWireHasNoRoles(t *testing.T) {
	id := identitytest.NewID(t)
	payload := `{
		"Subject":{"ID":"` + id.String() + `","Type":"standard","Status":"active"},
		"Origin":"http_request",
		"Grants":{"roles":["server_admin"]},
		"Roles":["server_admin"],
		"Kind":"root"
	}`

	var in identity.AccountInput
	if err := json.Unmarshal([]byte(payload), &in); err != nil {
		// 未知欄位在本專案的請求解碼裡會被拒；兩條路都走到同一個結論：拿不到角色。
		t.Logf("解碼回報：%v", err)
	}
	p, err := identity.NewAccountPrincipal(in)
	if err != nil {
		t.Fatalf("主體構造失敗：%v", err)
	}
	if len(p.Roles()) != 0 {
		t.Fatalf("請求內容把角色帶進來了：%v", p.Roles())
	}
	if p.HasRole(identity.RoleServerAdmin) {
		t.Fatal("請求內容自報的管理員身分生效了")
	}
	if err := identity.Authorize(p, identity.NeedServerAdmin); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("應為權限不足，實際 %v", err)
	}
	// 「是某人」這一層仍然可信（標識與狀態是事實），所以它過得了 NeedAuthenticated：
	// 這正是本套件要的分層——身分與授權是兩個問題，請求能碰到的只有前者，而且还要過資料庫。
	if err := identity.Authorize(p, identity.NeedAuthenticated); err != nil {
		t.Errorf("合法帳戶應通過 NeedAuthenticated，實際 %v", err)
	}
}

// TestParseRoleRefusesEverythingElse 固定「字串變角色」的唯一入口有多窄。
func TestParseRoleRefusesEverythingElse(t *testing.T) {
	cases := []string{
		"", " ", "root", "Root", "admin", "ADMIN", "server_admin ", " server_admin",
		"SERVER_ADMIN", "Server_Admin", "superuser", "activity_admin", "npc", "player",
		"服務器管理員", "伺服器管理員", "server_admin,root", "server-admin",
	}
	for _, raw := range cases {
		if r, err := identity.ParseRole(raw); err == nil {
			t.Errorf("角色字串 %q 被接受了（解析為 %s）", raw, r.String())
		} else if !errors.Is(err, identity.ErrUnknownRole) {
			t.Errorf("角色字串 %q 的錯誤類型不對：%v", raw, err)
		}
	}
	if _, err := identity.ParseRole(string(identity.RoleServerAdmin)); err != nil {
		t.Errorf("已定義角色 %q 應可解析", identity.RoleServerAdmin)
	}
}

// TestGrantsFromStringsFailsLoudly 確認授權資料壞掉時是「整體失敗」而不是「靜默少一個角色」。
func TestGrantsFromStringsFailsLoudly(t *testing.T) {
	ok, err := identity.NewServerGrantsFromStrings(string(identity.RoleServerAdmin))
	if err != nil {
		t.Fatalf("合法授予應成功：%v", err)
	}
	p, err := identity.NewAccountPrincipal(identity.AccountInput{
		Subject: identity.AccountSubject{
			ID:     identitytest.NewID(t),
			Type:   account.TypeStandard,
			Status: account.StatusActive,
		},
		Origin: identity.OriginHTTPRequest,
		Grants: ok,
	})
	if err != nil {
		t.Fatalf("由字串授予構造主體失敗：%v", err)
	}
	if err := identity.Authorize(p, identity.NeedServerAdmin); err != nil {
		t.Errorf("授予應生效，實際 %v", err)
	}

	// 任何一項不認得即整體失敗：一筆寫壞的授權記錄不能被降級成「他剛好沒有這個角色」。
	for _, bad := range [][]string{{"root"}, {string(identity.RoleServerAdmin), ""}, {"admin", "admin"}, {" "}} {
		if _, err := identity.NewServerGrantsFromStrings(bad...); err == nil {
			t.Errorf("非法授予 %q 應該失敗", strings.Join(bad, "|"))
		}
	}
	if _, err := identity.NewServerGrantsFromStrings(); err != nil {
		t.Error("零項授予應是合法的「沒有角色」，不該報錯")
	}
}

// TestContextRoundTripAndDefault 確認上下文的預設是匿名，而注入只能經 NewContext。
func TestContextRoundTripAndDefault(t *testing.T) {
	ctx := context.Background()
	if got := identity.FromContext(ctx); !got.IsAnonymous() {
		t.Fatalf("空上下文應讀出匿名主體，實際 %s", got.Kind().String())
	}
	if err := identity.Authorize(identity.FromContext(ctx), identity.NeedServerAdmin); !errors.Is(err, identity.ErrNotAuthenticated) {
		t.Errorf("空上下文裡的動作應被拒，實際 %v", err)
	}

	// 以另一種鍵型別硬塞一個同名鍵：FromContext 的型別斷言不認它，因此注入無效。
	type impostorKey string
	shoved := context.WithValue(ctx, impostorKey("principal"), "root")
	if got := identity.FromContext(shoved); !got.IsAnonymous() {
		t.Error("外部鍵型別可以覆寫受信主體")
	}

	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	withAdmin := identity.NewContext(ctx, admin)
	if got := identity.FromContext(withAdmin); got.AccountID() != admin.AccountID() || !got.HasRole(identity.RoleServerAdmin) {
		t.Errorf("上下文未原樣取回主體：%v", got)
	}
	if err := identity.Authorize(identity.FromContext(withAdmin), identity.NeedServerAdmin); err != nil {
		t.Errorf("上下文取回的主體判定錯誤：%v", err)
	}
	if err := identity.Authorize(identity.FromContext(withAdmin), identity.NeedRoot); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("管理員不應通過 NeedRoot，實際 %v", err)
	}
	// 匿名主體也可以被放進上下文（公開端點的上下文本來就該是匿名），结果仍是拒絕。
	anonymousCtx := identity.NewContext(ctx, identitytest.Anonymous(t))
	if !identity.FromContext(anonymousCtx).IsAnonymous() {
		t.Error("匿名主體放進上下文後變形了")
	}
}
