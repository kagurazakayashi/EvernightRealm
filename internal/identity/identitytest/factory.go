// Package identitytest 是 internal/identity 的測試身份工廠。
//
// 規则是「不准有生產可用的調試入口」，而調試入口最常見的形态就是一個叫
// `AsRoot()` 的匯出函式。本套件因此不提供任何繞過判定的構造：
//   - Root 主體仍然只能經 identity.VerifyRootCredential 拿證明——
//     每個函式都會用 internal/credential 的測試參數檔產生一份一次性憑據並老實比對，
//     所以「拿到 Root 主體」這件事在測試裡和在生產裡走的是同一條路，
//     工廠不可能比生產程式碼更寬鬆；
//   - 帳戶主體一律經 identity.NewAccountPrincipal，用的就是生產那套校驗
//     （禁用拒絕、訪客帶角色拒絕、零值標識拒絕）；
//   - 每個函式都要帶 testing.TB：生產程式碼要用它，就必須先捏造一個 testing.TB，
//     那種寫法在審查時是顯眼缺陷，不會被当成正常依賴。
//
// 因此本套件只應該被 *_test.go 引用。若你在非測試檔案裡看到 import 它，
// 那是需要修掉的缺陷，不是可用能力。
package identitytest

import (
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/credential"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// rootSecret 是測試憑據的明文。
//
// 它不是任何環境裡的密碼，也不進日誌與錯誤訊息：存在的目的只是讓
// credential.Hash 與 identity.VerifyRootCredential 有一次可重複的比對。
const rootSecret = "identitytest-一次性-root-憑據"

// NewID 產生一個測試用 UUIDv7 標識。
//
// 走 idgen 而不是手拼字串：本專案所有標識比較都假設正規小寫 UUIDv7，
// 工廠造出的假標識若格式不同，測試通過的只是「另一種形狀能通過」這件事。
func NewID(t testing.TB) idgen.ID {
	t.Helper()
	id, err := idgen.New()
	if err != nil {
		t.Fatalf("identitytest: 產生測試標識失敗: %v", err)
	}
	return id
}

// RootCredential 產生一組一次性 Root 憑據（Argon2id 編碼雜湊與其明文）。
//
// 用 credential.TestParams（低成本檔）而不是生產檔：這份雜湊只活在測試進程的記憶體裡，
// 落不了庫，也沒有一個真實系統以它為防線；把它做成生產檔參數只會讓測試慢下來，
// 換不到任何真實性。需要校驗生產檔行為時請直接在 credential 包的測試裡做。
func RootCredential(t testing.TB) (encoded, secret string) {
	t.Helper()
	hash, err := credential.Hash(rootSecret, credential.TestParams)
	if err != nil {
		t.Fatalf("identitytest: 產生測試 Root 憑據失敗: %v", err)
	}
	return hash, rootSecret
}

// RootProof 經真正的憑據比對換得一份有效證明。
//
// 要測試「沒有證明就不能構造 Root」時，直接用 identity.RootProof{}（零值）即可：
// 該型別的欄位不匯出，零值就是「沒比對過」，工廠不需要另造一個假證明。
func RootProof(t testing.TB) identity.RootProof {
	t.Helper()
	encoded, secret := RootCredential(t)
	proof, err := identity.VerifyRootCredential(encoded, secret)
	if err != nil {
		t.Fatalf("identitytest: 測試 Root 憑據校驗未通過: %v", err)
	}
	return proof
}

// Root 回傳一個通過憑據比對的 Root 主體。
func Root(t testing.TB, origin identity.Origin) identity.Principal {
	t.Helper()
	p, err := identity.Root(RootProof(t), origin)
	if err != nil {
		t.Fatalf("identitytest: 構造 Root 主體失敗: %v", err)
	}
	return p
}

// AccountOption 調整工廠構造帳戶主體時的細節（只改引數，不改判定規則）。
type AccountOption func(*identity.AccountInput)

// ServerAdmin 讓帳戶持有伺服器級管理員角色。
func ServerAdmin() AccountOption {
	return func(in *identity.AccountInput) {
		in.Grants = identity.NewServerGrants(identity.RoleServerAdmin)
	}
}

// WithGuestType 把帳戶類型改為 guest（預設 standard）。
func WithGuestType() AccountOption {
	return func(in *identity.AccountInput) {
		in.Subject.Type = account.TypeGuest
	}
}

// WithStatus 指定帳戶狀態（預設 active；給 disabled 時構造必然失敗，
// 那個失敗正是測試想要的東西，請改用 Account 而不是這些 Must 形式）。
func WithStatus(s account.Status) AccountOption {
	return func(in *identity.AccountInput) {
		in.Subject.Status = s
	}
}

// WithOrigin 指定呼叫來源（預設 http_request）。
func WithOrigin(o identity.Origin) AccountOption {
	return func(in *identity.AccountInput) {
		in.Origin = o
	}
}

// Account 回傳帳戶主體，構造失敗時讓測試直接失敗。
//
// 只用於正向情境；要斷言「某種主體構造不出來」請用 AccountErr，否則 t.Fatalf
// 會把預期中的失敗變成測試錯誤。
func Account(t testing.TB, id idgen.ID, opts ...AccountOption) identity.Principal {
	t.Helper()
	p, err := AccountErr(t, id, opts...)
	if err != nil {
		t.Fatalf("identitytest: 構造帳戶主體失敗: %v", err)
	}
	return p
}

// AccountErr 回傳帳戶主體與構造錯誤（錯留給測試斷言，不代做判定）。
func AccountErr(t testing.TB, id idgen.ID, opts ...AccountOption) (identity.Principal, error) {
	t.Helper()
	in := identity.AccountInput{
		Subject: identity.AccountSubject{
			ID:     id,
			Type:   account.TypeStandard,
			Status: account.StatusActive,
		},
		Origin: identity.OriginHTTPRequest,
	}
	for _, opt := range opts {
		opt(&in)
	}
	return identity.NewAccountPrincipal(in)
}

// System 回傳伺服器自身主體（啟動、CLI、背景任務）。
func System(t testing.TB, origin identity.Origin) identity.Principal {
	t.Helper()
	p, err := identity.NewSystem(origin)
	if err != nil {
		t.Fatalf("identitytest: 構造系統主體失敗: %v", err)
	}
	return p
}

// Anonymous 回傳匿名主體。
func Anonymous(t testing.TB) identity.Principal {
	t.Helper()
	return identity.Anonymous()
}

// Grants 回傳活動授權清單；要測試「零值活動標識會被拒」時請直接呼叫
// identity.NewActivityGrants，工廠不應把預期中的失敗吞掉。
func Grants(t testing.TB, ids ...idgen.ID) identity.ActivityGrants {
	t.Helper()
	g, err := identity.NewActivityGrants(ids...)
	if err != nil {
		t.Fatalf("identitytest: 構造活動授權清單失敗: %v", err)
	}
	return g
}
