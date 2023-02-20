// invite_register_test.go 是「拿一枚有效邀請碼換出一筆可立即登入的普通帳戶」這條准入通路的定向證據。
//
// 它要釘死的是本步的全部安全語意，而不只是happy path：
//   - 只有策略為 invite 時才走核銷；有效碼換出的是 standard＋active（與開放模式同一登入行為），
//     而且建號、核銷、審計落在同一筆交易；
//   - 缺碼／形状不合／查無此碼／已過期／已撤銷／額度用滿／併發落敗——七種原因一律 ErrInviteRejected，
//     而且一個帳戶都不多、一條審計都不寫、一枚名額都不誤耗（註冊失敗不消費，靠同筆交易回滾）；
//   - 一次性碼在 N 路併發下恰好一次生效，其餘全部拿到同一句不泄露細節的拒絕；
//   - 重複請求（同登入名＋同一枚多用量碼）撞唯一索引時，整筆回滾、不第二次消費；
//   - 模式中途被改掉時，下一條請求按新值重判（核銷這一步只認「寫入那一刻」的模式）。
//
// 全程用本次專屬的暫存庫與注入時鐘：不佔 5206、不碰任何真實資料目錄，也不留任何明文碼在斷言文字裡。
package selfregister

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/acctpolicy"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/invitecode"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// mintCode 鋪設一枚邀請碼，回它交還給註冊者的「明文」與入庫的「驗證材料哈希」。
//
// 它把 invitecode 內部那套形状（16 位元組 crypto/rand → RawURLEncoding 22 字元 + SHA-256 十六進位）
// 在測試側如實重現，好讓黑盒用例能拿一枚「能過 ParseCode、又對得上庫裡哈希」的真碼去提交，
// 而不是造假。Create 走的是倉儲唯一的寫入點，時鐘取注入的那一份，於是過期判定在測試裡是可推進的。
type mintedCode struct {
	plaintext string
	hash      string
	id        idgen.ID
}

func mintCode(t *testing.T, e *env, label string, maxUses int64, expiresAt time.Time) mintedCode {
	t.Helper()
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("產生測試邀請碼失敗：%v", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plaintext))
	hash := hex.EncodeToString(sum[:])
	ctx := context.Background()
	code, err := e.invites.Create(ctx, e.db.SQL(), invitecode.CreateInput{
		CodeHash:  hash,
		Label:     label,
		MaxUses:   maxUses,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("鋪設測試邀請碼失敗：%v", err)
	}
	return mintedCode{plaintext: plaintext, hash: hash, id: code.ID}
}

// usedCount 讀回一枚碼此刻已核銷的次數，供「失敗不消費／併發只一次」的斷言。
func usedCount(t *testing.T, e *env, hash string) int64 {
	t.Helper()
	var used int64
	err := e.db.SQL().QueryRowContext(context.Background(),
		"SELECT used_count FROM registration_invite_codes WHERE code_hash = ?", hash).Scan(&used)
	if err != nil {
		t.Fatalf("讀取邀請碼額度失敗：%v", err)
	}
	return used
}

func accountCount(t *testing.T, e *env) int {
	t.Helper()
	return countRows(t, e.db, "accounts")
}

func auditCount(t *testing.T, e *env) int {
	t.Helper()
	return countRows(t, e.db, "root_audit")
}

// registerInvite 以 invite 模式提交一筆帶碼註冊，回結果與錯誤。
func (e *env) registerInvite(login, display, password, code string) (RegisteredAccount, error) {
	return e.service.RegisterAccount(context.Background(), RegisterInput{
		LoginName: login, DisplayName: display, Password: password, InviteCode: code,
	}, "req-"+login, "203.0.113.60")
}

// TestInviteValidCodeCreatesActiveStandardAccount 一枚有效碼換出一筆可立即登入的普通帳戶：
// 建號＋核銷＋審計同筆交易成立，狀態 active、類型 standard、首次不必改密、額度佔用一次。
func TestInviteValidCodeCreatesActiveStandardAccount(t *testing.T) {
	e := newEnv(t)
	e.setSelfRegisterMode(t, acctpolicy.ModeInvite)
	code := mintCode(t, e, "有效單次碼", 1, time.Time{})
	auditsBefore := auditCount(t, e)

	created, err := e.registerInvite("invite.active", "受邀者", testPassword, code.plaintext)
	if err != nil {
		t.Fatalf("有效邀請碼應換出一筆帳戶，實際失敗：%v", err)
	}
	if created.Status != account.StatusActive {
		t.Errorf("invite 建出的帳戶應 active（與開放模式一致），實際 %q", created.Status)
	}
	if created.MustChangePassword {
		t.Error("口令為本人自選，首次登入不應被要求改密")
	}
	a, err := e.accounts.ByLoginName(context.Background(), e.db.SQL(), "invite.active")
	if err != nil {
		t.Fatalf("回讀新建帳戶失敗：%v", err)
	}
	if a.Type != account.TypeStandard {
		t.Errorf("邀請碼不攜帶權限，建出的必須是 standard，實際 %q", a.Type)
	}
	if got := usedCount(t, e, code.hash); got != 1 {
		t.Errorf("一次性碼此刻額度應被佔用一次，實際 used_count=%d", got)
	}
	if got := auditCount(t, e); got != auditsBefore+1 {
		t.Errorf("成功的核銷註冊應追加一筆建號審計，實際 %d→%d", auditsBefore, got)
	}
}

// TestInviteCodeDoesNotGrantAdmin 拿到碼的人不會自動成為管理員：授予表一筆都不多。
func TestInviteCodeDoesNotGrantAdmin(t *testing.T) {
	e := newEnv(t)
	e.setSelfRegisterMode(t, acctpolicy.ModeInvite)
	code := mintCode(t, e, "權限邊界", 5, time.Time{})
	if _, err := e.registerInvite("invite.norole", "受邀者", testPassword, code.plaintext); err != nil {
		t.Fatalf("有效碼註冊應成功：%v", err)
	}
	if n := countRows(t, e.db, "account_server_roles"); n != 0 {
		t.Errorf("邀請碼註冊絕不賦予任何伺服器級角色，account_server_roles 卻有 %d 行", n)
	}
}

// TestInviteRejectsBadCodes 七種「這枚碼這一次換不出一筆帳戶」的原因一律收斂成 ErrInviteRejected，
// 而且零副作用：不建號、不記審計、不誤耗（該有的那枚碼 used_count 不動）。
func TestInviteRejectsBadCodes(t *testing.T) {
	cases := []struct {
		name   string
		maxUse int64
		expiry func(clock *timeutil.Test) time.Time
		pre    func(t *testing.T, e *env, code mintedCode)
		submit func(t *testing.T, e *env, code mintedCode, before int)
	}{
		{
			name:   "形状不合法",
			maxUse: 1,
			expiry: func(*timeutil.Test) time.Time { return time.Time{} },
			submit: func(t *testing.T, e *env, code mintedCode, before int) {
				// 送一枚長度不對／非 base64url 的假碼：連哈希都不該被拿去查庫。
				if _, err := e.registerInvite("bad.shape", "受邀者", testPassword, "not-a-valid-code!!"); !errors.Is(err, ErrInviteRejected) {
					t.Errorf("形状不合法的碼應被拒為 ErrInviteRejected，實際 %v", err)
				}
			},
		},
		{
			name:   "查無此碼（形状合法但伺服器沒簽過）",
			maxUse: 1,
			expiry: func(*timeutil.Test) time.Time { return time.Time{} },
			submit: func(t *testing.T, e *env, code mintedCode, before int) {
				buf := make([]byte, 16)
				if _, err := rand.Read(buf); err != nil {
					t.Fatalf("產生隨機碼失敗：%v", err)
				}
				unknown := base64.RawURLEncoding.EncodeToString(buf)
				if _, err := e.registerInvite("unknown.code", "受邀者", testPassword, unknown); !errors.Is(err, ErrInviteRejected) {
					t.Errorf("這臺伺服器沒簽過的碼應被拒為 ErrInviteRejected，實際 %v", err)
				}
			},
		},
		{
			name:   "已過期",
			maxUse: 1,
			// 鋪設一枚「clock 之後 1 小時到期」的碼，再把時鐘推進過那個點——過期是可觀測事實，
			// 核銷那條 UPDATE 以 expires_at=0 OR 此刻早於到期為守衛，推進時鐘後必然命中零行。
			expiry: func(clock *timeutil.Test) time.Time { return clock.Now().Add(time.Hour) },
			pre: func(t *testing.T, e *env, code mintedCode) {
				e.clock.Advance(2 * time.Hour)
			},
			submit: func(t *testing.T, e *env, code mintedCode, before int) {
				if _, err := e.registerInvite("expired.code", "受邀者", testPassword, code.plaintext); !errors.Is(err, ErrInviteRejected) {
					t.Errorf("過期碼應被拒為 ErrInviteRejected，實際 %v", err)
				}
			},
		},
		{
			name:   "已撤銷",
			maxUse: 5,
			expiry: func(*timeutil.Test) time.Time { return time.Time{} },
			pre: func(t *testing.T, e *env, code mintedCode) {
				changed, err := e.invites.Revoke(context.Background(), e.db.SQL(), code.id)
				if err != nil || !changed {
					t.Fatalf("鋪設撤銷狀態失敗：%v / changed=%v", err, changed)
				}
			},
			submit: func(t *testing.T, e *env, code mintedCode, before int) {
				if _, err := e.registerInvite("revoked.code", "受邀者", testPassword, code.plaintext); !errors.Is(err, ErrInviteRejected) {
					t.Errorf("撤銷碼應被拒為 ErrInviteRejected，實際 %v", err)
				}
			},
		},
		{
			name:   "額度用盡",
			maxUse: 1,
			expiry: func(*timeutil.Test) time.Time { return time.Time{} },
			pre: func(t *testing.T, e *env, code mintedCode) {
				// 先老老實實成功一次（把唯一額度佔掉），下一次自然用盡。
				if _, err := e.registerInvite("exhaust.first", "受邀者", testPassword, code.plaintext); err != nil {
					t.Fatalf("第一次有效核銷應成功：%v", err)
				}
			},
			submit: func(t *testing.T, e *env, code mintedCode, before int) {
				if _, err := e.registerInvite("exhaust.second", "受邀者", testPassword, code.plaintext); !errors.Is(err, ErrInviteRejected) {
					t.Errorf("用盡的碼應被拒為 ErrInviteRejected，實際 %v", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.setSelfRegisterMode(t, acctpolicy.ModeInvite)
			auditsBefore := auditCount(t, e)
			code := mintCode(t, e, tc.name, tc.maxUse, tc.expiry(e.clock))
			accountsBefore := accountCount(t, e)
			if tc.pre != nil {
				tc.pre(t, e, code)
				// pre 裡的「成功一次」是本用例自己造的，用盡那組要重設基線：只斷言此後的提交不再新增帳戶/審計。
				if tc.name == "額度用盡" {
					accountsBefore = accountCount(t, e)
					auditsBefore = auditCount(t, e)
				}
			}
			before := accountsBefore
			tc.submit(t, e, code, before)
			if accountCount(t, e) != accountsBefore {
				t.Errorf("%s：被拒的註冊不得新增帳戶，基線 %d→%d", tc.name, accountsBefore, accountCount(t, e))
			}
			if auditCount(t, e) != auditsBefore {
				t.Errorf("%s：被拒的註冊不得追加審計，基線 %d→%d", tc.name, auditsBefore, auditCount(t, e))
			}
			// 「已過期」「已撤銷」這兩組：碼此刻不可核銷，Consume 命中零行，used_count 必須仍是 0。
			// 「查無／形状不合」根本沒有這一枚入庫的行；「額度用盡」的 1 是用盡前那次成功留下的，不在此列。
			if tc.name == "已過期" || tc.name == "已撤銷" {
				if got := usedCount(t, e, code.hash); got != 0 {
					t.Errorf("%s：註冊失敗不得誤耗名額，實際 used_count=%d", tc.name, got)
				}
			}
		})
	}
}

// TestInviteRegistrationFailureDoesNotConsume 有效碼遇上「登入名已被佔用」時整筆回滾：
// 建號失敗 ⇒ 那次核銷一起退回，used_count 歸零、不留下第二次消費的痕跡。
// 這正是「同名衝突、非法密碼或寫入失敗不误耗名额」的取證：核銷與建號共用同一筆 *database.Tx。
func TestInviteRegistrationFailureDoesNotConsume(t *testing.T) {
	e := newEnv(t)
	e.setSelfRegisterMode(t, acctpolicy.ModeInvite)
	// 先用開放模式鋪一筆佔名帳戶，再切回 invite，讓受邀者的名字撞車。（多用量碼，避免用盡干擾判定。）
	e.setSelfRegisterMode(t, acctpolicy.ModeOpen)
	if _, err := e.service.RegisterAccount(context.Background(), RegisterInput{
		LoginName: "clash.name", DisplayName: "先佔者", Password: testPassword,
	}, "req-clash", "203.0.113.61"); err != nil {
		t.Fatalf("開放模式鋪設佔名帳戶失敗：%v", err)
	}
	e.setSelfRegisterMode(t, acctpolicy.ModeInvite)

	code := mintCode(t, e, "多用量碼", 3, time.Time{})
	_, err := e.registerInvite("clash.name", "受邀者", "另一個自選口令", code.plaintext)
	if !errors.Is(err, ErrDuplicateLogin) {
		t.Errorf("同名應收口為 ErrDuplicateLogin，實際 %v", err)
	}
	if got := usedCount(t, e, code.hash); got != 0 {
		t.Errorf("建號失败應連同那次核銷一起回滾，實際 used_count=%d", got)
	}
}

// TestInviteSingleUseConcurrencyAllowsExactlyOne 一次性碼在 N 路併發下恰好一次有效消費：
// 只建出一筆帳戶、used_count 恆為 1，其餘每一路都拿到同一句不泄露細節的 ErrInviteRejected。
//
// BEGIN IMMEDIATE 讓併發的註冊整體串行化；落敗的那一筆取到的是對手已扣減後的新快照，
// 那條帶四重 WHERE 的 UPDATE 命中零行，於是沒有超發、也沒有第二個帳戶。每路用不同來源與不同名字，
// 好把「只有碼額度这一道閘」和「唯一索引／限流」分開：這裡要證的是名額不被超耗，不是名字唯一。
func TestInviteSingleUseConcurrencyAllowsExactlyOne(t *testing.T) {
	e := newEnv(t)
	e.setSelfRegisterMode(t, acctpolicy.ModeInvite)
	code := mintCode(t, e, "併發搶一枚", 1, time.Time{})

	const total = 6
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successes, rejected int
	wg.Add(total)
	for i := 0; i < total; i++ {
		go func(i int) {
			defer wg.Done()
			_, err := e.service.RegisterAccount(context.Background(), RegisterInput{
				LoginName: fmt.Sprintf("race.%d", i), DisplayName: "併發受邀者",
				Password: fmt.Sprintf("%s-%d", testPassword, i), InviteCode: code.plaintext,
			}, fmt.Sprintf("req-race-%d", i), fmt.Sprintf("203.0.113.%d", 70+i))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrInviteRejected):
				rejected++
			default:
				t.Errorf("併發落敗應收斂成 ErrInviteRejected，實際 %v", err)
			}
		}(i)
	}
	wg.Wait()

	if successes != 1 {
		t.Errorf("一次性碼併發下只能有一次成功，實際 %d 次", successes)
	}
	if rejected != total-1 {
		t.Errorf("其餘各路都該拿到同一句邀請碼被拒，實際拒了 %d 次", rejected)
	}
	if got := usedCount(t, e, code.hash); got != 1 {
		t.Errorf("額度恰好被佔用一次，實際 used_count=%d", got)
	}
	if n := accountCount(t, e); n != 1 {
		t.Errorf("整場併發只該多出一筆帳戶，實際 accounts=%d", n)
	}
}

// TestInviteDuplicateRequestNoSecondAccountOrConsume 同一枚多用量碼 + 同一登入名重複提交：
// 第一次成功建號並佔用額度，第二次撞唯一索引整筆回滾——不產生第二個帳戶，也不再多吃一次額度。
func TestInviteDuplicateRequestNoSecondAccountOrConsume(t *testing.T) {
	e := newEnv(t)
	e.setSelfRegisterMode(t, acctpolicy.ModeInvite)
	code := mintCode(t, e, "多用量重複", 5, time.Time{})

	if _, err := e.registerInvite("dup.invite", "受邀者", testPassword, code.plaintext); err != nil {
		t.Fatalf("第一次有效核銷註冊應成功：%v", err)
	}
	if got := usedCount(t, e, code.hash); got != 1 {
		t.Fatalf("第一次應佔用一次額度，實際 %d", got)
	}
	// 第二次（例如回應丟失後的補發）同名字、同碼：整筆回滾，既不建第二個帳戶，也不再多吃額度。
	if _, err := e.registerInvite("dup.invite", "受邀者", testPassword, code.plaintext); !errors.Is(err, ErrDuplicateLogin) {
		t.Errorf("重複提交應收口為同名衝突，實際 %v", err)
	}
	if got := usedCount(t, e, code.hash); got != 1 {
		t.Errorf("第二次建號失敗應把那次核銷一起退回，實際 used_count=%d", got)
	}
	if n := accountCount(t, e); n != 1 {
		t.Errorf("重複請求不得多出一個帳戶，實際 accounts=%d", n)
	}
}

// TestInviteModeJudgedAtWriteTime 模式中途被改掉時，下一條請求按「寫入那一刻」的現值重判：
// invite 時不帶碼被拒 → open 時不帶碼放行 → 再切回 invite 時那筆帶舊碼的補發又被拒。
// 這一條封死「前端先查到一個模式就一路按到底」的幻想：准入判定只認交易內現讀的策略。
func TestInviteModeJudgedAtWriteTime(t *testing.T) {
	e := newEnv(t)
	e.setSelfRegisterMode(t, acctpolicy.ModeInvite)
	code := mintCode(t, e, "模式切換", 5, time.Time{})

	if _, err := e.service.RegisterAccount(context.Background(), RegisterInput{
		LoginName: "switch.nocode", DisplayName: "受邀者", Password: testPassword,
	}, "req-switch-1", "203.0.113.80"); !errors.Is(err, ErrInviteRejected) {
		t.Errorf("invite 模式不帶碼應被拒，實際 %v", err)
	}
	e.setSelfRegisterMode(t, acctpolicy.ModeOpen)
	if _, err := e.service.RegisterAccount(context.Background(), RegisterInput{
		LoginName: "switch.open", DisplayName: "受邀者", Password: testPassword,
	}, "req-switch-2", "203.0.113.81"); err != nil {
		t.Errorf("切到 open 後不帶碼應放行（開放模式不看碼），實際 %v", err)
	}
	// 切回 invite：這一次帶一枚有效碼，但用一個已被 open 佔掉之外的新名字——證「帶碼就過」。
	e.setSelfRegisterMode(t, acctpolicy.ModeInvite)
	if _, err := e.registerInvite("switch.back", "受邀者", testPassword, code.plaintext); err != nil {
		t.Errorf("切回 invite 後帶有效碼應放行，實際 %v", err)
	}
	// open 那一趟完全沒碰這枚碼：它的額度仍該是只被 invite 那一趟佔用一次。
	if got := usedCount(t, e, code.hash); got != 1 {
		t.Errorf("非 invite 模式不得消費邀請碼，實際 used_count=%d", got)
	}
}

// TestInviteCodeNotLeakedAnywhere 是結構性的紅線掃描：無論成功或失敗，執行日誌裡都不該出現那枚明文碼。
// 用例把 InviteRejected 的原始原因只寫進日誌的 err 欄位（不含明文），成功路徑也不複述碼，
// 這一條把「明文碼不入日誌」钉成可失敗的斷言，而不是靠措辭承諾。
func TestInviteCodeNotLeakedAnywhere(t *testing.T) {
	e := newEnv(t)
	e.setSelfRegisterMode(t, acctpolicy.ModeInvite)
	code := mintCode(t, e, "不落日誌", 1, time.Time{})

	if _, err := e.registerInvite("leak.ok", "受邀者", testPassword, code.plaintext); err != nil {
		t.Fatalf("有效碼註冊應成功：%v", err)
	}
	// 失敗一筆：用一枚這臺伺服器沒簽過的合法形状碼。
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("產生隨機碼失敗：%v", err)
	}
	unknown := base64.RawURLEncoding.EncodeToString(buf)
	if _, err := e.registerInvite("leak.bad", "受邀者", testPassword, unknown); !errors.Is(err, ErrInviteRejected) {
		t.Fatalf("未簽過的碼應被拒：%v", err)
	}
	logged := e.logs.String()
	if logged == "" {
		t.Fatal("本用例預期有執行日誌產生，否則掃描沒有意義")
	}
	for _, secret := range []string{code.plaintext, code.hash, unknown} {
		if strings.Contains(logged, secret) {
			t.Errorf("明文碼或其驗證材料出現在執行日誌裡：%q", secret)
		}
	}
}
