// policy_test.go 是策略領域值的證據：模式集合的邊界、三個開關彼此獨立，
// 以及「策略值不等於能力」這句話在合成上真的成立（尚未實作的通路不可能被開關變可用）。
package acctpolicy

import (
	"errors"
	"testing"
)

// TestParseModeAcceptsOnlyApprovedNames 驗證模式解析只認四個已批准名字。
func TestParseModeAcceptsOnlyApprovedNames(t *testing.T) {
	for _, want := range []Mode{ModeClosed, ModeOpen, ModeApproval, ModeInvite} {
		got, err := ParseMode(want.String())
		if err != nil {
			t.Errorf("模式 %q 為已批准名字，應解析成功：%v", want, err)
			continue
		}
		if got != want {
			t.Errorf("模式解析應回 %q，實際 %q", want, got)
		}
	}

	// 不做大小寫正規化、不修剪空白、不放行空字串：這些都不是任何一句被批准的話。
	for _, text := range []string{"", "  ", "Closed", "OPEN", "open ", "pending", "auto", "CLOSED"} {
		got, err := ParseMode(text)
		if !errors.Is(err, ErrUnknownMode) {
			t.Errorf("模式 %q 應被拒（ErrUnknownMode），實際回 %q / %v", text, got, err)
		}
		if got != "" {
			t.Errorf("模式 %q 被拒時應回零值，實際 %q", text, got)
		}
	}
}

// TestModeWritableGate 驗證「名字已批准」與「本版本寫得進去」是兩件事。
//
// 這一條是分岔點：approval／invite 的 valid 為真（形態合法）、writable 為假（通路未落地）。
// 把兩者混為一談的話，要嘛介面現在就能記一種執行不了的模式，要嘛日後加模式時
// 必須改寫既有注釋裡那句「合法」的定義。
func TestModeWritableGate(t *testing.T) {
	cases := []struct {
		mode     Mode
		valid    bool
		writable bool
	}{
		{ModeClosed, true, true},
		{ModeOpen, true, true},
		{ModeApproval, true, false},
		{ModeInvite, true, false},
		{Mode("pending"), false, false},
	}
	for _, tc := range cases {
		if got := tc.mode.valid(); got != tc.valid {
			t.Errorf("模式 %q 的 valid 應為 %v，實際 %v", tc.mode, tc.valid, got)
		}
		if got := tc.mode.writable(); got != tc.writable {
			t.Errorf("模式 %q 的 writable 應為 %v，實際 %v", tc.mode, tc.writable, got)
		}
	}
}

// TestPolicyValidate 驗證策略形態復核只認四個名字。
func TestPolicyValidate(t *testing.T) {
	for _, mode := range []Mode{ModeClosed, ModeOpen, ModeApproval, ModeInvite} {
		p := Policy{SelfRegisterMode: mode}
		if err := p.Validate(); err != nil {
			t.Errorf("模式 %q 是合法取值，Validate 不應失敗：%v", mode, err)
		}
	}
	if err := (Policy{SelfRegisterMode: Mode("maybe")}).Validate(); err == nil {
		t.Error("不認識的模式應被 Validate 擋下")
	}
}

// TestSwitchesAreIndependent 驗證三個值能被獨立設定也獨立讀回。
//
// 「只關掉自註冊、訪客照常開放」這種組合是這個功能存在的理由之一：
// 若哪天有人把三個欄位壓成一個列舉，這條會先紅。
func TestSwitchesAreIndependent(t *testing.T) {
	p := Policy{AdminCreateStandard: true, SelfRegisterMode: ModeClosed, GuestEnabled: true}
	if !p.AdminCreateStandard || !p.GuestEnabled || p.SelfRegisterMode != ModeClosed {
		t.Fatalf("三個值應各自保留，實際 %+v", p)
	}
	if p.SelfRegisterMode != ModeClosed {
		t.Error("訪客開放不應把自註冊模式一起改成 open")
	}
}

// TestEntryOfKeepsEachSideGated 把「對外答案 = 策略 ∧ 通路 ∧ 可服務的模式」釘死。
//
// 訪客通路仍未實作：無論策略怎麼設，GuestOpen 恆為關（把開關當能力會讓自己沒有的入口冒充可用）。
// 自註冊通路已隨 internal/selfregister 落地，因此 SignUpOpen 不再恆為關——但只在
// 「模式=open」時才對外放開：closed 是部署者關著，approval／invite 的准入流程還沒上線，
// 三者都不該在登入前畫面上出現一個按下去必然失敗的註冊入口。
// AllowsSelfRegister 的契約與對外答案不同：它對任何有效非 closed 模式都回 true 並帶出模式，
// 由用例去分辨 open 放行、approval／invite 回 2016；零值 "" 不是有效模式，回 false。
func TestEntryOfKeepsEachSideGated(t *testing.T) {
	cases := []struct {
		name               string
		mode               Mode
		wantSignUpOpen     bool
		wantSelfRegisterOK bool
	}{
		{"open", ModeOpen, true, true},
		{"closed", ModeClosed, false, false},
		{"approval（准入未上線，對外關、Allows 帶出模式）", ModeApproval, false, true},
		{"invite（同上）", ModeInvite, false, true},
		{"零值 \"\"（不是有效模式，兩側都關）", Mode(""), false, false},
	}
	for _, tc := range cases {
		p := Policy{AdminCreateStandard: true, SelfRegisterMode: tc.mode, GuestEnabled: true}
		entry := p.EntryOf()
		if entry.SignUpOpen != tc.wantSignUpOpen {
			t.Errorf("%s：SignUpOpen 應為 %v，實際 %v", tc.name, tc.wantSignUpOpen, entry.SignUpOpen)
		}
		// 訪客通路未實作：策略開關再怎麼放，對外都是關。
		if entry.GuestOpen {
			t.Errorf("%s：GuestOpen 在通路未落地時必須恆為關，實際 true", tc.name)
		}
		if p.AllowsGuest() {
			t.Errorf("%s：訪客通路未實作，Allows 應為假", tc.name)
		}
		// 建號通路已落地：Allows 恰等於策略開關（對門外永不揭露，與 EntryOf 無關）。
		if !p.AllowsAdminCreateStandard() {
			t.Errorf("%s：建號通路已落地而開關為真，Allows 應為真", tc.name)
		}
		ok, gotMode := p.AllowsSelfRegister()
		if ok != tc.wantSelfRegisterOK {
			t.Errorf("%s：AllowsSelfRegister 放行與否應為 %v，實際 %v", tc.name, tc.wantSelfRegisterOK, ok)
		}
		if gotMode != tc.mode {
			t.Errorf("%s：AllowsSelfRegister 應原樣帶出模式 %q，實際 %q", tc.name, tc.mode, gotMode)
		}
	}
}

// TestAllowsSelfRegisterKeepsMode 驗證 Allows 同時給出「放不放行」與「按哪種模式放行」。
//
// 模式要一起回：closed 與 open 的差別、以及 open 之外哪些模式該被用例擋掉，
// 都靠這個返回值，而呼叫端不該再去比一次字串（兩處判定的結果遲早不一致）。
func TestAllowsSelfRegisterKeepsMode(t *testing.T) {
	closed := Policy{SelfRegisterMode: ModeClosed}
	ok, mode := closed.AllowsSelfRegister()
	if ok || mode != ModeClosed {
		t.Errorf("closed 應不放行並原樣帶出模式，實際 %v/%q", ok, mode)
	}
	open := Policy{SelfRegisterMode: ModeOpen}
	ok, mode = open.AllowsSelfRegister()
	if !ok || mode != ModeOpen {
		t.Errorf("通路已落地時 open 應放行並帶出模式，實際 %v/%q", ok, mode)
	}
	// 零值不是任何已登記模式：即使通路翻真也不能被算成放行（否則帶著誰也執行不了的模式回 true）。
	zero := Policy{}
	ok, mode = zero.AllowsSelfRegister()
	if ok || mode != Mode("") {
		t.Errorf("零值模式不是有效模式，應不放行且原樣帶出，實際 %v/%q", ok, mode)
	}
}

// TestCapabilitiesReflectThisBuild 把「本版本哪幾條建立通路存在」釘成一條可失敗的斷言。
//
// 它不是湊數：日後某人實作了某條通路卻忘了在 capabilities 裡改一位，對外入口就不會開放，
// 而那正是「做了功能但沒上線」最難查的形態；這條斷言會把他導向那個唯一的登記點。
// 管理員建號（internal/stdacct）與匿名自註冊（internal/selfregister）都已落地而翻真，
// 訪客通路仍未實作，該位必須是假。
func TestCapabilitiesReflectThisBuild(t *testing.T) {
	caps := capabilities()
	if !caps.AdminCreateStandard {
		t.Error("管理員建立普通帳戶的通路已落地，能力登記該位必須為真")
	}
	if !caps.SelfRegister {
		t.Error("匿名自註冊的通路已落地，能力登記該位必須為真")
	}
	if caps.Guest {
		t.Errorf("訪客通路仍未實作，能力登記該位應為假，實際 %+v", caps)
	}
}
