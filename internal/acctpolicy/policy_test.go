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

// TestEntryOfNeverOpensWithoutCapability 是本步最重要的一條：通路尚未實作時，
// 任何策略組合都算不出「對外開放」。
//
// 反過來的缺陷（把開關當能力）會是：Root 打開自註冊，登入前的畫面就出現一個
// 按下去必然失敗的註冊入口——那是讓未開發的模組冒充可用。
// 管理員建號那一條通路已落地，因此它不再受「恆為假」約束： Allows 合成結果
// 恰等於策略開關本身，而對外兩個布林與它無關（那個開關從不對門外揭露）。
func TestEntryOfNeverOpensWithoutCapability(t *testing.T) {
	combos := []Policy{
		{AdminCreateStandard: true, SelfRegisterMode: ModeOpen, GuestEnabled: true},
		{SelfRegisterMode: ModeOpen},
		{GuestEnabled: true},
		{AdminCreateStandard: true, SelfRegisterMode: ModeApproval, GuestEnabled: true},
	}
	for i, p := range combos {
		entry := p.EntryOf()
		if entry.SignUpOpen || entry.GuestOpen {
			t.Errorf("第 %d 組：自註冊與訪客通路都不存在，對外答案應全為關，實際 %+v", i+1, entry)
		}
		if p.AllowsAdminCreateStandard() != p.AdminCreateStandard {
			t.Errorf("第 %d 組：建號通路已落地，Allows 應恰等於策略開關 %v，實際 %v",
				i+1, p.AdminCreateStandard, p.AllowsAdminCreateStandard())
		}
		if ok, _ := p.AllowsSelfRegister(); ok {
			t.Errorf("第 %d 組：自註冊通路未實作，Allows 應為假", i+1)
		}
		if p.AllowsGuest() {
			t.Errorf("第 %d 組：訪客通路未實作，Allows 應為假", i+1)
		}
	}
}

// TestAllowsSelfRegisterKeepsMode 驗證 Allows 同時給出「放不放行」與「按哪種模式放行」。
//
// 模式要一起回：日後自註冊通路落地時，closed 與 open 的差別就在這個返回值上，
// 而呼叫端不該再去比一次字串（兩處判定的結果遲早不一致）。
func TestAllowsSelfRegisterKeepsMode(t *testing.T) {
	closed := Policy{SelfRegisterMode: ModeClosed}
	ok, mode := closed.AllowsSelfRegister()
	if ok || mode != ModeClosed {
		t.Errorf("closed 應不放行並原樣帶出模式，實際 %v/%q", ok, mode)
	}
	open := Policy{SelfRegisterMode: ModeOpen}
	ok, mode = open.AllowsSelfRegister()
	if ok || mode != ModeOpen {
		t.Errorf("通路未實作時 open 仍不應放行，且模式要如實帶出，實際 %v/%q", ok, mode)
	}
}

// TestCapabilitiesReflectThisBuild 把「本版本哪幾條建立通路存在」釘成一條可失敗的斷言。
//
// 它不是湊數：日後某人實作了自註冊卻忘了在 capabilities 裡改一位，對外入口就不會開放，
// 而那正是「做了功能但沒上線」最難查的形態；這條斷言會把他導向那個唯一的登記點。
// 管理員建號已隨 internal/stdacct 落地而翻真，其餘兩條仍必須是假。
func TestCapabilitiesReflectThisBuild(t *testing.T) {
	caps := capabilities()
	if !caps.AdminCreateStandard {
		t.Error("管理員建立普通帳戶的通路已落地，能力登記該位必須為真")
	}
	if caps.SelfRegister || caps.Guest {
		t.Errorf("自註冊與訪客通路仍未實作，能力登記該兩位應為假，實際 %+v", caps)
	}
}
