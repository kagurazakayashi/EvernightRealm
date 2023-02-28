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
// 這一條是分岔點，而且它會隨著通路落地而移動——這正是它存在的理由：
//   - closed／open 兩者皆真（不開放不需要通路支撐，開放的通路早已落地）；
//   - approval 兩側皆真：收申請與本人查狀態已經落地（見 internal/selfregister），
//     Root 把模式設成 approval 得到的是「收待審批申請、一個也不放行」，這句話本身可執行、可核實；
//   - invite 本步起兩側皆真：邀請碼的簽發／撤銷（internal/invitecode）與「拿一枚有效碼在自己的交易裡
//     原子核銷、換出一筆可立即登入的普通帳戶」（internal/selfregister 的 invite 分支）都已落地，
//     Root 把模式設成 invite 得到的是「持有效碼者可自行註冊並立即登入」，這句話可執行、可核實。
//
// 換言之「合法」與「寫得進」的定義都沒動，動的是通路登記表裡哪一欄翻真了。
// 這一格翻真的同時，Mode.writable 不再自己記名單，而是經 ModeServed 問 capabilities()——
// 日後某條通路落地或被撤下時只需要多登記／翻動一欄，這條測試跟著翻一個取值即可。
func TestModeWritableGate(t *testing.T) {
	cases := []struct {
		mode     Mode
		valid    bool
		writable bool
	}{
		{ModeClosed, true, true},
		{ModeOpen, true, true},
		{ModeApproval, true, true},
		{ModeInvite, true, true},
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
// 訪客通路已落地（見 internal/guestacct）：GuestOpen 現在等於策略開關本身，
// 而合成仍走 AllowsGuest——把開關當能力的那條紀律沒被取消，只是這一格的能力位翻真了。
// 自註冊那一側現在問的是 ModeServed（本版本服務得動 open 與 approval 兩種）：
//   - open：提交即成一個可登入的帳戶，入口自然放；
//   - approval：提交收成一筆待審批申請，而那個「等」字有資料層與本人查狀態的通路接得住，
//     所以門也放——注意它放的是「這扇門推得開」，不是「進去就有帳號用」，
//     那句由提交成功的回應裡 status 各自說（匿名入口不透露模式名字，用戶批准於 R2-006／R2-012）；
//   - invite：邀請碼的簽發＋核銷已落地，門也放，且 InviteCodeRequired 為 true——
//     這一趟要帶一枚有效碼。它只講「要不要帶碼」這一件可執行的小事，仍不回模式名字本身。
//
// InviteCodeRequired 只在生效模式確為 invite 時為 true，open／approval／closed 一律 false，
// 讓共享的匿名註冊表單據此顯示邀請碼欄位，而寫入那一刻的重判由 internal/selfregister 做。
// AllowsSelfRegister 的契約與對外答案不同：它對任何有效非 closed 模式都回 true 並帶出模式，
// 分辨「放行的是哪一種」是使用例經 ModeServed 做的事；零值 "" 不是有效模式，兩側都關。
func TestEntryOfKeepsEachSideGated(t *testing.T) {
	cases := []struct {
		name                   string
		mode                   Mode
		wantSignUpOpen         bool
		wantInviteCodeRequired bool
		wantSelfRegisterOK     bool
	}{
		{"open", ModeOpen, true, false, true},
		{"closed", ModeClosed, false, false, false},
		{"approval（准入已上線：對外開、要碼欄關、Allows 帶出模式）", ModeApproval, true, false, true},
		{"invite（通路已上線：對外開、要碼欄開、Allows 帶出模式）", ModeInvite, true, true, true},
		{"零值 \"\"（不是有效模式，兩側都關）", Mode(""), false, false, false},
	}
	for _, tc := range cases {
		p := Policy{AdminCreateStandard: true, SelfRegisterMode: tc.mode, GuestEnabled: true}
		entry := p.EntryOf()
		if entry.SignUpOpen != tc.wantSignUpOpen {
			t.Errorf("%s：SignUpOpen 應為 %v，實際 %v", tc.name, tc.wantSignUpOpen, entry.SignUpOpen)
		}
		if entry.InviteCodeRequired != tc.wantInviteCodeRequired {
			t.Errorf("%s：InviteCodeRequired 應為 %v，實際 %v", tc.name, tc.wantInviteCodeRequired, entry.InviteCodeRequired)
		}
		// 訪客通路已落地：策略開關為真時對外即放，而且它與自註冊的模式無關
		// （五個模式取值下都該是開——訪客只有一個開關，不借用模式那一格）。
		if !entry.GuestOpen {
			t.Errorf("%s：訪客開關為真且通路已落地，GuestOpen 應為真", tc.name)
		}
		if !p.AllowsGuest() {
			t.Errorf("%s：訪客通路已落地而開關為真，Allows 應為真", tc.name)
		}
		// 關掉時必須立刻收回：這一格是「策略 ∧ 通路」裡策略那一側的證據，
		// 也是 Root 唯一能让訪客入口消失的動作。
		off := p
		off.GuestEnabled = false
		if off.EntryOf().GuestOpen || off.AllowsGuest() {
			t.Errorf("%s：訪客開關關掉後對外與准入都應立即收回", tc.name)
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
// 管理員建號（internal/stdacct）、匿名自註冊（internal/selfregister）與邀請碼准入
// （簽發／撤銷見 internal/invitecode、核銷換號見 internal/selfregister 的 invite 分支）都已落地而翻真，
// 訪客通路（internal/guestacct）也已落地，四位全真。
func TestCapabilitiesReflectThisBuild(t *testing.T) {
	caps := capabilities()
	if !caps.AdminCreateStandard {
		t.Error("管理員建立普通帳戶的通路已落地，能力登記該位必須為真")
	}
	if !caps.SelfRegister {
		t.Error("匿名自註冊的通路已落地，能力登記該位必須為真")
	}
	if !caps.SelfRegisterApproval {
		t.Error("自註冊核准通路的收申請與本人查狀態已落地，能力登記該位必須為真")
	}
	if !caps.SelfRegisterInvite {
		t.Error("邀請碼准入的簽發／撤銷與核銷換號已落地，能力登記該位必須為真")
	}
	if !caps.Guest {
		t.Errorf("訪客進入的用例與端點已落地，能力登記該位必須為真，實際 %+v", caps)
	}
}
