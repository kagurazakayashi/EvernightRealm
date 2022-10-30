// device.go 是裝置登入策略的落點：一個主體能同時握有幾份「還換得出身份」的會話。
//
// 這個檔案存在的理由是一個具體的失敗形態——「名額」如果由客戶端宣稱，策略就等於沒有：
// 裝置名稱、型號、使用者可改的標識全都是請求裡的可寫欄位，拿它們計數等於把額度交給
// 被限制的那一方填寫。因此本檔只認一件事：主體（由 internal/identity 的受信主體換得，
// 見 SubjectOf）在 sessions 表裡還有幾行有效記錄。客戶端連一個用來「報自己是哪臺裝置」
// 的欄位都還沒有，名額就已經算完了。
//
// 三個模式的邊界（數值由組態 security.device_policy 決定，不在這裡發明的產品規則）：
//   - single：新登入成功時，該主體原有的有效會話一律失效。人只該在一臺裝置上線上。
//   - multi ：有效會話並存、不封頂（預設，也是本項存在之前的行為）。
//   - limited：並存但封頂；名額已滿時新的登入整個不發生（拒絕，不是淘汰既有的某臺）。
//
// 「一個登入會話＝一個裝置名額」這條對應關係是刻意挑的，不是巧合：
// sessions 行的 device_id 就是使用者可見的裝置標識（遷移 0004 的三個標識分工），
// 一行只可能來自一次登入，因此不需要另一張「裝置表」去描述同一件事——
// 多一張表就多一個可以和事實不一致的地方，而它的答案本來就能由會話行讀出來。
// 由此推出兩條必須成立的性質：
//   - 輪換不佔新名額：Rotate 是同一行換秘密（device_id 不動），有效行數沒有變；
//   - 重複登入不會無限累積名額：single 恆定 1 份，limited 恆 <= 上限，
//     而名額算的是「還換得出身份」的行——撤銷、絕對到期、閒置失效都立刻把名額還回去。
//
// 活動級覆蓋不在本檔：那一層需要「這個主體在這場活動裡的身份」才能判定，
// 而活動作用域尚未落地（AGENTS.md §7：不得虛構活動範圍）。本步留下的擴充套件點是
// ApplyLoginSlotPolicy 這一個入口——未來的活動級覆蓋是把「套哪套策略」的解析
// 換成按 (主體, 活動) 取值，計數與撤銷的落點不再長出第二份實作。
package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// DeviceMode 是裝置登入策略的模式（組態 security.device_policy.mode 的領域形態）。
type DeviceMode string

const (
	// DeviceModeSingle 是一人一機：新登入成功時撤銷該主體其餘全部有效會話。
	DeviceModeSingle DeviceMode = "single"
	// DeviceModeMulti 是「多裝置並存且不封頂」，也是零值語意（沿用本項之前的行為）。
	DeviceModeMulti DeviceMode = "multi"
	// DeviceModeLimited 是「並存但封頂」：名額已滿時拒絕新登入，不擅自淘汰任何一臺。
	DeviceModeLimited DeviceMode = "limited"
)

// String 回傳組態與日誌使用的機器表示。
func (m DeviceMode) String() string { return string(m) }

// normalize 把零值換成實際生效的模式。
//
// 零值必須有明確含義（不是「未設定所以再猜一次」）：Policy 的零值取向一直是
// 「除絕對期限外全部沿用既有行為」，裝置策略的對應值就是 multi（不封頂）。
func (m DeviceMode) normalize() DeviceMode {
	if m == "" {
		return DeviceModeMulti
	}
	return m
}

// validate 檢查模式是否為已定義值。
//
// 不認識的模式是裝配缺陷（組態層已先擋過一次），當場報錯而不是退回預設：
// 「以為自己設了 single、實際跑的是 multi」這種落差比啟動失敗難查得多。
func (m DeviceMode) validate() error {
	switch m.normalize() {
	case DeviceModeSingle, DeviceModeMulti, DeviceModeLimited:
		return nil
	default:
		return fmt.Errorf("session: 不認識的裝置策略模式 %q（僅 single|multi|limited）", string(m))
	}
}

// ParseDeviceMode 解析組態字串為 DeviceMode；空值表示沿用預設（multi）。
//
// 裝配層（internal/app）用它在啟動時把 security.device_policy.mode 換成領域值。
// 組態層已經先做過同一條列舉檢查，這裡是第二道閘：兩邊都守，裝配程式碼寫錯時
// 上線的是錯誤訊息而不是半套策略。
func ParseDeviceMode(value string) (DeviceMode, error) {
	m := DeviceMode(value).normalize()
	if err := m.validate(); err != nil {
		return "", err
	}
	return m, nil
}

// validate 檢查裝置策略的自洽性（由 NewStoreWithPolicy 在構造時呼叫）。
//
// 名額只認 limited：其它模式帶著一個正的名額數字，代表兩套互相矛盾的決定同時被寫下來，
// 而「其中一個其實是死的」這件事在運維側完全看不出來——構造階段當場拒絕比猜意圖誠實。
func (p Policy) validate() error {
	if err := p.DeviceMode.validate(); err != nil {
		return err
	}
	switch p.DeviceMode.normalize() {
	case DeviceModeLimited:
		if p.MaxDevices < 1 {
			return fmt.Errorf("session: limited 模式的裝置名額必須為正值，實際 %d", p.MaxDevices)
		}
	default:
		if p.MaxDevices != 0 {
			return fmt.Errorf("session: 裝置名額只在 limited 模式使用，模式 %q 時必須留 0（實際 %d）",
				string(p.DeviceMode), p.MaxDevices)
		}
	}
	return nil
}

// ApplyLoginSlotPolicy 在簽發新會話之前執行裝置名額策略；必須與後面的 Create 同屬一個交易。
//
// 回傳值是「這一次因為策略而被撤銷的會話數」，只在 single 模式可能大於 0。
// 它是可展示事實（給日誌與 Root 審計用），不含任何憑據材料。
//
// 為什麼必須在交易內、而且是「建會話之前」：
//   - 檢查與寫入之間如果隔著事務邊界，併發的兩次登入會各自數到「還差一格」，
//     兩份都會簽發出去，上限就變成 2N。同一個交易（預設 BEGIN IMMEDIATE，
//     見 internal/database）把「讀計數」與「插一行」壓在同一個寫者鎖後面，
//     第二個登入不是擠進去的，是明確看到名額已滿而被拒。
//   - single 模式在此刻撤銷舊行，新的那一行隨後在同一個交易裡插入；
//     中途任何一步失敗（含帳戶此刻不可用）整個交易回滾，出結論時不會出現
//     「舊會話已被停掉、新會話卻沒簽發出去」這種把人關在門外的半套結果。
//
// 名額算的是「此刻還換得出身份」的會話：未撤銷、未過絕對期限、且（啟用閒置時）
// 未過閒置線。這與 Verify 的拒絕條件逐字同源（見 liveScope），因此不會出現
// 「 Verify 說它已經死了、計數卻還算它佔一格」這種兩個時鐘。
//
// 錯誤只有兩類：ErrDeviceLimitReached（策略拒絕，呼叫端據此回對外結論）與
// 資料庫故障（非拒絕，不得報成 4xx）。主體不合格由 SubjectOf 擋下。
func (s *Store) ApplyLoginSlotPolicy(ctx context.Context, q database.Querier,
	p identity.Principal) (int, error) {
	if q == nil {
		return 0, errors.New("session: 需要可用的資料庫連線或交易")
	}
	subject, err := SubjectOf(p)
	if err != nil {
		return 0, err
	}
	switch s.policy.DeviceMode.normalize() {
	case DeviceModeSingle:
		// 先撤銷該主體其餘全部有效會話：新簽發的那一行是本模式下唯一留下的名額。
		n, err := s.revokeLive(ctx, q, subject)
		if err != nil {
			return 0, err
		}
		return n, nil
	case DeviceModeLimited:
		n, err := s.countLive(ctx, q, subject)
		if err != nil {
			return 0, err
		}
		if n >= s.policy.MaxDevices {
			// 刻意不把上限、現有行數、是哪幾臺裝置放進錯誤文字：這個結論要能被
			// 直接回給客戶端，而「你現在有 3 臺、上限是 50」屬於伺服器的內部配置。
			return 0, fmt.Errorf("%w：主體 %s 的有效會話已達上限", ErrDeviceLimitReached, subject.String())
		}
		return 0, nil
	default:
		// multi（含零值）：不封頂，也不撤銷任何既有會話。
		return 0, nil
	}
}

// liveScope 產生「此刻還換得出身份」的 WHERE 片段與對應引數。
//
// 三個條件都必須有：revoked_at 與 expires_at 是資料庫裡的事實，閒置線則由本倉儲的
// 政策決定（IdleTTL 不為正時整個條件不成立，也就是不啟用）。
// 閒置寫成算術（last_active_at + 閒置毫秒 > 現在毫秒）而不是把換算好的截止時刻交出去：
// 這樣閒置閾值始終只在 Policy 一處，呼叫端不可能拿一個自己算的閾值來繞過計數。
// 主體範圍與 RevokeSubject 同形（Root 按 subject_kind、帳戶按 account_id），
// 一個人的額度只由他自己是誰決定，與請求裡的其他欄位無關。
func (s *Store) liveScope(subject Subject, now time.Time) (string, []any) {
	clause := "subject_kind = ? AND revoked_at IS NULL AND expires_at > ?"
	args := []any{string(subject.kind), timeutil.ToMillis(now)}
	if subject.kind == SubjectAccount {
		clause += " AND account_id = ?"
		args = append(args, subject.accountID.String())
	}
	if s.policy.IdleTTL > 0 {
		clause += " AND last_active_at + ? > ?"
		args = append(args, s.policy.IdleTTL.Milliseconds(), timeutil.ToMillis(now))
	}
	return clause, args
}

// countLive 回報該主體此刻還換得出身份的會話數。
func (s *Store) countLive(ctx context.Context, q database.Querier, subject Subject) (int, error) {
	clause, args := s.liveScope(subject, s.clock.Now())
	var n int
	// 表名與欄名都是本套件自己拼的常量，只有值是引數：這裡沒有字串注入面。
	if err := q.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sessions WHERE "+clause, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("session: 統計有效會話失敗: %w", err)
	}
	return n, nil
}

// revokeLive 撤銷該主體此刻還換得出身份的全部會話，回傳撤銷行數。
//
// 一條 UPDATE 完成：這正是「不能指望呼叫端先列出會話再逐個撤銷」的理由（同 RevokeSubject）。
// revoked_at 用當前時刻寫入，遷移 0004 的 CHECK 保證它不早於 created_at
// （能被這條語句命中的行必然已經通過 expires_at > now，因此必然早於此刻）。
func (s *Store) revokeLive(ctx context.Context, q database.Querier, subject Subject) (int, error) {
	now := s.clock.Now()
	clause, args := s.liveScope(subject, now)
	query := "UPDATE sessions SET revoked_at = ? WHERE " + clause
	args = append([]any{timeutil.ToMillis(now)}, args...)
	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("session: 撤銷主體舊會話失敗: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("session: 讀取撤銷數量失敗: %w", err)
	}
	return int(n), nil
}
