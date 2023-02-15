// roster.go 是「註冊申請名冊」的查詢側：分頁、狀態篩選與名稱關鍵字比對，一次把
// 等審批與已拒絕的申請連同總數給齊。
//
// 這本名冊回答的是「哪些申請還掛在中間」，而不是「哪些人我可以打理」——後一句話屬
// internal/stdacct 那本目錄，它的 WHERE 按範圍規則把 pending 與 rejected 排在門外。
// 兩本書各有各的條件是刻意的（用戶批准的取向）：把那一頁的 WHERE 改寬，
// 「可打理的普通帳戶」與「等審批的申請」就會開始共用一套條件，而這兩句話的處置完全不同
// （一邊有停用／恢復／重置／改名四條通路，另一邊只有批准與拒絕兩顆按鈕）。
//
// 名冊列兩態而不是一態：
//   - pending：還在等決定的人，這是審核者要處理的那一頁；
//   - rejected：已經被拒絕過的人。他列在這裡是為了讓審核者看得見「這個人我已經決定了」，
//     而不是讓我在重複按下時只靠一句錯誤碼回想；今日沒有任何通路能把他翻回 pending，
//     因此這裡也不給他任何可寫的控件（界面據 status 決定按鈕在不在）。
//   - 已批准的人不在這本書裡：他帶著決定時刻離開了審批鏈，並出現在普通帳戶名冊上，
//     此後的停用、重置與改名都是那本名冊的事。
//
// 跨表只讀投影的三條邊界（見套件頭注的「只讀展示投影例外」）逐字沿用其餘兩本名冊：
//   - 只讀：一個字都不寫，也永不參與授權判定——「誰能批」只由 internal/identity 的主體回答；
//   - 欄位白名單：只取審核要用的六格（標識、登入名、顯示名、狀態、提交時刻、決定時刻）。
//     password_hash 與 login_name_key 在語句裡根本不出現，must_change_password、last_login_at
//     與 account_type 也不在：它們對「要不要放行這個人」不構成依據，把帳戶表的形狀一路帶進
//     回應只要多一個可外流的格子；
//   - 排除條件（不持有 server_admin 授予）回答的是「誰在這本名冊裡」，不是「誰有權做這件事」。
//     逐筆的範圍核實另見 decide.go 的 readApplication，它經帳戶實體讀法與授予公開讀法，
//     不反過來拿這段 SQL 回答授權。
package acctreview

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 名冊參數的結論錯誤：各自點出一個查詢參數，傳輸層據此回 1004 與 invalid_field。
// 它們與資料庫故障分開——「page=abc」是請求本體的問題，不是服務端的問題。
var (
	// ErrInvalidPage 表示頁碼不合界線（小於 1）。
	ErrInvalidPage = errors.New("acctreview: 頁碼不合法")
	// ErrInvalidPageSize 表示每頁筆數不合界線（小於 1 或超過上限）。
	ErrInvalidPageSize = errors.New("acctreview: 每頁筆數不合法")
	// ErrInvalidStatusFilter 表示狀態篩選值不在本名冊批准的集合內。
	// 「active」也在這個拒絕裡：被批准的人不屬於這本書，那是普通帳戶名冊的一頁。
	ErrInvalidStatusFilter = errors.New("acctreview: 狀態篩選值不合法")
	// ErrInvalidKeyword 表示名稱關鍵字為空白或超出長度上限。
	ErrInvalidKeyword = errors.New("acctreview: 名稱關鍵字不合法")
)

// 分頁界線由本套件定死：上限存在是「回應體大小不由資料量決定」的既有取向
// （與其餘兩本名冊同一理由），默認值則是名冊第一頁的常規尺寸。
const (
	// RosterDefaultPageSize 是未帶 page_size 參數時每頁的筆數。
	RosterDefaultPageSize = 20
	// RosterMaxPageSize 是 page_size 可取的上限。
	RosterMaxPageSize = 100
	// RosterFilterAll 是「不篩選」的參數值。
	RosterFilterAll = "all"
	// RosterKeywordMaxRunes 是名稱關鍵字的長度上限（碼位計）：它取自帳戶域兩欄各自的上界
	// （登入名與顯示名都不超過 64），更長的輸入不可能是任何一欄的子字串。
	RosterKeywordMaxRunes = 64
)

// RosterQuery 是名冊的一次查詢意圖。傳輸層負責「參數缺席時填默認值」
// （默認常數取自本套件，值只有一份），本層對送進來的每個值嚴格校驗——
// 「page_size 沒帶」與「page_size 帶了 0」是兩句話，不能都當成「沒帶」。
type RosterQuery struct {
	// Page 為頁碼，1 起算。
	Page int64
	// PageSize 為每頁筆數；1..RosterMaxPageSize。
	PageSize int64
	// StatusFilter 為狀態篩選：RosterFilterAll、pending 或 rejected。
	// 「不篩選」列出這本書的兩態；已批准的人由 WHERE 恆排除，
	// 與篩選值是兩件事（不是「沒翻到」，是「不在這本名冊的語意裡」）。
	StatusFilter string
	// Keyword 為名稱關鍵字（比對登入名或顯示名）；去首尾空白後為空即不篩選。
	// 它隻影響哪些行出現，不影響任何一行的欄位內容，而且只在通過授權之後才起作用——
	// 這不是一格匿名可打的搜尋框（匿名那一側是 internal/selfregister 的按憑據查本人）。
	Keyword string
}

// Application 是一筆申請在審核這側的可展示資料（名冊的一行，也是決定之後的回顯形態）。
//
// 不含也不可能有：憑據雜湊、登入名的內部正規化鍵、會話材料、角色與授予、活動與資產。
// 「審核一個人需要知道什麼」在這裡就是那六格：他是誰（標識與兩個名字）、他在審批鏈的哪一站
// （status）、他等了多久（submitted_at）與有沒有結論（reviewed_at）。
// Status 是原字串而不是枚舉：與其餘名冊同一口徑，表外值如實到介面再由界面原樣顯示，
// 寫路徑與單筆核實仍經 internal/account 的實體讀法，校驗鏈只有一份。
type Application struct {
	// AccountID 為帳戶穩定標識的字串形式（展示與按標識下決定都用它，不必再由投影解析成 UUID）。
	AccountID string
	// LoginName 為登入名原始寫法。
	LoginName string
	// DisplayName 為顯示名稱。
	DisplayName string
	// Status 為帳戶狀態原字串（pending|rejected，決定後回顯時可能是 active 或 rejected）。
	Status string
	// SubmittedAt 為申請提交時刻（即帳戶建立時刻）。
	SubmittedAt time.Time
	// ReviewedAt 為審核做出決定的時刻；零值代表還沒有人做過決定（介面據此決定按鈕在不在）。
	ReviewedAt time.Time
}

// RosterPage 是一頁名冊與其總數。
type RosterPage struct {
	// Rows 為當前頁的行；空頁是空切片而不是 nil（JSON 回應因此恆為數組）。
	Rows []Application
	// Page 與 PageSize 是本頁的實際分頁參數（回顯給呼叫端，不讓人自己算偏移）。
	Page     int64
	PageSize int64
	// Total 為符合篩選條件的總筆數（與分頁無關，供頁數計算）。
	Total int64
}

// Roster 以持有伺服器級管理權的主體分頁列舉註冊申請名冊，依提交時刻倒序。
//
// 順序：授權先於一切（與建號、目錄、停用同一道 NeedServerAdmin 閘，非管理員到這裡就結束、
// 不消耗一次資料庫讀取）→ 參數校驗 → 總數 → 本頁行。
// 「頁碼越界」不是錯誤：一個超出總數的合法頁碼回空行與真實總數，
// 這正是併發下別人那份申請被決定掉之後最後一頁被翻空的正常樣態；只有非法參數才回結論錯誤。
//
// 名冊不問帳戶建立策略：用戶批准的語意是「模式只管新提交，歷史申請原地保留」。
// Root 把模式改回 closed 或 open，都不該讓審核者看不見此刻還掛在中間的申請，
// 否則「關掉門」會連帶變成「替所有等待中的人做了一個拒絕的決定」。
func (s *Service) Roster(ctx context.Context, principal identity.Principal,
	q RosterQuery) (RosterPage, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		return RosterPage{}, err
	}
	if q.Page < 1 {
		return RosterPage{}, fmt.Errorf("%w：page=%d（必須大於等於 1）", ErrInvalidPage, q.Page)
	}
	if q.PageSize < 1 || q.PageSize > RosterMaxPageSize {
		return RosterPage{}, fmt.Errorf("%w：page_size=%d（必須在 1..%d）",
			ErrInvalidPageSize, q.PageSize, RosterMaxPageSize)
	}

	// 範圍由兩個條件決定，兩者都是「誰在這本書裡」而不是「誰有權做這件事」：
	//   - 狀態落在審批鏈的兩個取值（pending 等決定、rejected 已決定為拒絕）。
	//     用狀態而不是「有沒有審核時刻」篩選，是因為後者會把「曾被批准此後被停用」的人
	//     也一起列進來——那個人已經屬於普通帳戶名冊，不屬於這本書；
	//   - 不持有伺服器級授予。今日沒有任何通路能把授予寫到一筆申請人身上，
	//     這條是把那個形態在讀取側也釘住：萬一有繞過應用層的直寫，名冊也不把他列出來，
	//     而 decide.go 的逐筆核實會用同一句話把他擋在寫入之外（兩處同一條範圍規則，不是兩套）。
	where := []string{"a.status IN (?, ?)", "NOT EXISTS (SELECT 1 FROM account_server_roles r" +
		" WHERE r.account_id = a.id AND r.role = ?)"}
	args := []any{account.StatusPending.String(), account.StatusRejected.String(),
		identity.RoleServerAdmin.String()}

	switch q.StatusFilter {
	case "", RosterFilterAll:
		// 不篩選：不加狀態條件。注意這不等於「全部狀態」——已批准的人已由 WHERE 恆排除。
	case account.StatusPending.String(), account.StatusRejected.String():
		where = append(where, "a.status = ?")
		args = append(args, q.StatusFilter)
	default:
		return RosterPage{}, fmt.Errorf("%w：%q（僅接受 all|pending|rejected）",
			ErrInvalidStatusFilter, q.StatusFilter)
	}

	if keyword, err := normalizeKeyword(q.Keyword); err != nil {
		return RosterPage{}, err
	} else if keyword != "" {
		// 關鍵字以 LIKE 的子字串比對兩欄；ESCAPE 把 %、_ 與反斜線本身還原成字面字元，
		// 否則「100%」這種輸入會比對出整本名冊，而那已經不是篩選而是把名單交出去。
		like := "%" + escapeLikeWildcard(keyword) + "%"
		where = append(where, `(a.login_name LIKE ? ESCAPE '\' OR a.display_name LIKE ? ESCAPE '\')`)
		args = append(args, like, like)
	}

	whereSQL := strings.Join(where, " AND ")

	var total int64
	countQuery := "SELECT COUNT(*) FROM accounts a WHERE " + whereSQL
	if err := s.db.SQL().QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return RosterPage{}, fmt.Errorf("acctreview: 統計註冊申請名冊失敗: %w", err)
	}

	// 偏移的算術溢出保不住時等價於「翻不到的頁」：回空行與真實總數，不發查詢。
	// 這不是容錯，是不把 int64 邊界之外的輸入當成正當查詢送進資料庫。
	if q.Page-1 > (math.MaxInt64)/q.PageSize {
		return RosterPage{Rows: []Application{}, Page: q.Page, PageSize: q.PageSize, Total: total}, nil
	}
	offset := (q.Page - 1) * q.PageSize

	// 欄位白名單見套件頭注；新增欄位必須先回答「審核真的需要它嗎」，
	// 而不是把 accounts 的形狀一路帶進回應。
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT a.id, a.login_name, a.display_name,
			a.status, a.created_at, a.reviewed_at
		FROM accounts a
		WHERE `+whereSQL+`
		ORDER BY a.created_at DESC, a.id DESC
		LIMIT ? OFFSET ?`, append(args, q.PageSize, offset)...)
	if err != nil {
		return RosterPage{}, fmt.Errorf("acctreview: 讀取註冊申請名冊失敗: %w", err)
	}
	defer rows.Close()

	// 預留容量取本頁可能出現的行數，絕不按 total 分配（total 可以遠大於上限）。
	capacity := int64(0)
	if offset < total {
		capacity = min(total-offset, q.PageSize)
	}
	items := make([]Application, 0, capacity)
	for rows.Next() {
		var (
			app        Application
			idText     string
			statusText string
			createdAt  int64
			reviewedAt sql.NullInt64
		)
		if err := rows.Scan(&idText, &app.LoginName, &app.DisplayName,
			&statusText, &createdAt, &reviewedAt); err != nil {
			return RosterPage{}, fmt.Errorf("acctreview: 讀取註冊申請名冊列失敗: %w", err)
		}
		app.AccountID = idText
		app.Status = statusText
		app.SubmittedAt = timeutil.FromMillis(createdAt)
		if reviewedAt.Valid {
			app.ReviewedAt = timeutil.FromMillis(reviewedAt.Int64)
		}
		items = append(items, app)
	}
	if err := rows.Err(); err != nil {
		return RosterPage{}, fmt.Errorf("acctreview: 讀取註冊申請名冊失敗: %w", err)
	}
	return RosterPage{Rows: items, Page: q.Page, PageSize: q.PageSize, Total: total}, nil
}

// normalizeKeyword 整理名稱關鍵字：去首尾空白、檢查長度上限。
//
// 「整串都是空白」等價於「沒帶關鍵字」（回空字串給呼叫端判），而不是拿一個空 pattern
// 去 LIKE '%%' 把整本名冊列出來——那兩者對使用者的說法應該一樣，實現上也必須一樣。
// 長度上限的意義不是防呆：更長的輸入不可能是任何一欄的子字串（兩欄各自不超過 64 碼位），
// 放它過去只會得到一次必然為空的查詢，還多一個「關鍵字可以無限長」的誤讀。
func normalizeKeyword(raw string) (string, error) {
	keyword := strings.TrimSpace(raw)
	if keyword == "" {
		return "", nil
	}
	if utf8.RuneCountInString(keyword) > RosterKeywordMaxRunes {
		return "", fmt.Errorf("%w：長度 %d（上限 %d 個字元）",
			ErrInvalidKeyword, utf8.RuneCountInString(keyword), RosterKeywordMaxRunes)
	}
	return keyword, nil
}

// escapeLikeWildcard 把 LIKE 的中間萬用字元與轉義字元本身還原成字面字元。
//
// 三個字元一起擋是有原因的：% 與 _ 是 SQLite LIKE 的通配，反斜線是本查詢選定的
// ESCAPE 字元；漏掉任何一個，使用者輸入的「100%」或「a_b」就不再是他打進去的那個字。
// 擋完之後的 pattern 由呼叫端兩側加 %，比對語意是「含這段文字」而不是「以它開頭」。
func escapeLikeWildcard(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		switch r {
		case '\\', '%', '_':
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
