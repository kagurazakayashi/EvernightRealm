// directory.go 是「管理員的普通帳戶目錄」的查詢側：分頁、名稱／類型／狀態篩選與總數一次給齊。
//
// 這裡出現本套件唯一一處跨表 SQL。這是用戶批准把 R2-002「只讀展示投影例外」首次擴展到
// 第二個套件的落點，三條邊界與 internal/adminacct/directory.go 逐字同形：
//   - 這是只讀的呈現投影（read model）：不寫任何表，也永不參與任何授權判定——
//     「誰能做什麼」仍然只由 internal/identity 的主體與 internal/grant 的讀取路徑回答；
//   - 欄位是白名單投影而非 SELECT *：登入名、顯示名、來源類型、狀態、首次改密旗標與
//     三個時刻。password_hash、login_name_key 在語句裡根本不出現，
//     「目錄回應裡沒有一個格子可能含憑據」因此成立在 SQL 形狀上而不是自律上；
//   - 排除條件（不持有 server_admin 授予、未進入刪除終態）回答的是「誰在這本目錄裡」，
//     不是「誰有權做這件事」。單筆詳情與編輯不共用這段 SQL：它們經 internal/account
//     的實體讀法取真相、經 internal/grant 的公開讀法核授予，見 profile.go。
//
// 為什麼要在目錄裡排除管理員與 Root：普通帳戶目錄是「管理員打理他所服務的成員名冊」，
// 而不是伺服器級主體名冊。持有 server_admin 的帳戶（包括敲這條端點的管理員自己）
// 由 Root 的管理員目錄負責；配置 Root 根本不在 accounts 表裡，結構上不可能成為一行。
// 「甲管理員能不能改乙管理員的顯示名」在這本目錄沒有一格可答——那是 NeedRoot 的事。
//
// 為什麼連刪除終態一起排掉：本步沒有任何一條已實作的通路能把普通帳戶寫成 deleted
// （Root 的刪除通路要求目錄成員資格，也就是授予行），因此這一行今日只可能來自繞過應用層的
// 直寫。把它排除讓「標識不合法／查無此人／不在本目錄」收斂成同一句 1001 是一句誠實的話，
// 而不是把一個不可達狀態偽裝成需要新錯誤碼的能力。若將來開放普通帳戶刪除，
// 那一步要同時決定「列不列」與「用哪一句話拒絕寫入」，本套件不替它預留格子。
package stdacct

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

// 目錄參數的結論錯誤：各自點出一個查詢參數，傳輸層據此回 1004 與 invalid_field。
// 它們與資料庫故障分開——「page=abc」是請求本體的問題，不是服務端的問題。
var (
	// ErrInvalidPage 表示頁碼不合界線（小於 1）。
	ErrInvalidPage = errors.New("stdacct: 頁碼不合法")
	// ErrInvalidPageSize 表示每頁筆數不合界線（小於 1 或超過上限）。
	ErrInvalidPageSize = errors.New("stdacct: 每頁筆數不合法")
	// ErrInvalidStatusFilter 表示狀態篩選值不在本目錄批准的集合內。
	// 「deleted」也在這個拒絕裡：刪除終態不屬於本目錄（見套件頭注）。
	ErrInvalidStatusFilter = errors.New("stdacct: 狀態篩選值不合法")
	// ErrInvalidTypeFilter 表示來源類型篩選值不在帳戶域的封閉集合內。
	ErrInvalidTypeFilter = errors.New("stdacct: 類型篩選值不合法")
	// ErrInvalidKeyword 表示名稱關鍵字為空白或超出長度上限。
	ErrInvalidKeyword = errors.New("stdacct: 名稱關鍵字不合法")
)

// 分頁界線由本套件定死：上限存在是「回應體大小不由資料量決定」的既有取向
// （與 internal/adminacct 目錄同一理由），默認值則是目錄第一頁的常規尺寸。
const (
	// DirectoryDefaultPageSize 是未帶 page_size 參數時每頁的筆數。
	DirectoryDefaultPageSize = 20
	// DirectoryMaxPageSize 是 page_size 可取的上限。
	DirectoryMaxPageSize = 100
	// DirectoryFilterAll 是「不篩選」的參數值（狀態與類型兩個篩選共用同一個詞）。
	DirectoryFilterAll = "all"
	// DirectoryKeywordMaxRunes 是名稱关键字的長度上限（碼位計）：它取自帳戶域
	// 兩欄各自的上界（登入名與顯示名都不超過 64），更長的輸入不可能是任何一欄的子字串。
	DirectoryKeywordMaxRunes = 64
)

// DirectoryQuery 是目錄的一次查詢意圖。傳輸層負責「參數缺席時填默認值」
// （默認常數取自本套件，值只有一份），本層對送進來的每個值嚴格校驗——
// 「page_size 沒帶」與「page_size 帶了 0」是兩句話，不能都當成「沒帶」。
type DirectoryQuery struct {
	// Page 為頁碼，1 起算。
	Page int64
	// PageSize 為每頁筆數；1..DirectoryMaxPageSize。
	PageSize int64
	// StatusFilter 為狀態篩選：DirectoryFilterAll、active 或 disabled。
	// 「不篩選」列出本目錄內的兩種可登入狀態；刪除終態由 WHERE 恆排除，
	// 與篩選值是兩件事（不是「沒翻到」，是「不在這本目錄的語意裡」）。
	StatusFilter string
	// TypeFilter 為來源篩選：DirectoryFilterAll、standard 或 guest。
	// 取值經 internal/account 的封閉集合復核，不在此另寫一份字面值清單。
	TypeFilter string
	// Keyword 為名稱關鍵字（比對登入名或顯示名）；去首尾空白後為空即不篩選。
	// 它只影響哪些行出現，不影響任何一行的欄位內容。
	Keyword string
}

// DirectoryRow 是目錄的一行展示資料（欄位語意見套件頭注的白名單約定）。
//
// 與管理員目錄的差一欄是刻意的：這裡沒有 granted_at（普通帳戶沒有授予可言），
// 多的一欄是 account_type——「他是普通帳戶還是訪戶帳戶」是本目錄必須講清楚的來源事實。
type DirectoryRow struct {
	// AccountID 為帳戶標識的字串形式（展示用，不必再由投影解析成 UUID）。
	AccountID string
	// LoginName 為登入名原始寫法。
	LoginName string
	// DisplayName 為顯示名稱。
	DisplayName string
	// AccountType 為來源類型原字串（standard|guest）。
	AccountType string
	// Status 為帳戶狀態原字串。
	Status string
	// MustChangePassword 為是否仍欠首次改密。
	MustChangePassword bool
	// CreatedAt 為帳戶建立時刻。
	CreatedAt time.Time
	// LastLoginAt 為最近一次登入時刻；零值代表從未登入。
	LastLoginAt time.Time
}

// DirectoryPage 是一頁目錄與其總數。
type DirectoryPage struct {
	// Rows 為當前頁的行；空頁是空切片而不是 nil（JSON 回應因此恆為數組）。
	Rows []DirectoryRow
	// Page 與 PageSize 是本頁的實際分頁參數（回顯給呼叫端，不讓人自己算偏移）。
	Page     int64
	PageSize int64
	// Total 為符合篩選條件的總筆數（與分頁無關，供頁數計算）。
	Total int64
}

// Directory 以管理員主體分頁列舉普通帳戶目錄，依建立時刻倒序。
//
// 順序：授權先於一切（與建號同一道 NeedServerAdmin 閘）→ 參數校驗 → 總數 → 本頁行。
// 「頁碼越界」不是錯誤：一個超出總數的合法頁碼回空行與真實總數，
// 這正是併發下別人最後一頁被翻空的正常樣態；只有非法參數才回結論錯誤。
//
// 排序取 accounts 既有索引的順序（created_at DESC, id DESC）：與全倉庫
// 「最新在前＋標識破平」的套路一致，也讓總數與本頁行出自同一條 WHERE。
func (s *Service) Directory(ctx context.Context, principal identity.Principal,
	q DirectoryQuery) (DirectoryPage, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		return DirectoryPage{}, err
	}
	if q.Page < 1 {
		return DirectoryPage{}, fmt.Errorf("%w：page=%d（必須大於等於 1）", ErrInvalidPage, q.Page)
	}
	if q.PageSize < 1 || q.PageSize > DirectoryMaxPageSize {
		return DirectoryPage{}, fmt.Errorf("%w：page_size=%d（必須在 1..%d）",
			ErrInvalidPageSize, q.PageSize, DirectoryMaxPageSize)
	}

	where := []string{"a.status <> ?", "NOT EXISTS (SELECT 1 FROM account_server_roles r" +
		" WHERE r.account_id = a.id AND r.role = ?)"}
	args := []any{account.StatusDeleted.String(), identity.RoleServerAdmin.String()}

	switch q.StatusFilter {
	case "", DirectoryFilterAll:
		// 不篩選：不加狀態條件。注意這不等於「全部狀態」——刪除終態已由 WHERE 恆排除。
	case account.StatusActive.String(), account.StatusDisabled.String():
		where = append(where, "a.status = ?")
		args = append(args, q.StatusFilter)
	default:
		return DirectoryPage{}, fmt.Errorf("%w：%q（僅接受 all|active|disabled）",
			ErrInvalidStatusFilter, q.StatusFilter)
	}

	switch q.TypeFilter {
	case "", DirectoryFilterAll:
		// 不篩選來源：普通與訪戶帳戶都列出來，來源欄位本身講清楚他是哪一類。
	case account.TypeStandard.String(), account.TypeGuest.String():
		where = append(where, "a.account_type = ?")
		args = append(args, q.TypeFilter)
	default:
		return DirectoryPage{}, fmt.Errorf("%w：%q（僅接受 all|standard|guest）",
			ErrInvalidTypeFilter, q.TypeFilter)
	}

	if keyword, err := normalizeKeyword(q.Keyword); err != nil {
		return DirectoryPage{}, err
	} else if keyword != "" {
		// 關鍵字以 LIKE 的子字串比對兩欄；ESCAPE 把 %、_ 與反斜線本身還原成字面字元，
		// 否則「100%」這種輸入會比對出整個目錄，而那已經不是篩選而是把全表交出去。
		like := "%" + escapeLikeWildcard(keyword) + "%"
		where = append(where, `(a.login_name LIKE ? ESCAPE '\' OR a.display_name LIKE ? ESCAPE '\')`)
		args = append(args, like, like)
	}

	whereSQL := strings.Join(where, " AND ")

	var total int64
	countQuery := "SELECT COUNT(*) FROM accounts a WHERE " + whereSQL
	if err := s.db.SQL().QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return DirectoryPage{}, fmt.Errorf("stdacct: 統計普通帳戶目錄失敗: %w", err)
	}

	// 偏移的算術溢出保不住時等價於「翻不到的頁」：回空行與真實總數，不發查詢。
	// 這不是容錯，是不把 int64 邊界之外的輸入當成正當查詢送進資料庫。
	if q.Page-1 > (math.MaxInt64)/q.PageSize {
		return DirectoryPage{Rows: []DirectoryRow{}, Page: q.Page, PageSize: q.PageSize, Total: total}, nil
	}
	offset := (q.Page - 1) * q.PageSize

	// 欄位白名單見套件頭注；新增欄位必須先回答「目錄真的需要它嗎」，
	// 而不是把 accounts 的形狀一路帶進回應。
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT a.id, a.login_name, a.display_name,
			a.account_type, a.status, a.must_change_password, a.created_at, a.last_login_at
		FROM accounts a
		WHERE `+whereSQL+`
		ORDER BY a.created_at DESC, a.id DESC
		LIMIT ? OFFSET ?`, append(args, q.PageSize, offset)...)
	if err != nil {
		return DirectoryPage{}, fmt.Errorf("stdacct: 讀取普通帳戶目錄失敗: %w", err)
	}
	defer rows.Close()

	// 預留容量取本頁可能出現的行數，絕不按 total 分配（total 可以遠大於上限）。
	capacity := int64(0)
	if offset < total {
		capacity = min(total-offset, q.PageSize)
	}
	items := make([]DirectoryRow, 0, capacity)
	for rows.Next() {
		var (
			row                     DirectoryRow
			createdAt               int64
			lastLoginAt             sql.NullInt64
			mustChange              int64
			accountType, statusText string
		)
		if err := rows.Scan(&row.AccountID, &row.LoginName, &row.DisplayName,
			&accountType, &statusText, &mustChange, &createdAt, &lastLoginAt); err != nil {
			return DirectoryPage{}, fmt.Errorf("stdacct: 讀取普通帳戶目錄列失敗: %w", err)
		}
		// 狀態與類型原字串帶出、不經實體校驗：這一層解釋的是「怎麼展示」，不是
		// 「帳戶是否合法」（表外值如實到介面再由前端原樣顯示，與管理員目錄同口徑）；
		// 寫路徑與單筆詳情仍走 internal/account 的實體讀法，校驗鏈只有一份。
		row.AccountType = accountType
		row.Status = statusText
		row.MustChangePassword = mustChange != 0
		row.CreatedAt = timeutil.FromMillis(createdAt)
		if lastLoginAt.Valid {
			row.LastLoginAt = timeutil.FromMillis(lastLoginAt.Int64)
		}
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		return DirectoryPage{}, fmt.Errorf("stdacct: 讀取普通帳戶目錄失敗: %w", err)
	}
	return DirectoryPage{Rows: items, Page: q.Page, PageSize: q.PageSize, Total: total}, nil
}

// normalizeKeyword 整理名稱關鍵字：去首尾空白、檢查長度上限。
//
// 「整串都是空白」等價於「沒帶關鍵字」（回空字串給呼叫端判），而不是拿一個空 pattern
// 去 LIKE '%%' 把所有行列出來——那兩者對使用者的說法應該一樣，實現上也必須一樣。
// 長度上限的意義不是防呆：更長的輸入不可能是任何一欄的子字串（兩欄各自不超過 64 碼位），
// 放它過去只會得到一次必然為空的查詢，還多一個「關鍵字可以無限長」的誤讀。
func normalizeKeyword(raw string) (string, error) {
	keyword := strings.TrimSpace(raw)
	if keyword == "" {
		return "", nil
	}
	if utf8.RuneCountInString(keyword) > DirectoryKeywordMaxRunes {
		return "", fmt.Errorf("%w：長度 %d（上限 %d 個字元）",
			ErrInvalidKeyword, utf8.RuneCountInString(keyword), DirectoryKeywordMaxRunes)
	}
	return keyword, nil
}

// escapeLikeWildcard 把 LIKE 的中間萬用字元與轉義字元本身還原成字面字元。
//
// 三個字元一起擋是有原因的：% 與 _ 是 SQLite LIKE 的通配，反斜線是本查詢選定的
// ESCAPE 字元；漏掉任何一個，使用者輸入的「100%」或「a_b」就不再是他打進去的字。
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
