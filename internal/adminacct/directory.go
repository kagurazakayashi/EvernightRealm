// directory.go 是「Root 管理員目錄」的查詢側：分頁、狀態篩選與總數一次給齊。
//
// 這裡出現本套件唯一一处跨表 SQL，它的邊界必須講清楚（用戶批准於「授予讀寫只經
// internal/grant、兩張表各自只由自己的倉儲解釋」這條既定規定之上的例外，僅限展示）：
//   - 這是只讀的呈現投影（read model）：不寫任何表，也永不參與任何授權判定——
//     誰能做什麼仍然只由 internal/identity 的主體與 internal/grant 的讀取路徑回答；
//   - 欄位是白名單投影而非 SELECT *：登入名、顯示名、狀態、首次改密旗標、
//     三個時刻與授予時刻。password_hash、login_name_key 等欄位在語句裡根本不出現，
//     「目錄回應裡沒有一個格子可能含憑據」因此成立在 SQL 形狀上；
//   - 狀態值原字串帶出、不經實體校驗：投影解釋的是「怎麼展示」，不是「帳戶是否合法」，
//     表外值（資料庫被繞過校驗寫入時）如實到介面再由前端原樣顯示，與角色欄同口徑。
//     寫路徑與單筆詳情仍走 internal/account 的實體讀法，校驗鏈只有一份。
package adminacct

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/account"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 目錄參數的結論錯誤：各自點出一個查詢參數，傳輸層據此回 1004 與 invalid_field。
// 它们與資料庫故障分開——「page=abc」是請求本體的問題，不是服務端的問題。
var (
	// ErrInvalidPage 表示頁碼不合界線（小於 1）。
	ErrInvalidPage = errors.New("adminacct: 頁碼不合法")
	// ErrInvalidPageSize 表示每頁筆數不合界線（小於 1 或超過上限）。
	ErrInvalidPageSize = errors.New("adminacct: 每頁筆數不合法")
	// ErrInvalidStatusFilter 表示狀態篩選值不在批准集合內。
	ErrInvalidStatusFilter = errors.New("adminacct: 狀態篩選值不合法")
)

// 分頁界線由本套件定死：上限存在是「回應體大小不由資料量決定」的既有取向
// （與 internal/grant 對 limit 必為正值同一理由），默認值則是目錄第一頁的常規尺寸。
const (
	// DirectoryDefaultPageSize 是未帶 page_size 參數时每頁的筆數。
	DirectoryDefaultPageSize = 20
	// DirectoryMaxPageSize 是 page_size 可取的上限。
	DirectoryMaxPageSize = 100
	// DirectoryStatusAll 是「不篩選」的參數值。
	DirectoryStatusAll = "all"
)

// DirectoryQuery 是目錄的一次查詢意圖。傳輸層負責「參數缺席時填默認值」
// （默認常數取自本套件，值只有一份），本層對送進來的每個值嚴格校驗——
// 「page_size 沒帶」與「page_size 帶了 0」是兩句話，不能都當成「沒帶」。
type DirectoryQuery struct {
	// Page 為頁碼，1 起算。
	Page int64
	// PageSize 為每頁筆數；1..DirectoryMaxPageSize。
	PageSize int64
	// StatusFilter 為狀態篩選：DirectoryStatusAll、active 或 disabled。
	StatusFilter string
}

// DirectoryRow 是目錄的一行展示資料（欄位語意見套件頭注的白名單約定）。
type DirectoryRow struct {
	// AccountID 為帳戶標識的字串形式（展示用，不必再由投影解析成 UUID）。
	AccountID string
	// LoginName 為登入名原始寫法。
	LoginName string
	// DisplayName 為顯示名稱。
	DisplayName string
	// Status 為帳戶狀態原字串。
	Status string
	// MustChangePassword 為是否仍欠首次改密。
	MustChangePassword bool
	// CreatedAt 為帳戶建立時刻。
	CreatedAt time.Time
	// LastLoginAt 為最近一次登入時刻；零值代表從未登入。
	LastLoginAt time.Time
	// GrantedAt 為 server_admin 授予寫下的時刻。
	GrantedAt time.Time
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

// Directory 以 Root 主體分頁列舉管理員目錄，依授予時刻倒序。
//
// 順序：授權先於一切（與開設同一道 NeedRoot 閘）→ 參數校驗 → 總數 → 本頁行。
// 「頁碼越界」不是錯誤：一個超出總數的合法頁碼回空行與真實總數，
// 这正是併發下別人最後一頁被翻空的正常樣態；只有非法參數才回結論錯誤。
//
// 明確不在這份目錄裡的東西：配置 Root 主體。目錄的成員資格來自授予表，
// 而 Root 從不落授予表（它是主體類別不是角色）——「把 Root 伪装成一行可編輯的
// 普通帳戶」在這裡沒有存在的通道。
func (s *Service) Directory(ctx context.Context, principal identity.Principal,
	q DirectoryQuery) (DirectoryPage, error) {
	if err := identity.Authorize(principal, identity.NeedRoot); err != nil {
		return DirectoryPage{}, err
	}
	if q.Page < 1 {
		return DirectoryPage{}, fmt.Errorf("%w：page=%d（必須大於等於 1）", ErrInvalidPage, q.Page)
	}
	if q.PageSize < 1 || q.PageSize > DirectoryMaxPageSize {
		return DirectoryPage{}, fmt.Errorf("%w：page_size=%d（必須在 1..%d）",
			ErrInvalidPageSize, q.PageSize, DirectoryMaxPageSize)
	}
	var statusParam string
	switch q.StatusFilter {
	case "", DirectoryStatusAll:
		// 不篩選：不加 WHERE 條件，也不拿空字串去比對 accounts.status。
	case account.StatusActive.String(), account.StatusDisabled.String():
		statusParam = q.StatusFilter
	default:
		return DirectoryPage{}, fmt.Errorf("%w：%q（僅接受 all|active|disabled）",
			ErrInvalidStatusFilter, q.StatusFilter)
	}

	where := "r.role = ?"
	args := []any{identity.RoleServerAdmin.String()}
	if statusParam != "" {
		where += " AND a.status = ?"
		args = append(args, statusParam)
	}

	var total int64
	countQuery := "SELECT COUNT(*) FROM account_server_roles r JOIN accounts a ON a.id = r.account_id WHERE " + where
	if err := s.db.SQL().QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return DirectoryPage{}, fmt.Errorf("adminacct: 統計管理員目錄失敗: %w", err)
	}

	// 偏移的算術溢出保不住時等價於「翻不到的頁」：回空行與真實總數，不發查詢。
	// 這不是容錯，是不把 int64 邊界之外的輸入當成正當查詢送進資料庫。
	if q.Page-1 > (math.MaxInt64)/q.PageSize {
		return DirectoryPage{Rows: []DirectoryRow{}, Page: q.Page, PageSize: q.PageSize, Total: total}, nil
	}
	offset := (q.Page - 1) * q.PageSize

	// 欄位白名單見套件頭注；新增欄位必須先回答「目錄真的需要它嗎」，
	// 而不是把 accounts 的形状一路帶進回應。
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT r.account_id, r.granted_at,
			a.login_name, a.display_name, a.status, a.must_change_password,
			a.created_at, a.last_login_at
		FROM account_server_roles r JOIN accounts a ON a.id = r.account_id
		WHERE `+where+`
		ORDER BY r.granted_at DESC, r.account_id DESC
		LIMIT ? OFFSET ?`, append(args, q.PageSize, offset)...)
	if err != nil {
		return DirectoryPage{}, fmt.Errorf("adminacct: 讀取管理員目錄失敗: %w", err)
	}
	defer rows.Close()

	// 預留容量取本頁可能出現的行數，絕不按 total 分配（total 可以远大于上限）。
	capacity := int64(0)
	if offset < total {
		capacity = min(total-offset, q.PageSize)
	}
	items := make([]DirectoryRow, 0, capacity)
	for rows.Next() {
		var (
			row                  DirectoryRow
			grantedAt, createdAt int64
			lastLoginAt          sql.NullInt64
			mustChange           int64
		)
		if err := rows.Scan(&row.AccountID, &grantedAt, &row.LoginName, &row.DisplayName,
			&row.Status, &mustChange, &createdAt, &lastLoginAt); err != nil {
			return DirectoryPage{}, fmt.Errorf("adminacct: 讀取管理員目錄列失敗: %w", err)
		}
		row.MustChangePassword = mustChange != 0
		row.CreatedAt = timeutil.FromMillis(createdAt)
		row.GrantedAt = timeutil.FromMillis(grantedAt)
		if lastLoginAt.Valid {
			row.LastLoginAt = timeutil.FromMillis(lastLoginAt.Int64)
		}
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		return DirectoryPage{}, fmt.Errorf("adminacct: 讀取管理員目錄失敗: %w", err)
	}
	return DirectoryPage{Rows: items, Page: q.Page, PageSize: q.PageSize, Total: total}, nil
}
