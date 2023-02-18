// roster.go 是「服務器級註冊邀請碼名冊」的查詢側：分頁、狀態篩選與標籤關鍵字比對，
// 一次把符合條件的碼連同總數給齊。
//
// 這一本名冊回答的是「這臺服務器簽發過哪些邀請碼、它們此刻各在什麼狀態」，而不回答
// 「某一枚碼的明文是什麼」——後者今天根本讀不回來（庫裡只存驗證材料），名冊因此也就無從洩露。
//
// 狀態是讀用時派生的，可篩選也按派生的同一優先序在 SQL 裡落條件：
//   - revoked（撤銷時刻已落）
//   - expired（未撤銷、給了到期時刻且已到期）
//   - exhausted（未撤銷、未過期、已用次數打滿額度）
//   - active（以上都不成立——此刻仍可核銷）
//
// 這裡的 WHERE 條件與 code.go 的 deriveStatus 必須同序同判：一處改另一處要跟著改，否則界面篩出來
// 的行會和它自己那格顯示的狀態打架。測試 TestRosterFilterMatchesDerivedStatus 把兩者對齊釘住。
//
// 只讀展示投影的三條邊界逐字沿用其餘名冊（本套件是「只讀展示投影例外」的又一個同形使用者）：
//   - 只讀：一個都不寫，也永不參與授權判定——「誰能簽發／撤銷」只由 internal/identity 的主體回答；
//   - 欄位白名單：只取管理需要的六格（標識、標籤、狀態、額度與已用、創建時刻、到期時刻）。
//     code_hash 在 SELECT 里根本不出現在名冊投影上（見 Row 的換形點），must_change／賬戶欄位一概無關；
//   - 排除條件按狀態派生，回答的是「哪些行落在這一頁」，不是「誰有權限看」。
package invitecode

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// 名冊參數的結論錯誤：各自點出一個查詢參數，傳輸層據此回 1004 與 invalid_field。
var (
	// ErrInvalidPage 表示頁碼不合界線（小於 1）。
	ErrInvalidPage = errors.New("invitecode: 頁碼不合法")
	// ErrInvalidPageSize 表示每頁筆數不合界線（小於 1 或超過上限）。
	ErrInvalidPageSize = errors.New("invitecode: 每頁筆數不合法")
	// ErrInvalidStatusFilter 表示狀態篩選值不在本名冊批准的集合內。
	ErrInvalidStatusFilter = errors.New("invitecode: 狀態篩選值不合法")
	// ErrInvalidKeyword 表示標籤關鍵字為空白剔除後超長。
	ErrInvalidKeyword = errors.New("invitecode: 標籤關鍵字不合法")
)

// 分頁界線由本套件定死：上限存在是「回應體大小不由數據量決定」的既有取向（與其餘名冊同一理由），
// 默認值則是名冊第一頁的常規尺寸。
const (
	// RosterDefaultPageSize 是未帶 page_size 參數時每頁的筆數。
	RosterDefaultPageSize = 20
	// RosterMaxPageSize 是 page_size 可取的上限。
	RosterMaxPageSize = 100
	// RosterFilterAll 是「不篩選」的參數值。
	RosterFilterAll = "all"
	// RosterKeywordMaxRunes 是標籤關鍵字的長度上限（碼位計）：它取自標籤自身的上界（64），
	// 更長的輸入不可能是任何一行標籤的子字串。
	RosterKeywordMaxRunes = 64
)

// RosterQuery 是名冊的一次查詢意圖。傳輸層負責「參數缺席時填默認值」（默認常數取自本套件，值只有一份），
// 本層對送進來的每個值嚴格校驗——「page_size 沒帶」與「page_size 帶了 0」是兩句話，不能都當成「沒帶」。
type RosterQuery struct {
	// Page 為頁碼，1 起算。
	Page int64
	// PageSize 為每頁筆數；1..RosterMaxPageSize。
	PageSize int64
	// StatusFilter 為狀態篩選：RosterFilterAll 或 active|expired|exhausted|revoked 之一。
	// 「不篩選」列出全部四態；空串等同於 all。
	StatusFilter string
	// Keyword 為標籤關鍵字（比對標籤）；去首尾空白後為空即不篩選。
	Keyword string
}

// Row 是一枚碼在名冊上的一行（可展示資料，也是撤銷之後的回顯形態）。
//
// 不含也不可能含：明文碼、驗證材料哈希、任何賬戶資料、任何會話材料、任何角色。
// 「管理一枚碼需要知道什麼」在這裡就是這幾格：它是誰（標識與標籤）、它此刻算什麼狀態、
// 額度用了多少（used/total 與派生的 remaining）、它何時籤的、何時過期（缺席即永不過期）。
// Status 是派生出來的字符串（active|expired|exhausted|revoked），不是庫欄位。
type Row struct {
	CodeID    string
	Label     string
	Status    Status
	MaxUses   int64
	UsedCount int64
	Remaining int64
	CreatedAt time.Time
	// ExpiresAt 為零值代表永不過期（界面據這一格缺席講「沒有到期這回事」）。
	ExpiresAt time.Time
	// RevokedAt 為零值代表尚未被撤銷；非零即「被撤銷於何時」這個事實（派生出 revoked 狀態的依據）。
	RevokedAt time.Time
}

// RosterPage 是一頁名冊與其總數。
type RosterPage struct {
	// Rows 為當前頁的行；空頁是空切片而不是 nil（JSON 回應因此恆為數組）。
	Rows []Row
	// Page 與 PageSize 是本頁的實際分頁參數（回顯給呼叫端，不讓人自己算偏移）。
	Page     int64
	PageSize int64
	// Total 為符合篩選條件的總筆數（與分頁無關，供頁數計算）。
	Total int64
}

// Roster 以 Root 主體分頁列舉邀請碼名冊，依簽發時刻倒序。
//
// 順序：授權先於一切（與簽發、撤銷同一道 NeedRoot 閘，非 Root 到這裡就結束、不消耗一次數據庫讀取）
// → 參數校驗 → 總數 → 本頁行。「頁碼越界」不是錯誤：一個超出總數的合法頁碼回空行與真實總數，
// 這正是一枚碼被別人撤銷後最後一頁被翻空的正常樣態；只有非法參數才回結論錯誤。
func (s *Service) Roster(ctx context.Context, principal identity.Principal,
	q RosterQuery) (RosterPage, error) {
	if err := s.requireRoot(principal, "roster"); err != nil {
		return RosterPage{}, err
	}
	if q.Page < 1 {
		return RosterPage{}, fmt.Errorf("%w：page=%d（必須大於等於 1）", ErrInvalidPage, q.Page)
	}
	if q.PageSize < 1 || q.PageSize > RosterMaxPageSize {
		return RosterPage{}, fmt.Errorf("%w：page_size=%d（必須在 1..%d）",
			ErrInvalidPageSize, q.PageSize, RosterMaxPageSize)
	}

	// 此刻由注入時鐘給：名冊的狀態派生與「過期」判定都問的是同一個「現在」，
	// 不從牆鍾偷讀，也不從請求內容採信。
	now := s.clock.Now()

	where := []string{"1 = 1"}
	args := []any{}
	switch q.StatusFilter {
	case "", RosterFilterAll:
		// 不篩選：不加狀態條件（四種狀態都可能出現）。
	case StatusRevoked.String():
		where = append(where, "revoked_at <> 0")
	case StatusExpired.String():
		where = append(where, "revoked_at = 0 AND expires_at <> 0 AND expires_at <= ?")
		args = append(args, timeutil.ToMillis(now))
	case StatusExhausted.String():
		where = append(where, "revoked_at = 0 AND (expires_at = 0 OR expires_at > ?) AND used_count >= max_uses")
		args = append(args, timeutil.ToMillis(now))
	case StatusActive.String():
		where = append(where, "revoked_at = 0 AND (expires_at = 0 OR expires_at > ?) AND used_count < max_uses")
		args = append(args, timeutil.ToMillis(now))
	default:
		return RosterPage{}, fmt.Errorf("%w：%q（僅接受 all|active|expired|exhausted|revoked）",
			ErrInvalidStatusFilter, q.StatusFilter)
	}

	if keyword, err := normalizeKeyword(q.Keyword); err != nil {
		return RosterPage{}, err
	} else if keyword != "" {
		like := "%" + escapeLikeWildcard(keyword) + "%"
		where = append(where, `label LIKE ? ESCAPE '\'`)
		args = append(args, like)
	}
	whereSQL := strings.Join(where, " AND ")

	var total int64
	countQuery := "SELECT COUNT(*) FROM registration_invite_codes WHERE " + whereSQL
	if err := s.db.SQL().QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return RosterPage{}, fmt.Errorf("invitecode: 統計邀請碼名冊失敗: %w", err)
	}

	// 偏移的算術溢出保不住時等價於「翻不到的頁」：回空行與真實總數，不發查詢。
	if q.Page-1 > (math.MaxInt64)/q.PageSize {
		return RosterPage{Rows: []Row{}, Page: q.Page, PageSize: q.PageSize, Total: total}, nil
	}
	offset := (q.Page - 1) * q.PageSize

	// 名冊投影不取 code_hash：驗證材料對「這枚碼是什麼狀態」不構成依據，多讀一格就多一個可外流的字段。
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT id, label, max_uses, used_count,
			created_at, expires_at, revoked_at
		FROM registration_invite_codes
		WHERE `+whereSQL+`
		ORDER BY created_at DESC, id DESC
		LIMIT ? OFFSET ?`, append(args, q.PageSize, offset)...)
	if err != nil {
		return RosterPage{}, fmt.Errorf("invitecode: 讀取邀請碼名冊失敗: %w", err)
	}
	defer rows.Close()

	capacity := int64(0)
	if offset < total {
		capacity = min(total-offset, q.PageSize)
	}
	items := make([]Row, 0, capacity)
	for rows.Next() {
		var (
			codeID, label string
			maxUses, used int64
			createdAt     int64
			expiresAt     int64
			revokedAt     int64
		)
		if err := rows.Scan(&codeID, &label, &maxUses, &used, &createdAt, &expiresAt, &revokedAt); err != nil {
			return RosterPage{}, fmt.Errorf("invitecode: 讀取邀請碼名冊行失敗: %w", err)
		}
		items = append(items, rowOf(codeID, label, maxUses, used,
			timeutil.FromMillis(createdAt), expiresAt, revokedAt, now))
	}
	if err := rows.Err(); err != nil {
		return RosterPage{}, fmt.Errorf("invitecode: 讀取邀請碼名冊失敗: %w", err)
	}
	return RosterPage{Rows: items, Page: q.Page, PageSize: q.PageSize, Total: total}, nil
}

// rowOf 把名冊一行的原始欄位換成可展示的 Row，並按注入時鐘派生狀態。
//
// 派生走實體同一條 deriveStatus（先組一個最小的 InviteCode 再派生），不在這裡再記一份優先序：
// 名冊那一格和領域層那句「這枚碼現在算什麼」必須是同一個算法。
func rowOf(codeID, label string, maxUses, used int64, createdAt time.Time,
	expiresMillis, revokedMillis int64, now time.Time) Row {
	code := InviteCode{
		Label:     label,
		MaxUses:   maxUses,
		UsedCount: used,
		CreatedAt: createdAt,
	}
	if expiresMillis > 0 {
		code.ExpiresAt = timeutil.FromMillis(expiresMillis)
	}
	if revokedMillis > 0 {
		code.RevokedAt = timeutil.FromMillis(revokedMillis)
	}
	return Row{
		CodeID:    codeID,
		Label:     label,
		Status:    code.deriveStatus(now),
		MaxUses:   maxUses,
		UsedCount: used,
		Remaining: code.remaining(),
		CreatedAt: createdAt,
		ExpiresAt: code.ExpiresAt,
		RevokedAt: code.RevokedAt,
	}
}

// normalizeKeyword 整理標籤關鍵字：去首尾空白、檢查長度上限。
//
// 「整串都是空白」等價於「沒帶關鍵字」（回空串給呼叫端判），而不是拿一個空 pattern 去 LIKE '%%'
// 把整本名冊列出來。長度上限的意義不是防呆：更長的輸入不可能是任何一行標籤的子串（標籤不超 64 碼位）。
func normalizeKeyword(raw string) (string, error) {
	keyword := strings.TrimSpace(raw)
	if keyword == "" {
		return "", nil
	}
	if utf8.RuneCountInString(keyword) > RosterKeywordMaxRunes {
		return "", fmt.Errorf("%w：長度 %d（上限 %d 個字符）",
			ErrInvalidKeyword, utf8.RuneCountInString(keyword), RosterKeywordMaxRunes)
	}
	return keyword, nil
}

// escapeLikeWildcard 把 LIKE 的通配與轉義字元本身還原成字面字元（與 internal/acctreview 同實現）。
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
