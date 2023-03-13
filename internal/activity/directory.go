// directory.go 是活動目錄與單筆詳情的讀取用例：一個人能看見哪些活動，
// 由指派表回答，而不是由「他是不是管理員」回答。
//
// 這條分界是本步最容易寫錯的地方，因此寫成兩句話固定住：
//   - 伺服器級管理員不等於所有活動的管理員。NeedServerAdmin 只證明他屬於「管理員這個身份面」，
//     某一活動的資料要他看得見，還得有那一行的指派（見 identity.AuthorizeActivityScope）；
//   - 看不見就是不存在。查無與「存在但不屬於你」收斂成同一個 ErrActivityNotFound，
//     於是敲一個活動標識不會多出「這個標識確實是一個活動」這條資訊。
//
// Root 是本句的例外，而且例外寫在身份層而不是這裡的分支裡：它不屬於任何活動，
// 跨活動維運本來就是它的職責（同一取向見 internal/audit 的「Root 兩域可讀」）。
// 因此目錄對 Root 不按標識限制，詳情與各條寫入通路對 Root 一律放行。
package activity

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// 分頁與篩選的界線（與邀請碼名冊、帳戶目錄同一尺度：回應體大小不由資料量決定）。
const (
	// DirectoryDefaultPageSize 是未帶 page_size 時每頁的筆數。
	DirectoryDefaultPageSize = 20
	// DirectoryMaxPageSize 是 page_size 可取的上限。
	DirectoryMaxPageSize = 100
	// FilterAll 是「不篩選」的引數值（空串與 it 同義）。
	FilterAll = "all"
	// DirectoryKeywordMaxRunes 是關鍵字的碼位上限：比名稱上界更長的輸入
	// 不可能是任何一行名稱或描述的子字串。
	DirectoryKeywordMaxRunes = maxDescriptionRunes
)

// DirectoryQuery 是目錄的輸入。頁面與每頁筆數由呼叫端給預設值後交進來，
// 狀態篩選與關鍵字保持「請求送來什麼就是什麼」，正規劃在本檔案做（見 Directory）。
type DirectoryQuery struct {
	// Page 為頁碼，從 1 起。
	Page int64
	// PageSize 為每頁筆數；1..DirectoryMaxPageSize。
	PageSize int64
	// StatusFilter 為狀態篩選：FilterAll 或 draft|active|closed|archived 之一；空串等同 all。
	StatusFilter string
	// Keyword 為名稱與描述的關鍵字；去首尾空白後為空即不篩選。
	Keyword string
}

// DirectoryPage 是一頁活動加上符合條件的總數。
type DirectoryPage struct {
	// Rows 是本頁活動（建立時刻倒序，標識破平）。
	Rows []Activity
	// Page 與 PageSize 回顯實際生效的分頁引數。
	Page     int64
	PageSize int64
	// Total 是符合篩選條件的總筆數（不受分頁影響，也不受可見範圍之外的行影響）。
	Total int64
}

// Directory 以受信主體讀一頁活動目錄。
//
// 「他能看哪些」與「他能管哪些」在這一步是同一次查詢：可見集合直接取自指派表，
// 於是目錄裡出現的每一行都保證詳情與寫入通路也認得它——不會出現
// 「列得出來卻點不進去」或反過來的兩套答案。
//
// 被拒的目錄請求（不屬於管理員這個身份面）不改寫成空清單：那句處置是「換個身分辨不成」，
// 空的目錄會被讀成「這臺伺服器還沒有活動」，兩者差很遠。
func (s *Service) Directory(ctx context.Context, principal identity.Principal,
	query DirectoryQuery) (DirectoryPage, error) {
	if err := identity.Authorize(principal, identity.NeedServerAdmin); err != nil {
		s.log.Warn("活動目錄被拒：主體不具備伺服器級管理權",
			"subject", principal.String(), "entry", "directory")
		return DirectoryPage{}, err
	}

	page := query.Page
	size := query.PageSize
	if page < 1 {
		return DirectoryPage{}, fmt.Errorf("%w：page=%d（必須大於 0；沒帶參數由傳輸層填預設）",
			ErrInvalidPage, page)
	}
	if size < 1 || size > DirectoryMaxPageSize {
		return DirectoryPage{}, fmt.Errorf("%w：page_size=%d（必須在 1..%d）",
			ErrInvalidPageSize, size, DirectoryMaxPageSize)
	}
	statusFilter, err := normalizeStatusFilter(query.StatusFilter)
	if err != nil {
		return DirectoryPage{}, err
	}
	keyword, err := normalizeKeyword(query.Keyword)
	if err != nil {
		return DirectoryPage{}, err
	}

	visible, err := s.visibleActivities(ctx, principal)
	if err != nil {
		return DirectoryPage{}, err
	}

	stored, err := s.store.List(ctx, s.db.SQL(), ListQuery{
		Visible:      visible,
		StatusFilter: statusFilter,
		Keyword:      keyword,
		Page:         page,
		PageSize:     size,
	})
	if err != nil {
		s.log.Error("讀取活動目錄失敗", "err", err)
		return DirectoryPage{}, fmt.Errorf("activity: 讀取活動目錄失敗: %w", err)
	}
	return DirectoryPage{Rows: stored.Rows, Page: stored.Page, PageSize: stored.PageSize, Total: stored.Total}, nil
}

// ActivityDetail 以受信主體讀回單筆活動。
func (s *Service) ActivityDetail(ctx context.Context, principal identity.Principal,
	activityID idgen.ID) (Activity, error) {
	q := s.db.SQL()
	if err := s.requireActivityScope(ctx, q, principal, activityID, "detail"); err != nil {
		return Activity{}, err
	}
	return s.readActivity(ctx, q, activityID)
}

// visibleActivities 算出這個主體能看見的活動標識集合。
//
// 回傳 nil 與回傳空切片是兩件不同的事，且這句話寫在型別上而不是約定上：
//   - nil：不按標識限制（只有 Root 走到這一支）；
//   - 空切片：他什麼都看不到——目錄必須回空頁，而不是退化成全量。
//     把「漏帶授權資料」讀成「哪個活動都能看」是本套件最貴的一種錯。
func (s *Service) visibleActivities(ctx context.Context,
	principal identity.Principal) ([]idgen.ID, error) {
	if principal.IsRoot() {
		return nil, nil
	}
	ids, err := s.store.ManagedActivityIDs(ctx, s.db.SQL(), principal.AccountID())
	if err != nil {
		return nil, err
	}
	if ids == nil {
		// 倉儲查無任何指派時回的是 Go 的 nil 切片，與「不按標識限制」同值——
		// 這一層必須把兩者分開，所以換一個長度為零的非 nil 切片。
		return []idgen.ID{}, nil
	}
	return ids, nil
}

// normalizeStatusFilter 把狀態篩選引數換成資料庫欄位值。
//
// 空串與 all 都換成空串（語意是「不篩選」）；其餘取值必須落在封閉集合內，
// 落不進去回報 ErrInvalidStatusFilter——它與權限無關，改寫法就有答案。
func normalizeStatusFilter(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || value == FilterAll {
		return "", nil
	}
	status, err := ParseStatus(value)
	if err != nil {
		return "", fmt.Errorf("%w：%q 不在 draft|active|closed|archived|all 之內",
			ErrInvalidStatusFilter, value)
	}
	return status.String(), nil
}

// normalizeKeyword 正規化目錄關鍵字：剔除首尾空白，「整串都是空白」等價於「沒帶關鍵字」，
// 而不是拿一個空 pattern 去 LIKE '%%' 把整本目錄列出來。
func normalizeKeyword(raw string) (string, error) {
	keyword := strings.TrimSpace(raw)
	if keyword == "" {
		return "", nil
	}
	if n := utf8.RuneCountInString(keyword); n > DirectoryKeywordMaxRunes {
		return "", fmt.Errorf("%w：長度 %d 超過上限 %d",
			ErrInvalidKeyword, n, DirectoryKeywordMaxRunes)
	}
	return keyword, nil
}

// 目錄用例不碰的任何東西（寫在這裡是為了讓下次加欄位時先看見邊界）：
// 它不回傳活動內的成員、不回傳陣營，也不解釋「他在這個活動裡能做什麼」。
// 那些問題的答案還不存在，目錄不拿空值或推測冒充它們存在。
