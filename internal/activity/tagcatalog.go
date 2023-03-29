// tagcatalog.go 是「普通玩家讀活動標籤定義」那兩條讀法：一枚活動裡被設成公開的標籤
// 清單，以及按標識直查其中的單枚定義。
//
// 這一層存在的理由只有一句：公開旗標是隱私界而不是功能開關，所以它必須有一條
// 從結構上就递不出內部定義的讀法，而不是「讀全量再由某一處記得 filter」。四條規則：
//   - 准入只有「這次請求的憑據換出的那個帳戶，在這場活動裡有沒有成員行」。Root、系統主體
//     與匿名都不是帳戶主體，非成員也一律收斂成同一句不可分辨的 1001（口径同 selfselect.go
//     與 memberdirectory.go）；這一族沒有「切換成管理視角」的參數，請求本體與查詢串裡
//     都沒有一格能填「哪個玩家」或「給我內部定義」。
//   - 可見範圍由 SQL 那一端的 public = 1 決定（見 tagstore.go 的 PublicTags／PublicTagByID）。
//     「有這枚標籤、只是不給你讀」與「從未有過這枚標識」「那枚標籤屬於另一場活動」
//     是同一句話，玩家路徑上因此不掛存在性探測器。
//   - 輸出是白名單投影，不是行轉錄：一枚 PublicTagItem 只有標識與對外展示四值加排序。
//     內部可用性（available）、公開旗標本身（public）、建立與改動時刻、被貼標的人數、
//     審計原因與任何帳戶欄位一律不進這份投影——管理面要那些事實走 /admin 那一族，那道閘不同。
//   - 每一次請求都重新現讀：這一条街沒有快取層，也不採信請求交來的任何一格。
//     管理人把 public 由真改回假之後，下一次查詢就不再列出它；倉庫今日沒有實時層，
//     這裡也只宣稱到這一句（不假造推送）。
//
// 刻意沒有的兩件事，也不假裝有：
//   - 這一族不回答「這個玩家身上貼了哪些標籤」。貼標那一步尚未落地，今日沒有一份歸屬可投影，
//     也不拿空清單冒充「他沒有標籤」；這裡列出的只有定義本身。
//   - 這一族不改變任何人看不看得見：目錄的可見集合只由 0016 那兩欄（活動模式與本人覆蓋）
//     與成員行決定（見 memberdirectory.go）。一枚標籤是不是公開，既不會把一個本來不可見的
//     人變得可被查出，也不會讓任何人多得到一項能力——標籤不是角色，更不是權限。
package activity

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// PublicTagItem 是一枚標籤定義在玩家側的投影（欄位白名單見檔頭）。
//
// 它是「普通玩家能從標籤目錄裡拿到的全部」：沒有內部可用性、沒有公開旗標本身
// （清單裡每一行都已經是公開的，再帶一格 true 只是把內部模型抄給外面）、
// 沒有時刻、沒有被貼標的人數，也沒有「這枚標籤為什麼存在」那種後台原因。
type PublicTagItem struct {
	// TagID 是這枚標籤的穩定標識（日後引用標籤的都該是指向它，而不是名稱）。
	TagID idgen.ID
	// Name 是標籤名稱（展示值，可改；改動不讓任何既有引用失效）。
	Name string
	// Description 是標籤描述（可為空字串，意即「沒有寫過描述」）。
	Description string
	// Icon 為內建圖標鍵（空字串＝未選，界面以通用佔位圖標顯示）。
	Icon string
	// Color 為 #RRGGBB（空字串＝未選色）。界面不得只靠它辨認一枚標籤。
	Color string
	// SortOrder 為列表排序值；清單已由服務端按同一算式排好，這一格只是把事實帶回去。
	SortOrder int64
}

// PublicTagCatalog 以本次會話的帳戶讀「這場活動裡有幾枚標籤對外公開」。
//
// 順序只有兩跳，而且第一跳就決定可見範圍：先按（活動, 那個帳戶）讀他自己的成員行，
// 讀不到就是 ErrMemberNotFound——它與「根本沒有這場活動」「他不是任何地方的成員」
// 同一句話，玩家因此不會因為敲路徑就多知道「那個活動存在但沒我的份」。
// 空清單是這一讀的正常答案（「這場活動還沒公開任何標籤」），不是錯誤，也不做生命週期門禁：
// 讀取屬展示面，停止與歸檔的活動裡那份定義仍然讀得到（口径同陣營與目錄的讀法）。
func (s *Service) PublicTagCatalog(ctx context.Context, principal identity.Principal,
	activityID idgen.ID) ([]PublicTagItem, error) {
	accountID, err := s.requireSelfPrincipal(principal, "tag_catalog")
	if err != nil {
		return nil, err
	}
	q := s.db.SQL()
	if _, err := s.store.MemberByAccount(ctx, q, activityID, accountID); err != nil {
		return nil, err
	}
	rows, err := s.store.PublicTags(ctx, q, activityID)
	if err != nil {
		s.log.Error("讀取公開標籤目錄失敗", "activity", activityID.String(), "err", err)
		return nil, fmt.Errorf("activity: 讀取公開標籤目錄失敗: %w", err)
	}
	out := make([]PublicTagItem, 0, len(rows))
	for _, row := range rows {
		out = append(out, publicTagItemOf(row))
	}
	return out, nil
}

// PublicTagDetail 以同一條可見範圍讀回單枚公開標籤定義。
//
// 它刻意不另開一條「按標識查一行、然後問能不能給你看」的路：可見性直接寫在那條讀法的
// WHERE 裡（同一張表、同一個條件），於是「清單裡沒有它」與「按它的標識直查也查不到」
// 必然同進同退，而造出這個结果的三種原因（從未存在、屬於另一場活動、此刻沒被設成公開）
// 對外都是同一句話。
func (s *Service) PublicTagDetail(ctx context.Context, principal identity.Principal,
	activityID, tagID idgen.ID) (PublicTagItem, error) {
	accountID, err := s.requireSelfPrincipal(principal, "tag_catalog_detail")
	if err != nil {
		return PublicTagItem{}, err
	}
	q := s.db.SQL()
	if _, err := s.store.MemberByAccount(ctx, q, activityID, accountID); err != nil {
		return PublicTagItem{}, err
	}
	if tagID.IsNil() {
		return PublicTagItem{}, ErrTagNotFound
	}
	row, err := s.store.PublicTagByID(ctx, q, tagID, activityID)
	if err != nil {
		if errors.Is(err, ErrTagNotFound) {
			return PublicTagItem{}, err
		}
		s.log.Error("讀取單枚公開標籤失敗", "activity", activityID.String(), "tag", tagID.String(),
			"err", err)
		return PublicTagItem{}, err
	}
	return publicTagItemOf(row), nil
}

// publicTagItemOf 把一行標籤定義換成玩家側投影：這一處是那一族兩條讀法唯一的欄位清單，
// 於是清單裡那一行與直查那一份不可能各長一套。
func publicTagItemOf(tag Tag) PublicTagItem {
	return PublicTagItem{
		TagID: tag.ID, Name: tag.Name, Description: tag.Description,
		Icon: tag.Icon, Color: tag.Color, SortOrder: tag.SortOrder,
	}
}
