// tag_test.go 是標籤定義用例的服務層證據：新建的標籤一出生即可用且不公開（「預設內部」
// 這句話由域層與資料庫各自撐住）、同活動名稱唯一與跨活動同名的互不相干、跨活動讀改的
// 不可分辨、停止／歸檔兩道業務寫入門禁各有各的句子、併發編輯的落敗那一句、七欄白名單
// 編輯不碰身份與時刻、改名不換標識（引用因此不失效）、留痕帶著真實操作者與含公開前後值
// 的變更摘要，以及玩家那一族的可見範圍：未公開的定義與幽靈同形、翻公開後下一筆請求就
// 讀得到、收回後下一筆請求就讀不到（今日沒有快取層可失效，也不宣稱有推送）。
//
// 刻意不收的東西：
//   - 沒有替身：授權、門禁、重名核實、公開篩選、CAS 與審計都走真路徑（真資料庫＋注入時鐘）；
//   - 不測協定層（欄位注入 1004、機器碼對映）：那是 internal/httpapi 的端點證據；
//   - 不測「把標籤貼在玩家身上」：貼標尚未落地，本套件沒有一條通路能偽造那份歸屬，
//     也不拿空清單冒充「他沒有標籤」。
package activity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// tagDraft 湊一份最簡合法輸入：除名稱外全部走默認（未選圖標、未選色、未指定排序）。
func tagDraft(name string) TagDraft {
	return TagDraft{Name: name}
}

// mustCreateTag 建立一枚標籤，失敗即終止。
func (e *env) mustCreateTag(t *testing.T, principal identity.Principal,
	activityID idgen.ID, name string) Tag {
	t.Helper()
	tag, err := e.service.CreateTag(context.Background(), principal, activityID,
		tagDraft(name), "req-tag")
	if err != nil {
		t.Fatalf("建立標籤 %q 應成功：%v", name, err)
	}
	return tag
}

// tagFieldsOf 從一筆已讀回的標籤換出「以它自己的現值」的一份七欄值。
//
// 依據值一律取服務端讀回的那一份，不硬編：這一檔每次改動都先重讀，於是 CAS 那句
// 「你依據的現值還成不成立」問的是真實形態。
func tagFieldsOf(tag Tag) TagFields {
	return TagFields{
		Name: tag.Name, Description: tag.Description, Icon: tag.Icon, Color: tag.Color,
		SortOrder: tag.SortOrder, Available: tag.Available, Public: tag.Public,
	}
}

// tagEdit 湊一份「只改名稱」的合法編輯（新值與依據值都從 current 長出來）。
func tagEdit(current Tag, name string) TagEdit {
	changed := tagFieldsOf(current)
	changed.Name = name
	return TagEdit{New: changed, Expected: tagFieldsOf(current)}
}

// mustUpdateTag 送一次必須成功的編輯並回傳結果。
func (e *env) mustUpdateTag(t *testing.T, principal identity.Principal,
	activityID, tagID idgen.ID, edit TagEdit) Tag {
	t.Helper()
	updated, err := e.service.UpdateTag(context.Background(), principal, activityID, tagID,
		edit, "req-tag-update")
	if err != nil {
		t.Fatalf("編輯標籤 %s 應成功：%v", tagID.String(), err)
	}
	return updated
}

// setTagPublic 以服務端現值為依據值，送一次「只翻公開旗標」的編輯。
func (e *env) setTagPublic(t *testing.T, principal identity.Principal, tag Tag,
	want bool) (Tag, error) {
	t.Helper()
	edit := tagEdit(tag, tag.Name)
	edit.New.Public = want
	return e.service.UpdateTag(context.Background(), principal, tag.ActivityID, tag.ID,
		edit, "req-tag-public")
}

// setTagAvailability 以服務端現值為依據值，送一次「只翻可用性」的編輯。
func (e *env) setTagAvailability(t *testing.T, principal identity.Principal, tag Tag,
	want bool) (Tag, error) {
	t.Helper()
	edit := tagEdit(tag, tag.Name)
	edit.New.Available = want
	return e.service.UpdateTag(context.Background(), principal, tag.ActivityID, tag.ID,
		edit, "req-tag-availability")
}

// tagFacts 是一行標籤在資料庫裡的可觀察形態（白名單外的欄位是否被碰過靠它做等值比較）。
type tagFacts struct {
	activityID  string
	name        string
	description string
	icon        string
	color       string
	sortOrder   int64
	available   int64
	public      int64
	createdAt   int64
	updatedAt   int64
}

func (e *env) tagFacts(t *testing.T, id idgen.ID) tagFacts {
	t.Helper()
	var f tagFacts
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT activity_id, name, description,
			icon, color, sort_order, available, public, created_at, updated_at
		FROM activity_tags WHERE id = ?`, id.String()).
		Scan(&f.activityID, &f.name, &f.description, &f.icon, &f.color,
			&f.sortOrder, &f.available, &f.public, &f.createdAt, &f.updatedAt)
	if err != nil {
		t.Fatalf("讀取標籤 %s 的事實失敗：%v", id.String(), err)
	}
	return f
}

// tagGuardInWriteTx 在一個寫入交易內呼叫「這枚標籤此刻收不收新貼標」的判定，
// 形狀與日後那條貼標通路一致（同交易內現讀，判定與寫入共用一個快照）。
func (e *env) tagGuardInWriteTx(t *testing.T, activityID, tagID idgen.ID) (Tag, error) {
	t.Helper()
	var got Tag
	err := e.db.InTx(context.Background(), func(tctx context.Context, tx *database.Tx) error {
		var inner error
		got, inner = e.service.EnsureTagAcceptsNewAssignments(tctx, tx, activityID, tagID)
		return inner
	})
	return got, err
}

// latestTagAudit 讀回某一動作最新一筆活動域留痕（複用陣營那檔的可觀察形態）。
func (e *env) latestTagAudit(t *testing.T, action, activityID string) factionAuditRow {
	t.Helper()
	var row factionAuditRow
	err := e.db.SQL().QueryRowContext(context.Background(), `SELECT actor_kind,
			COALESCE(actor_id, ''), reason, changes_json
		FROM activity_audit WHERE action = ? AND activity_id = ?
		ORDER BY created_at DESC, id DESC LIMIT 1`, action, activityID).
		Scan(&row.actorKind, &row.actorID, &row.reason, &row.changes)
	if err != nil {
		t.Fatalf("讀取審計 %s／%s 失敗：%v", action, activityID, err)
	}
	return row
}

// transitionTo 把活動沿合法路徑推到目標狀態（草稿→開放→停止→歸檔逐跳走真通路）。
func (e *env) transitionTo(t *testing.T, principal identity.Principal,
	activityID idgen.ID, want Status) {
	t.Helper()
	path := []Status{StatusActive, StatusClosed, StatusArchived}
	for _, step := range path {
		if _, err := e.service.Transition(context.Background(), principal, activityID,
			step, "req-move"); err != nil {
			t.Fatalf("把活動推到 %s 應成功：%v", step, err)
		}
		if step == want {
			return
		}
	}
	t.Fatalf("狀態路徑裡沒有 %s 這一格", want)
}

// TestTagCreateIsInternalByDefault 驗收：新建的標籤一出生即可用、且不公開，
// 時刻取自注入時鐘，未指定排序值者排在最後；列表按「排序值、建立時刻、標識」穩定呈現。
func TestTagCreateIsInternalByDefault(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Tag.Create")
	activity := e.create(t, principal, "有標籤的場", "")

	first := e.mustCreateTag(t, principal, activity.ID, "先來的那枚")
	if first.Public {
		t.Error("新建的標籤必須一出生就是內部資訊（對外要管理人明確翻那一欄）")
	}
	if !first.Available {
		t.Error("新建的標籤必須一出生即可用")
	}
	if !first.AcceptsNewAssignments {
		t.Error("可用且活動可寫：派生那一格此刻該是真")
	}
	if first.SortOrder != 0 {
		t.Errorf("空表裡排尾值是 0，實際 %d", first.SortOrder)
	}
	second := e.mustCreateTag(t, principal, activity.ID, "指定排序的那枚")
	sortEdit := tagEdit(second, second.Name)
	sortEdit.New.SortOrder = 3
	e.mustUpdateTag(t, principal, activity.ID, second.ID, sortEdit)

	rows, err := e.service.Tags(context.Background(), principal, activity.ID)
	if err != nil {
		t.Fatalf("讀列表應成功：%v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("列表該有兩行，實際 %d", len(rows))
	}
	if rows[0].Name != "先來的那枚" || rows[1].Name != "指定排序的那枚" {
		t.Errorf("排序值小的排在前面（0→3），實際 %q→%q", rows[0].Name, rows[1].Name)
	}
	for _, row := range rows {
		if row.Public {
			t.Errorf("兩枚都是未翻開的內部標籤，列表卻把 %q 報成公開", row.Name)
		}
	}
}

// TestTagNameRules 驗收：同活動內重名被擋且整筆不落地，跨活動同名完全合法，
// 而名稱只是展示值——同一枚標籤改名前後標識一個字沒變。
func TestTagNameRules(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Tag.Name")
	activity := e.create(t, principal, "甲場", "")
	other := e.create(t, principal, "乙場", "")

	tag := e.mustCreateTag(t, principal, activity.ID, "冠軍")
	if _, err := e.service.CreateTag(context.Background(), principal, activity.ID,
		tagDraft("冠軍"), "req-dup"); !errors.Is(err, ErrTagNameTaken) {
		t.Errorf("同活動內重名該拿到 ErrTagNameTaken，實際 %v", err)
	}
	if _, err := e.service.CreateTag(context.Background(), principal, other.ID,
		tagDraft("冠軍"), "req-cross"); err != nil {
		t.Errorf("跨活動同名應完全合法，實際 %v", err)
	}
	if got := e.countRows(t, "activity_tags"); got != 2 {
		t.Errorf("撞名的那一次該整筆不落地，表裡該有 2 行，實際 %d", got)
	}

	// 名稱不是外鍵：把甲場那枚改名，標識與歸屬與建立時刻一個字都沒動。
	before := e.tagFacts(t, tag.ID)
	renamed := e.mustUpdateTag(t, principal, activity.ID, tag.ID, tagEdit(tag, "亞軍"))
	after := e.tagFacts(t, tag.ID)
	if renamed.ID != tag.ID {
		t.Error("改名換了標識：那等於把一枚標籤連同它的歷史搬到別名下")
	}
	if after.activityID != before.activityID || after.createdAt != before.createdAt {
		t.Errorf("改名動到歸屬或建立時刻（%q→%q／%d→%d）",
			before.activityID, after.activityID, before.createdAt, after.createdAt)
	}
	if after.name != "亞軍" {
		t.Errorf("改名該落在名稱那一欄，實際 %q", after.name)
	}
	// 改完之後原先那個名字空出來了：同活動內可以再建一枚叫「冠軍」的。
	if _, err := e.service.CreateTag(context.Background(), principal, activity.ID,
		tagDraft("冠軍"), "req-freed"); err != nil {
		t.Errorf("改名後原名該可重用，實際 %v", err)
	}
}

// TestTagCrossActivityIsIndistinguishable 驗收：拿甲場的標識去敲乙場，
// 與「那個標識從未存在」逐字同一句話，跨活動讀改不給任何可探測的信號。
func TestTagCrossActivityIsIndistinguishable(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Tag.Cross")
	activity := e.create(t, principal, "甲場", "")
	other := e.create(t, principal, "乙場", "")
	tag := e.mustCreateTag(t, principal, activity.ID, "甲場的標籤")
	ghost := identitytest.NewID(t)

	onOther, err := e.service.UpdateTag(context.Background(), principal, other.ID, tag.ID,
		tagEdit(tag, "別名的標籤"), "req-cross-update")
	onGhost, ghostErr := e.service.UpdateTag(context.Background(), principal, other.ID, ghost,
		tagEdit(tag, "湊不上任何東西"), "req-ghost-update")
	if !errors.Is(err, ErrTagNotFound) || !errors.Is(ghostErr, ErrTagNotFound) {
		t.Fatalf("跨活動與幽靈都該收斂成不可分辨的查無，實際 %v／%v", err, ghostErr)
	}
	if err.Error() != ghostErr.Error() {
		t.Errorf("兩句必須逐字同形：%q vs %q", err, ghostErr)
	}
	if onOther.ID == tag.ID || onGhost.ID == tag.ID {
		t.Error("被拒的編輯不該回讀任何一行")
	}
	rows, err := e.service.Tags(context.Background(), principal, other.ID)
	if err != nil {
		t.Fatalf("讀乙場列表應成功：%v", err)
	}
	if len(rows) != 0 {
		t.Errorf("甲場的標籤不該出現在乙場的列表裡，實際 %d 行", len(rows))
	}
	// 甲場那一行原樣還在（被拒的那兩次都沒碰到它）。
	if got := e.tagFacts(t, tag.ID).name; got != "甲場的標籤" {
		t.Errorf("跨活動的敲擊不該改到甲場那枚的名稱，實際 %q", got)
	}
}

// TestTagWritesRespectLifecycleGate 驗收：停止態的標籤寫入拿到「現在不行、重開就好」，
// 歸檔拿到「這件事已經結束」；兩句都整筆不落地，而讀法不受門禁約束（仍列、可讀）。
func TestTagWritesRespectLifecycleGate(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Tag.Gate")
	activity := e.create(t, principal, "會停止的場", "")
	tag := e.mustCreateTag(t, principal, activity.ID, "停止前的標籤")

	e.transitionTo(t, principal, activity.ID, StatusClosed)
	if _, err := e.service.CreateTag(context.Background(), principal, activity.ID,
		tagDraft("停止後建的"), "req-closed-create"); !errors.Is(err, ErrActivityClosedWrites) {
		t.Errorf("停止態的建立該拿到業務寫入那一句，實際 %v", err)
	}
	if _, err := e.setTagPublic(t, principal, tag, true); !errors.Is(err, ErrActivityClosedWrites) {
		t.Errorf("停止態翻公開該拿到業務寫入那一句，實際 %v", err)
	}
	rows, err := e.service.Tags(context.Background(), principal, activity.ID)
	if err != nil {
		t.Fatalf("停止態仍要讀得到列表：%v", err)
	}
	if len(rows) != 1 || rows[0].AcceptsNewAssignments {
		t.Errorf("停止態的列表該照樣列出行且派生那一格轉假，實際 %+v", rows)
	}

	e.transitionTo(t, principal, activity.ID, StatusArchived)
	if _, err := e.setTagPublic(t, principal, tag, true); !errors.Is(err, ErrArchived) {
		t.Errorf("歸檔態的寫入該拿到終態那一句，實際 %v", err)
	}
	if _, err := e.service.Tags(context.Background(), principal, activity.ID); err != nil {
		t.Errorf("歸檔態照樣讀得到列表（仍列、可讀），實際 %v", err)
	}
	if got := e.tagFacts(t, tag.ID).public; got != 0 {
		t.Errorf("兩次被拒的寫入都該整筆不落地，公開旗標卻被翻成 %d", got)
	}
}

// TestTagStaleEditKeepsWinner 驗收：兩份以同一現值為依據的編輯裡，落敗那一份拿到現值衝突，
// 而且一個字都不落、也不追加留痕；依據值裡連公開那一欄都參與比較。
func TestTagStaleEditKeepsWinner(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Tag.Stale")
	activity := e.create(t, principal, "兩人同時改的場", "")
	tag := e.mustCreateTag(t, principal, activity.ID, "被搶先的標籤")

	// 第一份：把名稱與公開一起翻開（贏家）。
	winning := tagEdit(tag, "贏家改的名字")
	winning.New.Public = true
	e.mustUpdateTag(t, principal, activity.ID, tag.ID, winning)
	before := e.tagFacts(t, tag.ID)
	auditsBefore := e.countAuditRows(t, "tag.update", activity.ID.String())

	// 第二份拿同一份舊現值重發：撞牆，且不得覆蓋贏家的方向。
	if _, err := e.service.UpdateTag(context.Background(), principal, activity.ID, tag.ID,
		winning, "req-lose"); !errors.Is(err, ErrTagProfileConflict) {
		t.Errorf("過期依據值該拿到現值衝突，實際 %v", err)
	}
	if after := e.tagFacts(t, tag.ID); after != before {
		t.Errorf("落敗的那一份該一個字都不落：\n舊 %+v\n新 %+v", before, after)
	}
	if got := e.countAuditRows(t, "tag.update", activity.ID.String()); got != auditsBefore {
		t.Errorf("被拒的編輯不追加留痕，實際 %d 筆（本該 %d 筆）", got, auditsBefore)
	}

	// 第三份以「從未存在的依據值」重發：伺服器不為它換第二句話，仍是同一枚衝突。
	stale := tagEdit(tag, "又改一次")
	if _, err := e.service.UpdateTag(context.Background(), principal, activity.ID, tag.ID,
		stale, "req-stale-again"); !errors.Is(err, ErrTagProfileConflict) {
		t.Errorf("第三份過期編輯同樣該撞牆，實際 %v", err)
	}
	if got := e.tagFacts(t, tag.ID); got.name != "贏家改的名字" || got.public != 1 {
		t.Errorf("贏家的現值不被落敗者覆蓋，實際 %+v", got)
	}
}

// TestTagPublicFlagIsPerTag 驗收：公開是一枚一枚決定的，翻開一枚不動另一枚，
// 而收回來之後標識與名稱與時刻全在——翻公開不改寫任何既有事實。
func TestTagPublicFlagIsPerTag(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Tag.PerTag")
	activity := e.create(t, principal, "兩枚標籤的場", "")
	one := e.mustCreateTag(t, principal, activity.ID, "要公開的那枚")
	other := e.mustCreateTag(t, principal, activity.ID, "留內部的那枚")
	otherFacts := e.tagFacts(t, other.ID)

	published, err := e.setTagPublic(t, principal, one, true)
	if err != nil {
		t.Fatalf("翻公開應成功：%v", err)
	}
	if !published.Public {
		t.Error("回應要如實回顯新的公開旗標")
	}
	rows, err := e.service.Tags(context.Background(), principal, activity.ID)
	if err != nil {
		t.Fatalf("讀列表應成功：%v", err)
	}
	for _, row := range rows {
		if row.Name == "要公開的那枚" && !row.Public {
			t.Errorf("%q 已被翻開，列表卻報成內部", row.Name)
		}
		if row.Name == "留內部的那枚" && row.Public {
			t.Errorf("%q 沒被翻開，列表卻報成公開（公開是一枚一枚的）", row.Name)
		}
	}

	// 收回公開：只動那一欄，名稱與標識與建立時刻原樣還在。
	if _, err := e.setTagPublic(t, principal, published, false); err != nil {
		t.Fatalf("收回公開應成功：%v", err)
	}
	if got := e.tagFacts(t, one.ID); got.public != 0 || got.name != one.Name {
		t.Errorf("收回公開只該動那一欄，實際 %+v", got)
	}
	if got := e.tagFacts(t, other.ID); got != otherFacts {
		t.Errorf("翻另一枚不該碰到這一枚：\n舊 %+v\n新 %+v", otherFacts, got)
	}
}

// TestTagPlayerCatalogFollowsFlag 驗收玩家那一族的可見範圍與請求級失效：
// 未公開時清單與直查都與幽靈同形，翻公開後下一筆請求就讀得到，收回後下一筆就讀不到；
// 而這一讀吃的是本人成員行，非成員與 Root 一律拿同一句不可分辨。
func TestTagPlayerCatalogFollowsFlag(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Tag.Catalog")
	activity := e.create(t, principal, "玩家會看標籤的場", "")
	player := e.plain(t, "tag.player")
	if _, err := e.service.CreateMember(context.Background(), principal, activity.ID,
		player.AccountID(), "觀眾", "req-member"); err != nil {
		t.Fatalf("建立成員行應成功：%v", err)
	}
	outsider := e.plain(t, "tag.outsider")

	hidden := e.mustCreateTag(t, principal, activity.ID, "內部備註")
	published, err := e.setTagPublic(t, principal,
		e.mustCreateTag(t, principal, activity.ID, "對外稱號"), true)
	if err != nil {
		t.Fatalf("翻公開應成功：%v", err)
	}

	rows, err := e.service.PublicTagCatalog(context.Background(), player, activity.ID)
	if err != nil {
		t.Fatalf("成員讀公開目錄應成功：%v", err)
	}
	if len(rows) != 1 || rows[0].TagID != published.ID {
		t.Fatalf("清單該只有那一枚公開的，實際 %+v", rows)
	}
	// 玩家投影不帶內部欄位：那一族的型別裡就沒有 available／public／時刻那些格子，
	// 於是「某一處忘了不填」無從發生（不是靠測試作者記住結構體有哪幾格）。
	projection := fmt.Sprintf("%+v", rows[0])
	for _, forbidden := range []string{"Available", "Public", "CreatedAt", "UpdatedAt",
		"AcceptsNewAssignments", "ActivityID"} {
		if strings.Contains(projection, forbidden) {
			t.Errorf("玩家投影不該帶出內部欄位 %q：%s", forbidden, projection)
		}
	}

	// 直查一枚內部標籤與直查一枚從未存在的標識：同一句話、同一份文字。
	_, hiddenErr := e.service.PublicTagDetail(context.Background(), player, activity.ID, hidden.ID)
	_, ghostErr := e.service.PublicTagDetail(context.Background(), player, activity.ID,
		identitytest.NewID(t))
	if !errors.Is(hiddenErr, ErrTagNotFound) || !errors.Is(ghostErr, ErrTagNotFound) {
		t.Fatalf("兩種都該收斂成查無，實際 %v／%v", hiddenErr, ghostErr)
	}
	if hiddenErr.Error() != ghostErr.Error() {
		t.Errorf("兩句必須逐字同形：%q vs %q", hiddenErr, ghostErr)
	}
	detail, err := e.service.PublicTagDetail(context.Background(), player, activity.ID, published.ID)
	if err != nil {
		t.Fatalf("直查一枚公開標籤應成功：%v", err)
	}
	if detail.TagID != published.ID || detail.Name != published.Name {
		t.Errorf("直查讀到的該是那一枚本身，實際 %+v", detail)
	}

	// 非成員與 Root 在這一族裡沒有可指向的成員行：與查無這活動同一句話。
	if _, err := e.service.PublicTagCatalog(context.Background(), outsider,
		activity.ID); !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("非成員敲目錄該拿不可分辨那一句，實際 %v", err)
	}
	if _, err := e.service.PublicTagCatalog(context.Background(), e.root(t),
		activity.ID); !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("Root 在玩家這一族該拿同一句，實際 %v", err)
	}

	// 收回公開：下一次請求就讀不到（本套件今日沒有快取層，也不宣稱有推送）。
	if _, err := e.setTagPublic(t, principal, published, false); err != nil {
		t.Fatalf("收回公開應成功：%v", err)
	}
	rows, err = e.service.PublicTagCatalog(context.Background(), player, activity.ID)
	if err != nil {
		t.Fatalf("收回公開後讀目錄仍應成功：%v", err)
	}
	if len(rows) != 0 {
		t.Errorf("收回公開後下一筆請求該讀不到它，實際 %+v", rows)
	}
	if _, err := e.service.PublicTagDetail(context.Background(), player, activity.ID,
		published.ID); !errors.Is(err, ErrTagNotFound) {
		t.Errorf("收回公開後直查該與幽靈同形，實際 %v", err)
	}
	// 管理那一族的讀法不受影響：那一枚仍在原處，只是又變回內部。
	adminRows, err := e.service.Tags(context.Background(), principal, activity.ID)
	if err != nil || len(adminRows) != 2 {
		t.Errorf("收回公開不刪行、也不動管理面的讀法，實際 %d 行／%v", len(adminRows), err)
	}
}

// TestTagAssignmentGuardConclusions 驗收留給貼標那一步的判定幾種結論各自成形：
// 可用即放行、停用即拒、跨活動與幽靈同形、停止與歸檔各有各的一句、唯讀交易連門都進不來。
//
// 這一格刻意與公開旗標無關：一枚已公開但停用的標籤照樣貼不上去，一枚未公開的標籤
// 照常被管理面使用——public 只決定定義讀不讀得到，不決定能不能被引用。
func TestTagAssignmentGuardConclusions(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Tag.Guard")
	actA := e.create(t, principal, "判定甲", "")
	actB := e.create(t, principal, "判定乙", "")
	open := e.mustCreateTag(t, principal, actA.ID, "還開著的")
	disabled := e.mustCreateTag(t, principal, actA.ID, "已停用的")
	ghost := identitytest.NewID(t)

	if got, err := e.tagGuardInWriteTx(t, actA.ID, open.ID); err != nil || !got.AcceptsNewAssignments {
		t.Fatalf("草稿活動裡的可用標籤該放行，實際 %v（%+v）", err, got)
	}
	// 未公開也照常放行：公開旗標不參與「能不能被使用」這句話。
	if _, err := e.tagGuardInWriteTx(t, actA.ID, disabled.ID); err != nil {
		t.Fatalf("停用前先確認判定走得通：%v", err)
	}
	stopped, err := e.setTagAvailability(t, principal, disabled, false)
	if err != nil {
		t.Fatalf("停用應成功：%v", err)
	}
	if _, err := e.tagGuardInWriteTx(t, actA.ID, disabled.ID); !errors.Is(err, ErrTagNotAcceptingAssignments) {
		t.Errorf("停用的標籤該被拒在新貼標之外，實際 %v", err)
	}
	// 跨活動與幽靈同形：判定不能變成「那個標識確實是甲場的標籤」探測器。
	_, errOnOther := e.tagGuardInWriteTx(t, actB.ID, open.ID)
	_, errOnGhost := e.tagGuardInWriteTx(t, actB.ID, ghost)
	if !errors.Is(errOnOther, ErrTagNotFound) || !errors.Is(errOnGhost, ErrTagNotFound) {
		t.Fatalf("兩種都該收斂成查無，實際 %v／%v", errOnOther, errOnGhost)
	}
	if errOnOther.Error() != errOnGhost.Error() {
		t.Errorf("兩句必須逐字同形：%q vs %q", errOnOther, errOnGhost)
	}
	// 公開旗標也一起翻開那枚停用的：判定仍拒——停用與公開是兩件事。
	// 依據值一律吃上一次寫入回讀的那一份（這才是 CAS 問的那句話）。
	publishedStopped, err := e.setTagPublic(t, principal, stopped, true)
	if err != nil {
		t.Fatalf("已停用的標籤仍該可被編輯（公開與可用互不相干）：%v", err)
	}
	if _, err := e.tagGuardInWriteTx(t, actA.ID, publishedStopped.ID); !errors.Is(err, ErrTagNotAcceptingAssignments) {
		t.Errorf("已公開但停用的標籤該被拒，實際 %v", err)
	}

	// 活動停止：連重新啟用的標籤也貼不出去（門禁那一句先答，處置是「等活動重開」）。
	reenabled, err := e.setTagAvailability(t, principal, publishedStopped, true)
	if err != nil {
		t.Fatalf("重新啟用應成功：%v", err)
	}
	e.transitionTo(t, principal, actA.ID, StatusClosed)
	if _, err := e.tagGuardInWriteTx(t, actA.ID, reenabled.ID); !errors.Is(err, ErrActivityClosedWrites) {
		t.Errorf("停止態的判定應拿到門禁那句，實際 %v", err)
	}
	e.transitionTo(t, principal, actA.ID, StatusArchived)
	if _, err := e.tagGuardInWriteTx(t, actA.ID, reenabled.ID); !errors.Is(err, ErrArchived) {
		t.Errorf("歸檔態的判定應拿到終態那句，實際 %v", err)
	}

	// 誤用兩種都不放行：判定存在的理由就是「與寫入同一個快照」，交易外與唯讀交易都不算。
	if _, err := e.service.EnsureTagAcceptsNewAssignments(context.Background(), nil,
		actA.ID, reenabled.ID); !errors.Is(err, errTagGuardNeedsWriteTx) {
		t.Errorf("零值交易該報誤用，實際 %v", err)
	}
	readOnlyErr := e.db.InTxReadOnly(context.Background(), func(tctx context.Context, tx *database.Tx) error {
		_, err := e.service.EnsureTagAcceptsNewAssignments(tctx, tx, actA.ID, reenabled.ID)
		if !errors.Is(err, errTagGuardNeedsWriteTx) {
			t.Errorf("唯讀交易該報誤用而不是放行，實際 %v", err)
		}
		return nil
	})
	if readOnlyErr != nil {
		t.Fatalf("唯讀誤用的斷言該留在回呼裡，回呼本身該正常收尾：%v", readOnlyErr)
	}
}

// TestTagAuditCarriesActorAndPublicChange 驗收留痕：建立與編輯各一筆，操作者是那位
// 真實的管理人（不是「伺服器自己做的」），而翻公開那一次的前後值與原因句都說得出來。
func TestTagAuditCarriesActorAndPublicChange(t *testing.T) {
	e := newEnv(t)
	principal, account := e.admin(t, "Tag.Audit")
	activity := e.create(t, principal, "留痕的場", "")
	tag := e.mustCreateTag(t, principal, activity.ID, "要被公開的")

	created := e.latestTagAudit(t, "tag.create", activity.ID.String())
	if created.actorKind == "system" || created.actorID == "" {
		t.Errorf("建立的留痕要帶著真實操作者，實際 %+v", created)
	}
	if created.actorID != account.ID.String() {
		t.Errorf("留痕的操作者該是那位管理人（%s），實際 %s", account.ID.String(), created.actorID)
	}
	if !strings.Contains(created.changes, "\"public\"") {
		t.Errorf("建立的摘要要如實記下這枚標籤出生不公開，實際 %s", created.changes)
	}

	auditsBefore := e.countAuditRows(t, "tag.update", activity.ID.String())
	published, err := e.setTagPublic(t, principal, tag, true)
	if err != nil {
		t.Fatalf("翻公開應成功：%v", err)
	}
	if got := e.countAuditRows(t, "tag.update", activity.ID.String()); got != auditsBefore+1 {
		t.Fatalf("翻公開那一次要留下一筆留痕，實際 %d 筆", got)
	}
	updated := e.latestTagAudit(t, "tag.update", activity.ID.String())
	if !strings.Contains(updated.changes, "\"public\"") ||
		!strings.Contains(updated.changes, "false") ||
		!strings.Contains(updated.changes, "true") {
		t.Errorf("摘要要帶得出 public 的前後值，實際 %s", updated.changes)
	}
	if !strings.Contains(updated.reason, "公開") {
		t.Errorf("原因句要說出這一次動的是公開範圍，實際 %q", updated.reason)
	}
	if updated.actorID != account.ID.String() {
		t.Errorf("編輯的留痕也要帶著同一位真實操作者，實際 %s", updated.actorID)
	}
	if !strings.Contains(updated.changes, tag.Name) {
		t.Errorf("摘要要點得出動的是哪一枚（名稱的前後值都在）：%s", updated.changes)
	}
	// 目標那一格帶的是這枚標籤的標識：留痕要能被「誰動過這一枚標籤」問得動。
	var targetID string
	if err := e.db.SQL().QueryRowContext(context.Background(),
		`SELECT COALESCE(target_id, '') FROM activity_audit
		 WHERE action = 'tag.update' AND activity_id = ?
		 ORDER BY created_at DESC, id DESC LIMIT 1`, activity.ID.String()).
		Scan(&targetID); err != nil {
		t.Fatalf("讀留痕的目標失敗：%v", err)
	}
	if targetID != tag.ID.String() {
		t.Errorf("留痕的目標該是那枚標籤本身（%s），實際 %s", tag.ID.String(), targetID)
	}

	// 被拒的編輯不留痕：以舊值重發什麼都沒發生，審計也不該記下一件沒發生過的事。
	if _, err := e.service.UpdateTag(context.Background(), principal, activity.ID, tag.ID,
		tagEdit(tag, "以舊值重發"), "req-stale"); err == nil {
		t.Fatal("以舊值重發該撞現值衝突")
	}
	if !published.Public {
		t.Error("贏家那一份的現值不該被落敗者覆蓋")
	}
	if got := e.countAuditRows(t, "tag.update", activity.ID.String()); got != auditsBefore+1 {
		t.Errorf("被拒的編輯不追加留痕，實際 %d 筆", got)
	}
}

// TestTagDomainValidation 驗收每一種湊得出來但無法解釋的展示輸入各有各的句子，
// 而且非法寫入整筆不落地（表裡一行也沒有）。
func TestTagDomainValidation(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Tag.Validation")
	activity := e.create(t, principal, "校驗的場", "")

	tooLong := strings.Repeat("長", 65)
	negative := int64(-1)
	cases := []struct {
		what  string
		draft TagDraft
		want  error
	}{
		{"空白名稱", tagDraft("   "), ErrInvalidName},
		{"超長名稱", tagDraft(tooLong), ErrInvalidName},
		{"集合外的圖標", TagDraft{Name: "正常", Icon: "dragon"}, ErrInvalidTagIcon},
		{"缺井的顏色", TagDraft{Name: "正常", Color: "ff0000"}, ErrInvalidTagColor},
		{"負的排序值", TagDraft{Name: "正常", SortOrder: &negative}, ErrInvalidTagSortOrder},
	}
	for _, tc := range cases {
		if _, err := e.service.CreateTag(context.Background(), principal, activity.ID,
			tc.draft, "req-invalid"); !errors.Is(err, tc.want) {
			t.Errorf("%s 該拿到 %v，實際 %v", tc.what, tc.want, err)
		}
	}
	if got := e.countRows(t, "activity_tags"); got != 0 {
		t.Errorf("非法寫入一律整筆不落地，表裡却有 %d 行", got)
	}

	// 大寫十六進位在域層被正規化成小寫：界面拿到的與庫裡的必須是同一個寫法。
	normalized, err := e.service.CreateTag(context.Background(), principal, activity.ID,
		TagDraft{Name: "選了色", Color: "#AABBCC", Icon: "star"}, "req-normalize")
	if err != nil {
		t.Fatalf("合法輸入應成功：%v", err)
	}
	if normalized.Color != "#aabbcc" || normalized.Icon != "star" {
		t.Errorf("顏色該正規化成小寫，實際 %q／圖標 %q", normalized.Color, normalized.Icon)
	}
}

// TestTagUnauthorizedPrincipalsRejected 驗收：普通玩家與未獲指派的管理人都敲不進
// 管理面任何一條路，而他們的敲擊不留下任何一行標籤。
func TestTagUnauthorizedPrincipalsRejected(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Tag.Authz")
	activity := e.create(t, principal, "准入取證的場", "")
	outsider, _ := e.admin(t, "Tag.Outsider")
	player := e.plain(t, "tag.player")

	if _, err := e.service.CreateTag(context.Background(), player, activity.ID,
		tagDraft("玩家想建標籤"), "req-player"); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("普通玩家該被拒在管理面之外，實際 %v", err)
	}
	if _, err := e.service.Tags(context.Background(), outsider, activity.ID); !errors.Is(err, ErrActivityNotFound) {
		t.Errorf("未獲指派的管理人不該因為持有授予就看到別人管的活動，且要收斂成不可分辨那一句，實際 %v", err)
	}
	if _, err := e.service.Tags(context.Background(), player, activity.ID); !errors.Is(err, identity.ErrPermissionDenied) &&
		!errors.Is(err, ErrActivityNotFound) {
		t.Errorf("普通玩家讀管理列表該被拒（2011 或不可分辨那一句），實際 %v", err)
	}
	if got := e.countRows(t, "activity_tags"); got != 0 {
		t.Errorf("被拒的寫入不該落地，表裡却有 %d 行", got)
	}
}

// TestTagArchivedActivityKeepsRowsReadable 驗收：活動進入終態後標籤行仍列、可讀，
// 玩家那一族也照樣讀得到已公開的那一枚（讀取不受生命週期門禁約束；本表沒有刪除通路）。
func TestTagArchivedActivityKeepsRowsReadable(t *testing.T) {
	e := newEnv(t)
	principal, _ := e.admin(t, "Tag.Archive")
	activity := e.create(t, principal, "會歸檔的場", "")
	tag := e.mustCreateTag(t, principal, activity.ID, "歸檔時還在的那枚")
	if _, err := e.setTagPublic(t, principal, tag, true); err != nil {
		t.Fatalf("翻公開應成功：%v", err)
	}
	player := e.plain(t, "tag.archived.player")
	if _, err := e.service.CreateMember(context.Background(), principal, activity.ID,
		player.AccountID(), "留下来的觀眾", "req-member"); err != nil {
		t.Fatalf("建立成員行應成功：%v", err)
	}

	e.transitionTo(t, principal, activity.ID, StatusArchived)
	rows, err := e.service.PublicTagCatalog(context.Background(), player, activity.ID)
	if err != nil {
		t.Fatalf("歸檔態的活動裡玩家那一族仍讀得到已公開的定義：%v", err)
	}
	if len(rows) != 1 || rows[0].TagID != tag.ID {
		t.Errorf("歸檔不刪行也不收回公開，實際 %+v", rows)
	}
	if got := e.tagFacts(t, tag.ID); got.public != 1 || got.name != tag.Name {
		t.Errorf("歸檔前後這一行的事實該一字不動，實際 %+v", got)
	}
}
