package audit

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
)

// rootViewer 是測試用的 Root 閱覽身分：兩域皆可讀，用於驗證與授權無關的查詢行為本身。
func rootViewer() Viewer { return Viewer{Kind: ActorRoot} }

// adminViewer 是測試用的管理員閱覽身分，只獲准讀入參給出的活動。
func adminViewer(activities ...idgen.ID) Viewer {
	return Viewer{Kind: ActorAdmin, Activities: activities}
}

// countingQuerier 記錄實際發出的 SELECT 次數，其餘方法交給被包裝的真實連線。
//
// 「拒絕存取」最強的證據不是回傳了錯誤，而是一條 SQL 都沒發出去：那樣就排除了
// 「先查出來再挑掉不該看的」這種把整個結果集交出去的做法。
type countingQuerier struct {
	database.Querier
	selects int
}

// QueryContext 計數後轉給真實連線。
func (c *countingQuerier) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	c.selects++
	return c.Querier.QueryContext(ctx, query, args...)
}

func TestAuthorizeAdmitsByKindAndScope(t *testing.T) {
	mine := mustID(t0)
	theirs := mustID(t3)

	cases := []struct {
		name       string
		viewer     Viewer
		scope      Scope
		activityID idgen.ID
		wantErr    error
	}{
		{"Root 讀 Root 域", rootViewer(), ScopeRoot, idgen.Nil, nil},
		{"Root 讀任一活動", rootViewer(), ScopeActivity, theirs, nil},
		{"管理員讀獲准的活動", adminViewer(mine), ScopeActivity, mine, nil},
		{"管理員讀未獲准的活動", adminViewer(mine), ScopeActivity, theirs, ErrDenied},
		{"管理員讀 Root 域", adminViewer(mine), ScopeRoot, idgen.Nil, ErrDenied},
		{"管理員沒有任何活動時讀該活動", adminViewer(), ScopeActivity, mine, ErrDenied},
		{"玩家讀活動域", Viewer{Kind: ActorPlayer}, ScopeActivity, mine, ErrDenied},
		{"玩家讀 Root 域", Viewer{Kind: ActorPlayer}, ScopeRoot, idgen.Nil, ErrDenied},
		{"NPC 讀活動域", Viewer{Kind: ActorNPC}, ScopeActivity, mine, ErrDenied},
		{"NPC 讀 Root 域", Viewer{Kind: ActorNPC}, ScopeRoot, idgen.Nil, ErrDenied},
		{"系統主體不是閱覽身分", Viewer{Kind: ActorSystem}, ScopeRoot, idgen.Nil, ErrDenied},
		// 未帶 activity_id 與錯帶 activity_id 是「呼叫端寫錯」，不能和「沒權限」混為一談：
		// 混了之後一個漏帶過濾的查詢會被回報成權限問題，真正的缺陷就此藏起來。
		{"活動域缺 activity_id", rootViewer(), ScopeActivity, idgen.Nil, ErrIncompleteScope},
		{"Root 域多帶 activity_id", rootViewer(), ScopeRoot, mine, ErrIncompleteScope},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Authorize(tc.viewer, tc.scope, tc.activityID)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("不應拒絕，實際 %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("錯誤類別不符：want %v，實際 %v", tc.wantErr, err)
			}
		})
	}

	// 未知作用域不是授權問題，所以不進上面那張表：它要沿用 table() 原本那條錯誤，
	// 既不報成「沒權限」也不報成「條件不合法」，否則一個打錯的作用域會偽裝成越權嘗試。
	if err := Authorize(rootViewer(), Scope("session"), idgen.Nil); err == nil {
		t.Fatal("未知作用域應被拒絕")
	} else if errors.Is(err, ErrDenied) || errors.Is(err, ErrIncompleteScope) {
		t.Errorf("未知作用域不應報成授權問題：%v", err)
	}
}

func TestAuthorizeRejectsInconsistentViewer(t *testing.T) {
	mine := mustID(t0)

	cases := []struct {
		name   string
		viewer Viewer
	}{
		{"未設定身分（零值）", Viewer{}},
		{"未知主體類別", Viewer{Kind: ActorKind("hacker")}},
		{"Root 不該帶活動清單", Viewer{Kind: ActorRoot, Activities: []idgen.ID{mine}}},
		{"玩家不該帶活動清單", Viewer{Kind: ActorPlayer, Activities: []idgen.ID{mine}}},
		{"活動清單裡混入零值標識", adminViewer(mine, idgen.Nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Authorize(tc.viewer, ScopeActivity, mine); !errors.Is(err, ErrInvalidViewer) {
				t.Errorf("應回 ErrInvalidViewer，實際 %v", err)
			}
		})
	}
}

// TestQueryRefusesCrossScopeReads 是作用域隔離的驗收場景：兩類查詢都無法越過授權讀到彼此。
func TestQueryRefusesCrossScopeReads(t *testing.T) {
	store, db, _ := newTestStore(t)
	ctx := context.Background()

	mine := mustID(t0)
	theirs := mustID(t3)

	rootRec := Record{Scope: ScopeRoot, Actor: Actor{Kind: ActorRoot, ID: mustID(t1)},
		Action: "admin.create", Target: Target{Kind: "admin", ID: mustID(t2).String()}}
	activityRec := validActivityRecord()
	otherRec := validActivityRecord()
	otherRec.ActivityID = theirs
	otherRec.Target = Target{Kind: "player", ID: theirs.String()}

	for _, rec := range []Record{rootRec, activityRec, otherRec} {
		if _, err := store.Append(ctx, db.SQL(), rec); err != nil {
			t.Fatalf("植入測試記錄失敗：%v", err)
		}
	}

	// 獲准的那一頁讀得到，證明拒絕不是「一律回空」造成的假象。
	granted, err := store.Query(ctx, db.SQL(), adminViewer(mine), Filter{Scope: ScopeActivity, ActivityID: mine})
	if err != nil {
		t.Fatal(err)
	}
	if len(granted.Records) != 1 {
		t.Fatalf("管理員讀獲准活動應取得 1 筆，實際 %d 筆", len(granted.Records))
	}

	denied := []struct {
		name   string
		viewer Viewer
		filter Filter
	}{
		{"管理員讀別的活動", adminViewer(mine), Filter{Scope: ScopeActivity, ActivityID: theirs}},
		{"管理員讀 Root 審計", adminViewer(mine, theirs), Filter{Scope: ScopeRoot}},
		{"玩家讀自己所在的活動", Viewer{Kind: ActorPlayer}, Filter{Scope: ScopeActivity, ActivityID: mine}},
		{"玩家讀 Root 審計", Viewer{Kind: ActorPlayer}, Filter{Scope: ScopeRoot}},
		{"NPC 讀活動審計", Viewer{Kind: ActorNPC}, Filter{Scope: ScopeActivity, ActivityID: mine}},
		{"系統讀 Root 審計", Viewer{Kind: ActorSystem}, Filter{Scope: ScopeRoot}},
		{"忘了帶身分", Viewer{}, Filter{Scope: ScopeRoot}},
	}
	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			counter := &countingQuerier{Querier: db.SQL()}
			page, err := store.Query(ctx, counter, tc.viewer, tc.filter)
			if err == nil {
				t.Fatalf("不應放行，還讀到 %d 筆", len(page.Records))
			}
			if len(page.Records) != 0 {
				t.Errorf("拒絕時仍交出了記錄：%+v", page.Records)
			}
			if counter.selects != 0 {
				t.Errorf("授權判定未先於 SQL：發出了 %d 條查詢", counter.selects)
			}
			if !errors.Is(err, ErrDenied) && !errors.Is(err, ErrInvalidViewer) {
				t.Errorf("錯誤類別不符：%v", err)
			}
		})
	}

	// Root 兩域皆可讀，且這是它專屬的能力：同一份記錄換個身分就讀不到。
	for _, filter := range []Filter{{Scope: ScopeRoot}, {Scope: ScopeActivity, ActivityID: theirs}} {
		page, err := store.Query(ctx, db.SQL(), rootViewer(), filter)
		if err != nil {
			t.Fatalf("Root 讀 %v 失敗：%v", filter.Scope, err)
		}
		if len(page.Records) != 1 {
			t.Errorf("Root 讀 %v 應取得 1 筆，實際 %d 筆", filter.Scope, len(page.Records))
		}
	}
}
