// 受信主體與 S09 審計介面銜接的測試：主體換成 audit 的 Actor／Viewer 之後，
// 既有那套 Root／活動作用域規則必須一條不變。
//
// 這裡刻意不新增任何審計 HTTP 入口（本步的範圍也不准新增），所以「查閱規則不變」
// 是直接把換出來的 Viewer 交回 internal/audit.Authorize 與真實資料庫查詢來驗證的——
// 換了表示形式卻改了規則，是這類銜接最容易出的錯，也只有這樣才測得出來。
package identity_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/audit"
	"github.com/kagurazakayashi/EvernightRealm/internal/database"
	"github.com/kagurazakayashi/EvernightRealm/internal/database/migrate"
	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity"
	"github.com/kagurazakayashi/EvernightRealm/internal/identity/identitytest"
	"github.com/kagurazakayashi/EvernightRealm/internal/idgen"
	"github.com/kagurazakayashi/EvernightRealm/internal/timeutil"
)

// TestRootSubjectIDShape 固定 Root 保留標識的形狀要求。
//
// 它必須能被 idgen 讀回（版本 7、正規小寫），否則 Root 的審計記錄寫得進去、讀不出來，
// 那張表就出現了一類「查不到的記錄」。
func TestRootSubjectIDShape(t *testing.T) {
	id, err := identity.RootSubjectID()
	if err != nil {
		t.Fatalf("Root 保留標識解析失敗：%v", err)
	}
	if id.IsNil() {
		t.Fatal("Root 保留標識不可是零值（會落地成 NULL，被讀回時當成系統主體）")
	}
	again, err := identity.RootSubjectID()
	if err != nil || again != id {
		t.Errorf("Root 保留標識必須穩定（換 Root 憑據不應改變審計身份）：%v %v", again, err)
	}
	roundTripped, err := idgen.Parse(id.String())
	if err != nil || roundTripped != id {
		t.Errorf("標識需可原樣讀回：%v %v", roundTripped, err)
	}
	// 它不該和任何真實產生的標識相撞。
	if fresh := identitytest.NewID(t); fresh == id {
		t.Error("Root 保留標識與 idgen 產生的標識相撞")
	}
}

// TestAuditActorMapping 逐類別核對審計操作者的換算結果。
func TestAuditActorMapping(t *testing.T) {
	accountID := identitytest.NewID(t)
	rootID, err := identity.RootSubjectID()
	if err != nil {
		t.Fatalf("取得 Root 保留標識失敗：%v", err)
	}

	cases := []struct {
		name     string
		p        identity.Principal
		wantKind audit.ActorKind
		wantID   idgen.ID
		wantErr  error
	}{
		{name: "匿名", p: identitytest.Anonymous(t), wantErr: identity.ErrNotAuthenticated},
		{
			name:     "Root",
			p:        identitytest.Root(t, identity.OriginCLI),
			wantKind: audit.ActorRoot,
			wantID:   rootID,
		},
		{
			name:     "伺服器管理員帳戶",
			p:        identitytest.Account(t, accountID, identitytest.ServerAdmin()),
			wantKind: audit.ActorAdmin,
			wantID:   accountID,
		},
		{
			name:    "普通帳戶",
			p:       identitytest.Account(t, identitytest.NewID(t)),
			wantErr: identity.ErrActivityScopeUnsupported,
		},
		{
			name:    "訪客帳戶",
			p:       identitytest.Account(t, identitytest.NewID(t), identitytest.WithGuestType()),
			wantErr: identity.ErrActivityScopeUnsupported,
		},
		{
			name:     "系統主體（啟動）",
			p:        identitytest.System(t, identity.OriginStartup),
			wantKind: audit.ActorSystem,
			wantID:   idgen.Nil,
		},
		{
			name:     "系統主體（背景）",
			p:        identitytest.System(t, identity.OriginBackground),
			wantKind: audit.ActorSystem,
			wantID:   idgen.Nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actor, err := tc.p.AuditActor()
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("應為 %v，實際 %v", tc.wantErr, err)
				}
				if actor.Kind != "" {
					t.Errorf("換算失敗時不可給出半個操作者：%+v", actor)
				}
				return
			}
			if err != nil {
				t.Fatalf("換算失敗：%v", err)
			}
			if actor.Kind != tc.wantKind {
				t.Errorf("主體類別為 %s，期待 %s", actor.Kind, string(tc.wantKind))
			}
			if actor.ID != tc.wantID {
				t.Errorf("actor.id 為 %s，期待 %s", actor.ID, tc.wantID)
			}
		})
	}
}

// TestAuditActorWritesToS09 確認換算結果能被既有審計寫入接口接受（不降級、不改規則）。
func TestAuditActorWritesToS09(t *testing.T) {
	db := newAuditDB(t)
	store := audit.NewStore(timeutil.System())
	activityID := identitytest.NewID(t)

	t.Run("root_principal_writes_root_scope", func(t *testing.T) {
		actor, err := identitytest.Root(t, identity.OriginHTTPRequest).AuditActor()
		if err != nil {
			t.Fatalf("換算失敗：%v", err)
		}
		id, err := store.Append(context.Background(), db.SQL(), audit.Record{
			Scope:  audit.ScopeRoot,
			Actor:  actor,
			Action: "server.settings.update",
			Target: audit.Target{Kind: "server_settings"},
		})
		if err != nil {
			t.Fatalf("Root 主體的審計寫入失敗：%v", err)
		}
		if id.IsNil() {
			t.Error("寫入後應回記錄標識")
		}
	})

	t.Run("cli_system_principal_writes_root_scope", func(t *testing.T) {
		actor, err := identitytest.System(t, identity.OriginCLI).AuditActor()
		if err != nil {
			t.Fatalf("換算失敗：%v", err)
		}
		if _, err := store.Append(context.Background(), db.SQL(), audit.Record{
			Scope:  audit.ScopeRoot,
			Actor:  actor,
			Action: "server.restore",
			Target: audit.Target{Kind: "server"},
		}); err != nil {
			t.Fatalf("CLI 系統主體的審計寫入失敗：%v", err)
		}
	})

	t.Run("server_admin_writes_activity_scope", func(t *testing.T) {
		actor, err := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin()).AuditActor()
		if err != nil {
			t.Fatalf("換算失敗：%v", err)
		}
		if _, err := store.Append(context.Background(), db.SQL(), audit.Record{
			Scope:      audit.ScopeActivity,
			ActivityID: activityID,
			Actor:      actor,
			Action:     "phase.change",
			Target:     audit.Target{Kind: "phase"},
			Reason:     "測試：驗證受信主體可寫活動域審計",
		}); err != nil {
			t.Fatalf("管理員主體的活動域審計寫入失敗：%v", err)
		}
	})

	t.Run("plain_account_cannot_write", func(t *testing.T) {
		// 普通帳戶連操作者都換不出來，因此不可能留下一筆「查不到是誰」的記錄。
		if _, err := identitytest.Account(t, identitytest.NewID(t)).AuditActor(); err == nil {
			t.Fatal("普通帳戶不應能換算出審計操作者")
		}
	})
}

// TestAuditViewerKeepsExistingRules 把換算出的 Viewer 交回 internal/audit 的判定，
// 核對 Root／活動作用域規則一絲未動。
func TestAuditViewerKeepsExistingRules(t *testing.T) {
	ownActivity := identitytest.NewID(t)
	otherActivity := identitytest.NewID(t)

	admin := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin())
	viewer, err := admin.AuditViewer(identitytest.Grants(t, ownActivity))
	if err != nil {
		t.Fatalf("管理員閱覽身分換算失敗：%v", err)
	}
	if viewer.Kind != audit.ActorAdmin {
		t.Errorf("閱覽身分類別為 %s", string(viewer.Kind))
	}
	cases := []struct {
		name     string
		scope    audit.Scope
		activity idgen.ID
		want     error
	}{
		{"own_activity_allowed", audit.ScopeActivity, ownActivity, nil},
		{"other_activity_denied", audit.ScopeActivity, otherActivity, audit.ErrDenied},
		{"root_scope_denied_for_admin", audit.ScopeRoot, idgen.Nil, audit.ErrDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := audit.Authorize(viewer, tc.scope, tc.activity)
			if tc.want == nil && err != nil {
				t.Errorf("應放行，實際 %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("應為 %v，實際 %v", tc.want, err)
			}
		})
	}

	// Root 的閱覽不受活動清單制約，且兩域都可讀。
	rootViewer, err := identitytest.Root(t, identity.OriginHTTPRequest).AuditViewer(identitytest.Grants(t))
	if err != nil {
		t.Fatalf("Root 閱覽身分換算失敗：%v", err)
	}
	if len(rootViewer.Activities) != 0 {
		t.Error("Root 的讀取範圍不由清單決定")
	}
	if err := audit.Authorize(rootViewer, audit.ScopeRoot, idgen.Nil); err != nil {
		t.Errorf("Root 應可讀 Root 域：%v", err)
	}
	if err := audit.Authorize(rootViewer, audit.ScopeActivity, ownActivity); err != nil {
		t.Errorf("Root 應可讀活動域：%v", err)
	}

	// 系統主體不是一種閱覽身分：沿用既有規則，兩域都拒。
	sysViewer, err := identitytest.System(t, identity.OriginBackground).AuditViewer(identitytest.Grants(t))
	if err != nil {
		t.Fatalf("系統主體閱覽身分換算失敗：%v", err)
	}
	if err := audit.Authorize(sysViewer, audit.ScopeRoot, idgen.Nil); !errors.Is(err, audit.ErrDenied) {
		t.Errorf("system 不可讀 Root 域，實際 %v", err)
	}

	// 普通帳戶與匿名不該拿到閱覽身分，而不是拿到一個「會被拒的 Viewer」。
	if _, err := identitytest.Account(t, identitytest.NewID(t)).AuditViewer(identitytest.Grants(t, ownActivity)); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Errorf("普通帳戶不應換算出閱覽身分，實際 %v", err)
	}
	if _, err := identitytest.Anonymous(t).AuditViewer(identitytest.Grants(t)); !errors.Is(err, identity.ErrNotAuthenticated) {
		t.Errorf("匿名不應換算出閱覽身分，實際 %v", err)
	}
}

// TestActivityGrantsValidation 固定活動授權清單的輸入校驗。
func TestActivityGrantsValidation(t *testing.T) {
	own := identitytest.NewID(t)
	if g, err := identity.NewActivityGrants(); err != nil || len(g.IDs()) != 0 {
		t.Errorf("空清單應合法且語意為「哪個活動都不能看」：%v %v", g.IDs(), err)
	}
	if _, err := identity.NewActivityGrants(idgen.Nil); !errors.Is(err, identity.ErrInvalidPrincipal) {
		t.Errorf("零值活動標識應被拒，實際 %v", err)
	}
	if _, err := identity.NewActivityGrants(own, own); !errors.Is(err, identity.ErrInvalidPrincipal) {
		t.Errorf("重複活動標識應被拒，實際 %v", err)
	}
	g := identitytest.Grants(t, own, identitytest.NewID(t))
	ids := g.IDs()
	if len(ids) != 2 {
		t.Fatalf("應有兩項，實際 %d", len(ids))
	}
	ids[0] = identitytest.NewID(t)
	if g.IDs()[0] != own {
		t.Error("IDs 回傳的是內部切片而不是副本")
	}
}

// TestAuditViewerRoundTripsThroughStore 用真實資料庫走一次「寫入→按閱覽身分查回」，
// 證明換算出的 actor.id 可被讀回（Root 保留標識的形狀要求在這裡落地）。
func TestAuditViewerRoundTripsThroughStore(t *testing.T) {
	db := newAuditDB(t)
	store := audit.NewStore(timeutil.System())
	root := identitytest.Root(t, identity.OriginCLI)

	actor, err := root.AuditActor()
	if err != nil {
		t.Fatalf("換算失敗：%v", err)
	}
	if _, err := store.Append(context.Background(), db.SQL(), audit.Record{
		Scope: audit.ScopeRoot, Actor: actor, Action: "server.shutdown",
		Target: audit.Target{Kind: "server"},
	}); err != nil {
		t.Fatalf("寫入失敗：%v", err)
	}

	viewer, err := root.AuditViewer(identitytest.Grants(t))
	if err != nil {
		t.Fatalf("閱覽身分換算失敗：%v", err)
	}
	page, err := store.Query(context.Background(), db.SQL(), viewer,
		audit.Filter{Scope: audit.ScopeRoot, Action: "server.shutdown", Limit: 10})
	if err != nil {
		t.Fatalf("查詢失敗：%v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("應查得一筆，實際 %d", len(page.Records))
	}
	rootID, err := identity.RootSubjectID()
	if err != nil {
		t.Fatalf("取得 Root 保留標識失敗：%v", err)
	}
	got := page.Records[0]
	if got.Actor.Kind != audit.ActorRoot || got.Actor.ID != rootID {
		t.Errorf("讀回的主體不正確：%+v", got.Actor)
	}

	// 管理員拿不到 Root 域：既有規則在存取層同樣生效。
	adminViewer, err := identitytest.Account(t, identitytest.NewID(t), identitytest.ServerAdmin()).AuditViewer(identitytest.Grants(t, identitytest.NewID(t)))
	if err != nil {
		t.Fatalf("管理員閱覽身分換算失敗：%v", err)
	}
	if _, err := store.Query(context.Background(), db.SQL(), adminViewer,
		audit.Filter{Scope: audit.ScopeRoot}); !errors.Is(err, audit.ErrDenied) {
		t.Errorf("管理員查 Root 域應被拒，實際 %v", err)
	}
}

// newAuditDB 開啟一支本次測試專屬的暫存資料庫並套用內嵌遷移。
//
// 與 internal/audit 同名輔助同取向：Windows 上 SQLite 句柄釋放有落後，
// 暫存目錄走有限次數重試刪除，不留殘檔也不動真實資料目錄。
func newAuditDB(t *testing.T) *database.DB {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() {
		if err := devkit.RemoveAllWithRetry(dir); err != nil {
			t.Errorf("暫存目錄清理失敗（殘留：%s）：%v", dir, err)
		}
	})
	db, err := database.Open(context.Background(), database.Options{
		Path:        filepath.Join(dir, "evernight.db"),
		BusyTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗：%v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrate.Apply(context.Background(), db.SQL(), migrate.Options{Clock: timeutil.System()}); err != nil {
		t.Fatalf("套用遷移失敗：%v", err)
	}
	return db
}
