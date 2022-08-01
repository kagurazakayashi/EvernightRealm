package webassets

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kagurazakayashi/EvernightRealm/internal/webassets/bundle"
)

// bundleSource 組出一份含 dist 子目錄的檔案樹，讓判定可在不動到實際內嵌內容的情況下重現。
//
// missing 為要拿掉的必要檔案（斜線寫法，不含 dist 前綴）；留空即為一份完整產物。
func bundleSource(missing string) fstest.MapFS {
	fsys := fstest.MapFS{distDir + "/" + bundle.PlaceholderName: &fstest.MapFile{Data: []byte(bundle.PlaceholderNote)}}
	for _, rel := range bundle.Required() {
		if rel == missing {
			continue
		}
		data := []byte("x")
		if rel == bundle.BootstrapFile {
			data = []byte("const e={" + bundle.LocalCanvasKitMarker + "};")
		}
		fsys[distDir+"/"+rel] = &fstest.MapFile{Data: data}
	}
	return fsys
}

func TestInspectAcceptsCompleteBundle(t *testing.T) {
	fsys, status := inspect(bundleSource(""))
	if !status.Available {
		t.Fatalf("完整產物應判定可用，實際原因：%s", status.Reason)
	}
	if fsys == nil {
		t.Fatal("可用時必須回傳檔案系統")
	}
	if status.Reason != "" {
		t.Errorf("可用時不應帶原因: %q", status.Reason)
	}
	if status.Files < len(bundle.Required()) {
		t.Errorf("檔案數 %d 少於必要清單 %d", status.Files, len(bundle.Required()))
	}
	if summary := status.Summary(); !strings.Contains(summary, "已內嵌") {
		t.Errorf("摘要應寫出已內嵌，實際 %q", summary)
	}
}

func TestInspectReportsPlaceholderOnly(t *testing.T) {
	// 這是一份剛複製下來、還沒跑過前端建置的倉庫：能編譯，但不能假裝有網頁介面。
	source := fstest.MapFS{distDir + "/" + bundle.PlaceholderName: &fstest.MapFile{Data: []byte(bundle.PlaceholderNote)}}

	fsys, status := inspect(source)
	if status.Available || fsys != nil {
		t.Fatalf("只有佔位檔時不應判定可用: %v / %v", fsys, status)
	}
	if !strings.Contains(status.Reason, bundle.Required()[0]) {
		t.Errorf("原因應點出缺少的檔案，實際 %q", status.Reason)
	}
	summary := status.Summary()
	for _, want := range []string{"未內嵌", "go run ./tools/buildweb"} {
		if !strings.Contains(summary, want) {
			t.Errorf("摘要應含 %q，實際 %q", want, summary)
		}
	}
}

func TestInspectRejectsCDNCanvasKit(t *testing.T) {
	source := bundleSource("")
	source[distDir+"/"+bundle.BootstrapFile] = &fstest.MapFile{Data: []byte(`{"useLocalCanvasKit":false}`)}

	_, status := inspect(source)
	if status.Available {
		t.Fatal("會向 CDN 取引擎的產物不應判定可用")
	}
	if !strings.Contains(status.Reason, "CanvasKit") {
		t.Errorf("原因應說明 CanvasKit 來源問題，實際 %q", status.Reason)
	}
}

func TestInspectWithoutDistDirectory(t *testing.T) {
	// 內嵌樣式被改壞成沒有 dist 時，仍要回「不可用 + 原因」而不是 panic。
	_, status := inspect(fstest.MapFS{"other/main.dart.js": &fstest.MapFile{Data: []byte("x")}})
	if status.Available {
		t.Fatal("沒有產物目錄時不應判定可用")
	}
	if status.Reason == "" {
		t.Error("不可用時必須給出原因")
	}
}

func TestDistReflectsEmbeddedArtifacts(t *testing.T) {
	// 這條鎖定「實際內嵌了什麼」：結果取決於工作樹裡的 dist，兩種狀態都合法，但必須自洽。
	fsys, status := Dist()
	switch {
	case status.Available:
		if fsys == nil {
			t.Fatal("判定可用卻沒有檔案系統")
		}
		if _, err := fs.Stat(fsys, bundle.Required()[0]); err != nil {
			t.Errorf("判定可用卻讀不到 %s: %v", bundle.Required()[0], err)
		}
		if status.Files < len(bundle.Required()) {
			t.Errorf("內嵌檔案數 %d 少於必要清單 %d", status.Files, len(bundle.Required()))
		}
		if !strings.Contains(status.Summary(), "已內嵌") {
			t.Errorf("摘要與狀態不一致: %q", status.Summary())
		}
	default:
		if fsys != nil {
			t.Fatal("判定不可用時不應回傳檔案系統")
		}
		if status.Reason == "" {
			t.Fatal("不可用時必須寫出原因")
		}
		if !strings.Contains(status.Summary(), "未內嵌") {
			t.Errorf("摘要與狀態不一致: %q", status.Summary())
		}
	}
}

func TestDistIsStableAcrossCalls(t *testing.T) {
	firstFS, first := Dist()
	secondFS, second := Dist()
	if first != second {
		t.Errorf("同一執行檔的判定結果不該隨呼叫次數改變: %+v vs %+v", first, second)
	}
	if (firstFS == nil) != (secondFS == nil) {
		t.Error("檔案系統的回傳與否應與判定一致")
	}
}
