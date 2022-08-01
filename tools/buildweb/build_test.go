package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
	"github.com/kagurazakayashi/EvernightRealm/internal/webassets/bundle"
)

func TestBuildArgs(t *testing.T) {
	const out = `D:\repo\internal\webassets\dist`

	t.Run("預設為 release 且一律關閉線上 CDN 資源", func(t *testing.T) {
		got := buildArgs(out, options{})
		joined := strings.Join(got, " ")
		if !strings.HasPrefix(joined, "build web --release "+noWebResourcesCDN) {
			t.Fatalf("參數順序不符預期: %s", joined)
		}
		if !strings.Contains(joined, "-o "+out) {
			t.Errorf("未帶輸出目錄: %s", joined)
		}
	})

	t.Run("debug 只換模式不換其他參數", func(t *testing.T) {
		got := strings.Join(buildArgs(out, options{debug: true}), " ")
		if !strings.Contains(got, " --debug ") || strings.Contains(got, "--release") {
			t.Errorf("debug 建置參數錯誤: %s", got)
		}
		if !strings.Contains(got, noWebResourcesCDN) {
			t.Errorf("debug 建置也要關閉 CDN 資源: %s", got)
		}
	})

	t.Run("額外編譯期參數逐筆附帶", func(t *testing.T) {
		o := options{defines: stringList{
			"ER_SERVER_BASE_URL=http://127.0.0.1:5299",
			"ER_BUILD_VERSION=0.1.0-dev",
		}}
		got := buildArgs(out, o)
		want := []string{"--dart-define=ER_SERVER_BASE_URL=http://127.0.0.1:5299", "--dart-define=ER_BUILD_VERSION=0.1.0-dev"}
		if len(got) < len(want) {
			t.Fatalf("參數太少: %v", got)
		}
		tail := strings.Join(got[len(got)-len(want):], " ")
		if tail != strings.Join(want, " ") {
			t.Errorf("尾端參數為 %q，預期 %q", tail, strings.Join(want, " "))
		}
	})

	t.Run("建置引數不含任何 git 命令", func(t *testing.T) {
		for _, arg := range buildArgs(out, options{defines: stringList{"A=B"}}) {
			if arg == "git" || strings.Contains(arg, "submodule") {
				t.Errorf("建置工具不得執行 git 操作，卻出現引數 %q", arg)
			}
		}
	})
}

func TestBuildCommandUsesFrontendToolchain(t *testing.T) {
	app := devkit.Frontend{Dir: `D:\repo\EvernightRealmAPP`, FlutterExe: `D:\SDK\flutter\bin\flutter.bat`}
	cmd := buildCommand(app, `D:\repo\internal\webassets\dist`, options{})

	if cmd.Exe != app.FlutterExe {
		t.Errorf("應使用解析出的 flutter，得到 %q", cmd.Exe)
	}
	if strings.Contains(cmd.Desc, "--") {
		t.Errorf("desc 不應出現引數: %q", cmd.Desc)
	}
}

func TestCleanOutput(t *testing.T) {
	t.Run("目錄不存在時建立目錄與佔位檔", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "nope")
		var stdout strings.Builder
		if err := cleanOutput(out, &stdout); err != nil {
			t.Fatalf("不應失敗: %v", err)
		}
		if !devkit.FileExists(filepath.Join(out, bundle.PlaceholderName)) {
			t.Error("空目錄會讓 go:embed 直接編譯失敗，必須留下佔位檔讓後端仍可建置")
		}
	})

	t.Run("清空既有產物", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "dist")
		writeFile(t, out, "main.dart.js", "舊產物")
		var stdout strings.Builder
		if err := cleanOutput(out, &stdout); err != nil {
			t.Fatalf("不應失敗: %v", err)
		}
		// 舊產物必須消失（否則會被一起內嵌進發布檔），但佔位檔要留下：
		// 清空之後若建置失敗，空目錄會讓整個後端連編譯都過不了，而錯誤訊息指不到是前端沒建置。
		if _, err := os.Stat(filepath.Join(out, "main.dart.js")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("舊產物應已被移除，實際 err=%v", err)
		}
		entries, err := os.ReadDir(out)
		if err != nil {
			t.Fatalf("產物目錄應仍存在: %v", err)
		}
		if len(entries) != 1 || entries[0].Name() != bundle.PlaceholderName {
			names := make([]string, 0, len(entries))
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
			t.Errorf("清空後只該剩佔位檔，實際 %v", names)
		}
		if !strings.Contains(stdout.String(), "已清空") {
			t.Errorf("應留下清空紀錄: %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), bundle.PlaceholderName) {
			t.Errorf("應說明補回了佔位檔: %q", stdout.String())
		}
	})

	t.Run("目標是檔案時拒絕", func(t *testing.T) {
		dir := t.TempDir()
		path := writeFile(t, dir, "dist", "這不是一個目錄")
		if err := cleanOutput(path, &strings.Builder{}); err == nil {
			t.Fatal("產物路徑為檔案時應拒絕，避免拿刪除目錄的邏輯去動檔案")
		}
		if !devkit.FileExists(path) {
			t.Error("拒絕時不得順手刪掉該檔案")
		}
	})
}
