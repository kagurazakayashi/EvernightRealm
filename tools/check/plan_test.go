package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
)

// fakeModule 建立一個含 go.mod 的最小目錄，當作 Go 側倉庫根的假目標。
func fakeModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeExec(t, dir, "go.mod", "module example.com/x\n")
	return dir
}

func TestMakePlanGoScope(t *testing.T) {
	root := fakeModule(t)

	in := invocation{
		scope:    scopeGo,
		repoRoot: root,
		goExe:    fakeToolchain(t, true),
		gates:    []string{gateVet},
		stdout:   &strings.Builder{},
		stderr:   &strings.Builder{},
	}
	steps, summary, err := makePlan(in)
	if err != nil {
		t.Fatalf("不應失敗: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("--gate vet 應只留一道，得到 %d", len(steps))
	}
	if filepath.Clean(steps[0].dir) != filepath.Clean(root) {
		t.Errorf("命令工作目錄=%q，預期 %q", steps[0].dir, root)
	}
	if got := strings.Join(steps[0].cmd.Args, " "); got != "vet ./..." {
		t.Errorf("引數=%q", got)
	}

	joined := strings.Join(summary, "\n")
	for _, want := range []string{"範圍：go", "後端", "Go 靜態檢查"} {
		if !strings.Contains(joined, want) {
			t.Errorf("摘要應包含 %q，實際:\n%s", want, joined)
		}
	}
}

func TestMakePlanReportsMissingGoMod(t *testing.T) {
	in := invocation{scope: scopeGo, repoRoot: t.TempDir(), stdout: &strings.Builder{}, stderr: &strings.Builder{}}
	_, _, err := makePlan(in)
	if err == nil || !strings.Contains(err.Error(), devkit.GoModuleFile) {
		t.Fatalf("找不到 go.mod 時應點出憑證檔名，實際 %v", err)
	}
}

// fakeFrontendTree 建立一棵「已檢出、已 pub get、已含品質入口」的假前端，
// 讓 makePlan 的前端側路徑完全不依賴本機工具鏈。
func fakeFrontendTree(t *testing.T) (root, appDir, flutterExe string) {
	t.Helper()
	root = t.TempDir()
	writeExec(t, root, devkit.GitmodulesFile, `[submodule "EvernightRealmAPP"]`+"\n\tpath = EvernightRealmAPP\n")

	appDir = filepath.Join(root, "EvernightRealmAPP")
	writeExec(t, appDir, devkit.PubspecFile, "name: evernightrealm\n")
	writeExec(t, appDir, filepath.Join("tools", "check", "check.dart"), "void main() {}\n")
	writeExec(t, appDir, filepath.Join(".dart_tool", "package_config.json"), "{}\n")

	flutterExe = writeExec(t, root, "flutter.exe", "")
	writeExec(t, root, "dart.exe", "")
	return root, appDir, flutterExe
}

func TestMakePlanAppScopeCallsFrontendEntry(t *testing.T) {
	root, appDir, flutterExe := fakeFrontendTree(t)

	in := invocation{
		scope:       scopeApp,
		repoRoot:    root,
		flutter:     flutterExe,
		passthrough: []string{"--plain-name", "路由"},
		stdout:      &strings.Builder{},
		stderr:      &strings.Builder{},
	}
	steps, summary, err := makePlan(in)
	if err != nil {
		t.Fatalf("不應失敗: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("前端側應只有一道（由前端入口自己分閘），得到 %d", len(steps))
	}
	step := steps[0]
	if filepath.Clean(step.dir) != filepath.Clean(appDir) {
		t.Errorf("工作目錄=%q，預期 %q", step.dir, appDir)
	}
	if filepath.Base(step.cmd.Exe) != "dart.exe" {
		t.Errorf("應由同套工具鏈的 dart 叫起，得到 %q", step.cmd.Exe)
	}
	wantArgs := "run " + devkit.FrontendCheckEntryRel + " --flutter " + flutterExe + " --plain-name 路由"
	if got := strings.Join(step.cmd.Args, " "); got != wantArgs {
		t.Errorf("引數=%q，預期 %q", got, wantArgs)
	}
	if step.hint != "" {
		t.Errorf("前端側的修正提示由它自己給，根側不應加: %q", step.hint)
	}
	joined := strings.Join(summary, "\n")
	for _, want := range []string{"範圍：app", "EvernightRealmAPP", "轉發 2 筆參數"} {
		if !strings.Contains(joined, want) {
			t.Errorf("摘要應包含 %q，實際:\n%s", want, joined)
		}
	}
}

func TestMakePlanAppScopeReportsMissingEntry(t *testing.T) {
	root, appDir, flutterExe := fakeFrontendTree(t)
	if err := os.Remove(filepath.Join(appDir, "tools", "check", "check.dart")); err != nil {
		t.Fatalf("移除入口失敗: %v", err)
	}

	in := invocation{scope: scopeApp, repoRoot: root, flutter: flutterExe, stdout: &strings.Builder{}, stderr: &strings.Builder{}}
	_, _, err := makePlan(in)
	if !errors.Is(err, devkit.ErrSubmoduleMissing) {
		t.Fatalf("前端尚未有品質入口時應如實回報子模組未就緒，實際 %v", err)
	}
}

func TestMakePlanAllScopeRunsBackendThenFrontend(t *testing.T) {
	root, appDir, flutterExe := fakeFrontendTree(t)
	// 假前端的倉庫根同時要有 go.mod，否則 all 範圍下後端側定位會先失敗。
	writeExec(t, root, devkit.GoModuleFile, "module example.com/x\n")

	in := invocation{
		scope:    scopeAll,
		repoRoot: root,
		flutter:  flutterExe,
		goExe:    fakeToolchain(t, true),
		gates:    []string{gateVet},
		stdout:   &strings.Builder{},
		stderr:   &strings.Builder{},
	}
	steps, _, err := makePlan(in)
	if err != nil {
		t.Fatalf("不應失敗: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("應為後端一道＋前端一道，得到 %d", len(steps))
	}
	if filepath.Clean(steps[0].dir) == filepath.Clean(appDir) {
		t.Error("順序應是先後端再前端")
	}
	if filepath.Clean(steps[1].dir) != filepath.Clean(appDir) {
		t.Errorf("第二道應在前端目錄，得到 %q", steps[1].dir)
	}
}

func TestCommandLineIsCopyable(t *testing.T) {
	cmd := devkit.Command{Desc: "Go 測試", Exe: `D:\SDK\go\bin\go.exe`, Args: []string{"test", "./...", "-count=1"}}
	got := commandLine(cmd)
	if got != `go.exe test ./... -count=1` {
		t.Errorf("得到 %q", got)
	}
	if strings.Contains(got, `D:\`) {
		t.Error("進度列不應被絕對路徑撐開")
	}
}
