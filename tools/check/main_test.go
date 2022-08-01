package main

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
)

func TestParseInvocationDefaults(t *testing.T) {
	var stdout, stderr strings.Builder
	in, err := parseInvocation(nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("空參數應使用預設值: %v", err)
	}
	if in.scope != scopeAll {
		t.Errorf("預設範圍為 %v", in.scope)
	}
	if len(in.gates) != 0 || len(in.targets) != 0 || len(in.passthrough) != 0 {
		t.Errorf("預設清單應為空: %#v", in)
	}
	if in.runRegex != "" || in.verbose || in.repoRoot != "" || in.module != "" || in.flutter != "" || in.goExe != "" {
		t.Errorf("預設值應留空由執行期推得: %#v", in)
	}
	if stderr.Len() != 0 {
		t.Errorf("預設解析不應寫 stderr: %q", stderr.String())
	}
}

func TestParseInvocationScope(t *testing.T) {
	cases := []struct {
		args []string
		want scope
	}{
		{args: []string{"go"}, want: scopeGo},
		{args: []string{"app"}, want: scopeApp},
		{args: []string{"all"}, want: scopeAll},
		{args: []string{"GO"}, want: scopeGo},
		{args: []string{"--gate", "fmt", "go"}, want: scopeGo},
		{args: []string{"./internal/config", "--run", "TestX"}, want: scopeAll},
	}
	for _, tc := range cases {
		var stdout, stderr strings.Builder
		in, err := parseInvocation(tc.args, &stdout, &stderr)
		if err != nil {
			t.Fatalf("%v 不應失敗: %v", tc.args, err)
		}
		if in.scope != tc.want {
			t.Errorf("%v → 範圍 %v，預期 %v", tc.args, in.scope, tc.want)
		}
	}

	t.Run("首個裸字不是範圍時後續皆為位置參數", func(t *testing.T) {
		var stdout, stderr strings.Builder
		in, err := parseInvocation([]string{"./internal/httpapi", "./internal/config"}, &stdout, &stderr)
		if err != nil {
			t.Fatalf("不應失敗: %v", err)
		}
		if in.scope != scopeAll {
			t.Errorf("範圍=%v", in.scope)
		}
		if len(in.targets) != 2 {
			t.Errorf("位置參數=%v", in.targets)
		}
	})
}

// TestParseInvocationFlagsAnywhere 是這個入口存在的關鍵理由：文件裡既存的手打串把旗標
// 放在套件之後（go test ./pkg -run TestX），Go 的 flag 套件會在那裡停止解析。
func TestParseInvocationFlagsAnywhere(t *testing.T) {
	var stdout, stderr strings.Builder
	in, err := parseInvocation([]string{
		"go", "./internal/httpapi", "--run", "TestCors", "--verbose",
		"--repo-root=D:\\share\\evernightrealm", "--module", "EvernightRealmAPP",
		"--flutter", `D:\SDK\flutter\bin\flutter.bat`, "--go", `D:\SDK\go\bin\go.exe`,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("不應失敗: %v", err)
	}
	if in.scope != scopeGo {
		t.Errorf("範圍=%v", in.scope)
	}
	if len(in.targets) != 1 || in.targets[0] != "./internal/httpapi" {
		t.Errorf("位置參數=%v", in.targets)
	}
	if in.runRegex != "TestCors" || !in.verbose {
		t.Errorf("定向參數未生效: %#v", in)
	}
	if in.repoRoot == "" || in.module == "" || in.flutter == "" || in.goExe == "" {
		t.Errorf("工具鏈覆寫未生效: %#v", in)
	}
}

func TestParseInvocationEqualsForms(t *testing.T) {
	var stdout, stderr strings.Builder
	in, err := parseInvocation([]string{"go", "--run=TestA", "--gate=vet"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("不應失敗: %v", err)
	}
	if in.runRegex != "TestA" || len(in.gates) != 1 || in.gates[0] != "vet" {
		t.Errorf("等號寫法未生效: %#v", in)
	}
}

func TestParseInvocationGates(t *testing.T) {
	var stdout, stderr strings.Builder
	in, err := parseInvocation([]string{"go", "--gate", "fmt,test", "--gate", "vet", "--gate", "fmt"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("不應失敗: %v", err)
	}
	if got := strings.Join(in.gates, ","); got != "fmt,test,vet" {
		t.Errorf("閘清單=%q，預期保留首次順序且去重", got)
	}
}

func TestParseInvocationPassthrough(t *testing.T) {
	var stdout, stderr strings.Builder
	in, err := parseInvocation([]string{
		"app", "--", "--plain-name", "路由 --未知", "--gate", "analyze",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("不應失敗: %v", err)
	}
	want := []string{"--plain-name", "路由 --未知", "--gate", "analyze"}
	if strings.Join(in.passthrough, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("轉發參數被改寫: %#v", in.passthrough)
	}
	if len(in.gates) != 0 {
		t.Errorf("`-- ` 之後的 --gate 不應被本入口吃掉: %#v", in.gates)
	}
}

func TestParseInvocationRejects(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{name: "未知旗標", args: []string{"--nope"}, want: "不認識的旗標"},
		{name: "旗標缺值", args: []string{"--run"}, want: "缺少值"},
		{name: "gate 缺值", args: []string{"--gate"}, want: "缺少值"},
		{name: "未知閘名", args: []string{"go", "--gate", "fmt,lint"}, want: "lint"},
		{name: "布爾旗標帶值", args: []string{"--verbose=1"}, want: "它是開關"},
		{name: "app 範圍混用 Go 定向", args: []string{"app", "--run", "TestX"}, want: "只作用於 Go 側"},
		{name: "app 範圍混用位置參數", args: []string{"app", "./internal/config"}, want: "只作用於 Go 側"},
		{name: "go 範圍混用轉發", args: []string{"go", "--", "--plain-name", "x"}, want: "不會執行到它"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			_, err := parseInvocation(tc.args, &stdout, &stderr)
			if err == nil {
				t.Fatalf("%v 應被拒絕", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("錯誤訊息應點出 %q，實際: %v", tc.want, err)
			}
		})
	}
}

func TestTestArgsShape(t *testing.T) {
	got := strings.Join(testArgs([]string{"./internal/httpapi"}, "TestCors", true), " ")
	for _, want := range []string{"test ./internal/httpapi", "-count=1", "-run TestCors", "-v"} {
		if !strings.Contains(got, want) {
			t.Errorf("缺少 %q: %s", want, got)
		}
	}
}

func TestParseInvocationHelp(t *testing.T) {
	var stdout, stderr strings.Builder
	_, err := parseInvocation([]string{"--help"}, &stdout, &stderr)
	if !errors.Is(err, errHelp) {
		t.Fatalf("--help 應回報 errHelp，實際 %v", err)
	}
	usage := usageText()
	for _, want := range []string{"go run ./tools/check", "提交鉤子", "check.dart", "--plain-name", "go test -run"} {
		if !strings.Contains(usage, want) {
			t.Errorf("說明文字應包含 %q，實際:\n%s", want, usage)
		}
	}
}

// testShell 取各平台必然存在的殼層命令：這裡要驗的是「有輸出即未過」的判定與轉接，
// 不是某個真實工具鏈的行為。
func testShell(t *testing.T) (string, []string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		spec := os.Getenv("ComSpec")
		if spec == "" {
			spec = "cmd.exe"
		}
		return spec, []string{"/c"}
	}
	return "/bin/sh", []string{"-c"}
}

func TestRunStepJudgesFormatGateByOutput(t *testing.T) {
	shell, prefix := testShell(t)

	t.Run("有輸出即未過，且輸出仍進終端機", func(t *testing.T) {
		var stdout, stderr strings.Builder
		args := append(append([]string{}, prefix...), "echo reported-file.go")
		step := planStep{
			cmd:          devkit.Command{Desc: gateFmtDesc, Exe: shell, Args: args},
			dir:          t.TempDir(),
			failOnOutput: true,
		}
		err := runStep(context.Background(), step, &stdout, &stderr)
		if err == nil {
			t.Fatal("gofmt 風格的「列出差異但回 0」必須被判未過")
		}
		if !strings.Contains(err.Error(), "reported-file.go") {
			t.Errorf("錯誤應點出檔案，實際 %v", err)
		}
		if !strings.Contains(stdout.String(), "reported-file.go") {
			t.Errorf("清單必須原樣呈現讓人能下手，實際 %q", stdout.String())
		}
	})

	t.Run("無輸出即通過", func(t *testing.T) {
		var stdout, stderr strings.Builder
		quiet := "exit 0"
		if runtime.GOOS != "windows" {
			quiet = "true"
		}
		step := planStep{
			cmd:          devkit.Command{Desc: gateFmtDesc, Exe: shell, Args: append(append([]string{}, prefix...), quiet)},
			dir:          t.TempDir(),
			failOnOutput: true,
		}
		if err := runStep(context.Background(), step, &stdout, &stderr); err != nil {
			t.Fatalf("無差異時應通過: %v", err)
		}
	})

	t.Run("一般閘只判退出碼", func(t *testing.T) {
		var stdout, stderr strings.Builder
		args := append(append([]string{}, prefix...), "echo 有輸出但不算失敗")
		step := planStep{cmd: devkit.Command{Desc: "Go 靜態檢查", Exe: shell, Args: args}, dir: t.TempDir()}
		if err := runStep(context.Background(), step, &stdout, &stderr); err != nil {
			t.Fatalf("vet 有輸出（警告）時仍依退出碼判定: %v", err)
		}
	})

	t.Run("非零退出碼一律未過", func(t *testing.T) {
		var stdout, stderr strings.Builder
		args := append(append([]string{}, prefix...), "exit", "7")
		step := planStep{
			cmd:          devkit.Command{Desc: gateFmtDesc, Exe: shell, Args: args},
			dir:          t.TempDir(),
			failOnOutput: true,
		}
		err := runStep(context.Background(), step, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "退出碼 7") {
			t.Fatalf("應回報退出碼，實際 %v", err)
		}
	})
}
