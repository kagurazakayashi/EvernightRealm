package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
)

func TestParseOptionsDefaults(t *testing.T) {
	var stdout, stderr strings.Builder
	opts, err := parseOptions(nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("空參數應使用預設值: %v", err)
	}
	if opts.output != defaultOutputRel {
		t.Errorf("預設產物目錄為 %q", opts.output)
	}
	if opts.repoRoot != "" || opts.module != "" || opts.flutter != "" {
		t.Errorf("預設值應留空由執行期推得: %#v", opts)
	}
	if opts.debug || opts.check || opts.skipClean {
		t.Errorf("旗標預設全為閉: %#v", opts)
	}
	if stderr.Len() != 0 {
		t.Errorf("預設解析不應寫 stderr: %q", stderr.String())
	}
}

func TestParseOptionsFlags(t *testing.T) {
	var stdout, stderr strings.Builder
	opts, err := parseOptions([]string{
		"--repo-root", `D:\share\evernightrealm`,
		"--module", "EvernightRealmAPP",
		"--output", "tmp-dist",
		"--flutter", `D:\SDK\flutter\bin\flutter.bat`,
		"--dart-define", "ER_SERVER_BASE_URL=http://127.0.0.1:5299",
		"--dart-define", "ER_BUILD_VERSION=0.1.0-dev",
		"--debug",
		"--check",
		"--skip-clean",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("解析失敗: %v", err)
	}
	if len(opts.defines) != 2 {
		t.Fatalf("--dart-define 重複給值未累計: %v", opts.defines)
	}
	if !opts.debug || !opts.check || !opts.skipClean {
		t.Errorf("旗標未生效: %#v", opts)
	}
	if opts.output != "tmp-dist" {
		t.Errorf("output=%q", opts.output)
	}
}

func TestParseOptionsRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "未知旗標", args: []string{"--nope"}},
		{name: "多餘位置參數", args: []string{"build"}},
		{name: "define 缺少等號", args: []string{"--dart-define", "ER_BUILD_VERSION"}},
		{name: "define 空白鍵", args: []string{"--dart-define", " =v"}},
		{name: "define 兩側空白", args: []string{"--dart-define", " A=v "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			_, err := parseOptions(tc.args, &stdout, &stderr)
			if err == nil {
				t.Fatalf("%q 應被拒絕", tc.args)
			}
		})
	}
}

func TestValidateDefinesAcceptsEmptyValue(t *testing.T) {
	// `KEY=` 是 Flutter 認可的寫法（把值清空），不應由本工具多加限制。
	if err := validateDefines(stringList{"ER_SERVER_BASE_URL="}); err != nil {
		t.Errorf("不應拒絕空值: %v", err)
	}
}

func TestMakePlanReportsMissingSubmodule(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, devkit.GitmodulesFile, realGitmodules)

	var stdout, stderr strings.Builder
	_, err := makePlan(options{repoRoot: root, output: defaultOutputRel, stdout: &stdout, stderr: &stderr})
	if !errors.Is(err, devkit.ErrSubmoduleMissing) {
		t.Fatalf("子模組未檢出時應回 ErrSubmoduleMissing，實際 %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("前置檢查失敗時不應已印出建置摘要: %q", stdout.String())
	}
}

func TestFrontendCheckStopsWhenEntryMissing(t *testing.T) {
	// 倉庫狀態完好但前端尚未有品質入口時，--check 必須在動任何檔案之前就停下來，
	// 否則會留下「舊產物已刪、新產物沒建」的空目錄。這裡直接組目標，不依賴本機 PATH。
	root, appDir := fakeRepo(t)
	target := buildTarget{
		root: root,
		app:  devkit.Frontend{Module: "EvernightRealmAPP", Dir: appDir, FlutterExe: "flutter"},
		out:  filepath.Join(root, filepath.FromSlash(defaultOutputRel)),
	}

	var stdout, stderr strings.Builder
	err := runFrontendCheck(t.Context(), target.app, options{stdout: &stdout, stderr: &stderr})
	if !errors.Is(err, devkit.ErrSubmoduleMissing) {
		t.Fatalf("入口缺失應回 ErrSubmoduleMissing，實際 %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("入口缺失時不應已印出品質閘進度: %q", stdout.String())
	}
}

func TestMainHelpMentionsBothStopConditions(t *testing.T) {
	var stdout, stderr strings.Builder
	_, err := parseOptions([]string{"--help"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "flag: help requested") {
		t.Fatalf("--help 應由 flag 套件處理並回報: %v", err)
	}
	usage := stderr.String()
	for _, want := range []string{"子模組", "初始化", "即停止", "internal/webassets/dist"} {
		if !strings.Contains(usage, want) {
			t.Errorf("說明文字應包含 %q，實際:\n%s", want, usage)
		}
	}
}
