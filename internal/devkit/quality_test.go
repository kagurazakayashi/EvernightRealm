package devkit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// frontendWithEntry 建立一個已含品質入口與依賴標記的假前端。
func frontendWithEntry(t *testing.T) Frontend {
	t.Helper()
	root, appDir := fakeRepo(t, realGitmodules)
	writeFile(t, appDir, FrontendCheckEntryRel, "void main() {}\n")
	writeFile(t, appDir, filepath.ToSlash(packageConfigRel), "{}\n")
	return Frontend{Module: "app", Dir: appDir, FlutterExe: filepath.Join(root, "flutter.bat")}
}

func TestFrontendCheckCommand(t *testing.T) {
	t.Run("入口與依賴俱備時用同目錄的 dart", func(t *testing.T) {
		fe := frontendWithEntry(t)
		dir := filepath.Dir(fe.FlutterExe)
		writeFile(t, dir, "dart.bat", "@echo off\n")

		cmd, err := FrontendCheckCommand(fe, nil)
		if err != nil {
			t.Fatalf("不應失敗: %v", err)
		}
		if filepath.Clean(cmd.Exe) != filepath.Clean(filepath.Join(dir, "dart.bat")) {
			t.Errorf("應使用與 flutter 同套工具鏈的 dart，得到 %q", cmd.Exe)
		}
		want := []string{"run", FrontendCheckEntryRel, "--flutter", fe.FlutterExe}
		if !slices.Equal(cmd.Args, want) {
			t.Errorf("引數為 %#v，預期 %#v", cmd.Args, want)
		}
	})

	t.Run("前端尚未有品質入口時點名子模組要更新", func(t *testing.T) {
		_, appDir := fakeRepo(t, realGitmodules)
		writeFile(t, appDir, filepath.ToSlash(packageConfigRel), "{}\n")

		_, err := FrontendCheckCommand(Frontend{Dir: appDir, FlutterExe: "flutter"}, nil)
		if !errors.Is(err, ErrSubmoduleMissing) {
			t.Fatalf("入口缺失屬子模組未就緒，實際 %v", err)
		}
		if !strings.Contains(err.Error(), FrontendCheckEntryRel) {
			t.Errorf("錯誤訊息應點出入口路徑: %v", err)
		}
	})

	t.Run("依賴未解析時說明該跑 pub get", func(t *testing.T) {
		fe := frontendWithEntry(t)
		if err := os.Remove(filepath.Join(fe.Dir, packageConfigRel)); err != nil {
			t.Fatalf("移除依賴標記失敗: %v", err)
		}
		_, err := FrontendCheckCommand(fe, nil)
		if err == nil {
			t.Fatal("dart run 在依賴未解析時必然失敗，應提前回報")
		}
		if !strings.Contains(err.Error(), "pub get") {
			t.Errorf("錯誤訊息應給出下一步: %v", err)
		}
	})

	t.Run("轉發參數原樣附在入口之後", func(t *testing.T) {
		fe := frontendWithEntry(t)
		writeFile(t, filepath.Dir(fe.FlutterExe), "dart.bat", "@echo off\n")
		passthrough := []string{"--plain-name", "路由 --unknown", "--coverage"}

		cmd, err := FrontendCheckCommand(fe, passthrough)
		if err != nil {
			t.Fatalf("不應失敗: %v", err)
		}
		want := append([]string{"run", FrontendCheckEntryRel, "--flutter", fe.FlutterExe}, passthrough...)
		if !slices.Equal(cmd.Args, want) {
			t.Errorf("引數被改寫: %#v", cmd.Args)
		}
	})
}

// shellStatement 把「一句殼層命令」換成該平台上真的會被整句執行的引數清單。
//
// 兩個殼層吃法不同：cmd 的 /c 把其餘內容當成一行命令文字，POSIX 的 -c 只取第一個操作數當
// 命令、後面的操作數變成 $0/$1。所以 `prefix + ["exit","3"]` 在 Linux 上實際跑的是 `exit`
// （無參，退出碼 0），測試會假通過；這裡依平台交「一句話」而不是兩個字，兩側驗的都是
// 同一件事：非零退出碼要被寫進錯誤訊息。
func shellStatement(prefix []string, statement string) []string {
	args := append([]string{}, prefix...)
	if runtime.GOOS == "windows" {
		return append(args, strings.Fields(statement)...)
	}
	return append(args, statement)
}

func TestCommandRun(t *testing.T) {
	ctx := context.Background()
	// 用各平台必然存在的殼層命令當受測對象：這裡要驗的是「轉接與退出碼判定」，
	// 不是某個真實工具鏈的行為。
	shell := func() (string, []string) {
		if runtime.GOOS == "windows" {
			spec := os.Getenv("ComSpec")
			if spec == "" {
				spec = "cmd.exe"
			}
			return spec, []string{"/c"}
		}
		return "/bin/sh", []string{"-c"}
	}

	t.Run("命令不存在時錯誤可判讀", func(t *testing.T) {
		cmd := Command{Desc: "不存在的命令", Exe: "devkit-no-such-executable-xyz"}
		err := cmd.Run(ctx, t.TempDir(), os.Stdout, os.Stderr)
		if err == nil {
			t.Fatal("應回傳錯誤")
		}
		if !strings.Contains(err.Error(), "不存在的命令") {
			t.Errorf("錯誤應含說明文字: %v", err)
		}
	})

	t.Run("非零退出碼寫進錯誤訊息", func(t *testing.T) {
		exe, prefix := shell()
		cmd := Command{Desc: "回傳 3", Exe: exe, Args: shellStatement(prefix, "exit 3")}
		err := cmd.Run(ctx, t.TempDir(), os.Stdout, os.Stderr)
		if err == nil {
			t.Fatal("非零退出碼應回傳錯誤")
		}
		if !strings.Contains(err.Error(), "退出碼 3") {
			t.Errorf("錯誤應含退出碼: %v", err)
		}
	})

	t.Run("成功時輸出轉接給呼叫方", func(t *testing.T) {
		var stdout, stderr strings.Builder
		exe, prefix := shell()
		cmd := Command{Desc: "印一行", Exe: exe, Args: append(prefix, "echo devkit-probe")}
		if err := cmd.Run(context.Background(), t.TempDir(), &stdout, &stderr); err != nil {
			t.Fatalf("不應失敗: %v", err)
		}
		if !strings.Contains(stdout.String(), "devkit-probe") {
			t.Errorf("輸出未轉接: %q", stdout.String())
		}
	})

	t.Run("錯誤訊息不帶工具名前綴", func(t *testing.T) {
		// 同一道命令可能被建置入口或品質入口叫用，前綴應由呼叫端加。
		cmd := Command{Desc: "印一行", Exe: "devkit-no-such-executable-xyz"}
		err := cmd.Run(ctx, t.TempDir(), os.Stdout, os.Stderr)
		if err != nil && (strings.HasPrefix(err.Error(), "buildweb:") || strings.HasPrefix(err.Error(), "check:")) {
			t.Errorf("共用件不應硬編工具名: %v", err)
		}
	})
}
