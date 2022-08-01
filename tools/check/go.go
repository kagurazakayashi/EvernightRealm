package main

import (
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
)

// Go 側三道閘的名稱。清單只在這裡出現一次：過濾、錯誤訊息與說明文字都從它推得。
const (
	gateFmt  = "fmt"
	gateVet  = "vet"
	gateTest = "test"

	// gateFmtDesc 是格式閘的說明文字；組步驟時靠它辨認「這一道要有輸出即未過」，
	// 而不是另傳一個布林參數——閘的識別資訊本來就跟著命令走。
	gateFmtDesc = "Go 格式檢查"
)

// goGateNames 依「便宜且訊息最直的在前」排序：格式差異一行就講完，分析要看程式碼，
// 測試最慢放最後，讓人在放棄等待之前先看到可修的東西。
var goGateNames = []string{gateFmt, gateVet, gateTest}

// defaultGoTargets 是未給位置參數時的檢查範圍。
//
// 用 ./... 而不是 .：後端有 internal 下多層套件與 tools 下的工具命令，只檢查根目錄會
// 得出一個「全綠但只覆蓋一個套件」的結果。
var defaultGoTargets = []string{"./..."}

// isKnownGate 回傳名稱是否為本入口認識的 Go 閘。
func isKnownGate(name string) bool { return containsString(goGateNames, name) }

// wantGate 依 --gate 過濾清單決定某道閘是否執行；清單留空表示全跑。
func wantGate(selected []string, name string) bool {
	if len(selected) == 0 {
		return true
	}
	return containsString(selected, name)
}

// goCommands 組出 Go 側要跑的閘（順序固定，與 goGateNames 一致）。
//
// 工具鏈在組命令時才解析：只要 `--gate vet` 卻因為本機沒有 gofmt 而失敗，是把過濾條件
// 實現成了新的依賴。
//
// 回傳清單的順序就是 goGateNames 的順序——這一點由「依序 append、不排序」保證，
// 呼叫端拿到的是已經排好的執行計畫。
func goCommands(in invocation, goExe string) ([]devkit.Command, error) {
	targets := in.targets
	if len(targets) == 0 {
		targets = defaultGoTargets
	}

	var cmds []devkit.Command
	if wantGate(in.gates, gateFmt) {
		fmtExe, err := devkit.GoFmtExecutable(goExe)
		if err != nil {
			return nil, err
		}
		cmds = append(cmds, devkit.Command{Desc: gateFmtDesc, Exe: fmtExe, Args: gofmtArgs(targets)})
	}
	if wantGate(in.gates, gateVet) {
		cmds = append(cmds, devkit.Command{Desc: "Go 靜態檢查", Exe: goExe, Args: vetArgs(targets)})
	}
	if wantGate(in.gates, gateTest) {
		cmds = append(cmds, devkit.Command{Desc: "Go 測試", Exe: goExe, Args: testArgs(targets, in.runRegex, in.verbose)})
	}
	return cmds, nil
}

// gofmtArgs 組出 `gofmt -l <目錄>`：只列出有差異的檔案，不改寫。
//
// 為什麼不 `-w`：這個入口的完成判斷是「本地命令可運行」，而自動改寫工作樹會讓人無法預期
// 一次檢查動了哪些檔案。要改的人自己跑 gofmt -w，那是一個明確的決定。
func gofmtArgs(targets []string) []string {
	args := []string{"-l"}
	return append(args, gofmtTargets(targets)...)
}

// gofmtHint 產生格式閘失敗時的下一步。
func gofmtHint(targets []string) string {
	return fmt.Sprintf("gofmt -w %s", strings.Join(gofmtTargets(targets), " "))
}

// gofmtTargets 把 Go 的套件寫法換成 gofmt 認得的目錄寫法（純函數，便於測試）。
//
// gofmt 收的是檔案與目錄，不認得 ./... 這種遞迴樣式；直接丟過去只會得到一句
// 「no such file or directory」。./internal/httpapi/... 這種局部遞迴則折回該目錄本身。
func gofmtTargets(targets []string) []string {
	var out []string
	for _, target := range targets {
		path := strings.TrimSpace(target)
		switch {
		case path == "":
			continue
		case path == "./..." || path == "all":
			path = "."
		case strings.HasSuffix(path, "/..."):
			path = strings.TrimSuffix(path, "/...")
			if path == "." || path == "" {
				path = "."
			}
		}
		if !containsString(out, path) {
			out = append(out, path)
		}
	}
	if len(out) == 0 {
		return []string{"."}
	}
	return out
}

// vetArgs 組出 `go vet <套件...>`。
func vetArgs(targets []string) []string {
	args := []string{"vet"}
	return append(args, targets...)
}

// testArgs 組出 `go test <套件...> -count=1 [-run R] [-v]`。
//
// -count=1 是必要的：Go 會快取測試結果，同一份程式碼第二次跑直接回 cached，於是
// 「檢查通過」變成上一次通過的結論。旗標放在套件之後，與倉庫文件裡既存的手打串同形。
func testArgs(targets []string, runRegex string, verbose bool) []string {
	args := []string{"test"}
	args = append(args, targets...)
	args = append(args, "-count=1")
	if runRegex != "" {
		args = append(args, "-run", runRegex)
	}
	if verbose {
		args = append(args, "-v")
	}
	return args
}

// goSteps 產生 Go 側的執行步驟，並回傳給摘要用的一行說明。
func goSteps(in invocation) ([]planStep, string, error) {
	root, err := devkit.ResolveModuleRoot(in.repoRoot)
	if err != nil {
		return nil, "", err
	}
	goExe, err := devkit.ResolveGo(in.goExe)
	if err != nil {
		return nil, "", err
	}
	cmds, err := goCommands(in, goExe)
	if err != nil {
		return nil, "", err
	}
	if len(cmds) == 0 {
		return nil, "", fmt.Errorf("--gate 過濾後沒有可執行的 Go 閘（可用：%s）", strings.Join(goGateNames, "、"))
	}

	targets := in.targets
	if len(targets) == 0 {
		targets = defaultGoTargets
	}
	steps := make([]planStep, 0, len(cmds))
	for _, cmd := range cmds {
		step := planStep{cmd: cmd, dir: root}
		if cmd.Desc == gateFmtDesc {
			step.hint = gofmtHint(targets)
			// gofmt 用退出碼 0 同時表達「沒差異」與「有差異並列出檔案」，
			// 這道閘只能靠有沒有輸出判定；忘了標記它，格式檢查就會永遠全綠。
			step.failOnOutput = true
		}
		steps = append(steps, step)
	}

	summary := fmt.Sprintf("後端：%s（go=%s，目錄=%s）", strings.Join(gateNamesOf(cmds), "、"), goExe, root)
	return steps, summary, nil
}

// gateNamesOf 由命令說明反推閘名清單，供摘要使用。
//
// 為什麼不直接把名稱傳下去：命令與名稱各自一份清單時，加一道閘容易只改其中一處，
// 摘要於是長期說謊。這裡以 Desc 作為唯一來源。
func gateNamesOf(cmds []devkit.Command) []string {
	names := make([]string, 0, len(cmds))
	for _, cmd := range cmds {
		names = append(names, cmd.Desc)
	}
	return names
}
