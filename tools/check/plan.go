package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
)

// appSteps 產生前端側的執行步驟：定位子模組，然後叫起前端倉庫自有的品質入口。
//
// 根側刻意不重列「格式化／分析／測試」三道閘：閘的定義在前端倉庫（它才知道 analyze 的
// 範圍、test 的定向旗標）。這樣「在前端目錄裡自己跑」與「由根倉庫跑」跑的必然是同一份
// 檢查，兩者不會因為其中一處改了而得出不同結論。
func appSteps(in invocation) ([]planStep, string, error) {
	root, err := devkit.ResolveRepoRoot(in.repoRoot)
	if err != nil {
		return nil, "", err
	}
	entries, err := devkit.ReadSubmodules(root)
	if err != nil {
		return nil, "", err
	}
	entry, err := devkit.SelectSubmodule(entries, in.module)
	if err != nil {
		return nil, "", err
	}
	frontend, err := devkit.PrepareFrontend(root, entry, in.flutter)
	if err != nil {
		return nil, "", err
	}
	cmd, err := devkit.FrontendCheckCommand(frontend, in.passthrough)
	if err != nil {
		return nil, "", err
	}

	rel := devkit.RelativeTo(root, frontend.Dir)
	summary := fmt.Sprintf("前端：%s（flutter=%s）", rel, frontend.FlutterExe)
	if len(in.passthrough) > 0 {
		summary += fmt.Sprintf("，轉發 %d 筆參數", len(in.passthrough))
	}
	return []planStep{{cmd: cmd, dir: frontend.Dir}}, summary, nil
}

// makePlan 把「定位倉庫、解析工具鏈、組出命令」全部做完，才讓呼叫方開始執行。
//
// 分開做是因為半成品最難收拾：定位失敗或工具鏈缺席時必須在下第一道命令之前就停，
// 否則前面的檢查跑完、後面才報「找不到 flutter」，看起來像入口自己壞了。
func makePlan(in invocation) ([]planStep, []string, error) {
	var (
		steps   []planStep
		summary []string
	)

	if in.scope != scopeApp {
		list, line, err := goSteps(in)
		if err != nil {
			return nil, nil, err
		}
		steps = append(steps, list...)
		summary = append(summary, line)
	}
	if in.scope != scopeGo {
		appStepList, line, err := appSteps(in)
		if err != nil {
			return nil, nil, err
		}
		steps = append(steps, appStepList...)
		summary = append(summary, line)
	}

	head := []string{fmt.Sprintf("範圍：%s", in.scope)}
	if in.runRegex != "" && in.scope != scopeApp {
		head = append(head, fmt.Sprintf("後端定向：%s", in.runRegex))
	}
	return steps, append(head, summary...), nil
}

// commandLine 產生進度列上的命令（可執行檔名＋引數）。
//
// 把命令本身印出來是為了能被直接複製：開發時常要在同一個位置繼續加旗標，能從終端機
// 撈到確切的引數比重新拼一次可靠。只取檔名，避免整列被絕對路徑撐開。
func commandLine(cmd devkit.Command) string {
	parts := make([]string, 0, len(cmd.Args)+1)
	parts = append(parts, filepath.Base(cmd.Exe))
	parts = append(parts, cmd.Args...)
	return strings.Join(parts, " ")
}
