// Command check 是根倉庫的本地品質入口：格式化、靜態檢查與定向測試一條命令跑完。
//
// 為什麼要有這個出口：這些命令此前是散在文件裡的手打串（gofmt -l .、go vet ./...、
// go test ./... -count=1、go test .\internal\httpapi\ -run TestXxx -v），每換一次會話就
// 要重新拼一次，而且拼錯的方向是「少跑了一道還全綠」。本入口把清單固化下來，並讓定向
// 檢查（只跑一個套件、一個測試）成為同一個入口的參數而不是另一串命令。
//
// 邊界：這是「本地命令」，不是提交鉤子。它只在被人叫起時執行，絕不自動 commit、push、
// 也不改動任何檔案（格式檢查只報告差異，改寫由人決定）。
//
// Go 側的閘在本工具裡；前端側的三道閘定義在前端子倉庫的 tools/check/check.dart，
// 本工具只負責找到子模組並把它叫起來——兩個入口對「跑哪些前端檢查」因此不會有兩種答案。
//
// 用法：
//
//	go run ./tools/check                      # 後端三道 + 前端入口，全跑
//	go run ./tools/check go                   # 只跑後端
//	go run ./tools/check go ./internal/httpapi --run TestCors --verbose
//	go run ./tools/check go --gate fmt        # 只檢查格式（不改寫）
//	go run ./tools/check app -- --plain-name 路由
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
)

// 退出碼與倉庫內其他工具命令一致：0 通過、1 有閘未過、2 命令列參數錯誤。
// --help 例外：它是正當的查詢，回 0。
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// toolName 用於錯誤前綴與 --help 的用法行。
const toolName = "check"

// errHelp 讓「要說明」與「打錯了」在命令列解析階段就分家。
var errHelp = errors.New("要求說明")

// scope 為一次檢查的範圍。
type scope int

const (
	scopeAll scope = iota // 後端與前端
	scopeGo               // 只有後端（Go 模組）
	scopeApp              // 只有前端（Flutter 子倉庫）
)

// String 讓範圍能出現在摘要與錯誤訊息裡而不需另有一份對照表。
func (s scope) String() string {
	switch s {
	case scopeGo:
		return "go"
	case scopeApp:
		return "app"
	default:
		return "all"
	}
}

// invocation 為一次品質檢查的全部輸入。
type invocation struct {
	scope scope
	// repoRoot 同時作為 Go 模組根與倉庫根的起點；留空則自目前目錄向上找各自的憑證檔。
	repoRoot string
	// module 用於 .gitmodules 內有多筆子模組時指名；留空要求恰好一筆。
	module string
	// flutter／goExe 為工具鏈覆寫值，留空依 PATH 再退回各自的環境變數。
	flutter string
	goExe   string
	// gates 為 Go 側閘的過濾清單；留空表示全跑。
	gates []string
	// runRegex 對應 `go test -run`，是「定向測試」的入口。
	runRegex string
	verbose  bool
	// targets 為 Go 側的位置參數（套件或目錄寫法）。
	targets []string
	// passthrough 為 `-- ` 之後原樣轉給前端入口的參數，本工具不解析。
	passthrough []string

	stdout io.Writer
	stderr io.Writer
}

func main() {
	in, err := parseInvocation(os.Args[1:], os.Stdout, os.Stderr)
	switch {
	case errors.Is(err, errHelp):
		// 說明寫給終端機，走 stdout：`tools/check --help > file` 不該只收到錯誤行。
		in.stdout.Write([]byte(usageText()))
		os.Exit(exitOK)
	case err != nil:
		fmt.Fprintf(os.Stderr, "%s: %v\n%s\n", toolName, err, usageText())
		os.Exit(exitUsage)
	}

	if err := run(in); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", toolName, err)
		os.Exit(exitFailure)
	}
	os.Exit(exitOK)
}

// flagNames 為可帶值的旗標；布爾旗標在 parseInvocation 裡單獨處理。
var flagNames = []string{"--repo-root", "--module", "--flutter", "--go", "--gate", "--run"}

// usageText 產生說明文字。手寫而非 fs.PrintDefaults：本入口不經 flag 套件（見 parseInvocation），
// 而說明裡最需要的是「旗標可以放在任意位置」與兩側定向參數的差別，這兩點模板給不出來。
func usageText() string {
	return strings.Join([]string{
		"用法：go run ./tools/check [範圍] [旗標] [Go 套件...] [-- 前端入口參數...]",
		"",
		"範圍：go（後端）｜app（前端）｜all（預設，兩者）",
		"",
		"旗標（可置於任意位置）：",
		"  --repo-root DIR   倉庫／模組根目錄（預設：自目前目錄向上找）",
		"  --module NAME     子模組名稱（.gitmodules 內多筆時必填）",
		"  --flutter PATH    flutter 可執行檔（預設：PATH，再退回 FLUTTER_ROOT/bin）",
		"  --go PATH         go 可執行檔（預設：PATH，再退回 GOROOT/bin）",
		"  --gate LIST       僅跑指定 Go 閘：fmt、vet、test（逗號分隔，可重複）",
		"  --run REGEX       定向測試，對應 go test -run（僅 Go 側）",
		"  -v, --verbose     逐筆輸出測試結果（僅 Go 側）",
		"  -h, --help        顯示本說明",
		"",
		"位置參數是 Go 側的套件或目錄（以倉庫根為基準）。前端側的定向一律放在 `-- ` 之後，",
		"原樣交給 EvernightRealmAPP/tools/check/check.dart 解釋——兩側的閘名不同，硬翻成",
		"同一套旗標只會出現第二份規則。",
		"",
		"範例：",
		"  go run ./tools/check go ./internal/httpapi --run TestCors   後端定向測試",
		"  go run ./tools/check go --gate fmt                         只檢查格式（不改寫）",
		"  go run ./tools/check app -- --plain-name 路由              前端定向測試",
		"  go run ./tools/check                                       兩側全跑",
		"",
		"本工具只在被叫起時執行：不裝提交鉤子、不執行任何 git 寫操作、不改動任何檔案",
		"（格式檢查只報告差異，改寫與否由人決定）。",
	}, "\n")
}

// parseInvocation 解析命令列。
//
// 不用 flag 套件而是自己走一遍：Go 的 flag 遇到第一個位置參數就停止解析，於是
// `check go ./internal/httpapi --run TestCors`（與文件裡既存的手打串同形）會把 --run
// 當成套件名。旗標可置於任意位置是這個入口的可用性前提，值得一個明確、可測的掃描規則。
//
// 規則一共四條：`--` 之後全部原樣轉發；已知旗標就地取值（`--k v` 與 `--k=v` 同形）；
// 第一個類別字（go／app／all）當作範圍；其餘裸字視為 Go 側位置參數。
func parseInvocation(args []string, stdout, stderr io.Writer) (invocation, error) {
	in := invocation{scope: scopeAll, stdout: stdout, stderr: stderr}

	var (
		passthroughMode bool
		scopeSeen       bool
		gateList        []string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if passthroughMode {
			in.passthrough = append(in.passthrough, arg)
			continue
		}
		if arg == "--" {
			passthroughMode = true
			continue
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			if !scopeSeen {
				if s, ok := parseScope(arg); ok {
					in.scope = s
					scopeSeen = true
					continue
				}
				scopeSeen = true // 首個裸字不是範圍：範圍維持預設，之後的裸字全當位置參數。
			}
			in.targets = append(in.targets, arg)
			continue
		}

		name, value, hasValue := splitFlag(arg)
		switch name {
		case "h", "help":
			return in, errHelp
		case "v", "verbose":
			if hasValue {
				return in, fmt.Errorf("-%s 不接受值（它是開關）", name)
			}
			in.verbose = true
		case "repo-root":
			v, err := flagValue(name, value, hasValue, args, &i)
			if err != nil {
				return in, err
			}
			in.repoRoot = v
		case "module":
			v, err := flagValue(name, value, hasValue, args, &i)
			if err != nil {
				return in, err
			}
			in.module = v
		case "flutter":
			v, err := flagValue(name, value, hasValue, args, &i)
			if err != nil {
				return in, err
			}
			in.flutter = v
		case "go":
			v, err := flagValue(name, value, hasValue, args, &i)
			if err != nil {
				return in, err
			}
			in.goExe = v
		case "run":
			v, err := flagValue(name, value, hasValue, args, &i)
			if err != nil {
				return in, err
			}
			in.runRegex = v
		case "gate":
			v, err := flagValue(name, value, hasValue, args, &i)
			if err != nil {
				return in, err
			}
			gateList = append(gateList, v)
		default:
			return in, fmt.Errorf("不認識的旗標 %q（可用：%s、-v、-h）", arg, strings.Join(flagNames, "、"))
		}
	}

	gates, err := parseGates(gateList)
	if err != nil {
		return in, err
	}
	in.gates = gates

	if err := validateInvocation(in); err != nil {
		return in, err
	}
	return in, nil
}

// parseScope 嘗試把裸字當成範圍；不是範圍時回 ok=false，讓呼叫端把它當位置參數。
func parseScope(raw string) (scope, bool) {
	switch strings.ToLower(raw) {
	case "go":
		return scopeGo, true
	case "app":
		return scopeApp, true
	case "all":
		return scopeAll, true
	default:
		return scopeAll, false
	}
}

// splitFlag 拆出旗標名與等號寫法的值。
//
// 單長短橫線都接受（-run 與 --run 同形），與 Go 自身命令行為一致；拆完的名字不帶橫線，
// 後續 switch 只需比名稱。
func splitFlag(arg string) (name, value string, hasValue bool) {
	body := strings.TrimLeft(arg, "-")
	name, value, hasValue = strings.Cut(body, "=")
	return name, value, hasValue
}

// flagValue 取值：`--k=v` 直接可用；`--k v` 吃掉下一個引數。
//
// 少了值時報錯而不是靜默拿下一個裸字頂替——`--run` 漏寫正則卻把下一個套件路徑當成測試名
// 會跑出一個「全綠但什麼都沒測」的結果，那是這個入口最不能犯的錯。
func flagValue(name, value string, hasValue bool, args []string, i *int) (string, error) {
	if hasValue {
		return value, nil
	}
	if *i+1 >= len(args) {
		return "", fmt.Errorf("旗標 --%s 缺少值", name)
	}
	*i++
	return args[*i], nil
}

// parseGates 把逗號分隔的閘名收成清單（可重複給值，去重且保持首次順序）。
func parseGates(raw []string) ([]string, error) {
	var seen []string
	for _, chunk := range raw {
		for _, item := range strings.Split(chunk, ",") {
			name := strings.ToLower(strings.TrimSpace(item))
			if name == "" {
				continue
			}
			if !isKnownGate(name) {
				return nil, fmt.Errorf("不認識的 Go 閘 %q（可用：%s）", item, strings.Join(goGateNames, "、"))
			}
			if !containsString(seen, name) {
				seen = append(seen, name)
			}
		}
	}
	return seen, nil
}

// validateInvocation 擋下「寫了但不會生效」的組合。
//
// 一個被忽略的旗標比一個報錯的旗標危險：範圍是 app 時，--run 屬 Go 側，留下來就會讓人
// 以為定向測試也套在前端上。
func validateInvocation(in invocation) error {
	goOnly := []struct {
		name  string
		given bool
	}{
		{name: "--gate", given: len(in.gates) > 0},
		{name: "--run", given: in.runRegex != ""},
		{name: "--verbose", given: in.verbose},
		{name: "Go 套件位置參數", given: len(in.targets) > 0},
	}

	if in.scope == scopeApp {
		for _, item := range goOnly {
			if item.given {
				return fmt.Errorf("%s 只作用於 Go 側，範圍為 app 時無效；前端的定向檢查請寫成 `-- --plain-name …`", item.name)
			}
		}
		return nil
	}
	if in.scope == scopeGo && len(in.passthrough) > 0 {
		return errors.New("`-- ` 之後的參數會轉給前端入口，範圍為 go 時不會執行到它；請改用範圍 all 或 app")
	}
	return nil
}

// containsString 為小清單用的線性查找。
func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

// planStep 是一道要執行的閘。
type planStep struct {
	cmd devkit.Command
	dir string
	// hint 是失敗時附上的下一步；只寫「怎麼修」的那一句，不重述錯誤本身。
	hint string
	// failOnOutput 表示「只要有輸出就算未過」。格式檢查需要它：gofmt -l 即使列出一整串
	// 未格式化的檔案也回傳 0（實測發現），只判退出碼會讓這道閘變成擺設，而「全綠卻什麼
	// 都沒檢查」正是這個入口最不能犯的錯。
	failOnOutput bool
}

// run 先把計畫做完（定位倉庫、解析工具鏈），再依序執行。
//
// 為什麼要先做完：半成品的工作樹最難收拾。定位失敗或工具鏈缺席時必須在下第一道命令之前
// 就停，否則前面的檢查會跑完、後面才報「找不到 flutter」，看起來像程式壞了。
func run(in invocation) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	steps, summary, err := makePlan(in)
	if err != nil {
		return err
	}
	for _, line := range summary {
		fmt.Fprintf(in.stdout, "%s\n", line)
	}

	started := time.Now()
	for idx, step := range steps {
		fmt.Fprintf(in.stdout, "── %d/%d %s：%s\n", idx+1, len(steps), step.cmd.Desc, commandLine(step.cmd))

		if err := runStep(ctx, step, in.stdout, in.stderr); err != nil {
			if step.hint != "" {
				fmt.Fprintf(in.stderr, "下一步：%s\n", step.hint)
			}
			return fmt.Errorf("第 %d/%d 道未過：%w", idx+1, len(steps), err)
		}
	}

	fmt.Fprintf(in.stdout, "品質檢查通過：%d 道閘，歷時 %s\n", len(steps), time.Since(started).Round(time.Millisecond))
	return nil
}

// runStep 執行一道閘；「有輸出即未過」的閘會把輸出邊顯示邊記下來作為判定依據。
//
// 為什麼需要這種單獨判定：gofmt 是格式化工具而不是檢查工具，`-l` 與 `-d` 都只用退出碼 0
// 回報「沒有差異」與「有差異並列出來」（實測發現）。所以「這道閘過了沒有」必須由呼叫端
// 依「有沒有列出檔案」判定，而那份清單仍要原樣進終端機——只剩「有 N 個檔案不對」是沒法下手的。
func runStep(ctx context.Context, step planStep, stdout, stderr io.Writer) error {
	if !step.failOnOutput {
		return step.cmd.Run(ctx, step.dir, stdout, stderr)
	}

	var recorded strings.Builder
	if err := step.cmd.Run(ctx, step.dir, io.MultiWriter(stdout, &recorded), stderr); err != nil {
		return err
	}
	lines := reportLines(recorded.String())
	switch len(lines) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("%s 發現 1 個待格式化的檔案：%s", step.cmd.Desc, lines[0])
	default:
		return fmt.Errorf("%s 發現 %d 個待格式化的檔案（首筆：%s）",
			step.cmd.Desc, len(lines), lines[0])
	}
}

// reportLines 把報告輸出拆成有意義的行，忽略空白與僅由換行構成的內容。
func reportLines(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r")); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
