// Command buildweb 由根倉庫建置 Flutter Web 產物，並把產物直接落到後續內嵌用的目錄。
//
// 為什麼要有這個出口：release Web 建置務必帶 --no-web-resources-cdn，否則 CanvasKit 改向
// gstatic CDN 取檔，純離線部署的首屏會白屏。這條參數此前只活在文件與一次性驗證腳本裡，
// 等於沒有出口——會忘了帶、會在子模組目錄外跑到別份產物。本工具把它固化為唯一建置路徑。
//
// 邊界（本步的驗收條件）：找不到子模組就停止，建置失敗就停止。任何情況下都不初始化
// 子模組、不下載依賴、不改動檢出版本。版本管理是人的決定，建置工具悄悄替工作樹做主，
// 代價遠高於多打一行提示。
//
// 倉庫根與子模組的定位、外部命令的執行方式取自 internal/devkit，與 tools/check 共用同一份：
// 兩個入口對「前端在哪」得出不同結論時，壞掉的只會是後來那個入口。
//
// 用法：
//
//	go run ./tools/buildweb                     # release，產物→internal/webassets/dist
//	go run ./tools/buildweb --check             # 先過前端品質閘再建置
//	go run ./tools/buildweb --debug --dart-define ER_SERVER_BASE_URL=http://127.0.0.1:5299
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kagurazakayashi/EvernightRealm/internal/devkit"
)

// 退出碼沿用既有後端命令的慣例：0 成功、1 一般失敗、2 命令列參數錯誤。
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// toolName 是錯誤訊息與摘要的統一前綴。共用件（devkit）不帶工具名，由這裡加上，
// 這樣同一道命令被別的入口叫用時不會頂著錯誤的來源。
const toolName = "buildweb"

// defaultOutputRel 是產物的預設落點（相對倉庫根）。
//
// 落在 internal/ 之下不是隨意：go:embed 只能內嵌所屬套件目錄及其子孫，產物放在別處就
// 需要再複製一份，兩份產物遲早不一致。目錄名不得以「.」或「_」開頭，否則 embed 樣式會
// 把它跳過。
const defaultOutputRel = "internal/webassets/dist"

// stringList 讓 --dart-define 可重複給值。
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, " ") }

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// options 為一次建置的全部輸入。
type options struct {
	// repoRoot 為根倉庫目錄；留空則自目前目錄向上找 .gitmodules。
	repoRoot string
	// module 用於 .gitmodules 內有多筆子模組時指名；留空要求恰好一筆。
	module string
	// output 為產物目錄，相對路徑以倉庫根為基準。
	output string
	// flutter 為 flutter 可執行檔路徑；留空依 PATH、再退回 FLUTTER_ROOT/bin。
	flutter string
	// defines 為額外傳給 flutter 的 --dart-define 值（KEY=VALUE）。
	defines stringList
	// debug 建置 debug 版而非 release 版。
	debug bool
	// check 於建置前先跑前端品質閘。
	check bool
	// skipClean 略過建置前的清空；僅用於觀察差異，正式產物不該用。
	skipClean bool

	stdout io.Writer
	stderr io.Writer
}

func main() {
	opts, err := parseOptions(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(opts.stderr, "%s: %v\n", toolName, err)
		os.Exit(exitUsage)
	}
	if err := run(opts); err != nil {
		fmt.Fprintf(opts.stderr, "%s: %v\n", toolName, err)
		os.Exit(exitFailure)
	}
	os.Exit(exitOK)
}

// parseOptions 解析命令列。旗標一律用長寫法，與倉庫內其他工具命令一致。
func parseOptions(args []string, stdout, stderr io.Writer) (options, error) {
	opts := options{stdout: stdout, stderr: stderr}

	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.repoRoot, "repo-root", "", "根倉庫目錄（預設：自目前目錄向上找 .gitmodules）")
	fs.StringVar(&opts.module, "module", "", "子模組名稱（.gitmodules 內多筆時必填）")
	fs.StringVar(&opts.output, "output", defaultOutputRel, "產物目錄；相對路徑以倉庫根為基準，必須落在倉庫根之內")
	fs.StringVar(&opts.flutter, "flutter", "", "flutter 可執行檔（預設：PATH，再退回 FLUTTER_ROOT/bin）")
	fs.Var(&opts.defines, "dart-define", "額外編譯期參數 KEY=VALUE，可重複")
	fs.BoolVar(&opts.debug, "debug", false, "建置 debug 版而非 release 版")
	fs.BoolVar(&opts.check, "check", false, "建置前先跑前端品質入口（格式化、分析、測試）")
	fs.BoolVar(&opts.skipClean, "skip-clean", false, "不清空產物目錄（僅供觀察差異）")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "用法：go run ./tools/buildweb [旗標]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "由根倉庫的實際子模組目錄建置 Flutter Web，產物預設落在 internal/webassets/dist。")
		fmt.Fprintln(stderr, "找不到子模組或建置失敗即停止；不會初始化子模組、下載依賴或改動檢出版本。")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "旗標：")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return opts, fmt.Errorf("命令列參數錯誤：%w", err)
	}
	if fs.NArg() > 0 {
		return opts, fmt.Errorf("命令列參數錯誤：不認識的位置參數 %q", fs.Arg(0))
	}
	if err := validateDefines(opts.defines); err != nil {
		return opts, err
	}
	return opts, nil
}

// validateDefines 檢查 --dart-define 值的形狀：必須是 K=V，且兩側無空白。
//
// 在解析階段就擋下來，是因為一個漏掉等號的參數傳給 flutter 之後會變成「多了一個位置
// 參數」，錯誤訊息指不到哪裡打錯。
func validateDefines(defines stringList) error {
	for _, define := range defines {
		key, _, ok := strings.Cut(define, "=")
		switch {
		case !ok:
			return fmt.Errorf("--dart-define 需為 KEY=VALUE 格式，實際為 %q", define)
		case strings.TrimSpace(key) == "":
			return fmt.Errorf("--dart-define 的 KEY 不可為空白，實際為 %q", define)
		case define != strings.TrimSpace(define):
			return fmt.Errorf("--dart-define 兩側不可有空白，實際為 %q", define)
		}
	}
	return nil
}

// run 依「定位 → 檢查 → 品質閘 → 清空 → 建置 → 複核產物」的順序執行一次建置。
//
// 順序有意為之：先把倉庫狀態查清楚才動任何檔案，品質閘放在清空之前——檢查失敗時
// 不該留下「舊產物已刪、新產物沒建」的空目錄。
func run(o options) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	target, err := makePlan(o)
	if err != nil {
		return err
	}

	fmt.Fprintf(o.stdout, "倉庫根：%s\n", target.root)
	fmt.Fprintf(o.stdout, "前端子模組：%s\n", submoduleSummary(target))
	fmt.Fprintf(o.stdout, "flutter：%s\n", target.app.FlutterExe)
	fmt.Fprintf(o.stdout, "產物目錄：%s\n", target.out)
	if len(o.defines) > 0 {
		fmt.Fprintf(o.stdout, "額外編譯期參數：%d 筆\n", len(o.defines))
	}

	if o.check {
		if err := runFrontendCheck(ctx, target.app, o); err != nil {
			return err
		}
	}
	if !o.skipClean {
		if err := cleanOutput(target.out, o.stdout); err != nil {
			return err
		}
	}

	started := time.Now()
	command := buildCommand(target.app, target.out, o)
	if err := command.Run(ctx, target.app.Dir, o.stdout, o.stderr); err != nil {
		return err
	}

	report, err := verifyArtifacts(target.out)
	if err != nil {
		return err
	}
	fmt.Fprintf(o.stdout, "Flutter Web 已建置：%s（%d 個檔案，%s，歷時 %s）\n",
		target.out, report.files, humanBytes(report.bytes), time.Since(started).Round(time.Millisecond))
	return nil
}

// buildTarget 為前置判斷完成後的建置計畫：在哪個倉庫、建置哪個子模組、產物落在哪。
type buildTarget struct {
	root string
	app  devkit.Frontend
	out  string
}

// makePlan 做完所有「不動任何檔案」的前置判斷。
func makePlan(o options) (buildTarget, error) {
	var target buildTarget

	root, err := devkit.ResolveRepoRoot(o.repoRoot)
	if err != nil {
		return buildTarget{}, err
	}
	entries, err := devkit.ReadSubmodules(root)
	if err != nil {
		return buildTarget{}, err
	}
	entry, err := devkit.SelectSubmodule(entries, o.module)
	if err != nil {
		return buildTarget{}, err
	}
	app, err := devkit.PrepareFrontend(root, entry, o.flutter)
	if err != nil {
		return buildTarget{}, err
	}
	out, err := resolveOutput(root, o.output, app.Dir)
	if err != nil {
		return buildTarget{}, err
	}

	target = buildTarget{root: root, app: app, out: out}
	return target, nil
}

// runFrontendCheck 叫起前端倉庫自有的品質入口，失敗即停止且不進入建置。
//
// 為什麼不在此重列三道閘：閘的定義在前端倉庫（它才知道要 analyze 什麼、test 怎麼定向）。
// 根側只負責找到子模組並把命令叫起來，這樣「前端獨立執行」與「由根倉庫執行」跑的
// 必然同一份檢查。
func runFrontendCheck(ctx context.Context, app devkit.Frontend, o options) error {
	command, err := devkit.FrontendCheckCommand(app, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(o.stdout, "品質閘：%s\n", command.Desc)
	return command.Run(ctx, app.Dir, o.stdout, o.stderr)
}

// submoduleSummary 產生摘要裡的一行：子模組名稱與其相對路徑；兩者相同時不重複印。
func submoduleSummary(target buildTarget) string {
	rel := devkit.RelativeTo(target.root, target.app.Dir)
	if rel == target.app.Module {
		return rel
	}
	return target.app.Module + "（" + rel + "）"
}
