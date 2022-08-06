# 圖示產生工具（後端）

把四個來源圖推導成後端（Go 單一執行檔）所需的圖示與 macOS 應用程式包素材。

> 前端（Flutter 六平台與啟動畫面）的圖示不在這裡：那由前端倉庫
> `EvernightRealmAPP` 自己的 `tools/icons/generate_icons.py` 負責。

## 為什麼需要它

各平台的圖示尺寸表是硬性的（Windows ico 十格、Linux hicolor 九格），手工匯出
必然漂移：換了來源圖之後漏掉某一格不會報錯，只會在發布後以「某台裝置上圖示還是
舊的」的形式出現。這個腳本把尺寸表固化成唯一出口，來源只有四個檔案，其餘全部
推導；`--check` 可以隨時核對現況。

## 用法

```bash
python tools/icons/generate_icons.py            # 產生後端全部圖示
python tools/icons/generate_icons.py --check    # 只核對，不寫入（CI 可用）
# macOS 應用程式包（單一執行檔在 macOS 上不會自帶圖示，只有 .app 才會被採用）
python tools/icons/generate_icons.py --package-macos --binary <darwin 執行檔> --version 1.0.0
```

需要 Pillow（`python -m pip install Pillow`）；不連網、可重複執行，同一來源圖產生
位元組相同的輸出。**此腳本不需要 `go`**：它自己寫出 Go 連結器吃的 `.syso`。

## 來源圖

| 檔案 | 用途 | 放哪裡 |
| --- | --- | --- |
| `EvernightRealmBackendRounded.png` | 圓角、背景透明。用於 Linux 圖示主題 | `assets/icons/` |
| `EvernightRealmBackendSquare.png` | 正方形、不透明滿版。用於店鋪素材 | `assets/icons/` |
| `EvernightRealmBackendRounded.ico` | Windows 應用程式圖示，原樣沿用 | `assets/icons/` |
| `EvernightRealmBackendRounded.icns` | macOS 應用程式圖示，原樣沿用 | `assets/icons/` |

**為什麼圓角／正方形要分開選**：各應用商店明文禁止圖示自帶圓角與透明（商店會
自己裁切），遞交帶圓角的圖會被判不合格；Linux 桌面則相反，圖示必須自帶圓角與
外圍留白。同一份來源圖不可能同時滿足，所以兩者都留在版本庫。

## 產出去向

| 平台 | 位置 | 進版本庫 |
| --- | --- | --- |
| Windows | `cmd/evernight-server/resource_windows_{amd64,arm64}.syso` | 否（編譯前先跑腳本） |
| macOS | `dist/macos/EvernightRealm Server.app`（`--package-macos` 現場組出） | 否 |
| Linux | `packaging/linux/icons/hicolor/<尺寸>/apps/<應用程式 ID>.png` | 否（打包時安裝） |
| 展示／店鋪 | `assets/icons/generated/`（含 Play 512、App Store 1024） | 否 |

進版本庫的只有四張來源圖與指向它們的黏著設定檔；**這裡列出的產物全部由腳本產生，
一律不進版本庫**（見 `.gitignore` 的圖示產物段落）。

因此**所有產物預設都不在工作區裡**（乾淨 clone 上本來就不存在），要用的時候再產生：

```bash
python tools/icons/generate_icons.py    # 連同 Windows .syso、Linux 打包素材與展示圖一起寫出來
```

同樣的原因，`--check` **不要求任何產物必須存在**（缺席不報錯），有出現才逐一定比對內容，
所以乾淨 clone 上的核對依然是綠的。

## 需要人工維護的地方

腳本只寫圖示與 `.syso`，**不會改寫手寫的黏著設定檔**（產生器改壞手寫檔的代價太高）。
下列設定檔要指到新圖示，改一次即可；改完可以用 `--check` 核對，
它會檢查這些檔案是否仍與腳本內的品牌底色一致：

| 檔案 | 要設定的內容 |
| --- | --- |
| `packaging/linux/evernightrealm-server.desktop` | `Icon=` 要等於圖示主題裡的檔名（即應用程式 ID `moe.yashi.evernightrealm.server`） |

## 後端 Windows 圖示怎麼進 exe

Go 沒有「指定 exe 圖示」的參數，官方作法是在套件目錄放一個 `.syso`（COFF 目的檔），
由 `go build` 自動連結。本腳本自行產生該物件，格式與 `akavel/rsrc` 一致
（已驗證同一來源 ICO 的輸出一位元組不差）：

* 單一 `.rsrc` 區段，資源樹為 型別 → 資源 ID → 語言(0x0409) → 資料項目；
* 資料項目的 `OffsetToData` 是 RVA，以 `ADDR32NB` 重定位（amd64 型別 3／arm64 型別 2）
  交給連結器填最終位址；資源樹節點的位移則相對於資源目錄起點，不重定位；
* 檔名用 `resource_windows_amd64.syso` 這種 `_GOOS_GOARCH` 後綴，
  交叉編譯 Linux／macOS 時才不會把 PE 目的檔一起帶進去。

不使用 `rsrc` 當作產生器的原因：它產生時需要連網抓模組，而 `.syso` 是不進版本庫的
本機產物，產生器離線可跑才能確保換台機器都能重建同一份東西。

要重新驗證兩者一致（需連網，只在懷疑時跑）：

```bash
cd $(mktemp -d) && cat > go.mod <<'EOF'
module refcheck

go 1.21
EOF
cp <倉庫>/assets/icons/EvernightRealmBackendRounded.ico ./icon.ico
cat > main.go <<'EOF'
package main

// 產生參照 syso 供逐位元組比對
import (
	"os"

	"github.com/akavel/rsrc/rsrc"
)

func main() {
	f, _ := os.Create("ref.syso")
	_ = rsrc.Embed(f, 0x0409, "icon.ico", "", nil)
	_ = f.Close()
}
EOF
go mod tidy && go run . && cmp ref.syso <倉庫>/cmd/evernight-server/resource_windows_amd64.syso && echo 一致
```

## 改完之後

**編譯前先確認圖示已產生**：乾淨 clone、換機器或剛清過產物時，
`cmd/evernight-server/resource_windows_*.syso` 不存在，Windows 執行檔會靜默地不帶圖示
（`go build` 不會報錯）。編譯前先跑一次產生腳本；純編譯不需要圖示時可略過。

```bash
python tools/icons/generate_icons.py             # 缺圖示就先產生（編譯前）
python tools/icons/generate_icons.py --check     # 圖示＋黏著設定檔一致性
cd ../.. && go build ./cmd/evernight-server      # 後端（Windows 目標會帶入 .syso）
```
