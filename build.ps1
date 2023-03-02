<#
.SYNOPSIS
    建置 EvernightRealm：前端 Flutter Web 產物內嵌 + 後端 Go 編譯。
.DESCRIPTION
    1) go run ./tools/buildweb —— 建置前端 Web 並落到 internal/webassets/dist
       （release 建置固定帶 --no-web-resources-cdn，避免 CanvasKit 回退 CDN 造成離線白屏）。
    2) go build ./... —— 全倉庫編譯驗證。
    3) go build -o build\evernight-server.exe ./cmd/evernight-server —— 產出可執行的服務端二進位。
    產物 build\evernight-server.exe 已含內嵌前端 Web，單檔即可發布。
    可用 -SkipWeb 跳過前端 Web 建置（只編譯後端）。
.EXAMPLE
    .\build.ps1
    .\build.ps1 -SkipWeb
#>
[CmdletBinding()]
param(
    [switch]$SkipWeb
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw '找不到 go 命令：請安裝 Go 並加入 PATH。'
}

Push-Location $root
try {
    if (-not $SkipWeb) {
        Write-Host '建置前端 Web（go run ./tools/buildweb）...' -ForegroundColor Cyan
        & go run ./tools/buildweb
        if ($LASTEXITCODE -ne 0) { throw "buildweb 失敗（退出碼 $LASTEXITCODE）。" }
    }

    Write-Host '編譯後端全倉庫（go build ./...）...' -ForegroundColor Cyan
    & go build ./...
    if ($LASTEXITCODE -ne 0) { throw "go build ./... 失敗（退出碼 $LASTEXITCODE）。" }

    $outDir = Join-Path $root 'build'
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    $exe = Join-Path $outDir 'evernight-server.exe'
    Write-Host "產出服務端二進位 $exe ..." -ForegroundColor Cyan
    & go build -o $exe ./cmd/evernight-server
    if ($LASTEXITCODE -ne 0) { throw "go build -o 失敗（退出碼 $LASTEXITCODE）。" }

    Write-Host "`n產物: $exe（內嵌前端 Web：$(-not $SkipWeb)）" -ForegroundColor Green
}
finally {
    Pop-Location
}
