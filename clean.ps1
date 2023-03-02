<#
.SYNOPSIS
    清理 EvernightRealm 後端建置產物。
.DESCRIPTION
    刪除：
      - build/（evernight-server.exe 等後端二進位）
      - internal/webassets/dist/*（前端 Web 產物；保留 .keep 佔位檔，
        否則尚未建置前端時 go:embed all:dist 會編不過）
    前端 Flutter 快取（EvernightRealmAPP/build、.dart_tool）由子模組自己的 clean.ps1 處理，
    本腳本不越界清理子模組。
.EXAMPLE
    .\clean.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

$build = Join-Path $root 'build'
if (Test-Path -LiteralPath $build) {
    Remove-Item -LiteralPath $build -Recurse -Force
    Write-Host "已刪除 $build" -ForegroundColor Green
} else {
    Write-Host '沒有 build 目錄。' -ForegroundColor DarkGray
}

$dist = Join-Path $root 'internal\webassets\dist'
if (Test-Path -LiteralPath $dist) {
    Get-ChildItem -LiteralPath $dist -Force |
        Where-Object { $_.Name -ne '.keep' } |
        Remove-Item -Recurse -Force
    Write-Host "已清理 $dist（保留 .keep）" -ForegroundColor Green
} else {
    Write-Host '沒有 internal/webassets/dist 目錄。' -ForegroundColor DarkGray
}
