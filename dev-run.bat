chcp 65001 >nul
setlocal
title EvernightRealm
echo EvernightRealm

if not defined PROXY_URL   set "PROXY_URL=http://192.168.255.1:23334"
if not defined HTTPS_PROXY set "HTTPS_PROXY=%PROXY_URL%"
if not defined HTTP_PROXY  set "HTTP_PROXY=%PROXY_URL%"
if not defined NO_PROXY    set "NO_PROXY=127.0.0.1,localhost"

echo chk...

where go >nul 2>nul
if errorlevel 1 (
  echo ERR NO GO
  exit /b 1
)
where flutter >nul 2>nul
if errorlevel 1 (
  echo ERR NO FLUTTER
  exit /b 1
)

set "FRONTEND_DEVICE=windows"
if /i "%~1"=="web" set "FRONTEND_DEVICE=chrome"

start "evernight-server (backend)" cmd /k "title evernight-server (backend) && cd /d %~dp0 && go run -v ./cmd/evernight-server"

start "EvernightRealmAPP (frontend)" cmd /k "title EvernightRealmAPP (frontend) && cd /d %~dp0EvernightRealmAPP && flutter run -v -d %FRONTEND_DEVICE%"

rem timeout 只寫命令名時，會被 PATH 上較前的 GNU coreutils 版搶走（實測：Git for Windows 的 usr\bin 在 PATH 上時，
rem 只會印出 "Try 'timeout --help'" 而不是等待）。這裡直接取系統目錄那份，並不可被鍵盤中斷。
"%SystemRoot%\System32\timeout.exe" /t 3 /nobreak >nul
exit /b 0
