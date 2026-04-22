@echo off
REM Burp Suite Swiss Knife MCP - Windows setup (double-click-friendly wrapper)
REM Runs setup.ps1 bypassing the user's execution policy for this invocation only.

setlocal
pushd "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1"
set EXITCODE=%ERRORLEVEL%

echo.
pause
popd
exit /b %EXITCODE%
