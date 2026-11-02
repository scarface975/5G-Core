@echo off
rem Starts one network function in this window. Called by the numbered .bat files: _run.bat <nf> [root]
setlocal
set NF=%~1
set AS_ROOT=%~2
title 5G core - %NF%
color 0B
call "%~dp0settings.bat"

where wsl >nul 2>nul
if errorlevel 1 (
  echo WSL is not installed. The network functions run in WSL Ubuntu.
  pause
  exit /b 1
)

for /f "usebackq delims=" %%i in (`wsl -e wslpath -a "%~dp0."`) do set WIN_DIR=%%i
for /f "usebackq delims=" %%i in (`wsl -e bash -c "echo $HOME"`) do set WSLHOME=%%i

set USER_ARGS=
if "%AS_ROOT%"=="root" set USER_ARGS=-u root

echo.
echo  5G core: starting %NF%  (close this window or press Ctrl+C to stop it)
echo.
wsl %USER_ARGS% -e env G5C_HOME=%WSLHOME% %G5C_EXTRA_ENV% bash "%WIN_DIR%/nf.sh" %NF%
echo.
echo  [%NF% has stopped - press a key to close]
pause >nul
