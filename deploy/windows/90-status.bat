@echo off
title 5G core - status
for /f "usebackq delims=" %%i in (`wsl -e wslpath -a "%~dp0..\.."`) do set REPO=%%i
for /f "usebackq delims=" %%i in (`wsl -e bash -c "echo $HOME"`) do set WSLHOME=%%i
wsl -e env G5C_RUN=%WSLHOME%/g5c-run G5C_BIN_DIR=%WSLHOME%/.cache/g5c-bin/bin bash "%REPO%/deploy/run/g5c-cluster.sh" status
echo.
pause
