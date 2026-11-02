@echo off
rem Builds the network functions once (inside WSL) and writes their configuration. Run this first, and again after the source changes.
title 5G core - prepare
color 0E
for /f "usebackq delims=" %%i in (`wsl -e wslpath -a "%~dp0..\.."`) do set REPO=%%i
echo Building the network functions in WSL (a few minutes the first time)...
wsl -e bash -lc "cd '%REPO%' && bash scripts/c_install.sh && bash deploy/run/g5c-cluster.sh conf-once"
if errorlevel 1 (
  echo.
  echo The build failed - see the messages above.
) else (
  echo.
  echo Done. Start the functions with 1-nrf.bat ... 8-amf.bat, or 9-start-all.bat.
)
pause
