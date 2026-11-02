@echo off
rem Opens one window per network function, in the order they depend on each other (the NRF first).
call "%~dp0settings.bat"
start "5G core - nrf"       "%~dp01-nrf.bat"
timeout /t 2 /nobreak >nul
start "5G core - scp"       "%~dp012-scp.bat"
timeout /t 1 /nobreak >nul
start "5G core - bsf"       "%~dp013-bsf.bat"
timeout /t 1 /nobreak >nul
start "5G core - udr"  "%~dp02-udr.bat"
timeout /t 1 /nobreak >nul
start "5G core - nssf"      "%~dp010-nssf.bat"
start "5G core - nef"       "%~dp011-nef.bat"
start "5G core - udm"       "%~dp03-udm.bat"
start "5G core - ausf" "%~dp04-ausf.bat"
start "5G core - pcf"       "%~dp05-pcf.bat"
timeout /t 2 /nobreak >nul
start "5G core - upf"       "%~dp06-upf.bat"
timeout /t 2 /nobreak >nul
start "5G core - smf"       "%~dp07-smf.bat"
timeout /t 2 /nobreak >nul
start "5G core - amf"       "%~dp08-amf.bat"
