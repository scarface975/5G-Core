@echo off
rem Stops every network function (all windows) - for a function whose window was closed badly.
title 5G core - stop all
wsl -u root -e bash -c "for n in amf smf upf pcf ausf udm nef scp bsf nssf udr nrf; do pkill -x $n 2>/dev/null; done; echo stopped"
pause
