@echo off
rem Optional settings shared by all the .bat files here. Everything works without changes when the gNB / UE run inside WSL.
rem
rem G5C_EXTRA_ENV: extra VAR=value pairs passed to every network function, separated by spaces. Examples:
rem   set G5C_EXTRA_ENV=G5C_LOG_LEVEL=debug
rem   set G5C_EXTRA_ENV=G5C_AMF_ADDR=172.20.10.5 G5C_UPF_ADDR=172.20.10.5
rem The addresses default to 127.2.0.x (all inside WSL):
rem   UDR 127.2.0.201:7790   UDM 127.2.0.1:7773   AUSF 127.2.0.2:7774   PCF 127.2.0.3:7775
rem   SMF 127.2.0.4:7776 (N4 127.2.0.4:8805)   AMF 127.2.0.5:7777 (N2 SCTP 127.2.0.5:38412)   UPF 127.2.0.7 (N4 8805, N3 2152, SBI 9091)
rem If you change an address, change it in every window (this file is shared) and delete %USERPROFILE%-side g5c-run\conf in WSL
rem (~/g5c-run/conf) so that the configurations are generated again.
set G5C_EXTRA_ENV=
