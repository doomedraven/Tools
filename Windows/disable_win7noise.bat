REM HELP
REM http://www.windows-commandline.com/start-stop-service-command-line/
REM disable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
REM disable Windows defender
sc config WinDefend start= disabled
REM disable windows update
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 1 /f
REM disable aero
net stop uxsms
REM disable the firewall
netsh firewall set opmode mode=DISABLE
REM disable IPv6
netsh interface teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
netsh interface ipv6 isatap set state state=disabled
REM disable active probing
reg add  "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v EnableActiveProbing /t REG_DWORD /d 0 /f
REM disable SSDP
sc config SSDPSRV start= disabled
net stop SSDPSRV
REM disable computer browsing
sc stop Browser
sc config Browser start= disabled
REM disable WinHTTP Web Proxy Auto-Discovery
reg add "HKLM\SYSTEM\CurrentControlSet\services\WinHttpAutoProxySvc" /v Start /t REG_DWORD /d 4 /f
REM disable Function Discovery Resource Publication service
reg add "HKLM\SYSTEM\CurrentControlSet\services\FDResPud" /v Start /t REG_DWORD /d 4 /f
REM IE blank page
reg add "HKCU\Software\Microsoft\Internet Explorer\Main" /V "Start Page" /D "" /F
REM disable IExplorer Proxy
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t  REG_DWORD /d 00000000 /f
REM disable netbios in TCP/IP
wmic nicconfig where index=8 call SetTcpipNetbios 2
REM disable netbios service
reg add "HKLM\SYSTEM\CurrentControlSet\services\Imhosts" /v Start /t REG_DWORD /d 4 /f
REM disable LLMNR
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f
REMdisable SQM
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\FlexGo\FGNotify\Prechecks"  /v Sqm /t REG_DWORD /d 00000002 /f
REM Disable cert check
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\SslBindingInfo" /v DefaultSslCertCheckMode /t REG_DWORD /d 1 /f
; disable ClickToRunSvc
sc stop "ClickToRunSvc" 
sc config "ClickToRunSvc" start= disabled 
