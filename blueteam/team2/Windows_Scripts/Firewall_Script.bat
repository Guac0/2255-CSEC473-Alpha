@echo off





net session >nul 2>&1
if %errorLevel% == 0 (
    echo [+] Running as Administrator
) else (
    echo [ERROR] This script must be run as Administrator.
    pause
    exit /b 1
)


netsh advfirewall set allprofiles state on
if %errorLevel% neq 0 (
    echo [ERROR] Failed to enable firewall.
    pause
    exit /b 1
)


netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound


netsh advfirewall set allprofiles logging filename %systemroot%\system32\logfiles\firewall\pfirewall.log

netsh advfirewall set allprofiles logging maxfilesize 4096

netsh advfirewall set allprofiles logging droppedconnections enable

netsh advfirewall set allprofiles logging allowedconnections enable
e


REM netsh advfirewall firewall add rule name="Block RPC Endpoint Mapper Port 135" dir=in action=block protocol=TCP localport=135
REM netsh advfirewall firewall add rule name="Block NetBIOS Name Service Port 137" dir=in action=block protocol=TCP localport=137
REM netsh advfirewall firewall add rule name="Block NetBIOS Datagram Service Port 138" dir=in action=block protocol=TCP localport=138
REM netsh advfirewall firewall add rule name="Block NetBIOS Session Service Port 139" dir=in action=block protocol=TCP localport=139
REM netsh advfirewall firewall add rule name="Block SMB Port 445" dir=in action=block protocol=TCP localport=445


netsh advfirewall firewall add rule name="Allow DHCP" dir=in action=allow protocol=UDP localport=68
netsh advfirewall firewall add rule name="Allow DNS" dir=out action=allow protocol=UDP remoteport=53
netsh advfirewall firewall add rule name="Allow Windows Update" dir=out action=allow protocol=TCP remoteport=80,443
netsh advfirewall firewall add rule name="Allow ICMP Ping" protocol=icmpv4:8,any dir=in action=allow
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes




REM set suspicious_ips=192.168.1.100 10.0.0.1
REM for %%i in (%suspicious_ips%) do (
REM     netsh advfirewall firewall add rule name="Block IP %%i" dir=in action=block remoteip=%%i
REM     echo [+] Blocking inbound traffic from %%i
REM )


echo Waiting 15 seconds for dead man's switch connectivity check...
timeout /t 15 /nobreak >nul
echo Checking outbound connectivity...
ping -n 1 8.8.8.8 >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Connectivity check failed. The machine may be bricked. Reverting firewall to off for safety.
    netsh advfirewall set allprofiles state off
) else (
    echo [+] Connectivity check passed. Firewall changes appear successful.
)



echo [+] Done
echo [INFO] Check logs at: %systemroot%\system32\logfiles\firewall\pfirewall.log


pause