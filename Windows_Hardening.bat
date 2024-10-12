@echo off
REM Windows Security Hardening Script
REM CyberPatriot Competition

echo Starting Windows system hardening...

REM Disable unnecessary services
echo Disabling unnecessary services...
sc config "Fax" start= disabled
sc config "XblAuthManager" start= disabled
sc config "XblGameSave" start= disabled
sc config "XboxGipSvc" start= disabled
sc config "XboxNetApiSvc" start= disabled
sc config "wuauserv" start= auto

REM Disable guest account
echo Disabling guest account...
net user Guest /active:no

REM Enforce password complexity
echo Enforcing password complexity policy...
secedit /export /cfg %temp%\secpol.cfg
findstr /v "PasswordComplexity" %temp%\secpol.cfg > %temp%\newsecpol.cfg
echo PasswordComplexity = 1 >> %temp%\newsecpol.cfg
secedit /configure /db %windir%\security\local.sdb /cfg %temp%\newsecpol.cfg

REM Set password expiration policy
echo Setting password expiration policy...
wmic path Win32_UserAccount set PasswordExpires=True

REM Remove all sound files (common formats)
echo Removing all sound files from the system...
for /r C:\ %%f in (*.mp3 *.wav *.ogg *.flac *.aac) do del "%%f" /f /q

REM Disable unnecessary network services
echo Disabling unnecessary network services...
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

REM Disable autoplay for all drives
echo Disabling autoplay...
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

REM Enable Windows Defender (if not already enabled)
echo Enabling Windows Defender...
sc config WinDefend start=auto
sc start WinDefend

REM Update the system
echo Updating system...
powershell -Command "Install-Module PSWindowsUpdate -Force -Confirm:$false"
powershell -Command "Get-WindowsUpdate -Install -AcceptAll -AutoReboot"

REM Check installed updates
echo Checking installed updates...
systeminfo | findstr /C:"KB"

echo Windows system hardening completed.
pause