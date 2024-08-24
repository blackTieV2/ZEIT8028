## **`Sticky.ps1`**

- **Purpose**: The `sticky.ps1` script is designed to exploit the **Sticky Keys** feature in Windows by modifying the Windows Registry. Specifically, it replaces the Sticky Keys executable (`sethc.exe`) with the Command Prompt (`cmd.exe`), enabling an attacker to launch a command prompt with system-level privileges without needing to log in.

- **Operation**:
  - **Registry Path**: The script targets the registry key at `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe`.
  - **Registry Modification**:
    - The script first checks if the specified registry path exists. If not, it creates it.
    - It then adds a new property named `"Debugger"` with the value `"C:\windows\system32\cmd.exe"` to this registry key.
    - By setting this property, the script essentially tells Windows to launch `cmd.exe` whenever `sethc.exe` (Sticky Keys) is triggered.

- **Effect**:
  - After executing this script, pressing `Shift` five times on the Windows login screen will open a command prompt instead of the Sticky Keys dialog. This command prompt runs with system privileges, giving the user or attacker full control over the system.

## **Indicators of Malicious Activity:**

- **Registry Modification**:
  - **Unusual Registry Key**: The script modifies a key under `Image File Execution Options`, which is commonly abused by attackers to redirect the execution of certain applications, such as accessibility tools, to other executables (e.g., `cmd.exe`).
  - **Debugger Property**: The creation of a `"Debugger"` property pointing to `cmd.exe` is a classic indicator of an attempt to bypass security controls and gain unauthorized access.

- **Privilege Escalation**:
  - **Unauthorized Access**: The script is designed to provide system-level command-line access, bypassing normal authentication mechanisms, which is a clear sign of a privilege escalation attempt.

- **Potential Persistence**:
  - **Sticky Keys Exploit**: This method can be used to maintain unauthorized access to a system, as it allows an attacker to open a command prompt with elevated privileges at any time from the login screen.

## **Conclusion:**

The `sticky.ps1` script is a clear example of a malicious script designed to facilitate unauthorized access to a Windows system. By exploiting the Sticky Keys feature, it allows an attacker to bypass the login screen and gain system-level access through a command prompt. This type of attack is particularly dangerous because it requires minimal interaction from the user and can be executed even if the system is locked.

**Recommendations**:
- **Immediate Action**: If this script is found on a system, it is crucial to investigate further to determine how it was introduced and whether unauthorized access has been gained.
- **Mitigation**: Restore the original `sethc.exe` behavior by removing the `"Debugger"` property or setting it back to its default value.
- **Monitoring**: Implement monitoring to detect future attempts to modify the registry in this manner, and consider restricting access to the registry for non-administrative users.
_____________________
Here’s a comprehensive overview of the `ElevateExecute.ps1` script, integrating your provided context with my earlier analysis:

---

## **ElevateExecute.ps1**

### **Overview**:
`ElevateExecute.ps1` is a PowerShell script designed to execute a specified script or program with elevated privileges, bypassing User Access Control (UAC). This is significant as it allows the execution of potentially harmful actions on the system without user consent or awareness, enabling attackers to escalate privileges and execute additional malicious scripts or programs.

### **Script Functionality**:

1. **Parameters**:
   - **$ScriptPath**: This mandatory parameter specifies the path to the script that is intended to be executed with elevated privileges.

2. **Privilege Elevation**:
   - **Registry Modification**: 
     - The script modifies the registry at `HKCU:\Software\Classes\Folder\shell\open\command` to set the `(Default)` value to `PowerShell.exe -File $ScriptPath`. This registry key is typically associated with folder actions, and altering it can hijack the execution path.
     - A `DelegateExecute` property is also added, which is a known technique for UAC bypass. By leveraging this registry change, the script forces the system to execute the specified PowerShell script with elevated privileges.
   - **Execution via `sdclt.exe`**:
     - The script uses the legitimate Windows binary `sdclt.exe`, which is vulnerable to UAC bypass. By launching this executable, the system is tricked into running the PowerShell script specified in the registry key with elevated privileges, bypassing UAC prompts.
   - **Cleanup**:
     - After the script has been executed, the registry changes are undone, removing the `(Default)` and `DelegateExecute` properties, thus erasing traces of the elevation technique used.

3. **Program Execution**:
   - **Start-Process**: If the script runs with administrative privileges, it will execute the specified script using `Start-Process`, ensuring that any subsequent commands or scripts are also executed with elevated rights.

### **Indicators of Malicious Activity**:

- **Privilege Escalation**:
  - The script is specifically designed to force elevation by exploiting a UAC bypass technique. This is a red flag, as it can be used to run other malicious scripts with administrative privileges, bypassing standard security controls.

- **Suspicious Context**:
  - The presence and use of this script alongside other potentially malicious scripts (like `vagrant-shell.ps1` and `sticky.ps1`) suggest it is part of a coordinated attack to gain and maintain elevated access on a compromised system.

### **Timeline Integration**:

- **August 17, 2019, 05:36 AM**:
  - The script was executed as part of a sequence of actions that included the execution of `vagrant-shell.ps1` and `winrm-elevated-shell.ps1`. This timeline indicates that the attacker first used `ElevateExecute.ps1` to gain administrative privileges and then deployed additional scripts to disable security features, capture data, or establish persistence.

### **Key Logs and Evidence**:

- **Event ID 4104**:
  - This event ID in the Windows Event Logs indicates that a PowerShell script was executed. When correlated with `ElevateExecute.ps1`, it likely reflects the script being run with elevated privileges, possibly after bypassing UAC. This can be tied to other suspicious script executions around the same time, strengthening the case for a coordinated attack.

- **Prefetch Information**:
  - Analysis of prefetch files shows that `ElevateExecute.ps1` was executed multiple times. This repeated execution could indicate attempts to ensure the successful deployment of the attacker’s payloads, especially in cases where initial attempts to escalate privileges or run malicious code may have failed.

### **Conclusion**:
`ElevateExecute.ps1` is a script that abuses a known UAC bypass technique to escalate privileges and execute a specified script with administrative rights. The use of this script, especially in the context of other malicious activities, strongly suggests that it is part of a broader attack aimed at compromising system security, gaining elevated access, and executing further malicious payloads. Immediate investigation and remediation are recommended if this script is detected in a system.

---

This comprehensive analysis covers the purpose, functionality, and potential malicious use of `ElevateExecute.ps1`, providing a detailed understanding of its role within a broader attack framework.
____
___

## `vagrant-shell.ps1` PowerShell script.

### Key Event Data Points:

1. **Event ID 4104 (PowerShell Script Block Logging)**
   - **Content of Script Blocks**: 
     - The script references a file, `vagrant-shell.ps1`, stored in the `/tmp/` directory, and it performs operations such as creating file streams, handling file paths, and clearing PowerShell script block caches.
     - Functions like `Cleanup`, `Check-Files`, and `Get-SHA1Sum` suggest that the script might be verifying the integrity of files by calculating their SHA1 hashes and comparing them with known values.
     - The script contains a section to ensure a destination directory exists and, if it doesn't, it creates it (`mkdir $parent`).
     - It also calls an internal PowerShell method `ClearScriptBlockCache`, likely intended to manage memory usage or to remove traces of previously executed script blocks, which is suspicious.

2. **Event ID 600 (PowerShell Host Startup)**
   - **Host Application**: The PowerShell script was executed with the command line: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -OutputFormat Text -file c:\tmp\vagrant-shell.ps1`.
   - **Execution Policy**: The `-ExecutionPolicy Bypass` parameter is significant because it allows the script to bypass system-wide execution policies, which is often seen in malicious scripts to avoid detection.
   - **Providers Started**: The logs show that various providers like `Registry`, `Alias`, `FileSystem`, and `Function` were started, indicating that the script was interacting with these components.

3. **Event ID 400 and 403 (PowerShell Engine State Changes)**
   - These events log changes in the state of the PowerShell engine, such as starting and stopping, associated with the execution of the `vagrant-shell.ps1` script.

### Analysis:

- **Malicious Indicators**:
  - **Bypass Execution Policy**: The use of `-ExecutionPolicy Bypass` is a red flag. It suggests that the script is trying to avoid any restrictions that might prevent it from running, which is typical behavior for malicious or unauthorized scripts.
  - **Clearing Script Block Cache**: The script includes code to clear the PowerShell script block cache. This could be an attempt to remove traces of previously executed code, which is suspicious and could indicate an effort to hide malicious activity.
  - **File Integrity Checks**: The script performs SHA1 hash checks on files, which could either be a legitimate operation (e.g., ensuring the integrity of configuration files) or could be part of a malware's internal checks to ensure its payloads haven't been tampered with.

### Script Overview:

The `vagrant-shell.ps1` script is highly suspicious and likely malicious based on the following key actions it performs:

1. **Disabling Windows Defender Features**:
   - The script uses **Set-MpPreference** commands to disable critical Windows Defender features, including:
     - **Real-Time Monitoring**: Stops real-time protection that scans files as they are accessed or downloaded.
     - **Behavior Monitoring**: Disables monitoring for suspicious application behavior.
     - **Script and Archive Scanning**: Prevents scanning of scripts and archives, which could allow the execution of other malicious files undetected.
     - **Network and Removable Drive Scanning**: Disables scanning of files on USB drives, network drives, and mapped drives.
   - **Summary**: These actions significantly reduce the system’s security, making it vulnerable to malware and other attacks.

2. **Persisting Changes in the Registry**:
   - The script modifies registry keys under `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender` to ensure that Windows Defender remains disabled even after a system reboot.
   - **Registry Keys Affected**:
     - **DisableAntiSpyware**: Completely disables Windows Defender AntiSpyware.
     - **DisableRealtimeMonitoring**: Ensures real-time monitoring stays off.
     - **DisableBehaviorMonitoring**: Keeps behavior monitoring off.
     - **DisableOnAccessProtection** and **DisableScanOnRealtimeEnable**: These further reduce the system's ability to protect against and detect malware in real-time.

### Indicators of Malicious Intent:

- **Complete Disabling of Security Features**: The script systematically disables almost all protective features of Windows Defender, which is a strong indicator of malicious intent. This behavior is typical of malware that aims to avoid detection and facilitate further malicious activity, such as downloading additional payloads, stealing data, or providing remote access to attackers.
- **Persistence Through Registry Changes**: By modifying the registry, the script ensures that these settings are preserved across reboots, making the system persistently vulnerable. This is a common tactic used by malware to maintain a foothold on the system.

### Conclusion:
The `ElevateExecute.ps1` script is likely part of a broader attack strategy aimed at elevating privileges to run other malicious scripts. Its presence and usage, particularly in close proximity to other malicious activities, reinforce its suspicious nature and justify further investigation.
_____

## `WinRM_Elevated_Shell.ps1`

The `WinRM_Elevated_Shell` scheduled task is highly suspicious and likely malicious based on the following key indicators:

### Key Details:
1. **Scheduled Task Name**: `WinRM_Elevated_Shell`
   - **Command**: Executes `cmd` with the following arguments:  
     ```
     /c powershell.exe -executionpolicy bypass -NoProfile -File c:/windows/temp/winrm-elevated-shell-f5d625ea-66b1-4480-bf3c-f84423135094.ps1 > C:\Users\Alan\AppData\Local\Temp\tmp95BE.tmp 2>C:\Users\Alan\AppData\Local\Temp\tmp95BF.tmp
     ```
   - **Privilege Level**: `HighestAvailable`, which means it runs with the highest privileges available to the user, potentially Administrator rights.
   - **Hidden**: The task is not hidden (`Hidden: false`), which might be an attempt to blend in with legitimate tasks by not drawing attention.
   - **Run As**: The task runs under the `alan` user account.

2. **Execution Policy**:
   - **Bypass Execution Policy**: The `-executionpolicy bypass` flag allows the script to bypass any restrictions, which is a common tactic used by attackers to execute malicious scripts that would otherwise be blocked.

3. **Script Path**:
   - **Script Location**: The script is located in `c:/windows/temp/`, which is an unusual location for legitimate PowerShell scripts, adding to the suspicion.

4. **Output Redirection**:
   - **Standard Output and Error Redirection**: The output and error are redirected to temporary files (`tmp95BE.tmp` and `tmp95BF.tmp`) in the `AppData\Local\Temp\` directory, possibly to hide the script's output from view and facilitate later analysis or exfiltration by the attacker.

### Additional Information:

**Metadata**:
- **File Path**: `/img_disk.raw/vol_vol7/Windows/System32/Tasks/WinRM_Elevated_Shell`
- **File Type**: XML (application/xml)
- **File Size**: 3152 bytes
- **File Creation Date**: 2019-08-17 05:36:28 (GMT)
- **File Modified Date**: 2019-08-17 05:36:40 (GMT)
- **Hash (SHA-256)**: `90857bb771e15c4f9eeb8dbea730d753650a859fce105f0239410876a56029a0`
- **MFT Entry**: 77904 Sequence: 5, indicating the file's placement in the filesystem.

### Extracted Text and Additional Context:

The task definition includes specific details that further point to malicious intent:

- **Task Content**:
  - The scheduled task executes a PowerShell script with elevated privileges, directing its output to temporary files. 
  - The script is stored in the `c:/windows/temp/` directory and is designed to remove itself after execution, a typical behavior of malicious scripts aiming to cover their tracks.

- **Temporary Files**:
  - **Output Files**: `C:\Users\Alan\AppData\Local\Temp\tmp95BE.tmp` and `C:\Users\Alan\AppData\Local\Temp\tmp95BF.tmp` are used to store the standard output and errors of the PowerShell script, likely to keep the execution quiet.

### Indicators of Malicious Activity:

- **Execution Policy Bypass**: The use of `-executionpolicy bypass` is a strong indicator of malicious intent, as it overrides any system policies meant to protect against unauthorized scripts.
- **Elevated Privileges**: The task is set to run with the highest privileges available, which could allow it to perform actions that require administrative rights, such as disabling security controls or accessing sensitive files.
- **Suspicious File Paths**: The use of temporary directories (`c:/windows/temp/` and `AppData\Local\Temp`) is typical for malicious activities, where attackers want to store files in locations that are less likely to be scrutinized by users or security software.
- **Obfuscation and Redirection**: The redirection of output and errors to temporary files might indicate an attempt to keep logs of the task's execution or to gather information without alerting the user.

### Conclusion:

The `WinRM_Elevated_Shell` task is a significant indicator of malicious activity. Its creation and execution are designed to grant elevated privileges, bypass security mechanisms, and hide its tracks, making it a likely tool for maintaining persistence or carrying out further attacks on the compromised system. Immediate remediation actions should include disabling and removing the task, restoring any security settings it may have altered, and conducting a thorough investigation to determine the full scope of the compromise.


____________
