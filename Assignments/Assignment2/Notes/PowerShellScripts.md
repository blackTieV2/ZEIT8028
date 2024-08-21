## `Sticky.ps1`

The `Sticky.ps1` PowerShell script is designed to capture screenshots of the desktop at regular intervals, saving the images to a publicly accessible directory. This script is likely used for data exfiltration and is highly suspicious due to its functionality.

### Script Overview:

1. **Screen Capture Functionality**:
   - The script runs in an infinite loop, capturing the screen every 30 seconds using .NET's `System.Drawing` and `System.Windows.Forms` libraries.
   - Each screenshot is saved as a PNG file in `C:\Users\Public\Pictures\` with a filename that includes a timestamp (e.g., `ss_20240821_112026.png`).

2. **Infinite Loop**:
   - The `while ($true)` loop ensures that the script continuously captures screenshots without stopping, which is a typical behavior in scripts designed for continuous monitoring or data gathering.

3. **File Storage**:
   - Screenshots are stored in a publicly accessible directory (`C:\Users\Public\Pictures\`). This location is often used in attacks to make it easier for attackers to retrieve the captured data, especially if the system is later compromised for file access.

### Indicators of Malicious Activity:

- **Continuous Monitoring**:
  - The script’s infinite loop suggests it is intended to run indefinitely, capturing potentially sensitive information displayed on the screen over time.

- **Public Directory for Storage**:
  - Storing files in `C:\Users\Public\Pictures\` may facilitate easy retrieval of the screenshots by an attacker or by another component of the attack.

- **Data Exfiltration Potential**:
  - The captured screenshots could be used to gather information about the victim's activities, including sensitive data such as passwords, financial information, or confidential documents.

### Connections to Other Scripts:

- **Possible Link to `vagrant-shell.ps1`**:
  - The `Sticky.ps1` script may be used in conjunction with `vagrant-shell.ps1`, which disables Windows Defender and establishes persistence. After disabling defenses, `Sticky.ps1` could be deployed to silently capture data from the compromised system.

### Next Steps for Investigation:

1. **Check for Scheduled Tasks**:
   - Investigate whether `Sticky.ps1` is run as part of a scheduled task or any other persistence mechanism set up by other scripts or attackers.

2. **Search for Captured Data**:
   - Examine the `C:\Users\Public\Pictures\` directory to see if there are any saved screenshots, which could provide insights into what the attacker was monitoring.

3. **Review PowerShell Logs**:
   - Analyze PowerShell event logs to identify when and how `Sticky.ps1` was executed, and whether it was triggered by another script or task.

### Conclusion:

The `Sticky.ps1` script is a clear indicator of malicious activity, designed to capture and possibly exfiltrate sensitive information from the victim's system. It should be treated with caution, and immediate steps should be taken to remove it from the system and investigate any further compromises it may be associated with.
_____________________
## `ElevateExecute.ps1`

### Overview:
`ElevateExecute.ps1` is a PowerShell script designed to ensure that specified programs or scripts run with elevated privileges. This is significant because it can be used to execute other scripts or programs with administrative rights, bypassing User Access Control (UAC) and potentially leading to unauthorized actions on the system.

### Script Functionality:

1. **Parameters**:
   - **$Program**: Path to the program or script to be executed.
   - **$Arguments**: Optional arguments for the program.

2. **Privilege Elevation**:
   - **Admin Check**: The script checks if it is running with administrative privileges using the `Test-IsAdmin` function.
   - **Re-launch with Elevated Rights**: If not running as an admin, the script will re-launch itself with elevated privileges using the `runas` verb.

3. **Program Execution**:
   - If running as an administrator, the script will execute the specified program with any provided arguments using `Start-Process`.

### Indicators of Malicious Activity:

- **Privilege Escalation**: The script is designed to force elevation, which can be exploited to run other malicious scripts with administrative privileges, bypassing security controls.
- **Suspicious Context**: The script's presence and execution alongside other malicious scripts, such as `vagrant-shell.ps1` and `Sticky.ps1`, suggest that it is part of a coordinated attack.

### Timeline Integration:

- **August 17, 2019, 05:36 AM**:
  - The script was executed as part of a sequence of actions that included the execution of `vagrant-shell.ps1` and `winrm-elevated-shell.ps1`. This timeline suggests that the attacker first used `ElevateExecute.ps1` to gain administrative privileges and then deployed additional scripts to disable security features and capture data.

### Key Logs and Evidence:

- **Event ID 4104**:
  - Indicates that the script was run with elevated privileges, possibly after bypassing UAC.
  - Correlated with the execution of other suspicious scripts at the same time .

- **Prefetch Information**:
  - Shows that `ElevateExecute.ps1` was executed multiple times, likely to ensure the successful deployment of the attacker’s payloads .
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

