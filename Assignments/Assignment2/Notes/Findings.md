## `RESUME.DOC.EXE`
### Key Data Points:
1. **Application Name**: `RESUME.DOC.EXE`
2. **Application Path**: `\VOLUME{01d5382712c52860-b2135219}\USERS\ALAN\DOWNLOADS\RESUME.DOC.EXE`
3. **Run Count**: `1` (The file was executed once.)
4. **File Created Date/Time**: `17/8/2019 5:42:15 AM`
5. **Last Run Date/Time**: `17/8/2019 5:41:59 AM`
6. **File Hash**: `AA8459C3` (Note: This is the hash from the AXIOM record. The full SHA-256 hash from VirusTotal is `bb3aef05f9007687f06fd26eab80612e5960249a5df74fe3ef6399b7c087b8e9`.)
7. **VirusTotal Detection**: **Malicious** (detected by 53 out of 70 antivirus engines)
8. **VirusTotal Link**: [VirusTotal Analysis for `RESUME.DOC.EXE`](https://www.virustotal.com/gui/file/bb3aef05f9007687f06fd26eab80612e5960249a5df74fe3ef6399b7c087b8e9)
9. **Volume Name**: `\VOLUME{01d5382712c52860-b2135219}`
10. **Volume Created Date/Time**: `11/7/2019 8:27:34 PM`
11. **File Location**: `.\Attachments\RESUME.DOC.EXE` and `.\Attachments\RESUME.DOC (1).EXE`
12. **Source**: `disk.raw - Partition 4 (Microsoft NTFS, 59.4 GB)`

### Analysis with VirusTotal Results:

1. **File Execution**:
   - **Created Date/Time vs. Last Run Date/Time**: The timestamps are almost identical, indicating `RESUME.DOC.EXE` was executed immediately after being created or downloaded.
   - **Run Count**: The file was executed once, which could be enough to initiate the malicious payload.

2. **File Hash and VirusTotal Detection**:
   - **SHA-256 Hash**: The file’s full SHA-256 hash is `bb3aef05f9007687f06fd26eab80612e5960249a5df74fe3ef6399b7c087b8e9`.
   - **VirusTotal Analysis**: The file is flagged as malicious by 53 out of 70 antivirus engines. This high detection rate confirms that `RESUME.DOC.EXE` is indeed malware, likely used to deliver a payload or perform malicious activities on the compromised system.
   - **Threat Classification**: Based on the detection by multiple antivirus engines, this file could be a dropper, a form of ransomware, or a Trojan. It is crucial to examine the specific classifications provided by the AV engines on VirusTotal to understand its exact behavior.

3. **File Location and Source**:
   - **Application Path**: The file was located in the `Downloads` folder, a common location for files downloaded from the internet, reinforcing the likelihood that the file was either delivered via a phishing email or downloaded from a malicious site.
   - **Prefetch File**: The prefetch file confirms execution, allowing you to track other files or processes that may have been affected during the execution.

4. **Potential Impact**:
   - **High Threat Level**: Given the high detection rate on VirusTotal, this file likely initiated a significant compromise on the system, possibly including data theft, system damage, or lateral movement within the network.

5. **Next Steps**:
   - **Investigate Further Based on VirusTotal Reports**: Review the detailed analysis on VirusTotal, including any behavior reports, domains, or IP addresses associated with the malware. This can help identify any Command and Control (C2) connections or additional payloads.
   - **Check for Persistence**: Investigate whether the malware installed any persistence mechanisms, such as registry keys or scheduled tasks, to survive reboots.
   - **Review Network Traffic**: Examine network logs to see if the malware attempted to communicate with external IPs, potentially exfiltrating data or downloading additional payloads.
   - **Correlate with Other Artifacts**: Cross-reference the execution of `RESUME.DOC.EXE` with other suspicious activities in system logs, memory dumps, and user behavior to build a comprehensive timeline of the attack.
---
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
