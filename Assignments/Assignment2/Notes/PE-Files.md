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
____

## `plink.exe`

### Overview:
`plink.exe` is a command-line tool from the PuTTY suite, commonly used for SSH connections. However, its presence in the `\Windows\Temp\` directory and its execution under suspicious circumstances are strong indicators of potential malicious activity.

### Key Details from the Investigation:

1. **File Path and Execution**:
   - **Location**: `\Windows\Temp\plink.exe`
   - **Prefetch File**: Indicates that `plink.exe` was executed on the system.
   - **First Seen**: `17/08/2019 05:52:31 AM (UTC)`
   - **Run Count**: The executable has been run at least once based on the prefetch file.

2. **Process Information**:
   - **Process ID**: 4016
   - **Parent Process ID**: 9920
   - **Execution Time**: `17/08/2019 05:52:31 AM (UTC)`
   - **Memory Artifacts**: Loaded libraries and DLLs include several core system files, indicating active use of `plink.exe` during the session.
   - **Security Identifiers**: The process ran under the Local System account and had administrative privileges.

3. **Suspicious Activity**:
   - **Command-Line Arguments**: The command executed with `plink.exe` included connecting to a remote server (`69.50.64.20`) on port 22 and forwarding a local port (`127.0.0.1:12345`) to a remote IP (`10.2.0.2:3389`), which suggests remote access or tunneling.
   - **Potential Data Exfiltration**: The use of SSH to create a reverse tunnel could facilitate unauthorized remote access or data exfiltration.

4. **Prefetch Information**:
   - **File Hash**: `423EF47C`
   - **Prefetch Path**: `Windows\Prefetch\PLINK.EXE-423EF47C.pf`
   - **Volume Name**: `\VOLUME{01d5382712c52860-b2135219}`
   - **Execution Dates**: Shows detailed records of the last eight times `plink.exe` was run, with the last run on `17/08/2019`.

### Indicators of Malicious Activity:

- **Unusual Location**: `plink.exe` being located in the `\Windows\Temp\` directory is suspicious since legitimate applications are typically not stored here.
- **SSH Tunneling**: The command-line usage of `plink.exe` to set up SSH tunnels is often associated with malicious activities, such as creating backdoors or bypassing network security controls.
- **Administrative Privileges**: Running under the Local System account with administrative rights further indicates potential misuse, as it suggests the process had unrestricted access to the system.

### Recommendations:

1. **Containment**:
   - Immediately terminate any active sessions related to `plink.exe`.
   - Isolate the affected system to prevent further unauthorized access or data exfiltration.

2. **Further Investigation**:
   - Investigate the parent process (PID: 9920) to identify how `plink.exe` was launched.
   - Review network traffic logs around the time of execution for any signs of data being sent to the remote IP address (`69.50.64.20`).

3. **System Hardening**:
   - Implement tighter security controls to prevent unauthorized binaries from being executed from temporary directories.
   - Monitor and restrict the use of remote access tools like PuTTY on sensitive systems.

### Conclusion:
The presence of `plink.exe` in the `\Windows\Temp\` directory, its execution with SSH tunneling commands, and the use of administrative privileges strongly suggest that it was used maliciously to establish a backdoor or for data exfiltration purposes. Immediate action is required to mitigate the threat.

____
## Mismatched Hashes for `OneDriveSetup.exe`
   - **Hash from the Known Good Version**:
     - **MD5**: 1941AED7D47CA3A8DA33D98B6D877E88
     - **SHA-256**: 9B1D2D09D1D26A0B6558828017E47A06357BA1B19FE18DF746934692D69976CC6
   - **Hash from the Folder Under Examination**:
     - **MD5**: 5227633dd8fa0f4b4845b360906ac9bc
     - **SHA-256**: a4cd491248830ad4986acc6f0217407cbcc278f0a9396c3566da8db93f54009d
   - **Analysis**:
     - The significant difference in hashes between the known good version of `OneDriveSetup.exe` and the version found in the OneDrive folder under examination indicates that the latter has likely been altered or replaced.
     - **Risk Implication**: This alteration strongly suggests malicious intent. The attacker might have replaced the legitimate installer with a trojanized version to gain persistence or execute further malicious activities on the compromised system.
     - **Action**: This altered `OneDriveSetup.exe` should be treated as highly suspect and requires deep analysis, including static and dynamic analysis to determine its true purpose and functionality. Additionally, check if this altered executable was executed, which could provide further insight into the attack's progression.

### Conclusion
- The presence of duplicate `CollectSyncLogs.bat` files in different folders, the discrepancy in the file count between similar folders, and the mismatched hashes for `OneDriveSetup.exe` all point towards a likely compromise involving these files. The evidence suggests that the attacker may have used these files to establish or maintain persistence, execute malicious payloads, and potentially collect sensitive data.

This analysis underscores the need for further investigation into these artifacts, including checking for any related network activity, cross-referencing with system and application logs, and examining other files in the surrounding directories.
