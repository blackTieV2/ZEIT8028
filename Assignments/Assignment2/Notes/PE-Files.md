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
_____

Here is a detailed GitHub Markdown entry that contextualizes the investigation findings regarding the `scvhost.exe` file:

---

# **Malicious `scvhost.exe` File Investigation**

## **Overview**

During the investigation of the compromised system, a suspicious executable named `scvhost.exe` was discovered in the `Temp` directory of the user "Alan". The file exhibited several red flags, including being flagged as malicious by multiple security vendors and displaying characteristics typical of malware payloads. This document provides a detailed analysis of the file and its potential impact on the system.

## **File Information**

- **File Path**: `/img_disk.raw/vol_vol7/Users/Alan/AppData/Local/Temp/scvhost.exe`
- **File Type**: PE64 (Windows Executable)
- **Size**: 7.00 KB
- **MD5**: `2a51f5723eabc17be1336e93fd092f3d`
- **SHA-256**: `5581667dfe47539d04c47ff729bcd771f3df2772ce768e6746832c192a37f745`
- **MIME Type**: `application/x-dosexec`
- **Created**: `2019-08-17 13:48:39 SGT`
- **Modified**: `2019-08-17 13:48:39 SGT`
- **Accessed**: `2019-08-17 13:49:18 SGT`

## **Detection and Analysis**

### **VirusTotal Report**
The `scvhost.exe` file was analyzed on [VirusTotal](https://www.virustotal.com/gui/file/5581667dfe47539d04c47ff729bcd771f3df2772ce768e6746832c192a37f745), where it was flagged by **58 out of 71** security vendors as malicious. The detections included associations with various malware families, notably:

- **Trojan.Metasploit.A**
- **Win64: Evo-gen [Trj]**
- **Trojan.Win64.Shelma**
- **BackDoor.Shell.244**

### **File Characteristics**
- **Time Stamp Anomalies**: The file was created, modified, and accessed in a very short window of time, suggesting it was immediately executed after being dropped on the system.
- **PE Analysis**: The file uses outdated linker and assembler tools, which could indicate an attempt to evade modern security defenses.

### **Behavioral Indicators**
Given the context in which `scvhost.exe` was found—within the `Temp` directory of a user—this file is highly suspicious and likely part of a larger attack chain. The `Temp` directory is often used by malware for staging malicious activities, including running payloads and establishing persistence.

## **Investigation Context**

### **Related Findings**
- The `scvhost.exe` file was found shortly after the detection of other suspicious activities on the system, including the presence of a malicious `CollectSyncLogs.bat` script, and potentially compromised OneDrive installation files.
- The investigation into the PowerShell logs and other system logs indicated possible remote command execution and system reconnaissance activities around the time `scvhost.exe` was active.

### **Initial Attack Vector**
- **Suspicion**: The initial compromise may have occurred through the execution of a malicious script or the download of a compromised file, leading to the execution of `scvhost.exe`.

### **Extent of Compromise**
- **Secondary and Tertiary Actions**: The `scvhost.exe` file could have been used to deploy additional payloads, establish backdoors, or exfiltrate data. The extent of these actions requires further analysis of network logs and process creation events.
- **Persistence Mechanism**: It is plausible that `scvhost.exe` was designed to maintain persistence on the system, either by modifying startup scripts or registry keys, or by dropping additional payloads in less monitored locations.

### **Indicators of Compromise (IoCs)**
- **SHA-256 Hash**: `5581667dfe47539d04c47ff729bcd771f3df2772ce768e6746832c192a37f745`
- **File Path**: `Temp/scvhost.exe`
- **MD5 Hash**: `2a51f5723eabc17be1336e93fd092f3d`
- **Associated Activities**: Execution of PowerShell commands, creation of temporary files with suspicious names, remote command execution indicators.

## **Next Steps**

1. **System Containment**:
   - Isolate the affected machine from the network to prevent further potential compromise or data exfiltration.

2. **Detailed Log Analysis**:
   - Further analyze PowerShell, WMI, and Security event logs to trace the origin and actions of `scvhost.exe`.

3. **Root Cause Analysis**:
   - Investigate any phishing emails, suspicious downloads, or external connections that might have been the initial attack vector leading to the presence of `scvhost.exe`.

4. **Eradication and Recovery**:
   - Remove the `scvhost.exe` file and any related malware artifacts from the system.
   - Restore the system from a known good backup if available, and ensure all security patches are applied.

5. **Strengthening Defenses**:
   - Implement stricter monitoring of the `Temp` directories and utilize advanced threat detection tools to catch similar threats in the future.

## **Conclusion**

The discovery of `scvhost.exe` is a strong indicator of a significant compromise. Immediate action is required to contain and eradicate the threat, followed by a thorough investigation to understand the full extent of the attack and prevent future occurrences.

## `procdump64.exe`
### Metadata
```text
Metadata
Name: /img_disk.raw/vol_vol7/Users/Craig/Desktop/Procdump/procdump64.exe
Type: File System
MIME Type: application/x-dosexec
Size: 341672
File Name Allocation: Allocated
Metadata Allocation: Allocated
Modified: 2017-04-25 04:37:46 UTC
Accessed: 2019-08-17 06:01:04 UTC
Created: 2017-04-25 04:37:46 UTC
Changed: 2019-08-17 05:59:54 UTC
MD5: a92669ec8852230a10256ac23bbf4489
SHA-256: 16f413862efda3aba631d8a7ae2bfff6d84acd9f454a7adaa518c7a8a6f375a5
Hash Lookup Results: UNKNOWN
Internal ID: 18052
```
### **Technical Report: Detailed Analysis of `procdump64.exe` Execution and Evidence Collection**

---

#### **1. Introduction**
This report provides an in-depth analysis of the execution of `procdump64.exe` used by an attacker to create a memory dump of the `lsass.exe` process. The analysis is based on artifacts extracted from the system, including Prefetch files, USN Journal entries, Jump Lists, LNK files, Shellbags, and `$LogFile` entries. These artifacts were meticulously examined to reconstruct the timeline and actions taken during the attack.

#### **2. Analysis of Key Artifacts**

##### **2.1 Prefetch Files**
**Artifact Details:**
- **Application Name:** `PROCDUMP64.EXE`
- **Application Path:** `\VOLUME{01d5382712c52860-b2135219}\USERS\CRAIG\DESKTOP\PROCDUMP\PROCDUMP64.EXE`
- **Run Count:** 1
- **Last Run Time:** `17/08/2019 6:00:34 AM`
- **Volume Name:** `VOLUME{01d5382712c52860-b2135219}`

**Analysis:**
The Prefetch file `PROCDUMP64.EXE-7C654F89.pf` confirms that `procdump64.exe` was executed on `17/08/2019` at `6:00:34 AM`. This was the first and only recorded run of the executable on this system. Prefetch files also indicate that this tool was used from the `C:\Users\Craig\Desktop\Procdump` directory.

**Evidence Snippet:**
```plaintext
PROCDUMP64.EXE,\VOLUME{01d5382712c52860-b2135219}\USERS\CRAIG\DESKTOP\PROCDUMP\PROCDUMP64.EXE,1,17/08/2019 6:00:34 AM
```

##### **2.2 USN Journal Entries**
**Artifact Details:**
- **File Name:** `procdump64.exe`
- **File Created:** `17/08/2019 5:59:54 AM`
- **File Closed:** `17/08/2019 5:59:54 AM`
- **MFT Record Number:** 125097

**Analysis:**
The USN Journal records the creation of `procdump64.exe` at `5:59:54 AM` on `17/08/2019`. The series of entries confirms that the file was created, modified, and closed within the same second, consistent with the extraction or initial preparation before execution.

**Evidence Snippet:**
```plaintext
procdump64.exe,88763944,17/08/2019 5:59:54 AM,"The file or directory is extended (added to). The file or directory is created for the first time. The file or directory is closed.",125097
```

##### **2.3 Jump Lists**
**Artifact Details:**
- **Linked Path:** `C:\Users\Craig\Desktop\Procdump\lsass.zip`
- **Last Accessed:** `17/08/2019 6:00:58 AM`
- **Volume Serial Number:** `B2135219`

**Analysis:**
The Jump List entry indicates that the attacker likely created a ZIP file named `lsass.zip` in the `Procdump` directory. The timing correlates with the execution of `procdump64.exe`, suggesting that the memory dump of `lsass.exe` was subsequently compressed.

**Evidence Snippet:**
```plaintext
C:\Users\Craig\Desktop\Procdump\lsass.zip,17/08/2019 6:00:54 AM,17/08/2019 6:00:58 AM
```

##### **2.4 LNK Files**
**Artifact Details:**
- **Linked Path:** `C:\Users\Craig\Desktop\Procdump\lsass.zip`
- **Accessed Time:** `17/08/2019 6:00:58 AM`

**Analysis:**
The LNK file confirms that `lsass.zip` was accessed immediately after its creation. This suggests the attacker might have been preparing the file for exfiltration or further analysis.

**Evidence Snippet:**
```plaintext
C:\Users\Craig\Desktop\Procdump\lsass.zip,17/08/2019 6:00:58 AM
```

##### **2.5 Shellbags**
**Artifact Details:**
- **Path:** `My Computer:{002641c6-0001-0026-efbe-1100000089a9}Procdump\`
- **First Interaction Date/Time:** `17/08/2019 5:59:55 AM`
- **Last Interaction Date/Time:** `17/08/2019 6:01:26 AM`

**Analysis:**
Shellbags indicate that the directory `Procdump` was accessed and navigated by the user or attacker between `5:59:55 AM` and `6:01:26 AM`. This aligns with the creation and usage of `procdump64.exe`.

**Evidence Snippet:**
```plaintext
My Computer:{002641c6-0001-0026-efbe-1100000089a9}Procdump\,17/08/2019 5:59:55 AM,17/08/2019 6:01:26 AM
```

##### **2.6 $LogFile Analysis**
**Artifact Details:**
- **File Name:** `PROCDUMP64.EXE-7C654F89.pf`
- **Creation Time:** `17/08/2019 6:00:36 AM`

**Analysis:**
The `$LogFile` records show the creation of the Prefetch file for `procdump64.exe`. The timing corroborates the Prefetch evidence, confirming the executable's first and only run.

**Evidence Snippet:**
```plaintext
PROCDUMP64.EXE-7C654F89.pf,92111608,17/08/2019 6:00:36 AM,"The file or directory is extended (added to). The file or directory is created for the first time. The file or directory is closed."
```

### **3. Summary of Findings**
The artifacts collectively provide strong evidence that `procdump64.exe` was used by the attacker to create a dump of the `lsass.exe` process on `17/08/2019`. The execution timeline is supported by multiple corroborating sources, including Prefetch files, USN Journal entries, Jump Lists, LNK files, Shellbags, and `$LogFile` records.

### **4. Conclusion**
The execution of `procdump64.exe` and subsequent actions, such as the creation of `lsass.zip`, demonstrate that the attacker sought to capture and potentially exfiltrate sensitive credential data from the `lsass.exe` process. This activity is well-documented through various system artifacts, each reinforcing the other in establishing a clear sequence of events.

---
