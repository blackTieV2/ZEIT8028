# PEs Found 

---

## **File Name:** `A.exe`

### Source: 
Prefetch - Victim 1 - Disk and Memory

#### **Hash Information:**
- **SHA-256**: `c9d5dc956841e000bfd8762e2f0b48b66c79b79500e894b4efa7fb9ba17e4e9e`
- **MD5**: `f01a9a2d1e31332ed36c1a4d2839f412`
- **SHA-1**: `90da10004c8f6fafdaa2cf18922670a745564f45`

#### **File Path:**
- `\$RECYCLE.BIN\S-1-5-21-2482471502-3058185966-1780743469-1001\A.EXE`

#### **Prefetch Artifacts:**
- **Prefetch File Name:** `A.EXE-275BA9F0.pf`
- **First Execution Time:** `14/10/2019 4:33:00 AM`
- **Last Execution Time:** `14/10/2019 4:33:07 AM`
- **Prefetch Hash:** `275BA9F0`
- **Associated File Volume:** `VOLUME{01d57f73e5f614a0-a2e60e11}`
- **File Origin:** It was located in the Recycle Bin, indicating potential attempts to hide or delete the file after its execution.

#### **Execution Frequency:**
- **Number of Executions**: 1


### Key Information from VirusTotal:
1. **Hash Information:**
   - **SHA-256**: `c9d5dc956841e000bfd8762e2f0b48b66c79b79500e894b4efa7fb9ba17e4e9e`
   - **MD5**: `f01a9a2d1e31332ed36c1a4d2839f412`
   - Identified as part of the **`NetTool.Nbtscan` family**, often linked with **hacktools and Trojans**.

2. **Security Vendor Detections:**
   - Labeled by multiple vendors as **Trojan, HackTool, and Potentially Unwanted Program (PUP)**.
   - Some detections include `HackTool.Win32.NBTSCAN`, `Trojan.Agent`, and `RiskWare`.

3. **Behavioral Tags:**
   - **Network Activity**: Communicates with several domains and IPs, such as `armmf.adobe.com`, and IPs like `23.216.147.65`.
   - **Registry Modifications**: Alters keys related to network configuration (`WinSock2\Parameters`).
   - **Files Dropped and Opened**: It creates and deletes several files in critical system locations, like `%SystemRoot%\System32\`.
   
4. **Network Indicators:**
   - **HTTP Requests**: Accesses files like `ArmManifest3.msi` from Adobe's domain (`armmf.adobe.com`).
   - **JA3 Fingerprint Detection**: A potential malicious SSL client fingerprint detected, indicating the presence of a malicious SSL communication pattern.

---

### Log Record for `P.exe`

#### File Information:
- **File Name**: P.exe
- **Location**: 
  - **Original Path**: `\VOLUME{01d57f73e5f614a0-a2e60e11}\$RECYCLE.BIN\S-1-5-21-2482471502-3058185966-1780743469-1001\P.EXE`
  - **Recovered Path**: `.\Attachments\P.EXE`
- **Execution Times**:
  - **First Execution**: 14/10/2019, 4:33:44 AM
  - **Last Execution**: 14/10/2019, 4:47:29 AM
- **Prefetch File Hash**: `496197BB`
- **Total Executions**: 5 times
- **Volume Serial Number**: `10/10/2019 2:06:23 PM`
- **Prefetch File Location**: `victim_01.disk.raw - Partition 4 (Microsoft NTFS, 59.4 GB) Windows\Windows\Prefetch\P.EXE-496197BB.pf`
- **Related Activity**:
  - Executed **around the same time as A.exe** (4:33 AM) and **Minesweeperz.exe**, indicating a likely connection between the files.
  - **Location in Recycle Bin** suggests an attempt to conceal or delete the file post-execution.

#### VirusTotal Information:
- **SHA-256**: `ad6b98c01ee849874e4b4502c3d7853196f6044240d3271e4ab3fc6e3c08e9a4`
- **MD5**: `9321c107d1f7e336cda550a2bf049108`
- **Detected by 3/71 vendors as malicious**.
- **Family**: `PsExec`
  - **Common Use**: PsExec is typically a legitimate tool used for remote process execution but can be exploited by threat actors for malicious purposes (e.g., lateral movement).
  - **Detections**: Labeled as `HackTool.Win64.PsExec` by multiple vendors, indicating that the file could be used as part of a post-exploitation toolkit.
- **Signing Information**:
  - **Signed**: Yes
  - **Publisher**: Microsoft Corporation
  - **Signature Date**: 28/06/2016

#### Behavioral Indicators:
- **Persistence Mechanism**:
  - The presence in the `$RECYCLE.BIN` folder indicates the file was deleted or hidden to avoid detection after its execution, a common tactic for hiding malicious processes.
- **Likely Usage**:
  - Given its detection as a variant of PsExec, it was likely used to execute commands or processes remotely on the system, possibly as part of a lateral movement or persistence strategy.

#### Network Indicators:
- **Potential for Lateral Movement**:
  - PsExec is frequently used by attackers to move laterally across a network by executing remote commands on other machines.
- **Potential Relationship to Other Files**:
  - **Executed alongside A.exe and Minesweeperz.exe**, suggesting coordinated behavior between these files, which were part of the compromise chain.

### Conclusion:
The file `P.exe` is likely part of the post-exploitation toolkit used by the attacker to perform lateral movement, remote command execution, or persistence. Its location in the recycle bin and execution timing strongly suggests it was used in conjunction with `A.exe` and `Minesweeperz.exe` to carry out the compromise.

---

### Log Record for `Minesweeperz.exe`

#### File Information:
- **File Name**: Minesweeperz.exe
- **Full Path**: `victim_01.disk.raw - Partition 4 (Microsoft NTFS, 59.4 GB) Windows\Users\Craig\Downloads\Minesweeperz.exe`
- **File Size (bytes)**: 7.78 MB (8155648 bytes)
- **Created**: `14/10/2019 4:25:09 AM`
- **Accessed**: `14/10/2019 4:25:24 AM`
- **Modified**: `14/10/2019 4:25:13 AM`
- **Last Modified (MFT)**: `14/10/2019 4:25:24 AM`
- **MD5 Hash**: `d9e80958e631496ad165e2326162f956`
- **SHA1 Hash**: `ad74b8eb3bd3ec17b96d450a731b76a3866d92c6`
- **SHA-256 Hash**: `ebf8020d148db05193c7ba5878569eb70b06e24903ed6ae0bff52a8de32c9b39`
- **Cluster**: 3451473
- **Cluster Count**: 1992
- **Physical Location**: 14,137,233,408 bytes
- **Physical Sector**: 27,611,784
- **MFT Record Number**: 96,593
- **Parent MFT Record Number**: 94,748
- **Inode**: -
- **Security ID**: `2748 (S-1-5-21-2482471502-3058185966-1780743469-1006)`
- **File Attributes**: Archive
- **Tags**: None
- **Comments**: None

#### Prefetch Entry:
- **Prefetch Location**: `"victim_01.disk.raw - Partition 4 (Microsoft NTFS, 59.4 GB) Windows\Windows\Prefetch\MINESWEEPERZ.EXE-ABF2F612.pf"`
- **Execution Count**: 4
- **Execution Timestamps**: 
  - First executed on `14/10/2019 4:25:35 AM`
  - Last executed on `14/10/2019 4:46:31 AM`

#### Key Information from VirusTotal:
1. **Hash Information**:
   - **MD5**: `d9e80958e631496ad165e2326162f956`
   - **SHA-1**: `ad74b8eb3bd3ec17b96d450a731b76a3866d92c6`
   - **SHA-256**: `ebf8020d148db05193c7ba5878569eb70b06e24903ed6ae0bff52a8de32c9b39`
   - **File Size**: 7.78 MB (8155648 bytes)
   - **File Type**: PE32+ executable (GUI) x86-64, for MS Windows
   - **SSDEEP**: `98304:lOp2gi4DPjmvFPGAexnxbXmO1idzVxFX:4p2gi4DCvFPGAWxb2uidH`
   - **Compilation Timestamp**: `2019-10-16 04:34:12 UTC`

2. **Security Vendor Detections**:
   - Labeled by multiple vendors as **Trojan, Agentb, and Malicious**.
   - Some detections include `Trojan:Win64/Agentb`, `Trojan.Win64.Agentb.akr`, and `Trojan:Win32/Phonzy.A!ml`.

3. **Behavioral Tags**:
   - **Network Activity**: Communicates with external domains.
   - **Potential Debug Evasion**: Detects debug environments and attempts to bypass them.
   - **Long Sleep Cycles**: The file uses long sleep cycles to potentially evade detection.

4. **Network Indicators**:
   - Possible connections to IP addresses/domains (yet to be confirmed based on traffic data).

#### Portable Executable (PE) Info:
- **Sections**:
   - **.text**: The main code section with a relatively high entropy, indicating possible packing or obfuscation.
     - **Entropy**: 5.86
     - **MD5**: `62a2e8faf618936d92f6d85eebe5d7cd`
   - **.rdata**: Contains import/export information and read-only data.
     - **Entropy**: 5.39
   - **.data**: Writable data section.
     - **Entropy**: 5.45
   - **.idata**: Import directory information.
     - **Entropy**: 3.98

#### Imports:
- **Kernel32.dll**:
  - `AddVectoredExceptionHandler`
  - `CloseHandle`
  - `CreateThread`
  - `ExitProcess`
  - **and more...**

#### Execution Artifacts:
- **Prefetch**: Executed four times between `14/10/2019 4:25:35 AM` and `14/10/2019 4:46:31 AM`.
- **Last Activity**: File was actively used shortly before the infection timeline began.

---
