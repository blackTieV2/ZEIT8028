# Status Report: Investigation into the Compromise of Computers

**Prepared by:** [Your Name], Digital Forensics Expert  
**Date:** [Current Date]

---

## **Executive Summary**

This report presents the findings of a comprehensive forensic investigation into the compromise of two computers within the organization, referred to as Victim 1 and Victim 2. The analysis draws upon disk images, memory dumps, network packet captures, and system logs to reconstruct the attack chain. The investigation identifies the initial attack vector, maps the progression of the compromise, and assesses potential data exfiltration. While substantial evidence has been gathered, certain critical artifacts are missing, preventing a complete reconstruction of the attack chain. These gaps are highlighted in the final section of this report.

---

## **1. How Were the Computers Compromised?**

### **a. What Was the Initial Attack Vector Used to Compromise the User?**

**Initial Attack Vector:** The user on Victim 1's machine downloaded and executed a malicious executable file masquerading as a game from an untrusted website.

**Evidence:**

- **Edge Browser History and Timeline Activity:**
  - On **October 14, 2019**, at approximately **04:23 AM**, user **Craig** searched for "free minesweeper" using the Edge browser.
  - Visited multiple Minesweeper-related websites:
    - `freeminesweeper.org`
    - `play-minesweeper.com`
    - `minesweeperonline.com`
  - Accessed and downloaded **Minesweeperz.exe** from the URL `https://filebin.net/qkzfz4ixazs73hb8/Minesweeperz.exe`.

- **Edge Cache Data Analysis:**
  - Cache records confirm the download of **Minesweeperz.exe** at **04:25 AM**.
  - Associated cookies and session data indicate active user engagement.

- **Network Packet Capture (PCAP) Analysis:**
  - **DNS Queries:**
    - Resolved `filebin.net` to IP address **185.47.40.36**.
  - **TLS Sessions:**
    - Encrypted connections to **185.47.40.36** at the time of download.
    - Wireshark filters confirm HTTP requests containing "Minesweeperz.exe" and TLS handshakes with `filebin.net`.

### **b. What Was the Document Used to Compromise the User?**

No malicious document was used. The compromise was initiated via a malicious executable file, **Minesweeperz.exe**.

### **c. What Was the Link Used to Compromise the User?**

**Malicious Link:**

- `https://filebin.net/qkzfz4ixazs73hb8/Minesweeperz.exe`

**Evidence:**

- **Edge Browser History and Cache Data:**
  - Direct access and download of the file from the above URL.
- **Network Traffic Analysis:**
  - PCAP files show communication with `filebin.net` during the download timeframe.

---

## **2. What Was the Extent of the Compromise?**

### **a. What Was the Second and Third Stage of the Infection?**

**Second Stage:** Execution of additional malicious tools to facilitate lateral movement and further compromise.

- **`A.exe` (Nbtscan):**
  - **Purpose:** Network scanning tool used to enumerate network resources.
  - **Evidence:**
    - Located in the Recycle Bin on Victim 1's machine: `\$RECYCLE.BIN\S-1-5-21-...\A.exe`.
    - **Prefetch Files:**
      - **Filename:** `A.EXE-275BA9F0.pf`
      - **Execution Time:** First and last execution on **October 14, 2019, at 04:33 AM**.
    - **VirusTotal Detections:**
      - Identified as `HackTool.Win32.NBTSCAN` by multiple vendors.

**Third Stage:** Deployment of tools for remote command execution and lateral movement to Victim 2's machine.

- **`P.exe` (PsExec):**
  - **Purpose:** A legitimate Microsoft tool used for executing processes on remote systems, exploited here for lateral movement.
  - **Evidence on Victim 1:**
    - Located in the Recycle Bin: `\$RECYCLE.BIN\S-1-5-21-...\P.exe`.
    - **Prefetch Files:**
      - **Filename:** `P.EXE-496197BB.pf`
      - **Execution Times:** Multiple executions between **04:33 AM** and **04:47 AM** on **October 14, 2019**.
    - **VirusTotal Detections:**
      - Detected as `HackTool.Win64.PsExec` by several vendors.
    - **Service Installation:**
      - **PSEXESVC.exe** found in `C:\Windows\` and running as a service.
      - **Event Logs:**
        - Event ID **7045** indicates the installation of `PSEXESVC` service at **04:37 AM**.
  - **Evidence on Victim 2:**
    - **Prefetch Files:**
      - Presence of `P.EXE` in the prefetch directory.
    - **PSEXESVC.exe** found and running, indicating PsExec was used to execute commands on Victim 2.

### **b. What Actions Were Taken on Target?**

- **Disabling Security Measures:**
  - **`vagrant-shell.ps1` Script Execution:**
    - **Location:** `C:\Windows\tmp\vagrant-shell.ps1` on both Victim 1 and Victim 2.
    - **Function:** Disables Windows Defender features by modifying registry settings and using PowerShell cmdlets.
    - **Evidence:**
      - Script content explicitly sets various Windows Defender preferences to disable real-time monitoring and protection.
      - **PowerShell Event Logs:**
        - Execution of the script with `ExecutionPolicy Bypass` flags.

- **Network Reconnaissance:**
  - **Execution of `A.exe`:**
    - Scans the network to identify accessible systems and shares.
    - **Evidence:**
      - Prefetch files and execution timestamps correlate with network scanning activity.

- **Lateral Movement to Victim 2:**
  - **Use of PsExec (`P.exe`):**
    - Remotely executed commands on Victim 2 to deploy malware.
    - **Evidence:**
      - Presence of PsExec artifacts on Victim 2.
      - **Network Logs:**
        - SMB connections from Victim 1 to Victim 2 around the time of PsExec execution.

- **Memory Injection and Process Hollowing:**
  - **Injected Processes:**
    - `smartscreen.exe` and `powershell.exe` on both Victim 1 and Victim 2.
  - **Evidence:**
    - **Volatility `malfind` Plugin Output:**
      - Shows memory regions with `PAGE_EXECUTE_READWRITE` permissions and suspicious code patterns.
    - **VirusTotal Detections:**
      - `smartscreen.exe` flagged as `Trojan.Patched` by multiple vendors.

### **c. Where Did the Implant Call Back To?**

- **Primary Callback Addresses:**

  - **IP Address:** `185.47.40.36` (associated with `filebin.net`)
    - **Evidence:**
      - Network captures show TLS encrypted communications with this IP during the time of compromise.
      - **AlienVault OTX Threat Intelligence:**
        - Historical data indicates involvement in malware distribution and phishing activities.

  - **IP Address:** `31.130.160.131`
    - **Evidence:**
      - TLS sessions with this IP address observed in network captures.
      - **Certificate Analysis:**
        - Self-signed or anomalous certificates suggest malicious use.

### **d. How Did the Actor Persist Their Access?**

- **Persistence Mechanisms Identified:**

  - **Registry Modifications:**
    - **Evidence:**
      - `vagrant-shell.ps1` script writes to registry paths under `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender` to disable protections persistently.
    - **Impact:**
      - Disables Windows Defender features even after system reboots.

  - **Installed Services:**
    - **PSEXESVC Service:**
      - **Evidence:**
        - Service installed on both Victim 1 and Victim 2.
        - Runs under `LocalSystem` account, providing high-level privileges.
      - **Event Logs:**
        - Installation logged with Event ID **7045**.

  - **Scheduled Tasks and Autoruns:**
    - **Evidence:**
      - While not conclusively identified, the use of scheduled tasks is a common persistence method associated with the tools used.
      - Further analysis required to confirm.

  - **Memory-Resident Malware:**
    - **Injected Processes:**
      - Malicious code residing in `smartscreen.exe` and `powershell.exe`.
    - **Evidence:**
      - Volatility `malfind` analysis reveals code injections.

---

## **3. Was Anything Taken?**

### **a. What Information Was Likely Stolen from the Host?**

- **Potential Data Exfiltration:**

  - **Network Traffic Analysis:**
    - **Outbound Connections:**
      - Encrypted TLS sessions to external IPs (`185.47.40.36`, `31.130.160.131`) during and after the compromise.
    - **Data Volume:**
      - Large amounts of data transmitted suggest possible exfiltration.
    - **Evidence:**
      - Wireshark analysis shows significant outbound encrypted traffic.

  - **Likely Stolen Data:**
    - **User Credentials:**
      - Given the use of credential-dumping tools and memory injections.
    - **Sensitive Documents:**
      - No direct evidence, but possible access due to the level of compromise.
    - **Network Information:**
      - Network scanning indicates collection of network topology and resource data.

- **Limitations in Determination:**

  - **Encrypted Traffic:**
    - Without decryption keys, the content of the outbound traffic cannot be confirmed.
  - **Lack of File Access Logs:**
    - Insufficient logging to determine specific files accessed or copied.

---

## **Missing Information Needed to Form a Complete Attack Chain**

Despite the substantial evidence gathered, certain critical artifacts are missing to fully reconstruct the attack chain and irrefutably prove each stage of the compromise:

1. **Detailed Logs of Lateral Movement:**
   - **Evidence Needed:**
     - Logs showing specific commands executed via PsExec from Victim 1 to Victim 2.
     - File transfer records or evidence of `Minesweeperz.exe` or other payloads being copied to Victim 2.
   - **Current Gap:**
     - While PsExec artifacts are present on Victim 2, the method of malware transfer is not explicitly documented.

2. **Decrypted Network Traffic:**
   - **Evidence Needed:**
     - Decryption of TLS sessions to confirm data exfiltration content.
   - **Current Gap:**
     - Encrypted traffic prevents analysis of exfiltrated data or commands from the C2 server.

3. **Comprehensive Event Logs:**
   - **Evidence Needed:**
     - Complete Windows Event Logs from both victims to trace attacker activities, including security, application, and system logs.
   - **Current Gap:**
     - Logs are partial or missing critical entries due to potential log tampering or insufficient logging configurations.

4. **File System Access Logs:**
   - **Evidence Needed:**
     - Auditing logs to determine specific files accessed, modified, or copied by the attacker.
   - **Current Gap:**
     - Lack of auditing makes it difficult to confirm data theft at the file level.

5. **Malware Samples from Victim 2:**
   - **Evidence Needed:**
     - Copy of `Minesweeperz.exe` or other malware files from Victim 2 for analysis.
   - **Current Gap:**
     - Absence of the malicious executable on Victim 2 prevents direct correlation.

6. **Attacker's Command History:**
   - **Evidence Needed:**
     - PowerShell command history, scripts executed, and command-line arguments used.
   - **Current Gap:**
     - Volatile data may have been lost, or attackers may have cleared histories.

7. **Network Device Logs:**
   - **Evidence Needed:**
     - Firewall, router, and switch logs to trace lateral movement and data exfiltration paths.
   - **Current Gap:**
     - Network logs were not provided or are incomplete.

8. **Endpoint Detection and Response (EDR) Data:**
   - **Evidence Needed:**
     - Alerts and logs from security solutions deployed on the endpoints.
   - **Current Gap:**
     - No EDR data available to supplement forensic findings.

9. **Confirmation of Persistence Mechanisms on Victim 2:**
   - **Evidence Needed:**
     - Explicit artifacts showing scheduled tasks, registry entries, or services installed on Victim 2.
   - **Current Gap:**
     - While some indicators are present, definitive evidence is lacking.

10. **User Account Activity Logs:**
    - **Evidence Needed:**
      - Detailed logs of account authentications, privilege escalations, and access times.
    - **Current Gap:**
      - Insufficient user activity logs to map the attacker's movements fully.

---

## **Conclusion**

The investigation reveals that the initial compromise occurred on Victim 1's machine due to the download and execution of a malicious file disguised as a game. The attacker leveraged legitimate tools like PsExec to move laterally to Victim 2, utilizing memory injection and disabling security features to maintain persistence and avoid detection. Encrypted communications with known malicious IP addresses suggest potential data exfiltration. However, due to missing critical artifacts, we cannot irrefutably confirm every stage of the attack chain, especially the exact method of malware propagation to Victim 2.

---

## **Recommendations**

1. **Immediate Actions:**

   - **Isolate Affected Systems:**
     - Disconnect both Victim 1 and Victim 2 from the network immediately.
   - **Preserve Evidence:**
     - Securely collect and store all logs, memory dumps, and disk images for further analysis.
   - **Credential Resets:**
     - Force password resets for all user and administrative accounts.

2. **Remediation Measures:**

   - **System Restoration:**
     - Rebuild compromised systems from known good backups.
   - **Malware Eradication:**
     - Use advanced malware removal tools to ensure complete cleaning.

3. **Enhance Security Posture:**

   - **Implement EDR Solutions:**
     - Deploy endpoint detection and response tools for real-time monitoring.
   - **Network Segmentation:**
     - Segment the network to limit lateral movement opportunities.
   - **Regular Auditing:**
     - Enable detailed logging and regular audits of critical systems.

4. **User Training and Awareness:**

   - **Security Education:**
     - Conduct training sessions on safe internet practices and phishing awareness.
   - **Policy Enforcement:**
     - Enforce strict policies against downloading and executing untrusted software.

5. **Further Investigation:**

   - **Gather Missing Evidence:**
     - Attempt to retrieve additional logs and data to fill the gaps identified.
   - **Engage Specialists:**
     - Consider hiring external cybersecurity experts for an in-depth investigation.

---

**Prepared by:**  
[Your Name]  
Digital Forensics Expert

---

**Note:** This report is based on the artifacts provided and current analysis. The findings may evolve as additional information becomes available.
