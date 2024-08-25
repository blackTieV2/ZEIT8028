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
