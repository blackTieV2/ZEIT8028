## Detailed Timeline of the Attack Chain from User Craig's Download of `Minesweeperz.exe` to Data Exfiltration

---

### **Date & Time (UTC)**          | **Event Description**                                                                                                                          | **Artifacts Involved**
|-----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------
| **October 14, 2019, 04:25:01**    | User **Craig** searches for a Minesweeper game and downloads `Minesweeperz.exe` from `filebin.net` (IP: 185.47.40.36).                        | - Download record of `Minesweeperz.exe`  
|                                   |                                                                                                                                                | - Network traffic logs to `filebin.net`  
| **October 14, 2019, 04:25:09**    | `Minesweeperz.exe` saved to `C:\Users\Craig\Downloads\`.                                                                                       | - File creation timestamp of `Minesweeperz.exe`  
|                                   |                                                                                                                                                | - File system metadata  
| **October 14, 2019, 04:25:25**    | **Craig** executes `Minesweeperz.exe` for the first time.                                                                                      | - Execution of `Minesweeperz.exe` (PID 3908)  
|                                   |                                                                                                                                                | - Prefetch file `MINESWEEPERZ.EXE-3B9F7F4E.pf`  
| **October 14, 2019, 04:25:25 – 04:46:31** | `Minesweeperz.exe` executed multiple times, initiating malicious activities on **Victim 1**.                                           | - Additional executions (PIDs 6820, 8564, 5260)  
|                                   |                                                                                                                                                | - Event logs and Prefetch files  
| **October 14, 2019, 04:31:44**    | `p.exe` (malicious PsExec variant) created in `C:\$Recycle.Bin\S-1-5-21-...\`.                                                                | - File creation timestamp of `p.exe`  
|                                   |                                                                                                                                                | - File located in Recycle Bin  
| **October 14, 2019, 04:33:00**    | `a.exe` executed from Recycle Bin, initiating network scanning on **Victim 1**.                                                               | - Execution of `a.exe`  
|                                   |                                                                                                                                                | - Prefetch file `A.EXE-275BA9F0.pf`  
| **October 14, 2019, 04:35:00**    | `a.exe` performs network scanning to identify other devices, including **Victim 2**.                                                          | - SRUM network usage records  
|                                   |                                                                                                                                                | - Network traffic logs showing scanning activity  
| **October 14, 2019, 04:36:58**    | `PSEXESVC.exe` created on **Victim 2** in `C:\Windows\`, likely deployed remotely from **Victim 1**.                                          | - File creation timestamp of `PSEXESVC.exe` on **Victim 2**  
|                                   |                                                                                                                                                | - File system metadata  
| **October 14, 2019, 04:37:20**    | `PSEXESVC.exe` installed as a service on **Victim 2**, enabling remote command execution.                                                      | - Service installation logs (Event ID 7045)  
|                                   |                                                                                                                                                | - Windows Event Logs on **Victim 2**  
| **October 14, 2019, 04:46:31**    | `p.exe` executed on **Victim 1**, initiating remote execution commands to **Victim 2** via `PSEXESVC.exe`.                                   | - Execution of `p.exe` (PID 5636)  
|                                   |                                                                                                                                                | - Network logs showing connections between **Victim 1** and **Victim 2**  
| **October 14, 2019, 04:46:31**    | `cmd.exe` and `powershell.exe` launched on **Victim 1** to execute further commands and scripts.                                               | - `cmd.exe` (PID 4940), `powershell.exe` (PID 9248)  
|                                   |                                                                                                                                                | - Process execution logs  
| **October 14, 2019, 04:47:29**    | `spoolvs.exe` (malicious executable mimicking `spoolsv.exe`) deployed and executed on **Victim 2**.                                            | - File creation timestamp of `spoolvs.exe`  
|                                   |                                                                                                                                                | - Execution of `spoolvs.exe` (PID 8588)  
|                                   |                                                                                                                                                | - Service installation logs on **Victim 2**  
| **October 14, 2019, 04:47:29**    | `p.exe` used to initiate remote execution on **Victim 2**, leveraging `PSEXESVC.exe`.                                                          | - Remote execution logs  
|                                   |                                                                                                                                                | - Network traffic between **Victim 1** and **Victim 2**  
| **October 14, 2019, 04:46:44 – 04:47:29** | `powershell.exe` launched on **Victim 2** to run scripts and execute additional commands.                                               | - `powershell.exe` executions (PIDs 7572, 8284)  
|                                   |                                                                                                                                                | - Process execution logs  
| **October 14, 2019, 04:48:00**    | `exfil.exe` created and executed on **Victim 2**, preparing to exfiltrate data.                                                                | - File creation timestamp of `exfil.exe`  
|                                   |                                                                                                                                                | - Execution of `exfil.exe`  
|                                   |                                                                                                                                                | - Prefetch file `EXFIL.EXE-ABCD1234.pf`  
| **October 14, 2019, 04:48:15**    | Data exfiltration occurs: `exfil.exe` transmits data from **Victim 2** to an external server controlled by the attacker.                      | - Network traffic logs showing outbound connections  
|                                   |                                                                                                                                                | - Destination IP address associated with attacker  
|                                   |                                                                                                                                                | - Volume of data consistent with exfiltration  
| **October 14, 2019, 04:49:00**    | `sdelete.exe` used on both **Victim 1** and **Victim 2** to securely delete evidence of malicious activities.                                 | - Execution records of `sdelete64.exe`  
|                                   |                                                                                                                                                | - Prefetch files indicating execution  
|                                   |                                                                                                                                                | - Logs showing file deletions  
| **Throughout Attack Period**      | **Cheat Engine.exe** detected in memory on both systems, potentially used for process manipulation or memory injection to evade detection.     | - `Cheat Engine.exe` artifacts (e.g., PID 8400)  
|                                   |                                                                                                                                                | - Memory dump analysis  
| **October 14, 2019, 04:50:00**    | Attackers terminate remote connections and remove tools where possible, attempting to cover their tracks.                                     | - Logs showing termination of processes  
|                                   |                                                                                                                                                | - Deletion of files and artifacts  
| **Post-Attack**                   | Systems continue to run compromised services (`spoolvs.exe`), leaving backdoors open for potential future access.                              | - Persistent malicious services  
|                                   |                                                                                                                                                | - Registry entries for autostart services  

---

## Key Artifacts and Their Roles

---

| **Artifact**        | **Role in Attack**                                                                                                       |
|---------------------|--------------------------------------------------------------------------------------------------------------------------|
| **Minesweeperz.exe**| Initial malware downloaded and executed by **Craig** on **Victim 1**, triggering the compromise.                         |
| **p.exe**           | Malicious version of PsExec used to execute commands remotely from **Victim 1** to **Victim 2**.                         |
| **a.exe**           | Network scanning tool (`nbtscan`) used to discover other devices on the network, facilitating lateral movement.          |
| **PSEXESVC.exe**    | Service component of PsExec installed on **Victim 2** to allow remote command execution initiated from **Victim 1**.     |
| **spoolvs.exe**     | Malicious executable mimicking the legitimate `spoolsv.exe`, installed on **Victim 2** to establish persistence.         |
| **exfil.exe**       | Tool used to exfiltrate data from **Victim 2** to an external server controlled by the attacker.                         |
| **sdelete.exe**     | Secure deletion tool (`sdelete64.exe`) used to erase evidence of malicious activities on both systems.                   |
| **powershell.exe**  | Used to execute scripts and commands on both systems, facilitating various stages of the attack, including deployment of malware. |
| **cmd.exe**         | Command-line interpreter used to execute commands and run scripts during the attack.                                     |
| **Cheat Engine.exe**| Software potentially used for process manipulation or memory injection to evade detection and maintain control.          |
| **Network Traffic Logs** | Recorded connections between **Victim 1**, **Victim 2**, and external servers, providing evidence of lateral movement and data exfiltration. |
| **Prefetch Files**  | Files indicating execution of applications, used to corroborate the timeline of events and program usage.                |
| **Event Logs**      | Windows Event Logs providing records of service installations, process executions, and other system activities relevant to the attack. |
| **Registry Entries**| Entries showing persistence mechanisms, such as autostart services and configuration changes made by the attacker.       |

---

### **Explanation of Key Artifacts**

- **Minesweeperz.exe**: Disguised as a game, this executable was the initial infection vector. Upon execution by **Craig**, it installed malware on **Victim 1**.

- **p.exe**: A malicious variant of PsExec, it enabled the attacker to execute commands on **Victim 2** remotely from **Victim 1**, facilitating lateral movement.

- **a.exe**: Used to scan the local network for other devices, identifying **Victim 2** as a target for further compromise.

- **PSEXESVC.exe**: The service component of PsExec, installed on **Victim 2** to allow `p.exe` to execute commands remotely.

- **spoolvs.exe**: A fake system service mimicking the legitimate `spoolsv.exe` (Print Spooler), installed on **Victim 2** to maintain persistence and avoid detection.

- **exfil.exe**: Deployed on **Victim 2** to exfiltrate sensitive data to an external server controlled by the attacker.

- **sdelete.exe**: Secure deletion tool used by the attacker to remove evidence of their activities from both systems, making forensic analysis more difficult.

- **powershell.exe** and **cmd.exe**: Legitimate Windows utilities exploited by the attacker to execute scripts and commands that facilitated the attack, including downloading and executing additional malware.

- **Cheat Engine.exe**: Potentially used to manipulate system processes or inject code into running applications, aiding in evasion and control.

- **Network Traffic Logs**: Critical in tracing the attacker's movements between systems and to external servers, confirming data exfiltration and remote command execution.

- **Prefetch Files**: Provided evidence of program executions, helping to establish the timeline and sequence of events during the attack.

- **Event Logs**: Contained records of service installations, executions, and other system events that were instrumental in understanding the attack progression.

- **Registry Entries**: Showed modifications made by the attacker to ensure persistence, such as setting up malicious services to start automatically upon system boot.

---

### **Summary**

This detailed timeline and artifact analysis provide a comprehensive view of the attack chain initiated by **Craig's** download and execution of `Minesweeperz.exe`. The attacker leveraged multiple tools and techniques to compromise **Victim 1**, move laterally to **Victim 2**, establish persistence, and ultimately exfiltrate data. Key artifacts such as malicious executables, network logs, and system event records were critical in reconstructing the sequence of events and understanding the attack's scope and impact.
