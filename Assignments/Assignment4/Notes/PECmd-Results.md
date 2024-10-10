### **Detailed Report on Prefetch Analysis of `a.exe`, `p.exe`, and `Minesweeperz.exe`**

#### **Artifact Overview:**
This report summarizes the analysis of the prefetch files for three key executables: `a.exe`, `p.exe`, and `Minesweeperz.exe`, which played pivotal roles in the compromise of the systems. These prefetch files provide insights into the execution timelines, system interactions, and potentially malicious activities associated with these executables.

#### **1. Prefetch Analysis for `a.exe`**

##### **Executable Overview:**
- **Executable Name**: `A.EXE`
- **Hash**: `275BA9F0`
- **File Size**: 14,944 bytes
- **Version**: Windows 10/11 compatible
- **Run Count**: 1 (Executed once)
- **Last Run Time**: **October 14, 2019, at 04:33:00 AM (UTC)**
- **Source File Path**: `$RECYCLE.BIN\\S-1-5-21-2482471502-3058185966-1780743469-1001\\A.EXE`

##### **Key Findings:**
- **Files Accessed**:
  - `NTDLL.DLL`, `WOW64.DLL`, `KERNEL32.DLL`, `USER32.DLL`, and `WSOCK32.DLL` are notable system files loaded during execution.
  - **Network-related DLLs** (e.g., `WSOCK32.DLL`, `WS2_32.DLL`) suggest that `a.exe` might have initiated or relied on **network operations**, aligning with its role as **Nbtscan** (a network reconnaissance tool).
  
- **Volume Information**:
  - **Volume Serial Number**: `A2E60E11`
  - The file was executed from a **recycled directory**, indicating possible efforts to **conceal its usage** by placing it in the recycle bin.

##### **Analysis**:
The single execution of `a.exe` at **04:33 AM** indicates that the attacker likely used this network-scanning tool for **reconnaissance**, mapping out network resources. This tool being found in the **Recycle Bin** suggests that the attacker was attempting to hide its usage by deleting it after its task was completed.

---

#### **2. Prefetch Analysis for `p.exe`**

##### **Executable Overview:**
- **Executable Name**: `P.EXE`
- **Hash**: `496197BB`
- **File Size**: 29,122 bytes
- **Version**: Windows 10/11 compatible
- **Run Count**: 5 (Executed five times)
- **Last Run Time**: **October 14, 2019, at 04:47:29 AM (UTC)**
- **Previous Run Times**:
  - **04:42:06 AM**, **04:38:24 AM**, **04:36:57 AM**, and **04:33:40 AM** on the same day.
  
##### **Key Findings:**
- **Files Accessed**:
  - **System-critical DLLs** such as `NTDLL.DLL`, `KERNEL32.DLL`, `USER32.DLL`, and `RPCRT4.DLL` were loaded during each execution.
  - The presence of `NETAPI32.DLL`, `WS2_32.DLL`, and `MSWSOCK.DLL` supports the assumption that PsExec was used for **remote command execution** over the network.
  
- **Volume Information**:
  - **Volume Serial Number**: `A2E60E11`
  - The file was also found in the **Recycle Bin**, further indicating attempts to conceal its use after facilitating lateral movement.

##### **Analysis**:
The multiple executions of `p.exe` within a short period, beginning at **04:33:40 AM** and ending at **04:47:29 AM**, point to the attacker’s effort to remotely execute commands on other systems, likely **Victim 2**. The use of PsExec suggests that **lateral movement** occurred between **Vic1 and Vic2**, and the file’s presence in the Recycle Bin again suggests an effort to hide traces of activity.

---

#### **3. Prefetch Analysis for `Minesweeperz.exe`**

##### **Executable Overview:**
- **Executable Name**: `MINESWEEPERZ.EXE`
- **Hash**: `ABF2F612`
- **File Size**: 28,070 bytes
- **Version**: Windows 10/11 compatible
- **Run Count**: 4 (Executed four times)
- **Last Run Time**: **October 14, 2019, at 04:46:31 AM (UTC)**
- **Previous Run Times**:
  - **04:25:42 AM**, **04:25:25 AM**, and **04:25:25 AM** on the same day.

##### **Key Findings:**
- **Files Accessed**:
  - The file accessed several **system DLLs** such as `NTDLL.DLL`, `KERNEL32.DLL`, `ADVAPI32.DLL`, `RPCRT4.DLL`, and **critical system files** such as `MSVCRT.DLL`, `WINMM.DLL`, and `USERENV.DLL`.
  - The file was loaded from the user **Craig’s Downloads directory**: `C:\\USERS\\CRAIG\\DOWNLOADS\\MINESWEEPERZ.EXE`.
  - Network-related DLLs like `WS2_32.DLL`, `MSWSOCK.DLL`, and `DNSAPI.DLL` were also accessed, indicating possible **network activity** initiated by the executable.

- **Volume Information**:
  - **Volume Serial Number**: `A2E60E11`
  - The file was located in the **Downloads** folder of the user **Craig**, confirming it was executed soon after it was downloaded.

##### **Analysis**:
The repeated execution of **Minesweeperz.exe** (starting at **04:25:25 AM** and ending at **04:46:31 AM**) aligns with the timeline of initial compromise on **Victim 1**. The file’s placement in the **Downloads folder** suggests that it was likely downloaded and executed by the user Craig, initiating the compromise. The file accessing network-related DLLs reinforces the possibility of it initiating connections to **Command and Control (C2) servers**.

---

### **Conclusion**:
The analysis of the prefetch files for `a.exe`, `p.exe`, and `Minesweeperz.exe` reveals critical information about their execution and role in the compromise:

- **`a.exe`** was executed once at **04:33 AM**, likely for network reconnaissance as part of the attacker’s **network mapping activities**.
- **`p.exe`** was executed multiple times, indicating its use in **remote command execution** and **lateral movement** between **Vic1 and Vic2**.
- **`Minesweeperz.exe`** was executed four times, starting the initial compromise by **downloading and executing malware** on **Victim 1**.

The placement of these files in **recycled directories** and the **Downloads** folder, along with the network-related DLLs they accessed, strongly indicates they were part of a **coordinated attack** involving **network reconnaissance**, **lateral movement**, and **malware execution**. The timeline of events shows a clear progression from initial compromise to lateral movement, with evidence of efforts to hide traces by deleting the executables after use.

---

## Victim 2 
### **Detailed Report on Prefetch Analysis of `BACKGROUNDTASKHOST.EXE`**

---

#### **Artifact Overview:**
The `BACKGROUNDTASKHOST.EXE` prefetch files from **Victim 2** provide insights into the execution and behavior of this system-critical executable. This executable is part of the Windows operating system, responsible for hosting background tasks and services. Prefetch analysis reveals the runtime history, associated files loaded during its execution, and directories accessed.

---

#### **Executable Overview:**
- **Executable Name**: `BACKGROUNDTASKHOST.EXE`
- **Hashes**: 
  - `A304C91`
  - `1F665FDB`
  - `47C6DDC4`
  - `5349C4D5`
- **File Size**: Varied between 31,616 and 128,840 bytes.
- **Version**: Windows 10/11 compatible.
- **Run Count**: Between 1 and 7 times depending on the specific prefetch file.
- **Last Run Time**: 
  - **Latest Execution**: **October 14, 2019, at 04:55:10 AM (UTC)**
  - **Previous Run Times**: Spanning from **October 9, 2019, to October 14, 2019**, with runs clustered around early morning times on **October 14** (around **04:16:01 AM to 04:55:10 AM**).

---

#### **Key Findings:**

##### **1. Execution Timeline:**
`BACKGROUNDTASKHOST.EXE` executed frequently on the system, with run counts as follows:
- **7 executions**: The latest at **04:55:10 AM** on **October 14, 2019**.
- Previous executions occurred consistently, including at:
  - **04:35:37 AM**
  - **04:29:44 AM**
  - **04:25:23 AM**
  - **04:16:01 AM**
  - **04:38:25 AM**

##### **2. Files Loaded During Execution:**
The executable loaded several important system DLLs and configuration files, such as:
- `NTDLL.DLL`
- `KERNEL32.DLL`
- `KERNELBASE.DLL`
- `USER32.DLL`
- `MSVCRT.DLL`
- `RPCRT4.DLL`
- `COMBASE.DLL`
- `BCRYPTPRIMITIVES.DLL`
- `SECHOST.DLL`
- `MSVCP_WIN.DLL`
- `GDI32.DLL`
- `IMM32.DLL`
- `USERENV.DLL`
- **AppRepository Package Files**, indicating communication with Windows' application ecosystem.

##### **3. Volume Information:**
- **Volume Serial Number**: `A2E60E11`
- **Volume Name**: `\VOLUME{01d57f73e5f614a0-a2e60e11}`
  - Executable files and system libraries were primarily loaded from **Windows system directories** such as `\WINDOWS\SYSTEM32`, indicating its critical function within the system's background services.

##### **4. Directories Accessed:**
- Accessed key system directories, including:
  - `\WINDOWS\SYSTEM32`
  - `\WINDOWS\GLOBALIZATION\SORTING`
  - `\PROGRAM FILES\WINDOWSAPPS`
  - `\PROGRAMDATA\MICROSOFT\WINDOWS\APPREPOSITORY`

##### **5. Potentially Related Applications:**
- The execution of `BACKGROUNDTASKHOST.EXE` occurred alongside files related to **Microsoft.XboxGameOverlay** and **Content Delivery Manager**, indicating it might have been involved in background tasks related to system or application updates, or background application interactions.
  
##### **6. Significance of Frequent Execution:**
- The frequent execution over a short period suggests that `BACKGROUNDTASKHOST.EXE` was performing system-maintenance or background tasks essential to system integrity or user applications. The timing of executions in the early morning may suggest these tasks were system-scheduled or user-initiated.

---

#### **Analysis:**

`BACKGROUNDTASKHOST.EXE` is a legitimate Windows executable responsible for managing background tasks, and its frequent execution appears normal for system operation. It accessed key system files, DLLs, and configuration libraries that are integral to the OS functioning, further solidifying its importance.

There is no direct evidence in the prefetch data that suggests any malicious activity associated with `BACKGROUNDTASKHOST.EXE` itself. However, the context of its execution could be valuable for determining whether these background tasks were exploited or if they played any part in malicious behavior related to other suspicious executables in the environment.

---

#### **Conclusion:**
`BACKGROUNDTASKHOST.EXE` was executed multiple times between **October 9 and October 14, 2019**, primarily as part of normal Windows operations. It accessed system-critical DLLs, managed background services, and interacted with Windows AppRepository, making it an essential part of the system's functionality. There is no evidence from this analysis to suggest malicious behavior directly associated with this executable.


---


