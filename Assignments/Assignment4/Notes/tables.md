## Timeline of Events: Two Separate Infections on Victim 1 and Victim 2

Below is a detailed timeline that separates the two distinct infections affecting Victim 1 and Victim 2. The table focuses exclusively on the execution of Portable Executable (PE) files and PowerShell scripts (`.ps1`), highlighting how each infection unfolded on the respective machines.

### **First Infection: Existing Advanced Persistent Threat (APT)**

This infection predates the second and involves the unauthorized installation of `sshd.exe` on both Victim 1 and Victim 2, providing persistent remote access to the attacker.

#### **Victim 1 and Victim 2**

| Timestamp (UTC)            | Victim  | Event Description                                | Process/Executable      |
|----------------------------|---------|--------------------------------------------------|-------------------------|
| **2019-10-09 20:10:25**    | Both    | `sshd.exe` file created in `C:\Program Files\OpenSSH\` | `sshd.exe`              |
| **2019-10-09 20:10:37**    | Both    | `sshd.exe` installed as a service (`OpenSSH SSH Server`) | `sshd.exe`              |
| **2019-10-09 20:10:49**    | Both    | `sshd.exe` first execution recorded in Prefetch  | `SSHD.EXE-2CD6179A.pf`  |
| **2019-10-10 06:22:00**    | Both    | `sshd.exe` execution confirmed via AmCache       | `sshd.exe`              |
| **2019-10-14 03:32:20**    | Both    | `sshd.exe` service started automatically at boot | `sshd.exe`              |
| **2019-10-14 03:37:22**    | Victim 1| Unauthorized SSH connection established          | `sshd.exe`              |
| **2019-10-14 03:39:00**    | Victim 2| Unauthorized SSH connection established          | `sshd.exe`              |

### **Second Infection: User-Initiated Malware Execution**

This infection begins with user Craig on Victim 1 downloading and executing `Minesweeperz.exe`, leading to further malicious activities and affecting both Victim 1 and Victim 2.

#### **Victim 1**

| Timestamp (UTC)            | Victim  | Event Description                                | Process/Executable      |
|----------------------------|---------|--------------------------------------------------|-------------------------|
| **2019-10-14 04:25:01**    | Victim 1| `Minesweeperz.exe` downloaded from `filebin.net` | `Minesweeperz.exe`      |
| **2019-10-14 04:25:09**    | Victim 1| `Minesweeperz.exe` file created in Downloads folder | `Minesweeperz.exe`   |
| **2019-10-14 04:25:25**    | Victim 1| First execution of `Minesweeperz.exe`            | `Minesweeperz.exe` (PID 3908) |
| **2019-10-14 04:25:25**    | Victim 1| Second execution of `Minesweeperz.exe`           | `Minesweeperz.exe` (PID 6820) |
| **2019-10-14 04:25:42**    | Victim 1| Third execution of `Minesweeperz.exe`            | `Minesweeperz.exe` (PID 8564) |
| **2019-10-14 04:31:44**    | Victim 1| `p.exe` created in Recycle Bin                   | `p.exe`                 |
| **2019-10-14 04:33:44**    | Victim 1| First execution of `p.exe`                       | `p.exe` (PID 5636)      |
| **2019-10-14 04:46:31**    | Victim 1| Fourth execution of `Minesweeperz.exe`           | `Minesweeperz.exe` (PID 5260) |
| **2019-10-14 04:46:31**    | Victim 1| `cmd.exe` executed as part of attack chain       | `cmd.exe` (PID 4940)    |
| **2019-10-14 04:46:31**    | Victim 1| `powershell.exe` launched to execute commands    | `powershell.exe` (PID 9248) |
| **2019-10-14 04:47:29**    | Victim 1| `p.exe` used to initiate remote execution on Victim 2 | `p.exe`             |

#### **Victim 2**

| Timestamp (UTC)            | Victim  | Event Description                                | Process/Executable      |
|----------------------------|---------|--------------------------------------------------|-------------------------|
| **2019-10-14 04:36:58**    | Victim 2| `PSEXESVC.exe` created in `C:\Windows\`          | `PSEXESVC.exe`          |
| **2019-10-14 04:37:20**    | Victim 2| `PSEXESVC.exe` installed as a service            | `PSEXESVC.exe`          |
| **2019-10-14 04:37:30**    | Victim 2| First execution of `PSEXESVC.exe`                | `PSEXESVC.exe`          |
| **2019-10-14 04:22:09**    | Victim 2| `spoolvs.exe` file created in System32 directory | `spoolvs.exe`           |
| **2019-10-14 04:22:09**    | Victim 2| `spoolvs.exe` executed as a service              | `spoolvs.exe` (PID 8588)|
| **2019-10-14 04:47:29**    | Victim 2| `spoolvs.exe` execution initiated remotely by `p.exe` | `spoolvs.exe`      |
| **2019-10-14 04:46:44**    | Victim 2| `powershell.exe` launched to execute commands    | `powershell.exe` (PID 7572) |
| **2019-10-14 04:47:29**    | Victim 2| `powershell.exe` launched as part of remote execution | `powershell.exe` (PID 8284) |

### **Additional Observations**

#### **Cheat Engine.exe on Both Victims**

| Timestamp (UTC)            | Victim  | Event Description                                | Process/Executable      |
|----------------------------|---------|--------------------------------------------------|-------------------------|
| **2019-10-14 04:31:52**    | Victim 1| `Cheat Engine.exe` found in pagefile.sys         | `Cheat Engine.exe` (PID 8400) |
| **2019-10-14 05:57:01**    | Victim 2| `Cheat Engine.exe` remnants found in slack space | `Cheat Engine.exe`      |

- **Role**: Likely used for memory manipulation or code injection to aid in the attack.

### **PowerShell Script Execution**

#### **Victim 1**

| Timestamp (UTC)            | Victim  | Event Description                                | Script                  |
|----------------------------|---------|--------------------------------------------------|-------------------------|
| **2019-10-09 19:25:36**    | Victim 1| PowerShell script created in Temp directory      | `script-5d9e2f72-8251-8ba5-2277-30f2341f32be.ps1` |
| **2019-10-09 20:14:22**    | Victim 1| PowerShell script modified (possibly executed)   | `script-5d9e2f72-8251-8ba5-2277-30f2341f32be.ps1` |

- **Note**: This script mentions `sdelete64.exe`, suggesting it was used to delete files securely.

### **Summary of Separation Between Infections**

- **First Infection**:
  - **Infection Vector**: Unauthorized installation of `sshd.exe`.
  - **Affected Systems**: Both Victim 1 and Victim 2.
  - **Key Artifacts**: `sshd.exe` service installation and execution.

- **Second Infection**:
  - **Infection Vector**: User Craig downloads and executes `Minesweeperz.exe`.
  - **Primary System Affected Initially**: Victim 1.
  - **Lateral Movement**: From Victim 1 to Victim 2 via `p.exe` and `PSEXESVC.exe`.
  - **Key Artifacts**: `Minesweeperz.exe`, `p.exe`, `PSEXESVC.exe`, `spoolvs.exe`, and associated `powershell.exe` executions.

---

This timeline clearly delineates the two separate infection events and illustrates how they affected both Victim 1 and Victim 2 through specific PE files and PowerShell scripts.
