### **Investigation Report: Victim_01**

---

#### **NetConn Analysis**

The network connection report from the memory dump of Victim_01 provides details of multiple established and closed TCP/UDP connections.

**Key Findings**:
- **Closed TCP connections**:
  - IP 34.95.124.132:443 (Google Cloud) suggests access to cloud-based services.
  - Multiple connections to IPs such as 103.243.221.109, 117.18.237.29, 107.178.254.65, 216.58.199.42 (Google), and 104.18.99.194 (Cloudflare). These are typically associated with services like CDNs, web hosting, and online service providers.
- **Listening Ports**:
  - Common services were running, such as **svchost.exe** listening on multiple ports (TCP/UDP), including well-known service ports like 135 (RPC) and 5357.
  - **sshd.exe** is listening on port 22, indicating SSH services running on the system, potentially for remote access.
- **UDP Activity**:
  - Several UDP services running under **svchost.exe**, indicating routine background processes.

**Value**:
- These closed connections suggest that the system was interacting with common internet infrastructure, but the presence of SSH listening on port 22 could indicate a security risk, especially if unauthorized.

---

#### **Pslist Analysis**

The process list extracted from Victim_01's memory reveals detailed information on running processes during the incident.

**Key Findings**:
- **sshd.exe (PID: 2992)** is an important point to note. SSH is commonly used for secure access but could also indicate unauthorized remote access.
- **Multiple instances of svchost.exe** managing various services. Notably:
  - **PID 3856** tied to multiple UDP services, including 127.0.0.1 (loopback).
- **MsMpEng.exe** (Microsoft's AntiMalware service, PID 3044) terminated abnormally at 2019-10-14 03:59:58 UTC, potentially indicating interference or tampering.
- **PowerShell.exe (PID 2288 and PID 6416)** are of interest, as PowerShell is often used in advanced attacks or for system administration tasks.
  
**Value**:
- The abrupt termination of **MsMpEng.exe** is suspicious, as it could be evidence of malware or attacker interference.
- The **sshd.exe** process needs further analysis, as SSH should typically not be active unless explicitly authorized.
  
---

### **Comprehensive Analysis**

The data from the **NetConn** and **Pslist** reports suggests that **Victim_01** was involved in regular internet interactions, but there are several signs of potential compromise:
- **SSH Service Running**: Indicates the possibility of remote access, which is unusual unless explicitly configured for administration.
- **PowerShell Activity**: The multiple PowerShell processes running, coupled with the abnormal termination of the antivirus service, may indicate that the system was exploited using PowerShell commands, a common tactic in fileless malware attacks.
- **Connections to Cloud Providers**: The outbound connections to Google and Cloudflare services could be legitimate, but they could also be used to mask data exfiltration or remote control mechanisms if associated with attacker infrastructure.

---

#### **Conclusion**:

The evidence suggests that **Victim_01** may have been compromised. The presence of SSH, abnormal termination of security processes, and multiple PowerShell instances indicate possible malicious activity. Further forensic investigation is recommended to examine the nature of the SSH connections and PowerShell commands executed during the time of the incident.

---

## Victim 02 Analysis

### **Facts from Reports:**

#### 1. **Netconn Report:**
   - **Common Ports Used:**
     - Port 3389 (Remote Desktop Protocol - RDP) via both IPv4 and IPv6, opened by `svchost.exe` (PID 404).
     - Port 5355 (Link-local Multicast Name Resolution - LLMNR), opened by `svchost.exe` (PID 1584).
     - Port 139 and 137 (NetBIOS), used by the `System` process (PID 4).
     - Several other common ports for network services like UDP on ports 5353 (Multicast DNS), 3702 (Web Services Discovery), and 1900 (Simple Service Discovery Protocol) were open by `svchost.exe`.

   - **Notable Remote Connections:**
     - TCP connection to a foreign IP (`172.217.167.67`) on port 443, possibly indicating a connection to a Google server or similar service.
     - Multiple CLOSED connections to an external IP `117.18.232.240` on port 80 (HTTP), which is associated with Microsoft or Akamai services.

#### 2. **Pslist Report:**
   - **High Process Activity:**
     - `svchost.exe` appears multiple times, supporting various system services, each with varying thread and handle counts. The instance with PID 596 supports a wide range of tasks and has multiple child processes.
     - `powershell.exe` was observed running twice (PID 7572 and 8284) in the system during the specified times, suggesting possible manual intervention or scripting activity.
     - `vmtoolsd.exe` (VMware Tools Daemon) is active (PID 3100 and others), confirming the machine is likely running inside a virtualized environment.

   - **Services of Interest:**
     - `MsMpEng.exe` (Microsoft Defender) is active, indicating that the system's antivirus was running during the memory capture.
     - `spoolsv.exe` (Print Spooler Service) and multiple instances of `svchost.exe` indicate a high number of system services running.

### **Analysis:**

Victim 02 shows signs of typical server or corporate workstation activity, particularly with ports such as 3389 (RDP), 139 (NetBIOS), and 5353/5355 (Multicast). The presence of multiple `svchost.exe` instances, alongside processes like `MsMpEng.exe`, suggests normal Windows operations. However, the active use of `powershell.exe` is concerning, as this can indicate potential malicious activity or post-exploitation. The powershell processes could be linked to scripting or administrative actions, and further examination of command-line history would be recommended.

The netstat data reveals connections to external IPs, including `172.217.167.67` (likely a Google server) and `117.18.232.240` (associated with Microsoft/Akamai). These may be legitimate but should be cross-verified against known good traffic, especially the IP ending with `240` due to its use of HTTP (port 80), which could be related to command-and-control activity or outbound data exfiltration.

In addition, the presence of `vmtoolsd.exe` confirms that the environment is virtualized, potentially making it a more attractive target for an attacker looking to compromise multiple machines hosted on the same infrastructure.

The process list shows several instances of `svchost.exe` handling critical services, which may mask malicious behavior. This aligns with common tactics used by advanced persistent threats (APTs) to blend into legitimate processes.

### **Conclusion:**
Victim 02 exhibits typical behavior for a server or corporate environment, with some indicators of suspicious activity, especially around the powershell executions and remote connections. Further investigation into the powershell commands, verification of the external IP traffic, and deeper analysis of the `svchost.exe` activity is required. The high number of closed connections to external addresses, particularly on HTTP, should be treated with caution, as they may represent attempted communications with a command-and-control server.

---

