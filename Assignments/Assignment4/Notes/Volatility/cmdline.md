### Command Line Scan Log Analysis
```bash
python vol.py --profile=Win10x64_17134 -f "Z:\Assessment 4\Evidence\victim_01.memory\victim_01.memory.raw" cmdscan
```

The `cmdscan` command output from the memory images of Victim 1 and Victim 2 provides insights into the active processes and the commands run in the system at the time the memory dump was taken. Let’s break down the findings for each victim.

#### Victim 1 (`cmdlineVic1.pdf`)
- **Observed Active Processes**: The output shows numerous instances of `svchost.exe`, `powershell.exe`, `smartscreen.exe`, and other common system processes. Notably, the following processes stand out:
  - **`powershell.exe`** (PID 2288, PID 7592): Powershell is a legitimate Windows process but is often abused by attackers for running malicious scripts.
  - **`smartscreen.exe`** (PID 8468): SmartScreen is a Windows Defender process, but given its involvement in the investigation (flagged by VirusTotal in previous scans), this requires closer scrutiny.

#### Red Flags:
- **Powershell Activity**: The presence of multiple PowerShell instances, particularly `PID 2288` and `PID 7592`, raises suspicions. PowerShell is often used by attackers to execute malicious scripts or download payloads. In the context of the investigation, these should be analyzed to check for potential abuse (e.g., malicious scripts or encoded commands).
  
- **Smartscreen.exe**: The flagged instance (PID 8468) shows SmartScreen being used. While this is a legitimate Windows process, the fact that it was flagged during VirusTotal scans and appears multiple times in the investigation logs suggests it might have been tampered with or replaced by malware.

#### Victim 2 (`cmdlineVic2.pdf`)
- **Observed Active Processes**: Similar to Victim 1, the output includes multiple instances of `svchost.exe`, `powershell.exe`, `smartscreen.exe`, and `conhost.exe`. Of particular interest are:
  - **`powershell.exe`** (PID 7572, PID 8284): As with Victim 1, the presence of PowerShell processes raises concerns about potential misuse.
  - **`smartscreen.exe`** (PID 7956): Like in Victim 1, this process is flagged for investigation based on VirusTotal results and should be further analyzed.

#### Red Flags:
- **Multiple Powershell Processes**: Victim 2 also shows several PowerShell processes (`PID 7572`, `PID 8284`). These should be checked for any unusual behavior, such as executing encoded scripts or making suspicious network connections.
  
- **Smartscreen.exe**: The `smartscreen.exe` process (PID 7956) in Victim 2 has been flagged in VirusTotal as potentially malicious, similar to Victim 1. This warrants further investigation to determine if it has been compromised.


