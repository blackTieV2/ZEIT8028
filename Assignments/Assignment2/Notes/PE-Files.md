## `plink.exe`

### Overview:
`plink.exe` is a command-line tool from the PuTTY suite, commonly used for SSH connections. However, its presence in the `\Windows\Temp\` directory and its execution under suspicious circumstances are strong indicators of potential malicious activity.

### Key Details from the Investigation:

1. **File Path and Execution**:
   - **Location**: `\Windows\Temp\plink.exe`
   - **Prefetch File**: Indicates that `plink.exe` was executed on the system.
   - **First Seen**: `17/08/2019 05:52:31 AM (UTC)`
   - **Run Count**: The executable has been run at least once based on the prefetch file.

2. **Process Information**:
   - **Process ID**: 4016
   - **Parent Process ID**: 9920
   - **Execution Time**: `17/08/2019 05:52:31 AM (UTC)`
   - **Memory Artifacts**: Loaded libraries and DLLs include several core system files, indicating active use of `plink.exe` during the session.
   - **Security Identifiers**: The process ran under the Local System account and had administrative privileges.

3. **Suspicious Activity**:
   - **Command-Line Arguments**: The command executed with `plink.exe` included connecting to a remote server (`69.50.64.20`) on port 22 and forwarding a local port (`127.0.0.1:12345`) to a remote IP (`10.2.0.2:3389`), which suggests remote access or tunneling.
   - **Potential Data Exfiltration**: The use of SSH to create a reverse tunnel could facilitate unauthorized remote access or data exfiltration.

4. **Prefetch Information**:
   - **File Hash**: `423EF47C`
   - **Prefetch Path**: `Windows\Prefetch\PLINK.EXE-423EF47C.pf`
   - **Volume Name**: `\VOLUME{01d5382712c52860-b2135219}`
   - **Execution Dates**: Shows detailed records of the last eight times `plink.exe` was run, with the last run on `17/08/2019`.

### Indicators of Malicious Activity:

- **Unusual Location**: `plink.exe` being located in the `\Windows\Temp\` directory is suspicious since legitimate applications are typically not stored here.
- **SSH Tunneling**: The command-line usage of `plink.exe` to set up SSH tunnels is often associated with malicious activities, such as creating backdoors or bypassing network security controls.
- **Administrative Privileges**: Running under the Local System account with administrative rights further indicates potential misuse, as it suggests the process had unrestricted access to the system.

### Recommendations:

1. **Containment**:
   - Immediately terminate any active sessions related to `plink.exe`.
   - Isolate the affected system to prevent further unauthorized access or data exfiltration.

2. **Further Investigation**:
   - Investigate the parent process (PID: 9920) to identify how `plink.exe` was launched.
   - Review network traffic logs around the time of execution for any signs of data being sent to the remote IP address (`69.50.64.20`).

3. **System Hardening**:
   - Implement tighter security controls to prevent unauthorized binaries from being executed from temporary directories.
   - Monitor and restrict the use of remote access tools like PuTTY on sensitive systems.

### Conclusion:
The presence of `plink.exe` in the `\Windows\Temp\` directory, its execution with SSH tunneling commands, and the use of administrative privileges strongly suggest that it was used maliciously to establish a backdoor or for data exfiltration purposes. Immediate action is required to mitigate the threat.
