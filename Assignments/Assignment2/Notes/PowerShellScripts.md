## `Sticky.ps1`

The `Sticky.ps1` PowerShell script is designed to capture screenshots of the desktop at regular intervals, saving the images to a publicly accessible directory. This script is likely used for data exfiltration and is highly suspicious due to its functionality.

### Script Overview:

1. **Screen Capture Functionality**:
   - The script runs in an infinite loop, capturing the screen every 30 seconds using .NET's `System.Drawing` and `System.Windows.Forms` libraries.
   - Each screenshot is saved as a PNG file in `C:\Users\Public\Pictures\` with a filename that includes a timestamp (e.g., `ss_20240821_112026.png`).

2. **Infinite Loop**:
   - The `while ($true)` loop ensures that the script continuously captures screenshots without stopping, which is a typical behavior in scripts designed for continuous monitoring or data gathering.

3. **File Storage**:
   - Screenshots are stored in a publicly accessible directory (`C:\Users\Public\Pictures\`). This location is often used in attacks to make it easier for attackers to retrieve the captured data, especially if the system is later compromised for file access.

### Indicators of Malicious Activity:

- **Continuous Monitoring**:
  - The script’s infinite loop suggests it is intended to run indefinitely, capturing potentially sensitive information displayed on the screen over time.

- **Public Directory for Storage**:
  - Storing files in `C:\Users\Public\Pictures\` may facilitate easy retrieval of the screenshots by an attacker or by another component of the attack.

- **Data Exfiltration Potential**:
  - The captured screenshots could be used to gather information about the victim's activities, including sensitive data such as passwords, financial information, or confidential documents.

### Connections to Other Scripts:

- **Possible Link to `vagrant-shell.ps1`**:
  - The `Sticky.ps1` script may be used in conjunction with `vagrant-shell.ps1`, which disables Windows Defender and establishes persistence. After disabling defenses, `Sticky.ps1` could be deployed to silently capture data from the compromised system.

### Next Steps for Investigation:

1. **Check for Scheduled Tasks**:
   - Investigate whether `Sticky.ps1` is run as part of a scheduled task or any other persistence mechanism set up by other scripts or attackers.

2. **Search for Captured Data**:
   - Examine the `C:\Users\Public\Pictures\` directory to see if there are any saved screenshots, which could provide insights into what the attacker was monitoring.

3. **Review PowerShell Logs**:
   - Analyze PowerShell event logs to identify when and how `Sticky.ps1` was executed, and whether it was triggered by another script or task.

### Conclusion:

The `Sticky.ps1` script is a clear indicator of malicious activity, designed to capture and possibly exfiltrate sensitive information from the victim's system. It should be treated with caution, and immediate steps should be taken to remove it from the system and investigate any further compromises it may be associated with.

