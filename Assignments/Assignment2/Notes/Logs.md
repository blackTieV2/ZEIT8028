## PowerShell logs 
from the `185724-Microsoft-Windows-PowerShell%4Operational.evtx` files contain a wealth of information, including script executions and various commands that were run on the system. Here’s an analysis of key findings and potential indicators of compromise:

### Key Findings from the Logs:

1. **Script Block Logging (Event ID 4104)**:
   - **Complex Script Execution**: The logs reveal the execution of complex PowerShell scripts with numerous parameters, including those related to networking (`LocalAddress`, `RemoteAddress`, `Protocol`, etc.). This could suggest that the scripts were manipulating network configurations or establishing remote connections.
   - **Remote Commands**: The logs indicate remote command execution tasks, particularly involving parameters like `RemoteTunnelEndpoint`, `RemoteTunnelHostname`, and `EncryptedTunnelBypass`. These could be associated with tunneling or bypassing encrypted communication channels, which is a tactic used by attackers to avoid detection.
   - **Use of Cmdletization**: The scripts make heavy use of cmdletization, which is a way to encapsulate complex operations within PowerShell cmdlets. This can be a legitimate technique but is often used in advanced persistent threats (APTs) to hide malicious activity within seemingly legitimate operations.

2. **Security-Related Parameters**:
   - **Authorization and Security Policies**: Parameters like `RequireAuthorization`, `Phase1AuthSet`, and `Phase2AuthSet` indicate that the scripts were likely modifying or interacting with security policies, particularly related to IPsec or similar security frameworks.
   - **Inbound/Outbound Security**: The manipulation of security settings related to inbound and outbound traffic (`InboundSecurity`, `OutboundSecurity`) suggests that these scripts may have been used to weaken the system's defenses or to ensure that certain types of traffic were allowed through without scrutiny.

3. **Potential Indicators of Malicious Activity**:
   - **Obfuscation and Dynamic Parameters**: The scripts use dynamic parameters and obfuscation techniques, which are common in malicious scripts designed to bypass detection.
   - **Persistence Mechanisms**: The presence of cmdletization and the structured nature of these scripts suggest that they may have been part of a broader persistence mechanism, potentially designed to maintain control over the system even after reboots.

### Indicators of Compromise (IOC):

- **Use of Cmdletization**: This technique is often used by advanced attackers to execute complex tasks that are difficult to detect. The presence of cmdletization in these scripts is a red flag.
- **Network Configuration Manipulation**: The modification of network parameters, such as tunnel endpoints and IPsec policies, suggests an attempt to control or monitor network traffic, potentially for data exfiltration or remote access.
- **Security Policy Manipulation**: The scripts' interaction with security policies, including bypassing encryption and authorization requirements, indicates an effort to weaken the system's security posture.


This analysis suggests that the system may have been subject to a sophisticated attack involving advanced PowerShell techniques. Further investigation and immediate action are recommended to contain and remediate the threat.

______________

## Firewall logs, 
I’ve identified several key indicators of compromise and suspicious activities:
`185757-Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx`
### Key Findings from the Firewall Logs:

1. **Frequent Rule Modifications**:
   - There are numerous logs indicating the addition, modification, and deletion of firewall rules. These changes were often made by `svchost.exe`, which is a legitimate system process but is frequently used by attackers to hide malicious activity.
   - The rules added or modified frequently involve network permissions, specifically allowing or blocking inbound and outbound traffic for various applications, including `Microsoft.Messaging`, `Microsoft.WindowsCamera`, `Shell Input Application`, and others.

2. **Suspicious Rule Changes**:
   - **Rule Additions**: Many rules were added to allow both inbound and outbound traffic across all profiles (Private, Domain, Public). This could be an attempt to open up the system to external communications that bypass security controls.
   - **Rule Deletions**: Several rules related to `WARP_JIT` were deleted, which might be an attempt to remove evidence or disable protective measures. The deletion of rules that block traffic could indicate an effort to ensure uninterrupted external communications, possibly for data exfiltration or command-and-control activities.

3. **Obfuscation and Bypassing**:
   - The firewall rules were frequently modified in a way that could bypass security mechanisms. For example, allowing inbound connections without specifying a precise application path, or using wildcard addresses (`*`) for both local and remote addresses, is a common tactic used to make rules overly permissive.
   - **Edge Traversal**: Some rules enabled edge traversal, allowing traffic to bypass network address translation (NAT) and reach the machine directly from external networks. This is particularly concerning if it was not explicitly configured for legitimate reasons.

### Indicators of Compromise:

- **Unauthorized Rule Modifications**: The numerous changes to firewall rules, especially those that allow wide-ranging access or delete protective measures, strongly suggest that the system was compromised.
- **Use of `svchost.exe`**: The consistent use of `svchost.exe` to modify these rules is suspicious. While it’s a legitimate process, its use in this context could indicate that an attacker has hijacked it to perform these modifications stealthily.
- **Wildcard Usage**: The extensive use of wildcards for IP addresses and ports suggests that the rules were designed to be overly permissive, which could facilitate unauthorized access or data exfiltration.


### Conclusion:

The firewall logs strongly indicate that the system may have been compromised, with an attacker manipulating firewall rules to facilitate malicious activities. Immediate action is recommended to restore the system’s security posture and prevent further compromise.

_____________

## Microsoft Defender Logs

`185754-Microsoft-Windows-Windows Defender%4Operational.evtx`

### Key Events & Indicators of Compromise:

1. **Defender Configuration Changes**:
   - **Event IDs 5007 & 5004** indicate multiple configuration changes in Microsoft Defender. These changes are a common tactic used by attackers to weaken or disable security features, potentially allowing malicious activities to proceed undetected.
   - **Examples**:
     - **SpyNetReporting**: The `SpyNetReporting` value was changed from `0x2` to `0x0`, disabling cloud-based protection.
     - **Script Scanning**: The setting for `DisableScriptScanning` was changed from `0x0` to `0x1`, disabling the scanning of scripts, which could allow malicious scripts to execute without detection.
     - **Real-time Protection**: Multiple events show that real-time protection features were altered, such as disabling `Behavior Monitoring`, `On Access`, and `IE Downloads and Outlook Express Attachments` monitoring.

2. **Antivirus Scan Stopped**:
   - **Event ID 1002** shows that a quick scan was started but stopped prematurely. This could indicate either a manual interruption or interference by malware.

3. **Update Errors**:
   - **Event IDs 2001** show errors when Defender tried to update its security intelligence. The errors, including `0x80072efe` (connection terminated abnormally) and `0x80072ee2` (operation timed out), suggest possible interference with the update process, potentially leaving the system vulnerable to new threats.

### Timeline and Correlation with Other Logs:
- **17/08/2019 05:36:42**: A flurry of changes in Defender's configuration occurs at this time, such as disabling various real-time protection features.
- **Correlation**: This time aligns with other suspicious activities detected in the system, such as the execution of malicious PowerShell scripts and alterations in firewall settings.

### Conclusion:
The Defender logs present strong evidence of tampering, likely by an attacker aiming to disable or weaken security defenses. These events should be correlated with other logs to build a complete picture of the attack. The changes made to Defender settings are typical indicators of compromise (IOCs) and should be considered as part of a broader investigation into the security breach.

_______

## Application event log

`185704-Application.evtx`

### **Analysis of `Application` Event Log**

1. **Security Notifications & Windows Defender State:**
   - Multiple entries indicate that the status of Windows Defender was updated, with states being toggled between `SECURITY_PRODUCT_STATE_ON` and `SECURITY_PRODUCT_STATE_OFF`. This points to a potential attack that involves disabling or interfering with Windows Defender to avoid detection.

2. **Application Crashes:**
   - A critical event shows that the application `SystemSettingsAdminFlows.exe` crashed due to an access violation in `wintypes.dll`. This could potentially indicate exploitation attempts or the presence of a script or tool trying to modify system settings.

3. **VSS Service Shutdown:**
   - The VSS (Volume Shadow Copy Service) shutting down due to idle timeout is noted several times. This could indicate regular system behavior, but in some contexts, it might relate to tampering with system backups.

4. **Certificate Updates:**
   - There are multiple successful auto updates of third-party root certificates. While this can be normal system behavior, in some cases, it might also indicate unauthorized updates or man-in-the-middle (MITM) attacks.

5. **Software Protection Platform:**
   - Events related to Software Protection Platform (SPP) are recorded, including successful scheduling for service restarts and exclusion of policies. Malicious actors sometimes disable or manipulate these services to avoid license enforcement and protection features.

### **Indicators of Potential Compromise:**
- **Repeated Toggling of Windows Defender:** The switching of states from `ON` to `OFF` and vice versa, especially within a short period, is highly suspicious and suggests tampering.
- **Application Crashes:** The crash of `SystemSettingsAdminFlows.exe` could be related to malicious activity or attempts to modify system settings, potentially indicating privilege escalation attempts.
- **VSS Service Behavior:** If VSS service behavior aligns with other malicious activities, it could indicate attempts to delete or alter backups, potentially as part of ransomware or other destructive operations.

________

## System log

`185771-System.evtx`

### Key Indicators:
1. **Service Modifications:**
   - Multiple events indicate changes in the startup configuration of critical services, such as the `Background Intelligent Transfer Service (BITS)` and `Windows Modules Installer`. These services were changed from `demand start` to `auto start`, which could be an indication of persistence mechanisms or preparation for downloading/uploading data.

2. **Windows Update Activities:**
   - Frequent and repeated entries for updates to various Microsoft components and applications (e.g., Microsoft.NET, Microsoft.UI.Xaml, and others) appear, which is normal but can also be leveraged by attackers to introduce malicious updates or to cover up traces of their activities.

3. **Registry Hive Access:**
   - Multiple entries involving access to registry hives, particularly those related to user settings for applications like Microsoft Edge, Xbox, and Windows Photos. Although these entries could be benign, they could also suggest attempts to manipulate user data or application settings.

### Suspicious Activity:
1. **Frequent Service Start/Stop:**
   - The log shows the `Background Intelligent Transfer Service` being toggled multiple times. Since BITS can be used to download or upload data in the background, its unexpected activation is concerning.

2. **Modifications to Critical System Components:**
   - The adjustments to `Windows Modules Installer` and `BITS` may suggest attempts to maintain or execute unauthorized changes. Attackers often manipulate these services to enable persistence or to execute malicious code.


### Summary:
The events captured in the `System` log suggest that system services and critical components have been modified. While these changes can be legitimate, their timing and the frequency of certain activities warrant further investigation to rule out unauthorized system manipulation.

____

## Code Integrity Logs 

`185744-Microsoft-Windows-CodeIntegrity%4Operational.evtx`

#### Key Events:
- **Event ID 3085**: 
  - The logs contain multiple entries with this event ID, which indicates that **Code Integrity** disabled **WHQL driver enforcement** for the boot session. 
  - **WHQL (Windows Hardware Quality Labs) driver enforcement** ensures that only drivers that have been tested and signed by Microsoft are loaded. Disabling this enforcement can allow unsigned or potentially malicious drivers to be loaded during the boot process.

#### Context and Implications:
- **Suspicious Timing**:
  - The Code Integrity logs show that WHQL driver enforcement was disabled at different times, with the most recent entries occurring on **August 17, 2019**, around **05:30-05:33 AM**. 
  - This timing correlates with other suspicious activities found in previous logs, such as tampering with Windows Defender settings and the execution of potentially malicious PowerShell scripts. 

- **Potential Exploitation**:
  - Disabling WHQL enforcement can be a tactic used by attackers to load malicious drivers or kernel-level malware that could go undetected by traditional security tools. 
  - The fact that this was done during the boot process suggests that an attacker may have attempted to establish deep persistence within the system, potentially compromising the kernel or critical system components.

### Cross-Referencing with Other Logs:
1. **PowerShell Logs (`185724-Microsoft-Windows-PowerShell%4Operational.evtx`)**:
   - The timeframe of these Code Integrity events overlaps with periods of suspicious PowerShell activity. It’s possible that the scripts were used to disable driver enforcement or prepare the system to load unauthorized drivers.

2. **System Logs (`185771-System.xml`)**:
   - The System logs showed service modifications and potentially unauthorized service creations around this time. If malicious drivers were loaded, they could have been used to manipulate these services or establish further persistence.

3. **Windows Defender Logs (`185754-Microsoft-Windows-Windows Defender%4Operational.xml`)**:
   - The Defender logs indicate that critical security features were disabled or modified. This would complement the disabling of WHQL enforcement, providing a broader context of the attack strategy to weaken the system's defenses.

### Summary:
- **How Was the Computer Compromised?**:
  - The repeated disabling of WHQL driver enforcement points to a potentially serious compromise, where the attacker gained the ability to load malicious drivers during system boot. This, combined with the manipulation of security settings and service configurations, suggests a sophisticated attack aimed at gaining deep persistence.

- **Extent of the Compromise**:
  - The attack likely included multiple stages: disabling security features, loading unauthorized drivers, and executing malicious scripts to control the system. The use of kernel-level attacks could mean that the attacker had extensive control over the system, possibly including the ability to evade detection and maintain long-term access.




