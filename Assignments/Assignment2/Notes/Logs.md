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
