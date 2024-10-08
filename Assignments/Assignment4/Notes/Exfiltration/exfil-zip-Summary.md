### Detailed Analysis of `exfil.zip` and Its Role in the Attack Chain

**Artifact Overview:**
- **File Name**: `exfil.zip`
- **Contents**: 
   - `SAM` file (Security Account Manager)
   - `SYSTEM` file (System Hive)
- **Source**: 
   - `victim_02.disk.raw - Partition 4 (Microsoft NTFS, 59.4 GB) Windows\exfil.zip\SYSTEM`
   - `victim_02.disk.raw - Partition 4 (Microsoft NTFS, 59.4 GB) Windows\exfil.zip\SAM`
- **Purpose**: These files contain critical system information, including hashed passwords and system configuration data, which are commonly targeted during privilege escalation and credential harvesting by attackers.

### Role of `exfil.zip` in the Attack Chain:

1. **Initial Foothold on Victim 1:**
   - The attack began on **Victim 1**, who downloaded a malicious executable, `minesweeperz.exe`, which was identified as a potential **malware downloader** or a **dropper**. This malware likely established an initial foothold, providing the attacker remote access to **Victim 1**'s machine.
   - Evidence from the timeline and traffic analysis suggests **Victim 1**’s system was infected first. During this phase, the attacker may have deployed tools for lateral movement or malware propagation.

2. **Lateral Movement to Victim 2:**
   - Following the infection of **Victim 1**, there is strong evidence suggesting **lateral movement** from **Victim 1** to **Victim 2**. 
   - **Victim 2** was likely compromised through this lateral movement mechanism. SSH tools found in the **Shim Cache** on **Victim 2** (e.g., `ssh-keygen.exe`, `sshd.exe`) point towards potential **remote access** established by the attacker.
   - The timeline suggests that after gaining access to **Victim 2**, the attacker was able to initiate further malicious activities, including credential harvesting.

3. **Exfiltration of Credentials and System Files:**
   - The **exfil.zip** file, found on **Victim 2**’s system, contains two critical files: the **SAM** and **SYSTEM** hives. These files are commonly targeted in attacks where **credential harvesting** is the goal.
      - The **SAM** file contains hashed password data for local accounts.
      - The **SYSTEM** file is needed to decrypt the password hashes from the **SAM** file.
   - Together, these files allow an attacker to **extract and crack the credentials** of local users on the compromised machine. By leveraging tools such as **mimikatz** or **hashcat**, the attacker can decrypt these passwords, granting them further access to the network.

4. **Encryption and Exfiltration Mechanism:**
   - Network traffic captured from the investigation shows **large encrypted data transfers** between **Victim 2** and an external IP address (185.47.40.36). These transfers are a strong indicator of **data exfiltration**, likely the **exfil.zip** file.
   - The timeline of these transfers, coupled with the **exfil.zip** creation timestamp, suggests the attacker encrypted and transmitted the sensitive system files out of **Victim 2**’s system to a command and control (C2) server or a drop point.

5. **Post-Exfiltration Cleanup:**
   - The presence of the **sdelete64.exe** tool, which securely deletes files from the disk, suggests that the attacker attempted to clean up after the exfiltration by removing traces of the operation, including any evidence of the **exfil.zip** file creation or transfer.
   - This points to a sophisticated attacker aiming to minimize forensic evidence, making detection and response more difficult for investigators.

### Key Findings from `exfil.zip` Analysis:

| Artifact      | Content                         | Significance                                                                                     |
|---------------|----------------------------------|--------------------------------------------------------------------------------------------------|
| **SAM**       | Contains local account hashes    | Critical for harvesting credentials, especially if combined with SYSTEM to decrypt the hashes.    |
| **SYSTEM**    | Registry hive with encryption keys| Allows an attacker to decrypt password hashes from the SAM file, essential for further exploitation.|

- **Extraction Timestamps**: 
  - Based on the forensic timeline, **exfil.zip** was created and transferred out of **Victim 2**'s machine shortly after it was compromised. 
  - The timestamps indicate that the exfiltration occurred around **14/10/2019 at 05:54:56 UTC**, aligning with suspicious network activity and large data transfers.

- **Indicators of Compromise (IoCs)**: 
  - The **exfil.zip** file, its creation, and transfer from **Victim 2** to the external IP (185.47.40.36) serve as strong IoCs indicating the completion of the exfiltration phase in this attack.

### Analysis of Attacker's Objective:

The creation of **exfil.zip** indicates that the attacker was primarily interested in **harvesting credentials** and possibly other system configuration details for further exploitation. The presence of **SAM** and **SYSTEM** in the exfiltrated file suggests the attacker aimed to:

- **Gain Persistent Access**: Using the credentials harvested from **Victim 2**, the attacker could have accessed other systems in the network, furthering their foothold.
- **Escalate Privileges**: By extracting and decrypting local account hashes, the attacker could escalate privileges on other systems or even domain-level accounts if cached credentials were present.

### Attack Chain Summary with `exfil.zip`:

1. **Initial Infection**: 
   - **Victim 1** compromised via `minesweeperz.exe`.
   - Attackers gained initial access, likely through remote code execution.

2. **Lateral Movement**: 
   - Using tools like **ssh-keygen.exe**, the attacker moved laterally to **Victim 2**, establishing remote access and persistence.

3. **Credential Harvesting**: 
   - The attacker extracted the **SAM** and **SYSTEM** files to facilitate credential harvesting.

4. **Exfiltration**: 
   - The **exfil.zip** containing **SAM** and **SYSTEM** files was created on **Victim 2** and subsequently exfiltrated over an encrypted TLS session to the external IP **185.47.40.36**.

5. **Cleanup and Persistence**: 
   - The attacker used **sdelete64.exe** to clean traces from **Victim 2**’s system and likely set up persistence mechanisms for future access.

### Conclusion:

The **exfil.zip** plays a critical role in the attack, marking the phase where the attacker harvested sensitive credentials and system files from **Victim 2**. By analyzing the SAM and SYSTEM files, it’s evident the attacker aimed to leverage these files to gain further access within the network or to escalate privileges. The sophisticated exfiltration mechanism, use of secure deletion tools, and the encrypted nature of the data transfer demonstrate a well-planned and executed attack strategy aimed at long-term persistence and control within the compromised network.
