
Drawing on all the reports, YARA results, and memory dumps from **Volatility** that I have analyzed, the attacker leveraged multiple sophisticated techniques to compromise the two PCs. Here's a detailed explanation of **WHAT** the attacker did and **HOW** they compromised the systems.

### Attack Vectors:
1. **Powershell Abuse and Process Injection**:
   Powershell, a legitimate and powerful scripting tool in Windows, was the central tool used by the attacker to carry out malicious activities on both PCs. Powershell scripts were likely obfuscated or executed in memory, bypassing traditional file-based detection systems. Powershell was used in conjunction with other processes, particularly **explorer.exe** and **RuntimeBroker.exe**, which were targeted for injection.
   
   The attacker employed **DLL injection** and **process hollowing** techniques to manipulate these legitimate processes, running their malicious code without raising immediate suspicion. The frequent appearance of functions like `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` suggests that these processes were injected with code, allowing the attacker to run arbitrary malware inside trusted Windows processes.

2. **Use of Process Injection and Hidden Process DLL Injections**:
   Multiple reports confirm that **RuntimeBroker.exe** and **explorer.exe** were injected with DLLs through memory manipulation techniques. These legitimate processes were likely "hollowed" out using **VirtualAllocEx** and **ReadProcessMemory**, allowing the attacker to inject and execute malicious payloads. By using **memory-resident attacks**, the malware avoided detection from most antivirus solutions, which focus on file-based threats.
   
   The injection process involved the usage of Windows API functions like `VirtualProtectEx` to modify the permissions of memory regions and `NtCreateSection` to map malicious code into the process memory. These functions are classic indicators of sophisticated injection techniques, often used by malware to gain persistence within the system.

3. **Persistence and Backdoor Mechanisms**:
   To maintain persistence, the attacker leveraged the **Windows Registry** and injected hooks into **API calls**. These hooks allowed them to execute their payloads whenever specific functions were called by legitimate system processes. Registry modifications, noted through `RegSetValueExW` and other API calls, show that the attacker used registry keys for persistence, possibly through run keys or scheduled tasks, ensuring the malware ran at system startup.
   
   Furthermore, API hooking via functions like `GetProcAddress` and `SetWindowsHookEx` suggests that the attacker was able to monitor and modify critical system activities to remain undetected and execute malicious code whenever certain conditions were met.

4. **Volatility Evidence of Memory-Resident Malware**:
   **Volatility** analysis showed evidence of malware that was never written to disk but instead operated entirely within system memory. By using **Powershell** to launch payloads directly in memory, the attacker avoided detection from most endpoint protection systems, which primarily focus on scanning files. This technique is part of a broader trend in **fileless malware** attacks, where all malicious operations occur within memory.
   
   The memory forensics tools identified malicious Powershell commands that triggered the use of **Volatility modules** like `pslist` and `dlllist`, showing that malicious processes were running in memory, along with injected DLLs that did not match typical system behavior.

5. **Use of `LoadLibrary` and Other Injection Methods**:
   The attack involved **dynamic loading of libraries** using the `LoadLibraryW` and `LoadLibraryExW` APIs. These are often leveraged to load malicious DLLs into legitimate processes. The **Hidden Process DLL Injection** report indicated several occurrences where these libraries were injected into trusted processes, including **MicrosoftEdge.exe**, **explorer.exe**, and **Powershell.exe**.

   By injecting into such trusted processes, the attacker was able to escalate privileges and execute malicious code while hiding behind the veil of legitimate Windows operations.

6. **Sophisticated Use of Windows Subsystem and APIs**:
   The reports also show that the attacker made heavy use of Windows APIs to manipulate process memory, inject DLLs, and evade detection. Functions like `VirtualAllocEx`, `NtMapViewOfSection`, `CreateRemoteThread`, and `WriteProcessMemory` were key elements in enabling the attacker to perform **remote code execution** and **in-memory exploitation** without triggering immediate alarms. The use of **Powershell** as a delivery mechanism for these payloads ensured that the attack could be carried out using tools already installed on the system, reducing the need for external malware files.

7. **Volatility and Rootkit-Like Behavior**:
   The **rootkit-like behavior** of this attack is evident in how the malware and injected code modified system memory, hooked into API functions, and controlled process behavior in a way that was not immediately visible in standard process listings. **Volatility** detected hidden processes, injected DLLs, and memory regions that were not typically associated with the processes they were found in. The evidence points to the attacker using rootkit techniques to hide their operations deep within the system, making detection difficult.

### Conclusion:
The attacker gained access to both PCs using **memory-resident Powershell malware** combined with **process injection** and **DLL injection** techniques. By leveraging **Powershell**, they avoided creating traditional malware files, instead operating almost entirely in system memory. They compromised legitimate system processes, such as **explorer.exe**, **RuntimeBroker.exe**, and **MicrosoftEdge.exe**, through advanced injection techniques. These processes were manipulated to run malicious code, allowing the attacker to maintain persistence and control while evading detection from traditional antivirus tools.

The compromise was likely part of a sophisticated **Advanced Persistent Threat (APT)**, using **fileless malware** and **memory manipulation** techniques to achieve their goals while remaining hidden within the operating system for as long as possible. The attackers also employed various Windows APIs to execute code, hook into system functions, and maintain persistence on the compromised PCs.