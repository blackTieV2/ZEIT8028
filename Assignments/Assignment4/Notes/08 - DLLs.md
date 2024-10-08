## DLL files flagged in VirusTotal

### 1. **ADVAPI32.dll** (Vic1 - powershell.exe - `0xffffb503219b9540`)
   - **SHA-256**: `9fe5e25d36b0c68db3eba7711a09ff25f8365b9c3c2241f8835b97df8eba6085`
   - **Flagged by**: Bkav Pro (as **W64.AIDetectMalware**).
   - **Comments**:
     - Only 1/72 flagged this file as malicious, which suggests a low confidence in it being a definitive threat. ADVAPI32.dll is a legitimate Windows API library, commonly used for managing security and registry operations. 
     - You should look further into its behavioral patterns from the sandbox and its related processes. No significant behavioral issues were flagged by the sandboxes at this time. 

### 2. **KERNELBASE.dll** (Vic1 - smartscreen.exe - `0xffffb50320e6a080`)
   - **SHA-256**: `3b12becd8375613d34bcbb29cc0b22efbd9622e18eb2373d543e564c87d018cb`
   - **Flagged by**: 2/72 vendors (Ikarus and SecureAge) for **Trojan.Patched**.
   - **Comments**:
     - KERNELBASE.dll is a legitimate Windows component, but the detection of **Trojan.Patched** could indicate it has been altered or injected into by a malicious process.
     - Given that this is the DLL tied to **smartscreen.exe** (which is itself a security utility), a modification of this DLL could indicate it was leveraged in defense evasion tactics. The creation time (September 2073) is also highly anomalous, which raises concerns of tampering.
  
### 3. **KERNELBASE.dll** (Vic2 - smartscreen.exe - `0xffffb80b89a562c0`)
   - **SHA-256**: `a7e30276238c70c66cb9a4483ed6f54d122ba31c84243bc0fcd12503c61d670e`
   - **Flagged by**: 2/72 vendors (Ikarus, Google) for **Trojan.Patched**.
   - **Comments**:
     - This is another instance of **KERNELBASE.dll** being flagged for **Trojan.Patched**, much like the one in Vic1. This supports the possibility that both victims were affected by the same or a similar type of tampering with KERNELBASE.dll.
     - Further behavioral analysis would be required to see if this module is being used for persistence or system hooking.

### **Analysis in Context**:
- The detection of **Trojan.Patched** in **KERNELBASE.dll** files across both victims suggests potential system hooking or modification of critical system functions. Since **smartscreen.exe** is involved in both, it is possible that this executable is being exploited to evade detection or carry out other malicious activities under the guise of a legitimate process.
- The **ADVAPI32.dll** finding, though flagged, is less conclusive and needs to be monitored alongside the flagged smartscreen-related files.
  
