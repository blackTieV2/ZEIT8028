## Machine Details

- **Operating System**: Windows 10 Enterprise Evaluation (1809)
- **System Root**: `C:\Windows`
- **Current Build Number**: `17763`
- **Edition**: Enterprise Evaluation
- **Registered Owner**: int3rupt
- **Install Date**: Approx. Unix Timestamp `1562812711`

### Summary
The compromised machine is running Windows 10 Enterprise Evaluation, registered to a user or organization named "int3rupt."

### 1. Set Up Your Environment
First, make sure you are in the directory where Volatility's `vol.py` script is located.

### 2. Identify the Profile
You need to identify the correct Volatility profile to use for your memory capture. This profile will correspond to the specific Windows version and architecture (32-bit or 64-bit).

Use the following command:

```bash
python2 vol.py -f ~/8028HDD/'Assessment 2'/Evidence/memory/memory.raw imageinfo
```

This will analyze the memory dump and provide suggested profiles. Look for the `Suggested Profile(s)` output.

### 3. Get the Exact Windows Version
Once you have the suggested profiles, you can dig deeper into the specific Windows version by using the `kdbgscan` or `verinfo` plugin.

```python
Suggested Profile(s) : Win10x64_17134, Win10x64_14393, Win10x64_10586, Win10x64_16299, Win2016x64_14393, Win10x64_17763, Win10x64_15063 (Instantiated with Win10x64_15063)
```
#### Using `verinfo`
This plugin provides a straightforward way to obtain the version information:

```bash
python2 vol.py -f ~/8028HDD/'Assessment 2'/Evidence/memory/memory.raw --profile=Win10x64_17763 verinfo
```

The `verinfo` plugin will directly provide you with the version information, including the major, minor, and build numbers.

### 4. Interpret the Results
After running `verinfo` examine the output:

- **Major and Minor Version:** This will indicate the main version of Windows (e.g., 6.1 corresponds to Windows 7).
- **Build Number:** This gives the specific build, which can be mapped to a specific update or service pack.
- **Service Pack:** Identifies the service pack level if applicable.

You can cross-reference the build number with Microsoft's official documentation or use online resources to match it to the specific release number of Windows.

```bash
\SystemRoot\System32\smss.exe
  File version    : 10.0.17763.1
  Product version : 10.0.17763.1
  Flags           : 
  OS              : Windows NT
  File Type       : Application
  File Date       : 
  CompanyName : Microsoft Corporation
  FileDescription : Windows Session Manager
  FileVersion : 10.0.17763.1 (WinBuild.160101.0800)
  InternalName : smss.exe
  LegalCopyright : \xa9 Microsoft Corporation. All rights reserved.
  OriginalFilename : smss.exe
  ProductName : Microsoft\xae Windows\xae Operating System
  ProductVersion : 10.0.17763.1
```

The output from the `verinfo` plugin shows that the memory capture is from a system running:

- **Windows Version:** Windows 10
- **Build Number:** 17763
- **Version:** 10.0.17763.1

### Interpretation:
- **Windows 10, Version 1809 (October 2018 Update):** The build number `17763` corresponds to Windows 10 Version 1809, which is also known as the October 2018 Update.

This confirms that the system from which the memory was captured was running Windows 10 Version 1809 (Build 17763). This version was released to the public in October 2018. The detailed file version (`10.0.17763.1`) indicates the specific build number, which is often the initial release build for this version of Windows 10.



