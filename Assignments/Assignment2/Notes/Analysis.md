## Key Artifacts:
(search related to `RESUME.doc.exe`)

### **1. UserAssist**
- **File Name**: `C:\Users\Alan\Downloads\resume.doc.exe`
- **Last Run Date/Time**: 17/08/2019 5:41:59 AM
- **Application Run Count**: 1
- **Source**: NTUSER.DAT (UserAssist registry key)

**Importance**: This artifact indicates that the file `resume.doc.exe` was executed by the user Alan. UserAssist tracks user interactions with files and programs, so this registry entry confirms the execution of the file.

### **2. Prefetch Files**
- **Application Name**: `RESUME.DOC.EXE`
- **Last Run Date/Time**: 17/08/2019 5:41:59 AM
- **File Created Date/Time**: 17/08/2019 5:42:15 AM
- **Application Path**: `C:\Users\Alan\Downloads\resume.doc.exe`
- **File Hash**: `AA8459C3`

**Importance**: The prefetch file shows that `resume.doc.exe` was executed at least once. The `File Created Date/Time` indicates when this prefetch file was created, typically shortly after the executable was run. This is crucial for establishing that the executable was launched and possibly executed a payload.

### **3. Windows Event Logs**
- **Event ID**: 2002
- **Created Date/Time**: 17/08/2019 5:41:00 AM
- **Event Data**: 
  - The event log entry includes a detailed log related to the application execution, which includes a reference to the file `resume.doc.exe` and the URL `https://ca-east.uploadfiles.io/get/hr4z39kn`.

**Importance**: This log indicates that the file `resume.doc.exe` was involved in some communication with the URL `https://ca-east.uploadfiles.io/get/hr4z39kn`. This suggests that the application might have been downloaded or fetched from this URL, or it might be communicating back to the URL after execution.

### **4. Edge/Internet Explorer Main History**
- **URL**: `https://uploadfiles.io/hr4z39kn`
- **Accessed Date/Time**: 17/08/2019 5:39:47 AM
- **Page Title**: `Uploadfiles.io - resume.doc.exe`

**Importance**: This shows that the user Alan accessed the URL and possibly downloaded the file `resume.doc.exe`. The browser history is essential as it gives you the exact time and URL that was visited, helping you understand how the malicious file was accessed.

### **5. Edge/Internet Explorer Downloads**
- **URL**: `https://uploadfiles.io/hr4z39kn`
- **Download Location**: `C:\Users\Alan\Downloads\resume.doc.exe`
- **Last Accessed Date/Time**: 17/08/2019 5:40:19 AM

**Importance**: Confirms the download of the malicious file `resume.doc.exe` from the URL. The timestamps align with the browser history, showing a clear sequence of events leading to the file's execution.

### **6. Timeline (Timeliner)**
- **Start Date/Time**: 17/08/2019 5:41:59 AM
- **Item Name**: `C:\Users\Alan\Downloads\resume.doc.exe`
- **Details**: The registry entry from `ntuser.dat` indicates that this file was executed by the user.

**Importance**: Provides a timeline of events, showing when the file was run. It supports the UserAssist data, further confirming the sequence of actions.

### **Summary of the Sequence**:
1. **Browser History** shows Alan visited the URL `https://uploadfiles.io/hr4z39kn` at 5:39:47 AM on 17/08/2019.
2. **Download**: Alan downloaded the file `resume.doc.exe` at 5:40:19 AM.
3. **Execution**: Alan executed `resume.doc.exe` at 5:41:59 AM, as shown by both the **UserAssist** and **Prefetch** data.
4. **Windows Event Log** provides additional context that the file executed was likely interacting with the internet, possibly communicating with the URL it was downloaded from.

