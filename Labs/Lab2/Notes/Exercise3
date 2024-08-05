### Exercise 3:

#### Part (a): Statically Locate the Sensitive Document

1. **Locate the File**
   - You have identified two instances of `m57biz.xls` in your file search:
     - `/Documents and Settings/Jean/Desktop/m57biz.xls ($FILE_NAME)|32712-48-4|r/rrwxrwxrwx|0|0|86|1216517283|1216517283|1216517283|1216517283`
     - `/Documents and Settings/Jean/Desktop/m57biz.xls|32712-128-3|r/rrwxrwxrwx|0|0|291840|1216517283|1216517283|1216517284|1216517283`
   
2. **Extract the File Using `icat`**
   - You have already extracted the file `m57biz.xls` using the command:
     ```shell
     icat lab2_partition.bin 32712-128-3 > m57biz.xls
     ```
   - Ensure you document the inode number and the extraction process in your notes.

3. **Verify the File Type Using `hexdump`**
   - You verified the file type using:
     ```shell
     hexdump -C -n 8 m57biz.xls
     ```
   - Confirmed it has the OLECF signature: `d0 cf 11 e0 a1 b1 1a e1`.

4. **Inspect the File Metadata Using `file`**
   - You have used the `file` command:
     ```shell
     file m57biz.xls
     ```
   - Output: 
     ```
     Composite Document File V2 Document, Little Endian, Os: Windows, Version 5.1, Code page: 1252, Author: Alison Smith, Last Saved By: Jean User, Name of Creating Application: Microsoft Excel, Create Time/Date: Thu Jun 12 15:13:51 2008, Last Saved Time/Date: Sun Jul 20 01:28:03 2008, Security: 0
     ```

5. **Inspect the File Metadata Using `olemeta`**
   - Use the `olemeta` tool to extract more detailed metadata:
     ```shell
     olemeta m57biz.xls
     ```
   - Document any interesting findings. For instance, the `olemeta` output showed:
     ```
     Name: m57biz.xls
     Author: Alison Smith
     Last Saved By: Jean User
     Revision Number: 4
     Total Editing Time: 00:00:00
     Last Printed: n/a
     Create Time/Date: 2008-06-12 15:13:51
     Last Saved Time/Date: 2008-07-20 01:28:03
     ```

### Analysis and Findings:

- **Creation Date**:
  - The spreadsheet was created on `Thu Jun 12 15:13:51 2008`.

- **Last Modified Date**:
  - The spreadsheet was last modified on `Sun Jul 20 01:28:03 2008`.

- **Authorship**:
  - The document was authored by Alison Smith and last saved by Jean User.

### Step-by-Step Instructions:

#### Part (b): Verification of File Type

1. **Confirm OLECF File Type**:
   - You confirmed the file is an OLECF file using `hexdump` and `file`.

2. **Verify Using Hexdump**:
   - The initial bytes match the OLECF signature, indicating it is a Microsoft Office file.

3. **Inspect Metadata**:
   - The `file` command provided initial metadata.
   - The `olemeta` tool provided detailed metadata, confirming the authorship and timestamps.

### Step-by-Step Instructions:

#### Part (c): Inspection of Metadata with File and Olemeta

1. **Using `file`**:
   - The `file` command confirmed the type and some metadata details.

2. **Using `olemeta`**:
   - Extracted detailed metadata showing authorship, creation, and modification dates.

### Next Steps:

1. **Explore Email and Browser History**:
   - Look for evidence of how the document was shared or uploaded.

2. **Inspect Network Logs**:
   - Check for any uploads to external websites or file transfers.

3. **Analyze User Activity Logs**:
   - Review system logs for user activity related to the document.

### Commands and Tools:

- **Email Analysis**:
  ```shell
  readpst -o output_folder email.pst
  ```

- **Browser History Analysis**:
  ```shell
  cat index.dat | strings | grep -i "m57biz.xls"
  ```

- **Network Log Inspection**:
  ```shell
  cat /var/log/network.log | grep -i "m57biz.xls"
  ```

- **System Log Review**:
  ```shell
  grep -i "m57biz.xls" /var/log/syslog
  ```

By following these steps, you should be able to gather the necessary information to answer the customer’s questions comprehensively. Document each finding in your report as you progress through the analysis.

### Report on Initial Findings

Based on the metadata extracted from the `m57biz.xls` file:

- **When did Jean create the spreadsheet?**
  - The spreadsheet was created on June 12, 2008, at 15:13:51.

- **How did it get from her computer to the competitor's website?**
  - This requires further analysis of email, browser history, and network logs to determine.

- **Who else from the company was involved?**
  - Further analysis of system logs and user activities is needed to determine additional involvement.

By meticulously documenting these findings and continuing with the investigation steps outlined, you will be able to provide a comprehensive report on the incident.
