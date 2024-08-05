### Exercise 3:

#### Part (a): Statically Locate the Sensitive Document

1. **Initial File Listing**
   - Eexecuted the following command to create a comprehensive list of all files in the disk image:
     ```shell
     fls -r -m / /mnt/8028HDD/Module\ 2/Lab\ 2/Lab2Image/Lab\ 2\ -\ Disk\ Forensics/lab2_partition.bin > Lab2-Ex3-flsRM.txt
     ```
   - This resulted in a text file of over 10 MB containing 68,522 listed files.
[Lab2-Ex3-flsRM.txt](https://github.com/blackTieV2/ZEIT8028/blob/main/Labs/Lab2/OutputFiles/Lab2-Ex3-flsRM.txt)
2. **Search for Excel Files**
   - Initially, tried to use `grep` to find Excel files:
     ```shell
     grep -iE "\.xls$|\.xlsx$" Lab2-Ex3-flsRM.txt
     ```
   - This command failed to return any results.

3. **Modified Search Command**
   - Modified the `grep` command to:
     ```shell
     grep -iE "\.xls|\.xlsx" Lab2-Ex3-flsRM.txt > flsGrepXls.txt
     ```
   - This resulted in a list of 30 files.
     [grep output](https://github.com/blackTieV2/ZEIT8028/blob/main/Labs/Lab2/OutputFiles/flsGrepXls.txt)
   - Among them, I identified the following entries:
     - `/Documents and Settings/Jean/Desktop/m57biz.xls ($FILE_NAME)|32712-48-4|r/rrwxrwxrwx|0|0|86|1216517283|1216517283|1216517283|1216517283`
     - `/Documents and Settings/Jean/Desktop/m57biz.xls|32712-128-3|r/rrwxrwxrwx|0|0|291840|1216517283|1216517283|1216517284|1216517283`
     - Noting and Documenting the file inode numer
     - `32712-128-3`
> ### Importance of the Inode Number:
> **Unique Identification:**
> The inode number is a unique identifier for a file within a filesystem. It is used by the filesystem to keep track of the file's attributes and location on the disk. This unique identification is crucial for accurately referencing and retrieving the file during forensic analysis.
>
> **File Metadata:**
> The inode stores important metadata about the file, such as its size, permissions, timestamps (creation, modification, access), and pointers to the data blocks where the file's actual content is stored. This metadata is essential for understanding the file's history and usage.
>
> **Consistency Verification:**
> During forensic analysis, the inode number can be used to verify the consistency and integrity of the file. By cross-referencing the inode information with other filesystem records, investigators can ensure that the file has not been tampered with or altered.
>
> **Efficient Access:**
> Inodes allow for efficient file access and retrieval. Instead of searching the entire filesystem for a file, the inode provides a direct pointer to the file's location, speeding up the analysis process.


4. **Extract the File Using `icat`**
   - Extracted the file `m57biz.xls` using the command:
     ```shell
     icat lab2_partition.bin 32712-128-3 > m57biz.xls
     ```
     [icat output](https://github.com/blackTieV2/ZEIT8028/blob/main/Labs/Lab2/OutputFiles/m57biz.xls)
  

5. **Verify the File Type Using `hexdump`**
   - Verified the file type using:
     ```shell
     hexdump -C -n 8 m57biz.xls
     ```
   - Confirmed it has the OLECF signature: `d0 cf 11 e0 a1 b1 1a e1`.

6. **Inspect the File Metadata Using `file`**
   - Used the `file` command:
     ```shell
     file m57biz.xls
     ```
   - Output: 
     ```
     Composite Document File V2 Document, Little Endian, Os: Windows, Version 5.1, Code page: 1252, Author: Alison Smith, Last Saved By: Jean User, Name of Creating Application: Microsoft Excel, Create Time/Date: Thu Jun 12 15:13:51 2008, Last Saved Time/Date: Sun Jul 20 01:28:03 2008, Security: 0
     ```

7. **Inspect the File Metadata Using `olemeta`**
   - Used the `olemeta` tool to extract more detailed metadata:
     ```shell
     olemeta m57biz.xls
     ```
   - Output from `olemeta`:
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

#### Part (b): Verification of File Type

1. **Confirm OLECF File Type**:
   - Confirmed the file is an OLECF file using `hexdump` and `file`.

2. **Verify Using Hexdump**:
   - The initial bytes match the OLECF signature, indicating it is a Microsoft Office file.

3. **Inspect Metadata**:
   - The `file` command provided initial metadata.
   - The `olemeta` tool provided detailed metadata, confirming the authorship and timestamps.

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

### Report on Initial Findings

Based on the metadata extracted from the `m57biz.xls` file:

- **When did Jean create the spreadsheet?**
  - The spreadsheet was created on June 12, 2008, at 15:13:51.

- **How did it get from her computer to the competitor's website?**
  - This requires further analysis of email, browser history, and network logs to determine.

- **Who else from the company was involved?**
  - Further analysis of system logs and user activities is needed to determine additional involvement.
