# Exercise 4: Finding the Pivot

### Part (a): Dynamic and Static Inspection

1. **Navigate to Jean's Documents Directory**:
    ```shell
    cd /mnt/8028HDD/Module2/Lab2/mnt/lab2_partition/'Documents and Settings'/Jean/'My Documents'
    ```

2. **List Contents of Jean's Documents Directory**:
    ```shell
    ls -l
    ```
    Output:
    ```plaintext
    total 5
    drwxrwxrwx 1 root root    0 Jul 18  2008  AIMLogger
    drwxrwxrwx 1 root root    0 Jul  6  2008 'My Music'
    drwxrwxrwx 1 root root 4096 Jul  6  2008 'My Pictures'
    -rwxrwxrwx 1 root root   75 Jul  6  2008  desktop.ini
    ```

3. **Find Relevant Files**:
    ```shell
    find . -type f -iname "*.eml" -o -iname "*.pst" -o -iname "*.msg" -o -iname "*.csv" -o -iname "*.xls" -o -iname "*.xlsx" -o -iname "*.pdf" -o -iname "*.doc" -o -iname "*.docx" -o -iname "*.zip" -o -iname "*.rar" -o -iname "*.7z" -o -iname "*.tar.gz" -o -iname "*.tar" -o -iname "*.html" > Lab2-Ex4-find.txt
    ```
[find output](https://github.com/blackTieV2/ZEIT8028/blob/main/Labs/Lab2/OutputFiles/Lab2-Ex4-find.txt)

4. **Inspect the Content of `Lab2-Ex4-find.txt`**:
    - Manually search for interesting files. Notably, `aim.html` and `alisonm57.html` were found.

5. **Analyze `alisonm57.html`**:
    - Extracted and opened the file to find chat logs between Jean (m57jean) and Alison (alisonm57).
    - **File Content**:
        ```plaintext
        ...
        <tr><td nowrap>6:05:38 AM</td><td nowrap>m57jean</td><td nowrap><font color="blue">hi</font></td></tr>
        <tr><td nowrap>6:05:41 AM</td><td nowrap>alisonm57</td><td nowrap><font color="blue">hey</font></td></tr>
        ...
        <tr><td nowrap>6:13:19 AM</td><td nowrap>alisonm57</td><td nowrap><font color="blue">bye</font></td></tr>
        ```
  ![ScreenShot of `alisonm57.html`](https://github.com/blackTieV2/ZEIT8028/blob/main/Labs/Lab2/ScreenShots/Lab2-Ex4-alisonm57_html.JPG)
### Analysis of AIM and AlisonM57 HTML Files

The content of the AIM and AlisonM57 HTML files provides valuable insight into the interactions between Jean and Alison. Here's a detailed analysis of both files:

#### AIM Chat History (`aim.html`)
- The AIM chat history shows automated messages from the AIM service on two dates: July 19 and July 20, 2008.
- The messages inform Jean about buddy requests and provide links to view these requests.
- No direct messages or interactions between Jean and any other individual are shown in this file.

#### AlisonM57 Chat History (`alisonm57.html`)
- The chat history between Jean (m57jean) and Alison (alisonm57) spans from July 18 to July 21, 2008.
- The conversations cover various topics, including work-related discussions and personal matters.
- Key points from the chat logs include:
  - Alison reminding Jean to focus more on work.
  - Jean acknowledging tasks and mentioning issues like PMS.
  - Alison and Jean discussing the company's direction and finances.
  - Alison questioning Jean about cash left in the account, with Jean responding about the discretionary funds available.
  - Jean making casual remarks about the boss and mentioning looking for a new laptop bag.
  - Alison indicating the need for high-speed internet for her next hotel stay.
  - Jean mentioning putting together an itinerary using a notebook app.

### Insights
- The chat history between Alison and Jean suggests a close working relationship with frequent communication. Alison appears to be in a supervisory role, reminding Jean of work priorities and financial matters.
- These chats also hint at potential financial irregularities or issues within the company, as Jean mentions discretionary funds and the boss "dipping" into resources.
- The next step would be to correlate the chat history timestamps with other relevant data on Jean's computer, such as email records, to determine if the spreadsheet was shared or discussed during these conversations.

This analysis provides a clearer picture of the interactions between Jean and Alison and helps build a profile of Jean's computer usage and communication patterns.

### Relevant Time Metadata

From the analysis of the `alisonm57.html` file, the relevant time metadata for the conversations between Jean (m57jean) and Alison (alisonm57) are as follows:

- **Friday, July 18, 2008**
  - 6:05:38 AM - 6:13:19 AM: Multiple messages exchanged between Jean and Alison.
- **Monday, July 21, 2008**
  - 12:50:12 AM - 1:46:45 AM: Multiple messages exchanged between Jean and Alison.

### Conclusions from the Discussions

The discussions between Jean and Alison reveal several key points:

1. **Work Dynamics**:
   - Alison often reminds Jean to focus on work, indicating a supervisory role.
   - Jean acknowledges tasks and mentions personal issues affecting her work.

2. **Financial Matters**:
   - Alison inquires about the company's financial status.
   - Jean mentions discretionary funds and hints at the boss's questionable financial practices.

3. **Personal Conversations**:
   - The chats also cover personal topics, including work-life balance and purchasing decisions.
   - Jean and Alison discuss marketing strategies and potential business directions.

4. **Potential Miscommunication**:
   - There are indications of miscommunication or unawareness, such as Jean mentioning financial issues that Alison is unaware of.

### Forensic Artefacts Extracted and Analyzed

1. **m57biz.xls**:
   - **Extraction**: Used `icat` to extract the file.
   - **Verification**: Confirmed as an OLECF file using `hexdump`.
   - **Metadata Inspection**:
     - **file command**: Revealed basic metadata.
     - **olemeta command**: Provided detailed metadata, including creation and modification times, authorship, and last saved by information.

2. **Chat History Files**:
   - **aim.html**: Contained automated AIM service messages with no relevant user interactions.
   - **alisonm57.html**: Detailed chat history between Jean and Alison, revealing important context about their interactions and company-related discussions.

### Next Steps

To proceed with the investigation, the following steps are recommended:

1. **Correlate Chat Timestamps**:
   - Cross-reference the chat history timestamps with other digital artifacts (e.g., emails, document access logs) to find any discussion or actions related to the spreadsheet.

2. **Investigate Email Records**:
   - Look for emails sent by Jean around the dates mentioned in the chats to see if the spreadsheet was shared via email.

3. **Review Financial Documents**:
   - Examine any financial documents or logs that might provide additional context to Jean's comments about discretionary funds and the boss's financial practices.

