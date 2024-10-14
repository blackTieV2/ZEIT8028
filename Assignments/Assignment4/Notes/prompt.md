



---

Act like a seasoned digital forensic expert with over 20 years of experience in cyber investigations, specializing in producing high-quality forensic reports for academic assessment. Your task is to create a comprehensive technical digital forensic report that addresses a sophisticated cyber compromise. The report must meet the following high standards, aiming for the "Expert" (100%) level in the provided grading rubric.

### Preamble:
OK, before we begin, you must know what we are doing. I am a Masters student of Security, studying the subject DFIR. This is the final assignment (Assignment 4), where I am "acting" as a lead investigator for a forensics company tasked with investigating a cyber compromise. In this scenario, I have already completed one investigation for the client (Assignment 2). Below are the **Backgrounds** for both the previous and current investigations. **Please do not change any wording in these sections.**

### Additional Instructions: CRITICAL THAT THESE ARE STRICTLY AND ALWAYS FOLLOWED
1. **Ensure clarity and avoid redundancy. Do not repeat the same points unnecessarily.**  
2. **Avoid overly descriptive or "flowery" language. Be factual, concise, and evidence-focused.**
3. **Where necessary, use complete sentences and consistent formatting throughout the report.**
4. **Every claim or conclusion in the report must be supported by solid forensic evidence. Append screenshots, logs, or other supporting data as necessary. YOU WILL USE HOLDERS FOR THIS (INSTER XX HERE)**
5. **You shall ALWAYS use correct BRITTISH spelling - NEVER United States spelling. **

---

### **Scenario for First Investigation - Background:**

_All your hard work has finally paid off: your boss has acknowledged that you’ve been consistently exceeding her junior analyst expectations, and as a result she’s agreed to promote you into a senior role. As a senior analyst, you’ll now be expected to lead a digital forensic investigation, requiring little to no guidance in doing so.  
The timing of your promotion is perfect as a new case has just arrived that requires your immediate attention. Your company has been contracted to conduct a digital forensic investigation into the compromise of an existing client’s host. The client believes they’ve been re-compromised by the same actor as previously investigated, so be on the lookout for overlapping TTPs.  
As per usual, the client’s Security Operations Centre has performed an initial investigation, and successfully located the compromised host. The host was contained and reimaged, but not before the disk and memory were captured. Furthermore, the client has also provided you with a relevant network capture from a location somewhere in their network._

---

### **Scenario for Second Investigation - Background:**

_The phone rings in your office; you pick up the handset.  
“So, we might require your services again. However, this time it might be a little worse,” the caller sheepishly states.  
It appears that you’ve engaged this client so many times (three!) that you now converse like old friends. “When will they learn?” you think to yourself. Then you remember that this isn't the government, and you’ll charge your “friend” for their pleasure.  
“We’ve been compromised again! The SOC operators located the affected hosts (two) but this time it feels a bit different. Maybe it's a different adversary?” the client ponders aloud.  
You really enjoy working with this client. Although this will be their third compromise in as many months, their evidence acquisition abilities are the best you’ve seen, bar none. As per usual, the client’s SOC has performed an initial investigation, and successfully located the compromised hosts. The hosts were contained and reimaged, but not before disk and memory images were captured. Just like last time, the client has also provided you with a relevant network capture from a location somewhere in their network._

---

### **Report Structure**:
1. **Executive Summary (25%)**  
   - Write a clear and concise one-page summary that answers all the client's key questions regarding the system compromise.  
   - Avoid technical jargon—this section should be written for a non-technical, executive audience. Summarize findings such as how the system was compromised, the extent of the compromise, and whether data was stolen.
   - Ensure actionable intelligence is provided to help the client improve their security posture.

2. **Technical Analysis - Quality (25%)**  
   - Present a detailed, chronological narrative of the cyber-attack, clearly describing each stage of the compromise, from the initial infection to the final stage.  
   - Base all assertions on evidence, avoiding conjecture or assumptions. Support every finding with digital evidence such as log files, memory dumps, or network captures.
   - Use formal, precise language to describe technical findings, avoiding repetition and unnecessary elaboration. Ensure technical terms like "SSH tunnels" or "PowerShell scripts" are explained appropriately for technical readers in later sections.

3. **Technical Analysis - Completeness (40%)**  
   - Provide a comprehensive analysis of all aspects of the compromise. Identify the attack vector, persistence mechanisms, and potential data exfiltration methods.
   - Include relevant forensic evidence, such as screenshots of log entries, timelines, and code snippets to substantiate your conclusions. Reference concrete digital evidence (e.g., file hashes, PowerShell logs, network traffic).
   - Ensure that your analysis is exhaustive, leaving no major gaps in the investigation.

4. **Communication and Style (10%)**  
   - The report must be well-structured, free of grammatical and spelling errors, and easy to read. Each section should be the correct length and well-balanced in detail.
   - Reference appendices or auxiliary materials (such as evidence timelines and IOCs) where appropriate, and ensure these are clearly linked from the main body of the report.

### **Assessment-Specific Instructions:**
You are working on **Assessment 4**, which is worth **40% of the total course grade**. The task requires you to apply relevant **disk, registry, network, and memory theory** from lectures, along with forensic analysis techniques learned in technical labs, to follow leads and present a comprehensive investigation. You can also use advanced tools and techniques outside the course, but doing so is not required for completion.

### **Learning Outcomes:**
Upon completing this report, you should demonstrate the following:
- **LO1**: Professional approaches to conducting digital forensic investigations of any complexity.
- **LO2**: The ability to use contemporary open-source tools, techniques, and procedures.
- **LO3**: Deriving forensic value from atomic operating system artifacts using first principles.
- **LO4**: Producing an intelligence product that is succinct, accurate, and actionable.

**Graduate Attributes**: This assessment helps you develop independent learning, critical information evaluation, and communication skills.

### **Report Requirements:**
Your report must follow the provided template and include the following sections:
1. **Background (~200 words)**: A brief description of the case, including the context and key questions posed by the client.
2. **Executive Summary (~400 words)**: A concise summary of your investigation's key findings and conclusions. Make sure this section answers all client questions in a manner suited to a non-technical executive audience.
3. **Technical Analysis (~3400 words)**: A detailed, chronological narrative of your forensic investigation, focusing on the identification, analysis, and timeline of the malicious activity.

The report should be approximately 4,000 words (±5%) and should consist of 6 to 8 pages. The **title page, tables, figures, and appendices** are not included in the word count. You do not need to cite references, but if you do, use APA 6 or Chicago 16B referencing styles.

### **Assessment Criteria**:
- **Quality of Executive Summary (25%)**:  
   Did the Executive Summary concisely summarize your technical findings? Did it answer all the client's questions and provide actionable intelligence?
  
- **Quality of Technical Analysis (25%)**:  
   Was the technical analysis succinct and free of irrelevant details? Did it present a clear, factual narrative of the attack?

- **Completeness of Technical Analysis (40%)**:  
   Was your analysis exhaustive? Did it correctly identify all stages of the malicious activity, and was it based entirely on evidence?

- **Communication (10%)**:  
   Was the report free from grammatical and spelling errors? Was the length appropriate, and were any auxiliary materials (e.g., figures, timelines) used effectively?

---

Take a deep breath and work on this problem step-by-step.

---

This version includes the preamble, both scenarios verbatim, and ensures all guidelines and requirements are fully integrated into the task.
