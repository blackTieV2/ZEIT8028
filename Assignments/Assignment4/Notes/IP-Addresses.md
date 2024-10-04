---

### **Log Report: Artifact - IP 185.47.40.36**

#### **Summary:**
- **IP Address**: 185.47.40.36
- **Owner**: Redpill Linpro AS (ISP based in Norway)
- **Associated Malicious Activity**: 
   - Phishing and Email Spam (Historical)
   - Flagged as **Malware** by MalwareURL
- **Risk Assessment**: Moderate based on the historical use in phishing campaigns, but no strong recent abuse evidence (Confidence of Abuse: 0%).

#### **1. Network Activity Observed:**
- **Date of Network Activity**: 2019-10-14, spanning a series of timestamps from 04:25:01 to 04:25:12.
- **Total Packets Captured**: 448 packets with **TLS Application Data** (Content Type 23).
  
##### **Top Notable Events from TLS Traffic**:
1. **Encrypted Application Data Transfer:**
   - Consistent exchange of TLSv1.2 encrypted data between the internal IP `10.2.0.10` and `185.47.40.36`.
   - Largest packet sizes observed were up to 26,334 bytes (multiple instances).
   - The communication seems to have occurred in a brief time span (within **11 seconds**), indicating a potentially automated process.

2. **Alert/Warning Packets:**
   - At least one instance of a TLS encrypted alert was noted (Packet #70745), potentially indicating a session close or some form of unusual termination in the TLS session.

#### **2. Reputation Analysis**:
- **VirusTotal Analysis** (from screenshot):
   - **Flagged by 1/94 Security Vendors**: 
     - **MalwareURL** reported this IP as linked to malware.
     - Other security vendors, including Acronis, ADMINUSLabs, and Abusix, marked it as **clean**.
- **Historical Abuse Report**:
   - Reported by **Mudguts** on **2022-03-09** for involvement in phishing (fake fax URL hosted at a now-dead URL).
   - **Category**: Phishing, Email Spam (no further activity detected in recent months).

#### **3. Recommendations**:
- **Investigate the Encrypted Traffic**:
   - Given the high volume of **TLS Application Data** being transferred over a short period, inspect the originating application on the local system (`10.2.0.10`).
   - Analyze any decrypted content (if possible) or metadata around these sessions to determine if this was benign or part of a larger attack.
  
- **Block or Monitor IP**:
   - Due to the flagged history (phishing, email spam) and MalwareURL's detection, consider **blocking** this IP temporarily within your network until more data is available.
   - Monitor for any further connections from this IP or similar ones in the same ASN (`AS39029`).

- **Review System Logs**:
   - Perform a review of internal system and application logs (especially from `10.2.0.10`) for any anomalies or suspicious behaviors during the session times.

---

### **Next Steps**:
- If there is further TLS traffic related to this IP after the date of this log, capture it and analyze its patterns.
- Follow up with any domain, URL, or file analysis related to **Redpill Linpro AS** or connected infrastructure.

---

This log report combines both the reputation data from sources like VirusTotal and AbuseIPDB with your network logs, offering a clear analysis of the artifact’s behavior and impact. If you need more analysis or a specific part expanded (e.g., reviewing more packet details), let me know!
