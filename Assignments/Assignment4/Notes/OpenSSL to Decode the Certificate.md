

### Wireshark Filter
``bash
ip.addr == 31.130.160.131 && tls.handshake.type == 11
``
#### Locate Certificate in a Frame
The certificate is present in Frame under TLSv1.2 Record Layer: Handshake Protocol: Certificate.

![image](https://github.com/user-attachments/assets/2467adf1-a086-4a37-ae3b-bcf154626191)

1. **Right-click** on the highlighted row.
2. Choose **Export Selected Packet Bytes**.
3. Save it with the file extension **`.der`** (e.g., `certificate.der`).

This should capture the certificate data correctly. Then in Kali run the `openssl` command to decode the certificate:

```bash
openssl x509 -inform der -in certificate.der -text -noout
```

You've successfully extracted and decoded the certificate. Here are the key details from the certificate:

### Key Details:
- **Version**: 3
- **Serial Number**: `02:84:f5:7f:46:7b:b1:f4:ed:58:49:ec:c6:c5:7f:ab`
- **Signature Algorithm**: `ecdsa-with-SHA384`
- **Issuer**: Empty (`O=`). This is unusual since the Issuer is typically the entity that issued the certificate.
- **Validity Period**:
  - **Not Before**: July 18, 2019
  - **Not After**: July 17, 2022
- **Subject**: Empty (`O=`), indicating the certificate's owner is not specified clearly.
- **Public Key**: RSA, 2048-bit
- **Key Usage**: Critical (Digital Signature, Key Encipherment)
- **Extended Key Usage**: TLS Web Server Authentication
- **Subject Alternative Name (SAN)**: No specific domain listed.

### Analysis:
1. **Empty Subject and Issuer**: Both the subject and issuer fields being empty (`O=`) are highly unusual for valid certificates. Legitimate certificates should contain identifying information for both the subject (owner) and the issuer (certificate authority). This could indicate either a misconfigured certificate or something suspicious.

2. **Signature Algorithm**: The use of `ecdsa-with-SHA384` is a strong algorithm, which is commonly seen in modern TLS communications.

3. **Public Key**: The RSA 2048-bit key is a common key length and widely used for secure web communications.

4. **Validity Period**: The certificate was valid between July 18, 2019, and July 17, 2022, which aligns with the timeframe of your captured traffic (October 2019). This suggests that the certificate was valid during the time of communication.

5. **Key Usage**: The certificate is designated for TLS Web Server Authentication, which means it was intended to be used for securing communications between a web server and a client.
