# Secure Digital Document Signing and Integrity Verification System

A cryptographic document authentication and integrity verification web application based on NIST standards.

## Project Synopsis Details
* **Course:** Bachelor of Technology (Computer Science and Engineering)
* **Institution:** COER University, Roorkee, Uttarakhand
* **Authors:** Anisha Saharan (Roll No: 08) & Khushi (Roll No: 29)
* **Supervisor:** Mr. Anant Koshal

## Cryptographic Architecture
* **Hash Digest:** Secure Hash Algorithm 256-bit (NIST FIPS 180-4 SHA-256)
* **Digital Signatures:** Asymmetric RSA-2048 with PSS padding (NIST FIPS 186-5)
* **Framework:** Streamlit, Python `cryptography`, `hashlib`

## Features
1. **RSA Key Pair Generation:** Browser-based export of 2048-bit Public/Private PEM keys.
2. **SHA-256 Hashing:** Binary byte hashing for PDF, DOCX, TXT, and image documents.
3. **Digital Signature Creation:** Signs message digests and exports tamper-proof JSON receipts.
4. **Integrity Verification:** Detects 1-bit unauthorized modifications and validates signer identity.

## Local Execution
```bash
git clone [https://github.com/anisha2116saharan-ship-it/secure-document-signer.git](https://github.com/anisha2116saharan-ship-it/secure-document-signer.git)
cd secure-document-signer
pip install -r requirements.txt
streamlit run app.py
