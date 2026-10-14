import streamlit as st
import hashlib
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# 1. Page Configuration
st.set_page_config(
    page_title="Secure Document Signing & Integrity Verifier",
    page_icon="🔏",
    layout="wide"
)

st.title("🔏 Secure Document Signing & Integrity Verification System")
st.markdown("""
A cryptographic system adhering to **NIST FIPS 180-4 (SHA-256)** and **FIPS 186-5 (RSA Digital Signatures)** 
to authenticate electronic records and detect unauthorized modifications.
""")

tabs = st.tabs(["🔑 1. Key Pair Generator", "✍️ 2. Sign Document", "🔍 3. Verify Document Integrity"])

# ==========================================
# TAB 1: RSA KEY PAIR GENERATOR
# ==========================================
with tabs[0]:
    st.subheader("Generate Asymmetric Cryptographic Keys (RSA-2048)")
    st.write("Generate a public-private key pair. Keep your **Private Key** secret; distribute your **Public Key** to verifiers.")
    
    if st.button("Generate New RSA-2048 Key Pair", type="primary"):
        with st.spinner("Generating cryptographic key pair..."):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()

            priv_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            pub_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            st.session_state["priv_key"] = priv_pem
            st.session_state["pub_key"] = pub_pem

    if "priv_key" in st.session_state:
        col1, col2 = st.columns(2)
        with col1:
            st.text_area("🔐 Private Key (Used to Sign)", st.session_state["priv_key"], height=220)
            st.download_button("Download Private Key (.pem)", st.session_state["priv_key"], file_name="private_key.pem")
        with col2:
            st.text_area("🔓 Public Key (Used to Verify)", st.session_state["pub_key"], height=220)
            st.download_button("Download Public Key (.pem)", st.session_state["pub_key"], file_name="public_key.pem")

# ==========================================
# TAB 2: SIGN DOCUMENT
# ==========================================
with tabs[1]:
    st.subheader("Cryptographic Hashing & Digital Signature Generation")
    
    doc_file = st.file_uploader("Upload Target Document (PDF, TXT, DOCX, PNG, etc.)", key="sign_doc")
    signer_name = st.text_input("Signer Identity / Organization", value="COER University")
    priv_key_input = st.text_area("Enter Signer's Private Key (PEM format)", value=st.session_state.get("priv_key", ""), height=180)

    if st.button("Generate Digital Signature", type="primary"):
        if doc_file is None or not priv_key_input.strip():
            st.warning("Please upload a file and provide the Private Key.")
        else:
            try:
                # 1. Compute SHA-256 Digest of file bytes
                doc_bytes = doc_file.read()
                sha256_hash = hashlib.sha256(doc_bytes).hexdigest()
                
                # 2. Load private key
                private_key = serialization.load_pem_private_key(
                    priv_key_input.encode('utf-8'),
                    password=None
                )
                
                # 3. Digitally sign the raw bytes using RSA-PSS SHA-256
                signature = private_key.sign(
                    doc_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                signature_b64 = base64.b64encode(signature).decode('utf-8')
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

                st.success("✅ Document Successfully Signed!")
                
                # Metadata Receipt
                manifest = {
                    "document_name": doc_file.name,
                    "signer_identity": signer_name,
                    "timestamp": timestamp,
                    "sha256_hash": sha256_hash,
                    "digital_signature_base64": signature_b64
                }
                
                st.code(f"Document SHA-256 Digest:\n{sha256_hash}", language="text")
                st.download_button(
                    label="Download Digital Signature Certificate (.json)",
                    data=json.dumps(manifest, indent=4),
                    file_name=f"{doc_file.name}_signature_receipt.json",
                    mime="application/json"
                )
            except Exception as e:
                st.error(f"Error during signing: {str(e)}")

# ==========================================
# TAB 3: INTEGRITY VERIFICATION PIPELINE
# ==========================================
with tabs[2]:
    st.subheader("Document Integrity & Authenticity Verification")
    st.write("Upload the document along with its signature certificate and signer's public key to check for unauthorized tampering.")

    colA, colB = st.columns(2)
    with colA:
        verify_doc = st.file_uploader("Upload Document to Verify", key="verify_doc")
    with colB:
        receipt_file = st.file_uploader("Upload Signature Certificate (.json)", type=["json"], key="receipt")

    pub_key_verify = st.text_area("Enter Signer's Public Key (PEM format)", value=st.session_state.get("pub_key", ""), height=150)

    if st.button("Run Integrity & Signature Verification", type="primary"):
        if not verify_doc or not receipt_file or not pub_key_verify.strip():
            st.warning("Please provide the document, the signature receipt JSON, and the public key.")
        else:
            try:
                receipt_data = json.load(receipt_file)
                original_hash = receipt_data.get("sha256_hash")
                sig_b64 = receipt_data.get("digital_signature_base64")
                signer = receipt_data.get("signer_identity", "Unknown")
                signing_time = receipt_data.get("timestamp", "Unknown")

                # Recalculate SHA-256 of candidate file
                candidate_bytes = verify_doc.read()
                current_hash = hashlib.sha256(candidate_bytes).hexdigest()
                signature_bytes = base64.b64decode(sig_b64)

                # Load public key
                public_key = serialization.load_pem_public_key(pub_key_verify.encode('utf-8'))

                # Cryptographic signature validation
                is_signature_valid = False
                try:
                    public_key.verify(
                        signature_bytes,
                        candidate_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    is_signature_valid = True
                except InvalidSignature:
                    is_signature_valid = False

                st.markdown("---")
                st.subheader("Verification Report")

                col_res1, col_res2 = st.columns(2)
                with col_res1:
                    st.write(f"**Signer:** {signer}")
                    st.write(f"**Signed At:** {signing_time}")
                    st.write(f"**Original Registered Hash:** `{original_hash}`")
                    st.write(f"**Computed Current Hash:** `{current_hash}`")

                with col_res2:
                    if is_signature_valid and (current_hash == original_hash):
                        st.success("### ✅ INTEGRITY VERIFIED")
                        st.write("1. **Authenticity:** Signature matches the signer's public key.")
                        st.write("2. **Integrity:** Zero unauthorized modifications detected.")
                    else:
                        st.error("### 🚨 TAMPER ALERT: INTEGRITY COMPROMISED")
                        st.write("The document content does not match the cryptographic signature or hash digest.")
            except Exception as e:
                st.error(f"Verification Failed: {str(e)}")
