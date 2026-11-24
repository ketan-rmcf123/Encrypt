"""
CryptoKit Interactive Web Application.
Built with Streamlit for intuitive exploration of classical and modern cryptography.
"""

import os
import sys
import streamlit as st

sys.path.insert(0, os.path.dirname(__file__))

from cryptokit.legacy_cipher import LegacyCipher
from cryptokit.rsa_cipher import RSACipher
from cryptokit.aes_cipher import AESCipher
from cryptokit.hashing import hash_data, hmac_digest

st.set_page_config(
    page_title="CryptoKit Studio",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom header
st.title("🔐 CryptoKit: Cryptography & Security Suite")
st.caption("Comprehensive cryptographic laboratory featuring the 2018 3-Stage Educational Cipher, Modern RSA-OAEP, AES-256-GCM, and Digital Signatures.")

tabs = st.tabs([
    "🏛️ Legacy 3-Stage Cipher",
    "🔑 RSA Cryptosystem",
    "🛡️ AES-256-GCM Vault",
    "🧮 Hashing & HMAC",
    "📖 Algorithm Guide"
])

# ----------------- TAB 1: LEGACY CIPHER -----------------
with tabs[0]:
    st.header("Classical 3-Stage Key-Schedule Cipher")
    st.info("Direct modern recreation of the original 2018 MATLAB substitution & XOR stream cipher.")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Encrypt Message")
        legacy_input = st.text_area("Plaintext Input", value="Ketan's Cryptography Suite 2026", height=100)
        if st.button("Encrypt (3 Stages)", key="leg_enc_btn", type="primary"):
            cipher = LegacyCipher()
            trace = cipher.encrypt_with_trace(legacy_input)
            st.success("Message Encrypted Successfully!")
            st.markdown("#### Execution Trace:")
            st.code(f"1. Key 1 Substitution: {trace['stage1_substitution']}", language="text")
            st.code(f"2. Key 2 Positional XOR: {trace['stage2_xor']}", language="text")
            st.code(f"3. Final Ciphertext (Raw): {trace['ciphertext']}", language="text")
            st.code(f"Hex Representation: {trace['ciphertext_hex']}", language="text")
            st.session_state["last_legacy_cipher"] = trace["ciphertext"]

    with col2:
        st.subheader("Decrypt Message")
        cipher_input = st.text_area(
            "Ciphertext Input",
            value=st.session_state.get("last_legacy_cipher", ""),
            height=100
        )
        if st.button("Decrypt Message", key="leg_dec_btn"):
            if cipher_input:
                cipher = LegacyCipher()
                trace = cipher.decrypt_with_trace(cipher_input)
                st.success("Message Decrypted!")
                st.markdown("#### Reverse Execution Trace:")
                st.code(f"1. Reverse Stage 3 (Key 3 XOR): {trace['recovered_stage2']}", language="text")
                st.code(f"2. Reverse Stage 2 (Key 2 XOR): {trace['recovered_stage1']}", language="text")
                st.code(f"3. Recovered Plaintext: {trace['plaintext']}", language="text")
            else:
                st.warning("Please provide ciphertext to decrypt.")

# ----------------- TAB 2: RSA -----------------
with tabs[1]:
    st.header("Modern RSA Asymmetric Cryptosystem (OAEP & PSS)")
    
    with st.expander("🔑 Generate RSA Keypair", expanded=True):
        col_k1, col_k2 = st.columns([1, 3])
        with col_k1:
            key_size = st.selectbox("Key Size (bits)", [2048, 3072, 4096], index=0)
            if st.button("Generate New Keypair", type="primary"):
                priv, pub = RSACipher.generate_key_pair(key_size)
                st.session_state["rsa_priv"] = priv
                st.session_state["rsa_pub"] = pub
                st.success(f"Generated RSA-{key_size} Key Pair!")
        with col_k2:
            st.text_area("Public Key (PEM)", value=st.session_state.get("rsa_pub", ""), height=120)
            st.text_area("Private Key (PEM)", value=st.session_state.get("rsa_priv", ""), height=120)

    col_r1, col_r2 = st.columns(2)
    with col_r1:
        st.subheader("RSA Encryption (OAEP + SHA-256)")
        rsa_msg = st.text_area("Secret Message to Encrypt", "Sensitive payload for RSA encryption.")
        pub_for_enc = st.text_area("Recipient Public Key", value=st.session_state.get("rsa_pub", ""), height=100)
        if st.button("Encrypt with Public Key"):
            if pub_for_enc and rsa_msg:
                try:
                    enc_res = RSACipher.encrypt_message(rsa_msg, pub_for_enc)
                    st.success("Encrypted with RSA-OAEP!")
                    st.code(enc_res, language="text")
                    st.session_state["last_rsa_cipher"] = enc_res
                except Exception as e:
                    st.error(f"Encryption failed: {e}")
            else:
                st.warning("Please provide a message and public key.")

    with col_r2:
        st.subheader("RSA Decryption (Private Key)")
        cipher_for_dec = st.text_area("Base64 Ciphertext", value=st.session_state.get("last_rsa_cipher", ""), height=100)
        priv_for_dec = st.text_area("Recipient Private Key", value=st.session_state.get("rsa_priv", ""), height=100)
        if st.button("Decrypt with Private Key"):
            if cipher_for_dec and priv_for_dec:
                try:
                    dec_res = RSACipher.decrypt_message(cipher_for_dec, priv_for_dec)
                    st.success("Decryption Successful!")
                    st.write("**Recovered Plaintext:**")
                    st.code(dec_res, language="text")
                except Exception as e:
                    st.error(f"Decryption failed: {e}")
            else:
                st.warning("Please provide ciphertext and private key.")

# ----------------- TAB 3: AES-256-GCM -----------------
with tabs[2]:
    st.header("AES-256-GCM Authenticated Encryption")
    st.info("Military-grade symmetric encryption featuring Galois/Counter Mode (GCM) and PBKDF2 HMAC-SHA256 key derivation.")

    mode = st.radio("Encryption Mode", ["Text Message", "File Encryption"], horizontal=True)

    if mode == "Text Message":
        col_a1, col_a2 = st.columns(2)
        with col_a1:
            st.subheader("Encrypt Text")
            aes_plaintext = st.text_area("Message to Protect", "Banking credentials & private notes.")
            aes_pass = st.text_input("Passphrase / Password", type="password", key="aes_enc_pass")
            if st.button("Encrypt Text", type="primary"):
                if aes_plaintext and aes_pass:
                    res = AESCipher.encrypt_text(aes_plaintext, aes_pass)
                    st.success("Authenticated Ciphertext Generated!")
                    st.code(res["payload_b64"], language="text")
                    st.session_state["last_aes_payload"] = res["payload_b64"]
                else:
                    st.warning("Please supply both message and passphrase.")

        with col_a2:
            st.subheader("Decrypt Text")
            aes_payload = st.text_area("Encrypted Base64 Payload", value=st.session_state.get("last_aes_payload", ""))
            aes_dec_pass = st.text_input("Decryption Passphrase", type="password", key="aes_dec_pass")
            if st.button("Decrypt Text"):
                if aes_payload and aes_dec_pass:
                    try:
                        recovered = AESCipher.decrypt_text(aes_payload, aes_dec_pass)
                        st.success("Authentication & Decryption Passed!")
                        st.code(recovered, language="text")
                    except Exception as e:
                        st.error(f"Authentication / Decryption failed: {e}")
                else:
                    st.warning("Please provide payload and passphrase.")

    else:
        st.subheader("Encrypted File Vault")
        uploaded_file = st.file_uploader("Upload File to Encrypt or Decrypt")
        action = st.radio("Action", ["Encrypt File", "Decrypt File"], horizontal=True)
        file_pass = st.text_input("File Passphrase", type="password")

        if uploaded_file and file_pass:
            if st.button("Process File"):
                temp_in = os.path.join(".", f"temp_{uploaded_file.name}")
                temp_out = os.path.join(".", f"processed_{uploaded_file.name}")
                with open(temp_in, "wb") as f:
                    f.write(uploaded_file.read())

                try:
                    if action == "Encrypt File":
                        AESCipher.encrypt_file(temp_in, temp_out, file_pass)
                        with open(temp_out, "rb") as f:
                            st.download_button(
                                "Download Encrypted File",
                                data=f.read(),
                                file_name=f"{uploaded_file.name}.enc"
                            )
                        st.success("File Encrypted with AES-256-GCM!")
                    else:
                        AESCipher.decrypt_file(temp_in, temp_out, file_pass)
                        clean_name = uploaded_file.name.replace(".enc", "")
                        with open(temp_out, "rb") as f:
                            st.download_button(
                                "Download Decrypted File",
                                data=f.read(),
                                file_name=f"decrypted_{clean_name}"
                            )
                        st.success("File Authenticated and Decrypted!")
                except Exception as e:
                    st.error(f"Processing failed: {e}")
                finally:
                    if os.path.exists(temp_in):
                        os.remove(temp_in)
                    if os.path.exists(temp_out):
                        os.remove(temp_out)

# ----------------- TAB 4: HASHING & HMAC -----------------
with tabs[3]:
    st.header("Cryptographic Hashes & HMAC Signatures")
    hash_input = st.text_area("Input Message", value="Integrity verification message 2026", height=80)
    if hash_input:
        hashes = hash_data(hash_input)
        cols = st.columns(2)
        with cols[0]:
            st.markdown("#### Message Digests")
            for algo, val in hashes.items():
                st.text_input(f"{algo.upper()}", value=val, key=f"digest_{algo}")
        with cols[1]:
            st.markdown("#### HMAC Generation")
            hmac_key = st.text_input("HMAC Secret Key", value="my-auth-secret")
            if hmac_key:
                mac = hmac_digest(hash_input, hmac_key, "sha256")
                st.text_input("HMAC-SHA256 Signature", value=mac)

# ----------------- TAB 5: GUIDE -----------------
with tabs[4]:
    st.header("Cryptographic Architecture & Theory")
    st.markdown("""
    ### 1. Legacy 3-Stage Key-Schedule Cipher
    This educational cipher was developed in 2018 in MATLAB. It illustrates how symmetric transformations cascade:
    1. **Key 1 (Substitution Involution)**: Maps characters across a central pivot (64). Because $f(f(x)) = x$, applying Key 1 twice cancels itself out.
    2. **Key 2 (Position-Dependent Keystream)**: Generates a keystream where byte $i$ is XORed with $128 - i$.
    3. **Key 3 (Adjacent-Pair Transposition Keystream)**: Swaps odd and even indices via bitwise XOR.

    ### 2. Modern RSA-OAEP
    RSA uses the mathematical difficulty of prime factorization.
    - **OAEP (Optimal Asymmetric Encryption Padding)** provides provable IND-CCA2 security against chosen-ciphertext attacks.
    - **PSS (Probabilistic Signature Scheme)** prevents signature forgery by randomizing the salt.

    ### 3. AES-256-GCM
    The global standard for authenticated symmetric encryption:
    - Provides confidentiality (CTR mode) and integrity/authenticity (Galois MAC).
    - Keys are derived via **PBKDF2 HMAC-SHA256** with 200,000 iterations to resist brute-force dictionary attacks.
    """)
