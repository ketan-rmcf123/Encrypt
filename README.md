# 🔐 CryptoKit & Modern Cryptography Suite

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit App](https://img.shields.io/badge/Interface-Streamlit-red.svg)](https://streamlit.io)
[![Tests: Passing](https://img.shields.io/badge/Tests-8%20Passed-brightgreen.svg)]()

> A cryptographic laboratory and security toolkit bridging **historical educational substitution/XOR stream ciphers (2018)** with **industry-standard modern cryptosystems** (RSA-OAEP 4096-bit, AES-256-GCM, PSS Digital Signatures, and PBKDF2).

---

## 🌟 Key Features

- **🏛️ Classical 3-Stage Key-Schedule Cipher**:
  - Exact recreation of the original 2018 MATLAB implementation with byte-level parity.
  - Step-by-step visual cryptographic pipeline showing each stage:
    1. *Stage 1*: ASCII Substitution Involution ($f(f(x)) = x$).
    2. *Stage 2*: Position-dependent bitwise XOR ($128 - \text{index}$).
    3. *Stage 3*: Adjacent-pair transposition XOR.
- **🔑 Production RSA Asymmetric Cryptography**:
  - RSA 2048, 3072, and 4096-bit key pair generation.
  - **OAEP Padding (SHA-256)** encryption and decryption (IND-CCA2 secure).
  - **PSS Digital Signatures** with SHA-256 and salt verification.
- **🛡️ Authenticated AES-256-GCM Symmetric Encryption**:
  - Galois/Counter Mode (GCM) ensuring confidentiality and message authentication.
  - PBKDF2 HMAC-SHA256 key derivation with 200,000 iterations and random salts.
  - Support for encrypting/decrypting both text messages and binary files.
- **🧮 Hashing & HMAC Studio**:
  - SHA-256, SHA-512, SHA-3, and MD5 message digests.
  - HMAC authentication tag generator.
- **💻 Interactive Streamlit Web UI**:
  - Real-time encryption/decryption, visual trace inspection, and file encryption downloads.
- **⚡ Unified CLI**:
  - Full-featured command-line tool `cryptokit` for terminal workflows and scripts.

---

## 📐 Architecture & Mathematical Design

```
+-------------------------------------------------------------+
|                     User Application                        |
|           (Streamlit Web UI / Terminal CLI)                 |
+------------------------------+------------------------------+
                               |
        +----------------------+----------------------+
        |                      |                      |
+-------v-------+      +-------v-------+      +-------v-------+
| Legacy Cipher |      |  RSA-OAEP/PSS |      |  AES-256-GCM  |
| 3-Stage Engine|      |  Asymmetric   |      |  Symmetric    |
| - Sub Key 1   |      | - 2048/4096   |      | - PBKDF2      |
| - XOR Key 2   |      | - OAEP Encr.  |      | - 12B Nonce   |
| - XOR Key 3   |      | - PSS Signing |      | - Auth Tag    |
+---------------+      +---------------+      +---------------+
```

### The Legacy 3-Stage Cipher Explained

The original 2018 algorithm processes ASCII characters through three sequential mathematical operations:

1. **Key 1 (Substitution Involution)**:
   $$\text{Key}_1(i) = \begin{cases} i + 64 & \text{if } i < 64 \\ i - 64 & \text{if } i > 64 \\ 64 & \text{if } i = 64 \end{cases}$$
   Because $\text{Key}_1(\text{Key}_1(x)) = x$, the encryption and decryption transformations are identical.

2. **Key 2 (Positional Keystream XOR)**:
   $$\text{Key}_2(i) = 128 - (i \pmod{127})$$
   $$S_2(i) = S_1(i) \oplus \text{Key}_2(i)$$

3. **Key 3 (Adjacent Transposition XOR)**:
   $$\text{Key}_3(i) = \begin{cases} i + 1 & \text{if } i \text{ is odd} \\ i - 1 & \text{if } i \text{ is even} \end{cases}$$
   $$\text{Final}(i) = S_2(i) \oplus \text{Key}_3(i)$$

---

## 🚀 Quick Start

### 1. Installation

```bash
git clone https://github.com/ketan-rmcf123/Encrypt.git
cd Encrypt
pip install -r requirements.txt
```

### 2. Launch Interactive Web App

```bash
streamlit run app.py
```
Open your browser to `http://localhost:8501`.

### 3. Command Line Interface (CLI)

```bash
# 1. Run Legacy 3-Stage Cipher
python -m cryptokit.cli legacy encrypt "Hello Modern World"
python -m cryptokit.cli legacy decrypt "<ciphertext>"

# 2. Generate RSA 2048-bit Keypair
python -m cryptokit.cli rsa keygen --bits 2048 --priv-out private.pem --pub-out public.pem

# 3. Encrypt and Decrypt with RSA
python -m cryptokit.cli rsa encrypt --pub-key public.pem "Secret message"
python -m cryptokit.cli rsa decrypt --priv-key private.pem "<base64-ciphertext>"

# 4. Symmetric File/Text Encryption with AES-256-GCM
python -m cryptokit.cli aes encrypt --password "MySecretPass!" "Sensitive text"
python -m cryptokit.cli aes decrypt --password "MySecretPass!" "<base64-payload>"

# 5. Checksum / Hash Generation
python -m cryptokit.cli hash "Verify integrity"
```

---

## 🧪 Testing

Run the automated test suite:

```bash
python -m unittest discover -s tests
# or using pytest
pytest tests/
```

All 8 unit tests cover roundtrip encryption, decryption, invalid password detection, signature verification, and mathematical stage tracking.

---

## 📁 Repository Structure

```
Encrypt/
├── app.py                      # Modern Streamlit Web Application
├── pyproject.toml              # Modern package manifest
├── requirements.txt            # Python dependencies
├── .gitignore                  # Git exclusions
├── cryptokit/                  # Core cryptographic engine
│   ├── __init__.py
│   ├── legacy_cipher.py        # 3-Stage educational cipher
│   ├── rsa_cipher.py           # RSA-OAEP & PSS digital signatures
│   ├── aes_cipher.py           # AES-256-GCM & PBKDF2 file/text engine
│   ├── hashing.py              # SHA-256/512 and HMAC digests
│   └── cli.py                  # Unified CLI tool
├── legacy/                     # Archived original 2018 files
│   ├── Encrypt.m               # Original MATLAB encryption script
│   ├── Decrypt.m               # Original MATLAB decryption script
│   └── Message.txt             # Original sample ciphertext
└── tests/
    ├── __init__.py
    └── test_cryptokit.py       # Comprehensive unit tests
```

---

## 📜 License

MIT License. Open for educational, personal, and production usage.
