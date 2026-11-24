"""
AES-256-GCM Authenticated Symmetric Cipher.

Provides high-performance symmetric encryption with:
- AES in Galois/Counter Mode (GCM) for confidentiality and integrity.
- PBKDF2 HMAC-SHA256 key derivation with 200,000 iterations and random 16-byte salt.
- Encrypted file and text support with automatic tag and IV handling.
"""

import base64
import os
from typing import Dict, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class AESCipher:
    """AES-256-GCM symmetric encryption engine with PBKDF2 key derivation."""

    ITERATIONS = 200_000

    @classmethod
    def derive_key(cls, password: str, salt: bytes) -> bytes:
        """Derive a 256-bit AES key from a passphrase and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=cls.ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    @classmethod
    def encrypt_text(cls, plaintext: str, password: str) -> Dict[str, str]:
        """
        Encrypt a text string using AES-256-GCM.
        Returns a dict containing the payload packed as base64 (salt + nonce + ciphertext).
        """
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = cls.derive_key(password, salt)
        aesgcm = AESGCM(key)

        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        # Combine: salt (16) + nonce (12) + ciphertext+tag
        payload = salt + nonce + ciphertext
        return {
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "salt_hex": salt.hex(),
            "nonce_hex": nonce.hex(),
        }

    @classmethod
    def decrypt_text(cls, payload_b64: str, password: str) -> str:
        """
        Decrypt a base64-encoded AES-256-GCM payload.
        """
        payload = base64.b64decode(payload_b64.encode("ascii"))
        if len(payload) < 28:
            raise ValueError("Invalid payload: data too short for salt + nonce + ciphertext.")

        salt = payload[:16]
        nonce = payload[16:28]
        ciphertext = payload[28:]

        key = cls.derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")

    @classmethod
    def encrypt_file(cls, input_path: str, output_path: str, password: str) -> None:
        """Encrypt an arbitrary file and write to output_path."""
        with open(input_path, "rb") as f:
            data = f.read()

        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = cls.derive_key(password, salt)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        with open(output_path, "wb") as f:
            f.write(salt + nonce + ciphertext)

    @classmethod
    def decrypt_file(cls, input_path: str, output_path: str, password: str) -> None:
        """Decrypt an arbitrary file and write to output_path."""
        with open(input_path, "rb") as f:
            payload = f.read()

        if len(payload) < 28:
            raise ValueError("Corrupt encrypted file: payload too short.")

        salt = payload[:16]
        nonce = payload[16:28]
        ciphertext = payload[28:]

        key = cls.derive_key(password, salt)
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)

        with open(output_path, "wb") as f:
            f.write(decrypted)
