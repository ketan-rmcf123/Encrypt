"""
Modern RSA Cryptographic Engine.

Provides industry-standard RSA capabilities:
- RSA 2048 / 4096 Key Pair Generation
- PKCS#1 v2.2 OAEP Encryption & Decryption (with SHA-256)
- PSS Digital Signing & Verification (with SHA-256)
- PEM Key serialization (PKCS#8 and SubjectPublicKeyInfo)
"""

import base64
from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class RSACipher:
    """Production-grade RSA Encryption & Digital Signature Manager."""

    @staticmethod
    def generate_key_pair(
        key_size: int = 2048,
        password: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Generate an RSA private and public key pair in PEM format.
        """
        if key_size not in (2048, 3072, 4096):
            key_size = 2048

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )

        encryption_algo = (
            serialization.BestAvailableEncryption(password.encode())
            if password
            else serialization.NoEncryption()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
        ).decode("utf-8")

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        return private_pem, public_pem

    @staticmethod
    def encrypt_message(message: str, public_key_pem: str) -> str:
        """
        Encrypt a UTF-8 string message using RSA-OAEP with SHA-256.
        Returns a Base64-encoded ciphertext string.
        """
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Provided key is not an RSA public key.")

        ciphertext = public_key.encrypt(
            message.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode("ascii")

    @staticmethod
    def decrypt_message(
        ciphertext_b64: str,
        private_key_pem: str,
        password: Optional[str] = None
    ) -> str:
        """
        Decrypt a Base64-encoded ciphertext string using RSA-OAEP with SHA-256.
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=password.encode() if password else None
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Provided key is not an RSA private key.")

        raw_ciphertext = base64.b64decode(ciphertext_b64.encode("ascii"))
        plaintext_bytes = private_key.decrypt(
            raw_ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext_bytes.decode("utf-8")

    @staticmethod
    def sign_message(
        message: str,
        private_key_pem: str,
        password: Optional[str] = None
    ) -> str:
        """
        Digitally sign a message using RSA-PSS with SHA-256.
        Returns Base64-encoded signature.
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=password.encode() if password else None
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Provided key is not an RSA private key.")

        signature = private_key.sign(
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode("ascii")

    @staticmethod
    def verify_signature(
        message: str,
        signature_b64: str,
        public_key_pem: str
    ) -> bool:
        """
        Verify an RSA-PSS digital signature.
        Returns True if valid, False otherwise.
        """
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Provided key is not an RSA public key.")

        signature = base64.b64decode(signature_b64.encode("ascii"))
        try:
            public_key.verify(
                signature,
                message.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
