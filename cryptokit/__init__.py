"""
CryptoKit: Modern Cryptographic Suite & Legacy Cipher Engine.
"""

from .legacy_cipher import LegacyCipher
from .rsa_cipher import RSACipher
from .aes_cipher import AESCipher
from .hashing import hash_data, hmac_digest

__version__ = "2.0.0"
__all__ = ["LegacyCipher", "RSACipher", "AESCipher", "hash_data", "hmac_digest"]
