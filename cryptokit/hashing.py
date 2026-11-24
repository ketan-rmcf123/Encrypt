"""
Cryptographic Hashing and Message Authentication Utilities.
"""

import hashlib
import hmac
from typing import Dict


def hash_data(data: str) -> Dict[str, str]:
    """Calculate multiple cryptographic hashes for a given string."""
    encoded = data.encode("utf-8")
    return {
        "md5": hashlib.md5(encoded).hexdigest(),
        "sha1": hashlib.sha1(encoded).hexdigest(),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "sha512": hashlib.sha512(encoded).hexdigest(),
        "sha3_256": hashlib.sha3_256(encoded).hexdigest(),
    }


def hmac_digest(message: str, key: str, algorithm: str = "sha256") -> str:
    """Compute HMAC authentication tag for a message and key."""
    digest_func = getattr(hashlib, algorithm.lower(), hashlib.sha256)
    return hmac.new(
        key.encode("utf-8"),
        message.encode("utf-8"),
        digest_func
    ).hexdigest()
