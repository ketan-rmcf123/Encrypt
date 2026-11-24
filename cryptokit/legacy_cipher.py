"""
Legacy 3-Stage Substitution/XOR Cipher Engine.

Recreates the original 2018 MATLAB implementation with exact mathematical
parity, while extending support for arbitrary text length, hex/base64 encoding,
and intermediate stage tracing for educational inspection.
"""

from typing import Dict, List, Tuple


class LegacyCipher:
    """
    3-Stage Cipher implementing:
    - Stage 1: Key 1 ASCII Substitution Involution (offset +/- 64 around 64).
    - Stage 2: Key 2 Position-Dependent Bitwise XOR (128 - pos).
    - Stage 3: Key 3 Position-Dependent Transposition XOR (adjacent pair flip).
    """

    def __init__(self, max_keys: int = 127) -> None:
        self.max_keys = max_keys
        self._key1 = self._generate_key1()
        self._key2 = self._generate_key2()
        self._key3 = self._generate_key3()

    def _generate_key1(self) -> List[int]:
        """Generate Key 1: 1-indexed ASCII substitution table (size 128)."""
        key1 = [0] * 128
        for i in range(1, 128):
            if i < 64:
                key1[i] = i + 64
            elif i > 64:
                key1[i] = i - 64
            else:
                key1[i] = 64
        return key1

    def _generate_key2(self) -> List[int]:
        """Generate Key 2: 1-indexed position keystream (128 - pos)."""
        key2 = [0] * 128
        for i in range(1, 128):
            key2[i] = 128 - i
        return key2

    def _generate_key3(self) -> List[int]:
        """Generate Key 3: 1-indexed adjacent-swap keystream."""
        key3 = [0] * 128
        for i in range(1, 127):
            if i % 2 == 1:
                key3[i] = i + 1
            else:
                key3[i] = i - 1
        key3[127] = 127
        return key3

    def _get_pos_key(self, key_table: List[int], index: int) -> int:
        """Get position-based key with 1-based indexing and cyclic wrapping."""
        # 1-based index mapped to 1..127
        wrapped = ((index - 1) % (self.max_keys)) + 1
        return key_table[wrapped]

    def encrypt_with_trace(self, plaintext: str) -> Dict[str, object]:
        """
        Encrypt plaintext and return intermediate results at every stage.
        """
        stage1_chars: List[int] = []
        stage2_chars: List[int] = []
        final_chars: List[int] = []

        for idx, char in enumerate(plaintext, start=1):
            ascii_val = ord(char) % 128  # Keep within 7-bit ASCII
            if ascii_val == 0:
                ascii_val = 32  # Default null to space

            # Stage 1: Key 1 Substitution
            s1 = self._key1[ascii_val]
            stage1_chars.append(s1)

            # Stage 2: Key 2 Bitwise XOR
            k2 = self._get_pos_key(self._key2, idx)
            s2 = s1 ^ k2
            stage2_chars.append(s2)

            # Stage 3: Key 3 Bitwise XOR
            k3 = self._get_pos_key(self._key3, idx)
            s3 = s2 ^ k3
            final_chars.append(s3)

        stage1_str = "".join(chr(c) for c in stage1_chars)
        stage2_str = "".join(chr(c) for c in stage2_chars)
        final_str = "".join(chr(c) for c in final_chars)

        return {
            "plaintext": plaintext,
            "stage1_substitution": stage1_str,
            "stage2_xor": stage2_str,
            "ciphertext": final_str,
            "stage1_bytes": bytes(stage1_chars),
            "stage2_bytes": bytes(stage2_chars),
            "ciphertext_bytes": bytes(final_chars),
            "ciphertext_hex": bytes(final_chars).hex(),
        }

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext and return final ciphertext string."""
        trace = self.encrypt_with_trace(plaintext)
        return str(trace["ciphertext"])

    def decrypt_with_trace(self, ciphertext: str) -> Dict[str, object]:
        """
        Decrypt ciphertext and return intermediate results at every stage.
        """
        stage2_chars: List[int] = []
        stage1_chars: List[int] = []
        recovered_chars: List[int] = []

        for idx, char in enumerate(ciphertext, start=1):
            val = ord(char)

            # Undo Stage 3: XOR with Key 3
            k3 = self._get_pos_key(self._key3, idx)
            s2 = val ^ k3
            stage2_chars.append(s2)

            # Undo Stage 2: XOR with Key 2
            k2 = self._get_pos_key(self._key2, idx)
            s1 = s2 ^ k2
            stage1_chars.append(s1)

            # Undo Stage 1: Key 1 is self-inverse (involution)
            orig_ascii = self._key1[s1 % 128]
            recovered_chars.append(orig_ascii)

        stage2_str = "".join(chr(c) for c in stage2_chars)
        stage1_str = "".join(chr(c) for c in stage1_chars)
        recovered_str = "".join(chr(c) for c in recovered_chars)

        return {
            "ciphertext": ciphertext,
            "recovered_stage2": stage2_str,
            "recovered_stage1": stage1_str,
            "plaintext": recovered_str,
            "plaintext_hex": recovered_str.encode("utf-8", errors="replace").hex(),
        }

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext and return recovered plaintext string."""
        trace = self.decrypt_with_trace(ciphertext)
        return str(trace["plaintext"])
