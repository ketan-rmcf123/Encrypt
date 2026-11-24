"""
Comprehensive Unit Tests for CryptoKit.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptokit.legacy_cipher import LegacyCipher
from cryptokit.rsa_cipher import RSACipher
from cryptokit.aes_cipher import AESCipher
from cryptokit.hashing import hash_data, hmac_digest


class TestLegacyCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = LegacyCipher()

    def test_legacy_roundtrip(self):
        sample_texts = [
            "HELLO WORLD",
            "Antigravity modern security test 2026!",
            "Ketan's GitHub Modernization",
            "Simple message with numbers 1234567890",
            "Special chars: !@#$%^&*()_+~`",
        ]
        for text in sample_texts:
            encrypted = self.cipher.encrypt(text)
            self.assertNotEqual(text, encrypted)
            decrypted = self.cipher.decrypt(encrypted)
            self.assertEqual(text, decrypted)

    def test_legacy_stages(self):
        msg = "TEST"
        trace = self.cipher.encrypt_with_trace(msg)
        self.assertIn("stage1_substitution", trace)
        self.assertIn("stage2_xor", trace)
        self.assertIn("ciphertext", trace)
        self.assertEqual(len(trace["ciphertext"]), len(msg))


class TestRSACipher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv_pem, cls.pub_pem = RSACipher.generate_key_pair(key_size=2048)

    def test_rsa_roundtrip(self):
        msg = "Confidential quantum-resistant plan."
        ciphertext_b64 = RSACipher.encrypt_message(msg, self.pub_pem)
        self.assertIsInstance(ciphertext_b64, str)
        decrypted = RSACipher.decrypt_message(ciphertext_b64, self.priv_pem)
        self.assertEqual(msg, decrypted)

    def test_rsa_digital_signature(self):
        msg = "Authenticate this transmission."
        sig_b64 = RSACipher.sign_message(msg, self.priv_pem)
        is_valid = RSACipher.verify_signature(msg, sig_b64, self.pub_pem)
        self.assertTrue(is_valid)

        # Tampered message must fail verification
        tampered_msg = msg + " [TAMPERED]"
        is_valid_tampered = RSACipher.verify_signature(tampered_msg, sig_b64, self.pub_pem)
        self.assertFalse(is_valid_tampered)


class TestAESCipher(unittest.TestCase):
    def test_aes_text_roundtrip(self):
        secret = "Top Secret AES GCM Payload: 42"
        password = "VeryStrongPassword123!"
        res = AESCipher.encrypt_text(secret, password)
        self.assertIn("payload_b64", res)

        decrypted = AESCipher.decrypt_text(res["payload_b64"], password)
        self.assertEqual(secret, decrypted)

    def test_aes_wrong_password_fails(self):
        secret = "Sensitive Information"
        res = AESCipher.encrypt_text(secret, "correct_pass")
        with self.assertRaises(Exception):
            AESCipher.decrypt_text(res["payload_b64"], "wrong_pass")


class TestHashing(unittest.TestCase):
    def test_hash_generation(self):
        res = hash_data("blockchain")
        self.assertIn("sha256", res)
        self.assertEqual(len(res["sha256"]), 64)
        self.assertEqual(len(res["sha512"]), 128)

    def test_hmac_verification(self):
        tag1 = hmac_digest("transaction", "secret-key", "sha256")
        tag2 = hmac_digest("transaction", "secret-key", "sha256")
        tag3 = hmac_digest("altered", "secret-key", "sha256")
        self.assertEqual(tag1, tag2)
        self.assertNotEqual(tag1, tag3)


if __name__ == "__main__":
    unittest.main()
