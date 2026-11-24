"""
CryptoKit Unified Command Line Interface.
"""

import argparse
import sys
from .legacy_cipher import LegacyCipher
from .rsa_cipher import RSACipher
from .aes_cipher import AESCipher
from .hashing import hash_data, hmac_digest


def main():
    parser = argparse.ArgumentParser(
        prog="cryptokit",
        description="CryptoKit: Modern Cryptography Suite & Legacy Cipher CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Legacy command
    legacy_parser = subparsers.add_parser("legacy", help="Run 3-stage legacy cipher")
    legacy_sub = legacy_parser.add_subparsers(dest="action", required=True)

    leg_enc = legacy_sub.add_parser("encrypt", help="Encrypt with legacy cipher")
    leg_enc.add_argument("text", help="Text to encrypt")

    leg_dec = legacy_sub.add_parser("decrypt", help="Decrypt with legacy cipher")
    leg_dec.add_argument("text", help="Ciphertext to decrypt")

    # RSA command
    rsa_parser = subparsers.add_parser("rsa", help="RSA cryptography operations")
    rsa_sub = rsa_parser.add_subparsers(dest="action", required=True)

    rsa_gen = rsa_sub.add_parser("keygen", help="Generate RSA 2048/4096 key pair")
    rsa_gen.add_argument("--bits", type=int, default=2048, choices=[2048, 3072, 4096])
    rsa_gen.add_argument("--priv-out", default="private_key.pem")
    rsa_gen.add_argument("--pub-out", default="public_key.pem")

    rsa_enc = rsa_sub.add_parser("encrypt", help="Encrypt text with public key")
    rsa_enc.add_argument("--pub-key", required=True, help="Path to public key file")
    rsa_enc.add_argument("message", help="Message to encrypt")

    rsa_dec = rsa_sub.add_parser("decrypt", help="Decrypt base64 ciphertext with private key")
    rsa_dec.add_argument("--priv-key", required=True, help="Path to private key file")
    rsa_dec.add_argument("ciphertext", help="Base64 ciphertext to decrypt")

    # AES command
    aes_parser = subparsers.add_parser("aes", help="AES-256-GCM symmetric encryption")
    aes_sub = aes_parser.add_subparsers(dest="action", required=True)

    aes_enc = aes_sub.add_parser("encrypt", help="Encrypt text with passphrase")
    aes_enc.add_argument("--password", required=True)
    aes_enc.add_argument("text", help="Plaintext to encrypt")

    aes_dec = aes_sub.add_parser("decrypt", help="Decrypt base64 payload with passphrase")
    aes_dec.add_argument("--password", required=True)
    aes_dec.add_argument("payload", help="Base64 payload to decrypt")

    # Hash command
    hash_parser = subparsers.add_parser("hash", help="Compute cryptographic hashes")
    hash_parser.add_argument("text", help="Text to hash")

    args = parser.parse_args()

    if args.command == "legacy":
        cipher = LegacyCipher()
        if args.action == "encrypt":
            trace = cipher.encrypt_with_trace(args.text)
            print("\n[+] --- Legacy 3-Stage Encryption Trace ---")
            print(f"Plaintext        : {args.text}")
            print(f"Stage 1 (Sub)    : {trace['stage1_substitution']}")
            print(f"Stage 2 (XOR-K2) : {trace['stage2_xor']}")
            print(f"Ciphertext (Raw) : {trace['ciphertext']}")
            print(f"Ciphertext (Hex) : {trace['ciphertext_hex']}\n")
        elif args.action == "decrypt":
            decrypted = cipher.decrypt(args.text)
            print(f"\n[+] Decrypted text: {decrypted}\n")

    elif args.command == "rsa":
        if args.action == "keygen":
            priv, pub = RSACipher.generate_key_pair(args.bits)
            with open(args.priv_out, "w") as f:
                f.write(priv)
            with open(args.pub_out, "w") as f:
                f.write(pub)
            print(f"\n[+] Generated RSA-{args.bits} keys successfully:")
            print(f"    Private key -> {args.priv_out}")
            print(f"    Public key  -> {args.pub_out}\n")
        elif args.action == "encrypt":
            with open(args.pub_key, "r") as f:
                pub = f.read()
            encrypted = RSACipher.encrypt_message(args.message, pub)
            print(f"\n[+] RSA Encrypted (Base64):\n{encrypted}\n")
        elif args.action == "decrypt":
            with open(args.priv_key, "r") as f:
                priv = f.read()
            decrypted = RSACipher.decrypt_message(args.ciphertext, priv)
            print(f"\n[+] RSA Decrypted text: {decrypted}\n")

    elif args.command == "aes":
        if args.action == "encrypt":
            res = AESCipher.encrypt_text(args.text, args.password)
            print(f"\n[+] AES-256-GCM Encrypted Payload (Base64):\n{res['payload_b64']}\n")
        elif args.action == "decrypt":
            dec = AESCipher.decrypt_text(args.payload, args.password)
            print(f"\n[+] AES-256-GCM Decrypted text: {dec}\n")

    elif args.command == "hash":
        hashes = hash_data(args.text)
        print(f"\n[+] Hashes for input: {args.text}")
        for algo, val in hashes.items():
            print(f"    {algo.upper():10s}: {val}")
        print()


if __name__ == "__main__":
    main()
