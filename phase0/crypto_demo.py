#!/usr/bin/env python3
"""
Phase 0 - Ed25519 keygen + XChaCha20-Poly1305 encrypt/decrypt + tamper detection
"""

from nacl.signing import SigningKey
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
from nacl.utils import random
from nacl.exceptions import CryptoError
import nacl.encoding

def main():
    print("=== Phase 0: libsodium demo ===\n")

    # 1. Generate Ed25519 keypair (signing)
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    print("Ed25519 private key (hex):", signing_key.encode(encoder=nacl.encoding.HexEncoder).decode())
    print("Ed25519 public  key (hex):", verify_key.encode(encoder=nacl.encoding.HexEncoder).decode())
    print()

    # 2. Generate a random 32-byte key for XChaCha20-Poly1305 (SecretBox)
    key = random(SecretBox.KEY_SIZE)          # 32 bytes
    box = SecretBox(key)

    message = b"Hello from Nest - Phase 0. This message is authentic."
    print("Original message:", message.decode())

    # 3. Encrypt (XChaCha20-Poly1305)
    encrypted = box.encrypt(message)
    print("Ciphertext (hex):", encrypted.hex())
    print()

    # 4. Decrypt + verify authenticity
    try:
        decrypted = box.decrypt(encrypted)
        print("Decrypted OK:", decrypted.decode())
    except CryptoError:
        print("ERROR: authentication failed (this should never happen with correct key)")
        return

    # 5. Tamper detection demo
    print("\n--- Tampering test ---")
    tampered = bytearray(encrypted)
    tampered[20] ^= 0x01          # flip one bit in the ciphertext
    tampered = bytes(tampered)

    try:
        box.decrypt(tampered)
        print("ERROR: tampered message was accepted!")
    except CryptoError:
        print("Tampering correctly detected - CryptoError raised as expected.")

    print("\nPhase 0 complete.")

if __name__ == "__main__":
    main()
