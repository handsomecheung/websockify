#!/usr/bin/env python3
"""
Simple Encryption Layer for websockify

This module provides AES-GCM encryption/decryption for websockify proxy.
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def get_encryption_from_env():
    """Get encryption instance from environment variable."""
    password = os.environ.get("NOVNC_ENCRYPTION_KEY")
    if password:
        return SimpleEncryption(password)
    return None


class SimpleEncryption:
    """Simple AES-GCM encryption compatible with noVNC client-side encryption."""

    def __init__(self, password):
        """Initialize with password (same as used in JavaScript)."""
        self.backend = default_backend()

        # Use same salt and iterations as JavaScript implementation
        salt = b"novnc-encryption-salt"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=self.backend  # 256-bit key
        )
        self.key = kdf.derive(password.encode("utf-8"))

    def encrypt(self, data):
        """Encrypt data using AES-GCM, returns IV(12) + ciphertext + tag(16)."""
        if isinstance(data, str):
            data = data.encode("utf-8")

        # Generate random 12-byte IV
        iv = os.urandom(12)

        # Create cipher
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        # Encrypt
        ciphertext = encryptor.update(data) + encryptor.finalize()

        # Return IV + ciphertext + tag (same format as JavaScript)
        return iv + ciphertext + encryptor.tag

    def decrypt(self, encrypted_data):
        """Decrypt data, expects IV(12) + ciphertext + tag(16)."""
        if len(encrypted_data) < 28:  # 12 (IV) + 16 (tag) minimum
            raise ValueError("Invalid encrypted data length")

        # Extract components
        iv = encrypted_data[:12]
        ciphertext_and_tag = encrypted_data[12:]
        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]

        # Create cipher
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()

        # Decrypt
        return decryptor.update(ciphertext) + decryptor.finalize()
