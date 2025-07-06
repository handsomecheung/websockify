#!/usr/bin/env python3

import os
import hashlib

from websockify.mb64 import MB64


def get_encryption_from_env():
    password = os.environ.get("NOVNC_ENCRYPTION_KEY")
    if password:
        return MB64Encryption(password)
    return None


def get_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class MB64Encryption:
    def __init__(self, password):
        self.mb64 = MB64()
        self.mb64.set_encoding(password)
        self.d = 0

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")

        return self.mb64.encode(data)

    def decrypt(self, data):
        return self.mb64.decode(data)
