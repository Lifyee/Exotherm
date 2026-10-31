import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(content: bytes, key: bytes):
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, content, None)
    return ct, nonce

def decrypt(ct: bytes, key: bytes, nonce: bytes):
    aes = AESGCM(key)
    content = aes.decrypt(nonce, ct, None)
    return content






