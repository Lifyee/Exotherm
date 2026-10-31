from argon2.low_level import Type, hash_secret_raw
import os

def create_key(password: bytes, salt = None):
    if salt is None:
        salt = os.urandom(16)
    else:
        pass
    key = hash_secret_raw(secret = password,
                          salt = salt,
                          time_cost = 3,
                          memory_cost=65536,
                          parallelism = 4,
                          hash_len = 32,
                          type = Type.ID)

    return key, salt




