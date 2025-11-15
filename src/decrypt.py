# decrypt.py
import os
import sys
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from argon2.low_level import Type, hash_secret_raw

SALT_SIZE = 16
KEY_SIZE = 32

# Version 1: PBKDF2-HMAC-SHA256
PBKDF2_ITERATIONS = 600000  # OWASP 2023 recommendation

# Version 2: Argon2id
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB in KiB
ARGON2_PARALLELISM = 4

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    # Read version header (4 bytes)
    version_num = int.from_bytes(encrypted_data[:4], byteorder="big")
    offset = 4

    salt = encrypted_data[offset:offset+SALT_SIZE]
    nonce = encrypted_data[offset+SALT_SIZE:offset+SALT_SIZE+12]
    ciphertext_with_tag = encrypted_data[offset+SALT_SIZE+12:]

    # Derive key based on version
    if version_num == 1:
        # Legacy PBKDF2 format
        print(f"Decrypting version {version_num} file (PBKDF2-HMAC-SHA256, {PBKDF2_ITERATIONS:,} iterations)", file=sys.stderr)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS
        )
        key = kdf.derive(password.encode("utf-8"))
    elif version_num == 2:
        # Current Argon2id format
        print(f"Decrypting version {version_num} file (Argon2id, {ARGON2_MEMORY_COST // 1024} MB)", file=sys.stderr)
        key = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_SIZE,
            type=Type.ID,
        )
    else:
        raise ValueError(f"Unsupported encryption version: {version_num}")

    # Decrypt using AES-GCM
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <encrypted_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    password = getpass("Enter backup password: ")

    try:
        with open(file_path, "rb") as f:
            encrypted_contents = f.read()
        
        decrypted_json = decrypt_data(encrypted_contents, password)
        print(decrypted_json.decode("utf-8"))
        print("\nDecryption successful.", file=sys.stderr)
    except InvalidTag:
        print("Decryption failed: Invalid password or corrupted file.", file=sys.stderr)
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)