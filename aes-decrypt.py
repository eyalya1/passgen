from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import sys
# Derive a key from the password
password = input("Enter AES Password\n").encode('utf-8')
if len(sys.argv) > 1:
    file = sys.argv[1]
else:
    file = input("Enter file to decrypt\n")

try:
    with open(file, "rb") as f:
        salt = f.read(16)  # First 16 bytes are the salt
        iv = f.read(12)  # Next 12 bytes are the IV (for AES-GCM)
        ciphertext = f.read()  # Remaining bytes are the ciphertext
except FileNotFoundError:
    print("File not found!")
    exit(1)

# Recreate the KDF with the same salt
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password)

# Decrypting with AES-GCM
try:
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(iv, ciphertext, None)  # `None` for additional authenticated data (AAD)
    print("Decrypted Data:", decrypted_data.decode())
except Exception as e:
    print("Decryption failed:", repr(e))  # Print detailed exception
