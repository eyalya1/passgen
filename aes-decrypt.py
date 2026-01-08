from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import sys
password = input("Enter AES Password\n").encode('utf-8')
if len(sys.argv) > 1:
    file = sys.argv[1]
else:
    file = input("Enter file to decrypt\n")

try:
    with open(file, "rb") as f:
        salt = f.read(16) 
        iv = f.read(12)  
        ciphertext = f.read()  
except FileNotFoundError:
    print("File not found!")
    exit(1)

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password)

try:
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(iv, ciphertext, None)
    print("Decrypted Data:", decrypted_data.decode())
except Exception as e:
    print("Decryption failed:", repr(e))  
