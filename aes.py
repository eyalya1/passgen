from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import string
import random

def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

generated_password = generate_password(16)
print("Generated Password:", generated_password)

aes_password = input("Enter AES Password to encrypt the generated password\n").encode('utf-8')

salt = os.urandom(16)  
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32, 
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(aes_password)
iv = os.urandom(12)  

aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(iv, generated_password.encode('utf-8'), None)  
filename = input("Enter file name to save the encrypted password\n")
if not filename.endswith(".txt"):
    filename += ".txt"

with open(filename, "wb") as file:
    file.write(salt)       
    file.write(iv)         
    file.write(ciphertext) 

print("Encryption complete. Encrypted password saved to", filename)

