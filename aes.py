from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import string
import random

# Function to generate a strong random password
def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# Step 1: Generate a random password
generated_password = generate_password(16)  # 16-character password
print("Generated Password:", generated_password)

# Step 2: Ask the user for an AES password
aes_password = input("Enter AES Password to encrypt the generated password\n").encode('utf-8')

# Step 3: Derive a key from the AES password
salt = os.urandom(16)  # Generate a random salt
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # AES-256 requires a 32-byte key
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(aes_password)
# Step 4: Generate a random IV (Initialization Vector)
iv = os.urandom(12)  # 12 bytes for AES-GCM

# Step 5: Encrypt the generated password using AES-GCM
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(iv, generated_password.encode('utf-8'), None)  # `None` for additional authenticated data (AAD)

# Step 6: Save the salt, IV, and ciphertext to a file
filename = input("Enter file name to save the encrypted password\n")
if not filename.endswith(".txt"):
    filename += ".txt"

with open(filename, "wb") as file:
    file.write(salt)       # Write the salt (16 bytes)
    file.write(iv)         # Write the IV (12 bytes)
    file.write(ciphertext) # Write the ciphertext

print("Encryption complete. Encrypted password saved to", filename)

