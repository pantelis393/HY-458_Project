import hashlib

data = b"example data"
# Vulnerable MD5 usage
import hashlib
# Replace MD5 with SHA-256
sha256_hash = hashlib.sha256(data).hexdigest()


# Static IV example
from Crypto.Random import get_random_bytes
iv = get_random_bytes(16)  # Generate a new IV for each encryption


# Vulnerable DES encryption
from Crypto.Cipher import DES
key = b"12345678"
from Crypto.Cipher import AES
# Replace DES with AES-256
cipher = AES.new(key, AES.MODE_CBC)

ciphertext = cipher.encrypt(b"plaintext")