import hashlib
import random
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import rsa

# 1. Hardcoded Secrets
# Vulnerability: Hardcoding cryptographic keys in the source code.
secret_key = "my_super_secret_key"

def encrypt_data(data):
    cipher = AES.new(secret_key.encode(), AES.MODE_CBC, iv=b'1234567890123456')
    return cipher.encrypt(pad_data(data))

def pad_data(data):
    # Simplistic padding (not secure)
    return data + b' ' * (16 - len(data) % 16)

# 2. Use of Weak Cryptographic Algorithms
# Vulnerability: Using MD5, which is considered cryptographically weak.
def hash_password_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

# 3. Missing Salt in Hashing
# Vulnerability: Not using a salt when hashing passwords.
def hash_password_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()

# 4. Use of ECB Mode
# Vulnerability: Using ECB mode for AES encryption.
def encrypt_ecb_mode(data, key):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    return cipher.encrypt(pad_data(data))

# 5. Inadequate Key Size
# Vulnerability: Using RSA keys of insufficient length.
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    return private_key

# 6. Predictable Initialization Vectors (IVs)
# Vulnerability: Using a static IV.
def encrypt_with_static_iv(data, key):
    iv = b'0000000000000000'
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    return cipher.encrypt(pad_data(data))

# 7. Insecure Random Number Generation
# Vulnerability: Using random.random() for cryptographic purposes.
def generate_token():
    return str(random.random())
