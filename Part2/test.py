import hashlib
from Crypto.Cipher import DES, DES3, AES
from Crypto.PublicKey import RSA, DSA
from Crypto.Cipher import PKCS1_v1_5
import random

# One-way hash functions
def hash_example():
    # MD5 (insecure)
    hashed_md5 = hashlib.md5(b"example").hexdigest()

    # SHA-1 (insecure)
    hashed_sha1 = hashlib.sha1(b"example").hexdigest()

    # SHA-256 (informational)
    hashed_sha256 = hashlib.sha256(b"example").hexdigest()

# Symmetric key cryptography
def symmetric_encryption():
    # DES (insecure)
    des_cipher = DES.new(b"12345678", DES.MODE_ECB)

    # 3DES (deprecated)
    triple_des_cipher = DES3.new(b"1234567812345678", DES3.MODE_ECB)

    # AES in ECB mode (insecure)
    aes_ecb_cipher = AES.new(b"16bytekey16bytekey", AES.MODE_ECB)

    # AES in CBC mode without integrity check (vulnerable)
    aes_cbc_cipher = AES.new(b"16bytekey16bytekey", AES.MODE_CBC)

    # AES with short key (128-bit)
    aes_short_key = AES.new(b"16bytekey16bytekey", key_size=128)

# Asymmetric key cryptography
def asymmetric_key_example():
    # Small RSA key (insecure)
    rsa_key = RSA.generate(1024)

    # DSA (vulnerable)
    dsa_key = DSA.generate(2048)

    # Static Diffie-Hellman (no forward secrecy)
    dh_key = "Static DH Example"

# Digital signatures
def digital_signature_example():
    # MD5-based signature (insecure)
    signature_md5 = PKCS1_v1_5.new(..., hashAlgo=hashlib.md5)

    # SHA-1-based signature (deprecated)
    signature_sha1 = PKCS1_v1_5.new(..., hashAlgo=hashlib.sha1)

# Cryptographically insecure RNG
def insecure_rng_example():
    # Non-cryptographic RNG (insecure)
    rng_value = random.random()

# Deprecated or weak algorithms
def deprecated_algorithms():
    # RC4 (insecure)
    rc4_cipher = RC4.new(b"key")

    # Blowfish (deprecated)
    blowfish_cipher = Blowfish.new(b"key")

    # IDEA (outdated)
    idea_cipher = IDEA.new(b"key")

# Hardcoded cryptographic keys
def hardcoded_keys():
    key = "hardcoded-key"  # Hardcoded cryptographic key (insecure)

# Avoid weak elliptic curves
def weak_ecc_example():
    # ECC with weak curve (secp192r1)
    weak_ecc = ECC.generate(curve='secp192r1')

# Improper padding in RSA
def rsa_padding_example():
    # RSA without OAEP padding (vulnerable)
    rsa_no_oaep = PKCS1_v1_5.new(...)
