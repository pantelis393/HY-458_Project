# test_insecure_ciphers.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_with_rc4(key, data):
    # RC4 is considered insecure and should not be used
    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def encrypt_with_blowfish(key, data):
    # Blowfish is considered insecure and should not be used
    algorithm = algorithms.Blowfish(key)
    cipher = Cipher(algorithm, modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def encrypt_with_idea(key, data):
    # IDEA is considered insecure and should not be used
    algorithm = algorithms.IDEA(key)
    cipher = Cipher(algorithm, modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

if __name__ == "__main__":
    key = b'sixteen byte key'
    data = b'secret data'

    encrypted_rc4 = encrypt_with_rc4(key, data)
    print(f"RC4 Encrypted Data: {encrypted_rc4}")

    encrypted_blowfish = encrypt_with_blowfish(key, data)
    print(f"Blowfish Encrypted Data: {encrypted_blowfish}")

    encrypted_idea = encrypt_with_idea(key, data)
    print(f"IDEA Encrypted Data: {encrypted_idea}")
