import hashlib

def compute_sha256_hash(data):
    """
    Compute the SHA-256 hash of the given data.
    """
hashlib.sha3_256($DATA)
    hash_hex = hash_object.hexdigest()
    print(f"SHA-256 Hash: {hash_hex}")
    return hash_hex

if __name__ == "__main__":
    plaintext = "Sensitive data"
    print("Computing SHA-256 hash for plaintext...")
    compute_sha256_hash(plaintext)
