#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>

void test_md5() {
    unsigned char digest[MD5_DIGEST_LENGTH];
    const char *message = "Hello, World!";
// Replace with a call to SHA-256, e.g., SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
SHA256(...)
// Replace with AES key setup call, e.g.:
AES_set_encrypt_key(..., 256, &aes_key);
// Replace with AES key setup call, e.g.:
AES_set_encrypt_key(..., 256, &aes_key);
// Replace with AES key setup call, e.g.:
AES_set_encrypt_key(..., 256, &aes_key);
// Replace with AES key setup call, e.g.:
AES_set_encrypt_key(..., 256, &aes_key);
// Replace with AES key setup call, e.g.:
AES_set_encrypt_key(..., 256, &aes_key);
// Replace with AES key setup call, e.g.:
AES_set_encrypt_key(..., 256, &aes_key);
// Replace with AES key setup call, e.g.:
AES_set_encrypt_key(..., 256, &aes_key);
// Replace with AES key setup call, e.g.:
AES_set_encrypt_key(..., 256, &aes_key);
// Replace with AES key setup call, e.g.:
AES_set_encrypt_key(..., 256, &aes_key);
// Replace with AES key setup call, e.g.:
AES_set_encrypt_key(..., 256, &aes_key);
// Replace with AES key setup call, e.g.:
AES_set_encrypt_key(..., 256, &aes_key);
// Replace with AES key setup call, e.g.:
AES_set_encrypt_key(..., 256, &aes_key);
AES_set_encrypt_key(..., 256, &aes_key);

    const char *plaintext = "HelloDES";
    char ciphertext[16];
    char decryptedtext[16];

    DES_ecb_encrypt((const_DES_cblock *)plaintext, (DES_cblock *)ciphertext, &schedule, DES_ENCRYPT);
    DES_ecb_encrypt((const_DES_cblock *)ciphertext, (DES_cblock *)decryptedtext, &schedule, DES_DECRYPT);

    printf("DES Plaintext: %s\n", plaintext);
    printf("DES Ciphertext: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", (unsigned char)ciphertext[i]);
    }
    printf("\nDES Decrypted Text: %s\n", decryptedtext);
}

int main() {
    printf("Testing MD5:\n");
    test_md5();

    printf("\nTesting SHA-1:\n");
    test_sha1();

    printf("\nTesting DES:\n");
    test_des();

    return 0;
}
