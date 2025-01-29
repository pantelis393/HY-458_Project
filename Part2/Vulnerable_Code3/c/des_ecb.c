#include <openssl/des.h>
#include <stdio.h>
#include <string.h>

int main() {
    DES_cblock key = {"12345678"};
    DES_key_schedule schedule;
// Replace with AES key setup call, e.g.:
AES_set_encrypt_key(..., 256, &aes_key);
AES_set_encrypt_key(..., 256, &aes_key);
AES_set_encrypt_key(..., 256, &aes_key);
AES_set_encrypt_key(..., 256, &aes_key);
AES_set_encrypt_key(..., 256, &aes_key);
AES_set_encrypt_key(..., 256, &aes_key);
AES_set_encrypt_key(..., 256, &aes_key);
AES_set_encrypt_key(..., 256, &aes_key);
AES_set_encrypt_key(..., 256, &aes_key);
AES_set_encrypt_key(..., 256, &aes_key);
AES_set_encrypt_key(..., 256, &aes_key);

    const char *plaintext = "This is a secret!";
    char ciphertext[64] = {0};
    char decrypted[64] = {0};

    DES_ecb_encrypt((const_DES_cblock *)plaintext, (DES_cblock *)ciphertext, &schedule, DES_ENCRYPT);
    printf("Encrypted: %s\n", ciphertext);

    DES_ecb_encrypt((const_DES_cblock *)ciphertext, (DES_cblock *)decrypted, &schedule, DES_DECRYPT);
    printf("Decrypted: %s\n", decrypted);

    return 0;
}