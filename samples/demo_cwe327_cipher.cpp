// Intentionally vulnerable sample: CWE-327 weak/broken ciphers.
//
// Uses DES (56-bit key, brute-forced in hours) and RC4 (biased keystream,
// practical plaintext recovery attacks) for encrypting sensitive data.
//
// A correct patch must replace DES with AES-256-GCM and RC4 with
// AES-GCM or ChaCha20-Poly1305.

#include <cstdio>
#include <cstring>

// OpenSSL DES and RC4 function prototypes (for Semgrep pattern matching)
typedef unsigned char DES_cblock[8];
typedef struct { unsigned char ks[16][8]; } DES_key_schedule;

void DES_set_key_checked(DES_cblock* key, DES_key_schedule* schedule);
void DES_ecb_encrypt(DES_cblock* input, DES_cblock* output,
                     DES_key_schedule* schedule, int enc);

typedef struct { int x; int y; unsigned char data[256]; } RC4_KEY;
void RC4_set_key(RC4_KEY* key, int len, const unsigned char* data);
void RC4(RC4_KEY* key, unsigned long len, const unsigned char* in,
         unsigned char* out);

void encrypt_with_des(const char* plaintext) {
    // VULNERABLE: DES is broken — 56-bit key is trivially brute-forced.
    DES_cblock key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    DES_key_schedule schedule;
    DES_set_key_checked(&key, &schedule);

    DES_cblock input, output;
    memcpy(input, plaintext, 8);
    DES_ecb_encrypt(&input, &output, &schedule, 1);
    printf("DES encrypted block: ");
    for (int i = 0; i < 8; i++) printf("%02x", output[i]);
    printf("\n");
}

void encrypt_with_rc4(const unsigned char* data, int len) {
    // VULNERABLE: RC4 has known keystream biases (NOMORE, Bar-Mitzvah).
    RC4_KEY key;
    unsigned char key_material[] = "weak_rc4_key";
    RC4_set_key(&key, strlen((char*)key_material), key_material);

    unsigned char* out = new unsigned char[len];
    RC4(&key, len, data, out);
    printf("RC4 encrypted: ");
    for (int i = 0; i < len; i++) printf("%02x", out[i]);
    printf("\n");
    delete[] out;
}

int main() {
    encrypt_with_des("TestData");
    unsigned char secret[] = "sensitive data here";
    encrypt_with_rc4(secret, strlen((char*)secret));
    return 0;
}
