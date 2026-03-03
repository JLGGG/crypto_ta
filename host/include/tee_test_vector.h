#ifndef TEE_TEST_VECTOR_H
#define TEE_TEST_VECTOR_H

#include "crypto_ta.h"

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t ikm[HKDF_IKM_MAX_SIZE];
    uint32_t ikm_len;
    uint8_t salt[HKDF_SALT_MAX_SIZE];
    uint32_t salt_len;
    uint8_t info[HKDF_INFO_MAX_SIZE];
    uint32_t info_len;
    uint8_t expected_okm[HKDF_OKM_MAX_SIZE];
    uint32_t expected_okm_len;
} HkdfTestVector_t;

typedef struct {
    uint8_t aes_128_key[AES_128_KEY_SIZE];
    uint32_t key_len;
    char *message;
    uint8_t expected_cmac[AES_128_KEY_SIZE];
} AesCmacTestVector_t;

typedef struct {
    uint8_t sha_type;
    char *message;
    uint8_t expected_digest[SHA_MAX_SIZE];
} ShaTestVector_t;

typedef struct {
    // uint32_t keyIdx;
    uint8_t key[AES_128_KEY_SIZE];
    uint8_t plain[PLAIN_MAX_SIZE];
    uint32_t plain_len;
    uint8_t cipher[CIPHER_MAX_SIZE];
    uint32_t cipher_len;
    uint8_t iv[GCM_IV_MAX_SIZE];
    uint32_t iv_len;
    uint8_t aad[GCM_AAD_MAX_SIZE];
    uint32_t aad_size;
    uint8_t tag[GCM_TAG_MAX_SIZE];
    uint32_t tag_len;
} AesGcmTestVector_t;

extern HkdfTestVector_t hkdf_test_case_01;
extern AesCmacTestVector_t cmac_test_case_01;
extern ShaTestVector_t sha_test_case_01;
extern ShaTestVector_t sha_test_case_02;
extern AesGcmTestVector_t gcm_test_case_01;

#endif // TEE_TEST_VECTOR_H
