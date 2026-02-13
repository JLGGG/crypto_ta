#ifndef TEE_TEST_VECTOR_H
#define TEE_TEST_VECTOR_H

#include "crypto_ta.h"

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t ikm[HKDF_IKM_MAX_SIZE];
    uint16_t ikm_len;
    uint8_t salt[HKDF_SALT_MAX_SIZE];
    uint16_t salt_len;
    uint8_t info[HKDF_INFO_MAX_SIZE];
    uint16_t info_len;
    uint8_t expected_okm[HKDF_OKM_MAX_SIZE];
    uint16_t expected_okm_len;
} HkdfTestCase_t;

typedef struct {
    uint8_t aes_128_key[AES_128_KEY_SIZE];
    uint16_t key_len;
    uint8_t *message;
    uint8_t expected_cmac[AES_128_KEY_SIZE];
} AesCmacTestCase_t;

typedef struct {
    uint8_t sha_type;
    uint8_t *message;
    uint8_t expected_digest[SHA_MAX_SIZE];
} ShaTestCase_t;

extern HkdfTestCase_t hkdf_test_case_01;
extern AesCmacTestCase_t cmac_test_case_01;
extern ShaTestCase_t sha_test_case_01;
extern ShaTestCase_t sha_test_case_02;

#endif // TEE_TEST_VECTOR_H
