#ifndef CRYPTO_TA_H
#define CRYPTO_TA_H

#include <stdint.h>

// UUID in TA
#define CRYPTO_TA_UUID \
    { 0x12345678, 0x1234, 0x1234, \
    { 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc } }

// Commands
typedef enum {
    CMD_SHA256 = 0U,
    CMD_SHA512,
    CMD_AES_PREPARE,
    CMD_AES_CMAC_SIGN,
    CMD_AES_CMAC_VERIFY,
    CMD_AES_GCM_ENC,
    CMD_AES_GCM_DEC,
    CMD_HKDF_DERIVE,
    CMD_SS_KEY_WRITE,
    CMD_SS_KEY_READ,
    CMD_SS_KEY_DELETE,
    CMD_SECOC_INIT,
    CMD_SECOC_SIGN,
    CMD_SECOC_VERIFY,
    CMD_ECDSA_VERIFY,
    CMD_COUNT
} TeeCmd_t;

// Algorithm (from GlobalPlatform TEE Internal Core API)
#define CRYPTO_ALG_AES_CMAC                 0x30000610U
#define CRYPTO_ALG_AES_GCM                  0x40000810U
#define CRYPTO_ALG_HKDF_SHA256_DERIVE_KEY   0x800040C0U

// Size
#define AES_128_KEY_SIZE        16U
#define AES_192_KEY_SIZE        24U
#define AES_256_KEY_SIZE        32U
#define PLAIN_MAX_SIZE          1024U
#define CIPHER_MAX_SIZE         1024U

#define SHA256_HASH_SIZE        32U
#define SHA512_HASH_SIZE        64U
#define SHA_MAX_SIZE            64U

#define HKDF_IKM_MAX_SIZE       64U // Max size for IKM, typically a SHA-512 digest
#define HKDF_SALT_MAX_SIZE      64U
#define HKDF_INFO_MAX_SIZE      128U
#define HKDF_OKM_MAX_SIZE       64U

#define GCM_IV_MAX_SIZE         12U
#define GCM_AAD_MAX_SIZE        128U
#define GCM_TAG_MAX_SIZE        16U

#define SECOC_KEY_ID            "master_key"
#define SECOC_KEY_ID_LEN        10U

#define ECDSA_KEY_ID            "ecdsa_test_key"
#define ECDSA_KEY_ID_LEN        14U

// DSA
typedef struct {
    uint8_t iv[GCM_IV_MAX_SIZE];
    uint32_t iv_len;
    uint8_t aad[GCM_AAD_MAX_SIZE];
    uint32_t aad_len;
    uint8_t payload[PLAIN_MAX_SIZE];
    uint32_t payload_len;
} TeeGcm_t;

#endif // CRYPTO_TA_H
