#ifndef CRYPTO_TA_H
#define CRYPTO_TA_H

// UUID in TA
#define CRYPTO_TA_UUID \
    { 0x12345678, 0x1234, 0x1234, \
    { 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc } }

// Commands
#define CMD_SHA256              0U
#define CMD_SHA512              1U
#define CMD_AES_PREPARE         2U
#define CMD_AES_CMAC_SIGN       3U
#define CMD_AES_CMAC_VERIFY     4U
#define CMD_AES_GCM_ENC         5U
#define CMD_AES_GCM_DEC         6U
#define CMD_HKDF_DERIVE         7U

// Algorithm (from GlobalPlatform TEE Internal Core API)
#define CRYPTO_ALG_AES_CMAC                 0x30000610U
#define CRYPTO_ALG_AES_GCM                  0x40000810U
#define CRYPTO_ALG_HKDF_SHA256_DERIVE_KEY   0x800040C0U

// Mode
#define CRYPTO_MODE_ENCRYPT     0x00000000U
#define CRYPTO_MODE_DECRYPT     0x00000001U
#define CRYPTO_MODE_SIGN        0x00000002U
#define CRYPTO_MODE_VERIFY      0x00000003U
#define CRYPTO_MODE_MAC         0x00000004U
#define CRYPTO_MODE_DIGEST      0x00000005U
#define CRYPTO_MODE_DERIVE      0x00000006U
#define CRYPTO_MODE_ILLEGAL     0x7FFFFFFFU

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

#endif // CRYPTO_TA_H
