#ifndef CRYPTO_TA_H
#define CRYPTO_TA_H

// UUID in TA
#define CRYPTO_TA_UUID \
    { 0x12345678, 0x1234, 0x1234, \
    { 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc } }

// Commands
#define CMD_SHA256              0
#define CMD_SHA512              1
#define CMD_AES_CMAC_PREPARE    2
#define CMD_AES_CMAC            3
#define CMD_HKDF_DERIVE         4

// Algorithm (from GlobalPlatform TEE Internal Core API)
#define CRYPTO_ALG_AES_CMAC                 0x30000610
#define CRYPTO_ALG_HKDF_SHA256_DERIVE_KEY   0x800040C0

// Mode
#define CRYPTO_MODE_ENCRYPT     0x00000000
#define CRYPTO_MODE_DECRYPT     0x00000001
#define CRYPTO_MODE_SIGN        0x00000002
#define CRYPTO_MODE_VERIFY      0x00000003
#define CRYPTO_MODE_MAC         0x00000004
#define CRYPTO_MODE_DIGEST      0x00000005
#define CRYPTO_MODE_DERIVE      0x00000006
#define CRYPTO_MODE_ILLEGAL     0x7FFFFFFF

#define AES_128_KEY_SIZE        16
#define AES_192_KEY_SIZE        24
#define AES_256_KEY_SIZE        32
#define SHA256_HASH_SIZE        32
#define SHA512_HASH_SIZE        64
#define SHA_MAX_SIZE            64

#define HKDF_IKM_MAX_SIZE       64 // Max size for IKM, typically a SHA-512 digest
#define HKDF_SALT_MAX_SIZE      64
#define HKDF_INFO_MAX_SIZE      128
#define HKDF_OKM_MAX_SIZE       64

#endif // CRYPTO_TA_H
