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
#define CMD_AES_ENC             4
#define CMD_AES_DEC             5

// Algorithm (from GlobalPlatform TEE Internal Core API)
#define CRYPTO_ALG_AES_CMAC     0x30000610

// Mode
#define CRYPTO_MODE_ENCRYPT     0x00000000
#define CRYPTO_MODE_DECRYPT     0x00000001
#define CRYPTO_MODE_SIGN        0x00000002
#define CRYPTO_MODE_VERIFY      0x00000003
#define CRYPTO_MODE_MAC         0x00000004
#define CRYPTO_MODE_DIGEST      0x00000005
#define CRYPTO_MODE_DERIVE      0x00000006
#define CRYPTO_MODE_ILLEGAL     0x7FFFFFFF

// Key sizes
#define AES_128_KEY_SIZE        16
#define AES_192_KEY_SIZE        24
#define AES_256_KEY_SIZE        32

#endif // CRYPTO_TA_H
