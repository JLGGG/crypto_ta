#ifndef CRYPTO_TA_H
#define CRYPTO_TA_H

#define CRYPTO_TA_UUID \
    { 0x12345678, 0x1234, 0x1234, \
    { 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc } }

#define CMD_SHA256              0
#define CMD_SHA512              1
#define CMD_AES_CMAC_PREPARE    2
#define CMD_AES_CMAC            3
#define CMD_AES_ENC             4
#define CMD_AES_DEC             5

#endif // CRYPTO_TA_H
