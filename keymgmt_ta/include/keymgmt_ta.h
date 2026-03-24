#ifndef KEYMGMT_TA_H
#define KEYMGMT_TA_H

#include <stdint.h>

// UUID in Keymgmt TA
#define KEYMGMT_TA_UUID \
    { 0x23456789, 0x2345, 0x2345, \
    { 0x23, 0x45, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd } }

// Commands
typedef enum {
    KM_CMD_KEYGEN = 0U,
    KM_CMD_GET_PUBKEY,
    KM_CMD_SIGN,
    KM_CMD_DELETE_KEY,
    KM_CMD_COUNT
} KeyMgmtCmd_t;

#define ECDSA_BITS      256U
#define ECDSA_PUB       64U
#define ECDSA_PRIV      32U
#define ECDSA_QX        32U
#define ECDSA_QY        32U
#define ECDSA_SIGN      64U
#define ECDSA_DIGEST    32U 

#endif // KEYMGMT_TA_H
