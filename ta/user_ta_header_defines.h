#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <my_crypto_ta.h>

#define TA_UUID                MY_CRYPTO_TA_UUID
#define TA_FLAGS               (TA_FLAG_EXEC_DDR | TA_FLAG_SINGLE_INSTANCE)
#define TA_STACK_SIZE          (2 * 1024)
#define TA_DATA_SIZE           (32 * 1024)

#endif
