#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>

#include "include/tee_test_vector.h"

#define RESULT_PRINT(a, b)                  \
    do {                                    \
        if (b) {                            \
            printf("[SUCCESS]: %s\n", (a)); \
        } else {                            \
            printf("[FAIL]: %s\n", (a));    \
        }                                   \
    } while(0)

int main(int argc, char *argv[])
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = CRYPTO_TA_UUID;
    uint32_t err_origin;

    char *input = "Hello OP-TEE Crypto!";
    uint8_t hash_sha256[SHA256_HASH_SIZE];
    uint8_t hash_sha512[SHA512_HASH_SIZE];
    uint8_t aes_cmac[AES_128_KEY_SIZE];
    uint8_t hkdf_okm[HKDF_OKM_MAX_SIZE];
    uint8_t result = 0U;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
    {
        printf("TEEC_InitializeContext failed: 0x%x\n", res);
        return 1;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("TEEC_OpenSession failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_ctx;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_NONE,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = input;
    op.params[0].tmpref.size = strlen(input);
    op.params[1].tmpref.buffer = hash_sha256;
    op.params[1].tmpref.size = sizeof(hash_sha256);

    res = TEEC_InvokeCommand(&sess, CMD_SHA256, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    for (int i=0; i<SHA256_HASH_SIZE; i++)
    {
        result |= hash_sha256[i] ^ sha_test_case_01.expected_digest[i];

    }

    if (!result)
    {
        RESULT_PRINT("SHA-256", 1);
    }
    else
    {
        RESULT_PRINT("SHA-256", 0);
    }

    op.params[0].tmpref.buffer = input;
    op.params[0].tmpref.size = strlen(input);
    op.params[1].tmpref.buffer = hash_sha512;
    op.params[1].tmpref.size = sizeof(hash_sha512);

    res = TEEC_InvokeCommand(&sess, CMD_SHA512, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    result = 0;
    for (int i=0; i<SHA512_HASH_SIZE; i++)
    {
        result |= hash_sha512[i] ^ sha_test_case_02.expected_digest[i];
    }
    
    if (!result)
    {
        RESULT_PRINT("SHA-512", 1);
    }
    else
    {
        RESULT_PRINT("SHA-512", 0);
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_INPUT,
        TEEC_VALUE_INPUT,
        TEEC_VALUE_INPUT,
        TEEC_MEMREF_TEMP_INPUT
    );

    op.params[0].value.a = CRYPTO_ALG_AES_CMAC;
    op.params[1].value.a = CRYPTO_MODE_MAC;
    op.params[2].value.a = cmac_test_case_01.key_len;
    op.params[3].tmpref.buffer = cmac_test_case_01.aes_128_key;
    op.params[3].tmpref.size = sizeof(cmac_test_case_01.aes_128_key);

    res = TEEC_InvokeCommand(&sess, CMD_AES_PREPARE, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_NONE,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = input;
    op.params[0].tmpref.size = strlen(input);
    op.params[1].tmpref.buffer = aes_cmac;
    op.params[1].tmpref.size = sizeof(aes_cmac);

    res = TEEC_InvokeCommand(&sess, CMD_AES_CMAC_SIGN, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    result = 0;
    for (int i=0; i<AES_128_KEY_SIZE; i++)
    {
        result |= aes_cmac[i] ^ cmac_test_case_01.expected_cmac[i];

    }

    if (!result)
    {
        RESULT_PRINT("AES-CMAC SIGN", 1);
    }
    else
    {
        RESULT_PRINT("AES-CMAC SIGN", 0);
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_VALUE_OUTPUT,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = input;
    op.params[0].tmpref.size = strlen(input);
    op.params[1].tmpref.buffer = aes_cmac;
    op.params[1].tmpref.size = sizeof(aes_cmac);

    res = TEEC_InvokeCommand(&sess, CMD_AES_CMAC_VERIFY, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    if (op.params[2].value.a == true)
    {
        RESULT_PRINT("AES_CMAC VERIFY", 1);
    }
    else
    {
        RESULT_PRINT("AES_CMAC VERIFY", 0);
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT
    );

    op.params[0].tmpref.buffer = hkdf_test_case_01.ikm;
    op.params[0].tmpref.size = hkdf_test_case_01.ikm_len;
    op.params[1].tmpref.buffer = hkdf_test_case_01.salt;
    op.params[1].tmpref.size = hkdf_test_case_01.salt_len;
    op.params[2].tmpref.buffer = hkdf_test_case_01.info;
    op.params[2].tmpref.size = hkdf_test_case_01.info_len;
    op.params[3].tmpref.buffer = hkdf_okm;
    op.params[3].tmpref.size = hkdf_test_case_01.expected_okm_len;

    res = TEEC_InvokeCommand(&sess, CMD_HKDF_DERIVE, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    result = 0;
    for (int i=0; i<hkdf_test_case_01.expected_okm_len; i++)
    {
        result |= hkdf_okm[i] ^ hkdf_test_case_01.expected_okm[i];
    }
    if (!result)
    {
        RESULT_PRINT("HKDF", 1);
    }
    else
    {
        RESULT_PRINT("HKDF", 0);
    }

cleanup_sess:
    TEEC_CloseSession(&sess);
cleanup_ctx:
    TEEC_FinalizeContext(&ctx);
    return res != TEEC_SUCCESS;
}
