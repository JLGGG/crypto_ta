#include "include/tee_test.h"
#include "include/tee_test_vector.h"

#include <tee_client_api.h>

#define RESULT_PRINT(a, b)                  \
    do {                                    \
        if (b) {                            \
            printf("[SUCCESS]: %s\n", (a)); \
        } else {                            \
            printf("[FAIL]: %s\n", (a));    \
        }                                   \
    } while(0)

int tee_test_run(void)
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
        return TEEC_ERROR_GENERIC;
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
        TEEC_MEMREF_TEMP_INPUT, // Key
        TEEC_VALUE_INPUT,       // Algorithm
        TEEC_NONE,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = cmac_test_case_01.aes_128_key;
    op.params[0].tmpref.size = sizeof(cmac_test_case_01.aes_128_key);
    op.params[1].value.a = CRYPTO_ALG_AES_CMAC;

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

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // Key
        TEEC_VALUE_INPUT,       // Algorithm
        TEEC_NONE,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = gcm_test_case_01.key;
    op.params[0].tmpref.size = sizeof(gcm_test_case_01.key);
    op.params[1].value.a = CRYPTO_ALG_AES_GCM;

    res = TEEC_InvokeCommand(&sess, CMD_AES_PREPARE, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }
    
    TeeGcm_t gcm_data = {0};
    uint8_t gcm_buffer[1024];
    uint8_t gcm_tag_buffer[16];

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // GCM structure
        TEEC_MEMREF_TEMP_OUTPUT, // Ciphertext
        TEEC_MEMREF_TEMP_OUTPUT, // Tag
        TEEC_NONE
    );

    memcpy(gcm_data.iv, gcm_test_case_01.iv, gcm_test_case_01.iv_len);
    gcm_data.iv_len = gcm_test_case_01.iv_len;

    memcpy(gcm_data.aad, gcm_test_case_01.aad, gcm_test_case_01.aad_size);
    gcm_data.aad_len = gcm_test_case_01.aad_size;

    memcpy(gcm_data.payload, gcm_test_case_01.plain, gcm_test_case_01.plain_len);
    gcm_data.payload_len = gcm_test_case_01.plain_len;

    op.params[0].tmpref.buffer = &gcm_data;
    op.params[0].tmpref.size = sizeof(gcm_data);
    op.params[1].tmpref.buffer = gcm_buffer;
    op.params[1].tmpref.size = sizeof(gcm_buffer);
    op.params[2].tmpref.buffer = gcm_tag_buffer;
    op.params[2].tmpref.size = sizeof(gcm_tag_buffer);

    res = TEEC_InvokeCommand(&sess, CMD_AES_GCM_ENC, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    result = 0;
    for (int i=0; i<gcm_test_case_01.cipher_len; i++)
    {
        result |= gcm_buffer[i] ^ gcm_test_case_01.cipher[i];
    }

    for (int i=0; i<gcm_test_case_01.tag_len; i++)
    {
        result |= gcm_tag_buffer[i] ^ gcm_test_case_01.tag[i];
    }

    if (!result)
    {
        RESULT_PRINT("AES-GCM Encryption", 1);
    }
    else
    {
        RESULT_PRINT("AES-GCM Encryption", 0);
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // GCM structure
        TEEC_MEMREF_TEMP_INPUT, // Tag
        TEEC_MEMREF_TEMP_OUTPUT, // Plaintext
        TEEC_NONE
    );

    memset(gcm_data.payload, 0, sizeof(gcm_data.payload));
    memset(gcm_buffer, 0, sizeof(gcm_buffer));
    memcpy(gcm_data.payload, gcm_test_case_01.cipher, gcm_test_case_01.cipher_len);

    op.params[0].tmpref.buffer = &gcm_data;
    op.params[0].tmpref.size = sizeof(gcm_data);
    op.params[1].tmpref.buffer = gcm_tag_buffer;
    op.params[1].tmpref.size = sizeof(gcm_tag_buffer);
    op.params[2].tmpref.buffer = gcm_buffer;
    op.params[2].tmpref.size = sizeof(gcm_buffer);

    res = TEEC_InvokeCommand(&sess, CMD_AES_GCM_DEC, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    result = 0;
    for (int i=0; i<gcm_test_case_01.plain_len; i++)
    {
        result |= gcm_buffer[i] ^ gcm_test_case_01.plain[i];
    }

    if (!result)
    {
        RESULT_PRINT("AES-GCM Decryption", 1);
    }
    else
    {
        RESULT_PRINT("AES-GCM Decryption", 0);
    }

cleanup_sess:
    TEEC_CloseSession(&sess);
cleanup_ctx:
    TEEC_FinalizeContext(&ctx);
    return res != TEEC_SUCCESS;
}
