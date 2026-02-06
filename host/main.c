#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include <crypto_ta.h>

int main(int argc, char *argv[])
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = CRYPTO_TA_UUID;
    uint32_t err_origin;

    char *input = "Hello OP-TEE Crypto!";
    uint8_t hash_sha256[32];
    uint8_t hash_sha512[64];
    uint8_t aes_cmac[AES_128_KEY_SIZE];
    uint8_t aes_128_key[AES_128_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                            0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t hkdf_ikm[HKDF_IKM_MAX_SIZE] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint8_t hkdf_salt[HKDF_SALT_MAX_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    uint8_t hkdf_info[HKDF_INFO_MAX_SIZE] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    uint8_t hkdf_okm[HKDF_OKM_MAX_SIZE];

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

    printf("Input: %s\n", input);
    printf("SHA-256: ");
    for (int i=0; i<32; i++)
    {
        printf("%02x", hash_sha256[i]);
    }
    printf("\n");

    printf("SHA-512: ");
    for (int i=0; i<64; i++)
    {
        printf("%02x", hash_sha512[i]);
    }
    printf("\n");

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_INPUT,
        TEEC_VALUE_INPUT,
        TEEC_VALUE_INPUT,
        TEEC_MEMREF_TEMP_INPUT
    );

    op.params[0].value.a = CRYPTO_ALG_AES_CMAC;
    op.params[1].value.a = CRYPTO_MODE_MAC;
    op.params[2].value.a = AES_128_KEY_SIZE;
    op.params[3].tmpref.buffer = aes_128_key;
    op.params[3].tmpref.size = sizeof(aes_128_key);

    res = TEEC_InvokeCommand(&sess, CMD_AES_CMAC_PREPARE, &op, &err_origin);
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

    res = TEEC_InvokeCommand(&sess, CMD_AES_CMAC, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    printf("AES-128-CMAC: ");
    for (int i=0; i<AES_128_KEY_SIZE; i++)
    {
        printf("%02x", aes_cmac[i]);
    }
    printf("\n");

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT
    );

    op.params[0].tmpref.buffer = hkdf_ikm;
    op.params[0].tmpref.size = 22;
    op.params[1].tmpref.buffer = hkdf_salt;
    op.params[1].tmpref.size = 13;
    op.params[2].tmpref.buffer = hkdf_info;
    op.params[2].tmpref.size = 10;
    op.params[3].tmpref.buffer = hkdf_okm;
    op.params[3].tmpref.size = 42;

    res = TEEC_InvokeCommand(&sess, CMD_HKDF_DERIVE, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    printf("HKDF-SHA256: ");
    for (int i=0; i<42; i++)
    {
        printf("%02x", hkdf_okm[i]);
    }
    printf("\n");

cleanup_sess:
    TEEC_CloseSession(&sess);
cleanup_ctx:
    TEEC_FinalizeContext(&ctx);
    return res != TEEC_SUCCESS;
}
