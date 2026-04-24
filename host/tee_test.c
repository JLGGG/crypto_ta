#include "include/tee_test.h"
#include "include/tee_test_vector.h"

#include <tee_client_api.h>

#define SUCCESS (1U)
#define FAIL    (0U)

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
    TEEC_Session km_sess;
    TEEC_Operation op;
    TEEC_UUID uuid = CRYPTO_TA_UUID;
    TEEC_UUID km_uuid = KEYMGMT_TA_UUID;
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
        printf("[CRYPTO TA]: TEEC_OpenSession failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_ctx;
    }

    res = TEEC_OpenSession(&ctx, &km_sess, &km_uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[KEYMGMT TA]: TEEC_OpenSession failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    /* -------------------- SHA Test  -------------------- */
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
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    for (int i=0; i<SHA256_HASH_SIZE; i++)
    {
        result |= hash_sha256[i] ^ sha_test_case_01.expected_digest[i];

    }

    if (!result)
    {
        RESULT_PRINT("SHA-256", SUCCESS);
    }
    else
    {
        RESULT_PRINT("SHA-256", FAIL);
    }

    op.params[0].tmpref.buffer = input;
    op.params[0].tmpref.size = strlen(input);
    op.params[1].tmpref.buffer = hash_sha512;
    op.params[1].tmpref.size = sizeof(hash_sha512);

    res = TEEC_InvokeCommand(&sess, CMD_SHA512, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    result = 0;
    for (int i=0; i<SHA512_HASH_SIZE; i++)
    {
        result |= hash_sha512[i] ^ sha_test_case_02.expected_digest[i];
    }
    
    if (!result)
    {
        RESULT_PRINT("SHA-512", SUCCESS);
    }
    else
    {
        RESULT_PRINT("SHA-512", FAIL);
    }

    /* -------------------- AES-CMAC Test  -------------------- */
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
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
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
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    result = 0;
    for (int i=0; i<AES_128_KEY_SIZE; i++)
    {
        result |= aes_cmac[i] ^ cmac_test_case_01.expected_cmac[i];

    }

    if (!result)
    {
        RESULT_PRINT("AES-CMAC SIGN", SUCCESS);
    }
    else
    {
        RESULT_PRINT("AES-CMAC SIGN", FAIL);
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
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    if (op.params[2].value.a == true)
    {
        RESULT_PRINT("AES_CMAC VERIFY", SUCCESS);
    }
    else
    {
        RESULT_PRINT("AES_CMAC VERIFY", FAIL);
    }

    /* -------------------- HKDF Test  -------------------- */
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
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    result = 0;
    for (int i=0; i<hkdf_test_case_01.expected_okm_len; i++)
    {
        result |= hkdf_okm[i] ^ hkdf_test_case_01.expected_okm[i];
    }
    if (!result)
    {
        RESULT_PRINT("HKDF", SUCCESS);
    }
    else
    {
        RESULT_PRINT("HKDF", FAIL);
    }

    /* -------------------- AES-GCM Test  -------------------- */
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
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
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
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
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
        RESULT_PRINT("AES-GCM Encryption", SUCCESS);
    }
    else
    {
        RESULT_PRINT("AES-GCM Encryption", FAIL);
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
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    result = 0;
    for (int i=0; i<gcm_test_case_01.plain_len; i++)
    {
        result |= gcm_buffer[i] ^ gcm_test_case_01.plain[i];
    }

    if (!result)
    {
        RESULT_PRINT("AES-GCM Decryption", SUCCESS);
    }
    else
    {
        RESULT_PRINT("AES-GCM Decryption", FAIL);
    }

    /* -------------------- Secure Storage Test  -------------------- */
    char *key_id = SECOC_KEY_ID;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // key id
        TEEC_MEMREF_TEMP_INPUT, // key data
        TEEC_NONE,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = key_id;
    op.params[0].tmpref.size = strlen(key_id);
    op.params[1].tmpref.buffer = cmac_test_case_01.aes_128_key;
    op.params[1].tmpref.size = cmac_test_case_01.key_len;

    res = TEEC_InvokeCommand(&sess, CMD_SS_KEY_WRITE, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        RESULT_PRINT("Write Key to Secure Storage", FAIL);
        goto cleanup_sess;
    }
    else
    {
        RESULT_PRINT("Write Key to Secure Storage", SUCCESS);
    }

    uint8_t key_buffer[AES_128_KEY_SIZE];

    result = 0;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // key id
        TEEC_MEMREF_TEMP_OUTPUT, // Get key from TEE
        TEEC_NONE,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = key_id;
    op.params[0].tmpref.size = strlen(key_id);
    op.params[1].tmpref.buffer = key_buffer;
    op.params[1].tmpref.size = sizeof(key_buffer);

    res = TEEC_InvokeCommand(&sess, CMD_SS_KEY_READ, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    for (int i=0; i<AES_128_KEY_SIZE; i++)
    {
        result |= key_buffer[i] ^ cmac_test_case_01.aes_128_key[i];
    }

    if (!result)
    {
        RESULT_PRINT("Read Key from Secure Storage", SUCCESS);
    }
    else
    {
        RESULT_PRINT("Read Key from Secure Storage", FAIL);
    }

    /* -------------------- SecOC Test  -------------------- */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = key_id;
    op.params[0].tmpref.size = strlen(key_id);
    op.params[1].tmpref.buffer = hkdf_test_case_01.salt;
    op.params[1].tmpref.size = hkdf_test_case_01.salt_len;
    op.params[2].tmpref.buffer = hkdf_test_case_01.info;
    op.params[2].tmpref.size = hkdf_test_case_01.info_len;

    res = TEEC_InvokeCommand(&sess, CMD_SECOC_INIT, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }
    else
    {
        RESULT_PRINT("SecOC Init", SUCCESS);
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_NONE,
        TEEC_NONE
    );

    char *message = "CAN_ID:0x123|DATA:AABBCCDD";

    op.params[0].tmpref.buffer = message;
    op.params[0].tmpref.size = strlen(message);
    op.params[1].tmpref.buffer = aes_cmac;
    op.params[1].tmpref.size = sizeof(aes_cmac);

    res = TEEC_InvokeCommand(&sess, CMD_SECOC_SIGN, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }
    else
    {
        RESULT_PRINT("SecOC Sign", SUCCESS);
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_VALUE_OUTPUT,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = message;
    op.params[0].tmpref.size = strlen(message);
    op.params[1].tmpref.buffer = aes_cmac;
    op.params[1].tmpref.size = sizeof(aes_cmac);

    res = TEEC_InvokeCommand(&sess, CMD_SECOC_VERIFY, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    if (op.params[2].value.a)
    {
        RESULT_PRINT("SecOC Verify (Correct Data)", SUCCESS);
    }
    else
    {
        RESULT_PRINT("SecOC Verify (Correct Data)", FAIL);
    }

    char *tampered = "CAN_ID:0x123|DATA:DEADBEEF";

    op.params[0].tmpref.buffer = tampered;
    op.params[0].tmpref.size = strlen(tampered);
    op.params[1].tmpref.buffer = aes_cmac;
    op.params[1].tmpref.size = sizeof(aes_cmac);

    res = TEEC_InvokeCommand(&sess, CMD_SECOC_VERIFY, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    if (!op.params[2].value.a)
    {
        RESULT_PRINT("SecOC Verify (Tampered Data)", SUCCESS);
    }
    else
    {
        RESULT_PRINT("SecOC Verify (Tampered Data)", FAIL);
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // key id
        TEEC_VALUE_OUTPUT, // Get the result of the deletion from TEE
        TEEC_NONE,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = key_id;
    op.params[0].tmpref.size = strlen(key_id);

    res = TEEC_InvokeCommand(&sess, CMD_SS_KEY_DELETE, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    if (!op.params[1].value.a)
    {
        RESULT_PRINT("Delete Key from Secure Storage", SUCCESS);
    }
    else
    {
        RESULT_PRINT("Delete Key from Secure Storage", FAIL);
    }

    /* -------------------- Key Management TA Test  -------------------- */
    char *km_key_id = ECDSA_KEY_ID;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // key id
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = km_key_id;
    op.params[0].tmpref.size = strlen(km_key_id);

    res = TEEC_InvokeCommand(&km_sess, KM_CMD_KEYGEN, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[KEYMGMT TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }
    else
    {
        RESULT_PRINT("ECDSA KeyGen", SUCCESS);
    }

    uint8_t km_pub_key[64];

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // key id
        TEEC_MEMREF_TEMP_OUTPUT, // pub key
        TEEC_NONE,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = km_key_id;
    op.params[0].tmpref.size = strlen(km_key_id);
    op.params[1].tmpref.buffer = km_pub_key;
    op.params[1].tmpref.size = sizeof(km_pub_key);

    res = TEEC_InvokeCommand(&km_sess, KM_CMD_GET_PUBKEY, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[KEYMGMT TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }
    else
    {
        RESULT_PRINT("ECDSA GetPubKey", SUCCESS);
    }

    char *test_fw = "Firmware Image v1.0 - Test Data";
    uint8_t digest[32];

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // firmware
        TEEC_MEMREF_TEMP_OUTPUT, // digest
        TEEC_NONE,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = test_fw;
    op.params[0].tmpref.size = strlen(test_fw);
    op.params[1].tmpref.buffer = digest;
    op.params[1].tmpref.size = sizeof(digest);

    res = TEEC_InvokeCommand(&sess, CMD_SHA256, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }
    else
    {
        RESULT_PRINT("Digest Generation for FW", SUCCESS);
    }

    uint8_t signature[64];

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // key id
        TEEC_MEMREF_TEMP_INPUT, // digest
        TEEC_MEMREF_TEMP_OUTPUT, // signature
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = km_key_id;
    op.params[0].tmpref.size = strlen(km_key_id);
    op.params[1].tmpref.buffer = digest;
    op.params[1].tmpref.size = sizeof(digest);
    op.params[2].tmpref.buffer = signature;
    op.params[2].tmpref.size = sizeof(signature);

    res = TEEC_InvokeCommand(&km_sess, KM_CMD_SIGN, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[KEYMGMT TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }
    else
    {
        RESULT_PRINT("Signature Generation for FW", SUCCESS);
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // key id
        TEEC_MEMREF_TEMP_INPUT, // digest
        TEEC_MEMREF_TEMP_INPUT, // signature
        TEEC_VALUE_OUTPUT
    );

    op.params[0].tmpref.buffer = km_key_id;
    op.params[0].tmpref.size = strlen(km_key_id);
    op.params[1].tmpref.buffer = digest;
    op.params[1].tmpref.size = sizeof(digest);
    op.params[2].tmpref.buffer = signature;
    op.params[2].tmpref.size = sizeof(signature);

    res = TEEC_InvokeCommand(&sess, CMD_ECDSA_VERIFY, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }
    else
    {
        if (op.params[3].value.a == SUCCESS)
        {
            RESULT_PRINT("ECDSA Verify (Valid)", SUCCESS);
        }
        else
        {
            RESULT_PRINT("ECDSA Verify (Valid)", FAIL);
        }
    }

    char *tamp_fw = "Tampered Firmware";
    uint8_t tampered_digest[32];

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // tampered firmware
        TEEC_MEMREF_TEMP_OUTPUT, // digest
        TEEC_NONE,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = tamp_fw;
    op.params[0].tmpref.size = strlen(tamp_fw);
    op.params[1].tmpref.buffer = tampered_digest;
    op.params[1].tmpref.size = sizeof(tampered_digest);

    res = TEEC_InvokeCommand(&sess, CMD_SHA256, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }
    else
    {
        RESULT_PRINT("Digest Generation for Tampered FW", SUCCESS);
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // key id
        TEEC_MEMREF_TEMP_INPUT, // digest
        TEEC_MEMREF_TEMP_INPUT, // signature
        TEEC_VALUE_OUTPUT
    );

    op.params[0].tmpref.buffer = km_key_id;
    op.params[0].tmpref.size = strlen(km_key_id);
    op.params[1].tmpref.buffer = tampered_digest;
    op.params[1].tmpref.size = sizeof(tampered_digest);
    op.params[2].tmpref.buffer = signature;
    op.params[2].tmpref.size = sizeof(signature);

    res = TEEC_InvokeCommand(&sess, CMD_ECDSA_VERIFY, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[CRYPTO TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }
    else
    {
        if (op.params[3].value.a == SUCCESS)
        {
            RESULT_PRINT("ECDSA Verify (Tampered)", FAIL);
        }
        else
        {
            RESULT_PRINT("ECDSA Verify (Tampered)", SUCCESS);
        }
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, // key id
        TEEC_VALUE_OUTPUT, // Get the result of the deletion from TEE
        TEEC_NONE,
        TEEC_NONE
    );

    op.params[0].tmpref.buffer = km_key_id;
    op.params[0].tmpref.size = strlen(km_key_id);

    res = TEEC_InvokeCommand(&km_sess, KM_CMD_DELETE_KEY, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        printf("[KEYMGMT TA]: TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, err_origin);
        goto cleanup_sess;
    }

    if (!op.params[1].value.a)
    {
        RESULT_PRINT("Delete Key from Key Management TA", SUCCESS);
    }
    else
    {
        RESULT_PRINT("Delete Key from Key Management TA", FAIL);
    }

cleanup_sess:
    TEEC_CloseSession(&sess);
    TEEC_CloseSession(&km_sess);
cleanup_ctx:
    TEEC_FinalizeContext(&ctx);
    return res != TEEC_SUCCESS;
}
