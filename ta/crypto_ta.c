#include <tee_internal_api.h>
#include <tee_api_defines_extensions.h>
#include <crypto_ta.h>
#include <string.h>

typedef struct {
    uint32_t algo;
    uint32_t key_size;
    TEE_ObjectHandle key_handle;
} TeeSession_t;

TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("TA Create");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt, TEE_Param params[4], void **session)
{
    (void)pt; (void)params;
    TeeSession_t *sess = TEE_Malloc(sizeof(*sess), 0);

    if (sess == NULL)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    sess->key_handle = TEE_HANDLE_NULL;

    *session = sess;
    DMSG("Session %p: newly allocated", *session);

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
    DMSG("Session %p: release session", session);
    TeeSession_t *sess = session;

    TEE_FreeTransientObject(sess->key_handle);
    TEE_Free(sess);
}

static TEE_Result do_sha256(uint32_t pt, TEE_Param params[4])
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;

    uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
    {
        return res;
    }

    res = TEE_DigestDoFinal(op, params[0].memref.buffer, params[0].memref.size,
                params[1].memref.buffer, &params[1].memref.size);
            
    TEE_FreeOperation(op);
    return res;
}

static TEE_Result do_sha512(uint32_t pt, TEE_Param params[4])
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;

    uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_AllocateOperation(&op, TEE_ALG_SHA512, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
    {
        return res;
    }

    res = TEE_DigestDoFinal(op, params[0].memref.buffer, params[0].memref.size,
                params[1].memref.buffer, &params[1].memref.size);
            
    TEE_FreeOperation(op);
    return res;
}

static TEE_Result alloc_resources(void *session, uint32_t param_types, TEE_Param params[4])
{
    TeeSession_t *sess = NULL;
    TEE_Attribute attr = {0};
    TEE_Result res = TEE_ERROR_GENERIC;
    uint32_t tee_obj_type = TEE_TYPE_AES;

    const uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,    // Key
        TEE_PARAM_TYPE_VALUE_INPUT,     // Algorithm
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    DMSG("Session %p: get resources", session);
    sess = session;

    if (param_types != exp_param_types)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (sess->key_handle != TEE_HANDLE_NULL)
    {
        TEE_FreeTransientObject(sess->key_handle);
        sess->key_handle = TEE_HANDLE_NULL;
    }

    sess->key_size = params[0].memref.size;
    sess->algo = params[1].value.a;

    // maxObjectSize: The second parameter is entered as a bit unit.
    res = TEE_AllocateTransientObject(tee_obj_type, sess->key_size * 8, &sess->key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate transient object");
        goto err;
    }

    TEE_InitRefAttribute(&attr,
        TEE_ATTR_SECRET_VALUE,
        params[0].memref.buffer,
        params[0].memref.size
    );
    res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_PopulateTransientObject failed, %d", res);
        goto err;
    }

    return TEE_SUCCESS;

err:
    TEE_FreeTransientObject(sess->key_handle);
    sess->key_handle = TEE_HANDLE_NULL;

    return res;
}

static TEE_Result aes_cmac_sign_op(void *session, uint32_t pt, TEE_Param params[4])
{
    TeeSession_t *sess = NULL;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
    void *message = NULL;
    size_t message_size = 0U;
    uint32_t cmac_len = 0U;
    void *temp_buffer = NULL;

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    DMSG("Session %p: cmac operation", session);
    sess = session;

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (sess->key_handle == TEE_HANDLE_NULL)
    {
        EMSG("Key handle not properly initialized.");
        return TEE_ERROR_BAD_STATE;
    }

    res = TEE_AllocateOperation(&op, sess->algo, TEE_MODE_MAC, sess->key_size * 8);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate operation");
        goto exit;
    }

    res = TEE_SetOperationKey(op, sess->key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_SetOperationKey failed %d", res);
        goto exit;
    }

    message = params[0].memref.buffer;
    message_size = params[0].memref.size;
    cmac_len = params[1].memref.size;

    if (params[1].memref.buffer && params[1].memref.size)
    {
        temp_buffer = TEE_Malloc(params[1].memref.size, 0);
        if (temp_buffer == NULL)
        {
            goto free_buffer;
        }
    }

    TEE_MACInit(op, NULL, 0);
    res = TEE_MACComputeFinal(op, message, message_size, temp_buffer, &cmac_len);
    if (res == TEE_SUCCESS)
    {
        TEE_MemMove(params[1].memref.buffer, temp_buffer, cmac_len);
    }

    params[1].memref.size = cmac_len;

free_buffer:
    TEE_Free(temp_buffer);
exit:
    TEE_FreeOperation(op);
    return res;
}

static TEE_Result aes_cmac_verify_op(void *session, uint32_t pt, TEE_Param params[4])
{
    TeeSession_t *sess = NULL;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
    void *message = NULL;
    size_t message_size = 0U;
    void *cmac = NULL;
    size_t cmac_len = 0U;

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE
    );

    DMSG("Session %p: cmac operation", session);
    sess = session;

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (sess->key_handle == TEE_HANDLE_NULL)
    {
        EMSG("Key handle not properly initialized.");
        return TEE_ERROR_BAD_STATE;
    }

    res = TEE_AllocateOperation(&op, sess->algo, TEE_MODE_MAC, sess->key_size * 8);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate operation");
        goto exit;
    }

    res = TEE_SetOperationKey(op, sess->key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_SetOperationKey failed %d", res);
        goto exit;
    }

    message = params[0].memref.buffer;
    message_size = params[0].memref.size;
    cmac = params[1].memref.buffer;
    cmac_len = params[1].memref.size;

    TEE_MACInit(op, NULL, 0);
    res = TEE_MACCompareFinal(op, message, message_size, cmac, cmac_len);
    params[2].value.a = (res == TEE_SUCCESS);

exit:
    TEE_FreeOperation(op);
    return res;
}

static TEE_Result aes_gcm_enc_op(void *session, uint32_t pt, TEE_Param params[4])
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TeeSession_t *sess = NULL;
    TeeGcm_t *gcm_data = NULL;
    void *ciphertext_temp_buffer = NULL;
    void *tag_temp_buffer = NULL;
    uint32_t ciphertext_len = 0U;
    uint32_t tag_len = 0U;

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,  // GCM data structure
        TEE_PARAM_TYPE_MEMREF_OUTPUT, // Ciphertext
        TEE_PARAM_TYPE_MEMREF_OUTPUT, // Tag
        TEE_PARAM_TYPE_NONE
    );

    DMSG("Session %p: AES-GCM encryption operation", session);
    sess = session;

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (sess->key_handle == TEE_HANDLE_NULL)
    {
        EMSG("Key handle not properly initialized.");
        return TEE_ERROR_BAD_STATE;
    }

    res = TEE_AllocateOperation(&op, sess->algo, TEE_MODE_ENCRYPT, sess->key_size * 8);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate operation");
        goto exit;
    }

    res = TEE_SetOperationKey(op, sess->key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_SetOperationKey failed %d", res);
        goto exit;
    }

    gcm_data = params[0].memref.buffer;
    ciphertext_len = params[1].memref.size;
    tag_len = params[2].memref.size;

    if ((params[1].memref.buffer && params[1].memref.size)
        && (params[2].memref.buffer && params[2].memref.size))
    {
        ciphertext_temp_buffer = TEE_Malloc(params[1].memref.size, 0);
        tag_temp_buffer = TEE_Malloc(params[2].memref.size, 0);
        if ((ciphertext_temp_buffer == NULL) || (tag_temp_buffer == NULL))
        {
            goto free_buffer;
        }
    }

    res = TEE_AEInit(op, gcm_data->iv, gcm_data->iv_len, tag_len * 8, gcm_data->aad_len, gcm_data->payload_len);
    if (res == TEE_SUCCESS)
    {
        if (gcm_data->aad_len > 0)
        {
            (void)TEE_AEUpdateAAD(op, gcm_data->aad, gcm_data->aad_len);
        }

        res = TEE_AEEncryptFinal(
            op,
            gcm_data->payload, // Plaintext
            gcm_data->payload_len,
            ciphertext_temp_buffer,
            &ciphertext_len,
            tag_temp_buffer,
            &tag_len);

        if (res == TEE_SUCCESS)
        {
            (void)TEE_MemMove(params[1].memref.buffer, ciphertext_temp_buffer, ciphertext_len);
            (void)TEE_MemMove(params[2].memref.buffer, tag_temp_buffer, tag_len);
        }
    }
free_buffer:
    (void)TEE_Free(ciphertext_temp_buffer);
    (void)TEE_Free(tag_temp_buffer);
exit:
    TEE_FreeOperation(op);
    return res;
}

static TEE_Result aes_gcm_dec_op(void *session, uint32_t pt, TEE_Param params[4])
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TeeSession_t *sess = NULL;
    TeeGcm_t *gcm_data = NULL;
    void *plaintext_temp_buffer = NULL;
    uint32_t plaintext_len = 0U;
    void *tag = NULL;
    uint32_t tag_len = 0U;

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,    // GCM data structure
        TEE_PARAM_TYPE_MEMREF_INPUT,    // Tag
        TEE_PARAM_TYPE_MEMREF_OUTPUT,   // Plaintext
        TEE_PARAM_TYPE_NONE
    );

    DMSG("Session %p: AES-GCM decryption operation", session);
    sess = session;

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (sess->key_handle == TEE_HANDLE_NULL)
    {
        EMSG("Key handle not properly initialized.");
        return TEE_ERROR_BAD_STATE;
    }

    res = TEE_AllocateOperation(&op, sess->algo, TEE_MODE_DECRYPT, sess->key_size * 8);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate operation");
        goto exit;
    }

    res = TEE_SetOperationKey(op, sess->key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_SetOperationKey failed %d", res);
        goto exit;
    }

    gcm_data = params[0].memref.buffer;
    tag = params[1].memref.buffer;
    tag_len = params[1].memref.size;
    plaintext_len = params[2].memref.size;

    if ((params[2].memref.buffer) && (params[2].memref.size))
    {
        plaintext_temp_buffer = TEE_Malloc(params[2].memref.size, 0);
        if (plaintext_temp_buffer == NULL)
        {
            goto free_buffer;
        }
    }

    res = TEE_AEInit(op, gcm_data->iv, gcm_data->iv_len, tag_len * 8, gcm_data->aad_len, gcm_data->payload_len);
    if (res == TEE_SUCCESS)
    {
        if (gcm_data->aad_len > 0)
        {
            (void)TEE_AEUpdateAAD(op, gcm_data->aad, gcm_data->aad_len);
        }

        res = TEE_AEDecryptFinal(
            op,
            gcm_data->payload, // Ciphertext
            gcm_data->payload_len,
            plaintext_temp_buffer,
            &plaintext_len,
            tag,
            tag_len);

        if (res == TEE_SUCCESS)
        {
            (void)TEE_MemMove(params[2].memref.buffer, plaintext_temp_buffer, plaintext_len);
        }
        else
        {
            res = TEE_ERROR_MAC_INVALID;
        }
    }
free_buffer:
    (void)TEE_Free(plaintext_temp_buffer);
exit:
    TEE_FreeOperation(op);
    return res;
}

static TEE_Result do_hkdf_derive(uint32_t pt, TEE_Param params[4])
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle ikm_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle okm_handle = TEE_HANDLE_NULL;
    TEE_Attribute attrs[3];
    uint32_t attr_count = 0U;

    void *ikm = NULL;
    size_t ikm_size = 0U;
    void *salt = NULL;
    size_t salt_size = 0U;
    void *info = NULL;
    size_t info_size = 0U;
    uint32_t okm_size = 0U;

    // params[0]: IKM  (Input key Material) - MEMREF_INPUT
    // params[1]: Salt (can be empty) - MEMREF_INPUT
    // params[2]: Info (can be empty) - MEMREF_INPUT
    // params[3]: OKM  (Output Key Material) - MEMREF_OUTPUT

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT
    );

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ikm = params[0].memref.buffer;
    ikm_size = params[0].memref.size;
    salt = params[1].memref.buffer;
    salt_size = params[1].memref.size;
    info = params[2].memref.buffer;
    info_size = params[2].memref.size;
    okm_size = params[3].memref.size;

    if (!ikm || ikm_size == 0 || okm_size == 0)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_HKDF_IKM, ikm_size * 8, &ikm_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate IKM object: 0x%x", res);
        goto clean;
    }

    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_HKDF_IKM, ikm, ikm_size);
    res = TEE_PopulateTransientObject(ikm_handle, &attrs[0], 1);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to populate IKM: 0x%x", res);
        goto clean;
    }

    res = TEE_AllocateOperation(&op, TEE_ALG_HKDF_SHA256_DERIVE_KEY, TEE_MODE_DERIVE, ikm_size * 8);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate operation: 0x%x", res);
        goto clean;
    }

    res = TEE_SetOperationKey(op, ikm_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to set operation key: 0x%x", res);
        goto clean;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, okm_size * 8, &okm_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate OKM object: 0x%x", res);
        goto clean;
    }

    if ((salt != NULL) && (salt_size > 0))
    {
        TEE_InitRefAttribute(&attrs[attr_count], TEE_ATTR_HKDF_SALT, salt, salt_size);
        attr_count++;
    }

    if ((info != NULL) && (info_size > 0))
    {
        TEE_InitRefAttribute(&attrs[attr_count], TEE_ATTR_HKDF_INFO, info, info_size);
        attr_count++;
    }
    TEE_InitValueAttribute(&attrs[attr_count], TEE_ATTR_HKDF_OKM_LENGTH, okm_size, 0);
    attr_count++;

    (void)TEE_DeriveKey(op, attrs, attr_count, okm_handle);

    res = TEE_GetObjectBufferAttribute(okm_handle, TEE_ATTR_SECRET_VALUE, params[3].memref.buffer, &okm_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to get OKM: 0x%x", res);
        goto clean;
    }

    params[3].memref.size = okm_size;
    DMSG("HKDF derived %u bytes", okm_size);

clean:
    TEE_FreeOperation(op);
    TEE_FreeTransientObject(ikm_handle);
    TEE_FreeTransientObject(okm_handle);
    return res;
}

static TEE_Result write_key_to_ss(uint32_t pt, TEE_Param params[4])
{
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    char *obj_id = NULL;
    size_t obj_id_size = 0U;
    char *key = NULL;
    size_t key_size = 0U;
    uint32_t flags;

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, // Key ID
        TEE_PARAM_TYPE_MEMREF_INPUT, // Key data
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Copy Key Id to TEE mem
    obj_id_size = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_size, 0);
    if (!obj_id)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_size);

    // Copy Key to TEE mem
    key_size = params[1].memref.size;
    key = TEE_Malloc(key_size, 0);
    if (!key)
    {
        TEE_Free(obj_id);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(key, params[1].memref.buffer, key_size);

    // Create persistent object
    flags = TEE_DATA_FLAG_ACCESS_READ |
            TEE_DATA_FLAG_ACCESS_WRITE |
            TEE_DATA_FLAG_ACCESS_WRITE_META |
            TEE_DATA_FLAG_OVERWRITE;

    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,
        obj_id, obj_id_size,
        flags,
        TEE_HANDLE_NULL,
        NULL, 0,
        &object
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_CreatePersistentObject failed: 0x%x", res);
        TEE_Free(obj_id);
        TEE_Free(key);
        return res;
    }

    // Write data to object
    res = TEE_WriteObjectData(object, key, key_size);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_WriteObjectData failed: 0x%x", res);
        TEE_CloseAndDeletePersistentObject1(object);
    }
    else
    {
        TEE_CloseObject(object);
    }

    TEE_Free(obj_id);
    TEE_Free(key);
    return res;
}

static TEE_Result read_key_from_ss(uint32_t pt, TEE_Param params[4])
{
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    TEE_ObjectInfo object_info = {0};
    char *obj_id = NULL;
    size_t obj_id_size = 0U;
    char *data = NULL;
    size_t data_size = 0U;
    uint32_t read_bytes = 0U;

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, // Key Id
        TEE_PARAM_TYPE_MEMREF_OUTPUT, // Get key from SS
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    obj_id_size = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_size, 0);
    if (!obj_id)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_size);

    data_size = params[1].memref.size;
    data = TEE_Malloc(data_size, 0);
    if (!data)
    {
        TEE_Free(obj_id);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        obj_id, obj_id_size,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
        &object
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_OpenPersistentObject failed: 0x%x", res);
        TEE_Free(obj_id);
        TEE_Free(data);
        return res;
    }

    res = TEE_GetObjectInfo1(object, &object_info);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_GetObjectInfo1 failed: 0x%x", res);
        goto exit;
    }

    res = TEE_ReadObjectData(object, data, object_info.dataSize, &read_bytes);
    if (res == TEE_SUCCESS)
    {
        TEE_MemMove(params[1].memref.buffer, data, read_bytes);
        params[1].memref.size = read_bytes;
    }
    else
    {
        EMSG("TEE_ReadObjectData failed: 0x%x", res);
    }

exit:
    TEE_CloseObject(object);
    TEE_Free(obj_id);
    TEE_Free(data);
    return res;
}

static TEE_Result delete_key_from_ss(uint32_t pt, TEE_Param params[4])
{
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    char *obj_id = NULL;
    size_t obj_id_size = 0U;

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, // Key Id
        TEE_PARAM_TYPE_VALUE_OUTPUT, // the result of the deletion
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    obj_id_size = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_size, 0);
    if (!obj_id)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_size);

    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        obj_id, obj_id_size,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META,
        &object
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_OpenPersistentObject failed: 0x%x", res);
        params[1].value.a = TEE_ERROR_STORAGE_NOT_AVAILABLE;
        goto exit;
    }
    else
    {
        params[1].value.a = TEE_SUCCESS;
    }

    TEE_CloseAndDeletePersistentObject1(object);
exit:
    TEE_Free(obj_id);
    return res;
}

static TEE_Result secoc_init(void *session, uint32_t pt, TEE_Param params[4])
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    TEE_ObjectHandle ikm_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle okm_handle = TEE_HANDLE_NULL;
    TEE_ObjectInfo obj_info = {0};
    TEE_Attribute attrs[3];
    TEE_Attribute attr;
    uint32_t attr_count = 0U;
    TeeSession_t *sess = NULL;
    char *obj_id = NULL;
    size_t obj_id_sz = 0U;
    char *salt = NULL;
    size_t salt_sz = 0U;
    char *info = NULL;
    size_t info_sz = 0U;
    uint8_t *ikm = NULL;
    size_t ikm_sz = 0U;
    uint8_t *okm = NULL;
    size_t okm_sz = 0U;
    uint32_t read_bytes = 0U;

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, // Object Id
        TEE_PARAM_TYPE_MEMREF_INPUT, // Salt
        TEE_PARAM_TYPE_MEMREF_INPUT, // Info
        TEE_PARAM_TYPE_NONE
    );

    DMSG("Session %p: SecOC init operation", session);
    sess = (TeeSession_t *)session;

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (sess->key_handle != TEE_HANDLE_NULL)
    {
        TEE_FreeTransientObject(sess->key_handle);
        sess->key_handle = TEE_HANDLE_NULL;
    }

    obj_id_sz = params[0].memref.size;
    salt_sz = params[1].memref.size;
    info_sz = params[2].memref.size;
    ikm_sz = AES_128_KEY_SIZE;
    okm_sz = AES_128_KEY_SIZE;

    obj_id = TEE_Malloc(obj_id_sz, 0);
    if (!obj_id)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

    if (salt_sz > 0)
    {
        salt = TEE_Malloc(salt_sz, 0);
        if (!salt)
        {
            res = TEE_ERROR_OUT_OF_MEMORY;
            goto free_mem;
        }
        TEE_MemMove(salt, params[1].memref.buffer, salt_sz);
    }

    if (info_sz > 0)
    {
        info = TEE_Malloc(info_sz, 0);
        if (!info)
        {
            res = TEE_ERROR_OUT_OF_MEMORY;
            goto free_mem;
        }
        TEE_MemMove(info, params[2].memref.buffer, info_sz);
    }

    ikm = TEE_Malloc(ikm_sz, 0);
    okm = TEE_Malloc(okm_sz, 0);
    if (!ikm || !okm)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto free_mem;
    }

    // Load IKM from Secure Storage
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        obj_id, obj_id_sz,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
        &obj
    );
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_OpenPersistentObject failed: 0x%x", res);
        goto free_mem;
    }

    res = TEE_GetObjectInfo1(obj, &obj_info);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_GetObjectInfo1 failed: 0x%x", res);
        goto exit;
    }

    res = TEE_ReadObjectData(obj, ikm, obj_info.dataSize, &read_bytes);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_ReadObjectData failed: 0x%x", res);
        goto exit;
    }

    // Derive Key in HKDF process
    res = TEE_AllocateTransientObject(TEE_TYPE_HKDF_IKM, ikm_sz * 8, &ikm_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate IKM object: 0x%x", res);
        goto exit;
    }

    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_HKDF_IKM, ikm, ikm_sz);
    res = TEE_PopulateTransientObject(ikm_handle, &attrs[0], 1);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to populate IKM: 0x%x", res);
        goto exit;
    }

    res = TEE_AllocateOperation(&op, TEE_ALG_HKDF_SHA256_DERIVE_KEY, TEE_MODE_DERIVE, ikm_sz * 8);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate operation: 0x%x", res);
        goto exit;
    }

    res = TEE_SetOperationKey(op, ikm_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to set operation key: 0x%x", res);
        goto exit;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, okm_sz * 8, &okm_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate OKM object: 0x%x", res);
        goto exit;
    }

    attr_count = 0;
    if (salt && salt_sz > 0)
    {
        TEE_InitRefAttribute(&attrs[attr_count], TEE_ATTR_HKDF_SALT, salt, salt_sz);
        attr_count++;
    }

    if (info && info_sz > 0)
    {
        TEE_InitRefAttribute(&attrs[attr_count], TEE_ATTR_HKDF_INFO, info, info_sz);
        attr_count++;
    }

    TEE_InitValueAttribute(&attrs[attr_count], TEE_ATTR_HKDF_OKM_LENGTH, okm_sz, 0);
    attr_count++;

    res = TEE_DeriveKey(op, attrs, attr_count, okm_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_DeriveKey failed: 0x%x", res);
        goto exit;
    }

    res = TEE_GetObjectBufferAttribute(okm_handle, TEE_ATTR_SECRET_VALUE, okm, &okm_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to get OKM: 0x%x", res);
        goto exit;
    }

    sess->key_size = AES_128_KEY_SIZE;
    sess->algo = TEE_ALG_AES_CMAC;

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, sess->key_size * 8, &sess->key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate session key object: 0x%x", res);
        goto exit;
    }

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, okm, okm_sz);
    res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_PopulateTransientObject failed: 0x%x", res);
        TEE_FreeTransientObject(sess->key_handle);
        sess->key_handle = TEE_HANDLE_NULL;
    }

exit:
    TEE_CloseObject(obj);
    TEE_FreeOperation(op);
    TEE_FreeTransientObject(ikm_handle);
    TEE_FreeTransientObject(okm_handle);

free_mem:
    TEE_Free(obj_id);
    TEE_Free(salt);
    TEE_Free(info);
    TEE_Free(ikm);
    TEE_Free(okm);

    return res;
}

static TEE_Result secoc_sign(uint32_t pt, TEE_Param params[4])
{

}

static TEE_Result secoc_verify(uint32_t pt, TEE_Param params[4])
{

}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd, uint32_t pt, TEE_Param params[4])
{
    switch(cmd)
    {
        case CMD_SHA256:
        {
            return do_sha256(pt, params);
        }
        case CMD_SHA512:
        {
            return do_sha512(pt, params);
        }
        case CMD_AES_PREPARE:
        {
            return alloc_resources(session, pt, params);
        }
        case CMD_AES_CMAC_SIGN:
        {
            return aes_cmac_sign_op(session, pt, params);
        }
        case CMD_AES_CMAC_VERIFY:
        {
            return aes_cmac_verify_op(session, pt, params);
        }
        case CMD_AES_GCM_ENC:
        {
            return aes_gcm_enc_op(session, pt, params);
        }
        case CMD_AES_GCM_DEC:
        {
            return aes_gcm_dec_op(session, pt, params);
        }
        case CMD_HKDF_DERIVE:
        {
            return do_hkdf_derive(pt, params);
        }
        case CMD_SS_KEY_WRITE:
        {
            return write_key_to_ss(pt, params);
        }
        case CMD_SS_KEY_READ:
        {
            return read_key_from_ss(pt, params);
        }
        case CMD_SS_KEY_DELETE:
        {
            return delete_key_from_ss(pt, params);
        }
        case CMD_SECOC_INIT:
        {
            return secoc_init(session, pt, params);
        }
        case CMD_SECOC_SIGN:
        {
            return secoc_sign(session, pt, params);
        }
        case CMD_SECOC_VERIFY:
        {
            return secoc_verify(session, pt, params);
        }
        default:
        {
            EMSG("Command ID 0x%d is not supported", cmd);
            return TEE_ERROR_NOT_SUPPORTED;
        }
    }
}
