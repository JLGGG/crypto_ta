#include <tee_internal_api.h>
#include <keymgmt_ta.h>
#include <string.h>

TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("KeyMgmt TA Create");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt, TEE_Param params[4], void **session)
{
    (void)pt; (void)params; (void)session;

    DMSG("KeyMgmt TA Session Open");

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
    DMSG("Session %p: release session", session);
}

static TEE_Result km_keygen(uint32_t pt, TEE_Param params[4])
{
    TEE_Result res;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle pub_obj = TEE_HANDLE_NULL;
    TEE_ObjectHandle priv_obj = TEE_HANDLE_NULL;
    TEE_Attribute attr;
    char *key_id = NULL;
    size_t key_id_sz = 0U;
    uint32_t flags;

    char pub_x[32] = {0};
    char pub_y[32] = {0};
    char pub_key[64] = {0};
    char priv_key[32] = {0};
    char pub_key_id[64];
    char priv_key_id[64];
    uint32_t pub_x_len = 32U;
    uint32_t pub_y_len = 32U;
    uint32_t priv_key_len = 32U;

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    key_id_sz = params[0].memref.size;
    key_id = TEE_Malloc(key_id_sz, 0);
    if (key_id == NULL)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(key_id, params[0].memref.buffer, key_id_sz);

    res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256U, &key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate KEY object: 0x%x", res);
        goto clean;
    }

    TEE_InitValueAttribute(&attr, TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0U);
    TEE_GenerateKey(key_handle, 256U, &attr, 1U);

    res = TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_ECC_PUBLIC_VALUE_X, pub_x, &pub_x_len);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to get PUB_X: 0x%x", res);
        goto clean;
    }

    res = TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_ECC_PUBLIC_VALUE_Y, pub_y, &pub_y_len);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to get PUB_Y: 0x%x", res);
        goto clean;
    }
    TEE_MemMove(pub_key, pub_x, 32U);
    TEE_MemMove(pub_key + 32U, pub_y, 32U);

    res = TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_ECC_PRIVATE_VALUE, priv_key, &priv_key_len);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to get PRIV_KEY: 0x%x", res);
        goto clean;
    }

    flags = TEE_DATA_FLAG_ACCESS_READ |
            TEE_DATA_FLAG_ACCESS_WRITE |
            TEE_DATA_FLAG_ACCESS_WRITE_META |
            TEE_DATA_FLAG_OVERWRITE;

    TEE_MemMove(pub_key_id, key_id, key_id_sz);
    TEE_MemMove(pub_key_id + key_id_sz, "_pub", 4U);
    size_t pub_key_id_sz = key_id_sz + 4U;

    TEE_MemMove(priv_key_id, key_id, key_id_sz);
    TEE_MemMove(priv_key_id + key_id_sz, "_priv", 5U);
    size_t priv_key_id_sz = key_id_sz + 5U;
    
    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,
        pub_key_id, pub_key_id_sz,
        flags,
        TEE_HANDLE_NULL,
        pub_key, 64,
        &pub_obj
    );
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_CreatePersistentObject failed: 0x%x", res);
        goto clean;
    }
    TEE_CloseObject(pub_obj);

    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,
        priv_key_id, priv_key_id_sz,
        flags,
        TEE_HANDLE_NULL,
        priv_key, 32,
        &priv_obj
    );
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_CreatePersistentObject failed: 0x%x", res);
        goto clean;
    }
    TEE_CloseObject(priv_obj);

clean:
    TEE_Free(key_id);
    TEE_FreeTransientObject(key_handle);
    return res;
}

static TEE_Result km_get_pubkey(uint32_t pt, TEE_Param params[4])
{
    TEE_Result res;
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    TEE_ObjectInfo obj_info = {0U};
    char *obj_id = NULL;
    size_t obj_id_sz = 0U;
    char *data = NULL;
    size_t data_sz = 0U;
    uint32_t read_bytes = 0U;
    char pub_key_id[64];

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    obj_id_sz = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_sz, 0U);
    if (obj_id == NULL)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

    data_sz = params[1].memref.size;
    data = TEE_Malloc(data_sz, 0U);
    if (data == NULL)
    {
        TEE_Free(obj_id);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(pub_key_id, obj_id, obj_id_sz);
    TEE_MemMove(pub_key_id + obj_id_sz, "_pub", 4U);
    size_t pub_key_id_sz = obj_id_sz + 4U;

    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        pub_key_id, pub_key_id_sz,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
        &obj
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_OpenPersistentObject failed: 0x%x", res);
        TEE_Free(obj_id);
        TEE_Free(data);
        return res;
    }

    res = TEE_GetObjectInfo1(obj, &obj_info);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_GetObjectInfo1 failed: 0x%x", res);
        goto clean;
    }

    res = TEE_ReadObjectData(obj, data, obj_info.dataSize, &read_bytes);
    if (res == TEE_SUCCESS)
    {
        TEE_MemMove(params[1].memref.buffer, data, read_bytes);
        params[1].memref.size = read_bytes;
    }
    else
    {
        EMSG("TEE_ReadObjectData failed: 0x%x", res);
    }

clean:
    TEE_CloseObject(obj);
    TEE_Free(obj_id);
    TEE_Free(data);
    return res;
}

static TEE_Result km_sign(uint32_t pt, TEE_Param params[4])
{
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_ObjectInfo object_info = {0U};
    TEE_Attribute attrs[2];
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t attr_count = 0U;
    char *key_id = NULL;
    size_t key_id_sz = 0U;
    char *digest = NULL;
    size_t digest_sz = 0U;
    char *signature = NULL;
    size_t signature_sz = 0U;
    char priv_key_id[64];
    char priv_key[32] = {0U};
    size_t priv_key_id_sz = 0U;
    uint32_t read_bytes = 0U;

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE
    );

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    key_id_sz = params[0].memref.size;
    key_id = TEE_Malloc(key_id_sz, 0);
    if (key_id == NULL)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(key_id, params[0].memref.buffer, key_id_sz);

    digest_sz = params[1].memref.size;
    digest = TEE_Malloc(digest_sz, 0);
    if (digest == NULL)
    {
        TEE_Free(key_id);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(digest, params[1].memref.buffer, digest_sz);

    signature_sz = params[2].memref.size;
    signature = TEE_Malloc(signature_sz, 0);
    if (signature == NULL)
    {
        TEE_Free(key_id);
        TEE_Free(digest);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(priv_key_id, key_id, key_id_sz);
    TEE_MemMove(priv_key_id + key_id_sz, "_priv", 5U);
    priv_key_id_sz = key_id_sz + 5U;

    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        priv_key_id, priv_key_id_sz,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
        &object
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_OpenPersistentObject failed: 0x%x", res);
        TEE_Free(key_id);
        TEE_Free(digest);
        TEE_Free(signature);
        return res;
    }

    res = TEE_GetObjectInfo1(object, &object_info);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_GetObjectInfo1 failed: 0x%x", res);
        goto clean;
    }

    res = TEE_ReadObjectData(object, priv_key, object_info.dataSize, &read_bytes);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_ReadObjectData failed: 0x%x", res);
        goto clean;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256U, &key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_AllocateTransientObject failed: 0x%x", res);
        goto clean;
    }

    TEE_InitRefAttribute(&attrs[attr_count], TEE_ATTR_ECC_PRIVATE_VALUE, priv_key, read_bytes);
    attr_count++;
    TEE_InitValueAttribute(&attrs[attr_count], TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0U);
    attr_count++;

    res = TEE_PopulateTransientObject(key_handle, attrs, attr_count);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_PopulateTransientObject failed: 0x%x", res);
        goto clean;
    }

    res = TEE_AllocateOperation(&op, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, 256U);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_AllocateOperation failed: 0x%x", res);
        goto clean;
    }

    res = TEE_SetOperationKey(op, key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_SetOperationKey failed: 0x%x", res);
        goto clean;
    }

    uint32_t sig_len = signature_sz;
    res = TEE_AsymmetricSignDigest(op, NULL, 0U, digest, digest_sz, signature, &sig_len);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_AsymmetricSignDigest failed: 0x%x", res);
    }
    else
    {
        TEE_MemMove(params[2].memref.buffer, signature, sig_len);
        params[2].memref.size = sig_len;
    }

clean:
    TEE_CloseObject(object);
    TEE_FreeTransientObject(key_handle);
    TEE_FreeOperation(op);
    TEE_Free(key_id);
    TEE_Free(digest);
    TEE_Free(signature);
    return res;
}

static TEE_Result km_delete_key(uint32_t pt, TEE_Param params[4])
{
    TEE_Result res;
    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    char *key_id = NULL;
    size_t key_id_sz = 0U;
    char pub_key_id[64];
    char priv_key_id[64];
    size_t pub_key_id_sz = 0U;
    size_t priv_key_id_sz = 0U;
    uint8_t delete_result = 0U;

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    key_id_sz = params[0].memref.size;
    key_id = TEE_Malloc(key_id_sz, 0U);
    if (!key_id)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(key_id, params[0].memref.buffer, key_id_sz);

    TEE_MemMove(pub_key_id, key_id, key_id_sz);
    TEE_MemMove(pub_key_id + key_id_sz, "_pub", 4U);
    pub_key_id_sz = key_id_sz + 4U;

    TEE_MemMove(priv_key_id, key_id, key_id_sz);
    TEE_MemMove(priv_key_id + key_id_sz, "_priv", 5U);
    priv_key_id_sz = key_id_sz + 5U;

    object = TEE_HANDLE_NULL;
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        pub_key_id, pub_key_id_sz,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META,
        &object
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_OpenPersistentObject failed: 0x%x", res);
        goto exit;
    }
    else
    {
        delete_result += 1U;
    }
    TEE_CloseAndDeletePersistentObject1(object);

    object = TEE_HANDLE_NULL;
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        priv_key_id, priv_key_id_sz,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META,
        &object
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_OpenPersistentObject failed: 0x%x", res);
        goto exit;
    }
    else
    {
        delete_result += 1U;
    }
    TEE_CloseAndDeletePersistentObject1(object);

exit:
    params[1].value.a = (delete_result == 2U) ? TEE_SUCCESS : TEE_ERROR_STORAGE_NOT_AVAILABLE;
    TEE_Free(key_id);
    return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd, uint32_t pt, TEE_Param params[4])
{
    (void)session;

    switch(cmd)
    {
        case KM_CMD_KEYGEN:
        {
            return km_keygen(pt, params);
        }
        case KM_CMD_GET_PUBKEY:
        {
            return km_get_pubkey(pt, params);
        }
        case KM_CMD_SIGN:
        {
            return km_sign(pt, params);
        }
        case KM_CMD_DELETE_KEY:
        {
            return km_delete_key(pt, params);
        }
        default:
        {
            EMSG("Command ID 0x%d is not supported", cmd);
            return TEE_ERROR_NOT_SUPPORTED;
        }
    }
}
