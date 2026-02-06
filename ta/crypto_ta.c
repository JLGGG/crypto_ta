#include <tee_internal_api.h>
#include <tee_api_defines_extensions.h>
#include <crypto_ta.h>
#include <string.h>

struct aes_cmac_algo {
    uint32_t algo;
    uint32_t mode;
    uint32_t key_size;
    TEE_OperationHandle op_handle;
    TEE_ObjectHandle key_handle;
};

TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("TA Create");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt, TEE_Param params[4], void **session)
{
    (void)pt; (void)params;
    struct aes_cmac_algo *sess = TEE_Malloc(sizeof(*sess), 0);

    if (!sess)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    sess->key_handle = TEE_HANDLE_NULL;
    sess->op_handle = TEE_HANDLE_NULL;

    *session = sess;
    DMSG("Session %p: newly allocated", *session);

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
    DMSG("Session %p: release session", session);
    struct aes_cmac_algo *sess = session;

    TEE_FreeTransientObject(sess->key_handle);
    TEE_FreeOperation(sess->op_handle);
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
    struct aes_cmac_algo *sess = NULL;
    TEE_Attribute attr = {0};
    TEE_Result res = TEE_ERROR_GENERIC;
    char *key = NULL;
    uint32_t tee_obj_type = TEE_TYPE_AES;
    size_t key_size;

    const uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT);

    DMSG("Session %p: get resources", session);
    sess = session;

    if (param_types != exp_param_types)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    sess->algo = params[0].value.a;
    sess->mode = params[1].value.a;
    sess->key_size = params[2].value.a;

    if (sess->op_handle != TEE_HANDLE_NULL)
    {
        TEE_FreeOperation(sess->op_handle);
        sess->op_handle = TEE_HANDLE_NULL;
    }

    // maxKeySize bits can be performed.
    res = TEE_AllocateOperation(&sess->op_handle, sess->algo, sess->mode, sess->key_size * 8);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate operation");
        goto err;
    }

    if (sess->key_handle != TEE_HANDLE_NULL)
    {
        TEE_FreeTransientObject(sess->key_handle);
        sess->key_handle = TEE_HANDLE_NULL;
    }

    res = TEE_AllocateTransientObject(tee_obj_type, sess->key_size * 8, &sess->key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate transient object");
        goto err;
    }

    key = params[3].memref.buffer;
    key_size = params[3].memref.size;
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_size);
    res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_PopulateTransientObject failed, %d", res);
        goto err;
    }

    res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_SetOperationKey failed %d", res);
        goto err;
    }

    return TEE_SUCCESS;

err:
    TEE_FreeOperation(sess->op_handle);
    sess->op_handle = TEE_HANDLE_NULL;

    TEE_FreeTransientObject(sess->key_handle);
    sess->key_handle = TEE_HANDLE_NULL;

    return res;
}

static TEE_Result aes_cmac_op(void *session, uint32_t pt, TEE_Param params[4])
{
    struct aes_cmac_algo *sess = NULL;
    TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
    void *message = NULL;
    size_t message_size = 0U;
    uint32_t cmac_len = 0U;
    void *b2 = NULL;

    const uint32_t exp_pt = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    DMSG("Session %p: cmac operation", session);
    sess = session;

    if (sess->op_handle == TEE_HANDLE_NULL)
    {
        EMSG("Operation not properly initialized.");
        return TEE_ERROR_BAD_STATE;
    }

    if (pt != exp_pt)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    message = params[0].memref.buffer;
    message_size = params[0].memref.size;
    cmac_len = (uint32_t)params[1].memref.size;

    if (params[1].memref.buffer && params[1].memref.size)
    {
        b2 = TEE_Malloc(params[1].memref.size, 0);
        if (!b2)
        {
            goto out;
        }
    }

    TEE_MACInit(sess->op_handle, NULL, 0);
    res = TEE_MACComputeFinal(sess->op_handle, message, message_size, b2, &cmac_len);
    if (res == TEE_SUCCESS)
    {
        TEE_MemMove(params[1].memref.buffer, b2, cmac_len);
    }

    params[1].memref.size = cmac_len;

out:
    TEE_Free(b2);
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

    // params[0]: IKM (Input key Material) - MEMREF_INPUT
    // params[1]: Salt (can be empty) - MEMREF_INPUT
    // params[2]: Info (can be empty) - MEMREF_INPUT
    // params[3]: OKM (Output Key Material) - MEMREF_OUTPUT

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

    if (salt && salt_size > 0)
    {
        TEE_InitRefAttribute(&attrs[attr_count], TEE_ATTR_HKDF_SALT, salt, salt_size);
        attr_count++;
    }

    if (info && info_size > 0)
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
        case CMD_AES_CMAC_PREPARE:
        {
            return alloc_resources(session, pt, params);
        }
        case CMD_AES_CMAC:
        {
            return aes_cmac_op(session, pt, params);
        }
        case CMD_HKDF_DERIVE:
        {
            return do_hkdf_derive(pt, params);
        }
        default:
        {
            EMSG("Command ID 0x%d is not supported", cmd);
            return TEE_ERROR_NOT_SUPPORTED;
        }
    }
}
