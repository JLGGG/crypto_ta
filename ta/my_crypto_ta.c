#include <tee_internal_api.h>
#include <my_crypto_ta.h>
#include <string.h>

TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("TA Create");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt, TEE_Param params[4], void **session)
{
    (void)pt; (void)params; (void)session;
    DMSG("Sessioni Open");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
    (void)session;
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

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd, uint32_t pt, TEE_Param params[4])
{
    (void)session;

    switch(cmd)
    {
        case CMD_SHA256:
            return do_sha256(pt, params);
        default:
            return TEE_ERROR_NOT_SUPPORTED;
    }
}
