#include <tee_internal_api.h>
#include <tee_api_defines_extensions.h>
#include <keymgmt_ta.h>

TEE_Result TA_CreateEntryPoint(void)
{
    DMSG("KeyMgmt TA Create");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt, TEE_Param params[4], void **session)
{
    (void)pt; (void)params;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
    DMSG("Session %p: release session", session);
}
