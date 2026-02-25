#include "include/tee_test.h"

int main(int argc, char *argv[])
{
    uint8_t res = 0U;

    res = tee_test_run();

    if (res != 0)
    {
        printf("Crypto TEE Tests fail\n");
    }

    return 0;
}
