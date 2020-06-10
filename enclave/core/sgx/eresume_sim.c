// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/registers.h>
#include "asmdefs.h"

void eresume_sim(void* addr)
{
    oe_set_fs_register_base(addr);
}
