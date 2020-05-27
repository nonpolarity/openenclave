// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/registers.h>
#include <openenclave/internal/sgx/td.h>
#include "enclave.h"

oe_thread_binding_t* oe_get_thread_binding_sim()
{
    void* enclave_fs = oe_get_fs_register_base();
    oe_sgx_td_t* td = (oe_sgx_td_t*)enclave_fs;
    void* host_fs = (void*)td->simulate;

    oe_set_fs_register_base(host_fs);

    oe_thread_binding_t* thread_data = oe_get_thread_binding();

    oe_set_fs_register_base(enclave_fs);

    return thread_data;
}
