// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/constants_x64.h>
#include <openenclave/internal/context.h>
#include <openenclave/internal/cpuid.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/jump.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include "asmdefs.h"
#include "cpuid.h"
#include "init.h"
#include "td.h"

#if defined(__linux__)
#include <asm/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <Windows.h>
#include <immintrin.h>
#endif

#include <assert.h>
#include <stdio.h>

#include <openenclave/internal/registers.h>

void _set_fs_register_base(const void* ptr)
{
#if defined(__linux__)
    syscall(__NR_arch_prctl, ARCH_SET_FS, ptr);
#elif defined(_WIN32)
    _writefsbase_u64((uint64_t)ptr);
#endif
}

void eresume_sim(oe_context_t* oe_context)
{
    sgx_tcs_t* sgx_tcs = (sgx_tcs_t*)(oe_context->rbx);
    oe_sgx_td_t* td = td_from_tcs(sgx_tcs);

    _set_fs_register_base((const void*)td);
    oe_continue_execution(oe_context);

    // Code should never run to here.
    oe_abort();
    return;
}
