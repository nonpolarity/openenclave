// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/registers.h>
#include <openenclave/internal/sgx/td.h>
#include <ucontext.h>
#include "enclave.h"
#include "exception.h"

// SGX hardware exit type, must align with Intel SDM.
#define SGX_EXIT_TYPE_HARDWARE 0x3
#define SGX_EXIT_TYPE_SOFTWARE 0x6

bool is_simulate(oe_host_exception_context_t* context)
{
    uint64_t tcs_address = context->rbx;
    oe_enclave_t* enclave = oe_query_enclave_instance((void*)tcs_address);
    return enclave->simulate;
}

static void _oe_aex_sim(ucontext_t* context, void* host_fs)
{
    sgx_tcs_t* tcs = (sgx_tcs_t*)(context->uc_mcontext.gregs[REG_RBX]);

    //// Update cssa as AEX does.
    tcs->cssa++;

    // This aex is delayed. Change the FS register to host side although this
    // code is already on host side.
    oe_set_fs_register_base(host_fs);
}

static sgx_ssa_gpr_t* _get_ssa_gpr(sgx_tcs_t* tcs)
{
    // why ossa != OE_SSA_FROM_TCS_BYTE_OFFSET?
    uint32_t cssa = tcs->cssa;
    // uint64_t ossa = ((sgx_tcs_t*)tcs_address)->ossa;

    // oe_sgx_td_t* td = (oe_sgx_td_t*)(tcs_address + TD_FROM_TCS);
    uint64_t ssa_frame_size = 0;
    //    uint64_t ssa_frame_size = td->base.__ssa_frame_size;
    if (ssa_frame_size == 0)
    {
        ssa_frame_size = OE_DEFAULT_SSA_FRAME_SIZE;
    }

    uint64_t ssa_base_address = (uint64_t)tcs + OE_SSA_FROM_TCS_BYTE_OFFSET;

    // cssa always points to the unfilled ssa.
    return (
        sgx_ssa_gpr_t*)(ssa_base_address + cssa * ssa_frame_size * OE_PAGE_SIZE - OE_SGX_GPR_BYTE_SIZE);
}

static void _update_ssa_from_context(ucontext_t* context)
{
    sgx_tcs_t* tcs = (sgx_tcs_t*)(context->uc_mcontext.gregs[REG_RBX]);
    sgx_ssa_gpr_t* ssa_gpr = _get_ssa_gpr(tcs);

    // Update gpr.
    ssa_gpr->rax = (uint64_t)(context->uc_mcontext.gregs[REG_RAX]);
    ssa_gpr->rbx = (uint64_t)(context->uc_mcontext.gregs[REG_RBX]);
    ssa_gpr->rcx = (uint64_t)(context->uc_mcontext.gregs[REG_RCX]);
    ssa_gpr->rdx = (uint64_t)(context->uc_mcontext.gregs[REG_RDX]);
    ssa_gpr->rsp = (uint64_t)(context->uc_mcontext.gregs[REG_RSP]);
    ssa_gpr->rbp = (uint64_t)(context->uc_mcontext.gregs[REG_RBP]);
    ssa_gpr->rsi = (uint64_t)(context->uc_mcontext.gregs[REG_RSI]);
    ssa_gpr->rdi = (uint64_t)(context->uc_mcontext.gregs[REG_RDI]);
    ssa_gpr->r8 = (uint64_t)(context->uc_mcontext.gregs[REG_R8]);
    ssa_gpr->r9 = (uint64_t)(context->uc_mcontext.gregs[REG_R9]);
    ssa_gpr->r10 = (uint64_t)(context->uc_mcontext.gregs[REG_R10]);
    ssa_gpr->r11 = (uint64_t)(context->uc_mcontext.gregs[REG_R11]);
    ssa_gpr->r12 = (uint64_t)(context->uc_mcontext.gregs[REG_R12]);
    ssa_gpr->r13 = (uint64_t)(context->uc_mcontext.gregs[REG_R13]);
    ssa_gpr->r14 = (uint64_t)(context->uc_mcontext.gregs[REG_R14]);
    ssa_gpr->r15 = (uint64_t)(context->uc_mcontext.gregs[REG_R15]);
    ssa_gpr->rip = (uint64_t)(context->uc_mcontext.gregs[REG_RIP]);
    ssa_gpr->rflags = (uint64_t)(context->uc_mcontext.gregs[REG_EFL]);

    // This flag is checked by virtual dispacher.
    ssa_gpr->exit_info.as_fields.valid = true;
    ssa_gpr->exit_info.as_fields.exit_type = SGX_EXIT_TYPE_SOFTWARE;
}

static void _update_context_from_ssa(ucontext_t* context)
{
    sgx_tcs_t* tcs = (sgx_tcs_t*)(context->uc_mcontext.gregs[REG_RBX]);
    sgx_ssa_gpr_t* ssa_gpr = _get_ssa_gpr(tcs);

    context->uc_mcontext.gregs[REG_RAX] = (greg_t)ssa_gpr->rax;
    context->uc_mcontext.gregs[REG_RBX] = (greg_t)ssa_gpr->rbx;
    context->uc_mcontext.gregs[REG_RCX] = (greg_t)ssa_gpr->rcx;
    context->uc_mcontext.gregs[REG_RDX] = (greg_t)ssa_gpr->rdx;
    context->uc_mcontext.gregs[REG_RSP] = (greg_t)ssa_gpr->rsp;
    context->uc_mcontext.gregs[REG_RBP] = (greg_t)ssa_gpr->rbp;
    context->uc_mcontext.gregs[REG_RSI] = (greg_t)ssa_gpr->rsi;
    context->uc_mcontext.gregs[REG_RDI] = (greg_t)ssa_gpr->rdi;
    context->uc_mcontext.gregs[REG_R8] = (greg_t)ssa_gpr->r8;
    context->uc_mcontext.gregs[REG_R9] = (greg_t)ssa_gpr->r9;
    context->uc_mcontext.gregs[REG_R10] = (greg_t)ssa_gpr->r10;
    context->uc_mcontext.gregs[REG_R11] = (greg_t)ssa_gpr->r11;
    context->uc_mcontext.gregs[REG_R12] = (greg_t)ssa_gpr->r12;
    context->uc_mcontext.gregs[REG_R13] = (greg_t)ssa_gpr->r13;
    context->uc_mcontext.gregs[REG_R14] = (greg_t)ssa_gpr->r14;
    context->uc_mcontext.gregs[REG_R15] = (greg_t)ssa_gpr->r15;
    context->uc_mcontext.gregs[REG_RIP] = (greg_t)ssa_gpr->rip;
    context->uc_mcontext.gregs[REG_EFL] = (greg_t)ssa_gpr->rflags;
}

static void _oe_eresume_sim(ucontext_t* context, void* enclave_fs)
{
    OE_UNUSED(context);
    //    sgx_tcs_t* tcs = (sgx_tcs_t*)(context->uc_mcontext.gregs[REG_RBX]);

    //    //// Update cssa as AEX does.
    //    tcs->cssa++;

    // Since aex was deferred, eresume must be advanced, to keep the status
    // before and after oe_host_handle_exception_sim consistent.
    // Change the FS register to enclave side although this
    // code is not so close to the boundary.
    oe_set_fs_register_base(enclave_fs);
}

/* Platform neutral exception handler */
uint64_t oe_host_handle_exception_sim(ucontext_t* context)
{
    void* enclave_fs = oe_get_fs_register_base();
    oe_sgx_td_t* td = (oe_sgx_td_t*)enclave_fs;
    void* host_fs = (void*)td->simulate;

    // Simulate the AEX in SGX hardware mode.
    // Copy the data of context into ssa manually.
    _oe_aex_sim(context, host_fs);
    _update_ssa_from_context(context);

    // uint64_t exit_code    = (uint64_t)context->uc_mcontext.gregs[REG_RAX];
    uint64_t tcs_address = (uint64_t)context->uc_mcontext.gregs[REG_RBX];
    // uint64_t exit_address = (uint64_t)context->uc_mcontext.gregs[REG_RIP];

    uint64_t ret = OE_EXCEPTION_CONTINUE_SEARCH;

    // Check if the signal happens inside the enclave.
    if (true)
    {
        // Check if the enclave exception happens inside the first pass
        // exception handler.
        oe_thread_binding_t* thread_data = oe_get_thread_binding();
        if (thread_data->flags & _OE_THREAD_HANDLING_EXCEPTION)
        {
            abort();
        }

        // Call-in enclave to handle the exception.
        oe_enclave_t* enclave = oe_query_enclave_instance((void*)tcs_address);
        if (enclave == NULL)
        {
            abort();
        }

        // Set the flag marks this thread is handling an enclave exception.
        thread_data->flags |= _OE_THREAD_HANDLING_EXCEPTION;

        // Call into enclave first pass exception handler.
        uint64_t arg_out = 0;
        oe_result_t result =
            oe_ecall(enclave, OE_ECALL_VIRTUAL_EXCEPTION_HANDLER, 0, &arg_out);

        // Some info about the exception are updated in SSA.
        // Copy the data back to context manually.
        _update_context_from_ssa(context);

        // Reset the flag
        thread_data->flags &= (~_OE_THREAD_HANDLING_EXCEPTION);
        if (result == OE_OK && arg_out == OE_EXCEPTION_CONTINUE_EXECUTION)
        {
            // This exception has been handled by the enclave. Let's resume.
            ret = OE_EXCEPTION_CONTINUE_EXECUTION;
            goto done;
        }
        else
        {
            // Un-handled enclave exception happened.
            // We continue the exception handler search as if it were a
            // non-enclave exception.
            ret = OE_EXCEPTION_CONTINUE_SEARCH;
            goto done;
        }
    }
    else
    {
        // Not an exclave exception.
        // Continue searching for other handlers.
        ret = OE_EXCEPTION_CONTINUE_SEARCH;
        goto done;
    }

done:
    _oe_eresume_sim(context, host_fs);
    return ret;
}
