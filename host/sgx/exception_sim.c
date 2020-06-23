// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/registers.h>
#include <openenclave/internal/sgx/td.h>
#include <signal.h>
#if defined(__linux__)
#include <ucontext.h>
#endif
#include "enclave.h"
#include "exception.h"

bool is_simulation(oe_host_exception_context_t* context)
{
    uint64_t tcs = context->rbx;
    oe_enclave_t* enclave = oe_query_enclave_instance((void*)tcs);
    return enclave->simulate;
}

static void _oe_aex_sim(sgx_tcs_t* tcs, oe_enclave_t* enclave)
{
    // Update cssa as AEX does in real mode.
    tcs->cssa++;

    // Change the FS/GS segment registers to host side.
    oe_set_fs_register_base((const void*)(enclave->host_fsbase));
    oe_set_gs_register_base((const void*)(enclave->host_gsbase));
}

static void _oe_eresume_sim(sgx_tcs_t* tcs, oe_enclave_t* enclave)
{
    // Update cssa as ERESUME does in real mode.
    tcs->cssa--;

    // Change the FS/GS segment registers to enclave side.
    uint64_t enclave_start = enclave->addr;
    uint64_t enclave_fsbase = enclave_start + tcs->fsbase;
    uint64_t enclave_gsbase = enclave_start + tcs->gsbase;
    oe_set_fs_register_base((const void*)enclave_fsbase);
    oe_set_gs_register_base((const void*)enclave_gsbase);
}

static sgx_ssa_gpr_t* _get_ssa_gpr(sgx_tcs_t* tcs)
{
    uint32_t cssa = tcs->cssa;
    oe_sgx_td_t* td =
        (oe_sgx_td_t*)((uint8_t*)tcs + OE_TD_FROM_TCS_BYTE_OFFSET);
    uint64_t ssa_frame_size = td->base.__ssa_frame_size;
    if (ssa_frame_size == 0)
    {
        ssa_frame_size = OE_DEFAULT_SSA_FRAME_SIZE;
    }

    uint64_t ssa_base_address = (uint64_t)tcs + OE_SSA_FROM_TCS_BYTE_OFFSET;

    // cssa always points to the unfilled ssa.
    return (
        sgx_ssa_gpr_t*)(ssa_base_address + cssa * ssa_frame_size * OE_PAGE_SIZE - OE_SGX_GPR_BYTE_SIZE);
}
#if defined(_WIN32)
static void _update_ssa_from_context(PCONTEXT context)
{
    sgx_tcs_t* tcs = (sgx_tcs_t*)(context->Rbx);
    sgx_ssa_gpr_t* ssa_gpr = _get_ssa_gpr(tcs);

    // Update gpr.
    ssa_gpr->rax = context->Rax;
    ssa_gpr->rbx = context->Rbx;
    ssa_gpr->rcx = context->Rcx;
    ssa_gpr->rdx = context->Rdx;
    ssa_gpr->rsp = context->Rsp;
    ssa_gpr->rbp = context->Rbp;
    ssa_gpr->rsi = context->Rsi;
    ssa_gpr->rdi = context->Rdi;
    ssa_gpr->r8 = context->R8;
    ssa_gpr->r9 = context->R9;
    ssa_gpr->r10 = context->R10;
    ssa_gpr->r11 = context->R11;
    ssa_gpr->r12 = context->R12;
    ssa_gpr->r13 = context->R13;
    ssa_gpr->r14 = context->R14;
    ssa_gpr->r15 = context->R15;
    ssa_gpr->rip = context->Rip;
    ssa_gpr->rflags = context->EFlags;

    // This flag is checked by virtual dispacher.
    ssa_gpr->exit_info.as_fields.valid = true;
}

static void _update_sgx_vector(
    PCONTEXT context,
    PEXCEPTION_RECORD exceptionrecord)
{
    // Hardcode here must match g_vector_to_exception_code_mapping[] in
    // enclave/core/sgx/exception.c
    uint32_t sgx_vector = OE_EXCEPTION_UNKNOWN;
    DWORD exceptioncode = exceptionrecord->ExceptionCode;
    switch (exceptioncode)
    {
        case EXCEPTION_INT_DIVIDE_BY_ZERO: // OE_EXCEPTION_DIVIDE_BY_ZERO
        case EXCEPTION_FLT_DIVIDE_BY_ZERO: // OE_EXCEPTION_DIVIDE_BY_ZERO
            sgx_vector = 0;
            break;
        case EXCEPTION_BREAKPOINT: // OE_EXCEPTION_BREAKPOIN
            sgx_vector = 3;
            break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: // OE_EXCEPTION_BOUND_OUT_OF_RANGE
            sgx_vector = 5;
            break;
        case EXCEPTION_ILLEGAL_INSTRUCTION: // OE_EXCEPTION_ILLEGAL_INSTRUCTION
            sgx_vector = 6;
            break;
        case OE_EXCEPTION_ACCESS_VIOLATION: // OE_EXCEPTION_ACCESS_VIOLATION
            sgx_vector = 13;
            break;
        case EXCEPTION_IN_PAGE_ERROR: // OE_EXCEPTION_PAGE_FAULT
            sgx_vector = 14;
            break;
        case EXCEPTION_DATATYPE_MISALIGNMENT: // OE_EXCEPTION_MISALIGNMENT
            sgx_vector = 17;
            break;
    }

    sgx_tcs_t* tcs = (sgx_tcs_t*)(context->Rbx);
    sgx_ssa_gpr_t* ssa_gpr = _get_ssa_gpr(tcs);
    ssa_gpr->exit_info.as_fields.vector = sgx_vector;
}

static void _update_context_from_ssa(PCONTEXT context)
{
    sgx_tcs_t* tcs = (sgx_tcs_t*)(context->Rbx);
    sgx_ssa_gpr_t* ssa_gpr = _get_ssa_gpr(tcs);

    context->Rax = ssa_gpr->rax;
    context->Rbx = ssa_gpr->rbx;
    context->Rcx = ssa_gpr->rcx;
    context->Rdx = ssa_gpr->rdx;
    context->Rsp = ssa_gpr->rsp;
    context->Rbp = ssa_gpr->rbp;
    context->Rsi = ssa_gpr->rsi;
    context->Rdi = ssa_gpr->rdi;
    context->R8 = ssa_gpr->r8;
    context->R9 = ssa_gpr->r9;
    context->R10 = ssa_gpr->r10;
    context->R11 = ssa_gpr->r11;
    context->R12 = ssa_gpr->r12;
    context->R13 = ssa_gpr->r13;
    context->R14 = ssa_gpr->r14;
    context->R15 = ssa_gpr->r15;
    context->Rip = ssa_gpr->rip;
    context->EFlags = (DWORD)ssa_gpr->rflags;
}

#else
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
}

static void _update_sgx_vector(ucontext_t* context, int sig_num)
{
    // Hardcode here must match g_vector_to_exception_code_mapping[] in
    // enclave/core/sgx/exception.c
    uint32_t sgx_vector = OE_EXCEPTION_UNKNOWN;
    switch (sig_num)
    {
        case SIGFPE: // OE_EXCEPTION_DIVIDE_BY_ZERO
            sgx_vector = 0;
            break;
        case SIGTRAP: // OE_EXCEPTION_BREAKPOIN
            sgx_vector = 3;
            break;
        case SIGILL: // OE_EXCEPTION_ILLEGAL_INSTRUCTION
            sgx_vector = 6;
            break;
        case SIGSEGV: // OE_EXCEPTION_ACCESS_VIOLATION
            sgx_vector = 13;
            break;
        case SIGBUS: // OE_EXCEPTION_MISALIGNMENT
            sgx_vector = 17;
            break;
    }

    sgx_tcs_t* tcs = (sgx_tcs_t*)(context->uc_mcontext.gregs[REG_RBX]);
    sgx_ssa_gpr_t* ssa_gpr = _get_ssa_gpr(tcs);
    ssa_gpr->exit_info.as_fields.vector = sgx_vector;
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
#endif
/* Platform dependent exception handler */
#if defined(_WIN32)
uint64_t oe_host_handle_exception_sim(
    struct _EXCEPTION_POINTERS* exception_pointers)
{
    PCONTEXT context = exception_pointers->ContextRecord;
    PEXCEPTION_RECORD exceptionrecord = exception_pointers->ExceptionRecord;

    sgx_tcs_t* tcs = (sgx_tcs_t*)(context->Rbx);
#else
uint64_t oe_host_handle_exception_sim(ucontext_t* context, int sig_num)
{
    sgx_tcs_t* tcs = (sgx_tcs_t*)(context->uc_mcontext.gregs[REG_RBX]);
#endif
    uint64_t ret = OE_EXCEPTION_CONTINUE_SEARCH;

    oe_enclave_t* enclave = oe_query_enclave_instance((void*)tcs);
    if (enclave == NULL)
    {
        goto done;
    }

    uint64_t enclave_start = enclave->addr;
    uint64_t enclave_end = enclave->addr + enclave->size;
#if defined(_WIN32)
    uint64_t rip = (uint64_t)(context->Rip);
#else
    uint64_t rip = (uint64_t)(context->uc_mcontext.gregs[REG_RIP]);
#endif
    if (rip >= enclave_start && rip < enclave_end)
    {
        // Simulate the AEX in SGX hardware mode.
        // Copy the data of context into ssa manually.
        _oe_aex_sim(tcs, enclave);
        _update_ssa_from_context(context);
#if defined(_WIN32)
        _update_sgx_vector(context, exceptionrecord);
#else
        _update_sgx_vector(context, sig_num);
#endif
        // Check if the enclave exception happens inside the first pass
        // exception handler.
        oe_thread_binding_t* thread_data = oe_get_thread_binding();
        if (thread_data->flags & _OE_THREAD_HANDLING_EXCEPTION)
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
        }
        else
        {
            // Unhandled enclave exception happened.
            // We continue the exception handler search as if it were a
            // non-enclave exception.
            ret = OE_EXCEPTION_CONTINUE_SEARCH;
        }

        // Simulate the ERESUME in SGX hardware mode.
        _oe_eresume_sim(tcs, enclave);
    }
    else
    {
        // Not an exclave exception.
        // Continue searching for other handlers.
        ret = OE_EXCEPTION_CONTINUE_SEARCH;
    }

done:
    return ret;
}
