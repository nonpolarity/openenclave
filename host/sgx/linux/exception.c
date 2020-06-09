// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../exception.h"
#include <assert.h>
#include <dlfcn.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/registers.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>
#include "../asmdefs.h"
#include "../enclave.h"

#define PAGE_SIZE 4096
#define TD_FROM_TCS (5 * PAGE_SIZE)
#define SGX_EXIT_TYPE_SOFTWARE 0x6

#if !defined(_NSIG) && defined(_SIG_MAXSIG)
#define _NSIG (_SIG_MAXSIG - 1)
#endif

static struct sigaction g_previous_sigaction[_NSIG];
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

static void oe_aex_sim(ucontext_t* context)
{
    sgx_tcs_t* tcs = (sgx_tcs_t*)(context->uc_mcontext.gregs[REG_RBX]);

    //// Update cssa as AEX does.
    tcs->cssa++;
}
static void update_ssa_from_context(ucontext_t* context)
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

// static void update_context_from_ssa(ucontext_t* context)
//{
//    sgx_tcs_t* tcs = (sgx_tcs_t*)(context->uc_mcontext.gregs[REG_RBX]);
//    sgx_ssa_gpr_t* ssa_gpr = _get_ssa_gpr(tcs);
//    context->uc_mcontext.gregs[REG_RIP] = (greg_t)(ssa_gpr->rip);
//}

static void update_context_from_ssa(ucontext_t* context)
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

static void _host_signal_handler(
    int sig_num,
    siginfo_t* sig_info,
    void* sig_data)
{
    ucontext_t* context = (ucontext_t*)sig_data;
    oe_host_exception_context_t host_context = {0};
    host_context.rax = (uint64_t)context->uc_mcontext.gregs[REG_RAX];
    host_context.rbx = (uint64_t)context->uc_mcontext.gregs[REG_RBX];
    host_context.rip = (uint64_t)context->uc_mcontext.gregs[REG_RIP];

    sgx_tcs_t* tcs = (sgx_tcs_t*)host_context.rbx;
    host_context.rbx = (uint64_t)tcs;

    if (is_simulate(&host_context))
    {
        oe_aex_sim(context);
        update_ssa_from_context(context);
    }

    // Call platform neutral handler.
    uint64_t action = oe_host_handle_exception(&host_context);

    if (action == OE_EXCEPTION_CONTINUE_EXECUTION)
    {
        // Exception has been handled.
        // In simulation mode we need to exec oe_exception_dispatcher().
        if (is_simulate(&host_context))
        {
            update_context_from_ssa(context);
        }

        return;
    }
    else if (g_previous_sigaction[sig_num].sa_handler == SIG_DFL)
    {
        // If not an enclave exception, and no valid previous signal handler is
        // set, raise it again, and let the default signal handler handle it.
        signal(sig_num, SIG_DFL);
        raise(sig_num);
    }
    else
    {
        // If not an enclave exception, and there is old signal handler, we need
        // to transfer the signal to the old signal handler.
        if (!(g_previous_sigaction[sig_num].sa_flags & SA_NODEFER))
        {
            sigaddset(&g_previous_sigaction[sig_num].sa_mask, sig_num);
        }

        sigset_t current_set;
        pthread_sigmask(
            SIG_SETMASK, &g_previous_sigaction[sig_num].sa_mask, &current_set);

        // Call sa_handler or sa_sigaction based on the flags.
        if (g_previous_sigaction[sig_num].sa_flags & SA_SIGINFO)
        {
            g_previous_sigaction[sig_num].sa_sigaction(
                sig_num, sig_info, sig_data);
        }
        else
        {
            g_previous_sigaction[sig_num].sa_handler(sig_num);
        }

        pthread_sigmask(SIG_SETMASK, &current_set, NULL);

        // If the g_previous_sigaction set SA_RESETHAND, it will break the chain
        // which means g_previous_sigaction->next_old_sigact will not be called.
        // This signal handler is not responsible for that, it just follows what
        // the OS does on SA_RESETHAND.
        if (g_previous_sigaction[sig_num].sa_flags & (int)SA_RESETHAND)
            g_previous_sigaction[sig_num].sa_handler = SIG_DFL;
    }

    return;
}

static void _register_signal_handlers(void)
{
    struct sigaction sig_action;

    // Set the signal handler.
    memset(&sig_action, 0, sizeof(sig_action));
    sig_action.sa_sigaction = _host_signal_handler;

    // Use sa_sigaction instead of sa_handler, allow catching the same signal as
    // the one you're currently handling, and automatically restart the system
    // call that interrupted the signal.
    sig_action.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;

    // Should honor the current signal masks.
    sigemptyset(&sig_action.sa_mask);
    if (sigprocmask(SIG_SETMASK, NULL, &sig_action.sa_mask) != 0)
    {
        abort();
    }

    // Unmask the signals we want to receive.
    sigdelset(&sig_action.sa_mask, SIGSEGV);
    sigdelset(&sig_action.sa_mask, SIGFPE);
    sigdelset(&sig_action.sa_mask, SIGILL);
    sigdelset(&sig_action.sa_mask, SIGBUS);
    sigdelset(&sig_action.sa_mask, SIGTRAP);

    // Set the signal handlers, and store the previous signal action into a
    // global array.
    if (sigaction(SIGSEGV, &sig_action, &g_previous_sigaction[SIGSEGV]) != 0)
    {
        abort();
    }

    if (sigaction(SIGFPE, &sig_action, &g_previous_sigaction[SIGFPE]) != 0)
    {
        abort();
    }

    if (sigaction(SIGILL, &sig_action, &g_previous_sigaction[SIGILL]) != 0)
    {
        abort();
    }

    if (sigaction(SIGBUS, &sig_action, &g_previous_sigaction[SIGBUS]) != 0)
    {
        abort();
    }

    if (sigaction(SIGTRAP, &sig_action, &g_previous_sigaction[SIGTRAP]) != 0)
    {
        abort();
    }

    return;
}

// The exception only need to be initialized once per process.
void oe_initialize_host_exception()
{
    _register_signal_handlers();
}
