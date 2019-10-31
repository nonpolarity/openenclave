// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../asmdefs.h"
#include <openenclave/internal/constants_x64.h>
#include <openenclave/internal/context.inc>

//==============================================================================
//
// void __morestack(
//     [IN] void* tcs,                  /* RDI */
//     [IN] uint64_t aep,               /* RSI */
//     [IN] uint64_t arg1,              /* RDX */
//     [IN] uint64_t arg2,              /* RCX */
//     [OUT] uint64_t* arg3,            /* R8 */
//     [OUT] uint64_t* arg4,            /* R9 */
//     [IN] oe_enclave_t* enclave);       /* on stack */
//
// Registers:
//     RDI   - tcs: thread control structure
//     RSI   - aep: asynchronous execution procedure
//     RDX   - arg1
//     RCX   - arg2
//     R8    - arg3
//     R9    - arg4
//
// N.B: Don't change the function name, otherwise debugger can't work.
// GDB depends on this hardcode function name when does stack walking for split
// stack.
//
// Note that oe_enter is defined to __morestack
//
//==============================================================================


#define ENCLAVE_PARAM (16)(%rbp)

.globl __morestack
.type __morestack, @function
__morestack:
    // Setup stack frame.
    push %rbp
    mov %rsp, %rbp

    // Allocate space for saving registers.
    sub $OE_CONTEXT_SIZE, %rsp

    // Change signature to:
    //  __morestack(ARG1=RDI, ARG2=RSI, TCS=RDX, AEP=RCX, ARG3=R8, ARG4=R9)
    // This closely matches the contract of ENCLU below. Just the TCS needs
    // to be moved to RBX before executing ENCLU.
    xchg %rdi, %rdx
    xchg %rsi, %rcx

    // Save all registers.
    push %rdi
    lea (-OE_CONTEXT_SIZE)(%rbp), %rdi
    call oe_snap_current_context@PLT
    pop %rdi

    // The EENTER(RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2) contract:
    // Input:
    //      RBX=TCS, RCX=AEP, RDI=ARG1, RSI=ARG2,
    //      RBP=Current host stack rbp,
    //      RSP=Current host stack sp.
    //      All other registers are NOT used/ignored.
    // Output:
    //      RDI=ARG1OUT, RSI=ARG2OUT,
    //      RBP is not changed,
    //      RSP might be decreased because of host stack memory allocation.
    //      All other Registers are clobbered.
.execute_eenter:
    mov %rdx, %rbx  // TCS -> RBX

    mov ENCLAVE_PARAM, %r10
    cmpb $0, OE_ENCLAVE_OFFSET_SIMULATE(%r10)
    je .execute_enclu

.execute_enclu_sim:
    // For simulation mode, make the following changes
    mov $0, %rax  // CSSA = 0
    lea .return_address(%rip), %rcx
    mov 72(%rbx), %rdx
    jmp *%rdx

.execute_enclu:
    mov $ENCLU_EENTER, %rax
    ENCLU

.return_address:
    // Save return values.
    push %rdi
    push %rsi

    // Restore all registers.
    lea (-OE_CONTEXT_SIZE)(%rbp), %rdi
    call oe_restore_partial_context@PLT

    // Restore return values.
    pop %rsi
    pop %rdi

    // Check if an OCALL needed to be dispatched.
    mov %rdi, %r10
    shr $48, %r10
    cmpq $OE_OCALL_CODE, %r10
    jne .return_from_ecall

.dispatch_ocall:
    // All parameters for __oe_host_stack_bridge are already in registers except
    // for the final parameter (enclave) that must be pushed onto the stack.
    // Since only one param is going to be pushed, subtract 8 from rsp, so that
    // that stack is 16-byte aligned upon entry to __oe_host_stack_bridge.
    sub $8, %rsp
    mov ENCLAVE_PARAM, %r10
    push %r10
    call __oe_host_stack_bridge@PLT
    add $16, %rsp

    // Restore all registers to original values.
    lea (-OE_CONTEXT_SIZE)(%rbp), %rdi
    call oe_restore_partial_context@PLT

    // __oe_host_stack_bridge returned values in arg3 (r8) and arg4 (r9) which
    // must be passed back to the enclave as arg1 (rdi) and arg2 (rsi).
    mov (%r8), %rdi
    mov (%r9), %rsi

    jmp .execute_eenter

.return_from_ecall:
    // Write results.
    mov %rdi, (%r8)
    mov %rsi, (%r9)

    // Restore stack frame
    mov %rbp, %rsp
    pop %rbp

    ret
.size __morestack, .-__morestack
