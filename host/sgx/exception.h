// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_EXCEPTION_H
#define _OE_HOST_EXCEPTION_H

#include <openenclave/bits/types.h>
#include <openenclave/internal/calls.h>
#if defined(_WIN32)
#else
#include <ucontext.h>
#endif

typedef struct _host_exception_context
{
    uint64_t rax;
    uint64_t rbx;
    uint64_t rip;
} oe_host_exception_context_t;

/* Initialize the exception processing. */
void oe_initialize_host_exception(void);

/* Platform neutral exception handler */
uint64_t oe_host_handle_exception(oe_host_exception_context_t* context);

#if defined(_WIN32)
#else
/* Exception handler in simulation mode on Linux */
uint64_t oe_host_handle_exception_sim(ucontext_t* context, int sig_num);

/* Check if the current enclave is in  simulation mode. */
bool is_simulate(oe_host_exception_context_t* context);
#endif

#endif // _OE_HOST_EXCEPTION_H
