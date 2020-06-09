// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_EXCEPTION_H
#define _OE_HOST_EXCEPTION_H

#include <openenclave/bits/types.h>
#include <openenclave/internal/calls.h>

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

/* Check if the current enclave is in  simulation mode. */
bool is_simulate(oe_host_exception_context_t* context);

#endif // _OE_HOST_EXCEPTION_H
