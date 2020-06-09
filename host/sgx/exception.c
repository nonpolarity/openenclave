// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "exception.h"
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <stdio.h>
#include "asmdefs.h"
#include "enclave.h"

/**
 * Relevant definitions from asmdefs.h copied locally
 * since asmdefs.h is too linux specific at the moment.
 */
#define ENCLU_ERESUME 3

bool is_simulate(oe_host_exception_context_t* context)
{
    uint64_t tcs_address = context->rbx;
    oe_enclave_t* enclave = oe_query_enclave_instance((void*)tcs_address);
    return enclave->simulate;
}

oe_enclave_t* oe_query_enclave_instance(void* tcs);

/* Platform neutral exception handler */
uint64_t oe_host_handle_exception(oe_host_exception_context_t* context)
{
    uint64_t exit_code = context->rax;
    uint64_t tcs_address = context->rbx;
    sgx_tcs_t* tcs = (sgx_tcs_t*)tcs_address;
    tcs_address = (uint64_t)tcs;
    uint64_t exit_address = context->rip;

    // Call-in enclave to handle the exception.
    oe_enclave_t* enclave = oe_query_enclave_instance((void*)tcs_address);
    if (enclave == NULL)
    {
        abort();
    }

    // Check if the enclave exception happens inside the first pass
    // exception handler.
    oe_thread_binding_t* thread_data;
    if (!enclave->simulate)
    {
        thread_data = oe_get_thread_binding();
    }
    else
    {
        thread_data = oe_get_thread_binding_sim();
    }

    if (thread_data->flags & _OE_THREAD_HANDLING_EXCEPTION)
    {
        abort();
    }

    // Check if the signal happens inside the enclave.
    if (((exit_address == OE_AEP_ADDRESS) && (exit_code == ENCLU_ERESUME)) ||
        enclave->simulate)
    {
        // Set the flag marks this thread is handling an enclave exception.
        thread_data->flags |= _OE_THREAD_HANDLING_EXCEPTION;

        // Call into enclave first pass exception handler.
        uint64_t arg_out = 0;
        oe_result_t result =
            oe_ecall(enclave, OE_ECALL_VIRTUAL_EXCEPTION_HANDLER, 0, &arg_out);

        // Reset the flag
        thread_data->flags &= (~_OE_THREAD_HANDLING_EXCEPTION);
        if (result == OE_OK && arg_out == OE_EXCEPTION_CONTINUE_EXECUTION)
        {
            // This exception has been handled by the enclave. Let's resume.
            return OE_EXCEPTION_CONTINUE_EXECUTION;
        }
        else
        {
            // Un-handled enclave exception happened.
            // We continue the exception handler search as if it were a
            // non-enclave exception.
            return OE_EXCEPTION_CONTINUE_SEARCH;
        }
    }
    else
    {
        // Not an exclave exception.
        // Continue searching for other handlers.
        return OE_EXCEPTION_CONTINUE_SEARCH;
    }
}
