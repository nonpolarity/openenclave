// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/advanced/allocator.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>

#ifdef OE_USE_DEBUG_oe_debug_malloc

#include <openenclave/advanced/debugmalloc.h>

#define oe_debug_malloc oe_debug_malloc
#define oe_debug_free oe_debug_free
#define oe_debug_calloc oe_debug_calloc
#define oe_debug_realloc oe_debug_realloc
#define oe_debug_posix_memalign oe_debug_posix_memalign
#define oe_debug_malloc_usable_size oe_debug_malloc_usable_size

#else

#define oe_debug_malloc oe_allocator_malloc
#define oe_debug_free oe_allocator_free
#define oe_debug_calloc oe_allocator_calloc
#define oe_debug_realloc oe_allocator_realloc
#define oe_debug_posix_memalign oe_allocator_posix_memalign
#define oe_debug_malloc_usable_size oe_allocator_malloc_usable_size

#endif

/* If true, disable the debug malloc checking */
bool oe_disable_debug_malloc_check;

static oe_allocation_failure_callback_t _failure_callback;

void oe_set_allocation_failure_callback(
    oe_allocation_failure_callback_t function)
{
    _failure_callback = function;
}

void* oe_malloc(size_t size)
{
    void* p = oe_debug_malloc(size);

    if (!p && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

void oe_free(void* ptr)
{
    oe_debug_free(ptr);
}

void* oe_calloc(size_t nmemb, size_t size)
{
    void* p = oe_debug_calloc(nmemb, size);

    if (!p && nmemb && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, nmemb * size);
    }

    return p;
}

void* oe_realloc(void* ptr, size_t size)
{
    void* p = oe_debug_realloc(ptr, size);

    if (!p && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

void* oe_memalign(size_t alignment, size_t size)
{
    void* ptr = NULL;

    // The only difference between posix_memalign and the obsolete memalign is
    // that posix_memalign requires alignment to be a multiple of sizeof(void*).
    // Adjust the alignment if needed.
    alignment = oe_round_up_to_multiple(alignment, sizeof(void*));

    oe_posix_memalign(&ptr, alignment, size);
    return ptr;
}

int oe_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    int rc = oe_debug_posix_memalign(memptr, alignment, size);

    if (rc != 0 && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return rc;
}

size_t oe_malloc_usable_size(void* ptr)
{
    return oe_debug_malloc_usable_size(ptr);
}
