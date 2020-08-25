// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/advanced/malloctoggle.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>

#ifdef OE_USE_DEBUG_oe_allocator_malloc

#include "debugmalloc.h"

#define oe_allocator_malloc oe_debug_malloc
#define FREE oe_debug_free
#define CALLOC oe_debug_calloc
#define REALLOC oe_debug_realloc
#define POSIX_MEMALIGN oe_debug_posix_memalign
#define oe_allocator_malloc_USABLE_SIZE oe_debug_malloc_usable_size

#else

#define oe_allocator_malloc oe_allocator_malloc
#define FREE oe_allocator_free
#define CALLOC oe_allocator_calloc
#define REALLOC oe_allocator_realloc
#define POSIX_MEMALIGN oe_allocator_posix_memalign
#define oe_allocator_malloc_USABLE_SIZE oe_allocator_malloc_usable_size

#endif

void* oe_malloc(size_t size)
{
    void* p = oe_allocator_malloc(size);

    if (!p && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

void oe_free(void* ptr)
{
    oe_allocator_free(ptr);
}

void* oe_calloc(size_t nmemb, size_t size)
{
    void* p = oe_allocator_calloc(nmemb, size);

    if (!p && nmemb && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, nmemb * size);
    }

    return p;
}

void* oe_realloc(void* ptr, size_t size)
{
    void* p = oe_allocator_realloc(ptr, size);

    if (!p && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

int oe_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    int rc = oe_allocator_posix_memalign(memptr, alignment, size);

    if (rc != 0 && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return rc;
}

size_t oe_malloc_usable_size(void* ptr)
{
    return oe_allocator_malloc_usable_size(ptr);
}
