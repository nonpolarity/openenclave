// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/advanced/allocator.h>
#include <openenclave/advanced/debugmalloc.h>

#ifndef DMTOGGLE_EXPORT
#define DMTOGGLE_EXPORT __attribute__((visibility("default")))
#endif
DMTOGGLE_EXPORT void* oe_debug_malloc(size_t size)
{
    return oe_allocator_malloc(size);
}

DMTOGGLE_EXPORT void oe_debug_free(void* ptr)
{
    oe_allocator_free(ptr);
}

DMTOGGLE_EXPORT void* oe_debug_calloc(size_t nmemb, size_t size)
{
    return oe_allocator_calloc(nmemb, size);
}

DMTOGGLE_EXPORT void* oe_debug_realloc(void* ptr, size_t size)
{
    return oe_allocator_realloc(ptr, size);
}

DMTOGGLE_EXPORT int oe_debug_posix_memalign(
    void** memptr,
    size_t alignment,
    size_t size)
{
    return oe_allocator_posix_memalign(memptr, alignment, size);
}

DMTOGGLE_EXPORT size_t oe_debug_malloc_usable_size(void* ptr)
{
    return oe_allocator_malloc_usable_size(ptr);
}
