// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/advanced/allocator.h>
#include <openenclave/advanced/debugmalloc.h>

/*
**==============================================================================
**
** Public definitions:
**
**==============================================================================
*/

void* oe_debug_malloc(size_t size)
{
    return oe_allocator_malloc(size);
}

void oe_debug_free(void* ptr)
{
    oe_allocator_free(ptr);
}

void* oe_debug_calloc(size_t nmemb, size_t size)
{
    return oe_allocator_calloc(nmemb, size);
}

void* oe_debug_realloc(void* ptr, size_t size)
{
    return oe_allocator_realloc(ptr, size);
}

void* oe_debug_memalign(size_t alignment, size_t size)
{
    OE_UNUSED(alignment);
    OE_UNUSED(size);

    return NULL;
}
// void* oe_debug_memalign(size_t alignment, size_t size)
//{
//    void* ptr = NULL;
//
//    // The only difference between posix_memalign and the obsolete memalign is
//    // that posix_memalign requires alignment to be a multiple of
//    sizeof(void*).
//    // Adjust the alignment if needed.
//    alignment = oe_round_up_to_multiple(alignment, sizeof(void*));
//
//    oe_debug_posix_memalign(&ptr, alignment, size);
//    return ptr;
//}

int oe_debug_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    return oe_allocator_posix_memalign(memptr, alignment, size);
}

size_t oe_debug_malloc_usable_size(void* ptr)
{
    return oe_allocator_malloc_usable_size(ptr);
}
