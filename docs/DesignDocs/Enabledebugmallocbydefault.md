Proposal to enable debugmalloc by default
====

# Motivation

While the lower memory allocator is pluggable, as a wrapper, the debugmalloc
tool keeps record of all memory activities, and can help developers to track
unintended memory leaking.
In debug mode, the debug malloc is on by default. This proposal is suggesting
to turn on debugmalloc in all building types.

# Specification

## Global option
To enable debugmalloc by default, we only need to set the compiling option
USE_DEBUG_MALLOC to "ON" as default, disregarding the building type.

## local/temporary option
As debugmalloc keeps tracking all the memory allocation, some overhead is
introduced, especially in some cases with enomorous allocations. There is already
some attempt to bypass debugmalloc, such as https://github.com/openenclave/openenclave/pull/3354.
As a runtime option, the drawback is that it does not guarantee thread safety.
Although for simple internal tests runtime option works, for user's multithread
applications it does not work. Regular mutex lock does not help in such
situation, since it requires the whole process from memomy allcation to memory
free be protected, in which way the performance may be close to single thread.

Thus we use a link-time option to disable debugmalloc temporarily.
The main idea is to create a static library "liboenodebugmalloc.a" for users to
choose, which provides the same functions as debugmalloc does, but all functions
bypass the allocation tracking activities:
```
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
    void* ptr = NULL;
    oe_debug_posix_memalign(&ptr, alignment, size);
    return ptr;
}

int oe_debug_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    return oe_allocator_posix_memalign(memptr, alignment, size);
}

size_t oe_debug_malloc_usable_size(void* ptr)
{
    return oe_allocator_malloc_usable_size(ptr);
}
```

The same names as debugmalloc can guarantee the success of link-time
substituion, and the callee name can guarantee the lower memory allocator is
still pluggable. Of course the extra layer of wrapper may have some overhead,
which is tested later and it shows the impact is minor.

Compared to runtime option, the link-time option has the drawback that it can't
give the developers fine-grained control. It can only turn off debugmalloc per
enclave, or from the view of building, per target.

# Example and test
Due to the several thousands allocations from mbedTLS, it takes much
longer time to finish tests/attestation_plugin while debugmalloc is on:
```
alvin@wechen3-u18-1:~/openenclave/build/tests/attestation_plugin$ ctest
Test project /home/alvin/openenclave/build/tests/attestation_plugin
    Start 1: tests/attestation_plugin
1/1 Test #1: tests/attestation_plugin .........   Passed  126.04 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) = 126.04 sec
alvin@wechen3-u18-1:~/openenclave/build/tests/attestation_plugin$
```

To temporarily disable debugmalloc, we can just add the link-time option:
```
alvin@wechen3-u18-1:~/openenclave/build/tests/attestation_plugin$ cat ~/openenclave/tests/attestation_plugin/enc/CMakeLists.txt | grep enclave_link_libraries
enclave_link_libraries(plugin_enc oenodebugmalloc oeenclave oelibc)
alvin@wechen3-u18-1:~/openenclave/build/tests/attestation_plugin$ ctest
Test project /home/alvin/openenclave/build/tests/attestation_plugin
    Start 1: tests/attestation_plugin
1/1 Test #1: tests/attestation_plugin .........   Passed   24.30 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) =  24.30 sec
alvin@wechen3-u18-1:~/openenclave/build/tests/attestation_plugin$
```
With the help of link-time option, debugmalloc is bypassed and the overhead is
reduced dramatically.

One more test to check the performance with the global option USE_DEBUG_MALLOC
set to OFF:
```
alvin@wechen3-u18-3:~/openenclave/build/tests/attestation_plugin$ ctest
Test project /home/alvin/openenclave/build/tests/attestation_plugin
    Start 1: tests/attestation_plugin
1/1 Test #1: tests/attestation_plugin .........   Passed   15.68 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) =  15.69 sec
alvin@wechen3-u18-3:~/openenclave/build/tests/attestation_plugin$
```

Since the link-time option just bypass debugmalloc, there is still a wrapper
of lower memory allocator that introduces some overhead. Considering
tests/attestation_plugin is the most memory-intensive test, the overhead is
acceptable. Yet the user can turn off debugmalloc completely through global
option USE_DEBUG_MALLOC, if performance is the most important consideration.
