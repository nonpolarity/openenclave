// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_DEBUG_MALLOC_H
#define _OE_DEBUG_MALLOC_H

void oe_debug_malloc_start_tracking(void);

void oe_debug_malloc_stop_tracking(void);

void oe_debug_malloc_print_objects(void);

#endif /* _OE_DEBUG_MALLOC_H */
