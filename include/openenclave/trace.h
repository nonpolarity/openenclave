// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_TRACE_USER
#define _OE_TRACE_USER

OE_EXTERNC_BEGIN

typedef enum _oe_log_level
{
    OE_LOG_LEVEL_NONE = 0,
    OE_LOG_LEVEL_FATAL,
    OE_LOG_LEVEL_ERROR,
    OE_LOG_LEVEL_WARNING,
    OE_LOG_LEVEL_INFO,
    OE_LOG_LEVEL_VERBOSE,
    OE_LOG_LEVEL_MAX
} oe_log_level_t;

typedef void (*oe_log_callback_t)(
    void* context,
    bool is_enclave,
    const char* time,
    long int usecs,
    oe_log_level_t level,
    uint64_t oe_thread,
    const char* message);
oe_result_t oe_log_set_callback(void* context, oe_log_callback_t callback);
extern void* oe_log_context;
extern oe_log_callback_t oe_log_callback;

OE_EXTERNC_END

#endif
