//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2020 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

#pragma once

#include <stdbool.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef bool (*trap_callback_t)(void* context);

bool ptrace_call_remote_function(pid_t pid, unsigned long func_addr,
    const unsigned long args[6], unsigned long *func_result);
bool ptrace_call_remote_function_with_trap_callback(pid_t pid,
    unsigned long func_addr, const unsigned long args[6],
    unsigned long *func_result, trap_callback_t trap_callback,
    void* trap_callback_context);

#if defined(__cplusplus)
}
#endif