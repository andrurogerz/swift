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

#include "ptrace.h"

#if defined(__cplusplus)
extern "C" {
#endif

bool remote_dlsym(pid_t pid, const char* lib_name, const char* func_name,
    uintptr_t* remote_addr);
bool remote_mmap(pid_t pid, size_t len, int prot, int flags,
    uintptr_t* remote_addr);
bool remote_munmap(pid_t pid, unsigned long addr, size_t len);
bool remote_malloc_disable(pid_t pid);
bool remote_malloc_enable(pid_t pid);
bool remote_malloc_iterate(pid_t pid, uintptr_t remote_base, size_t size,
    uintptr_t remote_callback_addr, uintptr_t remote_context_addr,
    trap_callback_t trap_callback, void* trap_callback_context);
bool remote_read_memory(
    pid_t pid, uintptr_t remote_addr, void* data, size_t len);
bool remote_write_memory(
    pid_t pid, uintptr_t remote_addr, void* data, size_t len);

#if defined(__cplusplus)
}
#endif