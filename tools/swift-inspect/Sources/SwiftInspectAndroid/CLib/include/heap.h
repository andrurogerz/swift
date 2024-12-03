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

#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef void (*heap_iterate_callback_t)(void* context, uint64_t base, uint64_t len);
bool heap_iterate(pid_t pid, void* callback_context, heap_iterate_callback_t callback);

void* heap_callback_start();
size_t heap_callback_len();

#if defined(__cplusplus)
}
#endif