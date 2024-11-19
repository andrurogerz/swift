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

typedef struct {
  unsigned long start_addr;
  unsigned long end_addr;
  char permissions[5];
  unsigned long offset;
  char device[6];
  unsigned long inode;
  char pathname[256];
} maps_entry_t;

typedef bool (*maps_entry_callback_t)(void*, const maps_entry_t*);

bool maps_iterate(pid_t pid, maps_entry_callback_t callback, void *context);

#if defined(__cplusplus)
}
#endif