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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>

#include "heap.h"
#include "remote.h"
#include "proc.h"

#if defined(__aarch64__) || defined(__ARM64__) || defined(_M_ARM64)
#define DEBUG_BREAK() asm("brk #0x0")
#elif defined(_M_X64) || defined(__amd64__) || defined(__x86_64__) || defined(_M_AMD64)
#define DEBUG_BREAK() asm("int3; nop")
#else
#error("only aarch64 and x86_64 are supported")
#endif

/* We allocate a buffer in the remote process that it populates with metadata
 * describing each heap entry it enumerates. We then read the contents of the
 * buffer, and individual heap entry contents, with process_vm_readv.
 * 
 * The buffer is interpreted as an array of 8-byte pairs. The first pair
 * contains metadata describing the buffer itself: max valid index (e.g. size of
 * the buffer) and next index (e.g. write cursor/position). Each subsequent pair
 * describes the address and length of a heap entry in the remote process.
 * 
 * ------------
 * | uint64_t | max valid index (e.g. sizeof(buffer) / sizeof(uint64_t))
 * ------------
 * | uint64_t | next free index (starts at 2)
 * ------------
 * | uint64_t | heap item 1 address
 * ------------ 
 * | uint64_t | heap item 1 size
 * ------------
 * | uint64_t | heap item 2 address
 * ------------ 
 * | uint64_t | heap item 2 size
 * ------------
 * | uint64_t | ...
 * ------------ 
 * | uint64_t | ...
 * ------------
 * | uint64_t | heap item N address
 * ------------ 
 * | uint64_t | heap item N size
 * ------------
 */

#define MAX_VALID_IDX 0
#define NEXT_FREE_IDX 1
#define HEADER_SIZE 2
#define ENTRY_SIZE  2

// NOTE: this function cannot call any other functions and must only use
// relative branches. We could inline assembly instead, but C is more reabable
// and maintainable.
static void remote_callback_start(unsigned long base, unsigned long size, void *arg) {
  volatile uint64_t *data = (uint64_t*)arg;
  while (data[NEXT_FREE_IDX] >= data[MAX_VALID_IDX]) {
    DEBUG_BREAK();
  }
  data[data[NEXT_FREE_IDX]++] = base;
  data[data[NEXT_FREE_IDX]++] = size;
}

// NOTE: this function is here to mark the end of remote_callback_start and is never
// called.
static void remote_callback_end() {}

void* heap_callback_start() {
  return (void*)remote_callback_start;
}

size_t heap_callback_len() {
  return (size_t)(remote_callback_end - remote_callback_start);
}

typedef struct {
  pid_t pid;
  heap_iterate_callback_t callback;
  void* callback_context;
  bool failed;
  size_t total_items;
  uintptr_t remote_data_addr;
  uintptr_t remote_code_addr;
} maps_iterate_remote_malloc_iterate_context_t;

static bool malloc_iterate_process_remote_entries(void* ctx) {
  maps_iterate_remote_malloc_iterate_context_t *context = ctx;
  const pid_t pid = context->pid;
  const uintptr_t remote_data_addr = context->remote_data_addr;

  uint64_t remote_header[HEADER_SIZE] = {0};
  if (!remote_read_memory(pid, remote_data_addr, &remote_header, sizeof(remote_header)))
    return false;

  if (remote_header[NEXT_FREE_IDX] > remote_header[MAX_VALID_IDX])
    return false; // should never happen

  for (size_t idx = HEADER_SIZE; idx < remote_header[NEXT_FREE_IDX]; idx += ENTRY_SIZE) {
    uint64_t remote_entry[ENTRY_SIZE] = {0};

    // TODO: read the remote in page-size chunks rather than one entry at a time
    uintptr_t remote_addr = remote_data_addr + (sizeof(uint64_t) * idx);
    if (!remote_read_memory(pid, remote_addr, &remote_entry, sizeof(remote_entry)))
      return false;

    context->callback(context->callback_context, remote_entry[0], remote_entry[1]);
  }

  if (remote_header[NEXT_FREE_IDX] > HEADER_SIZE) {
    context->total_items += (remote_header[NEXT_FREE_IDX] - HEADER_SIZE) / ENTRY_SIZE;
  }

  // reset the cursor to reuse the buffer for additional enumeration
  remote_header[NEXT_FREE_IDX] = HEADER_SIZE;
  if (!remote_write_memory(pid, remote_data_addr, &remote_header, sizeof(remote_header)))
    return false;

  return true;
}

static bool maps_iterate_remote_malloc_iterate(void* ctx, const maps_entry_t* entry) {
  // only iterate readable sections
  if (entry->permissions[0] != 'r')
    return true;

  // skip any memory sections that are not heaps (scudo, dlmalloc, asan)
  if (memcmp(entry->pathname, "[anon:libc_malloc]", sizeof("[anon:libc_malloc]")) != 0 &&
      memcmp(entry->pathname, "[anon:scudo:", sizeof("[anon:scudo:") - 1) != 0 &&
      memcmp(entry->pathname, "[anon:GWP-ASan", sizeof("[anon:GWP-ASan") - 1) != 0)
    return true;

  maps_iterate_remote_malloc_iterate_context_t *context = ctx;
  pid_t pid = context->pid;
  uintptr_t remote_data_addr = context->remote_data_addr;
  if (!remote_malloc_iterate(pid, entry->start_addr,
        entry->end_addr - entry->start_addr, context->remote_code_addr,
        remote_data_addr, malloc_iterate_process_remote_entries, context))
    fprintf(stderr, "failed remote_malloc_iterate\n");

  if (!malloc_iterate_process_remote_entries(context))
    return false;

  return true;
}

bool heap_iterate(pid_t pid, void* callback_context, heap_iterate_callback_t callback) {
  bool result = false;
  const size_t remote_data_size = getpagesize();
  uintptr_t remote_data_addr = 0;

  if (!remote_mmap(pid, remote_data_size, PROT_READ | PROT_WRITE,
        MAP_ANON | MAP_PRIVATE, &remote_data_addr))
    goto exit;

  uint64_t remote_header[HEADER_SIZE];
  remote_header[NEXT_FREE_IDX] = HEADER_SIZE;
  remote_header[MAX_VALID_IDX] = remote_data_size / sizeof(uint64_t);

  if (!remote_write_memory(pid, remote_data_addr, &remote_header,
        sizeof(remote_header)))
    goto exit;

  const size_t remote_callback_len =
    remote_callback_end - remote_callback_start;
  const size_t remote_code_size =
    (remote_callback_len + getpagesize() - 1) & ~(getpagesize() - 1);
  uintptr_t remote_code_addr = 0;

  if (!remote_mmap(pid, remote_code_size, PROT_EXEC| PROT_READ | PROT_WRITE,
        MAP_ANON | MAP_PRIVATE, &remote_code_addr))
    goto exit;

  if (!remote_write_memory(pid, remote_code_addr, remote_callback_start,
        remote_callback_len))
    goto exit;

  // stop allocations in the remote while we iterate its heap
  if (!remote_malloc_disable(pid))
    goto exit;

  maps_iterate_remote_malloc_iterate_context_t context = {
    .pid = pid,
    .callback = callback,
    .callback_context = callback_context,
    .failed = false,
    .total_items = 0,
    .remote_data_addr = remote_data_addr,
    .remote_code_addr = remote_code_addr,
  };
  maps_iterate(pid, maps_iterate_remote_malloc_iterate, &context);

  // re-enable remote allocations as soon as enumeration is done
  if (!remote_malloc_enable(pid))
    goto exit;

  if (context.failed)
    goto exit;

  result = true;

exit:
  remote_munmap(pid, remote_data_addr, remote_data_size);
  remote_munmap(pid, remote_code_addr, remote_code_size);
  return result;
}