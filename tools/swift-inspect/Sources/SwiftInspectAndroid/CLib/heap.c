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

typedef struct {
  uint64_t max_idx;
  uint64_t cur_idx;
  struct {
    uint64_t base;
    uint64_t size;
  } entries[];
} remote_callback_context_t;

_Static_assert(
    offsetof(remote_callback_context_t, entries) == 2 * sizeof(uint64_t),
    "entries field at unexpected offset");

#if defined(__aarch64__) || defined(__ARM64__) || defined(_M_ARM64)
#define DEBUG_BREAK() asm("brk #0x0; nop")
#elif defined(_M_X64) || defined(__amd64__) || defined(__x86_64__) || defined(_M_AMD64)
#define DEBUG_BREAK() asm("int3; nop")
#else
#error("only aarch64 and x86_64 are supported")
#endif

// NOTE: this function cannot call any other functions and must only use
// relative branches. We could inline assembly instead, but C is more reabable
// and maintainable.
static void remote_callback_start(unsigned long base, unsigned long size, void *arg) {
  volatile remote_callback_context_t* context = (remote_callback_context_t*)arg;
  while (context->cur_idx >= context->max_idx) {
    DEBUG_BREAK();
  }
  context->entries[context->cur_idx].base = base;
  context->entries[context->cur_idx].size = size;
  context->cur_idx += 1;
}

// NOTE: this function is here to mark the end of remote_callback_start and is never
// called.
static void remote_callback_end() {}

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

  remote_callback_context_t remote_context = {0};
  if (!remote_read_memory(pid, remote_data_addr, &remote_context, sizeof(remote_context)))
    return false;

  for (size_t idx = 0; idx < remote_context.cur_idx; idx++) {
    struct {
      uint64_t base;
      uint64_t size;
    } entry = {0};

    // TODO: read the remote in page-size chunks rather than one entry at a time
    uintptr_t remote_addr = remote_data_addr +
        offsetof(remote_callback_context_t, entries) + (sizeof(entry) * idx);
    if (!remote_read_memory(pid, remote_addr, &entry, sizeof(entry)))
      return false;

    // TODO: actually do something with the data we read from the remote
    context->callback(context->callback_context, entry.base, entry.size);
  }

  if (remote_context.cur_idx > 0) {
    context->total_items += remote_context.cur_idx;
  }

  // reset the cursor to allow more enumeration
  remote_context.cur_idx = 0;
  if (!remote_write_memory(pid, remote_data_addr, &remote_context, sizeof(remote_context)))
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

  remote_callback_context_t remote_context = {
    .cur_idx = 0,
    .max_idx = (remote_data_size - sizeof(remote_context)) /
      sizeof(remote_context.entries[0]),
  };

  if (!remote_write_memory(pid, remote_data_addr, &remote_context,
        sizeof(remote_context)))
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