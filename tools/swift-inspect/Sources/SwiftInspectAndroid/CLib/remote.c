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

#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/uio.h>

#include "proc.h"
#include "ptrace.h"
#include "remote.h"

typedef struct {
  uintptr_t addr;
  bool found;
  maps_entry_t entry;
} maps_find_by_addr_context_t;

static bool maps_iterate_find_by_addr(void* ctx, const maps_entry_t* entry) {
  maps_find_by_addr_context_t *context = ctx;
  if (context->addr >= entry->start_addr &&
      context->addr < entry->end_addr) {
    context->entry = *entry;
    context->found = true;
    return false; // stop iteration
  }
  return true;
}

typedef struct {
  maps_entry_t match_entry;
  bool found;
  maps_entry_t found_entry;
} maps_find_equivalent_entry_context_t;

static bool maps_iterate_find_equivalent(void* ctx, const maps_entry_t* entry) {
  maps_find_equivalent_entry_context_t *context = ctx;
  const size_t match_len =
    context->match_entry.end_addr - context->match_entry.start_addr;
  const size_t entry_len = entry->end_addr - entry->start_addr;
  if (match_len == entry_len &&
      strcmp(entry->permissions, context->match_entry.permissions) == 0 &&
      strcmp(entry->pathname, context->match_entry.pathname) == 0) {
    context->found_entry = *entry;
    context->found = true;
    return false; // stop iteration;
  }
  return true;
}

static bool find_remote_addr(pid_t pid, uintptr_t local_addr, uintptr_t* remote_addr) {
  // first, find the memory section in this process that contains the address
  maps_find_by_addr_context_t by_addr_context = {
    .addr = local_addr,
    .found = false,
    .entry = {0},
  };

  const pid_t current_pid = getpid();
  if (!maps_iterate(current_pid, maps_iterate_find_by_addr, &by_addr_context))
    return false;

  if (!by_addr_context.found) {
    fprintf(stderr, "unable to find 0x%016lx in current process %d\n",
        local_addr, getpid());
    return false;
  }

  // next, find the equivalent memory entry in the target process
  maps_find_equivalent_entry_context_t find_equivalent_context = {
    .match_entry = by_addr_context.entry,
    .found = false,
    .found_entry = {0},
  };

  if (!maps_iterate(pid, maps_iterate_find_equivalent, &find_equivalent_context))
    return false;

  if (!find_equivalent_context.found) {
    fprintf(stderr, "unable to find matching memory region for local address "
        "0x%016lx in target process %u\n", local_addr, pid);
    return false;
  }

  // finally, calculate the offset of the local function within the local memory
  // entry and apply it to the start of the remote memory entry
  const size_t addr_offset = local_addr - by_addr_context.entry.start_addr;
  *remote_addr = find_equivalent_context.found_entry.start_addr + addr_offset;
  return true;
}

bool remote_dlsym(pid_t pid, const char* lib_name, const char* func_name,
    uintptr_t* remote_addr) {

  void* lib = dlopen(lib_name, RTLD_LAZY);
  if (lib == NULL) {
    fprintf(stderr, "failed dlopen(%s): %s\n", lib_name, strerror(errno));
    return false;
  }

  void* func = dlsym(lib, func_name);
  if (func == 0) {
    fprintf(stderr, "failed dlsym(%s): %s\n", func_name, strerror(errno));
    return false;
  }

  return find_remote_addr(pid, (uintptr_t)func, remote_addr);
}

bool remote_mmap(pid_t pid, size_t len, int prot, int flags, uintptr_t *remote_addr) {
  uintptr_t mmap_addr = 0;
  if (!remote_dlsym(pid, "libc.so", "mmap", &mmap_addr))
    return false;

  const unsigned long args[] = {
    0,
    len,
    prot,
    flags,
    0, 0, 0,
  };
  unsigned long result = 0;
  if (!ptrace_call_remote_function(pid, mmap_addr, args, &result) ||
      result == -1) {
    fprintf(stderr, "failed mmap in remote process %d\n", pid);
    return false;
  }

  *remote_addr = (uintptr_t)result;
  return true;
}

bool remote_munmap(pid_t pid, unsigned long addr, size_t len) {
  uintptr_t munmap_addr = 0;
  if (!remote_dlsym(pid, "libc.so", "munmap", &munmap_addr))
    return false;

  const unsigned long args[] = {
    addr,
    len,
    0, 0, 0, 0,
  };
  unsigned long result = 0;
  if (!ptrace_call_remote_function(pid, munmap_addr, args, &result) ||
      result == -1) {
    fprintf(stderr, "failed munmap in remote process %d\n", pid);
    return false;
  }

  return true;
}

bool remote_malloc_disable(pid_t pid) {
  uintptr_t malloc_disable_addr = 0;
  if (!remote_dlsym(pid, "libc.so", "malloc_disable", &malloc_disable_addr))
    return false;

  const unsigned long args[] = {
    0, 0, 0, 0, 0, 0,
  };
  unsigned long result = 0;
  if (!ptrace_call_remote_function(pid, malloc_disable_addr, args, &result)) {
    fprintf(stderr, "failed malloc_disable in remote process %d\n", pid);
    return false;
  }
  return true;
}

bool remote_malloc_enable(pid_t pid) {
  uintptr_t malloc_enable_addr = 0;
  if (!remote_dlsym(pid, "libc.so", "malloc_enable", &malloc_enable_addr))
    return false;

  const unsigned long args[] = {
    0, 0, 0, 0, 0, 0,
  };
  unsigned long result = 0;
  if (!ptrace_call_remote_function(pid, malloc_enable_addr, args, &result)) {
    fprintf(stderr, "failed malloc_enable in remote process %d\n", pid);
    return false;
  }
  return true;
}

bool remote_malloc_iterate(pid_t pid, uintptr_t remote_base, size_t size,
    uintptr_t remote_callback_addr, uintptr_t remote_context_addr,
    trap_callback_t trap_callback, void* trap_callback_context) {
  uintptr_t malloc_iterate_addr = 0;
  if (!remote_dlsym(pid, "libc.so", "malloc_iterate", &malloc_iterate_addr))
    return false;

  const unsigned long args[] = {
    remote_base,
    size,
    remote_callback_addr,
    remote_context_addr,
    0, 0,
  };
  unsigned long result = 0;
  if (!ptrace_call_remote_function_with_trap_callback(pid, malloc_iterate_addr,
        args, &result, trap_callback, trap_callback_context)) {
    fprintf(stderr, "failed malloc_iterate in remote process %d\n", pid);
    return false;
  }
  return true;
}

bool remote_read_memory(pid_t pid, uintptr_t remote_addr, void* data, size_t len) {
  struct iovec iov_local = {
    .iov_base = data,
    .iov_len = len,
  };

  struct iovec iov_remote = {
    .iov_base = (void*)remote_addr,
    .iov_len = len,
  };

  const ssize_t read = process_vm_readv(pid, &iov_local, 1, &iov_remote, 1, 0);
  if (read == -1)
    return false;

  if (len != read) {
    fprintf(stderr, "only read %ld of %lu bytes from remote process %d at %016lx\n",
        read, len, pid, remote_addr);
    return false;
  }
  return true;
}

bool remote_write_memory(pid_t pid, uintptr_t remote_addr, void* data, size_t len) {
  struct iovec iov_local = {
    .iov_base = data,
    .iov_len = len,
  };

  struct iovec iov_remote = {
    .iov_base = (void*)remote_addr,
    .iov_len = len,
  };

  const ssize_t written = process_vm_writev(pid, &iov_local, 1, &iov_remote, 1, 0);
  if (written == -1)
    return false;

  if (len != written) {
    fprintf(stderr, "only wrote %ld of %lu bytes to remote process %d at %016lx\n",
        written, len, pid, remote_addr);
    return false;
  }
  return true;
}