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

#if defined(__linux__)

#include <dlfcn.h>
#include <linux/elf.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include <linux/uio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#if defined(__aarch64__) || defined(__ARM64__) || defined(_M_ARM64)
typedef struct user_pt_regs register_set_t;
#elif defined(_M_X64) || defined(__amd64__) || defined(__x86_64__) || defined(_M_AMD64)
typedef struct pt_regs register_set_t;
#else
#error("only aarch64 and x86_64 are supported")
#endif

bool ptrace_attach(pid_t pid) {
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    return false;

  int status = 0;
  do {
    if (waitpid(pid, &status, 0) != pid)
        return false;
  } while (!WIFSTOPPED(status));

  return true;
}

bool ptrace_continue(pid_t pid) {
  return !ptrace(PTRACE_CONT, pid, NULL, NULL);
}

bool ptrace_detach(pid_t pid) {
  return !ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

bool ptrace_getregs(pid_t pid, register_set_t* regs) {
  struct iovec vec = {
    .iov_base = regs,
    .iov_len = sizeof(register_set_t),
  };

  return !ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &vec);
}

bool ptrace_setregs(pid_t pid, register_set_t* regs) {
  struct iovec vec = {
    .iov_base = regs,
    .iov_len = sizeof(register_set_t),
  };
  return !ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &vec);
}

unsigned long ptrace_call_remote_function(pid_t pid, unsigned long func_addr, unsigned long args[6]) {
  register_set_t registers = {0};
  if (!ptrace_getregs(pid, &registers))
    return 0;

  register_set_t backup_registers = registers;

  // TODO(andrurogerz): this is hard-coded to arm64 calling convention, needs x86_64
  // populate the six argument registers-- no need to pass any args via stack
#if defined(__aarch64__) || defined(__ARM64__) || defined(_M_ARM64)
  registers.regs[0] = args[0];
  registers.regs[1] = args[1];
  registers.regs[2] = args[2];
  registers.regs[3] = args[3];
  registers.regs[4] = args[4];
  registers.regs[5] = args[5];
  registers.pc = func_addr;

  // Set lr (return address) to null. This will force the target thread to stop
  // with a SIGSEGV signal when the function returns. We will be notified via
  // waitpid() when this occurs and will then restore the state and continue the
  // process.
  registers.regs[30] = 0;
#elif defined(_M_X64) || defined(__amd64__) || defined(__x86_64__) || defined(_M_AMD64)
  registers.rdi = args[0];
  registers.rsi = args[1];
  registers.rdx = args[2];
  registers.rcx = args[3];
  registers.r8  = args[4];
  registers.r9  = args[5];
  registers.rip = func_addr;

  // TODO(andrurogerz): write return address to stack (registers.rsp)!!!
#endif

  if (!ptrace_setregs(pid, &registers) ||
      !ptrace_continue(pid))
    return 0;

  int status = 0;
  do {
    if (waitpid(pid, &status, 0) != pid)
        return 0;
  } while (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSEGV);

  if (!ptrace_getregs(pid, &registers) ||
      !ptrace_setregs(pid, &backup_registers) ||
      !ptrace_continue(pid))
    return 0;

#if defined(__aarch64__) || defined(__ARM64__) || defined(_M_ARM64)
  const unsigned long result = registers.regs[0];
#elif defined(_M_X64) || defined(__amd64__) || defined(__x86_64__) || defined(_M_AMD64)
  const unsigned long result = registers.rax;
#endif
  return result;
}

unsigned long ptrace_remote_alloc(pid_t pid, unsigned long mmap_addr, size_t len) {
  const unsigned long args[] = {
    0, 
    len,
    PROT_READ | PROT_WRITE,
    MAP_ANON | MAP_PRIVATE,
    0,
    0,
    0,
  };
  return ptrace_call_remote_function(pid, mmap_addr, args);
}

bool ptrace_remote_free(pid_t pid, unsigned long munmap_addr, unsigned long addr, size_t len) {
  const unsigned long args[] = {
    addr, 
    len,
    0,
    0,
    0,
    0,
  };
  return !ptrace_call_remote_function(pid, munmap_addr, args);
}


#endif // __linux__