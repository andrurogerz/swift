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

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <linux/elf.h>
#include <linux/uio.h>

#include <sys/ptrace.h>
#include <sys/wait.h>

#include "ptrace.h"

#if defined(__aarch64__) || defined(__ARM64__) || defined(_M_ARM64)
typedef struct user_pt_regs register_set_t;

static inline
void registers_setup_call(register_set_t* registers,
    const unsigned long args[6], unsigned long func_addr,
    unsigned long return_addr) {
  registers->regs[0] = args[0];
  registers->regs[1] = args[1];
  registers->regs[2] = args[2];
  registers->regs[3] = args[3];
  registers->regs[4] = args[4];
  registers->regs[5] = args[5];
  registers->pc = func_addr;
  registers->regs[30] = return_addr; // link register (x30)
}

static inline
unsigned long registers_retval(const register_set_t* registers) {
  return registers->regs[0];
}

#elif defined(_M_X64) || defined(__amd64__) || defined(__x86_64__) || defined(_M_AMD64)
typedef struct pt_regs register_set_t;

inline
void registers_setup_call(register_set_t* registers,
    const unsigned long args[6], unsigned long func_addr,
    unsigned long return_addr) {
  registers->rdi = args[0];
  registers->rsi = args[1];
  registers->rdx = args[2];
  registers->rcx = args[3];
  registers->r8  = args[4];
  registers->r9  = args[5];
  registers->rip = func_addr;
  registers->rax = 0; // rax contains the number of args in a va_args C function

  // note: return_addr is ignored; caller is responsible for pushing it onto
  // the stack
}

inline
unsigned long registers_stack_reserve(register_set_t* registers, size_t bytes) {
  registers->rsp -= sizeof(bytes);
  return registers->rsp;
}

inline
unsigned long registers_retval(const register_set_t* registers) {
  return registers->rax;
}

#else
#error("only aarch64 and x86_64 are supported")
#endif

static bool ptrace_attach(pid_t pid) {
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
    perror("ptrace(PTRACE_ATTACH) failed");
    return false;
  }

  // keep calling waitpid() until we get a stop event for the target process
  // or an error other than EINTR
  for (;;) {
    int status = 0;
    const int result = waitpid(pid, &status, 0);
    if (result == -1) {
      if (errno == EINTR)
        continue;

      perror("waitpid failed");
      return false;
    }

    if (result == pid && WIFSTOPPED(status))
      break;
  }

  return true;
}

static bool ptrace_detach(pid_t pid) {
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
    perror("ptrace(PTRACE_DETACH) failed");
    return false;
  }
  return true;
}

static bool ptrace_continue(pid_t pid) {
  if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
    perror("ptrace(PTRACE_CONT) failed");
    return false;
  }
  return true;
}

static bool ptrace_getregs(pid_t pid, register_set_t* regs) {
  struct iovec vec = {
    .iov_base = regs,
    .iov_len = sizeof(register_set_t),
  };
  if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &vec) == -1) {
    perror("ptrace(PTRACE_GETREGSET) failed");
    return false;
  }
  return true;
}

static bool ptrace_setregs(pid_t pid, register_set_t* regs) {
  struct iovec vec = {
    .iov_base = regs,
    .iov_len = sizeof(register_set_t),
  };
  if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &vec) == -1) {
    perror("ptrace(PTRACE_SETREGSET) failed");
    return false;
  }
  return true;
}

static bool ptrace_getsiginfo(pid_t pid, siginfo_t *siginfo) {
  if (ptrace(PTRACE_GETSIGINFO, pid, 0, siginfo) == -1) {
    perror("ptrace(PTRACE_GETSIGINFO) failed");
    return false;
  }
  return true;
}

static bool ptrace_pokedata(
    pid_t pid, unsigned long addr, unsigned long value) {
  if (ptrace(PTRACE_POKEDATA, pid, addr, value) == -1) {
    perror("ptrace(PTRACE_POKEDATA) failed");
    return false;
  }
  return true;
}

bool ptrace_call_remote_function(pid_t pid, unsigned long func_addr,
    const unsigned long args[6], unsigned long *func_result) {
  return ptrace_call_remote_function_with_trap_callback(pid, func_addr, args,
      func_result, NULL, NULL);
}

bool ptrace_call_remote_function_with_trap_callback(pid_t pid,
    unsigned long func_addr, const unsigned long args[6],
    unsigned long *func_result, trap_callback_t trap_callback,
    void* trap_callback_context) {
  if (!ptrace_attach(pid))
    return false;

  register_set_t registers = {0};
  if (!ptrace_getregs(pid, &registers))
    return false;

  register_set_t backup_registers = registers;

  // Set the return address to 0. This forces the function to return to 0 when
  // the function completes, resulting in SIGSEGV with address 0 which will stop
  // the process and we will be notified via waitpid(). At that point, we can
  // restore the original state and continue.
  registers_setup_call(&registers, args, func_addr, 0);

#if defined(_M_X64) || defined(__amd64__) || defined(__x86_64__) || defined(_M_AMD64)
  // on x86_64, return address is pushed onto the stack
  const long stack_addr = registers_stack_reserve(&registers, sizeof(long));
  if (!ptrace_pokedata(pid, stack_addr, 0)) {
    fprintf(stderr, "failed to write stack: %s\n", strerror(errno));
    return false;
  }
#endif

  // NOTE: we could support > 6 args by pushing additional args on the stack

  if (!ptrace_setregs(pid, &registers) ||
      !ptrace_continue(pid))
    return false;

  int status = 0;
  for (;;) {
    const int result = waitpid(pid, &status, 0);
    if (result == -1) {
      if (errno == EINTR)
        continue;

      perror("waitpid failed\n");
      return false;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      fprintf(stderr, "process %d unexpectedly exited\n", pid);
      return false;
    }

    if (WIFSTOPPED(status)) {
      if (trap_callback == NULL || WSTOPSIG(status) != SIGTRAP)
        break;

      // caller requested callback on SIGTRAP
      if (!trap_callback(trap_callback_context))
        break;

      // on callback success, move to the next instruction and continue
      if (!ptrace_getregs(pid, &registers))
        break;

#if defined(__aarch64__) || defined(__ARM64__) || defined(_M_ARM64)
      registers.pc += 4; // brk #0x0
#elif defined(_M_X64) || defined(__amd64__) || defined(__x86_64__) || defined(_M_AMD64)
      registers.rip += 1; // int3
#endif

      if (!ptrace_setregs(pid, &registers))
        break;

      if (!ptrace_continue(pid))
        break;
    }
  }

  siginfo_t siginfo = {0};
  if (!ptrace_getsiginfo(pid, &siginfo))
    return false;

  if (!ptrace_getregs(pid, &registers) ||
      !ptrace_setregs(pid, &backup_registers) ||
      !ptrace_detach(pid))
    return false;

  *func_result = registers_retval(&registers);

  // Only return success if the exception address was zero as expected because
  // the function return address was set to zero.
  return (WSTOPSIG(status) == SIGSEGV) && (siginfo.si_addr == 0);
}
