import Foundation
import AndroidSystemHeaders

#if arch(arm64)
typealias RegisterSet = user_pt_regs
#elseif arch(x86_64)
typealias RegisterSet = pt_regs
#else
#error("Unsupported architecture")
#endif

class PTrace {
  enum Error: Swift.Error {
    case PTraceFailure(_ command: Int32, pid: pid_t, errno: Int32 = get_errno())
    case WaitFailure(pid: pid_t, errno: Int32 = get_errno())
  }

  let pid: pid_t 

  init(pid: pid_t) {
    self.pid = pid
  }

  func attachAndWait() throws {
    if ptrace_attach(self.pid) == -1 {
      throw Error.PTraceFailure(PTRACE_ATTACH, pid: self.pid)
    }

    while true {
      var status: Int32 = 0;
      let result = waitpid(self.pid, &status, 0)
      if result == -1 {
        if get_errno() == EINTR { continue }
        throw Error.WaitFailure(pid: self.pid)
      }

      if result == self.pid && wifstopped(status) {
        break
      }
    }
  }

  func detach() throws {
    if ptrace_detach(self.pid) == -1 {
      throw Error.PTraceFailure(PTRACE_DETACH, pid: self.pid)
    }
  }

  func cont() throws {
    if ptrace_continue(self.pid) == -1 {
      throw Error.PTraceFailure(PTRACE_CONT, pid: self.pid)
    }
  }

  func getSigInfo() throws -> siginfo_t {
    var sigInfo = unsafeBitCast((), to: siginfo_t.self)
    if ptrace_getsiginfo(self.pid, &sigInfo) == -1 {
      throw Error.PTraceFailure(PTRACE_GETSIGINFO, pid: self.pid)
    }
    return sigInfo
  }

  func pokeData(addr: UInt, value: UInt) throws {
    if ptrace_pokedata(self.pid, addr, value) == -1 {
      throw Error.PTraceFailure(PTRACE_POKEDATA, pid: self.pid)
    }
  }

  func getRegSet() throws -> RegisterSet {
    var regSet = unsafeBitCast((), to: RegisterSet.self)
    try withUnsafeMutableBytes(of: &regSet) {
      var vec = iovec(
        iov_base: $0.baseAddress!,
        iov_len: UInt(MemoryLayout<RegisterSet>.size))
      if ptrace_getregset(self.pid, NT_PRSTATUS, &vec) == -1 {
        throw Error.PTraceFailure(PTRACE_GETREGSET, pid: self.pid)
      }
    }
    return regSet
  }

  func setRegSet(regSet: RegisterSet) throws {
    var regSetCopy = regSet
    try withUnsafeMutableBytes(of: &regSetCopy) {
      var vec = iovec(
        iov_base: $0.baseAddress!,
        iov_len: UInt(MemoryLayout<RegisterSet>.size))
      if ptrace_setregset(self.pid, NT_PRSTATUS, &vec) == -1 {
        throw Error.PTraceFailure(PTRACE_SETREGSET, pid: self.pid)
      }
    }
  }
}