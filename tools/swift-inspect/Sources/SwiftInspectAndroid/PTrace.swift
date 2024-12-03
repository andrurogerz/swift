import Foundation
import AndroidSystemHeaders

public class PTrace {
  enum Error: Swift.Error {
    case PTraceFailure(_ command: Int32, pid: pid_t, errno: Int32 = get_errno())
    case WaitFailure(pid: pid_t, errno: Int32 = get_errno())
  }

  let pid: pid_t 

  init(process pid: pid_t) throws {
    if ptrace_attach(pid) == -1 {
      throw Error.PTraceFailure(PTRACE_ATTACH, pid: pid)
    }

    while true {
      var status: Int32 = 0;
      let result = waitpid(pid, &status, 0)
      if result == -1 {
        if get_errno() == EINTR { continue }
        throw Error.WaitFailure(pid: pid)
      }

      if result == pid && wIfStopped(status) {
        break
      }
    }

    self.pid = pid
  }

  deinit {
    ptrace_detach(self.pid)
  }


  public func cont() throws {
    if ptrace_continue(self.pid) == -1 {
      throw Error.PTraceFailure(PTRACE_CONT, pid: self.pid)
    }
  }

  public func getSigInfo() throws -> siginfo_t {
    var sigInfo = siginfo_t()
    if ptrace_getsiginfo(self.pid, &sigInfo) == -1 {
      throw Error.PTraceFailure(PTRACE_GETSIGINFO, pid: self.pid)
    }
    return sigInfo
  }

  public func pokeData(addr: UInt64, value: UInt64) throws {
    if ptrace_pokedata(self.pid, UInt(addr), UInt(value)) == -1 {
      throw Error.PTraceFailure(PTRACE_POKEDATA, pid: self.pid)
    }
  }

  public func getRegSet() throws -> RegisterSet {
    var regSet = RegisterSet()
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

  public func setRegSet(regSet: RegisterSet) throws {
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