import Foundation
import LinuxSystemHeaders

#if arch(arm64)
public typealias RegisterSet = user_pt_regs

extension RegisterSet {
  func setupCall(funcAddr: UInt64, args: [UInt64], returnAddr: UInt64) -> RegisterSet {
    var registers = self
    registers.regs.0 = args.count > 0 ? args[0] : 0
    registers.regs.1 = args.count > 1 ? args[1] : 0
    registers.regs.2 = args.count > 2 ? args[2] : 0
    registers.regs.3 = args.count > 3 ? args[3] : 0
    registers.regs.4 = args.count > 4 ? args[4] : 0
    registers.regs.5 = args.count > 5 ? args[5] : 0
    registers.pc = funcAddr
    registers.regs.30 = returnAddr // link register (x30)
    return registers
  }

  func returnValue() -> UInt64 {
    return self.regs.0
  }
}

#elseif arch(x86_64)
public typealias RegisterSet = pt_regs

extension RegisterSet {
  func setupCall(funcAddr: UInt64, args: [UInt64], returnAddr: UInt64) -> RegisterSet {
    var registers = self
    registers.rdi = UInt(args.count > 0 ? args[0] : 0)
    registers.rsi = UInt(args.count > 1 ? args[1] : 0)
    registers.rdx = UInt(args.count > 2 ? args[2] : 0)
    registers.rcx = UInt(args.count > 3 ? args[3] : 0)
    registers.r8  = UInt(args.count > 4 ? args[4] : 0)
    registers.r9  = UInt(args.count > 5 ? args[5] : 0)
    registers.rip = UInt(funcAddr)
    registers.rax = 0 // rax is the number of args in a va_args function
    return registers
  }

  mutating func stackReserve(byteCount: UInt) -> UInt64 {
    self.rsp -= byteCount
    return UInt64(self.rsp)
  }

  func returnValue() -> UInt64 {
    return UInt64(self.rax);
  }
}

#else
#error("Only arm64 and x86_64 architectures are currently supported")
#endif
