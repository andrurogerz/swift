import Foundation
import AndroidSystemHeaders

public class Process {
  enum Error: Swift.Error {
    case ProcessVmReadFailure(pid: pid_t, address: UInt64, size: UInt64)
    case ProcessVmWriteFailure(pid: pid_t, address: UInt64, size: UInt64)
    case InvalidString(address: UInt64)
    case IllegalArgument(description: String)
    case WaitPidFailure(pid: pid_t, errno: Int32 = get_errno())
    case UnexpectedWaitStatus(pid: pid_t, status: Int32, sigInfo: siginfo_t? = nil)
  }

  public let pid: pid_t
  public let elfFile: ElfFile

  public init(_ pid: pid_t) throws {
    self.pid = pid
    let executableFilePath = "/proc/\(pid)/exe"
    self.elfFile = try ElfFile(filePath: executableFilePath)
  }

  // read a struct of type T from the target process
  public func readStruct<T>(address: UInt64) throws -> T {
    let result: [T] = try readArray(address: address, upToCount: 1)
    return result.first!
  }

  // read a null-terminated string from the target process
  public func readString(address: UInt64) throws -> String {
    var accumulatedBytes = [UInt8]()
    var readAddress: UInt64 = address
    let chunkSize: UInt = 64

    while true {
      let chunk: [UInt8] = try readArray(address: readAddress, upToCount: chunkSize)

      if let nullIndex = chunk.firstIndex(of: 0) {
        accumulatedBytes.append(contentsOf: chunk.prefix(nullIndex))
        break
      }

      accumulatedBytes.append(contentsOf: chunk)
      readAddress += UInt64(chunkSize)
    }

    guard let result = String(bytes: accumulatedBytes, encoding: .utf8) else {
      throw Error.InvalidString(address: address)
    }

    return result
  }

  // read an array of type T elements from the target process
  public func readArray<T>(address: UInt64, upToCount: UInt) throws -> [T] {
    let maxSize = upToCount * UInt(MemoryLayout<T>.stride) 
    let array: [T] = Array(unsafeUninitializedCapacity: Int(upToCount)) { buffer, initCount in
      var local = iovec(iov_base: buffer.baseAddress!, iov_len: maxSize)
      var remote = iovec(
        iov_base: UnsafeMutableRawPointer(bitPattern: UInt(address)), iov_len: maxSize)
      let bytesRead = process_vm_readv(self.pid, &local, 1, &remote, 1, 0)
      initCount = bytesRead / MemoryLayout<T>.stride;
    }

    guard array.count > 0 else {
      throw Error.ProcessVmReadFailure(pid: self.pid, address: address, size: UInt64(maxSize))
    }

    return array
  }

  public func writeMem(remoteAddr: UInt64, localAddr: UnsafeRawPointer, len: UInt) throws {
    var local = iovec(iov_base: UnsafeMutableRawPointer(mutating: localAddr), iov_len: len)
    var remote = iovec(iov_base: UnsafeMutableRawPointer(bitPattern: UInt(remoteAddr)), iov_len: len)

    let bytesWritten = process_vm_writev(self.pid, &local, 1, &remote, 1, 0)
    guard bytesWritten == len else {
      throw Error.ProcessVmWriteFailure(pid: self.pid, address: remoteAddr, size: UInt64(len))
    }
  }

  public func callRemoteFunction(at address: UInt64, with args: [UInt64] = [],
      onTrap callback: ((_ ptrace: PTrace) throws -> Void)? = nil) throws -> UInt64 {

    guard args.count <= 6 else {
      throw Error.IllegalArgument(description: "max of 6 arguments allowed")
    }

    let ptrace = try PTrace(process: self.pid)
    let origRegs = try ptrace.getRegSet()
    defer {
      _ = try? ptrace.setRegSet(regSet: origRegs)
    }

    // Set the return address to 0. This forces the function to return to 0 on
    // completion, resulting in a SIGSEGV with address 0 which will interrupt
    // the process and notify us (the tracer) via waitpid(). At that point, we
    // will restore the original state and continue the process.
    let returnAddr: UInt64 = 0

    var newRegs = origRegs.setupCall(funcAddr: address, args: args, returnAddr: returnAddr)

#if arch(x86_64)
    // push the return address onto the stack on x86_64
    let stackAddr = newRegs.stackReserve(byteCount: UInt(MemoryLayout<UInt64>.size))
    try ptrace.pokeData(addr: stackAddr, value: returnAddr)
#endif

    try ptrace.setRegSet(regSet: newRegs)
    try ptrace.cont()

    var status: Int32 = 0
    while true {
      let result = waitpid(self.pid, &status, 0)
      if result == -1 {
        if get_errno() == EINTR { continue }
        throw Error.WaitPidFailure(pid: self.pid) 
      }

      if wIfExited(status) || wIfSignaled(status) {
        throw Error.UnexpectedWaitStatus(pid: self.pid, status: status) 
      }

      if wIfStopped(status) {
        guard wStopSig(status) == SIGTRAP, let callback = callback else { break }

        // give the caller the opportunity to handle SIGTRAP
        try callback(ptrace)
        try ptrace.cont()
        continue
      }

      print("what?")
    }

    let sigInfo = try ptrace.getSigInfo()
    newRegs = try ptrace.getRegSet()

    guard wStopSig(status) == SIGSEGV, siginfo_si_addr(sigInfo) == nil else {
      print("WSTOPSIG(status):\(wStopSig(status)), si_addr:\(siginfo_si_addr(sigInfo)!)")
      throw Error.UnexpectedWaitStatus(pid: self.pid, status: status, sigInfo: sigInfo)
    }

    return UInt64(newRegs.returnValue())
  }
}
