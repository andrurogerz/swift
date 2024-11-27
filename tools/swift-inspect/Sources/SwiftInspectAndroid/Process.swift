import Foundation
import AndroidSystemHeaders

public class Process {
  enum Error: Swift.Error {
    case ProcessVmReadFailure(pid: pid_t, address: UInt64, size: UInt64)
    case InvalidString(address: UInt64)
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
    let chunkSize: UInt = 1 * 1024 * 1024

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
    let maxSize = upToCount * UInt(MemoryLayout<T>.size)
    var local = iovec(
      iov_base: UnsafeMutableRawPointer.allocate(
        byteCount: Int(maxSize), alignment: MemoryLayout<T>.alignment), iov_len: maxSize)
    var remote = iovec(
      iov_base: UnsafeMutableRawPointer(bitPattern: UInt(address)), iov_len: maxSize)

    let bytesRead = process_vm_readv(self.pid, &local, 1, &remote, 1, 0)

    guard bytesRead > 0 else {
      throw Error.ProcessVmReadFailure(pid: self.pid, address: address, size: UInt64(maxSize))
    }

    let buffer = UnsafeBufferPointer(
      start: local.iov_base?.assumingMemoryBound(to: T.self), count: bytesRead)
    return Array(buffer)
  }
}
