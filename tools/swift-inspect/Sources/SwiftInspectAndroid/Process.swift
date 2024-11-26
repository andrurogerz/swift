import Foundation
import AndroidSystemHeaders

public class Process {
  public enum Error: Swift.Error {
    case ProcessVmReadFailure(pid: pid_t, address: UInt64, size: UInt64)
    case InvalidString(address: UInt64)
  }

  public let pid: pid_t
  public let auxVec: AuxVec

  public init(_ pid: pid_t) throws {
    self.pid = pid
    self.auxVec = try AuxVec(for: pid)
  }

  // Read a struct of type T from the target process.
  public func readStruct<T>(address: UInt64) throws -> T {
    let result: [T] = try readArray(address: address, count: 1)
    return result.first!
  }

  // Read a null-terminated string from the target process.
  public func readString(address: UInt64) throws -> String {
    var accumulatedBytes = [UInt8]()
    var readAddress: UInt64 = address
    var chunkSize: UInt = 64

    while true {
      guard let chunk: [UInt8] = try? readArray(address: readAddress, count: chunkSize) else {
        // It is possible to fail reading a chunk because it extends past the
        // end of a readable memory region. In this situation, the string must
        // end within one chunk of the end of that memory region (or it is not
        // a valid string). To deal with this scenario, halve the chunk size
        // and retry the read. If we fail to read a single byte chunk then
        // the failure is for some other reason
        guard chunkSize > 1 else {
          throw Error.ProcessVmReadFailure(pid: self.pid, address: address, size: UInt64(chunkSize))
        }

        chunkSize /= 2
        continue
      }

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

  // Read an array of type T elements from the target process using.
  func readArray<T>(address: UInt64, count: UInt) throws -> [T] {
    let size = count * UInt(MemoryLayout<T>.size)
    var local = iovec(
      iov_base: UnsafeMutableRawPointer.allocate(
        byteCount: Int(size), alignment: MemoryLayout<T>.alignment), iov_len: size)
    var remote = iovec(iov_base: UnsafeMutableRawPointer(bitPattern: UInt(address)), iov_len: size)

    let bytesRead = process_vm_readv(self.pid, &local, 1, &remote, 1, 0)

    guard bytesRead == size else {
      throw Error.ProcessVmReadFailure(pid: self.pid, address: address, size: UInt64(size))
    }

    let buffer = UnsafeBufferPointer(
      start: local.iov_base?.assumingMemoryBound(to: T.self), count: Int(count))
    return Array(buffer)
  }
}
