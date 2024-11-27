import Foundation
import AndroidSystemHeaders

internal class AuxVec {
  enum Error: Swift.Error {
    case FileReadFailure(_ filePath: String)
  }

  // enum values must match the constants defined in usr/include/linux/auxv.h
  enum Tag: UInt64 {
    case AT_NULL = 0
    case AT_IGNORE = 1
    case AT_EXECFD = 2
    case AT_PHDR = 3
    case AT_PHENT = 4
    case AT_PHNUM = 5
    case AT_PAGESZ = 6
    case AT_BASE = 7
    case AT_FLAGS = 8
    case AT_ENTRY = 9
    case AT_NOTELF = 10
    case AT_UID = 11
    case AT_EUID = 12
    case AT_GID = 13
    case AT_EGID = 14
    case AT_PLATFORM = 15
    case AT_HWCAP = 16
    case AT_CLKTCK = 17
    case AT_SECURE = 23
    case AT_BASE_PLATFORM = 24
    case AT_RANDOM = 25
    case AT_HWCAP2 = 26
    case AT_RSEQ_FEATURE_SIZE = 27
    case AT_RSEQ_ALIGN = 28
    case AT_EXECFN = 31
    case AT_MINSIGSTKSZ = 51
  }

  static func load(for process: Process) throws -> [Tag: UInt64] {
    let filePath = "/proc/\(process.pid)/auxv"

    let fileHandle = try FileHandle(forReadingFrom: URL(fileURLWithPath: filePath))
    defer { fileHandle.closeFile() }

    var entries: [Tag: UInt64] = [:]

    guard let data = try fileHandle.readToEnd() else {
      throw Error.FileReadFailure(filePath)
    }

    // Aux vecotr is an array of 4-byte pairs in a 32-bit process, or an array
    // of 8-byte pairs in a 64-bit process
    let itemSize = process.elfFile.isElf64 ? MemoryLayout<UInt64>.size : MemoryLayout<UInt32>.size
    let entrySize = itemSize * 2

    for offset in stride(from: 0, to: data.count, by: entrySize) {
      let tagRange = offset..<(offset + itemSize)
      let rawTag = data[tagRange].withUnsafeBytes { $0.load(as: UInt64.self) }

      // ignore unknown tag types
      guard let tag = Tag(rawValue: rawTag) else { continue }

      // auxvec is null-terminated
      if tag == .AT_NULL { break }

      let valueRange = offset + itemSize..<(offset + entrySize)
      entries[tag] =
        data[valueRange].withUnsafeBytes { $0.load(as: UInt64.self) }
    }

    return entries
  }
}
