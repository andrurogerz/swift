import Foundation

public class ProcFs {
  public struct MemoryMapEntry {
      public let startAddr: UInt64
      public let endAddr: UInt64
      public let permissions: String
      public let offset: UInt64
      public let device: String
      public let inode: UInt64
      public let pathname: String?
  }

  public static func loadMaps(for pid: pid_t) throws -> [MemoryMapEntry]? {
    let path = "/proc/\(pid)/maps"

    let file = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
    defer { file.closeFile() }

    guard let content = String(data: file.readDataToEndOfFile(), encoding: .ascii) else {
      return nil
    }

    var entries: [MemoryMapEntry] = []

    content.enumerateLines { (line, _) in
      let components = line.split(separator: " ", omittingEmptySubsequences: true)
      guard components.count >= 5 else { return }
      let addrParts = components[0].split(separator: "-")
      let entry = MemoryMapEntry(
        startAddr: UInt64(addrParts[0], radix: 16) ?? 0,
        endAddr: UInt64(addrParts[1], radix: 16) ?? 0,
        permissions: String(components[1]),
        offset: UInt64(components[2], radix: 16) ?? 0,
        device: String(components[3]),
        inode: UInt64(components[4]) ?? 0,
        pathname: components.count == 6 ? String(components[5]) : nil
      )
      entries.append(entry)
    }

    return entries
  }
}