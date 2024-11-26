import Foundation
import AndroidSystemHeaders

public class ElfFile {
  enum Error: Swift.Error {
    case FileOpenFailure(_ filePath: String)
    case FileReadFailure(_ filePath: String, offset: UInt64, size: UInt64)
    case FileNotElfFormat(_ filePath: String)
    case MalformedElfFile(_ filePath: String, description: String = "")
  }

  let filePath: String
  let file: FileHandle
  let ehdr: ElfEhdr
  let isElf64: Bool

  public init(filePath: String) throws {
    self.filePath = filePath

    guard let file = try? FileHandle(forReadingFrom: URL(fileURLWithPath: filePath)) else {
      throw Error.FileOpenFailure(filePath)
    }
    self.file = file

    let identLen = UInt64(EI_NIDENT)
    file.seek(toFileOffset: 0)
    guard let identData = try file.read(upToCount: Int(identLen)),
      identData.count == identLen else {
      throw Error.FileReadFailure(filePath, offset: 0, size: identLen)
    }

    let identMagic = String(bytes: identData.prefix(Int(SELFMAG)), encoding: .utf8)
    guard identMagic == ELFMAG else {
      throw Error.FileNotElfFormat(filePath)
    }

    let identClass = identData[Int(EI_CLASS)]
    let isElf64 = identClass == ELFCLASS64
    guard isElf64 || identClass == ELFCLASS32 else {
      throw Error.MalformedElfFile(filePath, description: "invalid EI_CLASS: \(identClass)")
    }
    self.isElf64 = isElf64

    let ehdrSize = isElf64 ? MemoryLayout<Elf64_Ehdr>.size : MemoryLayout<Elf32_Ehdr>.size
    file.seek(toFileOffset: 0)
    guard let ehdrData = try file.read(upToCount: Int(ehdrSize)),
      ehdrData.count == ehdrSize else {
      throw Error.FileReadFailure(filePath, offset: 0, size: UInt64(ehdrSize))
    }

    if isElf64 {
      self.ehdr = ehdrData.withUnsafeBytes { $0.load(as: Elf64_Ehdr.self) as ElfEhdr }
    } else {
      self.ehdr = ehdrData.withUnsafeBytes { $0.load(as: Elf32_Ehdr.self) as ElfEhdr }
    }
  }

  public func loadSymbols() throws -> [String: UInt64] {
    var symbols: [String: UInt64] = [:]
    let sectionCount = UInt(self.ehdr.shnum)
    for sectionIndex in 0..<sectionCount {
      let shdr: ElfShdr = try self.readShdr(index: sectionIndex)

      // we are only looking for section swith symbol tables
      guard shdr.type == SHT_SYMTAB || shdr.type == SHT_DYNSYM else { continue }

      let shdrLink: ElfShdr = try self.readShdr(index: UInt(shdr.link))
      let symCount = UInt(shdr.size / shdr.entsize)
      for symIndex in 0..<symCount {
        let sym = try readSym(shdr: shdr, index: symIndex)

        guard sym.shndx != SHN_UNDEF, sym.value != 0, sym.size != 0 else {
          continue
        }

        // sym.name is a byte offset into the string table
        let symOffset = UInt64(sym.name)
        let symName = try readString(shdr: shdrLink, offset: symOffset)
        symbols[symName] = sym.value
      }
    }

    return symbols
  }

  // Reads and returns the Elf32_Shdr or Elf64_Shdr at the specified index.
  func readShdr(index: UInt) throws -> ElfShdr {
    func read<T: ElfShdr>(index: UInt) throws -> T {
      guard index < self.ehdr.shnum else {
        throw Error.MalformedElfFile(
          self.filePath, description: "shnum index \(index) >= \(self.ehdr.shnum))")
      }

      let shdrSize = T.size
      guard shdrSize == self.ehdr.shentsize else {
        throw Error.MalformedElfFile(self.filePath, description: "ehdr.shentsize != \(shdrSize)")
      }

      let shdrOffset: UInt64 = self.ehdr.shoff + UInt64(index) * UInt64(shdrSize)
      self.file.seek(toFileOffset: shdrOffset)
      guard let shdrData = try self.file.read(upToCount: shdrSize),
        shdrData.count == shdrSize else {
        throw Error.FileReadFailure(self.filePath, offset: shdrOffset, size: UInt64(shdrSize))
      }

      return shdrData.withUnsafeBytes { $0.load(as: T.self) as T }
    }

    if self.isElf64 {
      return try read(index: index) as Elf64_Shdr
    } else {
      return try read(index: index) as Elf32_Shdr
    }
  }

  // Reads and returns either an Elf32_Sym or Elf64_Sym.
  func readSym(shdr: ElfShdr, index: UInt) throws -> ElfSym {
    func read<T: ElfSym>(shdr: ElfShdr, index: UInt) throws -> T {
      let symCount = shdr.size / shdr.entsize
      guard index < symCount else {
        throw Error.MalformedElfFile(
          self.filePath, description: "sym index \(index) >= \(symCount))")
      }

      let symSize = T.size
      guard symSize == shdr.entsize else {
        throw Error.MalformedElfFile(self.filePath, description: "shdr.entsize != \(symSize)")
      }

      let symOffset: UInt64 = shdr.offset + UInt64(index) * UInt64(symSize)
      self.file.seek(toFileOffset: symOffset)
      guard let symData = try self.file.read(upToCount: symSize),
        symData.count == symSize else {
        throw Error.FileReadFailure(self.filePath, offset: symOffset, size: UInt64(symSize))
      }

      return symData.withUnsafeBytes { $0.load(as: T.self) as T }
    }

    if self.isElf64 {
      return try read(shdr: shdr, index: index) as Elf64_Sym
    } else {
      return try read(shdr: shdr, index: index) as Elf32_Sym
    }
  }

  func readString(shdr: ElfShdr, offset: UInt64) throws -> String {
    guard shdr.type == SHT_STRTAB else {
      throw Error.MalformedElfFile(self.filePath, description: "section is not SHT_STRTAB")
    }

    var fileOffset: UInt64 = shdr.offset + offset
    let chunkSize: Int = 64
    var data = Data()

    while true {
      self.file.seek(toFileOffset: fileOffset)
      guard let chunk = try self.file.read(upToCount: chunkSize),
        !chunk.isEmpty else {
        throw Error.FileReadFailure(self.filePath, offset: fileOffset, size: UInt64(chunkSize))
      }

      if let nullIndex = chunk.firstIndex(of: 0) {
        data.append(chunk[..<nullIndex])
        break
      }

      data.append(chunk)
      fileOffset += UInt64(chunk.count)
    }

    guard let result = String(data: data, encoding: .utf8) else {
      throw Error.MalformedElfFile(self.filePath, description: "invalid string in SHT_STRTAB")
    }

    return result
  }
}
