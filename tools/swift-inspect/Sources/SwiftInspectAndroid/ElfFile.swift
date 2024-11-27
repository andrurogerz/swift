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

  init(filePath: String) throws {
    self.filePath = filePath

    guard let file = try? FileHandle(forReadingFrom: URL(fileURLWithPath: filePath)) else {
      throw Error.FileOpenFailure(filePath)
    }
    self.file = file

    let identLen = Int(EI_NIDENT)
    file.seek(toFileOffset: 0)
    guard let identData = try file.read(upToCount: identLen),
      identData.count == identLen
    else {
      throw Error.FileReadFailure(filePath, offset: 0, size: UInt64(identLen))
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
    guard let ehdrData = try file.read(upToCount: ehdrSize),
      ehdrData.count == ehdrSize
    else {
      throw Error.FileReadFailure(filePath, offset: 0, size: UInt64(ehdrSize))
    }

    if isElf64 {
      self.ehdr = ehdrData.withUnsafeBytes { $0.load(as: Elf64_Ehdr.self) as ElfEhdr }
    } else {
      self.ehdr = ehdrData.withUnsafeBytes { $0.load(as: Elf32_Ehdr.self) as ElfEhdr }
    }
  }

  // Reads and returns the Elf32_Shdr or Elf64_Shdr at the specified index.
  func readShdr(index: UInt) throws -> ElfShdr {
    func read<T: ElfShdr>(index: UInt) throws -> T {
      guard index < self.ehdr.shnum else {
        throw Error.MalformedElfFile(
          self.filePath, description: "shnum index \(index) >= \(self.ehdr.shnum))")
      }

      let shdrSize = T.symbolSize
      guard shdrSize == self.ehdr.shentsize else {
        throw Error.MalformedElfFile(self.filePath, description: "ehdr.shentsize != \(shdrSize)")
      }

      let shdrOffset: UInt64 = self.ehdr.shoff + UInt64(index) * UInt64(shdrSize)
      self.file.seek(toFileOffset: shdrOffset)
      guard let shdrData = try self.file.read(upToCount: shdrSize),
        shdrData.count == shdrSize
      else {
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

  func readSection(shdr: ElfShdr) throws -> Data {
    let fileOffset = shdr.offset
    guard let stringTableSize = Int(exactly: shdr.size) else {
      throw Error.MalformedElfFile(
        self.filePath, description: "ElfShdr.sh_size too large \(shdr.size)")
    }

    self.file.seek(toFileOffset: fileOffset)
    guard let data = try self.file.read(upToCount: stringTableSize),
      data.count == stringTableSize
    else {
      throw Error.FileReadFailure(self.filePath, offset: fileOffset, size: shdr.size)
    }

    return data
  }

  // returns a map of symbol names to their start offset in the Elf file
  func loadSymbols(baseAddress: UInt64 = 0) throws -> [String: (
    start: UInt64, end: UInt64
  )] {
    var symbols: [String: (start: UInt64, end: UInt64)] = [:]
    let sectionCount = UInt(self.ehdr.shnum)
    for sectionIndex in 0..<sectionCount {
      let shdr: ElfShdr = try self.readShdr(index: sectionIndex)

      guard shdr.type == SHT_SYMTAB || shdr.type == SHT_DYNSYM else { continue }

      let sectionData: Data = try self.readSection(shdr: shdr)
      let symTable: [ElfSym] =
        self.isElf64
        ? sectionData.withUnsafeBytes { Array($0.bindMemory(to: Elf64_Sym.self)) }
        : sectionData.withUnsafeBytes { Array($0.bindMemory(to: Elf32_Sym.self)) }

      guard shdr.entsize == (self.isElf64 ? Elf64_Sym.symbolSize : Elf32_Sym.symbolSize) else {
        throw Error.MalformedElfFile(self.filePath, description: "invalid shdr.entsize")
      }

      // the link field in the section header for a symbol table section refers
      // to the index of the string table section containing the symbol names
      let shdrLink: ElfShdr = try self.readShdr(index: UInt(shdr.link))
      guard shdrLink.type == SHT_STRTAB else {
        throw Error.MalformedElfFile(self.filePath, description: "section is not SHT_STRTAB")
      }

      let strTable: Data = try self.readSection(shdr: shdrLink)

      let symCount = Int(shdr.size / shdr.entsize)
      for symIndex in 0..<symCount {
        let sym = symTable[symIndex]
        guard sym.shndx != SHN_UNDEF, sym.value != 0, sym.size != 0 else {
          continue
        }

        // sym.name is a byte offset into the string table
        guard let strStart = Int(exactly: sym.name),
          strStart < strTable.count
        else {
          throw Error.MalformedElfFile(
            self.filePath, description: "invalid string table offset: \(sym.name)")
        }

        guard let strEnd = strTable[strStart...].firstIndex(of: 0),
          let symName = String(data: strTable[strStart..<strEnd], encoding: .utf8)
        else {
          throw Error.MalformedElfFile(
            self.filePath, description: "invalid string @ offset \(strStart)")
        }

        // rebase the symbol value on the base address provided by the caller
        symbols[symName] = (
          start: sym.value + baseAddress, end: sym.value + sym.size + baseAddress
        )
      }
    }

    return symbols
  }
}
