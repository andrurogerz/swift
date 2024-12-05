import Foundation
import AndroidSystemHeaders

class LinkMap {
  enum Error: Swift.Error {
    case MalformedElf(_ description: String)
    case MissingAuxVecEntry(_ description: String)
    case ProcessReadMemoryFailure(address: UInt, _ description: String = "")
  }

  struct Entry {
    let baseAddress: UInt64
    let moduleName: String
  }

  let entries: [Entry]

  init(for process: Process) throws {
    let auxVec = try AuxVec.load(for: process)
    guard let phdrAddr = auxVec[.AT_PHDR] else {
      throw Error.MissingAuxVecEntry("missing AT_PHDR")
    }

    guard let phdrSize = auxVec[.AT_PHENT] else {
      throw Error.MissingAuxVecEntry("missing AT_PHENT")
    }

    guard let phdrCount = auxVec[.AT_PHNUM] else {
      throw Error.MissingAuxVecEntry("missing AT_PHNUM")
    }

    let isElf64 = process.elfFile.isElf64
    guard phdrSize == (isElf64 ? Elf64_Phdr.symbolSize : Elf32_Phdr.symbolSize) else {
      throw Error.MalformedElf("AT_PHENT invalid size: \(phdrSize)")
    }

    // determine the base load address for the executable file and locate the
    // dynamic segment
    var dynamicSegment: ElfPhdr? = nil
    var baseLoadSegment: ElfPhdr? = nil
    for i in 0...phdrCount {
      let address: UInt64 = phdrAddr + i * phdrSize
      let phdr: ElfPhdr =
        isElf64
        ? try process.readStruct(address: address) as Elf64_Phdr
        : try process.readStruct(address: address) as Elf32_Phdr

      switch phdr.type {
      case UInt32(PT_LOAD):
        // chose the PT_LOAD segment with the lowest p_vaddr value, which will
        // typically be zero
        if let loadSegment = baseLoadSegment {
          if phdr.vaddr < loadSegment.vaddr {
            baseLoadSegment = phdr
          }
        } else {
          baseLoadSegment = phdr
        }

      case UInt32(PT_DYNAMIC):
        guard dynamicSegment == nil else {
          throw Error.MalformedElf("multiple PT_DYNAMIC segments found")
        }
        dynamicSegment = phdr

      default:
        continue
      }
    }

    guard let dynamicSegment = dynamicSegment else {
      throw Error.MalformedElf("PT_DYNAMIC segment not found")
    }

    guard let baseLoadSegment = baseLoadSegment else {
      throw Error.MalformedElf("PT_LOAD segment not found")
    }

    let ehdrSize = isElf64 ? Elf64_Ehdr.symbolSize : Elf32_Ehdr.symbolSize
    let loadAddr: UInt64 = phdrAddr - UInt64(ehdrSize)
    let baseAddr: UInt64 = loadAddr - baseLoadSegment.vaddr
    let dynamicSegmentAddr: UInt64 = baseAddr + dynamicSegment.vaddr

    // parse through the dynamic segment to find the location of the .debug section
    var rDebugEntry: ElfDyn? = nil
    let entrySize = isElf64 ? Elf64_Dyn.symbolSize : Elf32_Dyn.symbolSize
    let dynamicEntryCount = UInt(dynamicSegment.memsz / UInt64(entrySize))
    for i in 0...dynamicEntryCount {
      let address: UInt64 = dynamicSegmentAddr + UInt64(i) * UInt64(entrySize)
      let dyn: ElfDyn =
        isElf64
        ? try process.readStruct(address: address) as Elf64_Dyn
        : try process.readStruct(address: address) as Elf32_Dyn

      if dyn.tag == DT_DEBUG {
        rDebugEntry = dyn
        break
      }
    }

    guard let rDebugEntry = rDebugEntry else {
      throw Error.MalformedElf("DT_DEBUG not found in dynamic segment")
    }

    // TODO(andrurogerz): only 64-bit processes are supported. Support for
    // 32-bit processes requires distinc 32- and 64-bit definitions for the
    // r_debug and link_map structs, which are not provided by the system
    // headers.
    guard isElf64 else {
      throw Error.MalformedElf("target process is not Elf64")
    }

    let rDebugAddr: UInt64 = rDebugEntry.val
    let rDebug: r_debug = try process.readStruct(address: rDebugAddr)

    var entries: [Entry] = []
    var linkMapAddr = UInt(bitPattern: rDebug.r_map)
    while linkMapAddr != 0 {
      let linkMap: link_map = try process.readStruct(address: UInt64(linkMapAddr))
      let nameAddr = UInt(bitPattern: linkMap.l_name)
      let name = try process.readString(address: UInt64(nameAddr))
      entries.append(Entry(baseAddress: linkMap.l_addr, moduleName: name))

      linkMapAddr = UInt(bitPattern: linkMap.l_next)
    }

    self.entries = entries
  }
}
