import Foundation
import AndroidSystemHeaders

public class LinkMap {
  public enum Error: Swift.Error {
    case MalformedElf(_ description: String)
    case MissingAuxVecEntry(_ description: String)
    case ProcessReadMemoryFailure(address: UInt, _ description: String = "")
  }

  public struct Entry {
    public let l_addr: Elf64_Addr
    public let l_name: String?

    public func rebase(address: UInt64) -> UInt64 {
      return self.l_addr + address
    }
  }

  public let entries: [Entry]

  public init(for process: Process) throws {
    guard let phdrAddr = process.auxVec.entries[.AT_PHDR] else {
      throw Error.MissingAuxVecEntry("missing AT_PHDR")
    }

    guard let phdrSize = process.auxVec.entries[.AT_PHENT] else {
      throw Error.MissingAuxVecEntry("missing AT_PHENT")
    }

    guard let phdrCount = process.auxVec.entries[.AT_PHNUM] else {
      throw Error.MissingAuxVecEntry("missing AT_PHNUM")
    }

    guard phdrSize == MemoryLayout<Elf64_Phdr>.size else {
      throw Error.MalformedElf("AT_PHENT \(phdrSize) < sizeof(Elf64_Phdr)")
    }

    // determine the base load address for the executable file and locate the
    // dynamic segment
    var dynamicSegment: Elf64_Phdr? = nil
    var baseLoadSegment: Elf64_Phdr? = nil
    for i in 0...phdrCount {
      let address: UInt64 = phdrAddr + i * phdrSize
      let phdr: Elf64_Phdr = try process.readStruct(address: address)

      switch phdr.p_type {
      case Elf64_Word(PT_LOAD):
        // chose the PT_LOAD segment with the lowest p_vaddr value, which will
        // typically be zero
        if let loadSegment = baseLoadSegment {
          if phdr.p_vaddr < loadSegment.p_vaddr {
            baseLoadSegment = phdr
          }
        } else {
          baseLoadSegment = phdr
        }

      case Elf64_Word(PT_DYNAMIC):
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

    let loadAddr: UInt64 = phdrAddr - UInt64(MemoryLayout<Elf64_Ehdr>.size)
    let baseAddr: UInt64 = loadAddr - baseLoadSegment.p_vaddr
    let dynamicSegmentAddr: UInt64 = baseAddr + dynamicSegment.p_vaddr

    // parse through the dynamic segment to find the location of the .debug section
    var rDebugEntry: Elf64_Dyn? = nil
    let entrySize = UInt64(MemoryLayout<Elf64_Dyn>.size)
    let dynamicEntryCount = UInt(dynamicSegment.p_memsz / entrySize)
    for i in 0...dynamicEntryCount {
      let address: UInt64 = dynamicSegmentAddr + UInt64(i) * entrySize
      let dyn: Elf64_Dyn = try process.readStruct(address: address)
      if dyn.d_tag == DT_DEBUG {
        rDebugEntry = dyn
        break
      }
    }

    guard let rDebugEntry = rDebugEntry else {
      throw Error.MalformedElf("DT_DEBUG not found in dynamic segment")
    }

    let rDebugAddr: UInt64 = rDebugEntry.d_un.d_ptr
    let rDebug: r_debug = try process.readStruct(address: rDebugAddr)

    var entries: [Entry] = []
    var linkMapAddr = UInt(bitPattern: rDebug.r_map)
    while linkMapAddr != 0 {
      let linkMap: link_map = try process.readStruct(address: UInt64(linkMapAddr))
      let nameAddr = UInt(bitPattern: linkMap.l_name)
      let name = try process.readString(address: UInt64(nameAddr))

      entries.append(
        Entry(
          l_addr: linkMap.l_addr,
          l_name: name,
        ))

      linkMapAddr = UInt(bitPattern: linkMap.l_next)
    }

    self.entries = entries
  }
}
