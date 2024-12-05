import Foundation
import AndroidSystemHeaders

protocol ElfPhdr {
  static var symbolSize: Int { get }
  var type: UInt32 { get }
  var offset: UInt64 { get }
  var vaddr: UInt64 { get }
  var paddr: UInt64 { get }
  var filesz: UInt64 { get }
  var memsz: UInt64 { get }
  var flags: UInt32 { get }
  var align: UInt64 { get }
}

extension Elf64_Phdr: ElfPhdr {
  static var symbolSize: Int { MemoryLayout<Elf64_Phdr>.size }
  var type: UInt32 { self.p_type }
  var offset: UInt64 { self.p_offset }
  var vaddr: UInt64 { self.p_vaddr }
  var paddr: UInt64 { self.p_paddr }
  var filesz: UInt64 { self.p_filesz }
  var memsz: UInt64 { self.p_memsz }
  var flags: UInt32 { self.p_flags }
  var align: UInt64 { self.p_align }
}

extension Elf32_Phdr: ElfPhdr {
  static var symbolSize: Int { MemoryLayout<Elf32_Phdr>.size }
  var type: UInt32 { self.p_type }
  var offset: UInt64 { UInt64(self.p_offset) }
  var vaddr: UInt64 { UInt64(self.p_vaddr) }
  var paddr: UInt64 { UInt64(self.p_paddr) }
  var filesz: UInt64 { UInt64(self.p_filesz) }
  var memsz: UInt64 { UInt64(self.p_memsz) }
  var flags: UInt32 { self.p_flags }
  var align: UInt64 { UInt64(self.p_align) }
}
