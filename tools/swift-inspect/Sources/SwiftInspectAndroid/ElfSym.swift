import Foundation
import AndroidSystemHeaders

protocol ElfSym {
  static var symbolSize: Int { get }
  var name: UInt32 { get }
  var info: UInt8 { get }
  var other: UInt8 { get }
  var shndx: UInt16 { get }
  var value: UInt64 { get }
  var size: UInt64 { get }
}

extension Elf32_Sym: ElfSym {
  static var symbolSize: Int { MemoryLayout<Elf32_Sym>.size }
  var name: UInt32 { self.st_name }
  var info: UInt8 { self.st_info }
  var other: UInt8 { self.st_other }
  var shndx: UInt16 { self.st_shndx }
  var value: UInt64 { UInt64(self.st_value) }
  var size: UInt64 { UInt64(self.st_size) }
}

extension Elf64_Sym: ElfSym {
  static var symbolSize: Int { MemoryLayout<Elf64_Sym>.size }
  var name: UInt32 { self.st_name }
  var info: UInt8 { self.st_info }
  var other: UInt8 { self.st_other }
  var shndx: UInt16 { self.st_shndx }
  var value: UInt64 { self.st_value }
  var size: UInt64 { self.st_size }
}
