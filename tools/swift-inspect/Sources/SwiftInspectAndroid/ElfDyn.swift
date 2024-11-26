import Foundation
import AndroidSystemHeaders

protocol ElfDyn {
  static var symbolSize: Int { get }
  var tag: Int64 { get }
  var val: UInt64 { get }
}

extension Elf64_Dyn: ElfDyn {
  static var symbolSize: Int { MemoryLayout<Elf64_Dyn>.size }
  var tag: Int64 { self.d_tag }
  var val: UInt64 { self.d_un.d_val }
}

extension Elf32_Dyn: ElfDyn {
  static var symbolSize: Int { MemoryLayout<Elf32_Dyn>.size }
  var tag: Int64 { Int64(self.d_tag) }
  var val: UInt64 { UInt64(self.d_un.d_val) }
}
