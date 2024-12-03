import Foundation
import AndroidSystemHeaders

public class SymbolCache {
  enum Error: Swift.Error {
    case SymbolNameNotFound(_ name: String)
    case NoSymbolForAddress(_ addr: UInt64)
  }

  // dictionary of [Module Name : [Symbol Name : (UInt64, UInt64)]]
  public let symbolLookup: [String: [String: (start: UInt64, end: UInt64)]]
  let linkMap: LinkMap

  // an array of all symbols sorted by their start address
  lazy var sortedAddressLookup: [(start: UInt64, end: UInt64, module: String, name: String)] = {
    var addressLookup: [(start: UInt64, end: UInt64, module: String, name: String)] = []
    for (module, symbols) in self.symbolLookup {
      for (name, (start, end)) in symbols {
        addressLookup.append(
          (start: start, end: end, module: module, name: name))
      }
    }
    addressLookup.sort { $0.start < $1.start }
    return addressLookup
  }()

  public init(for process: Process) throws {
    self.linkMap = try LinkMap(for: process)
    var symbolLookup: [String: [String: (start: UInt64, end: UInt64)]] = [:]
    for linkMapEntry in linkMap.entries {
      guard FileManager.default.fileExists(atPath: linkMapEntry.moduleName) else { continue }

      let elfFile = try ElfFile(filePath: linkMapEntry.moduleName)

      let symbolMap = try elfFile.loadSymbols(baseAddress: linkMapEntry.baseAddress)
      symbolLookup[linkMapEntry.moduleName] = symbolMap
    }
    self.symbolLookup = symbolLookup
  }

  public func address(of symbol: String) throws -> (UInt64, UInt64) {
    for (_, symbols) in symbolLookup {
      if let range = symbols[symbol] {
        return range
      }
    }
    throw Error.SymbolNameNotFound(symbol)
  }

  // find and return symbol that covers the specified address
  public func symbol(for address: UInt64) throws -> (
    start: UInt64, end: UInt64, module: String, name : String
  ) {
    var lowerBound = 0
    var upperBound = self.sortedAddressLookup.count
    while lowerBound < upperBound {
      let currentIndex = (lowerBound + upperBound) / 2
      let entry = self.sortedAddressLookup[currentIndex]
      if entry.start > address {
        upperBound = currentIndex
      } else if entry.end <= address {
        lowerBound = currentIndex + 1
      } else {
        assert(address >= entry.start)
        assert(address < entry.end)
        return entry
      }
    }
    throw Error.NoSymbolForAddress(address)
  }
}
