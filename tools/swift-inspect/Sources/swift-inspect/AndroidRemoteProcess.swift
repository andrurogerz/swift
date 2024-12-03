//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2020 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

#if os(Android)

import Foundation
import AndroidCLib // TODO(andrurogerz): just depend on SwiftInspectAndroid
import AndroidSystemHeaders 
import SwiftInspectAndroid
import SwiftRemoteMirror

internal final class AndroidRemoteProcess: RemoteProcess {
  public typealias ProcessIdentifier = pid_t
  public typealias ProcessHandle = SwiftInspectAndroid.Process

  public private(set) var process: ProcessHandle
  public private(set) var context: SwiftReflectionContextRef!
  public private(set) var processIdentifier: ProcessIdentifier
  public private(set) var processName: String = "<unknown process>"

  let ptrace: SwiftInspectAndroid.PTrace
  let memoryMap: [SwiftInspectAndroid.ProcFs.MemoryMapEntry]
  let symbolCache: SwiftInspectAndroid.SymbolCache

  static var QueryDataLayout: QueryDataLayoutFunction {
    return { (context, type, _, output) in
      guard let output = output else { return 0 }

      switch type {
      case DLQ_GetPointerSize:
        let size = UInt8(MemoryLayout<UnsafeRawPointer>.stride)
        output.storeBytes(of: size, toByteOffset: 0, as: UInt8.self)
        return 1

      case DLQ_GetSizeSize:
        let size = UInt8(MemoryLayout<UInt>.stride) // UInt is word-size like size_t
        output.storeBytes(of: size, toByteOffset: 0, as: UInt8.self)
        return 1

      case DLQ_GetLeastValidPointerValue:
        let value: UInt64 = 0x1000
        output.storeBytes(of: value, toByteOffset: 0, as: UInt64.self)
        return 1

      default:
        return 0
      }
    }
  }

  static var Free: FreeFunction {
    return { (_, bytes, _) in
      free(UnsafeMutableRawPointer(mutating: bytes))
    }
  }
  static var ReadBytes: ReadBytesFunction {
    return { (context, address, size, _) in
      let process: AndroidRemoteProcess = AndroidRemoteProcess.fromOpaque(context!)

      guard let byteArray: [UInt8] = try? process.process.readArray(address: address, upToCount: UInt(size)),
            let buffer = malloc(byteArray.count) else {
        return nil
      }

      byteArray.withUnsafeBytes {
        buffer.copyMemory(from: $0.baseAddress!, byteCount: byteArray.count)
      }

      return UnsafeRawPointer(buffer)
    }
  }

  static var GetStringLength: GetStringLengthFunction {
    return { (context, address) in
      let process: AndroidRemoteProcess = AndroidRemoteProcess.fromOpaque(context!)

      guard let string = try? process.process.readString(address: address),
            let len = UInt64(exactly: string.count) else {
          return 0
      }

      return len
    }
  }

  static var GetSymbolAddress: GetSymbolAddressFunction {
    return { (context, symbol, length) in
      let process: AndroidRemoteProcess =
        AndroidRemoteProcess.fromOpaque(context!)

      guard let symbol = symbol else { return 0 }
      let name: String = symbol.withMemoryRebound(to: UInt8.self, capacity: Int(length)) {
        let buffer = UnsafeBufferPointer(start: $0, count: Int(length))
        return String(decoding: buffer, as: UTF8.self)
      }

      guard let (startAddr, _) = try? process.symbolCache.address(of: name) else { return 0 }
      return startAddr
    }
  }

  init?(processId: ProcessIdentifier) {
    self.processIdentifier = processId

    do {
      let path = "/proc/\(processId)/cmdline"
      let cmdline = try String(contentsOfFile: path, encoding: .ascii)
      self.processName = cmdline;

      let process = try SwiftInspectAndroid.Process(processId)
      self.process = process

      let ptrace = try SwiftInspectAndroid.PTrace(process: processId)
      self.ptrace = ptrace

      let symbolCache = try SwiftInspectAndroid.SymbolCache(for: process)
      self.symbolCache = symbolCache

      guard let memoryMap = try SwiftInspectAndroid.ProcFs.loadMaps(for: processId) else {
        print("failed loading memory map for \(processId)")
        return nil
      }
      self.memoryMap = memoryMap

    } catch {
      print("failed initialization: \(error)")
      return nil
    }

    guard let context = swift_reflection_createReflectionContextWithDataLayout(self.toOpaqueRef(),
      Self.QueryDataLayout, Self.Free, Self.ReadBytes, Self.GetStringLength, Self.GetSymbolAddress)
      else { return nil }
    self.context = context
  }

  func symbolicate(_ address: swift_addr_t) -> (module: String?, symbol: String?) {
    guard let symbol = try? self.symbolCache.symbol(for: address) else {
      return (nil, nil)
    }
    return (module: symbol.module, symbol: symbol.name)
  }

  internal func iterateHeap(_ body: (swift_addr_t, UInt64) -> Void) {
    for entry in self.memoryMap {
      guard let name = entry.pathname,
        name == "[anon:libc_malloc]" ||
        name.hasPrefix("[anon:scudo:") ||
        name.hasPrefix("[anon:GWP-ASan") else { continue }

      // collect all of the allocations in this heap region
      let allocations: [(base: swift_addr_t, len: UInt64)]
      do {
        allocations = try self.iterateHeapRegion(startAddr: entry.startAddr, endAddr: entry.endAddr)
      } catch {
        print("failed iterating remote heap: \(error)")
        return
      }

      for alloc in allocations {
        body(alloc.base, alloc.len)
      }
    }
  }

  internal func initHeapMetadata(dataAddr: UInt64, dataLen: UInt64) throws {
    // (re-)initialize the metadata region in the remote process
    let startEntry: UInt64 = 2 // first two entries are metadtata
    let maxEntries: UInt64 = dataLen / UInt64(MemoryLayout<UInt64>.stride)
    let header: (UInt64, UInt64) = (maxEntries, startEntry)
    let headerLen = UInt(MemoryLayout.size(ofValue: header))
    try withUnsafePointer(to: header) {
      try self.process.writeMem(remoteAddr: dataAddr, localAddr: $0, len: headerLen)
    }
  }

  internal func processHeapAllocations(dataAddr: UInt64, dataLen: UInt64)
      throws -> [(base: swift_addr_t, len: UInt64)] {
    let count = UInt(dataLen) / UInt(MemoryLayout<UInt64>.size)
    let data: [UInt64] = try self.process.readArray(address: dataAddr, upToCount: count)
    let startEntry = 2 // first two entries are metadata
    let entryCount = Int(data[1])
    var items: [(base: swift_addr_t, len: UInt64)] = []
    for idx in stride(from: startEntry, to: entryCount, by: 2) {
      items.append((base: data[idx], len: data[idx + 1]))
    }

    return items
  }

  internal func iterateHeapRegion(startAddr: UInt64, endAddr: UInt64)
      throws -> [(base: swift_addr_t, len: UInt64)] {
    let (mmapAddr, _) = try symbolCache.address(of: "mmap")
    let (munmapAddr, _) = try symbolCache.address(of: "munmap")
    let (mallocIterateAddr, _) = try symbolCache.address(of: "malloc_iterate")

    /* We allocate a page-sized buffer in the remote process that malloc_iterate
     * populates with metadata describing each heap entry it enumerates.
     * 
     * The buffer is interpreted as an array of 8-byte pairs. The first pair
     * contains metadata describing the buffer itself: max valid index (e.g.
     * the size of the buffer) and next index (e.g. write cursor/position).
     * Each subsequent pair describes the address and length of a heap entry in
     * the remote process.
     * 
     * ------------
     * | uint64_t | max valid index (e.g. sizeof(buffer) / sizeof(uint64_t))
     * ------------
     * | uint64_t | next free index (starts at 2)
     * ------------
     * | uint64_t | heap item 1 address
     * ------------ 
     * | uint64_t | heap item 1 size
     * ------------
     * | uint64_t | heap item 2 address
     * ------------ 
     * | uint64_t | heap item 2 size
     * ------------
     * | uint64_t | ...
     * ------------ 
     * | uint64_t | ...
     * ------------
     * | uint64_t | heap item N address
     * ------------ 
     * | uint64_t | heap item N size
     * ------------
     */
    let dataLen = UInt64(sysconf(Int32(_SC_PAGESIZE)))
    var mmapArgs = [0, dataLen, UInt64(PROT_READ | PROT_WRITE), UInt64(MAP_ANON | MAP_PRIVATE)]
    let remoteDataAddr: UInt64 = try self.ptrace.callRemoteFunction(at: mmapAddr, with: mmapArgs)
    defer {
      let munmapArgs: [UInt64] = [remoteDataAddr, dataLen]
      _ = try? self.ptrace.callRemoteFunction(at: munmapAddr, with: munmapArgs)
    }
    
    // initialize the metadata region in the remote process
    try self.initHeapMetadata(dataAddr: remoteDataAddr, dataLen: dataLen)

    // allocate an rwx region to hold the malloc_iterate callback that will be
    // executed in the remote process
    let codeLen = UInt64(heap_callback_len())
    mmapArgs = [0, codeLen, UInt64(PROT_READ | PROT_WRITE | PROT_EXEC), UInt64(MAP_ANON | MAP_PRIVATE)]
    let remoteCodeAddr: UInt64 = try self.ptrace.callRemoteFunction(at: mmapAddr, with: mmapArgs)
    defer {
      let munmapArgs: [UInt64] = [remoteCodeAddr, codeLen]
      _ = try? self.ptrace.callRemoteFunction(at: munmapAddr, with: munmapArgs)
    }

    // copy the malloc_iterate callback implementation to the remote process
    let codeStart = heap_callback_start()!
    try self.process.writeMem(remoteAddr: remoteCodeAddr, localAddr: codeStart, len: UInt(codeLen))

    // collects metadata describing each heap allocation in the remote process
    var allocations: [(base: swift_addr_t, len: UInt64)] = []

    let regionLen = endAddr - startAddr 
    let args = [ startAddr, regionLen, remoteCodeAddr, remoteDataAddr ]
    _ = try self.ptrace.callRemoteFunction(at: mallocIterateAddr, with: args) {
      // This callback is invoked when a SIGTRAP is encountered, indicating
      // there is no more room for heap metadata in the data buffer. Process
      // all current metadata, skip the trap/break instruction, and continue
      // iterating heap items until completion.
      allocations.append(
        contentsOf: try self.processHeapAllocations(dataAddr: remoteDataAddr, dataLen: dataLen))

      try self.initHeapMetadata(dataAddr: remoteDataAddr, dataLen: dataLen)

      var regs = try self.ptrace.getRegSet()

      #if arch(arm64)
        regs.pc += 4 // brk #0x0
      #elseif arch(x86_64)
        regs.rip += 1 // int3
      #endif

      try self.ptrace.setRegSet(regSet: regs)
    }

    allocations.append(
      contentsOf: try self.processHeapAllocations(dataAddr: remoteDataAddr, dataLen: dataLen))

    return allocations
  }
}

#endif
