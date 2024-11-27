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
import SwiftInspectAndroid
import SwiftRemoteMirror

internal final class AndroidRemoteProcess: RemoteProcess {
  public typealias ProcessIdentifier = pid_t
  public typealias ProcessHandle = SwiftInspectAndroid.Process

  public private(set) var process: ProcessHandle
  public private(set) var context: SwiftReflectionContextRef!
  public private(set) var processIdentifier: ProcessIdentifier
  public private(set) var processName: String = "<unknown process>"

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

      for (_, symbols) in process.symbolCache.symbolLookup {
        if let address = symbols[name] {
          return address.start
        }
      }

      return 0
    }
  }

  init?(processId: ProcessIdentifier) {
    self.processIdentifier = processId

    guard let process = try? SwiftInspectAndroid.Process(processId) else { return nil }
    self.process = process

    guard let symbolCache = try? SwiftInspectAndroid.SymbolCache(for: process) else { return nil }
    self.symbolCache = symbolCache

    let procfs_cmdline_path = "/proc/\(processId)/cmdline"
    guard let cmdline = try? String(contentsOfFile: procfs_cmdline_path,
                                    encoding: .utf8) else {
      return nil
    }
    self.processName = cmdline;

    guard let context =
        swift_reflection_createReflectionContextWithDataLayout(self.toOpaqueRef(),
                                                               Self.QueryDataLayout,
                                                               Self.Free,
                                                               Self.ReadBytes,
                                                               Self.GetStringLength,
                                                               Self.GetSymbolAddress) else {
      return nil
    }
    self.context = context
  }

  func symbolicate(_ address: swift_addr_t) -> (module: String?, symbol: String?) {
    guard let symbol = self.symbolCache.symbol(for: address) else {
      return (nil, nil)
    }
    return (module: symbol.module, symbol: symbol.name)
  }

  internal func iterateHeap(_ body: (swift_addr_t, UInt64) -> Void) {
    struct HeapSnapshot {
      struct Allocation {
        var base: UInt64
        var len: UInt64
      }

      var items: [Allocation] = []

      static let callback: @convention(c)
        (UnsafeMutableRawPointer?, UInt64, UInt64) -> Void = { context, base, len in
          guard let context = context else { return }
          var snapshotPointer = context.assumingMemoryBound(to: HeapSnapshot.self)
          snapshotPointer.pointee.items.append(HeapSnapshot.Allocation(base: base, len: len))
        }
    }

    var snapshot: HeapSnapshot = HeapSnapshot()

    withUnsafeMutablePointer(to: &snapshot) { pointer in
      let context = UnsafeMutableRawPointer(pointer)
      if !heap_iterate(self.processIdentifier, context, HeapSnapshot.callback) {
        print("heap_iterate failed")
      }
    }

    for entry in snapshot.items {
      body(entry.base, entry.len)
    }
  }
}

#endif
