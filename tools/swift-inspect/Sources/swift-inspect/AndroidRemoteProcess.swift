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
import AndroidCLib // TODO(andrurogerz): just depend on SwiftInspectAndroid!
import SwiftInspectAndroid
import SwiftRemoteMirror

internal final class AndroidRemoteProcess: RemoteProcess {
  public typealias ProcessIdentifier = pid_t
  public typealias ProcessHandle = SwiftInspectAndroid.Process

  public private(set) var process: ProcessHandle
  public private(set) var context: SwiftReflectionContextRef!
  public private(set) var processIdentifier: ProcessIdentifier
  public private(set) var processName: String = "<unknown process>"

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
      let process: AndroidRemoteProcess =
        AndroidRemoteProcess.fromOpaque(context!)

      guard let buffer = malloc(Int(size)) else {
        return nil
      }

      if !remote_read_memory(process.process.pid, UInt(address), buffer, Int(size)) {
        free(buffer)
        return nil
      }

      return UnsafeRawPointer(buffer)
    }
  }

  static var GetStringLength: GetStringLengthFunction {
    return { (context, address) in
      let process: AndroidRemoteProcess =
        AndroidRemoteProcess.fromOpaque(context!)

      let len = remote_strlen(process.process.pid, UInt(address))
      return UInt64(len)
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

      guard let linkMap = try? SwiftInspectAndroid.LinkMap(for: process.process) else { return 0 }
      for entry in linkMap.entries {
        guard let filePath = entry.l_name else { continue }

        // all symbols of interest are in the core runtime
        guard filePath.hasSuffix("libswiftCore.so") else { continue }

        guard let elfFile = try? ElfFile(filePath: filePath) else { continue }
        guard let symbols = try? elfFile.loadSymbols() else { continue }

        for (symbol, address) in symbols {
          guard symbol.contains(name) else { continue }
          let rebasedAddress = entry.rebase(address: address)
          return swift_addr_t(rebasedAddress)
        }
      }

      return 0
    }
  }

  init?(processId: ProcessIdentifier) {
    self.processIdentifier = processId

    guard let process = try? SwiftInspectAndroid.Process(processId) else { return nil }
    self.process = process

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
    // TODO(andrurogerz)
    print("TODO: symbolicate")
    return (nil, nil)
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
      if !heap_iterate(self.process.pid, context, HeapSnapshot.callback) {
        print("heap_iterate failed")
      }
    }

    for entry in snapshot.items {
      body(entry.base, entry.len)
    }
  }
}

#endif
