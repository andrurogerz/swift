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

import SwiftRemoteMirror

internal final class AndroidRemoteProcess: RemoteProcess {
  public typealias ProcessIdentifier = pid_t
  public typealias ProcessHandle = pid_t // TODO(andrurogerz) wrong type?

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
      // TODO(andrurogerz)
      return
    }
  }

  static var ReadBytes: ReadBytesFunction {
    return { (context, address, size, _) in
      // TODO(andrurogerz)
      return nil
    }
  }

  static var GetStringLength: GetStringLengthFunction {
    return { (context, address) in
      // TODO(andrurogerz)
      return 0
    }
  }

  static var GetSymbolAddress: GetSymbolAddressFunction {
    return { (context, symbol, length) in
      // TODO(andrurogerz)
      return 0
    }
  }

  init?(processId: ProcessIdentifier) {
    self.process = processId
    self.processIdentifier = processId

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

  deinit {
  }

  func symbolicate(_ address: swift_addr_t) -> (module: String?, symbol: String?) {
    // TODO(andrurogerz)
    return (nil, nil)
  }

  func iterateHeap(_ body: (swift_addr_t, UInt64) -> Void) {
    // TODO(andrurogerz)
    return
  }
}

#endif