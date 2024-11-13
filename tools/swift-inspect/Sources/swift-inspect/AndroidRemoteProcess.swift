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
import SwiftRemoteMirror
import PosixInterface

internal final class AndroidRemoteProcess: RemoteProcess {
  public typealias ProcessIdentifier = pid_t
  public typealias ProcessHandle = pid_t // TODO(andrurogerz) wrong type?

  // describes a line from the /proc/<pid>/maps file
  struct MemoryMapEntry {
    let startAddress: UInt64
    let endAddress: UInt64
    let permissions: String
    let offset: UInt64
    let device: String
    let inode: UInt64
    let pathName: String?

    func isReadable() -> Bool {
      return self.permissions.contains("r")
    }

    func isWriteable() -> Bool {
      return self.permissions.contains("w")
    }

    func isExecutable() -> Bool {
      return self.permissions.contains("x")
    }

    func isPrivate() -> Bool {
      return self.permissions.contains("p")
    }
  }

  struct TargetFunctionAddrs {
    let dlopenAddr: UInt64
    let dlcloseAddr: UInt64
    let dlsymAddr: UInt64
  }

  private var memoryMap: [MemoryMapEntry]

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

  // Return an array of MemoryMapEntry items describing all of the memory ranges
  // in processId in the order they appear in /proc/\(processId)/maps.
  static func loadMemoryMap(_ processId: ProcessIdentifier) -> [MemoryMapEntry]? {
    let path = "/proc/\(processId)/maps"
    guard let fileHandle = try? FileHandle(forReadingFrom: URL(fileURLWithPath: path)) else {
      print("failed to to open file \(path)")
      return nil
    }
    defer { fileHandle.closeFile() }

    guard let content = String(data: fileHandle.readDataToEndOfFile(), encoding: .utf8) else {
      print("failed loading data from file \(path)")
      return nil
    }

    var memoryMapEntries = [MemoryMapEntry]()
    let lines = content.split(separator: "\n")
    for line in lines {
      let parts = line.split(separator: " ", omittingEmptySubsequences: true)
      guard parts.count >= 5 else {
        print("unexpected line in \(path): \"\(line)\"")
        continue
      }

      // start end end address of the memory region in base 16
      let addresses = parts[0].split(separator: "-")
      guard addresses.count == 2,
        let startAddress = UInt64(addresses[0], radix: 16),
        let endAddress = UInt64(addresses[1], radix: 16) else {
        print("unexpected address range format in \(path): \"\(parts[0])\"")
        continue
      }

      // access permissions of the memory region (ex. "r-xp", "rw-p")
      let permissions = String(parts[1])

      // offset in the file (if file-backed) in base 16
      guard let offset = UInt64(parts[2], radix: 16) else {
        print("unexpected offset value in \(path): \"\(parts[2])\"")
        continue
      }

      // device number associated with the memory region
      let device = String(parts[3])

      // inode of the file (if file-backed) in base 10
      guard let inode = UInt64(parts[4]) else {
        print("unexpected inode value in \(path): \"\(parts[4])\"")
        continue
      }

      // optional name of the region, or path to file if file-backed
      let pathName = parts.count > 5 ? String(parts[5]) : nil
      memoryMapEntries.append(MemoryMapEntry(
        startAddress: startAddress,
        endAddress: endAddress,
        permissions: permissions,
        offset: offset,
        device: device,
        inode: inode,
        pathName: pathName))
    }

    return memoryMapEntries
  }

  static func findFunctionInTarget(libName: String, funcName: String,
                                  currentProcessMemoryMap: [MemoryMapEntry],
                                  targetProcessMemoryMap: [MemoryMapEntry]) -> UInt64? {
    guard let libHandle = dlopen(libName, RTLD_LAZY) else {
      print("failed dlopen(\(libName))")
      return nil
    }
    defer { dlclose(libHandle) }

    guard let funcPointer = dlsym(libHandle, funcName) else {
      print("failed dlsym(\(funcName))")
      return nil
    }

    let funcAddr = unsafeBitCast(funcPointer, to: UInt64.self)

    var foundRegion: MemoryMapEntry? = nil
    for region in currentProcessMemoryMap {
      if region.pathName != nil &&
         region.isExecutable() &&
         funcAddr >= region.startAddress &&
         funcAddr < region.endAddress {
        foundRegion = region
        break
      }
    }

    guard let regionInCurrentProcess = foundRegion else {
      print("no memory region in current process containing \(funcName)")
      return nil
    }

    foundRegion = nil
    for region in targetProcessMemoryMap {
      guard let pathName = region.pathName else {
        continue
      }

      let regionInTargetProcessLen = region.endAddress - region.startAddress;
      let regionInCurrentProcessLen = regionInCurrentProcess.endAddress - regionInCurrentProcess.startAddress;
      if region.permissions == regionInCurrentProcess.permissions &&
         region.pathName == regionInCurrentProcess.pathName &&
         regionInTargetProcessLen == regionInCurrentProcessLen {
        foundRegion = region
        break
      }
    }

    guard let regionInTargetProcess = foundRegion else {
      print("no memory region \(regionInCurrentProcess.pathName!) in target process containing \(funcName)")
      return nil
    }

    let funcOffsetInRegion = funcAddr - regionInCurrentProcess.startAddress
    let funcAddrInTargetProcess = regionInTargetProcess.startAddress + funcOffsetInRegion
    return funcAddrInTargetProcess
  }

  static func findFuntionsInTarget(processId: ProcessIdentifier) -> TargetFunctionAddrs? {
    guard let currentProcessMemoryMap = AndroidRemoteProcess.loadMemoryMap(getpid()) else {
      return nil
    }

    guard let targetProcessMemoryMap = AndroidRemoteProcess.loadMemoryMap(processId) else {
      return nil
    }

    guard let dlopenAddr = findFunctionInTarget(libName: "libc.so", funcName: "dlopen",
                                                currentProcessMemoryMap: currentProcessMemoryMap,
                                                targetProcessMemoryMap: targetProcessMemoryMap) else {
      return nil
    }
    print("dlopen in target process is at \(String(dlopenAddr, radix: 16))")

    guard let dlcloseAddr = findFunctionInTarget(libName: "libc.so", funcName: "dlclose",
                                                 currentProcessMemoryMap: currentProcessMemoryMap,
                                                 targetProcessMemoryMap: targetProcessMemoryMap) else {
      return nil
    }
    print("dlclose in target process is at \(String(dlcloseAddr, radix: 16))")

    guard let dlsymAddr = findFunctionInTarget(libName: "libc.so", funcName: "dlsym",
                                               currentProcessMemoryMap: currentProcessMemoryMap,
                                               targetProcessMemoryMap: targetProcessMemoryMap) else {
      return nil
    }
    print("dlsym in target process is at \(String(dlsymAddr, radix: 16))")

    return TargetFunctionAddrs(
      dlopenAddr: dlopenAddr,
      dlcloseAddr: dlcloseAddr,
      dlsymAddr: dlsymAddr,
    )
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

    // TODO(andrurogerz): we should load the memory map as late as possible to
    // avoid missing any new entries
    guard let memoryMap = AndroidRemoteProcess.loadMemoryMap(processId) else {
      return nil
    }
    self.memoryMap = memoryMap

    print("target process \(processId) has \(memoryMap.count) regions in its memory map")

    let thisProcessId = getpid()
    if let myMemoryMap = AndroidRemoteProcess.loadMemoryMap(thisProcessId) {
      print("this process \(thisProcessId) has \(myMemoryMap.count) regions in its memory map")
    }

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
    let ptrace_result = ptrace_attach(processId)
    print("ptrace_result:\(ptrace_result)")
    var status: Int32 = 0;
    let wait_result = wait(&status)
    print("wait_result:\(wait_result), status:\(status)")

    guard let targetFunctionAddrs = AndroidRemoteProcess.findFuntionsInTarget(processId: processId) else {
      return nil
    };
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