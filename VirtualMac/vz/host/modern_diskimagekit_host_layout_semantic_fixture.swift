// Original macOS27 SDK semantic fixture. Its resilient values resolve actual metadata at runtime.
import Swift
import Foundation
import DiskImageKit
@inline(never) @_optimize(none) private func mirrored<T>(_ value: T, _ name: String) -> Any? {
 for child in Mirror(reflecting: value).children { if child.label == name { return child.value } }
 return nil
}
@available(macOS 27.0, *)
@_cdecl("VM27DIKitHostLayoutSemanticFixture")
public func vm27DIKitHostLayoutSemanticFixture() -> UInt64 {
 var checks: UInt32 = 0, failures: UInt32 = 0
 func check(_ condition: Bool) { checks += 1; if !condition { failures += 1 } }
 for _ in 0..<128 {
  let firstURL=URL(fileURLWithPath:"/vm27-configuration-first",isDirectory:false)
  let secondURL=URL(fileURLWithPath:"/vm27-configuration-second",isDirectory:false)
  let first=ASIFCreationConfiguration.asif(url:firstURL,blockCount:257,blockSize:.bytes4096)
  var changed=first
  check((mirrored(first,"_url") as? URL)==firstURL)
  check((mirrored(first,"_blockCount") as? Int)==257)
  check((mirrored(first,"_blockSize") as? DiskImage.BlockSize)?.rawValue==4096)
  changed=ASIFCreationConfiguration.asif(url:secondURL,blockCount:3,blockSize:.bytes512)
  check((mirrored(first,"_url") as? URL)==firstURL && (mirrored(first,"_blockCount") as? Int)==257)
  check((mirrored(changed,"_url") as? URL)==secondURL && (mirrored(changed,"_blockCount") as? Int)==3)
  let raw=RAWCreationConfiguration.raw(url:firstURL,blockCount:513)
  check((mirrored(raw,"_url") as? URL)==firstURL)
  check((mirrored(raw,"_blockCount") as? Int)==513)
  var rawCopy=raw;rawCopy=RAWCreationConfiguration.raw(url:secondURL,blockCount:17)
  check((mirrored(raw,"_url") as? URL)==firstURL && (mirrored(rawCopy,"_url") as? URL)==secondURL)
  let layer=ASIFLayerCreationConfiguration.asifLayer(url:firstURL,type:.cache)
  check((mirrored(layer,"_url") as? URL)==firstURL)
  let originalOpen=OpenConfiguration(url:firstURL,mode:.readWrite)
  let secondOpen=OpenConfiguration(url:secondURL,mode:.readOnly)
  check(originalOpen.url==firstURL && originalOpen.mode == .readWrite)
  let original=[originalOpen,originalOpen];var copied=original
  copied[0]=secondOpen
  check(original.count==2 && original[0].url==firstURL && copied[0].url==secondURL && copied[0].mode == .readOnly)
  copied.removeAll(keepingCapacity:true)
  check(copied.isEmpty && original.count==2 && original[0].url==firstURL && original[1].mode == .readWrite)
 }
 return UInt64(checks)<<32|UInt64(failures)
}
@available(macOS 27.0, *)
@_cdecl("VM27DIKitHostLayoutDimensions")
public func vm27DIKitHostLayoutDimensions(_ type: UInt32)->UInt64 {
 switch type {
 case 0:return UInt64(MemoryLayout<URL>.size)<<32|UInt64(MemoryLayout<URL>.stride)
 case 1:return UInt64(MemoryLayout<ASIFCreationConfiguration>.size)<<32|UInt64(MemoryLayout<ASIFCreationConfiguration>.stride)
 case 2:return UInt64(MemoryLayout<ASIFLayerCreationConfiguration>.size)<<32|UInt64(MemoryLayout<ASIFLayerCreationConfiguration>.stride)
 case 3:return UInt64(MemoryLayout<RAWCreationConfiguration>.size)<<32|UInt64(MemoryLayout<RAWCreationConfiguration>.stride)
 case 4:return UInt64(MemoryLayout<OpenConfiguration>.size)<<32|UInt64(MemoryLayout<OpenConfiguration>.stride)
 default:return 0
 }
}
