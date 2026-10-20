// One-iteration original SDK diagnostic. Callback is an explicit imported C convention function pointer.
import Swift
import Foundation
import DiskImageKit
public typealias VM27DIKitStepCallback = @convention(c) (UInt32, UInt32, UInt32, UInt32, UInt32) -> Void
@inline(never) @_optimize(none)
private func mirroredStep<T>(_ value:T,_ name:String,_ phase:VM27DIKitStepCallback,_ operation:UInt32,_ checks:UInt32,_ failures:UInt32)->Any? {
 let base:UInt32=1000+operation*10
 phase(base,0,0,checks,failures)
 let reflection=Mirror(reflecting:value)
 phase(base,1,0,checks,failures)
 phase(base+1,0,0,checks,failures)
 let children=reflection.children
 phase(base+1,1,0,checks,failures)
 phase(base+2,0,0,checks,failures)
 var iterator=children.makeIterator()
 phase(base+2,1,0,checks,failures)
 var childIndex:UInt32=0
 while true {
  phase(base+3,0,childIndex,checks,failures)
  let next=iterator.next()
  phase(base+3,1,childIndex,checks,failures)
  guard let child=next else{return nil}
  phase(base+4,0,childIndex,checks,failures)
  let matches=child.label==name
  phase(base+4,1,childIndex,checks,failures)
  if matches {
   phase(base+5,0,childIndex,checks,failures)
   let result=child.value
   phase(base+5,1,childIndex,checks,failures)
   return result
  }
  childIndex+=1
 }
}
@available(macOS 27.0, *)
@_cdecl("VM27DIKitHostLayoutStepFixture")
public func vm27DIKitHostLayoutStepFixture(_ phase:VM27DIKitStepCallback)->UInt64 {
 var checks:UInt32=0,failures:UInt32=0
 func check(_ value:Bool){checks+=1;if !value{failures+=1}}
 func before(_ operation:UInt32){phase(operation,0,0,checks,failures)}
 func after(_ operation:UInt32){phase(operation,1,0,checks,failures)}
 before(1)
 let firstURL=URL(fileURLWithPath:"/vm27-configuration-first",isDirectory:false)
 after(1)
 before(2)
 let secondURL=URL(fileURLWithPath:"/vm27-configuration-second",isDirectory:false)
 after(2)
 before(3)
 let first=ASIFCreationConfiguration.asif(url:firstURL,blockCount:257,blockSize:.bytes4096)
 after(3)
 before(4)
 var changed=first
 after(4)
 before(5)
 let firstURLAny=mirroredStep(first,"_url",phase,5,checks,failures)
 after(5)
 before(6)
 check((firstURLAny as? URL)==firstURL)
 after(6)
 before(7)
 let firstCountAny=mirroredStep(first,"_blockCount",phase,7,checks,failures)
 after(7)
 before(8)
 check((firstCountAny as? Int)==257)
 after(8)
 before(9)
 let firstBlockAny=mirroredStep(first,"_blockSize",phase,9,checks,failures)
 after(9)
 before(10)
 check((firstBlockAny as? DiskImage.BlockSize)?.rawValue==4096)
 after(10)
 before(11)
 changed=ASIFCreationConfiguration.asif(url:secondURL,blockCount:3,blockSize:.bytes512)
 after(11)
 before(12)
 let retainedURLAny=mirroredStep(first,"_url",phase,12,checks,failures)
 after(12)
 before(13)
 let retainedCountAny=mirroredStep(first,"_blockCount",phase,13,checks,failures)
 after(13)
 before(14)
 check((retainedURLAny as? URL)==firstURL && (retainedCountAny as? Int)==257)
 after(14)
 before(15)
 let changedURLAny=mirroredStep(changed,"_url",phase,15,checks,failures)
 after(15)
 before(16)
 let changedCountAny=mirroredStep(changed,"_blockCount",phase,16,checks,failures)
 after(16)
 before(17)
 check((changedURLAny as? URL)==secondURL && (changedCountAny as? Int)==3)
 after(17)
 before(18)
 let raw=RAWCreationConfiguration.raw(url:firstURL,blockCount:513)
 after(18)
 before(19)
 let rawURLAny=mirroredStep(raw,"_url",phase,19,checks,failures)
 after(19)
 before(20)
 check((rawURLAny as? URL)==firstURL)
 after(20)
 before(21)
 let rawCountAny=mirroredStep(raw,"_blockCount",phase,21,checks,failures)
 after(21)
 before(22)
 check((rawCountAny as? Int)==513)
 after(22)
 before(23)
 var rawCopy=raw
 after(23)
 before(24)
 rawCopy=RAWCreationConfiguration.raw(url:secondURL,blockCount:17)
 after(24)
 before(25)
 let rawRetainedURLAny=mirroredStep(raw,"_url",phase,25,checks,failures)
 after(25)
 before(26)
 let rawCopyURLAny=mirroredStep(rawCopy,"_url",phase,26,checks,failures)
 after(26)
 before(27)
 check((rawRetainedURLAny as? URL)==firstURL && (rawCopyURLAny as? URL)==secondURL)
 after(27)
 before(28)
 let layer=ASIFLayerCreationConfiguration.asifLayer(url:firstURL,type:.cache)
 after(28)
 before(29)
 let layerURLAny=mirroredStep(layer,"_url",phase,29,checks,failures)
 after(29)
 before(30)
 check((layerURLAny as? URL)==firstURL)
 after(30)
 before(31)
 let originalOpen=OpenConfiguration(url:firstURL,mode:.readWrite)
 after(31)
 before(32)
 let secondOpen=OpenConfiguration(url:secondURL,mode:.readOnly)
 after(32)
 before(33)
 let openedURL=originalOpen.url
 after(33)
 before(34)
 let openedMode=originalOpen.mode
 after(34)
 before(35)
 check(openedURL==firstURL && openedMode == .readWrite)
 after(35)
 before(36)
 let original=[originalOpen,originalOpen]
 after(36)
 before(37)
 var copied=original
 after(37)
 before(38)
 copied[0]=secondOpen
 after(38)
 before(39)
 check(original.count==2 && original[0].url==firstURL && copied[0].url==secondURL && copied[0].mode == .readOnly)
 after(39)
 before(40)
 copied.removeAll(keepingCapacity:true)
 after(40)
 before(41)
 check(copied.isEmpty && original.count==2 && original[0].url==firstURL && original[1].mode == .readWrite)
 after(41)
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

private final class VM27StepWeakURLReference {weak var value:NSURL?}
@available(macOS 27.0, *)
@_cdecl("VM27DIKitHostLayoutStepOwnershipFixture")
public func vm27DIKitHostLayoutStepOwnershipFixture(_ phase:VM27DIKitStepCallback)->UInt64 {
 var checks:UInt32=0,failures:UInt32=0
 func check(_ value:Bool){checks+=1;if !value{failures+=1}}
 func before(_ operation:UInt32){phase(operation,0,0,checks,failures)}
 func after(_ operation:UInt32){phase(operation,1,0,checks,failures)}
 before(101)
 let reference=VM27StepWeakURLReference()
 after(101)
 var original:ASIFCreationConfiguration?
 before(102)
 autoreleasepool {
  before(103)
  let object=NSURL(fileURLWithPath:"/vm27-ownership-first",isDirectory:false)
  after(103)
  before(104)
  reference.value=object
  after(104)
  before(105)
  original=ASIFCreationConfiguration.asif(url:object as URL,blockCount:257,blockSize:.bytes4096)
  after(105)
 }
 after(102)
 before(106)
 check(reference.value != nil)
 after(106)
 before(107)
 var copied=original
 after(107)
 before(108)
 original=nil
 after(108)
 before(109)
 let copiedURLMatches=(mirroredStep(copied!,"_url",phase,109,checks,failures) as? URL)?.path=="/vm27-ownership-first"
 after(109)
 before(110)
 check(reference.value != nil && copiedURLMatches)
 after(110)
 // End the Any copy lifetime before testing the last configuration copy destruction.
 before(111)
 copied=nil
 after(111)
 before(112)
 check(reference.value == nil)
 after(112)
 return UInt64(checks)<<32|UInt64(failures)
}
