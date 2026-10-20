// The SDK supplies the complete ArrayBuffer consuming/COW implementation.
// This exact AnyObject specialization owns its buffer argument and result;
// no wrapper changes element metadata, ARC or allocator behavior.
import Swift

extension _ArrayBuffer where Element == AnyObject {
  @_silgen_name("$ss12_ArrayBufferV20_consumeAndCreateNew14bufferIsUnique15minimumCapacity13growForAppendAByxGSb_SiSbtFyXl_Ts5")
  @inline(never) internal __consuming func vm27ConsumeAndCreateNew(
    bufferIsUnique: Bool, minimumCapacity: Int, growForAppend: Bool
  ) -> _ArrayBuffer<AnyObject> {
    _consumeAndCreateNew(bufferIsUnique: bufferIsUnique,
                         minimumCapacity: minimumCapacity,
                         growForAppend: growForAppend)
  }
}
