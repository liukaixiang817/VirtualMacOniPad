// Application-private implementations of eight exact AnyObject specializations.
// Swift compiles member SwiftCC, ownership and COW semantics from the serialized
// standard-library implementations. No class metadata or element is substituted.
import Swift

extension Array where Element == AnyObject {
  @_silgen_name("$sSa034_makeUniqueAndReserveCapacityIfNotB0yyFyXl_Ts5")
  @inline(never) public mutating func vm27MakeUnique() {
    _makeUniqueAndReserveCapacityIfNotUnique()
  }
  @_silgen_name("$sSa16_createNewBuffer14bufferIsUnique15minimumCapacity13growForAppendySb_SiSbtFyXl_Ts5")
  @inline(never) public mutating func vm27CreateNewBuffer(
    bufferIsUnique: Bool, minimumCapacity: Int, growForAppend: Bool
  ) {
    _createNewBuffer(bufferIsUnique: bufferIsUnique,
                     minimumCapacity: minimumCapacity, growForAppend: growForAppend)
  }
  @_silgen_name("$sSa37_appendElementAssumeUniqueAndCapacity_03newB0ySi_xntFyXl_Ts5")
  @inline(never) public mutating func vm27AppendAssumingCapacity(
    _ oldCount: Int, newElement: __owned AnyObject
  ) {
    _appendElementAssumeUniqueAndCapacity(oldCount, newElement: newElement)
  }
}

extension _ArrayBuffer where Element == AnyObject {
  @_silgen_name("$ss12_ArrayBufferV19_getElementSlowPathyyXlSiFyXl_Ts5")
  @inline(never) internal func vm27GetElementSlowPath(_ index: Int) -> AnyObject {
    _getElementSlowPath(index)
  }
}

extension ContiguousArray where Element == AnyObject {
  @_silgen_name("$ss15ContiguousArrayV034_makeUniqueAndReserveCapacityIfNotD0yyFyXl_Ts5")
  @inline(never) public mutating func vm27MakeUnique() {
    _makeUniqueAndReserveCapacityIfNotUnique()
  }
  @_silgen_name("$ss15ContiguousArrayV12_endMutationyyFyXl_Ts5")
  @inline(never) public mutating func vm27EndMutation() {
    _endMutation()
  }
  @_silgen_name("$ss15ContiguousArrayV36_reserveCapacityAssumingUniqueBuffer8oldCountySi_tFyXl_Ts5")
  @inline(never) public mutating func vm27ReserveAssumingUnique(_ oldCount: Int) {
    _reserveCapacityAssumingUniqueBuffer(oldCount: oldCount)
  }
  @_silgen_name("$ss15ContiguousArrayV37_appendElementAssumeUniqueAndCapacity_03newD0ySi_xntFyXl_Ts5")
  @inline(never) public mutating func vm27AppendAssumingCapacity(
    _ oldCount: Int, newElement: __owned AnyObject
  ) {
    _appendElementAssumeUniqueAndCapacity(oldCount, newElement: newElement)
  }
}
