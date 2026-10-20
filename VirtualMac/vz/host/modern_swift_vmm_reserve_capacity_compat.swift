// One application-private, exact AnyObject ContiguousArray specialization.
// Swift supplies the serialized standard-library body and its SwiftCC/COW ABI.
// The deployment target predates this specialization, so the body is emitted
// locally rather than recursively calling the identically named new export.
import Swift

extension ContiguousArray where Element == AnyObject {
  @_silgen_name("$ss15ContiguousArrayV15reserveCapacityyySiFyXl_Ts5")
  @inline(never) public mutating func vm27VMMReserveCapacity(_ minimumCapacity: Int) {
    reserveCapacity(minimumCapacity)
  }
}
