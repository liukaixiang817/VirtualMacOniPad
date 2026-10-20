// Mac-only genuine DIKit typed oracle. Loaded only after bootstrap succeeds.
import Swift
import DiskImageKit
public typealias VM27DIKitArrayProgress = @convention(c)(UInt32,UInt32,UInt32,UInt32)->Void
@inline(never) @_optimize(none)
private func throughWitness<T: CaseIterable>(_ type: T.Type) -> T.AllCases { T.allCases }
@available(macOS 27.0, *)
@_cdecl("VM27DIKitStaticArrayProgressFixture")
public func vm27DIKitStaticArrayProgressFixture(_ progress:VM27DIKitArrayProgress) -> UInt64 {
 var checks: UInt32 = 0, failures: UInt32 = 0
 func check(_ condition: Bool) { checks += 1; if !condition { failures += 1 } }
 for iteration in 0..<16 {
  progress(UInt32(iteration),0,checks,failures)
  let direct = DiskImage.BlockSize.allCases
  let witness = throughWitness(DiskImage.BlockSize.self)
  check(direct.count == 2)
  check(witness.count == 2)
  check(direct[0].rawValue == 512 && direct[1].rawValue == 4096)
  check(witness[0].rawValue == 512 && witness[1].rawValue == 4096)
  var changed = direct
  changed.append(.bytes512)
  check(changed.count == 3 && direct.count == 2)
  changed[0] = .bytes4096
  check(changed[0] == .bytes4096 && direct[0] == .bytes512)
  check(changed.removeLast() == .bytes512)
  check(changed.count == 2 && witness.count == 2)
  changed.removeAll(keepingCapacity: true)
  check(changed.isEmpty && direct.count == 2 && witness.count == 2)
  progress(UInt32(iteration),1,checks,failures)
 }
 return UInt64(checks)<<32 | UInt64(failures)
}
