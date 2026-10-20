// Finite functional fixture for the eight app-private AnyObject entry contracts.
// Each entry is a strong import from VM27AnyObjectArray, verified by the builder.
import Swift
import Foundation
import VM27AnyObjectArray

// C ABI import from the builder's bridging header, before the fixture's values.
if VM27ArrayProviderIdentity() != 8 { fatalError("Private array provider identity mismatch") }

private var checks = 0
private var dead = 0
private final class Value {
  let index: Int
  init(_ index: Int) { self.index = index }
  deinit { dead += 1 }
}
private func check(_ condition: Bool) {
  checks += 1
  if !condition { fatalError("Array compatibility fixture failed") }
}
private func exercise(_ seed: Int) {
  let oldDead = dead
  do {
    let values = (0..<9).map { Value(seed + $0) as AnyObject }
    var a: [AnyObject] = Array(values[0..<3])
    let sharedA = a
    a.vm27MakeUnique()
    a.vm27CreateNewBuffer(bufferIsUnique: true, minimumCapacity: 12, growForAppend: false)
    a.vm27AppendAssumingCapacity(3, newElement: values[3])
    a._endMutation()
    check(a.count == 4 && sharedA.count == 3)
    check(a[3] === values[3] && a[0] === sharedA[0])
    check(a._buffer.vm27GetElementSlowPath(2) === values[2])
    let same = a
    a.vm27CreateNewBuffer(bufferIsUnique: false, minimumCapacity: 24, growForAppend: true)
    a.vm27AppendAssumingCapacity(4, newElement: values[4])
    a._endMutation()
    check(a.count == 5 && same.count == 4 && same[3] === values[3])
    var c = ContiguousArray(values[0..<2])
    let sharedC = c
    c.vm27MakeUnique()
    c.vm27ReserveAssumingUnique(2)
    c.vm27AppendAssumingCapacity(2, newElement: values[2])
    c.vm27EndMutation()
    check(c.count == 3 && sharedC.count == 2 && c[2] === values[2])
    var empty: ContiguousArray<AnyObject> = []
    empty.vm27MakeUnique()
    empty.vm27ReserveAssumingUnique(0)
    empty.vm27AppendAssumingCapacity(0, newElement: values[8])
    empty.vm27EndMutation()
    check(empty.count == 1 && empty[0] === values[8])
    var ca: [AnyObject] = NSArray(array: values) as [AnyObject]
    check(ca._buffer.vm27GetElementSlowPath(7) === values[7])
    let cocoaShared = ca
    ca.vm27MakeUnique()
    ca.vm27CreateNewBuffer(bufferIsUnique: true, minimumCapacity: 16, growForAppend: false)
    ca.vm27AppendAssumingCapacity(9, newElement: values[0])
    ca._endMutation()
    check(ca.count == 10 && cocoaShared.count == 9 && ca[9] === values[0])
    check(dead == oldDead)
  }
  check(dead == oldDead + 9)
}
if CommandLine.arguments.contains("--invalid-index-negative") {
  let a: [AnyObject] = [Value(0)]
  _ = a._buffer.vm27GetElementSlowPath(-1)
  fatalError("Invalid negative index unexpectedly returned")
}
if CommandLine.arguments.contains("--invalid-index-count") {
  let a: [AnyObject] = [Value(0)]
  _ = a._buffer.vm27GetElementSlowPath(a.count)
  fatalError("Invalid end index unexpectedly returned")
}
for seed in 0..<512 { exercise(seed * 9) }
print("{\"checks\":\(checks),\"failures\":0,\"iterations\":512,\"destroyedObjects\":\(dead),\"VMCalls\":0,\"diskCalls\":0}")
