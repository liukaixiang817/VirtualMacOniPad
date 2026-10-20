// Compares the exact missing VMM specialization with stock reserveCapacity.
// Uses real NSObject references, shared buffers, COW, and original four sibling
// specializations from the unchanged, previously tested private provider.
import Swift
import Foundation
import VM27VMMArrayReserve
import VM27AnyObjectArray

if VM27VMMReserveStart() != 9 { fatalError("Private strong provider identity mismatch") }
private var checks = 0
private var destroyed = 0
private var reserveCalls = 0
private var stockCalls = 0
private var siblingCalls = 0
private final class Item: NSObject {
  let value: Int
  init(_ value: Int) { self.value = value }
  deinit { destroyed += 1 }
}
private func check(_ condition: Bool) {
  checks += 1
  if !condition { fatalError("VMM reserveCapacity comparison failed at check \(checks)") }
}
@inline(never) private func nativeReserve(_ a: inout ContiguousArray<AnyObject>, _ capacity: Int) {
  a.reserveCapacity(capacity)
  stockCalls += 1
}
@inline(never) private func privateReserve(_ a: inout ContiguousArray<AnyObject>, _ capacity: Int) {
  a.vm27VMMReserveCapacity(capacity)
  reserveCalls += 1
}
@inline(never) private func bufferAddress(_ a: ContiguousArray<AnyObject>) -> UInt {
  a.withUnsafeBufferPointer { UInt(bitPattern: $0.baseAddress) }
}
@inline(never) private func exercise(_ seed: Int) {
  let before = destroyed
  do {
    let objects = (0..<6).map { Item(seed + $0) as AnyObject }
    // Both arrays begin shared; reserveCapacity must preserve value/ownership,
    // produce usable capacity, and keep subsequent appends from changing aliases.
    var candidate = ContiguousArray(objects[0..<3])
    var stock = ContiguousArray(objects[0..<3])
    let candidateAlias = candidate
    let stockAlias = stock
    withExtendedLifetime((candidateAlias, stockAlias)) {
    check(bufferAddress(candidate) == bufferAddress(candidateAlias))
    check(bufferAddress(stock) == bufferAddress(stockAlias))
    for capacity in [Int.min, -1, 0, 2, 3, 4, 17, 64] {
      privateReserve(&candidate, capacity)
      nativeReserve(&stock, capacity)
      if seed == 0 {
        print("{\"record\":\"capacity\",\"requested\":\(capacity),\"private\":\(candidate.capacity),\"stock\":\(stock.capacity),\"count\":\(candidate.count)}")
        fflush(stdout)
      }
      check(candidate.count == stock.count && candidate.count == 3)
      check(candidate.capacity >= max(capacity, 3))
      check(stock.capacity >= max(capacity, 3))
      check(zip(candidate, stock).allSatisfy { $0 === $1 })
      check(candidateAlias.count == 3 && stockAlias.count == 3)
      check(zip(candidateAlias, objects[0..<3]).allSatisfy { $0 === $1 } &&
            zip(stockAlias, objects[0..<3]).allSatisfy { $0 === $1 })
      check(bufferAddress(candidate) != bufferAddress(candidateAlias) &&
            bufferAddress(stock) != bufferAddress(stockAlias))
      check(destroyed == before)
    }
    candidate.vm27MakeUnique(); siblingCalls += 1
    candidate.vm27ReserveAssumingUnique(3); siblingCalls += 1
    candidate.vm27AppendAssumingCapacity(3, newElement: objects[3]); siblingCalls += 1
    candidate.vm27EndMutation(); siblingCalls += 1
    stock.append(objects[3])
    check(candidate.count == stock.count && candidate.count == 4)
    check(candidate[3] === stock[3] && candidate[3] === objects[3])
    check(candidateAlias.count == 3 && stockAlias.count == 3)
    check(zip(candidateAlias, objects[0..<3]).allSatisfy { $0 === $1 } &&
          zip(stockAlias, objects[0..<3]).allSatisfy { $0 === $1 })
    check(bufferAddress(candidate) != bufferAddress(candidateAlias) &&
          bufferAddress(stock) != bufferAddress(stockAlias))
    }
    var emptyCandidate: ContiguousArray<AnyObject> = []
    var emptyStock: ContiguousArray<AnyObject> = []
    for capacity in [Int.min, -1, 0, 1, 9] {
      privateReserve(&emptyCandidate, capacity)
      nativeReserve(&emptyStock, capacity)
      check(emptyCandidate.isEmpty && emptyStock.isEmpty)
      check(emptyCandidate.capacity >= max(capacity, 0) && emptyStock.capacity >= max(capacity, 0))
    }
    emptyCandidate.append(objects[5]); emptyStock.append(objects[5])
    check(emptyCandidate.count == 1 && emptyCandidate[0] === emptyStock[0])
    withExtendedLifetime(objects) { check(destroyed == before) }
  }
  check(destroyed == before + 6)
}

if CommandLine.arguments.contains("--private-allocation-failure") || CommandLine.arguments.contains("--stock-allocation-failure") {
  var a: ContiguousArray<AnyObject> = []
  // 8 PiB plus the header cannot fit the supported user address space, and
  // multiplying this capacity by the pointer stride does not overflow UInt64.
  // This tests a genuine rejected allocation, not physical memory exhaustion.
  let impossibleVirtualCapacity = 1 << 50
  if CommandLine.arguments.contains("--private-allocation-failure") { privateReserve(&a, impossibleVirtualCapacity) }
  else { nativeReserve(&a, impossibleVirtualCapacity) }
  fatalError("Impossible capacity unexpectedly returned")
}
for seed in 0..<128 { exercise(seed * 6) }
check(reserveCalls == 1664 && stockCalls == 1664 && siblingCalls == 512)
if VM27VMMReserveFinish() != 9 { fatalError("Post-call provider identity mismatch") }
print("{\"record\":\"summary\",\"checks\":\(checks),\"failures\":0,\"iterations\":128,\"reserveCalls\":\(reserveCalls),\"stockCalls\":\(stockCalls),\"siblingCalls\":\(siblingCalls),\"destroyedObjects\":\(destroyed),\"VMCalls\":0,\"GPUCalls\":0,\"diskCalls\":0,\"full27Backend\":false}")
