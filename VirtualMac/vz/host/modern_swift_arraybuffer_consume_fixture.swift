// Ordinary Mac helper fixture. It executes no VZ, VMM, CPU or guest code.
import VM27ArrayBufferConsume

final class Element {
  static var made = 0
  static var destroyed = 0
  let identity: Int
  init(_ identity: Int) { self.identity = identity; Self.made += 1 }
  deinit { Self.destroyed += 1 }
}

var checks = 0
var privateCalls = 0
var stockCalls = 0
var actualUniqueCalls = 0

func check(_ condition: @autoclosure () -> Bool) {
  checks += 1
  precondition(condition(), "ArrayBuffer ownership/capacity check failed")
}

@inline(never) func newArray(_ count: Int, _ salt: Int) -> [AnyObject] {
  var array: [AnyObject] = []
  for index in 0..<count { array.append(Element(salt + index)) }
  return array
}

@inline(never) func exercise(_ count: Int, _ capacity: Int, _ grow: Bool, _ shared: Bool, _ salt: Int) {
  var privateArray = newArray(count, salt)
  var stockArray = newArray(count, salt)
  // These aliases exercise the nonunique copy path and remain live through
  // both consuming calls. The other case owns each native buffer uniquely.
  let privateAlias = shared ? privateArray : []
  let stockAlias = shared ? stockArray : []
  let privateUnique = privateArray._buffer.isUniquelyReferenced()
  let stockUnique = stockArray._buffer.isUniquelyReferenced()
  if shared && count != 0 { check(!privateUnique && !stockUnique) }
  check(privateUnique == stockUnique)
  if privateUnique { actualUniqueCalls += 1 }
  privateArray._buffer = privateArray._buffer.vm27ConsumeAndCreateNew(
    bufferIsUnique: privateUnique, minimumCapacity: capacity, growForAppend: grow)
  privateCalls += 1
  stockArray._buffer = stockArray._buffer._consumeAndCreateNew(
    bufferIsUnique: stockUnique, minimumCapacity: capacity, growForAppend: grow)
  stockCalls += 1
  check(privateArray.count == count && stockArray.count == count)
  check(privateArray.capacity >= capacity && stockArray.capacity >= capacity)
  check(privateArray.capacity == stockArray.capacity)
  for index in 0..<count {
    check((privateArray[index] as! Element).identity == salt + index)
    check((stockArray[index] as! Element).identity == salt + index)
    if shared {
      check(privateArray[index] === privateAlias[index])
      check(stockArray[index] === stockAlias[index])
    }
  }
  if shared {
    check(privateAlias.count == count && stockAlias.count == count)
    privateArray.append(Element(salt + count))
    stockArray.append(Element(salt + count))
    check(privateAlias.count == count && stockAlias.count == count)
    check(privateArray.count == count + 1 && stockArray.count == count + 1)
  }
  withExtendedLifetime(privateAlias) {}
  withExtendedLifetime(stockAlias) {}
}

if CommandLine.arguments.contains("--allocation-failure") {
  var array: [AnyObject] = []
  array._buffer = array._buffer.vm27ConsumeAndCreateNew(
    bufferIsUnique: false, minimumCapacity: 1 << 50, growForAppend: false)
  preconditionFailure("genuine allocator accepted an impossible allocation")
}

for round in 0..<32 {
  for count in [0, 1, 2, 7, 32] {
    for capacity in [count, count + 1, count + 17] {
      for grow in [false, true] {
        for shared in [false, true] {
          exercise(count, capacity, grow, shared, round * 1000)
        }
      }
    }
  }
}
check(actualUniqueCalls > 0)
check(privateCalls == 1920 && stockCalls == 1920)
check(Element.made == Element.destroyed)
print("{\"checks\":\(checks),\"failures\":0,\"privateCalls\":\(privateCalls),\"stockCalls\":\(stockCalls),\"actualUniqueCalls\":\(actualUniqueCalls),\"madeObjects\":\(Element.made),\"destroyedObjects\":\(Element.destroyed),\"originalVZCalls\":0,\"deviceOperations\":0,\"full27Backend\":false}")
